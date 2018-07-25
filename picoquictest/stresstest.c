/*
* Author: Christian Huitema
* Copyright (c) 2018, Private Octopus, Inc.
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL Private Octopus, Inc. BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "../picoquic/picoquic_internal.h"
#include "../picoquic/tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "..\picoquic\wincompat.h"
#else
#include <signal.h>
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>

#define PICOQUIC_MAX_STRESS_CLIENTS 256
#define PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS 16
#define PICOQUIC_STRESS_MINIMAL_QUERY_SIZE 127
#define PICOQUIC_STRESS_DEFAULT_RESPONSE_SIZE 257
#define PICOQUIC_STRESS_RESPONSE_LENGTH_MAX 1000000
#define PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE 0x10000
#define PICOQUIC_STRESS_MAX_CLIENT_STREAMS 16

uint64_t picoquic_stress_test_duration = 120000000; /* Default to 2 minutes */
size_t picoquic_stress_nb_clients = 4; /* Default to 4 clients */
uint64_t picoquic_stress_max_bidir = 8 * 4; /* Default to 8 streams max per connection */
size_t picoquic_stress_max_open_streams = 4; /* Default to 4 simultaneous streams max per connection */
uint64_t stress_random_ctx = 0xBabaC001BaddBab1ull;
uint32_t picoquic_stress_max_message_before_drop = 25;

typedef struct st_picoquic_stress_server_callback_ctx_t {
    // picoquic_first_server_stream_ctx_t* first_stream;
    size_t data_received_on_stream[PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS];
    uint32_t data_sum_of_stream[PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS];
    uint8_t buffer[PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE];
} picoquic_stress_server_callback_ctx_t;

typedef struct st_picoquic_stress_client_callback_ctx_t {
    uint64_t test_id;
    uint64_t max_bidir;
    uint64_t next_bidir;
    size_t max_open_streams;
    size_t nb_open_streams;
    uint64_t stream_id[PICOQUIC_STRESS_MAX_CLIENT_STREAMS];
    uint64_t last_interaction_time;
    uint32_t nb_client_streams;
    uint32_t message_disconnect_trigger;
    int progress_observed;
} picoquic_stress_client_callback_ctx_t;

typedef struct st_picoquic_stress_client_t {
    picoquic_quic_t* qclient;
    struct sockaddr_in client_addr;
    char ticket_file_name[32];
    picoquictest_sim_link_t* c_to_s_link;
    picoquictest_sim_link_t* s_to_c_link;
} picoquic_stress_client_t;

typedef struct st_picoquic_stress_ctx_t {
    picoquic_quic_t* qserver;
    struct sockaddr_in server_addr;
    uint64_t simulated_time;
    int sum_data_received_at_server;
    int sum_data_sent_at_server;
    int sum_connections;
    int nb_clients;
    picoquic_stress_client_t * c_ctx[PICOQUIC_MAX_STRESS_CLIENTS];
} picoquic_stress_ctx_t;

/*
 * Portable abort call, should work on Linux and Windows.
 * We deliberately do not call the ASSERT macros, becuse these
 * macros can be made no-op if compiled with NDEBUG
 */

static void stress_debug_break()
{
#ifdef _WINDOWS
    DebugBreak();
#else
    raise(SIGTRAP);
#endif
}


/*
* Call back function, server side.
*
* Try to provide some code coverage on the server side while maintaining as
* little state as possible.
* TODO: add debug_break on error condition.
*/

static void stress_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    int ret = 0;
    picoquic_stress_server_callback_ctx_t* ctx = (picoquic_stress_server_callback_ctx_t*)callback_ctx;

    if (fin_or_event == picoquic_callback_close || fin_or_event == picoquic_callback_application_close) {
        if (ctx != NULL) {
            free(ctx);
            picoquic_set_callback(cnx, stress_server_callback, NULL);
        }
    }
    else if (fin_or_event == picoquic_callback_challenge_response) {
        /* Do nothing */
    }
    else {
        if (ctx == NULL) {
            picoquic_stress_server_callback_ctx_t* new_ctx = (picoquic_stress_server_callback_ctx_t*)
                malloc(sizeof(picoquic_stress_server_callback_ctx_t));
            if (new_ctx == NULL) {
                /* Should really be a debug-break error */
                picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
                stress_debug_break();
            }
            else {
                memset(new_ctx, 0, sizeof(picoquic_stress_server_callback_ctx_t));
                picoquic_set_callback(cnx, stress_server_callback, new_ctx);
                ctx = new_ctx;
            }
        }

        if (ctx != NULL) {
            /* verify state and copy data to the stream buffer */
            if (fin_or_event == picoquic_callback_stop_sending) {
                if ((ret = picoquic_reset_stream(cnx, stream_id, 0)) != 0) {
                    stress_debug_break();
                }
            }
            else if (fin_or_event == picoquic_callback_stream_reset) {
                if ((ret = picoquic_reset_stream(cnx, stream_id, 0)) != 0) {
                    stress_debug_break();
                }
            }
            else if (fin_or_event == picoquic_callback_no_event || fin_or_event == picoquic_callback_stream_fin) {
                /* Write a response, which should somehow depend on the stream data and
                * the stream status and the data bytes */
                if ((stream_id & 3) != 0) {
                    /* This is not a client-initiated bidir stream. Just ignore the data */
                }
                else {
                    uint64_t bidir_id = stream_id / 4;
                    size_t response_length = 0;


                    if (bidir_id < PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS) {
                        size_t received = ctx->data_received_on_stream[bidir_id] + length;
                        if (ctx->data_received_on_stream[bidir_id] < PICOQUIC_STRESS_MINIMAL_QUERY_SIZE) {
                            /* Computing the size of the response as a pseudo random function of the
                             * content of the query. The response size will be between 0 and 
                             * PICOQUIC_STRESS_RESPONSE_LENGTH_MAX.
                             *
                             * The query size is arbitrary, thus the code only computes the
                             * pseudo random number on the the first bytes of the query,
                             * up to PICOQUIC_STRESS_MINIMAL_QUERY_SIZE.
                             *
                             * The random function is: hash[n] = hash[n-1]*101 + x[n]
                             *
                             * TODO: This may be too clever by half, and we could make the case for encoding the
                             * desired response size in the first four bytes of the query, and computing the
                             * random function at the client.
                             */
                            int processed = (int) length;
                            if (received >= PICOQUIC_STRESS_MINIMAL_QUERY_SIZE) {
                                processed = (int) received - PICOQUIC_STRESS_MINIMAL_QUERY_SIZE;
                            }

                            for (int i = 0; i < processed; i++) {
                                ctx->data_sum_of_stream[bidir_id] =
                                    ctx->data_sum_of_stream[bidir_id] * 101 + bytes[i];
                            }

                            if (received >= PICOQUIC_STRESS_MINIMAL_QUERY_SIZE) {
                                response_length = ctx->data_sum_of_stream[bidir_id] % PICOQUIC_STRESS_RESPONSE_LENGTH_MAX;
                            }
                        }
                        ctx->data_received_on_stream[bidir_id] += length;
                    }

                    /* for all streams above the limit, or all streams with short queries,just send a fixed size answer,
                    * after receiving all the client data */
                    if (fin_or_event == picoquic_callback_stream_fin &&
                        (bidir_id >= PICOQUIC_STRESS_MAX_NUMBER_TRACKED_STREAMS ||
                            ctx->data_received_on_stream[bidir_id] < PICOQUIC_STRESS_MINIMAL_QUERY_SIZE)) {

                        response_length = PICOQUIC_STRESS_DEFAULT_RESPONSE_SIZE;
                    }

                    if (response_length > 0) {
                        /* Push data on the stream */

                        while (response_length > PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE) {
                            if ( (ret = picoquic_add_to_stream(cnx, stream_id, ctx->buffer,
                                PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE, 0)) != 0) {
                                stress_debug_break();
                            }

                            response_length -= PICOQUIC_STRESS_MESSAGE_BUFFER_SIZE;
                        }
                        if ((ret = picoquic_add_to_stream(cnx, stream_id, ctx->buffer,
                                response_length, 1)) != 0) {
                            stress_debug_break();
                        }
                    }
                }
            } else {
                /* Unexpected frame */
                if ((ret = picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION)) != 0) {
                    stress_debug_break();
                }
            }
        }
    }

    /* that's it */
}

/* Callback function, client side.
* Implement simple scenarios for query generations, such as
* number of queries and interval between queries */

/* Stress client callback: same as the demo client callback, 
 * based on scenarios. But we need to account for failures,
 * effectively doing debugbreak in case of execution
 * failure, so the stress can be run under debugger.
 *
 * Consider also adding client misbehavior in the future,
 * including silent departure, version negotiation, or
 * zero share start.
 */


static void stress_client_start_streams(picoquic_cnx_t* cnx,
    picoquic_stress_client_callback_ctx_t* ctx) 
{
    int ret = 0;
    uint8_t buf[32];

    while (ctx->nb_open_streams < ctx->max_open_streams &&
        ctx->next_bidir <= ctx->max_bidir) {
        int stream_index = -1;
        for (size_t i = 0; i < ctx->max_open_streams; i++) {
            if (ctx->stream_id[i] == (uint64_t)((int64_t) -1)) {
                stream_index = (int) i;
                break;
            }
        }

        if (stream_index < 0) {
            stress_debug_break();
        }
        else {
            memset(buf, 0, sizeof(buf));
            picoformat_64(buf, ctx->test_id);
            picoformat_64(&buf[8], ctx->next_bidir);

            ctx->stream_id[stream_index] = ctx->next_bidir;
            ctx->next_bidir += 4;
            ctx->nb_open_streams++;

            if ((ret = picoquic_add_to_stream(cnx, ctx->stream_id[stream_index], buf, sizeof(buf), 1)) != 0){
                stress_debug_break();
            }
        }
    }
}

static void stress_client_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    int ret = 0;
    picoquic_stress_client_callback_ctx_t* ctx = (picoquic_stress_client_callback_ctx_t*)callback_ctx;

    ctx->last_interaction_time = picoquic_current_time();
    ctx->progress_observed = 1;

    if (fin_or_event == picoquic_callback_close || fin_or_event == picoquic_callback_application_close) {
        /* Free per connection resource */
        if (ctx != NULL) {
            free(ctx);
            picoquic_set_callback(cnx, stress_client_callback, NULL);
        }
    }
    else if (ctx != NULL) {
        /* if stream is already present, check its state. New bytes? */
        int stream_index = -1;
        int is_finished = 0;

        for (size_t i = 0; i < ctx->max_open_streams; i++) {
            if (ctx->stream_id[i] == stream_id) {
                stream_index = (int) i;
                break;
            }
        }

        if (stream_index >= 0) {
            /* if stream is finished, maybe start new ones */
            if (fin_or_event == picoquic_callback_stream_reset) {
                if ((ret = picoquic_reset_stream(cnx, stream_id, 0)) != 0) {
                    stress_debug_break();
                }
                is_finished = 1;
            }
            else if (fin_or_event == picoquic_callback_stop_sending) {
                if ((ret = picoquic_reset_stream(cnx, stream_id, 0)) != 0) {
                    stress_debug_break();
                }
                is_finished = 1;
            }
            else if (fin_or_event == picoquic_callback_stream_fin) {
                is_finished = 1;
            }

            if (is_finished != 0) {
                if (ctx->nb_open_streams > 0) {
                    ctx->nb_open_streams--;
                }
                else {
                    stress_debug_break();
                }

                ctx->stream_id[stream_index] =(uint64_t)((int64_t)-1);

                if (ctx->next_bidir >= ctx->max_bidir) {
                    /* This was the last stream */
                    if (ctx->nb_open_streams == 0) {
                        if ((ret = picoquic_close(cnx, 0)) != 0) {
                            stress_debug_break();
                        }
                    }
                }
                else {
                    /* Initialize the next bidir stream  */
                    stress_client_start_streams(cnx, ctx);
                }
            }
        }
    }

    /* that's it */
}

int stress_client_set_callback(picoquic_cnx_t* cnx) 
{
    static uint64_t test_id = 0;
    int ret = 0;

    if (picoquic_get_callback_context(cnx) != NULL) {
        /* Duplicate init call. This is a bug */
        stress_debug_break();
        ret = -1;
    }
    else {
        picoquic_stress_client_callback_ctx_t* ctx = 
            (picoquic_stress_client_callback_ctx_t*)malloc(sizeof(picoquic_stress_client_callback_ctx_t));
        if (ctx == NULL) {
            stress_debug_break();
            ret = -1;
        }
        else {
            memset(ctx, 0, sizeof(picoquic_stress_client_callback_ctx_t));
            ctx->test_id = test_id++;
            ctx->max_bidir = picoquic_stress_max_bidir;
            ctx->max_open_streams = picoquic_stress_max_open_streams;
            ctx->next_bidir = 4; /* TODO: change to zero when cream/crack gets done */
            for (size_t i = 0; i < ctx->max_open_streams; i++) {
                ctx->stream_id[i] = (uint64_t)((int64_t)-1);
            }
            picoquic_set_callback(cnx, stress_client_callback, ctx);

            if ((ctx->message_disconnect_trigger = (uint32_t) picoquic_test_uniform_random(&stress_random_ctx, 2* picoquic_stress_max_message_before_drop)) >= picoquic_stress_max_message_before_drop){
                ctx->message_disconnect_trigger = 0;
            }
            else {
                ctx->message_disconnect_trigger++;
            }

            stress_client_start_streams(cnx, ctx);
        }
    }

    return ret;
}

/* Orchestration of the simulation: one server, N simulation
 * links. On each link, there may be a new client added in
 * the future. Links have different delays, capacity, and
 * different client arrival rates.
 */

/*
 * Message loop and related functions
 */

static void stress_set_ip_address_from_index(struct sockaddr_in * addr, int c_index)
{
    memset(addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
#ifdef _WINDOWS
    addr->sin_addr.S_un.S_addr = (ULONG) c_index;
#else
    addr->sin_addr.s_addr = (uint32_t)c_index;;
#endif
    addr->sin_port = 4321;
}

static int stress_get_index_from_ip_address(struct sockaddr_in * addr)
{
    uint32_t c_index;
#ifdef _WINDOWS
    c_index = (int)addr->sin_addr.S_un.S_addr;
#else
    c_index = (int)addr->sin_addr.s_addr;
#endif
    return c_index;
}


static int stress_submit_sp_packets(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, int c_index)
{
    int ret = 0;
    picoquic_stateless_packet_t* sp = NULL;
    picoquictest_sim_link_t* target_link = NULL;

    while ((sp = picoquic_dequeue_stateless_packet(q)) != NULL) {
        if (sp->length > 0) {
            picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

            if (packet == NULL) {
                stress_debug_break();
                ret = -1;
                break;
            }
            else {
                memcpy(&packet->addr_from, &sp->addr_local,
                    (sp->addr_local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
                memcpy(&packet->addr_to, &sp->addr_to,
                    (sp->addr_to.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
                memcpy(packet->bytes, sp->bytes, sp->length);
                packet->length = sp->length;

                if (c_index >= 0)
                {
                    target_link = ctx->c_ctx[c_index]->c_to_s_link;
                }
                else {
                    /* find target from address */
                    int d_index = stress_get_index_from_ip_address((struct sockaddr_in *) &sp->addr_to);

                    if (d_index < 0 || d_index >= ctx->nb_clients) {
                        stress_debug_break();
                        ret = -1;
                    }
                    else {
                        target_link = ctx->c_ctx[d_index]->s_to_c_link;
                    }
                }

                if (target_link != NULL) {
                    picoquictest_sim_link_submit(target_link, packet, ctx->simulated_time);
                }
                else {
                    free(packet);
                    stress_debug_break();
                    ret = -1;
                    break;
                }
            }
        }
        picoquic_delete_stateless_packet(sp);
    }

    return ret;
}

static int stress_handle_packet_arrival(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, picoquictest_sim_link_t* link)
{
    int ret = 0;
    /* dequeue packet from server to client and submit */
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, ctx->simulated_time);

    if (packet != NULL) {
        ret = picoquic_incoming_packet(q, packet->bytes, (uint32_t)packet->length,
            (struct sockaddr*)&packet->addr_from,
            (struct sockaddr*)&packet->addr_to, 0,
            ctx->simulated_time);
        if (ret != 0){
            stress_debug_break();
        }
        free(packet);
    }

    return ret;
}

static int stress_handle_packet_prepare(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, int c_index)
{
    /* prepare packet and submit */
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
    picoquic_cnx_t* cnx = picoquic_get_earliest_cnx_to_wake(q, 0);
    picoquictest_sim_link_t* target_link = NULL;
    int simulate_disconnect = 0;

    if (packet != NULL && cnx != NULL) {
        /* Check that the client connection was properly terminated */
        picoquic_stress_client_callback_ctx_t* c_ctx = (c_index >= 0) ?
            (picoquic_stress_client_callback_ctx_t*)picoquic_get_callback_context(cnx) : NULL;

        /* Check whether immediate abrubt disconnection is required */
        if (c_ctx != NULL && cnx->cnx_state == picoquic_state_disconnected &&
            c_ctx->message_disconnect_trigger == 0) {
            uint64_t nb_sent = 0;
            for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++) {
                nb_sent += cnx->pkt_ctx[pc].send_sequence;
            }
            if (nb_sent > c_ctx->message_disconnect_trigger) {
                /* simulate an abrupt disconnect */
                ret = PICOQUIC_ERROR_DISCONNECTED;
                simulate_disconnect = 1;
            }
        }

        if (c_ctx == NULL || cnx->cnx_state == picoquic_state_disconnected 
            || simulate_disconnect == 0) { 
            ret = picoquic_prepare_packet(cnx, ctx->simulated_time,
                packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length);
        }

        if (ret == 0 && packet->length > 0) {
            memcpy(&packet->addr_from, &cnx->path[0]->dest_addr, sizeof(struct sockaddr_in));
            memcpy(&packet->addr_to, &cnx->path[0]->peer_addr, sizeof(struct sockaddr_in));

            if (c_index >= 0)
            {
                target_link = ctx->c_ctx[c_index]->c_to_s_link;
            }
            else {
                /* find target from address */
                int d_index = stress_get_index_from_ip_address((struct sockaddr_in *) &packet->addr_to);

                if (d_index < 0 || d_index >= ctx->nb_clients) {
                    stress_debug_break();
                    ret = -1;
                }
                else {
                    target_link = ctx->c_ctx[d_index]->s_to_c_link;
                }
            }
            if (target_link != NULL) {
                picoquictest_sim_link_submit(target_link, packet, ctx->simulated_time);
            }
        }
        else {
            free(packet);
            packet = NULL;

            if (ret == PICOQUIC_ERROR_DISCONNECTED) {
                /* Check the context again, it may have been freed in a callback */
                c_ctx = (c_index >= 0) ?
                    (picoquic_stress_client_callback_ctx_t*)picoquic_get_callback_context(cnx) : NULL;

                if (c_index >= 0) {
                    ret = 0;
                    if (c_ctx != NULL) {
                        if (simulate_disconnect == 0 && (
                            c_ctx->next_bidir <= c_ctx->max_bidir ||
                            c_ctx->nb_open_streams != 0)) {
                            stress_debug_break();
                            ret = -1;
                        }
                        free(c_ctx);
                        picoquic_set_callback(cnx, NULL, NULL);
                    }
                }
                else {
                    ret = 0;
                }
                picoquic_delete_cnx(cnx);
                if (c_index >= 0 && picoquic_get_earliest_cnx_to_wake(q, 0) != NULL) {
                    stress_debug_break();
                    ret = -1;
                }
            }
            else if (ret != 0) {
                stress_debug_break();
            }
        }
    }
    else
    {
        if (cnx != NULL) {
            stress_debug_break();
            ret = -1;
        }
        if (packet != NULL) {
            free(packet);
        }
    }

    return ret;
}

static int stress_start_client_connection(picoquic_quic_t * qclient, picoquic_stress_ctx_t * ctx)
{
    int ret = 0;

    picoquic_cnx_t * cnx = picoquic_create_cnx(qclient,
        picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&ctx->server_addr, ctx->simulated_time,
        0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

    if (cnx == NULL) {
        stress_debug_break();
        ret = -1;
    }
    else {
        ret = stress_client_set_callback(cnx);

        if (ret == 0) {
            ret = picoquic_start_client_cnx(cnx);
            if (ret != 0) {
                stress_debug_break();
            }
        }
        else {
            stress_debug_break();
        }
    }

    return ret;
}

static int stress_loop_poll_context(picoquic_stress_ctx_t * ctx) 
{
    int ret = 0;
    int best_index = -1;
    int64_t delay_max = 100000000;
    uint64_t best_wake_time = ctx->simulated_time + picoquic_get_next_wake_delay(
        ctx->qserver, ctx->simulated_time, delay_max);

    ret = stress_submit_sp_packets(ctx, ctx->qserver, -1);

    if (ret != 0) {
        stress_debug_break();
    }

    for (int x = 0; ret == 0 && x < ctx->nb_clients; x++) {
        /* Find the arrival time of the next packet, by looking at
         * the various links. remember the winner */
        picoquic_cnx_t * cnx;

        if (ctx->c_ctx[x]->s_to_c_link->first_packet != NULL && 
            ctx->c_ctx[x]->s_to_c_link->first_packet->arrival_time < best_wake_time) {
            best_wake_time = ctx->c_ctx[x]->s_to_c_link->first_packet->arrival_time;
            best_index = x;
        }

        if (ctx->c_ctx[x]->c_to_s_link->first_packet != NULL &&
            ctx->c_ctx[x]->c_to_s_link->first_packet->arrival_time < best_wake_time) {
            best_wake_time = ctx->c_ctx[x]->c_to_s_link->first_packet->arrival_time;
            best_index = x;
        }

        cnx = picoquic_get_earliest_cnx_to_wake(ctx->c_ctx[x]->qclient, 0);

        if (cnx != NULL &&
            cnx->next_wake_time < best_wake_time) {
            best_wake_time = cnx->next_wake_time;
            best_index = x;
        }

        ret = stress_submit_sp_packets(ctx, ctx->c_ctx[x]->qclient, x);

        if (ret != 0) {
            stress_debug_break();
        }
    }

    if (ret == 0) {
        /* Progress the current time */
        ctx->simulated_time = best_wake_time;

        if (best_index < 0) {
            /* The server is ready first */
            ret = stress_handle_packet_prepare(ctx, ctx->qserver, -1);

            if (ret != 0) {
                stress_debug_break();
            }
        }
        else {
            picoquic_cnx_t * cnx;

            if (ret == 0 && ctx->c_ctx[best_index]->s_to_c_link->first_packet != NULL &&
                ctx->c_ctx[best_index]->s_to_c_link->first_packet->arrival_time <= ctx->simulated_time) {
                /* dequeue packet from server to client and submit */
                ret = stress_handle_packet_arrival(ctx, ctx->c_ctx[best_index]->qclient, ctx->c_ctx[best_index]->s_to_c_link);
                if (ret != 0) {
                    stress_debug_break();
                }
            }

            if (ret == 0 && ctx->c_ctx[best_index]->c_to_s_link->first_packet != NULL &&
                ctx->c_ctx[best_index]->c_to_s_link->first_packet->arrival_time <= ctx->simulated_time) {
                /* dequeue packet from client to server and submit */
                ret = stress_handle_packet_arrival(ctx, ctx->qserver, ctx->c_ctx[best_index]->c_to_s_link);
                if (ret != 0) {
                    stress_debug_break();
                }
            }

            cnx = picoquic_get_earliest_cnx_to_wake(ctx->c_ctx[best_index]->qclient, 0);

            if (cnx != NULL) {
                /* If the connection is valid, check whether it is ready */
                if (cnx->next_wake_time <= ctx->simulated_time) {
                    ret = stress_handle_packet_prepare(ctx, ctx->c_ctx[best_index]->qclient, best_index);
                    if (ret != 0) {
                        stress_debug_break();
                    }
                }
            }
        }
    }

    return ret;
}

/* Stress test management
 * Parameters:
 *    Number of clients
 *    Simulated duration of stress test
 *    Profile of client run, i.e. max number of queries/client.
 *
 * Operation:
 *    Initialize the context:
 *    Loop:
 *        Clean terminated connections (part of simulation loop)
 *        Create connection for empty client contexts (part of simulation loop?)
 *        Run the loop, sending packets, etc.
 *    Clean up:
 *        Set termination flag for all contexts: close existing connections, do not create new ones.
 *        Run the loop until all contexts are freed.
 *        Fail if cannot clean up on a timeout.
 *    Report:
 *        Statistics on duration, volume, connections.
 *
 * Stress succeeds if it comes to a successful end.
 */

static const uint8_t stress_ticket_encrypt_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

static int stress_create_client_context(int client_index, picoquic_stress_ctx_t * stress_ctx)
{
    int ret = 0;
    picoquic_stress_client_t * ctx = (picoquic_stress_client_t *)malloc(sizeof(picoquic_stress_client_t));
    stress_ctx->c_ctx[client_index] = ctx;

    if (ctx == NULL) {
        DBG_PRINTF("Cannot create the client context #%d.\n", (int)client_index);
        ret = -1;
    }
    if (ret == 0) {
        memset(ctx, 0, sizeof(picoquic_stress_client_t));
        /* Initialize client specific address */
        stress_set_ip_address_from_index(&ctx->client_addr, (int)client_index);
        /* set stream ID to default value */

        /* initialize client specific ticket file */
        memcpy(ctx->ticket_file_name, "stress_ticket_000.bin", 19);
        ctx->ticket_file_name[14] = (uint8_t)('0' + client_index / 100);
        ctx->ticket_file_name[15] = (uint8_t)('0' + (client_index / 10) % 10);
        ctx->ticket_file_name[16] = (uint8_t)('0' + client_index % 10);
        ctx->ticket_file_name[21] = 0;
        if (ret == 0) {
            ret = picoquic_save_tickets(NULL, stress_ctx->simulated_time, ctx->ticket_file_name);
            if (ret != 0) {
                DBG_PRINTF("Cannot create ticket file <%s>.\n", ctx->ticket_file_name);
            }
        }
    }
    if (ret == 0) {
        /* initialize the simulation links from client to server and back. */
        ctx->c_to_s_link = picoquictest_sim_link_create(0.01, 10000, 0, 0, 0);
        ctx->s_to_c_link = picoquictest_sim_link_create(0.01, 10000, 0, 0, 0);
        if (ctx->c_to_s_link == NULL ||
            ctx->s_to_c_link == NULL) {
            DBG_PRINTF("Cannot create the sim links for client #%d.\n", (int)client_index);
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Create the quic context for this client*/
        ctx->qclient = picoquic_create(8, NULL, NULL, PICOQUIC_TEST_CERT_STORE, NULL, NULL,
            NULL, NULL, NULL, NULL, stress_ctx->simulated_time, &stress_ctx->simulated_time,
            ctx->ticket_file_name, NULL, 0);
        if (ctx->qclient == NULL) {
            DBG_PRINTF("Cannot create the quic client #%d.\n", (int)client_index);
            ret = -1;
        }
    }

    return ret;
}

static void stress_delete_client_context(int client_index, picoquic_stress_ctx_t * stress_ctx)
{
    picoquic_stress_client_t * ctx = stress_ctx->c_ctx[client_index];

    if (ctx != NULL) {
        if (ctx->qclient != NULL) {
            picoquic_free(ctx->qclient);
            ctx->qclient = NULL;
        }

        if (ctx->c_to_s_link != NULL) {
            picoquictest_sim_link_delete(ctx->c_to_s_link);
            ctx->c_to_s_link = NULL;
        }

        if (ctx->s_to_c_link != NULL) {
            picoquictest_sim_link_delete(ctx->s_to_c_link);
            ctx->s_to_c_link = NULL;
        }
        free(ctx);

        stress_ctx->c_ctx[client_index] = NULL;
    }
}

int stress_test()
{
    int ret = 0;
    picoquic_stress_ctx_t stress_ctx;
    double run_time_seconds = 0;
    double wall_time_seconds = 0;
    uint64_t wall_time_start = picoquic_current_time();
    uint64_t wall_time_max = wall_time_start + picoquic_stress_test_duration;
    uint64_t nb_connections = 0;
    uint64_t sim_time_next_log = 1000000;


    /* Initialization */
    memset(&stress_ctx, 0, sizeof(picoquic_stress_ctx_t));
    stress_set_ip_address_from_index(&stress_ctx.server_addr, -1);
    stress_ctx.nb_clients = (int)picoquic_stress_nb_clients;
    if (stress_ctx.nb_clients > PICOQUIC_MAX_STRESS_CLIENTS) {
        DBG_PRINTF("Number of stress clients too high (%d). Should be lower than %d\n",
            stress_ctx.nb_clients, PICOQUIC_MAX_STRESS_CLIENTS);
        ret = -1;
    } else {
        stress_ctx.qserver = picoquic_create(PICOQUIC_MAX_STRESS_CLIENTS,
            PICOQUIC_TEST_SERVER_CERT, PICOQUIC_TEST_SERVER_KEY, PICOQUIC_TEST_CERT_STORE,
            PICOQUIC_TEST_ALPN, stress_server_callback, NULL, NULL, NULL, NULL,
            stress_ctx.simulated_time, &stress_ctx.simulated_time, NULL,
            stress_ticket_encrypt_key, sizeof(stress_ticket_encrypt_key));

        if (stress_ctx.qserver == NULL) {
            DBG_PRINTF("%s", "Cannot create the test server.\n");
            ret = -1;
        }
        else {
            for (int i = 0; ret == 0 && i < stress_ctx.nb_clients; i++) {
                ret = stress_create_client_context(i, &stress_ctx);
            }
        }
    }

    /* Run the simulation until the specified time */
    sim_time_next_log = stress_ctx.simulated_time + 1000000;
    while (ret == 0 && stress_ctx.simulated_time < picoquic_stress_test_duration ) {
        if (picoquic_current_time() > wall_time_max) {
            DBG_PRINTF("%s", "Stress time takes too long!\n");
            ret = -1;
            break;
        }

        if (stress_ctx.simulated_time > sim_time_next_log) {
            double log_time = ((double)stress_ctx.simulated_time) / 1000000.0;
            DBG_PRINTF("T:%f. Nb cnx: %ull\n", log_time, 
                (unsigned long long)nb_connections);
            sim_time_next_log = stress_ctx.simulated_time + 1000000;
        }

        /* Poll for new packet transmission */
        ret = stress_loop_poll_context(&stress_ctx);

        if (ret == 0) {
            /* Check whether there is a need for new connections */
            for (int i = 0; ret == 0 && i < stress_ctx.nb_clients; i++) {
                if (stress_ctx.c_ctx[i]->qclient->cnx_list == NULL) {
                    ret = stress_start_client_connection(stress_ctx.c_ctx[i]->qclient, &stress_ctx);
                    if (ret != 0) {
                        stress_debug_break();
                    }
                }
            }
        }
        else {
            stress_debug_break();
        }
    }

    /* Shut down everything */
    for (int i = 0; i < stress_ctx.nb_clients; i++) {
        stress_delete_client_context((int)i, &stress_ctx);
    }

    if (stress_ctx.qserver != NULL) {
        picoquic_free(stress_ctx.qserver);
        stress_ctx.qserver = NULL;
    }

    /* Report */
    run_time_seconds = ((double)stress_ctx.simulated_time) / 1000000.0;
    wall_time_seconds = ((double)(picoquic_current_time() - wall_time_start)) / 1000000.0;
    DBG_PRINTF("Stress complete after simulating %3f s. in %3f s., returns %d\n",
        run_time_seconds, wall_time_seconds, ret);

    return ret;
}
