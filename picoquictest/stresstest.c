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
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>

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

#define STRESS_MAX_NUMBER_TRACKED_STREAMS 16
#define STRESS_MINIMAL_QUERY_SIZE 127
#define STRESS_DEFAULT_RESPONSE_SIZE 257
#define STRESS_RESPONSE_LENGTH_MAX 1000000
#define STRESS_MESSAGE_BUFFER_SIZE 0x10000

typedef struct st_picoquic_stress_server_callback_ctx_t {
    // picoquic_first_server_stream_ctx_t* first_stream;
    uint8_t buffer[STRESS_MESSAGE_BUFFER_SIZE];
    size_t data_received_on_stream[STRESS_MAX_NUMBER_TRACKED_STREAMS];
    uint32_t data_sum_of_stream[STRESS_MAX_NUMBER_TRACKED_STREAMS];
} picoquic_stress_server_callback_ctx_t;

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
            else {
                /* Write a response, which should somehow depend on the stream data and
                * the stream status and the data bytes */
                if ((stream_id & 3) != 0) {
                    /* This is not a client-initiated bidir stream. Just ignore the data */
                }
                else {
                    uint64_t bidir_id = stream_id / 4;
                    size_t response_length = 0;


                    if (bidir_id < STRESS_MAX_NUMBER_TRACKED_STREAMS) {
                        size_t received = ctx->data_received_on_stream[bidir_id] + length;
                        if (ctx->data_received_on_stream[bidir_id] < STRESS_MINIMAL_QUERY_SIZE) {
                            int processed = length;
                            if (received >= STRESS_MINIMAL_QUERY_SIZE) {
                                processed = received - STRESS_MINIMAL_QUERY_SIZE;
                            }

                            for (int i = 0; i < processed; i++) {
                                ctx->data_sum_of_stream[bidir_id] =
                                    ctx->data_sum_of_stream[bidir_id] * 101 + bytes[i];
                            }

                            if (received >= STRESS_MINIMAL_QUERY_SIZE) {
                                response_length = ctx->data_sum_of_stream[bidir_id] % STRESS_RESPONSE_LENGTH_MAX;
                            }
                        }
                    }

                    /* for all streams above the limit, or all streams with short queries,just send a fixed size answer,
                    * after receiving all the client data */
                    if (fin_or_event == picoquic_callback_stream_fin &&
                        (bidir_id >= STRESS_MAX_NUMBER_TRACKED_STREAMS ||
                            ctx->data_received_on_stream[bidir_id] < STRESS_MINIMAL_QUERY_SIZE)) {

                        response_length = STRESS_DEFAULT_RESPONSE_SIZE;
                    }

                    if (response_length > 0) {
                        /* Push data on the stream */

                        while (response_length > STRESS_MESSAGE_BUFFER_SIZE) {
                            if ( (ret = picoquic_add_to_stream(cnx, stream_id, ctx->buffer,
                                STRESS_MESSAGE_BUFFER_SIZE, 0)) != 0) {
                                stress_debug_break();
                            }

                            response_length -= STRESS_MESSAGE_BUFFER_SIZE;
                        }
                        if ((ret = picoquic_add_to_stream(cnx, stream_id, ctx->buffer,
                                response_length, 1)) != 0) {
                            stress_debug_break();
                        }
                    }
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

#define STRESS_MAX_CLIENT_STREAMS 16

typedef struct st_picoquic_stress_client_callback_ctx_t {
    uint64_t test_id;
    uint64_t max_bidir;
    uint64_t next_bidir;
    size_t max_open_streams;
    size_t nb_open_streams;
    uint64_t stream_id[STRESS_MAX_CLIENT_STREAMS];
    uint32_t nb_client_streams;
    uint64_t last_interaction_time;
    int progress_observed;
} picoquic_stress_client_callback_ctx_t;

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
                stream_index = i;
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
                stream_index = i;
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
                    stress_client_start_streams(ctx, cnx);
                }
            }
        }
    }

    /* that's it */
}

/* Orchestration of the simulation: one server, N simulation
 * links. On each link, there may be a new client added in
 * the future. Links have different delays, capacity, and
 * different client arrival rates.
 */

#define PICOQUIC_MAX_STRESS_CLIENTS 256

typedef struct st_picoquic_stress_client_t {
    picoquic_quic_t* qclient;
    struct sockaddr_in client_addr;
    picoquictest_sim_link_t* c_to_s_link;
    picoquictest_sim_link_t* s_to_c_link;
    int sum_data_received_at_client;
} picoquic_stress_client_t;

typedef struct st_picoquic_stress_ctx_t {
    picoquic_quic_t* qserver;
    uint64_t simulated_time;
    size_t nb_stress_client;
    int sum_data_received_at_server;
    int sum_data_sent_at_server;
    int nb_clients;
    picoquic_stress_client_t * c_ctx[PICOQUIC_MAX_STRESS_CLIENTS];
} picoquic_stress_ctx_t;

/*
 * Message loop and related functions
 */

void stress_set_ip_address_from_index(struct sockaddr_in * addr, int c_index)
{
    int ret = 0;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
#ifdef _WINDOWS
    addr->sin_addr.S_un.S_addr = (ULONG) c_index;
#else
    addr->sin_addr.s_addr = (uint32_t)c_index;;
#endif
    addr->sin_port = 4321;
}

int stress_get_index_from_ip_address(struct sockaddr_in * addr)
{
    uint32_t c_index = -1;
#ifdef _WINDOWS
    c_index = (int)addr->sin_addr.S_un.S_addr;
#else
    c_index = (int)addr->sin_addr.s_addr;
#endif
    return c_index;
}


int stress_submit_sp_packets(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, int c_index)
{
    int ret = 0;
    picoquic_stateless_packet_t* sp = NULL;
    picoquictest_sim_link_t* target_link = NULL;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        ret = -1;
    }
    else while ((sp = picoquic_dequeue_stateless_packet(q)) != NULL) {
        if (sp->length > 0) {
            memcpy(&packet->addr_from, &sp->addr_local,
                (sp->addr_local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memcpy(&packet->addr_to, &sp->addr_to,
                (sp->addr_to.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memcpy(packet->bytes, sp->bytes, sp->length);
            packet->length = sp->length;

            if (c_index > 0)
            {
                target_link = ctx->c_ctx[c_index]->c_to_s_link;
            }
            else {
                /* find target from address */
                int d_index = stress_get_index_from_ip_address((struct sockaddr_in *) &sp->addr_to);

                if (d_index < 0 || d_index >= ctx->nb_clients) {
                    ret = -1;
                }
                else {
                    target_link = ctx->c_ctx[c_index]->s_to_c_link;
                }
            }

            if (target_link != NULL) {
                picoquictest_sim_link_submit(target_link, packet, ctx->simulated_time);
            }
        }
        picoquic_delete_stateless_packet(sp);
    }

    return ret;
}

int stress_handle_packet_arrival(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, picoquictest_sim_link_t* link)
{
    int ret = 0;
    /* dequeue packet from server to client and submit */
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, ctx->simulated_time);

    if (packet != NULL) {
        ret = picoquic_incoming_packet(q, packet->bytes, (uint32_t)packet->length,
            (struct sockaddr*)&packet->addr_from,
            (struct sockaddr*)&packet->addr_to, 0,
            ctx->simulated_time);
    }

    return ret;
}

int stress_handle_packet_prepare(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, int c_index)
{
    /* prepare packet and submit */
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
    picoquic_packet* p = picoquic_create_packet();
    picoquic_cnx_t* cnx = q->cnx_wake_first;
    picoquictest_sim_link_t* target_link = NULL;

    if (packet != NULL && p != NULL && cnx != NULL) {
        ret = picoquic_prepare_packet(cnx, p, ctx->simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length);
        if (ret == 0 && p->length > 0) {
            memcpy(&packet->addr_from, &cnx->path[0]->dest_addr, sizeof(struct sockaddr_in));
            memcpy(&packet->addr_to, &cnx->path[0]->peer_addr, sizeof(struct sockaddr_in));

            if (c_index > 0)
            {
                target_link = ctx->c_ctx[c_index]->c_to_s_link;
            }
            else {
                /* find target from address */
                int d_index = stress_get_index_from_ip_address((struct sockaddr_in *) &packet->addr_to);

                if (d_index < 0 || d_index >= ctx->nb_clients) {
                    ret = -1;
                }
                else {
                    target_link = ctx->c_ctx[c_index]->s_to_c_link;
                }
            }

            picoquictest_sim_link_submit(target_link, packet, ctx->simulated_time);
        }
        else {
            free(p);
        }
        free(packet);
    }
    else
    {
        ret = -1;
        if (packet != NULL) {
            free(packet);
        }

        if (p != NULL) {
            free(p);
        }
    }

    return ret;
}

int stress_loop_poll_context(picoquic_stress_ctx_t * ctx, uint64_t next_time) {
    int ret = 0;
    int best_index = -1;
    int last_index = -1;
    int64_t delay_max = 100000000;
    uint64_t worst_wake_time = ctx->simulated_time + delay_max;
    uint64_t best_wake_time = ctx->simulated_time + picoquic_get_next_wake_delay(
        ctx->qserver, ctx->simulated_time, delay_max);

    ret = stress_submit_sp_packets(ctx, ctx->qserver, -1);

    for (int x = 0; ret == 0 && x < ctx->nb_clients; x++) {
        /* Find the arrival time of the next packet, by looking at
         * the various links. remember the winner */

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

        if (ctx->c_ctx[x]->qclient->cnx_wake_first != NULL &&
            ctx->c_ctx[x]->qclient->cnx_wake_first->next_wake_time < best_wake_time) {
            best_wake_time = ctx->c_ctx[x]->qclient->cnx_wake_first->next_wake_time;
            best_index = x;
        }

        ret = stress_submit_sp_packets(ctx, ctx->c_ctx[x]->qclient, x);
    }

    if (ret == 0) {
        /* Progress the current time */
        ctx->simulated_time = best_wake_time;

        if (best_index < 0) {
            /* The server is ready first */
            ret = stress_handle_packet_prepare(ctx, ctx->qserver, -1);
        }
        else {
            if (ret == 0 && ctx->c_ctx[best_index]->s_to_c_link->first_packet != NULL &&
                ctx->c_ctx[best_index]->s_to_c_link->first_packet->arrival_time <= ctx->simulated_time) {
                /* dequeue packet from server to client and submit */
                ret = stress_handle_packet_arrival(ctx, ctx->c_ctx[best_index]->qclient, ctx->c_ctx[best_index]->s_to_c_link);
            }

            if (ret == 0 && ctx->c_ctx[best_index]->c_to_s_link->first_packet != NULL &&
                ctx->c_ctx[best_index]->c_to_s_link->first_packet->arrival_time <= ctx->simulated_time) {
                /* dequeue packet from client to server and submit */
                ret = stress_handle_packet_arrival(ctx, ctx->qserver, ctx->c_ctx[best_index]->c_to_s_link);
            }

            if (ctx->c_ctx[best_index]->qclient->cnx_wake_first != NULL &&
                ctx->c_ctx[best_index]->qclient->cnx_wake_first->next_wake_time <= ctx->simulated_time) {

                ret = stress_handle_packet_prepare(ctx, ctx->c_ctx[best_index]->qclient, best_index);
            }
        }
    }

    return ret;
}

