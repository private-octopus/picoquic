/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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

#define PICOQUIC_TEST_SNI "picoquic.test"
#define PICOQUIC_TEST_ALPN "picoquic-test"
#define PICOQUIC_TEST_WRONG_ALPN "picoquic-bla-bla"
#define PICOQUIC_TEST_MAX_TEST_STREAMS 8

static const uint8_t test_ticket_encrypt_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};

/*
 * Generic call back function.
 */

typedef enum {
    test_api_fail_data_on_unknown_stream = 1,
    test_api_fail_recv_larger_than_sent = 2,
    test_api_fail_fin_received_twice = 4,
    test_api_fail_cannot_send_response = 8,
    test_api_fail_cannot_send_query = 16,
    test_api_fail_data_does_not_match = 32
} test_api_fail_mode;

typedef struct st_test_api_stream_desc_t {
    uint64_t stream_id;
    uint64_t previous_stream_id;
    size_t q_len;
    size_t r_len;
} test_api_stream_desc_t;

typedef struct st_test_api_stream_t {
    uint64_t stream_id;
    uint64_t previous_stream_id;
    int q_sent;
    int r_sent;
    picoquic_call_back_event_t q_received;
    picoquic_call_back_event_t r_received;
    size_t q_len;
    size_t q_recv_nb;
    size_t r_len;
    size_t r_recv_nb;
    uint8_t* q_src;
    uint8_t* q_rcv;
    uint8_t* r_src;
    uint8_t* r_rcv;
} test_api_stream_t;

typedef struct st_test_api_callback_t {
    int client_mode;
    int fin_received;
    int error_detected;
    uint32_t nb_bytes_received;
} test_api_callback_t;

typedef struct st_picoquic_test_tls_api_ctx_t {
    picoquic_quic_t* qclient;
    picoquic_quic_t* qserver;
    picoquic_cnx_t* cnx_client;
    picoquic_cnx_t* cnx_server;
    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;
    test_api_callback_t client_callback;
    test_api_callback_t server_callback;
    size_t nb_test_streams;
    test_api_stream_t test_stream[PICOQUIC_TEST_MAX_TEST_STREAMS];
    picoquictest_sim_link_t* c_to_s_link;
    picoquictest_sim_link_t* s_to_c_link;
    int test_finished;
} picoquic_test_tls_api_ctx_t;

static test_api_stream_desc_t test_scenario_oneway[] = {
    { 4, 0, 257, 0 }
};

static test_api_stream_desc_t test_scenario_q_and_r[] = {
    { 4, 0, 257, 2000 }
};

static test_api_stream_desc_t test_scenario_q2_and_r2[] = {
    { 4, 0, 257, 2000 },
    { 8, 0, 531, 11000 }
};

static test_api_stream_desc_t test_scenario_very_long[] = {
    { 4, 0, 257, 1000000 }
};

static test_api_stream_desc_t test_scenario_stop_sending[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 531, 11000 }
};

static test_api_stream_desc_t test_scenario_unidir[] = {
    { 2, 0, 4000, 0 },
    { 3, 0, 5000, 0 }
};

static test_api_stream_desc_t test_scenario_mtu_discovery[] = {
    { 2, 0, 100000, 0 }
};

static int test_api_init_stream_buffers(size_t len, uint8_t** src_bytes, uint8_t** rcv_bytes)
{
    int ret = 0;

    *src_bytes = (uint8_t*)malloc(len);
    *rcv_bytes = (uint8_t*)malloc(len);

    if (*src_bytes != NULL && *rcv_bytes != NULL) {
        memset(*rcv_bytes, 0, len);

        for (size_t i = 0; i < len; i++) {
            (*src_bytes)[i] = (uint8_t)(i);
        }
    } else {
        ret = -1;

        if (*src_bytes != NULL) {
            free(*src_bytes);
            *src_bytes = NULL;
        }

        if (*rcv_bytes != NULL) {
            free(*rcv_bytes);
            *rcv_bytes = NULL;
        }
    }

    return ret;
}

static int test_api_init_test_stream(test_api_stream_t* test_stream,
    uint64_t stream_id, uint64_t previous_stream_id, size_t q_len, size_t r_len)
{
    int ret = 0;

    memset(test_stream, 0, sizeof(test_api_stream_t));

    if (q_len != 0) {
        ret = test_api_init_stream_buffers(q_len, &test_stream->q_src, &test_stream->q_rcv);
        if (ret == 0) {
            test_stream->q_len = q_len;
        }
    }

    if (ret == 0 && r_len != 0) {
        ret = test_api_init_stream_buffers(r_len, &test_stream->r_src, &test_stream->r_rcv);
        if (ret == 0) {
            test_stream->r_len = r_len;
        }
    }

    if (ret == 0) {
        test_stream->previous_stream_id = previous_stream_id;
        test_stream->stream_id = stream_id;
    }

    return ret;
}

static void test_api_delete_test_stream(test_api_stream_t* test_stream)
{
    if (test_stream->q_src != NULL) {
        free(test_stream->q_src);
    }

    if (test_stream->q_rcv != NULL) {
        free(test_stream->q_rcv);
    }

    if (test_stream->r_src != NULL) {
        free(test_stream->r_src);
    }

    if (test_stream->r_rcv != NULL) {
        free(test_stream->r_rcv);
    }

    memset(test_stream, 0, sizeof(test_api_stream_t));
}

static void test_api_receive_stream_data(
    const uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event,
    uint8_t* buffer, size_t max_len, const uint8_t* reference, size_t* nb_received,
    picoquic_call_back_event_t* received, int* error_detected)
{
    if (*nb_received + length > max_len) {
        *error_detected |= test_api_fail_recv_larger_than_sent;
    } else {
        memcpy(buffer + *nb_received, bytes, length);

        if (memcmp(reference + *nb_received, bytes, length) != 0) {
            *error_detected |= test_api_fail_data_does_not_match;
        }
    }

    *nb_received += length;

    if (fin_or_event != picoquic_callback_no_event) {
        if (*received != picoquic_callback_no_event) {
            *error_detected |= test_api_fail_fin_received_twice;
        }

        *received = fin_or_event;
    }
}

static int test_api_queue_initial_queries(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t stream_id)
{
    int ret = 0;
    int more_stream = 0;

    for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++) {
        if (test_ctx->test_stream[i].previous_stream_id == stream_id) {
            picoquic_cnx_t* cnx = NULL;

            cnx = (test_ctx->test_stream[i].stream_id & 1) ? test_ctx->cnx_server : test_ctx->cnx_client;

            ret = picoquic_add_to_stream(cnx, test_ctx->test_stream[i].stream_id,
                test_ctx->test_stream[i].q_src,
                test_ctx->test_stream[i].q_len, 1);

            if (ret == 0) {
                test_ctx->test_stream[i].q_sent = 1;
                more_stream = 1;
            }
        }
    }

    if (more_stream == 0) {
        /* TODO: check whether the test is actually finished */
        test_ctx->test_finished = 1;
    } else {
        test_ctx->test_finished = 0;
    }

    return ret;
}

static void test_api_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    /* Need to implement the server sending strategy */
    test_api_callback_t* cb_ctx = (test_api_callback_t*)callback_ctx;
    picoquic_test_tls_api_ctx_t* ctx = NULL;
    size_t stream_index = 0;
    int is_client_stream = 0;
    picoquic_call_back_event_t stream_finished = picoquic_callback_no_event;

    is_client_stream = ((stream_id & 1) == 0) ? 1 : 0;

    if (fin_or_event == picoquic_callback_close || fin_or_event == picoquic_callback_application_close) {
        /* do nothing in our tests */
        return;
    }

    if (cb_ctx->client_mode) {
        ctx = (picoquic_test_tls_api_ctx_t*)(((char*)callback_ctx) - offsetof(struct st_picoquic_test_tls_api_ctx_t, client_callback));
    } else {
        ctx = (picoquic_test_tls_api_ctx_t*)(((char*)callback_ctx) - offsetof(struct st_picoquic_test_tls_api_ctx_t, server_callback));
    }

    while (stream_index < ctx->nb_test_streams) {
        if (ctx->test_stream[stream_index].stream_id == stream_id) {
            break;
        }
        stream_index++;
    }

    if (stream_index >= ctx->nb_test_streams) {
        cb_ctx->error_detected |= test_api_fail_data_on_unknown_stream;
    } else if (fin_or_event == picoquic_callback_stop_sending) {
        /* Respond with a reset, no matter what. Should be smarter later */
        picoquic_reset_stream(cnx, stream_id, 0);
    } else if (is_client_stream) {
        if (cb_ctx->client_mode) {
            /* this is a response from the server to a client stream */
            test_api_receive_stream_data(bytes, length, fin_or_event,
                ctx->test_stream[stream_index].r_rcv,
                ctx->test_stream[stream_index].r_len,
                ctx->test_stream[stream_index].r_src,
                &ctx->test_stream[stream_index].r_recv_nb,
                &ctx->test_stream[stream_index].r_received,
                &cb_ctx->error_detected);

            stream_finished = fin_or_event;
        } else {
            /* this is a query to a server */
            test_api_receive_stream_data(bytes, length, fin_or_event,
                ctx->test_stream[stream_index].q_rcv,
                ctx->test_stream[stream_index].q_len,
                ctx->test_stream[stream_index].q_src,
                &ctx->test_stream[stream_index].q_recv_nb,
                &ctx->test_stream[stream_index].q_received,
                &cb_ctx->error_detected);

            if (fin_or_event != 0) {
                if (ctx->test_stream[stream_index].r_len == 0 || fin_or_event == picoquic_callback_stream_reset) {
                    ctx->test_stream[stream_index].r_received = 1;
                    stream_finished = fin_or_event;
                } else if (cb_ctx->error_detected == 0) {
                    /* send a response */
                    if (picoquic_add_to_stream(ctx->cnx_server, stream_id,
                            ctx->test_stream[stream_index].r_src,
                            ctx->test_stream[stream_index].r_len, 1)
                        != 0) {
                        cb_ctx->error_detected |= test_api_fail_cannot_send_response;
                    }
                }
            }
        }
    } else {
        if (cb_ctx->client_mode) {
            /* this is a query from the server to the client */
            test_api_receive_stream_data(bytes, length, fin_or_event,
                ctx->test_stream[stream_index].q_rcv,
                ctx->test_stream[stream_index].q_len,
                ctx->test_stream[stream_index].q_src,
                &ctx->test_stream[stream_index].q_recv_nb,
                &ctx->test_stream[stream_index].q_received,
                &cb_ctx->error_detected);

            if (fin_or_event != 0) {
                if (ctx->test_stream[stream_index].r_len == 0 || fin_or_event == picoquic_callback_stream_reset) {
                    ctx->test_stream[stream_index].r_received = 1;
                    stream_finished = fin_or_event;
                } else if (cb_ctx->error_detected == 0) {
                    /* send a response */
                    if (picoquic_add_to_stream(ctx->cnx_client, stream_id,
                            ctx->test_stream[stream_index].r_src,
                            ctx->test_stream[stream_index].r_len, 1)
                        != 0) {
                        cb_ctx->error_detected |= test_api_fail_cannot_send_response;
                    }
                }
            }
        } else {
            /* this is a response to the server */
            test_api_receive_stream_data(bytes, length, fin_or_event,
                ctx->test_stream[stream_index].r_rcv,
                ctx->test_stream[stream_index].r_len,
                ctx->test_stream[stream_index].r_src,
                &ctx->test_stream[stream_index].r_recv_nb,
                &ctx->test_stream[stream_index].r_received,
                &cb_ctx->error_detected);

            stream_finished = fin_or_event;
        }
    }

    if (stream_finished != 0
        && cb_ctx->error_detected == 0) {
        /* queue the new queries initiated by that stream */
        if (test_api_queue_initial_queries(ctx, stream_id) != 0) {
            cb_ctx->error_detected |= test_api_fail_cannot_send_query;
        }
    }
}

static int test_api_init_send_recv_scenario(picoquic_test_tls_api_ctx_t* test_ctx,
    test_api_stream_desc_t* stream_desc, size_t size_of_scenarios)
{
    int ret = 0;
    size_t nb_stream_desc = size_of_scenarios / sizeof(test_api_stream_desc_t);

    if (nb_stream_desc > PICOQUIC_TEST_MAX_TEST_STREAMS) {
        ret = -1;
    } else {
        test_ctx->nb_test_streams = nb_stream_desc;
        test_ctx->test_finished = 0;

        for (size_t i = 0; ret == 0 && i < nb_stream_desc; i++) {
            ret = test_api_init_test_stream(&test_ctx->test_stream[i],
                stream_desc[i].stream_id, stream_desc[i].previous_stream_id,
                stream_desc[i].q_len, stream_desc[i].r_len);
        }
    }

    if (ret == 0) {
        ret = test_api_queue_initial_queries(test_ctx, 0);
    }

    return ret;
}

static int verify_transport_extension(picoquic_cnx_t* cnx_client, picoquic_cnx_t* cnx_server)
{
    int ret = 0;

    /* verify that local parameters have a sensible value */
    if (cnx_client->local_parameters.idle_timeout == 0 || cnx_client->local_parameters.initial_max_data == 0 || cnx_client->local_parameters.initial_max_stream_data == 0 || cnx_client->local_parameters.max_packet_size == 0) {
        ret = -1;
    } else if (cnx_server->local_parameters.idle_timeout == 0 || cnx_server->local_parameters.initial_max_data == 0 || cnx_server->local_parameters.initial_max_stream_data == 0 || cnx_server->local_parameters.max_packet_size == 0) {
        ret = -1;
    }
    /* Verify that the negotiation completed */
    else if (memcmp(&cnx_client->local_parameters, &cnx_server->remote_parameters,
                 sizeof(picoquic_transport_parameters))
        != 0) {
        ret = -1;
    } else if (memcmp(&cnx_server->local_parameters, &cnx_client->remote_parameters,
                   sizeof(picoquic_transport_parameters))
        != 0) {
        ret = -1;
    }

    return ret;
}

static int verify_sni(picoquic_cnx_t* cnx_client, picoquic_cnx_t* cnx_server,
    char const* sni)
{
    int ret = 0;
    char const* client_sni = picoquic_tls_get_sni(cnx_client);
    char const* server_sni = picoquic_tls_get_sni(cnx_server);

    if (sni == NULL) {
        if (cnx_client->sni != NULL) {
            ret = -1;
        } else if (client_sni != NULL) {
            ret = -1;
        } else if (server_sni != NULL) {
            ret = -1;
        }
    } else {
        if (cnx_client->sni == NULL) {
            ret = -1;
        } else if (client_sni == NULL) {
            ret = -1;
        } else if (server_sni == NULL) {
            ret = -1;
        } else if (strcmp(cnx_client->sni, sni) != 0) {
            ret = -1;
        } else if (strcmp(client_sni, sni) != 0) {
            ret = -1;
        } else if (strcmp(server_sni, sni) != 0) {
            ret = -1;
        }
    }

    return ret;
}

static int verify_alpn(picoquic_cnx_t* cnx_client, picoquic_cnx_t* cnx_server,
    char const* alpn)
{
    int ret = 0;
    char const* client_alpn = picoquic_tls_get_negotiated_alpn(cnx_client);
    char const* server_alpn = picoquic_tls_get_negotiated_alpn(cnx_server);

    if (alpn == NULL) {
        if (cnx_client->alpn != NULL) {
            ret = -1;
        } else if (client_alpn != NULL) {
            ret = -1;
        } else if (server_alpn != NULL) {
            ret = -1;
        }
    } else {
        if (cnx_client->alpn == NULL) {
            ret = -1;
        } else if (client_alpn == NULL) {
            ret = -1;
        } else if (server_alpn == NULL) {
            ret = -1;
        } else if (strcmp(cnx_client->alpn, alpn) != 0) {
            ret = -1;
        } else if (strcmp(client_alpn, alpn) != 0) {
            ret = -1;
        } else if (strcmp(server_alpn, alpn) != 0) {
            ret = -1;
        }
    }

    return ret;
}

static int verify_version(picoquic_cnx_t* cnx_client, picoquic_cnx_t* cnx_server)
{
    int ret = 0;

    if (cnx_client->version_index != cnx_server->version_index) {
        ret = -1;
    } else {
        for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
            if (cnx_client->proposed_version != picoquic_supported_versions[cnx_client->version_index].version && cnx_client->proposed_version == picoquic_supported_versions[i].version) {
                ret = -1;
                break;
            }
        }

        if (ret == 0) {
            if (cnx_client->version_index < 0 || cnx_client->version_index >= (int)picoquic_nb_supported_versions) {
                ret = -1;
            }
        }
    }

    return ret;
}

static void tls_api_delete_ctx(picoquic_test_tls_api_ctx_t* test_ctx)
{
    if (test_ctx->qclient != NULL) {
        picoquic_free(test_ctx->qclient);
    }

    if (test_ctx->qserver != NULL) {
        picoquic_free(test_ctx->qserver);
    }

    for (size_t i = 0; i < test_ctx->nb_test_streams; i++) {
        test_api_delete_test_stream(&test_ctx->test_stream[i]);
    }

    if (test_ctx->c_to_s_link != NULL) {
        picoquictest_sim_link_delete(test_ctx->c_to_s_link);
    }

    if (test_ctx->s_to_c_link != NULL) {
        picoquictest_sim_link_delete(test_ctx->s_to_c_link);
    }
}

static int tls_api_init_ctx(picoquic_test_tls_api_ctx_t** pctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t* p_simulated_time, 
    char const* ticket_file_name, int force_zero_share, int delayed_init)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = (picoquic_test_tls_api_ctx_t*)
        malloc(sizeof(picoquic_test_tls_api_ctx_t));

    *pctx = test_ctx;

    if (test_ctx != NULL) {
        /* Init to NULL */
        memset(test_ctx, 0, sizeof(picoquic_test_tls_api_ctx_t));
        test_ctx->client_callback.client_mode = 1;

        /* Init of the IP addresses */
        memset(&test_ctx->client_addr, 0, sizeof(struct sockaddr_in));
        test_ctx->client_addr.sin_family = AF_INET;
#ifdef _WINDOWS
        test_ctx->client_addr.sin_addr.S_un.S_addr = 0x0A000002;
#else
        test_ctx->client_addr.sin_addr.s_addr = 0x0A000002;
#endif
        test_ctx->client_addr.sin_port = 1234;

        memset(&test_ctx->server_addr, 0, sizeof(struct sockaddr_in));
        test_ctx->server_addr.sin_family = AF_INET;
#ifdef _WINDOWS
        test_ctx->server_addr.sin_addr.S_un.S_addr = 0x0A000001;
#else
        test_ctx->server_addr.sin_addr.s_addr = 0x0A000001;
#endif
        test_ctx->server_addr.sin_port = 4321;

        /* Test the creation of the client and server contexts */
        test_ctx->qclient = picoquic_create(8, NULL, NULL, NULL, test_api_callback,
            (void*)&test_ctx->client_callback, NULL, NULL, NULL, *p_simulated_time,
            p_simulated_time, ticket_file_name, NULL, 0);

        test_ctx->qserver = picoquic_create(8,
#ifdef _WINDOWS
#ifdef _WINDOWS64
            "..\\..\\certs\\cert.pem", "..\\..\\certs\\key.pem",
#else
            "..\\certs\\cert.pem", "..\\certs\\key.pem",
#endif
#else
            "certs/cert.pem", "certs/key.pem",
#endif
            PICOQUIC_TEST_ALPN, test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
            *p_simulated_time, p_simulated_time, NULL,
            test_ticket_encrypt_key, sizeof(test_ticket_encrypt_key));

        if (test_ctx->qclient == NULL || test_ctx->qserver == NULL) {
            ret = -1;
        }

        /* register the links */
        if (ret == 0) {
            test_ctx->c_to_s_link = picoquictest_sim_link_create(0.01, 10000, 0, 0, 0);
            test_ctx->s_to_c_link = picoquictest_sim_link_create(0.01, 10000, 0, 0, 0);

            if (test_ctx->c_to_s_link == NULL || test_ctx->s_to_c_link == NULL) {
                ret = -1;
            }
        }

        if (ret == 0) {
            /* Apply the zero share parameter if required */
            if (force_zero_share != 0)
            {
                test_ctx->qclient->flags |= picoquic_context_client_zero_share;
            }

            /* Create a client connection */
            test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, picoquic_null_connection_id,
                (struct sockaddr*)&test_ctx->server_addr, 0,
                proposed_version, sni, alpn, 1);

            if (test_ctx->cnx_client == NULL) {
                ret = -1;
            }
            else if (delayed_init == 0) {
                ret = picoquic_start_client_cnx(test_ctx->cnx_client);
            }
        }

        if (ret != 0) {
            tls_api_delete_ctx(test_ctx);
            *pctx = NULL;
        }
    }

    return ret;
}

static int tls_api_one_sim_round(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, int* was_active)
{
    int ret = 0;
    picoquictest_sim_link_t* target_link = NULL;

    /* If one of the sources can send a packet, send it, keep time as it */

    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        ret = -1;
    } else {
        picoquic_stateless_packet_t* sp = picoquic_dequeue_stateless_packet(test_ctx->qserver);

        if (sp != NULL) {
            if (sp->length > 0) {
                *simulated_time += 100000;

                *was_active |= 1;

                memcpy(packet->bytes, sp->bytes, sp->length);
                packet->length = sp->length;

                target_link = test_ctx->s_to_c_link;
            }
            picoquic_delete_stateless_packet(sp);
        }

        if (packet->length == 0) {
            /* check whether the client has something to send */
            picoquic_packet* p = picoquic_create_packet();

            if (p == NULL) {
                ret = -1;
            } else {
                if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
                    ret = picoquic_prepare_packet(test_ctx->cnx_client, p, *simulated_time,
                        packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length);
                    if (ret != 0)
                    {
                        /* useless test, but makes it easier to add a breakpoint under debugger */
                        ret = -1;
                    }
                } else {
                    p->length = 0;
                    packet->length = 0;
                }

                if (ret == 0) {
                    if (p->length > 0) {
                        /* queue in c_to_s */
                        target_link = test_ctx->c_to_s_link;
                    } else if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) {
                        ret = picoquic_prepare_packet(test_ctx->cnx_server, p, *simulated_time,
                            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length);
                        if (ret == 0 && p->length > 0) {
                            /* copy and queue in s to c */
                            target_link = test_ctx->s_to_c_link;
                        }
                        if (ret != 0)
                        {
                            /* useless test, but makes it easier to add a breakpoint under debugger */
                            ret = -1;
                        }
                    }
                }
            }
        }

        if (packet->length > 0) {
            picoquictest_sim_link_submit(target_link, packet, *simulated_time);
            *was_active |= 1;
        } else {
            uint64_t next_time = *simulated_time += 5000;
            uint64_t client_arrival, server_arrival;

            free(packet);

            if (test_ctx->cnx_client != NULL && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
                if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state != picoquic_state_disconnected && test_ctx->cnx_server->next_wake_time < test_ctx->cnx_client->next_wake_time) {
                    next_time = test_ctx->cnx_server->next_wake_time;
                } else {
                    next_time = test_ctx->cnx_client->next_wake_time;
                }
            } else if (test_ctx->cnx_server != NULL && test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) {
                next_time = test_ctx->cnx_server->next_wake_time;
            }

            if (next_time < *simulated_time + 5000) {
                next_time = *simulated_time + 5000;
            }

            client_arrival = picoquictest_sim_link_next_arrival(test_ctx->s_to_c_link, next_time);
            server_arrival = picoquictest_sim_link_next_arrival(test_ctx->c_to_s_link, next_time);

            if (client_arrival < server_arrival && client_arrival < next_time && (packet = picoquictest_sim_link_dequeue(test_ctx->s_to_c_link, client_arrival)) != NULL) {
                next_time = client_arrival;
                *simulated_time = next_time;

                ret = picoquic_incoming_packet(test_ctx->qclient, packet->bytes, (uint32_t)packet->length,
                    (struct sockaddr*)&test_ctx->server_addr,
                    (struct sockaddr*)&test_ctx->client_addr, 0,
                    *simulated_time);
                *was_active |= 1;

                if (ret != 0)
                {
                    /* useless test, but makes it easier to add a breakpoint under debugger */
                    ret = -1;
                }
            } else if (server_arrival < next_time && (packet = picoquictest_sim_link_dequeue(test_ctx->c_to_s_link, server_arrival)) != NULL) {

                next_time = server_arrival;
                *simulated_time = next_time;

                ret = picoquic_incoming_packet(test_ctx->qserver, packet->bytes, (uint32_t)packet->length,
                    (struct sockaddr*)&test_ctx->client_addr,
                    (struct sockaddr*)&test_ctx->server_addr, 0,
                    *simulated_time);


                if (ret != 0)
                {
                    /* useless test, but makes it easier to add a breakpoint under debugger */
                    ret = -1;
                }

                if (test_ctx->cnx_server == NULL) {
                    picoquic_connection_id_t target_cnxid = test_ctx->cnx_client->initial_cnxid;
                    picoquic_cnx_t* next = test_ctx->qserver->cnx_list;

                    while (next != NULL && picoquic_compare_connection_id(&next->initial_cnxid, &target_cnxid)!=0) {
                        next = next->next_in_table;
                    }

                    test_ctx->cnx_server = next;
                }

                *was_active |= 1;
            } else {
                *simulated_time = next_time;
            }
        }
    }

    return ret;
}

static int tls_api_connection_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t* simulated_time)
{
    int ret = 0;
    int nb_trials = 0;
    int nb_inactive = 0;

    test_ctx->c_to_s_link->loss_mask = loss_mask;
    test_ctx->s_to_c_link->loss_mask = loss_mask;

    test_ctx->c_to_s_link->queue_delay_max = queue_delay_max;
    test_ctx->s_to_c_link->queue_delay_max = queue_delay_max;

    while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 && (test_ctx->cnx_client->cnx_state != picoquic_state_client_ready || (test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state != picoquic_state_server_ready))) {
        int was_active = 0;
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, &was_active);

        if (was_active) {
            nb_inactive = 0;
        } else {
            nb_inactive++;
        }
    }

    return ret;
}

static int tls_api_data_sending_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t* simulated_time, int max_trials)
{
    int ret = 0;
    int nb_trials = 0;
    int nb_inactive = 0;

    test_ctx->c_to_s_link->loss_mask = loss_mask;
    test_ctx->s_to_c_link->loss_mask = loss_mask;

    if (max_trials <= 0) {
        max_trials = 100000;
    }

    while (ret == 0 && nb_trials < max_trials && nb_inactive < 256 && test_ctx->cnx_client->cnx_state == picoquic_state_client_ready && test_ctx->cnx_server->cnx_state == picoquic_state_server_ready) {
        int was_active = 0;

        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, &was_active);

        if (ret < 0)
        {
            break;
        }

        if (was_active) {
            nb_inactive = 0;
        } else {
            nb_inactive++;
        }

        if (test_ctx->test_finished) {
            if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                break;
            }
        }
    }

    return ret; /* end of sending loop */
}

static int tls_api_attempt_to_close(
    picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time)
{
    int ret = 0;
    int nb_rounds = 0;

    ret = picoquic_close(test_ctx->cnx_client, 0);

    if (ret == 0) {
        /* packet from client to server */
        /* Do not simulate losses there, as there is no way to correct them */

        test_ctx->c_to_s_link->loss_mask = 0;
        test_ctx->s_to_c_link->loss_mask = 0;

        while (ret == 0 && (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected || test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) && nb_rounds < 256) {
            int was_active = 0;
            ret = tls_api_one_sim_round(test_ctx, simulated_time, &was_active);
            nb_rounds++;
        }
    }

    if (ret == 0 && (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected || test_ctx->cnx_server->cnx_state != picoquic_state_disconnected)) {
        ret = -1;
    }

    return ret;
}

static int tls_api_test_with_loss(uint64_t* loss_mask, uint32_t proposed_version,
    char const* sni, char const* alpn)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, proposed_version, sni, alpn, &simulated_time, NULL, 0, 0);

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", proposed_version);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, loss_mask, 0, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection close returns %d\n", ret);
        }

        if (ret == 0) {
            ret = verify_transport_extension(test_ctx->cnx_client, test_ctx->cnx_server);
            if (ret != 0)
            {
                DBG_PRINTF("%s", "Transport extensions do no match\n");
            }
        }

        if (ret == 0) {
            ret = verify_sni(test_ctx->cnx_client, test_ctx->cnx_server, sni);

            if (ret != 0)
            {
                DBG_PRINTF("%s", "SNI do not match\n");
            }
        }

        if (ret == 0) {
            ret = verify_alpn(test_ctx->cnx_client, test_ctx->cnx_server, alpn);

            if (ret != 0)
            {
                DBG_PRINTF("%s", "ALPN do not match\n");
            }
        }

        if (ret == 0) {
            ret = verify_version(test_ctx->cnx_client, test_ctx->cnx_server);

            if (ret != 0)
            {
                DBG_PRINTF("%s", "Negotiated versions do not match\n");
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_test()
{
    return tls_api_test_with_loss(NULL, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL);
}

int tls_api_silence_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    uint64_t next_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, NULL, NULL, &simulated_time, NULL, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* simulate 5 seconds of silence */
    next_time = simulated_time + 5000000;
    while (ret == 0 && simulated_time < next_time && test_ctx->cnx_client->cnx_state == picoquic_state_client_ready && test_ctx->cnx_server->cnx_state == picoquic_state_server_ready) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, &was_active);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (ret == 0) {
        /* verify the absence of any spurious retransmission */
        if (test_ctx->cnx_client->nb_retransmission_total != 0) {
            ret = -1;
        } else if (test_ctx->cnx_server->nb_retransmission_total != 0) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_loss_test(uint64_t mask)
{
    uint64_t loss_mask = mask;

    return tls_api_test_with_loss(&loss_mask, 0, NULL, NULL);
}

int tls_api_many_losses()
{
    uint64_t loss_mask = 0;
    int ret = 0;

    for (uint64_t i = 0; ret == 0 && i < 6; i++) {
        for (uint64_t j = 1; ret == 0 && j < 4; j++) {
            loss_mask = ((1 << j) - 1) << i;
            ret = tls_api_test_with_loss(&loss_mask, 0, NULL, NULL);
        }
    }

    return ret;
}

int tls_api_version_negotiation_test()
{
    const uint32_t version_grease = 0x0aca4a0a;
    return tls_api_test_with_loss(NULL, version_grease, NULL, NULL);
}

int tls_api_sni_test()
{
    return tls_api_test_with_loss(NULL, 0, PICOQUIC_TEST_SNI, NULL);
}

int tls_api_alpn_test()
{
    return tls_api_test_with_loss(NULL, 0, NULL, PICOQUIC_TEST_ALPN);
}

int tls_api_wrong_alpn_test()
{
    return tls_api_test_with_loss(NULL, 0, NULL, PICOQUIC_TEST_WRONG_ALPN);
}

/*
 * Scenario based transmission tests.
 */

int tls_api_one_scenario_test(test_api_stream_desc_t* scenario,
    size_t sizeof_scenario, uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max,
    uint32_t proposed_version, uint64_t max_completion_microsec,
    picoquic_transport_parameters * client_params)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx,
        (proposed_version == 0) ? PICOQUIC_INTERNAL_TEST_VERSION_1 : proposed_version,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 0, 1);

    if (ret != 0)
    {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", proposed_version);
    }

    if (ret == 0 && client_params != NULL) {
        picoquic_set_transport_parameters(test_ctx->cnx_client, client_params);
    }

    if (ret == 0) {
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        if (ret != 0)
        {
            DBG_PRINTF("%s", "Could not initialize stream zero for the client\n");
        }

    }
         
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, queue_delay_max, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns error %d\n", ret);
        }
    }

    if (ret == 0 && max_data != 0) {
        test_ctx->cnx_client->maxdata_local = max_data;
        test_ctx->cnx_client->maxdata_remote = max_data;
        test_ctx->cnx_server->maxdata_local = max_data;
        test_ctx->cnx_server->maxdata_remote = max_data;
    }

    /* Prepare to send data */
    if (ret == 0) {
        loss_mask = init_loss_mask;
        ret = test_api_init_send_recv_scenario(test_ctx, scenario, sizeof_scenario);

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        if (test_ctx->server_callback.error_detected) {
            ret = -1;
        } else if (test_ctx->client_callback.error_detected) {
            ret = -1;
        } else {
            for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++) {
                if (test_ctx->test_stream[i].q_recv_nb != test_ctx->test_stream[i].q_len) {
                    ret = -1;
                } else if (test_ctx->test_stream[i].r_recv_nb != test_ctx->test_stream[i].r_len) {
                    ret = -1;
                } else if (test_ctx->test_stream[i].q_received == 0 || test_ctx->test_stream[i].r_received == 0) {
                    ret = -1;
                }
            }
        }
        if (ret != 0)
        {
            DBG_PRINTF("Test scenario verification returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = picoquic_close(test_ctx->cnx_client, 0);
        if (ret != 0)
        {
            DBG_PRINTF("Picoquic close returns %d\n", ret);
        }
    }

    if (ret == 0 && max_completion_microsec != 0) {
        if (simulated_time > max_completion_microsec)
        {
            DBG_PRINTF("Scenario completes in %llu microsec, more than %llu\n", simulated_time, max_completion_microsec);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_oneway_stream_test()
{
    return tls_api_one_scenario_test(test_scenario_oneway, sizeof(test_scenario_oneway), 0, 0, 0, 0, 65000, NULL);
}

int tls_api_q_and_r_stream_test()
{
    return tls_api_one_scenario_test(test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 0, 75000, NULL);
}

int tls_api_q2_and_r2_stream_test()
{
    return tls_api_one_scenario_test(test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2), 0, 0, 0, 0, 75000, NULL);
}

int tls_api_very_long_stream_test()
{
    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 0, 1500000, NULL);
}

int tls_api_very_long_max_test()
{
    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 128000, 0, 0, 1500000, NULL);
}

int tls_api_very_long_with_err_test()
{
    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0x30000, 128000, 0, 0, 4400000, NULL);
}

int tls_api_very_long_congestion_test()
{
    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 128000, 20000, 0, 1500000, NULL);
}

int unidir_test()
{
    return tls_api_one_scenario_test(test_scenario_unidir, sizeof(test_scenario_unidir), 0, 128000, 10000, 0, 75000, NULL);
}

/*
 * Server reset test.
 * Establish a connection between server and client.
 * When the connection is established, delete the server connection, and prime the client
 * to send data.
 * Expected result: the client sends a packet with a stream frame, the server responds
 * with a stateless reset, the client closes its own connection.
 */

int tls_api_server_reset_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 0, 0);
    uint8_t buffer[128];
    int was_active = 0;

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* verify that client and server have the same reset secret */
    if (ret == 0 && memcmp(test_ctx->cnx_client->reset_secret, test_ctx->cnx_server->reset_secret, PICOQUIC_RESET_SECRET_SIZE) != 0) {
        ret = -1;
    }

    /* Prepare to reset */
    if (ret == 0) {
        picoquic_delete_cnx(test_ctx->cnx_server);
        test_ctx->cnx_server = NULL;

        memset(buffer, 0xaa, sizeof(buffer));
        ret = picoquic_add_to_stream(test_ctx->cnx_client, 4,
            buffer, sizeof(buffer), 1);
    }

    /* Perform a couple rounds of sending data */
    for (int i = 0; ret == 0 && i < 64 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected; i++) {
        was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, &was_active);
    }

    /* Client should now be in state disconnected */
    if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
* Server reset negative test.
* Establish a connection between server and client.
* When the connection is established, fabricate a bogus server reset and
* send it to the client.
* Expected result: the client ignores the bogus reset.
*/
int tls_api_bad_server_reset_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 0, 0);
    uint8_t buffer[128];

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare the bogus reset */
    if (ret == 0) {
        size_t byte_index = 0;
        buffer[byte_index++] = 0x41;
        byte_index += picoquic_format_connection_id(&buffer[byte_index], test_ctx->cnx_client->server_cnxid);
        memset(buffer + byte_index, 0xcc, sizeof(buffer) - byte_index);
    }

    /* Submit bogus request to client */
    if (ret == 0) {
        ret = picoquic_incoming_packet(test_ctx->qclient, buffer, sizeof(buffer),
            (struct sockaddr*)(&test_ctx->server_addr),
            (struct sockaddr*)(&test_ctx->client_addr), 0,
            simulated_time);
    }

    /* check that the client is still up */
    if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_client_ready) {
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * verify that a connection is correctly established after a stateless redirect
 */

int tls_api_hrr_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 0, 0);

    if (ret == 0) {
        /* Set the server in HRR/Cookies mode */
        picoquic_set_cookie_mode(test_ctx->qserver, 1);
        /* Try the connection */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
* verify that a connection is correctly established
* if the client does not initially provide a key share
*/

int tls_zero_share_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 1, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}


/*
 * Test two successive connections from the same client.
 */

int tls_api_two_connections_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, NULL, "test-alpn", &simulated_time, NULL, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        /* Verify that the connection is fully established */
        uint64_t target_time = simulated_time + 2000000;

        while (ret == 0 && test_ctx->cnx_client->cnx_state == picoquic_state_client_ready && test_ctx->cnx_server->cnx_state == picoquic_state_server_ready && simulated_time < target_time) {
            int was_active = 0;
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, &was_active);
        }

        /* Delete the client connection from the client context,
         * without sending notification to the server */
        while (test_ctx->qclient->cnx_list != NULL) {
            picoquic_delete_cnx(test_ctx->qclient->cnx_list);
        }

        /* Erase the server connection reference */
        test_ctx->cnx_server = NULL;

        /* Create a new connection in the client context */

        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, picoquic_null_connection_id,
            (struct sockaddr*)&test_ctx->server_addr, simulated_time, 0, NULL, "test-alpn", 1);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    /* Now, restart a connection in the same context */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int tls_api_client_first_loss_test()
{
    return tls_api_loss_test(1ull);
}

int tls_api_client_second_loss_test()
{
    return tls_api_loss_test(2ull);
}

int tls_api_server_first_loss_test()
{
    return tls_api_loss_test(14ull);
}

int tls_api_client_losses_test()
{
    return tls_api_loss_test(3ull);
}

int tls_api_server_losses_test()
{
    return tls_api_loss_test(6ull);
}

/*
 * Do a simple test for all supported versions
 */
int tls_api_multiple_versions_test()
{
    int ret = 0;

    for (size_t i = 1; ret == 0 && i < picoquic_nb_supported_versions; i++) {
        ret = tls_api_one_scenario_test(test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0,
            picoquic_supported_versions[i].version, 0, NULL);
    }

    return ret;
}

/*
 * Keep alive test.
 */

int keep_alive_test_impl(int keep_alive)
{
    uint64_t simulated_time = 0;
    const uint64_t keep_alive_interval = 0; /* Will use the default value */
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 0, 0);
    int was_active = 0;

    /*
     * setup the connections.
     */

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /*
     * Enable keep alive
     */
    if (ret == 0 && keep_alive) {
        picoquic_enable_keep_alive(test_ctx->cnx_client, keep_alive_interval);
    }

    /* Perform rounds of sending data until the requested time has been spent */
    for (int i = 0; ret == 0 && i < 0x10000 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected ; i++) {
        was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, &was_active);
        if (simulated_time > 2 * PICOQUIC_MICROSEC_SILENCE_MAX) {
            break;
        }
    }

    /* Check that the status matched the expected value */
    if (keep_alive != 0) {
        if (test_ctx->cnx_client->cnx_state != picoquic_state_client_ready) {
            ret = -1;
        } else if (simulated_time < 2 * PICOQUIC_MICROSEC_SILENCE_MAX) {
            DBG_PRINTF("Keep alive test concludes after %llu microsecs instead of %llu, ret = %d\n",
                (unsigned long long)simulated_time, (unsigned long long)2 * PICOQUIC_MICROSEC_SILENCE_MAX, ret);
            ret = -1;
        } 
    } else if (keep_alive == 0) {
        /* If keep alive was not activated, reset ret to `0`, as `tls_api_one_sim_round` returns -1
         * when the connection was disconnected.
         */
        ret = test_ctx->cnx_client->cnx_state != picoquic_state_disconnected;
    }

    /* Close the connection */
    if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    /* Clean up */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int keep_alive_test()
{
    int ret = keep_alive_test_impl(1);

    if (ret == 0) {
        ret = keep_alive_test_impl(0);
    }

    return ret;
}

/*
 * Ping pong test.
 */

typedef struct st_ping_pong_test_callback_ctx_t {
    picoquic_stream_data_cb_fn master_fn;
    void* master_ctx;
    int pong_received;
    int error_received;
    size_t ping_length;
    uint8_t ping_frame[256];
} ping_pong_test_callback_ctx_t;

static void ping_pong_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    ping_pong_test_callback_ctx_t* ping_pong_ctx = (ping_pong_test_callback_ctx_t*)callback_ctx;
    if (stream_id == 0 && fin_or_event == 0) {
        /* This is a special frame call back. */
        if (length == ping_pong_ctx->ping_length && bytes[0] == picoquic_frame_type_path_response && memcmp(bytes + 1, &ping_pong_ctx->ping_frame[1], length - 1) == 0) {
            ping_pong_ctx->pong_received++;
        } else {
            ping_pong_ctx->error_received++;
        }
    } else if (ping_pong_ctx->master_fn != NULL) {
        ping_pong_ctx->master_fn(cnx, stream_id, bytes, length, fin_or_event, ping_pong_ctx->master_ctx);
    }
}

int ping_pong_test()
{
    ping_pong_test_callback_ctx_t ping_pong_ctx;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 0, 0);
    int was_active = 0;

    /*
     * Before initializing the context, set up a filter to intercept the call backs.
     */
    if (ret == 0) {
        memset(&ping_pong_ctx, 0, sizeof(ping_pong_test_callback_ctx_t));
        ping_pong_ctx.master_ctx = test_ctx->cnx_client->callback_ctx;
        ping_pong_ctx.master_fn = test_ctx->cnx_client->callback_fn;
        test_ctx->cnx_client->callback_ctx = &ping_pong_ctx;
        test_ctx->cnx_client->callback_fn = ping_pong_callback;
    }

    /*
     * setup the connections.
     */

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /*
     * Format and queue the ping frame
     * TODO: change these names to path challenge
     */
    if (ret == 0) {
        ping_pong_ctx.ping_length = 9;
        ping_pong_ctx.ping_frame[0] = picoquic_frame_type_path_challenge;
        for (uint8_t i = 1; i < 9; i++) {
            ping_pong_ctx.ping_frame[i] = 'a' + i - 2;
        }

        ret = picoquic_queue_misc_frame(test_ctx->cnx_client, ping_pong_ctx.ping_frame, ping_pong_ctx.ping_length);
    }

    /* Perform a couple rounds of sending data */
    for (int i = 0; ret == 0 && i < 32 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected; i++) {
        was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, &was_active);

        if (ping_pong_ctx.pong_received != 0 && picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
            break;
        }
    }

    /* Check that there was exactly one matching pong received */
    if (ret == 0 && (ping_pong_ctx.error_received != 0 || ping_pong_ctx.pong_received != 1)) {
        ret = -1;
    }

    /* Close the connection */
    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    /* Verify that no error was received during closing */
    if (ret == 0 && (ping_pong_ctx.error_received != 0 || ping_pong_ctx.pong_received != 1)) {
        ret = -1;
    }

    /* Clean up */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * In this test, the client attempts to setup a connection, but deliberately 
 * introduces an error in the transport parameters -- in our case, an illegal
 * max stream ID. This should cause the connection to fail.
 */
int transport_parameter_client_error_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_ERRONEOUS_SNI, "test-alpn", &simulated_time, NULL, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        } else if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
            ret = -1;
        } else if (
            test_ctx->cnx_client->remote_error != PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR) {
            ret = -1;
        } else {
            ret = 0;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Session resume test.
 */
static char const* ticket_file_name = "resume_tests_tickets.bin";

int session_resume_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char const* sni = "test-sni";
    char const* alpn = "test-alpn";
    uint64_t loss_mask = 0;
    int ret = 0;

    /* Initialize an empty ticket store */
    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file_name);

    for (int i = 0; i < 2; i++) {
        /* Set up the context, while setting the ticket store parameter for the client */
        if (ret == 0) {
            ret = tls_api_init_ctx(&test_ctx, 0, sni, alpn, &simulated_time, ticket_file_name, 0, 0);
        }

        if (ret == 0) {
            ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
        }

        if (ret == 0 && i == 1) {
            /* If resume succeeded, the second connection will have a type "PSK" */
            if (picoquic_tls_is_psk_handshake(test_ctx->cnx_server) == 0 || picoquic_tls_is_psk_handshake(test_ctx->cnx_client) == 0) {
                ret = -1;
            }
        }

        if (ret == 0) {
            ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
        }

        /* Verify that the session ticket has been received correctly */
        if (ret == 0) {
            if (test_ctx->qclient->p_first_ticket == NULL) {
                ret = -1;
            } else {
                ret = picoquic_save_tickets(test_ctx->qclient->p_first_ticket, simulated_time, ticket_file_name);
            }
        }
        /* Tear down and free everything */

        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
            test_ctx = NULL;
        }
    }

    return ret;
}

/*
 * Zero RTT test. Like the session resume test, but with a twist...
 */
int zero_rtt_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char const* sni = "test-sni";
    char const* alpn = "test-alpn";
    uint64_t loss_mask = 0;
    int ret = 0;

    /* Initialize an empty ticket store */
    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file_name);

    for (int i = 0; i < 2; i++) {
        /* Set up the context, while setting the ticket store parameter for the client */
        if (ret == 0) {
            ret = tls_api_init_ctx(&test_ctx, 0, sni, alpn, &simulated_time, ticket_file_name, 0, 0);
        }

        if (ret == 0 && i == 1) {
            /* set the link delays to 100 ms, for realistic testing */
            if (ret == 0) {
                test_ctx->c_to_s_link->microsec_latency = 100000;
                test_ctx->s_to_c_link->microsec_latency = 100000;
            }

            /* Queue an initial frame on the client connection */
            uint8_t ping_frame[2] = { picoquic_frame_type_ping, 0 };

            picoquic_queue_misc_frame(test_ctx->cnx_client, ping_frame, 2);
        }

        if (ret == 0) {
            ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
        }

        if (ret == 0 && i == 1) {
            /* If resume succeeded, the second connection will have a type "PSK" */
            if (picoquic_tls_is_psk_handshake(test_ctx->cnx_server) == 0 || picoquic_tls_is_psk_handshake(test_ctx->cnx_client) == 0) {
                ret = -1;
            } else {
                /* run a receive loop until no outstanding data */
                for (int i = 0; ret == 0 && i < 32 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected; i++) {
                    int was_active = 0;

                    ret = tls_api_one_sim_round(test_ctx, &simulated_time, &was_active);

                    if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                        break;
                    }
                }
            }
        }

        if (ret == 0) {
            ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
        }

        /* Verify that the 0RTT data was sent and acknowledged */
        if (ret == 0 && i == 1) {
            if (test_ctx->cnx_client->nb_zero_rtt_sent == 0) {
                ret = -1;
            } else if (test_ctx->cnx_client->nb_zero_rtt_acked != test_ctx->cnx_client->nb_zero_rtt_sent) {
                ret = -1;
            }
        }

        /* Verify that the session ticket has been received correctly */
        if (ret == 0) {
            if (test_ctx->qclient->p_first_ticket == NULL) {
                ret = -1;
            } else {
                ret = picoquic_save_tickets(test_ctx->qclient->p_first_ticket, simulated_time, ticket_file_name);
            }
        }

        /* Tear down and free everything */
        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
            test_ctx = NULL;
        }
    }

    return ret;
}

/*
 * Stop sending test. Start a long transmission, but after receiving some bytes,
 * send a stop sending request. Then ask for another transmission. The
 * test succeeds if only few bytes of the first are received, and all bytes
 * of the second.
 */

int stop_sending_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 0, 0);
    int nb_initial_loop = 0;

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_stop_sending, sizeof(test_scenario_stop_sending));
    }

    /* Perform a data sending loop for a few rounds, until some bytes are received on the first stream */
    while (ret == 0 && nb_initial_loop < 64) {
        nb_initial_loop++;

        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 16);

        if (test_ctx->test_stream[0].r_recv_nb != 0) {
            break;
        }
    }

    /* issue the stop sending command */
    if (ret == 0 && test_ctx->cnx_client != NULL) {
        ret = picoquic_stop_sending(test_ctx->cnx_client, test_scenario_stop_sending[0].stream_id, 1);
    }

    /* resume the sending scenario */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    if (ret == 0) {
        if (test_ctx->server_callback.error_detected) {
            ret = -1;
        } else if (test_ctx->client_callback.error_detected) {
            ret = -1;
        } else {
            for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++) {
                if (test_ctx->test_stream[i].q_recv_nb != test_ctx->test_stream[i].q_len) {
                    ret = -1;
                } else if (i == 0 && test_ctx->test_stream[i].r_recv_nb == test_ctx->test_stream[i].r_len) {
                    ret = -1;
                } else if (i != 0 && test_ctx->test_stream[i].r_recv_nb != test_ctx->test_stream[i].r_len) {
                    ret = -1;
                } else if (test_ctx->test_stream[i].q_received == 0 || test_ctx->test_stream[i].r_received == 0) {
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0) {
        ret = picoquic_close(test_ctx->cnx_client, 0);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
* MTU discovery test. Perform a moderate transmission.
* Verify that MTU was properly set to expected value
*/

int mtu_discovery_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_mtu_discovery, sizeof(test_scenario_mtu_discovery));
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    if (ret == 0) {
        if (test_ctx->cnx_client->path[0]->send_mtu != test_ctx->cnx_server->local_parameters.max_packet_size) {
            ret = -1;
        } else if (test_ctx->cnx_server->path[0]->send_mtu != test_ctx->cnx_client->local_parameters.max_packet_size) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Trying to reproduce the scenario that resulted in
 * spurious retransmissions,and checking that it is fixed.
 */

int spurious_retransmit_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    uint64_t next_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, NULL, NULL, &simulated_time, NULL, 0, 0);

    if (ret == 0) {
        test_ctx->c_to_s_link->microsec_latency = 50000;
        test_ctx->s_to_c_link->microsec_latency = 50000;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* simulate 1 second of silence */
    next_time = simulated_time + 1000000;
    while (ret == 0 && simulated_time < next_time && test_ctx->cnx_client->cnx_state == picoquic_state_client_ready && test_ctx->cnx_server->cnx_state == picoquic_state_server_ready) {
        int was_active = 0;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, &was_active);
    }

    if (ret == 0) {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (ret == 0) {
        /* verify the absence of any spurious retransmission */
        if (test_ctx->cnx_client->nb_spurious != 0) {
            ret = -1;
        } else if (test_ctx->cnx_server->nb_spurious != 0) {
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Test whether the server correctly sends an HRR in response to a 
 * Client Hello proposing an unsupported key share.
 */

static uint8_t clientHello25519[] = {
    /* Stream 0 header, including length */
    0x12, 0x00, 0x41, 0x29,
    /* TLS Record Header, end with 2 bytes length*/
    0x16, 0x03, 0x03, 0x01, 0x24,
    /* Handshake protocol header for CH, end with 3 bytes length */
    0x01, 0x00, 0x01, 0x20,
    /* CH length 73 + extensions 209 = 282, 0x0120 */
    /* Legacy version ID*/
    0x03, 0x03,
    /* Client random, 32 bytes*/
    0xc4, 0xe2, 0xea, 0xb7, 0xcc, 0x4b, 0xbb, 0x43, 0x7d, 0xfa, 
    0xb4, 0x7c, 0xa5, 0x6a, 0xf8, 0xa0, 0xdb, 0x07, 0x2b, 0x90,
    0xa4, 0x9f, 0xac, 0x89, 0x84, 0x9c, 0x10, 0xb2, 0xa5, 0x6a,
    0x7d, 0xfa,
    /* Legacy session ID l=32 + 32 bytes */
    0x20, 
    0xf8, 0xa0, 0xdb, 0x07, 0x2b, 0x90, 0xe5, 0x36, 0xf9, 0xc4, 
    0xa4, 0x9f, 0xac, 0x89, 0x84, 0x9c, 0x10, 0xb2, 0xa5, 0x6a,
    0xb4, 0x7c, 0xa5, 0x6a, 0xf8, 0xa0, 0xdb, 0x07, 0x2b, 0x90,
    0x7d, 0xfa,
    /* Cipher suites */ 
    0x00, 0x06, 0x13, 0x01, 0x13, 0x03, 0x13, 0x02,
    /* Legacy compression methods */
    0x01, 0x00,
    /* End of CH after extension length */
    0x00, 0xd1,
    /* Series of extenstion, 2 bytes type + 2 bytes length, total = 209 */
    /* Extension type 0, SNI, 15 bytes */
    0x00, 0x00, 0x00, 0x0b,
    0x00, 0x09, 0x00, 0x00, 0x06, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72,
    /* Extension type 16, ALPN, 12 bytes */
    /* TODO: update hq-09 to supported version */
    0x00, 0x10, 0x00, 0x08,
    0x00, 0x06, 0x05, 0x68, 0x71, 0x2d, 0x30, 0x39,
    /* Some extended value, 5 bytes */
    0xff, 0x01, 0x00, 0x01, 0x00,
    /* Extension type 10, Supported groups, 24 bytes */
    0x00, 0x0a, 0x00, 0x14, 0x00, 0x12,
    0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01,
    0x01, 0x02, 0x01, 0x03, 0x01, 0x04,
    /* Extension type 35, 4 bytes. */
    0x00, 0x23, 0x00, 0x00,
    /* Extension type 51, key share, 42 bytes for X25519 */
    0x00, 0x33, 0x00, 0x26, 0x00, 0x24,
    0x00, 0x1d,
    0x00, 0x20,
    0x78, 0xe5, 0x89, 0x74, 0x13, 0xf1, 0x71, 0x53, 0xc7, 0x0c, 0xf3, 0x3f,
    0xa3, 0x4c, 0x84, 0x97, 0x72, 0x4b, 0xda, 0xb4, 0xf5, 0x7f, 0x9d, 0x01,
    0xc9, 0x53, 0xf5, 0x88, 0xf0, 0x30, 0x46, 0x61,
    /* Extension type 43, supported_versions, 7 bytes */
    /* (TODO: update from 0x7F-0x17 to next supported draft) */
    0x00, 0x2b, 0x00, 0x03, 0x02, 0x7f, 0x17,
    /* Extension type 13, signature_algorithms, 36 bytes */
    0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e,
    0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05,
    0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x02,
    0x05, 0x02, 0x06, 0x02, 0x02, 0x02,
    /* Extension type 45, psk_key_exchange_modes, 6 bytes */
    0x00, 0x2d, 0x00, 0x02, 0x01, 0x01,
    /* Extension type 26, QUIC transport parameters, 58 bytes */
    0x00, 0x1a, 0x00, 0x36,
    0xff, 0x00, 0x00, 0x08, 0x00, 0x30, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x01, 0x00, 0x04, 0x00, 0x10, 0x00, 0x00, 0x00, 0x02,
    0x00, 0x04, 0x00, 0x00, 0xff, 0xfd, 0x00, 0x03, 0x00, 0x02, 0x00, 0x1e,
    0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x02, 0x05, 0xc8, 0x00, 0x08,
    0x00, 0x04, 0x00, 0x00, 0xff, 0xff
};

int wrong_keyshare_test()
{
    picoquic_quic_t* qserver = NULL;
    picoquic_cnx_t* cnx;
    test_api_callback_t server_callback;
    uint64_t simulated_time = 0;
    picoquic_connection_id_t cnx_id; 
    struct sockaddr_in addr_from;
    int ret = 0;

    /* TODO: find a better way to initialize CID from value */
    cnx_id.opaque64 = 0x0102030405060708ull;

    qserver = picoquic_create(8,
#ifdef _WINDOWS
#ifdef _WINDOWS64
        "..\\..\\certs\\cert.pem", "..\\..\\certs\\key.pem",
#else
        "..\\certs\\cert.pem", "..\\certs\\key.pem",
#endif
#else
        "certs/cert.pem", "certs/key.pem",
#endif
        PICOQUIC_TEST_ALPN, test_api_callback, (void*)&server_callback, NULL, NULL, NULL,
        simulated_time, &simulated_time, NULL,
        test_ticket_encrypt_key, sizeof(test_ticket_encrypt_key));

    if (qserver == NULL) {
        ret = -1;
    } else {
        /* Simulate an incoming client initial packet */
        memset(&addr_from, 0, sizeof(struct sockaddr_in));
        addr_from.sin_family = AF_INET;
#ifdef _WINDOWS
        addr_from.sin_addr.S_un.S_addr = 0x0A000001;
#else
        addr_from.sin_addr.s_addr = 0x0A000001;
#endif
        addr_from.sin_port = 4321;

        cnx = picoquic_create_cnx(qserver, cnx_id,
            (struct sockaddr*)&addr_from, simulated_time,
            PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, 0);

        if (cnx == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = picoquic_decode_frames(cnx,
            clientHello25519, sizeof(clientHello25519), 1, simulated_time);

        /* processing of client initial packet */
        if (ret == 0) {
            /* We do expect that the server will be ready to send an HRR */
            ret = picoquic_tlsinput_stream_zero(cnx);

            if (cnx->cnx_state != picoquic_state_server_send_hrr) {
                ret = -1;
            } else {
                /* check that the message queue on stream 0 is proper HRR */
                if (cnx->first_stream.stream_id != 0 || cnx->first_stream.send_queue == NULL || cnx->first_stream.send_queue->length == 0 || cnx->first_stream.send_queue->bytes == NULL) {
                    ret = -1;
                } else if (cnx->first_stream.send_queue->length <= 49 || cnx->first_stream.send_queue->bytes[0] != 0x16 || cnx->first_stream.send_queue->bytes[5] != 0x02) {
                    ret = -1;
                }
            }
        }

        if (ret == 0) {
            /* Simulate preparing an HRR */
            picoquic_packet_header ph;
            picoquic_stateless_packet_t* sp = NULL;

            memset(&ph, 0, sizeof(ph));
            ph.cnx_id = cnx_id;
            ph.vn = PICOQUIC_INTERNAL_TEST_VERSION_1;

            picoquic_queue_stateless_reset(cnx, &ph,
                (struct sockaddr*)&addr_from,
                (struct sockaddr*)&addr_from, 0);

            cnx->cnx_state = picoquic_state_disconnected;

            sp = picoquic_dequeue_stateless_packet(qserver);

            if (sp == NULL) {
                ret = -1;
            } else {
                picoquic_delete_stateless_packet(sp);
            }
        }
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

/*
* Set up a connection, and verify
* that the key generated for PN encryption on
* client and server produce the correct results.
*/

int pn_enc_1rtt_test()
{
    uint64_t loss_mask = 0;
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, NULL, NULL, &simulated_time, NULL, 0, 0);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0)
    {
        /* Try to encrypt a sequence number */
        if (ret == 0) {
            uint8_t seq_num_1[4] = { 0xde, 0xad, 0xbe, 0xef };
            uint8_t sample_1[16] = {
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
            uint8_t seq_num_2[4] = { 0xba, 0xba, 0xc0, 0x0l };
            uint8_t sample_2[16] = {
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96 };

            for (int i = 1; i < 4; i *= 2)
            {
                ret = test_one_pn_enc_pair(seq_num_1, 4, test_ctx->cnx_client->pn_enc, test_ctx->cnx_server->pn_dec, sample_1);

                if (ret == 0)
                {
                    ret = test_one_pn_enc_pair(seq_num_2, 4, test_ctx->cnx_server->pn_enc, test_ctx->cnx_client->pn_dec, sample_2);
                }
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int bad_certificate_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, "test-sni", "test-alpn", &simulated_time, NULL, 0, 0);

    /* Delete the server context, and recreate it with the bad certificate */

    if (ret == 0)
    {
        if (test_ctx->qserver != NULL) {
            picoquic_free(test_ctx->qserver);
        }

        test_ctx->qserver = picoquic_create(8,
#ifdef _WINDOWS
#ifdef _WINDOWS64
            "..\\..\\certs\\badcert.pem", "..\\..\\certs\\key.pem",
#else
            "..\\certs\\badcert.pem", "..\\certs\\key.pem",
#endif
#else
            "certs/badcert.pem", "certs/key.pem",
#endif
            PICOQUIC_TEST_ALPN, test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
            simulated_time, &simulated_time, NULL,
            test_ticket_encrypt_key, sizeof(test_ticket_encrypt_key));

        if (test_ctx->qserver == NULL) {
            ret = -1;
        }
    }

    /* Proceed with the connection loop. It should fail */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);

        if (test_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
            ret = -1;
        }
        else if (
            test_ctx->cnx_client->local_error != PICOQUIC_TLS_HANDSHAKE_FAILED) {
            ret = -1;
        }
        else {
            ret = 0;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
* Test setting the verify certificate callback.
*/

static int verify_sign_test(void* verify_ctx, ptls_iovec_t data, ptls_iovec_t sign) {
    int* ptr = (int*)verify_ctx;
    *ptr += 1;

    return 0;
}

static int verify_certificate_test(void* ctx, picoquic_cnx_t* cnx, ptls_iovec_t* certs, size_t num_certs,
                                   picoquic_verify_sign_cb_fn* verify_sign, void** verify_sign_ctx) {
    int* data = (int*)ctx;
    *data += 1;

    *verify_sign = verify_sign_test;
    *verify_sign_ctx = ctx;

    return 0;
}

int set_verify_certificate_callback_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int call_count = 0;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, 0, 0);

    /* Set the verify callback */
    if (ret == 0) {
        ret = picoquic_set_verify_certificate_callback(test_ctx->qclient, verify_certificate_test,
                                                       &call_count, NULL);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0 && call_count != 2) {
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Verify that the simulated time works as expected
 */

int virtual_time_test()
{
    int ret = 0;
    uint64_t test_time = 0;
    uint64_t simulated_time = 0;
    uint64_t current_time = picoquic_current_time();
    uint64_t ptls_time = 0;
    uint8_t callback_ctx[256];


    picoquic_quic_t * qsimul = picoquic_create(8, NULL, NULL, NULL, test_api_callback,
        (void*)callback_ctx, NULL, NULL, NULL, simulated_time,
        &simulated_time, ticket_file_name, NULL, 0);
    picoquic_quic_t * qdirect = picoquic_create(8, NULL, NULL, NULL, test_api_callback,
        (void*)callback_ctx, NULL, NULL, NULL, current_time,
        NULL, ticket_file_name, NULL, 0);

    if (qsimul == NULL || qdirect == NULL)
    {
        ret = -1;
    }
    else
    {
        /* Check that the simulated time follows the simulation */
        for (int i = 0; ret == 0 && i < 5; i++) {
            simulated_time += 12345678;
            test_time = picoquic_get_virtual_time(qsimul);
            ptls_time = picoquic_get_tls_time(qsimul);
            if (test_time != simulated_time) {
                DBG_PRINTF("Test time: %llu != Simulated: %llu",
                    (unsigned long long)test_time,
                    (unsigned long long)simulated_time);
                ret = -1;
            } else if (ptls_time < (test_time / 1000) || ptls_time >(test_time / 1000) + 1) {
                DBG_PRINTF("Test time: %llu does match ptls time: %llu",
                    (unsigned long long)test_time,
                    (unsigned long long)ptls_time);
                ret = -1;
            }
        }
        /* Check that the non simulated time follows the current time */
        for (int i = 0; ret == 0 && i < 5; i++) {
#ifdef _WINDOWS
            Sleep(1);
#else
            sleep(1);
#endif
            current_time = picoquic_current_time();
            test_time = picoquic_get_virtual_time(qdirect);
            ptls_time = picoquic_get_tls_time(qdirect);

            if (test_time < current_time) {
                DBG_PRINTF("Test time: %llu < previous current time: %llu",
                    (unsigned long long)test_time,
                    (unsigned long long)current_time);
                ret = -1;
            }
            else {
                current_time = picoquic_current_time();
                if (test_time > current_time) {
                    DBG_PRINTF("Test time: %llu > next current time: %llu",
                        (unsigned long long)test_time,
                        (unsigned long long)current_time);
                    ret = -1;
                } else if (ptls_time < (test_time / 1000) || ptls_time >(test_time / 1000) + 1) {
                    DBG_PRINTF("Test current time: %llu does match ptls time: %llu",
                        (unsigned long long)test_time,
                        (unsigned long long)ptls_time);
                    ret = -1;
                }
            }
        }
    }

    if (qsimul != NULL)
    {
        picoquic_free(qsimul);
        qsimul = NULL;
    }

    if (qdirect != NULL)
    {
        picoquic_free(qdirect);
        qsimul = NULL;
    }

    return ret;
}

/*
 * Testing with different initial connection parameters
 */

int tls_different_params_test()
{
    picoquic_transport_parameters test_parameters;

    memset(&test_parameters, 0, sizeof(picoquic_transport_parameters));

    picoquic_init_transport_parameters(&test_parameters, 1);

    test_parameters.initial_max_stream_id_bidir = 0;
    test_parameters.omit_connection_id = 1;

    return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 0, 1500000, &test_parameters);
}

