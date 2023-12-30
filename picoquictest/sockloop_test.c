/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "autoqlog.h"
#include "picoquic_packet_loop.h"

/* 
* Testing the socket loop.
* This requires sending packets through sockets, etc. We do that by using a 
* single QUIC context as both server and client, using a local socket to
* loop packets between the client and server connections.
 */

typedef struct st_sockloop_test_spec_t {
    uint8_t test_id;
    int af;
    uint16_t port;
    int socket_buffer_size;
    test_api_stream_desc_t* scenario;
    size_t scenario_size;
    int use_background_thread;
    int do_not_use_gso;
} sockloop_test_spec_t;

typedef struct st_sockloop_test_cb_t {
    picoquic_test_tls_api_ctx_t* test_ctx;
    int notified_ready;
    int established;
    int migration_to_preferred_started;
    int migration_to_preferred_finished;
    int migration_started;
    int address_updated;
    int force_migration;
    int nb_packets_before_key_update;
    int key_update_done;
    int zero_rtt_available;
    int socket_buffer_size;
    int multipath_probe_done;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    struct sockaddr_storage client_alt_address[PICOQUIC_NB_PATH_TARGET];
    int client_alt_if[PICOQUIC_NB_PATH_TARGET];
    int nb_alt_paths;
    picoquic_connection_id_t server_cid_before_migration;
    picoquic_connection_id_t client_cid_before_migration;
} sockloop_test_cb_t;


int sockloop_test_received_finished(picoquic_test_tls_api_ctx_t* test_ctx)
{
    int ret = 0;

    if (test_ctx->nb_test_streams > 0) {
        if (test_ctx->server_callback.error_detected) {
            ret = -1;
        }
        else if (test_ctx->client_callback.error_detected) {
            ret = -1;
        }
        else {
            ret = 1;
            for (size_t i = 0; ret == 1 && i < test_ctx->nb_test_streams; i++) {
                if (test_ctx->test_stream[i].q_recv_nb != test_ctx->test_stream[i].q_len ||
                    test_ctx->test_stream[i].r_recv_nb != test_ctx->test_stream[i].r_len) {
                    ret = 0;
                }
            }

            if (test_ctx->stream0_sent != test_ctx->stream0_target ||
                test_ctx->stream0_sent != test_ctx->stream0_received) {
                ret = 0;
            }
        }
    }
#if 1
    if (ret == 1) {
        ret = 1;
    }
#endif
    return ret;
}


int sockloop_test_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, 
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    sockloop_test_cb_t* cb_ctx = (sockloop_test_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        picoquic_cnx_t* cnx_client = (cb_ctx->test_ctx == NULL)?NULL:cb_ctx->test_ctx->cnx_client;
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            DBG_PRINTF("%s", "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            /* Post receive callback */
            if (cnx_client->cnx_state == picoquic_state_disconnected) {
                DBG_PRINTF("%s", "The connection is closed!\n");
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
                break;
            }
            if (picoquic_get_cnx_state(cnx_client) == picoquic_state_client_almost_ready && cb_ctx->notified_ready == 0) {
                /* if almost ready, display results of negotiation */
                if (picoquic_tls_is_psk_handshake(cnx_client)) {
                    DBG_PRINTF("%s", "The session was properly resumed!");
                }

                if (cnx_client->zero_rtt_data_accepted) {
                    DBG_PRINTF("%s", "Zero RTT data is accepted!");
                }

                if (cnx_client->alpn != NULL) {
                    DBG_PRINTF("Negotiated ALPN: %s", cnx_client->alpn);
                }
                DBG_PRINTF("%s", "Almost ready!");
                cb_ctx->notified_ready = 1;
            }
            else if (ret == 0 && (picoquic_get_cnx_state(cnx_client) == picoquic_state_ready ||
                picoquic_get_cnx_state(cnx_client) == picoquic_state_client_ready_start)) {
                /* Consider adding here something to handle migration tests */
                /* TODO: check if the receive is complete */
                if (sockloop_test_received_finished(cb_ctx->test_ctx) != 0) {
                    ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
                }
            }
            break;
        case picoquic_packet_loop_after_send:
            if (picoquic_get_cnx_state(cnx_client) == picoquic_state_disconnected) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            else if (ret == 0 && cb_ctx->established == 0 && (picoquic_get_cnx_state(cnx_client) == picoquic_state_ready ||
                picoquic_get_cnx_state(cnx_client) == picoquic_state_client_ready_start)) {
                DBG_PRINTF("Connection established. Version = %x, I-CID: %llx, verified: %d\n",
                    picoquic_supported_versions[cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_client)),
                    cnx_client->is_hcid_verified);
                cb_ctx->established = 1;

                /* Start the download scenario */
            }
            break;
        case picoquic_packet_loop_port_update:
            break;
            /* TODO: consider adding the delay computation callback! */
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}

int sockloop_test_create_ctx(picoquic_test_tls_api_ctx_t** p_test_ctx)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = (picoquic_test_tls_api_ctx_t*)
        malloc(sizeof(picoquic_test_tls_api_ctx_t));
    *p_test_ctx = test_ctx;

    if (test_ctx == NULL) {
        ret = -1;
    }
    else {
        /* Init to NULL */
        memset(test_ctx, 0, sizeof(picoquic_test_tls_api_ctx_t));
        test_ctx->client_callback.client_mode = 1;

#if 0
        /* Init of the IP addresses */
        memset(&test_ctx->client_addr, 0, sizeof(struct sockaddr_in));
        test_ctx->client_addr.sin_family = AF_INET;
#ifdef _WINDOWS
        test_ctx->client_addr.sin_addr.S_un.S_addr = htonl(0x0A000002);
#else
        test_ctx->client_addr.sin_addr.s_addr = htonl(0x0A000002);
#endif
        test_ctx->client_addr.sin_port = htons(1234);

        memset(&test_ctx->server_addr, 0, sizeof(struct sockaddr_in));
        test_ctx->server_addr.sin_family = AF_INET;
#ifdef _WINDOWS
        test_ctx->server_addr.sin_addr.S_un.S_addr = htonl(0x0A000001);
#else
        test_ctx->server_addr.sin_addr.s_addr = htonl(0x0A000001);
#endif
        test_ctx->server_addr.sin_port = htons(4321);
#endif

#if 0
        if (ret == 0) {
            /* Create the send buffer as requested */
            if (send_buffer_size == 0) {
                test_ctx->send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
            }
            else {
                test_ctx->send_buffer_size = send_buffer_size;
                test_ctx->use_udp_gso = 1;
            }
            test_ctx->send_buffer = (uint8_t*)malloc(test_ctx->send_buffer_size);
            if (test_ctx->send_buffer == NULL) {
                ret = -1;
            }
        }
#endif
    }

    return ret;
}

int sockloop_test_quic_config(picoquic_test_tls_api_ctx_t* test_ctx)
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picoquic_quic_t* quic = NULL;
    const uint8_t test_ticket_encrypt_key[16] = { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 };

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {
        quic = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            PICOQUIC_TEST_ALPN, test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
            0, NULL, NULL, test_ticket_encrypt_key, sizeof(test_ticket_encrypt_key));

        if (quic == NULL) {
            ret = -1;
        }
        else {
            /* Do not use randomization by default during tests */
            picoquic_set_random_initial(quic, 0);
            /* Do not use hole insertion by default */
            picoquic_set_optimistic_ack_policy(quic, 0);

            test_ctx->qserver = quic;
            test_ctx->qclient = quic;
        }
    }
    return ret;
}

int sockloop_test_addr_config(struct sockaddr_storage* addr,
    int af, uint16_t port)
{
    int ret = 0;
    memset(addr, 0, sizeof(struct sockaddr_storage));

    if (af == AF_INET6) {
        /* set server IPv6 to loopback */
        struct sockaddr_in6* sa6 = (struct sockaddr_in6*)addr;
        ((uint8_t*)(&sa6->sin6_addr))[15] = 1;
        sa6->sin6_port = htons(port);
        sa6->sin6_family = AF_INET6;
    }
    else if (af == AF_INET) {
        /* set server IPv6 to loopback */
        struct sockaddr_in* sa4 = (struct sockaddr_in*)addr;
        ((uint8_t*)(&sa4->sin_addr))[0] = 127;
        ((uint8_t*)(&sa4->sin_addr))[3] = 1;
        sa4->sin_port = htons(port);
        sa4->sin_family = AF_INET;
    }
    else {
        ret = -1;
    }
    return ret;
}

void sockloop_test_set_icid(picoquic_connection_id_t * icid, uint8_t test_id)
{
    const picoquic_connection_id_t icid_base = { { 0x50, 0xcc, 0x10, 0x09, 0, 0, 0, 0}, 8 };
    memcpy(icid, &icid_base, sizeof(picoquic_connection_id_t));
    icid->id[4] = test_id;
}

int sockloop_test_cnx_config(picoquic_test_tls_api_ctx_t* test_ctx, struct sockaddr* addr, picoquic_connection_id_t* icid, uint64_t current_time)
{
    int ret = 0;

    /* Create the client connection */
    test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, *icid, picoquic_null_connection_id,
        addr, current_time, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);
    if (test_ctx->cnx_client == NULL) {
        ret = -1;
    }
    else {
        picoquic_set_callback(test_ctx->cnx_client, test_api_callback, (void*)&test_ctx->client_callback);
    }

    return ret;
}

int sockloop_test_one(sockloop_test_spec_t *spec)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t icid = { 0 };
    struct sockaddr_storage server_address = { 0 };
    sockloop_test_cb_t loop_cb = { 0 };
    uint64_t current_time = picoquic_current_time();

    /* Create test context
    * TODO: this creates the client and server addresses. We probably
    * need to test scenarios using both IPv4 and IPv6, for coverage.
     */
    ret = sockloop_test_create_ctx(&test_ctx);
    /* Create QUIC context */
    /* Setting qclient and qserver to the same value since doing loopback test */
    if (ret == 0) {
        ret = sockloop_test_quic_config(test_ctx);
    }
    if (ret == 0) {
        picoquic_set_qlog(test_ctx->qserver, ".");
    }
    /* Create connection context
    * TODO: this may be the place for testing different server addresses,
    * e.g. ::1 and 127.0.0.1.
     */
    if (ret == 0) {
        ret = sockloop_test_addr_config(&server_address, spec->af, spec->port);
    }
    if (ret == 0){
        sockloop_test_set_icid(&icid, spec->test_id);
        ret = sockloop_test_cnx_config(test_ctx, (struct sockaddr*) &server_address, &icid, current_time);
    }
    /* Program connection scenario */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, spec->scenario, spec->scenario_size);
    }
    /* Run the loop 
     * TODO: unify windows and linux.
     * TODO: option to start the connection in a background thread.
     *       in that case, only start the client connection after
     *       the thread is verified and started, e.g., using an
     *       active loop until the thread is marked ready.
     * TODO: consider testing at least one migration scenario,
     *       for code coverage.
     * TODO: consider changing the API to add a second port number, to be
     *       used in migration and multipath tests.
     * TODO: document port number.
     */
    if (ret == 0) {
        loop_cb.test_ctx = test_ctx;
        picoquic_start_client_cnx(test_ctx->cnx_client);
#ifdef _WINDOWS
        ret = picoquic_packet_loop_win(test_ctx->qserver, spec->port, 0, 0,
            spec->socket_buffer_size, sockloop_test_cb, &loop_cb);
#else
        ret = picoquic_packet_loop(test_ctx->qserver, spec->port, 0, 0,
            spec->socket_buffer_size, spec->do_not_use_gso, sockloop_test_cb, &loop_cb);
#endif
    }
    /* Verify that the scenario worked. */
    /* TODO: verify scenario assumes qclient and qserver are defined. Fix that. */
    if (ret == 0) {
        ret = tls_api_one_scenario_verify(test_ctx);
    }
    /* Free the config */
    if (test_ctx != NULL) {
        if (test_ctx->qserver != NULL) {
            test_ctx->qclient = NULL;
            test_ctx->cnx_client = NULL;
        }
        tls_api_delete_ctx(test_ctx);
    }
    return ret;
}


static test_api_stream_desc_t sockloop_test_scenario_basic[] = {
    { 4, 0, 257, 2000 },
    { 8, 0, 531, 11000 }
};

void sockloop_test_set_spec(sockloop_test_spec_t* spec, uint8_t test_id)
{
    memset(spec, 0, sizeof(sockloop_test_spec_t));
    spec->test_id = test_id;
    spec->af = AF_INET6;
    spec->port = 3456;
    spec->scenario = sockloop_test_scenario_basic;
    spec->scenario_size = sizeof(sockloop_test_scenario_basic);
    spec->socket_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
}

int sockloop_basic_test()
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 1);

    return(sockloop_test_one(&spec));
}
