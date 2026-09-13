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
#include "picoquic_qlog.h"
#include "picoquic_packet_loop.h"
#include "picosocks.h"
#include "picoqmux.h"


#ifndef SLEEP
#ifdef _WINDOWS
#define SLEEP(x) Sleep(x)
#else
#define SLEEP(x) usleep((x)*1000)
#endif
#endif

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
    char const* thread_name;
    int use_background_thread;
    int ipv6_only;
    int do_not_use_gso;
    int simulate_eio;
    int double_bind;
    int extra_socket_required;
    int prefer_extra_socket;
    int force_migration;
    int bind_loopback; /* bind the server socket to the loopback address of spec->af */
    int test_system_call_duration; /* ask the loop to monitor and report system call duration */
} sockloop_test_spec_t;

typedef struct st_sockloop_test_cb_t {
    picoquic_test_tls_api_ctx_t* test_ctx;
    uint8_t test_id;
    int notified_ready;
    int established;
    int force_migration;
    int migration_started;
    int address_updated;
    int zero_rtt_available;
    int socket_buffer_size;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    struct sockaddr_storage client_alt_address[PICOQUIC_NB_PATH_TARGET];
    int client_alt_if[PICOQUIC_NB_PATH_TARGET];
    int nb_alt_paths;
    uint16_t alt_port;
    picoquic_connection_id_t server_cid_before_migration;
    picoquic_connection_id_t client_cid_before_migration;
    picoquic_packet_loop_param_t* param;
    picoquic_cnx_t* qmux_cnx;
    int test_system_call_duration;
    int system_call_duration_notified;
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
    return ret;
}

int sockloop_test_verify_extra_socket(picoquic_cnx_t* cnx_client, struct sockaddr* server_address)
{
    int ret = 0;
    if (picoquic_compare_addr((struct sockaddr*)&cnx_client->path[0]->first_tuple->peer_addr, server_address) != 0 ||
        picoquic_compare_addr((struct sockaddr*)&cnx_client->path[0]->first_tuple->local_addr, server_address) == 0) {
        ret = -1;
    }

    return ret;
}

int sockloop_test_cb(picoquic_quic_t* UNUSED(quic), picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    sockloop_test_cb_t* cb_ctx = (sockloop_test_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        picoquic_cnx_t* cnx_client = (cb_ctx->test_ctx == NULL)?NULL:cb_ctx->test_ctx->cnx_client;
        if (cnx_client == NULL){
            if (cb_ctx->qmux_cnx == NULL ||
                cb_ctx->qmux_cnx->cnx_state == picoquic_state_disconnected) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
        }
        else switch (cb_mode) {
        case picoquic_packet_loop_ready: {
            picoquic_packet_loop_options_t* options = (picoquic_packet_loop_options_t*)callback_arg;
            if (cb_ctx->test_id > 1) {
                options->do_time_check = 1;
                if (cb_ctx->param->extra_socket_required) {
                    options->provide_alt_port = 1;
                }
            }
            if (cb_ctx->test_system_call_duration) {
                options->do_system_call_duration = 1;
            }
            DBG_PRINTF("%s", "Waiting for packets.\n");
            break;
        }
        case picoquic_packet_loop_system_call_duration:
            cb_ctx->system_call_duration_notified = 1;
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
                /* Store the initial versions of address and CID */
                picoquic_store_addr(&cb_ctx->client_address, (struct sockaddr*)&cnx_client->path[0]->first_tuple->local_addr);
                picoquic_store_addr(&cb_ctx->server_address, (struct sockaddr*)&cnx_client->path[0]->first_tuple->peer_addr);
                cb_ctx->client_cid_before_migration = cnx_client->path[0]->first_tuple->p_local_cnxid->cnx_id;
                cb_ctx->server_cid_before_migration = cnx_client->path[0]->first_tuple->p_remote_cnxid->cnx_id;
            }
            else if (ret == 0 && picoquic_get_cnx_state(cnx_client) == picoquic_state_ready) {
                /* Handle migration tests */
                if (cb_ctx->force_migration){
                    if (!cb_ctx->migration_started &&
                        cnx_client->first_remote_cnxid_stash->cnxid_stash_first != NULL &&
                        cb_ctx->alt_port != 0 &&
                        cb_ctx->client_address.ss_family != AF_UNSPEC) {
                        memcpy(&cb_ctx->client_alt_address[0], &cb_ctx->client_address, sizeof(cb_ctx->client_address));
                        if (cb_ctx->force_migration == 3){
                            if (cb_ctx->client_alt_address[0].ss_family == AF_INET6) {
                                ((struct sockaddr_in6*)&cb_ctx->client_alt_address[0])->sin6_port = htons(cb_ctx->alt_port);
                            }
                            else {
                                ((struct sockaddr_in*)&cb_ctx->client_alt_address[0])->sin_port = htons(cb_ctx->alt_port);
                            }
                            cb_ctx->migration_started = 1;
                            ret = picoquic_probe_new_path(cnx_client,
                                (struct sockaddr*)&cb_ctx->server_address,
                                (struct sockaddr*)&cb_ctx->client_alt_address[0],
                                picoquic_get_quic_time(cb_ctx->test_ctx->qserver));
                        }
                        else if (cb_ctx->force_migration == 1) {
                            /* We set on the "prefer extra socket" flag in sockloop, which mapped the default
                            * client port to the "extra socket". Setting the return code to
                            * PICOQUIC_NO_ERROR_SIMULATE_NAT will cause the sockloop code to discard the
                            * socket.
                            */
                            cb_ctx->migration_started = 1;
                            if (cnx_client->path[0]->first_tuple->local_addr.ss_family == AF_INET6) {
                                ((struct sockaddr_in6*)&cnx_client->path[0]->first_tuple->local_addr)->sin6_port = htons(cb_ctx->param->local_port);
                            }
                            else {
                                ((struct sockaddr_in*)&cnx_client->path[0]->first_tuple->local_addr)->sin_port = htons(cb_ctx->param->local_port);
                            }
                            ret = PICOQUIC_NO_ERROR_SIMULATE_NAT;
                        }
                    }
                    else if (cb_ctx->migration_started && !cb_ctx->address_updated) {
                        if (picoquic_compare_addr((struct sockaddr*)&cnx_client->path[0]->first_tuple->local_addr, (struct sockaddr*)&cb_ctx->server_address) == 0) {
                            cb_ctx->address_updated = 1;
                        }
                    }
                }
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
        case picoquic_packet_loop_time_check: {
            packet_loop_time_check_arg_t* time_check_arg = (packet_loop_time_check_arg_t*) callback_arg;
            if (time_check_arg->delta_t > 5000) {
                time_check_arg->delta_t = 5000;
            }
            break;
        }
        case picoquic_packet_loop_wake_up: {
            ret = picoquic_start_client_cnx(cnx_client);
            DBG_PRINTF("Starting the client connection, returns: %d", ret);
            break;
        }
        case picoquic_packet_loop_alt_port:
            /* set the client alt address */
            cb_ctx->alt_port = *((uint16_t*)callback_arg);
            if (cb_ctx->force_migration && cb_ctx->force_migration == 1 &&
                cb_ctx->test_ctx->cnx_client != NULL &&
                cb_ctx->test_ctx->cnx_client->path[0]->first_tuple->local_addr.ss_family == AF_UNSPEC) {
                memcpy(&cb_ctx->test_ctx->cnx_client->path[0]->first_tuple->local_addr,
                    &cb_ctx->test_ctx->cnx_client->path[0]->first_tuple->peer_addr,
                    sizeof(struct sockaddr_storage));

                if (cnx_client->path[0]->first_tuple->local_addr.ss_family == AF_INET6) {
                    ((struct sockaddr_in6*)&cnx_client->path[0]->first_tuple->local_addr)->sin6_port = cb_ctx->alt_port;
                }
                else {
                    ((struct sockaddr_in*)&cnx_client->path[0]->first_tuple->local_addr)->sin_port = cb_ctx->alt_port;
                }

            }
            break;
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
        /* set server IPv4 to loopback */
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

int sockloop_test_verify_migration(sockloop_test_cb_t * loop_cb, picoquic_cnx_t* cnx_client)
{
    int ret = 0;
    if (!loop_cb->migration_started) {
        DBG_PRINTF("%s", "Could not start testing migration.\n");
        ret = -1;
    }
    else {
        int source_addr_cmp = picoquic_compare_addr(
            (struct sockaddr*) & cnx_client->path[0]->first_tuple->local_addr,
            (struct sockaddr*) & loop_cb->client_address);
        int dest_cid_cmp = picoquic_compare_connection_id(
            &cnx_client->path[0]->first_tuple->p_remote_cnxid->cnx_id,
            &loop_cb->server_cid_before_migration);
        if (cnx_client->path[0]->first_tuple->p_local_cnxid == NULL) {
            DBG_PRINTF("%s", "Local CID is NULL!\n");
            ret = -1;
        }
        else {
            int source_cid_cmp = picoquic_compare_connection_id(
                &cnx_client->path[0]->first_tuple->p_local_cnxid->cnx_id,
                &loop_cb->client_cid_before_migration);

            if (loop_cb->force_migration == 1 || loop_cb->force_migration == 3) {
                if (source_addr_cmp == 0){
                    DBG_PRINTF("%s", "Client source address did not change");
                    ret = -1;
                }
                if (loop_cb->force_migration == 3 && dest_cid_cmp == 0) {
                    DBG_PRINTF("%s", "Remode CID did not change");
                    ret = -1;
                }
                if (loop_cb->force_migration == 3 && source_cid_cmp == 0) {
                    DBG_PRINTF("%s", "Local CID did not change");
                    ret = -1;
                }
            }
        }
    }

    return ret;
}

int sockloop_test_one(sockloop_test_spec_t *spec)
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t icid = { 0 };
    sockloop_test_cb_t loop_cb = { 0 };
    uint64_t current_time = picoquic_current_time();
    picoquic_socket_ctx_t double_bind[2] = { 0 };
    picoquic_network_thread_ctx_t* thread_ctx = NULL;
    int nb_double_bind = 0;

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
    /* Create connection context */
    if (ret == 0) {
        ret = sockloop_test_addr_config(&loop_cb.server_address, spec->af, spec->port);
    }
    if (ret == 0){
        sockloop_test_set_icid(&icid, spec->test_id);
        ret = sockloop_test_cnx_config(test_ctx, (struct sockaddr*) &loop_cb.server_address, &icid, current_time);
    }
    /* Program connection scenario */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, spec->scenario, spec->scenario_size);
    }
    /* If testing a socket fault, bind sockets to the desired port */
    for (int i = 0; i < 2; i++) {
        double_bind[i].fd = INVALID_SOCKET;
    }
    if (ret == 0 && spec->double_bind) {
        picoquic_packet_loop_param_t param = { 0 };
        param.local_port = spec->port;
        param.local_af = AF_INET6;
        param.socket_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
        param.do_not_use_gso = 1;
        if ((nb_double_bind = picoquic_packet_loop_open_sockets(&param, double_bind, test_ctx->qserver->default_congestion_alg->ecn_mark)) <= 0) {
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
        }
    }

    /* Run the loop 
     * TODO: unify windows and linux.
     * TODO: option to start the connection in a background thread.
     *       in that case, only start the client connection after
     *       the thread is verified and started, e.g., using an
     *       active loop until the thread is marked ready.
     */
    if (ret == 0) {
        loop_cb.test_ctx = test_ctx;
        loop_cb.test_id = spec->test_id;
        loop_cb.test_system_call_duration = spec->test_system_call_duration;
        if (!spec->use_background_thread) {
            picoquic_start_client_cnx(test_ctx->cnx_client);
        }
        if (spec->test_id == 1) {
#ifdef _WINDOWS_BUT_MAYBE_NOT
            ret = picoquic_packet_loop_win(test_ctx->qserver, spec->port, 0, 0,
                spec->socket_buffer_size, sockloop_test_cb, &loop_cb);
#else
            ret = picoquic_packet_loop(test_ctx->qserver, spec->port,
                (spec->ipv6_only) ? AF_INET6 : 0, 0,
                spec->socket_buffer_size, spec->do_not_use_gso, sockloop_test_cb, &loop_cb);
#endif
        }
        else {
            picoquic_packet_loop_param_t param = { 0 };

            param.local_port = spec->port;
            param.local_af = (spec->ipv6_only) ? AF_INET6 : 0;
            param.socket_buffer_size = spec->socket_buffer_size;
            param.do_not_use_gso = spec->do_not_use_gso;
            param.simulate_eio = spec->simulate_eio;
            param.extra_socket_required = spec->extra_socket_required;
            param.prefer_extra_socket = spec->prefer_extra_socket;
            if (spec->bind_loopback) {
                ret = sockloop_test_addr_config(&param.local_addr[0], spec->af, 0);
            }

            loop_cb.force_migration = spec->force_migration;
            loop_cb.param = &param;

            if (spec->use_background_thread) {
                if (spec->thread_name != NULL) {
                    thread_ctx = picoquic_start_custom_network_thread(test_ctx->qserver, &param,
                        picoquic_internal_thread_create, picoquic_internal_thread_delete,
                        picoquic_internal_thread_setname, spec->thread_name, sockloop_test_cb, &loop_cb, &ret);
                }
                else {
                    thread_ctx = picoquic_start_network_thread(test_ctx->qserver, &param, sockloop_test_cb, &loop_cb, &ret);
                }
                if (thread_ctx == NULL) {
                    if (ret == 0) {
                        ret = -1;
                    }
                }
                else {
                    if (picoquic_get_thread_ctx(test_ctx->qserver) != thread_ctx) {
                        DBG_PRINTF("%s", "picoquic_get_thread_ctx does not match the started thread");
                        ret = -1;
                    }
                    for (int i = 0; i < 2000; i++) {
                        if (thread_ctx->thread_is_ready) {
                            DBG_PRINTF("Thread is ready after %dms", i);
                            break;
                        }
                        else {
                            SLEEP(1);
                        }
                    }
                    if (!thread_ctx->thread_is_ready) {
                        DBG_PRINTF("%s", "Cannot start the network thread in 2000ms");
                        ret = -1;
                    }
                    else if (picoquic_wake_up_network_thread(thread_ctx) != 0) {
                        DBG_PRINTF("%s", "Cannot wakeup the network thread");
                        ret = -1;
                    }
                    else {
                        for (int i = 0; i < 50; i++) {
                            if (sockloop_test_received_finished(test_ctx)) {
                                DBG_PRINTF("Receive finished after %dms", 100 * i);
                                break;
                            }
                            else {
                                SLEEP(100);
                            }
                        }
                    }
                    picoquic_delete_network_thread(thread_ctx);
                    if (picoquic_get_thread_ctx(test_ctx->qserver) != NULL) {
                        DBG_PRINTF("%s", "picoquic_get_thread_ctx is not NULL after delete");
                        ret = -1;
                    }
                }
            }
            else {
                ret = picoquic_packet_loop_v2(test_ctx->qserver, &param, sockloop_test_cb, &loop_cb);
            }
        }
    }
    /* Verify that the scenario worked. */
    /* TODO: verify scenario assumes qclient and qserver are defined. Fix that. */
    if (ret == 0) {
        if (spec->double_bind) {
            ret = -1;
        }
        else if (spec->force_migration != 0 && loop_cb.address_updated == 0) {
            ret = -1;
        }
        else if (spec->force_migration != 0 && sockloop_test_verify_migration(&loop_cb, test_ctx->cnx_client) != 0) {
            ret = -1;
        }
        else if (spec->test_system_call_duration && !loop_cb.system_call_duration_notified) {
            DBG_PRINTF("%s", "picoquic_packet_loop_system_call_duration was never notified");
            ret = -1;
        }
        else {
            ret = tls_api_one_scenario_verify(test_ctx);
        }
    }
    else {
        if (spec->double_bind) {
            ret = 0;
        }
    }
    /* Free the config */
    if (test_ctx != NULL) {
        if (test_ctx->qserver != NULL) {
            test_ctx->qclient = NULL;
            test_ctx->cnx_client = NULL;
        }
        tls_api_delete_ctx(test_ctx);
    }
    /* Free the sockets used in double blind test */
    for (int i = 0; i < 2; i++) {
        picoquic_packet_loop_close_socket(&double_bind[i]);
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

int sockloop_basic_test(void)
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 1);
    spec.ipv6_only = 1;
    spec.do_not_use_gso = 1;

    return(sockloop_test_one(&spec));
}

/* monitor_system_call_duration is only reachable when options->do_system_call_duration is
 * set on the picoquic_packet_loop_ready event, which no other test opts into. On the very
 * first monitored receive, scd_max starts at 0 so the very first real duration is guaranteed
 * to be "shall_notify". */
int sockloop_system_call_duration_test(void)
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 9);
    spec.test_system_call_duration = 1;

    return(sockloop_test_one(&spec));
}

static test_api_stream_desc_t sockloop_test_scenario_1M[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 257, 1000000 }
};

int sockloop_eio_test(void)
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 2);
    spec.socket_buffer_size = 0xffff;
    spec.scenario = sockloop_test_scenario_1M;
    spec.scenario_size = sizeof(sockloop_test_scenario_1M);
    spec.simulate_eio = 1;

    return(sockloop_test_one(&spec));
}

int sockloop_errsock_test(void)
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 3);
    spec.double_bind = 1;

    return(sockloop_test_one(&spec));
}

int sockloop_ipv4_test(void)
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 4);
    spec.af = AF_INET;
    spec.socket_buffer_size = 0xffff;
    spec.scenario = sockloop_test_scenario_1M;
    spec.scenario_size = sizeof(sockloop_test_scenario_1M);

    return(sockloop_test_one(&spec));
}

/* Compare the address part of two sockaddr, after aligning the port of the
 * expected address on the port reported by the socket. */
static int picoquic_addr_set_port_and_compare(struct sockaddr_storage* expected, uint16_t port,
    struct sockaddr_storage* actual)
{
    if (expected->ss_family == AF_INET6) {
        ((struct sockaddr_in6*)expected)->sin6_port = htons(port);
    }
    else if (expected->ss_family == AF_INET) {
        ((struct sockaddr_in*)expected)->sin_port = htons(port);
    }
    return picoquic_compare_addr((struct sockaddr*)expected, (struct sockaddr*)actual);
}

/* Check that socket s_ctx is bound to the loopback address of its family,
 * on a non-zero port. */
static int sockloop_bind_addr_check_socket(picoquic_socket_ctx_t* s_ctx, int af)
{
    int ret = 0;
    struct sockaddr_storage expected = { 0 };
    struct sockaddr_storage actual = { 0 };

    if (s_ctx->af != af) {
        DBG_PRINTF("Expected socket af=%d, got %d", af, s_ctx->af);
        ret = -1;
    }
    else if (sockloop_test_addr_config(&expected, af, 0) != 0) {
        ret = -1;
    }
    else if (picoquic_get_local_address(s_ctx->fd, &actual) != 0) {
        DBG_PRINTF("%s", "Cannot read local address of bound socket");
        ret = -1;
    }
    else if (s_ctx->port == 0) {
        DBG_PRINTF("%s", "Ephemeral port was not reported back");
        ret = -1;
    }
    else if (picoquic_addr_set_port_and_compare(&expected, s_ctx->port, &actual) != 0 ||
        picoquic_compare_addr((struct sockaddr*)&expected, (struct sockaddr*)&s_ctx->bound_addr) != 0) {
        char expected_text[64];
        char actual_text[64];
        char bound_text[64];
        DBG_PRINTF("Expected bind address %s, got %s, recorded %s",
            picoquic_addr_text((struct sockaddr*)&expected, expected_text, sizeof(expected_text)),
            picoquic_addr_text((struct sockaddr*)&actual, actual_text, sizeof(actual_text)),
            picoquic_addr_text((struct sockaddr*)&s_ctx->bound_addr, bound_text, sizeof(bound_text)));
        ret = -1;
    }
    return ret;
}

/* Verify that sockets opened with param.local_addr are bound to those
 * addresses rather than to the wildcard address: one socket per entry,
 * none for a family without an entry. af_list holds the families to
 * configure, nb_af of them. local_af is left to 0 (unspecified). */
static int sockloop_bind_addr_one(const int* af_list, int nb_af)
{
    int ret = 0;
    picoquic_packet_loop_param_t param = { 0 };
    picoquic_socket_ctx_t s_ctx[4] = { 0 };
    int nb_sockets;

    for (int i = 0; i < 4; i++) {
        s_ctx[i].fd = INVALID_SOCKET;
    }
    for (int i = 0; ret == 0 && i < nb_af; i++) {
        ret = sockloop_test_addr_config(&param.local_addr[i], af_list[i], 0);
    }
    if (ret == 0) {
        param.local_port = 0;
        param.socket_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
        param.do_not_use_gso = 1;
        nb_sockets = picoquic_packet_loop_open_sockets(&param, s_ctx, 0);
        if (nb_sockets != nb_af) {
            DBG_PRINTF("Expected %d sockets, got %d", nb_af, nb_sockets);
            ret = -1;
        }
        for (int i = 0; ret == 0 && i < nb_af; i++) {
            ret = sockloop_bind_addr_check_socket(&s_ctx[i], af_list[i]);
        }
        for (int i = 0; i < 4; i++) {
            picoquic_packet_loop_close_socket(&s_ctx[i]);
        }
    }
    return ret;
}

/* Verify that inconsistent parameters are refused: a local_af that does not
 * match the configured address, or two addresses of the same family. */
static int sockloop_bind_addr_refused(int local_af, int af0, int af1)
{
    int ret = 0;
    picoquic_packet_loop_param_t param = { 0 };
    picoquic_socket_ctx_t s_ctx[4] = { 0 };
    int nb_sockets;

    for (int i = 0; i < 4; i++) {
        s_ctx[i].fd = INVALID_SOCKET;
    }
    param.local_af = local_af;
    ret = sockloop_test_addr_config(&param.local_addr[0], af0, 0);
    if (ret == 0 && af1 != AF_UNSPEC) {
        ret = sockloop_test_addr_config(&param.local_addr[1], af1, 0);
    }
    if (ret == 0) {
        param.do_not_use_gso = 1;
        nb_sockets = picoquic_packet_loop_open_sockets(&param, s_ctx, 0);
        if (nb_sockets != 0) {
            DBG_PRINTF("Expected refusal for local_af=%d, af0=%d, af1=%d, got %d sockets",
                local_af, af0, af1, nb_sockets);
            ret = -1;
        }
        for (int i = 0; i < 4; i++) {
            picoquic_packet_loop_close_socket(&s_ctx[i]);
        }
    }
    return ret;
}

/* Verify that the send path substitutes the bound address for whatever
 * local address the path proposes, keeps the port, fills in an unspecified
 * local address, and leaves sockets bound to the wildcard alone. */
static int sockloop_bind_addr_send_source(int af)
{
    int ret = 0;
    picoquic_packet_loop_param_t param = { 0 };
    picoquic_socket_ctx_t s_ctx[4] = { 0 };
    struct sockaddr_storage other = { 0 };
    struct sockaddr_storage expected = { 0 };
    struct sockaddr_storage local_addr = { 0 };
    int nb_sockets;

    for (int i = 0; i < 4; i++) {
        s_ctx[i].fd = INVALID_SOCKET;
    }
    /* "other" is a different address of the same family, port 1234 */
    ret = sockloop_test_addr_config(&other, af, 1234);
    if (ret == 0) {
        if (af == AF_INET6) {
            ((uint8_t*)(&((struct sockaddr_in6*)&other)->sin6_addr))[14] = 0xff;
        }
        else {
            ((uint8_t*)(&((struct sockaddr_in*)&other)->sin_addr))[3] = 5;
        }
        ret = sockloop_test_addr_config(&param.local_addr[0], af, 0);
    }
    if (ret == 0) {
        param.do_not_use_gso = 1;
        nb_sockets = picoquic_packet_loop_open_sockets(&param, s_ctx, 0);
        if (nb_sockets != 1) {
            DBG_PRINTF("Expected 1 socket, got %d", nb_sockets);
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Path proposes another address: expect the bound address, same port */
        picoquic_store_addr(&local_addr, (struct sockaddr*)&other);
        picoquic_packet_loop_set_send_source(&s_ctx[0], &local_addr);
        (void)sockloop_test_addr_config(&expected, af, 1234);
        if (picoquic_compare_addr((struct sockaddr*)&expected, (struct sockaddr*)&local_addr) != 0) {
            DBG_PRINTF("%s", "Bound address was not substituted for the path's local address");
            ret = -1;
        }
    }
    if (ret == 0) {
        /* Path has no local address yet: expect the bound address and port */
        memset(&local_addr, 0, sizeof(local_addr));
        picoquic_packet_loop_set_send_source(&s_ctx[0], &local_addr);
        (void)sockloop_test_addr_config(&expected, af, s_ctx[0].port);
        if (picoquic_compare_addr((struct sockaddr*)&expected, (struct sockaddr*)&local_addr) != 0) {
            DBG_PRINTF("%s", "Unspecified local address was not filled from the bound address");
            ret = -1;
        }
    }
    for (int i = 0; i < 4; i++) {
        picoquic_packet_loop_close_socket(&s_ctx[i]);
        s_ctx[i].fd = INVALID_SOCKET;
    }
    if (ret == 0) {
        /* Socket bound to the wildcard: the path's local address is kept */
        memset(&param, 0, sizeof(param));
        param.local_af = af;
        param.do_not_use_gso = 1;
        nb_sockets = picoquic_packet_loop_open_sockets(&param, s_ctx, 0);
        if (nb_sockets != 1) {
            DBG_PRINTF("Expected 1 wildcard socket, got %d", nb_sockets);
            ret = -1;
        }
        else {
            picoquic_store_addr(&local_addr, (struct sockaddr*)&other);
            picoquic_packet_loop_set_send_source(&s_ctx[0], &local_addr);
            if (picoquic_compare_addr((struct sockaddr*)&other, (struct sockaddr*)&local_addr) != 0) {
                DBG_PRINTF("%s", "Wildcard socket changed the path's local address");
                ret = -1;
            }
        }
        for (int i = 0; i < 4; i++) {
            picoquic_packet_loop_close_socket(&s_ctx[i]);
        }
    }
    return ret;
}

/* An address family that picoquic_packet_loop_open_sockets does not know how to bind
 * (neither AF_INET nor AF_INET6) must be refused outright. */
static int sockloop_bind_addr_unsupported_af(void)
{
    int ret = 0;
    picoquic_packet_loop_param_t param = { 0 };
    picoquic_socket_ctx_t s_ctx[4] = { 0 };
    int nb_sockets;

    for (int i = 0; i < 4; i++) {
        s_ctx[i].fd = INVALID_SOCKET;
    }
    param.local_addr[0].ss_family = 999; /* Not AF_INET, AF_INET6, or AF_UNSPEC */
    param.do_not_use_gso = 1;

    nb_sockets = picoquic_packet_loop_open_sockets(&param, s_ctx, 0);
    if (nb_sockets != 0) {
        DBG_PRINTF("Expected refusal for unsupported af, got %d sockets", nb_sockets);
        ret = -1;
    }
    for (int i = 0; i < 4; i++) {
        picoquic_packet_loop_close_socket(&s_ctx[i]);
    }
    return ret;
}

/* If a public (shared) port is requested in addition to the local port, open_sockets
 * must open a second socket per address family for that public port. */
static int sockloop_bind_addr_public_port(void)
{
    int ret = 0;
    picoquic_packet_loop_param_t param = { 0 };
    picoquic_socket_ctx_t s_ctx[4] = { 0 };
    int nb_sockets;

    for (int i = 0; i < 4; i++) {
        s_ctx[i].fd = INVALID_SOCKET;
    }
    param.local_af = AF_INET;
    param.local_port = 0;
    param.public_port = 34567;
    param.do_not_use_gso = 1;

    nb_sockets = picoquic_packet_loop_open_sockets(&param, s_ctx, 0);
    if (nb_sockets != 2) {
        DBG_PRINTF("Expected 2 sockets (local + public port), got %d", nb_sockets);
        ret = -1;
    }
    else if (s_ctx[1].port != param.public_port) {
        DBG_PRINTF("Expected public port socket bound to %d, got %d", param.public_port, s_ctx[1].port);
        ret = -1;
    }
    for (int i = 0; i < 4; i++) {
        picoquic_packet_loop_close_socket(&s_ctx[i]);
    }
    return ret;
}

int picoquic_packet_loop_open_socket(picoquic_packet_loop_param_t* param, picoquic_socket_ctx_t* s_ctx, uint8_t ecn_value);

/* picoquic_packet_loop_open_socket itself refuses to open a socket for an address family
 * that has no configured local address, when other families do have one configured --
 * called directly here since picoquic_packet_loop_open_sockets never reaches this guard
 * (it only ever asks for sockets matching a family it already found in param->local_addr). */
static int sockloop_bind_addr_open_socket_no_addr_for_af(void)
{
    int ret = 0;
    picoquic_packet_loop_param_t param = { 0 };
    picoquic_socket_ctx_t s_ctx = { 0 };

    s_ctx.fd = INVALID_SOCKET;
    param.local_addr[0].ss_family = AF_INET;
    s_ctx.af = AF_INET6;

    if (picoquic_packet_loop_open_socket(&param, &s_ctx, 0) == 0) {
        DBG_PRINTF("%s", "Expected refusal when no local address is configured for the requested af");
        ret = -1;
        picoquic_packet_loop_close_socket(&s_ctx);
    }
    return ret;
}

int sockloop_bind_addr_test(void)
{
    const int af_v4[1] = { AF_INET };
    const int af_v6[1] = { AF_INET6 };
    const int af_both[2] = { AF_INET, AF_INET6 };
    int ret = sockloop_bind_addr_one(af_v4, 1);

    if (ret == 0) {
        ret = sockloop_bind_addr_one(af_v6, 1);
    }
    if (ret == 0) {
        ret = sockloop_bind_addr_unsupported_af();
    }
    if (ret == 0) {
        ret = sockloop_bind_addr_public_port();
    }
    if (ret == 0) {
        ret = sockloop_bind_addr_open_socket_no_addr_for_af();
    }
    if (ret == 0) {
        ret = sockloop_bind_addr_one(af_both, 2);
    }
    if (ret == 0) {
        ret = sockloop_bind_addr_refused(AF_INET6, AF_INET, AF_UNSPEC);
    }
    if (ret == 0) {
        ret = sockloop_bind_addr_refused(0, AF_INET, AF_INET);
    }
    if (ret == 0) {
        ret = sockloop_bind_addr_send_source(AF_INET);
    }
    if (ret == 0) {
        ret = sockloop_bind_addr_send_source(AF_INET6);
    }
    if (ret == 0) {
        /* Full loop, server bound to 127.0.0.1 only, client connecting to it. */
        sockloop_test_spec_t spec;
        sockloop_test_set_spec(&spec, 11);
        spec.af = AF_INET;
        spec.bind_loopback = 1;
        spec.do_not_use_gso = 1;
        ret = sockloop_test_one(&spec);
    }
    return ret;
}

int sockloop_migration_test(void)
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 5);
    spec.af = AF_INET6;
    spec.socket_buffer_size = 0xffff;
    spec.scenario = sockloop_test_scenario_1M;
    spec.scenario_size = sizeof(sockloop_test_scenario_1M);
    spec.extra_socket_required = 1;
    spec.force_migration = 3;

    return(sockloop_test_one(&spec));
}

int sockloop_nat_test(void)
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 6);
    spec.af = AF_INET;
    spec.socket_buffer_size = 0xffff;
    spec.scenario = sockloop_test_scenario_1M;
    spec.scenario_size = sizeof(sockloop_test_scenario_1M);
    spec.extra_socket_required = 1;
    spec.prefer_extra_socket = 1;
    spec.force_migration = 1;

    return(sockloop_test_one(&spec));
}

/* picoquic_packet_loop_set_send_source returns immediately if the socket's bound
 * address has a family other than AF_INET/AF_INET6 (picoquic_packet_loop_addr_is_wildcard's
 * fallthrough treats that as "wildcard"). Exercise that fallthrough directly. */
int sockloop_send_source_test(void)
{
    int ret = 0;
    picoquic_socket_ctx_t s_ctx;
    struct sockaddr_storage local_addr;

    memset(&s_ctx, 0, sizeof(s_ctx));
    memset(&local_addr, 0, sizeof(local_addr));

    s_ctx.bound_addr.ss_family = AF_UNSPEC;
    local_addr.ss_family = AF_UNSPEC;

    picoquic_packet_loop_set_send_source(&s_ctx, &local_addr);

    if (local_addr.ss_family != AF_UNSPEC) {
        DBG_PRINTF("%s", "picoquic_packet_loop_set_send_source touched local_addr for a non-IP bound address");
        ret = -1;
    }

    return ret;
}

static int sockloop_delete_thread_test_cb(picoquic_quic_t* UNUSED(quic), picoquic_packet_loop_cb_enum UNUSED(cb_mode),
    void* UNUSED(callback_ctx), void* UNUSED(callback_argv))
{
    return 0;
}

/* picoquic_delete_network_thread only frees thread_ctx->param if is_param_allocated is set.
 * That flag is only ever set by picoquic_start_server_threads, which is not itself under
 * test here, so poke it directly on a param that this test really did allocate -- matching
 * the ownership contract exactly, so the delete path frees real heap memory. */
int sockloop_delete_thread_allocated_param_test(void)
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    picoquic_quic_t* quic = NULL;

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SERVER_CERT);
    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_KEY);
    }
    if (ret == 0) {
        quic = picoquic_create(8, test_server_cert_file, test_server_key_file, NULL,
            PICOQUIC_TEST_ALPN, NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        if (quic == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        picoquic_packet_loop_param_t* param = (picoquic_packet_loop_param_t*)malloc(sizeof(picoquic_packet_loop_param_t));

        if (param == NULL) {
            ret = -1;
        }
        else {
            picoquic_network_thread_ctx_t* thread_ctx;
            memset(param, 0, sizeof(picoquic_packet_loop_param_t));

            thread_ctx = picoquic_start_network_thread(quic, param, sockloop_delete_thread_test_cb, NULL, &ret);
            if (thread_ctx == NULL) {
                free(param);
                if (ret == 0) {
                    ret = -1;
                }
            }
            else {
                for (int i = 0; i < 2000 && !thread_ctx->thread_is_ready; i++) {
                    SLEEP(1);
                }
                thread_ctx->is_param_allocated = 1;
                picoquic_delete_network_thread(thread_ctx);
            }
        }
    }

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

/* picoquic_server_set_context is a real public API (used by picoquicdemo.c) but was never
 * exercised by the test suite. Build a minimal server config and call it directly. */
int sockloop_server_set_context_test(void)
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    picoquic_quic_config_t config;
    picoquic_quic_t* qserver = NULL;

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SERVER_CERT);
    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        picoquic_config_init(&config);
        config.server_cert_file = test_server_cert_file;
        config.server_key_file = test_server_key_file;
        config.nb_connections = 8;

        ret = picoquic_server_set_context(&qserver, &config, 0, NULL, NULL, NULL);
        if (ret != 0 || qserver == NULL) {
            ret = -1;
        }
        else if (!qserver->default_tp.is_reset_stream_at_enabled ||
            qserver->default_tp.max_datagram_frame_size != PICOQUIC_MAX_PACKET_SIZE) {
            ret = -1;
        }
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

/* picoquic_start_server_threads is never called anywhere (picoquicdemo.c uses the lower level
 * picoquic_server_set_context plus a manual packet loop instead). Start exactly one thread and
 * tear it down; this also exercises the is_param_allocated ownership path taken by the function
 * itself (thread_ctxs[i]->is_param_allocated = 1). */
int sockloop_start_server_threads_test(void)
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    picoquic_quic_config_t config;
    picoquic_network_thread_ctx_t* thread_ctxs[1] = { NULL };
    int nb_threads_created = 0;

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SERVER_CERT);
    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        picoquic_config_init(&config);
        config.server_cert_file = test_server_cert_file;
        config.server_key_file = test_server_key_file;
        config.nb_connections = 8;
        config.nb_threads = 1;

        ret = picoquic_start_server_threads(&config, 0, NULL, NULL, NULL,
            sockloop_delete_thread_test_cb, NULL, NULL, NULL, NULL,
            thread_ctxs, 1, &nb_threads_created);

        if (ret != 0 || nb_threads_created != 1 || thread_ctxs[0] == NULL ||
            !thread_ctxs[0]->is_param_allocated) {
            ret = -1;
        }
        else {
            picoquic_quic_t* qserver = thread_ctxs[0]->quic;

            for (int i = 0; i < 2000 && !thread_ctxs[0]->thread_is_ready; i++) {
                SLEEP(1);
            }
            picoquic_delete_network_thread(thread_ctxs[0]);
            picoquic_free(qserver);
        }
    }

    return ret;
}

int sockloop_thread_test(void)
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 7);
    spec.socket_buffer_size = 0xffff;
    spec.scenario = sockloop_test_scenario_1M;
    spec.scenario_size = sizeof(sockloop_test_scenario_1M);
    spec.use_background_thread = 1;

    return(sockloop_test_one(&spec));
}

int sockloop_thread_name_test(void)
{
    sockloop_test_spec_t spec;
    sockloop_test_set_spec(&spec, 8);
    spec.socket_buffer_size = 0xffff;
    spec.scenario = sockloop_test_scenario_1M;
    spec.scenario_size = sizeof(sockloop_test_scenario_1M);
    spec.use_background_thread = 1;
    spec.thread_name = "picoquic loop";

    return(sockloop_test_one(&spec));
}

/* Add tests of a QMUX loop. */
uint8_t sockloop_qmux_test_data[] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13,14, 15, 16
};

typedef struct st_sockloop_qmux_test_t {
    uint8_t test_id;
    int af;
    uint16_t port;
    int socket_buffer_size;
    char const* thread_name;
    int use_background_thread;
    int test_bad_port;
    int test_close;
    int test_idle;
    /* variables used to monitor execution */
    picoquic_packet_loop_param_t* param;
    int received_stream_0;
    uint64_t stream_0_length_received;
    int stream_0_data_matches;
    int stream_0_fin_received;
    int should_close_tcp;
    /* Tracking the client connection to terminate gracefully */
    picoquic_cnx_t* qmux_cnx;
} sockloop_qmux_test_t;

/* Check that frames can be received properly */
/* TODO: run a test with all frames in skip frame test, to check
* that allowed frames pass, and that not allowed frames are rejected. */

int sockloop_qmux_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* UNUSED(v_stream_ctx))
{

    int ret = 0;
    sockloop_qmux_test_t* sim_ctx = (sockloop_qmux_test_t*)callback_ctx;

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            if (stream_id == 0) {
                DBG_PRINTF("Receive data on stream 0, client_mode: %d, len: %d, fin: %d",
                    cnx->client_mode, (int)length, (fin_or_event == picoquic_callback_stream_fin));
                sim_ctx->received_stream_0 = 1;
                sim_ctx->stream_0_length_received = length;
                if (length == sizeof(sockloop_qmux_test_data) &&
                    memcmp(bytes, sockloop_qmux_test_data, length) == 0) {
                    sim_ctx->stream_0_data_matches = 1;
                }
                if (fin_or_event == picoquic_callback_stream_fin) {
                    sim_ctx->stream_0_fin_received = 1;
                    if (sim_ctx->test_close) {
                        sim_ctx->should_close_tcp = 1;
                        picoquic_connection_disconnect(cnx);
                    }
                    else if (!sim_ctx->test_idle) {
                        picoquic_close_ex(cnx, 0, "data received.");
                    }
                }
            }
            break;
        case picoquic_callback_prepare_to_send:
        case picoquic_callback_datagram:
        case picoquic_callback_prepare_datagram:
            /* not expected */
            ret = -1;
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            /* TODO: react to abandon stream, etc. */
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Remove the connection from the context, and then delete it */
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
            DBG_PRINTF("Almost ready, client_mode: %d", cnx->client_mode);
            break;
        case picoquic_callback_ready:
            /* should mark the first stream as ready, create it if necessary */
            DBG_PRINTF("Ready, client_mode: %d", cnx->client_mode);
            if (cnx->client_mode) {
                picoquic_add_to_stream(cnx, 0, sockloop_qmux_test_data, sizeof(sockloop_qmux_test_data), 1);
            }
            break;
        case picoquic_callback_request_alpn_list:
            /* qmux_test_set_alpn_list((void*)bytes); */
            break;
        case picoquic_callback_set_alpn:
            break;
        case picoquic_callback_datagram_acked:
            /* Ack for packet carrying datagram-object received from peer */
        case picoquic_callback_datagram_lost:
            /* Packet carrying datagram-object probably lost */
        case picoquic_callback_datagram_spurious:
            /* Packet carrying datagram-object was not really lost */
            break;
        case picoquic_callback_pacing_changed:
            /* Notification of rate change from congestion controller */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

int sockloop_qmux_test_cb(picoquic_quic_t* UNUSED(quic), picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void* callback_arg)
{
    int ret = 0;
    sockloop_qmux_test_t* sim_ctx = (sockloop_qmux_test_t*)callback_ctx;

    if (sim_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        if (sim_ctx->qmux_cnx == NULL) {
            DBG_PRINTF("%s", "QMUX_CNX context is NULL.");
            ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        else switch (cb_mode) {
        case picoquic_packet_loop_ready: {
            picoquic_packet_loop_options_t* options = (picoquic_packet_loop_options_t*)callback_arg;
            options->do_time_check = 1;
            fprintf(stdout, "Waiting for packets.\n");
            break;
        }
        case picoquic_packet_loop_after_receive:
            /* Post receive callback */
            if (picoquic_get_cnx_state(sim_ctx->qmux_cnx) == picoquic_state_disconnected) {
                DBG_PRINTF("The connection is closed after receive! Client mode:\n", sim_ctx->qmux_cnx->client_mode);
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
                break;
            }
            break;
        case picoquic_packet_loop_after_send:
            if (picoquic_get_cnx_state(sim_ctx->qmux_cnx) == picoquic_state_disconnected) {
                DBG_PRINTF("The connection is closed after send! Client mode:\n", sim_ctx->qmux_cnx->client_mode);
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            break;
        case picoquic_packet_loop_port_update:
            break;
            /* TODO: consider adding the delay computation callback! */
        case picoquic_packet_loop_time_check: {
            packet_loop_time_check_arg_t* time_check_arg = (packet_loop_time_check_arg_t*)callback_arg;
            if (picoquic_get_cnx_state(sim_ctx->qmux_cnx) == picoquic_state_disconnected) {
                DBG_PRINTF("The connection is closed on time check! Client mode:\n", sim_ctx->qmux_cnx->client_mode);
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
                break;
            }
            else if (time_check_arg->delta_t > 10000000) {
                time_check_arg->delta_t = 10000000;
            }
            break;
        }
        case picoquic_packet_loop_wake_up:
            break;
        case picoquic_packet_loop_alt_port:
            break;
        case picoquic_packet_loop_system_call_duration:
            break;
        default:
            DBG_PRINTF("Unexpected socket loop callback: %d.\n", cb_mode);
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}

int sockloop_qmux_one(
    sockloop_qmux_test_t* spec)
{
    int ret = 0;
    picoquic_quic_t* qserver = NULL;
    picoquic_quic_t* qmux = NULL;
    picoquic_cnx_t* cnx_qmux = NULL;
    picoquic_packet_loop_param_t param = { 0 };
    struct sockaddr_storage dest = { 0 };
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
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
        /* Create a pro-forma QUIc server */
        qserver = picoquic_create(8,
            NULL, NULL, NULL,
            PICOQUIC_TEST_ALPN, test_api_callback, NULL, NULL, NULL, NULL,
            0, NULL, NULL, NULL, 0);
        /* Create a QMux context */
        qmux = picoqmux_create(16, test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            PICOQUIC_TEST_ALPN, sockloop_qmux_callback, spec, NULL, 0, NULL,
            0, test_ticket_encrypt_key, sizeof(test_ticket_encrypt_key));
        if (qserver == NULL || qmux == NULL) {
            ret = -1;
        }
        else {
            /* set the destination address to selected port and loopback */
            picoquic_set_test_address((struct sockaddr_in*)&dest, htonl(0x7f000001), 
                (spec->test_bad_port)?spec->port:htons(spec->port));
            /* start a client connection */
            cnx_qmux = picoqmux_create_qmux_cnx(qmux, picoquic_current_time(), 1, 0,
                PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, (struct sockaddr*)&dest);
            if (cnx_qmux == NULL) {
                ret = -1;
            }
            else {
                spec->qmux_cnx = cnx_qmux;
            }
        }
    }

    if (ret == 0) {
        param.local_port = spec->port;
        param.qmux_port = spec->port;
        param.local_af = 0;
        param.socket_buffer_size = spec->socket_buffer_size;
        spec->param = &param;

        if (spec->use_background_thread) {
            picoquic_network_thread_ctx_t* thread_ctx = NULL;

            if (spec->thread_name != NULL) {
                thread_ctx = picoquic_start_custom_network_thread_qmux(qserver, qmux, &param,
                    picoquic_internal_thread_create, picoquic_internal_thread_delete,
                    picoquic_internal_thread_setname, spec->thread_name, sockloop_qmux_test_cb, spec, &ret);
            }
            else {
                thread_ctx = picoquic_start_network_thread(qserver, &param, sockloop_qmux_test_cb, spec, &ret);
            }
            if (thread_ctx == NULL) {
                if (ret == 0) {
                    ret = -1;
                }
            }
            else {
                for (int i = 0; i < 2000; i++) {
                    if (thread_ctx->thread_is_ready) {
                        DBG_PRINTF("Thread is ready after %dms", i);
                        break;
                    }
                    else {
                        SLEEP(1);
                    }
                }
                if (!thread_ctx->thread_is_ready) {
                    DBG_PRINTF("%s", "Cannot start the network thread in 2000ms");
                    ret = -1;
                }
                else if (picoquic_wake_up_network_thread(thread_ctx) != 0) {
                    DBG_PRINTF("%s", "Cannot wakeup the network thread");
                    ret = -1;
                }
                else {
                    if (spec->test_bad_port) {
                        /* we merely check that the connection was properly terminated */
                        ret = 0;
                    }
                    else {
                        if (!spec->received_stream_0 ||
                            !spec->stream_0_fin_received ||
                            !spec->stream_0_data_matches) {
                            ret = -1;
                        }
                    }
                }
                picoquic_delete_network_thread(thread_ctx);
            }
        }
        else {
            /* TODO -- proper initialization */
            picoquic_network_thread_ctx_t t_ctx = { 0 };
            t_ctx.quic = qserver;
            t_ctx.qmux = qmux;
            t_ctx.param = &param;
            t_ctx.loop_callback = sockloop_qmux_test_cb;
            t_ctx.loop_callback_ctx = spec;

            (void)picoquic_packet_loop_v3((void*)&t_ctx);

            if (spec->test_bad_port) {
                /* we merely check that the connection was properly terminated */
                ret = 0;
            }
            else {
                if (!spec->received_stream_0 ||
                    !spec->stream_0_fin_received ||
                    !spec->stream_0_data_matches) {
                    ret = -1;
                }
            }
        }
    }
    if (qmux != NULL) {
        picoquic_free(qmux);
    }
    if (qserver != NULL) {
        picoquic_free(qserver);
    }
    return ret;
}

void sockloop_test_set_qmux_spec(sockloop_qmux_test_t* spec, uint8_t test_id)
{
    memset(spec, 0, sizeof(sockloop_qmux_test_t));
    spec->test_id = test_id;
    spec->af = AF_INET6;
    spec->port = 3456;
    spec->socket_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
}

int sockloop_qmux_test(void)
{
    sockloop_qmux_test_t spec;
    sockloop_test_set_qmux_spec(&spec, 1);

    return(sockloop_qmux_one(&spec));
}

int sockloop_qmux_badp_test(void)
{
    sockloop_qmux_test_t spec;
    sockloop_test_set_qmux_spec(&spec, 1);
    spec.test_bad_port = 1;

    return(sockloop_qmux_one(&spec));
}

int picoquic_packet_loop_open_qmux_cnx_sockets(picoquic_quic_t* qmux, picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets, int max_qmux_socket);

/* picoquic_packet_loop_open_qmux_cnx_sockets used to loop forever if nb_qmux_sockets reached
 * max_qmux_socket while qmux->cnx_list still had entries left: cnx was only advanced inside the
 * "socket opened" branch, never in the "limit reached" branch. Verify it now terminates and
 * leaves nb_qmux_sockets unchanged when the limit is already hit on entry. */
int sockloop_qmux_cnx_sockets_limit_test(void)
{
    int ret = 0;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);

    if (qclient == NULL) {
        ret = -1;
    }
    else {
        struct sockaddr_in saddr = { 0 };
        picoquic_cnx_t* cnx = picoquic_create_cnx(qclient,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr*)&saddr,
            0, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            ret = -1;
        }
        else {
            picoqmux_socket_ctx_t* sqmux_ctx[1] = { NULL };
            int nb_qmux_sockets = 0;

            /* Link the connection into the qmux's connection list directly (white-box),
             * matching what picoqmux_create_qmux_cnx does for a real QMUX connection. */
            cnx->next_in_table = NULL;
            qclient->cnx_list = cnx;

            if (picoquic_packet_loop_open_qmux_cnx_sockets(qclient, sqmux_ctx, &nb_qmux_sockets, 0) != 0 ||
                nb_qmux_sockets != 0) {
                ret = -1;
            }
            qclient->cnx_list = NULL;
            picoquic_delete_cnx(cnx);
        }
        picoquic_free(qclient);
    }
    return ret;
}
