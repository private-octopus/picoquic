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

/* 
* Testing the socket loop.
* This requires sending packets through sockets, etc. We do that by using a 
* single QUIC context as both server and client, using a local socket to
* loop packets between the client and server connections.
 */

typedef struct st_client_loop_cb_t {
    picoquic_cnx_t* cnx_client;
    picoquic_demo_callback_ctx_t* demo_callback_ctx;
    siduck_ctx_t* siduck_ctx;
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
    int is_siduck;
    int is_quicperf;
    int socket_buffer_size;
    int multipath_probe_done;
    char const* saved_alpn;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    struct sockaddr_storage client_alt_address[PICOQUIC_NB_PATH_TARGET];
    int client_alt_if[PICOQUIC_NB_PATH_TARGET];
    int nb_alt_paths;
    picoquic_connection_id_t server_cid_before_migration;
    picoquic_connection_id_t client_cid_before_migration;
} client_loop_cb_t;


int client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, 
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    client_loop_cb_t* cb_ctx = (client_loop_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            DBG_PRINTF("%s", "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            /* Post receive callback */
            if ((!cb_ctx->is_siduck && !cb_ctx->is_quicperf && cb_ctx->demo_callback_ctx->connection_closed) ||
                cb_ctx->cnx_client->cnx_state == picoquic_state_disconnected) {
                fprintf(stdout, "The connection is closed!\n");
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
                break;
            }
            /* Keeping track of the addresses and ports, as we
            * need them to verify the migration behavior */
            if (!cb_ctx->address_updated && cb_ctx->cnx_client->path[0]->local_addr.ss_family != 0) {
                uint16_t updated_port = (cb_ctx->cnx_client->path[0]->local_addr.ss_family == AF_INET) ?
                    ((struct sockaddr_in*) & cb_ctx->cnx_client->path[0]->local_addr)->sin_port :
                    ((struct sockaddr_in6*) & cb_ctx->cnx_client->path[0]->local_addr)->sin6_port;
                if (updated_port != 0) {
                    cb_ctx->address_updated = 1;
                    picoquic_store_addr(&cb_ctx->client_address, (struct sockaddr*) & cb_ctx->cnx_client->path[0]->local_addr);
                    fprintf(stdout, "Client port (AF=%d): %d.\n", cb_ctx->client_address.ss_family, updated_port);
                }
            }
            if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_almost_ready && cb_ctx->notified_ready == 0) {
                /* if almost ready, display results of negotiation */
                if (picoquic_tls_is_psk_handshake(cb_ctx->cnx_client)) {
                    fprintf(stdout, "The session was properly resumed!\n");
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "%s", "The session was properly resumed!");
                }

                if (cb_ctx->cnx_client->zero_rtt_data_accepted) {
                    fprintf(stdout, "Zero RTT data is accepted!\n");
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "%s", "Zero RTT data is accepted!");
                }

                if (cb_ctx->cnx_client->alpn != NULL) {
                    fprintf(stdout, "Negotiated ALPN: %s\n", cb_ctx->cnx_client->alpn);
                    picoquic_log_app_message(cb_ctx->cnx_client,
                        "Negotiated ALPN: %s", cb_ctx->cnx_client->alpn);
                    cb_ctx->saved_alpn = picoquic_string_duplicate(cb_ctx->cnx_client->alpn);
                }
                fprintf(stdout, "Almost ready!\n\n");
                cb_ctx->notified_ready = 1;
            }
            else if (ret == 0 && (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready ||
                picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_ready_start)) {
                int simulate_multipath = 0;

                if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready && cb_ctx->multipath_probe_done == 0) {
                    /* Create the required additional paths. 
                    * In some cases, we just want to test the software from a computer that is not actually
                    * multihomed. In that case, the client_alt_address is set to ::0 (IPv6 null address),
                    * and the callback will return "PICOQUIC_NO_ERROR_SIMULATE_MIGRATION", which
                    * causes the socket code to create an additional socket, and issue a 
                    * picoquic_probe_new_path request for the corresponding address.
                    */
                    struct sockaddr_in6 addr_zero = { 0 };
                    addr_zero.sin6_family = AF_INET6;

                    for (int i = 0; i < cb_ctx->nb_alt_paths; i++) {
                        if (picoquic_compare_addr((struct sockaddr*)&addr_zero, (struct sockaddr*)&cb_ctx->client_alt_address[i]) == 0) {
                            simulate_multipath = 1;
                            picoquic_log_app_message(cb_ctx->cnx_client, "%s\n", "Will try to simulate new path");
                        }
                        else if ((ret = picoquic_probe_new_path_ex(cb_ctx->cnx_client, (struct sockaddr *)&cb_ctx->server_address,
                            (struct sockaddr *)&cb_ctx->client_alt_address[i], cb_ctx->client_alt_if[i], picoquic_get_quic_time(quic), 0)) != 0) {
                            picoquic_log_app_message(cb_ctx->cnx_client, "Probe new path failed with exit code %d\n", ret);
                        } else {
                            picoquic_log_app_message(cb_ctx->cnx_client, "New path added, total path available %d\n", cb_ctx->cnx_client->nb_paths);
                        }
                        cb_ctx->multipath_probe_done = 1;
                    }
                }

                /* Track the migration to server preferred address */
                if (cb_ctx->cnx_client->remote_parameters.prefered_address.is_defined && !cb_ctx->migration_to_preferred_finished) {
                    if (picoquic_compare_addr(
                        (struct sockaddr*) & cb_ctx->server_address, (struct sockaddr*) & cb_ctx->cnx_client->path[0]->peer_addr) != 0) {
                        fprintf(stdout, "Migrated to server preferred address!\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Migrated to server preferred address!");
                        cb_ctx->migration_to_preferred_finished = 1;
                    }
                    else if (cb_ctx->cnx_client->nb_paths > 1 && !cb_ctx->migration_to_preferred_started) {
                        cb_ctx->migration_to_preferred_started = 1;
                        fprintf(stdout, "Attempting migration to server preferred address.\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Attempting migration to server preferred address.");

                    }
                    else if (cb_ctx->cnx_client->nb_paths == 1 && cb_ctx->migration_to_preferred_started) {
                        fprintf(stdout, "Could not migrate to server preferred address!\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Could not migrate to server preferred address!");
                        cb_ctx->migration_to_preferred_finished = 1;
                    }
                }

                /* Execute the migration trials
                * The actual change of sockets is delegated to the packet loop function,
                * so it can be integrated with other aspects of socket management.
                * If a new socket is needed, two special error codes will be used.
                */
                if (cb_ctx->force_migration && cb_ctx->migration_started == 0 && cb_ctx->address_updated &&
                    picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready &&
                    (cb_ctx->cnx_client->cnxid_stash_first != NULL || cb_ctx->force_migration == 1) &&
                    (!cb_ctx->cnx_client->remote_parameters.prefered_address.is_defined ||
                        cb_ctx->migration_to_preferred_finished)) {
                    int mig_ret = 0;
                    cb_ctx->migration_started = 1;
                    cb_ctx->server_cid_before_migration = cb_ctx->cnx_client->path[0]->p_remote_cnxid->cnx_id;
                    if (cb_ctx->cnx_client->path[0]->p_local_cnxid != NULL) {
                        cb_ctx->client_cid_before_migration = cb_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id;
                    }
                    else {
                        /* Special case of forced migration after preferred address migration */
                        memset(&cb_ctx->client_cid_before_migration, 0, sizeof(picoquic_connection_id_t));
                    }
                    switch (cb_ctx->force_migration) {
                    case 1:
                        fprintf(stdout, "Switch to new port. Will test NAT rebinding support.\n");
                        ret = PICOQUIC_NO_ERROR_SIMULATE_NAT;
                        break;
                    case 2:
                        mig_ret = picoquic_renew_connection_id(cb_ctx->cnx_client, 0);
                        if (mig_ret != 0) {
                            if (mig_ret == PICOQUIC_ERROR_MIGRATION_DISABLED) {
                                fprintf(stdout, "Migration disabled, cannot test CNXID renewal.\n");
                            }
                            else {
                                fprintf(stdout, "Renew CNXID failed, error: %x.\n", mig_ret);
                            }
                            cb_ctx->migration_started = -1;
                        }
                        else {
                            fprintf(stdout, "Switching to new CNXID.\n");
                        }
                        break;
                    case 3:
                        fprintf(stdout, "Will test migration to new port.\n");
                        ret = PICOQUIC_NO_ERROR_SIMULATE_MIGRATION;
                        break;
                    default:
                        cb_ctx->migration_started = -1;
                        fprintf(stdout, "Invalid migration code: %d!\n", cb_ctx->force_migration);
                        break;
                    }
                }

                /* Track key update */
                if (cb_ctx->nb_packets_before_key_update > 0 &&
                    !cb_ctx->key_update_done &&
                    picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready &&
                    cb_ctx->cnx_client->nb_packets_received > (uint64_t)cb_ctx->nb_packets_before_key_update) {
                    int key_rot_ret = picoquic_start_key_rotation(cb_ctx->cnx_client);
                    if (key_rot_ret != 0) {
                        fprintf(stdout, "Will not test key rotation.\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Will not test key rotation.");
                        cb_ctx->key_update_done = -1;
                    }
                    else {
                        fprintf(stdout, "Key rotation started.\n");
                        picoquic_log_app_message(cb_ctx->cnx_client, "%s", "Key rotation started.");
                        cb_ctx->key_update_done = 1;
                    }
                }

                if (!cb_ctx->is_siduck && !cb_ctx->is_quicperf && cb_ctx->demo_callback_ctx->nb_open_streams == 0) {
                    fprintf(stdout, "All done, Closing the connection.\n");
                    picoquic_log_app_message(cb_ctx->cnx_client, "%s", "All done, Closing the connection.");

                    ret = picoquic_close(cb_ctx->cnx_client, 0);
                }
                if (simulate_multipath) {
                    ret = PICOQUIC_NO_ERROR_SIMULATE_MIGRATION;
                }
            }
            break;
        case picoquic_packet_loop_after_send:
            if (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_disconnected) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            else if (ret == 0 && cb_ctx->established == 0 && (picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_ready ||
                picoquic_get_cnx_state(cb_ctx->cnx_client) == picoquic_state_client_ready_start)) {
                printf("Connection established. Version = %x, I-CID: %llx, verified: %d\n",
                    picoquic_supported_versions[cb_ctx->cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cb_ctx->cnx_client)),
                    cb_ctx->cnx_client->is_hcid_verified);

                picoquic_log_app_message(cb_ctx->cnx_client,
                    "Connection established. Version = %x, I-CID: %llx, verified: %d",
                    picoquic_supported_versions[cb_ctx->cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cb_ctx->cnx_client)),
                    cb_ctx->cnx_client->is_hcid_verified);
                cb_ctx->established = 1;

                if (!cb_ctx->zero_rtt_available && !cb_ctx->is_siduck && !cb_ctx->is_quicperf) {
                    /* Start the download scenario */
                    ret = picoquic_demo_client_start_streams(cb_ctx->cnx_client, cb_ctx->demo_callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                }
            }
            break;
        case picoquic_packet_loop_port_update:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}


int sockloop_test_create_ctx(picoquic_test_tls_api_ctx_t* test_ctx)
{
    return -1;
}

int sockloop_test_quic_config(picoquic_test_tls_api_ctx_t* test_ctx, picoquic_quic_t ** p_quic)
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picoquic_quic_t* quic = NULL;

    *p_quic = NULL;

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
        (use_ecdsa)?PICOQUIC_TEST_FILE_SERVER_CERT_ECDSA:PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
            (use_ecdsa)?PICOQUIC_TEST_FILE_SERVER_KEY_ECDSA:PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {
        quic = picoquic_create(nb_connections,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            (alpn == NULL) ? PICOQUIC_TEST_ALPN : alpn, test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
            0, NULL, NULL, test_ticket_encrypt_key, sizeof(test_ticket_encrypt_key));

        if (quic == NULL) {
            ret = -1;
        }
        else {
            *p_quic = quic;
        }
    }
    return ret;
}

int sockloop_test_cnx_config()
{
    return -1;
}

int sockloop_quic_test()
{
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_quic_t* quic = NULL;
    client_loop_cb_t loop_cb;

    /* Create QUIC context */
    ret = sockloop_test_quic_config(&quic);
    /* Create connection context */
    /* Program connection scenario */

    /* Run the loop */

#ifdef _WINDOWS
    ret = picoquic_packet_loop_win(quic, 0, loop_cb.server_address.ss_family, 0, 
        config->socket_buffer_size, client_loop_cb, &loop_cb);
#else
    ret = picoquic_packet_loop(quic, 0, loop_cb.server_address.ss_family, 0,
        config->socket_buffer_size, config->do_not_use_gso, client_loop_cb, &loop_cb);
#endif

    /* Verify that the scenario worked. */

    /* Free the config */
    if (quic != NULL) {
        picoquic_free(quic);
    }
    return ret;
}