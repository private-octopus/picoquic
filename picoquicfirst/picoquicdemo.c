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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include "getopt.h"
#include <WinSock2.h>
#include <Windows.h>

#define SERVER_CERT_FILE "certs\\cert.pem"
#define SERVER_KEY_FILE  "certs\\key.pem"

#else /* Linux */

#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/select.h>

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"

#endif

static const int default_server_port = 4443;
static const char* default_server_name = "::";
static const char* ticket_store_filename = "demo_ticket_store.bin";
static const char* token_store_filename = "demo_token_store.bin";


#include "picoquic.h"
#include "picoquic_packet_loop.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "autoqlog.h"
#include "h3zero.h"
#include "democlient.h"
#include "demoserver.h"
#include "siduck.h"
/*
 * SIDUCK datagram demo call back.
 */
int siduck_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

void print_address(FILE* F_log, struct sockaddr* address, char* label, picoquic_connection_id_t cnx_id)
{
    char hostname[256];

    const char* x = inet_ntop(address->sa_family,
        (address->sa_family == AF_INET) ? (void*)&(((struct sockaddr_in*)address)->sin_addr) : (void*)&(((struct sockaddr_in6*)address)->sin6_addr),
        hostname, sizeof(hostname));

    fprintf(F_log, "%016llx : ", (unsigned long long)picoquic_val64_connection_id(cnx_id));

    if (x != NULL) {
        fprintf(F_log, "%s %s, port %d\n", label, x,
            (address->sa_family == AF_INET) ? ((struct sockaddr_in*)address)->sin_port : ((struct sockaddr_in6*)address)->sin6_port);
    } else {
        fprintf(F_log, "%s: inet_ntop failed with error # %ld\n", label, WSA_LAST_ERROR(errno));
    }
}

/* server loop call back management */
typedef struct st_server_loop_cb_t {
    int just_once;
    int first_connection_seen;
    int connection_done;
} server_loop_cb_t;

static int server_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, void* callback_ctx)
{
    int ret = 0;
    server_loop_cb_t* cb_ctx = (server_loop_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            break;
        case picoquic_packet_loop_after_send:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }

        if (ret == 0 && cb_ctx->just_once){
            if (!cb_ctx->first_connection_seen && picoquic_get_first_cnx(quic) != NULL) {
                cb_ctx->first_connection_seen = 1;
                fprintf(stdout, "First connection noticed.\n");
            } else if (cb_ctx->first_connection_seen && picoquic_get_first_cnx(quic) == NULL) {
                fprintf(stdout, "No more active connections.\n");
                cb_ctx->connection_done = 1;
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
        }
    }
    return ret;
}

int quic_server(const char* server_name, int server_port,
    const char* pem_cert, const char* pem_key,
    int just_once, int do_retry, picoquic_connection_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_ctx, uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    int dest_if, int mtu_max, uint32_t proposed_version,
    const char* esni_key_file_name, const char* esni_rr_file_name,
    char const* log_file, char const* bin_dir, char const* qlog_dir, int use_long_log,
    picoquic_congestion_algorithm_t const* cc_algorithm, char const* web_folder,
    int initial_random)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qserver = NULL;
    uint64_t current_time = 0;
    picohttp_server_parameters_t picoquic_file_param;
    server_loop_cb_t loop_cb_ctx;

    memset(&picoquic_file_param, 0, sizeof(picohttp_server_parameters_t));
    picoquic_file_param.web_folder = web_folder;
    memset(&loop_cb_ctx, 0, sizeof(server_loop_cb_t));
    loop_cb_ctx.just_once = just_once;

    /* Setup the server context */
    if (ret == 0) {
        current_time = picoquic_current_time();
        /* Create QUIC context */
        qserver = picoquic_create(8, pem_cert, pem_key, NULL, NULL,
            picoquic_demo_server_callback, &picoquic_file_param,
            cnx_id_callback, cnx_id_callback_ctx, reset_seed, current_time, NULL, NULL, NULL, 0);

        if (qserver == NULL) {
            printf("Could not create server context\n");
            ret = -1;
        }
        else {
            picoquic_set_alpn_select_fn(qserver, picoquic_demo_server_callback_select_alpn);
            if (do_retry != 0) {
                picoquic_set_cookie_mode(qserver, 1);
            }
            else {
                picoquic_set_cookie_mode(qserver, 2);
            }
            qserver->mtu_max = mtu_max;

            if (cc_algorithm == NULL) {
                cc_algorithm = picoquic_bbr_algorithm;
            }
            picoquic_set_default_congestion_algorithm(qserver, cc_algorithm);

            picoquic_set_padding_policy(qserver, 39, 128);

            picoquic_set_binlog(qserver, bin_dir);

            picoquic_set_qlog(qserver, qlog_dir);

            picoquic_set_textlog(qserver, log_file);

            picoquic_set_log_level(qserver, use_long_log);

            if (initial_random) {
                picoquic_set_random_initial(qserver, 1);
            }

            picoquic_set_key_log_file_from_env(qserver);

            if (esni_key_file_name != NULL && esni_rr_file_name != NULL) {
                ret = picoquic_esni_load_key(qserver, esni_key_file_name);
                if (ret == 0) {
                    ret = picoquic_esni_server_setup(qserver, esni_rr_file_name);
                }
            }
        }
    }

    if (ret == 0) {
        /* Wait for packets */
#if _WINDOWS
        ret = picoquic_packet_loop_win(qserver, server_port, 0, dest_if, server_loop_cb, &loop_cb_ctx);
#else
        ret = picoquic_packet_loop(qserver, server_port, 0, dest_if, server_loop_cb, &loop_cb_ctx);
#endif
    }

    /* And exit */
    printf("Server exit, ret = 0x%x\n", ret);

    /* Clean up */
    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

static const char * test_scenario_default = "0:index.html;4:test.html;8:/1234567;12:main.jpg;16:war-and-peace.txt;20:en/latest/;24:/file-123K";

/* Client loop call back management.
 * This is pretty complex, because the demo client is used to test a variety of interop
 * scenarios, for example:
 *
 * Variants of migration:
 * - Basic NAT traversal (1)
 * - Simple CID swap (2)
 * - Organized migration (3)
 * Encryption key rotation, after some number of packets have been sent.
 *
 * The client loop terminates when the client connection is closed.
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
    char const* saved_alpn;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    picoquic_connection_id_t server_cid_before_migration;
    picoquic_connection_id_t client_cid_before_migration;
} client_loop_cb_t;

int client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, void* callback_ctx)
{
    int ret = 0;
    client_loop_cb_t* cb_ctx = (client_loop_cb_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            /* Post receive callback */
            if ((!cb_ctx->is_siduck && cb_ctx->demo_callback_ctx->connection_closed) ||
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
                    (cb_ctx->force_migration != 3 || !cb_ctx->cnx_client->remote_parameters.prefered_address.is_defined ||
                        cb_ctx->migration_to_preferred_finished)) {
                    int mig_ret = 0;
                    cb_ctx->migration_started = 1;
                    cb_ctx->server_cid_before_migration = cb_ctx->cnx_client->path[0]->remote_cnxid;
                    cb_ctx->client_cid_before_migration = cb_ctx->cnx_client->path[0]->p_local_cnxid->cnx_id;
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

                if (!cb_ctx->is_siduck && cb_ctx->demo_callback_ctx->nb_open_streams == 0) {
                    fprintf(stdout, "All done, Closing the connection.\n");
                    picoquic_log_app_message(cb_ctx->cnx_client, "%s", "All done, Closing the connection.");

                    ret = picoquic_close(cb_ctx->cnx_client, 0);
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

                if (!cb_ctx->zero_rtt_available && !cb_ctx->is_siduck) {
                    /* Start the download scenario */
                    picoquic_demo_client_start_streams(cb_ctx->cnx_client, cb_ctx->demo_callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
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

/* Quic Client */
int quic_client(const char* ip_address_text, int server_port, 
    const char * sni, const char * esni_rr_file,
    const char * alpn, const char * root_crt,
    uint32_t proposed_version, int force_zero_share, int force_migration,
    int nb_packets_before_key_update, int mtu_max, char const * log_file, 
    char const* bin_dir, char const* qlog_dir,
    int client_cnx_id_length, char const * client_scenario_text, 
    int no_disk, int use_long_log, picoquic_congestion_algorithm_t const* cc_algorithm,
    int large_client_hello, char const * out_dir, int cipher_suite_id,
    int initial_random)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    uint64_t current_time = 0;
    int is_name = 0;
    size_t client_sc_nb = 0;
    picoquic_demo_stream_desc_t * client_sc = NULL;
    int is_siduck = 0;
    siduck_ctx_t* siduck_ctx = NULL;
    client_loop_cb_t loop_cb;

    memset(&loop_cb, 0, sizeof(client_loop_cb_t));

    if (alpn != NULL && (strcmp(alpn, "siduck") == 0 || strcmp(alpn, "siduck-00") == 0)) {
        /* Set a siduck client */
        is_siduck = 1;
        siduck_ctx = siduck_create_ctx(stdout);
        if (siduck_ctx == NULL) {
            fprintf(stdout, "Could not get ready to quack\n");
            return -1;
        }
        fprintf(stdout, "Getting ready to quack\n");
    }
    else {
        if (no_disk) {
            fprintf(stdout, "Files not saved to disk (-D, no_disk)\n");
        }

        if (client_scenario_text == NULL) {
            client_scenario_text = test_scenario_default;
        }

        fprintf(stdout, "Testing scenario: <%s>\n", client_scenario_text);
        ret = demo_client_parse_scenario_desc(client_scenario_text, &client_sc_nb, &client_sc);
        if (ret != 0) {
            fprintf(stdout, "Cannot parse the specified scenario.\n");
            return -1;
        }
        else {
            ret = picoquic_demo_client_initialize_context(&callback_ctx, client_sc, client_sc_nb, alpn, no_disk, 0);
            callback_ctx.out_dir = out_dir;
        }
    }

    if (ret == 0) {
        ret = picoquic_get_server_address(ip_address_text, server_port, &loop_cb.server_address, &is_name);
        if (sni == NULL && is_name != 0) {
            sni = ip_address_text;
        }
    }

    /* Create QUIC context */
    current_time = picoquic_current_time();
    callback_ctx.last_interaction_time = current_time;

    if (ret == 0) {
        qclient = picoquic_create(8, NULL, NULL, root_crt, alpn, NULL, NULL, NULL, NULL, NULL, current_time, NULL,
            ticket_store_filename, NULL, 0);

        if (qclient == NULL) {
            ret = -1;
        } else {
            if (cc_algorithm == NULL) {
                cc_algorithm = picoquic_bbr_algorithm;
            }
            picoquic_set_default_congestion_algorithm(qclient, cc_algorithm);

            if (picoquic_load_retry_tokens(qclient, token_store_filename) != 0) {
                fprintf(stderr, "No token file present. Will create one as <%s>.\n", token_store_filename);
            }

            if (force_zero_share) {
                qclient->client_zero_share = 1;
            }
            qclient->mtu_max = mtu_max;

            (void)picoquic_set_default_connection_id_length(qclient, (uint8_t)client_cnx_id_length);

            picoquic_set_key_log_file_from_env(qclient);
            picoquic_set_binlog(qclient, bin_dir);
            picoquic_set_qlog(qclient, qlog_dir);
            picoquic_set_textlog(qclient, log_file);
            picoquic_set_log_level(qclient, use_long_log);
            if (initial_random) {
                picoquic_set_random_initial(qclient, 1);
            }

            if (cipher_suite_id != 0) {
                if (picoquic_set_cipher_suite(qclient, cipher_suite_id) != 0) {
                    fprintf(stderr, "Could not set cipher suite #%d.\n", cipher_suite_id);
                }
            }
        }
    }

    /* Create the client connection */
    if (ret == 0) {
        /* Create a client connection */
        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&loop_cb.server_address, current_time,
            proposed_version, sni, alpn, 1);

        if (cnx_client == NULL) {
            ret = -1;
        }
        else {
            if (is_siduck) {
                picoquic_set_callback(cnx_client, siduck_callback, siduck_ctx);
                cnx_client->local_parameters.max_datagram_frame_size = 128;
            }
            else {
                picoquic_set_callback(cnx_client, picoquic_demo_client_callback, &callback_ctx);

                if (cnx_client->alpn == NULL) {
                    picoquic_demo_client_set_alpn_from_tickets(cnx_client, &callback_ctx, current_time);
                    if (cnx_client->alpn != NULL) {
                        fprintf(stdout, "Set ALPN to %s based on stored ticket\n", cnx_client->alpn);
                        picoquic_log_app_message(cnx_client,
                            "Set ALPN to %s based on stored ticket", cnx_client->alpn);
                    }
                }

                /* Requires TP grease, for interop tests */
                cnx_client->grease_transport_parameters = 1;
                cnx_client->local_parameters.enable_time_stamp = 3;
                cnx_client->local_parameters.do_grease_quic_bit = 1;

                if (callback_ctx.tp != NULL) {
                    picoquic_set_transport_parameters(cnx_client, callback_ctx.tp);
                }
            }

            if (large_client_hello) {
                cnx_client->test_large_chello = 1;
            }

            if (esni_rr_file != NULL) {
                ret = picoquic_esni_client_from_file(cnx_client, esni_rr_file);
            }

            fprintf(stdout, "Max stream id bidir remote before start = %d (%d)\n",
                (int)cnx_client->max_stream_id_bidir_remote,
                (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);

            if (ret == 0) {
                ret = picoquic_start_client_cnx(cnx_client);

                printf("Starting client connection. Version = %x, I-CID: %llx\n",
                    picoquic_supported_versions[cnx_client->version_index].version,
                    (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_client)));

                fprintf(stdout, "Max stream id bidir remote after start = %d (%d)\n",
                    (int)cnx_client->max_stream_id_bidir_remote,
                    (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);
            }

            if (ret == 0 && !is_siduck) {
                if (picoquic_is_0rtt_available(cnx_client) && (proposed_version & 0x0a0a0a0a) != 0x0a0a0a0a) {
                    loop_cb.zero_rtt_available = 1;

                    fprintf(stdout, "Max stream id bidir remote after 0rtt = %d (%d)\n",
                        (int)cnx_client->max_stream_id_bidir_remote,
                        (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);

                    /* Queue a simple frame to perform 0-RTT test */
                    /* Start the download scenario */

                    ret = picoquic_demo_client_start_streams(cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                }
            }
        }
    }

    /* Wait for packets */
    if (ret == 0) {
        loop_cb.cnx_client = cnx_client;
        loop_cb.force_migration = force_migration;
        loop_cb.nb_packets_before_key_update = nb_packets_before_key_update;
        loop_cb.is_siduck = is_siduck;
        if (is_siduck) {
            loop_cb.siduck_ctx = siduck_ctx;
        }
        else {
            loop_cb.demo_callback_ctx = &callback_ctx;
        }

#ifdef _WINDOWS
        ret = picoquic_packet_loop_win(qclient, 0, loop_cb.server_address.ss_family, 0, client_loop_cb, &loop_cb);
#else
        ret = picoquic_packet_loop(qclient, 0, loop_cb.server_address.ss_family, 0, client_loop_cb, &loop_cb);
#endif
    }

    if (ret == 0) {
        /* Report on successes and failures */
        if (cnx_client->nb_zero_rtt_sent != 0) {
            fprintf(stdout, "Out of %d zero RTT packets, %d were acked by the server.\n",
                cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
            picoquic_log_app_message(cnx_client, "Out of %d zero RTT packets, %d were acked by the server.",
                cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
        }

        fprintf(stdout, "Quic Bit was %sgreased by the client.\n", (cnx_client->quic_bit_greased) ? "" : "NOT ");
        fprintf(stdout, "Quic Bit was %sgreased by the server.\n", (cnx_client->quic_bit_received_0) ? "" : "NOT ");

        if (cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_local != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_local != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_local != 0) {
            fprintf(stdout, "ECN was received (ect0: %" PRIu64 ", ect1: %" PRIu64 ", ce: %" PRIu64 ").\n",
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_local,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_local,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_local);
        }
        else {
            fprintf(stdout, "ECN was not received.\n");
        }

        if (cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_remote != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_remote != 0 ||
            cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_remote != 0) {
            fprintf(stdout, "ECN was acknowledged (ect0: %" PRIu64 ", ect1: %" PRIu64 ", ce: %" PRIu64 ").\n",
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect0_total_remote,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ect1_total_remote,
                cnx_client->pkt_ctx[picoquic_packet_context_application].ecn_ce_total_remote);
        }
        else {
            fprintf(stdout, "ECN was not acknowledged.\n");
        }

        if (loop_cb.force_migration){
            if (!loop_cb.migration_started) {
                fprintf(stdout, "Could not start testing migration.\n");
                picoquic_log_app_message(cnx_client, "%s", "Could not start testing migration.");
                loop_cb.migration_started = -1;
            }
            else {
                int source_addr_cmp = picoquic_compare_addr(
                    (struct sockaddr*) & cnx_client->path[0]->local_addr,
                    (struct sockaddr*) & loop_cb.client_address);
                int dest_cid_cmp = picoquic_compare_connection_id(
                    &cnx_client->path[0]->remote_cnxid,
                    &loop_cb.server_cid_before_migration);
                fprintf(stdout, "After migration:\n");
                fprintf(stdout, "- Default source address %s\n", (source_addr_cmp) ? "changed" : "did not change");
                if (cnx_client->path[0]->p_local_cnxid == NULL) {
                    fprintf(stdout, "- Local CID is NULL!\n");
                }
                else {
                    int source_cid_cmp = picoquic_compare_connection_id(
                        &cnx_client->path[0]->p_local_cnxid->cnx_id,
                        &loop_cb.client_cid_before_migration);
                    fprintf(stdout, "- Local CID %s\n", (source_cid_cmp) ? "changed" : "did not change");
                }
                fprintf(stdout, "- Remode CID %s\n", (dest_cid_cmp) ? "changed" : "did not change");
            }
        }

        if (loop_cb.nb_packets_before_key_update > 0) {
            if (loop_cb.key_update_done == 0) {
                fprintf(stdout, "Did not start key rotation.\n");
            }
            else if (loop_cb.key_update_done == -1) {
                fprintf(stdout, "Error when starting key rotation.\n");
            }
            else {
                fprintf(stdout, "Crypto rotation sequence: %" PRIu64 ", phase ENC: %d, phase DEC: %d\n",
                    cnx_client->crypto_rotation_sequence,
                    cnx_client->key_phase_enc, cnx_client->key_phase_dec);
            }
        }

        if (picoquic_get_data_received(cnx_client) > 0) {
            double duration_usec = (double)(picoquic_get_quic_time(qclient) - picoquic_get_cnx_start_time(cnx_client));

            if (duration_usec > 0) {
                double receive_rate_mbps = 8.0 * ((double)picoquic_get_data_received(cnx_client)) / duration_usec;
                fprintf(stdout, "Received %llu bytes in %f seconds, %f Mbps.\n",
                    (unsigned long long)picoquic_get_data_received(cnx_client),
                    duration_usec / 1000000.0, receive_rate_mbps);
                picoquic_log_app_message(cnx_client, "Received %llu bytes in %f seconds, %f Mbps.",
                    (unsigned long long)picoquic_get_data_received(cnx_client),
                    duration_usec / 1000000.0, receive_rate_mbps);
            }
        }
    }

    if (qclient != NULL) {
        uint8_t* ticket;
        uint16_t ticket_length;

        if (sni != NULL && loop_cb.saved_alpn != NULL && 0 == picoquic_get_ticket(qclient->p_first_ticket, current_time, sni, (uint16_t)strlen(sni), loop_cb.saved_alpn,
            (uint16_t)strlen(loop_cb.saved_alpn), &ticket, &ticket_length, NULL, 0)) {
            fprintf(stdout, "Received ticket from %s (%s):\n", sni, loop_cb.saved_alpn);
            picoquic_log_picotls_ticket(stdout, picoquic_null_connection_id, ticket, ticket_length);
        }

        if (picoquic_save_session_tickets(qclient, ticket_store_filename) != 0) {
            fprintf(stderr, "Could not store the saved session tickets.\n");
        }

        if (picoquic_save_retry_tokens(qclient, token_store_filename) != 0) {
            fprintf(stderr, "Could not save tokens to <%s>.\n", token_store_filename);
        }

        picoquic_free(qclient);
    }

    /* Clean up */
    if (is_siduck) {
        if (siduck_ctx != NULL) {
            free(siduck_ctx);
        }
    }
    else {
        picoquic_demo_client_delete_context(&callback_ctx);
    }

    if (loop_cb.saved_alpn != NULL) {
        free((void *)loop_cb.saved_alpn);
        loop_cb.saved_alpn = NULL;
    }

    if (client_scenario_text != NULL && client_sc != NULL) {
        demo_client_delete_scenario_desc(client_sc_nb, client_sc);
        client_sc = NULL;
    }
    return ret;
}

uint32_t parse_target_version(char const* v_arg)
{
    /* Expect the version to be encoded in base 16 */
    uint32_t v = 0;
    char const* x = v_arg;

    while (*x != 0) {
        int c = *x;

        if (c >= '0' && c <= '9') {
            c -= '0';
        } else if (c >= 'a' && c <= 'f') {
            c -= 'a';
            c += 10;
        } else if (c >= 'A' && c <= 'F') {
            c -= 'A';
            c += 10;
        } else {
            v = 0;
            break;
        }
        v *= 16;
        v += c;
        x++;
    }

    return v;
}

void usage()
{
    fprintf(stderr, "PicoQUIC demo client and server\n");
    fprintf(stderr, "Usage: picoquicdemo <options> [server_name [port [scenario]]] \n");
    fprintf(stderr, "  For the client mode, specify server_name and port.\n");
    fprintf(stderr, "  For the server mode, use -p to specify the port.\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -c file               cert file (default: %s)\n", SERVER_CERT_FILE);
    fprintf(stderr, "  -e if                 Send on interface (default: -1)\n");
    fprintf(stderr, "                           -1: receiving interface\n");
    fprintf(stderr, "                            0: routing lookup\n");
    fprintf(stderr, "                            n: ifindex\n");
    fprintf(stderr, "  -f migration_mode     Force client to migrate to start migration:\n");
    fprintf(stderr, "                        -f 1  test NAT rebinding,\n");
    fprintf(stderr, "                        -f 2  test CNXID renewal,\n");
    fprintf(stderr, "                        -f 3  test migration to new address.\n");
    fprintf(stderr, "  -h                    This help message\n");
    fprintf(stderr, "  -i <src mask value>   Connection ID modification: (src & ~mask) || val\n");
    fprintf(stderr, "                        Implies unconditional server cnx_id xmit\n");
    fprintf(stderr, "                          where <src> is int:\n");
    fprintf(stderr, "                            0: picoquic_cnx_id_random\n");
    fprintf(stderr, "                            1: picoquic_cnx_id_remote (client)\n");
    fprintf(stderr, "                            2: same as 0, plus encryption of unmasked data\n");
    fprintf(stderr, "                            3: same as 0, plus encryption of all data\n");
    fprintf(stderr, "                        val and mask must be hex strings of same length, 4 to 18\n");
    fprintf(stderr, "  -k file               key file (default: %s)\n", SERVER_KEY_FILE);
    fprintf(stderr, "  -K file               ESNI private key file (default: don't use ESNI)\n");
    fprintf(stderr, "  -E file               ESNI RR file (default: don't use ESNI)\n");
    fprintf(stderr, "  -C cipher_suite_id    specify cipher suite (e.g. -C 20 = chacha20)\n");
    fprintf(stderr, "  -o folder             Folder where client writes downloaded files,\n");
    fprintf(stderr, "                        defaults to current directory.\n");
    fprintf(stderr, "  -w folder             Folder containing web pages served by server\n");
    fprintf(stderr, "  -l file               Log file, Log to stdout if file = \"n\". No logging if absent.\n");
    fprintf(stderr, "  -b bin_dir            Binary logging to this directory. No binary logging if absent.\n");
    fprintf(stderr, "  -q qlog_dir           Qlog logging to this directory. No qlog logging if absent,\n");
    fprintf(stderr, "                        but qlogs could be extracted from binary logs using picolog\n");
    fprintf(stderr, "                        if binary logs are available.\n");
    fprintf(stderr, "                        Production of qlogs on servers affects performance.\n");
    fprintf(stderr, "  -L                    Log all packets. If absent, log stops after 100 packets.\n");
    fprintf(stderr, "  -p port               server port (default: %d)\n", default_server_port);
    fprintf(stderr, "  -m mtu_max            Largest mtu value that can be tried for discovery\n");
    fprintf(stderr, "  -n sni                sni (default: server name)\n");
    fprintf(stderr, "  -a alpn               alpn (default function of version)\n");
    fprintf(stderr, "  -r                    Do Reset Request\n");
    fprintf(stderr, "  -s <64b 64b>          Reset seed\n");
    fprintf(stderr, "  -t file               root trust file\n");
    fprintf(stderr, "  -u nb                 trigger key update after receiving <nb> packets on client\n");
    fprintf(stderr, "  -v version            Version proposed by client, e.g. -v ff000012\n");
    fprintf(stderr, "  -z                    Set TLS zero share behavior on client, to force HRR.\n");
    fprintf(stderr, "  -1                    Once: close the server after processing 1 connection.\n");
    fprintf(stderr, "  -S solution_dir       Set the path to the source files to find the default files\n");
    fprintf(stderr, "  -I length             Length of CNX_ID used by the client, default=8\n");
    fprintf(stderr, "  -G cc_algorithm       Use the specified congestion control algorithm:\n");
    fprintf(stderr, "                        reno, cubic or fast. Defaults to cubic.\n");
    fprintf(stderr, "  -D                    no disk: do not save received files on disk.\n");
    fprintf(stderr, "  -Q                    send a large client hello in order to test post quantum\n");
    fprintf(stderr, "                        readiness.\n");
    fprintf(stderr, "  -R                    randomize initial packet number\n");

    fprintf(stderr, "\nThe scenario argument specifies the set of files that should be retrieved,\n");
    fprintf(stderr, "and their order. The syntax is:\n");
    fprintf(stderr, "  *{[<stream_id>':'[<previous_stream>':'[<format>:]]]path;}\n");
    fprintf(stderr, "where:\n");
    fprintf(stderr, "  <stream_id>:          The numeric ID of the QUIC stream, e.g. 4. By default, the\n");
    fprintf(stderr, "                        next stream in the logical QUIC order, 0, 4, 8, etc.");
    fprintf(stderr, "  <previous_stream>:    The numeric ID of the previous stream. The GET command will\n");
    fprintf(stderr, "                        be issued after that stream's transfer finishes. By default,\n");
    fprintf(stderr, "                        previous stream in this scenario.\n");
    fprintf(stderr, "  <format>:             Whether the received file should be written to disc as\n");
    fprintf(stderr, "                        binary(b) or text(t). Defaults to text.\n");
    fprintf(stderr, "  <path>:               The name of the document that should be retrieved\n");
    fprintf(stderr, "If no scenario is specified, the client executes the default scenario.\n");

    exit(1);
}

int main(int argc, char** argv)
{
    const char * solution_dir = NULL;
    const char * server_name = default_server_name;
    const char * server_cert_file = NULL;
    const char * server_key_file = NULL;
    const char * esni_key_file = NULL;
    const char * esni_rr_file = NULL;
    const char * log_file = NULL;
    const char * bin_dir = NULL;
    const char * qlog_dir = NULL;
    const char * sni = NULL;
    const char * alpn = NULL;
    const char* www_dir = NULL;
    const char* out_dir = NULL;
    picoquic_congestion_algorithm_t const* cc_algorithm = NULL;
    int server_port = default_server_port;
    const char* root_trust_file = NULL;
    uint32_t proposed_version = 0;
    int is_client = 0;
    int just_once = 0;
    int do_retry = 0;
    int force_zero_share = 0;
    int force_migration = 0;
    int large_client_hello = 0;
    int nb_packets_before_update = 0;
    int client_cnx_id_length = 8;
    int no_disk = 0;
    int use_long_log = 0;
    int cipher_suite_id = 0;
    int initial_random = 0;
    picoquic_connection_id_callback_ctx_t * cnx_id_cbdata = NULL;
    uint64_t* reset_seed = NULL;
    uint64_t reset_seed_x[2];
    int dest_if = -1;
    int mtu_max = 0;
    char default_server_cert_file[512];
    char default_server_key_file[512];
    char * client_scenario = NULL;
    int ret = 0;

#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    /* Get the parameters */
    int opt;
    while ((opt = getopt(argc, argv, "c:k:K:p:u:v:o:w:f:i:s:e:E:C:l:b:q:m:n:a:t:S:I:G:1rRhzDLQ")) != -1) {
        switch (opt) {
        case 'c':
            server_cert_file = optarg;
            break;
        case 'k':
            server_key_file = optarg;
            break;
        case 'K':
            esni_key_file = optarg;
            break;
        case 'p':
            if ((server_port = atoi(optarg)) <= 0) {
                fprintf(stderr, "Invalid port: %s\n", optarg);
                usage();
            }
            break;
        case 'u':
            if ((nb_packets_before_update = atoi(optarg)) <= 0) {
                fprintf(stderr, "Invalid number of packets: %s\n", optarg);
                usage();
            }
            break;
        case 'v':
            if ((proposed_version = parse_target_version(optarg)) <= 0) {
                fprintf(stderr, "Invalid version: %s\n", optarg);
                usage();
            }
            break;
        case 'o':
            out_dir = optarg;
            break;
        case 'w':
            www_dir = optarg;
            break;
        case '1':
            just_once = 1;
            break;
        case 'r':
            do_retry = 1;
            break;
        case 'R':
            initial_random = 1;
            break;
        case 's':
            if (optind + 1 > argc) {
                fprintf(stderr, "option requires more arguments -- s\n");
                usage();
            }
            reset_seed = reset_seed_x; /* replacing the original alloca, which is not supported in Windows or BSD */
            reset_seed[1] = strtoul(optarg, NULL, 0);
            reset_seed[0] = strtoul(argv[optind++], NULL, 0);
            break;
        case 'S':
            solution_dir = optarg;
            break;
        case 'G':
            cc_algorithm = picoquic_get_congestion_algorithm(optarg);
            if (cc_algorithm == NULL) {
                fprintf(stderr, "Unsupported congestion control algorithm: %s\n", optarg);
                usage();
            }
            break;
        case 'e':
            dest_if = atoi(optarg);
            break;
        case 'C':
            cipher_suite_id = atoi(optarg);
            break;
        case 'E':
            esni_rr_file = optarg;
            break;
        case 'i':
            if (optind + 2 > argc) {
                fprintf(stderr, "option requires more arguments -- i\n");
                usage();
            }
            cnx_id_cbdata = picoquic_connection_id_callback_create_ctx(optarg, argv[optind], argv[optind + 1]);
            if (cnx_id_cbdata == NULL) {
                fprintf(stderr, "could not create callback context (%s, %s, %s)\n", optarg, argv[optind], argv[optind + 1]);
                usage();
            }
            optind += 2;
            break;
        case 'l':
            log_file = optarg;
            break;
        case 'L':
            use_long_log = 1;
            break;
        case 'b':
            bin_dir = optarg;
            break;
        case 'q':
            qlog_dir = optarg;
            break;
        case 'm':
            mtu_max = atoi(optarg);
            if (mtu_max <= 0 || mtu_max > PICOQUIC_MAX_PACKET_SIZE) {
                fprintf(stderr, "Invalid max mtu: %s\n", optarg);
                usage();
            }
            break;
        case 'n':
            sni = optarg;
            break;
        case 'a':
            alpn = optarg;
            break;
        case 't':
            root_trust_file = optarg;
            break;
        case 'z':
            force_zero_share = 1;
            break;
        case 'f':
            force_migration = atoi(optarg);
            if (force_migration <= 0 || force_migration > 3) {
                fprintf(stderr, "Invalid migration mode: %s\n", optarg);
                usage();
            }
            break;
        case 'I':
            client_cnx_id_length = atoi(optarg);
            if (client_cnx_id_length < 0 || client_cnx_id_length > PICOQUIC_CONNECTION_ID_MAX_SIZE){
                fprintf(stderr, "Invalid connection id length: %s\n", optarg);
                usage();
            }
            break;
        case 'D':
            no_disk = 1;
            break;
        case 'Q':
            large_client_hello = 1;
            break;
        case 'h':
            usage();
            break;
        default:
            usage();
            break;
        }
    }

    /* Simplified style params */
    if (optind < argc) {
        server_name = argv[optind++];
        is_client = 1;
    }

    if (optind < argc) {
        if ((server_port = atoi(argv[optind++])) <= 0) {
            fprintf(stderr, "Invalid port: %s\n", optarg);
            usage();
        }
    }

    if (optind < argc) {
        client_scenario = argv[optind++];
    }

    if (optind < argc) {
        usage();
    }

    if (is_client == 0) {

        if (server_cert_file == NULL &&
            picoquic_get_input_path(default_server_cert_file, sizeof(default_server_cert_file), solution_dir, SERVER_CERT_FILE) == 0) {
            server_cert_file = default_server_cert_file;
        }

        if (server_key_file == NULL &&
            picoquic_get_input_path(default_server_key_file, sizeof(default_server_key_file), solution_dir, SERVER_KEY_FILE) == 0) {
            server_key_file = default_server_key_file;
        }

        /* Run as server */
        printf("Starting Picoquic server (v%s) on port %d, server name = %s, just_once = %d, do_retry = %d\n",
            PICOQUIC_VERSION, server_port, server_name, just_once, do_retry);
        ret = quic_server(server_name, server_port,
            server_cert_file, server_key_file, just_once, do_retry,
            (cnx_id_cbdata == NULL) ? NULL : picoquic_connection_id_callback,
            (cnx_id_cbdata == NULL) ? NULL : (void*)cnx_id_cbdata,
            (uint8_t*)reset_seed, dest_if, mtu_max, proposed_version,
            esni_key_file, esni_rr_file,
            log_file, bin_dir, qlog_dir, use_long_log, cc_algorithm, www_dir, initial_random);
        printf("Server exit with code = %d\n", ret);
    } else {
        /* Run as client */
        printf("Starting Picoquic (v%s) connection to server = %s, port = %d\n", PICOQUIC_VERSION, server_name, server_port);
        ret = quic_client(server_name, server_port, sni, esni_rr_file, alpn, root_trust_file, proposed_version, force_zero_share, 
            force_migration, nb_packets_before_update, mtu_max, log_file, 
            bin_dir, qlog_dir, client_cnx_id_length, client_scenario,
            no_disk, use_long_log, cc_algorithm, large_client_hello, out_dir, cipher_suite_id, initial_random);

        printf("Client exit with code = %d\n", ret);
    }

    if (cnx_id_cbdata != NULL) {
        picoquic_connection_id_callback_free_ctx(cnx_id_cbdata);
    }
}
