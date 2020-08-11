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

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
#include "getopt.h"
#include <WinSock2.h>
#include <Windows.h>
#include <assert.h>
#include <iphlpapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <ws2tcpip.h>
#include "autoqlog.h"

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif

#define SERVER_CERT_FILE "certs\\cert.pem"
#define SERVER_KEY_FILE  "certs\\key.pem"

#else /* Linux */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

#ifndef SOCKET_TYPE
#define SOCKET_TYPE int
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) close(x)
#endif
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) ((long)(x))
#endif

#define SERVER_CERT_FILE "certs/cert.pem"
#define SERVER_KEY_FILE "certs/key.pem"
#include "autoqlog.h"

#endif

static const int default_server_port = 4443;
static const char* default_server_name = "::";
static const char* ticket_store_filename = "demo_ticket_store.bin";
static const char* token_store_filename = "demo_token_store.bin";

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picosocks.h"
#include "picoquic_utils.h"
#include "autoqlog.h"
#include "h3zero.c"
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

int quic_server(const char* server_name, int server_port,
    const char* pem_cert, const char* pem_key,
    int just_once, int do_retry, picoquic_connection_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_ctx, uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    int dest_if, int mtu_max, uint32_t proposed_version, 
    const char * esni_key_file_name, const char * esni_rr_file_name,
    char const * log_file, char const* bin_dir, char const* qlog_dir, int use_long_log,
    picoquic_congestion_algorithm_t const * cc_algorithm, char const * web_folder)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qserver = NULL;
    picoquic_server_sockets_t server_sockets;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    uint64_t current_time = 0;
    int64_t delay_max = 10000000;
    int connection_done = 0;
    picohttp_server_parameters_t picoquic_file_param;
    uint64_t loop_count_time = 0;
    int nb_loops = 0;
    picoquic_connection_id_t log_cid;
    int first_connection_seen = 0;

    memset(&picoquic_file_param, 0, sizeof(picohttp_server_parameters_t));
    picoquic_file_param.web_folder = web_folder;

    // picoquic_set_default_callback(test_ctx->qserver, server_callback_fn, server_param);

    /* Open a UDP socket */
    ret = picoquic_open_server_sockets(&server_sockets, server_port);

    /* Wait for packets and process them */
    if (ret == 0) {
        current_time = picoquic_current_time();
        loop_count_time = current_time;
        /* Create QUIC context */
        qserver = picoquic_create(8, pem_cert, pem_key, NULL, NULL,
            picoquic_demo_server_callback, &picoquic_file_param,
            cnx_id_callback, cnx_id_callback_ctx, reset_seed, current_time, NULL, NULL, NULL, 0);

        if (qserver == NULL) {
            printf("Could not create server context\n");
            ret = -1;
        } else {
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

            picoquic_set_binlog(qserver, bin_dir);

            picoquic_set_qlog(qserver, qlog_dir);
            
            picoquic_set_textlog(qserver, log_file);

            picoquic_set_log_level(qserver, use_long_log);

            picoquic_set_key_log_file_from_env(qserver);

            if (esni_key_file_name != NULL && esni_rr_file_name != NULL) {
                ret = picoquic_esni_load_key(qserver, esni_key_file_name);
                if (ret == 0) {
                    ret = picoquic_esni_server_setup(qserver, esni_rr_file_name);
                }
            }
        }
    }

    /* Wait for packets */
    while (ret == 0 && (!just_once || !connection_done)) {
        int64_t delta_t = picoquic_get_next_wake_delay(qserver, current_time, delay_max);
        unsigned char received_ecn;

        if_index_to = 0;

        bytes_recv = picoquic_select(server_sockets.s_socket, PICOQUIC_NB_SERVER_SOCKETS,
            &addr_from, 
            &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t, &current_time);

        nb_loops++;
        if (nb_loops >= 100) {
            uint64_t loop_delta = current_time - loop_count_time;
            loop_count_time = current_time;

            DBG_PRINTF("Looped %d times in %llu microsec, file: %d, line: %d\n",
                nb_loops, (unsigned long long) loop_delta, qserver->wake_file, qserver->wake_line);
            picoquic_log_context_free_app_message(qserver, &log_cid, "Looped %d times in %llu microsec, file: %d, line: %d",
                nb_loops, (unsigned long long) loop_delta, qserver->wake_file, qserver->wake_line);
            
            nb_loops = 0;
        }

        if (bytes_recv < 0) {
            ret = -1;
        } else {
            uint64_t loop_time = current_time;

            if (bytes_recv > 0) {
                /* Submit the packet to the server */
                (void)picoquic_incoming_packet(qserver, buffer,
                    (size_t)bytes_recv, (struct sockaddr*)&addr_from,
                    (struct sockaddr*)&addr_to, if_index_to, received_ecn,
                    current_time);

                if (just_once && !first_connection_seen && picoquic_get_first_cnx(qserver) != NULL) {
                    first_connection_seen = 1;
                    fprintf(stdout, "First connection noticed.\n");
                }
            }

            do {
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr;
                picoquic_cnx_t* last_cnx;
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;


                ret = picoquic_prepare_next_packet(qserver, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                if (ret == 0 && send_length > 0) {
                    loop_count_time = current_time;
                    nb_loops = 0;
                    sock_ret = picoquic_send_through_server_sockets(&server_sockets,
                        (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                        (const char*)send_buffer, (int)send_length, &sock_err);
                    if (sock_ret <= 0) {
                        if (last_cnx == NULL) {
                            picoquic_log_context_free_app_message(qserver, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, sock_ret, sock_err);
                        }
                    }
                }

            } while (ret == 0 && send_length > 0);

            if (just_once && first_connection_seen && picoquic_get_first_cnx(qserver) == NULL) {
                fprintf(stdout, "No more active connections.\n");
                connection_done = 1;
            }
        }
    }

    printf("Server exit, ret = %d\n", ret);

    /* Clean up */
    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    picoquic_close_server_sockets(&server_sockets);

    return ret;
}

static const char * test_scenario_default = "0:index.html;4:test.html;8:/1234567;12:main.jpg;16:war-and-peace.txt;20:en/latest/;24:/file-123K";

#define PICOQUIC_DEMO_CLIENT_MAX_RECEIVE_BATCH 4

/* Client client migration to a new port number: 
 *  - close the current socket.
 *  - open another socket at a randomly picked port number.
 *  - call the create probe API.
 * This is a bit tricky because the probe API requires passing the new address,
 * but in many cases the client will be behind a NAT, so it will not know its
 * actual IP address.
 */
int quic_client_migrate(picoquic_cnx_t * cnx, SOCKET_TYPE * fd, struct sockaddr * server_address, 
    struct sockaddr* client_address, int * address_updated, int force_migration, uint64_t current_time) 
{
    int ret = 0;

    if (server_address == NULL) {
        server_address = (struct sockaddr*) & cnx->path[0]->peer_addr;
    }

    if (force_migration != 2) {
        SOCKET_TYPE fd_m;


        fd_m = picoquic_open_client_socket(server_address->sa_family);
        if (fd_m == INVALID_SOCKET) {
            fprintf(stdout, "Could not open new socket.\n");
            ret = -1;
        }
        else {
            if (force_migration == 3) {
                uint16_t port = (client_address->sa_family == AF_INET) ?
                    ((struct sockaddr_in*)client_address)->sin_port :
                    ((struct sockaddr_in6*)client_address)->sin6_port;

                for (int trial = 0; trial < 4; trial++) {
                    port++;
                    ret = picoquic_bind_to_port(fd_m, client_address->sa_family, port);
                    if (ret == 0) {
                        if (client_address->sa_family == AF_INET) {
                            ((struct sockaddr_in*)client_address)->sin_port = port;
                        }
                        else {
                            ((struct sockaddr_in6*)client_address)->sin6_port = port;
                        }
                        break;
                    }
                }
                if (ret != 0) {
                    DBG_PRINTF("Could not bind new socket to port %d", port);
                }
            }
            if (ret == 0) {
                SOCKET_CLOSE(*fd);
                *fd = fd_m;
            }
            else {
                SOCKET_CLOSE(fd_m);
            }
        }
    }

    if (ret == 0) {
        if (force_migration == 1) {
            fprintf(stdout, "Switch to new port. Will test NAT rebinding support.\n");
            *address_updated = 0;
        }
        else if (force_migration == 2) {
            ret = picoquic_renew_connection_id(cnx, 0);
            if (ret != 0) {
                if (ret == PICOQUIC_ERROR_MIGRATION_DISABLED) {
                    fprintf(stdout, "Migration disabled, cannot test CNXID renewal.\n");
                }
                else {
                    fprintf(stdout, "Renew CNXID failed, error: %x.\n", ret);
                }
            }
            else {
                fprintf(stdout, "Switching to new CNXID.\n");
            }
        }
        else {
            ret = picoquic_probe_new_path(cnx, server_address, client_address, current_time);
            if (ret != 0) {
                if (ret == PICOQUIC_ERROR_MIGRATION_DISABLED) {
                    fprintf(stdout, "Migration disabled, will test NAT rebinding support.\n");
                    ret = 0;
                }
                else {
                    fprintf(stdout, "Create Probe failed, error: %x.\n", ret);
                }
            }
            else {
                *address_updated = 1;
                fprintf(stdout, "Switch to new port, sending probe.\n");
            }
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
    int large_client_hello, char const * out_dir, int cipher_suite_id)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    SOCKET_TYPE fd = INVALID_SOCKET;
    struct sockaddr_storage server_address;
    int server_addr_length = 0;
    struct sockaddr_storage client_address;
    struct sockaddr_storage packet_from;
    struct sockaddr_storage packet_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    uint64_t key_update_done = 0;
    int bytes_recv;
    int bytes_sent;
    uint64_t current_time = 0;
    uint64_t loop_time = 0;
    int client_ready_loop = 0;
    int client_receive_loop = 0;
    int established = 0;
    int is_name = 0;
    int migration_started = 0;
    int migration_to_preferred_started = 0;
    int migration_to_preferred_finished = 0;
    int address_updated = 0;
    int64_t delay_max = 10000000;
    int64_t delta_t = 0;
    int notified_ready = 0;
    int zero_rtt_available = 0;
    size_t client_sc_nb = 0;
    picoquic_demo_stream_desc_t * client_sc = NULL;
    int is_siduck = 0;
    siduck_ctx_t* siduck_ctx = NULL;
    char const* saved_alpn = NULL;
    unsigned char got_ecn = 0;

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
        ret = picoquic_get_server_address(ip_address_text, server_port, &server_address, &is_name);
        server_addr_length = (server_address.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        if (sni == NULL && is_name != 0) {
            sni = ip_address_text;
        }
    }

    /* Open a UDP socket */

    if (ret == 0) {
        fd = picoquic_open_client_socket(server_address.ss_family);
        if (fd == INVALID_SOCKET) {
            ret = -1;
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
            (struct sockaddr*)&server_address, current_time,
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
                    zero_rtt_available = 1;

                    fprintf(stdout, "Max stream id bidir remote after 0rtt = %d (%d)\n",
                        (int)cnx_client->max_stream_id_bidir_remote,
                        (int)cnx_client->remote_parameters.initial_max_stream_id_bidir);

                    /* Queue a simple frame to perform 0-RTT test */
                    /* Start the download scenario */

                    ret = picoquic_demo_client_start_streams(cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                }
            }
            
            if (ret == 0) {
                ret = picoquic_prepare_packet(cnx_client, current_time,
                    send_buffer, sizeof(send_buffer), &send_length, NULL, NULL);

                if (ret == 0 && send_length > 0) {
                    bytes_sent = sendto(fd, (const char*)send_buffer, (int)send_length, 0,
                        (struct sockaddr*) & server_address, server_addr_length);
                    if (bytes_sent <= 0)
                    {
                        fprintf(stderr, "Cannot send first packet to server, returns %d\n", bytes_sent);
                        ret = -1;
                    }
                }
            }
        }
    }

    /* Wait for packets */
    loop_time = current_time;

    while (ret == 0 && picoquic_get_cnx_state(cnx_client) != picoquic_state_disconnected) {
        unsigned char received_ecn;

        bytes_recv = picoquic_select(&fd, 1, &packet_from, 
            &packet_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t,
            &current_time);

        got_ecn |= received_ecn;

        if (bytes_recv != 0 && packet_to.ss_family != 0) {
            /* Keeping track of the addresses and ports, as we 
             * need them to verify the migration behavior */
            if (!address_updated) {
                struct sockaddr_storage local_address;
                if (picoquic_get_local_address(fd, &local_address) != 0) {
                    memset(&local_address, 0, sizeof(struct sockaddr_storage));
                    fprintf(stderr, "Could not read local address.\n");
                }

                address_updated = 1;
                picoquic_store_addr(&client_address, (struct sockaddr *)&packet_to);
                if (client_address.ss_family == AF_INET) {
                    ((struct sockaddr_in *)&client_address)->sin_port =
                        ((struct sockaddr_in *)&local_address)->sin_port;
                    fprintf(stdout, "IPv4 port: %d.\n", ((struct sockaddr_in*)& client_address)->sin_port);
                }
                else {
                    ((struct sockaddr_in6 *)&client_address)->sin6_port =
                        ((struct sockaddr_in6 *)&local_address)->sin6_port;
                    fprintf(stdout, "IPv6 port: %d.\n", ((struct sockaddr_in6*)& client_address)->sin6_port);
                }
                
                fprintf(stdout, "Client port (AF=%d): %d.\n",
                    client_address.ss_family,
                    (client_address.ss_family == AF_INET) ?
                    ((struct sockaddr_in*) & client_address)->sin_port :
                    ((struct sockaddr_in6*) & client_address)->sin6_port
                );
            }

            if (client_address.ss_family == AF_INET) {
                ((struct sockaddr_in *)&packet_to)->sin_port =
                    ((struct sockaddr_in *)&client_address)->sin_port;
            }
            else {
                ((struct sockaddr_in6 *)&packet_to)->sin6_port =
                    ((struct sockaddr_in6 *)&client_address)->sin6_port;
            }
        }

        if (bytes_recv < 0) {
            ret = -1;
        } else {
            if (bytes_recv > 0) {
                /* Submit the packet to the client */
                ret = picoquic_incoming_packet(qclient, buffer,
                    (size_t)bytes_recv, (struct sockaddr*)&packet_from,
                    (struct sockaddr*)&packet_to, if_index_to, received_ecn,
                    current_time);
                client_receive_loop++;

                if (picoquic_get_cnx_state(cnx_client) == picoquic_state_client_almost_ready && notified_ready == 0) {
                    if (picoquic_tls_is_psk_handshake(cnx_client)) {
                        fprintf(stdout, "The session was properly resumed!\n");
                        picoquic_log_app_message(cnx_client,
                            "%s", "The session was properly resumed!");
                    }

                    if (cnx_client->zero_rtt_data_accepted) {
                        fprintf(stdout, "Zero RTT data is accepted!\n");
                        picoquic_log_app_message(cnx_client,
                            "%s", "Zero RTT data is accepted!");
                    }

                    if (cnx_client->alpn != NULL) {
                        fprintf(stdout, "Negotiated ALPN: %s\n", cnx_client->alpn);
                        picoquic_log_app_message(cnx_client,
                            "Negotiated ALPN: %s", cnx_client->alpn);
                        saved_alpn = picoquic_string_duplicate(cnx_client->alpn);
                    }
                    fprintf(stdout, "Almost ready!\n\n");
                    notified_ready = 1;
                }

                delta_t = 0;
            }

            /* In normal circumstances, the code waits until all packets in the receive
             * queue have been processed before sending new packets. However, if the server
             * is sending lots and lots of data this can lead to the client not getting
             * the occasion to send acknowledgements. The server will start retransmissions,
             * and may eventually drop the connection for lack of acks. So we limit
             * the number of packets that can be received before sending responses. */

            if (bytes_recv == 0 || (ret == 0 && client_receive_loop > PICOQUIC_DEMO_CLIENT_MAX_RECEIVE_BATCH) ||
                (current_time - loop_time) > 25000) {
                client_receive_loop = 0;
                loop_time = current_time;

                if (ret == 0 && (picoquic_get_cnx_state(cnx_client) == picoquic_state_ready || 
                    picoquic_get_cnx_state(cnx_client) == picoquic_state_client_ready_start)) {
                    if (established == 0) {
                        printf("Connection established. Version = %x, I-CID: %llx, verified: %d\n",
                            picoquic_supported_versions[cnx_client->version_index].version,
                            (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_client)),
                            cnx_client->is_hcid_verified);

                        picoquic_log_app_message(cnx_client,
                            "Connection established. Version = %x, I-CID: %llx, verified: %d",
                            picoquic_supported_versions[cnx_client->version_index].version,
                            (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_client)),
                            cnx_client->is_hcid_verified);
                        established = 1;

                        if (zero_rtt_available == 0 && !is_siduck) {
                            /* Start the download scenario */

                            picoquic_demo_client_start_streams(cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                        }
                    }

                    client_ready_loop++;

                    if (cnx_client->remote_parameters.prefered_address.is_defined && !migration_to_preferred_finished) {
                        if (picoquic_compare_addr(
                            (struct sockaddr*) & server_address, (struct sockaddr*) & cnx_client->path[0]->peer_addr) != 0) {
                            fprintf(stdout, "Migrated to server preferred address!\n");
                            picoquic_log_app_message(cnx_client, "%s", "Migrated to server preferred address!");
                            migration_to_preferred_finished = 1;
                        }
                        else if (cnx_client->nb_paths > 1 && !migration_to_preferred_started) {
                            migration_to_preferred_started = 1;
                            fprintf(stdout, "Attempting migration to server preferred address.\n");
                            picoquic_log_app_message(cnx_client, "%s", "Attempting migration to server preferred address.");

                        }
                        else if (cnx_client->nb_paths == 1 && migration_to_preferred_started) {
                            fprintf(stdout, "Could not migrate to server preferred address!\n");
                            picoquic_log_app_message(cnx_client, "%s", "Could not migrate to server preferred address!");
                            migration_to_preferred_finished = 1;
                        }
                    }

                    if (force_migration && migration_started == 0 && address_updated &&
                        picoquic_get_cnx_state(cnx_client) == picoquic_state_ready &&
                        (cnx_client->cnxid_stash_first != NULL || force_migration == 1) &&
                        picoquic_get_cnx_state(cnx_client) == picoquic_state_ready &&
                        (force_migration != 3 || !cnx_client->remote_parameters.prefered_address.is_defined || migration_to_preferred_finished)) {
                        int mig_ret = quic_client_migrate(cnx_client, &fd, NULL, (struct sockaddr*) & client_address,
                            &address_updated, force_migration, current_time);

                        migration_started = 1;

                        if (mig_ret != 0) {
                            fprintf(stdout, "Will not test migration.\n");
                            picoquic_log_app_message(cnx_client, "%s", "Will not test migration.");
                            migration_started = -1;
                        }
                    }

                    if (nb_packets_before_key_update > 0 &&
                        !key_update_done &&
                        cnx_client->pkt_ctx[picoquic_packet_context_application].first_sack_item.end_of_sack_range > (uint64_t)nb_packets_before_key_update) {
                        int key_rot_ret = picoquic_start_key_rotation(cnx_client);
                        if (key_rot_ret != 0) {
                            fprintf(stdout, "Will not test key rotation.\n");
                            picoquic_log_app_message(cnx_client, "%s", "Will not test key rotation.");
                            key_update_done = (uint64_t)-1;
                        }
                        else {
                            fprintf(stdout, "Key rotation started.\n");
                            picoquic_log_app_message(cnx_client, "%s", "Key rotation started.");
                            key_update_done = 1;
                        }
                    }

                    if (bytes_recv == 0 || client_ready_loop > 4) {
                        if (!is_siduck && callback_ctx.nb_open_streams == 0) {
                            if (cnx_client->nb_zero_rtt_sent != 0) {
                                fprintf(stdout, "Out of %d zero RTT packets, %d were acked by the server.\n",
                                    cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
                                picoquic_log_app_message(cnx_client, "Out of %d zero RTT packets, %d were acked by the server.",
                                    cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
                            }

                            fprintf(stdout, "Quic Bit was %sgreased by the client.\n", (cnx_client->quic_bit_greased)?"":"NOT ");
                            fprintf(stdout, "Quic Bit was %sgreased by the server.\n", (cnx_client->quic_bit_received_0) ? "" : "NOT ");
                            fprintf(stdout, "ECN was %sreceived (0x%x)\n", (got_ecn == 0) ? "NOT " : "", got_ecn);

                            if (force_migration && !migration_started) {
                                fprintf(stdout, "Could not start testing migration.\n");
                                picoquic_log_app_message(cnx_client, "%s", "Could not start testing migration.");
                                migration_started = -1;
                            }

                            fprintf(stdout, "All done, Closing the connection.\n");
                            picoquic_log_app_message(cnx_client, "%s", "All done, Closing the connection.");
                            if (picoquic_get_data_received(cnx_client) > 0) {
                                double duration_usec = (double)(current_time - picoquic_get_cnx_start_time(cnx_client));

                                if (duration_usec > 0) {
                                    double receive_rate_mbps = 8.0*((double)picoquic_get_data_received(cnx_client)) / duration_usec;
                                    fprintf(stdout, "Received %llu bytes in %f seconds, %f Mbps.\n",
                                        (unsigned long long)picoquic_get_data_received(cnx_client),
                                        duration_usec/1000000.0, receive_rate_mbps);
                                    picoquic_log_app_message(cnx_client, "Received %llu bytes in %f seconds, %f Mbps.",
                                        (unsigned long long)picoquic_get_data_received(cnx_client),
                                        duration_usec / 1000000.0, receive_rate_mbps);
                                }
                            }

                            ret = picoquic_close(cnx_client, 0);
                        }
                        else if (
                            current_time > callback_ctx.last_interaction_time && current_time - callback_ctx.last_interaction_time > 10000000ull
                            && picoquic_is_cnx_backlog_empty(cnx_client)) {
                            fprintf(stdout, "No progress for 10 seconds. Closing. \n");
                            picoquic_log_app_message(cnx_client, "%s", "No progress for 10 seconds. Closing.");
                            ret = picoquic_close(cnx_client, 0);
                        }
                    }
                }

                if (ret == 0) {
                    struct sockaddr_storage x_to;
                    struct sockaddr_storage x_from;

                    send_length = PICOQUIC_MAX_PACKET_SIZE;

                    current_time = picoquic_get_quic_time(qclient);

                    ret = picoquic_prepare_packet(cnx_client, current_time,
                        send_buffer, sizeof(send_buffer), &send_length, &x_to, &x_from);

                    if (migration_started && force_migration == 3 && send_length > 0 && address_updated) {
                        if (picoquic_compare_addr((struct sockaddr*) & x_from, (struct sockaddr*) & client_address) != 0) {
                            fprintf(stderr, "Dropping packet sent from wrong address, port: %d\n",
                                (client_address.ss_family == AF_INET) ?
                                ((struct sockaddr_in*) & x_from)->sin_port :
                                ((struct sockaddr_in6*) & x_from)->sin6_port);
                            picoquic_log_app_message(cnx_client, "Dropping packet sent from wrong address, port: %d",
                                (client_address.ss_family == AF_INET) ?
                                ((struct sockaddr_in*) & x_from)->sin_port :
                                ((struct sockaddr_in6*) & x_from)->sin6_port);
                            send_length = 0;
                        }
                    }

                    if (ret == 0 && send_length > 0) {
                        bytes_sent = sendto(fd, (const char*)send_buffer, (int)send_length, 0,
                            (struct sockaddr*) & x_to, picoquic_addr_length((struct sockaddr*) & x_to));

                        if (bytes_sent <= 0)
                        {
                            fprintf(stdout, "Cannot send packet to server, returns %d\n", bytes_sent);
                            picoquic_log_app_message(cnx_client, "Cannot send packet to server, returns %d", bytes_sent);
                        }
                    }
                }

                delta_t = picoquic_get_next_wake_delay(qclient, current_time, delay_max);

                if (delta_t > 10000 && (is_siduck || callback_ctx.nb_open_streams == 0) &&
                    picoquic_is_cnx_backlog_empty(cnx_client)) {
                    delta_t = 10000;
                }
            }
        }
    }

    /* Clean up */
    if (is_siduck) {
        free(siduck_ctx);
    } else {
        picoquic_demo_client_delete_context(&callback_ctx);
    }

    if (qclient != NULL) {
        uint8_t* ticket;
        uint16_t ticket_length;

        if (sni != NULL && saved_alpn != NULL && 0 == picoquic_get_ticket(qclient->p_first_ticket, current_time, sni, (uint16_t)strlen(sni), saved_alpn,
            (uint16_t)strlen(saved_alpn), &ticket, &ticket_length, NULL, 0)) {
            fprintf(stdout, "Received ticket from %s (%s):\n", sni, saved_alpn);
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

    if (fd != INVALID_SOCKET) {
        SOCKET_CLOSE(fd);
    }

    if (saved_alpn != NULL) {
        free((void *)saved_alpn);
        saved_alpn = NULL;
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
    while ((opt = getopt(argc, argv, "c:k:K:p:u:v:o:w:f:i:s:e:E:C:l:b:q:m:n:a:t:S:I:G:1rhzDLQ")) != -1) {
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
            log_file, bin_dir, qlog_dir, use_long_log, cc_algorithm, www_dir);
        printf("Server exit with code = %d\n", ret);
    } else {
        /* Run as client */
        printf("Starting Picoquic (v%s) connection to server = %s, port = %d\n", PICOQUIC_VERSION, server_name, server_port);
        ret = quic_client(server_name, server_port, sni, esni_rr_file, alpn, root_trust_file, proposed_version, force_zero_share, 
            force_migration, nb_packets_before_update, mtu_max, log_file, 
            bin_dir, qlog_dir, client_cnx_id_length, client_scenario,
            no_disk, use_long_log, cc_algorithm, large_client_hello, out_dir, cipher_suite_id);

        printf("Client exit with code = %d\n", ret);
    }

    if (cnx_id_cbdata != NULL) {
        picoquic_connection_id_callback_free_ctx(cnx_id_cbdata);
    }
}
