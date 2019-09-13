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

#ifndef SOCKET_TYPE
#define SOCKET_TYPE SOCKET
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) closesocket(x)
#endif
#ifndef WSA_START_DATA
#define WSA_START_DATA WSADATA
#endif
#ifndef WSA_START
#define WSA_START(x, y) WSAStartup((x), (y))
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

#endif

static const int default_server_port = 4443;
static const char* default_server_name = "::";
static const char* ticket_store_filename = "demo_ticket_store.bin";
static const char* token_store_filename = "demo_token_store.bin";

#include "picoquic_internal.h"
#include "picosocks.h"
#include "util.h"
#include "h3zero.c"
#include "democlient.h"
#include "demoserver.h"

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

static void picoquic_set_key_log_file_from_env(picoquic_quic_t* quic)
{
    char * keylog_filename = NULL;
    FILE* F = NULL;

#ifdef _WINDOWS
    size_t len; 
    errno_t err = _dupenv_s(&keylog_filename, &len, "SSLKEYLOGFILE");

    if (keylog_filename == NULL) {
        return;
    }

    if (err == 0) {
        err = fopen_s(&F, keylog_filename, "a");

        free(keylog_filename);

        if (err != 0 || F == NULL) {
            return;
        }
    }
#else
    keylog_filename = getenv("SSLKEYLOGFILE");
    if (keylog_filename == NULL) {
        return;
    }
    F = fopen(keylog_filename, "a");
    if (F == NULL) {
        return;
    }
#endif

    picoquic_set_key_log_file(quic, F);
}

int quic_server(const char* server_name, int server_port,
    const char* pem_cert, const char* pem_key,
    int just_once, int do_hrr, picoquic_connection_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_ctx, uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    int dest_if, int mtu_max, uint32_t proposed_version, 
    const char * esni_key_file_name, const char * esni_rr_file_name,
    FILE * F_log, char const * cc_log_dir, int use_long_log)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qserver = NULL;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_cnx_t* cnx_next = NULL;
    picoquic_server_sockets_t server_sockets;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    unsigned long if_index_to;
    struct sockaddr_storage client_from;
    socklen_t from_length;
    socklen_t to_length;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    uint64_t current_time = 0;
    picoquic_stateless_packet_t* sp;
    int64_t delay_max = 10000000;
    int connection_done = 0;

    /* Open a UDP socket */
    ret = picoquic_open_server_sockets(&server_sockets, server_port);

    /* Wait for packets and process them */
    if (ret == 0) {
        current_time = picoquic_current_time();
        /* Create QUIC context */
        qserver = picoquic_create(8, pem_cert, pem_key, NULL, NULL, picoquic_demo_server_callback, NULL,
            cnx_id_callback, cnx_id_callback_ctx, reset_seed, current_time, NULL, NULL, NULL, 0);

        if (qserver == NULL) {
            printf("Could not create server context\n");
            ret = -1;
        } else {
            if (do_hrr != 0) {
                picoquic_set_cookie_mode(qserver, 1);
            }
            qserver->mtu_max = mtu_max;

            picoquic_set_default_congestion_algorithm(qserver, picoquic_cubic_algorithm);

            PICOQUIC_SET_LOG(qserver, F_log);

            if (use_long_log) {
                qserver->use_long_log = 1;
            }

            picoquic_set_key_log_file_from_env(qserver);

            if (cc_log_dir != NULL) {
                picoquic_set_cc_log(qserver, cc_log_dir);
            }

            if (esni_key_file_name != NULL && esni_rr_file_name != NULL) {
                ret = picoquic_esni_load_key(qserver, esni_key_file_name);
                if (ret == 0) {
                    ret = picoquic_esni_server_setup(qserver, esni_rr_file_name);
                }
            }
        }
    }

    /* Wait for packets */
    while (ret == 0 && (just_once == 0 || connection_done == 0)) {
        int64_t delta_t = picoquic_get_next_wake_delay(qserver, current_time, delay_max);
        uint64_t time_before = current_time;
        unsigned char received_ecn;

        from_length = to_length = sizeof(struct sockaddr_storage);
        if_index_to = 0;

        if (just_once != 0 && F_log != NULL &&  delta_t > 10000 && cnx_server != NULL && 
            (cnx_server->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || qserver->use_long_log)) {
            picoquic_log_congestion_state(F_log, cnx_server, current_time);
        }

        bytes_recv = picoquic_select(server_sockets.s_socket, PICOQUIC_NB_SERVER_SOCKETS,
            &addr_from, &from_length,
            &addr_to, &to_length, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t, &current_time);

        if (just_once != 0 && F_log != NULL && 
            (cnx_server == NULL || cnx_server->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || qserver->use_long_log)) {
            if (bytes_recv > 0) {
                fprintf(F_log, "Select returns %d, from length %d after %d us (wait for %d us)\n",
                    bytes_recv, from_length, (int)(current_time - time_before), (int)delta_t);
                print_address(F_log, (struct sockaddr*)&addr_from, "recv from:", picoquic_null_connection_id);
            } else {
                fprintf(F_log, "Select return %d, after %d us (wait for %d us)\n", bytes_recv,
                    (int)(current_time - time_before), (int)delta_t);
            }
        }

        if (bytes_recv < 0) {
            ret = -1;
        } else {
            uint64_t loop_time;

            if (bytes_recv > 0) {
                /* Submit the packet to the server */
                ret = picoquic_incoming_packet(qserver, buffer,
                    (size_t)bytes_recv, (struct sockaddr*)&addr_from,
                    (struct sockaddr*)&addr_to, if_index_to, received_ecn,
                    current_time);

                if (ret != 0) {
                    ret = 0;
                }

                if (cnx_server != picoquic_get_first_cnx(qserver) && picoquic_get_first_cnx(qserver) != NULL) {
                    cnx_server = picoquic_get_first_cnx(qserver);
                    memset(&client_from, 0, sizeof(client_from));
                    memcpy(&client_from, &addr_from, from_length);
                    if (F_log != NULL) {
                        fprintf(F_log, "%llx: ", (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_server)));
                        picoquic_log_time(F_log, cnx_server, picoquic_current_time(), "", " : ");
                        fprintf(F_log, "Connection established, state = %d, from length: %d\n",
                            picoquic_get_cnx_state(picoquic_get_first_cnx(qserver)), from_length);

                        print_address(F_log, (struct sockaddr*)&client_from, "Client address:",
                            picoquic_get_logging_cnxid(cnx_server));
                        picoquic_log_transport_extension(F_log, cnx_server, 1);
                    }
                }
            }
            loop_time = current_time;

            while ((sp = picoquic_dequeue_stateless_packet(qserver)) != NULL) {
                (void)picoquic_send_through_server_sockets(&server_sockets,
                    (struct sockaddr*)&sp->addr_to,
                    (sp->addr_to.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                    (struct sockaddr*)&sp->addr_local,
                    (sp->addr_local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                    dest_if == -1 ? sp->if_index_local : dest_if,
                    (const char*)sp->bytes, (int)sp->length);

                /* TODO: log stateless packet */
                if (F_log != NULL) {
                    fflush(F_log);
                }

                picoquic_delete_stateless_packet(sp);
            }

            while (ret == 0 && (cnx_next = picoquic_get_earliest_cnx_to_wake(qserver, loop_time)) != NULL) {
                int peer_addr_len = 0;
                struct sockaddr_storage peer_addr;
                int local_addr_len = 0;
                struct sockaddr_storage local_addr;

                ret = picoquic_prepare_packet(cnx_next, current_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &peer_addr_len, &local_addr, &local_addr_len);

                if (ret == PICOQUIC_ERROR_DISCONNECTED) {
                    ret = 0;

                    if (F_log != NULL) {
                        fprintf(F_log, "%llx: ", (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_next)));
                        picoquic_log_time(F_log, cnx_server, picoquic_current_time(), "", " : ");
                        fprintf(F_log, "Closed. Retrans= %d, spurious= %d, max sp gap = %d, max sp delay = %d\n",
                            (int)cnx_next->nb_retransmission_total, (int)cnx_next->nb_spurious,
                            (int)cnx_next->path[0]->max_reorder_gap, (int)cnx_next->path[0]->max_spurious_rtt);
                        fflush(F_log);
                    }

                    if (cnx_next == cnx_server) {
                        cnx_server = NULL;
                    }

                    picoquic_delete_cnx(cnx_next);


                    connection_done = 1;

                    break;
                }
                else if (ret == 0) {

                    if (send_length > 0) {
                        if (F_log != NULL && (just_once != 0 ||
                            cnx_next->cnx_state < picoquic_state_server_false_start ||
                            cnx_next->cnx_state >= picoquic_state_disconnecting) &&
                            cnx_next->pkt_ctx[picoquic_packet_context_application].send_sequence < 100) {
                            fprintf(F_log, "%llx: ", (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_next)));
                            fprintf(F_log, "Connection state = %d\n",
                                picoquic_get_cnx_state(cnx_next));
                        }

                        (void)picoquic_send_through_server_sockets(&server_sockets,
                            (struct sockaddr *)&peer_addr, peer_addr_len, (struct sockaddr *)&local_addr, local_addr_len,
                            dest_if == -1 ? picoquic_get_local_if_index(cnx_next) : dest_if,
                            (const char*)send_buffer, (int)send_length);
                    }
                }
                else {
                    break;
                }

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
    int force_migration, FILE * F_log) 
{
    int ret = 0;

    if (force_migration != 2) {
        SOCKET_TYPE fd_m;

        fd_m = picoquic_open_client_socket(server_address->sa_family);
        if (fd_m == INVALID_SOCKET) {
            fprintf(stdout, "Could not open new socket.\n");
            if (F_log != stdout && F_log != stderr && F_log != NULL)
            {
                fprintf(stdout, "Could not open new socket.\n");
            }
            ret = -1;
        }
        else {
            SOCKET_CLOSE(*fd);
            *fd = fd_m;
        }
    }

    if (ret == 0) {
        if (force_migration == 1) {
            fprintf(stdout, "Switch to new port. Will test NAT rebinding support.\n");
            if (F_log != stdout && F_log != stderr && F_log != NULL)
            {
                fprintf(F_log, "Switch to new port. Will test NAT rebinding support.\n");
            }
        }
        else if (force_migration == 2) {
            ret = picoquic_renew_connection_id(cnx, 0);
            if (ret != 0) {
                if (ret == PICOQUIC_ERROR_MIGRATION_DISABLED) {
                    fprintf(stdout, "Migration disabled, cannot test CNXID renewal.\n");
                    if (F_log != stdout && F_log != stderr && F_log != NULL)
                    {
                        fprintf(stdout, "Migration disabled, cannot test CNXID renewal.\n");
                    }
                }
                else {
                    fprintf(stdout, "Renew CNXID failed, error: %x.\n", ret);
                    if (F_log != stdout && F_log != stderr && F_log != NULL)
                    {
                        fprintf(F_log, "Create Probe failed, error: %x.\n", ret);
                    }
                }
            }
            else {
                fprintf(stdout, "Switching to new CNXID.\n");
                if (F_log != stdout && F_log != stderr && F_log != NULL)
                {
                    fprintf(F_log, "Switching to new CNXID.\n");
                }
            }
        }
        else {
            ret = picoquic_create_probe(cnx, server_address, NULL);
            if (ret != 0) {
                if (ret == PICOQUIC_ERROR_MIGRATION_DISABLED) {
                    fprintf(stdout, "Migration disabled, will test NAT rebinding support.\n");
                    if (F_log != stdout && F_log != stderr && F_log != NULL)
                    {
                        fprintf(F_log, "Will test NAT rebinding support.\n");
                    }

                    ret = 0;
                }
                else {
                    fprintf(stdout, "Create Probe failed, error: %x.\n", ret);
                    if (F_log != stdout && F_log != stderr && F_log != NULL)
                    {
                        fprintf(F_log, "Create Probe failed, error: %x.\n", ret);
                    }
                }
            }
            else {
                fprintf(stdout, "Switch to new port, sending probe.\n");
                if (F_log != stdout && F_log != stderr && F_log != NULL)
                {
                    fprintf(F_log, "Switch to new port, sending probe.\n");
                }
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
    int nb_packets_before_key_update, int mtu_max, FILE* F_log,
    int client_cnx_id_length, char const * client_scenario_text, char const * cc_log_dir,
    int no_disk, int use_long_log)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    SOCKET_TYPE fd = INVALID_SOCKET;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    struct sockaddr_storage packet_from;
    struct sockaddr_storage packet_to;
    unsigned long if_index_to;
    socklen_t from_length;
    socklen_t to_length;
    int server_addr_length = 0;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    uint64_t key_update_done = 0;
    int bytes_recv;
    int bytes_sent;
    uint64_t current_time = 0;
    int client_ready_loop = 0;
    int client_receive_loop = 0;
    int established = 0;
    int is_name = 0;
    int migration_started = 0;
    int address_updated = 0;
    int64_t delay_max = 10000000;
    int64_t delta_t = 0;
    int notified_ready = 0;
    int zero_rtt_available = 0;
    size_t client_sc_nb = 0;
    picoquic_demo_stream_desc_t * client_sc = NULL;

    if (alpn == NULL) {
        alpn = "h3-22";
    }

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
        ret = picoquic_demo_client_initialize_context(&callback_ctx, client_sc, client_sc_nb, alpn, no_disk);
    }

    if (ret == 0) {
        ret = picoquic_get_server_address(ip_address_text, server_port, &server_address, &server_addr_length, &is_name);
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
        qclient = picoquic_create(8, NULL, NULL, root_crt, alpn, NULL, NULL, NULL, NULL, NULL, current_time, NULL, ticket_store_filename, NULL, 0);

        if (qclient == NULL) {
            ret = -1;
        } else {
            picoquic_set_default_congestion_algorithm(qclient, picoquic_cubic_algorithm);

            if (picoquic_load_tokens(&qclient->p_first_token, current_time, token_store_filename) != 0) {
                fprintf(stderr, "Could not load tokens from <%s>.\n", token_store_filename);
            }

            if (force_zero_share) {
                qclient->flags |= picoquic_context_client_zero_share;
            }
            qclient->mtu_max = mtu_max;

            (void)picoquic_set_default_connection_id_length(qclient, (uint8_t)client_cnx_id_length);

            PICOQUIC_SET_LOG(qclient, F_log);
            if (use_long_log) {
                qclient->use_long_log = 1;
            }

            picoquic_set_key_log_file_from_env(qclient);

            if (cc_log_dir != NULL) {
                picoquic_set_cc_log(qclient, cc_log_dir);
            }


            if (sni == NULL) {
                /* Standard verifier would crash */
                fprintf(stdout, "No server name specified, certificate will not be verified.\n");
                if (F_log != stdout && F_log != stderr && F_log != NULL)
                {
                    fprintf(F_log, "No server name specified, certificate will not be verified.\n");
                }
                picoquic_set_null_verifier(qclient);
            }
            else if (root_crt == NULL) {

                /* Standard verifier would crash */
                fprintf(stdout, "No root crt list specified, certificate will not be verified.\n");
                if (F_log != stdout && F_log != stderr && F_log != NULL)
                {
                    fprintf(F_log, "No root crt list specified, certificate will not be verified.\n");
                }
                picoquic_set_null_verifier(qclient);
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
            picoquic_set_callback(cnx_client, picoquic_demo_client_callback, &callback_ctx);
            /* Requires TP grease, for interop tests */
            cnx_client->grease_transport_parameters = 1;


            if (callback_ctx.tp != NULL) {
                picoquic_set_transport_parameters(cnx_client, callback_ctx.tp);
            }

            if (esni_rr_file != NULL) {
                ret = picoquic_esni_client_from_file(cnx_client, esni_rr_file);
            }

            if (ret == 0) {
                ret = picoquic_start_client_cnx(cnx_client);
            }

            if (ret == 0) {
                if (picoquic_is_0rtt_available(cnx_client) && (proposed_version & 0x0a0a0a0a) != 0x0a0a0a0a) {
                    zero_rtt_available = 1;

                    /* Queue a simple frame to perform 0-RTT test */
                    /* Start the download scenario */

                    ret = picoquic_demo_client_start_streams(cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                }
            }
            
            if (ret == 0) {
                /* TODO: once migration is supported, manage addresses */
                ret = picoquic_prepare_packet(cnx_client, current_time,
                    send_buffer, sizeof(send_buffer), &send_length, NULL, NULL, NULL, NULL);

                if (ret == 0 && send_length > 0) {
                    bytes_sent = sendto(fd, send_buffer, (int)send_length, 0,
                        (struct sockaddr*)&server_address, server_addr_length);

                    if (F_log != NULL) {
                        if (bytes_sent <= 0)
                        {
                            fprintf(F_log, "Cannot send first packet to server, returns %d\n", bytes_sent);
                            ret = -1;
                        }
                    }
                }
            }
        }
    }

    /* Wait for packets */
    while (ret == 0 && picoquic_get_cnx_state(cnx_client) != picoquic_state_disconnected) {
        unsigned char received_ecn;

        from_length = to_length = sizeof(struct sockaddr_storage);

        bytes_recv = picoquic_select(&fd, 1, &packet_from, &from_length,
            &packet_to, &to_length, &if_index_to, &received_ecn,
            buffer, sizeof(buffer),
            delta_t,
            &current_time);

        if (bytes_recv != 0 && F_log != NULL &&
            (cnx_client == NULL || cnx_client->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || qclient->use_long_log)){
            fprintf(F_log, "Select returns %d, from length %d\n", bytes_recv, from_length);
        }

        if (bytes_recv != 0 && to_length != 0) {
            /* Keeping track of the addresses and ports, as we 
             * need them to verify the migration behavior */
            if (!address_updated) {
                struct sockaddr_storage local_address;
                if (picoquic_get_local_address(fd, &local_address) != 0) {
                    memset(&local_address, 0, sizeof(struct sockaddr_storage));
                }

                address_updated = 1;
                picoquic_store_addr(&client_address, (struct sockaddr *)&packet_to);
                if (client_address.ss_family == AF_INET) {
                    ((struct sockaddr_in *)&client_address)->sin_port =
                        ((struct sockaddr_in *)&local_address)->sin_port;
                }
                else {
                    ((struct sockaddr_in6 *)&client_address)->sin6_port =
                        ((struct sockaddr_in6 *)&local_address)->sin6_port;
                }
                if (F_log != NULL) {
                    fprintf(F_log, "Local address updated\n");
                }
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

                if (F_log != NULL) {
                    picoquic_log_processing(F_log, cnx_client, bytes_recv, ret);
                }

                if (picoquic_get_cnx_state(cnx_client) == picoquic_state_client_almost_ready && notified_ready == 0) {
                    if (picoquic_tls_is_psk_handshake(cnx_client)) {
                        fprintf(stdout, "The session was properly resumed!\n");
                        if (F_log != stdout && F_log != stderr && F_log != NULL) {
                            fprintf(F_log, "The session was properly resumed!\n");
                        }
                    }

                    if (cnx_client->zero_rtt_data_accepted) {
                        fprintf(stdout, "Zero RTT data is accepted!\n");
                    }
                    fprintf(stdout, "Almost ready!\n\n");
                    notified_ready = 1;
                }

                if (ret != 0 && F_log != NULL) {
                    picoquic_log_error_packet(F_log, buffer, (size_t)bytes_recv, ret);
                }

                delta_t = 0;
            }

            /* In normal circumstances, the code waits until all packets in the receive
             * queue have been processed before sending new packets. However, if the server
             * is sending lots and lots of data this can lead to the client not getting
             * the occasion to send acknowledgements. The server will start retransmissions,
             * and may eventually drop the connection for lack of acks. So we limit
             * the number of packets that can be received before sending responses. */

            if (bytes_recv == 0 || (ret == 0 && client_receive_loop > PICOQUIC_DEMO_CLIENT_MAX_RECEIVE_BATCH)) {
                client_receive_loop = 0;

                if (ret == 0 && (picoquic_get_cnx_state(cnx_client) == picoquic_state_ready || 
                    picoquic_get_cnx_state(cnx_client) == picoquic_state_client_ready_start)) {
                    if (established == 0) {
                        if (F_log != NULL) {
                            picoquic_log_transport_extension(F_log, cnx_client, 0);
                        }
                        printf("Connection established. Version = %x, I-CID: %llx\n",
                            picoquic_supported_versions[cnx_client->version_index].version,
                            (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_client)));
                        established = 1;

                        if (zero_rtt_available == 0) {
                            /* Start the download scenario */

                            picoquic_demo_client_start_streams(cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                        }
                    }

                    client_ready_loop++;

                    if (force_migration && migration_started == 0 && 
                        (cnx_client->cnxid_stash_first != NULL || force_migration == 1)
                        && picoquic_get_cnx_state(cnx_client) == picoquic_state_ready) {
                        int mig_ret = quic_client_migrate(cnx_client, &fd,
                            (struct sockaddr *)&server_address, force_migration, F_log);

                        migration_started = 1;
                        address_updated = 0;

                        if (mig_ret != 0) {
                            fprintf(stdout, "Will not test migration.\n");
                            migration_started = -1;
                        }
                    }

                    if (nb_packets_before_key_update > 0 &&
                        !key_update_done &&
                        cnx_client->pkt_ctx[picoquic_packet_context_application].first_sack_item.end_of_sack_range > (uint64_t)nb_packets_before_key_update) {
                        int key_rot_ret = picoquic_start_key_rotation(cnx_client);
                        if (key_rot_ret != 0) {
                            fprintf(stdout, "Will not test key rotation.\n");
                            key_update_done = -1;
                        }
                        else {
                            fprintf(stdout, "Key rotation started.\n");
                            key_update_done = 1;
                        }
                    }

                    if (bytes_recv == 0 || client_ready_loop > 4) {
                        if (callback_ctx.nb_open_streams == 0) {
                            if (cnx_client->nb_zero_rtt_sent != 0) {
                                fprintf(stdout, "Out of %d zero RTT packets, %d were acked by the server.\n",
                                    cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
                                if (F_log != stdout && F_log != stderr && F_log != NULL)
                                {
                                    fprintf(F_log, "Out of %d zero RTT packets, %d were acked by the server.\n",
                                        cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
                                }
                            }
                            fprintf(stdout, "All done, Closing the connection.\n");
                            if (F_log != stdout && F_log != stderr && F_log != NULL)
                            {
                                fprintf(F_log, "All done, Closing the connection.\n");
                            }
                            if (picoquic_get_data_received(cnx_client) > 0) {
                                double duration_usec = (double)(current_time - picoquic_get_cnx_start_time(cnx_client));

                                if (duration_usec > 0) {
                                    double receive_rate_mbps = 8.0*((double)picoquic_get_data_received(cnx_client)) / duration_usec;
                                    fprintf(stdout, "Received %llu bytes in %f seconds, %f Mbps.\n",
                                        (unsigned long long)picoquic_get_data_received(cnx_client),
                                        duration_usec/1000000.0, receive_rate_mbps);
                                    if (F_log != stdout && F_log != stderr && F_log != NULL)
                                    {
                                        fprintf(F_log, "Received %llu bytes in %f seconds, %f Mbps.\n",
                                            (unsigned long long)picoquic_get_data_received(cnx_client),
                                            duration_usec / 1000000.0, receive_rate_mbps);
                                    }
                                }
                            }

                            ret = picoquic_close(cnx_client, 0);
                        }
                        else if (
                            current_time > callback_ctx.last_interaction_time && current_time - callback_ctx.last_interaction_time > 10000000ull
                            && picoquic_is_cnx_backlog_empty(cnx_client)) {
                            fprintf(stdout, "No progress for 10 seconds. Closing. \n");
                            if (F_log != stdout && F_log != stderr && F_log != NULL)
                            {
                                fprintf(F_log, "No progress for 10 seconds. Closing. \n");
                            }
                            ret = picoquic_close(cnx_client, 0);
                        }
                    }
                }

                if (ret == 0) {
                    struct sockaddr_storage x_to;
                    int  x_to_length;
                    struct sockaddr_storage x_from;
                    int  x_from_length;

                    send_length = PICOQUIC_MAX_PACKET_SIZE;

                    ret = picoquic_prepare_packet(cnx_client, current_time,
                        send_buffer, sizeof(send_buffer), &send_length, &x_to, &x_to_length, &x_from, &x_from_length);

                    if (migration_started && force_migration == 3){
                        if (address_updated) {
                            if (picoquic_compare_addr((struct sockaddr *)&x_from, (struct sockaddr *)&client_address) != 0) {
                                fprintf(F_log, "Dropping packet sent from wrong address\n");
                                send_length = 0;
                            }
                        }
                    }

                    if (ret == 0 && send_length > 0) {
                        bytes_sent = sendto(fd, send_buffer, (int)send_length, 0,
                            (struct sockaddr*)&x_to, x_to_length);

                        if (bytes_sent <= 0)
                        {
                            fprintf(stdout, "Cannot send packet to server, returns %d\n", bytes_sent);

                            if (F_log != stdout && F_log != stderr && F_log != NULL)
                            {
                                fprintf(F_log, "Cannot send packet to server, returns %d\n", bytes_sent);
                            }
                        }
                    }
                }

                delta_t = picoquic_get_next_wake_delay(qclient, current_time, delay_max);

                if (delta_t > 10000 && callback_ctx.nb_open_streams == 0 &&
                    picoquic_is_cnx_backlog_empty(cnx_client)) {
                    delta_t = 10000;
                }
            }
        }
    }

    /* Clean up */
    picoquic_demo_client_delete_context(&callback_ctx);

    if (qclient != NULL) {
        uint8_t* ticket;
        uint16_t ticket_length;

        if (sni != NULL && 0 == picoquic_get_ticket(qclient->p_first_ticket, current_time, sni, (uint16_t)strlen(sni), alpn, (uint16_t)strlen(alpn), &ticket, &ticket_length, NULL, 0)) {
            FILE * F = (F_log != NULL) ? F_log : stdout;
            fprintf(F, "Received ticket from %s:\n", sni);
            picoquic_log_picotls_ticket(F, picoquic_null_connection_id, ticket, ticket_length);
        }

        if (picoquic_save_tickets(qclient->p_first_ticket, current_time, ticket_store_filename) != 0) {
            fprintf(stderr, "Could not store the saved session tickets.\n");
        }


        if (picoquic_save_tokens(qclient->p_first_token, current_time, token_store_filename) != 0) {
            fprintf(stderr, "Could not save tokens to <%s>.\n", token_store_filename);
        }

        picoquic_free(qclient);
    }

    if (fd != INVALID_SOCKET) {
        SOCKET_CLOSE(fd);
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
    fprintf(stderr, "  -l file               Log file, Log to stdout if file = \"n\". No logging if absent.\n");
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
    fprintf(stderr, "  -g cc_log_dir         log congestion control traces in specified dir\n");
    fprintf(stderr, "  -D                    no disk: do not save received files on disk.\n");
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
    const char * sni = NULL;
    const char * alpn = NULL;
    const char * cc_log_dir = NULL;
    int server_port = default_server_port;
    const char* root_trust_file = NULL;
    uint32_t proposed_version = 0;
    int is_client = 0;
    int just_once = 0;
    int do_hrr = 0;
    int force_zero_share = 0;
    int force_migration = 0;
    int nb_packets_before_update = 0;
    int client_cnx_id_length = 8;
    int no_disk = 0;
    int use_long_log = 0;
    picoquic_connection_id_callback_ctx_t * cnx_id_cbdata = NULL;
    uint64_t* reset_seed = NULL;
    uint64_t reset_seed_x[2];
    int dest_if = -1;
    int mtu_max = 0;
    char default_server_cert_file[512];
    char default_server_key_file[512];
    char * client_scenario = NULL;
    FILE* F_log = NULL;

#ifdef _WINDOWS
    WSADATA wsaData;
#endif
    int ret = 0;

    /* HTTP09 test */

    /* Get the parameters */
    int opt;
    while ((opt = getopt(argc, argv, "c:k:K:p:u:v:f:i:s:e:E:l:m:n:a:t:S:I:g:1rhzDL")) != -1) {
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
        case '1':
            just_once = 1;
            break;
        case 'r':
            do_hrr = 1;
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
        case 'g':
            cc_log_dir = optarg;
            break;
        case 'e':
            dest_if = atoi(optarg);
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
            if (client_cnx_id_length != 0 && (client_cnx_id_length < 4 || client_cnx_id_length > 18)){
                fprintf(stderr, "Invalid connection id length: %s\n", optarg);
                usage();
            }
            break;
        case 'D':
            no_disk = 1;
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

#ifdef _WINDOWS
    // Init WSA.
    if (ret == 0) {
        if (WSA_START(MAKEWORD(2, 2), &wsaData)) {
            fprintf(stderr, "Cannot init WSA\n");
            ret = -1;
        }
    }
#endif

    if (log_file != NULL) {
        if (strcmp(log_file, "-") == 0) {
            F_log = stdout;
        }
        else
        {
            if ((F_log = picoquic_file_open(log_file, "w")) == NULL) {
                fprintf(stderr, "Could not open the log file <%s>\n", log_file);
            }
        }
    }

    if (F_log != NULL) {
        debug_printf_push_stream(F_log);
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
        printf("Starting PicoQUIC server on port %d, server name = %s, just_once = %d, hrr= %d\n",
            server_port, server_name, just_once, do_hrr);
        ret = quic_server(server_name, server_port,
            server_cert_file, server_key_file, just_once, do_hrr,
            (cnx_id_cbdata == NULL) ? NULL : picoquic_connection_id_callback,
            (cnx_id_cbdata == NULL) ? NULL : (void*)cnx_id_cbdata,
            (uint8_t*)reset_seed, dest_if, mtu_max, proposed_version,
            esni_key_file, esni_rr_file,
            F_log, cc_log_dir, use_long_log);
        printf("Server exit with code = %d\n", ret);
    } else {
        /* Run as client */
        printf("Starting PicoQUIC connection to server IP = %s, port = %d\n", server_name, server_port);
        ret = quic_client(server_name, server_port, sni, esni_rr_file, alpn, root_trust_file, proposed_version, force_zero_share, 
            force_migration, nb_packets_before_update, mtu_max, F_log, client_cnx_id_length, client_scenario, cc_log_dir, no_disk, use_long_log);

        printf("Client exit with code = %d\n", ret);
    }

    if (F_log != stdout) {
        (void)picoquic_file_close(F_log);
    }

    if (cnx_id_cbdata != NULL) {
        picoquic_connection_id_callback_free_ctx(cnx_id_cbdata);
    }
}
