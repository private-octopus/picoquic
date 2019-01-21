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

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picosocks.h"
#include "util.h"
#include "h3zero.c"
#include "democlient.h"
#include "demoserver.h"

void print_address(struct sockaddr* address, char* label, picoquic_connection_id_t cnx_id)
{
    char hostname[256];

    const char* x = inet_ntop(address->sa_family,
        (address->sa_family == AF_INET) ? (void*)&(((struct sockaddr_in*)address)->sin_addr) : (void*)&(((struct sockaddr_in6*)address)->sin6_addr),
        hostname, sizeof(hostname));

    printf("%016llx : ", (unsigned long long)picoquic_val64_connection_id(cnx_id));

    if (x != NULL) {
        printf("%s %s, port %d\n", label, x,
            (address->sa_family == AF_INET) ? ((struct sockaddr_in*)address)->sin_port : ((struct sockaddr_in6*)address)->sin6_port);
    } else {
        printf("%s: inet_ntop failed with error # %ld\n", label, WSA_LAST_ERROR(errno));
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
    int just_once, int do_hrr, cnx_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_ctx, uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    int dest_if, int mtu_max, uint32_t proposed_version)
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

            /* TODO: add log level, to reduce size in "normal" cases */
            PICOQUIC_SET_LOG(qserver, stdout);

            picoquic_set_key_log_file_from_env(qserver);
        }
    }

    /* Wait for packets */
    while (ret == 0 && (just_once == 0 || cnx_server == NULL || picoquic_get_cnx_state(cnx_server) != picoquic_state_disconnected)) {
        int64_t delta_t = picoquic_get_next_wake_delay(qserver, current_time, delay_max);
        uint64_t time_before = current_time;

        from_length = to_length = sizeof(struct sockaddr_storage);
        if_index_to = 0;

        if (just_once != 0 && delta_t > 10000 && cnx_server != NULL) {
            picoquic_log_congestion_state(stdout, cnx_server, current_time);
        }

        bytes_recv = picoquic_select(server_sockets.s_socket, PICOQUIC_NB_SERVER_SOCKETS,
            &addr_from, &from_length,
            &addr_to, &to_length, &if_index_to,
            buffer, sizeof(buffer),
            delta_t, &current_time);

        if (just_once != 0) {
            if (bytes_recv > 0) {
                printf("Select returns %d, from length %d after %d us (wait for %d us)\n",
                    bytes_recv, from_length, (int)(current_time - time_before), (int)delta_t);
                print_address((struct sockaddr*)&addr_from, "recv from:", picoquic_null_connection_id);
            } else {
                printf("Select return %d, after %d us (wait for %d us)\n", bytes_recv,
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
                    (struct sockaddr*)&addr_to, if_index_to,
                    current_time);

                if (ret != 0) {
                    ret = 0;
                }

                if (cnx_server != picoquic_get_first_cnx(qserver) && picoquic_get_first_cnx(qserver) != NULL) {
                    cnx_server = picoquic_get_first_cnx(qserver);
                    printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_server)));
                    picoquic_log_time(stdout, cnx_server, picoquic_current_time(), "", " : ");
                    printf("Connection established, state = %d, from length: %d\n",
                        picoquic_get_cnx_state(picoquic_get_first_cnx(qserver)), from_length);
                    memset(&client_from, 0, sizeof(client_from));
                    memcpy(&client_from, &addr_from, from_length);

                    print_address((struct sockaddr*)&client_from, "Client address:",
                        picoquic_get_logging_cnxid(cnx_server));
                    picoquic_log_transport_extension(stdout, cnx_server, 1);
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

                fflush(stdout);

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

                    printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_next)));
                    picoquic_log_time(stdout, cnx_server, picoquic_current_time(), "", " : ");
                    printf("Closed. Retrans= %d, spurious= %d, max sp gap = %d, max sp delay = %d\n",
                        (int)cnx_next->nb_retransmission_total, (int)cnx_next->nb_spurious,
                        (int)cnx_next->path[0]->max_reorder_gap, (int)cnx_next->path[0]->max_spurious_rtt);

                    if (cnx_next == cnx_server) {
                        cnx_server = NULL;
                    }

                    picoquic_delete_cnx(cnx_next);

                    fflush(stdout);

                    break;
                }
                else if (ret == 0) {

                    if (send_length > 0) {
                        if (just_once != 0 ||
                            cnx_next->cnx_state < picoquic_state_server_false_start ||
                            cnx_next->cnx_state >= picoquic_state_disconnecting) {
                            printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_next)));
                            printf("Connection state = %d\n",
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

static const picoquic_demo_stream_desc_t test_scenario[] = {
#ifdef PICOQUIC_TEST_AGAINST_ATS
    { 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "", "slash.html", 0 },
    { 8, 4, "en/latest/", "slash_en_slash_latest.html", 0 }
#else
#ifdef PICOQUIC_TEST_AGAINST_QUICKLY
    { 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "123.txt", "123.txt", 0 }
#else
    { 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "index.html", "index.html", 0 },
    { 4, 0, "test.html", "test.html", 0 },
    { 8, 0, "1234567", "doc-1234567.html", 0 },
    { 12, 0, "main.jpg", "main.jpg", 1 },
    { 16, 0, "war-and-peace.txt", "war-and-peace.txt", 0 },
    { 20, 0, "en/latest/", "slash_en_slash_latest.html", 0 },
    { 24, 0, "/file-123K", "file-123k.txt", 0 }
#endif
#endif
};

static const size_t test_scenario_nb = sizeof(test_scenario) / sizeof(picoquic_demo_stream_desc_t);

#define PICOQUIC_DEMO_CLIENT_MAX_RECEIVE_BATCH 4

/* Client client migration to a new port number: 
 *  - close the current socket.
 *  - open another socket at a randomly picked port number.
 *  - call the create probe API.
 * This is a bit tricky because the probe API requires passing the new address,
 * but in many cases the client will be behind a NAT, so it will not know its
 * actual IP address.
 */
int quic_client_migrate(picoquic_cnx_t * cnx, SOCKET_TYPE * fd, struct sockaddr * server_address, int force_migration, FILE * F_log) 
{
    int ret = 0;

    if (force_migration != 2) {
        SOCKET_TYPE fd_m;

        fd_m = socket(server_address->sa_family, SOCK_DGRAM, IPPROTO_UDP);
        if (fd_m == INVALID_SOCKET) {
            fprintf(stdout, "Could not open new socket.\n");
            if (F_log != stdout && F_log != stderr)
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

    if (ret == 0){
        if (force_migration == 1) {
            fprintf(stdout, "Switch to new port. Will test NAT rebinding support.\n");
            if (F_log != stdout && F_log != stderr)
            {
                fprintf(F_log, "Switch to new port. Will test NAT rebinding support.\n");
            }
        }
        else if (force_migration == 2) {
            ret = picoquic_renew_connection_id(cnx);
            if (ret != 0) {
                if (ret == PICOQUIC_ERROR_MIGRATION_DISABLED) {
                    fprintf(stdout, "Migration disabled, cannot test CNXID renewal.\n");
                    if (F_log != stdout && F_log != stderr)
                    {
                        fprintf(stdout, "Migration disabled, cannot test CNXID renewal.\n");
                    }
                }
                else {
                    fprintf(stdout, "Renew CNXID failed, error: %x.\n", ret);
                    if (F_log != stdout && F_log != stderr)
                    {
                        fprintf(F_log, "Create Probe failed, error: %x.\n", ret);
                    }
                }
            }
            else {
                fprintf(stdout, "Switching to new CNXID.\n");
                if (F_log != stdout && F_log != stderr)
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
                    if (F_log != stdout && F_log != stderr)
                    {
                        fprintf(F_log, "Will test NAT rebinding support.\n");
                    }

                    ret = 0;
                }
                else {
                    fprintf(stdout, "Create Probe failed, error: %x.\n", ret);
                    if (F_log != stdout && F_log != stderr)
                    {
                        fprintf(F_log, "Create Probe failed, error: %x.\n", ret);
                    }
                }
            }
            else {
                fprintf(stdout, "Switch to new port, sending probe.\n");
                if (F_log != stdout && F_log != stderr)
                {
                    fprintf(F_log, "Switch to new port, sending probe.\n");
                }
            }
        }
    }

    return ret;
}

/* Quic Client */
int quic_client(const char* ip_address_text, int server_port, const char * sni, 
    const char * alpn, const char * root_crt,
    uint32_t proposed_version, int force_zero_share, int force_migration, 
    int nb_packets_before_key_update, int mtu_max, FILE* F_log,
    int client_cnx_id_length)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    SOCKET_TYPE fd = INVALID_SOCKET;
    struct sockaddr_storage server_address;
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
    int64_t delay_max = 10000000;
    int64_t delta_t = 0;
    int notified_ready = 0;int zero_rtt_available = 0;

    if (alpn == NULL) {
        alpn = "hq-17";
    }

    ret = picoquic_demo_client_initialize_context(&callback_ctx, test_scenario, test_scenario_nb, alpn);

    if (ret == 0) {
        ret = picoquic_get_server_address(ip_address_text, server_port, &server_address, &server_addr_length, &is_name);
        if (sni == NULL && is_name != 0) {
            sni = ip_address_text;
        }
    }

    /* Open a UDP socket */

    if (ret == 0) {
        fd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
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
            if (force_zero_share) {
                qclient->flags |= picoquic_context_client_zero_share;
            }
            qclient->mtu_max = mtu_max;

            (void)picoquic_set_default_connection_id_length(qclient, (uint8_t)client_cnx_id_length);

            PICOQUIC_SET_LOG(qclient, F_log);

            picoquic_set_key_log_file_from_env(qclient);

            if (sni == NULL) {
                /* Standard verifier would crash */
                fprintf(stdout, "No server name specified, certificate will not be verified.\n");
                if (F_log != stdout && F_log != stderr)
                {
                    fprintf(F_log, "No server name specified, certificate will not be verified.\n");
                }
                picoquic_set_null_verifier(qclient);
            }
            else if (root_crt == NULL) {

                /* Standard verifier would crash */
                fprintf(stdout, "No root crt list specified, certificate will not be verified.\n");
                if (F_log != stdout && F_log != stderr)
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


            if (callback_ctx.tp != NULL) {
                picoquic_set_transport_parameters(cnx_client, callback_ctx.tp);
            }

            ret = picoquic_start_client_cnx(cnx_client);

            if (ret == 0) {
                if (picoquic_is_0rtt_available(cnx_client) && (proposed_version & 0x0a0a0a0a) != 0x0a0a0a0a) {
                    zero_rtt_available = 1;

                    /* Queue a simple frame to perform 0-RTT test */
                    /* Start the download scenario */
                    callback_ctx.demo_stream = test_scenario;
                    callback_ctx.nb_demo_streams = test_scenario_nb;

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
        if (picoquic_is_cnx_backlog_empty(cnx_client) && callback_ctx.nb_open_streams == 0) {
            delay_max = 10000;
        } else {
            delay_max = 10000000;
        }

        from_length = to_length = sizeof(struct sockaddr_storage);

        bytes_recv = picoquic_select(&fd, 1, &packet_from, &from_length,
            &packet_to, &to_length, &if_index_to,
            buffer, sizeof(buffer),
            delta_t,
            &current_time);

        if (bytes_recv != 0) {
            fprintf(F_log, "Select returns %d, from length %d\n", bytes_recv, from_length);
        }

        if (bytes_recv < 0) {
            ret = -1;
        } else {
            if (bytes_recv > 0) {
                /* Submit the packet to the client */
                ret = picoquic_incoming_packet(qclient, buffer,
                    (size_t)bytes_recv, (struct sockaddr*)&packet_from,
                    (struct sockaddr*)&packet_to, if_index_to,
                    current_time);
                client_receive_loop++;

                picoquic_log_processing(F_log, cnx_client, bytes_recv, ret);

                if (picoquic_get_cnx_state(cnx_client) == picoquic_state_client_almost_ready && notified_ready == 0) {
                    if (picoquic_tls_is_psk_handshake(cnx_client)) {
                        fprintf(stdout, "The session was properly resumed!\n");
                        if (F_log != stdout && F_log != stderr) {
                            fprintf(F_log, "The session was properly resumed!\n");
                        }
                    }

                    if (cnx_client->zero_rtt_data_accepted) {
                        fprintf(stdout, "Zero RTT data is accepted!\n");
                    }
                    fprintf(stdout, "Almost ready!\n\n");
                    notified_ready = 1;
                }

                if (ret != 0) {
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
                        picoquic_log_transport_extension(F_log, cnx_client, 0);
                        printf("Connection established. Version = %x, I-CID: %llx\n",
                            picoquic_supported_versions[cnx_client->version_index].version,
                            (unsigned long long)picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx_client)));
                        established = 1;

                        if (zero_rtt_available == 0) {
                            /* Start the download scenario */
                            callback_ctx.demo_stream = test_scenario;
                            callback_ctx.nb_demo_streams = test_scenario_nb;

                            picoquic_demo_client_start_streams(cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
                        }
                    }

                    client_ready_loop++;

                    if (force_migration && migration_started == 0 && cnx_client->cnxid_stash_first != NULL
                        && picoquic_get_cnx_state(cnx_client) == picoquic_state_ready) {
                        int mig_ret = quic_client_migrate(cnx_client, &fd,
                            (struct sockaddr *)&server_address, force_migration, F_log);

                        migration_started = 1;

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

                    if ((bytes_recv == 0 || client_ready_loop > 4) && picoquic_is_cnx_backlog_empty(cnx_client)) {
                        if (callback_ctx.nb_open_streams == 0) {
                            if (cnx_client->nb_zero_rtt_sent != 0) {
                                fprintf(stdout, "Out of %d zero RTT packets, %d were acked by the server.\n",
                                    cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
                                if (F_log != stdout && F_log != stderr)
                                {
                                    fprintf(F_log, "Out of %d zero RTT packets, %d were acked by the server.\n",
                                        cnx_client->nb_zero_rtt_sent, cnx_client->nb_zero_rtt_acked);
                                }
                            }
                            fprintf(stdout, "All done, Closing the connection.\n");
                            if (F_log != stdout && F_log != stderr)
                            {
                                fprintf(F_log, "All done, Closing the connection.\n");
                            }

                            ret = picoquic_close(cnx_client, 0);
                        } else if (
                            current_time > callback_ctx.last_interaction_time && current_time - callback_ctx.last_interaction_time > 10000000ull) {
                            fprintf(stdout, "No progress for 10 seconds. Closing. \n");
                            if (F_log != stdout && F_log != stderr)
                            {
                                fprintf(F_log, "No progress for 10 seconds. Closing. \n");
                            }
                            ret = picoquic_close(cnx_client, 0);
                        }
                    }
                }

                if (ret == 0) {
                    send_length = PICOQUIC_MAX_PACKET_SIZE;

                    ret = picoquic_prepare_packet(cnx_client, current_time,
                        send_buffer, sizeof(send_buffer), &send_length, NULL, NULL, NULL, NULL);

                    if (ret == 0 && send_length > 0) {
                        bytes_sent = sendto(fd, send_buffer, (int)send_length, 0,
                            (struct sockaddr*)&server_address, server_addr_length);

                        if (bytes_sent <= 0)
                        {
                            fprintf(stdout, "Cannot send packet to server, returns %d\n", bytes_sent);

                            if (F_log != stdout && F_log != stderr)
                            {
                                fprintf(F_log, "Cannot send packet to server, returns %d\n", bytes_sent);
                            }
                        }
                    }
                }

                delta_t = picoquic_get_next_wake_delay(qclient, current_time, delay_max);
            }
        }
    }

    /* Clean up */
    picoquic_demo_client_delete_context(&callback_ctx);

    if (qclient != NULL) {
        uint8_t* ticket;
        uint16_t ticket_length;

        if (sni != NULL && 0 == picoquic_get_ticket(qclient->p_first_ticket, current_time, sni, (uint16_t)strlen(sni), alpn, (uint16_t)strlen(alpn), &ticket, &ticket_length)) {
            fprintf(F_log, "Received ticket from %s:\n", sni);
            picoquic_log_picotls_ticket(F_log, picoquic_null_connection_id, ticket, ticket_length);
        }

        if (picoquic_save_tickets(qclient->p_first_ticket, current_time, ticket_store_filename) != 0) {
            fprintf(stderr, "Could not store the saved session tickets.\n");
        }
        picoquic_free(qclient);
    }

    if (fd != INVALID_SOCKET) {
        SOCKET_CLOSE(fd);
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
    fprintf(stderr, "Usage: picoquicdemo [server_name [port]] <options>\n");
    fprintf(stderr, "  For the client mode, specify sever_name and port.\n");
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
    fprintf(stderr, "  -k file               key file (default: %s)\n", SERVER_KEY_FILE);
    fprintf(stderr, "  -l file               Log file\n");
    fprintf(stderr, "  -p port               server port (default: %d)\n", default_server_port);
    fprintf(stderr, "  -m mtu_max            Largest mtu value that can be tried for discovery\n");
    fprintf(stderr, "  -n sni                sni (default: server name)\n");
    fprintf(stderr, "  -a alpn               alpn (default function of version)\n");
    fprintf(stderr, "  -r                    Do Reset Request\n");
    fprintf(stderr, "  -s <64b 64b>          Reset seed\n");
    fprintf(stderr, "  -t file               root trust file");
    fprintf(stderr, "  -u nb                 trigger key update after receiving <nb> packets on client\n");
    fprintf(stderr, "  -v version            Version proposed by client, e.g. -v ff00000e\n");
    fprintf(stderr, "                        or restrict the server to draft-14 mode.\n");
    fprintf(stderr, "  -z                    Set TLS zero share behavior on client, to force HRR.\n");
    fprintf(stderr, "  -1                    Once\n");
    fprintf(stderr, "  -S solution_dir       Set the path to the source files to find the default files\n");
    fprintf(stderr, "  -I length             Length of CNX_ID used by the client, default=8\n");
    exit(1);
}

enum picoquic_cnx_id_select {
    picoquic_cnx_id_random = 0,
    picoquic_cnx_id_remote = 1
};

typedef struct {
    enum picoquic_cnx_id_select cnx_id_select;
    picoquic_connection_id_t cnx_id_mask;
    picoquic_connection_id_t cnx_id_val;
} cnx_id_callback_ctx_t;

static void cnx_id_callback(picoquic_connection_id_t cnx_id_local, picoquic_connection_id_t cnx_id_remote, void* cnx_id_callback_ctx, 
    picoquic_connection_id_t * cnx_id_returned)
{
    uint64_t val64;
    cnx_id_callback_ctx_t* ctx = (cnx_id_callback_ctx_t*)cnx_id_callback_ctx;

    if (ctx->cnx_id_select == picoquic_cnx_id_remote)
        cnx_id_local = cnx_id_remote;

    /* TODO: replace with encrypted value when moving to 17 byte CID */
    val64 = (picoquic_val64_connection_id(cnx_id_local) & picoquic_val64_connection_id(ctx->cnx_id_mask)) |
        picoquic_val64_connection_id(ctx->cnx_id_val);
    picoquic_set64_connection_id(cnx_id_returned, val64);
}

int main(int argc, char** argv)
{
    const char * solution_dir = NULL;
    const char* server_name = default_server_name;
    const char* server_cert_file = NULL;
    const char* server_key_file = NULL;
    const char* log_file = NULL;
    const char * sni = NULL;
    const char * alpn = NULL;
    int server_port = default_server_port;
    const char* root_trust_file = NULL;
    uint32_t proposed_version = 0;
    int is_client = 0;
    int just_once = 0;
    int do_hrr = 0;
    int force_zero_share = 0;
    int force_migration = 0;
    int nb_packets_before_update = 0;
    int cnx_id_mask_is_set = 0;
    int client_cnx_id_length = 8;
    cnx_id_callback_ctx_t cnx_id_cbdata = {
        .cnx_id_select = 0,
        .cnx_id_mask = {{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 8 },
        .cnx_id_val = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 0 }
    };
    uint64_t* reset_seed = NULL;
    uint64_t reset_seed_x[2];
    int dest_if = -1;
    int mtu_max = 0;
    char default_server_cert_file[512];
    char default_server_key_file[512];

#ifdef _WINDOWS
    WSADATA wsaData;
#endif
    int ret = 0;

    /* HTTP09 test */

    /* Get the parameters */
    int opt;
    while ((opt = getopt(argc, argv, "c:k:p:u:v:1rhzf:i:s:e:l:m:n:a:t:S:I:")) != -1) {
        switch (opt) {
        case 'c':
            server_cert_file = optarg;
            break;
        case 'k':
            server_key_file = optarg;
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
        case 'e':
            dest_if = atoi(optarg);
            break;
        case 'i':
            if (optind + 2 > argc) {
                fprintf(stderr, "option requires more arguments -- i\n");
                usage();
            }

            cnx_id_cbdata.cnx_id_select = atoi(optarg);
            /* TODO: find an alternative to parsing a 64 bit integer */
            picoquic_set64_connection_id(&cnx_id_cbdata.cnx_id_mask, ~strtoul(argv[optind++], NULL, 0));
            picoquic_set64_connection_id(&cnx_id_cbdata.cnx_id_val, strtoul(argv[optind++], NULL, 0));
            cnx_id_mask_is_set = 1;
            break;
        case 'l':
            log_file = optarg;
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
            break;
        case 'I':
            client_cnx_id_length = atoi(optarg);
            if (client_cnx_id_length != 0 && (client_cnx_id_length < 4 || client_cnx_id_length > 18)){
                fprintf(stderr, "Invalid connection id length: %s\n", optarg);
                usage();
            }
            break;
        case 'h':
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

#ifdef _WINDOWS
    // Init WSA.
    if (ret == 0) {
        if (WSA_START(MAKEWORD(2, 2), &wsaData)) {
            fprintf(stderr, "Cannot init WSA\n");
            ret = -1;
        }
    }
#endif

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
            /* TODO: find an alternative to using 64 bit mask. */
            (cnx_id_mask_is_set == 0) ? NULL : cnx_id_callback,
            (cnx_id_mask_is_set == 0) ? NULL : (void*)&cnx_id_cbdata,
            (uint8_t*)reset_seed, dest_if, mtu_max, proposed_version);
        printf("Server exit with code = %d\n", ret);
    } else {
        FILE* F_log = NULL;

        if (log_file != NULL) {
#ifdef _WINDOWS
            if (fopen_s(&F_log, log_file, "w") != 0) {
                F_log = NULL;
            }
#else
            F_log = fopen(log_file, "w");
#endif
            if (F_log == NULL) {
                fprintf(stderr, "Could not open the log file <%s>\n", log_file);
            }
        }

        if (F_log == NULL) {
            F_log = stdout;
        }

        if (F_log != NULL) {
            debug_printf_push_stream(F_log);
        }

        /* Run as client */
        printf("Starting PicoQUIC connection to server IP = %s, port = %d\n", server_name, server_port);
        ret = quic_client(server_name, server_port, sni, alpn, root_trust_file, proposed_version, force_zero_share, 
            force_migration, nb_packets_before_update, mtu_max, F_log, client_cnx_id_length);

        printf("Client exit with code = %d\n", ret);

        if (F_log != NULL && F_log != stdout) {
            fclose(F_log);
        }
    }
}
