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

#ifdef _WINDOWS64
static const char* default_server_cert_file = "..\\..\\certs\\cert.pem";
static const char* default_server_key_file = "..\\..\\certs\\key.pem";
#else
static const char* default_server_cert_file = "..\\certs\\cert.pem";
static const char* default_server_key_file = "..\\certs\\key.pem";
#endif

#else /* Linux */

#include <alloca.h>
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

static const char* default_server_cert_file = "certs/cert.pem";
static const char* default_server_key_file = "certs/key.pem";

#endif

static const int default_server_port = 4443;
static const char* default_server_name = "::";
static const char* ticket_store_filename = "demo_ticket_store.bin";

static const char* bad_request_message = "<html><head><title>Bad Request</title></head><body>Bad request. Why don't you try \"GET /doc-456789.html\"?</body></html>";


#include "../picoquic/picoquic.h"
#include "../picoquic/picoquic_internal.h"
#include "../picoquic/picosocks.h"
#include "../picoquic/util.h"

void picoquic_log_error_packet(FILE* F, uint8_t* bytes, size_t bytes_max, int ret);

void picoquic_log_packet(FILE* F, picoquic_quic_t* quic, picoquic_cnx_t* cnx,
    struct sockaddr* addr_peer, int receiving,
    uint8_t* bytes, size_t length, uint64_t current_time);
void picoquic_log_processing(FILE* F, picoquic_cnx_t* cnx, size_t length, int ret);
void picoquic_log_transport_extension(FILE* F, picoquic_cnx_t* cnx, int log_cnxid);
void picoquic_log_congestion_state(FILE* F, picoquic_cnx_t* cnx, uint64_t current_time);
void picoquic_log_picotls_ticket(FILE* F, picoquic_connection_id_t cnx_id,
    uint8_t* ticket, uint16_t ticket_length);

void print_address(struct sockaddr* address, char* label, picoquic_connection_id_t cnx_id)
{
    char hostname[256];

    const char* x = inet_ntop(address->sa_family,
        (address->sa_family == AF_INET) ? (void*)&(((struct sockaddr_in*)address)->sin_addr) : (void*)&(((struct sockaddr_in6*)address)->sin6_addr),
        hostname, sizeof(hostname));

    printf("%" PRIx64 ": ", picoquic_val64_connection_id(cnx_id));

    if (x != NULL) {
        printf("%s %s, port %d\n", label, x,
            (address->sa_family == AF_INET) ? ((struct sockaddr_in*)address)->sin_port : ((struct sockaddr_in6*)address)->sin6_port);
    } else {
        printf("%s: inet_ntop failed with error # %ld\n", label, WSA_LAST_ERROR(errno));
    }
}

static char* strip_endofline(char* buf, size_t bufmax, char const* line)
{
    for (size_t i = 0; i < bufmax; i++) {
        int c = line[i];

        if (c == 0 || c == '\r' || c == '\n') {
            buf[i] = 0;
            break;
        } else {
            buf[i] = c;
        }
    }

    buf[bufmax - 1] = 0;
    return buf;
}

#define PICOQUIC_FIRST_COMMAND_MAX 128
#define PICOQUIC_FIRST_RESPONSE_MAX (1 << 20)

typedef enum {
    picoquic_first_server_stream_status_none = 0,
    picoquic_first_server_stream_status_receiving,
    picoquic_first_server_stream_status_finished
} picoquic_first_server_stream_status_t;

typedef struct st_picoquic_first_server_stream_ctx_t {
    struct st_picoquic_first_server_stream_ctx_t* next_stream;
    picoquic_first_server_stream_status_t status;
    uint64_t stream_id;
    size_t command_length;
    size_t response_length;
    uint8_t command[PICOQUIC_FIRST_COMMAND_MAX];
} picoquic_first_server_stream_ctx_t;

typedef struct st_picoquic_first_server_callback_ctx_t {
    picoquic_first_server_stream_ctx_t* first_stream;
    size_t buffer_max;
    uint8_t* buffer;
} picoquic_first_server_callback_ctx_t;

static picoquic_first_server_callback_ctx_t* first_server_callback_create_context()
{
    picoquic_first_server_callback_ctx_t* ctx = (picoquic_first_server_callback_ctx_t*)
        malloc(sizeof(picoquic_first_server_callback_ctx_t));

    if (ctx != NULL) {
        ctx->first_stream = NULL;
        ctx->buffer = (uint8_t*)malloc(PICOQUIC_FIRST_RESPONSE_MAX);
        if (ctx->buffer == NULL) {
            free(ctx);
            ctx = NULL;
        } else {
            ctx->buffer_max = PICOQUIC_FIRST_RESPONSE_MAX;
        }
    }

    return ctx;
}

static void first_server_callback_delete_context(picoquic_first_server_callback_ctx_t* ctx)
{
    picoquic_first_server_stream_ctx_t* stream_ctx;

    while ((stream_ctx = ctx->first_stream) != NULL) {
        ctx->first_stream = stream_ctx->next_stream;
        free(stream_ctx);
    }

    free(ctx);
}

static void first_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    picoquic_first_server_callback_ctx_t* ctx = (picoquic_first_server_callback_ctx_t*)callback_ctx;
    picoquic_first_server_stream_ctx_t* stream_ctx = NULL;

    printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_initial_cnxid(cnx)));
    printf("Server CB, Stream: %" PRIu64 ", %" PRIst " bytes, fin=%d\n",
        stream_id, length, fin_or_event);

    if (fin_or_event == picoquic_callback_close || fin_or_event == picoquic_callback_application_close) {
        printf("%" PRIx64 ": %s\n", picoquic_val64_connection_id(picoquic_get_initial_cnxid(cnx)),
            (fin_or_event == picoquic_callback_close) ? "Connection closed" : "Application closed");
        if (ctx != NULL) {
            first_server_callback_delete_context(ctx);
            picoquic_set_callback(cnx, first_server_callback, NULL);
        }

        return;
    }

    if (ctx == NULL) {
        picoquic_first_server_callback_ctx_t* new_ctx = first_server_callback_create_context();
        if (new_ctx == NULL) {
            /* cannot handle the connection */
            DBG_PRINTF("%s\n", "Memory error, cannot allocate application context");
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return;
        } else {
            picoquic_set_callback(cnx, first_server_callback, new_ctx);
            ctx = new_ctx;
        }
    }

    stream_ctx = ctx->first_stream;

    /* if stream is already present, check its state. New bytes? */
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL) {
        stream_ctx = (picoquic_first_server_stream_ctx_t*)
            malloc(sizeof(picoquic_first_server_stream_ctx_t));
        if (stream_ctx == NULL) {
            /* Could not handle this stream */
            picoquic_reset_stream(cnx, stream_id, 500);
            return;
        } else {
            memset(stream_ctx, 0, sizeof(picoquic_first_server_stream_ctx_t));
            stream_ctx->next_stream = ctx->first_stream;
            ctx->first_stream = stream_ctx;
            stream_ctx->stream_id = stream_id;
        }
    }

    /* verify state and copy data to the stream buffer */
    if (fin_or_event == picoquic_callback_stop_sending) {
        stream_ctx->status = picoquic_first_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        return;
    } else if (fin_or_event == picoquic_callback_stream_reset) {
        stream_ctx->status = picoquic_first_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        return;
    } else if (stream_ctx->status == picoquic_first_server_stream_status_finished || stream_ctx->command_length + length > (PICOQUIC_FIRST_COMMAND_MAX - 1)) {
        /* send after fin, or too many bytes => reset! */
        picoquic_reset_stream(cnx, stream_id, 0);
        printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_initial_cnxid(cnx)));
        printf("Server CB, Stream: %" PRIu64 ", RESET, too long or after FIN\n",
            stream_id);
        return;
    } else {
        int crlf_present = 0;

        if (length > 0) {
            memcpy(&stream_ctx->command[stream_ctx->command_length],
                bytes, length);
            stream_ctx->command_length += length;
            for (size_t i = 0; i < length; i++) {
                if (bytes[i] == '\r' || bytes[i] == '\n') {
                    crlf_present = 1;
                    break;
                }
            }
        }

        /* if FIN present, process request through http 0.9 */
        if ((fin_or_event == picoquic_callback_stream_fin || crlf_present != 0) && stream_ctx->response_length == 0) {
            char buf[256];

            stream_ctx->command[stream_ctx->command_length] = 0;
            /* if data generated, just send it. Otherwise, just FIN the stream. */
            stream_ctx->status = picoquic_first_server_stream_status_finished;
            if (http0dot9_get(stream_ctx->command, stream_ctx->command_length,
                    ctx->buffer, ctx->buffer_max, &stream_ctx->response_length)
                != 0) {
                printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_initial_cnxid(cnx)));
                printf("Server CB, Stream: %" PRIu64 ", Reply with bad request message after command: %s\n",
                    stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));
                
                // picoquic_reset_stream(cnx, stream_id, 404);

                (void)picoquic_add_to_stream(cnx, stream_ctx->stream_id, (const uint8_t *) bad_request_message,
                    strlen(bad_request_message), 1);
            } else {
                printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_initial_cnxid(cnx)));
                printf("Server CB, Stream: %" PRIu64 ", Processing command: %s\n",
                    stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));
                picoquic_add_to_stream(cnx, stream_id, ctx->buffer,
                    stream_ctx->response_length, 1);
            }
        } else if (stream_ctx->response_length == 0) {
            char buf[256];

            printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_initial_cnxid(cnx)));
            stream_ctx->command[stream_ctx->command_length] = 0;
            printf("Server CB, Stream: %" PRIu64 ", Partial command: %s\n",
                stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));
        }
    }

    /* that's it */
}

int quic_server(const char* server_name, int server_port,
    const char* pem_cert, const char* pem_key,
    int just_once, int do_hrr, cnx_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_ctx, uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    int mtu_max)
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
    int client_addr_length;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    picoquic_packet* p = NULL;
    uint64_t current_time = 0;
    picoquic_stateless_packet_t* sp;
    int64_t delay_max = 10000000;

    /* Open a UDP socket */
    ret = picoquic_open_server_sockets(&server_sockets, server_port);

    /* Wait for packets and process them */
    if (ret == 0) {
        current_time = picoquic_current_time();
        /* Create QUIC context */
        qserver = picoquic_create(8, pem_cert, pem_key, NULL, first_server_callback, NULL,
            cnx_id_callback, cnx_id_callback_ctx, reset_seed, current_time, NULL, NULL, NULL, 0);

        if (qserver == NULL) {
            printf("Could not create server context\n");
            ret = -1;
        } else {
            if (do_hrr != 0) {
                picoquic_set_cookie_mode(qserver, 1);
            }
            qserver->mtu_max = mtu_max;
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
            if (bytes_recv > 0) {
                if (cnx_server != NULL && just_once != 0) {
                    picoquic_log_packet(stdout, qserver, cnx_server, (struct sockaddr*)&addr_from,
                        1, buffer, bytes_recv, current_time);
                }

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
                    printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_initial_cnxid(cnx_server)));
                    printf("Connection established, state = %d, from length: %d\n",
                        picoquic_get_cnx_state(picoquic_get_first_cnx(qserver)), from_length);
                    memset(&client_from, 0, sizeof(client_from));
                    memcpy(&client_from, &addr_from, from_length);
                    client_addr_length = from_length;

                    print_address((struct sockaddr*)&client_from, "Client address:",
                        picoquic_get_initial_cnxid(cnx_server));
                    picoquic_log_transport_extension(stdout, cnx_server, 1);
                }
            }
            if (ret == 0) {
                uint64_t loop_time = current_time;

                while ((sp = picoquic_dequeue_stateless_packet(qserver)) != NULL) {
                    int sent = picoquic_send_through_server_sockets(&server_sockets,
                        (struct sockaddr*)&sp->addr_to,
                        (sp->addr_to.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                        (struct sockaddr*)&sp->addr_local,
                        (sp->addr_local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                        sp->if_index_local,
                        (const char*)sp->bytes, (int)sp->length);

                    printf("Sending stateless packet, %d bytes\n", sent);
                    picoquic_delete_stateless_packet(sp);
                }

                while (ret == 0 && (cnx_next = picoquic_get_earliest_cnx_to_wake(qserver, loop_time)) != NULL) {
                    p = picoquic_create_packet();

                    if (p == NULL) {
                        ret = -1;
                    } else {
                        ret = picoquic_prepare_packet(cnx_next, p, current_time,
                            send_buffer, sizeof(send_buffer), &send_length);

                        if (ret == PICOQUIC_ERROR_DISCONNECTED) {
                            ret = 0;
                            free(p);

                            printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_initial_cnxid(cnx_next)));
                            printf("Closed. Retrans= %d, spurious= %d, max sp gap = %d, max sp delay = %d\n",
                                (int)cnx_next->nb_retransmission_total, (int)cnx_next->nb_spurious,
                                (int)cnx_next->path[0]->max_reorder_gap, (int)cnx_next->path[0]->max_spurious_rtt);

                            if (cnx_next == cnx_server) {
                                cnx_server = NULL;
                            }

                            picoquic_delete_cnx(cnx_next);

                            fflush(stdout);

                            break;
                        } else if (ret == 0) {
                            int peer_addr_len = 0;
                            struct sockaddr* peer_addr;
                            int local_addr_len = 0;
                            struct sockaddr* local_addr;

                            if (p->length > 0) {
                                if (just_once != 0) {
                                    printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_initial_cnxid(cnx_next)));
                                    printf("Connection state = %d\n",
                                        picoquic_get_cnx_state(cnx_next));
                                }

                                picoquic_get_peer_addr(cnx_next, &peer_addr, &peer_addr_len);
                                picoquic_get_local_addr(cnx_next, &local_addr, &local_addr_len);

                                (void)picoquic_send_through_server_sockets(&server_sockets,
                                    peer_addr, peer_addr_len, local_addr, local_addr_len,
                                    picoquic_get_local_if_index(cnx_next),
                                    (const char*)send_buffer, (int)send_length);

                                if (cnx_server != NULL && just_once != 0 && cnx_next == cnx_server) {
                                    picoquic_log_packet(stdout, qserver, cnx_server, (struct sockaddr*)peer_addr,
                                        0, send_buffer, send_length, current_time);
                                }
                            } else {
                                free(p);
                                p = NULL;
                            }
                        } else {
                            break;
                        }
                    }
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

typedef struct st_demo_stream_desc_t {
    uint32_t stream_id;
    uint32_t previous_stream_id;
    char const* doc_name;
    char const* f_name;
    int is_binary;
} demo_stream_desc_t;

static const demo_stream_desc_t test_scenario[] = {
#ifdef PICOQUIC_TEST_AGAINST_ATS
    { 4, 0, "", "slash.html", 0 },
    { 8, 4, "en/latest/", "slash_en_slash_latest.html", 0 }
#else
#ifdef PICOQUIC_TEST_AGAINST_QUICKLY
    { 4, 0, "123.txt", "123.txt", 0 }
#else
    { 4, 0, "index.html", "index.html", 0 },
    { 8, 4, "test.html", "test.html", 0 },
    { 12, 4, "doc-123456.html", "doc-123456.html", 0 },
    { 16, 4, "main.jpg", "main.jpg", 1 },
    { 20, 4, "war-and-peace.txt", "war-and-peace.txt", 0 },
    { 24, 4, "en/latest/", "slash_en_slash_latest.html", 0 }
#endif
#endif
};

static const size_t test_scenario_nb = sizeof(test_scenario) / sizeof(demo_stream_desc_t);

static const uint8_t test_ping[] = { picoquic_frame_type_ping, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

typedef struct st_picoquic_first_client_stream_ctx_t {
    struct st_picoquic_first_client_stream_ctx_t* next_stream;
    uint32_t stream_id;
    uint8_t command[PICOQUIC_FIRST_COMMAND_MAX + 1]; /* starts with "GET " */
    size_t received_length;
    FILE* F; /* NULL if stream is closed. */
} picoquic_first_client_stream_ctx_t;

typedef struct st_picoquic_first_client_callback_ctx_t {
    demo_stream_desc_t const* demo_stream;
    size_t nb_demo_streams;

    struct st_picoquic_first_client_stream_ctx_t* first_stream;
    int nb_open_streams;
    uint32_t nb_client_streams;
    uint64_t last_interaction_time;
    int progress_observed;
} picoquic_first_client_callback_ctx_t;

static void demo_client_open_stream(picoquic_cnx_t* cnx,
    picoquic_first_client_callback_ctx_t* ctx,
    uint32_t stream_id, char const* text, size_t text_len, char const* fname, int is_binary)
{
    int ret = 0;

    picoquic_first_client_stream_ctx_t* stream_ctx = (picoquic_first_client_stream_ctx_t*)
        malloc(sizeof(picoquic_first_client_stream_ctx_t));

    if (stream_ctx == NULL) {
        fprintf(stdout, "Memory error!\n");
    } else {
        fprintf(stdout, "Opening stream %d to GET /%s\n", stream_id, text);

        memset(stream_ctx, 0, sizeof(picoquic_first_client_stream_ctx_t));
        stream_ctx->command[0] = 'G';
        stream_ctx->command[1] = 'E';
        stream_ctx->command[2] = 'T';
        stream_ctx->command[3] = ' ';
        stream_ctx->command[4] = '/';
        if (text_len > 0) {
            memcpy(&stream_ctx->command[5], text, text_len);
        }
        stream_ctx->command[text_len + 5] = '\r';
        stream_ctx->command[text_len + 6] = '\n';
        stream_ctx->command[text_len + 7] = 0;
        stream_ctx->stream_id = stream_id;

        stream_ctx->next_stream = ctx->first_stream;
        ctx->first_stream = stream_ctx;

#ifdef _WINDOWS
        if (fopen_s(&stream_ctx->F, fname, (is_binary == 0) ? "w" : "wb") != 0) {
            ret = -1;
        }
#else
        stream_ctx->F = fopen(fname, (is_binary == 0) ? "w" : "wb");
        if (stream_ctx->F == NULL) {
            ret = -1;
        }
#endif
        if (ret != 0) {
            fprintf(stdout, "Cannot create file: %s\n", fname);
        } else {
            ctx->nb_open_streams++;
            ctx->nb_client_streams++;
        }

        if (stream_ctx->stream_id == 1) {
            /* Horrible hack to test sending in three blocks */
            (void)picoquic_add_to_stream(cnx, stream_ctx->stream_id, stream_ctx->command,
                5, 0);
            (void)picoquic_add_to_stream(cnx, stream_ctx->stream_id, &stream_ctx->command[5],
                text_len, 0);
            (void)picoquic_add_to_stream(cnx, stream_ctx->stream_id, &stream_ctx->command[5 + text_len],
                2, 1);
        } else {
            (void)picoquic_add_to_stream(cnx, stream_ctx->stream_id, stream_ctx->command,
                text_len + 7, 1);
        }
    }
}

static void demo_client_start_streams(picoquic_cnx_t* cnx,
    picoquic_first_client_callback_ctx_t* ctx, uint64_t fin_stream_id)
{
    for (size_t i = 0; i < ctx->nb_demo_streams; i++) {
        if (ctx->demo_stream[i].previous_stream_id == fin_stream_id) {
            demo_client_open_stream(cnx, ctx, ctx->demo_stream[i].stream_id,
                ctx->demo_stream[i].doc_name, strlen(ctx->demo_stream[i].doc_name),
                ctx->demo_stream[i].f_name,
                ctx->demo_stream[i].is_binary);
        }
    }
}

static void first_client_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    uint64_t fin_stream_id = 0;

    picoquic_first_client_callback_ctx_t* ctx = (picoquic_first_client_callback_ctx_t*)callback_ctx;
    picoquic_first_client_stream_ctx_t* stream_ctx = ctx->first_stream;

    ctx->last_interaction_time = picoquic_current_time();
    ctx->progress_observed = 1;

    if (fin_or_event == picoquic_callback_close || fin_or_event == picoquic_callback_application_close) {
        if (fin_or_event == picoquic_callback_application_close) {
            fprintf(stdout, "Received a request to close the application.\n");
        } else {
            fprintf(stdout, "Received a request to close the connection.\n");
        }

        while (stream_ctx != NULL) {
            if (stream_ctx->F != NULL) {
                fclose(stream_ctx->F);
                stream_ctx->F = NULL;
                ctx->nb_open_streams--;

                fprintf(stdout, "On stream %d, command: %s stopped after %d bytes\n",
                    stream_ctx->stream_id, stream_ctx->command, (int)stream_ctx->received_length);
            }
            stream_ctx = stream_ctx->next_stream;
        }

        return;
    }

    /* if stream is already present, check its state. New bytes? */
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL || stream_ctx->F == NULL) {
        /* Unexpected stream. */
        picoquic_reset_stream(cnx, stream_id, 0);
        return;
    } else if (fin_or_event == picoquic_callback_stream_reset) {
        picoquic_reset_stream(cnx, stream_id, 0);

        if (stream_ctx->F != NULL) {
            char buf[256];

            fclose(stream_ctx->F);
            stream_ctx->F = NULL;
            ctx->nb_open_streams--;
            fin_stream_id = stream_id;

            fprintf(stdout, "Reset received on stream %d, command: %s, after %d bytes\n",
                stream_ctx->stream_id,
                strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command),
                (int)stream_ctx->received_length);
        }
        return;
    } else if (fin_or_event == picoquic_callback_stop_sending) {
        char buf[256];
        picoquic_reset_stream(cnx, stream_id, 0);

        fprintf(stdout, "Stop sending received on stream %d, command: %s\n",
            stream_ctx->stream_id,
            strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));
        return;
    } else {
        if (length > 0) {
            (void)fwrite(bytes, 1, length, stream_ctx->F);
            stream_ctx->received_length += length;
        }

        /* if FIN present, process request through http 0.9 */
        if (fin_or_event == picoquic_callback_stream_fin) {
            char buf[256];
            /* if data generated, just send it. Otherwise, just FIN the stream. */
            fclose(stream_ctx->F);
            stream_ctx->F = NULL;
            ctx->nb_open_streams--;
            fin_stream_id = stream_id;

            fprintf(stdout, "Received file %s, after %d bytes, closing stream %d\n",
                strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command[4]),
                (int)stream_ctx->received_length, stream_ctx->stream_id);
        }
    }

    if (fin_stream_id != 0) {
        demo_client_start_streams(cnx, ctx, fin_stream_id);
    }

    /* that's it */
}

void quic_client_launch_scenario(picoquic_cnx_t* cnx_client,
    picoquic_first_client_callback_ctx_t* callback_ctx)
{
    /* Start the download scenario */
    callback_ctx->demo_stream = test_scenario;
    callback_ctx->nb_demo_streams = test_scenario_nb;

    demo_client_start_streams(cnx_client, callback_ctx, 0);
}

#define PICOQUIC_DEMO_CLIENT_MAX_RECEIVE_BATCH 4

int quic_client(const char* ip_address_text, int server_port, uint32_t proposed_version, int force_zero_share, int mtu_max, FILE* F_log)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t* qclient = NULL;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_first_client_callback_ctx_t callback_ctx;
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
    int bytes_recv;
    int bytes_sent;
    picoquic_packet* p = NULL;
    uint64_t current_time = 0;
    int client_ready_loop = 0;
    int client_receive_loop = 0;
    int established = 0;
    int is_name = 0;
    const char* sni = NULL;
    int64_t delay_max = 10000000;
    int64_t delta_t = 0;
    int notified_ready = 0;
    const char* alpn = "hq-09";

    memset(&callback_ctx, 0, sizeof(picoquic_first_client_callback_ctx_t));

    ret = picoquic_get_server_address(ip_address_text, server_port, &server_address, &server_addr_length, &is_name);
    if (is_name != 0) {
        sni = ip_address_text;
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
        qclient = picoquic_create(8, NULL, NULL, alpn, NULL, NULL, NULL, NULL, NULL, current_time, NULL, ticket_store_filename, NULL, 0);

        if (qclient == NULL) {
            ret = -1;
        } else {
            if (force_zero_share) {
                qclient->flags |= picoquic_context_client_zero_share;
            }
            qclient->mtu_max = mtu_max;
        }
    }

    /* Create the client connection */
    if (ret == 0) {
        /* Create a client connection */
        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id,
            (struct sockaddr*)&server_address, current_time,
            proposed_version, sni, alpn, 1);

        if (cnx_client == NULL) {
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(cnx_client);

            if (ret == 0) {

                picoquic_set_callback(cnx_client, first_client_callback, &callback_ctx);


                p = picoquic_create_packet();

                if (p == NULL) {
                    ret = -1;
                }
                else {
                    ret = picoquic_prepare_packet(cnx_client, p, current_time,
                        send_buffer, sizeof(send_buffer), &send_length);

                    if (ret == 0 && send_length > 0) {
                        bytes_sent = sendto(fd, send_buffer, (int)send_length, 0,
                            (struct sockaddr*)&server_address, server_addr_length);

                        if (bytes_sent > 0)
                        {
                            picoquic_log_packet(F_log, qclient, cnx_client, (struct sockaddr*)&server_address,
                                0, send_buffer, bytes_sent, current_time);

                            if (picoquic_is_0rtt_available(cnx_client)) {
                                /* Queue a simple frame to perform 0-RTT test */
                                picoquic_queue_misc_frame(cnx_client, test_ping, sizeof(test_ping));
                            }
                        }
                        else {
                            fprintf(F_log, "Cannot send first packet to server, returns %d\n", bytes_sent);
                            ret = -1;
                        }
                    }
                    else {
                        free(p);
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

            if (bytes_recv > 0)
            {
                picoquic_log_packet(F_log, qclient, cnx_client, (struct sockaddr*)&packet_from,
                    1, buffer, bytes_recv, current_time);
            }
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

                if (ret == 0 && picoquic_get_cnx_state(cnx_client) == picoquic_state_client_ready) {
                    if (established == 0) {
                        picoquic_log_transport_extension(F_log, cnx_client, 0);
                        printf("Connection established.\n");
                        established = 1;
#if 1
                        /* Start the download scenario */
                        callback_ctx.demo_stream = test_scenario;
                        callback_ctx.nb_demo_streams = test_scenario_nb;

                        demo_client_start_streams(cnx_client, &callback_ctx, 0);
#endif
                    }

                    client_ready_loop++;

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
                    p = picoquic_create_packet();

                    if (p == NULL) {
                        ret = -1;
                    } else {
                        send_length = PICOQUIC_MAX_PACKET_SIZE;

                        ret = picoquic_prepare_packet(cnx_client, p, current_time,
                            send_buffer, sizeof(send_buffer), &send_length);

                        if (ret == 0 && send_length > 0) {
                            bytes_sent = sendto(fd, send_buffer, (int)send_length, 0,
                                (struct sockaddr*)&server_address, server_addr_length);
                            picoquic_log_packet(F_log, qclient, cnx_client, (struct sockaddr*)&server_address,
                                0, send_buffer, send_length, current_time);

                        } else {
                            free(p);
                        }
                    }
                }

                delta_t = picoquic_get_next_wake_delay(qclient, current_time, delay_max);
            }
        }
    }

    /* Clean up */
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
    fprintf(stderr, "  -c file               cert file (default: %s)\n", default_server_cert_file);
    fprintf(stderr, "  -k file               key file (default: %s)\n", default_server_key_file);
    fprintf(stderr, "  -p port               server port (default: %d)\n", default_server_port);
    fprintf(stderr, "  -1                    Once\n");
    fprintf(stderr, "  -r                    Do Reset Request\n");
    fprintf(stderr, "  -s <64b 64b>          Reset seed\n");
    fprintf(stderr, "  -i <src mask value>   Connection ID modification: (src & ~mask) || val\n");
    fprintf(stderr, "                        Implies unconditional server cnx_id xmit\n");
    fprintf(stderr, "                          where <src> is int:\n");
    fprintf(stderr, "                            0: picoquic_cnx_id_random\n");
    fprintf(stderr, "                            1: picoquic_cnx_id_remote (client)\n");
    fprintf(stderr, "  -v version            Version proposed by client, e.g. -v ff000009\n");
    fprintf(stderr, "  -z                    Set TLS zero share behavior on client, to force HRR.\n");
    fprintf(stderr, "  -l file               Log file\n");
    fprintf(stderr, "  -m mtu_max            Largest mtu value that can be tried for discovery\n");
    fprintf(stderr, "  -h                    This help message\n");
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
    cnx_id_callback_ctx_t* ctx = (cnx_id_callback_ctx_t*)cnx_id_callback_ctx;

    if (ctx->cnx_id_select == picoquic_cnx_id_remote)
        cnx_id_local = cnx_id_remote;

    /* TODO: replace with encrypted value when moving to 17 byte CID */
    cnx_id_returned->opaque64 = (cnx_id_local.opaque64 & ctx->cnx_id_mask.opaque64) | ctx->cnx_id_val.opaque64;
}

int main(int argc, char** argv)
{
    const char* server_name = default_server_name;
    const char* server_cert_file = default_server_cert_file;
    const char* server_key_file = default_server_key_file;
    const char* log_file = NULL;
    int server_port = default_server_port;
    uint32_t proposed_version = 0xFF000009;
    int is_client = 0;
    int just_once = 0;
    int do_hrr = 0;
    int force_zero_share = 0;
    int cnx_id_mask_is_set = 0;
    cnx_id_callback_ctx_t cnx_id_cbdata = {
        .cnx_id_select = 0,
        .cnx_id_mask.opaque64 = UINT64_MAX,
        .cnx_id_val.opaque64 = 0
    };
    uint64_t* reset_seed = NULL;
    uint64_t reset_seed_x[2];
    int mtu_max = 0;

#ifdef _WINDOWS
    WSADATA wsaData;
#endif
    int ret = 0;

    /* HTTP09 test */

    /* Get the parameters */
    int opt;
    while ((opt = getopt(argc, argv, "c:k:p:v:1rhzi:s:l:m:")) != -1) {
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
        case 'v':
            if (optind + 1 > argc) {
                fprintf(stderr, "option requires more arguments -- s\n");
                usage();
            }
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
            reset_seed = reset_seed_x; /* replacing the original alloca, which is not supported in Windows */
            reset_seed[1] = strtoul(argv[optind], NULL, 0);
            reset_seed[0] = strtoul(argv[optind++], NULL, 0);
            break;
        case 'i':
            if (optind + 2 > argc) {
                fprintf(stderr, "option requires more arguments -- i\n");
                usage();
            }

            cnx_id_cbdata.cnx_id_select = atoi(optarg);
            /* TODO: find an alternative to parsing a 64 bit integer */
            cnx_id_cbdata.cnx_id_mask.opaque64 = ~strtoul(argv[optind++], NULL, 0);
            cnx_id_cbdata.cnx_id_val.opaque64 = strtoul(argv[optind++], NULL, 0);
            cnx_id_mask_is_set = 1;
            break;
        case 'l':
            if (optind + 1 > argc) {
                fprintf(stderr, "option requires more arguments -- s\n");
                usage();
            }
            log_file = optarg;
            break;
        case 'm':
            mtu_max = atoi(optarg);
            if (mtu_max <= 0 || mtu_max > PICOQUIC_MAX_PACKET_SIZE) {
                fprintf(stderr, "Invalid max mtu: %s\n", optarg);
                usage();
            }
            break;
        case 'z':
            force_zero_share = 1;
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
        /* Run as server */
        printf("Starting PicoQUIC server on port %d, server name = %s, just_once = %d, hrr= %d\n",
            server_port, server_name, just_once, do_hrr);
        ret = quic_server(server_name, server_port,
            server_cert_file, server_key_file, just_once, do_hrr,
            /* TODO: find an alternative to using 64 bit mask. */
            (cnx_id_mask_is_set == 0) ? NULL : cnx_id_callback,
            (cnx_id_mask_is_set == 0) ? NULL : (void*)&cnx_id_cbdata,
            (uint8_t*)reset_seed, mtu_max);
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
        ret = quic_client(server_name, server_port, proposed_version, force_zero_share, mtu_max, F_log);

        printf("Client exit with code = %d\n", ret);

        if (F_log != NULL && F_log != stdout) {
            fclose(F_log);
        }
    }
}
