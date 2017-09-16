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

#ifdef WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <WinSock2.h>
#include <iphlpapi.h>
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
#define WSA_LAST_ERROR(x)  WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif 

#else

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
/* #include <unistd.h> */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <errno.h>

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

#endif


#include "../picoquic/picoquic.h"
void picoquic_log_error_packet(FILE * F, uint8_t * bytes, size_t bytes_max, int ret);

void picoquic_log_packet(FILE* F, picoquic_quic_t * quic, picoquic_cnx_t * cnx,
	struct sockaddr * addr_peer, int receiving,
	uint8_t * bytes, size_t length, uint64_t current_time);
void picoquic_log_processing(FILE* F, picoquic_cnx_t * cnx, size_t length, int ret);
void picoquic_log_transport_extension(FILE* F, picoquic_cnx_t * cnx);

void print_address(struct sockaddr * address, int address_length, char * label)
{
    char hostname[256];
    char servInfo[256];

    int ret  = getnameinfo(address, address_length,
        hostname, 256, servInfo, 256, NI_NUMERICSERV);

    if (ret == 0) {
        printf("%s %s:%s\n", label, hostname, servInfo);
    }
    else
    {
        const char * x = inet_ntop(address->sa_family, address, hostname, sizeof(hostname));

        if (x != NULL)
        {
            printf("%s %s\n", label, x);
        }
        else
        {
            ret = -1;
            printf("inet_ntop failed with error # %ld\n", WSA_LAST_ERROR(errno));
        }
    }
}

int bind_to_port(SOCKET_TYPE fd, int af, int port)
{
    struct sockaddr_storage sa;
    int addr_length = 0;

    memset(&sa, 0, sizeof(sa));

    if (af == AF_INET)
    {
        struct sockaddr_in * s4 = (struct sockaddr_in *)&sa;

        s4->sin_family = af;
        s4->sin_port = htons(port);
        addr_length = sizeof(struct sockaddr_in);
    }
    else
    {
        struct sockaddr_in6 * s6 = (struct sockaddr_in6 *)&sa;

        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons(port);
        addr_length = sizeof(struct sockaddr_in6);
    }

    return bind(fd, (struct sockaddr *) &sa, addr_length);
}

#ifdef WIN32
#define PICOQUIC_NB_SERVER_SOCKETS 2
#else
#define PICOQUIC_NB_SERVER_SOCKETS 1
#endif
typedef struct st_picoquic_server_sockets_t {
    SOCKET_TYPE s_socket[PICOQUIC_NB_SERVER_SOCKETS];
} picoquic_server_sockets_t;

int picoquic_open_server_sockets(picoquic_server_sockets_t * sockets, int port)
{
    int ret = 0;
    const int sock_af[] = { AF_INET6, AF_INET };

    for (int i = 0; i < PICOQUIC_NB_SERVER_SOCKETS; i++)
    {
        if (ret == 0)
        {
            sockets->s_socket[i] = socket(sock_af[i], SOCK_DGRAM, IPPROTO_UDP);
        }
        else
        {
            sockets->s_socket[i] = INVALID_SOCKET;
        }

        if (sockets->s_socket[i] == INVALID_SOCKET)
        {
            ret = -1;
        }
        else
        {
            ret = bind_to_port(sockets->s_socket[i], sock_af[i], port);
        }
    }

    return ret;
}

void picoquic_close_server_sockets(picoquic_server_sockets_t * sockets)
{
    for (int i = 0; i < PICOQUIC_NB_SERVER_SOCKETS; i++)
    {
        if (sockets->s_socket[i] != INVALID_SOCKET)
        {
            SOCKET_CLOSE(sockets->s_socket[i]);
            sockets->s_socket[i] = INVALID_SOCKET;
        }
    }
}

uint64_t get_current_time()
{
    uint64_t now;
#ifdef WIN32
    FILETIME ft;
    /*
    * The GetSystemTimeAsFileTime API returns  the number
    * of 100-nanosecond intervals since January 1, 1601 (UTC),
    * in FILETIME format.
    */
    GetSystemTimeAsFileTime(&ft);

    /*
    * Convert to plain 64 bit format, without making
    * assumptions about the FILETIME structure alignment.
    */
    now |= ft.dwHighDateTime;
    now <<= 32;
    now |= ft.dwLowDateTime;
    /*
    * Convert units from 100ns to 1us
    */
    now /= 10;
    /*
    * Account for microseconds elapsed between 1601 and 1970.
    */
    now -= 11644473600000000ULL;
#else
    (void) gettimeofday(&tv, NULL);
    now = (tv.tv_sec * 1000000ull) + tv.tv_usec;
#endif
    return now;
}

int do_select(SOCKET_TYPE * sockets, int nb_sockets,
    struct sockaddr_storage * addr_from,
    socklen_t * from_length,
    uint8_t * buffer, int buffer_max,
    int is_active,
    uint64_t * current_time)
{

    fd_set   readfds;
    struct timeval tv;
    int ret_select = 0;
    int bytes_recv = 0;
    int sockmax = 0;

    FD_ZERO(&readfds);

    for (int i = 0; i < nb_sockets; i++)
    {
        if (sockmax < (int) sockets[i])
        {
            sockmax = sockets[i];
        }
        FD_SET(sockets[i], &readfds);
    }

    if (is_active)
    {
        tv.tv_sec = 0;
        tv.tv_usec = 100;
    }
    else
    {
        tv.tv_sec = 1;
        tv.tv_usec = 0;
    }

    ret_select = select(sockmax+1, &readfds, NULL, NULL, &tv);

    if (ret_select < 0)
    {
        bytes_recv = -1;
        if (bytes_recv <= 0)
        {
            fprintf(stderr, "Error: select returns %d\n", ret_select);
        }
    }
    else if (ret_select > 0)
    {
        for (int i = 0; i < nb_sockets; i++)
        {
            if (FD_ISSET(sockets[i], &readfds))
            {
                /* Read the incoming response */
                *from_length = sizeof(struct sockaddr_storage);
                bytes_recv = recvfrom(sockets[i], (char*)buffer, buffer_max, 0,
                    (struct sockaddr *)addr_from, from_length);

                if (bytes_recv <= 0)
                {
#ifdef WIN32
                    int last_error = WSAGetLastError();

                    if (last_error == WSAECONNRESET)
                    {
                        bytes_recv = 0;
                        continue;
                    }
#endif
                    fprintf(stderr, "Could not receive packet on UDP socket[%d]= %d!\n",
                        i, (int) sockets[i]);
                    break;
                }
                else
                {
                    break;
                }
            }
        }
    }

    *current_time = get_current_time();

    return bytes_recv;
}

int send_to_server_sockets(
    picoquic_server_sockets_t * sockets, 
    struct sockaddr * addr_dest, socklen_t addr_length,
    const char * bytes, int length)
{
    /* Linux uses a single socket for V6 and V4, Windows uses 2 */
#ifdef WIN32
    int socket_index = (addr_dest->sa_family == AF_INET) ? 1 : 0;
#else
    const int socket_index = 0;
#endif

    int sent = sendto(sockets->s_socket[socket_index], bytes, length, 0,
        addr_dest, addr_length);

    return sent;
}

#define PICOQUIC_FIRST_COMMAND_MAX 128
#define PICOQUIC_FIRST_RESPONSE_MAX (1<<20)

typedef enum
{
    picoquic_first_server_stream_status_none = 0,
    picoquic_first_server_stream_status_receiving,
    picoquic_first_server_stream_status_finished
} picoquic_first_server_stream_status_t;

typedef struct st_picoquic_first_server_stream_ctx_t {
    struct st_picoquic_first_server_stream_ctx_t * next_stream;
    picoquic_first_server_stream_status_t status;
    uint32_t stream_id;
    size_t command_length;
    size_t response_length;
    uint8_t command[PICOQUIC_FIRST_COMMAND_MAX];
} picoquic_first_server_stream_ctx_t;

typedef struct st_picoquic_first_server_callback_ctx_t {
    picoquic_first_server_stream_ctx_t * first_stream;
    size_t buffer_max;
    uint8_t * buffer;
} picoquic_first_server_callback_ctx_t;

static picoquic_first_server_callback_ctx_t * first_server_callback_create_context()
{
    picoquic_first_server_callback_ctx_t * ctx =
        (picoquic_first_server_callback_ctx_t*)
        malloc(sizeof(picoquic_first_server_callback_ctx_t));

    if (ctx != NULL)
    {
        ctx->first_stream = NULL;
        ctx->buffer = (uint8_t *)malloc(PICOQUIC_FIRST_RESPONSE_MAX);
        if (ctx->buffer == NULL)
        {
            free(ctx);
            ctx = NULL;
        }
        else
        {
            ctx->buffer_max = PICOQUIC_FIRST_RESPONSE_MAX;
        }
    }

    return ctx;
}

static void first_server_callback_delete_context(picoquic_first_server_callback_ctx_t * ctx)
{
    picoquic_first_server_stream_ctx_t * stream_ctx;

    while ((stream_ctx = ctx->first_stream) != NULL)
    {
        ctx->first_stream = stream_ctx->next_stream;
        free(stream_ctx);
    }

    free(ctx);
}

static void first_server_callback(picoquic_cnx_t * cnx,
    uint32_t stream_id, uint8_t * bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void * callback_ctx)
{
    picoquic_first_server_callback_ctx_t * ctx =
        (picoquic_first_server_callback_ctx_t*)callback_ctx;
    picoquic_first_server_stream_ctx_t * stream_ctx = NULL;

    if (fin_or_event == picoquic_callback_close)
    {
        if (ctx != NULL)
        {
            first_server_callback_delete_context(ctx);
            picoquic_set_callback(cnx, first_server_callback, NULL);
        }

        return;
    }

    if (ctx == NULL)
    {
        picoquic_first_server_callback_ctx_t * new_ctx =
            first_server_callback_create_context();
        if (new_ctx == NULL)
        {
            /* cannot handle the connection */
            picoquic_close(cnx);
            return;
        }
        else
        {
            picoquic_set_callback(cnx, first_server_callback, new_ctx);
            ctx = new_ctx;
        }
    }

    stream_ctx = ctx->first_stream;

    /* if stream is already present, check its state. New bytes? */
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id)
    {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL)
    {
        stream_ctx = (picoquic_first_server_stream_ctx_t *)
            malloc(sizeof(picoquic_first_server_stream_ctx_t));
        if (stream_ctx == NULL)
        {
            /* Could not handle this stream */
            picoquic_reset_stream(cnx, stream_id);
            return;
        }
        else
        {
            memset(stream_ctx, 0, sizeof(picoquic_first_server_stream_ctx_t));
            stream_ctx->next_stream = ctx->first_stream;
            ctx->first_stream = stream_ctx;
        }
    }

    /* verify state and copy data to the stream buffer */
    if (fin_or_event == picoquic_callback_stream_reset)
    {
        stream_ctx->status = picoquic_first_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id);
        return;
    }
    else if (stream_ctx->status == picoquic_first_server_stream_status_finished ||
        stream_ctx->command_length + length > PICOQUIC_FIRST_COMMAND_MAX)
    {
        /* send after fin, or too many bytes => reset! */
        picoquic_reset_stream(cnx, stream_id);
        return;
    }
    else
    {
        if (length > 0)
        {
            memcpy(&stream_ctx->command[stream_ctx->command_length],
                bytes, length);
            stream_ctx->command_length += length;
        }

        /* if FIN present, process request through http 0.9 */
        if (fin_or_event == picoquic_callback_stream_fin)
        {
            /* if data generated, just send it. Otherwise, just FIN the stream. */
            stream_ctx->status = picoquic_first_server_stream_status_finished;
            if (http0dot9_get(stream_ctx->command, stream_ctx->command_length,
                ctx->buffer, ctx->buffer_max, &stream_ctx->response_length) != 0)
            {
                picoquic_reset_stream(cnx, stream_id);
            }
            else
            {
                picoquic_add_to_stream(cnx, stream_id, ctx->buffer,
                    stream_ctx->response_length, 1);
            }
        }
    }

    /* that's it */
}

int quic_server(char * server_name, int server_port, 
    char * pem_cert, char * pem_key, int just_once)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t *qserver = NULL;
    picoquic_cnx_t *cnx_server = NULL;
    picoquic_cnx_t *cnx_next = NULL;
    picoquic_server_sockets_t server_sockets;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage client_from;
    socklen_t from_length;
    int client_addr_length;
    uint8_t buffer[1536];
	uint8_t send_buffer[1536];
	size_t send_length = 0;
    int bytes_recv;
    picoquic_packet * p = NULL;
	uint64_t current_time = 0;
	picoquic_stateless_packet_t * sp;
    int is_active = 0;

    /* Open a UDP socket */
    ret = picoquic_open_server_sockets(&server_sockets, server_port);

    /* Wait for packets and process them */
    if (ret == 0)
    {
        /* Create QUIC context */
        qserver = picoquic_create(8, pem_cert, pem_key, NULL, first_server_callback, NULL);

        if (qserver == NULL)
        {
            fprintf(stderr, "Could not create server context\n");
            ret = -1;
        }
    }

    /* Wait for packets */
    while (ret == 0 && (just_once == 0 || cnx_server == NULL ||
        picoquic_get_cnx_state(cnx_server)!= picoquic_state_disconnected))
    {
        bytes_recv = do_select(server_sockets.s_socket, PICOQUIC_NB_SERVER_SOCKETS,
            &addr_from, &from_length,
            buffer, sizeof(buffer), is_active, &current_time);

        if (bytes_recv != 0)
        {
            printf("Select returns %d, from length %d\n", bytes_recv, from_length);
            print_address((struct sockaddr *)&addr_from, from_length, "recv from:");
        }

        if (bytes_recv < 0)
        {
            ret = -1;
        }
        else
        {
            if (bytes_recv > 0)
            {
                current_time += 1000;

                /* Submit the packet to the server */
                ret = picoquic_incoming_packet(qserver, buffer,
                    (size_t)bytes_recv, (struct sockaddr *) &addr_from, current_time);

                if (ret != 0)
                {
                    ret = 0;
                }


                if (cnx_server != picoquic_get_first_cnx(qserver) &&
                    picoquic_get_first_cnx(qserver) != NULL)
                {
                    printf("Connection established, state = %d, from length: %d\n",
                        picoquic_get_cnx_state(picoquic_get_first_cnx(qserver)), from_length);
                    cnx_server = picoquic_get_first_cnx(qserver);
                    memset(&client_from, 0, sizeof(client_from));
                    memcpy(&client_from, &addr_from, from_length);
                    client_addr_length = from_length;
                    print_address((struct sockaddr*)&client_from, client_addr_length,
                        "Client address:");
                    picoquic_log_transport_extension(stdout, cnx_server);
                }
            }

            if (ret == 0)
            {
                is_active = 0;

                while ((sp = picoquic_dequeue_stateless_packet(qserver)) != NULL)
                {
                    int sent = send_to_server_sockets(&server_sockets,
                        (struct sockaddr *) &addr_from, from_length,
                        (const char *)sp->bytes, (int)sp->length);

                    printf("Sending stateless packet, %d bytes\n", sent);
                    picoquic_delete_stateless_packet(sp);
                    is_active = 1;
                }

                cnx_next = picoquic_get_first_cnx(qserver);
                while (ret == 0 && cnx_next != NULL)
                {
                    p = picoquic_create_packet();

                    if (p == NULL)
                    {
                        ret = -1;
                    }
                    else
                    {
                        ret = picoquic_prepare_packet(cnx_next, p, current_time,
                            send_buffer, sizeof(send_buffer), &send_length);

                        if (ret == PICOQUIC_ERROR_DISCONNECTED)
                        {
                            ret = 0;
                            free(p);
                            picoquic_delete_cnx(cnx_next);
                            is_active = 1;
                            break;
                        }
                        else if (ret == 0)
                        {
                            int peer_addr_len = 0;
                            struct sockaddr * peer_addr;

                            printf("Connection state = %d\n",
                                picoquic_get_cnx_state(cnx_next));
                            if (p->length > 0)
                            {

                                picoquic_get_peer_addr(cnx_next, &peer_addr, &peer_addr_len);

                                int sent = send_to_server_sockets(&server_sockets,
                                    peer_addr, peer_addr_len,
                                    (const char *)send_buffer, (int)send_length);
                                printf("Sending packet, %d bytes (sent: %d)\n",
                                    (int)send_length, sent);
                                is_active = 1;
                            }
                            else
                            {
                                free(p);
                            }
                        }
                        else
                        {
                            break;
                        }

                        cnx_next = picoquic_get_next_cnx(cnx_next);
                    }
                }
            }
        }
    }

    /* Clean up */
    if (qserver != NULL)
    {
        picoquic_free(qserver);
    }

    picoquic_close_server_sockets(&server_sockets);

    return ret;
}

typedef struct st_picoquic_first_client_stream_ctx_t {
    struct st_picoquic_first_client_stream_ctx_t * next_stream;
    uint32_t stream_id;
    uint8_t command[PICOQUIC_FIRST_COMMAND_MAX+1]; /* starts with "GET " */
    size_t received_length;
    FILE* F; /* NULL if stream is closed. */
} picoquic_first_client_stream_ctx_t;

typedef struct st_picoquic_first_client_callback_ctx_t {
    struct st_picoquic_first_client_stream_ctx_t * first_stream;
    int nb_open_streams;
    uint32_t nb_client_streams;
    uint64_t last_interaction_time;
    int progress_observed;
} picoquic_first_client_callback_ctx_t;

static void first_client_callback(picoquic_cnx_t * cnx,
    uint32_t stream_id, uint8_t * bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void * callback_ctx)
{
    picoquic_first_client_callback_ctx_t * ctx =
        (picoquic_first_client_callback_ctx_t*)callback_ctx;
    picoquic_first_client_stream_ctx_t * stream_ctx = ctx->first_stream;

    ctx->progress_observed = 1;

    if (fin_or_event == picoquic_callback_close)
    {
        fprintf(stdout, "Received a request to close the connection.\n");

        while (stream_ctx != NULL)
        {
            if (stream_ctx->F != NULL)
            {
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
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id)
    {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL || stream_ctx->F == NULL)
    {
        /* Unexpected stream. */
        picoquic_reset_stream(cnx, stream_id);
        return;
    }
    else if (fin_or_event == picoquic_callback_stream_reset)
    {
        picoquic_reset_stream(cnx, stream_id);
        if (stream_ctx->F != NULL)
        {
            fclose(stream_ctx->F);
            stream_ctx->F = NULL;
            ctx->nb_open_streams--;

            fprintf(stdout, "Reset received on stream %d, command: %s, after %d bytes\n",
                stream_ctx->stream_id, stream_ctx->command, (int)stream_ctx->received_length);
        }
        return;
    }
    else
    {
        if (length > 0)
        {
            (void)fwrite(bytes, 1, length, stream_ctx->F);
            stream_ctx->received_length += length;
        }

        /* if FIN present, process request through http 0.9 */
        if (fin_or_event == picoquic_callback_stream_fin)
        {
            /* if data generated, just send it. Otherwise, just FIN the stream. */
            fclose(stream_ctx->F);
            stream_ctx->F = NULL;
            ctx->nb_open_streams--;

            fprintf(stdout, "Received file %s, after %d bytes, closing stream %d\n",
                &stream_ctx->command[4], (int)stream_ctx->received_length, stream_ctx->stream_id);
        }
    }

    /* that's it */
}

int quic_client_ui(picoquic_cnx_t * cnx, picoquic_first_client_callback_ctx_t * ctx,
    uint64_t * current_time)
{
    int ret = 0;
    char text[PICOQUIC_FIRST_COMMAND_MAX];
    size_t text_len = 0;
    picoquic_first_client_stream_ctx_t * stream_ctx;
    int nb_doc_added = 0;

    for (;;) {
        fprintf(stdout, "Enter the requested document name, or return:\n");
        if (fgets(text, sizeof(text), stdin))
        {
            /* remove trailing blanks */
            text_len = strlen(text);
            while (text_len >= 1)
            {
                int c = text[text_len - 1];

                if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
                {
                    text_len--;
                    text[text_len] = 0;
                }
                else
                {
                    break;
                }
            }
        }
        else
        {
            text[0] = 0;
            text_len = 0;
        }

        if (text_len == 0)
        {
            break;
        }
        else if (text_len + 7 > PICOQUIC_FIRST_COMMAND_MAX)
        {
            fprintf(stdout, "Name too long!\n");
        }
        else
        {
            stream_ctx = (picoquic_first_client_stream_ctx_t *)
                malloc(sizeof(picoquic_first_client_stream_ctx_t));
            if (stream_ctx == NULL)
            {
                fprintf(stdout, "Memory error!\n");
                break;
            }
            else
            {
                memset(stream_ctx, 0, sizeof(picoquic_first_client_stream_ctx_t));
                stream_ctx->command[0] = 'G';
                stream_ctx->command[1] = 'E';
                stream_ctx->command[2] = 'T';
                stream_ctx->command[3] = ' ';
                memcpy(&stream_ctx->command[4], text, text_len);
                stream_ctx->command[text_len + 4] = '\r';
                stream_ctx->command[text_len + 5] = '\n';
                stream_ctx->command[text_len + 6] = 0;
                stream_ctx->stream_id = (ctx->nb_client_streams * 2) + 1;

                stream_ctx->next_stream = ctx->first_stream;
                ctx->first_stream = stream_ctx;


#ifdef WIN32
                if (fopen_s(&stream_ctx->F, text, "w") != 0) {
                    ret = -1;
                }
#else
                stream_ctx->F = fopen(text, "w");
                if (stream_ctx->F == NULL) {
                    ret = -1;
                }
#endif
                if (ret != 0)
                {
                    fprintf(stdout, "Cannot create file: %s\n", text);
                }
                else
                {
                    ctx->nb_client_streams++;
                    ctx->nb_open_streams++;
                }

                (void) picoquic_add_to_stream(cnx, stream_ctx->stream_id, stream_ctx->command,
                    text_len + 6, 1);
                nb_doc_added++;
            }
        }
    }

    *current_time = get_current_time();
    ctx->last_interaction_time = *current_time;
    ctx->progress_observed = 0;

    if (nb_doc_added == 0)
    {

        fprintf(stdout, "Closing the connection.\n");
        ret = picoquic_close(cnx);
    }

    return ret;
}

int quic_client(char * ip_address_text, int server_port)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic_t *qclient = NULL;
    picoquic_cnx_t *cnx_client = NULL;
    picoquic_first_client_callback_ctx_t callback_ctx;
    SOCKET_TYPE fd = INVALID_SOCKET;
    struct sockaddr_storage server_address;
    struct sockaddr_in * ipv4_dest = (struct sockaddr_in *)&server_address;
    struct sockaddr_in6 * ipv6_dest = (struct sockaddr_in6 *)&server_address;
    struct sockaddr_storage packet_from;
    socklen_t from_length;
    int server_addr_length = 0;
    uint8_t buffer[1536];
	uint8_t send_buffer[1536];
	size_t send_length = 0;
    int bytes_recv;
    int bytes_sent;
    picoquic_packet * p = NULL;
	uint64_t current_time = 0;
	int client_ready_loop = 0;
    int established = 0;
    char * sni = NULL;
    int is_active = 0;

    memset(&callback_ctx, 0, sizeof(picoquic_first_client_callback_ctx_t));

    /* get the IP address of the server */
    if (ret == 0)
    {
        memset(&server_address, 0, sizeof(server_address));

        if (inet_pton(AF_INET, ip_address_text, &ipv4_dest->sin_addr) == 1)
        {
            /* Valid IPv4 address */
            ipv4_dest->sin_family = AF_INET;
            ipv4_dest->sin_port = htons(server_port);
            server_addr_length = sizeof(struct sockaddr_in);
        }
        else
       
        if (inet_pton(AF_INET6, ip_address_text, &ipv6_dest->sin6_addr) == 1)
        {
            /* Valid IPv6 address */
            ipv6_dest->sin6_family = AF_INET6;
            ipv6_dest->sin6_port = htons(server_port);
            server_addr_length = sizeof(struct sockaddr_in6);
        }
        else
        {
            /* Server is described by name. Do a lookup for the IP address,
             * and then use the name as SNI parameter */
            struct addrinfo *result = NULL;
            struct addrinfo hints;

            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;

            if (getaddrinfo(ip_address_text, NULL, &hints, &result) != 0)
            {
                fprintf(stderr, "Cannot get IP address for %s\n", ip_address_text);
                ret = -1;
            }
            else
            {
                sni = ip_address_text;

                switch (result->ai_family)
                {
                case AF_INET:
                    ipv4_dest->sin_family = AF_INET;
                    ipv4_dest->sin_port = htons(server_port);
#ifdef WIN32
                    ipv4_dest->sin_addr.S_un.S_addr =
                        ((struct sockaddr_in *) result->ai_addr)->sin_addr.S_un.S_addr;
#else
                    ipv4_dest->sin_addr.s_addr =
                        ((struct sockaddr_in *) result->ai_addr)->sin_addr.s_addr;
#endif
                   server_addr_length = sizeof(struct sockaddr_in);
                    break;
                case AF_INET6:
                    ipv6_dest->sin6_family = AF_INET6;
                    ipv6_dest->sin6_port = htons(server_port);
                    memcpy(&ipv6_dest->sin6_addr,
                        &((struct sockaddr_in6 *) result->ai_addr)->sin6_addr,
                        sizeof(ipv6_dest->sin6_addr));
                    break;
                default:
                    fprintf(stderr, "Error getting IPv6 address for %s, family = %d\n",
                        ip_address_text, result->ai_family);
                    ret = -1;
                    break;
                }

                freeaddrinfo(result);
            }
        }
    }

    /* Open a UDP socket */

    if (ret == 0)
    {
        fd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
        if (fd == INVALID_SOCKET)
        {
            ret = -1;
        }

    }

    /*
    if (ret == 0)
    {
        ret = bind_to_port(fd, server_address.ss_family, server_port + 1);
    }
    */

    /* Create QUIC context */
    current_time = get_current_time();

    if (ret == 0)
    {
        qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL);

        if (qclient == NULL)
        {
            ret = -1;
        }
    }

    /* Create the client connection */
    if (ret == 0)
    {
        /* Create a client connection */

        cnx_client = picoquic_create_cnx(qclient, 0, 
            (struct sockaddr *)&server_address, current_time, 0, sni, "hq-05");

        if (cnx_client == NULL)
        {
            ret = -1;
        }
		else
		{
            picoquic_set_callback(cnx_client, first_client_callback, &callback_ctx);

			p = picoquic_create_packet();

			if (p == NULL)
			{
				ret = -1;
			}
			else
			{
				ret = picoquic_prepare_packet(cnx_client, p, current_time,
					send_buffer, sizeof(send_buffer), &send_length);

				if (ret == 0 && send_length > 0)
				{
					bytes_sent = sendto(fd, send_buffer, send_length, 0,
						(struct sockaddr *) &server_address, server_addr_length);

					picoquic_log_packet(stdout, qclient, cnx_client, (struct sockaddr *) &server_address,
						0, send_buffer, bytes_sent, current_time);
				}
				else
				{
					free(p);
				}
			}
		}
    }

    /* Wait for packets */
    while (ret == 0 &&
        picoquic_get_cnx_state(cnx_client) != picoquic_state_disconnected)
    {
        bytes_recv = do_select(&fd, 1, &packet_from, &from_length,
            buffer, sizeof(buffer), is_active, &current_time);

        if (bytes_recv != 0)
        {
            printf("Select returns %d, from length %d\n", bytes_recv, from_length);

			picoquic_log_packet(stdout, qclient, cnx_client, (struct sockaddr *) &packet_from,
				1, buffer, bytes_recv, current_time);
        }

        if (bytes_recv < 0)
        {
            ret = -1;
        }
        else
        {
            if (bytes_recv > 0)
            {
                /* Submit the packet to the client */
                ret = picoquic_incoming_packet(qclient, buffer,
                    (size_t)bytes_recv, (struct sockaddr *) &packet_from, current_time);

				picoquic_log_processing(stdout, cnx_client, bytes_recv, ret);

				if (picoquic_get_cnx_state(cnx_client) == picoquic_state_client_almost_ready)
				{
					fprintf(stdout, "Almost ready!\n\n");
				}

				if (ret != 0)
				{
					picoquic_log_error_packet(stdout, buffer, (size_t)bytes_recv, ret);
				}
            }

			if (ret == 0 && picoquic_get_cnx_state(cnx_client) == picoquic_state_client_ready)
			{
                if (established == 0)
                {
                    picoquic_log_transport_extension(stdout, cnx_client);
                    printf("Connection established.\n");
                    established = 1;
                }

                client_ready_loop++;

                if ((bytes_recv == 0 || client_ready_loop > 4) &&
                    picoquic_is_cnx_backlog_empty(cnx_client))
                {
                    if (callback_ctx.nb_open_streams == 0)
                    {
                        ret = quic_client_ui(cnx_client, &callback_ctx, &current_time);
                        client_ready_loop = 0;
                    }
                    else if (callback_ctx.progress_observed != 0)
                    {
                        callback_ctx.last_interaction_time = current_time;
                        callback_ctx.progress_observed = 0;
                    }
                    else if (current_time - callback_ctx.last_interaction_time >
                        10000000ull)
                    {
                        fprintf(stdout, "No progress for 10 seconds.\n");

                        ret = quic_client_ui(cnx_client, &callback_ctx, &current_time);
                        client_ready_loop = 0;
                    }
                }
			}

            if (ret == 0)
            {
                p = picoquic_create_packet();

                if (p == NULL)
                {
                    ret = -1;
                }
                else
                {
					send_length = 1000000;

                    ret = picoquic_prepare_packet(cnx_client, p, current_time, 
						send_buffer, sizeof(send_buffer), &send_length);

					if (ret == 0 && send_length > 0)
					{
						bytes_sent = sendto(fd, send_buffer, send_length, 0,
							(struct sockaddr *) &server_address, server_addr_length);
						picoquic_log_packet(stdout, qclient, cnx_client, (struct sockaddr *)  &server_address,
								0, send_buffer, send_length, current_time);

                        is_active = 1;
					}
					else
					{
						free(p);
                    }
                }
            }
        }
    }

    /* Clean up */
    if (qclient != NULL)
    {
        picoquic_free(qclient);
    }

    if (fd != INVALID_SOCKET)
    {
        SOCKET_CLOSE(fd);
    }

    return ret;
}

int main(int argc, char ** argv)
{
    char * server_name = (char *) "::";
    char * server_cert_file = (char *) "..\\certs\\cert.pem";
    char * server_key_file = (char *) "..\\certs\\key.pem";
    int server_port = 4443;
    int is_client = 1;
    int just_once = 0;
#ifdef WIN32
    WSADATA wsaData;
#endif
    int ret = 0;

    /* HTTP09 test */

    /* Get the parameters */
    if (argc > 1)
    {
        server_name = argv[1];

        if (argc > 2)
        {
            server_port = atoi(argv[2]);

            if (server_port <= 0)
            {
                fprintf(stderr, "Invalid port: %s\n", argv[2]);
                ret = -1;
            }
            else if (argc > 3)
            {
                is_client = 0;
                server_cert_file = argv[3];

                if (argc > 4)
                {
                    server_key_file = argv[4];

                    if (argc > 5)
                    {
                        just_once = 1;
                    }
                }
            }
        }
    }

#ifdef WIN32
    // Init WSA.
    if (ret == 0)
    {
        if (WSA_START(MAKEWORD(2, 2), &wsaData)) {
            fprintf(stderr, "Cannot init WSA\n");
            ret = -1;
        }
    }
#endif

    if (is_client == 0)
    {
        /* Run as server */
        printf("Starting PicoQUIC server on port %d, server name = %s, just_once = %d\n", 
            server_port, server_name, just_once);
        ret = quic_server(server_name, server_port, 
            server_cert_file, server_key_file, just_once);
        printf("Server exit with code = %d\n", ret);
    }
    else
    {
        /* Run as client */
        printf("Starting PicoQUIC contection to server IP = %s, port = %d\n", server_name, server_port);
        ret = quic_client(server_name, server_port);

        printf("Client exit with code = %d\n", ret);
    }
}
