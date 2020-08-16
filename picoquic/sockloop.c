/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

/* Socket loop implements the "wait for messages" loop common to most servers
 * and many clients.
 *
 * First step: do this as a straight copy of the code in picoquic demo.
 *
 * The "call loop back" function is called: when readdy, after receiving, and after sending. The
 * loop will terminate if the callback return code is not zero.
 *
 * TODO: get a client socket option (sample client)
 * TODO: rewrite the demo client???
 * TODO: in Windows, use WSA asynchronous calls instead of sendmsg, allowing for multiple parallel sends.
 * TODO: in Linux, use multiple send per call API
 * TDOO: trim the #define list.
 * TODO: support the QuicDoq scenario, manage extra socket.
 */

#ifdef _WINDOWS
#define WIN32_LEAN_AND_MEAN
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
#ifndef WSA_LAST_ERROR
#define WSA_LAST_ERROR(x) WSAGetLastError()
#endif
#ifndef socklen_t
#define socklen_t int
#endif

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
#endif

#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"

int picoquic_packet_loop(picoquic_quic_t * quic,
    int server_port,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t buffer[1536];
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    int bytes_recv;
    uint64_t loop_count_time = current_time;
    int nb_loops = 0;
    picoquic_connection_id_t log_cid;
    picoquic_server_sockets_t server_sockets;

    /* Open the sockets */
    ret = picoquic_open_server_sockets(&server_sockets, server_port);
    if (ret == 0) {
        printf("Server ready on port %d\n", server_port);
    }

    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    while (ret == 0) {
        int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
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
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);
            picoquic_log_context_free_app_message(quic, &log_cid, "Looped %d times in %llu microsec, file: %d, line: %d",
                nb_loops, (unsigned long long) loop_delta, quic->wake_file, quic->wake_line);

            nb_loops = 0;
        }

        if (bytes_recv < 0) {
            ret = -1;
        }
        else {
            uint64_t loop_time = current_time;

            if (bytes_recv > 0) {
                /* Submit the packet to the server */
                (void)picoquic_incoming_packet(quic, buffer,
                    (size_t)bytes_recv, (struct sockaddr*) & addr_from,
                    (struct sockaddr*) & addr_to, if_index_to, received_ecn,
                    current_time);

                if (loop_callback != NULL) {
                    ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx);
                }
            }

            while (ret == 0 ) {
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr;
                picoquic_cnx_t* last_cnx;
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;

                ret = picoquic_prepare_next_packet(quic, loop_time,
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
                            picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, sock_ret, sock_err);
                        }
                    }
                }
                else {
                    break;
                }
            }

            if (ret == 0 && loop_callback != NULL) {
                ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx);
            }
        }
    }

    /* Close the sockets */
    picoquic_close_server_sockets(&server_sockets);

    return ret;
}