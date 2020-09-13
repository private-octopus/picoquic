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
 * Second step: support simple servers and simple client.
 *
 * The "call loop back" function is called: when ready, after receiving, and after sending. The
 * loop will terminate if the callback return code is not zero -- except for special processing
 * of the migration testing code.
 * TODO: in Windows, use WSA asynchronous calls instead of sendmsg, allowing for multiple parallel sends.
 * TODO: in Linux, use multiple send per call API
 * TDOO: trim the #define list.
 * TODO: support the QuicDoq scenario, manage extra socket.
 */

#ifndef _WINDOWS
#include "picoquic_packet_loop.h"

int picoquic_packet_loop_win(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    return -1;
}
#else
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

#include "picosocks.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_packet_loop.h"

int picoquic_packet_loop_open_sockets_win(int local_port, int local_af, 
    picoquic_recvmsg_async_ctx_t** sock_ctx, int * sock_af, HANDLE * events,
    int nb_sockets_max)
{
    int ret = 0;
    int nb_sockets = (local_af == AF_UNSPEC) ? 2 : 1;

    /* Compute how many sockets are necessary */
    if (nb_sockets > nb_sockets_max) {
        DBG_PRINTF("Cannot open %d sockets, max set to %d\n", nb_sockets, nb_sockets_max);
        nb_sockets = 0;
    } else if (local_af == AF_UNSPEC) {
        sock_af[0] = AF_INET;
        sock_af[1] = AF_INET6;
    }
    else if (local_af == AF_INET || local_af == AF_INET6) {
        sock_af[0] = local_af;
    }
    else {
        DBG_PRINTF("Cannot open socket(AF=%d), unsupported AF\n", local_af);
        nb_sockets = 0;
    }

    for (int i = 0; i < nb_sockets; i++) {
        int recv_set = 0;
        int send_set = 0;

        sock_ctx[i] = picoquic_create_async_socket(sock_af[i]);
        if (sock_ctx[i] == NULL) {
            ret = -1;
            events[i] = NULL;
        }
        else {
            if (picoquic_socket_set_ecn_options(sock_ctx[i]->fd, sock_af[i], &recv_set, &send_set) != 0 ||
                picoquic_socket_set_pkt_info(sock_ctx[i]->fd, sock_af[i]) != 0 ||
                (local_port != 0 && picoquic_bind_to_port(sock_ctx[i]->fd, sock_af[i], local_port) != 0)
#if 0
                ||
                picoquic_recvmsg_async_start(sock_ctx[i]) != 0

#endif
                ){
                DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", sock_af[i], local_port);
                for (int j = 0; j < i; j++) {
                    if (sock_ctx[i] != NULL) {
                        picoquic_delete_async_socket(sock_ctx[i]);
                        sock_ctx[i] = NULL;

                    }
                }
                nb_sockets = 0;
                break;
            }
            else {
                events[i] = sock_ctx[i]->overlap.hEvent;
            }
        }
    }

    return nb_sockets;
}

int picoquic_packet_loop_win(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    uint64_t loop_count_time = current_time;
    int nb_loops = 0;
    picoquic_connection_id_t log_cid;
    picoquic_recvmsg_async_ctx_t* sock_ctx[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int sock_af[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    HANDLE events[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    uint16_t socket_port = (uint16_t)local_port;
    int testing_migration = 0; /* Hook for the migration test */
    uint16_t next_port = 0; /* Data for the migration test */
    picoquic_cnx_t* last_cnx = NULL;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif
    memset(sock_af, 0, sizeof(sock_af));

    if ((nb_sockets = picoquic_packet_loop_open_sockets_win(
        local_port, local_af, sock_ctx, sock_af, events, PICOQUIC_PACKET_LOOP_SOCKETS_MAX)) == 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (loop_callback != NULL) {
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx);
    }

    /* If the socket is not already bound, need to send a first packet to commit the port number */
    if (ret == 0 && local_port == 0) {
        struct sockaddr_storage peer_addr;
        struct sockaddr_storage local_addr;
        int if_index = dest_if;
        int sock_ret = 0;
        int sock_err = 0;

        ret = picoquic_prepare_next_packet(quic, current_time,
            send_buffer, sizeof(send_buffer), &send_length,
            &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

        if (ret == 0 && send_length > 0) {
            SOCKET_TYPE send_socket = sock_ctx[0]->fd;

            sock_ret = picoquic_send_through_socket(send_socket,
                (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                (const char*)send_buffer, (int)send_length, &sock_err);

            if (sock_ret <= 0) {
                if (last_cnx == NULL) {
                    picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                        peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                }
                else {
                    picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                        peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                }
            }
            else {
                struct sockaddr_storage local_address;
                if (picoquic_get_local_address(sock_ctx[0]->fd, &local_address) != 0) {
                    memset(&local_address, 0, sizeof(struct sockaddr_storage));
                    fprintf(stderr, "Could not read local address.\n");
                }
                else if (local_address.ss_family == AF_INET6) {
                    socket_port = ((struct sockaddr_in6*) & local_address)->sin6_port;
                }
                else if (local_address.ss_family == AF_INET) {
                    socket_port = ((struct sockaddr_in*) & local_address)->sin_port;
                }
                else {
                    DBG_PRINTF("Invalid local socket family: %d ", local_address.ss_family);
                    ret = -1;
                }
            }
        }
        else {
            DBG_PRINTF("%s", "No first packet prepared, cannot run the loop.");
            ret = -1;
        }
    }

    /* If the socket is already bound, start asynch receive */
    if (ret == 0 /* && local_port != 0 */) {
        for (int i = 0; i < nb_sockets; i++) {
            if (!sock_ctx[i]->is_started) {
                sock_ctx[i]->is_started = 1;
                ret = picoquic_recvmsg_async_start(sock_ctx[i]);
                if (ret == -1) {
                    DBG_PRINTF("%s", "Cannot start async recv");
                }
            }
        }
    }

    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    while (ret == 0) {
        uint64_t loop_time;
        int socket_rank = -1;
        int64_t delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
        DWORD delta_t_ms = (delta_t < 0)?0:(DWORD)(delta_t / 1000);
        DWORD ret_event = WSAWaitForMultipleEvents(nb_sockets, events, FALSE, delta_t_ms, 0);
        current_time = picoquic_get_quic_time(quic);
        loop_time = current_time;

        if (ret_event == WSA_WAIT_FAILED) {
            DBG_PRINTF("WSAWaitForMultipleEvents fails, error 0x%x", WSAGetLastError());
            ret = -1;
        } else if (ret_event >= WSA_WAIT_EVENT_0) {
            socket_rank = ret_event - WSA_WAIT_EVENT_0;
            /* if received data on a socket, process it. */
            if (socket_rank < nb_sockets) {
                /* Received data on socket i */
                ret = picoquic_recvmsg_async_finish(sock_ctx[socket_rank]);
                ResetEvent(sock_ctx[socket_rank]->overlap.hEvent);

                if (ret != 0) {
                    DBG_PRINTF("%s", "Cannot finish async recv");
                }
                else {
                    /* Document incoming port. By default, there is just one port in use.
                     * But we also have special code for supporting migration tests, which requires
                     * a second socket with a different port number.
                     */
                    uint16_t current_recv_port = socket_port;

                    if (testing_migration) {
                        if (socket_rank == 0) {
                            current_recv_port = socket_port;
                        }
                        else {
                            current_recv_port = next_port;
                        }
                    }

                    if (sock_ctx[socket_rank]->addr_dest.ss_family == AF_INET6) {
                        ((struct sockaddr_in6*) & sock_ctx[socket_rank]->addr_dest)->sin6_port = current_recv_port;
                    }
                    else if (sock_ctx[socket_rank]->addr_dest.ss_family == AF_INET) {
                        ((struct sockaddr_in*) & sock_ctx[socket_rank]->addr_dest)->sin_port = current_recv_port;
                    }

                    /* Submit the packet to the client */
                    ret = picoquic_incoming_packet(quic, sock_ctx[socket_rank]->buffer,
                        (size_t)sock_ctx[socket_rank]->bytes_recv, (struct sockaddr*) & sock_ctx[socket_rank]->addr_from,
                        (struct sockaddr*) & sock_ctx[socket_rank]->addr_dest, sock_ctx[socket_rank]->dest_if,
                        sock_ctx[socket_rank]->received_ecn, current_time);

                    if (ret == 0) {
                        /* Restart waiting for packets on the socket */
                        ret = picoquic_recvmsg_async_start(sock_ctx[socket_rank]);
                        if (ret == -1) {
                            DBG_PRINTF("%s", "Cannot re-start async recv");
                        }
                    }
                    else {
                        DBG_PRINTF("Packet processing error\r\n");
                    }

                    if (ret == 0 && loop_callback != NULL) {
                        ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx);
                    }
                }
            }

            /* Send packets that are now ready */
            /* TODO: manage asynch send. */
            while (ret == 0) {
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr;
                int if_index = dest_if;
                int sock_ret = 0;
                int sock_err = 0;

                ret = picoquic_prepare_next_packet(quic, loop_time,
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx);

                if (ret == 0 && send_length > 0) {
                    SOCKET_TYPE send_socket = INVALID_SOCKET;
                    loop_count_time = current_time;
                    nb_loops = 0;
                    for (int i = 0; i < nb_sockets; i++) {
                        if (sock_af[i] == peer_addr.ss_family) {
                            send_socket = sock_ctx[i]->fd;
                            break;
                        }
                    }

                    if (testing_migration) {
                        /* This code path is only used in the migration tests */
                        uint16_t send_port = (local_addr.ss_family == AF_INET) ?
                            ((struct sockaddr_in*) & local_addr)->sin_port :
                            ((struct sockaddr_in6*) & local_addr)->sin6_port;

                        if (send_port == next_port) {
                            send_socket = sock_ctx[nb_sockets - 1]->fd;
                        }
                    }

                    sock_ret = picoquic_send_through_socket(send_socket,
                        (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                        (const char*)send_buffer, (int)send_length, &sock_err);

                    if (sock_ret <= 0) {
                        if (last_cnx == NULL) {
                            picoquic_log_context_free_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
                        }
                        else {
                            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                                peer_addr.ss_family, local_addr.ss_family, if_index, sock_ret, sock_err);
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

        /* Special code for managing tests */
        if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
            /* Two pseudo error codes used for testing migration!
             * What follows is really test code, which we write here because it has to handle
             * the sockets, which interferes a lot with the handling of the packet loop.
             */
            int s_mig_af;
            picoquic_recvmsg_async_ctx_t* sock_ctx_mig = NULL;
            int testing_nat = (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT);
            HANDLE mig_sock_event = NULL;
            
            next_port = socket_port + 1;
            if (picoquic_packet_loop_open_sockets_win(next_port, sock_af[0], &sock_ctx_mig, &s_mig_af, &mig_sock_event, 1) != 1){
                if (last_cnx != NULL) {
                    picoquic_log_app_message(last_cnx, "Could not create socket for migration test, port=%d, af=%d",
                        next_port, sock_af[0]);
                }
            } else{
                sock_ctx_mig->is_started = 1;
                if (picoquic_recvmsg_async_start(sock_ctx_mig) != 0) {
                    if (last_cnx != NULL) {
                        picoquic_log_app_message(last_cnx, "Could not start migration socket, port=%d, af=%d",
                            next_port, sock_af[0]);
                    }
                    else {
                        DBG_PRINTF("%s", "Cannot start the migration socket");
                    }
                    picoquic_delete_async_socket(sock_ctx_mig);
                    sock_ctx_mig = NULL;
                    ret = -1;
                }
            }
            if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT || ret == PICOQUIC_NO_ERROR_SIMULATE_MIGRATION) {
                if (testing_nat) {
                    if (sock_ctx[0] != NULL) {
                        picoquic_delete_async_socket(sock_ctx[0]);
                    }
                    sock_ctx[0] = sock_ctx_mig;
                    events[0] = mig_sock_event;
                    ret = 0;
                    if (last_cnx != NULL) {
                        picoquic_log_app_message(last_cnx, "Testing NAT rebinding, port=%d, af=%d",
                            next_port, sock_af[0]);
                    }
                }
                else {
                    /* Testing organized migration */
                    if (nb_sockets < PICOQUIC_PACKET_LOOP_SOCKETS_MAX && last_cnx != NULL) {
                        struct sockaddr_storage local_address;
                        if (last_cnx != NULL) {
                            picoquic_log_app_message(last_cnx, "Testing organized migration, port=%d, af=%d",
                                next_port, sock_af[0]);
                        }
                        picoquic_store_addr(&local_address, (struct sockaddr*) & last_cnx->path[0]->local_addr);
                        if (local_address.ss_family == AF_INET6) {
                            ((struct sockaddr_in6*) & local_address)->sin6_port = next_port;
                        }
                        else if (local_address.ss_family == AF_INET) {
                            ((struct sockaddr_in*) & local_address)->sin_port = next_port;
                        }
                        sock_ctx[nb_sockets] = sock_ctx_mig;
                        events[nb_sockets] = mig_sock_event;
                        nb_sockets++;
                        testing_migration = 1;
                        ret = picoquic_probe_new_path(last_cnx, (struct sockaddr*) & last_cnx->path[0]->peer_addr,
                            (struct sockaddr*) & local_address, current_time);
                    }
                    else {
                        picoquic_delete_async_socket(sock_ctx_mig);
                    }
                }
            }
        }
    }

    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        if (sock_ctx[i] != NULL) {
            picoquic_delete_async_socket(sock_ctx[i]);
            sock_ctx[i] = NULL;
            events[i] = NULL;
        }
    }

    return ret;
}

#endif /* _Windows */