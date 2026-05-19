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

#include <limits.h>

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
#include <fcntl.h>

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

#if defined(PICOQUIC_WITH_IO_URING)
#include <linux/io_uring.h>
#include <liburing.h>
#else
#ifndef PICOQUIC_USES_SELECT
#if !defined(PICOQUIC_WITH_POLL)
#define PICOQUIC_WITH_POLL
#endif
#include <poll.h>
#else
#include <sys/select.h>
#endif
#endif

#if !defined(__APPLE__) && !defined(__FreeBSD__)
#ifdef __LINUX__
#include <linux/prctl.h>  /* Definition of PR_* constants */
#else
#include <sys/prctl.h>
#endif
#endif

#include <pthread.h>

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
#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquic_config.h"
#include "picoquic_lb.h"
#include "picoquic_qlog.h"
#include "performance_log.h"
#include "picoquic_packet_loop.h"
#include "picoquic_unified_log.h"
#include "picoqmux.h"

#if defined(_WINDOWS)
#ifdef UDP_SEND_MSG_SIZE
static int udp_gso_available = 1;
#else
static int udp_gso_available = 0;
#endif
#else
# if defined(UDP_SEGMENT)
static int udp_gso_available = 1;
#else
static int udp_gso_available = 0;
#endif
#endif

#ifdef _WINDOWS
/* Test support for UDP coalescing */
void picoquic_sockloop_win_coalescing_test(int * recv_coalesced, int * send_coalesced)
{
    int ret;
    DWORD option_value;
    int option_length;
    int last_error;

    *recv_coalesced = 0;
    *send_coalesced = 0;

    SOCKET_TYPE fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (fd != INVALID_SOCKET) {
#ifdef UDP_SEND_MSG_SIZE
        if (udp_gso_available) {
            option_length = (int)sizeof(option_value);

            if ((ret = getsockopt(fd, IPPROTO_UDP, UDP_SEND_MSG_SIZE, (char*)&option_value, &option_length)) != 0) {
                last_error = GetLastError();
                DBG_PRINTF("UDP_SEND_MSG_SIZE not supported, returns %d (%d)", ret, last_error);
                udp_gso_available = 0;
            }
            else {
                *send_coalesced = 1;
            }
        }
#endif
#ifdef UDP_RECV_MAX_COALESCED_SIZE
        option_value = 1;
        option_length = (int)sizeof(option_value);
        if ((ret = getsockopt(fd, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE, (char*)&option_value, &option_length)) != 0) {
            last_error = GetLastError();
            DBG_PRINTF("UDP_RECV_MAX_COALESCED_SIZE not supported, returns %d (%d)", ret, last_error);
        }
        else {
            *recv_coalesced = 1;
        }
#endif
        closesocket(fd);
    }
}

int picoquic_win_recvmsg_async_start(picoquic_socket_ctx_t* ctx)
{
    int last_error;
    int ret = 0;
    DWORD numberOfBytesReceived = 0;
    int should_retry;

    do {
        should_retry = 0;
        ctx->from_length = 0;
        ctx->dest_length = 0;
        ctx->dest_if = 0;
        ctx->received_ecn = 0;
        ctx->bytes_recv = 0;
        ctx->udp_coalesced_size = 0;

        ctx->overlap.Internal = 0;
        ctx->overlap.InternalHigh = 0;
        ctx->overlap.Offset = 0;
        ctx->overlap.OffsetHigh = 0;

        ctx->is_started = 0;

        ctx->dataBuf.buf = (char*)ctx->recv_buffer;
        ctx->dataBuf.len = (ULONG)ctx->recv_buffer_size;

        ctx->msg.name = (struct sockaddr*) & ctx->addr_from;
        ctx->msg.namelen = sizeof(ctx->addr_from);
        ctx->msg.lpBuffers = &ctx->dataBuf;
        ctx->msg.dwBufferCount = 1;
        ctx->msg.dwFlags = 0;
        ctx->msg.Control.buf = ctx->cmsg_buffer;
        ctx->msg.Control.len = sizeof(ctx->cmsg_buffer);

        /* Setting the &nbReceived parameter to NULL to force async behavior */
        ret = ctx->WSARecvMsg(ctx->fd, &ctx->msg, &numberOfBytesReceived, &ctx->overlap, NULL);

        if (ret != 0) {
            last_error = WSAGetLastError();
            if (last_error == WSA_IO_PENDING) {
                ret = 0;
            }
            else if (last_error == WSAECONNRESET) {
                /* Ignore the ICMP errors */
                should_retry = 1;
                ret = 0;
            }
            else {
                DBG_PRINTF("Could not start receive async (WSARecvMsg) on UDP socket %d = %d!\n",
                    (int)ctx->fd, last_error);
                ctx->bytes_recv = -1;
            }
        }
        else {
            ctx->nb_immediate_receive++;
        }
    } while (should_retry);

    return ret;
}

int picoquic_packet_set_windows_socket(int send_coalesced, int recv_coalesced, picoquic_socket_ctx_t* s_ctx)
{
    int ret = 0;
    GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
    GUID WSASendMsg_GUID = WSAID_WSASENDMSG;
    DWORD NumberOfBytes_recvguid = 0;
    DWORD NumberOfBytes_sendguid = 0;
    int nResult = 0;
    int last_error = 0;

    if ((nResult = WSAIoctl(s_ctx->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &WSARecvMsg_GUID, sizeof(WSARecvMsg_GUID),
        &s_ctx->WSARecvMsg, sizeof(s_ctx->WSARecvMsg),
        &NumberOfBytes_recvguid, NULL, NULL)) == SOCKET_ERROR ||
        (nResult = WSAIoctl(s_ctx->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
            &WSASendMsg_GUID, sizeof(WSASendMsg_GUID),
            &s_ctx->WSASendMsg, sizeof(s_ctx->WSASendMsg),
            &NumberOfBytes_sendguid, NULL, NULL)) == SOCKET_ERROR ||
        (s_ctx->overlap.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL))
        == WSA_INVALID_EVENT){
        last_error = WSAGetLastError();
        DBG_PRINTF("Could not initialize Windows parameters on socket %d= %d!\n",
            (int)s_ctx->fd, last_error);
        ret = -1;
    }

    if (ret == 0) {
        s_ctx->supports_udp_send_coalesced = send_coalesced;
        s_ctx->supports_udp_recv_coalesced = recv_coalesced;
        if (recv_coalesced) {
            s_ctx->recv_buffer_size = 0x10000;
        }
        else {
            s_ctx->recv_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
        }
        s_ctx->recv_buffer = (uint8_t*)malloc(s_ctx->recv_buffer_size);
        if (s_ctx->recv_buffer == NULL) {
            DBG_PRINTF("Could not allocate buffer size %zu for socket %d!\n",
                s_ctx->recv_buffer_size, (int)s_ctx->fd);
            ret = -1;
        }
        else if (recv_coalesced) {
            DWORD coalesced_size = (DWORD) s_ctx->recv_buffer_size;
            if (setsockopt(s_ctx->fd, IPPROTO_UDP, UDP_RECV_MAX_COALESCED_SIZE, (char*)&coalesced_size,
                (int)sizeof(coalesced_size)) != 0) {
                last_error = GetLastError();
                DBG_PRINTF("Cannot set UDP_RECV_MAX_COALESCED_SIZE %d, returns %d (%d)",
                    coalesced_size, ret, last_error);
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        ret = picoquic_win_recvmsg_async_start(s_ctx);
    }

    return ret;
}

int picoquic_win_recvmsg_async_finish(
    picoquic_socket_ctx_t* s_ctx)
{
    DWORD cbTransferred = 0;
    DWORD ret = 0;
    DWORD flags = 0;

    if (s_ctx == NULL) {
        return -1;
    }

    if (!WSAGetOverlappedResult(s_ctx->fd, &s_ctx->overlap, &cbTransferred, FALSE, &flags)) {
        ret = WSAGetLastError();
        if (ret == WSAECONNRESET) {
            s_ctx->bytes_recv = 0;
            ret = picoquic_win_recvmsg_async_start(s_ctx);
        }
        else {
            DBG_PRINTF("Could not complete async call (WSARecvMsg) on UDP socket %d = %d!\n",
                (int)s_ctx->fd, ret);
            s_ctx->bytes_recv = -1;
        }
    } 
    else {
        s_ctx->bytes_recv = cbTransferred;
        s_ctx->from_length = s_ctx->msg.namelen;

        picoquic_socks_cmsg_parse(&s_ctx->msg, &s_ctx->addr_dest, &s_ctx->dest_if, &s_ctx->received_ecn, &s_ctx->udp_coalesced_size);
    }

    return ret;
}

#endif

void picoquic_packet_loop_close_socket(picoquic_socket_ctx_t* s_ctx)
{
    if (s_ctx->fd != INVALID_SOCKET) {
        SOCKET_CLOSE(s_ctx->fd);
        s_ctx->fd = INVALID_SOCKET;
    }
#ifdef _WINDOWS
    if (s_ctx->overlap.hEvent != WSA_INVALID_EVENT) {
        WSACloseEvent(s_ctx->overlap.hEvent);
        s_ctx->overlap.hEvent = WSA_INVALID_EVENT;
    }

    if (s_ctx->recv_buffer != NULL) {
        free(s_ctx->recv_buffer);
        s_ctx->recv_buffer = NULL;
    }
#endif
}

#ifdef _WINDOWS
int picoquic_packet_loop_open_socket(int socket_buffer_size, int do_not_use_gso,
    picoquic_socket_ctx_t* s_ctx, uint8_t ecn_value)
#else
int picoquic_packet_loop_open_socket(int socket_buffer_size, int UNUSED(do_not_use_gso),
    picoquic_socket_ctx_t* s_ctx, uint8_t ecn_value)
#endif
{
    int ret = 0;
    struct sockaddr_storage local_address;
    int recv_set = 0;
    int send_set = 0;
    int opt_val = 1;
#ifdef _WINDOWS
    int recv_coalesced = 0;
    int send_coalesced = 0;

    /* Assess whether coalescing is supported */
    if (!do_not_use_gso) {
        picoquic_sockloop_win_coalescing_test(&recv_coalesced, &send_coalesced);
#if 0
        /* TODO: remove temporary fix, after we figure how to work that out. */
        recv_coalesced = 0;
#endif
    }
    s_ctx->overlap.hEvent = WSA_INVALID_EVENT;
    s_ctx->fd = WSASocket(s_ctx->af, SOCK_DGRAM, IPPROTO_UDP, NULL, 0, WSA_FLAG_OVERLAPPED);
#else
    s_ctx->fd = socket(s_ctx->af, SOCK_DGRAM, IPPROTO_UDP);
#endif


    if (s_ctx->fd == INVALID_SOCKET ||
#ifndef ESP_PLATFORM
        /* TODO: set option IPv6 only */
        picoquic_socket_set_ecn_options_ex(s_ctx->fd, s_ctx->af, &recv_set, &send_set, ecn_value) != 0 ||
#endif
        picoquic_socket_set_pkt_info(s_ctx->fd, s_ctx->af) != 0 ||
        (s_ctx->is_port_shared && setsockopt(s_ctx->fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt_val, sizeof(opt_val)) != 0) ||
#if defined(SO_REUSEPORT)
        (s_ctx->is_port_shared && setsockopt(s_ctx->fd, SOL_SOCKET, SO_REUSEPORT, (const char*)&opt_val, sizeof(opt_val)) != 0) ||
#endif
        picoquic_bind_to_port(s_ctx->fd,s_ctx->af, s_ctx->port) != 0 ||
        picoquic_get_local_address(s_ctx->fd, &local_address) != 0 ||
        picoquic_socket_set_pmtud_options(s_ctx->fd, s_ctx->af) != 0)
    {
        DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", s_ctx->af, s_ctx->port);
        ret = -1;
    }
    else {
        if (local_address.ss_family == AF_INET6) {
            s_ctx->port = ntohs(((struct sockaddr_in6*)&local_address)->sin6_port);
        }
        else if (local_address.ss_family == AF_INET) {
            s_ctx->port = ntohs(((struct sockaddr_in*)&local_address)->sin_port);
        }
        
#ifndef ESP_PLATFORM
        if (socket_buffer_size > 0) {
            socklen_t opt_len;
            int opt_ret;
            int so_sndbuf;
            int so_rcvbuf;
            int last_op = SO_SNDBUF;
            char const* last_op_name = "SO_SNDBUF";

            opt_len = sizeof(int);
            so_sndbuf = socket_buffer_size;
            opt_ret = setsockopt(s_ctx->fd, SOL_SOCKET, SO_SNDBUF, (const char*)&so_sndbuf, opt_len);
            if (opt_ret == 0) {
                last_op = SO_RCVBUF;
                last_op_name = "SO_RECVBUF";
                opt_len = sizeof(int);
                so_rcvbuf = socket_buffer_size;
                opt_ret = setsockopt(s_ctx->fd, SOL_SOCKET, SO_RCVBUF, (const char*)&so_rcvbuf, opt_len);
            }
            if (opt_ret != 0) {
                int so_errbuf = 0;
#ifdef _WINDOWS
                int sock_error = WSAGetLastError();
#else
                int sock_error = errno;
#endif
                opt_ret = getsockopt(s_ctx->fd, SOL_SOCKET, last_op, (char*)&so_errbuf, &opt_len);
                DBG_PRINTF("Cannot set %s to %d, err=%d, so_sndbuf=%d (%d)",
                    last_op_name, socket_buffer_size, sock_error, so_errbuf, opt_ret);
                ret = -1;
            }
        }
#endif

#ifdef _WINDOWS
        if (ret == 0) {
            ret = picoquic_packet_set_windows_socket(send_coalesced, recv_coalesced, s_ctx);
        }
#endif
    }

    return ret;
}

int picoquic_packet_loop_open_sockets(uint16_t local_port, int local_af, uint16_t public_port, int is_shared,
    int socket_buffer_size, int extra_socket_required, int do_not_use_gso, picoquic_socket_ctx_t* s_ctx, uint8_t ecn_value)
{
    /* Compute how many sockets are necessary, and set the intial value of AF and port per socket */
    int nb_sockets = 0;
    int af[2];
    int nb_af;
    uint16_t current_port = local_port;
    int sock_ret = 0;

    if (local_af == 0) {
#ifdef ESP_PLATFORM
        nb_af = 1;
        af[0] = AF_INET;
#else
        nb_af = 2;
        af[0] = AF_INET;
        af[1] = AF_INET6;
#endif
    }
    else {
        nb_af = 1;
        af[0] = local_af;
    }
    for (int iteration = 0; sock_ret == 0 && iteration < 1 + (extra_socket_required); iteration++) {
        for (int i_af = 0; sock_ret == 0 && i_af < nb_af; i_af++) {
            s_ctx[nb_sockets].af = af[i_af];
            s_ctx[nb_sockets].port = current_port;
            s_ctx[nb_sockets].n_port = htons(current_port);
            s_ctx[nb_sockets].is_port_shared = 0;
            if ((sock_ret = picoquic_packet_loop_open_socket(socket_buffer_size, do_not_use_gso, &s_ctx[nb_sockets], ecn_value)) == 0) {
                if (current_port == 0) {
                    current_port = s_ctx[nb_sockets].port;
                    s_ctx[nb_sockets].n_port = htons(current_port);
                }
                nb_sockets++;
            }
            if (sock_ret == 0 && public_port != 0) {
                s_ctx[nb_sockets].af = af[i_af];
                s_ctx[nb_sockets].port = public_port;
                s_ctx[nb_sockets].n_port = htons(public_port);
                s_ctx[nb_sockets].is_port_shared = (is_shared != 0);
                if ((sock_ret = picoquic_packet_loop_open_socket(socket_buffer_size, do_not_use_gso, &s_ctx[nb_sockets], ecn_value)) == 0) {
                    nb_sockets++;
                }
            }
        }
        current_port = 0;
    }

    if (sock_ret != 0) {
        DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", s_ctx[nb_sockets].af, s_ctx[nb_sockets].port);
        for (int j = 0; j < nb_sockets; j++) {
            picoquic_packet_loop_close_socket(&s_ctx[j]);
        }
        nb_sockets = 0;
    }
    return nb_sockets;
}

/*
* Management of QMUX sockets.
* 
* The sockets are declared in an array of pointers, which is
* set large enough to contain the planned number of connections.
*/

#ifndef _WINDOWS
static int picoquic_packet_loop_set_qmux_nonblocking(SOCKET_TYPE fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) ? -1 : 0;
}
#endif

#ifdef _WINDOWS
static int picoquic_sockloop_set_win_buf(picoquic_sockloop_win_buf_t * win_buf)
{
    int ret = 0;
    win_buf->buf_size = 0x4000;
    win_buf->buf_len = 0;
    win_buf->buf_offset = 0;
    if ((win_buf->buf = (uint8_t*)malloc(win_buf->buf_size)) == NULL) {
        ret = -1;
    }
    else if ((win_buf->overlap.hEvent = WSACreateEvent()) == WSA_INVALID_EVENT) {
        ret = -1;
        free(win_buf->buf);
        win_buf->buf = NULL;
    }
    else {
        memset(win_buf->buf, 0, win_buf->buf_size);
    }
    return ret;
}

static void picoquic_sockloop_free_win_buf(picoquic_sockloop_win_buf_t* win_buf)
{
    if (win_buf->overlap.hEvent != WSA_INVALID_EVENT) {
        WSACloseEvent(win_buf->overlap.hEvent);
        win_buf->overlap.hEvent = WSA_INVALID_EVENT;
    }
    if (win_buf->buf != NULL) {
        free(win_buf->buf);
        win_buf->buf = NULL;
    }
}

void picoquic_packet_loop_free_qmux_socket(picoqmux_socket_ctx_t* sqmux_sock_ctx)
{
    if (sqmux_sock_ctx != NULL) {
        if (sqmux_sock_ctx->fd != INVALID_SOCKET) {
            SOCKET_CLOSE(sqmux_sock_ctx->fd);
            sqmux_sock_ctx->fd = INVALID_SOCKET;
        }
        if (sqmux_sock_ctx->send_buffer != NULL) {
            free(sqmux_sock_ctx->send_buffer);
            sqmux_sock_ctx->send_buffer = NULL;
        }
#ifdef _WINDOWS
        picoquic_sockloop_free_win_buf(&sqmux_sock_ctx->winbuf_r);
        picoquic_sockloop_free_win_buf(&sqmux_sock_ctx->winbuf_w);
#endif
        free(sqmux_sock_ctx);
    }
}

static int picoquic_packet_loop_set_qmux_windows_socket(picoqmux_socket_ctx_t* sqmux_sock_ctx)
{
    int ret = 0;

    if (picoquic_sockloop_set_win_buf(&sqmux_sock_ctx->winbuf_r) != 0 ||
        picoquic_sockloop_set_win_buf(&sqmux_sock_ctx->winbuf_w) != 0) {
        DBG_PRINTF("Could not initialize Windows buffers on QMUX socket %d!\n", (int)sqmux_sock_ctx->fd);
        ret = -1;
    }
    return ret;
}
#endif

picoqmux_socket_ctx_t* picoquic_packet_loop_open_qmux_socket(
    int af, uint16_t public_port,
    int is_port_shared, int is_listening)
{
    picoqmux_socket_ctx_t* sqmux_sock_ctx = NULL;
    int opt_val = 1;

    if ((sqmux_sock_ctx = (picoqmux_socket_ctx_t*)malloc(sizeof(picoqmux_socket_ctx_t))) == NULL) {
        DBG_PRINTF("%s", "Cannot allocate memory for QMUX socket context\n");
        return NULL;
    }
    memset(sqmux_sock_ctx, 0, sizeof(picoqmux_socket_ctx_t));
    sqmux_sock_ctx->af = af;
    sqmux_sock_ctx->port = public_port;
    sqmux_sock_ctx->fd = INVALID_SOCKET;
#ifdef _WINDOWS
    sqmux_sock_ctx->fd = WSASocket(af, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
#else
    sqmux_sock_ctx->fd = socket(af, SOCK_STREAM, IPPROTO_TCP);
#endif

    if (sqmux_sock_ctx->fd == INVALID_SOCKET ||
#ifdef _WINDOWS
        picoquic_packet_loop_set_qmux_windows_socket(sqmux_sock_ctx) != 0 ||
#else
        picoquic_packet_loop_set_qmux_nonblocking(sqmux_sock_ctx->fd) != 0 ||
        (af == AF_INET6 && setsockopt(sqmux_sock_ctx->fd, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&opt_val, sizeof(opt_val)) != 0) ||
#endif
        (is_port_shared && setsockopt(sqmux_sock_ctx->fd, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt_val, sizeof(opt_val)) != 0) ||
        ((is_listening || public_port != 0) && picoquic_bind_to_port(sqmux_sock_ctx->fd, af, public_port) != 0)) {
        DBG_PRINTF("Cannot set socket (af=%d, port = %d)\n", af, public_port);
        picoquic_packet_loop_free_qmux_socket(sqmux_sock_ctx);
        return NULL;
    }

    /* TODO: listen, or asynchronous connect */
    if (is_listening) {
        if (listen(sqmux_sock_ctx->fd, 5) != 0) {
            DBG_PRINTF("Cannot listen on socket (af=%d, port = %d)\n", af, public_port);
            picoquic_packet_loop_free_qmux_socket(sqmux_sock_ctx);
            return NULL;
        } 
        sqmux_sock_ctx->is_listening = 1;
    }

    if (is_listening || public_port != 0) {
        struct sockaddr_storage local_addr;
        if (picoquic_get_local_address(sqmux_sock_ctx->fd, &local_addr) != 0) {
            DBG_PRINTF("Cannot get local socket address (af=%d, port = %d)\n", af, public_port);
            picoquic_packet_loop_free_qmux_socket(sqmux_sock_ctx);
            return NULL;
        }
        picoquic_store_addr(&sqmux_sock_ctx->local_addr, (struct sockaddr*)&local_addr);
        if (local_addr.ss_family == AF_INET6) {
            sqmux_sock_ctx->port = ntohs(((struct sockaddr_in6*)&local_addr)->sin6_port);
        }
        else if (local_addr.ss_family == AF_INET) {
            sqmux_sock_ctx->port = ntohs(((struct sockaddr_in*)&local_addr)->sin_port);
        }
    }


    return sqmux_sock_ctx;
}

#ifdef _WINDOWS
int picoquic_packet_loop_start_windows_recv(
    picoqmux_socket_ctx_t* sqmux_sock_ctx)
{
    int ret = 0;
    DWORD dwBytes;

    sqmux_sock_ctx->winbuf_r.wsaBuf.buf = (char*)sqmux_sock_ctx->winbuf_r.buf;
    sqmux_sock_ctx->winbuf_r.wsaBuf.len = (ULONG)sqmux_sock_ctx->winbuf_r.buf_size;
    sqmux_sock_ctx->winbuf_r.buf_len = 0;

    do {
        dwBytes = 0;
        if (WSARecv(sqmux_sock_ctx->fd, &sqmux_sock_ctx->winbuf_r.wsaBuf, 1,
            NULL, &dwBytes, &sqmux_sock_ctx->winbuf_r.overlap, NULL) == SOCKET_ERROR) {
            int last_error = WSAGetLastError();
            if (last_error != WSA_IO_PENDING) {
                DBG_PRINTF("WSARecv failed with error: %u\n", last_error);
                ret = -1;
            }
            else {
                /* This is the expected behavior, waiting for arrival of a new message */
                sqmux_sock_ctx->is_receiving = 1;
            }
            break;
        }
        else if (dwBytes > 0) {
            /* We got a message immediately. Process it. */
            sqmux_sock_ctx->winbuf_r.buf_len = dwBytes;
        }
    } while (dwBytes == 0);

    return ret;
}

int picoquic_sockloop_finish_windows_recv(
    picoqmux_socket_ctx_t* sqmux_sock_ctx)
{
    int ret = 0;
    DWORD cbTransferred = 0;
    DWORD flags = 0;
    if (!WSAGetOverlappedResult(sqmux_sock_ctx->fd, &sqmux_sock_ctx->winbuf_r.overlap, &cbTransferred, FALSE, &flags)) {
        int last_error = WSAGetLastError();
        DBG_PRINTF("Could not complete async call (WSARecv) on QMUX socket %d = %d!\n",
            (int)sqmux_sock_ctx->fd, last_error);
        ret = -1;
    }
    else {
        sqmux_sock_ctx->winbuf_r.buf_len = cbTransferred;
        sqmux_sock_ctx->is_receiving = 0;
        ret = 0;
    }
    return ret;
}

int picoquic_sockloop_start_windows_send(
    picoqmux_socket_ctx_t* sqmux_sock_ctx, uint64_t current_time)
{
    int ret = 0;

    if (sqmux_sock_ctx->cnx->next_wake_time <= current_time && !sqmux_sock_ctx->is_sending) {
        if (sqmux_sock_ctx->winbuf_w.buf_offset >= sqmux_sock_ctx->winbuf_w.buf_len) {
            sqmux_sock_ctx->winbuf_w.buf_offset = 0;
            sqmux_sock_ctx->winbuf_w.buf_len = 0;
            ret = picoqmux_prepare_packets(sqmux_sock_ctx->cnx, current_time, sqmux_sock_ctx->winbuf_w.buf,
                sqmux_sock_ctx->winbuf_w.buf_size, &sqmux_sock_ctx->winbuf_w.buf_len);
        }
        if (ret == 0 && sqmux_sock_ctx->winbuf_w.buf_len > sqmux_sock_ctx->winbuf_w.buf_offset) {
            sqmux_sock_ctx->winbuf_w.wsaBuf.buf = (char*)sqmux_sock_ctx->winbuf_w.buf +
                sqmux_sock_ctx->winbuf_w.buf_offset;
            sqmux_sock_ctx->winbuf_w.wsaBuf.len = (ULONG)(sqmux_sock_ctx->winbuf_w.buf_len -
                sqmux_sock_ctx->winbuf_w.buf_offset);
            sqmux_sock_ctx->is_sending = 1;
            if (WSASend(sqmux_sock_ctx->fd, &sqmux_sock_ctx->winbuf_w.wsaBuf, 1,
                NULL, 0, &sqmux_sock_ctx->winbuf_w.overlap, NULL) == SOCKET_ERROR) {
                int last_error = WSAGetLastError();
                if (last_error != WSA_IO_PENDING) {
                    DBG_PRINTF("WSASend failed with error: %u\n", last_error);
                    ret = -1;
                }
                else {
                    /* This is the expected behavior, waiting for completion of the send */
                    ret = 0;
                }
            }
        }
    }
    return ret;
}

int picoquic_sockloop_finish_windows_send(
    picoqmux_socket_ctx_t* sqmux_sock_ctx)
{
    int ret = 0;
    DWORD cbTransferred = 0;
    DWORD flags = 0;
    if (!WSAGetOverlappedResult(sqmux_sock_ctx->fd, &sqmux_sock_ctx->winbuf_w.overlap, &cbTransferred, FALSE, &flags)) {
        int last_error = WSAGetLastError();
        DBG_PRINTF("Could not complete async call (WSASend) on QMUX socket %d = %d!\n",
            (int)sqmux_sock_ctx->fd, last_error);
        ret = -1;
    }
    else {
        if (cbTransferred == 0 &&
            sqmux_sock_ctx->winbuf_w.buf_offset < sqmux_sock_ctx->winbuf_w.buf_len) {
            ret = -1;
        }
        else if (cbTransferred > 0) {
            sqmux_sock_ctx->winbuf_w.buf_offset += cbTransferred;
            if (sqmux_sock_ctx->winbuf_w.buf_offset >= sqmux_sock_ctx->winbuf_w.buf_len) {
                sqmux_sock_ctx->winbuf_w.buf_offset = 0;
                sqmux_sock_ctx->winbuf_w.buf_len = 0;
            }
            else {
                sqmux_sock_ctx->cnx->next_wake_time = picoquic_get_quic_time(sqmux_sock_ctx->cnx->quic);
            }
        }
        sqmux_sock_ctx->is_sending = 0;
    }
    return ret;
}

/* In winsock, it is difficult to wait for accept in the same way as in Unix.
* Instead, the documentation says to use "AcceptEx", which takes as parameter
* two sockets: the listening socket, and another to be created. The command can
* take an "overlapped" argument, describing a completion port or an event
* that will be activated when the accept completes.
*
* The acceptEx function is an extension. It is defined as a function pointer,
* which needs to be acquired before the call. Note that we pass a buffer size
* of zero, which means "don't wait for initial data." This simplifies
* behavior, and also closes a potential area for DOS attacks.
*/

static int picoquic_packet_loop_do_windows_accept(
    picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets,
    int max_qmux_socket,
    int listen_socket_rank)
{
    int ret = 0;
    if (sqmux_ctx[listen_socket_rank]->lpfnAcceptEx == NULL) {
        // Load the AcceptEx function into memory using WSAIoctl.
        // The WSAIoctl function is an extension of the ioctlsocket()
        // function that can use overlapped I/O. The function's 3rd
        // through 6th parameters are input and output buffers where
        // we pass the pointer to our AcceptEx function. This is used
        // so that we can call the AcceptEx function directly, rather
        // than refer to the Mswsock.lib library.
        GUID GuidAcceptEx = WSAID_ACCEPTEX;
        DWORD dwBytes;

        int iResult = WSAIoctl(sqmux_ctx[listen_socket_rank]->fd,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            &GuidAcceptEx, sizeof(GuidAcceptEx),
            &sqmux_ctx[listen_socket_rank]->lpfnAcceptEx, sizeof(LPFN_ACCEPTEX),
            &dwBytes, NULL, NULL);

        if (iResult == SOCKET_ERROR) {
            wprintf(L"WSAIoctl failed with error: %u\n", WSAGetLastError());
            ret = -1;
        }
    }

    if (*nb_qmux_sockets < max_qmux_socket) {
        /* create a socket for the incoming connection */
        DWORD dwBytes = 0;
        int accept_socket_rank = *nb_qmux_sockets;
#if 1
        int sock_addr_len = sizeof(struct sockaddr_storage);
#else
        int sock_addr_len = (sqmux_ctx[listen_socket_rank]->af == AF_INET)?
            sizeof(struct sockaddr_in): sizeof(struct sockaddr_in6);
#endif
        if ((sqmux_ctx[accept_socket_rank] = picoquic_packet_loop_open_qmux_socket(
            sqmux_ctx[listen_socket_rank]->af, 0, 0, 0)) == NULL) {
            ret = -1;
        }
        else {
            /* do the accept call */
            (*nb_qmux_sockets) += 1;
            sqmux_ctx[listen_socket_rank]->is_accepting = 1;
            sqmux_ctx[accept_socket_rank]->is_accepting = 1;
            sqmux_ctx[accept_socket_rank]->accepting_socket = sqmux_ctx[listen_socket_rank]->fd;
            if (sqmux_ctx[listen_socket_rank]->lpfnAcceptEx(
                sqmux_ctx[listen_socket_rank]->fd,
                sqmux_ctx[accept_socket_rank]->fd,
                sqmux_ctx[accept_socket_rank]->winbuf_r.buf,
                0,
                sock_addr_len + 16, sock_addr_len + 16,
                &dwBytes, &sqmux_ctx[accept_socket_rank]->winbuf_r.overlap) == FALSE) {
                int last_error = WSAGetLastError();
                if (last_error != WSA_IO_PENDING) {
                    DBG_PRINTF("AcceptEx failed with error: %u\n", WSAGetLastError());
                    ret = -1;
                }
                else {
                    /* This is the expected behavior, waiting for arrival of a new connection */
                    ret = 0;
                }
            }
        }
    }
    else {
        DBG_PRINTF("Too many QMUX sockets, cannot accept more (max=%d)\n", max_qmux_socket);
        /* TODO: keep track of accept calls. */
    }
    return ret;
}

static int picoquic_packet_loop_complete_windows_accept(
    picoqmux_socket_ctx_t** sqmux_ctx,
    int accept_socket_rank) {
    GUID GuidAcceptEx = WSAID_GETACCEPTEXSOCKADDRS;
    LPFN_GETACCEPTEXSOCKADDRS getAcceptexSockaddrs;
    DWORD dwBytes;
    struct sockaddr* local_sockaddr = NULL;
    struct sockaddr* remote_sockaddr = NULL;
    int local_sockaddr_len = 0;
    int remote_sockaddr_len = 0;
    int sock_addr_len = sizeof(struct sockaddr_storage);
    int ret = 0;

    for (int i = 0; i < accept_socket_rank; i++) {
        if (sqmux_ctx[i]->is_listening && sqmux_ctx[i]->fd == sqmux_ctx[accept_socket_rank]->accepting_socket) {
            sqmux_ctx[accept_socket_rank]->is_accepting = 0;
            sqmux_ctx[i]->is_accepting = 0;
            break;
        }
    }
#if 0
    /* Get overlapped result so as to properly complete the acceptex call*/
    if (WSAGetOverlappedResult(sqmux_ctx[accept_socket_rank]->accepting_socket,
        &sqmux_ctx[accept_socket_rank]->winbuf_r.overlap, &dwBytes, TRUE, NULL) != TRUE) {
        DBG_PRINTF("GetOverlappedResult failed with error: %u\n", WSAGetLastError());
        ret = -1;
    }
    else
#endif
    /* Call setsockopt() with SO_UPDATE_ACCEPT_CONTEXT on
     * the accepted socket using the listening socket as the data */
    if (setsockopt(sqmux_ctx[accept_socket_rank]->fd, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
        (char*)&sqmux_ctx[accept_socket_rank]->accepting_socket, sizeof(SOCKET_TYPE)) != 0) {
        DBG_PRINTF("setsockopt SO_UPDATE_ACCEPT_CONTEXT failed with error: %u\n", WSAGetLastError());
        ret = -1;
    }
    /* Acquire the pointer to LPFN_GETACCEPTEXSOCKADDRS 
     * and call the function to obtain the calling addresses */
    else if (WSAIoctl(sqmux_ctx[accept_socket_rank]->fd,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &GuidAcceptEx, sizeof(GuidAcceptEx),
        &getAcceptexSockaddrs, sizeof(LPFN_GETACCEPTEXSOCKADDRS),
        &dwBytes, NULL, NULL) == SOCKET_ERROR) {
        DBG_PRINTF("WSAIoctl failed with error: %u\n", WSAGetLastError());
        ret = -1;
    }
    else {
        getAcceptexSockaddrs(
            sqmux_ctx[accept_socket_rank]->winbuf_r.buf,
            0,
            sock_addr_len + 16,
            sock_addr_len + 16,
            &local_sockaddr,
            &local_sockaddr_len,
            &remote_sockaddr,
            &remote_sockaddr_len);
        if (local_sockaddr != NULL && local_sockaddr_len > 0) {
            picoquic_store_addr(&sqmux_ctx[accept_socket_rank]->local_addr,
                local_sockaddr);
        }
        if (remote_sockaddr != NULL && remote_sockaddr_len > 0) {
            picoquic_store_addr(&sqmux_ctx[accept_socket_rank]->remote_addr,
                remote_sockaddr);
        }
        sqmux_ctx[accept_socket_rank]->is_accepting = 0;
        sqmux_ctx[accept_socket_rank]->accepting_socket = 0;
    }
    return ret;
}

int picoquic_packet_loop_start_windows_accept_sockets(
    picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets,
    int max_qmux_socket)
{
    int ret = 0;
    for (int i = 0; i < *nb_qmux_sockets; i++) {
        if (sqmux_ctx[i]->is_listening &&
            !sqmux_ctx[i]->is_accepting) {
            if (picoquic_packet_loop_do_windows_accept(sqmux_ctx, nb_qmux_sockets, max_qmux_socket, i) != 0) {
                ret = -1;
                break;
            }
        }
    }
    return ret;
}

int picoquic_packet_loop_start_windows_connect(
    picoqmux_socket_ctx_t* sqmux_sock_ctx,
    struct sockaddr* dest)
{
    int ret = 0;
    int sock_ret = 0;
    GUID GuidConnectEx = WSAID_CONNECTEX;
    LPFN_CONNECTEX lpfnConnectEx;
    DWORD dwBytes = 0;
    // struct sockaddr_storage local_address = { 0 };

    /* Bind to an unspecified port so there is no issue */
    if (picoquic_bind_to_port(sqmux_sock_ctx->fd, dest->sa_family, 0) != 0) {
        DBG_PRINTF("Cannot bind to local address for connect (af=%d)\n", sqmux_sock_ctx->af);
        ret = -1;
        /* Fail!*/
    }
    /* Acquire the pointer to LPFN_GETACCEPTEXSOCKADDRS
     * and call the function to obtain the calling addresses */
    else if (WSAIoctl(sqmux_sock_ctx->fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &GuidConnectEx, sizeof(GuidConnectEx),
        &lpfnConnectEx, sizeof(lpfnConnectEx),
        &dwBytes, NULL, NULL) == SOCKET_ERROR) {
        DBG_PRINTF("WSAIoctl failed with error: %u\n", WSAGetLastError());
        ret = -1;
        /* Fail!*/
    }
    else if ((sock_ret = lpfnConnectEx(sqmux_sock_ctx->fd, dest,
        (socklen_t)((dest->sa_family == AF_INET) ?
            sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)),
        NULL, 0, NULL, &sqmux_sock_ctx->winbuf_r.overlap)) == FALSE) {
        int last_error = WSAGetLastError();
        if (last_error != WSA_IO_PENDING) {
            DBG_PRINTF("ConnectEx failed with error: %u\n", WSAGetLastError());
            ret = -1;
        }
    }
    return ret;
}

int picoquic_packet_loop_complete_windows_connect(
    picoqmux_socket_ctx_t* sqmux_sock_ctx)
{
    int ret = 0;

    sqmux_sock_ctx->is_connecting = 0;

    /* Make the socket more well-behaved. */
    if (setsockopt(sqmux_sock_ctx->fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) != 0) {
        printf("SO_UPDATE_CONNECT_CONTEXT failed: %d\n", WSAGetLastError());
        ret = -1;
    }
    return ret;
}

#endif

/* Open a client socket, and start a connect to the destination.
* We want this to be asynchronous.
* See https://cr.yp.to/docs/connect.html for more details.
*/
picoqmux_socket_ctx_t* picoquic_packet_loop_open_qmux_client_socket(
    picoquic_quic_t* qmux, struct sockaddr* dest, picoquic_cnx_t* cnx)
{
    picoqmux_socket_ctx_t* sqmux_sock_ctx = picoquic_packet_loop_open_qmux_socket(
        dest->sa_family, 0, 0, 0);
    if (sqmux_sock_ctx != NULL) {
        picoquic_store_addr(&sqmux_sock_ctx->remote_addr, dest);
        sqmux_sock_ctx->is_connecting = 1;
#ifdef _WINDOWS
        if (picoquic_packet_loop_start_windows_connect(
            sqmux_sock_ctx, dest) != 0) {
            DBG_PRINTF("Cannot connect to destination (af=%d)\n", dest->sa_family);
            picoquic_packet_loop_free_qmux_socket(sqmux_sock_ctx);
            return NULL;
        }
#else
        int sock_ret = connect(sqmux_sock_ctx->fd, dest,
            (socklen_t)((dest->sa_family == AF_INET) ?
                sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)));
        if (sock_ret != 0  && errno != EINPROGRESS) {
            DBG_PRINTF("Cannot connect to destination (af=%d)\n", dest->sa_family);
            picoquic_packet_loop_free_qmux_socket(sqmux_sock_ctx);
            return NULL;
        }
        sqmux_sock_ctx->is_connecting = (sock_ret != 0);
#endif
        sqmux_sock_ctx->cnx = cnx;
    }
    return sqmux_sock_ctx;
}

void picoquic_packet_loop_free_qmux_sockets(picoqmux_socket_ctx_t*** sqmux_ctx,
    int nb_qmux_sockets)
{
    if (*sqmux_ctx != NULL) {
        for (int i = 0; i < nb_qmux_sockets; i++) {
            picoquic_packet_loop_free_qmux_socket((*sqmux_ctx)[i]);
            (*sqmux_ctx)[i] = NULL;
        }
        free(*sqmux_ctx);
        *sqmux_ctx = NULL;
    }
}

int picoquic_packet_loop_open_qmux_sockets(
    picoquic_quic_t* qmux,
    picoqmux_socket_ctx_t*** sqmux_ctx,
    int* nb_qmux_sockets,
    int* max_qmux_socket,
    int public_port)
{
    int ret = 0;

    *sqmux_ctx = NULL;
    *nb_qmux_sockets = 0;
    *max_qmux_socket = 0;

    if (qmux != NULL) {
        *max_qmux_socket = qmux->max_number_connections + 2;
        *sqmux_ctx = (picoqmux_socket_ctx_t**)malloc(sizeof(picoqmux_socket_ctx_t*) * (*max_qmux_socket));
        if (*sqmux_ctx == NULL) {
            DBG_PRINTF("%s", "Cannot allocate memory for QMUX socket context\n");
            *max_qmux_socket = 0;
            ret = -1;
        }
        else {
            memset(*sqmux_ctx, 0, sizeof(picoqmux_socket_ctx_t*) * (*max_qmux_socket));
            if (public_port != 0) {
                for (int i = 0; i < 2; i++) {
                    if (((*sqmux_ctx)[i] = picoquic_packet_loop_open_qmux_socket(/*qmux,*/
                        (i == 0) ? AF_INET : AF_INET6, (uint16_t)public_port, 1, 1)) == NULL) {
                        ret = -1;
                        break;
                    }
                    (*sqmux_ctx)[i]->is_listening = 1;
                    (*nb_qmux_sockets) += 1;
                }
            }
            if (ret == 0) {
                ret = picoquic_packet_loop_start_windows_accept_sockets(
                    *sqmux_ctx, nb_qmux_sockets, *max_qmux_socket);
            }
        }
        if (ret != 0) {
            /* Free the qmux contexts */
            picoquic_packet_loop_free_qmux_sockets(sqmux_ctx, *nb_qmux_sockets);
        }
    }
    return ret;
}

int picoquic_packet_loop_open_qmux_cnx_sockets(
    picoquic_quic_t * qmux,
    picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets,
    int max_qmux_socket,
    uint64_t current_time) 
{
    int ret = 0;

    if (qmux != NULL) {
        picoquic_cnx_t* cnx = qmux->cnx_list;
        while (cnx != NULL) {
            if (*nb_qmux_sockets < max_qmux_socket) {
                struct sockaddr* dest =
                    (struct sockaddr*)&cnx->path[0]->first_tuple->peer_addr;
                if ((sqmux_ctx[*nb_qmux_sockets] = 
                    picoquic_packet_loop_open_qmux_client_socket(qmux, dest, cnx)) == NULL) {
                    ret = -1;
                    break;
                }

                cnx = cnx->next_in_table;
                (*nb_qmux_sockets) += 1;
            }
        }
    }
    return ret;
}



#if defined(_WINDOWS)
/*
* Windows: use asynchronous receive. Asynchronous receive requires
* declaring an overlap context and event per socket, as well as a
* buffer per socket. This should probably be an option. Instead of
* calling socket, just use a "wait for event" to find out which
* readmsg has completed on what socket. If a read is available,
* return it. The memory is allocated per socket. After the loop
* has processed the message, it needs to "rearm" the socket to
* ready it for the next message.
* 
* If using QMUX, use asynchronous operations for send/recv/accept.
* 
* The outcome of the combine QUIC/QMUX wait will be:
* 
* - event type:
*      - timeout
*      - wakeup
*      - receive QUIC datagram,
*      - new socket TCP ready after accept,
*      - data has arrived on TCP socket,
*      - data can be sent on TCP socket.
*/
int picoquic_packet_loop_wait(
    picoquic_socket_ctx_t* s_ctx,
    int nb_sockets,
    picoqmux_socket_ctx_t** sqmux_ctx,
    int nb_qmux_sockets,
    uint64_t current_time,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    uint8_t** received_buffer,
    int64_t delta_t,
    picoquic_network_thread_ctx_t* thread_ctx,
    picoquic_packet_loop_action_enum* action,
    int* socket_rank)
{
    int bytes_recv = 0;
    HANDLE events[256];
    int w_event_ptr[128];
    DWORD ret_event;
    DWORD nb_events = 0;
    DWORD qmux_recv_events = 0;
    DWORD qmux_send_events = 0;
    DWORD wake_up_event_rank = 0;
    DWORD dwDeltaT = (DWORD)((delta_t <= 0) ? 0 : (delta_t / 1000));
    int socket_was_ready = 0;
    int socket_ready_rank = 0;
    int socket_error = 0;

    for (int i = 0; i < 4 && i < nb_sockets; i++) {
        events[i] = s_ctx[i].overlap.hEvent;
        nb_events++;
    }
    *action = picoquic_packet_loop_action_none;
    if (thread_ctx->wake_up_defined) {
        wake_up_event_rank = nb_events;
        events[nb_events] = thread_ctx->wake_up_event;
        nb_events++;
    }
    /* TODO: set limit to number of TCP sockets. */
    qmux_recv_events = nb_events;
    for (int i = 0; i < nb_qmux_sockets && qmux_recv_events < 256; i++) {
        if (sqmux_ctx[i]->cnx != NULL &&
            !sqmux_ctx[i]->is_receiving &&
            !sqmux_ctx[i]->is_listening &&
            !sqmux_ctx[i]->is_accepting &&
            !sqmux_ctx[i]->is_connecting) {
            socket_error = picoquic_packet_loop_start_windows_recv(sqmux_ctx[i]);
            if (!sqmux_ctx[i]->is_receiving) {
                /* No receive is pending, so we won't wait for it. */
                socket_was_ready = 1;
                socket_ready_rank = i;
                break;
            }
        }
        events[qmux_recv_events] = sqmux_ctx[i]->winbuf_r.overlap.hEvent;
        qmux_recv_events++;
    }
    qmux_send_events = qmux_recv_events;
    if (socket_was_ready) {
        /* The call to wsarecv returned immadiately, no need to wait for more data */
        *action = picoquic_packet_loop_action_tcp_recv_ready;
        *socket_rank = socket_ready_rank;
        if (socket_error) {
            bytes_recv = -1;
        }
        else {
            bytes_recv = (int)sqmux_ctx[socket_ready_rank]->winbuf_r.buf_len;
        }
    }
    else {
        /* wait for the next send event. */
        for (int i = 0; i < nb_qmux_sockets && qmux_send_events < 256; i++) {
            if (sqmux_ctx[i]->cnx != NULL && sqmux_ctx[i]->cnx->next_wake_time <= current_time) {
                if (!sqmux_ctx[i]->is_sending &&
                    !sqmux_ctx[i]->is_accepting &&
                    !sqmux_ctx[i]->is_connecting) {
                    if (picoquic_sockloop_start_windows_send(sqmux_ctx[i], current_time) != 0) {
                        DBG_PRINTF("Cannot start send on socket %d, error 0x%x\n",
                            (int)sqmux_ctx[i]->fd, WSAGetLastError());
                    }
                }
                if (sqmux_ctx[i]->is_sending) {
                    events[qmux_send_events] = sqmux_ctx[i]->winbuf_w.overlap.hEvent;
                    w_event_ptr[qmux_send_events - qmux_recv_events] = i;
                    qmux_send_events++;
                }
            }
        }

            ret_event = WSAWaitForMultipleEvents(qmux_send_events, events, FALSE, dwDeltaT, TRUE);

            if (ret_event == WSA_WAIT_FAILED) {
                DBG_PRINTF("WSAWaitForMultipleEvents fails, error 0x%x", WSAGetLastError());
                bytes_recv = -1;
            }
            else if (ret_event == STATUS_TIMEOUT) {
                *action = picoquic_packet_loop_action_timeout;
                bytes_recv = 0;
            }
            else if (ret_event >= WSA_WAIT_EVENT_0) {
                DWORD event_rank = ret_event - WSA_WAIT_EVENT_0;

                if ((int)event_rank < nb_sockets) {
                    *action = picoquic_packet_loop_action_udp_received;
                    *socket_rank = (int)event_rank;
                    /* if received data on a socket, process it. */
                    int ret = picoquic_win_recvmsg_async_finish(&s_ctx[*socket_rank]);
                    ResetEvent(s_ctx[*socket_rank].overlap.hEvent);

                    if (ret != 0) {
                        DBG_PRINTF("%s", "Cannot finish async recv");
                        bytes_recv = -1;
                    }
                    else {
                        bytes_recv = s_ctx[*socket_rank].bytes_recv;
                        *received_ecn = s_ctx[*socket_rank].received_ecn;
                        *received_buffer = s_ctx[*socket_rank].recv_buffer;
                        picoquic_store_addr(addr_dest, (struct sockaddr*)&s_ctx[*socket_rank].addr_dest);
                        picoquic_store_addr(addr_from, (struct sockaddr*)&s_ctx[*socket_rank].addr_from);
                        /* Document incoming port */
                        if (addr_dest->ss_family == AF_INET6) {
                            ((struct sockaddr_in6*)addr_dest)->sin6_port = s_ctx[*socket_rank].n_port;
                        }
                        else if (addr_dest->ss_family == AF_INET) {
                            ((struct sockaddr_in*)addr_dest)->sin_port = s_ctx[*socket_rank].n_port;
                        }
                    }
                }
                else if (thread_ctx->wake_up_defined && event_rank == wake_up_event_rank) {
                    *action = picoquic_packet_loop_action_wake_up;
                    if (ResetEvent(thread_ctx->wake_up_event) == 0) {
                        DBG_PRINTF("Cannot reset network event, error 0x%x", GetLastError());
                        bytes_recv = -1;
                    }
                }
                else if (event_rank < qmux_recv_events) {
                    *socket_rank = event_rank - nb_events;
                    ResetEvent(sqmux_ctx[*socket_rank]->winbuf_r.overlap.hEvent);

                    if (sqmux_ctx[*socket_rank]->is_listening) {
                        /* Should not happen! */
                    }
                    else if (sqmux_ctx[*socket_rank]->is_accepting) {
                        if (picoquic_packet_loop_complete_windows_accept(
                            sqmux_ctx, *socket_rank) != 0) {
                            DBG_PRINTF("Cannot complete accept on socket %d, error 0x%x\n",
                                (int)sqmux_ctx[*socket_rank]->fd, WSAGetLastError());
                            bytes_recv = -1;
                        }
                        else {
                            /* New connection accepted. */
                            *action = picoquic_packet_loop_action_tcp_accept_ready;
                        }
                    }
                    else if (sqmux_ctx[*socket_rank]->is_connecting) {
                        if (picoquic_packet_loop_complete_windows_connect(sqmux_ctx[*socket_rank]) != 0) {
                            bytes_recv = -1;
                        }
                        *action = picoquic_packet_loop_action_none;
                    }
                    else {
                        /* Receive Qmux data on a TCP socket. */
                        *action = picoquic_packet_loop_action_tcp_recv_ready;
                        int ret = picoquic_sockloop_finish_windows_recv(sqmux_ctx[*socket_rank]);
                        if (ret != 0) {
                            DBG_PRINTF("Cannot finish recv on socket %d, error 0x%x\n",
                                (int)sqmux_ctx[*socket_rank]->fd, WSAGetLastError());
                            bytes_recv = -1;
                        }
                        else {
                            bytes_recv = (int)sqmux_ctx[*socket_rank]->winbuf_r.buf_len;
                        }
                    }
                }
                else {
                    *socket_rank = w_event_ptr[event_rank - qmux_recv_events];
                    ResetEvent(sqmux_ctx[*socket_rank]->winbuf_w.overlap.hEvent);
                    /* Setting the action to None, because completion is immediate */
                    *action = picoquic_packet_loop_action_none;
                    int ret = picoquic_sockloop_finish_windows_send(sqmux_ctx[*socket_rank]);
                    if (ret != 0) {
                        DBG_PRINTF("Cannot finish recv on socket %d, error 0x%x\n",
                            (int)sqmux_ctx[*socket_rank]->fd, WSAGetLastError());
                        bytes_recv = -1;
                    }
                }
            }
        }
    return bytes_recv;
}

#elif defined(PICOQUIC_WITH_IO_URING)
/* Preparing IO uring. Reserve a sufficient large ring.
* Not using any flag for now.
*/
int picoquic_packet_loop_prep_uring(struct io_uring* ring)
{
    int ret = io_uring_queue_init(
        2*(1 + PICOQUIC_PACKET_LOOP_SOCKETS_MAX + 1),
        ring,
        0);
    /* TO DO: issue a first request for the "pipe" if used. */
    return ret;
}

/* Allocation of memory for the recvmsg operation.
* We need:
* - struct msghdr: to hold the description of the recv_msg
* - msg_iov: to hold the resulting cmsg
* - iov_databuf: the actual value.
* - data buffer: to hold the packet.
* It is probably possible to *map* these buffers, and operate
* with zero copy. However, we need more time to understand exactly
* how this works.
* It should also be possble to use recv to get multiple messages, but
* this is not quite in the "spirit" of io_uring: it seems simpler to
* just queue multiple sqe, and process them. or, maybe, just use the
* *multishot* API.
* The first implementation is the "dancing bear" stage. Let's get it
* dance, worry next about how well and how fast.
 */
void  picoquic_packet_loop_recv_buf_uring_free(picoquic_socket_ctx_t* s_ctx)
{
    if (s_ctx->ctrl_buffer != NULL) {
        free(s_ctx->ctrl_buffer);
        s_ctx->ctrl_buffer = NULL;
    }
    if (s_ctx->data_iovec.iov_base != NULL) {
        free(s_ctx->data_iovec.iov_base);
        s_ctx->data_iovec.iov_base = NULL;
    }
    memset(&s_ctx->msg, 0, sizeof(s_ctx->msg));
}

int picoquic_packet_loop_recv_buf_uring_init(picoquic_socket_ctx_t* s_ctx)
{
    int ret = 0;
    s_ctx->ctrl_buffer = (uint8_t*)malloc(1024);
    s_ctx->data_iovec.iov_base = (uint8_t*)malloc(PICOQUIC_MAX_PACKET_SIZE);
    if (s_ctx->ctrl_buffer == NULL || s_ctx->data_iovec.iov_base == NULL) {
        picoquic_packet_loop_recv_buf_uring_free(s_ctx);
        ret = -1;
    }
    else {
        s_ctx->data_iovec.iov_len = PICOQUIC_MAX_PACKET_SIZE;
    }
    return ret;
}

/* starting a recvcmsg request on a specific socket.
* In contrast with the "immediate" version, this requires making
* sure that the "struct msghdr" and the "data buffer" remain
* valid for the duration of the call. 
* Design questions:
* 1- should the "fd" be mapped, or it it OK to pass the value.
* 2- should the buffer be mapped?
*/

int picoquic_packet_loop_start_recvmsg(struct io_uring* ring, picoquic_socket_ctx_t* s_ctx, uint64_t request_id)
{
    int ret = 0;
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);

    if (sqe == NULL ||
        (s_ctx->ctrl_buffer == NULL &&
            picoquic_packet_loop_recv_buf_uring_init(s_ctx) != 0)) {
        ret = -1;
    }
    else {
        struct msghdr* msg = &s_ctx->msg;
        memset(msg, 0, sizeof(struct msghdr));
        msg->msg_name = (struct sockaddr*)&s_ctx->addr_from;
        msg->msg_namelen = sizeof(struct sockaddr_storage);
        msg->msg_iov = &s_ctx->data_iovec;
        msg->msg_iovlen = 1;
        msg->msg_flags = 0;
        msg->msg_control = (void*)s_ctx->ctrl_buffer;
        msg->msg_controllen = 1024;
        s_ctx->is_io_uring_started = 1;

        io_uring_prep_recvmsg(sqe, s_ctx->fd, msg, 0);
        io_uring_sqe_set_data64(sqe, request_id);
    }
    return ret;
}

/* starting a readv request on the communication pipe.
*/
void picoquic_packet_loop_pipe_buffer_uring_free(picoquic_network_thread_ctx_t* thread_ctx)
{
    if (thread_ctx->pipe_iovec.iov_base != NULL) {
        free(thread_ctx->pipe_iovec.iov_base);
        thread_ctx->pipe_iovec.iov_base = NULL;
    }
}

int picoquic_packet_loop_pipe_buffer_uring_init(picoquic_network_thread_ctx_t* thread_ctx)
{
    int ret = 0;
    thread_ctx->pipe_iovec.iov_base = (uint8_t*)malloc(128);
    if (thread_ctx->pipe_iovec.iov_base == NULL) {
        ret = -1;
    }
    else {
        thread_ctx->pipe_iovec.iov_len = 128;
    }
    return ret;
}

int picoquic_packet_loop_start_pipe_readv(struct io_uring* ring, picoquic_network_thread_ctx_t* thread_ctx, uint64_t request_id)
{
    int ret = 0;
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);

    if (sqe == NULL ||
        (thread_ctx->pipe_iovec.iov_base == NULL &&
            picoquic_packet_loop_pipe_buffer_uring_init(thread_ctx) != 0)) {
        ret = -1;
    }
    else {
        io_uring_prep_readv(sqe, 
            (int)thread_ctx->wake_up_pipe_fd[0],
            &thread_ctx->pipe_iovec,
            1,
            0);
        io_uring_sqe_set_data64(sqe, request_id);
    }
    return ret;
}
/* Do the Uring loop.
* Wait until CQE or time.
* process CQE. Return buffer if any.
* Consider maybe using double buffers so one recv can execute while
* the other waits.
*/
int picoquic_packet_loop_uring(
    struct io_uring* ring,
    picoquic_socket_ctx_t* s_ctx,
    int nb_sockets,
    int64_t delta_t,
    picoquic_network_thread_ctx_t* thread_ctx,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    int* is_wake_up_event,
    unsigned char* received_ecn,
    uint8_t** received_buffer,
    picoquic_packet_loop_action_enum* action,
    int* socket_rank)
{
    int ret = 0;
    int bytes_recv = 0;

    /* Restart the wake pipe if needed. */
    if (thread_ctx->wake_up_defined && !thread_ctx->is_pipe_io_uring_started){
        ret = picoquic_packet_loop_start_pipe_readv(ring, thread_ctx, 0);
        thread_ctx->is_pipe_io_uring_started = 1;
    }
    /* Restart the socket if needed */
    for (int i = 0; ret == 0 && i < nb_sockets; i++) {
        if (!s_ctx[i].is_started) {
            ret = picoquic_packet_loop_start_recvmsg(ring, & s_ctx[i], i+1);
            s_ctx[i].is_started = 1;
        }
    }
    if (ret != 0) {
        bytes_recv = -1;
    } else {
        struct io_uring_cqe* cqe;
        struct __kernel_timespec ts;
        int io_ret;

        *action = picoquic_packet_loop_action_none;
        (void)io_uring_submit(ring);
        /* set the timeout value */
        ts.tv_sec = delta_t / 1000000;
        ts.tv_nsec = (delta_t - 1000 * ts.tv_sec) * 1000;
        /* call wait for sqe or timeout */
        io_ret = io_uring_wait_cqe_timeout(ring, &cqe, &ts);
        if (io_ret == 0) {
            /* Normal case. First, get the data and identify the socket */
            uint64_t id64 = io_uring_cqe_get_data64(cqe);
            if (id64 == 0) {
                /* This is the wake up pipe. We don't care about the data. */
                *action = picoquic_packet_loop_action_wake_up;
                *received_buffer = NULL;
                bytes_recv = 0;
                thread_ctx->is_pipe_io_uring_started = 0;
                if (cqe->res < 0) {
                    /* error condition */
                    bytes_recv = cqe->res;
                }
                else if (cqe->res == 0) {
                    bytes_recv = -1;
                }
                *action = picoquic_packet_loop_action_wake_up;
            }
            else {
                /* sendmsg completed on socket id64 - 1. */
                int i = (int)id64 - 1;
                *socket_rank = i;
                s_ctx[i].is_started = 0;
                if (cqe->res < 0) {
                    /* error condition */
                    ret = -cqe->res;
                    bytes_recv = cqe->res;
                    *received_buffer = NULL;
                }
                else {
                    /* parse the cmsg */
                    picoquic_socks_cmsg_parse(&s_ctx[i].msg, addr_dest, dest_if, received_ecn, NULL);
                    /* document bytes received */
                    bytes_recv = cqe->res;
                    *received_buffer = s_ctx[i].data_iovec.iov_base;
                    *action = picoquic_packet_loop_action_udp_received;
                }
            }
        }
        else if (io_ret == -ETIME) {
            /* timeout expired: no bytes received */
            *received_buffer = NULL;
            bytes_recv = 0;
            *action = picoquic_packet_loop_action_timeout;
        }
        else {
            /* error */
            ret = -1;
        }
    }
    return bytes_recv;
}

void io_uring_cancel_and_free(
    struct io_uring* ring,
    picoquic_socket_ctx_t* s_ctx,
    int nb_sockets,
    picoquic_network_thread_ctx_t* thread_ctx)
{
    struct io_uring_sqe* sqe = io_uring_get_sqe(ring);

    if (sqe != NULL) {
        io_uring_prep_cancel64(sqe, 0, IORING_ASYNC_CANCEL_ANY);
    }
    /* Free the wake pipe if needed. */
    if (thread_ctx->wake_up_defined) {
        picoquic_packet_loop_pipe_buffer_uring_free(thread_ctx);
    }
    /* Free the socket if needed */
    for (int i = 0; i < nb_sockets; i++) {
        picoquic_packet_loop_recv_buf_uring_free(&s_ctx[i]);
    }
}


#elif defined(PICOQUIC_WITH_POLL)
/* If using Poll(), we need to build a poll list that includes the
* UDP and TCP socket. We will declare the TCP sockets ready for
* writing if their wakeup time is <= current time.
*/
void picoquic_packet_loop_set_fds(
    struct pollfd* poll_list,
    size_t poll_list_size,
    picoquic_socket_ctx_t* s_ctx,
    int nb_sockets,
    picoqmux_socket_ctx_t** sqmux_ctx,
    int nb_qmux_sockets,
    picoquic_network_thread_ctx_t* thread_ctx,
    uint64_t current_time)
{
    int i_poll = 0;
    int i_poll_qmux = nb_sockets;

    if (poll_list_size < (size_t)(nb_sockets + nb_qmux_sockets + 1)) {
        DBG_PRINTF("Error: poll list size %d is too small for %d sockets and %d qmux sockets\n",
            (int)poll_list_size, nb_sockets, nb_qmux_sockets);
        return;
    }

    memset(poll_list, 0, sizeof(struct pollfd) * poll_list_size);

    if (thread_ctx->wake_up_defined) {
        poll_list[0].fd = (int)thread_ctx->wake_up_pipe_fd[0];
        poll_list[0].events = POLLIN;
        i_poll = 1;
        i_poll_qmux += 1;
    }
    for (int i = 0; i < nb_sockets; i++) {
        poll_list[i_poll+i].fd = (int)s_ctx[i].fd;
        poll_list[i_poll+i].events = POLLIN;
    }
    for (int i = 0; i < nb_qmux_sockets; i++) {
        poll_list[i + i_poll_qmux].fd = (int)sqmux_ctx[i]->fd;
        poll_list[i + i_poll_qmux].events =
            (sqmux_ctx[i]->cnx->next_wake_time <= current_time)?(POLLIN|POLLOUT):POLLIN;
    }
    for (int i = i_poll_qmux + nb_qmux_sockets; i < (int)poll_list_size; i++) {
        poll_list[i].fd = -1;
    }
}

int picoquic_packet_loop_poll(
    picoquic_socket_ctx_t* s_ctx,
    int nb_sockets,
    picoqmux_socket_ctx_t** sqmux_ctx,
    int nb_qmux_sockets,
    uint64_t current_time,
    struct pollfd* poll_list,
    size_t poll_list_size,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    uint8_t* buffer, int buffer_max,
    int64_t delta_t,
    picoquic_network_thread_ctx_t* thread_ctx,
    picoquic_packet_loop_action_enum* action,
    int* socket_rank)
{
    /* Picoquic expresses times in microseconds, but the timeout 
     * parameter of poll() is in milliseconds. The code below converts
     * the microsecond delay to the nearest millisecond, which is a
     * compromise. Return a smaller value than the timer incurs the
     * risk of waking up too soon, e.g., waiting "0" ms instead of
     * 499us, probably leading to an extra call to "poll". Returning a
     * larger value carries the opposite risk, waiting to long and thus
     * slowing down operations. We may need to change this code later
     * based on experience */
    int delta_t_ms = (int)((delta_t + 500) / 1000);
    int bytes_recv = 0;
    int i_poll = (thread_ctx->wake_up_defined) ? 1 : 0;
    int i_qmux_poll = i_poll + nb_sockets;
    int poll_max = i_qmux_poll + nb_qmux_sockets;
    int ret_poll;

    if (poll_list_size < (size_t)poll_max) {
        DBG_PRINTF("Error: poll list size %d is too small for %d sockets and %d qmux sockets (%d)\n",
            (int)poll_list_size, nb_sockets, nb_qmux_sockets, poll_max);
        return -1;
    }

    picoquic_packet_loop_set_fds(poll_list, poll_list_size, s_ctx, nb_sockets, sqmux_ctx, nb_qmux_sockets,
        thread_ctx, current_time);
    ret_poll = poll(poll_list, poll_max, delta_t_ms);

    if (received_ecn != NULL) {
        *received_ecn = 0;
    }
    *action = picoquic_packet_loop_action_none;

    if (ret_poll < 0) {
        bytes_recv = -1;
        DBG_PRINTF("Error: poll returns %d\n", ret_poll);
    }
    else if (ret_poll == 0) {
        *action = picoquic_packet_loop_action_timeout;
    }
    else if (ret_poll > 0) {
        /* Check if the 'wake up' pipe is full. If it is, read the data on it,
         * set the action as wake_up */

        if (thread_ctx->wake_up_defined && poll_list[0].revents != 0) {
            /* Something was written on the "wakeup" pipe. Read it. */
            uint8_t eventbuf[8];
            int pipe_recv;
            DBG_PRINTF("Waking up -- defined: %d, nb_sockets: %d",
                (thread_ctx->wake_up_defined) ? 1 : 0, nb_sockets);
            if ((pipe_recv = read(thread_ctx->wake_up_pipe_fd[0], eventbuf, sizeof(eventbuf))) <= 0) {
                bytes_recv = -1;
                DBG_PRINTF("Error: read pipe returns %d\n", (pipe_recv == 0) ? EPIPE : errno);
            }
            else {
                DBG_PRINTF("Waking up -- received: %d", pipe_recv); 
                *action = picoquic_packet_loop_action_wake_up;
            }
        }
        else
        {
            /* Find the first UDP event */
            for (int i = 0; i < nb_sockets; i++) {
                if (poll_list[i+i_poll].revents != 0) {
                    *socket_rank = i;
                    bytes_recv = picoquic_recvmsg(s_ctx[i].fd, addr_from,
                        addr_dest, dest_if, received_ecn,
                        buffer, buffer_max);
                    if (bytes_recv <= 0) {
                        DBG_PRINTF("Could not receive packet on UDP socket[%d]= %d!\n",
                            i, (int)s_ctx[i].fd);
                        break;
                    }
                    else {
                        /* Document incoming port */
                        if (addr_dest->ss_family == AF_INET6) {
                            ((struct sockaddr_in6*)addr_dest)->sin6_port = s_ctx[i].n_port;
                        }
                        else if (addr_dest->ss_family == AF_INET) {
                            ((struct sockaddr_in*)addr_dest)->sin_port = s_ctx[i].n_port;
                        }
                        *action = picoquic_packet_loop_action_udp_received;
                        break;
                    }
                }
            }
            if (bytes_recv == 0 && *action == picoquic_packet_loop_action_none) {
                /* Try to find the first TCP event */
                for (int i = 0; i < nb_qmux_sockets; i++) {
                    if ((poll_list[i + i_qmux_poll].revents & POLLIN) != 0) {
                        *socket_rank = i;
                        *action = (sqmux_ctx[i]->is_listening) ?
                            picoquic_packet_loop_action_tcp_accept_ready:
                            picoquic_packet_loop_action_tcp_recv_ready;
                        break;
                    }
                    else if ((poll_list[i + i_qmux_poll].revents & POLLOUT) != 0) {
                        *socket_rank = i;
                        *action = picoquic_packet_loop_action_tcp_send_ready;
                        break;
                    }
                }
            }
        }
    }

    return bytes_recv;
}
#else
int picoquic_packet_loop_select(picoquic_socket_ctx_t* s_ctx,
    int nb_sockets,
    picoqmux_socket_ctx_t** sqmux_ctx,
    int nb_qmux_sockets,
    uint64_t current_time,
    struct sockaddr_storage* addr_from,
    struct sockaddr_storage* addr_dest,
    int* dest_if,
    unsigned char* received_ecn,
    uint8_t* buffer, int buffer_max,
    int64_t delta_t,
    picoquic_network_thread_ctx_t* thread_ctx,
    picoquic_packet_loop_action_enum* action,
    int* socket_rank)
{
    fd_set readfds;
    fd_set writefds;
    struct timeval tv;
    int ret_select = 0;
    int bytes_recv = 0;
    int sockmax = 0;

    if (received_ecn != NULL) {
        *received_ecn = 0;
    }

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    for (int i = 0; i < nb_sockets; i++) {
        if (sockmax < (int)s_ctx[i].fd) {
            sockmax = (int)s_ctx[i].fd;
        }
        FD_SET(s_ctx[i].fd, &readfds);
    }

    for (int i = 0; i < nb_qmux_sockets; i++) {
        if (sockmax < (int)sqmux_ctx[i]->fd) {
            sockmax = (int)sqmux_ctx[i]->fd;
        }
        FD_SET(sqmux_ctx[i]->fd, &readfds);
        if (sqmux_ctx[i]->cnx->next_wake_time <= current_time) {
            FD_SET(sqmux_ctx[i]->fd, &writefds);
        }
    }

    *action = picoquic_packet_loop_action_none;
    if (thread_ctx->wake_up_defined) {
        if (sockmax < (int)thread_ctx->wake_up_pipe_fd[0]) {
            sockmax = (int)thread_ctx->wake_up_pipe_fd[0];
        }
        FD_SET(thread_ctx->wake_up_pipe_fd[0], &readfds);
    }

    if (delta_t <= 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    }
    else {
        if (delta_t > 10000000) {
            tv.tv_sec = (long)10;
            tv.tv_usec = 0;
        }
        else {
            tv.tv_sec = (long)(delta_t / 1000000);
            tv.tv_usec = (long)(delta_t % 1000000);
        }
    }

    ret_select = select(sockmax + 1, &readfds, &writefds, NULL, &tv);

    if (ret_select < 0) {
        bytes_recv = -1;
        DBG_PRINTF("Error: select returns %d\n", ret_select);
    }
    else if (ret_select == 0) {
        *action = picoquic_packet_loop_action_timeout;
    }
    else {
        /* Check if the 'wake up' pipe is full. If it is, read the data on it,
         * set the is_wake_up_event flag, and ignore the other file descriptors. */
        if (thread_ctx->wake_up_defined && FD_ISSET(thread_ctx->wake_up_pipe_fd[0], &readfds)) {
            /* Something was written on the "wakeup" pipe. Read it. */
            uint8_t eventbuf[8];
            int pipe_recv;
            if ((pipe_recv = read(thread_ctx->wake_up_pipe_fd[0], eventbuf, sizeof(eventbuf))) <= 0) {
                bytes_recv = -1;
                DBG_PRINTF("Error: read pipe returns %d\n", (pipe_recv == 0) ? EPIPE : errno);
            }
            else {
                *action = picoquic_packet_loop_action_wake_up;
            }
        }
        else
        {
            /* return the first UDP socket that is ready to receive */
            for (int i = 0; i < nb_sockets; i++) {
                if (FD_ISSET(s_ctx[i].fd, &readfds)) {
                    *socket_rank = i;
                    bytes_recv = picoquic_recvmsg(s_ctx[i].fd, addr_from,
                        addr_dest, dest_if, received_ecn,
                        buffer, buffer_max);

                    if (bytes_recv <= 0) {
                        DBG_PRINTF("Could not receive packet on UDP socket[%d]= %d!\n",
                            i, (int)s_ctx[i].fd);
                        break;
                    }
                    else {
                        /* Document incoming port */
                        if (addr_dest->ss_family == AF_INET6) {
                            ((struct sockaddr_in6*)addr_dest)->sin6_port = s_ctx[i].n_port;
                        }
                        else if (addr_dest->ss_family == AF_INET) {
                            ((struct sockaddr_in*)addr_dest)->sin_port = s_ctx[i].n_port;
                        }
                        *action = picoquic_packet_loop_action_udp_received;
                        break;
                    }
                }
            }
            if (bytes_recv == 0 && *action == picoquic_packet_loop_action_none) {
                /* Return the first TCP socket ready to write or receive */
                for (int i = 0; i < nb_qmux_sockets; i++) {
                    if (FD_ISSET(sqmux_ctx[i]->fd, &readfds)) {
                        *socket_rank = i;
                        *action = (sqmux_ctx[i]->is_listening) ?
                            picoquic_packet_loop_action_tcp_accept_ready :
                            picoquic_packet_loop_action_tcp_recv_ready;
                        break;
                    }
                    else if (FD_ISSET(sqmux_ctx[i]->fd, &writefds)) {
                        *socket_rank = i;
                        *action = picoquic_packet_loop_action_tcp_send_ready;
                        break;
                    }
                }
            }
        }
    }
    return bytes_recv;
}
#endif

static int monitor_system_call_duration(packet_loop_system_call_duration_t* sc_duration, uint64_t current_time, uint64_t previous_time)
{
    uint64_t duration = current_time - previous_time;
    int64_t dev = sc_duration->scd_smoothed - duration;
    int shall_notify = 0;

    if (duration > sc_duration->scd_max) {
        shall_notify = 1;
        sc_duration->scd_max = duration;
    }
    else if (duration != sc_duration->scd_last) {
        int64_t delta_d = sc_duration->scd_last - duration;

        if (delta_d > 1000 || delta_d < -1000 || delta_d < (int64_t)sc_duration->scd_last) {
            shall_notify = 1;
        }
        sc_duration->scd_last = duration;
    }

    sc_duration->scd_smoothed = (duration + 15 * sc_duration->scd_smoothed) / 16;
    if (dev < 0) {
        dev = -dev;
    }
    sc_duration->scd_dev = (7 * sc_duration->scd_dev + dev) / 8;

    return shall_notify;
}

/* Process an incoming connection on a TCP "listen" socket */
int picoquic_packet_loop_do_tcp_accept(picoquic_quic_t* qmux,
    picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets,
    int max_qmux_sockets,
    int socket_rank,
    uint64_t current_time)
{
    int ret = 0;
    picoquic_cnx_t* cnx = NULL;

#ifdef _WINDOWS
    if ((cnx = picoqmux_create_qmux_cnx(qmux, current_time, 0, 0, NULL, NULL, NULL)) == NULL) {
        ret = -1;
    }
    else {
        sqmux_ctx[socket_rank]->cnx = cnx;
    }
#else
    SOCKET_TYPE new_socket = INVALID_SOCKET;
    struct sockaddr_storage addr_from;
    socklen_t addr_from_len = sizeof(addr_from);
    picoqmux_socket_ctx_t* new_ctx = NULL;

    memset(&addr_from, 0, sizeof(addr_from));
    if (*nb_qmux_sockets >= max_qmux_sockets) {
        ret = -1;
    }
    else if ((new_socket = accept(sqmux_ctx[socket_rank]->fd, (struct sockaddr*)&addr_from, &addr_from_len)) == INVALID_SOCKET) {
        ret = (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) ? 0 : -1;
    }
    else if (picoquic_packet_loop_set_qmux_nonblocking(new_socket) != 0 ||
        (cnx = picoqmux_create_qmux_cnx(qmux, current_time, 0, 0, NULL, NULL, NULL)) == NULL ||
        (new_ctx = (picoqmux_socket_ctx_t*)malloc(sizeof(picoqmux_socket_ctx_t))) == NULL) {
        ret = -1;
    }
    else {
        memset(new_ctx, 0, sizeof(picoqmux_socket_ctx_t));
        new_ctx->fd = new_socket;
        new_socket = INVALID_SOCKET;
        new_ctx->af = addr_from.ss_family;
        new_ctx->cnx = cnx;
        cnx = NULL;
        picoquic_store_addr(&new_ctx->remote_addr, (struct sockaddr*)&addr_from);
        if (picoquic_get_local_address(new_ctx->fd, &new_ctx->local_addr) != 0) {
            ret = -1;
        }
        else {
            if (new_ctx->local_addr.ss_family == AF_INET6) {
                new_ctx->port = ntohs(((struct sockaddr_in6*)&new_ctx->local_addr)->sin6_port);
            }
            else if (new_ctx->local_addr.ss_family == AF_INET) {
                new_ctx->port = ntohs(((struct sockaddr_in*)&new_ctx->local_addr)->sin_port);
            }
            sqmux_ctx[*nb_qmux_sockets] = new_ctx;
            new_ctx = NULL;
            (*nb_qmux_sockets) += 1;
        }
    }
    if (ret != 0) {
        if (new_socket != INVALID_SOCKET) {
            SOCKET_CLOSE(new_socket);
        }
        picoquic_packet_loop_free_qmux_socket(new_ctx);
        if (cnx != NULL) {
            picoquic_delete_cnx(cnx);
        }
    }
#endif
    return ret;
}

/* Closing a TCP socket, and notifying the qmux connection */
void picoquic_packet_loop_tcp_close(
    picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets,
    int max_qmux_sockets,
    int socket_rank,
    uint64_t current_time)
{
    /* close the socket, and remove it from the list. */
    if (sqmux_ctx[socket_rank]->fd != INVALID_SOCKET) {
        SOCKET_CLOSE(sqmux_ctx[socket_rank]->fd);
        sqmux_ctx[socket_rank]->fd = INVALID_SOCKET;
    }
    /* signal the connection loss to the quic connection, so
     * that it can close itself. */
    if (sqmux_ctx[socket_rank]->cnx != NULL) {
        picoqmux_incoming_packets(sqmux_ctx[socket_rank]->cnx, current_time, NULL, 0, 1);
        sqmux_ctx[socket_rank]->cnx = NULL;
    }
}

/* Process incoming data on a TCP socket */
int picoquic_packet_loop_do_tcp_read(
    picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets,
    int max_qmux_sockets,
    int socket_rank,
    uint64_t current_time,
    uint8_t* qmux_buffer,
    size_t qmux_buffer_size)
{
    /* assume that a global read buffer is available, and fill it */
    int ret = 0;
    uint8_t* buf;
    int recv_len;
#ifdef _WINDOWS
    buf = sqmux_ctx[socket_rank]->winbuf_r.buf;
    recv_len = (int)sqmux_ctx[socket_rank]->winbuf_r.buf_len;
#else
    buf = qmux_buffer;
    recv_len = recv(sqmux_ctx[socket_rank]->fd, (char*)qmux_buffer, (int)qmux_buffer_size, 0);
#endif
    if (recv_len <= 0) {
        /* error or connection closed. */
        if (recv_len < 0) {
            DBG_PRINTF("Error: recv returns %d\n", recv_len);
        }
        else {
            DBG_PRINTF("Connection closed by peer.\n");
        }
        /* close the socket, and remove it from the list. */
        picoquic_packet_loop_tcp_close(sqmux_ctx,
            nb_qmux_sockets,
            max_qmux_sockets,
            socket_rank,
            current_time);
    }
    else {
        /* Submit the data to the quic connection. */
        picoqmux_incoming_packets(sqmux_ctx[socket_rank]->cnx, current_time, buf, (size_t)recv_len, 0);
        if (sqmux_ctx[socket_rank]->cnx != NULL &&
            (sqmux_ctx[socket_rank]->cnx->cnx_state == picoquic_state_disconnected ||
                sqmux_ctx[socket_rank]->cnx->cnx_state == picoquic_state_closing_received)) {
            picoquic_packet_loop_tcp_close(sqmux_ctx,
                nb_qmux_sockets,
                max_qmux_sockets,
                socket_rank,
                current_time);
        }
    }
    return ret;
}

/* Process sending opportunity on a TCP socket */
int picoquic_packet_loop_do_tcp_send(
    picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets,
    int max_qmux_sockets,
    int socket_rank,
    uint64_t current_time,
    uint8_t* qmux_buffer,
    size_t qmux_buffer_size)
{
    picoqmux_socket_ctx_t* sqmux_sock_ctx = sqmux_ctx[socket_rank];
    int ret = 0;
    (void)qmux_buffer;

    if (sqmux_sock_ctx->send_buffer_offset >= sqmux_sock_ctx->send_buffer_length) {
        sqmux_sock_ctx->send_buffer_offset = 0;
        sqmux_sock_ctx->send_buffer_length = 0;

        if (sqmux_sock_ctx->send_buffer_size < qmux_buffer_size) {
            uint8_t* new_buffer = (uint8_t*)realloc(sqmux_sock_ctx->send_buffer, qmux_buffer_size);
            if (new_buffer == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            }
            else {
                sqmux_sock_ctx->send_buffer = new_buffer;
                sqmux_sock_ctx->send_buffer_size = qmux_buffer_size;
            }
        }

        if (ret == 0) {
            ret = picoqmux_prepare_packets(sqmux_sock_ctx->cnx, current_time,
                sqmux_sock_ctx->send_buffer, sqmux_sock_ctx->send_buffer_size,
                &sqmux_sock_ctx->send_buffer_length);
        }
    }

    if (ret == 0 && sqmux_sock_ctx->send_buffer_offset < sqmux_sock_ctx->send_buffer_length) {
        size_t available = sqmux_sock_ctx->send_buffer_length - sqmux_sock_ctx->send_buffer_offset;
        int send_length = (available > (size_t)INT_MAX) ? INT_MAX : (int)available;
        int sent_length = send(sqmux_sock_ctx->fd,
            (const char*)sqmux_sock_ctx->send_buffer + sqmux_sock_ctx->send_buffer_offset,
            send_length, 0);

        if (sent_length < 0) {
#ifdef _WINDOWS
            int last_error = WSAGetLastError();
            if (last_error == WSAEWOULDBLOCK || last_error == WSAEINPROGRESS) {
                sqmux_sock_ctx->cnx->next_wake_time = current_time;
            }
            else {
                ret = -1;
            }
#else
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                sqmux_sock_ctx->cnx->next_wake_time = current_time;
            }
            else {
                ret = -1;
            }
#endif
        }
        else if (sent_length == 0) {
            ret = -1;
        }
        else {
            sqmux_sock_ctx->send_buffer_offset += (size_t)sent_length;
            if (sqmux_sock_ctx->send_buffer_offset >= sqmux_sock_ctx->send_buffer_length) {
                sqmux_sock_ctx->send_buffer_offset = 0;
                sqmux_sock_ctx->send_buffer_length = 0;
            }
            else {
                sqmux_sock_ctx->cnx->next_wake_time = current_time;
            }
        }
    }
    if (ret != 0) {
        /* Socket error, could not send data, maybe closed. */
        picoquic_packet_loop_tcp_close(sqmux_ctx,
            nb_qmux_sockets,
            max_qmux_sockets,
            socket_rank,
            current_time);
    }
    return ret;
}

void picoquic_packet_loop_abandon_socket(
    picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets,
    int max_qmux_sockets,
    int* qmux_socket_was_closed,
    int socket_rank) {
    /* close the socket, and mark it for removal from the list. */
    SOCKET_CLOSE(sqmux_ctx[socket_rank]->fd);
    sqmux_ctx[socket_rank]->fd = INVALID_SOCKET;
    if (*qmux_socket_was_closed < 0 ||
        *qmux_socket_was_closed > socket_rank) {
        *qmux_socket_was_closed = socket_rank;
    }
}

int picoquic_packet_loop_check_qmux_timers(
    picoqmux_socket_ctx_t** sqmux_ctx,
    int* nb_qmux_sockets,
    int max_qmux_sockets,
    int * qmux_socket_was_closed,
    uint64_t current_time,
    uint8_t* qmux_buffer,
    size_t qmux_buffer_size)
{
    int ret = 0;
    for (int i = 0; i < *nb_qmux_sockets; i++) {
        if (sqmux_ctx[i]->cnx != NULL &&
            sqmux_ctx[i]->fd != INVALID_SOCKET &&
            sqmux_ctx[i]->cnx->next_wake_time <= current_time) {
            ret = picoquic_packet_loop_do_tcp_send(
                sqmux_ctx, nb_qmux_sockets, max_qmux_sockets, i, current_time,
                qmux_buffer, qmux_buffer_size);
            if (ret != 0 || sqmux_ctx[i]->cnx->cnx_state == picoquic_state_disconnected){
                /* That connection cannot continue. */
                picoquic_packet_loop_abandon_socket(sqmux_ctx, nb_qmux_sockets, max_qmux_sockets,
                    qmux_socket_was_closed, i);
                ret = 0;
            }
            break;
        }
    }
    return ret;
}

/* Process the packet that was just received on a UDP socket */
int picoquic_packet_loop_udp_received(
    picoquic_quic_t * quic,
    picoquic_cnx_t** last_cnx,
#ifdef _WINDOWS
    picoquic_socket_ctx_t *s_ctx,
    int socket_rank,
#endif
    uint8_t * received_buffer,
    int bytes_recv,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    uint8_t received_ecn,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx,
    uint64_t current_time,
    int nb_loop_immediate,
    int * loop_immediate
)
{
    int ret = 0;

    if (bytes_recv > 0) {
        /* TODO: This block should be "receive UDP packet" */
#ifdef _WINDOWS
        size_t recv_bytes = 0;
        while (recv_bytes < (size_t)bytes_recv && ret == 0) {
            size_t recv_length = (size_t)(bytes_recv - recv_bytes);

            if (s_ctx[socket_rank].udp_coalesced_size > 0 &&
                recv_length > s_ctx[socket_rank].udp_coalesced_size) {
                recv_length = s_ctx[socket_rank].udp_coalesced_size;
            }
            /* Submit the packet to the client */
            ret = picoquic_incoming_packet_ex(quic, received_buffer + recv_bytes,
                recv_length, addr_from, addr_to, if_index_to,
                received_ecn, last_cnx, current_time);
            recv_bytes += recv_length;
        }
        if (ret == 0) {
            ret = picoquic_win_recvmsg_async_start(&s_ctx[socket_rank]);
        }
#else
        /* Submit the packet to the server */
        ret = picoquic_incoming_packet_ex(quic, received_buffer,
            (size_t)bytes_recv, addr_from, addr_to, if_index_to, received_ecn,
            last_cnx, current_time);
#endif
        if (loop_callback != NULL) {
            size_t b_recvd = (size_t)bytes_recv;
            ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx, &b_recvd);
        }

        /* If the number of packets received in immediate mode has not
        * reached the threshold, set the "immediate" flag and bypass
        * the sending code.
         */
        if (ret == 0 && nb_loop_immediate < PICOQUIC_PACKET_LOOP_RECV_MAX) {
            *loop_immediate = 1;
        }
    }
    return ret;
}

int picoquic_packet_loop_do_udp_send(
    picoquic_quic_t* quic,
    picoquic_cnx_t* last_cnx,
    SOCKET_TYPE send_socket,
    picoquic_packet_loop_param_t* param,
    uint8_t* send_buffer,
    size_t send_length,
    struct sockaddr_storage* peer_addr,
    struct sockaddr_storage* local_addr,
    int if_index,
    size_t send_msg_size,
    size_t* send_msg_ptr,
    picoquic_connection_id_t* log_cid,
    uint64_t current_time)
{
    int ret = 0;
    int sock_ret = 0;
    int sock_err = 0;

    if (send_socket == INVALID_SOCKET) {
        sock_ret = -1;
        sock_err = -1;
    }
    else
    {
        if (param->simulate_eio && send_length > PICOQUIC_MAX_PACKET_SIZE) {
            /* Test hook, simulating a driver that does not support GSO */
            sock_ret = -1;
            sock_err = EIO;
            param->simulate_eio = 0;
            DBG_PRINTF("Simulating EIO, send length = %zu", send_length);
        }
        else {
            sock_ret = picoquic_sendmsg(send_socket,
                (struct sockaddr*)peer_addr, (struct sockaddr*)local_addr, if_index,
                (const char*)send_buffer, (int)send_length, (int)send_msg_size, &sock_err);
        }
    }
    if (sock_ret <= 0) {
        /* TODO: add a test in which the socket fails. */
        if (last_cnx == NULL) {
            picoquic_log_context_free_app_message(quic, log_cid, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                peer_addr->ss_family, local_addr->ss_family, if_index, sock_ret, sock_err);
        }
        else {
            picoquic_log_app_message(last_cnx, "Could not send message to AF_to=%d, AF_from=%d, if=%d, ret=%d, err=%d",
                peer_addr->ss_family, local_addr->ss_family, if_index, sock_ret, sock_err);

            if (picoquic_socket_error_implies_unreachable(sock_err)) {
                picoquic_notify_destination_unreachable(last_cnx, current_time,
                    (struct sockaddr*)&peer_addr, (struct sockaddr*)&local_addr, if_index,
                    sock_err);
            }
            else if (sock_err == EIO) {
                /* TODO: this is an error encountered if the system supports GSO, but
                 * the specific interface driver does not. Main example is Mininet.
                 * Not sure that we can treat that correctly. Try to minimize the
                 * amount of untested code? Rely on config flag? Rely on error
                 * recovery? */
                size_t packet_index = 0;
                size_t packet_size = send_msg_size;

                while (packet_index < send_length) {
                    DBG_PRINTF("EIO, length= %zu/%zu", packet_index, send_length);
                    if (packet_index + packet_size > send_length) {
                        packet_size = send_length - packet_index;
                    }
                    sock_ret = picoquic_sendmsg(send_socket,
                        (struct sockaddr*)peer_addr, (struct sockaddr*)local_addr, if_index,
                        (const char*)(send_buffer + packet_index), (int)packet_size, 0, &sock_err);
                    if (sock_ret > 0) {
                        packet_index += packet_size;
                    }
                    else {
                        DBG_PRINTF("Retry with packet size=%zu fails at index %zu, ret=%d, err=%d.",
                            packet_size, packet_index, sock_ret, sock_err);
                        picoquic_log_app_message(last_cnx, "Retry with packet size=%zu fails at index %zu, ret=%d, err=%d.",
                            packet_size, packet_index, sock_ret, sock_err);
                        break;
                    }
                }
                if (sock_ret > 0) {
                    picoquic_log_app_message(last_cnx, "Retry of %zu bytes by chunks of %zu bytes succeeds.",
                        send_length, send_msg_size);
                }
                if (send_msg_ptr != NULL) {
                    /* Make sure that we do not use GSO anymore in this run */
                    send_msg_ptr = NULL;
                    picoquic_log_app_message(last_cnx, "%s", "UDP GSO was disabled");
                }
            }
        }
    }
    return ret;
}

#ifdef _WINDOWS
DWORD WINAPI picoquic_packet_loop_v3(LPVOID v_ctx)
#else
void* picoquic_packet_loop_v3(void* v_ctx)
#endif
{
    picoquic_network_thread_ctx_t* thread_ctx = (picoquic_network_thread_ctx_t*)v_ctx;
    picoquic_quic_t* quic = thread_ctx->quic;
    picoquic_quic_t* qmux = thread_ctx->qmux;
    picoquic_packet_loop_param_t* param = thread_ctx->param;
    picoquic_packet_loop_cb_fn loop_callback = thread_ctx->loop_callback;
    void* loop_callback_ctx = thread_ctx->loop_callback_ctx;
    int ret = 0;
    uint64_t current_time = picoquic_get_quic_time(quic);
    int64_t delay_max = 10000000;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    int if_index_to;
    uint8_t ecn_value = (quic->default_congestion_alg == NULL) ? 0 : quic->default_congestion_alg->ecn_mark;
#if !defined(_WINDOWS) && !defined(PICOQUIC_WITH_IO_URING)
    uint8_t buffer[1536];
#endif
    uint8_t* send_buffer = NULL;
    size_t send_length = 0;
    size_t send_msg_size = 0;
    size_t send_buffer_size = param->socket_buffer_size;
    size_t* send_msg_ptr = NULL;
    int bytes_recv;
    picoquic_connection_id_t log_cid;
    picoquic_socket_ctx_t s_ctx[PICOQUIC_PACKET_LOOP_SOCKETS_MAX];
    int nb_sockets = 0;
    picoqmux_socket_ctx_t **sqmux_ctx = NULL;
    int nb_qmux_sockets = 0;
    int max_qmux_sockets = 0;
    int nb_sockets_available = 0;
    int qmux_socket_was_closed = -1;
    uint8_t* qmux_buffer = NULL;
    size_t qmux_buffer_size = 0;
    picoquic_cnx_t* last_cnx = NULL;
    int loop_immediate = 0;
    unsigned int nb_loop_immediate = 0;
    picoquic_packet_loop_options_t options = { 0 };
    packet_loop_system_call_duration_t sc_duration = { 0 };
    picoquic_packet_loop_action_enum action = picoquic_packet_loop_action_none;
#if defined(_WINDOWS)
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#elif defined(PICOQUIC_WITH_IO_URING)
    struct io_uring ring = { 0 };
    int io_uring_is_init = 0;
#elif defined(PICOQUIC_WITH_POLL)
    struct pollfd* poll_list = NULL;
    size_t poll_list_size = 0;
#endif
    PICOQUIC_THREAD_SET_CHECK(thread_ctx->quic);

    if (thread_ctx->thread_name != NULL) {
        thread_ctx->thread_setname_fn(thread_ctx->thread_name);
    }

    if (send_buffer_size == 0) {
        send_buffer_size = 0xffff;
    }

    memset(s_ctx, 0, sizeof(s_ctx));
    if ((nb_sockets = picoquic_packet_loop_open_sockets(param->local_port,
        param->local_af, param->public_port, param->is_port_shared,
        param->socket_buffer_size,
        param->extra_socket_required, param->do_not_use_gso, s_ctx, ecn_value)) <= 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (qmux != NULL) {
        qmux_buffer_size = 0x4000;
        qmux_buffer = (uint8_t*)malloc(qmux_buffer_size);

        if (qmux_buffer == NULL) {
            ret = PICOQUIC_ERROR_MEMORY;
        }
        else {
            /* The loop starts by openig the "listening" sockets. */
            ret = picoquic_packet_loop_open_qmux_sockets(qmux, &sqmux_ctx,
                &nb_qmux_sockets, &max_qmux_sockets, param->qmux_port);
            if (nb_qmux_sockets < 0 || max_qmux_sockets <= 0) {
                ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            }
            /* If the application created connections in the qmux
             * context, open the corresponding sockets.
             */
            if (ret == 0) {
                ret = picoquic_packet_loop_open_qmux_cnx_sockets(qmux, sqmux_ctx, &nb_qmux_sockets, max_qmux_sockets, current_time);
            }
        }
    }
    if (ret == 0 && loop_callback != NULL) {
        struct sockaddr_storage l_addr;
        ret = loop_callback(quic, picoquic_packet_loop_ready, loop_callback_ctx, &options);

        if (picoquic_store_loopback_addr(&l_addr, s_ctx[0].af, s_ctx[0].port) == 0) {
            ret = loop_callback(quic, picoquic_packet_loop_port_update, loop_callback_ctx, &l_addr);
        }
        if (ret == 0 && options.provide_alt_port) {
            int alt_sock = (nb_sockets > 2 && param->local_af == 0) ? 2 : 1;
            uint16_t alt_port = s_ctx[alt_sock].port;
            ret = loop_callback(quic, picoquic_packet_loop_alt_port, loop_callback_ctx, &alt_port);
        }
    }
#if defined(_WINDOWS)
#elif defined(PICOQUIC_WITH_IO_URING)
    if (ret == 0 &&
        (ret = picoquic_packet_loop_prep_uring(&ring)) == 0) {
        io_uring_is_init = 1;
    }
#elif defined(PICOQUIC_WITH_POLL)
    if (ret == 0) {
        poll_list_size = (size_t)(nb_sockets + max_qmux_sockets + 1);
        if ((poll_list = (struct pollfd*)malloc(sizeof(struct pollfd) * poll_list_size)) == NULL) {
            ret = -1;
        }
        else {
            picoquic_packet_loop_set_fds(poll_list, poll_list_size, s_ctx, nb_sockets_available,
                sqmux_ctx, nb_qmux_sockets, thread_ctx, current_time);
        }
    }
#endif

    if (ret == 0) {
        nb_sockets_available = nb_sockets;

        if (udp_gso_available && !param->do_not_use_gso) {
            send_buffer_size = 0xFFFF;
            send_msg_ptr = &send_msg_size;
        }
        send_buffer = malloc(send_buffer_size);
        if (send_buffer == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        thread_ctx->thread_is_ready = 1;
    }
    else {
        DBG_PRINTF("%s", "Thread cannot run");
    }

    /* Wait for packets */
    /* TODO: add stopping condition, was && (!just_once || !connection_done) */
    /* Actually, no, rely on the callback return code for that? */
    while (ret == 0 && !thread_ctx->thread_should_close) {
        int socket_rank = -1;
        int64_t delta_t = 0;
        uint8_t received_ecn;
        uint8_t* received_buffer;
        uint64_t previous_time;

        if_index_to = 0;
        /* The "qmux_socket_was_closed" condition is set one of the TCP sockets was
        * closed during the previous iteration. In that case, we need to
        * pack the list of qmux sockets to only keep the valid ones.
         */
        if (qmux_socket_was_closed >= 0) {
            if (qmux_socket_was_closed < nb_qmux_sockets - 1) {
                memmove(&sqmux_ctx[qmux_socket_was_closed], &sqmux_ctx[qmux_socket_was_closed + 1],
                    sizeof(picoqmux_socket_ctx_t*) * (size_t)(nb_qmux_sockets - qmux_socket_was_closed - 1));
            }
            nb_qmux_sockets--;
            qmux_socket_was_closed = -1;
        }
        /* The "loop immediate" condition is set when a packet has been
        * received and processed successfully. We call select again with
        * a delay set to zero to check whether more packets need to be
        * received, trying to empty the receive queue before sending
        * more packet. However, this code is a bit dangerous,
        * because it can lead to long series of receiving packets without
        * ever sending responses or ACKs. We moderate that by counting the number
        * of loops in "immediate" mode, and ignoring the "loop
        * immediate" condition if that number reaches a limit */
        current_time = picoquic_current_time();
        if (!loop_immediate) {
            int64_t delta_t_qmux;
            nb_loop_immediate = 1;
            delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);
            if (qmux != NULL) {
                delta_t_qmux = picoquic_get_next_wake_delay(qmux, current_time, delay_max);
                if (delta_t_qmux < delta_t) {
                    delta_t = delta_t_qmux;
                }
            }
            if (options.do_time_check) {
                packet_loop_time_check_arg_t time_check_arg;
                time_check_arg.current_time = current_time;
                time_check_arg.delta_t = delta_t;
                ret = loop_callback(quic, picoquic_packet_loop_time_check, loop_callback_ctx, &time_check_arg);
                if (time_check_arg.delta_t < delta_t) {
                    delta_t = time_check_arg.delta_t;
                }
            }
        }
        else {
            nb_loop_immediate++;
        }
        /* The "loop immediate flag is set by default to zero. It will be
        * set to 1 if a packet has been received and the number of
        * packets received "immediately" does not exceed the limit.
         */
        loop_immediate = 0;
        /* Remember the time before the select call, so it duration be monitored */
        previous_time = current_time;
        /* Initialize the dest addr family to UNSPEC to handle systems that cannot set it. */
        addr_to.ss_family = AF_UNSPEC;

        /* ToDo: update for QMux*/
#if defined(_WINDOWS)
        bytes_recv = picoquic_packet_loop_wait(s_ctx, nb_sockets_available,
            sqmux_ctx, nb_qmux_sockets, current_time,
            &addr_from, &addr_to, &if_index_to, &received_ecn, &received_buffer,
            delta_t, thread_ctx, &action, &socket_rank);
#elif defined(PICOQUIC_WITH_IO_URING)
        bytes_recv = picoquic_packet_loop_uring(
            &ring, s_ctx, nb_sockets_available,
            sqmux_ctx, nb_qmux_sockets, current_time, delta_t, thread_ctx,
            &addr_from, &addr_to, &if_index_to, &is_wake_up_event, &received_ecn,
            &received_buffer, &socket_rank, &action);
#elif defined(PICOQUIC_WITH_POLL)
        bytes_recv = picoquic_packet_loop_poll(
            s_ctx, nb_sockets_available,
            sqmux_ctx, nb_qmux_sockets, current_time,
            poll_list, poll_list_size, &addr_from, &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer), delta_t, thread_ctx,
            &action, &socket_rank);
        received_buffer = buffer;
#else
        bytes_recv = picoquic_packet_loop_select(s_ctx, nb_sockets_available,
            sqmux_ctx, nb_qmux_sockets, current_time,
            &addr_from, &addr_to, &if_index_to, &received_ecn,
            buffer, sizeof(buffer), delta_t, thread_ctx,
            &action, &socket_rank);
        received_buffer = buffer;
#endif
        current_time = picoquic_current_time();
        if (options.do_system_call_duration && delta_t == 0 &&
            monitor_system_call_duration(&sc_duration, current_time, previous_time)) {
            ret = loop_callback(quic, picoquic_packet_loop_system_call_duration,
                loop_callback_ctx, &sc_duration);
        }

        if (bytes_recv < 0) {
            /* The interrupt error is expected if the loop is closing. */
            ret = (thread_ctx->thread_should_close) ? PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP : -1;
        }
        else {
            /* First, process immediate actions */
            switch (action) {
            case picoquic_packet_loop_action_none:
                break;
            case picoquic_packet_loop_action_timeout:
                /* perform a qmux check */
                ret = picoquic_packet_loop_check_qmux_timers(sqmux_ctx,
                    &nb_qmux_sockets, max_qmux_sockets, &qmux_socket_was_closed,
                    current_time, qmux_buffer, qmux_buffer_size);
                break;
            case picoquic_packet_loop_action_wake_up:
                ret = loop_callback(quic, picoquic_packet_loop_wake_up, loop_callback_ctx, NULL);
                break;
            case picoquic_packet_loop_action_udp_received:
                ret = picoquic_packet_loop_udp_received(quic, &last_cnx,
#ifdef _WINDOWS
                    s_ctx, socket_rank,
#endif
                    received_buffer, bytes_recv,
                    (struct sockaddr*)&addr_from, (struct sockaddr*)&addr_to, if_index_to, received_ecn,
                    loop_callback, loop_callback_ctx, current_time, nb_loop_immediate, &loop_immediate);
                if (ret == 0) {
                    if (loop_callback != NULL) {
                        size_t b_recvd = (size_t)bytes_recv;
                        ret = loop_callback(quic, picoquic_packet_loop_after_receive, loop_callback_ctx, &b_recvd);
                    }
                }
                break;
            case picoquic_packet_loop_action_tcp_accept_ready:
                ret = picoquic_packet_loop_do_tcp_accept(qmux, sqmux_ctx, 
                    &nb_qmux_sockets, max_qmux_sockets, socket_rank, current_time);
                break;
            case picoquic_packet_loop_action_tcp_recv_ready:
                ret = picoquic_packet_loop_do_tcp_read( sqmux_ctx,
                    &nb_qmux_sockets, max_qmux_sockets, socket_rank,
                    current_time, qmux_buffer, qmux_buffer_size);
                break;
            case picoquic_packet_loop_action_tcp_send_ready:
                ret = picoquic_packet_loop_do_tcp_send(sqmux_ctx,
                    &nb_qmux_sockets, max_qmux_sockets, socket_rank,
                    current_time, qmux_buffer, qmux_buffer_size);
                break;
            default:
                break;
            }
        }
        /* If the number of packets received in immediate mode has not
        * reached the threshold, set the "immediate" flag and bypass
        * the sending code.
         */
        if (ret == 0 && loop_immediate) {
            if (nb_loop_immediate < PICOQUIC_PACKET_LOOP_RECV_MAX) {
                continue;
            }
        }
        else {
            size_t bytes_sent = 0;
            size_t nb_packets_sent = 0;

            if (ret == PICOQUIC_NO_ERROR_SIMULATE_NAT) {
                if (param->extra_socket_required) {
                    /* Stop using the extra socket.
                     * This will simulate a NAT:
                     * - on the receive side, packets arriving to the old address will be ignored.
                     * - on the send side, client packets will be sent through the main socket,
                     *   and appear to come from that port instead of the extra port.
                     * - since the CID does not change, the server will execute the NAT behavior.
                     * The client will have to update its path -- but that can be avoided if the
                     * test code overrides the value of the "local" address that the client
                     * memorized for that path.
                     */
                    nb_sockets_available = nb_sockets / 2;

#if defined(_WINDOWS)
#elif defined(PICOQUIC_WITH_IO_URING)
#elif defined(PICOQUIC_WITH_POLL)
                    picoquic_packet_loop_set_fds(poll_list, poll_list_size, s_ctx, nb_sockets_available,
                        sqmux_ctx, nb_qmux_sockets, thread_ctx, current_time);
#endif
                }
                ret = 0;
            }

            /* We limit the number of packets sent in a loop, no make sure that
            * the code will not spend a lot of time sending packets while
            * packets may be adding in the receive queue.
             */
            /* TODO: isolate the UDP sending logic in a function. */
            while (ret == 0 && nb_packets_sent < PICOQUIC_PACKET_LOOP_SEND_MAX) {
                struct sockaddr_storage peer_addr;
                struct sockaddr_storage local_addr = { 0 };
                int if_index = 0;

                send_length = 0; 
                ret = picoquic_prepare_next_packet_ex(quic, current_time,
                    send_buffer, send_buffer_size, &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid, &last_cnx,
                    send_msg_ptr);
                if (ret == 0 && send_length > 0) {
                    /* If send_msg_size is defined, sendmsg may send more than one packet.
                     * We compute that to update the number of packets sent in the loop.
                     */
                    nb_packets_sent += (send_msg_size == 0) ? 1 :
                        (send_length + send_msg_size - 1) / (send_msg_size);
                    if (send_length > param->send_length_max) {
                        param->send_length_max = send_length;
                    }
                    /* We have multiple sockets, with support for
                    * either IPv6, or IPv4, or both, and binding to a port number.
                    * Find the first socket where:
                    * - the destination AF is supported.
                    * - either the source port is not specified, or it matches the local port.
                    */
                    SOCKET_TYPE send_socket = INVALID_SOCKET;
                    uint16_t send_port = (peer_addr.ss_family == AF_INET) ?
                        ((struct sockaddr_in*)&local_addr)->sin_port :
                        ((struct sockaddr_in6*)&local_addr)->sin6_port;

                    bytes_sent += send_length;

                    /* TODO: verify htons/ntohs */
                    for (int i = 0; i < nb_sockets_available; i++) {
                        if (s_ctx[i].af == peer_addr.ss_family) {
                            send_socket = s_ctx[i].fd;
                            if (send_port == 0 && !param->prefer_extra_socket) {
                                break;
                            }
                            if (s_ctx[i].n_port == send_port) {
                                break;
                            }
                        }
                    }

                    if (send_socket == INVALID_SOCKET) {
                        if (nb_sockets_available < PICOQUIC_PACKET_LOOP_SOCKETS_MAX) {
                            picoquic_socket_ctx_t* new_ctx = &s_ctx[nb_sockets_available];
                            memset(new_ctx, 0, sizeof(*new_ctx));
                            new_ctx->af = peer_addr.ss_family;
                            if (peer_addr.ss_family == AF_INET6) {
                                new_ctx->port = ntohs(((struct sockaddr_in6*)&peer_addr)->sin6_port);
                            }
                            else {
                                new_ctx->port = ntohs(((struct sockaddr_in*)&peer_addr)->sin_port);
                            }
                            new_ctx->n_port = htons(new_ctx->port);
                            if (picoquic_packet_loop_open_socket(param->socket_buffer_size, param->do_not_use_gso, new_ctx, ecn_value) == 0) {
                                send_socket = new_ctx->fd;
                                send_port = new_ctx->n_port;
                                nb_sockets_available++;
                                if (nb_sockets < nb_sockets_available) {
                                    DBG_PRINTF("new socket, nb = %d", nb_sockets_available);
                                    nb_sockets = nb_sockets_available;

#if defined(_WINDOWS)
#elif defined(PICOQUIC_WITH_IO_URING)
#elif defined(PICOQUIC_WITH_POLL)
                                    picoquic_packet_loop_set_fds(poll_list, poll_list_size, s_ctx, nb_sockets_available,
                                        sqmux_ctx, nb_qmux_sockets, thread_ctx, current_time);
#endif
                                }
                            }
                        }
                    }
                    ret = picoquic_packet_loop_do_udp_send(
                        quic, last_cnx, send_socket, param,
                        send_buffer, send_length, &peer_addr, &local_addr, if_index,
                        send_msg_size, send_msg_ptr, &log_cid, current_time);
                }
                else {
                    break;
                }
            }

            if (ret == 0 && loop_callback != NULL) {
                ret = loop_callback(quic, picoquic_packet_loop_after_send, loop_callback_ctx, &bytes_sent);
            }
        }
    }

    thread_ctx->thread_is_ready = 0;
#if defined(_WINDOWS)
#elif defined(PICOQUIC_WITH_IO_URING)
    if (io_uring_is_init) {
        /* Free the memory allocated for IO_URING */
        io_uring_cancel_and_free(&ring, s_ctx, nb_sockets, thread_ctx);
    }
#elif defined(PICOQUIC_WITH_POLL)
    if (poll_list != NULL){
        free(poll_list);
        poll_list = NULL;
    }
#else
#endif


    if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
        /* Normal termination requested by the application, returns no error */
        ret = 0;
    }

    /* Close the sockets */
    for (int i = 0; i < nb_sockets; i++) {
        picoquic_packet_loop_close_socket(&s_ctx[i]);
    }
    
    picoquic_packet_loop_free_qmux_sockets(&sqmux_ctx, nb_qmux_sockets);

    if (send_buffer != NULL) {
        free(send_buffer);
    }

    if (qmux_buffer != NULL) {
        free(qmux_buffer);
    }

    thread_ctx->return_code = ret;

#ifdef _WINDOWS
    return (DWORD)ret;
#else
    if (thread_ctx->is_threaded) {
        pthread_exit((void*)&thread_ctx->return_code);
    }
    return(NULL);
#endif
}

int picoquic_packet_loop_v2(picoquic_quic_t* quic,
    picoquic_packet_loop_param_t* param,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    picoquic_network_thread_ctx_t thread_ctx = { 0 };

    thread_ctx.quic = quic;
    thread_ctx.param = param;
    thread_ctx.loop_callback = loop_callback;
    thread_ctx.loop_callback_ctx = loop_callback_ctx;

    (void)picoquic_packet_loop_v3((void*)&thread_ctx);
    return thread_ctx.return_code;
}

/* Support for legacy API */

int picoquic_packet_loop(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    int socket_buffer_size,
    int do_not_use_gso,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx)
{
    picoquic_packet_loop_param_t param = { 0 };

    param.local_port = (uint16_t)local_port;
    param.local_af = local_af;
    param.dest_if = dest_if;
    param.socket_buffer_size = socket_buffer_size;
    param.do_not_use_gso = do_not_use_gso;

    return picoquic_packet_loop_v2(quic, &param, loop_callback, loop_callback_ctx);
}

/* Management of background thread. */

#ifdef ESP_PLATFORM
/* ESP32 doesn't have pipe(), so we use a UDP socket pair instead */
#define pipe esp_pipe
static int esp_pipe(int fd[2])
{
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    int listener = -1;

    /* Create listener socket on loopback */
    listener = socket(AF_INET, SOCK_DGRAM, 0);
    if (listener < 0) {
        return -1;
    }

    /* Bind to loopback on any available port */
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(listener);
        return -1;
    }

    /* Get the bound port */
    if (getsockname(listener, (struct sockaddr*)&addr, &addrlen) < 0) {
        close(listener);
        return -1;
    }

    /* Create sender socket */
    fd[1] = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd[1] < 0) {
        close(listener);
        return -1;
    }

    /* Connect sender to listener */
    if (connect(fd[1], (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd[1]);
        close(listener);
        return -1;
    }

    fd[0] = listener;
    return 0;
}
#endif

static void picoquic_close_network_wake_up(picoquic_network_thread_ctx_t* thread_ctx)
{
    if (thread_ctx->wake_up_defined) {
#ifdef _WINDOWS
        CloseHandle(thread_ctx->wake_up_event);
#else
        for (int i = 0; i < 2; i++) {
            (void)close(thread_ctx->wake_up_pipe_fd[i]);
        }
#endif
        thread_ctx->wake_up_defined = 0;
    }
}

static void picoquic_open_network_wake_up(picoquic_network_thread_ctx_t* thread_ctx, int *ret)
{
    thread_ctx->wake_up_defined = 0;
#ifdef _WINDOWS
    thread_ctx->wake_up_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (thread_ctx->wake_up_event == NULL) {
        *ret = GetLastError();
    }
    else {
        thread_ctx->wake_up_defined = 1;
    }
#else
    if (pipe(thread_ctx->wake_up_pipe_fd) != 0) {
        *ret = errno;
    }
    else
    {
        thread_ctx->wake_up_defined = 1;
    }
#endif
}

int picoquic_internal_thread_create(void** thread_id, picoquic_thread_fn thread_fn, void* thread_arg)
{
    int ret = picoquic_create_thread((picoquic_thread_t*)thread_id, thread_fn, thread_arg);
    return ret;
}

void picoquic_internal_thread_setname(char const * thread_name)
{
#ifdef _WINDOWS
    wchar_t wname[257];
    wname[0] = 0;

    if (swprintf(wname, 256, L"%S", thread_name) < 0) {
        DBG_PRINTF("Cannot convert thread name <%s> to wchar[256], err: 0x%x",
            thread_name, GetLastError());
    }
    else {
        HRESULT r = SetThreadDescription(GetCurrentThread(), wname);
        if (r != 0) {
            DBG_PRINTF("Set thread name <%S> returns: 0x%x", wname, r);
        }
    }
#else
#if defined(__APPLE__)
    pthread_setname_np(thread_name);
#elif defined(__FreeBSD__)
    pthread_setname_np(pthread_self(), thread_name);
#else
    int r=prctl(PR_SET_NAME, thread_name, 0, 0, 0);
    if (r != 0) {
        DBG_PRINTF("Set thread name <%s> returns: 0x%x", thread_name, r);
    }
#endif
#endif
}

void picoquic_internal_thread_delete(void** v_thread_id)
{
    picoquic_delete_thread((picoquic_thread_t *)v_thread_id);
}

picoquic_network_thread_ctx_t* picoquic_start_custom_network_thread_qmux(picoquic_quic_t* quic,
    picoquic_quic_t * qmux, picoquic_packet_loop_param_t* param,
    picoquic_custom_thread_create_fn thread_create_fn, picoquic_custom_thread_delete_fn thread_delete_fn,
    picoquic_custom_thread_setname_fn thread_setname_fn, char const* thread_name,
    picoquic_packet_loop_cb_fn loop_callback, void* loop_callback_ctx, int* ret)
{
    picoquic_network_thread_ctx_t* thread_ctx = (picoquic_network_thread_ctx_t*)malloc(sizeof(picoquic_network_thread_ctx_t));
    *ret = 0;

    if (thread_ctx == NULL) {
        /* Error, no memory */
    }
    else {
        memset(thread_ctx, 0, sizeof(picoquic_network_thread_ctx_t));
        /* Set the thread context in the quic context */
        quic->v_thread_ctx = thread_ctx;
        /* Fill the arguments in the context */
        thread_ctx->quic = quic;
        thread_ctx->qmux = qmux;
        thread_ctx->param = param;
        thread_ctx->loop_callback = loop_callback;
        thread_ctx->loop_callback_ctx = loop_callback_ctx;
        /* Open the wake up pipe or event */
        picoquic_open_network_wake_up(thread_ctx, ret);
        /* Start thread at specified entry point */
        if (thread_ctx->wake_up_defined){
            thread_ctx->is_threaded = 1;
            if (thread_create_fn == NULL) {
                thread_create_fn = picoquic_internal_thread_create;
            }
            if ((thread_ctx->thread_setname_fn = thread_setname_fn) == NULL) {
                thread_ctx->thread_setname_fn = picoquic_internal_thread_setname;
            }
            if ((thread_ctx->thread_delete_fn = thread_delete_fn) == NULL) {
                thread_ctx->thread_delete_fn = picoquic_internal_thread_delete;
            }
            thread_ctx->thread_name = thread_name;
            if ((*ret = thread_create_fn((void **)&thread_ctx->pthread, picoquic_packet_loop_v3, (void*)thread_ctx)) != 0) {
                /* Free the context and return error condition if something went wrong */
                thread_ctx->is_threaded = 0;
                picoquic_delete_network_thread(thread_ctx);
                thread_ctx = NULL;
            }
        }
    }
    return thread_ctx;
}

picoquic_network_thread_ctx_t* picoquic_start_custom_network_thread(picoquic_quic_t* quic, picoquic_packet_loop_param_t* param,
    picoquic_custom_thread_create_fn thread_create_fn, picoquic_custom_thread_delete_fn thread_delete_fn,
    picoquic_custom_thread_setname_fn thread_setname_fn, char const* thread_name,
    picoquic_packet_loop_cb_fn loop_callback, void* loop_callback_ctx, int* ret) {
    return picoquic_start_custom_network_thread_qmux(quic, NULL, param, thread_create_fn, thread_delete_fn, thread_setname_fn, thread_name, loop_callback, loop_callback_ctx, ret);
}

picoquic_network_thread_ctx_t* picoquic_start_network_thread(picoquic_quic_t* quic,
    picoquic_packet_loop_param_t* param, picoquic_packet_loop_cb_fn loop_callback, void* loop_callback_ctx, int* ret)
{
    return picoquic_start_custom_network_thread(quic, param, NULL, NULL, NULL, NULL, loop_callback, loop_callback_ctx, ret);
}

int picoquic_wake_up_network_thread(picoquic_network_thread_ctx_t* thread_ctx)
{
    int ret = 0;

    if (thread_ctx->wake_up_defined) {
#ifdef _WINDOWS
        if (SetEvent(thread_ctx->wake_up_event) == 0) {
            DWORD err = WSAGetLastError();
            DBG_PRINTF("Set network event fails, error 0x%x", err);
            ret = (int)err;
        }
#else
        /* TODO: write to network pipe */
        ssize_t written = 0;
        if ((written = write(thread_ctx->wake_up_pipe_fd[1], &ret, 1)) != 1) {
            if (written == 0) {
                ret = EPIPE;
            }
            else {
                ret = errno;
            }
        }
#endif
    }
    else {
        DBG_PRINTF("%s", "Wake up event not defined.");
        ret = -1;
    }
    return ret;
}

void picoquic_delete_network_thread(picoquic_network_thread_ctx_t* thread_ctx)
{
    /* set the should_close flag, so the thread knows the loop should stop */
    thread_ctx->thread_should_close = 1;
    /* Delete the wake up event. This ought to create a fault 
     * in the wait for event call, causing the thread to wake up,
     * notice the flag, and exit.
     */
    picoquic_close_network_wake_up(thread_ctx);
    /* Clear the thread context in the quic context, to avoid any risk of
     * use after free. */
    if (thread_ctx->quic != NULL) {
        thread_ctx->quic->v_thread_ctx = NULL;
    }
    /* delete the thread */
    if (thread_ctx->is_threaded) {
        thread_ctx->thread_delete_fn((void**)&thread_ctx->pthread);
    }
    /* If the param component was allocated as part of frame context, free it */
    if (thread_ctx->is_param_allocated) {
        free(thread_ctx->param);
    }
    /* Free the context */
    free(thread_ctx);
}


/* Set a server context, using more parameters than the simple
* creation from configuration.
*/

int picoquic_server_set_context(picoquic_quic_t** qserver,
    picoquic_quic_config_t* config,
    uint64_t current_time,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    picoquic_alpn_select_fn_v2 alpn_select_fn)
{
    int ret = 0;
    /* Create QUIC context */

    if (ret == 0) {
        *qserver = picoquic_create_and_configure(config, default_callback_fn, default_callback_ctx, current_time, NULL);
        if (*qserver == NULL) {
            ret = -1;
        }
        else {
            picoquic_set_key_log_file_from_env(*qserver);

            picoquic_set_alpn_select_fn_v2(*qserver, alpn_select_fn);

            picoquic_use_unique_log_names(*qserver, 1);

            if (config->qlog_dir != NULL)
            {
                picoquic_set_qlog(*qserver, config->qlog_dir);
            }
            if (config->performance_log != NULL)
            {
                ret = picoquic_perflog_setup(*qserver, config->performance_log);
            }
            if (ret == 0 && config->cnx_id_cbdata != NULL) {
                picoquic_load_balancer_config_t lb_config;
                ret = picoquic_lb_compat_cid_config_parse(&lb_config, config->cnx_id_cbdata, strlen(config->cnx_id_cbdata));
                if (ret != 0) {
                    fprintf(stdout, "Cannot parse the CNX_ID config policy: %s.\n", config->cnx_id_cbdata);
                }
                else {
                    ret = picoquic_lb_compat_cid_config(*qserver, &lb_config);
                    if (ret != 0) {
                        fprintf(stdout, "Cannot set the CNX_ID config policy: %s.\n", config->cnx_id_cbdata);
                    }
                }
            }
            if (ret == 0) {
                fprintf(stdout, "Accept enable multipath: %d.\n", (*qserver)->default_multipath_option);
            }
            (*qserver)->default_tp.is_reset_stream_at_enabled = 1;
            (*qserver)->default_tp.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
        }
    }
    return ret;
}

/* Return the thread context associated with a QUIC context,
* or a NULl pointer if there is none. */
struct st_picoquic_network_thread_ctx_t* picoquic_get_thread_ctx(picoquic_quic_t* quic)
{
    return (struct st_picoquic_network_thread_ctx_t*) quic->v_thread_ctx;
}

/*
* Start a set of N threads. Each thread manages its own quic context, which is
* created here from the config parameters. The thread interacts with the
* application through:
*
* - wake up and stop/delete calls, using the standard thread API,
* - the ALPN selection function, called when a new connection is created,
*   which can set the callback function and the callback context for the connection.
* - a callback function called from the packet loop, either when the
*  thread is woken up, or when the packet loop needs to check application delays.
* - per connection callbacks.
*
* The application will specialize the threads by providing the callback functions,
* and their default context:
* - the ALPN selection function is the same for all threads.
* - the packet loop callback is the same for all threads, and its context.
* - the default connection callback is the same for all threads.
* - the default connection callback context is the same for all threads.
*
* The packet loop callback context is the same for all threads. The function
* can retrieve the thread context from the "quic" context argument using
* the function picoquic_get_thread_ctx_from_quic().
*/

int picoquic_start_server_threads(
    struct st_picoquic_quic_config_t* config,
    uint64_t current_time,
    picoquic_alpn_select_fn_v2 alpn_select_fn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    picoquic_packet_loop_cb_fn loop_callback_fn,
    void* loop_callback_ctx,
    picoquic_custom_thread_create_fn thread_create_fn,
    picoquic_custom_thread_delete_fn thread_delete_fn,
    picoquic_custom_thread_setname_fn thread_setname_fn,
    picoquic_network_thread_ctx_t** thread_ctxs,
    int nb_threads_max,
    int* nb_threads_created)
{
    int ret = 0;
    int nb_threads = 0;
    uint8_t default_ticket_key[16] = { 0 };
    /* Set the thread functions to default value if not set */
    if (thread_create_fn == NULL) {
        thread_create_fn = picoquic_internal_thread_create;
    }
    if (thread_delete_fn == NULL) {
        thread_delete_fn = picoquic_internal_thread_delete;
    }
    if (thread_setname_fn == NULL) {
        thread_setname_fn = picoquic_internal_thread_setname;
    }
    /* Check that the number of threads matches the config value
     */
    if (config->nb_threads > nb_threads_max) {
        fprintf(stdout, "Cannot start %d threads, max is %d.\n", config->nb_threads, nb_threads_max);

        ret = -1;
    }
    else if (config->nb_threads < 1) {
        nb_threads = 1;
    }
    else {
        nb_threads = (int)config->nb_threads;
    }
    /* set the ticket encryption key if not present in config */
    if (ret == 0 && config->ticket_encryption_key == NULL) {
        picoquic_quic_t* quic = picoquic_create(1, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, default_ticket_key, current_time, NULL,
            NULL, NULL, 0);
        if (quic != NULL) {
            picoquic_crypto_random(quic, default_ticket_key, sizeof(default_ticket_key));
            picoquic_free(quic);
            config->ticket_encryption_key = default_ticket_key;
            config->ticket_encryption_key_length = sizeof(default_ticket_key);
        }
        else {
            fprintf(stdout, "Cannot create a temporary QUIC context to generate the default ticket encryption key.\n");
        }
    }

    for (int i = 0; ret == 0 && i < nb_threads; i++) {
        /* Allocate and initiate the params field. */
        picoquic_quic_t* qserver = NULL;
        picoquic_packet_loop_param_t* param = NULL;

        ret = picoquic_server_set_context(&qserver, config, current_time, default_callback_fn, default_callback_ctx, alpn_select_fn);
        if (ret != 0) {
            fprintf(stdout, "Cannot create the QUIC context for thread %d.\n", i);
            nb_threads = i;
        }
        else if ((param = (picoquic_packet_loop_param_t*)malloc(sizeof(picoquic_packet_loop_param_t))) == NULL) {
            fprintf(stdout, "Cannot create the packet loop param for thread %d.\n", i);
            nb_threads = i;
            ret = -1;
        }
        else {
            memset(param, 0, sizeof(picoquic_packet_loop_param_t));
            if (param->local_port != 0) {
                param->local_port = (uint16_t)(config->local_port + i);
            }
            param->public_port = config->server_port;
            param->is_port_shared = config->is_port_shared;
            param->local_af = 0;
            param->dest_if = config->dest_if;
            param->socket_buffer_size = config->socket_buffer_size;
            param->do_not_use_gso = config->do_not_use_gso;

            thread_ctxs[i] = picoquic_start_custom_network_thread(qserver, param,
                thread_create_fn, thread_delete_fn, thread_setname_fn, NULL,
                loop_callback_fn, loop_callback_ctx,
                &ret);
            if (thread_ctxs[i] == NULL) {
                picoquic_free(qserver);
                free(param);
                nb_threads = i;
            }
            else {
                thread_ctxs[i]->is_param_allocated = 1;
            }
        }
    }
    *nb_threads_created = nb_threads;
    return ret;
}
