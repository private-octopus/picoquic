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

#include "picosocks.h"
#include "picoquic_utils.h"
#ifndef _WINDOWS
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include "picoquic_packet_loop.h"

extern char** environ;
#endif

static int socket_ping_pong(SOCKET_TYPE fd, struct sockaddr* server_addr,
    picoquic_server_sockets_t* server_sockets)
{
    int ret = 0;
    uint64_t current_time = picoquic_current_time();
    uint8_t message[1440];
    uint8_t buffer[1536];
    int bytes_sent = 0;
    int bytes_recv = 0;
    struct sockaddr_storage server_addr_n = { 0 };
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_dest;
    int dest_if = 0;
    struct sockaddr_storage addr_back;
    int server_address_length = (server_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

    for (size_t i = 0; i < sizeof(message);) {
        for (int j = 0; j < 64 && i < sizeof(message); j += 8, i++) {
            message[i++] = (uint8_t)(current_time >> j);
        }
    }
    memcpy(&server_addr_n, server_addr, (server_addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));

    /* send from client to sever address */
    
    bytes_sent = sendto(fd, (const char*)&message, sizeof(message), 0, (struct sockaddr*)&server_addr_n, server_address_length);

    if (bytes_sent != (int)sizeof(message)) {
        DBG_PRINTF("Sendto sent %d bytes, expected %d\n", bytes_sent, (int)sizeof(message));
        ret = -1;
    }

    /* perform select at server */
    if (ret == 0) {
        unsigned char received_ecn;
        memset(buffer, 0, sizeof(buffer));

        bytes_recv = picoquic_select(server_sockets->s_socket, PICOQUIC_NB_SERVER_SOCKETS,
            &addr_from, &addr_dest, &dest_if, &received_ecn,
            buffer, sizeof(buffer), 1000000, &current_time);

        if (bytes_recv != bytes_sent) {
            DBG_PRINTF("Select returns %d bytes, expected %d\n", bytes_recv, bytes_sent);
            ret = -1;
        }
    }

    /* Convert message using XOR  and send to address from which the message was received */
    if (ret == 0) {
        int sock_err = 0;
        for (int i = 0; i < bytes_recv; i++) {
            buffer[i] ^= 0xFF;
        }

        if (picoquic_send_through_server_sockets(server_sockets,
                (struct sockaddr*)&addr_from,
                (struct sockaddr*)&addr_dest, dest_if,
                (char*)buffer, bytes_recv, &sock_err)
            != bytes_recv) {
            DBG_PRINTF("Send_through_server_sockets return %d, err %d", ret, sock_err);
            ret = -1;
        }
    }

    /* perform select at client */
    if (ret == 0) {
        unsigned char received_ecn;
        memset(buffer, 0, sizeof(buffer));

        bytes_recv = picoquic_select(&fd, 1,
            &addr_back, NULL, NULL, &received_ecn,
            buffer, sizeof(buffer), 1000000, &current_time);

        if (bytes_recv != bytes_sent) {
            DBG_PRINTF("Second select returns %d bytes, expected %d\n", bytes_recv, bytes_sent);
            ret = -1;
        } else {
            /* Check that the message matches what was sent initially */

            for (int i = 0; ret == 0 && i < bytes_recv; i++) {
                if (message[i] != (buffer[i] ^ 0xFF)) {
                    DBG_PRINTF("Second select, message mismatch at position %d\n", i);
                    ret = -1;
                }
            }

            DBG_PRINTF("Received ecn: %x\n", received_ecn);
        }
    }

    return ret;
}

static int socket_test_one(char const* addr_text, int server_port, int should_be_name,
    picoquic_server_sockets_t* server_sockets)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    int is_name;
    SOCKET_TYPE fd = INVALID_SOCKET;

    /* Resolve the server address -- check the "is_name" property */
    ret = picoquic_get_server_address(addr_text, server_port, &server_address, &is_name);

    if (ret == 0) {
        if (is_name != should_be_name) {
            ret = -1;
        } else {
            fd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
            if (fd == INVALID_SOCKET) {
                ret = -1;
            } else {
                ret = socket_ping_pong(fd, (struct sockaddr*)&server_address, server_sockets);
            }

            SOCKET_CLOSE(fd);
        }
    }

    return ret;
}

int socket_test_port(picoquic_server_sockets_t* server_sockets, int test_port)
{
    int ret = 0;

    /* For a series of server addresses, do a ping pong test */
    if (socket_test_one("127.0.0.1", test_port, 0, server_sockets) != 0) {
        ret = -1;
    }
    else if (socket_test_one("::1", test_port, 0, server_sockets) != 0) {
        ret = -1;
    }
    else if (socket_test_one("localhost", test_port, 1, server_sockets) != 0) {
        ret = -1;
    }

    return ret;
}

int socket_test(void)
{
    int ret = 0;
    int test_port = 12345;
    int test_port2 = 1234;

    /* Open server sockets */
    picoquic_server_sockets_t server_sockets;
    ret = picoquic_open_server_sockets(&server_sockets, test_port);

    if (ret == 0) {

        /* Test with one server socket */
        ret = socket_test_port(&server_sockets, test_port);

        if (ret == 0) {
            /* Test with two server sockets */
            picoquic_server_sockets_t server_sockets2;
            ret = picoquic_open_server_sockets(&server_sockets2, test_port2);

            if (ret == 0) {
                ret = socket_test_port(&server_sockets2, test_port2);
                picoquic_close_server_sockets(&server_sockets2);
            }
        }

        /* Close the sockets */
        picoquic_close_server_sockets(&server_sockets);
    }

    return ret;
}

/*
 * Test whether ECN values can be set.
 */

int socket_ecn_test_one(int af_domain)
{
    int ret = 0;
    SOCKET_TYPE fd = picoquic_open_client_socket(af_domain);

    if (fd == INVALID_SOCKET) {
        ret = -1;
    }
    else {
        int recv_set = 0;
        int send_set = 0;

        ret = picoquic_socket_set_ecn_options(fd, af_domain, &recv_set, &send_set);

        if (ret != 0) {
            DBG_PRINTF("Cannot set ECN options, af = %d, ret = %d\n", af_domain, ret);
        } else if (!recv_set) {
            DBG_PRINTF("Cannot receive ECN flags, af = %d\n", af_domain);
            ret = -1;
        } else if (!send_set){
            DBG_PRINTF("Cannot send ECN 0, af = %d\n", af_domain);
#ifndef _WINDOWS
            ret = -1;
#endif
        }

        SOCKET_CLOSE(fd);
    }

    return ret;
}

int socket_ecn_test(void)
{
    int ret;

    ret = socket_ecn_test_one(AF_INET);

    if (ret == 0) {
        ret = socket_ecn_test_one(AF_INET6);
    }

    return ret;
}

/*
 * Test that child processes do not inherit the sockets opened by picoquic.
 * Open sockets, start a child process, close the sockets, then check that
 * their ports can be bound again while the child is still running.
 */
#ifndef _WINDOWS
typedef struct st_socket_cloexec_port_t {
    char const* name;
    int af;
    int sock_type;
    uint16_t port;
} socket_cloexec_port_t;

static int socket_cloexec_get_port(socket_cloexec_port_t* p, char const* name, SOCKET_TYPE fd, int sock_type)
{
    struct sockaddr_storage addr;
    int ret = (fd == INVALID_SOCKET) ? -1 : picoquic_get_local_address(fd, &addr);

    if (ret == 0) {
        p->name = name;
        p->af = addr.ss_family;
        p->sock_type = sock_type;
        p->port = ntohs((addr.ss_family == AF_INET6) ?
            ((struct sockaddr_in6*)&addr)->sin6_port : ((struct sockaddr_in*)&addr)->sin_port);
    }
    return ret;
}

/* Bind a new socket to the same port, without SO_REUSEADDR or SO_REUSEPORT */
static int socket_cloexec_bind_again(socket_cloexec_port_t* p)
{
    int ret = 0;
    int val = 1;
    SOCKET_TYPE fd = socket(p->af, p->sock_type, 0);

    if (fd == INVALID_SOCKET ||
        (p->af == AF_INET6 && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(val)) != 0) ||
        picoquic_bind_to_port(fd, p->af, p->port) != 0) {
        DBG_PRINTF("%s socket (af=%d), port %d still in use after close, errno=%d: %s",
            p->name, p->af, p->port, errno, strerror(errno));
        ret = -1;
    }
    if (fd != INVALID_SOCKET) {
        SOCKET_CLOSE(fd);
    }
    return ret;
}
#endif

int socket_cloexec_test(void)
{
    int ret = 0;
#ifndef _WINDOWS
    picoquic_packet_loop_param_t param = { 0 };
    picoquic_socket_ctx_t s_ctx[1] = { 0 };
    picoquic_server_sockets_t server_sockets;
    SOCKET_TYPE client_fd = INVALID_SOCKET;
    picoqmux_socket_ctx_t* qmux_ctx = NULL;
    socket_cloexec_port_t ports[5];
    int nb_ports = 0;
    pid_t child = -1;
    char* child_argv[] = { "sleep", "10", NULL };

    s_ctx[0].fd = INVALID_SOCKET;
    for (int i = 0; i < PICOQUIC_NB_SERVER_SOCKETS; i++) {
        server_sockets.s_socket[i] = INVALID_SOCKET;
    }
    /* Open sockets with each picoquic API, on ephemeral ports */
    param.local_af = AF_INET;
    if (picoquic_packet_loop_open_sockets(&param, s_ctx, 0) != 1 ||
        socket_cloexec_get_port(&ports[nb_ports++], "packet loop", s_ctx[0].fd, SOCK_DGRAM) != 0 ||
        picoquic_open_server_sockets(&server_sockets, 0) != 0 ||
        socket_cloexec_get_port(&ports[nb_ports++], "server", server_sockets.s_socket[0], SOCK_DGRAM) != 0 ||
        socket_cloexec_get_port(&ports[nb_ports++], "server", server_sockets.s_socket[1], SOCK_DGRAM) != 0 ||
        (client_fd = picoquic_open_client_socket(AF_INET)) == INVALID_SOCKET ||
        picoquic_bind_to_port(client_fd, AF_INET, 0) != 0 ||
        socket_cloexec_get_port(&ports[nb_ports++], "client", client_fd, SOCK_DGRAM) != 0 ||
        (qmux_ctx = picoquic_packet_loop_open_qmux_socket(AF_INET, 0, 0, 1)) == NULL ||
        socket_cloexec_get_port(&ports[nb_ports++], "qmux", qmux_ctx->fd, SOCK_STREAM) != 0) {
        DBG_PRINTF("Cannot open the test sockets, nb_ports=%d", nb_ports);
        ret = -1;
    }
    /* glibc, musl, macOS and FreeBSD return from posix_spawn after the exec in the child */
    if (ret == 0 && posix_spawnp(&child, child_argv[0], NULL, NULL, child_argv, environ) != 0) {
        DBG_PRINTF("%s", "Cannot start the child process");
        child = -1;
        ret = -1;
    }
    picoquic_packet_loop_close_socket(&s_ctx[0]);
    picoquic_close_server_sockets(&server_sockets);
    if (client_fd != INVALID_SOCKET) {
        SOCKET_CLOSE(client_fd);
    }
    picoquic_packet_loop_free_qmux_socket(qmux_ctx);

    if (ret == 0) {
        for (int i = 0; i < nb_ports; i++) {
            if (socket_cloexec_bind_again(&ports[i]) != 0) {
                ret = -1;
            }
        }
    }
    if (child > 0) {
        (void)kill(child, SIGKILL);
        (void)waitpid(child, NULL, 0);
    }
#endif
    return ret;
}
