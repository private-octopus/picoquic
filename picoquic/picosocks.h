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

#ifndef PICOSOCKS_H
#define PICOSOCKS_H

#ifdef _WINDOWS
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

#else  /* Linux */

#include <stdint.h>
#include "getopt.h"
#include <stdlib.h>
#include <alloca.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#ifndef __USE_XOPEN2K
#define __USE_XOPEN2K
#endif
#ifndef __USE_POSIX
#define __USE_POSIX
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


#define PICOQUIC_NB_SERVER_SOCKETS 2

typedef struct st_picoquic_server_sockets_t {
    SOCKET_TYPE s_socket[PICOQUIC_NB_SERVER_SOCKETS];
} picoquic_server_sockets_t;

int picoquic_open_server_sockets(picoquic_server_sockets_t * sockets, int port);

void picoquic_close_server_sockets(picoquic_server_sockets_t * sockets);

uint64_t picoquic_current_time();

int picoquic_select(SOCKET_TYPE * sockets, int nb_sockets,
    struct sockaddr_storage * addr_from,
    socklen_t * from_length,
    uint8_t * buffer, int buffer_max,
    int64_t delta_t,
    uint64_t * current_time);

int picoquic_send_through_server_sockets(
    picoquic_server_sockets_t * sockets,
    struct sockaddr * addr_dest, socklen_t addr_length,
    const char * bytes, int length);

int picoquic_get_server_address(const char * ip_address_text, int server_port,
    struct sockaddr_storage *server_address,
    int * server_addr_length,
    int * is_name);

#endif