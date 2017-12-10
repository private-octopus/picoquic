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

#include "util.h"
#include "picosocks.h"

static int bind_to_port(SOCKET_TYPE fd, int af, int port)
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
#ifndef _WINDOWS
            if (sock_af[i] == AF_INET6) {
                int val = 1;
                ret = setsockopt(sockets->s_socket[i], IPPROTO_IPV6, IPV6_V6ONLY,
                    &val, sizeof(val));
                if (ret)
                    return ret;
            }
#endif
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

uint64_t picoquic_current_time()
{
    uint64_t now;
#ifdef _WINDOWS
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
    struct timeval tv;
    (void)gettimeofday(&tv, NULL);
    now = (tv.tv_sec * 1000000ull) + tv.tv_usec;
#endif
    return now;
}

int picoquic_select(SOCKET_TYPE * sockets, int nb_sockets,
    struct sockaddr_storage * addr_from,
    socklen_t * from_length,
    uint8_t * buffer, int buffer_max,
    int64_t delta_t,
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
        if (sockmax < (int)sockets[i])
        {
            sockmax = sockets[i];
        }
        FD_SET(sockets[i], &readfds);
    }

    if (delta_t <= 0)
    {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    }
    else
    {
        if (delta_t > 10000000)
        {
            tv.tv_sec = (long)10;
            tv.tv_usec = 0;
        }
        else
        {
            tv.tv_sec = (long)(delta_t / 1000000);
            tv.tv_usec = (long)(delta_t % 1000000);
        }
    }

    ret_select = select(sockmax + 1, &readfds, NULL, NULL, &tv);

    if (ret_select < 0)
    {
        bytes_recv = -1;
        if (bytes_recv <= 0)
        {
            DBG_PRINTF("Error: select returns %d\n", ret_select);
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
#ifdef _WINDOWS
                    int last_error = WSAGetLastError();

                    if (last_error == WSAECONNRESET)
                    {
                        bytes_recv = 0;
                        continue;
                    }
#endif
                    DBG_PRINTF("Could not receive packet on UDP socket[%d]= %d!\n",
                        i, (int)sockets[i]);

                    break;
                }
                else
                {
                    break;
                }
            }
        }
    }

    *current_time = picoquic_current_time();

    return bytes_recv;
}

int picoquic_send_through_server_sockets(
    picoquic_server_sockets_t * sockets,
    struct sockaddr * addr_dest, socklen_t addr_length,
    const char * bytes, int length)
{
    /* Both Linux and Windows use separate sockets for V4 and V6 */
    int socket_index = (addr_dest->sa_family == AF_INET) ? 1 : 0;

    int sent = sendto(sockets->s_socket[socket_index], bytes, length, 0,
        addr_dest, addr_length);

    return sent;
}

int picoquic_get_server_address(const char * ip_address_text, int server_port, 
    struct sockaddr_storage *server_address,
    int * server_addr_length,
    int * is_name)
{
    int ret = 0;
    struct sockaddr_in * ipv4_dest = (struct sockaddr_in *)server_address;
    struct sockaddr_in6 * ipv6_dest = (struct sockaddr_in6 *)server_address;

    /* get the IP address of the server */
    memset(server_address, 0, sizeof(struct sockaddr_storage));
    *is_name = 0;
    *server_addr_length = 0;

    if (inet_pton(AF_INET, ip_address_text, &ipv4_dest->sin_addr) == 1)
    {
        /* Valid IPv4 address */
        ipv4_dest->sin_family = AF_INET;
        ipv4_dest->sin_port = htons(server_port);
        *server_addr_length = sizeof(struct sockaddr_in);
    }
    else if (inet_pton(AF_INET6, ip_address_text, &ipv6_dest->sin6_addr) == 1)
    {
        /* Valid IPv6 address */
        ipv6_dest->sin6_family = AF_INET6;
        ipv6_dest->sin6_port = htons(server_port);
        *server_addr_length = sizeof(struct sockaddr_in6);
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
            *is_name = 1;

            switch (result->ai_family)
            {
            case AF_INET:
                ipv4_dest->sin_family = AF_INET;
                ipv4_dest->sin_port = htons(server_port);
#ifdef _WINDOWS
                ipv4_dest->sin_addr.S_un.S_addr =
                    ((struct sockaddr_in *) result->ai_addr)->sin_addr.S_un.S_addr;
#else
                ipv4_dest->sin_addr.s_addr =
                    ((struct sockaddr_in *) result->ai_addr)->sin_addr.s_addr;
#endif
                *server_addr_length = sizeof(struct sockaddr_in);
                break;
            case AF_INET6:
                ipv6_dest->sin6_family = AF_INET6;
                ipv6_dest->sin6_port = htons(server_port);
                memcpy(&ipv6_dest->sin6_addr,
                    &((struct sockaddr_in6 *) result->ai_addr)->sin6_addr,
                    sizeof(ipv6_dest->sin6_addr));
                *server_addr_length = sizeof(struct sockaddr_in6);
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

    return ret;
}