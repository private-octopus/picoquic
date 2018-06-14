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
#include "util.h"

static int bind_to_port(SOCKET_TYPE fd, int af, int port)
{
    struct sockaddr_storage sa;
    int addr_length = 0;

    memset(&sa, 0, sizeof(sa));

    if (af == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)&sa;
#ifdef _WINDOWS
        s4->sin_family = (ADDRESS_FAMILY)af;
#else
        s4->sin_family = af;
#endif
        s4->sin_port = htons((unsigned short)port);
        addr_length = sizeof(struct sockaddr_in);
    } else {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)&sa;

        s6->sin6_family = AF_INET6;
        s6->sin6_port = htons((unsigned short)port);
        addr_length = sizeof(struct sockaddr_in6);
    }

    return bind(fd, (struct sockaddr*)&sa, addr_length);
}

int picoquic_open_server_sockets(picoquic_server_sockets_t* sockets, int port)
{
    int ret = 0;
    const int sock_af[] = { AF_INET6, AF_INET };

    for (int i = 0; i < PICOQUIC_NB_SERVER_SOCKETS; i++) {
        if (ret == 0) {
            sockets->s_socket[i] = socket(sock_af[i], SOCK_DGRAM, IPPROTO_UDP);
        } else {
            sockets->s_socket[i] = INVALID_SOCKET;
        }

        if (sockets->s_socket[i] == INVALID_SOCKET) {
            ret = -1;
        }
        else {
#ifdef _WINDOWS
            int option_value = 1;
            if (sock_af[i] == AF_INET6) {
                ret = setsockopt(sockets->s_socket[i], IPPROTO_IPV6, IPV6_PKTINFO, (char*)&option_value, sizeof(int));
            }
            else {
                ret = setsockopt(sockets->s_socket[i], IPPROTO_IP, IP_PKTINFO, (char*)&option_value, sizeof(int));
            }
#else
            if (sock_af[i] == AF_INET6) {
                int val = 1;
                ret = setsockopt(sockets->s_socket[i], IPPROTO_IPV6, IPV6_V6ONLY,
                    &val, sizeof(val));
                if (ret == 0) {
                    val = 1;
                    ret = setsockopt(sockets->s_socket[i], IPPROTO_IPV6, IPV6_RECVPKTINFO, (char*)&val, sizeof(int));
                }
            }
            else {
                int val = 1;
#ifdef IP_PKTINFO
                ret = setsockopt(sockets->s_socket[i], IPPROTO_IP, IP_PKTINFO, (char*)&val, sizeof(int));
#else
                /* The IP_PKTINFO structure is not defined on BSD */
                ret = setsockopt(sockets->s_socket[i], IPPROTO_IP, IP_RECVDSTADDR, (char*)&val, sizeof(int));
#endif
            }
#endif
            if (ret == 0) {
                ret = bind_to_port(sockets->s_socket[i], sock_af[i], port);
            }
        }
    }

    return ret;
}

void picoquic_close_server_sockets(picoquic_server_sockets_t* sockets)
{
    for (int i = 0; i < PICOQUIC_NB_SERVER_SOCKETS; i++) {
        if (sockets->s_socket[i] != INVALID_SOCKET) {
            SOCKET_CLOSE(sockets->s_socket[i]);
            sockets->s_socket[i] = INVALID_SOCKET;
        }
    }
}

int picoquic_recvmsg(SOCKET_TYPE fd,
    struct sockaddr_storage* addr_from,
    socklen_t* from_length,
    struct sockaddr_storage* addr_dest,
    socklen_t* dest_length,
    unsigned long* dest_if,
    uint8_t* buffer, int buffer_max)
#ifdef _WINDOWS
{
    GUID WSARecvMsg_GUID = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG WSARecvMsg;
    char cmsg_buffer[1024];
    DWORD NumberOfBytes;
    int nResult;
    WSAMSG msg;
    WSABUF dataBuf;
    int recv_ret = 0;
    int bytes_recv;
    int last_error;

    if (dest_length != NULL) {
        *dest_length = 0;
    }

    if (dest_if != NULL) {
        *dest_if = 0;
    }

    nResult = WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &WSARecvMsg_GUID, sizeof WSARecvMsg_GUID,
        &WSARecvMsg, sizeof WSARecvMsg,
        &NumberOfBytes, NULL, NULL);

    if (nResult == SOCKET_ERROR) {
        last_error = WSAGetLastError();
        DBG_PRINTF("Could not initialize WSARecvMsg) on UDP socket %d= %d!\n",
            (int)fd, last_error);
        bytes_recv = -1;
        *from_length = 0;
    } else {
        dataBuf.buf = (char*)buffer;
        dataBuf.len = buffer_max;

        msg.name = (struct sockaddr*)addr_from;
        msg.namelen = *from_length;
        msg.lpBuffers = &dataBuf;
        msg.dwBufferCount = 1;
        msg.dwFlags = 0;
        msg.Control.buf = cmsg_buffer;
        msg.Control.len = sizeof(cmsg_buffer);

        recv_ret = WSARecvMsg(fd, &msg, &NumberOfBytes, NULL, NULL);

        if (recv_ret != 0) {
            last_error = WSAGetLastError();
            DBG_PRINTF("Could not receive message (WSARecvMsg) on UDP socket %d = %d!\n",
                (int)fd, last_error);
            bytes_recv = -1;
            *from_length = 0;
        } else {
            struct cmsghdr* cmsg;

            bytes_recv = NumberOfBytes;
            *from_length = msg.namelen;

            /* Get the control information */
            for (cmsg = WSA_CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = WSA_CMSG_NXTHDR(&msg, cmsg)) {
                if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_PKTINFO)) {
                    if (addr_dest != NULL && dest_length != NULL) {
                        IN_PKTINFO* pPktInfo = (IN_PKTINFO*)WSA_CMSG_DATA(cmsg);
                        ((struct sockaddr_in*)addr_dest)->sin_family = AF_INET;
                        ((struct sockaddr_in*)addr_dest)->sin_port = 0;
                        ((struct sockaddr_in*)addr_dest)->sin_addr.s_addr = pPktInfo->ipi_addr.s_addr;
                        *dest_length = sizeof(struct sockaddr_in);

                        if (dest_if != NULL) {
                            *dest_if = pPktInfo->ipi_ifindex;
                        }
                    }
                } else if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
                    if (addr_dest != NULL && dest_length != NULL) {
                        IN6_PKTINFO* pPktInfo6 = (IN6_PKTINFO*)WSA_CMSG_DATA(cmsg);
                        ((struct sockaddr_in6*)addr_dest)->sin6_family = AF_INET6;
                        ((struct sockaddr_in6*)addr_dest)->sin6_port = 0;
                        memcpy(&((struct sockaddr_in6*)addr_dest)->sin6_addr, &pPktInfo6->ipi6_addr, sizeof(IN6_ADDR));
                        *dest_length = sizeof(struct sockaddr_in6);

                        if (dest_if != NULL) {
                            *dest_if = pPktInfo6->ipi6_ifindex;
                        }
                    }
                }
            }
        }
    }

    return bytes_recv;
}
#else
{
    int bytes_recv = 0;
    struct msghdr msg;
    struct iovec dataBuf;
    char cmsg_buffer[1024];

    if (dest_length != NULL) {
        *dest_length = 0;
    }

    if (dest_if != NULL) {
        *dest_if = 0;
    }

    dataBuf.iov_base = (char*)buffer;
    dataBuf.iov_len = buffer_max;

    msg.msg_name = (struct sockaddr*)addr_from;
    msg.msg_namelen = *from_length;
    msg.msg_iov = &dataBuf;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = (void*)cmsg_buffer;
    msg.msg_controllen = sizeof(cmsg_buffer);

    bytes_recv = recvmsg(fd, &msg, 0);

    if (bytes_recv <= 0) {
        *from_length = 0;
    } else {
        /* Get the control information */
        struct cmsghdr* cmsg;
        *from_length = msg.msg_namelen;

        for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
#ifdef IP_PKTINFO
            if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_PKTINFO)) {
                if (addr_dest != NULL && dest_length != NULL) {
                    struct in_pktinfo* pPktInfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
                    ((struct sockaddr_in*)addr_dest)->sin_family = AF_INET;
                    ((struct sockaddr_in*)addr_dest)->sin_port = 0;
                    ((struct sockaddr_in*)addr_dest)->sin_addr.s_addr = pPktInfo->ipi_addr.s_addr;
                    *dest_length = sizeof(struct sockaddr_in);

                    if (dest_if != NULL) {
                        *dest_if = pPktInfo->ipi_ifindex;
                    }
                }
#else
            /* The IP_PKTINFO structure is not defined on BSD */
            if ((cmsg->cmsg_level == IPPROTO_IP) && (cmsg->cmsg_type == IP_RECVDSTADDR)) {
                if (addr_dest != NULL && dest_length != NULL) {
                    struct in_addr* pPktInfo = (struct in_addr*)CMSG_DATA(cmsg);
                    ((struct sockaddr_in*)addr_dest)->sin_family = AF_INET;
                    ((struct sockaddr_in*)addr_dest)->sin_port = 0;
                    ((struct sockaddr_in*)addr_dest)->sin_addr.s_addr = pPktInfo->s_addr;
                    *dest_length = sizeof(struct sockaddr_in);

                    if (dest_if != NULL) {
                        *dest_if = 0;
                    }
                }

#endif
            } else if ((cmsg->cmsg_level == IPPROTO_IPV6) && (cmsg->cmsg_type == IPV6_PKTINFO)) {
                if (addr_dest != NULL && dest_length != NULL) {
                    struct in6_pktinfo* pPktInfo6 = (struct in6_pktinfo*)CMSG_DATA(cmsg);

                    ((struct sockaddr_in6*)addr_dest)->sin6_family = AF_INET6;
                    ((struct sockaddr_in6*)addr_dest)->sin6_port = 0;
                    memcpy(&((struct sockaddr_in6*)addr_dest)->sin6_addr, &pPktInfo6->ipi6_addr, sizeof(struct in6_addr));
                    *dest_length = sizeof(struct sockaddr_in6);

                    if (dest_if != NULL) {
                        *dest_if = pPktInfo6->ipi6_ifindex;
                    }
                }
            }
        }
    }

    return bytes_recv;
}
#endif

int picoquic_sendmsg(SOCKET_TYPE fd,
    struct sockaddr* addr_dest,
    socklen_t dest_length,
    struct sockaddr* addr_from,
    socklen_t from_length,
    unsigned long dest_if,
    const char* bytes, int length)
#ifdef _WINDOWS
{
    GUID WSASendMsg_GUID = WSAID_WSASENDMSG;
    LPFN_WSASENDMSG WSASendMsg;
    char cmsg_buffer[1024];
    int control_length = 0;
    DWORD NumberOfBytes;
    int ret = 0;
    DWORD dwBytesSent = 0;
    WSAMSG msg;
    WSABUF dataBuf;
    int bytes_sent;
    int last_error;
    WSACMSGHDR* cmsg;

    ret = WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER,
        &WSASendMsg_GUID, sizeof WSASendMsg_GUID,
        &WSASendMsg, sizeof WSASendMsg,
        &NumberOfBytes, NULL, NULL);

    if (ret == SOCKET_ERROR) {
        last_error = WSAGetLastError();
        DBG_PRINTF("Could not initialize WSARecvMsg) on UDP socket %d= %d!\n",
            (int)fd, last_error);
        bytes_sent = -1;
    } else {
        /* Format the message header */

        memset(&msg, 0, sizeof(msg));
        msg.name = addr_dest;
        msg.namelen = dest_length;
        dataBuf.buf = (char*)bytes;
        dataBuf.len = length;
        msg.lpBuffers = &dataBuf;
        msg.dwBufferCount = 1;
        msg.Control.buf = (char*)cmsg_buffer;
        msg.Control.len = sizeof(cmsg_buffer);

        /* Format the control message */
        cmsg = WSA_CMSG_FIRSTHDR(&msg);

        if (addr_from != NULL && from_length != 0) {
            if (addr_from->sa_family == AF_INET) {
                memset(cmsg, 0, WSA_CMSG_SPACE(sizeof(struct in_pktinfo)));
                cmsg->cmsg_level = IPPROTO_IP;
                cmsg->cmsg_type = IP_PKTINFO;
                cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(struct in_pktinfo));
                struct in_pktinfo* pktinfo = (struct in_pktinfo*)WSA_CMSG_DATA(cmsg);
                pktinfo->ipi_addr.s_addr = ((struct sockaddr_in*)addr_from)->sin_addr.s_addr;
                pktinfo->ipi_ifindex = dest_if;

                control_length += WSA_CMSG_SPACE(sizeof(struct in_pktinfo));
            }
            else {
                memset(cmsg, 0, WSA_CMSG_SPACE(sizeof(struct in6_pktinfo)));
                cmsg->cmsg_level = IPPROTO_IPV6;
                cmsg->cmsg_type = IPV6_PKTINFO;
                cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(struct in6_pktinfo));
                struct in6_pktinfo* pktinfo6 = (struct in6_pktinfo*)WSA_CMSG_DATA(cmsg);
                memcpy(&pktinfo6->ipi6_addr.u, &((struct sockaddr_in6*)addr_from)->sin6_addr.u, sizeof(IN6_ADDR));
                pktinfo6->ipi6_ifindex = dest_if;

                control_length += WSA_CMSG_SPACE(sizeof(struct in6_pktinfo));
            }

            if (addr_from->sa_family == AF_INET6) {
                struct cmsghdr * cmsg_2 = WSA_CMSG_NXTHDR(&msg, cmsg);
                if (cmsg_2 == NULL) {
                    DBG_PRINTF("Cannot obtain second CMSG (control_length: %d)\n", control_length);
                }
                else {
                    int val = 1;
                    cmsg_2->cmsg_level = IPPROTO_IPV6;
                    cmsg_2->cmsg_type = IPV6_DONTFRAG;
                    cmsg_2->cmsg_len = WSA_CMSG_LEN(sizeof(int));
                    *((int *)WSA_CMSG_DATA(cmsg_2)) = val;
                    control_length += WSA_CMSG_SPACE(sizeof(int));
                }
            }
        }

        msg.Control.len = control_length;
        if (control_length == 0) {
            msg.Control.buf = NULL;
        }

        /* Send the message */

        ret = WSASendMsg(fd, &msg, 0, &dwBytesSent, NULL, NULL);

        if (ret != 0) {
            bytes_sent = -1;
        } else {
            bytes_sent = (int)dwBytesSent;
        }
    }

    return bytes_sent;
}
#else
{
    struct msghdr msg;
    struct iovec dataBuf;
    char cmsg_buffer[1024];
    int control_length = 0;
    int bytes_sent;
    struct cmsghdr* cmsg;

    /* Format the message header */

    dataBuf.iov_base = (char*)bytes;
    dataBuf.iov_len = length;

    memset(&msg, 0, sizeof(msg));
    msg.msg_name = addr_dest;
    msg.msg_namelen = dest_length;
    msg.msg_iov = &dataBuf;
    msg.msg_iovlen = 1;
    msg.msg_control = (void*)cmsg_buffer;
    msg.msg_controllen = sizeof(cmsg_buffer);

    /* Format the control message */
    cmsg = CMSG_FIRSTHDR(&msg);

    if (addr_from != NULL && from_length != 0) {
        if (addr_from->sa_family == AF_INET) {
#ifdef IP_PKTINFO
            memset(cmsg, 0, CMSG_SPACE(sizeof(struct in_pktinfo)));
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
            struct in_pktinfo* pktinfo = (struct in_pktinfo*)CMSG_DATA(cmsg);
            pktinfo->ipi_addr.s_addr = ((struct sockaddr_in*)addr_from)->sin_addr.s_addr;
            pktinfo->ipi_ifindex = dest_if;
            control_length += CMSG_SPACE(sizeof(struct in_pktinfo));
#else
            /* The IP_PKTINFO structure is not defined on BSD */
            memset(cmsg, 0, CMSG_SPACE(sizeof(struct in_addr)));
            cmsg->cmsg_level = IPPROTO_IP;
            cmsg->cmsg_type = IP_SENDSRCADDR;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in_addr));
            struct in_addr* pktinfo = (struct in_addr*)CMSG_DATA(cmsg);
            pktinfo->s_addr = ((struct sockaddr_in*)addr_from)->sin_addr.s_addr;
            control_length += CMSG_SPACE(sizeof(struct in_addr));
#endif
        } else if (addr_from->sa_family == AF_INET6) {
            memset(cmsg, 0, CMSG_SPACE(sizeof(struct in6_pktinfo)));
            cmsg->cmsg_level = IPPROTO_IPV6;
            cmsg->cmsg_type = IPV6_PKTINFO;
            cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
            struct in6_pktinfo* pktinfo6 = (struct in6_pktinfo*)CMSG_DATA(cmsg);
            memcpy(&pktinfo6->ipi6_addr, &((struct sockaddr_in6*)addr_from)->sin6_addr, sizeof(struct in6_addr));
            pktinfo6->ipi6_ifindex = dest_if;

            control_length += CMSG_SPACE(sizeof(struct in6_pktinfo));
        } else {
            DBG_PRINTF("Unexpected address family: %d\n", addr_from->sa_family);
        }
#ifdef IPV6_DONTFRAG
        if (addr_from->sa_family == AF_INET6) {
#ifdef CMSG_ALIGN
            struct cmsghdr * cmsg_2 = (struct cmsghdr *)((unsigned char *)cmsg + CMSG_ALIGN(cmsg->cmsg_len));
            {
#else
            struct cmsghdr * cmsg_2 = CMSG_NXTHDR((&msg), cmsg);
            if (cmsg_2 == NULL) {
                DBG_PRINTF("Cannot obtain second CMSG (control_length: %d)\n", control_length);
            } else {
#endif
                int val = 1;
                cmsg_2->cmsg_level = IPPROTO_IPV6;
                cmsg_2->cmsg_type = IPV6_DONTFRAG;
                cmsg_2->cmsg_len = CMSG_LEN(sizeof(int));
                memcpy(CMSG_DATA(cmsg_2), &val, sizeof(int));
                control_length += CMSG_SPACE(sizeof(int));
            }
        }
#endif
    }

    msg.msg_controllen = control_length;
    if (control_length == 0) {
        msg.msg_control = NULL;
    }

    bytes_sent = sendmsg(fd, &msg, 0);

    return bytes_sent;
}
#endif

int picoquic_select(SOCKET_TYPE* sockets,
    int nb_sockets,
    struct sockaddr_storage* addr_from,
    socklen_t* from_length,
    struct sockaddr_storage* addr_dest,
    socklen_t* dest_length,
    unsigned long* dest_if,
    uint8_t* buffer, int buffer_max,
    int64_t delta_t,
    uint64_t* current_time)
{
    fd_set readfds;
    struct timeval tv;
    int ret_select = 0;
    int bytes_recv = 0;
    int sockmax = 0;

    FD_ZERO(&readfds);

    for (int i = 0; i < nb_sockets; i++) {
        if (sockmax < (int)sockets[i]) {
            sockmax = (int)sockets[i];
        }
        FD_SET(sockets[i], &readfds);
    }

    if (delta_t <= 0) {
        tv.tv_sec = 0;
        tv.tv_usec = 0;
    } else {
        if (delta_t > 10000000) {
            tv.tv_sec = (long)10;
            tv.tv_usec = 0;
        } else {
            tv.tv_sec = (long)(delta_t / 1000000);
            tv.tv_usec = (long)(delta_t % 1000000);
        }
    }

    ret_select = select(sockmax + 1, &readfds, NULL, NULL, &tv);

    if (ret_select < 0) {
        bytes_recv = -1;
        if (bytes_recv <= 0) {
            DBG_PRINTF("Error: select returns %d\n", ret_select);
        }
    } else if (ret_select > 0) {
        for (int i = 0; i < nb_sockets; i++) {
            if (FD_ISSET(sockets[i], &readfds)) {
                bytes_recv = picoquic_recvmsg(sockets[i], addr_from, from_length,
                    addr_dest, dest_length, dest_if,
                    buffer, buffer_max);
                // bytes_recv = recvfrom(socket[i], buffer, buffer_max, 0, addr_from, from_length);

                if (bytes_recv <= 0) {
#ifdef _WINDOWS
                    int last_error = WSAGetLastError();

                    if (last_error == WSAECONNRESET || last_error == WSAEMSGSIZE) {
                        bytes_recv = 0;
                        continue;
                    }
#endif
                    DBG_PRINTF("Could not receive packet on UDP socket[%d]= %d!\n",
                        i, (int)sockets[i]);

                    break;
                } else {
                    break;
                }
            }
        }
    }

    *current_time = picoquic_current_time();

    return bytes_recv;
}

int picoquic_send_through_server_sockets(
    picoquic_server_sockets_t* sockets,
    struct sockaddr* addr_dest, socklen_t dest_length,
    struct sockaddr* addr_from, socklen_t from_length, unsigned long from_if,
    const char* bytes, int length)
{
    /* Both Linux and Windows use separate sockets for V4 and V6 */
    int socket_index = (addr_dest->sa_family == AF_INET) ? 1 : 0;

    int sent = picoquic_sendmsg(sockets->s_socket[socket_index], addr_dest, dest_length,
        addr_from, from_length, from_if, bytes, length);

#ifndef DISABLE_DEBUG_PRINTF
    if (sent <= 0) {
#ifdef _WINDOWS
        int last_error = WSAGetLastError();
#else
        int last_error = errno;
#endif
        DBG_PRINTF("Could not send packet on UDP socket[%d]= %d!\n",
            socket_index, last_error);
        DBG_PRINTF("Dest address length: %d, family: %d.\n",
            dest_length, addr_dest->sa_family);
    }
#endif

    return sent;
}

int picoquic_get_server_address(const char* ip_address_text, int server_port,
    struct sockaddr_storage* server_address,
    int* server_addr_length,
    int* is_name)
{
    int ret = 0;
    struct sockaddr_in* ipv4_dest = (struct sockaddr_in*)server_address;
    struct sockaddr_in6* ipv6_dest = (struct sockaddr_in6*)server_address;

    /* get the IP address of the server */
    memset(server_address, 0, sizeof(struct sockaddr_storage));
    *is_name = 0;
    *server_addr_length = 0;

    if (inet_pton(AF_INET, ip_address_text, &ipv4_dest->sin_addr) == 1) {
        /* Valid IPv4 address */
        ipv4_dest->sin_family = AF_INET;
        ipv4_dest->sin_port = htons((unsigned short)server_port);
        *server_addr_length = sizeof(struct sockaddr_in);
    } else if (inet_pton(AF_INET6, ip_address_text, &ipv6_dest->sin6_addr) == 1) {
        /* Valid IPv6 address */
        ipv6_dest->sin6_family = AF_INET6;
        ipv6_dest->sin6_port = htons((unsigned short)server_port);
        *server_addr_length = sizeof(struct sockaddr_in6);
    } else {
        /* Server is described by name. Do a lookup for the IP address,
        * and then use the name as SNI parameter */
        struct addrinfo* result = NULL;
        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;

        if (getaddrinfo(ip_address_text, NULL, &hints, &result) != 0) {
            fprintf(stderr, "Cannot get IP address for %s\n", ip_address_text);
            ret = -1;
        } else {
            *is_name = 1;

            switch (result->ai_family) {
            case AF_INET:
                ipv4_dest->sin_family = AF_INET;
                ipv4_dest->sin_port = htons((unsigned short)server_port);
#ifdef _WINDOWS
                ipv4_dest->sin_addr.S_un.S_addr = ((struct sockaddr_in*)result->ai_addr)->sin_addr.S_un.S_addr;
#else
                ipv4_dest->sin_addr.s_addr = ((struct sockaddr_in*)result->ai_addr)->sin_addr.s_addr;
#endif
                *server_addr_length = sizeof(struct sockaddr_in);
                break;
            case AF_INET6:
                ipv6_dest->sin6_family = AF_INET6;
                ipv6_dest->sin6_port = htons((unsigned short)server_port);
                memcpy(&ipv6_dest->sin6_addr,
                    &((struct sockaddr_in6*)result->ai_addr)->sin6_addr,
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
