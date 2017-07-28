#include "../picoquic/picoquic.h"

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
#else
#ifndef SOCKET_TYPE 
#define SOCKET_TYPE int
#endif
#ifndef INVALID_SOCKET 
#define INVALID_SOCKET -1
#endif
#ifndef SOCKET_CLOSE
#define SOCKET_CLOSE(x) close(x)
#endif
#ifndef WSA_START_DATA
#define WSA_START_DATA int
#endif
#ifndef WSA_START
#define WSA_START(x, y) (*y = 0, true)
#endif
#endif

void print_address(struct sockaddr * address, int address_length, char * label)
{
    char hostname[256];
    char servInfo[256];
    int ret  = getnameinfo(address, address_length,
        hostname, 256, servInfo, 256, NI_NUMERICSERV);

    if (ret != 0) {
        if (address->sa_family == AF_INET)
        {
            struct sockaddr_in * s4 = (struct sockaddr_in *)address;

            printf("%s %d.%d.%d.%d:%d\n", label,
                s4->sin_addr.S_un.S_un_b.s_b1,
                s4->sin_addr.S_un.S_un_b.s_b2,
                s4->sin_addr.S_un.S_un_b.s_b3,
                s4->sin_addr.S_un.S_un_b.s_b4,
                ntohs(s4->sin_port));
        }
        else
        {
            printf("getnameinfo failed with error # %ld\n", WSAGetLastError());
        }
    }
    else {
        printf("%s %s:%s\n", label, hostname, servInfo);
    }
}

int bind_to_port(SOCKET fd, int af, int port)
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

int do_select(SOCKET fd,
    struct sockaddr_storage * addr_from,
    int * from_length,
    uint8_t * buffer, int buffer_max)
{

    fd_set   readfds;
    struct timeval tv;
    int ret_select = 0;
    int bytes_recv = 0;

    FD_ZERO(&readfds);
    FD_SET(fd, &readfds);

    tv.tv_sec = 1;
    tv.tv_usec = 0;

    ret_select = select(fd, &readfds, NULL, NULL, &tv);

    if (ret_select < 0)
    {
        bytes_recv = -1;
        if (bytes_recv <= 0)
        {
            fprintf(stderr, "Error: select returns %d\n", ret_select);
        }
    }
    else
    {
        if (FD_ISSET(fd, &readfds))
        {
            /* Read the incoming response */
            *from_length = sizeof(struct sockaddr_storage);
            bytes_recv = recvfrom(fd, (char*)buffer, buffer_max, 0,
                (struct sockaddr *)addr_from, from_length);
            if (bytes_recv <= 0)
            {
                fprintf(stderr, "Could not receive packet on UDP socket!\n");
            }
        }
    }

    return bytes_recv;
}

int quic_server(char * server_name, int server_port, char * pem_cert, char * pem_key)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic *qserver = NULL;
    picoquic_cnx *cnx_server = NULL;
    struct sockaddr_in server_addr;
    SOCKET_TYPE fd = INVALID_SOCKET;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage client_from;
    int from_length;
    int client_addr_length;
    uint8_t buffer[1536];
	uint8_t send_buffer[1536];
	size_t send_length = 0;
    int bytes_recv;
    int bytes_sent;
    picoquic_packet * p = NULL;
	uint64_t current_time = 0;

    /* Open a UDP socket */

    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.S_un.S_addr = 0;
    server_addr.sin_port = htons(server_port);
    fd = socket(server_addr.sin_family, SOCK_DGRAM, IPPROTO_UDP);

    ret = (fd != INVALID_SOCKET) ? 0 : -1;

    if (ret == 0)
    {
        if (bind(fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_in)) != 0)
        {
            fprintf(stderr, "Could not bind socket to port %d\n", server_port);
        }
    }

    /* Wait for packets and process them */
    if (ret == 0)
    {
        /* Create QUIC context */
        qserver = picoquic_create(8, pem_cert, pem_key);

        if (qserver == NULL)
        {
            fprintf(stderr, "Could not create server context\n");
            ret = -1;
        }
    }

    /* Wait for packets */
    while (ret == 0 && (cnx_server == NULL ||
        cnx_server->cnx_state != picoquic_state_disconnected))
    {
        bytes_recv = do_select(fd, &addr_from, &from_length,
            buffer, sizeof(buffer));

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
                    (size_t) bytes_recv, (struct sockaddr *) &addr_from, current_time);

                if (cnx_server == NULL && qserver->cnx_list != NULL)
                {
                    printf("Connection established, state = %d, from length: %d\n",
                        qserver->cnx_list->cnx_state, from_length);
                    cnx_server = qserver->cnx_list;
                    memset(&client_from, 0, sizeof(client_from));
                    memcpy(&client_from, &addr_from, from_length);
                    client_addr_length = from_length;
                    print_address((struct sockaddr*)&client_from, client_addr_length,
                        "Client address:");
                }
            }
			else
			{
				current_time += 1000000;
			}

            if (ret == 0 && cnx_server != NULL)
            {
                p = picoquic_create_packet();

                if (p == NULL)
                {
                    ret = -1;
                }
                else
                {
                    ret = picoquic_prepare_packet(cnx_server, p, current_time,
						send_buffer, sizeof(send_buffer), &send_length);

                    if (ret == 0)
                    {

                        printf("Connection state = %d\n",
                            cnx_server->cnx_state);
                        if (p->length > 0)
                        {
                            printf("Sending packet, %d bytes\n", send_length);
                            bytes_sent = sendto(fd, send_buffer, send_length, 0,
                                (struct sockaddr *) &addr_from, from_length);
                        }
                        else
                        {
                            free(p);
                        }
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

    if (fd != INVALID_SOCKET)
    {
        SOCKET_CLOSE(fd);
    }

    return ret;
}

int quic_client(char * ip_address_text, int server_port)
{
    /* Start: start the QUIC process with cert and key files */
    int ret = 0;
    picoquic_quic *qclient = NULL;
    picoquic_cnx *cnx_client = NULL;
    SOCKET_TYPE fd = INVALID_SOCKET;
    struct sockaddr_storage server_address;
    struct sockaddr_in * ipv4_dest = (struct sockaddr_in *)&server_address;
    struct sockaddr_in6 * ipv6_dest = (struct sockaddr_in6 *)&server_address;
    struct sockaddr_storage packet_from;
    int from_length;
    int server_addr_length = 0;
    uint8_t buffer[1536];
	uint8_t send_buffer[1536];
	size_t send_length = 0;
    int bytes_recv;
    int bytes_sent;
    picoquic_packet * p = NULL;
	uint64_t current_time = 0;

    /* get the IP address of the server */
    if (ret == 0)
    {
        memset(&server_address, 0, sizeof(server_address));

        if (InetPtonA(AF_INET, ip_address_text, &ipv4_dest->sin_addr) == 1)
        {
            /* Valid IPv4 address */
            ipv4_dest->sin_family = AF_INET;
            ipv4_dest->sin_port = htons(server_port);
            server_addr_length = sizeof(struct sockaddr_in);
        }
        else if (InetPtonA(AF_INET6, ip_address_text, &ipv6_dest->sin6_addr) == 1)
        {
            /* Valid IPv6 address */
            ipv6_dest->sin6_family = AF_INET6;
            ipv6_dest->sin6_port = htons(server_port);
            server_addr_length = sizeof(struct sockaddr_in6);
        }
        else
        {
            fprintf(stderr, "Could not parse the address: %s\n", ip_address_text);
            ret = -1;
        }
    }

    /* Open a UDP socket */

    fd = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP);
    ret = (fd != INVALID_SOCKET) ? 0 : -1;

    if (ret == 0)
    {
        ret = bind_to_port(fd, server_address.ss_family, server_port + 1);
    }

    /* Create QUIC context */
    if (ret == 0)
    {
        qclient = picoquic_create(8, NULL, NULL);

        if (qclient == NULL)
        {
            ret = -1;
        }
    }
    /* Create the client connection */
    if (ret == 0)
    {
        /* Create a client connection */
        uint64_t cnx_id = 0;

        cnx_client = picoquic_create_cnx(qclient, 0, 
            (struct sockaddr *)&server_address);

        if (cnx_client == NULL)
        {
            ret = -1;
        }
    }

    /* Wait for packets */
    while (ret == 0 &&
        cnx_client->cnx_state != picoquic_state_disconnected)
    {
        bytes_recv = do_select(fd, &packet_from, &from_length,
            buffer, sizeof(buffer));

        if (bytes_recv != 0)
        {
            printf("Select returns %d, from length %d\n", bytes_recv, from_length);
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
                /* Submit the packet to the client */
                ret = picoquic_incoming_packet(qclient, buffer,
                    (size_t)bytes_recv, (struct sockaddr *) &packet_from, current_time);

                printf("Processed %d bytes, state=%d\n", bytes_recv,
                    cnx_client->cnx_state);
            }
			else if (bytes_recv == 0)
			{
				current_time += 1000000;

				if (cnx_client->cnx_state == picoquic_state_client_ready)
				{
					printf("Connection established. Disconnecting now.\n");
					ret = picoquic_close(cnx_client);
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
                    ret = picoquic_prepare_packet(cnx_client, p, current_time, 
						send_buffer, sizeof(send_buffer), &send_length);

					if (ret == 0 && send_length > 0)
					{
						bytes_sent = sendto(fd, send_buffer, send_length, 0,
							(struct sockaddr *) &server_address, server_addr_length);
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
    WSADATA wsaData;
    int ret = 0;

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
                }
            }
        }
    }

    // Init WSA.
    if (ret == 0)
    {
        if (WSA_START(MAKEWORD(2, 2), &wsaData)) {
            fprintf(stderr, "Cannot init WSA\n");
            ret = -1;
        }
    }

    if (is_client == 0)
    {
        /* Run as server */
        printf("Starting PicoQUIC server on port %d, server name = %s\n", server_port, server_name);
        ret = quic_server(server_name, server_port, server_cert_file, server_key_file);
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
