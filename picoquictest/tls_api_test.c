#include "../picoquic/picoquic.h"

int tls_api_one_packet(picoquic_cnx * cnx, picoquic_quic * qreceive, 
    struct sockaddr * sender_addr)
{
    /* Simulate a connection */
    int ret = 0;
    picoquic_packet * p = picoquic_create_packet();

    if (p == NULL)
    {
        ret = -1;
    }
    else
    {
        ret = picoquic_prepare_packet(cnx, p);

        if (ret == 0)
        {
            if (p->length > 0)
            {
                /* Submit the packet to the server */
                ret = picoquic_incoming_packet(qreceive, p->bytes, p->length, sender_addr);
            }
            else
            {
                free(p);
            }
        }
    }

    return ret;
}

int tls_api_test()
{

    int ret = 0;
    picoquic_quic * qclient = NULL, * qserver = NULL;
    picoquic_cnx * cnx_client = NULL, * cnx_server = NULL;
    struct sockaddr_in client_addr, server_addr;
    int nb_trials = 0;

    /* Init of the IP addresses */
    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.S_un.S_addr = 0x0A000002;
    client_addr.sin_port = 1234;

    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.S_un.S_addr = 0x0A000001;
    server_addr.sin_port = 4321;


    /* Test the creation of the client and server contexts */
    /* Create QUIC context */
    qclient = picoquic_create(8, NULL, NULL);
    qserver = picoquic_create(8, "..\\certs\\cert.pem", "..\\certs\\key.pem");

    if (qclient == NULL || qserver == NULL)
    {
        ret = -1;
    }

    if (ret == 0)
    {
        /* Create a client connection */
        cnx_client = picoquic_create_cnx(qclient, 12345, (struct sockaddr *)&server_addr);

        if (cnx_client == NULL)
        {
            ret = -1;
        }
    }

    while (ret == 0 && nb_trials < 6 &&
        (cnx_client->cnx_state != picoquic_state_client_ready ||
        (cnx_server == NULL || cnx_server->cnx_state != picoquic_state_server_ready)))

    {
        nb_trials++;

        /* packet from client to server */
        ret = tls_api_one_packet(cnx_client, qserver, (struct sockaddr *)&client_addr);

        if (ret == 0)
        {
            if (cnx_server == NULL)
            {
                cnx_server = qserver->cnx_list;
            }

            if (cnx_server == NULL)
            {
                ret = -1;
            }
            else
            {
                ret = tls_api_one_packet(cnx_server, qclient, (struct sockaddr *)&server_addr);
            }
        }
    }

    if (cnx_client->cnx_state != picoquic_state_client_ready ||
        cnx_server == NULL || cnx_server->cnx_state != picoquic_state_server_ready)
    {
        ret = -1;
    }

    if (qclient != NULL)
    {
        picoquic_free(qclient);
    }

    if (qserver != NULL)
    {
        picoquic_free(qserver);
    }

    return ret;
}