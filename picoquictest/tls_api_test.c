#include "../picoquic/picoquic.h"

/*
 * Simulate losses based on a loss pattern.
 * Loss will only apply to the first 64 transmissions
 */
static int tls_api_loss_simulator(uint64_t * loss_mask)
{
	/* Last bit indicates loss or not */
	int ret = (int)((*loss_mask) & 1ull);
	/* Shift 1 to prepare next round */
	*loss_mask >>= 1;

	return ret;
}

static int tls_api_one_packet(picoquic_cnx * cnx, picoquic_quic * qreceive, 
    struct sockaddr * sender_addr, uint64_t * loss_mask)
{
    /* Simulate a connection */
    int ret = 0;
    picoquic_packet * p = picoquic_create_packet();
	uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
	size_t send_length = 0;
	static uint64_t simulated_time = 0;

    if (p == NULL)
    {
        ret = -1;
    }
    else
    {
		simulated_time += 500;

        ret = picoquic_prepare_packet(cnx, p, simulated_time, 
			bytes, PICOQUIC_MAX_PACKET_SIZE, &send_length);

		if (ret == 0 && p->length > 0)
		{
			simulated_time += 500;

			if (loss_mask == NULL ||
				tls_api_loss_simulator(loss_mask) == 0)
			{
				/* Submit the packet to the server */
				ret = picoquic_incoming_packet(qreceive, bytes, send_length, sender_addr, 
					simulated_time);
			}
		}
		else
		{
			free(p);
		}
    }

    return ret;
}

static int tls_api_test_with_loss(uint64_t  * loss_mask)
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

    while (ret == 0 && nb_trials < 12 &&
        (cnx_client->cnx_state != picoquic_state_client_ready ||
        (cnx_server == NULL || cnx_server->cnx_state != picoquic_state_server_ready)))
    {
        nb_trials++;

        /* packet from client to server */
        ret = tls_api_one_packet(cnx_client, qserver, (struct sockaddr *)&client_addr, loss_mask);

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
                ret = tls_api_one_packet(cnx_server, qclient, (struct sockaddr *)&server_addr, loss_mask);
            }
        }
    }

    if (cnx_client->cnx_state != picoquic_state_client_ready ||
        cnx_server == NULL || cnx_server->cnx_state != picoquic_state_server_ready)
    {
        ret = -1;
    }
    else
    {
        ret = picoquic_close(cnx_client);

        if (ret == 0)
        {
            /* packet from client to server */
			/* Do not simulate losses there, as there is no way to correct them */
            ret = tls_api_one_packet(cnx_client, qserver, (struct sockaddr *)&client_addr, NULL);
        }

        if (ret == 0 && (
            cnx_client->cnx_state != picoquic_state_disconnected ||
            cnx_server->cnx_state != picoquic_state_disconnected))
        {
            ret = -1;
        }
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

int tls_api_test()
{
	return tls_api_test_with_loss(NULL);
}

int tls_api_loss_test(uint64_t mask)
{
	uint64_t loss_mask = mask;

	return tls_api_test_with_loss(&loss_mask);
}