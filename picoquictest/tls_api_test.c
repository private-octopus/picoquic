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

#include "../picoquic/picoquic_internal.h"

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

static int tls_api_one_packet(picoquic_quic_t * qsender, picoquic_cnx_t * cnx, picoquic_quic_t * qreceive,
    struct sockaddr * sender_addr, uint64_t * loss_mask, uint64_t * simulated_time)
{
    /* Simulate a connection */
    int ret = 0;
	picoquic_stateless_packet_t * sp = picoquic_dequeue_stateless_packet(qsender);
	size_t send_length = 0;

	if (sp != NULL)
	{
		if (sp->length > 0)
		{
			*simulated_time += 100000;

			if (loss_mask == NULL ||
				tls_api_loss_simulator(loss_mask) == 0)
			{
				/* Submit the packet to the server */
				ret = picoquic_incoming_packet(qreceive, sp->bytes, sp->length, sender_addr,
					*simulated_time);
			}
		}
		picoquic_delete_stateless_packet(sp);
	}
	else if (cnx != NULL)
	{
		picoquic_packet * p = picoquic_create_packet();
		uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
		size_t send_length = 0;

		if (p == NULL)
		{
			ret = -1;
		}
		else
		{
			*simulated_time += 500;

			ret = picoquic_prepare_packet(cnx, p, *simulated_time,
				bytes, PICOQUIC_MAX_PACKET_SIZE, &send_length);

			if (ret == 0 && p->length > 0)
			{
				*simulated_time += 500;

				if (loss_mask == NULL ||
					tls_api_loss_simulator(loss_mask) == 0)
				{
					/* Submit the packet to the server */
					ret = picoquic_incoming_packet(qreceive, bytes, send_length, sender_addr,
						*simulated_time);
				}
			}
			else
			{
				*simulated_time += 500000;
				free(p);
			}
		}
	}
	else
	{
		simulated_time += 1000000;
	}

    return ret;
}

static int verify_transport_extension(picoquic_cnx_t * cnx_client, picoquic_cnx_t * cnx_server)
{
	int ret = 0;

	/* verify that local parameters have a sensible value */
	if (cnx_client->local_parameters.idle_timeout == 0 ||
		cnx_client->local_parameters.initial_max_data == 0 ||
		cnx_client->local_parameters.initial_max_stream_data == 0 ||
		cnx_client->local_parameters.max_packet_size == 0)
	{
		ret = -1;
	}
	else if (cnx_server->local_parameters.idle_timeout == 0 ||
		cnx_server->local_parameters.initial_max_data == 0 ||
		cnx_server->local_parameters.initial_max_stream_data == 0 ||
		cnx_server->local_parameters.max_packet_size == 0)
	{
		ret = -1;
	}
	/* Verify that the negotiation completed */
	else if (memcmp(&cnx_client->local_parameters, &cnx_server->remote_parameters,
		sizeof(picoquic_transport_parameters)) != 0)
	{
		ret = -1;
	}
	else if (memcmp(&cnx_server->local_parameters, &cnx_client->remote_parameters,
		sizeof(picoquic_transport_parameters)) != 0)
	{
		ret = -1;
	}

	return ret;
}

static int tls_api_test_with_loss(uint64_t  * loss_mask, uint32_t proposed_version)
{

    int ret = 0;
    picoquic_quic_t * qclient = NULL, * qserver = NULL;
    picoquic_cnx_t * cnx_client = NULL, * cnx_server = NULL;
    struct sockaddr_in client_addr, server_addr;
    int nb_trials = 0;
	uint64_t simulated_time = 0;

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
    qclient = picoquic_create(8, NULL, NULL, NULL, NULL);
    qserver = picoquic_create(8, "..\\certs\\cert.pem", "..\\certs\\key.pem", NULL, NULL);

    if (qclient == NULL || qserver == NULL)
    {
        ret = -1;
    }

    if (ret == 0)
    {
        /* Create a client connection */
        cnx_client = picoquic_create_cnx(qclient, 12345, (struct sockaddr *)&server_addr, 0, 
			proposed_version, NULL, NULL);

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
        ret = tls_api_one_packet(qclient, cnx_client, qserver, (struct sockaddr *)&client_addr,
			loss_mask, &simulated_time);

        if (ret == 0)
        {
            if (cnx_server == NULL)
            {
                cnx_server = qserver->cnx_list;
            }
			
			ret = tls_api_one_packet(qserver, cnx_server, qclient, (struct sockaddr *)&server_addr,
					loss_mask, &simulated_time);
			if (ret != 0)
			{
				break;
			}
        }
		else
		{
			break;
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
            ret = tls_api_one_packet(qclient, cnx_client, qserver, (struct sockaddr *)&client_addr, NULL,
				&simulated_time);
        }

        if (ret == 0 && (
            cnx_client->cnx_state != picoquic_state_disconnected ||
            cnx_server->cnx_state != picoquic_state_disconnected))
        {
            ret = -1;
        }

		if (ret == 0)
		{
			ret = verify_transport_extension(cnx_client, cnx_server);
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
	return tls_api_test_with_loss(NULL, 0);
}

int tls_api_loss_test(uint64_t mask)
{
	uint64_t loss_mask = mask;

	return tls_api_test_with_loss(&loss_mask, 0);
}

int tls_api_many_losses()
{
	uint64_t loss_mask = 0;
	int ret = 0;

	for (uint64_t i = 0; ret == 0 && i < 6; i++)
	{
		for (uint64_t j = 1; ret == 0 && j < 4; j++)
		{
			loss_mask = ((1 << j) - 1) << i;
			ret = tls_api_test_with_loss(&loss_mask, 0);
		}
	}

	return ret;
}

int tls_api_version_negotiation_test()
{
	const uint32_t version_grease = 0x0aca4a0a;
	return tls_api_test_with_loss(NULL, version_grease);
}