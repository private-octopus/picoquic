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
#include "../picoquic/tls_api.h"

#define PICOQUIC_TEST_SNI "picoquic.test"
#define PICOQUIC_TEST_ALPN "picoquic-test"
#define PICOQUIC_TEST_WRONG_ALPN "picoquic-bla-bla"
#define PICOQUIC_TEST_MAX_TEST_STREAMS 8

/*
 * Generic call back function.
 */

typedef struct st_test_api_stream_desc_t {
	uint32_t stream_id;
	uint32_t previous_stream_id;
	size_t q_len;
	size_t r_len;
} test_api_stream_desc_t;

typedef struct st_test_api_stream_t {
	uint32_t stream_id;
	uint32_t previous_stream_id;
	int q_sent;
	int r_sent;
	size_t q_len;
	size_t q_recv_nb;
	size_t r_len;
	size_t r_recv_nb;
	uint8_t * q_src;
	uint8_t * q_rcv;
	uint8_t * r_src;
	uint8_t * r_rcv;
} test_api_stream_t;

typedef struct st_test_api_callback_t {
	int client_mode;
	int fin_received;
	int error_detected;
	uint32_t nb_bytes_received;
} test_api_callback_t;

typedef struct st_picoquic_test_tls_api_ctx_t {
	picoquic_quic_t * qclient;
	picoquic_quic_t * qserver;
	picoquic_cnx_t * cnx_client;
	picoquic_cnx_t * cnx_server;
	struct sockaddr_in client_addr;
	struct sockaddr_in server_addr;
	test_api_callback_t client_callback;
	test_api_callback_t server_callback;
	size_t nb_test_streams;
	test_api_stream_t test_stream[PICOQUIC_TEST_MAX_TEST_STREAMS];
} picoquic_test_tls_api_ctx_t;

static int test_api_init_stream_buffers(size_t len, uint8_t ** src_bytes, uint8_t ** rcv_bytes)
{
	static uint64_t rnd = 0xF1E2D3C4B5A688ull;
	int ret = 0;

	*src_bytes = (uint8_t *)malloc(len);
	*rcv_bytes = (uint8_t *)malloc(len);

	if (*src_bytes != NULL && *rcv_bytes != NULL)
	{
		memset(*rcv_bytes, 0, len);

		for (size_t i = 0; i < len; i++)
		{
			*src_bytes[i] = (uint8_t)(rnd & 0xFF);
			rnd ^= (rnd << 29) ^ (rnd >> 17) ^ (0xdeadbeefull);
		}
	}
	else
	{
		ret = -1;

		if (*src_bytes != NULL)
		{
			free(*src_bytes);
			*src_bytes = NULL;
		}

		if (*rcv_bytes != NULL)
		{
			free(*rcv_bytes);
			*rcv_bytes = NULL;
		}
	}

	return ret;
}

static int test_api_init_test_stream(test_api_stream_t * test_stream,
	uint32_t stream_id, uint32_t previous_stream_id, size_t q_len, size_t r_len)
{
	int ret = 0;

	memset(test_stream, 0, sizeof(test_stream));

	if (q_len != 0)
	{
		ret = test_api_init_stream_buffers(q_len, &test_stream->q_src, &test_stream->q_rcv);
		if (ret == 0)
		{
			test_stream->q_len = q_len;
		}
	}

	if (ret == 0 && r_len != 0)
	{
		ret = test_api_init_stream_buffers(q_len, &test_stream->r_src, &test_stream->r_rcv);
		if (ret == 0)
		{
			test_stream->q_len = q_len;
		}
	}

	if (ret == 0)
	{
		test_stream->previous_stream_id = previous_stream_id;
		test_stream->stream_id = stream_id;
	}

	return ret;
}

static void test_api_delete_test_stream(test_api_stream_t * test_stream)
{
	if (test_stream->q_src != NULL)
	{
		free(test_stream->q_src);
	}

	if (test_stream->q_rcv != NULL)
	{
		free(test_stream->q_rcv);
	}

	if (test_stream->r_src != NULL)
	{
		free(test_stream->q_src);
	}

	if (test_stream->r_rcv != NULL)
	{
		free(test_stream->q_rcv);
	}

	memset(test_stream, 0, sizeof(test_stream));
}

static void test_api_callback(picoquic_cnx_t * cnx,
	uint32_t stream_id, uint8_t * bytes, size_t length, int fin_noted, void * callback_ctx)
{
	/* Need to check whether the two sides are done sending */
	/* Need to implement the server sending strategy */
	test_api_callback_t * cb_ctx = (test_api_callback_t *)callback_ctx;
	cb_ctx->fin_received |= fin_noted;
	cb_ctx->nb_bytes_received += length;
}

/*
 * Simulate losses based on a 64 bit loss pattern.
 * This is defined to create large rates while allowing test of
 * specific scenarios, such as "lose 2nd packet"
 */
static int tls_api_loss_simulator(uint64_t * loss_mask)
{
	/* Last bit indicates loss or not */
	uint64_t ret = (uint64_t)((*loss_mask) & 1ull);
	/* Shift 1 to prepare next round */
	*loss_mask >>= 1;
	*loss_mask ^= (ret << 63);

	return (int)ret;
}

static int tls_api_one_packet(picoquic_quic_t * qsender, picoquic_cnx_t * cnx, picoquic_quic_t * qreceive,
    struct sockaddr * sender_addr, uint64_t * loss_mask, uint64_t * simulated_time, int * was_active)
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

			*was_active |= 1;

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

				*was_active |= 1;

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

static int verify_sni(picoquic_cnx_t * cnx_client, picoquic_cnx_t * cnx_server,
	char const * sni)
{
	int ret = 0;
	char const * client_sni = picoquic_tls_get_sni(cnx_client);
	char const * server_sni = picoquic_tls_get_sni(cnx_server);


	if (sni == NULL)
	{
		if (cnx_client->sni != NULL)
		{
			ret = -1;
		}
		else if (client_sni != NULL)
		{
			ret = -1;
		}
		else if (server_sni != NULL)
		{
			ret = -1;
		}
	}
	else
	{
		if (cnx_client->sni == NULL)
		{
			ret = -1;
		}
		else if (client_sni == NULL)
		{
			ret = -1;
		}
		else if (server_sni == NULL)
		{
			ret = -1;
		}
		else if (strcmp(cnx_client->sni, sni) != 0)
		{
			ret = -1;
		}
		else if (strcmp(client_sni, sni) != 0)
		{
			ret = -1;
		}
		else if (strcmp(server_sni, sni) != 0)
		{
			ret = -1;
		}
	}

	return ret;
}

static int verify_alpn(picoquic_cnx_t * cnx_client, picoquic_cnx_t * cnx_server,
	char const * alpn)
{
	int ret = 0;
	char const * client_alpn = picoquic_tls_get_negotiated_alpn(cnx_client);
	char const * server_alpn = picoquic_tls_get_negotiated_alpn(cnx_server);

	if (alpn == NULL)
	{
		if (cnx_client->alpn != NULL)
		{
			ret = -1;
		}
		else if (client_alpn != NULL)
		{
			ret = -1;
		}
		else if (server_alpn != NULL)
		{
			ret = -1;
		}
	}
	else
	{
		if (cnx_client->alpn == NULL)
		{
			ret = -1;
		}
		else if (client_alpn == NULL)
		{
			ret = -1;
		}
		else if (server_alpn == NULL)
		{
			ret = -1;
		}
		else if (strcmp(cnx_client->alpn, alpn) != 0)
		{
			ret = -1;
		}
		else if (strcmp(client_alpn, alpn) != 0)
		{
			ret = -1;
		}
		else if (strcmp(server_alpn, alpn) != 0)
		{
			ret = -1;
		}
	}

	return ret;
}

static int tls_api_init_ctx(picoquic_test_tls_api_ctx_t ** pctx, uint32_t proposed_version,
	char const * sni, char const * alpn)
{
	int ret = 0;
	picoquic_test_tls_api_ctx_t * test_ctx = (picoquic_test_tls_api_ctx_t *)
		malloc(sizeof(picoquic_test_tls_api_ctx_t));

	*pctx = test_ctx;

	if (test_ctx != NULL)
	{
		/* Init to NULL */
		memset(test_ctx, 0, sizeof(picoquic_test_tls_api_ctx_t));
		test_ctx->client_callback.client_mode = 1;

		/* Init of the IP addresses */
		memset(&test_ctx->client_addr, 0, sizeof(struct sockaddr_in));
		test_ctx->client_addr.sin_family = AF_INET;
		test_ctx->client_addr.sin_addr.S_un.S_addr = 0x0A000002;
		test_ctx->client_addr.sin_port = 1234;

		memset(&test_ctx->server_addr, 0, sizeof(struct sockaddr_in));
		test_ctx->server_addr.sin_family = AF_INET;
		test_ctx->server_addr.sin_addr.S_un.S_addr = 0x0A000001;
		test_ctx->server_addr.sin_port = 4321;

		/* Test the creation of the client and server contexts */
		/* Create QUIC context */
		test_ctx->qclient = picoquic_create(8, NULL, NULL, NULL, test_api_callback, 
			(void*)&test_ctx->client_callback);

		test_ctx->qserver = picoquic_create(8,
			"..\\certs\\cert.pem", "..\\certs\\key.pem",
			PICOQUIC_TEST_ALPN, test_api_callback, (void*)&test_ctx->server_callback);

		if (test_ctx->qclient == NULL || test_ctx->qserver == NULL)
		{
			ret = -1;
		}

		if (ret == 0)
		{
			/* Create a client connection */
			test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, 12345,
				(struct sockaddr *)&test_ctx->server_addr, 0,
				proposed_version, sni, alpn);

			if (test_ctx->cnx_client == NULL)
			{
				ret = -1;
			}
		}
	}

	return ret;
}

static void tls_api_delete_ctx(picoquic_test_tls_api_ctx_t * test_ctx)
{
	if (test_ctx->qclient != NULL)
	{
		picoquic_free(test_ctx->qclient);
	}

	if (test_ctx->qserver != NULL)
	{
		picoquic_free(test_ctx->qserver);
	}

	for (size_t i = 0; i < test_ctx->nb_test_streams; i++)
	{
		test_api_delete_test_stream(&test_ctx->test_stream[i]);
	}
}

static int test_api_init_send_recv_scenario(picoquic_test_tls_api_ctx_t * test_ctx,
	test_api_stream_desc_t * stream_desc, size_t size_of_scenarios)
{
	int ret = 0;
	size_t nb_stream_desc = size_of_scenarios / sizeof(test_api_stream_desc_t);

	if (nb_stream_desc > PICOQUIC_TEST_MAX_TEST_STREAMS)
	{
		ret = -1;
	}
	else
	{
		for (size_t i = 0; ret == 0 && i < nb_stream_desc; i++)
		{
			ret = test_api_init_test_stream(&test_ctx->test_stream[i],
				stream_desc[i].stream_id, stream_desc[i].previous_stream_id,
				stream_desc[i].q_len, stream_desc[i].r_len);
		}
	}

	/* TODO: Perform the "end of stream 0" callback */
	return ret;
}

static int tls_api_connection_loop(picoquic_test_tls_api_ctx_t * test_ctx, 
	uint64_t  * loss_mask, uint64_t *simulated_time)
{
	int ret = 0;
	int nb_trials = 0;
	int nb_inactive = 0;

	while (ret == 0 && nb_trials < 12 && nb_inactive < 4 &&
		(test_ctx->cnx_client->cnx_state != picoquic_state_client_ready ||
		(test_ctx->cnx_server == NULL ||
			test_ctx->cnx_server->cnx_state != picoquic_state_server_ready)))
	{
		int was_active = 0;
		nb_trials++;

		/* packet from client to server */
		ret = tls_api_one_packet(test_ctx->qclient, test_ctx->cnx_client, test_ctx->qserver,
			(struct sockaddr *)&test_ctx->client_addr, loss_mask, simulated_time, &was_active);

		if (ret == 0)
		{
			if (test_ctx->cnx_server == NULL)
			{
				test_ctx->cnx_server = test_ctx->qserver->cnx_list;
			}

			ret = tls_api_one_packet(test_ctx->qserver, test_ctx->cnx_server, test_ctx->qclient,
				(struct sockaddr *)&test_ctx->server_addr, loss_mask, simulated_time, &was_active);
			if (ret != 0)
			{
				break;
			}
		}
		else
		{
			break;
		}

		if (was_active)
		{
			nb_inactive = 0;
		}
		else
		{
			nb_inactive++;
		}
	}

	if (test_ctx->cnx_client->cnx_state != picoquic_state_client_ready ||
		test_ctx->cnx_server == NULL || test_ctx->cnx_server->cnx_state != picoquic_state_server_ready)
	{
		ret = -1;
	}

	return ret;
}

static int tls_api_data_sending_loop(picoquic_test_tls_api_ctx_t * test_ctx,
	uint64_t  * loss_mask, uint64_t *simulated_time)
{
	int ret = 0;
	int nb_trials = 0;
	int nb_inactive = 0;

	while (ret == 0 && nb_trials < 1000 && nb_inactive < 4 &&
		test_ctx->cnx_client->cnx_state == picoquic_state_client_ready &&
		test_ctx->cnx_server->cnx_state == picoquic_state_server_ready)
	{
		int was_active = 0;
		nb_trials++;

		/* packet from client to server */
		ret = tls_api_one_packet(test_ctx->qclient, test_ctx->cnx_client, test_ctx->qserver,
			(struct sockaddr *)&test_ctx->client_addr, loss_mask, simulated_time, &was_active);

		if (ret == 0)
		{
			ret = tls_api_one_packet(test_ctx->qserver, test_ctx->cnx_server, test_ctx->qclient,
				(struct sockaddr *)&test_ctx->server_addr, loss_mask, simulated_time, &was_active);

			if (ret != 0)
			{
				break;
			}
		}
		else
		{
			break;
		}

		if (was_active)
		{
			nb_inactive = 0;
		}
		else
		{
			nb_inactive++;
		}
	}

	return ret;
}

static int tls_api_test_with_loss(uint64_t  * loss_mask, uint32_t proposed_version,
	char const * sni, char const * alpn)
{
	uint64_t simulated_time = 0;
	picoquic_test_tls_api_ctx_t * test_ctx = NULL;
	int ret = tls_api_init_ctx(&test_ctx, proposed_version, sni, alpn);

	if (ret == 0)
	{
		ret = tls_api_connection_loop(test_ctx, loss_mask, &simulated_time);
	}

	if (ret == 0)
	{
		ret = picoquic_close(test_ctx->cnx_client);

        if (ret == 0)
        {
            /* packet from client to server */
			/* Do not simulate losses there, as there is no way to correct them */
			int is_active = 0;

            ret = tls_api_one_packet(test_ctx->qclient, test_ctx->cnx_client, test_ctx->qserver, 
				(struct sockaddr *)&test_ctx->client_addr, NULL, &simulated_time, &is_active);
        }

        if (ret == 0 && (
            test_ctx->cnx_client->cnx_state != picoquic_state_disconnected ||
			test_ctx->cnx_server->cnx_state != picoquic_state_disconnected))
        {
            ret = -1;
        }

		if (ret == 0)
		{
			ret = verify_transport_extension(test_ctx->cnx_client, test_ctx->cnx_server);
		}

		if (ret == 0)
		{
			ret = verify_sni(test_ctx->cnx_client, test_ctx->cnx_server, sni);
		}

		if (ret == 0)
		{
			ret = verify_alpn(test_ctx->cnx_client, test_ctx->cnx_server, alpn);
		}
    }

	if (test_ctx != NULL)
	{
		tls_api_delete_ctx(test_ctx);
		test_ctx = NULL;
	}

    return ret;
}

int tls_api_test()
{
	return tls_api_test_with_loss(NULL, 0, NULL, NULL);
}

int tls_api_loss_test(uint64_t mask)
{
	uint64_t loss_mask = mask;

	return tls_api_test_with_loss(&loss_mask, 0, NULL, NULL);
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
			ret = tls_api_test_with_loss(&loss_mask, 0, NULL, NULL);
		}
	}

	return ret;
}

int tls_api_version_negotiation_test()
{
	const uint32_t version_grease = 0x0aca4a0a;
	return tls_api_test_with_loss(NULL, version_grease, NULL, NULL);
}

int tls_api_sni_test()
{
	return tls_api_test_with_loss(NULL, 0, PICOQUIC_TEST_SNI, NULL);
}

int tls_api_alpn_test()
{
	return tls_api_test_with_loss(NULL, 0, NULL, PICOQUIC_TEST_ALPN);
}

int tls_api_wrong_alpn_test()
{
	return tls_api_test_with_loss(NULL, 0, NULL, PICOQUIC_TEST_WRONG_ALPN);
}

/*
 * Transmission test number one. Client sends data on stream 1,
 * verify that data is received properly.
 */

char const test_string[] = "The quick brown fox jumps over the lazy dog.";

int tls_api_oneway_stream_test()
{
	uint64_t simulated_time = 0;
	uint64_t loss_mask = 0;
	picoquic_test_tls_api_ctx_t * test_ctx = NULL;
	int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN);

	if (ret == 0)
	{
		ret = tls_api_connection_loop(test_ctx, 0, &simulated_time);
	}

	/* Send data on stream 1 */
	if (ret == 0)
	{
		ret = picoquic_add_to_stream(test_ctx->cnx_client, 1,
			(uint8_t *)test_string, sizeof(test_string), 1);
	}

	/* Perform a data sending loop */
	if (ret == 0)
	{
		ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time);
	}

	if (ret == 0)
	{
		if (test_ctx->server_callback.fin_received == 0)
		{
			ret = -1;
		}
		else if (test_ctx->server_callback.nb_bytes_received != sizeof(test_string))
		{
			ret = -1;
		}
	}

	if (ret == 0)
	{
		ret = picoquic_close(test_ctx->cnx_client);
	}

	if (test_ctx != NULL)
	{
		tls_api_delete_ctx(test_ctx);
		test_ctx = NULL;
	}

	return ret;
}