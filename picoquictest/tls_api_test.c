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

#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include "../picoquic/picoquic_internal.h"
#include "../picoquic/tls_api.h"
#include "picoquictest_internal.h"

#define PICOQUIC_TEST_SNI "picoquic.test"
#define PICOQUIC_TEST_ALPN "picoquic-test"
#define PICOQUIC_TEST_WRONG_ALPN "picoquic-bla-bla"
#define PICOQUIC_TEST_MAX_TEST_STREAMS 8

/*
 * Generic call back function.
 */

typedef enum {
	test_api_fail_data_on_unknown_stream = 1,
	test_api_fail_recv_larger_than_sent = 2,
	test_api_fail_fin_received_twice = 4,
	test_api_fail_cannot_send_response = 8,
	test_api_fail_cannot_send_query = 16,
	test_api_fail_data_does_not_match = 32
} test_api_fail_mode;

typedef struct st_test_api_stream_desc_t {
	uint64_t stream_id;
	uint64_t previous_stream_id;
	size_t q_len;
	size_t r_len;
} test_api_stream_desc_t;

typedef struct st_test_api_stream_t {
	uint64_t stream_id;
	uint64_t previous_stream_id;
	int q_sent;
	int r_sent;
	picoquic_call_back_event_t q_received;
	picoquic_call_back_event_t r_received;
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
	picoquictest_sim_link_t * c_to_s_link;
	picoquictest_sim_link_t * s_to_c_link;
    int test_finished;
} picoquic_test_tls_api_ctx_t;

static test_api_stream_desc_t test_scenario_oneway[] = {
	{ 1, 0, 257, 0 }
};

static test_api_stream_desc_t test_scenario_q_and_r[] = {
	{ 1, 0, 257, 2000 }
};

static test_api_stream_desc_t test_scenario_q2_and_r2[] = {
	{ 1, 0, 257, 2000 },
	{ 3, 0, 531, 11000 }
};

static test_api_stream_desc_t test_scenario_very_long[] = {
	{ 1, 0, 257, 1000000 }
};

static int test_api_init_stream_buffers(size_t len, uint8_t ** src_bytes, uint8_t ** rcv_bytes)
{
	int ret = 0;

	*src_bytes = (uint8_t *)malloc(len);
	*rcv_bytes = (uint8_t *)malloc(len);

	if (*src_bytes != NULL && *rcv_bytes != NULL)
	{
		memset(*rcv_bytes, 0, len);

		for (size_t i = 0; i < len; i++)
		{
			(*src_bytes)[i] = (uint8_t)(i);
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
	uint64_t stream_id, uint64_t previous_stream_id, size_t q_len, size_t r_len)
{
	int ret = 0;

	memset(test_stream, 0, sizeof(test_api_stream_t));

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
		ret = test_api_init_stream_buffers(r_len, &test_stream->r_src, &test_stream->r_rcv);
		if (ret == 0)
		{
			test_stream->r_len = r_len;
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
		free(test_stream->r_src);
	}

	if (test_stream->r_rcv != NULL)
	{
		free(test_stream->r_rcv);
	}

	memset(test_stream, 0, sizeof(test_api_stream_t));
}


static void test_api_receive_stream_data(
	const uint8_t * bytes, size_t length, picoquic_call_back_event_t fin_or_event,
	uint8_t * buffer, size_t max_len, const uint8_t * reference, size_t * nb_received, 
	picoquic_call_back_event_t * received, int * error_detected)
{
	if (*nb_received + length > max_len)
	{
		*error_detected |= test_api_fail_recv_larger_than_sent;
	}
	else
	{
		memcpy(buffer + *nb_received, bytes, length);

		if (memcmp(reference + *nb_received, bytes, length) != 0)
		{
			*error_detected |= test_api_fail_data_does_not_match;
		}
	}

	*nb_received += length;

	if (fin_or_event != picoquic_callback_no_event)
	{
		if (*received != picoquic_callback_no_event)
		{
			*error_detected |= test_api_fail_fin_received_twice;
		}

		*received = fin_or_event;
	}
}

static int test_api_queue_initial_queries(picoquic_test_tls_api_ctx_t * test_ctx, uint64_t stream_id)
{
	int ret = 0;
    int more_stream = 0;

	for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++)
	{
		if (test_ctx->test_stream[i].previous_stream_id == stream_id)
		{
			picoquic_cnx_t * cnx = (test_ctx->test_stream[i].stream_id & 1) ?
				test_ctx->cnx_client : test_ctx->cnx_server;
			ret = picoquic_add_to_stream(cnx, test_ctx->test_stream[i].stream_id,
				test_ctx->test_stream[i].q_src,
				test_ctx->test_stream[i].q_len, 1);

			if (ret == 0)
			{
				test_ctx->test_stream[i].q_sent = 1;
                more_stream = 1;
			}
		}
	}

    if (more_stream == 0)
    {
        /* TODO: check whether the test is actually finished */
        test_ctx->test_finished = 1;
    }
    else
    {
        test_ctx->test_finished = 0;
    }

	return ret;
}

static void test_api_callback(picoquic_cnx_t * cnx,
	uint64_t stream_id, uint8_t * bytes, size_t length, 
	picoquic_call_back_event_t fin_or_event, void * callback_ctx)
{
	/* Need to implement the server sending strategy */
	test_api_callback_t * cb_ctx = (test_api_callback_t *)callback_ctx;
	picoquic_test_tls_api_ctx_t * ctx = NULL;
	size_t stream_index = 0;
	int is_client_stream = (stream_id & 1);
	picoquic_call_back_event_t stream_finished = picoquic_callback_no_event;

    if (fin_or_event == picoquic_callback_close || 
        fin_or_event == picoquic_callback_application_close)
    {
        /* do nothing in our tests */
        return;
    }

	if (cb_ctx->client_mode)
	{
		ctx = (picoquic_test_tls_api_ctx_t *)(
			((char *)callback_ctx) - offsetof(struct st_picoquic_test_tls_api_ctx_t, client_callback));
	}
	else
	{
		ctx = (picoquic_test_tls_api_ctx_t *)(
			((char *)callback_ctx) - offsetof(struct st_picoquic_test_tls_api_ctx_t, server_callback));
	}

	while (stream_index < ctx->nb_test_streams)
	{
		if (ctx->test_stream[stream_index].stream_id == stream_id)
		{
			break;
		}
		stream_index++;
	}

	if (stream_index >= ctx->nb_test_streams)
	{
		cb_ctx->error_detected |= test_api_fail_data_on_unknown_stream;
	}
	else if (fin_or_event == picoquic_callback_stop_sending)
    {
        /* Respond with a reset, no matter what. Should be smarter later */
        picoquic_reset_stream(cnx, stream_id, 0);
    }
    else if (is_client_stream)
	{
		if (cb_ctx->client_mode)
		{
			/* this is a response from the server to a client stream */
			test_api_receive_stream_data(bytes, length, fin_or_event,
				ctx->test_stream[stream_index].r_rcv,
				ctx->test_stream[stream_index].r_len,
				ctx->test_stream[stream_index].r_src,
				&ctx->test_stream[stream_index].r_recv_nb,
				&ctx->test_stream[stream_index].r_received,
				&cb_ctx->error_detected);

			stream_finished = fin_or_event;
		}
		else
		{
			/* this is a query to a server */
			test_api_receive_stream_data(bytes, length, fin_or_event,
				ctx->test_stream[stream_index].q_rcv,
				ctx->test_stream[stream_index].q_len,
				ctx->test_stream[stream_index].q_src,
				&ctx->test_stream[stream_index].q_recv_nb,
				&ctx->test_stream[stream_index].q_received,
				&cb_ctx->error_detected);

			if (fin_or_event != 0)
			{
				if (ctx->test_stream[stream_index].r_len == 0 ||
					fin_or_event == picoquic_callback_stream_reset)
				{
					ctx->test_stream[stream_index].r_received = 1;
					stream_finished = fin_or_event;
				}
				else if (cb_ctx->error_detected == 0)
				{
					/* send a response */
					if (picoquic_add_to_stream(ctx->cnx_server, stream_id,
						ctx->test_stream[stream_index].r_src,
						ctx->test_stream[stream_index].r_len, 1) != 0)
					{
						cb_ctx->error_detected |= test_api_fail_cannot_send_response;
					}
				}
			}
		}
	}
	else
	{
		if (cb_ctx->client_mode)
		{
			/* this is a query from the server to the client */
			test_api_receive_stream_data(bytes, length, fin_or_event,
				ctx->test_stream[stream_index].q_rcv,
				ctx->test_stream[stream_index].q_len,
				ctx->test_stream[stream_index].q_src,
				&ctx->test_stream[stream_index].q_recv_nb,
				&ctx->test_stream[stream_index].q_received,
				&cb_ctx->error_detected);

			if (fin_or_event != 0)
			{
				if (ctx->test_stream[stream_index].r_len == 0 ||
					fin_or_event == picoquic_callback_stream_reset)
				{
					ctx->test_stream[stream_index].r_received = 1;
					stream_finished = fin_or_event;
				}
				else if (cb_ctx->error_detected == 0)
				{
					/* send a response */
					if (picoquic_add_to_stream(ctx->cnx_client, stream_id,
						ctx->test_stream[stream_index].r_src,
						ctx->test_stream[stream_index].r_len, 1) != 0)
					{
						cb_ctx->error_detected |= test_api_fail_cannot_send_response;
					}
				}
			}
		}
		else
		{
			/* this is a response to the server */
			test_api_receive_stream_data(bytes, length, fin_or_event,
				ctx->test_stream[stream_index].r_rcv,
				ctx->test_stream[stream_index].r_len,
				ctx->test_stream[stream_index].r_src,
				&ctx->test_stream[stream_index].r_recv_nb,
				&ctx->test_stream[stream_index].r_received,
				&cb_ctx->error_detected);

			stream_finished = fin_or_event;
		}
	}

	if (stream_finished == picoquic_callback_stream_fin && cb_ctx->error_detected == 0)
	{
		/* queue the new queries initiated by that stream */
		if (test_api_queue_initial_queries(ctx, stream_id) != 0)
		{
			cb_ctx->error_detected |= test_api_fail_cannot_send_query;
		}
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
		test_ctx->nb_test_streams = nb_stream_desc;
        test_ctx->test_finished = 0;

		for (size_t i = 0; ret == 0 && i < nb_stream_desc; i++)
		{
			ret = test_api_init_test_stream(&test_ctx->test_stream[i],
				stream_desc[i].stream_id, stream_desc[i].previous_stream_id,
				stream_desc[i].q_len, stream_desc[i].r_len);
		}
	}

	if (ret == 0)
	{
		ret = test_api_queue_initial_queries(test_ctx, 0);
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


static int verify_version(picoquic_cnx_t * cnx_client, picoquic_cnx_t * cnx_server)
{
    int ret = 0;

    if (cnx_client->version_index != cnx_server->version_index)
    {
        ret = -1;
    }
    else
    {
        for (size_t i = 0; i < picoquic_nb_supported_versions; i++)
        {
            if (cnx_client->proposed_version != 
                picoquic_supported_versions[cnx_client->version_index].version &&
                cnx_client->proposed_version == picoquic_supported_versions[i].version)
            {
                ret = -1;
                break;
            }
        }

        if (ret == 0)
        {
            if (cnx_client->version_index < 0 ||
                cnx_client->version_index >= (int) picoquic_nb_supported_versions)
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

	if (test_ctx->c_to_s_link != NULL)
	{
		picoquictest_sim_link_delete(test_ctx->c_to_s_link);
	}

	if (test_ctx->s_to_c_link != NULL)
	{
		picoquictest_sim_link_delete(test_ctx->s_to_c_link);
	}
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
#ifdef WIN32
		test_ctx->client_addr.sin_addr.S_un.S_addr = 0x0A000002;
#else
		test_ctx->client_addr.sin_addr.s_addr = 0x0A000002;
#endif
		test_ctx->client_addr.sin_port = 1234;

		memset(&test_ctx->server_addr, 0, sizeof(struct sockaddr_in));
		test_ctx->server_addr.sin_family = AF_INET;
#ifdef WIN32
		test_ctx->server_addr.sin_addr.S_un.S_addr = 0x0A000001;
#else
		test_ctx->server_addr.sin_addr.s_addr = 0x0A000001;
#endif
		test_ctx->server_addr.sin_port = 4321;

		/* Test the creation of the client and server contexts */
		/* Create QUIC context */
		test_ctx->qclient = picoquic_create(8, NULL, NULL, NULL, test_api_callback, 
			(void*)&test_ctx->client_callback, NULL, NULL, NULL);

		test_ctx->qserver = picoquic_create(8,
#ifdef WIN32
			"..\\certs\\cert.pem", "..\\certs\\key.pem",
#else
			"certs/cert.pem", "certs/key.pem",
#endif
			PICOQUIC_TEST_ALPN, test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL);

		if (test_ctx->qclient == NULL || test_ctx->qserver == NULL)
		{
			ret = -1;
		}

		/* register the links */
		if (ret == 0)
		{
			test_ctx->c_to_s_link = picoquictest_sim_link_create(0.01, 10000, 0, 0, 0);
			test_ctx->s_to_c_link = picoquictest_sim_link_create(0.01, 10000, 0, 0, 0);

			if (test_ctx->c_to_s_link == NULL || test_ctx->s_to_c_link == NULL)
			{
				ret = -1;
			}
		}

		if (ret == 0)
		{
			/* Create a client connection */
			test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, 0,
				(struct sockaddr *)&test_ctx->server_addr, 0,
				proposed_version, sni, alpn);

			if (test_ctx->cnx_client == NULL)
			{
				ret = -1;
			}
		}

		if (ret != 0)
		{
			tls_api_delete_ctx(test_ctx);
			*pctx = NULL;
		}
	}

	return ret;
}


static int tls_api_one_sim_round(picoquic_test_tls_api_ctx_t * test_ctx, 
	uint64_t *simulated_time, int * was_active)
{
	int ret = 0;
	picoquictest_sim_link_t * target_link = NULL;

	/* If one of the sources can send a packet, send it, keep time as it */

	picoquictest_sim_packet_t * packet = picoquictest_sim_link_create_packet();

	if (packet == NULL)
	{
		ret = -1;
	}
	else
	{
		picoquic_stateless_packet_t * sp = picoquic_dequeue_stateless_packet(test_ctx->qserver);

		if (sp != NULL)
		{
			if (sp->length > 0)
			{
				*simulated_time += 100000;

				*was_active |= 1;

				memcpy(packet->bytes, sp->bytes, sp->length);
				packet->length = sp->length;

				target_link = test_ctx->s_to_c_link;
			}
			picoquic_delete_stateless_packet(sp);
		}

		if (packet->length == 0)
		{
			/* check whether the client has something to send */
			picoquic_packet * p = picoquic_create_packet();

			if (p == NULL)
			{
				ret = -1;
			}
			else
			{
				if (test_ctx->cnx_client->cnx_state != picoquic_state_disconnected)
				{
					ret = picoquic_prepare_packet(test_ctx->cnx_client, p, *simulated_time,
						packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length);
				}
				else
				{
					p->length = 0;
					packet->length = 0;
				}

				if (ret == 0)
				{
					if (p->length > 0)
					{
						/* queue in c_to_s */
						target_link = test_ctx->c_to_s_link;
					}
					else if (test_ctx->cnx_server != NULL &&
                        test_ctx->cnx_server->cnx_state != picoquic_state_disconnected)
					{
						ret = picoquic_prepare_packet(test_ctx->cnx_server, p, *simulated_time,
							packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length);
						if (ret == 0 && p->length > 0)
						{
							/* copy and queue in s to c */
							target_link = test_ctx->s_to_c_link;
						}
					}
				}
			}
		}

		if (packet->length > 0)
		{
			picoquictest_sim_link_submit(target_link, packet, *simulated_time);
			*was_active |= 1;
		}
		else
		{
			uint64_t next_time = *simulated_time += 5000;
            uint64_t client_arrival, server_arrival;

			free(packet);

            if (test_ctx->cnx_client != NULL &&
                test_ctx->cnx_client->cnx_state != picoquic_state_disconnected)
            {
                if (test_ctx->cnx_server != NULL &&
                    test_ctx->cnx_server->cnx_state != picoquic_state_disconnected &&
                    test_ctx->cnx_server->next_wake_time <
                    test_ctx->cnx_client->next_wake_time)
                {
                    next_time = test_ctx->cnx_server->next_wake_time;
                }
                else
                {
                    next_time = test_ctx->cnx_client->next_wake_time;
                }
            }
            else if (test_ctx->cnx_server != NULL &&
                test_ctx->cnx_server->cnx_state != picoquic_state_disconnected)
            {
                next_time = test_ctx->cnx_server->next_wake_time;
            }

            if (next_time < *simulated_time + 5000)
            {
                next_time = *simulated_time + 5000;
            }

            client_arrival = picoquictest_sim_link_next_arrival(test_ctx->s_to_c_link, next_time);
            server_arrival = picoquictest_sim_link_next_arrival(test_ctx->c_to_s_link, next_time);

            if (client_arrival < server_arrival && client_arrival < next_time &&
                (packet = picoquictest_sim_link_dequeue(test_ctx->s_to_c_link, client_arrival)) != NULL)
			{
                next_time = client_arrival;
				*simulated_time = next_time;
				ret = picoquic_incoming_packet(test_ctx->qclient, packet->bytes, packet->length,
					(struct sockaddr *)&test_ctx->server_addr, *simulated_time);
				*was_active |= 1;
			}
            else if (server_arrival < next_time &&
                (packet = picoquictest_sim_link_dequeue(test_ctx->c_to_s_link, server_arrival)) != NULL)
            {

                next_time = server_arrival;
                *simulated_time = next_time;
                ret = picoquic_incoming_packet(test_ctx->qserver, packet->bytes, packet->length,
                    (struct sockaddr *)&test_ctx->client_addr, *simulated_time);

                if (test_ctx->cnx_server == NULL)
                {
                    uint64_t target_cnxid = test_ctx->cnx_client->initial_cnxid;
                    picoquic_cnx_t * next = test_ctx->qserver->cnx_list;

                    while (next != NULL && next->initial_cnxid != target_cnxid)
                    {
                        next = next->next_in_table;
                    }

                    test_ctx->cnx_server = next;
                }

                *was_active |= 1;
            }
            else
            {
                *simulated_time = next_time;
            }
		}
	}

	return ret;

}

static int tls_api_connection_loop(picoquic_test_tls_api_ctx_t * test_ctx,
	uint64_t  * loss_mask, uint64_t queue_delay_max, uint64_t *simulated_time)
{
	int ret = 0;
	int nb_trials = 0;
	int nb_inactive = 0;

	test_ctx->c_to_s_link->loss_mask = loss_mask;
	test_ctx->s_to_c_link->loss_mask = loss_mask;

	test_ctx->c_to_s_link->queue_delay_max = queue_delay_max;
	test_ctx->s_to_c_link->queue_delay_max = queue_delay_max;

	while (ret == 0 && nb_trials < 1024 && nb_inactive < 512 &&
		(test_ctx->cnx_client->cnx_state != picoquic_state_client_ready ||
		(test_ctx->cnx_server == NULL ||
			test_ctx->cnx_server->cnx_state != picoquic_state_server_ready)))
	{
		int was_active = 0;
		nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, &was_active);

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

static int tls_api_data_sending_loop(picoquic_test_tls_api_ctx_t * test_ctx,
	uint64_t  * loss_mask, uint64_t *simulated_time)
{
	int ret = 0;
	int nb_trials = 0;
	int nb_inactive = 0;
	
	test_ctx->c_to_s_link->loss_mask = loss_mask;
	test_ctx->s_to_c_link->loss_mask = loss_mask;

	while (ret == 0 && nb_trials < 1000 && nb_inactive < 256 &&
		test_ctx->cnx_client->cnx_state == picoquic_state_client_ready &&
		test_ctx->cnx_server->cnx_state == picoquic_state_server_ready)
	{
		int was_active = 0;

		ret = tls_api_one_sim_round(test_ctx, simulated_time, &was_active);

		if (was_active)
		{
			nb_inactive = 0;
		}
		else
		{
			nb_inactive++;
		}

        if (test_ctx->test_finished)
        {
            if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) &&
                picoquic_is_cnx_backlog_empty(test_ctx->cnx_server))
            {
                break;
            }
        }
	}

	return ret; /* end of sending loop */
}

static int tls_api_attempt_to_close(
    picoquic_test_tls_api_ctx_t * test_ctx, uint64_t * simulated_time)
{
    int ret = 0;
    int nb_rounds = 0;

    ret = picoquic_close(test_ctx->cnx_client, 0);

    if (ret == 0)
    {
        /* packet from client to server */
        /* Do not simulate losses there, as there is no way to correct them */

        test_ctx->c_to_s_link->loss_mask = 0;
        test_ctx->s_to_c_link->loss_mask = 0;

        while (ret == 0 && (
            test_ctx->cnx_client->cnx_state != picoquic_state_disconnected ||
            test_ctx->cnx_server->cnx_state != picoquic_state_disconnected) &&
            nb_rounds < 256)
        {
            int was_active = 0;
            ret = tls_api_one_sim_round(test_ctx, simulated_time, &was_active);
            nb_rounds++;
        }
    }

    if (ret == 0 && (
        test_ctx->cnx_client->cnx_state != picoquic_state_disconnected ||
        test_ctx->cnx_server->cnx_state != picoquic_state_disconnected))
    {
        ret = -1;
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
		ret = tls_api_connection_loop(test_ctx, loss_mask, 0, &simulated_time);
	}

	if (ret == 0)
	{
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);

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

        if (ret == 0)
        {
            ret = verify_version(test_ctx->cnx_client, test_ctx->cnx_server);
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
	return tls_api_test_with_loss(NULL, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL);
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
 * Scenario based transmission tests.
 */

int tls_api_one_scenario_test(test_api_stream_desc_t * scenario, 
	size_t sizeof_scenario, uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max,
    uint32_t proposed_version)
{
	uint64_t simulated_time = 0;
	uint64_t loss_mask = 0;
	picoquic_test_tls_api_ctx_t * test_ctx = NULL;
	int ret = tls_api_init_ctx(&test_ctx, 
        (proposed_version == 0)? PICOQUIC_INTERNAL_TEST_VERSION_1: proposed_version, 
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN);

	if (ret == 0)
	{
		ret = tls_api_connection_loop(test_ctx, &loss_mask, queue_delay_max, &simulated_time);
	}

	if (ret == 0 && max_data != 0)
	{
		test_ctx->cnx_client->maxdata_local = max_data;
		test_ctx->cnx_client->maxdata_remote = max_data;
		test_ctx->cnx_server->maxdata_local = max_data;
		test_ctx->cnx_server->maxdata_remote = max_data;
	}

	/* Prepare to send data */
	if (ret == 0)
	{
		loss_mask = init_loss_mask;
		ret = test_api_init_send_recv_scenario(test_ctx, scenario, sizeof_scenario);
	}

	/* Perform a data sending loop */
	if (ret == 0)
	{
		ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time);
	}

	if (ret == 0)
	{
		if (test_ctx->server_callback.error_detected)
		{
			ret = -1;
		}
		else if (test_ctx->client_callback.error_detected)
		{
			ret = -1;
		}
		else
		{
			for (size_t i = 0; ret == 0 && i < test_ctx->nb_test_streams; i++)
			{
				if (test_ctx->test_stream[i].q_recv_nb !=
					test_ctx->test_stream[i].q_len)
				{
					ret = -1;
				}
				else if (test_ctx->test_stream[i].r_recv_nb !=
					test_ctx->test_stream[i].r_len)
				{
					ret = -1;
				}
				else if (test_ctx->test_stream[i].q_received == 0 ||
					test_ctx->test_stream[i].r_received == 0)
				{
					ret = -1;
				}
			}
		}
	}

	if (ret == 0)
	{
		ret = picoquic_close(test_ctx->cnx_client, 0);
	}

	if (test_ctx != NULL)
	{
		tls_api_delete_ctx(test_ctx);
		test_ctx = NULL;
	}

	return ret;
}

int tls_api_oneway_stream_test()
{
	return tls_api_one_scenario_test(test_scenario_oneway, sizeof(test_scenario_oneway), 0, 0, 0, 0);
}

int tls_api_q_and_r_stream_test()
{
	return tls_api_one_scenario_test(test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 0);
}

int tls_api_q2_and_r2_stream_test()
{
	return tls_api_one_scenario_test(test_scenario_q2_and_r2, sizeof(test_scenario_q2_and_r2), 0, 0, 0, 0);
}

int tls_api_very_long_stream_test()
{
	return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 0);
}

int tls_api_very_long_max_test()
{
	return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 128000, 0, 0);
}

int tls_api_very_long_with_err_test()
{
	return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0x30000, 128000, 0, 0);
}

int tls_api_very_long_congestion_test()
{
	return tls_api_one_scenario_test(test_scenario_very_long, sizeof(test_scenario_very_long), 0, 128000, 10000, 0);
}


/*
 * Server reset test.
 * Establish a connection between server and client.
 * When the connection is established, delete the server connection, and prime the client
 * to send data.
 * Expected result: the client sends a packet with a stream frame, the server responds
 * with a stateless reset, the client closes its own connection.
 */

int tls_api_server_reset_test()
{
	 uint64_t simulated_time = 0;
	 uint64_t loss_mask = 0;
	 picoquic_test_tls_api_ctx_t * test_ctx = NULL;
	 int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN);
	 uint8_t buffer[128];
	 int was_active = 0;

	 if (ret == 0)
	 {
		 ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
	 }

	 /* verify that client and server have the same reset secret */
	 if (ret == 0 &&
		 memcmp(test_ctx->cnx_client->reset_secret,
			 test_ctx->cnx_server->reset_secret,
			 PICOQUIC_RESET_SECRET_SIZE) != 0)
	 {
		 ret = -1;
	 }

	 /* Prepare to reset */
	 if (ret == 0)
	 {
		 picoquic_delete_cnx(test_ctx->cnx_server);
		 test_ctx->cnx_server = NULL;

		 memset(buffer, 0xaa, sizeof(buffer));
		 ret = picoquic_add_to_stream(test_ctx->cnx_client, 1, buffer, sizeof(buffer), 1);
	 }

	 /* Perform a couple rounds of sending data */
	 for (int i = 0; ret == 0 && i < 32 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected; i++)
	 {
		 was_active = 0;

		 ret = tls_api_one_sim_round(test_ctx, &simulated_time, &was_active);
	 }

	 /* Client should now be in state disconnected */
	 if (ret == 0 && test_ctx->cnx_client->cnx_state != picoquic_state_disconnected)
	 {
		 ret = -1;
	 }

	 if (test_ctx != NULL)
	 {
		 tls_api_delete_ctx(test_ctx);
		 test_ctx = NULL;
	 }

	 return ret;
}

/*
* Server reset negative test.
* Establish a connection between server and client.
* When the connection is established, fabricate a bogus server reset and
* send it to the client.
* Expected result: the client ignores the bogus reset.
*/
int tls_api_bad_server_reset_test()
{
	uint64_t simulated_time = 0;
	uint64_t loss_mask = 0;
	picoquic_test_tls_api_ctx_t * test_ctx = NULL;
	int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN);
	uint8_t buffer[128];

	if (ret == 0)
	{
		ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
	}

	/* Prepare the bogus reset */
	if (ret == 0)
	{
		size_t byte_index = 0;
		buffer[byte_index++] = 0x41;
		picoformat_64(&buffer[byte_index], test_ctx->cnx_client->server_cnxid);
		byte_index += 8;
		memset(buffer + byte_index, 0xcc, sizeof(buffer) - byte_index);
	}

	/* Submit bogus request to client */
	if (ret == 0)
	{
		ret = picoquic_incoming_packet(test_ctx->qclient, buffer, sizeof(buffer),
			(struct sockaddr*)(&test_ctx->server_addr), simulated_time);
	}

	/* check that the client is still up */
	if (ret == 0 &&
		test_ctx->cnx_client->cnx_state != picoquic_state_client_ready)
	{
		ret = -1;
	}

	if (test_ctx != NULL)
	{
		tls_api_delete_ctx(test_ctx);
		test_ctx = NULL;
	}

	return ret;
}

/*
 * verify that a connection is correctly established after a stateless redirect
 */

int tls_api_hrr_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t * test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN);

    if (ret == 0)
    {
        /* Set the server in HRR/Cookies mode */
        picoquic_set_cookie_mode(test_ctx->qserver, 1);
        /* Try the connection */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0)
    {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (test_ctx != NULL)
    {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/*
 * Test two successive connections from the same client.
 */

int tls_api_two_connections_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t * test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, 0, NULL, "test-alpn");

    if (ret == 0)
    {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0)
    {
        /* Verify that the connection is fully established */
        uint64_t target_time = simulated_time + 2000000;

        while (ret == 0 &&
            test_ctx->cnx_client->cnx_state == picoquic_state_client_ready &&
            test_ctx->cnx_server->cnx_state == picoquic_state_server_ready &&
            simulated_time < target_time)
        {
            int was_active = 0;
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, &was_active);
        }

        /* Delete the client connection from the client context,
         * without sending notification to the server */
        while (test_ctx->qclient->cnx_list != NULL)
        {
            picoquic_delete_cnx(test_ctx->qclient->cnx_list);
        }

        /* Erase the server connection reference */
        test_ctx->cnx_server = NULL;

        /* Create a new connection in the client context */

        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, 0,
            (struct sockaddr *)&test_ctx->server_addr, simulated_time, 0, NULL, "test-alpn");

        if (test_ctx->cnx_client == NULL)
        {
            ret = -1;
        }
    }

    /* Now, restart a connection in the same context */
    if (ret == 0)
    {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0)
    {
        ret = tls_api_attempt_to_close(test_ctx, &simulated_time);
    }

    if (test_ctx != NULL)
    {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;

}

int tls_api_client_losses_test()
{
    return tls_api_loss_test(3ull);
}

int tls_api_server_losses_test()
{
    return tls_api_loss_test(6ull);
}

/*
 * Do a simple test for all supported versions
 */
int tls_api_multiple_versions_test()
{
    int ret = 0;

    for (size_t i = 1; ret == 0 && i < picoquic_nb_supported_versions; i++)
    {
        ret = tls_api_one_scenario_test(test_scenario_q_and_r, sizeof(test_scenario_q_and_r), 0, 0, 0, 
            picoquic_supported_versions[i].version);
    }

    return ret;
}