/*
* Author: Christian Huitema
* Copyright (c) 2025, Private Octopus, Inc.
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

#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "picoquic_qlog.h"
#include "picoquic_bbr.h"
#include "picoquic_utils.h"

/* Flow control test:
*
* Simulate a data receiver that can only process data slowly, and must
* buffer whatever excess data is delivered. The test verifies that the
* amount of data that the application must queue does not exceed a
* preset limit, and fails the connection if it does.
*/
#define FCTEST_TEST_ALPN "fctest"

typedef struct st_fctest_spec_t {
	uint8_t test_id;
	picoquic_congestion_algorithm_t* ccalgo;
	uint64_t loss_mask;
	uint64_t transfer_size;
	uint64_t microsecs_per_byte;
	uint64_t credit_quantum;
	uint64_t initial_credit;
	uint64_t bytes_buffered_max;
	uint64_t completion_target;
} fctest_spec_t;

typedef struct st_fctest_ctx_t {
	uint64_t transfer_size;
	uint64_t microsecs_per_byte;
	uint64_t credit_quantum;

	uint64_t simulated_time;
	uint64_t loss_mask;
	uint64_t stream_id;
	uint64_t bytes_sent;

	uint64_t bytes_received;
	uint64_t bytes_buffered;
	uint64_t buffered_time;
	uint64_t microsec_rounding_error;

	uint64_t credits_pending;

	uint64_t bytes_buffered_max;

	int is_started;
	int fin_sent;
	int fin_received;
	int is_closed;
	int error_detected;
} fctest_ctx_t;

void fctest_ctx_init(fctest_ctx_t* fctest_ctx, fctest_spec_t* spec)
{
	memset(fctest_ctx, 0, sizeof(fctest_ctx_t));
	fctest_ctx->transfer_size = spec->transfer_size;
	fctest_ctx->microsecs_per_byte = spec->microsecs_per_byte;
	fctest_ctx->credit_quantum = spec->credit_quantum;
	fctest_ctx->loss_mask = spec->loss_mask;
}

int fctest_start_stream(fctest_ctx_t* fctest_ctx, picoquic_cnx_t* cnx)
{
	int ret = 0;

	if (cnx->client_mode && !fctest_ctx->is_started) {
		uint8_t start[] = { 0xff, 0xfe, 0xfd, 0xfc };
		fctest_ctx->is_started = 1;
		fctest_ctx->stream_id = picoquic_get_next_local_stream_id(cnx, 0);
		ret = picoquic_add_to_stream(cnx, fctest_ctx->stream_id, start, sizeof(start), 1);
		if (ret == 0) {
			ret = picoquic_set_app_flow_control(cnx, fctest_ctx->stream_id, 1);
		}
	}
	return ret;
}

int fctest_receive_data(fctest_ctx_t* fctest_ctx, picoquic_cnx_t* cnx, uint64_t current_time, size_t length)
{
	int ret = 0;
	uint64_t delta_t = current_time - fctest_ctx->buffered_time + fctest_ctx->microsec_rounding_error;
	uint64_t processed_bytes = delta_t / fctest_ctx->microsecs_per_byte;

	if (processed_bytes >= fctest_ctx->bytes_buffered) {
		processed_bytes = fctest_ctx->bytes_buffered;
		fctest_ctx->bytes_buffered = 0;
		fctest_ctx->microsec_rounding_error = 0;
	}
	else {
		fctest_ctx->bytes_buffered -= processed_bytes;
		fctest_ctx->microsec_rounding_error = delta_t % fctest_ctx->microsecs_per_byte;
	}
	fctest_ctx->buffered_time = current_time;
	fctest_ctx->credits_pending += processed_bytes;

	if (length > 0) {
		fctest_ctx->bytes_buffered += length;
		fctest_ctx->bytes_received += length;
		if (fctest_ctx->bytes_buffered > fctest_ctx->bytes_buffered_max) {
			fctest_ctx->bytes_buffered_max = fctest_ctx->bytes_buffered;
		}
	}
	/* Enforcing a quantum, because dripping credits in small number will lead to
	 * silly packet syndrome */
	if (fctest_ctx->credits_pending >= fctest_ctx->credit_quantum) {
		fctest_ctx->credits_pending -= fctest_ctx->credit_quantum;
		ret = picoquic_open_flow_control(cnx, fctest_ctx->stream_id, fctest_ctx->credit_quantum);
	}
	return ret;
}

static int fctest_prepare_to_send(fctest_ctx_t* fctest_ctx, uint8_t* context, size_t space)
{
	int ret = 0;
	uint8_t* buffer;
	int is_fin = 0;

	if (fctest_ctx->bytes_sent + space >= fctest_ctx->transfer_size) {
		space = (size_t)(fctest_ctx->transfer_size - fctest_ctx->bytes_sent);
		is_fin = 1;
		fctest_ctx->fin_sent = 1;
	}

	buffer = picoquic_provide_stream_data_buffer(context, space, is_fin, !is_fin);
	if (buffer != NULL) {
		memset(buffer, 0xFC, space);
		fctest_ctx->bytes_sent += space;
	}
	else {
		ret = -1;
	}
	return ret;
}

/* Slow receiver call back */
int fctest_callback(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
	int ret = 0;
	fctest_ctx_t* fctest_ctx = (fctest_ctx_t*)callback_ctx;
	uint64_t current_time = picoquic_get_quic_time(cnx->quic);
	/* TODO: decide what to do with the stream context */

	if (fctest_ctx == NULL) {
		return -1;
	}

	if (ret == 0) {
		switch (fin_or_event) {
		case picoquic_callback_stream_data:
		case picoquic_callback_stream_fin:
			/* data arrival on stream x.
			* On server: Simulate dequeuing based on the receiver rate,
			* then increase queue by provided amount. Monitor maximum
			* queue length. Mark complete if stream fin.
			*/
			if (bytes == NULL && length != 0 && v_stream_ctx != NULL) {
				ret = -1;
			}
			else if (cnx->client_mode) {
				if (stream_id == fctest_ctx->stream_id) {
					ret = fctest_receive_data(fctest_ctx, cnx, current_time, length);
					fctest_ctx->fin_received = (fin_or_event == picoquic_callback_stream_fin);
				}
			}
			else {
				if (stream_id == fctest_ctx->stream_id && fin_or_event == picoquic_callback_stream_fin) {
					picoquic_mark_active_stream(cnx, stream_id, 1, NULL);
				}
			}
			break;
		case picoquic_callback_stream_reset: /* Peer reset stream #x */
		case picoquic_callback_stop_sending: /* Peer asks server to reset stream #x */
			/* Not expected in this test. Failure. */
			break;
		case picoquic_callback_stateless_reset:
		case picoquic_callback_close: /* Received connection close */
		case picoquic_callback_application_close: /* Received application close */
			fctest_ctx->is_closed = 1;
			break;
		case picoquic_callback_version_negotiation:
			/* Not expected in this test */
			ret = -1;
			break;
		case picoquic_callback_stream_gap:
			/* Gap indication, when unreliable streams are supported */
			ret = -1;
			break;
		case picoquic_callback_prepare_to_send:
			/* On the client, prepare the expected amount of data. Mark
			* active until the expected amount is received. */
			if (!cnx->client_mode) {
				ret = fctest_prepare_to_send(fctest_ctx, bytes, length);
			}
			break;
		case picoquic_callback_datagram: /* Datagram frame has been received */
			/* Not expected in this test */
			ret = -1;
			break;
		case picoquic_callback_prepare_datagram: /* Prepare the next datagram */
			/* Not expected in this test */
			ret = -1;
			break;
		case picoquic_callback_datagram_acked: /* Ack for packet carrying datagram-frame received from peer */
		case picoquic_callback_datagram_lost: /* Packet carrying datagram-frame probably lost */
		case picoquic_callback_datagram_spurious: /* Packet carrying datagram-frame was not really lost */
			/* Not expected in this test */
			ret = -1;
			break;
		case picoquic_callback_almost_ready:
		case picoquic_callback_ready:
			/* On the client, open a "bidir" stream and mark it active */
			ret = fctest_start_stream(fctest_ctx, cnx);
			break;
		default:
			/* unexpected -- just ignore. */
			break;
		}
	}

	return ret;
}

int fctest_one(fctest_spec_t* spec)
{
	int nb_trials = 0;
	int nb_inactive = 0;
	int was_active = 0;
	picoquic_test_tls_api_ctx_t* test_ctx = NULL;
	fctest_ctx_t fctest_ctx;
	picoquic_connection_id_t initial_cid = { {0xfc, 0x4e, 0x54, 0, 0, 0, 0, 0}, 8 };
	int ret = 0;
	uint64_t timeout = 10000;

	initial_cid.id[7] = spec->test_id;

	fctest_ctx_init(&fctest_ctx, spec);

	if (ret == 0) {
		ret = tls_api_init_ctx_ex2(&test_ctx,
			PICOQUIC_INTERNAL_TEST_VERSION_1,
			PICOQUIC_TEST_SNI, FCTEST_TEST_ALPN, &fctest_ctx.simulated_time, NULL, NULL, 0, 1, 0, &initial_cid, 8, 0, 0, 0);

		if (ret == 0) {
			picoquic_tp_t * client_tp = (picoquic_tp_t *) picoquic_get_transport_parameters(test_ctx->cnx_client, 1);

			client_tp->initial_max_stream_data_bidi_local = spec->initial_credit;

			picoquic_set_default_congestion_algorithm(test_ctx->qserver, spec->ccalgo);
			picoquic_set_congestion_algorithm(test_ctx->cnx_client, spec->ccalgo);

			picoquic_set_qlog(test_ctx->qserver, ".");
			test_ctx->qserver->use_long_log = 1;
			picoquic_set_qlog(test_ctx->qclient, ".");
		}
	}

	/* The default procedure creates connections using the test callback.
	* We want to replace that by the fctest callback */

	if (ret == 0) {
		/* TODO: proper call back context */
		picoquic_set_default_callback(test_ctx->qserver, fctest_callback, &fctest_ctx);
		picoquic_set_callback(test_ctx->cnx_client, fctest_callback, &fctest_ctx);
		if (ret == 0) {
			ret = picoquic_start_client_cnx(test_ctx->cnx_client);
		}
	}

	if (ret == 0) {
		ret = tls_api_connection_loop(test_ctx, &fctest_ctx.loss_mask, 0, &fctest_ctx.simulated_time);
	}

	while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
		/* May need to set a timeout per flow control. */
		if (fctest_ctx.bytes_buffered > 0 &&
			fctest_ctx.simulated_time >= fctest_ctx.buffered_time + timeout) {
			ret = fctest_receive_data(&fctest_ctx, test_ctx->cnx_client, fctest_ctx.simulated_time, 0);
		}
		/* Progress. */
		if ((ret = tls_api_one_sim_round(test_ctx, &fctest_ctx.simulated_time, fctest_ctx.simulated_time + timeout, &was_active)) != 0) {
			break;
		}

		/* TODO: test based on fctest context. */
		if (fctest_ctx.fin_received || fctest_ctx.is_closed || fctest_ctx.error_detected) {
			break;
		}

		if (was_active) {
			nb_inactive = 0;
		}
		else {
			nb_inactive++;
			if (nb_inactive > 256) {
				break;
			}
		}

		if (++nb_trials > 1000000) {
			ret = -1;
			break;
		}
	}

	/* check that the transfer is complete */
	if (ret == 0 &&(!fctest_ctx.fin_received || fctest_ctx.bytes_received < spec->transfer_size)) {
		DBG_PRINTF("Test received %" PRIu64 " bytes instead of %" PRIu64, fctest_ctx.bytes_received, spec->transfer_size);
		ret = -1;
	}

	/* TODO: check that the buffers remained within specified limits */
	if (ret == 0 && fctest_ctx.bytes_buffered_max > spec->initial_credit + spec->credit_quantum) {
		DBG_PRINTF("Test buffer max %" PRIu64 " bytes instead of %" PRIu64, fctest_ctx.bytes_buffered_max, spec->bytes_buffered_max);
		ret = -1;
	}

	/* Also check completion time */
	if (ret == 0 && spec->completion_target != 0 && fctest_ctx.simulated_time > spec->completion_target) {
		DBG_PRINTF("Test uses %llu microsec instead of %llu", fctest_ctx.simulated_time, spec->completion_target);
		ret = -1;
	}

	if (test_ctx != NULL) {
		tls_api_delete_ctx(test_ctx);
		test_ctx = NULL;
	}

	return ret;
}

int flow_control_test(void)
{
	fctest_spec_t spec = { 0 };
	spec.test_id = 1;
	spec.transfer_size = 1000000;
	spec.microsecs_per_byte = 10;
	spec.credit_quantum = 0x4000;
	spec.initial_credit = 0x10000;
	spec.bytes_buffered_max = 0x4000;
	spec.completion_target = 11000000;
	spec.ccalgo = picoquic_bbr_algorithm;

	return fctest_one(&spec);
}

/*
 * Minimal reproducer for picoquic_open_flow_control() becoming a silent no-op
 * after picoquic_set_max_data_control() enables bounded connection flow control.
 */

int flow_control_open_max_test(void)
{
	int ret = 0;
	struct sockaddr_in peer;
	picoquic_quic_t* quic = NULL;

	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_port = htons(4433);
	peer.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

	quic = picoquic_create(
		1, NULL, NULL, NULL, "repro", NULL, NULL, NULL, NULL, NULL,
		0, NULL, NULL, NULL, 0);

	if (quic == NULL) {
		DBG_PRINTF("%s", "picoquic_create failed");
		ret = -1;
	}
	else {
		picoquic_set_max_data_control(quic, 65536);
		picoquic_cnx_t* cnx = picoquic_create_cnx(
			quic, picoquic_null_connection_id, picoquic_null_connection_id,
			(const struct sockaddr*)&peer, 0, 0, "server.example", "repro", 1);
		if (cnx == NULL) {
			DBG_PRINTF("%s", "picoquic_create_cnx failed");
			ret = -1;
		}
		else {
			picoquic_stream_head_t* stream = NULL;
			cnx->cnx_state = picoquic_state_ready;
			if ((stream = picoquic_create_stream(cnx, 0)) == NULL) {
				DBG_PRINTF("%s", "picoquic_create_stream failed");
				ret = -1;
			}
			else {
				const picoquic_misc_frame_header_t* frame = NULL;

				stream->consumed_offset = 1024;
				stream->maxdata_local = 1024;

				if ((ret = picoquic_open_flow_control(cnx, 0, 1024)) != 0) {
					DBG_PRINTF("picoquic_open_flow_control returned %d", ret);
				}
				else if ((frame = cnx->first_misc_frame) == NULL) {
					DBG_PRINTF("%s", "BUG: returned success but queued no MAX_STREAM_DATA frame");
					ret = -1;
				}
				else {
					const uint8_t* encoded = (const uint8_t*)(frame)+sizeof(picoquic_misc_frame_header_t);
					if (frame->length == 0 || encoded[0] != picoquic_frame_type_max_stream_data) {
						DBG_PRINTF("%s", "BUG: returned success but first queued frame is not MAX_STREAM_DATA");
						ret = -1;
					}
				}
			}
		}
		picoquic_free(quic);
	}
	return ret;
}

/*
 * Test what happens if the application calls picoquic_mark_active_stream()
 * on a client-created unidirectional stream, but the stream number is
 * above the number of streams authorized by the peer.
 *
 * This test artificially constrains the server's initial unidir stream
 * limit to 1, so the client's second local unidir stream starts out beyond
 * the limit. It verifies:
 * - the first stream (within the limit) is scheduled immediately;
 * - the second stream (beyond the limit) is NOT scheduled at first;
 * - once the first stream is fully received and the server raises the
 *   limit, the second stream is scheduled and prepare_to_send fires;
 * - the diagnostic message added at the exclusion point (streams.c,
 *   picoquic_insert_output_stream) makes it into the client's qlog.
 */

typedef struct st_uniblock_ctx_t {
	uint64_t stream_id[2];
	int prepare_called[2];
	int is_closed;
	int error_detected;
} uniblock_ctx_t;

static int uniblock_prepare_to_send(uniblock_ctx_t* ctx, int idx, uint8_t* context, size_t space)
{
	uint8_t* buffer;
	size_t to_send = (space < 8) ? space : 8;

	ctx->prepare_called[idx] = 1;

	buffer = picoquic_provide_stream_data_buffer(context, to_send, 1, 0);
	if (buffer == NULL) {
		DBG_PRINTF("provide_stream_data_buffer(idx=%d, to_send=%zu) returned NULL", idx, to_send);
		return -1;
	}
	memset(buffer, (uint8_t)('a' + idx), to_send);
	return 0;
}

static int uniblock_callback(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
	int ret = 0;
	uniblock_ctx_t* ctx = (uniblock_ctx_t*)callback_ctx;
	(void)stream_id;
	(void)bytes;
	(void)length;
	(void)v_stream_ctx;

	if (ctx == NULL) {
		return -1;
	}

	switch (fin_or_event) {
	case picoquic_callback_stream_data:
	case picoquic_callback_stream_fin:
		/* Server: passively receive. consumed_offset and fin_received
		 * update automatically as part of stream reassembly, which is
		 * what drives the peer's MAX_STREAMS_UNI recovery -- no explicit
		 * app action is required here. */
		break;
	case picoquic_callback_prepare_to_send:
		if (cnx->client_mode && stream_id == ctx->stream_id[0]) {
			ret = uniblock_prepare_to_send(ctx, 0, bytes, length);
		}
		else if (cnx->client_mode && stream_id == ctx->stream_id[1]) {
			ret = uniblock_prepare_to_send(ctx, 1, bytes, length);
		}
		else {
			DBG_PRINTF("Unexpected prepare_to_send: client=%d, stream_id=%" PRIu64 ", tracked=[%" PRIu64 ",%" PRIu64 "]",
				cnx->client_mode, stream_id, ctx->stream_id[0], ctx->stream_id[1]);
			ret = -1;
		}
		break;
	case picoquic_callback_almost_ready:
	case picoquic_callback_ready:
		if (cnx->client_mode && ctx->stream_id[0] == 0 && ctx->stream_id[1] == 0) {
			/* picoquic_get_next_local_stream_id() only peeks at the next
			 * available ID -- it does not reserve it. The counter only
			 * advances once the stream is actually created (as a side
			 * effect of picoquic_mark_active_stream()), so the second ID
			 * must be queried only after the first stream exists. */
			ctx->stream_id[0] = picoquic_get_next_local_stream_id(cnx, 1);
			ret = picoquic_mark_active_stream(cnx, ctx->stream_id[0], 1, NULL);
			if (ret != 0) {
				DBG_PRINTF("mark_active_stream(%" PRIu64 ") returned %d", ctx->stream_id[0], ret);
			}
			else {
				ctx->stream_id[1] = picoquic_get_next_local_stream_id(cnx, 1);
				ret = picoquic_mark_active_stream(cnx, ctx->stream_id[1], 1, NULL);
				if (ret != 0) {
					DBG_PRINTF("mark_active_stream(%" PRIu64 ") returned %d", ctx->stream_id[1], ret);
				}
			}
		}
		break;
	case picoquic_callback_close:
	case picoquic_callback_application_close:
		ctx->is_closed = 1;
		break;
	default:
		break;
	}

	if (ret != 0) {
		ctx->error_detected = 1;
	}

	return ret;
}

int stream_uni_blocked_test(void)
{
	int ret = 0;
	uint64_t simulated_time = 0;
	uint64_t loss_mask = 0;
	int nb_trials = 0;
	int was_active = 0;
	picoquic_test_tls_api_ctx_t* test_ctx = NULL;
	uniblock_ctx_t uniblock_ctx;
	picoquic_tp_t server_parameters;
	picoquic_connection_id_t initial_cid = { { 0xb1, 0x0c, 0, 0, 0, 0, 0, 0 }, 8 };
	char const* client_qlog_name = "b10c000000000000.client.qlog";

	memset(&uniblock_ctx, 0, sizeof(uniblock_ctx));

	ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
		PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

	if (ret == 0 && test_ctx == NULL) {
		ret = -1;
	}

	if (ret == 0) {
		memset(&server_parameters, 0, sizeof(picoquic_tp_t));
		picoquic_init_transport_parameters(&server_parameters);
		server_parameters.initial_max_stream_id_unidir = 1;
		picoquic_set_default_tp(test_ctx->qserver, &server_parameters);

		picoquic_set_qlog(test_ctx->qclient, ".");

		picoquic_set_default_callback(test_ctx->qserver, uniblock_callback, &uniblock_ctx);
		picoquic_set_callback(test_ctx->cnx_client, uniblock_callback, &uniblock_ctx);

		ret = picoquic_start_client_cnx(test_ctx->cnx_client);
	}

	if (ret == 0) {
		ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
	}

	/* Give the first stream (within the initial limit) a short window to be
	 * scheduled. Note: we do NOT assert that the second stream is still
	 * blocked at this point -- in this simulated network the round trip
	 * (client sends stream[0]'s data+fin, server consumes it and raises
	 * the unidir limit, client receives MAX_STREAMS_UNI) can complete in
	 * well under a millisecond of simulated time, faster than any window
	 * we could safely wait here. The qlog check below is what actually
	 * proves the exclusion happened at least once. */
	if (ret == 0) {
		ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 500000);
	}

	if (ret == 0 && !uniblock_ctx.prepare_called[0]) {
		DBG_PRINTF("%s", "Stream within the initial unidir limit was never scheduled");
		ret = -1;
	}

	/* Keep running: once the server fully receives the first stream, it
	 * should raise the unidir limit, unblocking the second stream. */
	while (ret == 0 && !uniblock_ctx.prepare_called[1] && !uniblock_ctx.error_detected &&
		picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
		ret = tls_api_one_sim_round(test_ctx, &simulated_time, simulated_time + 1000000, &was_active);
		if (was_active) {
			nb_trials = 0;
		}
		else if (++nb_trials > 256) {
			break;
		}
	}

	if (ret == 0 && !uniblock_ctx.prepare_called[1]) {
		DBG_PRINTF("%s", "Stream beyond the initial unidir limit never got unblocked");
		ret = -1;
	}

	if (ret == 0 && uniblock_ctx.error_detected) {
		DBG_PRINTF("%s", "error_detected was set during the unblock loop");
		ret = -1;
	}

	if (test_ctx != NULL) {
		tls_api_delete_ctx(test_ctx);
		test_ctx = NULL;
	}

	/* Verify that the diagnostic message added at the exclusion point made
	 * it into the client's qlog. picoquic_set_qlog() names the file after
	 * the client's initial CID, so the name is known in advance. */
	if (ret == 0) {
		FILE* F = picoquic_file_open(client_qlog_name, "r");
		int found = 0;

		if (F == NULL) {
			DBG_PRINTF("Cannot open client qlog file: %s.", client_qlog_name);
			ret = -1;
		}
		else {
			char line[512];

			while (fgets(line, sizeof(line), F) != NULL) {
				if (strstr(line, "not scheduled") != NULL &&
					strstr(line, "unidir stream limit") != NULL) {
					found = 1;
					break;
				}
			}
			(void)picoquic_file_close(F);

			if (!found) {
				DBG_PRINTF("%s", "Diagnostic message not found in client qlog.");
				ret = -1;
			}
		}
	}

	return ret;
}

/*
 * Reproduces a field report more precisely: transport parameters are
 * generous on both the per-stream byte limit (65535) and the stream count
 * limit (5120), ruling out both of the flow-control mechanisms exercised
 * above. The client opens a single local unidirectional stream, sends an
 * initial chunk of data (matching the reported 517 bytes) with
 * is_still_active = 0, and later -- from outside any callback, the way an
 * application reacting to new data becoming available would -- calls
 * picoquic_mark_active_stream() again on the SAME stream to send more.
 * The question this answers: does prepare_to_send fire the second time?
 */

typedef struct st_uni_reactivate_ctx_t {
	uint64_t stream_id;
	int nb_prepare_calls;
	int is_closed;
	int error_detected;
} uni_reactivate_ctx_t;

static int uni_reactivate_prepare_to_send(uni_reactivate_ctx_t* ctx, uint8_t* context, size_t space)
{
	uint8_t* buffer;
	size_t to_send;
	int is_fin = (ctx->nb_prepare_calls > 0);

	to_send = is_fin ? 8 : 517;
	if (to_send > space) {
		to_send = space;
	}

	buffer = picoquic_provide_stream_data_buffer(context, to_send, is_fin, 0);
	if (buffer == NULL) {
		return -1;
	}
	memset(buffer, 'a', to_send);
	ctx->nb_prepare_calls++;
	return 0;
}

static int uni_reactivate_callback(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
	int ret = 0;
	uni_reactivate_ctx_t* ctx = (uni_reactivate_ctx_t*)callback_ctx;
	(void)v_stream_ctx;

	if (ctx == NULL) {
		return -1;
	}

	switch (fin_or_event) {
	case picoquic_callback_stream_data:
	case picoquic_callback_stream_fin:
		/* Server: passively receive. */
		break;
	case picoquic_callback_prepare_to_send:
		if (cnx->client_mode && stream_id == ctx->stream_id) {
			ret = uni_reactivate_prepare_to_send(ctx, bytes, length);
		}
		else {
			ret = -1;
		}
		break;
	case picoquic_callback_almost_ready:
	case picoquic_callback_ready:
		if (cnx->client_mode && ctx->stream_id == 0) {
			ctx->stream_id = picoquic_get_next_local_stream_id(cnx, 1);
			ret = picoquic_mark_active_stream(cnx, ctx->stream_id, 1, NULL);
		}
		break;
	case picoquic_callback_close:
	case picoquic_callback_application_close:
		ctx->is_closed = 1;
		break;
	default:
		break;
	}

	if (ret != 0) {
		ctx->error_detected = 1;
	}

	return ret;
}

int stream_uni_reactivate_test(void)
{
	int ret = 0;
	uint64_t simulated_time = 0;
	uint64_t loss_mask = 0;
	int nb_trials = 0;
	int was_active = 0;
	picoquic_test_tls_api_ctx_t* test_ctx = NULL;
	uni_reactivate_ctx_t ctx;
	picoquic_tp_t server_parameters;
	picoquic_connection_id_t initial_cid = { { 0xb1, 0x0d, 0, 0, 0, 0, 0, 0 }, 8 };

	memset(&ctx, 0, sizeof(ctx));

	ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
		PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

	if (ret == 0 && test_ctx == NULL) {
		ret = -1;
	}

	if (ret == 0) {
		/* Match the transport parameters from the field report: generous
		 * limits, so neither per-stream nor stream-count flow control is
		 * anywhere close to being the blocker. */
		memset(&server_parameters, 0, sizeof(picoquic_tp_t));
		picoquic_init_transport_parameters(&server_parameters);
		server_parameters.initial_max_stream_data_bidi_local = 2097152;
		server_parameters.initial_max_data = 31457280;
		server_parameters.initial_max_stream_id_bidir = 5120;
		server_parameters.initial_max_stream_id_unidir = 5120;
		server_parameters.initial_max_stream_data_bidi_remote = 65635;
		server_parameters.initial_max_stream_data_uni = 65535;
		picoquic_set_default_tp(test_ctx->qserver, &server_parameters);

		picoquic_set_qlog(test_ctx->qclient, ".");

		picoquic_set_default_callback(test_ctx->qserver, uni_reactivate_callback, &ctx);
		picoquic_set_callback(test_ctx->cnx_client, uni_reactivate_callback, &ctx);

		ret = picoquic_start_client_cnx(test_ctx->cnx_client);
	}

	if (ret == 0) {
		ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
	}

	/* Let the first chunk go out. */
	if (ret == 0) {
		ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, 500000);
	}

	if (ret == 0 && ctx.nb_prepare_calls < 1) {
		DBG_PRINTF("%s", "First write on the unidirectional stream never happened");
		ret = -1;
	}

	/* Simulate the application deciding, later, that it has more data --
	 * re-arm the stream the same way picoquic_mark_active_stream() would
	 * be called from application code reacting to a new data event. */
	if (ret == 0) {
		ret = picoquic_mark_active_stream(test_ctx->cnx_client, ctx.stream_id, 1, NULL);
		if (ret != 0) {
			DBG_PRINTF("Second mark_active_stream(%" PRIu64 ") returned %d", ctx.stream_id, ret);
		}
	}

	while (ret == 0 && ctx.nb_prepare_calls < 2 && !ctx.error_detected &&
		picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
		ret = tls_api_one_sim_round(test_ctx, &simulated_time, simulated_time + 1000000, &was_active);
		if (was_active) {
			nb_trials = 0;
		}
		else if (++nb_trials > 256) {
			break;
		}
	}

	if (ret == 0 && ctx.nb_prepare_calls < 2) {
		DBG_PRINTF("%s", "Second write on the unidirectional stream never happened -- reproduces the field report");
		ret = -1;
	}

	if (ret == 0 && ctx.error_detected) {
		ret = -1;
	}

	if (test_ctx != NULL) {
		tls_api_delete_ctx(test_ctx);
		test_ctx = NULL;
	}

	return ret;
}
