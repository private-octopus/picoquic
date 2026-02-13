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

#include "logreader.h"
#include "autoqlog.h"
#include "picoquic_logger.h"
#include "picoquic_bbr.h"
#include "qlog.h"

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

static int fctest_prepare_to_send(fctest_ctx_t* fctest_ctx, picoquic_cnx_t* cnx, uint8_t* context, size_t space)
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
				ret = fctest_prepare_to_send(fctest_ctx, cnx, bytes, length);
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

int flow_control_test()
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