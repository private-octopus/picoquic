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

/*
* Testing the implementation of Qmux in picoquic.
*
* - test of the send function. Verify that QMUX can format a packet.
* - test of the receive function. Test that QMUX can parse the frames in a packet.
* - raw connection. Verify that the server can create a QMUX connection.
* - back-to-back test. Do a qmux loop with pack to back sender/receiver. Try an end to end scenario.
* - back-to-back with TLS.
* - back-to-back with simulated network connection.
*
* The final step would of course be to implement a TCP extension to the socket loop.
*/


#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "picoquic_qlog.h"

int picoqmux_prepare_packet(picoquic_cnx_t* cnx, uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t* next_wake_time);
int picoqmux_incoming_packet(picoquic_cnx_t* cnx, uint64_t current_time,
    const uint8_t* receive_buffer, size_t receive_length, uint64_t* next_wake_time);
int picoqmux_has_sent_tp(picoquic_cnx_t* cnx);
int picoqmux_has_received_tp(picoquic_cnx_t* cnx);
void picoqmux_update_state_on_tp_sent(picoquic_cnx_t* cnx);
void picoqmux_update_state_on_tp_received(picoquic_cnx_t* cnx);

#define QMUX_FIRST_DATA 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
uint8_t qmux_test_data[] = { QMUX_FIRST_DATA };
uint8_t qmux_test_packet[] = { 0x0b, 0x0, 0x0f, QMUX_FIRST_DATA };

void qmux_test_simulate_remote(picoquic_cnx_t* cnx) {
    cnx->remote_parameters.initial_max_data = 0x10000;
    cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
    cnx->remote_parameters.initial_max_stream_data_bidi_local = 0x10000;
    cnx->remote_parameters.initial_max_stream_data_bidi_remote = 0x10000;
    cnx->remote_parameters.initial_max_stream_id_bidir = 100;
}

int qmux_send_test(void)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint8_t buffer[1536];
    size_t send_length = 0;
    uint64_t next_wake_time = 0;
    int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);

    if (ret == 0) {
        /* simulate that TP has been sent and received. */
        picoqmux_update_state_on_tp_sent(cnx);
        picoqmux_update_state_on_tp_received(cnx);
        /* simulate flow control open. */
        qmux_test_simulate_remote(cnx);
        /* add test data to stream zero. */
        ret = picoquic_add_to_stream(cnx, 0, qmux_test_data, sizeof(qmux_test_data), 1);
    }
    if (ret == 0) {
        /* prepare the packet */
        ret = picoqmux_prepare_packet(cnx, 0, buffer, sizeof(buffer), &send_length, &next_wake_time);

        if (send_length != sizeof(qmux_test_packet) ||
            memcmp(buffer, qmux_test_packet, send_length) != 0) {
            ret = -1;
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* Check that frames can be received properly */
/* TODO: run a test with all frames in skip frame test, to check
* that allowed frames pass, and that not allowed frames are rejected. */ 

/* Callback from Quic
*/
typedef struct st_qmux_test_callback_t {
    int received_stream_0;
    size_t stream_0_length_received;
    int stream0_fin_received;
    int stream0_data_matches;
} qmux_test_callback_t;

int qmux_test_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* UNUSED(v_stream_ctx))
{

    int ret = 0;
    qmux_test_callback_t* qtc = (qmux_test_callback_t*)callback_ctx;

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            if (stream_id == 0) {
                qtc->received_stream_0 = 1;
                qtc->stream_0_length_received = length;
                if (length == sizeof(qmux_test_data) &&
                    memcmp(bytes, qmux_test_data, length) == 0) {
                    qtc->stream0_data_matches = 1;
                }
                if (fin_or_event == picoquic_callback_stream_fin) {
                    qtc->stream0_fin_received = 1;
                }
            }
            break;
        case picoquic_callback_prepare_to_send:
        case picoquic_callback_datagram:
        case picoquic_callback_prepare_datagram:
            /* not expected */
            ret = -1;
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            /* TODO: react to abandon stream, etc. */
            break;
        case picoquic_callback_stateless_reset: /* Received an error message */
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Remove the connection from the context, and then delete it */
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* should mark the first stream as ready, create it if necessary */
            break;
        case picoquic_callback_datagram_acked:
            /* Ack for packet carrying datagram-object received from peer */
        case picoquic_callback_datagram_lost:
            /* Packet carrying datagram-object probably lost */
        case picoquic_callback_datagram_spurious:
            /* Packet carrying datagram-object was not really lost */
            break;
        case picoquic_callback_pacing_changed:
            /* Notification of rate change from congestion controller */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

int qmux_receive_test(void)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t next_wake_time = UINT64_MAX;
    qmux_test_callback_t qtc = { 0 };
    int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);

    cnx->client_mode = 0; /* make sure we are in server mode, to accept the packet */
    picoqmux_update_state_on_tp_received(cnx); /* simulate that TP has been received. */
    picoquic_set_callback(cnx, qmux_test_callback, &qtc);
    if (ret == 0) {
        /* prepare a packet */
        ret = picoqmux_incoming_packet(cnx, 12345,
            qmux_test_packet, sizeof(qmux_test_packet), &next_wake_time);
        if (ret == 0 && !(
            qtc.received_stream_0 &&
            qtc.stream_0_length_received == sizeof(qmux_test_data) &&
            qtc.stream0_fin_received &&
            qtc.stream0_data_matches)) {
            ret = -1;
        }
    }

    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

uint8_t qmux_test_tp_packet[] = {
    0xff, 0x51, 0x53, 0x30, 0x0d, 0x0a, 0x0d, 0x0a,
    0x40, 0x26, 0x05, 0x04, 0x80, 0x20, 0x00, 0x00,
    0x04, 0x04, 0x80, 0x10, 0x00, 0x00, 0x08, 0x02,
    0x42, 0x00, 0x01, 0x04, 0x80, 0x00, 0x75, 0x30,
    0x09, 0x02, 0x42, 0x00, 0x06, 0x04, 0x80, 0x01,
    0x00, 0x63, 0x07, 0x04, 0x80, 0x00, 0xff, 0xff };

int qmux_send_tp_test(void)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint8_t buffer[2048];
    size_t send_length = 0;
    uint64_t next_wake_time = 0;
    int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);

    if (ret == 0) {
        /* prepare the packet */
        ret = picoqmux_prepare_packet(cnx, 0, buffer, sizeof(buffer), &send_length, &next_wake_time);

        if (send_length != sizeof(qmux_test_tp_packet) ||
            memcmp(buffer, qmux_test_tp_packet, send_length) != 0) {
            ret = -1;
        }
    }

    if (ret == 0 && cnx->cnx_state != picoquic_state_client_ready_start) {
        ret = -1;
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int qmux_tp_receive_test(void)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t next_wake_time = UINT64_MAX;
    qmux_test_callback_t qtc = { 0 };
    int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);

    cnx->client_mode = 0; /* make sure we are in server mode, to accept the packet */

    picoquic_set_callback(cnx, qmux_test_callback, &qtc);
    if (ret == 0) {
        /* prepare a packet */
        ret = picoqmux_incoming_packet(cnx, 12345,
            qmux_test_tp_packet, sizeof(qmux_test_tp_packet), &next_wake_time);
        if (ret == 0 && cnx->cnx_state != picoquic_state_server_false_start) {
            ret = -1;
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int qmux_tp_receive_error_one(int set_tp_received, int set_tp_sent,
    uint8_t * message, size_t length, uint64_t expected)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t next_wake_time = UINT64_MAX;
    qmux_test_callback_t qtc = { 0 };
    int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);

    cnx->client_mode = 0; /* make sure we are in server mode, to accept the packet */

    picoquic_set_callback(cnx, qmux_test_callback, &qtc);

    if (set_tp_received) {
        picoqmux_update_state_on_tp_received(cnx);
    }

    if (set_tp_sent) {
        picoqmux_update_state_on_tp_sent(cnx);
    }

    if (ret == 0) {
        /* prepare a packet */
        int r_ret = picoqmux_incoming_packet(cnx, 12345,
            message, length, &next_wake_time);
        if (r_ret == 0) {
            ret = -1;
        }
    }

    if (ret == 0 && cnx->cnx_state != picoquic_state_disconnecting &&
        cnx->cnx_state != picoquic_state_handshake_failure) {
        ret = -1;
    }
    if (ret == 0 && cnx->local_error != expected) {
        ret = -1;
    }

    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int qmux_tp_recv_errors_test(void)
{
    int ret = 0;
    if (ret == 0) {
        /* TP not received, but message is not TP */
        ret = qmux_tp_receive_error_one(0, 0, qmux_test_data, sizeof(qmux_test_data),
            PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
    }
    if (ret == 0) {
        /* TP received, but message is not duplicate TP */;
        ret = qmux_tp_receive_error_one(1, 1, qmux_test_tp_packet, sizeof(qmux_test_tp_packet),
            PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
    }
    return ret;
}