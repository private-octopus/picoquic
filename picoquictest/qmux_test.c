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
    size_t consumed = 0;
    size_t send_length = 0;
    uint64_t next_wake_time = 0;
    int ret = picoquic_test_set_minimal_cnx(&quic, &cnx);

    if (ret == 0) {
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