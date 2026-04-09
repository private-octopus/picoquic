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

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>

uint8_t* picoquic_prepare_stream_and_datagrams(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint8_t* bytes_next, uint8_t* bytes_max,
    int is_first_in_packet, uint64_t max_priority_allowed,
    int* more_data, int* is_pure_ack, int* no_data_to_send, int* ret);

/* QMux prepare: prepare a packet. */
/*  Prepare the next packet to send when in the ready state */
int picoqmux_prepare_packet(picoquic_cnx_t* cnx, uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t* next_wake_time)
{
    int ret = 0;
    size_t length = 0;
    uint8_t* bytes = send_buffer;
    uint8_t* bytes_max = send_buffer + send_buffer_max;
    uint8_t* bytes_next = bytes;
    picoquic_path_t* path_x = cnx->path[0];
    int more_data = 0;
    int is_pure_ack = 1;
    int no_data_to_send = 0;
                
    /* if necessary, prepare the MAX STREAM frames */
    if (ret == 0) {
        bytes_next = picoquic_format_max_streams_frame_if_needed(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
    }

    /* If necessary, encode the max data frame */
    if (ret == 0) {
        if (cnx->quic->max_data_limit != 0) {
            if (cnx->data_received + ((3 * cnx->quic->max_data_limit) / 4) > cnx->maxdata_local) {
                uint64_t max_data_increase = cnx->data_received + cnx->quic->max_data_limit - cnx->maxdata_local;
                bytes_next = picoquic_format_max_data_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack,
                    max_data_increase);
            }
        }
        else if (2 * cnx->offset_received > cnx->maxdata_local) {
            bytes_next = picoquic_format_max_data_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack,
                picoquic_cc_increased_window(cnx, cnx->maxdata_local));
        }
    }

    /* If necessary, encode the max stream data frames */
    if (ret == 0 && cnx->max_stream_data_needed) {
        bytes_next = picoquic_format_required_max_stream_data_frames(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
    }

    /* If present, send misc frame */
    bytes_next = picoquic_format_misc_frames_in_context(cnx, bytes_next, bytes_max,
        &more_data, &is_pure_ack, picoquic_packet_context_application);

    /* Compute the length before entering the CC block */
    length = bytes_next - bytes;

    /* Send here the frames that are subject to both congestion and pacing control.
        * this includes the PMTU probes.
        * Check whether PMTU discovery is required. The call will return
        * three values: not needed at all, optional, or required.
        * If required, PMTU discovery takes priority over sending stream data.
        */

    if (cnx->is_address_discovery_provider) {
        /* If a new address was learned, prepare an observed address frame */
        /* TODO: tie this code to processing of paths */
        bytes_next = picoquic_prepare_observed_address_frame(bytes_next, bytes_max,
            path_x, path_x->first_tuple, current_time, next_wake_time, &more_data, &is_pure_ack);
    }

    if (ret == 0) {
        bytes_next = picoquic_prepare_stream_and_datagrams(cnx, path_x, bytes_next, bytes_max,
            (size_t)(bytes_next - bytes) == 0, UINT64_MAX, &more_data, &is_pure_ack, &no_data_to_send, &ret);
    }

    length = bytes_next - bytes;

    if (length == 0 || is_pure_ack) {
        /* Mark the bandwidth estimation as application limited */
        path_x->delivered_limited_index = path_x->delivered;
        /* Notify the peer if something is blocked */
        bytes_next = picoquic_format_blocked_frames(cnx, &bytes[length], bytes_max, &more_data, &is_pure_ack);
        length = bytes_next - bytes;
    }
    if (no_data_to_send) {
        path_x->last_sender_limited_time = current_time;
    }

    if (more_data) {
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        ret = 0;
    }
    /* Set sent length */
    *send_length = length;
    return ret;
}