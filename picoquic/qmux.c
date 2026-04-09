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


/*
 * Processing of the incoming QMUX packet.
 */

int picoqmux_decode_frames(picoquic_cnx_t* cnx, picoquic_path_t* path_x, const uint8_t* bytes,
    size_t bytes_maxsize,
    picoquic_stream_data_node_t* received_data,
    uint64_t current_time)
{
    const uint8_t* bytes_max = bytes + bytes_maxsize;
    int ack_needed = 0;
    picoquic_packet_data_t packet_data;

    memset(&packet_data, 0, sizeof(packet_data));

    while (bytes != NULL && bytes < bytes_max) {
        uint8_t first_byte = bytes[0];

        if (PICOQUIC_IN_RANGE(first_byte, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            bytes = picoquic_decode_stream_frame(cnx, bytes, bytes_max, received_data, current_time);
        }
        else if (first_byte == picoquic_frame_type_ack) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
            bytes = NULL;
        }
        else if (first_byte == picoquic_frame_type_ack_ecn) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
            bytes = NULL;
        }
        else {
            switch (first_byte) {
            case picoquic_frame_type_padding:
                bytes = picoquic_skip_0len_frame(bytes, bytes_max);
                break;
            case picoquic_frame_type_reset_stream:
                bytes = picoquic_decode_reset_stream_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_connection_close:
                bytes = picoquic_decode_connection_close_frame(cnx, bytes, bytes_max);
                ack_needed = 0;
                break;
            case picoquic_frame_type_application_close:
                bytes = picoquic_decode_application_close_frame(cnx, bytes, bytes_max);
                ack_needed = 0;
                break;
            case picoquic_frame_type_max_data:
                bytes = picoquic_decode_max_data_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_max_stream_data:
                bytes = picoquic_decode_max_stream_data_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_max_streams_bidir:
            case picoquic_frame_type_max_streams_unidir:
                bytes = picoquic_decode_max_streams_frame(cnx, bytes, bytes_max, first_byte);
                ack_needed = 1;
                break;
            case picoquic_frame_type_ping:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_data_blocked:
                bytes = picoquic_decode_blocked_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stream_data_blocked:
                bytes = picoquic_decode_stream_blocked_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_streams_blocked_unidir:
            case picoquic_frame_type_streams_blocked_bidir:
                bytes = picoquic_decode_streams_blocked_frame(cnx, bytes, bytes_max, first_byte);
                ack_needed = 1;
                break;
            case picoquic_frame_type_new_connection_id:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_stop_sending:
                bytes = picoquic_decode_stop_sending_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_path_challenge:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_path_response:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_crypto_hs:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_new_token:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_retire_connection_id:
                /* the old code point for ACK frames, but this is taken care of in the ACK tests above */
                bytes = picoquic_decode_retire_connection_id_frame(cnx, bytes, bytes_max, path_x, 0);
                ack_needed = 1;
                break;
            case picoquic_frame_type_handshake_done:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_datagram:
            case picoquic_frame_type_datagram_l:
                /* Datagram carrying packets are acked, but not repeated */
                ack_needed = 1;
                bytes = picoquic_decode_datagram_frame(cnx, path_x, bytes, bytes_max);
                break;
            case picoquic_frame_type_reset_stream_at:
                bytes = picoquic_decode_reset_stream_at_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            default: {
                uint64_t frame_id64;

                if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_id64)) != NULL) {
                    switch (frame_id64) {
                    case picoquic_frame_type_time_stamp:
                        bytes = picoquic_decode_time_stamp_frame(bytes, bytes_max, cnx, &packet_data);
                        break;
                    case picoquic_frame_type_observed_address_v4:
                    case picoquic_frame_type_observed_address_v6:
                        ack_needed = 1;
                        bytes = picoquic_decode_observed_address_frame(cnx, bytes, bytes_max, path_x, frame_id64);
                        break;
                    default:
                        /* Not expected! */
                        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, frame_id64);
                        bytes = NULL;
                        break;
                    }
                }
            }
            }
        }
    }
    return bytes != NULL ? 0 : PICOQUIC_ERROR_DETECTED;
}

int picoqmux_incoming_packet(picoquic_cnx_t* cnx, uint64_t current_time, 
    const uint8_t* receive_buffer, size_t receive_length, uint64_t* next_wake_time)
{
    int ret = 0;
    picoquic_path_t* path_x = cnx->path[0];
    picoquic_stream_data_node_t received_data = { 0 };

    ret = picoqmux_decode_frames(cnx, path_x, receive_buffer,
        receive_length, &received_data, current_time);

    if (ret == 0) {
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_QMUX);
    }
    return ret;
}