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

/* Internal picoquic functions resused here */
uint8_t* picoquic_prepare_stream_and_datagrams(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint8_t* bytes_next, uint8_t* bytes_max,
    int is_first_in_packet, uint64_t max_priority_allowed,
    int* more_data, int* is_pure_ack, int* no_data_to_send, int* ret);


/* QMUX states:
* 
*    picoquic_state_client_init,
*    picoquic_state_server_init,
*    picoquic_state_client_almost_ready,
*    picoquic_state_server_false_start,
*    picoquic_state_server_almost_ready,
*    picoquic_state_client_ready_start,
*    picoquic_state_ready,
*
* Client: 
*   on start: picoquic_state_client_init
*   after sending TP:
*     if TP received: picoquic_state_ready
*     else: picoquic_state_client_ready_start
*   after receiving TP:
*     if TP sent: picoquic_state_ready
*     else: picoquic_state_client_almost_ready
* 
* Server:
*   on start: picoquic_state_server_init
*   after sending TP:
*     if TP received: picoquic_state_ready
*     else: server_almost_ready
*   after receiving TP:
*    if TP sent: picoquic_state_ready
*    else: picoquic_state_server_false_start
* 
* On error:
*    ...
*/
int picoqmux_has_sent_tp(picoquic_cnx_t* cnx)
{
    return (cnx->cnx_state == picoquic_state_ready ||
        cnx->cnx_state == picoquic_state_client_ready_start ||
        cnx->cnx_state == picoquic_state_server_almost_ready);
}

int picoqmux_has_received_tp(picoquic_cnx_t* cnx)
{
    return (cnx->cnx_state == picoquic_state_ready ||
        cnx->cnx_state == picoquic_state_client_almost_ready ||
        cnx->cnx_state == picoquic_state_server_false_start);
}

void picoqmux_update_state_on_tp_sent(picoquic_cnx_t* cnx)
{
    if (cnx->client_mode) {
        if (picoqmux_has_received_tp(cnx)) {
            cnx->cnx_state = picoquic_state_ready;
        }
        else {
            cnx->cnx_state = picoquic_state_client_ready_start;
        }
    }
    else {
        if (picoqmux_has_received_tp(cnx)) {
            cnx->cnx_state = picoquic_state_ready;
        }
        else {
            cnx->cnx_state = picoquic_state_server_almost_ready;
        }
    }
}

void picoqmux_update_state_on_tp_received(picoquic_cnx_t* cnx)
{
    if (cnx->client_mode) {
        if (picoqmux_has_sent_tp(cnx)) {
            cnx->cnx_state = picoquic_state_ready;
        }
        else {
            cnx->cnx_state = picoquic_state_client_almost_ready;
        }
    }
    else {
        if (picoqmux_has_sent_tp(cnx)) {
            cnx->cnx_state = picoquic_state_ready;
        }
        else {
            cnx->cnx_state = picoquic_state_server_false_start;
        }
    }
}


/*
* QX_TRANSPORT_PARAMETERS frames are formatted as shown in Figure 2.
* 
* QX_TRANSPORT_PARAMETERS Frame {
*    Type (i) = 0x3f5153300d0a0d0a,
*    Length (i),
*    Transport Parameters (..),
* }
*
* In QMux, use of the following transport parameters is allowed.
*   max_idle_timeout
*   initial_max_data
*   initial_max_stream_data_bidi_local
*   initial_max_stream_data_bidi_remote
*   initial_max_stream_data_uni
*   initial_max_streams_bidi
*   initial_max_streams_uni
* Other parameters MAY be supported later.
* 
* The parameters MAY be received in any order, i.e., client first or server first.
* 
* The endpoints MUST send their TP as their first frame.
* They MUST NOT send other frames before receiving the peer's TP,
* except as part of 0 RTT data, if they remember the previous TP value.
* 
* The max_record_size transport parameter (0x0571c59429cd0845) is a
* variable-length integer specifying the maximum value of the Size
* field of a QMux Record that the peer can send, in the unit of bytes.
* The initial value of the max_record_size transport parameter is 16382.
* (and cannot be negotiated down).
*/

uint8_t* picoquic_format_qmux_tp_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max)
{
    if (bytes + 0x4000 >= bytes_max) {
        bytes_max = bytes + 0x3FFF;
    }

    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, FRAME_TYPE_QX_TRANSPORT_PARAMETERS)) == NULL ||
        bytes + 2  >= bytes_max) {
        bytes = NULL;
    }
    else {
        size_t consumed = 0;
        uint8_t* bytes_l = bytes;
        bytes += 2; /* reserve two bytes for length */

        /* Encode the transport parameters. 
        * Setting extension_mode = 2 ensures that only parameters adequate
        * for QMux will be sent.
        */
        if (picoquic_prepare_transport_extensions(cnx, 2, bytes, bytes_max - bytes, &consumed) != 0) {
            bytes = NULL;
        }
        else {
            /* set the bytes pointer to the right position */
            bytes += consumed;
            /* encode the length as 2 bytes varint */
            bytes_l[0] = (uint8_t)(consumed >> 8) | 0x40;
            bytes_l[1] = (uint8_t)(consumed & 0xFF);
        }
    }
    return bytes;
}

const uint8_t* picoquic_decode_qmux_tp_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, const uint8_t* bytes_max)
{
    /* this code assumes that the frame type has been decoded. */
    size_t length = 0;
    bytes = picoquic_frames_varlen_decode(bytes, bytes_max, &length);
    if (bytes == NULL || bytes + length > bytes_max) {
        bytes = NULL;
    }
    else {
        /* decode the transport parameters.
        * Setting extension_mode = 2 ensures that only parameters adequate
        * for QMux will be accepted.
         */
        size_t consumed = 0;
        if (picoquic_receive_transport_extensions(cnx, 2, (uint8_t*)bytes, length, &consumed) != 0 ||
            consumed != length) {
            bytes = NULL;
        }
        else {
            bytes += length;
        }
    }
    return bytes;
}

/* QMux ack: automatic acknowledgement of packets
* that was just sent. */

void picoqmux_auto_ack(picoquic_cnx_t* cnx, uint8_t * packet, size_t length, uint64_t current_time)
{
    int ret = 0;
    size_t byte_index = 0;
    int frame_is_pure_ack = 0;
    size_t frame_length = 0;

    cnx->path[0]->last_time_acked_data_frame_sent = current_time;

    while (ret == 0 && byte_index < length) {
        uint64_t ftype;
        size_t l_ftype = picoquic_varint_decode(&packet[byte_index], length - byte_index, &ftype);
        if (l_ftype == 0) {
            break;
        }

        switch (ftype) {
        case picoquic_frame_type_max_data:
            ret = picoquic_process_ack_of_max_data_frame(cnx, &packet[byte_index], length - byte_index, &frame_length);
            byte_index += frame_length;
            break;
        case picoquic_frame_type_max_stream_data:
            ret = picoquic_process_ack_of_max_stream_data_frame(cnx, &packet[byte_index], length - byte_index, &frame_length);
            byte_index += frame_length;
            break;
        case picoquic_frame_type_max_streams_bidir:
        case picoquic_frame_type_max_streams_unidir:
            ret = picoquic_process_ack_of_max_streams_frame(cnx, &packet[byte_index], length - byte_index, &frame_length);
            byte_index += frame_length;
            break;
        case picoquic_frame_type_reset_stream:
            ret = picoquic_process_ack_of_reset_stream_frame(cnx, &packet[byte_index], length - byte_index, &frame_length);
            byte_index += frame_length;
            break;
        case picoquic_frame_type_paths_blocked:
            ret = picoquic_process_ack_of_paths_blocked_frame(cnx, &packet[byte_index], length - byte_index, &frame_length);
            byte_index += frame_length;
            break;
        case picoquic_frame_type_path_cid_blocked:
            ret = picoquic_process_ack_of_path_cid_blocked_frame(cnx, &packet[byte_index], length - byte_index, &frame_length);
            byte_index += frame_length;
            break;
        case picoquic_frame_type_observed_address_v4:
        case picoquic_frame_type_observed_address_v6:
            ret = picoquic_process_ack_of_observed_address_frame(cnx->path[0], &packet[byte_index], length - byte_index, ftype, &frame_length);
            byte_index += frame_length;
            break;
        default:
            if (PICOQUIC_IN_RANGE(ftype, picoquic_frame_type_datagram, picoquic_frame_type_datagram_l)) {
                if (cnx->callback_fn != NULL) {
                    uint8_t frame_id;
                    uint64_t content_length;
                    uint8_t* content_bytes;

                    /* Parse and skip type and length */
                    content_bytes = picoquic_decode_datagram_frame_header(&packet[byte_index], &packet[length],
                        &frame_id, &content_length);

                    ret = (cnx->callback_fn)(cnx, current_time, content_bytes, (size_t)content_length,
                        picoquic_callback_datagram_acked, cnx->callback_ctx, NULL);
                }
            }

            ret = picoquic_skip_frame(&packet[byte_index],
                length - byte_index, &frame_length, &frame_is_pure_ack);
            byte_index += frame_length;
        }
        break;
    }
}

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

    /* If not yet sent, send the transport parameters */
    if (!picoqmux_has_sent_tp(cnx)) {
        bytes_next = picoquic_format_qmux_tp_frame(cnx, bytes_next, bytes_max);
        if (bytes_next == NULL) {
            ret = -1;
        }
        else {
            picoqmux_update_state_on_tp_sent(cnx);
        }
    }
                
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

    /* consider packets acked! */
    picoqmux_auto_ack(cnx, send_buffer, length, current_time);

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
    picoquic_packet_data_t packet_data;

    memset(&packet_data, 0, sizeof(packet_data));

    if (!picoqmux_has_received_tp(cnx)) {
        /* the first frame must be the transport parameters */
        uint64_t frame_id64;

        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_id64)) == NULL ||
            frame_id64 != FRAME_TYPE_QX_TRANSPORT_PARAMETERS) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, bytes == NULL ? 0 : (uint8_t)frame_id64);
            return -1;
        } else {
            bytes = picoquic_decode_qmux_tp_frame(cnx, bytes, bytes_max);
            if (bytes == NULL) {
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, 0x3f);
                return -1;
            }
            else {
                picoqmux_update_state_on_tp_received(cnx);
            }
        }
    }

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
                break;
            case picoquic_frame_type_connection_close:
                bytes = picoquic_decode_connection_close_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_application_close:
                bytes = picoquic_decode_application_close_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_max_data:
                bytes = picoquic_decode_max_data_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_max_stream_data:
                bytes = picoquic_decode_max_stream_data_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_max_streams_bidir:
            case picoquic_frame_type_max_streams_unidir:
                bytes = picoquic_decode_max_streams_frame(cnx, bytes, bytes_max, first_byte);
                break;
            case picoquic_frame_type_ping:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_data_blocked:
                bytes = picoquic_decode_blocked_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_stream_data_blocked:
                bytes = picoquic_decode_stream_blocked_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_streams_blocked_unidir:
            case picoquic_frame_type_streams_blocked_bidir:
                bytes = picoquic_decode_streams_blocked_frame(cnx, bytes, bytes_max, first_byte);
                break;
            case picoquic_frame_type_new_connection_id:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_stop_sending:
                bytes = picoquic_decode_stop_sending_frame(cnx, bytes, bytes_max);
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
                break;
            case picoquic_frame_type_handshake_done:
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            case picoquic_frame_type_datagram:
            case picoquic_frame_type_datagram_l:
                bytes = picoquic_decode_datagram_frame(cnx, path_x, bytes, bytes_max);
                break;
            case picoquic_frame_type_reset_stream_at:
                bytes = picoquic_decode_reset_stream_at_frame(cnx, bytes, bytes_max);
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
