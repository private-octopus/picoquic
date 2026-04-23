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
#include <picotls.h>
#include "picoquic_crypto_provider_api.h"
#include <stdlib.h>
#include <string.h>

/* Internal picoquic functions resused here */
uint8_t* picoquic_prepare_stream_and_datagrams(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint8_t* bytes_next, uint8_t* bytes_max,
    int is_first_in_packet, uint64_t max_priority_allowed,
    int* more_data, int* is_pure_ack, int* no_data_to_send, int* ret);


/* QMUX starting states:
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
*         callback ready.
*     else: picoquic_state_client_ready_start
*         callback almost ready.
*   after receiving TP:
*     if TP sent: picoquic_state_ready
*         callback ready.
*     else: picoquic_state_client_almost_ready
* 
* Server:
*   on start: picoquic_state_server_init
*   after sending TP:
*     if TP received: picoquic_state_ready
*         callback ready.
*     else: server_almost_ready
*   after receiving TP:
*    if TP sent: picoquic_state_ready
*         callback ready.
*    else: picoquic_state_server_false_start
*         callback almost ready.
* 
* On error:
*    ...
*/

void picoqmux_init(picoquic_cnx_t* cnx, int is_cleartext)
{
    cnx->is_qmux = 1;
    cnx->is_qmux_cleartext = is_cleartext;
    cnx->qx_acked_last = UINT64_MAX;
    cnx->qx_sent_last = UINT64_MAX;
    cnx->qx_query_ack = UINT64_MAX;
    cnx->qx_query_last = UINT64_MAX;
}

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

void picoqmux_update_state_to_ready(picoquic_cnx_t* cnx)
{

    cnx->cnx_state = picoquic_state_ready;
    if (cnx->callback_fn != NULL &&
        cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_ready, cnx->callback_ctx, NULL) != 0) {
        picoquic_log_app_message(cnx, "Callback ready returns error 0x%x", PICOQUIC_TRANSPORT_INTERNAL_ERROR);
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
    }
}

void picoqmux_update_state_on_tp_sent(picoquic_cnx_t* cnx)
{
    if (cnx->cnx_state < picoquic_state_ready) {
        if (picoqmux_has_received_tp(cnx)) {
            picoqmux_update_state_to_ready(cnx);
        }
        else
        {
            if (cnx->client_mode) {
                cnx->cnx_state = picoquic_state_client_ready_start;
            }
            else {
                cnx->cnx_state = picoquic_state_server_almost_ready;
            }
            if (cnx->callback_fn != NULL && 
                cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_almost_ready, cnx->callback_ctx, NULL) != 0) {
                picoquic_log_app_message(cnx, "Callback almost ready returns error 0x%x", PICOQUIC_TRANSPORT_INTERNAL_ERROR);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
            }
        }
    }
}

void picoqmux_update_state_on_tp_received(picoquic_cnx_t* cnx)
{
    if (picoqmux_has_sent_tp(cnx)) {
        picoqmux_update_state_to_ready(cnx);
    }
    else if (cnx->client_mode) {
        cnx->cnx_state = picoquic_state_client_almost_ready;
    }
    else {
        cnx->cnx_state = picoquic_state_server_false_start;
    }
}

/*
* QMUX closing is different from the quic logic:
* 
* As is with QUIC version 1, a connection can be closed either
* by a CONNECTION_CLOSE frame or by an idle timeout.
*
* Unlike QUIC version 1, idle timeout handling does not rely on ACK frames.
* Endpoints reset the idle timer when sending or receiving QMux frames.
* When no other traffic is available, QX_PING frames can be used to elicit
* a peer response and keep the connection active.
*
* Unlike QUIC version 1, there is no draining period; once an endpoint sends
* or receives the CONNECTION_CLOSE frame or reaches the idle timeout,
* all the resources allocated for the Service are freed and the underlying
* transport is closed immediately.
* 
* The callback "picoquic_callback_close" and 
* "picoquic_callback_application_close" are set just like QUIC (?)
* 
* In the "send" process, the closing logic is executed if the state
* is either "picoquic_state_handshake_failure" or greater
* than "picoquic_ready".
* 
* The current picoquic logic changes the state as follow:
* 
* - if a local decision to close is made, set the state to
*   picoquic_state_handshake_failure or picoquic_state_disconnecting
* - if a close connection frame is received, set the state to
*   picoquic_state_disconnected or picoquic_state_closing_received
* 
* We will treat the state picoquic_state_closing_received as equivalent
* to disconnected.
* 
* Formatting a close connection frame does not change the state in the
* current code. In Qmux, this will trigger a change to disconnected.
* 
* If the connection is in disconnected phase, we want the close
* packet to be queued. That is, defer the socket closure until the
* last formated packet is sent.
* 
* The current picoquic code handles the timer based only on the value
* of current time, last received time, and PTO. Instead, we will
* handle that based on current time, last sent time, and PTO, with
* probably a special case for the disconnected state.
*/

void picoqmux_send_closing(picoquic_cnx_t * cnx, uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    if (cnx->cnx_state == picoquic_state_handshake_failure ||
        cnx->cnx_state == picoquic_state_disconnecting) {
        /* format the close connection or app connection frame */
        uint8_t* bytes_next = send_buffer;
        int more_data = 0;
        int is_pure_ack = 1;
        if (cnx->local_error == 0) {
            bytes_next = picoquic_format_application_close_frame(cnx, bytes_next, bytes_next + send_buffer_max, &more_data, &is_pure_ack);
        }
        else {
            bytes_next = picoquic_format_connection_close_frame(cnx, bytes_next, bytes_next + send_buffer_max, &more_data, &is_pure_ack);
        }
        if (bytes_next > send_buffer) {
            *send_length = bytes_next - send_buffer;
            cnx->cnx_state = picoquic_state_disconnected;
        }
        else {
            /* do not change the state, since the frame was not sent. */
            *send_length = 0;
        }
        /* reset the wakeup timer to immediate, to either send the frame at
        * the next opportunity or close the socket.
        */
        cnx->next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_QMUX);
    }
}

void picoqmux_check_idle_timer(picoquic_cnx_t* cnx, uint64_t current_time, 
    uint64_t* next_wake_time)
{
    /* if already disconnected, nothing to do. */
    if (cnx->cnx_state == picoquic_state_disconnected ||
        cnx->cnx_state == picoquic_state_closing_received) {
        /* Nothing to do, should close the socket. */
        cnx->cnx_state = picoquic_state_disconnected;
    }
    else if (cnx->idle_timeout > 0){
        uint64_t idle_timer = cnx->latest_progress_time + cnx->idle_timeout;
        if (current_time >= idle_timer) {
            /* Too long silence, break it. */
            if (cnx->cnx_state != picoquic_state_handshake_failure &&
                cnx->cnx_state <= picoquic_state_ready) {
                cnx->local_error = PICOQUIC_ERROR_IDLE_TIMEOUT;
                cnx->cnx_state = picoquic_state_disconnecting;
            }
        }
        else {
            *next_wake_time = idle_timer;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_QMUX);
        }
    }
}

/* Update statistics after QX_PING response received
* 
* The path quality is copied from the path context:
*   quality->cwin = path_x->cwin;
*   quality->rtt = path_x->smoothed_rtt;
*   quality->rtt_sample = path_x->rtt_sample;
*   quality->rtt_min = path_x->rtt_min;
*   quality->rtt_max = path_x->rtt_max;
*   quality->rtt_variant = path_x->rtt_variant;
*   quality->pacing_rate = path_x->pacing.rate;
*   quality->receive_rate_estimate = path_x->receive_rate_estimate;
*   quality->sent = picoquic_get_sequence_number(path_x->cnx, path_x, picoquic_packet_context_application);
*   quality->lost = path_x->nb_losses_found;
*   quality->timer_losses = path_x->nb_timer_losses;
*   quality->spurious_losses = path_x->nb_spurious;
*   quality->max_spurious_rtt = path_x->max_spurious_rtt;
*   quality->max_reorder_delay = path_x->max_reorder_delay;
*   quality->max_reorder_gap = path_x->max_reorder_gap;
*   quality->bytes_in_transit = path_x->bytes_in_transit;
*   quality->bytes_sent = path_x->bytes_sent;
*   quality->bytes_received = path_x->received;
*
* We want compatibilty between QMux and QUIC, which requires updating
* the "path" variables when QMux is received:
* - get the RTT sample from the ping delay, and update accordingly.
* - update the sequence number in the path context after sending packets
* - keep loss, spurious, reorder = 0
* - estimate bytes in transit from delta between sent before ping, sent after ACK
* - update the byte sent variable per path
* - update the bytes received per path
* - estimate receive rate and send rate from measurement
*/

#if 0
/*
* On update, check whether an "updated" callback is required.
*/
void picoqmux_update_stats_after_qx(picoquic_cnx_t * cnx, uint64_t current_time)
{
    /* Compute the delta t between sent and acked,
     * use it to update RTT estimate. 
     */
    uint64_t rtt_sample = current_time - cnx->qx_time_sent;
    /* Compute the delta and the volume acked between
     * this and the previous stamp.
     */
}
#endif

/* Create a QUIC context parameterized for Qmux */
picoquic_quic_t* picoqmux_create(uint32_t max_nb_connections,
    char const* cert_file_name,
    char const* key_file_name,
    char const* cert_root_file_name,
    char const* default_alpn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    picoquic_connection_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_ctx,
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    uint64_t current_time,
    uint64_t* p_simulated_time,
    char const* ticket_file_name,
    const uint8_t* ticket_encryption_key,
    size_t ticket_encryption_key_length)
{
    /* TODO: reusing the whole creation process is a bit wasteful,
    * as it entails creating several hash tables that are not useful for Qmux.
    * Having specialized code would avoid that.
     */
    picoquic_quic_t* quic = picoquic_create(
        max_nb_connections, cert_file_name, key_file_name, cert_root_file_name,
        default_alpn, default_callback_fn, default_callback_ctx,
        cnx_id_callback, cnx_id_callback_ctx,
        reset_seed, current_time, p_simulated_time,
        ticket_file_name, ticket_encryption_key, ticket_encryption_key_length);

    if (quic != NULL) {
        /* remove the callbacks that would interfere with QMux processing. */
        ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
        /* ctx->on_client_hello? */
        /* setting ctx->update_traffic_key is necessary for QUIC,
         * but interferes with plain TLS key management. */
        if (ctx->update_traffic_key != NULL) {
            free(ctx->update_traffic_key);
            ctx->update_traffic_key = NULL;
        }
    }
    return quic;
}

/* QX PING frames come in to variations:
* FRAME_TYPE_QX_PING, FRAME_TYPE_QX_PING_R
 */
const uint8_t* picoquic_skip_qx_ping_frame(const uint8_t* bytes, const uint8_t* bytes_max)
{
    /* This code assumes that the frame type is already skipped */
    bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    return bytes;
}

const uint8_t* picoquic_parse_qx_ping_frame(const uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t* sequence)
{
    bytes = picoquic_frames_varint_decode(bytes, bytes_max, sequence);
    return bytes;
}

const uint8_t* picoquic_decode_qx_ping_frame(picoquic_cnx_t* cnx,
    const uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t frame_type, uint64_t UNUSED(current_time))
{
    uint64_t sequence = 0;

    /* This code assumes that the frame type is already skipped */
    if (!cnx->is_qmux) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
            picoquic_frame_type_time_stamp);
        bytes = NULL;
    }
    else if ((bytes = picoquic_parse_qx_ping_frame(bytes, bytes_max, &sequence)) != NULL) {
        if ((frame_type & 1) != 0) {
            /* receiving a query */
            int64_t delta = sequence - cnx->qx_query_last;
            if (delta <= 0) {
                /* Not in order */
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
                    frame_type);
                bytes = NULL;
            }
            else {
                cnx->qx_query_last = sequence;
            }
        }
        else {
            /* receiving a QX response */
            int64_t delta = sequence - cnx->qx_sent_last;
            if (delta > 0) {
                /* Not in order */
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
                    frame_type);
                bytes = NULL;
            }
            else if (delta == 0) {
#if 0
                /* TO: proper handling of QOS statistics. */
                picoqmux_update_stats_after_qx(current_time);
#endif
                cnx->qx_acked_last = sequence;
            }
        }
    }
    return bytes;
}

uint8_t* picoquic_format_qx_ping_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int is_response, int* more_data)
{
    uint8_t* bytes0 = bytes;
    uint64_t sequence = (is_response) ? cnx->qx_query_last : cnx->qx_sent_last;

    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max,
        (is_response)? FRAME_TYPE_QX_PING_R: FRAME_TYPE_QX_PING)) == NULL ||
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, sequence)) == NULL) {
        bytes = bytes0;
        *more_data = 1;
    }

    return bytes;
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
int picoqmux_prepare_cnx_packet(picoquic_cnx_t* cnx, uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
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


    if (cnx->cnx_state == picoquic_state_handshake_failure ||
        cnx->cnx_state > picoquic_state_ready) {
        picoqmux_send_closing(cnx, current_time, send_buffer, send_buffer_max, send_length);
        return ret;
    }

    /* If not yet sent, send the transport parameters */
    else if (!picoqmux_has_sent_tp(cnx)) {
        bytes_next = picoquic_format_qmux_tp_frame(cnx, bytes_next, bytes_max);
        if (bytes_next == NULL) {
            ret = -1;
        }
        else {
            picoqmux_update_state_on_tp_sent(cnx);
        }
    }

    /* if necessary, prepare the QX_PING_R frame */
    if (ret == 0 && cnx->qx_query_last != cnx->qx_query_ack && bytes + 16 < bytes_max) {
        bytes_next = picoquic_format_qx_ping_frame(cnx, bytes, bytes_max, 1, &more_data);
        cnx->qx_query_ack = cnx->qx_query_last;
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
            path_x, path_x->first_tuple, current_time, &cnx->next_wake_time, &more_data, &is_pure_ack);
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
        cnx->next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        ret = 0;
    }
    /* Set sent length */
    *send_length = length;

    /* consider packets acked! */
    picoqmux_auto_ack(cnx, send_buffer, length, current_time);

    return ret;
}

/* Prepare the next packets to send in the current buffer 
* This called directly by the socket loop when the connection
* is marked "active". If there is nothing to send, return
* sendlength = 0. If the socket should be closed, return -1.
*/

int picoqmux_prepare_cnx_packets(picoquic_cnx_t * cnx, uint64_t current_time, uint8_t* send_buffer,
    size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    uint64_t next_wake_time = UINT64_MAX;
    *send_length = 0;


    if (cnx->cnx_state == picoquic_state_disconnected) {
        /* We check the disconnect state before sending a packet. This
        * implies that the previous packet has been sent.
        */
        ret = PICOQUIC_ERROR_DISCONNECTED;
    }
    else {
        picoqmux_check_idle_timer(cnx, current_time, &next_wake_time);
        for (;;) {
            uint8_t* bytes = send_buffer + *send_length;
            size_t max_length = send_buffer_max - *send_length;
            size_t length = 0;
            if (max_length < 255) {
                next_wake_time = current_time;
                break;
            }
            else {
                ret = picoqmux_prepare_cnx_packet(cnx, current_time, bytes, max_length, &length);
                if (ret < 0) {
                    break;
                }
                else if (length == 0) {
                    /* Nothing more to send. */
                    break;
                }
                else {
                    *send_length += length;
                }
            }
        }
    }
    return ret;
}

/*
 * Processing of the incoming QMUX packet.
 */

int picoqmux_decode_frames(picoquic_cnx_t* cnx, picoquic_path_t* path_x, const uint8_t* bytes,
    size_t bytes_maxsize, int64_t current_time)
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
            bytes = picoquic_decode_stream_frame(cnx, bytes, bytes_max, NULL, current_time);
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
                    case FRAME_TYPE_QX_PING:
                    case FRAME_TYPE_QX_PING_R:
                        bytes = picoquic_decode_qx_ping_frame(cnx, bytes, bytes_max, frame_id64, current_time);
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

int picoqmux_incoming_cnx_packet(picoquic_cnx_t* cnx, uint64_t current_time, 
    const uint8_t* receive_buffer, size_t receive_length)
{
    int ret = 0;
    picoquic_path_t* path_x = cnx->path[0];

    ret = picoqmux_decode_frames(cnx, path_x, receive_buffer, receive_length, current_time);

    if (ret == 0) {
        cnx->latest_progress_time = current_time;
        cnx->next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_QMUX);
    }
    return ret;
}

/* Handling of TLS */
int picoqmux_send_handshake(picoquic_cnx_t* cnx, uint8_t* send_buffer,
    size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;

    if (tls_ctx->tls_wbuf.off > 0) {
        if (tls_ctx->tls_wbuf.off > send_buffer_max) {
            /*oops, not good. */
            ret = -1;
        }
        else
        {
            memcpy(send_buffer, tls_ctx->tls_wbuf.base, tls_ctx->tls_wbuf.off);
            *send_length = tls_ctx->tls_wbuf.off;
            tls_ctx->tls_wbuf.off = 0;
        }
    }
    cnx->is_qmux_tls_ready = ptls_handshake_is_complete(tls_ctx->tls);
    return ret;
}

int picoqmux_send_data(picoquic_cnx_t* cnx, uint64_t current_time, uint8_t* send_buffer,
    size_t send_buffer_max, size_t* send_length)
{
#define TLS_DATA_OVERHEAD 32
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    /* Prepare just enough data to fill the send buffer */
    size_t max_data = (send_buffer_max - TLS_DATA_OVERHEAD > 0x4000) ?
        0x4000 : send_buffer_max - TLS_DATA_OVERHEAD;
    uint8_t p_buffer[0x4000];
    size_t p_length = 0;
    int ret = picoqmux_prepare_cnx_packets(cnx, current_time, p_buffer, max_data, &p_length);
    if (ret == 0) {
        ptls_buffer_t s_buf;
        ptls_buffer_init(&s_buf, send_buffer, send_buffer_max);
        ret = ptls_send(tls_ctx->tls, &s_buf, p_buffer, p_length);
        if (ret == 0) {
            *send_length = s_buf.off;
        }
    }
    return ret;
}

int picoqmux_incoming_data(picoquic_cnx_t* cnx, uint64_t current_time,
    const uint8_t* incoming, size_t incoming_length, size_t * consumed)
{
    int ret = 0;
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    size_t in_len = incoming_length;

    ret = ptls_receive(tls_ctx->tls, &tls_ctx->tls_rbuf, incoming, &in_len);

    if (ret == 0) {
        *consumed = in_len;
        if (tls_ctx->tls_rbuf.off > 0) {
            ret = picoqmux_incoming_cnx_packet(cnx, current_time,
                tls_ctx->tls_rbuf.base, tls_ctx->tls_rbuf.off);
            tls_ctx->tls_rbuf.off = 0;
        }
    }

    return ret;
}

int picoqmux_incoming_handshake(picoquic_cnx_t* cnx,
    const uint8_t* receive_buffer, size_t receive_length, size_t* consumed)
{
    int ret = 0;
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;

    *consumed = receive_length;

    ret = ptls_handshake(tls_ctx->tls, &tls_ctx->tls_wbuf,
        receive_buffer, consumed, &tls_ctx->handshake_properties);

    if (ret == 0) {
        if (tls_ctx->tls_wbuf.off == 0) {
            cnx->is_qmux_tls_ready = ptls_handshake_is_complete(tls_ctx->tls);
        }
    }
    else if (ret == PTLS_ERROR_IN_PROGRESS) {
        ret = 0;
    }

    return ret;
}

int picoqmux_start_client_cnx(picoquic_cnx_t* cnx)
{
    int ret = 0;
    size_t consumed = 0;
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    if (cnx->cnx_state != picoquic_state_client_init ||
        cnx->tls_stream[0].sent_offset > 0 ||
        cnx->tls_stream[0].send_queue != NULL) {
        DBG_PRINTF("%s", "picoqmux_start_client_cnx called twice.");
        return -1;
    }

    if (cnx->sni != NULL) {
        ptls_set_server_name(tls_ctx->tls, cnx->sni, strlen(cnx->sni));
    }

    if (cnx->alpn != NULL) {
        tls_ctx->alpn_vec[0].base = (uint8_t*)cnx->alpn;
        tls_ctx->alpn_vec[0].len = strlen(cnx->alpn);
        tls_ctx->handshake_properties.client.negotiated_protocols.count = 1;
        tls_ctx->handshake_properties.client.negotiated_protocols.list = tls_ctx->alpn_vec;
    }
    else if (cnx->callback_fn != NULL) {
        /* Get the default ALPN list for the callback function */
        ret = cnx->callback_fn(cnx, 0, (uint8_t*)tls_ctx, 0, picoquic_callback_request_alpn_list, cnx->callback_ctx, NULL);

        tls_ctx->handshake_properties.client.negotiated_protocols.count = tls_ctx->alpn_count;
        tls_ctx->handshake_properties.client.negotiated_protocols.list = tls_ctx->alpn_vec;

        if (ret != 0) {
            DBG_PRINTF("ALPN list callback returns 0x%x", ret);
        }
    }

    picoquic_log_new_connection(cnx);

    /* A remote session ticket may have been loaded as part of initializing TLS,
     * and remote parameters may have been initialized to the initial value
     * of the previous session. Apply these new parameters. */
    cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
    cnx->max_stream_id_bidir_remote =
        STREAM_ID_FROM_RANK(cnx->remote_parameters.initial_max_stream_id_bidir, cnx->client_mode, 0);
    cnx->max_stream_id_unidir_remote =
        STREAM_ID_FROM_RANK(cnx->remote_parameters.initial_max_stream_id_unidir, cnx->client_mode, 1);
    cnx->max_stream_data_remote = cnx->remote_parameters.initial_max_data;
    cnx->max_stream_data_local = cnx->local_parameters.initial_max_stream_data_bidi_local;

    ptls_buffer_init(&tls_ctx->tls_wbuf, "", 0);
    ptls_buffer_init(&tls_ctx->tls_rbuf, "", 0);

    ret = picoqmux_incoming_handshake(cnx, NULL, 0, &consumed);

    return ret;
}

int picoqmux_init_server_cnx(picoquic_cnx_t* cnx)
{
    int ret = 0;
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    ptls_buffer_init(&tls_ctx->tls_wbuf, "", 0);
    ptls_buffer_init(&tls_ctx->tls_rbuf, "", 0);

    return ret;
}

/* Creation of a basic connection
 */

picoquic_cnx_t* picoqmux_create_qmux_cnx(picoquic_quic_t* quic, uint64_t current_time,
    int client_mode, int is_cleartext, char const* server, char const* alpn)
{
    picoquic_cnx_t* cnx = picoquic_create_cnx(quic,
        picoquic_null_connection_id,
        picoquic_null_connection_id,
        NULL, current_time,
        0, server, alpn, (char)client_mode);

    /* TODO: may need to create the connection in a different way than QUIC,
    * e.g., not using the QUIC extension. */
    if (cnx != NULL) {
        picoqmux_init(cnx, is_cleartext);
        if ((client_mode &&
            picoqmux_start_client_cnx(cnx) != 0) ||
            (!client_mode &&
                picoqmux_init_server_cnx(cnx) != 0)) {
            /* Cannot just do partial initialization! */
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }
    return cnx;
}

int picoqmux_prepare_packets(picoquic_cnx_t* cnx, uint64_t current_time, uint8_t* send_buffer,
    size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;

    /* Consider moving the timer protection here */
    if (cnx->is_qmux_cleartext) {
        ret = picoqmux_prepare_cnx_packets(cnx, current_time, send_buffer, send_buffer_max, send_length);
    }
    else if (cnx->is_qmux_tls_ready) {
        /* TLS is negotiated: prepare and encrypt packets */
        ret = picoqmux_send_data(cnx, current_time, send_buffer,
            send_buffer_max, send_length);
    }
    else {
        /* Perform the handshake */
        ret = picoqmux_send_handshake(cnx, send_buffer, send_buffer_max, send_length);
    }
    if (ret == 0) {
        if (*send_length > 0) {
            /* something sent. Notice progress. */
            cnx->latest_progress_time = current_time;
            cnx->next_wake_time = current_time;
        }
        else if (cnx->idle_timeout > 0) {
            cnx->next_wake_time = cnx->latest_progress_time + cnx->idle_timeout;
        }
        else {
            cnx->next_wake_time = UINT64_MAX;
        }
    }
    return ret;
}

int picoqmux_incoming_packets(picoquic_cnx_t* cnx, uint64_t current_time,
    const uint8_t* receive_buffer, size_t receive_length)
{
    int ret = 0;

    if (cnx->is_qmux_cleartext) {
        picoqmux_incoming_cnx_packet(cnx, current_time, receive_buffer, receive_length);
    }
    else
    {
        /* we can have here a concatenation of encrypted packets */
        while (ret == 0 && receive_length > 0) {
            size_t consumed = 0;
            if (cnx->is_qmux_tls_ready) {
                /* TLS is negotiated: receive data packets packets */
                ret = picoqmux_incoming_data(cnx, current_time, receive_buffer, receive_length, &consumed);
            }
            else {
                /* Perform the handshake */
                ret = picoqmux_incoming_handshake(cnx, receive_buffer, receive_length,
                    &consumed);
            }
            if (ret == 0) {
                if (consumed >= receive_length) {
                    receive_length = 0;
                }
                else {
                    receive_buffer += consumed;
                    receive_length -= consumed;
                }
            }
        }
    }

    if (ret == 0) {
        /* something received. Notice progress. */
        cnx->latest_progress_time = current_time;
        cnx->next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_QMUX);
    }

    return ret;
}
