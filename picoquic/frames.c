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

/* Decoding of the various frames, and application to context */
#include <stdlib.h>
#include <string.h>
#include "picoquic_internal.h"
#include "tls_api.h"

static const size_t challenge_length = 8;

picoquic_stream_head_t* picoquic_create_missing_streams(picoquic_cnx_t* cnx, uint64_t stream_id, int is_remote)
{
    /* Verify the stream ID control conditions */
    picoquic_stream_head_t* stream = NULL;
    unsigned int expect_client_stream = cnx->client_mode ^ is_remote;

    if (is_remote && stream_id < cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]) {
        return NULL;
    } else if (IS_CLIENT_STREAM_ID(stream_id) != expect_client_stream){
        /* TODO: not an error if lower than next stream, would be just an old stream. */
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR, 0);
    }
    else if (is_remote && stream_id > (IS_BIDIR_STREAM_ID(stream_id) ? cnx->max_stream_id_bidir_local : cnx->max_stream_id_unidir_local)){
        /* Protocol error, stream ID too high */
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR, 0);
    } 
    else if (stream_id < cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]) {
        /* Protocol error, stream already closed */
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_STATE_ERROR, 0);
    } else {
        while (stream_id >= cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]) {
            stream = picoquic_create_stream(cnx, cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]);
            if (stream == NULL) {
                picoquic_log_app_message(cnx, "Create stream %" PRIu64 " returns error 0x%x",
                    stream_id, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
                break;
            }
            else if (!IS_BIDIR_STREAM_ID(stream_id)) {
                if (!IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
                    /* Mark the stream as already finished in our direction */
                    stream->fin_requested = 1;
                    stream->fin_sent = 1;
                }
            }
        }
    }

    return stream;
}

int picoquic_is_stream_closed(picoquic_stream_head_t* stream, int client_mode)
{
    int is_closed = 0;

    if (!stream->is_output_stream) {
        if (IS_BIDIR_STREAM_ID(stream->stream_id)) {
            is_closed = ((stream->fin_requested && stream->fin_sent) || (stream->reset_requested && stream->reset_sent)) &&
                ((stream->fin_received && stream->fin_signalled) || (stream->reset_received && stream->reset_signalled));
        }
        else if (IS_LOCAL_STREAM_ID(stream->stream_id, client_mode)) {
            /* Unidir from local host*/
            is_closed = ((stream->fin_requested && stream->fin_sent) || (stream->reset_requested && stream->reset_sent));
        }
        else {
            is_closed = ((stream->fin_received && stream->fin_signalled) || (stream->reset_received && stream->reset_signalled));
        }
    }

    return is_closed;
}

int picoquic_is_stream_acked(picoquic_stream_head_t* stream)
{
    int is_acked = 0;

    if (stream->is_closed) {
        if (stream->reset_sent) {
            is_acked = 1;
        }
        else {
            /* Check whether the ack was already received */
            is_acked = picoquic_check_sack_list(&stream->first_sack_item, 0, stream->sent_offset);
        }
    }

    return is_acked;
}

int picoquic_delete_stream_if_closed(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    int ret = 0;

    if (!stream->is_closed && picoquic_is_stream_closed(stream, cnx->client_mode)) {
        picoquic_update_max_stream_ID_local(cnx, stream);
        stream->is_closed = 1;
        ret = 1;
    }
    
    /* We only delete the stream if there are no pending retransmissions */
    if (stream->is_closed && picoquic_is_stream_acked(stream)) {
        picoquic_delete_stream(cnx, stream);
    }

    return ret;
}

/* if the initial remote has changed, update the existing streams.
 * By definition, this is only needed for streams locally created for 0-RTT traffic.
 */

void picoquic_update_stream_initial_remote(picoquic_cnx_t* cnx)
{
    picoquic_stream_head_t* stream = picoquic_first_stream(cnx);

    while (stream) {
        if (IS_LOCAL_STREAM_ID(stream->stream_id, cnx->client_mode)) {
            if (IS_BIDIR_STREAM_ID(stream->stream_id)) {
                if (stream->maxdata_remote < cnx->remote_parameters.initial_max_stream_data_bidi_remote) {
                    stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_remote;
                }
            }
            else {
                if (stream->maxdata_remote < cnx->remote_parameters.initial_max_stream_data_uni) {
                    stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_uni;
                }
            }
        }
        else if (IS_BIDIR_STREAM_ID(stream->stream_id)) {
            if (stream->maxdata_remote < cnx->remote_parameters.initial_max_stream_data_bidi_local) {
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_local;
            }
        }
        stream = picoquic_next_stream(stream);
    };
}

picoquic_stream_head_t* picoquic_find_or_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int is_remote)
{
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL) {
        stream = picoquic_create_missing_streams(cnx, stream_id, is_remote);
    }

    return stream;
}

/*
 * Check of the number of newly received bytes, or newly committed bytes
 * when a new max offset is learnt for a stream.
 */

int picoquic_flow_control_check_stream_offset(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream,
    uint64_t new_fin_offset)
{
    int ret = 0;

    if (new_fin_offset > stream->maxdata_local) {
        /* protocol violation */
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR, 0);
    } else if (new_fin_offset > stream->fin_offset) {
        /* Checking the flow control limits. Need to pay attention
        * to possible integer overflow */

        uint64_t new_bytes = new_fin_offset - stream->fin_offset;

        if (new_bytes > cnx->maxdata_local || cnx->maxdata_local - new_bytes < cnx->data_received) {
            /* protocol violation */
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR, 0);
        } else {
            cnx->data_received += new_bytes;
            stream->fin_offset = new_fin_offset;
        }
    }

    return ret;
}

/*
 * RST_STREAM Frame
 *
 * An endpoint may use a RST_STREAM frame (type=0x01) to abruptly terminate a stream.
 */

uint8_t * picoquic_format_stream_reset_frame(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream,
    uint8_t* bytes, uint8_t * bytes_max, int * more_data, int * is_pure_ack)
{
    uint8_t* bytes0 = bytes;

    if (stream->reset_requested && !stream->reset_sent) {
        if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_reset_stream)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream->stream_id)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream->local_error)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream->sent_offset)) != NULL)
        {
            *is_pure_ack = 0;
            stream->reset_sent = 1;
            stream->fin_sent = 1;

            picoquic_update_max_stream_ID_local(cnx, stream);

            /* Free the queued data */
            while (stream->send_queue != NULL) {
                picoquic_stream_data_node_t* next = stream->send_queue->next_stream_data;
                if (stream->send_queue->bytes != NULL) {
                    free(stream->send_queue->bytes);
                }
                free(stream->send_queue);
                stream->send_queue = next;
            }
            (void)picoquic_delete_stream_if_closed(cnx, stream);
        }
        else {
            *more_data = 1;
            bytes = bytes0;
        }
    }

    return bytes;
}

uint8_t* picoquic_decode_stream_reset_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t stream_id = 0;
    uint64_t error_code_64 = 0;
    uint64_t final_offset = 0;
    picoquic_stream_head_t* stream;

    if ((bytes = picoquic_frames_varint_decode(bytes + 1, bytes_max, &stream_id)) != NULL) {
        bytes = picoquic_frames_varint_decode(bytes, bytes_max, &error_code_64);
        if (bytes != NULL) {
            bytes = picoquic_frames_varint_decode(bytes, bytes_max, &final_offset);
        }
    }
    if (bytes == NULL){
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_reset_stream);
    } else if ((stream = picoquic_find_or_create_stream(cnx, stream_id, 1)) == NULL) {
        bytes = NULL;  // error already signaled

    } else if ((stream->fin_received || stream->reset_received) && final_offset != stream->fin_offset) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR,
            picoquic_frame_type_reset_stream);
        bytes = NULL;

    } else if (picoquic_flow_control_check_stream_offset(cnx, stream, final_offset) != 0) {
        bytes = NULL;  // error already signaled

    } else if (!stream->reset_received) {
        stream->reset_received = 1;
        stream->remote_error  = error_code_64;

        picoquic_update_max_stream_ID_local(cnx, stream);

        if (cnx->callback_fn != NULL && !stream->reset_signalled) {
            if (cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stream_reset, cnx->callback_ctx, stream->app_stream_ctx) != 0) {
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR,
                    picoquic_frame_type_reset_stream);
            }
            stream->reset_signalled = 1;
            (void)picoquic_delete_stream_if_closed(cnx, stream);
        }
    }

    return bytes;
}

/*
 * New Connection ID frame
 */

uint8_t * picoquic_format_new_connection_id_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t * bytes_max, int * more_data, int * is_pure_ack, picoquic_local_cnxid_t* l_cid)
{
    /* TODO: Encoding retire before, currently 0. */
    uint8_t* bytes0 = bytes;

    if (l_cid != NULL && l_cid->sequence != 0 && l_cid->cnx_id.id_len > 0) {
        if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_new_connection_id)) == NULL ||
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, l_cid->sequence)) == NULL ||
            (bytes = picoquic_frames_uint8_encode(bytes, bytes_max, 0)) == NULL ||
            (bytes = picoquic_frames_cid_encode(bytes, bytes_max, &l_cid->cnx_id)) == NULL ||
            (bytes + PICOQUIC_RESET_SECRET_SIZE) > bytes_max) {
            *more_data = 1;
            bytes = bytes0;
        }
        else {
            *is_pure_ack = 0;
            (void)picoquic_create_cnxid_reset_secret(cnx->quic, &l_cid->cnx_id, bytes);
            bytes += PICOQUIC_RESET_SECRET_SIZE;
        }
    }

    return bytes;
}


uint8_t* picoquic_skip_new_connection_id_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t cid_length = 0;
    

    if ((bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL &&
        (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL &&
        (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL &&
        (bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &cid_length)) != NULL) {
        bytes = picoquic_frames_fixed_skip(bytes, bytes_max, (size_t)cid_length + PICOQUIC_RESET_SECRET_SIZE);
    }

    return bytes;
}

uint8_t* picoquic_decode_new_connection_id_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max, uint64_t current_time)
{
    /* store the connection ID in order to support migration. */
    uint64_t sequence = 0;
    uint64_t retire_before = 0;
    uint8_t cid_length = 0;
    uint8_t * cnxid_bytes = NULL;
    uint8_t * secret_bytes = NULL;

    if ((bytes = picoquic_frames_varint_decode(bytes + 1, bytes_max, &sequence)) != NULL) {
        bytes = picoquic_frames_varint_decode(bytes, bytes_max, &retire_before);
        if (bytes != NULL) {
            bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &cid_length);
        }
    }

    if (bytes != NULL) {
        cnxid_bytes = bytes;
        secret_bytes = bytes + cid_length;
        bytes = picoquic_frames_fixed_skip(bytes, bytes_max, (size_t)cid_length + PICOQUIC_RESET_SECRET_SIZE);
    }

    if (bytes == NULL || cid_length > PICOQUIC_CONNECTION_ID_MAX_SIZE ||
        retire_before > sequence) {
        picoquic_connection_error(cnx, (bytes == NULL) ? PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR : PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
            picoquic_frame_type_new_connection_id);
        bytes = NULL;
    } else {
        uint16_t ret = 0;

        if (bytes != NULL && retire_before > cnx->retire_cnxid_before) {
            /* TODO: retire the now deprecated CID */
            ret = (uint16_t)picoquic_remove_not_before_cid(cnx, retire_before, current_time);
        }
        if (ret == 0 && sequence >= cnx->retire_cnxid_before) {
            ret = (uint16_t)picoquic_enqueue_cnxid_stash(cnx, sequence, cid_length, cnxid_bytes, secret_bytes, NULL);
        }
        if (ret != 0) {
            picoquic_connection_error(cnx, ret, picoquic_frame_type_new_connection_id);
            bytes = NULL;
        }
    }

    return bytes;
}

/*
 * Format a retire connection ID frame.
 */

uint8_t * picoquic_format_retire_connection_id_frame(uint8_t* bytes, uint8_t* bytes_max, int * more_data, int * is_pure_ack, uint64_t sequence)
{
    uint8_t * bytes0 = bytes;

    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_retire_connection_id)) == NULL ||
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, sequence)) == NULL){
        bytes = bytes0;
        *more_data = 1;
    }
    else {
        *is_pure_ack = 0;
    }

    return bytes;
}


/*
 * Queue a retire connection id frame when a probe or a path is abandoned.
 */

int picoquic_queue_retire_connection_id_frame(picoquic_cnx_t * cnx, uint64_t sequence)
{
    int ret = 0;
    size_t consumed = 0;
    uint8_t frame_buffer[258];
    int is_pure_ack = 1;
    int more_data = 0;
    uint8_t * bytes_next = picoquic_format_retire_connection_id_frame(frame_buffer, frame_buffer + sizeof(frame_buffer), &more_data, &is_pure_ack, sequence);
    
    if ((consumed = bytes_next - frame_buffer) > 0) {
        ret = picoquic_queue_misc_frame(cnx, frame_buffer, consumed, is_pure_ack);
    }

    return ret;
}

/*
 * Skip retire connection ID frame.
 */

uint8_t* picoquic_skip_retire_connection_id_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    bytes = picoquic_frames_varint_skip(bytes + 1, bytes_max);

    return bytes;
}

/*
 * Decode retire connection ID frame.
 * Mark the corresponding paths as retired. This should trigger resending a new connection ID.
 * Applications MAY note an error if the connection ID does not exist, but then they
 * MUST be damn sure that this not just a repeat of a previous retire connection ID message...
 */

uint8_t* picoquic_decode_retire_connection_id_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max, uint64_t current_time, picoquic_path_t * path_x)
{
    /* store the connection ID in order to support migration. */
    uint64_t sequence;

    if ((bytes = picoquic_frames_varint_decode(bytes + 1, bytes_max, &sequence)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_retire_connection_id);
    }
    else if (sequence >= cnx->local_cnxid_sequence_next) {
        /* If there is no matching path, trigger an error */
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
            picoquic_frame_type_retire_connection_id);
        bytes = NULL;
    }
    else if (path_x->p_local_cnxid != NULL &&
        sequence == path_x->p_local_cnxid->sequence) {
        /* Cannot delete the path through which it arrives */
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
            picoquic_frame_type_retire_connection_id);
        bytes = NULL;
    }
    else {
        /* Go through the list of paths to find the connection ID */
        picoquic_retire_local_cnxid(cnx, sequence);
    }

    return bytes;
}

/*
 * New Retry Token frame 
 */

uint8_t * picoquic_format_new_token_frame(uint8_t* bytes, uint8_t * bytes_max, int * more_data, int * is_pure_ack,
    uint8_t* token, size_t token_length)
{
    uint8_t* bytes0 = bytes; 
    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_new_token)) != NULL &&
        (bytes = picoquic_frames_length_data_encode(bytes, bytes_max, token_length, token)) != NULL) {
        *is_pure_ack = 0;
    }
    else {
        *more_data = 1;
        bytes = bytes0;
    }

    return bytes;
}

int picoquic_queue_new_token_frame(picoquic_cnx_t * cnx, uint8_t * token, size_t token_length)
{
    int ret = 0;
    int more_data = 0;
    int is_pure_ack = 1;
    uint8_t frame_buffer[258];
    uint8_t* bytes = picoquic_format_new_token_frame(frame_buffer, frame_buffer + sizeof(frame_buffer), &more_data, &is_pure_ack, token, token_length);

    if (bytes > frame_buffer) {
        ret = picoquic_queue_misc_frame(cnx, frame_buffer, bytes - frame_buffer, 1);
    }

    return ret;
}

uint8_t* picoquic_skip_new_token_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    return picoquic_frames_length_data_skip(bytes+1, bytes_max);
}

uint8_t* picoquic_decode_new_token_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t current_time, struct sockaddr* addr_to)
{
    /* TODO: store the new token in order to support immediate connection on some servers. */

    uint64_t length = 0;
    uint8_t * token = NULL;

    if ((bytes = picoquic_frames_varint_decode(bytes + 1, bytes_max, &length)) != NULL) {
        token = bytes;
        bytes = picoquic_frames_fixed_skip(bytes, bytes_max, (size_t)length);
    }

    if (bytes == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_new_token);
    }
    else if (addr_to != NULL && cnx->client_mode && cnx->sni != NULL){
        uint8_t * ip_addr;
        uint8_t ip_addr_length;
        picoquic_get_ip_addr(addr_to, &ip_addr, &ip_addr_length);
        (void)picoquic_store_token(&cnx->quic->p_first_token, current_time, cnx->sni, (uint16_t)strlen(cnx->sni),
            ip_addr, ip_addr_length, token, (uint16_t)length);
    }

    return bytes;
}

/*
 * STOP SENDING Frame
 */

uint8_t* picoquic_format_stop_sending_frame(picoquic_stream_head_t* stream,
    uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack)
{
    if (!stream->stop_sending_requested || stream->stop_sending_sent || stream->fin_received || stream->reset_received) {
        /* set this, so we will not be called again */
        stream->stop_sending_sent = 1;
    }
    else
    {
        uint8_t* bytes0 = bytes;

        if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_stop_sending)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, (uint64_t)stream->stream_id)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream->local_stop_error)) != NULL
            ) {
            *is_pure_ack = 0;
            stream->stop_sending_sent = 1;
        }
        else {
            bytes = bytes0;
            *more_data = 1;
        }
    }

    return bytes;
}


uint8_t* picoquic_decode_stop_sending_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t stream_id = 0;
    uint64_t error_code = 0;
    picoquic_stream_head_t* stream;

    if ((bytes = picoquic_frames_varint_decode(bytes+1, bytes_max, &stream_id))  == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes,   bytes_max, &error_code)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_stop_sending);

    }
    else if ((stream = picoquic_find_or_create_stream(cnx, stream_id, 1)) == NULL) {
        bytes = NULL;  // Error already signaled
    } else if (!IS_BIDIR_STREAM_ID(stream_id) && !IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
            picoquic_frame_type_stop_sending);
        bytes = NULL;
    } else if (!stream->stop_sending_received && !stream->reset_requested) {
        stream->stop_sending_received = 1;
        stream->remote_stop_error = error_code;

        if (cnx->callback_fn != NULL && !stream->stop_sending_signalled) {
            if (cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stop_sending, cnx->callback_ctx, stream->app_stream_ctx) != 0) {
                picoquic_log_app_message(cnx, "Stop sending callback on stream %" PRIu64 " returns error 0x%x",
                    stream->stream_id, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR,
                    picoquic_frame_type_stop_sending);
            }
            stream->stop_sending_signalled = 1;
        }
    }

    return bytes;
}

uint8_t* picoquic_skip_stop_sending_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) != NULL) {
        bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    }
    return bytes;
}


/*
 * STREAM frames implicitly create a stream and carry stream data.
 */

int picoquic_is_stream_frame_unlimited(const uint8_t* bytes)
{
    return PICOQUIC_BITS_CLEAR_IN_RANGE(bytes[0], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max, 0x02);
}

int picoquic_parse_stream_header(const uint8_t* bytes, size_t bytes_max,
    uint64_t* stream_id, uint64_t* offset, size_t* data_length, int* fin,
    size_t* consumed)
{
    int ret = 0;
    int len = bytes[0] & 2;
    int off = bytes[0] & 4;
    uint64_t length = 0;
    size_t l_stream = 0;
    size_t l_len = 0;
    size_t l_off = 0;
    size_t byte_index = 1;

    *fin = bytes[0] & 1;

    if (bytes_max > byte_index) {
        l_stream = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, stream_id);
        byte_index += l_stream;
    }

    if (off == 0) {
        *offset = 0;
    } else if (bytes_max > byte_index) {
        l_off = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, offset);
        byte_index += l_off;
    }

    if (bytes_max < byte_index || l_stream == 0 || (off != 0 && l_off == 0)) {
        DBG_PRINTF("stream frame header too large: first_byte=0x%02x, bytes_max=%" PRIst,
            bytes[0], bytes_max);
        *data_length = 0;
        byte_index = bytes_max;
        ret = -1;
    } else if (len == 0) {
        *data_length = bytes_max - byte_index;
    } else {
        if (bytes_max > byte_index) {
            l_len = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &length);
            byte_index += l_len;
            *data_length = (size_t)length;
        }

        if (l_len == 0 || bytes_max < byte_index) {
            DBG_PRINTF("stream frame header too large: first_byte=0x%02x, bytes_max=%" PRIst,
                bytes[0], bytes_max);
            byte_index = bytes_max;
            ret = -1;
        } else if (byte_index + length > bytes_max) {
            DBG_PRINTF("stream data past the end of the packet: first_byte=0x%02x, data_length=%" PRIst ", max_bytes=%" PRIst,
                bytes[0], *data_length, bytes_max);
            ret = -1;
        }
    }

    *consumed = byte_index;
    return ret;
}

void picoquic_stream_data_callback(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    picoquic_stream_data_node_t* data;

    while ((data = (picoquic_stream_data_node_t*)picosplay_first(&stream->stream_data_tree)) != NULL && data->offset <= stream->consumed_offset) {
        size_t start = (size_t)(stream->consumed_offset - data->offset);
        size_t data_length = data->length - start;
        picoquic_call_back_event_t fin_now = picoquic_callback_stream_data;

        stream->consumed_offset += data_length;

        if (stream->consumed_offset >= stream->fin_offset && stream->fin_received && !stream->fin_signalled){
            fin_now = picoquic_callback_stream_fin;
            stream->fin_signalled = 1;
        }

        if (cnx->callback_fn(cnx, stream->stream_id, data->bytes + start, data_length, fin_now,
            cnx->callback_ctx, stream->app_stream_ctx) != 0) {
            picoquic_log_app_message(cnx, "Data callback on stream %" PRIu64 " returns error 0x%x",
                stream->stream_id, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
        }

        picosplay_delete_hint(&stream->stream_data_tree, &data->stream_data_node);
    }

    /* handle the case where the fin frame does not carry any data */

    if (stream->consumed_offset >= stream->fin_offset && stream->fin_received && !stream->fin_signalled) {
        stream->fin_signalled = 1;
        if (cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stream_fin,
            cnx->callback_ctx, stream->app_stream_ctx) != 0) {
            picoquic_log_app_message(cnx, "FIN callback on stream %" PRIu64 " returns error 0x%x", 
                stream->stream_id, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
        }
    }
}

static int add_chunk_node(picosplay_tree_t* tree, uint64_t offset, size_t length, const uint8_t* bytes, int* chunk_added)
{
    int ret = 0;

    picoquic_stream_data_node_t* node = (picoquic_stream_data_node_t*)malloc(sizeof(picoquic_stream_data_node_t));
    uint8_t* chunk_bytes = (uint8_t*)malloc(length);

    if (node == NULL || chunk_bytes == NULL) {
        free(node);
        free(chunk_bytes);
        ret = PICOQUIC_ERROR_MEMORY;
    } else {
        memcpy(chunk_bytes, bytes, length);
        memset(node, 0, sizeof(picoquic_stream_data_node_t));
        node->offset = offset;
        node->length = length;
        node->bytes = chunk_bytes;

        picosplay_insert(tree, node);
        *chunk_added = 1;
    }

    return ret;
}

/* Common code to data stream and crypto hs stream */
int picoquic_queue_network_input(picosplay_tree_t* tree, uint64_t consumed_offset,
    uint64_t frame_data_offset, const uint8_t* bytes, size_t length, int* new_data_available)
{
    const uint64_t input_begin = frame_data_offset;
    const uint64_t input_end = frame_data_offset + length;

    int ret = 0;

    /* Remove data that is already consumed */
    if (frame_data_offset < consumed_offset) {
        frame_data_offset = consumed_offset;
    }

    /* check for data that is already received in chunks with offset <= end */
    if (frame_data_offset < input_end) {

        picoquic_stream_data_node_t target;
        memset(&target, 0, sizeof(picoquic_stream_data_node_t));
        target.offset = frame_data_offset;

        picoquic_stream_data_node_t* prev = (picoquic_stream_data_node_t*)picosplay_find_previous(tree, &target);
        if (prev != NULL) {
            /* By definition, prev->offset <= frame_data_offset. Check whether the
             * beginning of the frame is already received and skip if necessary */
            const uint64_t prev_end = prev->offset + prev->length;
            frame_data_offset = frame_data_offset > prev_end ? frame_data_offset : prev_end;
        }

        picoquic_stream_data_node_t* next = (prev == NULL) ?
            (picoquic_stream_data_node_t*)picosplay_first(tree) :
            (picoquic_stream_data_node_t*)picosplay_next(&prev->stream_data_node);

        /* Check whether parts of the new frame are covered by already received chunks */
        while (ret == 0 && frame_data_offset < input_end && next != NULL && next->offset < input_end) {

            /* the tail of the frame overlaps with the next frame received */
            const uint64_t chunk_ofs = frame_data_offset;
            const uint64_t chunk_len = next->offset > frame_data_offset ? next->offset - frame_data_offset : 0;

            if (chunk_len > 0) {
                /* There is a gap between previous and next frame, and it will be at least partially filled */
                ret = add_chunk_node(tree, chunk_ofs, (size_t)chunk_len, bytes + frame_data_offset - input_begin, new_data_available);
            }

            frame_data_offset = next->offset + next->length;
            next = (picoquic_stream_data_node_t*)picosplay_next(&next->stream_data_node);
        }

        /* no further already received chunk within the new frame */
        if (ret == 0 && frame_data_offset < input_end) {
            const uint64_t chunk_ofs = frame_data_offset;
            const uint64_t chunk_len = input_end - frame_data_offset;
            ret = add_chunk_node(tree, chunk_ofs, (size_t)chunk_len, bytes + frame_data_offset - input_begin, new_data_available);
        }
    }

    return ret;
}

static int picoquic_stream_network_input(picoquic_cnx_t* cnx, uint64_t stream_id,
    uint64_t offset, int fin, uint8_t* bytes, size_t length, uint64_t current_time)
{
    int ret = 0;
    uint64_t should_notify = 0;
    /* Is there such a stream, is it still open? */
    picoquic_stream_head_t* stream;
    uint64_t new_fin_offset = offset + length;

    if ((stream = picoquic_find_or_create_stream(cnx, stream_id, 1)) == NULL) {
        if (stream_id < cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]) {
            return 0;
        }
        else {
            ret = 1;  // Error already signaled
        }
    }
    else if (stream->fin_received) {
        if (fin != 0 ? stream->fin_offset != new_fin_offset : new_fin_offset > stream->fin_offset) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR, 0);
        }
    }
    else {
        if (fin) {
            stream->fin_received = 1;
            should_notify = 1;
            cnx->latest_progress_time = current_time;
            picoquic_update_max_stream_ID_local(cnx, stream);
        }

        if (new_fin_offset > stream->fin_offset) {
            ret = picoquic_flow_control_check_stream_offset(cnx, stream, new_fin_offset);
        }
    }

    /* If the application provided a direct receive callback, it wil receive the data as they
     * arrive. If not, the data segments are organized in a splay and passed to the
     * application in strict order.
     */

    if (ret == 0) {
        if (stream->direct_receive_fn != NULL) {
            ret = stream->direct_receive_fn(cnx, stream_id, fin, bytes, offset, length, stream->direct_receive_ctx);
            if (ret == PICOQUIC_STREAM_RECEIVE_COMPLETE && stream->fin_received) {
                stream->fin_signalled = 1;
                ret = 0;
            }
            else if (ret != 0) {
                int err = (ret >= PICOQUIC_ERROR_CLASS) ? PICOQUIC_TRANSPORT_INTERNAL_ERROR : ret;
                ret = picoquic_connection_error(cnx, (uint16_t)err, 0);
            }
        }
        else {
            int new_data_available = 0;

            ret = picoquic_queue_network_input(&stream->stream_data_tree, stream->consumed_offset,
                offset, bytes, length, &new_data_available);
            if (ret != 0) {
                ret = picoquic_connection_error(cnx, (int16_t)ret, 0);
            }
            else if (new_data_available) {
                should_notify = 1;
                cnx->latest_progress_time = current_time;
            }

            if (ret == 0 && should_notify != 0 && cnx->callback_fn != NULL) {
                /* check how much data there is to send */
                picoquic_stream_data_callback(cnx, stream);
            }
        }
    }

    /* Either the direct receive or the data queueing can set the "fin_signalled" bit when all data expected
     * on the stream has been received. The stream can be closed when all data is sent and received */

    if (ret == 0) {
        int is_deleted = 0;

        if (stream->fin_signalled) {
            is_deleted = picoquic_delete_stream_if_closed(cnx, stream);
        }

        if (!is_deleted) {
            if (!stream->fin_signalled) {
                if (!stream->fin_received && !stream->reset_received && 2 * stream->consumed_offset > stream->maxdata_local) {
                    cnx->max_stream_data_needed = 1;
                }
            }
            if (stream->fin_received || stream->reset_received) {
                cnx->pkt_ctx[picoquic_packet_context_application].ack_after_fin = 1;
            }
        }
    }

    return ret;
}

uint8_t* picoquic_decode_stream_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max, uint64_t current_time)
{
    uint64_t stream_id;
    size_t   data_length;
    uint64_t offset;
    int      fin;
    size_t   consumed;

    if (picoquic_parse_stream_header(bytes, bytes_max - bytes, &stream_id, &offset, &data_length, &fin, &consumed) != 0) {
        bytes = NULL;
    }else if (offset + data_length >= (1ull<<62)){
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR, 0);
        bytes = NULL;
    } else if (picoquic_stream_network_input(cnx, stream_id, offset, fin, (bytes += consumed), data_length, current_time) != 0) {
        bytes = NULL;
    } else {
        bytes += data_length;
    }

    return bytes;
}

picoquic_stream_head_t* picoquic_find_ready_stream(picoquic_cnx_t* cnx)
{
    picoquic_stream_head_t* first_stream = cnx->first_output_stream;
    picoquic_stream_head_t* stream = first_stream;
    picoquic_stream_head_t* found_stream = NULL;
    picoquic_stream_head_t* previous_stream = NULL;


    /* Look for a ready stream */
    while (stream != NULL) {
        if ((cnx->maxdata_remote > cnx->data_sent&& stream->sent_offset < stream->maxdata_remote && (stream->is_active ||
            (stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset) ||
            (stream->fin_requested && !stream->fin_sent))) ||
            (stream->reset_requested && !stream->reset_sent) ||
            (stream->stop_sending_requested && !stream->stop_sending_sent)) {
            /* Something can be sent */
            found_stream = stream;
            break;
        }
        else if (((stream->fin_requested && stream->fin_sent) || (stream->reset_requested && stream->reset_sent)) && (!stream->stop_sending_requested || stream->stop_sending_sent)) {
            picoquic_stream_head_t* next_stream = stream->next_output_stream;
            /* If stream is exhausted, remove from output list */
            picoquic_remove_output_stream(cnx, stream, previous_stream);

            picoquic_delete_stream_if_closed(cnx, stream);
            stream = next_stream;
        }
        else {
            if (stream->is_active ||
                (stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset)) {
                if (stream->sent_offset >= stream->maxdata_remote) {
                    cnx->stream_blocked = 1;
                }
                else if (cnx->maxdata_remote <= cnx->data_sent) {
                    cnx->flow_blocked = 1;
                }
            }
            previous_stream = stream;
            stream = stream->next_output_stream;
        }
    }

    return found_stream;
}

/* Management of BLOCKED signals
 */

uint8_t * picoquic_format_data_blocked_frame(picoquic_cnx_t * cnx, uint8_t* bytes,
    uint8_t * bytes_max, int * more_data, int * is_pure_ack)
{
    uint8_t* bytes0 = bytes;

    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_data_blocked)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, cnx->maxdata_remote)) != NULL) {
        *is_pure_ack = 0;
        cnx->sent_blocked_frame = 1;
    }
    else {
        *more_data = 1;
        bytes = bytes0;
    }

    return bytes;
}

uint8_t * picoquic_format_stream_data_blocked_frame(uint8_t* bytes,
    uint8_t* bytes_max, int* more_data, int* is_pure_ack, picoquic_stream_head_t* stream)
{
    uint8_t* bytes0 = bytes;

    if ((bytes=picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_stream_data_blocked)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream->stream_id)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream->maxdata_remote)) != NULL)
    {
        *is_pure_ack = 0;
        stream->stream_data_blocked_sent = 1;
    }
    else {
        *more_data = 1;
        bytes = bytes0;
    }

    return bytes;
}

uint8_t * picoquic_format_stream_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    uint8_t* bytes_max, int* more_data, int* is_pure_ack, picoquic_stream_head_t* stream)
{
    uint8_t* bytes0 = bytes;
    uint8_t f_type = 0;
    uint64_t stream_limit = 0;
    int should_not_send = 0;

    if (IS_BIDIR_STREAM_ID(stream->stream_id)) {
        f_type = picoquic_frame_type_streams_blocked_bidir;
        stream_limit = STREAM_RANK_FROM_ID(stream->stream_id);
        should_not_send = cnx->stream_blocked_bidir_sent;
    }
    else {
        f_type = picoquic_frame_type_streams_blocked_unidir;
        stream_limit = STREAM_RANK_FROM_ID(stream->stream_id);
        should_not_send = cnx->stream_blocked_unidir_sent;
    }
    if (!should_not_send) {
        if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, f_type)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream_limit)) != NULL) {
            *is_pure_ack = 0;
            if (IS_BIDIR_STREAM_ID(stream->stream_id)) {
                cnx->stream_blocked_bidir_sent = 1;
            }
            else {
                cnx->stream_blocked_unidir_sent = 1;
            }
        }
        else {
            *more_data = 1;
            bytes = bytes0;
        }
    }

    return bytes;
}

uint8_t * picoquic_format_one_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    uint8_t* bytes_max, int* more_data, int* is_pure_ack, picoquic_stream_head_t* stream)
{
    if (stream->is_active ||
        (stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset)) {
        /* The stream has some data to send */
        /* if the stream is not active yet, verify that it fits under
            * the max stream id limit, which depends of the type of stream */
        if (IS_CLIENT_STREAM_ID(stream->stream_id) != cnx->client_mode &&
            stream->stream_id > ((IS_BIDIR_STREAM_ID(stream->stream_id)) ? cnx->max_stream_id_bidir_remote : cnx->max_stream_id_unidir_remote)) {
            if (!(IS_BIDIR_STREAM_ID(stream->stream_id) ? cnx->stream_blocked_bidir_sent : cnx->stream_blocked_unidir_sent))
            {
                /* Prepare a stream blocked frame */
                bytes = picoquic_format_stream_blocked_frame(cnx, bytes, bytes_max, more_data, is_pure_ack, stream);
            }
        }
        else {
            if (cnx->maxdata_remote <= cnx->data_sent && !cnx->sent_blocked_frame) {
                /* Prepare a blocked frame */
                bytes = picoquic_format_data_blocked_frame(cnx, bytes, bytes_max, more_data, is_pure_ack);
            }

            if (stream->sent_offset >= stream->maxdata_remote && !stream->stream_data_blocked_sent) {
                /* Prepare a stream data blocked frame */
                bytes = picoquic_format_stream_data_blocked_frame(bytes, bytes_max, more_data, is_pure_ack, stream);
            }
        }
    }

    return bytes;
}

uint8_t * picoquic_format_blocked_frames(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t * bytes_max, int * more_data, int * is_pure_ack)
{
    picoquic_stream_head_t* stream = picoquic_first_stream(cnx);
    picoquic_stream_head_t* hi_pri_stream = NULL;

    /* Check whether there is a high priority stream declared */
    if (cnx->high_priority_stream_id != (uint64_t)((int64_t)-1)) {
        hi_pri_stream = picoquic_find_stream(cnx, cnx->high_priority_stream_id);
    }

    /* Look for blocked streams, as long as there is message space available */
    while (stream != NULL) {
        if (hi_pri_stream == NULL || stream == hi_pri_stream) {
            bytes = picoquic_format_one_blocked_frame(cnx, bytes, bytes_max, more_data, is_pure_ack, stream);
            if (*more_data) {
                break;
            }
        }

        stream = picoquic_next_stream(stream);
    }

    return bytes;
}

/* handling of stream frames
 */

typedef struct st_picoquic_stream_data_buffer_argument_t {
    uint8_t* bytes; /* Points to the beginning of the encoding of the stream frame */
    size_t byte_index; /* Current index position after encoding type, stream-id and offset */
    size_t byte_space; /* Number of bytes available in the packet after the current index */
    size_t allowed_space; /* Maximum number of bytes that the application is authorized to write */
    size_t length; /* number of bytes that the application commits to write */
    int is_fin; /* Whether this is the end of the stream */
    int is_still_active; /* whether the stream is still considered active after this call */
    uint8_t* app_buffer; /* buffer provided to the application. */
} picoquic_stream_data_buffer_argument_t;

static size_t picoquic_encode_length_of_stream_frame(
    uint8_t* bytes, size_t byte_index, size_t byte_space, size_t length, size_t *start_index)
{
    if (length < byte_space) {
        if (length == byte_space - 1) {
            /* Special case: there are N bytes available, the application wants to write N-1 bytes.
             * We can encode N bytes because then we don't need a length field, just a flag in the
             * first byte. But if we had to encode "length=N-1", that would typically require 2
             * bytes, for a total of (2 + N-1)=N+1 bytes, larger than the packet size. We also
             * don't want to avoid the length field, because the encoding would be shorter than
             * the packet size, and other parts of the code might add a byte after that, e.g. padding,
             * which the receiver would mistake as data because of the "implicit length" encoding.
             * So we work against that issue by inserting a single padding byte in front of the
             * stream header.*/
            memmove(bytes + 1, bytes, byte_index);
            bytes[0] = picoquic_frame_type_padding;
            *start_index = 1;
            byte_index++;
        }
        else {
            /* Short frame, length field is required */
            /* We checked above that there are enough bytes to encode length */
            byte_index += picoquic_varint_encode(bytes + byte_index, byte_space, (uint64_t)length);
            bytes[0] |= 2; /* Indicates presence of length */
        }
    }

    return byte_index;
}

uint8_t* picoquic_provide_stream_data_buffer(void* context, size_t length, int is_fin, int is_still_active)
{
    picoquic_stream_data_buffer_argument_t * data_ctx = (picoquic_stream_data_buffer_argument_t*)context;
    uint8_t* buffer = NULL;
    size_t start_index = 0;

    if (length <= data_ctx->allowed_space) {
        data_ctx->length = length;

        if (is_fin) {
            data_ctx->is_fin = 1;
            data_ctx->bytes[0] |= 1;
        }

        data_ctx->is_still_active = is_still_active;

        data_ctx->byte_index = picoquic_encode_length_of_stream_frame(data_ctx->bytes,
            data_ctx->byte_index, data_ctx->byte_space, length, &start_index);

        buffer = data_ctx->bytes + data_ctx->byte_index;
        data_ctx->app_buffer = buffer;
    }

    return buffer;
}

static uint8_t* picoquic_format_stream_frame_header(uint8_t* bytes, uint8_t* bytes_max, uint64_t stream_id, uint64_t offset)
{
    uint8_t* bytes0 = bytes;
    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_stream_range_min)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream_id)) != NULL) {
        if (offset > 0) {
            *bytes0 |= 4; /* Indicates presence of offset */
            bytes = picoquic_frames_varint_encode(bytes, bytes_max, offset);
        }
    }

    return bytes;
}

uint8_t * picoquic_format_stream_frame(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream,
    uint8_t* bytes, uint8_t* bytes_max, int * more_data, int * is_pure_ack, int* is_still_active, int * ret)
{
    int may_close = 0;
    *ret = 0;

    /* Check parity */
    if (IS_CLIENT_STREAM_ID(stream->stream_id) == cnx->client_mode) {
        if (stream->stream_id > ((IS_BIDIR_STREAM_ID(stream->stream_id)) ? cnx->max_stream_id_bidir_remote : cnx->max_stream_id_unidir_remote)) {
            return bytes;
        }
    }

    if (stream->reset_requested && !stream->reset_sent) {
        return picoquic_format_stream_reset_frame(cnx, stream, bytes, bytes_max, more_data, is_pure_ack);
    }

    if (stream->stop_sending_requested && !stream->stop_sending_sent) {
        return picoquic_format_stop_sending_frame(stream, bytes, bytes_max, more_data, is_pure_ack);
    }

    if (!stream->is_active &&
        (stream->send_queue == NULL || stream->send_queue->length <= stream->send_queue->offset) &&
        (!stream->fin_requested || stream->fin_sent)) {
        /* Nothing to send */
    }
    else {
        uint8_t* bytes0 = bytes;
        size_t byte_index = 0;
        size_t length = 0;

        if ((bytes = picoquic_format_stream_frame_header(bytes, bytes_max, stream->stream_id, stream->sent_offset)) == NULL) {
            bytes = bytes0;
            *more_data = 1;
        } else {
            /* Compute the length */
            size_t byte_space = bytes_max - bytes;
            size_t allowed_space = byte_space;

            /* Enforce maxdata per stream on all streams, including stream 0
             * This may result in very short encoding, but we still send whatever is
             * allowed by flow control. Doing otherwise may cause a loop if the
             * "find_ready_stream" function did not completely replicate the
             * flow control test */
            if (allowed_space > (stream->maxdata_remote - stream->sent_offset)) {
                allowed_space = (size_t)(stream->maxdata_remote - stream->sent_offset);
            }

            if (allowed_space > (cnx->maxdata_remote - cnx->data_sent)) {
                allowed_space = (size_t)(cnx->maxdata_remote - cnx->data_sent);
            }

            if (stream->is_active && stream->send_queue == NULL && !stream->fin_requested) {
                /* The application requested active polling for this stream */
                picoquic_stream_data_buffer_argument_t stream_data_context;

                stream_data_context.bytes = bytes0;
                stream_data_context.byte_index = bytes - bytes0;
                stream_data_context.allowed_space = allowed_space;
                stream_data_context.byte_space = bytes_max - bytes;
                stream_data_context.length = 0;
                stream_data_context.is_fin = 0;
                stream_data_context.is_still_active = 0;
                stream_data_context.app_buffer = NULL;

                if ((cnx->callback_fn)(cnx, stream->stream_id, (uint8_t*)&stream_data_context, allowed_space, picoquic_callback_prepare_to_send, cnx->callback_ctx, stream->app_stream_ctx) != 0) {
                    /* something went wrong */
                    picoquic_log_app_message(cnx, "Prepare to send returns error 0x%x", PICOQUIC_TRANSPORT_INTERNAL_ERROR);
                    *ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
                    bytes = bytes0; /* CHECK: SHOULD THIS BE NULL ? */
                }
                else {
                    bytes = bytes0 + stream_data_context.byte_index + stream_data_context.length;
                    stream->sent_offset += stream_data_context.length;
                    cnx->data_sent += stream_data_context.length;

                    if (stream_data_context.length > 0) {
                        if (stream_data_context.app_buffer == NULL ||
                            stream_data_context.app_buffer < bytes0 ||
                            stream_data_context.app_buffer >= bytes_max) {
                            long long delta_buf = (long long)(stream_data_context.app_buffer - bytes);
                            DBG_PRINTF("Stream data buffer corruption, delta = %lld\n", delta_buf);
                            *ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
                            /* CHECK: SHOULD bytes BE NULL ? */
                        }
                    }

                    if (stream_data_context.is_fin) {
                        stream->is_active = 0;
                        stream->fin_requested = 1;
                        stream->fin_sent = 1;
                        picoquic_update_max_stream_ID_local(cnx, stream);
                        may_close = 1;

                        if (is_still_active != NULL) {
                            *is_still_active = 0;
                        }
                    }
                    else {
                        stream->is_active = stream_data_context.is_still_active;
                        if (is_still_active != NULL) {
                            *is_still_active = stream_data_context.is_still_active;
                        }
                    }
                }
            }
            else {
                /* The application queued data for this stream */
                size_t start_index = 0;

                byte_index = bytes - bytes0;

                if (stream->send_queue == NULL) {
                    length = 0;
                }
                else {
                    length = (size_t)(stream->send_queue->length - stream->send_queue->offset);
                }

                if (length >= allowed_space) {
                    length = allowed_space;
                }

                byte_index = picoquic_encode_length_of_stream_frame(bytes0, byte_index, byte_space, length, &start_index);

                if (length > 0 && stream->send_queue != NULL && stream->send_queue->bytes != NULL) {
                    memcpy(&bytes0[byte_index], stream->send_queue->bytes + stream->send_queue->offset, length);
                    byte_index += length;

                    stream->send_queue->offset += length;
                    if (stream->send_queue->offset >= stream->send_queue->length) {
                        picoquic_stream_data_node_t* next = stream->send_queue->next_stream_data;
                        free(stream->send_queue->bytes);
                        free(stream->send_queue);
                        stream->send_queue = next;
                    }

                    stream->sent_offset += length;
                    cnx->data_sent += length;
                }

                bytes = bytes0 + byte_index;

                if (stream->send_queue == NULL) {
                    if (stream->fin_requested) {
                        /* Set the fin bit -- target the start_index octet, to match behavior of length encoding */
                        stream->fin_sent = 1;
                        bytes0[start_index] |= 1;

                        picoquic_update_max_stream_ID_local(cnx, stream);
                        may_close = 1;
                    }
                }
                else if (length == 0) {
                    /* No point in sending a silly packet */
                    bytes = bytes0;
                    *more_data = 1;
                }
            }
        }

        if (*ret == 0) {
            *is_pure_ack &= (bytes == bytes0);

            if (!may_close || !picoquic_delete_stream_if_closed(cnx, stream)) {
                /* mark the stream as unblocked since we sent something */
                stream->stream_data_blocked_sent = 0;
                cnx->sent_blocked_frame = 0;
            }
        }
    }

    return bytes;
}

/* Format all available stream frames that fit in the packet.
 * Update more_data if more stream data is available
 * Update is_pure_ack if formated frames require ack
 * Set stream_tried_and_failed if there was nothing to send, indicating the app limited condition.
 */
uint8_t* picoquic_format_available_stream_frames(picoquic_cnx_t* cnx, uint8_t* bytes_next, uint8_t* bytes_max, int* more_data,
    int* is_pure_ack, int* stream_tried_and_failed, int* ret)
{
    uint8_t* bytes_previous = bytes_next;
    picoquic_stream_head_t* stream = picoquic_find_ready_stream(cnx);
    int more_stream_data = 0;

    while (*ret == 0 && stream != NULL && bytes_next < bytes_max) {
        int is_still_active = 0;

        bytes_next = picoquic_format_stream_frame(cnx, stream, bytes_next, bytes_max, &more_stream_data, is_pure_ack, &is_still_active, ret);

        if (*ret == 0) {
            if (bytes_next + 8 < bytes_max) {
                stream = picoquic_find_ready_stream(cnx);
            }
            else {
                more_stream_data = 1;
                break;
            }
        }
        else {
            break;
        }
    }

    *stream_tried_and_failed = (!more_stream_data && bytes_next == bytes_previous);
    *more_data |= more_stream_data;

    return bytes_next;
}

/* Format the stream frames that were queued for retransmit */

uint8_t* picoquic_format_stream_frame_for_retransmit(picoquic_cnx_t* cnx,
    uint8_t* bytes_next, uint8_t* bytes_max, int* is_pure_ack)
{
    picoquic_misc_frame_header_t* misc = cnx->stream_frame_retransmit_queue;
    uint8_t* frame = ((uint8_t*)misc) + sizeof(picoquic_misc_frame_header_t);
    uint64_t stream_id;
    uint64_t offset;
    size_t data_length;
    size_t consumed;
    int fin;
    int all_sent = 0;

    if (picoquic_parse_stream_header(frame, misc->length, &stream_id, &offset, &data_length, &fin, &consumed) != 0) {
        /* Malformed stream frame. Log an error, and ignore. */
        picoquic_log_app_message(cnx, "Malformed copied stream frame, type %d, length %zu",
            frame[0], misc->length);
        all_sent = 1;
    }
    else {
        uint8_t* bytes_first = bytes_next;
        size_t available = bytes_max - bytes_next;
        picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
        if (stream == NULL || stream->reset_sent || picoquic_check_sack_list(&stream->first_sack_item, offset, offset + data_length)) {
            /* That frame is not needed anymore */
            all_sent = 1;
        } else if (bytes_next + misc->length <= bytes_max) {
            /* The frame can be copied in full */
            if ((frame[0] & 2) == 0) {
                /* Length is not encoded. If it fits just fine, copy. Else, need to be smarter */
                size_t insert_pad = (bytes_max - bytes_next) - misc->length;
                if (insert_pad <= 2) {
                    /* pad, and then copy frame */
                    while (insert_pad > 0) {
                        *bytes_next = 0;
                        bytes_next++;
                        insert_pad--;
                    }
                    memcpy(bytes_next, frame, misc->length);
                    bytes_next += misc->length;
                }
                else {
                    /* Need to reencode the header, then copy */
                    if ((bytes_next = picoquic_format_stream_frame_header(bytes_next, bytes_max, stream_id, offset)) != NULL &&
                        (bytes_next = picoquic_frames_varint_encode(bytes_next, bytes_max, data_length)) != NULL) {
                        memcpy(bytes_next, frame + consumed, data_length);
                        bytes_next += data_length;
                        *bytes_first |= 2; /* length present */
                        *bytes_first |= fin;
                    }
                    else {
                        bytes_next = bytes_first;
                    }
                }
            }
            else {
                memcpy(bytes_next, frame, misc->length);
                bytes_next += misc->length;
            }
            all_sent = 1;
            *is_pure_ack = 0;
        }
        else {
            int success = 0;
            if (available > consumed &&
                (bytes_next = picoquic_format_stream_frame_header(bytes_next, bytes_max, stream_id, offset)) != NULL) {
                uint8_t* after_length = picoquic_frames_varint_encode(bytes_next, bytes_max, available - 2);
                if (after_length != NULL && after_length < bytes_max &&
                    (available = bytes_max - after_length) > 0) {
                    size_t remain = data_length - available;
                    uint8_t trial_pad[32] = { 0 }; /* max header = 1 + 8(stream) + 8(offset) +8(length)*/
                    uint8_t* trial_max = trial_pad + sizeof(trial_pad);
                    uint8_t* trial_next;
                    size_t trial_size = 0;

                    if ((trial_next = picoquic_format_stream_frame_header(trial_pad, trial_max, stream_id, offset + available)) != NULL &&
                        (trial_next = picoquic_frames_varint_encode(trial_next, trial_max, remain)) != NULL &&
                        (trial_size = trial_next - trial_pad) <= consumed + available) {
                        /* There are enough bytes available to reformat the frame after copying */
                        /* Finish encoding the copied bytes */
                        bytes_next = picoquic_frames_varint_encode(bytes_next, bytes_max, available);
                        *bytes_first |= 2;
                        memcpy(bytes_next, frame + consumed, available);
                        bytes_next += available;
                        /* Reformat the stored bytes to only keep the remains */
                        trial_pad[0] |= 2;
                        memcpy(frame, trial_pad, trial_size);
                        memmove(frame + trial_size, frame + consumed + available, remain);
                        misc->length = trial_size + remain;
                        frame[0] |= fin;
                        success = 1;
                        *is_pure_ack = 0;
                    }
                }
            }

            if (!success) {
                bytes_next = bytes_first;
            }
        }
    }

    if (all_sent) {
        picoquic_delete_misc_or_dg(&cnx->stream_frame_retransmit_queue, &cnx->stream_frame_retransmit_queue_last, misc);
    }

    return bytes_next;
}

uint8_t* picoquic_format_stream_frames_queued_for_retransmit(picoquic_cnx_t* cnx,
    uint8_t* bytes_next, uint8_t* bytes_max, int* more_data, int* is_pure_ack)
{
    picoquic_misc_frame_header_t* misc;

    while ((misc = cnx->stream_frame_retransmit_queue) != NULL && bytes_next < bytes_max) {
        bytes_next = picoquic_format_stream_frame_for_retransmit(cnx, bytes_next, bytes_max, is_pure_ack);
        if (misc == cnx->stream_frame_retransmit_queue) {
            break;
        }
    }

    *more_data |= (cnx->stream_frame_retransmit_queue != NULL);

    return bytes_next;
}

/*
 * Crypto HS frames
 */

int picoquic_is_tls_stream_ready(picoquic_cnx_t* cnx)
{
    int ret = 0;

    for (int epoch = 0; epoch < 4; epoch++) {
        picoquic_stream_head_t* stream = &cnx->tls_stream[epoch];

        if (stream->send_queue != NULL &&
            stream->send_queue->length > stream->send_queue->offset &&
            cnx->crypto_context[epoch].aead_encrypt != NULL) {
            ret = 1;
            break;
        }
    }

    return ret;
}


uint8_t* picoquic_decode_crypto_hs_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max, int epoch)
{
    uint64_t offset;
    uint64_t data_length;
    int      new_data_available;  // Unused

    if ((bytes = picoquic_frames_varint_decode(bytes+1, bytes_max, &offset))      == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes,   bytes_max, &data_length)) == NULL )
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_crypto_hs);

    } else if ((uint64_t)(bytes_max - bytes) < data_length) {
        DBG_PRINTF("crypto hs data past the end of the packet: data_length=%" PRIst ", remaining_space=%" PRIst, data_length, bytes_max - bytes);
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_crypto_hs);
        bytes = NULL;

    } else {
        picoquic_stream_head_t* stream = &cnx->tls_stream[epoch];
        int ret = picoquic_queue_network_input(&stream->stream_data_tree, stream->consumed_offset,
            offset, bytes, (size_t)data_length, &new_data_available);
        if (ret != 0) {
            picoquic_connection_error(cnx, (int16_t)ret, picoquic_frame_type_crypto_hs);
            bytes = NULL;
        } else {
            bytes += data_length;
        }
    }

    return bytes;
}

uint8_t* picoquic_format_crypto_hs_frame(picoquic_stream_head_t* stream, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack)
{
    uint8_t* bytes0 = bytes;

    if (stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset) {
        /* Check that there is enough room for at least 2 content bytes */
        if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_crypto_hs)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream->sent_offset)) != NULL) {
            /* As there is enough room, estimate the actual length, then encode the packet */
            size_t length = stream->send_queue->length - (size_t)stream->send_queue->offset;
            uint8_t* bytes_l;

            if (bytes + length > bytes_max) {
                length = bytes_max - bytes;
            }

            if ((bytes_l = picoquic_frames_varint_encode(bytes, bytes_max, length)) == NULL) {
                /* *more_data = 1; */
                bytes = bytes0;
            }
            else {
                if (bytes_l + length > bytes_max) {
                    length = bytes_max - bytes_l;
                    bytes = picoquic_frames_varint_encode(bytes, bytes_max, length);
                }
                else {
                    bytes = bytes_l;
                }
                if (bytes != NULL && length > 0) {
                    memcpy(bytes, stream->send_queue->bytes + stream->send_queue->offset, length);
                    bytes += length;

                    stream->send_queue->offset += length;
                    if (stream->send_queue->offset >= stream->send_queue->length) {
                        picoquic_stream_data_node_t* next = stream->send_queue->next_stream_data;
                        free(stream->send_queue->bytes);
                        free(stream->send_queue);
                        stream->send_queue = next;
                    }

                    stream->sent_offset += length;
                    *is_pure_ack = 0;
                }
            }
        }
        else {
            /* *more_data = 1; */
            bytes = bytes0;
        }
    }

    return bytes;
}


/*
 * ACK Frames
 */

int picoquic_parse_ack_header(uint8_t const* bytes, size_t bytes_max,
    uint64_t* num_block,
    uint64_t* largest, uint64_t* ack_delay, size_t* consumed,
    uint8_t ack_delay_exponent)
{
    int ret = 0;
    size_t byte_index = 1;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_blocks = 0;

    if (bytes_max > byte_index) {
        l_largest = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, largest);
        byte_index += l_largest;
    }

    if (bytes_max > byte_index) {
        l_delay = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, ack_delay);
        *ack_delay <<= ack_delay_exponent;
        byte_index += l_delay;
    }

    if (bytes_max > byte_index) {
        l_blocks = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, num_block);
        byte_index += l_blocks;
    }

    if (l_largest == 0 || l_delay == 0 || l_blocks == 0 || bytes_max < byte_index) {
        DBG_PRINTF("ack frame fixed header too large: first_byte=0x%02x, bytes_max=%" PRIst,
            bytes[0], bytes_max);
        byte_index = bytes_max;
        ret = -1;
    }

    *consumed = byte_index;
    return ret;
}


picoquic_packet_t* picoquic_check_spurious_retransmission(picoquic_cnx_t* cnx,
    uint64_t start_of_range, uint64_t end_of_range, uint64_t current_time,
    picoquic_packet_context_enum pc, picoquic_packet_t* p)
{
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];

    while (p != NULL && p->sequence_number >= start_of_range) {
        picoquic_packet_t* should_delete = NULL;

        if ( p->sequence_number <= end_of_range) {

            uint64_t max_spurious_rtt = current_time - p->send_time;
            uint64_t max_reorder_delay = pkt_ctx->latest_time_acknowledged - p->send_time;
            uint64_t max_reorder_gap = pkt_ctx->highest_acknowledged - p->sequence_number;
            picoquic_path_t * old_path = p->send_path;

            if (old_path != NULL) {
                if (p->length + p->checksum_overhead > old_path->send_mtu) {
                    old_path->send_mtu = p->length + p->checksum_overhead;
                    if (old_path->send_mtu > old_path->send_mtu_max_tried) {
                        old_path->send_mtu_max_tried = old_path->send_mtu;
                    }
                    old_path->mtu_probe_sent = 0; 
                }

                if (max_spurious_rtt > old_path->max_spurious_rtt) {
                    old_path->max_spurious_rtt = max_spurious_rtt;
                }

                if (max_reorder_delay > old_path->max_reorder_delay) {
                    old_path->max_reorder_delay = max_reorder_delay;
                }

                if (max_reorder_gap > old_path->max_reorder_gap) {
                    old_path->max_reorder_gap = max_reorder_gap;
                }

                if (old_path->smoothed_rtt == PICOQUIC_INITIAL_RTT && old_path->rtt_variant == 0) {
                    /* If the RTT has not been set, use it to update the path RTT */
                    picoquic_update_path_rtt(cnx, old_path, p->send_time, current_time, 0);
                }

                if (old_path->nb_losses_found > 0) {
                    old_path->nb_losses_found--;
                }

                if (old_path->total_bytes_lost > p->length) {
                    old_path->total_bytes_lost -= p->length;
                }
                else {
                    old_path->total_bytes_lost = 0;
                }

                if (cnx->congestion_alg != NULL) {
                    cnx->congestion_alg->alg_notify(cnx, old_path, picoquic_congestion_notification_spurious_repeat,
                        0, 0, 0, p->sequence_number, current_time);
                }
            }

            cnx->nb_spurious++;
            should_delete = p;
        }

        p = p->previous_packet;

        if (should_delete != NULL) {
            picoquic_dequeue_retransmitted_packet(cnx, should_delete);
        }
    }

    return p;
}

void picoquic_dequeue_old_retransmitted_packets(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc)
{
    picoquic_packet_t* p = cnx->pkt_ctx[pc].retransmitted_oldest;

    if (p != NULL) {
        uint64_t oldest_possible = cnx->pkt_ctx[pc].latest_time_acknowledged;

        if (oldest_possible > PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX) {
            oldest_possible -= PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX;

            while (p != NULL && p->send_time < oldest_possible) {
                picoquic_packet_t* should_delete = p;

                p = p->next_packet;

                if (should_delete != NULL) {
                    picoquic_dequeue_retransmitted_packet(cnx, should_delete);
                }
            }
        }
    }
}

void picoquic_estimate_path_bandwidth(picoquic_cnx_t * cnx, picoquic_path_t* path_x, uint64_t send_time,
    uint64_t delivered_prior, uint64_t delivered_time_prior, uint64_t delivered_sent_prior,
    uint64_t delivery_time, uint64_t current_time, int rs_is_path_limited)
{
    if (send_time >= path_x->delivered_sent_last) {
        if (path_x->delivered_time_last == 0) {
            /* No estimate yet, need to initialize the variables */
            path_x->delivered_last = path_x->delivered;
            path_x->delivered_time_last = delivery_time;
            path_x->delivered_sent_last = send_time;
        }
        else {
            uint64_t receive_interval = delivery_time - delivered_time_prior;

            if (receive_interval > PICOQUIC_BANDWIDTH_TIME_INTERVAL_MIN) {
                uint64_t delivered = path_x->delivered - delivered_prior;
                uint64_t send_interval = send_time - delivered_sent_prior;
                uint64_t bw_estimate;

                if (send_interval > receive_interval) {
                    receive_interval = send_interval;
                }

                bw_estimate = delivered * 1000000;
                bw_estimate /= receive_interval;

                if (!rs_is_path_limited || bw_estimate > path_x->bandwidth_estimate) {
                    path_x->bandwidth_estimate = bw_estimate;
                    if (path_x == cnx->path[0]){
                        if (cnx->is_ack_frequency_negotiated &&
                            cnx->ack_gap_local != picoquic_compute_ack_gap(cnx, bw_estimate)){
                            cnx->is_ack_frequency_updated = 1;
                        }
                    }
                }

                /* Bandwidth was estimated, update the references */
                path_x->delivered_last = path_x->delivered;
                path_x->delivered_time_last = delivery_time;
                path_x->delivered_sent_last = send_time;
                path_x->delivered_last_packet = delivered_prior;
                path_x->last_bw_estimate_path_limited = rs_is_path_limited;
                if (path_x->delivered > path_x->delivered_limited_index) {
                    path_x->delivered_limited_index = 0;
                }
            }
        }
    }
}

void picoquic_estimate_max_path_bandwidth(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t send_time,
    uint64_t delivery_time, uint64_t current_time)
{
    /* Test whether there is enough time since the last max bandwidth estimate */
    if (send_time >= path_x->max_sample_sent_time) {
        if (path_x->max_sample_sent_time == 0) {
            /* No sample set yet, need to initialize the variables */
            path_x->max_sample_delivered = path_x->delivered;
            path_x->max_sample_acked_time = delivery_time;
            path_x->max_sample_sent_time = send_time;
        }
        else {
            /* Compute a max bandwidth estimate */
            uint64_t receive_interval = delivery_time - path_x->max_sample_acked_time;

            if (receive_interval > PICOQUIC_MAX_BANDWIDTH_TIME_INTERVAL_MIN) {
                uint64_t delivered = path_x->delivered - path_x->max_sample_delivered;
                uint64_t send_interval = send_time - path_x->max_sample_sent_time;
                uint64_t bw_estimate;

                if (send_interval > receive_interval) {
                    receive_interval = send_interval;
                }

                bw_estimate = delivered * 1000000;
                bw_estimate /= receive_interval;
                /* Retain if larger than previous estimate */
                if (bw_estimate > path_x->max_bandwidth_estimate) {
                    path_x->max_bandwidth_estimate = bw_estimate;
                }

                /* Change the reference point if estimate duration is long enough */
                path_x->max_sample_delivered = path_x->delivered;
                path_x->max_sample_acked_time = delivery_time;
                path_x->max_sample_sent_time = send_time;
            }
        }
    }
}

/* Compute the desired number of packets coalesce in a single ACK.
 * This will be used to compute the value sent to the peer in the ACK FREQUENCY frame,
 * using the bandwidth estimate computed from received ACKs.
 * When the ACK FREQUENCY is not negotiated, this will be computed locally,
 * using the estimated received rate.
 * The computed value is only used if it is not overriden:
 * - For the Initial and Handshake contexts the gap is always 1.
 * - If "ack_after_fin" is set the gap is always 1.
 * - If packets are received out of order and the peer is sensitive, the gap is 1.
 */

uint64_t picoquic_compute_ack_gap(picoquic_cnx_t* cnx, uint64_t data_rate)
{
    uint64_t ack_gap = 1;

    if (data_rate > PICOQUIC_BANDWIDTH_MEDIUM) {
        if (cnx->path[0]->rtt_min > PICOQUIC_TARGET_RENO_RTT) {
            ack_gap = 10;
        }
        else {
            ack_gap = 4;
        }
    }
    else {
        ack_gap = 2;
    }

    return ack_gap;
}

uint64_t picoquic_compute_ack_delay_max(uint64_t rtt, uint64_t remote_min_ack_delay)
{
    uint64_t ack_delay_max = rtt / 4;

    if (ack_delay_max > PICOQUIC_ACK_DELAY_MAX) {
        ack_delay_max = PICOQUIC_ACK_DELAY_MAX;
    }

    if (ack_delay_max < remote_min_ack_delay) {
        ack_delay_max = remote_min_ack_delay;
    }
    return ack_delay_max;
}

void picoquic_update_1wd(picoquic_cnx_t * cnx, picoquic_path_t * old_path, 
    uint64_t send_time, uint64_t ack_delay, uint64_t remote_time_stamp)
{
    int64_t one_way_delay = 0;

    if (remote_time_stamp > 0) {
        int64_t time_stamp_local = remote_time_stamp - ack_delay + cnx->start_time + old_path->phase_delay;

        one_way_delay = time_stamp_local - send_time;

        if (one_way_delay < 0) {
            int64_t correct_1wd = old_path->rtt_sample / 2;
            picoquic_log_app_message(cnx,
                "BAD 1WD! RTS=%" PRIu64 ", AD=%"PRIu64 ", Start=%" PRIu64 ", Phi=%"PRIi64 ", Send=%" PRIu64 ", OWD=%"PRIu64 "\n",
                remote_time_stamp, ack_delay, cnx->start_time, old_path->phase_delay, send_time, one_way_delay);
            old_path->phase_delay += correct_1wd - one_way_delay;
            one_way_delay = correct_1wd;
        }
        old_path->one_way_delay_sample = one_way_delay;
    }
}

void picoquic_update_path_rtt(picoquic_cnx_t* cnx, picoquic_path_t * old_path, uint64_t send_time,
    uint64_t current_time, uint64_t ack_delay)
{
    uint64_t acknowledged_time = current_time - ack_delay;
    int64_t rtt_estimate = acknowledged_time - send_time;

    if (rtt_estimate > 0 && old_path != NULL) {
        if (ack_delay > old_path->max_ack_delay) {
            old_path->max_ack_delay = ack_delay;
        }

        if (rtt_estimate > 2000000) {
            DBG_PRINTF("Measured RTT = %llu", (unsigned long long)rtt_estimate);
        }

        if (old_path->smoothed_rtt == PICOQUIC_INITIAL_RTT && old_path->rtt_variant == 0) {
            old_path->smoothed_rtt = rtt_estimate;
            old_path->rtt_variant = rtt_estimate / 2;
            old_path->phase_delay = rtt_estimate / 2;

            if (!cnx->client_mode) {
                old_path->phase_delay = -old_path->phase_delay;
            }

            old_path->rtt_min = rtt_estimate;
            old_path->retransmit_timer = 3 * rtt_estimate +
                cnx->remote_parameters.max_ack_delay;
            if (old_path == cnx->path[0]) {
                /* Only update the ack delay upon measuring the default path */
                cnx->is_ack_frequency_updated = cnx->is_ack_frequency_negotiated;
                if (!cnx->is_ack_frequency_negotiated || cnx->cnx_state != picoquic_state_ready) {
                    cnx->ack_delay_remote = picoquic_compute_ack_delay_max(old_path->rtt_min, PICOQUIC_ACK_DELAY_MIN);
                }
            }
        }
        else {
            /* Computation per RFC 6298 */
            int64_t delta_rtt = rtt_estimate - old_path->smoothed_rtt;
            int64_t delta_rtt_average = 0;
            old_path->smoothed_rtt += delta_rtt / 8;

            if (delta_rtt < 0) {
                delta_rtt_average = (-delta_rtt) - old_path->rtt_variant;
            }
            else {
                delta_rtt_average = delta_rtt - old_path->rtt_variant;
            }
            old_path->rtt_variant += delta_rtt_average / 4;

            if (rtt_estimate < (int64_t)old_path->rtt_min) {
                old_path->rtt_min = rtt_estimate;

                if (old_path == cnx->path[0]) {
                    cnx->is_ack_frequency_updated = cnx->is_ack_frequency_negotiated;
                    if (!cnx->is_ack_frequency_negotiated || cnx->cnx_state != picoquic_state_ready) {
                        cnx->ack_delay_remote = picoquic_compute_ack_delay_max(old_path->rtt_min, PICOQUIC_ACK_DELAY_MIN);
                    }
                }
            }

            if (4 * old_path->rtt_variant < old_path->rtt_min &&
                old_path->rtt_min < PICOQUIC_TARGET_SATELLITE_RTT) {
                old_path->rtt_variant = old_path->rtt_min / 4;
            }

            old_path->retransmit_timer = old_path->smoothed_rtt + 4 * old_path->rtt_variant +
                cnx->remote_parameters.max_ack_delay;
        }
        old_path->rtt_sample = rtt_estimate;

        if (PICOQUIC_MIN_RETRANSMIT_TIMER > old_path->retransmit_timer) {
            old_path->retransmit_timer = PICOQUIC_MIN_RETRANSMIT_TIMER;
        }

        if (cnx->congestion_alg != NULL && !cnx->is_time_stamp_enabled) {
            cnx->congestion_alg->alg_notify(cnx, old_path,
                picoquic_congestion_notification_rtt_measurement,
                rtt_estimate, 0, 0, 0, current_time);
        }
    }
}

static picoquic_packet_t* picoquic_find_acked_packet(picoquic_cnx_t* cnx, uint64_t largest,
    uint64_t current_time, uint64_t ack_delay, uint64_t remote_time_stamp, picoquic_packet_context_enum pc, int* is_new_ack)
{
    picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[pc];
    picoquic_packet_t* packet = pkt_ctx->retransmit_oldest;

    /* Check whether this is a new acknowledgement */
    if (largest > pkt_ctx->highest_acknowledged || pkt_ctx->highest_acknowledged == (uint64_t)((int64_t)-1)) {
        pkt_ctx->highest_acknowledged = largest;
        pkt_ctx->highest_acknowledged_time = current_time;
        pkt_ctx->ack_of_ack_requested = 0;
        *is_new_ack = 1;

        if (ack_delay < PICOQUIC_ACK_DELAY_MAX) {
            /* if the ACK is reasonably recent, use it to update the RTT */
            /* find the stored copy of the largest acknowledged packet */

            while (packet != NULL && packet->previous_packet != NULL && packet->sequence_number < largest) {
                packet = packet->previous_packet;
            }

            if (packet == NULL || packet->sequence_number != largest) {
                /* There is no copy of this packet in store. It may have
                 * been deleted because too old, or maybe already
                 * retransmitted */
            }
            else {
                picoquic_path_t* old_path = packet->send_path;

                if (old_path != NULL) {
                    picoquic_update_path_rtt(cnx, old_path, packet->send_time, current_time, ack_delay);
                }
            }
        }
        else {
            *is_new_ack = 0;
        }
    }

    return packet;
}

static picoquic_sack_item_t* picoquic_process_ack_of_ack_range(picoquic_sack_item_t* first_sack, picoquic_sack_item_t* previous,
    uint64_t start_of_range, uint64_t end_of_range)
{
    picoquic_sack_item_t* next = (previous == NULL)? first_sack: previous->next_sack;

    while (next != NULL) {
        if (next->start_of_sack_range == start_of_range) {
            if (next == first_sack) {
                if (end_of_range < first_sack->end_of_sack_range) {
                    first_sack->start_of_sack_range = end_of_range + 1;
                }
                else {
                    first_sack->start_of_sack_range = first_sack->end_of_sack_range;
                }
            }
            else if (next->end_of_sack_range == end_of_range) {
                /* Matching range should be removed */
                previous->next_sack = next->next_sack;
                free(next);
            }
            break;
        } else if (next->end_of_sack_range > end_of_range) {
            previous = next;
            next = next->next_sack;
        }
        else {
            break;
        }
    }

    return previous;
}

int picoquic_process_ack_of_ack_frame(
    picoquic_sack_item_t* first_sack,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn)
{
    int ret;
    uint64_t largest;
    uint64_t ack_delay;
    uint64_t num_block;

    ret = picoquic_parse_ack_header(bytes, bytes_max,
        &num_block,
        &largest, &ack_delay, consumed, 0);

    if (ret == 0) {
        size_t byte_index = *consumed;
        picoquic_sack_item_t* previous_sack_item = NULL;

        /* Process each successive range */

        while (1) {
            uint64_t range;
            size_t l_range;
            uint64_t block_to_block;

            if (byte_index >= bytes_max) {
                ret = -1;
                break;
            }

            l_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &range);
            if (l_range == 0) {
                byte_index = bytes_max;
                ret = -1;
                break;
            } else {
                byte_index += l_range;
            }

            range++;
            if (largest + 1 < range) {
                DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
                ret = -1;
                break;
            }

            if (range > 0) {
                previous_sack_item = picoquic_process_ack_of_ack_range(first_sack, previous_sack_item, largest + 1 - range, largest);
            }

            if (num_block-- == 0)
                break;

            /* Skip the gap */

            if (byte_index >= bytes_max) {
                ret = -1;
                break;
            } else {
                size_t l_gap = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &block_to_block);
                if (l_gap == 0) {
                    byte_index = bytes_max;
                    ret = -1;
                    break;
                } else {
                    byte_index += l_gap;
                    block_to_block += 1; /* Add 1, since there are never 0 gaps -- see spec. */
                    block_to_block += range;
                }
            }

            if (largest < block_to_block) {
                DBG_PRINTF("ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
                    largest, range, block_to_block - range);
                ret = -1;
                break;
            }

            largest -= block_to_block;
        }

        if (ret == 0 && is_ecn) {
            if (byte_index >= bytes_max) {
                ret = -1;
            }
            else {
                for (int ecnx = 0; ecnx < 3; ecnx++) {
                    uint64_t ecn;
                    size_t l_ecn = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &ecn);
                    if (l_ecn == 0) {
                        byte_index = bytes_max;
                        ret = -1;
                        break;
                    }
                    else {
                        byte_index += l_ecn;
                    }
                }
            }
        }

        *consumed = byte_index;
    }

    return ret;
}

int picoquic_check_frame_needs_repeat(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, int* no_need_to_repeat)
{
    int ret = 0;
    int fin;
    size_t data_length;
    uint64_t stream_id;
    uint64_t offset;
    uint64_t maxdata;
    uint64_t max_stream_rank;
    picoquic_stream_head_t* stream = NULL;
    size_t consumed = 0;

    *no_need_to_repeat = 0;

    if (PICOQUIC_IN_RANGE(bytes[0], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
        ret = picoquic_parse_stream_header(bytes, bytes_max,
            &stream_id, &offset, &data_length, &fin, &consumed);

        if (ret == 0) {
            stream = picoquic_find_stream(cnx, stream_id);
            if (stream == NULL) {
                /* the stream was destroyed. That only happens if it was fully acked. */
                *no_need_to_repeat = 1;
            }
            else {
                if (stream->reset_sent) {
                    *no_need_to_repeat = 1;
                }
                else {
                    /* Check whether the ack was already received */
                    *no_need_to_repeat = picoquic_check_sack_list(&stream->first_sack_item, offset, offset + data_length);
                }
            }
        }
    }
    else {
        uint8_t* p_last_byte = bytes + bytes_max;
        switch (bytes[0]) {
        case picoquic_frame_type_max_data:
            if ((bytes = picoquic_frames_varint_decode(bytes + 1, p_last_byte, &maxdata)) == NULL) {
                /* Malformed frame, do not retransmit */
                *no_need_to_repeat = 1;
            }
            else if (maxdata < cnx->maxdata_local) {
                /* already updated */
                *no_need_to_repeat = 1;
            }
            break;
        case picoquic_frame_type_max_stream_data:
            if ((bytes = picoquic_frames_varint_decode(bytes + 1, p_last_byte, &stream_id)) == NULL ||
                (bytes = picoquic_frames_varint_decode(bytes, p_last_byte, &maxdata)) == NULL) {
                /* Malformed frame, do not retransmit */
                *no_need_to_repeat = 1;
            }
            else if ((stream = picoquic_find_stream(cnx, stream_id)) == NULL) {
                /* No such stream do not retransmit */
                *no_need_to_repeat = 1;
            }
            else if (stream->fin_received || stream->reset_received || stream->stop_sending_sent) {
                /* Stream stopped, no need to increase the window */
                *no_need_to_repeat = 1;
            }
            else if (maxdata < stream->maxdata_local) {
                /* Stream max data already increased */
                *no_need_to_repeat = 1;
            }
            break;
        case picoquic_frame_type_max_streams_bidir:
        case picoquic_frame_type_max_streams_unidir:
            if ((bytes = picoquic_frames_varint_decode(bytes + 1, p_last_byte, &max_stream_rank)) == NULL) {
                /* Malformed frame, do not retransmit */
                *no_need_to_repeat = 1;
            }
            else if (bytes[0] == picoquic_frame_type_max_streams_bidir &&
                cnx->max_stream_id_bidir_local > STREAM_ID_FROM_RANK(max_stream_rank, !cnx->client_mode, 0)) {
                /* Streams bidir already increased */
                *no_need_to_repeat = 1;
            }
            else if (cnx->max_stream_id_unidir_local > STREAM_ID_FROM_RANK(max_stream_rank, !cnx->client_mode, 1)) {
                /* Streams unidir already increased */
                *no_need_to_repeat = 1;
            }
            break;
        case picoquic_frame_type_data_blocked:
            if ((bytes = picoquic_frames_varint_decode(bytes + 1, p_last_byte, &maxdata)) == NULL) {
                /* Malformed frame, do not retransmit */
                *no_need_to_repeat = 1;
            }
            else if (maxdata < cnx->maxdata_remote) {
                /* already updated */
                *no_need_to_repeat = 1;
            }
            else {
                /* Only repeat if the sent flag is still there */
                *no_need_to_repeat = !cnx->sent_blocked_frame;
            }
            break;
        case picoquic_frame_type_streams_blocked_bidir:
            if ((bytes = picoquic_frames_varint_decode(bytes + 1, p_last_byte, &max_stream_rank)) == NULL) {
                /* Malformed frame, do not retransmit */
                *no_need_to_repeat = 1;
            }
            else if (cnx->max_stream_id_bidir_remote > STREAM_ID_FROM_RANK(max_stream_rank, !cnx->client_mode, 0)) {
                /* Streams bidir already increased */
                *no_need_to_repeat = 1;
            }
            else {
                /* Only repeat if the sent flag is still there */
                *no_need_to_repeat = !cnx->stream_blocked_bidir_sent;
            }
            break;
        case picoquic_frame_type_streams_blocked_unidir:
            if ((bytes = picoquic_frames_varint_decode(bytes + 1, p_last_byte, &max_stream_rank)) == NULL) {
                /* Malformed frame, do not retransmit */
                *no_need_to_repeat = 1;
            }
            else if (cnx->max_stream_id_unidir_remote > STREAM_ID_FROM_RANK(max_stream_rank, !cnx->client_mode, 1)) {
                /* Streams unidir already increased */
                *no_need_to_repeat = 1;
            }
            else {
                /* Only repeat if the sent flag is still there */
                *no_need_to_repeat = !cnx->stream_blocked_unidir_sent;
            }
            break;
        case picoquic_frame_type_stream_data_blocked:
            if ((bytes = picoquic_frames_varint_decode(bytes + 1, p_last_byte, &stream_id)) == NULL ||
                (bytes = picoquic_frames_varint_decode(bytes, p_last_byte, &maxdata)) == NULL) {
                /* Malformed frame, do not retransmit */
                *no_need_to_repeat = 1;
            }
            else if ((stream = picoquic_find_stream(cnx, stream_id)) == NULL) {
                /* No such stream do not retransmit */
                *no_need_to_repeat = 1;
            }
            else if (stream->fin_requested || stream->reset_requested || stream->fin_sent || stream->reset_sent) {
                /* Stream stopped, no need to increase the window */
                *no_need_to_repeat = 1;
            }
            else if (maxdata < stream->maxdata_remote || !stream->stream_data_blocked_sent) {
                /* Stream max data already increased */
                *no_need_to_repeat = 1;
            }
            break;
        case picoquic_frame_type_path_challenge:
            /* Path challenge repeat follows its own logic. */
            *no_need_to_repeat = 1;
            break;
        default: {
            uint64_t frame_id64;
            *no_need_to_repeat = 0;
            if ((bytes = picoquic_frames_varint_decode(bytes, bytes + bytes_max, &frame_id64)) != NULL) {
                switch (frame_id64) {
                case picoquic_frame_type_ack_frequency: {
                    uint64_t seq;
                    uint64_t packets;
                    uint64_t microsec;

                    if ((bytes = picoquic_parse_ack_frequency_frame(bytes, bytes + bytes_max, &seq, &packets, &microsec)) != NULL &&
                        seq == cnx->ack_frequency_sequence_local) {
                        *no_need_to_repeat = 1;
                    }
                    break;
                }
                case picoquic_frame_type_time_stamp:
                    *no_need_to_repeat = 1;
                    break;
                default:
                    break;
                }
            }
            break;
        }
        }
    }

    return ret;
}

static int picoquic_process_ack_of_stream_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, size_t* consumed)
{
    int ret;
    int fin;
    size_t data_length;
    uint64_t stream_id;
    uint64_t offset;
    picoquic_stream_head_t* stream = NULL;

    /* skip stream frame */
    ret = picoquic_parse_stream_header(bytes, bytes_max,
        &stream_id, &offset, &data_length, &fin, consumed);

    if (ret == 0) {
        *consumed += data_length;

        /* record the ack range for the stream */
        stream = picoquic_find_stream(cnx, stream_id);
        if (stream != NULL) {
            (void)picoquic_update_sack_list(&stream->first_sack_item,
                offset, offset + data_length - 1);

            picoquic_delete_stream_if_closed(cnx, stream);
        }
    }

    return ret;
}

void picoquic_process_possible_ack_of_ack_frame(picoquic_cnx_t* cnx, picoquic_packet_t* p, uint64_t current_time)
{
    int ret = 0;
    size_t byte_index;
    int frame_is_pure_ack = 0;
    size_t frame_length = 0;

    if (p->ptype == picoquic_packet_0rtt_protected) {
        cnx->nb_zero_rtt_acked++;
    }

    byte_index = p->offset;

    while (ret == 0 && byte_index < p->length) {
        if (p->bytes[byte_index] == picoquic_frame_type_ack) {
            ret = picoquic_process_ack_of_ack_frame(&cnx->pkt_ctx[p->pc].first_sack_item,
                &p->bytes[byte_index], p->length - byte_index, &frame_length, 0);
            byte_index += frame_length;
        } else if (p->bytes[byte_index] == picoquic_frame_type_ack_ecn) {
            ret = picoquic_process_ack_of_ack_frame(&cnx->pkt_ctx[p->pc].first_sack_item,
                &p->bytes[byte_index], p->length - byte_index, &frame_length, 1);
            byte_index += frame_length;
        }
        else if (PICOQUIC_IN_RANGE(p->bytes[byte_index], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            ret = picoquic_process_ack_of_stream_frame(cnx, &p->bytes[byte_index], p->length - byte_index, &frame_length);
            byte_index += frame_length;
            if (p->send_path != NULL && p->send_time > p->send_path->last_time_acked_data_frame_sent) {
                p->send_path->last_time_acked_data_frame_sent = p->send_time;
            }
        } else {
            if (PICOQUIC_IN_RANGE(p->bytes[byte_index], picoquic_frame_type_datagram, picoquic_frame_type_datagram_l) &&
                p->send_path != NULL && p->send_time > p->send_path->last_time_acked_data_frame_sent) {
                p->send_path->last_time_acked_data_frame_sent = p->send_time;
            }

            ret = picoquic_skip_frame(&p->bytes[byte_index],
                p->length - byte_index, &frame_length, &frame_is_pure_ack);
            byte_index += frame_length;
        }
    }
}

static int picoquic_process_ack_range(
    picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t highest, uint64_t range, picoquic_packet_t** ppacket,
    uint64_t current_time)
{
    picoquic_packet_t* p = *ppacket;
    int ret = 0;

    /* Compare the range to the retransmit queue */
    while (p != NULL && range > 0) {
        if (p->sequence_number > highest) {
            p = p->next_packet;
        } else {
            if (p->sequence_number == highest) {
                /* TODO: RTT Estimate */
                picoquic_packet_t* next = p->next_packet;
                picoquic_path_t * old_path = p->send_path;

                if (p->is_ack_trap) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, picoquic_frame_type_ack);
                    break;
                }

                if (old_path != NULL) {
                    old_path->delivered += p->length;

                    if (cnx->congestion_alg != NULL) {
#if 0
                        if (cnx->pkt_ctx[pc].nb_retransmit >= 2 && p->sequence_number >= cnx->pkt_ctx[pc].retransmit_sequence) {
                            cnx->congestion_alg->alg_notify(cnx, old_path,
                                picoquic_congestion_notification_reset,
                                0, 0, p->length, 0, current_time);
                        }
#endif
                        cnx->congestion_alg->alg_notify(cnx, old_path,
                            picoquic_congestion_notification_acknowledgement,
                            0, 0, p->length, 0, current_time);
                    }


                    /* If packet is larger than the current MTU, update the MTU */
                    if ((p->length + p->checksum_overhead) == old_path->send_mtu) {
                        old_path->nb_mtu_losses = 0;
                    } else if ((p->length + p->checksum_overhead) > old_path->send_mtu) {
                        old_path->send_mtu = p->length + p->checksum_overhead;
                        old_path->mtu_probe_sent = 0;
                    }
                }

                /* If the packet contained an ACK frame, perform the ACK of ACK pruning logic */
                picoquic_process_possible_ack_of_ack_frame(cnx, p, current_time);

                /* Keep track of reception of ACK of 1RTT data */
                if (p->ptype == picoquic_packet_1rtt_protected &&
                    (cnx->cnx_state == picoquic_state_client_ready_start ||
                        cnx->cnx_state == picoquic_state_server_false_start)) {
                    /* Transition to client ready state.
                     * The handshake is complete, all the handshake packets are implicitly acknowledged */
                    picoquic_ready_state_transition(cnx, current_time);
                }

                if (cnx->pkt_ctx[pc].nb_retransmit > 0 && p->sequence_number >= cnx->pkt_ctx[pc].retransmit_sequence) {
                    /* Acknowledgement larger than retransmit number show progress */
                    cnx->pkt_ctx[pc].nb_retransmit = 0;
                }

                (void)picoquic_dequeue_retransmit_packet(cnx, p, 1);
                p = next;
            }

            range--;
            highest--;
        }
    }

    *ppacket = p;
    return ret;
}

uint8_t* picoquic_decode_ack_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    const uint8_t* bytes_max, uint64_t current_time, int epoch, int is_ecn, picoquic_packet_data_t* packet_data)
{
    uint64_t num_block;
    uint64_t largest;
    uint64_t ack_delay;
    uint64_t remote_time_stamp = 0;
    size_t   consumed;
    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);
    uint64_t ecnx3[3] = { 0, 0, 0 };
    uint8_t first_byte = bytes[0];

    if (picoquic_parse_ack_header(bytes, bytes_max-bytes, &num_block,
        &largest, &ack_delay, &consumed,
        cnx->remote_parameters.ack_delay_exponent) != 0) {
        bytes = NULL;
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
    } else if (largest >= cnx->pkt_ctx[pc].send_sequence) {
        bytes = NULL;
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
    } else {
        bytes += consumed;

        /* Attempt to update the RTT */
        int is_new_ack = 0;
        picoquic_packet_t* top_packet = picoquic_find_acked_packet(cnx, largest, current_time, ack_delay, remote_time_stamp, pc, &is_new_ack);
        picoquic_packet_t* p_retransmitted_previous = cnx->pkt_ctx[pc].retransmitted_newest;
        
        if (top_packet != NULL && is_new_ack) {
            if (cnx->pkt_ctx[pc].latest_time_acknowledged < top_packet->send_time) {
                cnx->pkt_ctx[pc].latest_time_acknowledged = top_packet->send_time;
            }
            cnx->latest_progress_time = current_time;

            if (packet_data != NULL) {
                packet_data->acked_path = top_packet->send_path;
                packet_data->last_ack_delay = ack_delay;
                packet_data->largest_sent_time = top_packet->send_time;
                packet_data->delivered_prior = top_packet->delivered_prior;
                packet_data->delivered_time_prior = top_packet->delivered_time_prior;
                packet_data->delivered_sent_prior = top_packet->delivered_sent_prior;
                packet_data->rs_is_path_limited = top_packet->delivered_app_limited;
            }
        }

        do {
            uint64_t range;
            uint64_t block_to_block;

            if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &range)) == NULL) {
                DBG_PRINTF("Malformed ACK RANGE, %d blocks remain.\n", (int)num_block);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            }

            range ++;
            if (largest + 1 < range) {
                DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            }

            if (picoquic_process_ack_range(cnx, pc, largest, range, &top_packet, current_time) != 0) {
                bytes = NULL;
                break;
            }

            if (range > 0) {
                p_retransmitted_previous = picoquic_check_spurious_retransmission(cnx, largest + 1 - range, largest, current_time, pc, p_retransmitted_previous);
            }

            if (num_block-- == 0)
                break;

            /* Skip the gap */
            if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &block_to_block)) == NULL) {
                DBG_PRINTF("    Malformed ACK GAP, %d blocks remain.\n", (int)num_block);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            }

            block_to_block += 1; /* add 1, since zero is ruled out by varint, see spec. */
            block_to_block += range;

            if (largest < block_to_block) {
                DBG_PRINTF("ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
                    largest, range, block_to_block - range);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, first_byte);
                bytes = NULL;
                break;
            }

            largest -= block_to_block;
        } while (bytes != NULL);

        picoquic_dequeue_old_retransmitted_packets(cnx, pc);

    }

    if (bytes != 0 && is_ecn) {
        for (int ecnx = 0; bytes != NULL && ecnx < 3; ecnx++) {
            bytes = picoquic_frames_varint_decode(bytes, bytes_max, &ecnx3[ecnx]);
        }
    }

    if (bytes != 0 && is_ecn) {
        if (ecnx3[0] > cnx->pkt_ctx[pc].ecn_ect0_total_remote) {
            cnx->pkt_ctx[pc].ecn_ect0_total_remote = ecnx3[0];
        }
        if (ecnx3[1] > cnx->pkt_ctx[pc].ecn_ect1_total_remote) {
            cnx->pkt_ctx[pc].ecn_ect1_total_remote = ecnx3[1];
        }
        if (ecnx3[2] > cnx->pkt_ctx[pc].ecn_ce_total_remote) {
            cnx->pkt_ctx[pc].ecn_ce_total_remote = ecnx3[2];

            cnx->congestion_alg->alg_notify(cnx, cnx->path[0],
                picoquic_congestion_notification_ecn_ec,
                0, 0, 0, cnx->pkt_ctx[pc].first_sack_item.end_of_sack_range, current_time);
        }
    }

    return bytes;
}

uint8_t * picoquic_format_ack_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t * bytes_max, 
    int * more_data, uint64_t current_time, picoquic_packet_context_enum pc)
{
    uint64_t num_block = 0;
    picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[pc];
    picoquic_sack_item_t* next_sack = pkt_ctx->first_sack_item.next_sack;
    uint64_t ack_delay = 0;
    uint64_t ack_range = 0;
    uint64_t ack_gap = 0;
    uint64_t lowest_acknowledged = 0;
    int is_ecn = cnx->pkt_ctx[pc].sending_ecn_ack;
    uint8_t* after_stamp = bytes;
    int has_time_stamp = (pc == picoquic_packet_context_application && cnx->is_time_stamp_sent);
    uint8_t ack_type_byte = ((is_ecn) ? picoquic_frame_type_ack_ecn : picoquic_frame_type_ack);

    /* Check that there something to acknowledge */
    if (pkt_ctx->first_sack_item.start_of_sack_range != UINT64_MAX) {
        uint8_t* num_block_byte = NULL;

        if (current_time > pkt_ctx->time_stamp_largest_received) {
            ack_delay = current_time - pkt_ctx->time_stamp_largest_received;
            ack_delay >>= cnx->local_parameters.ack_delay_exponent;
        }

        if (has_time_stamp) {
            bytes = picoquic_format_time_stamp_frame(cnx, bytes, bytes_max, more_data, current_time);
            after_stamp = bytes;
        }

        if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, ack_type_byte)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, pkt_ctx->first_sack_item.end_of_sack_range)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, ack_delay)) != NULL) {
            /* Reserve one byte for the number of blocks */
            num_block_byte = bytes++;
            /* Encode the size of the first ack range */
            ack_range = pkt_ctx->first_sack_item.end_of_sack_range - pkt_ctx->first_sack_item.start_of_sack_range;
            bytes = picoquic_frames_varint_encode(bytes, bytes_max, ack_range);
        }

        if (bytes == NULL || num_block_byte == NULL) {
            bytes = after_stamp;
            *more_data = 1;
        }
        else {
            /* Set the lowest acknowledged */
            lowest_acknowledged = pkt_ctx->first_sack_item.start_of_sack_range;
            /* Encode the ack blocks that fit in the allocated space */
            while (num_block < 32 && next_sack != NULL) {
                uint8_t* bytes_start_range = bytes;

                ack_gap = lowest_acknowledged - next_sack->end_of_sack_range - 2; /* per spec */
                ack_range = next_sack->end_of_sack_range - next_sack->start_of_sack_range;

                if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, ack_gap)) == NULL ||
                    (bytes = picoquic_frames_varint_encode(bytes, bytes_max, ack_range)) == NULL) {
                    bytes = bytes_start_range;
                    *more_data = 1;
                    break;
                }
                else {
                    lowest_acknowledged = next_sack->start_of_sack_range;
                    next_sack = next_sack->next_sack;
                    num_block++;
                }
            }
            /* When numbers are lower than 64, varint encoding fits on one byte */
            *num_block_byte = (uint8_t)num_block;

            /* Remember the ACK value and time */
            pkt_ctx->highest_ack_sent = pkt_ctx->first_sack_item.end_of_sack_range;
            pkt_ctx->highest_ack_sent_time = current_time;
        }

        if (bytes > after_stamp && is_ecn) {
            /* Try to encode the ECN bytes */
            uint8_t* bytes_ecn = bytes;
            if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, cnx->pkt_ctx[pc].ecn_ect0_total_local)) == NULL ||
                (bytes = picoquic_frames_varint_encode(bytes, bytes_max, cnx->pkt_ctx[pc].ecn_ect1_total_local)) == NULL ||
                (bytes = picoquic_frames_varint_encode(bytes, bytes_max, cnx->pkt_ctx[pc].ecn_ce_total_local)) == NULL)
            {
                bytes = bytes_ecn;
                *more_data = 1;
                *after_stamp = picoquic_frame_type_ack;
            }
        }
    }

    if (bytes > after_stamp) {
        pkt_ctx->ack_needed = 0;
        pkt_ctx->ack_after_fin = 0;
    }

    return bytes;
}

void picoquic_set_ack_needed(picoquic_cnx_t* cnx, uint64_t current_time, picoquic_packet_context_enum pc)
{
    if (!cnx->pkt_ctx[pc].ack_needed) {
        cnx->pkt_ctx[pc].ack_needed = 1;
        cnx->pkt_ctx[pc].time_oldest_unack_packet_received = current_time;
    }
}

int picoquic_is_ack_needed(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t * next_wake_time, picoquic_packet_context_enum pc)
{
    int ret = 0;
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];

    if (pkt_ctx->ack_needed) {
        if (pc != picoquic_packet_context_application || pkt_ctx->ack_after_fin) {
            ret = 1;
        }
        else
        {
            uint64_t ack_gap = (pkt_ctx->first_sack_item.end_of_sack_range < 128) ? 2 : cnx->ack_gap_remote;
            if (pkt_ctx->highest_ack_sent + ack_gap <= pkt_ctx->first_sack_item.end_of_sack_range ||
                pkt_ctx->time_oldest_unack_packet_received + cnx->ack_delay_remote <= current_time) {
                ret = 1;
            }
            else{
                if (pkt_ctx->time_oldest_unack_packet_received + cnx->ack_delay_remote < *next_wake_time) {
                    *next_wake_time = pkt_ctx->time_oldest_unack_packet_received + cnx->ack_delay_remote;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_FRAME);
                }
            }
        }
    }
    else if (pkt_ctx->highest_ack_sent + 8 <= pkt_ctx->first_sack_item.end_of_sack_range &&
        pkt_ctx->highest_ack_sent_time + cnx->ack_delay_remote <= current_time) {
        /* Force sending an ack-of-ack from time to time, as a low priority action */
        if (pkt_ctx->first_sack_item.end_of_sack_range == (uint64_t)((int64_t)-1)) {
            ret = 0;
        }
        else {
            ret = 1;
        }
    }
    return ret;
}

/*
 * Connection close frame
 */

uint8_t * picoquic_format_connection_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, uint8_t* bytes_max, int * more_data, int * is_pure_ack)
{
    uint8_t* bytes0 = bytes;

    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_connection_close)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, cnx->local_error)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, cnx->offending_frame_type)) != NULL &&
        (bytes = picoquic_frames_uint8_encode(bytes, bytes_max, 0)) != NULL) {
        *is_pure_ack = 0;
    }
    else {
        bytes = bytes0;
        *more_data = 1;
    }
    return bytes;
}

uint8_t* picoquic_decode_connection_close_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t error_code = 0;
    bytes = picoquic_frames_varint_decode(bytes + 1, bytes_max, &error_code);
    cnx->remote_error = (uint16_t)error_code;

    if (bytes == NULL ||
        (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) == NULL ||
        (bytes = picoquic_frames_length_data_skip(bytes, bytes_max)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_connection_close);
    }
    else {
        cnx->cnx_state = (cnx->cnx_state < picoquic_state_client_ready_start || cnx->crypto_context[picoquic_epoch_1rtt].aead_decrypt == NULL) ? picoquic_state_disconnected : picoquic_state_closing_received;

        if (cnx->callback_fn) {
            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
        }
    }

    return bytes;
}

/*
 * Application close frame
 */

uint8_t * picoquic_format_application_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack)
{
    uint8_t* bytes0 = bytes;

    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_application_close)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, cnx->local_error)) != NULL &&
        (bytes = picoquic_frames_uint8_encode(bytes, bytes_max, 0)) != NULL) {
        *is_pure_ack = 0;
    }
    else {
        bytes = bytes0;
        *more_data = 1;
    }
    return bytes;
}

uint8_t* picoquic_decode_application_close_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t error_code = 0;
    bytes = picoquic_frames_varint_decode(bytes + 1, bytes_max, &error_code);
    cnx->remote_application_error = (uint16_t)error_code;

    if (bytes == NULL ||
        /* TODO, maybe: skip frame type for compatibility with draft-13 */
        (bytes = picoquic_frames_length_data_skip(bytes, bytes_max)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
            picoquic_frame_type_application_close);
    }
    else {
        cnx->cnx_state = (cnx->cnx_state < picoquic_state_client_ready_start) ? picoquic_state_disconnected : picoquic_state_closing_received;
        if (cnx->callback_fn) {
            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_application_close, cnx->callback_ctx, NULL);
        }
    }

    return bytes;
}



/*
 * Max data frame
 */

#define PICOQUIC_MAX_MAXDATA ((uint64_t)((int64_t)-1))
#define PICOQUIC_MAX_MAXDATA_1K (PICOQUIC_MAX_MAXDATA >> 10)
#define PICOQUIC_MAX_MAXDATA_1K_MASK (PICOQUIC_MAX_MAXDATA << 10)

uint8_t * picoquic_format_max_data_frame(picoquic_cnx_t* cnx, uint8_t * bytes, uint8_t * bytes_max,
    int * more_data, int * is_pure_ack, uint64_t maxdata_increase)
{
    uint8_t * bytes0 = bytes;

    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_max_data)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, cnx->maxdata_local + maxdata_increase)) != NULL) {
        cnx->maxdata_local = (cnx->maxdata_local + maxdata_increase);
        *is_pure_ack = 0;
    }
    else {
        *more_data = 1;
        bytes = bytes0;
    }

    return bytes;
}

uint8_t* picoquic_decode_max_data_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t maxdata;

    if ((bytes = picoquic_frames_varint_decode(bytes+1, bytes_max, &maxdata)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_max_data);
    } else if (maxdata > cnx->maxdata_remote) {
        cnx->maxdata_remote = maxdata;
        cnx->sent_blocked_frame = 0;
    }

    return bytes;
}

/*
 * Max stream data frame
 */

uint8_t* picoquic_format_max_stream_data_frame(picoquic_stream_head_t* stream, uint8_t* bytes, uint8_t* bytes_max,
    int* more_data, int* is_pure_ack, uint64_t new_max_data)
{
    uint8_t* bytes0 = bytes;

    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_max_stream_data)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, stream->stream_id)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, new_max_data)) != NULL) {
        stream->maxdata_local = new_max_data;
        *is_pure_ack = 0;
    }
    else {
        *more_data = 1;
        bytes = bytes0;
    }

    return bytes;
}


uint8_t* picoquic_decode_max_stream_data_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t stream_id;
    uint64_t maxdata = 0;
    picoquic_stream_head_t* stream = NULL;

    if ((bytes = picoquic_frames_varint_decode(bytes + 1, bytes_max, &stream_id)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &maxdata)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_max_stream_data);
    }
    else if ((stream = picoquic_find_stream(cnx, stream_id)) == NULL) {
        /* Maybe not an error if the stream is already closed, so just be tolerant */
        stream = picoquic_create_missing_streams(cnx, stream_id, 1);
    }
    
    if (stream != NULL && maxdata > stream->maxdata_remote) {
        /* TODO: call back if the stream was blocked? */
        stream->maxdata_remote = maxdata;
    }


    return bytes;
}

uint8_t * picoquic_format_required_max_stream_data_frames(picoquic_cnx_t* cnx,
    uint8_t* bytes, uint8_t * bytes_max, int * more_data, int * is_pure_ack)
{
    uint8_t* bytes0;
    picoquic_stream_head_t* stream = picoquic_first_stream(cnx);

    while (stream != NULL) {
        if (!stream->fin_received) {
            uint64_t new_window = picoquic_cc_increased_window(cnx, stream->maxdata_local);

            if (!stream->reset_received && 2 * stream->consumed_offset > stream->maxdata_local) {
                bytes0 = bytes;

                if ((bytes = picoquic_format_max_stream_data_frame(stream, bytes, bytes_max, more_data, is_pure_ack, stream->maxdata_local + new_window)) == bytes0) {
                    /* not enough space for this frame. */
                    break;
                }
            }
        }
        stream = picoquic_next_stream(stream);
    }

    if (stream == NULL) {
        cnx->max_stream_data_needed = 0;
    }

    return bytes;
}


/*
 * Max stream ID frames
 */

uint8_t * picoquic_format_max_streams_frame_if_needed(picoquic_cnx_t* cnx,
    uint8_t* bytes, uint8_t * bytes_max, int * more_data, int * is_pure_ack)
{
    uint8_t* bytes0 = bytes;

    if (cnx->max_stream_id_bidir_local_computed + 
        (cnx->local_parameters.initial_max_stream_id_bidir >> 1) > cnx->max_stream_id_bidir_local) {
        uint64_t new_bidir_local = cnx->max_stream_id_bidir_local +
            4 * STREAM_RANK_FROM_ID(cnx->local_parameters.initial_max_stream_id_bidir) + 4;
        if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_max_streams_bidir)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, STREAM_RANK_FROM_ID(new_bidir_local))) != NULL) {
            cnx->max_stream_id_bidir_local = new_bidir_local;
            *is_pure_ack = 0;
            bytes0 = bytes;
        } else {
            *more_data = 1;
            bytes = bytes0;
        }
    }
    
    if (cnx->max_stream_id_unidir_local_computed +
        (cnx->local_parameters.initial_max_stream_id_unidir >> 1) > cnx->max_stream_id_unidir_local) {
        uint64_t new_unidir_local = cnx->max_stream_id_unidir_local + cnx->local_parameters.initial_max_stream_id_unidir + 4;

        if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_max_streams_unidir)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, STREAM_RANK_FROM_ID(new_unidir_local))) != NULL) {
            cnx->max_stream_id_unidir_local = new_unidir_local;
            *is_pure_ack = 0;
        }
        else {
            *more_data = 1;
            bytes = bytes0;
        }
    }

    return bytes;
}

void picoquic_update_max_stream_ID_local(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    if (cnx->client_mode != IS_CLIENT_STREAM_ID(stream->stream_id) && !stream->max_stream_updated) {
        /* This is a remotely initiated stream */
        if (stream->consumed_offset >= stream->fin_offset && (stream->fin_received || stream->reset_received)) {
            /* Receive is complete */
            if (IS_BIDIR_STREAM_ID(stream->stream_id)) {
                if (stream->fin_sent || stream->reset_sent)
                {
                    /* Sending is complete */
                    stream->max_stream_updated = 1;
                    cnx->max_stream_id_bidir_local_computed += 4;
                }
            } else {
                /* No need to check receive complete on uni directional streams */
                stream->max_stream_updated = 1;
                cnx->max_stream_id_unidir_local_computed += 4;
            }
        }
    }
}

uint8_t* picoquic_decode_max_streams_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max, int max_streams_frame_type)
{
    uint64_t max_stream_rank;

    if ((bytes = picoquic_frames_varint_decode(bytes + 1, bytes_max, &max_stream_rank)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, max_streams_frame_type);
    }
    else {
        uint64_t max_stream_id;
        if (max_streams_frame_type == picoquic_frame_type_max_streams_bidir) {
            /* Bidir */
            max_stream_id = STREAM_ID_FROM_RANK(max_stream_rank, !cnx->client_mode, 0);
            if (max_stream_id > cnx->max_stream_id_bidir_remote) {
                picoquic_add_output_streams(cnx, cnx->max_stream_id_bidir_remote, max_stream_id, 1);
                cnx->max_stream_id_bidir_remote = max_stream_id;
                cnx->stream_blocked_bidir_sent = 0;
            }
        }
        else {
            /* Unidir */
            max_stream_id = STREAM_ID_FROM_RANK(max_stream_rank, !cnx->client_mode, 1);
            if (max_stream_id > cnx->max_stream_id_unidir_remote) {
                picoquic_add_output_streams(cnx, cnx->max_stream_id_unidir_remote, max_stream_id, 0);
                cnx->max_stream_id_unidir_remote = max_stream_id;
                cnx->stream_blocked_unidir_sent = 0;
            }
        }

        if (max_stream_id >= (1ull << 62)) {
            (void)picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR, max_streams_frame_type);
            bytes = NULL;
        }
    }

    return bytes;
}

/* Common code for datagrams and misc frames
 */

uint8_t * picoquic_format_first_misc_or_dg_frame(uint8_t* bytes, uint8_t * bytes_max, int * more_data, int * is_pure_ack,
    picoquic_misc_frame_header_t** first, picoquic_misc_frame_header_t** last)
{
    picoquic_misc_frame_header_t* misc_frame = *first;

    if (bytes + misc_frame->length > bytes_max) {
        *more_data = 1;
    } else {
        uint8_t* frame = ((uint8_t*)misc_frame) + sizeof(picoquic_misc_frame_header_t);
        memcpy(bytes, frame, misc_frame->length);
        bytes += misc_frame->length;
        *is_pure_ack &= misc_frame->is_pure_ack;
        picoquic_delete_misc_or_dg(first, last, *first);
    }

    return bytes;
}

/*
 * Sending of miscellaneous frames
 */

uint8_t* picoquic_format_first_misc_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack)
{
    return picoquic_format_first_misc_or_dg_frame(bytes, bytes_max, more_data, is_pure_ack, &cnx->first_misc_frame, &cnx->last_misc_frame);
}

/*
 * Path Challenge and Response frames
 */

uint8_t* picoquic_format_path_challenge_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack,
    uint64_t challenge)
{
    uint8_t* bytes0 = 0;
    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_path_challenge)) != NULL &&
        (bytes = picoquic_frames_uint64_encode(bytes, bytes_max, challenge)) != NULL) {
        *is_pure_ack = 0;
    }
    else {
        *more_data = 1;
        bytes = bytes0;
    }
    return bytes;
}


uint8_t* picoquic_decode_path_challenge_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max,
    picoquic_path_t * path_x, struct sockaddr* addr_from, struct sockaddr* addr_to)
{
    if (bytes_max - bytes <= (int) challenge_length) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_path_challenge);
        bytes = NULL;
    } else if (path_x != NULL) {
        /*
         * Queue a response frame as response to path challenge.
         * TODO: ensure it goes out on the same path as the incoming challenge.
         */
        uint64_t challenge_response;

        bytes++;
        challenge_response = PICOPARSE_64(bytes);
        bytes += challenge_length;
        if ((addr_from == NULL || picoquic_compare_addr(addr_from, (struct sockaddr *)&path_x->peer_addr) == 0) &&
            (addr_to == NULL || picoquic_compare_addr(addr_to, (struct sockaddr *)&path_x->local_addr) == 0)) {
            path_x->challenge_response = challenge_response;
            path_x->response_required = 1;
        } else {
            DBG_PRINTF("%s", "Path challenge ignored, wrong addresses\n");
        }
    }

    return bytes;
}

uint8_t * picoquic_format_path_response_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack,
    uint64_t challenge)
{
    uint8_t* bytes0 = 0;
    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_path_response)) != NULL &&
        (bytes = picoquic_frames_uint64_encode(bytes, bytes_max, challenge)) != NULL) {
        *is_pure_ack = 0;
    }
    else {
        *more_data = 1;
        bytes = bytes0;
    }
    return bytes;
}


uint8_t* picoquic_decode_path_response_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t response;

    if ((bytes = picoquic_frames_uint64_decode(bytes+1, bytes_max, &response)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_path_response);

    } else {
        int found_challenge = 0;

        /*
         * Check that the challenge corresponds to something that was sent locally
         */
        for (int i = 0; i < cnx->nb_paths; i++) {
            for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
                if (response == cnx->path[i]->challenge[ichal]) {
                    found_challenge = 1;
                    break;
                }
            }

            if (found_challenge) {
                cnx->path[i]->challenge_verified = 1;
                break;
            }
        }
    }

    return bytes;
}


uint8_t* picoquic_decode_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, 
            picoquic_frame_type_data_blocked);
    }
    return bytes;
}


uint8_t* picoquic_decode_stream_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    /* TODO: check that the stream number is valid */
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) == NULL ||
        (bytes = picoquic_frames_varint_skip(bytes,   bytes_max)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, 
            picoquic_frame_type_stream_data_blocked);
    }
    return bytes;
}


uint8_t* picoquic_decode_streams_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max, uint8_t frame_id)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, 
            frame_id);
    }
    return bytes;
}


static uint8_t* picoquic_skip_0len_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t frame = bytes[0];
    do {
        bytes++;
    } while (bytes < bytes_max && *bytes == frame);
    return bytes;
}

/* Handling of Handshake Done frame. 
 * The decode function is defined here, as well as a queue function.
 * There is no prepare function or skip function for this single byte frame.
 */
uint8_t* picoquic_decode_handshake_done_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint64_t current_time)
{
    if (!cnx->client_mode) {
        DBG_PRINTF("Handshake done (0x%x) not expected from client", bytes[0]);
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, bytes[0]);
        bytes = NULL;
    }
    else {
        bytes++;

        /* The connection is now confirmed */
        if (cnx->cnx_state == picoquic_state_client_ready_start) {
            /* Transition to client ready state.
             * The handshake is complete, all the handshake packets are implicitly acknowledged */
            picoquic_ready_state_transition(cnx, current_time);
        }
        else if (cnx->cnx_state < picoquic_state_client_ready_start) {
            DBG_PRINTF("Handshake done (0x%x) not expected in state %d", bytes[0], cnx->cnx_state);
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, picoquic_frame_type_handshake_done);
            bytes = NULL;
        }
    }
    return bytes;
}

int picoquic_queue_handshake_done_frame(picoquic_cnx_t* cnx)
{
    uint8_t frame_buffer = picoquic_frame_type_handshake_done;

    return picoquic_queue_misc_or_dg_frame(cnx, &cnx->first_datagram, &cnx->last_datagram,
            &frame_buffer, 1, 0);
}

/* Handling of datagram frames.
 * We follow the spec in
 * https://datatracker.ietf.org/doc/draft-pauly-quic-datagram/?include_text=1
 */

uint8_t* picoquic_skip_datagram_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t frame_id = *bytes++;
    unsigned int has_length = frame_id & 1;
    uint64_t length = 0;

    if (bytes != NULL) {
        if (has_length) {
            bytes = picoquic_frames_varint_decode(bytes, bytes_max, &length);
        }
        else {
            length = bytes_max - bytes ;
        }

        if (bytes != NULL) {
            bytes += length;
            if (bytes > bytes_max) {
                bytes = NULL;
            }
        }
    }

    return bytes;
}

uint8_t* picoquic_decode_datagram_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t frame_id = *bytes++;
    unsigned int has_length = frame_id & 1;
    uint64_t length = 0;

    if (has_length) {
        if (bytes != NULL && (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &length)) == NULL) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                frame_id);
        }
        if (bytes != NULL && bytes + length > bytes_max) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                frame_id);
            bytes = NULL;
        }
    }
    else {
        length = bytes_max - bytes;
    }

    if (bytes != NULL) {
        if (cnx->callback_fn != NULL) {
            /* submit the data to the app */
            if (cnx->callback_fn(cnx, 0, bytes, (size_t)length, picoquic_callback_datagram,
                cnx->callback_ctx, NULL) != 0) {
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, picoquic_frame_type_datagram);
                bytes = NULL;
            }
        }

        bytes += length;
    }

    return bytes;
}

uint8_t * picoquic_format_datagram_frame(uint8_t* bytes, uint8_t* bytes_max, int* more_data, int* is_pure_ack, size_t length, const uint8_t* src)
{
    uint8_t* bytes0 = bytes;

    if ((bytes = picoquic_frames_uint8_encode(bytes, bytes_max, picoquic_frame_type_datagram_l)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, length)) != NULL &&
        bytes + length <= bytes_max) {
        memcpy(bytes, src, length);
        bytes += length;
        *is_pure_ack = 0;
    }
    else {
        *more_data = 1;
        bytes = bytes0;
    }

    return bytes;
}

int picoquic_queue_datagram_frame(picoquic_cnx_t * cnx, size_t length, const uint8_t * src)
{
    int ret;
    size_t consumed = 0;
    uint8_t frame_buffer[PICOQUIC_MAX_PACKET_SIZE];
    int more_data = 0;
    int is_pure_ack = 1;
    uint8_t * bytes_next = picoquic_format_datagram_frame(frame_buffer, frame_buffer + sizeof(frame_buffer), &more_data, &is_pure_ack, length, src);

    if ((consumed = bytes_next - frame_buffer) > 0) {
        ret = picoquic_queue_misc_or_dg_frame(cnx, &cnx->first_datagram, &cnx->last_datagram, 
            frame_buffer, consumed, 0);
    }
    else {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }

    return ret;
}

uint8_t * picoquic_format_first_datagram_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    uint8_t *bytes_max, int * more_data, int * is_pure_ack)
{
    if (bytes + cnx->first_datagram->length > bytes_max) {
        /* TODO: don't do that if this is a coalesced packet... */
        /* This datagram is not compatible with the path. Just drop. */
        picoquic_delete_misc_or_dg(&cnx->first_datagram, &cnx->last_datagram, cnx->first_datagram);
    }
    else {
        bytes = picoquic_format_first_misc_or_dg_frame(bytes, bytes_max, more_data, is_pure_ack, 
            &cnx->first_datagram, &cnx->last_datagram);
    }

    return bytes;
}

/* ACK Frequency frames 
 */
uint8_t* picoquic_skip_ack_frequency_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    /* This code assumes that the frame type is already skipped */
    if ((bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL &&
        (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL) {
        bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    }
    return bytes;
}

uint8_t* picoquic_parse_ack_frequency_frame(uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t* seq, uint64_t* packets, uint64_t* microsec)
{
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, seq)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, packets)) != NULL) {
        bytes = picoquic_frames_varint_decode(bytes, bytes_max, microsec);
    }
    return bytes;
}

uint8_t* picoquic_decode_ack_frequency_frame(uint8_t* bytes, const uint8_t* bytes_max, picoquic_cnx_t * cnx)
{
    uint64_t seq = 0;
    uint64_t packets = 0;
    uint64_t microsec = 0;

    /* This code assumes that the frame type is already skipped */
    if ((bytes = picoquic_parse_ack_frequency_frame(bytes, bytes_max, &seq, &packets, &microsec)) != NULL){
        if (!cnx->is_ack_frequency_negotiated ||
            microsec < cnx->local_parameters.min_ack_delay ||
            packets == 0) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR,
                picoquic_frame_type_ack_frequency);
            bytes = NULL;
        }
        else {
            int64_t delta = seq - cnx->ack_frequency_sequence_remote;
            if (delta > 0) {
                cnx->ack_frequency_sequence_remote = seq;
                cnx->ack_gap_remote = packets;
                cnx->ack_delay_remote = microsec;
            }
        }
    }
    return bytes;
}

uint8_t* picoquic_format_ack_frequency_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data)
{
    uint8_t* bytes0 = bytes;
    uint64_t seq = cnx->ack_frequency_sequence_local + 1;
    uint64_t ack_gap;
    uint64_t ack_delay_max;

    /* Compute the desired value of the ack frequency*/
    ack_delay_max = picoquic_compute_ack_delay_max(cnx->path[0]->rtt_min, cnx->remote_parameters.min_ack_delay);
    ack_gap = picoquic_compute_ack_gap(cnx, cnx->path[0]->bandwidth_estimate);
    
    if (ack_gap <= cnx->ack_gap_local &&
        ack_delay_max == cnx->ack_frequency_delay_local) {
        cnx->is_ack_frequency_updated = 0;
    }
    else {
        if (ack_gap < cnx->ack_gap_local) {
            ack_gap = cnx->ack_gap_local;
        }
        if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_frame_type_ack_frequency)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, seq)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, ack_gap)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, ack_delay_max)) != NULL) {
            cnx->ack_frequency_sequence_local = seq;
            cnx->ack_gap_local = ack_gap;
            cnx->ack_frequency_delay_local = ack_delay_max;
            cnx->is_ack_frequency_updated = 0;
        }
        else {
            bytes = bytes0;
            *more_data = 1;
        }
    }
    return bytes;
}

/* ACK Frequency frames
 */
uint8_t* picoquic_skip_time_stamp_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    /* This code assumes that the frame type is already skipped */
    bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    return bytes;
}

uint8_t* picoquic_parse_time_stamp_frame(uint8_t* bytes, const uint8_t* bytes_max,
    uint64_t* time_stamp)
{
    bytes = picoquic_frames_varint_decode(bytes, bytes_max, time_stamp);
    return bytes;
}

uint8_t* picoquic_decode_time_stamp_frame(uint8_t* bytes, const uint8_t* bytes_max, picoquic_cnx_t* cnx,
    picoquic_packet_data_t * packet_data)
{
    uint64_t time_stamp = 0;

    /* This code assumes that the frame type is already skipped */
    if ((bytes = picoquic_parse_time_stamp_frame(bytes, bytes_max, &time_stamp)) != NULL) {
        if (!cnx->is_time_stamp_enabled) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION,
                picoquic_frame_type_time_stamp);
            bytes = NULL;
        }
        else {
            time_stamp <<= cnx->remote_parameters.ack_delay_exponent;

            if (time_stamp > packet_data->last_time_stamp_received) {
                packet_data->last_time_stamp_received = time_stamp;
            }
        }
    }
    return bytes;
}

uint8_t* picoquic_format_time_stamp_frame(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t* bytes_max, int* more_data, uint64_t current_time)
{
    uint8_t* bytes0 = bytes;
    uint64_t time_stamp = (current_time - cnx->start_time) >> cnx->local_parameters.ack_delay_exponent;

    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_frame_type_time_stamp)) == NULL ||
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, time_stamp)) == NULL) {
        bytes = bytes0;
        *more_data = 1;
    }

    return bytes;
}

size_t picoquic_encode_time_stamp_length(picoquic_cnx_t* cnx, uint64_t current_time)
{
    uint64_t time_stamp = (current_time - cnx->start_time) >> cnx->local_parameters.ack_delay_exponent;

    return (2 + picoquic_encode_varint_length(time_stamp));
}

/*
 * Decoding of the received frames.
 *
 * In some cases, the expected frames are "restricted" to only ACK, STREAM 0 and PADDING.
 */

void process_decoded_packet_data(picoquic_cnx_t* cnx, uint64_t current_time, picoquic_packet_data_t * packet_data)
{
    if (packet_data->acked_path != NULL) {
        uint64_t one_way_delay = 0;

        if (packet_data->acked_path->rtt_sample == 0) {
            uint64_t cnx_time = current_time - cnx->start_time;
            picoquic_log_app_message(cnx, "RTT Sample = 0 after %" PRIu64 "us.", cnx_time);
        }

        if (cnx->congestion_alg != NULL && cnx->is_time_stamp_enabled && packet_data->acked_path->rtt_sample > 0) {
            if (packet_data->last_time_stamp_received > 0) {
                picoquic_update_1wd(cnx, packet_data->acked_path,
                    packet_data->largest_sent_time, packet_data->last_ack_delay, packet_data->last_time_stamp_received);
                one_way_delay = packet_data->acked_path->one_way_delay_sample;
            }

            /* CC notification of RTT are only delayed if waiting for one way delay assessment */
            cnx->congestion_alg->alg_notify(cnx, packet_data->acked_path,
                picoquic_congestion_notification_rtt_measurement,
                packet_data->acked_path->rtt_sample, one_way_delay, 0, 0, current_time);
        }
    
        picoquic_estimate_path_bandwidth(cnx, packet_data->acked_path, packet_data->largest_sent_time,
            packet_data->delivered_prior, packet_data->delivered_time_prior, packet_data->delivered_sent_prior,
            (packet_data->last_time_stamp_received == 0) ? current_time : packet_data->last_time_stamp_received,
            current_time, packet_data->rs_is_path_limited);

        picoquic_estimate_max_path_bandwidth(cnx, packet_data->acked_path, packet_data->largest_sent_time,
            (packet_data->last_time_stamp_received == 0) ? current_time : packet_data->last_time_stamp_received,
            current_time);

        if (cnx->congestion_alg != NULL && packet_data->acked_path->rtt_sample > 0) {
            cnx->congestion_alg->alg_notify(cnx, packet_data->acked_path,
                picoquic_congestion_notification_bw_measurement,
                packet_data->acked_path->rtt_sample, one_way_delay, 0, 0, current_time);
        }
    }
}

int picoquic_decode_frames(picoquic_cnx_t* cnx, picoquic_path_t * path_x, uint8_t* bytes,
    size_t bytes_maxsize, int epoch,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    uint64_t current_time)
{
    const uint8_t *bytes_max = bytes + bytes_maxsize;
    int ack_needed = 0;
    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);
    picoquic_packet_data_t packet_data;

    memset(&packet_data, 0, sizeof(packet_data));

    while (bytes != NULL && bytes < bytes_max) {
        uint8_t first_byte = bytes[0];

        if (PICOQUIC_IN_RANGE(first_byte, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            if (epoch != 1 && epoch != 3) {
                DBG_PRINTF("Data frame (0x%x), when only TLS stream is expected", first_byte);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
                bytes = NULL;
                break;
            }

            bytes = picoquic_decode_stream_frame(cnx, bytes, bytes_max, current_time);
            ack_needed = 1;

        }
        else if (first_byte == picoquic_frame_type_ack) {
            if (epoch == picoquic_epoch_0rtt) {
                DBG_PRINTF("Ack frame (0x%x) not expected in 0-RTT packet", first_byte);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
                bytes = NULL;
                break;
            }
            bytes = picoquic_decode_ack_frame(cnx, bytes, bytes_max, current_time, epoch, 0, &packet_data);
        }
        else if (first_byte == picoquic_frame_type_ack_ecn) {
            if (epoch == picoquic_epoch_0rtt) {
                DBG_PRINTF("Ack-ECN frame (0x%x) not expected in 0-RTT packet", first_byte);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
                bytes = NULL;
                break;
            }
            bytes = picoquic_decode_ack_frame(cnx, bytes, bytes_max, current_time, epoch, 1, &packet_data);
        }
        else if (epoch != picoquic_epoch_0rtt && epoch != picoquic_epoch_1rtt && first_byte != picoquic_frame_type_padding
            && first_byte != picoquic_frame_type_ping
            && first_byte != picoquic_frame_type_connection_close
            && first_byte != picoquic_frame_type_crypto_hs) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, first_byte);
            bytes = NULL;
            break;
        }
        else {
            switch (first_byte) {
            case picoquic_frame_type_padding:
                bytes = picoquic_skip_0len_frame(bytes, bytes_max);
                break;
            case picoquic_frame_type_reset_stream:
                bytes = picoquic_decode_stream_reset_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_connection_close:
                bytes = picoquic_decode_connection_close_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_application_close:
                bytes = picoquic_decode_application_close_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
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
                bytes = picoquic_skip_0len_frame(bytes, bytes_max);
                ack_needed = 1;
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
                bytes = picoquic_decode_new_connection_id_frame(cnx, bytes, bytes_max, current_time);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stop_sending:
                bytes = picoquic_decode_stop_sending_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_path_challenge:
                bytes = picoquic_decode_path_challenge_frame(cnx, bytes, bytes_max, path_x, addr_from, addr_to);
                break;
            case picoquic_frame_type_path_response:
                bytes = picoquic_decode_path_response_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_crypto_hs:
                bytes = picoquic_decode_crypto_hs_frame(cnx, bytes, bytes_max, epoch);
                ack_needed = 1;
                break;
            case picoquic_frame_type_new_token:
                bytes = picoquic_decode_new_token_frame(cnx, bytes, bytes_max, current_time, addr_to);
                ack_needed = 1;
                break;
            case picoquic_frame_type_retire_connection_id:
                /* the old code point for ACK frames, but this is taken care of in the ACK tests above */
                bytes = picoquic_decode_retire_connection_id_frame(cnx, bytes, bytes_max, current_time, path_x);
                ack_needed = 1;
                break;
            case picoquic_frame_type_handshake_done:
                bytes = picoquic_decode_handshake_done_frame(cnx, bytes, current_time);
                ack_needed = 1;
                break;
            case picoquic_frame_type_datagram:
            case picoquic_frame_type_datagram_l:
                bytes = picoquic_decode_datagram_frame(cnx, bytes, bytes_max);
                break;
            default: {
                uint64_t frame_id64;
                if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_id64)) != NULL) {
                    switch (frame_id64) {
                    case picoquic_frame_type_ack_frequency:
                        bytes = picoquic_decode_ack_frequency_frame(bytes, bytes_max, cnx);
                        ack_needed = 1;
                        break;
                    case picoquic_frame_type_time_stamp:
                        bytes = picoquic_decode_time_stamp_frame(bytes, bytes_max, cnx, &packet_data);
                        ack_needed = 0;
                        break;
                    default:
                        /* Not implemented yet! */
                        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, frame_id64);
                        bytes = NULL;
                        break;
                    }
                }
                break;
            }
            }
        }
    }

    if (bytes != NULL) {
        process_decoded_packet_data(cnx, current_time, &packet_data);
    }

    if (bytes != NULL && ack_needed != 0) {
        cnx->latest_progress_time = current_time;
        picoquic_set_ack_needed(cnx, current_time, pc);
    }

    return bytes != NULL ? 0 : PICOQUIC_ERROR_DETECTED;
}

/*
* The STREAM skipping function only supports the varint format.
* The old "fixed int" versions are supported by code in the skip_frame function
*/
static uint8_t* picoquic_skip_stream_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t  len = bytes[0] & 2;
    uint8_t  off = bytes[0] & 4;

    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) != NULL           &&
        (off == 0 || (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL))
    {
        bytes = (len == 0) ? (uint8_t*)bytes_max : picoquic_frames_length_data_skip(bytes, bytes_max);
    }

    return bytes;
}

/*
 * Crypto HS skipping, very similar to stream frame
 */

static uint8_t* picoquic_skip_crypto_hs_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) != NULL) {
        bytes = picoquic_frames_length_data_skip(bytes, bytes_max);
    }
    return bytes;
}

/*
 * Closing frames
 */
static uint8_t* picoquic_skip_connection_close_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    bytes = picoquic_frames_varint_skip(bytes + 1, bytes_max);
    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_skip(bytes,  bytes_max)) != NULL) {
        bytes = picoquic_frames_length_data_skip(bytes, bytes_max);
    }
    return bytes;
}

static uint8_t* picoquic_skip_application_close_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    
    bytes = picoquic_frames_varint_skip(bytes + 1, bytes_max);

    if (bytes != NULL) {
        bytes = picoquic_frames_length_data_skip(bytes, bytes_max);
    }
    return bytes;
}


/*
 * The ACK skipping function only supports the varint format.
 * The old "fixed int" versions are supported by code in the skip_frame function
 */
static uint8_t* picoquic_skip_ack_frame_maybe_ecn(uint8_t* bytes, const uint8_t* bytes_max, int is_ecn, int has_1wd)
{
    uint64_t nb_blocks;

    if ((bytes = picoquic_frames_varint_skip(bytes + 1, bytes_max)) != NULL) {
        if (has_1wd) {
            bytes = picoquic_frames_varint_skip(bytes, bytes_max);
        }
        if (bytes != NULL &&
            (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL &&
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &nb_blocks)) != NULL &&
            (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL)
        {
            while (nb_blocks-- != 0) {
                if ((bytes = picoquic_frames_varint_skip(bytes, bytes_max)) == NULL ||
                    (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) == NULL)
                {
                    break;
                }
            }
        }
    }
   
    if (bytes != NULL && is_ecn) {
        for (int i = 0; bytes != NULL && i < 3; i++) {
            bytes = picoquic_frames_varint_skip(bytes, bytes_max);
        }
    }

    return bytes;
}

static uint8_t* picoquic_skip_ack_frame(uint8_t* bytes, const uint8_t* bytes_max) {
    return picoquic_skip_ack_frame_maybe_ecn(bytes, bytes_max, 0, 0);
}

static uint8_t* picoquic_skip_ack_ecn_frame(uint8_t* bytes, const uint8_t* bytes_max) {
    return picoquic_skip_ack_frame_maybe_ecn(bytes, bytes_max, 1, 0);
}

/* Lots of simple frames...
 */

static uint8_t* picoquic_skip_stream_reset_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    /* Stream ID */
    bytes = picoquic_frames_varint_skip(bytes + 1, bytes_max);
    /* Error code */
    if (bytes != NULL) {
        bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    }
    /* Offset */
    if (bytes != NULL)
    {
        bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    }
    return bytes;
}

static uint8_t* picoquic_skip_max_stream_data_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) != NULL) {
        bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    }
    return bytes;
}

static uint8_t* picoquic_skip_stream_blocked_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) != NULL) {
        bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    }
    return bytes;
}


int picoquic_skip_frame(uint8_t* bytes, size_t bytes_maxsize, size_t* consumed, int* pure_ack)
{
    const uint8_t *bytes_max = bytes + bytes_maxsize;
    uint8_t first_byte = bytes[0];

    *pure_ack = 1;

    if (PICOQUIC_IN_RANGE(first_byte, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
        *pure_ack = 0;
        bytes = picoquic_skip_stream_frame(bytes, bytes_max);
    } else if (first_byte == picoquic_frame_type_ack) {
        bytes = picoquic_skip_ack_frame(bytes, bytes_max);
    } else if (first_byte == picoquic_frame_type_ack_ecn) {
        bytes = picoquic_skip_ack_ecn_frame(bytes, bytes_max);
    } else {
        switch (first_byte) {
        case picoquic_frame_type_padding:
            bytes = picoquic_skip_0len_frame(bytes, bytes_max);
            break;
        case picoquic_frame_type_reset_stream:
            bytes = picoquic_skip_stream_reset_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_connection_close: {
            bytes = picoquic_skip_connection_close_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        }
        case picoquic_frame_type_application_close: {
            bytes = picoquic_skip_application_close_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        }
        case picoquic_frame_type_max_data:
            bytes = picoquic_frames_varint_skip(bytes+1, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_max_stream_data:
            bytes = picoquic_skip_max_stream_data_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_max_streams_bidir:
        case picoquic_frame_type_max_streams_unidir:
            bytes = picoquic_frames_varint_skip(bytes+1, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_ping:
            bytes = picoquic_skip_0len_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_data_blocked:
            bytes = picoquic_frames_varint_skip(bytes+1, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_stream_data_blocked:
            bytes = picoquic_skip_stream_blocked_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_streams_blocked_bidir:
        case picoquic_frame_type_streams_blocked_unidir:
            bytes = picoquic_frames_varint_skip(bytes+1, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_new_connection_id:
            bytes = picoquic_skip_new_connection_id_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_stop_sending:
            bytes = picoquic_skip_stop_sending_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_path_challenge:
            bytes = picoquic_frames_fixed_skip(bytes+1, bytes_max, challenge_length);
            break;
        case picoquic_frame_type_path_response:
            bytes = picoquic_frames_fixed_skip(bytes+1, bytes_max, challenge_length);
            break;
        case picoquic_frame_type_crypto_hs:
            bytes = picoquic_skip_crypto_hs_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_new_token:
            bytes = picoquic_skip_new_token_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_retire_connection_id:
            /* the old code point for ACK frames, but this is taken care of in the ACK tests above */
            bytes = picoquic_skip_retire_connection_id_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_handshake_done:
            bytes = bytes + 1;
            *pure_ack = 0;
            break;
        case picoquic_frame_type_datagram:
        case picoquic_frame_type_datagram_l:
            bytes = picoquic_skip_datagram_frame(bytes, bytes_max);
            break;
        default: {
            uint64_t frame_id64;
            if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_id64)) != NULL) {
                switch (frame_id64) {
                case picoquic_frame_type_ack_frequency:
                    bytes = picoquic_skip_ack_frequency_frame(bytes, bytes_max);
                    *pure_ack = 0;
                    break;
                case picoquic_frame_type_time_stamp:
                    bytes = picoquic_skip_time_stamp_frame(bytes, bytes_max);
                    break;
                default:
                    /* Not implemented yet! */
                    bytes = NULL;
                }
            }
            break;
        }
        }
    }

    *consumed = (bytes != NULL) ? bytes_maxsize - (bytes_max - bytes) : bytes_maxsize;

    return bytes == NULL;
}

int picoquic_decode_closing_frames(uint8_t* bytes, size_t bytes_max, int* closing_received)
{
    int ret = 0;
    size_t byte_index = 0;

    *closing_received = 0;
    while (ret == 0 && byte_index < bytes_max) {
        uint8_t first_byte = bytes[byte_index];

        if (first_byte == picoquic_frame_type_connection_close || first_byte == picoquic_frame_type_application_close) {
            *closing_received = 1;
            break;
        } else {
            size_t consumed = 0;
            int pure_ack = 0;

            ret = picoquic_skip_frame(bytes + byte_index,
                bytes_max - byte_index, &consumed, &pure_ack);
            byte_index += consumed;
        }
    }

    return ret;
}
