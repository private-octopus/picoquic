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
#include "bytestream.h"

/* ****************************************************
 * Frames private declarations
 * ****************************************************/

static const size_t challenge_length = 8;


/**
 * Frame decoder function
 * Inputs:
 *   cnx       - [in/out] picoquic Context
 *   bytes     - [in]     pointer to the beginning of the frame (frame type)
 *   bytes_max - [in]     pointer to the end of the packet (one past the last byte)
 * Returns:
 *   Pointer to the data following the end of this frame, if the frame has been decoded successfully;
 *   or NULL if, decoding failed (in which case, picoquic_connection_error has been called).
 */
typedef uint8_t* (*decode_frame_fn)(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max);

/**
 * Frame skip function
 * Inputs:
 *   bytes     - [in]     pointer to the beginning of the frame (frame type)
 *   bytes_max - [in]     pointer to the end of the packet (one past the last byte)
 * Returns:
 *   Pointer to the data following the end of this frame, if the frame has been skipped successfully;
 *   or NULL if, skipping failed.
 */
typedef uint8_t* (*skip_frame_fn)(uint8_t* bytes, const uint8_t* bytes_max);


/* ****************************************************
 * Helper utilities
 * ****************************************************/

/* Skip and decode function.
 * These functions return NULL in case of a failure (insufficient buffer).
 */

#define VARINT_LEN(bytes) ((size_t)1 << (((bytes)[0] & 0xC0) >> 6))


static uint8_t* picoquic_frames_fixed_skip(uint8_t* bytes, const uint8_t* bytes_max, size_t size)
{
    return (bytes += size) <= bytes_max ? bytes : NULL;
}


static uint8_t* picoquic_frames_varint_skip(uint8_t* bytes, const uint8_t* bytes_max)
{
    return bytes < bytes_max ? picoquic_frames_fixed_skip(bytes, bytes_max, VARINT_LEN(bytes)) : NULL;
}


/* Parse a varint. In case of an error, *n64 is unchanged, and NULL is returned */
uint8_t* picoquic_frames_varint_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64)
{
    uint8_t length;

    if (bytes < bytes_max && bytes + (length=(uint8_t)VARINT_LEN(bytes)) <= bytes_max) {
        uint64_t v = *bytes++ & 0x3F;

        while (--length > 0) {
            v <<= 8;
            v += *bytes++;
        }

        *n64 = v;
    } else {
        bytes = NULL;
    }

    return bytes;
}


static uint8_t* picoquic_frames_length_data_skip(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t length;
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &length)) != NULL) {
        bytes = picoquic_frames_fixed_skip(bytes, bytes_max, (size_t)length);
    }
    return bytes;
}


/* ****************************************************** */

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

int picoquic_delete_stream_if_closed(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    int ret = 0;

    if (picoquic_is_stream_closed(stream, cnx->client_mode)){
        picoquic_delete_stream(cnx, stream);
        ret = 1;
    }

    return ret;
}

void picoquic_delete_closed_streams(picoquic_cnx_t* cnx)
{
    picoquic_stream_head_t* stream = picoquic_first_stream(cnx);

    while (stream != NULL) {
        int is_closed = picoquic_is_stream_closed(stream, cnx->client_mode);

        /* TODO: should we wait for acknowledgements from the peer that the data has been received? */
        /* How abou waiting an RTO? */

        if (is_closed) {
            /* Delete the stream */
            picoquic_stream_head_t* deleted_stream = stream; 
            stream = picoquic_next_stream(stream);
            picoquic_delete_stream(cnx, deleted_stream);
        }
        else {
            stream = picoquic_next_stream(stream);
        }
    }
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

int picoquic_prepare_stream_reset_frame(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;

    bytestream bs;
    bytestream * s = bytestream_ref_init(&bs, bytes, bytes_max);

    if (stream->reset_requested && !stream->reset_sent) {

        ret |= bytewrite_int8(s, picoquic_frame_type_reset_stream);
        ret |= bytewrite_vint(s, stream->stream_id);
        if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
            ret |= bytewrite_int16(s, (uint16_t)stream->local_error);
        } else {
            ret |= bytewrite_vint(s, stream->local_error);
        }
        ret |= bytewrite_vint(s, stream->sent_offset);

        if (ret != 0) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else {
            picoquic_update_max_stream_ID_local(cnx, stream);

            /* Free the queued data */
            while (stream->send_queue != NULL) {
                picoquic_stream_data_t* next = stream->send_queue->next_stream_data;
                if (stream->send_queue->bytes != NULL) {
                    free(stream->send_queue->bytes);
                }
                free(stream->send_queue);
                stream->send_queue = next;
            }
            (void)picoquic_delete_stream_if_closed(cnx, stream);

            stream->reset_sent = 1;
            stream->fin_sent = 1;
        }
    }

    *consumed = (ret == 0) ? bytestream_length(s) : 0;
    return ret;
}

static int byteread_errorcode(bytestream * s, picoquic_cnx_t * cnx, uint64_t * error_code)
{
    if (picoquic_supported_versions[cnx->version_index].version != PICOQUIC_TWELFTH_INTEROP_VERSION) {
        return byteread_vint(s, error_code);
    }
    uint16_t error_code16 = 0;
    int ret = byteread_int16(s, &error_code16);
    *error_code = error_code16;
    return ret;
}

int picoquic_decode_stream_reset_frame(picoquic_cnx_t* cnx, bytestream * s)
{
    picoquic_stream_head_t* stream;

    uint64_t stream_id = 0;
    uint64_t error_code = 0;
    uint64_t final_offset = 0;

    int ret = 0;
    ret |= byteread_vint(s, &stream_id);
    ret |= byteread_errorcode(s, cnx, &error_code);
    ret |= byteread_vint(s, &final_offset);

    if (ret != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else if ((stream = picoquic_find_or_create_stream(cnx, stream_id, 1)) == NULL) {
        ret = -1;  // error already signaled
    } else if ((stream->fin_received || stream->reset_received) && final_offset != stream->fin_offset) {
        ret = PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR;
    } else if (picoquic_flow_control_check_stream_offset(cnx, stream, final_offset) != 0) {
        ret = -1;  // error already signaled
    } else if (!stream->reset_received) {
        stream->reset_received = 1;
        stream->remote_error  = error_code;

        picoquic_update_max_stream_ID_local(cnx, stream);

        if (cnx->callback_fn != NULL && !stream->reset_signalled) {
            if (cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stream_reset, cnx->callback_ctx, stream->app_stream_ctx) != 0) {
                ret = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
            }
            stream->reset_signalled = 1;
            (void)picoquic_delete_stream_if_closed(cnx, stream);
        }
    }

    return ret;
}

/*
 * New Connection ID frame
 */

int picoquic_prepare_new_connection_id_frame(picoquic_cnx_t * cnx, picoquic_path_t * path_x,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;

    bytestream stream;
    bytestream * s = bytestream_ref_init(&stream, bytes, bytes_max);

    if (path_x->path_sequence > 0 && path_x->local_cnxid.id_len > 0 && path_x->path_is_registered) {

        ret |= bytewrite_int8(s, picoquic_frame_type_new_connection_id);
        ret |= bytewrite_vint(s, path_x->path_sequence);
        if (picoquic_supported_versions[cnx->version_index].version != PICOQUIC_TWELFTH_INTEROP_VERSION) {
            ret |= bytewrite_int8(s, 0);
        }

        uint8_t secret[PICOQUIC_RESET_SECRET_SIZE];
        ret |= picoquic_create_cnxid_reset_secret(cnx->quic, path_x->local_cnxid, secret);

        ret |= bytewrite_int8(s, path_x->local_cnxid.id_len);
        ret |= bytewrite_buffer(s, path_x->local_cnxid.id, path_x->local_cnxid.id_len);
        ret |= bytewrite_buffer(s, secret, PICOQUIC_RESET_SECRET_SIZE);
    }

    *consumed = (ret == 0) ? bytestream_length(s) : 0;

    *consumed = (ret == 0) ? bytestream_length(s) : 0;

    return ret;
}

uint8_t* picoquic_skip_new_connection_id_frame(picoquic_cnx_t * cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    bytestream stream;
    bytestream * s = bytestream_ref_init(&stream, bytes + 1, bytes_max - bytes);

    int ret = byteread_skip_vint(s);
    if (picoquic_supported_versions[cnx->version_index].version != PICOQUIC_TWELFTH_INTEROP_VERSION) {
        ret |= byteread_skip_vint(s);
    }

    uint8_t cid_length = 0;
    ret |= byteread_int8(s, &cid_length);
    ret |= bytestream_skip(s, (size_t)cid_length + PICOQUIC_RESET_SECRET_SIZE);

    return ret == 0 ? (uint8_t*)bytestream_ptr(s) : NULL;
}

int picoquic_decode_new_connection_id_frame(picoquic_cnx_t* cnx, bytestream * s, uint64_t current_time)
{
    /* store the connection ID in order to support migration. */
    int ret = 0;
    
    uint64_t sequence = 0;
    uint64_t retire_before = 0;

    ret |= byteread_vint(s, &sequence);
    if (picoquic_supported_versions[cnx->version_index].version != PICOQUIC_TWELFTH_INTEROP_VERSION) {
        ret |= byteread_vint(s, &retire_before);
    }

    uint8_t cid_len = 0;
    ret |= byteread_int8(s, &cid_len);

    const uint8_t * cnxid_bytes = bytestream_ptr(s);
    ret |= bytestream_skip(s, cid_len);

    const uint8_t * secret_bytes = bytestream_ptr(s);
    ret |= bytestream_skip(s, PICOQUIC_RESET_SECRET_SIZE);

    if (ret != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else if (picoquic_is_valid_cid_len(cid_len) == 0 || retire_before > sequence) {
        ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
    } else {
        if (sequence >= cnx->retire_cnxid_before) {
            ret = picoquic_enqueue_cnxid_stash(cnx, sequence, cid_len, cnxid_bytes, secret_bytes, NULL);
        }
        if (retire_before > cnx->retire_cnxid_before) {
            /* TODO: retire the now deprecated CID */
            ret = picoquic_remove_not_before_cid(cnx, retire_before, current_time);
        }
    }

    return ret;
}

/*
 * Format a retire connection ID frame.
 */

int picoquic_prepare_retire_connection_id_frame(uint64_t sequence, 
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;

    *consumed = 0;
    
    if (bytes_max < 2) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }
    else {
        size_t ls;
        bytes[byte_index++] = picoquic_frame_type_retire_connection_id;
        ls = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, sequence);
        byte_index += ls;

        if (ls == 0) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
        else {
            *consumed = byte_index;
        }
    }

    return ret;
}

/*
 * Queue a retire connection id frame when a probe or a path is abandoned.
 */

int picoquic_queue_retire_connection_id_frame(picoquic_cnx_t * cnx, uint64_t sequence)
{
    size_t consumed = 0;
    uint8_t frame_buffer[258];
    int ret = picoquic_prepare_retire_connection_id_frame(sequence, frame_buffer, sizeof(frame_buffer), &consumed);

    if (ret == 0 && consumed > 0) {
        ret = picoquic_queue_misc_frame(cnx, frame_buffer, consumed);
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

int picoquic_decode_retire_connection_id_frame(picoquic_cnx_t* cnx, bytestream * s, uint64_t current_time, picoquic_path_t * path_x)
{
    /* store the connection ID in order to support migration. */
    int ret = 0;

    uint64_t sequence;

    if (byteread_vint(s, &sequence) != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    }
    else if (sequence >= cnx->path_sequence_next || cnx->path[0]->local_cnxid.id_len == 0) {
        /* If there is no matching path, trigger an error */
        ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
    }
    else if (sequence == path_x->path_sequence && path_x->path_is_registered) {
        /* Cannot delete the path through which it arrives */
        ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
    }
    else {
        /* Go through the list of paths to find the connection ID */

        for (int i = 0; i < cnx->nb_paths; i++) {
            if (cnx->path[i]->path_sequence == sequence && path_x->path_is_registered) {
                if (sequence == 0) {
                    cnx->is_path_0_deleted = 1;
                }
                /* Mark the corresponding path as demoted */
                picoquic_demote_path(cnx, i, current_time);
                break;
            }
        }
    }

    return ret;
}

/*
 * New Retry Token frame 
 */

int picoquic_prepare_new_token_frame(uint8_t * token, size_t token_length,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;

    *consumed = 0;

    if (bytes_max < 2) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }
    else {
        size_t l1;
        bytes[byte_index++] = picoquic_frame_type_new_token;
        l1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, token_length);
        byte_index += l1;
        if (l1 > 0 && bytes_max >= byte_index + token_length) {
            memcpy(bytes + byte_index, token, token_length);
            *consumed = byte_index + token_length;
        }
        else {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
    }

    return ret;
}

int picoquic_queue_new_token_frame(picoquic_cnx_t * cnx, uint8_t * token, size_t token_length)
{
    size_t consumed = 0;
    uint8_t frame_buffer[258];
    int ret = picoquic_prepare_new_token_frame(token, token_length, frame_buffer, sizeof(frame_buffer), &consumed);

    if (ret == 0 && consumed > 0) {
        ret = picoquic_queue_misc_frame(cnx, frame_buffer, consumed);
    }

    return ret;
}

uint8_t* picoquic_skip_new_token_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    return picoquic_frames_length_data_skip(bytes+1, bytes_max);
}

int picoquic_decode_new_token_frame(picoquic_cnx_t* cnx, bytestream * s,
    uint64_t current_time, struct sockaddr* addr_to)
{
    /* TODO: store the new token in order to support immediate connection on some servers. */
    int ret = 0;

    uint64_t length = 0;
    ret |= byteread_vint(s, &length);

    const uint8_t * token = bytestream_ptr(s);
    ret |= bytestream_skip(s, length);

    if (ret != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    }
    else if (addr_to != NULL && cnx->client_mode && cnx->sni != NULL) {
        uint8_t * ip_addr;
        uint8_t ip_addr_length;
        picoquic_get_ip_addr(addr_to, &ip_addr, &ip_addr_length);
        (void)picoquic_store_token(&cnx->quic->p_first_token, current_time, cnx->sni, (uint16_t)strlen(cnx->sni),
            ip_addr, ip_addr_length, token, (uint16_t)length);
    }

    return ret;
}

/*
 * STOP SENDING Frame
 */

int picoquic_prepare_stop_sending_frame(picoquic_stream_head_t* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;

    bytestream bs;
    bytestream * s = bytestream_ref_init(&bs, bytes, bytes_max);

    if (stream->stop_sending_requested && !stream->stop_sending_sent && !stream->fin_received && !stream->reset_received) {
        ret |= bytewrite_int8(s, picoquic_frame_type_stop_sending);
        ret |= bytewrite_vint(s, stream->stream_id);
        ret |= bytewrite_int16(s, (uint16_t)stream->local_stop_error);

        if (ret != 0) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
    }

    if (ret == 0) {
        /* set this, so we will not be called again */
        stream->stop_sending_sent = 1;
    }

    *consumed = (ret == 0) ? bytestream_length(s) : 0;
    return ret;
}

int picoquic_decode_stop_sending_frame(picoquic_cnx_t* cnx, bytestream * s)
{
    int ret = 0;
    uint64_t stream_id = 0;
    uint16_t error_code = 0;

    ret |= byteread_vint(s, &stream_id);
    ret |= byteread_int16(s, &error_code);

    if (ret != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    }
    else {
        picoquic_stream_head_t * stream = picoquic_find_or_create_stream(cnx, stream_id, 1);
        if (stream == NULL) {
            ret = -1;
        }
        else if (!stream->stop_sending_received && !stream->reset_requested) {
            stream->stop_sending_received = 1;
            stream->remote_stop_error = error_code;

            if (cnx->callback_fn != NULL && !stream->stop_sending_signalled) {
                if (cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stop_sending, cnx->callback_ctx, stream->app_stream_ctx) != 0) {
                    ret = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
                }
                stream->stop_sending_signalled = 1;
            }
        }
    }

    return ret;
}

uint8_t* picoquic_skip_stop_sending_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    int ret = 0;

    bytestream bs;
    bytestream* s = bytestream_ref_init(&bs, bytes, bytes_max - bytes);

    ret |= bytestream_skip(s, 1u);
    ret |= byteread_skip_vint(s);
    ret |= bytestream_skip(s, 2u);

    return ret == 0 ? (uint8_t*)bytestream_ptr(s) : NULL;
}


/*
 * STREAM frames implicitly create a stream and carry stream data.
 */

int picoquic_is_stream_frame_unlimited(const uint8_t* bytes)
{
    return PICOQUIC_BITS_CLEAR_IN_RANGE(bytes[0], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max, 0x02);
}

int picoquic_parse_stream_header(bytestream * s, uint8_t ftype,
    uint64_t* stream_id, uint64_t* offset, uint8_t** data_bytes, size_t* length, int* fin)
{
    int ret = byteread_vint(s, stream_id);

    if ((ftype & 4) != 0) {
        ret |= byteread_vint(s, offset);
    } else {
        *offset = 0;
    }

    if ((ftype & 2) != 0) {
        uint64_t data_length = 0;
        ret |= byteread_vint(s, &data_length);
        *length = (size_t)data_length;
    } else {
        *length = bytestream_remain(s);
    }

    *data_bytes = (uint8_t*)bytestream_ptr(s);
    ret |= bytestream_skip(s, *length);

    *fin = ftype & 1;

    if (ret != 0) {
        DBG_PRINTF("stream data past the end of the packet: first_byte=0x%02x, data_length=%" PRIst ", max_bytes=%" PRIst,
            ftype, *length, bytestream_remain(s));
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    }

    return ret;
}

void picoquic_stream_data_callback(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    picoquic_stream_data_t* data = stream->stream_data;

    while (data != NULL && data->offset <= stream->consumed_offset) {
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
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
        }

        free(data->bytes);
        stream->stream_data = data->next_stream_data;
        free(data);
        data = stream->stream_data;
    }

    /* handle the case where the fin frame does not carry any data */

    if (stream->consumed_offset >= stream->fin_offset && stream->fin_received && !stream->fin_signalled) {
        stream->fin_signalled = 1;
        if (cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stream_fin,
            cnx->callback_ctx, stream->app_stream_ctx) != 0) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
        }
    }
}

/* Common code to data stream and crypto hs stream */
static int picoquic_queue_network_input(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream, uint64_t offset, uint8_t* bytes, size_t length, int * new_data_available)
{
    int ret = 0;
    picoquic_stream_data_t** pprevious = &stream->stream_data;
    picoquic_stream_data_t* next = stream->stream_data;
    size_t start = 0;

    if (offset <= stream->consumed_offset) {
        if (offset + length <= stream->consumed_offset) {
            /* already received */
            start = length;
        }
        else {
            start = (size_t)(stream->consumed_offset - offset);
        }
    }

    /* Queue of a block in the stream */

    while (next != NULL && start < length && next->offset <= offset + start) {
        if (offset + length <= next->offset + next->length) {
            start = length;
        } else if (offset < next->offset + next->length) {
            start = (size_t)(next->offset + next->length - offset);
        }
        pprevious = &next->next_stream_data;
        next = next->next_stream_data;
    }

    if (start < length) {
        size_t data_length = length - start;

        if (next != NULL && next->offset < offset + length) {
            data_length -= (size_t)(offset + length - next->offset);
        }

        if (data_length > 0) {
            picoquic_stream_data_t* data = (picoquic_stream_data_t*)malloc(sizeof(picoquic_stream_data_t));

            if (data == NULL) {
                ret = picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY, 0);
            }
            else {
                data->length = data_length;
                data->bytes = (uint8_t*)malloc(data_length);
                if (data->bytes == NULL) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY, 0);
                    free(data);
                }
                else {
                    data->offset = offset + start;
                    memcpy(data->bytes, bytes + start, data_length);
                    data->next_stream_data = next;
                    *pprevious = data;
                    *new_data_available = 1;
                }
            }
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
        } else {
            ret = 1;  // Error already signaled
        }
    } else if (stream->fin_received) {

        if (fin != 0 ? stream->fin_offset != new_fin_offset : new_fin_offset > stream->fin_offset) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR, 0);
        }

    } else {
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

    if (ret == 0) {
        int new_data_available = 0;

        ret = picoquic_queue_network_input(cnx, stream, offset, bytes, length, &new_data_available);

        if (new_data_available) {
            should_notify = 1;
            cnx->latest_progress_time = current_time;
        }
    }

    if (ret == 0 && should_notify != 0 && cnx->callback_fn != NULL) {
        /* check how much data there is to send */
        picoquic_stream_data_callback(cnx, stream);
    }

    if (ret == 0) {
        if (!stream->fin_signalled || !picoquic_delete_stream_if_closed(cnx, stream)) {
            if (!stream->fin_received && !stream->reset_received && 2 * stream->consumed_offset > stream->maxdata_local) {
                cnx->max_stream_data_needed = 1;
            }
        }
    }

    return ret;
}

int picoquic_decode_stream_frame(picoquic_cnx_t* cnx, int epoch, uint8_t ftype, bytestream * s, uint64_t current_time)
{
    uint64_t stream_id;
    uint64_t offset;
    uint64_t length;
    int      fin;
    uint8_t * data_bytes;
    int ret = 0;

    if (picoquic_parse_stream_header(s, ftype, &stream_id, &offset, &data_bytes, &length, &fin) != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else  if (epoch != 1 && epoch != 3) {
        DBG_PRINTF("%s", "Data frame, when only TLS stream is expected");
        ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
    } else if (offset + length >= (1ull<<62)){
        ret = PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR;
    } else {
        ret = picoquic_stream_network_input(cnx, stream_id, offset, fin, data_bytes, length, current_time);
    }

    return ret;
}

picoquic_stream_head_t* picoquic_find_ready_stream(picoquic_cnx_t* cnx)
{
    picoquic_stream_head_t* start_stream = NULL;
    picoquic_stream_head_t* found_stream = NULL;
    picoquic_stream_head_t* previous_stream = NULL;
    picoquic_stream_head_t* end_of_second_pass = NULL;
    int is_second_pass = 0;

    if (cnx->high_priority_stream_id != (uint64_t)((int64_t)-1)) {
        picoquic_stream_head_t* hi_pri_stream = NULL;

        /* Check parity */
        if (IS_CLIENT_STREAM_ID(cnx->high_priority_stream_id) == cnx->client_mode) {
            if (cnx->high_priority_stream_id > ((IS_BIDIR_STREAM_ID(cnx->high_priority_stream_id)) ? cnx->max_stream_id_bidir_remote : cnx->max_stream_id_unidir_remote)) {
                return NULL;
            }
        }

        hi_pri_stream = picoquic_find_stream(cnx, cnx->high_priority_stream_id);

        if (hi_pri_stream == NULL) {
            cnx->high_priority_stream_id = (uint64_t)((int64_t)-1);
        }
        else if (hi_pri_stream->sent_offset >= hi_pri_stream->maxdata_remote ||
            cnx->maxdata_remote <= cnx->data_sent) {
            /* Hi priority stream is blocked by peer; waiting for unblock
             * before allowing any activity on other streams. */
            return NULL;
        }
        else if (hi_pri_stream->is_active ||
            (hi_pri_stream->send_queue != NULL &&
                hi_pri_stream->send_queue->length > hi_pri_stream->send_queue->offset)) {
            /* Data ready on the hi-priority stream */
            return hi_pri_stream;
        }
        else {
            /* No data on high pri stream. Assume not needed anymore */
            cnx->high_priority_stream_id = (uint64_t)((int64_t)-1);
        }
    }

    /* Skip to the first non visited stream */
    if (cnx->last_visited_stream != NULL) {
        previous_stream = cnx->last_visited_stream;
        start_stream = cnx->last_visited_stream->next_output_stream;
        end_of_second_pass = start_stream;
        cnx->last_visited_stream = NULL;
    }

    if (start_stream == NULL) {
        previous_stream = NULL;
        start_stream = cnx->first_output_stream;
        is_second_pass = 1; 
    }

    /* Look for a ready stream */
    if (start_stream != NULL) {
        picoquic_stream_head_t* stream = start_stream;

        do {
            if ((cnx->maxdata_remote > cnx->data_sent && stream->sent_offset < stream->maxdata_remote && (stream->is_active ||
                (stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset) ||
                (stream->fin_requested && !stream->fin_sent))) ||
                (stream->reset_requested && !stream->reset_sent) ||
                (stream->stop_sending_requested && !stream->stop_sending_sent)) {
                /* Something can be sent */
                found_stream = stream;
                break;
            }
            else if (((stream->fin_requested && stream->fin_sent) || (stream->reset_requested && stream->reset_sent)) && (!stream->stop_sending_requested || stream->stop_sending_sent)) {
                picoquic_stream_head_t * next_stream = stream->next_output_stream;
                /* If stream is exhausted, remove from output list */
                if (stream == end_of_second_pass) {
                    end_of_second_pass = next_stream;
                }
                if (stream == cnx->first_output_stream) {
                    cnx->first_output_stream = next_stream;
                }
                else if (previous_stream != NULL) {
                    previous_stream->next_output_stream = next_stream;
                }
                else {
                    DBG_PRINTF("Corrupted list of output streams found when removing stream %d", (int)stream->stream_id);
                    break;
                }
                stream->next_output_stream = NULL;
                stream->is_output_stream = 0;
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

            if (stream == NULL && !is_second_pass) {
                previous_stream = NULL;
                stream = cnx->first_output_stream;
                is_second_pass = 1;
            }
            else if (is_second_pass && stream == end_of_second_pass) {
                stream = NULL;
                break;
            }
        } while (stream != NULL);
    }

    return found_stream;
}

/* Management of BLOCKED signals
 */

int picoquic_prepare_data_blocked_frame(uint8_t* bytes,
    size_t bytes_max, size_t* consumed, uint64_t data_limit)
{
    int ret = 0;

    if (bytes_max < 2) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    }
    else {
        size_t ll;
        bytes[0] = picoquic_frame_type_data_blocked;

        ll = picoquic_varint_encode(bytes + 1, bytes_max-1, data_limit);

        if (ll == 0) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            *consumed = 0;
        }
        else {
            *consumed = 1 + ll;
        }
    }

    return ret;
}

int picoquic_prepare_stream_data_blocked_frame(uint8_t* bytes,
    size_t bytes_max, size_t* consumed, uint64_t stream_id, uint64_t data_limit)
{
    int ret = 0;

    if (bytes_max < 3) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    }
    else {
        size_t ll1;
        size_t ll2 = 0;
        bytes[0] = picoquic_frame_type_stream_data_blocked;

        ll1 = picoquic_varint_encode(bytes + 1, bytes_max - 1, stream_id);

        if (ll1 > 0) {
            ll2 = picoquic_varint_encode(bytes + 1 + ll1, bytes_max - 1 - ll1, data_limit);
        }

        if (ll2 == 0) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            *consumed = 0;
        }
        else {
            *consumed = 1 + ll1 + ll2;
        }
    }

    return ret;
}

int picoquic_prepare_stream_blocked_frame(uint8_t* bytes,
    size_t bytes_max, size_t* consumed, picoquic_cnx_t * cnx, uint64_t stream_id)
{
    int ret = 0;
    uint8_t f_type = 0;
    uint64_t stream_limit = 0;
    int should_not_send = 0;

    if (IS_BIDIR_STREAM_ID(stream_id)) {
        f_type = picoquic_frame_type_streams_blocked_bidir;
        stream_limit = STREAM_RANK_FROM_ID(stream_id);
        should_not_send = cnx->stream_blocked_bidir_sent;
    }
    else {
        f_type = picoquic_frame_type_streams_blocked_unidir;
        stream_limit = STREAM_RANK_FROM_ID(stream_id);
        should_not_send = cnx->stream_blocked_unidir_sent;
    }
    if (should_not_send) {
        *consumed = 0;
    }
    else {
        if (bytes_max < 2) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            *consumed = 0;
        }
        else {
            size_t ll = 0;
            bytes[0] = f_type;

            ll = picoquic_varint_encode(bytes + 1, bytes_max - 1, stream_limit);

            if (ll == 0) {
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                *consumed = 0;
            }
            else {
                *consumed = 1 + ll;
            }
        }
    }
    return ret;
}

static int picoquic_prepare_one_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max, picoquic_stream_head_t * stream, size_t* data_bytes)
{
    int ret = 0;

    if (stream->is_active ||
        (stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset)) {
        /* The stream has some data to send */
        /* if the stream is not active yet, verify that it fits under
            * the max stream id limit, which depends of the type of stream */
        if (IS_CLIENT_STREAM_ID(stream->stream_id) != cnx->client_mode ||
            stream->stream_id > ((IS_BIDIR_STREAM_ID(stream->stream_id)) ? cnx->max_stream_id_bidir_remote : cnx->max_stream_id_unidir_remote)) {
            /* Prepare a stream blocked frame */
            ret = picoquic_prepare_stream_blocked_frame(bytes, bytes_max, data_bytes, cnx, stream->stream_id);
            if (ret == 0) {
                if (IS_BIDIR_STREAM_ID(stream->stream_id)) {
                    cnx->stream_blocked_bidir_sent = 1;
                }
                else {
                    cnx->stream_blocked_unidir_sent = 1;
                }
            }
        }
        else {
            if (cnx->maxdata_remote <= cnx->data_sent && !cnx->sent_blocked_frame) {
                /* Prepare a blocked frame */
                ret = picoquic_prepare_data_blocked_frame(bytes, bytes_max, data_bytes, cnx->maxdata_remote);
                if (ret == 0) {
                    cnx->sent_blocked_frame = 1;
                }
            }

            if (stream->sent_offset >= stream->maxdata_remote && !stream->stream_data_blocked_sent) {
                /* Prepare a stream data blocked frame */
                ret = picoquic_prepare_stream_data_blocked_frame(bytes, bytes_max, data_bytes, stream->stream_id, stream->maxdata_remote);
                if (ret == 0) {
                    stream->stream_data_blocked_sent = 1;
                }
            }
        }
    }

    return ret;
}

int picoquic_prepare_blocked_frames(picoquic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_first_stream(cnx);
    picoquic_stream_head_t* hi_pri_stream = NULL;
    size_t byte_index = 0;

    *consumed = 0;

    /* Check whether there is a high priority stream declared */
    if (cnx->high_priority_stream_id != (uint64_t)((int64_t)-1)) {
        hi_pri_stream = picoquic_find_stream(cnx, cnx->high_priority_stream_id);
    }

    /* Look for blocked streams, as long as there is message space available */
    while (ret == 0 && stream != NULL) {
        if (hi_pri_stream == NULL || stream == hi_pri_stream){
            size_t data_bytes = 0;

            ret = picoquic_prepare_one_blocked_frame(cnx, bytes + byte_index, bytes_max - byte_index, stream, &data_bytes);
            if (ret == 0) {
                byte_index += data_bytes;
            }
        }

        stream = picoquic_next_stream(stream);
    }

    if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
        ret = 0;
    }

    if (ret == 0) {
        *consumed = byte_index;
    }

    return ret;
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
    }

    return buffer;
}

static int picoquic_prepare_stream_frame_header(uint8_t* bytes, size_t bytes_max, uint64_t stream_id, uint64_t offset, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t l_stream = 0;
    size_t l_off = 0;

    bytes[byte_index++] = picoquic_frame_type_stream_range_min;

    if (bytes_max > byte_index) {
        l_stream = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream_id);
        byte_index += l_stream;
    }

    if (offset > 0 && bytes_max > byte_index) {
        bytes[0] |= 4; /* Indicates presence of offset */
        l_off = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, offset);
        byte_index += l_off;
    }

    if (l_stream == 0 || (offset > 0 && l_off == 0)) {
        *consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }
    else {
        *consumed = byte_index;
    }

    return ret;
}

int picoquic_prepare_stream_frame(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int* is_still_active)
{
    int ret = 0;
    int may_close = 0;

    /* Check parity */
    if (IS_CLIENT_STREAM_ID(stream->stream_id) == cnx->client_mode) {
        if (stream->stream_id > ((IS_BIDIR_STREAM_ID(stream->stream_id)) ? cnx->max_stream_id_bidir_remote : cnx->max_stream_id_unidir_remote)){
            *consumed = 0;
            return 0;
        }
    }

    if (stream->reset_requested && !stream->reset_sent) {
        return picoquic_prepare_stream_reset_frame(cnx, stream, bytes, bytes_max, consumed);
    }

    if (stream->stop_sending_requested && !stream->stop_sending_sent) {
        return picoquic_prepare_stop_sending_frame(stream, bytes, bytes_max, consumed);
    }
    
    if (!stream->is_active &&
        (stream->send_queue == NULL || stream->send_queue->length <= stream->send_queue->offset) &&
        (!stream->fin_requested || stream->fin_sent)) {
        *consumed = 0;
    } else {
        size_t byte_index = 0;
        size_t length = 0;

        ret = picoquic_prepare_stream_frame_header(bytes, bytes_max, stream->stream_id, stream->sent_offset, &byte_index);

        if (ret != 0 || byte_index + 3 > bytes_max) {
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
        else {
            /* Compute the length */
            size_t byte_space = bytes_max - byte_index;
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

                stream_data_context.bytes = bytes;
                stream_data_context.byte_index = byte_index;
                stream_data_context.allowed_space = allowed_space;
                stream_data_context.byte_space = bytes_max - byte_index;
                stream_data_context.length = 0;
                stream_data_context.is_fin = 0;

                if ((cnx->callback_fn)(cnx, stream->stream_id, (uint8_t*)&stream_data_context, allowed_space, picoquic_callback_prepare_to_send, cnx->callback_ctx, stream->app_stream_ctx) != 0) {
                    /* something went wrong */
                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
                }
                else {
                    byte_index = stream_data_context.byte_index + stream_data_context.length;
                    stream->sent_offset += stream_data_context.length;
                    cnx->data_sent += stream_data_context.length;
                    *consumed = byte_index;

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

                if (stream->send_queue == NULL) {
                    length = 0;
                }
                else {
                    length = (size_t)(stream->send_queue->length - stream->send_queue->offset);
                }

                if (length >= allowed_space) {
                    length = allowed_space;
                }

                byte_index = picoquic_encode_length_of_stream_frame(bytes, byte_index, byte_space, length, &start_index);

                if (length > 0 && stream->send_queue != NULL && stream->send_queue->bytes != NULL) {
                    memcpy(&bytes[byte_index], stream->send_queue->bytes + stream->send_queue->offset, length);
                    byte_index += length;

                    stream->send_queue->offset += length;
                    if (stream->send_queue->offset >= stream->send_queue->length) {
                        picoquic_stream_data_t* next = stream->send_queue->next_stream_data;
                        free(stream->send_queue->bytes);
                        free(stream->send_queue);
                        stream->send_queue = next;
                    }

                    stream->sent_offset += length;
                    cnx->data_sent += length;
                }
                *consumed = byte_index;

                if (stream->send_queue == NULL) {
                    if (stream->fin_requested) {
                        /* Set the fin bit */
                        stream->fin_sent = 1;
                        bytes[start_index] |= 1;

                        picoquic_update_max_stream_ID_local(cnx, stream);
                        may_close = 1;
                    }
                }
                else if (length == 0) {
                    /* No point in sending a silly packet */
                    *consumed = 0;
                    ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                }
            }
        }

        if (ret == 0) {
            if (!may_close || !picoquic_delete_stream_if_closed(cnx, stream)){
                /* remember the last stream on which data is sent so each stream is visited in turn. */
                cnx->last_visited_stream = stream;
                /* mark the stream as unblocked since we sent something */
                stream->stream_data_blocked_sent = 0;
                cnx->sent_blocked_frame = 0;
            }
        }
    }

    return ret;
}

int picoquic_split_stream_frame(uint8_t* frame, size_t frame_length, uint8_t* b1, size_t b1_max, size_t *lb1, uint8_t* b2, size_t b2_max, size_t *lb2) 
{
    int ret;
    uint64_t stream_id;
    uint64_t offset;
    uint8_t* data_bytes;
    size_t data_length;
    int fin;

    bytestream bs;
    bytestream* s = bytestream_ref_init(&bs, frame, frame_length);

    uint8_t ftype;
    byteread_int8(s, &ftype);

    if ((ret = picoquic_parse_stream_header(s, ftype, &stream_id, &offset, &data_bytes, &data_length, &fin)) == 0) {
        /* Does the whole frame fit in b1? */
        size_t b1_index = 0;
        size_t b1_length = 0;
        size_t consumed = 0;

        if (picoquic_prepare_stream_frame_header(b1, b1_max, stream_id, offset, &b1_index) != 0){
            *lb1 = 0;
        }
        else {
            size_t b1_available = b1_max - b1_index;

            if (data_length > b1_available && b1_available < 3) {
                /* do not send silly frames */
                *lb1 = 0;
            }
            else {
                size_t start_index = 0;

                b1_length = (data_length > b1_available) ? b1_available : data_length;

                b1_index = picoquic_encode_length_of_stream_frame(b1, b1_index, b1_available, b1_length, &start_index);

                memcpy(b1 + b1_index, data_bytes, b1_length);

                if (fin && b1_length >= data_length) {
                    /* Encode fin bit if all data sent */
                    b1[start_index] |= 1;
                }

                consumed += b1_length;

                *lb1 = b1_index + b1_length;
            }
        }

        if (b1_length >= data_length && b1_index != 0) {
            *lb2 = 0;
        }else {
            size_t b2_length = data_length - b1_length;
            size_t b2_index = 0;

            if (picoquic_prepare_stream_frame_header(b2, b2_max, stream_id, offset + b1_length, &b2_index) != 0) {
                *lb2 = 0;
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            }
            else {
                size_t b2_available = b2_max - b2_index;

                if (b2_length + 2 > b2_available) {
                    /* Reserve at least 2 bytes for length encoding, because we don't want to
                     * use implict incoding for the second frame */
                    *lb2 = 0;
                    ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                }
                else {
                    size_t start_index = 0;
                    b2_index = picoquic_encode_length_of_stream_frame(b2, b2_index, b2_available, b2_length, &start_index);

                    memcpy(b2 + b2_index, data_bytes + consumed, b2_length);

                    if (fin) {
                        /* Encode fin bit if all data sent */
                        b2[start_index] |= 1;
                    }

                    *lb2 = b2_index + b2_length;
                }
            }
        }
    }
    return ret;
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


int picoquic_decode_crypto_hs_frame(picoquic_cnx_t* cnx, int epoch, bytestream * s)
{
    int new_data_available;  // Unused
    int ret = 0;

    uint64_t offset;
    uint64_t length;

    ret |= byteread_vint(s, &offset);
    ret |= byteread_vint(s, &length);

    uint8_t * data_bytes = (uint8_t*)bytestream_ptr(s);
    ret |= bytestream_skip(s, length);

    if (ret != 0) {
        DBG_PRINTF("crypto hs data past the end of the packet: data_length=%" PRIst ", remaining_space=%" PRIst, length, bytestream_remain(s));
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else if (picoquic_queue_network_input(cnx, &cnx->tls_stream[epoch], offset, data_bytes, length, &new_data_available) != 0) {
        ret = -1;  // Error signaled
    }

    return ret;
}

static void stream_consume_bytes(picoquic_stream_head_t* stream, size_t length)
{
    stream->send_queue->offset += length;

    if (stream->send_queue->offset >= stream->send_queue->length) {
        picoquic_stream_data_t* next = stream->send_queue->next_stream_data;
        free(stream->send_queue->bytes);
        free(stream->send_queue);
        stream->send_queue = next;
    }

    stream->sent_offset += length;
}

int picoquic_prepare_crypto_hs_frame(picoquic_cnx_t* cnx, int epoch,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    picoquic_stream_head_t* stream = &cnx->tls_stream[epoch];

    if (stream->send_queue == NULL || stream->send_queue->length <= stream->send_queue->offset) {
        *consumed = 0;
    }
    else {
        bytestream bs;
        bytestream* s = bytestream_ref_init(&bs, bytes, bytes_max);

        size_t queue_length = stream->send_queue->length - stream->send_queue->offset;
        size_t approx_length = queue_length < bytes_max ? queue_length : bytes_max;

        size_t required_len = 1u + bytestream_vint_len(stream->sent_offset) + bytestream_vint_len(approx_length);
        if (required_len >= bytes_max) {
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
        else {
            size_t length = bytes_max - required_len;
            if (length > queue_length) {
                length = queue_length;
            }

            bytewrite_int8(s, picoquic_frame_type_crypto_hs);
            bytewrite_vint(s, stream->sent_offset);
            bytewrite_vint(s, length);
            bytewrite_buffer(s, stream->send_queue->bytes + stream->send_queue->offset, length);

            stream_consume_bytes(stream, length);
            *consumed = bytestream_length(s);
        }
    }
    return ret;
}

/*
 * ACK Frames
 */

int picoquic_parse_ack_header(uint8_t const* bytes, size_t bytes_max,
    uint64_t* num_block, uint64_t* nb_ecnx3,
    uint64_t* largest, uint64_t* ack_delay, size_t* consumed,
    uint8_t ack_delay_exponent)
{
    bytestream stream;
    bytestream * s = bytestream_ref_init(&stream, bytes, bytes_max);

    int ret = 0;
    ret |= bytestream_skip(s, 1);
    ret |= byteread_vint(s, largest);
    ret |= byteread_vint(s, ack_delay);

    *ack_delay <<= ack_delay_exponent;

    if (nb_ecnx3 != NULL) {
        for (int ecnx = 0; ecnx < 3; ecnx++) {
            ret |= byteread_vint(s, & nb_ecnx3[ecnx]);
        }
    }

    ret |= byteread_vint(s, num_block);

    if (ret != 0) {
        DBG_PRINTF("ack frame fixed header too large: first_byte=0x%02x, bytes_max=%" PRIst,
            bytes[0], bytes_max);
        ret = -1;
    }

    *consumed = bytestream_length(s);
    return ret;
}


void picoquic_check_spurious_retransmission(picoquic_cnx_t* cnx,
    uint64_t start_of_range, uint64_t end_of_range, uint64_t current_time,
    picoquic_packet_context_enum pc)
{
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];
    picoquic_packet_t* p = pkt_ctx->retransmitted_newest;

    while (p != NULL) {
        picoquic_packet_t* should_delete = NULL;

        if (p->sequence_number >= start_of_range && p->sequence_number <= end_of_range) {

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

                if (cnx->congestion_alg != NULL ) {
                    cnx->congestion_alg->alg_notify(old_path, picoquic_congestion_notification_spurious_repeat,
                        0, 0, p->sequence_number, current_time);
                }
            }

            cnx->nb_spurious++;
            should_delete = p;
        } else if (p->send_time + PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX < pkt_ctx->latest_time_acknowledged) {
            should_delete = p;
        }

        p = p->next_packet;

        if (should_delete != NULL) {
            picoquic_dequeue_retransmitted_packet(cnx, should_delete);
        }
    }
}

void picoquic_update_path_rtt(picoquic_cnx_t* cnx, picoquic_path_t * old_path, int64_t rtt_estimate,
    picoquic_packet_context_t * pkt_ctx, uint64_t current_time, uint64_t ack_delay)
{
    if (rtt_estimate > 0 && old_path != NULL) {
        if (ack_delay > old_path->max_ack_delay) {
            old_path->max_ack_delay = ack_delay;
        }

        if (old_path->smoothed_rtt == PICOQUIC_INITIAL_RTT && old_path->rtt_variant == 0) {
            old_path->smoothed_rtt = rtt_estimate;
            old_path->rtt_variant = rtt_estimate / 2;
            old_path->rtt_min = rtt_estimate;
            old_path->retransmit_timer = 3 * rtt_estimate + old_path->max_ack_delay;
            pkt_ctx->ack_delay_local = old_path->rtt_min / 4;
            if (pkt_ctx->ack_delay_local < PICOQUIC_ACK_DELAY_MIN) {
                pkt_ctx->ack_delay_local = PICOQUIC_ACK_DELAY_MIN;
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

                pkt_ctx->ack_delay_local = old_path->rtt_min / 4;
                if (pkt_ctx->ack_delay_local < PICOQUIC_ACK_DELAY_MIN) {
                    pkt_ctx->ack_delay_local = PICOQUIC_ACK_DELAY_MIN;
                }
                else if (pkt_ctx->ack_delay_local > PICOQUIC_ACK_DELAY_MAX) {
                    pkt_ctx->ack_delay_local = PICOQUIC_ACK_DELAY_MAX;
                }
            }

            if (4 * old_path->rtt_variant < old_path->rtt_min) {
                old_path->rtt_variant = old_path->rtt_min / 4;
            }

            old_path->retransmit_timer = old_path->smoothed_rtt + 4 * old_path->rtt_variant +
                cnx->remote_parameters.max_ack_delay;
        }

        if (PICOQUIC_MIN_RETRANSMIT_TIMER > old_path->retransmit_timer) {
            old_path->retransmit_timer = PICOQUIC_MIN_RETRANSMIT_TIMER;
        }

        if (cnx->congestion_alg != NULL) {
            cnx->congestion_alg->alg_notify(old_path,
                picoquic_congestion_notification_rtt_measurement,
                rtt_estimate, 0, 0, current_time);
        }
    }
}

static picoquic_packet_t* picoquic_update_rtt(picoquic_cnx_t* cnx, uint64_t largest,
    uint64_t current_time, uint64_t ack_delay, picoquic_packet_context_enum pc)
{
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];
    picoquic_packet_t* packet = pkt_ctx->retransmit_oldest;

    /* Check whether this is a new acknowledgement */
    if (largest > pkt_ctx->highest_acknowledged || pkt_ctx->highest_acknowledged == (uint64_t)((int64_t)-1)) {
        pkt_ctx->highest_acknowledged = largest;
        pkt_ctx->highest_acknowledged_time = current_time;
        pkt_ctx->ack_of_ack_requested = 0;

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
            } else {
                uint64_t acknowledged_time = current_time - ack_delay;
                int64_t rtt_estimate = acknowledged_time - packet->send_time;


                if (pkt_ctx->latest_time_acknowledged < packet->send_time) {
                    pkt_ctx->latest_time_acknowledged = packet->send_time;
                }
                cnx->latest_progress_time = current_time;

                if (rtt_estimate > 0) {
                    picoquic_path_t * old_path = packet->send_path;

                    if (old_path != NULL) {
#if 0
                        if (ack_delay > old_path->max_ack_delay) {
                            old_path->max_ack_delay = ack_delay;
                        }

                        if (old_path->smoothed_rtt == PICOQUIC_INITIAL_RTT && old_path->rtt_variant == 0) {
                            old_path->smoothed_rtt = rtt_estimate;
                            old_path->rtt_variant = rtt_estimate / 2;
                            old_path->rtt_min = rtt_estimate;
                            old_path->retransmit_timer = 3 * rtt_estimate + old_path->max_ack_delay;
                            pkt_ctx->ack_delay_local = old_path->rtt_min / 4;
                            if (pkt_ctx->ack_delay_local < PICOQUIC_ACK_DELAY_MIN) {
                                pkt_ctx->ack_delay_local = PICOQUIC_ACK_DELAY_MIN;
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

                                pkt_ctx->ack_delay_local = old_path->rtt_min / 4;
                                if (pkt_ctx->ack_delay_local < PICOQUIC_ACK_DELAY_MIN) {
                                    pkt_ctx->ack_delay_local = PICOQUIC_ACK_DELAY_MIN;
                                }
                                else if (pkt_ctx->ack_delay_local > PICOQUIC_ACK_DELAY_MAX) {
                                    pkt_ctx->ack_delay_local = PICOQUIC_ACK_DELAY_MAX;
                                }
                            }

                            if (4 * old_path->rtt_variant < old_path->rtt_min) {
                                old_path->rtt_variant = old_path->rtt_min / 4;
                            }

                            old_path->retransmit_timer = old_path->smoothed_rtt + 4 * old_path->rtt_variant + 
                                cnx->remote_parameters.max_ack_delay;
                        }

                        if (PICOQUIC_MIN_RETRANSMIT_TIMER > old_path->retransmit_timer) {
                            old_path->retransmit_timer = PICOQUIC_MIN_RETRANSMIT_TIMER;
                        }

                        if (cnx->congestion_alg != NULL) {
                            cnx->congestion_alg->alg_notify(old_path,
                                picoquic_congestion_notification_rtt_measurement,
                                rtt_estimate, 0, 0, current_time);
                        }
#else
                        picoquic_update_path_rtt(cnx, old_path, rtt_estimate, pkt_ctx, current_time, ack_delay);
#endif
                    }
                }
            }
        }
    }

    return packet;
}

static void picoquic_process_ack_of_ack_range(picoquic_sack_item_t* first_sack,
    uint64_t start_of_range, uint64_t end_of_range)
{
    if (first_sack->start_of_sack_range == start_of_range) {
        if (end_of_range < first_sack->end_of_sack_range) {
            first_sack->start_of_sack_range = end_of_range + 1;
        } else {
            first_sack->start_of_sack_range = first_sack->end_of_sack_range;
        }
    } else {
        picoquic_sack_item_t* previous = first_sack;
        picoquic_sack_item_t* next = previous->next_sack;

        while (next != NULL) {
            if (next->end_of_sack_range == end_of_range && next->start_of_sack_range == start_of_range) {
                /* Matching range should be removed */
                previous->next_sack = next->next_sack;
                free(next);
                break;
            } else if (next->end_of_sack_range > end_of_range) {
                previous = next;
                next = next->next_sack;
            } else {
                break;
            }
        }
    }
}

int picoquic_process_ack_of_ack_frame(
    picoquic_sack_item_t* first_sack,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn_14)
{
    int ret;
    uint64_t largest;
    uint64_t ack_delay;
    uint64_t num_block;
    uint64_t ecnx3[3];

    /* Find the oldest ACK range, in order to calibrate the
     * extension of the largest number to 64 bits */

    picoquic_sack_item_t* target_sack = first_sack;
    while (target_sack->next_sack != NULL) {
        target_sack = target_sack->next_sack;
    }

    ret = picoquic_parse_ack_header(bytes, bytes_max,
        &num_block, (is_ecn_14)? ecnx3 : NULL,
        &largest, &ack_delay, consumed, 0);

    if (ret == 0) {
        size_t byte_index = *consumed;

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
                picoquic_process_ack_of_ack_range(first_sack, largest + 1 - range, largest);
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
    uint8_t* data_bytes;

    *no_need_to_repeat = 0;

    if (PICOQUIC_IN_RANGE(bytes[0], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {

        bytestream bs;
        bytestream* s = bytestream_ref_init(&bs, bytes, bytes_max);

        uint8_t ftype;
        byteread_int8(s, &ftype);

        ret = picoquic_parse_stream_header(s, ftype,
            &stream_id, &offset, &data_bytes, &data_length, &fin);

        if (ret == 0) {
            stream = picoquic_find_stream(cnx, stream_id);
            if (stream == NULL) {
                /* the stream was destroyed. Just keep repeating, to be on the safe side. */
            } else {
                if (stream->reset_sent) {
                    *no_need_to_repeat = 1;
                } else {
                    /* Check whether the ack was already received */
                    *no_need_to_repeat = picoquic_check_sack_list(&stream->first_sack_item, offset, offset + data_length);
                }
            }
        }
    }
    else {
        uint8_t * p_last_byte = bytes + bytes_max;
        switch (bytes[0]) {
        case picoquic_frame_type_max_data:
            if ((bytes = picoquic_frames_varint_decode(bytes + 1, p_last_byte, &maxdata)) == NULL) {
                /* Malformed frame, do not retransmit */
                *no_need_to_repeat = 1;
            } else if (maxdata < cnx->maxdata_local) {
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
        default:
            break;
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
    uint8_t* data_bytes;

    /* skip stream frame */
    bytestream bs;
    bytestream* s = bytestream_ref_init(&bs, bytes, bytes_max);

    uint8_t ftype;
    byteread_int8(s, &ftype);

    ret = picoquic_parse_stream_header(s, ftype,
        &stream_id, &offset, &data_bytes, &data_length, &fin);

    if (ret == 0) {
        *consumed = bytestream_length(s);

        /* record the ack range for the stream */
        stream = picoquic_find_stream(cnx, stream_id);
        if (stream != NULL) {
            (void)picoquic_update_sack_list(&stream->first_sack_item,
                offset, offset + data_length - 1);
        }
    }

    return ret;
}

void picoquic_process_possible_ack_of_ack_frame(picoquic_cnx_t* cnx, picoquic_packet_t* p)
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
        } else if (PICOQUIC_IN_RANGE(p->bytes[byte_index], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            ret = picoquic_process_ack_of_stream_frame(cnx, &p->bytes[byte_index], p->length - byte_index, &frame_length);
            byte_index += frame_length;
        } else {
            ret = picoquic_skip_frame(cnx, &p->bytes[byte_index],
                p->length - byte_index, &frame_length, &frame_is_pure_ack);
            byte_index += frame_length;
        }
    }
}

/* Acknowledge a single packet p */
static int picoquic_process_ack(
    picoquic_cnx_t* cnx, picoquic_packet_context_enum pc,
    picoquic_packet_t * p, uint64_t current_time)
{
    int ret = 0;

    /* TODO: RTT Estimate */
    picoquic_path_t* old_path = p->send_path;

    if (p->is_ack_trap) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, picoquic_frame_type_ack);
    }

    if (ret == 0) {

        if (old_path != NULL) {
            if (cnx->congestion_alg != NULL) {
                cnx->congestion_alg->alg_notify(old_path,
                    picoquic_congestion_notification_acknowledgement,
                    0, p->length, 0, current_time);
            }

            /* If packet is larger than the current MTU, update the MTU */
            if ((p->length + p->checksum_overhead) > old_path->send_mtu) {
                old_path->send_mtu = p->length + p->checksum_overhead;
                old_path->mtu_probe_sent = 0;
            }
        }

        /* If the packet contained an ACK frame, perform the ACK of ACK pruning logic */
        picoquic_process_possible_ack_of_ack_frame(cnx, p);

        /* Keep track of reception of ACK of 1RTT data */
        if (p->ptype == picoquic_packet_1rtt_protected &&
            (cnx->cnx_state == picoquic_state_client_ready_start ||
                cnx->cnx_state == picoquic_state_server_false_start)) {
            /* Transition to client ready state.
             * The handshake is complete, all the handshake packets are implicitly acknowledged */
            picoquic_ready_state_transition(cnx, current_time);
        }

        (void)picoquic_dequeue_retransmit_packet(cnx, p, 1);

        /* Any acknowledgement shows progress */
        cnx->pkt_ctx[pc].nb_retransmit = 0;
    }

    return ret;
}

/* Acknowledge a range of packets (largest-gap-range .. largest-gap] */

static int picoquic_process_ack_range(
    picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, picoquic_packet_t** ppacket,
    uint64_t * plargest, uint64_t range, uint64_t current_time)
{
    picoquic_packet_t* p = *ppacket;
    uint64_t largest = *plargest;
    int ret = 0;

    range++;

    if (largest + 1 < range) {
        DBG_PRINTF("Malformed ACK RANGE, largest=% " PRIx64 ", range=% " PRIx64, largest, range);
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_ack);
        ret = -1;
    }
    else
    {
        *plargest = *plargest - range;

        /* Compare the range to the retransmit queue */
        while (ret == 0 && p != NULL && range > 0) {
            picoquic_packet_t* next = p->next_packet;
            if (p->sequence_number > largest) {
                p = next;
            } else {
                if (p->sequence_number == largest) {
                    if (picoquic_process_ack(cnx, pc, p, current_time) != 0) {
                        ret = -1;
                        break;
                    }
                    p = next;
                }

                range--;
                largest--;
            }
        }
    }

    if (range > 0) {
        picoquic_check_spurious_retransmission(cnx, largest + 1 - range, largest, current_time, pc);
    }

    *ppacket = p;
    return ret;
}

/* Skip a range of packets */
static int picoquic_skip_ack_range(picoquic_cnx_t* cnx, uint64_t* plargest, uint64_t gap)
{
    int ret = 0;

    if (*plargest < gap + 1) {
        DBG_PRINTF("Malformed ACK GAP, gap=% " PRIx64, gap);
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR, picoquic_frame_type_ack);
        ret = -1;
    }
    else
    {
        *plargest -= gap + 1;
    }

    return ret;
}

static int picoquic_decode_ack_frame(picoquic_cnx_t* cnx, int epoch, uint8_t ftype, bytestream * s, uint64_t current_time)
{
    uint64_t largest;
    uint64_t ack_delay;
    uint64_t nb_blocks;

    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);

    int ret = 0;
    ret |= byteread_vint(s, &largest);
    ret |= byteread_vint(s, &ack_delay);
    ret |= byteread_vint(s, &nb_blocks);

    if (ret != 0) {
        DBG_PRINTF("Malformed ACK, header too small: %zu bytes\n", bytestream_size(s));
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else if (epoch == 1) {
        DBG_PRINTF("Ack/Ack-ECN frame (0x%x) not expected in 0-RTT packet", ftype);
        ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
    } else if (largest >= cnx->pkt_ctx[pc].send_sequence) {
        DBG_PRINTF("Malformed ACK, largest(%" PRIx64 ") >= seq_no(%" PRIx64 ")\n", largest, cnx->pkt_ctx[pc].send_sequence);
        ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
    } else {
        ack_delay <<= cnx->remote_parameters.ack_delay_exponent;

        /* Attempt to update the RTT */
        picoquic_packet_t* top_packet = picoquic_update_rtt(cnx, largest, current_time, ack_delay, pc);

        for (uint64_t block = 0; block <= nb_blocks; block++) {

            if (block != 0) {
                uint64_t gap = 0;
                if (byteread_vint(s, &gap) != 0 || picoquic_skip_ack_range(cnx, &largest, gap)) {
                    ret = -1;
                    break;
                }
            }

            uint64_t range;
            if (byteread_vint(s, &range) != 0 || picoquic_process_ack_range(cnx, pc, &top_packet, &largest, range, current_time) != 0) {
                ret = -1;
                break;
            }
        }
    }

    if (ret == 0 && ftype == picoquic_frame_type_ack_ecn)
    {
        uint64_t ecnx3[3] = { 0, 0, 0 };
        for (int ecnx = 0; ecnx < 3; ecnx++) {
            ret |= byteread_vint(s, &ecnx3[ecnx]);
        }

        if (ret == 0) {
            if (ecnx3[0] > cnx->ecn_ect0_total_remote) {
                cnx->ecn_ect0_total_remote = ecnx3[0];
            }
            if (ecnx3[1] > cnx->ecn_ect1_total_remote) {
                cnx->ecn_ect1_total_remote = ecnx3[1];
            }
            if (ecnx3[2] > cnx->ecn_ce_total_remote) {
                cnx->ecn_ce_total_remote = ecnx3[2];

                cnx->congestion_alg->alg_notify(cnx->path[0],
                    picoquic_congestion_notification_ecn_ec,
                    0, 0, cnx->pkt_ctx[pc].first_sack_item.end_of_sack_range, current_time);
            }
        }
    }

    return ret;
}

/*
 * The ACK skipping function only supports the varint format.
 * The old "fixed int" versions are supported by code in the skip_frame function
 */
static uint8_t* picoquic_skip_ack_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    bytestream stream;
    bytestream* s = bytestream_ref_init(&stream, bytes, bytes_max - bytes);

    int ret = 0;

    uint8_t ftype;
    ret |= byteread_int8(s, &ftype);
    ret |= byteread_skip_vint(s);
    ret |= byteread_skip_vint(s);

    uint64_t nb_blocks;
    ret |= byteread_vint(s, &nb_blocks);
    ret |= byteread_skip_vint(s);

    for (uint64_t block = 0; block < nb_blocks && ret == 0; block++) {
        ret |= byteread_skip_vint(s);
        ret |= byteread_skip_vint(s);
    }

    if (ret == 0 && ftype == picoquic_frame_type_ack_ecn) {
        for (int i = 0; bytes != NULL && i < 3; i++) {
            ret |= byteread_skip_vint(s);
        }
    }

    if (ret == 0) {
        return (uint8_t*)bytestream_ptr(s);
    } else {
        return NULL;
    }
}

static int encode_ecn_block(picoquic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max, size_t* byte_index)
{
    int ret = 0;
    size_t l_ect0 = 0;
    size_t l_ect1 = 0;
    size_t l_ce = 0;

    l_ect0 = picoquic_varint_encode(bytes + *byte_index, bytes_max - *byte_index,
        cnx->ecn_ect0_total_local);
    *byte_index += l_ect0;

    l_ect1 = picoquic_varint_encode(bytes + *byte_index, bytes_max - *byte_index,
        cnx->ecn_ect1_total_local);
    *byte_index += l_ect1;

    l_ce = picoquic_varint_encode(bytes + *byte_index, bytes_max - *byte_index,
        cnx->ecn_ce_total_local);
    *byte_index += l_ce;

    if (l_ect0 == 0 || l_ect1 == 0 || l_ce == 0) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }

    return ret;
}

int picoquic_prepare_ack_frame(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    uint64_t num_block = 0;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_first_range = 0;
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];
    picoquic_sack_item_t* next_sack = pkt_ctx->first_sack_item.next_sack;
    uint64_t ack_delay = 0;
    uint64_t ack_range = 0;
    uint64_t ack_gap = 0;
    uint64_t lowest_acknowledged = 0;
    size_t num_block_index = 0;
    int is_ecn = cnx->sending_ecn_ack;
    uint8_t ack_type_byte = ((is_ecn) ? picoquic_frame_type_ack_ecn : picoquic_frame_type_ack);

    /* Check that there is enough room in the packet, and something to acknowledge */
    if (pkt_ctx->first_sack_item.start_of_sack_range == (uint64_t)((int64_t)-1)) {
        *consumed = 0;
    } else if (bytes_max < 13) {
        /* A valid ACK, with our encoding, uses at least 13 bytes.
        * If there is not enough space, don't attempt to encode it.
        */
        *consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        /* Encode the first byte */
        bytes[byte_index++] = ack_type_byte;
        /* Encode the largest seen */
        l_largest = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
            pkt_ctx->first_sack_item.end_of_sack_range);
        byte_index += l_largest;
        /* Encode the ack delay */
        if (byte_index < bytes_max) {
            if (current_time > pkt_ctx->time_stamp_largest_received) {
                ack_delay = current_time - pkt_ctx->time_stamp_largest_received;
                ack_delay >>= cnx->local_parameters.ack_delay_exponent;
            }
            l_delay = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                ack_delay);
            byte_index += l_delay;
        }

        /* Reserve one byte for the number of blocks */
        num_block_index = byte_index;
        byte_index++;
        /* Encode the size of the first ack range */
        if (byte_index < bytes_max) {
            ack_range = pkt_ctx->first_sack_item.end_of_sack_range - pkt_ctx->first_sack_item.start_of_sack_range;
            l_first_range = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                ack_range);
            byte_index += l_first_range;
        }

        if (l_delay == 0 || l_largest == 0 || l_first_range == 0 || byte_index > bytes_max) {
            /* not enough space */
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else {
            /* Set the lowest acknowledged */
            lowest_acknowledged = pkt_ctx->first_sack_item.start_of_sack_range;
            /* Encode the ack blocks that fit in the allocated space */
            while (num_block < 63 && next_sack != NULL) {
                size_t l_gap = 0;
                size_t l_range = 0;

                if (byte_index < bytes_max) {
                    ack_gap = lowest_acknowledged - next_sack->end_of_sack_range - 2; /* per spec */
                    l_gap = picoquic_varint_encode(bytes + byte_index,
                        bytes_max - byte_index, ack_gap);
                }

                if (byte_index + l_gap < bytes_max) {
                    ack_range = next_sack->end_of_sack_range - next_sack->start_of_sack_range;
                    l_range = picoquic_varint_encode(bytes + byte_index + l_gap,
                        bytes_max - byte_index - l_gap, ack_range);
                }

                if (l_gap == 0 || l_range == 0) {
                    /* Not enough space to encode this gap. */
                    break;
                } else {
                    byte_index += l_gap + l_range;
                    lowest_acknowledged = next_sack->start_of_sack_range;
                    next_sack = next_sack->next_sack;
                    num_block++;
                }
            }
            /* When numbers are lower than 64, varint encoding fits on one byte */
            bytes[num_block_index] = (uint8_t)num_block;

            /* Remember the ACK value and time */
            pkt_ctx->highest_ack_sent = pkt_ctx->first_sack_item.end_of_sack_range;
            pkt_ctx->highest_ack_sent_time = current_time;

            *consumed = byte_index;
        }

        if (ret == 0 && is_ecn) {
            ret = encode_ecn_block(cnx, bytes, bytes_max, &byte_index);
            if (ret != 0) {
                *consumed = 0;
            }
            else {
                *consumed = byte_index;
            }
        }
    }

    if (ret == 0) {
        pkt_ctx->ack_needed = 0;
    }

    return ret;
}

int picoquic_is_ack_needed(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t * next_wake_time, picoquic_packet_context_enum pc)
{
    int ret = 0;
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];

    if (pkt_ctx->ack_needed) {
        if (pkt_ctx->highest_ack_sent + 2 <= pkt_ctx->first_sack_item.end_of_sack_range ||
            pkt_ctx->highest_ack_sent_time + pkt_ctx->ack_delay_local <= current_time) {
            ret = 1;
        }
        else if (pkt_ctx->highest_ack_sent_time + pkt_ctx->ack_delay_local < *next_wake_time) {
            *next_wake_time = pkt_ctx->highest_ack_sent_time + pkt_ctx->ack_delay_local;
        }
    }
    else if (pkt_ctx->highest_ack_sent + 8 <= pkt_ctx->first_sack_item.end_of_sack_range &&
        pkt_ctx->highest_ack_sent_time + pkt_ctx->ack_delay_local <= current_time) {
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
int picoquic_prepare_connection_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t l0 = 0;
    size_t l1 = 0;
    size_t l2 = 0;

    if (bytes_max > 3) {
        bytes[byte_index++] = picoquic_frame_type_connection_close;
        if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
            picoformat_16(bytes + byte_index, (uint16_t)cnx->local_error);
            l0 = 2;
        }
        else {
            l0 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                cnx->local_error);
        }
        byte_index += l0;
        l1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, 
            cnx->offending_frame_type);
        byte_index += l1;
        l2 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, 0);
        byte_index += l2;
        *consumed = byte_index;

        if (l0 == 0 || l1 == 0 || l2 == 0) {
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
    }
    else {
        *consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }

    return ret;
}

int picoquic_decode_connection_close_frame(picoquic_cnx_t * cnx, bytestream * s)
{
    int ret = 0;
    ret |= byteread_errorcode(s, cnx, &cnx->remote_error);
    ret |= byteread_skip_vint(s);

    uint64_t length = 0;
    ret |= byteread_vint(s, &length);
    ret |= bytestream_skip(s, length);

    if (ret != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else {
        cnx->cnx_state = (cnx->cnx_state < picoquic_state_client_ready_start || cnx->crypto_context[3].aead_decrypt == NULL) ? picoquic_state_disconnected : picoquic_state_closing_received;

        if (cnx->callback_fn) {
            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
        }
    }

    if (ret != 0 && ret != -1) {
        picoquic_connection_error(cnx, (uint16_t)ret, picoquic_frame_type_connection_close);
    }

    return ret;
}

/*
 * Application close frame
 */

int picoquic_prepare_application_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t l0 = 0;
    size_t l1 = 0;

    if (bytes_max > 3) {
        bytes[byte_index++] = picoquic_frame_type_application_close;
        if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
            picoformat_16(bytes + byte_index, (uint16_t)cnx->local_error);
            l0 = 2;
        }
        else {
            l0 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                cnx->local_error);
        }
        byte_index += l0;
        l1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, 0);
        byte_index += l1;
        *consumed = byte_index;

        if (l0 == 0 || l1 == 0) {
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
    }
    else {
        *consumed = 0;
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    }

    return ret;
}

int picoquic_decode_application_close_frame(picoquic_cnx_t* cnx, bytestream * s)
{
    int ret = 0;
    ret |= byteread_errorcode(s, cnx, &cnx->remote_application_error);

    uint64_t length = 0;
    ret |= byteread_vint(s, &length);
    ret |= bytestream_skip(s, length);

    if (ret != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    }
    else {
        cnx->cnx_state = (cnx->cnx_state < picoquic_state_client_ready_start) ? picoquic_state_disconnected : picoquic_state_closing_received;
        if (cnx->callback_fn) {
            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_application_close, cnx->callback_ctx, NULL);
        }
    }

    return ret;
}



/*
 * Max data frame
 */

#define PICOQUIC_MAX_MAXDATA ((uint64_t)((int64_t)-1))
#define PICOQUIC_MAX_MAXDATA_1K (PICOQUIC_MAX_MAXDATA >> 10)
#define PICOQUIC_MAX_MAXDATA_1K_MASK (PICOQUIC_MAX_MAXDATA << 10)

int picoquic_prepare_max_data_frame(picoquic_cnx_t* cnx, uint64_t maxdata_increase,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t l1 = 0;

    if (bytes_max < 1) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        bytes[0] = picoquic_frame_type_max_data;
        l1 = picoquic_varint_encode(bytes + 1, bytes_max - 1, cnx->maxdata_local + maxdata_increase);

        if (l1 == 0) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else {
            cnx->maxdata_local = (cnx->maxdata_local + maxdata_increase);
        }

        *consumed = 1 + l1;
    }

    return ret;
}

int picoquic_decode_max_data_frame(picoquic_cnx_t* cnx, bytestream * s)
{
    int ret = 0;
    uint64_t maxdata;

    if (byteread_vint(s, &maxdata) != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else if (maxdata > cnx->maxdata_remote) {
        cnx->maxdata_remote = maxdata;
        cnx->sent_blocked_frame = 0;
    }

    return ret;
}

/*
 * Max stream data frame
 */

int picoquic_prepare_max_stream_data_frame(picoquic_stream_head_t* stream,
    uint8_t* bytes, size_t bytes_max, uint64_t new_max_data, size_t* consumed)
{
    int ret = 0;
    size_t l1 = picoquic_varint_encode(bytes + 1, bytes_max - 1, stream->stream_id);
    size_t l2 = picoquic_varint_encode(bytes + 1 + l1, bytes_max - 1 - l1, new_max_data);

    if (l1 == 0 || l2 == 0) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    } else {
        bytes[0] = picoquic_frame_type_max_stream_data;
        *consumed = 1 + l1 + l2;
        stream->maxdata_local = new_max_data;
    }

    return ret;
}

int picoquic_decode_max_stream_data_frame(picoquic_cnx_t* cnx, bytestream * s)
{
    int ret = 0;
    uint64_t stream_id;
    uint64_t maxdata = 0;
    picoquic_stream_head_t* stream = NULL;

    if (byteread_vint(s, &stream_id) != 0 ||
        byteread_vint(s, &maxdata) != 0)
    {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    }
    else if ((stream = picoquic_find_stream(cnx, stream_id)) == NULL) {
        /* Maybe not an error if the stream is already closed, so just be tolerant */
        stream = picoquic_create_missing_streams(cnx, stream_id, 1);
    }
    
    if (stream != NULL && maxdata > stream->maxdata_remote) {
        /* TODO: call back if the stream was blocked? */
        stream->maxdata_remote = maxdata;
    }

    return ret;
}

int picoquic_prepare_required_max_stream_data_frames(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    picoquic_stream_head_t* stream = picoquic_first_stream(cnx);

    while (stream != NULL && ret == 0 && byte_index < bytes_max) {
        if (!stream->fin_received && !stream->reset_received && 2 * stream->consumed_offset > stream->maxdata_local) {
            size_t bytes_in_frame = 0;

            ret = picoquic_prepare_max_stream_data_frame(stream,
                bytes + byte_index, bytes_max - byte_index,
                stream->maxdata_local + 2 * stream->consumed_offset,
                &bytes_in_frame);
            if (ret == 0) {
                byte_index += bytes_in_frame;
            } else {
                break;
            }
        }
        stream = picoquic_next_stream(stream);
    }

    if (ret == 0 && stream == NULL) {
        cnx->max_stream_data_needed = 0;
    }

    if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
        ret = 0;
    }

    if (ret == 0) {
        *consumed = byte_index;
    } else {
        *consumed = 0;
    }

    return ret;
}

/*
 * Max stream ID frames
 */
int picoquic_prepare_max_streams_frame_if_needed(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    uint64_t new_bidir_local = cnx->max_stream_id_bidir_local;
    uint64_t new_unidir_local = cnx->max_stream_id_unidir_local;

    *consumed = 0;
    
    if (cnx->max_stream_id_bidir_local_computed + (cnx->local_parameters.initial_max_stream_id_bidir >> 1) > cnx->max_stream_id_bidir_local) {
        if (1 > bytes_max) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
        else {
            size_t l1;
            
            new_bidir_local = cnx->max_stream_id_bidir_local + 4* STREAM_RANK_FROM_ID(cnx->local_parameters.initial_max_stream_id_bidir) + 4;
            
            l1 = picoquic_varint_encode(bytes + 1, bytes_max - 1, STREAM_RANK_FROM_ID(new_bidir_local));

            if (l1 == 0) {
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            }
            else {
                bytes[0] = picoquic_frame_type_max_streams_bidir;

                byte_index = 1 + l1;
            }
        }
    }

    if (ret == 0) {

        if (cnx->max_stream_id_unidir_local_computed + (cnx->local_parameters.initial_max_stream_id_unidir >> 1) > cnx->max_stream_id_unidir_local) {
            if (byte_index + 1 > bytes_max) {
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            }
            else {
                size_t l1;
                new_unidir_local = cnx->max_stream_id_unidir_local + cnx->local_parameters.initial_max_stream_id_unidir + 4;

                l1 = picoquic_varint_encode(bytes + 1, bytes_max - 1, new_unidir_local);

                if (l1 == 0) {
                    ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                }
                else {
                    bytes[0] = picoquic_frame_type_max_streams_unidir;
                    byte_index += 1 + l1;
                }
            }
        }
    }

    if (ret == 0) {
        cnx->max_stream_id_bidir_local = new_bidir_local;
        cnx->max_stream_id_unidir_local = new_unidir_local;
        *consumed = byte_index;
    }

    return ret;
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

int picoquic_decode_max_streams_frame(picoquic_cnx_t* cnx, uint8_t ftype, bytestream * s)
{
    int ret = 0;
    uint64_t max_stream_rank;

    if ((byteread_vint(s, &max_stream_rank)) != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    }
    else {
        uint64_t max_stream_id;
        if (ftype == picoquic_frame_type_max_streams_bidir) {
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
            ret = PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR;
        }
    }

    return ret;
}



/*
 * Sending of miscellaneous frames
 */

int picoquic_prepare_first_misc_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
                                      size_t bytes_max, size_t* consumed)
{
    int ret = picoquic_prepare_misc_frame(cnx->first_misc_frame, bytes, bytes_max, consumed);

    if (ret == 0) {
        picoquic_misc_frame_header_t* misc_frame = cnx->first_misc_frame;
        cnx->first_misc_frame = misc_frame->next_misc_frame;
        free(misc_frame);
    }

    return ret;
}

int picoquic_prepare_misc_frame(picoquic_misc_frame_header_t* misc_frame, uint8_t* bytes,
                                size_t bytes_max, size_t* consumed)
{
    int ret = 0;

    if (misc_frame->length > bytes_max) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    } else {
        uint8_t* frame = ((uint8_t*)misc_frame) + sizeof(picoquic_misc_frame_header_t);
        memcpy(bytes, frame, misc_frame->length);
        *consumed = misc_frame->length;
    }

    return ret;
}

/*
 * Path Challenge and Response frames
 */

int picoquic_prepare_path_challenge_frame(uint8_t* bytes,
    size_t bytes_max, size_t* consumed, uint64_t challenge)
{
    int ret = 0;
    if (bytes_max < (1 + 8)) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    } else {
        bytes[0] = picoquic_frame_type_path_challenge;
        picoformat_64(bytes + 1, challenge);
        *consumed = 1 + 8;
    }

    return ret;
}

int picoquic_decode_path_challenge_frame(picoquic_cnx_t* cnx, bytestream * s,
    picoquic_path_t * path_x, struct sockaddr* addr_from, struct sockaddr* addr_to)
{
    int ret = 0;
    uint64_t challenge_response;

    if (byteread_int64(s, &challenge_response) != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else if (path_x != NULL) {
        /*
         * Queue a response frame as response to path challenge.
         * TODO: ensure it goes out on the same path as the incoming challenge.
         */
        if ((addr_from == NULL || picoquic_compare_addr(addr_from, (struct sockaddr *)&path_x->peer_addr) == 0) &&
            (addr_to == NULL || picoquic_compare_addr(addr_to, (struct sockaddr *)&path_x->local_addr) == 0)) {
            path_x->challenge_response = challenge_response;
            path_x->response_required = 1;
        }
        else if (addr_from != NULL && picoquic_compare_addr(addr_from, (struct sockaddr *)&path_x->alt_peer_addr) == 0 &&
            addr_to != NULL && picoquic_compare_addr(addr_to, (struct sockaddr *)&path_x->alt_local_addr) == 0) {
            path_x->alt_challenge_response = challenge_response;
            path_x->alt_response_required = 1;
            cnx->alt_path_challenge_needed = 1;
        } else {
            DBG_PRINTF("%s", "Path challenge ignored, wrong addresses\n");
        }
    }

    return ret;
}

int picoquic_prepare_path_response_frame(uint8_t* bytes,
    size_t bytes_max, size_t* consumed, uint64_t challenge)
{
    int ret = 0;
    if (bytes_max < (1 + 8)) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    }
    else {
        bytes[0] = picoquic_frame_type_path_response;
        picoformat_64(bytes + 1, challenge);
        *consumed = 1 + 8;
    }

    return ret;
}

int picoquic_decode_path_response_frame(picoquic_cnx_t* cnx, bytestream * s,
    struct sockaddr* addr_from, struct sockaddr* addr_to)
{
    int ret = 0;
    uint64_t response;

    if (byteread_int64(s, &response) != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
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
                if (picoquic_supported_versions[cnx->version_index].version != PICOQUIC_TWELFTH_INTEROP_VERSION ||
                    ((addr_from == NULL || picoquic_compare_addr(addr_from, (struct sockaddr *)&cnx->path[i]->peer_addr) == 0) &&
                        (addr_to == NULL || picoquic_compare_addr(addr_to, (struct sockaddr *)&cnx->path[i]->local_addr) == 0))) {
                        cnx->path[i]->challenge_verified = 1;
                    }
                    else {
                        DBG_PRINTF("%s", "Challenge response from different address, ignored.\n");
                    }
                    break;
            }
            else {
                for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
                    if (response == cnx->path[i]->alt_challenge[ichal]) {
                        found_challenge = 1;
                        break;
                    }
                }
                if (found_challenge) {
                    if (picoquic_supported_versions[cnx->version_index].version != PICOQUIC_TWELFTH_INTEROP_VERSION ||
                        ((addr_from == NULL || picoquic_compare_addr(addr_from, (struct sockaddr *)&cnx->path[i]->alt_peer_addr) == 0) &&
                        (addr_to == NULL || picoquic_compare_addr(addr_to, (struct sockaddr *)&cnx->path[i]->alt_local_addr) == 0))) {
                        /* Promote the alt address to valid address */
                        cnx->path[i]->peer_addr_len = picoquic_store_addr(&cnx->path[i]->peer_addr, (struct sockaddr *)&cnx->path[i]->alt_peer_addr);
                        cnx->path[i]->local_addr_len = picoquic_store_addr(&cnx->path[i]->local_addr, (struct sockaddr *)&cnx->path[i]->alt_local_addr);
                        memset(&cnx->path[i]->alt_peer_addr, 0, sizeof(cnx->path[i]->alt_peer_addr));
                        memset(&cnx->path[i]->alt_local_addr, 0, sizeof(cnx->path[i]->alt_local_addr));
                        cnx->path[i]->challenge_response = cnx->path[i]->alt_challenge_response;
                        cnx->path[i]->response_required = cnx->path[i]->alt_response_required;
                        cnx->path[i]->alt_peer_addr_len = 0;
                        cnx->path[i]->alt_local_addr_len = 0;
                        cnx->path[i]->alt_challenge_timeout = 0;
                        cnx->path[i]->challenge_verified = 1;
                        cnx->path[i]->alt_challenge_required = 0;
                        cnx->path[i]->alt_response_required = 0;
                        cnx->path[i]->alt_challenge_response = 0;
                    }
                    else {
                        DBG_PRINTF("%s", "Rebinding response from different address, ignored.\n");
                    }
                    break;
                }
            }
        }

        if (found_challenge == 0) {
            picoquic_probe_t * probe = picoquic_find_probe_by_challenge(cnx, response);

            if (probe != NULL){
                if (picoquic_supported_versions[cnx->version_index].version != PICOQUIC_TWELFTH_INTEROP_VERSION ||
                    (addr_from != NULL && picoquic_compare_addr(addr_from, (struct sockaddr *)&probe->peer_addr) == 0 &&
                    addr_to != NULL && picoquic_compare_addr(addr_to, (struct sockaddr *)&probe->local_addr) == 0)) {
                    probe->challenge_verified = 1;
                    cnx->has_successful_probe = 1;
                }
                else {
                    DBG_PRINTF("%s", "Probe response from different address, ignored.\n");
                }
            }
        }
    }

    return ret;
}


int picoquic_decode_blocked_frame(picoquic_cnx_t * cnx, bytestream * s)
{
    UNREFERENCED_PARAMETER(cnx);

    if (byteread_skip_vint(s) != 0) {
        return PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else {
        return 0;
    }
}


int picoquic_decode_stream_blocked_frame(picoquic_cnx_t * cnx, bytestream * s)
{
    UNREFERENCED_PARAMETER(cnx);

    /* TODO: check that the stream number is valid */
    if (byteread_skip_vint(s) != 0 || byteread_skip_vint(s) != 0) {
        return PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else {
        return 0;
    }
}


int picoquic_decode_streams_blocked_frame(picoquic_cnx_t * cnx, bytestream * s)
{
    UNREFERENCED_PARAMETER(cnx);

    if (byteread_skip_vint(s) != 0) {
        return PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else {
        return 0;
    }
}


static uint8_t* picoquic_skip_0len_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t frame = bytes[0];
    do {
        bytes++;
    } while (bytes < bytes_max && *bytes == frame);
    return bytes;
}

static void picoquic_skip_0len_frame_(bytestream * s, uint8_t ftype)
{
    uint8_t i8 = 0;
    while (byteshow_int8(s, &i8) == 0 && i8 == ftype) {
        bytestream_skip(s, 1u);
    }
}

/* Handling of datagram frames.
 * We follow the spec in
 * https://datatracker.ietf.org/doc/draft-pauly-quic-datagram/?include_text=1
 */

uint8_t* picoquic_skip_datagram_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t frame_id = *bytes++;
    unsigned int has_length = frame_id & 1;
    unsigned int has_id = (frame_id & 2)>>1;
    uint64_t length = 0;

    if (has_id) {
        bytes = picoquic_frames_varint_skip(bytes, bytes_max);
    }

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

int picoquic_decode_datagram_frame(picoquic_cnx_t* cnx, uint8_t ftype, bytestream * s)
{
    int ret = 0;

    uint64_t id = 0;
    if (ftype & 2) {
        ret |= byteread_vint(s, &id);
    }

    uint64_t length = bytestream_remain(s);
    if (ftype & 1) {
        ret |= byteread_vint(s, &length);
    }

    uint8_t* data_bytes = (uint8_t*)bytestream_ptr(s);
    ret |= bytestream_skip(s, length);

    if (ret != 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    } else if (cnx->callback_fn != NULL) {
        /* submit the data to the app */
        if (cnx->callback_fn(cnx, id, data_bytes, (size_t)length, picoquic_callback_datagram,
            cnx->callback_ctx, NULL) != 0) {
            ret = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
        }
    }

    return ret;
}


int picoquic_prepare_datagram_frame(uint64_t id, size_t length, uint8_t * src, uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t l_id = 0;
    size_t l_l = 0;

    bytes[byte_index++] = (id == 0) ? picoquic_frame_type_datagram_l : picoquic_frame_type_datagram_id_l;

    if (id == 0) {
        bytes[byte_index++] = picoquic_frame_type_datagram_l;
    }
    else {
        bytes[byte_index++] = picoquic_frame_type_datagram_id_l;

        l_id = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, id);
        byte_index += l_id;
    }
    
    l_l = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, length);
    byte_index += l_l;

    if (l_l > 0 && l_id> 0 && byte_index + length <= bytes_max) {
        memcpy(bytes + byte_index, src, length);
        byte_index += length;
    }
    else {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        byte_index = 0;
    }

    *consumed = byte_index;

    return ret;
}

int picoquic_queue_datagram_frame(picoquic_cnx_t * cnx, uint64_t id,
    size_t length, uint8_t * bytes)
{
    size_t consumed = 0;
    uint8_t frame_buffer[PICOQUIC_MAX_PACKET_SIZE];
    int ret = picoquic_prepare_datagram_frame(id, length, bytes, frame_buffer, sizeof(frame_buffer), &consumed);

    if (ret == 0 && consumed > 0) {
        ret = picoquic_queue_misc_frame(cnx, frame_buffer, consumed);
    }

    return ret;
}

/*
 * Decoding of the received frames.
 *
 * In some cases, the expected frames are "restricted" to only ACK, STREAM 0 and PADDING.
 */

int picoquic_decode_frames(picoquic_cnx_t* cnx, picoquic_path_t * path_x, uint8_t* bytes,
    size_t bytes_maxsize, int epoch,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to, uint64_t current_time)
{
    int ret = 0;
    int ack_needed = 0;
    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];

    bytestream bs;
    bytestream * s = bytestream_ref_init(&bs, bytes, bytes_maxsize);

    while (ret == 0 && !bytestream_finished(s)) {

        uint8_t ftype;
        byteread_int8(s, &ftype);

        if (PICOQUIC_IN_RANGE(ftype, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {

            ret = picoquic_decode_stream_frame(cnx, epoch, ftype, s, current_time);
            ack_needed = 1;

        } else if (epoch != 1 && epoch != 3 && ftype != picoquic_frame_type_padding
                                            && ftype != picoquic_frame_type_ack
                                            && ftype != picoquic_frame_type_ack_ecn
                                            && ftype != picoquic_frame_type_path_challenge
                                            && ftype != picoquic_frame_type_path_response
                                            && ftype != picoquic_frame_type_connection_close
                                            && ftype != picoquic_frame_type_crypto_hs) {
            ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;

        } else {
            switch (ftype) {
            case picoquic_frame_type_padding:
                picoquic_skip_0len_frame_(s, ftype);
                break;
            case picoquic_frame_type_ping:
                picoquic_skip_0len_frame_(s, ftype);
                ack_needed = 1;
                break;
            case picoquic_frame_type_ack:
            case picoquic_frame_type_ack_ecn:
                ret = picoquic_decode_ack_frame(cnx, epoch, ftype, s, current_time);
                break;
            case picoquic_frame_type_reset_stream:
                ret = picoquic_decode_stream_reset_frame(cnx, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stop_sending:
                ret = picoquic_decode_stop_sending_frame(cnx, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_crypto_hs:
                ret = picoquic_decode_crypto_hs_frame(cnx, epoch, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_new_token:
                ret = picoquic_decode_new_token_frame(cnx, s, current_time, addr_to);
                ack_needed = 1;
                break;
            case picoquic_frame_type_max_data:
                ret = picoquic_decode_max_data_frame(cnx, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_max_stream_data:
                ret = picoquic_decode_max_stream_data_frame(cnx, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_max_streams_bidir:
            case picoquic_frame_type_max_streams_unidir:
                ret = picoquic_decode_max_streams_frame(cnx, ftype, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_data_blocked:
                ret = picoquic_decode_blocked_frame(cnx, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stream_data_blocked:
                ret = picoquic_decode_stream_blocked_frame(cnx, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_streams_blocked_unidir:
            case picoquic_frame_type_streams_blocked_bidir:
                ret = picoquic_decode_streams_blocked_frame(cnx, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_new_connection_id:
                ret = picoquic_decode_new_connection_id_frame(cnx, s, current_time);
                ack_needed = 1;
                break;
            case picoquic_frame_type_retire_connection_id:
                /* the old code point for ACK frames, but this is taken care of in the ACK tests above */
                ret = picoquic_decode_retire_connection_id_frame(cnx, s, current_time, path_x);
                ack_needed = 1;
                break;
            case picoquic_frame_type_path_challenge:
                ret = picoquic_decode_path_challenge_frame(cnx, s, path_x, addr_from, addr_to);
                break;
            case picoquic_frame_type_path_response:
                ret = picoquic_decode_path_response_frame(cnx, s, addr_from, addr_to);
                break;
            case picoquic_frame_type_connection_close:
                ret = picoquic_decode_connection_close_frame(cnx, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_application_close:
                ret = picoquic_decode_application_close_frame(cnx, s);
                ack_needed = 1;
                break;
            case picoquic_frame_type_datagram:
            case picoquic_frame_type_datagram_l:
            case picoquic_frame_type_datagram_id:
            case picoquic_frame_type_datagram_id_l:
                ret = picoquic_decode_datagram_frame(cnx, ftype, s);
                break;
            default: {
                uint64_t frame_id64;
                if ((ret = byteread_vint(s, &frame_id64)) == 0) {
                    /* Not implemented yet! */
                    ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
                }
                break;
            }
            }
        }
        if (ret != 0 && ret != -1) {
            picoquic_connection_error(cnx, (uint16_t)ret, ftype);
        }
    }

    if (bytes != NULL && ack_needed != 0) {
        cnx->latest_progress_time = current_time;
        pkt_ctx->ack_needed = 1;
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
static uint8_t* picoquic_skip_connection_close_frame(picoquic_cnx_t * cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
        bytes = picoquic_frames_fixed_skip(bytes + 1, bytes_max, sizeof(uint16_t));
    }
    else {
        bytes = picoquic_frames_varint_skip(bytes + 1, bytes_max);
    }
    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_skip(bytes,  bytes_max)) != NULL) {
        bytes = picoquic_frames_length_data_skip(bytes, bytes_max);
    }
    return bytes;
}

static uint8_t* picoquic_skip_application_close_frame(picoquic_cnx_t * cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
        bytes = picoquic_frames_fixed_skip(bytes + 1, bytes_max, sizeof(uint16_t));
    }
    else {
        bytes = picoquic_frames_varint_skip(bytes + 1, bytes_max);
    }

    if (bytes != NULL) {
        bytes = picoquic_frames_length_data_skip(bytes, bytes_max);
    }
    return bytes;
}

/* Lots of simple frames...
 */

static uint8_t* picoquic_skip_stream_reset_frame(picoquic_cnx_t * cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    /* Stream ID */
    bytes = picoquic_frames_varint_skip(bytes + 1, bytes_max);
    /* Error code */
    if (bytes != NULL) {
        if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
            bytes = picoquic_frames_fixed_skip(bytes, bytes_max, sizeof(uint16_t));
        }
        else {
            bytes = picoquic_frames_varint_skip(bytes, bytes_max);
        }
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


int picoquic_skip_frame(picoquic_cnx_t * cnx, uint8_t* bytes, size_t bytes_maxsize, size_t* consumed, int* pure_ack)
{
    const uint8_t *bytes_max = bytes + bytes_maxsize;
    uint8_t first_byte = bytes[0];

    *pure_ack = 1;

    if (PICOQUIC_IN_RANGE(first_byte, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
        *pure_ack = 0;
        bytes = picoquic_skip_stream_frame(bytes, bytes_max);
    } else if (first_byte == picoquic_frame_type_ack || first_byte == picoquic_frame_type_ack_ecn) {
        bytes = picoquic_skip_ack_frame(bytes, bytes_max);
    } else {
        switch (first_byte) {
        case picoquic_frame_type_padding:
            bytes = picoquic_skip_0len_frame(bytes, bytes_max);
            break;
        case picoquic_frame_type_reset_stream:
            bytes = picoquic_skip_stream_reset_frame(cnx, bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_connection_close: {
            bytes = picoquic_skip_connection_close_frame(cnx, bytes, bytes_max);
            *pure_ack = 0;
            break;
        }
        case picoquic_frame_type_application_close: {
            bytes = picoquic_skip_application_close_frame(cnx, bytes, bytes_max);
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
            bytes = picoquic_skip_new_connection_id_frame(cnx, bytes, bytes_max);
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
        case picoquic_frame_type_datagram:
        case picoquic_frame_type_datagram_l:
        case picoquic_frame_type_datagram_id:
        case picoquic_frame_type_datagram_id_l:
            bytes = picoquic_skip_datagram_frame(bytes, bytes_max);
            break;
        default: {
            uint64_t frame_id64;
            if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_id64)) != NULL) {
                /* Not implemented yet! */
                bytes = NULL;
            }
            break;
        }
        }
    }

    *consumed = (bytes != NULL) ? bytes_maxsize - (bytes_max - bytes) : bytes_maxsize;

    return bytes == NULL;
}

int picoquic_decode_closing_frames(picoquic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max, int* closing_received)
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

            ret = picoquic_skip_frame(cnx, bytes + byte_index,
                bytes_max - byte_index, &consumed, &pure_ack);
            byte_index += consumed;
        }
    }

    return ret;
}
