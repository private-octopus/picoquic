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
#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>

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

#define VARINT_LEN(bytes) (1U << (((bytes)[0] & 0xC0) >> 6))


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

    if (bytes < bytes_max && bytes + (length=VARINT_LEN(bytes)) <= bytes_max) {
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


static uint8_t* picoquic_frames_uint8_decode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t* n)
{
    if (bytes < bytes_max) {
        *n = *bytes++;
    } else {
        bytes = NULL;
    }
    return bytes;
}


static uint8_t* picoquic_frames_uint16_decode(uint8_t* bytes, const uint8_t* bytes_max, uint16_t* n)
{
    if (bytes + sizeof(*n) <= bytes_max) {
        *n = PICOPARSE_16(bytes);
        bytes += sizeof(*n);
    } else {
        bytes = NULL;
    }
    return bytes;
}


static uint8_t* picoquic_frames_uint64_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n)
{
    if (bytes + sizeof(*n) <= bytes_max) {
        *n = PICOPARSE_64(bytes);
        bytes += sizeof(*n);
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

picoquic_stream_head* picoquic_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head* stream = (picoquic_stream_head*)malloc(sizeof(picoquic_stream_head));
    if (stream != NULL) {
        picoquic_stream_head* previous_stream = NULL;
        picoquic_stream_head* next_stream = cnx->first_stream;

        memset(stream, 0, sizeof(picoquic_stream_head));
        stream->stream_id = stream_id;
        stream->maxdata_local = cnx->local_parameters.initial_max_stream_data;
        stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data;

        /*
         * Make sure that the streams are open in order.
         */

        while (next_stream != NULL && next_stream->stream_id < stream_id) {
            previous_stream = next_stream;
            next_stream = next_stream->next_stream;
        }

        stream->next_stream = next_stream;

        if (previous_stream == NULL) {
            cnx->first_stream = stream;
        } else {
            previous_stream->next_stream = stream;
        }
    }

    return stream;
}

/* if the initial remote has changed, update the existing streams
 */

void picoquic_update_stream_initial_remote(picoquic_cnx_t* cnx)
{
    picoquic_stream_head* stream = cnx->first_stream;

    while (stream) {
        if (stream->maxdata_remote < cnx->remote_parameters.initial_max_stream_data) {
            stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data;
        }
        stream = stream->next_stream;
    };
}

picoquic_stream_head* picoquic_find_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int create)
{
    picoquic_stream_head* stream = cnx->first_stream;

    while (stream) {
        if (stream->stream_id == stream_id) {
            break;
        } else {
            stream = stream->next_stream;
        }
    };

    if (create != 0 && stream == NULL) {
        stream = picoquic_create_stream(cnx, stream_id);
    }

    return stream;
}

picoquic_stream_head* picoquic_find_or_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int is_remote)
{
    picoquic_stream_head* stream = picoquic_find_stream(cnx, stream_id, 0);

    if (stream == NULL) {
        /* Verify the stream ID control conditions */
        unsigned int expect_client_stream = cnx->client_mode ^ is_remote;
        uint64_t max_stream = IS_BIDIR_STREAM_ID(stream_id) ? cnx->max_stream_id_bidir_local : cnx->max_stream_id_unidir_local;

        if (IS_CLIENT_STREAM_ID(stream_id) != expect_client_stream || stream_id > max_stream) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_ID_ERROR);

        } else if ((stream = picoquic_create_stream(cnx, stream_id)) == NULL) {
            picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY);

        } else if (!IS_BIDIR_STREAM_ID(stream_id)) {
            /* Mark the stream as already finished in our direction */
            stream->stream_flags |= picoquic_stream_flag_fin_notified | picoquic_stream_flag_fin_sent;
        }
    }

    return stream;
}

/*
 * Check of the number of newly received bytes, or newly committed bytes
 * when a new max offset is learnt for a stream.
 */

int picoquic_flow_control_check_stream_offset(picoquic_cnx_t* cnx, picoquic_stream_head* stream,
    uint64_t new_fin_offset)
{
    int ret = 0;

    if (new_fin_offset > stream->maxdata_local) {
        /* protocol violation */
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR);
    } else if (new_fin_offset > stream->fin_offset) {
        /* Checking the flow control limits. Need to pay attention
        * to possible integer overflow */

        uint64_t new_bytes = new_fin_offset - stream->fin_offset;

        if (new_bytes > cnx->maxdata_local || cnx->maxdata_local - new_bytes < cnx->data_received) {
            /* protocol violation */
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR);
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

int picoquic_prepare_stream_reset_frame(picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;

    if ((stream->stream_flags & picoquic_stream_flag_reset_requested) == 0 || (stream->stream_flags & picoquic_stream_flag_reset_sent) != 0) {
        *consumed = 0;
    } else {
        size_t l1 = 0, l2 = 0;
        if (bytes_max > 2) {
            bytes[byte_index++] = picoquic_frame_type_reset_stream;
            l1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->stream_id);
            byte_index += l1;
            if (l1 > 0 && bytes_max > byte_index + 3) {
                picoformat_16(bytes + byte_index, (uint16_t)stream->local_error);
                byte_index += 2;
                l2 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->sent_offset);
                byte_index += l2;
            }
        }

        if (l1 == 0 || l2 == 0) {
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            *consumed = 0;
        } else {
            *consumed = byte_index;
            stream->stream_flags |= picoquic_stream_flag_reset_sent | picoquic_stream_flag_fin_sent;

            /* Free the queued data */
            while (stream->send_queue != NULL) {
                picoquic_stream_data* next = stream->send_queue->next_stream_data;
                if (stream->send_queue->bytes != NULL) {
                    free(stream->send_queue->bytes);
                }
                free(stream->send_queue);
                stream->send_queue = next;
            }
        }
    }

    return ret;
}

uint8_t* picoquic_decode_stream_reset_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t stream_id = 0;
    uint16_t error_code = 0;
    uint64_t final_offset = 0;
    picoquic_stream_head* stream;

    if ((bytes = picoquic_frames_varint_decode(bytes+1, bytes_max, &stream_id))    == NULL ||
        (bytes = picoquic_frames_uint16_decode(bytes,   bytes_max, &error_code))   == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes,   bytes_max, &final_offset)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);

    } else if ((stream = picoquic_find_or_create_stream(cnx, stream_id, 1)) == NULL) {
        bytes = NULL;  // error already signaled

    } else if ((stream->stream_flags & (picoquic_stream_flag_fin_received | picoquic_stream_flag_reset_received)) != 0 && final_offset != stream->fin_offset) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR);
        bytes = NULL;

    } else if (picoquic_flow_control_check_stream_offset(cnx, stream, final_offset) != 0) {
        bytes = NULL;  // error already signaled

    } else if ((stream->stream_flags & picoquic_stream_flag_reset_received) == 0) {
        stream->stream_flags |= picoquic_stream_flag_reset_received;
        stream->remote_error  = error_code;

        if (cnx->callback_fn != NULL && (stream->stream_flags & picoquic_stream_flag_reset_signalled) == 0) {
            cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stream_reset, cnx->callback_ctx);
            stream->stream_flags |= picoquic_stream_flag_reset_signalled;
        }
    }

    return bytes;
}

/*
 * New Connection ID frame
 */

uint8_t* picoquic_skip_connection_id_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    uint8_t cid_length;

    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max))              != NULL &&
        (bytes = picoquic_frames_uint8_decode(bytes,  bytes_max, &cid_length)) != NULL)
    {
        bytes = picoquic_frames_fixed_skip(bytes, bytes_max, cid_length + 16);
    }

    return bytes;
}


uint8_t* picoquic_decode_connection_id_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    /* TODO: store the connection ID in order to support migration. */
    if ((bytes = picoquic_skip_connection_id_frame(bytes, bytes_max)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
    }

    return bytes;
}

/*
 * New Retry Token frame 
 */
uint8_t* picoquic_skip_new_token_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    return picoquic_frames_length_data_skip(bytes+1, bytes_max);
}


uint8_t* picoquic_decode_new_token_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    /* TODO: store the new token in order to support immediate connection on some servers. */
    if ((bytes = picoquic_skip_new_token_frame(bytes, bytes_max)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
    }

    return bytes;
}

/*
 * STOP SENDING Frame
 */

int picoquic_prepare_stop_sending_frame(picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    const size_t min_length = 1 + 4 + 2;
    size_t byte_index = 0;

    if (bytes_max < min_length) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else if ((stream->stream_flags & picoquic_stream_flag_stop_sending_requested) == 0 || (stream->stream_flags & picoquic_stream_flag_stop_sending_sent) != 0 || (stream->stream_flags & picoquic_stream_flag_fin_received) != 0 || (stream->stream_flags & picoquic_stream_flag_reset_received) != 0) {
        *consumed = 0;
    } else {
        bytes[byte_index++] = picoquic_frame_type_stop_sending;
        byte_index += picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
            (uint64_t)stream->stream_id);
        picoformat_16(bytes + byte_index, (uint16_t)stream->local_stop_error);
        byte_index += 2;
        *consumed = byte_index;
        stream->stream_flags |= picoquic_stream_flag_stop_sending_sent;
    }

    return ret;
}

uint8_t* picoquic_decode_stop_sending_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t stream_id = 0;
    uint16_t error_code = 0;
    picoquic_stream_head* stream;

    if ((bytes = picoquic_frames_varint_decode(bytes+1, bytes_max, &stream_id))  == NULL ||
        (bytes = picoquic_frames_uint16_decode(bytes,   bytes_max, &error_code)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);

    } else if ((stream = picoquic_find_or_create_stream(cnx, stream_id, 1)) == NULL) {
        bytes = NULL;  // Error already signaled

    } else if ((stream->stream_flags & (picoquic_stream_flag_stop_sending_received | picoquic_stream_flag_reset_requested)) == 0) {
        stream->stream_flags |= picoquic_stream_flag_stop_sending_received;
        stream->remote_stop_error = error_code;

        if (cnx->callback_fn != NULL && (stream->stream_flags & picoquic_stream_flag_stop_sending_signalled) == 0) {
            cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stop_sending, cnx->callback_ctx);
            stream->stream_flags |= picoquic_stream_flag_stop_sending_signalled;
        }
    }

    return bytes;
}

uint8_t* picoquic_skip_stop_sending_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) != NULL) {
        bytes = picoquic_frames_fixed_skip(bytes, bytes_max, sizeof(uint16_t));
    }
    return bytes;
}


/*
 * Stream frame.
 * In our implementation, stream 0 is special, and feeds directly
 * into the SSL API.
 *
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

void picoquic_stream_data_callback(picoquic_cnx_t* cnx, picoquic_stream_head* stream)
{
    picoquic_stream_data* data = stream->stream_data;

    while (data != NULL && data->offset <= stream->consumed_offset) {
        size_t start = (size_t)(stream->consumed_offset - data->offset);
        size_t data_length = data->length - start;
        picoquic_call_back_event_t fin_now = picoquic_callback_no_event;

        stream->consumed_offset += data_length;

        if (stream->consumed_offset >= stream->fin_offset && (stream->stream_flags & (picoquic_stream_flag_fin_received | picoquic_stream_flag_fin_signalled)) == picoquic_stream_flag_fin_received) {
            fin_now = picoquic_callback_stream_fin;
            stream->stream_flags |= picoquic_stream_flag_fin_signalled;
        }

        cnx->callback_fn(cnx, stream->stream_id, data->bytes + start, data_length, fin_now,
            cnx->callback_ctx);

        free(data->bytes);
        stream->stream_data = data->next_stream_data;
        free(data);
        data = stream->stream_data;
    }

    /* handle the case where the fin frame does not carry any data */

    if (stream->consumed_offset >= stream->fin_offset && (stream->stream_flags & (picoquic_stream_flag_fin_received | picoquic_stream_flag_fin_signalled)) == picoquic_stream_flag_fin_received) {
        stream->stream_flags |= picoquic_stream_flag_fin_signalled;
        cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stream_fin,
            cnx->callback_ctx);
    }
}

/* Common code to data stream and crypto hs stream */
static int picoquic_queue_network_input(picoquic_cnx_t* cnx, picoquic_stream_head* stream, size_t offset, uint8_t* bytes, size_t length, int * new_data_available)
{
    int ret = 0;
    picoquic_stream_data** pprevious = &stream->stream_data;
    picoquic_stream_data* next = stream->stream_data;
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
            picoquic_stream_data* data = (picoquic_stream_data*)malloc(sizeof(picoquic_stream_data));

            if (data == NULL) {
                ret = picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY);
            }
            else {
                data->length = data_length;
                data->bytes = (uint8_t*)malloc(data_length);
                if (data->bytes == NULL) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY);
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
    picoquic_stream_head* stream;
    uint64_t new_fin_offset = offset + length;

    if ((stream = picoquic_find_or_create_stream(cnx, stream_id, 1)) == NULL) {
        ret = 1;  // Error already signaled

    } else if ((stream->stream_flags & picoquic_stream_flag_fin_received) != 0) {

        if (fin != 0 ? stream->fin_offset != new_fin_offset : new_fin_offset > stream->fin_offset) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR);
        }

    } else {
        if (fin) {
            stream->stream_flags |= picoquic_stream_flag_fin_received;
            should_notify = 1;
            cnx->latest_progress_time = current_time;
        }

        if (new_fin_offset > stream->fin_offset) {
            ret = picoquic_flow_control_check_stream_offset(cnx, stream, new_fin_offset);
        }
    }

    if (ret == 0) {
        int new_data_available = 0;

        ret = picoquic_queue_network_input(cnx, stream, (size_t)offset, bytes, length, &new_data_available);

        if (new_data_available) {
            should_notify = 1;
            cnx->latest_progress_time = current_time;
        }
    }

    if (ret == 0 && should_notify != 0 && cnx->callback_fn != NULL) {
        /* check how much data there is to send */
        picoquic_stream_data_callback(cnx, stream);
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

    if (picoquic_parse_stream_header(bytes, bytes_max-bytes, &stream_id, &offset, &data_length, &fin, &consumed) != 0) {
        bytes = NULL;
    } else if (picoquic_stream_network_input(cnx, stream_id, offset, fin, (bytes += consumed), data_length, current_time) != 0) {
        bytes = NULL;
    } else {
        bytes += data_length;
    }

    return bytes;
}

picoquic_stream_head* picoquic_find_ready_stream(picoquic_cnx_t* cnx)
{
    picoquic_stream_head* stream = cnx->first_stream;

    if (cnx->maxdata_remote > cnx->data_sent) {
        while (stream) {
            if ((stream->stream_flags & picoquic_stream_flag_reset_sent) == 0 && ((stream->send_queue != NULL &&
                stream->send_queue->length > stream->send_queue->offset &&
                stream->sent_offset < stream->maxdata_remote) ||
                ((stream->stream_flags & picoquic_stream_flag_fin_notified) != 0 &&
                (stream->stream_flags & picoquic_stream_flag_fin_sent) == 0 &&
                    (stream->sent_offset < stream->maxdata_remote)) ||
                    (stream->stream_flags & picoquic_stream_flag_reset_requested) != 0 || ((stream->stream_flags & picoquic_stream_flag_stop_sending_requested) != 0 && (stream->stream_flags & picoquic_stream_flag_stop_sending_sent) == 0))) {
                /* if the stream is not active yet, verify that it fits under
                 * the max stream id limit */
                 /* Check parity */
                if (IS_CLIENT_STREAM_ID(stream->stream_id) == cnx->client_mode) {
                    if (stream->stream_id <= cnx->max_stream_id_bidir_remote) {
                        break;
                    }
                }
                else {
                    break;
                }
            }

            stream = stream->next_stream;

        } ;
    } else {
        if ((stream->send_queue == NULL || stream->send_queue->length <= stream->send_queue->offset) && ((stream->stream_flags & picoquic_stream_flag_fin_notified) == 0 || (stream->stream_flags & picoquic_stream_flag_fin_sent) != 0) && ((stream->stream_flags & picoquic_stream_flag_reset_requested) == 0 || (stream->stream_flags & picoquic_stream_flag_reset_sent) != 0) && ((stream->stream_flags & picoquic_stream_flag_stop_sending_requested) == 0 || (stream->stream_flags & picoquic_stream_flag_stop_sending_sent) != 0)) {
            stream = NULL;
        }
    }

    return stream;
}

int picoquic_prepare_stream_frame(picoquic_cnx_t* cnx, picoquic_stream_head* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;

    if ((stream->stream_flags & picoquic_stream_flag_reset_requested) != 0) {
        return picoquic_prepare_stream_reset_frame(stream, bytes, bytes_max, consumed);
    }

    if ((stream->stream_flags & picoquic_stream_flag_stop_sending_requested) != 0 && (stream->stream_flags & picoquic_stream_flag_stop_sending_sent) == 0) {
        return picoquic_prepare_stop_sending_frame(stream, bytes, bytes_max, consumed);
    }

    if ((stream->send_queue == NULL || stream->send_queue->length <= stream->send_queue->offset) && ((stream->stream_flags & picoquic_stream_flag_fin_notified) == 0 || (stream->stream_flags & picoquic_stream_flag_fin_sent) != 0)) {
        *consumed = 0;
    } else {
        size_t byte_index = 0;
        size_t l_stream = 0;
        size_t l_off = 0;
        size_t length = 0;

        bytes[byte_index++] = picoquic_frame_type_stream_range_min;

        if (bytes_max > byte_index) {
            l_stream = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->stream_id);
            byte_index += l_stream;
        }

        if (stream->sent_offset > 0 && bytes_max > byte_index) {
            bytes[0] |= 4; /* Indicates presence of offset */
            l_off = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->sent_offset);
            byte_index += l_off;
        }

        if (byte_index > bytes_max || l_stream == 0 || (stream->sent_offset > 0 && l_off == 0)) {
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else {
            /* Compute the length */
            size_t space = bytes_max - byte_index;

            if (space < 2 || stream->send_queue == NULL) {
                length = 0;
            } else {
                size_t available = (size_t)(stream->send_queue->length - stream->send_queue->offset);

                length = available;

                /* Enforce maxdata per stream on all streams, including stream 0 */
                if (length >(stream->maxdata_remote - stream->sent_offset)) {
                    length = (size_t)(stream->maxdata_remote - stream->sent_offset);
                }

                /* Abide by flow control restrictions, stream 0 is exempt */
                if (stream->stream_id != 0) {
                    if (length > (cnx->maxdata_remote - cnx->data_sent)) {
                        length = (size_t)(cnx->maxdata_remote - cnx->data_sent);
                    }
                }

                if (length >= space) {
                    length = space;
                } else {
                    /* This is going to be a trial and error process */
                    size_t l_len = 0;

                    /* Try a simple encoding */
                    bytes[0] |= 2; /* Indicates presence of length */
                    l_len = picoquic_varint_encode(bytes + byte_index, space,
                        (uint64_t)length);
                    if (l_len == 0 || (l_len == space && length > 0)) {
                        /* Will not try a silly encoding */
                        *consumed = 0;
                        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                    } else if (length + l_len > space) {
                        /* try a shorter packet */
                        length = space - l_len;
                        l_len = picoquic_varint_encode(bytes + byte_index, space,
                            (uint64_t)length);
                        byte_index += l_len;
                    } else {
                        /* This is good */
                        byte_index += l_len;
                    }
                }
            }

            if (ret == 0 && length > 0) {
                memcpy(&bytes[byte_index], stream->send_queue->bytes + stream->send_queue->offset, length);
                byte_index += length;

                stream->send_queue->offset += length;
                if (stream->send_queue->offset >= stream->send_queue->length) {
                    picoquic_stream_data* next = stream->send_queue->next_stream_data;
                    free(stream->send_queue->bytes);
                    free(stream->send_queue);
                    stream->send_queue = next;
                }

                stream->sent_offset += length;
                if (stream->stream_id != 0) {
                    cnx->data_sent += length;
                }
                *consumed = byte_index;
            }

            if (ret == 0 && (stream->stream_flags & picoquic_stream_flag_fin_notified) != 0 && stream->send_queue == 0) {
                /* Set the fin bit */
                stream->stream_flags |= picoquic_stream_flag_fin_sent;
                bytes[0] |= 1;
            } else if (ret == 0 && length == 0) {
                /* No point in sending a silly packet */
                *consumed = 0;
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
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
    picoquic_stream_head* stream = &cnx->tls_stream;

    if (stream->send_queue != NULL &&
        stream->send_queue->length > stream->send_queue->offset) {
        /* Need to consider whether the epoch allows for transmission */
        for (int i = 0; i < 4; i++) {
            if (stream->sent_offset < cnx->epoch_offsets[i + 1] &&
                cnx->crypto_context[i].aead_encrypt != NULL) {
                ret = 1;
                break;
            }
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
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);

    } else if (bytes_max - bytes < data_length) {
        DBG_PRINTF("crypto hs data past the end of the packet: data_length=%" PRIst ", remaining_space=%" PRIst, data_length, bytes_max - bytes);
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
        bytes = NULL;

    } else if (picoquic_queue_network_input(cnx, &cnx->tls_stream, (size_t)offset, bytes, (size_t)data_length, &new_data_available) != 0) {
        bytes = NULL;  // Error signaled

    } else {
        bytes += data_length;
        if (epoch < 5) {
            if (cnx->epoch_received[epoch] < (size_t)(offset + data_length)) {
                cnx->epoch_received[epoch] = (size_t)(offset + data_length);
            }
        }
    }

    return bytes;
}

int picoquic_prepare_crypto_hs_frame(picoquic_cnx_t* cnx, int epoch,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    picoquic_stream_head* stream = &cnx->tls_stream;

    if ((stream->send_queue == NULL || stream->send_queue->length <= stream->send_queue->offset) && ((stream->stream_flags & picoquic_stream_flag_fin_notified) == 0 || (stream->stream_flags & picoquic_stream_flag_fin_sent) != 0)) {
        *consumed = 0;
    } else {
        size_t byte_index = 0;
        size_t l_off = 0;
        size_t length = 0;
        int next_epoch = (epoch < 4) ? epoch + 1 : epoch;
        size_t next_epoch_offset = cnx->epoch_offsets[next_epoch];

        bytes[byte_index++] = picoquic_frame_type_crypto_hs;

        if (bytes_max > byte_index) {
            l_off = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, stream->sent_offset);
            byte_index += l_off;
        }

        if (byte_index > bytes_max || (stream->sent_offset > 0 && l_off == 0)) {
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        }
        else {
            /* Compute the length */
            size_t space = bytes_max - byte_index;

            /* TODO: check logic here -- I was tired when I wrote that */

            if (space < 2 || stream->send_queue == NULL || stream->sent_offset >= next_epoch_offset) {
                length = 0;
            } else {
                /* This is going to be a trial and error process */
                size_t l_len = 0;
                size_t available = stream->send_queue->length - (size_t)stream->send_queue->offset;

                /* Adjust to limit content to epoch */
                if (stream->sent_offset + available > next_epoch_offset) {
                    available = next_epoch_offset - (size_t)stream->sent_offset;
                }

                length = available;
                /* Trial encoding */
                l_len = picoquic_varint_encode(bytes + byte_index, space,
                    (uint64_t)length);

                if (length + l_len >= space) {
                    if (space < l_len) {
                        /* Will not try a silly encoding */
                        *consumed = 0;
                        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
                    }
                    else {
                        /* New encoding with appropriate length */
                        length = space - l_len;
                        l_len = picoquic_varint_encode(bytes + byte_index, space,
                            (uint64_t)length);
                    }
                }
                /* This is good */
                byte_index += l_len;
            }

            if (ret == 0 && length > 0) {
                memcpy(&bytes[byte_index], stream->send_queue->bytes + stream->send_queue->offset, length);
                byte_index += length;

                stream->send_queue->offset += length;
                if (stream->send_queue->offset >= stream->send_queue->length) {
                    picoquic_stream_data* next = stream->send_queue->next_stream_data;
                    free(stream->send_queue->bytes);
                    free(stream->send_queue);
                    stream->send_queue = next;
                }

                stream->sent_offset += length;
                *consumed = byte_index;
            } else if (ret == 0 && length == 0) {
                /* No point in sending a silly packet */
                *consumed = 0;
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            }
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

    if (nb_ecnx3 != NULL) {
        for (int ecnx = 0; ecnx < 3; ecnx++) {
            int l_ecnx = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &nb_ecnx3[ecnx]);

            if (l_ecnx == 0) {
                byte_index = bytes_max;
            }
            else {
                byte_index += l_ecnx;
            }
        }
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


void picoquic_check_spurious_retransmission(picoquic_cnx_t* cnx,
    uint64_t start_of_range, uint64_t end_of_range, uint64_t current_time,
    picoquic_packet_context_enum pc)
{
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];
    picoquic_packet* p = pkt_ctx->retransmitted_newest;

    while (p != NULL) {
        picoquic_packet* should_delete = NULL;

        if (p->sequence_number >= start_of_range && p->sequence_number <= end_of_range) {

            uint64_t max_spurious_rtt = current_time - p->send_time;
            uint64_t max_reorder_delay = pkt_ctx->latest_time_acknowledged - p->send_time;
            uint64_t max_reorder_gap = pkt_ctx->highest_acknowledged - p->sequence_number;
            picoquic_path_t * old_path = p->send_path;

            if (p->length + p->checksum_overhead > old_path->send_mtu) {
                old_path->send_mtu = (uint32_t)(p->length + p->checksum_overhead);
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

            cnx->nb_spurious++;
            should_delete = p;
        } else if (p->send_time + PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX < pkt_ctx->latest_time_acknowledged) {
            should_delete = p;
        }

        p = p->next_packet;

        if (should_delete != NULL) {
            if (should_delete->previous_packet == NULL) {
                pkt_ctx->retransmitted_newest = should_delete->next_packet;
            } else {
                should_delete->previous_packet->next_packet = should_delete->next_packet;
            }

            if (should_delete->next_packet == NULL) {
                pkt_ctx->retransmitted_oldest = should_delete->previous_packet;
            } else {
                should_delete->next_packet->previous_packet = should_delete->previous_packet;
            }

            free(should_delete);
        }
    }
}

static picoquic_packet* picoquic_update_rtt(picoquic_cnx_t* cnx, uint64_t largest,
    uint64_t current_time, uint64_t ack_delay, picoquic_packet_context_enum pc)
{
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];
    picoquic_packet* packet = pkt_ctx->retransmit_newest;

    /* Check whether this is a new acknowledgement */
    if (largest > pkt_ctx->highest_acknowledged || pkt_ctx->first_sack_item.start_of_sack_range == (uint64_t)((int64_t)-1)) {
        pkt_ctx->highest_acknowledged = largest;

        if (ack_delay < PICOQUIC_ACK_DELAY_MAX) {
            /* if the ACK is reasonably recent, use it to update the RTT */
            /* find the stored copy of the largest acknowledged packet */

            while (packet != NULL && packet->sequence_number > largest) {
                packet = packet->next_packet;
            }

            if (packet == NULL || packet->sequence_number < largest) {
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

                    if (ack_delay > old_path->max_ack_delay) {
                        old_path->max_ack_delay = ack_delay;
                    }

                    if (old_path->smoothed_rtt == PICOQUIC_INITIAL_RTT && old_path->rtt_variant == 0) {
                        old_path->smoothed_rtt = rtt_estimate;
                        old_path->rtt_variant = rtt_estimate / 2;
                        old_path->rtt_min = rtt_estimate;
                        old_path->retransmit_timer = 3 * rtt_estimate + old_path->max_ack_delay;
                        pkt_ctx->ack_delay_local = old_path->rtt_min / 4;
                        if (pkt_ctx->ack_delay_local < 1000) {
                            pkt_ctx->ack_delay_local = 1000;
                        }
                    } else {
                        /* Computation per RFC 6298 */
                        int64_t delta_rtt = rtt_estimate - old_path->smoothed_rtt;
                        int64_t delta_rtt_average = 0;
                        old_path->smoothed_rtt += delta_rtt / 8;

                        if (delta_rtt < 0) {
                            delta_rtt_average = (-delta_rtt) - old_path->rtt_variant;
                        } else {
                            delta_rtt_average = delta_rtt - old_path->rtt_variant;
                        }
                        old_path->rtt_variant += delta_rtt_average / 4;

                        if (rtt_estimate < (int64_t)old_path->rtt_min) {
                            old_path->rtt_min = rtt_estimate;

                            pkt_ctx->ack_delay_local = old_path->rtt_min / 4;
                            if (pkt_ctx->ack_delay_local < 1000) {
                                pkt_ctx->ack_delay_local = 1000;
                            } else if (pkt_ctx->ack_delay_local > 10000) {
                                pkt_ctx->ack_delay_local = 10000;
                            }
                        }

                        if (4 * old_path->rtt_variant < old_path->rtt_min) {
                            old_path->rtt_variant = old_path->rtt_min / 4;
                        }

                        old_path->retransmit_timer = old_path->smoothed_rtt + 4 * old_path->rtt_variant + old_path->max_ack_delay;
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
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn)
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
        &num_block, (is_ecn)? ecnx3 : NULL, 
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

int picoquic_check_stream_frame_already_acked(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, int* no_need_to_repeat)
{
    int ret = 0;
    int fin;
    size_t data_length;
    uint64_t stream_id;
    uint64_t offset;
    picoquic_stream_head* stream = NULL;
    size_t consumed = 0;

    *no_need_to_repeat = 0;

    if (PICOQUIC_IN_RANGE(bytes[0], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
        ret = picoquic_parse_stream_header(bytes, bytes_max,
            &stream_id, &offset, &data_length, &fin, &consumed);

        if (ret == 0) {
            stream = picoquic_find_stream(cnx, stream_id, 0);
            if (stream == NULL) {
                /* this is weird -- the stream was destroyed. */
                *no_need_to_repeat = 1;
            } else {
                if ((stream->stream_flags & picoquic_stream_flag_reset_sent) != 0) {
                    *no_need_to_repeat = 1;
                } else {
                    /* Check whether the ack was already received */
                    *no_need_to_repeat = picoquic_check_sack_list(&stream->first_sack_item, offset, offset + data_length);
                }
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
    picoquic_stream_head* stream = NULL;

    /* skip stream frame */
    ret = picoquic_parse_stream_header(bytes, bytes_max,
        &stream_id, &offset, &data_length, &fin, consumed);

    if (ret == 0) {
        *consumed += data_length;

        /* record the ack range for the stream */
        stream = picoquic_find_stream(cnx, stream_id, 0);
        if (stream != NULL) {
            (void)picoquic_update_sack_list(&stream->first_sack_item,
                offset, offset + data_length - 1);
        }
    }

    return ret;
}

void picoquic_process_possible_ack_of_ack_frame(picoquic_cnx_t* cnx, picoquic_packet* p)
{
    int ret = 0;
    size_t byte_index;
    int frame_is_pure_ack = 0;
    size_t frame_length = 0;

    if (ret == 0 && p->ptype == picoquic_packet_0rtt_protected) {
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
            ret = picoquic_skip_frame(&p->bytes[byte_index],
                p->length - byte_index, &frame_length, &frame_is_pure_ack);
            byte_index += frame_length;
        }
    }
}

static int picoquic_process_ack_range(
    picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t highest, uint64_t range, picoquic_packet** ppacket,
    uint64_t current_time)
{
    picoquic_packet* p = *ppacket;
    int ret = 0;
    /* Compare the range to the retransmit queue */
    while (p != NULL && range > 0) {
        if (p->sequence_number > highest) {
            p = p->next_packet;
        } else {
            if (p->sequence_number == highest) {
                /* TODO: RTT Estimate */
                picoquic_packet* next = p->next_packet;
                picoquic_path_t * old_path = p->send_path;

                if (cnx->congestion_alg != NULL) {
                    cnx->congestion_alg->alg_notify(old_path,
                        picoquic_congestion_notification_acknowledgement,
                        0, p->length, 0, current_time);
                }

                /* If the packet contained an ACK frame, perform the ACK of ACK pruning logic */
                picoquic_process_possible_ack_of_ack_frame(cnx, p);

                /* If packet is larger than the current MTU, update the MTU */
                if ((p->length + p->checksum_overhead) > old_path->send_mtu) {
                    old_path->send_mtu = (uint32_t)(p->length + p->checksum_overhead);
                    old_path->mtu_probe_sent = 0;
                }

                picoquic_dequeue_retransmit_packet(cnx, p, 1);
                p = next;
                /* Any acknowledgement shows progress */
                cnx->pkt_ctx[pc].nb_retransmit = 0;
            }

            range--;
            highest--;
        }
    }

    *ppacket = p;
    return ret;
}

uint8_t* picoquic_decode_ack_frame_maybe_ecn(picoquic_cnx_t* cnx, uint8_t* bytes,
    const uint8_t* bytes_max, uint64_t current_time, int epoch, int is_ecn)
{
    uint64_t num_block;
    uint64_t largest;
    uint64_t ack_delay;
    size_t   consumed;
    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);
    uint64_t ecnx3[3];

    if (picoquic_parse_ack_header(bytes, bytes_max-bytes, &num_block, 
        (is_ecn)? ecnx3:NULL,
        &largest, &ack_delay, &consumed,
        cnx->remote_parameters.ack_delay_exponent) != 0) {
        bytes = NULL;
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
    } else {
        bytes += consumed;

        if (is_ecn) {
            cnx->ecn_ect0_total_remote = ecnx3[0];
            cnx->ecn_ect1_total_remote = ecnx3[1];
            cnx->ecn_ce_total_remote = ecnx3[2];
        }

        /* Attempt to update the RTT */
        picoquic_packet* top_packet = picoquic_update_rtt(cnx, largest, current_time, ack_delay, pc);

        while (bytes != NULL) {
            uint64_t range;
            uint64_t block_to_block;

            if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &range)) == NULL) {
                DBG_PRINTF("Malformed ACK RANGE, %d blocks remain.\n", (int)num_block);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
                bytes = NULL;
                break;
            }

            range ++;
            if (largest + 1 < range) {
                DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
                bytes = NULL;
                break;
            }

            if (picoquic_process_ack_range(cnx, pc, largest, range, &top_packet, current_time) != 0) {
                bytes = NULL;
                break;
            }

            if (range > 0) {
                picoquic_check_spurious_retransmission(cnx, largest + 1 - range, largest, current_time, pc);
            }

            if (num_block-- == 0)
                break;

            /* Skip the gap */
            if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &block_to_block)) == NULL) {
                DBG_PRINTF("    Malformed ACK GAP, %d blocks remain.\n", (int)num_block);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
                bytes = NULL;
                break;
            }

            block_to_block += 1; /* add 1, since zero is ruled out by varint, see spec. */
            block_to_block += range;

            if (largest < block_to_block) {
                DBG_PRINTF("ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
                    largest, range, block_to_block - range);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
                bytes = NULL;
                break;
            }

            largest -= block_to_block;
        }
    }

    return bytes;
}

uint8_t* picoquic_decode_ack_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    const uint8_t* bytes_max, uint64_t current_time, int epoch)
{
    return picoquic_decode_ack_frame_maybe_ecn(cnx, bytes, bytes_max, current_time, epoch, 0);
}

uint8_t* picoquic_decode_ack_ecn_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    const uint8_t* bytes_max, uint64_t current_time, int epoch)
{
    return picoquic_decode_ack_frame_maybe_ecn(cnx, bytes, bytes_max, current_time, epoch, 1);
}


int picoquic_prepare_ack_frame_maybe_ecn(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn)
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
    uint8_t ack_type_byte = (is_ecn)?picoquic_frame_type_ack_ecn: picoquic_frame_type_ack;

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
        if (byte_index < bytes_max) {
            l_largest = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                pkt_ctx->first_sack_item.end_of_sack_range);
            byte_index += l_largest;
        }
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

        if (is_ecn) {
            int l_ect0 = 0;
            int l_ect1 = 0;
            int l_ce = 0;

            l_ect0 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                cnx->ecn_ect0_total_local);
            byte_index += l_ect0;

            l_ect1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                cnx->ecn_ect1_total_local);
            byte_index += l_ect0;

            l_ce = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index,
                cnx->ecn_ce_total_local);
            byte_index += l_ce;

            if (l_ect0 == 0 || l_ect1 == 0 || l_ce == 0) {
                *consumed = 0;
                ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
            }
        }

        if (ret == 0) {
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
        }

        if (l_delay == 0 || l_largest == 0 || l_first_range == 0 || byte_index > bytes_max) {
            /* not enough space */
            *consumed = 0;
            ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        } else if (ret == 0) {
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
            pkt_ctx->highest_ack_time = current_time;

            *consumed = byte_index;
        }
    }

    if (ret == 0) {
        pkt_ctx->ack_needed = 0;
    }

    return ret;
}

int picoquic_prepare_ack_frame(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed) {
    return picoquic_prepare_ack_frame_maybe_ecn(cnx, current_time, pc, bytes, bytes_max, consumed, 0);
}

int picoquic_prepare_ack__ecn_frame(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed) {
    return picoquic_prepare_ack_frame_maybe_ecn(cnx, current_time, pc, bytes, bytes_max, consumed, 1);
}

int picoquic_is_ack_needed(picoquic_cnx_t* cnx, uint64_t current_time, picoquic_packet_context_enum pc)
{
    int ret = 0;
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];

    if (pkt_ctx->highest_ack_sent + 2 <= pkt_ctx->first_sack_item.end_of_sack_range ||
        pkt_ctx->highest_ack_time + pkt_ctx->ack_delay_local <= current_time) {
        ret = pkt_ctx->ack_needed;
    }

    return ret;
}

/*
 * Connection close frame
 */
int picoquic_prepare_generic_close_frame(
    uint8_t* bytes, size_t bytes_max, size_t* consumed, uint8_t ftype, uint16_t err)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t l1 = 0;

    if (bytes_max > 4) {
        bytes[byte_index++] = ftype;
        picoformat_16(bytes + byte_index, err);
        byte_index += 2;
        l1 = picoquic_varint_encode(bytes + byte_index, bytes_max - byte_index, 0);
        byte_index += l1;
        *consumed = byte_index;

        if (l1 == 0) {
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

static uint8_t* picoquic_decode_generic_close_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max,
                                                    picoquic_call_back_event_t event, uint16_t* error_code)
{
    if ((bytes = picoquic_frames_uint16_decode(bytes+1,  bytes_max, error_code)) == NULL ||
#ifdef DRAFT_13
        (bytes = picoquic_frames_varint_skip(  bytes,    bytes_max))             == NULL ||
#endif
        (bytes = picoquic_frames_length_data_skip(bytes, bytes_max))             == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
    } else {
        cnx->cnx_state = (cnx->cnx_state < picoquic_state_client_ready) ? picoquic_state_disconnected : picoquic_state_closing_received;
        if (cnx->callback_fn) {
            (cnx->callback_fn)(cnx, 0, NULL, 0, event, cnx->callback_ctx);
        }
    }

    return bytes;
}

int picoquic_prepare_connection_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    return picoquic_prepare_generic_close_frame(bytes, bytes_max, consumed, picoquic_frame_type_connection_close, (uint16_t)cnx->local_error);
}

uint8_t* picoquic_decode_connection_close_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    return picoquic_decode_generic_close_frame(cnx, bytes, bytes_max, picoquic_callback_close, &cnx->remote_error);
}

/*
 * Application close frame
 */

int picoquic_prepare_application_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    return picoquic_prepare_generic_close_frame(bytes, bytes_max, consumed, picoquic_frame_type_application_close, (uint16_t)cnx->application_error);
}

uint8_t* picoquic_decode_application_close_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    return picoquic_decode_generic_close_frame(cnx, bytes, bytes_max, picoquic_callback_application_close, &cnx->remote_application_error);
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

uint8_t* picoquic_decode_max_data_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t maxdata;

    if ((bytes = picoquic_frames_varint_decode(bytes+1, bytes_max, &maxdata)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
    } else if (maxdata > cnx->maxdata_remote) {
        cnx->maxdata_remote = maxdata;
    }

    return bytes;
}

/*
 * Max stream data frame
 */

int picoquic_prepare_max_stream_data_frame(picoquic_stream_head* stream,
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


uint8_t* picoquic_decode_max_stream_data_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t stream_id;
    uint64_t maxdata;
    picoquic_stream_head* stream;

    if ((bytes = picoquic_frames_varint_decode(bytes+1, bytes_max, &stream_id)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes,   bytes_max, &maxdata))   == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);

    } else if ((stream = picoquic_find_stream(cnx, stream_id, 1)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_ERROR_MEMORY);
        bytes = NULL;

    } else if (maxdata > stream->maxdata_remote) {
        /* TODO: call back if the stream was blocked? */
        stream->maxdata_remote = maxdata;
    }

    return bytes;
}

int picoquic_prepare_required_max_stream_data_frames(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    picoquic_stream_head* stream = cnx->first_stream;

    while (stream != NULL && ret == 0 && byte_index < bytes_max) {
        if ((stream->stream_flags & (picoquic_stream_flag_fin_received | picoquic_stream_flag_reset_received)) == 0 && 2 * stream->consumed_offset > stream->maxdata_local) {
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
        stream = stream->next_stream;
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
 * Max stream ID frame
 */
int picoquic_prepare_max_stream_ID_frame(picoquic_cnx_t* cnx, uint32_t increment,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t l1 = picoquic_varint_encode(bytes + 1, bytes_max - 1, cnx->max_stream_id_bidir_local + increment);

    if (l1 == 0) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else {
        bytes[0] = picoquic_frame_type_max_stream_id;
        cnx->max_stream_id_bidir_local += increment;
        *consumed = 1 + l1;
    }

    return ret;
}


uint8_t* picoquic_decode_max_stream_id_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t max_stream_id;

    if ((bytes = picoquic_frames_varint_decode(bytes+1, bytes_max, &max_stream_id)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);

    } else if (cnx->client_mode != IS_CLIENT_STREAM_ID(max_stream_id)) {    // Only accept my stream IDs
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_STREAM_ID_ERROR);
        bytes = NULL;

    } else {
        uint64_t *max_id = IS_BIDIR_STREAM_ID(max_stream_id) ? &cnx->max_stream_id_bidir_remote : &cnx->max_stream_id_unidir_remote;
        if (max_stream_id > *max_id) {
            *max_id = max_stream_id;
        }
    }

    return bytes;
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
    size_t bytes_max, size_t* consumed, picoquic_path_t * path)
{
    int ret = 0;
    if (bytes_max < (1 + 8)) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    } else {
        bytes[0] = picoquic_frame_type_path_challenge;
        picoformat_64(bytes + 1, path->challenge);
        *consumed = 1 + 8;
    }

    return ret;
}

uint8_t* picoquic_decode_path_challenge_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    if (bytes_max - bytes <= (int) challenge_length) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
        bytes = NULL;

    } else {
        /*
         * Queue a response frame as response to path challenge.
         * TODO: ensure it goes out on the same path as the incoming challenge.
         */
        uint8_t frame_buffer[258];

        frame_buffer[0] = picoquic_frame_type_path_response;
        memcpy(frame_buffer+1, bytes+1, challenge_length);

        // Ignore return code. If cannot send the response, consider it "lost"
        picoquic_queue_misc_frame(cnx, frame_buffer, challenge_length+1);

        bytes += challenge_length+1;
    }

    return bytes;
}

uint8_t* picoquic_decode_path_response_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t response;

    if ((bytes = picoquic_frames_uint64_decode(bytes+1, bytes_max, &response)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);

    } else {
        int found_challenge = 0;
        /*
         * Check that the challenge corresponds to something that was sent locally
         */
        for (int i = 0; i < cnx->nb_paths; i++) {
            if (response == cnx->path[i]->challenge) {
                /* TODO: verify that the network addresses match the path */
                found_challenge = 1;
                cnx->path[i]->challenge_verified = 1;
            }
        }

        if (found_challenge == 0 && cnx->callback_fn != NULL) {
            cnx->callback_fn(cnx, 0, bytes-(challenge_length+1), challenge_length+1,
                             picoquic_callback_challenge_response, cnx->callback_ctx);
        }
    }

    return bytes;
}


uint8_t* picoquic_decode_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
    }
    return bytes;
}


uint8_t* picoquic_decode_stream_blocked_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    /* TODO: check that the stream number is valid */
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) == NULL ||
        (bytes = picoquic_frames_varint_skip(bytes,   bytes_max)) == NULL)
    {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
    }
    return bytes;
}


uint8_t* picoquic_decode_stream_id_needed_frame(picoquic_cnx_t* cnx, uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max)) == NULL) {
        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
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


/*
 * Decoding of the received frames.
 *
 * In some cases, the expected frames are "restricted" to only ACK, STREAM 0 and PADDING.
 */

int picoquic_decode_frames(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_maxsize, int epoch, uint64_t current_time)
{
    const uint8_t *bytes_max = bytes + bytes_maxsize;
    int ack_needed = 0;
    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];

    while (bytes != NULL && bytes < bytes_max) {
        uint8_t first_byte = bytes[0];

        if (PICOQUIC_IN_RANGE(first_byte, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            if (epoch != 1 && epoch != 3) {
                DBG_PRINTF("Data frame (0x%x), when only TLS stream is expected", first_byte);
                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
                bytes = NULL;
                break;
            }

            bytes = picoquic_decode_stream_frame(cnx, bytes, bytes_max, current_time);
            ack_needed = 1;

        } else if (first_byte == picoquic_frame_type_ack) {
            bytes = picoquic_decode_ack_frame(cnx, bytes, bytes_max, current_time, epoch);
        } else if (first_byte == picoquic_frame_type_ack_ecn) {
            bytes = picoquic_decode_ack_ecn_frame(cnx, bytes, bytes_max, current_time, epoch);
        } else if (epoch != 1 && epoch != 3 && first_byte != picoquic_frame_type_padding
                                            && first_byte != picoquic_frame_type_path_challenge
                                            && first_byte != picoquic_frame_type_path_response
                                            && first_byte != picoquic_frame_type_connection_close
                                            && first_byte != picoquic_frame_type_crypto_hs) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
            bytes = NULL;
            break;

        } else {
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
            case picoquic_frame_type_max_stream_id:
                bytes = picoquic_decode_max_stream_id_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_ping:
                bytes = picoquic_skip_0len_frame(bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_blocked:
                bytes = picoquic_decode_blocked_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stream_blocked:
                bytes = picoquic_decode_stream_blocked_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stream_id_needed:
                bytes = picoquic_decode_stream_id_needed_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_new_connection_id:
                bytes = picoquic_decode_connection_id_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_stop_sending:
                bytes = picoquic_decode_stop_sending_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            case picoquic_frame_type_path_challenge:
                bytes = picoquic_decode_path_challenge_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_path_response:
                bytes = picoquic_decode_path_response_frame(cnx, bytes, bytes_max);
                break;
            case picoquic_frame_type_crypto_hs:
                bytes = picoquic_decode_crypto_hs_frame(cnx, bytes, bytes_max, epoch);
                ack_needed = 1;
                break;
            case picoquic_frame_type_new_token:
                bytes = picoquic_decode_new_token_frame(cnx, bytes, bytes_max);
                ack_needed = 1;
                break;
            default: {
                uint64_t frame_id64;
                if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_id64)) != NULL) {
                    /* Not implemented yet! */
                    picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR);
                    bytes = NULL;
                }
                break;
            }
            }
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
static uint8_t* picoquic_skip_generic_closing_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_fixed_skip(bytes+1, bytes_max, sizeof(uint16_t))) != NULL
#ifdef DRAFT_13
            &&
        (bytes = picoquic_frames_varint_skip(bytes,  bytes_max))                   != NULL
#endif
    )
    {
        bytes = picoquic_frames_length_data_skip(bytes, bytes_max);
    }
    return bytes;
}

/*
 * The ACK skipping function only supports the varint format.
 * The old "fixed int" versions are supported by code in the skip_frame function
 */
static uint8_t* picoquic_skip_ack_frame_maybe_ecn(uint8_t* bytes, const uint8_t* bytes_max, int is_ecn)
{
    uint64_t nb_blocks;

    if ((bytes = picoquic_frames_varint_skip(bytes + 1, bytes_max)) != NULL &&
        (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL)
    {
        if (is_ecn) {
            for (int i = 0; bytes != NULL && i < 3; i++) {
                bytes = picoquic_frames_varint_skip(bytes, bytes_max);
            }
        }
    }

    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &nb_blocks)) != NULL &&
        (bytes = picoquic_frames_varint_skip(bytes,   bytes_max))             != NULL)
    {
        while (nb_blocks-- != 0) {
            if ((bytes = picoquic_frames_varint_skip(bytes, bytes_max)) == NULL ||
                (bytes = picoquic_frames_varint_skip(bytes, bytes_max)) == NULL)
            {
                break;
            }
        }
    }

    return bytes;
}

static uint8_t* picoquic_skip_ack_frame(uint8_t* bytes, const uint8_t* bytes_max) {
    return picoquic_skip_ack_frame_maybe_ecn(bytes, bytes_max, 0);
}

static uint8_t* picoquic_skip_ack_ecn_frame(uint8_t* bytes, const uint8_t* bytes_max) {
    return picoquic_skip_ack_frame_maybe_ecn(bytes, bytes_max, 1);
}

/* Lots of simple frames...
 */

static uint8_t* picoquic_skip_stream_reset_frame(uint8_t* bytes, const uint8_t* bytes_max)
{
    if ((bytes = picoquic_frames_varint_skip(bytes+1, bytes_max))                   != NULL &&
        (bytes = picoquic_frames_fixed_skip(bytes,    bytes_max, sizeof(uint16_t))) != NULL)
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


int picoquic_skip_frame(uint8_t* bytes, size_t bytes_maxsize, size_t* consumed,
    int* pure_ack)
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
            bytes = picoquic_skip_generic_closing_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        }
        case picoquic_frame_type_application_close: {
            bytes = picoquic_skip_generic_closing_frame(bytes, bytes_max);
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
        case picoquic_frame_type_max_stream_id:
            bytes = picoquic_frames_varint_skip(bytes+1, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_ping:
            bytes = picoquic_skip_0len_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_blocked:
            bytes = picoquic_frames_varint_skip(bytes+1, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_stream_blocked:
            bytes = picoquic_skip_stream_blocked_frame(bytes, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_stream_id_needed:
            bytes = picoquic_frames_varint_skip(bytes+1, bytes_max);
            *pure_ack = 0;
            break;
        case picoquic_frame_type_new_connection_id:
            bytes = picoquic_skip_connection_id_frame(bytes, bytes_max);
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
