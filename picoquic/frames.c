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

picoquic_stream_head * picoquic_create_stream(picoquic_cnx_t * cnx, uint32_t stream_id)
{
	picoquic_stream_head * stream = (picoquic_stream_head *)malloc(sizeof(picoquic_stream_head));
	if (stream != NULL)
	{
        picoquic_stream_head * previous_stream = NULL;
        picoquic_stream_head * next_stream = cnx->first_stream.next_stream;

		memset(stream, 0, sizeof(picoquic_stream_head));
		stream->stream_id = stream_id;
		stream->maxdata_local = cnx->local_parameters.initial_max_stream_data;
		stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data;

        /*
         * Make sure that the streams are open in order.
         */

        while (next_stream != NULL && next_stream->stream_id < stream_id)
        {
            previous_stream = next_stream;
            next_stream = next_stream->next_stream;
        }

        stream->next_stream = next_stream;

        if (previous_stream == NULL)
        {
            cnx->first_stream.next_stream = stream;
        }
        else
        {
            previous_stream->next_stream = stream;
        }
	}

	return stream;
}

picoquic_stream_head * picoquic_find_stream(picoquic_cnx_t * cnx, uint32_t stream_id, int create)
{
	picoquic_stream_head * stream = &cnx->first_stream;

	do {
		if (stream->stream_id == stream_id)
		{
			break;
		}
		else
		{
			stream = stream->next_stream;
		}
	} while (stream);

	if (create != 0 && stream == NULL)
	{
		stream = picoquic_create_stream(cnx, stream_id);
	}

	return stream;
}

int picoquic_find_or_create_stream(picoquic_cnx_t * cnx, uint32_t stream_id,
	picoquic_stream_head ** stream, int is_remote)
{
	int ret = 0;

	/* Verify the stream ID control conditions */
	if (stream_id > cnx->max_stream_id_local)
	{
		ret = PICOQUIC_TRANSPORT_ERROR_STREAM_ID_ERROR;
	}
	else
	{
		*stream = picoquic_find_stream(cnx, stream_id, 0);

		if (*stream == NULL)
		{
			/* Check parity */
			int parity = ((cnx->quic->flags&picoquic_context_server) == 0) ?
				is_remote^1 : is_remote;
			if ((stream_id & 1) != parity)
			{
				ret = PICOQUIC_TRANSPORT_ERROR_STREAM_ID_ERROR;
			}
			else
			{
				*stream = picoquic_create_stream(cnx, stream_id);

				if (*stream == NULL)
				{
					ret = PICOQUIC_ERROR_MEMORY;
				}
			}
		}
	}

	return ret;
}

/*
 * Check of the number of newly received bytes, or newly committed bytes
 * when a new max offset is learnt for a stream.
 */

int picoquic_flow_control_check_stream_offset(picoquic_cnx_t * cnx, picoquic_stream_head * stream,
	uint64_t new_fin_offset)
{
	int ret = 0;

	if (stream->stream_id == 0)
	{
		return 0;
	}

	if (new_fin_offset > stream->maxdata_local)
	{
		/* protocol violation */
		ret = PICOQUIC_TRANSPORT_ERROR_FLOW_CONTROL_ERROR;
	}
	else if (new_fin_offset > stream->fin_offset)
	{
		/* Checking the flow control limits. Need to pay attention
		* to possible integer overflow */

		uint64_t new_bytes = new_fin_offset - stream->fin_offset;

		if (new_bytes > cnx->maxdata_local ||
			cnx->maxdata_local - new_bytes < cnx->data_received)
		{
			/* protocol violation */
			ret = PICOQUIC_TRANSPORT_ERROR_FLOW_CONTROL_ERROR;
		}
		else
		{
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
 *
 * After sending a RST_STREAM, an endpoint ceases transmission of STREAM frames on 
 * the identified stream. A receiver of RST_STREAM can discard any data that it 
 * already received on that stream. An endpoint sends a RST_STREAM in response to 
 * a RST_STREAM unless the stream is already closed.
 *
 * The RST_STREAM frame is as follows:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Stream ID (32)                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Error Code (32)                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                                                               |
 * +                       Final Offset (64)                       +
 * |                                                               |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * The fields are:
 *
 * Stream ID:
 *     The 32-bit Stream ID of the stream being terminated.
 * Error code:
 *     A 32-bit error code which indicates why the stream is being closed.
 * Final offset:
 *     A 64-bit unsigned integer indicating the absolute byte offset of the 
 *     end of data written on this stream by the RST_STREAM sender.
 */

int picoquic_prepare_stream_reset_frame(picoquic_cnx_t * cnx, picoquic_stream_head * stream,
	uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	const size_t min_length = 1 + 4 + 4 + 8;

	if (bytes_max < min_length)
	{
		ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
	}
	else if ((stream->stream_flags&picoquic_stream_flag_reset_requested) == 0 ||
		(stream->stream_flags&picoquic_stream_flag_reset_sent) != 0)
	{
		*consumed = 0;
	}
	else
	{
		bytes[0] = picoquic_frame_type_reset_stream;
		picoformat_32(bytes + 1, stream->stream_id);
		picoformat_32(bytes + 5, stream->local_error);
		picoformat_64(bytes + 9, stream->sent_offset);
		*consumed = 17;

		stream->stream_flags |= picoquic_stream_flag_reset_sent;
	}

	return ret;
}

int picoquic_decode_stream_reset_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
	size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	const size_t min_length = 1 + 4 + 4 + 8;
	uint32_t stream_id;
	uint32_t error_code;
	uint32_t final_offset;
	picoquic_stream_head * stream = NULL;

	if (bytes_max < min_length)
	{
		/* TODO: protocol error */
		ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
		*consumed = bytes_max;
	}
	else
	{
		stream_id = PICOPARSE_32(bytes + 1);
		error_code = PICOPARSE_32(bytes + 5);
		final_offset = PICOPARSE_64(bytes + 9);
		*consumed = 17;

		if (stream_id == 0)
		{
			ret = PICOQUIC_ERROR_CANNOT_RESET_STREAM_ZERO;
		}
		else
		{
			ret = picoquic_find_or_create_stream(cnx, stream_id, &stream, 1);

			if (ret == 0)
			{
				if ((stream->stream_flags&
					(picoquic_stream_flag_fin_received| picoquic_stream_flag_reset_received)) != 0 &&
                    final_offset != stream->fin_offset)
				{
					ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
				}
				else
				{
					stream->stream_flags |= picoquic_stream_flag_reset_received;
					stream->remote_error = error_code;

					ret = picoquic_flow_control_check_stream_offset(cnx, stream, final_offset);

					if (ret == 0)
					{

						if (cnx->callback_fn != NULL && 
                            (stream->stream_flags&picoquic_stream_flag_reset_received) == 0)
						{
							cnx->callback_fn(cnx, stream->stream_id, NULL, 0,
								picoquic_callback_stream_reset, cnx->callback_ctx);
							stream->stream_flags |= picoquic_stream_flag_reset_signalled;
						}

						if ((stream->stream_flags&
							(picoquic_stream_flag_fin_notified | picoquic_stream_flag_reset_requested)) == 0)
						{
							stream->local_error = PICOQUIC_TRANSPORT_ERROR_QUIC_RECEIVED_RST;
							stream->stream_flags |= picoquic_stream_flag_reset_requested;
						}
					}
				}
			}
		}
	}

	return ret;
}

/*
 * Stream frame.
 * In our implementation, stream 0 is special, and feeds directly
 * into the SSL API.
 *
 * STREAM frames implicitly create a stream and carry stream data. 
 * The type byte for a STREAM frame contains embedded flags, and is 
 * formatted as 11FSSOOD. These bits are parsed as follows:
 *
 * The first two bits must be set to 11, indicating that this is a STREAM frame.
 *
 * F is the FIN bit, which is used for stream termination.
 *
 * The SS bits encode the length of the Stream ID header field. The values 00, 01, 
 * 02, and 03 indicate lengths of 8, 16, 24, and 32 bits long respectively.
 *
 * The OO bits encode the length of the Offset header field. The values 00, 01, 02, 
 * and 03 indicate lengths of 0, 16, 32, and 64 bits long respectively.
 * 
 * The D bit indicates whether a Data Length field is present in the STREAM header. 
 * When set to 0, this field indicates that the Stream Data field extends to the end
 * of the packet. When set to 1, this field indicates that Data Length field contains
 * the length (in bytes) of the Stream Data field. The option to omit the length should 
 * only be used when the packet is a "full-sized" packet, to avoid the risk of corruption
 * via padding.
 *
 * A STREAM frame is shown below.
 * 
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Stream ID (8/16/24/32)                   ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                      Offset (0/16/32/64)                    ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |       [Data Length (16)]      |        Stream Data (*)      ...
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 */
static const int picoquic_offset_length_code[4] = { 0, 2, 4, 8 };

int picoquic_parse_stream_header(const uint8_t * bytes, size_t bytes_max,
								 uint32_t * stream_id, uint64_t * offset, size_t * data_length,
								 size_t * consumed)
{
    int     ret = 0;
    size_t  byte_index = 1;
    uint8_t first_byte = bytes[0];
    uint8_t stream_id_length = 1 + ((first_byte >> 3) & 3);
    uint8_t offset_length = picoquic_offset_length_code[(first_byte >> 1) & 3];
    uint8_t data_length_length = (first_byte & 1) * 2;

    if (bytes_max < (1u + stream_id_length + offset_length + data_length_length))
    {
        DBG_PRINTF("stream frame header too large: first_byte=0x%02x, bytes_max=%" PRIst,
                   first_byte, bytes_max);
        ret = -1;
    }
    else
    {
        switch (stream_id_length)
        {
        case 1:
            *stream_id = bytes[byte_index];
            break;
        case 2:
            *stream_id = PICOPARSE_16(&bytes[byte_index]);
            break;
        case 3:
            *stream_id = PICOPARSE_24(&bytes[byte_index]);
            break;
        case 4:
            *stream_id = PICOPARSE_32(&bytes[byte_index]);
            break;
        default:
            DBG_FATAL_PRINTF("Internal error: invalid stream_id_length=%u", stream_id_length);
            break;
        }

        byte_index += stream_id_length;

        switch (offset_length)
        {
        case 0:
            *offset = 0;
            break;
        case 2:
            *offset = PICOPARSE_16(&bytes[byte_index]);
            break;
        case 4:
            *offset = PICOPARSE_32(&bytes[byte_index]);
            break;
        case 8:
            *offset = PICOPARSE_64(&bytes[byte_index]);
            break;
        default:
            DBG_FATAL_PRINTF("Internal Error: invalid offset_length %u", offset_length);
            break;
        }

        byte_index += offset_length;

        if (data_length_length == 0)
        {
            *data_length = bytes_max - byte_index;
        }
        else
        {
            *data_length = PICOPARSE_16(&bytes[byte_index]);
            byte_index += 2;

            if (byte_index + *data_length > bytes_max)
            {
                DBG_PRINTF("stream data past the end of the packet: first_byte=0x%02x, data_length=%" PRIst ", max_bytes=%" PRIst,
                           first_byte, *data_length, bytes_max);
                ret = -1;
            }
        }
        *consumed = byte_index;
    }

    return ret;
}

void picoquic_stream_data_callback(picoquic_cnx_t * cnx, picoquic_stream_head * stream)
{
	picoquic_stream_data * data = stream->stream_data;

	while (data != NULL && data->offset <= stream->consumed_offset)
	{
		size_t start = (size_t)(stream->consumed_offset - data->offset);
		size_t data_length = data->length - start;
		picoquic_call_back_event_t fin_now = picoquic_callback_no_event;
		
		stream->consumed_offset += data_length;

		if (stream->consumed_offset >= stream->fin_offset &&
			(stream->stream_flags&
			(picoquic_stream_flag_fin_received | picoquic_stream_flag_fin_signalled)) ==
			picoquic_stream_flag_fin_received)
		{
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

	if (stream->consumed_offset >= stream->fin_offset &&
		(stream->stream_flags&
		(picoquic_stream_flag_fin_received | picoquic_stream_flag_fin_signalled)) ==
		picoquic_stream_flag_fin_received)
	{
		cnx->callback_fn(cnx, stream->stream_id, NULL, 0, picoquic_callback_stream_fin,
			cnx->callback_ctx);
		stream->stream_flags |= picoquic_stream_flag_fin_signalled;
	}
}

int picoquic_stream_network_input(picoquic_cnx_t * cnx, uint32_t stream_id,
    uint64_t offset, int fin, uint8_t * bytes, size_t length, uint64_t current_time)
{
    int ret = 0;
	uint32_t should_notify = 0;
    /* Is there such a stream, is it still open? */
	picoquic_stream_head * stream = NULL; 
	uint64_t new_fin_offset = offset + length;

	ret = picoquic_find_or_create_stream(cnx, stream_id, &stream, 1);
	
	if (ret == 0)
	{
		if ((stream->stream_flags&picoquic_stream_flag_fin_received) != 0)
		{
			if (new_fin_offset > stream->fin_offset)
			{
				ret = -1;
			}
			else if (fin != 0 && stream->fin_offset != new_fin_offset)
			{
				ret = -1;
			}
		}
		else if (fin)
		{
			if (stream_id == 0)
			{
				ret = -1;
			}
			else
			{
				stream->stream_flags |= picoquic_stream_flag_fin_received;
				should_notify = stream_id;
                cnx->latest_progress_time = current_time;
			}
		}
	}

	if (ret == 0 && new_fin_offset > stream->fin_offset)
	{
		ret = picoquic_flow_control_check_stream_offset(cnx, stream, new_fin_offset);
	}

	if (ret == 0)
    {
        picoquic_stream_data ** pprevious = &stream->stream_data;
        picoquic_stream_data * next = stream->stream_data;
        size_t start = 0;

        if (offset <= stream->consumed_offset)
        {
            if (offset + length <= stream->consumed_offset)
            {
                /* already received */
                start = length;
            }
            else
            {
                start = (size_t)(stream->consumed_offset - offset);
            }
        }
        
        /* Queue of a block in the stream */

        while (next != NULL && start < length && next->offset <= offset + start )
        {
            if (offset + length <= next->offset + next->length)
            {
                start = length;
            }
            else if (offset < next->offset + next->length)
            {
                start = (size_t)(next->offset + next->length - offset);
            }
            pprevious = &next->next_stream_data;
            next = next->next_stream_data;
        }

		if (start < length)
		{
			size_t data_length = length - start;

			if (next != NULL && next->offset < offset + length)
			{
				data_length -= (size_t)(offset + length - next->offset);
			}

			if (data_length > 0)
			{
				picoquic_stream_data * data = (picoquic_stream_data*)malloc(sizeof(picoquic_stream_data));

				if (data == NULL)
				{
					ret = -1;
				}
				else
				{
					data->length = data_length;
					data->bytes = (uint8_t *)malloc(data_length);
					if (data->bytes == NULL)
					{
						ret = -1;
						free(data);
					}
					else
					{
						data->offset = offset + start;
						memcpy(data->bytes, bytes + start, data_length);
						data->next_stream_data = next;
						*pprevious = data;
						should_notify = stream_id; /* this way, do not notify stream 0 */
                        cnx->latest_progress_time = current_time;
					}
				}
			}
		}
    }

	if (ret == 0 && should_notify != 0 && cnx->callback_fn != NULL)
	{
		/* check how much data there is to send */
		picoquic_stream_data_callback(cnx, stream);
	}
    
    return ret;
}

int picoquic_decode_stream_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
    size_t bytes_max, int restricted, size_t * consumed, uint64_t current_time)
{
    int      ret;
    uint32_t stream_id;
    size_t   data_length;
    uint64_t offset;

    ret = picoquic_parse_stream_header(bytes, bytes_max,
                                       &stream_id, &offset, &data_length, consumed);

    if (restricted && stream_id != 0)
    {
        DBG_PRINTF("non-zero stream (%u), where only stream 0 is expected", stream_id);
        ret = -1;
    }
    else
    {
        ret = picoquic_stream_network_input(cnx, stream_id, offset, bytes[0] & 32,
                                            bytes + *consumed, data_length, current_time);
        *consumed += data_length;
    }

    return ret;
}


picoquic_stream_head * picoquic_find_ready_stream(picoquic_cnx_t * cnx, int restricted)
{
	picoquic_stream_head * stream = &cnx->first_stream;

	if (restricted == 0 && cnx->maxdata_remote > cnx->data_sent)
	{
		do {
			if ((stream->send_queue != NULL &&
				stream->send_queue->length > stream->send_queue->offset &&
				(stream->stream_id == 0 ||
				stream->sent_offset < stream->maxdata_remote)) ||
				((stream->stream_flags&picoquic_stream_flag_fin_notified) != 0 &&
				(stream->stream_flags&picoquic_stream_flag_fin_sent) == 0) ||
				((stream->stream_flags&picoquic_stream_flag_reset_requested) != 0 &&
				(stream->stream_flags&picoquic_stream_flag_reset_sent) == 0))
			{
				/* if the stream is not active yet, verify that it fits under
				 * the max stream id limit */

				if (stream->stream_id == 0)
				{
					break;
				}
				else
				{
					/* Check parity */
					int parity = ((cnx->quic->flags&picoquic_context_server) == 0) ? 0 : 1;

					if (((stream->stream_id & 1) ^ parity) == 1)
					{
						if (stream->stream_id < cnx->max_stream_id_remote)
						{
							break;
						}
					}
					else
					{
						break;
					}
				}
			}

			stream = stream->next_stream;

		} while (stream);
	}
	else
	{
		if ((stream->send_queue == NULL ||
			stream->send_queue->length <= stream->send_queue->offset) &&
			((stream->stream_flags&picoquic_stream_flag_fin_notified) == 0 ||
			(stream->stream_flags&picoquic_stream_flag_fin_sent) != 0) &&
				((stream->stream_flags&picoquic_stream_flag_reset_requested) == 0 ||
			(stream->stream_flags&picoquic_stream_flag_reset_sent) != 0))
		{
			stream = NULL;
		}
	}

	return stream;
}

int picoquic_prepare_stream_frame(picoquic_cnx_t * cnx, picoquic_stream_head * stream,
    uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
    int ret = 0;
    size_t byte_index = 1;
    uint8_t ss_bits = 0;
    uint8_t oo_bits = 0;
    size_t length;

	if ((stream->stream_flags&picoquic_stream_flag_reset_requested) != 0)
	{
		return picoquic_prepare_stream_reset_frame(cnx, stream, bytes, bytes_max, consumed);
	}

    if ((stream->send_queue == NULL ||
        stream->send_queue->length <= stream->send_queue->offset) &&
		((stream->stream_flags&picoquic_stream_flag_fin_notified) == 0 ||
		(stream->stream_flags&picoquic_stream_flag_fin_sent) != 0))
    {
        *consumed = 0;
    }
    else
    {
        /*
         * Encode the stream ID length
         */
        if (stream->stream_id < 256)
        {
            bytes[byte_index++] = (uint8_t)stream->stream_id;
            ss_bits = 0;
        }
        else if (stream->stream_id < 0x10000)
        {
            picoformat_16(&bytes[byte_index], (uint16_t)stream->stream_id);
            byte_index += 2;
            ss_bits = 1;
        }
        else
        {
            picoformat_32(&bytes[byte_index], (uint32_t)stream->stream_id);
            byte_index += 4;
            ss_bits = 3;
        }
        /*
         * Encode the offset
         */
        if (stream->sent_offset > 0)
        {
            if (stream->sent_offset < 0x10000)
            {
                picoformat_16(&bytes[byte_index], (uint16_t)stream->sent_offset);
                byte_index += 2;
                oo_bits = 1;
            }
            else if (stream->sent_offset < 0x100000000ull)
            {
                picoformat_32(&bytes[byte_index], (uint32_t)stream->sent_offset);
                byte_index += 4;
                oo_bits = 2;
            }
            else
            {
                picoformat_64(&bytes[byte_index], stream->sent_offset);
                byte_index += 8;
                oo_bits = 3;
            }
        }
        /*
         * Compute the available length
         */
        length = bytes_max - byte_index - 2;

        if (stream->send_queue == NULL)
        {
            length = 0;
        }
        else
        {
            size_t available = (size_t)(stream->send_queue->length - stream->send_queue->offset);

            if (available < length)
            {
                length = available;
            }

			/* Abide by flow control and packet size  restrictions */
			if (stream->stream_id != 0)
			{
				if (length > (cnx->maxdata_remote - cnx->data_sent))
				{
					length = (size_t)(cnx->maxdata_remote - cnx->data_sent);
				}

				if (length > (stream->maxdata_remote - stream->sent_offset))
				{
					length = (size_t)(stream->maxdata_remote - stream->sent_offset);
				}
			}
        }

        /* Encode the length */
        picoformat_16(&bytes[byte_index], (uint16_t)length);
        byte_index += 2;

        if (length > 0)
        {
            memcpy(&bytes[byte_index], stream->send_queue->bytes + stream->send_queue->offset, length);
            byte_index += length;

            stream->send_queue->offset += length;
            if (stream->send_queue->offset >= stream->send_queue->length)
            {
                picoquic_stream_data * next = stream->send_queue->next_stream_data;
                free(stream->send_queue->bytes);
                free(stream->send_queue);
                stream->send_queue = next;
            }

            stream->sent_offset += length;
			cnx->data_sent += length;
        }

        bytes[0] = 0xC1 | (ss_bits << 3) | (oo_bits << 1);
		if ((stream->stream_flags&picoquic_stream_flag_fin_notified) != 0 &&
			stream->send_queue == 0)
		{
			/* Set the fin bit */
			stream->stream_flags |= picoquic_stream_flag_fin_sent;
			bytes[0] |= 0x20;
		}
        *consumed = byte_index;
    }

    return ret;
}

/*
The type byte for a ACK frame contains embedded flags, and is formatted as 101NLLMM. These bits are parsed as follows:

The first three bits must be set to 101 indicating that this is an ACK frame.
The N bit indicates whether the frame contains a Num Blocks field.
The two LL bits encode the length of the Largest Acknowledged field. The values 00, 01, 02, and 03 indicate lengths of 8, 16, 32, and 64 bits respectively.
The two MM bits encode the length of the ACK Block Length fields. The values 00, 01, 02, and 03 indicate lengths of 8, 16, 32, and 64 bits respectively.

An ACK frame is shown below.

0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|[Num Blocks(8)]|   NumTS (8)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Largest Acknowledged (8/16/32/64)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        ACK Delay (16)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     ACK Block Section (*)                   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Timestamp Section (*)                   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

int picoquic_parse_ack_header(uint8_t const * bytes, size_t bytes_max, 
    uint64_t target_sequence, unsigned * num_block, unsigned * num_ts, 
    uint64_t * largest, uint64_t * ack_delay, unsigned * mm, size_t * consumed,
    uint32_t version_flags)
{
	int ret = 0;
	size_t byte_index = 1;
	uint8_t first_byte = bytes[0];
	int has_num_block = (first_byte >> 4) & 1;
	unsigned ll = (first_byte >> 2) & 3;
	*mm = (first_byte & 3);
	size_t min_len = has_num_block + 1 + (1 << ll) + 2 + (1 << *mm);

    if ((version_flags&picoquic_version_basic_time_stamp) != 0)
    {
        min_len++;
    }

	if (first_byte < 0xA0 || first_byte > 0xBF)
	{
		DBG_PRINTF("Invalid first byte: 0x%02x", first_byte);
		ret = -1;
	}
	else if (min_len > bytes_max)
	{
        DBG_PRINTF("ack frame fixed header too large: first_byte=0x%02x, bytes_max=%" PRIst,
                   first_byte, bytes_max);
		ret = -1;
	}
	else
	{
		if (has_num_block)
		{
			*num_block = bytes[byte_index++];
		}
		else
		{
			*num_block = 0;
		}

        if ((version_flags&picoquic_version_basic_time_stamp) != 0)
        {
            *num_ts = bytes[byte_index++];
        }
        else
        {
            *num_ts = 0;
        }

		/* decoding the largest */
		switch (ll)
		{
		case 0:
			*largest = bytes[byte_index++];
			*largest = picoquic_get_packet_number64(target_sequence,
				0xFFFFFFFFFFFFFF00ull, (uint32_t) *largest);
			break;
		case 1:
			*largest = PICOPARSE_16(bytes + byte_index);
			*largest = picoquic_get_packet_number64(target_sequence,
				0xFFFFFFFFFFFF0000ull, (uint32_t) *largest);
			byte_index += 2;
			break;
		case 2:
			*largest = PICOPARSE_32(bytes + byte_index);
			*largest = picoquic_get_packet_number64(target_sequence,
				0xFFFFFFFF00000000ull, (uint32_t) *largest);
			byte_index += 4;
			break;
		case 3:
			*largest = PICOPARSE_64(bytes + byte_index);
			byte_index += 8;
			break;
		default:
			DBG_FATAL_PRINTF("Internal error: out of range ll=%u", ll);
			break;
		}

		/* ACK delay */
		*ack_delay = picoquic_float16_to_deltat(PICOPARSE_16(bytes + byte_index));
		byte_index += 2;

		if (byte_index + (*num_block)*(1+(1<<*mm)) + (*num_ts)*3 + 2 > bytes_max)
		{
			DBG_PRINTF("ack frame header too large: fixed=%" PRIst ", ack_blk=%u, ts=%u, bytes_max=%" PRIst,
					   byte_index, (*num_block)*(1+(1<<*mm)), (*num_ts)*3 + 2, bytes_max);
			ret = -1;
		}
	}

	*consumed = byte_index;
	return ret;
}

static picoquic_packet * picoquic_update_rtt(picoquic_cnx_t * cnx, uint64_t largest,
	uint64_t current_time, uint64_t ack_delay)
{
	picoquic_packet * packet = cnx->retransmit_newest;

	/* Check whether this is a new acknowledgement */
	if (largest > cnx->highest_acknowledged )
	{
		cnx->highest_acknowledged = largest;

		if (ack_delay < PICOQUIC_ACK_DELAY_MAX)
		{
			/* if the ACK is reasonably recent, use it to update the RTT */
			/* find the stored copy of the largest acknowledged packet */

			while (packet != NULL && packet->sequence_number > largest)
			{
				packet = packet->next_packet;
			}

			if (packet == NULL || packet->sequence_number < largest)
			{
				/* There is no copy of this packet in store.
				 * This can only come from some kind of fake acknowledgement,
				 * hitting a deliberate hole */

				/* TODO: treat as protocol error */
			}
			else
			{
				uint64_t acknowledged_time = current_time - ack_delay;
				int64_t rtt_estimate = acknowledged_time - packet->send_time;

				cnx->latest_time_acknowledged = packet->send_time;
                cnx->latest_progress_time = current_time;

				if (rtt_estimate > 0)
				{
					if (cnx->smoothed_rtt == PICOQUIC_INITIAL_RTT &&
						cnx->rtt_variant == 0)
					{
						cnx->smoothed_rtt = rtt_estimate;
						cnx->rtt_variant = rtt_estimate / 2;
						cnx->rtt_min = rtt_estimate;
						cnx->retransmit_timer = 3 * rtt_estimate;
					}
					else
					{
						/* Computation per RFC 6298 */
						int64_t delta_rtt = rtt_estimate - cnx->smoothed_rtt;
						int64_t delta_rtt_average = 0;
						cnx->smoothed_rtt += delta_rtt / 8;
						if (delta_rtt < 0)
						{
							delta_rtt_average = (-delta_rtt) - cnx->rtt_variant;
						}
						else
						{
							delta_rtt_average = delta_rtt - cnx->rtt_variant;
						}
						cnx->rtt_variant += delta_rtt_average / 4;

						cnx->retransmit_timer = cnx->smoothed_rtt + 4 * cnx->rtt_variant;

						if (rtt_estimate < (int64_t) cnx->rtt_min)
						{
							cnx->rtt_min = rtt_estimate;
						}
					}

					if (PICOQUIC_MIN_RETRANSMIT_TIMER > cnx->retransmit_timer)
					{
						cnx->retransmit_timer = PICOQUIC_MIN_RETRANSMIT_TIMER;
					}

					if (cnx->congestion_alg != NULL)
					{
						cnx->congestion_alg->alg_notify(cnx,
							picoquic_congestion_notification_rtt_measurement,
							rtt_estimate, 0, 0, current_time);
					}
				}
			}
		}
	}

	return packet;
}

static void picoquic_process_ack_of_ack_range(picoquic_sack_item_t * first_sack, 
    uint64_t start_of_range, uint64_t end_of_range)
{
    if (first_sack->start_of_sack_range == start_of_range)
    {
        if (end_of_range < first_sack->end_of_sack_range)
        {
            first_sack->start_of_sack_range = end_of_range + 1;
        }
        else
        {
            first_sack->start_of_sack_range = first_sack->end_of_sack_range;
        }
    }
    else
    {
        picoquic_sack_item_t * previous = first_sack;
        picoquic_sack_item_t * next = previous->next_sack;

        while (next != NULL)
        {
            if (next->end_of_sack_range == end_of_range &&
                next->start_of_sack_range == start_of_range)
            {
                /* Matching range should be removed */
                previous->next_sack = next->next_sack;
                free(next);
                break;
            }
            else if (next->end_of_sack_range > end_of_range)
            {
                previous = next;
                next = next->next_sack;
            }
            else
            {
                break;
            }
        }
    }
}

int picoquic_process_ack_of_ack_frame(
    picoquic_sack_item_t * first_sack,
    uint8_t * bytes, size_t bytes_max, size_t * consumed, uint32_t version_flags)
{
	int ret;
	uint64_t largest;
	uint64_t ack_delay;
	unsigned mm;
	unsigned num_block;
	unsigned num_ts;

	/* Find the oldest ACK range, in order to calibrate the
	 * extension of the largest number to 64 bits */

	picoquic_sack_item_t * target_sack = first_sack;
	while (target_sack->next_sack != NULL)
	{
		target_sack = target_sack->next_sack;
	}
	uint64_t target_sequence = target_sack->start_of_sack_range;

	ret = picoquic_parse_ack_header(bytes, bytes_max, target_sequence,
        &num_block, &num_ts, &largest, &ack_delay, &mm, consumed, version_flags);

	if (ret == 0)
	{
        size_t byte_index = *consumed;
        uint64_t extra_ack = 1;

        /* Process each successive range */

        while (1)
        {
            uint64_t range;

            switch (mm)
            {
            case 0:
                range = bytes[byte_index++];
                break;
            case 1:
                range = PICOPARSE_16(bytes + byte_index);
                byte_index += 2;
                break;
            case 2:
                range = PICOPARSE_32(bytes + byte_index);
                byte_index += 4;
                break;
            case 3:
                range = PICOPARSE_64(bytes + byte_index);
                byte_index += 8;
                break;
            default:
                DBG_FATAL_PRINTF("Internal error: out of range mm=%u", mm);
                break;
            }

            range += extra_ack;
            if (largest + 1 < range)
            {
                DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
                ret = -1;
                break;
            }

            if (range > 0)
            {
                picoquic_process_ack_of_ack_range(first_sack, largest + 1 - range, largest);
            }

            if (num_block-- == 0)
                break;

            /* Skip the gap */
            uint64_t block_to_block = range + bytes[byte_index++];
            if (largest < block_to_block)
            {
                DBG_PRINTF("ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
                    largest, range, block_to_block - range);
                ret = -1;
                break;
            }

            largest -= block_to_block;
            extra_ack = 0;
        }

        if (num_ts > 0)
        {
            byte_index += 2 + num_ts * 3;
        }
        *consumed = byte_index;
    }

	return ret;
}

static int picoquic_process_ack_of_stream_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
    size_t bytes_max, size_t * consumed)
{
    int      ret;
    size_t   data_length;
    uint32_t stream_id;
    uint64_t offset;
    picoquic_stream_head * stream = NULL;

    /* skip stream frame */
    ret = picoquic_parse_stream_header(bytes, bytes_max,
                                       &stream_id, &offset, &data_length, consumed);

    if (ret == 0)
    {
        *consumed += data_length;

        /* record the ack range for the stream */
        stream = picoquic_find_stream(cnx, stream_id, 0);
        if (stream != NULL)
        {
            uint64_t blocksize;
            (void)picoquic_update_sack_list(&stream->first_sack_item,
                    offset, offset + data_length - 1, &blocksize);
        }
    }

    return ret;
}

void picoquic_process_possible_ack_of_ack_frame(picoquic_cnx_t * cnx, picoquic_packet * p)
{
	int ret = 0;
	size_t byte_index;
	picoquic_packet_header ph;
	int frame_is_pure_ack = 0;
	size_t frame_length = 0;

	/* Get the packet type */
	ret = picoquic_parse_packet_header(p->bytes, p->length, &ph);
	byte_index = ph.offset;

	while (ret == 0 && byte_index < p->length)
	{
		if (p->bytes[byte_index] >= picoquic_frame_type_ack_range_min &&
			p->bytes[byte_index] <= picoquic_frame_type_ack_range_max)
		{
			ret = picoquic_process_ack_of_ack_frame(&cnx->first_sack_item, &p->bytes[byte_index], 
                p->length - byte_index, &frame_length,
                picoquic_supported_versions[cnx->version_index].version_flags);
            byte_index += frame_length;
		}
        else if (p->bytes[byte_index] >= picoquic_frame_type_stream_range_min &&
            p->bytes[byte_index] <= picoquic_frame_type_stream_range_max)
        {
            ret = picoquic_process_ack_of_stream_frame(cnx, &p->bytes[byte_index], p->length - byte_index, &frame_length);
            byte_index += frame_length;
        }
        else
		{
			ret = picoquic_skip_frame(&p->bytes[byte_index],
				p->length - ph.offset, &frame_length, &frame_is_pure_ack,
                picoquic_supported_versions[cnx->version_index].version_flags);
			byte_index += frame_length;
		}
	}
}

static picoquic_packet * picoquic_process_ack_range(
	picoquic_cnx_t * cnx, uint64_t highest, uint64_t range, picoquic_packet * p,
	uint64_t current_time)
{
	/* Compare the range to the retransmit queue */
	while (p != NULL && range > 0)
	{
		if (p->sequence_number > highest)
		{
			p = p->next_packet;
		}
		else
		{
			/* If the packet contained an ACK frame, perform the ACK of ACK pruning logic */
			picoquic_process_possible_ack_of_ack_frame(cnx, p);

			if (p->sequence_number == highest)
			{
				/* TODO: RTT Estimate */
				picoquic_packet * next = p->next_packet;
				if (cnx->congestion_alg != NULL)
				{
					cnx->congestion_alg->alg_notify(cnx,
						picoquic_congestion_notification_acknowledgement,
						0, p->length, 0, current_time);
				}
				picoquic_dequeue_retransmit_packet(cnx, p, 1);
				p = next;
				/* Any acknowledgement shows progress */
				cnx->nb_retransmit = 0;
			}

			range--;
			highest--;
		}
	}

	return p;
}

int picoquic_decode_ack_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
    size_t bytes_max, int restricted, size_t * consumed, uint64_t current_time)
{
	int ret;
	unsigned num_block;
	unsigned num_ts;
	unsigned mm;
	uint64_t largest;
	uint64_t ack_delay;

	ret = picoquic_parse_ack_header(bytes, bytes_max, cnx->send_sequence,
        &num_block, &num_ts, &largest, &ack_delay, &mm, consumed,
        picoquic_supported_versions[cnx->version_index].version_flags);

	if (ret == 0)
	{
		size_t byte_index = *consumed;

		/* Attempt to update the RTT */
		picoquic_packet * top_packet = picoquic_update_rtt(cnx, largest, current_time, ack_delay);
		unsigned extra_ack = 1;

		while(1)
		{
			uint64_t range;

			switch (mm)
			{
			case 0:
				range = bytes[byte_index++];
				break;
			case 1:
				range = PICOPARSE_16(bytes + byte_index);
				byte_index += 2;
				break;
			case 2:
				range = PICOPARSE_32(bytes + byte_index);
				byte_index += 4;
				break;
			case 3:
				range = PICOPARSE_64(bytes + byte_index);
				byte_index += 8;
				break;
			default:
				DBG_FATAL_PRINTF("Internal error: out of range mm=%u", mm);
				break;
			}

			range += extra_ack;
			if (largest + 1 < range)
			{
				DBG_PRINTF("ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
				ret = -1;
				break;
			}

			top_packet = picoquic_process_ack_range(cnx, largest, range, top_packet, current_time);

			if (num_block-- == 0)
				break;

			/* Skip the gap */
			uint64_t block_to_block = range + bytes[byte_index++];
			if (largest < block_to_block)
			{
				DBG_PRINTF("ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
						   largest, range, block_to_block-range);
				ret = -1;
				break;
			}

			largest -= block_to_block;
			extra_ack = 0;
		}

		if (num_ts > 0)
		{
			byte_index += 2 + num_ts * 3;
		}
		*consumed = byte_index;
	}

	return ret;
}

int picoquic_prepare_ack_frame(picoquic_cnx_t * cnx, uint64_t current_time,
	uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	size_t byte_index = 0;
	int num_block = 0;
	picoquic_sack_item_t * next_sack = cnx->first_sack_item.next_sack;
	uint64_t ack_delay = 0;
	uint64_t ack_range = 0;
	uint64_t lowest_acknowledged = 0;

	/* Check that there is enough room in the packet, and something to acknowledge */
	if (cnx->first_sack_item.start_of_sack_range == 0 &&
		cnx->first_sack_item.end_of_sack_range == 0)
	{
		*consumed = 0;
	}
	else if (bytes_max < 13)
	{
		/* A valid ACK, with our encoding, uses at least 13 bytes.
		 * If there is not enough space, don't attempt to encode it.
		 */
		*consumed = 0;
	}
	else
	{
		/* Encode the first byte as 101NLLMM, with N=1, LL=2, MM=2 */
		bytes[byte_index++] = 0xBA;
		/* Encode the number of blocks, always present. Will be overwritten later */
		bytes[byte_index++] = 0;

        if ((picoquic_supported_versions[cnx->version_index].version_flags&
            picoquic_version_basic_time_stamp) != 0)
        {
            /* Encode a number of time stamps -- set to zero for now */
            bytes[byte_index++] = 0;
        }

		/* Encode the largest seen on 4 bytes */
		picoformat_32(bytes + byte_index, (uint32_t)cnx->first_sack_item.end_of_sack_range);
		byte_index += 4;
		/* Encode the ACK delay for the largest seen */
		if (current_time > cnx->time_stamp_largest_received)
		{
			ack_delay = current_time - cnx->time_stamp_largest_received;
		}
		picoformat_16(bytes + byte_index, picoquic_deltat_to_float16(ack_delay));
		byte_index += 2;
		/* Encode the size of the first ack range */
		ack_range = cnx->first_sack_item.end_of_sack_range - cnx->first_sack_item.start_of_sack_range;
		picoformat_32(bytes + byte_index, (uint32_t)ack_range);
		byte_index += 4;
		/* Set the lowest acknowledged */
		lowest_acknowledged = cnx->first_sack_item.start_of_sack_range;
		/* Encode each of the ack block items */
		while (next_sack != NULL && num_block < 255 && (byte_index + 5) <= bytes_max)
		{
			uint64_t gap = lowest_acknowledged - next_sack->end_of_sack_range -1;
			while (gap > 255 && num_block < 255 && (byte_index + 5) <= bytes_max)
			{
				bytes[byte_index++] = 255;
				picoformat_32(bytes + byte_index, (uint32_t)ack_range);
				byte_index += 4;
				gap -= 255;
				num_block++;
			}

			if (num_block < 255 && (byte_index + 5) <= bytes_max)
			{
				ack_range = next_sack->end_of_sack_range - next_sack->start_of_sack_range;
				bytes[byte_index++] = (uint8_t)gap;
				picoformat_32(bytes + byte_index, (uint32_t)ack_range + 1);
				byte_index += 4;
				lowest_acknowledged = next_sack->start_of_sack_range;
				next_sack = next_sack->next_sack;
				num_block++;
			}
		}
		bytes[1] = num_block;

		/* Do not encode additional time stamps yet */
		*consumed = byte_index;

		/* Remember the ACK value and time */
		cnx->highest_ack_sent = cnx->first_sack_item.end_of_sack_range;
		cnx->highest_ack_time = current_time;
	}

	if (ret == 0)
	{
		cnx->ack_needed = 0;
	}

	return ret;
}

int picoquic_is_ack_needed(picoquic_cnx_t * cnx, uint64_t current_time)
{
	int ret = 0;

	if (cnx->highest_ack_sent + 2 <= cnx->first_sack_item.end_of_sack_range ||
		(cnx->first_sack_item.next_sack != NULL &&
			cnx->highest_ack_time + 10000 <= current_time))
	{
		ret = cnx->ack_needed;
	}

	return ret;
}

/*
 * Connection close frame
 */


int picoquic_prepare_connection_close_frame(picoquic_cnx_t * cnx,
	uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
	int ret = 0;

	if (bytes_max < 7)
	{
		*consumed = 0;
		ret = -1;
	}
	else
	{
		bytes[0] = picoquic_frame_type_connection_close;
		picoformat_32(bytes + 1, cnx->local_error);
		picoformat_16(bytes + 5, 0);
		*consumed = 7;
	}

	return ret;
}

int picoquic_decode_connection_close_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
	size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	const size_t min_length = 1 + 4 + 2;
	uint32_t error_code;
	uint16_t string_length;

	if (bytes_max < min_length)
	{
		/* TODO: protocol error */
		ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
		*consumed = bytes_max;
	}
	else
	{
		error_code = PICOPARSE_32(bytes + 1);
		string_length = PICOPARSE_16(bytes + 5);

		if (string_length + 7u > bytes_max)
		{
			ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
			*consumed = bytes_max;
		}
		else
		{
			cnx->cnx_state = picoquic_state_disconnected;
			cnx->remote_error = error_code;
			*consumed = string_length + 7;
            if (cnx->callback_fn)
            {
                (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
            }
		}
	}

	return ret;
}

/*
 * Max data frame
 *
 * The MAX_DATA frame (type=0x04) is used in flow control to inform the peer of the maximum 
 * amount of data that can be sent on the connection as a whole.
 *
 * The frame is as follows:
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |                                                               |
 *  +                        Maximum Data (64)                      +
 *  |                                                               |
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *  The fields in the MAX_DATA frame are as follows:
 *
 * Maximum Data:
 *  A 64-bit unsigned integer indicating the maximum amount of data that can be sent on 
 *  the entire connection, in units of 1024 octets. That is, the updated connection-level 
 *  data limit is determined by multiplying the encoded value by 1024.
 */

#define PICOQUIC_MAX_MAXDATA ((uint64_t)((int64_t)-1))
#define PICOQUIC_MAX_MAXDATA_1K (PICOQUIC_MAX_MAXDATA >> 10)
#define PICOQUIC_MAX_MAXDATA_1K_MASK (PICOQUIC_MAX_MAXDATA << 10)

int picoquic_prepare_max_data_frame(picoquic_cnx_t * cnx, uint64_t maxdata_increase,
	uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	const size_t min_length = 1 + 8;

	if (bytes_max < min_length)
	{
		ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
	}
	else
	{
		bytes[0] = picoquic_frame_type_max_data;
		cnx->maxdata_local = (cnx->maxdata_local + maxdata_increase)&PICOQUIC_MAX_MAXDATA_1K_MASK;
		picoformat_64(bytes + 1, cnx->maxdata_local >> 10);
		*consumed = 9;
	}

	return ret;
}

int picoquic_decode_max_data_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
	size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	const size_t min_length = 1 + 8;
	uint64_t maxdata_1k;

	if (bytes_max < min_length)
	{
		/* TODO: protocol error */
		ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
		*consumed = bytes_max;
	}
	else
	{
		maxdata_1k = PICOPARSE_64(bytes + 1);
		*consumed = 9;

		/* TODO: call back if the connection was blocked? */
		uint64_t maxdata = (maxdata_1k > PICOQUIC_MAX_MAXDATA_1K) ?
			PICOQUIC_MAX_MAXDATA : maxdata_1k << 10;
		if (maxdata > cnx->maxdata_remote)
		{
			cnx->maxdata_remote = maxdata;
		}
	}

	return ret;
}

/*
 * Max stream data frame
 */

int picoquic_prepare_max_stream_data_frame(picoquic_cnx_t * cnx, picoquic_stream_head * stream,
	uint8_t * bytes, size_t bytes_max, uint64_t new_max_data, size_t * consumed)
{
	int ret = 0;
	const size_t min_length = 1 + 4 + 8;

	if (bytes_max < min_length)
	{
		ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
	}
	else if ((stream->stream_flags&(picoquic_stream_flag_fin_received |
		picoquic_stream_flag_reset_received)) != 0)
	{
		*consumed = 0;
	}
	else
	{
		stream->maxdata_local = new_max_data;

		bytes[0] = picoquic_frame_type_max_stream_data;
		picoformat_32(bytes + 1, stream->stream_id);
		picoformat_64(bytes + 5, stream->maxdata_local);
		*consumed = 13;
	}

	return ret;
}

int picoquic_decode_max_stream_data_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
	size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	const size_t min_length = 1 + 4 + 8;
	uint32_t stream_id;
	uint64_t maxdata;
	picoquic_stream_head * stream = NULL;

	if (bytes_max < min_length)
	{
		/* TODO: protocol error */
		ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
		*consumed = bytes_max;
	}
	else
	{
		stream_id = PICOPARSE_32(bytes + 1);
		maxdata = PICOPARSE_64(bytes + 5);
		*consumed = 13;

		if (stream_id == 0)
		{
			ret = PICOQUIC_ERROR_CANNOT_CONTROL_STREAM_ZERO;
		}
		else
		{
			stream = picoquic_find_stream(cnx, stream_id, 1);

			if (stream == NULL)
			{
				ret = PICOQUIC_ERROR_MEMORY;
			}
			else
			{
				/* TODO: call back if the stream was blocked? */
				if (maxdata > stream->maxdata_remote)
				{
					stream->maxdata_remote = maxdata;
				}
			}
		}
	}

	return ret;
}

int picoquic_prepare_required_max_stream_data_frames(picoquic_cnx_t * cnx,
	uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	size_t byte_index = 0;
	picoquic_stream_head * stream = &cnx->first_stream;

	while (stream != NULL && ret == 0 && byte_index < bytes_max)
	{
		if (stream->stream_id != 0 &&
			(stream->stream_flags&(picoquic_stream_flag_fin_received |
				picoquic_stream_flag_reset_received)) == 0 &&
			2 * stream->consumed_offset > stream->maxdata_local)
		{
			size_t bytes_in_frame = 0;

			ret = picoquic_prepare_max_stream_data_frame(cnx, stream,
				bytes + byte_index, bytes_max - byte_index,
				stream->maxdata_local + 2 * stream->consumed_offset,
				&bytes_in_frame);
			if (ret == 0)
			{
				byte_index += bytes_in_frame;
			}
		}
		stream = stream->next_stream;
	}

	if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL)
	{
		ret = 0;
	}

	if (ret == 0)
	{
		*consumed = byte_index;
	}
	else
	{
		*consumed = 0;
	}

	return ret;
}
/*
 * Max stream ID frame
 */

int picoquic_prepare_max_stream_ID_frame(picoquic_cnx_t * cnx, uint32_t increment,
	uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	const size_t min_length = 1 + 4;

	if (bytes_max < min_length)
	{
		ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
	}
	else
	{
		bytes[0] = picoquic_frame_type_max_stream_id;
		cnx->max_stream_id_local += increment;
		picoformat_32(bytes + 1, cnx->max_stream_id_local);
		*consumed = 5;
	}

	return ret;
}

int picoquic_decode_max_stream_id_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
	size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	const size_t min_length = 1 + 4;
	uint32_t max_stream_id;

	if (bytes_max < min_length)
	{
		/* TODO: protocol error */
		ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
		*consumed = bytes_max;
	}
	else
	{
		max_stream_id = PICOPARSE_32(bytes + 1);
		*consumed = 5;

		if (max_stream_id > cnx->max_stream_id_remote)
		{
			cnx->max_stream_id_remote = max_stream_id;
		}
	}

	return ret;
}

/*
 * Decoding of the received frames.
 *
 * In some cases, the expected frames are "restricted" to only ACK, STREAM 0 and PADDING.
 */

int picoquic_decode_frames(picoquic_cnx_t * cnx, uint8_t * bytes,
    size_t bytes_max, int restricted, uint64_t current_time)
{
    int ret = 0;
    size_t byte_index = 0;

    while (byte_index < bytes_max && ret == 0)
    {
        uint8_t first_byte = bytes[byte_index];
		size_t consumed = 0;

        if (first_byte >= picoquic_frame_type_ack_range_min)
        {
            if (first_byte >= picoquic_frame_type_stream_range_min)
            {
                /* decode stream frame */

                ret = picoquic_decode_stream_frame(cnx, bytes + byte_index, bytes_max - byte_index, 
                    restricted, &consumed, current_time);
				cnx->ack_needed = 1;

                byte_index += consumed;
            }
            else
            {
                /* ACK processing */
                size_t consumed = 0;

                ret = picoquic_decode_ack_frame(cnx, bytes + byte_index, bytes_max - byte_index, 
					restricted, &consumed, current_time);

                byte_index += consumed;
            }
        }
        else if (restricted)
        {
           /* forbidden! */
            if (first_byte == picoquic_frame_type_padding)
            {
                /* Padding */
                do {
                    byte_index++;
                } while (byte_index < bytes_max && 
					bytes[byte_index] == picoquic_frame_type_padding);
            }
            else
            {
                ret = PICOQUIC_ERROR_INVALID_FRAME;
            }
        }
        else switch (first_byte)
        {
        case picoquic_frame_type_padding:
            do {
                byte_index++;
            } while (byte_index < bytes_max && 
				bytes[byte_index] == picoquic_frame_type_padding);
            break;
		case picoquic_frame_type_reset_stream:
			ret = picoquic_decode_stream_reset_frame(cnx, bytes + byte_index, bytes_max - byte_index, &consumed);
			byte_index += consumed;
			cnx->ack_needed = 1;
			break;
        case picoquic_frame_type_connection_close:
			ret = picoquic_decode_connection_close_frame(cnx, bytes + byte_index, bytes_max - byte_index, &consumed);
			byte_index += consumed;
            break;
        case picoquic_frame_type_goaway:
			/* This really should be an error, as go away is not supported anymore */
			byte_index += 9;
			break;
        case picoquic_frame_type_max_data:
			ret = picoquic_decode_max_data_frame(cnx, bytes + byte_index, bytes_max - byte_index, &consumed);
			byte_index += consumed;
			cnx->ack_needed = 1;
			break;
        case picoquic_frame_type_max_stream_data:
			ret = picoquic_decode_max_stream_data_frame(cnx, bytes + byte_index, bytes_max - byte_index, &consumed);
			byte_index += consumed;
			cnx->ack_needed = 1;
			break;
        case picoquic_frame_type_max_stream_id: /* MAX_STREAM_ID */
			ret = picoquic_decode_max_stream_id_frame(cnx, bytes + byte_index, bytes_max - byte_index, &consumed);
			byte_index += consumed;
			cnx->ack_needed = 1;
			break;
        case picoquic_frame_type_ping: /* PING */
			byte_index ++;
			cnx->ack_needed = 1;
			break;
        case picoquic_frame_type_blocked: /* BLOCKED */
			byte_index++;
			break;
        case picoquic_frame_type_stream_blocked: /* STREAM_BLOCKED */
			byte_index+=5;
			break;
        case picoquic_frame_type_stream_id_needed: /* STREAM_ID_NEEDED */
			byte_index++;
			cnx->ack_needed = 1;
			break;
        case picoquic_frame_type_new_connection_id: /* NEW_CONNECTION_ID */
			byte_index+=9;
			cnx->ack_needed = 1;
			break;
        default:
            /* Not implemented yet! */
            ret = -1;
            break;
        }
    } 
    return ret;
}

int picoquic_skip_frame(uint8_t * bytes, size_t bytes_max, size_t * consumed, 
    int * pure_ack, uint32_t version_flags)
{
	int ret = 0;
	size_t byte_index = 0;
	uint8_t first_byte = bytes[byte_index++];

	*pure_ack = 1;
	*consumed = 0;

	if (first_byte >= picoquic_frame_type_ack_range_min)
	{
		if (first_byte >= picoquic_frame_type_stream_range_min)
		{
			/* skip stream frame */
			uint8_t stream_id_length = 1 + ((first_byte >> 3) & 3);
			uint8_t offset_length = picoquic_offset_length_code[(first_byte >> 1) & 3];
			uint8_t data_length_length = (first_byte & 1)*2;
			size_t data_length;

			*pure_ack = 0;

			if (bytes_max < (1u + stream_id_length + offset_length + data_length_length))
			{
				ret = -1;
			}
			else
			{
				byte_index += stream_id_length;
				byte_index += offset_length;

				if (data_length_length == 0)
				{
					data_length = bytes_max - byte_index;
				}
				else
				{
					data_length = PICOPARSE_16(&bytes[byte_index]);
					byte_index += 2;

					if (byte_index + data_length > bytes_max)
					{
						ret = -1;
					}
				}

				if (ret == 0)
				{
					*consumed = byte_index + data_length;
				}
			}
		}
		else
		{
			/* skip ack frame */
			int has_num_block = (first_byte >> 4) & 1;
			int num_block = 0;
			int num_ts;
			int ll = (first_byte >> 2) & 3;
			int mm = (first_byte & 3);

			if (bytes_max < 3)
			{
				ret = -1;
			}
			else
			{
				if (has_num_block)
				{
					num_block = bytes[byte_index++];
				}

                if (version_flags&picoquic_version_basic_time_stamp)
                {
                    num_ts = bytes[byte_index++];
                }
                else
                {
                    num_ts = 0;
                }

				switch (ll)
				{
				case 0:
					byte_index++;
					break;
				case 1:
					byte_index += 2;
					break;
				case 2:
					byte_index += 4;
					break;
				case 3:
					byte_index += 8;
					break;
				}
				/* ACK delay */
				byte_index += 2;

				/* last range and blocks */
				switch (mm)
				{
				case 0:
					byte_index += 1 + num_block*(1 + 1);
					break;
				case 1:
					byte_index += 2 + num_block*(1 + 2);
					break;
				case 2:
					byte_index += 4 + num_block*(1 + 4);
					break;
				case 3:
					byte_index += 8 + num_block*(1 + 8);
					break;
			    default:
					DBG_FATAL_PRINTF("Internal error: out of range mm=%u", mm);
					break;
				}

				if (num_ts > 0)
				{
					byte_index += 2 + num_ts * 3;
				}

				if (byte_index > bytes_max)
				{
					ret = -1;
					*consumed = 0;
				}
				else
				{
					*consumed = byte_index;
				}
			}
		}
	}
	else
	{
		switch (first_byte)
		{
		case picoquic_frame_type_padding:
			/* Padding */
			do {
				byte_index++;
			} while (byte_index < bytes_max && bytes[byte_index] == picoquic_frame_type_padding);

			break;
		case picoquic_frame_type_reset_stream: 
			byte_index += 17;
			*pure_ack = 0;
			break;
		case picoquic_frame_type_connection_close: 
			byte_index += 7;
			*pure_ack = 0;
			break;
		case picoquic_frame_type_goaway:
			byte_index += 9;
			break;
		case picoquic_frame_type_max_data:
			byte_index += 9;
			*pure_ack = 0;
			break;
		case picoquic_frame_type_max_stream_data:
			byte_index += 13;
			*pure_ack = 0;
			break;
		case picoquic_frame_type_max_stream_id:
			byte_index += 5;
			*pure_ack = 0;
			break;
		case picoquic_frame_type_ping:
			byte_index++;
			*pure_ack = 0;
			break;
		case picoquic_frame_type_blocked:
			byte_index++;
			break;
		case picoquic_frame_type_stream_blocked:
			byte_index += 5;
			break;
		case picoquic_frame_type_stream_id_needed:
			byte_index++;
			break;
		case picoquic_frame_type_new_connection_id:
			byte_index += 9;
			*pure_ack = 0;
			break;
		default:
			/* Not implemented yet! */
			ret = -1;
			break;
		}
		*consumed = byte_index;
	}

	return ret;
}
