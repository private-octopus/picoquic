/* Decoding of the various frames, and application to context */
#include "picoquic.h"

/*
 * Decoding of a stream frame.
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

picoquic_stream_head * find_stream(picoquic_cnx * cnx, uint32_t stream_id, int create)
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
        stream = (picoquic_stream_head *)malloc(sizeof(picoquic_stream_head));
        if (stream != NULL)
        {
            stream->consumed_offset = 0;
            stream->fin_offset = 0;
            stream->next_stream = cnx->first_stream.next_stream;
            stream->stream_id = stream_id;
            cnx->first_stream.next_stream = stream;
        }
    }

    return stream;
}

int picoquic_stream_input(picoquic_cnx * cnx, uint32_t stream_id,
    uint64_t offset, int fin, uint8_t * bytes, size_t length)
{
    int ret = 0;
    /* Is there such a stream, is it still open? */
    picoquic_stream_head * stream = find_stream(cnx, stream_id, 1);

    if (stream == NULL)
    {
        ret = -1;
    }
    else
    {
        picoquic_stream_data ** pprevious = &stream->stream_data;
        picoquic_stream_data * next = stream->stream_data;
        size_t start = 0;
        int overlap = 0;

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
                data_length -= (size_t) (offset + length - next->offset);
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
                    }
                }
            }
        }
    }
    
    return ret;
}

int picoquic_decode_stream_frame(picoquic_cnx * cnx, uint8_t * bytes,
    size_t bytes_max, int restricted, size_t * consumed)
{
    int ret = 0;
    size_t byte_index = 1;
    uint8_t first_byte = bytes[0];
    uint8_t stream_id_length = 1 + ((first_byte >> 3) & 3);
    uint8_t offset_length = picoquic_offset_length_code[(first_byte >> 1) & 3];
    uint8_t data_length_length = (first_byte & 1) * 2;
    uint32_t stream_id;
    size_t data_length;
    uint64_t offset;


    *consumed = 0;

    if (bytes_max < (1u + stream_id_length + offset_length + data_length_length))
    {
        ret = -1;
    }
    else
    {
        switch (stream_id_length)
        {
        case 1:
            stream_id = bytes[byte_index];
            break;
        case 2:
            stream_id = PICOPARSE_16(&bytes[byte_index]);
            break;
        case 3:
            stream_id = PICOPARSE_24(&bytes[byte_index]);
            break;
        case 4:
            stream_id = PICOPARSE_32(&bytes[byte_index]);
            break;
        }

        if (restricted && stream_id != 0)
        {
            ret = -1;
        }
        else
        {
            byte_index += stream_id_length;

            switch (offset_length)
            {
            case 0:
                offset = 0;
                break;
            case 2:
                offset = PICOPARSE_16(&bytes[byte_index]);
                break;
            case 4:
                offset = PICOPARSE_32(&bytes[byte_index]);
                break;
            case 8:
                offset = PICOPARSE_64(&bytes[byte_index]);
                break;
            }
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

                ret = picoquic_stream_input(cnx, stream_id, offset, first_byte & 32,
                    bytes + byte_index, data_length);
            }
        }
    }

    return ret;
}


int picoquic_prepare_stream_frame(picoquic_cnx * cnx, picoquic_stream_head * stream,
    uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
    int ret = 0;
    size_t byte_index = 1;
    uint8_t ss_bits = 0;
    uint8_t oo_bits = 0;
    size_t length;

    if (stream->send_queue == NULL ||
        stream->send_queue->length <= stream->send_queue->offset)
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
        }

        bytes[0] = 0xC1 | (ss_bits << 3) | (oo_bits << 1);

        *consumed = byte_index;
    }

    return ret;
}

/*
 * Decoding of the received frames.
 Type   Frame
 0x00 	PADDING
 0x01 	RST_STREAM
 0x02 	CONNECTION_CLOSE
 0x03 	GOAWAY
 0x04 	MAX_DATA
 0x05 	MAX_STREAM_DATA
 0x06 	MAX_STREAM_ID
 0x07 	PING
 0x08 	BLOCKED
 0x09 	STREAM_BLOCKED
 0x0a 	STREAM_ID_NEEDED
 0x0b 	NEW_CONNECTION_ID
 0xa0 - 0xbf 	ACK
 0xc0 - 0xff 	STREAM
 *
 * In some cases, the expected frames are "restricted" to only ACK, STREAM 0 and PADDING.
 */

int picoquic_decode_frames(picoquic_cnx * cnx, uint8_t * bytes,
    size_t bytes_max, int restricted)
{
    int ret = 0;
    size_t byte_index = 0;

    while (byte_index < bytes_max && ret == 0)
    {
        uint8_t first_byte = bytes[byte_index];

        if (first_byte >= 0xa0)
        {
            if (first_byte >= 0xc0)
            {
                /* decode stream frame */
                size_t consumed = 0;

                ret = picoquic_decode_stream_frame(cnx, bytes + byte_index, bytes_max - byte_index, restricted, &consumed);

                byte_index += consumed;
            }
            else
            {
                /* ACK processing */
            }
        }
        else if (restricted)
        {
           /* forbidden! */
            if (first_byte == 0)
            {
                /* Padding */
                do {
                    byte_index++;
                } while (byte_index < bytes_max && bytes[byte_index] == 0);
            }
            else
            {
                ret = -1;
            }
        }
        else switch (first_byte)
        {
        case 0:
            /* Padding */
            do {
                byte_index++;
            } while (byte_index < bytes_max && bytes[byte_index] == 0);
            break;
        case 0x01: /* RST_STREAM */
        case 0x02: /* CONNECTION_CLOSE */
        case 0x03: /* GOAWAY */
        case 0x04: /* MAX_DATA */
        case 0x05: /* MAX_STREAM_DATA */
        case 0x06: /* MAX_STREAM_ID */
        case 0x07: /* PING */
        case 0x08: /* BLOCKED */
        case 0x09: /* STREAM_BLOCKED */
        case 0x0a: /* STREAM_ID_NEEDED */
        case 0x0b: /* NEW_CONNECTION_ID */
        default:
            /* Not implemented yet! */
            ret = -1;
            break;
        }
    } 
    return ret;
}