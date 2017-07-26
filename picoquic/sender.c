#include "picoquic.h"
#include "fnv1a.h"
#include "tls_api.h"

/*
 * Sending logic.
 *
 * Data is sent over streams. This is instantiated by the "Post to stream" command, which
 * chains data to the head of stream structure. Data is unchained when it sent for the
 * first time.
 * 
 * Data is sent in packets, which contain stream frames and possibly other frames.
 * The retransmission logic operates on packets. If a packet is seen as lost, the
 * important frames that it contains will have to be retransmitted.
 *
 * Unacknowledged packets are kept in a chained list. Packets get removed from that
 * list during the processing of acknowledgements. Packets are marked lost when a
 * sufficiently older packet is acknowledged, or after a timer. Lost packets
 * generate new packets, which are queued in the chained list.
 *
 * Stream 0 is special, in the sense that it cannot be closed or reset, and is not
 * subject to flow control.
 */

int picoquic_add_to_stream(picoquic_cnx * cnx, uint32_t stream_id, uint8_t * data, size_t length)
{
    int ret = 0;
    picoquic_stream_head * stream = NULL;

    /* TODO: check for other streams. */
    if (stream_id == 0)
    {
        stream = &cnx->first_stream;
    }

    if (stream == NULL)
    {
        ret = -1;
    }
    else
    {
        picoquic_stream_data * stream_data = (picoquic_stream_data *)malloc(sizeof(picoquic_stream_data));

        if (stream_data == 0)
        {
            ret = -1;
        }
        else
        {
            stream_data->bytes = (uint8_t *)malloc(length);

            if (stream_data->bytes == NULL)
            {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            }
            else
            {
                picoquic_stream_data ** pprevious = &stream->send_queue;
                picoquic_stream_data * next = stream->send_queue;

                memcpy(stream_data->bytes, data, length);
                stream_data->length = length;
                stream_data->offset = 0;
                stream_data->next_stream_data = NULL;

                while (next != NULL)
                {
                    pprevious = &next->next_stream_data;
                    next = next->next_stream_data;
                }

                *pprevious = stream_data;
            }
        }
    }

    return ret;
}

picoquic_packet * picoquic_create_packet()
{
    picoquic_packet * packet = (picoquic_packet *)malloc(sizeof(picoquic_packet));

    if (packet != NULL)
    {
        memset(packet, 0, sizeof(picoquic_packet));
    }

    return packet;
}


int picoquic_prepare_packet(picoquic_cnx * cnx, picoquic_packet * packet,
	uint64_t current_time)
{
    /* TODO: Check for interesting streams */
    int ret = 0;
    picoquic_stream_head * stream = &cnx->first_stream;
    picoquic_packet_type_enum packet_type = 0;
    size_t checksum_overhead = 8;
    int use_fnv1a = 1;
    size_t data_bytes = 0;
    uint64_t cnx_id = cnx->server_cnxid;

    /* Prepare header -- depend on connection state */
    /* TODO: 0-RTT work. */
    switch (cnx->cnx_state)
    {
    case picoquic_state_client_init:
        packet_type = picoquic_packet_client_initial;
        cnx_id = cnx->initial_cnxid;
        /* In the initial state, need to actually create the first bytes */
        break;
    case picoquic_state_server_init:
        packet_type = picoquic_packet_server_cleartext;
        break;
    case picoquic_state_server_almost_ready:
        packet_type = picoquic_packet_server_cleartext;
        break;
    case picoquic_state_client_handshake_start: 
        packet_type = picoquic_packet_client_cleartext;
        break;
    case picoquic_state_client_handshake_progress:
        packet_type = picoquic_packet_client_cleartext;
        break;
    case picoquic_state_client_almost_ready:
        packet_type = picoquic_packet_client_cleartext;
        break;
    case picoquic_state_client_ready: 
        packet_type = picoquic_packet_1rtt_protected_phi0;
        use_fnv1a = 0;
        checksum_overhead = 16;
        break;
    case picoquic_state_server_handshake_progress:
        packet_type = picoquic_packet_server_stateless;
        break;
    case picoquic_state_server_ready: 
        packet_type = picoquic_packet_1rtt_protected_phi0;
        use_fnv1a = 0;
        checksum_overhead = 16;
        break;
    case picoquic_state_disconnecting:
        packet_type = picoquic_packet_1rtt_protected_phi0;
        use_fnv1a = 0;
        checksum_overhead = 16;
        break;
    case picoquic_state_disconnected: 
        ret = -1; 
        break;
    default:
        ret = -1;
        break;
    }

    if (use_fnv1a && cnx->first_stream.send_queue == NULL)
    {
        /* when in a clear text mode, only send packets if there is
         * actually something to send */

        packet->length = 0;
    }
    else if (ret == 0)
    {
        /* Prepare the packet header */
        int bytes_index = 0;
        int header_length = 0;
        uint8_t * bytes = packet->bytes;
        size_t length;

        /* Create a long packet */
        bytes[0] = 0x80 | packet_type;

        picoformat_64(&bytes[1], cnx_id);
        picoformat_32(&bytes[9], (uint32_t) cnx->send_sequence);
        picoformat_32(&bytes[13], cnx->version);

        length = 17;
        header_length = length;

        if (cnx->cnx_state == picoquic_state_disconnecting)
        {
            /* Content is just a disconnect frame */
            size_t consumed = 0;
            ret = picoquic_prepare_connection_close_frame(cnx, bytes + header_length,
                cnx->send_mtu - checksum_overhead - length, &consumed);
            if (ret == 0)
            {
                length += consumed;
            }
            cnx->cnx_state = picoquic_state_disconnected;
        }
        else if (stream->send_queue == NULL)
        {
            length = 0;
        }
        else
        {
            /* TODO: Check whether ACK is needed */
			ret = picoquic_prepare_ack_frame(cnx, current_time, &bytes[length],
				cnx->send_mtu - checksum_overhead - length, &data_bytes);
			if (ret == 0)
			{
				length += data_bytes;
			}

            /* Encode the stream frame */
            ret = picoquic_prepare_stream_frame(cnx, stream, &bytes[length],
                cnx->send_mtu - checksum_overhead - length, &data_bytes);

            if (ret == 0)
            {
                length += data_bytes;
                if (packet_type == picoquic_packet_client_initial)
                {
                    while (length < cnx->send_mtu - checksum_overhead)
                    {
                        bytes[length++] = 0; /* TODO: Padding frame type, which is 0 */
                    }
                }
            }
        }

        if (ret == 0 && length > 0)
        {
            if (use_fnv1a)
            {
                length = fnv1a_protect(bytes, length, sizeof(packet->bytes));
            }
            else
            {
                /* AEAD Encrypt, in place */
                length = picoquic_aead_encrypt(cnx, bytes + header_length,
                    bytes + header_length, length - header_length,
                    cnx->send_sequence, bytes, header_length);
                length += header_length;
            }

            packet->length = length;

            /* If the stream zero packets are sent, progress the state */
            if (ret == 0 && stream->stream_id == 0 && data_bytes > 0 &&
                stream->send_queue == NULL)
            {
                switch (cnx->cnx_state)
                {
                case picoquic_state_server_almost_ready:
                    cnx->cnx_state = picoquic_state_server_ready;
                    break;
                case picoquic_state_client_almost_ready:
                    cnx->cnx_state = picoquic_state_client_ready;
                    break;
                default:
                    break;
                }
            }
        }
    }

    return ret;
}

int picoquic_close(picoquic_cnx * cnx)
{
    int ret = 0;
    if (cnx->cnx_state == picoquic_state_server_ready ||
        cnx->cnx_state == picoquic_state_client_ready)
    {
        cnx->cnx_state = picoquic_state_disconnecting;
    }
    else
    {
        ret = -1;
    }

    return ret;
}