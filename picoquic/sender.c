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

#include "picoquic_internal.h"
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

int picoquic_add_to_stream(picoquic_cnx_t * cnx, uint32_t stream_id, 
	const uint8_t * data, size_t length, int set_fin)
{
    int ret = 0;
    picoquic_stream_head * stream = NULL;

    /* TODO: check for other streams. */
    if (stream_id == 0)
    {
        stream = &cnx->first_stream;
    }
	else
	{
		stream = picoquic_find_stream(cnx, stream_id, 1);

		if (stream == NULL)
		{
			ret = -1;
		}
		else if (set_fin)
		{
			if ((stream->stream_flags&picoquic_stream_flag_fin_notified) != 0)
			{
				/* app error, notified the fin twice*/
				if (length > 0)
				{
					ret = -1;
				}
			}
			else
			{
				stream->stream_flags |= picoquic_stream_flag_fin_notified;
			}
		}
	}

	if (ret == 0 && length > 0)
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

#ifdef PICOQUIC_RETRANSMIT_INITIAL_USEFUL
/*
 * Retransmit the client initial, but no other packet, after
 * receiving a version negotiation from the server
 */
int picoquic_retransmit_initial(picoquic_cnx_t * cnx, picoquic_packet * packet)
{
	int ret = 0;
	picoquic_packet * p = cnx->retransmit_oldest;
	picoquic_packet ** previous = &cnx->retransmit_oldest;
	picoquic_packet_header ph;
	uint8_t * bytes = packet->bytes;

	while ((p = *previous) != NULL)
	{
		int ret = picoquic_parse_packet_header(p->bytes, p->length, &ph);
		if (ret == 0 && ph.ptype == picoquic_packet_client_initial)
		{
			break;
		}
		previous = &p->next_packet;
	}

	if (p == NULL)
	{
		ret = -1;
	}
	else
	{
		int ret = 0;
		int packet_is_pure_ack = 1;
		int frame_is_pure_ack = 0;
		uint8_t * bytes = packet->bytes;
		size_t header_length = 0;
		size_t frame_length = 0;
		size_t byte_index = 0; /* Used when parsing the old packet */
		size_t checksum_length = 16;

		/* Create a long packet. TODO: special case for 0-RTT data. TODO: short packets. */
		bytes[0] = 0x80 | ph.ptype;

		picoformat_64(&bytes[1], ph.cnx_id);
		picoformat_32(&bytes[9], (uint32_t)cnx->send_sequence);
		picoformat_32(&bytes[13], cnx->version);

		memcpy(&bytes[17], &p->bytes[ph.offset], p->length - ph.offset);
		packet->length = p->length - ph.offset + 17;

		/* deueue and free the queued packet */
		picoquic_dequeue_retransmit_packet(cnx, p, 1);
	}

	return ret;
}
#endif /* PICOQUIC_RETRANSMIT_INITIAL_USEFUL */

/*
 * If a retransmit is needed, fill the packet with the required
 * retransmission. Also, prune the retransmit queue as needed.
 */

int picoquic_retransmit_needed(picoquic_cnx_t * cnx, uint64_t current_time, 
	picoquic_packet * packet, int * use_fnv1a)
{
	picoquic_packet * p;
	size_t length = 0;

	/* Only retransmit at reasonable intervals */
	if (cnx->nb_retransmit > 0 &&
		(cnx->latest_retransmit_time + 1000000ull * cnx->nb_retransmit) > current_time)
	{
		return 0;
	}
	else if (cnx->nb_retransmit > 4)
	{
		cnx->cnx_state = picoquic_state_disconnected;
	}

	/* TODO: while packets are pure ACK, drop them from retransmit queue */
	while ((p = cnx->retransmit_oldest) != NULL)
	{
		int64_t delta_seq = cnx->highest_acknowledged - p->sequence_number;

		length = 0;

		if (delta_seq < 3)
		{
			int64_t delta_t = cnx->latest_time_acknowledged - p->send_time;

			/* TODO: out of order delivery time ought to be dynamic */
			if (delta_t < 10000)
			{
				/* Don't fire yet, because of possible out of order delivery */
				int64_t time_out = current_time - p->send_time;

				/* TODO: timer limit ought to be dynamic */
				if (time_out < 1000000)
				{
					p = NULL;
				}
			}
		}

		if (p == NULL)
		{
			break;
		}
		else
		{
			/* check if this is an ACK only packet */
			picoquic_packet_header ph;
			int ret = 0;
			int packet_is_pure_ack = 1;
			int frame_is_pure_ack = 0;
			uint8_t * bytes = packet->bytes;
			size_t header_length = 0;
			size_t frame_length = 0;
			size_t byte_index = 0; /* Used when parsing the old packet */
			size_t checksum_length = 16;

			/* Get the packet type */
			ret = picoquic_parse_packet_header(p->bytes, p->length, &ph);

			switch (ph.ptype)
			{
			case picoquic_packet_client_initial:
			case picoquic_packet_server_cleartext:
			case picoquic_packet_client_cleartext:
				*use_fnv1a = 1;
				checksum_length = 8;
				break;
			default:
				*use_fnv1a = 0;
				break;
			}

			/* Create a long packet. TODO: special case for 0-RTT data. TODO: short packets. */
			bytes[0] = 0x80 | ph.ptype;

			picoformat_64(&bytes[1], ph.cnx_id);
			picoformat_32(&bytes[9], (uint32_t)cnx->send_sequence);
			picoformat_32(&bytes[13], cnx->version);

			length = 17;
			header_length = length;
			packet->sequence_number = cnx->send_sequence;
			packet->send_time = current_time;

			/* Copy the relevant bytes from one packet to the next */
			byte_index = ph.offset;

			while (ret == 0 && byte_index < p->length)
			{
				ret = picoquic_skip_frame(&p->bytes[byte_index],
					p->length - ph.offset, &frame_length, &frame_is_pure_ack);

				if (!frame_is_pure_ack)
				{
					memcpy(&bytes[length], &p->bytes[byte_index], frame_length);
					length += frame_length;
					packet_is_pure_ack = 0;
				}
				byte_index += frame_length;
			}

			/* Remove old packet from queue */
			picoquic_dequeue_retransmit_packet(cnx, p, 1);

			/* If we have a good packet, return it */
			if (packet_is_pure_ack)
			{
				length = 0;
			}
			else
			{
				/* special case for the client initial */
				if (ph.ptype == picoquic_packet_client_initial)
				{
					while (length < (cnx->send_mtu - checksum_length))
					{
						bytes[length++] = 0;
					}
				}
				packet->length = length;
				cnx->nb_retransmit++;
				cnx->latest_retransmit_time = current_time;

				break;
			}
		}
	} 

	return length;
}

int picoquic_prepare_packet(picoquic_cnx_t * cnx, picoquic_packet * packet,
	uint64_t current_time, uint8_t * send_buffer, size_t send_buffer_max, size_t * send_length)
{
	/* TODO: Check for interesting streams */
	int ret = 0;
	/* TODO: manage multiple streams. */
	picoquic_stream_head * stream = &cnx->first_stream;
	picoquic_packet_type_enum packet_type = 0;
	size_t checksum_overhead = 8;
	int use_fnv1a = 1;
	size_t data_bytes = 0;
	uint64_t cnx_id = cnx->server_cnxid;
	int retransmit_possible = 0;
	picoquic_packet * retransmit_packet = NULL;
	size_t bytes_index = 0;
	int header_length = 0;
	uint8_t * bytes = packet->bytes;
	size_t length = 0;

	/* Prepare header -- depend on connection state */
	/* TODO: 0-RTT work. */
	switch (cnx->cnx_state)
	{
	case picoquic_state_client_init:
		packet_type = picoquic_packet_client_initial;
		cnx_id = cnx->initial_cnxid;
		/* In the initial state, need to actually create the first bytes */
		break;
	case picoquic_state_client_init_sent:
	case picoquic_state_client_init_resent:
		packet_type = picoquic_packet_client_initial;
		cnx_id = cnx->initial_cnxid;
		retransmit_possible = 1;
		break;
	case picoquic_state_client_renegotiate:
		packet_type = picoquic_packet_client_initial;
		cnx_id = cnx->initial_cnxid;
		break;
	case picoquic_state_server_init:
		packet_type = picoquic_packet_server_cleartext;
		break;
	case picoquic_state_server_almost_ready:
		packet_type = picoquic_packet_server_cleartext;
		break;
	case picoquic_state_client_handshake_start:
		packet_type = picoquic_packet_client_cleartext;
		retransmit_possible = 1;
		break;
	case picoquic_state_client_handshake_progress:
		packet_type = picoquic_packet_client_cleartext;
		retransmit_possible = 1;
		break;
	case picoquic_state_client_almost_ready:
		packet_type = picoquic_packet_client_cleartext;
		break;
	case picoquic_state_client_ready:
		packet_type = picoquic_packet_1rtt_protected_phi0;
		retransmit_possible = 1;
		use_fnv1a = 0;
		checksum_overhead = 16;
		stream = picoquic_find_ready_stream(cnx, 0);
		break;
	case picoquic_state_server_ready:
		packet_type = picoquic_packet_1rtt_protected_phi0;
		use_fnv1a = 0;
		checksum_overhead = 16;
		stream = picoquic_find_ready_stream(cnx, 0);
		retransmit_possible = 1;
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
	
	if (retransmit_possible &&
		(length = picoquic_retransmit_needed(cnx, current_time, packet, &use_fnv1a)) > 0)
	{
		/* Set the new checksum length */
		checksum_overhead = (use_fnv1a) ? 8 : 16;
		/* Check whether it makes sens to add an ACK at the end of the retransmission */
		if (picoquic_prepare_ack_frame(cnx, current_time, &bytes[length],
			cnx->send_mtu - checksum_overhead - length, &data_bytes) == 0)
		{
			length += data_bytes;
			packet->length = length;
		}
	}
	else if (use_fnv1a && cnx->first_stream.send_queue == NULL)
	{
		/* when in a clear text mode, only send packets if there is
		 * actually something to send, or resend */

		packet->length = 0;
	}
	else if (ret == 0)
	{
		/* Prepare the packet header */
		if (packet_type == picoquic_packet_1rtt_protected_phi0 ||
			packet_type == picoquic_packet_1rtt_protected_phi1)
		{
			/* Create a short packet -- using 32 bit sequence numbers for now */
			uint8_t C = (cnx->remote_parameters.omit_connection_id != 0) ? 0 : 0x40;
			uint8_t K = (packet_type == picoquic_packet_1rtt_protected_phi0) ? 0 : 0x20;
			uint8_t PT = 3;

			length = 0;
			bytes[length++] = (C | K | PT);
			if (C != 0)
			{
				picoformat_64(&bytes[length], cnx_id);
				length += 8;
			}
			picoformat_32(&bytes[length], (uint32_t)cnx->send_sequence);
			length += 4;
		}
		else
		{
			/* Create a long packet */
			bytes[0] = 0x80 | packet_type;

			picoformat_64(&bytes[1], cnx_id);
			picoformat_32(&bytes[9], (uint32_t)cnx->send_sequence);
			picoformat_32(&bytes[13], cnx->version);

			length = 17;
		}
		header_length = length;
		packet->sequence_number = cnx->send_sequence;
		packet->send_time = current_time;

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
		/* include here the actual retransmission, copying bytes
		 * from the old packet to the new one */
		else if ((stream == NULL || stream->send_queue == NULL) &&
			picoquic_is_ack_needed(cnx, current_time) == 0)
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
			if (stream != NULL)
			{
				ret = picoquic_prepare_stream_frame(cnx, stream, &bytes[length],
					cnx->send_mtu - checksum_overhead - length, &data_bytes);
			}

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

			/* If stream zero packets are sent, progress the state */
			if (ret == 0 && stream != NULL && stream->stream_id == 0 && data_bytes > 0 &&
				stream->send_queue == NULL)
			{
				switch (cnx->cnx_state)
				{
				case picoquic_state_client_init:
					cnx->cnx_state = picoquic_state_client_init_sent;
					break;
				case picoquic_state_client_renegotiate:
					cnx->cnx_state = picoquic_state_client_init_resent;
					break;
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

	if (ret == 0 && length > 0)
	{
		packet->length = length;
		cnx->send_sequence++;

		if (use_fnv1a)
		{
			memcpy(send_buffer, packet->bytes, length);
			length = fnv1a_protect(send_buffer, length, send_buffer_max);
		}
		else
		{
			/* AEAD Encrypt, to the send buffer */
			memcpy(send_buffer, packet->bytes, header_length);
			length = picoquic_aead_encrypt(cnx, send_buffer + header_length,
				packet->bytes + header_length, length - header_length,
				packet->sequence_number, send_buffer, header_length);
			length += header_length;
		}

		*send_length = length;

		/* Manage the double linked packet list for retransmissions */
		packet->previous_packet = NULL;
		if (cnx->retransmit_newest == NULL)
		{
			packet->next_packet = NULL;
			cnx->retransmit_oldest = packet;
		}
		else
		{
			packet->next_packet = cnx->retransmit_newest;
			packet->next_packet->previous_packet = packet;
		}
		cnx->retransmit_newest = packet;
	}
	else
	{
		*send_length = 0;
	}
	
	return ret;
}

int picoquic_close(picoquic_cnx_t * cnx)
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