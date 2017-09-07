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

/*
* Packet logging.
*/
#include <stdio.h>
#include "picoquic_internal.h"
#include "fnv1a.h"
#include "tls_api.h"

void picoquic_log_error_packet(FILE * F, uint8_t * bytes, size_t bytes_max, int ret)
{
	fprintf(F, "Packet length %d caused error: %d\n", (int)bytes_max, ret);

	for (size_t i = 0; i < bytes_max;)
	{
		fprintf(F, "%04x:  ", i);

		for (int j = 0; j < 16 && i < bytes_max; j++, i++)
		{
			fprintf(F, "%02x ", bytes[i]);
		}
		fprintf(F, "\n");
	}
	fprintf(F, "\n");
}

void picoquic_log_packet_address(FILE* F, picoquic_cnx_t * cnx,
	struct sockaddr * addr_peer, int receiving, size_t length)
{
	fprintf(F, (receiving)? "Receiving %d bytes from ":"Sending %d bytes to ",
		length);

	if (addr_peer->sa_family == AF_INET)
	{
		struct sockaddr_in * s4 = (struct sockaddr_in *)addr_peer;

		fprintf(F, "%d.%d.%d.%d:%d\n",
			s4->sin_addr.S_un.S_un_b.s_b1,
			s4->sin_addr.S_un.S_un_b.s_b2,
			s4->sin_addr.S_un.S_un_b.s_b3,
			s4->sin_addr.S_un.S_un_b.s_b4,
			ntohs(s4->sin_port));
	}
	else
	{
		int zero_found = 0;
		struct sockaddr_in6 * s6 = (struct sockaddr_in6 *)addr_peer;

		for (int i = 0; i < 8; i++)
		{
			if (i != 0)
			{
				fprintf(F, ":");
			}

			if (s6->sin6_addr.u.Byte[2 * i] != 0)
			{
				fprintf(F, "%x%02x", s6->sin6_addr.u.Byte[2 * i], s6->sin6_addr.u.Byte[(2 * i) + 1]);
			}
			else
			{
				fprintf(F, "%x", s6->sin6_addr.u.Byte[(2 * i) + 1]);
			}
		}
		fprintf(F, "\n");
	}
}

static char const * picoquic_ptype_names[] = {
	"error",
	"version negotiation",
	"client initial",
	"server stateless",
	"server cleartext",
	"client cleartext",
	"0rtt protected",
	"1rtt protected phi0",
	"1rtt protected phi1",
	"public reset"
};

static const size_t picoquic_nb_ptype_names = sizeof(picoquic_ptype_names) / sizeof(char const *);

char const * picoquic_log_ptype_name(picoquic_packet_type_enum ptype)
{
	if (((size_t)ptype) < picoquic_nb_ptype_names)
	{
		return picoquic_ptype_names[ptype];
	}
	else
	{
		return "unknown";
	}
}

void picoquic_log_packet_header(FILE* F, picoquic_cnx_t * cnx, picoquic_packet_header * ph)
{
	fprintf(F, "    Type: %d(%s), CnxID: %llx%s, Seq: %x (%llx), Version %x\n",
		ph->ptype, picoquic_log_ptype_name(ph->ptype), ph->cnx_id,
		(cnx == NULL) ? " (unknown)" : "",
		ph->pn, ph->pn64, ph->vn);
}

void picoquic_log_negotiation_packet(FILE* F, 
	uint8_t * bytes, size_t length, picoquic_packet_header * ph)
{
	size_t byte_index = ph->offset;
	uint32_t vn = 0;

	fprintf(F, "    versions: ");

	while (byte_index + 4 <= length)
	{
		vn = PICOPARSE_32(bytes + byte_index);
		byte_index += 4;
		fprintf(F, "%x, ", vn);
	}
	fprintf(F, "\n");
}


int picoquic_log_stream_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	int ret = 0;
	size_t byte_index = 1;
	uint8_t first_byte = bytes[0];
	uint8_t stream_id_length = 1 + ((first_byte >> 3) & 3);
	uint8_t offset_length = 0;
	uint8_t data_length_length = (first_byte & 1) * 2;
	uint32_t stream_id = 0;
	size_t data_length;
	uint64_t offset = 0;

	switch ((first_byte >> 1) & 3)
	{
	case 0:
		offset_length = 0;
		break;
	case 1:
		offset_length = 2;
		break;
	case 2:
		offset_length = 4;
		break;
	case 3:
		offset_length = 8;
		break;
	}

	if (bytes_max < (1u + stream_id_length + offset_length + data_length_length))
	{
		fprintf(F, "    Malformed stream frame.\n");
		byte_index = bytes_max;
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
		}

		fprintf(F, "    Stream %d, offset %llu, length %d", stream_id, offset, data_length);

		if (byte_index + data_length > bytes_max)
		{
			fprintf(F, ", malformed!\n");
			byte_index = bytes_max;
		}
		else
		{
			fprintf(F, ": ");
			for (size_t i = 0; i < 8 && i < data_length; i++)
			{
				fprintf(F, "%02x", bytes[byte_index + i]);
			}
			fprintf(F, "%s\n", (data_length > 8)?"...":"");
			byte_index += data_length;
		}
	}

	return byte_index;
}

size_t picoquic_log_ack_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{

	int ret = 0;
	size_t byte_index = 1;
	uint8_t first_byte = bytes[0];
	int has_num_block = (first_byte >> 4) & 1;
	int num_block = 0;
	int num_ts;
	int ll = (first_byte >> 2) & 3;
	int mm = (first_byte & 3);
	uint64_t largest;
	uint64_t last_range = 0;
	uint64_t ack_range = 0;
	uint64_t acked_mask = 0;
	uint64_t gap;
	size_t min_size;

	if (bytes_max < 3)
	{
		fprintf(F, "    Malformed ACK frame\n");
		return bytes_max;
	}

	if (has_num_block)
	{
		num_block = bytes[byte_index++];
	}
	num_ts = bytes[byte_index++];

	/* Check the size first */
	min_size = byte_index;

	switch (ll)
	{
	case 0:
		min_size++;
		break;
	case 1:
		min_size += 2;
		break;
	case 2:
		min_size += 4;
		break;
	case 3:
		min_size += 8;
		break;
	}
	/* ACK delay */
	min_size += 2;

	/* last range and blocks */
	switch (mm)
	{
	case 0:
		min_size += 1 + num_block*(1 + 1);
		break;
	case 1:
		min_size += 2 + num_block*(1 + 2);
		break;
	case 2:
		min_size += 4 + num_block*(1 + 4);
		break;
	case 3:
		min_size += 8 + num_block*(1 + 8);
		break;
	}

	if (num_ts > 0)
	{
		min_size += 2 + num_ts * 3;
	}

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed ACK, requires %d bytes out of %d\n", min_size, bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, print it */

	fprintf(F, "    ACK (nb=%d, nt=%d),", num_block, num_ts);

	/* decoding the largest */
	switch (ll)
	{
	case 0:
		largest = bytes[byte_index++];
		fprintf(F, "Largest = %02x, ", (uint8_t)largest);
		break;
	case 1:
		largest = PICOPARSE_16(bytes + byte_index);
		fprintf(F, "Largest = %04x, ", (uint16_t)largest);
		byte_index += 2;
		break;
	case 2:
		largest = PICOPARSE_32(bytes + byte_index);
		fprintf(F, "Largest = %08x, ", (uint32_t)largest);
		byte_index += 4;
		break;
	case 3:
		largest = PICOPARSE_64(bytes + byte_index);
		fprintf(F, "Largest = %llx, ", largest);
		byte_index += 8;
		break;
	}
	/* ACK delay */
	byte_index += 2;

	/* last range */
	switch (mm)
	{
	case 0:
		last_range = bytes[byte_index++];
		byte_index += 1;
		break;
	case 1:
		last_range = PICOPARSE_16(bytes + byte_index);
		byte_index += 2;
		break;
	case 2:
		last_range = PICOPARSE_32(bytes + byte_index);
		byte_index += 4;
		break;
	case 3:
		last_range = PICOPARSE_64(bytes + byte_index);
		byte_index += 8;
		break;
	}
	fprintf(F, "range: %llx, ", last_range);

	for (int i = 0; ret == 0 && i < num_block; i++)
	{
		gap = bytes[byte_index++];

		switch (mm)
		{
		case 0:
			ack_range = bytes[byte_index++];
			byte_index += 1;
			break;
		case 1:
			ack_range = PICOPARSE_16(bytes + byte_index);
			byte_index += 2;
			break;
		case 2:
			ack_range = PICOPARSE_32(bytes + byte_index);
			byte_index += 4;
			break;
		case 3:
			ack_range = PICOPARSE_64(bytes + byte_index);
			byte_index += 8;
			break;
		}

		fprintf(F, "gap: %llx, range: %llx, ", gap, ack_range);
	}

	if (ret == 0)
	{
		if (num_ts > 0)
		{
			byte_index += 2 + num_ts * 3;
		}

		if (byte_index > bytes_max)
		{
			fprintf(F, "malformed!\n");
			byte_index = bytes_max;
		}
		else
		{
			fprintf(F, "\n");
		}
	}

	return byte_index;
}

size_t picoquic_log_reset_stream_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	int ret = 0;
	size_t byte_index = 1;
	const size_t min_size = 1 + 4 + 4 + 8;
	uint32_t stream_id;
	uint32_t error_code;
	uint64_t offset;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed RESET STREAM, requires %d bytes out of %d\n", min_size, bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
	stream_id = PICOPARSE_32(bytes + byte_index);
	byte_index += 4;
	error_code = PICOPARSE_32(bytes + byte_index);
	byte_index += 4;
	offset = PICOPARSE_64(bytes + byte_index);
	byte_index += 8;


	fprintf(F, "    Stream %d (0x%08x), Error 0x%08x, Offset 0x%llx.\n", 
		stream_id, stream_id, error_code, offset);

	return byte_index;
}

size_t picoquic_log_go_away_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	int ret = 0;
	size_t byte_index = 1;
	const size_t min_size = 1 + 4 + 4;
	uint32_t max_stream_id_client;
	uint32_t max_stream_id_server;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed MAX STREAM ID, requires %d bytes out of %d\n", min_size, bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
	max_stream_id_client = PICOPARSE_32(bytes + byte_index);
	byte_index += 4;
	
	max_stream_id_server = PICOPARSE_32(bytes + byte_index);
	byte_index += 4;

	fprintf(F, "    Max stream client %d (0x%08x), server %d (0x%08x).\n",
		max_stream_id_client, max_stream_id_client,
		max_stream_id_server, max_stream_id_server);

	return byte_index;
}

size_t picoquic_log_connection_close_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	int ret = 0;
	size_t byte_index = 1;
	size_t min_size = 1 + 4 + 2;
	uint32_t error_code;
	uint16_t string_length;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed CONNECTION CLOSE, requires %d bytes out of %d\n", min_size, bytes_max);
		return bytes_max;
	}

	/* Now that the size is above the minimum */
	error_code = PICOPARSE_32(bytes + byte_index);
	byte_index += 4;
	string_length = PICOPARSE_16(bytes + byte_index);
	byte_index += 2;


	fprintf(F, "    Connection close, Error 0x%08x, Reason length %d (0x%04x):\n",
		error_code, string_length, string_length);
	if (byte_index + string_length > bytes_max)
	{
		fprintf(F, "    Malformed CONNECTION CLOSE, requires %d bytes out of %d\n", 
			byte_index + string_length, bytes_max);
		byte_index = bytes_max;
	}
	else
	{
		/* TODO: print the UTF8 string */
		byte_index += string_length;
	}

	return byte_index;
}

size_t picoquic_log_max_data_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	int ret = 0;
	size_t byte_index = 1;
	const size_t min_size = 1 + 8;
	uint64_t max_data;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed MAX DATA, requires %d bytes out of %d\n", min_size, bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
	max_data = PICOPARSE_64(bytes + byte_index);
	byte_index += 8;

	fprintf(F, "    Max data: 0x%llx.\n", max_data);

	return byte_index;
}

size_t picoquic_log_max_stream_data_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	int ret = 0;
	size_t byte_index = 1;
	const size_t min_size = 1 + 4 + 8;
	uint32_t stream_id;
	uint64_t max_data;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed MAX STREAM DATA, requires %d bytes out of %d\n", min_size, bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
	stream_id = PICOPARSE_32(bytes + byte_index);
	byte_index += 4;
	max_data = PICOPARSE_64(bytes + byte_index);
	byte_index += 8;

	fprintf(F, "    Stream: %d (0x%08x), max data: 0x%llx.\n", 
		stream_id, stream_id, max_data);

	return byte_index;
}

size_t picoquic_log_max_stream_id_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	int ret = 0;
	size_t byte_index = 1;
	const size_t min_size = 1 + 4;
	uint32_t max_stream_id;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed MAX STREAM ID, requires %d bytes out of %d\n", min_size, bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
	max_stream_id = PICOPARSE_32(bytes + byte_index);
	byte_index += 4;

	fprintf(F, "    Max stream: %d (0x%08x).\n",
		max_stream_id, max_stream_id);

	return byte_index;
}

size_t picoquic_log_stream_blocked_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	int ret = 0;
	size_t byte_index = 1;
	const size_t min_size = 1 + 4;
	uint32_t blocked_stream_id;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed STREAM BLOCKED, requires %d bytes out of %d\n", min_size, bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
	blocked_stream_id = PICOPARSE_32(bytes + byte_index);
	byte_index += 4;

	fprintf(F, "    Stream blocked: %d (0x%08x).\n",
		blocked_stream_id, blocked_stream_id);

	return byte_index;
}

size_t picoquic_log_new_connection_id_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	int ret = 0;
	size_t byte_index = 1;
	const size_t min_size = 1 + 8;
	uint64_t new_cnx_id;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed New Connection Id, requires %d bytes out of %d\n", min_size, bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
	new_cnx_id = PICOPARSE_64(bytes + byte_index);
	byte_index += 8;

	fprintf(F, "    New connection id: 0x%016llx.\n",
		new_cnx_id);

	return byte_index;
}


static char const * picoquic_log_frame_names[] =
{
	"Padding",
	"CONNECTION_CLOSE",
	"RST_STREAM",
	"GOAWAY",
	"MAX_DATA",
	"MAX_STREAM_DATA",
	"MAX_STREAM_ID",
	"PING",
	"BLOCKED",
	"STREAM_BLOCKED",
	"STREAM_ID_NEEDED",
	"NEW_CONNECTION_ID"
};

static const size_t picoquic_nb_log_frame_names = sizeof(picoquic_log_frame_names) / sizeof(char const *);

void picoquic_log_frames(FILE* F, uint8_t * bytes, size_t length)
{
	size_t byte_index = 0;
	size_t consumed = 0;

	while (byte_index < length)
	{
		if (bytes[byte_index] >= 0xC0)
		{
			byte_index += picoquic_log_stream_frame(F, bytes + byte_index, length - byte_index);
		}
		else if (bytes[byte_index] > 0xA0)
		{
			byte_index += picoquic_log_ack_frame(F, bytes + byte_index, length - byte_index);
		}
		else if(bytes[byte_index] == 0)
		{
			size_t nb_pad = 0;

			while (bytes[byte_index] == 0)
			{
				byte_index++;
				nb_pad++;
			}

			fprintf(F, "Padding, %d bytes\n", nb_pad);
		}
		else
		{
			uint32_t frame_id = bytes[byte_index];

			if (frame_id < picoquic_nb_log_frame_names)
			{
				fprintf(F, "    %s frame\n", picoquic_log_frame_names[frame_id]);
			}
			else
			{
				fprintf(F, "    Unknown frame, type: %x\n", frame_id);
			}

			switch (frame_id)
			{
			case 0x01: /* RST_STREAM */
				byte_index += picoquic_log_reset_stream_frame(F, bytes + byte_index, 
					length - byte_index);
				break;
			case 0x02: /* CONNECTION_CLOSE */
				byte_index += picoquic_log_connection_close_frame(F, bytes + byte_index,
					length - byte_index);
				break;
			case 0x03: /* GOAWAY */
				/* Not supported anymore. */
				byte_index += picoquic_log_go_away_frame(F, bytes + byte_index,
					length - byte_index);
				break;
			case 0x04: /* MAX_DATA */
				byte_index += picoquic_log_max_data_frame(F, bytes + byte_index,
					length - byte_index);
				break;
			case 0x05: /* MAX_STREAM_DATA */
				byte_index += picoquic_log_max_stream_data_frame(F, bytes + byte_index,
					length - byte_index);
				break;
			case 0x06: /* MAX_STREAM_ID */
				byte_index += picoquic_log_max_stream_id_frame(F, bytes + byte_index,
					length - byte_index);
				break;
			case 0x07: /* PING -- Format depends on version! */
				/* No payload in current version */
				byte_index++;
				break;
			case 0x08: /* BLOCKED */
				/* No payload */
				byte_index++;
				break;
			case 0x09: /* STREAM_BLOCKED */
				byte_index += picoquic_log_stream_blocked_frame(F, bytes + byte_index,
					length - byte_index);
				break;
			case 0x0a: /* STREAM_ID_NEEDED */
				/* No payload */
				byte_index++;
				break;
			case 0x0b: /* NEW_CONNECTION_ID */
				byte_index += picoquic_log_new_connection_id_frame(F, bytes + byte_index,
					length - byte_index);
				break;
			default:
				/* Not implemented yet! */
				byte_index = length;
				break;
			}
		}
	}
}

uint32_t picoquic_log_decrypt_clear_text(FILE* F, 
	uint8_t * bytes, size_t length)
{
	/* Verify the checksum */
	uint32_t decoded_length = fnv1a_check(bytes, length);
	if (decoded_length == 0)
	{
		/* Incorrect checksum, drop and log. */
		fprintf(F, "    Error: cannot verify the FNV1A checksum.\n");
	}
	else
	{
		fprintf(F, "    FNV1A checksum is correct (%d bytes).\n", decoded_length);
	}

	return decoded_length;
}

void picoquic_log_decrypt_encrypted(FILE* F,
	picoquic_cnx_t * cnx,
	uint8_t * bytes, size_t length, picoquic_packet_header * ph)
{
	/* decrypt in a separate copy */
	uint8_t decrypted[PICOQUIC_MAX_PACKET_SIZE];
	size_t decrypted_length = picoquic_aead_decrypt(cnx, decrypted,
		bytes + ph->offset, length - ph->offset, ph->pn64, bytes, ph->offset);

	if (decrypted_length > length)
	{
		fprintf(F, "    Decryption failed!\n");
	}
	else
	{
		fprintf(F, "    Decrypted %d bytes\n", decrypted_length);
		picoquic_log_frames(F, decrypted, decrypted_length);
	}
}


void picoquic_log_packet(FILE* F, picoquic_quic_t * quic, picoquic_cnx_t * cnx, 
	struct sockaddr * addr_peer, int receiving,
	uint8_t * bytes,  size_t length)
{
	int ret = 0;
	picoquic_packet_header ph;
	size_t decoded_length = 0;

	/* first log line */
	picoquic_log_packet_address(F, cnx, addr_peer, receiving, length);
	/* Parse the clear text header */
	ret = picoquic_parse_packet_header(bytes, length, &ph);


	if (ret != 0)
	{
		/* packet does not even parse */
		fprintf(F, "   Cannot parse the packet header.\n");
	}
	else 
	{
		cnx = picoquic_cnx_by_net(quic, addr_peer);

		if (cnx == NULL && ph.cnx_id != 0)
		{
			cnx = picoquic_cnx_by_id(quic, ph.cnx_id);
		}

		if (cnx != NULL)
		{
			ph.pn64 = picoquic_get_packet_number64(
				cnx->first_sack_item.end_of_sack_range, ph.pnmask, ph.pn);
		}
		else
		{
			ph.pn64 = ph.pn;
		}

		picoquic_log_packet_header(F, cnx, &ph);

		switch (ph.ptype)
		{
		case picoquic_packet_version_negotiation:
			/* log version negotiation */
			picoquic_log_negotiation_packet(F, bytes, length, &ph);
			break;
		case picoquic_packet_server_stateless:
		case picoquic_packet_client_initial:
		case picoquic_packet_server_cleartext:
		case picoquic_packet_client_cleartext:
			/* log clear text packet */
			decoded_length = picoquic_log_decrypt_clear_text(F, bytes, length);
			if (decoded_length > 0)
			{
				/* log the frames */
				picoquic_log_frames(F, bytes + ph.offset, decoded_length - ph.offset);
			}
			break;
		case picoquic_packet_0rtt_protected:
			/* log 0-rtt packet */
			break;
		case picoquic_packet_1rtt_protected_phi0:
		case picoquic_packet_1rtt_protected_phi1:
			if (receiving)
			{
				picoquic_log_decrypt_encrypted(F, cnx, bytes, length, &ph);
			}
			break;
		default:
			/* Packet type error. Log and ignore */
			break;
		}
	}
	fprintf(F, "\n");
}

static char const * picoquic_log_state_name[] = {
	"client_init",
	"client_init_sent",
	"client_renegotiate",
    "picoquic_state_client_hrr_received",
	"client_init_resent",
	"server_init",
	"client_handshake_start",
	"client_handshake_progress",
	"client_almost_ready",
	"client_ready",
	"server_almost_ready",
	"server_ready",
	"disconnecting",
	"disconnected"
};

static const size_t picoquic_nb_log_state_name = sizeof(picoquic_log_state_name) / sizeof(char const *);

void picoquic_log_processing(FILE* F, picoquic_cnx_t * cnx, size_t length, int ret)
{
	fprintf(F, "Processed %d bytes, state = %d (%s), return %d\n\n",
		length, cnx->cnx_state,
		(((size_t)cnx->cnx_state) < picoquic_nb_log_state_name) ?
		picoquic_log_state_name[(size_t)cnx->cnx_state] : "unknown",
		ret);
}

void picoquic_log_transport_extension(FILE* F, picoquic_cnx_t * cnx)
{

	uint8_t * bytes = NULL;
	size_t bytes_max = 0;
	int ext_received_return = 0;
	int client_mode = 1;
	int ret = 0;
	size_t byte_index = 0;
	char const * sni = picoquic_tls_get_sni(cnx);
	char const * alpn = picoquic_tls_get_negotiated_alpn(cnx);

	if (sni == NULL)
	{
		fprintf(F, "SNI not received.\n");
	}
	else
	{
		fprintf(F, "Received SNI: %s\n", sni);
	}

	if (alpn == NULL)
	{
		fprintf(F, "ALPN not received.\n");
	}
	else
	{
		fprintf(F, "Received ALPN: %s\n", alpn);
	}
	picoquic_provide_received_transport_extensions(cnx,
		&bytes, &bytes_max, &ext_received_return, &client_mode);

	if (bytes_max == 0)
	{
		fprintf(F, "Did not receive transport parameter TLS extension.\n");
	}
	else if (bytes_max < 128)
	{
		fprintf(F, "Received transport parameter TLS extension (%d bytes):\n", (uint32_t)bytes_max);
		switch (client_mode)
		{
		case 0: // Client hello
			if (bytes_max < 8)
			{
				fprintf(F, "Malformed extension\n");
				ret = -1;
			}
			else
			{
				uint32_t version;
				uint32_t proposed_version;

				version = PICOPARSE_32(bytes + byte_index);
				byte_index += 4;
				proposed_version = PICOPARSE_32(bytes + byte_index);
				byte_index += 4;

				fprintf(F, "Version: %08x\nProposed version: %08x\n", version, proposed_version);
			}
			break;
		case 1: // Server encrypted extension
		{
			if (bytes_max < 1)
			{
				fprintf(F, "Malformed extension\n");
				ret = -1;
			}
			else
			{
				size_t supported_versions_size = bytes[byte_index++];

				if ((supported_versions_size & 3) != 0)
				{
					fprintf(F,
						"Malformed extension, supported version size = %d, not multiple of 4.\n",
						(uint32_t)supported_versions_size);
					ret = -1;

				}
				else if (supported_versions_size > 252 ||
					byte_index + supported_versions_size > bytes_max)
				{
					fprintf(F, "    Malformed extension, supported version size = %d, max %d or 252\n",
						(uint32_t)supported_versions_size, (uint32_t)(bytes_max - byte_index));
					ret = -1;
				}
				else
				{
					size_t nb_supported_versions = supported_versions_size / 4;
					fprintf(F, "    Supported version (%d bytes):\n", supported_versions_size);

					for (size_t i = 0; i < nb_supported_versions; i++)
					{
						uint32_t supported_version = PICOPARSE_32(bytes + byte_index);

						byte_index += 4;
						if (supported_version == cnx->proposed_version &&
							cnx->proposed_version != cnx->version)
						{
							fprintf(F, "        %08x (same as proposed!)\n", supported_version);
						}
						else
						{
							fprintf(F, "        %08x\n", supported_version);
						}
					}
				}
			}
			break;
		}
		default: // New session ticket
			break;
		}

		if (ret == 0 && byte_index + 2 > bytes_max)
		{
			fprintf(F, "    Malformed extension list\n");
			ret = -1;
		}
		else
		{
			uint16_t extensions_size = PICOPARSE_16(bytes + byte_index);
			size_t extensions_end;
			byte_index += 2;
			extensions_end = byte_index + extensions_size;

			if (extensions_end > bytes_max)
			{
				fprintf(F, "    Extension list too long (%d bytes vs %d)\n",
					(uint32_t)extensions_size, (uint32_t)(bytes_max - byte_index));
			}
			else
			{
				fprintf(F, "    Extension list (%d bytes):\n",
					(uint32_t)extensions_size);
				while (ret == 0 && byte_index < extensions_end)
				{
					if (byte_index + 6 > extensions_end)
					{
						fprintf(F, "        Malformed extension.\n");
						ret = -1;
					}
					else
					{
						uint16_t extension_type = PICOPARSE_16(bytes + byte_index);
						uint16_t extension_length = PICOPARSE_16(bytes + byte_index + 2);
						byte_index += 4;

						fprintf(F, "        Extension type: %d, length %d (0x%04x / 0x%04x), ",
							extension_type, extension_length, extension_type, extension_length);

						if (byte_index + extension_length > extensions_end)
						{
							fprintf(F, "Malformed extension.\n");
							ret = -1;
						}
						else
						{
							for (uint16_t i = 0; i < extension_length; i++)
							{
								fprintf(F, "%02x", bytes[byte_index++]);
							}
							fprintf(F, "\n");
						}
					}
				}
			}
		}
		if (byte_index < bytes_max)
		{
			fprintf(F, "    Remaining bytes (%d)\n", (uint32_t)(bytes_max - byte_index));
		}
	}
	else
	{
		fprintf(F, "Received transport parameter TLS extension (%d bytes):\n", (uint32_t)bytes_max);
		fprintf(F, "    First 128 received bytes (%d):\n", (uint32_t)(bytes_max - byte_index));
	}

	while (byte_index < bytes_max && byte_index < 128)
	{
		fprintf(F, "        ");
		for (int i = 0; i < 32 && byte_index < bytes_max && byte_index < 128; i++)
		{
			fprintf(F, "%02x", bytes[byte_index++]);
		}
		fprintf(F, "\n");
	}
	fprintf(F, "\n");
}