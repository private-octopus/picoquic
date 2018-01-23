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
#include <string.h>
#include <stdio.h>
#include "picoquic_internal.h"
#include "fnv1a.h"
#include "tls_api.h"

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
    "handshake_failure",
    "client_ready",
    "server_almost_ready",
    "server_ready",
    "disconnecting",
    "closing_received",
    "closing",
    "draining",
    "disconnected",
    "send_hrr"
};

static const size_t picoquic_nb_log_state_name = sizeof(picoquic_log_state_name) / sizeof(char const *);

static char const * picoquic_log_frame_names[] =
{
    "Padding",
    "RST_STREAM",
    "CONNECTION_CLOSE",
    "GOAWAY",
    "MAX_DATA",
    "MAX_STREAM_DATA",
    "MAX_STREAM_ID",
    "PING",
    "BLOCKED",
    "STREAM_BLOCKED",
    "STREAM_ID_NEEDED",
    "NEW_CONNECTION_ID",
    "STOP_SENDING",
    "PONG",
    "ACK"
};

void picoquic_log_error_packet(FILE * F, uint8_t * bytes, size_t bytes_max, int ret)
{
	fprintf(F, "Packet length %d caused error: %d\n", (int)bytes_max, ret);

	for (size_t i = 0; i < bytes_max;)
	{
		fprintf(F, "%04x:  ", (int)i);

		for (int j = 0; j < 16 && i < bytes_max; j++, i++)
		{
			fprintf(F, "%02x ", bytes[i]);
		}
		fprintf(F, "\n");
	}
	fprintf(F, "\n");
}

void picoquic_log_time(FILE* F, picoquic_cnx_t * cnx, uint64_t current_time, 
    const char * label1, const char * label2)
{
    uint64_t delta_t = (cnx == NULL)? current_time: current_time - cnx->start_time;
    uint64_t time_sec = delta_t / 1000000;
    uint32_t time_usec = (uint32_t)(delta_t % 1000000);

    fprintf(F, "%s%llu.%06d%s", label1,
        (unsigned long long) time_sec, time_usec, label2);
}

void picoquic_log_packet_address(FILE* F, picoquic_cnx_t * cnx,
	struct sockaddr * addr_peer, int receiving, size_t length, uint64_t current_time)
{
    uint64_t delta_t = 0;  
    uint64_t time_sec = 0;
    uint32_t time_usec = 0;

	fprintf(F, (receiving)? "Receiving %d bytes from ":"Sending %d bytes to ",
		(int)length);

	if (addr_peer->sa_family == AF_INET)
	{
		struct sockaddr_in * s4 = (struct sockaddr_in *)addr_peer;
                uint8_t * addr = (uint8_t *) &s4->sin_addr;

		fprintf(F, "%d.%d.%d.%d:%d",
			addr[0], addr[1], addr[2], addr[3],
			ntohs(s4->sin_port));
	}
	else
	{
		struct sockaddr_in6 * s6 = (struct sockaddr_in6 *)addr_peer;
                uint8_t * addr = (uint8_t *) &s6->sin6_addr;

		for (int i = 0; i < 8; i++)
		{
			if (i != 0)
			{
				fprintf(F, ":");
			}

			if (addr[2 * i] != 0)
			{
				fprintf(F, "%x%02x", addr[2 * i], addr[(2 * i) + 1]);
			}
			else
			{
				fprintf(F, "%x", addr[(2 * i) + 1]);
			}
		}
	}

    if (cnx != NULL)
    {
        delta_t = current_time - cnx->start_time;
        time_sec = delta_t / 1000000;
        time_usec = (uint32_t)(delta_t % 1000000);
    }

    fprintf(F, "\n at T=%llu.%06d (%llx)\n",
        (unsigned long long) time_sec, time_usec,
        (unsigned long long) current_time);
}

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
	fprintf(F, "    Type: %d (%s), CnxID: %llx%s, Seq: %x (%llx), Version %x\n",
		ph->ptype, picoquic_log_ptype_name(ph->ptype),
                (unsigned long long)ph->cnx_id,
		(cnx == NULL) ? " (unknown)" : "",
		ph->pn, (unsigned long long)ph->pn64, ph->vn);
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

size_t picoquic_log_stream_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	size_t byte_index;
	uint64_t stream_id;
	size_t data_length;
	uint64_t offset;
    int fin;
    int ret = 0;

	debug_printf_push_stream(F);
    ret = picoquic_parse_stream_header(bytes, bytes_max,
            &stream_id, &offset, &data_length, &fin, &byte_index);

	debug_printf_pop_stream();

	if (ret != 0)
		return bytes_max;

	fprintf(F, "    Stream %" PRIu64 ", offset %" PRIu64 ", length %d, fin = %d", stream_id,
			offset, (int)data_length, fin);

	fprintf(F, ": ");
	for (size_t i = 0; i < 8 && i < data_length; i++)
	{
		fprintf(F, "%02x", bytes[byte_index + i]);
	}
	fprintf(F, "%s\n", (data_length > 8)?"...":"");

	return byte_index + data_length;
}

size_t picoquic_log_ack_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
    size_t   byte_index;
    uint64_t num_block;
    uint64_t largest;
    uint64_t ack_delay;

    debug_printf_push_stream(F);

    int ret = picoquic_parse_ack_header(bytes, bytes_max,
        &num_block, &largest, &ack_delay, &byte_index, 0);

    debug_printf_pop_stream();

    if (ret != 0)
        return bytes_max;

    /* Now that the size is good, print it */
    fprintf(F, "    ACK (nb=%u)", (int)num_block);

    /* decoding the acks */
    unsigned extra_ack = 1;

    while (ret == 0)
    {
        uint64_t range;
        uint64_t block_to_block;

        if (byte_index >= bytes_max)
        {
            fprintf(F, "    Malformed ACK RANGE, %d blocks remain.\n", (int)num_block);
            ret = -1;
            break;
        }

        size_t l_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &range);
        if (l_range == 0)
        {
            byte_index = bytes_max;
            ret = -1;
            fprintf(F, "    Malformed ACK RANGE, requires %d bytes out of %d", (int)picoquic_varint_skip(bytes),
                (int)(bytes_max - byte_index));
            break;
        }
        else
        {
            byte_index += l_range;
        }

        range += extra_ack;
        if (largest + 1 < range)
        {
            fprintf(F, "ack range error: largest=%" PRIx64 ", range=%" PRIx64, largest, range);
            byte_index = bytes_max;
            ret = -1;
            break;
        }

        if (range > 1)
            fprintf(F, ", %" PRIx64 "-%" PRIx64, largest - (range - 1), largest);
        else if (range == 1)
            fprintf(F, ", %" PRIx64, largest);
        else
            fprintf(F, ", _");

        if (num_block-- == 0)
            break;

        /* Skip the gap */

        if (byte_index >= bytes_max)
        {
            fprintf(F, "\n    Malformed ACK GAP, %d blocks remain.", (int)num_block);
            byte_index = bytes_max;
            ret = -1;
            break;
        }
        else
        {
            size_t l_gap = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &block_to_block);
            if (l_gap == 0)
            {
                byte_index = bytes_max;
                ret = -1;
                fprintf(F, "\n    Malformed ACK GAP, requires %d bytes out of %d", (int)picoquic_varint_skip(bytes),
                    (int)(bytes_max - byte_index));
                break;
            }
            else
            {
                byte_index += l_gap;
                block_to_block += range;
            }
        }

        if (largest < block_to_block)
        {
            fprintf(F, "\n    ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64,
                largest, range, block_to_block - range);
            byte_index = bytes_max;
            ret = -1;
            break;
        }

        largest -= block_to_block;
        extra_ack = 0;
    }

    fprintf(F, "\n");

    return byte_index;
}

size_t picoquic_log_reset_stream_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    uint64_t stream_id = 0;
    uint32_t error_code = 0;
    uint64_t offset = 0;

    size_t l1 = 0, l2 = 0;
    if (bytes_max > 2)
    {
        l1 = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &stream_id);
        byte_index += l1;
        if (l1 > 0 && bytes_max >= byte_index + 3)
        {
            error_code = PICOPARSE_16(bytes + byte_index);
            byte_index += 2;
            l2 = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &offset);
            byte_index += l2;
        }
    }

    if (l1 == 0 || l2 == 0)
    {
        fprintf(F, "    Malformed RESET STREAM, requires %d bytes out of %d\n", (int)(byte_index +
            ((l1 == 0) ? (picoquic_varint_skip(bytes + 1) + 3) : picoquic_varint_skip(bytes + byte_index))),
            (int)bytes_max);
        byte_index = bytes_max;
    }
    else
    {
        fprintf(F, "    RESET STREAM %llu, Error 0x%08x, Offset 0x%llx.\n",
            (unsigned long long)stream_id, error_code, (unsigned long long) offset);
    }

    return byte_index;
}

size_t picoquic_log_stop_sending_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    const size_t min_size = 1 + picoquic_varint_skip(bytes + 1) + 2;
    uint64_t stream_id;
    uint32_t error_code;

    if (min_size > bytes_max)
    {
        fprintf(F, "    Malformed STOP SENDING, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
        return bytes_max;
    }

    /* Now that the size is good, parse and print it */
    byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &stream_id);
    error_code = PICOPARSE_16(bytes + byte_index);
    byte_index += 2;

    fprintf(F, "    STOP SENDING %d (0x%08x), Error 0x%x.\n",
        (uint32_t)stream_id, (uint32_t)stream_id, error_code);

    return byte_index;
}

size_t picoquic_log_connection_close_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    uint32_t error_code = 0;
    uint64_t string_length = 0;

    size_t l1 = 0;
    if (bytes_max >= 4)
    {
        error_code = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        l1 = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &string_length);
    }

    if (l1 == 0)
    {
        fprintf(F, "    Malformed CONNECTION CLOSE, requires %d bytes out of %d\n",
            (int)(byte_index + picoquic_varint_skip(bytes + 3)), (int)bytes_max);
        return bytes_max;
    }
    else
    {
        byte_index += l1;
    }

    fprintf(F, "    CONNECTION CLOSE, Error 0x%04x, Reason length %llu\n",
        error_code, (unsigned long long) string_length);
    if (byte_index + string_length > bytes_max)
    {
        fprintf(F, "    Malformed CONNECTION CLOSE, requires %llu bytes out of %llu\n",
            (unsigned long long)(byte_index + string_length), (unsigned long long) bytes_max);
        byte_index = bytes_max;
    }
    else
    {
        /* TODO: print the UTF8 string */
        byte_index += (size_t)string_length;
    }

    return byte_index;
}

size_t picoquic_log_application_close_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    uint32_t error_code = 0;
    uint64_t string_length = 0;

    size_t l1 = 0;
    if (bytes_max >= 4)
    {
        error_code = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        l1 = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &string_length);
    }

    if (l1 == 0)
    {
        fprintf(F, "    Malformed APPLICATION CLOSE, requires %d bytes out of %d\n",
            (int)(byte_index + picoquic_varint_skip(bytes + 3)), (int)bytes_max);
        return bytes_max;
    }
    else
    {
        byte_index += l1;
    }

    fprintf(F, "    APPLICATION CLOSE, Error 0x%04x, Reason length %d (0x%04x):\n",
        error_code, (uint16_t)string_length, (uint16_t)string_length);
    if (byte_index + string_length > bytes_max)
    {
        fprintf(F, "    Malformed APPLICATION CLOSE, requires %d bytes out of %d\n",
            (int)(byte_index + string_length), (int)bytes_max);
        byte_index = bytes_max;
    }
    else
    {
        /* TODO: print the UTF8 string */
        byte_index += (size_t)string_length;
    }

    return byte_index;
}

size_t picoquic_log_max_data_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    uint64_t max_data;

    size_t l1 = picoquic_varint_decode(bytes + 1, bytes_max - 1, &max_data);

    if (1 + l1 > bytes_max)
    {
        fprintf(F, "    Malformed MAX DATA, requires %d bytes out of %d\n", (int)(1 + l1), (int)bytes_max);
        return bytes_max;
    }
    else
    {
        byte_index = 1 + l1;
    }

    fprintf(F, "    MAX DATA: 0x%llx.\n", (unsigned long long) max_data);

    return byte_index;
}

size_t picoquic_log_max_stream_data_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    uint64_t stream_id;
    uint64_t max_data;


    size_t l1 = picoquic_varint_decode(bytes + 1, bytes_max - 1, &stream_id);
    size_t l2 = picoquic_varint_decode(bytes + 1 + l1, bytes_max - 1 - l1, &max_data);

    if (l1 == 0 || l2 == 0)
    {
        fprintf(F, "    Malformed MAX STREAM DATA, requires %d bytes out of %d\n",
            (int)(1 + l1 + l2), (int)bytes_max);
        return bytes_max;
    }
    else
    {
        byte_index = 1 + l1 + l2;
    }

    fprintf(F, "    MAX STREAM DATA, Stream: %" PRIu64 ", max data: 0x%llx.\n",
        stream_id, (unsigned long long) max_data);

    return byte_index;
}

size_t picoquic_log_max_stream_id_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	size_t byte_index = 1;
    const size_t min_size = 1 + picoquic_varint_skip(bytes + 1);
	uint64_t max_stream_id;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed MAX STREAM ID, requires %d bytes out of %d\n", (int) min_size, (int) bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
    byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &max_stream_id);

	fprintf(F, "    MAX STREAM ID: %" PRIu64 ".\n", max_stream_id);

	return byte_index;
}

size_t picoquic_log_blocked_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    const size_t min_size = 1 + picoquic_varint_skip(bytes + 1);
    uint64_t blocked_offset = 0;

    if (min_size > bytes_max)
    {
        fprintf(F, "    Malformed BLOCKED, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
        return bytes_max;
    }

    /* Now that the size is good, parse and print it */
    byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &blocked_offset);
    byte_index += picoquic_varint_skip(&bytes[byte_index]);

    fprintf(F, "    BLOCKED: offset %" PRIu64 ".\n",
        blocked_offset);

    return byte_index;
}

size_t picoquic_log_stream_blocked_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	size_t byte_index = 1;
	const size_t min_size =  1 + picoquic_varint_skip(bytes+1);
	uint64_t blocked_stream_id;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed STREAM BLOCKED, requires %d bytes out of %d\n", (int) min_size, (int) bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */   
    byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &blocked_stream_id);
    byte_index += picoquic_varint_skip(&bytes[byte_index]);
    

	fprintf(F, "    STREAM BLOCKED: %" PRIu64 ".\n",
		blocked_stream_id);

	return byte_index;
}

size_t picoquic_log_new_connection_id_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	size_t byte_index = 1;
	size_t min_size = 1 + 8 + 16;
	uint64_t new_cnx_id;
    size_t l_seq = 2;

    l_seq = picoquic_varint_skip(&bytes[byte_index]);

    min_size += l_seq;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed NEW CONNECTION ID, requires %d bytes out of %d\n", (int) min_size, (int) bytes_max);
		return bytes_max;
	}

    byte_index += l_seq;
	/* Now that the size is good, parse and print it */
	new_cnx_id = PICOPARSE_64(bytes + byte_index);
	byte_index += 8;

	fprintf(F, "    NEW CONNECTION ID: 0x%016llx, ",
		(unsigned long long) new_cnx_id);

    for (size_t i = 0; i < 16; i++)
    {
        fprintf(F, "%02x", bytes[byte_index++]);
    }

    fprintf(F, "\n");

	return byte_index;
}

size_t picoquic_log_ping_pong_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
    size_t byte_index = 1;
    size_t ping_length = bytes[byte_index++];

    if (byte_index + ping_length > bytes_max)
    {
        fprintf(F, "    Malformed %s frame, length %d, %d bytes needed, %d available\n",
            picoquic_log_frame_names[bytes[0]], (int)ping_length,
            (int)(ping_length + 2), (int)bytes_max);
        byte_index = bytes_max;
    }
    else if (ping_length == 0)
    {
        if (bytes[0] == picoquic_frame_type_ping)
        {
            fprintf(F, "    %s frame, length = 0.\n",
                picoquic_log_frame_names[bytes[0]]);
        }
        else
        {
            fprintf(F, "    Unexpected empty %s frame.\n",
                picoquic_log_frame_names[bytes[0]]);
            byte_index = bytes_max;
        }
    }
    else
    {
        fprintf(F, "    %s length %d: ", picoquic_log_frame_names[bytes[0]], (int)ping_length);

        for (size_t i = 0; i < ping_length && i < 16; i++)
        {
            fprintf(F, "%02x", bytes[byte_index + i]);
        }

        if (ping_length > 16)
        {
            fprintf(F, " ...");
        }
        fprintf(F, "\n");

        byte_index += ping_length;
    }

    return byte_index;
}

void picoquic_log_frames(FILE* F, uint8_t * bytes, size_t length)
{
	size_t byte_index = 0;

    while (byte_index < length)
    {
        int ack_or_data = 0;

        if (bytes[byte_index] >= picoquic_frame_type_stream_range_min &&
            bytes[byte_index] <= picoquic_frame_type_stream_range_max)
        {
            ack_or_data = 1;
            byte_index += picoquic_log_stream_frame(F, bytes + byte_index, length - byte_index);
        }
        else if (bytes[byte_index] == picoquic_frame_type_ack)
        {
            ack_or_data = 1;
            byte_index += picoquic_log_ack_frame(F, bytes + byte_index, length - byte_index);
        }
        

        if (ack_or_data == 0)
        {
            if (bytes[byte_index] == 0)
            {
                int nb_pad = 0;

                while (bytes[byte_index] == 0 && byte_index < length)
                {
                    byte_index++;
                    nb_pad++;
                }

                fprintf(F, "    Padding, %d bytes\n", nb_pad);
            }
            else
            {
                uint32_t frame_id = bytes[byte_index];

                switch (frame_id)
                {
                case picoquic_frame_type_reset_stream: /* RST_STREAM */
                    byte_index += picoquic_log_reset_stream_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_connection_close: /* CONNECTION_CLOSE */
                    byte_index += picoquic_log_connection_close_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_application_close:
                    byte_index += picoquic_log_application_close_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_max_data: /* MAX_DATA */
                    byte_index += picoquic_log_max_data_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_max_stream_data: /* MAX_STREAM_DATA */
                    byte_index += picoquic_log_max_stream_data_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_max_stream_id: /* MAX_STREAM_ID */
                    byte_index += picoquic_log_max_stream_id_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_ping:
                    byte_index += picoquic_log_ping_pong_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_blocked: /* BLOCKED */
                    /* No payload */
                    byte_index += picoquic_log_blocked_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_stream_blocked: /* STREAM_BLOCKED */
                    byte_index += picoquic_log_stream_blocked_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_stream_id_needed: /* STREAM_ID_NEEDED */
                    /* No payload */
                    fprintf(F, "    %s frame\n", picoquic_log_frame_names[frame_id]);
                    byte_index++;
                    byte_index += picoquic_varint_skip(&bytes[byte_index]);
                    break;
                case picoquic_frame_type_new_connection_id: /* NEW_CONNECTION_ID */
                    byte_index += picoquic_log_new_connection_id_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_stop_sending: /* STOP_SENDING */
                    byte_index += picoquic_log_stop_sending_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_pong: /* PONG */
                    byte_index += picoquic_log_ping_pong_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                default:
                    /* Not implemented yet! */
                    fprintf(F, "    Unknown frame, type: %x\n", frame_id);
                    byte_index = length;
                    break;
                }
            }
        }
    }
}

uint32_t picoquic_log_decrypt_clear_text(FILE* F, 
	uint8_t * bytes, size_t length)
{
	/* Verify the checksum */
	uint32_t decoded_length = (uint32_t) fnv1a_check(bytes, length);
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
	picoquic_cnx_t * cnx, int receiving,
	uint8_t * bytes, size_t length, picoquic_packet_header * ph)
{
	/* decrypt in a separate copy */
	uint8_t decrypted[PICOQUIC_MAX_PACKET_SIZE];
    size_t decrypted_length = 0;
    int cmp_reset_secret = 0;  
    int cmp_reset_secret_old = 0;

    /* Check first whether this could be a reset packet */
    if (length > PICOQUIC_RESET_SECRET_SIZE + 10)
    {
        cmp_reset_secret = (memcmp(bytes + length - PICOQUIC_RESET_SECRET_SIZE,
            cnx->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0);

        if (cmp_reset_secret == 0)
        {
            cmp_reset_secret = (memcmp(bytes + 9, cnx->reset_secret,
                PICOQUIC_RESET_SECRET_SIZE) == 0);
            cmp_reset_secret_old = cmp_reset_secret;
        }
    }

    if (cmp_reset_secret != 0)
    {
        fprintf(F, "    Stateless reset packet%s, %d bytes\n", 
            (cmp_reset_secret_old == 0)?"":" (old format)",
            (int)length);
    }
    else
    {
        if (receiving)
        {
            decrypted_length = picoquic_aead_decrypt(cnx, decrypted,
                bytes + ph->offset, length - ph->offset, ph->pn64, bytes, ph->offset);
        }
        else
        {
            decrypted_length = picoquic_aead_de_encrypt(cnx, decrypted,
                bytes + ph->offset, length - ph->offset, ph->pn64, bytes, ph->offset);
        }

        if (decrypted_length > length)
        {
            fprintf(F, "    Decryption failed!\n");
        }
        else
        {
            fprintf(F, "    Decrypted %d bytes\n", (int)decrypted_length);
            picoquic_log_frames(F, decrypted, decrypted_length);
        }
    }
}

void picoquic_log_decrypt_0rtt(FILE* F,
    picoquic_cnx_t * cnx, uint8_t * bytes, size_t length, picoquic_packet_header * ph)
{
    /* decrypt in a separate copy */
    uint8_t decrypted[PICOQUIC_MAX_PACKET_SIZE];
    size_t decrypted_length = 0;

    decrypted_length = picoquic_aead_0rtt_decrypt(cnx, decrypted,
        bytes + ph->offset, length - ph->offset, ph->pn64, bytes, ph->offset);

    if (decrypted_length > length)
    {
        fprintf(F, "    Decryption failed!\n");
    }
    else
    {
        fprintf(F, "    Decrypted %d bytes\n", (int)decrypted_length);
        picoquic_log_frames(F, decrypted, decrypted_length);
    }
}

void picoquic_log_decrypt_encrypted_cleartext(FILE* F,
    picoquic_cnx_t * cnx, int receiving,
    uint8_t * bytes, size_t length, picoquic_packet_header * ph)
{
    /* decrypt in a separate copy */
    uint8_t decrypted[PICOQUIC_MAX_PACKET_SIZE];
    size_t decrypted_length = 0;

    if (receiving)
    {
        decrypted_length = picoquic_aead_cleartext_decrypt(cnx, decrypted,
            bytes + ph->offset, length - ph->offset, ph->pn64, bytes, ph->offset);
    }
    else
    {
        decrypted_length = picoquic_aead_cleartext_de_encrypt(cnx, decrypted,
            bytes + ph->offset, length - ph->offset, ph->pn64, bytes, ph->offset);
    }

    if (decrypted_length > length)
    {
        fprintf(F, "    Decryption failed!\n");
    }
    else
    {
        fprintf(F, "    Decrypted %d bytes\n", (int)decrypted_length);
        picoquic_log_frames(F, decrypted, decrypted_length);
    }
}


void picoquic_log_packet(FILE* F, picoquic_quic_t * quic, picoquic_cnx_t * cnx, 
	struct sockaddr * addr_peer, int receiving,
	uint8_t * bytes,  size_t length, uint64_t current_time)
{
	int ret = 0;
	picoquic_packet_header ph;
    picoquic_cnx_t * pcnx = cnx;

	/* first log line */
	picoquic_log_packet_address(F, cnx, addr_peer, receiving, length, current_time);

	/* Parse the clear text header */
    ret = picoquic_parse_packet_header(quic, bytes, (uint32_t)length, NULL,
        ((cnx->quic->flags&picoquic_context_server) == 0) ? 
        ((receiving == 0)?1:0): ((receiving == 0) ? 0 : 1), &ph, &pcnx);

	if (ret != 0)
	{
		/* packet does not even parse */
		fprintf(F, "   Cannot parse the packet header.\n");
	}
	else 
	{
        if (cnx == NULL)
        {
            cnx = picoquic_cnx_by_net(quic, addr_peer);
        }

		if (cnx == NULL && ph.cnx_id != 0)
		{
			cnx = picoquic_cnx_by_id(quic, ph.cnx_id);
		}

		if (cnx != NULL)
		{
			ph.pn64 = picoquic_get_packet_number64(
                (receiving == 0)?cnx->send_sequence:cnx->first_sack_item.end_of_sack_range, 
                ph.pnmask, ph.pn);
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
            if (cnx != NULL)
            {
                picoquic_log_decrypt_encrypted_cleartext(F, cnx, receiving, bytes, length, &ph);
            }
			break;
		case picoquic_packet_0rtt_protected:
			/* log 0-rtt packet */
            picoquic_log_decrypt_0rtt(F, cnx, bytes, length, &ph);
			break;
		case picoquic_packet_1rtt_protected_phi0:
		case picoquic_packet_1rtt_protected_phi1:
            picoquic_log_decrypt_encrypted(F, cnx, receiving, bytes, length, &ph);
			break;
		default:
			/* Packet type error. Log and ignore */
			break;
		}
	}
	fprintf(F, "\n");
}

void picoquic_log_processing(FILE* F, picoquic_cnx_t * cnx, size_t length, int ret)
{
	fprintf(F, "Processed %d bytes, state = %d (%s), return %d\n\n",
		(int) length, cnx->cnx_state,
		(((size_t)cnx->cnx_state) < picoquic_nb_log_state_name) ?
		picoquic_log_state_name[(size_t)cnx->cnx_state] : "unknown",
		ret);
}

void picoquic_log_transport_extension(FILE* F, picoquic_cnx_t * cnx, int log_cnxid)
{
	uint8_t * bytes = NULL;
	size_t bytes_max = 0;
	int ext_received_return = 0;
	int client_mode = 1;
	int ret = 0;
	size_t byte_index = 0;
	char const * sni = picoquic_tls_get_sni(cnx);
	char const * alpn = picoquic_tls_get_negotiated_alpn(cnx);

    if (log_cnxid != 0)
    {
        printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
    }
	if (sni == NULL)
	{
		fprintf(F, "SNI not received.\n");
	}
	else
	{
		fprintf(F, "Received SNI: %s\n", sni);
	}


    if (log_cnxid != 0)
    {
        printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
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
        if (log_cnxid != 0)
        {
            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
        }
		fprintf(F, "Did not receive transport parameter TLS extension.\n");
	}
	else if (bytes_max < 128)
	{
        if (log_cnxid != 0)
        {
            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
        }
		fprintf(F, "Received transport parameter TLS extension (%d bytes):\n", (uint32_t)bytes_max);
		switch (client_mode)
		{
		case 0: // Client hello
            if (bytes_max < 4)
            {
                if (log_cnxid != 0)
                {
                    printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                }
				fprintf(F, "Malformed extension\n");
				ret = -1;
			}
            else
            {
                uint32_t proposed_version;
                proposed_version = PICOPARSE_32(bytes + byte_index);
                byte_index += 4;
                if (log_cnxid != 0)
                {
                    printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                }
                fprintf(F, "Proposed version: %08x\n", proposed_version);
            }
			break;
		case 1: // Server encrypted extension
		{
			if (bytes_max < 1)
			{
                if (log_cnxid != 0)
                {
                    printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                }
				fprintf(F, "Malformed extension\n");
				ret = -1;
			}
			else
			{
                if (log_cnxid != 0)
                {
                    printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                }
                if (bytes_max < byte_index + 4)
                {
                    fprintf(F, "Malformed extension\n");
                    ret = -1;
                }
                else
                {
                    uint32_t version;

                    version = PICOPARSE_32(bytes + byte_index);
                    byte_index += 4;

                    fprintf(F, "Version: %08x\n", version);
                }

                if (ret == 0)
                {
                    size_t supported_versions_size = bytes[byte_index++];

                    if ((supported_versions_size & 3) != 0)
                    {
                        if (log_cnxid != 0)
                        {
                            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                        }
                        fprintf(F,
                            "Malformed extension, supported version size = %d, not multiple of 4.\n",
                            (uint32_t)supported_versions_size);
                        ret = -1;

                    }
                    else if (supported_versions_size > 252 ||
                        byte_index + supported_versions_size > bytes_max)
                    {
                        if (log_cnxid != 0)
                        {
                            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                        }
                        fprintf(F, "    Malformed extension, supported version size = %d, max %d or 252\n",
                            (uint32_t)supported_versions_size, (uint32_t)(bytes_max - byte_index));
                        ret = -1;
                    }
                    else
                    {
                        size_t nb_supported_versions = supported_versions_size / 4;

                        if (log_cnxid != 0)
                        {
                            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                        }
                        fprintf(F, "    Supported version (%d bytes):\n", (int)supported_versions_size);

                        for (size_t i = 0; i < nb_supported_versions; i++)
                        {
                            uint32_t supported_version = PICOPARSE_32(bytes + byte_index);

                            byte_index += 4;
                            if (log_cnxid != 0)
                            {
                                printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                            }
                            if (supported_version == cnx->proposed_version &&
                                cnx->proposed_version !=
                                picoquic_supported_versions[cnx->version_index].version)
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
			}
			break;
		}
		default: // New session ticket
			break;
		}

		if (ret == 0 && byte_index + 2 > bytes_max)
		{
            if (log_cnxid != 0)
            {
                printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
            }
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
                if (log_cnxid != 0)
                {
                    printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                }
				fprintf(F, "    Extension list too long (%d bytes vs %d)\n",
					(uint32_t)extensions_size, (uint32_t)(bytes_max - byte_index));
			}
			else
			{
                if (log_cnxid != 0)
                {
                    printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                }
				fprintf(F, "    Extension list (%d bytes):\n",
					(uint32_t)extensions_size);
				while (ret == 0 && byte_index < extensions_end)
				{
					if (byte_index + 6 > extensions_end)
					{
                        if (log_cnxid != 0)
                        {
                            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                        }
						fprintf(F, "        Malformed extension.\n");
						ret = -1;
					}
					else
					{
						uint16_t extension_type = PICOPARSE_16(bytes + byte_index);
						uint16_t extension_length = PICOPARSE_16(bytes + byte_index + 2);
						byte_index += 4;

                        if (log_cnxid != 0)
                        {
                            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                        }
						fprintf(F, "        Extension type: %d, length %d (0x%04x / 0x%04x), ",
							extension_type, extension_length, extension_type, extension_length);

                        if (log_cnxid != 0)
                        {
                            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
                        }
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
            if (log_cnxid != 0)
            {
                printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
            }
			fprintf(F, "    Remaining bytes (%d)\n", (uint32_t)(bytes_max - byte_index));
		}
	}
	else
	{
        if (log_cnxid != 0)
        {
            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
        }
		fprintf(F, "Received transport parameter TLS extension (%d bytes):\n", (uint32_t)bytes_max);
        if (log_cnxid != 0)
        {
            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
        }
		fprintf(F, "    First 128 received bytes (%d):\n", (uint32_t)(bytes_max - byte_index));
	}

	while (byte_index < bytes_max && byte_index < 128)
	{
        if (log_cnxid != 0)
        {
            printf("%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
        }
		fprintf(F, "        ");
		for (int i = 0; i < 32 && byte_index < bytes_max && byte_index < 128; i++)
		{
			fprintf(F, "%02x", bytes[byte_index++]);
		}
		fprintf(F, "\n");
	}
    if (log_cnxid == 0)
    {
        fprintf(F, "\n");
    }
}

void picoquic_log_congestion_state(FILE* F, picoquic_cnx_t * cnx, uint64_t current_time)
{
    fprintf(F, "%" PRIx64 ": ", picoquic_get_initial_cnxid(cnx));
    picoquic_log_time(F, cnx, current_time, "T= ", ", ");
    fprintf(F, "cwin: %d,", (int)cnx->cwin);
    fprintf(F, "flight: %d,", (int)cnx->bytes_in_transit);;
    fprintf(F, "nb_ret: %d,", (int)cnx->nb_retransmission_total);
    fprintf(F, "rtt_min: %d,", (int)cnx->rtt_min);
    fprintf(F, "rtt: %d,", (int)cnx->smoothed_rtt);
    fprintf(F, "rtt_var: %d,", (int)cnx->rtt_variant);
    fprintf(F, "max_ack_delay: %d,", (int)cnx->max_ack_delay);
    fprintf(F, "state: %d\n", (int)cnx->cnx_state);
}

/*
    From TLS 1.3 spec:
   struct {
       uint32 ticket_lifetime;
       uint32 ticket_age_add;
       opaque ticket_nonce<0..255>;
       opaque ticket<1..2^16-1>;
       Extension extensions<0..2^16-2>;
   } NewSessionTicket;

   struct {
       ExtensionType extension_type;
       opaque extension_data<0..2^16-1>;
   } Extension;
*/
void picoquic_log_tls_ticket(FILE* F, uint64_t cnx_id,
    uint8_t * ticket, uint16_t ticket_length)
{
    uint32_t lifetime = 0;
    uint32_t age_add = 0;
    uint8_t nonce_length = 0;
    uint8_t * nonce_ptr = NULL;
    uint16_t ticket_val_length = 0;
    uint8_t * ticket_val_ptr = NULL;
    uint16_t extension_length = 0;
    uint8_t * extension_ptr = NULL;
    uint16_t byte_index = 0;
    uint16_t min_length = 4 + 4 + 1 + 2 + 2;
    int ret = 0;

    if (ticket_length < min_length)
    {
        ret = -1;
    }
    else
    {
        lifetime = PICOPARSE_32(ticket);
        byte_index += 4;
        age_add = PICOPARSE_32(ticket + byte_index);
        byte_index += 4;
        nonce_length = ticket[byte_index++];
        min_length += nonce_length;
        if (ticket_length < min_length)
        {
            ret = -1;
        }
        else
        {
            nonce_ptr = &ticket[byte_index];
            byte_index += nonce_length;

            ticket_val_length = PICOPARSE_16(ticket + byte_index);
            byte_index += 2;
            min_length += ticket_val_length;
            if (ticket_length < min_length)
            {
                ret = -1;
            }
            else
            {
                ticket_val_ptr = &ticket[byte_index];
                byte_index += ticket_val_length;

                extension_length = PICOPARSE_16(ticket + byte_index);
                byte_index += 2;
                min_length += extension_length;
                if (ticket_length < min_length)
                {
                    ret = -1;
                }
                else
                {
                    extension_ptr = &ticket[byte_index];
                    if (min_length > ticket_length)
                    {
                        ret = -2;
                    }
                }
            }
        }
    }

    if (ret == -1)
    {
        fprintf(F, "%llu: Malformed ticket, length = %d, at least %d required.\n",
            (unsigned long long)cnx_id, ticket_length, min_length);
    }
    fprintf(F, "%llu: lifetime = %d, age_add = %x, %d nonce, %d ticket, %d extensions.\n",
        (unsigned long long)cnx_id, lifetime, age_add, nonce_length, ticket_val_length, extension_length);

    if (extension_ptr != NULL)
    {
        uint16_t x_index = 0;

        fprintf(F, "%llu: ticket extensions: ", (unsigned long long)cnx_id);

        while (x_index + 4 < extension_length)
        {
            uint16_t x_type = PICOPARSE_16(extension_ptr + x_index);
            uint16_t x_len = PICOPARSE_16(extension_ptr + x_index + 2);
            x_index += 4 + x_len;

            if (x_type == 42 && x_len == 4)
            {
                uint32_t ed_len = PICOPARSE_32(extension_ptr + x_index - 4);
                fprintf(F, "%d(ED: %x),", x_type, ed_len);
            }
            else
            {
                fprintf(F, "%d (%d bytes),", x_type, x_len);
            }

            if (x_index > extension_length)
            {
                fprintf(F, "\n%llu: malformed extensions, require %d bytes, not just %d",
                    (unsigned long long)cnx_id, x_index, extension_length);
            }
        }

        fprintf(F, "\n");

        if (x_index < extension_length)
        {
            fprintf(F, "\n%llu: %d extra bytes at the end of the extensions\n",
                (unsigned long long)cnx_id, extension_length - x_index);
        }
    }

    if (ret == -2)
    {
        fprintf(F, "%llu: Malformed TLS ticket, %d extra bytes.\n",
            (unsigned long long)cnx_id, ticket_length - min_length);
    }

}

/*

From Picotls code:
uint64_t time;
uint16_t cipher_suite;
24 bit int = length of ticket;
<TLS ticket>
16 bit length
<resumption secret>

 */

void picoquic_log_picotls_ticket(FILE* F, uint64_t cnx_id,
    uint8_t * ticket, uint16_t ticket_length)
{
    uint64_t ticket_time = 0;
    uint16_t suite_id = 0;
    uint32_t tls_ticket_length = 0;
    uint8_t * tls_ticket_ptr = NULL;
    uint16_t secret_length = 0;
    uint8_t * secret_ptr = NULL;
    uint16_t byte_index = 0;
    uint32_t min_length = 8 + 2 + 3 + 2;
    int ret = 0;

    if (ticket_length < min_length)
    {
        ret = -1;
    }
    else
    {
        ticket_time = PICOPARSE_64(ticket);
        byte_index += 8;
        suite_id = PICOPARSE_16(ticket + byte_index);
        byte_index += 2;
        tls_ticket_length = PICOPARSE_24(ticket + byte_index);
        byte_index += 3;
        min_length += tls_ticket_length;
        if (ticket_length < min_length)
        {
            ret = -1;
        }
        else
        {
            tls_ticket_ptr = &ticket[byte_index];
            byte_index += tls_ticket_length;

            secret_length = PICOPARSE_16(ticket + byte_index);
            byte_index += 2;
            min_length += secret_length;
            if (ticket_length < min_length)
            {
                ret = -1;
            }
            else
            {
                secret_ptr = &ticket[byte_index];
                byte_index += secret_length;
                
                if (min_length > ticket_length)
                {
                    ret = -2;
                }
            }
        }
    }

    fprintf(F, "%llu: ticket time = %llu, suite = %x, %d ticket, %d secret.\n",
        (unsigned long long)cnx_id, (unsigned long long)ticket_time,
        suite_id, tls_ticket_length, secret_length);

    if (ret == -1)
    {
        fprintf(F, "%llu: Malformed PTLS ticket, length = %d, at least %d required.\n",
            (unsigned long long)cnx_id, ticket_length, min_length);
    }
    else
    {
        if (tls_ticket_length > 0 && tls_ticket_ptr != NULL)
        {
            picoquic_log_tls_ticket(F, cnx_id, tls_ticket_ptr, tls_ticket_length);
        }
    }

    if (ret == -2)
    {
        fprintf(F, "%llu: Malformed PTLS ticket, %d extra bytes.\n",
            (unsigned long long)cnx_id, ticket_length - min_length);
    }
}