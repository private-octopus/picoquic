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
    "client_ready",
    "server_almost_ready",
    "server_ready",
    "disconnecting",
    "closing_received",
    "closing",
    "draining",
    "disconnected"
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

	debug_printf_push_stream(F);

	int ret = picoquic_parse_stream_header(bytes, bytes_max, &stream_id, &offset, &data_length, &fin, &byte_index);

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

size_t picoquic_log_ack_frame(FILE * F, uint8_t * bytes, size_t bytes_max, 
    uint32_t version_flags)
{
	size_t   byte_index;
	uint64_t num_block;
	unsigned num_ts;
	unsigned mm;
	uint64_t largest;
	uint64_t ack_delay;

	debug_printf_push_stream(F);

	int ret = picoquic_parse_ack_header(bytes, bytes_max, 0,
        &num_block, &num_ts, &largest, &ack_delay, &mm, &byte_index,
        version_flags, 0);

	debug_printf_pop_stream();

	if (ret != 0)
		return bytes_max;

	/* Now that the size is good, print it */
	fprintf(F, "    ACK (nb=%u, nt=%u)", (int)num_block, (int)num_ts);

	/* decoding the acks */
	unsigned extra_ack = 1;

	while(ret == 0)
	{
		uint64_t range;
        uint64_t block_to_block;

        if (byte_index >= bytes_max)
        {
            fprintf(F, "    Malformed ACK RANGE, %d blocks remain.\n", (int) num_block);
            ret = -1;
            break;
        }

        if ((version_flags&picoquic_version_fix_ints) == 0)
        {
            size_t l_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &range);
            if (l_range == 0)
            {
                byte_index = bytes_max;
                ret = -1;
                fprintf(F, "    Malformed ACK RANGE, requires %d bytes out of %d\n", (int)picoquic_varint_skip(bytes),
                    (int)(bytes_max - byte_index));
                break;
            }
            else
            {
                byte_index += l_range;
            }
        }
        else
        {
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
                /* not reachable */
                range = 0;
                break;
            }
        }
		range += extra_ack;
		if (largest + 1 < range)
		{
			fprintf(F, "ack range error: largest=%" PRIx64 ", range=%" PRIx64 "\n", largest, range);
			return bytes_max;
		}

		if (range > 1)
			fprintf(F, ", %" PRIx64 "-%" PRIx64, largest - (range-1), largest);
		else if (range == 1)
			fprintf(F, ", %" PRIx64, largest);
		else
			fprintf(F, ", _");

		if (num_block-- == 0)
			break;

		/* Skip the gap */

        if (byte_index >= bytes_max)
        {
            fprintf(F, "    Malformed ACK GAP, %d blocks remain.\n", (int)num_block);
            ret = -1;
            break;
        }
        else
        {
            if ((version_flags&picoquic_version_fix_ints) == 0)
            {
                size_t l_gap = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &block_to_block);
                if (l_gap == 0)
                {
                    byte_index = bytes_max;
                    ret = -1;
                    fprintf(F, "    Malformed ACK GAP, requires %d bytes out of %d\n", (int)picoquic_varint_skip(bytes),
                        (int)(bytes_max - byte_index));
                    break;
                }
                else
                {
                    byte_index += l_gap;
                    block_to_block += range;
                }
            }
            else
            {
                block_to_block = range + bytes[byte_index++];
            }
        }

		if (largest < block_to_block)
		{
			fprintf(F, "ack gap error: largest=%" PRIx64 ", range=%" PRIx64 ", gap=%" PRIu64 "\n",
					largest, range, block_to_block-range);
			return bytes_max;
		}

		largest -= block_to_block;
		extra_ack = 0;
	}

	if (num_ts > 0)
	{
		byte_index += 2 + num_ts * 3;
	}

	fprintf(F, "\n");

	return byte_index;
}

size_t picoquic_log_reset_stream_frame(FILE * F, uint8_t * bytes, size_t bytes_max,
    uint32_t version_flags)
{
	size_t byte_index = 1;
	uint64_t stream_id;
	uint32_t error_code;
	uint64_t offset;


    if ((version_flags&picoquic_version_fix_ints) == 0)
    {
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
                ((l1==0)?(picoquic_varint_skip(bytes+1) + 3):picoquic_varint_skip(bytes + byte_index))),
                (int)bytes_max);
            byte_index = bytes_max;
        }
        else
        {
            fprintf(F, "    RESET STREAM %llu, Error 0x%08x, Offset 0x%llx.\n",
                (unsigned long long)stream_id, error_code, (unsigned long long) offset);
        }
    }
    else
    {
        const size_t min_size = ((version_flags&picoquic_version_long_error_codes) != 0) ?
            1 + 4 + 4 + 8 : 1 + 4 + 2 + 8;

        if (min_size > bytes_max)
        {
            fprintf(F, "    Malformed RESET STREAM, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
            return bytes_max;
        }

        /* Now that the size is good, parse and print it */
        stream_id = PICOPARSE_32(bytes + byte_index);
        byte_index += 4;
        if ((version_flags&picoquic_version_long_error_codes) != 0)
        {
            error_code = PICOPARSE_32(bytes + byte_index);
            byte_index += 4;
        }
        else
        {
            error_code = PICOPARSE_16(bytes + byte_index);
            byte_index += 2;
        }
        offset = PICOPARSE_64(bytes + byte_index);
        byte_index += 8;


        fprintf(F, "    RESET STREAM %llu, Error 0x%08x, Offset 0x%llx.\n",
            (unsigned long long)stream_id, error_code, (unsigned long long) offset);
    }
	return byte_index;
}

size_t picoquic_log_stop_sending_frame(FILE * F, uint8_t * bytes, size_t bytes_max,
    uint32_t version_flags)
{
    size_t byte_index = 1;
    const size_t min_size = ((version_flags&picoquic_version_fix_ints) == 0)?
        (1 + picoquic_varint_skip(bytes+1) + 2)
        :(((version_flags&picoquic_version_long_error_codes) != 0) ?
        1 + 4 + 4 : 1 + 4 + 2);
    uint64_t stream_id;
    uint32_t error_code;

    if (min_size > bytes_max)
    {
        fprintf(F, "    Malformed STOP SENDING, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
        return bytes_max;
    }

    /* Now that the size is good, parse and print it */
    if ((version_flags&picoquic_version_fix_ints) == 0)
    {
        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &stream_id);
        error_code = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
    }
    else
    {
        stream_id = PICOPARSE_32(bytes + byte_index);
        byte_index += 4;
        if ((version_flags&picoquic_version_long_error_codes) != 0)
        {
            error_code = PICOPARSE_32(bytes + byte_index);
            byte_index += 4;
        }
        else
        {
            error_code = PICOPARSE_16(bytes + byte_index);
            byte_index += 2;
        }
    }

    fprintf(F, "    STOP SENDING %d (0x%08x), Error 0x%x.\n",
        (uint32_t) stream_id, (uint32_t) stream_id, error_code);

    return byte_index;
}

size_t picoquic_log_connection_close_frame(FILE * F, uint8_t * bytes,
    size_t bytes_max, uint32_t version_flags)
{
    size_t byte_index = 1;
    uint32_t error_code;
    uint64_t string_length;


    if ((version_flags&picoquic_version_fix_ints) == 0)
    {
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
    }
    else
    {
        size_t min_size = ((version_flags&picoquic_version_long_error_codes) != 0) ? 7 : 5;

        if (min_size > bytes_max)
        {
            fprintf(F, "    Malformed CONNECTION CLOSE, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
            return bytes_max;
        }

        /* Now that the size is above the minimum */
        if ((version_flags&picoquic_version_long_error_codes) != 0)
        {
            error_code = PICOPARSE_32(bytes + byte_index);
            byte_index += 4;
        }
        else
        {
            error_code = PICOPARSE_16(bytes + byte_index);
            byte_index += 2;
        }

        string_length = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
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
		byte_index += (size_t) string_length;
	}

	return byte_index;
}

size_t picoquic_log_application_close_frame(FILE * F, uint8_t * bytes, size_t bytes_max, 
    uint32_t version_flags)
{
    size_t byte_index = 1;
    uint32_t error_code;
    uint64_t string_length;

    if ((version_flags&picoquic_version_fix_ints) == 0)
    {
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
                (int)(byte_index + picoquic_varint_skip(bytes+3)), (int)bytes_max);
            return bytes_max;
        }
        else
        {
            byte_index += l1;
        }
    }
    else
    {
        size_t min_size = ((version_flags&picoquic_version_long_error_codes) != 0) ? 7 : 5;

        if (min_size > bytes_max)
        {
            fprintf(F, "    Malformed APPLICATION CLOSE, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
            return bytes_max;
        }

        /* Now that the size is above the minimum */
        if ((version_flags&picoquic_version_long_error_codes) != 0)
        {
            error_code = PICOPARSE_32(bytes + byte_index);
            byte_index += 4;
        }
        else
        {
            error_code = PICOPARSE_16(bytes + byte_index);
            byte_index += 2;
        }

        string_length = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
    }

    fprintf(F, "    APPLICATION CLOSE, Error 0x%04x, Reason length %d (0x%04x):\n",
        error_code, (uint16_t) string_length, (uint16_t) string_length);
    if (byte_index + string_length > bytes_max)
    {
        fprintf(F, "    Malformed APPLICATION CLOSE, requires %d bytes out of %d\n",
            (int)(byte_index + string_length), (int)bytes_max);
        byte_index = bytes_max;
    }
    else
    {
        /* TODO: print the UTF8 string */
        byte_index += (size_t) string_length;
    }

    return byte_index;
}

size_t picoquic_log_max_data_frame(FILE * F, uint8_t * bytes, size_t bytes_max, uint32_t version_flags)
{
	size_t byte_index = 1;
	uint64_t max_data;
    const size_t min_size = 1 + 8;

    if ((version_flags&picoquic_version_fix_ints) == 0)
    {
        size_t l1 = picoquic_varint_decode(bytes + 1, bytes_max - 1, &max_data);

        if (min_size > bytes_max)
        {
            fprintf(F, "    Malformed MAX DATA, requires %d bytes out of %d\n", (int)(1+l1), (int)bytes_max);
            return bytes_max;
        }
        else
        {
            byte_index = 1+l1;
        }
    }
    else
    {
        if (min_size > bytes_max)
        {
            fprintf(F, "    Malformed MAX DATA, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
            return bytes_max;
        }

        /* Now that the size is good, parse and print it */
        max_data = PICOPARSE_64(bytes + byte_index);
        byte_index += 8;
    }

	fprintf(F, "    MAX DATA: 0x%llx.\n", (unsigned long long) max_data);

	return byte_index;
}

size_t picoquic_log_max_stream_data_frame(FILE * F, uint8_t * bytes, size_t bytes_max, uint32_t version_flags)
{
	size_t byte_index = 1;
	const size_t min_size = 1 + 4 + 8;
	uint64_t stream_id;
	uint64_t max_data;

    if ((version_flags&picoquic_version_fix_ints) == 0)
    {
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
    }
    else
    {
        if (min_size > bytes_max)
        {
            fprintf(F, "    Malformed MAX STREAM DATA, requires %d bytes out of %d\n", (int)min_size, (int)bytes_max);
            return bytes_max;
        }

        /* Now that the size is good, parse and print it */
        stream_id = PICOPARSE_32(bytes + byte_index);
        byte_index += 4;
        max_data = PICOPARSE_64(bytes + byte_index);
        byte_index += 8;
    }

	fprintf(F, "    MAX STREAM DATA, Stream: %" PRIu64 ", max data: 0x%llx.\n", 
		stream_id,(unsigned long long) max_data);

	return byte_index;
}

size_t picoquic_log_max_stream_id_frame(FILE * F, uint8_t * bytes, size_t bytes_max, uint32_t version_flags)
{
	size_t byte_index = 1;
	const size_t min_size = ((version_flags&picoquic_version_fix_ints)==0)?
        1 + picoquic_varint_skip(bytes+1):
        1 + 4;
	uint64_t max_stream_id;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed MAX STREAM ID, requires %d bytes out of %d\n", (int) min_size, (int) bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
    if ((version_flags&picoquic_version_fix_ints) == 0)
    {
        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &max_stream_id);
    }
    else
    {
        max_stream_id = PICOPARSE_32(bytes + byte_index);
        byte_index += 4;
    }

	fprintf(F, "    MAX STREAM ID: %" PRIu64 ".\n", max_stream_id);

	return byte_index;
}

size_t picoquic_log_stream_blocked_frame(FILE * F, uint8_t * bytes, size_t bytes_max, uint32_t version_flags)
{
	size_t byte_index = 1;
	const size_t min_size = ((version_flags&picoquic_version_fix_ints) == 0)?
        1 + picoquic_varint_skip(bytes+1):
        1 + 4;
	uint64_t blocked_stream_id;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed STREAM BLOCKED, requires %d bytes out of %d\n", (int) min_size, (int) bytes_max);
		return bytes_max;
	}

	/* Now that the size is good, parse and print it */
    if ((version_flags&picoquic_version_fix_ints) == 0)
    {
        byte_index += picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &blocked_stream_id);
    }
    else
    {
        blocked_stream_id = PICOPARSE_32(bytes + byte_index);
        byte_index += 4;
    }

	fprintf(F, "    STREAM BLOCKED: %" PRIu64 ".\n",
		blocked_stream_id);

	return byte_index;
}

size_t picoquic_log_new_connection_id_frame(FILE * F, uint8_t * bytes, size_t bytes_max)
{
	size_t byte_index = 1;
	const size_t min_size = 1 + 8 + 16;
	uint64_t new_cnx_id;

	if (min_size > bytes_max)
	{
		fprintf(F, "    Malformed NEW CONNECTION ID, requires %d bytes out of %d\n", (int) min_size, (int) bytes_max);
		return bytes_max;
	}

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

size_t picoquic_log_ping_pong_frame(FILE * F, uint8_t * bytes, size_t bytes_max, uint32_t version_flags)
{
    size_t byte_index = 1;

    if ((version_flags&picoquic_version_short_pings) != 0)
    {
        if (bytes[0] == picoquic_frame_type_ping)
        {
            /* No payload in old versions */
            fprintf(F, "    %s frame\n", picoquic_log_frame_names[bytes[0]]);
        }
        else
        {
            fprintf(F, "    Unexpected PONG frame.\n");
            byte_index = bytes_max;
        }
    }
    else
    {
        size_t ping_length = bytes[byte_index++];

        if (byte_index + ping_length > bytes_max)
        {
            fprintf(F, "    Malformed %s frame, length %d, %d bytes needed, %d available\n",
                picoquic_log_frame_names[bytes[0]], (int) ping_length,
                (int)(ping_length + 2), (int) bytes_max);
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
            fprintf(F, "    %s length %d: ", picoquic_log_frame_names[bytes[0]], (int) ping_length);

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
    }

    return byte_index;
}

void picoquic_log_frames(FILE* F, uint8_t * bytes, size_t length, uint32_t version_flags)
{
	size_t byte_index = 0;

    while (byte_index < length)
    {
        int ack_or_data = 0;

        if ((version_flags&picoquic_version_fix_ints) == 0)
        {
            if (bytes[byte_index] >= picoquic_frame_type_stream_range_min &&
                bytes[byte_index] <= picoquic_frame_type_stream_range_max)
            {
                ack_or_data = 1;
                byte_index += picoquic_log_stream_frame(F, bytes + byte_index, length - byte_index);
            }
            else if (bytes[byte_index] == picoquic_frame_type_ack)
            {
                ack_or_data = 1;
                byte_index += picoquic_log_ack_frame(F, bytes + byte_index, length - byte_index, version_flags);
            }
        }
        else
        {
            if (bytes[byte_index] >= 0xC0)
            {
                ack_or_data = 1;
                byte_index += picoquic_log_stream_frame(F, bytes + byte_index, length - byte_index);
            }
            else if (bytes[byte_index] > 0xA0)
            {
                ack_or_data = 1;
                byte_index += picoquic_log_ack_frame(F, bytes + byte_index, length - byte_index,
                    version_flags);
            }
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
                        length - byte_index, version_flags);
                    break;
                case picoquic_frame_type_connection_close: /* CONNECTION_CLOSE */
                    byte_index += picoquic_log_connection_close_frame(F, bytes + byte_index,
                        length - byte_index, version_flags);
                    break;
                case picoquic_frame_type_application_close:
                    byte_index += picoquic_log_application_close_frame(F, bytes + byte_index,
                        length - byte_index, version_flags);
                    break;
                case picoquic_frame_type_max_data: /* MAX_DATA */
                    byte_index += picoquic_log_max_data_frame(F, bytes + byte_index,
                        length - byte_index, version_flags);
                    break;
                case picoquic_frame_type_max_stream_data: /* MAX_STREAM_DATA */
                    byte_index += picoquic_log_max_stream_data_frame(F, bytes + byte_index,
                        length - byte_index, version_flags);
                    break;
                case picoquic_frame_type_max_stream_id: /* MAX_STREAM_ID */
                    byte_index += picoquic_log_max_stream_id_frame(F, bytes + byte_index,
                        length - byte_index, version_flags);
                    break;
                case picoquic_frame_type_ping:
                    byte_index += picoquic_log_ping_pong_frame(F, bytes + byte_index,
                        length - byte_index, version_flags);
                    break;
                case picoquic_frame_type_blocked: /* BLOCKED */
                    /* No payload */
                    byte_index++;
                    break;
                case picoquic_frame_type_stream_blocked: /* STREAM_BLOCKED */
                    byte_index += picoquic_log_stream_blocked_frame(F, bytes + byte_index,
                        length - byte_index, version_flags);
                    break;
                case picoquic_frame_type_stream_id_needed: /* STREAM_ID_NEEDED */
                    /* No payload */
                    fprintf(F, "    %s frame\n", picoquic_log_frame_names[frame_id]);
                    byte_index++;
                    break;
                case picoquic_frame_type_new_connection_id: /* NEW_CONNECTION_ID */
                    byte_index += picoquic_log_new_connection_id_frame(F, bytes + byte_index,
                        length - byte_index);
                    break;
                case picoquic_frame_type_stop_sending: /* STOP_SENDING */
                    byte_index += picoquic_log_stop_sending_frame(F, bytes + byte_index,
                        length - byte_index, version_flags);
                    break;
                case picoquic_frame_type_pong: /* PONG */
                    byte_index += picoquic_log_ping_pong_frame(F, bytes + byte_index,
                        length - byte_index, version_flags);
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
	picoquic_cnx_t * cnx, int receiving,
	uint8_t * bytes, size_t length, picoquic_packet_header * ph)
{
	/* decrypt in a separate copy */
	uint8_t decrypted[PICOQUIC_MAX_PACKET_SIZE];
    size_t decrypted_length = 0;
    
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
		fprintf(F, "    Decrypted %d bytes\n", (int) decrypted_length);
		picoquic_log_frames(F, decrypted, decrypted_length,
            picoquic_supported_versions[cnx->version_index].version_flags);
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
        picoquic_log_frames(F, decrypted, decrypted_length,
            picoquic_supported_versions[cnx->version_index].version_flags);
    }
}


void picoquic_log_packet(FILE* F, picoquic_quic_t * quic, picoquic_cnx_t * cnx, 
	struct sockaddr * addr_peer, int receiving,
	uint8_t * bytes,  size_t length, uint64_t current_time)
{
	int ret = 0;
	picoquic_packet_header ph;
	size_t decoded_length = 0;
    picoquic_cnx_t * pcnx = cnx;

	/* first log line */
	picoquic_log_packet_address(F, cnx, addr_peer, receiving, length, current_time);

	/* Parse the clear text header */
    ret = picoquic_parse_packet_header(quic, bytes, length, NULL,
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
                if ((picoquic_supported_versions[cnx->version_index].version_flags&
                    picoquic_version_use_fnv1a) != 0)
                {
                    decoded_length = picoquic_log_decrypt_clear_text(F, bytes, length);

                    /* log clear text packet */
                    if (decoded_length > 0)
                    {
                        /* log the frames */
                        picoquic_log_frames(F, bytes + ph.offset, decoded_length - ph.offset,
                            picoquic_supported_versions[cnx->version_index].version_flags);
                    }
                }
                else
                {
                    picoquic_log_decrypt_encrypted_cleartext(F, cnx, receiving, bytes, length, &ph);
                }
            }
			break;
		case picoquic_packet_0rtt_protected:
			/* log 0-rtt packet */
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
					fprintf(F, "    Supported version (%d bytes):\n", (int) supported_versions_size);

					for (size_t i = 0; i < nb_supported_versions; i++)
					{
						uint32_t supported_version = PICOPARSE_32(bytes + byte_index);

						byte_index += 4;
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
