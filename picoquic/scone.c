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
#include "picoquic_unified_log.h"
#include <stdlib.h>
#include <string.h>

uint8_t* picoquic_scone_format_packet(uint8_t* bytes, const uint8_t* bytes_max, unsigned int signal,
    size_t dcid_length, uint8_t* dcid_id, size_t scid_length, uint8_t* scid_id)
{
    if (bytes + 6  + dcid_length  + 1 + scid_length > bytes_max) {
        bytes = NULL;
    }
    else {
        bytes[0] = (uint8_t)(0xC0 + (signal >> 1) & 0x3f);
        bytes[1] = 0x6f + ((signal & 1) > 0) ? 0x80 : 0;
        bytes[2] = 0x7d;
        bytes[3] = 0xc0;
        bytes[4] = 0xfd;
        bytes[5] = (uint8_t)dcid_length;
        bytes += 6;
        memcpy(bytes, dcid_id, dcid_length);
        bytes += dcid_length;
        *bytes = (uint8_t)scid_length;
        bytes++;
        memcpy(bytes, scid_id, scid_length);
        bytes += scid_length;
    }
    return bytes;
}

const uint8_t * picoquic_scone_parse_packet(const uint8_t* bytes, const uint8_t* bytes_max, unsigned int * signal,
    size_t * dcid_length, uint8_t * dcid_id, size_t* scid_length, uint8_t* scid_id)
{
    if (bytes + 6 >= bytes_max ||
        (bytes[0] & 0xc0) != 0xc0 ||
        (bytes[1] & 0x7f) != 0x6f ||
        bytes[2] != 0x7d ||
        bytes[3] != 0xc0 ||
        bytes[4] != 0xfd) {
        /* Malformed scone header */
        bytes = NULL;
    }
    else
    {
        *signal = ((bytes[0] & 0x3f) << 1) + (bytes[1] >> 7);
        bytes += 5;
        *dcid_length = *bytes;
        bytes++;
        if (bytes + *dcid_length + 1 > bytes_max) {
            bytes = NULL;
        }
        else {
            *dcid_id = *bytes;
            bytes++;
            *scid_length = *bytes;
            if (bytes + *dcid_length > bytes_max) {
                bytes = NULL;
            }
        }
    }
    return bytes;
}

const uint8_t* picoquic_scone_parse_cids(const uint8_t* bytes, const uint8_t* bytes_max,
    size_t* dcid_length, const uint8_t** dcid_id, size_t* scid_length, const uint8_t** scid_id)
{
    *dcid_length = *bytes;
    bytes++;
    if (bytes + *dcid_length + 1 > bytes_max) {
        bytes = NULL;
    }
    else {
        *dcid_id = bytes;
        bytes++;
        *scid_length = *bytes;
        if (bytes + *dcid_length > bytes_max) {
            bytes = NULL;
        }
        else {
            *scid_id = bytes;
        }
    }

    return bytes;
}


void picoquic_scone_padding(uint8_t* bytes, size_t length)
{
    if (length < 2) {
        if (length > 0) {
            *bytes = 0;
        }
    }
    else {
        /* keeping it simple for now */
        memset(bytes, 0, length - 2);
        bytes += length - 2;
        bytes[0] = 0xc8;
        bytes[1] = 0x13;
    }
}

int picoquic_scone_incoming(picoquic_quic_t* quic, picoquic_cnx_t ** pcnx, uint8_t first_byte, picoquic_packet_header* ph, const uint8_t* bytes, const uint8_t * bytes_max)
{
    int ret = 0;
    size_t dcid_length;
    const uint8_t* dcid_id;
    size_t scid_length;
    const uint8_t* scid_id;
    unsigned int signal;

    if ((bytes = picoquic_scone_parse_cids(bytes, bytes_max, &dcid_length, &dcid_id, &scid_length, &scid_id)) == NULL) {
        /* parsing error */
    } else {
        signal = ((first_byte & 0x3f) << 1) + (ph->vn >> 31);
        ph->offset = bytes - bytes_max;
        ph->payload_length = 0;
#if 0
        /* The SCONE packet should always include the dest cnx-id */
        if (ph->dest_cnx_id.id_len == quic->local_cnxid_length) {
            *pcnx = picoquic_cnx_by_id(quic, ph->dest_cnx_id, &ph->l_cid);
        }
#endif
    }
    return ret;
}

#if 0
int picoquic_prepare_packet_scone(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t* next_wake_time)
{
    /* Is it time to send a scone? */
    if (current_time >= path_x->bandwidth_estimate)

    /* if not, set the next wake time. */

    /* Else, try the formatting */

}


int picoquic_parse_packet_scone(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t* next_wake_time)
{
    /* Is it time to send a scone? */

    /* if not, set the next wake time. */

    /* Else, try the formatting */

}
#endif