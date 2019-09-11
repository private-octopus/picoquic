/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "picoquic_internal.h"
#include "bytestream.h"

int fileread_binlog(FILE* bin_log, int(*cb)(bytestream*, void*), void* cbptr)
{
    int ret = 0;
    uint8_t head[4];
    bytestream_buf stream_msg;

    fseek(bin_log, 16, SEEK_SET);

    while (ret == 0 && fread(head, sizeof(head), 1, bin_log) > 0) {

        uint32_t len = (head[0] << 24) | (head[1] << 16) | (head[2] << 8) | head[3];
        if (len > sizeof(stream_msg.buf)) {
            ret = -1;
        }

        if (ret == 0 && fread(stream_msg.buf, len, 1, bin_log) <= 0) {
            ret = -1;
        }

        if (ret == 0) {
            bytestream* s = bytestream_buf_init(&stream_msg, len);
            ret |= cb(s, cbptr);
        }
    }

    return ret;
}

int byteread_packet_header(bytestream * s, picoquic_packet_header * ph)
{
    int ret = 0;

    /* packet information */
    uint8_t header_flags = 0;
    byteread_int8(s, &header_flags);
    ph->spin = (header_flags & 2) != 0;
    ph->key_phase = (header_flags & 1) != 0;

    uint64_t payload_length = 0;
    byteread_vint(s, &payload_length);
    ph->payload_length = payload_length;

    uint64_t ptype;
    byteread_vint(s, &ptype);
    ph->ptype = (picoquic_packet_type_enum)ptype;

    byteread_vint(s, &ph->pn64);

    byteread_cid(s, &ph->dest_cnx_id);
    byteread_cid(s, &ph->srce_cnx_id);

    if (ptype != picoquic_packet_1rtt_protected &&
        ptype != picoquic_packet_version_negotiation) {
        byteread_int32(s, &ph->vn);
    }

    if (ptype == picoquic_packet_initial) {
        uint64_t token_length = 0;
        byteread_vint(s, &token_length);
        bytestream_skip(s, token_length);
    }

    return ret;
}

int byteread_frames(bytestream * s)
{
    int ret = 0;

    uint64_t time, seq_no, length, type;

    bytestream_reset(s);
    ret |= byteread_vint(s, &time);
    ret |= byteread_vint(s, &seq_no);
    ret |= byteread_vint(s, &length);
    ret |= byteread_vint(s, &type);

    uint64_t nb_frames = 0;
    ret |= byteread_vint(s, &nb_frames);

    for (uint64_t i = 0; i < nb_frames; ++i) {

        uint64_t ftype, frame_length, stream_id, epoch, path_seq;
        ret |= byteread_vint(s, &ftype);
        ret |= byteread_vint(s, &frame_length);

        if (ftype >= picoquic_frame_type_stream_range_min &&
            ftype <= picoquic_frame_type_stream_range_max) {
            ret |= byteread_vint(s, &stream_id);
        }
        else switch (ftype) {

        case picoquic_frame_type_crypto_hs:
            ret |= byteread_vint(s, &epoch);
            break;
        case picoquic_frame_type_new_connection_id:
            ret |= byteread_vint(s, &path_seq);
            break;
        }
    }

    return ret;
}

/* Open the bin file for reading */
FILE * picoquic_open_cc_log_file_for_read(char const * bin_cc_log_name, uint32_t * log_time)
{
    int ret = 0;
    FILE * bin_log = picoquic_file_open(bin_cc_log_name, "rb");
    if (bin_log == NULL) {
        DBG_PRINTF("Cannot open CC file %s.\n", bin_cc_log_name);
        ret = -1;
    }

    if (ret == 0) {
        bytestream_buf stream;
        bytestream * ps = bytestream_buf_init(&stream, 16);

        uint32_t fcc = 0;
        uint32_t version = 0;

        if (fread(stream.buf, bytestream_size(ps), 1, bin_log) <= 0) {
            ret = -1;
            DBG_PRINTF("Cannot read header for file %s.\n", bin_cc_log_name);
        }
        else if (byteread_int32(ps, &fcc) != 0 || fcc != FOURCC('q', 'l', 'o', 'g')) {
            ret = -1;
            DBG_PRINTF("Header for file %s does not start with magic number.\n", bin_cc_log_name);
        }
        else if (byteread_int32(ps, &version) != 0 || version != 0x01) {
            ret = -1;
            DBG_PRINTF("Header for file %s requires unsupported version.\n", bin_cc_log_name);
        }
        else {
            ret = byteread_int32(ps, log_time);
        }
    }

    if (ret != 0) {
        bin_log = picoquic_file_close(bin_log);
    }

    return bin_log;
}
