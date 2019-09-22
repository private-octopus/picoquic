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
#include "logreader.h"
#include "logwriter.h"
#include "cidset.h"

static int byteread_packet_header(bytestream * s, picoquic_packet_header * ph);

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

typedef struct convert_log_file_event_st {

    const picoquic_connection_id_t * cid;
    binlog_convert_cb_t * callbacks;

} convert_log_file_event_t;

static int binlog_convert_event(bytestream * s, void * ptr)
{
    int ret = 0;
    convert_log_file_event_t* ctx = (convert_log_file_event_t*)ptr;
    void * cbptr = ctx->callbacks->ptr;

    picoquic_connection_id_t cid;
    ret |= byteread_cid(s, &cid);

    /* filter for connection id */
    if (ret != 0 || picoquic_compare_connection_id(&cid, ctx->cid) != 0) {
        return ret;
    }

    uint64_t time = 0;
    ret |= byteread_vint(s, &time);

    uint64_t id = 0;
    ret |= byteread_vint(s, &id);

    if (id == picoquic_log_event_pdu_recv || id == picoquic_log_event_pdu_sent) {
        int rxtx = id == picoquic_log_event_pdu_recv;
        ret |= ctx->callbacks->pdu(time, rxtx, cbptr);
    }

    if (id == picoquic_log_event_packet_recv || id == picoquic_log_event_packet_sent) {

        int rxtx = id == picoquic_log_event_packet_recv;

        uint64_t packet_length = 0;
        ret |= byteread_vint(s, &packet_length);

        picoquic_packet_header ph;
        ret |= byteread_packet_header(s, &ph);

        if (ret == 0) {
            ret = ctx->callbacks->packet_start(time, packet_length, &ph, rxtx, cbptr);
        }

        while (ret == 0 && bytestream_remain(s) > 0) {
            uint64_t len = 0;
            ret |= byteread_vint(s, &len);

            bytestream stream;
            bytestream* frame = bytestream_ref_init(&stream, bytestream_ptr(s), len);

            ret |= bytestream_skip(s, len);
            if (ret == 0) {
                ret |= ctx->callbacks->packet_frame(frame, cbptr);
            }
        }
        if (ret == 0) {
            ret |= ctx->callbacks->packet_end(cbptr);
        }
    }

    return ret;
}

int binlog_convert(FILE * f_binlog, const picoquic_connection_id_t * cid, binlog_convert_cb_t * callbacks)
{
    convert_log_file_event_t ctx;
    ctx.cid = cid;
    ctx.callbacks = callbacks;

    return fileread_binlog(f_binlog, binlog_convert_event, &ctx);
}

static int binlog_list_cids_cb(bytestream * s, void * cbptr)
{
    picoquic_connection_id_t cid;
    int ret = byteread_cid(s, &cid);

    if (ret == 0) {
        ret = cidset_insert((picohash_table*)cbptr, &cid);
    }

    return ret;
}

int binlog_list_cids(FILE * binlog, picohash_table * cids)
{
    return fileread_binlog(binlog, binlog_list_cids_cb, cids);
}

static int byteread_packet_header(bytestream * s, picoquic_packet_header * ph)
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

/* Open the bin file for reading */
FILE * picoquic_open_cc_log_file_for_read(char const * bin_cc_log_name, uint64_t * log_time)
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
            ret = byteread_int64(ps, log_time);
        }
    }

    if (ret != 0) {
        bin_log = picoquic_file_close(bin_log);
    }

    return bin_log;
}
