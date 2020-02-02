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
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include "picoquic_internal.h"
#include "bytestream.h"
#include "logreader.h"
#include "logconvert.h"

typedef struct qlog_context_st {

    FILE * f_txtlog;      /*!< The file handle of the opened output file. */

    const char * cid_name; /*!< Name of the connection, default = initial connection id */

    uint64_t start_time;  /*!< Timestamp is very first log event reported. */
    int packet_count;
    int frame_count;

    int state;
} qlog_context_t;

int qlog_pdu(uint64_t time, int rxtx, void * ptr)
{
    (void)time;
    (void)rxtx;
    (void)ptr;
    return 0;
}

int qlog_packet_start(uint64_t time, uint64_t size, const picoquic_packet_header * ph, int rxtx, void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;

    int64_t delta_time = time - ctx->start_time;

    if (ctx->packet_count != 0) {
        fprintf(f, ",\n");
    } else {
        fprintf(f, "\n");
    }

    fprintf(f, "[%"PRId64", \"TRANSPORT\", \"%s\", { \"packet_type\": \"%s\", \"header\": { \"packet_number\": \"%"PRIu64"\", \"packet_size\": %"PRIu64", \"payload_length\": %zu",
        delta_time, (rxtx == 0)?"PACKET_SENT":"PACKET_RECEIVED", ptype2str(ph->ptype), ph->pn64, size, ph->payload_length);

    if (ph->srce_cnx_id.id_len > 0) {
        char scid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
        picoquic_print_connection_id_hexa(scid_name, sizeof(scid_name), &ph->srce_cnx_id);
        fprintf(f, ", \"scid\": \"%s\"", scid_name);
    }

    if (ph->dest_cnx_id.id_len > 0) {
        char dcid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
        picoquic_print_connection_id_hexa(dcid_name, sizeof(dcid_name), &ph->dest_cnx_id);
        fprintf(f, ", \"dcid\": \"%s\"", dcid_name);
    }

    fprintf(f, " }, \"frames\": [");

    ctx->frame_count = 0;
    return 0;
}

int qlog_packet_frame(bytestream * s, void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;

    if (ctx->frame_count != 0) {
        fprintf(f, ", ");
    }

    fprintf(f, "{ ");

    uint64_t ftype = 0;
    byteread_vint(s, &ftype);

    fprintf(f, "\"frame_type\": \"%s\"", ftype2str((picoquic_frame_type_enum_t)ftype));

    if (ftype >= picoquic_frame_type_stream_range_min &&
        ftype <= picoquic_frame_type_stream_range_max) {
        uint64_t stream_id = 0;
        byteread_vint(s, &stream_id);
        uint64_t offset = 0;
        if ((ftype & 4) != 0) {
            byteread_vint(s, &offset);
        }
        uint64_t length = bytestream_remain(s);
        if ((ftype & 2) != 0) {
            byteread_vint(s, &length);
        }
        fprintf(f, ", \"id\": %"PRIu64", \"offset\": %"PRIu64", \"length\": %"PRIu64", \"fin\": %s ",
            stream_id, offset, length, (ftype & 1) ? "true":"false");
    } else switch (ftype) {
    case picoquic_frame_type_ack:
    case picoquic_frame_type_ack_ecn:
    case picoquic_frame_type_ack_1wd:
    case picoquic_frame_type_ack_ecn_1wd:
    {
        uint64_t largest = 0;
        byteread_vint(s, &largest);
        uint64_t ack_delay = 0;
        uint64_t remote_time_stamp = 0;
        if (ftype == picoquic_frame_type_ack_1wd ||
            ftype == picoquic_frame_type_ack_ecn_1wd) {
            byteread_vint(s, &remote_time_stamp);
            fprintf(f, ", \"remote_time_stamp\": %"PRIu64"", remote_time_stamp);
        }
        byteread_vint(s, &ack_delay);
        fprintf(f, ", \"ack_delay\": %"PRIu64"", ack_delay);
        uint64_t num = 0;
        byteread_vint(s, &num);
        fprintf(f, ", \"acked_ranges\": [");
        for (uint64_t i = 0; i <= num; i++) {
            uint64_t skip = 0;
            if (i != 0) {
                byteread_vint(s, &skip);
                skip++;

                largest -= skip;
                fprintf(f, ", ");
            }
            uint64_t range = 0;
            byteread_vint(s, &range);

            fprintf(f, "[%"PRIu64", %"PRIu64"]", largest - range, largest);
            largest -= range + 1;
        }
        fprintf(f, "]");
        if (ftype == picoquic_frame_type_ack_ecn ||
            ftype == picoquic_frame_type_ack_ecn_1wd) {
            fprintf(f, ", \"ecn\": [");
            for (int ecnx = 0; ecnx < 3; ecnx++) {
                uint64_t ecn_v = 0;
                byteread_vint(s, &ecn_v);
                fprintf(f, "%s%"PRIu64, (ecnx == 0) ? "" : ",", ecn_v);
            }
            fprintf(f, "]");
        }
        break;
    }
    }

    fprintf(f, "}");
    ctx->frame_count++;
    return 0;
}

int qlog_packet_end(void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;
    fprintf(f, "]}]");
    ctx->packet_count++;
    return 0;
}

int qlog_connection_start(uint64_t time, const picoquic_connection_id_t * cid, int client_mode,
    uint32_t proposed_version, const picoquic_connection_id_t * remote_cnxid, void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;

    ctx->start_time = time;
    ctx->packet_count = 0;

    fprintf(f, "{ \"qlog_version\": \"draft-00\", \"title\": \"picoquic\", \"traces\": [\n");
    fprintf(f, "{ \"vantage_point\": { \"name\": \"backend-67\", \"type\": \"%s\" },\n",
        client_mode?"client":"server");

    fprintf(f, "\"title\": \"picoquic\", \"description\": \"%s\",", ctx->cid_name);
    fprintf(f, "\"event_fields\": [\"relative_time\", \"CATEGORY\", \"EVENT_TYPE\", \"DATA\"],\n");
    fprintf(f, "\"configuration\": {\"time_units\": \"us\"},\n");
    fprintf(f, "\"common_fields\": { \"protocol_type\": \"QUIC_HTTP3\", \"reference_time\": \"%"PRIu64"\"},\n", ctx->start_time);
    fprintf(f, "\"events\": [\n");
    ctx->state = 1;
    return 0;
}

int qlog_connection_end(uint64_t time, void * ptr)
{
    qlog_context_t * ctx = (qlog_context_t*)ptr;
    FILE * f = ctx->f_txtlog;
    fprintf(f, "]}]}\n");

    ctx->state = 2;
    return 0;
}

int qlog_convert(const picoquic_connection_id_t* cid, FILE * f_binlog, const char * binlog_name, const char * out_dir)
{
    int ret = 0;

    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", binlog_name);
        ret = -1;
    }
    else {

        FILE* f_txtlog = open_outfile(cid_name, binlog_name, out_dir, "qlog");
        if (f_txtlog == NULL) {
            ret = -1;
        }
        else {

            qlog_context_t qlog;
            qlog.f_txtlog = f_txtlog;
            qlog.cid_name = cid_name;
            qlog.start_time = 0;
            qlog.packet_count = 0;
            qlog.state = 0;

            binlog_convert_cb_t ctx;
            ctx.connection_start = qlog_connection_start;
            ctx.connection_end = qlog_connection_end;
            ctx.pdu = qlog_pdu;
            ctx.packet_start = qlog_packet_start;
            ctx.packet_frame = qlog_packet_frame;
            ctx.packet_end = qlog_packet_end;
            ctx.ptr = &qlog;

            ret = binlog_convert(f_binlog, cid, &ctx);

            if (qlog.state == 1) {
                qlog_connection_end(0, &qlog);
            }

            picoquic_file_close(f_txtlog);
        }
    }

    return ret;
}
