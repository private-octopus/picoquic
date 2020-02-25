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

    fprintf(f, "[%"PRId64", \"TRANSPORT\", \"%s\", { \"packet_type\": \"%s\", \"header\": { \"packet_number\": \"%"PRIu64"\", \"packet_size\": %"PRIu64 ,
        delta_time, (rxtx == 0)?"PACKET_SENT":"PACKET_RECEIVED", ptype2str(ph->ptype), ph->pn64, size);

    if (ph->ptype != picoquic_packet_1rtt_protected) {
        fprintf(f, ", \"payload_length\": %zu", ph->payload_length);
    }

    if (ph->ptype != picoquic_packet_1rtt_protected && ph->srce_cnx_id.id_len > 0) {
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

void qlog_string(FILE* f, bytestream* s, uint64_t l)
{
    uint64_t x;
    int error_found = (s->ptr + (size_t)l > s->size);

    fprintf(f, "\"");

    for (x = 0; x < l && s->ptr < s->size; x++) {
        fprintf(f, "%02x", s->data[s->ptr++]);
    }

    if (error_found) {
        fprintf(f, "... coding error!");
    }

    fprintf(f, "\"");
}

void qlog_reset_stream_frame(FILE* f, bytestream* s)
{
    uint64_t stream_id = 0;
    uint64_t error_code = 0;
    uint64_t final_size = 0;

    byteread_vint(s, &stream_id);
    fprintf(f, ", \"stream_id\": %"PRIu64"", stream_id);
    byteread_vint(s, &error_code);
    fprintf(f, ", \"error_code\": %"PRIu64"", error_code);
    byteread_vint(s, &final_size);
    fprintf(f, ", \"final_size\": %"PRIu64"", final_size);
}

void qlog_stop_sending_frame(FILE* f, bytestream* s)
{
    uint64_t stream_id = 0;
    uint64_t error_code = 0;

    byteread_vint(s, &stream_id);
    fprintf(f, ", \"stream_id\": %"PRIu64"", stream_id);
    byteread_vint(s, &error_code);
    fprintf(f, ", \"error_code\": %"PRIu64"", error_code);
}

void qlog_closing_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    uint64_t error_code = 0;
    uint64_t offending_frame_type = 0;
    uint64_t reason_length = 0;
    char const* offensive_type_name = NULL;

    fprintf(f, ", \"error_space\": \"%s\"", 
        (ftype == picoquic_frame_type_connection_close)?"transport":"application");
    byteread_vint(s, &error_code);
    fprintf(f, ", \"raw_error_code\": %"PRIu64"", error_code);
    
    if (ftype == picoquic_frame_type_connection_close) {
        byteread_vint(s, &offending_frame_type);
        offensive_type_name = ftype2str(offending_frame_type);
        if (strcmp(offensive_type_name, "unknown") == 0) {
            fprintf(f, ", \"offending_frame_type\": \"%"PRIx64"\"", offending_frame_type);
        }
        else {
            fprintf(f, ", \"offending_frame_type\": \"%s\"", offensive_type_name);
        }
    }

    byteread_vint(s, &reason_length);
    if (reason_length > 0){
        fprintf(f, ", \"reason\": \"");
        for (uint64_t i = 0; i < reason_length && s->ptr < s->size; i++) {
            int c = s->data[s->ptr++];

            if (c < 0x20 || c > 0x7E) {
                c = '.';
            }
            fprintf(f, "%c", c);
        }
        fprintf(f, "\"");
    }
}

void qlog_max_data_frame(FILE* f, bytestream* s)
{
    uint64_t maximum = 0;
    byteread_vint(s, &maximum);
    fprintf(f, ", \"maximum\": %"PRIu64"", maximum);
}

void qlog_max_stream_data_frame(FILE* f, bytestream* s)
{
    uint64_t stream_id = 0;
    uint64_t maximum = 0;

    byteread_vint(s, &stream_id);
    fprintf(f, ", \"stream_id\": %"PRIu64"", stream_id);
    byteread_vint(s, &maximum);
    fprintf(f, ", \"maximum\": %"PRIu64"", maximum);
}

void qlog_max_streams_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    uint64_t maximum;

    fprintf(f, ", \"stream_type\": \"%s\"",
        (ftype == picoquic_frame_type_max_streams_bidir) ?
        "bidirectional" : "unidirectional");

    byteread_vint(s, &maximum);
    fprintf(f, ", \"maximum\": %"PRIu64"", maximum);
}

void qlog_blocked_frame(FILE* f, bytestream* s)
{
    uint64_t limit = 0;

    byteread_vint(s, &limit);
    fprintf(f, ", \"limit\": %"PRIu64"", limit);
}

void qlog_stream_blocked_frame(FILE* f, bytestream* s)
{
    uint64_t stream_id = 0;
    uint64_t limit = 0;

    byteread_vint(s, &stream_id);
    fprintf(f, ", \"stream_id\": %"PRIu64"", stream_id);
    byteread_vint(s, &limit);
    fprintf(f, ", \"limit\": %"PRIu64"", limit);
}

void qlog_streams_blocked_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    uint64_t limit;

    fprintf(f, ", \"stream_type\": \"%s\"", 
        (ftype == picoquic_frame_type_streams_blocked_bidir)?
        "bidirectional":"unidirectional");

    byteread_vint(s, &limit);
    fprintf(f, ", \"limit\": %"PRIu64"", limit);
}

void qlog_new_connection_id_frame(FILE* f, bytestream* s)
{
    uint64_t sequence_number = 0;
    uint64_t retire_before = 0;
    uint64_t cid_length = 0;

    byteread_vint(s, &sequence_number);
    fprintf(f, ", \"sequence_number\": %"PRIu64"", sequence_number);
    byteread_vint(s, &retire_before);
    fprintf(f, ", \"retire_before\": %"PRIu64"", retire_before);
    byteread_vint(s, &cid_length);
    fprintf(f, ", \"connection_id\": ");
    qlog_string(f, s, cid_length);
    fprintf(f, ", \"reset_token\": ");
    qlog_string(f, s, 16);
}

void qlog_retire_connection_id_frame(FILE* f, bytestream* s)
{
    uint64_t sequence_number = 0;
    byteread_vint(s, &sequence_number);
    fprintf(f, ", \"sequence_number\": %"PRIu64"", sequence_number);
}

void qlog_new_token_frame(FILE* f, bytestream* s)
{
    uint64_t toklen = 0;

    fprintf(f, ", \"new_token\": ");
    byteread_vint(s, &toklen);
    qlog_string(f, s, toklen);
}

void qlog_path_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    if (ftype == picoquic_frame_type_path_challenge) {
        fprintf(f, ", \"path_challenge\": ");
    }
    else {
        fprintf(f, ", \"path_response\": ");
    }
    qlog_string(f, s, 8);
}

void qlog_crypto_hs_frame(FILE* f, bytestream* s)
{
    uint64_t offset = 0;
    uint64_t data_length = 0;


    byteread_vint(s, &offset);
    fprintf(f, ", \"offset\": %"PRIu64"", offset);
    byteread_vint(s, &data_length);
    fprintf(f, ", \"length\": %"PRIu64"", data_length);
}

void qlog_datagram_frame(uint64_t ftype, FILE* f, bytestream* s)
{
    unsigned int has_length = ftype & 1;
    uint64_t length = 0;

    if (has_length) {
        byteread_vint(s, &length);
        fprintf(f, ", length: %"PRIu64"", length);
    }
}

void qlog_ack_frequency_frame(FILE* f, bytestream* s)
{
    uint64_t sequence_number = 0;
    uint64_t packet_tolerance = 0;
    uint64_t max_ack_delay = 0;
    byteread_vint(s, &sequence_number);
    fprintf(f, ", \"sequence_number\": %"PRIu64"", sequence_number);
    byteread_vint(s, &packet_tolerance);
    fprintf(f, ", \"packet_tolerance\": %"PRIu64"", packet_tolerance);
    byteread_vint(s, &max_ack_delay);
    fprintf(f, ", \"max_ack_delay\": %"PRIu64" ", max_ack_delay);
}

void qlog_ack_frame(uint64_t ftype, FILE * f, bytestream* s)
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

    fprintf(f, "\n    \"frame_type\": \"%s\"", ftype2str((picoquic_frame_type_enum_t)ftype));

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
        qlog_ack_frame(ftype, f, s);
        break;
    case picoquic_frame_type_ack_frequency:
        qlog_ack_frequency_frame(f, s);
        break;
    case picoquic_frame_type_datagram:
    case picoquic_frame_type_datagram_l:
        qlog_datagram_frame(ftype, f, s);
        break;
    case picoquic_frame_type_crypto_hs:
        qlog_crypto_hs_frame(f, s);
        break;
    case picoquic_frame_type_path_challenge:
    case picoquic_frame_type_path_response:
        qlog_path_frame(ftype, f, s);
        break;
    case picoquic_frame_type_new_token:
        qlog_new_token_frame(f, s);
        break;
    case picoquic_frame_type_retire_connection_id:
        qlog_retire_connection_id_frame(f, s);
        break;
    case picoquic_frame_type_new_connection_id:
        qlog_new_connection_id_frame(f, s);
        break;
    case picoquic_frame_type_streams_blocked_bidir:
    case picoquic_frame_type_streams_blocked_unidir:
        qlog_streams_blocked_frame(ftype, f, s);
        break;
    case picoquic_frame_type_stream_data_blocked:
        qlog_stream_blocked_frame(f, s);
        break;
    case picoquic_frame_type_data_blocked:
        qlog_blocked_frame(f, s);
        break;
    case picoquic_frame_type_max_streams_bidir:
    case picoquic_frame_type_max_streams_unidir:
        qlog_max_streams_frame(ftype, f, s);
        break;
    case picoquic_frame_type_max_stream_data:
        qlog_max_stream_data_frame(f, s);
        break;
    case picoquic_frame_type_max_data:
        qlog_max_data_frame(f, s);
        break;
    case picoquic_frame_type_connection_close:
    case picoquic_frame_type_application_close:
        qlog_closing_frame(ftype, f, s);
        break;
    case picoquic_frame_type_stop_sending:
        qlog_stop_sending_frame(f, s);
        break;
    case picoquic_frame_type_reset_stream:
        qlog_reset_stream_frame(f, s);
        break;
    default:
        break;
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

int qlog_convert(const picoquic_connection_id_t* cid, FILE* f_binlog, const char* binlog_name, const char* txt_name, const char* out_dir)
{
    int ret = 0;
    FILE* f_txtlog = NULL;
    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];

    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", binlog_name);
        ret = -1;
    }
    else if (txt_name == NULL) {
        f_txtlog = open_outfile(cid_name, binlog_name, out_dir, "qlog");
    }
    else {
        f_txtlog = picoquic_file_open(txt_name, "w");
    }

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

    return ret;
}
