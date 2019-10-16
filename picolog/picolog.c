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
#include "csv.h"
#include "cidset.h"
#include "logreader.h"
#ifdef _WINDOWS
#include "../picoquicfirst/getopt.h"
#endif

typedef struct app_conversion_context_st
{
    const char * out_format;
    const char * out_dir;

    const char * binlog_name;
    FILE * f_binlog;

    const char * template_name;
    FILE * f_template;

    uint64_t log_time;
} app_conversion_context_t;

int convert_csv(const picoquic_connection_id_t * cid, void * ptr);
int convert_svg(const picoquic_connection_id_t * cid, void * ptr);
int convert_qlog(const picoquic_connection_id_t * cid, void * ptr);

int usage();
void usage_formats();

/* - Open binary log file and find all connection ids it contains by:
 *   - read each event
 *   - read connection id of the event
 *   - store connection id in the hashtable if it doesn't contain it already
 * - Print all connection ids found.
 * - Check if user provided a connection id on the command line and verify it is
 *   contained in the hashtable. If so, replace the hashtable of connection ids
 *   with a new hashtable only containing the user provided connection id.
 * - Iterate over all connection ids in the hashtable and for each connection id
 *   convert all events for that connection id into the specified format.
 */
int main(int argc, char ** argv)
{
    int ret = 0;

    picohash_table * cids = cidset_create();

    const char * cid_name = NULL;
    picoquic_connection_id_t cid = picoquic_null_connection_id;

    app_conversion_context_t appctx = { 0 };
    appctx.out_format = "csv";

    int opt;
    while ((opt = getopt(argc, argv, "o:f:t:c:h")) != -1) {
        switch (opt) {
        case 'o':
            appctx.out_dir = optarg;
            break;
        case 'f':
            appctx.out_format = optarg;
            break;
        case 't':
            appctx.template_name = optarg;
            break;
        case 'c':
            cid_name = optarg;
            break;
        case 'h':
        default:
            return usage();
            break;
        }
    }

    if (optind < argc) {
        appctx.binlog_name = argv[optind++];
    } else {
        return usage();
    }

    if (cids == NULL) {
        fprintf(stderr, "Fatal: failed to create resources.\n");
        return 1;
    }

    if (cid_name != NULL && picoquic_parse_connection_id_hexa(cid_name, strlen(cid_name), &cid) == 0) {
        fprintf(stderr, "Could not parse connection id: %s\n", cid_name);
        ret = -1;
    }

    debug_printf_push_stream(stderr);

    appctx.f_binlog = picoquic_open_cc_log_file_for_read(appctx.binlog_name, &appctx.log_time);
    if (appctx.f_binlog == NULL) {
        fprintf(stderr, "Could not open log file %s\n", appctx.binlog_name);
        ret = -1;
    }

    if (appctx.template_name != NULL) {
        appctx.f_template = picoquic_file_open(appctx.template_name, "r");
        if (appctx.f_template == NULL) {
            fprintf(stderr, "Could not open template file %s\n", appctx.binlog_name);
            ret = -1;
        }
    }

    if (ret == 0) {
        binlog_list_cids(appctx.f_binlog, cids);

        fprintf(stderr, "%s contains %"PRIst" connection(s):\n\n", appctx.binlog_name, cids->count);
        cidset_print(stderr, cids);
        fprintf(stderr, "\n");

        if (!picoquic_is_connection_id_null(&cid)) {
            if (!cidset_has_cid(cids, &cid)) {
                fprintf(stderr, "%s does not contain connection %s\n", appctx.binlog_name, cid_name);
                ret = -1;
            } else {
                (void)cidset_delete(cids);
                cids = cidset_create();
                cidset_insert(cids, &cid);
            }
        }
    }

    if (ret == 0) {
        if (strcmp(appctx.out_format, "csv") == 0) {
            ret = cidset_iterate(cids, convert_csv, &appctx);
        } else if (strcmp(appctx.out_format, "svg") == 0) {
            if (appctx.f_template == NULL) {
                fprintf(stderr, "The svg format conversion requires a template file specified by parameter -t\n");
                ret = -1;
            } else {
                ret = cidset_iterate(cids, convert_svg, &appctx);
            }
        } else if (strcmp(appctx.out_format, "qlog") == 0) {
            ret = cidset_iterate(cids, convert_qlog, &appctx);
        } else {
            fprintf(stderr, "Invalid output format '%s'. Valid formats are\n\n", appctx.out_format);
            usage_formats();
            ret = 1;
        }
    }

    (void)picoquic_file_close(appctx.f_binlog);
    (void)picoquic_file_close(appctx.f_template);
    (void)cidset_delete(cids);
    return ret;
}

int usage()
{
    fprintf(stderr, "PicoQUIC log file converter\n");
    fprintf(stderr, "Usage: picolog <options> input \n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -o directory          output directory name\n");
    fprintf(stderr, "                        default is current working directory\n");
    fprintf(stderr, "  -f format             output format:\n");
    usage_formats();
    fprintf(stderr, "  -t template-file      template file for svg format conversion\n");
    fprintf(stderr, "  -c connection-id      only convert logs of specified connection id\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "picolog converts binary log files into the format specified. Output files are\n");
    fprintf(stderr, "placed in the specified directory with their connection-id as file name.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If no connection id is specified all connections contained in the binary file\n");
    fprintf(stderr, "are converted producing as many output files as connections are found in the\n");
    fprintf(stderr, "binary file.\n");
    return 1;
}

void usage_formats()
{
    fprintf(stderr, "                        -f csv  : generate CC csv file\n");
    fprintf(stderr, "                        -f svg  : generate svg packet flow diagram.\n");
    fprintf(stderr, "                                  requires a template specified by -t\n");
    fprintf(stderr, "                        -f qlog : generate IETF QLOG file\n");
}

FILE * open_outfile(const char * cid_name, const char * binlog_name, const char * out_dir, const char * out_ext)
{
    if (out_dir == NULL) {
        return stdout;
    }

    char filename[512];
    int ret = picoquic_sprintf(filename, sizeof(filename), NULL, "%s%c%s.%s",
        out_dir, PICOQUIC_FILE_SEPARATOR, cid_name, out_ext);

    if (ret != 0) {
        DBG_PRINTF("Cannot format file name for connection %s in file %s", cid_name, binlog_name);
        return NULL;
    }
    
    FILE * f = picoquic_file_open(filename, "w");
    if (f == NULL) {
        fprintf(stderr, "Could not open '%s' for writing (err=%d)", filename, errno);
    }
    return f;
}

int convert_csv(const picoquic_connection_id_t * cid, void * ptr)
{
    const app_conversion_context_t* appctx = (const app_conversion_context_t*)ptr;
    int ret = 0;

    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", appctx->binlog_name);
        ret = -1;
    }

    if (ret == 0) {
        ret = picoquic_cc_bin_to_csv(appctx->f_binlog,
            open_outfile(cid_name, appctx->binlog_name, appctx->out_dir, "csv"));
    }

    return ret;
}

typedef struct svg_context_st {

    FILE * f_txtlog;      /*!< The file handle of the opened output file. */
    FILE * f_template;    /*!< The file handle of the opened template file. */

    const char * cid_name; /*!< Name of the connection, default = initial connection id */

    uint64_t start_time;  /*!< Timestamp is very first log event reported. */
    int packet_count;
    int frame_count;

    int state;
} svg_context_t;

int svg_pdu(uint64_t time, int rxtx, void * ptr)
{
    (void)time;
    (void)rxtx;
    (void)ptr;
    return 0;
}

const char * ptype2str(picoquic_packet_type_enum ptype)
{
    switch (ptype) {
    case picoquic_packet_error:
        return "error";
    case picoquic_packet_version_negotiation:
        return "version";
    case picoquic_packet_initial:
        return "initial";
    case picoquic_packet_retry:
        return "retry";
    case picoquic_packet_handshake:
        return "handshake";
    case picoquic_packet_0rtt_protected:
        return "0rtt";
    case picoquic_packet_1rtt_protected:
        return "1rtt";
    case picoquic_packet_type_max:
    default:
        return "unknown";
    }
}

char const* fname2str(picoquic_frame_type_enum_t ftype)
{
    if ((int)ftype >= picoquic_frame_type_stream_range_min &&
        (int)ftype <= picoquic_frame_type_stream_range_max) {
        return "stream";
    }

    switch (ftype) {
    case picoquic_frame_type_padding:
        return "padding";
    case picoquic_frame_type_reset_stream:
        return "reset_stream";
    case picoquic_frame_type_connection_close:
        return "connection_close";
    case picoquic_frame_type_application_close:
        return "application_close";
    case picoquic_frame_type_max_data:
        return "max_data";
    case picoquic_frame_type_max_stream_data:
        return "max_stream_data";
    case picoquic_frame_type_max_streams_bidir:
        return "max_streams_bidir";
    case picoquic_frame_type_max_streams_unidir:
        return "max_streams_unidir";
    case picoquic_frame_type_ping:
        return "ping";
    case picoquic_frame_type_data_blocked:
        return "data_blocked";
    case picoquic_frame_type_stream_data_blocked:
        return "stream_data_blocked";
    case picoquic_frame_type_streams_blocked_bidir:
        return "streams_blocked_bidir";
    case picoquic_frame_type_streams_blocked_unidir:
        return "streams_blocked_unidir";
    case picoquic_frame_type_new_connection_id:
        return "new_connection_id";
    case picoquic_frame_type_stop_sending:
        return "stop_sending";
    case picoquic_frame_type_ack:
        return "ack";
    case picoquic_frame_type_path_challenge:
        return "path_challenge";
    case picoquic_frame_type_path_response:
        return "path_response";
    case picoquic_frame_type_crypto_hs:
        return "crypto";
    case picoquic_frame_type_new_token:
        return "new_token";
    case picoquic_frame_type_ack_ecn:
        return "ack_ecn";
    case picoquic_frame_type_retire_connection_id:
        return "retire_connection_id";
    case picoquic_frame_type_datagram:
    case picoquic_frame_type_datagram_l:
    case picoquic_frame_type_datagram_id:
    case picoquic_frame_type_datagram_id_l:
        return "datagram";
    default:
        return "unknown";
    }
}

int svg_connection_start(uint64_t time, const picoquic_connection_id_t * cid, int client_mode,
    uint32_t proposed_version, const picoquic_connection_id_t * remote_cnxid, void * ptr)
{
    (void)time;
    (void)cid;
    (void)client_mode;
    (void)proposed_version;
    (void)remote_cnxid;
    (void)ptr;
    return 0;
}

int svg_connection_end(uint64_t time, void* ptr)
{
    (void)time;
    (void)ptr;
    return 0;
}

int svg_packet_start(uint64_t time, uint64_t size, const picoquic_packet_header * ph, int rxtx, void * ptr)
{
    const int event_height = 32;
    svg_context_t * svg = (svg_context_t*)ptr;
    FILE * f = svg->f_txtlog;

    time -= svg->start_time;

    int x_pos = 50;
    int y_pos = 32 + svg->packet_count * event_height;

    const char * dir = rxtx == 0 ? "out" : "in";

    uint64_t time1 = time / 1000;
    uint64_t time01 = (time % 1000) / 100;

    fprintf(f, "  <use x=\"%d\" y=\"%d\" xlink:href=\"#packet-%s\" />\n", x_pos, y_pos, dir);
    fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"time\">%"PRIu64".%"PRIu64" ms</text>\n", x_pos - 4, y_pos + 8, time1, time01);

    if (rxtx == 0) {
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"seq_%s\">%"PRIu64"</text>\n", x_pos - 4, y_pos - 4, dir, ph->pn64);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"arw\">%"PRIu64" b</text>\n", 80, y_pos - 2, size);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"frm\" xml:space=\"preserve\"> %s</text>\n", 80, y_pos - 2, ptype2str(ph->ptype));
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"frm\" xml:space=\"preserve\">", x_pos + 30, y_pos + 10);
    }
    else {
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"seq_%s\">%"PRIu64"</text>\n", 600 - x_pos + 4, y_pos - 4, dir, ph->pn64);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"arw\">%"PRIu64" b</text>\n", 600 - 80, y_pos - 2, size);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"frm\" xml:space=\"preserve\">%s </text>\n", 600-80, y_pos - 2, ptype2str(ph->ptype));
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"frm\" xml:space=\"preserve\">", 600 - x_pos - 30, y_pos + 10);
    }

    svg->packet_count++;
    return 0;
}

int svg_packet_frame(bytestream * s, void * ptr)
{
    svg_context_t * svg = (svg_context_t*)ptr;

    uint8_t ftype = 0;
    byteread_int8(s, &ftype);

    if (ftype >= picoquic_frame_type_stream_range_min &&
        ftype <= picoquic_frame_type_stream_range_max) {
        uint64_t stream_id = 0;
        byteread_vint(s, &stream_id);
        fprintf(svg->f_txtlog, " stream[%"PRIu64"] ", stream_id);
    } else {
        fprintf(svg->f_txtlog, " %s ", fname2str(ftype));
    }
    return 0;
}

int svg_packet_end(void * ptr)
{
    svg_context_t * svg = (svg_context_t*)ptr;
    FILE * f = svg->f_txtlog;
    fprintf(f, "</text>\n");
    return 0;
}

int convert_svg(const picoquic_connection_id_t * cid, void * ptr)
{
    const app_conversion_context_t* appctx = (const app_conversion_context_t*)ptr;
    int ret = 0;

    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", appctx->binlog_name);
        ret = -1;
    }

    svg_context_t svg;
    svg.f_txtlog = open_outfile(cid_name, appctx->binlog_name, appctx->out_dir, "svg");
    svg.f_template = appctx->f_template;
    svg.cid_name = cid_name;
    svg.start_time = appctx->log_time;
    svg.packet_count = 0;

    binlog_convert_cb_t ctx;
    ctx.connection_start = svg_connection_start;
    ctx.connection_end = svg_connection_end;
    ctx.pdu = svg_pdu;
    ctx.packet_start = svg_packet_start;
    ctx.packet_frame = svg_packet_frame;
    ctx.packet_end = svg_packet_end;
    ctx.ptr = &svg;

    char line[256];
    while (fgets(line, sizeof(line), appctx->f_template) != NULL) /* read a line */ {
        if (strcmp(line, "#\n") != 0) {
            /* Copy the template to the SVG file */
            fprintf(svg.f_txtlog, "%s", line);
        } else {
            ret = binlog_convert(appctx->f_binlog, cid, &ctx);
        }
    }

    return ret;
}

int qlog_packet_start(uint64_t time, uint64_t size, const picoquic_packet_header * ph, int rxtx, void * ptr)
{
    svg_context_t * ctx = (svg_context_t*)ptr;
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
    svg_context_t * ctx = (svg_context_t*)ptr;
    FILE * f = ctx->f_txtlog;

    if (ctx->frame_count != 0) {
        fprintf(f, ", ");
    }

    fprintf(f, "{ ");

    uint8_t ftype = 0;
    byteread_int8(s, &ftype);

    fprintf(f, "\"frame_type\": \"%s\"", fname2str(ftype));

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
    case picoquic_frame_type_ack: {
        uint64_t largest = 0;
        byteread_vint(s, &largest);
        uint64_t ack_delay = 0;
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
        break;
    }
    }

    fprintf(f, "}");
    ctx->frame_count++;
    return 0;
}

int qlog_packet_end(void * ptr)
{
    svg_context_t * ctx = (svg_context_t*)ptr;
    FILE * f = ctx->f_txtlog;
    fprintf(f, "]}]");
    ctx->packet_count++;
    return 0;
}

int qlog_connection_start(uint64_t time, const picoquic_connection_id_t * cid, int client_mode,
    uint32_t proposed_version, const picoquic_connection_id_t * remote_cnxid, void * ptr)
{
    svg_context_t * ctx = (svg_context_t*)ptr;
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
    svg_context_t * ctx = (svg_context_t*)ptr;
    FILE * f = ctx->f_txtlog;
    fprintf(f, "]}]}\n");

    ctx->state = 2;
    return 0;
}

int convert_qlog(const picoquic_connection_id_t* cid, void* ptr)
{
    const app_conversion_context_t* appctx = (const app_conversion_context_t*)ptr;
    int ret = 0;

    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", appctx->binlog_name);
        ret = -1;
    }
    else {

        FILE* f_txtlog = open_outfile(cid_name, appctx->binlog_name, appctx->out_dir, "qlog");
        if (f_txtlog == NULL) {
            ret = -1;
        }
        else {

            svg_context_t qlog;
            qlog.f_txtlog = f_txtlog;
            qlog.f_template = appctx->f_template;
            qlog.cid_name = cid_name;
            qlog.start_time = 0;
            qlog.packet_count = 0;
            qlog.state = 0;

            binlog_convert_cb_t ctx;
            ctx.connection_start = qlog_connection_start;
            ctx.connection_end = qlog_connection_end;
            ctx.pdu = svg_pdu;
            ctx.packet_start = qlog_packet_start;
            ctx.packet_frame = qlog_packet_frame;
            ctx.packet_end = qlog_packet_end;
            ctx.ptr = &qlog;

            ret = binlog_convert(appctx->f_binlog, cid, &ctx);

            if (qlog.state == 1) {
                qlog_connection_end(0, &qlog);
            }
        }
    }

    return ret;
}
