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

    uint32_t log_time;
} app_conversion_context_t;

int convert_csv(const picoquic_connection_id_t * cid, void * ptr);
int convert_svg(const picoquic_connection_id_t * cid, void * ptr);

int usage();
void usage_formats();

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
    fprintf(stderr, "                        -f csv : generate CC csv file\n");
    fprintf(stderr, "                        -f svg : generate svg packet flow diagram.\n");
    fprintf(stderr, "                                 requires a template specified by -t\n");
}

FILE * open_outfile(const picoquic_connection_id_t * cid, const char * binlog_name, const char * out_dir, const char * out_ext)
{
    int ret = 0;

    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", binlog_name);
        ret = -1;
    }

    char filename[512];
    if (ret == 0) {
        if (out_dir != NULL) {
            ret = picoquic_sprintf(filename, sizeof(filename), NULL, "%s%c%s.%s",
                out_dir, PICOQUIC_FILE_SEPARATOR, cid_name, out_ext);
        } else {
            ret = picoquic_sprintf(filename, sizeof(filename), NULL, "%s.%s",
                cid_name, out_ext);
        }
        if (ret != 0) {
            DBG_PRINTF("Cannot format file name for connection %s in file %s", cid_name, binlog_name);
        }
    }

    if (ret == 0) {
        return picoquic_file_open(filename, "w");
    } else {
        return NULL;
    }
}

int convert_csv(const picoquic_connection_id_t * cid, void * ptr)
{
    const app_conversion_context_t* appctx = (const app_conversion_context_t*)ptr;
    return picoquic_cc_bin_to_csv(appctx->f_binlog,
        open_outfile(cid, appctx->binlog_name, appctx->out_dir, "csv"));
}

typedef struct svg_context_st {

    FILE * f_txtlog;      /*!< The file handle of the opened SVG file. */
    uint64_t start_time;  /*!< Timestamp is very first log event reported. */
    int packet_count;

} svg_context_t;

int svg_pdu(uint64_t time, int rxtx, void * ptr)
{
    svg_context_t * svg = (svg_context_t*)ptr;
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
        return "cid";
    case picoquic_frame_type_stop_sending:
        return "stop_sending";
    case picoquic_frame_type_ack:
        return "ack";
    case picoquic_frame_type_path_challenge:
        return "path_challenge";
    case picoquic_frame_type_path_response:
        return "path_response";
    case picoquic_frame_type_crypto_hs:
        return "crypto_hs";
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

int svg_packet_start(uint64_t time, const picoquic_packet_header * ph, int rxtx, void * ptr)
{
    const int event_height = 32;
    svg_context_t * svg = (svg_context_t*)ptr;
    FILE * f = svg->f_txtlog;

    if (svg->packet_count == 0) {
        svg->start_time = time;
    }

    time -= svg->start_time;

    int x_pos = 50;
    int y_pos = 32 + svg->packet_count * event_height;

    const char * dir = rxtx == 0 ? "out" : "in";

    uint64_t time1 = time / 1000;
    uint64_t time01 = (time % 1000) / 100;

    fprintf(f, "  <use x=\"%d\" y=\"%d\" xlink:href=\"#packet-%s\" />\n", x_pos, y_pos, dir);
    fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"time\">%I64d.%I64d ms</text>\n", x_pos - 4, y_pos + 8, time1, time01);

    if (rxtx == 0) {
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"seq_%s\">%I64d</text>\n", x_pos - 4, y_pos - 4, dir, ph->pn64);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"end\" class=\"arw\">%I64d b</text>\n", 80, y_pos - 2, ph->payload_length);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"frm\" xml:space=\"preserve\"> %s</text>\n", 80, y_pos - 2, ptype2str(ph->ptype));
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"frm\" xml:space=\"preserve\">", x_pos + 30, y_pos + 10);
    }
    else {
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"seq_%s\">%I64d</text>\n", 600 - x_pos + 4, y_pos - 4, dir, ph->pn64);
        fprintf(f, "  <text x=\"%d\" y=\"%d\" text-anchor=\"start\" class=\"arw\">%I64d b</text>\n", 600 - 80, y_pos - 2, ph->payload_length);
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
        fprintf(svg->f_txtlog, " stream[%I64d] ", stream_id);
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

    svg_context_t svg;
    svg.f_txtlog = open_outfile(cid, appctx->binlog_name, appctx->out_dir, "svg");
    svg.start_time = 0;
    svg.packet_count = 0;

    binlog_convert_cb_t ctx;
    ctx.pdu = svg_pdu;
    ctx.packet_start = svg_packet_start;
    ctx.packet_frame = svg_packet_frame;
    ctx.packet_end = svg_packet_end;
    ctx.ptr = &svg;

    char line[256];
    while (fgets(line, sizeof(line), appctx->f_template) != NULL) /* read a line */ {
        if (strcmp(line, "#\n") != 0) {
            /* Copy the template to the SVG file */
            fprintf(svg.f_txtlog, line);
        } else {
            ret = binlog_convert(appctx->f_binlog, cid, &ctx);
        }
    }

    return ret;
}
