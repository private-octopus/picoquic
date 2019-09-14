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
    const char * log_name;
    FILE * f_binlog;
    uint32_t log_time;
} app_conversion_context_t;

int binlog_list_cids(FILE * f_binlog, picohash_table * cids);
int convert_csv(const picoquic_connection_id_t * cid, void * cbptr);

int usage();

int main(int argc, char ** argv)
{
    int ret = 0;

    picohash_table * cids = cidset_create();

    const char * cid_name = NULL;
    picoquic_connection_id_t cid = picoquic_null_connection_id;

    app_conversion_context_t appctx = { 0 };
    appctx.out_format = "csv";

    int opt;
    while ((opt = getopt(argc, argv, "o:f:c:h")) != -1) {
        switch (opt) {
        case 'o':
            appctx.out_dir = optarg;
            break;
        case 'f':
            appctx.out_format = optarg;
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
        appctx.log_name = argv[optind++];
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

    appctx.f_binlog = picoquic_open_cc_log_file_for_read(appctx.log_name, &appctx.log_time);
    if (appctx.f_binlog == NULL) {
        fprintf(stderr, "Could not open file %s\n", appctx.log_name);
        ret = -1;
    }

    if (ret == 0) {
        binlog_list_cids(appctx.f_binlog, cids);
        
        fprintf(stderr, "%s contains %"PRIst" connection(s):\n\n", appctx.log_name, cids->count);
        cidset_print(stderr, cids);

        if (!picoquic_is_connection_id_null(&cid)) {
            if (!cidset_has_cid(cids, &cid)) {
                fprintf(stderr, "%s does not contain connection %s\n", appctx.log_name, cid_name);
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
        } else {
            fprintf(stderr, "Invalid output format %s\n", appctx.out_format);
            ret = 1;
        }
    }

    (void)picoquic_file_close(appctx.f_binlog);
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
    fprintf(stderr, "                        -f csv: generate CC csv file\n");
    fprintf(stderr, "  -c connection-id      only convert logs from specified connection id\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "picolog converts binary log files into the format specified. Output files are\n");
    fprintf(stderr, "placed in the specified directory with their connection-id as file name.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "If no connection id is specified all connections contained in the binary file\n");
    fprintf(stderr, "are converted.\n");
    return 1;
}

FILE * open_outfile(const picoquic_connection_id_t * cid, const char * log_name, const char * out_dir, const char * out_ext)
{
    int ret = 0;

    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", log_name);
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
            DBG_PRINTF("Cannot format file name for connection %s in file %s", cid_name, log_name);
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
        open_outfile(cid, appctx->log_name, appctx->out_dir, "csv"));
}

static int list_cids_cb(bytestream * s, void * cbptr)
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
    return fileread_binlog(binlog, list_cids_cb, cids);
}
