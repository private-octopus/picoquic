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
#include "svg.h"
#include "qlog.h"
#include "cidset.h"
#include "logreader.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"

#ifdef _WINDOWS
#define PICOLOG_BIN_INPUT "picoquictest\\picolog_test_input.log"
#define PICOLOG_SVG_TEMPLATE "loglib\\template.svg"
#define SVG_LOG_REF "picoquictest\\svglog_ref.svg"
#define SVG_LOG_OUTPUT ".\\0102030405060708.svg"
#define CIDSET_OUTPUT ".\\cidset.txt"

#else
#define PICOLOG_BIN_INPUT "picoquictest/picolog_test_input.log"
#define PICOLOG_SVG_TEMPLATE "loglib/template.svg"
#define SVG_LOG_REF "picoquictest/svglog_ref.svg"
#define SVG_LOG_OUTPUT "./0102030405060708.svg"
#define CIDSET_OUTPUT "./cidset.txt"

#endif
typedef struct app_conversion_context_st
{
    const char* out_format;
    const char* out_dir;

    const char* binlog_name;
    FILE* f_binlog;

    const char* template_name;
    FILE* f_template;

    uint64_t log_time;
    uint16_t flags;
} app_conversion_context_t;

/*
int convert_csv(const picoquic_connection_id_t* cid, void* ptr);
int convert_svg(const picoquic_connection_id_t* cid, void* ptr);
int convert_qlog(const picoquic_connection_id_t* cid, void* ptr);
int filedump_binlog(FILE* bin_log, FILE* bin_dump);
*/
int svg_convert(const picoquic_connection_id_t* cid, FILE* f_binlog, FILE* f_template, const char* binlog_name, const char* out_dir);

int test_convert_svg(const picoquic_connection_id_t* cid, void* ptr)
{
    const app_conversion_context_t* appctx = (const app_conversion_context_t*)ptr;
    return svg_convert(cid, appctx->f_binlog, appctx->f_template, appctx->binlog_name, appctx->out_dir);
}

int picolog_basic_test()
{
    int ret = 0;
    /* find the test input file */
    char log_test_input[512];
    char svg_template[512];
    app_conversion_context_t appctx = { 0 };
    picohash_table* cids = NULL;

    appctx.binlog_name = "?";
    appctx.out_dir = ".";
    ret = picoquic_get_input_path(log_test_input, sizeof(log_test_input), picoquic_solution_dir, PICOLOG_BIN_INPUT);
    if (ret == 0) {
        appctx.binlog_name = log_test_input;
        if ((appctx.f_binlog = picoquic_file_open(log_test_input, "rb")) == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(svg_template, sizeof(svg_template), picoquic_solution_dir, PICOLOG_SVG_TEMPLATE);
        if (ret == 0) {
            if ((appctx.f_template = picoquic_file_open(svg_template, "r")) == NULL) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        cids = cidset_create();
        if (cids == NULL) {
            ret = -1;
        }
        else {
            binlog_list_cids(appctx.f_binlog, cids);
            if (cids->count == 0) {
                ret = -1;
            }
        }
    }
    
    if (ret == 0) {
        FILE* cid_prints;
        if ((cid_prints = picoquic_file_open(CIDSET_OUTPUT, "w")) == NULL) {
            ret = -1;
        }
        else {
            cidset_print(cid_prints, cids);
            (void)picoquic_file_close(cid_prints);
        }
    }

    if (ret == 0) {
        picoquic_connection_id_t cid_test = { {11, 12, 13, 14, 15, 16, 17, 18}, 8 };

        if (cidset_has_cid(cids, &cid_test)) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = cidset_iterate(cids, test_convert_svg, &appctx);
    }

    (void)picoquic_file_close(appctx.f_binlog);
    (void)picoquic_file_close(appctx.f_template);
    if (cids != NULL) {
        (void)cidset_delete(cids);
    }

#if 0
    /* compare the log file to the expected value */
    if (ret == 0)
    {
        char svglog_ref[512];

        ret = picoquic_get_input_path(svglog_ref, sizeof(svglog_ref), picoquic_solution_dir, SVG_LOG_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the svglog test ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(SVG_LOG_OUTPUT, svglog_ref);
        }
    }
#endif

    return ret;
}
