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
#include "csv.h"
#ifdef _WINDOWS
#include "../picoquicfirst/getopt.h"
#endif

FILE * open_outfile(const char * log_name, const char * out_file, const char * out_ext);

void usage();

int main(int argc, char ** argv)
{
    int ret = 0;

    const char * log_name = NULL;
    const char * out_format = "csv";
    const char * out_file = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "o:f")) != -1) {
        switch (opt) {
        case 'o':
            out_file = optarg;
            break;
        case 'f':
            out_format = optarg;
            break;
        default:
            usage();
            break;
        }
    }

    if (optind < argc) {
        log_name = argv[optind++];
    }

    debug_printf_push_stream(stderr);

    uint32_t log_time = 0;
    FILE* log = log_name ? picoquic_open_cc_log_file_for_read(log_name, &log_time) : NULL;

    if (log_name != NULL && log == NULL) {
        fprintf(stderr, "Could not open file %s\n", log_name);
        exit(1);
    }

    if (strcmp(out_format, "csv") == 0) {
        ret = picoquic_cc_bin_to_csv(log, open_outfile(log_name, out_file, "csv"));
    } else {
        fprintf(stderr, "Invalid output format %s\n", out_format);
        ret = 1;
    }

    (void)picoquic_file_close(log);
    return ret;
}

FILE * open_outfile(const char * log_name, const char * out_file, const char * out_ext)
{
    int ret = 0;

    char filename[512];
    if (out_file == NULL) {
        out_file = filename;

        if (picoquic_sprintf(filename, sizeof(filename), NULL, "%s.%s", log_name, out_ext) != 0) {
            DBG_PRINTF("Cannot format file name for %s", log_name);
            ret = -1;
        }
    }

    if (ret == 0) {
        return picoquic_file_open(out_file, "w");
    } else {
        return NULL;
    }
}

void usage()
{
    fprintf(stderr, "PicoQUIC log file converter\n");
    fprintf(stderr, "Usage: picolog <options> [input] \n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -o file               output file name\n");
    fprintf(stderr, "  -f format             output format:\n");
    fprintf(stderr, "                        -f csv: generate CC csv file\n");
}
