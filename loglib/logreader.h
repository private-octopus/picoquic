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

typedef struct log_file_ctx_st {
    const picoquic_connection_id_t * cid;

    FILE * f_binlog;
    FILE * f_txtlog;

    int (*pdu)(uint64_t time, int rxtx, void * ptr);
    int (*packet)(uint64_t time, const picoquic_packet_header * ph, int rxtx, void * ptr);
    int (*frame)(bytestream * s, void * ptr);

    void * ptr;

} log_file_ctx_t;

int fileread_binlog(FILE * bin_log, int(*cb)(bytestream *, void *), void * cbptr);
int convert_log_file(FILE * f_binlog, const log_file_ctx_t * ctx);

FILE * picoquic_open_cc_log_file_for_read(char const * bin_cc_log_name, uint32_t * log_time);

int picoquic_cc_log_file_to_csv(char const * bin_cc_log_name, char const * csv_cc_log_name);

int byteread_packet_header(bytestream* s, picoquic_packet_header* ph);
int byteread_frames(bytestream* s);
