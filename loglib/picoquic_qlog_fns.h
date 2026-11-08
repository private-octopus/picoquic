/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

#ifndef PICOQUIC_QLOG_FNS_H
#define PICOQUIC_QLOG_FNS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "picoquic.h"

    /* Write bytes as JSON-escaped content, unquoted. */
    void qlog_fns_char_content(FILE* f, const uint8_t* s, uint64_t l);
    /* Write a text and a number, with the same output as
     * fprintf(f, "%s%" PRIu64, text, value) or fprintf(f, "%s%" PRId64, text, value). */
    void qlog_fns_text_uint(FILE* f, const char* text, uint64_t value);
    void qlog_fns_text_int(FILE* f, const char* text, int64_t value);
    /* Write one frame record of a binary log as a qlog frame object. */
    void qlog_binlog_frame(FILE* f, const uint8_t* record, const uint8_t* record_end, int* frame_count);
    /* Write each transport parameter as a field of the current event. The
     * caller checks that tp holds tp_length bytes. */
    void qlog_fns_transport_extensions(FILE* f, uint8_t* tp, size_t tp_length);

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_QLOG_FNS_H */
