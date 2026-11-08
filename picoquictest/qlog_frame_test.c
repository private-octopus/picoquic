/*
* Author: Christan Huitema
* Copyright (c) 2026, Private Octopus, Inc.
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

#include <stdlib.h>
#include <string.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "picoquic_qlog_fns.h"


#define QLOG_FRAMES_TEST_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "qlog_frames_test_ref.txt"
#define QLOG_FRAMES_TEST "qlog_frames_test.json"
#define QLOG_BINLOG_FRAME_TEST "qlog_binlog_frame_test.txt"

// Forward declaration for the QLOG frame logging dispatcher
extern void qlog_frames(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, int skip_padding);

/* Test cases for qlog_binlog_frame. Each case is a list of records of a
 * binary log, with the expected output and frame count. The log stores
 * STREAM, CRYPTO and DATAGRAM frames without all of their data. The log
 * writer can store the start of a damaged frame, but it does not write empty
 * records or records whose frame type does not decode. Each record is in a
 * 16-byte array. The varint decoder computes the end of a varint, at most 8
 * bytes, before it compares it with the end of the record. No varint in these
 * records starts after byte 8, so the decoder does not compute a pointer past
 * the end of the array. */
typedef struct st_qlog_binlog_record_t {
    uint8_t bytes[16];
    size_t length;
} qlog_binlog_record_t;

typedef struct st_qlog_binlog_frame_case_t {
    char const* name;
    size_t nb_records;
    qlog_binlog_record_t records[4];
    int expected_count;
    char const* expected;
} qlog_binlog_frame_case_t;

static const qlog_binlog_frame_case_t qlog_binlog_frame_cases[] = {
    { "empty", 1, { { { 0 }, 0 } }, 0, "" },
    { "bad_type", 1, { { { 0x40 }, 1 } }, 0, "" },
    { "unknown_type", 1, { { { 0x21, 0x02, 0x03, 0x04 }, 4 } }, 1,
        "{ \n    \"frame_type\": \"unknown\", \"unknown_frame_type\": 33}" },
    { "stream", 1, { { { 0x0e, 0x04, 0x40, 0x80, 0x10, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 }, 13 } }, 1,
        "{ \n    \"frame_type\": \"stream\", \"id\": 4, \"offset\": 128, \"length\": 16, \"fin\": false , \"begins_with\": \"a0a1a2a3a4a5a6a7\"}" },
    { "stream_added_length", 1, { { { 0x09, 0x01, 0x03, 'a', 'b', 'c' }, 6 } }, 1,
        "{ \n    \"frame_type\": \"stream\", \"id\": 1, \"offset\": 0, \"length\": 3, \"fin\": true , \"has_length\": false, \"begins_with\": \"616263\"}" },
    { "stream_clipped", 1, { { { 0x0a, 0x01, 0x02, 'a', 'b', 'c' }, 6 } }, 1,
        "{ \n    \"frame_type\": \"stream\", \"id\": 1, \"offset\": 0, \"length\": 2, \"fin\": false , \"begins_with\": \"6162\"}" },
    { "stream_truncated", 1, { { { 0x0e, 0x04, 0x80 }, 3 } }, 1,
        "{ \n    \"frame_type\": \"stream\"}" },
    { "datagram", 1, { { { 0x30 }, 1 } }, 1,
        "{ \n    \"frame_type\": \"datagram\"}" },
    { "datagram_l", 1, { { { 0x31, 0x10 }, 2 } }, 1,
        "{ \n    \"frame_type\": \"datagram\", \"length\": 16}" },
    { "crypto", 1, { { { 0x06, 0x00, 0x40, 0x20 }, 4 } }, 1,
        "{ \n    \"frame_type\": \"crypto\", \"offset\": 0, \"length\": 32}" },
    { "close_no_error", 1, { { { 0x1c, 0x00, 0x00, 0x02, 'o', 'k' }, 6 } }, 1,
        "{ \n    \"frame_type\": \"connection_close\", \"error_space\": \"transport\", \"error_code\": 0, \"reason\": \"ok\"}" },
    /* The empty record and the record with a bad type add no comma. */
    { "sequence", 4, { { { 0x10, 0x05 }, 2 }, { { 0 }, 0 }, { { 0x40 }, 1 }, { { 0x01 }, 1 } }, 2,
        "{ \n    \"frame_type\": \"max_data\", \"maximum\": 5}, { \n    \"frame_type\": \"ping\"}" }
};

/* Write the records of a test case with qlog_binlog_frame, and compare the
 * output and the frame count with the expected values. */
static int qlog_binlog_frame_check(const qlog_binlog_frame_case_t* test)
{
    int ret = 0;
    int frame_count = 0;
    char actual[512];
    size_t actual_length = 0;
    FILE* F = picoquic_file_open(QLOG_BINLOG_FRAME_TEST, "wb");

    if (F == NULL) {
        ret = -1;
    }
    else {
        for (size_t i = 0; i < test->nb_records; i++) {
            const uint8_t* bytes = test->records[i].bytes;
            qlog_binlog_frame(F, bytes, bytes + test->records[i].length, &frame_count);
        }
        F = picoquic_file_close(F);
        if ((F = picoquic_file_open(QLOG_BINLOG_FRAME_TEST, "rb")) == NULL) {
            ret = -1;
        }
        else {
            actual_length = fread(actual, 1, sizeof(actual) - 1, F);
            F = picoquic_file_close(F);
            actual[actual_length] = 0;
            if (frame_count != test->expected_count || strcmp(actual, test->expected) != 0) {
                DBG_PRINTF("qlog_binlog_frame, %s: %d frames, <%s>", test->name, frame_count, actual);
                ret = -1;
            }
        }
    }
    return ret;
}

static int qlog_binlog_frame_test(void)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < sizeof(qlog_binlog_frame_cases) / sizeof(qlog_binlog_frame_cases[0]); i++) {
        ret = qlog_binlog_frame_check(&qlog_binlog_frame_cases[i]);
    }
    return ret;
}

int qlog_frames_test(void)
{
    int ret = 0;
    char qlog_frames_test_ref[512];
    char const * need_comma = "";
    FILE* F = picoquic_file_open(QLOG_FRAMES_TEST, "w");
    if (F == NULL) {
        return -1;
    }
    fprintf(F, "[\n");
    for (size_t i = 0; i < nb_test_skip_list; i++) {
        test_skip_frames_t* test = &test_skip_list[i];
        const uint8_t* bytes = test->val;
        const uint8_t* bytes_max = test->val + test->len;

        fprintf(F, "%s{ \"test\": \"%s\", \"frame\": ", need_comma, test->name);
        need_comma = ",\n";

        // Write one line per frame
        qlog_frames(F, bytes, bytes_max, 0);
        fprintf(F, "}");
    }
    /* Also log a one-byte-short version of each good frame, to exercise the
     * "ran out of bytes mid-parse" branch of each per-frame-type qlog decoder --
     * same truncation idiom already used by logger_test and binlog_test. */
    for (size_t i = 0; i < nb_test_skip_list; i++) {
        test_skip_frames_t* test = &test_skip_list[i];
        if (test->len > 1 && !test->is_pure_ack) {
            const uint8_t* bytes = test->val;
            const uint8_t* bytes_max = test->val + test->len - 1;

            fprintf(F, "%s{ \"test\": \"%s_truncated\", \"frame\": ", need_comma, test->name);
            need_comma = ",\n";

            qlog_frames(F, bytes, bytes_max, 0);
            fprintf(F, "}");
        }
    }
    /* Also run the known-malformed frames, matching logger_test/binlog_test's
     * coverage of test_frame_error_list. */
    for (size_t i = 0; i < nb_test_frame_error_list; i++) {
        test_skip_frames_t* test = &test_frame_error_list[i];
        const uint8_t* bytes = test->val;
        const uint8_t* bytes_max = test->val + test->len;

        fprintf(F, "%s{ \"test\": \"%s\", \"frame\": ", need_comma, test->name);
        need_comma = ",\n";

        qlog_frames(F, bytes, bytes_max, 0);
        fprintf(F, "}");
    }
    fprintf(F, "\n]\n");
    (void)picoquic_file_close(F);


    ret = picoquic_get_input_path(qlog_frames_test_ref, sizeof(qlog_frames_test_ref), picoquic_solution_dir,
        QLOG_FRAMES_TEST_REF);

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the log ref file name.\n");
    }
    else {
        ret = picoquic_test_compare_text_files(qlog_frames_test_ref, QLOG_FRAMES_TEST);
    }

    if (ret == 0) {
        ret = qlog_binlog_frame_test();
    }

    return ret;
}
