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


#define QLOG_FRAMES_TEST_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "qlog_frames_test_ref.txt"
#define QLOG_FRAMES_TEST "qlog_frames_test.json"

// Forward declaration for the QLOG frame logging dispatcher
// Adjust the signature if your implementation differs
extern const uint8_t* qlog_frames(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max);

int qlog_frames_test()
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
        qlog_frames(F, bytes, bytes_max);
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

    return ret;
}
