/*
* Author: Christian Huitema
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

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "performance_log.h"
#include <string.h>

int picoquic_perflog_file_is_empty(char const* perflog_file_name);

/* picoquic_perflog_param_name's default case (rank outside the known columns) is never
 * exercised: every existing caller only ever passes values in [0, PICOQUIC_PERF_LOG_MAX_ITEMS). */
int perflog_param_name_test(void)
{
    int ret = 0;

    if (picoquic_perflog_param_name((picoquic_perflog_column_enum)0xffff) != NULL) {
        DBG_PRINTF("%s", "picoquic_perflog_param_name did not return NULL for an out-of-range rank");
        ret = -1;
    }
    return ret;
}

/* picoquic_perflog_file_is_empty is only ever called, in existing tests, on a file that does
 * not exist yet (via picoquic_perflog_setup, on the first run). Check both outcomes directly
 * on a real file: freshly created (empty) and after writing to it (not empty). */
int perflog_file_is_empty_test(void)
{
    int ret = 0;
    char const* file_name = "perflog_file_is_empty_test.txt";
    FILE* F = picoquic_file_open(file_name, "w");

    if (F == NULL) {
        ret = -1;
    }
    else {
        picoquic_file_close(F);
        if (!picoquic_perflog_file_is_empty(file_name)) {
            DBG_PRINTF("%s", "picoquic_perflog_file_is_empty reported a freshly created file as not empty");
            ret = -1;
        }
    }

    if (ret == 0 && (F = picoquic_file_open(file_name, "w")) == NULL) {
        ret = -1;
    }
    else if (ret == 0) {
        fprintf(F, "not empty\n");
        picoquic_file_close(F);
        if (picoquic_perflog_file_is_empty(file_name)) {
            DBG_PRINTF("%s", "picoquic_perflog_file_is_empty reported a non-empty file as empty");
            ret = -1;
        }
    }

    return ret;
}

/* picoquic_perflog_record's "append to an existing list" branch, and picoquic_perflog_free's
 * "still has queued items" cleanup loop, are only reached when a perflog context accumulates
 * more than one entry before being saved or freed. The only existing tests run a single
 * connection per perflog context, which always takes the "save immediately" path (this
 * connection is both the first and the last one on the QUIC context) -- so neither of those
 * branches is otherwise reachable. Set up two connections on the same context, record both
 * directly (bypassing real connection deletion, which is what would normally trigger the
 * auto-save), then force a free while both records are still pending. */
int perflog_multi_cnx_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx1 = NULL;
    picoquic_cnx_t* cnx2 = NULL;
    uint64_t simulated_time = 0;
    char const* perflog_file = "perflog_multi_cnx_test.csv";

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx1, &simulated_time) != 0) {
        ret = -1;
    }
    else if (picoquic_perflog_setup(quic, perflog_file) != 0) {
        ret = -1;
    }
    else {
        cnx2 = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
            NULL, simulated_time, 0, PICOQUIC_TEST_SNI, "minimal", 1);
        if (cnx2 == NULL) {
            ret = -1;
        }
    }

    if (ret == 0 && quic->perflog_fn(quic, cnx1, 0) != 0) {
        DBG_PRINTF("%s", "Recording the first connection unexpectedly failed");
        ret = -1;
    }
    if (ret == 0 && quic->perflog_fn(quic, cnx2, 0) != 0) {
        DBG_PRINTF("%s", "Recording the second connection unexpectedly failed");
        ret = -1;
    }
    if (ret == 0) {
        /* Force cleanup while both records are still queued. */
        (void)quic->perflog_fn(quic, NULL, 1);
    }

    picoquic_test_delete_minimal_cnx(&quic, &cnx1);

    return ret;
}
