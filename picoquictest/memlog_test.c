/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
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
#include "picoquic.h"
#include "auto_memlog.h"

/* testing the "memory log" function.
 */
#define MEMLOG_FILE "memlog_file.csv"
#ifdef _WINDOWS
#define MEMLOG_TEST_REF "picoquictest\\memlog_test_ref.csv"
#else
#define MEMLOG_TEST_REF "picoquictest/memlog_test_ref.csv"
#endif

//void memlog_call_back(picoquic_cnx_t* cnx, picoquic_path_t* path, void* v_memlog, int op_code, uint64_t current_time);

static test_api_stream_desc_t test_scenario_memlog[] = {
    { 4, 0, 100000, 100000 }
};

int memlog_test_one()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    int nb_inactive = 0;
    int nb_trials = 0;
    int was_active = 0;
    uint64_t picosec_per_byte = (1000000ull * 8) / 10;
    uint64_t queue_delay_max = 40000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x8e, 0x10, 0x97, 0xe5, 0x70, 0, 0, 0}, 8 };
    int ret = 0;

    if (ret == 0) {
        ret = tls_api_init_ctx_ex2(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid, 8, 0, 0, 0);

        if (ret == 0) {
            /* Initialize memory log on client or server */
            ret = memlog_init(test_ctx->cnx_client, 100, MEMLOG_FILE);
        }
    }

    if (ret == 0) {
        picoquic_start_client_cnx(test_ctx->cnx_client);
        ret = tls_api_connection_loop(test_ctx, &loss_mask, queue_delay_max, &simulated_time);
    }

    if (ret == 0) {
        /* Prepare to send data */
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_memlog, sizeof(test_scenario_memlog));
    }

    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        /* Progress. */
#if 1
        if (nb_trials == 8431) {
            DBG_PRINTF("%s", "bug");
        }
#endif
        if ((ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active)) != 0) {
            break;
        }

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }

        if (test_ctx->test_finished) {
            if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) && picoquic_is_cnx_backlog_empty(test_ctx->cnx_server)) {
                break;
            }
        }

        if (++nb_trials > 1000000 || nb_inactive > 1024) {
            ret = -1;
            break;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* compare the log file to the expected value */
    if (ret == 0)
    {
        char memlog_test_ref[512];

        ret = picoquic_get_input_path(memlog_test_ref, sizeof(memlog_test_ref),
            picoquic_solution_dir, MEMLOG_TEST_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the qlog trace test ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(MEMLOG_FILE, memlog_test_ref);
        }
    }

    return ret;
}

int memlog_test()
{
    int ret = memlog_test_one();

    return ret;
}