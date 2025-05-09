/*
* Author: Matthias Hofstaetter
* Copyright (c) 2025, Matthias Hofstaetter
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

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <stddef.h>
#include "picoquic_binlog.h"
#include "autoqlog.h"
#include "picoquictest.h"
#include "picoquic_bbr.h"
#include "picoquic_bbr1.h"
#include "picoquic_cubic.h"
#include "picoquic_fastcc.h"
#include "picoquic_newreno.h"
#include "picoquic_prague.h"

static int hystart_test_one(picoquic_congestion_algorithm_t* ccalgo, picoquic_hystart_alg_t hystart_algo, size_t data_size, uint64_t max_completion_time,
                            uint64_t datarate, uint64_t latency, uint64_t jitter, uint64_t queue_delay_max)
{
    uint64_t simulated_time = 0;
    uint64_t picoseq_per_byte = (1000000ull * 8) / datarate;
    picoquic_connection_id_t initial_cid = { {0x08, 0x22, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = 0;

    initial_cid.id[2] = ccalgo->congestion_algorithm_number;
    initial_cid.id[3] = hystart_algo;
    initial_cid.id[4] = (datarate > 0xff) ? 0xff : (uint8_t)datarate;
    initial_cid.id[5] = (latency > 2550000) ? 0xff : (uint8_t)(latency / 10000);
    initial_cid.id[6] = (jitter > 255000) ? 0xff : (uint8_t)(jitter / 1000);
    initial_cid.id[7] = (queue_delay_max > 255000) ? 0xff : (uint8_t)(queue_delay_max / 1000);

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        /* Set CC algo. */
        const char* option_string = "Y0";
        switch (hystart_algo) {
            case picoquic_hystart_alg_hystart_pp_t:
                option_string = "Y1";
                break;
            case picoquic_hystart_alg_disabled_t:
                option_string = "Y2";
                break;
            default:
                break;
        }
        picoquic_set_default_congestion_algorithm_ex(test_ctx->qserver, ccalgo, option_string);
        picoquic_set_congestion_algorithm_ex(test_ctx->cnx_client, ccalgo, option_string);

        /* Configure links. */
        test_ctx->c_to_s_link->jitter = jitter;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte;
        test_ctx->s_to_c_link->jitter = jitter;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte;
        test_ctx->stream0_flow_release = 1;
        test_ctx->immediate_exit = 1;

        /* set the binary log on the client side */
        picoquic_set_qlog(test_ctx->qclient, ".");
        test_ctx->qclient->use_long_log = 1;
        /* Since the client connection was created before the binlog was set, force log of connection header */
        binlog_new_connection(test_ctx->cnx_client);

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            NULL, 0, data_size, 0, 0, queue_delay_max, max_completion_time);
    }

    /* Free the resource, which will close the log file. */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int hystart_test() {
    picoquic_congestion_algorithm_t* ccalgos[] = {
        picoquic_newreno_algorithm,
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        //picoquic_fastcc_algorithm,
        picoquic_bbr_algorithm,
        picoquic_prague_algorithm,
        picoquic_bbr1_algorithm
    };
    uint64_t max_completion_times[] = {
        10000000,
        10500000,
        10500000,
        //21000,
        10000000,
        10000000,
        10000000
    };
    int ret = 0;

    for (size_t i = 0; i < sizeof(ccalgos) / sizeof(picoquic_congestion_algorithm_t*) && !ret; i++) {
        for (picoquic_hystart_alg_t hystart_alg = picoquic_hystart_alg_hystart_t; hystart_alg <= picoquic_hystart_alg_disabled_t && !ret; hystart_alg++) {
            ret = hystart_test_one(ccalgos[i], hystart_alg, 50000000, max_completion_times[i], 50, 125000, 0, 125000 * 10);
            if (ret != 0) {
                DBG_PRINTF("HyStart test fails for <%s><%i>", ccalgos[i]->congestion_algorithm_id, hystart_alg);
            }
        }
    }

    return ret;
}