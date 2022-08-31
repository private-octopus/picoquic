/*
* Author: Christian Huitema
* Copyright (c) 2022, Private Octopus, Inc.
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
#include "picoquic_utils.h"
#include "picosocks.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "picoquic_binlog.h"
#include "logreader.h"
#include "qlog.h"

static test_api_stream_desc_t test_scenario_l4s[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 257, 1000000 },
    { 12, 8, 257, 1000000 },
    { 16, 12, 257, 1000000 }
};


static int l4s_congestion_test(picoquic_congestion_algorithm_t* ccalgo, uint64_t max_completion_time, uint64_t max_losses, uint64_t max_rttvar)
{
    uint64_t simulated_time = 0;
    uint64_t queue_delay_max = 20000;
    uint64_t l4s_max = queue_delay_max / 4;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x45, 0xcc, 0, 0, 0, 0, 0, 0}, 8 };
    int ret;

    initial_cid.id[2] = ccalgo->congestion_algorithm_number;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the congestion algorithm to specified value.
     * Initialize L4S behavior.
     * Request a packet trace */
    if (ret == 0) {

        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);


        if (strcmp(ccalgo->congestion_algorithm_id, "prague") == 0) {
            test_ctx->c_to_s_link->l4s_max = l4s_max;
            test_ctx->s_to_c_link->l4s_max = l4s_max;
            test_ctx->packet_ecn_default = PICOQUIC_ECN_ECT_0;
        }
        picoquic_set_binlog(test_ctx->qserver, ".");

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_l4s, sizeof(test_scenario_l4s), 0, 0, 0, queue_delay_max, max_completion_time);
    }

    /* Verify that L4S ECN feedback was received properly */
    /* verify that the delay meets target requirements */
    /* Verify that the losses are as expected, "low loss" part of L4S */
    if (ret == 0) {
        if (test_ctx->cnx_server == NULL) {
            DBG_PRINTF("%s", "Cannot assess server connection");
            ret = -1;
        }
        else if (test_ctx->cnx_server->nb_retransmission_total > max_losses) {
            DBG_PRINTF("Noted %" PRIu64 " losses, expected maximum %" PRIu64, test_ctx->cnx_server->nb_retransmission_total, max_losses);
            ret = -1;
        }
        else if (test_ctx->cnx_server->path[0]->rtt_variant > max_rttvar) {
            DBG_PRINTF("RTT variant %" PRIu64 ", expected maximum %" PRIu64, test_ctx->cnx_server->path[0]->rtt_variant, max_rttvar);
            ret = -1;
        }
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* This test is used for reference. Perf is bad, because each CE mark is
 * a congestion mark.
 */
int l4s_reno_test()
{
    picoquic_congestion_algorithm_t* ccalgo = picoquic_newreno_algorithm;

    int ret = l4s_congestion_test(ccalgo, 3550000, 50, 9000);

    return ret;
}

int l4s_prague_test()
{
    picoquic_congestion_algorithm_t* ccalgo = picoquic_prague_algorithm;

    int ret = l4s_congestion_test(ccalgo, 3500000, 5, 6000);

    return ret;
}