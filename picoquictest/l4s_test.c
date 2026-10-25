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
#include "picoquic_qlog.h"
#include "picoquic_newreno.h"
#include "picoquic_cubic.h"
#include "picoquic_bbr.h"
#include "picoquic_bbr1.h"
#include "picoquic_prague.h"
#include "c4.h"

#include "picoquictest_dualq.h"

static test_api_stream_desc_t test_scenario_l4s[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 257, 1000000 },
    { 12, 8, 257, 1000000 },
    { 16, 12, 257, 1000000 }
};


/* Optional settings of l4s_congestion_test. If data_size is set, the
 * scenario is a single download of that size instead of test_scenario_l4s.
 * If max_th is set, the L4S queue marks with a probability rising from 0
 * at min_th to 1 at max_th of sojourn time, a step if both are equal,
 * instead of the dualq default derived from max_rttvar. If queue_delay_max
 * is set, it replaces the default of twice the link latency.
 */
typedef struct st_l4s_test_options_t {
    size_t data_size;
    uint64_t min_th;
    uint64_t max_th;
    uint64_t queue_delay_max;
} l4s_test_options_t;

static int l4s_congestion_test(picoquic_congestion_algorithm_t* ccalgo, int do_l4s, uint64_t max_completion_time, uint64_t max_losses, uint64_t max_rttvar,
    size_t nb_link_states, test_vary_link_spec_t* link_state, const l4s_test_options_t* options)
{
    uint64_t simulated_time = 0;
    uint64_t queue_delay_max = 20000;
    uint64_t l4s_max = max_rttvar;
    test_api_stream_desc_t* scenario = test_scenario_l4s;
    size_t sizeof_scenario = sizeof(test_scenario_l4s);
    test_api_stream_desc_t single_stream = { 4, 0, 257, 0 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x45, 0xcc, 0, 0, 0, 0, 0, 0}, 8 };
    int ret;

    initial_cid.id[2] = ccalgo->congestion_algorithm_number;
    initial_cid.id[3] = (uint8_t)nb_link_states;

    for (size_t i = 0; i < nb_link_states; i++) {
        if (2 * link_state[i].microsec_latency > queue_delay_max) {
            queue_delay_max = 2 * link_state[i].microsec_latency;
            /* l4s_max = link_state->microsec_latency / 4; */
        }
    }

    if (options != NULL) {
        initial_cid.id[4] = (uint8_t)(options->min_th / 100);
        initial_cid.id[5] = (uint8_t)(options->max_th / 100);
        if (options->data_size > 0) {
            single_stream.r_len = options->data_size;
            scenario = &single_stream;
            sizeof_scenario = sizeof(single_stream);
        }
        if (options->max_th > 0) {
            l4s_max = options->max_th;
        }
        if (options->queue_delay_max > 0) {
            queue_delay_max = options->queue_delay_max;
        }
    }

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }
    else {
        test_ctx->c_to_s_link->queue_delay_max = queue_delay_max;
        test_ctx->s_to_c_link->queue_delay_max = queue_delay_max;
    }

    /* Set the congestion algorithm to specified value.
     * Initialize L4S behavior.
     * Request a packet trace */
    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qclient, ccalgo);
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);


        if (do_l4s) {
            test_ctx->ecn_support = 1;
            test_ctx->packet_ecn_default = PICOQUIC_ECN_ECT_1;
            /* The dualq buffer is sized from the link rate and latency. */
            if (nb_link_states > 0) {
                (void)test_vary_link(test_ctx, simulated_time, link_state);
            }
            if ((ret = dualq_configure(test_ctx->c_to_s_link, l4s_max)) == 0) {
                ret = dualq_configure(test_ctx->s_to_c_link, l4s_max);
            }
            if (ret == 0 && options != NULL && options->max_th > 0) {
                dualq_state_t* dqs[2] = { (dualq_state_t*)test_ctx->c_to_s_link->aqm_state,
                    (dualq_state_t*)test_ctx->s_to_c_link->aqm_state };

                for (int i = 0; i < 2; i++) {
                    dqs[i]->minTh = options->min_th;
                    dqs[i]->range = options->max_th - options->min_th;
                }
            }
        }

        if (ret == 0) {
            picoquic_set_qlog(test_ctx->qserver, ".");

            ret = tls_api_one_scenario_body_ex(test_ctx, &simulated_time,
                scenario, sizeof_scenario, 0, 0, 0, queue_delay_max, max_completion_time, nb_link_states, link_state);
        }
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
int l4s_reno_test(void)
{
    picoquic_congestion_algorithm_t* ccalgo = picoquic_newreno_algorithm;

    int ret = l4s_congestion_test(ccalgo, 1, 5600000, 45, 3000, 0, NULL, NULL);

    return ret;
}

int l4s_prague_test(void)
{
    picoquic_congestion_algorithm_t* ccalgo = picoquic_prague_algorithm;

    int ret = l4s_congestion_test(ccalgo, 1, 4300000, 9, 4500, 0, NULL, NULL);

    return ret;
}

int l4s_bbr_test(void)
{
    picoquic_congestion_algorithm_t* ccalgo = picoquic_bbr_algorithm;

    int ret = l4s_congestion_test(ccalgo, 1, 3800000, 21, 3000, 0, NULL, NULL);

    return ret;
}


int l4s_bbr1_test(void)
{
    picoquic_congestion_algorithm_t* ccalgo = picoquic_bbr1_algorithm;

    int ret = l4s_congestion_test(ccalgo, 1, 3600000, 150, 3000, 0, NULL, NULL);

    return ret;
}

int l4s_c4_test(void)
{
    picoquic_congestion_algorithm_t* ccalgo = c4_algorithm;

    int ret = l4s_congestion_test(ccalgo, 1, 3650000, 50, 3000, 0, NULL, NULL);

    return ret;
}

test_vary_link_spec_t l4s_link_updown[] = {
    { 1000000, 10000000, 10000000, 10000},
    { 2000000,  2000000,  2000000, 10000},
    { 8000000, 10000000, 10000000, 10000},
};

size_t nb_l4s_link_updown = sizeof(l4s_link_updown) / sizeof(test_vary_link_spec_t);

int l4s_prague_updown_test(void)
{
    picoquic_congestion_algorithm_t* ccalgo = picoquic_prague_algorithm;

    int ret = l4s_congestion_test(ccalgo, 1, 6300000, 55, 6000, nb_l4s_link_updown, l4s_link_updown, NULL);

    return ret;
}

int l4s_bbr_updown_test(void)
{
#if defined(_WINDOWS) && !defined(_WINDOWS64)
    return 0;
#else
    picoquic_congestion_algorithm_t* ccalgo = picoquic_bbr_algorithm;

    int ret = l4s_congestion_test(ccalgo, 1, 5800000, 80, 3000, nb_l4s_link_updown, l4s_link_updown, NULL);

    return ret;
#endif
}

/* 100 Mbps links for the Prague tests, by RTT. */
static test_vary_link_spec_t l4s_link_100mbps_20ms[] = {
    { 60000000, 100000000, 100000000, 10000 }
};

static test_vary_link_spec_t l4s_link_100mbps_40ms[] = {
    { 60000000, 100000000, 100000000, 20000 }
};

/* A 1 ms marking step at 20 ms RTT. Pacing bursts longer than the step get
 * marked even when there is no standing queue.
 */
int l4s_prague_shallow_test(void)
{
    l4s_test_options_t options = { 50000000, 1000, 1000, 0 };

    return l4s_congestion_test(picoquic_prague_algorithm, 1, 6000000, 50, 1000, 1, l4s_link_100mbps_20ms, &options);
}

/* The RFC 9332 ramp from 3 to 6 ms at 40 ms RTT, with a 100 ms buffer so
 * that the slow start overshoot is marked rather than dropped. The window
 * must not be reduced a second time for that overshoot, since recovering
 * by one packet per RTT takes seconds at that RTT.
 */
int l4s_prague_long_rtt_test(void)
{
    l4s_test_options_t options = { 50000000, 3000, 6000, 120000 };

    return l4s_congestion_test(picoquic_prague_algorithm, 1, 5000000, 10, 6000, 1, l4s_link_100mbps_40ms, &options);
}
