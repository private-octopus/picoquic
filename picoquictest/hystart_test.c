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
#include "cc_common.h"

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

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, &initial_cid);

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

int hystart_test(void) {
    picoquic_congestion_algorithm_t* ccalgos[] = {
        picoquic_newreno_algorithm,
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        //picoquic_fastcc_algorithm,
        picoquic_bbr_algorithm,
        picoquic_prague_algorithm,
        picoquic_bbr1_algorithm
    };
    uint64_t max_completion_times[][3] = {
        /* hystart     hystart++   disabled */
        {10000000,  10000000,   10000000},  /* newreno */
        {10500000,  10500000,   10500000},  /* cubic */
        {10500000,  10500000,   10500000},  /* dcubic */
        //21000,
        {10000000,  10000000,   10000000},  /* bbr */
        {10000000,  10000000,   10000000}, /* prague */
        {10000000,  10000000,   10000000}   /* bbr1 */
    };
    int ret = 0;

    for (size_t i = 0; i < sizeof(ccalgos) / sizeof(picoquic_congestion_algorithm_t*) && !ret; i++) {
        for (picoquic_hystart_alg_t hystart_alg = picoquic_hystart_alg_hystart_t; hystart_alg <= picoquic_hystart_alg_disabled_t && !ret; hystart_alg++) {
            ret = hystart_test_one(ccalgos[i], hystart_alg, 50000000, max_completion_times[i][hystart_alg], 50, 125000, 0, 125000 * 10);
            if (ret != 0) {
                DBG_PRINTF("HyStart test fails for <%s><%i>", ccalgos[i]->congestion_algorithm_id, hystart_alg);
            }
        }
    }

    return ret;
}

/*
 * Slow start mechanism tests.
 *
 * Three mechanisms can be selected per congestion controller through the option
 * string: "Y0" = HyStart (default), "Y1" = HyStart++ (RFC 9406), "Y2" = disabled
 * (plain slow start, exit on loss only).
 *
 * HyStart++ measures rounds with windowEnd = SND.NXT: the round ends when windowEnd
 * is acknowledged. The helpers below keep send_sequence far enough ahead that the
 * packet closing a round is exactly the last one acknowledged in a batch of
 * N_RTT_SAMPLE acks. Each batch is thus one full round with N_RTT_SAMPLE RTT
 * samples; the SS/CSS test is evaluated on its last ack, just before the round
 * boundary is processed.
 */

#define HYSTART_TEST_ACKS_PER_ROUND PICOQUIC_HYSTART_PP_N_RTT_SAMPLE

typedef struct st_hystart_test_round_ctx_t {
    picoquic_cnx_t* cnx;
    picoquic_path_t* path_x;
    /* State machine test: direct calls into cc_common. */
    picoquic_hystart_pp_state_t* pp_state;
    /* CC level test: notifications to the congestion controller. */
    uint64_t* simulated_time;
    uint64_t time_step;
    uint64_t nb_bytes;
    /* cwin growth observed on each ack of the last round. */
    int64_t delta[HYSTART_TEST_ACKS_PER_ROUND];
} hystart_test_round_ctx_t;

static picoquic_packet_context_t* hystart_test_pkt_ctx(hystart_test_round_ctx_t* rc)
{
    return &rc->cnx->pkt_ctx[picoquic_packet_context_application];
}

/* Acknowledge the next packet with the given RTT sample.
 * Returns the HyStart++ "enter CA" verdict in the state machine test, 0 otherwise. */
static int hystart_test_ack_one(hystart_test_round_ctx_t* rc, uint64_t rtt)
{
    int ret = 0;

    hystart_test_pkt_ctx(rc)->highest_acknowledged += 1;

    if (rc->pp_state != NULL) {
        ret = picoquic_cc_hystart_pp_test(rc->pp_state, rc->cnx, rc->path_x, rtt);
    }
    else {
        picoquic_per_ack_state_t ack_state = { 0 };

        *rc->simulated_time += rc->time_step;
        ack_state.rtt_measurement = rtt;
        rc->cnx->congestion_alg->alg_notify(rc->cnx, rc->path_x,
            picoquic_congestion_notification_rtt_measurement, &ack_state, *rc->simulated_time);
        ack_state.nb_bytes_acknowledged = rc->nb_bytes;
        rc->cnx->congestion_alg->alg_notify(rc->cnx, rc->path_x,
            picoquic_congestion_notification_acknowledgement, &ack_state, *rc->simulated_time);
    }

    return ret;
}

/* Acknowledge the packet carrying the initial windowEnd (packet 0), so that the
 * following rounds are aligned on batch boundaries. */
static void hystart_test_prime(hystart_test_round_ctx_t* rc, uint64_t rtt)
{
    hystart_test_pkt_ctx(rc)->send_sequence = HYSTART_TEST_ACKS_PER_ROUND;
    (void)hystart_test_ack_one(rc, rtt);
}

/* Keep two rounds in flight: the boundary processed on the last ack of the
 * current round then sets windowEnd to the last packet of the next round. */
static void hystart_test_round_start(hystart_test_round_ctx_t* rc)
{
    picoquic_packet_context_t* pkt_ctx = hystart_test_pkt_ctx(rc);
    uint64_t first = pkt_ctx->highest_acknowledged + 1;

    pkt_ctx->send_sequence = first + 2 * HYSTART_TEST_ACKS_PER_ROUND - 1;
}

/* Acknowledge one full round with the same RTT sample on every ack.
 * Returns the number of acks on which HyStart++ asked to enter CA (state machine test). */
static int hystart_test_round(hystart_test_round_ctx_t* rc, uint64_t rtt)
{
    int nb_exit = 0;

    hystart_test_round_start(rc);

    for (int k = 0; k < HYSTART_TEST_ACKS_PER_ROUND; k++) {
        uint64_t cwin_before = rc->path_x->cwin;
        nb_exit += hystart_test_ack_one(rc, rtt);
        rc->delta[k] = (int64_t)rc->path_x->cwin - (int64_t)cwin_before;
    }

    return nb_exit;
}

/*
 * HyStart++ state machine (RFC 9406, section 4.2), driven directly through cc_common.
 */

/* Two flat rounds after a reset make lastRoundMinRTT valid, then one round at
 * probe_rtt; returns 0 if the SS/CSS decision matches expect_css. */
static int hystart_pp_threshold_check(hystart_test_round_ctx_t* rc, uint64_t base_rtt, uint64_t probe_rtt, int expect_css)
{
    int ret = 0;

    picoquic_hystart_pp_reset(rc->pp_state, rc->cnx, rc->path_x);
    (void)hystart_test_round(rc, base_rtt);
    (void)hystart_test_round(rc, base_rtt);
    (void)hystart_test_round(rc, probe_rtt);

    if ((IS_IN_CSS((*rc->pp_state)) != 0) != (expect_css != 0)) {
        DBG_PRINTF("HyStart++ base RTT %" PRIu64 ", probe RTT %" PRIu64 ": in CSS = %d, expected %d",
            base_rtt, probe_rtt, IS_IN_CSS((*rc->pp_state)) != 0, expect_css);
        ret = -1;
    }

    return ret;
}

int hystart_pp_state_test(void)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    picoquic_hystart_pp_state_t pp;
    hystart_test_round_ctx_t rc;
    int ret = 0;

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        return -1;
    }

    memset(&pp, 0, sizeof(pp));
    memset(&rc, 0, sizeof(rc));
    rc.cnx = cnx;
    rc.path_x = cnx->path[0];
    rc.pp_state = &pp;

    /* Initial state: all RTT trackers at infinity, windowEnd = SND.NXT. */
    picoquic_hystart_pp_reset(&pp, cnx, cnx->path[0]);
    if (pp.current_round.last_round_min_rtt != UINT64_MAX ||
        pp.current_round.current_round_min_rtt != UINT64_MAX ||
        pp.current_round.rtt_sample_count != 0 ||
        pp.current_round.window_end != hystart_test_pkt_ctx(&rc)->send_sequence ||
        pp.css_baseline_min_rtt != UINT64_MAX ||
        pp.css_round_count != 0) {
        DBG_PRINTF("%s", "HyStart++ reset does not initialize the state as expected");
        ret = -1;
    }

    /* Flat RTT: stays in standard slow start, lastRoundMinRTT tracks the rounds. */
    if (ret == 0) {
        hystart_test_prime(&rc, 100000);
        for (int r = 0; ret == 0 && r < 4; r++) {
            if (hystart_test_round(&rc, 100000) != 0 || IS_IN_CSS(pp)) {
                DBG_PRINTF("Flat RTT, round %d: unexpected exit from slow start", r);
                ret = -1;
            }
        }
        if (ret == 0 && (pp.current_round.last_round_min_rtt != 100000 ||
            pp.current_round.current_round_min_rtt != UINT64_MAX ||
            pp.current_round.rtt_sample_count != 0)) {
            DBG_PRINTF("After flat rounds: last_round_min_rtt=%" PRIu64 ", current_round_min_rtt=%" PRIu64 ", sample_count=%" PRIu64,
                pp.current_round.last_round_min_rtt, pp.current_round.current_round_min_rtt, pp.current_round.rtt_sample_count);
            ret = -1;
        }
    }

    /* RTT increase below RttThresh (100ms / MIN_RTT_DIVISOR = 12.5ms): still slow start. */
    if (ret == 0) {
        if (hystart_test_round(&rc, 112000) != 0 || IS_IN_CSS(pp)) {
            DBG_PRINTF("%s", "RTT increase below threshold triggered CSS");
            ret = -1;
        }
    }

    /* Fewer than N_RTT_SAMPLE samples: no decision, even with a large increase.
     * (RttThresh is now 112ms / 8 = 14ms, 130ms is well above 126ms.) */
    if (ret == 0) {
        int nb_exit = 0;

        hystart_test_round_start(&rc);
        for (int k = 0; k < HYSTART_TEST_ACKS_PER_ROUND / 2; k++) {
            nb_exit += hystart_test_ack_one(&rc, 130000);
        }
        if (nb_exit != 0 || IS_IN_CSS(pp) || pp.current_round.rtt_sample_count != HYSTART_TEST_ACKS_PER_ROUND / 2) {
            DBG_PRINTF("Decision taken with only %" PRIu64 " RTT samples", pp.current_round.rtt_sample_count);
            ret = -1;
        }
        /* Completing the round (N_RTT_SAMPLE samples) enters CSS; the partial round counts. */
        for (int k = 0; ret == 0 && k < HYSTART_TEST_ACKS_PER_ROUND / 2; k++) {
            nb_exit += hystart_test_ack_one(&rc, 130000);
        }
        if (ret == 0 && (nb_exit != 0 || !IS_IN_CSS(pp) || pp.css_baseline_min_rtt != 130000 || pp.css_round_count != 1)) {
            DBG_PRINTF("After RTT increase: in CSS = %d, baseline = %" PRIu64 ", css rounds = %" PRIu64 ", exit = %d",
                IS_IN_CSS(pp) != 0, pp.css_baseline_min_rtt, pp.css_round_count, nb_exit);
            ret = -1;
        }
    }

    /* CSS lasts CSS_ROUNDS rounds, then HyStart++ asks to enter congestion avoidance. */
    for (uint64_t r = 2; ret == 0 && r <= PICOQUIC_HYSTART_PP_CSS_ROUNDS; r++) {
        int nb_exit = hystart_test_round(&rc, 130000);
        int expected = (r == PICOQUIC_HYSTART_PP_CSS_ROUNDS) ? 1 : 0;

        if (nb_exit != expected || !IS_IN_CSS(pp) || pp.css_round_count != r) {
            DBG_PRINTF("CSS round %" PRIu64 ": exit = %d (expected %d), css rounds = %" PRIu64 ", in CSS = %d",
                r, nb_exit, expected, pp.css_round_count, IS_IN_CSS(pp) != 0);
            ret = -1;
        }
    }

    /* Spurious exit: the RTT drops below the CSS baseline, slow start resumes and
     * the next CSS phase gets the full CSS_ROUNDS again. */
    if (ret == 0) {
        int nb_exit = 0;

        picoquic_hystart_pp_reset(&pp, cnx, cnx->path[0]);
        (void)hystart_test_round(&rc, 100000);
        (void)hystart_test_round(&rc, 100000);
        nb_exit += hystart_test_round(&rc, 130000);
        nb_exit += hystart_test_round(&rc, 130000);
        if (nb_exit != 0 || !IS_IN_CSS(pp) || pp.css_round_count != 2) {
            DBG_PRINTF("Before spurious exit: in CSS = %d, css rounds = %" PRIu64, IS_IN_CSS(pp) != 0, pp.css_round_count);
            ret = -1;
        }
        if (ret == 0) {
            nb_exit += hystart_test_round(&rc, 100000);
            if (nb_exit != 0 || IS_IN_CSS(pp) || pp.css_round_count != 0) {
                DBG_PRINTF("After spurious exit: in CSS = %d, css rounds = %" PRIu64 ", exit = %d",
                    IS_IN_CSS(pp) != 0, pp.css_round_count, nb_exit);
                ret = -1;
            }
        }
        for (uint64_t r = 1; ret == 0 && r <= PICOQUIC_HYSTART_PP_CSS_ROUNDS; r++) {
            int expected = (r == PICOQUIC_HYSTART_PP_CSS_ROUNDS) ? 1 : 0;

            nb_exit = hystart_test_round(&rc, 130000);
            if (nb_exit != expected || !IS_IN_CSS(pp) || pp.css_round_count != r) {
                DBG_PRINTF("Second CSS phase, round %" PRIu64 ": exit = %d (expected %d), css rounds = %" PRIu64,
                    r, nb_exit, expected, pp.css_round_count);
                ret = -1;
            }
        }
    }

    /* RttThresh clamping: MIN_RTT_THRESH (4ms) for short RTT, MAX_RTT_THRESH (16ms) for long RTT. */
    if (ret == 0) {
        ret = hystart_pp_threshold_check(&rc, 10000, 10000 + PICOQUIC_HYSTART_PP_MIN_RTT_THRESH - 1, 0);
    }
    if (ret == 0) {
        ret = hystart_pp_threshold_check(&rc, 10000, 10000 + PICOQUIC_HYSTART_PP_MIN_RTT_THRESH, 1);
    }
    if (ret == 0) {
        ret = hystart_pp_threshold_check(&rc, 200000, 200000 + PICOQUIC_HYSTART_PP_MAX_RTT_THRESH - 1, 0);
    }
    if (ret == 0) {
        ret = hystart_pp_threshold_check(&rc, 200000, 200000 + PICOQUIC_HYSTART_PP_MAX_RTT_THRESH, 1);
    }

    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/*
 * Slow start mechanisms at the congestion controller level.
 *
 * Each controller is fed RTT and ACK notifications directly: two flat rounds, then
 * rounds with the RTT raised by 30ms (above both the HyStart threshold, rtt/4, and
 * the HyStart++ threshold, rtt/8). Expected per mechanism:
 * - disabled: never leaves slow start, cwin grows by the acked bytes on every ack.
 * - HyStart: leaves slow start within a few rounds of the RTT increase.
 * - HyStart++: enters CSS at the end of the first raised round (growth divided by
 *   CSS_GROWTH_DIVISOR), enters congestion avoidance at the end of the CSS_ROUNDS-th
 *   CSS round, and grows slower than slow start afterwards.
 */

typedef struct st_hystart_cc_case_t {
    picoquic_congestion_algorithm_t* ccalgo;
    uint64_t ss_state; /* alg_observe state value while in the initial slow start */
    int check_ca_growth; /* per ack growth after the exit must be below slow start growth */
    int check_ssthresh_flag; /* path->is_ssthresh_initialized tracks the exit */
} hystart_cc_case_t;

#define HYSTART_CC_DELTA_ANY (-1)
#define HYSTART_CC_DELTA_BELOW_SS (-2)

static int hystart_cc_check(const hystart_cc_case_t* c, hystart_test_round_ctx_t* rc, const char* option_string,
    const char* phase, int expect_in_ss, int64_t expected_delta)
{
    uint64_t cc_state = 0;
    uint64_t cc_param = 0;
    int in_ss;
    int64_t delta = rc->delta[HYSTART_TEST_ACKS_PER_ROUND / 2];
    int ret = 0;

    rc->cnx->congestion_alg->alg_observe(rc->path_x, &cc_state, &cc_param);
    in_ss = (cc_state == c->ss_state);

    if (in_ss != expect_in_ss) {
        DBG_PRINTF("%s <%s> %s: cc_state = %" PRIu64 ", expected %s slow start",
            c->ccalgo->congestion_algorithm_id, option_string, phase, cc_state, (expect_in_ss) ? "in" : "out of");
        ret = -1;
    }
    else if (c->check_ssthresh_flag && (rc->path_x->is_ssthresh_initialized != 0) != (expect_in_ss == 0)) {
        DBG_PRINTF("%s <%s> %s: is_ssthresh_initialized = %d, expected %d",
            c->ccalgo->congestion_algorithm_id, option_string, phase, rc->path_x->is_ssthresh_initialized, expect_in_ss == 0);
        ret = -1;
    }
    else if (expected_delta >= 0 && delta != expected_delta) {
        DBG_PRINTF("%s <%s> %s: cwin grows by %" PRId64 " per ack, expected %" PRId64,
            c->ccalgo->congestion_algorithm_id, option_string, phase, delta, expected_delta);
        ret = -1;
    }
    else if (expected_delta == HYSTART_CC_DELTA_BELOW_SS && delta >= (int64_t)rc->nb_bytes) {
        DBG_PRINTF("%s <%s> %s: cwin grows by %" PRId64 " per ack, expected less than %" PRIu64,
            c->ccalgo->congestion_algorithm_id, option_string, phase, delta, rc->nb_bytes);
        ret = -1;
    }

    return ret;
}

static int hystart_cc_test_one(const hystart_cc_case_t* c, picoquic_hystart_alg_t hystart_alg, const char* option_string)
{
    const uint64_t base_rtt = 100000;
    const uint64_t high_rtt = base_rtt + 30000;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    hystart_test_round_ctx_t rc;
    int64_t nb_bytes;
    int ret = 0;

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        return -1;
    }

    picoquic_set_congestion_algorithm_ex(cnx, c->ccalgo, option_string);

    memset(&rc, 0, sizeof(rc));
    rc.cnx = cnx;
    rc.path_x = cnx->path[0];
    rc.simulated_time = &simulated_time;
    rc.time_step = base_rtt / HYSTART_TEST_ACKS_PER_ROUND;
    rc.nb_bytes = rc.path_x->send_mtu;
    nb_bytes = (int64_t)rc.nb_bytes;

    /* Not app limited, not sender limited, path RTT known. */
    cnx->cwin_blocked = 1;
    rc.path_x->last_time_acked_data_frame_sent = 1;
    rc.path_x->last_sender_limited_time = 0;
    rc.path_x->rtt_min = base_rtt;
    rc.path_x->smoothed_rtt = base_rtt;

    hystart_test_prime(&rc, base_rtt);
    (void)hystart_test_round(&rc, base_rtt);
    (void)hystart_test_round(&rc, base_rtt);
    ret = hystart_cc_check(c, &rc, option_string, "flat round 2", 1, nb_bytes);

    for (int r = 1; ret == 0 && r <= 6; r++) {
        char phase[32];

        (void)hystart_test_round(&rc, high_rtt);
        (void)picoquic_sprintf(phase, sizeof(phase), NULL, "raised round %d", r);

        switch (hystart_alg) {
        case picoquic_hystart_alg_disabled_t:
            ret = hystart_cc_check(c, &rc, option_string, phase, 1, nb_bytes);
            break;
        case picoquic_hystart_alg_hystart_t:
            if (r == 3) {
                ret = hystart_cc_check(c, &rc, option_string, phase, 0, HYSTART_CC_DELTA_ANY);
            }
            else if (r == 6) {
                ret = hystart_cc_check(c, &rc, option_string, phase, 0,
                    (c->check_ca_growth) ? HYSTART_CC_DELTA_BELOW_SS : HYSTART_CC_DELTA_ANY);
            }
            break;
        case picoquic_hystart_alg_hystart_pp_t:
            if (r == 1) {
                /* CSS is entered on the last ack of this round. */
                ret = hystart_cc_check(c, &rc, option_string, phase, 1, nb_bytes);
            }
            else if (r < PICOQUIC_HYSTART_PP_CSS_ROUNDS) {
                ret = hystart_cc_check(c, &rc, option_string, phase, 1, nb_bytes / PICOQUIC_HYSTART_PP_CSS_GROWTH_DIVISOR);
            }
            else if (r == PICOQUIC_HYSTART_PP_CSS_ROUNDS) {
                /* Congestion avoidance is entered on the last ack of this round. */
                ret = hystart_cc_check(c, &rc, option_string, phase, 0, nb_bytes / PICOQUIC_HYSTART_PP_CSS_GROWTH_DIVISOR);
            }
            else {
                ret = hystart_cc_check(c, &rc, option_string, phase, 0,
                    (c->check_ca_growth) ? HYSTART_CC_DELTA_BELOW_SS : HYSTART_CC_DELTA_ANY);
            }
            break;
        default:
            ret = -1;
            break;
        }
    }

    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int hystart_cc_test(void)
{
    hystart_cc_case_t cases[] = {
        { picoquic_cubic_algorithm, 0, 1, 1 },
        { picoquic_dcubic_algorithm, 0, 1, 1 },
        { picoquic_newreno_algorithm, 0, 1, 1 },
        { picoquic_prague_algorithm, 0, 1, 1 },
        /* BBR1 only runs HyStart in "startup long RTT" (state 4), entered for rtt_min > 50ms. */
        { picoquic_bbr1_algorithm, 4, 0, 0 }
    };
    const char* option_strings[] = { "Y0", "Y1", "Y2" };
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < sizeof(cases) / sizeof(hystart_cc_case_t); i++) {
        for (int v = 0; ret == 0 && v < 3; v++) {
            ret = hystart_cc_test_one(&cases[i], (picoquic_hystart_alg_t)v, option_strings[v]);
        }
    }

    /* A preceding numeric option must not swallow the 'Y' option. */
    if (ret == 0) {
        ret = hystart_cc_test_one(&cases[4], picoquic_hystart_alg_disabled_t, "Q0.001Y2");
    }

    return ret;
}

/*
 * End to end: delay based slow start exit versus loss based exit.
 *
 * 10 Mbps, 50ms RTT, 1 second of queueing before drops. With HyStart or HyStart++
 * the sender must leave slow start on the delay signal, before any loss. With slow
 * start exit disabled, the only way out is a loss: either the sender never sets
 * ssthresh, or it does so after bytes were lost.
 */

typedef struct st_hystart_e2e_result_t {
    uint64_t exit_time;
    uint64_t loss_at_exit;
    uint64_t cwin_at_exit;
    uint64_t first_loss_time;
    uint64_t completion_time;
} hystart_e2e_result_t;

static int hystart_e2e_one(picoquic_congestion_algorithm_t* ccalgo, picoquic_hystart_alg_t hystart_alg,
    const char* option_string, hystart_e2e_result_t* res)
{
    uint64_t simulated_time = 0;
    picoquic_connection_id_t initial_cid = { {0x08, 0x23, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret;

    memset(res, 0, sizeof(*res));
    initial_cid.id[2] = ccalgo->congestion_algorithm_number;
    initial_cid.id[3] = (uint8_t)hystart_alg;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, &initial_cid);

    if (ret == 0) {
        picoquic_set_default_congestion_algorithm_ex(test_ctx->qserver, ccalgo, option_string);
        picoquic_set_congestion_algorithm_ex(test_ctx->cnx_client, ccalgo, option_string);

        test_ctx->c_to_s_link->jitter = 0;
        test_ctx->c_to_s_link->microsec_latency = 25000;
        test_ctx->c_to_s_link->picosec_per_byte = 800000; /* 10 Mbps */
        test_ctx->s_to_c_link->jitter = 0;
        test_ctx->s_to_c_link->microsec_latency = 25000;
        test_ctx->s_to_c_link->picosec_per_byte = 800000;
        test_ctx->stream0_flow_release = 1;
        test_ctx->immediate_exit = 1;

        ret = tls_api_one_scenario_body_connect(test_ctx, &simulated_time, 0, 1000000);
    }

    if (ret == 0) {
        test_ctx->stream0_target = 4000000;
        test_ctx->loss_mask_default = 0;
        ret = test_api_init_send_recv_scenario(test_ctx, NULL, 0);
    }

    if (ret == 0) {
        int nb_trials = 0;
        int nb_inactive = 0;

        test_ctx->c_to_s_link->loss_mask = &test_ctx->loss_mask_default;
        test_ctx->s_to_c_link->loss_mask = &test_ctx->loss_mask_default;

        while (ret == 0 && nb_trials < 1000000 && nb_inactive < 256 && TEST_CLIENT_READY && TEST_SERVER_READY) {
            int was_active = 0;
            picoquic_path_t* path_x = test_ctx->cnx_client->path[0];

            nb_trials++;
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);
            if (ret < 0) {
                break;
            }

            /* The client sends the data: observe its path. */
            if (res->exit_time == 0 && path_x->is_ssthresh_initialized) {
                res->exit_time = simulated_time;
                res->loss_at_exit = path_x->total_bytes_lost;
                res->cwin_at_exit = path_x->cwin;
            }
            if (res->first_loss_time == 0 && path_x->total_bytes_lost > 0) {
                res->first_loss_time = simulated_time;
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }

            if (test_ctx->test_finished) {
                break;
            }
        }
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 0);
        res->completion_time = simulated_time;
    }

    DBG_PRINTF("%s <%s>: exit at %" PRIu64 "us (cwin %" PRIu64 ", %" PRIu64 " bytes lost), first loss at %" PRIu64 "us, done at %" PRIu64 "us, ret = %d",
        ccalgo->congestion_algorithm_id, option_string, res->exit_time, res->cwin_at_exit, res->loss_at_exit,
        res->first_loss_time, res->completion_time, ret);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int hystart_ss_exit_test(void)
{
    picoquic_congestion_algorithm_t* ccalgos[] = {
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        picoquic_newreno_algorithm,
        picoquic_prague_algorithm
    };
    const char* option_strings[] = { "Y0", "Y1", "Y2" };
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < sizeof(ccalgos) / sizeof(picoquic_congestion_algorithm_t*); i++) {
        for (int v = 0; ret == 0 && v < 3; v++) {
            hystart_e2e_result_t res;
            picoquic_hystart_alg_t hystart_alg = (picoquic_hystart_alg_t)v;

            ret = hystart_e2e_one(ccalgos[i], hystart_alg, option_strings[v], &res);

            if (ret == 0) {
                if (hystart_alg == picoquic_hystart_alg_disabled_t) {
                    if (res.exit_time != 0 && res.loss_at_exit == 0) {
                        DBG_PRINTF("%s <%s>: left slow start without loss although slow start exit is disabled",
                            ccalgos[i]->congestion_algorithm_id, option_strings[v]);
                        ret = -1;
                    }
                }
                else if (res.exit_time == 0 || res.loss_at_exit != 0) {
                    DBG_PRINTF("%s <%s>: expected a delay based slow start exit before any loss",
                        ccalgos[i]->congestion_algorithm_id, option_strings[v]);
                    ret = -1;
                }
            }
        }
    }

    return ret;
}