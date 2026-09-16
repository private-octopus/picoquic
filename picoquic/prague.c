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
* 
* This code is derived in part from the initial implementation of the prague
* algorithm in picoquic, written in 2019 by by Quentin De Coninck.
*/

#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>
#include "cc_common.h"

/*
 * We implement here the Prague algorithm as a simple modification of New Reno,
 * with the following changes:
 * 
 * - maintain a coefficient "alpha", exponentially smoothed value of "frac", the
 *   fraction of EC/(ECT+ECT1) notifications in previous RTT.
 *       As a slight deviation from the base prague specification, we set
 *       alpha to frac if frac is more than alpha + 0.5. This addresses the
 *       issue of sudden onset of congestion.
 * - modify HyStart to not exit immediately on ECN notification
 * - use alpha in New Reno: control amount of window increase or decrease, as
 *   in Prague spec.
 * - reset the L3S computation on "enter_recovery". This is a useful but
 *   imperfect attempt at avoiding "double dipping".
 * 
 */

/* TODO:
* Prague is specified in
* https://www.ietf.org/archive/id/draft-briscoe-iccrg-prague-congestion-control-01.html
* 
* 
* Prague should be treated for QUIC as an extension of RFC 9002.
* RFC 9002 describes 3 states: slow start, congestion avoidance, and recovery,
* but in practice the differentiation does not need a state variable.
* There are two main actions in RFC 9002:
* - increase the congestion window on ACK
* - decrease the congestion window on loss
* The increase depends on whether CWND is below or above ssthresh:
* - if below SSTHRESH, the increase is the number of bytes acknowledged,
* 
*   except during "application limited" periods.
* - if above SSTHRESH, the increase is the ratio:
*   number of bytes ackowledged * MSS / CWND
* The decrease of the congestion window only happens if the loss is detected
* outside of the recovery period, i.e., if a packet sent during recovery
* has been acked. The effect is to reset ssthresh to:
*   max(flight_size / 2, 2 * MSS),
* while the congestion window is set to 2 packets
* 
* On top of that, RFC 9002 defines a persistent congestion period, which
* is defined as a period of time during which no packet was acked.
* 
* The main effect of Prague is to modify the increase and decrease functions,
* based on the coefficient alpha:
* 
* - instead of dropping ssthresh to half the flight size, it is dropped to:
*   ssthresh = (1 - alpha/2) * cwnd;
*   ... per the draft. This should probably be changed to:
*   ssthresh = (1 - alpha/2) * flight_size;
*   This would be the same as Reno if alpha == 1.
* 
* - in recovery, a Prague CC applies additive increase irrespective of its
*   CWR state, but only for bytes that have been ACK'd without ECN feedback.
* 
* - otherwise, the increase is the same as in Reno, but may be scaled
*   by (1 - alpha/2).
* 
* Properly computing alpha is tricky. The spec says:
* 
* - update at most every RTT, based on the number of CE and ECT1 packets
*   received in the last RTT. This means maintaining a last epoch indication,
*   i.e., the packet number that started the epoch, and a counter of
*   marks received at that time.
* - when we receive an ACK >= last epoch, we compute the change in CE and ECT1
*   marks and update the ratio.
* - On the first ever ECN/CE notification, alpha should initialized to 1.
* - There is a complicated rule on detecting "sudden onset of congestion",
*   which the code does not properly implement.
* 
* Compared to Reno (or RFC 9002), Prague will enter recovery more often,
* but will reduce the congestion window by smaller amounts. There will be
* a "saw tooth" effectas for Reno, but the saw tooth will be smaller and
* more frequent.
/

/* Observations and issues:
 *
 * Exit hystart one RTT too late. Hystart ends when the first EC markings appear.
 * These are the marks cause by traffic of epoch N-1. The traffic of epoch N
 * is already in flight, will cause congestion and losses. Increasing 
 * the pacing rate or the quantum value does cause an earlier exit from
 * slow start, but the window ends up too small -- maybe due to the
 * redundant loss signal mentioned above.
 * 
 * Window shrinking after idle. There are no data in flight at the beginning
 * of the epoch. The leaky-bucket based pacing allows a quick initial flight
 * to come in. The queue increases, many packets are marked. As a consequence,
 * the window shrinks, even in the absence of losses.
 * 
 * This variant overrides the smoothing if there are sudden onset of marks.
 * Not doing that improves performance, but also causes a sharp increase in
 * the number of losses.
 * 
 * Redundant loss signals. Marks are detected at epoch[N]. Very likely, this 
 * correlates with losses one RTO timer later. The window shrunk once because
 * of the marks, shrinks again when the loss happens -- value is then too low.
 * Something similar happens in the other direction as well. Slow start exits
 * due to increased delays, observed before the end of the epoch. Shortly
 * after that, congestion marks are reported at end of epoch, causing window
 * to shrink further. Same could happen if losses are observed, followed
 * by CE marks. This is mitigated by restarting the L4S computation after
 * slow start, but the mitigation is not sufficient. It would be better
 * to wait for the a full RTT, so packets sent with excessive rate are
 * purged from the queue.
 * 
 * Correlated CE marks. If CE marks happen at epoch N, the traffic in flight
 * correpond to the old window, before the window is reduced. CE marks will
 * very likely be detected in next window, causing too much reduction. This
 * effect is much reduced if dirctly using "frac" instead of computing "alpha".
 * 
 * L4S threshold is hard to set for the AQM. Too low, and the throughput
 * drops. Too high, and the amount of losses increases too much. In the
 * tests, the threshold is set approximately BDP/4. This may be dues to
 * inefficient solutions of the issues mentioned above.
 */

#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>

typedef enum {
    picoquic_prague_alg_slow_start = 0,
    picoquic_prague_alg_congestion_avoidance
} picoquic_prague_alg_state_t;

#define NB_RTT_RENO 4
#define PRAGUE_SHIFT_G 4 /* g = 1/2^4, gain parameter for alpha EWMA */
#define PRAGUE_G_INV (1<<PRAGUE_SHIFT_G)

typedef struct st_picoquic_prague_state_t {
    picoquic_prague_alg_state_t alg_state;
    uint64_t alpha;
    uint64_t residual_ack;
    uint64_t ssthresh;
    uint64_t recovery_stamp;
    uint64_t recovery_sequence;
    uint64_t l4s_update_sent;
    uint64_t l4s_epoch_send;
    uint64_t l4s_epoch_ect1;
    uint64_t l4s_epoch_ce;
    uint64_t l4s_packet_ect1;
    uint64_t l4s_packet_ce;

    picoquic_min_max_rtt_t rtt_filter;
} picoquic_prague_state_t;

/* Re-entry into slow start, e.g. after a PMTU blackhole reset: restart CWND growth from
 * scratch, but keep the previously learned ssthresh ceiling instead of resetting it to
 * infinity, so a repeated reset does not keep forgetting what was already learned. */
static void picoquic_prague_init_reno(picoquic_prague_state_t* pr_state, picoquic_path_t* path_x)
{
    pr_state->alg_state = picoquic_prague_alg_slow_start;
    pr_state->alpha = 0;
    path_x->cwin = PICOQUIC_CWIN_INITIAL;
}

void picoquic_prague_init(picoquic_path_t* path_x, char const* UNUSED(option_string), uint64_t UNUSED(current_time))
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_prague_state_t* pr_state = (picoquic_prague_state_t*)malloc(sizeof(picoquic_prague_state_t));
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(option_string);
#endif

    if (pr_state != NULL) {
        memset(pr_state, 0, sizeof(picoquic_prague_state_t));
        /* ssthresh is only ever set to infinity here, on the very first run. */
        pr_state->ssthresh = UINT64_MAX;
        path_x->congestion_alg_state = (void*)pr_state;
        picoquic_prague_init_reno(pr_state, path_x);
    }
    else {
        path_x->congestion_alg_state = NULL;
    }
}

static picoquic_packet_context_t* picoquic_prague_get_pkt_ctx(picoquic_cnx_t* cnx,  picoquic_path_t* path_x)
{
    picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];

    /* Reset the L3S measurement context to the current value */
    if (cnx->is_multipath_enabled) {
        pkt_ctx = &path_x->pkt_ctx;
    }

    return pkt_ctx;
}

static void picoquic_prague_reset_l3s(picoquic_cnx_t* cnx, picoquic_prague_state_t* pr_state, picoquic_path_t* path_x)
{
    picoquic_packet_context_t* pkt_ctx = picoquic_prague_get_pkt_ctx(cnx, path_x);
    pr_state->l4s_epoch_send = pkt_ctx->send_sequence;
    pr_state->l4s_epoch_ect1 = pkt_ctx->ecn_ect1_total_remote;
    pr_state->l4s_epoch_ce = pkt_ctx->ecn_ce_total_remote;
    pr_state->alpha = 0;
}


static void picoquic_prague_reset(picoquic_cnx_t * cnx, picoquic_prague_state_t* pr_state, picoquic_path_t* path_x)
{
    picoquic_prague_init_reno(pr_state, path_x);
    picoquic_prague_reset_l3s(cnx, pr_state, path_x);
}

static void picoquic_prague_initialize_era(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_prague_state_t* pr_state,
    uint64_t current_time)
{
    /* Initialize the era */
    picoquic_packet_context_t* pkt_ctx = picoquic_prague_get_pkt_ctx(cnx, path_x);
    pr_state->l4s_epoch_ect1 = pkt_ctx->ecn_ect1_total_remote;
    pr_state->l4s_epoch_ce = pkt_ctx->ecn_ce_total_remote;
    pr_state->recovery_stamp = current_time;
    pr_state->recovery_sequence = picoquic_cc_get_sequence_number(path_x->cnx, path_x);
}

/* Prague reduces the congestion window at most once per
* RTT. This is done by entering recovery, during which the
* window is reset to ssthresh.
* 
* If entering recovery from loss, the reduction factor is 1/2.
* If entering from CE, the reduction factor depends on alpha.
 */
static void picoquic_prague_enter_recovery(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_prague_state_t* pr_state,
    uint64_t current_time)
{
    pr_state->ssthresh = path_x->cwin / 2;
    if (pr_state->ssthresh < PICOQUIC_CWIN_MINIMUM) {
        pr_state->ssthresh = PICOQUIC_CWIN_MINIMUM;
    }
    
    path_x->cwin = pr_state->ssthresh;
    pr_state->alg_state = picoquic_prague_alg_congestion_avoidance;

    picoquic_prague_initialize_era(cnx, path_x, pr_state, current_time);
}

static void picoquic_prague_update_alpha(picoquic_path_t* path_x, picoquic_prague_state_t* pr_state,
    uint64_t delta_ect1, uint64_t delta_ce, uint64_t current_time)
{
    uint64_t frac = 0;
    int is_suspect = 0;

    if (delta_ce > 0) {
        frac = (delta_ce * 1024) / (delta_ce + delta_ect1);
    }
    else {
        frac = 0;
    }

#if 0
    /* Not reachable: l4s_update_sent is initialized to 0 and never assigned anywhere else in
     * this file, so this guard's first clause is always false. */
    if (pr_state->l4s_update_sent != 0 && frac >= 512 && pr_state->alpha < 128 &&
        current_time - pr_state->recovery_stamp > path_x->smoothed_rtt) {
        /*
         * the epoch lasted more than the RTT. This is most
         * probably due to period of inactivity, then effects of imprecise
         * tuning of pacing's leaky bucket algorithm. Limiting the
         * fraction frac to about 1/8th to avoid too much bad effects. */
        is_suspect = 1;
        frac = 128;
    }
#endif

    if (delta_ce > 0 || delta_ect1 > 0) {
        if (frac > pr_state->alpha && (frac >= 512 || is_suspect)) {
            pr_state->alpha = frac;
        }
        else
        {
            uint64_t alpha_shifted = pr_state->alpha << PRAGUE_SHIFT_G;
            alpha_shifted -= pr_state->alpha;
            alpha_shifted += frac;
            pr_state->alpha = alpha_shifted >> PRAGUE_SHIFT_G;
        }
    }
    picoquic_log_app_message(path_x->cnx,
        "Prague: %" PRIu64 ",%d,%d,%d,%" PRIu64 ",%" PRIu64,
        current_time, (int)delta_ect1, (int)delta_ce, (int)pr_state->alpha, path_x->cwin, path_x->rtt_sample);
}

void picoquic_prague_process_ack(picoquic_cnx_t* cnx,
    picoquic_path_t* path_x, picoquic_prague_state_t* pr_state, picoquic_per_ack_state_t* ack_state, uint64_t current_time)
{
    picoquic_packet_context_t* pkt_ctx = picoquic_prague_get_pkt_ctx(cnx, path_x);
    uint64_t next_sequence = picoquic_cc_get_ack_number(path_x->cnx, path_x);

    if (next_sequence > pr_state->recovery_sequence) {
        /* new period. Update alpha, etc. */
        int64_t delta_ect1 = pkt_ctx->ecn_ect1_total_remote - pr_state->l4s_epoch_ect1;
        int64_t delta_ce = pkt_ctx->ecn_ce_total_remote - pr_state->l4s_epoch_ce;

        if (delta_ect1 >= 0 && delta_ce >= 0 && delta_ce + delta_ect1 > 0 ) {
            /* We are receiving ECN signals, so update alpha and do CWND reduction */
            uint64_t delta_cwin;
            picoquic_prague_update_alpha(path_x, pr_state, delta_ect1, delta_ce, current_time);

            /* Update the ssthresh and the CWIN */
            delta_cwin = (path_x->cwin * pr_state->alpha) / 2048;
            path_x->cwin -= delta_cwin;
            if (path_x->cwin < PICOQUIC_CWIN_MINIMUM) {
                path_x->cwin = PICOQUIC_CWIN_MINIMUM;
            }
            pr_state->ssthresh = path_x->cwin;
        }
        /* reset the era limits */
        picoquic_prague_initialize_era(cnx, path_x, pr_state, current_time);
    }
    /* Increment CWND whether in recovery or not */
    if (pkt_ctx->ecn_ect1_total_remote >= pr_state->l4s_packet_ect1 &&
        pkt_ctx->ecn_ce_total_remote >= pr_state->l4s_packet_ce) {
        uint64_t delta_ect1_ack = pkt_ctx->ecn_ect1_total_remote - pr_state->l4s_packet_ect1;
        uint64_t delta_ce_ack = pkt_ctx->ecn_ce_total_remote - pr_state->l4s_packet_ce;
        uint64_t ack_bytes = ack_state->nb_bytes_acknowledged;
        double frac_not_ce = 1.0;

        if (delta_ce_ack + delta_ect1_ack > 0) {
            frac_not_ce = ((double)delta_ect1_ack) / (double)(delta_ce_ack + delta_ect1_ack);
            ack_bytes = (uint64_t)(frac_not_ce * (double)ack_bytes);
        }
        path_x->cwin += path_x->send_mtu * ack_bytes / path_x->cwin;
    }
}

void picoquic_prague_process_start_ack(picoquic_cnx_t* cnx,
    picoquic_path_t* path_x, picoquic_prague_state_t* pr_state, picoquic_per_ack_state_t* ack_state, uint64_t current_time)
{
    picoquic_packet_context_t* pkt_ctx = picoquic_prague_get_pkt_ctx(cnx, path_x);
    if (pr_state->ssthresh == UINT64_MAX) {
        /* Increase cwin based on bandwidth estimation. */
        path_x->cwin = picoquic_cc_update_target_cwin_estimation(path_x);
    }
    if (pkt_ctx->ecn_ce_total_remote > pr_state->l4s_epoch_ce) {
        /* CE mark received in intitial state:
         * exit and enter recovery.
         */
        picoquic_prague_enter_recovery(cnx, path_x, pr_state, current_time);
    }
    else {
        path_x->cwin += picoquic_cc_slow_start_increase_ex2(path_x, ack_state->nb_bytes_acknowledged, 0, pr_state->alpha);

        /* if cnx->cwin exceeds SSTHRESH, exit and go to CA. On the very first run, ssthresh is
         * infinite and this never fires; after a reset, it holds the previously learned value. */
        if (path_x->cwin >= pr_state->ssthresh) {
            pr_state->alg_state = picoquic_prague_alg_congestion_avoidance;
            picoquic_prague_initialize_era(cnx, path_x, pr_state, current_time);
        }
    }
}


/* Callback management for Prague
 */
void picoquic_prague_notify(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time)
{
    picoquic_prague_state_t* pr_state = (picoquic_prague_state_t*)path_x->congestion_alg_state;

    if (pr_state != NULL) {
        switch (notification) {
        /* RTT measurements will happen before acknowledgement is signalled */
        case picoquic_congestion_notification_acknowledgement: {
            /* Increase or reduce the congestion window based on alpha */
            switch (pr_state->alg_state) {
            case picoquic_prague_alg_slow_start:
                picoquic_prague_process_start_ack(cnx, path_x, pr_state, ack_state, current_time);
                break;
            case picoquic_prague_alg_congestion_avoidance:
            default:
                picoquic_prague_process_ack(cnx, path_x, pr_state, ack_state, current_time);
                break;
            }
            break;
        }
        case picoquic_congestion_notification_ecn_ec:
            /* already managed as part of ACK */
            break;
        case picoquic_congestion_notification_repeat:
            /* enter recovery on loss. We should do nothing on timeout */
            if (picoquic_cc_hystart_loss_test(&pr_state->rtt_filter, notification, ack_state->lost_packet_number,
                PICOQUIC_SMOOTHED_LOSS_THRESHOLD) && current_time - pr_state->recovery_stamp > path_x->smoothed_rtt) {
                picoquic_prague_enter_recovery(cnx, path_x, pr_state, current_time);
            }
            break;
        case picoquic_congestion_notification_timeout:
            /* We should not react on PTO */
            break;
        case picoquic_congestion_notification_spurious_repeat:
            /* we should do nothing, since we do not react on PTO */
            break;
        case picoquic_congestion_notification_rtt_measurement:
            if (pr_state->alg_state == picoquic_prague_alg_slow_start &&
                pr_state->ssthresh == UINT64_MAX) {

                if (path_x->rtt_min > PICOQUIC_TARGET_RENO_RTT) {
                    path_x->cwin = picoquic_cc_update_cwin_for_long_rtt(path_x);
                }

                /* HyStart. */
                /* Using RTT increases as signal to get out of initial slow start */
                if (picoquic_cc_hystart_test(&pr_state->rtt_filter, (cnx->is_time_stamp_enabled) ? ack_state->one_way_delay : ack_state->rtt_measurement,
                    cnx->path[0]->pacing.packet_time_microsec, current_time,
                    cnx->is_time_stamp_enabled)) {
                    /* RTT increased too much, get out of slow start! */
                    pr_state->ssthresh = path_x->cwin;
                    pr_state->alg_state = picoquic_prague_alg_congestion_avoidance;
                    path_x->is_ssthresh_initialized = 1;
                }
            }
            break;
        case picoquic_congestion_notification_reset:
            picoquic_prague_reset(cnx, pr_state, path_x);
            break;
        default:
            /* ignore */
            break;
        }
        /* Compute pacing data */
        picoquic_update_pacing_data(path_x, pr_state->alg_state == picoquic_prague_alg_slow_start &&
            pr_state->ssthresh == UINT64_MAX);
    }
}

/* Release the state of the congestion control algorithm */
void picoquic_prague_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}

/* Observe the state of congestion control */

void picoquic_prague_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    picoquic_prague_state_t* pr_state = (picoquic_prague_state_t*)path_x->congestion_alg_state;
    *cc_state = (uint64_t)pr_state->alg_state;
    *cc_param = (pr_state->ssthresh == UINT64_MAX) ? 0 : pr_state->ssthresh;
}

/* Definition record for the Prague algorithm */

#define PICOQUIC_PRAGUE_ID "prague" 

picoquic_congestion_algorithm_t picoquic_prague_algorithm_struct = {
    PICOQUIC_PRAGUE_ID, PICOQUIC_CC_ALGO_NUMBER_PRAGUE, PICOQUIC_ECN_ECT_1,
    picoquic_prague_init,
    picoquic_prague_notify,
    picoquic_prague_delete,
    picoquic_prague_observe
};

picoquic_congestion_algorithm_t* picoquic_prague_algorithm = &picoquic_prague_algorithm_struct;
