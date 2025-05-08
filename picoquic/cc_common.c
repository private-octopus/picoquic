/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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
#include <stdlib.h>
#include <string.h>
#include "cc_common.h"

uint64_t picoquic_cc_get_sequence_number(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    uint64_t sequence_number;

    if (cnx->is_multipath_enabled) {
            sequence_number = path_x->pkt_ctx.send_sequence;
        }
    else {
       sequence_number = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence;
    }

    return sequence_number;
}

uint64_t picoquic_cc_get_ack_number(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    uint64_t highest_acknowledged;

    if (cnx->is_multipath_enabled) {
        highest_acknowledged = path_x->pkt_ctx.highest_acknowledged;
    }
    else {
        highest_acknowledged = cnx->pkt_ctx[picoquic_packet_context_application].highest_acknowledged;
    }

    return highest_acknowledged;
}

uint64_t picoquic_cc_get_ack_sent_time(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    uint64_t latest_time_acknowledged;

    if (cnx->is_multipath_enabled) {
        latest_time_acknowledged = path_x->pkt_ctx.latest_time_acknowledged;
    }
    else {
        latest_time_acknowledged = cnx->pkt_ctx[picoquic_packet_context_application].latest_time_acknowledged;
    }

    return latest_time_acknowledged;
}


void picoquic_cc_filter_rtt_min_max(picoquic_min_max_rtt_t * rtt_track, uint64_t rtt)
{
    int x = rtt_track->sample_current;
    int x_max;

    rtt_track->samples[x] = rtt;

    rtt_track->sample_current = x + 1;
    if (rtt_track->sample_current >= PICOQUIC_MIN_MAX_RTT_SCOPE) {
        rtt_track->is_init = 1;
        rtt_track->sample_current = 0;
    }
    
    x_max = (rtt_track->is_init) ? PICOQUIC_MIN_MAX_RTT_SCOPE : x + 1;

    rtt_track->sample_min = rtt_track->samples[0];
    rtt_track->sample_max = rtt_track->samples[0];

    for (int i = 1; i < x_max; i++) {
        if (rtt_track->samples[i] < rtt_track->sample_min) {
            rtt_track->sample_min = rtt_track->samples[i];
        } else if (rtt_track->samples[i] > rtt_track->sample_max) {
            rtt_track->sample_max = rtt_track->samples[i];
        }
    }
}

int picoquic_cc_hystart_loss_test(picoquic_min_max_rtt_t* rtt_track, picoquic_congestion_notification_t event,
    uint64_t lost_packet_number, double error_rate_max)
{
    int ret = 0;
    uint64_t next_number = rtt_track->last_lost_packet_number;

    if (lost_packet_number > next_number) {
        if (next_number + PICOQUIC_SMOOTHED_LOSS_SCOPE < lost_packet_number) {
            next_number = lost_packet_number - PICOQUIC_SMOOTHED_LOSS_SCOPE;
        }

        while (next_number < lost_packet_number) {
            rtt_track->smoothed_drop_rate *= (1.0 - PICOQUIC_SMOOTHED_LOSS_FACTOR);
            next_number++;
        }

        rtt_track->smoothed_drop_rate += (1.0 - rtt_track->smoothed_drop_rate) * PICOQUIC_SMOOTHED_LOSS_FACTOR;
        rtt_track->last_lost_packet_number = lost_packet_number;

        switch (event) {
        case picoquic_congestion_notification_repeat:
            ret = rtt_track->smoothed_drop_rate > error_rate_max;
            break;
        case picoquic_congestion_notification_timeout:
            ret = 1;
        default:
            break;
        }
    }

    return ret;
}

int picoquic_cc_hystart_loss_volume_test(picoquic_min_max_rtt_t* rtt_track, picoquic_congestion_notification_t event,  uint64_t nb_bytes_newly_acked, uint64_t nb_bytes_newly_lost)
{
    int ret = 0;

    rtt_track->smoothed_bytes_lost_16 -= rtt_track->smoothed_bytes_lost_16 / 16;
    rtt_track->smoothed_bytes_lost_16 += nb_bytes_newly_lost;
    rtt_track->smoothed_bytes_sent_16 -= rtt_track->smoothed_bytes_sent_16 / 16;
    rtt_track->smoothed_bytes_sent_16 += nb_bytes_newly_acked + nb_bytes_newly_lost;

    if (rtt_track->smoothed_bytes_sent_16 > 0) {
        rtt_track->smoothed_drop_rate = ((double)rtt_track->smoothed_bytes_lost_16) / ((double)rtt_track->smoothed_bytes_sent_16);
    }
    else {
        rtt_track->smoothed_drop_rate = 0;
    }

    switch (event) {
    case picoquic_congestion_notification_acknowledgement:
        ret = rtt_track->smoothed_drop_rate > PICOQUIC_SMOOTHED_LOSS_THRESHOLD;
        break;
    case picoquic_congestion_notification_timeout:
        ret = 1;
    default:
        break;
    }

    return ret;
}

int picoquic_cc_hystart_test(picoquic_min_max_rtt_t* rtt_track, uint64_t rtt_measurement, uint64_t packet_time, uint64_t current_time, int is_one_way_delay_enabled)
{
    int ret = 0;

    if(current_time > rtt_track->last_rtt_sample_time + 1000) {
        picoquic_cc_filter_rtt_min_max(rtt_track, rtt_measurement);
        rtt_track->last_rtt_sample_time = current_time;

        if (rtt_track->is_init) {
            uint64_t delta_max;

            if (rtt_track->rtt_filtered_min == 0 ||
                rtt_track->rtt_filtered_min > rtt_track->sample_max) {
                rtt_track->rtt_filtered_min = rtt_track->sample_max;
            }
            delta_max = rtt_track->rtt_filtered_min / 4;

            if (rtt_track->sample_min > rtt_track->rtt_filtered_min) {
                if (rtt_track->sample_min > rtt_track->rtt_filtered_min + delta_max) {
                    rtt_track->nb_rtt_excess++;
                    if (rtt_track->nb_rtt_excess >= PICOQUIC_MIN_MAX_RTT_SCOPE) {
                        /* RTT increased too much, get out of slow start! */
                        ret = 1;
                    }
                }
            }
            else {
                rtt_track->nb_rtt_excess = 0;
            }
        }
    }

    return ret;
}

uint64_t picoquic_cc_slow_start_increase(picoquic_path_t * path_x, uint64_t nb_delivered) {
    /* App limited. */
    /* TODO discuss
     * path_x->cwin < path_x->bytes_in_transit returns false in cc code
     * path_x->cnx->cwin_blocked is set to true
     * (path_x->cwin < path_x->bytes_in_transit) != path_x->cnx->cwin_blocked?
     */
    if (!path_x->cnx->cwin_blocked) {
        return 0;
    }

    return nb_delivered;
}

/** For each arriving ACK in slow start, where N is the number of previously unacknowledged bytes acknowledged in
 * the arriving ACK:
 * Update the cwnd:
 *      cwnd = cwnd + min(N, L * SMSS)
 */
/** For each arriving ACK in CSS, where N is the number of previously unacknowledged bytes acknowledged in the arriving
 * ACK:
 * Update the cwnd:
 *      cwnd = cwnd + (min(N, L * SMSS) / CSS_GROWTH_DIVISOR)
 */
uint64_t picoquic_cc_slow_start_increase_ex(picoquic_path_t * path_x, uint64_t nb_delivered, int in_css)
{
    if (in_css) {
        /* In consecutive Slow Start. */
        return picoquic_cc_slow_start_increase(path_x, nb_delivered / PICOQUIC_HYSTART_PP_CSS_GROWTH_DIVISOR);
    }

    /* Fallback to traditional Slow Start. */
    return picoquic_cc_slow_start_increase(path_x, nb_delivered); /* nb_delivered; */
}

uint64_t picoquic_cc_slow_start_increase_ex2(picoquic_path_t* path_x, uint64_t nb_delivered, int in_css, uint64_t prague_alpha) {
    if (prague_alpha != 0) { /* monitoring of ECN */
        uint64_t delta = nb_delivered;

        /* Calculate delta based on prague_ahpha. */
        if (path_x->smoothed_rtt <= PICOQUIC_TARGET_RENO_RTT) {
            /* smoothed_rtt <= 100ms */
            delta *= (1024 - prague_alpha);
            delta /= 1024;
        } else {
            delta *= path_x->smoothed_rtt;
            delta *= (1024 - prague_alpha);
            delta /= PICOQUIC_TARGET_RENO_RTT;
            delta /= 1024;
        }

        return picoquic_cc_slow_start_increase_ex(path_x, delta, in_css);
    }

    /* Fallback to HyStart++ Consecutive Slow Start. */
    return picoquic_cc_slow_start_increase_ex(path_x, nb_delivered, in_css);
}

/*
 * HyStart++
 */
/** lastRoundMinRTT and currentRoundMinRTT are initialized to infinity at the initialization time. currRTT is
 * the RTT sampled from the latest incoming ACK and initialized to infinity.
 * - lastRoundMinRTT = infinity
 * - currentRoundMinRTT = infinity
 * - currRTT = infinity
 */
void picoquic_hystart_pp_reset(picoquic_hystart_pp_state_t* hystart_pp_state) {
    /* init round */
    hystart_pp_state->current_round.last_round_min_rtt = UINT64_MAX;
    hystart_pp_state->current_round.current_round_min_rtt = UINT64_MAX;
    //hystart_pp_state.curr_rtt = UINT64_MAX;
    hystart_pp_state->current_round.rtt_sample_count = 0;
    hystart_pp_state->current_round.window_end = 0;

    /* init state */
    //hystart_pp_state->rtt_thresh = UINT64_MAX;
    hystart_pp_state->css_baseline_min_rtt = UINT64_MAX;
    hystart_pp_state->css_round_count = 0;

    /* TODO Move start round here. */
}

void picoquic_hystart_pp_init(picoquic_hystart_pp_state_t* hystart_pp_state, picoquic_cnx_t* cnx, picoquic_path_t* path_x) {
    picoquic_hystart_pp_reset(hystart_pp_state);
    picoquic_hystart_pp_start_new_round(hystart_pp_state, cnx, path_x);
}

/** At the start of each round during standard slow start [RFC5681] and CSS, initialize the variables used to
 *  compute the last round's and current round's minimum RTT:
 *  - lastRoundMinRTT = currentRoundMinRTT
 *  - currentRoundMinRTT = infinity
 *  - rttSampleCount = 0
 */
/** HyStart++ measures rounds using sequence numbers, as follows:
 *  - Define windowEnd as a sequence number initialized to SND.NXT.
 */
void picoquic_hystart_pp_start_new_round(picoquic_hystart_pp_state_t* hystart_pp_state, picoquic_cnx_t* cnx, picoquic_path_t* path_x) {
    hystart_pp_state->current_round.last_round_min_rtt = hystart_pp_state->current_round.current_round_min_rtt;
    hystart_pp_state->current_round.current_round_min_rtt = UINT64_MAX;
    hystart_pp_state->current_round.rtt_sample_count = 0;

    /* Set window end to next sent sequence number. */
    hystart_pp_state->current_round.window_end = picoquic_cc_get_sequence_number(cnx, path_x);
}

/** For each arriving ACK in slow start, where N is the number of previously unacknowledged bytes acknowledged in
 * the arriving ACK:
 * Keep track of the minimum observed RTT:
 *      currentRoundMinRTT = min(currentRoundMinRTT, currRTT)
 *      rttSampleCount += 1
 */
/** For each arriving ACK in CSS, where N is the number of previously unacknowledged bytes acknowledged in the arriving
 * ACK:
 * Keep track of the minimum observed RTT:
 *      currentRoundMinRTT = min(currentRoundMinRTT, currRTT)
 *      rttSampleCount += 1
 */
void picoquic_hystart_pp_keep_track(picoquic_hystart_pp_state_t *hystart_pp_state, uint64_t rtt_measurement) {
    hystart_pp_state->current_round.current_round_min_rtt = MIN(hystart_pp_state->current_round.current_round_min_rtt, rtt_measurement);
    hystart_pp_state->current_round.rtt_sample_count++;
}

/** For rounds where at least N_RTT_SAMPLE RTT samples have been obtained and currentRoundMinRTT and lastRoundMinRTT
 * are valid, check to see if delay increase triggers slow start exit:
 *      if ((rttSampleCount >= N_RTT_SAMPLE) AND (currentRoundMinRTT != infinity) AND (lastRoundMinRTT != infinity))
 *          RttThresh = max(MIN_RTT_THRESH, min(lastRoundMinRTT / MIN_RTT_DIVISOR, MAX_RTT_THRESH))
 *          if (currentRoundMinRTT >= (lastRoundMinRTT + RttThresh))
 *              cssBaselineMinRtt = currentRoundMinRTT
 *              exit slow start and enter CSS
 */
/** For CSS rounds where at least N_RTT_SAMPLE RTT samples have been obtained, check to see if the current round's
 * minRTT drops below baseline (cssBaselineMinRtt) indicating that slow start exit was spurious:
 *      if (currentRoundMinRTT < cssBaselineMinRtt)
 *          cssBaselineMinRtt = infinity
 *          resume slow start including HyStart++
 */
void picoquic_hystart_pp_test(picoquic_hystart_pp_state_t *hystart_pp_state) {
    if (hystart_pp_state->css_baseline_min_rtt == UINT64_MAX) {
        /* In slow start (SS) */
        if (hystart_pp_state->current_round.rtt_sample_count >= PICOQUIC_HYSTART_PP_N_RTT_SAMPLE &&
            hystart_pp_state->current_round.current_round_min_rtt != UINT64_MAX &&
            hystart_pp_state->current_round.last_round_min_rtt != UINT64_MAX) {
            uint64_t rtt_thresh = MAX(PICOQUIC_HYSTART_PP_MIN_RTT_THRESH, MIN(hystart_pp_state->current_round.last_round_min_rtt / PICOQUIC_HYSTART_PP_MIN_RTT_DIVISOR, PICOQUIC_HYSTART_PP_MAX_RTT_THRESH));

            if (hystart_pp_state->current_round.current_round_min_rtt >= (hystart_pp_state->current_round.last_round_min_rtt + rtt_thresh)) {
                fprintf(stdout, "Enter CSS.\n"); /* TODO remove after debug. */
                /* Exit slow start and enter CSS. */
                hystart_pp_state->css_baseline_min_rtt = hystart_pp_state->current_round.current_round_min_rtt;
            }
        }
    } else {
        /* In conservative slow start (CSS) */
        if (hystart_pp_state->current_round.rtt_sample_count >= PICOQUIC_HYSTART_PP_N_RTT_SAMPLE) {
            if (hystart_pp_state->current_round.current_round_min_rtt < hystart_pp_state->css_baseline_min_rtt) {
                fprintf(stdout, "Resume SS.\n"); /* TODO remove after debug. */
                /* Resume slow start including hystart++. */
                hystart_pp_state->css_baseline_min_rtt = UINT64_MAX;
            }
        }
    }
}

int picoquic_cc_hystart_pp_test(picoquic_hystart_pp_state_t* hystart_pp_state, picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_per_ack_state_t* ack_state) {
    int ret = 0;

    /* Keep track of the minimum RTT seen so far. */
    picoquic_hystart_pp_keep_track(hystart_pp_state, ack_state->rtt_measurement);

    /* Switch between SS and CSS. */
    picoquic_hystart_pp_test(hystart_pp_state);

    /* Check if we reached the end of the round. */
    /* HyStart++ measures rounds using sequence numbers, as follows:
     * - When windowEnd is ACKed, the current round ends and windowEnd is set to SND.NXT.
     */
    if (picoquic_cc_get_ack_number(cnx, path_x) != UINT64_MAX && picoquic_cc_get_ack_number(cnx, path_x) >= hystart_pp_state->current_round.window_end) {
        /* Round has ended. */
        if (IS_IN_CSS((*hystart_pp_state))) {
            /* In CSS increase CSS round counter. */
            hystart_pp_state->css_round_count++;

            /* Enter CA if css round counter > max css rounds. */
            if (hystart_pp_state->css_round_count >= PICOQUIC_HYSTART_PP_CSS_ROUNDS) {
                ret = 1;
            }
        }

        /* Start new round. */
        picoquic_hystart_pp_start_new_round(hystart_pp_state, cnx, path_x);
    }

    return ret;
}

uint64_t picoquic_cc_update_target_cwin_estimation(picoquic_path_t* path_x) {
    /* RTT measurements will happen after the bandwidth is estimated. */
    uint64_t max_win = path_x->peak_bandwidth_estimate * path_x->smoothed_rtt / 1000000;
    uint64_t min_win = max_win / 2;

    /* Return increased cwin, if larger than current cwin. */
    if (min_win > path_x->cwin) {
        return min_win;
    }

    /* Otherwise, return current cwin. */
    return path_x->cwin;
}

uint64_t picoquic_cc_update_cwin_for_long_rtt(picoquic_path_t * path_x) {
    uint64_t min_cwnd;

    if (path_x->rtt_min > PICOQUIC_TARGET_SATELLITE_RTT) {
        min_cwnd = (uint64_t)((double)PICOQUIC_CWIN_INITIAL * (double)PICOQUIC_TARGET_SATELLITE_RTT / (double)PICOQUIC_TARGET_RENO_RTT);
    }
    else {
        min_cwnd = (uint64_t)((double)PICOQUIC_CWIN_INITIAL * (double)path_x->rtt_min / (double)PICOQUIC_TARGET_RENO_RTT);
    }

    /* Return increased cwin, if larger than current cwin. */
    if (min_cwnd > path_x->cwin) {
        return min_cwnd;
    }

    /* Otherwise, return current cwin. */
    return path_x->cwin;
}

uint64_t picoquic_cc_increased_window(picoquic_cnx_t* cnx, uint64_t previous_window)
{
    uint64_t new_window;
    if (cnx->path[0]->rtt_min <= PICOQUIC_TARGET_RENO_RTT) {
        new_window = previous_window * 2;
    }
    else {
        double w = (double)previous_window;
        w /= (double)PICOQUIC_TARGET_RENO_RTT;
        w *= (cnx->path[0]->rtt_min > PICOQUIC_TARGET_SATELLITE_RTT) ? PICOQUIC_TARGET_SATELLITE_RTT : (double)cnx->path[0]->rtt_min;
        new_window = (uint64_t)w;
    }
    return new_window;
}