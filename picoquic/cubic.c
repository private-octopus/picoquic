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

#define PICOQUIC_CUBIC_C 0.4
#define PICOQUIC_CUBIC_BETA_ECN (7.0 / 8.0)
#define PICOQUIC_CUBIC_BETA (3.0 / 4.0)

typedef enum {
    picoquic_cubic_alg_slow_start = 0,
    picoquic_cubic_alg_recovery,
    picoquic_cubic_alg_congestion_avoidance
} picoquic_cubic_alg_state_t;

typedef struct st_picoquic_cubic_state_t {
    picoquic_cubic_alg_state_t alg_state;
    uint64_t recovery_sequence;
    uint64_t start_of_epoch;
    uint64_t previous_start_of_epoch;
    double K;
    double W_max;
    double W_last_max;
    double W_reno;
    uint64_t ssthresh;
    picoquic_min_max_rtt_t rtt_filter;

    /* HyStart++ */
    picoquic_hystart_pp_state_t hystart_pp_state;
} picoquic_cubic_state_t;

static void cubic_reset(picoquic_cubic_state_t* cubic_state, picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time) {
    memset(&cubic_state->rtt_filter, 0, sizeof(picoquic_min_max_rtt_t));
    memset(cubic_state, 0, sizeof(picoquic_cubic_state_t));
    cubic_state->alg_state = picoquic_cubic_alg_slow_start;
    cubic_state->ssthresh = UINT64_MAX;
    cubic_state->W_last_max = (double)cubic_state->ssthresh / (double)path_x->send_mtu;
    cubic_state->W_max = cubic_state->W_last_max;
    cubic_state->start_of_epoch = current_time;
    cubic_state->previous_start_of_epoch = 0;
    cubic_state->W_reno = PICOQUIC_CWIN_INITIAL;
    cubic_state->recovery_sequence = 0;
    path_x->cwin = PICOQUIC_CWIN_INITIAL;

    memset(&cubic_state->hystart_pp_state, 0, sizeof(picoquic_hystart_pp_state_t));
    picoquic_hystart_pp_reset(&cubic_state->hystart_pp_state);
}

static void cubic_init(picoquic_cnx_t * cnx, picoquic_path_t* path_x, uint64_t current_time)
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_cubic_state_t* cubic_state = (picoquic_cubic_state_t*)malloc(sizeof(picoquic_cubic_state_t));
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx);
#endif
    path_x->congestion_alg_state = (void*)cubic_state;
    if (cubic_state != NULL) {
        cubic_reset(cubic_state, cnx, path_x, current_time);
    }

    /* HyStart++ */
    if (IS_HYSTART_PP_ENABLED(cnx)) {
        picoquic_hystart_pp_init(&cubic_state->hystart_pp_state, cnx, path_x);
    }
}

static double cubic_root(double x)
{
    /* First find an approximation */
    double v = 1;
    double y = 1.0;
    double y2;
    double y3;

    /*
     * v = 1
     *
     * x = (cubic_state->W_max * (1.0 - PICOQUIC_CUBIC_BETA)) / PICOQUIC_CUBIC_C
     * PICOQUIC_CUBIC_C = 0.4
     * (1.0 - PICOQUIC_CUBIC_BETA) = 1 - 7/8 = 1/8
     *
     * v > x * 8
     * 1 > (cubic_state->W_max * (1/8) / 0.4) * 8
     * cubic_state->W_max < 2/5
     */
    while (v > x * 8) {
        v /= 8;
        y /= 2;
    }

    while (v < x) {
        v *= 8;
        y *= 2;
    }

    for (int i = 0; i < 3; i++) {
        y2 = y * y;
        y3 = y2 * y;
        y += (x - y3) / (3.0*y2);
    }

    return y;
}

/* Compute W_cubic(t) = C * (t - K) ^ 3 + W_max */
static double cubic_W_cubic(
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{
    double delta_t_sec = ((double)(current_time - cubic_state->start_of_epoch) / 1000000.0) - cubic_state->K;
    double W_cubic = (PICOQUIC_CUBIC_C * (delta_t_sec * delta_t_sec * delta_t_sec)) + cubic_state->W_max;

    return W_cubic;
}

/* On entering congestion avoidance, need to compute the new coefficients
 * of the cubic curve */
static void cubic_enter_avoidance(
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{
    cubic_state->K = cubic_root(cubic_state->W_max*(1.0 - PICOQUIC_CUBIC_BETA_ECN) / PICOQUIC_CUBIC_C);
    cubic_state->alg_state = picoquic_cubic_alg_congestion_avoidance;
    cubic_state->start_of_epoch = current_time;
    cubic_state->previous_start_of_epoch = cubic_state->start_of_epoch;
}

/* The recovery state last 1 RTT, during which parameters will be frozen
 */
static void cubic_enter_recovery(picoquic_cnx_t * cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{
    cubic_state->recovery_sequence = picoquic_cc_get_sequence_number(cnx, path_x);
    /* Update similar to new reno, but different beta */
    cubic_state->W_max = (double)path_x->cwin / (double)path_x->send_mtu;
    /* Apply fast convergence */
    if (cubic_state->W_max < cubic_state->W_last_max) {
        cubic_state->W_last_max = cubic_state->W_max;
        cubic_state->W_max = cubic_state->W_max * PICOQUIC_CUBIC_BETA_ECN;
    }
    else {
        cubic_state->W_last_max = cubic_state->W_max;
    }
    /* Compute the new ssthresh */
    cubic_state->ssthresh = (uint64_t)(cubic_state->W_max * PICOQUIC_CUBIC_BETA_ECN * (double)path_x->send_mtu);
    if (cubic_state->ssthresh < PICOQUIC_CWIN_MINIMUM) {
        /* If things are that bad, fall back to slow start */

        cubic_state->alg_state = picoquic_cubic_alg_slow_start;
        cubic_state->ssthresh = UINT64_MAX;
        path_x->is_ssthresh_initialized = 0;
        cubic_state->previous_start_of_epoch = cubic_state->start_of_epoch;
        cubic_state->start_of_epoch = current_time;
        cubic_state->W_reno = PICOQUIC_CWIN_MINIMUM;
        path_x->cwin = PICOQUIC_CWIN_MINIMUM;
    }
    else {
        if (notification == picoquic_congestion_notification_timeout) {
            path_x->cwin = PICOQUIC_CWIN_MINIMUM;
            cubic_state->previous_start_of_epoch = cubic_state->start_of_epoch;
            cubic_state->start_of_epoch = current_time;
            cubic_state->alg_state = picoquic_cubic_alg_slow_start;
        }
        else {
            /* Enter congestion avoidance immediately */
            cubic_enter_avoidance(cubic_state, current_time);
            /* Compute the initial window for both Reno and Cubic */
            double W_cubic = cubic_W_cubic(cubic_state, current_time);
            uint64_t win_cubic = (uint64_t)(W_cubic * (double)path_x->send_mtu);
            cubic_state->W_reno = ((double)path_x->cwin) / 2.0;

            /* The formulas that compute "W_cubic" at the beginning of congestion avoidance
            * guarantee that "w_cubic" is larger than "w_reno" even if "fast convergence"
            * is applied as long as "beta_cubic" is greater than
            * (-1 + sqrt(1+4))/2, about 0.618033988749895.
            * Since beta_cubic is set to 3/4, we do not need to compare "w_cubic" and
            * "w_reno" to pick the largest. */
            path_x->cwin = win_cubic;
        }
    }
}

/* On spurious repeat notification, restore the previous congestion control.
 * Assume that K is still valid -- we only update it after exiting recovery.
 * Set cwin to the value of W_max before the recovery event
 * Set W_max to W_max_last, i.e. the value before the recovery event
 * Set the epoch back to where it was, by computing the inverse of the
 * W_cubic formula */
static void cubic_correct_spurious(picoquic_path_t* path_x,
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{
    if (cubic_state->ssthresh != UINT64_MAX) {
        cubic_state->W_max = cubic_state->W_last_max;
        cubic_enter_avoidance(cubic_state, cubic_state->previous_start_of_epoch);
        double W_cubic = cubic_W_cubic(cubic_state, current_time);
        cubic_state->W_reno = W_cubic * (double)path_x->send_mtu;
        cubic_state->ssthresh = (uint64_t)(cubic_state->W_max * PICOQUIC_CUBIC_BETA * (double)path_x->send_mtu);
        path_x->cwin = (uint64_t)cubic_state->W_reno;
    }
}

/*
 * Properly implementing Cubic requires managing a number of
 * signals, such as packet losses or acknowledgements. We attempt
 * to condensate all that in a single API, which could be shared
 * by many different congestion control algorithms.
 */
static void cubic_notify(
    picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time)
{
    picoquic_cubic_state_t* cubic_state = (picoquic_cubic_state_t*)path_x->congestion_alg_state;
    path_x->is_cc_data_updated = 1;

    if (cubic_state != NULL) {
        switch (notification) {
            /* RTT measurements will happen before acknowledgement is signalled */
            case picoquic_congestion_notification_acknowledgement:
                switch (cubic_state->alg_state) {
                    case picoquic_cubic_alg_slow_start:
                        /* Increase cwin based on bandwidth estimation. */
                        path_x->cwin = picoquic_cc_update_target_cwin_estimation(path_x);

                        if (path_x->last_time_acked_data_frame_sent > path_x->last_sender_limited_time) {
                            /* cubic_state->hystart_pp_state.css_baseline_min_rtt == UINT64_MAX -> in SS
                             * cubic_state->hystart_pp_state.css_baseline_min_rtt < UINT64_MAX -> in CSS */
                            path_x->cwin += picoquic_cc_slow_start_increase_ex(path_x, ack_state->nb_bytes_acknowledged,
                            (IS_HYSTART_PP_ENABLED(cnx)) ? IS_IN_CSS(cubic_state->hystart_pp_state) : 0);

                            /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                            if (path_x->cwin >= cubic_state->ssthresh) {
                                cubic_state->W_reno = ((double)path_x->cwin) / 2.0;
                                path_x->is_ssthresh_initialized = 1;
                                cubic_enter_avoidance(cubic_state, current_time);
                            }
                        }
                        break;
                    /* TODO discuss
                     * picoquic_cubic_alg_recovery is not entered anyway
                     */
                    case picoquic_cubic_alg_recovery:
                        /* exit recovery, move to CA or SS, depending on CWIN */
                        cubic_state->alg_state = picoquic_cubic_alg_slow_start;
                        path_x->cwin += ack_state->nb_bytes_acknowledged;
                        /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                        if (path_x->cwin >= cubic_state->ssthresh) {
                            cubic_state->alg_state = picoquic_cubic_alg_congestion_avoidance;
                        }
                        break;
                    case picoquic_cubic_alg_congestion_avoidance:
                        if (path_x->last_time_acked_data_frame_sent > path_x->last_sender_limited_time) {
                            double W_cubic;
                            uint64_t win_cubic;
                            /* Protection against limited senders. */
                            if (cubic_state->start_of_epoch < path_x->last_sender_limited_time) {
                                cubic_state->start_of_epoch = path_x->last_sender_limited_time;
                            }
                            /* Compute the cubic formula */
                            W_cubic = cubic_W_cubic(cubic_state, current_time);
                            win_cubic = (uint64_t)(W_cubic * (double)path_x->send_mtu);
                            /* Also compute the Reno formula */
                            cubic_state->W_reno += ((double)ack_state->nb_bytes_acknowledged) * ((double)path_x->send_mtu) / cubic_state->W_reno;

                            /* Pick the largest */
                            if ((double)win_cubic > cubic_state->W_reno) {
                                /* if cubic is larger than threshold, switch to cubic mode */
                                path_x->cwin = win_cubic;
                            }
                            else {
                                path_x->cwin = (uint64_t)cubic_state->W_reno;
                            }
                        }
                        break;
                }
                break;
            case picoquic_congestion_notification_repeat:
            case picoquic_congestion_notification_timeout:
            case picoquic_congestion_notification_ecn_ec:
                switch (cubic_state->alg_state) {
                    case picoquic_cubic_alg_slow_start:
                        /* For compatibility with Linux-TCP deployments, we implement a filter so
                         * Cubic will only back off after repeated losses, not just after a single loss.
                         */
                        if ((notification == picoquic_congestion_notification_ecn_ec ||
                            picoquic_cc_hystart_loss_test(&cubic_state->rtt_filter, notification, ack_state->lost_packet_number, PICOQUIC_SMOOTHED_LOSS_THRESHOLD)) &&
                            (current_time - cubic_state->start_of_epoch > path_x->smoothed_rtt ||
                                cubic_state->recovery_sequence <= picoquic_cc_get_ack_number(cnx, path_x))) {
                            path_x->is_ssthresh_initialized = 1;
                            cubic_enter_recovery(cnx, path_x, notification, cubic_state, current_time);
                        }
                        break;
                    case picoquic_cubic_alg_recovery:
                    case picoquic_cubic_alg_congestion_avoidance:
                        /* For compatibility with Linux-TCP deployments, we implement a filter so
                         * Cubic will only back off after repeated losses, not just after a single loss.
                         */
                        if (ack_state->lost_packet_number >= cubic_state->recovery_sequence &&
                            (notification == picoquic_congestion_notification_ecn_ec ||
                                picoquic_cc_hystart_loss_test(&cubic_state->rtt_filter, notification, ack_state->lost_packet_number, PICOQUIC_SMOOTHED_LOSS_THRESHOLD))) {
                            /* Re-enter recovery */
                            cubic_enter_recovery(cnx, path_x, notification, cubic_state, current_time);
                        }
                        break;
                }
                break;
            case picoquic_congestion_notification_spurious_repeat:
                /* Reset CWIN based on ssthresh, not based on current value. */
                cubic_correct_spurious(path_x, cubic_state, current_time);
                break;
            case picoquic_congestion_notification_rtt_measurement:
                if (cubic_state->alg_state == picoquic_cubic_alg_slow_start &&
                    cubic_state->ssthresh == UINT64_MAX) {

                    switch (cnx->hystart_alg) {
                        case picoquic_hystart_alg_hystart_t:
                            /* HyStart. */
                            /* Using RTT increases as signal to get out of initial slow start */
                            if (picoquic_cc_hystart_test(&cubic_state->rtt_filter, (cnx->is_time_stamp_enabled) ? ack_state->one_way_delay : ack_state->rtt_measurement,
                                    cnx->path[0]->pacing.packet_time_microsec, current_time, cnx->is_time_stamp_enabled)) {
                                /* RTT increased too much, get out of slow start! */

                                if (cubic_state->rtt_filter.rtt_filtered_min > PICOQUIC_TARGET_RENO_RTT){
                                    double correction;
                                    if (cubic_state->rtt_filter.rtt_filtered_min > PICOQUIC_TARGET_SATELLITE_RTT) {
                                        correction = (double)PICOQUIC_TARGET_SATELLITE_RTT / (double)cubic_state->rtt_filter.rtt_filtered_min;
                                    }
                                    else {
                                        correction = (double)PICOQUIC_TARGET_RENO_RTT / (double)cubic_state->rtt_filter.rtt_filtered_min;
                                    }
                                    uint64_t base_window = (uint64_t)(correction * (double)path_x->cwin);
                                    uint64_t delta_window = path_x->cwin - base_window;
                                    path_x->cwin -= (delta_window / 2);
                                }
#if 1
                                else {
                                    /* In the general case, compensate for the growth of the window after the acknowledged packet was sent. */
                                    path_x->cwin /= 2;
                                }
#endif

                                cubic_state->ssthresh = path_x->cwin;
                                cubic_state->W_max = (double)path_x->cwin / (double)path_x->send_mtu;
                                cubic_state->W_last_max = cubic_state->W_max;
                                cubic_state->W_reno = ((double)path_x->cwin);
                                path_x->is_ssthresh_initialized = 1;
                                /* enter recovery to ignore the losses expected if the window grew
                                * too large after the acknowleded packet was sent. */
                                cubic_enter_recovery(cnx, path_x, notification, cubic_state, current_time);
                                /* apply a correction to enter the test phase immediately */
                                uint64_t K_micro = (uint64_t)(cubic_state->K * 1000000.0);
                                if (K_micro > current_time) {
                                    cubic_state->K = ((double)current_time) / 1000000.0;
                                    cubic_state->start_of_epoch = 0;
                                }
                                else {
                                    cubic_state->start_of_epoch = current_time - K_micro;
                                }
                            }
                            break;
                        case picoquic_hystart_alg_hystart_pp_t:
                            /* HyStart++. */
                            /* Keep track of the minimum RTT seen so far. */
                            picoquic_hystart_pp_keep_track(&cubic_state->hystart_pp_state, ack_state->rtt_measurement);

                            /* Switch between SS and CSS. */
                            picoquic_hystart_pp_test(&cubic_state->hystart_pp_state);

                            /* Check if we reached the end of the round. */
                            /* HyStart++ measures rounds using sequence numbers, as follows:
                             * - When windowEnd is ACKed, the current round ends and windowEnd is set to SND.NXT.
                             */
                            if (picoquic_cc_get_ack_number(cnx, path_x) != UINT64_MAX && picoquic_cc_get_ack_number(cnx, path_x) >= cubic_state->hystart_pp_state.current_round.window_end) {
                                /* Round has ended. */
                                if (IS_IN_CSS(cubic_state->hystart_pp_state)) {
                                    /* In CSS increase CSS round counter. */
                                    cubic_state->hystart_pp_state.css_round_count++;

                                    /* Enter CA if css round counter > max css rounds. */
                                    if (cubic_state->hystart_pp_state.css_round_count >= PICOQUIC_HYSTART_PP_CSS_ROUNDS) {
                                        cubic_state->ssthresh = path_x->cwin;
                                        cubic_state->W_max = (double)path_x->cwin / (double)path_x->send_mtu;
                                        cubic_state->W_last_max = cubic_state->W_max;
                                        cubic_state->W_reno = ((double)path_x->cwin);
                                        path_x->is_ssthresh_initialized = 1;
                                        cubic_enter_avoidance(cubic_state, current_time);
                                    }
                                }

                                /* Start new round. */
                                picoquic_hystart_pp_start_new_round(&cubic_state->hystart_pp_state, cnx, path_x);
                            }
                            break;
                        default:
                            break;
                    }
                }
                break;
            case picoquic_congestion_notification_seed_cwin:
                if (cubic_state->alg_state == picoquic_cubic_alg_slow_start) {
                    if (cubic_state->ssthresh == UINT64_MAX) {
                        if (path_x->cwin < ack_state->nb_bytes_acknowledged) {
                            path_x->cwin = ack_state->nb_bytes_acknowledged;
                        }
                        cubic_state->ssthresh = ack_state->nb_bytes_acknowledged;
                        cubic_state->W_max = (double)path_x->cwin / (double)path_x->send_mtu;
                        cubic_state->W_last_max = cubic_state->W_max;
                        cubic_state->W_reno = ((double)path_x->cwin);
                        path_x->is_ssthresh_initialized = 1;
                        cubic_enter_avoidance(cubic_state, current_time);
                    }
                }
                break;
            /*
             * cover cubic_reset().
             */
            case picoquic_congestion_notification_reset:
                cubic_reset(cubic_state, cnx, path_x, current_time);
                break;
            default:
                break;

        }

        /* Compute pacing data */
        picoquic_update_pacing_data(cnx, path_x, cubic_state->alg_state == picoquic_cubic_alg_slow_start &&
            cubic_state->ssthresh == UINT64_MAX);
    }
}
/* Exit slow start on either long delay of high loss
 */
static void dcubic_exit_slow_start(
    picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{
    if (cubic_state->ssthresh == UINT64_MAX) {
        path_x->is_ssthresh_initialized = 1;
        cubic_state->ssthresh = path_x->cwin;
        cubic_state->W_max = (double)path_x->cwin / (double)path_x->send_mtu;
        cubic_state->W_last_max = cubic_state->W_max;
        cubic_state->W_reno = ((double)path_x->cwin);
        cubic_enter_avoidance(cubic_state, current_time);
        /* apply a correction to enter the test phase immediately */
        uint64_t K_micro = (uint64_t)(cubic_state->K * 1000000.0);
        if (K_micro > current_time) {
            cubic_state->K = ((double)current_time) / 1000000.0;
            cubic_state->start_of_epoch = 0;
        }
        else {
            cubic_state->start_of_epoch = current_time - K_micro;
        }
    }
    else {
        if (current_time - cubic_state->start_of_epoch > path_x->smoothed_rtt ||
            cubic_state->recovery_sequence <= picoquic_cc_get_ack_number(cnx, path_x)) {
            /* re-enter recovery if this is a new event */
            cubic_enter_recovery(cnx, path_x, notification, cubic_state, current_time);
        }
    }
}

/*
 * Define delay-based Cubic, dcubic, and alternative congestion control protocol similar to Cubic but 
 * using delay measurements instead of reacting to packet losses. This is a quic hack, intended for
 * trials of a lossy satellite networks.
 */
static void dcubic_notify(
    picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time)
{
    picoquic_cubic_state_t* cubic_state = (picoquic_cubic_state_t*)path_x->congestion_alg_state;
    path_x->is_cc_data_updated = 1;
    if (cubic_state != NULL) {
        switch (notification) {
            case picoquic_congestion_notification_repeat:
            case picoquic_congestion_notification_timeout:
                switch (cubic_state->alg_state) {
                    case picoquic_cubic_alg_slow_start:
                        /* In contrast to Cubic, only exit on high losses */
                        if (picoquic_cc_hystart_loss_test(&cubic_state->rtt_filter, notification, ack_state->lost_packet_number, PICOQUIC_SMOOTHED_LOSS_THRESHOLD)) {
                            dcubic_exit_slow_start(cnx, path_x, notification, cubic_state, current_time);
                        }
                        break;
                    case picoquic_cubic_alg_recovery:
                        break;
                    case picoquic_cubic_alg_congestion_avoidance:
                        /* In contrast to Cubic, only exit on high losses */
                        if (picoquic_cc_hystart_loss_test(&cubic_state->rtt_filter, notification, ack_state->lost_packet_number, PICOQUIC_SMOOTHED_LOSS_THRESHOLD) &&
                            ack_state->lost_packet_number > cubic_state->recovery_sequence) {
                            /* re-enter recovery */
                            cubic_enter_recovery(cnx, path_x, notification, cubic_state, current_time);
                        }
                        break;
                }
                break;
            case picoquic_congestion_notification_rtt_measurement:
                switch (cubic_state->alg_state) {
                    case picoquic_cubic_alg_slow_start:
                        /* if in slow start, increase the window for long delay RTT */
                        if (path_x->rtt_min > PICOQUIC_TARGET_RENO_RTT && cubic_state->ssthresh == UINT64_MAX) {
                            path_x->cwin = picoquic_cc_update_cwin_for_long_rtt(path_x);
                        }

                        switch (cnx->hystart_alg) {
                            case picoquic_hystart_alg_hystart_t:
                                /* HyStart. */
                                /* Using RTT increases as congestion signal. This is used
                                 * for getting out of slow start, but also for ending a cycle
                                 * during congestion avoidance */
                                if (picoquic_cc_hystart_test(&cubic_state->rtt_filter, (cnx->is_time_stamp_enabled) ? ack_state->one_way_delay : ack_state->rtt_measurement,
                                    cnx->path[0]->pacing.packet_time_microsec, current_time, cnx->is_time_stamp_enabled)) {
                                    dcubic_exit_slow_start(cnx, path_x, notification, cubic_state, current_time);
                                }
                                break;
                            case picoquic_hystart_alg_hystart_pp_t:
                                /* HyStart++. */
                                /* Using RTT increases as congestion signal. This is used
                                 * for getting out of slow start, but also for ending a cycle
                                 * during congestion avoidance */

                                /* Keep track of the minimum RTT seen so far. */
                                picoquic_hystart_pp_keep_track(&cubic_state->hystart_pp_state, ack_state->rtt_measurement);

                                /* Switch between SS and CSS. */
                                picoquic_hystart_pp_test(&cubic_state->hystart_pp_state);

                                /* Check if we reached the end of the round. */
                                /* HyStart++ measures rounds using sequence numbers, as follows:
                                 * - When windowEnd is ACKed, the current round ends and windowEnd is set to SND.NXT.
                                 */
                                if (picoquic_cc_get_ack_number(cnx, path_x) != UINT64_MAX && picoquic_cc_get_ack_number(cnx, path_x) >= cubic_state->hystart_pp_state.current_round.window_end) {
                                    /* Round has ended. */

                                    if (cubic_state->hystart_pp_state.css_baseline_min_rtt != UINT64_MAX) {
                                        /* In CSS increase CSS round counter. */
                                        cubic_state->hystart_pp_state.css_round_count++;

                                        /* Enter CA if css round counter > max css rounds. */
                                        if (cubic_state->hystart_pp_state.css_round_count >= PICOQUIC_HYSTART_PP_CSS_ROUNDS) {
                                            cubic_state->ssthresh = path_x->cwin;
                                            cubic_state->W_max = (double)path_x->cwin / (double)path_x->send_mtu;
                                            cubic_state->W_last_max = cubic_state->W_max;
                                            cubic_state->W_reno = ((double)path_x->cwin);
                                            path_x->is_ssthresh_initialized = 1;
                                            dcubic_exit_slow_start(cnx, path_x, notification, cubic_state, current_time);
                                        }
                                    }

                                    /* Start new round. */
                                    picoquic_hystart_pp_start_new_round(&cubic_state->hystart_pp_state, cnx, path_x);
                                }
                                break;
                            default:
                                break;
                        }

                        break;
                    case picoquic_cubic_alg_recovery:
                        /* if in slow start, increase the window for long delay RTT */
                        if (path_x->rtt_min > PICOQUIC_TARGET_RENO_RTT && cubic_state->ssthresh == UINT64_MAX) {
                            path_x->cwin = picoquic_cc_update_cwin_for_long_rtt(path_x);
                        }
                        /* continue */
                    case picoquic_cubic_alg_congestion_avoidance:
                        /* Using RTT increases as congestion signal. This is used
                         * for getting out of slow start, but also for ending a cycle
                         * during congestion avoidance */
                        if (picoquic_cc_hystart_test(&cubic_state->rtt_filter, (cnx->is_time_stamp_enabled) ? ack_state->one_way_delay : ack_state->rtt_measurement,
                                cnx->path[0]->pacing.packet_time_microsec, current_time, cnx->is_time_stamp_enabled)) {
                            if (current_time - cubic_state->start_of_epoch > path_x->smoothed_rtt ||
                                cubic_state->recovery_sequence <= picoquic_cc_get_ack_number(cnx, path_x)) {
                                /* re-enter recovery */
                                cubic_enter_recovery(cnx, path_x, notification, cubic_state, current_time);
                            }
                        }
                        break;
                }
                break;
            case picoquic_congestion_notification_spurious_repeat:
                /* In contrast to Cubic, do nothing here */
                break;
            case picoquic_congestion_notification_ecn_ec:
                /* In contrast to Cubic, do nothing here */
                break;
            default:
                cubic_notify(cnx, path_x, notification, ack_state, current_time);
                /* return immediately to avoid calculation of pacing rate twice. */
                return;
        }

        /* Compute pacing data */
        picoquic_update_pacing_data(cnx, path_x, 
            cubic_state->alg_state == picoquic_cubic_alg_slow_start && cubic_state->ssthresh == UINT64_MAX);
    }
}


/* Release the state of the congestion control algorithm */
static void cubic_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}

/* Observe the state of congestion control */

void cubic_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    picoquic_cubic_state_t* cubic_state = (picoquic_cubic_state_t*)path_x->congestion_alg_state;
    *cc_state = (uint64_t)cubic_state->alg_state;
    *cc_param = (uint64_t)cubic_state->W_max;
}


/* Definition record for the Cubic algorithm */

#define picoquic_cubic_ID "cubic" /* CBIC */
#define picoquic_dcubic_ID "dcubic" /* DBIC */

picoquic_congestion_algorithm_t picoquic_cubic_algorithm_struct = {
    picoquic_cubic_ID, PICOQUIC_CC_ALGO_NUMBER_CUBIC,
    cubic_init,
    cubic_notify,
    cubic_delete,
    cubic_observe
};

picoquic_congestion_algorithm_t picoquic_dcubic_algorithm_struct = {
    picoquic_dcubic_ID, PICOQUIC_CC_ALGO_NUMBER_DCUBIC,
    cubic_init,
    dcubic_notify,
    cubic_delete,
    cubic_observe
};

picoquic_congestion_algorithm_t* picoquic_cubic_algorithm = &picoquic_cubic_algorithm_struct;
picoquic_congestion_algorithm_t* picoquic_dcubic_algorithm = &picoquic_dcubic_algorithm_struct;
