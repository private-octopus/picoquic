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

#ifndef CC_COMMON_H
#define CC_COMMON_H

#ifdef __cplusplus
extern "C" {
#endif

#define PICOQUIC_MIN_MAX_RTT_SCOPE 7
#define PICOQUIC_SMOOTHED_LOSS_SCOPE 32
#define PICOQUIC_SMOOTHED_LOSS_FACTOR (1.0/16.0)
#define PICOQUIC_SMOOTHED_LOSS_THRESHOLD (0.15)

/*
 * HyStart++
 */

/* It is RECOMMENDED that a HyStart++ implementation use the following constants: */
/* MIN_RTT_THRESH = 4 msec
 * MAX_RTT_THRESH = 16 msec
 * MIN_RTT_DIVISOR = 8
 * N_RTT_SAMPLE = 8
 * CSS_GROWTH_DIVISOR = 4
 * CSS_ROUNDS = 5
 * L = infinity if paced, L = 8 if non-paced
 */
/* Take a look at the RFC for more information. */
#define PICOQUIC_HYSTART_PP_MIN_RTT_THRESH 4000 /* msec */
#define PICOQUIC_HYSTART_PP_MAX_RTT_THRESH 16000 /* msec */
#define PICOQUIC_HYSTART_PP_MIN_RTT_DIVISOR 8
#define PICOQUIC_HYSTART_PP_N_RTT_SAMPLE 8
#define PICOQUIC_HYSTART_PP_CSS_GROWTH_DIVISOR 4
#define PICOQUIC_HYSTART_PP_CSS_ROUNDS 5
/* Since picoquic is always paced, L is set to infinity (UINT64_MAX).
 * Because L is only used to limit the increase function, we don't need it at all. For more information, take a look at
 * the picoquic_hystart_pp_increase() function.
 */
/* #define PICOQUIC_HYSTART_PP_L UINT64_MAX */ /* infinity if paced, L = 8 if non-paced */

typedef struct st_picoquic_min_max_rtt_t {
    uint64_t last_rtt_sample_time;
    uint64_t rtt_filtered_min;
    int nb_rtt_excess;
    int sample_current;
    int is_init;
    double smoothed_drop_rate;
    uint64_t smoothed_bytes_sent_16;
    uint64_t smoothed_bytes_lost_16;
    uint64_t last_lost_packet_number;
    uint64_t sample_min;
    uint64_t sample_max;
    uint64_t samples[PICOQUIC_MIN_MAX_RTT_SCOPE];
} picoquic_min_max_rtt_t;

uint64_t picoquic_cc_get_sequence_number(picoquic_cnx_t* cnx, picoquic_path_t* path_x);

uint64_t picoquic_cc_get_ack_number(picoquic_cnx_t* cnx, picoquic_path_t * path_x);

uint64_t picoquic_cc_get_ack_sent_time(picoquic_cnx_t* cnx, picoquic_path_t* path_x);

/*
 * Slow Start
 * Returns number of bytes CWIN should be increased.
 */

uint64_t picoquic_cc_slow_start_increase(picoquic_path_t* path_x, uint64_t nb_delivered);

uint64_t picoquic_cc_slow_start_increase_ex(picoquic_path_t* path_x, uint64_t nb_delivered, int in_css);

uint64_t picoquic_cc_slow_start_increase_ex2(picoquic_path_t* path_x, uint64_t nb_delivered, int in_css, uint64_t prague_alpha);

/*
 * HyStart
 */

void picoquic_cc_filter_rtt_min_max(picoquic_min_max_rtt_t* rtt_track, uint64_t rtt);

int picoquic_cc_hystart_loss_test(picoquic_min_max_rtt_t* rtt_track, picoquic_congestion_notification_t event, uint64_t lost_packet_number, double error_rate_max);

int picoquic_cc_hystart_loss_volume_test(picoquic_min_max_rtt_t* rtt_track, picoquic_congestion_notification_t event, uint64_t nb_bytes_newly_acked, uint64_t nb_bytes_newly_lost);

int picoquic_cc_hystart_test(picoquic_min_max_rtt_t* rtt_track, uint64_t rtt_measurement, uint64_t packet_time, uint64_t current_time, int is_one_way_delay_enabled);

/*
 * HyStart++
 */

#define IS_HYSTART_PP(hystart_alg) (hystart_alg == picoquic_hystart_alg_hystart_pp_t)
#define IS_IN_CSS(hystart_pp_state) (hystart_pp_state.css_baseline_min_rtt != UINT64_MAX)

typedef struct st_picoquic_hystart_pp_round_t {
    uint64_t last_round_min_rtt;
    uint64_t current_round_min_rtt;
    //uint64_t curr_rtt; /* TODO check if needed */
    uint64_t rtt_sample_count;
    uint64_t window_end;
} picoquic_hystart_pp_round_t;

typedef struct st_picoquic_hystart_pp_state_t {
    picoquic_hystart_pp_round_t current_round;

    uint64_t rtt_thresh;
    uint64_t css_baseline_min_rtt;
    uint64_t css_round_count;
} picoquic_hystart_pp_state_t;

void picoquic_hystart_pp_reset(picoquic_hystart_pp_state_t* hystart_pp_state, picoquic_cnx_t* cnx, picoquic_path_t* path_x);

void picoquic_hystart_pp_start_new_round(picoquic_hystart_pp_state_t* hystart_pp_state, picoquic_cnx_t* cnx, picoquic_path_t* path_x);

void picoquic_hystart_pp_keep_track(picoquic_hystart_pp_state_t* hystart_pp_state, uint64_t rtt_measurement);

void picoquic_hystart_pp_test(picoquic_hystart_pp_state_t* hystart_pp_state);

int picoquic_cc_hystart_pp_test(picoquic_hystart_pp_state_t* hystart_pp_state, picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t rtt_measurement);

/*
 * Returns CWIN based on bandwidth estimation if larger than current CWIN. Otherwise, returns current CWIN.
 */
uint64_t picoquic_cc_update_target_cwin_estimation(picoquic_path_t* path_x);

/*
 * Returns CWIN for long RTT connections if larger than current CWIN. Otherwise, returns current CWIN.
 */
uint64_t picoquic_cc_update_cwin_for_long_rtt(picoquic_path_t* path_x);

/* Many congestion control algorithms run a parallel version of new reno in order
 * to provide a lower bound estimate of either the congestion window or the
 * the minimal bandwidth. This implementation of new reno does not directly
 * refer to the connection and path variables (e.g. cwin) but instead sets
 * its entire state in memory.
 */

typedef enum {
    picoquic_newreno_alg_slow_start = 0,
    picoquic_newreno_alg_congestion_avoidance
} picoquic_newreno_alg_state_t;

typedef struct st_picoquic_newreno_sim_state_t {
    picoquic_newreno_alg_state_t alg_state;
    uint64_t cwin;
    uint64_t residual_ack;
    uint64_t ssthresh;
    uint64_t recovery_start;
    uint64_t recovery_sequence;
} picoquic_newreno_sim_state_t;

void picoquic_newreno_sim_reset(picoquic_newreno_sim_state_t* nrss);

void picoquic_newreno_sim_notify(
    picoquic_newreno_sim_state_t* nr_state,
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time);

#ifdef __cplusplus
}
#endif

#endif