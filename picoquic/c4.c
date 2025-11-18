/*
* Author: Christian Huitema
* Copyright (c) 2025, Private Octopus, Inc.
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

/* C4 algorithm is a work in progress. We start with some simple principles:
* - Track delays, but this expose issue when competing with Cubic
* - Compete with Cubic: fallback to BBRv1, best of last 6 epochs, ignore delays, losses.
* - Stopping the compete mode? When the delay becomes acceptable?
* - App limited mode: freeze the parameters? Do probe on search?
* - Probing mode: probe for one RTT, recover for one RTT, assess after recover.
* - Probing interval: Fibonacci sequence, up to 16 or 17? 1, 1, 2, 3, 5, 8, 13
* - Tuning the interval: no bw increase => larger, bw increase => sooner, how soon?
* - stopping the compete mode: ECN? ECN as signal that the bottleneck is actively managed.
* - compete with self? Maybe introduce some random behavior.
* Principles were later revised to track data rate and max RTT.
 */

/* States of C4:
* 
* Initial.   Similar to Hystart for now, as a place holder.
* Recovery.  After an event, freeze the parameters for one RTT. This is the time
*            to measure whether a previous push was a success.
* Cruising.  For N intervals. Be ready to notice congestion, or change in conditions.
*            We should define N as x*log(cwin / cwin_min), so connections sending
*            lots of data wait a bit longer, which should improve fairness.
*            Question: is this "N intervals" or "some amount of data sent"?
*            the latter is better for the fairness issue.
* Pushing.   For one RTT. Transmit at higher rate, to probe the network, then
*            move to "cruising". Higher rate should be 25% higher, to probe
*            without creating big queues.
* Slowdown.  Periodic slowdown to 1/2 the nominal CWIN, in order to reset
*            the min delay.
* Checking:  Post slowdown. use nominal CWND until the min CWND is
*            verified.
* 
* Transitions:
*            initial to recovery -- similar to hystart for now.
*            recovery to initial -- if measurements show increase in data rate compared to era.
*            recovery to cruising -- at the end of period.
*            cruising, pushing to recovery -- if excess delay, loss or ECN
*            pushing to recovery -- at end of period.
*            to slowdown..
* 
* 
* State variables:
* - CWIN. Main control variable.
* - Sequence number of first packet sent in epoch. Epoch ends when this is acknowledged.
* - Observed data rate. Measured at the end of epoch N, reflects setting at epoch N-1.
* - Average rate of EC marking
* - Average rate of Packet loss
* - Average rate of excess delay
* - Number of cruising bytes sent.
* - Cruising bytes target before transition to push
* - RTT min
 */

#define C4_WITH_LOGGING 

#define PICOQUIC_CC_ALGO_NUMBER_C4 8
#define C4_DELAY_THRESHOLD_MAX 25000
#define MULT1024(c, v) (((v)*(c)) >> 10)
#define C4_ALPHA_NEUTRAL_1024 1024 /* 100% */
#define C4_ALPHA_RECOVER_1024 960 /* 93.75% */
#define C4_ALPHA_CRUISE_1024 1024 /* 100% */
#define C4_ALPHA_PUSH_1024 1280 /* 125 % */
#define C4_ALPHA_PUSH_LOW_1024 1088 /* 106.25 % */
#define C4_ALPHA_INITIAL 2048 /* 200% */
#define C4_ALPHA_PREVIOUS_LOW 960 /* 93.75% */
#define C4_BETA_1024 128 /* 0.125 */
#define C4_BETA_LOSS_1024 256 /* 25%, 1/4th */
#define C4_BETA_INITIAL_1024 512 /* 50% */
#define C4_NB_PACKETS_BEFORE_LOSS 20
#define C4_NB_PUSH_BEFORE_RESET 4
#define C4_NB_CRUISE_BEFORE_PUSH 4
#define C4_MAX_DELAY_ERA_CONGESTIONS 4
#define C4_RTT_MARGIN_5PERCENT 51
#define C4_MAX_JITTER 250000
#define C4_KAPPA ((double)(1.0/4.0))
#define C4_ECN_SHIFT_G 4 /* g = 1/2^4, gain parameter for alpha EWMA */

typedef enum {
    c4_initial = 0,
    c4_recovery,
    c4_cruising,
    c4_pushing
} c4_alg_state_t;


typedef enum {
    c4_congestion_none = 0,
    c4_congestion_delay,
    c4_congestion_ecn,
    c4_congestion_loss
} c4_congestion_t;

typedef struct st_c4_state_t {
    c4_alg_state_t alg_state;
    uint64_t nominal_rate; /* Control variable if not delay based. */
    uint64_t nominal_max_rtt; /* Estimate of queue-free max RTT */
    uint64_t running_min_rtt; /* Rough estimate of min RTT, for buffer estimation */
    uint64_t alpha_1024_current;
    uint64_t alpha_1024_previous;
    uint64_t nb_packets_in_startup;
    uint64_t era_sequence; /* sequence number of first packet in era */
    uint64_t nb_cruise_left_before_push; /* Number of cruise periods required before push */
    uint64_t seed_cwin; /* Value of CWIN remembered from previous trials */
    uint64_t seed_rate; /* data rate remembered from seed cwin. */

    int nb_eras_no_increase;
    int nb_push_no_congestion; /* Number of successive pushes with no congestion */
    uint64_t push_rate_old;
    uint64_t push_alpha;

    uint64_t era_max_rtt;
    uint64_t era_min_rtt;

    uint64_t delay_threshold;
    uint64_t recent_delay_excess;

    uint64_t last_lost_packet_number; /* Used for computation of loss rate. Init to 0 */
    double smoothed_drop_rate; /* Average packet loss rate */

    uint64_t ecn_alpha; /* average marking rate */
    uint64_t ecn_ect1; /* running total of ect1 marks */
    uint64_t ecn_ce; /* running total of ce marks */
    uint64_t ecn_threshold; /* Congestion notified if ecn_alpha > ecn_threshold */

    unsigned int recovery_event_not_delay : 1;
    unsigned int congestion_notified : 1;
    unsigned int push_was_not_limited : 1;
    unsigned int use_seed_cwin : 1;
    unsigned int initial_after_jitter : 1;
    unsigned int do_cascade : 1;
    unsigned int do_slow_push : 1;
    /* Handling of options. */
    char const* option_string;
} c4_state_t;

static void c4_enter_recovery(
    picoquic_path_t* path_x,
    c4_state_t* c4_state,
    c4_congestion_t c_mode,
    uint64_t current_time);

static void c4_enter_cruise(
    picoquic_path_t* path_x,
    c4_state_t* c4_state,
    uint64_t current_time);

/* The sensitivity function provides a value from 0 to 1
* indicating how sensitive this flow is to congestion event.
* The idea is that flow consuming lots of resource should react
* faster than flow that consume little, leading eventually
* to good sharing of resource.
*/
/* The sensitivity will be directly translated into a packet
* loss detection threshold. We want that threshold to be very
* high at low data rates (lower than 50kB/s), about 2% at
* high data rate (matching the sensitivity of BBR), and 
* about 5% at intermediate rates (1MBps), with slopes
* in between. We assume that the loss threshold is computed as:
*
* Threshold = 2% + (1-sensitivity)*50%
* 
* This gives us the curve points:
* - 0 to 50kB/s: 0
* - 1MB/s: (1-0.03/0.5) = 0.94, approximate to 963/1024
* - 10MB/s: 1
*/

static uint64_t c4_sensitivity_1024(c4_state_t* c4_state)
{
    uint64_t sensitivity = 1024;
    if (c4_state->nominal_rate < 50000) {
        sensitivity = 0;
    }
    else if (c4_state->nominal_rate > 10000000) {
        sensitivity = 1024;
    }
    else if (c4_state->nominal_rate < 1000000) {
        sensitivity = (c4_state->nominal_rate - 50000) * 963 / 950000;
    }
    else {
        sensitivity = 963 + ((c4_state->nominal_rate - 1000000) * 61 / 9000000);
    }
    return sensitivity;
}

/* Compute the delay threshold for declaring congestion,
* as the min of RTT/8 and c4_DELAY_THRESHOLD_MAX (25 ms) 
 */

uint64_t c4_delay_threshold(c4_state_t* c4_state)
{
    uint64_t sensitivity = c4_sensitivity_1024(c4_state);
    uint64_t fraction = 64 + MULT1024(1024 - sensitivity, 196);
    uint64_t delay = MULT1024(fraction, c4_state->nominal_max_rtt);
    if (delay > C4_DELAY_THRESHOLD_MAX) {
        delay = C4_DELAY_THRESHOLD_MAX;
    }
    return delay;
}

/* Compute the ECNmarking threshold for declaring a congestion event.
* The marking threshold should be large if the sensitivity is small --
* maybe 25%, and smaller if the sensitivity is large -- maybe 12.5%.
*/
uint64_t c4_ecn_threshold(c4_state_t* c4_state)
{
    uint64_t sensitivity = c4_sensitivity_1024(c4_state);

    uint64_t ecn_threshold = 256 - MULT1024(sensitivity, 128);

    return ecn_threshold;
}

/* Compute the loss rate threshold for declaring a congestion event
*/
double c4_loss_threshold(c4_state_t* c4_state)
{
    uint64_t sensitivity = c4_sensitivity_1024(c4_state);
    double fraction = ((double)sensitivity) / 1024.0;
    double loss_threshold = 0.02 + 0.50 * (1-fraction);

    return loss_threshold;
}

/* Compute the loss rate */
void c4_update_loss_rate(c4_state_t * c4_state, uint64_t lost_packet_number)
{
    uint64_t next_number = c4_state->last_lost_packet_number;

    if (lost_packet_number > next_number) {
        if (next_number + PICOQUIC_SMOOTHED_LOSS_SCOPE < lost_packet_number) {
            next_number = lost_packet_number - PICOQUIC_SMOOTHED_LOSS_SCOPE;
        }

        while (next_number < lost_packet_number) {
            c4_state->smoothed_drop_rate *= (1.0 - PICOQUIC_SMOOTHED_LOSS_FACTOR);
            next_number++;
        }

        c4_state->smoothed_drop_rate += (1.0 - c4_state->smoothed_drop_rate) * PICOQUIC_SMOOTHED_LOSS_FACTOR;
        c4_state->last_lost_packet_number = lost_packet_number;
    }
}

/* Compute the ECN alpha
*
* This is similar the prague implementation.
*/
static void c4_update_ecn_alpha(picoquic_path_t* path_x, c4_state_t* c4_state, uint64_t current_time)
{
    uint64_t frac = 0;
    picoquic_packet_context_t* pkt_ctx = (path_x->cnx->is_multipath_enabled)?
        &path_x->pkt_ctx : &path_x->cnx->pkt_ctx[picoquic_packet_context_application];
    int64_t delta_ect1 = pkt_ctx->ecn_ect1_total_remote - c4_state->ecn_ect1;
    int64_t delta_ce = pkt_ctx->ecn_ce_total_remote - c4_state->ecn_ce;

    c4_state->ecn_ect1 = pkt_ctx->ecn_ect1_total_remote;
    c4_state->ecn_ce = pkt_ctx->ecn_ce_total_remote;

    if (delta_ce > 0 || delta_ect1 > 0) {
        frac = (delta_ce * 1024) / (delta_ce + delta_ect1);

        if (frac > c4_state->ecn_alpha && frac >= 512) {
            c4_state->ecn_alpha = frac;
        }
        else
        {
            uint64_t alpha_shifted = c4_state->ecn_alpha << C4_ECN_SHIFT_G;
            alpha_shifted -= c4_state->ecn_alpha;
            alpha_shifted += frac;
            c4_state->ecn_alpha = alpha_shifted >> C4_ECN_SHIFT_G;
        }
    }
    picoquic_log_app_message(path_x->cnx,
        "C4-ECN: %" PRIu64 ",%d,%d,%d,%" PRIu64 ",%" PRIu64,
        current_time, (int)delta_ect1, (int)delta_ce, (int)c4_state->ecn_alpha, path_x->cwin, path_x->rtt_sample);
}

/*
* c4_apply_rate_and_cwin:
* Manage all setting of the actual cwin, pacing rate and quantum
* at a single place, based on the state parameters computed
* in the other functions.
*/

static void c4_apply_rate_and_cwin(
    picoquic_path_t* path_x,
    c4_state_t* c4_state)
{

    uint64_t pacing_rate = MULT1024(c4_state->alpha_1024_current, c4_state->nominal_rate);
    uint64_t quantum;
    uint64_t target_cwin = PICOQUIC_CWIN_INITIAL;
    if (c4_state->nominal_max_rtt != 0 && c4_state->nominal_rate != 0) {
        target_cwin = (pacing_rate * c4_state->nominal_max_rtt) / 1000000;
    }

    if (c4_state->alg_state == c4_initial) {
        if (target_cwin < PICOQUIC_CWIN_INITIAL) {
            /* target CWIN is always at least PICOQUIC_CWIN_INITIAL.
            * If that is too much, C4 will detect congestion and exit the
            * initial stage.
             */
            target_cwin = PICOQUIC_CWIN_INITIAL;
        }
        /* Initial special case: bandwidth discovery */
        if (c4_state->nb_packets_in_startup > 0) {
            uint64_t min_win = (path_x->peak_bandwidth_estimate * path_x->smoothed_rtt / 1000000) / 2;
            if (min_win > target_cwin) {
                target_cwin = min_win;
            }
            if (path_x->peak_bandwidth_estimate > 2*pacing_rate) {
                pacing_rate = path_x->peak_bandwidth_estimate / 2;
            }
        }
        /* Initial special case: seed cwin */
        if (c4_state->use_seed_cwin && c4_state->seed_cwin > target_cwin) {
            /* Match half the difference between seed and computed CWIN */
            target_cwin = (c4_state->seed_cwin + target_cwin) / 2;
            c4_state->seed_rate = (c4_state->seed_cwin * 1000000) / path_x->smoothed_rtt;
            if (c4_state->seed_rate > pacing_rate) {
                pacing_rate = c4_state->seed_rate;
            }
        }
        /* Increase pacing rate by factor 1.25 to allow for bunching of packets */
        pacing_rate = MULT1024(1024+256, pacing_rate);
    }
    else if (c4_state->alg_state == c4_pushing) {
        uint64_t delta_alpha = c4_state->alpha_1024_current - 1024;
        uint64_t delta_rate = MULT1024(delta_alpha, c4_state->nominal_rate);
        uint64_t delta_cwin = (delta_rate * c4_state->nominal_max_rtt) / 1000000;
        if (delta_cwin < path_x->send_mtu) {
            target_cwin += path_x->send_mtu - delta_cwin;
        }
    }

    path_x->cwin = target_cwin;
    quantum = target_cwin / 4;
    if (quantum > 0x10000) {
        quantum = 0x10000;
    }
    else if (quantum < 2 * path_x->send_mtu) {
        quantum = 2 * path_x->send_mtu;
    }
    picoquic_update_pacing_rate(path_x->cnx, path_x, (double)pacing_rate, quantum);
}

/* Perform evaluation. Assess whether the previous era resulted
 * in a significant increase or not.
 */
static void c4_growth_evaluate(c4_state_t* c4_state)
{
    int is_growing = 0;
    if (c4_state->push_alpha > C4_ALPHA_PUSH_LOW_1024) {
        /* If the value of "push_alpha" was large enough, we can reasonably
         * measure growth. */
        uint64_t target_rate = (3*c4_state->push_rate_old +
            MULT1024(c4_state->push_alpha, c4_state->push_rate_old)) / 4;
        is_growing = (c4_state->nominal_rate > target_rate);
    }
    else {
        /* If the value was not big enough, we have to make decision
         * based on congestion signals.
         */
        is_growing = (c4_state->nominal_rate > c4_state->push_rate_old &&
            !c4_state->congestion_notified);
    }
    if (is_growing) {
        c4_state->nb_push_no_congestion++;
        c4_state->nb_eras_no_increase = 0;
    }
    else if (c4_state->push_was_not_limited) {
        c4_state->nb_push_no_congestion = 0;
        c4_state->nb_eras_no_increase++;
    }
}

static void c4_growth_reset(c4_state_t* c4_state)
{
    c4_state->congestion_notified = 0;
    c4_state->push_was_not_limited = 0;
    c4_state->push_rate_old = c4_state->nominal_rate;
    /* Push alpha will have to be reset to the correct value when entering push */
    c4_state->push_alpha = c4_state->alpha_1024_current;
}


/* End of round trip.
* Happens if packet waited for is acked.
* Add bandwidth measurement to bandwidth barrel.
 */
static int c4_era_check(
    picoquic_path_t* path_x,
    c4_state_t* c4_state)
{
    if (path_x->cnx->cnx_state < picoquic_state_ready) {
        return 0;
    }
    else {
        return (picoquic_cc_get_ack_number(path_x->cnx, path_x) >= c4_state->era_sequence);
    }
}

static void c4_era_reset(
    picoquic_path_t* path_x,
    c4_state_t* c4_state,
    uint64_t current_time)
{
    c4_state->era_sequence = picoquic_cc_get_sequence_number(path_x->cnx, path_x);
    c4_state->era_max_rtt = 0;
    c4_state->era_min_rtt = UINT64_MAX;
    c4_state->alpha_1024_previous = c4_state->alpha_1024_current;
    c4_update_ecn_alpha(path_x, c4_state, current_time);
}

static void c4_enter_initial(picoquic_path_t* path_x, c4_state_t* c4_state, uint64_t current_time)
{
    c4_state->alg_state = c4_initial;
    c4_state->nb_push_no_congestion = 0;
    c4_state->alpha_1024_current = C4_ALPHA_INITIAL;
    c4_state->nb_packets_in_startup = 0;
    c4_era_reset(path_x, c4_state, current_time);
    c4_state->nb_eras_no_increase = 0;
    c4_state->ecn_alpha = 0;
    c4_growth_reset(c4_state);
}

static void c4_set_options(c4_state_t* c4_state)
{
    if (c4_state->option_string != NULL) {
        char const* x = c4_state->option_string;
        char c;
        int ended = 0;

        while ((c = *x) != 0 && !ended) {
            x++;
            switch (c) {
            case 'K': /* allow the cascade behavior */
                c4_state->do_cascade = 1;
                break;
            case 'k': /* disallow the cascade behavior */
                c4_state->do_cascade = 0;
                break;
            case 'O': /* allow the slow push behavior */
                c4_state->do_slow_push = 1;
                break;
            case 'o': /* disallow the slow push behavior */
                c4_state->do_slow_push = 0;
                break;
            default:
                ended = 1;
                break;
            }
        }
    }
}

void c4_reset(c4_state_t* c4_state, picoquic_path_t* path_x, char const* option_string, uint64_t current_time)
{
    memset(c4_state, 0, sizeof(c4_state_t));
    c4_state->option_string = option_string;
    c4_state->running_min_rtt = UINT64_MAX;
    c4_state->alpha_1024_current = C4_ALPHA_INITIAL;
    c4_state->do_slow_push = 1;
    c4_state->do_cascade = 1;
    c4_set_options(c4_state);
    c4_enter_initial(path_x, c4_state, current_time);
}

void c4_seed_cwin(c4_state_t* c4_state, picoquic_path_t* path_x, uint64_t bytes_in_flight)
{
    if (c4_state->alg_state == c4_initial) {
        c4_state->use_seed_cwin = 1;
        c4_state->seed_cwin = bytes_in_flight;
    }
}

static void c4_exit_initial(picoquic_path_t* path_x, c4_state_t* c4_state, picoquic_congestion_notification_t notification, uint64_t current_time)
{
    /* We assume that any required correction is done prior to calling this */
    c4_state->nb_eras_no_increase = 0;
    c4_state->nb_push_no_congestion = 0;
    c4_enter_recovery(path_x, c4_state, c4_congestion_none, current_time);
}

static void c4_initial_handle_rtt(picoquic_path_t* path_x, c4_state_t* c4_state, picoquic_congestion_notification_t notification, uint64_t rtt_measurement, uint64_t current_time)
{
    /* HyStart. */
    /* Using RTT increases as congestion signal. This is used
     * for getting out of slow start, but also for ending a cycle
     * during congestion avoidance */
    /* we do not directly use "hystart test", because we want to separate the
    * "update_rtt" functions from the actual tests.
     */
    if (c4_state->recent_delay_excess > 0
        && c4_state->nb_eras_no_increase > 1
        && c4_state->push_rate_old >= c4_state->nominal_rate){

        c4_exit_initial(path_x, c4_state, notification, current_time);
    }
}

static void c4_initial_handle_loss(picoquic_path_t* path_x, c4_state_t* c4_state, picoquic_congestion_notification_t notification, uint64_t current_time)
{
    c4_state->nb_packets_in_startup += 1;
    if (c4_state->nb_packets_in_startup > C4_NB_PACKETS_BEFORE_LOSS) {
        c4_exit_initial(path_x, c4_state, notification, current_time);
    }
}

static void c4_initial_handle_ack(picoquic_path_t* path_x, c4_state_t* c4_state, picoquic_per_ack_state_t* ack_state, uint64_t current_time)
{
    c4_state->nb_packets_in_startup += 1;
    if (c4_state->use_seed_cwin && c4_state->seed_rate > 0 &&
        c4_state->nominal_rate >= c4_state->seed_rate) {
        /* The nominal bandwidth is larger than the seed. The seed has been validated. */
        c4_state->use_seed_cwin = 0;
    }
    if (c4_era_check(path_x, c4_state)) {
        /*
        * We should only consider a lack of increase if the application is
        * not app limited. However, if the application *is* app limited,
        * that strategy leads to staying in "initial" mode forever,
        * which is not good either. If we don't check if the app limited,
        * we lose in the very common case where the server sends almost
        * nothing for several RTT, until the client asks for some data.
        * So we test that we have seen at least some data.
        */
        c4_growth_evaluate(c4_state);
        c4_era_reset(path_x, c4_state, current_time);
        if (c4_state->nb_eras_no_increase >= 3) {
            c4_exit_initial(path_x, c4_state, picoquic_congestion_notification_acknowledgement, current_time);
            return;
        }
        else {
            c4_growth_reset(c4_state);
        }
    }
}

void c4_init(picoquic_cnx_t * cnx, picoquic_path_t* path_x, char const* option_string, uint64_t current_time)
{
    /* Initialize the state of the congestion control algorithm */
    c4_state_t* c4_state = path_x->congestion_alg_state;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx);
#endif
    
    if (c4_state == NULL) {
        c4_state = (c4_state_t*)malloc(sizeof(c4_state_t));
    }
    
    if (c4_state != NULL){
        cnx->is_lost_feedback_notification_required = 1;
        
        c4_reset(c4_state, path_x, option_string, current_time);
    }

    path_x->congestion_alg_state = (void*)c4_state;
}

/*
* Enter recovery.
* CWIN is set to C4_ALPHA_RECOVER of nominal value (90%)
* Remember the first no ACK packet -- recovery will end when that
* packet is acked.
*/
static void c4_enter_recovery(
    picoquic_path_t* path_x,
    c4_state_t* c4_state,
    c4_congestion_t c_mode,
    uint64_t current_time)
{
    if (c_mode != c4_congestion_none) {
        c4_state->recovery_event_not_delay = 0;
    }
    else {
        c4_state->nb_push_no_congestion = 0;
        c4_state->recovery_event_not_delay = (c_mode != c4_congestion_delay);
    }
    c4_state->alpha_1024_current = C4_ALPHA_RECOVER_1024;

    if (c4_state->alg_state == c4_initial) {
        c4_growth_reset(c4_state);
    }
    /* There may be multiple congestion signals coming in, but we 
    * will not reinitialize the state if C4 is already in recovery.
     */
    if (c4_state->alg_state != c4_recovery) {
        c4_state->alg_state = c4_recovery;
        c4_era_reset(path_x, c4_state, current_time);
    }
}

/* Exit recovery. We will test whether the previous push was successful.
* We do that by comparing the nominal cwin to the value before entering
* push. This "previous value" would be zero if the previous state
* was not pushing.
 */

static void c4_exit_recovery(
    picoquic_path_t* path_x,
    c4_state_t* c4_state, uint64_t current_time)
{
    /* Assess growth */
    c4_growth_evaluate(c4_state);
    c4_growth_reset(c4_state);
    /* Reset the delay excess to avoid bounces of delay event */
    c4_state->recent_delay_excess = 0;
    /* Reset the smoothed drop rate at the end of recovery.
    * so that the next measurements reflect the new parameters.
    */
    c4_state->smoothed_drop_rate = 0;
    /* Reset the ecn_alpha */
    c4_state->ecn_alpha = 0;


    /* Trigger the cascade if we have many successful pushes */
    if (c4_state->nb_push_no_congestion >= C4_NB_PUSH_BEFORE_RESET) {
        c4_enter_initial(path_x, c4_state, current_time);
    }
    else {
        c4_enter_cruise(path_x, c4_state, current_time);
    }
}

/* Enter cruise.
* CWIN is set C4_ALPHA_CRUISE of nominal value (98%?)
* Ack target if set to nominal cwin times log2 of cwin.
*/
static void c4_enter_cruise(
    picoquic_path_t* path_x,
    c4_state_t* c4_state,
    uint64_t current_time)
{
    c4_era_reset(path_x, c4_state, current_time);
    c4_state->use_seed_cwin = 0;

    if (c4_state->nb_push_no_congestion > 0 && c4_state->do_cascade) {
        c4_state->nb_cruise_left_before_push = 0;
    }
    else {
        c4_state->nb_cruise_left_before_push = C4_NB_CRUISE_BEFORE_PUSH;
    }
    c4_state->alpha_1024_current = C4_ALPHA_CRUISE_1024;
    c4_state->alg_state = c4_cruising;
}

/* Enter push.
* CWIN is set C4_ALPHA_PUSH of nominal value (125%?)q
* Ack target if set to nominal cwin times log2 of cwin.
*/
static void c4_enter_push(
    picoquic_path_t* path_x,
    c4_state_t* c4_state,
    uint64_t current_time)
{
    if (c4_state->nb_push_no_congestion == 0 && c4_state->do_slow_push) {
        /* If the previous push was not successful, increase by 6.25% instead of 25% */
        c4_state->alpha_1024_current = C4_ALPHA_PUSH_LOW_1024;
    }
    else {
        c4_state->alpha_1024_current = C4_ALPHA_PUSH_1024;
    }
    if (c4_state->ecn_alpha > 0) {
        uint64_t scale_1024;
        uint64_t push_delta;
        c4_state->ecn_threshold = c4_ecn_threshold(c4_state);
        scale_1024 = (c4_state->ecn_alpha * 1024) / c4_state->ecn_threshold;
        push_delta = MULT1024(scale_1024, c4_state->alpha_1024_current);
        c4_state->alpha_1024_current -= push_delta;
    }
    c4_state->push_alpha = c4_state->alpha_1024_current;
    c4_era_reset(path_x, c4_state, current_time);
    c4_state->alg_state = c4_pushing;
}

void c4_update_min_max_rtt(picoquic_path_t* path_x, c4_state_t* c4_state)
{
    /* Include the last sample, to deal with order of arrivals between ACK and RTT */
    if (path_x->rtt_sample > c4_state->era_max_rtt) {
        c4_state->era_max_rtt = path_x->rtt_sample;
    }
    if (path_x->rtt_sample < c4_state->era_min_rtt) {
        c4_state->era_min_rtt = path_x->rtt_sample;
    }
    /* Update the running min RTT, as the max RTT computation depends on it. */
    if (c4_state->era_min_rtt < c4_state->running_min_rtt) {
        c4_state->running_min_rtt = c4_state->era_min_rtt;
    }
    else if (c4_state->alpha_1024_previous <= C4_ALPHA_PREVIOUS_LOW) {
        c4_state->running_min_rtt = (7 * c4_state->running_min_rtt + c4_state->era_min_rtt) / 8;
    }
    /* Update the max RTT */
    if (c4_state->nominal_max_rtt == 0) {
        c4_state->nominal_max_rtt = c4_state->era_max_rtt;
    }
    else if (c4_state->alpha_1024_previous <= 1024) {
        /* We want to increase the max RTT, but we want to limit the jitter
         * measurement to avoid aberrant behavior.
         */
        uint64_t corrected_max = (c4_state->era_max_rtt < c4_state->running_min_rtt + C4_MAX_JITTER) ?
            c4_state->era_max_rtt : c4_state->running_min_rtt + C4_MAX_JITTER;

        if (corrected_max > c4_state->nominal_max_rtt) {
            c4_state->nominal_max_rtt = corrected_max;
        }
        else if (c4_state->alpha_1024_previous <= C4_ALPHA_PREVIOUS_LOW) {
            /* If not growing, slowly diminish the max rtt */
            c4_state->nominal_max_rtt = (7 * c4_state->nominal_max_rtt + corrected_max) / 8;
        }
    }
    /* Recompute the delay threshold if the max RTT was updated. */
    c4_state->delay_threshold = c4_delay_threshold(c4_state);
}

/* Handle data ack event.
 */
void c4_handle_ack(picoquic_path_t* path_x, c4_state_t* c4_state, picoquic_per_ack_state_t* ack_state, uint64_t current_time)
{
    uint64_t previous_rate = c4_state->nominal_rate;
    uint64_t rate_measurement = 0;

    if (ack_state->rtt_measurement > 0 && ack_state->nb_bytes_delivered_since_packet_sent > 0) {
        uint64_t verified_rtt = (ack_state->rtt_measurement > ack_state->send_delay) ?
            ack_state->rtt_measurement : ack_state->send_delay;
        rate_measurement = (ack_state->nb_bytes_delivered_since_packet_sent * 1000000) /
            verified_rtt;

#ifdef C4_WITH_LOGGING
        /* Collect raw measurements for analysis */
        picoquic_log_app_message(path_x->cnx,
            "C4_rate, %" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%d ,%" PRIu64 ", %d",
            rate_measurement, c4_state->nominal_rate, 
            ack_state->nb_bytes_delivered_since_packet_sent, ack_state->rtt_measurement, ack_state->send_delay,
            c4_state->nominal_max_rtt, (int)c4_state->alg_state, path_x->bandwidth_estimate, c4_state->congestion_notified);
#endif

        /* Assessment of rate limited status */
        if (rate_measurement > c4_state->nominal_rate  && 
            !(c4_state->alg_state == c4_recovery && c4_state->congestion_notified != 0)) {
            c4_state->push_was_not_limited = 1;
            c4_state->nominal_rate = rate_measurement;
            c4_state->delay_threshold = c4_delay_threshold(c4_state);
        }
        else {
            /* The ACK rate did not grow, but that's not a proof.
                * If the number of bytes sent are larger than the corrected bytes,
                * we know the delivery was slowed by the network, not the app.
                */
            uint64_t target_cwin = (previous_rate * c4_state->running_min_rtt) / 1000000;
            if (ack_state->nb_bytes_delivered_since_packet_sent > target_cwin) {
                c4_state->push_was_not_limited = 1;
            }
        }
    }

    if (c4_state->alg_state == c4_initial) {
        c4_initial_handle_ack(path_x, c4_state, ack_state, current_time);
    }
    else {
        if (c4_era_check(path_x, c4_state)) {
            /* Update max rtt and running min rtt */
            c4_update_min_max_rtt(path_x, c4_state);
            /* test need to reenter initial if conditions did change */
            if (!c4_state->initial_after_jitter &&
                c4_state->nominal_max_rtt > 50000 &&
                5 * c4_state->running_min_rtt < 2 * c4_state->nominal_max_rtt) {
                c4_state->initial_after_jitter = 1;
                c4_enter_initial(path_x, c4_state, current_time);
            }
            else
            {
                /* Manage the transition to the next state */
                switch (c4_state->alg_state) {
                case c4_recovery:
                    c4_exit_recovery(path_x, c4_state, current_time);
                    break;
                case c4_cruising:
                    if (c4_state->nb_cruise_left_before_push > 0) {
                        c4_state->nb_cruise_left_before_push--;
                    }
                    c4_era_reset(path_x, c4_state, current_time);
                    if (c4_state->nb_cruise_left_before_push <= 0 &&
                        path_x->last_time_acked_data_frame_sent > path_x->last_sender_limited_time) {
                        c4_enter_push(path_x, c4_state, current_time);
                    }
                    break;
                case c4_pushing:
                    c4_enter_recovery(path_x, c4_state, c4_congestion_none, current_time);
                    break;
                default:
                    c4_era_reset(path_x, c4_state, current_time);
                    break;
                }
            }
        }
    }
}

/* Reaction to ECN/CE or sustained losses.
 * This is more or less the same code as added to bbr.
 * This code is called if an ECN/EC event is received, 
 * or a lost event indicating a high loss rate,
 * or a delay event.
 * 
 * TODO: proper treatment of ECN per L4S
 */
static void c4_notify_congestion(
    picoquic_path_t* path_x,
    c4_state_t* c4_state,
    uint64_t rtt_latest,
    c4_congestion_t c_mode,
    uint64_t current_time)
{
    uint64_t beta = C4_BETA_LOSS_1024;
    c4_state->congestion_notified = 1;

    if (c4_state->alg_state == c4_recovery &&
        (c_mode != c4_congestion_delay || !c4_state->recovery_event_not_delay)) {
        /* Do not treat additional events during same freeze interval */
        return;
    }

    if (c_mode == c4_congestion_loss) {
        /* Make amount of slow down function of sensitivity,
        * for better fairness between C4 connections.
        */
        beta = (C4_BETA_LOSS_1024 + MULT1024(c4_sensitivity_1024(c4_state), C4_BETA_LOSS_1024))/2;
    }
    else if (c_mode == c4_congestion_ecn) {
        /* Apply proportional reduction. Question: should it be sensitivity related? */
        beta = (c4_state->ecn_alpha - c4_state->ecn_threshold) * 1024 / c4_state->ecn_threshold;
        if (beta > C4_BETA_LOSS_1024) {
            /* capping beta to the standard 1/4th. */
            beta = C4_BETA_LOSS_1024;
        }
    }
    
    if (c_mode == c4_congestion_delay) {
        /* TODO: we should really use bytes in flight! */
        beta = c4_state->recent_delay_excess*1024/c4_state->delay_threshold;

        if (beta > C4_BETA_LOSS_1024) {
            /* capping beta to the standard 1/4th. */
            beta = C4_BETA_LOSS_1024;
        }
    }
    else {
        /* Clear the excess delay to avoid spurious delay measurements */
        c4_state->recent_delay_excess = 0;
    }

    if (c4_state->alg_state == c4_pushing) {
        c4_state->nb_push_no_congestion = 0;
    }
    else {
        c4_state->nominal_rate -= MULT1024(beta, c4_state->nominal_rate);
        if (c_mode == c4_congestion_loss) {
            c4_state->nominal_max_rtt -= MULT1024(beta, c4_state->nominal_max_rtt);
            c4_state->delay_threshold = c4_delay_threshold(c4_state);
        }
    }

    c4_enter_recovery(path_x, c4_state, c_mode, current_time);

    c4_apply_rate_and_cwin(path_x, c4_state);

    path_x->is_ssthresh_initialized = 1;
}

/* Update RTT:
* Maintain rtt_min, rtt_max, and rtt_min_stamp,
* as well as rtt_min_is_trusted and delay_threshold.
* Do not otherwise change the state.
 */

static void c4_update_rtt(
    c4_state_t* c4_state,
    uint64_t rtt_measurement,
    uint64_t current_time)
{
    if (rtt_measurement > c4_state->era_max_rtt) {
        c4_state->era_max_rtt = rtt_measurement;
    }
    if (rtt_measurement < c4_state->era_min_rtt) {
        c4_state->era_min_rtt = rtt_measurement;
    }
    if (rtt_measurement < c4_state->running_min_rtt) {
        c4_state->running_min_rtt = rtt_measurement;
    }
    if (c4_state->nominal_max_rtt == 0) {
        c4_state->nominal_max_rtt = rtt_measurement;
        c4_state->recent_delay_excess = 0;
    }
    else {
        uint64_t target_rtt = c4_state->nominal_max_rtt + c4_state->delay_threshold;
        if (rtt_measurement > target_rtt) {
            c4_state->recent_delay_excess = rtt_measurement - target_rtt;
        }
        else {
            c4_state->recent_delay_excess = 0;
        }
    }
}

static void c4_handle_rtt(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    c4_state_t* c4_state,
    uint64_t rtt_measurement,
    uint64_t current_time)
{
    if (c4_state->recent_delay_excess > 0 &&
        c4_state->alpha_1024_previous > 1024) {
        /* May well be congested */
        c4_notify_congestion(path_x, c4_state, rtt_measurement, c4_congestion_delay, current_time);
    }
}

/*
 * Properly implementing c4 requires managing a number of
 * signals, such as packet losses or acknowledgements. We attempt
 * to condensate all that in a single API, which could be shared
 * by many different congestion control algorithms.
 */
void c4_notify(
    picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t * ack_state,
    uint64_t current_time)
{
    c4_state_t* c4_state = (c4_state_t*)path_x->congestion_alg_state;
    path_x->is_cc_data_updated = 1;

    if (ack_state != NULL && ack_state->pc != picoquic_packet_context_application) {
        return;
    }

    if (c4_state != NULL) {
        switch (notification) {
        case picoquic_congestion_notification_acknowledgement:
            c4_handle_ack(path_x, c4_state, ack_state, current_time);
            c4_apply_rate_and_cwin(path_x, c4_state);
            break;
        case picoquic_congestion_notification_ecn_ec:
            /* TODO: ECN is special? Implement the prague logic */
            c4_state->ecn_threshold = c4_ecn_threshold(c4_state);
            c4_update_ecn_alpha(path_x, c4_state, current_time);
            if (c4_state->ecn_alpha > c4_state->ecn_threshold) {
                c4_notify_congestion(path_x, c4_state, 0, c4_congestion_ecn, current_time);
            }
            break;
        case picoquic_congestion_notification_repeat:
            if (c4_state->alg_state == c4_recovery && ack_state->lost_packet_number < c4_state->era_sequence) {
                /* Do not worry about loss of packets sent before entering recovery */
                break;
            }
            c4_update_loss_rate(c4_state, ack_state->lost_packet_number);

            if (c4_state->smoothed_drop_rate > c4_loss_threshold(c4_state)) {
                if (c4_state->alg_state == c4_initial) {
                    c4_initial_handle_loss(path_x, c4_state, notification, current_time);
                }
                else {
                    c4_notify_congestion(path_x, c4_state, 0, c4_congestion_loss, current_time);
                }
            }
            break;
        case picoquic_congestion_notification_timeout:
            /* Treat timeout as PTO: no impact on congestion control */
            break;
        case picoquic_congestion_notification_spurious_repeat:
            /* Remove handling of spurious repeat, as it was tied to timeout */
            break;
        case picoquic_congestion_notification_rtt_measurement:
            c4_update_rtt(c4_state, ack_state->rtt_measurement, current_time);
            if (c4_state->alg_state == c4_initial) {
                c4_initial_handle_rtt(path_x, c4_state, notification, ack_state->rtt_measurement, current_time);
                c4_apply_rate_and_cwin(path_x, c4_state);
            }
            else {
                c4_handle_rtt(cnx, path_x, c4_state, ack_state->rtt_measurement, current_time);
            }
            break;
        case picoquic_congestion_notification_lost_feedback:
            break;
        case picoquic_congestion_notification_cwin_blocked:
            break;
        case picoquic_congestion_notification_reset:
            c4_reset(c4_state, path_x, c4_state->option_string, current_time);
            break;
        case picoquic_congestion_notification_seed_cwin:
            c4_seed_cwin(c4_state, path_x, ack_state->nb_bytes_acknowledged);
            break;
        default:
            /* ignore */
            break;
        }
    }
}

/* Release the state of the congestion control algorithm */
void c4_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}

/* Observe the state of congestion control */
void c4_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    c4_state_t* c4_state = (c4_state_t*)path_x->congestion_alg_state;
    *cc_state = (uint64_t)c4_state->alg_state;
    *cc_param = c4_state->nominal_max_rtt;
}

/* Definition record for the C4 CC algorithm */
#define C4_ID "c4" 

picoquic_congestion_algorithm_t c4_algorithm_struct = {
    C4_ID, PICOQUIC_CC_ALGO_NUMBER_C4,
    c4_init,
    c4_notify,
    c4_delete,
    c4_observe
};

picoquic_congestion_algorithm_t* c4_algorithm = &c4_algorithm_struct;
