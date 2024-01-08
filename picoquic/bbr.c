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

/*
Implementation of the BBR algorithm, tuned for Picoquic.

The main idea of BBR is to track the "bottleneck bandwidth", and to tune the
transport stack to send exactly at that speed. This ensures good network
utilisation while avoiding the building of queues. To do that the stack
needs to constantly estimate the available data rate. It does that by
measuring the rate at which acknowledgements come back, providing what it
calls the delivery rate.

That approach includes an implicit feedback loop. The delivery rate can never
exceed the sending rate. That will effectively detects a transmission slow
down due to partial congestion, but if the algorithm just did that the
sending rate will remain constant when the network is lightly loaded
and ratchet down during time of congestion, leading to very low efficiency.
The available bandwidth can only be tested by occasionally sending faster
than the measured delivery rate.

BBR does that by following a cycle of "send, test and drain". During the
sending period, the stack sends at the measured rate. During the testing
period, it sends faster, 25% faster with recommended parameters. This
risk creating a queue if the bandwidth had not increased, so the test
period is followed by a drain period during which the stack sends 25%
slower than the measured rate. If the test is successful, the new bandwidth
measurement will be available at the end of the draining period, and
the increased bandwidth will be used in the next cycle.

Tuning the sending rate does not guarantee a short queue, it only
guarantees a stable queue. BBR controls the queue by limiting the
amount of data "in flight" (congestion window, CWIN) to the product
of the bandwidth estimate by the RTT estimate, plus a safety marging to ensure
continuous transmission. Using the average RTT there would lead to a runaway
loop in which oversized windows lead to increased queues and then increased
average RTT. Instead of average RTT, BBR uses a minimum RTT. Since the
mimimum RTT might vary with routing changes, the minimum RTT is measured
on a sliding window of 10 seconds.

The bandwidth estimation needs to be robust against short term variations
common in wireless networks. BBR retains the maximum
delivery rate observed over a series of probing intervals. Each interval
starts with a specific packet transmission and ends when that packet
or a later transmission is acknowledged. BBR does that by tracking
the delivered counter associated with packets and comparing it to
the delivered counter at start of period.

During start-up, BBR performs its own equivalent of Reno's slow-start.
It does that by using a pacing gain of 2.89, i.e. sending 2.89 times
faster than the measured maximum. It exits slow start when it found
a bandwidth sufficient to fill the pipe.

The bandwidth measurements can be wrong if the application is not sending
enough data to fill the pipe. BBR tracks that, and does not reduce bandwidth
or exit slow start if the application is limiting transmission.

This implementation follows draft-cardwell-iccrg-bbr-congestion-control,
with a couple of changes for handling the multipath nature of quic.
There is a BBR control state per path.
Most of BBR the variables defined in the draft are implemented
in the "BBR state" structure, with a few exceptions:

* BBR.delivered is represented by path_x.delivered, and is maintained
  as part of ACK processing

* We use "bytes_in_transit", which is already maintained by the stack.

* Compute bytes_delivered by summing all calls to ACK(bytes) before
  the call to RTT update.

* In the Probe BW mode, the draft suggests cwnd_gain = 2. We observed
  that this results in queue sizes of 2, which is too high, so we
  reset that to 1.125.

The "packet" variables are defined in the picoquic_packet_t.

Early testing showed that BBR startup phase requires several more RTT
than the Hystart process used in modern versions of Reno or Cubic. BBR
only ramps up the data rate after the first bandwidth measurement is
available, 2*RTT after start, while Reno or Cubic start ramping up
after just 1 RTT. BBR only exits startup if three consecutive RTT
pass without significant BW measurement increase, which not only
adds delay but also creates big queues as data is sent at 2.89 times
the bottleneck rate. This is a tradeoff: longer search for bandwidth in
slow start is less likely to stop too early because of transient
issues, but one high bandwidth and long delay links this translates
to long delays and a big batch of packet losses.

This BBR implementation addresses these issues by switching to
Hystart instead of startup if the RTT is above the Reno target of
100 ms. 

*/

/* Detection of leaky-bucket pacers.
 * This is based on code added to BBR after the IETF draft was published.
 * The code detect whether the connection is being "policed" by a leaky-bucket based
 * parser, and introduces state variables:
 * - lt_use_bw, boolean: check whether the connection is currently constrained
 *   to use a limited bandwidth.
 * - lt_rtt_cnt: number of RTT during which the bandwidth has been limited. Exit the
 *   limited bandwidth state when this reaches the maximum value.
 * - lt_is_sampling: whether the connection is sampling the number of loss
 *   intervals. This starts when the first losses are noticed. It is reset if
 *   the bandwidth is app limited.
 * Sampling lasts for a number of rounds, as counted by the round_start
 * variable. No action taken except updating counters in that state.
 * Sampling can only ends on an interval when losses are detected, to avoid
 * undercounting. If no loss, sampling continues after the min required
 * interval. If no losses for too long, sampling state is reset.
 * At the end of the sampling interval compute the ratio of packets lost
 * to packet delivered. If it is below threshold, continue sampling, i.e.,
 * extend the interval.
 * If loss rate exceed the threshold, compute the duration of the interval.
 * If it is too short, extend. If is is too long, reset the sampling.
 * Else, compute the delivery rate for the interval. Check whether this
 * is the first detection, in which case do nothing but remember the estimated
 * rate in "lt_bw". Else, check whether the new rate is "close enough" to
 * the previous rate, which indicates active policing. If that is true,
 * activate policing to the average rate between current and previous sample.
 */

/* Reaction to losses and ECN
 * This code is an implementation of BBRv1, which pretty much ignores packet
 * losses or ECN marks. Google has still developed BBRv2, which is generally
 * considered much more robust. Once the BBRv2 specification is available,
 * we should develop it. However, before BBRv2 is there, we need to fix the
 * most egregious issues in BBR v1. For example, in a test, we show that if
 * a receiver starts a high speed download and then disappears, the sender
 * will only close the connection after repeating over 1000 packets,
 * compared to only 32 with New Reno or Cubic. This is because BBR does
 * not slow down or reduce the CWIN on loss indication, even when there
 * are many loss indications. 
 *
 * We implement the following fixes:
 *
 * - On basic loss indication, run a filter to determine whether the loss
 *   rate is getting too high. This will allow the code to continue
 *   ignoring low loss rates, but somehow react to high loss rates.
 *
 * - If high loss rate is detected, halve the congestion window. Do
 *   the same if an EC mark is received.
 *
 * - If a timeout loss is detected, reduce the window to the minimum
 *   value.
 *
 * This needs to be coordinated with the BBR state machine. We implement
 * it as such:
 *
 * - if the state is start-up or start-up-long-rtt, exit startup
 *   and move to a drain state.
 * - if the state is probe-bw, start the new period with a conservative
 *   packet window (trigger by cycle_on_loss state variable)
 * - if the state is probe-RTT, do nothing special...
 *
 * The packet losses and congestion signals should be used only once per
 * RTT. We filter with a "loss period start time" value, and only
 * take signals into account if they happen 1-RTT after the current
 * loss start time. However, if the previous loss was not due to
 * timeout, the timeout will still be handled.
 */

/*
* Handling of suspension
* 
* After a timeout, the path is suspended, and the congestion window is
* immediately reduced. If do not do anything in particular, the
* suspended state will be cleared on the first next acknowledgement,
* and the congestion window will be restored gradually.
* 
* This is correct in general, when the timeout is due to some series
* of packet loss events. It is not so good in the particular case of
* Wi-Fi suspension, when the timeout is caused by the Wi-Fi link
* being "suspended" for the time needed to scan other channels. In that
* case, the code will receive a "spurious time out" notification,
* typically triggered when an ACK queued "in the network" is delivered
* when transmission resume. Waiting for the next ACK has two
* downsides:
* 
* - it comes some times later, something like 1/2 RTT to 1 full RTT.
* - the CWIND is lower than if the suspension had not happened.
*
* The reasonable solution is to exit the suspended state upon
* notification of spurious reset, and restore the prior cwin.
*/

typedef enum {
    picoquic_bbr_alg_startup = 0,
    picoquic_bbr_alg_drain,
    picoquic_bbr_alg_probe_bw,
    picoquic_bbr_alg_probe_rtt,
    picoquic_bbr_alg_startup_long_rtt
} picoquic_bbr_alg_state_t;

#define BBR_BTL_BW_FILTER_LENGTH 10
#define BBR_RT_PROP_FILTER_LENGTH 10
#define BBR_HIGH_GAIN 2.8853900817779 /* 2/ln(2) */
#define BBR_MIN_PIPE_CWND(mss) ((mss)*4)
#define BBR_GAIN_CYCLE_LEN 8
#define BBR_PROBE_RTT_INTERVAL 10000000 /* 10 sec, 10000000 microsecs */
#define BBR_PROBE_RTT_DURATION 200000 /* 200msec, 200000 microsecs */
#define BBR_PACING_RATE_LOW 150000.0 /* 150000 B/s = 1.2 Mbps */
#define BBR_PACING_RATE_MEDIUM 3000000.0 /* 3000000 B/s = 24 Mbps */
#define BBR_GAIN_CYCLE_LEN 8
#define BBR_GAIN_CYCLE_MAX_START 5
#define BBR_LT_BW_INTERVAL_MIN_RTT 4
#define BBR_LT_BW_RATIO_SCALE 1024
#define BBR_LT_BW_RATIO_SCALED_TARGET 205 /* 205/1024 is very close 20% */

#define BBR_LT_BW_INTERVAL_MAX_RTT (4*BBR_LT_BW_INTERVAL_MIN_RTT)
#define BBR_LT_BW_RATIO_INVERSE 8
#define BBR_LT_BW_BYTES_PER_SEC_DIFF 4000
#define BBR_LT_BW_MAX_RTTS 48
#if 0
/* Use this setting when debugging BBR slow start */
#define BBR_HYSTART_THRESHOLD_RTT 1000000
#else
#define BBR_HYSTART_THRESHOLD_RTT 50000
#endif


static const double bbr_pacing_gain_cycle[BBR_GAIN_CYCLE_LEN] = { 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.25, 0.75};

typedef struct st_picoquic_bbr_state_t {
    picoquic_bbr_alg_state_t state;
    uint64_t btl_bw;
    uint64_t next_round_delivered;
    uint64_t btl_bw_filter[BBR_BTL_BW_FILTER_LENGTH];
    uint64_t full_bw;
    uint64_t rt_prop;
    uint64_t rt_prop_stamp;
    uint64_t cycle_stamp;
    uint64_t probe_rtt_done_stamp;
    uint64_t prior_cwnd;
    uint64_t prior_in_flight;
    uint64_t bytes_delivered; /* Number of bytes signalled in ACK notify, but not processed yet */
    uint64_t send_quantum;
    picoquic_min_max_rtt_t rtt_filter;
    uint64_t target_cwnd;
    double pacing_gain;
    double cwnd_gain;
    double pacing_rate;
    unsigned int cycle_index;
    unsigned int cycle_start;
    int round_count;
    int full_bw_count;
    int lt_rtt_cnt;
    uint64_t lt_bw;
    uint64_t lt_last_stamp; /* Time in microsec at start of interval */
    uint64_t previous_round_lost;
    uint64_t previous_sampling_delivered;
    uint64_t previous_sampling_lost;
    uint64_t loss_interval_start; /* Time in microsec when last loss considered */
    uint64_t congestion_sequence; /* sequence number after congestion notification */
    uint64_t cwin_before_suspension; /* So it can be restored if suspension stops. */
#if 1
    uint64_t epoch_start_stamp;
#endif
    uint64_t wifi_shadow_rtt; /* Shadow RTT used for wifi connections. */
    double quantum_ratio; /* Fraction of pacing rate used for Quantum, or zero if not set*/
    unsigned int filled_pipe : 1;
    unsigned int round_start : 1;
    unsigned int rt_prop_expired : 1;
    unsigned int probe_rtt_round_done : 1;
    unsigned int idle_restart : 1;
    unsigned int packet_conservation : 1;
    unsigned int btl_bw_increased : 1;
    unsigned int lt_use_bw : 1;
    unsigned int lt_is_sampling : 1;
    unsigned int last_loss_was_timeout : 1;
    unsigned int cycle_on_loss : 1;
    unsigned int is_suspended;
    unsigned int is_suspension_nearly_over : 1; /* Suspension likely over, waiting for ACK before repeating data. */

} picoquic_bbr_state_t;

void BBRltbwSampling(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time);
static void BBRResetProbeBwMode(picoquic_bbr_state_t* bbr_state, uint64_t current_time);

static uint64_t BBRGetBtlBW(picoquic_bbr_state_t* bbr_state)
{
    return (bbr_state->lt_use_bw) ? bbr_state->lt_bw : bbr_state->btl_bw;
}

void BBREnterStartupLongRTT(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x)
{
    uint64_t cwnd = PICOQUIC_CWIN_INITIAL;
    bbr_state->state = picoquic_bbr_alg_startup_long_rtt;

    if (path_x->rtt_min > PICOQUIC_TARGET_RENO_RTT) {
        if (path_x->rtt_min > PICOQUIC_TARGET_SATELLITE_RTT) {
            cwnd = (uint64_t)((double)cwnd * (double)PICOQUIC_TARGET_SATELLITE_RTT / (double)PICOQUIC_TARGET_RENO_RTT);
        }
        else {
            cwnd = (uint64_t)((double)cwnd * (double)path_x->rtt_min / (double)PICOQUIC_TARGET_RENO_RTT);
        }
    }
    if (cwnd > path_x->cwin) {
        path_x->cwin = cwnd;
    }
}

void BBREnterStartup(picoquic_bbr_state_t* bbr_state)
{
    bbr_state->state = picoquic_bbr_alg_startup;
    bbr_state->pacing_gain = BBR_HIGH_GAIN;
    bbr_state->cwnd_gain = BBR_HIGH_GAIN;
}

void BBRSetSendQuantum(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x)
{
    if (bbr_state->quantum_ratio == 0) {
        if (bbr_state->pacing_rate < BBR_PACING_RATE_LOW) {
            bbr_state->send_quantum = 1ull * path_x->send_mtu;
        } 
        else if (bbr_state->pacing_rate < BBR_PACING_RATE_MEDIUM) {
            bbr_state->send_quantum = 2ull * path_x->send_mtu;
        }
        else {
            bbr_state->send_quantum = (uint64_t)(bbr_state->pacing_rate * 0.001);
            if (bbr_state->send_quantum > 0x10000) {
                bbr_state->send_quantum = 0x10000;
            }
        }
    }
    else {
        bbr_state->send_quantum = (uint64_t)(bbr_state->pacing_rate * bbr_state->quantum_ratio);

        if (bbr_state->send_quantum > 0x10000) {
            bbr_state->send_quantum = 0x10000;
        }
        else if (bbr_state->send_quantum < 2ull * path_x->send_mtu) {
            if (bbr_state->send_quantum < 1ull * path_x->send_mtu) {
                bbr_state->send_quantum = 1ull * path_x->send_mtu;
            }
            else {
                bbr_state->send_quantum = 2ull * path_x->send_mtu;
            }
        }
    }
}

uint64_t BBRInflight(picoquic_bbr_state_t* bbr_state, double gain)
{
    uint64_t cwnd = PICOQUIC_CWIN_INITIAL;
    if (bbr_state->rt_prop != UINT64_MAX){
        /* Bandwidth is estimated in bytes per second, rtt in microseconds*/
        uint64_t rt_target = bbr_state->rt_prop;
        if (bbr_state->rt_prop < bbr_state->wifi_shadow_rtt) {
            rt_target = bbr_state->wifi_shadow_rtt;
        }
        double estimated_bdp = (((double)BBRGetBtlBW(bbr_state) * (double)rt_target) / 1000000.0);
        uint64_t quanta = 3 * bbr_state->send_quantum;       
        cwnd = (uint64_t)(gain * estimated_bdp) + quanta;
    }
    return cwnd;
}


void BBRUpdateTargetCwnd(picoquic_bbr_state_t* bbr_state)
{
    bbr_state->target_cwnd = BBRInflight(bbr_state, bbr_state->cwnd_gain);
}

static void picoquic_bbr_reset(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time, 
    uint64_t wifi_shadow_rtt, double quantum_ratio)
{
    memset(bbr_state, 0, sizeof(picoquic_bbr_state_t));
    path_x->cwin = PICOQUIC_CWIN_INITIAL;
    bbr_state->rt_prop = UINT64_MAX;
    bbr_state->wifi_shadow_rtt = wifi_shadow_rtt;
    bbr_state->quantum_ratio = quantum_ratio;

    bbr_state->rt_prop_stamp = current_time;
    bbr_state->cycle_stamp = current_time;
    bbr_state->cycle_index = 0;
    bbr_state->cycle_start = 0;

    BBREnterStartup(bbr_state);
    BBRSetSendQuantum(bbr_state, path_x);
    BBRUpdateTargetCwnd(bbr_state);
}

static void picoquic_bbr_init(picoquic_cnx_t * cnx, picoquic_path_t* path_x, uint64_t current_time)
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_bbr_state_t* bbr_state = (picoquic_bbr_state_t*)malloc(sizeof(picoquic_bbr_state_t));

    path_x->congestion_alg_state = (void*)bbr_state;
    if (bbr_state != NULL) {
        picoquic_bbr_reset(bbr_state, path_x, current_time, cnx->quic->wifi_shadow_rtt, cnx->quic->bbr_quantum_ratio);
    }
}

/* Release the state of the congestion control algorithm */
static void picoquic_bbr_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}


/* Implementation of leaky-bucket pacer detection
 */

void BBRltbwResetInterval(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time)
{
    bbr_state->lt_last_stamp = current_time;
    bbr_state->previous_sampling_delivered = path_x->delivered;
    bbr_state->previous_sampling_lost = path_x->total_bytes_lost;
    bbr_state->previous_round_lost = path_x->total_bytes_lost;
    bbr_state->lt_rtt_cnt = 0;
}

void BBRltbwResetSampling(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time)
{
    bbr_state->lt_bw = 0;
    bbr_state->lt_use_bw = 0;
    bbr_state->lt_is_sampling = 0;
    BBRltbwResetInterval(bbr_state, path_x, current_time);
}

void BBRltbwIntervalDone(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t bw, uint64_t current_time)
{
    if (bbr_state->lt_bw) {
        /* This is not the first limited interval. Look whether it is close enough */
        uint64_t diff = (bw > bbr_state->lt_bw) ? bw - bbr_state->lt_bw : bbr_state->lt_bw - bw;
        if (diff * BBR_LT_BW_RATIO_INVERSE < bbr_state->lt_bw ||
            diff < BBR_LT_BW_BYTES_PER_SEC_DIFF) {
            bbr_state->lt_bw = (bbr_state->lt_bw + bw) / 2;
            bbr_state->lt_use_bw = 1;
            bbr_state->pacing_gain = 1.0;
            bbr_state->lt_rtt_cnt = 0;
            return;
        }
    }
    /* If first interval or non-matching rate, just remember */
    bbr_state->lt_bw = bw;
    BBRltbwResetInterval(bbr_state, path_x, current_time);
}

void BBRltbwSampling(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time)
{
    uint64_t losses = (path_x->total_bytes_lost > bbr_state->previous_round_lost) ?
        path_x->total_bytes_lost - bbr_state->previous_round_lost : 0;
    uint64_t delivered;
    uint64_t interval_microsec;
    uint64_t bw;

    if (bbr_state->lt_use_bw) {
        if (bbr_state->state == picoquic_bbr_alg_probe_bw && bbr_state->round_start) {
            bbr_state->lt_rtt_cnt++;
            if (bbr_state->lt_rtt_cnt > BBR_LT_BW_MAX_RTTS) {
                BBRltbwResetSampling(bbr_state, path_x, current_time);
                BBRResetProbeBwMode(bbr_state, current_time);
                return;
            }
        }
    }
    
    if (!bbr_state->lt_is_sampling) {
            /* Return if no loss; */
            if (losses == 0) {
                return;
            }
            /* Reset sampling otherwise. */
            BBRltbwResetSampling(bbr_state, path_x, current_time);
            bbr_state->lt_is_sampling = 1;
    }

    /* Reset sampling if app is limited */
    if (path_x->last_bw_estimate_path_limited) {
        BBRltbwResetSampling(bbr_state, path_x, current_time);
        return;
    }
    /* Check whether we are reaching the end of the interval */
    if (!bbr_state->round_start) {
        return;
    } else {
        bbr_state->lt_rtt_cnt++;	/* count round trips in this interval */
        bbr_state->previous_round_lost = path_x->total_bytes_lost;

        if (bbr_state->lt_rtt_cnt < BBR_LT_BW_INTERVAL_MIN_RTT) {
            return;		/* sampling interval needs to be longer */
        }
        if (bbr_state->lt_rtt_cnt > BBR_LT_BW_INTERVAL_MAX_RTT) {
            BBRltbwResetSampling(bbr_state, path_x, current_time);  /* interval is too long */
            return;
        }
    }
    /* Continue sampling if no losses on this round */
    if (losses == 0) {
        return;
    }
    /* Calculate bytes lost and delivered in sampling interval.
     * Notice that the previous values of losses and delivered were for the round, not the interval.
     */
    if (path_x->delivered <= bbr_state->previous_sampling_delivered) {
        /* No delivery at all, cannot calculate any ratio, wait some more. */
        return;
    } 
    losses = (path_x->total_bytes_lost > bbr_state->previous_sampling_lost) ?
        path_x->total_bytes_lost - bbr_state->previous_sampling_lost : 0;
    delivered = path_x->delivered - bbr_state->previous_sampling_delivered;
    /* Check the loss ratio */
    if (losses * BBR_LT_BW_RATIO_SCALE < BBR_LT_BW_RATIO_SCALED_TARGET * delivered) {
        /* Not enough losses, continue sampling */
        return;
    }
    /* Find average delivery rate in this sampling interval. */
    interval_microsec = current_time - bbr_state->lt_last_stamp;
    if (interval_microsec < 1000) {
        /* Interval too small for significant measurements, wait a bit */
        return;
    }
    /* Compute  bw in bytes per second */
    bw = (delivered * 1000000) / interval_microsec; 
    /* Apply the changes */
    BBRltbwIntervalDone(bbr_state, path_x, bw, current_time);
}

/* Track the round count using the "delivered" counter. The value carried per
 * packet is the delivered count when this packet was sent. If it is greater
 * than next_round_delivered, it means that the packet was sent at or after
 * the beginning of the round, and thus that at least one RTT has elapsed
 * for this round. */

void BBRUpdateBtlBw(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time)
{
    uint64_t bandwidth_estimate = path_x->bandwidth_estimate;
#if 1
    if (path_x->delivered_last_packet >= bbr_state->next_round_delivered &&
        bbr_state->epoch_start_stamp < current_time)
    {
        uint64_t delivered_this_round = path_x->delivered_last_packet - bbr_state->next_round_delivered;
        uint64_t epoch_length = current_time - bbr_state->epoch_start_stamp;
        uint64_t alt_estimate = delivered_this_round*1000000 / epoch_length;
        if (alt_estimate > bandwidth_estimate) {
            bandwidth_estimate = alt_estimate;
        }
    }
#endif

    if (bbr_state->state == picoquic_bbr_alg_startup &&
        bandwidth_estimate < (path_x->peak_bandwidth_estimate / 2)) {
        bandwidth_estimate = path_x->peak_bandwidth_estimate/2;
    }

    if (bbr_state->rt_prop > 0) {
        /* Stop the bandwidth estimate from falling too low. */
        uint64_t min_bandwidth = (((uint64_t)PICOQUIC_CWIN_MINIMUM) * 1000000) / bbr_state->rt_prop;
        if (bandwidth_estimate < min_bandwidth) {
            bandwidth_estimate = min_bandwidth;
        }
    }

    if (path_x->delivered_last_packet >= bbr_state->next_round_delivered)
    {
        bbr_state->next_round_delivered = path_x->delivered;
        bbr_state->round_count++;
        bbr_state->round_start = 1;
    }
    else {
        bbr_state->round_start = 0;
    }

    BBRltbwSampling(bbr_state, path_x, current_time);

    if (bbr_state->round_start) {
#if 1
        bbr_state->epoch_start_stamp = current_time;
#endif
        if (bandwidth_estimate > bbr_state->btl_bw ||
            !path_x->last_bw_estimate_path_limited) {
            /* Forget the oldest BW round, shift by 1, compute the max BTL_BW for
            * the remaining rounds, set current round max to current value */
            bbr_state->btl_bw = 0;
            for (int i = BBR_BTL_BW_FILTER_LENGTH - 2; i >= 0; i--) {
                uint64_t b = bbr_state->btl_bw_filter[i];
                bbr_state->btl_bw_filter[i + 1] = b;
                if (b > bbr_state->btl_bw) {
                    bbr_state->btl_bw = b;
                }
            }
            bbr_state->btl_bw_increased |= (bandwidth_estimate > bbr_state->btl_bw_filter[0]);
            bbr_state->btl_bw_filter[0] = bandwidth_estimate;
            if (bandwidth_estimate > bbr_state->btl_bw) {
                bbr_state->btl_bw = bandwidth_estimate;
            }
        }
        else {
            bbr_state->btl_bw_increased = 0;
        }
    }
    else {
        if (bandwidth_estimate > bbr_state->btl_bw_filter[0]) {
            bbr_state->btl_bw_filter[0] =bandwidth_estimate;
            if (bandwidth_estimate > bbr_state->btl_bw) {
                bbr_state->btl_bw = bandwidth_estimate;
                bbr_state->btl_bw_increased = 1;
            }
        }
    }
}

/* This will use one way samples if available */
/* Should augment that with common RTT filter to suppress jitter */
void BBRUpdateRTprop(picoquic_bbr_state_t* bbr_state, uint64_t rtt_sample, uint64_t current_time)
{
    bbr_state->rt_prop_expired =
        current_time > bbr_state->rt_prop_stamp + BBR_PROBE_RTT_INTERVAL &&
        current_time > bbr_state->rt_prop_stamp + 20 * bbr_state->rt_prop;
    if (rtt_sample <= bbr_state->rt_prop || bbr_state->rt_prop_expired) {
        bbr_state->rt_prop = rtt_sample;
        bbr_state->rt_prop_stamp = current_time;
    }
    else {
        uint64_t delta = rtt_sample - bbr_state->rt_prop;
        if (20 * delta < bbr_state->rt_prop) {
            bbr_state->rt_prop_stamp = current_time;
        }
#if 1
        if (bbr_state->rt_prop < 1000 && rtt_sample < 5000){
            bbr_state->rt_prop_stamp = current_time;
        }
#endif
    }
}

int BBRIsNextCyclePhase(picoquic_bbr_state_t* bbr_state, uint64_t prior_in_flight, uint64_t packets_lost, uint64_t current_time)
{
    int is_full_length = bbr_state->cycle_on_loss || (current_time - bbr_state->cycle_stamp) > bbr_state->rt_prop;
    
    if (bbr_state->pacing_gain != 1.0) {
        if (bbr_state->pacing_gain > 1.0) {
            is_full_length &=
                (packets_lost > 0 ||
                    prior_in_flight >= BBRInflight(bbr_state, bbr_state->pacing_gain));
        }
        else {  /*  (BBR.pacing_gain < 1) */
            is_full_length &= prior_in_flight <= BBRInflight(bbr_state, 1.0);
        }
    }
    return is_full_length;
}

void BBRSetMinimalGain(picoquic_bbr_state_t* bbr_state)
{
    if (bbr_state->pacing_gain > 1.0 && bbr_state->rt_prop > 0) {
        uint64_t target_cwin = bbr_state->btl_bw * bbr_state->rt_prop / 1000000;

        if (target_cwin < 4 * PICOQUIC_MAX_PACKET_SIZE) {
            double d_target = (double)target_cwin;
            double d_gain = ((double)(4 * PICOQUIC_MAX_PACKET_SIZE)) / d_target;

            if (d_gain > bbr_state->pacing_gain) {
                bbr_state->pacing_gain = d_gain;
            }
        }
    }
}

void BBRAdvanceCyclePhase(picoquic_bbr_state_t* bbr_state, uint64_t current_time)
{
    bbr_state->cycle_on_loss = 0;
    bbr_state->cycle_stamp = current_time;
    bbr_state->cycle_index++;
    if (bbr_state->cycle_index >= BBR_GAIN_CYCLE_LEN) {
        unsigned int start = bbr_state->cycle_start;
        if (bbr_state->btl_bw_increased) {
            bbr_state->btl_bw_increased = 0;
            start++;
            if (start > BBR_GAIN_CYCLE_MAX_START) {
                start = BBR_GAIN_CYCLE_MAX_START;
            }
        }
        else if (start > 0) {
            start--;
        }
        bbr_state->cycle_index = start;
        bbr_state->cycle_start = start;
    }
   
    bbr_state->pacing_gain = bbr_pacing_gain_cycle[bbr_state->cycle_index];
    BBRSetMinimalGain(bbr_state);
}

void BBRCheckCyclePhase(picoquic_bbr_state_t* bbr_state, uint64_t packets_lost, uint64_t current_time)
{
    if (bbr_state->state == picoquic_bbr_alg_probe_bw &&
        BBRIsNextCyclePhase(bbr_state, bbr_state->prior_in_flight, packets_lost, current_time)) {
        BBRAdvanceCyclePhase(bbr_state, current_time);
    }
}

static void BBRResetProbeBwMode(picoquic_bbr_state_t* bbr_state, uint64_t current_time)
{
    bbr_state->state = picoquic_bbr_alg_probe_bw;
    bbr_state->cycle_index = 2;
    BBRAdvanceCyclePhase(bbr_state, current_time);
}

void BBRCheckFullPipe(picoquic_bbr_state_t* bbr_state, int rs_is_app_limited)
{
    if (!bbr_state->filled_pipe && bbr_state->round_start && !rs_is_app_limited) {
        if (bbr_state->btl_bw >= bbr_state->full_bw * 1.25) {  // BBR.BtlBw still growing?
            bbr_state->full_bw = bbr_state->btl_bw;   // record new baseline level
            bbr_state->full_bw_count = 0;
        }
        else {
            bbr_state->full_bw_count++; // another round w/o much growth
            if (bbr_state->full_bw_count >= 3) {
                bbr_state->filled_pipe = 1;
            }
        }
    }
}

void BBREnterProbeBW(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time)
{
    unsigned int start = 0;
    bbr_state->state = picoquic_bbr_alg_probe_bw;
    bbr_state->pacing_gain = 1.0;
    bbr_state->cwnd_gain = 2.0;

    if (bbr_state->rt_prop > PICOQUIC_TARGET_RENO_RTT) {
        uint64_t ref_rt = (bbr_state->rt_prop > PICOQUIC_TARGET_SATELLITE_RTT) ? PICOQUIC_TARGET_SATELLITE_RTT : bbr_state->rt_prop;
        start = (unsigned int)(ref_rt / PICOQUIC_TARGET_RENO_RTT);
        if (start > BBR_GAIN_CYCLE_MAX_START) {
            start = BBR_GAIN_CYCLE_MAX_START;
        }
    }
    else {
        start = 2;
    }

    bbr_state->cycle_index = start;
    bbr_state->cycle_start = start;
    bbr_state->btl_bw_increased = 1;

    BBRAdvanceCyclePhase(bbr_state, current_time);
    /* Start sampling */
    BBRltbwSampling(bbr_state, path_x, current_time);
}

void BBREnterDrain(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time)
{
    path_x->is_ssthresh_initialized = 1;
    bbr_state->state = picoquic_bbr_alg_drain;
    bbr_state->pacing_gain = 1.0 / BBR_HIGH_GAIN;  /* pace slowly */
    bbr_state->cwnd_gain = BBR_HIGH_GAIN;   /* maintain cwnd */
    /* Start sampling */
    BBRltbwSampling(bbr_state, path_x, current_time);
}

void BBRCheckDrain(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t bytes_in_transit, uint64_t current_time)
{
    if (bbr_state->state == picoquic_bbr_alg_startup && bbr_state->filled_pipe) {
        BBREnterDrain(bbr_state, path_x, current_time);
    }

    if (bbr_state->state == picoquic_bbr_alg_drain && bytes_in_transit <= BBRInflight(bbr_state, 1.0)) {
        BBREnterProbeBW(bbr_state, path_x, current_time);  /* we estimate queue is drained */
    }
}

void BBRExitStartupLongRtt(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time)
{
    /* Reset the round filter so it will start at current time */
    bbr_state->next_round_delivered = path_x->delivered;
    bbr_state->round_count++;
    bbr_state->round_start = 1;
    /* Set the filled pipe indicator */
    bbr_state->full_bw = bbr_state->btl_bw;
    bbr_state->full_bw_count = 3;
    bbr_state->filled_pipe = 1;
    /* Check the RTT measurement for pathological cases */
    if ((bbr_state->rtt_filter.is_init || bbr_state->rtt_filter.sample_current > 0) &&
        bbr_state->rt_prop > 30000000 &&
        bbr_state->rtt_filter.sample_max < bbr_state->rt_prop) {
        bbr_state->rt_prop = bbr_state->rtt_filter.sample_max;
        bbr_state->rt_prop_stamp = current_time;
    }
    /* Enter drain */
    BBREnterDrain(bbr_state, path_x, current_time);
    /* If there were just few bytes in transit, enter probe */
    if (path_x->bytes_in_transit <= BBRInflight(bbr_state, 1.0)) {
        BBREnterProbeBW(bbr_state, path_x, current_time);
    }
}

void BBRExitStartupSeedBDP(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t bdp, 
    uint64_t current_time)
{
    /* Set the BW to the value deduced from the BDP */
    uint64_t bandwidth_estimate = bdp * 1000000 / path_x->rtt_min;
    path_x->cwin = bdp;
    /* Set the parameters */
    if (bandwidth_estimate > bbr_state->btl_bw_filter[0]) {
        bbr_state->btl_bw_filter[0] = bandwidth_estimate;
        if (bandwidth_estimate > bbr_state->btl_bw) {
            bbr_state->btl_bw = bandwidth_estimate;
            bbr_state->btl_bw_increased = 1;
        }
    }


    BBRUpdateRTprop(bbr_state, path_x->rtt_min, current_time);
    /* Enter drain */
    BBREnterDrain(bbr_state, path_x, current_time);
    /* If there were just few bytes in transit, enter probe */
    if (path_x->bytes_in_transit <= BBRInflight(bbr_state, 1.0)) {
        BBREnterProbeBW(bbr_state, path_x, current_time);
    }
}

void BBREnterProbeRTT(picoquic_bbr_state_t* bbr_state)
{
    bbr_state->state = picoquic_bbr_alg_probe_rtt;
    bbr_state->pacing_gain = 1.0;
    bbr_state->cwnd_gain = 1.0;
}

void BBRExitProbeRTT(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t current_time)
{
    if (bbr_state->filled_pipe) {
        BBREnterProbeBW(bbr_state, path_x, current_time);
    }
    else {
        BBREnterStartup(bbr_state);
    }
}

int InLossRecovery(picoquic_bbr_state_t* bbr_state)
{
    return bbr_state->packet_conservation;
}

uint64_t BBRSaveCwnd(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x) {
    uint64_t w = path_x->cwin;

    if ((InLossRecovery(bbr_state) || bbr_state->state == picoquic_bbr_alg_probe_bw) &&
        (path_x->cwin < bbr_state->prior_cwnd)){
        w = bbr_state->prior_cwnd;
    }
    
    return w;
}

void BBRRestoreCwnd(picoquic_bbr_state_t* bbr_state, picoquic_path_t * path_x)
{
    if (path_x->cwin < bbr_state->prior_cwnd) {
        path_x->cwin = bbr_state->prior_cwnd;
    }
}


void BBRHandleProbeRTT(picoquic_bbr_state_t* bbr_state, picoquic_path_t * path_x, uint64_t bytes_in_transit, uint64_t current_time)
{
#if 0
    /* Ignore low rate samples during ProbeRTT: */
    C.app_limited =
        (BW.delivered + bytes_in_transit) ? 0 : 1;
#endif

    if (bbr_state->probe_rtt_done_stamp == 0 &&
        bytes_in_transit <= BBR_MIN_PIPE_CWND((uint64_t)path_x->send_mtu)) {
        bbr_state->probe_rtt_done_stamp =
            current_time + BBR_PROBE_RTT_DURATION;
        bbr_state->probe_rtt_round_done = 0;
        bbr_state->next_round_delivered = path_x->delivered;
    }
    else if (bbr_state->probe_rtt_done_stamp != 0) {
        if (bbr_state->round_start) {
            bbr_state->probe_rtt_round_done = 1;
        }
        
        if (bbr_state->probe_rtt_round_done &&
            current_time > bbr_state->probe_rtt_done_stamp) {
            bbr_state->rt_prop_stamp = current_time;
            BBRRestoreCwnd(bbr_state, path_x);
            BBRExitProbeRTT(bbr_state, path_x, current_time);
        }
    }
}

void BBRCheckProbeRTT(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t bytes_in_transit, uint64_t current_time)
{
    if (bbr_state->state != picoquic_bbr_alg_probe_rtt &&
        bbr_state->rt_prop_expired &&
        !bbr_state->idle_restart) {
        BBREnterProbeRTT(bbr_state);
        bbr_state->prior_cwnd = BBRSaveCwnd(bbr_state, path_x);
        bbr_state->probe_rtt_done_stamp = 0;
    }
    
    if (bbr_state->state == picoquic_bbr_alg_probe_rtt) {
        BBRHandleProbeRTT(bbr_state, path_x, bytes_in_transit, current_time);
        bbr_state->idle_restart = 0;
    }
}

void BBRUpdateModelAndState(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x,
    uint64_t rtt_sample, uint64_t bytes_in_transit, uint64_t packets_lost, uint64_t current_time)
{
    BBRUpdateBtlBw(bbr_state, path_x, current_time);
    BBRCheckCyclePhase(bbr_state, packets_lost, current_time);
    BBRCheckFullPipe(bbr_state, path_x->last_bw_estimate_path_limited);
    BBRCheckDrain(bbr_state, path_x, bytes_in_transit, current_time);
    BBRUpdateRTprop(bbr_state, rtt_sample, current_time);
    BBRCheckProbeRTT(bbr_state, path_x, bytes_in_transit, current_time);
}

void BBRSetPacingRateWithGain(picoquic_bbr_state_t* bbr_state, double pacing_gain)
{
    double rate = pacing_gain * (double)BBRGetBtlBW(bbr_state);

    if (bbr_state->filled_pipe || rate > bbr_state->pacing_rate){
        bbr_state->pacing_rate = rate;
    }
}

void BBRSetPacingRate(picoquic_bbr_state_t* bbr_state)
{
    BBRSetPacingRateWithGain(bbr_state, bbr_state->pacing_gain);
}

/* TODO: clarity on bytes vs packets  */
void BBRModulateCwndForRecovery(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, 
    uint64_t bytes_in_transit, uint64_t bytes_lost, uint64_t bytes_delivered)
{
    if (bytes_lost > 0) {
        if (path_x->cwin > bytes_lost) {
            path_x->cwin -= bytes_lost;
        }
        else {
            path_x->cwin = path_x->send_mtu;
        }
    }
    if (bbr_state->packet_conservation) {
        if (path_x->cwin < bytes_in_transit + bytes_delivered) {
            path_x->cwin = bytes_in_transit + bytes_delivered;
        }
    }
}

void BBRModulateCwndForProbeRTT(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x)
{
    if (bbr_state->state == picoquic_bbr_alg_probe_rtt)
    {
        if (path_x->cwin > BBR_MIN_PIPE_CWND((uint64_t)path_x->send_mtu)) {
            path_x->cwin = BBR_MIN_PIPE_CWND((uint64_t)path_x->send_mtu);
        }
    }
}

void BBRSetCwnd(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t bytes_in_transit, uint64_t packets_lost, uint64_t bytes_delivered)
{
    BBRUpdateTargetCwnd(bbr_state);
    BBRModulateCwndForRecovery(bbr_state, path_x, bytes_in_transit, packets_lost, bytes_delivered);
    if (!bbr_state->packet_conservation) {
        if (bbr_state->filled_pipe) {
            path_x->cwin += bytes_delivered;
            if (path_x->cwin > bbr_state->target_cwnd) {
                path_x->cwin = bbr_state->target_cwnd;
            }
        }
        else if (path_x->cwin < bbr_state->target_cwnd || path_x->delivered < PICOQUIC_CWIN_INITIAL)
        {
            path_x->cwin += bytes_delivered;
        }
        if (path_x->cwin < BBR_MIN_PIPE_CWND((uint64_t)path_x->send_mtu))
        {
            path_x->cwin = BBR_MIN_PIPE_CWND((uint64_t)path_x->send_mtu);
        }
    }

    BBRModulateCwndForProbeRTT(bbr_state, path_x);
}


void BBRUpdateControlParameters(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t bytes_in_transit, uint64_t packets_lost, uint64_t bytes_delivered)
{
    BBRSetPacingRate(bbr_state);
    BBRSetSendQuantum(bbr_state, path_x);
    BBRSetCwnd(bbr_state, path_x, bytes_in_transit, packets_lost, bytes_delivered);
}

void BBRHandleRestartFromIdle(picoquic_bbr_state_t* bbr_state, uint64_t bytes_in_transit, int is_app_limited)
{
    if (bytes_in_transit == 0 && is_app_limited)
    {
        bbr_state->idle_restart = 1;
        if (bbr_state->state == picoquic_bbr_alg_probe_bw) {
            BBRSetPacingRateWithGain(bbr_state, 1.0);
        }
    }
}

/* This is the per ACK processing, activated upon receiving an ACK.
 * At that point, we expect the following:
 *  - delivered has been updated to reflect all the data acked on the path.
 *  - the delivery rate sample has been computed.
 */

void  BBRUpdateOnACK(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x,
    uint64_t rtt_sample, uint64_t bytes_in_transit, uint64_t packets_lost, uint64_t bytes_delivered,
    uint64_t current_time)
{
    BBRUpdateModelAndState(bbr_state, path_x, rtt_sample, bytes_in_transit,
        packets_lost, current_time);
    BBRUpdateControlParameters(bbr_state, path_x, bytes_in_transit, packets_lost, bytes_delivered);
}

void BBROnTransmit(picoquic_bbr_state_t* bbr_state, uint64_t bytes_in_transit, int is_app_limited)
{
    BBRHandleRestartFromIdle(bbr_state, bytes_in_transit, is_app_limited);
}

/* Dealing with recovery. What happens when all
 * the packets are lost, when all packets have been retransmitted.. */

void BBROnAllPacketsLost(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x)
{
    bbr_state->prior_cwnd = BBRSaveCwnd(bbr_state, path_x);
    path_x->cwin = path_x->send_mtu;
}

void BBROnEnterFastRecovery(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x, uint64_t bytes_in_transit, uint64_t bytes_delivered )
{
    if (bytes_delivered < path_x->send_mtu) {
        bytes_delivered = path_x->send_mtu;
    }
    bbr_state->prior_cwnd = BBRSaveCwnd(bbr_state, path_x);
    path_x->cwin = bytes_in_transit + bytes_delivered;
    bbr_state->packet_conservation = 1;
}

void BBRAfterOneRoundtripInFastRecovery(picoquic_bbr_state_t* bbr_state)
{
    bbr_state->packet_conservation = 0;
}

void BBRExitFastRecovery(picoquic_bbr_state_t* bbr_state, picoquic_path_t* path_x)
{
    bbr_state->packet_conservation = 0;
    BBRRestoreCwnd(bbr_state, path_x);
}

/* Reaction to ECN or sustained losses
 */
void picoquic_bbr_notify_congestion(
    picoquic_bbr_state_t* bbr_state,
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    uint64_t current_time,
    int is_timeout)
{
    /* Apply filter of last loss */
    if ((bbr_state->cycle_on_loss || current_time < bbr_state->loss_interval_start + path_x->smoothed_rtt) &&
        (!is_timeout || bbr_state->last_loss_was_timeout)) {
        /* filter repeated loss events */
        return;
    }
    if (is_timeout || path_x->cwin < PICOQUIC_CWIN_MINIMUM) {
        if (!bbr_state->is_suspended) {
            bbr_state->is_suspended = 1;
            bbr_state->cwin_before_suspension = path_x->cwin;
        }
        path_x->cwin = PICOQUIC_CWIN_MINIMUM;
    } else {
        path_x->cwin = path_x->cwin / 2;
    }
    bbr_state->loss_interval_start = current_time;
    bbr_state->last_loss_was_timeout = is_timeout;
    bbr_state->congestion_sequence = picoquic_cc_get_sequence_number(cnx, path_x);

    /* Update and check the packet loss rate */
    if (bbr_state->state == picoquic_bbr_alg_startup_long_rtt) {
        BBRExitStartupLongRtt(bbr_state, path_x, current_time);
    }
    else if (bbr_state->state == picoquic_bbr_alg_startup) {
        bbr_state->filled_pipe = 1;
        BBREnterDrain(bbr_state, path_x, current_time);
    }
    else {
        bbr_state->cycle_on_loss = 1;
    }
}

/*
* Exit from suspension, after notification of spurious repeat.
*/
void picoquic_bbr_suspension_almost_over(
    picoquic_bbr_state_t* bbr_state,
    picoquic_path_t* path_x,
    uint64_t lost_packet_number)
{
    if (bbr_state->is_suspended &&
        bbr_state->cwin_before_suspension > 0 &&
        !bbr_state->is_suspension_nearly_over &&
        bbr_state->congestion_sequence >= lost_packet_number) {
        bbr_state->is_suspension_nearly_over = 1;
    }
}

void picoquic_bbr_suspension_exit(
    picoquic_bbr_state_t* bbr_state,
    picoquic_cnx_t * cnx,
    picoquic_path_t* path_x)
{
    if (bbr_state->is_suspended &&
        bbr_state->is_suspension_nearly_over) {
        path_x->cwin = bbr_state->cwin_before_suspension;
        /* Set the pacing rate in picoquic sender */
        picoquic_update_pacing_rate(cnx, path_x, bbr_state->pacing_rate, bbr_state->send_quantum);
    }
    bbr_state->is_suspended = 0;
    bbr_state->is_suspension_nearly_over = 0;
}




/*
 * In order to implement BBR, we map generic congestion notification
 * signals to the corresponding BBR actions.
 */
static void picoquic_bbr_notify(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    uint64_t rtt_measurement,
    uint64_t one_way_delay,
    uint64_t nb_bytes_acknowledged,
    uint64_t lost_packet_number,
    uint64_t current_time)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(lost_packet_number);
#endif
    picoquic_bbr_state_t* bbr_state = (picoquic_bbr_state_t*)path_x->congestion_alg_state;
    path_x->is_cc_data_updated = 1;

    if (bbr_state != NULL) {
        switch (notification) {
        case picoquic_congestion_notification_acknowledgement:
            /* sum the amount of data acked per packet */
            if (bbr_state->is_suspended) {
                picoquic_bbr_suspension_exit(bbr_state, cnx, path_x);
            }
            bbr_state->bytes_delivered += nb_bytes_acknowledged;
            break;
        case picoquic_congestion_notification_ecn_ec:
            /* Non standard code to react on ECN_EC */
            if (lost_packet_number >= bbr_state->congestion_sequence) {
                picoquic_bbr_notify_congestion(bbr_state, cnx, path_x, current_time, 0);
            }
            break;
        case picoquic_congestion_notification_repeat:
        case picoquic_congestion_notification_timeout:
            /* Non standard code to react to high rate of packet loss, or timeout loss */
            if (lost_packet_number >= bbr_state->congestion_sequence &&
                picoquic_hystart_loss_test(&bbr_state->rtt_filter, notification, lost_packet_number)) {
                picoquic_bbr_notify_congestion(bbr_state, cnx, path_x, current_time,
                    (notification == picoquic_congestion_notification_timeout) ? 1 : 0);
            }
            break;
        case picoquic_congestion_notification_spurious_repeat:
            if (bbr_state->is_suspended) {
                picoquic_bbr_suspension_almost_over(bbr_state, path_x, lost_packet_number);
            }
            break;
        case picoquic_congestion_notification_rtt_measurement:
            if (bbr_state->state == picoquic_bbr_alg_startup && path_x->rtt_min > BBR_HYSTART_THRESHOLD_RTT) {
                BBREnterStartupLongRTT(bbr_state, path_x);
            }
            if (bbr_state->state == picoquic_bbr_alg_startup_long_rtt) {
                if (picoquic_hystart_test(&bbr_state->rtt_filter, (cnx->is_time_stamp_enabled) ? one_way_delay : rtt_measurement,
                    cnx->path[0]->pacing_packet_time_microsec, current_time, cnx->is_time_stamp_enabled)) {
                    BBRExitStartupLongRtt(bbr_state, path_x, current_time);
                }
            }
            break;
        case picoquic_congestion_notification_bw_measurement:
            /* RTT measurements will happen after the bandwidth is estimated */
            if (bbr_state->state == picoquic_bbr_alg_startup_long_rtt) {
                uint64_t max_win;
                uint64_t min_win;

                BBRUpdateBtlBw(bbr_state, path_x, current_time);
                if (rtt_measurement <= bbr_state->rt_prop) {
                    bbr_state->rt_prop = rtt_measurement;
                    bbr_state->rt_prop_stamp = current_time;
                }
                if (path_x->last_time_acked_data_frame_sent > path_x->last_sender_limited_time) {
                    picoquic_hystart_increase(path_x, &bbr_state->rtt_filter, bbr_state->bytes_delivered);
                }
                bbr_state->bytes_delivered = 0;

                max_win = path_x->peak_bandwidth_estimate * bbr_state->rt_prop / 1000000;
                min_win = max_win /= 2;

                if (path_x->cwin < min_win) {
                    path_x->cwin = min_win;
                }
                else if (path_x->smoothed_rtt > PICOQUIC_TARGET_RENO_RTT) {
                    path_x->pacing_bandwidth_pause = 1;
                }

                picoquic_update_pacing_data(cnx, path_x, 1);
            } else {
                BBRUpdateOnACK(bbr_state, path_x,
                    rtt_measurement, path_x->bytes_in_transit, 0 /* packets_lost */, bbr_state->bytes_delivered,
                    current_time);
                /* Remember the number in flight before the next ACK -- TODO: update after send instead. */
                bbr_state->prior_in_flight = path_x->bytes_in_transit;
                /* Reset the number of bytes delivered */
                bbr_state->bytes_delivered = 0;

                if (bbr_state->pacing_rate > 0) {
                    /* Set the pacing rate in picoquic sender */
                    picoquic_update_pacing_rate(cnx, path_x, bbr_state->pacing_rate, bbr_state->send_quantum);
                }
            }
            break;
        case picoquic_congestion_notification_cwin_blocked:
            break;
        case picoquic_congestion_notification_reset:
            picoquic_bbr_reset(bbr_state, path_x, current_time, cnx->quic->wifi_shadow_rtt, cnx->quic->bbr_quantum_ratio);
            break;
        case picoquic_congestion_notification_seed_cwin:
            if (bbr_state->state == picoquic_bbr_alg_startup_long_rtt) {
                BBRExitStartupSeedBDP(bbr_state, path_x, nb_bytes_acknowledged, current_time);
                picoquic_update_pacing_data(cnx, path_x, 1);
            }
            else if (bbr_state->state == picoquic_bbr_alg_startup){
                /* If in initial startup phase, do something */
                double seed_bw_estimate = (double)nb_bytes_acknowledged;
                uint64_t bwe;
                seed_bw_estimate /= (double)path_x->smoothed_rtt;
                seed_bw_estimate *= 1000000;
                bwe = (uint64_t)seed_bw_estimate*2; /* Hack -- account for div by two in BBRUpdateBtlBw */
                if (path_x->bandwidth_estimate_max < bwe) {
                    path_x->bandwidth_estimate_max = bwe;
                    BBRUpdateBtlBw(bbr_state, path_x, current_time);
                    BBRSetPacingRate(bbr_state);
                    if (bbr_state->pacing_rate > 0) {
                        /* Set the pacing rate in picoquic sender */
                        picoquic_update_pacing_rate(cnx, path_x, bbr_state->pacing_rate, bbr_state->send_quantum);
                    }
                }
            }
            break;
        default:
            /* ignore */
            break;
        }
    }
}

/* Observe the state of congestion control */

void picoquic_bbr_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    picoquic_bbr_state_t* bbr_state = (picoquic_bbr_state_t*)path_x->congestion_alg_state;
    *cc_state = (uint64_t)bbr_state->state;
    *cc_param = bbr_state->btl_bw;
}

#define picoquic_bbr_ID "bbr" /* BBR */

picoquic_congestion_algorithm_t picoquic_bbr_algorithm_struct = {
    picoquic_bbr_ID, PICOQUIC_CC_ALGO_NUMBER_BBR,
    picoquic_bbr_init,
    picoquic_bbr_notify,
    picoquic_bbr_delete,
    picoquic_bbr_observe
};

picoquic_congestion_algorithm_t* picoquic_bbr_algorithm = &picoquic_bbr_algorithm_struct;