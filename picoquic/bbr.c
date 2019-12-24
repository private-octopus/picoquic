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

typedef enum {
    picoquic_bbr_alg_slow_start = 0,
    picoquic_bbr_alg_recovery,
    picoquic_bbr_alg_congestion_avoidance
} picoquic_bbr_alg_state_t;

#define BBR_BTL_BW_FILTER_LENGTH 10
#define BBR_RT_PROP_FILTER_LENGTH 10
#define BBR_HIGH_GAIN 2.8853900817779 /* 2/ln(2) */
#define BBR_MIN_PIPE_CWND (4*PICOQUIC_MAX_PACKET_SIZE)
#define BBR_GAIN_CYCLE_LEN 8
#define BBR_PROBE_RTT_INTERNAL 10000000 /* 10 sec, 10000000 microsecs */
#define BBR_PROBE_RTT_DURATION 200000 /* 200msec, 200000 microsecs */

typedef struct st_picoquic_bbr_state_t {
    picoquic_bbr_alg_state_t alg_state;
    uint64_t btl_bw;
    uint64_t btl_bw_filter[BBR_BTL_BW_FILTER_LENGTH];
    uint64_t rt_prop;
    uint64_t rt_prop_stamp;
    uint64_t rt_prop_expired;
    double pacing_gain;
    double cwnd_gain;
    int round_count;
    uint64_t next_round_delivered;
    int filled_pipe : 1;
    int round_start : 1;
} picoquic_bbr_state_t;

static void picoquic_bbr_init(picoquic_path_t* path_x)
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_bbr_state_t* bbr_state = (picoquic_bbr_state_t*)malloc(sizeof(picoquic_bbr_state_t));
    path_x->congestion_alg_state = (void*)bbr_state;
    if (bbr_state != NULL) {
        memset(bbr_state, 0, sizeof(picoquic_bbr_state_t));
        bbr_state->alg_state = picoquic_bbr_alg_slow_start;
        path_x->cwin = PICOQUIC_CWIN_INITIAL;
    }
}

#if 0
void BBRUpdateRound(picoquic_bbr_state_t* bbr_state, uint64_t delivered)
{
    if (delivered >= bbr_state->next_round_delivered)
    {
        bbr_state->next_round_delivered = delivered;
        bbr_state->round_count++;
        bbr_state->round_start = 1;
    }
    else {
        bbr_state->round_start = 0;
    }
}

void BBRUpdateBtlBw(picoquic_bbr_state_t* bbr_state, uint64_t delivered, uint64_t delivery_rate, int rs_is_app_limited)
{
    BBRUpdateRound(bbr_state, delivered);
    if (delivery_rate >= bbr_state->btl_bw || !rs_is_app_limited)
    {
        /* Update the max bandwidth for this round */
        /* Compute the max for all rounds, based on the round_start variable */
    }
}

/* This will use one way samples if available */
/* Should augment that with common RTT filter to suppress jitter */
void BBRUpdateRTprop(picoquic_bbr_state_t* bbr_state, uint64_t rtt_sample)
{
    /*     BBR.rtprop_expired =
      Now() > BBR.rtprop_stamp + RTpropFilterLen
    if (packet.rtt >= 0 and
       (packet.rtt <= BBR.RTprop or BBR.rtprop_expired))
      BBR.RTprop = packet.rtt
      BBR.rtprop_stamp = Now()
      */
}

void BBRUpdateModelAndState(picoquic_bbr_state_t* bbr_state, uint64_t delivered, uint64_t delivery_rate, int rs_is_app_limited, uint64_t rtt_sample)
{
    BBRUpdateBtlBw(bbr_state, delivered, delivery_rate, rs_is_app_limited);
    BBRCheckCyclePhase();
    BBRCheckFullPipe();
    BBRCheckDrain();
    BBRUpdateRTprop(bbr_state, rtt_sample);
    BBRCheckProbeRTT();
}

void BBRUpdateControlParameters()
{
    /*
     Need to revisit the pacing algorithm to allow BBR to set the values.

    BBRSetPacingRate();
      BBRSetPacingRateWithGain(pacing_gain):
    rate = pacing_gain * BBR.BtlBw
    if (BBR.filled_pipe || rate > BBR.pacing_rate)
      BBR.pacing_rate = rate

  BBRSetPacingRate():
    BBRSetPacingRateWithGain(BBR.pacing_gain)
    BBRSetSendQuantum();
      BBRSetSendQuantum():
    if (BBR.pacing_rate < 1.2 Mbps)
      BBR.send_quantum = 1 * MSS
    else if (BBR.pacing_rate < 24 Mbps)
      BBR.send_quantum  = 2 * MSS
    else
      BBR.send_quantum  = min(BBR.pacing_rate * 1ms, 64KBytes)

    BBRSetCwnd();
      BBRInflight(gain):
    if (BBR.RTprop == Inf)
      return InitialCwnd -- no valid RTT samples yet --
    quanta = 3 * BBR.send_quantum
        estimated_bdp = BBR.BtlBw * BBR.RTprop
        return gain * estimated_bdp + quanta

        BBRUpdateTargetCwnd() :
        BBR.target_cwnd = BBRInflight(BBR.cwnd_gain)
    */
}


void  BBRUpdateOnACK(picoquic_bbr_state_t* bbr_state, uint64_t delivered, uint64_t delivery_rate, int rs_is_app_limited, uint64_t rtt_sample)
{
    BBRUpdateModelAndState(bbr_state, delivered, delivery_rate, rs_is_app_limited, rtt_sample);
    BBRUpdateControlParameters();
}

void BBROnTransmit()
{
    BBRHandleRestartFromIdle();
}


/* TODO: dealing with recovery. What happens when all
 * the packets are lost, when all packets have been retransmitted.. */

#endif