/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <picotls.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <signal.h>
#endif

/* Test the coalesced Send API.
 * The simulation here involves:
 * - simulating the coalesced send implementation,
 * - filing each of the cooalesced packets as separate 
 *   packets on the link.
 * - (TODO) simulating the coalesced receive by packing
 *   consecutive packets in a receive folder, modulo 
 *   arrival time.
 * - Getting statistics on the effectiveness of the
 *   coalescing process.
 */
int netperf_next_arrival(picoquictest_sim_link_t * link, picoquic_quic_t * quic, uint64_t simulated_time)
{
    return 0;
}

int netperf_next_departure(picoquic_quic_t* quic, picoquictest_sim_link_t* link, uint64_t simulated_time)
{
    return 0;
}

int netperf_step(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t * simulated_time)
{
    int next_action = -1;
    uint64_t next_time = UINT64_MAX;
    uint64_t action_time;

    if ((action_time = picoquictest_sim_link_next_arrival(test_ctx->s_to_c_link, next_time)) < next_time) {
        next_action = 0;
        next_time = action_time;
    }

    if ((action_time = picoquictest_sim_link_next_arrival(test_ctx->c_to_s_link, next_time)) < next_time) {
        next_action = 1;
        next_time = action_time;
    }

    if ((action_time = picoquic_get_next_wake_time(test_ctx->qclient, *simulated_time)) < next_time) {
        next_action = 2;
        next_time = action_time;
    }

    if ((action_time = picoquic_get_next_wake_time(test_ctx->qserver, *simulated_time)) < next_time) {
        next_action = 3;
        next_time = action_time;
    }

    if (next_time == UINT64_MAX) {
        /* No more action possible */
        ret = -1;
    }
    else {
        if (next_time > *simulated_time) {
            *simulated_time = next_time;
        }

        switch (next_action) {
        case 0:
            ret = netperf_next_arrival(test_ctx->s_to_c_link, test_ctx->qclient, *simulated_time);
            break;
        case 1:
            ret = netperf_next_arrival(test_ctx->c_to_s_link, test_ctx->qserver, *simulated_time);
            break;
        case 2:
            ret = netperf_next_departure(test_ctx->qclient, test_ctx->c_to_s_link, *simulated_time);
            break;
        case 3:
            ret = netperf_next_departure(test_ctx->qserver, test_ctx->s_to_c_link, *simulated_time);
            break;
        default:
            ret = -1;
            break;
        }
    }

    return ret;
}