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

/*
* Implementation of the RED algorithm as a basic active queue management
* for picoquic_ns.
 */

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picosocks.h"
#include <stdlib.h>
#include <string.h>
#include "picoquictest_rctl.h"

typedef struct st_rctl_state_t {
    struct st_picoquictest_aqm_t super;
    double bucket_increase_per_microsec;
    uint64_t bucket_max;
    double bucket_current;
    uint64_t bucket_arrival_last;
} rctl_state_t;

void rctl_submit(picoquictest_aqm_t* self, picoquictest_sim_link_t* link,
    picoquictest_sim_packet_t* packet, uint64_t current_time, int* should_drop, int* should_mark_ce)
{
    rctl_state_t* rctl_state = (rctl_state_t*)self;

    *should_drop = 0;
    *should_mark_ce = 0;

    if (rctl_state->bucket_increase_per_microsec > 0) {
        /* Simulate a rate limiter based on classic leaky bucket algorithm */
        uint64_t delta_microsec = current_time - rctl_state->bucket_arrival_last;
        rctl_state->bucket_arrival_last = current_time;
        rctl_state->bucket_current += ((double)delta_microsec) * rctl_state->bucket_increase_per_microsec;
        if (rctl_state->bucket_current > (double)rctl_state->bucket_max) {
            rctl_state->bucket_current = (double)rctl_state->bucket_max;
        }
        if (rctl_state->bucket_current > (double)packet->length) {
            rctl_state->bucket_current -= (double)packet->length;
        }
        else {
            *should_drop = 1;
        }
    }
}

void rctl_release(picoquictest_aqm_t* self, picoquictest_sim_link_t* link)
{
    free(self);
    link->aqm_state = NULL;
}

void rctl_reset(picoquictest_aqm_t* self, uint64_t current_time)
{
    rctl_state_t* rctl_state = (rctl_state_t*)self;
    /* reset the leaky bucket, so it starts working from the current time. */
    rctl_state->bucket_arrival_last = current_time;
    rctl_state->bucket_current = (double)rctl_state->bucket_max;
}

int rctl_configure(picoquictest_sim_link_t* link, double bucket_increase_per_microsec, uint64_t bucket_max, uint64_t current_time)
{
    int ret = 0;
    /* Create a configuration */
    rctl_state_t* rctl_state = (rctl_state_t*)malloc(sizeof(rctl_state_t));

    if (rctl_state == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memset(rctl_state, 0, sizeof(rctl_state_t));
        rctl_state->super.submit = rctl_submit;
        rctl_state->super.release = rctl_release;
        rctl_state->super.reset = rctl_reset;
        rctl_state->bucket_increase_per_microsec = bucket_increase_per_microsec;
        rctl_state->bucket_max = bucket_max;
        rctl_state->bucket_current = (double)bucket_max;
        rctl_state->bucket_arrival_last = current_time;

        link->aqm_state = &rctl_state->super;
    }
    return ret;
}