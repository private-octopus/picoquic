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
#include "picoquictest_dualq.h"

/* This implementation is a very rough place holder for the dualq AQM defined for L4S 
*/

typedef struct st_dualq_aqm_state_t {
    struct st_picoquictest_aqm_t super;
    uint64_t dualq_threshold;
} dualq_aqm_state_t;

void dualq_aqm_submit(picoquictest_aqm_t* self, picoquictest_sim_link_t* link,
    picoquictest_sim_packet_t* packet, uint64_t current_time, int* should_drop)
{
    dualq_aqm_state_t* dualq_state = (dualq_aqm_state_t*)self;
    uint64_t queue_delay = (current_time > link->queue_time) ? 0 : link->queue_time - current_time;

    *should_drop = 0;

    if (link->queue_delay_max > 0 && queue_delay >= link->queue_delay_max) {
        *should_drop = 1;
    }
    else {
        if (queue_delay > dualq_state->dualq_threshold) {
            if (packet->ecn_mark == PICOQUIC_ECN_ECT_1) {
                packet->ecn_mark = PICOQUIC_ECN_CE;
            }
            else {
                *should_drop = 1;
            }
        }
    }
}

void dualq_aqm_release(picoquictest_aqm_t* self, picoquictest_sim_link_t* link)
{
    free(self);
    link->aqm_state = NULL;
}

void dualq_aqm_reset(picoquictest_aqm_t* self, uint64_t current_time)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(self);
    UNREFERENCED_PARAMETER(current_time);
#endif
}

int dualq_aqm_configure(picoquictest_sim_link_t* link, uint64_t dualq_threshold)
{
    int ret = 0;
    /* Create a configuration */
    dualq_aqm_state_t* dualq_state = (dualq_aqm_state_t*)malloc(sizeof(dualq_aqm_state_t));

    if (dualq_state == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memset(dualq_state, 0, sizeof(dualq_aqm_state_t));
        dualq_state->super.submit = dualq_aqm_submit;
        dualq_state->super.release = dualq_aqm_release;
        dualq_state->super.reset = dualq_aqm_reset;

        dualq_state->dualq_threshold = dualq_threshold;

        link->aqm_state = &dualq_state->super;
    }
    return ret;
}
