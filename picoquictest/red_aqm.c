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
#include "picoquictest_red.h"

typedef struct st_red_aqm_state_t {
    struct st_picoquictest_aqm_t super;
    uint64_t red_threshold; /* threshold for starting to drop packets */
    uint64_t red_queue_max; /* all packets above that are dropped. */
    uint64_t red_average_queue;
    double drop_total;
} red_aqm_state_t;

int red_aqm_recur(red_aqm_state_t* red_state, double drop_rate)
{
    int should_drop = 0;
    red_state->drop_total += drop_rate;
    if (red_state->drop_total > 1.0) {
        should_drop = 1;
        red_state->drop_total -= 1.0;
    }
    return should_drop;
}

double red_aqm_drop_rate(red_aqm_state_t* red_state, uint64_t queue_delay)
{
    double drop_rate = 0.0;

    if (queue_delay >= red_state->red_threshold)
    {
        if (queue_delay >= red_state->red_queue_max) {
            drop_rate = 1.0;
        }
        else {
            drop_rate = ((double)(queue_delay - red_state->red_threshold)) /
                (double)(red_state->red_queue_max - red_state->red_threshold);
        }
    }
    return drop_rate;
} 

void red_aqm_submit(picoquictest_aqm_t* self, picoquictest_sim_link_t* link,
    picoquictest_sim_packet_t* packet, uint64_t current_time, int* should_drop)
{
    red_aqm_state_t* red_state = (red_aqm_state_t*)self;
    uint64_t queue_delay = (current_time > link->queue_time) ? 0 : link->queue_time - current_time;

    red_state->red_average_queue = (3 * red_state->red_average_queue + queue_delay) / 4;

    *should_drop = red_aqm_recur(red_state, red_aqm_drop_rate(red_state, red_state->red_average_queue));

    picoquictest_sim_link_enqueue(link, packet, current_time, *should_drop);
}

void red_aqm_release(picoquictest_aqm_t* self, picoquictest_sim_link_t* link)
{
    free(self);
    link->aqm_state = NULL;
}

void red_aqm_reset(picoquictest_aqm_t* self, struct st_picoquictest_sim_link_t* link, uint64_t current_time)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(self);
    UNREFERENCED_PARAMETER(current_time);
    UNREFERENCED_PARAMETER(link);
#endif
}

int red_aqm_configure(picoquictest_sim_link_t* link, uint64_t red_threshold, uint64_t red_queue_max)
{
    int ret = 0;
    /* Create a configuration */
    red_aqm_state_t * red_state = (red_aqm_state_t*)malloc(sizeof(red_aqm_state_t));

    if (red_state == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memset(red_state, 0, sizeof(red_aqm_state_t));
        red_state->super.submit = red_aqm_submit;
        red_state->super.release = red_aqm_release;
        red_state->super.reset = red_aqm_reset;
        red_state->red_threshold = red_threshold;
        red_state->red_queue_max = red_queue_max;

        link->aqm_state = &red_state->super;
    }
    return ret;
}
