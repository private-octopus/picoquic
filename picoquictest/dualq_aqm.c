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
* Implementation of the DualQ AQM
* 
* ECT1 and CE in L4S queue
* 
* p_C ~= (p_L / k)^2
* default k = 2
* overflow drop if saturated
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
    uint64_t last_dequeue_time;
    int next_queue; /* 0: l4s, 1: plain */
    picoquictest_sim_packet_t* l4s_queue_first;
    picoquictest_sim_packet_t* l4s_queue_last;
    picoquictest_sim_packet_t* plain_queue_first;
    picoquictest_sim_packet_t* plain_queue_last;
} dualq_aqm_state_t;

/* Dequeue.
* The packets are first queued in the L4S or plain queue.
* If there is room in the main queue, add them there.
* 
* The last packet in the delay queue has a specified
* delivery time, computed as its queue time plus the
* latency. 
*/

void dualq_aqm_dequeue_queue(picoquictest_sim_link_t* link, picoquictest_sim_packet_t** queue_first,
    picoquictest_sim_packet_t** queue_last, uint64_t queue_delay, uint64_t current_time)
{
    picoquictest_sim_packet_t* packet = *queue_first;
    uint64_t transmit_time = 0;
    *queue_first = packet->next_packet;
    if (*queue_first == NULL) {
        *queue_last = NULL;
    }
    picoquictest_sim_link_enqueue(link, packet, queue_delay, transmit_time, current_time);
}

void dualq_aqm_dequeue()
{

}


void dualq_aqm_submit_l4s(dualq_aqm_state_t* dualq_state, picoquictest_sim_link_t* link,
    picoquictest_sim_packet_t* packet, uint64_t current_time, int* should_drop)
{

}

void dualq_aqm_submit_plain(dualq_aqm_state_t* dualq_state, picoquictest_sim_link_t* link,
    picoquictest_sim_packet_t* packet, uint64_t current_time, int* should_drop)
{

}

/* Submit: mark or delete the packet */
void dualq_aqm_submit(picoquictest_aqm_t* self, picoquictest_sim_link_t* link,
    picoquictest_sim_packet_t* packet, uint64_t current_time, int* should_drop)
{
    dualq_aqm_state_t* dualq_state = (dualq_aqm_state_t*)self;

    *should_drop = 0;

    if (packet->ecn_mark == PICOQUIC_ECN_ECT_1) {
        dualq_aqm_submit_l4s(dualq_state, link, packet, current_time, should_drop);
    }
    else {
        dualq_aqm_submit_plain(dualq_state, link, packet, current_time, should_drop);
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
