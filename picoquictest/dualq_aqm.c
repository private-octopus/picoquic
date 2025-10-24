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
* Implementation of the DualQ AQM,
* based on code sample for dualq pi2 in RFC 9332
 */

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picosocks.h"
#include <stdlib.h>
#include <string.h>
#include "picoquictest_dualq.h"
#if 0
#define DUALQ_MAX_LINK_RATE 125000000 /* 125,000,000 Bytes/sec, i.e., 1 Gbps -- pretty much a simulation limit */

typedef struct st_dualq_queue_t {
    uint64_t queue_bytes;
    uint64_t queue_time;
    double count;
    picoquictest_sim_packet_t* queue_first;
    picoquictest_sim_packet_t* queue_last;
} dualq_queue_t;

typedef struct st_dualq_state_t {
    struct st_picoquictest_aqm_t super;
    /* Initialization parameters */
    uint64_t target; /* PI2 queue delay target for both L4S and Classic, microseconds*/
    double k; /* Coupling factor */
    double p_Cmax; /* above this drop probability, classic queue uses drops instead of marks. */
    uint64_t Tupdate; /* interval between update of pi2 parameters, microseconds */
    double pi2_alpha; /* PI integral gain in Hz */
    double pi2_beta; /* PI proportional gain in MHz (1/microsecond) */
    uint64_t maxTh; /* Above this queue size threshold, L queue behaves as classic. */
    uint64_t minTh; /* Queue size above which L queue starts CE marking */
    uint64_t range; /* maxTh - minTh */
    double p_Lmax; /* above this drop probability, L4S queue uses drops instead of marks. */
    uint64_t limit; /* Maximum size of L4S + Classic queues */
    int schedule_tick; /* Counter used for weighed fair queuing, 15 for L4S, 1 for Classic */
    dualq_queue_t lq; /* The L4S queue of packets */
    dualq_queue_t cq; /* The classic queue of packets */
    int64_t curq; /* Current length of the classic queue, in microsecond */
    int64_t prevq; /* Previous length of the classic queue, in microsecond */
    uint64_t update_next; /* last time the pi2 parameters should be updated */
    double pprime; /* the p' coefficent in RFC9332, nominal mark rate of L4S queue derived from length of classic queue */
    double pprime_L; /* the p'_L coefficient in RFC9332, mark rate of L4S queue computed from L4S queue length, before coupling */
    double p_L; /* actual mark rate of L4S queue, after combining with "p_CL" */
    double p_CL; /* Coupled L4S prob = base prob pprime_L * coupling factor k */
    double p_C; /* Nominal drop rate of classic queue, equal to pprime_L^2 */
} dualq_state_t;
#endif

/* Add a packet to a queue. Maintain counters, etc. 
 */

void dualq_enqueue_queue(dualq_state_t* dualq, picoquictest_sim_link_t* link, dualq_queue_t* xq, picoquictest_sim_packet_t* packet)
{
    if (xq->queue_first == NULL) {
        xq->queue_first = packet;
        xq->queue_last = packet;
    }
    else {
        xq->queue_last->next_packet = packet;
        xq->queue_last = packet;
    }
    packet->next_packet = 0;
    xq->count += 1;
    xq->queue_bytes += packet->length;
    xq->queue_time += picoquictest_sim_link_transmit_time(link, packet);
}

picoquictest_sim_packet_t* dualq_dequeue_queue(dualq_state_t* dualq, picoquictest_sim_link_t* link, dualq_queue_t* xq)
{
    picoquictest_sim_packet_t* packet = xq->queue_first;

    if (packet != NULL) {
        xq->queue_first = packet->next_packet;
        packet->next_packet = NULL;
        if (xq->queue_first == NULL) {
            xq->queue_last = NULL;
            xq->queue_bytes = 0;
            xq->queue_time = 0;
            xq->count = 0;
        }
        else
        {
            uint64_t transmit_time = picoquictest_sim_link_transmit_time(link, packet);
            if (transmit_time < xq->queue_time) {
                xq->queue_time -= transmit_time;
            }
            else {
                xq->queue_time = 0;
            }
            if (packet->length < xq->queue_bytes) {
                xq->queue_bytes -= packet->length;
            }
            else {
                /* error case. do not use 0, as that would stop dequeuing */
                xq->queue_bytes = 1;
            }
            xq->count -= 1;
        }
    }
    return packet;
}


/* Process the packet that was just submitted. 
 */
void dualq_enqueue(dualq_state_t* dualq, picoquictest_sim_link_t* link, picoquictest_sim_packet_t* packet, uint64_t current_time)
{
    /* Test limit and classify lq or cq */
    if (dualq->cq.queue_bytes + dualq->lq.queue_bytes + packet->length > dualq->limit)
    {
        /* drop packet if buffer is full */
        picoquictest_sim_link_enqueue(link, packet, 0, 1);
    }
    else {
        /* 4 : timestamp(pkt) % only needed if using the sojourn technique */
        packet->arrival_time = current_time;
        /* Packet classifier */
        if (packet->ecn_mark == PICOQUIC_ECN_ECT_1 ||
            packet->ecn_mark == PICOQUIC_ECN_CE) {
            /* Add to L4S queue */
            dualq_enqueue_queue(dualq, link, &dualq->lq, packet);
        }
        else
        {
            /* add to classic queue */
            dualq_enqueue_queue(dualq, link, &dualq->cq, packet);
        }
    }
}


/* Dequeue.
* The packets are first queued in the L4S or plain queue.
* If there is room in the main queue, add them there.
* 
* The last packet in the delay queue has a specified
* delivery time, computed as its queue time plus the
* latency. 
* 
* The "dequeue" policy by default is weighted round robin, 
* 
*/

int dualq_recur(dualq_queue_t* xq, double likelihood) {
    /* Returns TRUE with a certain likelihood */
    int ret = 0;
    xq->sum_p += likelihood;
    if (xq->sum_p > 1.0) {
        xq->sum_p -= 1.0;
        ret = 1;
    }
    return ret;
}

/* dualq_scheduler selects between the head packets of the two
* queues.The choice of scheduler technology is discussed later. */
picoquictest_sim_packet_t* dualq_scheduler(dualq_state_t* dualq, picoquictest_sim_link_t* link, int* is_lq) {
    picoquictest_sim_packet_t* packet = NULL;
    *is_lq = ((dualq->schedule_tick & 0x0f) == 0) ? 0 : 1;

    packet = dualq_dequeue_queue(dualq, link, (*is_lq == 0)? &dualq->cq : &dualq->lq);
    if (packet == NULL) {
        *is_lq ^= 1;
        packet = dualq_dequeue_queue(dualq, link, (*is_lq == 0) ? &dualq->cq : &dualq->lq);
    }
    
    dualq->schedule_tick += 1;
    dualq->schedule_tick &= 0x0f;
    return packet;
}

double dualq_laqm(dualq_state_t* dualq)
{
    double pprime = 0;
    /* Returns Native L4S AQM probability */
    if (dualq->lq.count > 1) {
        if (dualq->lq.queue_time >= dualq->maxTh) {
            pprime = 1.0;
        }
        else if (dualq->lq.queue_time > dualq->minTh) {
            pprime = ((double)(dualq->lq.queue_time - dualq->minTh)) / dualq->range;
        }
    }
    return pprime;
}

picoquictest_sim_packet_t* dualq_dequeue_one(dualq_state_t* dualq, picoquictest_sim_link_t* link, uint64_t current_time, int* should_drop)
{
    picoquictest_sim_packet_t* packet = NULL;
    int is_lq = 0;
    /* Couples L4S& Classic queues */
    *should_drop = 0;

    if ((packet = dualq_scheduler(dualq, link, &is_lq)) != NULL) {
        if (is_lq) {
            /* scheduler chose lq */
            /* Check for overload saturation */
            if (dualq->p_CL < dualq->p_Lmax) {
                dualq->pprime_L = dualq_laqm(dualq); /* Native LAQM */
                dualq->p_L = (dualq->pprime_L > dualq->p_CL) ? dualq->pprime_L : dualq->p_CL; /* Combining function */
                if (dualq_recur(&dualq->lq, dualq->pprime_L)) {
                    /* Linear marking */
                    packet->ecn_mark = PICOQUIC_ECN_CE;
                }
            }
            else {
                /* overload saturation */
                if (dualq_recur(&dualq->lq, dualq->p_C)) {
                    /* probability p_C = p'^2 */
                    /* revert to Classic drop due to overload */
                    *should_drop = 1; 
                }
                else if (dualq_recur(&dualq->lq, dualq->p_CL)) {
                    /* probability p_CL = k * p' */
                    /* linear marking of remaining packets */
                    packet->ecn_mark = PICOQUIC_ECN_CE;
                }
            }
        }
        else {
            /* probability p_C = p'^2 */
            if (dualq_recur(&dualq->cq, dualq->p_C)) {
                if (packet->ecn_mark == 0 ||
                    dualq->p_C >= dualq->p_Cmax) {
                    /* Overload disables ECN */
                    /* Packet is not marked ECN at all, just drop it */
                    *should_drop = 1; /* squared drop */
                }
                else
                {
                    /* Square marking */
                    packet->ecn_mark = PICOQUIC_ECN_CE;
                }
            }
        }
    }
    return packet;
}

/* The Pi2 coefficients must be updated every Tupdate */

void dualq_pi2_update(dualq_state_t* dualq)
{
    int64_t target_delta;
    int64_t delta_q;

    dualq->curq = (dualq->cq.queue_time > dualq->lq.queue_time) ?
        dualq->cq.queue_time : dualq->lq.queue_time;

    target_delta = dualq->curq - dualq->target;
    delta_q = dualq->curq - dualq->prevq;

    dualq->pprime = dualq->pprime +
        dualq->pi2_alpha * target_delta +
        dualq->pi2_beta * delta_q;
    /* Bounding p' to [0..1] */
    if (dualq->pprime < 0) {
        dualq->pprime = 0;
    }
    else if (dualq->pprime > 1.0) {
        dualq->pprime = 1.0;
    }
    /* Coupled L4S prob = base prob * coupling factor */
    if ((dualq->p_CL = dualq->pprime * dualq->k) > 1.0) {
        dualq->p_CL = 1.0;
    }
    dualq->p_C = dualq->pprime * dualq->pprime_L;
    dualq->prevq = dualq->curq;
}


/* Periodic or aperiodic updates, based on current time.
* loop on dequeue until there is no space in
* the link's queue, and then check whether parameter
* updates are necessary. */
void dualq_update_it(dualq_state_t* dualq, picoquictest_sim_link_t* link, uint64_t current_time)
{
    picoquictest_sim_packet_t* packet;
    int should_drop;
    
    while (link->queue_time <= current_time) {
        if ((packet = dualq_dequeue_one(dualq, link, link->queue_time, &should_drop)) != NULL) {
            picoquictest_sim_link_enqueue(link, packet, link->queue_time, should_drop);
        }
        else {
            break;
        }
    }
    if (link->queue_time < current_time) {
        link->queue_time = current_time;
    }

    if (current_time >= dualq->update_next) {
        dualq_pi2_update(dualq);
        dualq->update_next = current_time + dualq->Tupdate;
    }
}

void dualq_check_arrival(picoquictest_aqm_t* self, struct st_picoquictest_sim_link_t* link)
{
    if (link->first_packet == NULL) {
        dualq_state_t* dualq = (dualq_state_t*)self;
        dualq_update_it(dualq, link, link->queue_time);
    }
}


/* Submit: implement the sim link API */
void dualq_submit(picoquictest_aqm_t* self, picoquictest_sim_link_t* link,
    picoquictest_sim_packet_t* packet, uint64_t current_time)
{
    dualq_state_t* dualq = (dualq_state_t*)self;

    /* queue the packet. */
    dualq_enqueue(dualq, link, packet, current_time);

    /* submit data if possible, and compute the new value of pi2 parameters if it is time */
    dualq->last_input_time = current_time;
    dualq_update_it(dualq, link, current_time);
}

void dualq_release(picoquictest_aqm_t* self, picoquictest_sim_link_t* link)
{
    dualq_state_t* dualq = (dualq_state_t*)self;
    picoquictest_sim_packet_t* packet;

    while ((packet = dualq_dequeue_queue(dualq, link, &dualq->lq)) != NULL){
        picoquictest_sim_link_enqueue(link, packet, 0, 1);
    }
    while ((packet = dualq_dequeue_queue(dualq, link, &dualq->cq)) != NULL) {
        picoquictest_sim_link_enqueue(link, packet, 0, 1);
    }

    free(self);
    link->aqm_state = NULL;
}

void dualq_reset(picoquictest_aqm_t* self, picoquictest_sim_link_t* link, uint64_t current_time)
{
    dualq_state_t* dualq = (dualq_state_t*)self;
    dualq_update_it(dualq, link, current_time);
}

/* TODO: most of these parameters could be constants,
* or could be read from the link specification.
* For example, the link specification has a maximum data rate,
* buffer size, latency (with RTT_MAX = 2*latency)
* We may want to experiment with different target delays than 15ms.
 */
void dualq_params_init(dualq_state_t* dualq, uint64_t l4s_max)
{
    /* Set input parameter defaults
    /* DualQ Coupled framework parameters */
    dualq->limit = ((uint64_t)DUALQ_MAX_LINK_RATE * 250ull)/1000000 ; /* Dual buffer size */
    dualq->k = 2.0; /* Coupling factor */
    /* NOT SHOWN % scheduler - dependent weight or equival't parameter */
    /* PI2 Classic AQM parameters */
    dualq->target = 15000; /* Queue delay target for Classic queue, microseconds */
    uint64_t RTT_max = 100000;  /* Worst case RTT expected, microseconds */
    /* PI2 constants derived from above PI2 parameters */
    dualq->p_Cmax = 1.0 / (dualq->k * dualq->k);
    if (dualq->p_Cmax > 1.0) {
        dualq->p_Cmax = 1;
    }
    /* PI sampling interval */
    dualq->Tupdate = RTT_max / 3;
    if (dualq->Tupdate > dualq->target) {
        dualq->Tupdate = dualq->target;
    }
    /* PI coefficients */
    /* The spec says Hz, we measure in 1/us because times are in microseconds */
    dualq->pi2_alpha = (0.1 * (double)dualq->Tupdate) / ((double)RTT_max * (double)RTT_max);
    dualq->pi2_beta = (0.3) / RTT_max; /* PI proportional gain in Hz */
    /* L4S ramp AQM parameters */
    dualq->minTh = 800; /* L4S min marking threshold in micros seconds */
    if (l4s_max == 0) {
        dualq->maxTh = 1200;
        dualq->minTh = 800;
    }
    else {
        dualq->maxTh = l4s_max;
        if (l4s_max > 1200) {
            dualq->minTh = 800;
        }
        else {
            dualq->minTh = l4s_max / 3;
        }
    }
    dualq->range = dualq->maxTh - dualq->minTh; /* Range of L4S ramp in time units */

    /* 19 : Th_len = 1 pkt % Min L4S marking threshold in packets */
    /* L4S constants */
    dualq->p_Lmax = 1.0; /* Max L4S marking prob */
}


int dualq_configure(picoquictest_sim_link_t* link, uint64_t l4s_max)
{
    int ret = 0;
    dualq_state_t* dualq = NULL;

    /* Check whether the link is already configured */
    if (link->aqm_state != NULL) {
        /* use the function pointers as signature to recognize dualq */
        if (link->aqm_state->submit == dualq_submit &&
            link->aqm_state->check_arrival == dualq_check_arrival &&
            link->aqm_state->reset == dualq_reset &&
            link->aqm_state->release == dualq_release) {
            /* already using dualq! */
            dualq = (dualq_state_t*)link->aqm_state;
        }
        else
        {
            link->aqm_state->release(link->aqm_state, link);
        }
    }
    if (dualq == NULL) {
        /* Create a configuration */
        dualq = (dualq_state_t*)malloc(sizeof(dualq_state_t));

        if (dualq == NULL) {
            ret = PICOQUIC_ERROR_MEMORY;
        }
        else {
            memset(dualq, 0, sizeof(dualq_state_t));
            dualq->super.submit = dualq_submit;
            dualq->super.check_arrival = dualq_check_arrival;
            dualq->super.reset = dualq_reset;
            dualq->super.release = dualq_release;
        }
    }

    if (ret == 0){
        /* reconfigure with the new parameter */
        link->aqm_state = &dualq->super;
        dualq_params_init(dualq, l4s_max);
    }
    return ret;
}

