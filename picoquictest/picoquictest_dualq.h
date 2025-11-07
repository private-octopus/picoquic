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

#ifndef PICOQUICTEST_DUALQ_H
#define PICOQUICTEST_DUALQ_H

#include "picoquic_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

    int dualq_configure(picoquictest_sim_link_t* link, uint64_t l4s_max);

    /* The following internal structures and functions should only be
    * used for tests and monitoring.
    */

#define DUALQ_MAX_LINK_RATE 125000000 /* 125,000,000 Bytes/sec, i.e., 1 Gbps -- pretty much a simulation limit */

    typedef struct st_dualq_queue_t {
        uint64_t queue_bytes;
        uint64_t queue_time;
        int count; /* number of packets in queue */
        double sum_p; /* Ongoing sum of drop prob, create drop is sum > 1*/
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
        uint64_t lq_average_queue;
        double pprime; /* the p' coefficent in RFC9332, nominal mark rate of L4S queue derived from length of classic queue */
        double pprime_L; /* the p'_L coefficient in RFC9332, mark rate of L4S queue computed from L4S queue length, before coupling */
        double p_L; /* actual mark rate of L4S queue, after combining with "p_CL" */
        double p_CL; /* Coupled L4S prob = base prob pprime_L * coupling factor k */
        double p_C; /* Nominal drop rate of classic queue, equal to pprime_L^2 */
        /* Picoquic NS data */
        uint64_t last_input_time;
    } dualq_state_t;

    void dualq_enqueue_queue(dualq_state_t* dualq, picoquictest_sim_link_t* link, dualq_queue_t* xq, picoquictest_sim_packet_t* packet);
    picoquictest_sim_packet_t* dualq_dequeue_one(dualq_state_t* dualq, picoquictest_sim_link_t* link, uint64_t current_time, int* should_drop);
#ifdef __cplusplus
}
#endif

#endif /* PICOQUICTEST_DUALQ_H */