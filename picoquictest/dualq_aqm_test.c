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
* Unit tests of the DualQ AQM code
 */
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picosocks.h"
#include <stdlib.h>
#include <string.h>
#include "picoquictest_dualq.h"
#include "picoquictest_internal.h"

typedef struct st_dualq_test_ctx_t {
    picoquic_quic_t * quic;
    picoquic_cnx_t* cnx;
    picoquictest_sim_link_t* link;
    uint64_t simulated_time;
    dualq_state_t* dqs;
} dualq_test_ctx;

void dualq_test_release_ctx(dualq_test_ctx* dqt_ctx)
{
    picoquic_test_delete_minimal_cnx(&dqt_ctx->quic, &dqt_ctx->cnx);
    if (dqt_ctx->link != NULL) {
        picoquictest_sim_link_delete(dqt_ctx->link);
    }
    dqt_ctx->link = NULL;
}

int dualq_test_get_ctx(dualq_test_ctx* dqt_ctx)
{
    int ret = 0;
    
    memset(dqt_ctx, 0, sizeof(dualq_test_ctx));

    ret = picoquic_test_set_minimal_cnx_with_time(&dqt_ctx->quic, &dqt_ctx->cnx, &dqt_ctx->simulated_time);
    if (ret == 0) {
        if ((dqt_ctx->link = picoquictest_sim_link_create(0.01, 25000, NULL, 50000, dqt_ctx->simulated_time)) == NULL) {
            ret = -1;
        }
        else {
            ret = dualq_configure(dqt_ctx->link, 5000);
            if (ret == 0) {
                dqt_ctx->dqs = (dualq_state_t*)dqt_ctx->link->aqm_state;
            }
        }
    }
    if (ret != 0) {
        dualq_test_release_ctx(dqt_ctx);
    }
    return ret;
}

int dualq_test_ctx_test(void)
{
    dualq_test_ctx dqt_ctx;
    int ret = dualq_test_get_ctx(&dqt_ctx);
    if (ret == 0) {
        dualq_test_release_ctx(&dqt_ctx);
    }
    return ret;
}

picoquictest_sim_packet_t* dualq_test_get_packet(uint8_t ecn_mark, size_t length)
{
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet != NULL) {
        packet->ecn_mark = ecn_mark;
        packet->length = length;
    }
    return packet;
}

/* Enqueue test: check the low level queue API */
int dualq_enqueue_test(void)
{
    dualq_test_ctx dqt_ctx;
    int ret = dualq_test_get_ctx(&dqt_ctx);
    uint8_t ecn_sequence[] = {0, PICOQUIC_ECN_ECT_0, 0, PICOQUIC_ECN_ECT_1, PICOQUIC_ECN_CE};
    int queue_id[] = { 0, 0, 0, 1, 1 };

    for (size_t i=0; ret == 0 && i< sizeof(ecn_sequence)/sizeof(uint8_t); i++){
        dualq_queue_t* xq = (queue_id[i] == 0) ? &dqt_ctx.dqs->cq : &dqt_ctx.dqs->lq;
        picoquictest_sim_packet_t* packet = dualq_test_get_packet(ecn_sequence[i], 1000);
        uint64_t old_bytes = xq->queue_bytes;
        picoquictest_sim_packet_t* old_last = xq->queue_last;
        picoquictest_sim_packet_t* old_first = xq->queue_first;
        picoquictest_sim_packet_t* last_in_link = dqt_ctx.link->last_packet;

        dualq_enqueue_queue(xq, packet);

        if (xq->queue_last != packet ||
            xq->queue_bytes != old_bytes + packet->length ||
            packet->next_packet != NULL) {
            ret = -1;
        }
        else if (old_first == NULL && xq->queue_first != packet){
            ret = -1;
        }
        else if (old_first != NULL && xq->queue_first != old_first) {
            ret = -1;
        }
        else if (old_last != NULL && old_last->next_packet != packet) {
            ret = -1;
        }
        else if (dqt_ctx.link->last_packet != last_in_link) {
            ret = -1;
        }
    }

    dualq_test_release_ctx(&dqt_ctx);

    return(ret);
}

/* Dequeue test: basic check of the dequeue API */
int dualq_dequeue_test(void)
{
    dualq_test_ctx dqt_ctx;
    int ret = dualq_test_get_ctx(&dqt_ctx);
    uint8_t ecn_sequence[] = { 0, PICOQUIC_ECN_ECT_0, 0, PICOQUIC_ECN_ECT_1, PICOQUIC_ECN_CE };
    int queue_id[] = { 0, 0, 0, 1, 1 };
    int trials = 0;
    int received = 0;
    uint64_t max_time = 100000;

    /* Load the link with just 5 packets */
    for (size_t i = 0; ret == 0 && i < sizeof(ecn_sequence) / sizeof(uint8_t); i++) {
        picoquictest_sim_packet_t* packet = dualq_test_get_packet(ecn_sequence[i], 1000);
        dualq_queue_t* xq = (queue_id[i] == 0) ? &dqt_ctx.dqs->cq : &dqt_ctx.dqs->lq;
        dualq_enqueue_queue(xq, packet);
    }
    /* Perform link departure until all packets sent */

    while (ret == 0 &&
        (dqt_ctx.dqs->lq.queue_bytes > 0 ||
            dqt_ctx.dqs->cq.queue_bytes > 0)) {
        trials++;
        if (trials > 1000) {
            ret = -1;
        }
        else {
            int shoulddrop = 0;
            picoquictest_sim_packet_t* packet = dualq_dequeue_one(dqt_ctx.dqs, dqt_ctx.simulated_time, &shoulddrop);

            if (packet == NULL) {
                dqt_ctx.simulated_time += 1000;
            }
            else {
                received++;
                free(packet);
            }
        }
    }
    if (ret == 0 && received != 5) {
        ret = -1;
    }

    if (ret == 0 &&
        (dqt_ctx.dqs->cq.queue_bytes != 0 ||
            dqt_ctx.dqs->cq.queue_first != NULL ||
            dqt_ctx.dqs->cq.queue_last != NULL)) {
        ret = -1;
    }
    if (ret == 0 &&
        (dqt_ctx.dqs->lq.queue_bytes != 0 ||
            dqt_ctx.dqs->lq.queue_first != NULL ||
            dqt_ctx.dqs->lq.queue_last != NULL)) {
        ret = -1;
    }

    if (ret == 0 && dqt_ctx.simulated_time > max_time) {
        ret = -1;
    }

    dualq_test_release_ctx(&dqt_ctx);

    return ret;
}

/* Submit test: verify the submit behavior.
* If the link queue is empty, the packet should go there.
* Otherwise, queue in L or C queue */
int dualq_test_check_queue(picoquictest_sim_link_t* link)
{
    int ret = 0;
    uint64_t previous_time = 0;
    picoquictest_sim_packet_t* packet = link->first_packet;

    while (packet != NULL && ret == 0) {
        if (packet->arrival_time <= previous_time) {
            ret = -1;
        }
        else {
            previous_time = packet->arrival_time;
            packet = packet->next_packet;
        }
    }
    return ret; 
}


int dualq_submit_test(void)
{
    dualq_test_ctx dqt_ctx;
    int ret = dualq_test_get_ctx(&dqt_ctx);
    uint8_t ecn_sequence[] = { 0, PICOQUIC_ECN_ECT_0, 0, PICOQUIC_ECN_ECT_1, PICOQUIC_ECN_CE };
    int queue_id[] = { 0, 0, 0, 1, 1 };
    int one_was_dropped = 0;

    for (size_t i = 0; ret == 0 && i < 50; i++) {
        int i_queue = i % 5;
        dualq_queue_t* xq = (queue_id[i_queue] == 0) ? &dqt_ctx.dqs->cq : &dqt_ctx.dqs->lq;
        picoquictest_sim_packet_t* packet = dualq_test_get_packet(ecn_sequence[i_queue], 1000);
        uint64_t old_bytes = xq->queue_bytes;
        uint64_t old_queue_time = dqt_ctx.link->queue_time;
        uint64_t old_total = dqt_ctx.dqs->cq.queue_bytes + dqt_ctx.dqs->lq.queue_bytes + packet->length;
        picoquictest_sim_link_submit(dqt_ctx.link, packet, dqt_ctx.simulated_time);


        if (old_queue_time <= dqt_ctx.simulated_time) {
            /* First packet should be directly queued to the link. */
            if (dqt_ctx.link->queue_time == old_queue_time) {
                ret = -1;
            }
        }
        else {
            if (dqt_ctx.link->queue_time != old_queue_time) {
                ret = -1;
            }
            else if (old_total > dqt_ctx.dqs->limit) {
                /* expect packet to be dropped, and queue sizes to not increase */
                if (xq->queue_bytes != old_bytes) {
                    ret = -1;
                }
                else {
                    one_was_dropped = 1;
                    break;
                }
            }
            else {
                if (xq->queue_bytes == old_bytes) {
                    ret = -1;
                }
                else {
                    ret = dualq_test_check_queue(dqt_ctx.link);
                }
            }
        }
    }

    if (ret == 0 && !one_was_dropped) {
        ret = -1;
    }

    dualq_test_release_ctx(&dqt_ctx);

    return(ret);
}

/* Configure test: dualq_test_get_ctx always configures with a fixed l4s_max (5000), which
 * never exercises the l4s_max==0 (use defaults) or l4s_max<=1200 (low threshold) branches
 * of dualq_params_init. Check both directly. */
int dualq_configure_defaults_test(void)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquictest_sim_link_t* link = picoquictest_sim_link_create(0.01, 25000, NULL, 50000, simulated_time);

    if (link == NULL) {
        ret = -1;
    }
    else {
        if ((ret = dualq_configure(link, 0)) == 0) {
            dualq_state_t* dqs = (dualq_state_t*)link->aqm_state;
            if (dqs->maxTh != 1200 || dqs->minTh != 800) {
                DBG_PRINTF("dualq l4s_max=0 defaults wrong: maxTh=%" PRIu64 ", minTh=%" PRIu64, dqs->maxTh, dqs->minTh);
                ret = -1;
            }
        }
        picoquictest_sim_link_delete(link);
    }

    if (ret == 0 &&
        (link = picoquictest_sim_link_create(0.01, 25000, NULL, 50000, simulated_time)) == NULL) {
        ret = -1;
    }
    else if (ret == 0) {
        if ((ret = dualq_configure(link, 600)) == 0) {
            dualq_state_t* dqs = (dualq_state_t*)link->aqm_state;
            if (dqs->maxTh != 600 || dqs->minTh != 200) {
                DBG_PRINTF("dualq l4s_max=600 low-threshold wrong: maxTh=%" PRIu64 ", minTh=%" PRIu64, dqs->maxTh, dqs->minTh);
                ret = -1;
            }
        }
        picoquictest_sim_link_delete(link);
    }

    return ret;
}

/* Configure test: calling dualq_configure twice on the same link should recognize the
 * existing dualq state via its function-pointer signature and reuse it, rather than
 * releasing and recreating it. */
int dualq_configure_reuse_test(void)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquictest_sim_link_t* link = picoquictest_sim_link_create(0.01, 25000, NULL, 50000, simulated_time);

    if (link == NULL) {
        ret = -1;
    }
    else {
        if ((ret = dualq_configure(link, 5000)) == 0) {
            void* first_aqm_state = link->aqm_state;
            if ((ret = dualq_configure(link, 5000)) == 0 &&
                link->aqm_state != first_aqm_state) {
                DBG_PRINTF("%s", "dualq_configure did not reuse the existing state on a matching re-configure");
                ret = -1;
            }
        }
        picoquictest_sim_link_delete(link);
    }

    return ret;
}

/* Overload test: force the "overload saturation" branches of dualq_dequeue_one -- for the
 * L4S queue (p_CL >= p_Lmax) and for the Classic queue (an already ECN-capable packet) --
 * neither of which is reached by the other tests, since none of them drive the classic
 * queue's own drop probability, nor the coupled L4S probability, up to saturation. */
int dualq_overload_test(void)
{
    dualq_test_ctx dqt_ctx;
    int ret = dualq_test_get_ctx(&dqt_ctx);

    if (ret == 0) {
        dualq_state_t* dqs = dqt_ctx.dqs;
        int should_drop = 0;
        picoquictest_sim_packet_t* packet;

        /* L4S queue overload: p_CL >= p_Lmax forces the "else" (overload) branch. */
        dqs->p_Lmax = 0.5;
        dqs->p_CL = 1.0;
        dqs->p_C = 0.2;
        dqs->lq.sum_p = 0.85; /* + p_C (0.2) = 1.05 > 1.0: first packet is squared-dropped. */

        dualq_enqueue_queue(&dqs->lq, dualq_test_get_packet(PICOQUIC_ECN_ECT_1, 1000));
        packet = dualq_dequeue_one(dqs, dqt_ctx.simulated_time, &should_drop);
        if (packet == NULL || !should_drop) {
            DBG_PRINTF("%s", "L4S overload did not drop the first packet as expected");
            ret = -1;
        }
        free(packet);

        /* sum_p is now 0.05; + p_C (0.2) = 0.25 (no drop); + p_CL (1.0) = 1.25 > 1.0: marked. */
        dualq_enqueue_queue(&dqs->lq, dualq_test_get_packet(PICOQUIC_ECN_ECT_1, 1000));
        packet = dualq_dequeue_one(dqs, dqt_ctx.simulated_time, &should_drop);
        if (ret == 0 && (packet == NULL || should_drop || packet->ecn_mark != PICOQUIC_ECN_CE)) {
            DBG_PRINTF("%s", "L4S overload did not CE-mark the second packet as expected");
            ret = -1;
        }
        free(packet);

        /* Classic queue overload: an unmarked packet gets squared-dropped... */
        dqs->p_Cmax = 0.25;
        dqs->p_C = 0.2;
        dqs->cq.sum_p = 0.9; /* + p_C (0.2) = 1.1 > 1.0: recur triggers. */

        dualq_enqueue_queue(&dqs->cq, dualq_test_get_packet(0, 1000));
        packet = dualq_dequeue_one(dqs, dqt_ctx.simulated_time, &should_drop);
        if (ret == 0 && (packet == NULL || !should_drop)) {
            DBG_PRINTF("%s", "Classic overload did not drop the unmarked packet as expected");
            ret = -1;
        }
        free(packet);

        /* ... while one that already carries an ECN mark gets squared-marked instead,
         * since p_C (0.2) stays below p_Cmax (0.25). */
        dqs->cq.sum_p = 0.9; /* + p_C (0.2) = 1.1 > 1.0: recur triggers again. */
        dualq_enqueue_queue(&dqs->cq, dualq_test_get_packet(PICOQUIC_ECN_ECT_0, 1000));
        packet = dualq_dequeue_one(dqs, dqt_ctx.simulated_time, &should_drop);
        if (ret == 0 && (packet == NULL || should_drop || packet->ecn_mark != PICOQUIC_ECN_CE)) {
            DBG_PRINTF("%s", "Classic overload did not CE-mark the ECN-capable packet as expected");
            ret = -1;
        }
        free(packet);
    }

    dualq_test_release_ctx(&dqt_ctx);

    return ret;
}

/* PI2 update test: force pprime, and its coupled p_CL, above 1.0 in a single update tick to
 * exercise both upper-bound clamps in dualq_pi2_update -- not reached by any other test,
 * since normal PI2 gains never drive pprime that high in one tick. */
int dualq_pi2_clamp_test(void)
{
    dualq_test_ctx dqt_ctx;
    int ret = dualq_test_get_ctx(&dqt_ctx);

    if (ret == 0) {
        dualq_state_t* dqs = dqt_ctx.dqs;

        dqs->pi2_alpha = 0;
        dqs->pi2_beta = 0;
        dqs->pprime = 1.5;

        dualq_pi2_update(dqs, dqt_ctx.simulated_time);

        if (dqs->pprime != 1.0 || dqs->p_CL != 1.0) {
            DBG_PRINTF("dualq pi2 clamp: pprime=%f, p_CL=%f, expected 1.0/1.0", dqs->pprime, dqs->p_CL);
            ret = -1;
        }
    }

    dualq_test_release_ctx(&dqt_ctx);

    return ret;
}

/* Dual Q end to end test. Assume that packets arrive in batches and
 * are retrieved as soon as available. Check that the interval between
 * submission and retrieval is what we expect */

int dualq_sustain_test_receive(dualq_test_ctx* dqt_ctx, int* nb_received)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(dqt_ctx->link,
        dqt_ctx->simulated_time);
    if (packet == NULL) {
        ret = -1;
    }
    else {
        *nb_received += 1;
        free(packet);
    }
    if (ret == 0){
        ret = dualq_test_check_queue(dqt_ctx->link);
    }
    return ret;
}

void dualq_sustain_test_admit(dualq_test_ctx* dqt_ctx)
{
    picoquictest_sim_link_admit_pending(dqt_ctx->link,
        dqt_ctx->simulated_time);
}

int dualq_sustain_test_submit(dualq_test_ctx* dqt_ctx, int* nb_sent)
{
    int ret = 0;
    const uint8_t ecn_sequence[] = { 0, PICOQUIC_ECN_ECT_0, 0, PICOQUIC_ECN_ECT_1, PICOQUIC_ECN_CE };
    picoquictest_sim_packet_t* packet = dualq_test_get_packet(ecn_sequence[*nb_sent % 5], 1000);
    if (packet == NULL) {
        ret = -1;
    }
    else {
        packet->bytes[0] = (uint8_t)*nb_sent;
        *nb_sent += 1;
        picoquictest_sim_link_submit(dqt_ctx->link, packet, dqt_ctx->simulated_time);
        ret = dualq_test_check_queue(dqt_ctx->link);
    }
    return ret;
}

typedef enum {
    st_none = 0,
    st_arrival,
    st_admission,
    st_submit
} dualq_sustain_test_enum;

int dualq_sustain_test(void)
{
    dualq_test_ctx dqt_ctx;
    int ret = dualq_test_get_ctx(&dqt_ctx);
    uint64_t submit_time = dqt_ctx.simulated_time;
    uint64_t max_time = 125000;
    int nb_received = 0;
    int nb_sent = 0;

    while (ret == 0) {
        uint64_t action_time = UINT64_MAX;
        dualq_sustain_test_enum next_action = st_none;
        uint64_t admission_time;
        uint64_t arrival_time = picoquictest_sim_link_next_arrival(dqt_ctx.link, action_time);
        if (arrival_time < action_time) {
            next_action = st_arrival;
            action_time = arrival_time;
        }
        admission_time = picoquictest_sim_link_next_admission(dqt_ctx.link, dqt_ctx.simulated_time, action_time);
        if (admission_time < action_time) {
            next_action = st_admission;
            action_time = admission_time;
        }

        /* Check whether submit is blocked, or whether the time is right. */
        if (nb_sent < 100 &&
            dqt_ctx.dqs->cq.queue_bytes + dqt_ctx.dqs->lq.queue_bytes + 1000 <= dqt_ctx.dqs->limit &&
            submit_time < action_time) {
            next_action = st_submit;
            action_time = submit_time;
        }
        /* Exit if no next action */
        if (next_action == st_none) {
            break;
        }
        /* Update the time to follow events */
        if (dqt_ctx.simulated_time < action_time) {
            if (action_time > dqt_ctx.simulated_time + 4000) {
                ret = -1;
                break;
            }
            dqt_ctx.simulated_time = action_time;
        }
        else {
            action_time = dqt_ctx.simulated_time;
        }

        if (next_action == st_submit) {
            dualq_sustain_test_submit(&dqt_ctx, &nb_sent);
            if ((nb_sent % 7) == 0) {
                submit_time += 4000;
            }
        }
        else if (next_action == st_arrival) {
            dualq_sustain_test_receive(&dqt_ctx, &nb_received);
        }
        else if (next_action == st_admission) {
            dualq_sustain_test_admit(&dqt_ctx);
        }
        else {
            /* This is unexpected! */
            ret = -1;
            break;
        }
    }

    if (ret == 0 && (nb_received + dqt_ctx.link->packets_dropped) != 100) {
        ret = -1;
    }
    if (ret == 0 && dqt_ctx.simulated_time > max_time) {
        ret = -1;
    }

    dualq_test_release_ctx(&dqt_ctx);

    return(ret);
}

/* Series of unit tests of the dualq aqm function */

int dualq_aqm_test(void)
{
    int ret = dualq_test_ctx_test();

    if (ret == 0) {
        ret = dualq_enqueue_test();
    }

    if (ret == 0) {
        ret = dualq_dequeue_test();
    }

    if (ret == 0) {
        ret = dualq_submit_test();
    }

    if (ret == 0) {
        ret = dualq_configure_defaults_test();
    }

    if (ret == 0) {
        ret = dualq_configure_reuse_test();
    }

    if (ret == 0) {
        ret = dualq_overload_test();
    }

    if (ret == 0) {
        ret = dualq_pi2_clamp_test();
    }

    if (ret == 0) {
        ret = dualq_sustain_test();
    }

    return ret;
}
