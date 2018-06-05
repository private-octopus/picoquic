/*
* Author: Christian Huitema
* Copyright (c) 2018, Private Octopus, Inc.
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

#include "../picoquic/picoquic_internal.h"
#include "../picoquic/tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "..\picoquic\wincompat.h"
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>

/* Stress server callback: the same call back as the demo server.
 */

/* Stress client callback: same as the demo client callback, 
 * based on scenarios. But we need to account for failures,
 * effectively doing debugbreak in case of execution
 * failure, so the stress can be run under debugger.
 *
 * Consider also adding client misbehavior in the future,
 * including silent departure, version negotiation, or
 * zero share start.
 */

/* Orchestration of the simulation: one server, N simulation
 * links. On each link, there may be a new client added in
 * the future. Links have different delays, capacity, and
 * different client arrival rates.
 */

#define PICOQUIC_MAX_STRESS_CLIENTS 256

typedef struct st_picoquic_stress_client_t {
    picoquic_quic_t* qclient;
    struct sockaddr_in client_addr;
    picoquictest_sim_link_t* c_to_s_link;
    picoquictest_sim_link_t* s_to_c_link;
    int sum_data_received_at_client;
} picoquic_stress_client_t;

typedef struct st_picoquic_stress_ctx_t {
    picoquic_quic_t* qserver;
    size_t nb_stress_client;
    int sum_data_received_at_server;
    int sum_data_sent_at_server;
    int nb_clients;
    picoquic_stress_client_t * c_ctx[PICOQUIC_MAX_STRESS_CLIENTS];
} picoquic_stress_ctx_t;

/*
 * Message loop
 */

int stress_submit_sp_packet(picoquic_stress_ctx_t * ctx, picoquic_stateless_packet_t* sp, int c_index)
{
    int ret = 0;
    picoquictest_sim_link_t* target_link = NULL;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        ret = -1;
    }
    else {
        if (sp->length > 0) {
            memcpy(&packet->addr_from, &sp->addr_local,
                (sp->addr_local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memcpy(&packet->addr_to, &sp->addr_to,
                (sp->addr_to.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memcpy(packet->bytes, sp->bytes, sp->length);
            packet->length = sp->length;

            if (c_index > 0)
            {
                target_link = ctx->c_ctx[c_index]->s_to_c_link;
            }
            else {
                /* TODO: find target list from address */
            }
        }
        picoquic_delete_stateless_packet(sp);
    }

    return ret;
}

int stress_loop_poll_context(picoquic_stress_ctx_t * ctx, uint64_t next_time, uint64_t current_time) {
    int best_index = -1;
    int last_index = -1;
    int64_t delay_max = 100000000;
    picoquic_stateless_packet_t* sp;
    uint64_t worst_wake_time = current_time + delay_max;
    uint64_t best_wake_time = current_time + picoquic_get_next_wake_delay(
        ctx->qserver, current_time, delay_max);


    while ((sp = picoquic_dequeue_stateless_packet(ctx->qserver)) != NULL)
    {
        /* send all the queued packets -- need to find out to which client. */
    }

    for (int x = 0; x < ctx->nb_clients; x++) {
        /* Find the arrival time of the next packet, by looking at
         * the various links. remember the winner */

        if (ctx->c_ctx[x]->s_to_c_link->first_packet != NULL && 
            ctx->c_ctx[x]->s_to_c_link->first_packet->arrival_time < best_wake_time) {
            best_wake_time = ctx->c_ctx[x]->s_to_c_link->first_packet->arrival_time;
            best_index = x;
        }

        if (ctx->c_ctx[x]->s_to_c_link->first_packet != NULL &&
            ctx->c_ctx[x]->s_to_c_link->first_packet->arrival_time < best_wake_time) {
            best_wake_time = ctx->c_ctx[x]->s_to_c_link->first_packet->arrival_time;
            best_index = x;
        }

        if (ctx->c_ctx[x]->qclient->cnx_wake_first != NULL &&
            ctx->c_ctx[x]->qclient->cnx_wake_first->next_wake_time < best_wake_time) {
            best_wake_time = ctx->c_ctx[x]->qclient->cnx_wake_first->next_wake_time;
            best_index = x;
        }

        while ((sp = picoquic_dequeue_stateless_packet(ctx->c_ctx[x]->qclient)) != NULL)
        {
            /* send all the queued packets -- need to find out to which client. */
        }
    }

    /* Progress the current time */
    current_time = best_wake_time;

    if (best_index < 0) {
        /* The server is ready first */
    }
    else {
        if (ctx->c_ctx[best_index]->s_to_c_link->first_packet != NULL &&
            ctx->c_ctx[best_index]->s_to_c_link->first_packet->arrival_time <= current_time) {
            /* dequeue packet and submit */
        }

        if (ctx->c_ctx[best_index]->s_to_c_link->first_packet != NULL &&
            ctx->c_ctx[best_index]->s_to_c_link->first_packet->arrival_time <= current_time) {
            /* dequeue packet and submit */
        }

        if (ctx->c_ctx[best_index]->qclient->cnx_wake_first != NULL &&
            ctx->c_ctx[best_index]->qclient->cnx_wake_first->next_wake_time <= current_time) {
            /* prepare packet and submit */
        }
    }

    return -1;
}
