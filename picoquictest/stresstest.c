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
    uint64_t simulated_time;
    size_t nb_stress_client;
    int sum_data_received_at_server;
    int sum_data_sent_at_server;
    int nb_clients;
    picoquic_stress_client_t * c_ctx[PICOQUIC_MAX_STRESS_CLIENTS];
} picoquic_stress_ctx_t;

/*
 * Message loop and related functions
 */

void stress_set_ip_address_from_index(struct sockaddr_in * addr, int c_index)
{
    int ret = 0;

    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr->sin_family = AF_INET;
#ifdef _WINDOWS
    addr->sin_addr.S_un.S_addr = (ULONG) c_index;
#else
    addr->sin_addr.s_addr = (uint32_t)c_index;;
#endif
    addr->sin_port = 4321;
}

int stress_get_index_from_ip_address(struct sockaddr_in * addr)
{
    uint32_t c_index = -1;
#ifdef _WINDOWS
    c_index = (int)addr->sin_addr.S_un.S_addr;
#else
    c_index = (int)addr->sin_addr.s_addr;
#endif
    return c_index;
}


int stress_submit_sp_packets(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, int c_index)
{
    int ret = 0;
    picoquic_stateless_packet_t* sp = NULL;
    picoquictest_sim_link_t* target_link = NULL;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        ret = -1;
    }
    else while ((sp = picoquic_dequeue_stateless_packet(q)) != NULL) {
        if (sp->length > 0) {
            memcpy(&packet->addr_from, &sp->addr_local,
                (sp->addr_local.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memcpy(&packet->addr_to, &sp->addr_to,
                (sp->addr_to.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memcpy(packet->bytes, sp->bytes, sp->length);
            packet->length = sp->length;

            if (c_index > 0)
            {
                target_link = ctx->c_ctx[c_index]->c_to_s_link;
            }
            else {
                /* find target from address */
                int d_index = stress_get_index_from_ip_address((struct sockaddr_in *) &sp->addr_to);

                if (d_index < 0 || d_index >= ctx->nb_clients) {
                    ret = -1;
                }
                else {
                    target_link = ctx->c_ctx[c_index]->s_to_c_link;
                }
            }

            if (target_link != NULL) {
                picoquictest_sim_link_submit(target_link, packet, ctx->simulated_time);
            }
        }
        picoquic_delete_stateless_packet(sp);
    }

    return ret;
}

int stress_handle_packet_arrival(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, picoquictest_sim_link_t* link)
{
    int ret = 0;
    /* dequeue packet from server to client and submit */
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(link, ctx->simulated_time);

    if (packet != NULL) {
        ret = picoquic_incoming_packet(q, packet->bytes, (uint32_t)packet->length,
            (struct sockaddr*)&packet->addr_from,
            (struct sockaddr*)&packet->addr_to, 0,
            ctx->simulated_time);
    }

    return ret;
}

int stress_handle_packet_prepare(picoquic_stress_ctx_t * ctx, picoquic_quic_t * q, int c_index)
{
    /* prepare packet and submit */
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
    picoquic_packet* p = picoquic_create_packet();
    picoquic_cnx_t* cnx = q->cnx_wake_first;
    picoquictest_sim_link_t* target_link = NULL;

    if (packet != NULL && p != NULL && cnx != NULL) {
        ret = picoquic_prepare_packet(cnx, p, ctx->simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length);
        if (ret == 0 && p->length > 0) {
            memcpy(&packet->addr_from, &cnx->path[0]->dest_addr, sizeof(struct sockaddr_in));
            memcpy(&packet->addr_to, &cnx->path[0]->peer_addr, sizeof(struct sockaddr_in));

            if (c_index > 0)
            {
                target_link = ctx->c_ctx[c_index]->c_to_s_link;
            }
            else {
                /* find target from address */
                int d_index = stress_get_index_from_ip_address((struct sockaddr_in *) &packet->addr_to);

                if (d_index < 0 || d_index >= ctx->nb_clients) {
                    ret = -1;
                }
                else {
                    target_link = ctx->c_ctx[c_index]->s_to_c_link;
                }
            }

            picoquictest_sim_link_submit(target_link, packet, ctx->simulated_time);
        }
        else {
            free(p);
        }
        free(packet);
    }
    else
    {
        ret = -1;
        if (packet != NULL) {
            free(packet);
        }

        if (p != NULL) {
            free(p);
        }
    }

    return ret;
}

int stress_loop_poll_context(picoquic_stress_ctx_t * ctx, uint64_t next_time) {
    int ret = 0;
    int best_index = -1;
    int last_index = -1;
    int64_t delay_max = 100000000;
    picoquic_stateless_packet_t* sp;
    uint64_t worst_wake_time = ctx->simulated_time + delay_max;
    uint64_t best_wake_time = ctx->simulated_time + picoquic_get_next_wake_delay(
        ctx->qserver, ctx->simulated_time, delay_max);

    ret = stress_submit_sp_packets(ctx, ctx->qserver, -1);

    for (int x = 0; ret == 0 && x < ctx->nb_clients; x++) {
        /* Find the arrival time of the next packet, by looking at
         * the various links. remember the winner */

        if (ctx->c_ctx[x]->s_to_c_link->first_packet != NULL && 
            ctx->c_ctx[x]->s_to_c_link->first_packet->arrival_time < best_wake_time) {
            best_wake_time = ctx->c_ctx[x]->s_to_c_link->first_packet->arrival_time;
            best_index = x;
        }

        if (ctx->c_ctx[x]->c_to_s_link->first_packet != NULL &&
            ctx->c_ctx[x]->c_to_s_link->first_packet->arrival_time < best_wake_time) {
            best_wake_time = ctx->c_ctx[x]->c_to_s_link->first_packet->arrival_time;
            best_index = x;
        }

        if (ctx->c_ctx[x]->qclient->cnx_wake_first != NULL &&
            ctx->c_ctx[x]->qclient->cnx_wake_first->next_wake_time < best_wake_time) {
            best_wake_time = ctx->c_ctx[x]->qclient->cnx_wake_first->next_wake_time;
            best_index = x;
        }

        ret = stress_submit_sp_packets(ctx, ctx->c_ctx[x]->qclient, x);
    }

    if (ret == 0) {
        /* Progress the current time */
        ctx->simulated_time = best_wake_time;

        if (best_index < 0) {
            /* The server is ready first */
            ret = stress_handle_packet_prepare(ctx, ctx->qserver, -1);
        }
        else {
            if (ret == 0 && ctx->c_ctx[best_index]->s_to_c_link->first_packet != NULL &&
                ctx->c_ctx[best_index]->s_to_c_link->first_packet->arrival_time <= ctx->simulated_time) {
                /* dequeue packet from server to client and submit */
                ret = stress_handle_packet_arrival(ctx, ctx->c_ctx[best_index]->qclient, ctx->c_ctx[best_index]->s_to_c_link);
            }

            if (ret == 0 && ctx->c_ctx[best_index]->c_to_s_link->first_packet != NULL &&
                ctx->c_ctx[best_index]->c_to_s_link->first_packet->arrival_time <= ctx->simulated_time) {
                /* dequeue packet from client to server and submit */
                ret = stress_handle_packet_arrival(ctx, ctx->qserver, ctx->c_ctx[best_index]->c_to_s_link);
            }

            if (ctx->c_ctx[best_index]->qclient->cnx_wake_first != NULL &&
                ctx->c_ctx[best_index]->qclient->cnx_wake_first->next_wake_time <= ctx->simulated_time) {

                ret = stress_handle_packet_prepare(ctx, ctx->c_ctx[best_index]->qclient, best_index);
            }
        }
    }

    return ret;
}
