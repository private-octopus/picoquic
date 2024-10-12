/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
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

#include <stdlib.h>
#include <string.h>
#include "picomask.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "picoquic.h"
#include "picoquic_utils.h"

typedef struct st_picomask_test_ctx_t {
    uint64_t simulated_time;
    /* Three quic nodes: client(0), proxy(1), target(2) */
    picoquic_quic_t* quic[3];
    struct sockaddr_storage addr[3];
    /* Four links: server->client[0], client->server[1], server->target[2], target->server[3],
     */
    picoquictest_sim_link_t* link[4];
    /* all nodes run H3, client as client, proxy and target as servers */
    /* Transfer test will be by getting a test file from target to client */
    /* ECN simulation */
    uint8_t packet_ecn_default;
    uint8_t recv_ecn_client;
    uint8_t recv_ecn_server;
} picoquic_picomask_test_ctx_t;

/*
* test configuration.
* 
* Build a test network with three nodes: client, proxy, target.
*/
picoquic_picomask_test_ctx_t * picomask_test_config()
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picoquic_picomask_test_ctx_t* pt_ctx = NULL;

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
        PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret == 0) {
        pt_ctx = (picoquic_picomask_test_ctx_t*)malloc(sizeof(picoquic_picomask_test_ctx_t));
        if (pt_ctx == NULL) {
            ret = -1;
        }
        else {
            memset(pt_ctx, 0, sizeof(picoquic_picomask_test_ctx_t));
        }
    }

    if (ret == 0) {
        /* Create addresses */
        /* Create client context */
        /* Create server context */
        /* Create target context */
        /* Create server - client link [0] */
        /* Create client - server link [1] */
        /* Create server - target link [2] */
        /* Create target - server link [3] */

    }
    return pt_ctx;
}

/* Process arrival of a packet from a link */
int picomask_test_packet_arrival(picoquic_picomask_test_ctx_t* pt_ctx, int link_id, int * is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(pt_ctx->link[link_id], pt_ctx->simulated_time);

    if (packet == NULL) {
        /* unexpected, probably bug in test program */
        ret = -1;
    }
    else {
        int node_id = -1; /* by default, go to proxy */

        switch (link_id) {
        case 0:
            node_id = 1;
            break;
        case 1:
            node_id = 0;
            break;
        case 2:
            node_id = 1;
            break;
        case 3:
            node_id = 2;
            break;
        default:
            ret = -1;
        }

        if (ret == 0) {
            *is_active = 1;

            ret = picoquic_incoming_packet(pt_ctx->quic[node_id],
                packet->bytes, (uint32_t)packet->length,
                (struct sockaddr*)&packet->addr_from,
                (struct sockaddr*)&packet->addr_to, 0, 0,
                pt_ctx->simulated_time);
        }

        free(packet);
    }

    return ret;
}

/* Packet departure from selected node */
int picomask_test_packet_departure(picoquic_picomask_test_ctx_t* pt_ctx, int node_id,
    int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        /* memory error during test. Something is really wrong. */
        ret = -1;
    }
    else {
        /* check whether there is something to send */
        int if_index = 0;

        ret = picoquic_prepare_next_packet(pt_ctx->quic[node_id], pt_ctx->simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from, &if_index, NULL, NULL);

        if (ret != 0)
        {
            /* useless test, but makes it easier to add a breakpoint under debugger */
            free(packet);
            ret = -1;
        }
        else if (packet->length > 0) {
            /* Find link ID from node ID and destination IP */
            int link_id = -1;

            switch (node_id) {
            case 0:
                link_id = 0;
                break;
            case 1:
                if (picoquic_compare_addr((struct sockaddr*)&packet->addr_to,
                    (struct sockaddr*)&pt_ctx->addr[0]) == 0) {
                    link_id = 1;
                }
                else if (picoquic_compare_addr((struct sockaddr*)&packet->addr_to,
                    (struct sockaddr*)&pt_ctx->addr[2]) == 0) {
                    link_id = 3;
                }
                else {
                    free(packet);
                    ret = -1;
                }
                break;
            case 2:
                link_id = 2;
                break;
            }
            if (ret == 0) {
                /* If the source address is not set, set it */
                if (packet->addr_from.ss_family == 0) {
                    picoquic_store_addr(&packet->addr_from, (struct sockaddr*)&pt_ctx->addr[node_id]);
                }
                /* send now. */
                *is_active = 1;
                picoquictest_sim_link_submit(pt_ctx->link[link_id], packet, pt_ctx->simulated_time);
            }
        }
        else {
            free(packet);
        }
    }

    return ret;
}

/* step by step simulation
 */
int picomask_test_step(picoquic_picomask_test_ctx_t* pt_ctx, int* is_active)
{
    int ret = 0;
    uint64_t next_arrival_time = UINT64_MAX;
    int arrival_index = -1;
    uint64_t next_departure_time = UINT64_MAX;
    int departure_index = -1;
    int need_frame_departure = 0;
    uint64_t next_frame_time = UINT64_MAX;
    uint64_t next_time = UINT64_MAX;

    /* Check earliest packet arrival */
    for (int i = 0; i < 4; i++) {
        uint64_t arrival = picoquictest_sim_link_next_arrival(pt_ctx->link[i], next_arrival_time);
        if (arrival < next_arrival_time) {
            next_arrival_time = arrival;
            arrival_index = i;
        }
    }
    if (next_arrival_time < next_time) {
        next_time = next_arrival_time;
    }

    /* Check earliest packet departure */
    for (int i = 0; i < 3; i++) {
        uint64_t departure = picoquic_get_next_wake_time(pt_ctx->quic[i], pt_ctx->simulated_time);
        if (departure < next_departure_time) {
            next_departure_time = departure;
            departure_index = i;
        }
    }
    if (next_time > next_departure_time) {
        next_time = next_departure_time;
    }

    /* Update the time now */
    if (next_time > pt_ctx->simulated_time) {
        pt_ctx->simulated_time = next_time;
    }
    else {
        next_time = pt_ctx->simulated_time;
    }

    if (ret == 0) {
        /* Perform earliest action */
        if (next_arrival_time <= next_time) {
            /* Process next packet from simulated link */
            ret = picomask_test_packet_arrival(pt_ctx, arrival_index, is_active);
        }
        else {
            /* Prepare next packet from selected connection */
            ret = picomask_test_packet_departure(pt_ctx, departure_index, is_active);
        }
    }
    if (ret < 0) {
        DBG_PRINTF("Simulation fails at T=%" PRIu64, pt_ctx->simulated_time);
    }

    return ret;
}

/* 
* First test: verify that the UDP Connect context can be established.
*/