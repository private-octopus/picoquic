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
#include <stdint.h>
#include "h3zero.h"
#include "h3zero_common.h"
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picosocks.h"
#include "h3zero_url_template.h"
#include "picomask.h"


typedef struct st_picomask_test_ctx_t {
    uint64_t simulated_time;
    char const* alpn;
    char const* target_sni;
    char const* proxy_sni;
    char const* path;
    char const* path_template;
    /* Three quic nodes: client(0), proxy(1), target(2) */
    picoquic_quic_t* quic[3];
    struct sockaddr_storage addr[3];
    picohttp_server_parameters_t server_context;
    picohttp_server_parameters_t target_context;
    picomask_ctx_t client_app_ctx;
    picomask_ctx_t* proxy_app_ctx;
    picoquic_cnx_t* cnx_to_proxy;
    /* Four links: server->client[0], client->server[1], server->target[2], target->server[3],
     */
    picoquictest_sim_link_t* link[4];
    /* all nodes run H3, client as client, proxy and target as servers */
    /* Transfer test will be by getting a test file from target to client */
    /* ECN simulation */
    uint8_t packet_ecn_default;
    uint8_t recv_ecn_client;
    uint8_t recv_ecn_server;
} picomask_test_ctx_t;


/* Process arrival of a packet from a link */
int picomask_test_packet_arrival(picomask_test_ctx_t* pt_ctx, int link_id, int * is_active)
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
int picomask_test_packet_departure(picomask_test_ctx_t* pt_ctx, int node_id,
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
int picomask_test_step(picomask_test_ctx_t* pt_ctx, int* is_active)
{
    int ret = 0;
    uint64_t next_arrival_time = UINT64_MAX;
    int arrival_index = -1;
    uint64_t next_departure_time = UINT64_MAX;
    int departure_index = -1;
#if 0
    int need_frame_departure = 0;
    uint64_t next_frame_time = UINT64_MAX;
#endif
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



/* Connection loop. Run the simulation loop step by step until
 * the connection is ready. */

typedef int(*picomask_loop_test)(picomask_test_ctx_t* pt_ctx);

int picomask_proxy_ready(picomask_test_ctx_t* pt_ctx)
{
    int ret = 0;

    if (pt_ctx->cnx_to_proxy == NULL ||
        picoquic_get_cnx_state(pt_ctx->cnx_to_proxy) >= picoquic_state_ready) {
        ret = 1;
    }
    return ret;
}

int picomask_proxy_broken(picomask_test_ctx_t* pt_ctx)
{
    int ret = 0;

    if (pt_ctx->cnx_to_proxy == NULL ||
        picoquic_get_cnx_state(pt_ctx->cnx_to_proxy) > picoquic_state_ready) {
        ret = 1;
    }
    return ret;
}

int picomask_proxy_available(picomask_test_ctx_t* pt_ctx)
{
    int ret = 0;

    if (picomask_proxy_broken(pt_ctx)){
        ret = 1;
    }
    else {
        /* find the client side stream context, verify that it is upgraded */
    }
    return ret;
}

int picomask_test_loop(picomask_test_ctx_t* pt_ctx, picomask_loop_test loop_test_fn)
{
    int ret = 0;
    int nb_trials_max = 1024;
    int nb_trials = 0;
    int nb_inactive = 0;
    int is_complete = 0;

    while (ret == 0 && nb_trials < nb_trials_max && nb_inactive < 128) {
        int is_active = 0;
        nb_trials++;

        ret = picomask_test_step(pt_ctx, &is_active);

        if (loop_test_fn(pt_ctx)) {
            is_complete = 1;
            break;
        }

        if (is_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }

    if (!is_complete) {
        ret = -1;
    }

    return ret;
}
/*
* Delete the configuration
*/
void picomask_test_delete(picomask_test_ctx_t* pt_ctx)
{
    picomask_ctx_release(&pt_ctx->client_app_ctx);

    for (int i = 0; i < 3; i++) {
        if (pt_ctx->quic[i] != NULL) {
            picoquic_free(pt_ctx->quic[i]);
            pt_ctx->quic[i] = NULL;
        }
    }

    for (int i = 0; i < 4; i++) {
        if (pt_ctx->link[i] != NULL) {
            picoquictest_sim_link_delete(pt_ctx->link[i]);
            pt_ctx->link[i] = NULL;
        }
    }

    free(pt_ctx);
}

/*
* test configuration.
*
* Build a test network with three nodes: client, proxy, target.
* - the client quic context is at quic[0]
* - the proxy context is at quic[1]
* - the target context is at quic [2]
* We also create 4 links:
* - link[0]: from client to proxy
* - link[1]: from proxy to client
* - link[2]: from target to proxy
* - link[3]: from proxy to target
*/

int picomask_test_set_server_ctx(picomask_test_ctx_t* pt_ctx)
{
    int ret = 0;
    picohttp_server_path_item_t* path_item = (picohttp_server_path_item_t*)malloc(sizeof(picohttp_server_path_item_t));
    picomask_ctx_t* picomask_ctx = (picomask_ctx_t*)malloc(sizeof(picomask_ctx_t));

    path_item = (picohttp_server_path_item_t*)malloc(sizeof(picohttp_server_path_item_t));
    if (path_item == NULL || picomask_ctx == NULL ||
        picomask_ctx_init(picomask_ctx, 4) != 0){
        ret = -1;
        if (path_item != NULL) {
            free(path_item);
            path_item = NULL;
        }
        if (picomask_ctx != NULL) {
            free(picomask_ctx);
            picomask_ctx = NULL;
        }
    } else {
        path_item->path = pt_ctx->path;
        path_item->path_length = strlen(pt_ctx->path);
        path_item->path_callback = picomask_callback;
        path_item->path_app_ctx = (void*)picomask_ctx;

        pt_ctx->server_context.path_table = path_item;
        pt_ctx->server_context.path_table_nb = 1;
        pt_ctx->server_context.web_folder = NULL;
    }

    return ret;
}

picomask_test_ctx_t* picomask_test_config()
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picomask_test_ctx_t* pt_ctx = NULL;

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
        pt_ctx = (picomask_test_ctx_t*)malloc(sizeof(picomask_test_ctx_t));
        if (pt_ctx == NULL) {
            ret = -1;
        }
        else {
            memset(pt_ctx, 0, sizeof(picomask_test_ctx_t));

            pt_ctx->alpn = "h3";
            pt_ctx->target_sni = PICOQUIC_TEST_SNI;
            pt_ctx->proxy_sni = PICOQUIC_TEST_SNI;
            pt_ctx->path = "/masque/udp";
            pt_ctx->path_template = "/masque/udp?h={target_host}&p={target_port}";

            pt_ctx->target_context.web_folder = ".";
            pt_ctx->target_context.path_table = NULL;
            pt_ctx->target_context.path_table_nb = 0;

            ret = picomask_test_set_server_ctx(pt_ctx);
        }
    }

    if (ret == 0) {
        /* Set addresses */
        for (int i = 0; i < 3; i++) {
            unsigned long h = 0xa0000001;
            struct sockaddr_in* a = (struct sockaddr_in*)&pt_ctx->addr[i];
            a->sin_family = AF_INET;
#ifdef _WINDOWS
            a->sin_addr.S_un.S_addr = htonl(h + i);
#else

            a->sin_addr.s_addr = htonl(h + i);
#endif
            a->sin_port = htons(1234);
        }
        /* Create client context */
        pt_ctx->quic[0] = picoquic_create(8, NULL, NULL, test_server_cert_store_file, NULL,
            h3zero_callback,
            /* TODO: default client callback context */ NULL,
            NULL, NULL, NULL, pt_ctx->simulated_time,
            &pt_ctx->simulated_time,
            /* TODO -- should we store tickets? */NULL,
            NULL, 0);
        /* Create server context */
        pt_ctx->quic[1] = picoquic_create(8, test_server_cert_file, test_server_key_file, NULL, "h3",
            h3zero_callback,
            &pt_ctx->server_context,
            NULL, NULL, NULL, pt_ctx->simulated_time,
            &pt_ctx->simulated_time,
            /* TODO -- should we store tickets? */NULL,
            NULL, 0);
        /* Create target context */
        pt_ctx->quic[2] = picoquic_create(8, test_server_cert_file, test_server_key_file, NULL, "h3",
            h3zero_callback,
            &pt_ctx->target_context,
            NULL, NULL, NULL, pt_ctx->simulated_time,
            &pt_ctx->simulated_time,
            /* TODO -- should we store tickets? */NULL,
            NULL, 0);
        if (pt_ctx->quic[0] == NULL || pt_ctx->quic[1] == NULL || pt_ctx->quic[1] == NULL) {
            ret = -1;
        }
        else {
            /* initialise client app context */
            ret = picomask_ctx_init(&pt_ctx->client_app_ctx, 8);
        }
        /* Create links */
        for (int i = 0; ret == 0 && i < 4; i++) {
            if ((pt_ctx->link[i] = picoquictest_sim_link_create(0.01, 10000, NULL, 0, pt_ctx->simulated_time)) == NULL) {
                ret = -1;
            }
        }
    }

    if (ret < 0 && pt_ctx != NULL) {
        picomask_test_delete(pt_ctx);
        pt_ctx = NULL;
    }

    return pt_ctx;
}

/* Create a client connection to a specified address */
int picomask_test_cnx_create(picomask_test_ctx_t* pt_ctx)
{
    int ret = 0;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    h3zero_stream_ctx_t** p_stream_ctx = NULL;
    char path[256];

    /* use the generic H3 callback */
    /* Set the client callback context */
    if ((h3_ctx = h3zero_callback_create_context(NULL)) == NULL ||
        (cnx = picoquic_create_cnx(pt_ctx->quic[0], picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&pt_ctx->addr[1], pt_ctx->simulated_time, 0, pt_ctx->proxy_sni, pt_ctx->alpn, 1)) == NULL) {
        ret = -1;
    }
    else
    {
        pt_ctx->cnx_to_proxy = cnx;
        /* TODO: Set transport parameters? */
        picoquic_set_callback(cnx, h3zero_callback, h3_ctx);
        /* Perform the initialization, settings and QPACK streams
         */
        ret = h3zero_protocol_init(cnx);

        if (ret == 0) {
            size_t path_length;
            ret = picomask_expand_udp_path(path, sizeof(path), &path_length, pt_ctx->path_template, (struct sockaddr*)&pt_ctx->addr[2]);
        }

        if (ret == 0){
            /* TODO: missing authority and template!*/
            ret = picomask_connect(cnx, &pt_ctx->client_app_ctx, NULL, path, h3_ctx);
        }
    }
    return ret;
}

/* Test the formatting of the UDP path 
 */
typedef struct st_udp_path_test_t {
    char const* ip_address_text;
    uint16_t server_port;
    char const* path_template;
    char const* path_expansion;
} udp_path_test_t;

udp_path_test_t path_tests[] = {
    { "10.0.0.1", 443,
    "/.well-known/masque/udp/{target_host}/{target_port}/",
    "/.well-known/masque/udp/10.0.0.1/443/" },
    { "10.0.0.1", 4443,
    "/masque?h={target_host}&p={target_port}",
    "/masque?h=10.0.0.1&p=4443" },
    { "2001:db8::42", 443,
    "/masque{?target_host,target_port}",
    "/masque?target_host=2001%3Adb8%3A%3A42&target_port=443" }
};

int picomask_udp_path_test()
{
    int ret = 0;
    char text[256];
    size_t text_length;

    for (size_t i = 0; i < sizeof(path_tests) / sizeof(udp_path_test_t); i++) {
        struct sockaddr_storage server_address = { 0 };
        int is_name = 0;
        if ((ret = picoquic_get_server_address(path_tests[i].ip_address_text, path_tests[i].server_port, &server_address, &is_name)) == 0 && 
            (ret = picomask_expand_udp_path(text, sizeof(text), &text_length, path_tests[i].path_template,(struct sockaddr*)&server_address)) == 0){
            if (text_length != strlen(path_tests[i].path_expansion) ||
                memcmp(text, path_tests[i].path_expansion, text_length) != 0) {
                ret = -1;
            }
        }
    }
    return ret;
}

/*
* First test: verify that the UDP Connect context can be established.
*/
int picomask_udp_test()
{
    int ret = 0;
    picomask_test_ctx_t* pt_ctx = picomask_test_config();

    if (pt_ctx == NULL) {
        ret = -1;
    }
    else {
        /* Create a client connection to the server, and a UDP context */
        ret = picomask_test_cnx_create(pt_ctx);
    }

    if (ret == 0) {
        /* Establish the QUIC connection between client and proxy */
        picoquic_start_client_cnx(pt_ctx->cnx_to_proxy);
        ret = picomask_test_loop(pt_ctx, picomask_proxy_ready);
    }

    if (ret == 0) {
        /* Establish the control stream */
        ret = picomask_test_loop(pt_ctx, picomask_proxy_available);
    }

    /* TODO: start a connection to the target */

    if (pt_ctx != NULL) {
        /* Clear the context */
        picomask_test_delete(pt_ctx);
    }
    return ret;
}