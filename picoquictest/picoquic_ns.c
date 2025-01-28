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


#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "tls_api.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "quicperf.h"
#include "logreader.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "qlog.h"
#include "autoqlog.h"
#include "picosocks.h"
#include "picoquic_ns.h"

/*
* The simulation follows the model established for the "stress" tests: single
* client context, single server context.All connections will run the
* "test" protocol.The background connections will run a "high load"
* scenario, the test connection will use a specific scenario.The simulation
* will manage links from and two server, shared by all clients.Demuxing
* will be per CID.The typical run time will be :
* -start
* -set the configuration.
* -on a loop
* -if time has come, start a required connection
* -simulate arrival and departure of packets
* -on packet arrival, do the usual test protocol processing.
* -if the client has sent / received all its data, exit the simulation.
* -also exit if this takes too long.
* -after the loop :
* -verify that the client scenario was executed properly.
*
* We use "qperf" as the protocol, as it is designed for exactly that purpose.
* The cc_compete server is a quicperf server. However, we want to intercept
* the creation of server side connection and ensure that they are using the
* desired congestion control algorithm. We ensure that by setting this
* default callback function for the server context. When a new connection
* arrives, the server uses the "cc_compete" context to find the matching
* client connection, discover the desired congestion algorithm, and
* program it in the server side connection context
* 
* The main advantages of this simulation are:
* - Running the actual picoquic code.
* - Operating in "virtual time", much faster than "real time".
* 
* There are limits to this setup:
* - we set a maximum number of nodes, links, connections. This is not strictly
*   necessary. We could dynamically allocate arrays.
* - we only support a "single link" topology. We could envisage supporting
*   the >-< topology used in many networking tests: a shared link in the middle,
*   two links on the left leading to the "main" and "background" clients,
*   two links on the right leading the the "main" and "background" servers.
*   Or, at a later stage, maybe allow for aribitrary topologies.
* - we do not yet support dynamically changing the properties of the links,
*   e.g., having link break, be restored, or change data rate and latency.
* - the "L4S" implementation is a place holder.
* - we do not support complex AQM
* - we do not simulate CPU consumption.
* - we do not simulate UDP GSO, i.e., preparing batches of packets.
* 
* The picoquic library comes with a set of CC algorithm implementation. It
* is technically possible for implementors to define their own
 */

#define PICOQUIC_NS_MAX_CLIENTS 5
#define QUIC_PERF_ALPN "perf"
#define PICOQUIC_NS_NB_LINKS 2
#define PICOQUIC_NS_NB_NODES 2

typedef struct st_picoquic_ns_client_t {
    uint64_t start_time;
    picoquic_cnx_t* cnx;
    picoquic_congestion_algorithm_t* cc_algo;
    quicperf_ctx_t* quicperf_ctx;
    picoquic_connection_id_t icid;
} picoquic_ns_client_t;

typedef struct st_picoquic_ns_ctx_t {
    picoquic_quic_t* q_ctx[PICOQUIC_NS_NB_NODES];
    struct sockaddr_in addr[PICOQUIC_NS_NB_NODES];
    picoquictest_sim_link_t* link[PICOQUIC_NS_NB_LINKS];
    uint64_t simulated_time;
    int nb_connections;
    uint64_t next_cnx_start_time;
    picoquic_ns_client_t* client_ctx[PICOQUIC_NS_MAX_CLIENTS];
    uint8_t packet_ecn_default;
} picoquic_ns_ctx_t;


int picoquic_ns_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    picoquic_ns_ctx_t* cc_ctx;
    quicperf_ctx_t* perf_ctx = NULL;

    if (callback_ctx != picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        /* Unexpected.  W return an error. The server will close that connection. */
        picoquic_close(cnx, QUICPERF_ERROR_INTERNAL_ERROR);
        ret = -1;
    }
    else {
        cc_ctx = (picoquic_ns_ctx_t*)callback_ctx;
        ret = -1; /* will reset to zero if find a matching client */
        for (int i = 0; i < cc_ctx->nb_connections; i++) {
            if (cc_ctx->client_ctx[i]->cnx != NULL &&
                picoquic_compare_connection_id(&cnx->path[0]->p_remote_cnxid->cnx_id,
                    &cc_ctx->client_ctx[i]->cnx->path[0]->p_local_cnxid->cnx_id) == 0) {
                picoquic_set_congestion_algorithm(cnx, cc_ctx->client_ctx[i]->cc_algo);
                ret = 0;
            }
        }
    }
    if (ret == 0) {
        /* set the server connection context */
        perf_ctx = quicperf_create_ctx(NULL);
        if (perf_ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, QUICPERF_ERROR_INTERNAL_ERROR);
            ret = -1;
        }
        else {
            picoquic_set_callback(cnx, quicperf_callback, perf_ctx);
        }
    }
    if (ret == 0) {
        ret = quicperf_callback(cnx, stream_id, bytes, length, fin_or_event, perf_ctx, v_stream_ctx);
    }
    return ret;
}

int picoquic_ns_create_client_ctx(picoquic_ns_ctx_t* cc_ctx, picoquic_ns_spec_t* spec, int client_id)
{
    int ret = 0;
    picoquic_ns_client_t* client_ctx = (picoquic_ns_client_t*)malloc(sizeof(picoquic_ns_client_t));

    if (client_ctx == NULL) {
        ret = -1;
    }
    else {
        char const* scenario_text = NULL;

        memset(client_ctx, 0, sizeof(picoquic_ns_client_t));
        cc_ctx->client_ctx[client_id] = client_ctx;

        if (spec->icid.id_len > 0) {
            int cid_bin = client_id;
            int cid_index = spec->icid.id_len - 1;
            client_ctx->icid = spec->icid;
            while (cid_bin > 0 && cid_index >= 0) {
                client_ctx->icid.id[cid_index] = (uint8_t)client_id;
                cid_bin >>= 8;
                cid_index--;
            }
        }

        if (client_id == 0) {
            client_ctx->start_time = spec->main_start_time;
            client_ctx->cc_algo = spec->main_cc_algo;
            scenario_text = spec->main_scenario_text;
        }
        else {
            client_ctx->start_time = spec->background_start_time;
            client_ctx->cc_algo = spec->background_cc_algo;
            scenario_text = spec->background_scenario_text;
        }
        if ((client_ctx->quicperf_ctx = quicperf_create_ctx(scenario_text)) == NULL) {
            ret = -1;
        }
    }
    return ret;
}

void picoquic_ns_delete_client_ctx(picoquic_ns_ctx_t* cc_ctx, int client_id)
{
    picoquic_ns_client_t* client_ctx = cc_ctx->client_ctx[client_id];

    if (client_ctx != NULL) {
        /* delete the connection */
        if (client_ctx->cnx != NULL) {
            picoquic_delete_cnx(client_ctx->cnx);
            client_ctx->cnx = NULL;
        }
        if (client_ctx->quicperf_ctx != NULL) {
            quicperf_delete_ctx(client_ctx->quicperf_ctx);
            client_ctx->quicperf_ctx = NULL;
        }
        free(client_ctx);
        cc_ctx->client_ctx[client_id] = NULL;
    }
}

int picoquic_ns_create_link(picoquic_ns_ctx_t* cc_ctx, picoquic_ns_spec_t* spec, int link_id)
{
    int ret = 0;
    double data_rate = spec->data_rate_in_gbps;
    uint64_t latency = spec->latency;
    if (data_rate == 0) {
        data_rate = 0.01; /* default to 10mbps */
    }
    if (latency == 0) {
        latency = 10000; /* default to 10ms */
    }

    if ((cc_ctx->link[link_id] = picoquictest_sim_link_create(data_rate, latency, NULL,
        spec->queue_delay_max, cc_ctx->simulated_time)) == NULL) {
        ret = -1;
    }
    else {
        cc_ctx->link[link_id]->l4s_max = spec->l4s_max;
    }
    return ret;
}

void picoquic_ns_delete_ctx(picoquic_ns_ctx_t* cc_ctx)
{
    /* delete the connections before deleting the quic context,
    * to avoid repeated calls to picoquic_delete_cnx
     */
    for (int i = 0; i < PICOQUIC_NS_MAX_CLIENTS; i++) {
        picoquic_ns_delete_client_ctx(cc_ctx, i);
    }

    /* deleting the quic context wil delete the server side
     * connection contexts */
    for (int i = 0; i < PICOQUIC_NS_NB_NODES; i++) {
        if (cc_ctx->q_ctx[i] != NULL) {
            picoquic_free(cc_ctx->q_ctx[i]);
            cc_ctx->q_ctx[i] = NULL;
        }
    }
    /* delete the link contexts and free the packets in transit.*/
    for (int i = 0; i < PICOQUIC_NS_NB_LINKS; i++) {
        if (cc_ctx->link[i] != NULL) {
            picoquictest_sim_link_delete(cc_ctx->link[i]);
            cc_ctx->link[i] = NULL;
        }
    }
    /* and then free the context itself */
    free(cc_ctx);
}

picoquic_ns_ctx_t* picoquic_ns_create_ctx(picoquic_ns_spec_t* spec)
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_client_cert_store_file[512];
    picoquic_ns_ctx_t* cc_ctx = (picoquic_ns_ctx_t*)malloc(sizeof(picoquic_ns_ctx_t));
    if (cc_ctx == NULL) {
        ret = -1;
    }
    else {
        memset(cc_ctx, 0, sizeof(picoquic_ns_ctx_t));
        if (picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT) != 0 ||
            picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file),
                picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY) != 0 ||
            picoquic_get_input_path(test_client_cert_store_file, sizeof(test_client_cert_store_file),
                picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE) != 0)
        {
            DBG_PRINTF("%s", "Could not find the default server key and certs");
            ret = -1;
        }
    }

    if (ret == 0) {
        for (int i = 0; i < PICOQUIC_NS_NB_NODES; i++) {
            uint32_t ip_addr = 0x0A000001 + i;
            cc_ctx->addr[i].sin_family = AF_INET;
            cc_ctx->addr[i].sin_port = 1234;
#ifdef _WINDOWS
            cc_ctx->addr[i].sin_addr.S_un.S_addr = htonl(ip_addr);
#else
            cc_ctx->addr[i].sin_addr.s_addr = htonl(ip_addr);
#endif
        }
        /* Create server side quic context */
        if ((cc_ctx->q_ctx[0] = picoquic_create(
            PICOQUIC_NS_MAX_CLIENTS,
            test_server_cert_file,
            test_server_key_file,
            NULL,
            QUIC_PERF_ALPN,
            picoquic_ns_server_callback,
            (void*)cc_ctx,
            NULL,
            NULL,
            NULL,
            cc_ctx->simulated_time,
            &cc_ctx->simulated_time,
            NULL,
            NULL,
            0)) == NULL) {
            ret = -1;
        }
        /* Create client side quic context */
        if ((cc_ctx->q_ctx[1] = picoquic_create(
            PICOQUIC_NS_MAX_CLIENTS,
            NULL,
            NULL,
            test_client_cert_store_file,
            QUIC_PERF_ALPN,
            quicperf_callback,
            (void*)cc_ctx,
            NULL,
            NULL,
            NULL,
            cc_ctx->simulated_time,
            &cc_ctx->simulated_time,
            NULL,
            NULL,
            0)) == NULL) {
            ret = -1;
        }
        else {
            picoquic_set_default_pmtud_policy(cc_ctx->q_ctx[1], picoquic_pmtud_delayed);
        }
        if (spec->qlog_dir != NULL) {
            for (int i = 0; ret == 0 && i < 2; i++) {
                ret = picoquic_set_qlog(cc_ctx->q_ctx[i], spec->qlog_dir);
                picoquic_set_log_level(cc_ctx->q_ctx[i], 1);
            }
        }
        /* Create the required links */
        for (int i = 0; ret == 0 && i < PICOQUIC_NS_NB_LINKS; i++) {
            ret = picoquic_ns_create_link(cc_ctx, spec, i);
        }
        if (spec->l4s_max > 0) {
            cc_ctx->packet_ecn_default = PICOQUIC_ECN_ECT_1;
        }
        /* Create the client contexts */
        if (spec->nb_connections > PICOQUIC_NS_MAX_CLIENTS) {
            ret = -1;
        }
        else {
            cc_ctx->nb_connections = spec->nb_connections;
            for (int i = 0; ret == 0 && i < cc_ctx->nb_connections; i++) {
                ret = picoquic_ns_create_client_ctx(cc_ctx, spec, i);
            }
        }
    }

    if (ret != 0 && cc_ctx != NULL) {
        picoquic_ns_delete_ctx(cc_ctx);
        cc_ctx = NULL;
    }

    return cc_ctx;
}

int picoquic_ns_incoming_packet(picoquic_ns_ctx_t* cc_ctx, int link_id)
{
    int ret = 0;
    /* dequeue packet from specified link */
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(cc_ctx->link[link_id],
        cc_ctx->simulated_time);

    /* TODO, but not yet: add management of CPU time, see picoquic_test_endpoint_t */
    /* For now, just submit the packet to the specified server.
     * The context id is set to the same value of the node id
     */
    if (packet != NULL) {
        int node_id = link_id;
        picoquic_cnx_t* first_cnx = NULL;
        ret = picoquic_incoming_packet_ex(cc_ctx->q_ctx[node_id], packet->bytes, packet->length,
            (struct sockaddr*)&packet->addr_from, (struct sockaddr*)&packet->addr_to, 0,
            packet->ecn_mark, &first_cnx, cc_ctx->simulated_time);
        free(packet);
    }
    return ret;
}

int picoquic_ns_prepare_packet(picoquic_ns_ctx_t* cc_ctx, int node_id, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();
    if (packet == NULL) {
        ret = -1;
    }
    else {
        int if_index = 0;
        picoquic_cnx_t* last_cnx = NULL;
        ret = picoquic_prepare_next_packet_ex(cc_ctx->q_ctx[node_id], cc_ctx->simulated_time,
            packet->bytes, sizeof(packet->bytes), &packet->length,
            &packet->addr_to, &packet->addr_from, &if_index, NULL, &last_cnx, NULL);

        if (ret == 0 && packet->length > 0) {
            /* TODO: if handling multiple links, the choice of outgoing link in the
             * depends on the source address, or if it is null on the destination
             * address.
             * In the initial implementation, just two nodes, so the destination is
             * always the other node.
             */
            int link_id = (node_id == 0) ? 1 : 0;
            if (packet->addr_from.ss_family == 0) {
                picoquic_store_addr(&packet->addr_from, (struct sockaddr*)&cc_ctx->addr[node_id]);
            }
            packet->ecn_mark = cc_ctx->packet_ecn_default;
            picoquictest_sim_link_submit(cc_ctx->link[link_id], packet, cc_ctx->simulated_time);
            *is_active = 1;
        }
        else {
            /* No packet to send, or other errors */
            free(packet);
        }
    }
    return ret;
}

int picoquic_ns_start_connection(picoquic_ns_ctx_t* cc_ctx, int cnx_id)
{
    int ret = 0;
    /* Create a client connection */
    cc_ctx->client_ctx[cnx_id]->cnx = picoquic_create_cnx(
        cc_ctx->q_ctx[1], cc_ctx->client_ctx[cnx_id]->icid, picoquic_null_connection_id,
        (struct sockaddr*)&cc_ctx->addr[0], cc_ctx->simulated_time,
        0, PICOQUIC_TEST_SNI, QUIC_PERF_ALPN, 1);

    if (cc_ctx->client_ctx[cnx_id]->cnx == NULL) {
        ret = -1;
    }
    else {
        picoquic_set_congestion_algorithm(cc_ctx->client_ctx[cnx_id]->cnx, cc_ctx->client_ctx[cnx_id]->cc_algo);
        picoquic_set_callback(cc_ctx->client_ctx[cnx_id]->cnx, quicperf_callback,
            cc_ctx->client_ctx[cnx_id]->quicperf_ctx);
        cc_ctx->client_ctx[cnx_id]->cnx->local_parameters.max_datagram_frame_size = 1532;
        ret = picoquic_start_client_cnx(cc_ctx->client_ctx[cnx_id]->cnx);
    }
    return ret;
}

int picoquic_ns_step(picoquic_ns_ctx_t* cc_ctx, int* is_active)
{
    int ret = 0;
    int link_id_next = -1;
    int node_id_next = -1;
    int cnx_id_next = -1;
    uint64_t t_next_action = UINT64_MAX;
    enum {
        no_action,
        link_departure,
        prepare_packet,
        start_connection
    } next_action = no_action;
    /* Check whether there is something to receive */
    for (int i = 0; i < PICOQUIC_NS_NB_LINKS; i++) {
        if (cc_ctx->link[i]->first_packet != NULL) {
            uint64_t t_arrival = picoquictest_sim_link_next_arrival(cc_ctx->link[i], t_next_action);
            if (t_arrival < t_next_action) {
                t_next_action = t_arrival;
                link_id_next = i;
                next_action = link_departure;
            }
        }
    }

    /* Check whether there is something to send */
    for (int i = 0; i < PICOQUIC_NS_NB_NODES; i++) {
        uint64_t t_next = picoquic_get_next_wake_time(cc_ctx->q_ctx[i], t_next_action);
        if (t_next < t_next_action) {
            t_next_action = t_next;
            node_id_next = i;
            next_action = prepare_packet;
        }
    }
    /* check whether there is a connection to start
    * the initial value of "next_cnx_start_time" is always 0,
    * since no packet is prepared or sent before the first connection starts.
     */
    if (cc_ctx->next_cnx_start_time < t_next_action) {
        for (int i = 0; i < cc_ctx->nb_connections; i++) {
            if (cc_ctx->client_ctx[i]->cnx == NULL &&
                cc_ctx->client_ctx[i]->start_time < t_next_action) {
                t_next_action = cc_ctx->client_ctx[i]->start_time;
                cnx_id_next = i;
                next_action = start_connection;
            }
        }
    }

    if (t_next_action > cc_ctx->simulated_time) {
        cc_ctx->simulated_time = t_next_action;
    }

    switch (next_action) {
    case link_departure:
        ret = picoquic_ns_incoming_packet(cc_ctx, link_id_next);
        *is_active = 1;
        break;
    case prepare_packet:
        ret = picoquic_ns_prepare_packet(cc_ctx, node_id_next, is_active);
        break;
    case start_connection:
        if ((ret = picoquic_ns_start_connection(cc_ctx, cnx_id_next)) == 0) {
            /* Reset the next connection start time. */
            *is_active = 1;
            cc_ctx->next_cnx_start_time = UINT64_MAX;
            for (int i = 0; i < cc_ctx->nb_connections; i++) {
                if (cc_ctx->client_ctx[i]->cnx == NULL &&
                    cc_ctx->client_ctx[i]->start_time < cc_ctx->next_cnx_start_time) {
                    cc_ctx->next_cnx_start_time = cc_ctx->client_ctx[i]->start_time;
                }
            }
        }
        break;
    case no_action:
    default:
        ret = -1;
        break;
    }
    return ret;
}

int picoquic_ns_is_finished(picoquic_ns_ctx_t* cc_ctx)
{
    int ret = 0;
    if (cc_ctx == NULL || cc_ctx->client_ctx[0] == NULL) {
        ret = -1;
    }
    else if (cc_ctx->client_ctx[0]->cnx != NULL) {
        if (picoquic_get_cnx_state(cc_ctx->client_ctx[0]->cnx) >= picoquic_state_disconnected) {
            ret = -1;
        }
    }
    else if (cc_ctx->simulated_time > cc_ctx->client_ctx[0]->start_time) {
        ret = -1;
    }
    return ret;
}

int picoquic_ns(picoquic_ns_spec_t* spec)
{
    int ret = 0;
    picoquic_ns_ctx_t* cc_ctx = picoquic_ns_create_ctx(spec);
    int nb_inactive = 0;

    if (cc_ctx == NULL) {
        ret = -1;
    }

    while (ret == 0) {
        int is_active = 0;
        ret = picoquic_ns_step(cc_ctx, &is_active);

        if (is_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
            if (nb_inactive > 512) {
                ret = -1;
                break;
            }
        }

        if (picoquic_ns_is_finished(cc_ctx) != 0) {
            break;
        }
    }

    /* TODO: check the completion. Should it be done there or inside each test? */
    if (ret == 0 && cc_ctx->simulated_time > spec->main_target_time) {
        ret = -1;
    }

    if (cc_ctx != NULL) {
        picoquic_ns_delete_ctx(cc_ctx);
    }
    return ret;
}
