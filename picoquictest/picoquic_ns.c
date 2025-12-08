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
#include "picoquictest_dualq.h"

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
* program it in the server side connection context.
* 
* The main advantages of this simulation are:
* - Running the actual picoquic code.
* - Operating in "virtual time", much faster than "real time".
* 
* We can simulate a link with a capacity and a latency varies over time. The
* API provides two ways to do that:
* 
* - either pick one of the predefines variation scenarios, such as `blackhole`
* - or provide an array of 
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
    picoquic_congestion_algorithm_t const* cc_algo;
    char const* cc_option_string;
    quicperf_ctx_t* quicperf_ctx;
    picoquic_connection_id_t icid;
    uint64_t seed_cwin;
    uint64_t seed_rtt;
} picoquic_ns_client_t;

typedef struct st_picoquic_ns_ctx_t {
    picoquic_quic_t* q_ctx[PICOQUIC_NS_NB_NODES];
    struct sockaddr_in addr[PICOQUIC_NS_NB_NODES];
    picoquictest_sim_link_t* link[PICOQUIC_NS_NB_LINKS];
    uint64_t simulated_time;
    int nb_connections;
    picoquic_ns_link_spec_t* vary_link_spec;
    int vary_link_is_user_provided;
    size_t vary_link_nb;
    uint64_t next_vary_link_time;
    size_t vary_link_index;
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
            if (cc_ctx->client_ctx[i] != NULL && cc_ctx->client_ctx[i]->cnx != NULL &&
                picoquic_compare_connection_id(&cnx->path[0]->first_tuple->p_remote_cnxid->cnx_id,
                    &cc_ctx->client_ctx[i]->cnx->path[0]->first_tuple->p_local_cnxid->cnx_id) == 0) {
                picoquic_set_congestion_algorithm_ex(cnx, cc_ctx->client_ctx[i]->cc_algo,
                    cc_ctx->client_ctx[i]->cc_option_string);
                if (cc_ctx->client_ctx[i]->seed_cwin > 0 &&
                    cc_ctx->client_ctx[i]->seed_rtt > 0) {
                    uint8_t* ip_addr;
                    uint8_t ip_addr_len;
                    picoquic_get_ip_addr((struct sockaddr*)&cc_ctx->addr[1], &ip_addr, &ip_addr_len);
                    picoquic_seed_bandwidth(cnx, cc_ctx->client_ctx[i]->seed_rtt,
                        cc_ctx->client_ctx[i]->seed_cwin, ip_addr, ip_addr_len);
                }
                
                ret = 0;
            }
        }
    }
    if (ret == 0) {
        /* set the server connection context */
        perf_ctx = quicperf_create_ctx(NULL, NULL);
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

int picoquic_ns_create_client_ctx(picoquic_ns_ctx_t* cc_ctx, picoquic_ns_spec_t* spec, int client_id, FILE* err_fd)
{
    int ret = 0;
    picoquic_ns_client_t* client_ctx = (picoquic_ns_client_t*)malloc(sizeof(picoquic_ns_client_t));

    if (client_ctx == NULL) {
        if (err_fd != NULL) {
            fprintf(err_fd, "Could not allocate memory.\n");
        }
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
            client_ctx->cc_option_string = spec->main_cc_options;
            client_ctx->seed_cwin = spec->seed_cwin;
            client_ctx->seed_rtt = spec->seed_rtt;
            scenario_text = spec->main_scenario_text;
        }
        else {
            client_ctx->start_time = spec->background_start_time;
            client_ctx->cc_algo = spec->background_cc_algo;
            client_ctx->cc_option_string = spec->background_cc_options;
            scenario_text = spec->background_scenario_text;
        }
        if ((client_ctx->quicperf_ctx = quicperf_create_ctx(scenario_text, err_fd)) == NULL) {
            if (err_fd != NULL) {
                fprintf(err_fd, "Could not create quicperf context.\n");
            }
            ret = -1;
        }
        else{
            /* Set log and trigger for media statistsics and file. */
            client_ctx->quicperf_ctx->stats_start = spec->media_stats_start;
            if (spec->qperf_log != NULL) {
                /* scenario requires a performance log */
                client_ctx->quicperf_ctx->report_file = picoquic_file_open(spec->qperf_log, "w");
                if (client_ctx->quicperf_ctx->report_file == NULL) {
                    if (err_fd != NULL) {
                        fprintf(err_fd, "Error opening qperf log file %s\n", spec->qperf_log);
                    }
                    ret = -1;
                }
            }
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
            if (client_ctx->quicperf_ctx->report_file != NULL) {
                (void)picoquic_file_close(client_ctx->quicperf_ctx->report_file);
                client_ctx->quicperf_ctx->report_file = NULL;
            }
            quicperf_delete_ctx(client_ctx->quicperf_ctx);
            client_ctx->quicperf_ctx = NULL;
        }
        free(client_ctx);
        cc_ctx->client_ctx[client_id] = NULL;
    }
}

/* Get picoquic_ns_link_spec_t array from parameters and model spec.
*/
int picoquic_ns_create_default_link_spec(picoquic_ns_ctx_t* cc_ctx, picoquic_ns_spec_t* spec, size_t nb_specs)
{
    int ret = 0;
    cc_ctx->vary_link_spec = (picoquic_ns_link_spec_t*)malloc(nb_specs * sizeof(picoquic_ns_link_spec_t));
    if (cc_ctx->vary_link_spec == NULL) {
        ret = -1;
    }
    else {
        memset(cc_ctx->vary_link_spec, 0, nb_specs * sizeof(picoquic_ns_link_spec_t));
        cc_ctx->vary_link_nb = nb_specs;
        for (size_t i = 0; i < nb_specs; i++) {
            if (spec->data_rate_in_gbps == 0) {
                cc_ctx->vary_link_spec[i].data_rate_in_gbps_down = 0.01;
            }
            else {
                cc_ctx->vary_link_spec[i].data_rate_in_gbps_down = spec->data_rate_in_gbps;
            }
            if (spec->data_rate_up_in_gbps == 0) {
                cc_ctx->vary_link_spec[i].data_rate_in_gbps_up = cc_ctx->vary_link_spec[i].data_rate_in_gbps_down;
            }
            else {
                cc_ctx->vary_link_spec[i].data_rate_in_gbps_up = spec->data_rate_up_in_gbps;
            }
            cc_ctx->vary_link_spec[i].latency = spec->latency;
            cc_ctx->vary_link_spec[i].jitter = spec->jitter;
            cc_ctx->vary_link_spec[i].is_wifi_jitter = spec->is_wifi_jitter;
            cc_ctx->vary_link_spec[i].queue_delay_max = spec->queue_delay_max;
            cc_ctx->vary_link_spec[i].l4s_max = spec->l4s_max;
        }
    }
    return ret;
}

int picoquic_ns_create_link_spec(picoquic_ns_ctx_t* cc_ctx, picoquic_ns_spec_t* spec)
{
    int ret = 0;

    if (spec->vary_link_nb > 0) {
        cc_ctx->vary_link_is_user_provided = 1;
        cc_ctx->vary_link_nb = spec->vary_link_nb;
        cc_ctx->vary_link_spec = spec->vary_link_spec;
    }
    else {
        switch (spec->link_scenario) {
        case link_scenario_none:
            ret = picoquic_ns_create_default_link_spec(cc_ctx, spec, 1);
            break;
        case link_scenario_black_hole:
            if ((ret = picoquic_ns_create_default_link_spec(cc_ctx, spec, 3)) == 0) {
                cc_ctx->vary_link_spec[0].duration = 2000000;
                cc_ctx->vary_link_spec[1].duration = 2000000;
                cc_ctx->vary_link_spec[2].duration = UINT64_MAX;
                cc_ctx->vary_link_spec[1].data_rate_in_gbps_down = 0;
                cc_ctx->vary_link_spec[1].data_rate_in_gbps_up = 0;
            }
            break;
        case link_scenario_drop_and_back:
            if ((ret = picoquic_ns_create_default_link_spec(cc_ctx, spec, 3)) == 0) {
                cc_ctx->vary_link_spec[0].duration = 1500000;
                cc_ctx->vary_link_spec[1].duration = 2000000;
                cc_ctx->vary_link_spec[2].duration = UINT64_MAX;
                cc_ctx->vary_link_spec[1].data_rate_in_gbps_down *= 0.5;
                cc_ctx->vary_link_spec[1].data_rate_in_gbps_up *= 0.5;
            }
            break;
        case link_scenario_low_and_up:
            if ((ret = picoquic_ns_create_default_link_spec(cc_ctx, spec, 2)) == 0) {
                cc_ctx->vary_link_spec[0].duration = 2500000;
                cc_ctx->vary_link_spec[0].data_rate_in_gbps_down *= 0.5;
                cc_ctx->vary_link_spec[0].data_rate_in_gbps_up *= 0.5;
                cc_ctx->vary_link_spec[1].duration = UINT64_MAX;
            }
            break;
        case link_scenario_wifi_fade:
            if ((ret = picoquic_ns_create_default_link_spec(cc_ctx, spec, 3)) == 0) {
                cc_ctx->vary_link_spec[0].duration = 1000000;
                cc_ctx->vary_link_spec[0].jitter = 999;
                cc_ctx->vary_link_spec[0].is_wifi_jitter = 1;
                cc_ctx->vary_link_spec[1].duration = 2000000;
                cc_ctx->vary_link_spec[1].data_rate_in_gbps_down *= 0.9;
                cc_ctx->vary_link_spec[1].data_rate_in_gbps_up *= 0.9;
                cc_ctx->vary_link_spec[1].is_wifi_jitter = 1;
                cc_ctx->vary_link_spec[1].jitter = 12000;
                cc_ctx->vary_link_spec[2].jitter = 999;
                cc_ctx->vary_link_spec[2].is_wifi_jitter = 1;
                cc_ctx->vary_link_spec[2].duration = UINT64_MAX;
            }
            break;
        case link_scenario_wifi_suspension:
            if ((ret = picoquic_ns_create_default_link_spec(cc_ctx, spec, 2)) == 0) {
                cc_ctx->vary_link_spec[0].duration = 1800000;
                cc_ctx->vary_link_spec[1].duration = 200000;
                cc_ctx->vary_link_spec[1].data_rate_in_gbps_down = 0;
                cc_ctx->vary_link_spec[1].data_rate_in_gbps_up = 0;
            }
            break;
        default:
            ret = -1;
            break;
        }
    }
    return ret;
}

int picoquic_ns_create_link(picoquic_ns_ctx_t* cc_ctx, int link_id)
{
    int ret = 0;
    picoquic_ns_link_spec_t* link_spec = &cc_ctx->vary_link_spec[0];
    double data_rate = (link_id == 0) ? link_spec->data_rate_in_gbps_up : link_spec->data_rate_in_gbps_down;
    uint64_t latency = link_spec->latency;
    if (data_rate == 0) {
        data_rate = 0.01; /* default to 10mbps */
    }
    if (latency == 0) {
        latency = 10000; /* default to 10ms */
    }
    if ((cc_ctx->link[link_id] = picoquictest_sim_link_create(data_rate, latency, NULL,
        link_spec->queue_delay_max, cc_ctx->simulated_time)) == NULL) {
        ret = -1;
    }
    else {
        cc_ctx->link[link_id]->nb_loss_in_burst = link_spec->nb_loss_in_burst;
        cc_ctx->link[link_id]->packets_between_losses = link_spec->packets_between_losses;
        cc_ctx->link[link_id]->packets_sent_next_burst = cc_ctx->link[link_id]->packets_sent +
            link_spec->packets_between_losses;
        if (link_spec->l4s_max > 0) {
            ret = dualq_configure(cc_ctx->link[link_id], link_spec->l4s_max);
        }
    }
    return ret;
}

int picoquic_ns_create_links(picoquic_ns_ctx_t* cc_ctx, picoquic_ns_spec_t* spec)
{
    /* first step is to create the scenarios */
    int ret = picoquic_ns_create_link_spec(cc_ctx, spec);

    /* next create the link with parameters of the first scenario */
    if (ret == 0) {
        for (int i = 0; ret == 0 && i < PICOQUIC_NS_NB_LINKS; i++) {
            ret = picoquic_ns_create_link(cc_ctx, i);
        }
    }

    /* The simulation will automatically execute the transition to
     * the first "vary_link_spec" value. */

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

    /* delete the link specifications */
    if (cc_ctx->vary_link_spec != NULL) {
        if (!cc_ctx->vary_link_is_user_provided) {
            free(cc_ctx->vary_link_spec);
        }
        cc_ctx->vary_link_spec = NULL;
        cc_ctx->vary_link_nb = 0;
    }
    /* and then free the context itself */
    free(cc_ctx);
}

picoquic_ns_ctx_t* picoquic_ns_create_ctx(picoquic_ns_spec_t* spec, FILE* err_fd)
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
            if (err_fd != NULL) {
                fprintf(err_fd, "Could not find the default server key and certs.\n");
            }
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
            if (err_fd != NULL) {
                fprintf(err_fd, "Could not create picoquic server context.\n");
            }
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
            if (err_fd != NULL) {
                fprintf(err_fd, "Could not create picoquic client context.\n");
            }
            ret = -1;
        }
        else {
            picoquic_set_default_pmtud_policy(cc_ctx->q_ctx[1], picoquic_pmtud_delayed);
        }
        if (spec->qlog_dir != NULL) {
            for (int i = 0; ret == 0 && i < 2; i++) {
                ret = picoquic_set_qlog(cc_ctx->q_ctx[i], spec->qlog_dir);
                picoquic_set_log_level(cc_ctx->q_ctx[i], 1);

                if (ret != 0 && err_fd != NULL) {
                    fprintf(err_fd, "Could not set qlog in dir %s\n", spec->qlog_dir);
                }
            }
        }
        /* Create the required links */
        if (ret == 0){
            ret = picoquic_ns_create_links(cc_ctx, spec);
            if (ret != 0 && err_fd != NULL) {
                fprintf(err_fd, "Could not create links.\n");
            }
        }
        if (spec->l4s_max > 0) {
            cc_ctx->packet_ecn_default = PICOQUIC_ECN_ECT_1;
        }
        /* Create the client contexts */
        if (spec->nb_connections > PICOQUIC_NS_MAX_CLIENTS || spec->nb_connections == 0) {
            ret = -1;
        }
        else {
            cc_ctx->nb_connections = spec->nb_connections;
            for (int i = 0; ret == 0 && i < cc_ctx->nb_connections; i++) {
                ret = picoquic_ns_create_client_ctx(cc_ctx, spec, i, err_fd);
                if (ret != 0 && err_fd != NULL) {
                    fprintf(err_fd, "Could not create client context [%d]\n", i);
                }
            }
        }
    }

    if (ret != 0 && cc_ctx != NULL) {
        picoquic_ns_delete_ctx(cc_ctx);
        cc_ctx = NULL;
    }

    return cc_ctx;
}

void picoquic_ns_packet_admission(picoquic_ns_ctx_t* cc_ctx, int link_id)
{
    picoquictest_sim_link_admit_pending(cc_ctx->link[link_id],
        cc_ctx->simulated_time);
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
        picoquic_set_congestion_algorithm_ex(cc_ctx->client_ctx[cnx_id]->cnx, cc_ctx->client_ctx[cnx_id]->cc_algo, cc_ctx->client_ctx[cnx_id]->cc_option_string);
        picoquic_set_callback(cc_ctx->client_ctx[cnx_id]->cnx, quicperf_callback,
            cc_ctx->client_ctx[cnx_id]->quicperf_ctx);
        cc_ctx->client_ctx[cnx_id]->cnx->local_parameters.max_datagram_frame_size = 1532;
        ret = picoquic_start_client_cnx(cc_ctx->client_ctx[cnx_id]->cnx);
    }
    return ret;
}

/* Simulate a variation in the state of a link. 
* The variation can be either a change in latency or delay, or a change in throughput.
* 
* When the variation happens, we want to recompute the delay and delivery time of
* the packets that are queued on the link, but we have a bit of a gray area for packets
* whose transmission has started already.
* 
* If the link is suspended, the latency becomes infinite. This means all
* packets not sent yet will be queued "forever".
* If the link is resumed, all the old packets are requeued at the new
* throughput and latency.
* 
* If the link is not fully blocked, we may have a little complication for handling
* the packets in transit. The simplest solution may be to just requeue every
* packet with the new parameter, but this does not account for packets
* that are "already sent". the modified rules would be:
* 
* - Consider all non delivered packets.
* - if the old arrival time is sooner than suspension plus
*   old latency, and also sooner than the new time, consider
*   that the packet is "in the air".
*   Leave it as is and do not increment the queue.
* - else, consider we are in requeing mode. Reset the arrival
*   time of this packet and all packets that follows.
* 
* The point of the these rule is to guarantee a complete ordering
* of delivery times.
*/
void picoquic_ns_simlink_reset(picoquictest_sim_link_t* link, double data_rate_in_gps, picoquic_ns_link_spec_t* vary_link_spec, uint64_t current_time)
{
    double pico_d = (data_rate_in_gps <= 0) ? 0 : (8000.0 / data_rate_in_gps);

    picoquictest_sim_packet_t* packet = link->first_packet;
    picoquictest_sim_packet_t* previous_packet = NULL;
    uint64_t latency_horizon = current_time + link->microsec_latency;

    /* Skip the packets that are "in transit" */
    while (packet != NULL && packet->arrival_time <= latency_horizon) {
        previous_packet = packet;
        packet = packet->next_packet;
    }
    /* Close the queue */
    if (previous_packet == NULL) {
        link->first_packet = NULL;
        link->last_packet = NULL;
    }
    else {
        previous_packet->next_packet = NULL;
        link->last_packet = previous_packet;
    }
    /* Requeue the other packets:
     * reset the queue time to current_time, i.e., after packets in transit are delivered.*/
    link->queue_time = current_time;
    /* reset the AQM, so it starts working from the current time. */
    if (link->aqm_state != NULL) {
        link->aqm_state->reset(link->aqm_state, link, current_time);
    }
    /* reset the value of the link parameters */
    pico_d *= (1.024 * 1.024); /* account for binary units */
    link->next_send_time = current_time;
    link->queue_time = current_time;
    link->picosec_per_byte = (uint64_t)pico_d;
    link->microsec_latency = vary_link_spec->latency;
    link->jitter = vary_link_spec->jitter;
    link->jitter_mode = (vary_link_spec->is_wifi_jitter) ? jitter_wifi : jitter_gauss;
    link->queue_delay_max = vary_link_spec->queue_delay_max;
    link->is_suspended = (data_rate_in_gps <= 0);
    link->nb_loss_in_burst = vary_link_spec->nb_loss_in_burst;
    link->packets_between_losses = vary_link_spec->packets_between_losses;
    link->packets_sent_next_burst = link->packets_sent + vary_link_spec->packets_between_losses;
    if (link->aqm_state != NULL) {
        link->aqm_state->reset(link->aqm_state, link, current_time);
    }


    /* Reschedule the next packets */
    while (packet != NULL) {
        picoquictest_sim_packet_t* next_packet = packet->next_packet;
        picoquictest_sim_link_submit(link, packet, current_time);
        packet = next_packet;
    }
}

/* If it is time for link state transition, apply the requested link changes,
* compute the next transition time, rotate the index in the link spec list.
*/

void picoquic_ns_vary_link(picoquic_ns_ctx_t* cc_ctx)
{
    picoquic_ns_link_spec_t* vary_link_spec = &cc_ctx->vary_link_spec[cc_ctx->vary_link_index];

    picoquic_ns_simlink_reset(cc_ctx->link[0], vary_link_spec->data_rate_in_gbps_up, vary_link_spec, cc_ctx->simulated_time);
    picoquic_ns_simlink_reset(cc_ctx->link[1], vary_link_spec->data_rate_in_gbps_down, vary_link_spec, cc_ctx->simulated_time);

    if (cc_ctx->vary_link_nb < 2) {
        cc_ctx->next_vary_link_time = UINT64_MAX;
    }
    else {
        if ((cc_ctx->next_vary_link_time = cc_ctx->simulated_time + vary_link_spec->duration) < cc_ctx->simulated_time) {
            /* manage potential integer overflow. */
            cc_ctx->next_vary_link_time = UINT64_MAX;
        }
        cc_ctx->vary_link_index++;
        if (cc_ctx->vary_link_index >= cc_ctx->vary_link_nb) {
            cc_ctx->vary_link_index = 0;
        }
    }
}

/* One simulation step -- TODO: add link variability.
 */

int picoquic_ns_step(picoquic_ns_ctx_t* cc_ctx, int* is_active)
{
    int ret = 0;
    int link_id_next = -1;
    int node_id_next = -1;
    int cnx_id_next = -1;
    uint64_t t_next_action = UINT64_MAX;
    enum {
        no_action,
        link_transition,
        link_departure,
        link_admission,
        prepare_packet,
        start_connection
    } next_action = no_action;

    /* check whether there is a link state change */
    if (cc_ctx->next_vary_link_time < t_next_action) {
        t_next_action = cc_ctx->next_vary_link_time;
        next_action = link_transition;
    }

    /* Check whether there is something to receive */
    for (int i = 0; i < PICOQUIC_NS_NB_LINKS; i++) {
        uint64_t t_admission = picoquictest_sim_link_next_admission(cc_ctx->link[i], cc_ctx->simulated_time, t_next_action);
        if (t_admission < t_next_action) {
            t_next_action = t_admission;
            link_id_next = i;
            next_action = link_admission;
        }
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
    case link_transition:
        picoquic_ns_vary_link(cc_ctx);
        break;
    case link_departure:
        ret = picoquic_ns_incoming_packet(cc_ctx, link_id_next);
        *is_active = 1;
        break;
    case link_admission:
        picoquic_ns_packet_admission(cc_ctx, link_id_next);
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

static int picoquic_ns_media_excluded(char const* media_excluded, char const* id)
{
    int is_excluded = 0;
    size_t id_len = strlen(id);
    while (*media_excluded != 0){
        size_t to_next_comma = 0;

        while (*media_excluded == ' ' || *media_excluded == '\t') {
            media_excluded++;
        }
        while (media_excluded[to_next_comma] != 0 && media_excluded[to_next_comma] != ',') {
            to_next_comma++;
        }
        if (to_next_comma == id_len && memcmp(media_excluded, id, id_len) == 0) {
            is_excluded = 1;
            break;
        }
        media_excluded += to_next_comma;
        if (*media_excluded == ',') {
            media_excluded++;
        }
    }
    return is_excluded;
}

int picoquic_ns_media_check(quicperf_ctx_t* quicperf_ctx, picoquic_ns_spec_t* spec, FILE* err_fd)
{
    int ret = 0;

    for (size_t i = 0; i < quicperf_ctx->nb_scenarios; i++) {
        if (quicperf_ctx->scenarios[i].media_type != quicperf_media_batch &&
            !picoquic_ns_media_excluded(spec->media_excluded, quicperf_ctx->scenarios[i].id)) {
            quicperf_stream_report_t* report = &quicperf_ctx->reports[i];
            if (report->nb_frames_received == 0) {
                if (err_fd != NULL) {
                    fprintf(stderr, "No frame received for media %zu (%s)\n",
                        i, quicperf_ctx->scenarios[i].id);
                }
                ret = -1;
                break;
            }
            else {
                if (spec->media_latency_average > 0) {
                    double average_delay = ((double)report->sum_delays) / report->nb_frames_received;
                    if (average_delay > (double)spec->media_latency_average) {
                        if (err_fd != NULL) {
                            fprintf(stderr, "Media %zu (%s), latency average %f, expected %"PRIu64"\n",
                                i, quicperf_ctx->scenarios[i].id, average_delay, spec->media_latency_average);
                        }
                        ret = -1;
                        break;
                    }
                }
                if (spec->media_latency_max > 0 && report->max_delays > spec->media_latency_max) {
                    if (err_fd != NULL) {
                        fprintf(stderr, "Media %zu (%s), latency max %"PRIu64", expected %"PRIu64"\n",
                            i, quicperf_ctx->scenarios[i].id, report->max_delays, spec->media_latency_max);
                    }
                    ret = -1;
                    break;
                }
            }
        }
    }

    return ret;
}

int picoquic_ns(picoquic_ns_spec_t* spec, FILE* err_fd)
{
    int ret = 0;
    picoquic_ns_ctx_t* cc_ctx = picoquic_ns_create_ctx(spec, err_fd);
    int nb_inactive = 0;

    if (cc_ctx == NULL) {
        if (err_fd != NULL) {
            fprintf(err_fd, "Cannot allocate simulation context.\n");
        }
        ret = -1;
    }
    while (ret == 0) {
        int is_active = 0;

        if ((ret = picoquic_ns_step(cc_ctx, &is_active)) != 0) {
            if (err_fd != NULL) {
                fprintf(err_fd, "Simulation fails at simulated time %" PRIu64 " after %d inactive steps, ret = %d(0x%x)\n",
                    cc_ctx->simulated_time, nb_inactive, ret, ret);
            }
        }

        if (is_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
            if (nb_inactive > 512) {
                if (err_fd != NULL) {
                    fprintf(err_fd, "Simulation stalls at simulated time %" PRIu64 " after %d inactive steps\n",
                        cc_ctx->simulated_time, nb_inactive);
                }
                ret = -1;
                break;
            }
        }

        if (picoquic_ns_is_finished(cc_ctx) != 0) {
            break;
        }
    }
    if (err_fd != NULL && ret != 0) {
        fprintf(err_fd, "Simulated time %" PRIu64 ", ret = %d(0x%x)\n",
            (cc_ctx!=NULL)?cc_ctx->simulated_time:0, ret, ret);
    }

    if (ret == 0 &&
        (cc_ctx->client_ctx[0]->cnx == NULL ||
        (cc_ctx->client_ctx[0]->cnx->cnx_state == picoquic_state_disconnected &&
            (cc_ctx->client_ctx[0]->cnx->local_error != 0 ||
                cc_ctx->client_ctx[0]->cnx->remote_error != 0)))) {
        if (err_fd != NULL) {
            if (cc_ctx->client_ctx[0]->cnx == NULL) {
                fprintf(err_fd, "Connection was deleted before simulated time %" PRIu64 "\n",
                    cc_ctx->simulated_time);
            }
            else {
                fprintf(err_fd, "Connection was disconnected before simulated time %" PRIu64 ", local err: %" PRIu64", remote err: %" PRIu64 "\n",
                    cc_ctx->simulated_time, cc_ctx->client_ctx[0]->cnx->local_error, cc_ctx->client_ctx[0]->cnx->remote_error);
            }
        }
        ret = -1;
    }

    /* TODO: check the completion. Should it be done there or inside each test? */
    if (ret == 0 && cc_ctx->simulated_time > spec->main_target_time) {
        if (err_fd != NULL) {
            fprintf(err_fd, "Simulated time %" PRIu64 ", expected %" PRIu64 "\n",
                cc_ctx->simulated_time, spec->main_target_time);
        }
        ret = -1;
    }

    if (ret == 0 && cc_ctx->client_ctx[0] != NULL) {
        ret = picoquic_ns_media_check(cc_ctx->client_ctx[0]->quicperf_ctx, spec, err_fd);
    }

    if (cc_ctx != NULL) {
        picoquic_ns_delete_ctx(cc_ctx);
    }
    return ret;
}
