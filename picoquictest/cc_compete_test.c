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
#include "tls_api.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "quicperf.h"
#include "logreader.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "qlog.h"

/* Congestion compete test.
* These tests measure what happens when multiple connections fight for the same
* resource. The typical scenario involves connections with lots of data to
* send, with a duration sufficient to test congestion control mechanisms.
* An example would be testing BBR against itself, against Cubic, and against Reno.
* We will consider a "connection under test", and treat the other connections
* as "background".
*
* We are not aiming for an exact sharing between the competing connections, but we
* would like to verify that "nobody starves". The "main" connection should not
* get a reasonable share of the bandwidth, say at least 25%, and it should also
* not get an excessive share, say no more than 80%. (Of course these numbers
* should not be hardcoded.)
*
* We now that effects like "latecomer advantage" may favor a new connection
* over the existing ones. We need to be able to program scenarios in which the
* connection hunder test starts either before or after the background connection.
*
* The first priority is to consider "duels" between the tested connection and the
* background connections. However, we may want to try scenarios with more than
* two connections.
*
* The simulation follows the model established for the "stress" tests: single
* client context, single server context. All connections will run the
* "test" protocol. The background connections will run a "high load"
* scenario, the test connection will use a specific scenario. The simulation
* will manage links from and two server, shared by all clients. Demuxing
* will be per CID. The typical run time will be:
* - start
*     - set the configuration.
*  - on a loop
*     - if time has come, start a required connection
*     - simulate arrival and departure of packets
*     - on packet arrival, do the usual test protocol processing.
*     - if the client has sent/received all its data, exit the
*       simulation.
*     - also exit if this takes too long.
*  - after the loop:
*     - verify that the client scenario was executed properly.
* 
* Can we use "qperf" as the protocol? It is designed for exactly that purpose...
*/
#define MAX_CC_COMPETE_CLIENTS 5
#define QUIC_PERF_ALPN "perf"

typedef struct st_cc_compete_client_t {
    picoquic_cnx_t* cnx;
    picoquic_congestion_algorithm_t* cc_algo;
} cc_compete_client_t;

typedef struct st_cc_compete_ctx_t {
    picoquic_quic_t * qclient;
    picoquic_quic_t* qserver;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    picoquictest_sim_link_t* c_to_s_link;
    picoquictest_sim_link_t* s_to_c_link;
    uint64_t simulated_time;
    int nb_connections;
    cc_compete_client_t* client_ctx[MAX_CC_COMPETE_CLIENTS];
} cc_compete_ctx_t;

typedef struct st_cc_compete_test_spec_t {
    uint64_t main_start_time;
    test_api_stream_desc_t* test_scenario;
    size_t size_test_scenario;
} cc_compete_test_spec_t;

/* The cc_compete server is a quicperf server. However, we want to intercept
* the creation of server side connection and ensure that they are using the
* desired congestion control algorithm. We ensure that by setting this
* default callback function for the server context. When a new connection
* arrives, the server uses the "cc_compete" context to find the matching
* client connection, discover the desired congestion algorithm, and
* program it in the server side connection context
 */
int cc_compete_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    cc_compete_ctx_t* cc_ctx;
    quicperf_ctx_t* perf_ctx = NULL;

    if (callback_ctx != picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        /* Unexpected.  W return an error. The server will close that connection. */
        picoquic_close(cnx, QUICPERF_ERROR_INTERNAL_ERROR);
        ret = -1;
    }
    else {
        cc_ctx = (cc_compete_ctx_t*)callback_ctx;
        ret = -1; /* will reset to zero if find a matching client */
        for (int i = 0; i < cc_ctx->nb_connections; i++) {
            if (picoquic_compare_connection_id(&cnx->path[0]->p_remote_cnxid->cnx_id,
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

cc_compete_ctx_t* cc_compete_create_ctx()
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_client_cert_store_file[512];
    cc_compete_ctx_t* cc_ctx = (cc_compete_ctx_t*)malloc(sizeof(cc_compete_ctx_t));
    if (cc_ctx == NULL) {
        return cc_ctx;
    }

    memset(cc_ctx, 0, sizeof(cc_ctx));
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

    if (ret == 0) {
        /* Create server context */
        cc_ctx->qserver = picoquic_create(
            MAX_CC_COMPETE_CLIENTS,
            test_server_cert_file,
            test_server_key_file,
            NULL,
            QUIC_PERF_ALPN,
            cc_compete_server_callback,
            (void*) cc_ctx,
            NULL,
            NULL,
            NULL,
            cc_ctx->simulated_time,
            &cc_ctx->simulated_time,
            NULL,
            NULL,
            NULL);
        /* Create client context */
        cc_ctx->qserver = picoquic_create(
            MAX_CC_COMPETE_CLIENTS,
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
            NULL);
        /* Create the required links */
    }
}