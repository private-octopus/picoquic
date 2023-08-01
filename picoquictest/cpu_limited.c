/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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
#include <inttypes.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "picoquic_binlog.h"
#include "logreader.h"
#include "qlog.h"

/* Add a series of tests to study the behavior of cpu-limited clients.
* This requires simulating clients that have cpu limitations, such
* as only being able to proceed a set number of messages per second.
* 
* The main effort is to modify the simulator to keep track of the
* "software load" of a node. The simulator interacts with the code
* through two APIs: prepare a packet to send; and, receive a packet.
* We assume that each of these calls will take some time, because
* it includes CPU processing. The simulation needs to maintain a
* "node readiness" clock, so that the node only becomes available
* some time after performing an action. Then, we do the following:
* 
* - On the "prepare packet" side, only consider the client ready
*   if time is large than the next ready time and also larger
*   than the next clock readiness time. Increase the next ready
*   time if a packet is successfully processed (but not if the
*   prepare packet call returns "no action").
* 
* - On the "receive packet" side, only accept a packet if the
*   arrival time is after the the next ready time. If it is not,
*   queue the packet in an "arrival queue", and drop it if the
*   arrival queue is over some limit. Increase the next ready
*   time after the packet is processed
*
* We test this configuration with a couple of scenarios.
*/

typedef struct st_limited_test_config_t {
    uint8_t test_id;
    picoquic_congestion_algorithm_t* ccalgo;
    uint64_t incoming_cpu_time;
    uint64_t prepare_cpu_time;
    size_t packet_queue_max;
    uint64_t max_completion_time;
} limited_test_config_t;

static test_api_stream_desc_t test_scenario_limited[] = {
#if 1
    { 4, 0, 257, 1000000 },
    { 8, 0, 257, 1000000 }
#else
    { 4, 0, 257, 1000000 },
    { 8, 0, 257, 1000000 },
    { 12, 0, 257, 1000000 },
    { 16, 0, 257, 1000000 }
#endif
};

int limited_client_test_one(limited_test_config_t * config)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x11, 0x01, 0xc1, 0x1e, 0x44, 0, 0, 0}, 8 };
    int ret;

    initial_cid.id[5] = config->test_id;


    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the congestion algorithm and endpoint limits to specified value. */
    if (ret == 0) {

        picoquic_set_default_congestion_algorithm(test_ctx->qserver, config->ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, config->ccalgo);
        test_ctx->client_endpoint.incoming_cpu_time = config->incoming_cpu_time;
        test_ctx->client_endpoint.prepare_cpu_time = config->prepare_cpu_time;
        test_ctx->client_endpoint.packet_queue_max = config->packet_queue_max;
        test_ctx->qserver->use_long_log = 1;
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qclient->use_long_log = 1;
        picoquic_set_binlog(test_ctx->qclient, ".");
        binlog_new_connection(test_ctx->cnx_client);

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_limited, sizeof(test_scenario_limited), 0, 0, 0, 20000, config->max_completion_time);
    }

    /* Free the resource, which will close the log file.
    */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

static void limited_config_set_default( limited_test_config_t* config, uint8_t test_id)
{
    memset(config, 0, sizeof(config));
    config->test_id = test_id;
    config->ccalgo = picoquic_newreno_algorithm;
    config->incoming_cpu_time = 2000;
    config->prepare_cpu_time = 2000;
    config->packet_queue_max = 16;
}

int limited_reno_test()
{
    limited_test_config_t config;
    limited_config_set_default(&config, 1);
    config.ccalgo = picoquic_newreno_algorithm;
    config.max_completion_time = 3750000;

    return limited_client_test_one(&config);
}

int limited_cubic_test()
{
    limited_test_config_t config;
    limited_config_set_default(&config, 2);
    config.ccalgo = picoquic_cubic_algorithm;
    config.max_completion_time = 3700000;

    return limited_client_test_one(&config);
}

int limited_bbr_test()
{
    limited_test_config_t config;
    limited_config_set_default(&config, 3);
    config.ccalgo = picoquic_bbr_algorithm;
    config.max_completion_time = 3700000;

    return limited_client_test_one(&config);
}