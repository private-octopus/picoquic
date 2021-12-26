/*
* Author: Christian Huitema
* Copyright (c) 2021, Private Octopus, Inc.
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

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic_binlog.h"
#include "csv.h"
#include "qlog.h"
#include "autoqlog.h"
#include "picoquic_logger.h"
#include "performance_log.h"
#include "picoquictest.h"


/* Very high latency test. This requires relaxing the handshake timer, so that it covers
 * at least one rtt.
 */
static int high_latency_one(picoquic_congestion_algorithm_t* ccalgo,
    test_api_stream_desc_t* scenario, size_t sizeof_scenario,
    uint64_t max_completion_time, uint64_t latency, uint64_t mbps_up,
    uint64_t mbps_down, uint64_t jitter, int has_loss, int do_preemptive, int seed_bw)
{
    uint64_t simulated_time = 0;
    uint64_t picoseq_per_byte_up = (1000000ull * 8) / mbps_up;
    uint64_t picoseq_per_byte_down = (1000000ull * 8) / mbps_down;
    picoquic_tp_t client_parameters;
    picoquic_tp_t server_parameters;
    picoquic_connection_id_t initial_cid = { {0x1a, 0x7e, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = 0;

    initial_cid.id[2] = ccalgo->congestion_algorithm_number;
    initial_cid.id[3] = (mbps_up > 0xff) ? 0xff : (uint8_t)mbps_up;
    initial_cid.id[4] = (mbps_down > 0xff) ? 0xff : (uint8_t)mbps_down;
    initial_cid.id[5] = (latency > 16000000) ? 0xff : (uint8_t)(latency / 100000);
    initial_cid.id[6] = (jitter > 255000) ? 0xff : (uint8_t)(jitter / 1000);
    initial_cid.id[7] = (has_loss) ? 0x30 : 0x00;
    if (seed_bw) {
        initial_cid.id[7] |= 0x80;
    }
    if (do_preemptive) {
        initial_cid.id[7] ^= 0x0f;
    }

    memset(&client_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&client_parameters, 1);
    client_parameters.enable_time_stamp = 3;
    memset(&server_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&server_parameters, 0);
    server_parameters.enable_time_stamp = 3;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, &client_parameters, &server_parameters, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Simulate satellite links: 250 mbps, 300ms delay in each direction */
    /* Set the congestion algorithm to specified value. Also, request a packet trace */
    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
        picoquic_set_preemptive_repeat_policy(test_ctx->qserver, do_preemptive);
        picoquic_set_preemptive_repeat_per_cnx(test_ctx->cnx_client, do_preemptive);

        test_ctx->c_to_s_link->jitter = jitter;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_up;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_down;
        test_ctx->s_to_c_link->jitter = jitter;
        test_ctx->stream0_flow_release = 1;
        test_ctx->immediate_exit = 1;

        if (seed_bw) {
            uint8_t* ip_addr;
            uint8_t ip_addr_length;
            uint64_t estimated_rtt = 2 * latency;
            uint64_t estimated_bdp = (125000ull * mbps_up) * estimated_rtt / 1000000ull;
            picoquic_get_ip_addr((struct sockaddr*)&test_ctx->server_addr, &ip_addr, &ip_addr_length);

            picoquic_seed_bandwidth(test_ctx->cnx_client, estimated_rtt, estimated_bdp,
                ip_addr, ip_addr_length);
        }

        picoquic_cnx_set_pmtud_required(test_ctx->cnx_client, 1);

        /* Set the binary log on the server side */
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;

        /* set the binary log on the client side */
        picoquic_set_binlog(test_ctx->qclient, ".");
        test_ctx->qclient->use_long_log = 1;
        /* Since the client connection was created before the binlog was set, force log of connection header */
        binlog_new_connection(test_ctx->cnx_client);

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                scenario, sizeof_scenario, 0, (has_loss) ? 0x10000000 : 0, 0, 2 * latency, max_completion_time);
        }

        if (ret == 00 && do_preemptive) {
            DBG_PRINTF("Preemptive repeats: %" PRIu64, test_ctx->cnx_client->nb_preemptive_repeat);
            if (test_ctx->cnx_client->nb_preemptive_repeat == 0) {
                ret = -1;
            }
        }
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Basic test. Just verify that the handshake completes, and that a small
 * document can be downloaded
 */

static test_api_stream_desc_t hilat_scenario_basic[] = {
    { 4, 0, 257, 2000 }
};

int high_latency_basic_test()
{
    /* Simple test. */
    uint64_t latency = 5000000;
    uint64_t expected_completion = latency*7;

    return high_latency_one(picoquic_newreno_algorithm, 
        hilat_scenario_basic, sizeof(hilat_scenario_basic),
        expected_completion, latency, 10, 10, 0, 0, 0, 0);
}


static test_api_stream_desc_t hilat_scenario_10mb[] = {
    { 4, 0, 257, 1000000 },
    { 8, 0, 257, 1000000 },
    { 16, 0, 257, 1000000 },
    { 20, 0, 257, 1000000 },
    { 24, 0, 257, 1000000 },
    { 28, 0, 257, 1000000 },
    { 32, 0, 257, 1000000 },
    { 36, 0, 257, 1000000 },
    { 40, 0, 257, 1000000 }
};

/* Transfer test, 10MB file over a 10 MB link, using BBR.
 * In theory, this should require 1 RTT for handshake, then 1RTT for
 * requesting the file and 8 seconds for transferring it. But the
 * connection will not reach full bandwidth before going out
 * of slow start, so we can expect a much longer time.
 * 
 * The first iteration of this test surfaced a bug in the
 * way hystart tests for 'excessive" delays. There was some leftover
 * code to set a tight delay bound in long delay links, which
 * cause hystart to exit too soon.
 * 
 * TODO: in both BBR and Cubic, the congestion remains in slow start
 * for the all duration of the 10MB transfer. Should use a bigger
 * value!
 */

int high_latency_bbr_test()
{
    uint64_t latency = 5000000;
    uint64_t expected_completion = 63600000;

    return high_latency_one(picoquic_bbr_algorithm,
        hilat_scenario_10mb, sizeof(hilat_scenario_10mb),
        expected_completion, latency, 10, 10, 0, 0, 0, 0);
}

int high_latency_cubic_test()
{
    /* Simple test. */
    uint64_t latency = 5000000;
    uint64_t expected_completion = 63600000;

    return high_latency_one(picoquic_bbr_algorithm,
        hilat_scenario_10mb, sizeof(hilat_scenario_10mb),
        expected_completion, latency, 10, 10, 0, 0, 0, 0);
}

#if 0
int high_latency_seeded_test()
{
    /* Simulate remembering RTT and BW from previous connection */
    return high_latency_one(picoquic_bbr_algorithm, 100000000, 4800000, 250, 3, 0, 0, 0, 1);
}

int high_latency_loss_test()
{
    /* Should be less than 10 sec per draft etosat. */
    return high_latency_one(picoquic_bbr_algorithm, 100000000, 8000000, 250, 3, 0, 1, 0, 0);
}

int high_latency_preemptive_test()
{
    /* Variation of the loss test, using preemptive repeat*/
    /* Should be less than 10 sec per draft etosat.  */
    return high_latency_one(picoquic_bbr_algorithm, 100000000, 7000000, 250, 3, 0, 1, 1, 0);
}

int high_latency_jitter_test()
{
    /* Should be less than 7 sec per draft etosat. */
    return high_latency_one(picoquic_bbr_algorithm, 100000000, 6200000, 250, 3, 3000, 0, 0, 0);
}

int high_latency_medium_test()
{
    /* Should be less than 20 sec per draft etosat. */
    return high_latency_one(picoquic_bbr_algorithm, 100000000, 18000000, 50, 10, 0, 0, 0, 0);
}

int high_latency_small_test()
{
    /* Should be less than 85 sec per draft etosat. */
    return high_latency_one(picoquic_bbr_algorithm, 100000000, 81000000, 10, 2, 0, 0, 0, 0);
}

int high_latency_small_up_test()
{
    /* Should be less than 420 sec per draft etosat. */
    return high_latency_one(picoquic_bbr_algorithm, 100000000, 400000000, 2, 10, 0, 0, 0, 0);
}

int high_latency_cubic_test()
{
    /* Should be less than 7 sec per draft etosat, but cubic is much slower */
    return high_latency_one(picoquic_cubic_algorithm, 100000000, 11000000, 250, 3, 0, 0, 0, 0);
}

int high_latency_cubic_loss_test()
{
    /* Should be less than 10 sec per draft etosat, but cubic is a bit slower */
    return high_latency_one(picoquic_cubic_algorithm, 100000000, 12100000, 250, 3, 0, 1, 0, 0);
}
#endif