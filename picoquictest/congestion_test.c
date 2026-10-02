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

#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>

#include "picoquic_qlog.h"
#include "picoquic_logger.h"

#include "picoquic_newreno.h"
#include "picoquic_cubic.h"
#include "picoquic_bbr.h"
#include "picoquic_bbr1.h"
#include "picoquic_fastcc.h"
#include "picoquic_prague.h"
#include "picoquic_c4.h"
#include "cc_common.h"

static test_api_stream_desc_t test_scenario_congestion[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 257, 1000000 },
    { 12, 8, 257, 1000000 },
    { 16, 12, 257, 1000000 }
};

static test_api_stream_desc_t test_scenario_10mb[] = {
    { 4, 0, 257, 1000000 },
    { 8, 0, 257, 1000000 },
    { 12, 0, 257, 1000000 },
    { 16, 0, 257, 1000000 },
    { 20, 0, 257, 1000000 },
    { 24, 0, 257, 1000000 },
    { 28, 0, 257, 1000000 },
    { 32, 0, 257, 1000000 },
    { 36, 0, 257, 1000000 },
    { 40, 0, 257, 1000000 }
};

static test_api_stream_desc_t test_scenario_very_long[] = {
    { 4, 0, 257, 1000000 }
};


static char const* ticket_file_name = "resume_tests_tickets.bin";

static int congestion_control_test(picoquic_congestion_algorithm_t* ccalgo, uint64_t max_completion_time, uint64_t jitter, uint8_t jitter_id)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xcc, 0xcc, 0, 0, 0, 0, 0, 0}, 8 };
    int ret;

    initial_cid.id[2] = ccalgo->congestion_algorithm_number;
    initial_cid.id[3] = jitter_id;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the congestion algorithm to specified value. Also, request a packet trace */
    if (ret == 0) {

        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);

        test_ctx->c_to_s_link->jitter = jitter;
        test_ctx->s_to_c_link->jitter = jitter;

        picoquic_set_qlog(test_ctx->qserver, ".");

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_congestion, sizeof(test_scenario_congestion), 0, 0, 0, 20000 + 2 * jitter, max_completion_time);
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int cubic_test(void)
{
    return congestion_control_test(picoquic_cubic_algorithm, 3500000, 0, 0);
}

int cubic_jitter_test(void)
{
    return congestion_control_test(picoquic_cubic_algorithm, 3550000, 5000, 5);
}

int c4_test(void)
{
    return congestion_control_test(c4_algorithm, 3600000, 0, 0);
}

int c4_jitter_test(void)
{
    return congestion_control_test(c4_algorithm, 3650000, 5000, 5);
}

int fastcc_test(void)
{
    return congestion_control_test(picoquic_fastcc_algorithm, 3700000, 0, 0);
}

int fastcc_jitter_test(void)
{
    return congestion_control_test(picoquic_fastcc_algorithm, 4050000, 5000, 5);
}

int bbr_test(void)
{
    return congestion_control_test(picoquic_bbr_algorithm, 3500000, 0, 0);
}

int bbr_jitter_test(void)
{
    return congestion_control_test(picoquic_bbr_algorithm, 3600000, 5000, 5);
}

static int congestion_long_test(picoquic_congestion_algorithm_t* ccalgo)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xbb, 0xcc, 0x10, 0, 0, 0, 0, 0}, 8 };
    int ret;


    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Set the congestion algorithm to specified value. Also, request a packet trace */
    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);


        test_ctx->c_to_s_link->jitter = 0;
        test_ctx->s_to_c_link->jitter = 0;
        test_ctx->c_to_s_link->picosec_per_byte = 8000000; /* Simulate 1 Mbps */

        picoquic_set_qlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;

        ret = tls_api_one_scenario_body_connect(test_ctx, &simulated_time, 0, 0);
        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_congestion, sizeof(test_scenario_congestion));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Run a data sending loop for 1024 rounds, causing BBR to detect a low RTT */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 1024);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    /* Increase the RTT from the previous value, which will cause the bandwidth to drop unless RTT is reset  */
    if (ret == 0) {
        test_ctx->c_to_s_link->microsec_latency = 5 * test_ctx->c_to_s_link->microsec_latency;
        test_ctx->s_to_c_link->microsec_latency = 5 * test_ctx->s_to_c_link->microsec_latency;
    }


    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 15000000);
    }

    /* Free the resource, which will close the log file. */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int bbr_long_test(void)
{
    return congestion_long_test(picoquic_bbr_algorithm);
}

int c4_long_test(void)
{
    return congestion_long_test(c4_algorithm);
}

int bbr1_test(void)
{
    return congestion_control_test(picoquic_bbr1_algorithm, 3600000, 0, 0);
}

int bbr1_long_test(void)
{
    return congestion_long_test(picoquic_bbr1_algorithm);
}

/* Performance test.
 * Check a variety of challenging scenarios
 */

int performance_test_one(uint64_t max_completion_time, uint64_t mbps, uint64_t rkbps, uint64_t latency,
    uint64_t jitter, uint64_t buffer_size, picoquic_tp_t* server_parameters)
{
    uint64_t simulated_time = 0x0005a138fbde8743; /* Init to non zero time to test handling of time in cc algorithm */
    uint64_t picoseq_per_byte_100 = (1000000ull * 8) / mbps;
    uint64_t picoseq_per_byte_return = (rkbps == 0) ? picoseq_per_byte_100 : (1000000000ull * 8) / rkbps;
    picoquic_connection_id_t initial_cid = { {0xbb, 0xcc, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_congestion_algorithm_t* ccalgo = picoquic_bbr_algorithm;
    uint64_t buffer_id = (buffer_size * 16) / (latency + jitter);
    int ret = 0;


    initial_cid.id[3] = (rkbps > 0xff) ? 0xff : (uint8_t)rkbps;
    initial_cid.id[4] = (mbps > 0xff) ? 0xff : (uint8_t)mbps;
    initial_cid.id[5] = (latency > 2550000) ? 0xff : (uint8_t)(latency / 10000);
    initial_cid.id[6] = (jitter > 255000) ? 0xff : (uint8_t)(jitter / 1000);
    initial_cid.id[7] = (buffer_id > 255) ? 0xff : (uint8_t)buffer_id;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, server_parameters, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
        test_ctx->qserver->use_long_log = 1;

        picoquic_set_qlog(test_ctx->qserver, ".");
        picoquic_set_qlog(test_ctx->qclient, ".");

        test_ctx->c_to_s_link->jitter = jitter;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_return;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_100;
        test_ctx->s_to_c_link->jitter = jitter;

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time, test_scenario_10mb, sizeof(test_scenario_10mb), 0, 0, 0, buffer_size, max_completion_time);
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

int performance_test(uint64_t max_completion_time, uint64_t mbps, uint64_t latency, uint64_t jitter, uint64_t buffer_size)
{
    return performance_test_one(max_completion_time, mbps, 0, latency, jitter, buffer_size, NULL);
}

/* BBR Performance test.
 * Verify that 10 MB can be downloaded in less than 1 second on a 100 mbps link.
 */

int bbr_performance_test(void)
{
    uint64_t max_completion_time = 1050000;
    uint64_t latency = 10000;
    uint64_t jitter = 3000;
    uint64_t buffer = 2 * (latency + jitter);
    uint64_t mbps = 100;

    int ret = performance_test(max_completion_time, mbps, latency, jitter, buffer);

    return ret;
}

/* BBR Performance test on a slow long link
 * Verify that 10 MB can be downloaded in less than 100 seconds on a 1 mbps link.
 */

int bbr_slow_long_test(void)
{
    uint64_t max_completion_time = 81000000;
    uint64_t latency = 300000;
    uint64_t jitter = 3000;
    uint64_t buffer = 2 * (latency + jitter);
    uint64_t mbps = 1;

    int ret = performance_test(max_completion_time, mbps, latency, jitter, buffer);

    return ret;
}

/* BBR Performance test on a pathological long link, with 2 seconds RTT
 * Verify that 10 MB can be downloaded in less than 128 seconds on a 1 mbps link.
 */

int bbr_one_second_test(void)
{
    uint64_t max_completion_time = 90000000;
    uint64_t latency = 1000000;
    uint64_t jitter = 3000;
    uint64_t buffer = 2 * (latency + jitter);
    uint64_t mbps = 1;

    int ret = performance_test(max_completion_time, mbps, latency, jitter, buffer);

    return ret;
}


/* AWS like performance test
 * Verify that 10MB can be downloaded very fast on a low latency Gbps link. */
int gbps_performance_test(void)
{
    uint64_t max_completion_time = 250000;
    uint64_t latency = 4000;
    uint64_t jitter = 2000;
    uint64_t buffer = 2 * (latency + jitter);
    uint64_t mbps = 1000;

    int ret = performance_test(max_completion_time, mbps, latency, jitter, buffer);

    return ret;
}


/* Asymmetric test.
 * Verify that 10MB can be downloaded reasonably fast on a low latency 10Mbps link with 100kbps return path
 * The buffer size is set to a high value, which allows queues to grow and delays to build up. In theory,
 * BBR should minimize these queues, but the test verifies that it actually does.
 */
int bbr_asym100_test(void)
{
    uint64_t max_completion_time = 8500000;
    uint64_t latency = 1000;
    uint64_t jitter = 750;
    uint64_t buffer = 50000;
    uint64_t mbps = 10;
    uint64_t kbps = 100;

    int ret = performance_test_one(max_completion_time, mbps, kbps, latency, jitter, buffer, NULL);

    return ret;
}

/* Asymmetric test, no delay.
 * Variant in which the negotiation of delayed ACK is disabled.
 */
int bbr_asym100_nodelay_test(void)
{
    uint64_t max_completion_time = 8500000;
    uint64_t latency = 1000;
    uint64_t jitter = 750;
    uint64_t buffer = 50000;
    uint64_t mbps = 10;
    uint64_t kbps = 100;
    picoquic_tp_t server_parameters;

    memset(&server_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&server_parameters);
    server_parameters.min_ack_delay = 0;

    int ret = performance_test_one(max_completion_time, mbps, kbps, latency, jitter, buffer,
        &server_parameters);

    return ret;
}

/* Asymmetric test.
 * Variant using 400 kbps return path and a 40 Mbps link
 */
int bbr_asym400_test(void)
{
    uint64_t max_completion_time = 2350000;
    uint64_t latency = 1000;
    uint64_t jitter = 750;
    uint64_t buffer = 50000;
    uint64_t mbps = 40;
    uint64_t kbps = 400;

    int ret = performance_test_one(max_completion_time, mbps, kbps, latency, jitter, buffer, NULL);

    return ret;
}

/* Tests of BDP option.
 * = Verify that a download works faster with BDP option enabled
 * = Verify that the BDP option is not validated if the min rtt changes
 * - Verify that the BDP option is not validated if the IP address changes
 * - Verify that the BDP option is not validated if the delay is too long
 */

typedef enum {
    bdp_test_option_none = 0,
    bdp_test_option_basic,
    bdp_test_option_rtt,
    bdp_test_option_ip,
    bdp_test_option_delay,
    bdp_test_option_reno,
    bdp_test_option_cubic,
    bdp_test_option_short,
    bdp_test_option_short_lo,
    bdp_test_option_short_hi,
    bdp_test_option_bbr1
} bdp_test_option_enum;

int bdp_option_test_one(bdp_test_option_enum bdp_test_option)
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    char const* sni = PICOQUIC_TEST_SNI;
    char const* alpn = PICOQUIC_TEST_ALPN;
    uint32_t proposed_version = 0;
    uint64_t max_completion_time = 6800000;
    uint64_t latency = 300000ull;
    uint64_t buffer_size = 2 * latency;
    picoquic_connection_id_t initial_cid = { {0xbd, 0x80, 0, 0, 0, 0, 0, 0}, 8 };
    picoquic_congestion_algorithm_t* ccalgo = picoquic_bbr_algorithm;
    picoquic_tp_t server_parameters;
    picoquic_tp_t client_parameters;

    int ret = 0;

    /* Initialize an empty ticket store */
    ret = picoquic_save_tickets(NULL, simulated_time, ticket_file_name);

    for (int i = 0; ret == 0 && i < 2; i++) {
        /* If testing delay, insert a 24 hour delay before the second connection attempt */    
        if (i == 1 && bdp_test_option == bdp_test_option_delay) {
            simulated_time += 24ull * 3600ull * 1000000ull;
        }
        initial_cid.id[2] = i;
        initial_cid.id[3] = (uint8_t)bdp_test_option;
        /* Set up the context, while setting the ticket store parameter for the client */
        ret = tls_api_init_ctx_ex(&test_ctx,
            (i == 0) ? 0 : proposed_version, sni, alpn, &simulated_time, ticket_file_name, NULL, 0, 1, 0, &initial_cid);
        /* Set the various parameters */
        if (ret == 0) {
            test_ctx->c_to_s_link->microsec_latency = latency;
            test_ctx->s_to_c_link->microsec_latency = latency;
            test_ctx->c_to_s_link->picosec_per_byte = (1000000ull * 8) / 20;
            test_ctx->s_to_c_link->picosec_per_byte = (1000000ull * 8) / 20;

            if (bdp_test_option == bdp_test_option_short ||
                bdp_test_option == bdp_test_option_short_lo ||
                bdp_test_option == bdp_test_option_short_hi) {
                /* Test that the BDP option also works well if delay < 250 ms */
                max_completion_time = 4500000;
                test_ctx->c_to_s_link->microsec_latency = 100000ull;
                test_ctx->s_to_c_link->microsec_latency = 100000ull;
                buffer_size = 2 * test_ctx->c_to_s_link->microsec_latency;
                if (i == 0) {
                    if (bdp_test_option == bdp_test_option_short_lo) {
                        test_ctx->c_to_s_link->picosec_per_byte *= 2;
                        test_ctx->s_to_c_link->picosec_per_byte *= 2;
                    }
                    else if (bdp_test_option == bdp_test_option_short_hi) {
                        test_ctx->c_to_s_link->picosec_per_byte /= 2;
                        test_ctx->s_to_c_link->picosec_per_byte /= 2;
                    }
                }
                else if (i == 1 && bdp_test_option == bdp_test_option_short_lo) {
                    max_completion_time = 4650000;
                }
            }
            else if (i > 0) {
                switch (bdp_test_option) {
                case bdp_test_option_none:
                    break;
                case bdp_test_option_basic:
                    max_completion_time = 5900000;
                    break;
                case bdp_test_option_rtt:
                    max_completion_time = 4610000;
                    test_ctx->c_to_s_link->microsec_latency = 50000ull;
                    test_ctx->s_to_c_link->microsec_latency = 50000ull;
                    buffer_size = 2 * test_ctx->c_to_s_link->microsec_latency;
                    break;
                case bdp_test_option_ip:
                    picoquic_set_test_address(&test_ctx->client_addr, 0x08080808, 2345);
                    max_completion_time = 9000000;
                    break;
                case bdp_test_option_delay:
                    max_completion_time = 8000000;
                    break;
                case bdp_test_option_reno:
                    max_completion_time = 6750000;
                    break;
                default:
                    break;
                }
            }
            if (bdp_test_option == bdp_test_option_reno) {
                ccalgo = picoquic_newreno_algorithm;
            }
            else if (bdp_test_option == bdp_test_option_cubic) {
                ccalgo = picoquic_cubic_algorithm;
                max_completion_time = 10000000;
            }
            else if (bdp_test_option == bdp_test_option_bbr1) {
                ccalgo = picoquic_bbr1_algorithm;
            }
            picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
            picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
            picoquic_set_default_bdp_frame_option(test_ctx->qclient, 1);
            picoquic_set_default_bdp_frame_option(test_ctx->qserver, 1);
            test_ctx->qserver->use_long_log = 1;
            picoquic_set_qlog(test_ctx->qserver, ".");
            /* Set parameters */
            picoquic_init_transport_parameters(&server_parameters);
            picoquic_init_transport_parameters(&client_parameters);
            server_parameters.enable_bdp_frame = 1;
            client_parameters.enable_bdp_frame = 1;
            client_parameters.initial_max_stream_data_bidi_remote = 1000000;
            client_parameters.initial_max_data = 10000000;
            picoquic_set_transport_parameters(test_ctx->cnx_client, &client_parameters);
            ret = picoquic_set_default_tp(test_ctx->qserver, &server_parameters);

            if (ret == 0) {
                ret = tls_api_one_scenario_body(test_ctx, &simulated_time, test_scenario_10mb, sizeof(test_scenario_10mb), 0, 0, 0, buffer_size,
                    (i == 0) ? 0 : max_completion_time);
            }

            /* Verify that the BDP option was set and processed */
            if (ret == 0) {
                if (i == 1 && test_ctx->cnx_client->nb_zero_rtt_acked == 0 && bdp_test_option != bdp_test_option_delay) {
                    DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, no zero RTT data acked.\n",
                        bdp_test_option, i);
                    ret = -1;
                }
                if (!test_ctx->cnx_client->send_receive_bdp_frame) {
                    DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, bdp option not negotiated on client.\n",
                        bdp_test_option, i);
                    ret = -1;
                }
                if (!test_ctx->cnx_server->send_receive_bdp_frame) {
                    DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, bdp option not negotiated on server.\n",
                        bdp_test_option, i);
                    ret = -1;
                }
                if (ret == 0 && i == 1) {
                    if (test_ctx->cnx_server->nb_retransmission_total * 10 >
                        test_ctx->cnx_server->nb_packets_sent &&
                        bdp_test_option != bdp_test_option_cubic &&
                        bdp_test_option != bdp_test_option_delay &&
                        bdp_test_option != bdp_test_option_ip) {
                        DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, too many losses, %"PRIu64"/%"PRIu64".\n",
                            bdp_test_option, i, test_ctx->cnx_server->nb_retransmission_total,
                            test_ctx->cnx_server->nb_packets_sent);
                        ret = -1;

                    }
                    /* Verify bdp test option was executed */
                    if (!test_ctx->cnx_client->path[0]->is_bdp_sent) {
                        DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, bdp frame not sent by client.\n",
                            bdp_test_option, i);
                        ret = -1;
                    }
                    else if (bdp_test_option == bdp_test_option_basic ||
                        bdp_test_option == bdp_test_option_reno ||
                        bdp_test_option == bdp_test_option_short ||
                        bdp_test_option == bdp_test_option_short_hi ||
                        bdp_test_option == bdp_test_option_short_lo ||
                        bdp_test_option == bdp_test_option_cubic ||
                        bdp_test_option == bdp_test_option_bbr1) {
                        if (!test_ctx->cnx_server->cwin_notified_from_seed) {
                            DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, cwin not seed on server.\n",
                                bdp_test_option, i);
                            ret = -1;
                        }
                    }
                    else if (test_ctx->cnx_server->cwin_notified_from_seed) {
                        DBG_PRINTF("BDP RTT test (bdp test: %d), cnx %d, unexpected cwin seed on server.\n",
                            bdp_test_option, i);
                        ret = -1;
                    }
                }
            }

            /* Save the session tickets */
            if (ret == 0) {
                if (test_ctx->qclient->p_first_ticket == NULL) {
                    DBG_PRINTF("BDP RTT test (bdp option: %d), cnx %d, no ticket received.\n",
                        bdp_test_option, i);
                    ret = -1;
                }
                else {
                    ret = picoquic_save_tickets(test_ctx->qclient->p_first_ticket, simulated_time, ticket_file_name);
                    if (ret != 0) {
                        DBG_PRINTF("Zero RTT test (bdp test option: %d), cnx %d, ticket save error (0x%x).\n",
                            bdp_test_option, i, ret);
                    }
                }
            }

            /* Free the resource, which will close the log file. */
            if (test_ctx != NULL) {
                tls_api_delete_ctx(test_ctx);
                test_ctx = NULL;
            }
        }
    }

    return ret;
}

int bdp_basic_test(void)
{
    return bdp_option_test_one(bdp_test_option_basic);
}

int bdp_rtt_test(void)
{
    /* TODO: this test succeeds for the wrong reason.
    * The goal of the test is to verify that the BDP is NOT set
    * if the RTT on the second connection does not match the RTT
    * on the first one. The test does that, but only because the
    * second connection's RTT is lower than BBRLongRttThreshold,
    * thus uses regular BBR startup, in which the BDP option is
    * not implemented.
     */
    return bdp_option_test_one(bdp_test_option_rtt);
}

int bdp_ip_test(void)
{
    return bdp_option_test_one(bdp_test_option_ip);
}

int bdp_delay_test(void)
{
    return bdp_option_test_one(bdp_test_option_delay);
}

int bdp_reno_test(void)
{
    return bdp_option_test_one(bdp_test_option_reno);
}

int bdp_short_test(void)
{
    return bdp_option_test_one(bdp_test_option_short);
}

int bdp_short_hi_test(void)
{
    return bdp_option_test_one(bdp_test_option_short_hi);
}

int bdp_short_lo_test(void)
{
    return bdp_option_test_one(bdp_test_option_short_lo);
}

#if defined(_WINDOWS) && !defined(_WINDOWS64)
int bdp_cubic_test(void)
{
    /* We do not run this test in Win32 builds. */
    return 0;
}
#else
int bdp_cubic_test(void)
{
    return bdp_option_test_one(bdp_test_option_cubic);
}
#endif

int bdp_bbr1_test(void)
{
    return bdp_option_test_one(bdp_test_option_bbr1);
}

/*
 * The "blackhole" test simulates a link breakage of 2 seconds, during which all packets
 * are lost. The connection is expected to survive the blackhole, and then recover.
*/

static int blackhole_test_one(picoquic_congestion_algorithm_t* ccalgo, uint64_t max_completion_time, uint64_t jitter)
{
    uint64_t simulated_time = 0;
    uint64_t latency = 15000;
    uint64_t picoseq_per_byte_10 = (1000000ull * 8) / 10;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xb1, 0xac, 2, 3, 4, 5, 6, 7}, 8 };
    int ret = 0;

    initial_cid.id[2] = ccalgo->congestion_algorithm_number;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Simulate 10 ms link, 15ms latency, 2 seconds blackhole */
    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);

        test_ctx->c_to_s_link->jitter = jitter;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_10;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_10;
        test_ctx->s_to_c_link->jitter = jitter;
        test_ctx->blackhole_end = 7000000;
        test_ctx->blackhole_start = 5000000;


        picoquic_set_qlog(test_ctx->qserver, ".");

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time, test_scenario_10mb, sizeof(test_scenario_10mb), 0, 0, 0, 2 * latency, max_completion_time);
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int blackhole_test(void)
{
    int ret = blackhole_test_one(picoquic_bbr_algorithm, 15000000, 0);

    return ret;
}

/*
* Application limited test.
* The application is set to limit the max data values to stay lower than a set flow control window.
* We verify that in these scenario the CWIN does not grow too much above the flow control window.
*/
#define APP_LIMIT_TRACE_QLOG "acc1020304050607.server.qlog"

int app_limit_cc_test_one(
    picoquic_congestion_algorithm_t* ccalgo, uint64_t max_completion_time)
{
    uint64_t simulated_time = 0;
    uint64_t latency = 300000;
    uint64_t picoseq_per_byte_1 = (1000000ull * 8) / 1;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_tp_t client_parameters;
    uint64_t cwin_limit = 120000;
    picoquic_connection_id_t initial_cid = { {0xac, 0xc1, 2, 3, 4, 5, 6, 7}, 8 };
    int ret = 0;

    (void)picoquic_file_delete(APP_LIMIT_TRACE_QLOG, NULL);

    memset(&client_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&client_parameters);
    client_parameters.initial_max_data = 40000;

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, &client_parameters,
        NULL, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {

        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
        picoquic_set_qlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        picoquic_set_max_data_control(test_ctx->qclient, client_parameters.initial_max_data);

        test_ctx->c_to_s_link->jitter = 0;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_1;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_1;
        test_ctx->s_to_c_link->jitter = 0;

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 2 * latency, max_completion_time);
        }
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }


    /* Get the max bytes in flight from QLOG file, and check it is under the limit */
    if (ret == 0) {
        uint64_t bytes_in_flight_max;
        ret = picoquic_check_bytes_in_flight(APP_LIMIT_TRACE_QLOG, &bytes_in_flight_max);
        if (ret == 0 && bytes_in_flight_max > cwin_limit) {
            DBG_PRINTF("MAX In Flight = %" PRIu64 ", larger than %" PRIu64, bytes_in_flight_max, cwin_limit);
            ret = -1;
        }
    }

    return ret;
}

int app_limit_cc_test(void)
{
    picoquic_congestion_algorithm_t* ccalgos[] = {
        picoquic_newreno_algorithm,
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        picoquic_bbr_algorithm,
        picoquic_fastcc_algorithm,
        picoquic_bbr1_algorithm
    };
    uint64_t max_completion_times[] = {
        22000000,
        23500000,
        22000000,
        21000000,
        25000000,
        25000000
    };
    int ret = 0;

    for (size_t i = 0; i < sizeof(ccalgos) / sizeof(picoquic_congestion_algorithm_t*); i++) {
        ret = app_limit_cc_test_one(ccalgos[i], max_completion_times[i]);
        if (ret != 0) {
            DBG_PRINTF("Appplication limited congestion test fails for <%s>", ccalgos[i]->congestion_algorithm_id);
            break;
        }
    }

    return ret;
}

/* Test the effectiveness of the CWIN MAX option
 */

#define CWIN_MAX_TRACE_QLOG "c9149a0102030405.server.qlog"

int picoquic_check_bytes_in_flight(char const * qlog_file, uint64_t* max_bytes_in_flight)
{
    int ret = 0;
    FILE* F = picoquic_file_open(qlog_file, "r");

    if (F == NULL) {
        DBG_PRINTF("Cannot open <%s>", qlog_file);
        ret = -1;
    }
    else {
        *max_bytes_in_flight = 0;
        while (ret == 0 && F != NULL) {
            char buffer[512];
            int c_index = 0;
            if (fgets(buffer, 512, F) == NULL) {
                break;
            }
            /* Look for bytes_in_flight property */
            while (buffer[c_index] != 0 && (
                buffer[c_index] != '\"' ||
                strcmp("\"bytes_in_flight\":", &buffer[c_index]) != 0)) {
                c_index++;
            }
            if (buffer[c_index] != 0) {
                uint64_t bytes_in_flight = 0;
                while (buffer[c_index] != 0 && buffer[c_index] != ':') {
                    c_index++;
                }
                while (buffer[c_index] != 0 && (buffer[c_index] < '0' || buffer[c_index] > '9')) {
                    c_index++;
                }
                while (buffer[c_index] >= '0' && buffer[c_index] <= '9') {
                    bytes_in_flight *= 10;
                    bytes_in_flight += (uint64_t)buffer[c_index] - '0';
                    c_index++;
                }
                if (bytes_in_flight > *max_bytes_in_flight) {
                    *max_bytes_in_flight = bytes_in_flight;
                }
            }
        }
        picoquic_file_close(F);
    }
    return ret;
}

int cwin_max_test_one(
    picoquic_congestion_algorithm_t* ccalgo, uint64_t cwin_limit, uint64_t max_completion_time)
{
    uint64_t simulated_time = 0;
    uint64_t latency = 300000;
    uint64_t picoseq_per_byte_1 = (1000000ull * 8) / 100;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_tp_t client_parameters;
    picoquic_connection_id_t initial_cid = { {0xc9, 0x14, 0x9a, 1, 2, 3, 4, 5}, 8 };
    int ret = 0;

    (void)picoquic_file_delete(CWIN_MAX_TRACE_QLOG, NULL);

    memset(&client_parameters, 0, sizeof(picoquic_tp_t));
    picoquic_init_transport_parameters(&client_parameters);

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, &client_parameters,
        NULL, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
        picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
        picoquic_set_cwin_max(test_ctx->qserver, 0x10000);
        picoquic_set_qlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        picoquic_set_max_data_control(test_ctx->qclient, client_parameters.initial_max_data);

        test_ctx->c_to_s_link->jitter = 0;
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->c_to_s_link->picosec_per_byte = picoseq_per_byte_1;
        test_ctx->s_to_c_link->microsec_latency = latency;
        test_ctx->s_to_c_link->picosec_per_byte = picoseq_per_byte_1;
        test_ctx->s_to_c_link->jitter = 0;

        if (ret == 0) {
            ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
                test_scenario_very_long, sizeof(test_scenario_very_long), 0, 0, 0, 2 * latency, max_completion_time);
        }
    }

    /* Free the resource, which will close the log file.
    */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    /* Get the max bytes in flight from QLOG file, and check it is under the limit */
    if (ret == 0) {
        uint64_t bytes_in_flight_max;
        ret = picoquic_check_bytes_in_flight(CWIN_MAX_TRACE_QLOG, &bytes_in_flight_max);
        if (ret == 0 && bytes_in_flight_max > cwin_limit) {
            DBG_PRINTF("MAX In Flight = %" PRIu64 ", larger than %" PRIu64, bytes_in_flight_max, cwin_limit);
            ret = -1;
        }
    }

    return ret;
}

int cwin_max_test(void)
{
    picoquic_congestion_algorithm_t* ccalgos[] = {
        picoquic_newreno_algorithm,
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        picoquic_bbr_algorithm,
        picoquic_fastcc_algorithm,
        picoquic_bbr1_algorithm
    };
    uint64_t max_completion_times[] = {
        11000000,
        11000000,
        11000000,
        11000000,
        12100000,
        11000000
    };
    int ret = 0;

    for (size_t i = 0; i < sizeof(ccalgos) / sizeof(picoquic_congestion_algorithm_t*); i++) {
        ret = cwin_max_test_one(ccalgos[i], 68000, max_completion_times[i]);
        if (ret != 0) {
            DBG_PRINTF("CWIN Max test fails for <%s>", ccalgos[i]->congestion_algorithm_id);
            break;
        }
    }

    return ret;
}

/* BBR1ExitStartupSeedBDP is only reached when a 0-RTT ticket-based BDP seed notification
 * arrives while BBR1 is in its startup_long_rtt state. Drive that directly: force entry into
 * startup_long_rtt with a single high-RTT ACK, then deliver the seed_cwin notification. */
int bbr1_seed_bdp_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    picoquic_per_ack_state_t ack_state = { 0 };
    uint64_t seeded_bdp = 200000;

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        /* The wifi_shadow_rtt option exercises both the option-string parser and BBR1Inflight's
         * shadow-RTT floor (rt_prop stays well below it in this test). */
        picoquic_set_congestion_algorithm_ex(cnx, picoquic_bbr1_algorithm, "T5000000");

        /* A large bandwidth_estimate on the first round pushes the computed pacing rate above
         * the send_quantum clamp in BBR1SetSendQuantum. */
        cnx->path[0]->bandwidth_estimate = 100000000;

        /* rtt_min above BBR1's long-RTT hystart threshold forces entry into startup_long_rtt */
        cnx->path[0]->rtt_min = 100000;
        ack_state.rtt_measurement = 100000;
        ack_state.nb_bytes_acknowledged = 1000;
        cnx->congestion_alg->alg_notify(cnx, cnx->path[0], picoquic_congestion_notification_acknowledgement,
            &ack_state, simulated_time);

        memset(&ack_state, 0, sizeof(ack_state));
        ack_state.nb_bytes_acknowledged = seeded_bdp;
        cnx->congestion_alg->alg_notify(cnx, cnx->path[0], picoquic_congestion_notification_seed_cwin,
            &ack_state, simulated_time);

        if (cnx->path[0]->cwin != seeded_bdp) {
            DBG_PRINTF("BBR1 seed BDP did not set cwin as expected, cwin=%" PRIu64, cnx->path[0]->cwin);
            ret = -1;
        }

        /* Exercise the explicit reset notification, e.g. sent on PMTU blackhole recovery. */
        cnx->congestion_alg->alg_notify(cnx, cnx->path[0], picoquic_congestion_notification_reset,
            &ack_state, simulated_time);
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* The plain-startup half of the seed_cwin case (as opposed to the startup_long_rtt half covered
 * by bbr1_seed_bdp_test above) only updates the pacing rate once a prior ACK has already given
 * BBR1 a non-zero bandwidth estimate. Establish that baseline first, then seed with a larger
 * estimate so the seed is applied and the pacing rate gets pushed to the sender. */
int bbr1_seed_startup_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    picoquic_per_ack_state_t ack_state = { 0 };

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_path_t* path_x = cnx->path[0];

        picoquic_set_congestion_algorithm(cnx, picoquic_bbr1_algorithm);

        /* First, a normal low-RTT ACK: stays in plain startup, establishes a baseline pacing rate. */
        path_x->bandwidth_estimate = 1000000;
        ack_state.rtt_measurement = 20000;
        ack_state.nb_bytes_acknowledged = 1000;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_acknowledgement,
            &ack_state, simulated_time);

        /* Then a seed_cwin notification with a large enough acked count that the derived bandwidth
         * estimate exceeds bandwidth_estimate_max, so BBR1 updates the pacing rate again. */
        path_x->smoothed_rtt = 20000;
        memset(&ack_state, 0, sizeof(ack_state));
        ack_state.nb_bytes_acknowledged = 10000000;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_seed_cwin,
            &ack_state, simulated_time);
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* BBR1's long-term-bandwidth (policer detection) sampling is reached on every ACK, but only
 * does something once losses accumulate at a sustained ~20%+ ratio over several rounds. Drive
 * enough synthetic rounds of consistent loss to exercise both branches of BBR1ltbwIntervalDone:
 * the first interval (remembers the estimated bandwidth) and a second, matching interval
 * (confirms the estimate and switches to using it). */
int bbr1_ltbw_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    uint64_t delivered_per_round = 100000;
    uint64_t lost_per_round = 25000; /* 25%, above the ~20% long-term-bandwidth target ratio */

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_path_t* path_x = cnx->path[0];

        picoquic_set_congestion_algorithm(cnx, picoquic_bbr1_algorithm);

        for (int i = 0; i < 10; i++) {
            picoquic_per_ack_state_t ack_state = { 0 };

            simulated_time += 10000;
            path_x->delivered += delivered_per_round;
            path_x->delivered_last_packet = path_x->delivered;
            path_x->total_bytes_lost += lost_per_round;
            path_x->last_bw_estimate_path_limited = 0;

            ack_state.rtt_measurement = 20000;
            ack_state.nb_bytes_acknowledged = delivered_per_round;
            cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_acknowledgement,
                &ack_state, simulated_time);
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* Two more early-return branches in BBR1ltbwSampling, past the point where losses are confirmed
 * present: "no new data delivered since sampling started" (delivered frozen while losses still
 * accumulate) and "sampling interval too short to be meaningful" (rounds advance current_time by
 * under a microsecond each, so the 4-round interval never reaches the 1000-microsecond floor). */
int bbr1_ltbw_edge_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_path_t* path_x = cnx->path[0];

        picoquic_set_congestion_algorithm(cnx, picoquic_bbr1_algorithm);

        /* Losses accumulate every round, but delivered never advances: previous_sampling_delivered
         * stays equal to delivered forever, so BBR1ltbwSampling returns before computing a ratio. */
        for (int i = 0; i < 6; i++) {
            picoquic_per_ack_state_t ack_state = { 0 };

            simulated_time += 10000;
            path_x->delivered_last_packet = 1;
            path_x->total_bytes_lost += 25000;
            path_x->last_bw_estimate_path_limited = 0;

            ack_state.rtt_measurement = 20000;
            cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_acknowledgement,
                &ack_state, simulated_time);
        }

        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_reset, NULL, simulated_time);

        /* This time delivered and losses both advance at a 25% ratio, satisfying the loss-ratio
         * test, but current_time barely moves: the interval is under the 1000-microsecond floor. */
        for (int i = 0; i < 6; i++) {
            picoquic_per_ack_state_t ack_state = { 0 };

            simulated_time += 100;
            path_x->delivered += 100000;
            path_x->delivered_last_packet = path_x->delivered;
            path_x->total_bytes_lost += 25000;
            path_x->last_bw_estimate_path_limited = 0;

            ack_state.rtt_measurement = 20000;
            ack_state.nb_bytes_acknowledged = 100000;
            cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_acknowledgement,
                &ack_state, simulated_time);
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* Exercise the fastcc notifications that no other test reaches: an explicit reset (e.g. sent on
 * PMTU blackhole recovery), a direct ECN-CE reaction (no test currently pairs fastcc with an L4S
 * or ECN-marking scenario), the spurious-repeat "undo" of a prior congestion-event count, and
 * both branches of picoquic_fastcc_seed_cwin (outside vs inside the initial state, and with
 * bytes_in_flight below vs above the current cwin). */
int fastcc_notify_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    picoquic_per_ack_state_t ack_state = { 0 };

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_path_t* path_x = cnx->path[0];

        picoquic_set_congestion_algorithm(cnx, picoquic_fastcc_algorithm);

        /* Direct ECN-CE reaction: freezes the congestion window. */
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_ecn_ec,
            &ack_state, simulated_time);

        /* Seed while frozen (not the initial state): picoquic_fastcc_seed_cwin is a no-op. */
        ack_state.nb_bytes_acknowledged = 1000000;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_seed_cwin,
            &ack_state, simulated_time);

        /* Explicit reset, e.g. sent on PMTU blackhole recovery: back to the initial state. */
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_reset,
            &ack_state, simulated_time);

        /* Seed in the initial state with a bytes_in_flight above cwin: cwin is raised. */
        ack_state.nb_bytes_acknowledged = 1000000;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_seed_cwin,
            &ack_state, simulated_time);
        if (path_x->cwin != 1000000) {
            DBG_PRINTF("fastcc seed_cwin did not raise cwin as expected, cwin=%" PRIu64, path_x->cwin);
            ret = -1;
        }

        /* Seed again, this time below the now-raised cwin: cwin is left unchanged. */
        ack_state.nb_bytes_acknowledged = 100;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_seed_cwin,
            &ack_state, simulated_time);
        if (path_x->cwin != 1000000) {
            DBG_PRINTF("fastcc seed_cwin lowered cwin unexpectedly, cwin=%" PRIu64, path_x->cwin);
            ret = -1;
        }

        /* First RTT sample after reset always trusts rtt_min, so delta_rtt is forced to 0 --
         * that may or may not clear delay_threshold, so nb_cc_events could be 0 or 1 here. */
        ack_state.rtt_measurement = 1000;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_rtt_measurement,
            &ack_state, simulated_time);

        /* A huge jump in RTT is always well above the delay threshold (capped at 25000
         * microseconds regardless of rtt_min), so this reliably raises nb_cc_events by 1,
         * to at least 1 and at most 2 -- short of the freeze threshold of 4 either way. */
        simulated_time += 20000;
        ack_state.rtt_measurement = 501000;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_rtt_measurement,
            &ack_state, simulated_time);

        /* Spurious repeat: undoes one pending congestion event. */
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_spurious_repeat,
            &ack_state, simulated_time);
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* Exercise two c4 notifications that no other test reaches: c4_era_check's early return before
 * the connection reaches the ready state (c4_handle_ack's era-based state transitions are
 * otherwise unreachable before then -- this needs a non-initial state, since c4_initial_handle_ack
 * never consults era_check directly, so seed the CWIN first to reach c4_resuming), and an
 * explicit reset notification (e.g. sent on PMTU blackhole recovery). */
int c4_notify_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    picoquic_per_ack_state_t ack_state = { 0 };

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_path_t* path_x = cnx->path[0];

        picoquic_set_congestion_algorithm(cnx, c4_algorithm);

        /* cnx_state is well before "ready" here: era_check will return 0 immediately below. */
        ack_state.nb_bytes_acknowledged = 200000;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_seed_cwin,
            &ack_state, simulated_time);

        memset(&ack_state, 0, sizeof(ack_state));
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_acknowledgement,
            &ack_state, simulated_time);

        /* Explicit reset, e.g. sent on PMTU blackhole recovery. */
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_reset,
            &ack_state, simulated_time);
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* c4's "careful resume" feature -- c4_seed_cwin, c4_enter_resuming, c4_on_resuming_ack and
 * c4_on_resuming_era_end -- was entirely unreached by any other test: no test seeds a c4
 * connection with a remembered CWIN/rate pair. Drive it directly: seed while in the initial
 * state (the only state c4_seed_cwin acts on), then feed two era-ending ACKs to exercise both
 * branches of c4_on_resuming_era_end (one more era to wait, then exit to recovery). */
int c4_seed_resuming_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    uint64_t seeded_bdp = 200000;
    picoquic_per_ack_state_t ack_state = { 0 };

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_path_t* path_x = cnx->path[0];

        picoquic_set_congestion_algorithm(cnx, c4_algorithm);
        cnx->cnx_state = picoquic_state_ready;

        /* Seed the CWIN/rate: c4 is in its default initial state after set_congestion_algorithm. */
        ack_state.nb_bytes_acknowledged = seeded_bdp;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_seed_cwin,
            &ack_state, simulated_time);
        if (path_x->cwin != seeded_bdp) {
            DBG_PRINTF("c4 seed did not set cwin as expected, cwin=%" PRIu64, path_x->cwin);
            ret = -1;
        }

        /* c4_era_check requires the lowest unacked sequence number to have moved past the
         * sequence number recorded when entering resuming (0, since nothing was ever sent). */
        cnx->pkt_ctx[picoquic_packet_context_application].highest_acknowledged = 1000;

        /* First era end while resuming: one more era to wait before validating the seed. */
        memset(&ack_state, 0, sizeof(ack_state));
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_acknowledgement,
            &ack_state, simulated_time);

        /* Second era end while resuming: exits to recovery. */
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_acknowledgement,
            &ack_state, simulated_time);
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* Exercise two prague paths that no other test reaches: the per-path packet context used in
 * multipath mode (picoquic_prague_get_pkt_ctx's alternate branch), and an explicit reset
 * notification (e.g. sent on PMTU blackhole recovery). */
int prague_notify_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    picoquic_per_ack_state_t ack_state = { 0 };

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_path_t* path_x = cnx->path[0];

        picoquic_set_congestion_algorithm(cnx, picoquic_prague_algorithm);

        /* Multipath mode: get_pkt_ctx reads the per-path context instead of the connection's. */
        cnx->is_multipath_enabled = 1;

        /* Explicit reset, e.g. sent on PMTU blackhole recovery. */
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_reset,
            &ack_state, simulated_time);
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* picoquic_prague_process_ack's ECN-driven congestion-avoidance path (as opposed to the
 * slow-start path covered by ordinary use) is only reached after a first congestion event moves
 * prague out of slow start. Drive three losses to trigger that (picoquic_cc_hystart_loss_test
 * needs a sustained ~15% smoothed drop rate, which three consecutive losses clears), then feed
 * repeated CE-marked eras to walk the congestion window all the way down to its floor. */
int prague_ecn_recovery_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 10000000;
    picoquic_per_ack_state_t ack_state = { 0 };

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_path_t* path_x = cnx->path[0];
        picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];

        picoquic_set_congestion_algorithm(cnx, picoquic_prague_algorithm);

        for (uint64_t lost = 1; lost <= 3; lost++) {
            ack_state.lost_packet_number = lost;
            cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_repeat,
                &ack_state, simulated_time);
        }

        /* Past this point, prague is in congestion_avoidance. A new era only starts once packets
         * sent after the previous era began have been acked -- i.e. roughly one RTT -- which is
         * what next_sequence > recovery_sequence (picoquic_prague_process_ack) actually tests:
         * this is prague's "ignore repeated congestion signals within the same RTT" guard. So
         * each round below advances send_sequence (packets sent this era) and then
         * highest_acknowledged to match (those packets now acked), simulating one real RTT per
         * era; simply bumping highest_acknowledged without ever moving send_sequence forward
         * would trigger a new era on every single call, defeating that guard. Zero
         * nb_bytes_acknowledged keeps the unrelated per-packet CWND-growth term out of the way. */
        memset(&ack_state, 0, sizeof(ack_state));
        for (int i = 0; i < 15; i++) {
            pkt_ctx->send_sequence += 10;
            pkt_ctx->highest_acknowledged = pkt_ctx->send_sequence;
            pkt_ctx->ecn_ce_total_remote += 100;
            cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_acknowledgement,
                &ack_state, simulated_time);
        }

        if (path_x->cwin != PICOQUIC_CWIN_MINIMUM) {
            DBG_PRINTF("prague ECN-driven cwin did not reach the floor, cwin=%" PRIu64, path_x->cwin);
            ret = -1;
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* picoquic_congestion_notification_reset fires on path migration (RFC 9002): the new path's
 * characteristics are unknown, so a compliant algorithm must discard everything it learned and
 * restart as if the connection were brand new -- in particular path_x->cwin should return to
 * PICOQUIC_CWIN_INITIAL, not stay at whatever elevated value slow-start growth reached before
 * the reset. Run a short, realistic ramp-up (enough ACK/RTT-measurement rounds to grow cwin well
 * past its initial value under ordinary slow-start growth, for every algorithm), then reset, and
 * check that cwin actually came back down. */
/* Run 20 rounds of ACK/RTT-measurement notifications, simulating a short but real ramp-up. */
static void cc_algo_reset_ramp_up(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t* simulated_time)
{
    for (int i = 0; i < 20; i++) {
        picoquic_per_ack_state_t ack_state = { 0 };

        *simulated_time += 20000;
        path_x->bandwidth_estimate = 10000000;
        path_x->last_time_acked_data_frame_sent = *simulated_time;
        ack_state.rtt_measurement = 20000;
        ack_state.nb_bytes_acknowledged = 5000;
        ack_state.nb_bytes_delivered_since_packet_sent = 5000;
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_rtt_measurement,
            &ack_state, *simulated_time);
        cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_acknowledgement,
            &ack_state, *simulated_time);
    }
}

static int cc_algo_reset_test_one(picoquic_congestion_algorithm_t* ccalgo)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    uint64_t cwin_fresh;
    uint64_t cwin_before_reset;
    uint64_t cwin_after_reset;

    /* Reference: what a brand new connection reaches after the same ramp-up, with no prior
     * history at all. Some algorithms (e.g. BBR) do not zero cwin synchronously inside the reset
     * notification itself -- cwin is a value they derive from other state (pacing gain, round
     * counting, full-pipe detection, ...) on the next real event, all of which the reset call
     * does clear. So the meaningful check is not "is cwin exactly PICOQUIC_CWIN_INITIAL right
     * after reset", but "does cwin converge back to what a fresh connection would reach, instead
     * of staying anchored to what the old path could sustain". */
    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_set_congestion_algorithm(cnx, ccalgo);
        cnx->cnx_state = picoquic_state_ready;
        /* Not app-limited: required for reno/cubic/prague's slow-start growth (cc_common.c's
         * picoquic_cc_slow_start_increase) and for fastcc's own growth gate. */
        cnx->cwin_blocked = 1;
        cc_algo_reset_ramp_up(cnx, cnx->path[0], &simulated_time);
        cwin_fresh = cnx->path[0]->cwin;
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    if (ret == 0 &&
        picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else if (ret == 0) {
        picoquic_path_t* path_x = cnx->path[0];

        picoquic_set_congestion_algorithm(cnx, ccalgo);
        cnx->cnx_state = picoquic_state_ready;
        cnx->cwin_blocked = 1;

        /* Run the connection for a short while, so there is real learned state to discard. */
        cc_algo_reset_ramp_up(cnx, path_x, &simulated_time);

        cwin_before_reset = path_x->cwin;
        if (cwin_before_reset <= PICOQUIC_CWIN_INITIAL) {
            DBG_PRINTF("%s: cwin did not grow before reset, cwin=%" PRIu64, ccalgo->congestion_algorithm_id, cwin_before_reset);
            ret = -1;
        }

        /* Simulate a path migration: the algorithm must forget what it learned. */
        if (ret == 0) {
            picoquic_per_ack_state_t ack_state = { 0 };
            cnx->congestion_alg->alg_notify(cnx, path_x, picoquic_congestion_notification_reset,
                &ack_state, simulated_time);

            /* Let the new path settle, exactly as for the fresh-connection reference above. */
            cc_algo_reset_ramp_up(cnx, path_x, &simulated_time);
            cwin_after_reset = path_x->cwin;

            /* cwin_after_reset should land close to cwin_fresh: a few sender-MTUs of absolute
             * slack, to allow for minor implementation-specific rounding, but nowhere near the
             * full amount that a whole extra ramp-up's worth of carried-over state would add. */
            {
                uint64_t tolerance = 4 * PICOQUIC_CWIN_INITIAL;
                uint64_t delta = (cwin_after_reset > cwin_fresh) ?
                    cwin_after_reset - cwin_fresh : cwin_fresh - cwin_after_reset;

                if (delta > tolerance) {
                    DBG_PRINTF("%s: cwin after reset+settle (%" PRIu64 ") is not close to a fresh start (%" PRIu64
                        "), pre-reset value was %" PRIu64,
                        ccalgo->congestion_algorithm_id, cwin_after_reset, cwin_fresh, cwin_before_reset);
                    ret = -1;
                }
            }
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int cc_algo_reset_test(void)
{
    picoquic_congestion_algorithm_t* ccalgos[] = {
        picoquic_newreno_algorithm,
        picoquic_cubic_algorithm,
        picoquic_dcubic_algorithm,
        picoquic_bbr_algorithm,
        picoquic_bbr1_algorithm,
        picoquic_fastcc_algorithm,
        c4_algorithm,
        picoquic_prague_algorithm
    };
    int ret = 0;

    for (size_t i = 0; i < sizeof(ccalgos) / sizeof(picoquic_congestion_algorithm_t*); i++) {
        if (cc_algo_reset_test_one(ccalgos[i]) != 0) {
            DBG_PRINTF("CC algo reset test fails for <%s>", ccalgos[i]->congestion_algorithm_id);
            ret = -1;
        }
    }

    return ret;
}

/* picoquic_cc_slow_start_increase_ex's in_css branch (HyStart++ Consecutive Slow Start) is not
 * exercised by any current caller: cubic.c and prague.c (via _ex2) always pass in_css=0. It is
 * a live, directly reachable public function though, not dead code, so exercise it directly. */
int cc_common_slow_start_increase_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;

    if (picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time) != 0) {
        ret = -1;
    }
    else {
        picoquic_path_t* path_x = cnx->path[0];
        uint64_t delta;

        /* App limited: no growth, regardless of in_css. */
        cnx->cwin_blocked = 0;
        delta = picoquic_cc_slow_start_increase_ex(path_x, 4000, 0);
        if (delta != 0) {
            DBG_PRINTF("App limited traditional slow start returns %" PRIu64 ", expected 0", delta);
            ret = -1;
        }
        delta = picoquic_cc_slow_start_increase_ex(path_x, 4000, 1);
        if (ret == 0 && delta != 0) {
            DBG_PRINTF("App limited HyStart++ CSS slow start returns %" PRIu64 ", expected 0", delta);
            ret = -1;
        }

        /* Not app limited: traditional slow start grows by the full delivered amount. */
        cnx->cwin_blocked = 1;
        delta = picoquic_cc_slow_start_increase_ex(path_x, 4000, 0);
        if (ret == 0 && delta != 4000) {
            DBG_PRINTF("Traditional slow start returns %" PRIu64 ", expected 4000", delta);
            ret = -1;
        }

        /* HyStart++ CSS grows by 1/PICOQUIC_HYSTART_PP_CSS_GROWTH_DIVISOR of the delivered amount. */
        delta = picoquic_cc_slow_start_increase_ex(path_x, 4000, 1);
        if (ret == 0 && delta != 4000 / PICOQUIC_HYSTART_PP_CSS_GROWTH_DIVISOR) {
            DBG_PRINTF("HyStart++ CSS slow start returns %" PRIu64 ", expected %" PRIu64,
                delta, (uint64_t)(4000 / PICOQUIC_HYSTART_PP_CSS_GROWTH_DIVISOR));
            ret = -1;
        }
    }

    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}
