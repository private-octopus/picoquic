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
#include "picoquic_ns.h"
#include "picoquic_newreno.h"
#include "picoquic_cubic.h"
#include "picoquic_bbr.h"
#include "picoquic_bbr1.h"
#include "picoquic_fastcc.h"
#include "picoquic_prague.h"
#include "picoquic_utils.h"

/* Congestion compete test.
* These tests measure what happens when multiple connections fight for the same
* resource. The typical scenario involves connections with lots of data to
* send, with a duration sufficient to test congestion control mechanisms.
* An example would be testing BBR against itself, against Cubic, and against Reno.
* We will consider a "connection under test", and treat the other connections
* as "background".
*
* We are not aiming for an exact sharing between the competing connections, but we
* would like to verify that "nobody starves". The "main" connection should
* get a reasonable share of the bandwidth, say at least 25%, and it should also
* not get an excessive share, say no more than 80%. (Of course these numbers
* should not be hardcoded.)
*
* We know that effects like "latecomer advantage" may favor a new connection
* over the existing ones. We need to be able to program scenarios in which the
* connection hunder test starts either before or after the background connection.
*
* The first priority is to consider "duels" between the tested connection and the
* background connections. However, we may want to try scenarios with more than
* two connections.
*
* The tests rely on the "picoquic_ns" simulator.
*/


char const* cc_compete_batch_scenario_4M = "=b1:*1:397:4000000;";
char const* cc_compete_batch_scenario_10M = "=b1:*1:397:10000000;";

int cc_compete_cubic2_test()
{
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0xc0, 0xcb, 0xcb, 0, 0, 0, 0}, 8 };
    spec.main_cc_algo = picoquic_cubic_algorithm;
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_batch_scenario_4M;
    spec.background_cc_algo = picoquic_cubic_algorithm;
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 2;
    spec.main_target_time = 8500000;
    spec.queue_delay_max = 40000;
    spec.icid = icid;
    spec.qlog_dir = ".";

    return picoquic_ns(&spec, NULL);
}

int cc_compete_prague2_test()
{
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0xc0, 0xa9, 0xa9, 0, 0, 0, 0}, 8 };
    spec.main_cc_algo = picoquic_prague_algorithm;
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_batch_scenario_4M;
    spec.background_cc_algo = picoquic_prague_algorithm;
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 2;
    spec.main_target_time = 1600000;
    spec.data_rate_in_gbps = 0.05;
    spec.latency = 25000;
    spec.l4s_max = 15000;
    spec.icid = icid;
    spec.qlog_dir = ".";

    return picoquic_ns(&spec, NULL);
}

/* The current version of the "compete_d_cubic" test shows how the throughput
* of the connection managed with "dcubic" collapses when competing with
* a standard cubic connection. This is expected: dcubic backs off as soon
* as the delay increases, cubic does not. The logs show that the background
* connections gets the most bandwidth until it has finished sending the
* 10MB requested in the scenario, and the the main connection picks up
* slowly after that.
 */

int cc_compete_d_cubic_test()
{
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0xc0, 0xdc, 0xcb, 0, 0, 0, 0}, 8 };
    spec.main_cc_algo = picoquic_dcubic_algorithm;
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_batch_scenario_4M;
    spec.background_cc_algo = picoquic_cubic_algorithm;
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 2;
    spec.main_target_time = 10000000;
    spec.data_rate_in_gbps = 0.02;
    spec.latency = 40000;
    spec.icid = icid;
    spec.qlog_dir = ".";

    return picoquic_ns(&spec, NULL);
}

/* Check that the picoquic_ns simulations can correctly test asymmetric paths.
 */
int cc_ns_asym_test()
 {
     picoquic_ns_spec_t spec = { 0 };
     picoquic_connection_id_t icid = { { 0xcc, 0xa5, 0xcb, 0, 0, 0, 0, 0}, 8 };
     spec.main_cc_algo = picoquic_cubic_algorithm;
     spec.main_start_time = 0;
     spec.main_scenario_text = cc_compete_batch_scenario_4M;
     spec.background_cc_algo = picoquic_cubic_algorithm;
     spec.background_start_time = 0;
     spec.background_scenario_text = cc_compete_batch_scenario_10M;
     spec.nb_connections = 1;
     spec.data_rate_in_gbps = 0.01;
     spec.data_rate_up_in_gbps = 0.001;
     spec.latency = 300000;
     spec.main_target_time = 7500000;
     spec.queue_delay_max = 600000;
     spec.icid = icid;
     spec.qlog_dir = ".";

     return picoquic_ns(&spec, NULL);
 }


/* Check that the picoquic_ns simulations can correctly test asymmetric paths.
 */

char const* cc_compete_media_scenario = "=a1:d50:p2:S:n250:80; \
     = vlow: s30 :p4:S:n150 : 3750 : G30 : I37500; \
     = vmid: s30 :p6:S:n150 : 6250 : G30 : I62500 : D250000;";
#define MEDIA_TEST_LOG "ns_mediatest_log.txt"

int cc_ns_media_test()
{
    int ret = 0;
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0xed, 0x1a, 0, 0, 0, 0, 0}, 8 };
    FILE* err_fd = NULL;
    spec.main_cc_algo = picoquic_cubic_algorithm;
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_media_scenario;
    spec.background_cc_algo = picoquic_cubic_algorithm;
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 1;
    spec.data_rate_in_gbps = 0.1;
    spec.data_rate_up_in_gbps = 0.1;
    spec.latency = 15000;
    spec.main_target_time = 40000000;
    spec.queue_delay_max = 100000;
    spec.icid = icid;
    spec.qlog_dir = ".";
    spec.qperf_log = "./ns_qperflog.csv";
    spec.media_stats_start = 200000;
    spec.media_latency_average = 30500;
    spec.media_latency_max = 44000;
    spec.media_excluded = "vhigh, vmid,  vlast";

    err_fd = picoquic_file_open(MEDIA_TEST_LOG, "w");
    if (err_fd == NULL) {
        DBG_PRINTF("Cannot open %s\n", MEDIA_TEST_LOG);
        ret = -1;
    }
    else {
        ret = picoquic_ns(&spec, err_fd);
        picoquic_file_close(err_fd);
    }
    return ret;
}

/* Check that the picoquic_ns simulations can correctly test the black hole scenario.
 */
int cc_ns_blackhole_test()
{
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0xb1, 0xcb, 0, 0, 0, 0, 0}, 8 };
    spec.main_cc_algo = picoquic_cubic_algorithm;
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_batch_scenario_4M;
    spec.background_cc_algo = picoquic_cubic_algorithm;
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 1;
    spec.data_rate_in_gbps = 0.01;
    spec.latency = 40000;
    spec.main_target_time = 6000000;
    spec.queue_delay_max = 80000;
    spec.icid = icid;
    spec.qlog_dir = ".";
    spec.link_scenario = link_scenario_black_hole;

    return picoquic_ns(&spec, NULL);
}

/* Check that the picoquic_ns simulations can correctly test the drop_and_back scenario.
 */
int cc_ns_drop_and_back_test()
{
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0xdb, 0xcb, 0, 0, 0, 0, 0}, 8 };
    spec.main_cc_algo = picoquic_cubic_algorithm;
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_batch_scenario_4M;
    spec.background_cc_algo = picoquic_cubic_algorithm;
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 1;
    spec.data_rate_in_gbps = 0.01;
    spec.latency = 40000;
    spec.main_target_time = 5000000;
    spec.queue_delay_max = 80000;
    spec.icid = icid;
    spec.qlog_dir = ".";
    spec.link_scenario = link_scenario_drop_and_back;

    return picoquic_ns(&spec, NULL);
}

/* Check that the picoquic_ns simulations can correctly test the low_and_up scenario.
 */
int cc_ns_low_and_up_test()
{
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0x1a, 0xcb, 0, 0, 0, 0, 0}, 8 };
    spec.main_cc_algo = picoquic_cubic_algorithm;
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_batch_scenario_4M;
    spec.background_cc_algo = picoquic_cubic_algorithm;
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 1;
    spec.data_rate_in_gbps = 0.01;
    spec.latency = 40000;
    spec.main_target_time = 5500000;
    spec.queue_delay_max = 80000;
    spec.icid = icid;
    spec.qlog_dir = ".";
    spec.link_scenario = link_scenario_low_and_up;

    return picoquic_ns(&spec, NULL);
}

/* Check that the picoquic_ns simulations can correctly test the wifi fade scenario.
* also check the cc options are handled as expected.
 */
int cc_ns_wifi_fade_test()
{
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0xff, 0xbb, 0, 0, 0, 0, 0}, 8 };
    spec.main_cc_algo = picoquic_bbr_algorithm;
    spec.main_cc_options = "T50000";
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_batch_scenario_4M;
    spec.background_cc_algo = picoquic_bbr_algorithm;
    spec.background_cc_options = "T50000";
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 1;
    spec.data_rate_in_gbps = 0.01;
    spec.latency = 5000;
    spec.main_target_time = 7000000;
    spec.queue_delay_max = 15000;
    spec.icid = icid;
    spec.qlog_dir = ".";
    spec.link_scenario = link_scenario_wifi_fade;

    return picoquic_ns(&spec, NULL);
}


/* Check that the picoquic_ns simulations can correctly test the low_and_up scenario.
 */
int cc_ns_wifi_suspension_test()
{
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0xf5, 0xbb, 0, 0, 0, 0, 0}, 8 };
    spec.main_cc_algo = picoquic_bbr_algorithm;
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_batch_scenario_4M;
    spec.background_cc_algo = picoquic_bbr_algorithm;
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 1;
    spec.data_rate_in_gbps = 0.01;
    spec.latency = 5000;
    spec.main_target_time = 4000000;
    spec.queue_delay_max = 15000;
    spec.icid = icid;
    spec.qlog_dir = ".";
    spec.link_scenario = link_scenario_wifi_suspension;

    return picoquic_ns(&spec, NULL);
}


/* Check that the picoquic_ns simulations can correctly test the low_and_up scenario.
* The simple scenario merely duplicates the "wifi fade" scenario, the only difference
* being that the "varylink" structure is user specified.
*/
picoquic_ns_link_spec_t cc_varylink_test_spec[] = {
    { 1000000,  0.01,  0.01, 5000, 0, 15000, 0 },
    { 2000000,  0.001,  0.001, 5000, 0, 15000, 0, 2, 8 },
    { UINT64_MAX,  0.01,  0.01, 5000, 0, 15000, 0 }
};

int cc_ns_varylink_test()
{
    picoquic_ns_spec_t spec = { 0 };
    picoquic_connection_id_t icid = { { 0xcc, 0x11, 0xbb, 0, 0, 0, 0, 0}, 8 };
    spec.main_cc_algo = picoquic_bbr_algorithm;
    spec.main_start_time = 0;
    spec.main_scenario_text = cc_compete_batch_scenario_4M;
    spec.background_cc_algo = picoquic_bbr_algorithm;
    spec.background_start_time = 0;
    spec.background_scenario_text = cc_compete_batch_scenario_10M;
    spec.nb_connections = 1;
    spec.data_rate_in_gbps = 0.01;
    spec.latency = 5000;
    spec.main_target_time = 7000000;
    spec.queue_delay_max = 15000;
    spec.icid = icid;
    spec.qlog_dir = ".";
    spec.link_scenario = link_scenario_none;
    spec.vary_link_nb = sizeof(cc_varylink_test_spec) / sizeof(picoquic_ns_link_spec_t);
    spec.vary_link_spec = cc_varylink_test_spec;

    return picoquic_ns(&spec, NULL);
}
