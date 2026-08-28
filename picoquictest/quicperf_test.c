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
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquic_binlog.h"
#include "picosplay.h"
#include "picoquictest_internal.h"
#include "quicperf.h"

#define qpstr_batch "256:12345;"
#define qpstr_batch100 "* 100:256 : 12345;"
#define qpstr_batch2 "= b1:256 : 12345; = b2:=b1: 256 : 12345;"
#define qpstr_video1 "= v1:s30:n300:12345;"
#define qpstr_video2 "=v2:s30:p4:C:n300:12345;"
#define qpstr_video3 "=v3 : s30: p4:S: n1800:12345:G150:I11111;"
#define qpstr_video4 "=v4 : s30:p4:S:  n1800:12345:G150:I11111:D1000;"
#define qpstr_audio "=a0:d50:p2:C:n500:40;"
#define qpstr_combo "=a1:d50:p2:S:n3000:80; \
= vlow:*3 : s30 :p4:S:n1800 : 3750 : G150 : I37500; \
= vmid:*3 : s30 :p6:S: n1800 : 6250 : G150 : I62500 : D1000; \
= vhi:*3 : s30 :p8:S: n1800 : 12500 : G150 : I125000 : D1000;"

const quicperf_stream_desc_t qpsc_batch[1] = {
    {
    { 0, 0 }, /* id */
    { 0, 0 }, /* previous id */
    1, /* repeat_count */
    quicperf_media_batch, /* media_type */
    0, /* frequency */
    256, /* post_size */
    12345, /* response_size */
    0, /* nb_frames */
    0, /* frame_size */
    0, /* group_size */
    0, /* first_frame_size */
    0, /* reset_delay */
    0, /* priority */
    0, /* is_infinite */
    0, /*  is_client_media */
} };

const quicperf_stream_desc_t qpsc_batch100[1] = { {
    { 0, 0 }, /* id */
    { 0, 0 }, /* previous id */
    100, /* repeat_count */
    quicperf_media_batch, /* media_type */
    0, /* frequency */
    256, /* post_size */
    12345, /* response_size */
    0, /* nb_frames */
    0, /* frame_size */
    0, /* group_size */
    0, /* first_frame_size */
    0, /* reset_delay */
    0, /* priority */
    0, /* is_infinite */
    0, /*  is_client_media */
}};

const quicperf_stream_desc_t qpsc_batch2[2] = {
    {
        { 'b', '1', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_batch, /* media_type */
        0, /* frequency */
        256, /* post_size */
        12345, /* response_size */
        0, /* nb_frames */
        0, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        0, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'b', '2', 0 }, /* id */
        { 'b', '1', 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_batch, /* media_type */
        0, /* frequency */
        256, /* post_size */
        12345, /* response_size */
        0, /* nb_frames */
        0, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        0, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video1[1] = {
    {
        { 'v', '1', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        300, /* nb_frames */
        12345, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        0, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video2[1] = {
    {
        { 'v', '2', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        300, /* nb_frames */
        12345, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        1, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video3[] = {
    {
        { 'v', '3', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        12345, /* frame_size */
        150, /* group_size */
        11111, /* first_frame_size */
        0, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_video4[] = {
    {
        { 'v', '4', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        12345, /* frame_size */
        150, /* group_size */
        11111, /* first_frame_size */
        1000, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_audio[1] = {
    {
        { 'a', '0', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_datagram, /* media_type */
        50, /* frequency */
        0, /* post_size */
        0, /* response_size */
        500, /* nb_frames */
        40, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        2, /* priority */
        0, /* is_infinite */
        1, /*  is_client_media */
    }
};

const quicperf_stream_desc_t qpsc_combo[4] = {
    {
        { 'a', '1', 0 }, /* id */
        { 0, 0 }, /* previous id */
        1, /* repeat_count */
        quicperf_media_datagram, /* media_type */
        50, /* frequency */
        0, /* post_size */
        0, /* response_size */
        3000, /* nb_frames */
        80, /* frame_size */
        0, /* group_size */
        0, /* first_frame_size */
        0, /* reset_delay */
        2, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'v', 'l', 'o', 'w',  0}, /* id */
        { 0, 0 }, /* previous id */
        3, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        3750, /* frame_size */
        150, /* group_size */
        37500, /* first_frame_size */
        0, /* reset_delay */
        4, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'v', 'm', 'i', 'd',  0}, /* id */
        { 0, 0 }, /* previous id */
        3, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        6250, /* frame_size */
        150, /* group_size */
        62500, /* first_frame_size */
        1000, /* reset_delay */
        6, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    },
    {
        { 'v', 'h', 'i',  0}, /* id */
        { 0, 0 }, /* previous id */
        3, /* repeat_count */
        quicperf_media_stream, /* media_type */
        30, /* frequency */
        0, /* post_size */
        0, /* response_size */
        1800, /* nb_frames */
        12500, /* frame_size */
        150, /* group_size */
        125000, /* first_frame_size */
        1000, /* reset_delay */
        8, /* priority */
        0, /* is_infinite */
        0, /*  is_client_media */
    }
};

typedef struct st_quicperf_test_line_t {
    const quicperf_stream_desc_t* sc;
    size_t nb_sc;
    char const* str;
} quicperf_test_line_t;

const quicperf_test_line_t test_lines[] = {
    { qpsc_batch, 1, qpstr_batch },
    { qpsc_batch100, 1, qpstr_batch100 },
    { qpsc_batch2, 2, qpstr_batch2 },
    { qpsc_video1, 1, qpstr_video1 },
    { qpsc_video2, 1, qpstr_video2 },
    { qpsc_video3, 1, qpstr_video3 },
    { qpsc_video4, 1, qpstr_video4 },
    { qpsc_audio, 1, qpstr_audio },
    { qpsc_combo, 4, qpstr_combo }
};

const size_t nb_test_lines = sizeof(test_lines) / sizeof(quicperf_test_line_t);

int quicperf_compare_stream_desc(const quicperf_stream_desc_t* sc1, const quicperf_stream_desc_t* sc2)
{
    int ret = 0;
    char const* diff = NULL;

    if (strcmp(sc1->id, sc2->id) != 0) {
        diff = "id";
    }
    else if (strcmp(sc1->previous_id, sc2->previous_id) != 0) {
        diff = "previous_id";
    }
    else if (sc1->repeat_count != sc2->repeat_count) {
        diff = "repeat_count";
    }
    else if (sc1->media_type != sc2->media_type) {
        diff = "media_type";
    }
    else if (sc1->frequency != sc2->frequency) {
        diff = "frequency";
    }
    else if (sc1->post_size != sc2->post_size) {
        diff = "post_size";
    }
    else if (sc1->post_size != sc2->post_size) {
        diff = "post_size";
    }
    else if (sc1->response_size != sc2->response_size) {
        diff = "response_size";
    }
    else if (sc1->nb_frames != sc2->nb_frames) {
        diff = "nb_frames";
    }
    else if (sc1->frame_size != sc2->frame_size) {
        diff = "frame_size";
    }
    else if (sc1->group_size != sc2->group_size) {
        diff = "group_size";
    }
    else if (sc1->first_frame_size != sc2->first_frame_size) {
        diff = "first_frame_size";
    }
    else if (sc1->reset_delay != sc2->reset_delay) {
        diff = "reset_delay";
    }
    else if (sc1->priority != sc2->priority) {
        diff = "priority";
    }
    else if (sc1->is_infinite != sc2->is_infinite) {
        diff = "is_infinite";
    }
    else if (sc1->is_client_media != sc2->is_client_media) {
        diff = "is_client_media";
    }
    if (diff != NULL) {
        DBG_PRINTF("Values of %s do not match.\n", diff);
        ret = -1;
    }
    return ret;
}

int quicperf_parse_test_one(const quicperf_test_line_t* tl)
{
    int ret = 0;

    /* Parse the scenario */
    quicperf_ctx_t* ctx = quicperf_create_ctx(tl->str, NULL);
    if (ctx == NULL) {
        ret = -1;
    }
    else {
        /* Compare to the reference */
        if (ctx->nb_scenarios != tl->nb_sc) {
            DBG_PRINTF("Found %zu streams instead of %zu", ctx->nb_scenarios, tl->nb_sc);
            ret = -1;
        }
        else {
            for (size_t i = 0; ret == 0 && i < ctx->nb_scenarios; i++) {
                if (quicperf_compare_stream_desc(&ctx->scenarios[i], &tl->sc[i]) != 0) {
                    DBG_PRINTF("Stream descriptio %zu does not match", i);
                    ret = -1;
                }
            }
        }
        /* Free the scenario */
        quicperf_delete_ctx(ctx);
    }
    return ret;
}

int quicperf_parse_test(void)
{
    int ret = 0;
    for (size_t i = 0; ret == 0 && i < nb_test_lines; i++) {
        ret = quicperf_parse_test_one(&test_lines[i]);
        if (ret != 0) {
            DBG_PRINTF("Parse test fails for test_lines[%zu]", i);
        }
    }
    return ret;
}

typedef struct st_quicperf_test_target_t {
    uint64_t nb_frames_received_min;
    uint64_t nb_frames_received_max;
    uint64_t average_delay_min;
    uint64_t average_delay_max;
    uint64_t max_delay;
    uint64_t min_delay;
} quicperf_test_target_t;

/* Multipath probe timing, used to explore the race reported between
 * second-path setup and the quicperf scenario start (both are triggered
 * off the same "almost ready" condition, from independent code paths,
 * with no ordering guarantee between them in the field).
 *
 * - quicperf_mp_probe_immediate: retry the probe starting at the first
 *   opportunity (cnx_state >= almost_ready), exactly like picoquicdemo's
 *   client_create_additional_path. Tightest possible race against
 *   quicperf's own almost_ready-triggered scenario start.
 * - quicperf_mp_probe_delayed: wait probe_delay_us after almost_ready
 *   before the first attempt, giving quicperf's scenario a head start.
 * - quicperf_mp_probe_settled: fully validate the second path
 *   (wait_multipath_ready) before anything else is allowed to contend
 *   with it. This is what every existing multipath test does; it is the
 *   negative control and is expected to always succeed.
 */
typedef enum {
    quicperf_mp_probe_immediate = 0,
    quicperf_mp_probe_delayed,
    quicperf_mp_probe_settled
} quicperf_mp_probe_timing_t;

static int quicperf_e2e_test_ex(uint8_t test_id, char const* scenario, uint64_t completion_target,
    size_t nb_targets, quicperf_test_target_t* targets,
    int use_multipath, quicperf_mp_probe_timing_t probe_timing, uint64_t probe_delay_us)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    quicperf_ctx_t  *quicperf_ctx;
    int ret = 0;
    picoquic_connection_id_t initial_cid = { {0x9e, 0x8f, 0, 0, 0, 0, 0, 0}, 8 };

    initial_cid.id[2] = test_id;

    quicperf_ctx = quicperf_create_ctx(scenario, NULL);
    if (quicperf_ctx == NULL) {
        DBG_PRINTF("Could not get ready to run QUICPERF(%s)\n", scenario);
        return -1;
    }

    if (ret == 0 && quicperf_ctx->nb_scenarios != nb_targets) {
        DBG_PRINTF("Expected %zu scenario items, got %zu\n", quicperf_ctx->nb_scenarios, nb_targets);
        return -1;
    }

    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, "perf", &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

        if (ret == 0) {
            picoquic_set_binlog(test_ctx->qserver, ".");
            test_ctx->qserver->use_long_log = 1;
        }

        if (ret == 0) {
            picoquic_set_binlog(test_ctx->qclient, ".");
        }
    }

    if (ret != 0) {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }
    else if (test_ctx == NULL || test_ctx->cnx_client == NULL || test_ctx->qserver == NULL) {
        DBG_PRINTF("%s", "Connections where not properly created!\n");
        ret = -1;
    }

    /* The default procedure creates connections using the test callback.
     * We want to replace that by the quicperf callback */

    if (ret == 0) {
        test_ctx->qserver->default_tp.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
        test_ctx->cnx_client->local_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
        // picoquic_set_alpn_select_fn(test_ctx->qserver, picoquic_demo_server_callback_select_alpn);
        picoquic_set_default_callback(test_ctx->qserver, quicperf_callback, NULL);
        picoquic_set_callback(test_ctx->cnx_client, quicperf_callback, quicperf_ctx);

        if (ret == 0 && use_multipath) {
            /* Register the second pair of simulated links, and negotiate the
             * multipath transport parameter on both sides, before the
             * handshake starts. */
            picoquic_tp_t server_parameters;

            ret = multipath_test_add_links(test_ctx, 0);
            if (ret == 0) {
                multipath_init_params(&server_parameters, 0);
                picoquic_set_default_tp(test_ctx->qserver, &server_parameters);
                test_ctx->cnx_client->local_parameters.initial_max_path_id = 2;
            }
        }

        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0 && use_multipath && probe_timing != quicperf_mp_probe_settled) {
        /* Step the simulation manually so the probe for the second path can
         * be issued right as (or shortly after) the client reaches
         * almost_ready -- the same condition that triggers quicperf's own
         * scenario start (see quicperf_callback, case
         * picoquic_callback_almost_ready). This is deliberately NOT
         * synchronized with quicperf's start: the two are independent in
         * the field (picoquicdemo's packet-loop callback vs. the
         * connection callback), and we want the harness to reproduce that
         * lack of synchronization rather than paper over it. */
        int probe_pending = 1;
        uint64_t probe_ready_time = 0;

        time_out = simulated_time + 4000000;

        while (ret == 0 && probe_pending &&
            test_ctx->cnx_client->cnx_state != picoquic_state_disconnected) {
            ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);
            if (ret == -1) {
                break;
            }

            if (test_ctx->cnx_client->cnx_state >= picoquic_state_client_almost_ready) {
                if (probe_timing == quicperf_mp_probe_delayed) {
                    if (probe_ready_time == 0) {
                        probe_ready_time = simulated_time + probe_delay_us;
                    }
                    if (simulated_time < probe_ready_time) {
                        continue;
                    }
                }

                {
                    int probe_ret = picoquic_probe_new_path(test_ctx->cnx_client,
                        (struct sockaddr*)&test_ctx->server_addr,
                        (struct sockaddr*)&test_ctx->client_addr_2, simulated_time);

                    if (probe_ret == 0) {
                        probe_pending = 0;
                    }
                    else if (probe_ret != PICOQUIC_ERROR_PATH_ID_BLOCKED &&
                        probe_ret != PICOQUIC_ERROR_PATH_CID_BLOCKED &&
                        probe_ret != PICOQUIC_ERROR_PATH_NOT_READY) {
                        DBG_PRINTF("Probe new path failed, ret = 0x%x", probe_ret);
                        ret = probe_ret;
                    }
                    /* else: transient, retry on a later round. */
                }
            }
            if (++nb_trials > 100000) {
                ret = -1;
                break;
            }
        }
        if (ret == 0 && probe_pending) {
            DBG_PRINTF("%s", "Could not issue the multipath probe before disconnection");
            ret = -1;
        }
        if (ret == 0) {
            ret = wait_client_connection_ready(test_ctx, &simulated_time);
        }
    }
    else if (ret == 0 && use_multipath) {
        /* quicperf_mp_probe_settled: negative control. Let the handshake
         * complete (quicperf's scenario has already auto-started, at the
         * latest by the time the connection is fully ready), then only
         * probe and fully validate the second path before doing anything
         * else -- exactly like every other multipath test. */
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
        if (ret == 0) {
            ret = wait_client_connection_ready(test_ctx, &simulated_time);
        }
        if (ret == 0) {
            ret = picoquic_probe_new_path(test_ctx->cnx_client,
                (struct sockaddr*)&test_ctx->server_addr,
                (struct sockaddr*)&test_ctx->client_addr_2, simulated_time);
        }
        if (ret == 0) {
            ret = wait_multipath_ready(test_ctx, &simulated_time);
        }
    }
    else if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Simulate the connection from the client side. */
    time_out = simulated_time + 30000000;
    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

        if (ret == -1) {
            break;
        }

        if (test_ctx->cnx_client->cnx_state == picoquic_state_ready &&
            picoquic_is_cnx_backlog_empty(test_ctx->cnx_client) &&
            quicperf_ctx->next_group_start_time < simulated_time) {
            if (quicperf_ctx->nb_open_streams == 0) {
                ret = picoquic_close(test_ctx->cnx_client, 0);
            }
            else if (simulated_time > quicperf_ctx->last_interaction_time &&
                simulated_time - quicperf_ctx->last_interaction_time > 10000000ull) {
                (void)picoquic_close(test_ctx->cnx_client, 0xdeadbeef);
                ret = -1;
            }
        }
        if (++nb_trials > 100000) {
            ret = -1;
            break;
        }
    }

    if (ret == 0 && test_ctx->qclient->nb_data_nodes_allocated > test_ctx->qclient->nb_data_nodes_in_pool) {
        ret = -1;
    }
    else if (ret == 0 && test_ctx->qserver->nb_data_nodes_allocated > test_ctx->qserver->nb_data_nodes_in_pool) {
        ret = -1;
    }

    if (ret == 0 && completion_target != 0) {
        if (simulated_time > completion_target) {
            DBG_PRINTF("Test uses %llu microsec instead of %llu", simulated_time, completion_target);
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_targets; i++) {
        quicperf_test_target_t* target = &targets[i];
        quicperf_stream_report_t* report = &quicperf_ctx->reports[i];

        if (target->nb_frames_received_min != 0 &&
            report->nb_frames_received < target->nb_frames_received_min) {
            DBG_PRINTF("Scenario %zu, expected at least %" PRIu64 "frames, got % PRIu64", i, target->nb_frames_received_min, report->nb_frames_received);
            ret = -1;
        }
        else if (target->nb_frames_received_max != 0 &&
            report->nb_frames_received > target->nb_frames_received_max) {
            DBG_PRINTF("Scenario %zu, expected at most %" PRIu64 "frames, got % PRIu64", i, target->nb_frames_received_max, report->nb_frames_received);
            ret = -1;
        }
        else if (report->nb_frames_received > 0) {
            uint64_t average_delay = report->sum_delays / report->nb_frames_received;

            if (target->average_delay_min != 0 &&
                average_delay < target->average_delay_min) {
                DBG_PRINTF("Scenario %zu, expected average delay >= %" PRIu64 ", got % PRIu64", i, target->average_delay_min, average_delay);
                ret = -1;
            }
            else if (target->average_delay_max != 0 &&
                average_delay > target->average_delay_max) {
                DBG_PRINTF("Scenario %zu, expected average delay <= %" PRIu64 ", got % PRIu64", i, target->average_delay_max, average_delay);
                ret = -1;
            }
            else if (target->max_delay != 0 &&
                report->max_delays > target->max_delay) {
                DBG_PRINTF("Scenario %zu, expected max delay <= %" PRIu64 ", got % PRIu64", i, target->max_delay, report->max_delays);
                ret = -1;
            }
            else if (target->min_delay != 0 &&
                report->min_delays < target->min_delay) {
                DBG_PRINTF("Scenario %zu, expected min delay >= %" PRIu64 ", got % PRIu64", i, target->min_delay, report->min_delays);
                ret = -1;
            }
        }
    }

    quicperf_delete_ctx(quicperf_ctx);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int quicperf_e2e_test(uint8_t test_id, char const *scenario, uint64_t completion_target, size_t nb_targets, quicperf_test_target_t * targets)
{
    return quicperf_e2e_test_ex(test_id, scenario, completion_target, nb_targets, targets,
        0, quicperf_mp_probe_immediate, 0);
}

int quicperf_e2e_test_multipath(uint8_t test_id, char const* scenario, uint64_t completion_target,
    size_t nb_targets, quicperf_test_target_t* targets,
    quicperf_mp_probe_timing_t probe_timing, uint64_t probe_delay_us)
{
    return quicperf_e2e_test_ex(test_id, scenario, completion_target, nb_targets, targets,
        1, probe_timing, probe_delay_us);
}

int quicperf_batch_test(void)
{
    char const* batch_scenario = "=b1:*1:397:1000000;";
    quicperf_test_target_t batch_target = {
        0, /* nb_frames_received_min */
        0, /* nb_frames_received_max */
        0, /* average_delay_min */
        0, /* average_delay_max */
        0, /* max_delay */
        0, /* min_delay */
    };

    return quicperf_e2e_test(0xba, batch_scenario, 1200000, 1, &batch_target);
}

int quicperf_datagram_test(void)
{
    char const* datagram_scenario = "=a1:d50:n250:100;";
    quicperf_test_target_t datagram_target = {
        250, /* nb_frames_received_min */
        250, /* nb_frames_received_max */
        20000, /* average_delay_min */
        25000, /* average_delay_max */
        50000, /* max_delay */
        20000, /* min_delay */
    };

    return quicperf_e2e_test(0xda, datagram_scenario, 6000000, 1, &datagram_target);
}

int quicperf_datagram_multiflow_test(void)
{
    /* Four parallel datagram flows, each sending frames large enough that
     * only one comfortably fits per packet at a time. This used to trigger a
     * bug in picoquic_prepare_stream_and_datagrams (streams.c). */
    char const* datagram_multiflow_scenario =
        "=a:d250:p2:S:n200:1300;=b:d250:p2:S:n200:1300;=c:d250:p2:S:n200:1300;=d:d250:p2:S:n200:1300;";
    quicperf_test_target_t datagram_multiflow_target[4] = {
        { 200, 200, 0, 0, 0, 0 },
        { 200, 200, 0, 0, 0, 0 },
        { 200, 200, 0, 0, 0, 0 },
        { 200, 200, 0, 0, 0, 0 }
    };

    return quicperf_e2e_test(0x1c, datagram_multiflow_scenario, 3000000, 4, datagram_multiflow_target);
}

int quicperf_media_test(void)
{
    char const* media_scenario = "=v1:s30:n150:2000:G30:I20000;";
    quicperf_test_target_t media_target = {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        25000, /* average_delay_max */
        50000, /* max_delay */
        20000, /* min_delay */
    };

    return quicperf_e2e_test(0x1a,media_scenario, 6000000, 1, &media_target);
}

int quicperf_ungrouped_test(void)
{
    /* Media stream with no "G" (group size) parameter: the whole stream is
     * a single ungrouped batch of frames. This used to cause the client to
     * request a second, spurious round of the same nb_frames after the
     * first one completed, doubling the number of frames actually sent. */
    char const* ungrouped_scenario = "=v1:s30:p2:S:n80:18000;";
    quicperf_test_target_t ungrouped_target = {
        80, /* nb_frames_received_min */
        80, /* nb_frames_received_max */
        0, /* average_delay_min */
        0, /* average_delay_max */
        0, /* max_delay */
        0, /* min_delay */
    };

    return quicperf_e2e_test(0x18, ungrouped_scenario, 4000000, 1, &ungrouped_target);
}

int quicperf_group_remainder_test(void)
{
    /* Media stream where "G" (group size) does not evenly divide "n" (nb_frames):
     * group 0 sends 60 frames, and the trailing remainder group sends the
     * last 20. Exercises the "group_size * (group_id + 1) > nb_frames" remainder
     * computation in quicperf_request_media_stream_from_scenario, as well as the
     * deactivation check in quicperf_activate_next_group after the remainder group. */
    char const* group_remainder_scenario = "=v1:s30:p2:S:n80:18000:G60;";
    quicperf_test_target_t group_remainder_target = {
        80, /* nb_frames_received_min */
        80, /* nb_frames_received_max */
        0, /* average_delay_min */
        0, /* average_delay_max */
        0, /* max_delay */
        0, /* min_delay */
    };

    return quicperf_e2e_test(0x19, group_remainder_scenario, 4000000, 1, &group_remainder_target);
}

int quicperf_datagram_vs_group_test(void)
{
    /* Realistic regression scenario for a bug that caused the simulation
     * to stall in scenarios mixing audio datagrams and vvideo streams:
     * a1 + vlow + vmid, as in c4_media_wb. This scenario did not actually reproduce the
     * bug, but the test provides additional coverage. */
    char const* scenario = "=a1:d50:p2:S:n250:80;=vlow:s30:p4:S:n150:3750:G30:I37500;=vmid:s30:p6:S:n150:6250:G30:I62500:D250000;";
    quicperf_test_target_t targets[3] = {
        { 250, 250, 0, 0, 0, 0 },
        { 0, 0, 0, 0, 0, 0 },
        { 0, 0, 0, 0, 0, 0 }
    };

    return quicperf_e2e_test(0x1e, scenario, 8000000, 3, targets);
}

/* Internal quicperf.c functions, not part of the public quicperf.h API,
 * needed to drive quicperf_server_timer directly for the test below. */
quicperf_stream_ctx_t* quicperf_create_stream_ctx(quicperf_ctx_t* ctx, uint64_t stream_id);
int quicperf_server_timer(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, uint64_t current_time);

int quicperf_server_timer_wakeup_test(void)
{
    /* Deterministic repro of a bug that caused the simulation
     * to stall in scenarios mixing audio datagrams and vvideo streams: given a
     * datagram stream due at t=1000 and a still-pacing non-datagram stream
     * due later at t=2000, the timer should schedule the next wakeup at the
     * minimum (1000), but the non-datagram branch overwrote it unconditionally. */
    int ret = 0;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    quicperf_ctx_t* ctx = NULL;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, "perf", &simulated_time, NULL, NULL, 0, 1, 0, NULL);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0 && test_ctx->cnx_server == NULL) {
        DBG_PRINTF("%s", "No server connection after handshake");
        ret = -1;
    }

    if (ret == 0 && (ctx = quicperf_create_ctx(NULL, NULL)) == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        quicperf_stream_ctx_t* datagram_ctx = quicperf_create_stream_ctx(ctx, 0);
        quicperf_stream_ctx_t* video_ctx = quicperf_create_stream_ctx(ctx, 4);

        if (datagram_ctx == NULL || video_ctx == NULL) {
            ret = -1;
        }
        else {
            /* Datagram stream due at t=1000. */
            datagram_ctx->is_datagram = 1;
            datagram_ctx->nb_frames = 250;
            datagram_ctx->nb_frames_sent = 10;
            datagram_ctx->frequency = 50;
            datagram_ctx->next_frame_time = 1000;

            /* Non-datagram stream, resting between frames, due at t=2000. */
            video_ctx->is_datagram = 0;
            video_ctx->is_activated = 0;
            video_ctx->next_frame_time = 2000;

            /* current_time = 100: neither is due yet. */
            ret = quicperf_server_timer(test_ctx->cnx_server, ctx, 100);

            if (ret == 0 && ctx->stream_wakeup_time != 1000) {
                DBG_PRINTF("Wrong wakeup time: expected 1000 (datagram), got %" PRIu64 " -- clobbered by video's next_frame_time",
                    ctx->stream_wakeup_time);
                ret = -1;
            }
        }
    }

    if (ctx != NULL) {
        quicperf_delete_ctx(ctx);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* Internal quicperf.c function, not part of the public quicperf.h API,
 * needed to drive quicperf_receive_media_data directly for the test below. */
void quicperf_receive_media_data(picoquic_cnx_t* cnx, quicperf_ctx_t* ctx, quicperf_stream_ctx_t* stream_ctx,
    uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event);

int quicperf_receive_media_overrun_test(void)
{
    /* Verify that quicperf_receive_media_data does stop parsing
     * frames once nb_frames_received reaches nb_frames. A well-behaved peer
     * never does this, but the client cannot rely on that over the network. */
    int ret = 0;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    quicperf_ctx_t* ctx = NULL;
    char const* scenario = "=x:s30:n2:10;";
    uint8_t bytes[30];

    memset(bytes, 0, sizeof(bytes));

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, "perf", &simulated_time, NULL, NULL, 0, 1, 0, NULL);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0 && (ctx = quicperf_create_ctx(scenario, NULL)) == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        quicperf_stream_ctx_t* stream_ctx = quicperf_create_stream_ctx(ctx, 0);

        if (stream_ctx == NULL) {
            ret = -1;
        }
        else {
            stream_ctx->stream_desc_index = 0;
            stream_ctx->nb_frames = 2;
            stream_ctx->frame_size = 10;
            stream_ctx->first_frame_size = 10;

            /* 30 bytes = 3 frames' worth, but only 2 frames were declared. */
            quicperf_receive_media_data(test_ctx->cnx_client, ctx, stream_ctx,
                bytes, sizeof(bytes), picoquic_callback_stream_data);

            if (stream_ctx->nb_frames_received != 2) {
                DBG_PRINTF("Expected 2 frames received, got %" PRIu64 " -- extra bytes past the last frame were counted",
                    stream_ctx->nb_frames_received);
                ret = -1;
            }
        }
    }

    if (ctx != NULL) {
        quicperf_delete_ctx(ctx);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* Internal quicperf.c function, not part of the public quicperf.h API,
 * needed to check tree membership for the test below. */
quicperf_stream_ctx_t* quicperf_find_stream_ctx(quicperf_ctx_t* ctx, uint64_t stream_id);

int quicperf_server_timer_leak_test(void)
{
    /* Verfiy that quicperf_server_timer deletes all the streams that
    * for which is_closed is set, and not just the first one. The current call
    * graph only calls this function when exactly one stream needs to be 
    * closed, but the graph could change in the future and we want to
    * be robust. */
    int ret = 0;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    quicperf_ctx_t* ctx = NULL;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, "perf", &simulated_time, NULL, NULL, 0, 1, 0, NULL);

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0 && test_ctx->cnx_server == NULL) {
        DBG_PRINTF("%s", "No server connection after handshake");
        ret = -1;
    }

    if (ret == 0 && (ctx = quicperf_create_ctx(NULL, NULL)) == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        quicperf_stream_ctx_t* ctx_a = quicperf_create_stream_ctx(ctx, 0);
        quicperf_stream_ctx_t* ctx_b = quicperf_create_stream_ctx(ctx, 4);

        if (ctx_a == NULL || ctx_b == NULL) {
            ret = -1;
        }
        else {
            ctx_a->is_closed = 1;
            ctx_b->is_closed = 1;

            ret = quicperf_server_timer(test_ctx->cnx_server, ctx, 100);

            if (ret == 0 &&
                (quicperf_find_stream_ctx(ctx, 0) != NULL || quicperf_find_stream_ctx(ctx, 4) != NULL)) {
                DBG_PRINTF("%s", "One closed stream context leaked: only the last one found was deleted");
                ret = -1;
            }
        }
    }

    if (ctx != NULL) {
        quicperf_delete_ctx(ctx);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int quicperf_chain_test(void)
{
    /* Scenario "b" names scenario "a" as its "previous stream", so "b" should
     * only start after "a" has completed. */
    char const* chain_scenario = "=a:s30:p2:S:n60:18000;=b:=a:s30:p2:S:n60:18000;";
    quicperf_test_target_t chain_target[2] = {
        {
            60, /* nb_frames_received_min */
            60, /* nb_frames_received_max */
            0, 0, 0, 0
        },
        {
            60, /* nb_frames_received_min */
            60, /* nb_frames_received_max */
            0, 0, 0, 0
        }
    };

    return quicperf_e2e_test(0x1b, chain_scenario, 6000000, 2, chain_target);
}

int quicperf_print_report_test(void)
{
    /* quicperf_print_report used to stop after printing the first non-batch
     * scenario: the loop guard is "ret == 0", but the final fprintf(F, ".\n")
     * was OR'ed into ret without the "<= 0" check used by the other fprintf
     * calls in the same loop. fprintf returns the number of bytes written
     * (2, for ".\n") on success, so ret became nonzero right after the first
     * scenario printed successfully, silently dropping every later scenario
     * from the report -- e.g. a chained stream that both ran and completed
     * correctly would never show up in the printed output. */
    int ret = 0;
    char const* chain_scenario = "=a:s30:p2:S:n60:18000;=b:=a:s30:p2:S:n60:18000;";
    char const* file_name = "quicperf_print_report_test.tmp";
    quicperf_ctx_t* ctx = quicperf_create_ctx(chain_scenario, NULL);
    FILE* F = NULL;

    if (ctx == NULL) {
        return -1;
    }

    for (size_t i = 0; i < ctx->nb_scenarios; i++) {
        ctx->reports[i].nb_frames_received = ctx->scenarios[i].nb_frames;
    }

    F = picoquic_file_open(file_name, "w+");
    if (F == NULL) {
        quicperf_delete_ctx(ctx);
        return -1;
    }

    (void)quicperf_print_report(F, ctx);

    {
        char line[256];
        int nb_lines_found = 0;

        rewind(F);
        while (fgets(line, sizeof(line), F) != NULL) {
            if (strstr(line, "Quicperf scenario") != NULL) {
                nb_lines_found++;
            }
        }
        if (nb_lines_found != (int)ctx->nb_scenarios) {
            DBG_PRINTF("Expected %zu report lines, got %d", ctx->nb_scenarios, nb_lines_found);
            ret = -1;
        }
    }

    (void)picoquic_file_close(F);
    (void)remove(file_name);
    quicperf_delete_ctx(ctx);

    return ret;
}

int quicperf_multi_test(void)
{
    char const* multi_scenario = "=a1:d50:p2:S:n250:80; \
     = vlow: s30 :p4:S:n150 : 3750 : G30 : I37500; \
     = vmid: s30 :p6:S:n150 : 6250 : G30 : I62500 : D250000;";
    quicperf_test_target_t multi_target[] = {
        {
        250, /* nb_frames_received_min */
        250, /* nb_frames_received_max */
        20000, /* average_delay_min */
        28000, /* average_delay_max */
        100000, /* max_delay */
        20000, /* min_delay */
        },
        {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        40000, /* average_delay_max */
        66000, /* max_delay */
        20000, /* min_delay */
        },
        {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        40000, /* average_delay_max */
        133000, /* max_delay */
        20000, /* min_delay */
        }
    };

    return quicperf_e2e_test(0x17, multi_scenario, 6000000, 3, multi_target);
}

int quicperf_overflow_test(void)
{
    char const* overflow_scenario = "=a1:d50:p2:S:n250:80; \
     = vlow: s30 :p4:S:n150 : 3750 : G30 : I37500; \
     = vmid: s30 :p6:S:n150 : 6250 : G30 : I62500 : D300000; \
     = vhi:*3 : s30 :p8:S: n150 : 12500 : G150 : I125000 : D250000;";
    quicperf_test_target_t overflow_target[] = {
        {
        250, /* nb_frames_received_min */
        250, /* nb_frames_received_max */
        20000, /* average_delay_min */
        40000, /* average_delay_max */
        100000, /* max_delay */
        20000, /* min_delay */
        },
        {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        40000, /* average_delay_max */
        100000, /* max_delay */
        20000, /* min_delay */
        },
        {
        150, /* nb_frames_received_min */
        150, /* nb_frames_received_max */
        20000, /* average_delay_min */
        45000, /* average_delay_max */
        120000, /* max_delay */
        20000, /* min_delay */
        },
        {
        3, /* nb_frames_received_min */
        24, /* nb_frames_received_max */
        20000, /* average_delay_min */
        650000, /* average_delay_max */
        750000, /* max_delay */
        20000, /* min_delay */
        }
    };

    return quicperf_e2e_test(0xf1, overflow_scenario, 6000000, 4, overflow_target);
}

/* Multipath race reproduction.
 *
 * A field report described quicperf over a multipath connection (picoquicdemo
 * client started with -M and an alt-path config) stalling right after the
 * handshake completes, about half the time: second-path setup appeared to
 * race the quicperf scenario start, both endpoints settled into 10s polling,
 * and no application data ever flowed.
 *
 * quicperf's own scenario start and the earliest legal moment to probe a new
 * path are both gated on the same condition -- cnx_state reaching
 * picoquic_state_client_almost_ready -- but from two independent code paths
 * with no ordering guarantee between them (see quicperf_callback vs.
 * picoquicdemo's client_loop_cb / picoquic_check_new_path_allowed). These
 * tests use a single small batch scenario: if the connection stalls at all,
 * no data flows regardless of scenario type, so a minimal transfer is enough
 * to detect it. The existing 10-second no-interaction check inside
 * quicperf_e2e_test_ex already fails the test if the stall reproduces --
 * matching the field report's own "10 s polling" symptom -- so no extra
 * detection logic is required.
 */
static char const* quicperf_mp_scenario = "=b1:1000:100000;";
static quicperf_test_target_t quicperf_mp_target = { 0, 0, 0, 0, 0, 0 };

int quicperf_multipath_race_test(void)
{
    /* Tightest race: retry the probe starting at the first round where
     * cnx_state >= almost_ready, exactly like picoquicdemo does. */
    return quicperf_e2e_test_multipath(0x1d, quicperf_mp_scenario, 5000000, 1, &quicperf_mp_target,
        quicperf_mp_probe_immediate, 0);
}

int quicperf_multipath_race_delayed_test(void)
{
    /* Give quicperf's scenario a 10ms head start before the first probe
     * attempt, to see whether the race window is that wide. */
    return quicperf_e2e_test_multipath(0x1e, quicperf_mp_scenario, 5000000, 1, &quicperf_mp_target,
        quicperf_mp_probe_delayed, 10000);
}

int quicperf_multipath_settled_test(void)
{
    /* Negative control: fully validate the second path (as every other
     * multipath test does) before anything else is allowed to contend with
     * it. This should always succeed; if it doesn't, the bug isn't about
     * ordering. */
    return quicperf_e2e_test_multipath(0x1f, quicperf_mp_scenario, 5000000, 1, &quicperf_mp_target,
        quicperf_mp_probe_settled, 0);
}

/* Loopback performance test.
 *
 * Goal: profile the "prepare next packet" sending path -- picoquic_prepare_next_packet_ex,
 * picoquic_prepare_segment, picoquic_prepare_packet_ready -- without the cost or noise of
 * an actual socket, or of the simulated-link machinery used by the rest of this file
 * (queueing, bandwidth/propagation model, NAT rewriting, etc).
 *
 * Packets are never queued or delayed: each call to picoquic_prepare_next_packet_ex is
 * immediately followed by a call to picoquic_incoming_packet_ex feeding the produced bytes
 * back into the very same context, which dispatches them to the right connection by CID.
 * There is no simulated bandwidth or propagation delay -- the two connections just run as
 * fast as the host CPU can prepare, protect and process packets.
 *
 * The QUIC clock still needs to move forward, for pacing, loss timers, etc. When neither
 * connection has anything ready to send, the clock jumps straight to
 * picoquic_get_next_wake_time(). When a packet is handed off, the clock is nudged forward by
 * a single microsecond -- just enough to keep timestamps strictly increasing and RTT samples
 * away from a degenerate zero, without adding any artificial delay of consequence. Using a
 * simulated clock instead of the real one keeps the test fast and repeatable -- it runs at
 * whatever speed the host CPU can prepare and process packets, not at wall-clock speed.
 * 
 * This simplified clock does not play well with classic congestion control algorithms like
 * Reno, Cubic, etc. Instead, we use a simple "fixed window" algorithm to ensure that
 * the congestion window is sufficient to get proper packet trains and
 * thus realistic CPU estimates. 
 *
 * The client runs a quicperf "batch" scenario asking for a large download (e.g., 10GB),
 * which puts the load on the server's sending path -- the part of the code this test is
 * meant to profile.
 */

#define PERF_LOOPBACK_TEST_RESPONSE_SIZE 1000000
#define PERF_LOOPBACK_MAX_LOOPS 100000000
#define PERF_LOOPBACK_MAX_TIME 300000000ull /* 300 simulated seconds, safety net against a stall */
#define PERF_LOOPBACK_SEND_BUFFER_SIZE 65536 /* 64KB: large enough to let prepare_next_packet_ex
                                               * batch several UDP datagrams in one call (GSO) */

/* Response size used by perf_loopback_test, in bytes. Kept small by default (1MB) so the
 * regular test suite stays fast; picohttp_t accepts a "-p nnn" option to run a bigger
 * transfer (e.g. 10GB) when the point is to actually profile the sending path rather than
 * just exercise it. */
uint64_t picohttp_perf_loopback_size = PERF_LOOPBACK_TEST_RESPONSE_SIZE;

/* "Fixed window" congestion control, for use in the following performance test:
 * ensure that the congestion window is kept at a large static value.
 * Defined as static functions here because this algorithm should not be used in production.
 */
#define PERF_LOOPBACK_FIXEDCWIN_VALUE (128 * 1024)

static void perf_loopback_fixedcwin_set(picoquic_path_t* path_x)
{
    path_x->cwin = PERF_LOOPBACK_FIXEDCWIN_VALUE;
    path_x->is_ssthresh_initialized = 1;
    picoquic_update_pacing_data(path_x, 0);
}

static void perf_loopback_fixedcwin_init(picoquic_path_t* path_x, char const* UNUSED(option_string), uint64_t UNUSED(current_time))
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(option_string);
    UNREFERENCED_PARAMETER(current_time);
#endif
    /* Stateless: there is nothing to track between calls, cwin is always the same fixed
     * value regardless of what happens on the path. */
    path_x->congestion_alg_state = NULL;
    perf_loopback_fixedcwin_set(path_x);
}

static void perf_loopback_fixedcwin_notify(
    picoquic_cnx_t* UNUSED(cnx),
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_per_ack_state_t* UNUSED(ack_state),
    uint64_t UNUSED(current_time))
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx);
    UNREFERENCED_PARAMETER(ack_state);
    UNREFERENCED_PARAMETER(current_time);
#endif
    /* Every notification -- acknowledgement, repeat, timeout, ecn, spurious repeat, rtt
     * measurement, cwin_blocked, seed_cwin, reset, lost_feedback, restart_from_idle -- is
     * treated the same way: none of them are allowed to move cwin. This is deliberately
     * not a switch on `notification`: there is no case that should do anything different. */
    (void)notification;
    path_x->is_cc_data_updated = 1;
    perf_loopback_fixedcwin_set(path_x);
}

static void perf_loopback_fixedcwin_delete(picoquic_path_t* UNUSED(path_x))
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(path_x);
#endif
    /* Nothing was allocated in perf_loopback_fixedcwin_init. */
}

static void perf_loopback_fixedcwin_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    *cc_state = 0;
    *cc_param = path_x->cwin;
}

#define PERF_LOOPBACK_FIXEDCWIN_ID "perf_loopback_fixedcwin"

static picoquic_congestion_algorithm_t perf_loopback_fixedcwin_algorithm_struct = {
    PERF_LOOPBACK_FIXEDCWIN_ID, 0, PICOQUIC_ECN_ECT_0,
    perf_loopback_fixedcwin_init,
    perf_loopback_fixedcwin_notify,
    perf_loopback_fixedcwin_delete,
    perf_loopback_fixedcwin_observe
};

static picoquic_congestion_algorithm_t* perf_loopback_fixedcwin_algorithm = &perf_loopback_fixedcwin_algorithm_struct;

/* Same rotating-bitmask loss idiom as picoquictest_sim_link_testloss in sim_link.c, kept
 * local since perf_loopback bypasses sim_link entirely and that function is file-static. */
static int perf_loopback_testloss(uint64_t* loss_mask)
{
    uint64_t loss_bit = 0;

    if (loss_mask != NULL) {
        loss_bit = (uint64_t)((*loss_mask) & 1ull);
        *loss_mask >>= 1;
        *loss_mask |= (loss_bit << 63);
    }

    return (int)loss_bit;
}

static int perf_loopback_test_one(uint64_t response_size, uint64_t loss_mask, uint64_t* p_wall_time_us, uint64_t* p_nb_packets)
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_cnx_t* cnx_server = NULL; /* discovered as first connection that is not the client connection */
    quicperf_ctx_t* quicperf_ctx = NULL;
    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    char scenario[128];
    uint8_t* send_buffer = NULL;
    uint64_t nb_packets = 0;
    uint64_t nb_packets_lost = 0;
    uint64_t nb_client_packets = 0;
    uint64_t nb_server_packets = 0;
    uint64_t nb_batches = 0;
    uint64_t nb_bytes = 0;
    uint64_t nb_stall_jumps = 0;
    uint64_t wall_start = 0;
    uint64_t wall_end = 0;
    int nb_loops = 0;

    if ((ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file),
        picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT)) != 0 ||
        (ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY)) != 0 ||
        (ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file),
            picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE)) != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
        return -1;
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_port = 1234;
#ifdef _WINDOWS
    client_addr.sin_addr.S_un.S_addr = htonl(0x0A000002);
#else
    client_addr.sin_addr.s_addr = htonl(0x0A000002);
#endif

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = 4321;
#ifdef _WINDOWS
    server_addr.sin_addr.S_un.S_addr = htonl(0x0A000001);
#else
    server_addr.sin_addr.s_addr = htonl(0x0A000001);
#endif
    (void)client_addr; /* not otherwise referenced: the addresses only need to be distinct */

    /* A single context plays both the client and the server roles. */
    quic = picoquic_create(8,
        test_server_cert_file, test_server_key_file, test_server_cert_store_file,
        QUICPERF_ALPN, quicperf_callback, NULL, NULL, NULL, NULL,
        simulated_time, &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        DBG_PRINTF("%s", "Could not create the perf loopback QUIC context.\n");
        return -1;
    }

    /* Set as the default for the context, before creating any connection */
    picoquic_set_default_congestion_algorithm(quic, perf_loopback_fixedcwin_algorithm);

    /* No qlog, no binlog: this is meant to measure the sending path itself, not I/O. */
    picoquic_set_random_initial(quic, 0);

    (void)snprintf(scenario, sizeof(scenario), "=b1:*1:1000:%" PRIu64 ";", response_size);

    if ((quicperf_ctx = quicperf_create_ctx(scenario, stderr)) == NULL) {
        DBG_PRINTF("Could not parse scenario <%s>\n", scenario);
        picoquic_free(quic);
        return -1;
    }

    cnx_client = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
        (struct sockaddr*)&server_addr, simulated_time, 0, PICOQUIC_TEST_SNI, QUICPERF_ALPN, 1);

    if (cnx_client == NULL) {
        DBG_PRINTF("%s", "Could not create the perf loopback client connection.\n");
        quicperf_delete_ctx(quicperf_ctx);
        picoquic_free(quic);
        return -1;
    }

    picoquic_set_callback(cnx_client, quicperf_callback, quicperf_ctx);

    if ((ret = picoquic_start_client_cnx(cnx_client)) != 0) {
        DBG_PRINTF("Could not start the client connection, ret = %d\n", ret);
    }

    /* Allocated on the heap rather than kept as a stack array. */
    send_buffer = (uint8_t*)malloc(PERF_LOOPBACK_SEND_BUFFER_SIZE);

    if (send_buffer == NULL) {
        DBG_PRINTF("%s", "Could not allocate the perf loopback send buffer.\n");
        quicperf_delete_ctx(quicperf_ctx);
        picoquic_free(quic);
        return -1;
    }

    wall_start = picoquic_current_time();

    while (ret == 0 && nb_loops < PERF_LOOPBACK_MAX_LOOPS &&
        simulated_time < PERF_LOOPBACK_MAX_TIME &&
        picoquic_get_cnx_state(cnx_client) != picoquic_state_disconnected) {
        struct sockaddr_storage addr_to;
        struct sockaddr_storage addr_from;
        int if_index = 0;
        picoquic_connection_id_t log_cid;
        picoquic_cnx_t* last_cnx = NULL;
        picoquic_cnx_t* first_cnx = NULL;
        size_t send_length = 0;
        size_t send_msg_size = 0;

        nb_loops++;

        ret = picoquic_prepare_next_packet_ex(quic, simulated_time, send_buffer, PERF_LOOPBACK_SEND_BUFFER_SIZE,
            &send_length, &addr_to, &addr_from, &if_index, &log_cid, &last_cnx, &send_msg_size);

        if (ret != 0) {
            DBG_PRINTF("Prepare packet returned %d\n", ret);
            break;
        }

        if (last_cnx != NULL && last_cnx != cnx_client && cnx_server == NULL) {
            cnx_server = last_cnx;
        }

        if (send_length > 0) {
            size_t segment_size = (send_msg_size == 0 || send_msg_size > send_length) ? send_length : send_msg_size;
            size_t sent_so_far = 0;
            uint8_t* segment_bytes = send_buffer;

            nb_batches++;

            while (ret == 0 && sent_so_far < send_length) {
                size_t this_length = send_length - sent_so_far;
                if (this_length > segment_size) {
                    this_length = segment_size;
                }

                nb_packets++;
                nb_bytes += this_length;
                if (last_cnx == cnx_client) {
                    nb_client_packets++;
                }
                else {
                    nb_server_packets++;
                }

                /* Deliver the packet right away: no queue, no delay. Just nudge the
                 * clock by one microsecond so timestamps stay strictly increasing and
                 * RTT samples never land on exactly zero. */
                simulated_time += 1;

                if (perf_loopback_testloss(&loss_mask)) {
                    /* Simulated loss: the packet was "sent" (already counted above,
                     * same as a real dropped packet would be) but never delivered. */
                    nb_packets_lost++;
                }
                else {
                    ret = picoquic_incoming_packet_ex(quic, segment_bytes, this_length,
                        (struct sockaddr*)&addr_from, (struct sockaddr*)&addr_to, if_index, 0,
                        &first_cnx, simulated_time);

                    if (ret != 0) {
                        DBG_PRINTF("Incoming packet returned %d\n", ret);
                        break;
                    }
                }

                segment_bytes += this_length;
                sent_so_far += this_length;
            }
        }
        else {
            uint64_t next_time = picoquic_get_next_wake_time(quic, simulated_time);

            if (next_time <= simulated_time) {
                next_time = simulated_time + 1;
            }
            simulated_time = next_time;
            nb_stall_jumps++;
        }

        /* Safety net in case a future scenario type does not self-close like this one does. */
        if (ret == 0 && quicperf_ctx->nb_open_streams == 0 &&
            picoquic_get_cnx_state(cnx_client) == picoquic_state_ready &&
            picoquic_is_cnx_backlog_empty(cnx_client)) {
            ret = picoquic_close(cnx_client, 0);
        }
    }

    wall_end = picoquic_current_time();

    if (ret == 0 && picoquic_get_cnx_state(cnx_client) != picoquic_state_disconnected) {
        DBG_PRINTF("%s", "Perf loopback test did not reach a clean disconnect.\n");
        ret = -1;
    }

    if (ret == 0 && quicperf_ctx->data_received < response_size) {
        DBG_PRINTF("Received only %" PRIu64 " of %" PRIu64 " requested bytes\n",
            quicperf_ctx->data_received, response_size);
        ret = -1;
    }

    fprintf(stdout, "Perf loopback: %" PRIu64 " app bytes, %" PRIu64 " wire bytes, %" PRIu64
        " packets (%" PRIu64 " client, %" PRIu64 " server, %" PRIu64 " lost), %" PRIu64 " batches, %" PRIu64 " stall jumps, in %" PRIu64 " us.\n",
        quicperf_ctx->data_received, nb_bytes, nb_packets, nb_client_packets, nb_server_packets,
        nb_packets_lost, nb_batches, nb_stall_jumps, wall_end - wall_start);

    if (wall_end > wall_start) {
        double seconds = (double)(wall_end - wall_start) / 1000000.0;
        double us_per_packet = (nb_packets == 0) ? 0.0 :
            (double)(wall_end - wall_start) / (double)nb_packets;
        double packets_per_batch = (nb_batches == 0) ? 0.0 : (double)nb_packets / (double)nb_batches;

        fprintf(stdout, "Perf loopback: %.3f seconds, %.1f MB/s, %.0f packets/s, %.3f us/packet, %.2f packets/batch.\n",
            seconds, ((double)nb_bytes / (1024.0 * 1024.0)) / seconds,
            (double)nb_packets / seconds, us_per_packet, packets_per_batch);
    }

    if (p_wall_time_us != NULL) {
        *p_wall_time_us = wall_end - wall_start;
    }
    if (p_nb_packets != NULL) {
        *p_nb_packets = nb_packets;
    }

    free(send_buffer);
    quicperf_delete_ctx(quicperf_ctx);
    picoquic_free(quic);

    return ret;
}

int perf_loopback_test(void)
{
    uint64_t wall_time_us = 0;
    uint64_t nb_packets = 0;

    return perf_loopback_test_one(picohttp_perf_loopback_size, 0, &wall_time_us, &nb_packets);
}

/* Same scenario, but with a single bit set in the rotating loss mask: one packet in 64
 * (~1.6%) is dropped in each direction, deterministically and reproducibly, to exercise
 * the sack-list code paths that perf_loopback's loss-free run never reaches -- multiple
 * concurrent ranges, merges, and duplicate-after-retransmission checks. */
int perf_loopback_loss_test(void)
{
    uint64_t wall_time_us = 0;
    uint64_t nb_packets = 0;

    return perf_loopback_test_one(picohttp_perf_loopback_size, 1, &wall_time_us, &nb_packets);
}
