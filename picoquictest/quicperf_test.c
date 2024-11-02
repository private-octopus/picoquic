#include "picoquic_internal.h"
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
    quicperf_ctx_t* ctx = quicperf_create_ctx(tl->str);
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

int quicperf_parse_test()
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

#if 0
/* Generic function definition for the test parser
* We start with a set of messages (e.g., commands or responses)
* encode them as a string of octets, and
* verify that they can be parsed and decoded
* correctly.
 */

typedef size_t (*test_msg_format_fn)(uint8_t* buffer, size_t length, size_t msg_index);
typedef int (*test_msg_parse_fn)(uint8_t* msg, size_t msg_length, size_t msg_index);

int quicperf_parse_buffer_interval_test(uint8_t* buffer, size_t length, size_t interval, test_msg_parse_fn test_parse)
{
    int ret = 0;
    size_t msg_index = 0;
    size_t nb_processed = 0;
    uint8_t msg[256];
    uint8_t bytes_received = 0;
    uint8_t msg_length = 0;

    while (ret == 0 && nb_processed < length) {
        size_t data_read = 0;
        size_t available = interval;
        if (nb_processed + interval > length) {
            available = length - nb_processed;
        }

        while (ret == 0 && data_read < available) {
            size_t nb_read = quicperf_accumulate_buffer(buffer + nb_processed + data_read, available - data_read, &msg_length, &bytes_received, msg, sizeof(msg));
            if (nb_read > available || nb_read == 0) {
                ret = -1;
            }
            else if (msg_length == 0) {
                ret = -1;
            }
            else if (bytes_received > msg_length) {
                ret = -1;
            }
            else {
                data_read += nb_read;
                if (bytes_received == msg_length) {
                    /* Process the message */
                    ret = test_parse(msg, bytes_received, msg_index);
                    /* increment the message count. */
                    msg_index++;
                    msg_length = 0;
                    bytes_received = 0;
                }
            }
        }
        nb_processed += available;
    }
    if (ret == 0 && msg_length > 0) {
        ret = -1;
    }
    return ret;
}

static const size_t test_intervals[] = { 255, 1, 2, 3, 5, 7, 11 };
static const nb_test_intervals = sizeof(test_intervals) / sizeof(size_t);

static int quicperf_parse_buffer_test(uint8_t* buffer, size_t length, test_msg_parse_fn test_parse)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_test_intervals; i++) {
        ret = quicperf_parse_buffer_interval_test(buffer, length, test_intervals[i], test_parse);
    }

    return ret;
}

int quicperf_parse_msg_test(test_msg_parse_fn test_parse, test_msg_format_fn test_format, int nb_test_msg)
{
    int ret = 0;
    /* Fixed size buffer, more than enough for the test commands. */
    uint8_t buffer[1024];
    size_t next_write = 0;

    /* Encode the test commands */
    for (size_t i = 0; ret == 0 && i < nb_test_msg; i++) {
        size_t length = test_format(buffer + next_write + 1, sizeof(buffer) - next_write - 1, i);
        if (length == 0 || length >= 256) {
            ret = -1;
        }
        else {
            buffer[next_write] = (uint8_t)length;
            next_write += length + 1;
        }
    }

    /* Do a test parsing with various read intervals */
    if (ret == 0) {
        ret = quicperf_parse_buffer_test(buffer, next_write, test_parse);
    }
    return ret;
}

/* Test the command format, instantiating
* the generic functions.
 */

static const quicperf_media_command_t test_cmd[] = {
    { 0, 3, 0, 30, 15000, 1000, 0, 0 },
    { 1, 5, 0, 30, 15000, 1000, 150, 10000 },
    { 2, 1, 1, 50, 25000, 80, 0, 0 }
};
static const nb_test_cmd = sizeof(test_cmd) / sizeof(quicperf_media_command_t);

int quicperf_compare_cmd(const quicperf_media_command_t* cmd1, const quicperf_media_command_t* cmd2)
{
    int ret = 0;

    if (cmd1->media_stream_id != cmd2->media_stream_id ||
        cmd1->priority != cmd2->priority ||
        cmd1->media_type != cmd2->media_type ||
        cmd1->frequency != cmd2->frequency ||
        cmd1->number_of_frames != cmd2->number_of_frames ||
        cmd1->frame_size != cmd2->frame_size ||
        cmd1->frames_per_group != cmd2->frames_per_group ||
        cmd1->first_frame_size != cmd2->first_frame_size) {
        ret = -1;
    }
    return ret;
}

static int quicperf_parse_cmd_buffer_test(uint8_t* msg, size_t msg_length, size_t msg_index)
{
    int ret = 0;
    quicperf_media_command_t cmd;
    size_t parsed = quicperf_parse_media_command(msg, msg_length, &cmd);

    if (parsed == SIZE_MAX) {
        ret = -1;
    }
    else {
        ret = quicperf_compare_cmd(&cmd, &test_cmd[msg_index]);
    }

    return ret;
}

static size_t quicperf_format_cmd_test(uint8_t* buffer, size_t length, size_t test_index)
{
    return quicperf_format_media_command(buffer, length, &test_cmd[test_index]);
}

int quicperf_parse_cmd_test()
{
    return quicperf_parse_msg_test(quicperf_parse_cmd_buffer_test, quicperf_format_cmd_test, nb_test_cmd);
}


/* Test the report format, instantiating
* the generic functions.
 */

static const quicperf_media_report_t test_rpt[] = {
    { 0, 0, 0, 1000, 2000 },
    { 1, 0, 0, 1010, 2200 },
    { 1, 0, 1, 33000, 35200 },
    { 1, 0, 2, 66010, 68200 }
};
static const nb_test_rpt = sizeof(test_rpt) / sizeof(quicperf_media_report_t);

int quicperf_compare_rpt(const quicperf_media_report_t* rpt1, const quicperf_media_report_t* rpt2)
{
    int ret = 0;

    if (rpt1->media_stream_id != rpt2->media_stream_id ||
        rpt1->group_id != rpt2->group_id ||
        rpt1->frame_id != rpt2->frame_id ||
        rpt1->client_time_stamp != rpt2->client_time_stamp ||
        rpt1->server_time_stamp != rpt2->server_time_stamp) {
        ret = -1;
    }
    return ret;
}

static int quicperf_parse_rpt_buffer_test(uint8_t* msg, size_t msg_length, size_t msg_index)
{
    int ret = 0;
    quicperf_media_report_t rpt;
    size_t parsed = quicperf_parse_media_report(msg, msg_length, &rpt);

    if (parsed == SIZE_MAX) {
        ret = -1;
    }
    else {
        ret = quicperf_compare_rpt(&rpt, &test_rpt[msg_index]);
    }

    return ret;
}

static size_t quicperf_format_rpt_test(uint8_t* buffer, size_t length, size_t test_index)
{
    return quicperf_format_media_report(buffer, length, &test_rpt[test_index]);
}

int quicperf_parse_rpt_test()
{
    return quicperf_parse_msg_test(quicperf_parse_rpt_buffer_test, quicperf_format_rpt_test, nb_test_rpt);
}

#endif

char const* quicperf_test_scenario = "=v1:s30:n4:100;";

int quicperf_e2e_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    quicperf_ctx_t  *quicperf_ctx;
    int ret = 0;
    uint64_t completion_target = 5000000;
    picoquic_connection_id_t initial_cid = { {0xde, 0xc1, 3, 4, 5, 6, 7, 8}, 8 };


    quicperf_ctx = quicperf_create_ctx(quicperf_test_scenario);
    if (quicperf_ctx == NULL) {
        DBG_PRINTF("Could not get ready to run QUICPERF\n");
        return -1;
    }
    else {

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
        // picoquic_set_alpn_select_fn(test_ctx->qserver, picoquic_demo_server_callback_select_alpn);
        picoquic_set_default_callback(test_ctx->qserver, quicperf_callback, NULL);
        picoquic_set_callback(test_ctx->cnx_client, quicperf_callback, quicperf_ctx);
        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
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
            picoquic_is_cnx_backlog_empty(test_ctx->cnx_client)) {
            if (quicperf_ctx->nb_open_streams == 0) {
                ret = picoquic_close(test_ctx->cnx_client, 0);
            }
            else if (simulated_time > quicperf_ctx->last_interaction_time &&
                simulated_time - quicperf_ctx->last_interaction_time > 10000000ull) {
                (void)picoquic_close(test_ctx->cnx_client, 0);
                ret = -1;
            }
        }
        if (++nb_trials > 100000) {
            ret = -1;
            break;
        }
    }

#if 0
    /* Verify that the data was properly received. */
    for (size_t i = 0; ret == 0 && i < nb_scenario; i++) {
        picoquic_demo_client_stream_ctx_t* stream = callback_ctx.first_stream;

        while (stream != NULL && stream->stream_id != demo_scenario[i].stream_id) {
            stream = stream->next_stream;
        }

        if (stream == NULL) {
            DBG_PRINTF("Scenario stream %d is missing\n", (int)i);
            ret = -1;
        }
        else if (stream->F != NULL) {
            DBG_PRINTF("Scenario stream %d, file was not closed\n", (int)i);
            ret = -1;
        }
        else if (stream->received_length < demo_length[i]) {
            DBG_PRINTF("Scenario stream %d, only %d bytes received\n",
                (int)i, (int)stream->received_length);
            ret = -1;
        }
        else if (stream->post_sent < demo_scenario[i].post_size) {
            DBG_PRINTF("Scenario stream %d, only %d bytes sent\n",
                (int)i, (int)stream->post_sent);
            ret = -1;
        }
    }
#endif

    if (ret == 0 && completion_target != 0) {
        if (simulated_time > completion_target) {
            DBG_PRINTF("Test uses %llu microsec instead of %llu", simulated_time, completion_target);
            ret = -1;
        }
    }

    if (ret == 0 && test_ctx->qclient->nb_data_nodes_allocated > test_ctx->qclient->nb_data_nodes_in_pool) {
        ret = -1;
    }
    else if (ret == 0 && test_ctx->qserver->nb_data_nodes_allocated > test_ctx->qserver->nb_data_nodes_in_pool) {
        ret = -1;
    }

    quicperf_delete_ctx(quicperf_ctx);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}