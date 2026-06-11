/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "picoquic_unified_log.h"
#include "autoqlog.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "demoserver.h"
#include "pico_webtransport.h"
#include "wt_baton.h"

#ifdef _WINDOWS
#include "wincompat.h"
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

/*
* The web transport unit tests are based on the "baton" protocol
* which is also used for interop testing. 
* TODO: the current protocol is limited. It does not test sending
* large volume of data, sending large number of streams, or
* sending datagrams. Consider extensions!
*/
int picowt_connect_ex(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx, h3zero_stream_ctx_t* stream_ctx,
    const char* authority, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx,
    char const* wt_available_protocols, uint8_t* extra, size_t extra_length);

wt_baton_app_ctx_t baton_test_ctx = {
    .nb_turns_required = 15
};

picohttp_server_path_item_t path_item_list[1] =
{
    {
        .path = "/baton",
        .path_length = 6,
        .path_callback = wt_baton_callback,
        .path_app_ctx = &baton_test_ctx,
        .connect_protocol = H3ZERO_WEBTRANSPORT_H3_PROTOCOL,
        .connect_protocol_length = sizeof(H3ZERO_WEBTRANSPORT_H3_PROTOCOL) - 1,
        .origin_validator = h3zero_origin_validator_allow_all
    }
};

static int picowt_baton_test_reset(wt_baton_ctx_t * baton_ctx, int* reset_needed)
{
    int ret = 0;

    /* Check whether there is already a lane assigned to that stream */
    for (size_t i = 0; i < baton_ctx->nb_lanes; i++) {
        if (baton_ctx->lanes[i].baton_state == wt_baton_state_sending) {
            /* Found a reset target, look for stream context */
            h3zero_stream_ctx_t* stream_ctx = h3zero_find_stream(baton_ctx->h3_ctx,
                baton_ctx->lanes[i].sending_stream_id);
            if (stream_ctx == NULL) {
                ret = -1;
            } else {
                ret = picowt_reset_stream(baton_ctx->cnx, stream_ctx, 12345);
                *reset_needed = 0;
            }
            break;
        }
    }
    return ret;
}

static int picowt_baton_test_one_ex(
    uint8_t test_id, const char* baton_path,
    uint64_t do_losses, uint64_t completion_target, const char* client_qlog_dir,
    const char* server_qlog_dir, picohttp_server_path_item_t* table, size_t table_nb)
{
    char const* alpn = "h3";
    uint64_t simulated_time = 0;
    uint64_t loss_mask = do_losses;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    wt_baton_ctx_t baton_ctx = { 0 };
    int ret = 0;
    picohttp_server_parameters_t server_param = { 0 };
    picoquic_connection_id_t initial_cid = { {0x77, 0x74, 0xba, 0, 0, 0, 0, 0}, 8 };
    h3zero_callback_ctx_t* h3zero_cb = NULL;
    h3zero_stream_ctx_t* control_stream_ctx = NULL;
    int reset_needed = (test_id == 9);

    initial_cid.id[3] = test_id;

    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, alpn, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

        if (ret == 0 && server_qlog_dir != NULL) {
            picoquic_set_qlog(test_ctx->qserver, server_qlog_dir);
            test_ctx->qserver->use_long_log = 1;
        }

        if (ret == 0 && client_qlog_dir != NULL) {
            picoquic_set_qlog(test_ctx->qclient, client_qlog_dir);
        }

        if (ret == 0) {
            picowt_set_default_transport_parameters(test_ctx->qserver);
            picowt_set_transport_parameters(test_ctx->cnx_client);
        }
    }

    if (ret != 0) {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }
    else if (test_ctx == NULL || test_ctx->cnx_client == NULL) {
        DBG_PRINTF("%s", "Connections where not properly created!\n");
        ret = -1;
    }

    /* The default procedure creates connections using the test callback.
    * We want to replace that by the demo client callback */

    if (ret == 0) {
        /* Set the client callback context using as much as possible
        * the generic picowt calls. */
        ret = picowt_prepare_client_cnx(test_ctx->qclient, (struct sockaddr*)NULL,
            &test_ctx->cnx_client, &h3zero_cb, &control_stream_ctx, simulated_time, PICOQUIC_TEST_SNI);

        if (ret == 0) {
            /* Initialize the server -- should include the path setup for connect action */
            memset(&server_param, 0, sizeof(picohttp_server_parameters_t));
            server_param.web_folder = NULL;
            server_param.path_table = table;
            server_param.path_table_nb = table_nb;

            picoquic_set_alpn_select_fn_v2(test_ctx->qserver, picoquic_demo_server_callback_select_alpn);
            picoquic_set_default_callback(test_ctx->qserver, h3zero_callback, &server_param);
        }

        if (ret == 0) {
            ret = wt_baton_prepare_context(test_ctx->cnx_client, &baton_ctx, h3zero_cb,
                control_stream_ctx, PICOQUIC_TEST_SNI, baton_path);
        }

        if (ret == 0) {
            if (test_id == 8) {
                uint8_t grease_capsule[12] = { 0x00,0x0a,0xc0,0xe9,0x89,0x05,0x97,0xf9,0x46,0xe4,0x01,0x1d };
                ret = picowt_connect_ex(test_ctx->cnx_client, h3zero_cb, control_stream_ctx,
                    baton_ctx.authority, baton_ctx.server_path,
                    wt_baton_callback, &baton_ctx, PICOWT_BATON_ALPN, grease_capsule, 12);
            }
            else {
                ret = picowt_connect(test_ctx->cnx_client, h3zero_cb, control_stream_ctx,
                    baton_ctx.authority, baton_ctx.server_path,
                    wt_baton_callback, &baton_ctx, PICOWT_BATON_ALPN_AVAILABLE);
            }
        }

        if (ret == 0 && !control_stream_ctx->is_connect_pending) {
            DBG_PRINTF("WebTransport CONNECT was not deferred before peer SETTINGS at t: %llu", simulated_time);
            ret = -1;
        }

        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    /* Establish the connection from client to server. At this stage,
    * this is merely an H3 connection.
    */

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0 && !h3zero_cb->settings.settings_received) {
        DBG_PRINTF("Settings not received before WebTransport CONNECT at t: %llu", simulated_time);
        ret = -1;
    }

    if (ret == 0 && control_stream_ctx->is_connect_pending) {
        DBG_PRINTF("WebTransport CONNECT still pending after peer SETTINGS at t: %llu", simulated_time);
        ret = -1;
    }

    /* Simulate the connection from the client side. */
    time_out = simulated_time + 30000000;
    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

        if (ret != 0) {
            DBG_PRINTF("Simulation error detected after %d trials\n", nb_trials);
            break;
        }

        /* logic of web transport scenarios. */
        if (ret == 0 && baton_ctx.nb_turns > 2 && reset_needed) {
            ret = picowt_baton_test_reset(&baton_ctx, &reset_needed);
        }

        if (ret == 0 && ++nb_trials > 100000) {
            DBG_PRINTF("Simulation not concluded after %d trials\n", nb_trials);
            ret = -1;
            break;
        }
    }

    /* Verify that the web transport scenarios were properly executed  */
    if (ret == 0) {
        if (test_id == 3 || test_id == 4 ||
            ((baton_ctx.baton_state == wt_baton_state_done || baton_ctx.baton_state == wt_baton_state_closed) &&
                baton_ctx.nb_turns >= 8 &&
                baton_ctx.lanes_completed == baton_ctx.nb_lanes &&
                baton_ctx.nb_datagrams_sent > 0 && baton_ctx.nb_datagrams_received > 0)) {
            DBG_PRINTF("Baton test succeeds after %d turns, %d datagrams sent, %d received",
                baton_ctx.nb_turns, baton_ctx.nb_datagrams_sent, baton_ctx.nb_datagrams_received);
        }
        else if (test_id == 9 && baton_ctx.baton_state == wt_baton_state_closed) {
            DBG_PRINTF("Baton reset test succeeds after %d turns, %d datagrams sent, %d received",
                baton_ctx.nb_turns, baton_ctx.nb_datagrams_sent, baton_ctx.nb_datagrams_received);
        }
        else {
            DBG_PRINTF("Baton test fails after %d turns, state %d",
                baton_ctx.nb_turns, baton_ctx.baton_state);
            ret = -1;
        }
        if (ret == 0 && test_id == 5 && baton_ctx.lanes[0].first_baton != 33) {
            DBG_PRINTF("On URI test, first baton was %d instead of 33",
                baton_ctx.lanes[0].first_baton);
            ret = -1;
        }
        if (ret == 0 && test_id == 1 && strcmp(baton_ctx.wt_protocol, PICOWT_BATON_ALPN) != 0) {
            DBG_PRINTF("Negotiated WT protocol was %s instead of %s",
                baton_ctx.wt_protocol, PICOWT_BATON_ALPN);
            ret = -1;
        }
    }
    /* Verify that settings were correctly received */
    if (ret == 0 && !h3zero_cb->settings.settings_received) {
        DBG_PRINTF("Settings not received at t: %llu", simulated_time);
        ret = -1;
    }
    /* verify that the execution time is as expected */
    if (ret == 0 && completion_target != 0) {
        if (simulated_time > completion_target) {
            DBG_PRINTF("Test uses %llu microsec instead of %llu", simulated_time, completion_target);
            ret = -1;
        }
    }
    /* verify that the connection was disconnected without error */
    if (ret == 0 &&
        (test_ctx->cnx_client->remote_error != 0 ||
            test_ctx->cnx_client->local_error != 0)) {
        DBG_PRINTF("Connection close error: remote %llu, local %llu",
            test_ctx->cnx_client->remote_error, test_ctx->cnx_client->local_error);
        ret = -1;

    }

    if (h3zero_cb != NULL)
    {
        h3zero_callback_delete_context(test_ctx->cnx_client, h3zero_cb);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

static int picowt_baton_test_one(
    uint8_t test_id, const char* baton_path,
    uint64_t do_losses, uint64_t completion_target, const char* client_qlog_dir,
    const char* server_qlog_dir)
{
    return picowt_baton_test_one_ex(test_id, baton_path, do_losses, completion_target,
        client_qlog_dir, server_qlog_dir, path_item_list, 1);
}

int picowt_baton_basic_test(void)
{
    int ret = picowt_baton_test_one(1, "/baton?baton=240", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_error_test(void)
{
    int ret = picowt_baton_test_one(4, "/baton?inject=1", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_long_test(void)
{
    int ret = picowt_baton_test_one(2, "/baton", 0, 5000000, ".", ".");

    return ret;
}

int picowt_baton_wrong_test(void)
{
    int ret = picowt_baton_test_one(3, "/wrong_baton", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_uri_test(void)
{
    int ret = picowt_baton_test_one(5, "/baton?baton=33", 0, 5000000, ".", ".");

    return ret;
}

int picowt_baton_multi_test(void)
{
    int ret = picowt_baton_test_one(6, "/baton?baton=240&count=4", 0, 5000000, ".", ".");

    return ret;
}

int picowt_baton_random_test(void)
{
    int ret = picowt_baton_test_one(7, "/baton?count=4", 0, 5000000, ".", ".");

    return ret;
}

int picowt_baton_krome_test(void)
{
    int ret = picowt_baton_test_one(8, "/baton?baton=240", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_reset_test(void)
{
    int ret = picowt_baton_test_one(9, "/baton?count=8", 0, 5000000, ".", ".");

    return ret;
}

int picowt_baton_wildcard_test(void)
{
    picohttp_server_path_item_t wildcard_table[1] = {
        {
            .path = "*",
            .path_length = 1,
            .path_callback = wt_baton_callback,
            .connect_protocol = H3ZERO_WEBTRANSPORT_H3_PROTOCOL,
            .connect_protocol_length = sizeof(H3ZERO_WEBTRANSPORT_H3_PROTOCOL) - 1,
            .origin_validator = h3zero_origin_validator_allow_all
        }
    };
    /* /baton is not a specific entry in wildcard_table; the '*' handler must catch it */
    return picowt_baton_test_one_ex(1, "/baton?baton=240", 0, 2000000, ".", ".",
        wildcard_table, 1);
}

static int picowt_noop_callback(picoquic_cnx_t* UNUSED(cnx),
    uint8_t* UNUSED(bytes), size_t UNUSED(length),
    picohttp_call_back_event_t UNUSED(wt_event),
    struct st_h3zero_stream_ctx_t* UNUSED(stream_ctx),
    void* UNUSED(path_app_ctx))
{
    return 0;
}

static int picowt_parse_connect_protocol(uint8_t* frame, h3zero_header_parts_t* header)
{
    uint64_t frame_type = 0;
    uint64_t header_length = 0;
    const uint8_t* bytes = frame;
    const uint8_t* bytes_max = frame + PICOHTTP_SERVER_FRAME_MAX;

    memset(header, 0, sizeof(h3zero_header_parts_t));
    bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_type);
    if (bytes == NULL || frame_type != h3zero_frame_header ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &header_length)) == NULL ||
        bytes + header_length > bytes_max ||
        h3zero_parse_qpack_header_frame((uint8_t*)bytes,
            (uint8_t*)bytes + header_length, header) != bytes + header_length) {
        return -1;
    }

    return 0;
}

static int picowt_connect_protocol_test_one(picoquic_cnx_t* cnx,
    int draft15, const char* expected_protocol)
{
    h3zero_callback_ctx_t h3_ctx = { 0 };
    h3zero_stream_ctx_t* stream_ctx = NULL;
    h3zero_header_parts_t header = { 0 };
    int ret = 0;

    h3zero_init_stream_tree(&h3_ctx.h3_stream_tree);
    h3_ctx.settings.settings_received = 1;
    h3_ctx.settings.h3_datagram = 1;
    if (draft15) {
        h3_ctx.settings.enable_connect_protocol = 1;
        h3_ctx.settings.webtransport_enabled = 1;
    }
    else {
        h3_ctx.settings.webtransport_max_sessions = 1;
    }
    cnx->remote_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
    cnx->remote_parameters.is_reset_stream_at_enabled = 1;

    stream_ctx = picowt_set_control_stream(cnx, &h3_ctx);
    if (stream_ctx == NULL) {
        ret = -1;
    }
    else {
        ret = picowt_connect_ex(cnx, &h3_ctx, stream_ctx, PICOQUIC_TEST_SNI,
            "/baton", picowt_noop_callback, NULL, PICOWT_BATON_ALPN_AVAILABLE, NULL, 0);
    }
    if (ret == 0) {
        ret = picowt_parse_connect_protocol(stream_ctx->frame, &header);
    }
    if (ret == 0 && (header.protocol_length != strlen(expected_protocol) ||
        memcmp(header.protocol, expected_protocol, header.protocol_length) != 0)) {
        ret = -1;
    }

    h3zero_release_header_parts(&header);
    if (stream_ctx != NULL) {
        h3zero_delete_stream(cnx, &h3_ctx, stream_ctx);
    }
    h3zero_delete_all_stream_prefixes(cnx, &h3_ctx);

    return ret;
}

static int picowt_connect_protocol_test(picoquic_cnx_t* cnx)
{
    int ret = picowt_connect_protocol_test_one(cnx, 1, H3ZERO_WEBTRANSPORT_H3_PROTOCOL);

    if (ret == 0) {
        ret = picowt_connect_protocol_test_one(cnx, 0, H3ZERO_WEBTRANSPORT_H3_PROTOCOL_OLD);
    }

    return ret;
}

int picowt_tp_test(void)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    int ret = picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time);

    if (ret == 0) {
        /* Reset the client TP to low values in order to test the picowt function */

        if (cnx->local_parameters.initial_max_data >= 0x3FFF) {
            cnx->local_parameters.initial_max_data = 0x1000;
        }
        if (cnx->local_parameters.initial_max_stream_data_bidi_local >= 0x3FFF) {
            cnx->local_parameters.initial_max_stream_data_bidi_local = 0x1000;
        }
        if (cnx->local_parameters.initial_max_stream_data_bidi_remote >= 0x3FFF) {
            cnx->local_parameters.initial_max_stream_data_bidi_remote = 0x1000;
        }
        if (cnx->local_parameters.initial_max_stream_data_uni >= 0x3FFF) {
            cnx->local_parameters.initial_max_stream_data_uni = 0x1000;
        }
        if (cnx->local_parameters.initial_max_stream_id_bidir >= 0x3F) {
            cnx->local_parameters.initial_max_stream_id_bidir = 0;
        }
        if (cnx->local_parameters.initial_max_stream_id_unidir >= 0x3F) {
            cnx->local_parameters.initial_max_stream_id_unidir = 0;
        }
        if (cnx->local_parameters.max_datagram_frame_size > 0) {
            cnx->local_parameters.max_datagram_frame_size = 0;
        }
        /* Call the setup function */
        picowt_set_transport_parameters(cnx);

        /* verify*/
        if (cnx->local_parameters.initial_max_data < 0x3FFF ||
            cnx->local_parameters.initial_max_stream_data_bidi_local < 0x3FFF ||
            cnx->local_parameters.initial_max_stream_data_bidi_remote < 0x3FFF ||
            cnx->local_parameters.initial_max_stream_data_uni < 0x3FFF ||
            cnx->local_parameters.initial_max_stream_id_bidir < 0x3F ||
            cnx->local_parameters.initial_max_stream_id_unidir < 0x3F ||
            cnx->local_parameters.max_datagram_frame_size == 0) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = picowt_connect_protocol_test(cnx);
    }

    picoquic_set_callback(cnx, NULL, NULL);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int h3zero_set_test_context(picoquic_quic_t** quic, picoquic_cnx_t** cnx, h3zero_callback_ctx_t** h3_ctx, uint64_t* simulated_time);

static uint8_t* picowt_test_format_capsule(uint8_t* bytes, uint8_t* bytes_max,
    uint64_t capsule_type, const uint8_t* payload, size_t payload_length)
{
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, capsule_type)) != NULL &&
        (bytes = picoquic_frames_varlen_encode(bytes, bytes_max, payload_length)) != NULL &&
        payload_length > 0) {
        if (bytes + payload_length > bytes_max) {
            bytes = NULL;
        }
        else {
            memcpy(bytes, payload, payload_length);
            bytes += payload_length;
        }
    }

    return bytes;
}

static int picowt_drain_send_check(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* control_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, control_stream_ctx->stream_id);

    if (stream == NULL || stream->send_queue == NULL) {
        ret = -1;
    }
    else {
        picoquic_stream_queue_node_t* send_node = stream->send_queue;
        const uint8_t* bytes = send_node->bytes;
        const uint8_t* bytes_max = bytes + send_node->length;
        const uint8_t* frame_max = NULL;
        uint64_t frame_type = UINT64_MAX;
        uint64_t frame_length = UINT64_MAX;
        uint64_t capsule_type = UINT64_MAX;
        size_t capsule_length = SIZE_MAX;

        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_type)) == NULL ||
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_length)) == NULL ||
            frame_type != h3zero_frame_data ||
            bytes + frame_length != bytes_max) {
            ret = -1;
        }
        else {
            frame_max = bytes + frame_length;
            if ((bytes = picoquic_frames_varint_decode(bytes, frame_max, &capsule_type)) == NULL ||
                (bytes = picoquic_frames_varlen_decode(bytes, frame_max, &capsule_length)) == NULL ||
                capsule_type != picowt_capsule_drain_webtransport_session ||
                capsule_length != 0 ||
                bytes != frame_max) {
                ret = -1;
            }
        }
    }

    return ret;
}

static int picowt_drain_receive_capsule_test(void)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = h3zero_set_test_context(&quic, &cnx, &h3_ctx, &simulated_time);
    picowt_capsule_t capsule;
    uint8_t buffer[64];
    uint8_t payload[16];
    uint8_t* bytes = NULL;

    memset(&capsule, 0, sizeof(capsule));

    if (ret == 0) {
        bytes = picowt_test_format_capsule(buffer, buffer + sizeof(buffer),
            picowt_capsule_drain_webtransport_session, NULL, 0);
        if (bytes == NULL ||
            picowt_receive_capsule(cnx, buffer, bytes, &capsule) != 0 ||
            !capsule.h3_capsule.is_stored ||
            capsule.h3_capsule.capsule_type != picowt_capsule_drain_webtransport_session ||
            capsule.h3_capsule.capsule_length != 0 ||
            capsule.error_code != 0 ||
            capsule.error_msg != NULL ||
            capsule.error_msg_len != 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        picowt_release_capsule(&capsule);
        payload[0] = 0;
        bytes = picowt_test_format_capsule(buffer, buffer + sizeof(buffer),
            picowt_capsule_drain_webtransport_session, payload, 1);
        if (bytes == NULL ||
            picowt_receive_capsule(cnx, buffer, bytes, &capsule) == 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        static const uint8_t close_msg[] = { 'b', 'y', 'e' };

        picowt_release_capsule(&capsule);
        bytes = picoquic_frames_uint32_encode(payload, payload + sizeof(payload), 0x01020304);
        if (bytes != NULL) {
            memcpy(bytes, close_msg, sizeof(close_msg));
            bytes += sizeof(close_msg);
            bytes = picowt_test_format_capsule(buffer, buffer + sizeof(buffer),
                picowt_capsule_close_webtransport_session, payload, bytes - payload);
        }
        if (bytes == NULL ||
            picowt_receive_capsule(cnx, buffer, bytes, &capsule) != 0 ||
            !capsule.h3_capsule.is_stored ||
            capsule.h3_capsule.capsule_type != picowt_capsule_close_webtransport_session ||
            capsule.error_code != 0x01020304 ||
            capsule.error_msg_len != sizeof(close_msg) ||
            capsule.error_msg == NULL ||
            memcmp(capsule.error_msg, close_msg, sizeof(close_msg)) != 0) {
            ret = -1;
        }
    }

    picowt_release_capsule(&capsule);
    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int picowt_drain_test_one(int expect_error)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = h3zero_set_test_context(&quic, &cnx, &h3_ctx, &simulated_time);

    if (ret == 0) {
        h3zero_stream_ctx_t* control_stream_ctx = picowt_set_control_stream(cnx, h3_ctx);

        if (control_stream_ctx == NULL) {
            ret = -1;
        }
        else if (expect_error) {
            control_stream_ctx->ps.stream_state.is_fin_sent = 1;
            if (picowt_send_drain_session_message(cnx, control_stream_ctx) == 0) {
                ret = -1;
            }
        }
        else {
            ret = picowt_send_drain_session_message(cnx, control_stream_ctx);
            if (ret == 0) {
                ret = picowt_drain_send_check(cnx, control_stream_ctx);
            }
        }
    }


    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int picowt_drain_test(void)
{
    int ret = picowt_drain_test_one(0);

    if (ret == 0) {
        ret = picowt_drain_test_one(1);
    }
    if (ret == 0) {
        ret = picowt_drain_receive_capsule_test();
    }

    return ret;
}
