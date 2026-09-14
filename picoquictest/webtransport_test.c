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
#include "picoquic_qlog.h"
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
int h3zero_check_connect_protocol(const picohttp_server_path_item_t* item, h3zero_stream_ctx_t* stream_ctx);
int picowt_process_pending_connect(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx);
int picowt_set_wt_protocol(h3zero_stream_ctx_t* stream_ctx, const char* selected_protocol);

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


static int picowt_baton_test_bad_capsule(picoquic_cnx_t * cnx, uint64_t stream_id)
{
    int ret = 0;
    uint8_t bad_capsule[] = { 0x00, 0x10, 0, 0xc0, 0, 0, 0, 0xba, 0xdc, 0xa9, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    ret = picoquic_add_to_stream(cnx, stream_id, bad_capsule, sizeof(bad_capsule), 0);
    return ret;
}

/* Open a new local WT stream and immediately FIN it without ever sending
 * the padding-length prefix and baton byte the peer expects on a baton
 * data stream. The peer should recognize this as "FIN before baton" and
 * close the session, instead of e.g. reading past the end of an empty
 * buffer -- see wt_baton_stream_data's is_receiving/is_fin handling. */
static int picowt_baton_test_fin_before_baton(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* h3_ctx, uint64_t control_stream_id)
{
    int ret = 0;
    h3zero_stream_ctx_t* stream_ctx = picowt_create_local_stream(cnx, 0, h3_ctx, control_stream_id);

    if (stream_ctx == NULL) {
        ret = -1;
    }
    else {
        ret = picoquic_add_to_stream(cnx, stream_ctx->stream_id, NULL, 0, 1);
    }
    return ret;
}

/* Open a new local WT stream and write a partial baton message to it
 * (a padding length, but not yet the padding or the baton byte that
 * would complete it), without ever finishing it -- so the peer's one
 * incoming slot for this lane count stays occupied. The caller is
 * expected to invoke this twice, with only one lane configured (the
 * default): the first call should be accepted normally, and the second
 * should find every incoming slot already busy and get rejected as
 * "data on wrong stream" -- see wt_baton_stream_data's receive_id /
 * receive_available bookkeeping. */
static int picowt_baton_test_extra_incoming_stream(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* h3_ctx, uint64_t control_stream_id)
{
    int ret = 0;
    uint8_t partial_baton_message[] = { 0x00 }; /* padding length = 0; the baton byte is deliberately withheld */
    h3zero_stream_ctx_t* stream_ctx = picowt_create_local_stream(cnx, 0, h3_ctx, control_stream_id);

    if (stream_ctx == NULL) {
        ret = -1;
    }
    else {
        ret = picoquic_add_to_stream(cnx, stream_ctx->stream_id, partial_baton_message, sizeof(partial_baton_message), 0);
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
    int capsule_needed = (test_id == 10);
    int stop_then_reset_needed = (test_id == 11);
    int stop_reset_sent_trial = -1;
    int fin_before_baton_needed = (test_id == 15);
    int extra_incoming_stream_needed = (test_id == 16);
    int extra_incoming_stream_trial = -1;

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
            /* Tests 12 and 13 check that the client rejects a bad path
             * locally, in wt_baton_prepare_context, before ever sending a
             * CONNECT -- that never exercises the server's own rejection in
             * wt_baton_accept. Test 14 checks the server side instead: skip
             * client-side validation by preparing with no path at all, then
             * attach the bad path only afterwards, so it is the server that
             * first parses and rejects it. */
            int bypass_client_validation = (test_id == 14);

            ret = wt_baton_prepare_context(test_ctx->cnx_client, &baton_ctx, h3zero_cb,
                control_stream_ctx, PICOQUIC_TEST_SNI, (bypass_client_validation) ? NULL : baton_path);
            if (ret == 0 && bypass_client_validation) {
                baton_ctx.server_path = baton_path;
            }
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

        if (ret == 0 && h3zero_cb->pending_wt_connect != control_stream_ctx) {
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

    if (ret == 0 && h3zero_cb->pending_wt_connect != NULL) {
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

        if (ret == 0 && baton_ctx.nb_turns > 2 && stop_then_reset_needed) {
            /* Queue STOP_SENDING and RESET_STREAM "almost simultaneously" to reproduce
             * potential issues when deleting the web transport context. */
            ret = picoquic_stop_sending(test_ctx->cnx_client, control_stream_ctx->stream_id, 0);
            if (ret == 0) {
                ret = picowt_reset_stream(test_ctx->cnx_client, control_stream_ctx, 54321);
            }
            stop_then_reset_needed = 0;
            stop_reset_sent_trial = nb_trials;
        }

        if (ret == 0 && stop_reset_sent_trial >= 0 && nb_trials > stop_reset_sent_trial + 16) {
            /* The server only tears down its WT session state on receiving
             * STOP_SENDING/RESET_STREAM for the control stream; unlike the
             * client side (see wt_baton_stream_stop/wt_baton_stream_reset),
             * it does not close the whole connection just because one WT
             * session ended abruptly. So nothing will end this connection
             * on its own once the probe above has run its course -- close
             * it explicitly so the test can conclude. What's under test is
             * whether the probe corrupts memory (checked by ASan/valgrind)
             * or forces an unexpected error close (checked below). */
            ret = picoquic_close(test_ctx->cnx_client, 0);
            stop_reset_sent_trial = -1;
        }

        if (ret == 0 && capsule_needed) {
            /* Inject a bad capsule on the control stream */
            ret = picowt_baton_test_bad_capsule(test_ctx->cnx_client, control_stream_ctx->stream_id);
            capsule_needed = 0;
        }

        if (ret == 0 && baton_ctx.nb_turns > 2 && fin_before_baton_needed) {
            ret = picowt_baton_test_fin_before_baton(test_ctx->cnx_client, h3zero_cb, control_stream_ctx->stream_id);
            fin_before_baton_needed = 0;
        }

        if (ret == 0 && baton_ctx.nb_turns > 2 && extra_incoming_stream_needed) {
            /* First call opens a stream and leaves it unfinished, occupying
             * the connection's one incoming slot (the default lane count).
             * The second call, a few trials later, opens another one while
             * the first is still open, which the peer has no slot left for. */
            ret = picowt_baton_test_extra_incoming_stream(test_ctx->cnx_client, h3zero_cb, control_stream_ctx->stream_id);
            extra_incoming_stream_needed = 0;
            extra_incoming_stream_trial = nb_trials;
        }

        if (ret == 0 && extra_incoming_stream_trial >= 0 && nb_trials > extra_incoming_stream_trial + 8) {
            ret = picowt_baton_test_extra_incoming_stream(test_ctx->cnx_client, h3zero_cb, control_stream_ctx->stream_id);
            extra_incoming_stream_trial = -1;
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
        else if (test_id == 11) {
            /* This test probes a use-after-free/double-free in the server's
             * wt_baton_ctx_t when STOP_SENDING is followed by RESET_STREAM
             * on the same stream. If the bug is present, the process should
             * crash, or ASan/valgrind should flag heap corruption, before
             * this point is ever reached. Reaching here cleanly just means
             * the bug wasn't tickled by this timing -- rerun under ASan. */
            DBG_PRINTF("Stop+reset use-after-free probe completed after %d turns, state %d",
                baton_ctx.nb_turns, baton_ctx.baton_state);
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
    /* verify that the bad capsule triggered an error, and symmetrically,
     * that the bad connect params -- rejected client-side, out of range
     * (test 12) or unparseable (test 13), or rejected server-side (test 14)
     * -- and the malformed-peer scenarios -- FIN before baton (test 15) or
     * an incoming stream with no free lane (test 16) -- also triggered an
     * error -- either way, a nonzero ret at this point is the expected
     * outcome, and an unexpectedly clean ret == 0 is the actual failure. */
    if (test_id == 10 || test_id == 12 || test_id == 13 || test_id == 14 ||
        test_id == 15 || test_id == 16) {
        if (ret == 0) {
            DBG_PRINTF("Unexpected connection success for test: %d", test_id);
            ret = -1;
        }
        else {
            ret = 0;
        }
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

int picowt_baton_stop_reset_test(void)
{
    int ret = picowt_baton_test_one(11, "/baton?count=8", 0, 5000000, ".", ".");

    return ret;
}

int picowt_baton_bad_params_test(void)
{
    /* Check that a connect attempt with bad parameters is processed properly. */
    int ret = picowt_baton_test_one(12, "/baton?version=1", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_bad_params_syntax_test(void)
{
    /* Same as picowt_baton_bad_params_test, but the "version" value itself
     * fails to parse as a number (wt_baton_ctx_path_params's first check),
     * instead of parsing fine and then failing the range/version check
     * (its second check, already covered by test 12). */
    int ret = picowt_baton_test_one(13, "/baton?version=abc", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_server_reject_test(void)
{
    /* Tests 12 and 13 both use a bad path that the client itself refuses
     * to send, via wt_baton_prepare_context's own call to
     * wt_baton_ctx_path_params -- so the CONNECT never actually reaches
     * the server, and wt_baton_accept's own rejection of a bad path
     * (including the cleanup through picowt_abort_registration) is never
     * exercised. Test 14 (handled by a special case in
     * picowt_baton_test_one_ex) sends the same bad "version" value, but
     * bypasses the client-side check so the server is the one to parse
     * and reject it. */
    int ret = picowt_baton_test_one(14, "/baton?version=1", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_fin_before_baton_test(void)
{
    /* A malformed peer opens a new baton data stream and FINs it
     * immediately, without ever sending the padding length and baton
     * byte the protocol requires. wt_baton must detect and reject this,
     * not read past the incomplete buffer -- see
     * picowt_baton_test_fin_before_baton and wt_baton_stream_data's
     * "Error: FIN before baton on data stream" branch. */
    int ret = picowt_baton_test_one(15, "/baton?baton=240", 0, 2000000, ".", ".");

    return ret;
}

int picowt_baton_wrong_stream_test(void)
{
    /* A malformed peer opens a second baton data stream while the first
     * is still incomplete. With the default lane count (1), the peer has
     * no free incoming slot for it -- see
     * picowt_baton_test_extra_incoming_stream and wt_baton_stream_data's
     * "Received baton data on wrong stream" branch. */
    int ret = picowt_baton_test_one(16, "/baton?baton=240", 0, 2000000, ".", ".");

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

int picowt_baton_overflow_test(void)
{
    int ret = picowt_baton_test_one(10, "/baton?count=8", 0, 5000000, ".", ".");

    return ret;
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

/* picowt_connect_ex registers a stream prefix before checking that the peer's
 * settings meet WebTransport requirements. If they don't -- here, deliberately
 * leaving h3_datagram unset -- it must unwind that registration via
 * picowt_abort_registration rather than leaving a dangling prefix behind. */
static int picowt_connect_abort_test(picoquic_cnx_t* cnx)
{
    h3zero_callback_ctx_t h3_ctx = { 0 };
    h3zero_stream_ctx_t* stream_ctx = NULL;
    int ret = 0;

    h3zero_init_stream_tree(&h3_ctx.h3_stream_tree);
    h3_ctx.settings.settings_received = 1;
    h3_ctx.settings.enable_connect_protocol = 1;
    h3_ctx.settings.webtransport_enabled = 1;
    cnx->remote_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
    cnx->remote_parameters.is_reset_stream_at_enabled = 1;

    stream_ctx = picowt_set_control_stream(cnx, &h3_ctx);
    if (stream_ctx == NULL) {
        ret = -1;
    }
    else {
        uint64_t stream_id = stream_ctx->stream_id;

        ret = picowt_connect_ex(cnx, &h3_ctx, stream_ctx, PICOQUIC_TEST_SNI,
            "/baton", picowt_noop_callback, NULL, PICOWT_BATON_ALPN_AVAILABLE, NULL, 0);

        if (ret == 0) {
            /* Requirements were unexpectedly met -- the abort path was not exercised. */
            ret = -1;
        }
        else if (h3zero_find_stream_prefix(&h3_ctx, stream_id) != NULL) {
            /* picowt_abort_registration should have removed the prefix it registered. */
            ret = -1;
        }
        else {
            ret = 0;
        }

        h3zero_delete_stream(cnx, &h3_ctx, stream_ctx);
    }
    h3zero_delete_all_stream_prefixes(cnx, &h3_ctx);

    return ret;
}

/* picowt_abort_registration with a NULL h3_ctx -- e.g. the connection-level
 * setup failed before any h3 context existed -- must still safely clear the
 * stream_ctx's callback pointers and report that the caller owns freeing it,
 * without touching any stream prefix table. */
static int picowt_abort_registration_no_ctx_test(void)
{
    int ret = 0;
    h3zero_stream_ctx_t stream_ctx;

    memset(&stream_ctx, 0, sizeof(h3zero_stream_ctx_t));
    stream_ctx.stream_id = 4;
    stream_ctx.path_callback = picowt_noop_callback;

    if (picowt_abort_registration(NULL, NULL, &stream_ctx) != 1 ||
        stream_ctx.path_callback != NULL) {
        ret = -1;
    }

    return ret;
}

/* picowt_process_pending_connect's rejection branch runs when settings
 * finally arrive for a CONNECT that had to be deferred (sent before
 * settings_received was set) but still don't meet WebTransport requirements.
 * That's a different path from picowt_connect_ex's own immediate-failure
 * check: it requires the CONNECT to have been deferred first, then settings
 * to arrive and still fail the requirements check. Use a real callback so
 * the connect_refused notification to the app is also exercised. */
static int picowt_deferred_connect_reject_test(picoquic_cnx_t* cnx)
{
    h3zero_callback_ctx_t h3_ctx = { 0 };
    h3zero_stream_ctx_t* stream_ctx = NULL;
    int ret = 0;

    h3zero_init_stream_tree(&h3_ctx.h3_stream_tree);
    /* settings_received is left at 0, so picowt_connect_ex defers the CONNECT. */

    stream_ctx = picowt_set_control_stream(cnx, &h3_ctx);
    if (stream_ctx == NULL) {
        ret = -1;
    }
    else {
        ret = picowt_connect_ex(cnx, &h3_ctx, stream_ctx, PICOQUIC_TEST_SNI,
            "/baton", picowt_noop_callback, NULL, PICOWT_BATON_ALPN_AVAILABLE, NULL, 0);

        if (ret != 0 || h3_ctx.pending_wt_connect != stream_ctx) {
            /* Should have been deferred, not failed or sent outright. */
            ret = -1;
        }
        else {
            /* Settings "arrive" but still don't meet requirements (h3_datagram
             * is left unset) -- the pending CONNECT must be gracefully rejected. */
            h3_ctx.settings.settings_received = 1;
            ret = picowt_process_pending_connect(cnx, &h3_ctx);

            if (ret != 0 || h3_ctx.pending_wt_connect != NULL ||
                h3zero_find_stream_prefix(&h3_ctx, stream_ctx->stream_id) != NULL) {
                /* Rejection must clear the pending state and the prefix it had registered. */
                ret = -1;
            }
        }

        h3zero_delete_stream(cnx, &h3_ctx, stream_ctx);
    }
    h3zero_delete_all_stream_prefixes(cnx, &h3_ctx);

    return ret;
}

/* picowt_select_wt_protocol parses a comma-separated list of protocol names
 * offered by the client. Two edge cases are not exercised by the baton
 * tests, which only ever offer well-formed, short protocol lists:
 * - a single candidate token so long it overflows the 254-byte scratch
 *   buffer, which must be treated as "no match" rather than overrun it;
 * - calling picowt_set_wt_protocol a second time on the same stream, which
 *   must fail since a protocol was already selected. */
static int picowt_select_wt_protocol_test(void)
{
    int ret = 0;
    h3zero_stream_ctx_t stream_ctx;
    char oversized_protocol[300];

    memset(oversized_protocol, 'x', sizeof(oversized_protocol) - 1);
    oversized_protocol[sizeof(oversized_protocol) - 1] = 0;

    memset(&stream_ctx, 0, sizeof(h3zero_stream_ctx_t));
    stream_ctx.ps.stream_state.header.wt_available_protocols = (uint8_t const*)oversized_protocol;

    if (picowt_select_wt_protocol(&stream_ctx, oversized_protocol) == 0) {
        /* An oversized candidate must never be treated as a match. */
        ret = -1;
    }
    else if (stream_ctx.ps.stream_state.wt_protocol != NULL) {
        ret = -1;
    }
    else if (picowt_set_wt_protocol(&stream_ctx, H3ZERO_WEBTRANSPORT_H3_PROTOCOL) != 0 ||
        stream_ctx.ps.stream_state.wt_protocol == NULL) {
        ret = -1;
    }
    else if (picowt_set_wt_protocol(&stream_ctx, H3ZERO_WEBTRANSPORT_H3_PROTOCOL_OLD) == 0) {
        /* A protocol was already selected; re-selecting must fail. */
        ret = -1;
    }

    free((void*)stream_ctx.ps.stream_state.wt_protocol);

    return ret;
}

/* picowt_send_close_session_message must reject an error message too long to
 * fit its fixed 512-byte encoding buffer, rather than overrun it. On that
 * failure path neither cnx nor the stream state is touched further, so a
 * minimal stack stream_ctx (with is_fin_sent left clear) is enough. */
static int picowt_send_close_session_message_too_long_test(void)
{
    int ret = 0;
    h3zero_stream_ctx_t control_stream_ctx;
    char long_err_msg[600];

    memset(&control_stream_ctx, 0, sizeof(h3zero_stream_ctx_t));
    memset(long_err_msg, 'e', sizeof(long_err_msg) - 1);
    long_err_msg[sizeof(long_err_msg) - 1] = 0;

    if (picowt_send_close_session_message(NULL, &control_stream_ctx, 0, long_err_msg) == 0) {
        ret = -1;
    }

    return ret;
}

static int picowt_get_authority_test(void)
{
    int ret = 0;
    h3zero_stream_ctx_t stream_ctx;
    const uint8_t* test_authority = (const uint8_t*)"example.com";

    memset(&stream_ctx, 0, sizeof(h3zero_stream_ctx_t));
    stream_ctx.ps.stream_state.header.authority = test_authority;

    if (picowt_get_authority(&stream_ctx) != (const char*)test_authority) {
        ret = -1;
    }

    return ret;
}

/* h3zero_check_connect_protocol accepts an exact match against the path
 * item's configured protocol, and leniently accepts either draft name
 * ("webtransport" or "webtransport-h3") when the other side used the other
 * one -- but must reject a protocol that is neither. Only the accept paths
 * are exercised by the baton tests; the genuine-rejection path is not. */
static int h3zero_check_connect_protocol_test(void)
{
    int ret = 0;
    picohttp_server_path_item_t item = { 0 };
    h3zero_stream_ctx_t stream_ctx;
    char const* new_protocol = H3ZERO_WEBTRANSPORT_H3_PROTOCOL;
    char const* old_protocol = H3ZERO_WEBTRANSPORT_H3_PROTOCOL_OLD;
    char const* bogus_protocol = "not-a-webtransport-protocol";

    item.connect_protocol = new_protocol;
    item.connect_protocol_length = strlen(new_protocol);

    /* Exact match: accepted */
    memset(&stream_ctx, 0, sizeof(h3zero_stream_ctx_t));
    stream_ctx.ps.stream_state.header.protocol = (uint8_t const*)new_protocol;
    stream_ctx.ps.stream_state.header.protocol_length = strlen(new_protocol);
    if (h3zero_check_connect_protocol(&item, &stream_ctx) != 0) {
        ret = -1;
    }

    /* Old draft name against a new-draft path item: lenient match, accepted */
    if (ret == 0) {
        stream_ctx.ps.stream_state.header.protocol = (uint8_t const*)old_protocol;
        stream_ctx.ps.stream_state.header.protocol_length = strlen(old_protocol);
        if (h3zero_check_connect_protocol(&item, &stream_ctx) != 0) {
            ret = -1;
        }
    }

    /* Genuinely unrelated protocol: rejected */
    if (ret == 0) {
        stream_ctx.ps.stream_state.header.protocol = (uint8_t const*)bogus_protocol;
        stream_ctx.ps.stream_state.header.protocol_length = strlen(bogus_protocol);
        if (h3zero_check_connect_protocol(&item, &stream_ctx) == 0) {
            ret = -1;
        }
    }

    return ret;
}

/* h3zero_delete_stream_prefix on a prefix that was never declared (or already
 * removed) must be a safe no-op that just logs, rather than touching the
 * (empty, or unrelated) prefix list. */
static int h3zero_delete_stream_prefix_not_found_test(picoquic_cnx_t* cnx)
{
    h3zero_callback_ctx_t h3_ctx = { 0 };

    h3zero_init_stream_tree(&h3_ctx.h3_stream_tree);

    h3zero_delete_stream_prefix(cnx, &h3_ctx, 12345);

    return 0;
}

/* h3zero_origin_validator_allow_all is wired into the demo server's and the
 * test path tables as the default origin_validator, but is only invoked from
 * within h3zero_common.c's CONNECT dispatch when an incoming request actually
 * carries an Origin header -- something none of the current test scenarios do.
 * Call it directly, matching its trivial "always allow" contract. */
static int picowt_origin_validator_test(void)
{
    int ret = 0;
    const uint8_t test_origin[] = "https://example.com";
    const uint8_t test_authority[] = "example.com";

    if (h3zero_origin_validator_allow_all(test_origin, sizeof(test_origin) - 1,
        test_authority, sizeof(test_authority) - 1, NULL) != 0) {
        ret = -1;
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
    if (ret == 0) {
        ret = picowt_connect_abort_test(cnx);
    }
    if (ret == 0) {
        ret = picowt_deferred_connect_reject_test(cnx);
    }
    if (ret == 0) {
        ret = picowt_abort_registration_no_ctx_test();
    }
    if (ret == 0) {
        ret = picowt_select_wt_protocol_test();
    }
    if (ret == 0) {
        ret = picowt_send_close_session_message_too_long_test();
    }
    if (ret == 0) {
        ret = picowt_get_authority_test();
    }
    if (ret == 0) {
        ret = picowt_origin_validator_test();
    }
    if (ret == 0) {
        ret = h3zero_check_connect_protocol_test();
    }
    if (ret == 0) {
        ret = h3zero_delete_stream_prefix_not_found_test(cnx);
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

    if (ret == 0) {
        /* Close capsule needs at least 4 bytes (the error code); a shorter one
         * must be rejected rather than read past its declared length. */
        static const uint8_t short_payload[] = { 1, 2 };

        picowt_release_capsule(&capsule);
        bytes = picowt_test_format_capsule(buffer, buffer + sizeof(buffer),
            picowt_capsule_close_webtransport_session, short_payload, sizeof(short_payload));
        if (bytes == NULL ||
            picowt_receive_capsule(cnx, buffer, bytes, &capsule) == 0) {
            ret = -1;
        }
    }

    picowt_release_capsule(&capsule);
    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* Regression test for a buffer-overflow bug: h3zero_accumulate_capsule keeps
 * capsule_buffer/capsule_buffer_size across capsules (to avoid a realloc when
 * the next capsule fits in the existing buffer), but was not resetting
 * value_read when starting the next one. If a shorter capsule immediately
 * followed a longer one on the same h3zero_capsule_t -- exactly how
 * picowt_receive_capsule's own loop processes multiple capsules from one
 * buffer, with no picowt_release_capsule call in between -- "capsule_length -
 * value_read" underflowed (both are size_t) into a huge memcpy. Feed two
 * close-session capsules, second shorter than the first, through a single
 * picowt_receive_capsule call to reproduce that exact sequence. */
static int picowt_receive_capsule_reuse_test(void)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = h3zero_set_test_context(&quic, &cnx, &h3_ctx, &simulated_time);
    picowt_capsule_t capsule;
    uint8_t buffer[128];
    uint8_t* next = buffer;
    uint8_t payload1[44];
    uint8_t payload2[4];

    memset(&capsule, 0, sizeof(capsule));

    if (ret == 0) {
        uint8_t* p = picoquic_frames_uint32_encode(payload1, payload1 + sizeof(payload1), 0x01020304);
        if (p != NULL) {
            memset(p, 'A', payload1 + sizeof(payload1) - p);
        }
        next = picowt_test_format_capsule(next, buffer + sizeof(buffer),
            picowt_capsule_close_webtransport_session, payload1, sizeof(payload1));

        if (next != NULL) {
            (void)picoquic_frames_uint32_encode(payload2, payload2 + sizeof(payload2), 0x0a0b0c0d);
            next = picowt_test_format_capsule(next, buffer + sizeof(buffer),
                picowt_capsule_close_webtransport_session, payload2, sizeof(payload2));
        }

        if (next == NULL ||
            picowt_receive_capsule(cnx, buffer, next, &capsule) != 0 ||
            !capsule.h3_capsule.is_stored ||
            capsule.h3_capsule.capsule_type != picowt_capsule_close_webtransport_session ||
            capsule.error_code != 0x0a0b0c0d ||
            capsule.error_msg_len != 0) {
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
    if (ret == 0) {
        ret = picowt_receive_capsule_reuse_test();
    }

    return ret;
}

/* picowt_reset_stream must refuse to reset a stream that is both remote and
 * unidirectional: from this (client) cnx's perspective, such a stream is
 * one it never had permission to write to or reset -- see the
 * "!is_local && !is_bidir" branch. */
int picowt_reset_stream_remote_unidir_test(void)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint64_t simulated_time = 0;
    int ret = picoquic_test_set_minimal_cnx_with_time(&quic, &cnx, &simulated_time);

    if (ret == 0) {
        h3zero_stream_ctx_t stream_ctx;
        memset(&stream_ctx, 0, sizeof(stream_ctx));
        /* bit0 = 1 (server/remote-initiated, from this client cnx's point of
         * view), bit1 = 1 (unidirectional). */
        stream_ctx.stream_id = 3;

        if (picowt_reset_stream(cnx, &stream_ctx, 0) == 0) {
            DBG_PRINTF("%s", "Reset of a remote unidirectional stream unexpectedly succeeded");
            ret = -1;
        }
    }

    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/* Distinct from the existing picowt_select_wt_protocol_test above (oversized
 * candidate token, double-select): these two cases target the trailing
 * whitespace skip between a candidate and its separator, and a malformed
 * list with no comma or end after a candidate. */
typedef struct st_picowt_select_wt_protocol_whitespace_test_case_t {
    char const* available;
    char const* supported;
    int expected_ret;
} picowt_select_wt_protocol_whitespace_test_case_t;

static const picowt_select_wt_protocol_whitespace_test_case_t picowt_select_wt_protocol_whitespace_test_cases[] = {
    /* trailing space before the comma after a (non-matching) first
     * candidate, then a match on the second -- exercises the whitespace
     * skip between a candidate and its separator. */
    { "foo , bar", "bar", 0 },
    /* no comma or end after a candidate (a stray character instead): the
     * list is malformed, but parsing must stop cleanly, not misbehave. */
    { "xyz!rest", "bar", -1 }
};

static const size_t nb_picowt_select_wt_protocol_whitespace_test_cases =
    sizeof(picowt_select_wt_protocol_whitespace_test_cases) / sizeof(picowt_select_wt_protocol_whitespace_test_cases[0]);

int picowt_select_wt_protocol_whitespace_test(void)
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_picowt_select_wt_protocol_whitespace_test_cases; i++) {
        picowt_select_wt_protocol_whitespace_test_case_t const* c = &picowt_select_wt_protocol_whitespace_test_cases[i];
        h3zero_stream_ctx_t stream_ctx;
        int select_ret;

        memset(&stream_ctx, 0, sizeof(stream_ctx));
        stream_ctx.ps.stream_state.header.wt_available_protocols = (uint8_t const*)c->available;

        select_ret = picowt_select_wt_protocol(&stream_ctx, c->supported);
        if (select_ret != c->expected_ret) {
            DBG_PRINTF("Select wt protocol case %zu (\"%s\" vs \"%s\"): expected %d, got %d",
                i, c->available, c->supported, c->expected_ret, select_ret);
            ret = -1;
        }
        free((void*)stream_ctx.ps.stream_state.wt_protocol);
    }

    return ret;
}

/* picowt_format_connect_frame is internal to webtransport.c (not declared
 * in pico_webtransport.h) but, like the quicperf.c/democlient.c/demoserver.c
 * parsers, given external linkage so its buffer-management edge cases can
 * be driven directly -- without needing to satisfy
 * picowt_webtransport_requirements_met's negotiated-transport-parameters
 * preconditions just to reach them through picowt_connect. */
int picowt_format_connect_frame(h3zero_stream_ctx_t* stream_ctx,
    const char* authority, const char* path, const char* connect_protocol,
    char const* wt_available_protocols, uint8_t* extra, size_t extra_length,
    size_t* connect_length);

/* Exercises picowt_format_connect_frame's buffer-management branches: a
 * minimal connect (short enough that the header length fits in a single
 * length byte -- every existing test's connect happens to be long enough
 * to need the two-byte form instead), an authority long enough to overflow
 * the 1024-byte frame buffer inside h3zero_create_connect_header_frame,
 * and an "extra" (capsule) payload that does not fit after the header. */
int picowt_format_connect_frame_test(void)
{
    int ret = 0;
    h3zero_stream_ctx_t stream_ctx;
    size_t connect_length = 0;

    memset(&stream_ctx, 0, sizeof(stream_ctx));
    if (picowt_format_connect_frame(&stream_ctx, "a", "/", H3ZERO_WEBTRANSPORT_H3_PROTOCOL,
        NULL, NULL, 0, &connect_length) != 0) {
        DBG_PRINTF("%s", "Minimal connect frame unexpectedly failed to format");
        ret = -1;
    }

    if (ret == 0) {
        char huge_authority[2000];
        memset(huge_authority, 'a', sizeof(huge_authority) - 1);
        huge_authority[sizeof(huge_authority) - 1] = 0;

        memset(&stream_ctx, 0, sizeof(stream_ctx));
        if (picowt_format_connect_frame(&stream_ctx, huge_authority, "/", H3ZERO_WEBTRANSPORT_H3_PROTOCOL,
            NULL, NULL, 0, &connect_length) == 0) {
            DBG_PRINTF("%s", "Oversized authority unexpectedly fit in the frame buffer");
            ret = -1;
        }
    }

    if (ret == 0) {
        uint8_t extra[1024];
        memset(extra, 'x', sizeof(extra));
        memset(&stream_ctx, 0, sizeof(stream_ctx));
        if (picowt_format_connect_frame(&stream_ctx, "a", "/", H3ZERO_WEBTRANSPORT_H3_PROTOCOL,
            NULL, extra, sizeof(extra), &connect_length) == 0) {
            DBG_PRINTF("%s", "Oversized extra data unexpectedly fit in the frame buffer");
            ret = -1;
        }
    }

    return ret;
}

/* picowt_send_close_session_message must refuse to send on a control
 * stream that has already sent its FIN, the same way
 * picowt_send_drain_session_message does (see picowt_drain_test_one(1))
 * -- exercised directly here instead of only through wt_baton_close_session,
 * which happens to always check this itself before calling in. */
int picowt_send_close_session_already_closed_test(void)
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
        else {
            control_stream_ctx->ps.stream_state.is_fin_sent = 1;
            if (picowt_send_close_session_message(cnx, control_stream_ctx, 0, "bye") == 0) {
                DBG_PRINTF("%s", "Close session message unexpectedly sent after FIN");
                ret = -1;
            }
        }
    }

    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}
