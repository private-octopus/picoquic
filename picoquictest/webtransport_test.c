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
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "h3zero.h"
#include "democlient.h"
#include "demoserver.h"
#ifdef _WINDOWS
#include "wincompat.h"
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "picoquic_unified_log.h"
#include "pico_webtransport.h"

/**
* The relay game:
*
* A client opens a WT session to the server
*
* The server:
*   1. picks a random number [0-255] (called the baton)
*   2. opens a UNI stream
*   3. sends the baton + FIN.
*
* If either peer receives a UNI stream, it:
*   1. decodes the baton
*   2. adds 1
*   3. opens a BIDI stream
*   4. sends the new baton + FIN
*
* If either peer receives a BIDI stream, it:
*   1. decodes the baton
*   2. adds 1
*   3. replies with the new baton + FIN on the BIDI stream
*
* If either peer receives a BIDI reply, it:
*   1. decodes the baton
*   2. adds 1
*   3. opens a UNI stream
*   4. sends the new baton + FIN
*
* If either peer receives a baton == 0 at any point, ignore the above and close
* the session.
*
* Example:
*
* C->S: open
* S->C: U(250)
* C->S: Breq(251)
* S->C: Bresp(252)
* C->S: U(253)
* S->C: Breq(254)
* C->S: Bresp(255)
* S->C: U(0)
* C->S: FIN 
*/

/* Web transport tests:
* basic: declare context on server, create h3 connection,
* establish WT connection, clear everything.
* bidir-stream: set connection as in basic, create a stream from client,
* receive stream on server, reply with transform, receive reply on
* client on same stream.
* unidir-stream: same as bidir, but use unidir stream from client.
* server replies with unidir stream of its own, client matches reply
* to query, verifies content.
* lots-of-data-bidir: same as bidir stream, but receive data of specified length.
* lots-of-data-unidir: same as bidir stream, but receive data of specified length.
* lots-of-bidir-streams: same as bidir stream, but repeated with several streams.
* lots-of-unidir-streams: same as unidir stream, but repeated with several streams.
* 
* these tests differ by the web transport scenario description:
* - number of streams
* - use bidir or unidir
* - volume of data sent from client
* - volume of data sent from server
* verification:
* - stream content has header and data
* - header specifies stream order (16 bits)
*/

typedef struct st_picowt_test_ctx_t {
    int is_server;
} picowt_test_ctx_t;

typedef struct st_picowt_test_cnx_ctx_t {
    int is_connected;
} picowt_test_cnx_ctx_t;

typedef struct st_picowt_test_stream_ctx_t {
    int is_connected;
} picowt_test_stream_ctx_t;

/* Web transport test application callback */
int picowt_test_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picowt_event_t wt_event, void* callback_ctx, void* cnx_ctx, void* stream_ctx)
{
    picowt_test_ctx_t* test_wt_ctx = (picowt_test_ctx_t*)callback_ctx;
    picowt_test_cnx_ctx_t* test_wt_cnx_ctx = (picowt_test_cnx_ctx_t*)callback_ctx;
    picowt_test_stream_ctx_t* test_wt_stream_ctx = (picowt_test_stream_ctx_t*)stream_ctx;

    if (test_wt_cnx_ctx == NULL) {
        /* Create a new connection. This in theory only happens in a server context */
        if (test_wt_ctx == NULL || !test_wt_ctx) {
            return -1;
        }
        else {
            /* Create the context */
        }
    }
    switch (wt_event) {
    case picowt_cb_ready: /* Data can be sent and received */
        break;
    case picowt_cb_close: /* Control socket closed. Stream=0, bytes=NULL, len=0 */
    case picowt_cb_stream_data: /* Data received from peer on stream N */
    case picowt_cb_stream_fin: /* Fin received from peer on stream N; data is optional */
    case picowt_cb_stream_reset: /* Reset Stream received from peer on stream N; bytes=NULL, len = 0  */
    case picowt_cb_stop_sending: /* Stop sending received from peer on stream N; bytes=NULL, len = 0 */
    case picowt_cb_prepare_to_send: /* Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details */
    case picowt_cb_datagram: /* Datagram frame has been received */
    case picowt_cb_prepare_datagram: /* Prepare the next datagram */
    case picowt_cb_datagram_acked: /* Ack for packet carrying datagram-frame received from peer */
    case picowt_cb_datagram_lost: /* Packet carrying datagram-frame probably lost */
    case picowt_cb_datagram_spurious: /* Packet carrying datagram-frame was not really lost */
    case picowt_cb_pacing_changed: /* Pacing rate for the connection changed */
    default:
        return -1;
    }
    return -1;
}

/* One connection test */
static int picowt_test_one(picoquic_stream_data_cb_fn server_callback_fn, void * server_param,
    const picoquic_demo_stream_desc_t * demo_scenario, size_t nb_scenario, size_t const * demo_length,
    uint64_t do_losses, uint64_t completion_target, const char * out_dir, const char * client_bin,
    const char * server_bin)
{
    char const* alpn = "h3";
    uint64_t simulated_time = 0;
    uint64_t loss_mask = do_losses;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    int ret;
    picoquic_connection_id_t initial_cid = { {0x77, 0x74, 1, 2, 3, 4, 5, 6}, 8 };

    ret = picoquic_demo_client_initialize_context(&callback_ctx, demo_scenario, nb_scenario, alpn, 0, 0);
    callback_ctx.out_dir = out_dir;
    callback_ctx.no_print = 1;

    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, alpn, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

        if (ret == 0 && server_bin != NULL) {
            picoquic_set_binlog(test_ctx->qserver, ".");
            test_ctx->qserver->use_long_log = 1;
        }

        if (ret == 0 && client_bin != NULL) {
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
     * We want to replace that by the demo client callback */

    if (ret == 0) {
        picoquic_set_alpn_select_fn(test_ctx->qserver, picoquic_demo_server_callback_select_alpn);
        picoquic_set_default_callback(test_ctx->qserver, server_callback_fn, server_param);
        picoquic_set_callback(test_ctx->cnx_client, picoquic_demo_client_callback, &callback_ctx);
        /* TODO: register the web transport path for the 'connect' action. */


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

    if (ret == 0) {
        /* Todo: replace this by a description of client's WT scenarios.
         */
        ret = picoquic_demo_client_start_streams(test_ctx->cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
    }

    /* Simulate the connection from the client side. */
    time_out = simulated_time + 30000000;
    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

        if (ret == -1) {
            break;
        }

        /* TODO: insert here the logic of web transport scenarios. */
        if (++nb_trials > 100000) {
            ret = -1;
            break;
        }
    }

    /* Verify that the web transport scenarios were properly executed  */
   

    /* verify that the execution time is as expected */

    if (ret == 0 && completion_target != 0) {
        if (simulated_time > completion_target) {
            DBG_PRINTF("Test uses %llu microsec instead of %llu", simulated_time, completion_target);
            ret = -1;
        }
    }

    picoquic_demo_client_delete_context(&callback_ctx);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Tests of the web transport API.
 * 1- Get a web transport context.
 * 2- Validate each of the API with a test protocol.
 */

int webtransport_ctx_test()
{

    return -1;
}