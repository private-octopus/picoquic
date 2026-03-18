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

/* The web protocol interop tester is using an extended version of h09 to
 * test web transport. At the most basic, this means that the client
 * who wants to perform an H09 transaction will:
 * 
 * - connect to the server using h3
 * - perform an extended connect on the specified path to open a WT session
 * - open a bidir stream and use it very much as a TCP connection.
 * - repeat
 * - eventually, close the WT connection and the QUIC session.
 *
 * The protocol is extended to test unidirectional streams and datagrams:
 * 
 * - Added a Push command to send data from the client.
 * 
 * - the client can open an unidirectional stream to send an H09 GET request.
 * - the server will open a related  unidirectional stream for the response.
 *
 * - the client can open an unidirectional stream to send an H09 PUSH request.
 * - the server will open a related  unidirectional stream for the response.
 * - the client will open an unidirectional stream to push the data.
 * 
 * - the client can send H09 GET request as a datagram.
 * - the server will send the response as a datagram.
 * 
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _WINDOWS
#include "wincompat.h"
#include "ws2ipdef.h"
#pragma warning(disable:4100)
#endif
#include "h3zero.h"
#include "h3zero_common.h"
#include "h09_server.h"

/* WT Protocol */
#define PICOWT_BATON_ALPN "hq-interop"
#define PICOWT_BATON_ALPN_AVAILABLE "hq-interop"

/* Client side API. happens when connection is starting */
int wt_h09_connecting(picoquic_cnx_t* cnx, struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{
    /* ... */
    return 0;
}

/* Server side API. Create the context for the WT transaction */
int wt_h09_accept(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{
    /* ... */
    return 0;
}

/* Client side. */
void wt_h09_connect_accepted(struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{
    if (stream_ctx->ps.stream_state.header.wt_protocol != NULL) {
        /* For test purpose, copy the result of the negotiation in the h09 context. */
        wt_h09_ctx_t* h09_ctx = (wt_h09_ctx_t*)path_app_ctx;
        size_t wt_protocol_len = strlen((char const*)stream_ctx->ps.stream_state.header.wt_protocol);
        if (wt_protocol_len > 254) {
            wt_protocol_len = 254;
        }
        memcpy(h09_ctx->wt_protocol, h09_ctx->ps.stream_state.header.wt_protocol, wt_protocol_len);
        h09_ctx->wt_protocol[wt_protocol_len + 1] = 0;

        /* TODO: if testing, write the connect result?*/
    }
    break;
}

/* Data arrival on stream */
int wt_h09_stream_data(picoquic_cnx_t * cnx, uint8_t * bytes, size_t length, int is_fin, struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{
    int ret = 0;
    /* TODO! */
    return ret;
}

/* Data requested on stream */
int wt_h09_provide_data(cnx, bytes, length, stream_ctx, path_app_ctx)
{
    int ret = 0;
    return ret;
}

/* Arrival of datagram */
int wt_h09_receive_datagram(cnx, bytes, length, stream_ctx, path_app_ctx)
{
    int ret = 0;
    return ret;
}

/* Provide datagram */

int wt_h09_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t wt_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    DBG_PRINTF("wt_h09_callback: %d, %" PRIi64 "\n", (int)wt_event, (stream_ctx == NULL) ? (int64_t)-1 : (int64_t)stream_ctx->stream_id);
    switch (wt_event) {
    case picohttp_callback_connecting:
        ret = wt_h09_connecting(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_connect:
        /* A connect has been received on this stream, and could be accepted.
        */
        /* The web transport should create a web transport connection context,
        * and also register the stream ID as identifying this context.
        * Then, callback the application. That means the WT app context
        * should be obtained from the path app context, etc.
        */
        (void)picowt_select_wt_protocol(stream_ctx, PICOWT_H09_ALPN_FILTER);
        ret = wt_h09_accept(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_connect_refused:
        /* The response from the server has arrived and it is negative. The
        * application needs to close that stream.
        * Do we need an error code? Maybe pass as bytes + length.
        * Application should clean up the app context.
        */
        picoquic_log_app_message(cnx, "WT Connection refused on stream %" PRIu64 ", status= %d",
            stream_ctx->stream_id,
            stream_ctx->ps.stream_state.header.status);
        break;
    case picohttp_callback_connect_accepted: /* Connection request was accepted by peer */
        /* The response from the server has arrived and it is positive.
         * The application can start sending data.
         */
        picoquic_log_app_message(cnx, "WT Connection accepted on stream %" PRIu64 ", protocol= %s",
            stream_ctx->stream_id,
            stream_ctx->ps.stream_state.header.wt_protocol != NULL ? (char const*)stream_ctx->ps.stream_state.header.wt_protocol : "none");
        if (stream_ctx->ps.stream_state.header.wt_protocol != NULL) {
            /* For test purpose, copy the result of the negotiation in the baton context. */
            wt_h09_ctx_t* baton_ctx = (wt_h09_ctx_t*)path_app_ctx;
            size_t wt_protocol_len = strlen((char const*)stream_ctx->ps.stream_state.header.wt_protocol);
            if (wt_protocol_len > 254) {
                wt_protocol_len = 254;
            }
            memcpy(baton_ctx->wt_protocol, stream_ctx->ps.stream_state.header.wt_protocol, wt_protocol_len);
            baton_ctx->wt_protocol[wt_protocol_len + 1] = 0;
        }
        break;
    case picohttp_callback_post_fin:
    case picohttp_callback_post_data:
        /* Data received on a stream for which the per-app stream context is known.
        * the app just has to process the data, and process the fin bit if present.
        */
        ret = wt_h09_stream_data(cnx, bytes, length, (wt_event == picohttp_callback_post_fin), stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_provide_data: /* Stack is ready to send chunk of response */
        /* We assume that the required stream headers have already been pushed,
        * and that the stream context is already set. Just send the data.
        */
        ret = wt_h09_provide_data(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_post_datagram:
        /* Data received on a stream for which the per-app stream context is known.
        * the app just has to process the data.
        */
        ret = wt_h09_receive_datagram(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_provide_datagram: /* Stack is ready to send a datagram */
        ret = wt_h09_provide_datagram(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_reset: /* Stream has been abandoned. */
        /* If control stream: abandon the whole connection. */
        ret = wt_h09_stream_reset(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_stop_sending: /* peer wants to abandon the stream */
        ret = wt_h09_stream_stop(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_free: /* Used during clean up the stream. Only cause the freeing of memory. */
        /* Free the memory attached to the stream */
        break;
    case picohttp_callback_deregister:
        /* The app context has been removed from the registry.
         * Its references should be removed from streams belonging to this session.
         * On the client, the memory should be freed.
         */
        wt_h09_unlink_context(cnx, stream_ctx, path_app_ctx);
        break;
    default:
        /* protocol error */
        ret = -1;
        break;
    }
    return ret;
}