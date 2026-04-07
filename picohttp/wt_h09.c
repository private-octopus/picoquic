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
 * test web transport.
 * 
 * In the basic mode, the client is configured with a series of URL
 * that should be fetched from the server. The client establishes a
 * connection, fetches the relevant URL, and close the connection when done.
 * The URL have the format:
 * https://server/webtransport1/file1.txt
 * https://server/webtransport1/file2.txt
 * https://server/webtransport2/file3.txt
 * In that format, "webtransport1" is the path of the WT/H09 service,
 * and file1.txt the name of the file. The client is expected to establish
 * the first WebTransport session on `/webtransport1` and download `file1.txt`
 * and `file2.txt`, and the second WebTransport session on `/webtransport2`
 * and download `file3.txt`. Both sessions MUST be established in parallel,
 * on the same underlying QUIC connection.
 * 
 * 
 * At the most basic, this means that the client
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
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_internal.h>
#ifdef _WINDOWS
#include "wincompat.h"
#include "ws2ipdef.h"
#pragma warning(disable:4100)
#endif
#include "h3zero.h"
#include "h3zero_common.h"
#include "h09_common.h"
#include "pico_webtransport.h"
#include "wt_h09.h"





/* Close the session. */
int wt_h09_close_session(picoquic_cnx_t* cnx, wt_h09_ctx_t* h09_ctx, uint32_t err, char const* err_msg)
{
    int ret = 0;

    h3zero_stream_ctx_t* stream_ctx = h09_ctx->control_stream_ctx;

    picoquic_log_app_message(cnx, "Closing session control stream %" PRIu64, h09_ctx->control_stream_id);

    ret = picowt_send_close_session_message(cnx, stream_ctx, err, err_msg);
    h09_ctx->h09_state = wt_h09_state_closed;

    return(ret);
}

/* Client side API. happens when connection is starting */
int wt_h09_connecting(picoquic_cnx_t* cnx, struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{
    /* ... */
    return 0;
}

int wt_h09_ctx_init(wt_h09_ctx_t* h09_ctx, h3zero_callback_ctx_t* h3_ctx, struct st_h3zero_stream_ctx_t* stream_ctx, wt_h09_app_ctx_t* app_ctx)
{
    memset(h09_ctx, 0, sizeof(wt_h09_ctx_t));
    h09_ctx->control_stream_ctx = stream_ctx;
    h09_ctx->h3_ctx = h3_ctx;
    if (app_ctx != NULL) {
        /* TODO: something a bit more sensible! */
        h09_ctx->app_count = 0;
    }

    return 0;
}

int wt_h09_prepare_context(picoquic_cnx_t* cnx, wt_h09_ctx_t* h09_ctx,
    h3zero_callback_ctx_t* h3_ctx, h3zero_stream_ctx_t* control_stream_ctx,
    const char* server_name, const char* path)
{
    int ret = 0;

    wt_h09_ctx_init(h09_ctx, h3_ctx, NULL, NULL);
    h09_ctx->cnx = cnx;
    h09_ctx->is_client = 1;
    h09_ctx->authority = server_name;
    h09_ctx->server_path = path;

    h09_ctx->connection_ready = 1;
    h09_ctx->is_client = 1;
#if 0
    if (h09_ctx->server_path != NULL) {
        ret = wt_h09_ctx_path_params(h09_ctx, (const uint8_t*)h09_ctx->server_path,
            strlen(h09_ctx->server_path));
    }
#endif

    /* TO DO: initiate the scenarios */

    return ret;

}

/* Server side API. Create the context for the WT transaction */
int wt_h09_accept(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{

    int ret = 0;
    wt_h09_app_ctx_t* app_ctx = (wt_h09_app_ctx_t*)path_app_ctx;
    h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx);
    wt_h09_ctx_t* h09_ctx = (wt_h09_ctx_t*)malloc(sizeof(wt_h09_ctx_t));
    if (h09_ctx == NULL) {
        ret = -1;
    }
    else {
        /* register the incoming stream ID */
        ret = wt_h09_ctx_init(h09_ctx, h3_ctx, stream_ctx, app_ctx);

#if 0
        /* init the global parameters */
        if (path != NULL && path_length > 0) {
            ret = wt_h09_ctx_path_params(h09_ctx, path, path_length);
        }
#endif

        if (ret == 0) {
            stream_ctx->sfs.path_callback = wt_h09_callback;
            stream_ctx->sfs.path_callback_ctx = h09_ctx;
        }
    }
    return ret;
}

int wt_h09_start_next_stream(picoquic_cnx_t* cnx, struct st_h3zero_stream_ctx_t* control_stream_ctx, wt_h09_ctx_t* h09_ctx)
{
    int ret = 0;

    if (h09_ctx->next_request < h09_ctx->nb_requests) {
        struct st_h3zero_stream_ctx_t* stream_ctx;

        if ((stream_ctx = picowt_create_local_stream(cnx, 0, h09_ctx->h3_ctx, h09_ctx->control_stream_id)) == NULL) {
            ret = -1;
        }
        else if ((ret = picoquic_add_to_stream(cnx, stream_ctx->stream_id, (uint8_t*)"GET ", 4, 0)) == 0 &&
            (ret = picoquic_add_to_stream(cnx, stream_ctx->stream_id, (uint8_t*)h09_ctx->requests[h09_ctx->next_request],
                strlen(h09_ctx->requests[h09_ctx->next_request]), 0)) == 0 &&
            (ret = picoquic_add_to_stream(cnx, stream_ctx->stream_id, (uint8_t*)"\r\n", 2, 1)) == 0) {
            /* TODO: create the file in the download directory.*/
            /* Create a context for associating file and stream-ID */
        }
    }
    return 0;
}


/* Client side. */
int wt_h09_connect_accepted(picoquic_cnx_t * cnx, struct st_h3zero_stream_ctx_t* stream_ctx, wt_h09_ctx_t* h09_ctx)
{
    int ret = 0;
    picoquic_log_app_message(cnx, "WT Connection accepted on stream %" PRIu64 ", protocol= %s",
        stream_ctx->stream_id,
        stream_ctx->ps.stream_state.header.wt_protocol != NULL ? (char const*)stream_ctx->ps.stream_state.header.wt_protocol : "none");
    if (stream_ctx->ps.stream_state.header.wt_protocol != NULL) {
        /* For test purpose, copy the result of the negotiation in the h09 context. */
        size_t wt_protocol_len = strlen((char const*)stream_ctx->ps.stream_state.header.wt_protocol);
        if (wt_protocol_len > 254) {
            wt_protocol_len = 254;
        }
        memcpy(h09_ctx->wt_protocol, stream_ctx->ps.stream_state.header.wt_protocol, wt_protocol_len);
        h09_ctx->wt_protocol[wt_protocol_len + 1] = 0;
    }
    ret = wt_h09_start_next_stream(cnx, stream_ctx, h09_ctx);
    return ret;
}

/* Data arrival on stream */
int wt_h09_stream_data(picoquic_cnx_t * cnx, uint8_t * bytes, size_t length, int is_fin, struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{
    int ret = 0;
    /* TODO! */
    return ret;
}

/* Data requested on stream */
int wt_h09_provide_data(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{
    int ret = 0;
    return ret;
}

/* Arrival of datagram */
int wt_h09_receive_datagram(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{
    int ret = 0;
    return ret;
}

/* Arrival of datagram */
int wt_h09_provide_datagram(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, struct st_h3zero_stream_ctx_t* stream_ctx, void* path_app_ctx)
{
    int ret = 0;
    return ret;
}


void wt_h09_unlink_context(picoquic_cnx_t* cnx,
    h3zero_stream_ctx_t* control_stream_ctx,
    void* v_ctx)
{
    h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx);
    wt_h09_ctx_t* h09_ctx = (wt_h09_ctx_t*)v_ctx;

    picowt_deregister(cnx, h3_ctx, control_stream_ctx);

    picowt_release_capsule(&h09_ctx->capsule);
    if (!cnx->client_mode) {
        free(h09_ctx);
    }
    else {
        h09_ctx->connection_closed = 1;
    }
}


int wt_h09_stream_reset(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_h09_ctx_t* h09_ctx = (wt_h09_ctx_t*)path_app_ctx;

    picoquic_log_app_message(cnx, "Received reset on stream %" PRIu64 ", closing the session", stream_ctx->stream_id);

    if (h09_ctx != NULL) {
        ret = wt_h09_close_session(cnx, h09_ctx, 0, NULL);

        /* Any reset results in the abandon of the context */
        h09_ctx->h09_state = wt_h09_state_closed;
        if (h09_ctx->is_client) {
            (void)picoquic_close(cnx, 0);
        }
        h3zero_delete_stream_prefix(cnx, h09_ctx->h3_ctx, h09_ctx->control_stream_id);
    }

    return ret;
}

int wt_h09_stream_stop(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_h09_ctx_t* h09_ctx = (wt_h09_ctx_t*)path_app_ctx;

    picoquic_log_app_message(cnx, "Received stop sending on stream %" PRIu64 ", closing the session", stream_ctx->stream_id);

    if (h09_ctx != NULL) {
        ret = wt_h09_close_session(cnx, h09_ctx, 0, NULL);

        /* Any reset results in the abandon of the context */
        h09_ctx->h09_state = wt_h09_state_closed;
        if (h09_ctx->is_client) {
            (void)picoquic_close(cnx, 0);
        }
        h3zero_delete_stream_prefix(cnx, h09_ctx->h3_ctx, h09_ctx->control_stream_id);
    }

    return ret;
}


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
        (void)picowt_select_wt_protocol(stream_ctx, PICOWT_H09_ALPN_AVAILABLE);
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
        ret = wt_h09_connect_accepted(cnx, stream_ctx, (wt_h09_ctx_t*)(path_app_ctx));
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