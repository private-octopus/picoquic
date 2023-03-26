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

/* The "baton" protocol was defined as a test application protocol for 
 * web transport. We use it here to test design ideas for implementing
 * web transport as a "filter". In that "filter" architecture, the
 * call back from the H3 stack arrive directly to the application
 * processor. If needed, the application uses the web transport
 * library to implement the web transport functions.
 */


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

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <tls_api.h>
#include "h3zero.h"
#include "h3zero_common.h"
#include "pico_webtransport.h"
#include "demoserver.h"
#include "wt_baton.h"

int wt_baton_accept(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    struct st_picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_app_ctx_t* app_ctx = (wt_baton_app_ctx_t*)path_app_ctx;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)malloc(sizeof(wt_baton_ctx_t));
    if (baton_ctx == NULL) {
        ret = -1;
    }
    else {
        memset(baton_ctx, 0, sizeof(wt_baton_ctx_t));
        /* remember the app parameters. */
        baton_ctx->nb_turns_required = (app_ctx == NULL) ? 7 : app_ctx->nb_turns_required;
        /* do the picowt_wt_accept, 
         * this will set parameters, e.g. app_ctx.
         */

        /* fill the baton with random data */
        picoquic_public_random(baton_ctx->baton, 256);
        /* Create a unidir stream */
        /* Copy the baton with increment */

    }
    return ret;
}

/* Web transport/baton callback. This will be called from the web server
* when the path points to a web transport callback.
* Discuss: is the stream context needed? Should it be a wt_stream_context?
*/

int picowt_h3zero_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t event,
    struct st_picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;

    switch (event) {
    case picohttp_callback_connect:
        /* A connect has been received on this stream, and could be accepted.
        * On the call, the path_app_ctx is set to the registered value.
        * The application must create an application connection context, which needs
        * to be registered with the stream_id. 
        */
        /* ret = wt_baton_accept(); */
        break;
    case picohttp_callback_connect_refused:
        /* The response from the server has arrived and it is negative. The 
        * application needs to close that stream.
        * Do we need an error code? Maybe pass as bytes + length.
        * Application should clean up the app context.
        */
        break;
    case picohttp_callback_connect_accepted: /* Connection request was accepted by peer */
        /* The response from the server has arrived and it is positive.
         * The application can start sending data.
         */
        break;
    case picohttp_callback_first_data: /* First data received from peer on stream N */
        /* This is the first data because the callback context for the stream has not
         * been set. Instead, the stack is providing the connection context, associated
         * with the prefix. The application needs to set that context before processing
         * the data. If it fails to do so, the stack will close the connection with
         * prejudice.
         */
        break;
    case picohttp_callback_post_data:
        /* Data received on a stream for which the per-app stream context is known.
        * the app just has to process the data.
        */
        break;
    case picohttp_callback_post_fin: /* All posted data have been received */
        /* Close the stream. If it is the WT control stream, close the 
         * entire WT connection */
        break;
    case picohttp_callback_provide_data: /* Stack is ready to send chunk of response */
        /* We assume that the required stream headers have already been pushed,
        * and that the stream context is already set. Just send the data.
        */
        break;
    case picohttp_callback_reset: /* Stream has been abandoned. */
        /* If control stream: abandon the whole connection. */
        break;
    default:
        /* protocol error */
        ret = -1;
        break;
    }
    return ret;
}

/** 
* wt_baton_connect:
* post a connection request using the baton protocol.
* this should be almost entirely done using the WT helper that
* obtains the connection context and registers the stream ID.
* Application needs to provide a connection context.
*/
int wt_baton_connect()
{
    return -1;
}

/**
* Create stream: when a stream is created locally. 
* Send the stream header. Associate the stream with a per_stream
* app context. mark the stream as active, per batn protocol.
*/

int wt_baton_create_stream(picoquic_cnx_t* cnx, int is_bidir, wt_baton_ctx_t* baton_ctx)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx);
    UNREFERENCED_PARAMETER(is_bidir);
    UNREFERENCED_PARAMETER(baton_ctx);
#endif
    /* uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, !is_bidir); */
    return -1;
}

wt_baton_stream_ctx_t* wt_baton_find_stream(wt_baton_ctx_t* ctx, uint64_t stream_id)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(stream_id);
#endif
    return NULL;
}

void wt_baton_stream_free(wt_baton_ctx_t* ctx, wt_baton_stream_ctx_t* stream_ctx)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(ctx);
    UNREFERENCED_PARAMETER(stream_ctx);
#endif
    /* unlink the stream */
    /* free it. */
}

void wt_baton_ctx_release(wt_baton_ctx_t* ctx)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(ctx);
#endif
    /* Free all the streams */
    /* dereference the control stream ID */
}

void wt_baton_ctx_free(wt_baton_ctx_t* ctx)
{
    wt_baton_ctx_release(ctx);
    free(ctx);
}

/* Implementation of the baton client. 
* This is an H3 client, specialized to only use WT+baton.
*/
int wt_baton_client_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    /* TODO: add reference to the baton connection context */
    wt_baton_ctx_t* ctx = (wt_baton_ctx_t*)callback_ctx;
    wt_baton_stream_ctx_t* stream_ctx = (wt_baton_stream_ctx_t*)v_stream_ctx;

    switch (event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* Data arrival on stream #x, maybe with fin mark */
        if (stream_ctx == NULL) {
            stream_ctx = wt_baton_find_stream(ctx, stream_id);
        }
        if (stream_ctx != NULL /* && stream_ctx->is_open */) {
            /* TODO: if stream is bidir */
            if (length > 0) {
                uint16_t error_found = 0;
                size_t available_data = 0;
                uint8_t* bytes_max = bytes + length;
                while (bytes < bytes_max) {
                    bytes = h3zero_parse_data_stream(bytes, bytes_max, &stream_ctx->stream_state, &available_data, &error_found);
                    if (bytes == NULL) {
                        ret = picoquic_close(cnx, error_found);
                        if (ret != 0) {
                            picoquic_log_app_message(cnx,
                                "Could not parse incoming data from stream %" PRIu64 ", error 0x%x", stream_id, error_found);
                        }
                        break;
                    }
                    else if (available_data > 0) {
                        /* Issue: the server call uses the "server stream ctx" data type. What to do on the client? */
                        picowt_h3zero_callback(cnx, bytes, available_data, picohttp_callback_post_data, /* TODO: server stream ctx? */NULL, ctx);
                    }
                }
            }
            /* Todo: if stream is unidir */

            if (event == picoquic_callback_stream_fin) {
                /* TODO: call the "post FIN" event. */
            }
        }
        break;
    case picoquic_callback_stream_reset:
        /* TODO: call the "post reset" event. */
        break;
    case picoquic_callback_stop_sending:
        /* TODO: stop sending event */
        break;
    case picoquic_callback_stateless_reset:
        fprintf(stdout, "Received a stateless reset.\n");
        ctx->connection_closed = 1;
        break;
    case picoquic_callback_close: /* Received connection close */
        fprintf(stdout, "Received a request to close the connection.\n");
        ctx->connection_closed = 1;
        break;
    case picoquic_callback_application_close: /* Received application close */
        fprintf(stdout, "Received a request to close the application.\n");
        ctx->connection_closed = 1;
        break;
    case picoquic_callback_version_negotiation:
        fprintf(stdout, "Received a version negotiation request:");
        for (size_t byte_index = 0; byte_index + 4 <= length; byte_index += 4) {
            uint32_t vn = PICOPARSE_32(bytes + byte_index);
            fprintf(stdout, "%s%08x", (byte_index == 0) ? " " : ", ", vn);
        }
        fprintf(stdout, "\n");
        break;
    case picoquic_callback_prepare_to_send:
        /* Used on client when posting data */
        /* Used for active streams */
        if (stream_ctx == NULL) {
            /* Unexpected */
            picoquic_reset_stream(cnx, stream_id, 0);
            return 0;
        }
        else {
            /* call prepare to send event */
        }
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        ctx->connection_ready = 1;
        /* TODO: send the WT CONNECT */
        break;
    case picoquic_callback_request_alpn_list:
        /* TODO: set alpn list */
        /* picoquic_demo_client_set_alpn_list((void*)bytes); */
        picoquic_add_proposed_alpn((void*)bytes, "h3");
        break;
    case picoquic_callback_set_alpn:
        /* ctx->alpn = picoquic_parse_alpn((const char*)bytes); */
        break;
    default:
        /* unexpected */
        break;
    }

    /* TODO: if disconnected, something... */
    return ret;
}
