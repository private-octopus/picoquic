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


/* Close the session. */
int wt_baton_close_session(picoquic_cnx_t* cnx, wt_baton_ctx_t* baton_ctx)
{
    int ret = picoquic_add_to_stream(cnx, baton_ctx->control_stream_id, NULL, 0, 1);
    return(ret);
}

/* Update context when sending a connect request */
int wt_baton_connecting(picoquic_cnx_t* cnx,
    picohttp_server_stream_ctx_t* stream_ctx, void * v_baton_ctx)
{
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)v_baton_ctx;

    picoquic_log_app_message(cnx, "Outgoing connect baton on stream: %"PRIu64, stream_ctx->stream_id);
    baton_ctx->baton_state = wt_baton_state_ready;
    baton_ctx->control_stream_id = stream_ctx->stream_id;

    return 0;
}

/* Process incoming stream data. */
int wt_baton_relay(picoquic_cnx_t* cnx, 
    picohttp_server_stream_ctx_t* stream_ctx, wt_baton_ctx_t* baton_ctx)
{
    int ret = 0;

    /* Find the next stream context */
    if (stream_ctx == NULL ||
        (IS_BIDIR_STREAM_ID(stream_ctx->stream_id) && IS_LOCAL_STREAM_ID(stream_ctx->stream_id, baton_ctx->is_client))) {
        /* need to relay on a new unidir stream */
        stream_ctx = wt_baton_create_stream(cnx, 0, baton_ctx);
        if (stream_ctx != NULL) {
            /* Write the first required bytes for sending the context ID */
            uint8_t unidir_header[16];
            uint8_t* bytes = unidir_header;
            bytes = picoquic_frames_varint_encode(bytes, unidir_header + 16, h3zero_stream_type_webtransport);
            bytes = picoquic_frames_varint_encode(bytes, unidir_header + 16, baton_ctx->control_stream_id);
            ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, unidir_header, bytes - unidir_header, 0, stream_ctx);
        }
        else {
            ret = 0;
        }
    }
    else if (!IS_BIDIR_STREAM_ID(stream_ctx->stream_id)) {
        /* need to relay on a new local bidir stream */
        stream_ctx = wt_baton_create_stream(cnx, 1, baton_ctx);
        if (stream_ctx != NULL) {
            /* Write the first required bytes for sending the context ID */
            uint8_t bidir_header[16];
            uint8_t* bytes = bidir_header;
            bytes = picoquic_frames_varint_encode(bytes, bidir_header + 16, h3zero_frame_webtransport_stream);
            bytes = picoquic_frames_varint_encode(bytes, bidir_header + 16, baton_ctx->control_stream_id);
            ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, bidir_header, bytes - bidir_header, 0, stream_ctx);
        }
        else {
            ret = 0;
        }
    }
    else {
        /* NO OP: baton was received on remote bidir stream, will send on the reverse stream. */
    }

    if (ret == 0 && stream_ctx != NULL) {
        picoquic_log_app_message(cnx, "Relaying the baton on data stream: %"PRIu64 " after %d turns", stream_ctx->stream_id, baton_ctx->nb_turns);
        baton_ctx->nb_turns += 1;
        baton_ctx->baton_state = wt_baton_state_sent;
        baton_ctx->nb_baton_bytes_received = 0;
        stream_ctx->path_callback = picowt_h3zero_callback;
        stream_ctx->path_callback_ctx = baton_ctx;
        ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, baton_ctx->baton, 256, 1, stream_ctx);

        stream_ctx->ps.stream_state.is_fin_sent = 1;
        if (stream_ctx->ps.stream_state.is_fin_received == 1) {
            picoquic_set_app_stream_ctx(cnx, stream_ctx->stream_id, NULL);
            h3zero_delete_stream(baton_ctx->h3_stream_tree, stream_ctx);
        }
    }

    return ret;
}

int wt_baton_check(picoquic_cnx_t* cnx, picohttp_server_stream_ctx_t* stream_ctx, wt_baton_ctx_t* baton_ctx)
{
    int ret = 0;
    /* if the baton is all zeroes, then the exchange is done */
    int baton_is_zeroes = 1;
    for (int i = 0; i < 256; i++) {
        if (baton_ctx->baton_received[i] != 0) {
            baton_is_zeroes = 0;
            break;
        }
    }
    if (baton_is_zeroes) {
        picoquic_log_app_message(cnx, "All ZERO baton on stream: %"PRIu64 " after %d turns", stream_ctx->stream_id, baton_ctx->nb_turns);
        baton_ctx->baton_state = wt_baton_state_done;
        /* Close the control stream, which will close the session */
        if (IS_BIDIR_STREAM_ID(stream_ctx->stream_id) && !IS_LOCAL_STREAM_ID(stream_ctx->stream_id, baton_ctx->is_client)) {
            /* before closing the session, close this stream.*/
            ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, NULL, 0, 1, NULL);
        }
        ret = wt_baton_close_session(cnx, baton_ctx);
    }
    else {
        /* else the baton must be equal to baton sent + 1 */
        uint8_t remainder = 1;
        int is_wrong_baton = 0;
        if (baton_ctx->baton_state == wt_baton_state_sent) {
            for (int i = 255; i >= 0; i--) {
                uint8_t next = baton_ctx->baton[i] + remainder;
                if (next != baton_ctx->baton_received[i]) {
                    is_wrong_baton = 1;
                    break;
                }
                remainder &= (next == 0);
            }
        }
        if (is_wrong_baton) {
            baton_ctx->baton_state = wt_baton_state_error;
            picoquic_log_app_message(cnx, "Wrong baton on stream: %"PRIu64 " after %d turns", stream_ctx->stream_id, baton_ctx->nb_turns);
            ret = -1;
        }
        else {
            baton_ctx->nb_turns += 1;  /* add a turn for the peer sending this */
            if (baton_ctx->nb_turns >= baton_ctx->nb_turns_required) {
                picoquic_log_app_message(cnx, "Final baton turn after %d turns", baton_ctx->nb_turns);
                baton_ctx->baton_state = wt_baton_state_done;
                memset(baton_ctx->baton, 0, 256);
            }
            else {
                remainder = 1;

                baton_ctx->baton_state = wt_baton_state_sent;
                for (int i = 255; i >= 0; i--) {
                    uint8_t next = baton_ctx->baton_received[i] + remainder;
                    remainder &= (next == 0);
                    baton_ctx->baton[i] = next;
                }
            }
            ret = wt_baton_relay(cnx, stream_ctx, baton_ctx);
        }
    }
    return ret;
}

int wt_baton_stream_data(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    struct st_picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;
    size_t expected = 256 - (size_t)baton_ctx->nb_baton_bytes_received;

    if (baton_ctx->baton_state != wt_baton_state_ready && baton_ctx->baton_state != wt_baton_state_sent) {
        /* Unexpected data at this stage */
        picoquic_log_app_message(cnx, "Received baton data on stream %" PRIu64 ", when not ready",
            stream_ctx->stream_id);
        ret = -1;
    }
    else {
        if (length > expected) {
            /* Protocol error */
            picoquic_log_app_message(cnx, "Received %zu baton bytes on stream %" PRIu64 ", %zu expected",
                length, stream_ctx->stream_id, 256 - baton_ctx->nb_baton_bytes_received);
            ret = -1;
        }
        else {
            memcpy(baton_ctx->baton_received + baton_ctx->nb_baton_bytes_received, bytes, length);
            baton_ctx->nb_baton_bytes_received += length;

            if (baton_ctx->nb_baton_bytes_received >= 256) {
                baton_ctx->last_received_stream_ctx = stream_ctx;
                ret = wt_baton_check(cnx, stream_ctx, baton_ctx);
            }
        }
    }
    
    return ret;
}

/* Accept an incoming connection */

int wt_baton_accept(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    struct st_picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_app_ctx_t* app_ctx = (wt_baton_app_ctx_t*)path_app_ctx;
    h3zero_server_callback_ctx_t* h3_ctx = (h3zero_server_callback_ctx_t*)picoquic_get_callback_context(cnx);
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)malloc(sizeof(wt_baton_ctx_t));
    if (baton_ctx == NULL) {
        ret = -1;
    }
    else {
        /* register the incoming stream ID */
        ret = wt_baton_ctx_init(baton_ctx, h3_ctx, app_ctx, stream_ctx);
        if (ret == 0) {
            baton_ctx->connection_ready = 1;
            /* fill the baton with random data */
            picoquic_public_random(baton_ctx->baton, 256);
            /* Get the relaying started */
            ret = wt_baton_relay(cnx, NULL, baton_ctx);
        }
    }
    return ret;
}


/* Process the FIN of a stream.
 */
int wt_baton_stream_fin(picoquic_cnx_t* cnx,
    picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;

    if (stream_ctx->stream_id == baton_ctx->control_stream_id) {
        /* Closing the control stream implies closing the baton context. 
         */
        baton_ctx->baton_state = wt_baton_state_closed;
        if (baton_ctx->is_client) {
            wt_baton_ctx_release(baton_ctx);
            picoquic_log_app_message(cnx, "FIN on control stream. Closing the connection.\n");
            ret = picoquic_close(cnx, 0);
        }
        else {
            wt_baton_ctx_release(baton_ctx);
        }
    }
    else {
        stream_ctx->ps.stream_state.is_fin_received = 1;
        if (stream_ctx->ps.stream_state.is_fin_sent == 1) {
            picoquic_set_app_stream_ctx(cnx, stream_ctx->stream_id, NULL);
            h3zero_delete_stream(baton_ctx->h3_stream_tree, stream_ctx);
        }
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
    printf("picowt_h3zero_callback: %d\n", (int)event);
    switch (event) {
    case picohttp_callback_connecting:
        ret = wt_baton_connecting(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_connect:
        /* A connect has been received on this stream, and could be accepted.
        */
        /* The web transport should create a web transport connection context,
        * and also register the stream ID as identifying this context.
        * Then, callback the application. That means the WT app context
        * should be obtained from the path app context, etc.
        */
        ret = wt_baton_accept(cnx, bytes, length, stream_ctx, path_app_ctx);
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
        ret = wt_baton_stream_data(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_post_fin: /* All posted data have been received */
        /* Close the stream. If it is the WT control stream, close the 
         * entire WT connection */
        ret = wt_baton_stream_fin(cnx, stream_ctx, path_app_ctx);
        picoquic_log_app_message(cnx, "FIN received on data stream: %"PRIu64, stream_ctx->stream_id);
        break;
    case picohttp_callback_session_fin: /*  Control stream has been closed. */
        picoquic_log_app_message(cnx, "FIN received on control stream: %"PRIu64, stream_ctx->stream_id);
        ret = wt_baton_stream_fin(cnx, stream_ctx, path_app_ctx);
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
* Create stream: when a stream is created locally. 
* Send the stream header. Associate the stream with a per_stream
* app context. mark the stream as active, per batn protocol.
*/

picohttp_server_stream_ctx_t* wt_baton_create_stream(picoquic_cnx_t* cnx, int is_bidir, wt_baton_ctx_t* baton_ctx)
{
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, !is_bidir);
    picohttp_server_stream_ctx_t* stream_ctx = h3zero_find_or_create_stream(
        cnx, stream_id, baton_ctx->h3_stream_tree, 1, 1);
    if (stream_ctx != NULL) {
        /* Associate the stream with a per_stream context */
        if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
            fprintf(stdout, "Could not set context for stream %"PRIu64 ".\n", stream_id);
        }
    }
    return stream_ctx;
}

picohttp_server_stream_ctx_t* wt_baton_find_stream(wt_baton_ctx_t* ctx, uint64_t stream_id)
{
    picohttp_server_stream_ctx_t* stream_ctx = picohttp_find_stream(ctx->h3_stream_tree, stream_id);
    return stream_ctx;
}

void wt_baton_ctx_release(wt_baton_ctx_t* ctx)
{
    /* dereference the control stream ID */
    h3zero_delete_stream_prefix(ctx->stream_prefixes, ctx->control_stream_id);
    /* Free the streams created for this session */
    if (ctx->h3_stream_tree == &ctx->local_h3_tree) {
        /* Free all the streams registered locally */
        picosplay_empty_tree(ctx->h3_stream_tree);
    }
    else {
        /* TODO: Only free the streams that are related to this context */
        picosplay_node_t* previous = NULL;

        while(1){
            picosplay_node_t* next = (previous == NULL) ? picosplay_first(ctx->h3_stream_tree) : picosplay_next(previous);
            if (next == NULL) {
                break;
            }
            else {
                picohttp_server_stream_ctx_t* stream_ctx =
                    (picohttp_server_stream_ctx_t*) picohttp_stream_node_value(next);
                if (stream_ctx->control_stream_id == stream_ctx->control_stream_id) {
                    picosplay_delete(ctx->h3_stream_tree, next);
                }
                else {
                    previous = next;
                }
            }
        }
    }
}

void wt_baton_ctx_free(wt_baton_ctx_t* ctx)
{
    wt_baton_ctx_release(ctx);
    free(ctx);
}

/* Initialize the content of a wt_baton context.
* We need a nuanced behavior, depending on whether this is a native baton client,
* or piggybacking on an HTTP server. In the latter case, we reuse the H3
* stream tree already managed in the H3 server context.
 */

int wt_baton_ctx_init(wt_baton_ctx_t* ctx, h3zero_server_callback_ctx_t* h3_ctx, wt_baton_app_ctx_t * app_ctx, picohttp_server_stream_ctx_t* stream_ctx)
{
    int ret = 0;

    memset(ctx, 0, sizeof(wt_baton_ctx_t));
    /* Init the stream tree */
    /* Do we use the path table for the client? or the web folder? */
    /* connection wide tracking of stream prefixes */
    if (h3_ctx == NULL) {
        /* init of stream splay */
        ctx->h3_stream_tree = &ctx->local_h3_tree;
        h3zero_init_stream_tree(ctx->h3_stream_tree);
        /* init of local prefix table. */
        ctx->stream_prefixes = &ctx->local_stream_prefixes;
    }
    else {
        /* set references to existing objects */
        ctx->h3_stream_tree = &h3_ctx->h3_stream_tree;
        ctx->stream_prefixes = &h3_ctx->stream_prefixes;
    }

    /* Connection flags connection_ready and connection_closed are left
    * to zero by default. */
    /* init the baton protocol will be done in the "accept" call for server */
    /* init the global parameters */
    if (app_ctx != NULL) {
        ctx->nb_turns_required = app_ctx->nb_turns_required;
    }
    else {
        ctx->nb_turns_required = 7;
    }

    if (stream_ctx != NULL) {
        /* Register the control stream and the stream id */
        ctx->control_stream_id = stream_ctx->stream_id;
        ret = h3zero_declare_stream_prefix(ctx->stream_prefixes, stream_ctx->stream_id, picowt_h3zero_callback, ctx);
    }

    if (ret != 0) {
        /* Todo: undo init. */
    }
    return ret;
}

int wt_baton_process_remote_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t event,
    picohttp_server_stream_ctx_t* stream_ctx,
    wt_baton_ctx_t* ctx)
{
    int ret = 0;

    if (stream_ctx == NULL) {
        stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx->h3_stream_tree, 1, 1);
        picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx);
    }
    if (stream_ctx == NULL) {
        ret = -1;
    }
    else {
        uint8_t* bytes_max = bytes + length;

        bytes = h3zero_parse_incoming_remote_stream(bytes, bytes_max, stream_ctx,
            ctx->h3_stream_tree, ctx->stream_prefixes);
        if (bytes == NULL) {
            picoquic_log_app_message(cnx, "Cannot parse incoming stream: %"PRIu64, stream_id);
            ret = -1;
        }
        else if (stream_ctx->path_callback != NULL){
            if (bytes < bytes_max) {
                stream_ctx->path_callback(cnx, bytes, bytes_max - bytes, picohttp_callback_post_data, stream_ctx, stream_ctx->path_callback_ctx);
            }
            if (event == picoquic_callback_stream_fin) {
                /* FIN of the control stream is FIN of the whole session */
                stream_ctx->path_callback(cnx, NULL, 0, picohttp_callback_post_fin, stream_ctx, ctx);
            }
        }
    }
    return ret;
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
    picohttp_server_stream_ctx_t* stream_ctx = (picohttp_server_stream_ctx_t*)v_stream_ctx;

    switch (event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* TODO: blocked here -- data is received, but does nothing.. */
        fprintf(stdout, "Received data on the connection.\n");
        /* Data arrival on stream #x, maybe with fin mark */
        if (stream_ctx == NULL) {
            stream_ctx = wt_baton_find_stream(ctx, stream_id);
        }
        if (IS_BIDIR_STREAM_ID(stream_id)) {
            if (IS_LOCAL_STREAM_ID(stream_id, 1)) {
                if (stream_ctx == NULL) {
                    fprintf(stdout, "unexpected data on local stream context: %" PRIu64 ".\n", stream_id);
                    ret = -1;
                }
                else if (stream_id == ctx->control_stream_id) {
                    if (length > 0) {
                        uint16_t error_found = 0;
                        size_t available_data = 0;
                        uint8_t* bytes_max = bytes + length;
                        while (bytes < bytes_max) {
                            bytes = h3zero_parse_data_stream(bytes, bytes_max, &stream_ctx->ps.stream_state, &available_data, &error_found);
                            if (bytes == NULL) {
                                picoquic_log_app_message(cnx,
                                    "Could not parse incoming data from stream %" PRIu64 ", error 0x%x", stream_id, error_found);
                                ret = picoquic_close(cnx, error_found);
                                break;
                            }
                            else if (available_data > 0) {
                                /* Issue: the server call uses the "server stream ctx" data type. What to do on the client? */
                                picowt_h3zero_callback(cnx, bytes, available_data, picohttp_callback_post_data, stream_ctx, ctx);
                            }
                        }
                    }
                    if (event == picoquic_callback_stream_fin) {
                        /* FIN of the control stream is FIN of the whole session */
                        picowt_h3zero_callback(cnx, NULL, 0, picohttp_callback_post_fin, stream_ctx, ctx);
                    }
                }
                else {
                    /* NOT the control stream -- this was a stream created locally, on which
                     * the peer is replying. */
                    if (length > 0) {
                        picowt_h3zero_callback(cnx, bytes, length, picohttp_callback_post_data, stream_ctx, ctx);
                    }
                    if (event == picoquic_callback_stream_fin) {
                        /* FIN of the data stream -- maybe remove the associated resource */
                        picowt_h3zero_callback(cnx, NULL, 0, picohttp_callback_post_fin, stream_ctx, ctx);
                    }
                }
            }
            else {
                /* process incoming bidir */
                ret = wt_baton_process_remote_stream(cnx, stream_id, bytes, length,
                    event, stream_ctx, ctx);
            }
        }
        else {
            /* process the unidir streams. */
            ret = wt_baton_process_remote_stream(cnx, stream_id, bytes, length,
                event, stream_ctx, ctx);
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
            ret = 0;
        }
        else {
            /* call prepare to send event */
        }
        break;
    case picoquic_callback_almost_ready:
        break;
    case picoquic_callback_ready:
        /* Create a stream context for the connect call. */
        stream_ctx = wt_baton_create_stream(cnx, 1, ctx);
        if (stream_ctx == NULL) {
            ret = -1;
        }
        else {
            ctx->connection_ready = 1;
            ctx->is_client = 1;
            /* send the WT CONNECT */
            ret = picowt_connect(cnx, stream_ctx, ctx->stream_prefixes, ctx->server_path, picowt_h3zero_callback, ctx);
        }
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
