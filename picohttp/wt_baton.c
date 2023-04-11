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
    int ret = 0;

    picohttp_server_stream_ctx_t* stream_ctx = wt_baton_find_stream(baton_ctx, baton_ctx->control_stream_id);

    picoquic_log_app_message(cnx, "Closing session, closing and unlinking control stream %" PRIu64, baton_ctx->control_stream_id);

    if (stream_ctx != NULL && !stream_ctx->ps.stream_state.is_fin_sent) {
        ret = picoquic_add_to_stream_with_ctx(cnx, baton_ctx->control_stream_id, NULL, 0, 1, NULL);
        stream_ctx->ps.stream_state.is_fin_sent = 1;
    }

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
        stream_ctx->path_callback = wt_baton_callback;
        stream_ctx->path_callback_ctx = baton_ctx;
        ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, &baton_ctx->baton, 1, 1, stream_ctx);

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
    if (baton_ctx->baton_received == 0) {
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
        int is_wrong_baton = (baton_ctx->baton_state == wt_baton_state_sent &&
            baton_ctx->baton_received != (baton_ctx->baton + 1));
        if (is_wrong_baton) {
            baton_ctx->baton_state = wt_baton_state_error;
            picoquic_log_app_message(cnx, "Wrong baton on stream: %"PRIu64 " after %d turns", stream_ctx->stream_id, baton_ctx->nb_turns);
            ret = wt_baton_close_session(cnx, baton_ctx);
        }
        else {
            int baton_7 = baton_ctx->baton_received % 7;

            if (baton_7 == picoquic_is_client(cnx) && baton_ctx->baton_received != 0) {
                baton_ctx->is_datagram_ready = 1;
                baton_ctx->baton_datagram_send_next = baton_ctx->baton_received;
                h3zero_set_datagram_ready(cnx, baton_ctx->control_stream_id);
            }

            baton_ctx->nb_turns += 1;  /* add a turn for the peer sending this */
            if (baton_ctx->nb_turns >= baton_ctx->nb_turns_required) {
                picoquic_log_app_message(cnx, "Final baton turn after %d turns", baton_ctx->nb_turns);
                baton_ctx->baton_state = wt_baton_state_done;
                baton_ctx->baton = 0;
            }
            else if (baton_ctx->nb_turns >= 4 && baton_ctx->nb_turns_required == 257) {
                picoquic_log_app_message(cnx, "Error injection after %d turns (key: %d)", baton_ctx->nb_turns, baton_ctx->nb_turns_required);
                baton_ctx->baton += 31;
                if (baton_ctx->baton == 0) {
                    baton_ctx->baton = 1;
                }
            }
            else {
                baton_ctx->baton_state = wt_baton_state_sent;
                baton_ctx->baton = baton_ctx->baton_received + 1;
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

    if (baton_ctx->baton_state != wt_baton_state_ready && baton_ctx->baton_state != wt_baton_state_sent) {
        /* Unexpected data at this stage */
        picoquic_log_app_message(cnx, "Received baton data on stream %" PRIu64 ", when not ready",
            stream_ctx->stream_id);
        ret = -1;
    }
    else {
        if (length > 1) {
            /* Protocol error */
            picoquic_log_app_message(cnx, "Received %zu baton bytes on stream %" PRIu64 ", %zu expected",
                length, stream_ctx->stream_id, 1);
            ret = -1;
        }
        else {
            baton_ctx->baton_received = *bytes;
            ret = wt_baton_check(cnx, stream_ctx, baton_ctx);
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
    h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx);
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)malloc(sizeof(wt_baton_ctx_t));
    if (baton_ctx == NULL) {
        ret = -1;
    }
    else {
        picoquic_log_app_message(cnx, "allocated baton context size(%zu), control stream %" PRIu64, sizeof(wt_baton_ctx_t), stream_ctx->stream_id);
        /* register the incoming stream ID */
        ret = wt_baton_ctx_init(baton_ctx, h3_ctx, app_ctx, stream_ctx);
        if (ret == 0) {
            stream_ctx->ps.stream_state.is_web_transport = 1;
            stream_ctx->path_callback = wt_baton_callback;
            stream_ctx->path_callback_ctx = baton_ctx;
            baton_ctx->connection_ready = 1;
            /* fill the baton with random data */
            baton_ctx->baton = (uint8_t)picoquic_public_uniform_random(128) + 1;
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

    stream_ctx->ps.stream_state.is_fin_received = 1;

    if (stream_ctx->stream_id == baton_ctx->control_stream_id) {
        /* Closing the control stream implies closing the baton context. 
         */
        picoquic_log_app_message(cnx, "FIN on control stream. Closing the connection.\n");
        ret = wt_baton_close_session(cnx, baton_ctx);
        baton_ctx->baton_state = wt_baton_state_closed;
        if (cnx->client_mode) {
            baton_ctx->connection_closed = 1;
            /* Close the connection */
            picoquic_close(cnx, 0);
        }
        h3zero_delete_stream_prefix(cnx, baton_ctx->stream_prefixes, baton_ctx->control_stream_id);
    }
    else {
        if (stream_ctx->ps.stream_state.is_fin_sent == 1) {
            picoquic_set_app_stream_ctx(cnx, stream_ctx->stream_id, NULL);
            h3zero_delete_stream(baton_ctx->h3_stream_tree, stream_ctx);
        }
    }
    return ret;
}

int wt_baton_stream_reset(picoquic_cnx_t* cnx, picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;

    picoquic_log_app_message(cnx, "Received reset on stream %" PRIu64 ", closing the session", stream_ctx->stream_id);

    if (baton_ctx != NULL) {
        ret = wt_baton_close_session(cnx, baton_ctx);

        /* Any reset results in the abandon of the context */
        baton_ctx->baton_state = wt_baton_state_closed;
        if (baton_ctx->is_client) {
            ret = picoquic_close(cnx, 0);
        }
        h3zero_delete_stream_prefix(cnx, baton_ctx->stream_prefixes, baton_ctx->control_stream_id);
    }

    return ret;
}

void wt_baton_unlink_context(picoquic_cnx_t* cnx,
    struct st_picohttp_server_stream_ctx_t* control_stream_ctx,
    void* v_ctx)
{
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)v_ctx;
    picosplay_node_t* previous = NULL;

    /* dereference the control stream ID */
    picoquic_log_app_message(cnx, "Prefix for control stream %"PRIu64 " was unregistered", control_stream_ctx->stream_id);
    /* Free the streams created for this session */
    while (1) {
        picosplay_node_t* next = (previous == NULL) ? picosplay_first(baton_ctx->h3_stream_tree) : picosplay_next(previous);
        if (next == NULL) {
            break;
        }
        else {
            picohttp_server_stream_ctx_t* stream_ctx =
                (picohttp_server_stream_ctx_t*)picohttp_stream_node_value(next);

            if (control_stream_ctx->stream_id == stream_ctx->control_stream_id &&
                control_stream_ctx->stream_id != stream_ctx->stream_id) {
                h3zero_forget_stream(cnx, stream_ctx);
                picosplay_delete_hint(baton_ctx->h3_stream_tree, next);
            }
            else {
                previous = next;
            }
        }
    }
    /* Then free the baton context, if this is not a client */
    picoquic_set_app_stream_ctx(cnx, control_stream_ctx->stream_id, NULL);
    if (!cnx->client_mode) {
        free(baton_ctx);
    }
}

/* Management of datagrams
 */
int wt_baton_receive_datagram(picoquic_cnx_t* cnx,
    const uint8_t* bytes, size_t length,
    struct st_picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;
    const uint8_t* bytes_max = bytes + length;
    uint64_t padding_length;
    uint8_t next_baton = 0;

    /* Parse the padding length  */
    if (stream_ctx != NULL && stream_ctx->stream_id != baton_ctx->control_stream_id) {
        /* error, unexpected datagram on this stream */
    }
    else if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &padding_length)) != NULL &&
            (bytes = picoquic_frames_fixed_skip(bytes, bytes_max, padding_length)) != NULL &&
            (bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &next_baton)) != NULL &&
            bytes == bytes_max){
        baton_ctx->baton_datagram_received = next_baton;
        baton_ctx->nb_datagrams_received += 1;
        baton_ctx->nb_datagram_bytes_received += 1;
    }
    else {
        /* error, badly coded datagram */
    }
    return ret;
}

int wt_baton_provide_datagram(picoquic_cnx_t* cnx,
    void* context, size_t space,
    struct st_picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_baton_ctx_t* baton_ctx = (wt_baton_ctx_t*)path_app_ctx;

    if (baton_ctx->is_datagram_ready) {
        if (space > 1536) {
            space = 1536;
        }
        if (space < 3) {
            /* Not enough space to send anything */
        }
        else {
            uint8_t* buffer = h3zero_provide_datagram_buffer(context, space, 0);
            if (buffer == NULL) {
                ret = -1;
            }
            else {
                size_t padding_length = space - 3;
                uint8_t* bytes = buffer;
                *bytes++ = 0x40 | (uint8_t)((padding_length >> 8) & 0x3F);
                *bytes++ = (uint8_t)(padding_length & 0xFF);
                memset(bytes, 0, padding_length);
                bytes += padding_length;
                *bytes = baton_ctx->baton_datagram_send_next;
                baton_ctx->is_datagram_ready = 0;
                baton_ctx->baton_datagram_send_next = 0;
                baton_ctx->nb_datagrams_sent += 1;
                baton_ctx->nb_datagram_bytes_sent += space;
            }
        }
    }

    return ret;
}

/* Web transport/baton callback. This will be called from the web server
* when the path points to a web transport callback.
* Discuss: is the stream context needed? Should it be a wt_stream_context?
*/

int wt_baton_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t event,
    struct st_picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    DBG_PRINTF("wt_baton_callback: %d, %" PRIi64 "\n", (int)event, (stream_ctx == NULL)?(int64_t)-1:(int64_t)stream_ctx->stream_id);
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
    case picohttp_callback_post_data:
        /* Data received on a stream for which the per-app stream context is known.
        * the app just has to process the data.
        */
        ret = wt_baton_stream_data(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_post_fin: /* All posted data have been received */
        /* Close the stream. If it is the WT control stream, close the 
         * entire WT connection */
        picoquic_log_app_message(cnx, "FIN received on data stream: %"PRIu64, stream_ctx->stream_id);
        ret = wt_baton_stream_fin(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_provide_data: /* Stack is ready to send chunk of response */
        /* We assume that the required stream headers have already been pushed,
        * and that the stream context is already set. Just send the data.
        */
        break;
    case picohttp_callback_post_datagram:
        /* Data received on a stream for which the per-app stream context is known.
        * the app just has to process the data.
        */
        ret = wt_baton_receive_datagram(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_provide_datagram: /* Stack is ready to send a datagram */
        ret = wt_baton_provide_datagram(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_reset: /* Stream has been abandoned. */
        /* If control stream: abandon the whole connection. */
        ret = wt_baton_stream_reset(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_free: /* Used during clean up the stream. Only cause the freeing of memory. */
        /* Free the memory attached to the stream */
        break;
    case picohttp_callback_deregister:
        /* The app context has been removed from the registry.
         * Its references should be removed from streams belonging to this session.
         * On the client, the memory should be freed.
         */
        wt_baton_unlink_context(cnx, stream_ctx, path_app_ctx);
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
    picohttp_server_stream_ctx_t* stream_ctx = h3zero_find_stream(ctx->h3_stream_tree, stream_id);
    return stream_ctx;
}

/* Initialize the content of a wt_baton context.
* TODO: replace internal pointers by pointer to h3zero context
*/
int wt_baton_ctx_init(wt_baton_ctx_t* ctx, h3zero_callback_ctx_t* h3_ctx, wt_baton_app_ctx_t * app_ctx, picohttp_server_stream_ctx_t* stream_ctx)
{
    int ret = 0;

    memset(ctx, 0, sizeof(wt_baton_ctx_t));
    /* Init the stream tree */
    /* Do we use the path table for the client? or the web folder? */
    /* connection wide tracking of stream prefixes */
    if (h3_ctx == NULL) {
        ret = -1;
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
        ctx->nb_turns_required = 17;
    }

    if (stream_ctx != NULL) {
        /* Register the control stream and the stream id */
        ctx->control_stream_id = stream_ctx->stream_id;
        stream_ctx->control_stream_id = stream_ctx->stream_id;
        ret = h3zero_declare_stream_prefix(ctx->stream_prefixes, stream_ctx->stream_id, wt_baton_callback, ctx);
    }
    else {
        /* Poison the control stream ID field so errors can be detected. */
        ctx->control_stream_id = UINT64_MAX;
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

