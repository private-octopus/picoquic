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

/*
 * Web Transport API implementation for Picoquic.
 * 
 * Expected usage:
 *  - quic server is multipurpose, serves H3 pages, posts, etc., in addition to web socket.
 *  - WT acting as client learns of a connection to the intended server. TBD: generic
 *    connection also used for something else, or specialized connection?
 *  - WT client issues CONNECT on connection, which creates a WT context.
 *  - Server side, WT responder is notified of connect, which creates a WT context.
 *  - Both client and server could open streams
 * 
 * Architecture:
 * 
 *    -- quic events generate picoquic callbacks.
 *    -- web transport state established when processing CONNECT
 *    -- web transport intercepts related callbacks:
 *        -- incoming unidir streams starting with specified frame
 *        -- incoming bidir streams starting with specified frame
 *        -- datagrams starting with specified ID
 *    -- mapping of picoquic callbacks to WT callbacks
 * 
 * 
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <picoquic.h>
#include "h3zero_common.h"
#include "pico_webtransport.h"

/* Web transport commands */

/* Web transport initiate, client side
* cnx: an established QUIC connection, set to ALPN=H3.
* wt_callback: callback function to use in the web transport connection.
* wt_ctx: application level context for that connection.
* 
* This will reserve a bidir stream, and send a "connect" frame on that
* stream. The client will receive a WT event when the response comes
* back. 
* 
* This should create a WT connection context, which will be associated with
* the stream ID. This is associated with the connection itself. Do we have
* an H3 context for the connection?
*/
void picowt_connect(picoquic_cnx_t* cnx, h3zero_stream_prefixes_t stream_prefixes, const char* uri, picowt_ready_cb_fn wt_callback, void* wt_ctx)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx);
    UNREFERENCED_PARAMETER(stream_prefixes);
    UNREFERENCED_PARAMETER(uri);
    UNREFERENCED_PARAMETER(wt_callback);
    UNREFERENCED_PARAMETER(wt_ctx);
#endif
    /* find a new bidir stream */
    /* register the stream ID as session ID */
}

#if 0
/* Web transport callback. This will be called from the web server
 * when the path points to a web transport callback
 */

int picowt_h3zero_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t fin_or_event,
    struct st_picohttp_server_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    switch (fin_or_event) {
    case picohttp_callback_connect:
        /* A connect has been received on this stream, and could be accepted.
         */
        /* The web transport should create a web transport connection context,
         * and also register the stream ID as identifying this context.
         * Then, callback the application. That means the WT app context
         * should be obtained from the path app context, etc.
         */
        break;
    case picohttp_callback_post_data:
        /* Data received on a bidirectional stream. 
         * To do: check the processing of the webtransport data frame. 
         */
        break;
    case picohttp_callback_post_data_unidir:
        /* Data received from peer on unidir stream N */
        /* Todo: depend on stream state? */
        break;
    case picohttp_callback_post_fin: /* All posted data have been received */
        /* Todo: check whether this is data stream or control stream. If control
        * stream, then the whole WT connection needs to go */
        break;
    case picohttp_callback_provide_data: /* Stack is ready to send chunk of response */
        /* Behavior depends on the state of the stream: 
         * - Bidir stream created locally: need to send first the WT Data frame.
         * - Bidir stream created remotely: let the application send data.
         */
        break;
    case picohttp_callback_reset: /* Stream has been abandoned. */
        /* If control stream: abandon the whole connection. */
        /* Pass that to the application. */
    default:
        /* protocol error */
        return -1;
    }
}
#endif
