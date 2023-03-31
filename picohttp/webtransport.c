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
* stream_ctx: a new stream, created for the purpose of sending the connect request
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
int picowt_connect(picoquic_cnx_t* cnx, picohttp_server_stream_ctx_t* stream_ctx, h3zero_stream_prefixes_t * stream_prefixes, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx)
{
    /* register the stream ID as session ID */
    int ret = h3zero_declare_stream_prefix(stream_prefixes, stream_ctx->stream_id, wt_callback, wt_ctx);

    ret = wt_callback(cnx, NULL, 0, picohttp_callback_connecting, stream_ctx, wt_ctx);

    if (ret == 0) {
        /* Format and send the connect frame. */
        uint8_t buffer[1024];
        uint8_t* bytes = buffer;
        uint8_t* bytes_max = bytes + 1024;

        *bytes++ = h3zero_frame_header;
        bytes += 2; /* reserve two bytes for frame length */

        bytes = h3zero_create_connect_header_frame(bytes, bytes_max, (const uint8_t*)path, strlen(path), "webtransport", NULL,
            H3ZERO_USER_AGENT_STRING);

        if (bytes == NULL) {
            ret = -1;
        }
        else {
            /* Encode the header length */
            size_t header_length = bytes - &buffer[3];
            if (header_length < 64) {
                buffer[1] = (uint8_t)(header_length);
                memmove(&buffer[2], &buffer[3], header_length);
                bytes--;
            }
            else {
                buffer[1] = (uint8_t)((header_length >> 8) | 0x40);
                buffer[2] = (uint8_t)(header_length & 0xFF);
            }
            size_t connect_length = bytes - buffer;

            ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, buffer, connect_length,
                    0, stream_ctx);
        }

        if (ret != 0) {
            /* remove the stream prefix */
            h3zero_delete_stream_prefix(stream_prefixes, stream_ctx->stream_id);
        }
    }
    return ret;
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
