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

#ifndef pico_webtransport_H
#define pico_webtransport_H

#ifdef __cplusplus
extern "C" {
#endif

/* Web transport callback API */
typedef enum {
    picowt_cb_ready, /* Data can be sent and received, connection migration can be initiated */
    picowt_cb_close, /* Control socket closed. Stream=0, bytes=NULL, len=0 */
    picowt_cb_stream_data, /* Data received from peer on stream N */
    picowt_cb_stream_fin, /* Fin received from peer on stream N; data is optional */
    picowt_cb_stream_reset, /* Reset Stream received from peer on stream N; bytes=NULL, len = 0  */
    picowt_cb_stop_sending, /* Stop sending received from peer on stream N; bytes=NULL, len = 0 */
    picowt_cb_prepare_to_send, /* Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details */
    picowt_cb_datagram, /* Datagram frame has been received */
    picowt_cb_prepare_datagram, /* Prepare the next datagram */
    picowt_cb_datagram_acked, /* Ack for packet carrying datagram-frame received from peer */
    picowt_cb_datagram_lost, /* Packet carrying datagram-frame probably lost */
    picowt_cb_datagram_spurious, /* Packet carrying datagram-frame was not really lost */
    picowt_cb_pacing_changed /* Pacing rate for the connection changed */
} picowt_event_t;

#if 0
/* TODO: Set API to match requirements */
typedef int (*picowt_ready_cb_fn)(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picowt_event_t event, void* callback_ctx, void* stream_ctx);
#endif

/* Web transport initiate, client side
 * cnx: an established QUIC connection, set to ALPN=H3.
 * wt_callback: callback function to use in the web transport connection.
 * wt_ctx: application level context for that connection.
 */
int picowt_connect(picoquic_cnx_t* cnx, picohttp_server_stream_ctx_t* stream_ctx, h3zero_stream_prefixes_t* stream_prefixes, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx);

/* Private API for implementing web transport:
 * - process the register request.
 * - process the incoming streams, associate them with webtransport context.
 * - maintain state on streams, to check whether they are 
 * - process the incoming datagrams.
 */

/* web transport stream context.
 */
typedef struct st_picowt_stream_ctx_t {
    /* Pointer to connection context*/
    /* Chain stream context to pico_web_transport_ctx */
    uint64_t stream_id; /* stream ID */
    int header_received; /* Incoming streams: was the web transport header processed ?*/
    int header_sent;  /* Outgoing streams: was the web transport header sent ?*/
    int fin_received;
    int fin_sent;
} picowt_stream_ctx_t;

/* Web transport connection context */
typedef struct st_picowt_cnx_ctx_t {
    /* Context ID is set to stream ID of the connect stream. */
    uint64_t context_id;
} picowt_cnx_ctx_t;

/* Web transport server context */

/* Open web transport context */


#ifdef __cplusplus
}
#endif

#endif /* PICO_WEBTRANSPORT_H */