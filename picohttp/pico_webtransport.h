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


/* Web socket callback API */
typedef enum {
    pico_webtransport_cb_ready, /* Data can be sent and received, connection migration can be initiated */
    pico_webtransport_cb_close, /* Control socket closed. Stream=0, bytes=NULL, len=0 */
    pico_webtransport_cb_stream_data, /* Data received from peer on stream N */
    pico_webtransport_cb_stream_fin, /* Fin received from peer on stream N; data is optional */
    pico_webtransport_cb_stream_reset, /* Reset Stream received from peer on stream N; bytes=NULL, len = 0  */
    pico_webtransport_cb_stop_sending, /* Stop sending received from peer on stream N; bytes=NULL, len = 0 */
    pico_webtransport_cb_prepare_to_send, /* Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details */
    pico_webtransport_cb_datagram, /* Datagram frame has been received */
    pico_webtransport_cb_prepare_datagram, /* Prepare the next datagram */
    pico_webtransport_cb_datagram_acked, /* Ack for packet carrying datagram-frame received from peer */
    pico_webtransport_cb_datagram_lost, /* Packet carrying datagram-frame probably lost */
    pico_webtransport_cb_datagram_spurious, /* Packet carrying datagram-frame was not really lost */
    pico_webtransport_cb_pacing_changed /* Pacing rate for the connection changed */
} pico_webtransport_event_t;

/* Buffer request, similar to provide stream data. */
uint8_t * pico_webtransport_provide_buffer(void* context, size_t nb_bytes, int is_fin, int is_still_active);

/* TODO: Set API to match requirements */
typedef int (*pico_webtransport_ready_cb_fn)(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    pico_webtransport_event_t fin_or_event, void* callback_ctx, void* stream_ctx);

/* Server: web socket register: declare URI and associated callback function. */
void pico_webtransport_register(picoquic_quic_t * quic, const char* uri, pico_webtransport_ready_cb_fn ws_callback, void * ws_ctx);

/* Web socket initiate, client side */
void pico_webtransport_connect(picoquic_cnx_t* cnx, const char* uri, pico_webtransport_ready_cb_fn ws_callback, void* ws_ctx);

/* Web socket terminate, either client or server */
void pico_webtransport_close();

/* Private API for implementing web socket:
 * - process the register request.
 * - process the incoming streams, associate them with websocket context.
 * - maintain state on streams, to check whether they are 
 * - process the incoming datagrams.
 */

/* web socket stream context.
 */
typedef struct st_pico_webtransport_stream_ctx_t {
    /* Pointer to connection context*/
    /* Chain stream context to pico_web_socket_ctx */
    uint64_t stream_id; /* stream ID */
    int header_received; /* Incoming streams: was the web socket header processed ?*/
    int header_sent;  /* Outgoing streams: was the web socket header sent ?*/
    int fin_received;
    int fin_sent;
} pico_webtransport_stream_ctx_t;

/* Web socket context */
typedef struct st_pico_webtransport_cnx_ctx_t {
    /* Context ID is set to stream ID of the connect stream. */
    uint64_t context_id;
} pico_webtransport_cnx_ctx_t;

#ifdef __cplusplus
}
#endif

#endif /* pico_webtransport_H */