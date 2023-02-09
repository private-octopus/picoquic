/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

#ifndef PICOWT_H
#define PICOWT_H

#include <stdio.h>
#include <inttypes.h>
#include "picoquic.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The API that we need to support:
 * 
 * - Create a web transport context:
 *     - On the client side: create a session;
 *       be notified when the session is ready.
 *     - On the server side: create a session upon receiving a connect request.
 * - Close the web transport context and session.
 *     - be notified if the session is closed by the peer.
 * - Create a bidirectional stream
 *     - be notified if the peer creates a stream, upon arrival of data.
 *     - be notified if the stream is finished
 * - Create a unidirectional stream
 *     - be notified if the peer creates a stream, upon arrival of data.
 *     - be notified if the stream is finished
 * - Mark a stream (bidir or unidir) as active
 *     - be notified if the stream is ready for sending
 *     - on callback, mark the stream as closed.
 * - Mark the context as ready to send datagrams
 *     - on callback, provide data
 *     - be notified when datagram arrives
 * - Reset a stream
 *     - be notified
 * - Ask peer to stop sending on stream
 *     - be notified
 */

typedef enum {
    picowt_callback_connect, /* Webtransport connect requested by peer */
    picowt_callback_ready, /* Connect request for this context was successfull */
    picowt_callback_close, /* Connection close. Stream=0, bytes=NULL, len=0 */
    picowt_callback_pacing_changed, /* Pacing rate for the connection changed */
    picowt_callback_stream_data, /* Data received from peer on stream N */
    picowt_callback_stream_fin, /* Fin received from peer on stream N; data is optional */
    picowt_callback_stream_reset, /* Reset Stream received from peer on stream N; bytes=NULL, len = 0  */
    picowt_callback_stop_sending, /* Stop sending received from peer on stream N; bytes=NULL, len = 0 */
    picowt_callback_prepare_to_send, /* Ask application to send data in frame */
    picowt_callback_prepare_datagram, /* Datagram arrival */
    picowt_callback_prepare_datagram, /* Prepare the next datagram */
    picowt_callback_datagram_acked, /* Ack for packet carrying datagram-frame received from peer */
    picowt_callback_datagram_lost, /* Packet carrying datagram-frame probably lost */
    picowt_callback_datagram_spurious /* Packet carrying datagram-frame was not really lost */
} picowt_call_back_event_t;

typedef int (*picowt_callback_fn)(picoquic_cnx_t* cnx, picowt_call_back_event_t event, 
    uint64_t current_time,  uint64_t stream_id, uint8_t* bytes, size_t length,
    void* callback_ctx, void * stream_ctx);

/* TODO: These two structures should be opaque
 */
typedef struct st_picowt_stream_ctx_t {
    picowt_ctx_t* picowt_ctx;
    struct st_picowt_stream_ctx_t* next_stream;
    struct st_picowt_stream_ctx_t* previous_stream;
    uint64_t stream_id;
    void* app_stream_ctx;
} picowt_stream_ctx_t;

typedef struct st_picowt_ctx_t {
    picoquic_cnx_t* cnx;
    uint64_t control_stream_id;
    struct st_picowt_stream_ctx_t* first_stream;
    struct st_picowt_stream_ctx_t* last_stream;
    void* app_ctx;
} picowt_ctx_t;

/* Create a webtransport session. This will generate a connect request
 * to the specified path on the specified H3 connection. The next
 * callback will be associated with the specified context.
 * TODO: do we need more data? Should the call return a picowt_ctx_t ?
 */
picowt_ctx_t * picowt_create_session(picoquic_cnx_t* cnx, const char * path, void* app_ctx);

/* Close the web transport context and session.
 * This will close or reset all associated streams.
 */
void picowt_close_session(picowt_ctx_t* picowt_ctx);

/* Create and use a stream context
 */
picowt_stream_ctx_t * picowt_create_stream(picoquic_cnx_t* cnx, const char * path, int is_bidir, int priority, void* app_stream_ctx);
void picowt_close_stream(picowt_stream_ctx_t* picowt_stream_ctx);
void picowt_reset_stream(picowt_stream_ctx_t* picowt_stream_ctx);
void picowt_stop_sending(picowt_stream_ctx_t* picowt_stream_ctx);
int picowt_is_stream_bidir(picowt_stream_ctx_t* picowt_stream_ctx);
int picowt_set_priority(picowt_stream_ctx_t* picowt_stream_ctx, int priority);
int picowt_mark_ready_to_send_on_stream(picowt_stream_ctx_t* picowt_stream_ctx, int is_ready);
uint8_t* picowt_provide_stream_data_buffer(void* context, size_t nb_bytes, int is_fin, int is_still_active);

/* Send datagrams */
int picowt_mark_ready_to_send_datagram(picowt_ctx_t* picowt_ctx, int is_ready);
uint8_t* picowt_provide_datagram_buffer(void* context, size_t nb_bytes, int is_still_active);

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_CONFIG_H */