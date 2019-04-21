/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#ifndef DEMO_SERVER_H
#define DEMO_SERVER_H

/* This server code is provided for demonstration purposes.
 * The demo server serves a canned index page, or generate
 * variable length content in response to requests of the
 * form "GET /123456" (123456 bytes of data in that case.) 
 */

 /* Defining first the Http 3.0 variant of the server 
  */

#define H3ZERO_SERVER_FRAME_MAX 4096
#define H3ZERO_COMMAND_MAX 256
#define H3ZERO_RESPONSE_MAX (1 << 20)

typedef enum {
    h3zero_server_stream_status_none = 0,
    h3zero_server_stream_status_receiving,
    h3zero_server_stream_status_finished
} h3zero_server_stream_status_t;

typedef struct st_h3zero_server_stream_ctx_t {
    struct st_h3zero_server_stream_ctx_t* next_stream;
    h3zero_server_stream_status_t status;
    uint64_t stream_id;
    size_t received_length;
    uint32_t echo_length;
    uint32_t echo_sent;
    uint8_t frame[H3ZERO_SERVER_FRAME_MAX];
} h3zero_server_stream_ctx_t;

typedef struct st_h3zero_server_callback_ctx_t {
    h3zero_server_stream_ctx_t* first_stream;
    size_t buffer_max;
    uint8_t* buffer;
} h3zero_server_callback_ctx_t;

int h3zero_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);


/* Defining then the Http 0.9 variant of the server
 */

#define PICOQUIC_FIRST_COMMAND_MAX 128
#define PICOQUIC_FIRST_RESPONSE_MAX (1 << 20)

typedef enum {
    picoquic_h09_server_stream_status_none = 0,
    picoquic_h09_server_stream_status_receiving,
    picoquic_h09_server_stream_status_finished
} picoquic_h09_server_stream_status_t;

typedef struct st_picoquic_h09_server_stream_ctx_t {
    struct st_picoquic_h09_server_stream_ctx_t* next_stream;
    picoquic_h09_server_stream_status_t status;
    uint64_t stream_id;
    size_t command_length;
    size_t response_length;
    uint8_t command[PICOQUIC_FIRST_COMMAND_MAX];
} picoquic_h09_server_stream_ctx_t;

typedef struct st_picoquic_h09_server_callback_ctx_t {

    picoquic_h09_server_stream_ctx_t* first_stream;
    size_t buffer_max;
    uint8_t* buffer;
} picoquic_h09_server_callback_ctx_t;

int picoquic_h09_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

/* The generic server callback will call either http3 or http0.9,
 * according to the ALPN selected by the client
 */

int picoquic_demo_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

#endif /* DEMO_SERVER_H */