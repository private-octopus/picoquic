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

#define PICOHTTP_SERVER_FRAME_MAX 4096
#define PICOHTTP_FIRST_COMMAND_MAX 256
#define PICOHTTP_RESPONSE_MAX (1 << 20)

#define PICOHTTP_ALPN_H3_LATEST "h3-29"
#define PICOHTTP_ALPN_HQ_LATEST "hq-29"

  /* Define the per URL callback used to implement POST and other
   * REST-like interactions
   */

typedef enum {
    picohttp_callback_get, /* Received a get command */
    picohttp_callback_post, /* Received a post command */
    picohttp_callback_post_data, /* Data received from peer on stream N */
    picohttp_callback_post_fin, /* All posted data have been received */
    picohttp_callback_provide_data, /* Stack is ready to send chunk of response */
    picohttp_callback_reset /* Stream has been abandoned. */
} picohttp_call_back_event_t;

struct st_picohttp_server_stream_ctx_t;

typedef int (*picohttp_post_data_cb_fn)(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t fin_or_event, struct st_picohttp_server_stream_ctx_t* stream_ctx);

/* Define the table of special-purpose paths used for POST or REST queries */
typedef struct st_picohttp_server_path_item_t {
    char* path;
    size_t path_length;
    picohttp_post_data_cb_fn path_callback;
} picohttp_server_path_item_t;

typedef struct st_picohttp_server_parameters_t {
    char const* web_folder;
    picohttp_server_path_item_t* path_table;
    size_t path_table_nb;
} picohttp_server_parameters_t;

/* Identify the path item based on the incoming path in GET or POST */

int picohttp_find_path_item(const uint8_t* path, size_t path_length, const picohttp_server_path_item_t* path_table, size_t path_table_nb);

/* Define stream context common to http 3 and http 09 callbacks
 */
typedef enum {
    picohttp_server_stream_status_none = 0,
    picohttp_server_stream_status_header,
    picohttp_server_stream_status_crlf,
    picohttp_server_stream_status_receiving,
    picohttp_server_stream_status_finished
} picohttp_server_stream_status_t;

typedef struct st_picohttp_server_stream_ctx_t {
    /* TODO-POST: identification of URL to process POST or GET? */
    /* TODO-POST: provide content-type */
    picosplay_node_t http_stream_node;
    struct st_picohttp_server_stream_ctx_t* next_stream;
    int is_h3;
    union {
        h3zero_data_stream_state_t stream_state; /* h3 only */
        struct {
            picohttp_server_stream_status_t status; 
            int proto; 
            uint8_t* path; 
            size_t path_length;
            size_t command_length;
        } hq; /* h09 only */
    } ps; /* Protocol specific state */
    uint64_t stream_id;
    size_t response_length;
    size_t echo_length;
    size_t echo_sent;
    size_t post_received;
    uint8_t frame[PICOHTTP_SERVER_FRAME_MAX];
    int method;
    picohttp_post_data_cb_fn path_callback;
    void* path_callback_ctx;
    FILE* F;
} picohttp_server_stream_ctx_t;

/* Define the H3Zero server callback */

typedef struct st_h3zero_server_callback_ctx_t {
    picosplay_tree_t h3_stream_tree;
    picohttp_server_stream_ctx_t* first_stream;
    size_t buffer_max;
    uint8_t* buffer;
    picohttp_server_path_item_t * path_table;
    size_t path_table_nb;
    char const* web_folder;
} h3zero_server_callback_ctx_t;

int h3zero_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);


/* Defining then the Http 0.9 variant of the server
 */

typedef struct st_picoquic_h09_server_callback_ctx_t {
    picosplay_tree_t h09_stream_tree;
    picohttp_server_stream_ctx_t* first_stream;
    picohttp_server_path_item_t * path_table;
    size_t path_table_nb;
    char const* web_folder;
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

size_t picoquic_demo_server_callback_select_alpn(picoquic_quic_t* quic, ptls_iovec_t* list, size_t count);

int demo_server_is_path_sane(const uint8_t* path, size_t path_length);

int demo_server_try_file_path(const uint8_t* path, size_t path_length, size_t* echo_size, FILE** pF, char const* web_folder);

/* For building a basic HTTP 0.9 test server */
int http0dot9_get(uint8_t* command, size_t command_length,
    uint8_t* response, size_t response_max, size_t* response_length);

#endif /* DEMO_SERVER_H */