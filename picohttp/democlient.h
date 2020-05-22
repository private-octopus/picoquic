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

#ifndef DEMO_CLIENT_H
#define DEMO_CLIENT_H
/* This client code is provided for demonstration purposes.
 * The test client operates by running simple scripted scenarios,
 * described by a table of scenario stream descriptions.
 * The test client will create a session, and then request
 * documents on a series of streams, as specified in
 * the descriptions.
 * The client initialization installs different callback
 * functions depending on the selected ALPN: HTTP 0.9 for
 * the initial tests, and HTTP 3 for the full stack tests.
 */

typedef enum {
    picoquic_alpn_undef = 0,
	picoquic_alpn_http_0_9,
	picoquic_alpn_http_3,
    picoquic_alpn_siduck
} picoquic_alpn_enum;

#define PICOQUIC_DEMO_STREAM_ID_INITIAL (uint64_t)((int64_t)-1)

typedef struct st_picoquic_demo_stream_desc_t {
    int repeat_count;
    uint64_t stream_id;
    uint64_t previous_stream_id;
    char const* doc_name;
    char const* f_name;
    uint64_t post_size;
} picoquic_demo_stream_desc_t;

#define PICOQUIC_DEMO_STREAM_LIST_MAX 16

typedef struct st_picoquic_demo_stream_ctx_t picoquic_demo_client_stream_ctx_t;

typedef struct st_picoquic_demo_stream_ctx_t {
    picoquic_demo_client_stream_ctx_t* next_stream;
    h3zero_data_stream_state_t stream_state;
    size_t received_length;
    size_t scenario_index;
    uint64_t stream_id;
    size_t post_size;
    size_t post_sent;
    char* f_name;
    FILE* F; /* NULL if stream is closed or no_disk. */
    int is_open : 1;
    int is_file_open : 1;
    int flow_opened : 1;
} picoquic_demo_client_stream_ctx_t;

typedef struct st_picoquic_demo_client_callback_ctx_t {
    picoquic_demo_client_stream_ctx_t* first_stream;
    picoquic_demo_stream_desc_t const * demo_stream;
    picoquic_tp_t const * tp;
    char const* out_dir;
    uint64_t last_interaction_time;

    size_t nb_demo_streams;

    int nb_open_streams;
    int nb_open_files;
    uint32_t nb_client_streams;

    picoquic_alpn_enum alpn;

    int progress_observed;
    int no_disk;
    int delay_fin; /* For tests only! */
    int no_print;
    int connection_ready;
    int connection_closed;
} picoquic_demo_callback_ctx_t;

picoquic_alpn_enum picoquic_parse_alpn(char const * alpn);
picoquic_alpn_enum picoquic_parse_alpn_nz(char const* alpn, size_t len);

void picoquic_demo_client_set_alpn_from_tickets(picoquic_cnx_t* cnx, picoquic_demo_callback_ctx_t* ctx, uint64_t current_time);

int h3zero_client_init(picoquic_cnx_t* cnx);
int demo_client_prepare_to_send(void * context, size_t space, size_t echo_length, size_t * echo_sent, FILE * F);
int h3zero_client_create_stream_request(
    uint8_t * buffer, size_t max_bytes, uint8_t const * path, size_t path_len, size_t post_size, const char * host, size_t * consumed);

int h09_demo_client_prepare_stream_open_command(
    uint8_t * command, size_t max_size, uint8_t const* path, size_t path_len, size_t post_size, const char * host, size_t * consumed);

int picoquic_demo_client_start_streams(picoquic_cnx_t* cnx,
    picoquic_demo_callback_ctx_t* ctx, uint64_t fin_stream_id);
int picoquic_demo_client_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);
int picoquic_demo_client_initialize_context(
    picoquic_demo_callback_ctx_t* ctx,
    picoquic_demo_stream_desc_t const * demo_stream,
    size_t nb_demo_streams,
    char const * alpn,
    int no_disk, int delay_fin);
void picoquic_demo_client_delete_context(picoquic_demo_callback_ctx_t* ctx);

int demo_client_parse_scenario_desc(char const * text, size_t * nb_streams, picoquic_demo_stream_desc_t ** desc);
void demo_client_delete_scenario_desc(size_t nb_streams, picoquic_demo_stream_desc_t * desc);

#endif /* DEMO_CLIENT_H */