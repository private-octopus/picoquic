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

#ifndef picoqinq_server_H
#define picoqinq_server_H


struct st_picoqinq_server_stream_ctx_t;

/* Define stream context for callbacks
 */
typedef enum {
    picoqinq_server_stream_status_none = 0,
    picoqinq_server_stream_status_header,
    picoqinq_server_stream_status_crlf,
    picoqinq_server_stream_status_receiving,
    picoqinq_server_stream_status_finished
} picoqinq_server_stream_status_t;

#define PICOQINQ_SERVER_FRAME_MAX 2048

typedef struct st_picoqinq_server_stream_ctx_t {
    struct st_picoqinq_server_stream_ctx_t* next_stream;
    uint64_t stream_id;
    size_t data_received;
    int is_fin_received : 1;
    int is_reset : 1;
    uint8_t frame[PICOQINQ_SERVER_FRAME_MAX];
} picoqinq_server_stream_ctx_t;


/* Define the QinQ server callback */

typedef struct st_picoqinq_server_callback_ctx_t {
    struct st_picoqinq_ctx_t* qinq_ctx;
    picoqinq_server_stream_ctx_t* first_stream;
    size_t buffer_max;
    uint8_t* buffer;
} picoqinq_server_callback_ctx_t;

/*
 * Structures used in the hash table of connections
 */
#define PICOQINQ_MIN_CID_LENGTH 4
typedef struct st_picoqinq_cnx_id_key_t {
    uint8_t cnx_id[PICOQINQ_MIN_CID_LENGTH];
    struct st_picoqinq_server_callback_ctx_t* cnx_ctx;
    struct st_picoqinq_cnx_id_key_t* next_cnx_id;
} picoqinq_cnx_id_key_t;

/* Quic in Quic context
 */
typedef struct st_picoqinq_ctx_t {
    picoquic_quic_t* quic;
    /* TODO: hash table of CNX_ID */
    /* TODO: list of connections? */
} picoqinq_ctx_t;

picoqinq_server_stream_ctx_t * picoqinq_find_or_create_stream(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    picoqinq_server_callback_ctx_t * ctx,
    int should_create);

int picoqinq_server_callback_data(picoquic_cnx_t* cnx, picoqinq_server_stream_ctx_t * stream_ctx, uint64_t stream_id, uint8_t* bytes, 
    size_t length, picoquic_call_back_event_t fin_or_event, picoqinq_server_callback_ctx_t* callback_ctx);

picoqinq_server_callback_ctx_t * picoqinq_server_callback_create_context(picoqinq_ctx_t * qinq_ctx);

void picoqinq_server_callback_delete_context(picoqinq_server_callback_ctx_t * ctx);

int picoqinq_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

#endif /* DEMO_SERVER_H */