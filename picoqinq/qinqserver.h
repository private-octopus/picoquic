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

/*
 */

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

/* Context management definitions.
 */

typedef struct st_picoqinq_cnx_address_link_t {
    struct st_picoqinq_srv_cnx_ctx_t* cnx_ctx;
    struct st_picoqinq_peer_address_record_t * address_record;
    uint64_t last_access_time;
    struct st_picoqinq_cnx_address_link_t* next_cnx_by_address;
    struct st_picoqinq_cnx_address_link_t* next_address_by_cnx;
} picoqinq_cnx_address_link_t;


typedef struct st_picoqinq_peer_address_record_t {
    struct sockaddr_storage peer_addr;
    picoqinq_cnx_address_link_t* first_cnx_by_address;
} picoqinq_peer_address_record_t;

typedef struct st_picoqinq_srv_ctx_t {
    /* Quic in Quic context, server side */
    picoquic_quic_t* quic;
    uint8_t min_prefix_length;

    picohash_table* table_peer_addresses;

    struct st_picoqinq_srv_cnx_ctx_t* cnx_first;
    struct st_picoqinq_srv_cnx_ctx_t* cnx_last;
} picoqinq_srv_ctx_t;

typedef struct st_picoqinq_srv_cnx_ctx_t {
    picoqinq_srv_ctx_t* qinq;
    struct st_picoqinq_srv_cnx_ctx_t* ctx_previous;
    struct st_picoqinq_srv_cnx_ctx_t* ctx_next;
    picoqinq_header_compression_t* receive_hc;
    picoqinq_header_compression_t* send_hc;
    picoqinq_cnx_address_link_t* first_address_by_cnx;
    picoqinq_server_stream_ctx_t* first_stream;
} picoqinq_srv_cnx_ctx_t;

int picoquic_incoming_proxy_packet(
    picoqinq_srv_cnx_ctx_t* qinq,
    uint8_t* bytes,
    size_t packet_length,
    picoquic_connection_id_t* dcid,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time);

int picoqinq_server_incoming_packet(
    picoqinq_srv_ctx_t* qinq,
    uint8_t* bytes,
    size_t packet_length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time);

picoqinq_srv_ctx_t* picoqinq_create_srv_ctx(picoquic_quic_t* quic, uint8_t min_prefix_length, size_t nb_connections);
void picoqinq_delete_srv_ctx(picoqinq_srv_ctx_t* ctx);

picoqinq_srv_cnx_ctx_t* picoqinq_create_srv_cnx_ctx(picoqinq_srv_ctx_t* qinq);
void picoqinq_delete_srv_cnx_ctx(picoqinq_srv_cnx_ctx_t* ctx);

picoqinq_server_stream_ctx_t * picoqinq_find_or_create_stream(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    picoqinq_srv_cnx_ctx_t * ctx,
    int should_create);

int picoqinq_server_callback_data(picoquic_cnx_t* cnx, picoqinq_server_stream_ctx_t * stream_ctx, uint64_t stream_id, uint8_t* bytes,
    size_t length, picoquic_call_back_event_t fin_or_event, picoqinq_srv_cnx_ctx_t* callback_ctx);

void picoqinq_server_callback_delete_context(picoqinq_srv_cnx_ctx_t * ctx);

int picoqinq_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

#endif /* DEMO_SERVER_H */