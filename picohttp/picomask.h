/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
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

#ifndef PICOMASK_H
#define PICOMASK_H

#include "picohash.h"
#include "picosplay.h"
#include "picoquic.h"
#include "picoquic_utils.h"
#include "h3zero.h"
#include "h3zero_common.h"
//#include "picoquic_internal.h"

#ifdef __cplusplus
extern "C" {
#endif
/*
* Context is split between two levels:
* - The global context of the picomask service, which
*   holds for example the list of all connection contexts,
*   the global list of incoming VCID, etc.
* - The per connection entry, which holds the state
*   and the queue of packets for a given connect-udp
*   connection.
* The global context is initialized when starting the
* service.
*/

/* We need to reserve an interface ID that does not collude with
* values likely used by the operating system. This excludes
* small numbers, and special numbers like 0 or -1. We pick
* a random 31 bit number, derived from the SHA1 hash of
* "Picomask UDP interface":
* 2798c62715dd8ce6e2c6dd92a37a8276f16c029e
*/
#define picomask_interface_id 0x2798c627

typedef struct st_picomask_packet_t {
    struct st_picomask_packet_t* next_packet;
    uint64_t arrival_time;
    size_t length;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    uint8_t ecn_mark;
    uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
} picomask_packet_t;

typedef struct st_picomask_ctx_t {
    picoquic_cnx_t* cnx; /* Null on server. On client, the connection to the proxy */
    h3zero_callback_ctx_t* h3_ctx; /* Null on server. On client, the H3 context of the proxy connection */
    char const* path_template; /* Null on server */
    picosplay_tree_t udp_tree;
    picohash_table* table_udp_ctx;
    uint64_t picomask_number_next;
    picomask_packet_t* intercepted_first; /* queue of packets waitting to be sent to peer */
    picomask_packet_t* intercepted_last;
    picomask_packet_t* forwarding_first; /* queue of packets waiting to be sent to network */
    picomask_packet_t* forwarding_last;
    picomask_packet_t* packet_heap;
} picomask_ctx_t;

typedef struct st_picomask_h3_ctx_t {
    struct sockaddr_storage target_addr;
    picoquic_cnx_t* cnx;
} picomask_h3_ctx_t;

typedef struct st_picomask_udp_ctx_t {
    picohash_item hash_item;
    picosplay_node_t node;
    struct sockaddr_storage target_addr;
    struct sockaddr_storage local_addr;
    picomask_ctx_t* picomask_ctx;
    h3zero_stream_ctx_t* h3_stream;
    /* Management of capsule protocol on control stream */
    /* Management of datagram queue -- incoming packets
     * that have to be processed locally */
    picomask_packet_t* outgoing_first;
    picomask_packet_t* outgoing_last;
} picomask_udp_ctx_t;

int picomask_ctx_init(picomask_ctx_t* ctx);
void picomask_ctx_release(picomask_ctx_t* ctx);

picomask_udp_ctx_t* picomask_udp_ctx_by_number(picomask_ctx_t* ctx, uint64_t picomask_number);

int picomask_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t wt_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx);

int picomask_register_proxy(picoquic_quic_t* quic, char const* proxy_sni, size_t max_nb_udp,
    struct sockaddr* proxy_addr, uint64_t current_time, const char* path_template);

picomask_udp_ctx_t* picomask_udp_ctx_find(picomask_ctx_t* picomask_ctx, struct sockaddr* target_addr);

int picomask_connect_udp(picoquic_quic_t* quic, const char* authority, struct sockaddr* target_addr);

int picomask_expand_udp_path(char* text, size_t text_size, size_t* text_length, char const* path_template, struct sockaddr* addr);

#ifdef __cplusplus
}
#endif

#endif /* PICOMASK_H */
