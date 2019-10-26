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

#ifndef QINQ_PROTO_H
#define QINQ_PROTO_H

#include <stdint.h>
#include "picohash.h"
#include "picoquic.h"

#define QINQ_PROTO_RESERVE_HEADER 1
#define QINQ_PROTO_RESERVE_CID 2

#define PICOQINQ_ERROR_NO_ERROR 0x500
#define PICOQINQ_ERROR_INTERNAL 0x501
#define PICOQINQ_ERROR_PROTOCOL 0x502
#define PICOQINQ_ERROR_CID_TOO_SHORT 0x503

#define PICOQINQ_MINIMUM_CID_LENGTH 4

typedef struct st_picoquic_cid_cnx_link_t {
    struct st_picoqinq_cnx_ctx_t* cnx_ctx;
    picoquic_connection_id_t cid;
    struct st_picoqinq_qinq_cid_prefix_route_t* cid_route;
    struct st_picoquic_cid_cnx_link_t* next_route;
    struct st_picoquic_cid_cnx_link_t* next_cid;
} picoquic_cid_cnx_link_t;

typedef struct st_picoqinq_qinq_cid_prefix_route_t {
    picoquic_connection_id_t cid_prefix; /* Reduced to agreed min length of CID */
    picoquic_cid_cnx_link_t* first_route;
} picoqinq_qinq_cid_prefix_route_t;

typedef struct st_picoqinq_qinq_t {
    uint8_t min_prefix_length;
    picohash_table* table_prefix_route;
    struct st_picoqinq_cnx_ctx_t* cnx_first;
    struct st_picoqinq_cnx_ctx_t* cnx_last;
} picoqinq_qinq_t;

typedef struct st_picoqinq_header_compression_t {
    struct st_picoqinq_header_compression_t* next_hc;
    uint64_t hcid;
    size_t address_length;
    uint8_t address[16];
    uint16_t port;
    picoquic_connection_id_t cid;
} picoqinq_header_compression_t;

typedef struct st_picoqinq_cnx_ctx_t {
    picoqinq_qinq_t* qinq;
    struct st_picoqinq_cnx_ctx_t* ctx_previous;
    struct st_picoqinq_cnx_ctx_t* ctx_next;
    picoqinq_header_compression_t* receive_hc;
    picoqinq_header_compression_t* send_hc;
    picoquic_cid_cnx_link_t* first_cid;
} picoqinq_cnx_ctx_t;

picoqinq_qinq_t* picoqinq_create(uint8_t min_prefix_length, size_t nb_cid);
void picoqinq_delete(picoqinq_qinq_t* ctx);

picoqinq_cnx_ctx_t* picoqinq_create_cnx_ctx(picoqinq_qinq_t* qinq);
void picoqinq_delete_cnx_ctx(picoqinq_cnx_ctx_t* ctx);

uint8_t* picoqinq_decode_datagram_header(picoqinq_cnx_ctx_t* ctx, uint8_t* bytes, uint8_t* bytes_max, size_t* address_length, const uint8_t** address, uint16_t* port,
    picoquic_connection_id_t** cid);

uint8_t* picoqinq_encode_reserve_header(uint8_t* bytes, uint8_t* bytes_max,
    uint64_t direction, uint64_t hcid,
    size_t address_length, const uint8_t* address, uint16_t port, const picoquic_connection_id_t* cid);
uint8_t* picoqinq_decode_reserve_header(uint8_t* bytes, uint8_t* bytes_max,
    uint64_t* direction, uint64_t* hcid,
    size_t* address_length, const uint8_t** address, uint16_t* port, picoquic_connection_id_t* cid);
picoqinq_header_compression_t* picoqinq_create_header(uint64_t hcid,
    size_t address_length, const uint8_t* address, uint16_t port, const picoquic_connection_id_t* cid);
void picoqinq_reserve_header(picoqinq_header_compression_t* hc, picoqinq_header_compression_t** phc_head);
uint64_t picoqinq_find_reserve_header_id_by_address(picoqinq_header_compression_t** phc_head, size_t address_length, const uint8_t* address, uint16_t port, const picoquic_connection_id_t* cid);
picoqinq_header_compression_t* picoqinq_find_reserve_header_by_id(picoqinq_header_compression_t** phc_head, uint64_t hcid);

uint8_t* picoqinq_encode_reserve_cid(uint8_t* bytes, uint8_t* bytes_max, const picoquic_connection_id_t* cid);
uint8_t* picoqinq_decode_reserve_cid(uint8_t* bytes, uint8_t* bytes_max, picoquic_connection_id_t* cid);

#endif /* QINQ_PROTO_H */