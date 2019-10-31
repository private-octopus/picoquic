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
#include "picoquic.h"

#define QINQ_PROTO_RESERVE_HEADER 1
#define QINQ_PROTO_RESERVE_CID 2

#define PICOQINQ_ERROR_NO_ERROR 0x500
#define PICOQINQ_ERROR_INTERNAL 0x501
#define PICOQINQ_ERROR_PROTOCOL 0x502
#define PICOQINQ_ERROR_CID_TOO_SHORT 0x503
#define PICOQINQ_ERROR_INVALID_PACKET 0x504

#define PICOQINQ_RESERVATION_DELAY 1000000

#define PICOQINQ_MINIMUM_CID_LENGTH 4

typedef struct st_picoqinq_header_compression_t {
    struct st_picoqinq_header_compression_t* next_hc;
    uint64_t hcid;
    struct sockaddr_storage addr_s;
    picoquic_connection_id_t cid;
    uint64_t last_access_time;
} picoqinq_header_compression_t;

typedef struct st_picoqinq_packet_t {
    struct st_picoqinq_packet_t* next_packet;
    picoquic_connection_id_t dcid;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    unsigned char received_ecn;
    size_t packet_length;
    uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
} picoqinq_packet_t;

int qinq_copy_address(struct sockaddr_storage* addr_s, size_t address_length, const uint8_t* address, uint16_t port);

uint8_t* picoqinq_decode_datagram_header(uint8_t* bytes, uint8_t* bytes_max, struct sockaddr_storage * addr_s,
    picoquic_connection_id_t** cid, picoqinq_header_compression_t** p_receive_hc, uint64_t current_time);
int picoqinq_datagram_to_packet(uint8_t* bytes, uint8_t* bytes_max, struct sockaddr_storage* addr_s,
    picoquic_connection_id_t** cid, uint8_t* packet_data, size_t packet_data_max, size_t* packet_length,
    picoqinq_header_compression_t** p_receive_hc, uint64_t current_time);

uint8_t* picoqinq_encode_reserve_header(uint8_t* bytes, uint8_t* bytes_max,
    uint64_t direction, uint64_t hcid, const struct sockaddr* addr, const picoquic_connection_id_t* cid);
uint8_t* picoqinq_decode_reserve_header(uint8_t* bytes, uint8_t* bytes_max,
    uint64_t* direction, uint64_t* hcid, struct sockaddr_storage* addr_s, picoquic_connection_id_t* cid);
picoqinq_header_compression_t* picoqinq_create_header(uint64_t hcid, struct sockaddr* addr, const picoquic_connection_id_t* cid, uint64_t current_time);
void picoqinq_reserve_header(picoqinq_header_compression_t* hc, picoqinq_header_compression_t** phc_head);
picoqinq_header_compression_t* picoqinq_find_reserve_header_by_address(picoqinq_header_compression_t** phc_head, struct sockaddr* addr, const picoquic_connection_id_t* cid, uint64_t current_time);
uint64_t picoqinq_find_reserve_header_id_by_address(picoqinq_header_compression_t** phc_head, struct sockaddr* addr, const picoquic_connection_id_t* cid, uint64_t current_time);
picoqinq_header_compression_t* picoqinq_find_reserve_header_by_id(picoqinq_header_compression_t** phc_head, uint64_t hcid, uint64_t current_time);

uint8_t* picoqinq_encode_reserve_cid(uint8_t* bytes, uint8_t* bytes_max, const picoquic_connection_id_t* cid);
uint8_t* picoqinq_decode_reserve_cid(uint8_t* bytes, uint8_t* bytes_max, picoquic_connection_id_t* cid);

#endif /* QINQ_PROTO_H */