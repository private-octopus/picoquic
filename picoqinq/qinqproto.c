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
#include "util.h"
#include "qinqproto.h"
#include "util.h"

uint8_t* picoquic_frames_fixed_skip(uint8_t* bytes, const uint8_t* bytes_max, size_t size);
uint8_t* picoquic_frames_varint_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64);
uint8_t* picoquic_frames_varlen_decode(uint8_t* bytes, const uint8_t* bytes_max, size_t* n);
uint8_t* picoquic_frames_uint8_decode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t* n);
uint8_t* picoquic_frames_uint16_decode(uint8_t* bytes, const uint8_t* bytes_max, uint16_t* n);
uint8_t* picoquic_frames_uint32_decode(uint8_t* bytes, const uint8_t* bytes_max, uint32_t* n);
uint8_t* picoquic_frames_uint64_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n);
uint8_t* picoquic_frames_cid_decode(uint8_t* bytes, const uint8_t* bytes_max, picoquic_connection_id_t* n);


/* In order to route incoming connection, the Qinq context contains a hash table
 * of connection ID, or rather of the first N bytes of the connection ID, with
 * N a confirmation parameter. Each table entry contains a chained list of the
 * "links" between a connection and a hash item (route), plus the actual value
 * of the CID reserved for the connection, which may be larger than the
 * minimum. The links are organized in two linked lists: one per route, for
 * all the CID that point to the route, and one per connection, with all
 * the CID reserved for that connection.
 *
 * The Qinq context also contains a double linked list of connections.
 * When a connection is deleted, all the links are deleted, and if there is
 * no more link for a selected route that route is deleted from the
 * hash table. */

static uint64_t picoqinq_rcid_hash(const void* key)
{
    const picoqinq_qinq_cid_prefix_route_t* cid = (const picoqinq_qinq_cid_prefix_route_t*)key;
    return picoquic_connection_id_hash(&cid->cid_prefix);
}

static int picoqinq_rcid_compare(const void* key1, const void* key2)
{
    const picoqinq_qinq_cid_prefix_route_t* cid1 = (const picoqinq_qinq_cid_prefix_route_t*)key1;
    const picoqinq_qinq_cid_prefix_route_t* cid2 = (const picoqinq_qinq_cid_prefix_route_t*)key2;

    return picoquic_compare_connection_id(&cid1->cid_prefix, &cid2->cid_prefix);
}

static void picoqinq_cid_cnx_link_delete(picoquic_cid_cnx_link_t* link)
{
    picoqinq_qinq_cid_prefix_route_t* route = link->cid_route;
    picoquic_cid_cnx_link_t** pprevious = &route->first_route;

    /* Remove the links in the route table */
    while (*pprevious != NULL) {
        if ((*pprevious) == link) {
            *pprevious = link->next_route;
            link->next_route = NULL;
            break;
        }
        else {
            pprevious = &(*pprevious)->next_route;
        }
    }

    /* Remove the links in the cnx context */
    pprevious = &link->cnx_ctx->first_cid;
    while (*pprevious != NULL) {
        if ((*pprevious) == link) {
            *pprevious = link->next_cid;
            link->next_cid = NULL;
            break;
        }
        else {
            pprevious = &(*pprevious)->next_cid;
        }
    }

    if (route->first_route == NULL) {
        /* No other CID shares the prefix. Remove the item from the hash table */
        picohash_item* item = picohash_retrieve(link->cnx_ctx->qinq->table_prefix_route, link->cid_route);
        if (item != NULL) {
            picohash_item_delete(link->cnx_ctx->qinq->table_prefix_route, item, 1);
        }
    }

    free(link);
}

int picoqinq_cid_cnx_link_create(picoqinq_cnx_ctx_t* cnx_ctx, picoquic_connection_id_t * cid)
{
    int ret = 0;

    picoquic_cid_cnx_link_t* link = (picoquic_cid_cnx_link_t*)malloc(sizeof(picoquic_cid_cnx_link_t));
    picoqinq_qinq_cid_prefix_route_t* key = (picoqinq_qinq_cid_prefix_route_t*)malloc(sizeof(picoqinq_qinq_cid_prefix_route_t));

    if (link == NULL || key == NULL) {
        ret = PICOQINQ_ERROR_INTERNAL;
    }
    else {
        picohash_item* item;
        memset(key, 0, sizeof(picoqinq_qinq_cid_prefix_route_t));
        picoquic_parse_connection_id(cid->id, cnx_ctx->qinq->min_prefix_length, &key->cid_prefix);

        item = picohash_retrieve(cnx_ctx->qinq->table_prefix_route, key);

        if (item == NULL) {
            ret = picohash_insert(cnx_ctx->qinq->table_prefix_route, key);
        }
        else {
            free(key);
            key = (picoqinq_qinq_cid_prefix_route_t*)item;
        }

        if (ret == 0) {
            picoquic_parse_connection_id(cid->id, cid->id_len, &link->cid);
            link->cid_route = key;
            link->cnx_ctx = cnx_ctx;
            link->next_cid = cnx_ctx->first_cid;
            cnx_ctx->first_cid = link;
            link->next_route = key->first_route;
            key->first_route = link;
            key = NULL;
            link = NULL;
        }
    }

    if (ret != 0) {
        if (key) {
            free(key);
        }
        if (link) {
            free(link);
        }
    }

    return(ret);
}

picoqinq_qinq_cid_prefix_route_t* picoqinq_find_route_by_cid(picoqinq_qinq_t* qinq, uint8_t* id)
{
    picoqinq_qinq_cid_prefix_route_t* route = NULL;
    picoqinq_qinq_cid_prefix_route_t key;
    picohash_item* item;
    memset(&key, 0, sizeof(picoqinq_qinq_cid_prefix_route_t));
    picoquic_parse_connection_id(id, qinq->min_prefix_length, &key.cid_prefix);

    item = picohash_retrieve(qinq->table_prefix_route, &key);

    if (item != NULL) {
        route = (picoqinq_qinq_cid_prefix_route_t *)item->key;
    }

    return route;
}

picoqinq_qinq_t* picoqinq_create(uint8_t min_prefix_length, size_t nb_cid)
{
    picoqinq_qinq_t* qinq = (picoqinq_qinq_t*)malloc(sizeof(picoqinq_qinq_t));

    if (qinq != NULL) {
        qinq->min_prefix_length = min_prefix_length;
        qinq->cnx_first = NULL;
        qinq->cnx_last = NULL;
        qinq->table_prefix_route = picohash_create((size_t)nb_cid * 4,
            picoqinq_rcid_hash, picoqinq_rcid_compare);

        if (qinq->table_prefix_route == NULL) {
            DBG_PRINTF("%s", "Cannot initialize hash tables\n");
            free(qinq);
            qinq = NULL;
        }
    }

    return qinq;
}

void picoqinq_delete(picoqinq_qinq_t* qinq)
{
    while (qinq->cnx_first != NULL) {
        picoqinq_delete_cnx_ctx(qinq->cnx_first);
    }

    picohash_delete(qinq->table_prefix_route, 1);
}

picoqinq_cnx_ctx_t* picoqinq_create_cnx_ctx(picoqinq_qinq_t* qinq)
{
    picoqinq_cnx_ctx_t* cnx_ctx = (picoqinq_cnx_ctx_t*)malloc(sizeof(picoqinq_cnx_ctx_t));
    
    if (cnx_ctx != NULL) {
        cnx_ctx->qinq = qinq;
        cnx_ctx->receive_hc = NULL;
        cnx_ctx->send_hc = NULL;
        cnx_ctx->first_cid = NULL;
        if (qinq->cnx_last == NULL) {
            qinq->cnx_last = cnx_ctx;
        }
        cnx_ctx->ctx_previous = NULL;
        cnx_ctx->ctx_next = qinq->cnx_first;
        qinq->cnx_first = cnx_ctx;
    }

    return cnx_ctx;
}

static void picoqinq_delete_cnx_ctx_hc(picoqinq_header_compression_t** phc)
{
    picoqinq_header_compression_t* hc;

    while((hc = *phc) != NULL) {
        *phc = hc->next_hc;
        free(hc);
    }
}

void picoqinq_delete_cnx_ctx(picoqinq_cnx_ctx_t* ctx)
{
    picoqinq_delete_cnx_ctx_hc(&ctx->receive_hc);
    picoqinq_delete_cnx_ctx_hc(&ctx->send_hc);

    while (ctx->first_cid) {
        picoqinq_cid_cnx_link_delete(ctx->first_cid);
    }

    if (ctx->ctx_previous == NULL) {
        ctx->qinq->cnx_first = ctx->ctx_next;
    }
    else {
        ctx->ctx_previous->ctx_next = ctx->ctx_next;
    }
    ctx->ctx_previous = NULL;

    if (ctx->ctx_next == NULL) {
        ctx->qinq->cnx_last = ctx->ctx_previous;
    }
    else {
        ctx->ctx_next->ctx_previous = ctx->ctx_previous;
    }
    ctx->ctx_next = NULL;

    free(ctx);
}

/* The datagram frames start with:
 *  - if using h3, varint describing the QINQ stream. Omitted in QINQ native, because there is only one stream.
 *       This will be already decoded by the HTTP specific code before calling the parser
 *  - Header compression index, varint.
 *       integer value N if this is a place holder for the IP address and the CID
 * The structure of the datagram would thus be:
 *    <0><length of address><address><16 bit port number><first byte><reminder of packet including DCID>
 *    <N(1rTT)><reminder of 1-RTT packet with DCID bytes removed>
 * Compression of Initial or handshake packet is for further study.
 */

uint8_t * picoqinq_decode_datagram_header(picoqinq_cnx_ctx_t* ctx, uint8_t * bytes, uint8_t * bytes_max, size_t* address_length, const uint8_t** address, uint16_t* port,
    picoquic_connection_id_t** cid)
{
    uint64_t hcid;

    *address_length = 0;
    *address = NULL;
    *port = 0;
    *cid = NULL;

    bytes = picoquic_frames_varint_decode(bytes, bytes_max, &hcid);
    if (bytes == 0) {
        if (hcid == 0) {
            if ((bytes = picoquic_frames_varlen_decode(bytes, bytes_max, address_length)) != NULL) {
                *address = bytes;
                if ((bytes = picoquic_frames_fixed_skip(bytes, bytes_max, *address_length)) != NULL) {
                    bytes = picoquic_frames_uint16_decode(bytes, bytes_max, port);
                }
            }
        }
        else {
            picoqinq_header_compression_t* hc = picoqinq_find_reserve_header_by_id(&ctx->receive_hc, hcid);

            if (hc == NULL) {
                bytes = NULL;
            }
            else {
                *address_length = hc->address_length;
                *address = hc->address;
                *cid = &hc->cid;
            }
        }
    }

    return bytes;
}

/* To reserve a header, the node send a reserve header message on a new bidir
 * stream (either client or server depending of direction). The message has the
 * format: 
 *     - Op code "reserve header" -- varint.
 *     - Direction: 0 to server, 1 to client,
 *     - address length -- varint
 *     - N bytes of address
 *     - 16 bits port number
 *     - cid length -- varint
 *     - cid content bytes
 * The other node replies with a message composed of a single varint:
 *     - header compression code -- varint
 * A reply of max int (0x3FFFFFFFFFFFFFFF) indicates that no code is available.
 * Other replies indicate that the compression code can now be used.
 */

uint8_t* picoqinq_encode_reserve_header(uint8_t* bytes, uint8_t* bytes_max,
    uint64_t direction, uint64_t hcid,
    size_t address_length, const uint8_t* address, uint16_t port, const picoquic_connection_id_t* cid)
{
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, QINQ_PROTO_RESERVE_HEADER)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, direction)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, hcid)) != NULL &&
        (bytes = picoquic_frames_l_v_encode(bytes, bytes_max, address_length, address)) != NULL &&
        (bytes = picoquic_frames_uint16_encode(bytes, bytes_max, port)) != NULL) {
        bytes = picoquic_frames_cid_encode(bytes, bytes_max, cid);
    }
    return bytes;
}

/* Assume that the operation code is already parsed */
uint8_t* picoqinq_decode_reserve_header(uint8_t* bytes, uint8_t* bytes_max,
    uint64_t* direction, uint64_t* hcid,
    size_t* address_length, const uint8_t** address, uint16_t* port, picoquic_connection_id_t* cid)
{
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, direction)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, hcid)) != NULL &&
        (bytes = picoquic_frames_varlen_decode(bytes, bytes_max, address_length)) != NULL) {
        *address = bytes;
        if ((bytes = picoquic_frames_fixed_skip(bytes, bytes_max, *address_length)) != NULL &&
            (bytes = picoquic_frames_uint16_decode(bytes, bytes_max, port)) != NULL) {
            bytes = picoquic_frames_cid_decode(bytes, bytes_max, cid);
        }
    }

    return bytes;
}

picoqinq_header_compression_t* picoqinq_create_header(uint64_t hcid,
    size_t address_length, const uint8_t* address, uint16_t port, const picoquic_connection_id_t* cid)
{
    picoqinq_header_compression_t* hc = (picoqinq_header_compression_t*)malloc(sizeof(picoqinq_header_compression_t));
    if (hc != NULL) {
        hc->next_hc = NULL;
        hc->hcid = hcid;
        hc->address_length = address_length;
        memcpy(hc->address, address, address_length);
        hc->port = port;
        memcpy(hc->cid.id, cid->id, cid->id_len);
        hc->cid.id_len = cid->id_len;
    }
    return hc;
}

void picoqinq_reserve_header(picoqinq_header_compression_t* hc, picoqinq_header_compression_t** phc_head)
{
    if (hc != NULL && phc_head != NULL) {
        picoqinq_header_compression_t** phc_next = &hc->next_hc;
        hc->next_hc = *phc_head;
        *phc_head = hc;

        while (*phc_next) {          
            if ((*phc_next)->hcid == hc->hcid) {
                picoqinq_header_compression_t* to_delete = *phc_next;
                *phc_next = to_delete->next_hc;
                free(to_delete);
            }
            else {
                phc_next = &(*phc_next)->next_hc;
            }
        }
    }
}

uint64_t picoqinq_find_reserve_header_id_by_address(picoqinq_header_compression_t** phc_head, size_t address_length, const uint8_t* address, uint16_t port, const picoquic_connection_id_t* cid)
{
    uint64_t hcid = 0;
    picoqinq_header_compression_t** pnext = phc_head;
    picoqinq_header_compression_t* next;

    while ((next = *pnext) != NULL) {
        if (next->address_length == address_length &&
            next->port == port &&
            next->cid.id_len == cid->id_len &&
            memcmp(next->address, address, address_length) == 0 &&
            memcmp(next->cid.id, cid->id, cid->id_len) == 0) {
            hcid = next->hcid;

            if (next != *phc_head) {
                /* Bring LRU on top of list */
                *pnext = next->next_hc;
                next->next_hc = *phc_head;
                *phc_head = next;
            }
            break;
        }
        else {
            pnext = &next->next_hc;
        }
    }
    return hcid;
}

picoqinq_header_compression_t* picoqinq_find_reserve_header_by_id(picoqinq_header_compression_t** phc_head, uint64_t hcid)
{
    picoqinq_header_compression_t** pnext = phc_head;
    picoqinq_header_compression_t* next;

    while ((next = *pnext) != NULL) {
        if (next->hcid == hcid) {
            if (next != *phc_head) {
                /* Bring LRU on top of list */
                *pnext = next->next_hc;
                next->next_hc = *phc_head;
                *phc_head = next;
            }
            break;
        }
        else {
            pnext = &next->next_hc;
        }
    }
    return next;
}

/* To reserve a CID to handle incoming packets, the client sends a CID reservation
 * message on a new bidir client stream. The message has the format:
 *     - Op code "reserve header" -- varint.
 *     - cid length -- varint
 *     - cid content bytes 
 * There is no reply necessary -- the server just closes the stream.  
 * There is no synchronization requirement -- this is best effort.
 *
 * The CID is pushed when it is created.
 * We may consider dropping when it is retired.
 *
 * The hash table managed by the server lists the first N bytes of the CID.
 * This delivers a list of matching connection. A secondary filter per
 * connection checks the match for the full CID. 
 */

uint8_t* picoqinq_encode_reserve_cid(uint8_t* bytes, uint8_t* bytes_max, const picoquic_connection_id_t* cid)
{
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, QINQ_PROTO_RESERVE_CID)) != NULL) {
        bytes = picoquic_frames_cid_encode(bytes, bytes_max, cid);
    }
    return bytes;
}

uint8_t* picoqinq_decode_reserve_cid(uint8_t* bytes, uint8_t* bytes_max, picoquic_connection_id_t* cid)
{
    return picoquic_frames_cid_decode(bytes, bytes_max, cid);
}