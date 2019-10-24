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
#include "bytestream.h"
#include "qinqproto.h"

picoqinq_cnx_ctx_t* picoqinq_create_ctx()
{
    return NULL;
}

void picoqinq_delete_ctx(picoqinq_cnx_ctx_t* ctx)
{
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

int picoqinq_parse_datagram_header(picoqinq_cnx_ctx_t* ctx, bytestream* stream, size_t* address_length, const uint8_t** address, uint16_t* port,
    picoquic_connection_id_t** cid)
{
    uint64_t hcid;
    int ret = 0;

    *address_length = 0;
    *address = NULL;
    *port = 0;
    *cid = NULL;

    ret = byteread_vint(stream, &hcid);
    if (ret == 0) {
        if (hcid == 0) {
            if ((ret = byteread_vint(stream, address_length)) == 0) {
                *address = bytestream_ptr(stream);
                if ((ret = bytestream_skip(stream, *address_length)) == 0) {
                    ret = byteread_int16(stream, port);
                }
            }
        }
        else {
            picoqinq_header_compression_t* hc = picoqinq_find_reserve_header_by_id(&ctx->receive_hc, hcid);

            if (hc == NULL) {
                ret = -1;
            }
            else {
                *address_length = hc->address_length;
                *address = hc->address;
                *cid = &hc->cid;
            }
        }
    }

    return ret;
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

int picoqinq_prepare_reserve_header(bytestream * stream,
    uint64_t direction, uint64_t hcid,
    size_t address_length, const uint8_t* address, uint16_t port, const picoquic_connection_id_t* cid)
{
    int ret;

    if ((ret = bytewrite_vint(stream, QINQ_PROTO_RESERVE_HEADER)) == 0 &&
        (ret = bytewrite_vint(stream, direction)) == 0 &&
        (ret = bytewrite_vint(stream, hcid)) == 0 &&
        (ret = bytewrite_vint(stream, address_length)) == 0 &&
        (ret = bytewrite_buffer(stream, address, address_length)) == 0 &&
        (ret = bytewrite_int16(stream, port)) == 0) {
        ret = bytewrite_cid(stream, cid);
    }
    return ret;
}

/* Assume that the operation code is already parsed */
int picoqinq_parse_reserve_header(bytestream* stream,
    uint64_t* direction, uint64_t* hcid,
    size_t* address_length, const uint8_t** address, uint16_t* port, picoquic_connection_id_t* cid)
{
    int ret;

    if ((ret = byteread_vint(stream, direction)) == 0 &&
        (ret = byteread_vint(stream, hcid)) == 0 &&
        (ret = byteread_vint(stream, address_length)) == 0) {
        *address = bytestream_ptr(stream);
        if ((ret = bytestream_skip(stream, *address_length)) == 0 &&
            (ret = byteread_int16(stream, port)) == 0) {
            ret = byteread_cid(stream, cid);
        }
    }

    return ret;
}

/* Confirm once approved */
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

int picoqinq_prepare_reserve_cid(bytestream* stream, const picoquic_connection_id_t* cid)
{
    int ret;

    if ((ret = bytewrite_vint(stream, QINQ_PROTO_RESERVE_HEADER)) == 0) {
        ret = bytewrite_cid(stream, cid);
    }
    return ret;
}

int picoqinq_parse_reserve_cid(bytestream* stream, picoquic_connection_id_t* cid)
{
    return byteread_cid(stream, cid);
}

uint8_t* picoqinq_register_cid(picoqinq_cnx_ctx_t* ctx, picoquic_connection_id_t* cid)
{
    /* add to the hash table. */
    /* add to the local table. */
    return -1;
}