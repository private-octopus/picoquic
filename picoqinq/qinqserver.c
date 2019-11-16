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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "util.h"
#include "picohash.h"
#include "picoquic.h"
#include "qinqproto.h"
#include "qinqserver.h"


uint8_t* picoquic_frames_fixed_skip(uint8_t* bytes, const uint8_t* bytes_max, size_t size);
uint8_t* picoquic_frames_varint_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64);
uint8_t* picoquic_frames_varlen_decode(uint8_t* bytes, const uint8_t* bytes_max, size_t* n);
uint8_t* picoquic_frames_uint8_decode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t* n);
uint8_t* picoquic_frames_uint16_decode(uint8_t* bytes, const uint8_t* bytes_max, uint16_t* n);
uint8_t* picoquic_frames_uint32_decode(uint8_t* bytes, const uint8_t* bytes_max, uint32_t* n);
uint8_t* picoquic_frames_uint64_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n);
uint8_t* picoquic_frames_cid_decode(uint8_t* bytes, const uint8_t* bytes_max, picoquic_connection_id_t* n);

/* In order to manage an incoming connection, we manage a list of outgoing packets and their
 * ties to local proxy contexts. This is  a table of:
 *   <address>, <proxy-client-connection>, <time>
 * When a packet comes out, the address record is created or refreshed. 
 * When a packet comes in, the candidate connections are examined and tested further,
 * for example to find a CID match. */


static uint64_t picoqinq_address_record_hash(const void* key)
{
    const picoqinq_peer_address_record_t* ar = (const picoqinq_peer_address_record_t*)key;
    return picoquic_hash_addr((struct sockaddr*) & ar->peer_addr);
}

static int picoqinq_address_record_compare(const void* key1, const void* key2)
{
    const picoqinq_peer_address_record_t* ar1 = (const picoqinq_peer_address_record_t*)key1;
    const picoqinq_peer_address_record_t* ar2 = (const picoqinq_peer_address_record_t*)key2;

    return picoquic_compare_addr((struct sockaddr *)&ar1->peer_addr, (struct sockaddr*) &ar2->peer_addr);
}

void picoqinq_cnx_address_link_delete(picoqinq_cnx_address_link_t* link)
{
    picoqinq_peer_address_record_t* ar = link->address_record;
    picoqinq_cnx_address_link_t** pprevious = &ar->first_cnx_by_address;

    /* Remove the links in the address record table */
    while (*pprevious != NULL) {
        if ((*pprevious) == link) {
            *pprevious = link->next_cnx_by_address;
            link->next_cnx_by_address = NULL;
            break;
        }
        else {
            pprevious = &(*pprevious)->next_cnx_by_address;
        }
    }

    /* Remove the links in the cnx context */
    pprevious = &link->cnx_ctx->first_address_by_cnx;
    while (*pprevious != NULL) {
        if ((*pprevious) == link) {
            *pprevious = link->next_address_by_cnx;
            link->next_address_by_cnx = NULL;
            break;
        }
        else {
            pprevious = &(*pprevious)->next_address_by_cnx;
        }
    }

    if (ar->first_cnx_by_address == NULL) {
        /* No other connection shares this address. Remove the item from the hash table */
        picohash_item* item = picohash_retrieve(link->cnx_ctx->qinq->table_peer_addresses, ar);
        if (item != NULL) {
            picohash_item_delete(link->cnx_ctx->qinq->table_peer_addresses, item, 1);
        }
    }

    free(link);
}

int picoqinq_cnx_address_link_create_or_touch(picoqinq_srv_cnx_ctx_t* cnx_ctx, const struct sockaddr* addr, uint64_t current_time)
{
    int ret = 0;

    picoqinq_peer_address_record_t s_key;
    picoqinq_peer_address_record_t* key = NULL;
    picoqinq_cnx_address_link_t* link = NULL;
    picohash_item* item;
    memset(&s_key, 0, sizeof(picoqinq_peer_address_record_t));
    picoquic_store_addr(&s_key.peer_addr, addr);

    item = picohash_retrieve(cnx_ctx->qinq->table_peer_addresses, &s_key);

    if (item == NULL) {
        key = (picoqinq_peer_address_record_t*)malloc(sizeof(picoqinq_peer_address_record_t));

        if (key == NULL) {
            ret = PICOQINQ_ERROR_INTERNAL;
        }
        else {
            memset(key, 0, sizeof(picoqinq_peer_address_record_t));
            picoquic_store_addr(&key->peer_addr, addr);
            ret = picohash_insert(cnx_ctx->qinq->table_peer_addresses, key);

            if (ret != 0) {
                free(key);
            }
        }
    }
    else {
        key = (picoqinq_peer_address_record_t*)item->key;

        /* Find whether there is a link associated with the current connection. */
        link = key->first_cnx_by_address;

        while (link != NULL && link->cnx_ctx != cnx_ctx) {
            link = link->next_cnx_by_address;
        }
    }

    if (ret == 0) {
        if (link == NULL) {
            link = (picoqinq_cnx_address_link_t*)malloc(sizeof(picoqinq_cnx_address_link_t));
            if (link == NULL) {
                ret = PICOQINQ_ERROR_INTERNAL;
            }
            else {
                link->last_access_time = current_time;
                link->address_record = key;
                link->cnx_ctx = cnx_ctx;
                link->next_address_by_cnx = cnx_ctx->first_address_by_cnx;
                cnx_ctx->first_address_by_cnx = link;
                link->next_cnx_by_address = key->first_cnx_by_address;
                key->first_cnx_by_address = link;
            }
        }
        else {
            link->last_access_time = current_time;
        }
    }

    return(ret);
}

picoqinq_peer_address_record_t* picoqinq_find_address_record(picoqinq_srv_ctx_t* qinq, const struct sockaddr * addr)
{
    picoqinq_peer_address_record_t* ar = NULL;
    picoqinq_peer_address_record_t key;
    picohash_item* item;
    memset(&key, 0, sizeof(picoqinq_peer_address_record_t));
    picoquic_store_addr(&key.peer_addr, addr);

    item = picohash_retrieve(qinq->table_peer_addresses, &key);

    if (item != NULL) {
        ar = (picoqinq_peer_address_record_t*)item->key;
    }

    return ar;
}

/* Forward incoming packet as datagram on proxy connection */

int picoquic_incoming_proxy_packet(
    picoqinq_srv_cnx_ctx_t* cnx_ctx,
    uint8_t* packet_data,
    size_t packet_length,
    picoquic_connection_id_t* dcid,
    struct sockaddr* addr_from,
    uint64_t current_time)
{
    /* Submit packet as datagram on specified connection */
    int ret = 0;
    uint8_t dg[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t* next_dg_byte = picoqinq_packet_to_datagram(dg, dg + PICOQUIC_MAX_PACKET_SIZE, addr_from, dcid, packet_data, packet_length, &cnx_ctx->send_hc, current_time);

    if (next_dg_byte == NULL) {
        ret = -1;
    }
    else {
        ret = picoquic_queue_datagram_frame(cnx_ctx->cnx, 0, next_dg_byte - dg, dg);
    }
    
    return ret;
}

/* Check whether a proxy connection is the best match for an incoming packet.
 *
 * The Good match argument states whether the incoming CID matches a value registered by the proxy.
 * The Last Update argument provides the last time at which the connection was updated.
 */

int picoqinq_test_proxy_for_incoming(
    picoqinq_srv_cnx_ctx_t* cnx_ctx,
    uint8_t* bytes,
    size_t packet_length,
    picoquic_connection_id_t* dcid,
    struct sockaddr* addr_from)
{
    int ret = 0;
    picoqinq_header_compression_t* next = cnx_ctx->send_hc;

    while (next != NULL) {
        if (picoquic_compare_addr((struct sockaddr*) & next->addr_s, addr_from) == 0) {
            /* Assume DCID only NULL if the incoming is a short packet */
            if (dcid != NULL) {
                ret = (picoquic_compare_connection_id(dcid, &next->cid) == 0);
                break;
            }
            else if (packet_length > (size_t)next->cid.id_len + 1) {
                ret = (memcmp(bytes + 1, next->cid.id, next->cid.id_len) == 0);
                break;
            }
        }
        next = next->next_hc;
    }

    return ret;
}

/* Find the best proxy connection for an incoming packet 
 */

picoqinq_srv_cnx_ctx_t* picoqinq_find_best_proxy_for_incoming(
    picoqinq_srv_ctx_t* qinq,
    const picoquic_connection_id_t* dcid,
    const struct sockaddr* addr_from,
    uint64_t current_time)
{
    picoqinq_srv_cnx_ctx_t * cnx_ctx = NULL;
    picoqinq_peer_address_record_t* ar = picoqinq_find_address_record(qinq, addr_from);

    if (ar != NULL) {
        picoqinq_cnx_address_link_t* link = ar->first_cnx_by_address;
        picoqinq_srv_cnx_ctx_t* best_match_cnx = NULL;
        picoqinq_srv_cnx_ctx_t* most_recent_cnx = NULL;
        uint64_t match_time = 0;

        while (link != NULL) {
            if (link->last_access_time + PICOQINQ_ADDRESS_USE_TIME_DEFAULT >= current_time) {
                /* Packet may be bound to this proxied connections, pending address check */
                if (picoqinq_find_reserve_header_by_address(&link->cnx_ctx->send_hc, addr_from, dcid, 0) != NULL) {
                    if (best_match_cnx == NULL || link->last_access_time > match_time) {
                        best_match_cnx = link->cnx_ctx;
                        match_time = link->last_access_time;
                    }
                }
                else if (best_match_cnx == NULL && (most_recent_cnx == NULL || link->last_access_time > match_time)) {
                    most_recent_cnx = link->cnx_ctx;
                    match_time = link->last_access_time;
                }
            }
            else {
                /* TODO: Links that are too old should be removed */
            }
            link = link->next_cnx_by_address;
        }

        if (best_match_cnx != NULL) {
            cnx_ctx = best_match_cnx;
        }
        else {
            cnx_ctx = most_recent_cnx;
        }
    }

    return cnx_ctx;
}

/*
 * Manage an incoming packet.
 *
 * Identify the client context by connection ID.
 *  - First check whether this could be a local packet. If yes, pass to local quic context.
 *  - If no, check whether this is a plausible proxy packet.
 *        - If yes, forward as datagram to each candidate connection.
 *        - If no, pass to local quic context.
 * TODO: once we proxy incoming connection, more complex logic.
 */

int picoqinq_server_incoming_packet(
    picoqinq_srv_ctx_t* qinq,
    uint8_t* bytes,
    size_t packet_length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time)
{
    picoquic_connection_id_t dcid;
    picoquic_connection_id_t* p_cid = NULL;
    int ret = 0;

    if (packet_length < 17) {
        /* packet too short */
        ret = -1;
    }
    else if ((bytes[0] & 64) != 64) {
        /* Not a QUIC packet */
        ret = -1;
    }
    else
    {
        if ((bytes[0] & 0x80) == 0x80) {
            /* This is a long packet header. According to the invariant specification,
             * the initial byte is followed by a 4 bytes version field,
             * followed by DCI length and DCID value. */

            if (picoquic_parse_connection_id(bytes + 6, bytes[5], &dcid) == 0) {
                /* Unexpected. Cannot do anything with that packet */
                ret = -1;
            }
            else {
                p_cid = &dcid;
            }
        }
    }

    if (ret == 0) {
        if (p_cid != NULL && picoquic_is_local_cid(qinq->quic, p_cid)) {
            /* Local packet. Forward to local quic context */
            ret = picoquic_incoming_packet(qinq->quic, bytes, packet_length, addr_from, addr_to, if_index_to, received_ecn, current_time);
        }
        else {
            picoqinq_srv_cnx_ctx_t* cnx_ctx = picoqinq_find_best_proxy_for_incoming(qinq, p_cid, addr_from, current_time);

            if (cnx_ctx != NULL) {
                ret = picoquic_incoming_proxy_packet(cnx_ctx, bytes, packet_length, p_cid, addr_from, current_time);
            }
            else {
                /* TODO: if this is an initial packet, it may be bound to the local SNI/ALPN,
                 * or to a proxied server. But we do not support proxied servers yet, so
                 * we just pass everything to the local server. */
                ret = picoquic_incoming_packet(qinq->quic, bytes, packet_length, addr_from, addr_to, if_index_to, received_ecn, current_time);
            }
        }
    }

    return ret;
}

picoqinq_srv_ctx_t* picoqinq_create_srv_ctx(picoquic_quic_t* quic, uint8_t min_prefix_length, size_t nb_connections)
{
    picoqinq_srv_ctx_t* qinq = (picoqinq_srv_ctx_t*)malloc(sizeof(picoqinq_srv_ctx_t));

    if (qinq != NULL) {
        qinq->quic = quic;
        qinq->min_prefix_length = min_prefix_length;
        qinq->cnx_first = NULL;
        qinq->cnx_last = NULL;
        qinq->table_peer_addresses = picohash_create((size_t)nb_connections * 4,
            picoqinq_address_record_hash, picoqinq_address_record_compare);

        if (qinq->table_peer_addresses == NULL) {
            DBG_PRINTF("%s", "Cannot initialize hash tables\n");
            free(qinq);
            qinq = NULL;
        }
    }

    return qinq;
}

void picoqinq_delete_srv_ctx(picoqinq_srv_ctx_t* qinq)
{
    while (qinq->cnx_first != NULL) {
        picoqinq_delete_srv_cnx_ctx(qinq->cnx_first);
    }

    picohash_delete(qinq->table_peer_addresses, 1);
}

picoqinq_srv_cnx_ctx_t* picoqinq_create_srv_cnx_ctx(picoqinq_srv_ctx_t* qinq, picoquic_cnx_t* cnx)
{
    picoqinq_srv_cnx_ctx_t* cnx_ctx = (picoqinq_srv_cnx_ctx_t*)malloc(sizeof(picoqinq_srv_cnx_ctx_t));

    if (cnx_ctx != NULL) {
        memset(cnx_ctx, 0, sizeof(picoqinq_srv_cnx_ctx_t));
        cnx_ctx->first_stream = NULL;
        cnx_ctx->cnx = cnx;
        cnx_ctx->qinq = qinq;
        cnx_ctx->receive_hc = NULL;
        cnx_ctx->send_hc = NULL;
        cnx_ctx->first_address_by_cnx = NULL;
        cnx_ctx->ctx_previous = NULL;
        if (qinq->cnx_first == NULL) {
            qinq->cnx_last = cnx_ctx;
        }
        else {
            qinq->cnx_first->ctx_previous = cnx_ctx;
        }
        cnx_ctx->ctx_next = qinq->cnx_first;
        qinq->cnx_first = cnx_ctx;
    }

    return cnx_ctx;
}

static void picoqinq_delete_srv_cnx_ctx_hc(picoqinq_header_compression_t** phc)
{
    picoqinq_header_compression_t* hc;

    while ((hc = *phc) != NULL) {
        *phc = hc->next_hc;
        free(hc);
    }
}

void picoqinq_delete_srv_cnx_ctx(picoqinq_srv_cnx_ctx_t* ctx)
{
    if (ctx != NULL) {
        picoqinq_server_stream_ctx_t* stream_ctx;

        /* Delete the streams contexts */
        while ((stream_ctx = ctx->first_stream) != NULL) {
            ctx->first_stream = stream_ctx->next_stream;
            free(stream_ctx);
        }
        
        /* Delete the hcid contexts */
        picoqinq_delete_srv_cnx_ctx_hc(&ctx->receive_hc);
        picoqinq_delete_srv_cnx_ctx_hc(&ctx->send_hc);

        /* Remove the address links*/
        while (ctx->first_address_by_cnx) {
            picoqinq_cnx_address_link_delete(ctx->first_address_by_cnx);
        }

        /* Unlink the connection from the server context */
        if (ctx->ctx_previous == NULL) {
            ctx->qinq->cnx_first = ctx->ctx_next;
        }
        else {
            ctx->ctx_previous->ctx_next = ctx->ctx_next;
        }

        if (ctx->ctx_next == NULL) {
            ctx->qinq->cnx_last = ctx->ctx_previous;
        }
        else {
            ctx->ctx_next->ctx_previous = ctx->ctx_previous;
        }
        ctx->ctx_next = NULL;
        ctx->ctx_previous = NULL;

        free(ctx);
    }
}

/*
 * Datagram call back, process Quic datagrams received from a qinq client.
 */
int picoqinq_server_callback_datagram(picoqinq_srv_cnx_ctx_t* cnx_ctx, uint8_t* bytes, size_t length, uint64_t current_time)
{

    /* TODO: perform address verifications: we should implement some firewall logic to test
     * whether there were replies from that address already. If they were not, we should
     * at a minimum perform some rate limiting, to prevent abuses. */
    /* Possibly, verify that this is a valid CNX-ID, but consider possible migrations. */
    /* Send the datagram on the selected socket for the context. */
    int ret = 0;
    picoquic_stateless_packet_t* outpack = picoquic_create_stateless_packet(cnx_ctx->qinq->quic);
    picoquic_connection_id_t* cid;

    if (outpack != NULL) {
        /* TODO: Parse the datagram header to extract the address_to */
        ret = picoqinq_datagram_to_packet(bytes, bytes + length, &outpack->addr_to, &cid,
            outpack->bytes, sizeof(outpack->bytes), &outpack->length, &cnx_ctx->receive_hc, current_time);

        if (ret != 0) {
            picoquic_delete_stateless_packet(outpack);
        }
        else {
            picoquic_queue_stateless_packet(cnx_ctx->qinq->quic, outpack);

            /* Keep track of address so responses can be matched to connection */
            ret = picoqinq_cnx_address_link_create_or_touch(cnx_ctx, (struct sockaddr*) & outpack->addr_to, current_time);
        }
    }
    else {
        ret = PICOQUIC_ERROR_MEMORY;
    }

    return ret;
}

/* Per stream context.
 *
 * QINQ uses streams to send protocol elements such as registration of connection IDs.
 * The "end of stream" marks the end of a protocol element. When it is received, the
 * protocol machine is called, and the response is posted on the stream.
 */

picoqinq_server_stream_ctx_t* picoqinq_find_or_create_server_stream(picoquic_cnx_t* cnx, uint64_t stream_id, picoqinq_srv_cnx_ctx_t* ctx, int should_create)
{
    picoqinq_server_stream_ctx_t* stream_ctx = NULL;

    /* if stream is already present, check its state. New bytes? */
    stream_ctx = ctx->first_stream;
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL && should_create) {
        stream_ctx = (picoqinq_server_stream_ctx_t*)
            malloc(sizeof(picoqinq_server_stream_ctx_t));
        if (stream_ctx == NULL) {
            /* Could not handle this stream */
            picoquic_reset_stream(cnx, stream_id, PICOQINQ_ERROR_INTERNAL);
        }
        else {
            memset(stream_ctx, 0, sizeof(picoqinq_server_stream_ctx_t));
            stream_ctx->next_stream = ctx->first_stream;
            ctx->first_stream = stream_ctx;
            stream_ctx->stream_id = stream_id;
        }
    }

    return stream_ctx;
}

void picoqinq_forget_server_stream(picoqinq_srv_cnx_ctx_t* ctx, picoqinq_server_stream_ctx_t* stream_ctx)
{
    if (ctx != NULL && stream_ctx != NULL) {
        picoqinq_server_stream_ctx_t** previous_link = &ctx->first_stream;
        while (*previous_link != NULL && *previous_link != stream_ctx) {
            *previous_link = (*previous_link)->next_stream;
        }
        if (*previous_link == stream_ctx) {
            *previous_link = stream_ctx->next_stream;
        }
        free(stream_ctx);
    }
}

int picoqinq_server_protocol_input(picoqinq_srv_cnx_ctx_t * cnx_ctx, uint8_t * frame, size_t frame_length, uint64_t current_time) {
    uint8_t* bytes = frame;
    uint8_t* bytes_max = frame + frame_length;
    uint64_t proto_code = 0;
    int ret = 0;

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &proto_code)) != NULL)
    {
        if (proto_code != QINQ_PROTO_RESERVE_HEADER) {
            ret = PICOQINQ_ERROR_PROTOCOL;
        }
        else {
            uint64_t hcid = 0;
            uint64_t direction = 0;
            struct sockaddr_storage addr_s;
            picoquic_connection_id_t cid;

            if ((bytes = picoqinq_decode_reserve_header(bytes, bytes_max, &direction, &hcid, &addr_s, &cid)) != 0){
                picoqinq_header_compression_t* hc = picoqinq_create_header(hcid, (struct sockaddr*) &addr_s, &cid, current_time);
                if (hc == NULL) {
                    ret = PICOQINQ_ERROR_INTERNAL;
                }
                else {
                    picoqinq_reserve_header(hc, (direction == PICOQINQ_DIRECTION_SERVER_TO_CLIENT)?&cnx_ctx->send_hc:&cnx_ctx->receive_hc);
                }
            }
        }
    }

    if (ret == 0 && bytes == NULL) {
        ret = PICOQINQ_ERROR_PROTOCOL;
    }

    return ret;
}

int picoqinq_server_callback_data(picoquic_cnx_t* cnx, picoqinq_server_stream_ctx_t* stream_ctx, uint64_t stream_id, uint8_t* bytes, 
    size_t length, picoquic_call_back_event_t fin_or_event, picoqinq_srv_cnx_ctx_t* callback_ctx, uint64_t current_time)
{
    int ret = 0;

    if (stream_ctx == NULL) {
        stream_ctx = picoqinq_find_or_create_server_stream(cnx, stream_id, callback_ctx, 1);
    }

    if (stream_ctx == NULL) {
        /* not enough resource */
        ret = picoquic_stop_sending(cnx, stream_id, PICOQINQ_ERROR_INTERNAL);
    } else if (stream_ctx->data_received + length > sizeof(stream_ctx->frame)) {
        /* Message too big. */
        ret = picoquic_reset_stream(cnx, stream_id, PICOQINQ_ERROR_PROTOCOL);
    }
    else {
        if (length > 0) {
            memcpy(&stream_ctx->frame[stream_ctx->data_received], bytes, length);
            stream_ctx->data_received += length;
        }

        if (fin_or_event == picoquic_callback_stream_fin) {
            /* TODO: consider server streams */
            /* Submit the message, obtain the response, send it back and finish the stream. */
            uint8_t response[256];

            int proto_ret = picoqinq_server_protocol_input(callback_ctx, stream_ctx->frame, stream_ctx->data_received, current_time);

            if (proto_ret == 0) {
                *response = 0;
                ret = picoquic_add_to_stream(cnx, stream_id, response, 1, 1);
            }
            else {
                /* Reset the stream */
                ret = picoquic_reset_stream(cnx, stream_id, proto_ret);
            }
        }
    }

    return ret;
}

/*
 * QINQ server call back.
 *
 * Create a context for each client connection.
 * 
 * The context holds:
 *  - a list of per stream context, used for managing incoming and outgoing requests.
 *  - a list of the connection ID that are registered for this context
 *  - the identity of the client, if it is known.
 */

int picoqinq_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    picoqinq_srv_cnx_ctx_t* ctx = NULL;
    picoqinq_server_stream_ctx_t* stream_ctx = (picoqinq_server_stream_ctx_t*)v_stream_ctx;


    /* TODO: the default context found here should be a function of the protocol, but
     * in the current setup it is just set globally.
     */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        ctx = picoqinq_create_srv_cnx_ctx(
            (picoqinq_srv_ctx_t*)picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx)), cnx);
        if (ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else {
            picoquic_set_callback(cnx, picoqinq_server_callback, ctx);
        }
    }
    else {
        ctx = (picoqinq_srv_cnx_ctx_t*)callback_ctx;
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            ret = picoqinq_server_callback_data(cnx, stream_ctx, stream_id, bytes, length, fin_or_event, ctx, picoquic_get_quic_time(picoquic_get_quic_ctx(cnx)));
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            picoqinq_forget_server_stream(ctx, stream_ctx);
            picoquic_reset_stream(cnx, stream_id, 0);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            picoqinq_delete_srv_cnx_ctx(ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            break;
        case picoquic_callback_stream_gap:
            /* Gap indication, when unreliable streams are supported */
            if (stream_ctx == NULL) {
                stream_ctx = picoqinq_find_or_create_server_stream(cnx, stream_id, ctx, 0);
            }
            if (stream_ctx != NULL) {
                /* Reset the stream status */
                picoqinq_forget_server_stream(ctx, stream_ctx);
                stream_ctx = NULL;
                picoquic_reset_stream(cnx, stream_id, 0);
            }
            picoquic_stop_sending(cnx, stream_id, PICOQINQ_ERROR_INTERNAL);
            break;
        case picoquic_callback_prepare_to_send:
            /* Used for active streams  -- is this really needed? */
            /* ret = picoqinq_server_callback_prepare_to_send(cnx, stream_id, stream_ctx, (void*)bytes, length, ctx); */
            break;
        case picoquic_callback_datagram:
            /* Process the datagram, which contains an address and a QUIC packet */
            ret = picoqinq_server_callback_datagram(ctx, bytes, length, picoquic_get_quic_time(picoquic_get_quic_ctx(cnx)));
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what QINQ expects */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

/* TODO: the QINQ context shall be created on server launch, and initialized
 * as an ALPN definition.
 */
