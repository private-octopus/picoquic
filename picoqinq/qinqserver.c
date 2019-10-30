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

int picoqinq_cid_cnx_link_create(picoqinq_srv_cnx_ctx_t* cnx_ctx, picoquic_connection_id_t* cid)
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

picoqinq_qinq_cid_prefix_route_t* picoqinq_find_route_by_cid(picoqinq_srv_ctx_t* qinq, uint8_t* id)
{
    picoqinq_qinq_cid_prefix_route_t* route = NULL;
    picoqinq_qinq_cid_prefix_route_t key;
    picohash_item* item;
    memset(&key, 0, sizeof(picoqinq_qinq_cid_prefix_route_t));
    picoquic_parse_connection_id(id, qinq->min_prefix_length, &key.cid_prefix);

    item = picohash_retrieve(qinq->table_prefix_route, &key);

    if (item != NULL) {
        route = (picoqinq_qinq_cid_prefix_route_t*)item->key;
    }

    return route;
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
    int ret = 0;

    if (packet_length < 17) {
        /* packet too short */
    }
    else if ((bytes[0] & 64) != 0) {
        /* Not a QUIC packet */
    }
    else if ((bytes[0] & 0x80) == 0x80) {
        /* This is a long packet header. According to the invariant specification, 
         * the initial byte is followed by a 4 bytes version field,
         * followed by DCI length and DCID value. */
        
        if (picoquic_parse_connection_id(bytes + 6, bytes[5], &dcid) == 0) {
            /* Unexpected. Cannot do anything with that packet */
        }
        else {
            if (picoquic_is_local_cid(qinq->quic, &dcid)) {
                /* Local packet. Forward to local quic context */
                ret = picoquic_incoming_packet(qinq->quic, bytes, packet_length, addr_from, addr_to, if_index_to, received_ecn, current_time);
            }
            else {
                int is_proxied = 0;
                picoqinq_qinq_cid_prefix_route_t* route = picoqinq_find_route_by_cid(qinq, dcid.id);

                if (route != NULL) {
                    picoquic_cid_cnx_link_t* link = route->first_route;

                    while (link != NULL) {
                        if (picoquic_compare_connection_id(&link->cid, &dcid) == 0) {
                            /* Packet may be bound to this proxied connections, pending address check */
                            is_proxied |= picoquic_incoming_proxy_packet(link->cnx_ctx, bytes, packet_length, &link->cid, addr_from, addr_to, if_index_to, received_ecn, current_time);
                        }
                        link = link->next_route;
                    }
                }

                if (is_proxied == 0) {
                    /* TODO: if this is an initial packet, it may be bound to the local SNI/ALPN,
                     * or to a proxied server. But we do not support proxied servers yet, so
                     * we just pass everything to the local server. */
                    ret = picoquic_incoming_packet(qinq->quic, bytes, packet_length, addr_from, addr_to, if_index_to, received_ecn, current_time);
                }
            }
        }
    }
    else {
        /* This is a short packet header. Prepare a CID value. */
        int is_local = 0;
        int is_proxied = 0;

        if (picoquic_get_local_cid_length(qinq->quic) < packet_length){
            (void)picoquic_parse_connection_id(bytes + 1, picoquic_get_local_cid_length(qinq->quic), &dcid);
            if (picoquic_is_local_cid(qinq->quic, &dcid)) {
                /* local delivery */
                ret = picoquic_incoming_packet(qinq->quic, bytes, packet_length, addr_from, addr_to, if_index_to, received_ecn, current_time);
                is_local = 1;
            }
        }

        if (!is_local && qinq->min_prefix_length < packet_length){
            picoqinq_qinq_cid_prefix_route_t* route = picoqinq_find_route_by_cid(qinq, bytes+1);

            if (route != NULL) {
                picoquic_cid_cnx_link_t* link = route->first_route;

                while (link != NULL) {
                    if (memcmp(&link->cid.id, bytes+1, link->cid.id_len) == 0) {
                        /* Packet may be bound to this proxied connections, pending address check */
                        is_proxied |= picoquic_incoming_proxy_packet(link->cnx_ctx, bytes, packet_length, 
                            &link->cid, addr_from, addr_to, if_index_to, received_ecn, current_time);
                    }
                    link = link->next_route;
                }
            }
        }

        if (!is_local && !is_proxied) {
            /* This packet could not be processed */
            ret = PICOQINQ_ERROR_INVALID_PACKET;
        }
    }

    return ret;
}

int picoquic_incoming_proxy_packet(
    picoqinq_srv_cnx_ctx_t* qinq,
    uint8_t* bytes,
    size_t packet_length,
    picoquic_connection_id_t * dcid,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time)
{
    /* TODO: check whether the packet is acceptable, submit as datagram, etc. */
    return 0;
}


picoqinq_srv_ctx_t* picoqinq_create_srv_ctx(picoquic_quic_t* quic, uint8_t min_prefix_length, size_t nb_cid)
{
    picoqinq_srv_ctx_t* qinq = (picoqinq_srv_ctx_t*)malloc(sizeof(picoqinq_srv_ctx_t));

    if (qinq != NULL) {
        qinq->quic = quic;
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

void picoqinq_delete_srv_ctx(picoqinq_srv_ctx_t* qinq)
{
    while (qinq->cnx_first != NULL) {
        picoqinq_delete_srv_cnx_ctx(qinq->cnx_first);
    }

    picohash_delete(qinq->table_prefix_route, 1);
}

picoqinq_srv_cnx_ctx_t* picoqinq_create_srv_cnx_ctx(picoqinq_srv_ctx_t* qinq)
{
    picoqinq_srv_cnx_ctx_t* cnx_ctx = (picoqinq_srv_cnx_ctx_t*)malloc(sizeof(picoqinq_srv_cnx_ctx_t));

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
    picoqinq_delete_srv_cnx_ctx_hc(&ctx->receive_hc);
    picoqinq_delete_srv_cnx_ctx_hc(&ctx->send_hc);

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

/* TODO: the QINQ context shall be created on server launch, and initialized
 * as an ALPN definition.
 */

/*
 * Datagram call back, process Quic datagrams received from a qinq client.
 */
int picoqinq_server_callback_datagram(picoqinq_srv_cnx_ctx_t* ctx, uint8_t* bytes, size_t length)
{
    /* Verify that this is an expected destination for which quic is supported. */
    /* Possibly, verify that this is a valid CNX-ID, but consider possible migrations. */
    /* Send the datagram on the selected socket for the context. */
    int ret = 0;
    picoquic_stateless_packet_t* outpack = picoquic_create_stateless_packet(ctx->qinq->quic);

    if (outpack != NULL) {
        /* TODO: Parse the datagram header to extract the address_to */
        /* TODO: perform address verifications */
        /* TODO: keep track of CID */
        picoquic_queue_stateless_packet(ctx->qinq->quic, outpack);
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

int picoqinq_server_callback_data(picoquic_cnx_t* cnx, picoqinq_server_stream_ctx_t* stream_ctx, uint64_t stream_id, uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event, picoqinq_srv_cnx_ctx_t* callback_ctx)
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
        ret = -1;
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
            size_t response_length=0;
            /* TODO
            ret = picoqinq_server_protocol_input(callback_ctx, stream_ctx->frame, stream_ctx->data_received,
                response, sizeof(response), &response_length); */
            if (ret == 0) {
                ret = picoquic_add_to_stream(cnx, stream_id, response, response_length, 1);
            }
            else {
                /* Reset the stream */
                ret = picoquic_reset_stream(cnx, stream_id, PICOQINQ_ERROR_PROTOCOL);
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

picoqinq_srv_cnx_ctx_t* picoqinq_server_callback_create_context(picoqinq_srv_ctx_t* qinq_ctx)
{
    picoqinq_srv_cnx_ctx_t* ctx = (picoqinq_srv_cnx_ctx_t*)
        malloc(sizeof(picoqinq_srv_cnx_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(picoqinq_srv_cnx_ctx_t));
        ctx->first_stream = NULL;
    }
    return ctx;
}

void picoqinq_server_callback_delete_context(picoqinq_srv_cnx_ctx_t* ctx)
{
    if (ctx != NULL) {
        picoqinq_server_stream_ctx_t* stream_ctx = NULL;
        /* Manage the list of streams. */
        while (1) {
            picoqinq_server_stream_ctx_t* stream_ctx = ctx->first_stream;
            if (stream_ctx != NULL) {
                ctx->first_stream = stream_ctx->next_stream;
                free(stream_ctx);
            }
            else {
                break;
            }
        }
        /* TODO: manage the list of CID. */
        /* TODO: manage identity. */
        free(ctx);
    }
}


int picoqinq_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    picoqinq_srv_cnx_ctx_t* ctx = NULL;
    picoqinq_server_stream_ctx_t* stream_ctx = (picoqinq_server_stream_ctx_t*)v_stream_ctx;

    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        ctx = picoqinq_server_callback_create_context(
            (picoqinq_srv_ctx_t*)picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx)));
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
            ret = picoqinq_server_callback_data(cnx, stream_ctx, stream_id, bytes, length, fin_or_event, ctx);
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            picoqinq_forget_server_stream(ctx, stream_ctx);
            picoquic_reset_stream(cnx, stream_id, 0);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            picoqinq_server_callback_delete_context(ctx);
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
            ret = picoqinq_server_callback_datagram(ctx, bytes, length);
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


