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

/* Implementation of the masque service over picoquic and h3zero.
* 
* The masque proxying is implemented using h3zero, and hooking
* into several APIs.
* 
* The management of Connect UDP uses the "extended
* connect" API, just like web transport. We have two consider
* multiple connection levels:
* 
* - there is a single Masque context managing all common data,
*   including lists of other contexts and lists of connection
*   identifiers. This is tied to the QUIC context in which
*   QUIC and H3 connections as defined.
* - there is one masque context per H3 connection. On the
*   server, this may mean one context per connection from masque
*   clients. On the client, there may be multiple contexts if the
*   client connects to multiple Masque proxies. This context
*   is tied to the H3 context of the connection.
* - there is one UDP_CONNECT context per <proxy, target> tuple,
*   where target is identified by IP address and port number.
* 
* On the client, the proper matching between connections, paths and UDP
* CONNECT contexts is debatable. We don't want something too
* intrusive. One solution would be to use a specific interface
* ID, if we can accept the risk of collision in the interface
* ID space. The "local" address will have that interface ID
* and the IP Address and port of the proxy. The "remote" address
* will have the that interface ID
* and the IP Address and port of the target.
* 
* The flow will be:
* - create or a connection to a target address, using the normal
*   API, but setting the "interface index" to the reserved
*   value "picomask interface ID".
* - intercept packets sent to the "picomask interface", and
*   submit them to the picomask outgoing API.
* 
* - if there is no connection yet to the selected proxy,
*   set one up.
* - if the is no Connect UDP context for the proxy and the
*   target, set one up.
* - if the context is created, queue the packets in the
*   connect UDP context, and wake up that context.
* 
* In the reverse path, packets will be incoming from the targets,
* and have to be associated with the selected context.
* We need a procedure to intercept incoming packets, by examining
* the connection ID and/or the IP addresses.
* 
* We assume that the size of queues will be managed by congestion control.
* If excessive, set the ECN marks or drop.
* 
* On the server, data from target is incoming over the UDP socket. If it
* does not match a local CID, it will be added to the queue
* of the UDP CONNECT context that matches the target address
* (remote address). This ends up with the same "send path"
* as for the cleint.
* 
* On the server, data from the client arrives in datagrams. It is queued
* in front of the local socket, maybe witten diractly to the UDP
* socket. Maybe integrate with the "prepare" API to catch these
* packets, so we have only on connection loop.
* 
* We need to define an H3Zero callback, using the same API as for
* "post" or "web transport", to handle the "connect UDP" protocol.
* The connection control messages will be handled through that
* callback, as well as the tunneled datagrams.
* 
* The forwarding path should be able to perform transforms,
* for incoming as well as outgoing packets.
*
*/

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "h3zero.h"
#include "h3zero_common.h"
#include "picoquic_utils.h"
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picosocks.h"
#include "h3zero_url_template.h"
#include "h3zero_uri.h"
#include "picomask.h"

int h3zero_queue_connect_header_frame(
    picoquic_cnx_t* cnx, h3zero_stream_ctx_t* stream_ctx,
    char const* authority, uint8_t const* path, size_t path_length, char const* protocol,
    char const* origin, char const* ua_string)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(origin);
#endif

    /* Format and send the connect frame. */
    int ret = 0;
    uint8_t buffer[1024];
    uint8_t* bytes = buffer;
    uint8_t* bytes_max = bytes + 1024;

    *bytes++ = h3zero_frame_header;
    bytes += 2; /* reserve two bytes for frame length */

    bytes = h3zero_create_connect_header_frame(bytes, bytes_max, authority, path, path_length, protocol, NULL,
        ua_string);

    if (bytes == NULL) {
        ret = -1;
    }
    else {
        /* Encode the header length */
        size_t header_length = bytes - &buffer[3];
        if (header_length < 64) {
            buffer[1] = (uint8_t)(header_length);
            memmove(&buffer[2], &buffer[3], header_length);
            bytes--;
        }
        else {
            buffer[1] = (uint8_t)((header_length >> 8) | 0x40);
            buffer[2] = (uint8_t)(header_length & 0xFF);
        }
        size_t connect_length = bytes - buffer;
        stream_ctx->ps.stream_state.is_upgrade_requested = 1;
        ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, buffer, connect_length,
            0, stream_ctx);
    }

    return ret;
}


/* UDP context splay management
*/


static picosplay_node_t* picomask_udp_node_create(void* value)
{
    return &((picomask_udp_ctx_t*)value)->node;
}

void* picomask_udp_node_value(picosplay_node_t* node)
{
    return (node == NULL)?NULL:(void*)((char*)node - offsetof(struct st_picomask_udp_ctx_t, node));
}

static int64_t picomask_udp_node_compare(void* l, void* r)
{
    struct sockaddr* la = (struct sockaddr*) & ((picomask_udp_ctx_t*)picomask_udp_node_value(l))->target_addr;
    struct sockaddr* ra = (struct sockaddr*)&((picomask_udp_ctx_t*)picomask_udp_node_value(r))->target_addr;

    return picoquic_compare_addr(la, ra);
}

static void picomask_udp_free(picomask_udp_ctx_t* udp_ctx)
{

    if (udp_ctx->h3_stream != NULL) {
        udp_ctx->h3_stream->path_callback_ctx = NULL;
        udp_ctx->h3_stream->path_callback = NULL;
        udp_ctx->h3_stream = NULL;
    }
    free(udp_ctx);
}

static void picomask_udp_node_delete(void* tree, picosplay_node_t* node)
{
    picomask_udp_ctx_t* udp_ctx = picomask_udp_node_value(node);
    picomask_udp_free(udp_ctx);
}

picomask_udp_ctx_t* picomask_udp_ctx_find(picomask_ctx_t* picomask_ctx, const struct sockaddr* target_addr)
{
    picomask_udp_ctx_t* udp_ctx = NULL;
    picomask_udp_ctx_t trial = { 0 };
    picosplay_node_t* node;
    picoquic_store_addr(&trial.target_addr, target_addr);
    node = picosplay_find(&picomask_ctx->udp_tree, &trial);
    if (node != NULL) {
        udp_ctx = picomask_udp_node_value(node);
    }
    return udp_ctx;
}

/* Delete the picomask context per udp connect
 */
void picomask_udp_ctx_delete(picomask_ctx_t* picomask_ctx, picomask_udp_ctx_t* udp_ctx)
{
    if (udp_ctx != NULL) {
        picosplay_node_t* node = picosplay_find(&picomask_ctx->udp_tree, (void*)udp_ctx);
        if (node != NULL) {
            picosplay_delete_hint(&picomask_ctx->udp_tree, node);
        }
        else {
            picomask_udp_free(udp_ctx);
        }
    }
}

void picomask_udp_init_tree(picosplay_tree_t* udp_tree)
{
    picosplay_init_tree(udp_tree, picomask_udp_node_compare, picomask_udp_node_create, picomask_udp_node_delete, picomask_udp_node_value);
}

/* Init the global context */

int picomask_ctx_init(picomask_ctx_t* ctx)
{
    int ret = 0;

    memset(ctx, 0, sizeof(picomask_ctx_t));
    picomask_udp_init_tree(&ctx->udp_tree);

    return ret;
}

void picomask_ctx_release(picomask_ctx_t* ctx)
{
    picosplay_empty_tree(&ctx->udp_tree);
}

/* Create the picomask context per udp connect */
int picomask_udp_ctx_create(picomask_ctx_t* picomask_ctx, struct sockaddr* target_addr, h3zero_stream_ctx_t * h3_stream, picomask_udp_ctx_t** p_udp_ctx)
{
    int ret = 0;
    picomask_udp_ctx_t* udp_ctx = (picomask_udp_ctx_t*)malloc(sizeof(picomask_udp_ctx_t));
    if (udp_ctx == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    } else {
        picosplay_node_t* node;
        memset(udp_ctx, 0, sizeof(picomask_udp_ctx_t));
        picoquic_store_addr(&udp_ctx->target_addr, target_addr);
        udp_ctx->local_addr.ss_family = AF_UNSPEC;
        node = picosplay_find(&picomask_ctx->udp_tree, (void*)udp_ctx);
        if (node != NULL) {
            ret = PICOQUIC_ERROR_DUPLICATE;
            free(udp_ctx);
            udp_ctx = NULL;
        }
        else {
            udp_ctx->picomask_ctx = picomask_ctx;
            udp_ctx->h3_stream = h3_stream;
            h3_stream->path_callback_ctx = udp_ctx;
            picosplay_insert(&picomask_ctx->udp_tree, udp_ctx);
            *p_udp_ctx = udp_ctx;
        }
    }
    return ret;
}

int picomask_udp_path_params(uint8_t* path, size_t path_length, struct sockaddr_storage* addr)
{
    int ret = 0;
    size_t query_offset = h3zero_query_offset(path, path_length);
    if (query_offset >= path_length) {
        ret = -1;
    } else {
        const uint8_t* queries = path + query_offset;
        size_t queries_length = path_length - query_offset;
        char ip_address_text[256];
        size_t ip_address_length =0;
        uint64_t server_port = 0;

        if (h3zero_query_parameter_string(queries, queries_length, "h", 1, (uint8_t *)ip_address_text, sizeof(ip_address_text), &ip_address_length) != 0 ||
            h3zero_query_parameter_number(queries, queries_length, "p", 1, &server_port, 0) != 0 ||
            server_port == 0 ||
            server_port > 0xffff ||
            ip_address_length >= sizeof(ip_address_text)) {
            ret = -1;
        }
        else if (picoquic_check_port_blocked((uint16_t)server_port)) {
            ret = -1;
        }
        else {
            int is_name = 0;
            ip_address_text[ip_address_length] = 0;
            /* TODO: for now, we want to only support addresses, not host names. */
            ret = picoquic_get_server_address(ip_address_text, (uint16_t)server_port, addr, &is_name);
            /* TODO: 
            * Verify that the path is OK: the UDP proxy disallows UDP proxying requests
            * to vulnerable targets, such as the UDP proxy's own addresses and localhost,
            * link-local, multicast, and broadcast addresses */
        }
    }

    return ret;
}

/* Release data and memory associated with a stream context */
void picomask_release_stream(h3zero_stream_ctx_t* stream_ctx)
{
    picomask_udp_ctx_t* udp_ctx = (picomask_udp_ctx_t * )stream_ctx->path_callback_ctx;
    if (udp_ctx != NULL) {
        picomask_udp_ctx_delete(udp_ctx->picomask_ctx, udp_ctx);
        stream_ctx->path_callback_ctx = NULL;
    }
    stream_ctx->path_callback = NULL;
}

struct st_picomask_fns_t picomask_fns = {
    picomask_intercept,
    picomask_redirect
};

/* Accept an incoming connection */
int picomask_accept(picoquic_cnx_t* cnx,
    uint8_t* path, size_t path_length,
    h3zero_stream_ctx_t* stream_ctx,
    void* v_path_app_ctx)
{
    int ret = 0;
    picomask_ctx_t* picomask_ctx = (picomask_ctx_t*)v_path_app_ctx;
    struct sockaddr_storage target_addr;
    picomask_udp_ctx_t* udp_ctx = NULL;

    /* the target's IP address and port number from the path? */
    ret = picomask_udp_path_params(path, path_length, &target_addr);

    /* attempt to create a UDP context */
    if (ret == 0) {
        ret = picomask_udp_ctx_create(picomask_ctx, (struct sockaddr*)&target_addr, stream_ctx, &udp_ctx);
    }
    if (ret == 0) {
        h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)cnx->callback_ctx;
        ret = h3zero_declare_stream_prefix(h3_ctx, stream_ctx->stream_id,
            picomask_callback, picomask_ctx);
        /* Force the MTU to be large enough to carry initial packets as datagrams. */
        if (udp_ctx->h3_stream->cnx->path[0]->send_mtu < PICOMASK_MTU_MIN) {
            udp_ctx->h3_stream->cnx->path[0]->send_mtu = PICOMASK_MTU_MIN;
        }
        if (cnx->quic->picomask_ctx == NULL) {
            cnx->quic->picomask_ctx = picomask_ctx;
            cnx->quic->picomask_fns = &picomask_fns;
        }
    }
    /* TODO: should provide return parameters such as local address */
    return ret;
}


/* Set app stream context. Todo: this is similar to code used in web transport.
* Function should be moved to h3 common.
 */
h3zero_stream_ctx_t* picomask_set_control_stream(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* h3_ctx)
{
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    h3zero_stream_ctx_t* stream_ctx = h3zero_find_or_create_stream(
        cnx, stream_id, h3_ctx, 1, 1);
    if (stream_ctx != NULL) {
        /* Associate the stream with a per_stream context */
        if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
            DBG_PRINTF("Could not set context for stream %"PRIu64, stream_id);
            h3zero_delete_stream(cnx, h3_ctx, stream_ctx);
            stream_ctx = NULL;
        }
    }
    return stream_ctx;
}

/* Expand the "path" component to include the IP address and port
* of the target, as expressed in a sockaddr, with port in network order.
 */
int picomask_expand_udp_path(char* text, size_t text_size, size_t* text_length, char const* path_template, struct sockaddr* addr)
{
    int ret = 0;
    h3zero_url_expression_param_t params[2] = { 0 };
    char addr_text[64];
    char port_text[8];
    size_t port_text_len;
    uint8_t * ip_addr;
    uint8_t ip_addr_len;
    uint16_t port = ntohs(picoquic_get_addr_port(addr));
    picoquic_get_ip_addr(addr, &ip_addr, &ip_addr_len);

    /* Convert address component to text */
    if (picoquic_sprintf(port_text, sizeof(port_text), &port_text_len, "%d", port) != 0 ||
        inet_ntop(addr->sa_family, ip_addr, addr_text, sizeof(addr_text)) == NULL) {
        ret = -1;
    }
    else {
        params[0].variable = "target_host";
        params[0].variable_length = 11;
        params[0].instance = addr_text;
        params[0].instance_length = strlen(addr_text);
        params[1].variable = "target_port";
        params[1].variable_length = 11;
        params[1].instance = port_text;
        params[1].instance_length = port_text_len;
        ret = h3zero_expand_template(text, text_size, text_length, path_template, params, 2);
    }
    return ret;
}

int picomask_connect_udp(picoquic_quic_t* quic, const char* authority, struct sockaddr* target_addr)
{
    int ret = 0;
    picomask_ctx_t* picomask_ctx = (picomask_ctx_t*)quic->picomask_ctx;
    if (picomask_ctx == NULL || picomask_ctx->cnx == NULL ||
        picomask_ctx->h3_ctx == NULL || picomask_ctx->path_template == NULL) {
        ret = -1;
    }
    else {
        h3zero_stream_ctx_t* stream_ctx = picomask_set_control_stream(picomask_ctx->cnx, picomask_ctx->h3_ctx);
        picomask_udp_ctx_t* udp_ctx = NULL;

        if (stream_ctx == NULL) {
            ret = -1;
        }
        /* Create the connection context for the UDP connect */
        else if ((ret = picomask_udp_ctx_create(picomask_ctx, target_addr, stream_ctx, &udp_ctx)) != 0) {
            DBG_PRINTF("Could not create UDP Connect context for stream %"PRIu64, stream_ctx->stream_id);
            ret = -1;
        }
        /* Register for the prefix in the H3 context. */
        else if ((ret = h3zero_declare_stream_prefix(picomask_ctx->h3_ctx, stream_ctx->stream_id,
            picomask_callback, udp_ctx)) != 0) {
            /* This can only if the stream prefix is already declared */
            DBG_PRINTF("Duplicate stream prefix %"PRIu64, stream_ctx->stream_id);
            ret = -1;
        }
        /* Finalize the context */
        else {
            /* WT_CONNECT establishes a mapping to a specific IP+port. */
            char path[256];
            size_t path_length;
            stream_ctx->is_open = 1;
            /* Set target_addr from path and address  */
            ret = picomask_expand_udp_path(path, sizeof(path), &path_length, picomask_ctx->path_template, target_addr);
            /* Then, queue the UDP_CONNECT frame. */
            if (ret == 0) {
                ret = h3zero_queue_connect_header_frame(picomask_ctx->cnx, stream_ctx, authority, (const uint8_t*)path, path_length, "connect-udp", NULL,
                    H3ZERO_USER_AGENT_STRING);
            }
        }

        if (ret != 0 && udp_ctx != NULL) {
            /* remove the stream prefix */
            h3zero_delete_stream_prefix(picomask_ctx->cnx, picomask_ctx->h3_ctx, stream_ctx->stream_id);
            /* TODO: verify that UDP context is deleted. */
        }
    }
    
    return ret;
}

/* Receive datagram.
* The datagram contains an encapsulated QUIC packet, in which the quarter stream ID 
* points at the stream context. The behavior is different on client and server.
* On client, the datagram is submitted to the QUIC context using the "incoming" API.
* On server, the datagram is queued to the "forwarded" queue, to be sent on the
* external path on the next call when picomask_forwarding is called.
* 
* The stream context points to the stream ID, and to the per application and
* per stream data, which contains the IP address.
 */
int picomask_receive_datagram(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length, h3zero_stream_ctx_t* stream_ctx, picomask_ctx_t* picomask_ctx)
{
    int ret = 0;
    /* Find the context from h3zero */
    picomask_udp_ctx_t* udp_ctx = (picomask_udp_ctx_t*)stream_ctx->path_callback_ctx;
    picoquic_quic_t* quic = picoquic_get_quic_ctx(cnx);
    uint64_t current_time = picoquic_get_quic_time(quic);
    picoquic_cnx_t* first_cnx = NULL;

    if (picoquic_is_client(cnx)) {
        ret = picoquic_incoming_packet_ex(quic, bytes, length,
            (struct sockaddr*)&udp_ctx->target_addr, (struct sockaddr*)&udp_ctx->local_addr,
            PICOQUIC_RESERVED_IF_INDEX, 0, &first_cnx, current_time);
    }
    else {
        picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(cnx->quic);
        if (sp != NULL) {
            sp->length = length;
            memcpy(sp->bytes, bytes, length);
            /* Fill up control fields */
            sp->ptype = picoquic_packet_1rtt_protected;
            picoquic_store_addr(&sp->addr_to, (struct sockaddr*)&udp_ctx->target_addr);
            picoquic_store_addr(&sp->addr_local, (struct sockaddr*)&cnx->path[0]->first_tuple->local_addr);
            sp->if_index_local = cnx->path[0]->first_tuple->if_index;
            sp->cnxid_log64 = picoquic_val64_connection_id(cnx->path[0]->first_tuple->p_local_cnxid->cnx_id);
            picoquic_queue_stateless_packet(quic, sp);
        }
        /* No action if memory allocation fails, because this indicates congestion. */
    }
    return ret;
}

/*
* Implementation of the picoquic "proxy intercept" API.
* This will be called when the picoquic stack has prepared a packet.
* The first step is to decide whether the packet shall be proxied.
* If the packet shall be proxied, a copy shall be added to
* the proxy context.
*/

int picomask_queue_datagram_to_context(picoquic_cnx_t * cnx, picomask_udp_ctx_t* udp_ctx, const uint8_t * bytes, size_t length)
{
    /* TODO: this code is horrific, we need a way to bypass the datagram queue */
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    size_t v_ll = picoquic_varint_encode(buffer, PICOQUIC_MAX_PACKET_SIZE, udp_ctx->h3_stream->stream_id / 4);

    if (v_ll + length > PICOQUIC_MAX_PACKET_SIZE) {
        ret = PICOQUIC_ERROR_PACKET_TOO_LONG;
    }
    else {
        memcpy(buffer + v_ll, bytes, length);
        ret = picoquic_queue_datagram_frame(cnx, v_ll + length, buffer);
    }
    return ret;
}

int picomask_intercept(struct st_picomask_ctx_t* picomask_ctx, uint64_t current_time,
    uint8_t* send_buffer, size_t* send_length, size_t* send_msg_size,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int *if_index)
{
    int ret = 0;
    picomask_udp_ctx_t* udp_ctx;

    /* Check whether there is a context associated with the 4-tuple */
    udp_ctx = picomask_udp_ctx_find(picomask_ctx, (struct sockaddr*)p_addr_to);
    if (udp_ctx == NULL) {
        /* TODO: create a UDP CTX, and if needed create a connection */
    }

    /* Queue a datagram in the context */
    if (udp_ctx != NULL) {
        /* Force the path MTU so min length packets can be forwarded as datagrams */
        if (picomask_ctx->cnx->path[0]->send_mtu < PICOMASK_MTU_MIN) {
            picomask_ctx->cnx->path[0]->send_mtu = PICOMASK_MTU_MIN;
        }
        ret = picomask_queue_datagram_to_context(picomask_ctx->cnx, udp_ctx, send_buffer, *send_length);
        if (ret == PICOQUIC_ERROR_DATAGRAM_TOO_LONG) {
            /* Not really an error: packets larger than the tunnel PMTU should be dropped. */
            ret = 0;
        }
    }
    else {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    /* Confirm the interception */
    *send_length = 0;
    return ret;
}

/* Redirect: an incoming packet */

int picomask_redirect(struct st_picomask_ctx_t* picomask_ctx,
    const uint8_t* bytes,
    size_t packet_length,
    const struct sockaddr* addr_from,
    size_t* consumed)
{
    int ret = 0;
    picomask_udp_ctx_t* udp_ctx;
    /* Check whether there is a context associated with the 4-tuple */
    udp_ctx = picomask_udp_ctx_find(picomask_ctx, addr_from);

    if (udp_ctx != NULL) {
        /* Force the path MTU so min length packets can be forwarded as datagrams */
        if (udp_ctx->h3_stream->cnx->path[0]->send_mtu < PICOMASK_MTU_MIN) {
            udp_ctx->h3_stream->cnx->path[0]->send_mtu = PICOMASK_MTU_MIN;
        }
        ret = picomask_queue_datagram_to_context(udp_ctx->h3_stream->cnx, udp_ctx, bytes, packet_length);
        if (ret == 0 || ret == PICOQUIC_ERROR_DATAGRAM_TOO_LONG){
            ret = PICOQUIC_ERROR_REDIRECTED;
            *consumed = packet_length;
        }
    }
    return ret;
}

/* picomask callback. This will be called from the web server
* when the path points to a picomask callback.
*/

int picomask_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t wt_event,
    h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    picomask_ctx_t* picomask_ctx = (picomask_ctx_t*)path_app_ctx;

    DBG_PRINTF("picomask_callback: %d, %" PRIi64 "\n", (int)wt_event, (stream_ctx == NULL)?(int64_t)-1:(int64_t)stream_ctx->stream_id);
    switch (wt_event) {
    case picohttp_callback_connect:
        /* A connect has been received on this stream, and could be accepted.
        * The path app context should point to the global masque context.
        */
        ret = picomask_accept(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_connect_refused:
        /* The response from the server has arrived and it is negative. The 
        * application needs to close that stream.
        */
        break;
    case picohttp_callback_connect_accepted: 
        if (stream_ctx != NULL) {
            /* Stream will now carry "capsules" */
            stream_ctx->is_upgraded = 1;
        }
        break;
    case picohttp_callback_post_fin:
    case picohttp_callback_post_data:
        /* Receiving capsule data on the control stream. 
         * if the FIN bit is set, the connection will be closed.
         */
        /* ret = picomask_stream_data(cnx, bytes, length, (wt_event == picohttp_callback_post_fin), stream_ctx, path_app_ctx); */
        break; 
    case picohttp_callback_provide_data: 
        /* callback to provide data. Provide the next capsule. */
        /* ret = picomask_provide_data(cnx, bytes, length, stream_ctx, path_app_ctx); */
        break;
    case picohttp_callback_post_datagram:
        /* Stack received a datagram. Submit as "incoming" packet on the
        * select connection and path */
        ret = picomask_receive_datagram(cnx, bytes, length, stream_ctx, picomask_ctx);
        break;
    case picohttp_callback_provide_datagram: 
        /* callback to provide a datagram. Not used in the current code. */
        ret = -1;
        break;
    case picohttp_callback_reset: 
        /* Control stream has been abandoned. */
        picomask_release_stream(stream_ctx);
        break;
    case picohttp_callback_free: /* Used during clean up the stream. Only cause the freeing of memory. */
                                 /* Free the memory attached to the stream */
        picomask_release_stream(stream_ctx);
        break;
    case picohttp_callback_deregister:
        picomask_release_stream(stream_ctx);
        break;
    default:
        /* protocol error */
        ret = -1;
        break;
    }
    return ret;
}

/* Creation of an outer connection.
 * On client, this is done explicitly: create a connection to
 * a proxy, get a unique UDP connection ID. This requires
 * first creating an H3 connection (may already exist), and
 * then issuing the UDP connect.
 * On server, this is done upon successful connection from
 * a client.
 */

/* Connect proxy declares a proxy for use as a proxy service for connections that
* need it.
*/
int picomask_register_proxy_client(picoquic_quic_t* quic, char const* proxy_sni, size_t max_nb_udp,
    struct sockaddr* proxy_addr, uint64_t current_time, const char* path_template)
{
    int ret = 0;
    picomask_ctx_t* picomask_ctx = quic->picomask_ctx;

    if (picomask_ctx == NULL) {
        picomask_ctx = (picomask_ctx_t*)malloc(sizeof(picomask_ctx_t));
        if (picomask_ctx == NULL) {
            ret = -1;
        }
        else {
            ret = picomask_ctx_init(picomask_ctx);
            picomask_ctx->path_template = path_template;
            quic->picomask_ctx = picomask_ctx;
            quic->picomask_fns = &picomask_fns;
        }
    }

    if (ret == 0 && picomask_ctx->cnx == NULL &&
        (picomask_ctx->cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
            proxy_addr, current_time, 0, proxy_sni, "h3", 1)) == NULL) {
        ret = -1;
    }

    if (ret == 0 && picomask_ctx->h3_ctx == NULL) {
        picomask_ctx->cnx->local_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
        if ((picomask_ctx->h3_ctx = h3zero_callback_create_context(NULL)) == NULL) {
            ret = -1;
        }
        else {
            picoquic_set_callback(picomask_ctx->cnx, h3zero_callback, picomask_ctx->h3_ctx);
            ret = h3zero_protocol_init(picomask_ctx->cnx);
        }
    }
    /* TODO: release picomask_ctx on error */
    return ret;
}
