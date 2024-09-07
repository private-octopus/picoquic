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


#include "picomask.h"
#include "h3zero.h"
#include "h3zero_common.h"

int picomask_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t wt_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx);

/* Context retrieval functions */
static uint64_t table_udp_hash(const void * key)
{
    /* the key is a unique 64 bit number, so we keep this simple. */
    return *((uint64_t*)key);
}

static int table_udp_compare(const void* key1, const void* key2)
{
    return (*((uint64_t*)key1) == *((uint64_t*)key2)) ? 0 : -1;
}


static picohash_item * table_udp_to_item(const void* key)
{
    picomask_cnx_ctx_t* cnx_ctx = (picomask_cnx_ctx_t*)key;
    return &cnx_ctx->hash_item;
}

picomask_cnx_ctx_t* picomask_cnx_ctx_by_number(picomask_ctx_t* ctx, uint64_t picomask_number)
{
    picomask_cnx_ctx_t* cnx_ctx = NULL;
    picohash_item* item;
    picomask_cnx_ctx_t key = { 0 };
    key.picomask_number = picomask_number;
    key.hash_item.key = (void*)&key.picomask_number;
    item = picohash_retrieve(ctx->table_udp_ctx, &key);

    if (item != NULL) {
        cnx_ctx = (picomask_cnx_ctx_t*)(((uint8_t*)(item)-
            offsetof(struct st_picomask_cnx_ctx_t, hash_item)));
    }
    return cnx_ctx;
}

/* Init the global context */

int picomask_ctx_init(picomask_ctx_t* ctx, size_t max_nb_connections)
{
    int ret = 0;

    if ((ctx->table_udp_ctx = picohash_create_ex(max_nb_connections,
        table_udp_hash, table_udp_compare, table_udp_to_item)) == NULL) {
        ret = -1;
    }

    return ret;
}

void picomask_ctx_release(picomask_ctx_t* ctx)
{
    /* Delete all the existing contexts, by walking through
    * the table */
    /* then delete the table itself. */
    picohash_delete(ctx->table_udp_ctx, 0);
}


/* Create the picomask context per udp connect */
picomask_cnx_ctx_t* picomask_cnx_ctx_create(picomask_ctx_t* picomask_ctx)
{
    picomask_cnx_ctx_t* cnx_ctx = (picomask_cnx_ctx_t*)malloc(sizeof(picomask_cnx_ctx_t));
    if (cnx_ctx != NULL) {
        memset(cnx_ctx, 0, sizeof(picomask_cnx_ctx_t));
        cnx_ctx->picomask_number = picomask_ctx->picomask_number_next++;
        /* register in table of contexts */
        picohash_insert(picomask_ctx->table_udp_ctx, cnx_ctx);
    }
    return cnx_ctx;
}
#if 0
/* Update context when sending a connect request */
int picomask_connecting(picoquic_cnx_t* cnx,
    h3zero_stream_ctx_t* stream_ctx, void * v_masque_ctx)
{
    picomask_ctx_t* picomask_ctx = (picomask_ctx_t*)v_masque_ctx;

    picoquic_log_app_message(cnx, "Outgoing connect udp on stream: %"PRIu64, stream_ctx->stream_id);

    return 0;
}

/* Accept an incoming connection */
int picomask_accept(picoquic_cnx_t* cnx,
    uint8_t* path, size_t path_length,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;

    /* Find the target's IP address and port number from the path */

    /* Verify that the path is OK: the UDP proxy disallows UDP proxying requests
    * to vulnerable targets, such as the UDP proxy's own addresses and localhost,
    * link-local, multicast, and broadcast addresses */

    /* If doing just connect UDP, by opposition to QUIC proxy, accept
    * only one connection for a given IP+port. If doing QUIC proxy,
    * manage the registered CID for the long header packets.
    */

    /* create a per connection context, indexed by stream ID and
    * some unique identifier of the connection.
    */

    /* if all is well, */
    return ret;
}
#endif

/* Prepare datagram. This is the call from the inner connection,
* stating that a datagram can now be sent. The masque context
* pick the UDP connect context with the smallest wakeup time,
 */

/* picomask callback. This will be called from the web server
* when the path points to a picomask callback.
*/

int picomask_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t wt_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    DBG_PRINTF("picomask_callback: %d, %" PRIi64 "\n", (int)wt_event, (stream_ctx == NULL)?(int64_t)-1:(int64_t)stream_ctx->stream_id);
    switch (wt_event) {
    case picohttp_callback_connect:
        /* A connect has been received on this stream, and could be accepted.
        * The path app context should point to the global masque context.
        */
        /* ret = picomask_accept(cnx, bytes, length, stream_ctx, path_app_ctx); */
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
        /* ret = picomask_receive_datagram(cnx, bytes, length, stream_ctx, path_app_ctx); */
        break;
    case picohttp_callback_provide_datagram: 
        /* callback to provide data. This will translate to a "prepare data" call
        * on the next available connection context and path context */
        /* ret = picomask_provide_datagram(cnx, bytes, length, stream_ctx, path_app_ctx); */
        break;
    case picohttp_callback_reset: 
        /* Control stream has been abandoned. Abandon the whole connection. */
        /* ret = picomask_stream_reset(cnx, stream_ctx, path_app_ctx); */
        break;
    case picohttp_callback_free: /* Used during clean up the stream. Only cause the freeing of memory. */
                                 /* Free the memory attached to the stream */
        break;
    case picohttp_callback_deregister:
        /* The app context has been removed from the registry.
        * Its references should be removed from streams belonging to this session.
        * On the client, the memory should be freed.
        */
        /* picomask_unlink_context(cnx, stream_ctx, path_app_ctx); */
        break;
    default:
        /* protocol error */
        ret = -1;
        break;
    }
    return ret;
}

/* Connect is called when the path registers to use the tunnel service.
* The call should document the masque context of the service, and
* also the inner connection and inner path id.
*/
int picomask_connect(picoquic_cnx_t* cnx, picomask_ctx_t* picomask_ctx, 
    char const * server_path, 
    h3zero_callback_ctx_t* h3_ctx)
{
    int ret = 0;
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    h3zero_stream_ctx_t* stream_ctx = NULL;
    picomask_cnx_ctx_t* cnx_ctx = NULL;
    UNREFERENCED_PARAMETER(server_path);
    /* Create an H3 stream context */
    if ((stream_ctx = h3zero_find_or_create_stream(
        cnx, stream_id, h3_ctx, 1, 1)) == NULL) {
        ret = -1;
    }
    /* Associate the stream with a per_stream context */
    else if ((ret = picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx)) != 0) {
        DBG_PRINTF("Could not set context for stream %"PRIu64, stream_id);
        stream_ctx = NULL;
    }
    /* Create the connection context for the UDP connect */
    else if ((cnx_ctx = picomask_cnx_ctx_create(picomask_ctx)) == NULL) {
        DBG_PRINTF("Could not create UDP Connect context for stream %"PRIu64, stream_id);
        ret = -1;
    }
    /* Register for the prefix in the H3 context. */
    else if ((ret = h3zero_declare_stream_prefix(h3_ctx, stream_ctx->stream_id,
        picomask_callback, cnx_ctx))!=0){
        DBG_PRINTF("Could not declare prefix stream %"PRIu64, stream_id);
        /* clean up? */
    }
    /* Finalize the context */
    else {
        /* WT_CONNECT finalizes the context with a call to the connecting event.
        * But we do not have any sub protocol, so we can do that here.
         */
        cnx_ctx->cnx = cnx;
        cnx_ctx->stream_id = stream_id;
        /* to do: set target_addr from path */
        /* Then, queue the UDP_CONNECT frame. */
    }

    if (ret != 0) {
        /* clean up the partially created contexts */
        if (cnx_ctx != NULL) {
            /* delete that */
        }
        if (stream_ctx != NULL) {
            h3zero_delete_stream(cnx, h3_ctx, stream_ctx);
        }
    }
    return ret;
}

/* Calls from the inner connection:
* state when a path is ready to send data. This is a combination of
* having data to send, and not being limited by CC and pacing.
* 
* Should document the "next time" for the path. Then, the
* masque context will translate that into a "ready to send"
* signal for the inner connection. 
 */

/* Mapping a path to a proxy, on the client?
* 
*/


/* Creation of an outer connection.
 * On client, this is done explicitly: create a connection to
 * a proxy, get a unique UDP connection ID. This requires
 * first creating an H3 connection (may already exist), and
 * then issuing the UDP connect.
 * On server, this is done upon successful connection from
 * a client.
 */



/* management of outgoing packets at the client */
int picomask_outgoing()
{
    /* Is there an established context for these addresses? 
     * if yes, queue it there.
     */

    /* If not, is there yet an established H3 connection for
     * the source address?
     */

    /* If not, establish the h3 connection. 
    * TODO: provide credentials.
     */

    /* is there now an established H3 connection for
     * the source address?*/

    /* if not, return an error */
    /* if yes, create a Connect UDP context, queue the packet to it */
    return -1;
}