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
* We need to define an H3Zero callback, using the same API as for
* "post" or "web transport", to handle the "connect UDP" protocol.
* The connection control messages will be handled through that
* callback, as well as the tunneled datagrams.
* 
* We need a procedure to intercept incoming packets, by examining
* the connection ID. 
* 
* We also need to define extensions to path management for
* handling tunneled paths. The path will be examined if the
* outer connection can send a datagram, and if there is
* a queue of packets for the connect UDP context.
* 
* The forwarding path should be able to perform transforms,
* for incoming as well as outgoing packets.
 */

#include "picomask.h"
#include "h3zero.h"
#include "h3zero_common.h"

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

 /* Web transport/baton callback. This will be called from the web server
 * when the path points to a web transport callback.
 * Discuss: is the stream context needed? Should it be a wt_stream_context?
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
    case picohttp_callback_connecting:
        ret = picomask_connecting(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_connect:
        /* A connect has been received on this stream, and could be accepted.
        */
        ret = picomask_accept(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_connect_refused:
        /* The response from the server has arrived and it is negative. The 
        * application needs to close that stream.
        */
        break;
    case picohttp_callback_connect_accepted: /* Connection request was accepted by peer */
                                             /* The response from the server has arrived and it is positive.
                                             * The application can start sending data.
                                             */
        if (stream_ctx != NULL) {
            /* Stream will now carry "capsules" */
            stream_ctx->is_upgraded = 1;
        }
        break;
    case picohttp_callback_post_fin:
    case picohttp_callback_post_data:
        ret = picomask_stream_data(cnx, bytes, length, (wt_event == picohttp_callback_post_fin), stream_ctx, path_app_ctx);
        break; 
    case picohttp_callback_provide_data: 
        /* Quic is ready to send. Push reminder of capsules! */
        ret = picomask_provide_data(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_post_datagram:
        /* Stack received a datagram. Submit as "incoming" packet on connection. */
        ret = picomask_receive_datagram(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_provide_datagram: 
        /* Stack can now send another datagram.
        * Should ask the inner connection to produce a packet. */
        ret = picomask_provide_datagram(cnx, bytes, length, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_reset: 
        /* Control stream has been abandoned. Abandon the whole connection. */
        ret = picomask_stream_reset(cnx, stream_ctx, path_app_ctx);
        break;
    case picohttp_callback_free: /* Used during clean up the stream. Only cause the freeing of memory. */
                                 /* Free the memory attached to the stream */
        break;
    case picohttp_callback_deregister:
        /* The app context has been removed from the registry.
        * Its references should be removed from streams belonging to this session.
        * On the client, the memory should be freed.
        */
        picomask_unlink_context(cnx, stream_ctx, path_app_ctx);
        break;
    default:
        /* protocol error */
        ret = -1;
        break;
    }
    return ret;
}
#endif