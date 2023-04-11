/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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

/* The "baton" protocol was defined as a test application protocol for 
 * web transport. We use it here to test design ideas for implementing
 * web transport as a "filter". In that "filter" architecture, the
 * call back from the H3 stack arrive directly to the application
 * processor. If needed, the application uses the web transport
 * library to implement the web transport functions.
 */

#ifndef WT_BATON_H
#define WT_BATON_H

#ifdef __cplusplus
extern "C" {
#endif
    /* Wt_baton context:
     *
     */
    typedef enum {
        wt_baton_state_none = 0,
        wt_baton_state_ready,
        wt_baton_state_sent,
        wt_baton_state_done,
        wt_baton_state_error,
        wt_baton_state_closed,
        wt_baton_state_reset
    } wt_baton_state_enum;

    typedef struct st_wt_baton_ctx_t {
        /* the streams are managed though a splay.
         * on the server, we just reuse the local server tree.
         * on the native client, we need to manage a local tree,
         * and set the tree pointer to that.
         */
        picosplay_tree_t * h3_stream_tree;
        char const* server_path;
        /* connection wide tracking of stream prefixes.
         * on the server, we use the global tracker.
         * on the client, we manage a placeholder.
         */
        h3zero_stream_prefixes_t * stream_prefixes;
        /* control stream context, will need to remain open as long 
         */
        uint64_t control_stream_id;
        /* Connection state */
        int is_client;
        int connection_ready;
        int connection_closed;
        /* Baton protocol data */
        uint8_t baton;
        uint8_t baton_received;
        uint64_t nb_baton_bytes_received;
        int nb_turns;
        int nb_turns_required;
        wt_baton_state_enum baton_state;
        /* Datagram management */
        int nb_datagrams_received;
        size_t nb_datagram_bytes_received;
        uint8_t baton_datagram_received;
        int nb_datagrams_sent;
        size_t nb_datagram_bytes_sent;
        int is_datagram_ready;
        uint8_t baton_datagram_send_next;
    } wt_baton_ctx_t;

    typedef struct st_wt_baton_app_ctx_t {
        int nb_turns_required;
    } wt_baton_app_ctx_t;

    int wt_baton_accept(picoquic_cnx_t* cnx,
        uint8_t* bytes, size_t length,
        struct st_picohttp_server_stream_ctx_t* stream_ctx,
        void* path_app_ctx);

    picohttp_server_stream_ctx_t* wt_baton_create_stream(picoquic_cnx_t* cnx, int is_bidir, wt_baton_ctx_t* baton_ctx);
    picohttp_server_stream_ctx_t* wt_baton_find_stream(wt_baton_ctx_t* ctx, uint64_t stream_id);

    int wt_baton_ctx_init(wt_baton_ctx_t* ctx, h3zero_callback_ctx_t* h3_ctx, wt_baton_app_ctx_t* app_ctx, picohttp_server_stream_ctx_t* stream_ctx);
    /* Web transport callback. This will be called from the web server
    * when the path points to a web transport callback
    */

    int wt_baton_callback(picoquic_cnx_t* cnx,
        uint8_t* bytes, size_t length,
        picohttp_call_back_event_t fin_or_event,
        struct st_picohttp_server_stream_ctx_t* stream_ctx,
        void* path_app_ctx);

#ifdef __cplusplus
}
#endif
#endif /* WT_BATON_H */