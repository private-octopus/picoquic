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
        wt_baton_state_connect_received,
        wt_baton_state_unidir_sent,
        wt_baton_state_unidir_received,
        wt_baton_state_bidir_sent,
        wt_baton_state_bidir_received,
        wt_baton_state_done,
        wt_baton_state_closed
    } wt_baton_state_enum;

    typedef struct st_wt_baton_stream_ctx_t {
        struct st_wt_baton_stream_ctx_t* next;
        struct st_wt_baton_stream_ctx_t* previous;
        h3zero_data_stream_state_t stream_state;
        uint8_t baton[256];
        size_t nb_received;
        size_t nb_sent;
        int connection_closed;
    } wt_baton_stream_ctx_t;

    typedef struct st_wt_baton_ctx_t {
        uint8_t baton[256];
        int nb_turns;
        int is_disconnected;
        int nb_turns_required;
        wt_baton_state_enum baton_state;
        struct st_wt_baton_stream_ctx_t* first;
        struct st_wt_baton_stream_ctx_t* last;
        int connection_ready;
        int connection_closed;
    } wt_baton_ctx_t;

    typedef struct st_wt_baton_app_ctx_t {
        int nb_turns_required;
    } wt_baton_app_ctx_t;

    int wt_baton_accept(picoquic_cnx_t* cnx,
        uint8_t* bytes, size_t length,
        struct st_picohttp_server_stream_ctx_t* stream_ctx,
        void* path_app_ctx);

    int wt_baton_create_stream(picoquic_cnx_t* cnx, int is_bidir, wt_baton_ctx_t* baton_ctx);

    void wt_baton_ctx_release(wt_baton_ctx_t* ctx);

    /* Web transport callback. This will be called from the web server
    * when the path points to a web transport callback
    */

    int picowt_h3zero_callback(picoquic_cnx_t* cnx,
        uint8_t* bytes, size_t length,
        picohttp_call_back_event_t fin_or_event,
        struct st_picohttp_server_stream_ctx_t* stream_ctx,
        void* path_app_ctx);

    /* Client call back -- limited implementation of H3. */
    int wt_baton_client_callback(picoquic_cnx_t* cnx,
        uint64_t stream_id, uint8_t* bytes, size_t length,
        picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);
#ifdef __cplusplus
}
#endif
#endif WT_BATON_H