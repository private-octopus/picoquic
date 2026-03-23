/*
* Author: Christian Huitema
* Copyright (c) 2026, Private Octopus, Inc.
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

#ifndef WT_H09_H
#define WT_H09_H

#ifdef __cplusplus
extern "C" {
#endif
#define PICOWT_H09_ALPN "hq-interop"
#define PICOWT_H09_ALPN_AVAILABLE "hq-interop"

    /* Wt_h09 context:
     *
     */
    typedef enum {
        wt_h09_state_none = 0,
        wt_h09_state_ready,
        wt_h09_state_sent,
        wt_h09_state_sending,
        wt_h09_state_done,
        wt_h09_state_error,
        wt_h09_state_closed,
        wt_h09_state_reset
    } wt_h09_state_enum;


    typedef struct st_wt_h09_app_ctx_t {
        char const* server_dir;
        char const* client_dir;
        char const* requests;
        size_t nb_requests;
        size_t next_request;
        int is_symmetric; /* Control flag: are symmetric requests authorized */

    } wt_h09_app_ctx_t;

    typedef struct st_wt_h09_ctx_t {
        picoquic_cnx_t* cnx;
        int connection_closed;
        char wt_protocol[256];
        wt_h09_state_enum h09_state;
        char const* authority;
        char const* server_path; /* Present if node is serving data */
        char const* download_path; /* present if node is receiving data */
        uint64_t control_stream_id;
        h3zero_stream_ctx_t* control_stream_ctx;
        int is_client;
        h3zero_callback_ctx_t* h3_ctx;
        picowt_capsule_t capsule;
        int connection_ready;
        int app_count;

        char const** requests;
        size_t nb_requests;
        size_t next_request;
        int is_symmetric;
    } wt_h09_ctx_t;

    int wt_h09_callback(picoquic_cnx_t* cnx,
        uint8_t* bytes, size_t length,
        picohttp_call_back_event_t wt_event,
        struct st_h3zero_stream_ctx_t* stream_ctx,
        void* path_app_ctx);

    int wt_h09_ctx_init(wt_h09_ctx_t* h09_ctx, h3zero_callback_ctx_t* h3_ctx,
        struct st_h3zero_stream_ctx_t* stream_ctx, wt_h09_app_ctx_t* app_ctx);

    int wt_h09_prepare_context(picoquic_cnx_t* cnx, wt_h09_ctx_t* h09_ctx,
        h3zero_callback_ctx_t* h3_ctx, h3zero_stream_ctx_t* control_stream_ctx,
        const char* server_name, const char* path);

#ifdef __cplusplus
}
#endif

#endif /* H09_SERVER_H */