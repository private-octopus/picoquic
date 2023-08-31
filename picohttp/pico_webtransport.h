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

#ifndef pico_webtransport_H
#define pico_webtransport_H

#include "h3zero_common.h"

#ifdef __cplusplus
extern "C" {
#endif

    /* Set required transport parameters for web transport  */
    void picowt_set_transport_parameters(picoquic_cnx_t* cnx);
    /* Web transport initiate, client side
     * cnx: an established QUIC connection, set to ALPN=H3.
     * wt_callback: callback function to use in the web transport connection.
     * wt_ctx: application level context for that connection.
     */
    int picowt_connect(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx, picohttp_server_stream_ctx_t* stream_ctx, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx);
    /* Send capsule to close web transport session,
     * and close web transport control stream.
     */
    int picowt_send_close_session_message(picoquic_cnx_t* cnx, picohttp_server_stream_ctx_t* control_stream_ctx, uint32_t picowt_err, const char* err_msg);

    /* accumulate data for the web transport capsule in
     * specified context.
     */
    typedef struct st_picowt_capsule_t {
        h3zero_capsule_t h3_capsule;
        uint32_t error_code;
        const uint8_t* error_msg;
        size_t error_msg_len;
    } picowt_capsule_t;

    int picowt_receive_capsule(picoquic_cnx_t *cnx, const uint8_t* bytes, const uint8_t* bytes_max, picowt_capsule_t* capsule);
    void picowt_release_capsule(picowt_capsule_t* capsule);
#ifdef __cplusplus
}
#endif
#endif /* PICO_WEBTRANSPORT_H */