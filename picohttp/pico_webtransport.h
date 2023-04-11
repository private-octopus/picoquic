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

#ifdef __cplusplus
extern "C" {
#endif

/* Web transport callback API */

/* Web transport initiate, client side
 * cnx: an established QUIC connection, set to ALPN=H3.
 * wt_callback: callback function to use in the web transport connection.
 * wt_ctx: application level context for that connection.
 */
    void picowt_set_transport_parameters(picoquic_cnx_t* cnx);
    int picowt_connect(picoquic_cnx_t* cnx, picohttp_server_stream_ctx_t* stream_ctx, h3zero_stream_prefixes_t* stream_prefixes, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx);

#ifdef __cplusplus
}
#endif

#endif /* PICO_WEBTRANSPORT_H */