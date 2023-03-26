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
#ifndef H3ZERO_COMMON_H
#define H3ZERO_COMMON_H
#ifdef __cplusplus
extern "C" {
#endif

    /* Define the per URL callback used to implement POST and other
    * REST-like interactions
    */
    typedef enum {
        picohttp_callback_get, /* Received a get command */
        picohttp_callback_post, /* Received a post command */
        picohttp_callback_connect, /* Received a connect command */
        picohttp_callback_connect_refused, /* Connection request was refused by peer */
        picohttp_callback_connect_accepted, /* Connection request was accepted by peer */
        picohttp_callback_first_data, /* First data received from peer on stream N */
        picohttp_callback_post_data, /* Data received from peer on stream N */
        picohttp_callback_post_data_unidir, /* Data received from peer on unidir stream N */
        picohttp_callback_post_fin, /* All posted data have been received on this stream */
        picohttp_callback_provide_data, /* Stack is ready to send chunk of data on stream N */
        picohttp_callback_reset /* Stream has been abandoned. */
    } picohttp_call_back_event_t;

    struct st_picohttp_server_stream_ctx_t;

    typedef int (*picohttp_post_data_cb_fn)(picoquic_cnx_t* cnx,
        uint8_t* bytes, size_t length,
        picohttp_call_back_event_t fin_or_event,
        struct st_picohttp_server_stream_ctx_t* stream_ctx,
        void * path_app_ctx);

    /* Handling of stream prefixes, for applications that use it.
     */
    typedef struct st_h3zero_stream_prefix_t {
        struct st_h3zero_stream_prefix_t* next;
        struct st_h3zero_stream_prefix_t* previous;
        uint64_t prefix;
        void* function_call;
        void* function_ctx;
    } h3zero_stream_prefix_t;

    typedef struct st_h3zero_stream_prefixes_t {
        struct st_h3zero_stream_prefix_t* first;
        struct st_h3zero_stream_prefix_t* last;
    } h3zero_stream_prefixes_t;

    int h3zero_declare_stream_prefix(h3zero_stream_prefixes_t * prefixes, uint64_t prefix, void* function_call, void* function_ctx);

    /* Callback management
     */

#ifdef __cplusplus
}
#endif

#endif /* H3ZERO_COMMON_H */