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

#ifndef H09_SERVER_H
#define H09_SERVER_H

#include "h3zero_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Defining then the Http 0.9 variant of the demo server */
#define picoquic_h09_server_callback_ctx_t h3zero_callback_ctx_t

/* define a neutral structure that can be used by WT or by direct calls */
typedef struct st_h09_ctx_t {
    int status;
} h09_ctx_t;

typedef struct st_h09_stream_ctx_t {
    uint64_t stream_id;

} h09_stream_ctx_t;

int picoquic_h09_server_process_data_header(const uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event, h3zero_stream_ctx_t* stream_ctx, size_t* r_processed);

int picoquic_h09_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx);

#ifdef __cplusplus
}
#endif

#endif /* H09_SERVER_H */
