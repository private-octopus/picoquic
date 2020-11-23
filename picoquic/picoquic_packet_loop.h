/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

#ifndef PICOQUIC_PACKET_LOOP_H
#define PICOQUIC_PACKET_LOOP_H

#include "picosocks.h"
#include "picoquic.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PICOQUIC_PACKET_LOOP_SOCKETS_MAX 2
#define PICOQUIC_PACKET_LOOP_SEND_MAX 10

typedef enum {
    picoquic_packet_loop_ready = 0,
    picoquic_packet_loop_after_receive,
    picoquic_packet_loop_after_send
} picoquic_packet_loop_cb_enum;

typedef int (*picoquic_packet_loop_cb_fn)(picoquic_quic_t * quic, picoquic_packet_loop_cb_enum cb_mode, void * callback_ctx);

int picoquic_packet_loop(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void * loop_callback_ctx);

#ifdef _WINDOWS
int picoquic_packet_loop_win(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx);
#endif

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_PACKET_LOOP_H */