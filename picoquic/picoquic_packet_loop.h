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

/* The packet loop will call the application back after specific events.
 */
typedef enum {
    picoquic_packet_loop_ready = 0, /* Argument type: packet loop options */
    picoquic_packet_loop_after_receive, /* Argument type size_t*: nb packets received */
    picoquic_packet_loop_after_send, /* Argument type size_t*: nb packets sent */
    picoquic_packet_loop_port_update, /* argument type struct_sockaddr*: new address for wakeup */
    picoquic_packet_loop_time_check /* argument type . Optional. */
} picoquic_packet_loop_cb_enum;

typedef int (*picoquic_packet_loop_cb_fn)(picoquic_quic_t * quic, picoquic_packet_loop_cb_enum cb_mode, void * callback_ctx, void * callback_argv);

/* Packet loop option list shows support by application of optional features.
 * It is set to null initially, and then passed to the socket as argument to
 * the "ready" callback. Application should set the flags corresponding to
 * the features that it supports */
typedef struct st_picoquic_packet_loop_options_t {
    int do_time_check : 1; /* App should be polled for next time before sock select */
} picoquic_packet_loop_options_t;

/* The time check option passes as argument a pointer to a structure specifying
 * the current time and the proposed delta. The application uses the specified
 * current time to compute an updated delta.
 */
typedef struct st_packet_loop_time_check_arg_t {
    uint64_t current_time;
    int64_t delta_t;
} packet_loop_time_check_arg_t;

/* Two versions of the packet loop, one portable and one speciailezed
 * for winsock.
 */
int picoquic_packet_loop(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    int socket_buffer_size,
    int do_not_use_gso,
    picoquic_packet_loop_cb_fn loop_callback,
    void * loop_callback_ctx);

#ifdef _WINDOWS
int picoquic_packet_loop_win(picoquic_quic_t* quic,
    int local_port,
    int local_af,
    int dest_if,
    int socket_buffer_size,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx);
#endif

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_PACKET_LOOP_H */