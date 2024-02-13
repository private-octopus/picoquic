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
#include "picoquic_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PICOQUIC_PACKET_LOOP_SOCKETS_MAX 4
#define PICOQUIC_PACKET_LOOP_SEND_MAX 10
#define PICOQUIC_PACKET_LOOP_SEND_DELAY_MAX 2500

typedef struct st_picoquic_socket_ctx_t {
    SOCKET_TYPE fd;
    int af;
    uint16_t port;

    /* Flags */
    unsigned int is_started : 1;
    unsigned int supports_udp_send_coalesced : 1;
    unsigned int supports_udp_recv_coalesced : 1;
    /* Receive data buffer and fields */
    size_t recv_buffer_size;
    uint8_t* recv_buffer;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_dest;
    socklen_t from_length;
    socklen_t dest_length;
    int dest_if;
    unsigned char received_ecn;
    int bytes_recv;
    /* Management of sendmsg */
    char cmsg_buffer[1024];
    size_t udp_coalesced_size;
#ifdef _WINDOWS
    /* Windows specific */
    WSAOVERLAPPED overlap;
    LPFN_WSARECVMSG WSARecvMsg;
    LPFN_WSASENDMSG WSASendMsg;
    WSABUF dataBuf;
    WSAMSG msg;
    int nb_immediate_receive;
    int so_sndbuf;
    int so_rcvbuf;
#endif
} picoquic_socket_ctx_t;

/* The packet loop will call the application back after specific events.
 */
typedef enum {
    picoquic_packet_loop_ready = 0, /* Argument type: packet loop options */
    picoquic_packet_loop_after_receive, /* Argument type size_t*: nb packets received */
    picoquic_packet_loop_after_send, /* Argument type size_t*: nb packets sent */
    picoquic_packet_loop_port_update, /* argument type struct_sockaddr*: new address for wakeup */
    picoquic_packet_loop_time_check, /* argument type packet_loop_time_check_arg_t*. Optional. */
    picoquic_packet_loop_wake_up /* no argument (void* NULL). Used when loop wakeup is supported */
} picoquic_packet_loop_cb_enum;

/* The time check option passes as argument a pointer to a structure specifying
* the current time and the proposed delta. The application uses the specified
* current time to compute an updated delta.
*/
typedef struct st_packet_loop_time_check_arg_t {
    uint64_t current_time;
    int64_t delta_t;
} packet_loop_time_check_arg_t;

typedef int (*picoquic_packet_loop_cb_fn)(picoquic_quic_t * quic, picoquic_packet_loop_cb_enum cb_mode, void * callback_ctx, void * callback_argv);

/* Packet loop option list shows support by application of optional features.
 * It is set to null initially, and then passed to the socket as argument to
 * the "ready" callback. Application should set the flags corresponding to
 * the features that it supports */
typedef struct st_picoquic_packet_loop_options_t {
    int do_time_check : 1; /* App should be polled for next time before sock select */
} picoquic_packet_loop_options_t;

/* Version 2 of packet loop, works in progress.
* Parameters are set in a struct, for future
* extensibility.
 */
typedef struct st_picoquic_packet_loop_param_t {
    uint16_t local_port;
    int local_af;
    int dest_if;
    int socket_buffer_size;
    int do_not_use_gso;
    int extra_socket_required;
    int simulate_eio;
    size_t send_length_max;
} picoquic_packet_loop_param_t;

int picoquic_packet_loop_v2(picoquic_quic_t* quic,
    picoquic_packet_loop_param_t * param,
    picoquic_packet_loop_cb_fn loop_callback,
    void * loop_callback_ctx);

/* Threaded version of packet loop, when running picoquic in a background thread.
* 
* Thread is started by calling picoquic_start_network_thread, which
* returns an argument of type picoquic_network_thread_ctx_t. Returns a NULL
* pointer if the thread could not be created.
* 
* If the application needs to post new data or otherwise interact with
* the quic connections, it should call picoquic_wake_up_network_thread,
* passing the thread context as an argument. This with trigger a
* callback of type `picoquic_packet_loop_wake_up`, which executes
* in the context of the network thread. Picoquic APIs can be called
* in this context without worrying about concurrency issues.
* 
* If the application wants to close the network thread, it calls
* picoquic_close_network_thread, passing the thread context as an argument.
* The network thread context will be freed during that call.
*/

typedef struct st_picoquic_network_thread_ctx_t {
    picoquic_quic_t* quic;
    picoquic_packet_loop_param_t* param;
    picoquic_packet_loop_cb_fn loop_callback;
    void* loop_callback_ctx;
    picoquic_thread_t thread_id;
#ifdef _WINDOWS
    HANDLE wake_up_event;
#else
    int wake_up_pipe_fd[2];
#endif
    int is_threaded;
    int wake_up_defined;
    volatile int thread_should_close;
    int return_code;
} picoquic_network_thread_ctx_t;

picoquic_network_thread_ctx_t* picoquic_start_network_thread(
    picoquic_quic_t* quic,
    picoquic_packet_loop_param_t* param,
    picoquic_packet_loop_cb_fn loop_callback,
    void* loop_callback_ctx,
    int * ret);

int picoquic_wake_up_network_thread(picoquic_network_thread_ctx_t* thread_ctx);
void picoquic_delete_network_thread(picoquic_network_thread_ctx_t* thread_ctx);


/* Legacy versions the packet loop, one portable and one specialized
 * for winsock. Keeping these API for compatibility, but the implementation
 * redirects to picoquic_packet_loop_v2.
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

/* Following declarations are used for unit tests. */
void picoquic_packet_loop_close_socket(picoquic_socket_ctx_t* s_ctx);
int picoquic_packet_loop_open_sockets(uint16_t local_port, int local_af, int socket_buffer_size, int extra_socket_required,
    int do_not_use_gso, picoquic_socket_ctx_t* s_ctx);

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_PACKET_LOOP_H */

