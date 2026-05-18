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

#ifndef PICOQMUX_H
#define PICOQMUX_H

#include "picoquic.h"
#include "picoquic_utils.h"

#ifdef __cplusplus
extern "C" {
#endif

picoquic_quic_t* picoqmux_create(uint32_t max_nb_connections,
    char const* cert_file_name,
    char const* key_file_name,
    char const* cert_root_file_name,
    char const* default_alpn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    uint64_t current_time,
    uint64_t* p_simulated_time,
    char const* ticket_file_name,
    const uint8_t* ticket_encryption_key,
    size_t ticket_encryption_key_length);
int picoqmux_init(picoquic_cnx_t* cnx, int is_cleartext);
picoquic_cnx_t* picoqmux_create_qmux_cnx(picoquic_quic_t* quic, uint64_t current_time,
    int client_mode, int is_cleartext, char const* server, char const* alpn, struct sockaddr * dest);
int picoqmux_prepare_cnx_packets(picoquic_cnx_t* cnx, uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length);
int picoqmux_incoming_cnx_packet(picoquic_cnx_t* cnx, uint64_t current_time,
    const uint8_t* receive_buffer, size_t receive_length);
int picoqmux_has_sent_tp(picoquic_cnx_t* cnx);
int picoqmux_has_received_tp(picoquic_cnx_t* cnx);
void picoqmux_update_state_on_tp_sent(picoquic_cnx_t* cnx);
void picoqmux_update_state_on_tp_received(picoquic_cnx_t* cnx);
int picoqmux_prepare_packets(picoquic_cnx_t* cnx, uint64_t current_time, uint8_t* send_buffer,
    size_t send_buffer_max, size_t* send_length);
int picoqmux_incoming_packets(picoquic_cnx_t* cnx, uint64_t current_time,
    const uint8_t* receive_buffer, size_t receive_length, int is_tcp_closed);

#ifdef __cplusplus
}
#endif
#endif /* PICOQMUX_H */
