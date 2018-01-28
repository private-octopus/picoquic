/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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

#ifndef TLS_API_H
#define TLS_API_H
#include "picoquic_internal.h"

int picoquic_master_tlscontext(picoquic_quic_t* quic, char const* cert_file_name, char const* key_file_name,
    const uint8_t* ticket_key, size_t ticket_key_length);

void picoquic_master_tlscontext_free(picoquic_quic_t* quic);

int picoquic_tlscontext_create(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t current_time);

void picoquic_tlscontext_free(void* ctx);

int picoquic_tlsinput_stream_zero(picoquic_cnx_t* cnx);

int picoquic_initialize_stream_zero(picoquic_cnx_t* cnx);

void picoquic_crypto_random(picoquic_quic_t* quic, void* buf, size_t len);
uint64_t picoquic_crypto_uniform_random(picoquic_quic_t* quic, uint64_t rnd_max);

uint64_t picoquic_public_random_64(void);
void picoquic_public_random_seed(picoquic_quic_t* quic);
void picoquic_public_random(void* buf, size_t len);
uint64_t picoquic_public_uniform_random(uint64_t rnd_max);

int picoquic_setup_0RTT_aead_contexts(picoquic_cnx_t* cnx, int is_server);
int picoquic_setup_1RTT_aead_contexts(picoquic_cnx_t* cnx, int is_server);

size_t picoquic_aead_get_checksum_length(void* aead_context);

size_t picoquic_aead_decrypt(picoquic_cnx_t* cnx, uint8_t* output, uint8_t* input, size_t input_length,
    uint64_t seq_num, uint8_t* auth_data, size_t auth_data_length);

size_t picoquic_aead_encrypt(picoquic_cnx_t* cnx, uint8_t* output, uint8_t* input, size_t input_length,
    uint64_t seq_num, uint8_t* auth_data, size_t auth_data_length);

size_t picoquic_aead_de_encrypt(picoquic_cnx_t* cnx, uint8_t* output, uint8_t* input, size_t input_length,
    uint64_t seq_num, uint8_t* auth_data, size_t auth_data_length);

size_t picoquic_aead_0rtt_encrypt(picoquic_cnx_t* cnx, uint8_t* output, uint8_t* input, size_t input_length,
    uint64_t seq_num, uint8_t* auth_data, size_t auth_data_length);

size_t picoquic_aead_0rtt_decrypt(picoquic_cnx_t* cnx, uint8_t* output, uint8_t* input, size_t input_length,
    uint64_t seq_num, uint8_t* auth_data, size_t auth_data_length);

int picoquic_setup_cleartext_aead_contexts(picoquic_cnx_t* cnx);

size_t picoquic_aead_cleartext_decrypt(picoquic_cnx_t* cnx, uint8_t* output, uint8_t* input,
    size_t input_length, uint64_t seq_num, uint8_t* auth_data, size_t auth_data_length);

size_t picoquic_aead_cleartext_encrypt(picoquic_cnx_t* cnx, uint8_t* output, uint8_t* input,
    size_t input_length, uint64_t seq_num, uint8_t* auth_data, size_t auth_data_length);

size_t picoquic_aead_cleartext_de_encrypt(picoquic_cnx_t* cnx, uint8_t* output, uint8_t* input,
    size_t input_length, uint64_t seq_num, uint8_t* auth_data, size_t auth_data_length);

void picoquic_aead_free(void* aead_context);

int picoquic_create_cnxid_reset_secret(picoquic_quic_t* quic, uint64_t cnx_id,
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE]);

void picoquic_provide_received_transport_extensions(picoquic_cnx_t* cnx,
    uint8_t** ext_received,
    size_t* ext_received_length,
    int* ext_received_return,
    int* client_mode);

char const* picoquic_tls_get_negotiated_alpn(picoquic_cnx_t* cnx);
char const* picoquic_tls_get_sni(picoquic_cnx_t* cnx);

#endif /* TLS_API_H */
