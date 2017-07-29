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
#include "picoquic.h"

int picoquic_master_tlscontext(picoquic_quic * quic, char * cert_file_name, char * key_file_name);

void picoquic_master_tlscontext_free(picoquic_quic * quic);

int picoquic_tlscontext_create(picoquic_quic * quic, picoquic_cnx * cnx);

void picoquic_tlscontext_free(void * ctx);

int picoquic_tlsinput_stream_zero(picoquic_cnx * cnx);

int picoquic_initialize_stream_zero(picoquic_cnx * cnx);

void picoquic_crypto_random(picoquic_quic * quic, void * buf, size_t len);

int picoquic_setup_1RTT_aead_contexts(picoquic_cnx * cnx, int is_server);

size_t picoquic_aead_decrypt(picoquic_cnx *cnx, uint8_t * output, uint8_t * input, size_t input_length,
    uint64_t seq_num, uint8_t * auth_data, size_t auth_data_length);

size_t picoquic_aead_encrypt(picoquic_cnx *cnx, uint8_t * output, uint8_t * input, size_t input_length,
    uint64_t seq_num, uint8_t * auth_data, size_t auth_data_length);

void picoquic_aead_free(void* aead_context);

#endif /* TLS_API_H */
