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

#define PICOQUIC_LABEL_INITIAL_CLIENT "client in"
#define PICOQUIC_LABEL_INITIAL_SERVER "server in"

#define PICOQUIC_LABEL_TRAFFIC_UPDATE "quic ku"
#define PICOQUIC_LABEL_TRAFFIC_UPDATE_23 "traffic upd"

#define PICOQUIC_LABEL_KEY "key"
#define PICOQUIC_LABEL_IV "iv"
#define PICOQUIC_LABEL_HP "hp"
#define PICOQUIC_LABEL_CID "cid"
#define PICOQUIC_LABEL_CID_GLOBAL "cid global"
#define PICOQUIC_LABEL_CID_GLOBAL_ROUNDS 4

#define PICOQUIC_LABEL_QUIC_BASE NULL
#define PICOQUIC_LABEL_QUIC_KEY_BASE "tls13 quic "

int picoquic_master_tlscontext(picoquic_quic_t* quic, char const* cert_file_name, char const* key_file_name,
    char const * cert_root_file_name, const uint8_t* ticket_key, size_t ticket_key_length);

void picoquic_master_tlscontext_free(picoquic_quic_t* quic);

int picoquic_tlscontext_create(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t current_time);

void picoquic_tlscontext_free(void* ctx);

void picoquic_tlscontext_remove_ticket(picoquic_cnx_t* cnx);

int picoquic_tls_stream_process(picoquic_cnx_t* cnx);
int picoquic_is_tls_complete(picoquic_cnx_t* cnx);

int picoquic_initialize_tls_stream(picoquic_cnx_t* cnx, uint64_t current_time);

uint64_t picoquic_get_tls_time(picoquic_quic_t* quic);

void picoquic_crypto_random(picoquic_quic_t* quic, void* buf, size_t len);
uint64_t picoquic_crypto_uniform_random(picoquic_quic_t* quic, uint64_t rnd_max);

uint64_t picoquic_public_random_64(void);
void picoquic_public_random_seed_64(uint64_t seed, int reset);
void picoquic_public_random_seed(picoquic_quic_t* quic);
void picoquic_public_random(void* buf, size_t len);
uint64_t picoquic_public_uniform_random(uint64_t rnd_max);

size_t picoquic_aead_get_checksum_length(void* aead_context);

size_t picoquic_aead_encrypt_generic(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_context);

size_t picoquic_aead_decrypt_generic(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_ctx);

void picoquic_aead_free(void* aead_context);

size_t picoquic_pn_iv_size(void *pn_enc);

void picoquic_pn_encrypt(void *pn_enc, const void * iv, void *output, const void *input, size_t len);

typedef const struct st_ptls_cipher_suite_t ptls_cipher_suite_t;

int picoquic_setup_initial_master_secret(
    ptls_cipher_suite_t * cipher,
    ptls_iovec_t salt,
    picoquic_connection_id_t initial_cnxid,
    uint8_t * master_secret);

int picoquic_setup_initial_secrets(
    ptls_cipher_suite_t * cipher,
    uint8_t * master_secret,
    uint8_t * client_secret,
    uint8_t * server_secret);

int picoquic_setup_initial_traffic_keys(picoquic_cnx_t* cnx);

uint8_t * picoquic_get_app_secret(picoquic_cnx_t* cnx, int is_enc);
size_t picoquic_get_app_secret_size(picoquic_cnx_t* cnx);
int picoquic_compute_new_rotated_keys(picoquic_cnx_t * cnx);
void picoquic_apply_rotated_keys(picoquic_cnx_t * cnx, int is_enc);
int picoquic_rotate_app_secret(ptls_cipher_suite_t * cipher, uint8_t * secret);

void picoquic_crypto_context_free(picoquic_crypto_context_t * ctx);

void * picoquic_setup_test_aead_context(int is_encrypt, const uint8_t * secret);
void * picoquic_pn_enc_create_for_test(const uint8_t * secret);

#if 0
/* TODO: find replacement for this test */
int picoquic_compare_cleartext_aead_contexts(picoquic_cnx_t* cnx1, picoquic_cnx_t* cnx2);
#endif

int picoquic_create_cnxid_reset_secret(picoquic_quic_t* quic, picoquic_connection_id_t * cnx_id,
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE]);

void picoquic_provide_received_transport_extensions(picoquic_cnx_t* cnx,
    uint8_t** ext_received,
    size_t* ext_received_length,
    int* ext_received_return,
    int* client_mode);

char const* picoquic_tls_get_negotiated_alpn(picoquic_cnx_t* cnx);
char const* picoquic_tls_get_sni(picoquic_cnx_t* cnx);

int picoquic_enable_custom_verify_certificate_callback(picoquic_quic_t* quic);

void picoquic_dispose_verify_certificate_callback(picoquic_quic_t* quic, int custom);

void picoquic_tls_set_client_authentication(picoquic_quic_t* quic, int client_authentication);

int picoquic_tls_client_authentication_activated(picoquic_quic_t* quic);

int picoquic_server_decrypt_retry_token(picoquic_quic_t* quic, const struct sockaddr* addr_peer, const uint8_t* token, size_t token_length, uint8_t* text, size_t* text_length);

int picoquic_prepare_retry_token(picoquic_quic_t* quic, const struct sockaddr * addr_peer,
    uint64_t current_time, const picoquic_connection_id_t * odcid, const picoquic_connection_id_t* rcid,
    uint8_t * token, size_t token_max, size_t * token_size);

int picoquic_verify_retry_token(picoquic_quic_t* quic, const struct sockaddr * addr_peer,
    uint64_t current_time, picoquic_connection_id_t * odcid, const picoquic_connection_id_t* rcid,
    const uint8_t * token, size_t token_size, int new_context_created);

void picoquic_cid_free_under_mask_ctx(void * v_pn_enc);
int picoquic_cid_get_under_mask_ctx(void ** v_pn_enc, const void * secret);
void picoquic_cid_encrypt_under_mask(void * cid_enc, const picoquic_connection_id_t * cid_in, const picoquic_connection_id_t * mask, picoquic_connection_id_t * cid_out);
void picoquic_cid_decrypt_under_mask(void * cid_enc, const picoquic_connection_id_t * cid_in, const picoquic_connection_id_t * mask, picoquic_connection_id_t * cid_out);

void picoquic_cid_free_encrypt_global_ctx(void ** v_cid_enc);

int picoquic_esni_load_rr(char const * esni_rr_file_name, uint8_t *esnikeys, size_t esnikeys_max, size_t *esnikeys_len);
struct st_ptls_esni_secret_t * picoquic_esni_secret(picoquic_cnx_t * cnx);

uint16_t picoquic_esni_version(picoquic_cnx_t * cnx);
uint8_t * picoquic_esni_nonce(picoquic_cnx_t * cnx);

/* Define hash functions here so applications don't need to directly interface picotls */
#define PICOQUIC_HASH_SIZE_MAX 64
void * picoquic_hash_create(char const * algorithm_name);
size_t picoquic_hash_get_length(char const* algorithm_name);
void picoquic_hash_update(uint8_t* input, size_t input_length, void* hash_context);
void picoquic_hash_finalize(uint8_t* output, void* hash_context);

/* Special AEAD context definition functions used for stateless retry integrity protection */
void * picoquic_create_retry_protection_context(int is_enc, uint8_t * key);
void * picoquic_find_retry_protection_context(picoquic_cnx_t * cnx, int sending);
void picoquic_delete_retry_protection_contexts(picoquic_quic_t * quic);
size_t picoquic_encode_retry_protection(void * integrity_aead, uint8_t * bytes, size_t bytes_max, size_t byte_index, const picoquic_connection_id_t * odcid);
int picoquic_verify_retry_protection(void * integrity_aead, uint8_t * bytes, size_t * length, size_t byte_index, const picoquic_connection_id_t * odcid);

/* AES ECB function used for CID encryption */
void* picoquic_aes128_ecb_create(int is_enc, const void* ecb_key);

void picoquic_aes128_ecb_free(void* v_aesecb);

void picoquic_aes128_ecb_encrypt(void* v_aesecb, uint8_t* output, const uint8_t* input, size_t len);

#endif /* TLS_API_H */