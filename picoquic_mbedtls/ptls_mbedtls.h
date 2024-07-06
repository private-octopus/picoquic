/*
* Copyright (c) 2023, Christian Huitema
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to
* deal in the Software without restriction, including without limitation the
* rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
* sell copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
* IN THE SOFTWARE.
*/
#ifndef picotls_mbedtls_h
#define picotls_mbedtls_h

#ifdef __cplusplus
extern "C" {
#endif
#include "picotls.h"
#include "psa/crypto.h"
#include "mbedtls/x509_crt.h"

extern ptls_hash_algorithm_t ptls_mbedtls_sha256;
extern ptls_hash_algorithm_t ptls_mbedtls_sha512;
#if defined(MBEDTLS_SHA384_C)
extern ptls_hash_algorithm_t ptls_mbedtls_sha384;
#endif

extern ptls_cipher_algorithm_t ptls_mbedtls_aes128ecb;
extern ptls_cipher_algorithm_t ptls_mbedtls_aes256ecb;
extern ptls_cipher_algorithm_t ptls_mbedtls_aes128ctr;
extern ptls_cipher_algorithm_t ptls_mbedtls_aes256ctr;
extern ptls_cipher_algorithm_t ptls_mbedtls_chacha20;

extern ptls_aead_algorithm_t ptls_mbedtls_aes128gcm;
extern ptls_aead_algorithm_t ptls_mbedtls_aes256gcm;
extern ptls_aead_algorithm_t ptls_mbedtls_chacha20poly1305;

extern ptls_cipher_suite_t ptls_mbedtls_aes128gcmsha256;
extern ptls_cipher_suite_t ptls_mbedtls_aes256gcmsha384;
extern ptls_cipher_suite_t ptls_mbedtls_chacha20poly1305sha256;

extern ptls_key_exchange_algorithm_t ptls_mbedtls_secp256r1;
extern ptls_key_exchange_algorithm_t ptls_mbedtls_x25519;

int ptls_mbedtls_init();
void ptls_mbedtls_free();
void ptls_mbedtls_random_bytes(void* buf, size_t len);

typedef struct st_ptls_mbedtls_signature_scheme_t {
    uint16_t scheme_id;
    psa_algorithm_t hash_algo;
} ptls_mbedtls_signature_scheme_t;

typedef struct st_ptls_mbedtls_sign_certificate_t {
    ptls_sign_certificate_t super;
    mbedtls_svc_key_id_t key_id;
    psa_key_attributes_t attributes;
    const ptls_mbedtls_signature_scheme_t * schemes;
} ptls_mbedtls_sign_certificate_t;

typedef struct st_ptls_mbedtls_certificate_t {
    ptls_verify_certificate_t super;
    mbedtls_x509_crt *trust_ca;
    mbedtls_x509_crl *trust_crl;
    int (*f_vrfy)(void*, mbedtls_x509_crt*, int, uint32_t*);
    void* p_vrfy;
} ptls_mbedtls_verify_certificate_t;

typedef struct st_mbedtls_message_verify_ctx_t {
    psa_key_id_t key_id;
} mbedtls_message_verify_ctx_t;

int ptls_mbedtls_load_private_key(ptls_context_t* ctx, char const* pem_fname);
void ptls_mbedtls_dispose_sign_certificate(ptls_sign_certificate_t* _self);
int ptls_mbedtls_sign_certificate(ptls_sign_certificate_t* _self, ptls_t* tls, ptls_async_job_t** async,
    uint16_t* selected_algorithm, ptls_buffer_t* outbuf, ptls_iovec_t input,
    const uint16_t* algorithms, size_t num_algorithms);

int picoquic_mbedtls_get_certs_from_file(char const* pem_fname, ptls_iovec_t** vec, size_t* count);


int ptls_mbedtls_init_verify_certificate(ptls_context_t* ptls_ctx, char const* pem_fname);
void ptls_mbedtls_dispose_verify_certificate(ptls_context_t* ptls_ctx);

int ptls_mbedtls_load_file(char const* file_name, unsigned char** buf, size_t* n);

#ifdef __cplusplus
}
#endif
#endif /* picotls_mbedtls_h */