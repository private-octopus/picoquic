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

#ifndef PICOQUIC_CRYPTO_PROVIDER_API_H
#define PICOQUIC_CRYPTO_PROVIDER_API_H

#ifdef __cplusplus
extern "C" {
#endif

#define TLS_API_INIT_FLAGS_NO_OPENSSL 1
#define TLS_API_INIT_FLAGS_NO_MINICRYPTO 2
#define TLS_API_INIT_FLAGS_NO_FUSION 4
#define TLS_API_INIT_FLAGS_NO_MBEDTLS 8
    void picoquic_register_ciphersuite(ptls_cipher_suite_t* suite, int is_low_memory);
    void picoquic_register_key_exchange_algorithm(ptls_key_exchange_algorithm_t* key_exchange);

    typedef int (*picoquic_set_tls_key_provider_t)(ptls_context_t* ctx, const uint8_t* data, size_t len);
    typedef uint8_t* (*picoquic_get_private_key_from_file_t)(char const* file_name, int* key_length);
    typedef int (*picoquic_set_private_key_from_file_t)(char const* keypem, ptls_context_t* ctx);
    typedef void (*picoquic_dispose_sign_certificate_t)(ptls_sign_certificate_t* cert);
    typedef ptls_iovec_t* (*picoquic_get_certs_from_file_t)(char const* file_name, size_t* count);
    typedef ptls_verify_certificate_t* (*picoquic_get_certificate_verifier_t)(char const* cert_root_file_name,
        unsigned int* is_cert_store_not_empty);
    typedef void (*picoquic_dispose_certificate_verifier_t)(ptls_verify_certificate_t* verifier);
    typedef int (*picoquic_set_tls_root_certificates_t)(ptls_context_t* ctx, ptls_iovec_t* certs, size_t count);
    typedef int (*picoquic_explain_crypto_error_t)(char const** err_file, int* err_line);
    typedef void (*picoquic_clear_crypto_errors_t)();
    typedef void (*picoquic_set_random_provider_in_ctx_t)(ptls_context_t* ctx);
    typedef void (*picoquic_crypto_random_provider_t)(void *buf, size_t len);

    void picoquic_register_tls_key_provider_fn(
        picoquic_set_private_key_from_file_t set_private_key_from_file_fn,
        picoquic_dispose_sign_certificate_t dispose_sign_certificate_fn,
        picoquic_get_certs_from_file_t get_certs_from_file_fn);

    void picoquic_register_verify_certificate_fn(picoquic_get_certificate_verifier_t certificate_verifier_fn,
        picoquic_dispose_certificate_verifier_t dispose_certificate_verifier_fn,
        picoquic_set_tls_root_certificates_t set_tls_root_certificates_fn);

    void picoquic_register_explain_crypto_error_fn(picoquic_explain_crypto_error_t explain_crypto_error_fn,
        picoquic_clear_crypto_errors_t clear_crypto_errors_fn);

    void picoquic_register_crypto_random_provider_fn(picoquic_crypto_random_provider_t random_provider);

#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_CRYPTO_PROVIDER_API_H */
