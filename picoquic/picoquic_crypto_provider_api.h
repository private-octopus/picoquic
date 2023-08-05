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

    void picoquic_register_ciphersuite(ptls_cipher_suite_t* suite, int is_low_memory);
    void picoquic_register_key_exchange_algorithm(ptls_key_exchange_algorithm_t* key_exchange);

    typedef int (*picoquic_set_tls_key_provider_fn)(ptls_context_t* ctx, const uint8_t* data, size_t len);
    typedef uint8_t* (*picoquic_get_private_key_from_key_file_fn)(char const* file_name, int* key_length);
    typedef int (*picoquic_set_private_key_from_key_file_fn)(char const* keypem, ptls_context_t* ctx);
    void picoquic_register_tls_key_provider_fn(picoquic_set_tls_key_provider_fn set_tls_key_fn,
        picoquic_get_private_key_from_key_file_fn get_key_from_key_file_fn,
        picoquic_set_private_key_from_key_file_fn set_key_from_key_file_fn);

#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_CRYPTO_PROVIDER_API_H */
