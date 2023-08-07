/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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

/* This module interfaces with the minicrypto libraries. It loads the
* required variables and function pointers so they can be used by picoquic.
*/

#include "picotls.h"
#include "picoquic_crypto_provider_api.h"
#include "picotls/minicrypto.h"


static int set_minicrypto_private_key_from_key_file(char const* keypem, ptls_context_t* ctx)
{
#if 1
    return ptls_minicrypto_load_private_key(ctx, keypem);
#else
    ptls_asn1_pkcs8_private_key_t pkey = {{0}};
    int ret = ptls_pem_parse_private_key(keypem, &pkey, NULL);

    if (ret != 0)
        goto err;
#if 0
    /* Check that this is the expected key type.
    * At this point, the minicrypto library only supports ECDSA keys.
    * In theory, we could add support for RSA keys at some point.
    */
    if (pkey.algorithm_length != sizeof(ptls_asn1_algorithm_ecdsa) ||
        memcmp(pkey.vec.base + pkey.algorithm_index, ptls_asn1_algorithm_ecdsa, sizeof(ptls_asn1_algorithm_ecdsa)) != 0) {
        ret = -1;
        goto err;
    }
#endif

    ret = ptls_set_ecdsa_private_key(ctx, &pkey, NULL);

err:
    if (pkey.vec.base) {
        ptls_clear_memory(pkey.vec.base, pkey.vec.len);
        free(pkey.vec.base);
    }
    return ret;
#endif
}


void picoquic_clear_minicrypto()
{
    /* Nothing for now */
}

void picoquic_init_minicrypto()
{
    /* Nothing for now */
}


/* Register the minicrypto functions
*/
void picoquic_ptls_minicrypto_load(int unload)
{
    if (unload) {
        picoquic_clear_minicrypto();
    }
    else {
        picoquic_init_minicrypto();

        picoquic_register_ciphersuite(&ptls_minicrypto_aes128gcmsha256, 1);
        picoquic_register_ciphersuite(&ptls_minicrypto_aes256gcmsha384, 1);
        picoquic_register_ciphersuite(&ptls_minicrypto_chacha20poly1305sha256, 1);
        picoquic_register_key_exchange_algorithm(&ptls_minicrypto_secp256r1);
        picoquic_register_key_exchange_algorithm(&ptls_minicrypto_x25519);

        picoquic_register_crypto_random_provider_fn(ptls_minicrypto_random_bytes);

        picoquic_register_tls_key_provider_fn(
            set_minicrypto_private_key_from_key_file,
            NULL, NULL);
#if 0
        picoquic_register_verify_certificate_fn(picoquic_openssl_get_certificate_verifier,
            picoquic_openssl_dispose_certificate_verifier,
            picoquic_openssl_set_tls_root_certificates);
        picoquic_register_explain_crypto_error_fn(picoquic_open_ssl_explain_crypto_error,
            picoquic_openssl_clear_crypto_errors);
#endif
    }
}