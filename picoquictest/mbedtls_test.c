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

#include <stddef.h>
#include <stdint.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic_binlog.h"
#include "csv.h"
#include "qlog.h"
#include "autoqlog.h"
#include "picoquic_logger.h"
#include "performance_log.h"
#include "picoquictest.h"
#include "picoquic_crypto_provider_api.h"
#include <picotls.h>
#if 0
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#endif
#include "picotls/minicrypto.h"

#ifdef PICOQUIC_WITH_MBEDTLS
#include "mbedtls/mbedtls_config.h"
#include "mbedtls/build_info.h"
#include "psa/crypto.h"
#include "psa/crypto_struct.h"
#include "psa/crypto_values.h"
#include "picotls.h"
#include "ptls_mbedtls.h"
#endif
/* Mbedtls test:
 * Use the "flag" option of tls_api_init to only load specified
 * providers -- specifically, do not load openssl, nor "fusion".
 * Then, run a basic connection test, to check that negotiation
 * succeeds.
 * Then, unload the tls api provider and reset the control flag
 * to zero.
 */

static test_api_stream_desc_t test_scenario_mbedtls[] = {
    { 4, 0, 2000, 2000 }
};

int mbedtls_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t target_time = 1000000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x99, 0xbe, 0xd7, 0x15, 0, 0, 0, 0}, 8 };
    int ret = 0;

    picoquic_tls_api_reset(TLS_API_INIT_FLAGS_NO_OPENSSL|TLS_API_INIT_FLAGS_NO_FUSION);

    ret = tls_api_init_ctx_ex2(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid, 8, 0, 0, 1);
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 20000, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_mbedtls, sizeof(test_scenario_mbedtls));
    }

    /* Try to complete the data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, target_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    picoquic_tls_api_reset(0);

    return ret;
}

/* The following test verifies that the MBED TLS library is properly
* mapped to the "picotls" APIs.
 */

#ifdef PICOQUIC_WITH_MBEDTLS
#include "mbedtls/build_info.h"

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
static int test_random();
static int test_hash(ptls_hash_algorithm_t* algo, ptls_hash_algorithm_t* ref);
static int test_label(ptls_hash_algorithm_t* hash, ptls_hash_algorithm_t* ref);
static int test_cipher(ptls_cipher_algorithm_t* cipher, ptls_cipher_algorithm_t* cipher_ref);
static int test_aead(ptls_aead_algorithm_t* algo, ptls_hash_algorithm_t* hash, ptls_aead_algorithm_t* ref, ptls_hash_algorithm_t* hash_ref);
static int test_key_exchange(ptls_key_exchange_algorithm_t* client, ptls_key_exchange_algorithm_t* server);

int mbedtls_crypto_test()
{
    ptls_cipher_algorithm_t* cipher_test[5] = {
        &ptls_mbedtls_aes128ecb,
        &ptls_mbedtls_aes128ctr,
        &ptls_mbedtls_aes256ecb,
        &ptls_mbedtls_aes256ctr,
        &ptls_mbedtls_chacha20
    };
    ptls_cipher_algorithm_t* cipher_ref[5] = {
        &ptls_minicrypto_aes128ecb,
        &ptls_minicrypto_aes128ctr,
        &ptls_minicrypto_aes256ecb,
        &ptls_minicrypto_aes256ctr,
        &ptls_minicrypto_chacha20
    };
    int ret = 0;

    /* Initialize the PSA crypto library. */
    if ((ret = ptls_mbedtls_init()) != 0) {
        DBG_PRINTF("%s", "psa_crypto_init fails.");
    }
    else {
        ret = test_random();
        DBG_PRINTF("test random returns: %d\n", ret);

        if (ret == 0) {
            ret = test_hash(&ptls_mbedtls_sha256, &ptls_minicrypto_sha256);
            DBG_PRINTF("test hash returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_label(&ptls_mbedtls_sha256, &ptls_minicrypto_sha256);
            DBG_PRINTF("test label returns: %d\n", ret);
        }

        if (ret == 0) {
            for (int i = 0; i < 5; i++) {
                if (test_cipher(cipher_test[i], cipher_ref[i]) != 0) {
                    DBG_PRINTF("test cipher %d fails\n", i);
                    ret = -1;
                }
            }
            DBG_PRINTF("test ciphers returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_aead(&ptls_mbedtls_aes128gcm, &ptls_mbedtls_sha256, &ptls_minicrypto_aes128gcm, &ptls_minicrypto_sha256);
            DBG_PRINTF("test aeads returns: %d\n", ret);
        }

        if (ret == 0) {
            ret = test_key_exchange(&ptls_mbedtls_secp256r1, &ptls_minicrypto_secp256r1);
            if (ret != 0) {
                DBG_PRINTF("%s", "test key exchange secp256r1 mbedtls to minicrypto fails\n");
            }
            else {
                ret = test_key_exchange(&ptls_minicrypto_secp256r1, &ptls_mbedtls_secp256r1);
                if (ret != 0) {
                    DBG_PRINTF("%s", "test key exchange secp256r1 minicrypto to mbedtls fails\n");
                }
            }
            ret = test_key_exchange(&ptls_mbedtls_x25519, &ptls_minicrypto_x25519);
            if (ret != 0) {
                DBG_PRINTF("%s", "test key exchange x25519 mbedtls to minicrypto fails\n");
            }
            else {
                ret = test_key_exchange(&ptls_minicrypto_x25519, &ptls_mbedtls_x25519);
                if (ret != 0) {
                    DBG_PRINTF("%s", "test key exchange x25519 minicrypto to mbedtls fails\n");
                }
            }
            DBG_PRINTF("test key exchange returns: %d\n", ret);
        }

        /* Deinitialize the PSA crypto library. */
        ptls_mbedtls_free();
    }
    return (ret == 0) ? 0 : -1;
}

#define PTLS_MBEDTLS_RANDOM_TEST_LENGTH 1021

static int test_random()
{
    /* The random test is just trying to check that we call the API properly. 
    * This is done by getting a vector of 1021 bytes, computing the sum of
    * all values, and comparing to theoretical min and max,
    * computed as average +- 8*standard deviation for sum of 1021 terms.
    * 8 random deviations results in an extremely low probability of random
    * failure.
    * Note that this does not actually test the random generator.
    */

    uint8_t buf[PTLS_MBEDTLS_RANDOM_TEST_LENGTH];
    uint64_t sum = 0;
    const uint64_t max_sum_1021 = 149505;
    const uint64_t min_sum_1021 = 110849;
    int ret = 0;

    ptls_mbedtls_random_bytes(buf, PTLS_MBEDTLS_RANDOM_TEST_LENGTH);
    for (size_t i = 0; i < PTLS_MBEDTLS_RANDOM_TEST_LENGTH; i++) {
        sum += buf[i];
    }
    if (sum > max_sum_1021 || sum < min_sum_1021) {
        ret = -1;
    }

    return ret;
}

static int hash_trial(ptls_hash_algorithm_t* algo, const uint8_t* input, size_t len1, size_t len2, uint8_t* final_hash)
{
    int ret = 0;
    ptls_hash_context_t* hash_ctx = algo->create();

    hash_ctx->update(hash_ctx, input, len1);
    if (len2 > 0) {
        hash_ctx->update(hash_ctx, input + len1, len2);
    }
    hash_ctx->final(hash_ctx, final_hash, PTLS_HASH_FINAL_MODE_FREE);

    return ret;
}

static int hash_reset_trial(ptls_hash_algorithm_t* algo, const uint8_t* input, size_t len1, size_t len2, 
    uint8_t* hash1, uint8_t* hash2)
{
    int ret = 0;
    ptls_hash_context_t* hash_ctx = algo->create();

    hash_ctx->update(hash_ctx, input, len1);
    hash_ctx->final(hash_ctx, hash1, PTLS_HASH_FINAL_MODE_RESET);
    hash_ctx->update(hash_ctx, input + len1, len2);
    hash_ctx->final(hash_ctx, hash2, PTLS_HASH_FINAL_MODE_FREE);

    return ret;
}

static int test_hash(ptls_hash_algorithm_t* algo, ptls_hash_algorithm_t* ref)
{
    int ret = 0;
    uint8_t input[1234];
    uint8_t final_hash[32];
    uint8_t final_ref[32];
    uint8_t hash1[32], hash2[32], href1[32], href2[32];

    memset(input, 0xba, sizeof(input));

    ret = hash_trial(algo, input, sizeof(input), 0, final_hash);
    if (ret == 0) {
        ret = hash_trial(ref, input, sizeof(input), 0, final_ref);
    }
    if (ret == 0) {
        if (memcmp(final_hash, final_ref, ref->digest_size) != 0) {
            ret = -1;
        }
    }
    if (ret == 0) {
        ret = hash_trial(algo, input, sizeof(input) - 17, 17, final_hash);
    }
    if (ret == 0) {
        if (memcmp(final_hash, final_ref, ref->digest_size) != 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = hash_reset_trial(algo, input, sizeof(input) - 126, 126, hash1, hash2);
    }
    if (ret == 0) {
        ret = hash_reset_trial(ref, input, sizeof(input) - 126, 126, href1, href2);
    }
    if (ret == 0) {
        if (memcmp(hash1, href1, ref->digest_size) != 0) {
            ret = -1;
        }
        else if (memcmp(hash2, href2, ref->digest_size) != 0) {
            ret = -1;
        }
    }

    return ret;
}

static int cipher_trial(ptls_cipher_algorithm_t * cipher, const uint8_t * key, const uint8_t * iv, int is_enc, const uint8_t * v_in, uint8_t * v_out1, uint8_t * v_out2, size_t len)
{
    int ret = 0;
    ptls_cipher_context_t* test_cipher = ptls_cipher_new(cipher, is_enc, key);
    if (test_cipher == NULL) {
        ret = -1;
    } else {
        if (test_cipher->do_init != NULL) {
            ptls_cipher_init(test_cipher, iv);
        }
        ptls_cipher_encrypt(test_cipher, v_out1, v_in, len);
        if (test_cipher->do_init != NULL) {
            ptls_cipher_init(test_cipher, iv);
        }
        ptls_cipher_encrypt(test_cipher, v_out2, v_out1, len);
        ptls_cipher_free(test_cipher);
    }

    return ret;
}

static int test_cipher(ptls_cipher_algorithm_t * cipher, ptls_cipher_algorithm_t * cipher_ref)
{
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t v_in[16];
    uint8_t v_out_1a[16], v_out_2a[16], v_out_1b[16], v_out_2b[16], v_out_1d[16], v_out_2d[16];
    int ret = 0;

    /* Set initial values */
    memset(key, 0x55, sizeof(key));
    memset(iv, 0x33, sizeof(iv));
    memset(v_in, 0xaa, sizeof(v_in));

    /* Encryption test */
    ret = cipher_trial(cipher, key, iv, 1, v_in, v_out_1a, v_out_2a, 16);
    if (ret == 0) {
        ret = cipher_trial(cipher_ref, key, iv, 1, v_in, v_out_1b, v_out_2b, 16);
    }
    if (ret == 0) {
        if (memcmp(v_out_1a, v_out_1b, 16) != 0) {
            ret = -1;
        }
        else if (memcmp(v_out_2a, v_out_2b, 16) != 0) {
            ret = -1;
        }
    }
    /* decryption test */
    if (ret == 0) {
        ret = cipher_trial(cipher, key, iv, 0, v_out_2a, v_out_1d, v_out_2d, 16);
    }
    if (ret == 0) {
        if (memcmp(v_out_1a, v_out_1d, 16) != 0) {
            ret = -1;
        }
        else if (memcmp(v_out_2d, v_in, 16) != 0) {
            ret = -1;
        }
    }

    return ret;
}

static int label_test(ptls_hash_algorithm_t * hash, uint8_t * v_out, size_t o_len, const uint8_t * secret,
    char const * label, char const * label_prefix)
{
    uint8_t h_val_v[32];
    ptls_iovec_t h_val = { 0 };
    ptls_iovec_t s_vec = { 0 };
    s_vec.base = (uint8_t *)secret;
    s_vec.len = 32;
    h_val.base = h_val_v;
    h_val.len = 32;
    memset(h_val_v, 0, sizeof(h_val_v));

    ptls_hkdf_expand_label(hash, v_out, o_len, s_vec, label, h_val, label_prefix);
    return 0;
}

static int test_label(ptls_hash_algorithm_t* hash, ptls_hash_algorithm_t* ref)
{
    int ret = 0;
    uint8_t v_out[16], v_ref[16];
    uint8_t secret[32];
    char const* label = "label";
    char const* label_prefix = "label_prefix";
    memset(secret, 0x5e, sizeof(secret));

    ret = label_test(hash, v_out, 16, secret, label, label_prefix);

    if (ret == 0) {
        ret = label_test(ref, v_ref, 16, secret, label, label_prefix);
    }

    if (ret == 0 && memcmp(v_out, v_ref, 16) != 0) {
        ret = -1;
    }

    return ret;
}

static int aead_trial(ptls_aead_algorithm_t * algo, ptls_hash_algorithm_t * hash, const uint8_t * secret, int is_enc, 
    const uint8_t * v_in, size_t len, uint8_t * aad, size_t aad_len, uint64_t seq, uint8_t * v_out, size_t * o_len)
{
    int ret = 0;
    ptls_aead_context_t* aead = ptls_aead_new(algo, hash, is_enc, secret, "test_aead");

    if (aead == NULL) {
        ret = -1;
    }
    else{
        if (is_enc) {
            *o_len = ptls_aead_encrypt(aead, v_out, v_in, len, seq, aad, aad_len);
            if (*o_len != len + algo->tag_size) {
                ret = -1;
            }
        }
        else {
            *o_len = ptls_aead_decrypt(aead, v_out, v_in, len, seq, aad, aad_len);
            if (*o_len != len - algo->tag_size) {
                ret = -1;
            }
        }
        ptls_aead_free(aead);
    }
    return ret;
}

static int test_aead(ptls_aead_algorithm_t* algo, ptls_hash_algorithm_t* hash, ptls_aead_algorithm_t* ref, ptls_hash_algorithm_t* hash_ref)
{
    uint8_t secret[32];
    uint8_t v_in[1234];
    uint8_t aad[17];
    uint8_t v_out_a[1250], v_out_b[1250], v_out_r[1250];
    size_t olen_a, olen_b, olen_r;
    uint64_t seq = 12345;
    int ret = 0;

    memset(secret, 0x58, sizeof(secret));
    memset(v_in, 0x12, sizeof(v_in));
    memset(aad, 0xaa, sizeof(aad));

    ret = aead_trial(algo, hash, secret, 1, v_in, sizeof(v_in), aad, sizeof(aad), seq, v_out_a, &olen_a);
    if (ret == 0) {
        ret = aead_trial(ref, hash_ref, secret, 1, v_in, sizeof(v_in), aad, sizeof(aad), seq, v_out_b, &olen_b);
    }
    if (ret == 0 && (olen_a != olen_b || memcmp(v_out_a, v_out_b, olen_a) != 0)) {
        ret = -1;
    }
    if (ret == 0) {
        ret = aead_trial(ref, hash_ref, secret, 0, v_out_a, olen_a, aad, sizeof(aad), seq, v_out_r, &olen_r);
    }
    if (ret == 0 && (olen_r != sizeof(v_in) || memcmp(v_in, v_out_r, sizeof(v_in)) != 0)) {
        ret = -1;
    }
    return ret;
}

/* Test key exchanges. We copy paste the code from "test.h" in picotls.
* if intergarted with picotls, we should reuse this code.
*/

static int test_key_exchange(ptls_key_exchange_algorithm_t *client, ptls_key_exchange_algorithm_t *server)
{
    ptls_key_exchange_context_t *ctx;
    ptls_iovec_t client_secret, server_pubkey, server_secret;
    int f_ret;
    int ret = 0;

    /* fail */
    if ((f_ret = server->exchange(server, &server_pubkey, &server_secret, (ptls_iovec_t) { NULL })) == 0) {
        ret = -1;
    }
    if (ret == 0) {
        /* perform ecdh */
        ret = client->create(client, &ctx);
        if (ret == 0) {
            ret = server->exchange(server, &server_pubkey, &server_secret, ctx->pubkey);
        }
        if (ret == 0) {
            ret = ctx->on_exchange(&ctx, 1, &client_secret, server_pubkey);
        }
        if (ret == 0) {
            if (client_secret.len != server_secret.len ||
                memcmp(client_secret.base, server_secret.base, client_secret.len) != 0) {
                ret = -1;
            }
        }
    }

    free(client_secret.base);
    free(server_pubkey.base);
    free(server_secret.base);

    if (ret == 0) {
        /* client abort */
        ret = client->create(client, &ctx);
        if (ret == 0) {
            ret = ctx->on_exchange(&ctx, 1, NULL, ptls_iovec_init(NULL, 0));
        }
        if (ctx != NULL) {
            ret = -1;
        }
    }

    return ret;
}


/*
Sign certificate has to implement a callback:

if ((ret = tls->ctx->sign_certificate->cb(
tls->ctx->sign_certificate, tls, tls->is_server ? &tls->server.async_job : NULL, &algo, sendbuf,
ptls_iovec_init(data, datalen), signature_algorithms != NULL ? signature_algorithms->list : NULL,
signature_algorithms != NULL ? signature_algorithms->count : 0)) != 0) {

or:

static int sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
ptls_buffer_t *outbuf, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)

The callback "super" type is ptls_sign_certificate_t, defined by the macro:
PTLS_CALLBACK_TYPE(int, sign_certificate, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
ptls_buffer_t *output, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms);

The notation is simple: input buffer and supported algorithms as input, selected algo and output buffer as output.
Output buffer is already partially filled.

For PSA/MbedTLS, see:
https://mbed-tls.readthedocs.io/en/latest/getting_started/psa/
Using PSA, Signing a message with RSA provides the following sequence:

-- Set key attributes --
psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
psa_set_key_algorithm(&attributes, PSA_ALG_RSA_PKCS1V15_SIGN_RAW);
psa_set_key_type(&attributes, PSA_KEY_TYPE_RSA_KEY_PAIR);
psa_set_key_bits(&attributes, 1024);

-- Import the key --
status = psa_import_key(&attributes, key, key_len, &key_id);
if (status != PSA_SUCCESS) {
printf("Failed to import key\n");
return;
}

-- Sign message using the key --
status = psa_sign_hash(key_id, PSA_ALG_RSA_PKCS1V15_SIGN_RAW,
hash, sizeof(hash),
signature, sizeof(signature),
&signature_length);

TODO: verify that Picotls does compute the hash before calling sign.
TODO: verify that there are "sign raw" implementations for ECDSA, EDDSA

-- Verify hash:
psa_status_t psa_verify_hash(mbedtls_svc_key_id_t key, psa_algorithm_t alg, const uint8_t *hash, size_t hash_length, const uint8_t *signature, size_t signature_length)

Load a key in memory

int mbedtls_pk_parse_keyfile(mbedtls_pk_context* ctx,
const char* path, const char* pwd,
int (*f_rng)(void*, unsigned char*, size_t), void* p_rng);

But before using the psa API, the key must be imported. That means the key has to
be expressed in the proper x509/DER format.

*/
#ifdef _WINDOWS
#ifdef _WINDOWS64
#define ASSET_DIR ..\\..\\data
#define ASSET_RSA_KEY "..\\..\\data\\rsa\\key.pem"
#define ASSET_RSA_PKCS8_KEY "..\\..\\data\\rsa-pkcs8\\key.pem"
#define ASSET_SECP256R1_KEY "..\\..\\data\\secp256r1\\key.pem"
#define ASSET_SECP384R1_KEY "..\\..\\data\\secp384r1\\key.pem"
#define ASSET_SECP521R1_KEY "..\\..\\data\\secp521r1\\key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "..\\..\\data\\secp256r1-pkcs8\\key.pem"
#define ASSET_ED25519_KEY "..\\..\\data\\ed25519\\key.pem"
#else
#define ASSET_DIR ..\\data
#define ASSET_RSA_KEY "..\\data\\rsa\\key.pem"
#define ASSET_RSA_PKCS8_KEY "..\\data\\rsa-pkcs8\\key.pem"
#define ASSET_SECP256R1_KEY "..\\data\\secp256r1\\key.pem"
#define ASSET_SECP384R1_KEY "..\\data\\secp384r1\\key.pem"
#define ASSET_SECP521R1_KEY "..\\data\\secp521r1\\key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "..\\data\\secp256r1-pkcs8\\key.pem"
#define ASSET_ED25519_KEY "..\\data\\ed25519\\key.pem"
#endif
#else
#define ASSET_DIR data
#define ASSET_RSA_KEY "data/rsa/key.pem"
#define ASSET_RSA_PKCS8_KEY "data/rsa-pkcs8/key.pem"
#define ASSET_SECP256R1_KEY "data/secp256r1/key.pem"
#define ASSET_SECP384R1_KEY "data/secp384r1/key.pem"
#define ASSET_SECP521R1_KEY "data/secp521r1/key.pem"
#define ASSET_SECP256R1_PKCS8_KEY "data/secp256r1-pkcs8/key.pem"
#define ASSET_ED25519_KEY "data/ed25519/key.pem"
#endif

static int mbedtls_test_load_one_der_key(char const* path)
{
    int ret = -1;
    unsigned char hash[32];
    const unsigned char h0[32] = {
        1, 2, 3, 4, 5, 6, 7, 8,
        9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31, 32
    };
    ptls_context_t ctx = { 0 };

    ret = ptls_mbedtls_load_private_key(&ctx, path);
    if (ret != 0) {
        printf("Cannot create sign_certificate from: %s\n", path);
    }
    else if (ctx.sign_certificate == NULL) {
        printf("Sign_certificate not set in ptls context for: %s\n", path);
        ret = -1;
    }
    else {
        /* Try to sign something */
        int ret;
        ptls_mbedtls_sign_certificate_t* signer = (ptls_mbedtls_sign_certificate_t*)
            (((unsigned char*)ctx.sign_certificate) - offsetof(struct st_ptls_mbedtls_sign_certificate_t, super));
#if 0
        /* get the key algorithm */
        psa_algorithm_t algo = psa_get_key_algorithm(&signer->attributes);
#endif
        ptls_buffer_t outbuf;
        uint8_t outbuf_smallbuf[256];
        ptls_iovec_t input = { hash, sizeof(hash) };
        uint16_t selected_algorithm = 0;
        int num_algorithms = 0;
        uint16_t algorithms[16];
        memcpy(hash, h0, 32);
        while (signer->schemes[num_algorithms].scheme_id != UINT16_MAX && num_algorithms < 16) {
            algorithms[num_algorithms] = signer->schemes[num_algorithms].scheme_id;
            num_algorithms++;
        }

        ptls_buffer_init(&outbuf, outbuf_smallbuf, sizeof(outbuf_smallbuf));

        ret = ptls_mbedtls_sign_certificate(ctx.sign_certificate, NULL, NULL, &selected_algorithm,
            &outbuf, input, algorithms, num_algorithms);
        if (ret == 0) {
            printf("Signed a message, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
        }
        else {
            printf("Sign failed, key: %s, scheme: %x, signature size: %zu\n", path, selected_algorithm, outbuf.off);
        }
        ptls_buffer_dispose(&outbuf);
        ptls_mbedtls_dispose_sign_certificate(&signer->super);
    }

    return ret;
}

int mbedtls_load_der_test()
{
    int ret = 0;
    if (ret == 0) {
        ret = mbedtls_test_load_one_der_key(ASSET_RSA_KEY);
    }

    if (ret == 0) {
        ret = mbedtls_test_load_one_der_key(ASSET_SECP256R1_KEY);
    }

    if (ret == 0) {
        ret = mbedtls_test_load_one_der_key(ASSET_SECP384R1_KEY);
    }

    if (ret == 0) {
        ret = mbedtls_test_load_one_der_key(ASSET_SECP521R1_KEY);
    }

    if (ret == 0) {
        ret = mbedtls_test_load_one_der_key(ASSET_SECP256R1_PKCS8_KEY);
    }

    if (ret == 0) {
        ret = mbedtls_test_load_one_der_key(ASSET_RSA_PKCS8_KEY);
    }

#if 0
    /* Commenting out ED25519 for now, probably not supported yet in MBEDTLS/PSA */
    if (ret == 0) {
        ret = mbedtls_test_load_one_der_key(ASSET_ED25519_KEY);
    }
#endif

    return ret;
}

#endif
