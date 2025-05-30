/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picosocks.h"
#include "tls_api.h"
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <picotls.h>
#ifdef _WINDOWS
#include <picotls\pembase64.h>
#include <picotls\minicrypto.h>
#else
#include <picotls/pembase64.h>
#include <picotls/minicrypto.h>
#endif
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
typedef const struct st_ptls_cipher_suite_t ptls_cipher_suite_t;
#include "picoquic_crypto_provider_api.h"

/* ECH Init.
* For client side usage, we need to build up a list of supported HPKE ciphersuites
* and key exchanges, and then document that in the QUIC context.
* The code is written to work around the const qualifier in
* the typedef of ptls_hpke_cipher_suite_t and ptls_hpke_kem_t
 */

typedef struct st_ptls_hpke_cipher_suite_nc_t {
    ptls_hpke_cipher_suite_id_t id;
    const char* name; /* in form of "<kdf>/<aead>" using the sames specified in IANA HPKE registry */
    ptls_hash_algorithm_t* hash;
    ptls_aead_algorithm_t* aead;
} ptls_hpke_cipher_suite_nc_t;

ptls_hpke_cipher_suite_nc_t ech_hpke_aes128gcmsha256 = {
    .id = {.kdf = PTLS_HPKE_HKDF_SHA256, .aead = PTLS_HPKE_AEAD_AES_128_GCM},
    .name = "HKDF-SHA256/AES-128-GCM",
    .hash = NULL /* sha256 */,
    .aead = NULL /* aes128gcm */ };
ptls_hpke_cipher_suite_nc_t ech_hpke_aes128gcmsha512 = {
    .id = {.kdf = PTLS_HPKE_HKDF_SHA512, .aead = PTLS_HPKE_AEAD_AES_128_GCM},
    .name = "HKDF-SHA512/AES-128-GCM",
    .hash = NULL /*  sha512 */,
    .aead = NULL /* aes128gcm */ };
ptls_hpke_cipher_suite_nc_t ech_hpke_aes256gcmsha384 = {
    .id = {.kdf = PTLS_HPKE_HKDF_SHA384, .aead = PTLS_HPKE_AEAD_AES_256_GCM},
    .name = "HKDF-SHA384/AES-256-GCM",
    .hash = NULL /* sha384 */,
    .aead = NULL /*  aes256gcm */ };
ptls_hpke_cipher_suite_nc_t ech_hpke_chacha20poly1305sha256 = {
    .id = {.kdf = PTLS_HPKE_HKDF_SHA256, .aead = PTLS_HPKE_AEAD_CHACHA20POLY1305},
    .name = "HKDF-SHA256/ChaCha20Poly1305",
    .hash = NULL /* sha256 */,
    .aead = NULL /* chacha20poly1305 */ };
static ptls_hpke_cipher_suite_t *ech_hpke_cipher_suites[5] = { NULL, NULL, NULL, NULL, NULL };

typedef struct st_ptls_hpke_kem_nc_t {
    uint16_t id;
    ptls_key_exchange_algorithm_t* keyex;
    ptls_hash_algorithm_t* hash;
} ptls_hpke_kem_nc_t;

ptls_hpke_kem_nc_t ech_hpke_kem_p256sha256 = { PTLS_HPKE_KEM_P256_SHA256,  NULL /* secp256r1 */,  NULL /* sha256 */ };
ptls_hpke_kem_nc_t ech_hpke_kem_p384sha384 = { PTLS_HPKE_KEM_P384_SHA384,  NULL /* secp384r1 */,  NULL /* sha384  */ };
ptls_hpke_kem_nc_t ech_hpke_kem_x25519sha256 = { PTLS_HPKE_KEM_X25519_SHA256,  NULL /* x25519 */,  NULL /* sha256 */ };
static ptls_hpke_kem_t* ech_hpke_kems[4] = { NULL, NULL, NULL, NULL };

static void ech_configure_ciphers_and_kmems()
{
    /* we need to have an execution time evaluation of which aead, hash and
    * key exchange algorithms are present, then build the tables of
    * cipher suites and key exchange accordingly.
     */
    int nb_ciphers = 0;
    int nb_kems = 0;
    ptls_hash_algorithm_t* x_sha256 = NULL;
    ptls_hash_algorithm_t* x_sha384 = NULL;
    ptls_hash_algorithm_t* x_sha512 = NULL;
    ptls_aead_algorithm_t* x_aes128gcm = NULL;
    ptls_aead_algorithm_t* x_aes256gcm = NULL;
    ptls_aead_algorithm_t* x_chacha_poly = NULL;
    ptls_key_exchange_algorithm_t* x_secp256r1 = NULL;
    ptls_key_exchange_algorithm_t* x_x25519 = NULL;
    ptls_key_exchange_algorithm_t* x_secp384r1 = NULL;
    size_t hash_offset = offsetof(ptls_hpke_cipher_suite_t, hash);
    size_t aead_offset = offsetof(ptls_hpke_cipher_suite_t, aead);
    size_t keyex_offset2 = offsetof(ptls_hpke_kem_t, keyex);
    size_t hash_offset2 = offsetof(ptls_hpke_kem_t, hash);
    ptls_hpke_cipher_suite_t* ech_hpke_cipher_static[4] = {
        (ptls_hpke_cipher_suite_t*)&ech_hpke_aes128gcmsha256,
        (ptls_hpke_cipher_suite_t*)&ech_hpke_aes128gcmsha512,
        (ptls_hpke_cipher_suite_t*)&ech_hpke_aes256gcmsha384,
        (ptls_hpke_cipher_suite_t*)&ech_hpke_chacha20poly1305sha256
    };
    ptls_hpke_kem_t* ech_hpke_kem_static[3] = { 
        (ptls_hpke_kem_t* )&ech_hpke_kem_p256sha256,
        (ptls_hpke_kem_t*) &ech_hpke_kem_p384sha384,
        (ptls_hpke_kem_t*) &ech_hpke_kem_x25519sha256};

    if (picoquic_cipher_suites[0].high_memory_suite == NULL) {
        /* No cipher suite documenetd: this is an indication that
        * the tls api is not initialized.
         */
        picoquic_tls_api_init();
    }

    for (int i = 0; i < PICOQUIC_CIPHER_SUITES_NB_MAX; i++) {
        if (picoquic_cipher_suites[i].high_memory_suite == NULL ||
            picoquic_cipher_suites[i].high_memory_suite->aead == NULL ||
            picoquic_cipher_suites[i].high_memory_suite->hash == NULL) {
            break;
        }
        if (strcmp(picoquic_cipher_suites[i].high_memory_suite->hash->name, "sha256") == 0) {
            x_sha256 = picoquic_cipher_suites[i].high_memory_suite->hash;
        }
        else if (strcmp(picoquic_cipher_suites[i].high_memory_suite->hash->name, "sha384") == 0) {
            x_sha384 = picoquic_cipher_suites[i].high_memory_suite->hash;
        }
        else if (strcmp(picoquic_cipher_suites[i].high_memory_suite->hash->name, "sha512") == 0) {
            x_sha512 = picoquic_cipher_suites[i].high_memory_suite->hash;
        }

        if (strcmp(picoquic_cipher_suites[i].high_memory_suite->aead->name, "AES128-GCM") == 0) {
            x_aes128gcm = picoquic_cipher_suites[i].high_memory_suite->aead;
        }
        else if (strcmp(picoquic_cipher_suites[i].high_memory_suite->aead->name, "AES256-GCM") == 0) {
            x_aes256gcm = picoquic_cipher_suites[i].high_memory_suite->aead;
        }
        else if (strcmp(picoquic_cipher_suites[i].high_memory_suite->aead->name, "CHACHA20-POLY1305") == 0) {
            x_chacha_poly = picoquic_cipher_suites[i].high_memory_suite->aead;
        }
    }

    for (int i = 0; i < PICOQUIC_KEY_EXCHANGES_NB_MAX; i++) {
        if (picoquic_key_exchanges[i] == NULL) {
            break;
        }
        if (strcmp(picoquic_key_exchanges[i]->name, "secp256r1") == 0) {
            x_secp256r1 = picoquic_key_exchanges[i];
        }
        else if (strcmp(picoquic_key_exchanges[i]->name, "x25519") == 0) {
            x_x25519 = picoquic_key_exchanges[i];
        }
        else if (strcmp(picoquic_key_exchanges[i]->name, "secp384r1") == 0) {
            x_secp384r1 = picoquic_key_exchanges[i];
        }
    }

    /* Using offset and recasting to work around const declaration of ptls_hpke_cipher_suite_t */
    *(ptls_hash_algorithm_t**)(((uint8_t*)&ech_hpke_aes128gcmsha256) + hash_offset) = x_sha256;
    *(ptls_hash_algorithm_t**)(((uint8_t*)&ech_hpke_aes128gcmsha512) + hash_offset) = x_sha512;
    *(ptls_hash_algorithm_t**)(((uint8_t*)&ech_hpke_aes256gcmsha384) + hash_offset) = x_sha384;
    *(ptls_hash_algorithm_t**)(((uint8_t*)&ech_hpke_chacha20poly1305sha256) + hash_offset) = x_sha256;
    *(ptls_aead_algorithm_t**)(((uint8_t*)&ech_hpke_aes128gcmsha256) + aead_offset) = x_aes128gcm;
    *(ptls_aead_algorithm_t**)(((uint8_t*)&ech_hpke_aes128gcmsha512) + aead_offset) = x_aes128gcm;
    *(ptls_aead_algorithm_t**)(((uint8_t*)&ech_hpke_aes256gcmsha384) + aead_offset) = x_aes256gcm;
    *(ptls_aead_algorithm_t**)(((uint8_t*)&ech_hpke_chacha20poly1305sha256) + aead_offset) = x_chacha_poly;

    /* Using offset and recasting to work around const declaration of ptls_hpke_cipher_suite_t */
    *(ptls_hash_algorithm_t**)(((uint8_t*)&ech_hpke_kem_p256sha256) + hash_offset2) = x_sha256;
    *(ptls_hash_algorithm_t**)(((uint8_t*)&ech_hpke_kem_p384sha384) + hash_offset2) = x_sha384;
    *(ptls_hash_algorithm_t**)(((uint8_t*)&ech_hpke_kem_x25519sha256) + hash_offset2) = x_sha256;
    *(ptls_key_exchange_algorithm_t**)(((uint8_t*)&ech_hpke_kem_p256sha256) + keyex_offset2) = x_secp256r1;
    *(ptls_key_exchange_algorithm_t**)(((uint8_t*)&ech_hpke_kem_p384sha384) + keyex_offset2) = x_secp384r1;
    *(ptls_key_exchange_algorithm_t**)(((uint8_t*)&ech_hpke_kem_x25519sha256) + keyex_offset2) = x_x25519;

    for (int i = 0; i < 4; i++) {
        if (ech_hpke_cipher_static[i]->hash != NULL &&
            ech_hpke_cipher_static[i]->aead != NULL) {
            ech_hpke_cipher_suites[nb_ciphers] = ech_hpke_cipher_static[i];
            nb_ciphers++;
        }
    }
    for (int i = 0; i < 3; i++) {
        if (ech_hpke_kem_static[i]->hash != NULL &&
            ech_hpke_kem_static[i]->keyex != NULL) {
            ech_hpke_kems[nb_kems] = ech_hpke_kem_static[i];
            nb_kems++;
        }
    }
}

/* Read the configuration file.
* We assume that it exactly one config, in base 64 encoding. 
 */

int picoquic_ech_read_config(ptls_buffer_t * config, char const * config_file_name)
{
    int ret = 0;
    char buffer[1024];
    FILE* F = picoquic_file_open(config_file_name, "r");
    if (F == NULL) {
        ret = -1;
    }
    else {
        ptls_base64_decode_state_t d_state;
        ptls_base64_decode_init(&d_state);
        while (fgets(buffer, sizeof(buffer), F) != NULL) {
            ret = ptls_base64_decode(buffer, &d_state, config);
        }
        if (d_state.status == PTLS_BASE64_DECODE_DONE || (d_state.status == PTLS_BASE64_DECODE_IN_PROGRESS && d_state.nbc == 0)) {
            ret = 0;
        }
        else {
            ret = PTLS_ERROR_INCORRECT_BASE64;
        }
        F=picoquic_file_close(F);
    }
    return ret;
}

/*
* The ECH extension in TLS is defined as:
*       enum { outer(0), inner(1) } ECHClientHelloType;
*
*       struct {
*          ECHClientHelloType type;
*          select (ECHClientHello.type) {
*              case outer:
*                  HpkeSymmetricCipherSuite cipher_suite;
*                  uint8 config_id;
*                  opaque enc<0..2^16-1>;
*                  opaque payload<1..2^16-1>;
*              case inner:
*                  Empty;
*          };
*       } ECHClientHello;
* 
* On the server side, picotls decode the "cipher_suite" and "config_id"
* parameters, and the "enc" prefix, and then call the "create_opener"
* callback, documented in the PTLS context as ech.server.create_opener.
* 
* It is called as: 
* tls->ech.aead = tls->ctx->ech.server.create_opener->cb(
*                     tls->ctx->ech.server.create_opener, &tls->ech.kem, &tls->ech.cipher, tls, ch->ech.config_id,
*                     ch->ech.cipher_suite, ch->ech.enc, ptls_iovec_init(ech_info_prefix, sizeof(ech_info_prefix)))
* 
* The opener signature is:
* 
* ptls_aead_context_t* ech_opener_callback(ptls_ech_create_opener_t * self,
*     ptls_hpke_kem_t** kem, ptls_hpke_cipher_suite_t** cipher, ptls_t* tls, 
*    uint8_t config_id, ptls_hpke_cipher_suite_id_t cipher_id, ptls_iovec_t enc, ptls_iovec_t info_prefix)
* 
* with the following parameters:
* 
* - "self" points to the "callback" structure documented in the 
* ptls context as ech.server.create_opener. Its first member is the "cb" pointer
* to the function, followed by implementation specific parameters.
* - "kem" and "cipher" are output parameters, to be set by the callback.
* - "tls" is the ptls context
* - "config_id" and "cipher_id" are decoded from the "config_id" and "cipher_suite"
*   parameters of the ECH extension in the client hello
* - "enc" points to the content of the "enc" field of the ECH extension, i.e.,
*   the HPKE encapsulated key.
* - "info_prefix" points to the constant used when deriving the ECH keys -- in the
*   current code, this is set to "tls ech".
*
* The callback should find a configuration that matches the config_id, then
* perform the specified key exchange and derive the aead key used to encrypt
* the payload.
*
* TODO:
 * ECH: creates the AEAD context to be used for "Open"-ing inner CH. Given `config_id`, the callback looks up the ECH config and the
 * corresponding private key, invokes `ptls_hpke_setup_base_r` with provided `cipher`, `enc`, and `info_prefix` (which will be
 * "tls ech" || 00).
 * 
 * SetupBaseR function of RFC 9180. Given `kem`, `algo`, `info`, receiver's private key (`keyex`), and the esnder's public key,
 * returns the AEAD context to be used for decrypting data.
 *
int ptls_hpke_setup_base_r(ptls_hpke_kem_t* kem, ptls_hpke_cipher_suite_t* cipher, ptls_key_exchange_context_t* keyex,
    ptls_aead_context_t** ctx, ptls_iovec_t pk_s, ptls_iovec_t info);
 *
PTLS_CALLBACK_TYPE(ptls_aead_context_t*, ech_create_opener, ptls_hpke_kem_t** kem, ptls_hpke_cipher_suite_t** cipher, ptls_t* tls,
    uint8_t config_id, ptls_hpke_cipher_suite_id_t cipher_id, ptls_iovec_t enc, ptls_iovec_t info_prefix);
* 
*/

typedef struct st_ech_opener_callback_t {
    ptls_ech_create_opener_t super;
    ptls_hpke_kem_t* kem;
    ptls_key_exchange_context_t* keyex;
    ptls_buffer_t config;
} ech_opener_callback_t;


/* Find the config based on the config ID */
/* Perform the key exchange using the public key provided by the client
 * in the "enc" parameter and the private key corresponding to the config ID */
ptls_aead_context_t* ech_opener_callback(ptls_ech_create_opener_t * cb,
    ptls_hpke_kem_t** p_kem, ptls_hpke_cipher_suite_t** cipher, ptls_t* tls, 
    uint8_t config_id, ptls_hpke_cipher_suite_id_t cipher_id, ptls_iovec_t enc, ptls_iovec_t info_prefix)
{
    ptls_aead_context_t* aead = NULL;
    ptls_buffer_t infobuf;
    int ret = 0;
    ech_opener_callback_t* ech_cb = (ech_opener_callback_t*)cb;

    *cipher = NULL;
    for (size_t i = 0; ech_hpke_cipher_suites[i] != NULL; ++i) {
        if (ech_hpke_cipher_suites[i]->id.kdf == cipher_id.kdf &&
            ech_hpke_cipher_suites[i]->id.aead == cipher_id.aead) {
            *cipher = ech_hpke_cipher_suites[i];
            break;
        }
    }
    if (*cipher == NULL)
        return NULL;
    *p_kem = ech_cb->kem;

    /* Compose the "info" field by combining the "info_prefix" and the selected configuration.
    * In the unit test example, the binary string is preceded by a two bytes of length, with
    * an added null byte at the end.
    */


    ptls_buffer_init(&infobuf, "", 0);
    ptls_buffer_pushv(&infobuf, info_prefix.base, info_prefix.len);
    ptls_buffer_pushv(&infobuf, ech_cb->config.base+2, ech_cb->config.off - 2);
    ret = ptls_hpke_setup_base_r(ech_cb->kem, *cipher, ech_cb->keyex, &aead, enc,
        ptls_iovec_init(infobuf.base, infobuf.off));
Exit:
    ptls_buffer_dispose(&infobuf);
    return aead;
}

/* Dispose of the ech callback. */
static void ech_dispose_opener_callback(ech_opener_callback_t* ech_cb)
{

    if (picoquic_keyex_dispose_fn != NULL && ech_cb->keyex != NULL) {
        picoquic_keyex_dispose_fn(ech_cb->keyex);
    }
    memset(ech_cb, 0, sizeof(ech_opener_callback_t));
    free(ech_cb);
}

/* Initialize the opener structure */
static int ech_init_opener_callback(ech_opener_callback_t** p_ech_cb, char const * private_key_file, char const* config_file_name)
{
    int ret = 0;
    /* Allocate an opener callback */
    ech_opener_callback_t* ech_cb = (ech_opener_callback_t*)malloc(sizeof(ech_opener_callback_t));
    if (ech_cb == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memset(ech_cb, 0, sizeof(ech_opener_callback_t));
        /* set the callback */
        ech_cb->super.cb = ech_opener_callback;
        /* Reserve 2 bytes for length of list of config. */
        ptls_buffer_init(&ech_cb->config, "\x00\x00", 2);
        ech_cb->config.off = 2;
        /* Read the config bytes into the ech_cb->config buffer */
        ret = picoquic_ech_read_config(&ech_cb->config, config_file_name);
        if (ret == 0) {
            uint16_t kem_id;
            uint16_t list_of_config_length = (uint16_t)(ech_cb->config.off - 2);
            ech_cb->config.base[0] = (uint8_t)((list_of_config_length >> 8) & 0xff);
            ech_cb->config.base[1] = (uint8_t)(list_of_config_length & 0xff);
            /* Get kem-id from config, then get kem from kem_id */
            kem_id = (((uint16_t)ech_cb->config.base[7]) << 8) + ech_cb->config.base[8];
            for (int i = 0; i < 4 && ech_hpke_kems[i] !=  NULL; i++) {
                if (ech_hpke_kems[i]->id == kem_id) {
                    ech_cb->kem = ech_hpke_kems[i];
                    break;
                }
            }
            if (ech_cb->kem == NULL || picoquic_keyex_from_key_file_fn == NULL) {
                ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            }
            else {
                ret = picoquic_keyex_from_key_file_fn(&ech_cb->keyex, private_key_file);
            }
        }
        if (ret != 0) {
            ech_dispose_opener_callback(ech_cb);
            ech_cb = NULL;
        }
    }
    *p_ech_cb = ech_cb;
    return ret;
}

/* Configure a QUIC context for ECH
*
* For the client, document parameters in ech.client:
*    ech.client.ciphers: list of HPKE symmetric cipher-suites (set to NULL to disable ECH altogether)
*    ech.client.kems: list of supported key exchanges.
* For the server, document:
*    ech.server.create_opener: the ECH "opener" callback function, which
*        does ECDH key exchange and returns the AEAD context.
*    ech.server.retry_configs: ECHConfigList to be sent to the client when
*        there is mismatch (or when the client sends a grease)

* - On the client side, the configuration depends from the capabilities of
*   the local crypto provider. This list is created dynamically by a call to
*   'ech_init'.
* - For the server, we need to document the ECH configuration and to create
*   a callback based on the ECH private key.
* We assume here that there will be just one ECH configuration for the server.
* We copy this configuration in the ECH callback buffer, and we add a pointer
* to it in ech.server.retry_configs.
*/

/* Compute the list of ECH cipher suites and key management methods
 * available based on compile options and TLS init parameters
 */
void picoquic_ech_init()
{
    static int is_ech_init = 0;

    if (!is_ech_init) {
        ech_configure_ciphers_and_kmems();
        is_ech_init = 1;
    }
}

/* Configure a QUIC context to support ECH.
 * used for ECH and the supported ECH configuration.
 */
int picoquic_ech_configure_quic_ctx(picoquic_quic_t * quic, char const* private_key_file, char const* config_file_name)
{
    int ret = 0;
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    ctx->ech.client.ciphers = ech_hpke_cipher_suites;
    ctx->ech.client.kems = ech_hpke_kems;
    if (private_key_file != NULL) {
        ech_opener_callback_t* ech_cb = NULL;
        if ((ret = ech_init_opener_callback(&ech_cb, private_key_file, config_file_name)) == 0) {
            ctx->ech.server.create_opener = &ech_cb->super;
            ctx->ech.server.retry_configs.base = ech_cb->config.base;
            ctx->ech.server.retry_configs.len = ech_cb->config.off;
        }
    }
    return ret;
}

/* The call to ech_release_quic_ctx releases the allocations done by the
* call to ech_configure_quic_ctx. It should be used when deleting the quic context.
* It can be safely used even if there was no call to ech_configure_quic_ctx.
 */

void picoquic_release_quic_ech_ctx(picoquic_quic_t* quic)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    ech_opener_callback_t* ech_cb = (ech_opener_callback_t*)ctx->ech.server.create_opener;
    ctx->ech.server.retry_configs.base = NULL;
    ctx->ech.server.retry_configs.len = 0;

    if (ech_cb != NULL) {
        ech_dispose_opener_callback(ech_cb);
    }
}

/* Configure a tls connection context on the client side:
* We need to document the client handshake properties
* "ech.configs" with a list of server configurations (HTTPS records.)
*/
void picoquic_ech_configure_client(picoquic_cnx_t* cnx, ptls_iovec_t configs)
{
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    tls_ctx->handshake_properties.client.ech.configs = configs;
}

/* Check whether the ech handshake succeeded.
 */
int picoquic_is_ech_handshake(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    return ptls_is_ech_handshake(tls_ctx->tls, NULL, NULL, NULL);
}
