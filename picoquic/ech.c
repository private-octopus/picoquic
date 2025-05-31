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

/* Read the configuration file.
* We assume that it contains exactly one config, in base 64 encoding. 
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
        if (ret == 0) {
            DBG_PRINTF("Got %zu bytes from %s", config->off, config_file_name);
        }
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
    for (size_t i = 0; picoquic_hpke_cipher_suites[i] != NULL; ++i) {
        if (picoquic_hpke_cipher_suites[i]->id.kdf == cipher_id.kdf &&
            picoquic_hpke_cipher_suites[i]->id.aead == cipher_id.aead) {
            *cipher = picoquic_hpke_cipher_suites[i];
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
    ptls_buffer_dispose(&ech_cb->config);
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
        DBG_PRINTF("Cannot allocate callback memory (%zu bytes)", sizeof(ech_opener_callback_t));
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memset(ech_cb, 0, sizeof(ech_opener_callback_t));
        /* set the callback */
        ech_cb->super.cb = ech_opener_callback;
        ptls_buffer_init(&ech_cb->config, "", 0);
        /* Read the config bytes into the ech_cb->config buffer */
        ret = picoquic_ech_read_config(&ech_cb->config, config_file_name);
        if (ret != 0) {
            DBG_PRINTF("Cannot read ech configuration from %s", config_file_name);
        } else {
            uint16_t kem_id;
            /* Get kem-id from config, then get kem from kem_id */
            kem_id = (((uint16_t)ech_cb->config.base[7]) << 8) + ech_cb->config.base[8];
            for (int i = 0; i < 4 && picoquic_hpke_kems[i] !=  NULL; i++) {
                if (picoquic_hpke_kems[i]->id == kem_id) {
                    ech_cb->kem = picoquic_hpke_kems[i];
                    break;
                }
            }
            if (ech_cb->kem == NULL){
                DBG_PRINTF("Cannot find hpke kwm for code 0x%04x", kem_id);
                ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            }
            else if (picoquic_keyex_from_key_file_fn == NULL) {
                DBG_PRINTF("%s", "Cannot find picoquic_keyex_from_key_file_fn");
                ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            }
            else {
                ret = picoquic_keyex_from_key_file_fn(&ech_cb->keyex, private_key_file);
                if (ret != 0) {
                    DBG_PRINTF("picoquic_keyex_from_key_file_fn fails, ret= %d(0x%x)", ret, ret);
                }
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
* For both clients and servers, document:
*    ech.client.ciphers: list of HPKE symmetric cipher-suites (set to NULL to disable ECH altogether)
*    ech.client.kems: list of supported key exchanges.
*    (these lists are initialized during the initialization of the TLS API.)
* For the server, document:
*    ech.server.create_opener: the ECH "opener" callback function, which
*        does ECDH key exchange and returns the AEAD context.
*    ech.server.retry_configs: ECHConfigList to be sent to the client when
*        there is mismatch (or when the client sends a grease)
* We assume here that there will be just one ECH configuration for the server.
* We copy this configuration in the ECH callback buffer, and we add a pointer
* to it in ech.server.retry_configs.
*/
int picoquic_ech_configure_quic_ctx(picoquic_quic_t * quic, char const* private_key_file, char const* config_file_name)
{
    int ret = 0;
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    picoquic_release_quic_ech_ctx(quic);
    ctx->ech.client.ciphers = picoquic_hpke_cipher_suites;
    ctx->ech.client.kems = picoquic_hpke_kems;
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
* 
* This is performed automatically when deleting a quic context in "picoquic_free"
 */

void picoquic_release_quic_ech_ctx(picoquic_quic_t* quic)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    if (ctx != NULL) {
        ech_opener_callback_t* ech_cb = (ech_opener_callback_t*)ctx->ech.server.create_opener;
        ctx->ech.server.retry_configs.base = NULL;
        ctx->ech.server.retry_configs.len = 0;

        if (ech_cb != NULL) {
            ech_dispose_opener_callback(ech_cb);
        }
    }
}

/* Configure a tls connection context on the client side:
* We need to document the client handshake properties
* "ech.configs" with a list of server configurations (HTTPS records.)
* This data will be freed when deleted the tls_ctx for the connection.
*/
int picoquic_ech_configure_client(picoquic_cnx_t* cnx, uint8_t * config_data, size_t config_length)
{
    int ret = 0;
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    tls_ctx->handshake_properties.client.ech.configs.base = (uint8_t*)malloc(config_length);
    if (tls_ctx->handshake_properties.client.ech.configs.base == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memcpy(tls_ctx->handshake_properties.client.ech.configs.base, config_data, config_length);
        tls_ctx->handshake_properties.client.ech.configs.len = config_length;
    }
    return ret;
}

/* Check whether the ech handshake succeeded.
 */
int picoquic_is_ech_handshake(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    return ptls_is_ech_handshake(tls_ctx->tls, NULL, NULL, NULL);
}
