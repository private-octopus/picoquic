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
#include <picotls\asn1.h>
#else
#include <picotls/pembase64.h>
#include <picotls/minicrypto.h>
#include <picotls/asn1.h>
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

/* The key is expected to be read from a PEM file. The ASN1 syntax of a sec256r1
* public key is:
*   Sequence { (sequence type = 0x30)
*      Sequence {  (sequence type = 0x30)
*          Object_ID { (ASN1 type = 0x06)
*             identifier of the algorithm -- 2a:86:48:ce:3d:02:01
*          }
*          Object_ID { (ASN1 type = 0x06)
*             identifier of the curve -- 2a:86:48:ce:3d:03:01:07
*      }
*      BIT STRING {  (ASN1 type = 0x03)
*         first octet encoded number of padding bits at the end, should be 00
*         string of octets representing the public key
*      }
*   }
* 
* For secp384r1 we find:
* 
* Sequence {:30:76:
*    Sequence { 30:10:
*        Object ID { 06:07:
*                      2a:86:48:ce:3d:02:01:
*        Object ID { 06:05:
*                     :2b:81:04:00:22:
*    }
*    BIT STRING {03:62:
*       Null Byte 00:
*       97 bytes: 04:43:e9:2c:2c:61:ae
*       :69:bc:fa:ae:af:56:8d:90:e3:2d:d4:c6:43:66:97
*       :a5:4c:73:82:3b:b6:dd:4f:d4:89:bc:1f:7d:f9:eb
*       :c2:ad:ec:29:48:d0:3b:f6:92:e7:af:0f:7d:13:5f
*       :a4:b6:a3:ab:3e:34:e8:56:81:11:9b:d5:4f:23:08
*       :4e:1a:ee:95:10:e6:aa:36:33:f7:24:ce:f3:3c:21
*       :e1:e6:2e:d4:69:d1:37:f3:c9:a6:d7:19:63:70:83
*    }
*  }
*
* 
* for x25519 we find:
*  
* Sequence { :30:2a:
*     Sequence { 30:05:
*         Object ID { 06:03:
*                       2b:65:6e:
*         }
*     Bit String { 03:21:
*         Null Byte 00
*         :79:49:77
*         :8b:22:a1:a7:f5:86:e4:09:62:54:79:21:36:55:55
*         :16:49:20:a8:6e:dc:1d:bb:a2:2a:a6:7e:71:0c
*     }
* }
* 
* From RFC 5480:
* In the X.509 certificate, the subjectPublicKeyInfo field has the
* SubjectPublicKeyInfo type, which has the following ASN.1 syntax:
*     SubjectPublicKeyInfo  ::=  SEQUENCE  {
*      algorithm         AlgorithmIdentifier,
*      subjectPublicKey  BIT STRING
*     }
*     
*    AlgorithmIdentifier  ::=  SEQUENCE  {
*        algorithm   OBJECT IDENTIFIER,
*        parameters  ANY DEFINED BY algorithm OPTIONAL
*    }
*    id-ecPublicKey OBJECT IDENTIFIER ::= {
*        iso(1) member-body(2) us(840) ansi-X9-62(10045) keyType(2) 1 }
*    
* secp256r1 OBJECT IDENTIFIER ::= {
*    iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
*    prime(1) 7 }
* secp384r1 OBJECT IDENTIFIER ::= {
*    iso(1) identified-organization(3) certicom(132) curve(0) 34 }
* 
* From RFC 8410:
* id-X25519    OBJECT IDENTIFIER ::= { 1 3 101 110 }
*/



size_t picoquic_parse_public_key_asn1(ptls_iovec_t public_key_asn1,
    ptls_iovec_t* public_key_algo, ptls_iovec_t* public_key_param,
    ptls_iovec_t* public_key_bit_string, int* decode_error,
    ptls_minicrypto_log_ctx_t* log_ctx)
{
    uint8_t* bytes = public_key_asn1.base;
    size_t bytes_max = public_key_asn1.len;

    /* read the ASN1 messages */
    size_t byte_index = 0;
    uint32_t seq0_length = 0;
    size_t last_byte0;
    uint32_t seq1_length = 0;
    size_t last_byte1 = 0;
    uint32_t oid_length;
    size_t last_oid_byte;
    uint32_t key_data_length;
    size_t key_data_last;

    /* start with sequence */
    byte_index = ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, 0x30, &seq0_length, NULL, &last_byte0,
        decode_error, log_ctx);

    if (*decode_error == 0 && bytes_max != last_byte0) {
        byte_index = ptls_asn1_error_message("Length larger than message", bytes_max, byte_index, 0, log_ctx);
        *decode_error = PTLS_ERROR_BER_EXCESSIVE_LENGTH;
    }

    if (*decode_error == 0) {
        /* open embedded sequence */
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, 0x30, &seq1_length, NULL, &last_byte1,
            decode_error, log_ctx);
    }

    if (*decode_error == 0) {
        if (log_ctx != NULL) {
            log_ctx->fn(log_ctx->ctx, "   Algorithm Identifier:\n");
        }
        /* get length of OID */
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, last_byte1, byte_index, 0x06, &oid_length, NULL, &last_oid_byte,
            decode_error, log_ctx);

        if (*decode_error == 0) {
            if (log_ctx != NULL) {
                /* print the OID value */
                log_ctx->fn(log_ctx->ctx, "      Algorithm:");
                ptls_asn1_dump_content(bytes + byte_index, oid_length, 0, log_ctx);
                log_ctx->fn(log_ctx->ctx, ",\n");
            }
            public_key_algo->base = bytes + byte_index;
            public_key_algo->len = oid_length;
            byte_index += oid_length;
        }
    }

    if (*decode_error == 0) {
        /* get parameters, ANY */
        if (log_ctx != NULL) {
            log_ctx->fn(log_ctx->ctx, "      Parameters:\n");
        }

        public_key_param->base = bytes + byte_index;
        if (last_byte1 <= byte_index) {
            public_key_param->len = 0;
        }
        else {
            public_key_param->len = last_byte1 - byte_index;
        }
        byte_index = last_byte1;
    }

    /* get bit string, key */
    if (*decode_error == 0) {
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, last_byte0, byte_index, 0x03, &key_data_length, NULL,
            &key_data_last, decode_error, log_ctx);
        if (*decode_error == 0) {
            public_key_bit_string->base = bytes + byte_index;
            public_key_bit_string->len = key_data_length;
            byte_index += key_data_length;
        }
    }

    if (*decode_error == 0 && byte_index != last_byte0) {
        byte_index = ptls_asn1_error_message("Length larger than element", bytes_max, byte_index, 0, log_ctx);
        *decode_error = PTLS_ERROR_BER_ELEMENT_TOO_SHORT;
    }

    if (log_ctx != NULL) {
        log_ctx->fn(log_ctx->ctx, "\n");
    }
    return byte_index;
}


static uint8_t oid_algo_secp[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
static uint8_t oid_pr_secp256r1[] = { 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static uint8_t oid_pr_secp384r1[] = { 0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22 };
static uint8_t oid_x25519[] = { 0x2b, 0x65, 0x6e };

int picoquic_ech_parse_public_key(ptls_iovec_t public_key_asn1,
    uint16_t* group_id,
    ptls_iovec_t* public_key_bits)
{
    int ret = 0;
    ptls_iovec_t public_key_algo;
    ptls_iovec_t public_key_param;
    ptls_iovec_t public_key_bit_string;
    size_t expected_key_length = 0;
    (void)picoquic_parse_public_key_asn1(public_key_asn1,
        &public_key_algo, &public_key_param,
        &public_key_bit_string, &ret, NULL);
    if (ret == 0) {
        if (public_key_algo.len == sizeof(oid_algo_secp) &&
            memcmp(public_key_algo.base, oid_algo_secp, sizeof(oid_algo_secp)) == 0) {
            if (public_key_param.len == sizeof(oid_pr_secp256r1) &&
                memcmp(public_key_param.base, oid_pr_secp256r1, sizeof(oid_pr_secp256r1)) == 0) {
                *group_id = PTLS_GROUP_SECP256R1;
                expected_key_length = 0x41;
            }
            else if (public_key_param.len == sizeof(oid_pr_secp384r1) &&
                memcmp(public_key_param.base, oid_pr_secp384r1, sizeof(oid_pr_secp384r1)) == 0) {
                *group_id = PTLS_GROUP_SECP384R1;
                expected_key_length = 0x61;
            }
            else {
                DBG_PRINTF("%s", "Unsupported SecP Group ID");
                ret = -1;
            }
        }
        else if (public_key_algo.len == sizeof(oid_x25519) &&
            memcmp(public_key_algo.base, oid_x25519, sizeof(oid_x25519)) == 0) {
            *group_id = PTLS_GROUP_X25519;
            expected_key_length = 0x20;
        }
    }
    else {
        DBG_PRINTF("%s", "Unsupported Algorithm ID");
        ret = -1;
    }
    if (ret == 0) {
        if (public_key_bit_string.len > 1 && public_key_bit_string.base[0] == 0) {
            public_key_bits->base = public_key_bit_string.base + 1;
            public_key_bits->len = public_key_bit_string.len - 1;
            if (public_key_bits->len != expected_key_length) {
                DBG_PRINTF("Invalid length for curve 0x%04x: %zu, expected %zu",
                    *group_id, public_key_bits->len, expected_key_length);
                ret = -1;
            }
        }
    }
    return ret;
}

int picoquic_ech_get_kem_from_curve(ptls_hpke_kem_t **kem, uint16_t group_id)
{
    int ret = -1;

    for (int i = 0; i < PICOQUIC_HPKE_KEM_NB_MAX; i++) {
        if (picoquic_hpke_kems[i] == NULL) {
            break;
        }
        else if (picoquic_hpke_kems[i]->keyex->id == group_id) {
            *kem = picoquic_hpke_kems[i];
            ret = 0;
            break;
        }
    }
    return ret;
}

int picoquic_ech_get_ciphers_from_kem(ptls_hpke_cipher_suite_t** cipher_vec, size_t cipher_vec_nb_max, uint16_t kem_id)
{
    int ret = 0;
    size_t nb_ciphers = 0;
    uint16_t target_kdf_id = PTLS_HPKE_HKDF_SHA256;
    uint16_t target_aead_id = PTLS_HPKE_AEAD_AES_128_GCM;
    ptls_hpke_cipher_suite_t* target_cipher = NULL;
    ptls_hpke_cipher_suite_t* default_cipher = NULL;

    if (cipher_vec_nb_max < 2) {
        return -1;
    }

    switch (kem_id) {
    case PTLS_HPKE_KEM_P256_SHA256:
        target_kdf_id = PTLS_HPKE_HKDF_SHA256;
        target_aead_id = PTLS_HPKE_AEAD_AES_128_GCM;
        break;
    case PTLS_HPKE_KEM_P384_SHA384:
        target_kdf_id = PTLS_HPKE_HKDF_SHA384;
        target_aead_id = PTLS_HPKE_AEAD_AES_256_GCM;
        break;
    case PTLS_HPKE_KEM_X25519_SHA256:
        target_kdf_id = PTLS_HPKE_HKDF_SHA256;
        target_aead_id = PTLS_HPKE_AEAD_CHACHA20POLY1305;
        break;
    default:
        break;
    }

    for (size_t i = 0; i < PICOQUIC_HPKE_CIPHER_SUITE_NB_MAX; i++) {
        if (picoquic_hpke_cipher_suites[i] == NULL) {
            break;
        }
        else if (picoquic_hpke_cipher_suites[i]->id.aead == target_aead_id &&
            picoquic_hpke_cipher_suites[i]->id.kdf == target_kdf_id) {
            target_cipher = picoquic_hpke_cipher_suites[i];
            break;
        }
        else if (picoquic_hpke_cipher_suites[i]->id.aead == PTLS_HPKE_AEAD_AES_128_GCM &&
            picoquic_hpke_cipher_suites[i]->id.kdf == PTLS_HPKE_HKDF_SHA256) {
            default_cipher = picoquic_hpke_cipher_suites[i];
        }
    }
    if (target_cipher == NULL) {
        if (default_cipher != NULL) {
            cipher_vec[0] = default_cipher;
            nb_ciphers = 1;
        }
        else {
            ret = -1;
        }
    } else {
        cipher_vec[0] = target_cipher;
        nb_ciphers = 1;
        if (default_cipher != NULL && default_cipher != target_cipher && cipher_vec_nb_max > 2) {
            cipher_vec[1] = default_cipher;
            nb_ciphers++;
        }
    }
    for (size_t i = nb_ciphers; i < cipher_vec_nb_max; i++) {
        cipher_vec[i] = NULL;
    }
    return ret;
}

static uint8_t ech_config_id_from_config(ptls_iovec_t public_key_bits, ptls_hpke_kem_t* kem, ptls_hpke_cipher_suite_t** cipher_vec, char const* public_name)
{
    /* compute the config ID */
    uint64_t config_sum = 0;
    uint8_t config_id = 0;
    for (size_t i = 0; i < public_key_bits.len; i++) {
        config_sum += public_key_bits.base[i];
    }
    config_sum += kem->id;
    for (size_t i = 0; cipher_vec[i] != NULL; i++) {
        config_sum += cipher_vec[i]->id.aead;
        config_sum += cipher_vec[i]->id.kdf;
    }
    for (size_t i = 0; public_name[i] != 0; i++) {
        config_sum += (uint8_t)public_name[i];
    }
    while (config_sum > 0) {
        config_id ^= (uint8_t)(config_sum & 0xff);
        config_sum >>= 8;
    }
    return config_id;
}

/* Server side support.
*
* The server need two parameters: an ECH encryption key, and an
* ECH configuration.
*
* The ECH configuration has several parameters:
* - configuration ID,
* - identifier of the HPKE key encapsulation mechanism (KEM),
* - server public name, i.e., the DNS name of the client facing server,
* - server public key, i.e., the public key of the client facing server.
* - supported HPKE cipher suites.
*
* If the configuration is not available, it will have to be created.
* The server admin will have to provide the parameters.
* Many picoquic deployments use small servers with limited management.
* In that case, we may use default values such as the DNS name of
* the local server, the public key found in the local server certificate,
* a locally supported HPKE-KEM compatible with the public key,
* the list of locally supported HPKE symmetric cipher suites,
* and a configuration ID computed as combination of these local
* parameters.
*/
int picoquic_ech_encode_config(
    ptls_buffer_t* config_buf,
    uint8_t config_id,
    ptls_hpke_kem_t* kem,
    ptls_iovec_t public_key,
    ptls_hpke_cipher_suite_t** ciphers,
    uint8_t max_name_length,
    char const* public_name
) {
    int ret = ptls_ech_encode_config(config_buf, config_id, kem, public_key,
        ciphers, max_name_length, public_name);
    return ret;
}

int picoquic_ech_create_rr_from_binary(ptls_buffer_t* config_buf, ptls_iovec_t public_key_asn1, char const* public_name)
{
    int ret = 0;
    ptls_iovec_t public_key_bits = ptls_iovec_init(NULL, 0);
    uint16_t group_id = 0;
    ptls_hpke_kem_t* kem = NULL;
    ptls_hpke_cipher_suite_t* cipher_vec[PICOQUIC_HPKE_CIPHER_SUITE_NB_MAX + 1];
    uint8_t config_id = 0;

    /* Parse the ASN1 public key to extract the key type and the key bytes */
    if ((ret = picoquic_ech_parse_public_key(public_key_asn1, &group_id, &public_key_bits)) != 0) {
        DBG_PRINTF("Cannot get group and pubkey from ASN1, err: %x", ret);
    }
    /* Find a compatible KEM */
    else if ((ret = picoquic_ech_get_kem_from_curve(&kem, group_id)) != 0) {
        DBG_PRINTF("Could not find KEM for group = 0x%04x", group_id);
    }
    /* Find the list of locally supported cipher suites, retaining only the most common */
    else if ((ret = picoquic_ech_get_ciphers_from_kem(cipher_vec, PICOQUIC_HPKE_CIPHER_SUITE_NB_MAX + 1, kem->id)) != 0) {
        DBG_PRINTF("Could not find Ciphers for kem = 0x%04x", kem->id);
    }
    else {
        /* Compute a config ID from public key bytes, kem-id, cipher-suite IDs and public name */
        config_id = ech_config_id_from_config(public_key_bits, kem, cipher_vec, public_name);
        /* Encode the key config */
        if ((ret = ptls_ech_encode_config(config_buf, config_id, kem, public_key_bits,
            cipher_vec, 255, public_name)) != 0) {
            DBG_PRINTF("Could not encode the configuration, err: %x", ret);
        }
    }
    return ret;
}

int picoquic_ech_create_config_from_rr(uint8_t ** config, size_t * config_len, const ptls_buffer_t* rr_buf)
{
    int ret = 0;
    size_t bin_size = rr_buf->off + 2;
    uint8_t* bin_val = (uint8_t*)malloc(bin_size);
    if (bin_val == NULL) {
        DBG_PRINTF("Cannot allocate %d bytes for config bin buffer", bin_size);
        ret = -1;
    }
    else {
        bin_val[0] = (uint8_t)(((rr_buf->off) >> 8) & 0xff);
        bin_val[1] = (uint8_t)(rr_buf->off & 0xff);
        memcpy(bin_val + 2, rr_buf->base, rr_buf->off);
        *config = bin_val;
        *config_len = bin_size;
    }
    return ret;
}


int picoquic_ech_create_config_from_public_key(uint8_t** config, size_t* config_len, char const * public_key_file, char const* public_name)
{
    int ret = 0;
    ptls_iovec_t public_key_asn1 = ptls_iovec_init(NULL, 0);
    size_t pub_key_objects = 0;

    /* Read the public key from a file. */
    ret = ptls_load_pem_objects(public_key_file, "PUBLIC KEY", &public_key_asn1, 1, &pub_key_objects);
    if (ret != 0) {
        DBG_PRINTF("Cannot load pubkey from <%s>, err: %x", public_key_file, ret);
    }
    else
    {
        ptls_buffer_t rr_buf;
        ptls_buffer_init(&rr_buf, "", 0);
        ret = picoquic_ech_create_rr_from_binary(&rr_buf, public_key_asn1, public_name);
        if (ret == 0) {
            ret = picoquic_ech_create_config_from_rr(config, config_len, &rr_buf);
        }
        ptls_buffer_dispose(&rr_buf);
    }
    return ret;
}

/*
* In therory, all the information required to set up ECH is present in the
* certificate used by the public server. The public key certainly is there.
* 
* The certificate has a rather simple structure (see RFC 5280):
* 
*  Certificate  ::=  SEQUENCE  {
*        tbsCertificate       TBSCertificate,
*        signatureAlgorithm   AlgorithmIdentifier,
*        signatureValue       BIT STRING  }
*
*   TBSCertificate  ::=  SEQUENCE  {
*        version         [0]  EXPLICIT Version DEFAULT v1,
*        serialNumber         CertificateSerialNumber,
*        signature            AlgorithmIdentifier,
*        issuer               Name,
*        validity             Validity,
*        subject              Name,
*        subjectPublicKeyInfo SubjectPublicKeyInfo,
*        issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
*                             -- If present, version MUST be v2 or v3
*        subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
*                             -- If present, version MUST be v2 or v3
*        extensions      [3]  EXPLICIT Extensions OPTIONAL
*                             -- If present, version MUST be v3
*        }
* 
* We need a simple parser that:
* - opens the outside sequence,
* - opens its first element, the TBSCertificate
* - skip the elements version [0], serialNumber (INTEGER), 
*   signature (AlgorithmIdentifier, SEQUENCE),
*   issuer (Name, CHOICE, RdnSequence SEQUENCE OF),
*   validity (SEQUENCE)
*   subject (Name, CHOICE, RdnSequence SEQUENCE OF).
* - return the bytes from start (Type) of subjectPublicKeyInfo(SEQUENCE)
*   to end of that element.
*/
int picoquic_ech_get_public_key_from_cert(ptls_iovec_t cert, ptls_iovec_t* public_key_asn1,
    ptls_minicrypto_log_ctx_t* log_ctx)
{
    int ret = 0;
    uint8_t* bytes = cert.base;
    size_t bytes_max = cert.len;
    size_t byte_index = 0;
    uint32_t seq0_length = 0;
    size_t last_byte0;
    uint32_t seq1_length = 0;
    size_t last_byte1 = 0;
    size_t last_byte2 = 0;
    uint32_t skipped_length;
    size_t pubkey_info_index = 0;
    int indefinite_length;
    const uint8_t skipped_types[] = {
        0xa0, /* version [0] */
        0x02, /* serialNumber (INTEGER) */
        0x30, /* AlgorithmIdentifier, SEQUENCE) */
        0x30, /* issuer (Name, CHOICE, RdnSequence SEQUENCE OF) */
        0x30, /* validity (SEQUENCE) */
        0x30, /* subject (Name, CHOICE, RdnSequence SEQUENCE OF). */
    };
    /* open the outside sequence */

    /* start with sequence */
    byte_index = ptls_asn1_get_expected_type_and_length(bytes, bytes_max, byte_index, 0x30, &seq0_length, NULL, &last_byte0,
        &ret, log_ctx);
    if (ret == 0 && bytes_max != last_byte0) {
        byte_index = ptls_asn1_error_message("Length larger than message", bytes_max, byte_index, 0, log_ctx);
        ret = PTLS_ERROR_BER_EXCESSIVE_LENGTH;
    }
    if (ret == 0) {
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, seq0_length, byte_index, 0x30, &seq1_length, NULL, &last_byte1,
            &ret, log_ctx);
    }
    /* get the first component, TBSCertificate SEQUENCE */
    for (size_t i = 0; i < sizeof(skipped_types) && ret == 0; i++) {
#if 0
        if (skipped_types[i] == 0xff) {
            int structure_bit;
            int type_class;
            uint32_t type_number;
            uint32_t length;
            size_t last_byte_x;
            size_t type_length;
            size_t length_length;

            type_length = ptls_asn1_read_type(bytes + byte_index, last_byte1, &structure_bit, &type_class, &type_number,
                &ret, 0, log_ctx);
            if (ret == 0) {
                byte_index += type_length;
                length_length = ptls_asn1_read_length(bytes + byte_index, last_byte1, byte_index, &length, &indefinite_length,
                    &last_byte_x, &ret, 0, log_ctx); 
                if (ret == 0) {
                    byte_index += length_length;
                    byte_index += length;
                }
            }
        }
        else
#endif
        {
            byte_index = ptls_asn1_get_expected_type_and_length(bytes, last_byte1, byte_index, skipped_types[i], &skipped_length,
                &indefinite_length, &last_byte2,
                &ret, log_ctx);
            if (ret == 0) {
                byte_index += skipped_length;
            }
        }
    }
    /* If all went well, this component is the public key info. */
    if (ret == 0) {
        pubkey_info_index = byte_index;
        /* open embedded sequence */
        byte_index = ptls_asn1_get_expected_type_and_length(bytes, last_byte1, byte_index, 0x30, &skipped_length, NULL, &last_byte2,
            &ret, log_ctx);
        if (ret == 0) {
            public_key_asn1->base = bytes + pubkey_info_index;
            public_key_asn1->len = byte_index + skipped_length - pubkey_info_index;
        }
    }
    return ret;
}

int picoquic_ech_create_config_from_cert(uint8_t** config, size_t* config_len, char const* cert_file, char const* public_name)
{
    int ret = 0;
    ptls_iovec_t cert_bytes = ptls_iovec_init(NULL, 0);
    ptls_iovec_t public_key_asn1 = ptls_iovec_init(NULL, 0);
    size_t cert_objects = 0;
    /* Read the cert from a file. */
    if ((ret = ptls_load_pem_objects(cert_file, "CERTIFICATE", &cert_bytes, 1, &cert_objects)) != 0) {
        DBG_PRINTF("Cannot read cert bytes from <%s>", cert_file);
    }
    /* Extract the Public Key Info */
    if (ret == 0 && (ret = picoquic_ech_get_public_key_from_cert(cert_bytes, &public_key_asn1, NULL)) != 0) {
        DBG_PRINTF("Cannot extract public key from cert bytes of <%s>, ret = %d (0x%x)", cert_file, ret, ret);
    }
    /* Obtain the configuration */
    if (ret == 0){
        ptls_buffer_t rr_buf;
        ptls_buffer_init(&rr_buf, "", 0);
        if ((ret = picoquic_ech_create_rr_from_binary(&rr_buf, public_key_asn1, public_name)) != 0) {
            DBG_PRINTF("Cannot extract config from public key of <%s>, ret = %d (0x%x)", cert_file, ret, ret);
        }
        else {
            ret = picoquic_ech_create_config_from_rr(config, config_len, &rr_buf);
            ptls_buffer_dispose(&rr_buf);
        }
    }
    return ret;
}

