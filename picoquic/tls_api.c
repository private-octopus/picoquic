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

#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <stddef.h>
#include "picotls.h"
#include "picoquic_internal.h"
#include "picotls/openssl.h"
#if 0
#include "picotls/ffx.h"
#endif
#include "tls_api.h"
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include "logwriter.h"

#define container_of(ptr, type, member) ((type *)((char *)(ptr) - offsetof(type, member)))

#ifndef UNREFERENCED_PARAMETER
#define UNREFERENCED_PARAMETER(x) (void)(x)
#endif


#define PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION 0xFFA5
#define PICOQUIC_TRANSPORT_PARAMETERS_MAX_SIZE 2048

#ifdef PTLS_ESNI_NONCE_SIZE
#define PICOQUIC_ESNI_NONCE_SIZE PTLS_ESNI_NONCE_SIZE
#else 
#define PICOQUIC_ESNI_NONCE_SIZE 16
#endif


typedef struct st_picoquic_tls_ctx_t {
    ptls_t* tls;
    picoquic_cnx_t* cnx;
    int client_mode;
    ptls_raw_extension_t ext[2];
    ptls_handshake_properties_t handshake_properties;
    ptls_iovec_t alpn_vec[PICOQUIC_ALPN_NUMBER_MAX];
    int alpn_count;
    uint8_t ext_data[PICOQUIC_TRANSPORT_PARAMETERS_MAX_SIZE];
    uint8_t ext_received[PICOQUIC_TRANSPORT_PARAMETERS_MAX_SIZE];
    size_t ext_received_length;
    int ext_received_return;
    uint16_t esni_version;
    uint8_t esni_nonce[PICOQUIC_ESNI_NONCE_SIZE];
    uint8_t app_secret_enc[PTLS_MAX_DIGEST_SIZE];
    uint8_t app_secret_dec[PTLS_MAX_DIGEST_SIZE];
} picoquic_tls_ctx_t;

struct st_picoquic_log_event_t {
    ptls_log_event_t super;
    FILE* fp;
};

int picoquic_server_setup_ticket_aead_contexts(picoquic_quic_t* quic,
    ptls_context_t* tls_ctx,
    const uint8_t* secret, size_t secret_length);

static void picoquic_setup_cleartext_aead_salt(size_t version_index, ptls_iovec_t* salt);

static void picoquic_free_log_event(picoquic_quic_t* quic);

/*
 * Make sure that openssl is properly initialized.
 * 
 * The OpenSSL resources are allocated on first use, and not released until the end of the
 * process. The only problem is when use memory leak tracers such as valgrind. The OpenSSL
 * allocations will create a large number of issues, which may hide the actual leaks that
 * should be fixed. To alleviate that, the application may use an explicit call to
 * a global destructor like OPENSSL_cleanup(), but normally the OpenSSL stack does it
 * during the process exit.
 */
static int openssl_is_init = 0;

static void picoquic_init_openssl()
{
    if (openssl_is_init == 0) {
        openssl_is_init = 1;
        ERR_load_crypto_strings();
        OpenSSL_add_all_algorithms();
#if !defined(OPENSSL_NO_ENGINE)
        /* Load all compiled-in ENGINEs */
        ENGINE_load_builtin_engines();
        ENGINE_register_all_ciphers();
        ENGINE_register_all_digests();
#endif
    }
}

/*
 * Provide access to transport received transport extension for
 * logging purpose.
 */
void picoquic_provide_received_transport_extensions(picoquic_cnx_t* cnx,
    uint8_t** ext_received,
    size_t* ext_received_length,
    int* ext_received_return,
    int* client_mode)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;

    *ext_received = ctx->ext_received;
    *ext_received_length = ctx->ext_received_length;
    *ext_received_return = ctx->ext_received_return;
    *client_mode = ctx->client_mode;
}

static int set_sign_certificate_from_key(EVP_PKEY* pkey, ptls_context_t* ctx)
{
    int ret = 0;
    ptls_openssl_sign_certificate_t* signer;

    signer = (ptls_openssl_sign_certificate_t*)malloc(sizeof(ptls_openssl_sign_certificate_t));

    if (signer == NULL || pkey == NULL) {
        ret = -1;
    } else {
        ret = ptls_openssl_init_sign_certificate(signer, pkey);
        ctx->sign_certificate = &signer->super;
    }

    if (pkey != NULL) {
        EVP_PKEY_free(pkey);
    }

    if (ret != 0 && signer != NULL) {
        free(signer);
    }

    return ret;
}

static int set_sign_certificate_from_key_file(char const* keypem, ptls_context_t* ctx)
{
    int ret = 0;
    BIO* bio = BIO_new_file(keypem, "rb");
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey == NULL) {
        DBG_PRINTF("%s", "failed to load private key");
        ret = -1;
    }
    else {
        ret = set_sign_certificate_from_key(pkey, ctx);
    }
    BIO_free(bio);
    return ret;
}

/* Crypto random number generator */

void picoquic_crypto_random(picoquic_quic_t* quic, void* buf, size_t len)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    ctx->random_bytes(buf, len);
}

uint64_t picoquic_crypto_uniform_random(picoquic_quic_t* quic, uint64_t rnd_max)
{
    uint64_t rnd;
    uint64_t rnd_min = ((uint64_t)((int64_t)-1)) % rnd_max;

    do {
        picoquic_crypto_random(quic, &rnd, sizeof(rnd));
    } while (rnd < rnd_min);

    return rnd % rnd_max;
}

/*
 * Non crypto public random generator. This is meant to provide good enough randomness
 * without disclosing the state of the crypto random number generator. This is
 * adequate for non critical random numbers, such as sequence numbers or padding.
 *
 * The following is an implementation of xorshift1024* suggested by Sebastiano Vigna,
 * following the general xorshift design by George Marsaglia.
 * The state must be seeded so that it is not everywhere zero.
 *
 * The seed operation gets 64 bits from the crypto random generator. We then run the
 * generator 16 times to mix that input into the 1024 bits of seed[16].
 *
 * If we were really paranoid, we would want to break possible discovery by passing
 * the seeding bits from the crypto random generator through SHA256 or something
 * similar, so there would be really no way to get at the state of crypto random
 * generator. The 16 rounds of the xorshift process give a pretty good hash, but
 * that can probably be broken by linear analysis. Or at least we have no proof
 * that it cannot be broken.
 */

static uint64_t public_random_seed[16] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static int public_random_index = 0;
static const uint64_t public_random_multiplier = 1181783497276652981ull;

uint64_t picoquic_public_random_64(void)
{
    uint64_t s1;
    const uint64_t s0 = public_random_seed[public_random_index++];
    public_random_index &= 15;
    s1 = public_random_seed[public_random_index];
    s1 ^= s1 << 31; // a
    s1 ^= s1 >> 11; // b
    s1 ^= s0 ^ (s0 >> 30); // c
    public_random_seed[public_random_index] = s1;
    return s1 * public_random_multiplier;
}

void picoquic_public_random_seed_64(uint64_t seed, int reset)
{
    if (reset) {
        public_random_index = 0;
        for (uint64_t i = 0; i < 16; i++) {
            public_random_seed[i] = i + 1u;
        }
    }

    public_random_seed[public_random_index] ^= seed;

    for (int i = 0; i < 16; i++) {
        (void)picoquic_public_random_64();
    }
}


void picoquic_public_random_seed(picoquic_quic_t* quic)
{
    uint64_t seed;
    picoquic_crypto_random(quic, &seed, sizeof(seed));

    picoquic_public_random_seed_64(seed, 0);
}

void picoquic_public_random(void* buf, size_t len)
{
    uint8_t* x = buf;

    while (len > 0) {
        uint64_t y = picoquic_public_random_64();
        for (int i = 0; i < 8 && len > 0; i++) {
            *x++ = (uint8_t)(y & 255);
            y >>= 8;
            len--;
        }
    }
}

uint64_t picoquic_public_uniform_random(uint64_t rnd_max)
{
    uint64_t rnd;
    uint64_t rnd_min = ((uint64_t)((int64_t)-1)) % rnd_max;

    do {
        rnd = picoquic_public_random_64();
    } while (rnd < rnd_min);

    return rnd % rnd_max;
}

/*
 * The collect extensions call back is called by the picotls stack upon
 * reception of a handshake message containing extensions. It should return true (1)
 * if the stack can process the extension, false (0) otherwise.
 */

int picoquic_tls_collect_extensions_cb(ptls_t* tls, struct st_ptls_handshake_properties_t* properties, uint16_t type)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tls);
    UNREFERENCED_PARAMETER(properties);
#endif
#ifdef _DEBUG
    DBG_PRINTF("Collect extension callback, ext: %x, ret=%d\n",
        type, type == PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION);
#endif
    return type == PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION;
}

void picoquic_tls_set_extensions(picoquic_cnx_t* cnx, picoquic_tls_ctx_t* tls_ctx)
{
    size_t consumed;
    int ret = picoquic_prepare_transport_extensions(cnx, (tls_ctx->client_mode) ? 0 : 1,
        tls_ctx->ext_data, sizeof(tls_ctx->ext_data), &consumed);
#ifdef _DEBUG
    DBG_PRINTF("Prepare extension, ext: %x, ret=%d\n",
        PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION, ret);
#endif

    if (ret == 0) {
        tls_ctx->ext[0].type = PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION;
        tls_ctx->ext[0].data.base = tls_ctx->ext_data;
        tls_ctx->ext[0].data.len = consumed;
        tls_ctx->ext[1].type = 0xFFFF;
        tls_ctx->ext[1].data.base = NULL;
        tls_ctx->ext[1].data.len = 0;
    } else {
        tls_ctx->ext[0].type = 0xFFFF;
        tls_ctx->ext[0].data.base = NULL;
        tls_ctx->ext[0].data.len = 0;
    }

    tls_ctx->handshake_properties.additional_extensions = tls_ctx->ext;
}

/*
 * The collected extensions call back is called by the stack upon
 * reception of a handshake message containing supported extensions.
 */

int picoquic_tls_collected_extensions_cb(ptls_t* tls, ptls_handshake_properties_t* properties,
    ptls_raw_extension_t* slots)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tls);
#endif
    int ret = 0;
    size_t consumed = 0;
    /* Find the context from the TLS context */
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)((char*)properties - offsetof(struct st_picoquic_tls_ctx_t, handshake_properties));

    for (int i_slot = 0; slots[i_slot].type != 0xFFFF; i_slot++) {
#ifdef _DEBUG
        DBG_PRINTF("Receive extension, slot[%d]: %x\n",
            i_slot, slots[i_slot].type);
#endif
        if (slots[i_slot].type == PICOQUIC_TRANSPORT_PARAMETERS_TLS_EXTENSION) {
            size_t copied_length = sizeof(ctx->ext_received);

            /* Retrieve the transport parameters */
            ret = picoquic_receive_transport_extensions(ctx->cnx, (ctx->client_mode) ? 1 : 0,
                slots[i_slot].data.base, slots[i_slot].data.len, &consumed);

            /* Copy the extensions in the local context for further debugging */
            ctx->ext_received_length = slots[i_slot].data.len;
            if (copied_length > ctx->ext_received_length)
                copied_length = ctx->ext_received_length;
            memcpy(ctx->ext_received, slots[i_slot].data.base, copied_length);
            ctx->ext_received_return = ret;
            /* For now, override the value in case of default */
            ret = 0;

            /* In server mode, only compose the extensions if properly received from client */
            if (ctx->client_mode == 0) {
                picoquic_tls_set_extensions(ctx->cnx, ctx);
            }
        }
    }

    return ret;
}

/*
 * The Hello Call Back is called on the server side upon reception of the 
 * Client Hello. The picotls code will parse the client hello and retrieve
 * parameters such as SNI and proposed ALPN.
 * TODO: check the SNI in case several are supported.
 * TODO: check the ALPN in case several are supported.
 */

int picoquic_client_hello_call_back(ptls_on_client_hello_t* on_hello_cb_ctx,
    ptls_t* tls, ptls_on_client_hello_parameters_t *params)
{
    const uint8_t * alpn_found = 0;
    size_t alpn_found_length = 0;
    int ret = 0;
    picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)on_hello_cb_ctx) + sizeof(ptls_on_client_hello_t));
    picoquic_quic_t* quic = *ppquic;

    /* Save the server name */
    ptls_set_server_name(tls, (const char *)params->server_name.base, params->server_name.len);

#ifdef PTLS_ESNI_NONCE_SIZE
    if (params->esni && quic->cnx_in_progress != NULL) {
        /* Find the ESNI secret if any, and copy key values to picoquic tls context */
        picoquic_tls_ctx_t* tls_ctx = (picoquic_tls_ctx_t*)quic->cnx_in_progress->tls_ctx;
        struct st_ptls_esni_secret_t * esni = ptls_get_esni_secret(tls_ctx->tls);
        if (esni != NULL) {
            tls_ctx->esni_version = esni->version;
            memcpy(tls_ctx->esni_nonce, esni->nonce, PTLS_ESNI_NONCE_SIZE);
        }
    }
#endif

    if (quic->F_log != NULL && quic->cnx_in_progress != NULL) {
        picoquic_log_negotiated_alpn(quic->F_log, quic->cnx_in_progress, 1, 1, params->negotiated_protocols.list, params->negotiated_protocols.count);
    }

    /* Check if the client is proposing the expected ALPN */
    if (quic->default_alpn != NULL) {
        size_t len = strlen(quic->default_alpn);

        for (size_t i = 0; i < params->negotiated_protocols.count; i++) {
            if (params->negotiated_protocols.list[i].len == len && memcmp(params->negotiated_protocols.list[i].base, quic->default_alpn, len) == 0) {
                DBG_PRINTF("ALPN[%d] matches default alpn (%s)", (int)i, quic->default_alpn);
                alpn_found = (const uint8_t *)quic->default_alpn;
                alpn_found_length = len;
                ptls_set_negotiated_protocol(tls, quic->default_alpn, len);
                break;
            }
        }
    }
    else if (quic->alpn_select_fn != NULL) {
        size_t selected = quic->alpn_select_fn(quic, params->negotiated_protocols.list, params->negotiated_protocols.count);

        DBG_PRINTF("ALPN Selection call back selects %d (out of %d)", (int)selected, (int)params->negotiated_protocols.count);

        if (selected < params->negotiated_protocols.count) {
            alpn_found = params->negotiated_protocols.list[selected].base;
            alpn_found_length = params->negotiated_protocols.list[selected].len;
            ptls_set_negotiated_protocol(tls, (const char *)params->negotiated_protocols.list[selected].base, params->negotiated_protocols.list[selected].len);
        }
    }

    if (quic->cnx_in_progress != NULL && quic->cnx_in_progress->f_binlog != NULL) {
        binlog_transport_extension(quic->cnx_in_progress, 
            0, params->server_name.base, params->server_name.len, alpn_found, alpn_found_length, 
            params->negotiated_protocols.list, params->negotiated_protocols.count,
            0, NULL);
    }

    /* ALPN is mandatory in Quic. Return an error if no match found. */
    if (alpn_found == NULL) {
        ret = PTLS_ALERT_NO_APPLICATION_PROTOCOL;
    }



    DBG_PRINTF("Client Hello call back returns %d (0x%x)", ret, ret);

    return ret;
}

/*
 * The server will generate session tickets if some parameters are set in the server
 * TLS context, including:
 *  - the session ticket encryption callback, defined per the "encrypt_ticket" member of the context.
 *  - the session ticket lifetime, defined per the "ticket_life_time" member of the context.
 * The encrypt call back is called on the server side when a session resume ticket is ready.
 * The call is:
 * cb(tls->ctx->encrypt_ticket, tls, 1, sendbuf,
 *    ptls_iovec_init(session_id.base, session_id.off))
 * The call to decrypt is:
 * tls->ctx->encrypt_ticket->cb(tls->ctx->encrypt_ticket, tls, 0, &decbuf, identity->identity)
 * Should return 0 if the ticket is good, etc.
 */

int picoquic_server_encrypt_ticket_call_back(ptls_encrypt_ticket_t* encrypt_ticket_ctx,
    ptls_t* tls, int is_encrypt, ptls_buffer_t* dst, ptls_iovec_t src)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tls);
#endif

    /* Assume that the keys are in the quic context 
     * The tickets are composed of a 64 bit "sequence number" 
     * followed by the result of the clear text encryption.
     */
    int ret = 0;
    picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)encrypt_ticket_ctx) + sizeof(ptls_encrypt_ticket_t));
    picoquic_quic_t* quic = *ppquic;

    if (is_encrypt != 0) {
        ptls_aead_context_t* aead_enc = (ptls_aead_context_t*)quic->aead_encrypt_ticket_ctx;
        /* Encoding*/
        if (aead_enc == NULL) {
            ret = -1;
        } else if ((ret = ptls_buffer_reserve(dst, 8 + src.len + aead_enc->algo->tag_size)) == 0) {
            /* Create and store the ticket sequence number */
            uint64_t seq_num = picoquic_public_random_64();
            picoformat_64(dst->base + dst->off, seq_num);
            dst->off += 8;
            /* Run AEAD encryption */
            dst->off += ptls_aead_encrypt(aead_enc, dst->base + dst->off,
                src.base, src.len, seq_num, NULL, 0);
        }
    } else {
        ptls_aead_context_t* aead_dec = (ptls_aead_context_t*)quic->aead_decrypt_ticket_ctx;
        /* Encoding*/
        if (aead_dec == NULL) {
            ret = -1;
        } else if (src.len < 8 + aead_dec->algo->tag_size) {
            ret = -1;
        } else if ((ret = ptls_buffer_reserve(dst, src.len)) == 0) {
            /* Decode the ticket sequence number */
            uint64_t seq_num = PICOPARSE_64(src.base);
            /* Decrypt */
            size_t decrypted = ptls_aead_decrypt(aead_dec, dst->base + dst->off,
                src.base + 8, src.len - 8, seq_num, NULL, 0);

            if (decrypted > src.len - 8) {
                /* decryption error */
                ret = -1;
                if (quic->F_log != NULL) {
                    picoquic_log_app_message(quic->cnx_in_progress, "%s",
                        "Session ticket could not be decrypted");
                }
            } else {
                dst->off += decrypted;
                if (quic->F_log != NULL) {
                    picoquic_log_app_message(quic->cnx_in_progress, "%s",
                        "Session ticket properly decrypted");
                }
            }
        }
    }

    return ret;
}

/*
 * The client signals its willingness to receive session resume tickets by providing
 * the "save ticket" callback in the client's quic context.
 */

int picoquic_client_save_ticket_call_back(ptls_save_ticket_t* save_ticket_ctx,
    ptls_t* tls, ptls_iovec_t input)
{
    int ret = 0;
    picoquic_quic_t* quic = *((picoquic_quic_t**)(((char*)save_ticket_ctx) + sizeof(ptls_save_ticket_t)));
    const char* sni = ptls_get_server_name(tls);
    const char* alpn = ptls_get_negotiated_protocol(tls);
    picoquic_cnx_t * cnx = (picoquic_cnx_t *)*ptls_get_data_ptr(tls);

    if (alpn == NULL && quic != NULL) {
        alpn = quic->default_alpn;
    }

    if (sni != NULL && alpn != NULL) {
        ret = picoquic_store_ticket(&quic->p_first_ticket, 0, sni, (uint16_t)strlen(sni),
            alpn, (uint16_t)strlen(alpn), input.base, (uint16_t)input.len, &cnx->remote_parameters);
    } else {
        DBG_PRINTF("Received incorrect session resume ticket, sni = %s, alpn = %s, length = %d\n",
            (sni == NULL) ? "NULL" : sni, (alpn == NULL) ? "NULL" : alpn, (int)input.len);
    }

    return ret;
}

/*
 * Time get callback
 */
uint64_t picoquic_get_simulated_time_cb(ptls_get_time_t* self)
{
    uint64_t** pp_simulated_time = (uint64_t**)(((char*)self) + sizeof(ptls_get_time_t));
    return ((**pp_simulated_time) / 1000);
}

/*
 * Verify certificate
 */
typedef struct {
    ptls_verify_certificate_t cb;
    picoquic_quic_t *quic;
} picoquic_verify_certificate_t;

typedef struct {
    /* The pointer to the overlying `verify_ctx` */
    void *verify_ctx;
    int (*verify_sign)(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t sign);
} picoquic_verify_ctx_t;

static int verify_sign_callback(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t sign)
{
    picoquic_verify_ctx_t* ctx = (picoquic_verify_ctx_t*)verify_ctx;
    int ret = 0;

    ret = ctx->verify_sign(ctx->verify_ctx, data, sign);

    free(ctx);

    return ret;
}

static int verify_certificate_callback(ptls_verify_certificate_t* _self, ptls_t* tls,
                                       int (**verify_sign)(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t sign),
                                       void **verify_data,
                                       ptls_iovec_t *certs,
                                       size_t num_certs)
{
    picoquic_verify_certificate_t *self = container_of(_self, picoquic_verify_certificate_t, cb);
    picoquic_cnx_t* cnx = (picoquic_cnx_t*)*ptls_get_data_ptr(tls);
    int ret = 0;
    void *verify_ctx = NULL;
    picoquic_verify_sign_cb_fn verify_sign_fn = NULL;

    ret = (self->quic->verify_certificate_callback_fn)(self->quic->verify_certificate_ctx, cnx,
                                                       certs, num_certs, &verify_sign_fn, &verify_ctx);

    if (ret == 0) {
        *verify_sign = verify_sign_callback;
        *verify_data = malloc(sizeof(picoquic_verify_ctx_t));
        if (*verify_data != NULL) {
            ((picoquic_verify_ctx_t*)*verify_data)->verify_ctx = verify_ctx;
            ((picoquic_verify_ctx_t*)*verify_data)->verify_sign = verify_sign_fn;
        }
    }

    return ret;
}

int picoquic_enable_custom_verify_certificate_callback(picoquic_quic_t* quic) {
    picoquic_verify_certificate_t* verifier = NULL;
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    assert(quic->verify_certificate_callback_fn != NULL);

    verifier = (picoquic_verify_certificate_t*)malloc(sizeof(picoquic_verify_certificate_t));
    if (verifier == NULL) {
        return PICOQUIC_ERROR_MEMORY;
    } else {
        verifier->quic = quic;
        verifier->cb.cb = verify_certificate_callback;
        ctx->verify_certificate = &verifier->cb;
        quic->is_cert_store_not_empty = 1;

        return 0;
    }
}

void picoquic_dispose_verify_certificate_callback(picoquic_quic_t* quic, int custom) {
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    if (ctx->verify_certificate == NULL) {
        return;
    }

    if (custom == 1) {
        free(ctx->verify_certificate);
    } else {
        ptls_openssl_dispose_verify_certificate((ptls_openssl_verify_certificate_t*)ctx->verify_certificate);
    }

    ctx->verify_certificate = NULL;
}

/* set key from secret: this is used to create AEAD contexts and PN encoding contexts
 * after a key update callback, and also to create the initial keys from a locally
 * computed secret
 */
static int picoquic_set_aead_from_secret(void ** v_aead,ptls_cipher_suite_t * cipher, int is_enc, const void *secret)
{
    int ret = 0;

    if (*v_aead != NULL) {
        ptls_aead_free((ptls_aead_context_t*)*v_aead);
    }

    if ((*v_aead = ptls_aead_new(cipher->aead, cipher->hash, is_enc, secret, PICOQUIC_LABEL_QUIC_KEY_BASE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    }
#ifdef _DEBUG
    else {
        DBG_PRINTF("AEAD %s IV (%d):\n", 
            (is_enc)?"Encryption":"Decryption",
            (int)cipher->aead->iv_size);
    }
#endif

    return ret;
}

static int picoquic_set_pn_enc_from_secret(void ** v_pn_enc, ptls_cipher_suite_t * cipher, int is_enc, const void *secret)
{
    uint8_t pnekey[PTLS_MAX_SECRET_SIZE];
    int ret;

    if (*v_pn_enc != NULL) {
        ptls_cipher_free((ptls_cipher_context_t *)*v_pn_enc);
        *v_pn_enc = NULL;
    }

    if ((ret = ptls_hkdf_expand_label(cipher->hash, pnekey, 
        cipher->aead->ctr_cipher->key_size, ptls_iovec_init(secret, cipher->hash->digest_size), 
        PICOQUIC_LABEL_HP, ptls_iovec_init(NULL, 0), PICOQUIC_LABEL_QUIC_KEY_BASE)) == 0) {
#ifdef _DEBUG
        DBG_PRINTF("PN Encryption key (%d):\n", (int)cipher->aead->ctr_cipher->key_size);
        debug_dump(pnekey, (int)cipher->aead->ctr_cipher->key_size);
#endif
        if ((*v_pn_enc = ptls_cipher_new(cipher->aead->ctr_cipher, is_enc, pnekey)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
        }
    }
    
    return ret;
}

void* picoquic_aes128_ecb_create(int is_enc, const void* ecb_key)
{
    return (void*) ptls_cipher_new(&ptls_openssl_aes128ecb, is_enc, ecb_key);
}

void picoquic_aes128_ecb_free(void * v_aesecb)
{
    ptls_cipher_free((ptls_cipher_context_t *)v_aesecb);
}

void picoquic_aes128_ecb_encrypt(void* v_aesecb, uint8_t * output, const uint8_t * input, size_t len)
{
    ptls_cipher_encrypt((ptls_cipher_context_t*)v_aesecb, output, input, len);
}

static int picoquic_set_key_from_secret(ptls_cipher_suite_t * cipher, int is_enc, int is_rotation, picoquic_crypto_context_t * ctx, const void *secret)
{
    int ret = 0;

    if (is_enc != 0) {
        ret = picoquic_set_aead_from_secret(&ctx->aead_encrypt, cipher, is_enc, secret);
        
        if (ret == 0 && !is_rotation) {
            ret = picoquic_set_pn_enc_from_secret(&ctx->pn_enc, cipher, is_enc, secret);
        }
    } else {
        ret = picoquic_set_aead_from_secret(&ctx->aead_decrypt, cipher, is_enc, secret);
        
        if (ret == 0 && !is_rotation) {
            ret = picoquic_set_pn_enc_from_secret(&ctx->pn_dec, cipher, is_enc, secret);
        }
    }

    return ret;
}


/* Key update callback: this is called by TLS whenever the session key has changed,
 * from the function "setup_traffic_protection" in picotls.c.
 *
 * The macro generated callback struct is:
 *     typedef struct st_ptls_update_traffic_key_t {
 *      ret (*cb)(struct st_ptls_update_traffic_key_t * self, ptls_t *tls, int is_enc, size_t epoch, const void *secret);
 *  } ptls_update_traffic_key_t;
 *
 * The parameters are defined as:
 *  - self    -- classic callback structure in picotls, can be remapped to hold additional arguments.
 *  - tls     -- the tls context of the connection
 *  - is_enc  -- 0: decryption key, 1: decryption key
 *  - epoch   -- 1: "c e traffic"
 *            -- 2: "s hs traffic"
 *            -- 2: "c hs traffic"
 *            -- 3: "s ap traffic"
 *            -- 3: "c ap traffic"
 *  - secret  -- the expansion of the master secret with the label specific to the key epoch
 *               and client or server mode.
 */

typedef struct st_picoquic_update_traffic_key_t {
    int(*cb)(struct st_ptls_update_traffic_key_t * self, ptls_t *tls, int is_enc, size_t epoch, const void *secret);
    picoquic_cnx_t *cnx;
} picoquic_update_traffic_key_t;

static int picoquic_update_traffic_key_callback(ptls_update_traffic_key_t * self, ptls_t *tls, int is_enc, size_t epoch, const void *secret)
{
    picoquic_cnx_t* cnx = (picoquic_cnx_t*)*ptls_get_data_ptr(tls);
    picoquic_tls_ctx_t * tls_ctx = (picoquic_tls_ctx_t *)cnx->tls_ctx;
    ptls_context_t* ctx = (ptls_context_t*)cnx->quic->tls_master_ctx;
    ptls_cipher_suite_t * cipher = ptls_get_cipher(tls);
    UNREFERENCED_PARAMETER(self);
#ifdef _DEBUG
    DBG_PRINTF("Update traffic key epoch:%d, enc:%d\n", (int)epoch, is_enc);
    debug_dump(secret, (int)cipher->hash->digest_size);
#endif

    int ret = picoquic_set_key_from_secret(cipher, is_enc, 0, &cnx->crypto_context[epoch], secret);
    if (cnx->cnx_state < picoquic_state_ready) {
        cnx->recycle_sooner_needed = 1;
    }

    if (ret == 0 && epoch == 3) {
        memcpy((is_enc) ? tls_ctx->app_secret_enc : tls_ctx->app_secret_dec, secret, cipher->hash->digest_size);
    }

    if (ctx->log_event != NULL) {
        char hexbuf[PTLS_MAX_DIGEST_SIZE * 2 + 1];
        static const char *log_labels[2][4] = {
            {NULL, "QUIC_CLIENT_EARLY_TRAFFIC_SECRET", "QUIC_CLIENT_HANDSHAKE_TRAFFIC_SECRET", "QUIC_CLIENT_TRAFFIC_SECRET_0"},
            {NULL, NULL, "QUIC_SERVER_HANDSHAKE_TRAFFIC_SECRET", "QUIC_SERVER_TRAFFIC_SECRET_0"}};
        const char *secret_label = log_labels[ptls_is_server(tls) == is_enc][epoch];
        ptls_hexdump(hexbuf, secret, cipher->hash->digest_size);
        ctx->log_event->cb(ctx->log_event, tls, secret_label, "%s", hexbuf);
    }

    return ret;
}

ptls_update_traffic_key_t * picoquic_set_update_traffic_key_callback() {
    ptls_update_traffic_key_t * cb_st = (ptls_update_traffic_key_t *)malloc(sizeof(ptls_update_traffic_key_t));

    if (cb_st != NULL) {
        memset(cb_st, 0, sizeof(ptls_update_traffic_key_t));
        cb_st->cb = picoquic_update_traffic_key_callback;
    }

    return cb_st;
}

int picoquic_setup_initial_master_secret(
    ptls_cipher_suite_t * cipher,
    ptls_iovec_t salt,
    picoquic_connection_id_t initial_cnxid,
    uint8_t * master_secret)
{
    int ret = 0;
    ptls_iovec_t ikm;
    uint8_t cnx_id_serialized[PICOQUIC_CONNECTION_ID_MAX_SIZE];

    ikm.len = picoquic_format_connection_id(cnx_id_serialized, PICOQUIC_CONNECTION_ID_MAX_SIZE,
        initial_cnxid);
    ikm.base = cnx_id_serialized;

    /* Extract the master key -- key length will be 32 per SHA256 */
    ret = ptls_hkdf_extract(cipher->hash, master_secret, salt, ikm);

    return ret;
}

int picoquic_setup_initial_secrets(
    ptls_cipher_suite_t * cipher,
    uint8_t * master_secret,
    uint8_t * client_secret,
    uint8_t * server_secret)
{
    int ret = 0;
    ptls_iovec_t prk;

    prk.base = master_secret;
    prk.len = cipher->hash->digest_size;

    /* Get the client secret */
    ret = ptls_hkdf_expand_label(cipher->hash, client_secret, cipher->hash->digest_size,
        prk, PICOQUIC_LABEL_INITIAL_CLIENT, ptls_iovec_init(NULL, 0), NULL);

    if (ret == 0) {
        /* Get the server secret */
        ret = ptls_hkdf_expand_label(cipher->hash, server_secret, cipher->hash->digest_size,
            prk, PICOQUIC_LABEL_INITIAL_SERVER, ptls_iovec_init(NULL, 0), NULL);
    }

    return ret;
}

int picoquic_setup_initial_traffic_keys(picoquic_cnx_t* cnx)
{
    int ret = 0;
    uint8_t master_secret[256]; /* secret_max */
    ptls_cipher_suite_t cipher = { 0, &ptls_openssl_aes128gcm, &ptls_openssl_sha256 };
    ptls_iovec_t salt;
    uint8_t client_secret[256];
    uint8_t server_secret[256];
    uint8_t *secret1, *secret2;

    picoquic_setup_cleartext_aead_salt(cnx->version_index, &salt);

    /* Extract the master key -- key length will be 32 per SHA256 */
    ret = picoquic_setup_initial_master_secret(&cipher, salt, cnx->initial_cnxid, master_secret);

    /* set up client and server secrets */
    if (ret == 0) {
        ret = picoquic_setup_initial_secrets(&cipher, master_secret, client_secret, server_secret);
    }

    /* derive the initial keys */
    if (ret == 0) {
        if (!cnx->client_mode) {
            secret1 = server_secret;
            secret2 = client_secret;
        }
        else {
            secret1 = client_secret;
            secret2 = server_secret;
        }
        
        ret = picoquic_set_key_from_secret(&cipher, 1, 0, &cnx->crypto_context[0], secret1);

        if (ret == 0) {
            ret = picoquic_set_key_from_secret(&cipher, 0, 0, &cnx->crypto_context[0], secret2);
        }
    }

    return ret;
}

/*
 * Key rotation.
 *
 * The old keys get moved to the old crypto context.
 * The secrets are rotated.
 * The new context gets informed.
 *
 * The key update is defined in RFC 8446 section 7.2 as:
 * application_traffic_secret_N+1 =
 *         HKDF-Expand-Label(application_traffic_secret_N,
 *                            "quic ku", "", Hash.length)
  * Label: PICOQUIC_LABEL_TRAFFIC_UPDATE
 */
int picoquic_rotate_app_secret(ptls_cipher_suite_t * cipher, uint8_t * secret)
{
    int ret = 0;
    uint8_t new_secret[PTLS_MAX_DIGEST_SIZE];

    ret = ptls_hkdf_expand_label(cipher->hash, new_secret,
        cipher->hash->digest_size, ptls_iovec_init(secret, cipher->hash->digest_size), PICOQUIC_LABEL_TRAFFIC_UPDATE,
        ptls_iovec_init(NULL, 0), PICOQUIC_LABEL_QUIC_BASE);
    if (ret == 0) {
        memcpy(secret, new_secret, cipher->hash->digest_size);
    }

    return ret;
}


uint8_t * picoquic_get_app_secret(picoquic_cnx_t* cnx, int is_enc)
{
    picoquic_tls_ctx_t * tls_ctx = (picoquic_tls_ctx_t *)cnx->tls_ctx;

    return (is_enc) ?tls_ctx->app_secret_enc:tls_ctx->app_secret_dec;
}

size_t picoquic_get_app_secret_size(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t * tls_ctx = (picoquic_tls_ctx_t *)cnx->tls_ctx;

    ptls_cipher_suite_t * cipher = ptls_get_cipher(tls_ctx->tls);

    return (cipher->hash->digest_size);
}

int picoquic_compute_new_rotated_keys(picoquic_cnx_t * cnx)
{
    int ret = 0;
    picoquic_tls_ctx_t * tls_ctx = (picoquic_tls_ctx_t *)cnx->tls_ctx;
    ptls_cipher_suite_t * cipher = ptls_get_cipher(tls_ctx->tls);

    /* Verify that the previous transition is complete */
    if (cnx->crypto_context_new.aead_decrypt != NULL ||
        cnx->crypto_context_new.aead_encrypt != NULL) {
        if (cnx->crypto_context_new.aead_decrypt == NULL ||
            cnx->crypto_context_new.aead_encrypt == NULL) {
            ret = PICOQUIC_ERROR_CANNOT_COMPUTE_KEY;
        }
        else {
            /* already computed */
            return 0;
        }
    }

    /* Recompute the secrets */
    if (ret == 0) {
        ret = picoquic_rotate_app_secret(cipher, tls_ctx->app_secret_enc);
#ifdef _DEBUG
        if (ret == 0) {
            DBG_PRINTF("Rotated Encryption Secret (%d):\n", (int)cipher->hash->digest_size);
            debug_dump(tls_ctx->app_secret_enc, (int)cipher->hash->digest_size);
        }
        else {
            DBG_PRINTF("Encryption secret rotation fails, ret=%x\n", ret);
        }
#endif
    }

    if (ret == 0) {
        ret = picoquic_set_key_from_secret(cipher, 1, 1, &cnx->crypto_context_new, tls_ctx->app_secret_enc);
    }

    if (ret == 0) {
        ret = picoquic_rotate_app_secret(cipher, tls_ctx->app_secret_dec);
#ifdef _DEBUG
        if (ret == 0) {
            DBG_PRINTF("Rotated Decryption Secret (%d):\n", (int)cipher->hash->digest_size);
            debug_dump(tls_ctx->app_secret_dec, (int)cipher->hash->digest_size);
        }
        else {
            DBG_PRINTF("Decryption secret rotation fails, ret=%x\n", ret);
        }
#endif

    }

    if (ret == 0) {
        ret = picoquic_set_key_from_secret(cipher, 0, 1, &cnx->crypto_context_new, tls_ctx->app_secret_dec);
    }

    return (ret == 0)?0: PICOQUIC_ERROR_CANNOT_COMPUTE_KEY;
}

void picoquic_apply_rotated_keys(picoquic_cnx_t * cnx, int is_enc)
{
    if (is_enc) {
        if (cnx->crypto_context[3].aead_encrypt != NULL) {
            ptls_aead_free((ptls_aead_context_t *)cnx->crypto_context[3].aead_encrypt);
        }

        cnx->crypto_context[3].aead_encrypt = cnx->crypto_context_new.aead_encrypt;
        cnx->crypto_context_new.aead_encrypt = NULL;

        cnx->key_phase_enc ^= 1;
        picoquic_log_pn_dec_trial(cnx);
    }
    else {
        if (cnx->crypto_context_old.aead_decrypt != NULL) {
            ptls_aead_free((ptls_aead_context_t *)cnx->crypto_context_old.aead_decrypt);
        }

        cnx->crypto_context_old.aead_decrypt = cnx->crypto_context[3].aead_decrypt;
        cnx->crypto_context[3].aead_decrypt = cnx->crypto_context_new.aead_decrypt;
        cnx->crypto_context_new.aead_decrypt = NULL;

        cnx->key_phase_dec ^= 1;
    }
}

/*
 * Release the crypto context, and the associated keys.
 */

void picoquic_crypto_context_free(picoquic_crypto_context_t * ctx)
{
    if (ctx->aead_encrypt != NULL) {
        ptls_aead_free((ptls_aead_context_t *)ctx->aead_encrypt);
        ctx->aead_encrypt = NULL;
    }

    if (ctx->aead_decrypt != NULL) {
        ptls_aead_free((ptls_aead_context_t *)ctx->aead_decrypt);
        ctx->aead_decrypt = NULL;
    }

    if (ctx->pn_enc != NULL) {
        ptls_cipher_free((ptls_cipher_context_t *)ctx->pn_enc);
        ctx->pn_enc = NULL;
    }

    if (ctx->pn_dec != NULL) {
        ptls_cipher_free((ptls_cipher_context_t *)ctx->pn_dec);
        ctx->pn_dec = NULL;
    }
}

/* Definition of supported key exchange algorithms */

ptls_key_exchange_algorithm_t *picoquic_key_exchanges[] = { &ptls_openssl_secp256r1,                                                         
#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
                                                           &ptls_openssl_x25519,
#endif
                                                           NULL };

ptls_key_exchange_algorithm_t* picoquic_key_secp256r1[] = { &ptls_openssl_secp256r1, NULL };

#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
ptls_key_exchange_algorithm_t* picoquic_key_x25519[] = { & ptls_openssl_x25519, NULL };
#endif

ptls_cipher_suite_t *picoquic_cipher_suites[] = { 
    &ptls_openssl_aes128gcmsha256,
    &ptls_openssl_aes256gcmsha384,
#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
    &ptls_openssl_chacha20poly1305sha256,
#else
    /* No support for ChaCha 20 */
#endif
    NULL };

ptls_cipher_suite_t* picoquic_cipher_suite_aes128gcmsha256[] = {
    &ptls_openssl_aes128gcmsha256,
    NULL
};

ptls_cipher_suite_t* picoquic_cipher_suite_aes256gcmsha384[] = {
    &ptls_openssl_aes256gcmsha384,
    NULL
};

#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
ptls_cipher_suite_t* picoquic_cipher_suite_chacha20poly1305sha256[] = {
    & ptls_openssl_chacha20poly1305sha256,
    NULL };
#endif

/*
 * Setting the master TLS context.
 * On servers, this implies setting the "on hello" call back
 */

int picoquic_master_tlscontext(picoquic_quic_t* quic,
    char const* cert_file_name, char const* key_file_name, const char * cert_root_file_name,
    const uint8_t* ticket_key, size_t ticket_key_length)
{
    /* Create a client context or a server context */
    int ret = 0;
    ptls_context_t* ctx;
    ptls_openssl_verify_certificate_t* verifier = NULL;
    ptls_on_client_hello_t* och = NULL;
    ptls_encrypt_ticket_t* encrypt_ticket = NULL;
    ptls_save_ticket_t* save_ticket = NULL;

    picoquic_init_openssl(); /* OpenSSL init, just in case */

    ctx = (ptls_context_t*)malloc(sizeof(ptls_context_t));

    if (ctx == NULL) {
        ret = -1;
    } else {
        memset(ctx, 0, sizeof(ptls_context_t));
        ctx->random_bytes = ptls_openssl_random_bytes;
        ctx->key_exchanges = picoquic_key_exchanges; /* was:  ptls_openssl_key_exchanges; */
        ctx->cipher_suites = picoquic_cipher_suites; /* was: ptls_openssl_cipher_suites; */

        ctx->send_change_cipher_spec = 0;

        ctx->hkdf_label_prefix__obsolete = NULL;
        ctx->update_traffic_key = picoquic_set_update_traffic_key_callback();

        if (quic->p_simulated_time == NULL) {
            ctx->get_time = &ptls_get_time;
        } else {
            ptls_get_time_t* time_getter = (ptls_get_time_t*)malloc(sizeof(ptls_get_time_t) + sizeof(uint64_t*));
            if (time_getter == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            } else {
                uint64_t** pp_simulated_time = (uint64_t**)(((char*)time_getter) + sizeof(ptls_get_time_t));

                time_getter->cb = picoquic_get_simulated_time_cb;
                *pp_simulated_time = quic->p_simulated_time;
                ctx->get_time = time_getter;
            }
        }

        if (cert_file_name != NULL && key_file_name != NULL) {
            /* Read the certificate file */
            if (ptls_load_certificates(ctx, (char*)cert_file_name) != 0) {
                ret = -1;
            } else {
                ret = set_sign_certificate_from_key_file(key_file_name, ctx);
            }
        }

        if (ret == 0) {
            och = (ptls_on_client_hello_t*)malloc(sizeof(ptls_on_client_hello_t) + sizeof(picoquic_quic_t*));
            if (och != NULL) {
                picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)och) + sizeof(ptls_on_client_hello_t));

                och->cb = picoquic_client_hello_call_back;
                ctx->on_client_hello = och;
                *ppquic = quic;
            } else {
                ret = PICOQUIC_ERROR_MEMORY;
            }
        }

        if (ret == 0) {
            ret = picoquic_server_setup_ticket_aead_contexts(quic, ctx, ticket_key, ticket_key_length);
        }

        if (ret == 0) {
            encrypt_ticket = (ptls_encrypt_ticket_t*)malloc(sizeof(ptls_encrypt_ticket_t) + sizeof(picoquic_quic_t*));
            if (encrypt_ticket == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            } else {
                picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)encrypt_ticket) + sizeof(ptls_encrypt_ticket_t));

                encrypt_ticket->cb = picoquic_server_encrypt_ticket_call_back;
                *ppquic = quic;

                ctx->encrypt_ticket = encrypt_ticket;
                ctx->ticket_lifetime = 100000; /* 100,000 seconds, a bit more than one day */
                ctx->require_dhe_on_psk = 1;
                ctx->max_early_data_size = 0xFFFFFFFF;
            }
        }

        verifier = (ptls_openssl_verify_certificate_t*)malloc(sizeof(ptls_openssl_verify_certificate_t));
        if (verifier == NULL) {
            ctx->verify_certificate = NULL;
        } else {
            X509_STORE *store = X509_STORE_new();

            if (cert_root_file_name != NULL && store != NULL) {
                int file_ret = 0;
                X509_LOOKUP* lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
                if ((file_ret = X509_LOOKUP_load_file(lookup, cert_root_file_name, X509_FILETYPE_PEM)) != 1) {
                    DBG_PRINTF("Cannot load X509 store (%s), ret = %d\n",
                        cert_root_file_name, ret);
                }
                else {
                    quic->is_cert_store_not_empty = 1;
                }
            }

            ptls_openssl_init_verify_certificate(verifier, store);
            ctx->verify_certificate = &verifier->super;

            // If we created an instance of the store, release our reference after giving it to the verify_certificate callback.
            // The callback internally increased the reference counter by one.
            if (store != NULL) {
#if OPENSSL_VERSION_NUMBER > 0x10100000L
                X509_STORE_free(store);
#endif
            }
        }

        if (quic->ticket_file_name != NULL) {
            save_ticket = (ptls_save_ticket_t*)malloc(sizeof(ptls_save_ticket_t) + sizeof(picoquic_quic_t*));
            if (save_ticket != NULL) {
                picoquic_quic_t** ppquic = (picoquic_quic_t**)(((char*)save_ticket) + sizeof(ptls_save_ticket_t));

                save_ticket->cb = picoquic_client_save_ticket_call_back;
                ctx->save_ticket = save_ticket;
                *ppquic = quic;
            }
        }

        if (ret == 0) {
            /* Tell Picotls to not require EOED messages during handshake */
            ctx->omit_end_of_early_data = 1;
        }

        if (ret == 0) {
            quic->tls_master_ctx = ctx;
            picoquic_public_random_seed(quic);
        } else {
            free(ctx);
        }
    }

    return ret;
}

static void free_certificates_list(ptls_iovec_t* certs, size_t len) {
    if (certs == NULL) {
        return;
    }

    for (size_t i = 0; i < len; ++i) {
        free(certs[i].base);
    }
    free(certs);
}

int picoquic_set_cipher_suite(picoquic_quic_t* quic, int cipher_suite_id)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    int ret = 0;

    if (ctx == NULL) {
        ret = -1;
    }
    else {
        switch (cipher_suite_id) {
        case 0:
            ctx->cipher_suites = picoquic_cipher_suites;
            break;
        case 20:
#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
            ctx->cipher_suites = picoquic_cipher_suite_chacha20poly1305sha256;
            break;
#else
            ret = -1;
            break;
#endif
        case 128:
            ctx->cipher_suites = picoquic_cipher_suite_aes128gcmsha256;
            break;
        case 256:
            ctx->cipher_suites = picoquic_cipher_suite_aes256gcmsha384;
            break;
        default:
            ret = -1;
            break;
        }
    }
    return ret;
}

int picoquic_set_key_exchange(picoquic_quic_t* quic, int key_exchange_id)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    int ret = 0;

    if (ctx == NULL) {
        ret = -1;
    }
    else {
        switch (key_exchange_id) {
        case 0:
            ctx->key_exchanges = picoquic_key_exchanges;
            break;
        case 20:
#ifdef PTLS_OPENSSL_HAVE_CHACHA20_POLY1305
            ctx->key_exchanges = picoquic_key_x25519;
            break;
#else
            ret = -1;
            break;
#endif
        case 128:
            ctx->key_exchanges = picoquic_key_secp256r1;
            break;
        case 256:
            ctx->key_exchanges = picoquic_key_secp256r1;
            break;
        default:
            ret = -1;
            break;
        }
    }
    return ret;
}


void picoquic_master_tlscontext_free(picoquic_quic_t* quic)
{
    if (quic->tls_master_ctx != NULL) {
        ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

        if (quic->p_simulated_time != NULL && ctx->get_time != NULL) {
            free(ctx->get_time);
            ctx->get_time = NULL;
        }

        free_certificates_list(ctx->certificates.list, ctx->certificates.count);

        if (ctx->sign_certificate != NULL) {
            ptls_openssl_dispose_sign_certificate((ptls_openssl_sign_certificate_t*)ctx->sign_certificate);
            free((ptls_openssl_sign_certificate_t*)ctx->sign_certificate);
            ctx->sign_certificate = NULL;
        }

        picoquic_dispose_verify_certificate_callback(quic, 0);

        if (ctx->on_client_hello != NULL) {
            free(ctx->on_client_hello);
        }

        if (ctx->encrypt_ticket != NULL) {
            free(ctx->encrypt_ticket);
        }

        if (ctx->update_traffic_key != NULL) {
            free(ctx->update_traffic_key);
        }

        /* Need to be tested */
        if (ctx->save_ticket != NULL) {
            free(ctx->save_ticket);
        }

        picoquic_free_log_event(quic);
    }
}

/* Return the virtual time seen by tls */
uint64_t picoquic_get_tls_time(picoquic_quic_t* quic)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    uint64_t now = ctx->get_time->cb(ctx->get_time);

    return now;
}

/*
 * Creation of a TLS context.
 * This includes setting the handshake properties that will later be
 * used during the TLS handshake.
 */
int picoquic_tlscontext_create(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t current_time)
{
    int ret = 0;
    /* allocate a context structure */
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)malloc(sizeof(picoquic_tls_ctx_t));

    /* Create the TLS context */
    if (ctx == NULL) {
        ret = -1;
    } else {
        memset(ctx, 0, sizeof(picoquic_tls_ctx_t));

        ctx->cnx = cnx;

        ctx->handshake_properties.collect_extension = picoquic_tls_collect_extensions_cb;
        ctx->handshake_properties.collected_extensions = picoquic_tls_collected_extensions_cb;
        ctx->client_mode = cnx->client_mode;

        ctx->tls = ptls_new((ptls_context_t*)quic->tls_master_ctx,
            (ctx->client_mode) ? 0 : 1);
        *ptls_get_data_ptr(ctx->tls) = cnx;

        if (ctx->tls == NULL) {
            free(ctx);
            ctx = NULL;
            ret = -1;
        } else if (!ctx->client_mode) {
            /* A server side connection, but no cert/key where given for the master context */
            if (((ptls_context_t*)quic->tls_master_ctx)->encrypt_ticket == NULL) {
                ret = PICOQUIC_ERROR_TLS_SERVER_CON_WITHOUT_CERT;
                picoquic_tlscontext_free(ctx);
                ctx = NULL;
            }

            if (ctx != NULL) {
                /* The server should never attempt a stateless retry */
                ctx->handshake_properties.server.enforce_retry = 0;
                ctx->handshake_properties.server.retry_uses_cookie = 0;
                ctx->handshake_properties.server.cookie.key = NULL;
                ctx->handshake_properties.server.cookie.additional_data.base = NULL;
                ctx->handshake_properties.server.cookie.additional_data.len = 0;
            }
        }
    }
    
    if (cnx->tls_ctx != NULL) {
        picoquic_tlscontext_free(cnx->tls_ctx);
    }

    cnx->tls_ctx = (void*)ctx;

    return ret;
}

/* Set the log event to record keys for use by Wireshark.
 */

static void picoquic_log_event_call_back(ptls_log_event_t *_self, ptls_t *tls, const char *type, const char *fmt, ...)
{
    struct st_picoquic_log_event_t *self = (struct st_picoquic_log_event_t*)_self;
    char randomhex[PTLS_HELLO_RANDOM_SIZE * 2 + 1];
    va_list args;

    if (self->fp != NULL) {
        ptls_hexdump(randomhex, ptls_get_client_random(tls).base, PTLS_HELLO_RANDOM_SIZE);
            fprintf(self->fp, "%s %s ", type, randomhex);

            va_start(args, fmt);
            vfprintf(self->fp, fmt, args);
            va_end(args);

            fprintf(self->fp, "\n");
            fflush(self->fp);
    }
}

/**
 * Free the log-event call back, either when the TLS master context is freed,
 * or when the key log file is reset.
 */
static void picoquic_free_log_event(picoquic_quic_t* quic)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    if (ctx->log_event != NULL) {
        struct st_picoquic_log_event_t* picoquic_log_event = (struct st_picoquic_log_event_t*)ctx->log_event;
        if (picoquic_log_event != NULL && picoquic_log_event->fp != NULL) {
            picoquic_file_close(picoquic_log_event->fp);
        }
        free(ctx->log_event);
        ctx->log_event = NULL;
    }
}


/**
 * Sets the output file handle for writing traffic secrets in a format that can
 * be recognized by Wireshark.
 */
void picoquic_set_key_log_file(picoquic_quic_t *quic, char const * keylog_filename)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    struct st_picoquic_log_event_t* log_event = (struct st_picoquic_log_event_t*)ctx->log_event;

    if (log_event == NULL) {
        log_event = (struct st_picoquic_log_event_t*)malloc(sizeof(struct st_picoquic_log_event_t));
        if (log_event != NULL) {
            log_event->super.cb = picoquic_log_event_call_back;
        }
    }
    else {
        if (log_event->fp != NULL) {
            picoquic_file_close(log_event->fp);
            log_event->fp = NULL;
        }
    }

    if (log_event != NULL) {
        log_event->fp = picoquic_file_open(keylog_filename, "a");
        log_event->super.cb = picoquic_log_event_call_back;
        ctx->log_event = (ptls_log_event_t*)log_event;
    }

    ctx->log_event = (ptls_log_event_t*)log_event;
}

/*
Check whether the ticket that was received, or used, authorizes 0-RTT data.

From TLS 1.3 spec:
struct {
uint32 ticket_lifetime;
uint32 ticket_age_add;
opaque ticket_nonce<0..255>;
opaque ticket<1..2^16-1>;
Extension extensions<0..2^16-2>;
} NewSessionTicket;

struct {
ExtensionType extension_type;
opaque extension_data<0..2^16-1>;
} Extension;
*/

int picoquic_does_tls_ticket_allow_early_data(uint8_t* ticket, uint16_t ticket_length)
{
    uint8_t nonce_length = 0;
    uint16_t ticket_val_length = 0;
    uint16_t extension_length = 0;
    uint8_t* extension_ptr = NULL;
    uint16_t byte_index = 0;
    uint16_t min_length = 4 + 4 + 1 + 2 + 2;
    int ret = 0;

    if (ticket_length >= min_length) {
        byte_index += 4; /* Skip lifetime */
        byte_index += 4; /* Skip age add */
        nonce_length = ticket[byte_index++];
        min_length += nonce_length;
        if (ticket_length >= min_length) {
            byte_index += nonce_length;

            ticket_val_length = PICOPARSE_16(ticket + byte_index);
            byte_index += 2;
            min_length += ticket_val_length;
            if (ticket_length >= min_length) {
                byte_index += ticket_val_length;

                extension_length = PICOPARSE_16(ticket + byte_index);
                byte_index += 2;
                min_length += extension_length;
                if (ticket_length >= min_length) {
                    extension_ptr = &ticket[byte_index];
                }
            }
        }
    }

    if (extension_ptr != NULL) {
        uint16_t x_index = 0;

        while (x_index + 4 < extension_length) {
            uint16_t x_type = PICOPARSE_16(extension_ptr + x_index);
            uint16_t x_len = PICOPARSE_16(extension_ptr + x_index + 2);
            x_index += 4 + x_len;

            if (x_type == 42 && x_len == 4) {
                uint32_t ed_len = PICOPARSE_32(extension_ptr + x_index - 4);
                if (ed_len == 0xFFFFFFFF) {
                    ret = 1;
                }
                break;
            }
        }
    }

    return ret;
}

/*
* Creation of a TLS context.
* This includes setting the handshake properties that will later be
* used during the TLS handshake.
*/
void picoquic_tlscontext_remove_ticket(picoquic_cnx_t* cnx)
{
    /* allocate a context structure */
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)(cnx->tls_ctx);

    ctx->handshake_properties.client.session_ticket.base = NULL;
    ctx->handshake_properties.client.session_ticket.len = 0;
}

void picoquic_tlscontext_free(void* vctx)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)vctx;
    if (ctx->tls != NULL) {
        ptls_free((ptls_t*)ctx->tls);
        ctx->tls = NULL;
    }
    free(ctx);
}

char const* picoquic_tls_get_negotiated_alpn(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;

    return ptls_get_negotiated_protocol(ctx->tls);
}

char const* picoquic_tls_get_sni(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;

    return ptls_get_server_name(ctx->tls);
}

int picoquic_tls_is_psk_handshake(picoquic_cnx_t* cnx)
{
    /* int ret = cnx->is_psk_handshake; */
    int ret = ptls_is_psk_handshake(((picoquic_tls_ctx_t*)(cnx->tls_ctx))->tls);
    return ret;
}


/*
* Sending data on the crypto stream.
*/

static int picoquic_add_to_tls_stream(picoquic_cnx_t* cnx, const uint8_t* data, size_t length, int epoch)
{
    int ret = 0;
    picoquic_stream_head_t* stream = &cnx->tls_stream[epoch];

    if (length > 0) {
        picoquic_stream_data_node_t* stream_data = (picoquic_stream_data_node_t*)malloc(sizeof(picoquic_stream_data_node_t));

        if (stream_data == 0) {
            ret = -1;
        }
        else {
            stream_data->bytes = (uint8_t*)malloc(length);

            if (stream_data->bytes == NULL) {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            }
            else {
                picoquic_stream_data_node_t** pprevious = &stream->send_queue;
                picoquic_stream_data_node_t* next = stream->send_queue;

                memcpy(stream_data->bytes, data, length);
                stream_data->length = length;
                stream_data->offset = 0;
                stream_data->next_stream_data = NULL;

                while (next != NULL) {
                    pprevious = &next->next_stream_data;
                    next = next->next_stream_data;
                }

                *pprevious = stream_data;
            }
        }
    }

    return ret;
}

/* Add a supported ALPN context */
int picoquic_add_proposed_alpn(void* tls_context, const char* alpn)
{
    int ret = 0;
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)tls_context;
    if (ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else if (ctx->alpn_count >= PICOQUIC_ALPN_NUMBER_MAX) {
        ret = PICOQUIC_ERROR_SEND_BUFFER_TOO_SMALL;
    } else {
        ctx->alpn_vec[ctx->alpn_count].base = (uint8_t*)alpn;
        ctx->alpn_vec[ctx->alpn_count].len = strlen(alpn);
        ctx->alpn_count++;
    }

    return ret;
}

/* Log OPENSSL errors */
void picoquic_log_openssl_errors(picoquic_cnx_t* cnx, int ret)
{
    unsigned long openssl_err;
    char const* err_file = NULL;
    int err_line = 0;

    while ((openssl_err = ERR_get_error_line(&err_file, &err_line)) != 0) {
        picoquic_log_app_message(cnx, "OpenSSL error: %lu, file %s, line %d", openssl_err,
            (err_file == NULL) ? "?" : err_file, err_line);
    }
    
    picoquic_log_app_message(cnx, "Picotls returns error: %d (0x%x)", ret, ret);
}

/* Prepare the initial message when starting a connection.
 */

int picoquic_initialize_tls_stream(picoquic_cnx_t* cnx, uint64_t current_time)
{
    int ret = 0;
    struct st_ptls_buffer_t sendbuf;
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    size_t epoch_offsets[PICOQUIC_NUMBER_OF_EPOCH_OFFSETS] = { 0, 0, 0, 0, 0 };

    if (cnx->sni != NULL) {
        ptls_set_server_name(ctx->tls, cnx->sni, strlen(cnx->sni));
    }

    if (cnx->alpn != NULL) {
        ctx->alpn_vec[0].base = (uint8_t*)cnx->alpn;
        ctx->alpn_vec[0].len = strlen(cnx->alpn);
        ctx->handshake_properties.client.negotiated_protocols.count = 1;
        ctx->handshake_properties.client.negotiated_protocols.list = ctx->alpn_vec;
    }
    else if (cnx->callback_fn != NULL) {
        /* Get the default ALPN list for the callback function */
        ret = cnx->callback_fn(cnx, 0, (uint8_t*)ctx, 0, picoquic_callback_request_alpn_list, cnx->callback_ctx, NULL);

        ctx->handshake_properties.client.negotiated_protocols.count = ctx->alpn_count;
        ctx->handshake_properties.client.negotiated_protocols.list = ctx->alpn_vec;

        if (ret != 0) {
            DBG_PRINTF("ALPN list callback returns 0x%x", ret);
        }
    }

    /* ALPN is mandatory, there should be at least one */
    if (ret == 0 && ctx->handshake_properties.client.negotiated_protocols.count == 0) {
        ret = PICOQUIC_ERROR_NO_ALPN_PROVIDED;
        DBG_PRINTF("No ALPN provided, error 0x%x", ret);
    }

    if (cnx->quic->F_log != NULL) {
        picoquic_log_negotiated_alpn(cnx->quic->F_log, cnx, 0, 1, ctx->handshake_properties.client.negotiated_protocols.list, ctx->handshake_properties.client.negotiated_protocols.count);
    }
    if (cnx->f_binlog != NULL) {
        binlog_transport_extension(cnx,
            1, (const uint8_t *)cnx->sni, (cnx->sni == NULL)?0:strlen(cnx->sni), NULL, 0,
            ctx->handshake_properties.client.negotiated_protocols.list, 
            ctx->handshake_properties.client.negotiated_protocols.count,
            0, NULL);
    }

    /* No resumption if no alpn specified upfront, because it would make the negotiation and
     * the handling of 0-RTT way too messy */
    if (cnx->sni != NULL && cnx->alpn != NULL && !cnx->quic->client_zero_share) {
        uint8_t* ticket = NULL;
        uint16_t ticket_length = 0;

        if (picoquic_get_ticket(cnx->quic->p_first_ticket, current_time,
            cnx->sni, (uint16_t)strlen(cnx->sni), cnx->alpn, (uint16_t)strlen(cnx->alpn),
            &ticket, &ticket_length, &cnx->remote_parameters, 1)
            == 0) {
            ctx->handshake_properties.client.session_ticket.base = ticket;
            ctx->handshake_properties.client.session_ticket.len = ticket_length;

            ctx->handshake_properties.client.max_early_data_size = &cnx->max_early_data_size;

            cnx->psk_cipher_suite_id = PICOPARSE_16(ticket + 8);
        }
    }

    if (cnx->quic->client_zero_share &&
        cnx->cnx_state == picoquic_state_client_init)
    {
        ctx->handshake_properties.client.negotiate_before_key_exchange = 1;
    }
    else
    {
        ctx->handshake_properties.client.negotiate_before_key_exchange = 0;
    }

    if (ret != 0) {
        DBG_PRINTF("Could not set up TLS parameters, error 0x%x, abandoning connection", ret);
        cnx->cnx_state = picoquic_state_disconnected;
    } else {
        picoquic_tls_set_extensions(cnx, ctx);

        ptls_buffer_init(&sendbuf, "", 0);

        /* Clearing the global error state of openssl before calling handle message.
         * This allows detection of errors during processing. */
        ERR_clear_error();
        ret = ptls_handle_message(ctx->tls, &sendbuf, epoch_offsets, 0, NULL, 0, &ctx->handshake_properties);

        /* assume that all the data goes to epoch 0, initial */
        if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS)) {
#ifdef PTLS_ESNI_NONCE_SIZE
            /* Find the ESNI secret if any, and copy key values to picoquic tls context */
            struct st_ptls_esni_secret_t* esni = ptls_get_esni_secret(ctx->tls);
            if (esni != NULL) {
                ctx->esni_version = esni->version;
                memcpy(ctx->esni_nonce, esni->nonce, PTLS_ESNI_NONCE_SIZE);
            }
#endif
            if (sendbuf.off > 0) {
                ret = picoquic_add_to_tls_stream(cnx, sendbuf.base, sendbuf.off, 0);
            }
            else {
                ret = 0;
            }
        }
        else {
            picoquic_log_openssl_errors(cnx, ret);
            ret = -1;
        }
        ptls_buffer_dispose(&sendbuf);
    }

    return ret;
}

/*
 * Packet number encryption and decryption utilities
 */

void * picoquic_pn_enc_create_for_test(const uint8_t * secret)
{
    ptls_cipher_suite_t cipher = { 0, &ptls_openssl_aes128gcm, &ptls_openssl_sha256 };
    void *v_pn_enc = NULL;
    
    (void)picoquic_set_pn_enc_from_secret(&v_pn_enc, &cipher, 1, secret);

    return v_pn_enc;
}

size_t picoquic_pn_iv_size(void *pn_enc)
{
    return ((ptls_cipher_context_t *)pn_enc)->algo->iv_size;
}

void picoquic_pn_encrypt(void *pn_enc, const void * iv, void *output, const void *input, size_t len)
{
    ptls_cipher_init((ptls_cipher_context_t *) pn_enc, iv);
    ptls_cipher_encrypt((ptls_cipher_context_t *) pn_enc, output, input, len);
}

/* Utility functions, so applications do not have to load picotls.h */

void picoquic_aead_free(void* aead_context)
{
    ptls_aead_free((ptls_aead_context_t*)aead_context);
}

size_t picoquic_aead_get_checksum_length(void* aead_context)
{
    size_t tag_size = ((ptls_aead_context_t*)aead_context)->algo->tag_size;
    /* TODO: remove this temporary fix to deal with Feb 2019 change in picotls */
    if (tag_size > 16) {
        tag_size = 16;
    }
    return tag_size;
}

/* Setting of encryption contexts for test */
void * picoquic_setup_test_aead_context(int is_encrypt, const uint8_t * secret)
{
    void * v_aead = NULL;
    ptls_cipher_suite_t cipher = { 0, &ptls_openssl_aes128gcm, &ptls_openssl_sha256 };

    (void)picoquic_set_aead_from_secret(&v_aead, &cipher, is_encrypt, secret);

    return v_aead;
}

int picoquic_server_setup_ticket_aead_contexts(picoquic_quic_t* quic,
    ptls_context_t* tls_ctx,
    const uint8_t* secret, size_t secret_length)
{
    int ret = 0;
    uint8_t temp_secret[256]; /* secret_max */
    ptls_cipher_suite_t cipher = { 0, &ptls_openssl_aes128gcm, &ptls_openssl_sha256 };

    if (cipher.hash->digest_size > sizeof(temp_secret)) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    } else {
        if (secret != NULL && secret_length > 0) {
            memset(temp_secret, 0, cipher.hash->digest_size);
            memcpy(temp_secret, secret, (secret_length > cipher.hash->digest_size) ? cipher.hash->digest_size : secret_length);
        } else {
            tls_ctx->random_bytes(temp_secret, cipher.hash->digest_size);
        }

        /* Create the AEAD contexts */
        ret = picoquic_set_aead_from_secret(&quic->aead_encrypt_ticket_ctx, &cipher, 1, temp_secret);
        if (ret == 0) {
            ret = picoquic_set_aead_from_secret(&quic->aead_decrypt_ticket_ctx, &cipher, 0, temp_secret);
        }

        /* erase the temporary secret */
        ptls_clear_memory(temp_secret, cipher.hash->digest_size);
    }
    return ret;
}

/* AEAD encrypt/decrypt routines */
size_t picoquic_aead_decrypt_generic(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_ctx)
{
    size_t decrypted = 0;

    if (aead_ctx == NULL) {
        decrypted = SIZE_MAX;
    } else {
        decrypted = ptls_aead_decrypt((ptls_aead_context_t*)aead_ctx,
            (void*)output, (const void*)input, input_length, seq_num,
            (void*)auth_data, auth_data_length);
    }

    return decrypted;
}

size_t picoquic_aead_encrypt_generic(uint8_t* output, const uint8_t* input, size_t input_length,
    uint64_t seq_num, const uint8_t* auth_data, size_t auth_data_length, void* aead_context)
{
    size_t encrypted = 0;

    encrypted = ptls_aead_encrypt((ptls_aead_context_t*)aead_context,
        (void*)output, (const void*)input, input_length, seq_num,
        (void*)auth_data, auth_data_length);

    return encrypted;
}

/* management of version specific salt, for initial packet encryption.
 */

uint8_t picoquic_cleartext_null_salt[] = {
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0
};

static void picoquic_setup_cleartext_aead_salt(size_t version_index, ptls_iovec_t* salt)
{
    if (picoquic_supported_versions[version_index].version_aead_key != NULL && picoquic_supported_versions[version_index].version_aead_key_length > 0) {
        salt->base = picoquic_supported_versions[version_index].version_aead_key;
        salt->len = picoquic_supported_versions[version_index].version_aead_key_length;
    } else {
        salt->base = picoquic_cleartext_null_salt;
        salt->len = sizeof(picoquic_cleartext_null_salt);
    }
}

#if 0
/* TODO: find a replacement for this test. */
/* Compare AEAD context parameters. This is done just by comparing the IV,
 * which is accessible in the context */
int picoquic_compare_cleartext_aead_contexts(picoquic_cnx_t* cnx1, picoquic_cnx_t* cnx2)
{
    int ret = 0;
    ptls_aead_context_t * aead_enc = (ptls_aead_context_t *)cnx1->crypto_context[0].aead_encrypt;
    ptls_aead_context_t * aead_dec = (ptls_aead_context_t *)cnx2->crypto_context[0].aead_decrypt;

    if (aead_enc == NULL )
    {
        DBG_PRINTF("%s", "Missing aead encoding context\n");
        ret = -1;
    }
    else if (aead_dec == NULL)
    {
        DBG_PRINTF("%s", "Missing aead decoding context\n");
        ret = -1;
    }
    else if (memcmp(aead_enc->static_iv, aead_dec->static_iv, 16) != 0){
        DBG_PRINTF("%s", "Encoding IV does not match decoding IV\n");
        ret = -1;
    }

    return ret;
}
#endif

/* Input stream zero data to TLS context.
 *
 * Processing  depends on the "epoch" in which packets have been received. That
 * epoch is be passed through the ptls_handle_message() API.
 * The API has an "epoch offset" parameter that documents how many bytes of the
 * should be sent at each epoch.
 */

int picoquic_tls_stream_process(picoquic_cnx_t* cnx)
{
    int ret = 0;
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    size_t next_epoch = 0;

    /* Provide indication of current connection for later callbacks */
    cnx->quic->cnx_in_progress = cnx;

    for (size_t epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS && ret == 0; epoch++) {
        picoquic_stream_head_t* stream = &cnx->tls_stream[epoch];
        picoquic_stream_data_node_t* data = (picoquic_stream_data_node_t*)picosplay_first(&stream->stream_data_tree);
        size_t processed = 0;
        int data_pushed = 0;

        next_epoch = ptls_get_read_epoch(ctx->tls);

        if (epoch != next_epoch) {
            if (epoch > next_epoch) {
                break;
            } else {
                if (data != NULL && data->offset > stream->consumed_offset) {
                    /* Protocol error: data received that could not be read */
#ifdef _DEBUG
                    DBG_PRINTF("Connection error - TLS data at epoch %d, expected %d.\n",
                        epoch, next_epoch);
#endif
                    ret = picoquic_connection_error(cnx,
                        PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
                }
                continue;
            }
        }

        while ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS) &&
            data != NULL && data->offset <= stream->consumed_offset) {
            struct st_ptls_buffer_t sendbuf;
            size_t start = (size_t)(stream->consumed_offset - data->offset);
            size_t epoch_data = data->length - start;
            size_t send_offset[PICOQUIC_NUMBER_OF_EPOCH_OFFSETS] = { 0, 0, 0, 0, 0 };

            ptls_buffer_init(&sendbuf, "", 0);

            /* Clearing the global error state of openssl before calling handle message.
             * This allows detection of errors during processing. */
            ERR_clear_error();

            ret = ptls_handle_message(ctx->tls, &sendbuf, send_offset, epoch,
                data->bytes + start, epoch_data, &ctx->handshake_properties);

#ifdef _DEBUG
            if (cnx->cnx_state < picoquic_state_ready) {
                DBG_PRINTF("State: %d, tls input: %d, ret 0x%x\n",
                    cnx->cnx_state, epoch_data, ret);
            }
#endif
            if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS ||
                ret == PTLS_ERROR_STATELESS_RETRY)) {
                for (int i = 0; i < PICOQUIC_NUMBER_OF_EPOCHS; i++) {
                    if (send_offset[i] < send_offset[i + 1]) {
                        data_pushed = 1;
                        ret = picoquic_add_to_tls_stream(cnx,
                            sendbuf.base + send_offset[i], send_offset[i + 1] - send_offset[i], i);
                    }
                }
                if (cnx->client_mode) {
                    if (cnx->alpn == NULL) {
                        const char* alpn = ptls_get_negotiated_protocol(ctx->tls);

                        if (alpn != NULL){
                            cnx->alpn = picoquic_string_duplicate(alpn);

                            if (cnx->f_binlog != NULL) {
                                binlog_transport_extension(cnx, 0, NULL, 0, 
                                    (const uint8_t *)alpn, strlen(alpn), NULL, 0, 0, NULL);
                            }

                            if (cnx->callback_fn != NULL) {
                                cnx->callback_fn(cnx, 0, (uint8_t*)alpn, 0, picoquic_callback_set_alpn, cnx->callback_ctx, NULL);
                            }
                            else {
                                DBG_PRINTF("Negotiated ALPN: %s", alpn);
                            }
                        }
                    }
                    switch (ctx->handshake_properties.client.early_data_acceptance) {
                    case PTLS_EARLY_DATA_REJECTED:
                        cnx->zero_rtt_data_accepted = 0;
                        break;
                    case PTLS_EARLY_DATA_ACCEPTED:
                        cnx->zero_rtt_data_accepted = 1;
                        break;
                    default:
                        break;
                    }
                }
            }
            else {
                picoquic_log_openssl_errors(cnx, ret);
            }

            stream->consumed_offset += epoch_data;
            processed += epoch_data;

            if (start + epoch_data >= data->length) {
                picosplay_delete_hint(&cnx->tls_stream[epoch].stream_data_tree, &data->stream_data_node);
                data = (picoquic_stream_data_node_t*)picosplay_first(&cnx->tls_stream[epoch].stream_data_tree);
            }

            ptls_buffer_dispose(&sendbuf);
        }

        if (processed > 0) {
            if (ret == 0) {
                switch (cnx->cnx_state) {
                case picoquic_state_client_retry_received:
                    /* This is not supposed to happen -- HRR should generate "error in progress" */
                    break;
                case picoquic_state_client_init:
                case picoquic_state_client_init_sent:
                case picoquic_state_client_renegotiate:
                case picoquic_state_client_init_resent:
                case picoquic_state_client_handshake_start:
                    if (ptls_handshake_is_complete(ctx->tls)) {
                        if (cnx->remote_parameters_received == 0) {

#ifdef _DEBUG
                            DBG_PRINTF("%s", "Connection error - no transport parameter received.\n");
#endif
                            ret = picoquic_connection_error(cnx,
                                PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        else {
                            if (cnx->crypto_context[3].aead_encrypt != NULL) {
                                cnx->cnx_state = picoquic_state_client_almost_ready;
                            }
                        }
                    }
                    break;
                case picoquic_state_server_init:
                case picoquic_state_server_handshake:
                    /* If client authentication is activated, the client sends the certificates with its `Finished` packet.
                       The server does not send any further packets, so, we can switch into false start state here.
                    */
                    if (data_pushed == 0 && ((ptls_context_t*)cnx->quic->tls_master_ctx)->require_client_authentication == 1) {
                        cnx->cnx_state = picoquic_state_server_false_start;

                        /* On a server that does address validation, send a NEW TOKEN frame */
                        if (!cnx->client_mode && (cnx->quic->check_token||cnx->quic->provide_token)) {
                            uint8_t token_buffer[256];
                            size_t token_size;
                            picoquic_connection_id_t n_cid = picoquic_null_connection_id;

                            if (picoquic_prepare_retry_token(cnx->quic, (struct sockaddr *)&cnx->path[0]->peer_addr,
                                picoquic_get_quic_time(cnx->quic) + PICOQUIC_TOKEN_DELAY_LONG, &n_cid, &n_cid,
                                token_buffer, sizeof(token_buffer), &token_size) == 0) {
                                if (picoquic_queue_new_token_frame(cnx, token_buffer, token_size) != 0) {
                                    picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, picoquic_frame_type_new_token);
                                }
                            }
                        }
                    }
                    else {
                        if (cnx->crypto_context[3].aead_encrypt != NULL) {
                            cnx->cnx_state = picoquic_state_server_almost_ready;
                        }
                    }
                    break;
                case picoquic_state_client_almost_ready:
                case picoquic_state_handshake_failure:
                case picoquic_state_handshake_failure_resend:
                case picoquic_state_client_ready_start:
                case picoquic_state_server_almost_ready:
                case picoquic_state_server_false_start:
                case picoquic_state_ready:
                case picoquic_state_disconnecting:
                case picoquic_state_closing_received:
                case picoquic_state_closing:
                case picoquic_state_draining:
                case picoquic_state_disconnected:
                    break;
                default:
                    DBG_PRINTF("Unexpected connection state: %d\n", cnx->cnx_state);
                    break;
                }
            }
            else if (ret == PTLS_ERROR_IN_PROGRESS && (cnx->cnx_state == picoquic_state_client_init || cnx->cnx_state == picoquic_state_client_init_sent || cnx->cnx_state == picoquic_state_client_init_resent)) {
                /* Extract and install the client 0-RTT key */
#ifdef _DEBUG
                DBG_PRINTF("%s", "Handshake not yet complete.\n");
#endif
            }
            else if (ret == PTLS_ERROR_IN_PROGRESS &&
                (cnx->cnx_state == picoquic_state_server_init ||
                    cnx->cnx_state == picoquic_state_server_handshake))
            {
                if (ptls_handshake_is_complete(ctx->tls))
                {
                    cnx->cnx_state = picoquic_state_server_almost_ready;
                }
            }

            if ((ret == 0 || ret == PTLS_ERROR_IN_PROGRESS || ret == PTLS_ERROR_STATELESS_RETRY)) {
                ret = 0;
            }
            else {
                uint16_t error_code = PICOQUIC_TRANSPORT_INTERNAL_ERROR;

                if (PTLS_ERROR_GET_CLASS(ret) == PTLS_ERROR_CLASS_SELF_ALERT) {
                    error_code = PICOQUIC_TRANSPORT_CRYPTO_ERROR(ret);
                }
#ifdef _DEBUG
                DBG_PRINTF("Handshake failed, ret = 0x%x.\n", ret);
#endif
                (void)picoquic_connection_error(cnx, error_code, 0);
                ret = 0;
            }
        }
    }


    /* Reset indication of current connection */
    cnx->quic->cnx_in_progress = NULL;

    return ret;
}

/*
 * Test whether the TLS handshake is complete according to TLS stack
 */
int picoquic_is_tls_complete(picoquic_cnx_t* cnx)
{
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    return ptls_handshake_is_complete(ctx->tls);
}

/*
 * Compute the 16 byte reset secret associated with a connection ID.
 * We implement it as the hash of a secret seed maintained per QUIC context
 * and the 8 bytes connection ID.
 * This is written using PTLS portable hash API, initialized
 * for now with the OpenSSL implementation. Will have to adapt if we
 * decide to use the minicrypto API.
 */

int picoquic_create_cnxid_reset_secret(picoquic_quic_t* quic, picoquic_connection_id_t * cnx_id,
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE])
{
    /* Using OpenSSL for now: ptls_hash_algorithm_t ptls_openssl_sha256 */
    int ret = 0;
    ptls_hash_algorithm_t* algo = &ptls_openssl_sha256;
    ptls_hash_context_t* hash_ctx = algo->create();
    uint8_t final_hash[PTLS_MAX_DIGEST_SIZE];

    if (hash_ctx == NULL) {
        ret = -1;
        memset(reset_secret, 0, PICOQUIC_RESET_SECRET_SIZE);
    } else {
        hash_ctx->update(hash_ctx, quic->reset_seed, sizeof(quic->reset_seed));
        hash_ctx->update(hash_ctx, cnx_id, sizeof(picoquic_connection_id_t));
        hash_ctx->final(hash_ctx, final_hash, PTLS_HASH_FINAL_MODE_FREE);
        memcpy(reset_secret, final_hash, PICOQUIC_RESET_SECRET_SIZE);
    }

    return (ret);
}

void picoquic_set_tls_certificate_chain(picoquic_quic_t* quic, ptls_iovec_t* certs, size_t count)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;

    free_certificates_list(ctx->certificates.list, ctx->certificates.count);

    ctx->certificates.list = certs;
    ctx->certificates.count = count;
}

int picoquic_set_tls_root_certificates(picoquic_quic_t* quic, ptls_iovec_t* certs, size_t count)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    ptls_openssl_verify_certificate_t* verify_ctx = (ptls_openssl_verify_certificate_t*)ctx->verify_certificate;

    for (size_t i = 0; i < count; ++i) {
        X509* cert = d2i_X509(NULL, (const uint8_t**)&certs[i].base, (long)certs[i].len);

        if (cert == NULL) {
            return -1;
        }

        if (X509_STORE_add_cert(verify_ctx->cert_store, cert) == 0) {
            X509_free(cert);
            return -2;
        }

        quic->is_cert_store_not_empty = 1;

        X509_free(cert);
    }

    return 0;
}

int picoquic_set_tls_key(picoquic_quic_t* quic, const uint8_t* data, size_t len)
{
    ptls_context_t* ctx = (ptls_context_t*)quic->tls_master_ctx;
    if (ctx->sign_certificate != NULL) {
        ptls_openssl_dispose_sign_certificate((ptls_openssl_sign_certificate_t*)ctx->sign_certificate);
        ctx->sign_certificate = NULL;
    }

    return set_sign_certificate_from_key(d2i_AutoPrivateKey(NULL, &data, (long)len), ctx);
}

void picoquic_tls_set_client_authentication(picoquic_quic_t* quic, int client_authentication) {
    ((ptls_context_t*)quic->tls_master_ctx)->require_client_authentication = client_authentication;
}

int picoquic_tls_client_authentication_activated(picoquic_quic_t* quic) {
    return ((ptls_context_t*)quic->tls_master_ctx)->require_client_authentication;
}

/* 
 * Create or verify a token. Tokens are tied to an IP address and a time of
 * issue, and come in two variations:
 * - specific tokens are tied to an Original DCID.
 * - generic tokens work with a zero length DCID.
 * The structure of the token is:
 * - time valid until: uint64_t
 * - ODCID length, one byte
 * - ODCID, length bytes
 * This is encrypted using the same AEAD contexts as the encryption of session tickets.
 * The encrypted structure is:
 * - 64 bit random sequence number.
 * - Encrypted value of the token.
 * - AEAD checksum.
 * When invoking AEAD, the sequence number is used to update the IV, and the IP address
 * is passed as "authenticated" data. The 64 bit random number alleviates the concern of
 * reusing the same AEAD key twice. The authenticated data ensures that if the token is
 * used from a different address, the decryption will fail.
 */

static int picoquic_server_encrypt_retry_token(picoquic_quic_t * quic, const struct sockaddr * addr_peer,
    uint8_t * token, size_t * token_length, size_t token_max, const uint8_t * text, size_t text_length)
{
    int ret = 0;
    uint64_t sequence;
    uint8_t* auth_data;
    size_t auth_data_length;

    if (text_length + 1u + 16u > token_max) {
        ret = -1;
        *token_length = 0;
    }
    else {

        if (addr_peer->sa_family == AF_INET) {
            auth_data = (uint8_t*)&((struct sockaddr_in*)addr_peer)->sin_addr;
            auth_data_length = 4;
        }
        else {
            auth_data = (uint8_t*)&((struct sockaddr_in6*)addr_peer)->sin6_addr;
            auth_data_length = 16;
        }
        picoquic_crypto_random(quic, token, 8);
        sequence = PICOPARSE_64(token);

        *token_length = (size_t)8u + picoquic_aead_encrypt_generic(token + 8, text, text_length,
            sequence, auth_data, auth_data_length, quic->aead_encrypt_ticket_ctx);
    }

    return ret;
}

int picoquic_server_decrypt_retry_token(picoquic_quic_t* quic, const struct sockaddr * addr_peer,
    const uint8_t * token, size_t token_length, uint8_t * text, size_t *text_length)
{
    int ret = 0;
    uint64_t sequence;
    uint8_t* auth_data;
    size_t auth_data_length;

    if (addr_peer->sa_family == AF_INET) {
        auth_data = (uint8_t*)&((struct sockaddr_in *)addr_peer)->sin_addr;
        auth_data_length = 4;
    }
    else {
        auth_data = (uint8_t*)&((struct sockaddr_in6 *)addr_peer)->sin6_addr;
        auth_data_length = 16;
    }

    if (token_length < 8) {
        ret = -1;
    }
    else {
        sequence = PICOPARSE_64(token);

        *text_length = picoquic_aead_decrypt_generic(text, token+8, token_length-8,
            sequence, auth_data, auth_data_length, quic->aead_decrypt_ticket_ctx);
        if (*text_length >= token_length - 8) {
            ret = -1;
        }
    }

    return ret;
}

int picoquic_prepare_retry_token(picoquic_quic_t* quic, const struct sockaddr* addr_peer,
    uint64_t current_time, const picoquic_connection_id_t* odcid, const picoquic_connection_id_t* rcid,
    uint8_t* token, size_t token_max, size_t* token_size)
{
    int ret = 0;
    uint8_t text[128];
    uint64_t token_time = current_time;
    uint8_t* bytes = text;
    uint8_t* bytes_max = text + sizeof(text);

    /* set a short life time for short lived tokens, 24 hours otherwise */
    if (odcid->id_len == 0) {
        token_time += 24ull * 3600ull * 1000000ull;
    }
    else {
        token_time += 4000000ull;
    }
    /* serialize the token components */
    if ((bytes = picoquic_frames_uint64_encode(bytes, bytes_max, token_time)) != NULL &&
        (bytes = picoquic_frames_cid_encode(bytes, bytes_max, odcid)) != NULL &&
        (bytes = picoquic_frames_cid_encode(bytes, bytes_max, rcid)) != NULL) {
        /* Pad to min token size */
        while (bytes < text + PICOQUIC_RETRY_TOKEN_PAD_SIZE) {
            *bytes++ = 0;
        }
        /* Encode the clear text components */
        ret = picoquic_server_encrypt_retry_token(quic, addr_peer, token, token_size, token_max, text, bytes - text);
    }
    else {
        ret = -1;
    }

    return ret;
}

int picoquic_verify_retry_token(picoquic_quic_t* quic, const struct sockaddr * addr_peer,
    uint64_t current_time, picoquic_connection_id_t * odcid, const picoquic_connection_id_t* rcid,
    const uint8_t * token, size_t token_size, int new_context_created)
{
    int ret = 0;
    uint8_t text[128];
    size_t text_len = 0;
    picoquic_connection_id_t cid;

    odcid->id_len = 0;

    /* decode the encrypted token */
    ret = picoquic_server_decrypt_retry_token(quic, addr_peer, token, token_size,
        text, &text_len);

    if (ret == 0) {
        /* Decode the clear text components */
        uint8_t* bytes = text;
        uint8_t* bytes_max = text + text_len;
        uint64_t token_time = PICOPARSE_64(text);

        if ((bytes = picoquic_frames_uint64_decode(bytes, bytes_max, &token_time)) != NULL &&
            (bytes = picoquic_frames_cid_decode(bytes, bytes_max, odcid)) != NULL &&
            (bytes = picoquic_frames_cid_decode(bytes, bytes_max, &cid)) != NULL) {
            if (token_time < current_time) {
                /* Invalid token, too old */
                ret = -1;
            }
            else {
                /* Remove old tickets before testing this one. */
                picoquic_registered_token_clear(quic, current_time);
                if (new_context_created && (ret = picoquic_registered_token_check_reuse(quic, token, token_size, token_time)) != 0) {
                    picoquic_log_context_free_app_message(quic, rcid, "Duplicate token test returns %d", ret);
                }
                else if (odcid->id_len > 0 &&
                    picoquic_compare_connection_id(rcid, &cid) != 0) {
                    /* Invalid token, bad rcid */
                    ret = -1;
                }
            }
        }
        else {
            *odcid = picoquic_null_connection_id;
        }
    }

    return ret;
}

/*
 * Encryption functions for CID encryption
 */

void picoquic_cid_free_under_mask_ctx(void * v_cid_enc)
{
    if (v_cid_enc != NULL) {
        ptls_cipher_free((ptls_cipher_context_t *)v_cid_enc);
    }
}

int picoquic_cid_get_under_mask_ctx(void ** v_cid_enc, const void *secret)
{
    uint8_t cidkey[PTLS_MAX_SECRET_SIZE];
    uint8_t long_secret[PTLS_MAX_DIGEST_SIZE];
    ptls_cipher_suite_t cipher = { 0, &ptls_openssl_aes128gcm, &ptls_openssl_sha256 };
    int ret;

    picoquic_cid_free_under_mask_ctx(*v_cid_enc);
    *v_cid_enc = NULL;
    /* Secret is only guaranteed to be 16 bytes long. Avoid excess length issues */
    memset(long_secret, 0, sizeof(long_secret));
    memcpy(long_secret, secret, 16);

    if ((ret = ptls_hkdf_expand_label(cipher.hash, cidkey,
        cipher.aead->ctr_cipher->key_size, ptls_iovec_init(long_secret, cipher.hash->digest_size),
        PICOQUIC_LABEL_CID, ptls_iovec_init(NULL, 0), PICOQUIC_LABEL_QUIC_KEY_BASE)) == 0) {
#ifdef _DEBUG
        DBG_PRINTF("CID Encryption key (%d):\n", (int)cipher.aead->ctr_cipher->key_size);
        debug_dump(cidkey, (int)cipher.aead->ctr_cipher->key_size);
#endif
        if ((*v_cid_enc = ptls_cipher_new(cipher.aead->ctr_cipher, 1, cidkey)) == NULL) {
            ret = PTLS_ERROR_NO_MEMORY;
        }
    }

    return ret;
}

void picoquic_cid_encrypt_under_mask(void *cid_enc, const picoquic_connection_id_t * cid_in, const picoquic_connection_id_t * mask,
    picoquic_connection_id_t * cid_out)
{
    uint8_t unmasked[18];
    uint8_t val[18];

    memset(unmasked, 0, 18);
    memset(val, 0, 18);

    for (uint8_t i = 0; i < cid_in->id_len; i++) {
        /* retain only the random bits */
        unmasked[i] = cid_in->id[i] & mask->id[i];
    }

    ptls_cipher_init((ptls_cipher_context_t *)cid_enc, unmasked);
    ptls_cipher_encrypt((ptls_cipher_context_t *)cid_enc, val, val, cid_in->id_len);

    for (uint8_t i = 0; i < cid_in->id_len; i++) {
        /* randomize the unmasked bits */
        cid_out->id[i] = cid_in->id[i]^(val[i] & ~mask->id[i]);
    }
    cid_out->id_len = cid_in->id_len;
    if (cid_out->id_len < 18) {
        memset(cid_out->id + cid_out->id_len, 0, 18 - cid_out->id_len);
    }
}

void picoquic_cid_decrypt_under_mask(void *cid_enc, const picoquic_connection_id_t * cid_in, const picoquic_connection_id_t * mask,
    picoquic_connection_id_t * cid_out)
{
    picoquic_cid_encrypt_under_mask(cid_enc, cid_in, mask, cid_out);
}
#if 0
void picoquic_cid_free_encrypt_global_ctx(void ** v_cid_enc)
{
    if (v_cid_enc != NULL) {
        ptls_cipher_free((ptls_cipher_context_t *)v_cid_enc);
    }
}
#endif

/* Support for encrypted SNI (ESNI).
 */

/* Load the ESNI exchange keys. This function must be called at least once
 * before setting up ESNI for the server. 
 * esni_key_elements should be declared as an array of ptls_key_exchange_context_t*
 * of size less than *esni_key_count.
 * The last element in the array should be a NULL pointer.
 */

int picoquic_esni_load_key(picoquic_quic_t * quic, char const * esni_key_file_name)
{
    EVP_PKEY *pkey = NULL;
    int ret = 0;
    size_t esni_key_exchange_count = 0;
    
    while (esni_key_exchange_count < 15 &&
        quic->esni_key_exchange[esni_key_exchange_count] != 0)
        esni_key_exchange_count++;

    if (quic->esni_key_exchange[esni_key_exchange_count] != 0) {
        DBG_PRINTF("Too many ESNI private key file, %zu already\n", esni_key_exchange_count);
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
#if 0
    }
    else if ((fp = picoquic_file_open(esni_key_file_name, "rt")) == NULL) {
        DBG_PRINTF("failed to open ESNI private key file:%s\n", esni_key_file_name);
        ret = PICOQUIC_ERROR_INVALID_FILE;
    }
    else {
        if ((pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL)) == NULL) {
            DBG_PRINTF("failed to load private key from file:%s\n", picoquic_file_open);
            ret = PICOQUIC_ERROR_INVALID_FILE;
        }
        else {
#else
    } else {
        BIO* bio = BIO_new_file(esni_key_file_name, "rb");
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (pkey == NULL) {
            DBG_PRINTF("%s", "failed to load private key");
            ret = PICOQUIC_ERROR_INVALID_FILE;
        } else {
#endif
            quic->esni_key_exchange[esni_key_exchange_count] = (ptls_key_exchange_context_t*)malloc(sizeof(ptls_key_exchange_context_t));
            if (quic->esni_key_exchange[esni_key_exchange_count] == NULL) {
                DBG_PRINTF("%s", "no memory for ESNI private key\n");
                ret = PICOQUIC_ERROR_MEMORY;
            } else if ((ret = ptls_openssl_create_key_exchange(&quic->esni_key_exchange[esni_key_exchange_count], pkey)) != 0) {
                DBG_PRINTF("failed to load private key from file:%s:picotls-error:%d", esni_key_file_name, ret);
                ret = PICOQUIC_ERROR_INVALID_FILE;
                free(quic->esni_key_exchange[esni_key_exchange_count]);
                quic->esni_key_exchange[esni_key_exchange_count] = NULL;
            }
            else {
                EVP_PKEY_free(pkey);
            }
#if 0
            fp = picoquic_file_close(fp);
#endif
        }
#if 1
        BIO_free(bio);
#endif
    }

    return ret;
}

int picoquic_esni_load_rr(char const * esni_rr_file_name, uint8_t *esnikeys, size_t esnikeys_max, size_t *esnikeys_len)
{
    FILE * fp = NULL;
    int ret = 0;

    *esnikeys_len = 0;

    if ((fp = picoquic_file_open(esni_rr_file_name, "rb")) == NULL) {
        fprintf(stderr, "failed to open file:%s\n", esni_rr_file_name);
        ret = PICOQUIC_ERROR_INVALID_FILE;
    }
    else {
        *esnikeys_len = fread(esnikeys, 1, esnikeys_max, fp);
        if (*esnikeys_len == 0 || !feof(fp)) {
            DBG_PRINTF("failed to load ESNI data from file:%s\n", esni_rr_file_name);
        }
        (void)picoquic_file_close(fp);
    }

    return ret;
}

/* Setup ESNI by providing a set of RRDATA for the specified context.
 * The "esni_rr_file_name" file contains the RRDATA of _ESNI RR published for the service in the DNS.
 * The "esni_key_elements" contains a null terminated array of ptls_key_exchange_context_t* 
 * TODO: in theory, it should be possible to support multuple ESNI contexts in a single server.
 * This would require repeated calls to the "init context" API, and an esni vector
 * containing a longer null terminated list of esni pointers.
 */

static const size_t picoquic_esnikeys_max_rr = 65536;

int picoquic_esni_server_setup(picoquic_quic_t * quic, char const * esni_rr_file_name)
{
    uint8_t * esnikeys = malloc(picoquic_esnikeys_max_rr);
    size_t esnikeys_len;
    ptls_context_t *ctx = (ptls_context_t *)quic->tls_master_ctx;
    int ret = 0;

    if (esnikeys != NULL) {
        /* read esnikeys */
        ret = picoquic_esni_load_rr(esni_rr_file_name, esnikeys, picoquic_esnikeys_max_rr, &esnikeys_len);

        /* Install the ESNI data in the server context */
        if (ret == 0) {
            ctx->esni = malloc(sizeof(*ctx->esni) * 2);

            if (ctx->esni != NULL) {
                ctx->esni[1] = NULL;
                ctx->esni[0] = malloc(sizeof(**ctx->esni));
            }

            if (ctx->esni == NULL || ctx->esni[0] == NULL) {
                DBG_PRINTF("%s", "no memory for SNI allocation.\n");
                ret = PICOQUIC_ERROR_MEMORY;
            }
            else {
                if ((ret = ptls_esni_init_context(ctx, ctx->esni[0], ptls_iovec_init(esnikeys, esnikeys_len), quic->esni_key_exchange)) != 0) {
                    DBG_PRINTF("failed to parse ESNI data of file:%s:error=%d\n", esni_rr_file_name, ret);
                }
            }
        }
        free(esnikeys);
    }
    else {
        DBG_PRINTF("failed to allocate memory(%zu) for parsing esni record\n", picoquic_esnikeys_max_rr);
        ret = PICOQUIC_ERROR_MEMORY;
    }

    return ret;
}

/* Setup the client side ESNI record, prior to using ESNI in a connection attempt. 
 */
int picoquic_esni_client_from_file(picoquic_cnx_t * cnx, char const * esni_rr_file_name)
{
    int ret = 0;
    picoquic_tls_ctx_t* ctx = (picoquic_tls_ctx_t*)cnx->tls_ctx;
    uint8_t* esnikeys = malloc(picoquic_esnikeys_max_rr);
    size_t esnikeys_len;

    if (esnikeys != NULL) {
        /* read esnikeys */
        ret = picoquic_esni_load_rr(esni_rr_file_name, esnikeys, picoquic_esnikeys_max_rr, &esnikeys_len);

        if (ret == 0 && esnikeys_len > 0 && esnikeys_len <= picoquic_esnikeys_max_rr){
            ctx->handshake_properties.client.esni_keys.base = (uint8_t*)malloc(esnikeys_len);
            if (ctx->handshake_properties.client.esni_keys.base == NULL) {
                ctx->handshake_properties.client.esni_keys.len = 0;
                DBG_PRINTF("%s", "no memory for SNI allocation.\n");
                ret = PICOQUIC_ERROR_MEMORY;
            }
            else {
                ctx->handshake_properties.client.esni_keys.len = esnikeys_len;
                memcpy(ctx->handshake_properties.client.esni_keys.base, esnikeys, esnikeys_len);
            }
        }
        else {
            ctx->handshake_properties.client.esni_keys.len = 0;
            ctx->handshake_properties.client.esni_keys.base = NULL;
            if (ret != 0) {
                ret = PICOQUIC_ERROR_INVALID_FILE;
            }
        }
        free(esnikeys);
    }
    else {
        DBG_PRINTF("failed to allocate memory(%zu) for parsing esni record\n", picoquic_esnikeys_max_rr);
        ret = PICOQUIC_ERROR_MEMORY;
    }

    return ret;
}

/**
 * Access to ESNI data for tests
 */

uint16_t picoquic_esni_version(picoquic_cnx_t * cnx)
{
    return(((picoquic_tls_ctx_t*)cnx->tls_ctx)->esni_version);
}

uint8_t * picoquic_esni_nonce(picoquic_cnx_t * cnx)
{
    return(((picoquic_tls_ctx_t*)cnx->tls_ctx)->esni_nonce);
}

/* Export hash functions so applications do not need to access picotls */

void* picoquic_hash_create(char const* algorithm_name) {
    ptls_hash_context_t* ctx;

    if (strcmp(algorithm_name, "SHA256") == 0) {
        ctx = ptls_openssl_sha256.create();
    }
    else if (strcmp(algorithm_name, "SHA384") == 0) {
        ctx = ptls_openssl_sha384.create();
    }
    else {
        ctx = NULL;
    }

    return (void*)ctx;
}

size_t picoquic_hash_get_length(char const* algorithm_name) {
    size_t len;

    if (strcmp(algorithm_name, "SHA256") == 0) {
        len = ptls_openssl_sha256.digest_size;
    }
    else if (strcmp(algorithm_name, "SHA384") == 0) {
        len = ptls_openssl_sha384.digest_size;
    }
    else {
        len = 0;
    }

    return len;
}

void picoquic_hash_update(uint8_t* input, size_t input_length, void* hash_context) {
    ((ptls_hash_context_t * )hash_context)->update((ptls_hash_context_t*)hash_context, input, input_length);
}

void picoquic_hash_finalize(uint8_t* output, void* hash_context) {
    ((ptls_hash_context_t*)hash_context)->final((ptls_hash_context_t*)hash_context, output, PTLS_HASH_FINAL_MODE_FREE);
}

/* Retry Packet Protection.
 * This is done by applying AES-GCM128 with a constant key and a NULL nonce,
 * using an extension of the retry packet as authenticated data and a zero
 * length content, computing a 16 bytes checksum. Or verifying it in the
 * other direction.
 *
 * The retry protection key is stored in the Quic context. It is created on
 * first use, and deleted when the context is deleted.
 */

void * picoquic_create_retry_protection_context(int is_enc, uint8_t * key)
{
    return (void *)picoquic_setup_test_aead_context(is_enc, key);
}

void * picoquic_find_retry_protection_context(picoquic_cnx_t * cnx, int sending)
{
    void * aead_ctx = NULL;
    void ** aead_vector = (sending) ? cnx->quic->retry_integrity_sign_ctx : cnx->quic->retry_integrity_verify_ctx;

    if (picoquic_supported_versions[cnx->version_index].version_retry_key != NULL) {
        if (aead_vector == NULL) {
            if (sending) {
                cnx->quic->retry_integrity_sign_ctx = (void**)malloc(sizeof(void*)*picoquic_nb_supported_versions);
                aead_vector = cnx->quic->retry_integrity_sign_ctx;
            }
            else {
                cnx->quic->retry_integrity_verify_ctx = (void**)malloc(sizeof(void*)*picoquic_nb_supported_versions);
                aead_vector = cnx->quic->retry_integrity_verify_ctx;
            }
            if (aead_vector != NULL) {
                memset(aead_vector, 0, sizeof(void*)*picoquic_nb_supported_versions);
            }
        }

        if (aead_vector != NULL) {
            aead_ctx = aead_vector[cnx->version_index];
            if (aead_ctx == NULL) {
                aead_ctx = picoquic_create_retry_protection_context(sending, picoquic_supported_versions[cnx->version_index].version_retry_key);
                aead_vector[cnx->version_index] = aead_ctx;
            }
        }
    }

    return aead_ctx;
}

static void ** picoquic_delete_one_retry_protection_context(void ** ctx)
{
    if (ctx != NULL) {
        for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
            if (ctx[i] != NULL) {
                picoquic_aead_free(ctx[i]);
            }
        }
        free(ctx);
    }
    return NULL;
}

void picoquic_delete_retry_protection_contexts(picoquic_quic_t * quic)
{
    quic->retry_integrity_sign_ctx = picoquic_delete_one_retry_protection_context(quic->retry_integrity_sign_ctx);
    quic->retry_integrity_verify_ctx = picoquic_delete_one_retry_protection_context(quic->retry_integrity_verify_ctx);
}

static size_t picoquic_format_retry_protection_pseudo_packet(uint8_t * pseudo_packet, uint8_t * bytes, size_t byte_index, const picoquic_connection_id_t * odcid)
{
    size_t pseudo_index = 0;

    if (byte_index + odcid->id_len + 1 < PICOQUIC_MAX_PACKET_SIZE) {
        pseudo_packet[pseudo_index++] = odcid->id_len;
        memcpy(&pseudo_packet[pseudo_index], odcid->id, odcid->id_len);
        pseudo_index += odcid->id_len;
        memcpy(&pseudo_packet[pseudo_index], bytes, byte_index);
        pseudo_index += byte_index;
    }

    return pseudo_index;
}

size_t picoquic_encode_retry_protection(void * integrity_aead, uint8_t * bytes, size_t bytes_max, size_t byte_index, const picoquic_connection_id_t * odcid)
{
    size_t pseudo_index;
    uint8_t pseudo_packet[PICOQUIC_MAX_PACKET_SIZE];

    if (integrity_aead != NULL && byte_index + picoquic_aead_get_checksum_length(integrity_aead) < bytes_max &&
        (pseudo_index = picoquic_format_retry_protection_pseudo_packet(pseudo_packet, bytes, byte_index, odcid)) > 0){
        byte_index += picoquic_aead_encrypt_generic(bytes+byte_index, bytes+byte_index, 0, 0, pseudo_packet, pseudo_index, integrity_aead);
    }

    return byte_index;
}

int picoquic_verify_retry_protection(void * integrity_aead, uint8_t * bytes, size_t * length, size_t byte_index, const picoquic_connection_id_t * odcid)
{
    int ret = PICOQUIC_ERROR_AEAD_CHECK;
    size_t pseudo_index;
    uint8_t pseudo_packet[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t decoded[PICOQUIC_MAX_PACKET_SIZE];
    size_t checksum_length = picoquic_aead_get_checksum_length(integrity_aead);

    if (byte_index + checksum_length < *length) {
        *length -= checksum_length;
        if ((pseudo_index = picoquic_format_retry_protection_pseudo_packet(pseudo_packet, bytes, *length, odcid)) > 0 &&
            picoquic_aead_decrypt_generic(decoded, bytes + *length, checksum_length, 0, pseudo_packet, pseudo_index, integrity_aead) == 0) {
            ret = 0;
        }
    }

    return ret;
}
