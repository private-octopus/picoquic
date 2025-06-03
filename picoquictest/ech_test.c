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
#include "picoquictest_internal.h"
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
#include "picoquictest.h"
typedef const struct st_ptls_cipher_suite_t ptls_cipher_suite_t;
#include "picoquic_crypto_provider_api.h"
#include "picoquic_binlog.h"

 /* ech_rr_test:
 * Create an ech RR.
  */
#ifdef _WINDOWS
#define PICOQUIC_TEST_ECH_PUB_KEY "certs\\ech\\public.pem"
#define PICOQUIC_TEST_ECH_PRIVATE_KEY "certs\\ech\\private.pem"
#define PICOQUIC_TEST_ECH_CONFIG "certs\\ech\\ech_config.txt"
#else
#define PICOQUIC_TEST_ECH_PUB_KEY "certs/ech/public.pem"
#define PICOQUIC_TEST_ECH_PRIVATE_KEY "certs/ech/private.pem"
#define PICOQUIC_TEST_ECH_CONFIG "certs/ech/ech_config.txt"
#endif
#define ECH_CONFIG_FILE_TXT "ech_config.txt"
#define ECH_RR_FILE_TXT "ech_rr.txt"

int picoquic_ech_read_config(ptls_buffer_t* config, char const* file_name);

int picoquic_ech_parse_public_key(ptls_iovec_t public_key_asn1,
    uint16_t* group_id,
    ptls_iovec_t* public_key_bits);
int picoquic_ech_get_kem_from_curve(ptls_hpke_kem_t** kem, uint16_t group_id);
int picoquic_ech_get_ciphers_from_kem(ptls_hpke_cipher_suite_t** cipher_vec, size_t cipher_vec_nb_max, uint16_t kem_id);
int picoquic_ech_create_config_from_binary(ptls_buffer_t* config_buf, ptls_iovec_t public_key_asn1, char const* public_name);

int ech_rr_test()
{
    int ret = 0;
    uint8_t config_id = 1;
    ptls_hpke_kem_t* kem = NULL;
    ptls_hpke_kem_t test_hpke_kem_p256sha256 = { PTLS_HPKE_KEM_P256_SHA256, &ptls_minicrypto_secp256r1, &ptls_minicrypto_sha256 };
    char test_server_pub_key_file[512];
#if 0
    ptls_iovec_t public_key = ptls_iovec_init(NULL, 0);
#endif
    ptls_iovec_t public_key_asn1 = ptls_iovec_init(NULL, 0);
    size_t pub_key_objects = 0;
    ptls_hpke_cipher_suite_t test_hpke_aes128gcmsha256 = {
        .id = {.kdf = PTLS_HPKE_HKDF_SHA256, .aead = PTLS_HPKE_AEAD_AES_128_GCM},
        .name = "HKDF-SHA256/AES-128-GCM",
        .hash = &ptls_minicrypto_sha256,
        .aead = &ptls_minicrypto_aes128gcm
    };
#if 0
    ptls_hpke_cipher_suite_t* test_hpke_cipher_vec[2] = { &test_hpke_aes128gcmsha256, NULL };
    ptls_hpke_cipher_suite_t* cipher_vec[PICOQUIC_HPKE_CIPHER_SUITE_NB_MAX + 1];
#endif
    const char* public_name = "test.example.com";
    uint8_t max_name_length = 128;
    ptls_buffer_t rr_buf;
    ptls_buffer_t config_buf;
    uint8_t smallbuf[256];
    uint8_t smallbuf2[256];
    ptls_buffer_init(&rr_buf, (void*)smallbuf, sizeof(smallbuf));
    ptls_buffer_init(&config_buf, (void*)smallbuf2, sizeof(smallbuf2));

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = picoquic_get_input_path(test_server_pub_key_file, sizeof(test_server_pub_key_file), picoquic_solution_dir,
        PICOQUIC_TEST_ECH_PUB_KEY);
    if (ret != 0) {
        DBG_PRINTF("Cannot find pub_key file in <%s>, err: %d (0x%x)", picoquic_solution_dir, ret, ret);
    }
    else {
#if 0
        ret = ptls_load_pem_objects("public-256.pem", "PUBLIC KEY", &public_key_asn1, 1, &pub_key_objects);
#else
        ret = ptls_load_pem_objects(test_server_pub_key_file, "PUBLIC KEY", &public_key_asn1, 1, &pub_key_objects);
#endif
        if (ret != 0) {
            DBG_PRINTF("Cannot load pubkey from <%s>, err: %x", test_server_pub_key_file, ret);
        }
        else 
        {
#if 1
            ret = picoquic_ech_create_config_from_binary(&rr_buf, public_key_asn1, public_name);
            if (ret != 0) {
                DBG_PRINTF("Cannot create ECH record from <%s>, err: %d (0x%x)", test_server_pub_key_file, ret, ret);
            }
#else
            uint16_t group_id = 0;
            ret = picoquic_ech_parse_public_key(public_key_asn1, &group_id, &public_key);
#if 0
            size_t p_out = 0;
            while (p_out < public_key.len) {
                for (int i = 0; i < 15 && p_out < public_key.len; i++, p_out++) {
                    printf(":%02x", public_key.base[p_out]);
                }
                printf("\n");
            }
            /* Print ASN1 key for debugging */
            printf("ASN1 pub key\n");
            p_out = 0;
            while (p_out < public_key_asn1.len) {
                for (int i = 0; i < 15 && p_out < public_key_asn1.len; i++, p_out++) {
                    printf(":%02x", public_key_asn1.base[p_out]);
                }
                printf("\n");
            }
#endif
            if ((ret = picoquic_ech_get_kem_from_curve(&kem, group_id)) != 0) {
                DBG_PRINTF("Could not find KEM for group = 0x%04x", group_id);
            }
            else if ((ret = picoquic_ech_get_ciphers_from_kem(cipher_vec, PICOQUIC_HPKE_CIPHER_SUITE_NB_MAX + 1, kem->id)) != 0) {
                DBG_PRINTF("Could not find Ciphers for kem = 0x%04x", kem->id);
            }
#endif

        }
    }
#if 0
    if (ret == 0) {
        ret = ptls_ech_encode_config(&rr_buf, config_id, kem, public_key,
            cipher_vec, max_name_length, public_name);
        if (ret != 0) {
            DBG_PRINTF("Cannot create ECH record from <%s>, err: %d (0x%x)", test_server_pub_key_file, ret, ret);
        }
    }
#endif
    /* save an RR representation in ech_rr.txt */
    if (ret == 0) {
        int last_err;
        size_t ech_text_size = ptls_base64_howlong(rr_buf.off);
        char* ech_text = (char*)malloc(ech_text_size + 1);

        if (ech_text == NULL) {
            DBG_PRINTF("Cannot allocate %d bytes for text buffer", ech_text_size);
            ret = -1;
        }
        else {
            int lt = ptls_base64_encode(rr_buf.base, rr_buf.off, ech_text);
            if (lt != ech_text_size + 1) {
                DBG_PRINTF("Cannot base64 encode %zu bytes into %zu", rr_buf.off, ech_text_size);
                ret = -1;
            }
        }
        if (ret == 0) {
            FILE* F = picoquic_file_open_ex(ECH_RR_FILE_TXT, "w", &last_err);
            if (F == NULL) {
                DBG_PRINTF("Cannot open file <%s>, err: %x", ECH_RR_FILE_TXT, last_err);
                ret = -1;
            }
            else {
                size_t written = fwrite(ech_text, 1, ech_text_size, F);
                if (written != ech_text_size) {
                    DBG_PRINTF("Cannot write %d bytes on file <%s>, err= %zu", ech_text, ECH_RR_FILE_TXT, written);
                    ret = -1;
                }
                else {
                    (void)fprintf(F, "\n");
                    DBG_PRINTF("Wrote %d bytes on file <%s>", ech_text_size + 1, ECH_RR_FILE_TXT);
                }
                picoquic_file_close(F);
            }
        }
        if (ech_text != NULL) {
            free(ech_text);
        }
    }
    /* Save a config representation in ech_config.txt */
    if (ret == 0) {
        int last_err;
        size_t bin_size = rr_buf.off + 2;
        uint8_t * bin_val = (uint8_t*)malloc(bin_size);
        if (bin_val == NULL) {
            DBG_PRINTF("Cannot allocate %d bytes for config bin buffer", bin_size);
            ret = -1;
        }
        else {
            size_t config_text_size = ptls_base64_howlong(bin_size);
            char* config_text = (char*)malloc(config_text_size + 1);

            bin_val[0] = (uint8_t)(((rr_buf.off) >> 8) & 0xff);
            bin_val[1] = (uint8_t)(rr_buf.off & 0xff);
            memcpy(bin_val + 2, rr_buf.base, rr_buf.off);

            if (config_text == NULL) {
                DBG_PRINTF("Cannot allocate %d bytes for config text buffer", config_text_size + 1);
                ret = -1;
            }
            else {
                int lc = ptls_base64_encode(bin_val, bin_size, config_text);
                if (lc != config_text_size + 1) {
                    DBG_PRINTF("Cannot base64 encode %zu bytes into %zu", lc, config_text_size);
                    ret = -1;
                }
                if (ret == 0) {
                    FILE* F = picoquic_file_open_ex(ECH_CONFIG_FILE_TXT, "w", &last_err);
                    if (F == NULL) {
                        DBG_PRINTF("Cannot open file <%s>, err: %x", ECH_CONFIG_FILE_TXT, last_err);
                        ret = -1;
                    }
                    else {
                        size_t written = fwrite(config_text, 1, config_text_size, F);
                        if (written != config_text_size) {
                            DBG_PRINTF("Cannot write %d bytes on file <%s>, err= %zu", config_text_size, ECH_CONFIG_FILE_TXT, written);
                            ret = -1;
                        }
                        else {
                            (void)fprintf(F, "\n");
                            DBG_PRINTF("Wrote %d bytes on file <%s>", config_text_size + 1, ECH_CONFIG_FILE_TXT);
                        }
                        picoquic_file_close(F);
                    }
                }
                free(config_text);
            }
            free(bin_val);
        }
    }
    if (ret == 0) {
        ptls_buffer_t config;
        ptls_buffer_init(&config, "", 0);
        ret = picoquic_ech_read_config(&config, ECH_RR_FILE_TXT);
        if (ret != 0) {
            DBG_PRINTF("Cannot read config from file <%s>", ECH_RR_FILE_TXT);
        }
        else {
            if (config.off != rr_buf.off ||
                memcmp(config.base, rr_buf.base, rr_buf.off) != 0) {
                DBG_PRINTF("Config differs from source (base: %zu, read: %zu)", rr_buf.off, config.off);
                ret = -1;
            }
        }
        ptls_buffer_dispose(&config);
    }

    ptls_buffer_dispose(&rr_buf);
    free(public_key_asn1.base);

    return ret;
}

/* ECH end to end test. Create a connection, verify that the proper files
* are returned.
 */

int ech_e2e_test()
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xec, 0x8e, 0x2e, 0, 0, 0, 0, 0}, 8 };
    ptls_buffer_t ech_config_buf = { 0 };

    char ech_test_key_file[512];
    char ech_test_config_file[512];
    int ret;

    /* Create a test context with delayed init */
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0) {
        ret = picoquic_get_input_path(ech_test_key_file, sizeof(ech_test_key_file), picoquic_solution_dir,
            PICOQUIC_TEST_ECH_PRIVATE_KEY);
        if (ret != 0) {
            DBG_PRINTF("Cannot locate %s", PICOQUIC_TEST_ECH_PRIVATE_KEY);
        }
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(ech_test_config_file, sizeof(ech_test_config_file), picoquic_solution_dir,
            PICOQUIC_TEST_ECH_CONFIG);
        if (ret != 0) {
            DBG_PRINTF("Cannot locate %s", PICOQUIC_TEST_ECH_CONFIG);
        }
    }

    if (ret == 0) {
        /* server side configuration */
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        ret = picoquic_ech_configure_quic_ctx(test_ctx->qserver, ech_test_key_file, ech_test_config_file);
        if (ret != 0) {
            DBG_PRINTF("Cannot configure quic server context for ECH, ret = %d (0x%x).", ret, ret);
        }
    }
    if (ret == 0) {
        /* client side configuration */
        ret = picoquic_ech_configure_quic_ctx(test_ctx->qclient, NULL, NULL);
        if (ret != 0) {
            DBG_PRINTF("Cannot configure quic client context for ECH, ret = %d (0x%x).", ret, ret);
        }
    }
    if (ret == 0) {
        /* Read the ECH config from the same file used for the server */
        ptls_buffer_init(&ech_config_buf, "", 0);
        ret = picoquic_ech_read_config(&ech_config_buf, ech_test_config_file);
        if (ret == 0) {
            picoquic_ech_configure_client(test_ctx->cnx_client, ech_config_buf.base, ech_config_buf.off);
        }
        else {
            DBG_PRINTF("Cannot configure quic client connection for ECH, ret = %d (0x%x).", ret, ret);
        }
    }
    if (ret == 0) {
        /* start the client connection, thus creating a TLS context */
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0 && (!TEST_CLIENT_READY || !TEST_SERVER_READY)) {
        DBG_PRINTF("%s", "Connection failed!");
        ret = -1;
    }

    if (ret == 0) {
        /* TODO: verify that ECH worked! */
        if (!picoquic_is_ech_handshake(test_ctx->cnx_client)) {
            DBG_PRINTF("%s", "ECH negotiation failed!");
            ret = -1;
        }
    }

    ptls_buffer_dispose(&ech_config_buf);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}