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
#define ECH_CONFIG_FILE_TXT "ech_config.txt"
#define ECH_RR_FILE_TXT "ech_rr.txt"

int picoquic_ech_read_config(ptls_buffer_t* config, char const* file_name);

int picoquic_ech_parse_public_key(ptls_iovec_t public_key_asn1,
    uint16_t* group_id,
    ptls_iovec_t* public_key_bits);
int picoquic_ech_get_kem_from_curve(ptls_hpke_kem_t** kem, uint16_t group_id);
int picoquic_ech_get_ciphers_from_kem(ptls_hpke_cipher_suite_t** cipher_vec, size_t cipher_vec_nb_max, uint16_t kem_id); 
int picoquic_ech_create_rr_from_binary(ptls_buffer_t* config_buf, ptls_iovec_t public_key_asn1, char const* public_name);
int picoquic_ech_create_config_from_rr(uint8_t** config, size_t* config_len, const ptls_buffer_t* rr_buf);
int picoquic_ech_create_config_from_public_key(uint8_t** config, size_t* config_len, char const* public_key_file, char const* public_name);
int picoquic_ech_create_config_from_cert(uint8_t** config, size_t* config_len, char const* cert_file, char const* public_name);

int ech_test_save_buf(ptls_iovec_t io_buf, char const * file_name)
{
    int ret = 0;

    int last_err;
    size_t ech_text_size = ptls_base64_howlong(io_buf.len);
    char* ech_text = (char*)malloc(ech_text_size + 1);

    if (ech_text == NULL) {
        DBG_PRINTF("Cannot allocate %d bytes for text buffer", ech_text_size);
        ret = -1;
    }
    else {
        int lt = ptls_base64_encode(io_buf.base, io_buf.len, ech_text);
        if (lt != ech_text_size + 1) {
            DBG_PRINTF("Cannot base64 encode %zu bytes into %zu", io_buf.len, ech_text_size);
            ret = -1;
        }
    }
    if (ret == 0) {
        FILE* F = picoquic_file_open_ex(file_name, "w", &last_err);
        if (F == NULL) {
            DBG_PRINTF("Cannot open file <%s>, err: %x", file_name, last_err);
            ret = -1;
        }
        else {
            size_t written = fwrite(ech_text, 1, ech_text_size, F);
            if (written != ech_text_size) {
                DBG_PRINTF("Cannot write %d bytes on file <%s>, err= %zu", ech_text, file_name, written);
                ret = -1;
            }
            else {
                (void)fprintf(F, "\n");
                DBG_PRINTF("Wrote %d bytes on file <%s>", ech_text_size + 1, file_name);
            }
            picoquic_file_close(F);
        }
    }
    if (ech_text != NULL) {
        free(ech_text);
    }
    return ret;
}

int ech_test_check_buf(ptls_iovec_t io_buf, char const* ref_file_name)
{
    int ret = 0;
    char test_ref_file[512];

    ret = picoquic_get_input_path(test_ref_file, sizeof(test_ref_file), picoquic_solution_dir,
        ref_file_name);

    if (ret != 0) {
        DBG_PRINTF("Cannot find <%s> file in <%s>, err: %d (0x%x)", ref_file_name, picoquic_solution_dir, ret, ret);
    }
    else {
        ptls_buffer_t config;
        ptls_buffer_init(&config, "", 0);
        ret = picoquic_ech_read_config(&config, test_ref_file);
        if (ret != 0) {
            DBG_PRINTF("Cannot read reference for <%s> from <%s>, err: %d (0x%x)", ref_file_name, test_ref_file, ret, ret);
        }
        else {
            if (config.off != io_buf.len ||
                memcmp(config.base, io_buf.base, io_buf.len) != 0) {
                DBG_PRINTF("Data does not match reference for <%s> from <%s>, len = %zu vs %zu",
                    ref_file_name, test_ref_file, io_buf.len, config.off);
                ret = -1;
            }
        }
        ptls_buffer_dispose(&config);
    }
    return ret;
}

int ech_rr_test()
{
    int ret = 0;
    char test_server_pub_key_file[512];
    ptls_iovec_t public_key_asn1 = ptls_iovec_init(NULL, 0);
    size_t pub_key_objects = 0;
    const char* public_name = "test.example.com";
    uint8_t config_id = 1;
    ptls_hpke_kem_t* kem = NULL;
    uint8_t max_name_length = 128;
    ptls_buffer_t rr_buf;
    uint8_t smallbuf[256];
    ptls_buffer_init(&rr_buf, (void*)smallbuf, sizeof(smallbuf));

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = picoquic_get_input_path(test_server_pub_key_file, sizeof(test_server_pub_key_file), picoquic_solution_dir,
        PICOQUIC_TEST_ECH_PUB_KEY);
    if (ret != 0) {
        DBG_PRINTF("Cannot find pub_key file in <%s>, err: %d (0x%x)", picoquic_solution_dir, ret, ret);
    }
    else {
        ret = ptls_load_pem_objects(test_server_pub_key_file, "PUBLIC KEY", &public_key_asn1, 1, &pub_key_objects);
        if (ret != 0) {
            DBG_PRINTF("Cannot load pubkey from <%s>, err: %x", test_server_pub_key_file, ret);
        }
        else 
        {
            ret = picoquic_ech_create_rr_from_binary(&rr_buf, public_key_asn1, public_name);
            if (ret != 0) {
                DBG_PRINTF("Cannot create ECH record from <%s>, err: %d (0x%x)", test_server_pub_key_file, ret, ret);
            }
        }
    }
    /* save an RR representation in ech_rr.txt */
    if (ret == 0) {
        ptls_iovec_t io_rr_buf = { .base = rr_buf.base, .len = rr_buf.off };
        ret = ech_test_save_buf(io_rr_buf, ECH_RR_FILE_TXT);
        if (ret == 0) {
            ret = ech_test_check_buf(io_rr_buf, PICOQUIC_TEST_ECH_RR_REF);
        }
    }
    /* Save a config representation in ech_config.txt */
    if (ret == 0) {
        uint8_t* config = NULL;
        size_t config_len = 0;
        if ((ret = picoquic_ech_create_config_from_rr(&config, &config_len, &rr_buf)) != 0) {
            DBG_PRINTF("Cannot create config from rr_buf size %zu", rr_buf.off);
        }
        else {
            ptls_iovec_t io_config = { .base = config, .len = config_len };

            ret = ech_test_save_buf(io_config, ECH_CONFIG_FILE_TXT);
            if (ret == 0) {
                ret = ech_test_check_buf(io_config, PICOQUIC_TEST_ECH_CONFIG_REF);
            }
            free(config);
        }
    }
    ptls_buffer_dispose(&rr_buf);
    free(public_key_asn1.base);

    return ret;
}

/* ECH test of config from CERT */
int ech_cert_test()
{
    int ret = 0;
    char test_server_cert_file[512];
    uint8_t* config = NULL;
    size_t config_len = 0;

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }
    if ((ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
        PICOQUIC_TEST_ECH_CERT)) != 0) {
        DBG_PRINTF("Cannot find cert file in <%s>, err: %d (0x%x)", picoquic_solution_dir, ret, ret);
    }
    else if ((ret = picoquic_ech_create_config_from_cert(&config, &config_len, test_server_cert_file, "test.example.com")) != 0) {
        DBG_PRINTF("Cannot create config from cert file in <%s>, err: %d (0x%x)", test_server_cert_file, ret, ret);
    }
    else {
        ptls_iovec_t io_config = { .base = config, .len = config_len };
        ret = ech_test_check_buf(io_config, PICOQUIC_TEST_ECH_CONFIG_REF);
        free(config);
    }

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
        ptls_buffer_dispose(&ech_config_buf);
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