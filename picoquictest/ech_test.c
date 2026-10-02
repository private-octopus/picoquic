/*
* Author: Christian Huitema
* Copyright (c) 2025, Private Octopus, Inc.
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
#pragma warning(disable:4204)
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
#include "picoquic_qlog.h"
#include "picoquic_logger.h"

 /* ech_config_test:
 * Create an ech configuration list, i.e., the content of an HTTPS "ech=" parameter.
  */
#define ECH_CONFIG_FILE_TXT "ech_config.txt"

int picoquic_ech_read_config(ptls_buffer_t* config, char const* file_name);
int picoquic_ech_create_config_from_public_key(uint8_t** config, size_t* config_len, char const* public_key_file, char const* public_name);
int picoquic_ech_create_config_from_private_key(uint8_t** config, size_t* config_len, char const* private_key_file, char const* public_name);
int picoquic_ech_save_config(uint8_t* config, size_t config_len, char const* file_name);
int picoquic_ech_create_config_file(char const* public_name, char const* private_key_file, char const* ech_config_file);
int picoquic_ech_get_kem_from_curve(ptls_hpke_kem_t** kem, uint16_t group_id);
int picoquic_ech_get_ciphers_from_kem(ptls_hpke_cipher_suite_t** cipher_vec, size_t cipher_vec_nb_max, uint16_t kem_id);
int picoquic_ech_create_config_from_binary(uint8_t** config, size_t* config_len, ptls_iovec_t public_key_asn1, char const* public_name);

int ech_test_check_buf(uint8_t* config, size_t config_len, char const* ref_file_name)
{
    int ret = 0;
    char test_ref_file[512];

    ret = picoquic_get_input_path(test_ref_file, sizeof(test_ref_file), picoquic_solution_dir,
        ref_file_name);

    if (ret != 0) {
        DBG_PRINTF("Cannot find <%s> file in <%s>, err: %d (0x%x)", ref_file_name, picoquic_solution_dir, ret, ret);
    }
    else {
        ptls_buffer_t config_buffer;
        ptls_buffer_init(&config_buffer, "", 0);
        ret = picoquic_ech_read_config(&config_buffer, test_ref_file);
        if (ret != 0) {
            DBG_PRINTF("Cannot read reference for <%s> from <%s>, err: %d (0x%x)", ref_file_name, test_ref_file, ret, ret);
        }
        else {
            if (config_buffer.off != config_len ||
                memcmp(config_buffer.base, config, config_len) != 0) {
                DBG_PRINTF("Data does not match reference for <%s> from <%s>, len = %zu vs %zu",
                    ref_file_name, test_ref_file, config_len, config_buffer.off);
                ret = -1;
            }
        }
        ptls_buffer_dispose(&config_buffer);
    }
    return ret;
}

int ech_config_test(void)
{
    int ret = 0;
    char test_server_pub_key_file[512];
    const char* public_name = "test.example.com";
    uint8_t* config = NULL;
    size_t config_len = 0;

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = picoquic_get_input_path(test_server_pub_key_file, sizeof(test_server_pub_key_file), picoquic_solution_dir,
        PICOQUIC_TEST_ECH_PUB_KEY);
    if (ret != 0) {
        DBG_PRINTF("Cannot find pub_key file in <%s>, err: %d (0x%x)", picoquic_solution_dir, ret, ret);
    }
    else if ((ret = picoquic_ech_create_config_from_public_key(&config, &config_len, test_server_pub_key_file, public_name)) != 0) {
        DBG_PRINTF("Cannot create ECH record from <%s>, err: %d (0x%x)", test_server_pub_key_file, ret, ret);
    }
    /* Save a config representation in ech_config.txt */
    if (ret == 0) {
        ret = picoquic_ech_save_config(config, config_len, ECH_CONFIG_FILE_TXT);
        if (ret == 0) {
            ret = ech_test_check_buf(config, config_len, PICOQUIC_TEST_ECH_CONFIG_REF);
        }
    }

    if (config != NULL) {
        free(config);
    }

    return ret;
}

int ech_config_p_test(void)
{
    int ret = 0;
    char test_server_key_file[512];
    const char* public_name = "test.example.com";
    uint8_t* config = NULL;
    size_t config_len = 0;

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
        PICOQUIC_TEST_ECH_PRIVATE_KEY);
    if (ret != 0) {
        DBG_PRINTF("Cannot locate %s", PICOQUIC_TEST_ECH_PRIVATE_KEY);
    }
    else if ((ret = picoquic_ech_create_config_from_private_key(&config, &config_len, test_server_key_file, public_name)) != 0) {
        DBG_PRINTF("Cannot create ECH record from <%s>, err: %d (0x%x)", test_server_key_file, ret, ret);
    }

    /* Save a config representation in ech_config.txt */
    if (ret == 0) {
        ret = picoquic_ech_save_config(config, config_len, ECH_CONFIG_FILE_TXT);
        if (ret == 0) {
            ret = ech_test_check_buf(config, config_len, PICOQUIC_TEST_ECH_CONFIG_REF);
        }
    }

    if (config != NULL) {
        free(config);
    }

    return ret;
}

/* picoquic_ech_create_config_from_private_key's 0x61-byte-pubkey branch (secp384r1) was
 * never exercised by any test -- the checked-in ECH test key is secp256r1 (0x41 bytes). */
#define ECH_CONFIG_SECP384R1_KEY "certs" PICOQUIC_FILE_SEPARATOR "ech" PICOQUIC_FILE_SEPARATOR "private_secp384r1.pem"
#define ECH_CONFIG_SECP384R1_REF "certs" PICOQUIC_FILE_SEPARATOR "ech" PICOQUIC_FILE_SEPARATOR "ech_config_secp384r1.txt"
#define ECH_CONFIG_SECP384R1_TXT "ech_config_secp384r1_test.txt"

int ech_config_secp384r1_test(void)
{
    int ret = 0;
    char test_server_key_file[512];
    const char* public_name = "test.example.com";
    uint8_t* config = NULL;
    size_t config_len = 0;

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
        ECH_CONFIG_SECP384R1_KEY);
    if (ret != 0) {
        DBG_PRINTF("Cannot locate %s", ECH_CONFIG_SECP384R1_KEY);
    }
    else if ((ret = picoquic_ech_create_config_from_private_key(&config, &config_len, test_server_key_file, public_name)) != 0) {
        DBG_PRINTF("Cannot create ECH record from <%s>, err: %d (0x%x)", test_server_key_file, ret, ret);
    }

    if (ret == 0) {
        ret = picoquic_ech_save_config(config, config_len, ECH_CONFIG_SECP384R1_TXT);
        if (ret == 0) {
            ret = ech_test_check_buf(config, config_len, ECH_CONFIG_SECP384R1_REF);
        }
    }

    if (config != NULL) {
        free(config);
    }

    return ret;
}

/* picoquic_ech_create_config_from_public_key (unlike _from_private_key) goes through
 * picoquic_ech_parse_public_key, which reads the curve from the key's ASN.1 algorithm
 * OID rather than deriving it from the raw key length -- its secp384r1 and x25519
 * branches were never exercised, only the default secp256r1 one. */
#define ECH_CONFIG_PUB_SECP384R1_KEY "certs" PICOQUIC_FILE_SEPARATOR "secp384r1" PICOQUIC_FILE_SEPARATOR "pub.pem"
#define ECH_CONFIG_PUB_SECP384R1_REF "certs" PICOQUIC_FILE_SEPARATOR "ech" PICOQUIC_FILE_SEPARATOR "ech_config_pub_secp384r1.txt"
#define ECH_CONFIG_PUB_SECP384R1_TXT "ech_config_pub_secp384r1_test.txt"

int ech_config_pub_secp384r1_test(void)
{
    int ret = 0;
    char test_server_pub_key_file[512];
    const char* public_name = "test.example.com";
    uint8_t* config = NULL;
    size_t config_len = 0;

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = picoquic_get_input_path(test_server_pub_key_file, sizeof(test_server_pub_key_file), picoquic_solution_dir,
        ECH_CONFIG_PUB_SECP384R1_KEY);
    if (ret != 0) {
        DBG_PRINTF("Cannot locate %s", ECH_CONFIG_PUB_SECP384R1_KEY);
    }
    else if ((ret = picoquic_ech_create_config_from_public_key(&config, &config_len, test_server_pub_key_file, public_name)) != 0) {
        DBG_PRINTF("Cannot create ECH record from <%s>, err: %d (0x%x)", test_server_pub_key_file, ret, ret);
    }

    if (ret == 0) {
        ret = picoquic_ech_save_config(config, config_len, ECH_CONFIG_PUB_SECP384R1_TXT);
        if (ret == 0) {
            ret = ech_test_check_buf(config, config_len, ECH_CONFIG_PUB_SECP384R1_REF);
        }
    }

    if (config != NULL) {
        free(config);
    }

    return ret;
}

#define ECH_CONFIG_PUB_X25519_KEY "certs" PICOQUIC_FILE_SEPARATOR "ech" PICOQUIC_FILE_SEPARATOR "public_x25519.pem"
#define ECH_CONFIG_PUB_X25519_REF "certs" PICOQUIC_FILE_SEPARATOR "ech" PICOQUIC_FILE_SEPARATOR "ech_config_pub_x25519.txt"
#define ECH_CONFIG_PUB_X25519_TXT "ech_config_pub_x25519_test.txt"

int ech_config_pub_x25519_test(void)
{
    int ret = 0;
    char test_server_pub_key_file[512];
    const char* public_name = "test.example.com";
    uint8_t* config = NULL;
    size_t config_len = 0;

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = picoquic_get_input_path(test_server_pub_key_file, sizeof(test_server_pub_key_file), picoquic_solution_dir,
        ECH_CONFIG_PUB_X25519_KEY);
    if (ret != 0) {
        DBG_PRINTF("Cannot locate %s", ECH_CONFIG_PUB_X25519_KEY);
    }
    else if ((ret = picoquic_ech_create_config_from_public_key(&config, &config_len, test_server_pub_key_file, public_name)) != 0) {
        DBG_PRINTF("Cannot create ECH record from <%s>, err: %d (0x%x)", test_server_pub_key_file, ret, ret);
    }

    if (ret == 0) {
        ret = picoquic_ech_save_config(config, config_len, ECH_CONFIG_PUB_X25519_TXT);
        if (ret == 0) {
            ret = ech_test_check_buf(config, config_len, ECH_CONFIG_PUB_X25519_REF);
        }
    }

    if (config != NULL) {
        free(config);
    }

    return ret;
}

#define ECH_CONFIG_FROM_FILE_TXT "ech_config_from_file_test.txt"

/* picoquic_ech_create_config_file combines picoquic_ech_create_config_from_private_key
 * and picoquic_ech_save_config (each already exercised separately in ech_config_p_test
 * above) into the single entry point used by picoquic_config.c -- never itself called
 * from a test until now. Check its output file matches the checked-in reference. */
int ech_config_file_test(void)
{
    int ret = 0;
    char test_server_key_file[512];
    char test_ref_file[512];
    const char* public_name = "test.example.com";

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
        PICOQUIC_TEST_ECH_PRIVATE_KEY);
    if (ret != 0) {
        DBG_PRINTF("Cannot locate %s", PICOQUIC_TEST_ECH_PRIVATE_KEY);
    }
    else {
        ret = picoquic_get_input_path(test_ref_file, sizeof(test_ref_file), picoquic_solution_dir,
            PICOQUIC_TEST_ECH_CONFIG_REF);
        if (ret != 0) {
            DBG_PRINTF("Cannot locate %s", PICOQUIC_TEST_ECH_CONFIG_REF);
        }
    }

    if (ret == 0 &&
        (ret = picoquic_ech_create_config_file(public_name, test_server_key_file, ECH_CONFIG_FROM_FILE_TXT)) != 0) {
        DBG_PRINTF("Cannot create ECH config file from <%s>, err: %d (0x%x)", test_server_key_file, ret, ret);
    }

    if (ret == 0) {
        ret = picoquic_test_compare_text_files(ECH_CONFIG_FROM_FILE_TXT, test_ref_file);
        if (ret != 0) {
            DBG_PRINTF("%s", "ECH config file content does not match reference.");
        }
    }

    return ret;
}

#if 0
/* ECH test of config from CERT */
int ech_cert_test(void)
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
#endif
/* ECH end to end test. Create a connection, verify that the proper files
* are returned.
 */

typedef struct st_ech_e2e_spec_t {
    int expect_success;
    int expect_grease;
    int no_ech_server;
    int complete_cnx;
    int try_twice;
} ech_e2e_spec_t;

int ech_test_check_retry_config(picoquic_cnx_t* cnx,
    uint8_t* config, size_t config_len)
{
    int ret = 0;
    uint8_t* retry_config;
    size_t retry_config_len;

    picoquic_ech_get_retry_config(cnx, &retry_config, &retry_config_len);

    if (retry_config == NULL ||
        retry_config_len != config_len ||
        memcmp(retry_config, config, config_len) != 0) {
        ret = -1;
    }
    return ret;
}

#define ECH_TICKET_FILE_NAME "ech_ticket_store.bin"

static test_api_stream_desc_t ech_scenario_small[] = {
    { 4, 0, 256, 1000 }
};

int ech_test_complete_cnx(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* loss_mask, uint64_t* simulated_time)
{
    /* load a small scenario */
    int ret = test_api_init_send_recv_scenario(test_ctx, ech_scenario_small, sizeof(ech_scenario_small));

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, loss_mask, simulated_time, 0);
    }

    /* Before closing, wait for the session ticket to arrive */
    ret = session_resume_wait_for_ticket(test_ctx, simulated_time);

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, simulated_time, 1000000);
    }

    /* Verify that the session ticket has been received correctly */
    if (ret == 0) {
        if (test_ctx->qclient->p_first_ticket == NULL) {
            DBG_PRINTF("%s", "no ticket received.");
            ret = -1;
        }
        else {
            ret = picoquic_save_tickets(test_ctx->qclient->p_first_ticket, *simulated_time, ECH_TICKET_FILE_NAME);
            if (ret != 0) {
                DBG_PRINTF("ticket save error (0x%x).\n", ret);
            }
        }
    }

    return ret;
}


int ech_e2e_second(picoquic_test_tls_api_ctx_t* test_ctx, ptls_buffer_t *ech_config_buf, uint64_t * loss_mask, uint64_t* simulated_time)
{
    int ret = 0;

    /* We should verify that 0RTT works for the 2nd connection */
    picoquic_delete_cnx(test_ctx->cnx_client);
    test_ctx->cnx_client = NULL;
    if (test_ctx->cnx_server != NULL) {
        picoquic_delete_cnx(test_ctx->cnx_server);
        test_ctx->cnx_server = NULL;
    }

    /* recreate the client connection */
    test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient, picoquic_null_connection_id,
        picoquic_null_connection_id,
        (struct sockaddr*)&test_ctx->server_addr, *simulated_time,
        PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

    if (test_ctx->cnx_client == NULL) {
        ret = -1;
    }
    else {
        if (ech_config_buf->off > 0) {
            picoquic_ech_configure_client(test_ctx->cnx_client, ech_config_buf->base, ech_config_buf->off);
        }

        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, loss_mask, 0, simulated_time);
    }
    if (ret == 0 ) {
        /* If resume succeeded, the second connection will have a type "PSK" */
        if (picoquic_tls_is_psk_handshake(test_ctx->cnx_client) == 0) {
            DBG_PRINTF("%s", "ECH test, second connection is not PSK.");
            ret = -1;
        }
        else {
            /* run a receive loop until no outstanding data */
            ret = tls_api_synch_to_empty_loop(test_ctx, simulated_time, 2048, 0, 0);
        }
    }
    return ret;
}

int ech_e2e_test_one(ech_e2e_spec_t* spec)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xec, 0x8e, 0x2e, 0, 0, 0, 0, 0}, 8 };
    ptls_buffer_t ech_config_buf = { 0 };
    char ech_test_key_file[512];
    char ech_test_config_file[512];
    int ret;

    initial_cid.id[3] = (uint8_t)spec->expect_success;
    initial_cid.id[4] = (uint8_t)spec->expect_grease;

    ptls_buffer_init(&ech_config_buf, "", 0);


    /* Initialize an empty ticket store */
    ret = picoquic_save_tickets(NULL, simulated_time, ECH_TICKET_FILE_NAME);

    /* Create a test context with delayed init */
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, ECH_TICKET_FILE_NAME, NULL, 0, 1, 0, &initial_cid);

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
        picoquic_set_qlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        if (!spec->no_ech_server) {
            ret = picoquic_ech_configure_quic_ctx(test_ctx->qserver, ech_test_key_file, ech_test_config_file);
            if (ret != 0) {
                DBG_PRINTF("Cannot configure quic server context for ECH, ret = %d (0x%x).", ret, ret);
            }
        }
    }
    if (ret == 0 && (!spec->no_ech_server || spec->expect_grease)) {
        /* client side configuration */
        ret = picoquic_ech_configure_quic_ctx(test_ctx->qclient, NULL, NULL);
        if (ret != 0) {
            DBG_PRINTF("Cannot configure quic client context for ECH, ret = %d (0x%x).", ret, ret);
        }
    }

    if (!spec->no_ech_server) {
        if (ret == 0) {
            /* Read the ECH config from the same file used for the server */
            ret = picoquic_ech_read_config(&ech_config_buf, ech_test_config_file);
        }

        if (ret == 0) {
            if (spec->expect_success) {
                ret = picoquic_ech_configure_client(test_ctx->cnx_client, ech_config_buf.base, ech_config_buf.off);
            }
            else if (spec->expect_grease) {
                ret = picoquic_ech_configure_client(test_ctx->cnx_client, NULL, 0);
            }
            else {
                ret = -1;
            }
            if (ret != 0) {
                DBG_PRINTF("Cannot configure quic client connection for ECH, ret = %d (0x%x).", ret, ret);
            }
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
        if (spec->expect_success) {
            /* TODO: verify that ECH worked! */
            if (!picoquic_is_ech_handshake(test_ctx->cnx_client)) {
                DBG_PRINTF("%s", "ECH negotiation failed!");
                ret = -1;
            }
        }
        else if (picoquic_is_ech_handshake(test_ctx->cnx_client)) {
            DBG_PRINTF("%s", "ECH negotiation should have failed!");
            ret = -1;
        }
        else if (ech_test_check_retry_config(test_ctx->cnx_client,
            ech_config_buf.base, ech_config_buf.off) != 0) {
            if (!spec->no_ech_server) {
                /* TODO: understand why this does not work. */
                DBG_PRINTF("%s", "No retry config available!");
            }
        }
        else if (spec->no_ech_server) {
            DBG_PRINTF("%s", "There should be no retry config!");
            ret = -1;
        }
    }

    if (ret == 0 && spec->complete_cnx) {
        ret = ech_test_complete_cnx(test_ctx, &loss_mask, &simulated_time);
    }

    if (ret == 0 && spec->try_twice) {
        ret = ech_e2e_second(test_ctx, &ech_config_buf, &loss_mask, &simulated_time);
    }

    ptls_buffer_dispose(&ech_config_buf);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int ech_e2e_test(void)
{
    ech_e2e_spec_t spec = { 0 };
    spec.expect_success = 1;
    return ech_e2e_test_one(&spec);
}

int ech_e2e_0rtt_test(void)
{
    ech_e2e_spec_t spec = { 0 };
    spec.expect_grease = 1;
    spec.complete_cnx = 1;
    spec.try_twice = 1;
    return ech_e2e_test_one(&spec);
}

int ech_grease_test(void)
{
    ech_e2e_spec_t spec = { 0 };
    spec.expect_grease = 1;
    return ech_e2e_test_one(&spec);
}

int ech_no_ech_test(void)
{
    ech_e2e_spec_t spec = { 0 };
    spec.expect_grease = 0;
    spec.no_ech_server = 1;
    spec.complete_cnx = 1;
    spec.try_twice = 1;
    return ech_e2e_test_one(&spec);
}

/* ech_bad_config_test:
 *
 * Verify that bad configurations such as empty files or blank files are
 * properly rejected.
 */
static int ech_write_bad_config_file(char const* file_name, int all_whitespace, int too_short)
{
    int ret = 0;
    FILE* F = picoquic_file_open(file_name, "w");
    if (F == NULL) {
        ret = -1;
    }
    else {
        if (all_whitespace) {
            fprintf(F, "   \n\t \n   \n");
        }
        else if (too_short) {
            fprintf(F, "abcdabcd\n");
        }
        /* else: leave the file completely empty */
        F = picoquic_file_close(F);
    }
    return ret;
}

static int ech_bad_config_test_one(int all_whitespace, int too_short)
{
    int ret = 0;
    char const* bad_config_file = "ech_bad_config_test.txt";
    ptls_buffer_t config_buf;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    picoquic_connection_id_t initial_cid = { {0xec, 0xba, 0xd0, 0, 0, 0, 0, 0}, 8 };

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = ech_write_bad_config_file(bad_config_file, all_whitespace, too_short);

    /* Step 1: deterministic, no sanitizer required. picoquic_ech_read_config
     * must not report success while config_buf.off is still 0. */
    if (ret == 0) {
        ptls_buffer_init(&config_buf, "", 0);
        ret = picoquic_ech_read_config(&config_buf, bad_config_file);
        if (ret == 0 && config_buf.off == 0) {
            DBG_PRINTF("%s", "picoquic_ech_read_config reported success for an empty/whitespace config");
            ret = -1;
        }
        else if (ret != 0) {
            ret = 0; /* correctly rejected: this is the fixed behavior we want */
        }
        else {
            DBG_PRINTF("Unexpected: got %zu decoded bytes from a bad config file", config_buf.off);
            ret = -1;
        }
        ptls_buffer_dispose(&config_buf);
    }

    /* Step 2: the real startup entry point, exercising the unchecked
     * config.base[7]/[8] read in ech_init_opener_callback(). Run under
     * ASan / valgrind memcheck for a conclusive result -- a clean return
     * code alone does not prove the out-of-bounds read didn't happen. */
    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
    }
    if (ret == 0) {
        int ech_ret = picoquic_ech_configure_quic_ctx(test_ctx->qserver, "no_such_private_key.pem", bad_config_file);
        if (ech_ret == 0) {
            DBG_PRINTF("%s", "picoquic_ech_configure_quic_ctx succeeded from a bad config file");
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int ech_bad_config_empty_test(void)
{
    return ech_bad_config_test_one(0, 0);
}

int ech_bad_config_whitespace_test(void)
{
    return ech_bad_config_test_one(1, 0);
}

int ech_bad_config_too_short_test(void)
{
    return ech_bad_config_test_one(0, 1);
}

/* picoquic_ech_read_config's file-open failure and base64-decode-error branches are not
 * reached by ech_bad_config_test_one above: that helper always writes a file that opens
 * fine, with content that is valid-but-incomplete base64, not outright invalid base64. */
int ech_bad_config_missing_file_test(void)
{
    int ret = 0;
    ptls_buffer_t config_buf;

    ptls_buffer_init(&config_buf, "", 0);
    ret = picoquic_ech_read_config(&config_buf, "ech_config_file_does_not_exist.txt");
    if (ret == 0) {
        DBG_PRINTF("%s", "picoquic_ech_read_config reported success for a nonexistent file");
        ret = -1;
    }
    else {
        ret = 0;
    }
    ptls_buffer_dispose(&config_buf);
    return ret;
}

int ech_bad_config_invalid_base64_test(void)
{
    int ret = 0;
    char const* bad_config_file = "ech_bad_config_invalid_base64_test.txt";
    FILE* F = picoquic_file_open(bad_config_file, "w");

    if (F == NULL) {
        ret = -1;
    }
    else {
        fprintf(F, "!!!!!!!!\n");
        F = picoquic_file_close(F);
    }

    if (ret == 0) {
        ptls_buffer_t config_buf;

        ptls_buffer_init(&config_buf, "", 0);
        ret = picoquic_ech_read_config(&config_buf, bad_config_file);
        if (ret == 0) {
            DBG_PRINTF("%s", "picoquic_ech_read_config reported success for invalid base64 content");
            ret = -1;
        }
        else {
            ret = 0;
        }
        ptls_buffer_dispose(&config_buf);
    }
    return ret;
}

/* picoquic_ech_get_kem_from_curve and picoquic_ech_get_ciphers_from_kem are small lookup
 * helpers, directly reachable through the public API, whose "not found"/edge-case paths are
 * never hit by the E2E config-creation tests above (those only ever look up curves and KEMs
 * that picoquic actually registers). */
int ech_kem_lookup_test(void)
{
    int ret = 0;
    ptls_hpke_kem_t* kem = NULL;
    ptls_hpke_cipher_suite_t* cipher_vec[4] = { NULL, NULL, NULL, NULL };

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    /* An unregistered curve group ID must be reported as "not found". */
    if (picoquic_ech_get_kem_from_curve(&kem, 0xffff) == 0) {
        DBG_PRINTF("%s", "picoquic_ech_get_kem_from_curve found a KEM for a bogus group ID");
        ret = -1;
    }

    /* A cipher_vec buffer too small to hold even the mandatory default entry is rejected. */
    if (ret == 0 && picoquic_ech_get_ciphers_from_kem(cipher_vec, 1, PTLS_HPKE_KEM_P256_SHA256) == 0) {
        DBG_PRINTF("%s", "picoquic_ech_get_ciphers_from_kem accepted a too-small buffer");
        ret = -1;
    }

    /* An unrecognized KEM ID falls back to the same default target as P256, rather than
     * failing -- since AES128-GCM-SHA256 is always picoquic's baseline registered suite. */
    if (ret == 0 &&
        (picoquic_ech_get_ciphers_from_kem(cipher_vec, 4, 0xffff) != 0 || cipher_vec[0] == NULL)) {
        DBG_PRINTF("%s", "picoquic_ech_get_ciphers_from_kem found no cipher for an unrecognized KEM ID");
        ret = -1;
    }

    return ret;
}

static uint8_t* ech_find_bytes(uint8_t* base, size_t base_len, const uint8_t* pattern, size_t pattern_len)
{
    if (pattern_len == 0 || base_len < pattern_len) {
        return NULL;
    }
    for (size_t i = 0; i + pattern_len <= base_len; i++) {
        if (memcmp(base + i, pattern, pattern_len) == 0) {
            return base + i;
        }
    }
    return NULL;
}

/* picoquic_parse_public_key_asn1's error branches (unsupported algorithm OID, unsupported
 * SecP curve OID, declared length past the end of the buffer) are never reached by the
 * "happy path" config-creation tests above, which only ever feed it real, well-formed
 * public keys. Rather than hand-building ASN.1 from scratch, take a real key and corrupt
 * it in targeted ways, and check that the parser rejects each corruption. */
int ech_pubkey_asn1_test(void)
{
    int ret = 0;
    char test_server_pub_key_file[512];
    const char* public_name = "test.example.com";
    ptls_iovec_t public_key_asn1 = ptls_iovec_init(NULL, 0);
    size_t pub_key_objects = 0;
    static const uint8_t oid_algo_secp[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    static const uint8_t oid_pr_secp256r1[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    if ((ret = picoquic_get_input_path(test_server_pub_key_file, sizeof(test_server_pub_key_file),
        picoquic_solution_dir, PICOQUIC_TEST_ECH_PUB_KEY)) != 0) {
        DBG_PRINTF("Cannot find pub_key file in <%s>, err: %d (0x%x)", picoquic_solution_dir, ret, ret);
    }
    else {
        ret = ptls_load_pem_objects(test_server_pub_key_file, "PUBLIC KEY", &public_key_asn1, 1, &pub_key_objects);
    }

    if (ret == 0) {
        uint8_t* config = NULL;
        size_t config_len = 0;
        uint8_t* algo_oid;
        uint8_t* curve_oid;

        /* Sanity check: the real key must parse successfully, and must contain the OID
         * bytes this test is about to corrupt -- otherwise the corruptions below would
         * silently become no-ops. */
        if (picoquic_ech_create_config_from_binary(&config, &config_len, public_key_asn1, public_name) != 0) {
            DBG_PRINTF("%s", "The reference public key unexpectedly failed to parse");
            ret = -1;
        }
        if (config != NULL) {
            free(config);
        }

        algo_oid = ech_find_bytes(public_key_asn1.base, public_key_asn1.len, oid_algo_secp, sizeof(oid_algo_secp));
        curve_oid = ech_find_bytes(public_key_asn1.base, public_key_asn1.len, oid_pr_secp256r1, sizeof(oid_pr_secp256r1));
        if (ret == 0 && (algo_oid == NULL || curve_oid == NULL)) {
            DBG_PRINTF("%s", "Could not locate the expected OID bytes in the reference public key");
            ret = -1;
        }

        /* Corrupt the algorithm OID: neither secp nor X25519 any more. */
        if (ret == 0) {
            uint8_t saved = algo_oid[sizeof(oid_algo_secp) - 1];
            uint8_t* bad_config = NULL;
            size_t bad_config_len = 0;

            algo_oid[sizeof(oid_algo_secp) - 1] ^= 0xff;
            if (picoquic_ech_create_config_from_binary(&bad_config, &bad_config_len, public_key_asn1, public_name) == 0) {
                DBG_PRINTF("%s", "Parser accepted a public key with a corrupted algorithm OID");
                ret = -1;
            }
            if (bad_config != NULL) {
                free(bad_config);
            }
            algo_oid[sizeof(oid_algo_secp) - 1] = saved;
        }

        /* Corrupt the curve OID: still a SecP algorithm, but neither secp256r1 nor secp384r1. */
        if (ret == 0) {
            uint8_t saved = curve_oid[sizeof(oid_pr_secp256r1) - 1];
            uint8_t* bad_config = NULL;
            size_t bad_config_len = 0;

            curve_oid[sizeof(oid_pr_secp256r1) - 1] ^= 0xff;
            if (picoquic_ech_create_config_from_binary(&bad_config, &bad_config_len, public_key_asn1, public_name) == 0) {
                DBG_PRINTF("%s", "Parser accepted a public key with a corrupted curve OID");
                ret = -1;
            }
            if (bad_config != NULL) {
                free(bad_config);
            }
            curve_oid[sizeof(oid_pr_secp256r1) - 1] = saved;
        }

        /* Truncate the buffer: the outer SEQUENCE's declared length no longer fits. */
        if (ret == 0) {
            ptls_iovec_t truncated = ptls_iovec_init(public_key_asn1.base, public_key_asn1.len - 1);
            uint8_t* bad_config = NULL;
            size_t bad_config_len = 0;

            if (picoquic_ech_create_config_from_binary(&bad_config, &bad_config_len, truncated, public_name) == 0) {
                DBG_PRINTF("%s", "Parser accepted a truncated public key");
                ret = -1;
            }
            if (bad_config != NULL) {
                free(bad_config);
            }
        }
    }

    if (public_key_asn1.base != NULL) {
        free(public_key_asn1.base);
    }

    return ret;
}

/* picoquic_ech_create_config_from_public_key's "cannot load pubkey" branch is never
 * reached by the tests above, which only ever load real, existing key files. */
int ech_pubkey_missing_file_test(void)
{
    int ret = 0;
    uint8_t* config = NULL;
    size_t config_len = 0;

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    if (picoquic_ech_create_config_from_public_key(&config, &config_len,
        "ech_pubkey_file_does_not_exist.pem", "test.example.com") == 0) {
        DBG_PRINTF("%s", "picoquic_ech_create_config_from_public_key succeeded for a nonexistent file");
        ret = -1;
    }
    if (config != NULL) {
        free(config);
    }
    return ret;
}

/* picoquic_ech_get_kem_from_curve and picoquic_ech_get_ciphers_from_kem "not found" paths
 * (including their loop-exhaustion break) are never reached in a normal build, since
 * picoquic always registers all 3 standard curves and at least one cipher suite. Force
 * them by temporarily clearing the registration arrays, then restore the real values. */
int ech_registration_failure_test(void)
{
    int ret = 0;
    char test_server_key_file[512];
    const char* public_name = "test.example.com";
    uint8_t* config = NULL;
    size_t config_len = 0;
    ptls_hpke_kem_t* saved_kems[PICOQUIC_HPKE_KEM_NB_MAX + 1];
    ptls_hpke_cipher_suite_t* saved_ciphers[PICOQUIC_HPKE_CIPHER_SUITE_NB_MAX + 1];

    if (picoquic_hpke_kems[0] == NULL) {
        picoquic_tls_api_init();
    }

    ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
        PICOQUIC_TEST_ECH_PRIVATE_KEY);
    if (ret != 0) {
        DBG_PRINTF("Cannot locate %s", PICOQUIC_TEST_ECH_PRIVATE_KEY);
    }

    if (ret == 0) {
        size_t i;

        for (i = 0; i < PICOQUIC_HPKE_KEM_NB_MAX + 1; i++) {
            saved_kems[i] = picoquic_hpke_kems[i];
            picoquic_hpke_kems[i] = NULL;
        }

        if (picoquic_ech_create_config_from_private_key(&config, &config_len, test_server_key_file, public_name) == 0) {
            DBG_PRINTF("%s", "Config creation succeeded with no registered KEM");
            ret = -1;
        }
        if (config != NULL) {
            free(config);
            config = NULL;
        }
        for (i = 0; i < PICOQUIC_HPKE_KEM_NB_MAX + 1; i++) {
            picoquic_hpke_kems[i] = saved_kems[i];
        }
    }

    if (ret == 0) {
        size_t i;

        for (i = 0; i < PICOQUIC_HPKE_CIPHER_SUITE_NB_MAX + 1; i++) {
            saved_ciphers[i] = picoquic_hpke_cipher_suites[i];
            picoquic_hpke_cipher_suites[i] = NULL;
        }

        if (picoquic_ech_create_config_from_private_key(&config, &config_len, test_server_key_file, public_name) == 0) {
            DBG_PRINTF("%s", "Config creation succeeded with no registered cipher suite");
            ret = -1;
        }
        if (config != NULL) {
            free(config);
            config = NULL;
        }
        for (i = 0; i < PICOQUIC_HPKE_CIPHER_SUITE_NB_MAX + 1; i++) {
            picoquic_hpke_cipher_suites[i] = saved_ciphers[i];
        }
    }

    return ret;
}