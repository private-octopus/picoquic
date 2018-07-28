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
#include "../picoquic/wincompat.h"
#endif
#include "../picoquic/picoquic_internal.h"
#include "../picoquic/tls_api.h"
#include "../picoquic/util.h"
#include "picotls.h"
#include "picotls/openssl.h"
#include <string.h>
#include "picoquictest_internal.h"

static uint8_t const addr1[4] = { 10, 0, 0, 1 };
static uint8_t const addr2[4] = { 10, 0, 0, 2 };

void cleartext_aead_packet_init_header(picoquic_packet_header* ph,
    picoquic_connection_id_t cnx_id, uint32_t pn, uint32_t vn, picoquic_packet_type_enum ptype)
{
    memset(ph, 0, sizeof(picoquic_packet_header));
    ph->dest_cnx_id = cnx_id;
    ph->srce_cnx_id = picoquic_null_connection_id;
    ph->pn = pn;
    ph->pn64 = pn;
    ph->vn = vn;
    ph->ptype = ptype;
    ph->offset = 17;
    ph->pnmask = 0xFFFFFFFF00000000ull;
    ph->version_index = picoquic_get_version_index(ph->vn);
}

void cleartext_aead_init_packet(picoquic_packet_header* ph,
    uint8_t* cleartext, size_t target)
{
    size_t byte_index = 0;
    uint64_t seed = picoquic_val64_connection_id(ph->dest_cnx_id);

    seed ^= ph->pn;

    /* Serialize the header */
    cleartext[byte_index++] = 0x80 | ((uint8_t)ph->ptype);
    picoformat_32(&cleartext[byte_index], ph->vn);
    byte_index += 4;
    byte_index += picoquic_format_connection_id(&cleartext[byte_index], 1526 - byte_index, ph->dest_cnx_id);
    byte_index += picoquic_format_connection_id(&cleartext[byte_index], 1526 - byte_index, ph->srce_cnx_id);
    ph->pn_offset = (uint32_t)byte_index;
    picoformat_32(&cleartext[byte_index], ph->pn);
    byte_index += 4;
    /* Add some silly content */
    while (byte_index < target) {
        seed *= 101;
        cleartext[byte_index++] = (uint8_t)seed & 255;
    }
}

int cleartext_aead_test()
{
    int ret = 0;
    uint8_t clear_text[1536];
    uint8_t incoming[1536];
    uint32_t seqnum = 0xdeadbeef;
    size_t clear_length = 1200;
    size_t encoded_length;
    size_t decoded_length;
    picoquic_packet_header ph_init;
    struct sockaddr_in test_addr_c, test_addr_s;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    picoquic_quic_t* qserver = picoquic_create(8,
        PICOQUIC_TEST_SERVER_CERT, PICOQUIC_TEST_SERVER_KEY, PICOQUIC_TEST_CERT_STORE,
        "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (qclient == NULL || qserver == NULL) {
        DBG_PRINTF("%s", "Could not create Quic contexts.\n");
        ret = -1;
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, 0, NULL, NULL, 1);
        if (cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create client connection context.\n");
            ret = -1;
        }
    }

    if (ret == 0) {

        memset(&test_addr_s, 0, sizeof(struct sockaddr_in));
        test_addr_s.sin_family = AF_INET;
        memcpy(&test_addr_s.sin_addr, addr2, 4);
        test_addr_s.sin_port = 4433;

        cnx_server = picoquic_create_cnx(qserver, cnx_client->initial_cnxid, cnx_client->initial_cnxid,
            (struct sockaddr*)&test_addr_s, 0,
            cnx_client->proposed_version, NULL, NULL, 0);

        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Could not create server connection context.\n");
            ret = -1;
        } else if (picoquic_compare_connection_id(&cnx_client->initial_cnxid, &cnx_server->initial_cnxid) != 0) {
            DBG_PRINTF("Server Cnx-ID= %llx, differs from Client Cnx-ID = %llx\n",
                (unsigned long long) picoquic_val64_connection_id(cnx_client->initial_cnxid),
                (unsigned long long) picoquic_val64_connection_id(cnx_server->initial_cnxid));
            ret = -1;
        }
        else if (picoquic_compare_cleartext_aead_contexts(cnx_client, cnx_server) != 0 ||
            picoquic_compare_cleartext_aead_contexts(cnx_server, cnx_client) != 0) {
            DBG_PRINTF("%s", "Cleartext encryption contexts no not match.\n");
            ret = -1;
        }
    }

    /* Create a packet from client to server, encrypt, decrypt */
    if (ret == 0) {
        cleartext_aead_packet_init_header(&ph_init,
            cnx_client->initial_cnxid, seqnum, cnx_client->proposed_version,
            picoquic_packet_initial);
        cleartext_aead_init_packet(&ph_init, clear_text, clear_length);

        /* AEAD Encrypt, to the send buffer */
        memcpy(incoming, clear_text, ph_init.offset);
        encoded_length = picoquic_aead_encrypt_generic(incoming + ph_init.offset,
            clear_text + ph_init.offset, clear_length - ph_init.offset,
            seqnum, incoming, ph_init.offset, cnx_client->crypto_context[0].aead_encrypt);
        encoded_length += ph_init.offset;

        /* AEAD Decrypt */
        decoded_length = picoquic_aead_decrypt_generic(incoming + ph_init.offset,
            incoming + ph_init.offset, encoded_length - ph_init.offset, seqnum,
            incoming, ph_init.offset, cnx_server->crypto_context[0].aead_decrypt);
        decoded_length += ph_init.offset;

        if (decoded_length != clear_length) {
            DBG_PRINTF("Decoded length (%d) does not match clear lenth (%d).\n", (int)decoded_length, (int)clear_length);
            ret = -1;
        } else if (memcmp(incoming, clear_text, clear_length) != 0) {
            DBG_PRINTF("%s", "Decoded message not match clear length.\n");
            ret = 1;
        }
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (cnx_server != NULL) {
        picoquic_delete_cnx(cnx_server);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

static picoquic_connection_id_t clear_test_vector_cnx_id = { { 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 }, 8 };

static uint32_t clear_test_vector_vn = 0xff00000d;
static uint8_t clear_test_vector_client_iv[12] = {
    0xab, 0x95, 0x0b, 0x01, 0x98, 0x63, 0x79, 0x78,
    0xcf, 0x44, 0xaa, 0xb9 };
static uint8_t clear_test_vector_server_iv[12] = {
    0x32, 0x05, 0x03, 0x5a, 0x3c, 0x93, 0x7c, 0x90,
    0x2e, 0xe4, 0xf4, 0xd6 };


static int cleartext_iv_cmp(void * void_aead, uint8_t * ref_iv, size_t iv_length)
{
    ptls_aead_context_t* aead = (ptls_aead_context_t*)void_aead;

    return memcmp(aead->static_iv, ref_iv, iv_length);
}

int cleartext_aead_vector_test_one(picoquic_connection_id_t test_id, uint8_t * client_iv, size_t client_iv_length,
    uint8_t * server_iv, size_t server_iv_length, char const * test_name)
{
    int ret = 0;
    struct sockaddr_in test_addr_c;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (qclient == NULL) {
        DBG_PRINTF("%s: Could not create Quic context.\n", test_name);
        ret = -1;
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, test_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, clear_test_vector_vn, NULL, NULL, 1);

        if (cnx_client == NULL) {
            DBG_PRINTF("%s: Could not create client connection context.\n", test_name);
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(cnx_client);
        }
    }

    if (ret == 0) {
        /* Compare client key to expected value */
        if (cnx_client->crypto_context[0].aead_encrypt == NULL)
        {
            DBG_PRINTF("%s: Could not create clear text AEAD encryption context.\n", test_name);
            ret = -1;
        } else if (0 != cleartext_iv_cmp(cnx_client->crypto_context[0].aead_encrypt, 
            client_iv, client_iv_length)) {
            DBG_PRINTF("%s: Clear text AEAD encryption IV does not match expected value.\n", test_name);
            ret = -1;
        } else if (cnx_client->crypto_context[0].aead_decrypt == NULL) {
            DBG_PRINTF("%s: Could not create clear text AEAD decryption context.\n", test_name);
            ret = -1;
        } else if (0 != cleartext_iv_cmp(cnx_client->crypto_context[0].aead_decrypt,
            server_iv, server_iv_length)) {
            DBG_PRINTF("%s: Clear text AEAD decryption IV does not match expected value.\n", test_name);
            ret = -1;
        }
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

int cleartext_aead_vector_test()
{
    return cleartext_aead_vector_test_one(clear_test_vector_cnx_id, clear_test_vector_client_iv, sizeof(clear_test_vector_client_iv),
        clear_test_vector_server_iv, sizeof(clear_test_vector_server_iv), "aead_vector");
}

/*
 * Test the CTR primitives used for PN encryption
 */

int pn_ctr_test()
{
    int ret = 0;

    static const uint8_t key[] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
    static const uint8_t iv[] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
    static const uint8_t expected[] = { 
        0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60,
        0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97 };
    static const uint8_t packet_clear_pn[] = {
        0x5D,
        0xba, 0xba, 0xc0, 0x01,
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc, 0x5b, 
        0x88, 0x55
    };
    static const uint8_t packet_encrypted_pn[] = {
        0x5d,
        0x80, 0x6d, 0xbb, 0xb5,
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0x20, 0x3f, 0xbe, 0x2e, 0x32, 0x17, 0xfc, 0x5b,
        0x88, 0x55
    };

    uint8_t in_bytes[16];
    uint8_t out_bytes[16];
    uint8_t decoded[16];
    ptls_aead_algorithm_t* aead = &ptls_openssl_aes128gcm;
    ptls_cipher_context_t *pn_enc = ptls_cipher_new(aead->ctr_cipher, 1, key);

    /* test against expected value, from PTLS test */
    ptls_cipher_init(pn_enc, iv);
    memset(in_bytes, 0, 16);
    ptls_cipher_encrypt(pn_enc, out_bytes, in_bytes, sizeof(in_bytes));
    if (memcmp(out_bytes, expected, 16) != 0)
    {
        ret = -1;
    }

    /* test for various values of the PN length */

    for (size_t i = 1; ret == 0 && i <= 16; i *= 2)
    {
        memset(in_bytes, (int)i, i);
        ptls_cipher_init(pn_enc, iv);
        ptls_cipher_encrypt(pn_enc, out_bytes, in_bytes, i);
        for (size_t j = 0; j < i; j++)
        {
            if (in_bytes[j] != (out_bytes[j] ^ expected[j]))
            {
                ret = -1;
                break;
            }
        }
        ptls_cipher_init(pn_enc, iv);
        ptls_cipher_encrypt(pn_enc, decoded, out_bytes, i);
        if (memcmp(in_bytes, decoded, i) != 0)
        {
            ret = -1;
        }

        ptls_cipher_init(pn_enc, iv);
        ptls_cipher_encrypt(pn_enc, out_bytes, out_bytes, i);
        if (memcmp(in_bytes, out_bytes, i) != 0)
        {
            ret = -1;
        }
    }

    /* Test with the encrypted value from the packet */
    if (ret == 0)
    {
        ptls_cipher_init(pn_enc, packet_clear_pn + 5);
        ptls_cipher_encrypt(pn_enc, out_bytes, packet_clear_pn + 1, 4);
        if (memcmp(out_bytes, packet_encrypted_pn + 1, 4) != 0)
        {
            ret = -1;
        }
        else
        {
            ptls_cipher_init(pn_enc, packet_encrypted_pn + 5);
            ptls_cipher_encrypt(pn_enc, out_bytes, packet_encrypted_pn + 1, 4);
            if (memcmp(out_bytes, packet_clear_pn + 1, 4) != 0)
            {
                ret = -1;
            }
        }
    }

    // cleanup
    if (pn_enc != NULL)
    {
        ptls_cipher_free(pn_enc);
    }

    return ret;
}

/*
* Test that the generated encryption and decryption produce
* the same results.
*/

int test_one_pn_enc_pair(uint8_t * seqnum, size_t seqnum_len, void * pn_enc, void * pn_dec, uint8_t * sample)
{
    int ret = 0;
    uint8_t encoded[32];
    uint8_t decoded[32];

    ptls_cipher_init((ptls_cipher_context_t *)pn_enc, sample);
    ptls_cipher_encrypt((ptls_cipher_context_t *)pn_enc, encoded, seqnum, seqnum_len);

    ptls_cipher_init((ptls_cipher_context_t *)pn_dec, sample);
    ptls_cipher_encrypt((ptls_cipher_context_t *)pn_dec, decoded, encoded, seqnum_len);

    if (memcmp(seqnum, decoded, seqnum_len) != 0)
    {
        ret = -1;
    }

    return ret;
}

/*
 * Test that the key generated for cleartext PN encryption on
 * client and server produce the correct results.
 */

int cleartext_pn_enc_test()
{
    int ret = 0;
    struct sockaddr_in test_addr_c, test_addr_s;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    picoquic_quic_t* qserver = picoquic_create(8,
#ifdef _WINDOWS
#ifdef _WINDOWS64
        "..\\..\\certs\\cert.pem", "..\\..\\certs\\key.pem",
#else
        "..\\certs\\cert.pem", "..\\certs\\key.pem",
#endif
#else
        "certs/cert.pem", "certs/key.pem",
#endif
        NULL, "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (qclient == NULL || qserver == NULL) {
        DBG_PRINTF("%s", "Could not create Quic contexts.\n");
        ret = -1;
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, 0, NULL, NULL, 1);
        if (cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create client connection context.\n");
            ret = -1;
        } else {
            ret = picoquic_start_client_cnx(cnx_client);
        }
    }

    if (ret == 0) {

        memset(&test_addr_s, 0, sizeof(struct sockaddr_in));
        test_addr_s.sin_family = AF_INET;
        memcpy(&test_addr_s.sin_addr, addr2, 4);
        test_addr_s.sin_port = 4433;

        cnx_server = picoquic_create_cnx(qserver, cnx_client->initial_cnxid, cnx_client->local_cnxid,
            (struct sockaddr*)&test_addr_s, 0,
            cnx_client->proposed_version, NULL, NULL, 0);

        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Could not create server connection context.\n");
            ret = -1;
        }
    }

    /* Try to encrypt a sequence number */
    if (ret == 0) {
        uint8_t seq_num_1[4] = { 0xde, 0xad, 0xbe, 0xef };
        uint8_t sample_1[16] = {
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };
        uint8_t seq_num_2[4] = { 0xba, 0xba, 0xc0, 0x0l };
        uint8_t sample_2[16] = {
            0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96};

        ret = test_one_pn_enc_pair(seq_num_1, 4, 
            cnx_client->crypto_context[0].pn_enc, cnx_server->crypto_context[0].pn_dec, sample_1);

        if (ret != 0) {
            DBG_PRINTF("%s", "Test of encoding PN sample 1 failed.\n");
        } else {
            ret = test_one_pn_enc_pair(seq_num_2, 4, cnx_server->crypto_context[0].pn_enc, 
                cnx_client->crypto_context[0].pn_dec, sample_2);
            if (ret != 0) {
                DBG_PRINTF("%s", "Test of encoding PN sample 2 failed.\n");
            }
        }
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (cnx_server != NULL) {
        picoquic_delete_cnx(cnx_server);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

/* Test vector copied from Kazuho Ohu's test code in quicly -- then changed */

int cleartext_pn_vector_test()
{
    int ret = 0;
    static const uint8_t cid[] = { 0x77, 0x0d, 0xc2, 0x6c, 0x17, 0x50, 0x9b, 0x35 };
    static const uint8_t sample[] = { 0x05, 0x80, 0x24, 0xa9, 0x72, 0x75, 0xf0, 0x1d, 0x2a, 0x1e, 0xc9, 0x1f, 0xd1, 0xc2, 0x65, 0xbb };
    static const uint8_t encrypted_pn[] = { 0x02, 0x6c, 0xe6, 0xde };
    static const uint8_t expected_pn[] = { 0xc0, 0x00, 0x00, 0x00 };

    struct sockaddr_in test_addr_s;
    picoquic_connection_id_t initial_cnxid;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qserver = picoquic_create(8,
#ifdef _WINDOWS
#ifdef _WINDOWS64
        "..\\..\\certs\\cert.pem", "..\\..\\certs\\key.pem",
#else
        "..\\certs\\cert.pem", "..\\certs\\key.pem",
#endif
#else
        "certs/cert.pem", "certs/key.pem",
#endif
        NULL, "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (qserver == NULL) {
        DBG_PRINTF("%s", "Could not create Quic contexts.\n");
        ret = -1;
    }

    if (ret == 0 && picoquic_parse_connection_id(cid, sizeof(cid), &initial_cnxid) != sizeof(cid)) {
        ret = -1;
    }


    if (ret == 0) {

        memset(&test_addr_s, 0, sizeof(struct sockaddr_in));
        test_addr_s.sin_family = AF_INET;
        memcpy(&test_addr_s.sin_addr, addr2, 4);
        test_addr_s.sin_port = 4433;

        cnx_server = picoquic_create_cnx(qserver, initial_cnxid, initial_cnxid,
            (struct sockaddr*)&test_addr_s, 0, PICOQUIC_SEVENTH_INTEROP_VERSION, NULL, NULL, 0);

        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Could not create server connection context.\n");
            ret = -1;
        }
    }

    /* Try to decrypt the test vector */
    if (ret == 0) {
        uint8_t decrypted[8];

        memset(decrypted, 0, sizeof(decrypted));

        picoquic_pn_encrypt(cnx_server->crypto_context[0].pn_dec, sample, decrypted, encrypted_pn, sizeof(encrypted_pn));

        if (memcmp(decrypted, expected_pn, sizeof(expected_pn)) != 0)
        {
            DBG_PRINTF("%s", "Test of encoding PN vector failed.\n");
            ret = -1;
        }
    }

    if (cnx_server != NULL) {
        picoquic_delete_cnx(cnx_server);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}

/*
 * test copied from EKR test vector
 */

static uint8_t draft13_test_input_packet[] = {
    0xff, 0xff, 0x00, 0x00, 0x0d, 0x50, 0x06, 0xb8, 0x58, 0xec,
    0x6f, 0x80, 0x45, 0x2b, 0x00, 0x44, 0xef, 0xa5, 0xd8, 0xd3,
    0x07, 0xc2, 0x97, 0x3f, 0xa0, 0xd6, 0x3f, 0xd9, 0xb0, 0x3a,
    0x4e, 0x16, 0x3b, 0x99, 0x0d, 0xd7, 0x78, 0x89, 0x4a, 0x9e,
    0xdc, 0x8e, 0xac, 0xfb, 0xe4, 0xaa, 0x6f, 0xbf, 0x4a, 0x22,
    0xec, 0x7f, 0x90, 0x6b, 0x5e, 0x8b, 0x8a, 0xe1, 0x2e, 0x5f,
    0xcc, 0x79, 0x24, 0xdf, 0xee, 0xe8, 0x13, 0x84, 0x2b, 0xb2,
    0x14, 0x9b, 0x80, 0x5e, 0x55, 0x89, 0x50, 0x84, 0xe8, 0x39,
    0x32, 0x00, 0xbb, 0x3f, 0xc6, 0x18, 0xaf, 0x7d, 0x08, 0x28,
    0x14, 0x85, 0xd9, 0x14, 0xce, 0x42, 0x30, 0x3f, 0x5d, 0x77,
    0x2b, 0x20, 0x05, 0x08, 0xa0, 0xc0, 0x02, 0x53, 0xe3, 0x32,
    0xe3, 0x6a, 0x84, 0xf6, 0x57, 0x32, 0x1a, 0xc4, 0xc8, 0xe2,
    0xcc, 0x8a, 0x11, 0x7e, 0x95, 0x87, 0x1f, 0x12, 0xb1, 0xf3,
    0x6b, 0xe8, 0xc4, 0xb7, 0x6f, 0xa4, 0x33, 0xdc, 0x4d, 0x31,
    0x42, 0xe6, 0x54, 0x7f, 0x45, 0x98, 0xbf, 0x4b, 0x19, 0x21,
    0x30, 0xae, 0xa6, 0xfc, 0x20, 0xda, 0x51, 0x58, 0xb2, 0x16,
    0x2b, 0x5a, 0x89, 0x99, 0x57, 0xda, 0x05, 0xde, 0xd5, 0xc7,
    0x09, 0x07, 0x29, 0x8f, 0xd8, 0x85, 0x84, 0x7f, 0x22, 0xa1,
    0xec, 0xb0, 0xa8, 0x14, 0xfe, 0x01, 0x70, 0xe2, 0x3c, 0xad,
    0x20, 0xaf, 0x64, 0xf0, 0x5c, 0xc1, 0x3c, 0x74, 0xe9, 0x18,
    0x24, 0x10, 0x1a, 0xfd, 0xcf, 0x5f, 0x15, 0x32, 0xfc, 0x2f,
    0xde, 0x93, 0x6a, 0x3a, 0x15, 0x9f, 0x76, 0x28, 0x3a, 0x26,
    0xc7, 0x38, 0xf7, 0x78, 0xc7, 0x6e, 0x6c, 0xa4, 0x1f, 0xa7,
    0xf1, 0x34, 0x40, 0x1d, 0x39, 0x02, 0x7f, 0xd8, 0x1d, 0xe1,
    0x7a, 0x80, 0x21, 0xa9, 0xc0, 0xaa, 0xa9, 0xb4, 0x47, 0x8f,
    0xe5, 0xc0, 0x64, 0x79, 0x41, 0x61, 0x8f, 0x3b, 0xee, 0x41,
    0x0c, 0xaf, 0x94, 0xc2, 0x48, 0xd2, 0xa6, 0x4b, 0x5e, 0x45,
    0x84, 0x5c, 0xd7, 0x7d, 0xe1, 0x3a, 0x5e, 0xd9, 0x40, 0x34,
    0xd2, 0xbc, 0x5f, 0x45, 0x78, 0x87, 0x35, 0x19, 0x93, 0xc1,
    0xec, 0xfa, 0x34, 0xfd, 0x0c, 0x65, 0x8f, 0xea, 0x3f, 0x80,
    0x86, 0xd2, 0x68, 0x08, 0xee, 0xf9, 0x76, 0x26, 0x2e, 0xcf,
    0x0a, 0xd6, 0x46, 0xb6, 0x27, 0x94, 0x55, 0x11, 0xdd, 0xe8,
    0x3e, 0x26, 0x60, 0x9c, 0xd5, 0xcf, 0xd7, 0xed, 0x9f, 0x62,
    0x07, 0xd7, 0x66, 0x18, 0xb4, 0x4c, 0x48, 0xbf, 0x62, 0x3b,
    0xf4, 0x20, 0xdc, 0x7c, 0x12, 0x7e, 0x5d, 0x5f, 0x52, 0x9f,
    0x08, 0x3b, 0x71, 0xa1, 0x7b, 0x17, 0xda, 0x32, 0x9b, 0xfc,
    0x38, 0xa7, 0x4b, 0xf8, 0xcf, 0xcf, 0x31, 0x5c, 0x7c, 0x07,
    0x0b, 0x71, 0xeb, 0xfa, 0xe3, 0xab, 0x35, 0x13, 0x41, 0xa7,
    0x67, 0xad, 0xfd, 0xd9, 0xe5, 0x7c, 0x73, 0x8f, 0x5d, 0xe9,
    0xda, 0x53, 0x71, 0x1e, 0x88, 0x6d, 0x14, 0x72, 0x31, 0x0b,
    0x91, 0x7a, 0x1c, 0x97, 0x98, 0xe3, 0xe9, 0xb1, 0x3c, 0x7c,
    0x74, 0xbe, 0xb8, 0xd1, 0xb8, 0x23, 0x45, 0xbe, 0xa1, 0x34,
    0x94, 0x15, 0x67, 0x9a, 0x9c, 0x64, 0xb0, 0x43, 0x3b, 0x68,
    0xc8, 0x71, 0xae, 0x08, 0x09, 0x2a, 0x1f, 0x61, 0x06, 0xbc,
    0x06, 0x33, 0x7c, 0xd3, 0x43, 0x86, 0x6e, 0xe8, 0x18, 0x5c,
    0x03, 0xfc, 0xf3, 0xbb, 0x06, 0x66, 0x45, 0x3f, 0x84, 0x79,
    0x05, 0x54, 0x71, 0x99, 0x41, 0x4c, 0x1e, 0x57, 0x53, 0x57,
    0x47, 0xbe, 0x61, 0xcd, 0xf6, 0x77, 0x83, 0x78, 0xf1, 0x21,
    0xd6, 0x8d, 0xf0, 0x18, 0x1e, 0xe9, 0xe8, 0xd9, 0x93, 0x2c,
    0x1c, 0x59, 0x3c, 0x0f, 0x8c, 0x0a, 0x1a, 0xf0, 0xf5, 0x26,
    0x2b, 0x86, 0x20, 0x50, 0x02, 0xdc, 0xed, 0x9e, 0xcd, 0xae,
    0xe2, 0xd0, 0xaa, 0x07, 0xdd, 0x4c, 0x14, 0xf9, 0x85, 0x71,
    0xe4, 0xbe, 0xa7, 0x2f, 0x84, 0x74, 0xf6, 0x36, 0x97, 0x04,
    0x3e, 0x93, 0x6e, 0xbb, 0x2b, 0xf9, 0x71, 0x6e, 0xd0, 0xef,
    0xbd, 0xc1, 0x30, 0x05, 0xa7, 0x5c, 0xee, 0x3a, 0x49, 0xba,
    0xbc, 0x61, 0xb9, 0x67, 0x77, 0x64, 0x51, 0x0e, 0xb1, 0x98,
    0x28, 0xdf, 0x4e, 0x10, 0xfb, 0x38, 0xb7, 0x9a, 0x1e, 0xfb,
    0xf0, 0x4c, 0xc2, 0xd5, 0x71, 0x94, 0x9d, 0x54, 0x03, 0xf7,
    0x97, 0x36, 0x17, 0x43, 0xdc, 0xc5, 0xe3, 0xbf, 0x3b, 0x43,
    0x96, 0xf7, 0xae, 0x1a, 0x3a, 0xff, 0xbc, 0x9f, 0x72, 0xe5,
    0x40, 0xd9, 0x20, 0x36, 0x39, 0x70, 0x30, 0x7e, 0x07, 0x25,
    0xfa, 0x83, 0x8d, 0x61, 0x18, 0x03, 0x25, 0x1a, 0x4a, 0x08,
    0xcc, 0xca, 0x19, 0x83, 0xd5, 0xb2, 0x9a, 0x58, 0x37, 0x58,
    0xbe, 0x63, 0x34, 0x3e, 0x88, 0xf5, 0x59, 0x1d, 0x88, 0x5b,
    0x8a, 0xf6, 0x95, 0xf3, 0x3a, 0xdb, 0xdd, 0x0d, 0x94, 0x1d,
    0x26, 0x02, 0x87, 0xe3, 0x2e, 0xf5, 0xa9, 0x8f, 0xd5, 0x5a,
    0xc1, 0x37, 0x21, 0x10, 0x21, 0xfd, 0xc2, 0x3b, 0x5d, 0x7a,
    0x54, 0x69, 0xf5, 0x78, 0xbf, 0x7a, 0xff, 0x65, 0x29, 0x11,
    0x79, 0x96, 0xf9, 0xeb, 0xab, 0x5e, 0x6d, 0xc7, 0xb0, 0x47,
    0xb3, 0x56, 0x33, 0x2f, 0xea, 0x82, 0xfd, 0xd6, 0x20, 0xeb,
    0x86, 0xf3, 0xc1, 0xd3, 0x85, 0x5c, 0x8b, 0x80, 0x75, 0xda,
    0x59, 0xa7, 0x66, 0x2f, 0x4a, 0x11, 0xb9, 0x77, 0xd9, 0x96,
    0xb8, 0xb3, 0xc7, 0x65, 0x7a, 0xd4, 0xa8, 0x2a, 0x20, 0xa7,
    0xf7, 0x6c, 0xe3, 0x76, 0xc0, 0x32, 0x00, 0x86, 0xed, 0x02,
    0x9d, 0xd6, 0x15, 0x39, 0x93, 0x07, 0x98, 0x31, 0x13, 0xcc,
    0x0a, 0xa9, 0x73, 0xec, 0xba, 0x69, 0x1e, 0x7e, 0x4c, 0xdc,
    0x80, 0xae, 0xfa, 0x7e, 0x8c, 0x83, 0x47, 0xba, 0xba, 0x05,
    0x0e, 0xac, 0xa7, 0xdc, 0x35, 0xa2, 0x1a, 0xa8, 0x54, 0xe5,
    0x31, 0xdc, 0x77, 0x58, 0xd7, 0xd1, 0x0b, 0x8c, 0x8e, 0x42,
    0xc1, 0xbe, 0x3b, 0xbf, 0x26, 0x6d, 0x05, 0x5a, 0xc2, 0x5c,
    0x37, 0x27, 0x9e, 0xbe, 0xfa, 0x28, 0xbb, 0xe8, 0x9a, 0x34,
    0xad, 0x1a, 0xb3, 0xd2, 0x3d, 0x7a, 0x66, 0xd1, 0xc2, 0x16,
    0xa5, 0x76, 0x50, 0xe6, 0xec, 0x9f, 0xc8, 0xba, 0x7a, 0xdf,
    0xb3, 0x8e, 0x57, 0xf2, 0x0c, 0x46, 0x71, 0x66, 0xc8, 0xfe,
    0x79, 0x44, 0xe6, 0x7f, 0x82, 0x13, 0x81, 0x60, 0x00, 0x20,
    0x04, 0x81, 0x2c, 0x78, 0xba, 0x4b, 0x5f, 0x0d, 0xa9, 0x17,
    0xda, 0x4c, 0xc1, 0x4c, 0xf8, 0xfc, 0x10, 0xdb, 0xa3, 0xf5,
    0x33, 0xfa, 0xcb, 0x11, 0xef, 0x06, 0xd8, 0xb8, 0xf1, 0x78,
    0xea, 0x9c, 0x5e, 0x8a, 0xcb, 0xbc, 0xa7, 0xb7, 0xf0, 0xe1,
    0xf6, 0xb7, 0xa7, 0x0e, 0xc2, 0xd5, 0x10, 0x8c, 0xc4, 0x11,
    0x78, 0x05, 0x62, 0x95, 0x79, 0x3b, 0xed, 0x35, 0x7a, 0xcc,
    0xbb, 0x03, 0xc0, 0x58, 0x2d, 0xc6, 0x9b, 0xc7, 0x7a, 0x34,
    0x03, 0x0f, 0x38, 0xcc, 0xe2, 0x56, 0xc5, 0xa9, 0xce, 0xc6,
    0xe8, 0x62, 0x14, 0x6e, 0x3f, 0x04, 0x63, 0xf1, 0x0d, 0xd5,
    0x83, 0x32, 0x57, 0xd0, 0xa0, 0x35, 0x91, 0x66, 0xa7, 0xe2,
    0x02, 0x7d, 0x98, 0xea, 0xf2, 0x6c, 0xf0, 0xd5, 0xa4, 0xa0,
    0x5f, 0x6e, 0xf8, 0xb7, 0x42, 0xf5, 0xd3, 0x14, 0xa3, 0x1d,
    0xee, 0xea, 0xbe, 0x4e, 0xbc, 0x31, 0x06, 0x54, 0x7e, 0x79,
    0xc6, 0xcb, 0x93, 0x31, 0x05, 0xd9, 0x07, 0xb4, 0xc8, 0xc6,
    0x04, 0x43, 0xe9, 0x7a, 0x15, 0x46, 0x94, 0xba, 0xb5, 0xed,
    0xfc, 0x78, 0x1a, 0x43, 0x86, 0x75, 0xb9, 0xde, 0x6e, 0xd0,
    0x3c, 0x77, 0xf5, 0x14, 0x58, 0xea, 0xb6, 0x1c, 0xa2, 0xe8,
    0x0a, 0xc0, 0x2c, 0xc8, 0xc0, 0x37, 0xd8, 0xfb, 0x3c, 0xf1,
    0x29, 0xd7, 0x10, 0x7f, 0x61, 0x8d, 0x66, 0x03, 0x2c, 0xc0,
    0x22, 0x38, 0xa2, 0x11, 0xf7, 0x8b, 0xfa, 0x44, 0xe7, 0xc1,
    0xbb, 0xcf, 0xcc, 0x62, 0x77, 0x71, 0xc1, 0x88, 0xd1, 0xb3,
    0x71, 0x3c, 0xe5, 0xe7, 0x5c, 0xd2, 0x32, 0x5a, 0x0a, 0x2b,
    0xa0, 0x82, 0x68, 0xca, 0xd1, 0x3b, 0x27, 0xd9, 0x76, 0x96,
    0xef, 0x67, 0x8b, 0x59, 0x2d, 0x0a, 0xc8, 0x0a, 0xd1, 0xba,
    0xcb, 0x4a, 0x1b, 0xa7, 0x5b, 0xea, 0x8c, 0x47, 0x7f, 0x39,
    0xfc, 0x32, 0xc2, 0xaa, 0x20, 0xf3, 0x52, 0xbb, 0x0d, 0xa1,
    0xc4, 0x9b, 0x7d, 0x39, 0x27, 0xbc, 0xd9, 0xdf, 0xaf, 0x22,
    0x92, 0x37, 0x08, 0x1d, 0x5f, 0xa0, 0x89, 0x24, 0xfe, 0xfd,
    0x92, 0x3f, 0xf0, 0xac, 0x6b, 0xaa, 0xd6, 0x86, 0x4b, 0x7c,
    0x10, 0xdc, 0x73, 0x37, 0x9a, 0x5e, 0xbd, 0x9e, 0x46, 0x78,
    0xa0, 0xc2, 0x65, 0x17, 0x65, 0x6e, 0x8e, 0x51, 0xfc, 0xa2,
    0xa5, 0x1a, 0x33, 0xfb, 0x2c, 0xdd, 0x5d, 0x76, 0xd1, 0x26,
    0x74, 0xc2, 0x40, 0xba, 0x9a, 0x48, 0x93, 0xc1, 0xaf, 0x69,
    0xb8, 0xf2, 0xc4, 0xad, 0xf3, 0x7c, 0x4a, 0x47, 0x55, 0x1e,
    0xb2, 0x00, 0x6a, 0x73, 0x2f, 0x6b, 0x3b, 0x2f, 0x33, 0x8c,
    0x07, 0x8e, 0xde, 0x33, 0x94, 0x6d, 0xfe, 0x4a, 0x55, 0xbf,
    0x64, 0x4d, 0x3b, 0x98, 0x84, 0x86, 0x93, 0xad, 0xa1, 0xfc,
    0xb6, 0xfc, 0x16, 0xca, 0xc3, 0x39, 0xee, 0x65, 0xc2, 0x4d,
    0xc6, 0x4b, 0x0a, 0xe9, 0x20, 0x05, 0x35, 0x4a, 0xf0, 0x0a,
    0xde, 0x71, 0xe6, 0xc5, 0xe2, 0xef, 0xd8, 0x5c, 0x46, 0x13,
    0x1d, 0x94, 0x8f, 0xf1, 0x40, 0x96, 0xb0, 0xf0, 0x6a, 0x41,
    0xd8, 0x3c, 0x85, 0x22, 0xf3, 0x0b, 0xeb, 0x4e, 0xaa, 0xf4,
    0xa6, 0xf9, 0x08, 0xfe, 0x2a, 0x6e, 0xe7, 0x54, 0xc8, 0x96
};

static uint32_t draft13_test_vn = 0xff00000d;

static picoquic_connection_id_t draft13_test_cnx_id = { 
    { 0x06, 0xb8, 0x58, 0xec, 0x6f, 0x80, 0x45, 0x2b }, 8 };

static uint8_t draft13_test_salt[] = {
    0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c, 0x32, 0x96,
    0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f, 0xe0, 0x6d, 0x6c, 0x38
};

static uint8_t draft13_test_server_initial_secret[] = {
    0x7e, 0x0a, 0xba, 0x2c, 0x4b, 0x97, 0x42, 0xd0, 0xd1, 0x30,
    0xbc, 0x73, 0x18, 0x62, 0x2a, 0xd3, 0xb4, 0x4a, 0xca, 0x1f,
    0x09, 0xab, 0xb1, 0x9b, 0x3f, 0x39, 0x4c, 0xd7, 0xe2, 0x0f,
    0x4b, 0xe0
};

static uint8_t draft13_test_server_key[] = {
    0x26, 0x08, 0x0e, 0x60, 0xd2, 0x88, 0xdb, 0x7d, 0xf8, 0x16,
    0xa1, 0xcb, 0x0b, 0xc6, 0xc7, 0xf4
};

static uint8_t draft13_test_server_iv[] = {
    0xb9, 0xfd, 0xc5, 0xb4, 0x48, 0xaf, 0x3e, 0x02, 0x34, 0x22,
    0x44, 0x3b
};

static uint8_t draft13_test_server_pn[] = {
    0x00, 0xba, 0xbb, 0xe1, 0xbe, 0x0f, 0x0c, 0x66, 0x18, 0x18,
    0x8b, 0x4f, 0xcc, 0xa5, 0x7a, 0x96
};

static uint8_t draft13_test_client_initial_secret[] = {
    0x82, 0xa7, 0x35, 0x72, 0xe7, 0xcb, 0x89, 0x52, 0x3b, 0x68,
    0xc3, 0x9e, 0xaa, 0x83, 0x25, 0x40, 0x4f, 0x86, 0x49, 0x8c,
    0x8e, 0x24, 0x37, 0xdf, 0xdc, 0xe1, 0x0f, 0x9c, 0x34, 0x28,
    0x1a, 0x3d
};

static uint8_t draft13_test_client_key[] = {
    0xa7, 0x99, 0x43, 0x56, 0x6c, 0x41, 0x34, 0x2f, 0x2b, 0xc3,
    0xde, 0x6b, 0x7c, 0x15, 0x39, 0xdf
};

static uint8_t draft13_test_client_iv[] = {
    0x84, 0xeb, 0x95, 0x4f, 0xfe, 0x16, 0x1c, 0x38, 0x75, 0x91,
    0x9f, 0x5f
};

static uint8_t draft13_test_client_pn[] = {
    0x5c, 0x0f, 0x64, 0x72, 0xa1, 0x56, 0x58, 0x04, 0x7a, 0x3c,
    0xc1, 0xf1, 0x54, 0x78, 0xdc, 0xf4
};

static uint64_t draft13_test_decoded_pn = 0;

static int draft13_label_expansion_test(ptls_cipher_suite_t * cipher, char const * label, uint8_t * secret, size_t secret_length, uint8_t const * key_ref, size_t key_ref_len)
{
    int ret = 0;
    uint8_t key_out[256];

    if ((ret = ptls_hkdf_expand_label(cipher->hash, key_out, key_ref_len, ptls_iovec_init(secret, secret_length),
        label, ptls_iovec_init(NULL, 0), PICOQUIC_LABEL_QUIC_BASE)) != 0) {
        DBG_PRINTF("Cannot expand label <%s>, ret = %x\n", label, ret);
    }
    else if (memcmp(key_out, key_ref, key_ref_len) != 0) {
        DBG_PRINTF("Expanded key for label <%s> does not match\n", label);
        ret = -1;
    }

    return ret;
}

static int draft31_incoming_initial_test()
{
    int ret = 0;
    /* Create a server context */
    picoquic_quic_t* qserver = picoquic_create(8,
        PICOQUIC_TEST_SERVER_CERT, PICOQUIC_TEST_SERVER_KEY, PICOQUIC_TEST_CERT_STORE,
        "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (qserver == NULL) {
        DBG_PRINTF("%s", "Could not create Quic server context.\n");
        ret = -1;
    }

    if (ret == 0) {
        /* Simulate arrival of an initial packet in the server context */
        int ret = 0;
        picoquic_cnx_t* cnx = NULL;
        picoquic_packet_header ph;
        uint32_t length = (uint32_t) sizeof(draft13_test_input_packet);
        uint64_t current_time = 0;
        uint32_t consumed = 0;
        struct sockaddr_in test_addr_c;

        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        /* Parse the header and decrypt the packet */
        ret = picoquic_parse_header_and_decrypt(qserver, draft13_test_input_packet, length, length,
            (struct sockaddr *)&test_addr_c, current_time, &ph, &cnx, &consumed);

        if (ret != 0) {
            DBG_PRINTF("Cannot parse or decrypt incoming packet, ret = %x\n", ret);
        }
        else if (ph.ptype != picoquic_packet_initial) {
            DBG_PRINTF("Incoming packet type %d instead of initial\n", ph.ptype);
            ret = -1;
        }
        else if (ph.pn != draft13_test_decoded_pn) {
            DBG_PRINTF("Incoming packet sequence %d instead of %d\n", ph.pn, draft13_test_decoded_pn);
            ret = -1;
        }
        else if (consumed != length) {
            DBG_PRINTF("Incoming packet length %d instead of %d\n", consumed, length);
            ret = -1;
        }

        if (cnx != NULL) {
            picoquic_delete_cnx(cnx);
        }

        picoquic_free(qserver);
    }

    return ret;
}

int draft13_vector_test()
{
    int ret = 0;
    int version_index = 0;
    ptls_iovec_t salt;
    uint8_t master_secret[256];
    uint8_t client_secret[256];
    uint8_t server_secret[256];
    ptls_cipher_suite_t cipher = { 0, &ptls_openssl_aes128gcm, &ptls_openssl_sha256 };

    /* Check the label expansions */
    if (ret == 0) {
        ret = draft13_label_expansion_test(&cipher, PICOQUIC_LABEL_KEY,
            draft13_test_server_initial_secret, sizeof(draft13_test_server_initial_secret),
            draft13_test_server_key, sizeof(draft13_test_server_key));
    }

    if (ret == 0) {
        ret = draft13_label_expansion_test(&cipher, PICOQUIC_LABEL_IV,
            draft13_test_server_initial_secret, sizeof(draft13_test_server_initial_secret),
            draft13_test_server_iv, sizeof(draft13_test_server_iv));
    }

    if (ret == 0) {
        ret = draft13_label_expansion_test(&cipher, PICOQUIC_LABEL_PN,
            draft13_test_server_initial_secret, sizeof(draft13_test_server_initial_secret),
            draft13_test_server_pn, sizeof(draft13_test_server_pn));
    }

    if (ret == 0) {
        ret = draft13_label_expansion_test(&cipher, PICOQUIC_LABEL_KEY,
            draft13_test_client_initial_secret, sizeof(draft13_test_client_initial_secret),
            draft13_test_client_key, sizeof(draft13_test_client_key));
    }

    if (ret == 0) {
        ret = draft13_label_expansion_test(&cipher, PICOQUIC_LABEL_IV,
            draft13_test_client_initial_secret, sizeof(draft13_test_client_initial_secret),
            draft13_test_client_iv, sizeof(draft13_test_client_iv));
    }

    if (ret == 0) {
        ret = draft13_label_expansion_test(&cipher, PICOQUIC_LABEL_PN,
            draft13_test_client_initial_secret, sizeof(draft13_test_client_initial_secret),
            draft13_test_client_pn, sizeof(draft13_test_client_pn));
    }

    /* Check the salt */
    version_index = picoquic_get_version_index(draft13_test_vn);
    if (version_index < 0) {
        DBG_PRINTF("Test version (%x) is not supported.\n", draft13_test_vn);
        ret = -1;
    }
    else if (picoquic_supported_versions[version_index].version_aead_key == NULL) {
        DBG_PRINTF("Test version (%x) has no salt.\n", draft13_test_vn);
        ret = -1;
    }
    else if (picoquic_supported_versions[version_index].version_aead_key_length != sizeof(draft13_test_salt))
    {
        DBG_PRINTF("Test version (%x) has no salt[%d], expected [%d].\n", draft13_test_vn,
            (int)picoquic_supported_versions[version_index].version_aead_key_length, (int) sizeof(draft13_test_salt));
        ret = -1;
    }
    else if (memcmp(picoquic_supported_versions[version_index].version_aead_key, draft13_test_salt, sizeof(draft13_test_salt)) != 0) {
        DBG_PRINTF("Test version (%x) does not have matching salt.\n", draft13_test_vn);
        ret = -1;
    }

    /* Check the master secret and then client and server secret */
    if (ret == 0) {
        salt.base = draft13_test_salt;
        salt.len = sizeof(draft13_test_salt);

        ret = picoquic_setup_initial_master_secret(&cipher, salt, draft13_test_cnx_id, master_secret);

        if (ret != 0) {
            DBG_PRINTF("Cannot compute master secret, ret = %x\n", ret);
        }
        else {
            ret = picoquic_setup_initial_secrets(&cipher, master_secret, client_secret, server_secret);

            if (ret != 0) {
                DBG_PRINTF("Cannot derive client and server secrets, ret = %x\n", ret);
            }
            else {
                if (memcmp(client_secret, draft13_test_client_initial_secret, sizeof(draft13_test_client_initial_secret)) != 0) {
                    DBG_PRINTF("%s", "Initial client secret does not match expected value");
                    ret = -1;
                }
                
                if (memcmp(server_secret, draft13_test_server_initial_secret, sizeof(draft13_test_server_initial_secret)) != 0) {
                    DBG_PRINTF("%s", "Initial server secret does not match expected value");
                    ret = -1;
                }
            }
        }
    }

    /* First integration test: verify that the aead keys are as expected */
    if (ret == 0) {
        ret = cleartext_aead_vector_test_one(draft13_test_cnx_id, draft13_test_client_iv, sizeof(draft13_test_client_iv),
            draft13_test_server_iv, sizeof(draft13_test_server_iv), "draft13_vector");
    }

    /* Final integration test: verify that the incoming packet can be decrypted */
    if (ret == 0) {
        ret = draft31_incoming_initial_test();
    }

    return ret;
}
