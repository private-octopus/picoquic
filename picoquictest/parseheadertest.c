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

#include <stdlib.h>
#include <string.h>
#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"

/* test vectors and corresponding structure */
#define TEST_CNXID_LEN_BYTE 0x51
#define TEST_CNXID_LEN_INI 8
#define TEST_CNXID_LEN_REM 4
#define TEST_CNXID_INI_BYTES 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
#define TEST_CNXID_INI_BYTES_ZERO 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#define TEST_CNXID_INI_VAL {{TEST_CNXID_INI_BYTES, TEST_CNXID_INI_BYTES_ZERO}, 8}
#define TEST_CNXID_REM_BYTES 0x04, 0x05, 0x06, 0x07
#define TEST_CNXID_REM_BYTES_ZERO 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#define TEST_CNXID_REM_VAL {{TEST_CNXID_REM_BYTES, TEST_CNXID_REM_BYTES_ZERO}, 4}
#define TEST_CNXID_NULL_VAL {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0}
#define TEST_CNXID_LOCAL_BYTE 0x55
#define TEST_CNXID_LEN_LOCAL 8
#define TEST_CNXID_LOCAL_BYTES 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
#define TEST_CNXID_LOCAL_VAL {{TEST_CNXID_LOCAL_BYTES, TEST_CNXID_INI_BYTES_ZERO}, 8}

/*
 * New definitions
 */
#define TEST_CNXID_LEN_10 8
#define TEST_CNXID_10_BYTES 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
#define TEST_CNXID_10_VAL { { TEST_CNXID_10_BYTES, TEST_CNXID_INI_BYTES_ZERO }, 8 }

static picoquic_connection_id_t test_cnxid_ini = TEST_CNXID_INI_VAL;
static picoquic_connection_id_t test_cnxid_rem = TEST_CNXID_REM_VAL;
static picoquic_connection_id_t test_cnxid_local = TEST_CNXID_LOCAL_VAL;
static picoquic_connection_id_t test_cnxid_r10 = TEST_CNXID_10_VAL;

static uint8_t pinitial10[] = {
    0xC3,
    0x50, 0x43, 0x51, 0x30,
    TEST_CNXID_LEN_INI,
    TEST_CNXID_INI_BYTES,
    TEST_CNXID_LEN_REM,
    TEST_CNXID_REM_BYTES,
    0x00,
    0x44, 00,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hinitial10 = {
    TEST_CNXID_INI_VAL,
    TEST_CNXID_REM_VAL,
    0xDEADBEEF,
    0x50435130,
    22,
    22,
    picoquic_packet_initial,
    0xFFFFFFFF00000000ull,
    0, 
    0x400,
    0,
    0,
    picoquic_packet_context_initial,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static uint8_t pinitial10_l[] = {
    0xC3,
    0x50, 0x43, 0x51, 0x30,
    TEST_CNXID_LEN_INI,
    TEST_CNXID_INI_BYTES,
    TEST_CNXID_LEN_LOCAL,
    TEST_CNXID_LOCAL_BYTES,
    0,
    0x44, 00,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hinitial10_l = {
    TEST_CNXID_INI_VAL,
    TEST_CNXID_LOCAL_VAL,
    0xDEADBEEF,
    0x50435130,
    26,
    26,
    picoquic_packet_initial,
    0xFFFFFFFF00000000ull,
    0,
    0x400,
    0,
    0,
    picoquic_packet_context_initial,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static uint8_t pvnego10[] = {
    0xFF,
    0, 0, 0, 0,
    TEST_CNXID_LEN_10,
    TEST_CNXID_10_BYTES,
    TEST_CNXID_LEN_REM,
    TEST_CNXID_REM_BYTES,
    0x50, 0x43, 0x51, 0x30,
    0xFF, 0, 0, 7
};

static uint8_t pvnegobis10[] = {
    0xAA,
    0, 0, 0, 0,
    TEST_CNXID_LEN_10,
    TEST_CNXID_10_BYTES,
    TEST_CNXID_LEN_REM,
    TEST_CNXID_REM_BYTES,
    0x50, 0x43, 0x51, 0x30,
    0xFF, 0, 0, 7
};

static picoquic_packet_header hvnego10 = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_REM_VAL,
    0,
    0,
    19,
    0,
    picoquic_packet_version_negotiation,
    0,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 19,
    0,
    0,
    picoquic_packet_context_initial,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static uint8_t phandshake[] = {
    0xE3,
    0x50, 0x43, 0x51, 0x30,
    TEST_CNXID_LEN_LOCAL,
    TEST_CNXID_LOCAL_BYTES,
    TEST_CNXID_LEN_REM,
    TEST_CNXID_REM_BYTES,
    0x44, 00,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hhandshake = {
    TEST_CNXID_LOCAL_VAL,
    TEST_CNXID_REM_VAL,
    0xDEADBEEF,
    0x50435130,
    21,
    21,
    picoquic_packet_handshake,
    0xFFFFFFFF00000000ull,
    0,
    0x400,
    0,
    2,
    picoquic_packet_context_handshake,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

static uint8_t packet_short_phi0_c_32[] = {
    0x43,
    TEST_CNXID_10_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hphi0_c_32 = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_NULL_VAL,
    0xDEADBEEF,
    0,
    9,
    9,
    picoquic_packet_1rtt_protected,
    0xFFFFFFFF00000000ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 9,
    0,
    3,
    picoquic_packet_context_application,
    0,
    0,
    0,
    0,
    1,
    0,
    0
};

static uint8_t packet_short_phi0_c_32_spin[] = {
    0x63, /* Setting the spin bit */
    TEST_CNXID_10_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hphi0_c_32_spin = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_NULL_VAL,
    0xDEADBEEF,
    0,
    9,
    9,
    picoquic_packet_1rtt_protected,
    0xFFFFFFFF00000000ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 9, 
    0,
    3,
    picoquic_packet_context_application,
    0,
    1,
    0,
    1,
    0,
    0,
    0
};

static uint8_t packet_short_phi1_noc_32[] = {
    0x47,
    0xDE, 0xAD, 0xBE, 0xEF,
};

static picoquic_packet_header hphi1_noc_32 = { 
    TEST_CNXID_NULL_VAL,
    TEST_CNXID_NULL_VAL,
    0xDEADBEEF,
    0,
    1,
    1,
    picoquic_packet_1rtt_protected,
    0xFFFFFFFF00000000ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 1,
    0,
    3,
    picoquic_packet_context_application,
    1,
    0,
    0,
    0,
    0,
    0,
    0
};

struct _test_entry {
    uint8_t* packet;
    size_t length;
    picoquic_packet_header* ph;
    int decode_test_only;
    uint8_t local_cid_length;
};

static struct _test_entry test_entries[] = {
    { pinitial10, sizeof(pinitial10), &hinitial10, 1, 8 },
    { pinitial10_l, sizeof(pinitial10_l), &hinitial10_l, 0, 8 },
    { pvnego10, sizeof(pvnego10), &hvnego10, 1, 8 },
    { pvnegobis10, sizeof(pvnegobis10), &hvnego10, 1, 8 },
    { phandshake, sizeof(phandshake), &hhandshake, 1, 8 },
    { packet_short_phi0_c_32, sizeof(packet_short_phi0_c_32), &hphi0_c_32, 0, 8 },
    { packet_short_phi0_c_32_spin, sizeof(packet_short_phi0_c_32_spin), &hphi0_c_32_spin, 1, 8 },
    { packet_short_phi1_noc_32, sizeof(packet_short_phi1_noc_32), &hphi1_noc_32, 1, 0 }
};

static const size_t nb_test_entries = sizeof(test_entries) / sizeof(struct _test_entry);

int parseheadertest()
{
    int ret = 0;
    picoquic_packet_header ph;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx_10 = NULL;
    struct sockaddr_in addr_10;
    picoquic_cnx_t* pcnx;
    uint8_t packet[PICOQUIC_MAX_PACKET_SIZE];

    /* Initialize the quic context and the connection contexts */
    memset(&addr_10, 0, sizeof(struct sockaddr_in));
    addr_10.sin_family = AF_INET;
#ifdef _WINDOWS
    addr_10.sin_addr.S_un.S_addr = 0x0A000002;
#else
    addr_10.sin_addr.s_addr = 0x0A000002;
#endif
    // addr_07.sin_port = 4433;
    addr_10.sin_port = 4434;

    quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (quic == NULL) {
        ret = -1;
    } else {
        cnx_10 = picoquic_create_cnx(quic, test_cnxid_ini, test_cnxid_rem, (struct sockaddr*)&addr_10,
            0, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, 1);

        if (cnx_10 == NULL) {
            ret = -1;
        }
        else {
            /* Remove old local CID from table and avoid leak. */
            picoquic_delete_local_cnxid(cnx_10, cnx_10->path[0]->p_local_cnxid);
            if (cnx_10->nb_local_cnxid != 0) {
                DBG_PRINTF("Expected 0 cnxid left, got %d", cnx_10->nb_local_cnxid);
            }
            else {
                /* Update the local cnx_id so it be predictable in tests */
                picoquic_local_cnxid_t* local_cnxid0 = picoquic_create_local_cnxid(cnx_10, &test_cnxid_local);
                if (local_cnxid0 == NULL) {
                    DBG_PRINTF("%s", "Cannot create the new CNX_ID");
                    ret = -1;
                }
                else {
                    cnx_10->path[0]->p_local_cnxid = local_cnxid0;
                }
            }
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_test_entries; i++) {
        pcnx = (i < 3) ? NULL : cnx_10;
        quic->local_cnxid_length = test_entries[i].local_cid_length;
        memset(packet, 0xcc, sizeof(packet));
        memcpy(packet, test_entries[i].packet, (uint32_t)test_entries[i].length);

        if (picoquic_parse_packet_header(quic, packet, sizeof(packet),
                (struct sockaddr*)&addr_10, &ph, &pcnx, 1)
            != 0) {
            ret = -1;
        } else if (picoquic_compare_connection_id(&ph.dest_cnx_id, &test_entries[i].ph->dest_cnx_id) != 0) {
            ret = -1;
        } else if (picoquic_compare_connection_id(&ph.srce_cnx_id, &test_entries[i].ph->srce_cnx_id) != 0) {
            ret = -1;
        } else if (ph.vn != test_entries[i].ph->vn) {
            ret = -1;
        } else if (ph.offset != test_entries[i].ph->offset) {
            ret = -1;
        } else if (ph.pn_offset != test_entries[i].ph->pn_offset) {
            ret = -1;
        } else if (ph.payload_length != test_entries[i].ph->payload_length) {
            ret = -1;
        } else if (ph.ptype != test_entries[i].ph->ptype) {
            ret = -1;
        } else if (ph.spin != test_entries[i].ph->spin) {
            ret = -1;
        } else if (ph.epoch != test_entries[i].ph->epoch) {
            ret = -1;
        } else if (ph.pc != test_entries[i].ph->pc) {
            ret = -1;
        } else if (ph.key_phase != test_entries[i].ph->key_phase) {
            ret = -1;
        }
    }

    if (ret == 0) {
        quic->local_cnxid_length = 8;
    }

    for (size_t i = 0; ret == 0 && i < nb_test_entries; i++) {
        size_t header_length;
        size_t pn_offset;
        size_t pn_length;

        if (test_entries[i].decode_test_only) {
            continue;
        }

        pcnx = (i < 3) ? NULL : cnx_10;
        memset(packet, 0xcc, sizeof(packet));
        /* Prepare the header inside the packet */
        if (i < 2) {
            cnx_10->path[0]->remote_cnxid = picoquic_null_connection_id;
        }
        else {
            cnx_10->path[0]->remote_cnxid = test_cnxid_r10;
        }
        header_length = picoquic_create_packet_header(cnx_10, test_entries[i].ph->ptype,
            test_entries[i].ph->pn, &cnx_10->path[0]->remote_cnxid, &cnx_10->path[0]->p_local_cnxid->cnx_id, 0, packet, &pn_offset, &pn_length);
        picoquic_update_payload_length(packet, pn_offset, pn_offset, pn_offset +
            test_entries[i].ph->payload_length);
        
        if ( pn_offset != test_entries[i].ph->pn_offset) {
           ret = -1;
        }
        
        if (memcmp(packet, test_entries[i].packet, header_length) != 0)
        {
            ret = -1;
        }
    }

    return ret;
}


/* Test a range of variations of packet encryption and decryption */
int test_packet_decrypt_one(
    picoquic_quic_t* q_server,
    uint8_t * send_buffer,
    size_t send_length,
    size_t packet_length,
    struct sockaddr * addr_from,
    picoquic_cnx_t* cnx_target,
    picoquic_packet_header * expected_ph,
    int expected_return
)
{
    int ret = 0;
    int decoding_return;
    uint64_t current_time = 0;
    picoquic_packet_header received_ph;
    picoquic_cnx_t* server_cnx = NULL;
    size_t consumed = 0;
    int new_context_created = 0;

    /* Decrypt the packet */
    decoding_return = picoquic_parse_header_and_decrypt(q_server,
        send_buffer, send_length, packet_length,
        addr_from,
        current_time, &received_ph, &server_cnx,
        &consumed, &new_context_created);

    /* verify that decryption matches original value */
    if (decoding_return != expected_return) {
        DBG_PRINTF("Return %x instead of %x.\n", decoding_return, expected_return);
        ret = -1;
    } else if (cnx_target != NULL && server_cnx != cnx_target) {
        DBG_PRINTF("%s", "Could not retrieve the connection\n");
        ret = -1;
    }
    else if (received_ph.ptype != expected_ph->ptype) {
        DBG_PRINTF("PTYPE %x instead of %x.\n", received_ph.ptype, expected_ph->ptype);
        ret = -1;
    }
    else if (received_ph.offset != expected_ph->offset) {
        DBG_PRINTF("Offset %x instead of %x.\n", received_ph.offset, expected_ph->offset);
        ret = -1;
    }
    else if (received_ph.vn != expected_ph->vn) {
        DBG_PRINTF("Version %x instead of %x.\n", received_ph.vn, expected_ph->vn);
        ret = -1;
    }
    else if (received_ph.pn64 != expected_ph->pn64) {
        DBG_PRINTF("PN64 %llx instead of %llx.\n", (unsigned long long)received_ph.pn64, (unsigned long long)expected_ph->pn64);
        ret = -1;
    }
    else if (received_ph.payload_length != expected_ph->payload_length) {
        DBG_PRINTF("Payload length %x instead of %x.\n", received_ph.payload_length, expected_ph->payload_length);
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&received_ph.dest_cnx_id, &expected_ph->dest_cnx_id) != 0) {
        DBG_PRINTF("%s", "Dest CNXID does not match.\n");
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&received_ph.srce_cnx_id, &expected_ph->srce_cnx_id) != 0) {
        DBG_PRINTF("%s", "Srce CNXID does not match.\n");
        ret = -1;
    }

    return ret;
}

int test_packet_encrypt_one(
    struct sockaddr * addr_from,
    picoquic_cnx_t* cnx_client,
    picoquic_quic_t* q_server,
    picoquic_cnx_t* server_cnx,
    picoquic_packet_type_enum ptype,
    uint32_t length
)
{
    int ret = 0;
    size_t header_length = 0;
    size_t checksum_overhead = 0;
    size_t send_length = 0;
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    picoquic_path_t * path_x = cnx_client->path[0];
    uint64_t current_time = 0;
    picoquic_packet_header expected_header;
    picoquic_packet_t * packet = (picoquic_packet_t *) malloc(sizeof(picoquic_packet_t));
    picoquic_packet_context_enum pc = 0;

    if (packet == NULL) {
        DBG_PRINTF("%s", "Out of memory\n");
        ret = -1;
    }
    else {
        memset(packet, 0, sizeof(picoquic_packet_t));
        memset(packet->bytes, 0xbb, length);
        header_length = picoquic_predict_packet_header_length(cnx_client, ptype);
        packet->ptype = ptype;
        packet->offset = header_length;
        packet->length = length;
        packet->sequence_number = cnx_client->pkt_ctx[pc].send_sequence;
        packet->send_path = cnx_client->path[0];

        /* Create a packet with specified parameters */
        picoquic_finalize_and_protect_packet(cnx_client, packet,
            ret, length, header_length, checksum_overhead,
            &send_length, send_buffer, PICOQUIC_MAX_PACKET_SIZE, 
            &path_x->remote_cnxid, &path_x->p_local_cnxid->cnx_id,
            path_x, current_time);

        expected_header.ptype = packet->ptype;
        expected_header.offset = packet->offset;
        expected_header.pn64 = packet->sequence_number;
        expected_header.vn = picoquic_supported_versions[cnx_client->version_index].version;
        expected_header.payload_length = packet->length - packet->offset;

        if (packet->ptype == picoquic_packet_0rtt_protected ||
            packet->ptype == picoquic_packet_initial) {
            expected_header.dest_cnx_id = cnx_client->initial_cnxid;
        }
        else {
            expected_header.dest_cnx_id = cnx_client->path[0]->remote_cnxid;
        }

        if (packet->ptype == picoquic_packet_1rtt_protected) {
            expected_header.vn = 0;
            expected_header.srce_cnx_id = picoquic_null_connection_id;
        }
        else {
            expected_header.vn = picoquic_supported_versions[cnx_client->version_index].version;
            expected_header.srce_cnx_id = cnx_client->path[0]->p_local_cnxid->cnx_id;
        }

        /* Decrypt the packet */
        ret = test_packet_decrypt_one(q_server,
            send_buffer, send_length, send_length,
            addr_from, server_cnx, &expected_header, 0);
    }
    return ret;
}

static const uint8_t test_0rtt_secret[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1
};

static const uint8_t test_handshake_secret[] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
};

static const uint8_t test_1rtt_secret[] = {
    0, 1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10
};

static uint8_t const addr1[4] = { 10, 0, 0, 1 };

int packet_enc_dec_test()
{
    int ret = 0;
    struct sockaddr_in test_addr_c;
    picoquic_cnx_t* cnx_client = NULL;
    picoquic_cnx_t* cnx_server = NULL;
    picoquic_quic_t* qclient = NULL;
    picoquic_quic_t* qserver = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {
        qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        qserver = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            "test", NULL, NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
        if (qclient == NULL || qserver == NULL) {
            DBG_PRINTF("%s", "Could not create Quic contexts.\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        memset(&test_addr_c, 0, sizeof(struct sockaddr_in));
        test_addr_c.sin_family = AF_INET;
        memcpy(&test_addr_c.sin_addr, addr1, 4);
        test_addr_c.sin_port = 12345;

        cnx_client = picoquic_create_cnx(qclient, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)&test_addr_c, 0, 0, NULL, PICOQUIC_TEST_ALPN, 1);
        if (cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create client connection context.\n");
            ret = -1;
        }
        else {
            ret = picoquic_start_client_cnx(cnx_client);
        }
    }

    /* Test with a series of packets */
    /* First, client initial */
    if (ret == 0) {
        ret = test_packet_encrypt_one(
            (struct sockaddr *) &test_addr_c,
            cnx_client, qserver, NULL, picoquic_packet_initial, 1256);
    }
    /* If that work, update the connection context */
    if (ret == 0) {
        cnx_server = qserver->cnx_list;
        if (cnx_server == NULL) {
            DBG_PRINTF("%s", "Did not create the server connection context.\n");
            ret = -1;
        } else {
            /* Set the remote context ID for the client */
            cnx_client->path[0]->remote_cnxid = cnx_server->path[0]->p_local_cnxid->cnx_id;
        }
    }

    /* Try handshake packet from client */
    if (ret == 0) {
        cnx_client->crypto_context[2].aead_encrypt = picoquic_setup_test_aead_context(1, test_handshake_secret);
        cnx_server->crypto_context[2].aead_decrypt = picoquic_setup_test_aead_context(0, test_handshake_secret);
        cnx_client->crypto_context[2].pn_enc = picoquic_pn_enc_create_for_test(test_handshake_secret);
        cnx_server->crypto_context[2].pn_dec = picoquic_pn_enc_create_for_test(test_handshake_secret);
        ret = test_packet_encrypt_one(
            (struct sockaddr *) &test_addr_c,
            cnx_client, qserver, cnx_server, picoquic_packet_handshake, 1256);
    }

    /* Now try a zero RTT packet */
    if (ret == 0) {
        cnx_client->crypto_context[1].aead_encrypt = picoquic_setup_test_aead_context(1, test_0rtt_secret);
        cnx_server->crypto_context[1].aead_decrypt = picoquic_setup_test_aead_context(0, test_0rtt_secret);
        cnx_client->crypto_context[1].pn_enc = picoquic_pn_enc_create_for_test(test_0rtt_secret);
        cnx_server->crypto_context[1].pn_dec = picoquic_pn_enc_create_for_test(test_0rtt_secret);

        /* Use a null connection ID to trigger use of initial ID */
        cnx_client->path[0]->remote_cnxid = picoquic_null_connection_id;

        ret = test_packet_encrypt_one(
            (struct sockaddr *) &test_addr_c,
            cnx_client, qserver, cnx_server, picoquic_packet_0rtt_protected, 256);


        /* Set the remote context ID for the next test  */
        cnx_client->path[0]->remote_cnxid = cnx_server->path[0]->p_local_cnxid->cnx_id;
    }

    /* And try a 1 RTT packet */
    if (ret == 0) {
        cnx_client->crypto_context[3].aead_encrypt = picoquic_setup_test_aead_context(1, test_1rtt_secret);
        cnx_server->crypto_context[3].aead_decrypt = picoquic_setup_test_aead_context(0, test_1rtt_secret);
        cnx_client->crypto_context[3].pn_enc = picoquic_pn_enc_create_for_test(test_1rtt_secret);
        cnx_server->crypto_context[3].pn_dec = picoquic_pn_enc_create_for_test(test_1rtt_secret);

        ret = test_packet_encrypt_one(
            (struct sockaddr *) &test_addr_c,
            cnx_client, qserver, cnx_server, picoquic_packet_1rtt_protected, 1024);
    }

    if (cnx_client != NULL) {
        picoquic_delete_cnx(cnx_client);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    if (qserver != NULL) {
        picoquic_free(qserver);
    }

    return ret;
}
