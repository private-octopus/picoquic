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

#include "../picoquic/picoquic_internal.h"
#include <stdlib.h>
#include <string.h>

/* test vectors and corresponding structure */
#define TEST_CNXID_LEN_BYTE 0x51
#define TEST_CNXID_INI_BYTES 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
#define TEST_CNXID_INI_BYTES_ZERO 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#define TEST_CNXID_INI_VAL {{TEST_CNXID_INI_BYTES, TEST_CNXID_INI_BYTES_ZERO}, 8}
#define TEST_CNXID_REM_BYTES 0x04, 0x05, 0x06, 0x07
#define TEST_CNXID_REM_BYTES_ZERO 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
#define TEST_CNXID_REM_VAL {{TEST_CNXID_REM_BYTES, TEST_CNXID_REM_BYTES_ZERO}, 4}
#define TEST_CNXID_NULL_VAL {{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0}

/*
 * New definitions
 */

#define TEST_CNXID_10_BYTES 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
#define TEST_CNXID_10_VAL { { TEST_CNXID_10_BYTES, TEST_CNXID_INI_BYTES_ZERO }, 8 }

static picoquic_connection_id_t test_cnxid_ini = TEST_CNXID_INI_VAL;
static picoquic_connection_id_t test_cnxid_rem = TEST_CNXID_REM_VAL;

static uint8_t pinitial10[] = {
    0xFF,
    0x50, 0x43, 0x51, 0x30,
    TEST_CNXID_LEN_BYTE,
    TEST_CNXID_INI_BYTES,
    TEST_CNXID_REM_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF,
    0x44, 00
};

static picoquic_packet_header hinitial10 = {
    TEST_CNXID_INI_VAL,
    TEST_CNXID_REM_VAL,
    0xDEADBEEF,
    0x50435130,
    24,
    18,
    picoquic_packet_client_initial,
    0xFFFFFFFF00000000ull,
    0, 
    0x400,
    0
};

static uint8_t pvnego10[] = {
    0xFF,
    0, 0, 0, 0,
    TEST_CNXID_LEN_BYTE,
    TEST_CNXID_10_BYTES,
    TEST_CNXID_REM_BYTES,
    0x50, 0x43, 0x51, 0x30,
    0xFF, 0, 0, 7
};

static uint8_t pvnegobis10[] = {
    0xAA,
    0, 0, 0, 0,
    TEST_CNXID_LEN_BYTE,
    TEST_CNXID_10_BYTES,
    TEST_CNXID_REM_BYTES,
    0x50, 0x43, 0x51, 0x30,
    0xFF, 0, 0, 7
};

static picoquic_packet_header hvnego10 = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_REM_VAL,
    0,
    0,
    18,
    0,
    picoquic_packet_version_negotiation,
    0,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 18,
    0
};

static uint8_t packet_short_phi0_c_32[] = {
    0x32,
    TEST_CNXID_10_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hphi0_c_32 = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_NULL_VAL,
    0xDEADBEEF,
    0,
    13,
    9,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFF00000000ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 13, 
    0
};

static uint8_t packet_short_phi1_c_16[] = {
    0x71,
    TEST_CNXID_10_BYTES,
    0xBE, 0xEF
};

static picoquic_packet_header hphi1_c_16 = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_NULL_VAL,
    0xBEEF,
    0,
    11,
    9,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFF0000ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 11,
    0
};

static uint8_t packet_short_phi1_c_8[] = {
    0x70,
    TEST_CNXID_10_BYTES,
    0xEF
};

static picoquic_packet_header hphi1_c_8 = {
    TEST_CNXID_10_VAL,
    TEST_CNXID_NULL_VAL,
    0xEF,
    0,
    10,
    9,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFFFF00ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 10,
    0
};

static uint8_t packet_short_phi0_noc_16[] = {
    0x31,
    0xBE, 0xEF,
};

static picoquic_packet_header hphi0_noc_16 = { 
    TEST_CNXID_NULL_VAL,
    TEST_CNXID_NULL_VAL,
    0xBEEF,
    0,
    3,
    1,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFF0000ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 3,
    0
};

static uint8_t packet_short_phi0_noc_8[] = {
    0x30,
    0xEF
};

static picoquic_packet_header hphi0_noc_8 = {
    TEST_CNXID_NULL_VAL,
    TEST_CNXID_NULL_VAL,
    0xEF,
    0,
    2,
    1,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFFFF00ull,
    0,
    PICOQUIC_MAX_PACKET_SIZE - 2,
    0
};

struct _test_entry {
    uint8_t* packet;
    size_t length;
    picoquic_packet_header* ph;
};

static struct _test_entry test_entries[] = {
    { pinitial10, sizeof(pinitial10), &hinitial10 },
    { pvnego10, sizeof(pvnego10), &hvnego10 },
    { pvnegobis10, sizeof(pvnegobis10), &hvnego10 },
    { packet_short_phi0_c_32, sizeof(packet_short_phi0_c_32), &hphi0_c_32 },
    { packet_short_phi1_c_16, sizeof(packet_short_phi1_c_16), &hphi1_c_16 },
    { packet_short_phi1_c_8, sizeof(packet_short_phi1_c_8), &hphi1_c_8 },
    { packet_short_phi0_noc_16, sizeof(packet_short_phi0_noc_16), &hphi0_noc_16 },
    { packet_short_phi0_noc_8, sizeof(packet_short_phi0_noc_8), &hphi0_noc_8 }
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

    quic = picoquic_create(8, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (quic == NULL) {
        ret = -1;
    } else {
        cnx_10 = picoquic_create_cnx(quic, test_cnxid_ini, test_cnxid_rem, (struct sockaddr*)&addr_10,
            0, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, 1);

        if (cnx_10 == NULL) {
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_test_entries; i++) {
        pcnx = (i < 3) ? NULL : cnx_10;
        if (i >= 6) {
            quic->local_ctx_length = 0;
        }
        memset(packet, 0xcc, sizeof(packet));
        memcpy(packet, test_entries[i].packet, (uint32_t)test_entries[i].length);

        if (picoquic_parse_packet_header(quic, packet, sizeof(packet),
                (struct sockaddr*)&addr_10, &ph, &pcnx)
            != 0) {
            ret = -1;
        }

        if (picoquic_compare_connection_id(&ph.dest_cnx_id, &test_entries[i].ph->dest_cnx_id) != 0 || 
            picoquic_compare_connection_id(&ph.srce_cnx_id, &test_entries[i].ph->srce_cnx_id) != 0 ||
            ph.pn != test_entries[i].ph->pn || 
            ph.vn != test_entries[i].ph->vn ||
            ph.offset != test_entries[i].ph->offset ||
            ph.payload_length != test_entries[i].ph->payload_length ||
            ph.ptype != test_entries[i].ph->ptype || ph.pnmask != test_entries[i].ph->pnmask) {
            ret = -1;
        }
    }

    return ret;
}
