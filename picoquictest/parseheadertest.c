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
#include "../picoquic/picoquic_internal.h"

/* test vectors and corresponding structure */

#define TEST_CNXID_INI_BYTES  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 
#define TEST_CNXID_INI_VAL    0x0001020304050607ull

#define TEST_CNXID_07_BYTES  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
#define TEST_CNXID_07_VAL    0x0102030405060708ull

static uint8_t pinitial07[] = {
    0x82,
    TEST_CNXID_INI_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF,
    0xFF, 0, 0, 7
};

static picoquic_packet_header hinitial07 = {
    TEST_CNXID_INI_VAL,
    0xDEADBEEF,
    0xFF000007ul,
    17,
    picoquic_packet_client_initial,
    0xFFFFFFFF00000000ull,
    0, 1
};

static uint8_t pvnego07[] = {
    0x81,
    TEST_CNXID_07_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF,
    0x1A, 0x2A, 0x3A, 0x4A,
    0xFF, 0, 0, 7,
    0x50, 0x43, 0x51, 0x30
};

static picoquic_packet_header hvnego07 = {
    TEST_CNXID_07_VAL,
    0xDEADBEEF,
    0x1A2A3A4Aul,
    17,
    picoquic_packet_version_negotiation,
    0xFFFFFFFF00000000ull,
    0, 1
};

static uint8_t packet_short_phi0_c_32_07[] = {
    0x43,
    TEST_CNXID_07_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hphi0_c_32_07 = {
    TEST_CNXID_07_VAL,
    0xDEADBEEF,
    0,
    13,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFF00000000ull,
    0, 1
};

static uint8_t packet_short_phi0_noc_16_07[] = {
    0x02,
    0xBE, 0xEF,
};

static picoquic_packet_header hphi0_noc_16_07 = {
    0,
    0xBEEF,
    0,
    3,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFF0000ull,
    0, 1
};

static uint8_t packet_short_phi0_noc_8_07[] = {
    0x01,
    0xEF
};

static picoquic_packet_header hphi0_noc_8_07 = {
    0,
    0xEF,
    0,
    2,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFFFF00ull,
    0, 1
};

static uint8_t packet_short_phi1_c_16_07[] = {
    0x62,
    TEST_CNXID_07_BYTES,
    0xBE, 0xEF
};

static picoquic_packet_header hphi1_c_16_07 = {
    TEST_CNXID_07_VAL,
    0xBEEF,
    0,
    11,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFF0000ull,
    0, 1
};

static uint8_t packet_short_phi1_c_8_07[] = {
    0x61,
    TEST_CNXID_07_BYTES,
    0xEF
};

static picoquic_packet_header hphi1_c_8_07 = {
    TEST_CNXID_07_VAL,
    0xEF,
    0,
    10,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFFFF00ull,
    0, 1
};

/*
 * New definitions
 */

#define TEST_CNXID_08_BYTES  0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
#define TEST_CNXID_08_VAL    0x0203040506070809ull

static uint8_t pinitial08[] = {
    0xFF,
    TEST_CNXID_INI_BYTES,
    0x50, 0x43, 0x51, 0x30,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hinitial08 = {
    TEST_CNXID_INI_VAL,
    0xDEADBEEF,
    0x50435130,
    17,
    picoquic_packet_client_initial,
    0xFFFFFFFF00000000ull,
    0, 0
};

static uint8_t pvnego08[] = {
    0xFF,
    TEST_CNXID_08_BYTES,
    0, 0, 0, 0,
    0x50, 0x43, 0x51, 0x30,
    0xFF, 0, 0, 7
};

static uint8_t pvnegobis08[] = {
    0xAA,
    TEST_CNXID_08_BYTES,
    0, 0, 0, 0,
    0x50, 0x43, 0x51, 0x30,
    0xFF, 0, 0, 7
};

static picoquic_packet_header hvnego08 = {
    TEST_CNXID_08_VAL,
    0,
    0,
    13,
    picoquic_packet_version_negotiation,
    0,
    0, 0
};

static uint8_t packet_short_phi0_c_32_08[] = {
    0x1D,
    TEST_CNXID_08_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hphi0_c_32_08 = {
    TEST_CNXID_08_VAL,
    0xDEADBEEF,
    0,
    13,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFF00000000ull,
    0, 0
};

static uint8_t packet_short_phi1_c_16_08[] = {
    0x3E,
    TEST_CNXID_08_BYTES,
    0xBE, 0xEF
};

static picoquic_packet_header hphi1_c_16_08 = {
    TEST_CNXID_08_VAL,
    0xBEEF,
    0,
    11,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFF0000ull,
    0, 0
};

static uint8_t packet_short_phi1_c_8_08[] = {
    0x3F,
    TEST_CNXID_08_BYTES,
    0xEF
};

static picoquic_packet_header hphi1_c_8_08 = {
    TEST_CNXID_08_VAL,
    0xEF,
    0,
    10,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFFFF00ull,
    0, 0
};


static uint8_t packet_short_phi0_noc_16_08[] = {
    0x5E,
    0xBE, 0xEF,
};

static picoquic_packet_header hphi0_noc_16_08 = {
    0,
    0xBEEF,
    0,
    3,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFF0000ull,
    0, 0
};

static uint8_t packet_short_phi0_noc_8_08[] = {
    0x5F,
    0xEF
};

static picoquic_packet_header hphi0_noc_8_08 = {
    0,
    0xEF,
    0,
    2,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFFFF00ull,
    0, 0
};

struct _test_entry {
    uint8_t * packet;
    size_t length;
    picoquic_packet_header * ph;
};

static struct _test_entry test_entries[] = {
    { pinitial07 , sizeof(pinitial07), &hinitial07 },
    { pvnego07 , sizeof(pvnego07), &hvnego07 },
    { packet_short_phi0_c_32_07, sizeof(packet_short_phi0_c_32_07), &hphi0_c_32_07 },
    { packet_short_phi1_c_16_07 , sizeof(packet_short_phi1_c_16_07), &hphi1_c_16_07 },
    { packet_short_phi1_c_8_07, sizeof(packet_short_phi1_c_8_07), &hphi1_c_8_07 },
    { packet_short_phi0_noc_16_07, sizeof(packet_short_phi0_noc_16_07), &hphi0_noc_16_07 },
    { packet_short_phi0_noc_8_07, sizeof(packet_short_phi0_noc_8_07), &hphi0_noc_8_07 },
    { pinitial08 , sizeof(pinitial08), &hinitial08 },
    { pvnego08, sizeof(pvnego08), &hvnego08},
    { pvnegobis08, sizeof(pvnegobis08), &hvnego08 },
    { packet_short_phi0_c_32_08, sizeof(packet_short_phi0_c_32_08), &hphi0_c_32_08 },
    { packet_short_phi1_c_16_08 , sizeof(packet_short_phi1_c_16_08), &hphi1_c_16_08 },
    { packet_short_phi1_c_8_08, sizeof(packet_short_phi1_c_8_08), &hphi1_c_8_08 },
    { packet_short_phi0_noc_16_08, sizeof(packet_short_phi0_noc_16_08), &hphi0_noc_16_08 },
    { packet_short_phi0_noc_8_08, sizeof(packet_short_phi0_noc_8_08), &hphi0_noc_8_08 }
};

static const size_t nb_test_entries = sizeof(test_entries) / sizeof(struct _test_entry);

int parseheadertest()
{
    int ret = 0;
    picoquic_packet_header ph;
    picoquic_quic_t * quic = NULL;
    picoquic_cnx_t * cnx_07 = NULL;
    picoquic_cnx_t * cnx_08 = NULL;
    struct sockaddr_in addr_07;
    struct sockaddr_in addr_08;
    picoquic_cnx_t * pcnx;


    /* Initialize the quic context and the connection contexts */
    memset(&addr_07, 0, sizeof(struct sockaddr_in));
    memset(&addr_08, 0, sizeof(struct sockaddr_in));
    addr_07.sin_family = AF_INET;
    addr_08.sin_family = AF_INET;
#ifdef _WINDOWS
    addr_07.sin_addr.S_un.S_addr = 0x0A000001;
    addr_08.sin_addr.S_un.S_addr = 0x0A000002;
#else
    addr_07.sin_addr.s_addr = 0x0A000001;
    addr_08.sin_addr.s_addr = 0x0A000002;
#endif
    addr_07.sin_port = 4433;
    addr_08.sin_port = 4434;

    quic = picoquic_create(8, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (quic == NULL)
    {
        ret = -1;
    }
    else
    {
        cnx_07 = picoquic_create_cnx(quic, TEST_CNXID_07_VAL, (struct sockaddr *) &addr_07,
            0, PICOQUIC_SECOND_INTEROP_VERSION, NULL, NULL);

        cnx_08 = picoquic_create_cnx(quic, TEST_CNXID_08_VAL, (struct sockaddr *) &addr_08,
            0, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL);

        if (cnx_07 == NULL || cnx_08 == NULL)
        {
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_test_entries; i++)
    {
        pcnx = NULL;

        if (picoquic_parse_packet_header(quic, test_entries[i].packet, (uint32_t)test_entries[i].length,
            (test_entries[i].ph->version_index == 0) ? (struct sockaddr *)&addr_08 : (struct sockaddr *)&addr_07,
            0, &ph, &pcnx) != 0)
        {
            ret = -1;
        }

        if (ph.cnx_id != test_entries[i].ph->cnx_id ||
            ph.pn != test_entries[i].ph->pn ||
            ph.vn != test_entries[i].ph->vn ||
            ph.offset != test_entries[i].ph->offset ||
            ph.ptype != test_entries[i].ph->ptype ||
            ph.pnmask != test_entries[i].ph->pnmask)
        {
            ret = -1;
        }
    }

    return ret;
}
