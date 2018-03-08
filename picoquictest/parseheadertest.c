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

#define TEST_CNXID_INI_BYTES 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
#define TEST_CNXID_INI_VAL 0x0001020304050607ull

#define TEST_CNXID_07_BYTES 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
#define TEST_CNXID_07_VAL 0x0102030405060708ull

/*
 * New definitions
 */

#define TEST_CNXID_08_BYTES 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
#define TEST_CNXID_08_VAL 0x0203040506070809ull

static picoquic_connection_id_t test_cnxid_08 = { TEST_CNXID_08_VAL };

static uint8_t pinitial08[] = {
    0xFF,
    TEST_CNXID_INI_BYTES,
    0x50, 0x43, 0x51, 0x30,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hinitial08 = {
    { TEST_CNXID_INI_VAL },
    0xDEADBEEF,
    0x50435130,
    17,
    13,
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
    { TEST_CNXID_08_VAL },
    0,
    0,
    13,
    0,
    picoquic_packet_version_negotiation,
    0,
    0, 0
};

static uint8_t packet_short_phi0_c_32[] = {
    0x02,
    TEST_CNXID_08_BYTES,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hphi0_c_32 = {
    { TEST_CNXID_08_VAL },
    0xDEADBEEF,
    0,
    13,
    9,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFF00000000ull,
    0, 0
};

static uint8_t packet_short_phi1_c_16[] = {
    0x21,
    TEST_CNXID_08_BYTES,
    0xBE, 0xEF
};

static picoquic_packet_header hphi1_c_16 = {
    { TEST_CNXID_08_VAL },
    0xBEEF,
    0,
    11,
    9,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFF0000ull,
    0, 0
};

static uint8_t packet_short_phi1_c_8[] = {
    0x20,
    TEST_CNXID_08_BYTES,
    0xEF
};

static picoquic_packet_header hphi1_c_8 = {
    { TEST_CNXID_08_VAL },
    0xEF,
    0,
    10,
    9,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFFFF00ull,
    0, 0
};

static uint8_t packet_short_phi0_noc_16[] = {
    0x41,
    0xBE, 0xEF,
};

static picoquic_packet_header hphi0_noc_16 = {
    { 0 },
    0xBEEF,
    0,
    3,
    1,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFF0000ull,
    0, 0
};

static uint8_t packet_short_phi0_noc_8[] = {
    0x40,
    0xEF
};

static picoquic_packet_header hphi0_noc_8 = {
    { 0 },
    0xEF,
    0,
    2,
    1,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFFFF00ull,
    0, 0
};

struct _test_entry {
    uint8_t* packet;
    size_t length;
    picoquic_packet_header* ph;
};

static struct _test_entry test_entries[] = {
    { pinitial08, sizeof(pinitial08), &hinitial08 },
    { pvnego08, sizeof(pvnego08), &hvnego08 },
    { pvnegobis08, sizeof(pvnegobis08), &hvnego08 },
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
    picoquic_cnx_t* cnx_08 = NULL;
    struct sockaddr_in addr_08;
    picoquic_cnx_t* pcnx;

    /* Initialize the quic context and the connection contexts */
    memset(&addr_08, 0, sizeof(struct sockaddr_in));
    addr_08.sin_family = AF_INET;
#ifdef _WINDOWS
    addr_08.sin_addr.S_un.S_addr = 0x0A000002;
#else
    addr_08.sin_addr.s_addr = 0x0A000002;
#endif
    // addr_07.sin_port = 4433;
    addr_08.sin_port = 4434;

    quic = picoquic_create(8, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, 0, NULL, NULL, NULL, 0);
    if (quic == NULL) {
        ret = -1;
    } else {
        cnx_08 = picoquic_create_cnx(quic, test_cnxid_08, (struct sockaddr*)&addr_08,
            0, PICOQUIC_INTERNAL_TEST_VERSION_1, NULL, NULL, 1);

        if (cnx_08 == NULL) {
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_test_entries; i++) {
        pcnx = NULL;

        if (picoquic_parse_packet_header(quic, test_entries[i].packet, (uint32_t)test_entries[i].length,
                (struct sockaddr*)&addr_08, &ph, &pcnx)
            != 0) {
            ret = -1;
        }

        if (picoquic_compare_connection_id(&ph.cnx_id, &test_entries[i].ph->cnx_id) != 0 || ph.pn != test_entries[i].ph->pn || 
            ph.vn != test_entries[i].ph->vn || ph.offset != test_entries[i].ph->offset || 
            ph.ptype != test_entries[i].ph->ptype || ph.pnmask != test_entries[i].ph->pnmask) {
            ret = -1;
        }
    }

    return ret;
}
