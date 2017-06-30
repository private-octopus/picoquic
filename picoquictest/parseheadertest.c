#include "../picoquic/picoquic.h"
#include <stdlib.h>

/* test vectors and corresponding structure */
static uint8_t perror_empty[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

static uint8_t pinitial[] = {
    0x82,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xDE, 0xAD, 0xBE, 0xEF,
    0xFF, 0, 0, 13
};

static picoquic_packet_header hinitial = {
    0x0102030405060708ull,
    0xDEADBEEF,
    0xFF00000Dul,
    17,
    picoquic_packet_client_initial,
    0xFFFFFFFF00000000ull
};

static uint8_t packet_short_phi0_c_32[] = {
    0x23,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xDE, 0xAD, 0xBE, 0xEF
};

static picoquic_packet_header hphi0_c_32 = {
    0x0102030405060708ull,
    0xDEADBEEF,
    0,
    5,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFF00000000ull
};

static uint8_t packet_short_phi1_c_16[] = {
    0x22,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xBE, 0xEF
};

static picoquic_packet_header hphi1_c_16 = {
    0x0102030405060708ull,
    0xBEEF,
    0,
    3,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFF0000ull
};

static uint8_t packet_short_phi1_c_8[] = {
    0x21,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0xEF
};

static picoquic_packet_header hphi1_c_8 = {
    0x0102030405060708ull,
    0xEF,
    0,
    3,
    picoquic_packet_1rtt_protected_phi1,
    0xFFFFFFFFFFFFFF00ull
};


static uint8_t packet_short_phi0_noc_16[] = {
    0x03,
    0xBE, 0xEF
};

static picoquic_packet_header hphi0_noc_16 = {
    0,
    0xBEEF,
    0,
    3,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFF0000ull
};

static uint8_t packet_short_phi0_noc_8[] = {
    0x03,
    0xEF
};

static picoquic_packet_header hphi0_noc_8 = {
    0,
    0xEF,
    0,
    3,
    picoquic_packet_1rtt_protected_phi0,
    0xFFFFFFFFFFFFFF00ull
};

struct _test_entry {
    uint8_t * packet;
    size_t length;
    picoquic_packet_header * ph;
};

static struct _test_entry test_entries[] = {
    { pinitial , sizeof(pinitial), &hinitial },
    { packet_short_phi0_c_32, sizeof(packet_short_phi0_c_32), &hphi0_c_32 },
    { packet_short_phi1_c_16 , sizeof(packet_short_phi1_c_16), &hphi1_c_16 },
    { packet_short_phi1_c_8, sizeof(packet_short_phi1_c_8), &hphi1_c_8 },
    { packet_short_phi0_noc_16, sizeof(packet_short_phi0_noc_16), &hphi0_noc_16 },
    { packet_short_phi0_noc_8, sizeof(packet_short_phi0_noc_8), &hphi0_noc_8 }
};

static const size_t nb_test_entries = sizeof(test_entries) / sizeof(struct _test_entry);

int parseheadertest()
{
    int ret = 0;
    picoquic_packet_header ph;

    for (size_t i = 0; ret && i < nb_test_entries; i++)
    {
        if (picoquic_parse_packet_header(
            test_entries[i].packet, test_entries[i].length, &ph) != 0)
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