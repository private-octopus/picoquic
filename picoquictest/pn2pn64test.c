#include "../picoquic/picoquic.h"
#include <stdlib.h>

struct _pn2pn64test_entry
{
    uint64_t highest;
    uint64_t mask;
    uint32_t pn;
    uint64_t expected;
};

static struct _pn2pn64test_entry test_entries[] = {
    { 0x10000, 0xFFFFFFFFFFFF0000ull, 0x8000, 0x18000},
    { 0xFFFE, 0xFFFFFFFFFFFF0000ull, 0x8000, 0x8000 },
    { 0xFFFF, 0xFFFFFFFFFFFF0000ull, 0x8000, 0x8000 },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0xDEADBEF0, 0xDEADBEF0 },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0xDEADBEEF, 0xDEADBEEF },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0xDEADBEEE, 0xDEADBEEE },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0, 0x100000000ull },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 1, 0x100000001ull },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0x10000000, 0x110000000ull },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0x5EADBEEE, 0x15EADBEEEull },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0x5EADBEF0, 0x5EADBEF0ull },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0x5EADBEEF, 0x15EADBEEFull },
    { 0x5EADBEEF, 0xFFFFFFFF00000000ull, 0xDEADBEEF, 0xDEADBEEFull },
    { 0x15EADBEEF, 0xFFFFFFFF00000000ull, 0xDEADBEEF, 0x1DEADBEEFull },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0xBEF0, 0xDEADBEF0 },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0xBEEF, 0xDEADBEEF },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0xBEEE, 0xDEADBEEE },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0x3EEE, 0xDEAE3EEEull },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0x3EEF, 0xDEAE3EEFull },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0x3EF0, 0xDEAD3EF0ull },
    { 0xDEADBEEF, 0xFFFFFFFFFFFFFF00ull, 0xF0, 0xDEADBEF0 },
    { 0xDEADBEEF, 0xFFFFFFFFFFFFFF00ull, 0xEF, 0xDEADBEEF },
    { 0xDEADBEEF, 0xFFFFFFFFFFFFFF00ull, 0xEE, 0xDEADBEEE },
    { 0xDEADBEEF, 0xFFFFFFFFFFFFFF00ull, 0x7F, 0xDEADBE7Full },
    { 0xDEADBE71, 0xFFFFFFFFFFFFFF00ull, 0xEF, 0xDEADBEEFull },
    { 0xDEADBE70, 0xFFFFFFFFFFFFFF00ull, 0xEF, 0xDEADBEEFull },
    { 0xDEADBE6F, 0xFFFFFFFFFFFFFF00ull, 0xEF, 0xDEADBEEFull },
    { 0xDEADBE6E, 0xFFFFFFFFFFFFFF00ull, 0xEF, 0xDEADBDEFull }
};

static const size_t nb_test_entries = sizeof(test_entries) / sizeof(struct _pn2pn64test_entry);

int pn2pn64test()
{
    int ret = 0;

    for (size_t i = 0; i < nb_test_entries; i++)
    {
        uint64_t pn64 = picoquic_get_packet_number64(
            test_entries[i].highest,
            test_entries[i].mask,
            test_entries[i].pn);

        if (pn64 != test_entries[i].expected)
        {
            ret = -1;
        }
    }

    return ret;
}