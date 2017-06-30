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
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0xDEADBEF0, 0xDEADBEF0 },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0xDEADBEEF, 0xDEADBEEF },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0xDEADBEEE, 0xDEADBEEE },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0, 0x100000000ull },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 1, 0x100000001ull },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0x10000000, 0x11000000ull },
    { 0xDEADBEEF, 0xFFFFFFFF00000000ull, 0x5EADBEEE, 0x5EADBEEEull },
    { 0x1DEADBEEFull, 0xFFFFFFFF00000000ull, 0x5EADBEEE, 0x5EADBEEEull },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0xBEF0, 0xDEADBEF0 },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0xBEEF, 0xDEADBEEF },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0xBEEE, 0xDEADBEEE },
    { 0xDEADBEEF, 0xFFFFFFFFFFFF0000ull, 0x3EEE, 0xDEACBEEFull },
    { 0xDEADBEEF, 0xFFFFFFFFFFFFFF00ull, 0xF0, 0xDEADBEF0 },
    { 0xDEADBEEF, 0xFFFFFFFFFFFFFF00ull, 0xEF, 0xDEADBEEF },
    { 0xDEADBEEF, 0xFFFFFFFFFFFFFF00ull, 0xEE, 0xDEADBEEE },
    { 0xDEADBEEF, 0xFFFFFFFFFFFFFF00ull, 0x7E, 0xDEADBD7EFull }
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

}