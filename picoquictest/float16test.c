#include "../picoquic/picoquic.h"

/*
* Float16 format required for encoding the time deltas in current QUIC draft.
*
* The time format used in the ACK frame above is a 16-bit unsigned float with
* 11 explicit bits of mantissa and 5 bits of explicit exponent, specifying time
* in microseconds. The bit format is loosely modeled after IEEE 754. For example,
* 1 microsecond is represented as 0x1, which has an exponent of zero, presented
* in the 5 high order bits, and mantissa of 1, presented in the 11 low order bits.
* When the explicit exponent is greater than zero, an implicit high-order 12th bit
* of 1 is assumed in the mantissa. For example, a floating value of 0x800 has an
* explicit exponent of 1, as well as an explicit mantissa of 0, but then has an
* effective mantissa of 4096 (12th bit is assumed to be 1). Additionally, the actual
* exponent is one-less than the explicit exponent, and the value represents 4096
* microseconds. Any values larger than the representable range are clamped to 0xFFFF.
*/

struct _float16test_st {
    uint64_t n64;
    uint16_t f16;
    uint64_t n64_decoded;
};

static struct _float16test_st float16_test_case[] = {
    { 0, 0, 0},
    { 1, 1, 1},
    { 0x7FF, 0x7FF, 0x7FF},
    { 0x800, 0x800, 0x800},
    { 0x801, 0x801, 0x801 },
    { 0xFFF, 0xFFF, 0xFFF },
    { 0x1000, 0x1000, 0x1000 },
    { 0x1001, 0x1000, 0x1000 },
    { 0x1002, 0x1001, 0x1002 },
    { 0x2004, 0x1801, 0x2004 },
    { 0x10000000, 0x9000, 0x10000000 },
    { 0x10080000, 0x9004, 0x10080000 },
    { 0x3FFC0000000, 0xFFFF, 0x3FFC0000000 },
    { 0x40000000000, 0xFFFF, 0x3FFC0000000 },
    { 0x7F00000000000, 0xFFFF, 0x3FFC0000000 }
};

static size_t nb_float16_test_case = sizeof(float16_test_case) / sizeof(struct _float16test_st);

int float16test()
{
    int ret = 0;

    for (int i = 0; ret == 0 && i < nb_float16_test_case; i++)
    {
        uint16_t encoded = picoquic_deltat_to_float16(float16_test_case[i].n64);
        uint64_t decoded = picoquic_float16_to_deltat(float16_test_case[i].f16);

        if (encoded != float16_test_case[i].f16)
        {
            ret = -1;
        }
        else if (decoded != float16_test_case[i].n64_decoded)
        {
            ret = -1;
        }
    }

    return ret;
}
