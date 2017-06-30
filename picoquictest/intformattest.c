#include "../picoquic/picoquic.h"

static const uint64_t test_number[] = {
    0,
    1,
    0xFFFFFFFFFFFFFFFFull,
    0xDEADBEEFull,
    0x12345678DEADBEEFull
};

static size_t nb_test_numbers = sizeof(test_number) / sizeof(const uint64_t);

static uint64_t decode_number(uint8_t * bytes, size_t length)
{
    uint64_t n = 0;

    for (size_t i = 0; i < length; i++)
    {
        n <<= 8;

        n += bytes[i];
    }

    return n;
}

int intformattest()
{
    /* Test the formating routines */
    int ret = 0;
    uint8_t bytes[8];
    uint64_t decoded;
    uint64_t parsed;
    uint32_t test32;
    uint16_t test16;
    uint64_t test64;

    /* First test with 16 bits macros */
    for (size_t i = 0; ret == 0 && i < nb_test_numbers; i++)
    {
        test16 = (uint16_t)test_number[i];
        picoformat_16(bytes, test16);
        decoded = decode_number(bytes, 2);
        if (decoded != test16)
        {
            ret = -1;
        }
        else
        {
            parsed = PICOPARSE_16(bytes);
            if (parsed != test16)
            {
                ret = -1;
            }
        }
    }

    /* Next test with 32 bits macros */
    for (size_t i = 0; ret == 0 && i < nb_test_numbers; i++)
    {
        test32 = (uint32_t)test_number[i];
        picoformat_32(bytes, test32);
        decoded = decode_number(bytes, 4);
        if (decoded != test32)
        {
            ret = -1;
        }
        else
        {
            parsed = PICOPARSE_32(bytes);
            if (parsed != test32)
            {
                ret = -1;
            }
        }
    }

    /* Final test with 64 bits macros */
    for (size_t i = 0; ret == 0 && i < nb_test_numbers; i++)
    {
        test64 = test_number[i];
        picoformat_64(bytes, test64);
        decoded = decode_number(bytes, 8);
        if (decoded != test64)
        {
            ret = -1;
        }
        else
        {
            parsed = PICOPARSE_64(bytes);
            if (parsed != test64)
            {
                ret = -1;
            }
        }
    }

    return ret;
}