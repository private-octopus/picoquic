#include "../picoquic/fnv1a.h"
#include <stdlib.h>

int fnv1atest()
{
    int ret = 0;
    uint8_t bytes[512];
    size_t test_length;
    size_t coded_length;
    size_t decoded_length;



    /* try some test length at various alignments */
    for (test_length = 496; ret==0 && test_length < 504; test_length++)
    {
        /* initialize bytes to some value */
        for (size_t i = 0; i < sizeof(bytes); i++)
        {
            bytes[i] = (uint8_t)(i + 'A');
        }

        /* try some invalid max length */
        for (size_t x = 0; ret == 0 && x < 8; x++)
        {
            coded_length = fnv1a_protect(bytes, test_length, test_length + x);

            if (coded_length != 0)
            {
                ret = -1;
            }
        }

        if (ret == 0)
        {
            /* try with valid max length */
            coded_length = fnv1a_protect(bytes, test_length, sizeof(bytes));

            if (coded_length == 0)
            {
                ret = -1;
            }
            else
            {
                decoded_length = fnv1a_check(bytes, coded_length);

                if (decoded_length != test_length)
                {
                    ret = -1;
                }
            }
        }

        if (ret == 0)
        {
            /* try  content errors */
            for (size_t j = 0; j < test_length; j+=7)
            {
                uint8_t old_byte = bytes[j];

                bytes[j] ^= 1;

                decoded_length = fnv1a_check(bytes, coded_length);

                bytes[j] = old_byte;

                if (decoded_length != 0)
                {
                    ret = -1;
                }
            } 
        }
    }

    return ret;
}
