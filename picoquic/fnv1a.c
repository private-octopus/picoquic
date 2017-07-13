#include "picoquic.h"
#include "fnv1a.h"

uint64_t fnv1a_hash(uint64_t hash, uint8_t * bytes, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        hash ^= bytes[i];
        hash *= FNV1A_PRIME;
    }

    return hash;
}

size_t fnv1a_protect(uint8_t * bytes, size_t length, size_t length_max)
{
    size_t ret = 0;

    if (length + 8 <= length_max)
    {
        uint64_t hash = fnv1a_hash(FNV1A_OFFSET, bytes, length);
        picoformat_64(&bytes[length], hash);
        ret = length + 8;
    }

    return ret;
}

size_t fnv1a_check(uint8_t * bytes, size_t length)
{
    size_t ret = 0;

    if (length  > 8)
    {
        uint64_t hash1 = fnv1a_hash(FNV1A_OFFSET, bytes, ret = length-8);
        uint64_t hash2 = PICOPARSE_64(bytes+ret);

        if (hash1 != hash2)
        {
            ret = 0;
        }
    }

    return ret;
}