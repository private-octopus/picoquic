#include "fnv1a.h"

uint64_t fnv1a_hash(uint64_t hash, uint8_t * bytes, size_t length)
{
    for (size_t i = 0; i < length; i++)
    {
        hash ^= bytes[i];
        hash *= FNV1A_PRIME;
    }
}