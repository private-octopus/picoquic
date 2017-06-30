#ifndef FNV1A_H
#define FNV1A_H

/*
From the QUIC TLS spec:

FNV-1a can be expressed in pseudocode as:

hash := offset basis
for each input octet:
hash := hash XOR input octet
hash := hash * prime

That is, a 64-bit unsigned integer is initialized with an offset basis.
Then, for each octet of the input, the exclusive binary OR of the value
is taken, then multiplied by a prime. Any overflow from multiplication
is discarded.

The offset basis for the 64-bit FNV-1a is the decimal value
14695981039346656037 (in hex, 0xcbf29ce484222325). The prime is
1099511628211 (in hex, 0x100000001b3; or as an expression 2^40 + 2^8 + 0xb3).

Once all octets have been processed in this fashion, the final integer
value is encoded as 8 octets in network byte order.
*/
#include <stdint.h>

#define FNV1A_OFFSET 0xcbf29ce484222325ull
#define FNV1A_PRIME 0x100000001b3ull

uint64_t fnv1a_hash(uint64_t hash, uint8_t * bytes, size_t length);
size_t fnv1a_protect(uint8_t * bytes, size_t length, size_t length_max);
size_t fnv1a_check(uint8_t * bytes, size_t length);

#endif
