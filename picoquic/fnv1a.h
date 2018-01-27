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
#include <stddef.h>
#include <stdint.h>

#define FNV1A_OFFSET 0xcbf29ce484222325ull
#define FNV1A_PRIME 0x100000001b3ull

uint64_t fnv1a_hash(uint64_t hash, uint8_t* bytes, size_t length);
size_t fnv1a_protect(uint8_t* bytes, size_t length, size_t length_max);
size_t fnv1a_check(uint8_t* bytes, size_t length);

#endif
