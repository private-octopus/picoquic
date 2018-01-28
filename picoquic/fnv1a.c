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

#include "fnv1a.h"
#include "picoquic_internal.h"

uint64_t fnv1a_hash(uint64_t hash, uint8_t* bytes, size_t length)
{
    for (size_t i = 0; i < length; i++) {
        hash ^= bytes[i];
        hash *= FNV1A_PRIME;
    }

    return hash;
}

size_t fnv1a_protect(uint8_t* bytes, size_t length, size_t length_max)
{
    size_t ret = 0;

    if (length + 8 <= length_max) {
        uint64_t hash = fnv1a_hash(FNV1A_OFFSET, bytes, length);
        picoformat_64(&bytes[length], hash);
        ret = length + 8;
    }

    return ret;
}

size_t fnv1a_check(uint8_t* bytes, size_t length)
{
    size_t ret = 0;

    if (length > 8) {
        uint64_t hash1 = fnv1a_hash(FNV1A_OFFSET, bytes, ret = length - 8);
        uint64_t hash2 = PICOPARSE_64(bytes + ret);

        if (hash1 != hash2) {
            ret = 0;
        }
    }

    return ret;
}