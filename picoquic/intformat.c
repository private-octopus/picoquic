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

#include <stdint.h>
#ifndef WIN32
#include <sys/types.h>
#endif

void picoformat_16(uint8_t* bytes, uint16_t n16)
{
    bytes[0] = (uint8_t)(n16 >> 8);
    bytes[1] = (uint8_t)(n16);
}

void picoformat_32(uint8_t* bytes, uint32_t n32)
{
    bytes[0] = (uint8_t)(n32 >> 24);
    bytes[1] = (uint8_t)(n32 >> 16);
    bytes[2] = (uint8_t)(n32 >> 8);
    bytes[3] = (uint8_t)(n32);
}

void picoformat_64(uint8_t* bytes, uint64_t n64)
{
    bytes[0] = (uint8_t)(n64 >> 56);
    bytes[1] = (uint8_t)(n64 >> 48);
    bytes[2] = (uint8_t)(n64 >> 40);
    bytes[3] = (uint8_t)(n64 >> 32);
    bytes[4] = (uint8_t)(n64 >> 24);
    bytes[5] = (uint8_t)(n64 >> 16);
    bytes[6] = (uint8_t)(n64 >> 8);
    bytes[7] = (uint8_t)(n64);
}

/*
 * Summary of Integer Encodings
 * 2Bit 	Length 	Usable Bits 	Range
 * 00       1        6       0-63
 * 01       2       14       0-16383
 * 10       4       30       0-1073741823
 * 11       8       62       0-4611686018427387903
 */

size_t picoquic_varint_encode(uint8_t* bytes, size_t max_bytes, uint64_t n64)
{
    uint8_t* x = bytes;

    if (n64 < 16384) {
        if (n64 < 64) {
            if (max_bytes > 0) {
                *x++ = (uint8_t)(n64);
            }
        } else {
            if (max_bytes >= 2) {
                *x++ = (uint8_t)((n64 >> 8) | 0x40);
                *x++ = (uint8_t)(n64);
            }
        }
    } else if (n64 < 1073741824) {
        if (max_bytes >= 4) {
            *x++ = (uint8_t)((n64 >> 24) | 0x80);
            *x++ = (uint8_t)(n64 >> 16);
            *x++ = (uint8_t)(n64 >> 8);
            *x++ = (uint8_t)(n64);
        }
    } else {
        if (max_bytes >= 8) {
            *x++ = (uint8_t)((n64 >> 56) | 0xC0);
            *x++ = (uint8_t)(n64 >> 48);
            *x++ = (uint8_t)(n64 >> 40);
            *x++ = (uint8_t)(n64 >> 32);
            *x++ = (uint8_t)(n64 >> 24);
            *x++ = (uint8_t)(n64 >> 16);
            *x++ = (uint8_t)(n64 >> 8);
            *x++ = (uint8_t)(n64);
        }
    }

    return (x - bytes);
}

void picoquic_varint_encode_16(uint8_t* bytes, uint16_t n16)
{
    uint8_t* x = bytes;
    
    *x++ = (uint8_t)(((n16 >> 8) | 0x40)&0x7F);
    *x++ = (uint8_t)(n16);
}

size_t picoquic_varint_decode(const uint8_t* bytes, size_t max_bytes, uint64_t* n64)
{
    size_t length = ((size_t)1) << ((bytes[0] & 0xC0) >> 6);

    if (length > max_bytes) {
        length = 0;
        *n64 = 0;
    } else {
        uint64_t v = *bytes++ & 0x3F;

        for (size_t i = 1; i < length; i++) {
            v <<= 8;
            v += *bytes++;
        }

        *n64 = v;
    }

    return length;
}

size_t picoquic_varint_skip(uint8_t* bytes)
{
    size_t length = ((size_t)1) << ((bytes[0] & 0xC0) >> 6);

    return length;
}

void picoquic_headint_encode_32(uint8_t* bytes, uint64_t sequence_number)
{
    uint8_t* x = bytes;

    *x++ = (uint8_t)(((sequence_number >> 24) | 0xC0) & 0xFF);
    *x++ = (uint8_t)((sequence_number >> 16) & 0xFF);
    *x++ = (uint8_t)((sequence_number >> 8) & 0xFF);
    *x++ = (uint8_t)(sequence_number & 0xFF);
}

size_t picoquic_headint_decode(const uint8_t* bytes, size_t max_bytes, uint64_t* n64)
{
    int len = 0;

    *n64 = 0;
    if ((bytes[0] & 0x80) == 0)
    {
        if (max_bytes >= 1) {
            *n64 = (bytes[0]&0x7F);
            len = 1;
        }
    }
    else if ((bytes[0] & 0x40) == 0) {

        if (max_bytes >= 2) {
            *n64 = ((bytes[0] & 0x3F)<<8)|bytes[1];
            len = 2;
        }
    }
    else if (max_bytes >= 4) {
        *n64 = ((bytes[0] & 0x3F) << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        len = 4;
    }

    return len;
}
