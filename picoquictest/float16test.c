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

#include "../picoquic/picoquic_internal.h"

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
    { 0, 0, 0 },
    { 1, 1, 1 },
    { 0x7FF, 0x7FF, 0x7FF },
    { 0x800, 0x800, 0x800 },
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

    for (size_t i = 0; ret == 0 && i < nb_float16_test_case; i++) {
        uint16_t encoded = picoquic_deltat_to_float16(float16_test_case[i].n64);
        uint64_t decoded = picoquic_float16_to_deltat(float16_test_case[i].f16);

        if (encoded != float16_test_case[i].f16) {
            ret = -1;
        } else if (decoded != float16_test_case[i].n64_decoded) {
            ret = -1;
        }
    }

    return ret;
}
