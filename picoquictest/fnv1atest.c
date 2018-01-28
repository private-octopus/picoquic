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

#include "../picoquic/fnv1a.h"
#include <stdint.h>
#include <stdlib.h>

int fnv1atest()
{
    int ret = 0;
    uint8_t bytes[512];
    size_t test_length;
    size_t coded_length;
    size_t decoded_length;

    /* try some test length at various alignments */
    for (test_length = 496; ret == 0 && test_length < 504; test_length++) {
        /* initialize bytes to some value */
        for (size_t i = 0; i < sizeof(bytes); i++) {
            bytes[i] = (uint8_t)(i + 'A');
        }

        /* try some invalid max length */
        for (size_t x = 0; ret == 0 && x < 8; x++) {
            coded_length = fnv1a_protect(bytes, test_length, test_length + x);

            if (coded_length != 0) {
                ret = -1;
            }
        }

        if (ret == 0) {
            /* try with valid max length */
            coded_length = fnv1a_protect(bytes, test_length, sizeof(bytes));

            if (coded_length == 0) {
                ret = -1;
            } else {
                decoded_length = fnv1a_check(bytes, coded_length);

                if (decoded_length != test_length) {
                    ret = -1;
                }
            }
        }

        if (ret == 0) {
            /* try  content errors */
            for (size_t j = 0; j < test_length; j += 7) {
                uint8_t old_byte = bytes[j];

                bytes[j] ^= 1;

                decoded_length = fnv1a_check(bytes, coded_length);

                bytes[j] = old_byte;

                if (decoded_length != 0) {
                    ret = -1;
                }
            }
        }
    }

    return ret;
}
