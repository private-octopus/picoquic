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

void picoformat_16(uint8_t *bytes, uint16_t n16)
{
    bytes[0] = (uint8_t)(n16 >> 8);
    bytes[1] = (uint8_t)(n16);
}

void picoformat_32(uint8_t *bytes, uint32_t n32)
{
    bytes[0] = (uint8_t)(n32 >> 24);
    bytes[1] = (uint8_t)(n32 >> 16);
    bytes[2] = (uint8_t)(n32 >> 8);
    bytes[3] = (uint8_t)(n32);
}

void picoformat_64(uint8_t *bytes, uint64_t n64)
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