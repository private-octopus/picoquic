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

#include "picoquic_internal.h"
#include "picostream.h"
#include <stdlib.h>
#ifdef _WINDOWS
#include <malloc.h>
#endif
#include <string.h>

static const uint8_t expected_stream0[16] =
{
    0x00, 0x01, 0x42, 0x03, 0x84, 0x05, 0x06, 0x07,
    0xc8, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

int eval_picostream_write(picostream * s, int ret, const char * fn_name)
{
    size_t expected_size = sizeof(expected_stream0);
    size_t stream_len = picostream_length(s);

    if (ret != 0) {
        DBG_PRINTF("%s failed to write %zu bytes. result: %d, length: %zu\n", fn_name, expected_size, ret, stream_len);
    }

    if (ret == 0 && stream_len != expected_size) {
        DBG_PRINTF("%s stream length does not match: result: %zu, expected: %zu\n", fn_name, stream_len, expected_size);
        ret = -1;
    }

    if (ret == 0 && memcmp(picostream_data(s), expected_stream0, expected_size) != 0) {
        DBG_PRINTF("%s content does not match\n", fn_name);
        ret = -1;
    }

    return ret;
}

int eval_picostream_read(picostream * s, int ret, const char * fn_name)
{
    size_t expected_size = sizeof(expected_stream0);
    size_t stream_len = picostream_length(s);

    if (ret != 0) {
        DBG_PRINTF("%s failed to read %zu bytes. result: %d, length: %zu\n", fn_name, expected_size, ret, stream_len);
    }

    if (ret == 0 && stream_len != expected_size) {
        DBG_PRINTF("%s stream length does not match: result: %zu, expected: %zu\n", fn_name, stream_len, expected_size);
        ret = -1;
    }

    return ret;
}

int verify_picostream_write_int32(picostream * s)
{
    int ret = 0;
    ret |= picostream_write_int32(s, 0x00014203);
    ret |= picostream_write_int32(s, 0x84050607);
    ret |= picostream_write_int32(s, 0xc8090a0b);
    ret |= picostream_write_int32(s, 0x0c0d0e0f);
    return eval_picostream_write(s, ret, "picostream_write_int32");
}

int verify_picostream_write_int(picostream * s)
{
    int ret = 0;
    ret |= picostream_write_int(s, 0x00);
    ret |= picostream_write_int(s, 0x01);
    ret |= picostream_write_int(s, 0x0203);
    ret |= picostream_write_int(s, 0x04050607);
    ret |= picostream_write_int(s, 0x08090a0b0c0d0e0f);
    return eval_picostream_write(s, ret, "picostream_write_int");
}

int verify_picostream_write_buffer(picostream * s)
{
    int ret = 0;
    ret |= picostream_write_buffer(s, expected_stream0, 2);
    ret |= picostream_write_buffer(s, expected_stream0 + 2, 14);
    return eval_picostream_write(s, ret, "picostream_write_buffer");
}

int verify_picostream_read_int32(picostream * s)
{
    int ret = 0;
    uint32_t value = 0;
    ret |= picostream_read_int32(s, &value) || value != 0x00014203;
    ret |= picostream_read_int32(s, &value) || value != 0x84050607;
    ret |= picostream_read_int32(s, &value) || value != 0xc8090a0b;
    ret |= picostream_read_int32(s, &value) || value != 0x0c0d0e0f;
    return eval_picostream_read(s, ret, "picostream_read_int32");
}

int verify_picostream_read_int(picostream * s)
{
    int ret = 0;
    uint64_t value64 = 0;
    ret |= picostream_read_int(s, &value64) != 0 || value64 != 0x00;
    ret |= picostream_read_int(s, &value64) != 0 || value64 != 0x01;
    ret |= picostream_read_int(s, &value64) != 0 || value64 != 0x0203;
    ret |= picostream_read_int(s, &value64) != 0 || value64 != 0x04050607;
    ret |= picostream_read_int(s, &value64) != 0 || value64 != 0x08090a0b0c0d0e0f;
    return eval_picostream_read(s, ret, "picostream_read_int");
}

int verify_picostream_read_buffer(picostream* s)
{
    int ret = 0;
    uint8_t buf[16];
    ret |= picostream_read_buffer(s, buf, 2) != 0 || memcmp(expected_stream0, buf, 2) != 0;
    ret |= picostream_read_buffer(s, buf, 14) != 0 || memcmp(expected_stream0+2, buf, 14) != 0;
    return eval_picostream_read(s, ret, "picostream_read_buffer");
}

int verify_picostream_write(picostream * s)
{
    int ret = 0;

    picostream_reset(s);
    memset(picostream_data(s), 0x00, sizeof(expected_stream0));
    ret |= verify_picostream_write_int32(s);

    picostream_reset(s);
    memset(picostream_data(s), 0x00, sizeof(expected_stream0));
    ret |= verify_picostream_write_int(s);

    picostream_reset(s);
    memset(picostream_data(s), 0x00, sizeof(expected_stream0));
    ret |= verify_picostream_write_buffer(s);

    return ret;
}

int verify_picostream_read(picostream * s)
{
    int ret = 0;

    picostream_reset(s);
    ret |= verify_picostream_read_int32(s);

    picostream_reset(s);
    ret |= verify_picostream_read_int(s);

    picostream_reset(s);
    ret |= verify_picostream_read_buffer(s);

    return ret;
}

int verify_picostream_on_stack()
{
    int ret = 0;

    pico_writestream wstream;
    picostream * ws = picostream_init_write(&wstream);
    ret |= verify_picostream_write(ws);

    picostream rstream;
    picostream * rs = picostream_init_read(&rstream, expected_stream0, sizeof(expected_stream0));
    ret |= verify_picostream_read(rs);

    return ret;
}

int verify_picostream_on_heap()
{
    int ret = 0;

    picostream * s = picostream_alloc(sizeof(expected_stream0));
    ret |= verify_picostream_write(s);

    picostream_reset(s);
    memcpy(picostream_data(s), expected_stream0, sizeof(expected_stream0));
    ret |= verify_picostream_read(s);

    picostream_delete(s);

    return ret;
}

/*
 * This tests picostream write functionality when close to or over the allocated limits.
 */
int picostream_test_write_limits()
{
    int ret = 0;
    static uint8_t buf[4] = { 0x0c, 0x0d, 0x0e, 0x0f };
    picostream * s3 = picostream_alloc(3);
    picostream * s4 = picostream_alloc(4);

    if (picostream_write_int32(s3, 0x0c0d0e0f) == 0) {
        DBG_PRINTF("%s", "picostream_write_int32 of 4 bytes didn't fail on 3 byte buffer\n");
        ret = -1;
    }

    if (picostream_write_int32(s4, 0x0c0d0e0f) != 0) {
        DBG_PRINTF("%s", "picostream_write_int32 of 4 bytes failed on 4 byte buffer\n");
        ret = -1;
    }

    picostream_reset(s3);
    picostream_reset(s4);

    if (picostream_write_int(s3, 0x0c0d0e0f) == 0) {
        DBG_PRINTF("%s", "picostream_write_int of 4 bytes didn't fail on 3 byte buffer\n");
        ret = -1;
    }

    if (picostream_write_int(s4, 0x0c0d0e0f) != 0) {
        DBG_PRINTF("%s", "picostream_write_int of 4 bytes failed on 4 byte buffer\n");
        ret = -1;
    }

    picostream_reset(s3);
    picostream_reset(s4);

    if (picostream_write_buffer(s3, buf, sizeof(buf)) == 0) {
        DBG_PRINTF("%s", "picostream_write_buffer of 4 bytes didn't fail on 3 byte buffer\n");
        ret = -1;
    }

    if (picostream_write_buffer(s4, buf, sizeof(buf)) != 0) {
        DBG_PRINTF("%s", "picostream_write_buffer of 4 bytes failed on 4 byte buffer\n");
        ret = -1;
    }

    picostream_delete(s3);
    picostream_delete(s4);

    return ret;
}

/*
 * This tests picostream read functionality when close to or over the allocated limits.
 */
int picostream_test_read_limits()
{
    static const uint8_t buf[4] = { 0x8c, 0x0d, 0x0e, 0x0f };
    uint8_t tmp[4];

    picostream stream3;
    picostream stream4;
    picostream * s3 = picostream_init_read(&stream3, buf, 3);
    picostream * s4 = picostream_init_read(&stream4, buf, 4);

    int ret = 0;

    uint32_t value32 = 0;
    if (picostream_read_int32(s3, &value32) == 0) {
        DBG_PRINTF("%s", "picostream_read_int32 of 4 bytes didn't fail on 3 byte buffer\n");
        ret = -1;
    }

    if (picostream_read_int32(s4, &value32) != 0) {
        DBG_PRINTF("%s", "picostream_read_int32 of 4 bytes failed on 4 byte buffer\n");
        ret = -1;
    }

    picostream_reset(s3);
    picostream_reset(s4);

    uint64_t value64 = 0;
    if (picostream_read_int(s3, &value64) == 0) {
        DBG_PRINTF("%s", "picostream_read_int of 4 bytes didn't fail on 3 byte buffer\n");
        ret = -1;
    }

    if (picostream_read_int(s4, &value64) != 0) {
        DBG_PRINTF("%s", "picostream_read_int of 4 bytes failed on 4 byte buffer\n");
        ret = -1;
    }

    picostream_reset(s3);
    picostream_reset(s4);

    if (picostream_read_buffer(s3, tmp, sizeof(tmp)) == 0) {
        DBG_PRINTF("%s", "picostream_read_buffer of 4 bytes didn't fail on 3 byte buffer\n");
        ret = -1;
    }

    if (picostream_read_buffer(s4, tmp, sizeof(tmp)) != 0) {
        DBG_PRINTF("%s", "picostream_read_buffer of 4 bytes failed on 4 byte buffer\n");
        ret = -1;
    }

    return ret;
}

int picostream_test()
{
    int ret = 0;

    if (verify_picostream_on_stack() != 0) {
        ret = -1;
    }

    if (verify_picostream_on_heap() != 0) {
        ret = -1;
    }

    if (picostream_test_write_limits() != 0) {
        ret = -1;
    }

    if (picostream_test_read_limits() != 0) {
        ret = -1;
    }

    return ret;
}
