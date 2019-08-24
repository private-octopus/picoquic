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
#include "bytestream.h"
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

int eval_bytestream_write(bytestream * s, int ret, const char * fn_name)
{
    size_t expected_size = sizeof(expected_stream0);
    size_t stream_len = bytestream_length(s);

    if (ret != 0) {
        DBG_PRINTF("%s failed to write %zu bytes. result: %d, length: %zu\n", fn_name, expected_size, ret, stream_len);
    }

    if (ret == 0 && stream_len != expected_size) {
        DBG_PRINTF("%s stream length does not match: result: %zu, expected: %zu\n", fn_name, stream_len, expected_size);
        ret = -1;
    }

    if (ret == 0 && memcmp(bytestream_data(s), expected_stream0, expected_size) != 0) {
        DBG_PRINTF("%s content does not match\n", fn_name);
        ret = -1;
    }

    return ret;
}

int eval_bytestream_read(bytestream * s, int ret, const char * fn_name)
{
    size_t expected_size = sizeof(expected_stream0);
    size_t stream_len = bytestream_length(s);

    if (ret != 0) {
        DBG_PRINTF("%s failed to read %zu bytes. result: %d, length: %zu\n", fn_name, expected_size, ret, stream_len);
    }

    if (ret == 0 && stream_len != expected_size) {
        DBG_PRINTF("%s stream length does not match: result: %zu, expected: %zu\n", fn_name, stream_len, expected_size);
        ret = -1;
    }

    return ret;
}

int verify_bytestream_write_intXX(bytestream * s)
{
    int ret = 0;
    ret |= bytewrite_int8(s, 0x00);
    ret |= bytewrite_int8(s, 0x01);
    ret |= bytewrite_int16(s, 0x4203);
    ret |= bytewrite_int32(s, 0x84050607);
    ret |= bytewrite_int64(s, 0xc8090a0b0c0d0e0f);
    return eval_bytestream_write(s, ret, "bytewrite_intXX");
}

int verify_bytestream_write_int(bytestream * s)
{
    int ret = 0;
    ret |= bytewrite_vint(s, 0x00);
    ret |= bytewrite_vint(s, 0x01);
    ret |= bytewrite_vint(s, 0x0203);
    ret |= bytewrite_vint(s, 0x04050607);
    ret |= bytewrite_vint(s, 0x08090a0b0c0d0e0f);
    return eval_bytestream_write(s, ret, "bytewrite_vint");
}

int verify_bytestream_write_buffer(bytestream * s)
{
    int ret = 0;
    ret |= bytewrite_buffer(s, expected_stream0, 2);
    ret |= bytewrite_buffer(s, expected_stream0 + 2, 14);
    return eval_bytestream_write(s, ret, "bytewrite_buffer");
}

int verify_bytestream_read_intXX(bytestream * s)
{
    int ret = 0;
    uint8_t val8 = 0;
    ret |= byteread_int8(s, &val8) || val8 != 0x00;
    ret |= byteread_int8(s, &val8) || val8 != 0x01;

    uint16_t val16 = 0;
    ret |= byteread_int16(s, &val16) || val16 != 0x4203;

    uint32_t val32 = 0;
    ret |= byteread_int32(s, &val32) || val32 != 0x84050607;

    uint64_t val64 = 0;
    ret |= byteread_int64(s, &val64) || val64 != 0xc8090a0b0c0d0e0f;

    return eval_bytestream_read(s, ret, "byteread_intXX");
}

int verify_bytestream_read_int(bytestream * s)
{
    int ret = 0;
    uint64_t value64 = 0;
    ret |= byteread_vint(s, &value64) != 0 || value64 != 0x00;
    ret |= byteread_vint(s, &value64) != 0 || value64 != 0x01;
    ret |= byteread_vint(s, &value64) != 0 || value64 != 0x0203;
    ret |= byteread_vint(s, &value64) != 0 || value64 != 0x04050607;
    ret |= byteread_vint(s, &value64) != 0 || value64 != 0x08090a0b0c0d0e0f;
    return eval_bytestream_read(s, ret, "byteread_vint");
}

int verify_bytestream_skip_int(bytestream * s)
{
    int ret = 0;
    ret |= byteread_skip_vint(s) != 0 || bytestream_length(s) != 1;
    ret |= byteread_skip_vint(s) != 0 || bytestream_length(s) != 2;
    ret |= byteread_skip_vint(s) != 0 || bytestream_length(s) != 4;
    ret |= byteread_skip_vint(s) != 0 || bytestream_length(s) != 8;
    ret |= byteread_skip_vint(s) != 0 || bytestream_length(s) != 16;
    return eval_bytestream_read(s, ret, "byteread_skip_vint");
}

int verify_bytestream_read_buffer(bytestream* s)
{
    int ret = 0;
    uint8_t buf[16];
    ret |= byteread_buffer(s, buf, 2) != 0 || memcmp(expected_stream0, buf, 2) != 0;
    ret |= byteread_buffer(s, buf, 14) != 0 || memcmp(expected_stream0+2, buf, 14) != 0;
    return eval_bytestream_read(s, ret, "byteread_buffer");
}

int verify_bytestream_write(bytestream * s)
{
    int ret = 0;

    bytestream_clear(s);
    ret |= verify_bytestream_write_intXX(s);

    bytestream_clear(s);
    ret |= verify_bytestream_write_int(s);

    bytestream_clear(s);
    ret |= verify_bytestream_write_buffer(s);

    return ret;
}

int verify_bytestream_read(bytestream * s)
{
    int ret = 0;

    bytestream_reset(s);
    ret |= verify_bytestream_read_intXX(s);

    bytestream_reset(s);
    ret |= verify_bytestream_read_int(s);

    bytestream_reset(s);
    ret |= verify_bytestream_read_buffer(s);

    return ret;
}

int verify_bytestream_on_stack()
{
    int ret = 0;

    bytestream_buf wstream;
    bytestream * ws = bytewriter_init(&wstream);
    ret |= verify_bytestream_write(ws);

    bytestream rstream;
    bytestream * rs = bytereader_init(&rstream, expected_stream0, sizeof(expected_stream0));
    ret |= verify_bytestream_read(rs);

    bytestream_reset(rs);
    ret |= verify_bytestream_skip_int(rs);

    return ret;
}

int verify_bytestream_on_heap()
{
    int ret = 0;

    bytestream stream;
    bytestream * s = bytestream_alloc(&stream, sizeof(expected_stream0));

    bytestream_reset(s);
    ret |= verify_bytestream_write(s);

    bytestream_reset(s);
    bytewrite_buffer(s, expected_stream0, sizeof(expected_stream0));
    bytestream_reset(s);
    ret |= verify_bytestream_read(s);

    bytestream_delete(s);

    return ret;
}

/*
 * This tests bytestream write functionality when close to or over the allocated limits.
 */
int bytestream_test_write_limits()
{
    int ret = 0;
    const static uint8_t buf[8] = { 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

    bytestream stream;
    bytestream * s9 = bytestream_alloc(&stream, 9);

    bytestream_reset(s9);
    bytestream_skip(s9, 9 - 1);

    if (bytewrite_int8(s9, 0x0e) != 0) {
        DBG_PRINTF("%s", "bytewrite_int8 failed on 9 byte buffer\n");
        ret = -1;
    }

    if (bytewrite_int8(s9, 0x0f) == 0) {
        DBG_PRINTF("%s", "bytewrite_int8 didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);
    bytestream_skip(s9, 9 - 3);

    if (bytewrite_int16(s9, 0x0c0d) != 0) {
        DBG_PRINTF("%s", "bytewrite_int16 failed on 9 byte buffer\n");
        ret = -1;
    }

    if (bytewrite_int16(s9, 0x0e0f) == 0) {
        DBG_PRINTF("%s", "bytewrite_int16 didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);
    bytestream_skip(s9, 9 - 5);

    if (bytewrite_int32(s9, 0x08090a0b) != 0) {
        DBG_PRINTF("%s", "first bytewrite_int32 failed on 9 byte buffer\n");
        ret = -1;
    }

    if (bytewrite_int32(s9, 0x0c0d0e0f) == 0) {
        DBG_PRINTF("%s", "second bytewrite_int32 didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);

    if (bytewrite_int64(s9, 0x0102030405060708) != 0) {
        DBG_PRINTF("%s", "first bytewrite_int64 failed on 9 byte buffer\n");
        ret = -1;
    }

    if (bytewrite_int64(s9, 0x08090a0b0c0d0e0f) == 0) {
        DBG_PRINTF("%s", "second bytewrite_int64 didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);

    if (bytewrite_vint(s9, 0x0102030405060708) != 0) {
        DBG_PRINTF("%s", "first bytewrite_vint failed on 9 byte buffer\n");
        ret = -1;
    }

    if (bytewrite_vint(s9, 0x08090a0b0c0d0e0f) == 0) {
        DBG_PRINTF("%s", "second bytewrite_vint didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);

    if (bytewrite_buffer(s9, buf, sizeof(buf)) != 0) {
        DBG_PRINTF("%s", "bytewrite_buffer of 8 bytes failed on 9 byte buffer\n");
        ret = -1;
    }

    if (bytewrite_buffer(s9, buf, sizeof(buf)) == 0) {
        DBG_PRINTF("%s", "bytewrite_buffer of 8 bytes didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    /* Also expect that no other, smaller write call succeeds */
    if (bytewrite_int8(s9, 0x01) == 0) {
        DBG_PRINTF("%s", "bytewrite_int8 didn't fail after write failure\n");
        ret = -1;
    }

    bytestream_delete(s9);

    return ret;
}

/*
 * This tests bytestream read functionality when close to or over the allocated limits.
 */
int bytestream_test_read_limits()
{
    int ret = 0;
    
    uint8_t i8;
    uint16_t i16;
    uint32_t i32;
    uint64_t i64;
    uint8_t buf[8];

    const static uint8_t buf9[9] = {
        0xc8, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xc8
    };

    uint8_t * heap = malloc(sizeof(buf9));
    memcpy(heap, buf9, sizeof(buf9));

    bytestream stream;
    bytestream * s9 = bytereader_init(&stream, heap, sizeof(buf9));

    bytestream_reset(s9);
    bytestream_skip(s9, 9 - 1);

    if (byteread_int8(s9, &i8) != 0) {
        DBG_PRINTF("%s", "byteread_int8 failed on 9 byte buffer\n");
        ret = -1;
    }

    if (byteread_int8(s9, &i8) == 0) {
        DBG_PRINTF("%s", "byteread_int8 didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);
    bytestream_skip(s9, 9 - 3);

    if (byteread_int16(s9, &i16) != 0) {
        DBG_PRINTF("%s", "byteread_int16 failed on 9 byte buffer\n");
        ret = -1;
    }

    if (byteread_int16(s9, &i16) == 0) {
        DBG_PRINTF("%s", "byteread_int16 didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);
    bytestream_skip(s9, 9 - 5);

    if (byteread_int32(s9, &i32) != 0) {
        DBG_PRINTF("%s", "first byteread_int32 failed on 9 byte buffer\n");
        ret = -1;
    }

    if (byteread_int32(s9, &i32) == 0) {
        DBG_PRINTF("%s", "second byteread_int32 didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);

    if (byteread_int64(s9, &i64) != 0) {
        DBG_PRINTF("%s", "first byteread_int64 failed on 9 byte buffer\n");
        ret = -1;
    }

    if (byteread_int64(s9, &i64) == 0) {
        DBG_PRINTF("%s", "second byteread_int64 didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);

    if (byteread_vint(s9, &i64) != 0) {
        DBG_PRINTF("%s", "first byteread_vint failed on 9 byte buffer\n");
        ret = -1;
    }

    if (byteread_vint(s9, &i64) == 0) {
        DBG_PRINTF("%s", "second byteread_vint didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    if (byteread_vint(s9, &i64) == 0) {
        DBG_PRINTF("%s", "third byteread_vint didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);

    if (byteread_skip_vint(s9) != 0) {
        DBG_PRINTF("%s", "first byteread_skip_vint failed on 9 byte buffer\n");
        ret = -1;
    }

    if (byteread_skip_vint(s9) == 0) {
        DBG_PRINTF("%s", "second byteread_skip_vint didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    if (byteread_skip_vint(s9) == 0) {
        DBG_PRINTF("%s", "third byteread_skip_vint didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    bytestream_reset(s9);

    if (byteread_buffer(s9, buf, sizeof(buf)) != 0) {
        DBG_PRINTF("%s", "byteread_buffer of 8 bytes failed on 9 byte buffer\n");
        ret = -1;
    }

    if (byteread_buffer(s9, buf, sizeof(buf)) == 0) {
        DBG_PRINTF("%s", "byteread_buffer of 8 bytes didn't fail on 9 byte buffer\n");
        ret = -1;
    }

    /* Also expect that no other, smaller read call succeeds */
    if (byteread_int8(s9, &i8) == 0) {
        DBG_PRINTF("%s", "byteread_int8 didn't fail after read failure\n");
        ret = -1;
    }

    free(heap);
    return ret;
}

typedef struct st_picoquic_val_len {
    uint64_t val;
    size_t len;
} picoquic_val_len;

int bytestream_test_vint()
{
    int ret = 0;

    static const picoquic_val_len values[] = {
        { 0, 1 },
        { 10, 1 },
        { 100, 2 },
        { 1000, 2 },
        { 10000, 2 },
        { 100000, 4 },
        { 10000000, 4 },
        { 1000000000, 4 },
        { 100000000000, 8 },
        { 1000000000000000, 8 },
        { 0x3f, 1 },
        { 0x40, 2 },
        { 0x3fff, 2 },
        { 0x4000, 4 },
        { 0x3fffffff, 4 },
        { 0x40000000, 8 },
    };

    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); ++i)
    {
        size_t len = bytestream_vint_len(values[i].val);
        if (len != values[i].len) {
            DBG_PRINTF("bytestream_vint_len(%" PRIu64 ") returned %zu instead of %zu\n",
                values[i].val, len, values[i].len);
            ret = -1;
        }
    }

    return ret;
}

int bytestream_test_utils()
{
    int ret = 0;
    size_t size = 0;
    int finish = 0;

    const static uint8_t buf9[9] = {
        0xc8, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xc8
    };

    bytestream stream;
    bytestream* s9 = bytereader_init(&stream, buf9, sizeof(buf9));

    bytestream_reset(s9);

    if ((size = bytestream_size(s9)) != sizeof(buf9)) {
        DBG_PRINTF("bytestream_size returned %zu on 9 byte buffer\n", size);
        ret = -1;
    }

    if ((size = bytestream_length(s9)) != 0) {
        DBG_PRINTF("first bytestream_length returned %zu\n", size);
        ret = -1;
    }

    if ((size = bytestream_remain(s9)) != sizeof(buf9)) {
        DBG_PRINTF("first bytestream_remain returned %zu\n", size);
        ret = -1;
    }

    bytestream_skip(s9, 9 - 1);

    if ((size = bytestream_length(s9)) != 9 - 1) {
        DBG_PRINTF("second bytestream_length returned %zu\n", size);
        ret = -1;
    }

    if ((size = bytestream_remain(s9)) != 1) {
        DBG_PRINTF("second bytestream_remain returned %zu\n", size);
        ret = -1;
    }

    if ((finish = bytestream_finished(s9)) != 0) {
        DBG_PRINTF("first bytestream_finished returned %d\n", finish);
        ret = -1;
    }

    bytestream_skip(s9, 1);

    if ((size = bytestream_length(s9)) != sizeof(buf9)) {
        DBG_PRINTF("second bytestream_length returned %zu\n", size);
        ret = -1;
    }

    if ((size = bytestream_remain(s9)) != 0) {
        DBG_PRINTF("third bytestream_remain returned %zu\n", size);
        ret = -1;
    }

    if ((finish = bytestream_finished(s9)) == 0) {
        DBG_PRINTF("second bytestream_finished returned %d\n", finish);
        ret = -1;
    }

    return ret;
}

int bytestream_test()
{
    int ret = 0;

    if (verify_bytestream_on_stack() != 0) {
        ret = -1;
    }

    if (verify_bytestream_on_heap() != 0) {
        ret = -1;
    }

    if (bytestream_test_write_limits() != 0) {
        ret = -1;
    }

    if (bytestream_test_read_limits() != 0) {
        ret = -1;
    }

    if (bytestream_test_vint() != 0) {
        ret = -1;
    }

    if (bytestream_test_utils() != 0) {
        ret = -1;
    }

    return ret;
}
