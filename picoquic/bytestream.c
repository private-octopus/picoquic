/*
* Author: Christian Huitema
* Copyright (c) 2018, Private Octopus, Inc.
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

#include <stdlib.h>
#include <string.h>

#include "bytestream.h"
#include "picoquic_internal.h"

static int bytestream_error(bytestream * s);

bytestream * bytereader_init(bytestream * s, const void * bytes, size_t nb_bytes)
{
    s->data = (uint8_t*)bytes;
    s->size = nb_bytes;
    s->ptr = 0;

    return s;
}

bytestream * bytewriter_init(bytestream_buf * s)
{
    s->s.data = s->buf;
    s->s.size = PICOSTREAM_MAX_BUFFER_SIZE;
    s->s.ptr = 0;

    return &s->s;
}

bytestream * bytestream_alloc(bytestream * s, size_t nb_bytes)
{
    s->data = (uint8_t*)malloc(nb_bytes);
    if (s->data == NULL) {
        free(s);
        return NULL;
    }
    s->size = nb_bytes;
    s->ptr = 0;

    return s;
}

void bytestream_delete(bytestream * s)
{
    if (s->data != NULL) {
        free(s->data);
        s->data = NULL;
    }
}

void * bytestream_data(bytestream * s)
{
    return s->data;
}

size_t bytestream_size(bytestream * s)
{
    return s->size;
}

size_t bytestream_length(bytestream * s)
{
    return s->ptr;
}

void bytestream_reset(bytestream * s)
{
    s->ptr = 0;
}

int bytestream_skip(bytestream * s, size_t nb_bytes)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < nb_bytes) {
        return bytestream_error(s);
    } else {
        s->ptr += nb_bytes;
        return 0;
    }
}

int bytewrite_vint(bytestream * s, uint64_t value)
{
    size_t len = picoquic_varint_encode(s->data + s->ptr, s->size - s->ptr, value);
    if (len == 0) {
        return bytestream_error(s);
    } else {
        s->ptr += len;
        return 0;
    }
}

int byteread_vint(bytestream * s, uint64_t * value)
{
    size_t len = picoquic_varint_decode(s->data + s->ptr, s->size - s->ptr, value);
    if (len == 0) {
        return bytestream_error(s);
    } else {
        s->ptr += len;
        return 0;
    }
}

int bytewrite_int8(bytestream * s, uint8_t value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 1) {
        return bytestream_error(s);
    } else {
        s->data[s->ptr++] = value;
        return 0;
    }
}

int byteread_int8(bytestream * s, uint8_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 1) {
        return bytestream_error(s);
    }
    else {
        *value = s->data[s->ptr++];
        return 0;
    }
}

int bytewrite_int16(bytestream * s, uint16_t value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 2) {
        return bytestream_error(s);
    } else {
        picoformat_16(s->data + s->ptr, value);
        s->ptr += 2;
        return 0;
    }
}

int byteread_int16(bytestream * s, uint16_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 2) {
        return bytestream_error(s);
    }
    else {
        const uint8_t * ptr = s->data + s->ptr;
        *value = (ptr[0] << 8) | ptr[1];
        s->ptr += 2;
        return 0;
    }
}

int bytewrite_int32(bytestream * s, uint32_t value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 4) {
        return bytestream_error(s);
    } else {
        picoformat_32(s->data + s->ptr, value);
        s->ptr += 4;
        return 0;
    }
}

int byteread_int32(bytestream * s, uint32_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 4) {
        return bytestream_error(s);
    }
    else {
        const uint8_t * ptr = s->data + s->ptr;
        *value = (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | ptr[3];
        s->ptr += 4;
        return 0;
    }
}

int bytewrite_int64(bytestream * s, uint64_t value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 8) {
        return bytestream_error(s);
    } else {
        picoformat_64(s->data + s->ptr, value);
        s->ptr += 8;
        return 0;
    }
}

int byteread_int64(bytestream * s, uint64_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 8) {
        return bytestream_error(s);
    }
    else {
        uint64_t v = 0;
        for (size_t i = 0; i < 8; i++) {
            v <<= 8;
            v += s->data[s->ptr++];
        }
        *value = v;
        return 0;
    }
}

int bytewrite_buffer(bytestream * s, const void * buffer, size_t length)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < length) {
        return bytestream_error(s);
    }

    memcpy(s->data + s->ptr, buffer, length);
    s->ptr += length;
    return 0;
}

int byteread_buffer(bytestream * s, void * buffer, size_t length)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < length) {
        return bytestream_error(s);
    }

    memcpy(buffer, s->data + s->ptr, length);
    s->ptr += length;
    return 0;
}

static int bytestream_error(bytestream* s)
{
    s->ptr = s->size;
    return -1;
}
