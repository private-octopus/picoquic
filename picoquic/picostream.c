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

#include "picostream.h"
#include "picoquic_internal.h"

picostream * picostream_alloc(size_t nb_bytes)
{
    picostream* s = (picostream*)malloc(sizeof(picostream));
    if (s == NULL) {
        return NULL;
    }

    s->data = (uint8_t*)malloc(nb_bytes);
    if (s->data == NULL) {
        free(s);
        return NULL;
    }
    s->size = nb_bytes;
    s->ptr = 0;

    return s;
}

void picostream_delete(picostream * s)
{
    if (s != NULL) {
        if (s->data != NULL) {
            free(s->data);
        }
        free(s);
    }
}

void * picostream_data(picostream * s)
{
    return s->data;
}

size_t picostream_size(picostream * s)
{
    return s->size;
}

size_t picostream_length(picostream * s)
{
    return s->ptr;
}

void picostream_reset(picostream * s)
{
    s->ptr = 0;
}

int picostream_skip(picostream * s, size_t nb_bytes)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < nb_bytes) {
        s->ptr = s->size;
        return -1;
    } else {
        s->ptr += nb_bytes;
        return 0;
    }
}

int picostream_write_int(picostream * s, uint64_t value)
{
    size_t len = picoquic_varint_encode(s->data + s->ptr, s->size - s->ptr, value);
    if (len == 0) {
        s->ptr += s->size;
        return -1;
    } else {
        s->ptr += len;
        return 0;
    }
}

int picostream_read_int(picostream * s, uint64_t * value)
{
    size_t len = picoquic_varint_decode(s->data + s->ptr, s->size - s->ptr, value);
    if (len == 0) {
        s->ptr += s->size;
        return -1;
    } else {
        s->ptr += len;
        return 0;
    }
}

int picostream_write_int32(picostream * s, uint32_t value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 4) {
        s->ptr = s->size;
        return -1;
    } else {
        picoformat_32(s->data + s->ptr, value);
        s->ptr += 4;
        return 0;
    }
}

int picostream_read_int32(picostream * s, uint32_t * value)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < 4) {
        s->ptr = s->size;
        return -1;
    }
    else {
        uint32_t v = 0;
        for (size_t i = 0; i < 4; i++) {
            v <<= 8;
            v += s->data[s->ptr++];
        }
        *value = v;
        return 0;
    }
}

int picostream_write_buffer(picostream * s, const void * buffer, size_t length)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < length) {
        return -1;
    }

    memcpy(s->data + s->ptr, buffer, length);
    s->ptr += length;
    return 0;
}

int picostream_read_buffer(picostream * s, void * buffer, size_t length)
{
    size_t max_bytes = s->size - s->ptr;
    if (max_bytes < length) {
        return -1;
    }

    memcpy(buffer, s->data + s->ptr, length);
    s->ptr += length;
    return 0;
}
