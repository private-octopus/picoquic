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

#ifndef PICOQUIC_PICOSTREAM_H
#define PICOQUIC_PICOSTREAM_H

#include "picoquic_internal.h"

#define PICOSTREAM_MAX_BUFFER_SIZE 2048

typedef struct {
    uint8_t * data;
    size_t size;
    size_t ptr;
} bytestream;

typedef struct {
    bytestream s;
    uint8_t buf[PICOSTREAM_MAX_BUFFER_SIZE];
} bytestream_buf;

bytestream * bytereader_init(bytestream * s, const void * bytes, size_t nb_bytes);
bytestream * bytewriter_init(bytestream_buf * s);
bytestream * bytestream_alloc(bytestream * s, size_t nb_bytes);
void bytestream_delete(bytestream * s);
void * bytestream_data(bytestream * s);
size_t bytestream_size(bytestream * s);
size_t bytestream_length(bytestream * s);

void bytestream_reset(bytestream * s);
int bytestream_skip(bytestream * s, size_t nb_bytes);

int bytewrite_int8(bytestream * s, uint8_t value);
int byteread_int8(bytestream * s, uint8_t * value);

int bytewrite_int16(bytestream * s, uint16_t value);
int byteread_int16(bytestream * s, uint16_t * value);

int bytewrite_int32(bytestream * s, uint32_t value);
int byteread_int32(bytestream * s, uint32_t * value);

int bytewrite_int64(bytestream * s, uint64_t value);
int byteread_int64(bytestream * s, uint64_t * value);

int bytewrite_vint(bytestream * s, uint64_t value);
int byteread_vint(bytestream * s, uint64_t * value);

int bytewrite_buffer(bytestream * s, const void * buffer, size_t length);
int byteread_buffer(bytestream * s, void * buffer, size_t length);

#endif /* PICOQUIC_PICOSTREAM_H */
