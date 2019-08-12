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
} picostream;

typedef struct {
    picostream s;
    uint8_t buf[PICOSTREAM_MAX_BUFFER_SIZE];
} pico_writestream;

picostream * picostream_init_read(picostream * s, const void * bytes, size_t nb_bytes);
picostream * picostream_init_write(pico_writestream * s);
picostream * picostream_alloc(size_t nb_bytes);
void picostream_delete(picostream * s);
void * picostream_data(picostream * s);
size_t picostream_size(picostream * s);
size_t picostream_length(picostream * s);

void picostream_reset(picostream * s);
int picostream_skip(picostream * s, size_t nb_bytes);

int picostream_write_int32(picostream * s, uint32_t value);
int picostream_read_int32(picostream * s, uint32_t * value);

int picostream_write_int(picostream * s, uint64_t value);
int picostream_read_int(picostream * s, uint64_t * value);

int picostream_write_buffer(picostream * s, const void * buffer, size_t length);
int picostream_read_buffer(picostream * s, void * buffer, size_t length);

#endif /* PICOQUIC_PICOSTREAM_H */
