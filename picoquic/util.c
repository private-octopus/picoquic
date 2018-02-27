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

/* Simple set of utilities */

#include "picoquic_internal.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

char* picoquic_string_create(const char* original, size_t len)
{
    char* str = (char*)malloc(len + 1);

    if (str != NULL) {
        if (original == NULL || len == 0) {
            str[0] = 0;
        } else {
            memcpy(str, original, len);
            str[len] = 0;
        }
    }

    return str;
}

char* picoquic_string_duplicate(const char* original)
{
    char* str = NULL;

    if (original != NULL) {
        size_t len = strlen(original);

        str = picoquic_string_create(original, len);
    }

    return str;
}

static FILE* debug_out = NULL;
static int debug_suspended = 0;

void debug_printf(const char* fmt, ...)
{
    if (debug_suspended == 0) {
        va_list args;
        va_start(args, fmt);
        vfprintf(debug_out ? debug_out : stderr, fmt, args);
        va_end(args);
    }
}

void debug_printf_push_stream(FILE* f)
{
    if (debug_out) {
        fprintf(stderr, "Nested err out not supported\n");
        exit(1);
    }
    debug_out = f;
}

void debug_printf_pop_stream(void)
{
    if (debug_out == NULL) {
        fprintf(stderr, "No current err out\n");
        exit(1);
    }
    debug_out = NULL;
}

void debug_printf_suspend(void)
{
    debug_suspended = 1;
}

void debug_printf_resume(void)
{
    debug_suspended = 0;
}

size_t picoquic_format_connection_id(uint8_t* bytes, picoquic_connection_id_t cnx_id)
{
    picoformat_64(bytes, cnx_id.opaque64);

    return PICOQUIC_CONNECTION_ID_SIZE;
}

size_t picoquic_parse_connection_id(uint8_t * bytes, picoquic_connection_id_t * cnx_id)
{
    size_t len = sizeof(picoquic_connection_id_t);

    cnx_id->opaque64 = PICOPARSE_64(bytes);

    return len;
}

const picoquic_connection_id_t picoquic_null_connection_id = { 0 };

int picoquic_is_connection_id_null(picoquic_connection_id_t cnx_id)
{
    return (cnx_id.opaque64 == 0) ? 1 : 0;
}

int picoquic_compare_connection_id(picoquic_connection_id_t * cnx_id1, picoquic_connection_id_t * cnx_id2)
{
    return(cnx_id1->opaque64 == cnx_id2->opaque64) ? 0 : -1;
}

uint64_t picoquic_val64_connection_id(picoquic_connection_id_t cnx_id)
{
    return (cnx_id.opaque64);
}