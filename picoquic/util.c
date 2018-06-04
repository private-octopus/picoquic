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
#ifdef _WINDOWS
/* clang-format off */
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <WinSock2.h>
#include <Ws2def.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include "picoquic_internal.h"
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

char* picoquic_string_create(const char* original, size_t len)
{
    size_t allocated = len + 1;
    char * str = NULL;

    if (allocated > len && allocated >= 1) {
        str = (char*)malloc(allocated);

        if (str != NULL) {
            if (original == NULL || len == 0) {
                str[0] = 0;
            }
            else {
                memcpy(str, original, len);
                str[len] = 0;
            }
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

char* picoquic_strip_endofline(char* buf, size_t bufmax, char const* line)
{
    for (size_t i = 0; i < bufmax; i++) {
        int c = line[i];

        if (c == 0 || c == '\r' || c == '\n') {
            buf[i] = 0;
            break;
        }
        else {
            buf[i] = (char) c;
        }
    }

    buf[bufmax - 1] = 0;
    return buf;
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

uint8_t picoquic_create_packet_header_cnxid_lengths(uint8_t dest_len, uint8_t srce_len)
{
    uint8_t ret;

    ret = (dest_len < 4) ? 0 : (dest_len - 3);
    ret <<= 4;
    ret |= (srce_len < 4) ? 0 : (srce_len - 3);

    return ret;
}

void picoquic_parse_packet_header_cnxid_lengths(uint8_t l_byte, uint8_t *dest_len, uint8_t *srce_len)
{
    uint8_t h1 = (l_byte>>4);
    uint8_t h2 = (l_byte & 0x0F);

    *dest_len = (h1 == 0) ? 0 : h1 + 3;
    *srce_len = (h2 == 0) ? 0 : h2 + 3;
}

uint32_t picoquic_format_connection_id(uint8_t* bytes, size_t bytes_max, picoquic_connection_id_t cnx_id)
{
    uint32_t copied = cnx_id.id_len;
    if (copied > bytes_max || copied == 0) {
        copied = 0;
    } else {
        memcpy(bytes, cnx_id.id, copied);
    }

    return copied;
}

uint32_t picoquic_parse_connection_id(const uint8_t * bytes, uint8_t len, picoquic_connection_id_t * cnx_id)
{
    if (len <= PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        cnx_id->id_len = len;
        memcpy(cnx_id->id, bytes, len);
    } else {
        len = 0;
        cnx_id->id_len = 0;
    }
    return len;
}

const picoquic_connection_id_t picoquic_null_connection_id = { 
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0 };

int picoquic_is_connection_id_null(picoquic_connection_id_t cnx_id)
{
    return (cnx_id.id_len == 0) ? 1 : 0;
}

int picoquic_compare_connection_id(picoquic_connection_id_t * cnx_id1, picoquic_connection_id_t * cnx_id2)
{
    int ret = -1;

    if (cnx_id1->id_len == cnx_id2->id_len) {
        ret = memcmp(cnx_id1->id, cnx_id2->id, cnx_id1->id_len);
    }

    return ret;
}

uint64_t picoquic_val64_connection_id(picoquic_connection_id_t cnx_id)
{
    uint64_t val64 = 0;

    if (cnx_id.id_len < 8)
    {
        for (size_t i = 0; i < cnx_id.id_len; i++) {
            val64 <<= 8;
            val64 |= cnx_id.id[i];
        }
        for (size_t i = cnx_id.id_len; i < 8; i++) {
            val64 <<= 8;
        }
    } else {
        for (size_t i = 0; i < 8; i++) {
            val64 <<= 8;
            val64 |= cnx_id.id[i];
        }
    }

    return val64;
}

void picoquic_set64_connection_id(picoquic_connection_id_t * cnx_id, uint64_t val64)
{
    for (int i = 7; i >= 0; i--) {
        cnx_id->id[i] = (uint8_t)(val64 & 0xFF);
        val64 >>= 8;
    }
    for (size_t i = 8; i < sizeof(cnx_id->id); i++) {
        cnx_id->id[i] = 0;
    }
    cnx_id->id_len = 8;
}

int picoquic_compare_addr(struct sockaddr * expected, struct sockaddr * actual)
{
    int ret = -1;

    if (expected->sa_family == actual->sa_family) {
        if (expected->sa_family == AF_INET) {
            struct sockaddr_in * ex = (struct sockaddr_in *)expected;
            struct sockaddr_in * ac = (struct sockaddr_in *)actual;
            if (ex->sin_port == ac->sin_port &&
#ifdef _WINDOWS
                ex->sin_addr.S_un.S_addr == ac->sin_addr.S_un.S_addr) {
#else
                ex->sin_addr.s_addr == ac->sin_addr.s_addr){
#endif
                ret = 0;
            }
        } else {
            struct sockaddr_in6 * ex = (struct sockaddr_in6 *)expected;
            struct sockaddr_in6 * ac = (struct sockaddr_in6 *)actual;


            if (ex->sin6_port == ac->sin6_port &&
                memcmp(&ex->sin6_addr, &ac->sin6_addr, 16) == 0) {
                ret = 0;
            }
        }
    }

    return ret;
}