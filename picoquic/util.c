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
#include "util.h"

char* picoquic_string_create(const char* original, size_t len)
{
    size_t allocated = len + 1;
    char * str = NULL;

    /* test > 0 to protect against integer overflow */
    if (allocated > len && allocated > 0) {
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

void debug_set_stream(FILE *F)
{
    debug_out = F;
}

void debug_printf(const char* fmt, ...)
{
    if (debug_suspended == 0 && debug_out != NULL) {
        va_list args;
        va_start(args, fmt);
        vfprintf(debug_out, fmt, args);
        va_end(args);
    }
}

void debug_dump(const void * x, int len)
{
    if (debug_suspended == 0 && debug_out != NULL) {
        uint8_t * bytes = (uint8_t *)x;

        for (int i = 0; i < len;) {
            fprintf(debug_out, "%04x:  ", (int)i);

            for (int j = 0; j < 16 && i < len; j++, i++) {
                fprintf(debug_out, "%02x ", bytes[i]);
            }
            fprintf(debug_out, "\n");
        }
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

int debug_printf_reset(int suspended)
{
    int ret = debug_suspended;
    debug_suspended = suspended;
    return ret;
}

int picoquic_parse_hexa_digit(char x) {
    int ret = -1;

    if (x >= '0' && x <= '9') {
        ret = x - '0';
    }
    else if (x >= 'A' && x <= 'F') {
        ret = x - 'A' + 10;
    }
    else if (x >= 'a' && x <= 'f') {
        ret = x - 'a' + 10;
    }

    return ret;
}

size_t picoquic_parse_hexa(char const * hex_input, size_t input_length, uint8_t * bin_output, size_t output_max)
{
    size_t ret = 0;
    if (input_length > 0 || (input_length & 1) == 0 || 2 * output_max >= input_length) {
        size_t offset = 0;

        while (offset < input_length) {
            int a = picoquic_parse_hexa_digit(hex_input[offset++]);
            int b = picoquic_parse_hexa_digit(hex_input[offset++]);

            if (a < 0 || b < 0) {
                ret = 0;
                break;
            }
            else {
                bin_output[ret++] = (uint8_t)((a << 4) | b);
            }
        }
    }

    return ret;
}

uint8_t picoquic_parse_connection_id_hexa(char const * hex_input, size_t input_length, picoquic_connection_id_t * cnx_id)
{
    memset(cnx_id, 0, sizeof(picoquic_connection_id_t));
    cnx_id->id_len = (uint8_t) picoquic_parse_hexa(hex_input, input_length, cnx_id->id, 18);

    if (cnx_id->id_len == 0) {
        memset(cnx_id, 0, sizeof(picoquic_connection_id_t));
    }

    return (cnx_id->id_len);
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

uint8_t picoquic_format_connection_id(uint8_t* bytes, size_t bytes_max, picoquic_connection_id_t cnx_id)
{
    uint8_t copied = cnx_id.id_len;
    if (copied > bytes_max || copied == 0) {
        copied = 0;
    } else {
        memcpy(bytes, cnx_id.id, copied);
    }

    return copied;
}

int picoquic_is_connection_id_length_valid(uint8_t len) {
    int ret = 0;
    if (len >= PICOQUIC_CONNECTION_ID_MIN_SIZE && len <= PICOQUIC_CONNECTION_ID_MAX_SIZE) {
        ret = len;
    }
    return ret;
}

uint8_t picoquic_parse_connection_id(const uint8_t * bytes, uint8_t len, picoquic_connection_id_t * cnx_id)
{
    if (picoquic_is_connection_id_length_valid(len)) {
        cnx_id->id_len = len;
        memcpy(cnx_id->id, bytes, len);
    } else {
        len = 0;
        cnx_id->id_len = 0;
    }
    return len;
}

const picoquic_connection_id_t picoquic_null_connection_id = { 
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 0 };

int picoquic_is_connection_id_null(picoquic_connection_id_t cnx_id)
{
    return (cnx_id.id_len == 0) ? 1 : 0;
}

int picoquic_compare_connection_id(const picoquic_connection_id_t * cnx_id1, const picoquic_connection_id_t * cnx_id2)
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

int picoquic_compare_addr(const struct sockaddr * expected, const struct sockaddr * actual)
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

/* Copy a sockaddr to a storage value, and return the copied address length */
int picoquic_store_addr(struct sockaddr_storage * stored_addr, const struct sockaddr * addr)
{
    int len = 0;
    
    if (addr != NULL && addr->sa_family != 0) {
        len = (int)((addr->sa_family == AF_INET) ? sizeof(struct sockaddr_in) :
            sizeof(struct sockaddr_in6));
        memcpy(stored_addr, addr, len);
    }
    else {
        memset(stored_addr, 0, sizeof(struct sockaddr_storage));
    }

    return len;
}

/* Return a pointer to the IP address and IP length in a sockaddr */
void picoquic_get_ip_addr(struct sockaddr * addr, uint8_t ** ip_addr, uint8_t * ip_addr_len)
{
    if (addr->sa_family == AF_INET) {
        *ip_addr = (uint8_t *)&((struct sockaddr_in *)addr)->sin_addr;
        *ip_addr_len = 4;
    }
    else if(addr->sa_family == AF_INET6) {
        *ip_addr = (uint8_t *)&((struct sockaddr_in6 *)addr)->sin6_addr;
        *ip_addr_len = 16;
    }
    else {
        *ip_addr = NULL;
        *ip_addr_len = 0;
    }
}

/* Return a directory path based on solution dir and file name */
#ifdef _WINDOWS
#define PICOQUIC_FILE_SEPARATOR '\\'
#ifdef _WINDOWS64
#define PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\"
#else
#define PICOQUIC_DEFAULT_SOLUTION_DIR "..\\"
#endif
#else
#define PICOQUIC_DEFAULT_SOLUTION_DIR "./"
#define PICOQUIC_FILE_SEPARATOR '/'
#endif

int picoquic_get_input_path(char * target_file_path, size_t file_path_max, const char * solution_path, const char * file_name) 
{
    int ret = 0;
    size_t solution_path_length;
    size_t file_name_length;
    size_t separator_length = 0;
    if (solution_path == NULL) {
        solution_path = PICOQUIC_DEFAULT_SOLUTION_DIR;
    }

    solution_path_length = strlen(solution_path);
    file_name_length = strlen(file_name);
    if (solution_path_length == 0 || solution_path[solution_path_length - 1] != PICOQUIC_FILE_SEPARATOR) {
        separator_length = 1;
    }

    if (solution_path_length + separator_length + file_name_length + 1 > file_path_max) {
        target_file_path[0] = 0;
        ret = -1;
    }
    else {
        size_t byte_index = 0;
        memcpy(&target_file_path[byte_index], solution_path, solution_path_length);
        byte_index += solution_path_length;

        if (separator_length) {
            target_file_path[byte_index++] = PICOQUIC_FILE_SEPARATOR;
        }
        memcpy(&target_file_path[byte_index], file_name, file_name_length);
        byte_index += file_name_length;

        target_file_path[byte_index] = 0;
    }

    return ret;
}

/* Safely open files in a portable way */
FILE * picoquic_file_open(char const * file_name, char const * flags)
{
    FILE * F;

#ifdef _WINDOWS
    errno_t err = fopen_s(&F, file_name, flags);
    if (err != 0 && F != NULL) {
            fclose(F);
            F = NULL;
        }
#else
    F = fopen(file_name, flags);
#endif

    return F;
}