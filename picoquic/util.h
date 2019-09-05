/*
* Author: Igor Lubashev
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

#ifndef PICOQUIC_UTILS_H
#define PICOQUIC_UTILS_H

#include <stdio.h>
#include <inttypes.h>
#include "picoquic.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef WIN32
#define PRIst "Iu"
#ifndef PRIu64
#define PRIu64 "I64u"
#endif
#ifndef PRIx64
#define PRIx64 "I64x"
#endif
#else
#define PRIst "zu"
#endif

void debug_set_stream(FILE *F);
void debug_printf(const char* fmt, ...);
void debug_printf_push_stream(FILE* f);
void debug_printf_pop_stream(void);
void debug_printf_suspend(void);
void debug_printf_resume(void);
int debug_printf_reset(int suspended);
void debug_dump(const void * x, int len);

int picoquic_sprintf(char* buf, size_t buf_len, size_t * nb_chars, const char* fmt, ...);

extern const picoquic_connection_id_t picoquic_null_connection_id;
uint8_t picoquic_format_connection_id(uint8_t* bytes, size_t bytes_max, picoquic_connection_id_t cnx_id);
int picoquic_is_connection_id_length_valid(uint8_t len);
uint8_t picoquic_parse_connection_id(const uint8_t* bytes, uint8_t len, picoquic_connection_id_t *cnx_id);
int picoquic_is_connection_id_null(picoquic_connection_id_t cnx_id);
int picoquic_compare_connection_id(const picoquic_connection_id_t * cnx_id1, const picoquic_connection_id_t * cnx_id2);
uint64_t picoquic_val64_connection_id(picoquic_connection_id_t cnx_id);
void picoquic_set64_connection_id(picoquic_connection_id_t * cnx_id, uint64_t val64);
uint8_t picoquic_parse_connection_id_hexa(char const * hex_input, size_t input_length, picoquic_connection_id_t * cnx_id);
int picoquic_print_connection_id_hexa(char* buf, size_t buf_len, const picoquic_connection_id_t* cnxid);
uint8_t picoquic_create_packet_header_cnxid_lengths(uint8_t dest_len, uint8_t srce_len);
void picoquic_parse_packet_header_cnxid_lengths(uint8_t l_byte, uint8_t *dest_len, uint8_t *srce_len);

int picoquic_compare_addr(const struct sockaddr * expected, const struct sockaddr * actual);
int picoquic_store_addr(struct sockaddr_storage * stored_addr, const struct sockaddr * addr);
void picoquic_get_ip_addr(struct sockaddr * addr, uint8_t ** ip_addr, uint8_t * ip_addr_len);

int picoquic_get_input_path(char * target_file_path, size_t file_path_max, const char * solution_path, const char * file_name);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

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

#ifndef DISABLE_DEBUG_PRINTF

#define DBG_PRINTF_FILENAME_MAX 24
#define DBG_PRINTF(fmt, ...)                                                                 \
    debug_printf("%s:%u [%s]: " fmt "\n",                                                    \
        &__FILE__[MAX(DBG_PRINTF_FILENAME_MAX, sizeof(__FILE__)) - DBG_PRINTF_FILENAME_MAX], \
        __LINE__, __FUNCTION__, __VA_ARGS__)

#define DBG_FATAL_PRINTF(fmt, ...)                    \
    do {                                              \
        DBG_PRINTF("(FATAL) " fmt "\n", __VA_ARGS__); \
        exit(1);                                      \
    } while (0)

#else

#define DBG_PRINTF(fmt, ...)
#define DBG_FATAL_PRINTF(fmt, ...)

#endif //#ifdef DISABLE_DEBUG_PRINTF

/* Safely open files in a portable way */
FILE * picoquic_file_open_ex(char const * file_name, char const * flags, int * last_err);
FILE * picoquic_file_open(char const * file_name, char const * flags);
FILE * picoquic_file_close(FILE * F);

#ifdef __cplusplus
}
#endif
#endif
