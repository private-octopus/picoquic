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

void debug_printf(const char* fmt, ...);
void debug_printf_push_stream(FILE* f);
void debug_printf_pop_stream(void);
void debug_printf_suspend(void);
void debug_printf_resume(void);

extern const picoquic_connection_id_t picoquic_null_connection_id;
uint32_t picoquic_format_connection_id(uint8_t* bytes, size_t bytes_max, picoquic_connection_id_t cnx_id);
uint32_t picoquic_parse_connection_id(const uint8_t* bytes, uint8_t len, picoquic_connection_id_t *cnx_id);
int picoquic_is_connection_id_null(picoquic_connection_id_t cnx_id);
int picoquic_compare_connection_id(picoquic_connection_id_t * cnx_id1, picoquic_connection_id_t * cnx_id2);
uint64_t picoquic_val64_connection_id(picoquic_connection_id_t cnx_id);
void picoquic_set64_connection_id(picoquic_connection_id_t * cnx_id, uint64_t val64);
uint8_t picoquic_create_packet_header_cnxid_lengths(uint8_t dest_len, uint8_t srce_len);
void picoquic_parse_packet_header_cnxid_lengths(uint8_t l_byte, uint8_t *dest_len, uint8_t *srce_len);

int picoquic_compare_addr(struct sockaddr * expected, struct sockaddr * actual);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef DISABLE_DEBUG_PRINTF

#define DBG_PRINTF_FILENAME_MAX 24
#define DBG_PRINTF(fmt, ...)                                                                 \
    debug_printf("%s:%u [%s]: " fmt "\n",                                                    \
        __FILE__ + MAX(DBG_PRINTF_FILENAME_MAX, sizeof(__FILE__)) - DBG_PRINTF_FILENAME_MAX, \
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

#endif
