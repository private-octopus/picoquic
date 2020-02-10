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

#ifdef _WINDOWS
#ifndef _WINDOWS64
#ifndef PICOQUIC_USE_CONSTANT_TIME_MEMCMP
#define PICOQUIC_USE_CONSTANT_TIME_MEMCMP
#endif
#endif
#endif

#ifdef __APPLE__
#ifndef PICOQUIC_USE_CONSTANT_TIME_MEMCMP
#define PICOQUIC_USE_CONSTANT_TIME_MEMCMP
#endif
#endif

/* File identifiers in simple tracing functions */
#define PICOQUIC_SENDER 1
#define PICOQUIC_PACKET 2
#define PICOQUIC_QUICCTX 3
#define PICOQUIC_FRAME 4
#define SET_LAST_WAKE(quic, file_id) ((quic)->wake_file = file_id, (quic)->wake_line = __LINE__)


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
int picoquic_is_connection_id_null(const picoquic_connection_id_t * cnx_id);
int picoquic_compare_connection_id(const picoquic_connection_id_t * cnx_id1, const picoquic_connection_id_t * cnx_id2);
uint64_t picoquic_connection_id_hash(const picoquic_connection_id_t * cid);
uint64_t picoquic_val64_connection_id(picoquic_connection_id_t cnx_id);
void picoquic_set64_connection_id(picoquic_connection_id_t * cnx_id, uint64_t val64);
uint64_t picoquic_hash_addr(const struct sockaddr* addr);
uint8_t picoquic_parse_connection_id_hexa(char const * hex_input, size_t input_length, picoquic_connection_id_t * cnx_id);
int picoquic_print_connection_id_hexa(char* buf, size_t buf_len, const picoquic_connection_id_t* cnxid);
uint8_t picoquic_create_packet_header_cnxid_lengths(uint8_t dest_len, uint8_t srce_len);

int picoquic_compare_addr(const struct sockaddr * expected, const struct sockaddr * actual);
int picoquic_store_addr(struct sockaddr_storage * stored_addr, const struct sockaddr * addr);
void picoquic_get_ip_addr(struct sockaddr * addr, uint8_t ** ip_addr, uint8_t * ip_addr_len);

int picoquic_get_input_path(char * target_file_path, size_t file_path_max, const char * solution_path, const char * file_name);

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifdef _WINDOWS
#define PICOQUIC_FILE_SEPARATOR "\\"
#ifdef _WINDOWS64
#define PICOQUIC_DEFAULT_SOLUTION_DIR "..\\..\\"
#else
#define PICOQUIC_DEFAULT_SOLUTION_DIR "..\\"
#endif
#else
#define PICOQUIC_DEFAULT_SOLUTION_DIR "./"
#define PICOQUIC_FILE_SEPARATOR "/"
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

/* Encoding functions of the form uint8_t * picoquic_frame_XXX_encode(uint8_t * bytes, uint8_t * bytes-max, ...)
 */
uint8_t* picoquic_frames_varint_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n64);
uint8_t* picoquic_frames_varlen_encode(uint8_t* bytes, const uint8_t* bytes_max, size_t n);
uint8_t* picoquic_frames_uint8_encode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t n);
uint8_t* picoquic_frames_uint16_encode(uint8_t* bytes, const uint8_t* bytes_max, uint16_t n);
uint8_t* picoquic_frames_uint24_encode(uint8_t * bytes, const uint8_t * bytes_max, uint32_t n);
uint8_t* picoquic_frames_uint32_encode(uint8_t* bytes, const uint8_t* bytes_max, uint32_t n);
uint8_t* picoquic_frames_uint64_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n);
uint8_t* picoquic_frames_l_v_encode(uint8_t* bytes, const uint8_t* bytes_max, size_t l, const uint8_t* v);
uint8_t* picoquic_frames_cid_encode(uint8_t* bytes, const uint8_t* bytes_max, const picoquic_connection_id_t* cid);

/* Constant time memory comparison may be required on some platforms for testing reset secrets */
int picoquic_constant_time_memcmp(const uint8_t* x, const uint8_t* y, size_t l);

/* A set of portable function enables minimal support for
 * thread, mutex and event in Windows and Linux
 */
#ifdef _WINDOWS
#define picoquic_thread_t HANDLE
#define picoquic_thread_return_t DWORD WINAPI
typedef DWORD (WINAPI* picoquic_thread_fn)(LPVOID lpParam);
#define picoquic_mutex_t HANDLE
#define picoquic_event_t HANDLE
#define picoquic_thread_do_return return 0
#else
 /* Linux routine returns */
#define picoquic_thread_t pthread_t
#define picoquic_thread_return_t void 
typedef void (*picoquic_thread_fn) (void* lpParam);
#define picoquic_mutex_t pthread_mutex_t 
#define picoquic_thread_do_return return

typedef struct st_picoquic_event_t {
    pthread_mutex_t mutex;
    pthread_cond_t cond;
} picoquic_event_t;
#endif

int picoquic_create_thread(picoquic_thread_t* thread, picoquic_thread_fn thread_fn, void* arg);
void picoquic_delete_thread(picoquic_thread_t* thread);

int picoquic_create_mutex(picoquic_mutex_t* mutex);
int picoquic_delete_mutex(picoquic_mutex_t* mutex);
int picoquic_lock_mutex(picoquic_mutex_t* mutex);
int picoquic_unlock_mutex(picoquic_mutex_t* mutex);

int picoquic_create_event(picoquic_event_t* event);
void picoquic_delete_event(picoquic_event_t* event);
int picoquic_signal_event(picoquic_event_t* event);
int picoquic_wait_for_event(picoquic_event_t* event, uint64_t microsec_wait);


#ifdef __cplusplus
}
#endif
#endif
