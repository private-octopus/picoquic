/*
* Author: Christian Huitema
* Copyright (c) 2026, Private Octopus, Inc.
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

/* Web transport interop test protocol, as specified in
 * https://github.com/quic-interop/quic-interop-runner/blob/master/webtransport.md
 *
 * The requester asks for files with "GET <name>", on a unidirectional stream,
 * a bidirectional stream or a datagram. The responder sends the file back with
 * "PUSH <name>\n<content>" on a new unidirectional stream or in a datagram,
 * or as raw content on the same bidirectional stream.
 *
 * The test case, the requests and the application protocols are read from the
 * environment variables TESTCASE, REQUESTS and PROTOCOLS.
 */

#ifndef WT_INTEROP_H
#define WT_INTEROP_H

#include "h3zero.h"
#include "h3zero_common.h"
#include "pico_webtransport.h"
#include "picoquic_config.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WT_INTEROP_NAME_MAX 256
#define WT_INTEROP_LINE_MAX (WT_INTEROP_NAME_MAX + 8)
#define WT_INTEROP_DATAGRAM_MAX 1200
#define WT_INTEROP_NEGOTIATED_FILE "negotiated_protocol.txt"

#define WT_INTEROP_SESSION_ERR_DONE 0
#define WT_INTEROP_SESSION_ERR_PROTOCOL 1
#define WT_INTEROP_STREAM_ERR_NOT_FOUND 1

    typedef enum {
        wt_interop_test_unknown = 0,
        wt_interop_test_handshake,
        wt_interop_test_transfer,
        wt_interop_test_unidirectional_receive,
        wt_interop_test_unidirectional_send,
        wt_interop_test_bidirectional_receive,
        wt_interop_test_bidirectional_send,
        wt_interop_test_datagram_receive,
        wt_interop_test_datagram_send
    } wt_interop_test_enum;

    typedef enum {
        wt_interop_mode_none = 0,
        wt_interop_mode_unidirectional,
        wt_interop_mode_bidirectional,
        wt_interop_mode_datagram
    } wt_interop_mode_enum;

    /* One entry of the REQUESTS list: endpoint and optional file name. */
    typedef struct st_wt_interop_request_t {
        struct st_wt_interop_request_t* next;
        char* endpoint;
        char* file_name;
    } wt_interop_request_t;

    /* Parameters shared by all sessions of a client or server. */
    typedef struct st_wt_interop_param_t {
        int is_client;
        wt_interop_test_enum test_id;
        char const* www_dir;
        char const* download_dir;
        char* supported_protocols; /* "a, b, c", for picowt_select_wt_protocol */
        char* available_protocols; /* "\"a\", \"b\"", for the wt-available-protocols header */
        char* host; /* client only, from the request URLs */
        uint16_t port;
        char* authority;
        wt_interop_request_t* first_request;
        wt_interop_request_t* last_request;
        size_t nb_requests;
    } wt_interop_param_t;

    /* Per stream state, both for receiving and for sending. */
    typedef struct st_wt_interop_stream_t {
        struct st_wt_interop_stream_t* next;
        uint64_t stream_id;
        /* receive side */
        int is_line_done;
        int is_command_done;
        int is_get_pending;
        int is_body_expected;
        size_t line_length;
        char line[WT_INTEROP_LINE_MAX];
        char* receive_name;
        FILE* F_receive;
        /* send side */
        int is_sending;
        size_t header_length;
        size_t header_sent;
        uint8_t header[WT_INTEROP_LINE_MAX];
        FILE* F_send;
        uint64_t send_remaining;
    } wt_interop_stream_t;

    /* Datagram waiting to be sent. */
    typedef struct st_wt_interop_datagram_t {
        struct st_wt_interop_datagram_t* next;
        size_t length;
        uint8_t data[WT_INTEROP_DATAGRAM_MAX];
    } wt_interop_datagram_t;

    /* File requested by this endpoint in this session. */
    typedef struct st_wt_interop_file_t {
        struct st_wt_interop_file_t* next;
        char* name;
        int is_received;
    } wt_interop_file_t;

    typedef struct st_wt_interop_session_t {
        picoquic_cnx_t* cnx;
        h3zero_callback_ctx_t* h3_ctx;
        wt_interop_param_t const* param;
        int is_client;
        uint64_t control_stream_id;
        char endpoint[WT_INTEROP_NAME_MAX];
        picowt_capsule_t capsule;
        wt_interop_mode_enum request_mode;
        wt_interop_stream_t* first_stream;
        wt_interop_datagram_t* first_datagram;
        wt_interop_datagram_t* last_datagram;
        wt_interop_file_t* first_file;
        size_t nb_files;
        size_t nb_files_received;
        int nb_errors;
        int is_accepted;
        int is_refused;
        int is_done;
        int is_closed;
        int is_deregistered;
        char negotiated_protocol[WT_INTEROP_NAME_MAX];
    } wt_interop_session_t;

    /* Parse the TESTCASE value. */
    wt_interop_test_enum wt_interop_parse_test_case(char const* test_case);

    /* Parse "https://host[:port]/endpoint[/file]". Path points into url, after the "/". */
    int wt_interop_parse_url(char const* url, char* host, size_t host_max, uint16_t* port, char const** path);

    /* Initialize parameters from explicit strings; any of them may be NULL. */
    int wt_interop_param_init(wt_interop_param_t* param, int is_client, char const* test_case,
        char const* requests, char const* protocols, char const* www_dir, char const* download_dir);

    /* Initialize parameters from the TESTCASE, REQUESTS and PROTOCOLS environment variables. */
    int wt_interop_param_from_env(wt_interop_param_t* param, int is_client, char const* www_dir, char const* download_dir);

    void wt_interop_param_clear(wt_interop_param_t* param);

    /* Fill a wildcard path table item that accepts sessions on any endpoint present in www_dir. */
    void wt_interop_set_path_item(picohttp_server_path_item_t* item, wt_interop_param_t* param);

    int wt_interop_callback(picoquic_cnx_t* cnx,
        uint8_t* bytes, size_t length,
        picohttp_call_back_event_t wt_event,
        struct st_h3zero_stream_ctx_t* stream_ctx,
        void* path_app_ctx);

    /* Client: prepare the connection and queue the CONNECT request. If *p_cnx is NULL, it is created. */
    int wt_interop_client_prepare(picoquic_quic_t* quic, struct sockaddr* server_address, uint64_t current_time,
        char const* sni, wt_interop_param_t const* param, picoquic_cnx_t** p_cnx, h3zero_callback_ctx_t** p_h3_ctx,
        wt_interop_session_t** p_session);

    /* Client: release the session after the H3 context has been deleted. */
    void wt_interop_session_free(wt_interop_session_t* session);

    /* Client: 1 if the test case completed as expected. */
    int wt_interop_client_is_success(wt_interop_session_t const* session);

    /* Client: run a complete interop test, using a real socket loop. */
    int wt_interop_client(picoquic_quic_config_t* config, wt_interop_param_t const* param);

#ifdef __cplusplus
}
#endif
#endif /* WT_INTEROP_H */
