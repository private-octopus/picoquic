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

/* Web transport interop test protocol, see wt_interop.h.
 *
 * The test case determines which side requests files, and over which channel:
 * - client, for the transfer-*-receive tests, with REQUESTS listing full URLs;
 * - server, for the transfer-*-send tests, with REQUESTS listing "endpoint/file".
 * The other side only responds. Both sides write the negotiated protocol
 * to "negotiated_protocol.txt" for the handshake test.
 *
 * The requester closes the session once all files are received. The client
 * closes the connection once its session is done or closed by the server.
 * The library only supports one web transport session per connection, so
 * all requests must use the same endpoint.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include <picoquic_packet_loop.h>
#include <picoquic_config.h>
#include <picoquic_qlog.h>
#include "h3zero.h"
#include "h3zero_common.h"
#include "pico_webtransport.h"
#include "wt_interop.h"

#ifdef _WINDOWS
#include <direct.h>
#include <sys/types.h>
#include <sys/stat.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#endif

#define WT_INTEROP_PATH_MAX 1024
#define WT_INTEROP_IS_BIDIR(id) (((id) & 2) == 0)

/* Duplicate the first length characters of a string. */
static char* wt_interop_strndup(char const* s, size_t length)
{
    char* d = (char*)malloc(length + 1);
    if (d != NULL) {
        memcpy(d, s, length);
        d[length] = 0;
    }
    return d;
}

/* Copy of an environment variable, or NULL if not set. */
static char* wt_interop_getenv(char const* name)
{
    char* value = NULL;
#ifdef _WINDOWS
    size_t len = 0;
    char* env_value = NULL;

    if (_dupenv_s(&env_value, &len, name) == 0 && env_value != NULL) {
        value = picoquic_string_duplicate(env_value);
        free(env_value);
    }
#else
    char const* env_value = getenv(name);
    if (env_value != NULL) {
        value = picoquic_string_duplicate(env_value);
    }
#endif
    return value;
}

static int wt_interop_is_dir(char const* path)
{
#ifdef _WINDOWS
    struct _stat st;
    return (_stat(path, &st) == 0 && (st.st_mode & _S_IFDIR) != 0);
#else
    struct stat st;
    return (stat(path, &st) == 0 && S_ISDIR(st.st_mode));
#endif
}

static int wt_interop_mkdir(char const* path)
{
    int ret = 0;
    if (!wt_interop_is_dir(path)) {
#ifdef _WINDOWS
        ret = _mkdir(path);
#else
        ret = mkdir(path, 0755);
        if (ret != 0 && errno == EEXIST) {
            ret = 0;
        }
#endif
    }
    return ret;
}

/* Names must be a single, sane path component. */
static int wt_interop_name_is_sane(char const* name, size_t length)
{
    return (length > 0 && length < WT_INTEROP_NAME_MAX &&
        memchr(name, '/', length) == NULL &&
        picoquic_is_path_sane((const uint8_t*)name, length) == 0);
}

/* Build "dir/endpoint[/name]", with dir defaulting to the current directory. */
static int wt_interop_make_path(char* path, size_t path_max, char const* dir, char const* endpoint, char const* name)
{
    int ret;
    if (dir == NULL || dir[0] == 0) {
        dir = ".";
    }
    if (name == NULL) {
        ret = picoquic_sprintf(path, path_max, NULL, "%s/%s", dir, endpoint);
    }
    else if (endpoint == NULL) {
        ret = picoquic_sprintf(path, path_max, NULL, "%s/%s", dir, name);
    }
    else {
        ret = picoquic_sprintf(path, path_max, NULL, "%s/%s/%s", dir, endpoint, name);
    }
    return ret;
}

wt_interop_test_enum wt_interop_parse_test_case(char const* test_case)
{
    static const struct {
        char const* name;
        wt_interop_test_enum test_id;
    } test_table[] = {
        { "handshake", wt_interop_test_handshake },
        { "transfer", wt_interop_test_transfer },
        { "transfer-unidirectional-receive", wt_interop_test_unidirectional_receive },
        { "transfer-unidirectional-send", wt_interop_test_unidirectional_send },
        { "transfer-bidirectional-receive", wt_interop_test_bidirectional_receive },
        { "transfer-bidirectional-send", wt_interop_test_bidirectional_send },
        { "transfer-datagram-receive", wt_interop_test_datagram_receive },
        { "transfer-datagram-send", wt_interop_test_datagram_send }
    };
    wt_interop_test_enum test_id = wt_interop_test_unknown;

    if (test_case != NULL) {
        for (size_t i = 0; i < sizeof(test_table) / sizeof(test_table[0]); i++) {
            if (strcmp(test_case, test_table[i].name) == 0) {
                test_id = test_table[i].test_id;
                break;
            }
        }
    }
    return test_id;
}

/* Channel used by this side to request files, or none if it only responds. */
static wt_interop_mode_enum wt_interop_request_mode(wt_interop_test_enum test_id, int is_client)
{
    wt_interop_mode_enum mode = wt_interop_mode_none;

    switch (test_id) {
    case wt_interop_test_unidirectional_receive:
        mode = (is_client) ? wt_interop_mode_unidirectional : wt_interop_mode_none;
        break;
    case wt_interop_test_unidirectional_send:
        mode = (is_client) ? wt_interop_mode_none : wt_interop_mode_unidirectional;
        break;
    case wt_interop_test_bidirectional_receive:
        mode = (is_client) ? wt_interop_mode_bidirectional : wt_interop_mode_none;
        break;
    case wt_interop_test_bidirectional_send:
        mode = (is_client) ? wt_interop_mode_none : wt_interop_mode_bidirectional;
        break;
    case wt_interop_test_datagram_receive:
        mode = (is_client) ? wt_interop_mode_datagram : wt_interop_mode_none;
        break;
    case wt_interop_test_datagram_send:
        mode = (is_client) ? wt_interop_mode_none : wt_interop_mode_datagram;
        break;
    default:
        break;
    }
    return mode;
}

int wt_interop_parse_url(char const* url, char* host, size_t host_max, uint16_t* port, char const** path)
{
    int ret = 0;
    char const* h = NULL;
    size_t host_length = 0;
    char const* p = NULL;

    *port = 443;
    *path = NULL;
    if (url == NULL || strncmp(url, "https://", 8) != 0) {
        ret = -1;
    }
    else {
        h = url + 8;
        if (*h == '[') {
            char const* close = strchr(h, ']');
            if (close == NULL) {
                ret = -1;
            }
            else {
                h++;
                host_length = close - h;
                p = close + 1;
            }
        }
        else {
            p = h;
            while (*p != 0 && *p != ':' && *p != '/') {
                p++;
            }
            host_length = p - h;
        }
    }
    if (ret == 0 && (host_length == 0 || host_length >= host_max)) {
        ret = -1;
    }
    if (ret == 0 && *p == ':') {
        unsigned long v = 0;
        p++;
        if (*p < '0' || *p > '9') {
            ret = -1;
        }
        while (ret == 0 && *p >= '0' && *p <= '9') {
            v = v * 10 + (unsigned long)(*p - '0');
            if (v > 0xFFFF) {
                ret = -1;
            }
            p++;
        }
        if (ret == 0 && v == 0) {
            ret = -1;
        }
        *port = (uint16_t)v;
    }
    if (ret == 0 && *p != '/') {
        ret = -1;
    }
    if (ret == 0) {
        memcpy(host, h, host_length);
        host[host_length] = 0;
        *path = p + 1;
    }
    return ret;
}

static int wt_interop_request_exists(wt_interop_param_t const* param, char const* ep, size_t ep_length, char const* file, size_t file_length)
{
    int found = 0;

    for (wt_interop_request_t const* r = param->first_request; !found && r != NULL; r = r->next) {
        found = strlen(r->endpoint) == ep_length && memcmp(r->endpoint, ep, ep_length) == 0 &&
            ((r->file_name == NULL) ? (file_length == 0) :
                (strlen(r->file_name) == file_length && memcmp(r->file_name, file, file_length) == 0));
    }
    return found;
}

/* Split "endpoint[/file]" and add it to the request list, ignoring duplicates. */
static int wt_interop_add_request(wt_interop_param_t* param, char const* path, size_t length)
{
    int ret = 0;
    size_t ep_length = 0;
    char const* file = NULL;
    size_t file_length = 0;
    wt_interop_request_t* request = NULL;

    if (length > 0 && path[0] == '/') {
        path++;
        length--;
    }
    while (ep_length < length && path[ep_length] != '/') {
        ep_length++;
    }
    if (ep_length < length) {
        file = path + ep_length + 1;
        file_length = length - ep_length - 1;
    }
    if (!wt_interop_name_is_sane(path, ep_length) ||
        (file_length > 0 && !wt_interop_name_is_sane(file, file_length))) {
        ret = -1;
    }
    else if (wt_interop_request_exists(param, path, ep_length, file, file_length)) {
        ret = 0;
    }
    else if ((request = (wt_interop_request_t*)malloc(sizeof(wt_interop_request_t))) == NULL) {
        ret = -1;
    }
    else {
        memset(request, 0, sizeof(wt_interop_request_t));
        if ((request->endpoint = wt_interop_strndup(path, ep_length)) == NULL ||
            (file_length > 0 && (request->file_name = wt_interop_strndup(file, file_length)) == NULL)) {
            free(request->endpoint);
            free(request);
            ret = -1;
        }
        else {
            if (param->last_request == NULL) {
                param->first_request = request;
            }
            else {
                param->last_request->next = request;
            }
            param->last_request = request;
            param->nb_requests++;
        }
    }
    return ret;
}

/* Parse one request: a full URL on the client, a path on the server. */
static int wt_interop_parse_one_request(wt_interop_param_t* param, char const* token, size_t length)
{
    int ret = 0;
    char* t = wt_interop_strndup(token, length);

    if (t == NULL) {
        ret = -1;
    }
    else if (param->is_client) {
        char host[256];
        uint16_t port = 0;
        char const* path = NULL;

        if (wt_interop_parse_url(t, host, sizeof(host), &port, &path) != 0) {
            fprintf(stderr, "Cannot parse request URL: %s\n", t);
            ret = -1;
        }
        else if (param->host == NULL) {
            char authority[300];
            int is_ipv6 = (strchr(host, ':') != NULL);
            if (picoquic_sprintf(authority, sizeof(authority), NULL, (is_ipv6) ? "[%s]:%u" : "%s:%u", host, (unsigned int)port) != 0 ||
                (param->host = picoquic_string_duplicate(host)) == NULL ||
                (param->authority = picoquic_string_duplicate(authority)) == NULL) {
                ret = -1;
            }
            param->port = port;
        }
        else if (strcmp(param->host, host) != 0 || param->port != port) {
            fprintf(stderr, "All requests must use the same server, %s differs\n", t);
            ret = -1;
        }
        if (ret == 0) {
            ret = wt_interop_add_request(param, path, strlen(path));
        }
    }
    else {
        ret = wt_interop_add_request(param, t, length);
    }
    if (ret != 0 && t != NULL) {
        fprintf(stderr, "Invalid request: %s\n", t);
    }
    free(t);
    return ret;
}

static int wt_interop_parse_requests(wt_interop_param_t* param, char const* requests)
{
    int ret = 0;
    char const* r = requests;

    while (ret == 0 && r != NULL && *r != 0) {
        size_t length = 0;
        while (*r == ' ' || *r == '\t' || *r == '\n' || *r == '\r') {
            r++;
        }
        while (r[length] != 0 && r[length] != ' ' && r[length] != '\t' && r[length] != '\n' && r[length] != '\r') {
            length++;
        }
        if (length > 0) {
            ret = wt_interop_parse_one_request(param, r, length);
        }
        r += length;
    }
    if (ret == 0 && param->is_client && param->nb_requests > 0) {
        /* The library supports a single web transport session per connection. */
        for (wt_interop_request_t* request = param->first_request->next; request != NULL; request = request->next) {
            if (strcmp(request->endpoint, param->first_request->endpoint) != 0) {
                fprintf(stderr, "Only one endpoint is supported, %s differs from %s\n",
                    request->endpoint, param->first_request->endpoint);
                ret = -1;
                break;
            }
        }
    }
    return ret;
}

/* Parse a list of protocols, separated by spaces or commas, optionally quoted. */
static int wt_interop_parse_protocols(wt_interop_param_t* param, char const* protocols)
{
    int ret = 0;
    size_t total = 0;
    char const* p = protocols;
    char* supported = NULL;
    char* available = NULL;
    size_t s_len = 0;
    size_t a_len = 0;

    if (protocols != NULL) {
        total = strlen(protocols);
    }
    if (total > 0) {
        /* Worst case: each character becomes a quoted protocol with a separator. */
        if ((supported = (char*)malloc(3 * total + 1)) == NULL ||
            (available = (char*)malloc(5 * total + 1)) == NULL) {
            ret = -1;
        }
        while (ret == 0 && *p != 0) {
            size_t length = 0;
            while (*p == ' ' || *p == '\t' || *p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
                p++;
            }
            while (p[length] != 0 && p[length] != ' ' && p[length] != '\t' && p[length] != ',' &&
                p[length] != '"' && p[length] != '\n' && p[length] != '\r') {
                length++;
            }
            if (length > 0) {
                if (s_len > 0) {
                    memcpy(supported + s_len, ", ", 2);
                    s_len += 2;
                    memcpy(available + a_len, ", ", 2);
                    a_len += 2;
                }
                memcpy(supported + s_len, p, length);
                s_len += length;
                available[a_len++] = '"';
                memcpy(available + a_len, p, length);
                a_len += length;
                available[a_len++] = '"';
            }
            p += length;
        }
    }
    if (ret == 0 && s_len > 0) {
        supported[s_len] = 0;
        available[a_len] = 0;
        param->supported_protocols = supported;
        param->available_protocols = available;
    }
    else {
        free(supported);
        free(available);
    }
    return ret;
}

int wt_interop_param_init(wt_interop_param_t* param, int is_client, char const* test_case,
    char const* requests, char const* protocols, char const* www_dir, char const* download_dir)
{
    int ret = 0;

    memset(param, 0, sizeof(wt_interop_param_t));
    param->is_client = is_client;
    param->www_dir = www_dir;
    param->download_dir = download_dir;
    param->test_id = wt_interop_parse_test_case(test_case);

    if (param->test_id == wt_interop_test_unknown) {
        fprintf(stderr, "Unsupported web transport test case: %s\n", (test_case == NULL) ? "(none)" : test_case);
        ret = -1;
    }
    else if (wt_interop_parse_protocols(param, protocols) != 0 ||
        wt_interop_parse_requests(param, requests) != 0) {
        ret = -1;
    }
    else if (is_client && param->nb_requests == 0) {
        fprintf(stderr, "The client needs at least one request URL\n");
        ret = -1;
    }
    if (ret != 0) {
        wt_interop_param_clear(param);
    }
    return ret;
}

int wt_interop_param_from_env(wt_interop_param_t* param, int is_client, char const* www_dir, char const* download_dir)
{
    char* test_case = wt_interop_getenv("TESTCASE");
    char* requests = wt_interop_getenv("REQUESTS");
    char* protocols = wt_interop_getenv("PROTOCOLS");
    int ret = wt_interop_param_init(param, is_client, test_case, requests, protocols, www_dir, download_dir);

    free(test_case);
    free(requests);
    free(protocols);
    return ret;
}

void wt_interop_param_clear(wt_interop_param_t* param)
{
    wt_interop_request_t* request = param->first_request;

    while (request != NULL) {
        wt_interop_request_t* next = request->next;
        free(request->endpoint);
        free(request->file_name);
        free(request);
        request = next;
    }
    free(param->supported_protocols);
    free(param->available_protocols);
    free(param->host);
    free(param->authority);
    memset(param, 0, sizeof(wt_interop_param_t));
}

/* Session level file management */

static FILE* wt_interop_open_download(wt_interop_session_t* session, char const* name)
{
    FILE* F = NULL;
    char path[WT_INTEROP_PATH_MAX];
    char const* dir = session->param->download_dir;

    if (dir != NULL && dir[0] != 0) {
        (void)wt_interop_mkdir(dir);
    }
    if (wt_interop_make_path(path, sizeof(path), dir, session->endpoint, NULL) == 0 &&
        wt_interop_mkdir(path) == 0 &&
        wt_interop_make_path(path, sizeof(path), dir, session->endpoint, name) == 0) {
        F = picoquic_file_open(path, "wb");
    }
    if (F == NULL) {
        picoquic_log_app_message(session->cnx, "Cannot create file %s/%s", session->endpoint, name);
    }
    return F;
}

static FILE* wt_interop_open_www(wt_interop_session_t* session, char const* name, uint64_t* size)
{
    FILE* F = NULL;
    char path[WT_INTEROP_PATH_MAX];

    *size = 0;
    if (wt_interop_make_path(path, sizeof(path), session->param->www_dir, session->endpoint, name) == 0 &&
        (F = picoquic_file_open(path, "rb")) != NULL) {
        long l;
        if (fseek(F, 0, SEEK_END) != 0 || (l = ftell(F)) < 0 || fseek(F, 0, SEEK_SET) != 0) {
            F = picoquic_file_close(F);
        }
        else {
            *size = (uint64_t)l;
        }
    }
    if (F == NULL) {
        picoquic_log_app_message(session->cnx, "Cannot read file %s/%s", session->endpoint, name);
    }
    return F;
}

static void wt_interop_write_negotiated(wt_interop_session_t* session)
{
    char path[WT_INTEROP_PATH_MAX];
    FILE* F = NULL;
    char const* dir = session->param->download_dir;

    if (dir != NULL && dir[0] != 0) {
        (void)wt_interop_mkdir(dir);
    }
    if (wt_interop_make_path(path, sizeof(path), dir, NULL, WT_INTEROP_NEGOTIATED_FILE) == 0 &&
        (F = picoquic_file_open(path, "wb")) != NULL) {
        size_t length = strlen(session->negotiated_protocol);
        if (fwrite(session->negotiated_protocol, 1, length, F) != length) {
            session->nb_errors++;
        }
        (void)picoquic_file_close(F);
    }
    else {
        picoquic_log_app_message(session->cnx, "Cannot write %s", WT_INTEROP_NEGOTIATED_FILE);
        session->nb_errors++;
    }
}

static void wt_interop_set_negotiated(wt_interop_session_t* session, char const* protocol, size_t length)
{
    if (protocol != NULL) {
        if (length >= 2 && protocol[0] == '"' && protocol[length - 1] == '"') {
            protocol++;
            length -= 2;
        }
        if (length >= sizeof(session->negotiated_protocol)) {
            length = sizeof(session->negotiated_protocol) - 1;
        }
        memcpy(session->negotiated_protocol, protocol, length);
        session->negotiated_protocol[length] = 0;
    }
    picoquic_log_app_message(session->cnx, "WT interop session on /%s, protocol: %s", session->endpoint,
        (protocol == NULL) ? "none" : session->negotiated_protocol);
}

/* Record that a requested file was fully received. */
static void wt_interop_file_received(wt_interop_session_t* session, char const* name)
{
    wt_interop_file_t* file = session->first_file;

    while (file != NULL && strcmp(file->name, name) != 0) {
        file = file->next;
    }
    if (file == NULL) {
        picoquic_log_app_message(session->cnx, "Received unrequested file %s", name);
    }
    else if (!file->is_received) {
        file->is_received = 1;
        session->nb_files_received++;
    }
}

static int wt_interop_init_files(wt_interop_session_t* session)
{
    int ret = 0;

    for (wt_interop_request_t* request = session->param->first_request; ret == 0 && request != NULL; request = request->next) {
        if (request->file_name != NULL && strcmp(request->endpoint, session->endpoint) == 0) {
            wt_interop_file_t* file = (wt_interop_file_t*)malloc(sizeof(wt_interop_file_t));
            if (file == NULL || (file->name = picoquic_string_duplicate(request->file_name)) == NULL) {
                free(file);
                ret = -1;
            }
            else {
                file->is_received = 0;
                file->next = session->first_file;
                session->first_file = file;
                session->nb_files++;
            }
        }
    }
    return ret;
}

/* Stream records */

static wt_interop_stream_t* wt_interop_find_stream(wt_interop_session_t* session, uint64_t stream_id)
{
    wt_interop_stream_t* stream = session->first_stream;
    while (stream != NULL && stream->stream_id != stream_id) {
        stream = stream->next;
    }
    return stream;
}

static wt_interop_stream_t* wt_interop_create_stream(wt_interop_session_t* session, uint64_t stream_id)
{
    wt_interop_stream_t* stream = (wt_interop_stream_t*)malloc(sizeof(wt_interop_stream_t));
    if (stream != NULL) {
        memset(stream, 0, sizeof(wt_interop_stream_t));
        stream->stream_id = stream_id;
        stream->next = session->first_stream;
        session->first_stream = stream;
    }
    return stream;
}

static void wt_interop_release(wt_interop_session_t* session)
{
    while (session->first_stream != NULL) {
        wt_interop_stream_t* stream = session->first_stream;
        session->first_stream = stream->next;
        (void)picoquic_file_close(stream->F_receive);
        (void)picoquic_file_close(stream->F_send);
        free(stream->receive_name);
        free(stream);
    }
    while (session->first_datagram != NULL) {
        wt_interop_datagram_t* datagram = session->first_datagram;
        session->first_datagram = datagram->next;
        free(datagram);
    }
    session->last_datagram = NULL;
    while (session->first_file != NULL) {
        wt_interop_file_t* file = session->first_file;
        session->first_file = file->next;
        free(file->name);
        free(file);
    }
    picowt_release_capsule(&session->capsule);
}

void wt_interop_session_free(wt_interop_session_t* session)
{
    if (session != NULL) {
        wt_interop_release(session);
        free(session);
    }
}

/* Session completion */

static int wt_interop_is_requester(wt_interop_session_t const* session)
{
    return session->request_mode != wt_interop_mode_none;
}

static int wt_interop_close_session(wt_interop_session_t* session, uint32_t err)
{
    int ret = 0;
    h3zero_stream_ctx_t* control_stream_ctx = h3zero_find_stream(session->h3_ctx, session->control_stream_id);

    if (control_stream_ctx != NULL && !control_stream_ctx->ps.stream_state.is_fin_sent) {
        ret = picowt_send_close_session_message(session->cnx, control_stream_ctx, err,
            (err == WT_INTEROP_SESSION_ERR_DONE) ? "Done" : "Protocol error");
    }
    return ret;
}

/* Close the session when the requester has everything; the client then closes the connection. */
static int wt_interop_check_done(wt_interop_session_t* session)
{
    int ret = 0;

    if (!session->is_done && session->is_accepted) {
        if (wt_interop_is_requester(session)) {
            /* A server with nothing to request leaves the closing to the client; errors end the test early. */
            session->is_done = ((session->nb_files_received >= session->nb_files &&
                (session->is_client || session->nb_files > 0)) || session->nb_errors > 0);
        }
        else if (session->is_client) {
            session->is_done = (session->param->test_id == wt_interop_test_handshake || session->is_closed);
        }
        if (session->is_done) {
            picoquic_log_app_message(session->cnx, "WT interop session done, %zu files received, %d errors",
                session->nb_files_received, session->nb_errors);
            if (!session->is_closed) {
                ret = wt_interop_close_session(session,
                    (session->nb_errors == 0) ? WT_INTEROP_SESSION_ERR_DONE : WT_INTEROP_SESSION_ERR_PROTOCOL);
            }
            if (session->is_client) {
                ret = picoquic_close(session->cnx, 0);
            }
        }
    }
    return ret;
}

int wt_interop_client_is_success(wt_interop_session_t const* session)
{
    int is_success = 0;
    if (session != NULL && session->is_accepted && session->nb_errors == 0) {
        if (wt_interop_is_requester(session)) {
            is_success = (session->nb_files_received >= session->nb_files);
        }
        else {
            is_success = 1;
        }
    }
    return is_success;
}

/* Requests */

static int wt_interop_request_on_stream(wt_interop_session_t* session, char const* name, int is_bidir)
{
    int ret = 0;
    uint8_t line[WT_INTEROP_LINE_MAX];
    size_t length = 0;
    h3zero_stream_ctx_t* stream_ctx = picowt_create_local_stream(session->cnx, is_bidir, session->h3_ctx, session->control_stream_id);

    if (stream_ctx == NULL ||
        picoquic_sprintf((char*)line, sizeof(line), &length, "GET %s", name) != 0) {
        ret = -1;
    }
    else {
        stream_ctx->path_callback = wt_interop_callback;
        stream_ctx->path_callback_ctx = session;
        if (is_bidir) {
            wt_interop_stream_t* stream = wt_interop_create_stream(session, stream_ctx->stream_id);
            if (stream == NULL || (stream->receive_name = picoquic_string_duplicate(name)) == NULL) {
                ret = -1;
            }
            else {
                stream->is_line_done = 1;
                stream->is_command_done = 1;
                stream->is_body_expected = 1;
            }
        }
        if (ret == 0) {
            ret = picoquic_add_to_stream_with_ctx(session->cnx, stream_ctx->stream_id, line, length, 1, stream_ctx);
            stream_ctx->ps.stream_state.is_fin_sent = 1;
        }
    }
    return ret;
}

static int wt_interop_queue_datagram(wt_interop_session_t* session, uint8_t const* header, size_t header_length, FILE* F, uint64_t size)
{
    int ret = 0;
    wt_interop_datagram_t* datagram = NULL;

    if (header_length + size > WT_INTEROP_DATAGRAM_MAX) {
        picoquic_log_app_message(session->cnx, "Datagram too large, %zu bytes", (size_t)(header_length + size));
        ret = -1;
    }
    else if ((datagram = (wt_interop_datagram_t*)malloc(sizeof(wt_interop_datagram_t))) == NULL) {
        ret = -1;
    }
    else {
        datagram->next = NULL;
        memcpy(datagram->data, header, header_length);
        datagram->length = header_length;
        if (size > 0) {
            if (fread(datagram->data + header_length, 1, (size_t)size, F) != (size_t)size) {
                ret = -1;
                free(datagram);
            }
            else {
                datagram->length += (size_t)size;
            }
        }
        if (ret == 0) {
            if (session->last_datagram == NULL) {
                session->first_datagram = datagram;
            }
            else {
                session->last_datagram->next = datagram;
            }
            session->last_datagram = datagram;
            ret = h3zero_set_datagram_ready(session->cnx, session->control_stream_id);
        }
    }
    return ret;
}

static int wt_interop_start_requests(wt_interop_session_t* session)
{
    int ret = 0;

    for (wt_interop_file_t* file = session->first_file; ret == 0 && file != NULL; file = file->next) {
        switch (session->request_mode) {
        case wt_interop_mode_unidirectional:
            ret = wt_interop_request_on_stream(session, file->name, 0);
            break;
        case wt_interop_mode_bidirectional:
            ret = wt_interop_request_on_stream(session, file->name, 1);
            break;
        case wt_interop_mode_datagram: {
            uint8_t line[WT_INTEROP_LINE_MAX];
            size_t length = 0;
            if (picoquic_sprintf((char*)line, sizeof(line), &length, "GET %s", file->name) != 0) {
                ret = -1;
            }
            else {
                ret = wt_interop_queue_datagram(session, line, length, NULL, 0);
            }
            break;
        }
        default:
            break;
        }
    }
    if (ret == 0) {
        ret = wt_interop_check_done(session);
    }
    return ret;
}

/* Responses */

/* Respond to "GET name": on the same stream if bidir, else on a new unidir stream. */
static int wt_interop_respond_on_stream(wt_interop_session_t* session, h3zero_stream_ctx_t* stream_ctx,
    wt_interop_stream_t* stream, char const* name)
{
    int ret = 0;
    uint64_t size = 0;
    FILE* F = wt_interop_open_www(session, name, &size);

    if (F == NULL) {
        if (WT_INTEROP_IS_BIDIR(stream_ctx->stream_id)) {
            ret = picowt_reset_stream(session->cnx, stream_ctx, WT_INTEROP_STREAM_ERR_NOT_FOUND);
        }
    }
    else if (WT_INTEROP_IS_BIDIR(stream_ctx->stream_id)) {
        stream->F_send = F;
        stream->send_remaining = size;
        stream->is_sending = 1;
        ret = picoquic_mark_active_stream(session->cnx, stream_ctx->stream_id, 1, stream_ctx);
    }
    else {
        h3zero_stream_ctx_t* push_ctx = picowt_create_local_stream(session->cnx, 0, session->h3_ctx, session->control_stream_id);
        wt_interop_stream_t* push_stream = NULL;
        size_t length = 0;

        if (push_ctx == NULL || (push_stream = wt_interop_create_stream(session, push_ctx->stream_id)) == NULL ||
            picoquic_sprintf((char*)push_stream->header, sizeof(push_stream->header), &length, "PUSH %s\n", name) != 0) {
            (void)picoquic_file_close(F);
            ret = -1;
        }
        else {
            push_ctx->path_callback = wt_interop_callback;
            push_ctx->path_callback_ctx = session;
            push_stream->header_length = length;
            push_stream->F_send = F;
            push_stream->send_remaining = size;
            push_stream->is_sending = 1;
            ret = picoquic_mark_active_stream(session->cnx, push_ctx->stream_id, 1, push_ctx);
        }
    }
    return ret;
}

static int wt_interop_respond_datagram(wt_interop_session_t* session, char const* name)
{
    int ret = 0;
    uint64_t size = 0;
    uint8_t line[WT_INTEROP_LINE_MAX];
    size_t length = 0;
    FILE* F = wt_interop_open_www(session, name, &size);

    if (F != NULL) {
        if (picoquic_sprintf((char*)line, sizeof(line), &length, "PUSH %s\n", name) != 0 ||
            wt_interop_queue_datagram(session, line, length, F, size) != 0) {
            session->nb_errors++;
        }
        (void)picoquic_file_close(F);
    }
    return ret;
}

/* Data reception */

/* Parse "GET name" or "PUSH name"; return 1 for GET, 2 for PUSH, 0 if invalid. */
static int wt_interop_parse_command(char* line, size_t length, char const** name)
{
    int command = 0;

    while (length > 0 && (line[length - 1] == '\r' || line[length - 1] == '\n')) {
        length--;
    }
    line[length] = 0;
    if (length > 4 && memcmp(line, "GET ", 4) == 0) {
        command = 1;
        *name = line + 4;
    }
    else if (length > 5 && memcmp(line, "PUSH ", 5) == 0) {
        command = 2;
        *name = line + 5;
    }
    if (command != 0) {
        if (**name == '/') {
            *name += 1;
        }
        if (!wt_interop_name_is_sane(*name, strlen(*name))) {
            command = 0;
        }
    }
    return command;
}

static int wt_interop_write_body(wt_interop_session_t* session, wt_interop_stream_t* stream, const uint8_t* bytes, size_t length)
{
    int ret = 0;

    if (stream->F_receive == NULL && stream->receive_name != NULL) {
        stream->F_receive = wt_interop_open_download(session, stream->receive_name);
        if (stream->F_receive == NULL) {
            /* The caller counts the error and ends the session now, not at the FIN. */
            stream->is_body_expected = 0;
            ret = -1;
        }
    }
    if (ret == 0 && length > 0 && stream->F_receive != NULL && fwrite(bytes, 1, length, stream->F_receive) != length) {
        ret = -1;
    }
    return ret;
}

static int wt_interop_data_stream(wt_interop_session_t* session, h3zero_stream_ctx_t* stream_ctx,
    const uint8_t* bytes, size_t length, int is_fin)
{
    int ret = 0;
    size_t consumed = 0;
    int command = 0;
    char const* name = NULL;
    wt_interop_stream_t* stream = wt_interop_find_stream(session, stream_ctx->stream_id);

    if (stream == NULL) {
        stream = wt_interop_create_stream(session, stream_ctx->stream_id);
    }
    if (stream == NULL) {
        ret = -1;
    }
    else {
        /* Accumulate the command line, up to the first newline or the FIN. */
        while (!stream->is_line_done && consumed < length) {
            if (stream->line_length >= WT_INTEROP_LINE_MAX - 1) {
                ret = -1;
                break;
            }
            stream->line[stream->line_length++] = (char)bytes[consumed];
            stream->is_line_done = (bytes[consumed] == '\n');
            consumed++;
        }
        if (ret == 0 && !stream->is_line_done && is_fin) {
            stream->is_line_done = 1;
        }
        if (ret == 0 && stream->is_line_done && !stream->is_command_done) {
            int has_newline = (stream->line_length > 0 && stream->line[stream->line_length - 1] == '\n');
            stream->is_command_done = 1;
            command = wt_interop_parse_command(stream->line, stream->line_length, &name);
            if (command == 2 && has_newline) {
                if ((stream->receive_name = picoquic_string_duplicate(name)) == NULL) {
                    ret = -1;
                }
                else {
                    stream->is_body_expected = 1;
                }
            }
            else if (command == 1) {
                stream->is_get_pending = 1;
            }
            else {
                ret = -1;
            }
        }
        if (ret == 0 && stream->is_get_pending) {
            if (consumed < length) {
                ret = -1;
            }
            else if (is_fin) {
                /* The line was already validated, parsing again only recovers the name. */
                stream->is_get_pending = 0;
                (void)wt_interop_parse_command(stream->line, strlen(stream->line), &name);
                ret = wt_interop_respond_on_stream(session, stream_ctx, stream, name);
            }
        }
        if (ret == 0 && stream->is_body_expected) {
            ret = wt_interop_write_body(session, stream, bytes + consumed, length - consumed);
            if (ret == 0 && is_fin) {
                stream->F_receive = picoquic_file_close(stream->F_receive);
                stream->is_body_expected = 0;
                wt_interop_file_received(session, stream->receive_name);
                ret = wt_interop_check_done(session);
            }
        }
        if (ret != 0) {
            picoquic_log_app_message(session->cnx, "WT interop protocol error on stream %" PRIu64, stream_ctx->stream_id);
            session->nb_errors++;
            ret = wt_interop_check_done(session);
            if (!session->is_done) {
                ret = wt_interop_close_session(session, WT_INTEROP_SESSION_ERR_PROTOCOL);
            }
        }
    }
    return ret;
}

/* Capsules and FIN on the control stream. May free the session on the server. */
static int wt_interop_control_stream(wt_interop_session_t* session, h3zero_stream_ctx_t* stream_ctx,
    const uint8_t* bytes, size_t length, int is_fin)
{
    int ret = 0;

    if (bytes != NULL && length > 0) {
        ret = picowt_receive_capsule(session->cnx, bytes, bytes + length, &session->capsule);
    }
    if (ret == 0 && is_fin) {
        stream_ctx->ps.stream_state.is_fin_received = 1;
        session->is_closed = 1;
        if (session->is_client) {
            ret = wt_interop_check_done(session);
            if (!session->is_done) {
                ret = picoquic_close(session->cnx, 0);
            }
        }
        else {
            h3zero_delete_stream_prefix(session->cnx, session->h3_ctx, session->control_stream_id);
        }
    }
    return ret;
}

static int wt_interop_stream_data(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length, int is_fin,
    h3zero_stream_ctx_t* stream_ctx, wt_interop_session_t* session)
{
    int ret = 0;

    if (session == NULL) {
        picoquic_log_app_message(cnx, "WT interop data without session on stream %" PRIu64, stream_ctx->stream_id);
        ret = -1;
    }
    else if (stream_ctx->stream_id == session->control_stream_id) {
        ret = wt_interop_control_stream(session, stream_ctx, bytes, length, is_fin);
    }
    else if (stream_ctx->ps.stream_state.control_stream_id == UINT64_MAX) {
        picoquic_log_app_message(cnx, "WT interop data after session close on stream %" PRIu64, stream_ctx->stream_id);
    }
    else {
        ret = wt_interop_data_stream(session, stream_ctx, bytes, length, is_fin);
    }
    return ret;
}

static int wt_interop_provide_data(wt_interop_session_t* session, h3zero_stream_ctx_t* stream_ctx, void* context, size_t space)
{
    int ret = 0;
    wt_interop_stream_t* stream = wt_interop_find_stream(session, stream_ctx->stream_id);

    if (stream == NULL || !stream->is_sending) {
        (void)picoquic_provide_stream_data_buffer(context, 0, 0, 0);
    }
    else {
        size_t header_left = stream->header_length - stream->header_sent;
        uint64_t total = header_left + stream->send_remaining;
        size_t n = (total < (uint64_t)space) ? (size_t)total : space;
        int is_fin = ((uint64_t)n == total);
        uint8_t* buffer = picoquic_provide_stream_data_buffer(context, n, is_fin, !is_fin);

        if (buffer == NULL && n > 0) {
            ret = -1;
        }
        else if (n > 0) {
            size_t h = (header_left < n) ? header_left : n;
            size_t k = n - h;
            if (h > 0) {
                memcpy(buffer, stream->header + stream->header_sent, h);
                stream->header_sent += h;
            }
            if (k > 0 && fread(buffer + h, 1, k, stream->F_send) != k) {
                memset(buffer + h, 0, k);
                session->nb_errors++;
            }
            stream->send_remaining -= k;
        }
        if (is_fin) {
            stream->F_send = picoquic_file_close(stream->F_send);
            stream->is_sending = 0;
            stream_ctx->ps.stream_state.is_fin_sent = 1;
        }
    }
    return ret;
}

/* Datagrams */

static int wt_interop_receive_datagram(wt_interop_session_t* session, const uint8_t* bytes, size_t length)
{
    int ret = 0;
    char line[WT_INTEROP_LINE_MAX];
    size_t line_length = 0;
    char const* name = NULL;
    int command;
    int has_newline;

    while (line_length < length && line_length < WT_INTEROP_LINE_MAX - 1 && bytes[line_length] != '\n') {
        line[line_length] = (char)bytes[line_length];
        line_length++;
    }
    has_newline = (line_length < length && bytes[line_length] == '\n');
    command = wt_interop_parse_command(line, line_length, &name);
    if (command == 1 && (line_length == length || (has_newline && line_length + 1 == length))) {
        ret = wt_interop_respond_datagram(session, name);
    }
    else if (command == 2 && has_newline) {
        wt_interop_file_t* file = session->first_file;
        while (file != NULL && strcmp(file->name, name) != 0) {
            file = file->next;
        }
        if (file != NULL && !file->is_received) {
            FILE* F = wt_interop_open_download(session, name);
            size_t body_length = length - line_length - 1;
            if (F == NULL || fwrite(bytes + line_length + 1, 1, body_length, F) != body_length) {
                session->nb_errors++;
            }
            (void)picoquic_file_close(F);
            wt_interop_file_received(session, name);
            ret = wt_interop_check_done(session);
        }
    }
    else {
        picoquic_log_app_message(session->cnx, "Invalid WT interop datagram, %zu bytes", length);
    }
    return ret;
}

static int wt_interop_provide_datagram(wt_interop_session_t* session, void* context, size_t space)
{
    int ret = 0;
    wt_interop_datagram_t* datagram = session->first_datagram;

    if (datagram == NULL) {
        (void)h3zero_provide_datagram_buffer(context, 0, 0);
    }
    else if (datagram->length > space) {
        (void)h3zero_provide_datagram_buffer(context, 0, 1);
    }
    else {
        uint8_t* buffer = h3zero_provide_datagram_buffer(context, datagram->length, datagram->next != NULL);
        if (buffer == NULL) {
            ret = -1;
        }
        else {
            memcpy(buffer, datagram->data, datagram->length);
            session->first_datagram = datagram->next;
            if (session->first_datagram == NULL) {
                session->last_datagram = NULL;
            }
            free(datagram);
        }
    }
    return ret;
}

/* Session set up */

static wt_interop_session_t* wt_interop_session_create(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* h3_ctx,
    wt_interop_param_t const* param, int is_client, char const* endpoint, size_t endpoint_length)
{
    wt_interop_session_t* session = (wt_interop_session_t*)malloc(sizeof(wt_interop_session_t));

    if (session != NULL) {
        memset(session, 0, sizeof(wt_interop_session_t));
        session->cnx = cnx;
        session->h3_ctx = h3_ctx;
        session->param = param;
        session->is_client = is_client;
        session->control_stream_id = UINT64_MAX;
        session->request_mode = wt_interop_request_mode(param->test_id, is_client);
        memcpy(session->endpoint, endpoint, endpoint_length);
        session->endpoint[endpoint_length] = 0;
        if (wt_interop_init_files(session) != 0) {
            wt_interop_session_free(session);
            session = NULL;
        }
    }
    return session;
}

/* Accept the session if www_dir has the endpoint, or if REQUESTS mentions it. */
static int wt_interop_endpoint_is_known(wt_interop_param_t const* param, char const* endpoint)
{
    int is_known = 0;
    char path[WT_INTEROP_PATH_MAX];

    for (wt_interop_request_t* request = param->first_request; request != NULL; request = request->next) {
        if (strcmp(request->endpoint, endpoint) == 0) {
            is_known = 1;
            break;
        }
    }
    if (!is_known && wt_interop_make_path(path, sizeof(path), param->www_dir, endpoint, NULL) == 0) {
        is_known = wt_interop_is_dir(path);
    }
    return is_known;
}

static int wt_interop_accept(picoquic_cnx_t* cnx, const uint8_t* path, size_t path_length,
    h3zero_stream_ctx_t* stream_ctx, wt_interop_param_t const* param)
{
    int ret = 0;
    h3zero_callback_ctx_t* h3_ctx = (h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx);
    wt_interop_session_t* session = NULL;
    size_t ep_length = 0;
    char endpoint[WT_INTEROP_NAME_MAX];

    if (path_length > 0 && path[0] == '/') {
        path++;
        path_length--;
    }
    while (ep_length < path_length && path[ep_length] != '/' && path[ep_length] != '?') {
        ep_length++;
    }
    if (param == NULL || h3_ctx == NULL || !picowt_is_webtransport_connect(stream_ctx) ||
        !wt_interop_name_is_sane((char const*)path, ep_length)) {
        ret = -1;
    }
    else {
        memcpy(endpoint, path, ep_length);
        endpoint[ep_length] = 0;
        if (!wt_interop_endpoint_is_known(param, endpoint)) {
            picoquic_log_app_message(cnx, "WT interop: unknown endpoint /%s", endpoint);
            ret = -1;
        }
        else if ((session = wt_interop_session_create(cnx, h3_ctx, param, 0, endpoint, ep_length)) == NULL) {
            ret = -1;
        }
    }
    if (ret == 0) {
        session->control_stream_id = stream_ctx->stream_id;
        stream_ctx->ps.stream_state.control_stream_id = stream_ctx->stream_id;
        ret = h3zero_declare_stream_prefix(h3_ctx, stream_ctx->stream_id, wt_interop_callback, session);
        if (ret != 0) {
            wt_interop_session_free(session);
            session = NULL;
        }
    }
    if (ret == 0) {
        stream_ctx->path_callback = wt_interop_callback;
        stream_ctx->path_callback_ctx = session;
        session->is_accepted = 1;
        if (param->supported_protocols != NULL &&
            picowt_select_wt_protocol(stream_ctx, param->supported_protocols) == 0) {
            wt_interop_set_negotiated(session, stream_ctx->ps.stream_state.wt_protocol, strlen(stream_ctx->ps.stream_state.wt_protocol));
        }
        else {
            wt_interop_set_negotiated(session, NULL, 0);
        }
        if (param->test_id == wt_interop_test_handshake) {
            wt_interop_write_negotiated(session);
        }
        ret = wt_interop_start_requests(session);
        if (ret != 0 && picowt_abort_registration(cnx, h3_ctx, stream_ctx)) {
            wt_interop_session_free(session);
        }
    }
    return ret;
}

static void wt_interop_connect_accepted(wt_interop_session_t* session, h3zero_stream_ctx_t* stream_ctx)
{
    session->is_accepted = 1;
    wt_interop_set_negotiated(session, (char const*)stream_ctx->ps.stream_state.header.wt_protocol,
        stream_ctx->ps.stream_state.header.wt_protocol_length);
    if (session->param->test_id == wt_interop_test_handshake) {
        wt_interop_write_negotiated(session);
    }
    if (wt_interop_start_requests(session) != 0) {
        session->nb_errors++;
        (void)wt_interop_close_session(session, WT_INTEROP_SESSION_ERR_PROTOCOL);
        (void)picoquic_close(session->cnx, 0);
    }
}

static int wt_interop_stream_abandoned(wt_interop_session_t* session, h3zero_stream_ctx_t* stream_ctx)
{
    int ret = 0;

    if (stream_ctx->stream_id == session->control_stream_id) {
        ret = wt_interop_control_stream(session, stream_ctx, NULL, 0, 1);
    }
    else {
        wt_interop_stream_t* stream = wt_interop_find_stream(session, stream_ctx->stream_id);
        if (stream != NULL) {
            int was_expected = stream->is_body_expected;
            stream->is_body_expected = 0;
            stream->F_receive = picoquic_file_close(stream->F_receive);
            stream->F_send = picoquic_file_close(stream->F_send);
            stream->is_sending = 0;
            if (was_expected) {
                picoquic_log_app_message(session->cnx, "WT interop transfer of %s abandoned", stream->receive_name);
                session->nb_errors++;
                ret = wt_interop_check_done(session);
            }
        }
    }
    return ret;
}

static void wt_interop_deregister(picoquic_cnx_t* cnx, h3zero_stream_ctx_t* control_stream_ctx, wt_interop_session_t* session)
{
    picowt_deregister(cnx, session->h3_ctx, control_stream_ctx);
    wt_interop_release(session);
    session->is_deregistered = 1;
    if (!session->is_client) {
        free(session);
    }
}

int wt_interop_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t wt_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    wt_interop_session_t* session = (wt_interop_session_t*)path_app_ctx;

    switch (wt_event) {
    case picohttp_callback_connecting:
        session->control_stream_id = stream_ctx->stream_id;
        break;
    case picohttp_callback_connect_refused:
        picoquic_log_app_message(cnx, "WT interop session refused, status %d", stream_ctx->ps.stream_state.header.status);
        picowt_uncount_session((h3zero_callback_ctx_t*)picoquic_get_callback_context(cnx), stream_ctx);
        session->is_refused = 1;
        ret = picoquic_close(cnx, 0);
        break;
    case picohttp_callback_connect_accepted:
        wt_interop_connect_accepted(session, stream_ctx);
        break;
    case picohttp_callback_post_data:
    case picohttp_callback_post_fin:
        ret = wt_interop_stream_data(cnx, bytes, length, (wt_event == picohttp_callback_post_fin), stream_ctx, session);
        break;
    case picohttp_callback_provide_data:
        ret = wt_interop_provide_data(session, stream_ctx, bytes, length);
        break;
    case picohttp_callback_post_datagram:
        ret = wt_interop_receive_datagram(session, bytes, length);
        break;
    case picohttp_callback_provide_datagram:
        ret = wt_interop_provide_datagram(session, bytes, length);
        break;
    case picohttp_callback_reset:
    case picohttp_callback_stop_sending:
        ret = wt_interop_stream_abandoned(session, stream_ctx);
        break;
    case picohttp_callback_drain:
        break;
    case picohttp_callback_free:
        break;
    case picohttp_callback_deregister:
        wt_interop_deregister(cnx, stream_ctx, session);
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

/* Path table callback, whose context is the parameters: once a CONNECT is accepted, wt_interop_callback handles the session. */
static int wt_interop_server_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t wt_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;

    switch (wt_event) {
    case picohttp_callback_connect:
        ret = wt_interop_accept(cnx, bytes, length, stream_ctx, (wt_interop_param_t const*)path_app_ctx);
        break;
    case picohttp_callback_post:
    case picohttp_callback_post_data:
    case picohttp_callback_post_fin:
        /* The wildcard also matches POST requests: ignore the data and send an empty response. */
        break;
    case picohttp_callback_free:
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

void wt_interop_set_path_item(picohttp_server_path_item_t* item, wt_interop_param_t* param)
{
    memset(item, 0, sizeof(picohttp_server_path_item_t));
    item->path = "*";
    item->path_length = 1;
    item->path_callback = wt_interop_server_callback;
    item->path_app_ctx = param;
    item->connect_protocol = H3ZERO_WEBTRANSPORT_H3_PROTOCOL;
    item->connect_protocol_length = sizeof(H3ZERO_WEBTRANSPORT_H3_PROTOCOL) - 1;
    item->origin_validator = h3zero_origin_validator_allow_all;
}

/* Client */

int wt_interop_client_prepare(picoquic_quic_t* quic, struct sockaddr* server_address, uint64_t current_time,
    char const* sni, wt_interop_param_t const* param, picoquic_cnx_t** p_cnx, h3zero_callback_ctx_t** p_h3_ctx,
    wt_interop_session_t** p_session)
{
    int ret = 0;
    h3zero_stream_ctx_t* control_stream_ctx = NULL;
    char path[WT_INTEROP_NAME_MAX + 2];
    char const* endpoint = (param->first_request == NULL) ? NULL : param->first_request->endpoint;

    *p_session = NULL;
    if (endpoint == NULL || picoquic_sprintf(path, sizeof(path), NULL, "/%s", endpoint) != 0) {
        ret = -1;
    }
    else if (picowt_prepare_client_cnx(quic, server_address, p_cnx, p_h3_ctx, &control_stream_ctx, current_time, sni) != 0) {
        ret = -1;
    }
    else if ((*p_session = wt_interop_session_create(*p_cnx, *p_h3_ctx, param, 1, endpoint, strlen(endpoint))) == NULL) {
        ret = -1;
    }
    else {
        (*p_session)->control_stream_id = control_stream_ctx->stream_id;
        ret = picowt_connect(*p_cnx, *p_h3_ctx, control_stream_ctx, param->authority, path,
            wt_interop_callback, *p_session, param->available_protocols);
        if (ret != 0) {
            wt_interop_session_free(*p_session);
            *p_session = NULL;
        }
    }
    return ret;
}

static int wt_interop_client_loop_cb(picoquic_quic_t* UNUSED(quic), picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void* UNUSED(callback_arg))
{
    int ret = 0;
    wt_interop_session_t* session = (wt_interop_session_t*)callback_ctx;

#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
    UNREFERENCED_PARAMETER(callback_arg);
#endif
    switch (cb_mode) {
    case picoquic_packet_loop_ready:
    case picoquic_packet_loop_port_update:
        break;
    case picoquic_packet_loop_after_receive:
    case picoquic_packet_loop_after_send:
        if (picoquic_get_cnx_state(session->cnx) == picoquic_state_disconnected) {
            ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
        }
        break;
    default:
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
        break;
    }
    return ret;
}

int wt_interop_client(picoquic_quic_config_t* config, wt_interop_param_t const* param)
{
    int ret = 0;
    struct sockaddr_storage server_address = { 0 };
    char const* sni = "test";
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    wt_interop_session_t* session = NULL;
    uint64_t current_time = picoquic_current_time();
    int is_name = 0;

    if (param->host == NULL) {
        ret = -1;
    }
    else if ((ret = picoquic_get_server_address(param->host, param->port, &server_address, &is_name)) != 0) {
        fprintf(stderr, "Cannot get the IP address for <%s> port <%d>\n", param->host, (int)param->port);
    }
    else {
        if (is_name) {
            sni = param->host;
        }
        if ((quic = picoquic_create_and_configure(config, NULL, NULL, current_time, NULL)) == NULL) {
            fprintf(stderr, "Cannot create the QUIC context\n");
            ret = -1;
        }
    }
    if (ret == 0) {
        picoquic_set_key_log_file_from_env(quic);
        if (config->qlog_dir != NULL) {
            picoquic_set_qlog(quic, config->qlog_dir);
        }
        ret = wt_interop_client_prepare(quic, (struct sockaddr*)&server_address, current_time, sni, param,
            &cnx, &h3_ctx, &session);
        if (ret != 0) {
            fprintf(stderr, "Cannot prepare the web transport session\n");
        }
    }
    if (ret == 0 && (ret = picoquic_start_client_cnx(cnx)) != 0) {
        fprintf(stderr, "Cannot start the connection\n");
    }
    if (ret == 0) {
        ret = picoquic_packet_loop(quic, 0, server_address.ss_family, 0, 0, 0, wt_interop_client_loop_cb, session);
        if (ret == PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP) {
            ret = 0;
        }
    }
    if (session != NULL) {
        printf("WT interop session /%s: accepted %d, protocol <%s>, files %zu/%zu, errors %d\n",
            session->endpoint, session->is_accepted, session->negotiated_protocol,
            session->nb_files_received, session->nb_files, session->nb_errors);
        if (ret == 0 && !wt_interop_client_is_success(session)) {
            ret = -1;
        }
    }
    if (h3_ctx != NULL) {
        h3zero_callback_delete_context(cnx, h3_ctx);
    }
    wt_interop_session_free(session);
    if (quic != NULL) {
        picoquic_free(quic);
    }
    return ret;
}
