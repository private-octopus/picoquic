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

/* Tests of the web transport interop protocol, see picohttp/wt_interop.c.
 * Each transfer test mirrors one of the runner's test cases, with the same
 * TESTCASE values on each side, smaller files, and a simulated link.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "demoserver.h"
#include "pico_webtransport.h"
#include "wt_interop.h"

#ifdef _WINDOWS
#include "wincompat.h"
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define WT_INTEROP_TEST_ENDPOINT "wtep"
#define WT_INTEROP_TEST_URL "https://test.example.com:4443/"

static void wt_interop_test_mkdir(char const* dir_path)
{
#ifdef _WINDOWS
    (void)_mkdir(dir_path);
#else
    (void)mkdir(dir_path, 0777);
#endif
}

static int wt_interop_test_create_file(char const* path, size_t length, uint64_t* random_ctx)
{
    int ret = 0;
    FILE* F = picoquic_file_open(path, "wb");

    if (F == NULL) {
        ret = -1;
    }
    else {
        for (size_t i = 0; ret == 0 && i < length; i++) {
            uint8_t b = (uint8_t)(picoquic_test_random(random_ctx) & 0xFF);
            if (fwrite(&b, 1, 1, F) != 1) {
                ret = -1;
            }
        }
        (void)picoquic_file_close(F);
    }
    return ret;
}

static int wt_interop_test_read_text(char const* path, char* text, size_t text_max)
{
    int ret = 0;
    size_t length = 0;
    FILE* F = picoquic_file_open(path, "rb");

    if (F == NULL) {
        ret = -1;
    }
    else {
        length = fread(text, 1, text_max - 1, F);
        text[length] = 0;
        (void)picoquic_file_close(F);
    }
    return ret;
}

/* Parsing of URLs, test cases, protocols and requests. */
int wt_interop_url_test(void)
{
    int ret = 0;
    char host[64];
    uint16_t port = 0;
    char const* path = NULL;
    wt_interop_param_t param;
    static const struct {
        char const* url;
        int expected_ret;
        char const* host;
        uint16_t port;
        char const* path;
    } url_cases[] = {
        { "https://server4:443/ep/file1.txt", 0, "server4", 443, "ep/file1.txt" },
        { "https://server4/ep/", 0, "server4", 443, "ep/" },
        { "https://[2001:db8::1]:4433/ep", 0, "2001:db8::1", 4433, "ep" },
        { "https://10.0.0.1:8443/ep", 0, "10.0.0.1", 8443, "ep" },
        { "http://server4/ep", -1, NULL, 0, NULL },
        { "https://server4:0/ep", -1, NULL, 0, NULL },
        { "https://server4:70000/ep", -1, NULL, 0, NULL },
        { "https://server4:44x/ep", -1, NULL, 0, NULL },
        { "https://server4", -1, NULL, 0, NULL },
        { "https:///ep", -1, NULL, 0, NULL },
        { "https://[::1/ep", -1, NULL, 0, NULL }
    };

    for (size_t i = 0; ret == 0 && i < sizeof(url_cases) / sizeof(url_cases[0]); i++) {
        int r = wt_interop_parse_url(url_cases[i].url, host, sizeof(host), &port, &path);
        if ((r == 0) != (url_cases[i].expected_ret == 0) ||
            (r == 0 && (strcmp(host, url_cases[i].host) != 0 || port != url_cases[i].port ||
                strcmp(path, url_cases[i].path) != 0))) {
            DBG_PRINTF("URL case %zu (%s) failed", i, url_cases[i].url);
            ret = -1;
        }
    }

    if (ret == 0 && (wt_interop_parse_test_case("transfer-datagram-send") != wt_interop_test_datagram_send ||
        wt_interop_parse_test_case("handshake") != wt_interop_test_handshake ||
        wt_interop_parse_test_case("zerortt") != wt_interop_test_unknown ||
        wt_interop_parse_test_case(NULL) != wt_interop_test_unknown)) {
        DBG_PRINTF("%s", "Test case parsing failed");
        ret = -1;
    }

    /* Client with two files on one endpoint, and quoted protocols. */
    if (ret == 0) {
        if (wt_interop_param_init(&param, 1, "transfer-unidirectional-receive",
            " https://server4:443/ep1/f1  https://server4:443/ep1/f2\n", "\"a\" \"bb\"", NULL, NULL) != 0) {
            DBG_PRINTF("%s", "Valid client parameters rejected");
            ret = -1;
        }
        else {
            if (param.nb_requests != 2 || param.port != 443 || strcmp(param.host, "server4") != 0 ||
                strcmp(param.authority, "server4:443") != 0 ||
                strcmp(param.first_request->endpoint, "ep1") != 0 ||
                strcmp(param.first_request->file_name, "f1") != 0 ||
                strcmp(param.supported_protocols, "a, bb") != 0 ||
                strcmp(param.available_protocols, "\"a\", \"bb\"") != 0) {
                DBG_PRINTF("%s", "Client parameters not parsed as expected");
                ret = -1;
            }
            wt_interop_param_clear(&param);
        }
    }

    /* Server with paths, and session only client URL. */
    if (ret == 0) {
        if (wt_interop_param_init(&param, 0, "transfer-datagram-send", "ep/f1 /ep/f2", "x", NULL, NULL) != 0 ||
            param.nb_requests != 2 || param.host != NULL || strcmp(param.last_request->file_name, "f2") != 0) {
            DBG_PRINTF("%s", "Server parameters not parsed as expected");
            ret = -1;
        }
        wt_interop_param_clear(&param);
    }
    if (ret == 0) {
        if (wt_interop_param_init(&param, 1, "handshake", "https://[::1]:443/ep/", NULL, NULL, NULL) != 0 ||
            param.first_request->file_name != NULL || strcmp(param.authority, "[::1]:443") != 0 ||
            param.supported_protocols != NULL) {
            DBG_PRINTF("%s", "Session only client parameters not parsed as expected");
            ret = -1;
        }
        wt_interop_param_clear(&param);
    }

    /* Duplicate requests are merged, so the client asks for each file once. */
    if (ret == 0) {
        if (wt_interop_param_init(&param, 1, "transfer-unidirectional-receive",
            "https://s/ep/f1 https://s/ep/f2 https://s/ep/f1", NULL, NULL, NULL) != 0 ||
            param.nb_requests != 2) {
            DBG_PRINTF("%s", "Duplicate client requests not merged");
            ret = -1;
        }
        wt_interop_param_clear(&param);
    }
    if (ret == 0) {
        if (wt_interop_param_init(&param, 0, "transfer-datagram-send", "ep/f1 /ep/f1", NULL, NULL, NULL) != 0 ||
            param.nb_requests != 1) {
            DBG_PRINTF("%s", "Duplicate server requests not merged");
            ret = -1;
        }
        wt_interop_param_clear(&param);
    }

    /* Invalid combinations must be rejected. */
    if (ret == 0) {
        static const struct {
            int is_client;
            char const* test_case;
            char const* requests;
        } bad_cases[] = {
            { 1, "transfer", "https://a/ep/f1 https://b/ep/f2" },
            { 1, "transfer", "https://a/ep1/f1 https://a/ep2/f2" },
            { 1, "transfer", "https://a:444/ep/f1 https://a/ep/f2" },
            { 1, "transfer", "" },
            { 1, "transfer", "https://a/../f1" },
            { 0, "transfer", "ep/../f1" },
            { 1, "retry", "https://a/ep/f1" }
        };
        for (size_t i = 0; ret == 0 && i < sizeof(bad_cases) / sizeof(bad_cases[0]); i++) {
            if (wt_interop_param_init(&param, bad_cases[i].is_client, bad_cases[i].test_case,
                bad_cases[i].requests, NULL, NULL, NULL) == 0) {
                DBG_PRINTF("Bad case %zu was accepted", i);
                wt_interop_param_clear(&param);
                ret = -1;
            }
        }
    }
    return ret;
}

/* The wildcard path item also receives POST events, whose context is the parameters, not a session. */
int wt_interop_wildcard_post_test(void)
{
    int ret = 0;
    wt_interop_param_t param;
    picohttp_server_path_item_t item;
    h3zero_stream_ctx_t stream_ctx;
    uint8_t buffer[64];

    memset(&stream_ctx, 0, sizeof(stream_ctx));
    stream_ctx.stream_id = 4;
    if (wt_interop_param_init(&param, 0, "transfer", NULL, NULL, NULL, NULL) != 0) {
        ret = -1;
    }
    else {
        wt_interop_set_path_item(&item, &param);
        if (item.path_callback == wt_interop_callback) {
            DBG_PRINTF("%s", "The path item must not use the session callback");
            ret = -1;
        }
        else if (item.path_callback(NULL, (uint8_t*)"/x", 2, picohttp_callback_post, &stream_ctx, item.path_app_ctx) != 0 ||
            item.path_callback(NULL, buffer, sizeof(buffer), picohttp_callback_post_data, &stream_ctx, item.path_app_ctx) != 0 ||
            item.path_callback(NULL, buffer, sizeof(buffer), picohttp_callback_post_fin, &stream_ctx, item.path_app_ctx) != 0) {
            DBG_PRINTF("%s", "POST events not ignored by the wildcard path item");
            ret = -1;
        }
        else if (item.path_callback(NULL, buffer, sizeof(buffer), picohttp_callback_provide_data, &stream_ctx, item.path_app_ctx) == 0 ||
            item.path_callback(NULL, buffer, sizeof(buffer), picohttp_callback_post_datagram, &stream_ctx, item.path_app_ctx) == 0) {
            DBG_PRINTF("%s", "Session events accepted by the wildcard path item");
            ret = -1;
        }
        wt_interop_param_clear(&param);
    }
    return ret;
}

typedef struct st_wt_interop_test_spec_t {
    char const* name;
    char const* client_test_case;
    char const* server_test_case;
    int is_send;
    int is_handshake;
    size_t nb_files;
    size_t const* sizes;
    size_t size_base;
    int add_missing;
    int block_download;
} wt_interop_test_spec_t;

/* Build the request lists, create source files, and remove stale downloads. */
static int wt_interop_test_prepare_files(wt_interop_test_spec_t const* spec, char const* source_www,
    char const* destination, char* client_requests, size_t client_max, char* server_requests, size_t server_max)
{
    int ret = 0;
    char path[512];
    size_t c_len = 0;
    size_t s_len = 0;
    uint64_t random_ctx = 0x123456789abcdefull;

    client_requests[0] = 0;
    server_requests[0] = 0;
    if (picoquic_sprintf(path, sizeof(path), NULL, "%s/%s", source_www, WT_INTEROP_TEST_ENDPOINT) != 0) {
        ret = -1;
    }
    else {
        wt_interop_test_mkdir(source_www);
        wt_interop_test_mkdir(path);
    }
    if (ret == 0 && (spec->is_send || spec->nb_files == 0)) {
        ret = picoquic_sprintf(client_requests, client_max, &c_len, "%s%s", WT_INTEROP_TEST_URL, WT_INTEROP_TEST_ENDPOINT);
    }
    for (size_t i = 0; ret == 0 && i < spec->nb_files; i++) {
        char file_name[64];
        size_t length = 0;
        size_t size = (spec->sizes != NULL) ? spec->sizes[i] : spec->size_base + 2 * i;

        if (picoquic_sprintf(file_name, sizeof(file_name), NULL, "file%zu.bin", i) != 0 ||
            picoquic_sprintf(path, sizeof(path), NULL, "%s/%s/%s", source_www, WT_INTEROP_TEST_ENDPOINT, file_name) != 0 ||
            wt_interop_test_create_file(path, size, &random_ctx) != 0 ||
            picoquic_sprintf(path, sizeof(path), NULL, "%s/%s/%s", destination, WT_INTEROP_TEST_ENDPOINT, file_name) != 0) {
            ret = -1;
        }
        else {
            (void)picoquic_file_delete(path, NULL);
            if (spec->is_send) {
                ret = picoquic_sprintf(server_requests + s_len, server_max - s_len, &length, "%s%s/%s",
                    (s_len > 0) ? " " : "", WT_INTEROP_TEST_ENDPOINT, file_name);
                s_len += length;
            }
            else {
                ret = picoquic_sprintf(client_requests + c_len, client_max - c_len, &length, "%s%s%s/%s",
                    (c_len > 0) ? " " : "", WT_INTEROP_TEST_URL, WT_INTEROP_TEST_ENDPOINT, file_name);
                c_len += length;
            }
        }
    }
    if (ret == 0 && spec->add_missing) {
        ret = picoquic_sprintf(client_requests + c_len, client_max - c_len, NULL, " %s%s/nofile.bin",
            WT_INTEROP_TEST_URL, WT_INTEROP_TEST_ENDPOINT);
    }
    return ret;
}

static int wt_interop_test_check_files(wt_interop_test_spec_t const* spec, char const* source_www, char const* destination)
{
    int ret = 0;
    char source[512];
    char received[512];

    for (size_t i = 0; ret == 0 && i < spec->nb_files; i++) {
        if (picoquic_sprintf(source, sizeof(source), NULL, "%s/%s/file%zu.bin", source_www, WT_INTEROP_TEST_ENDPOINT, i) != 0 ||
            picoquic_sprintf(received, sizeof(received), NULL, "%s/%s/file%zu.bin", destination, WT_INTEROP_TEST_ENDPOINT, i) != 0 ||
            picoquic_test_compare_binary_files(source, received) != 0) {
            DBG_PRINTF("File %s does not match %s", received, source);
            ret = -1;
        }
    }
    return ret;
}

static int wt_interop_test_check_negotiated(char const* dir, char const* expected)
{
    int ret = 0;
    char path[512];
    char text[256];

    if (picoquic_sprintf(path, sizeof(path), NULL, "%s/%s", dir, WT_INTEROP_NEGOTIATED_FILE) != 0 ||
        wt_interop_test_read_text(path, text, sizeof(text)) != 0 ||
        strcmp(text, expected) != 0) {
        DBG_PRINTF("Negotiated protocol in %s is not %s", dir, expected);
        ret = -1;
    }
    return ret;
}

static int wt_interop_test_one(wt_interop_test_spec_t const* spec, uint8_t test_id)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    int ret = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x77, 0x74, 0x1e, 0, 0, 0, 0, 0}, 8 };
    picohttp_server_parameters_t server_param = { 0 };
    picohttp_server_path_item_t path_item;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    wt_interop_session_t* session = NULL;
    wt_interop_param_t client_param = { 0 };
    wt_interop_param_t server_param_wt = { 0 };
    char client_requests[2048];
    char server_requests[2048];
    char dir_s_www[64];
    char dir_s_dl[64];
    char dir_c_www[64];
    char dir_c_dl[64];
    char const* protocols_c = (spec->is_handshake) ? "p1 p2 p3" : "wtip";
    char const* protocols_s = (spec->is_handshake) ? "p0 p3 p2" : "wtip";

    initial_cid.id[3] = test_id;
    if (picoquic_sprintf(dir_s_www, sizeof(dir_s_www), NULL, "wti_%s_s_www", spec->name) != 0 ||
        picoquic_sprintf(dir_s_dl, sizeof(dir_s_dl), NULL, "wti_%s_s_dl", spec->name) != 0 ||
        picoquic_sprintf(dir_c_www, sizeof(dir_c_www), NULL, "wti_%s_c_www", spec->name) != 0 ||
        picoquic_sprintf(dir_c_dl, sizeof(dir_c_dl), NULL, "wti_%s_c_dl", spec->name) != 0) {
        ret = -1;
    }
    else {
        char negotiated[128];
        wt_interop_test_mkdir(dir_s_dl);
        wt_interop_test_mkdir(dir_c_dl);
        wt_interop_test_mkdir(dir_c_www);
        if (picoquic_sprintf(negotiated, sizeof(negotiated), NULL, "%s/%s", dir_c_dl, WT_INTEROP_NEGOTIATED_FILE) == 0) {
            (void)picoquic_file_delete(negotiated, NULL);
        }
        if (picoquic_sprintf(negotiated, sizeof(negotiated), NULL, "%s/%s", dir_s_dl, WT_INTEROP_NEGOTIATED_FILE) == 0) {
            (void)picoquic_file_delete(negotiated, NULL);
        }
        ret = wt_interop_test_prepare_files(spec, (spec->is_send) ? dir_c_www : dir_s_www,
            (spec->is_send) ? dir_s_dl : dir_c_dl, client_requests, sizeof(client_requests),
            server_requests, sizeof(server_requests));
    }
    if (ret == 0 && spec->block_download) {
        /* A plain file where the endpoint directory should be makes every download open fail. */
        char blocker[128];
        FILE* F = NULL;
        if (picoquic_sprintf(blocker, sizeof(blocker), NULL, "%s/%s", dir_c_dl, WT_INTEROP_TEST_ENDPOINT) != 0 ||
            (F = picoquic_file_open(blocker, "w")) == NULL) {
            DBG_PRINTF("%s", "Cannot create the download blocker");
            ret = -1;
        }
        (void)picoquic_file_close(F);
    }

    if (ret == 0 &&
        (wt_interop_param_init(&client_param, 1, spec->client_test_case, client_requests, protocols_c, dir_c_www, dir_c_dl) != 0 ||
        wt_interop_param_init(&server_param_wt, 0, spec->server_test_case, server_requests, protocols_s, dir_s_www, dir_s_dl) != 0)) {
        DBG_PRINTF("%s", "Cannot initialize the interop parameters");
        ret = -1;
    }

    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, "h3", &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
        if (ret != 0 || test_ctx == NULL || test_ctx->cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create the QUIC test contexts");
            ret = -1;
        }
    }

    if (ret == 0) {
        picowt_set_default_transport_parameters(test_ctx->qserver);
        wt_interop_set_path_item(&path_item, &server_param_wt);
        server_param.path_table = &path_item;
        server_param.path_table_nb = 1;
        picoquic_set_alpn_select_fn_v2(test_ctx->qserver, picoquic_demo_server_callback_select_alpn);
        picoquic_set_default_callback(test_ctx->qserver, h3zero_callback, &server_param);

        ret = wt_interop_client_prepare(test_ctx->qclient, NULL, simulated_time, PICOQUIC_TEST_SNI,
            &client_param, &test_ctx->cnx_client, &h3_ctx, &session);
        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    time_out = simulated_time + 30000000;
    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);
        if (ret == 0 && ++nb_trials > 100000) {
            DBG_PRINTF("Simulation not concluded after %d trials", nb_trials);
            ret = -1;
        }
    }

    if (ret == 0 && (spec->add_missing || spec->block_download)) {
        /* The failure must end the test promptly, not after an idle timeout. */
        if (wt_interop_client_is_success(session) || session->nb_errors == 0 || simulated_time > 2000000) {
            DBG_PRINTF("Failure not detected: errors %d, time %" PRIu64, session->nb_errors, simulated_time);
            ret = -1;
        }
    }
    else if (ret == 0 && !wt_interop_client_is_success(session)) {
        DBG_PRINTF("Client not successful: accepted %d, files %zu/%zu, errors %d",
            session->is_accepted, session->nb_files_received, session->nb_files, session->nb_errors);
        ret = -1;
    }
    if (ret == 0 && (test_ctx->cnx_client->remote_error != 0 || test_ctx->cnx_client->local_error != 0)) {
        DBG_PRINTF("Connection close error: remote 0x%" PRIx64 ", local 0x%" PRIx64,
            test_ctx->cnx_client->remote_error, test_ctx->cnx_client->local_error);
        ret = -1;
    }
    if (ret == 0 && spec->is_handshake) {
        ret = wt_interop_test_check_negotiated(dir_c_dl, "p2");
        if (ret == 0) {
            ret = wt_interop_test_check_negotiated(dir_s_dl, "p2");
        }
    }
    if (ret == 0 && !spec->add_missing && !spec->block_download) {
        ret = wt_interop_test_check_files(spec, (spec->is_send) ? dir_c_www : dir_s_www, (spec->is_send) ? dir_s_dl : dir_c_dl);
    }

    if (h3_ctx != NULL) {
        h3zero_callback_delete_context(test_ctx->cnx_client, h3_ctx);
    }
    wt_interop_session_free(session);
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }
    wt_interop_param_clear(&client_param);
    wt_interop_param_clear(&server_param_wt);

    return ret;
}

static const size_t wt_interop_stream_sizes[] = { 100, 0, 25000, 300000 };

int wt_interop_handshake_test(void)
{
    wt_interop_test_spec_t spec = { "hs", "handshake", "handshake", 0, 1, 0, NULL, 0, 0, 0 };
    return wt_interop_test_one(&spec, 1);
}

int wt_interop_uni_receive_test(void)
{
    wt_interop_test_spec_t spec = { "ur", "transfer-unidirectional-receive", "transfer", 0, 0, 4, wt_interop_stream_sizes, 0, 0, 0 };
    return wt_interop_test_one(&spec, 2);
}

int wt_interop_uni_send_test(void)
{
    wt_interop_test_spec_t spec = { "us", "transfer", "transfer-unidirectional-send", 1, 0, 4, wt_interop_stream_sizes, 0, 0, 0 };
    return wt_interop_test_one(&spec, 3);
}

int wt_interop_bidi_receive_test(void)
{
    wt_interop_test_spec_t spec = { "br", "transfer-bidirectional-receive", "transfer", 0, 0, 4, wt_interop_stream_sizes, 0, 0, 0 };
    return wt_interop_test_one(&spec, 4);
}

int wt_interop_bidi_send_test(void)
{
    wt_interop_test_spec_t spec = { "bs", "transfer", "transfer-bidirectional-send", 1, 0, 4, wt_interop_stream_sizes, 0, 0, 0 };
    return wt_interop_test_one(&spec, 5);
}

int wt_interop_datagram_receive_test(void)
{
    wt_interop_test_spec_t spec = { "dr", "transfer-datagram-receive", "transfer", 0, 0, 20, NULL, 600, 0, 0 };
    return wt_interop_test_one(&spec, 6);
}

int wt_interop_datagram_send_test(void)
{
    wt_interop_test_spec_t spec = { "ds", "transfer", "transfer-datagram-send", 1, 0, 20, NULL, 600, 0, 0 };
    return wt_interop_test_one(&spec, 7);
}

int wt_interop_missing_file_test(void)
{
    wt_interop_test_spec_t spec = { "mf", "transfer-bidirectional-receive", "transfer", 0, 0, 2, wt_interop_stream_sizes, 0, 1, 0 };
    return wt_interop_test_one(&spec, 8);
}

/* A single large file, so the FIN arrives in a later callback than the failed open. */
static const size_t wt_interop_download_fail_sizes[] = { 300000 };

int wt_interop_download_fail_test(void)
{
    wt_interop_test_spec_t spec = { "df", "transfer-bidirectional-receive", "transfer", 0, 0, 1, wt_interop_download_fail_sizes, 0, 0, 1 };
    return wt_interop_test_one(&spec, 9);
}

/* The largest payload, header "PUSH file1.bin\n" included. */
static const size_t wt_interop_datagram_large_sizes[] = { 600, WT_INTEROP_DATAGRAM_MAX - 15 };

int wt_interop_datagram_large_test(void)
{
    int ret = 0;
    /* Worst case at the minimum MTU: flags, 20 byte CID, 4 byte PN, AEAD tag, frame type and length, quarter stream ID. */
    size_t budget = PICOQUIC_ENFORCED_INITIAL_MTU - (1 + 20 + 4 + 16 + 1 + 2 + 8);

    if (WT_INTEROP_DATAGRAM_MAX > budget) {
        DBG_PRINTF("Datagram max %d exceeds the minimum MTU budget %zu", WT_INTEROP_DATAGRAM_MAX, budget);
        ret = -1;
    }
    else {
        wt_interop_test_spec_t spec = { "dl", "transfer-datagram-receive", "transfer", 0, 0, 2, wt_interop_datagram_large_sizes, 0, 0, 0 };
        ret = wt_interop_test_one(&spec, 10);
    }
    return ret;
}
