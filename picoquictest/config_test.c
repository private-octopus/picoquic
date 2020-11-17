/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

#include <stdlib.h>
#include <string.h>

#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquic_config.h"

static char* ref_option_text = "c:k:K:p:v:o:w:rRs:S:G:e:C:E:i:l:Lb:q:m:n:a:t:zI:DQh";

int config_option_letters_test()
{
    char option_text[256];
    int ret = picoquic_config_option_letters(option_text, sizeof(option_text), NULL);

    if (ret != 0) {
        DBG_PRINTF("picoquic_config_option_letters returns %d", ret);
    }
    else if (strcmp(option_text, ref_option_text) != 0) {
        DBG_PRINTF("picoquic_config_option_letters returns %s", option_text);
        ret = -1;
    }

    return ret;
}

static picoquic_quic_config_t param1 = {
    0, /*uint32_t nb_connections; */
    "/data/github/picoquic", /* char const* solution_dir; */
    "/data/certs/cert.pem", /* char const* server_cert_file; */
    "/data/certs/key.pem", /* char const* server_key_file; */
    "/data/certs/esni_key.pem", /* char const* esni_key_file; */
    "/data/certs/esni_rr.txt", /* char const* esni_rr_file; */
    "/data/log.txt", /* char const* log_file; */
    "/data/log/", /* char const* bin_dir; */
    "/data/qlog/", /* char const* qlog_dir; */
    4433, /* int server_port; */
    1, /* int dest_if; */
    1536, /* int mtu_max; */
    "cubic", /* const picoquic_congestion_algorithm_t* cc_algorithm; */
    NULL, /* picoquic_connection_id_callback_ctx_t* cnx_id_cbdata; */
    /* Common flags */
    1, /* unsigned int initial_random : 1; */
    1, /* unsigned int use_long_log : 1; */
    /* Server only */
    "/data/www/", /* char const* www_dir; */
    { 0x012345678abcdef, 0xfedcba9876543210}, /* uint64_t reset_seed[2]; */
    NULL, /* const uint8_t* ticket_encryption_key; */
    0, /* size_t ticket_encryption_key_length; */
    /* Server flags */
    1, /* unsigned int do_retry : 1; */

    /* Client only */
    NULL, /* char const* ticket_file_name; */
    NULL, /* char const* token_file_name; */
    NULL, /* char const* sni; */
    NULL, /* char const* alpn; */
    NULL, /* char const* out_dir; */
    NULL, /* char const* root_trust_file; */
    0, /* int cipher_suite_id; */
    0, /* uint32_t proposed_version; */
    0, /* int client_cnx_id_length; */
    0, /* unsigned int force_zero_share : 1; */
    0, /* unsigned int no_disk : 1; */
    0, /* unsigned int large_client_hello : 1; */
};

static char const* config_argv1[] = {
    "-S", "/data/github/picoquic",
    "-c", "/data/certs/cert.pem",
    "-k", "/data/certs/key.pem",
    "-K", "/data/certs/esni_key.pem",
    "-E", "/data/certs/esni_rr.txt",
    "-l", "/data/log.txt",
    "-b", "/data/log/",
    "-q", "/data/qlog/",
    "-p", "4433",
    "-e", "1",
    "-m", "1536",
    "-G", "cubic",
    "-R",
    "-L",
    "-w", "/data/www/",
    "-r",
    "-s", "012345678abcdef", "0xfedcba9876543210",
    NULL
};

static picoquic_quic_config_t param2 = {
    0, /*uint32_t nb_connections; */
    NULL, /* char const* solution_dir; */
    NULL, /* char const* server_cert_file; */
    NULL, /* char const* server_key_file; */
    NULL, /* char const* esni_key_file; */
    NULL, /* char const* esni_rr_file; */
    NULL, /* char const* log_file; */
    NULL, /* char const* bin_dir; */
    NULL, /* char const* qlog_dir; */
    0, /* int server_port; */
    0, /* int dest_if; */
    0, /* int mtu_max; */
    NULL, /* const picoquic_congestion_algorithm_t* cc_algorithm; */
    NULL, /* picoquic_connection_id_callback_ctx_t* cnx_id_cbdata; */
    /* Common flags */
    0, /* unsigned int initial_random : 1; */
    0, /* unsigned int use_long_log : 1; */
    /* Server only */
    NULL, /* char const* www_dir; */
    {0, 0}, /* uint64_t reset_seed[2]; */
    NULL, /* const uint8_t* ticket_encryption_key; */
    0, /* size_t ticket_encryption_key_length; */
    /* Server flags */
    0, /* unsigned int do_retry : 1; */

    /* Client only */
    NULL, /* char const* ticket_file_name; */
    NULL, /* char const* token_file_name; */
    "test.example.com", /* char const* sni; */
    "test", /* char const* alpn; */
    "/data/w_out", /* char const* out_dir; */
    "data/certs/root.pem", /* char const* root_trust_file; */
    20, /* int cipher_suite_id; */
    0xff000020, /* uint32_t proposed_version; */
    5, /* int client_cnx_id_length; */
    1,/* unsigned int force_zero_share : 1; */
    1, /* unsigned int no_disk : 1; */
    1 /* unsigned int large_client_hello : 1; */
};

static const char* config_argv2[] = {
    "-n", "test.example.com",
    "-a", "test",
    "-o", "/data/w_out",
    "-t", "data/certs/root.pem",
    "-C", "20",
    "-v", "ff000020",
    "-z",
    "-D",
    "-Q",
    "-I", "5",
    NULL
};

int config_test_compare_string(const char* title, const char* expected, const char* actual)
{
    int ret = 0;

    if (expected == NULL) {
        if (actual != NULL) {
            DBG_PRINTF("Expected %s = NULL, got %x", title, actual);
            ret = -1;
        }
    }
    else if (actual == NULL) {
        DBG_PRINTF("Expected %s = %s, got NULL", title, expected);
        ret = -1;
    }
    else if (strcmp(expected, actual) != 0) {
        DBG_PRINTF("Expected %s = %s, got %s", title, actual, expected);
        ret = -1;
    }
    return ret;
}

int config_test_compare_int(const char* title, int expected, int actual)
{
    int ret = 0;
    
    if (expected != actual) {
        DBG_PRINTF("Expected %s = %d, got %d", title, actual, expected);
        ret = -1;
    }
    return ret;
}



int config_test_compare_uint32(const char* title, uint32_t expected, uint32_t actual)
{
    int ret = 0;

    if (expected != actual) {
        DBG_PRINTF("Expected %s = 0x%" PRIx32 ", got 0x%" PRIx32, title, actual, expected);
        ret = -1;
    }
    return ret;
}

int config_test_compare(const picoquic_quic_config_t* expected, const picoquic_quic_config_t* actual)
{
    int ret = 0;

    ret |= config_test_compare_int("nb_connections", expected->nb_connections, actual->nb_connections);
    ret |= config_test_compare_string("solution_dir", expected->solution_dir, actual->solution_dir);
    ret |= config_test_compare_string("server_cert_file", expected->server_cert_file, actual->server_cert_file);
    ret |= config_test_compare_string("server_key_file", expected->server_key_file, actual->server_key_file);
    ret |= config_test_compare_string("esni_key_file", expected->esni_key_file, actual->esni_key_file);
    ret |= config_test_compare_string("esni_rr_file", expected->esni_rr_file, actual->esni_rr_file);
    ret |= config_test_compare_string("log_file", expected->log_file, actual->log_file);
    ret |= config_test_compare_string("bin_dir", expected->bin_dir, actual->bin_dir);
    ret |= config_test_compare_string("qlog_dir", expected->qlog_dir, actual->qlog_dir);
    ret |= config_test_compare_string("qlog_dir", expected->qlog_dir, actual->qlog_dir);
    ret |= config_test_compare_int("qlog_dir", expected->server_port, actual->server_port);
    ret |= config_test_compare_int("dest_if", expected->dest_if, actual->dest_if);
    ret |= config_test_compare_int("mtu_max", expected->mtu_max, actual->mtu_max);
    ret |= config_test_compare_string("cc_algo_id", expected->cc_algo_id, actual->cc_algo_id);
    ret |= config_test_compare_int("initial_random", expected->initial_random, actual->initial_random);
    ret |= config_test_compare_int("use_long_log", expected->use_long_log, actual->use_long_log);
    ret |= config_test_compare_string("www_dir", expected->www_dir, actual->www_dir);
    ret |= config_test_compare_int("do_retry", expected->do_retry, actual->do_retry);
    /* TODO: reset_seed */
    ret |= config_test_compare_string("sni", expected->sni, actual->sni);
    ret |= config_test_compare_string("alpn", expected->alpn, actual->alpn);
    ret |= config_test_compare_string("out_dir", expected->out_dir, actual->out_dir);
    ret |= config_test_compare_string("root_trust_file", expected->root_trust_file, actual->root_trust_file);
    ret |= config_test_compare_string("root_trust_file", expected->root_trust_file, actual->root_trust_file);
    ret |= config_test_compare_int("cipher_suite_id", expected->cipher_suite_id, actual->cipher_suite_id);
    ret |= config_test_compare_uint32("proposed_version", expected->proposed_version, actual->proposed_version);
    ret |= config_test_compare_int("force_zero_share", expected->force_zero_share, actual->force_zero_share);
    ret |= config_test_compare_int("no_disk", expected->no_disk, actual->no_disk);
    ret |= config_test_compare_int("large_client_hello", expected->large_client_hello, actual->large_client_hello);
    ret |= config_test_compare_int("client_cnx_id_length", expected->client_cnx_id_length, actual->client_cnx_id_length);

    return ret;
}

int config_test_parse_command_line(const picoquic_quic_config_t* expected, const char** argv, int argc)
{
    int ret = 0;
    int opt_ind = 0;
    picoquic_quic_config_t actual;

    memset(&actual, 0, sizeof(picoquic_quic_config_t));

    while (opt_ind < argc && ret == 0) {
        const char* x = argv[opt_ind];
        const char* optval = NULL;
        int opt;
        if (x == NULL) {
            /* could not parse to the end! */
            DBG_PRINTF("Unexpected stop after %d arguments, expected %d", opt_ind, argc);
            ret = -1;
            break;
        }
        else if (x[0] != '-' || x[1] == 0 || x[2] != 0) {
            /* could not parse to the end! */
            DBG_PRINTF("Unexpected argument: %s", x);
            ret = -1;
            break;
        }
        opt = x[1];
        opt_ind++;
        if (opt_ind < argc) {
            optval = argv[opt_ind];
            if (optval[0] == '-') {
                optval = NULL;
            }
            else {
                opt_ind++;
            }
        }
        ret = picoquic_config_command_line(opt, &opt_ind, argc, argv, optval, &actual);
        if (ret != 0) {
            DBG_PRINTF("Could not part opt -%c", opt);
        }
    }

    if (ret == 0) {
        ret = config_test_compare(expected, &actual);
    }

    return (ret);
}

int config_option_test()
{
    int ret = config_test_parse_command_line(&param1, config_argv1, (int)(sizeof(config_argv1) / sizeof(char const*)) - 1);
    if (ret != 0) {
        DBG_PRINTF("First config option test returns %d", ret);
    }
    else {
        ret = config_test_parse_command_line(&param2, config_argv2, (int)(sizeof(config_argv2) / sizeof(char const*)) - 1);
        if (ret != 0) {
            DBG_PRINTF("Second config option test returns %d", ret);
        }
    }

    return ret;
}