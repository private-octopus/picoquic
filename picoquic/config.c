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

/* Manage the configuration options for the QUIC context
 * TODO: split between common options, client options, server options?
 * TODO: separate generic option (QUIC level) and application options (per ALPN)
 * TODO: organize as hierarchy of calls, eg app -> protocol -> quic.
 * TODO: do not force linking of binlog, textlog, qlog
 */

#include <stdio.h>
#include <stdint.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"
#include "picoquic_config.h"

typedef enum{
    picoquic_option_CERT,
    picoquic_option_KEY,
    picoquic_option_ESNI_KEY,
    picoquic_option_SERVER_PORT,
    picoquic_option_UPDATE_KEY_AFTER,
    picoquic_option_PROPOSED_VERSION,
    picoquic_option_OUTDIR,
    picoquic_option_WWWDIR,
    picoquic_option_JUST_ONCE,
    picoquic_option_DO_RETRY,
    picoquic_option_INITIAL_RANDOM,
    picoquic_option_RESET_SEED,
    picoquic_option_SOLUTION_DIR,
    picoquic_option_CC_ALGO,
    picoquic_option_DEST_IF,
    picoquic_option_CIPHER_SUITE,
    picoquic_option_ESNI_RR_FILE,
    picoquic_option_INIT_CNXID,
    picoquic_option_LOG_FILE,
    picoquic_option_LONG_LOG,
    picoquic_option_BINLOG_DIR,
    picoquic_option_QLOG_DIR,
    picoquic_option_MTU_MAX,
    picoquic_option_SNI,
    picoquic_option_ALPN,
    picoquic_option_ROOT_TRUST_FILE,
    picoquic_option_FORCE_ZERO_SHARE,
    picoquic_option_FORCE_MIGRATION,
    picoquic_option_CNXID_LENGTH,
    picoquic_option_NO_DISK,
    picoquic_option_LARGE_CLIENT_HELLO,
    picoquic_option_HELP
}  picoquic_option_enum_t;

typedef struct st_option_param_t {
    char const * param;
    int length;
} option_param_t;

typedef struct st_option_table_line_t {
    picoquic_option_enum_t option_num;
    char option_letter;
    char const* option_name;
    int nb_params_required;
    char const* param_sample;
    char const* option_help;
} option_table_line_t;

static option_table_line_t option_table[] = {
    { picoquic_option_CERT, 'c', "cert", 1, "file", "cert file" },
    { picoquic_option_KEY, 'k', "key", 1, "file", "key file" },
    { picoquic_option_ESNI_KEY, 'K', "esni_key", 1, "file", "ESNI private key file (default: don't use ESNI)" },
    { picoquic_option_SERVER_PORT, 'p', "port", 1, "number", "server port" },
    { picoquic_option_UPDATE_KEY_AFTER, 'u', "update_after", 1, "", "" },
    { picoquic_option_PROPOSED_VERSION, 'v', "proposed_version", 1, "", "" },
    { picoquic_option_OUTDIR, 'o', "outdir", 1, "folder", "Folder where client writes downloaded files, defaults to current directory." },
    { picoquic_option_WWWDIR, 'w', "wwwdir", 1, "folder", "Folder containing web pages served by server" },
    { picoquic_option_JUST_ONCE, '1', "once", 0, "", "Once: close the server after processing 1 connection." },
    { picoquic_option_DO_RETRY, 'r', "do_retry", 0, "", " Do Retry Request" },
    { picoquic_option_INITIAL_RANDOM, 'R', "initial_random", 0, "", "" },
    { picoquic_option_RESET_SEED, 's', "reset_seed", 2, "<64b 64b>", "Reset seed" },
    { picoquic_option_SOLUTION_DIR, 'S', "solution_dir", 1, "folder", "Set the path to the source files to find the default files" },
    { picoquic_option_CC_ALGO, 'G', "cc_algo", 1, "cc_algorithm",
    "Use the specified congestion control algorithm: reno, cubic, bbr or fast. Defaults to bbr." },
    { picoquic_option_DEST_IF, 'e', "dest_if", 1, "if", "Send on interface (default: -1)" },
    { picoquic_option_CIPHER_SUITE, 'C', "cipher_suite", 1, "cipher_suite_id", "specify cipher suite (e.g. -C 20 = chacha20)" },
    { picoquic_option_ESNI_RR_FILE, 'E', "esni_rr_file", 1, "file", "ESNI RR file (default: don't use ESNI)" },
    { picoquic_option_INIT_CNXID, 'i', "cnxid_params", 3, "<src mask value>", "TBD" },
    { picoquic_option_LOG_FILE, 'l', "text_log", 1, "file", "Log file, Log to stdout if file = \"-\". No text logging if absent." },
    { picoquic_option_LONG_LOG, 'L', "long_log", 0, "", "Log all packets. If absent, log stops after 100 packets." },
    { picoquic_option_BINLOG_DIR, 'b', "binlog_dir", 1, "folder", "Binary logging to this directory. No binary logging if absent." },
    { picoquic_option_QLOG_DIR, 'q', "qlog_dir", 1, "folder", 
    "Qlog logging to this directory. No qlog logging if absent, but qlogs could be produced using picolog if binary logs are available." },
    { picoquic_option_MTU_MAX, 'm', "mtu_max", 1, "mtu_max", "Largest mtu value that can be tried for discovery." },
    { picoquic_option_SNI, 'n', "sni", 1, "sni", "sni (default: server name)" },
    { picoquic_option_ALPN, 'a', "alpn", 1, "alpn", "alpn (default function of version)" },
    { picoquic_option_ROOT_TRUST_FILE, 't', "root_trust_file", 1, "file", "root trust file" },
    { picoquic_option_FORCE_ZERO_SHARE, 'z', "force_zero_share", 0, "", "Set TLS zero share behavior on client, to force HRR" },
    { picoquic_option_FORCE_MIGRATION, 'f', "force_migration", 1, "migration_mode",
    "Force client to migrate to start migration: 1  test NAT rebinding, 2  test CNXID renewal, 3  test migration to new address." },
    { picoquic_option_CNXID_LENGTH, 'I', "cnxid_length", 1, "length", "Length of CNX_ID used by the client, default=8" },
    { picoquic_option_NO_DISK, 'D', "no_disk", 0, "no disk: do not save received files on disk" },
    { picoquic_option_LARGE_CLIENT_HELLO, 'Q', "large_client_hello", 0,
    "send a large client hello in order to test post quantum readiness" },
    { picoquic_option_HELP, 'h', "help", 0, "This help message" }
};

static size_t option_table_size = sizeof(option_table) / sizeof(option_table_line_t);

static int skip_spaces(const char* line, int offset)
{
    int c;

    while ((c = line[offset]) != 0) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            offset++;
        }
        else {
            break;
        }
    }
    return offset;
}

static int skip_name(const char* line, int offset)
{
    int c;

    while ((c = line[offset]) != 0) {
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == ':' || c == '#') {
            break;
        }
        else {
            offset++;
        }
    }
    return offset;
}

static int parse_line_params(const char* line, int offset, option_param_t* params, int params_max, int* nb_params)
{
    int nb_found = 0;

    offset = skip_spaces(line, offset);
    if (line[offset] == ':') {
        while (nb_found < params_max) {
            int offset_start;
            offset_start = skip_spaces(line, offset);
            offset = skip_name(line, offset);
            if (offset == offset_start) {
                /* Nothing there. */
                break;
            }
            else {
                params[nb_found].param = line + offset_start;
                params[nb_found].length = offset - offset_start;
                nb_found++;
            }
        }
    }
    *nb_params = nb_found;
    return offset;
}

static int compare_option_name(const char * line, int offset, int length, char const* option_name)
{
    int ret = -1;
    
    if (length == strlen(option_name)) {
        ret = strncmp(option_name, line + offset, length);
    }

    return ret;
}

static uint32_t config_parse_target_version(char const* v_arg)
{
    /* Expect the version to be encoded in base 16 */
    uint32_t v = 0;
    char const* x = v_arg;

    while (*x != 0) {
        int c = *x;

        if (c >= '0' && c <= '9') {
            c -= '0';
        }
        else if (c >= 'a' && c <= 'f') {
            c -= 'a';
            c += 10;
        }
        else if (c >= 'A' && c <= 'F') {
            c -= 'A';
            c += 10;
        }
        else {
            v = 0;
            break;
        }
        v *= 16;
        v += c;
        x++;
    }

    return v;
}

static void config_set_string_param(char const** v, char const* p, int p_len)
{
    char* p_dup;

    if (*v != NULL) {
        free((void*)*v);
        *v = NULL;
    }
    p_dup = malloc(p_len + 1);
    if (p_dup != NULL) {
        memcpy(p_dup, p, p_len);
        p_dup[p_len] = 0;
        *v = (char const*)p_dup;
    }
    else {
        fprintf(stderr, "Cannot allocate %d characters\n", p_len);
    }
}

static char* config_optval_string(char* buffer, int buffer_max, const char* p, int p_length)
{
    if (p_length + 1 > buffer_max) {
        p_length = buffer_max - 1;
    }
    memcpy(buffer, p, p_length);
    buffer[p_length] = 0;
    return buffer;
}

int config_atoi(const char* p, int p_length)
{
    int v = 0;

    for (int i = 0; i < p_length; i++) {
        int c = p[i] - '0';
        if (c < 0 || c > 9) {
            v = -1;
            break;
        }
        else {
            v *= 10;
            v += c;
        }
    }

    return v;
}

uint64_t config_atoull(const char* p, int p_length)
{
    uint64_t v = 0;

    for (int i = 0; i < p_length; i++) {
        int c = p[i];
        unsigned int d = 0;
        if (c >= '0' || c <= '9') {
            d = c - '0';
        }
        else if (c >= 'a' || c <= 'f') {
            d = c - 'a' + 10;
        }
        else if (c >= 'A' || c <= 'F') {
            d = c - 'A' + 10;
        }
        else {
            continue;
        }
        v <<= 4;
        v += d;
    }

    return v;
}

static int config_set_option(option_table_line_t* option_desc, option_param_t* params, int nb_params, picoquic_quic_config_t* config)
{
    int ret = 0;
    char opval_buffer[256];

    switch (option_desc->option_num) {
    case picoquic_option_CERT:
        config_set_string_param(&config->server_cert_file, params[0].param, params[0].length);
        break;
    case picoquic_option_KEY:
        config_set_string_param(&config->server_key_file, params[0].param, params[0].length);
        break;
    case picoquic_option_ESNI_KEY:
        config_set_string_param(&config->esni_key_file, params[0].param, params[0].length);
        break;
    case picoquic_option_SERVER_PORT:
        if ((config->server_port = config_atoi(params[0].param, params[0].length)) <= 0) {
            fprintf(stderr, "Invalid port: %s\n", config_optval_string(opval_buffer, 256, params[0].param, params[0].length));
            ret = -1;
        }
        break;
    case picoquic_option_UPDATE_KEY_AFTER:
        if ((config->nb_packets_before_update = config_atoi(params[0].param, params[0].length)) <= 0) {
            fprintf(stderr, "Invalid number of packets: %s\n", config_optval_string(opval_buffer, 256, params[0].param, params[0].length));
            ret = -1;
        }
        break;
    case picoquic_option_PROPOSED_VERSION:
        if ((config->proposed_version = config_parse_target_version(config_optval_string(opval_buffer, 256, params[0].param, params[0].length))) <= 0) {
            fprintf(stderr, "Invalid version: %s\n", config_optval_string(opval_buffer, 256, params[0].param, params[0].length));
            ret = -1;
        }
        break;
    case picoquic_option_OUTDIR:
        config_set_string_param(&config->out_dir, params[0].param, params[0].length);
        break;
    case picoquic_option_WWWDIR:
        config_set_string_param(&config->www_dir, params[0].param, params[0].length);
        break;
    case picoquic_option_JUST_ONCE:
        config->just_once = 1;
        break;
    case picoquic_option_DO_RETRY:
        config->do_retry = 1;
        break;
    case picoquic_option_INITIAL_RANDOM:
        config->initial_random = 1;
        break;
    case picoquic_option_RESET_SEED:
        config->reset_seed[1] = config_atoull(params[0].param, params[0].length);
        config->reset_seed[0] = config_atoull(params[1].param, params[0].length);
        break;
    case picoquic_option_SOLUTION_DIR:
        config_set_string_param(&config->solution_dir, params[0].param, params[0].length);
        break;
    case picoquic_option_CC_ALGO:
        config_set_string_param(&config->cc_algo_id, params[0].param, params[0].length);
        break;
    case picoquic_option_DEST_IF:
        config->dest_if = config_atoi(params[0].param, params[0].length);
        break;
    case picoquic_option_CIPHER_SUITE:
        config->cipher_suite_id = config_atoi(params[0].param, params[0].length);
        break;
    case picoquic_option_ESNI_RR_FILE:
        config_set_string_param(&config->esni_rr_file, params[0].param, params[0].length);
        break;
#if 0
        /* TODO: should be rewired to use the standard function */
    case picoquic_option_INIT_CNXID:
        config->cnx_id_cbdata = picoquic_connection_id_callback_create_ctx(config_optval_string(opval_buffer, 256, params[0].param, params[0].length), argv[*p_optind], argv[p_optind[1]]);
        if (config->cnx_id_cbdata == NULL) {
            fprintf(stderr, "could not create callback context (%s, %s, %s)\n", config_optval_string(opval_buffer, 256, params[0].param, params[0].length), argv[*p_optind], argv[p_optind[1]]);
            ret = -1;
        }
        *p_optind += 2;
        break;
#endif
    case picoquic_option_LOG_FILE:
        config_set_string_param(&config->log_file, params[0].param, params[0].length);
        break;
    case picoquic_option_LONG_LOG:
        config->use_long_log = 1;
        break;
    case picoquic_option_BINLOG_DIR:
        config_set_string_param(&config->bin_dir, params[0].param, params[0].length);
        break;
    case picoquic_option_QLOG_DIR:
        config_set_string_param(&config->qlog_dir, params[0].param, params[0].length);
        break;
    case picoquic_option_MTU_MAX:
        config->mtu_max = config_atoi(params[0].param, params[0].length);
        if (config->mtu_max <= 0 || config->mtu_max > PICOQUIC_MAX_PACKET_SIZE) {
            fprintf(stderr, "Invalid max mtu: %s\n", config_optval_string(opval_buffer, 256, params[0].param, params[0].length));
            ret = -1;
        }
        break;
    case picoquic_option_SNI:
        config_set_string_param(&config->sni, params[0].param, params[0].length);
        break;
    case picoquic_option_ALPN:
        config_set_string_param(&config->alpn, params[0].param, params[0].length);
        break;
    case picoquic_option_ROOT_TRUST_FILE:
        config_set_string_param(&config->root_trust_file, params[0].param, params[0].length);
        break;
    case picoquic_option_FORCE_ZERO_SHARE:
        config->force_zero_share = 1;
        break;
    case picoquic_option_FORCE_MIGRATION:
        config->force_migration = config_atoi(params[0].param, params[0].length);
        if (config->force_migration <= 0 || config->force_migration > 3) {
            fprintf(stderr, "Invalid migration mode: %s\n", config_optval_string(opval_buffer, 256, params[0].param, params[0].length));
            ret = -1;
        }
        break;
    case picoquic_option_CNXID_LENGTH:
        config->client_cnx_id_length = config_atoi(params[0].param, params[0].length);
        if (config->client_cnx_id_length < 0 || config->client_cnx_id_length > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
            fprintf(stderr, "Invalid connection id length: %s\n", config_optval_string(opval_buffer, 256, params[0].param, params[0].length));
            ret = -1;
        }
        break;
    case picoquic_option_NO_DISK:
        config->no_disk = 1;
        break;
    case picoquic_option_LARGE_CLIENT_HELLO:
        config->large_client_hello = 1;
        break;
    case picoquic_option_HELP:
        ret = -1;
        break;
    default:
        ret = -1;
        break;
    }
    return ret;
}

int picoquic_config_option_letters(char* option_string, size_t string_max, size_t * string_length)
{
    size_t l = 0;
    int ret = 0;

    for (size_t i = 0; l + 1 < string_max && i < option_table_size; i++) {
        option_string[l++] = option_table[i].option_letter;
        if (option_table[i].nb_params_required > 0) {
            if (l + 1 < string_max) {
                option_string[l++] = ':';
            }
            else {
                l--;
                ret = -1;
                break;
            }
        }
    }
    option_string[l] = 0;
    if (string_length != NULL) {
        *string_length = l;
    }
    return ret;
}

int picoquic_config_command_line(int opt, int * p_optind, int argc, char const ** argv, char const* optarg, picoquic_quic_config_t * config)
{
    int ret = 0;
    int option_index = -1;
    option_param_t params[5];
    int nb_params = 0;

    /* Get the parameters */
    for (size_t i = 0; i < option_table_size; i++) {
        if (option_table[i].option_letter == opt) {
            option_index = (int)i;
            break;
        }
    }

    if (option_index == -1) {
        fprintf(stderr, "Unknown option: -%c\n", opt);
    }
    else {
        if (option_table[option_index].nb_params_required > 0) {
            params[0].param = optarg;
            params[0].length = (int)strlen(optarg);
            nb_params++;
            while (nb_params < option_table[option_index].nb_params_required) {
                if (*p_optind + 1 > argc) {
                    fprintf(stderr, "option -%c requires %d arguments\n", opt, option_table[option_index].nb_params_required);
                    ret = -1;
                    break;
                }
                else {
                    params[nb_params].param = argv[*p_optind];
                    params[nb_params].length = (int)strlen(argv[*p_optind]);
                    nb_params++;
                    *p_optind += 1;
                }
            }
        }
    }

    if (ret == 0) {
        ret = config_set_option(&option_table[option_index], params, nb_params, config);
    }

    return ret;
}

int picoquic_config_file(char const* file_name, picoquic_quic_config_t* config)
{
    int ret = 0;
    FILE* F = picoquic_file_open(file_name, "r");
    if (F == NULL) {
        DBG_PRINTF("Could not open configuration file: %s", file_name);
        ret = -1;
    }
    else {
        char line[1024];
        int line_number = 0;

        while (fgets(line, sizeof(line), F) != NULL && ret == 0) {
            /* Parse the line. Expect format: <arg_id>":" spaces* argv1 [space ^spaces argvn]* */
            int offset = skip_spaces(line, 0);
            int name_offset;
            int name_length;
            option_param_t params[5];
            int nb_params;
            int option_index = -1;

            line_number++;
            name_offset = offset;
            offset = skip_name(line, name_offset);
            if (offset == name_offset) {
                /* Empty line */
            }
            else {
                name_length = offset - name_offset;
                /* Parse the option parameters, up to 5 of them */
                offset = parse_line_params(line, offset, params, 5, &nb_params);
                /* Recognize the option and apply the parameters  */
                for (size_t i = 0; i < option_table_size; i++) {
                    if (compare_option_name(line, name_offset, name_length, option_table[i].option_name) == 0) {
                        option_index = (int)i;
                        break;
                    }
                }

                if (option_index == -1) {
                    char buffer[256];
                    fprintf(stderr, "Unknown option: -%s\n", config_optval_string(buffer, 256, line + name_offset, name_length));
                    ret = -1;
                }
                else {
                    if (option_table[option_index].nb_params_required != nb_params) {
                        fprintf(stderr, "option %s requires %d arguments, %d present\n",
                            option_table[option_index].option_name,
                            option_table[option_index].nb_params_required,
                            nb_params);
                        ret = -1;
                    }
                }

                if (ret == 0) {
                    ret = config_set_option(&option_table[option_index], params, nb_params, config);
                }
            }
        }
        picoquic_file_close(F);
    }

    return ret;
}

/* Create a QUIC Context based on configuration data.
 * Arguments from configuration:
 * - uint32_t nb_connections,
 * - char const* cert_file_name,
 * - char const* key_file_name,
 * - char const * cert_root_file_name,
 * - char const* default_alpn,
 * - picoquic_connection_id_cb_fn cnx_id_callback,
 * - void* cnx_id_callback_data,
 * - uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
 * - char const* ticket_file_name,
 * - const uint8_t* ticket_encryption_key,
 * - size_t ticket_encryption_key_length
 * Arguments from program:
 * - picoquic_stream_data_cb_fn default_callback_fn,
 * - void* default_callback_ctx,
 * - uint64_t current_time,
 * - uint64_t* p_simulated_time,
 */

picoquic_quic_t* picoquic_create_and_configure(picoquic_quic_config_t* config,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    uint64_t current_time,
    uint64_t * p_simulated_time)
{
    /* Create context */
    /* TODO: sane default for NB connections 
     * TODO: padding policy 
     * TODO: mtu max accessor 
     * TODO: set supported CC without linking every option
     * TODO: set logging option without linking every option
     * TODO: set key log file option
     */
    picoquic_quic_t* quic = picoquic_create(
        config->nb_connections,
        config->server_cert_file,
        config->server_key_file,
        config->root_trust_file,
        config->alpn,
        default_callback_fn,
        default_callback_ctx,
        (config->cnx_id_cbdata == NULL) ? NULL : picoquic_connection_id_callback,
        config->cnx_id_cbdata,
        (uint8_t *)config->reset_seed,
        current_time,
        p_simulated_time,
        config->ticket_file_name,
        config->ticket_encryption_key,
        config->ticket_encryption_key_length);

    if (quic != NULL) {
        int ret = 0;
        picoquic_congestion_algorithm_t const* cc_algo = NULL;

        /* Additional configuration options */
        /* picoquic_set_alpn_select_fn(qserver, picoquic_demo_server_callback_select_alpn); */
        if (config->do_retry) {
            picoquic_set_cookie_mode(quic, 1);
        }
        else {
            /* TODO: option to provide cookie by default or not */
            picoquic_set_cookie_mode(quic, 2);
        }
        /* quic->mtu_max = config->mtu_max; */

        if (config->cc_algo_id != NULL) {
            cc_algo = picoquic_get_congestion_algorithm(config->cc_algo_id);
            if (cc_algo == NULL) {
                fprintf(stderr, "Unrecognized congestion algorithm: %s", config->cc_algo_id);
            }
        }
        if (cc_algo == NULL) {
            cc_algo = picoquic_bbr_algorithm;
        }
        picoquic_set_default_congestion_algorithm(quic, cc_algo);

        picoquic_set_padding_policy(quic, 39, 128);

        picoquic_set_binlog(quic, config->bin_dir);

        /* picoquic_set_qlog(quic, config->qlog_dir); */

        picoquic_set_textlog(quic, config->log_file);

        picoquic_set_log_level(quic, config->use_long_log);

        if (config->initial_random) {
            picoquic_set_random_initial(quic, 1);
        }

        /* picoquic_set_key_log_file_from_env(quic); */

        if (config->esni_key_file != NULL && config->esni_rr_file != NULL) {
            ret = picoquic_esni_load_key(quic, config->esni_key_file);
            if (ret == 0) {
                ret = picoquic_esni_server_setup(quic, config->esni_rr_file);
            }
        }

        if (ret != 0) {
            /* Something went wrong */
            DBG_PRINTF("QUIC configuration fails, ret = %d (0x%x)", ret, ret);
            picoquic_free(quic);
            quic = NULL;
        }
    }

    return quic;
}