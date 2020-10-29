/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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
 * TODO: get options from file
 * TODO: version of picoquic_create taking configuration as input
 * ToDO: organize as hierarchy of calls, eg app -> protocol -> quic.
 */

#include <stdio.h>
#include <stdint.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquic_binlog.h"
#include "picoquic_logger.h"

char const* picoquic_options = "c:k:K:p:u:v:o:w:f:i:s:e:E:C:l:b:q:m:n:a:t:S:I:G:1rRhzDLQ";

typedef struct st_picoquic_quic_config_t {
    uint32_t nb_connections;
    char const* solution_dir;
    char const* server_cert_file;
    char const* server_key_file;
    char const* esni_key_file;
    char const* esni_rr_file;
    char const* log_file;
    char const* bin_dir;
    char const* qlog_dir;
    char const* ticket_file_name;
    const uint8_t* ticket_encryption_key;
    size_t ticket_encryption_key_length;
    int server_port;
    int dest_if;
    int nb_packets_before_update;
    int mtu_max;
    const picoquic_congestion_algorithm_t* cc_algorithm;
    picoquic_connection_id_callback_ctx_t* cnx_id_cbdata;
    /* Common flags */
    unsigned int initial_random : 1;
    unsigned int use_long_log : 1;
    /* Server only */
    char const* www_dir;
    /* Server flags */
    unsigned int just_once : 1;
    unsigned int flag : 1;
    unsigned int do_retry : 1;
    uint64_t reset_seed[2];

    /* Client only */
    char const* sni;
    char const* alpn;
    char const* out_dir;
    char const* root_trust_file;
    int cipher_suite_id;
    uint32_t proposed_version; 
    unsigned int force_zero_share : 1;
    unsigned int no_disk : 1;
    unsigned int large_client_hello : 1;
    int force_migration;
    int client_cnx_id_length;

} picoquic_quic_config_t;

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


int picoquic_config_command_line(int opt, int * p_optind, int argc, char const ** argv, char const* optarg, picoquic_quic_config_t * config)
{
    int ret = 0;

    /* Get the parameters */
    switch (opt) {
    case 'c':
        config->server_cert_file = optarg;
        break;
    case 'k':
        config->server_key_file = optarg;
        break;
    case 'K':
        config->esni_key_file = optarg;
        break;
    case 'p':
        if ((config->server_port = atoi(optarg)) <= 0) {
            fprintf(stderr, "Invalid port: %s\n", optarg);
            ret = -1;
        }
        break;
    case 'u':
        if ((config->nb_packets_before_update = atoi(optarg)) <= 0) {
            fprintf(stderr, "Invalid number of packets: %s\n", optarg);
            ret = -1;
        }
        break;
    case 'v':
        if ((config->proposed_version = config_parse_target_version(optarg)) <= 0) {
            fprintf(stderr, "Invalid version: %s\n", optarg);
            ret = -1;
        }
        break;
    case 'o':
        config->out_dir = optarg;
        break;
    case 'w':
        config->www_dir = optarg;
        break;
    case '1':
        config->just_once = 1;
        break;
    case 'r':
        config->do_retry = 1;
        break;
    case 'R':
        config->initial_random = 1;
        break;
    case 's':
        if (*p_optind + 1 > argc) {
            fprintf(stderr, "option requires more arguments -- s\n");
            ret = -1;
        }
        config->reset_seed[1] = strtoul(optarg, NULL, 0);
        config->reset_seed[0] = strtoul(argv[*p_optind], NULL, 0);
        *p_optind += 1;
        break;
    case 'S':
        config->solution_dir = optarg;
        break;
    case 'G':
        config->cc_algorithm = picoquic_get_congestion_algorithm(optarg);
        if (config->cc_algorithm == NULL) {
            fprintf(stderr, "Unsupported congestion control algorithm: %s\n", optarg);
            ret = -1;
        }
        break;
    case 'e':
        config->dest_if = atoi(optarg);
        break;
    case 'C':
        config->cipher_suite_id = atoi(optarg);
        break;
    case 'E':
        config->esni_rr_file = optarg;
        break;
    case 'i':
        if (*p_optind + 2 > argc) {
            fprintf(stderr, "option requires more arguments -- i\n");
            ret = -1;
        }
        config->cnx_id_cbdata = picoquic_connection_id_callback_create_ctx(optarg, argv[*p_optind], argv[p_optind[1]]);
        if (config->cnx_id_cbdata == NULL) {
            fprintf(stderr, "could not create callback context (%s, %s, %s)\n", optarg, argv[*p_optind], argv[p_optind[1]]);
            ret = -1;
        }
        *p_optind += 2;
        break;
    case 'l':
        config->log_file = optarg;
        break;
    case 'L':
        config->use_long_log = 1;
        break;
    case 'b':
        config->bin_dir = optarg;
        break;
    case 'q':
        config->qlog_dir = optarg;
        break;
    case 'm':
        config->mtu_max = atoi(optarg);
        if (config->mtu_max <= 0 || config->mtu_max > PICOQUIC_MAX_PACKET_SIZE) {
            fprintf(stderr, "Invalid max mtu: %s\n", optarg);
            ret = -1;
        }
        break;
    case 'n':
        config->sni = optarg;
        break;
    case 'a':
        config->alpn = optarg;
        break;
    case 't':
        config->root_trust_file = optarg;
        break;
    case 'z':
        config->force_zero_share = 1;
        break;
    case 'f':
        config->force_migration = atoi(optarg);
        if (config->force_migration <= 0 || config->force_migration > 3) {
            fprintf(stderr, "Invalid migration mode: %s\n", optarg);
            ret = -1;
        }
        break;
    case 'I':
        config->client_cnx_id_length = atoi(optarg);
        if (config->client_cnx_id_length < 0 || config->client_cnx_id_length > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
            fprintf(stderr, "Invalid connection id length: %s\n", optarg);
            ret = -1;
        }
        break;
    case 'D':
        config->no_disk = 1;
        break;
    case 'Q':
        config->large_client_hello = 1;
        break;
    case 'h':
        ret = -1;
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

int picoquic_config_file(char const* file_name, picoquic_quic_config_t* config)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(config);
#endif
    int ret = 0;
    FILE* F = picoquic_file_open(file_name, "r");
    if (F == NULL) {
        DBG_PRINTF("Could not open configuration file: %s", file_name);
        ret = -1;
    }
    else {
        char line[1024];

        while (fgets(line, sizeof(line), F) != NULL) {
            /* Parse the line. Expect format: <arg_id>":" spaces* argv1 [space ^spaces argvn]* */

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

        if (config->cc_algorithm == NULL) {
            config->cc_algorithm = picoquic_bbr_algorithm;
        }
        picoquic_set_default_congestion_algorithm(quic, config->cc_algorithm);

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