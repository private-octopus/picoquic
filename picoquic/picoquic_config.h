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

#ifndef PICOQUIC_CONFIG_H
#define PICOQUIC_CONFIG_H

#include <stdio.h>
#include <inttypes.h>
#include "picoquic.h"

#ifdef __cplusplus
extern "C" {
#endif

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
    char const* cc_algo_id;
    picoquic_connection_id_callback_ctx_t* cnx_id_cbdata;
    /* Common flags */
    unsigned int initial_random : 1;
    unsigned int use_long_log : 1;
    /* Server only */
    char const* www_dir;
    /* Server flags */
    unsigned int just_once : 1;
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

int picoquic_config_option_letters(char* option_string, size_t string_max, size_t* string_length);

int picoquic_config_command_line(int opt, int* p_optind, int argc, char const** argv, char const* optarg, picoquic_quic_config_t* config);

int picoquic_config_file(char const* file_name, picoquic_quic_config_t* config);

picoquic_quic_t* picoquic_create_and_configure(picoquic_quic_config_t* config,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    uint64_t current_time,
    uint64_t* p_simulated_time);

#ifdef __cplusplus
}
#endif
#endif PICOQUIC_CONFIG_H