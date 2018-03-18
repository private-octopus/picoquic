/*
* Author: Christian Huitema
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
#ifdef _WINDOWS
#include "../picoquicfirst/getopt.h"
#endif
#include "../picoquic/picoquic.h"
#include "../picoquic/util.h"
#include "../picoquictest/picoquictest.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct st_picoquic_test_def_t {
    char const* test_name;
    int (*test_fn)();
} picoquic_test_def_t;

static const picoquic_test_def_t test_table[] = {
    { "picohash", picohash_test },
    { "cnxcreation", cnxcreation_test },
    { "parseheader", parseheadertest },
    { "pn2pn64", pn2pn64test },
    { "intformat", intformattest },
    { "fnv1a", fnv1atest },
    { "float16", float16test },
    { "varint", varint_test },
    { "skip_frames", skip_frame_test },
    { "StreamZeroFrame", StreamZeroFrameTest },
    { "sack", sacktest },
    { "sendack", sendacktest },
    { "ackrange", ackrange_test },
    { "ack_of_ack", ack_of_ack_test },
    { "sim_link", sim_link_test },
    { "logger", logger_test },
    { "tls_api", tls_api_test },
    { "silence_test", tls_api_silence_test },
    { "tls_api_version_negotiation", tls_api_version_negotiation_test },
    { "first_loss", tls_api_client_first_loss_test },
    { "second_loss", tls_api_client_second_loss_test },
    { "SH_loss", tls_api_server_first_loss_test },
    { "client_losses", tls_api_client_losses_test },
    { "server_losses", tls_api_server_losses_test },
    { "transport_param", transport_param_test },
    { "tls_api_sni", tls_api_sni_test },
    { "tls_api_alpn", tls_api_alpn_test },
    { "tls_api_wrong_alpn", tls_api_wrong_alpn_test },
    { "tls_api_oneway_stream", tls_api_oneway_stream_test },
    { "tls_api_q_and_r_stream", tls_api_q_and_r_stream_test },
    { "tls_api_q2_and_r2_stream", tls_api_q2_and_r2_stream_test },
    { "tls_api_server_reset", tls_api_server_reset_test },
    { "tls_api_bad_server_reset", tls_api_bad_server_reset_test },
    { "tls_api_very_long_stream", tls_api_very_long_stream_test },
    { "tls_api_very_long_max", tls_api_very_long_max_test },
    { "tls_api_very_long_with_err", tls_api_very_long_with_err_test },
    { "tls_api_very_long_congestion", tls_api_very_long_congestion_test },
    { "http0dot9", http0dot9_test },
    { "hrr", tls_api_hrr_test },
    { "two_connections", tls_api_two_connections_test },
    { "clear_text_aead", cleartext_aead_test },
    { "multiple_versions", tls_api_multiple_versions_test },
    { "ping_pong", ping_pong_test },
    { "keep_alive", keep_alive_test },
    { "transport_parameter_client_error", transport_parameter_client_error_test },
    { "sockets", socket_test },
    { "ticket_store", ticket_store_test },
    { "session_resume", session_resume_test },
    { "zero_rtt", zero_rtt_test },
    { "stop_sending", stop_sending_test },
    { "unidir", unidir_test },
    { "mtu_discovery", mtu_discovery_test },
    { "spurious_retransmit", spurious_retransmit_test },
    { "wrong_keyshare", wrong_keyshare_test },
    { "pn_ctr", pn_ctr_test},
    { "cleartext_pn_enc", cleartext_pn_enc_test},
    { "pn_enc_1rtt", pn_enc_1rtt_test },
    { "tls_zero_share", tls_zero_share_test },
    { "cleartext_aead_vector", cleartext_aead_vector_test },
    { "transport_param_log", transport_param_log_test },
    { "bad_certificate", bad_certificate_test },
    { "set_verify_certificate_callback_test", set_verify_certificate_callback_test },
    { "virtual_time" , virtual_time_test },
{"different_params", tls_different_params_test }
};

static size_t const nb_tests = sizeof(test_table) / sizeof(picoquic_test_def_t);

static int do_one_test(size_t i, FILE* F)
{
    int ret = 0;

    if (i >= nb_tests) {
        fprintf(F, "Invalid test number %" PRIst "\n", i);
        ret = -1;
    } else {
        fprintf(F, "Starting test number %" PRIst ", %s\n", i, test_table[i].test_name);

        fflush(F);

        ret = test_table[i].test_fn();
        if (ret == 0) {
            fprintf(F, "    Success.\n");
        } else {
            fprintf(F, "    Fails, error: %d.\n", ret);
        }
    }

    fflush(F);

    return ret;
}

int usage(char const * argv0)
{
    fprintf(stderr, "PicoQUIC test exexution\n");
    fprintf(stderr, "Usage: picoquic_ct [-x <excluded>] [<list of tests]\n");
    fprintf(stderr, "\nUsage: %s [test1 [test2 ..[testN]]]\n\n", argv0);
    fprintf(stderr, "   Or: %s [-x test]*", argv0);
    fprintf(stderr, "Valid test names are: \n");
    for (size_t x = 0; x < nb_tests; x++) {
        fprintf(stderr, "    ");

        for (int j = 0; j < 4 && x < nb_tests; j++, x++) {
            fprintf(stderr, "%s, ", test_table[x].test_name);
        }
        fprintf(stderr, "\n");
    }
    fprintf(stderr, "Options: \n");
    fprintf(stderr, "  -x test        Do not run the specified test.\n");
    fprintf(stderr, "  -h             Print this help message\n");

    return -1;
}

int get_test_number(char const * test_name)
{
    int test_number = -1;

    for (size_t i = 0; i < nb_tests; i++) {
        if (strcmp(test_name, test_table[i].test_name) == 0) {
            test_number = i;
        }
    }

    return test_number;
}

int main(int argc, char** argv)
{
    int ret = 0;
    int nb_test_tried = 0;
    int nb_test_failed = 0;
    int * is_excluded = malloc(sizeof(int)*nb_tests);
    int opt;

    if (is_excluded == NULL)
    {
        fprintf(stderr, "Could not allocate memory.\n");
        ret = -1;
    }
    else
    {
        memset(is_excluded, 0, sizeof(int)*nb_tests);

        while (ret == 0 && (opt = getopt(argc, argv, "x:h")) != -1) {
            switch (opt) {
            case 'x': {
                int test_number = get_test_number(optarg);

                if (test_number < 0) {
                    fprintf(stderr, "Incorrect test name: %s\n", optarg);
                    usage(argv[0]);
                }
                else {
                    is_excluded[test_number] = 1;
                }
                break;
            }
            case 'h':
                usage(argv[0]);
                break;
            }
        }

        if (ret == 0)
        {
            if (optind >= argc) {
                for (size_t i = 0; i < nb_tests; i++) {
                    if (is_excluded[i] == 0) {
                        nb_test_tried++;
                        if (do_one_test(i, stdout) != 0) {
                            nb_test_failed++;
                            ret = -1;
                        }
                    }
                    else {
                        fprintf(stderr, "test number %d (%s) is bypassed.\n", (int)i, test_table[i].test_name);
                    }
                }
            } else {
                for (int arg_num = optind; arg_num < argc; arg_num++) {
                    int test_number = get_test_number(argv[arg_num]);

                    if (test_number < 0) {
                        fprintf(stderr, "Incorrect test name: %s\n", argv[arg_num]);
                        usage(argv[0]);
                    }
                    else {
                        nb_test_tried++;
                        if (do_one_test(test_number, stdout) != 0) {
                            nb_test_failed++;
                            ret = -1;
                        }
                        break;
                    }
                }
            }
        }

        if (nb_test_tried > 1) {
            fprintf(stdout, "Tried %d tests, %d fail%s.\n", nb_test_tried,
                nb_test_failed, (nb_test_failed > 1) ? "" : "s");
        }

        free(is_excluded);
    }
    return (ret);
}
