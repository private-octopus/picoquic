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
#include "getopt.h"
#endif
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct st_picoquic_test_def_t {
    char const* test_name;
    int (*test_fn)();
} picoquic_test_def_t;

typedef enum {
    test_not_run = 0,
    test_excluded,
    test_success,
    test_failed
} test_status_t;

static const picoquic_test_def_t test_table[] = {
    { "connection_id_print", util_connection_id_print_test },
    { "connection_id_parse", util_connection_id_parse_test },
    { "sprintf", util_sprintf_test },
    { "memcmp", util_memcmp_test },
    { "threading", util_threading_test },
    { "picohash", picohash_test },
    { "bytestream", bytestream_test },
    { "splay", splay_test },
    { "cnxcreation", cnxcreation_test },
    { "parseheader", parseheadertest },
    { "pn2pn64", pn2pn64test },
    { "intformat", intformattest },
    { "varint", varint_test },
    { "sack", sacktest },
    { "skip_frames", skip_frame_test },
    { "parse_frames", parse_frame_test },
    { "logger", logger_test },
    { "binlog", binlog_test },
    { "TlsStreamFrame", TlsStreamFrameTest },
    { "StreamZeroFrame", StreamZeroFrameTest },
    { "stream_splay", stream_splay_test },
    { "stream_output", stream_output_test },
    { "stream_retransmit_copy", test_copy_for_retransmit },
    { "stream_retransmit_format", test_format_for_retransmit },
    { "sendack", sendacktest },
    { "ackrange", ackrange_test },
    { "ack_of_ack", ack_of_ack_test },
    { "sim_link", sim_link_test },
    { "clear_text_aead", cleartext_aead_test },
    { "pn_ctr", pn_ctr_test },
    { "cleartext_pn_enc", cleartext_pn_enc_test },
    { "cid_for_lb", cid_for_lb_test },
    { "retry_protection_vector", retry_protection_vector_test },
    { "draft17_vector", draft17_vector_test },
    { "esni", esni_test },
    { "pn_enc_1rtt", pn_enc_1rtt_test },
    { "cnxid_stash", cnxid_stash_test },
    { "new_cnxid", new_cnxid_test },
    { "pacing", pacing_test },
    { "tls_api", tls_api_test },
    { "tls_api_inject_hs_ack", tls_api_inject_hs_ack_test },
    { "null_sni", null_sni_test },
    { "silence_test", tls_api_silence_test },
    { "tls_api_version_negotiation", tls_api_version_negotiation_test },
    { "first_loss", tls_api_client_first_loss_test },
    { "second_loss", tls_api_client_second_loss_test },
    { "SH_loss", tls_api_server_first_loss_test },
    { "client_losses", tls_api_client_losses_test },
    { "server_losses", tls_api_server_losses_test },
    { "many_losses", tls_api_many_losses },
    { "ddos_amplification", ddos_amplification_test},
    { "ddos_amplification_0rtt", ddos_amplification_0rtt_test},
    { "blackhole", blackhole_test },
    { "no_ack_frequency", no_ack_frequency_test },
    { "connection_drop", connection_drop_test },
    { "transport_param_stream_id", transport_param_stream_id_test },
    { "stream_rank", stream_rank_test },
    { "stream_id_to_rank", stream_id_to_rank_test},
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
    { "many_short_loss", many_short_loss_test },
    { "retry", tls_api_retry_test },
    { "retry_large", tls_api_retry_large_test},
    { "retry_token", tls_retry_token_test },
    { "retry_token_valid", tls_retry_token_valid_test },
    { "two_connections", tls_api_two_connections_test },
    { "multiple_versions", tls_api_multiple_versions_test },
    { "keep_alive", keep_alive_test },
    { "sockets", socket_test },
    { "socket_ecn", socket_ecn_test },
    { "ticket_store", ticket_store_test },
    { "token_store", token_store_test },
    { "token_reuse_api", token_reuse_api_test },
    { "session_resume", session_resume_test },
    { "zero_rtt", zero_rtt_test },
    { "zero_rtt_loss", zero_rtt_loss_test },
    { "stop_sending", stop_sending_test },
    { "unidir", unidir_test },
    { "mtu_discovery", mtu_discovery_test },
    { "mtu_drop", mtu_drop_test },
    { "red_cc", red_cc_test },
    { "pacing_cc", pacing_cc_test },
    { "spurious_retransmit", spurious_retransmit_test },
    { "tls_zero_share", tls_zero_share_test },
    { "transport_param_log", transport_param_log_test },
    { "bad_certificate", bad_certificate_test },
    { "set_verify_certificate_callback_test", set_verify_certificate_callback_test },
    { "virtual_time" , virtual_time_test },
    { "different_params", tls_different_params_test },
    { "quant_params", tls_quant_params_test },
    { "set_certificate_and_key", set_certificate_and_key_test },
    { "request_client_authentication", request_client_authentication_test },
    { "bad_client_certificate", bad_client_certificate_test },
    { "nat_rebinding", nat_rebinding_test },
    { "nat_rebinding_loss", nat_rebinding_loss_test },
    { "fast_nat_rebinding", fast_nat_rebinding_test},
    { "spin_bit", spin_bit_test},
    { "loss_bit", loss_bit_test},
    { "client_error", client_error_test },
    { "packet_enc_dec", packet_enc_dec_test},
    { "pn_vector", cleartext_pn_vector_test },
    { "zero_rtt_spurious", zero_rtt_spurious_test },
    { "zero_rtt_retry", zero_rtt_retry_test },
    { "zero_rtt_no_coal", zero_rtt_no_coal_test },
    { "zero_rtt_many_losses", zero_rtt_many_losses_test },
    { "zero_rtt_long", zero_rtt_long_test },
    { "zero_rtt_delay", zero_rtt_delay_test },
    { "random_tester", random_tester_test},
    { "random_gauss", random_gauss_test},
    { "random_public_tester", random_public_tester_test},
    { "transmit_cnxid", transmit_cnxid_test },
    { "probe_api", probe_api_test },
    { "migration" , migration_test },
    { "migration_long", migration_test_long },
    { "migration_with_loss", migration_test_loss },
    { "migration_fail", migration_fail_test },
    { "preferred_address", preferred_address_test},
    { "preferred_address_dis_mig", preferred_address_dis_mig_test },
    { "cnxid_renewal",  cnxid_renewal_test },
    { "retire_cnxid", retire_cnxid_test },
    { "not_before_cnxid", not_before_cnxid_test },
    { "server_busy", server_busy_test },
    { "initial_close", initial_close_test },
    { "initial_server_close", initial_server_close_test },
    { "new_rotated_key", new_rotated_key_test },
    { "key_rotation", key_rotation_test },
    { "key_rotation_server", key_rotation_auto_server },
    { "key_rotation_client", key_rotation_auto_client },
    { "false_migration", false_migration_test },
    { "nat_handshake", nat_handshake_test },
    { "key_rotation_vector", key_rotation_vector_test },
    { "key_rotation_stress", key_rotation_stress_test },
    { "short_initial_cid", short_initial_cid_test },
    { "stream_id_max", stream_id_max_test },
    { "padding_test", padding_test },
    { "packet_trace", packet_trace_test },
    { "qlog_trace", qlog_trace_test },
    { "qlog_trace_auto", qlog_trace_auto_test },
    { "qlog_trace_only", qlog_trace_only_test },
    { "qlog_trace_ecn", qlog_trace_ecn_test },
    { "rebiding_stress", rebinding_stress_test },
    { "ready_to_send", ready_to_send_test },
    { "cubic", cubic_test },
    { "cubic_jitter", cubic_jitter_test },
    { "fastcc", fastcc_test },
    { "fastcc_jitter", fastcc_jitter_test },
    { "bbr", bbr_test },
    { "bbr_jitter", bbr_jitter_test },
    { "bbr_long", bbr_long_test },
    { "bbr_performance", bbr_performance_test },
    { "bbr_slow_long", bbr_slow_long_test },
    { "bbr_one_second", bbr_one_second_test },
    { "bbr_gbps", gbps_performance_test },
    { "long_rtt", long_rtt_test },
    { "satellite_basic", satellite_basic_test },
    { "satellite_loss", satellite_loss_test },
    { "satellite_jitter", satellite_jitter_test },
    { "satellite_medium", satellite_medium_test },
    { "satellite_small", satellite_small_test },
    { "satellite_small_up", satellite_small_up_test },
    { "cid_length", cid_length_test },
    { "optimistic_ack", optimistic_ack_test },
    { "optimistic_hole", optimistic_hole_test },
    { "bad_coalesce", bad_coalesce_test },
    { "bad_cnxid", bad_cnxid_test },
    { "document_addresses", document_addresses_test },
    { "large_client_hello", large_client_hello_test },
    { "send_stream_blocked", send_stream_blocked_test },
    { "queue_network_input", queue_network_input_test },
    { "pacing_update", pacing_update_test },
    { "direct_receive", direct_receive_test },
    { "app_limit_cc", app_limit_cc_test },
    { "initial_race", initial_race_test },
    { "chacha20", chacha20_test },
    { "cid_quiescence", cid_quiescence_test },
    { "migration_controlled", migration_controlled_test },
    { "migration_mtu_drop", migration_mtu_drop_test },
    { "grease_quic_bit", grease_quic_bit_test },
    { "grease_quic_bit_one_way", grease_quic_bit_one_way_test },
    { "cplusplus", cplusplustest },
    { "stress", stress_test },
    { "fuzz", fuzz_test },
    { "fuzz_initial", fuzz_initial_test}
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
    fprintf(stderr, "PicoQUIC test execution\n");
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
    fprintf(stderr, "  -x test           Do not run the specified test.\n");
    fprintf(stderr, "  -s nnn            Run stress for nnn minutes.\n");
    fprintf(stderr, "  -f nnn            Run fuzz for nnn minutes.\n");
    fprintf(stderr, "  -n                Disable debug prints.\n");
    fprintf(stderr, "  -r                Retry failed tests with debug print enabled.\n");
    fprintf(stderr, "  -h                Print this help message\n");
    fprintf(stderr, "  -S solution_dir   Set the path to the source files to find the default files\n");

    return -1;
}

int get_test_number(char const * test_name)
{
    int test_number = -1;

    for (size_t i = 0; i < nb_tests; i++) {
        if (strcmp(test_name, test_table[i].test_name) == 0) {
            test_number = (int)i;
        }
    }

    return test_number;
}

int main(int argc, char** argv)
{
    int ret = 0;
    int nb_test_tried = 0;
    int nb_test_failed = 0;
    int stress_minutes = 0;
    int found_exclusion = 0;
    test_status_t * test_status = (test_status_t *) calloc(nb_tests, sizeof(test_status_t));
    int opt;
    int do_fuzz = 0;
    int do_stress = 0;
    int disable_debug = 0;
    int retry_failed_test = 0;

    if (test_status == NULL)
    {
        fprintf(stderr, "Could not allocate memory.\n");
        ret = -1;
    }
    else
    {
        while (ret == 0 && (opt = getopt(argc, argv, "f:s:S:x:nrh")) != -1) {
            switch (opt) {
            case 'x': {
                int test_number = get_test_number(optarg);

                if (test_number < 0) {
                    fprintf(stderr, "Incorrect test name: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                else {
                    test_status[test_number] = test_excluded;
                    found_exclusion = 1;
                }
                break;
            }
            case 'f':
                do_fuzz = 1;
                stress_minutes = atoi(optarg);
                if (stress_minutes <= 0) {
                    fprintf(stderr, "Incorrect stress minutes: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                break;
            case 's':
                do_stress = 1;
                stress_minutes = atoi(optarg);
                if (stress_minutes <= 0) {
                    fprintf(stderr, "Incorrect stress minutes: %s\n", optarg);
                    ret = usage(argv[0]);
                }
                break;
            case 'S':
                picoquic_set_solution_dir(optarg);
                break;
            case 'n':
                disable_debug = 1;
                break;
            case 'r':
                retry_failed_test = 1;
                break;
            case 'h':
                usage(argv[0]);
                exit(0);
                break;
            default:
                ret = usage(argv[0]);
                break;
            }
        }

        if (disable_debug) {
            debug_printf_suspend();
        }
        else {
            debug_printf_push_stream(stderr);
        }

        if (ret == 0 && stress_minutes > 0) {
            if (optind >= argc && found_exclusion == 0) {
                for (size_t i = 0; i < nb_tests; i++) {
                    if (strcmp(test_table[i].test_name, "stress") == 0)
                    {
                        if (do_stress == 0) {
                            test_status[i] = test_excluded;
                        }
                    }
                    else if (strcmp(test_table[i].test_name, "fuzz") == 0) {
                        if (do_fuzz == 0) {
                            test_status[i] = test_excluded;
                        }
                    }
                    else {
                        test_status[i] = test_excluded;
                    }
                }
                picoquic_stress_test_duration = stress_minutes;
                picoquic_stress_test_duration *= 60000000;
            }
        }

        if (ret == 0)
        {
            if (optind >= argc) {
                for (size_t i = 0; i < nb_tests; i++) {
                    if (test_status[i] == test_not_run) {
                        nb_test_tried++;
                        if (do_one_test(i, stdout) != 0) {
                            test_status[i] = test_failed;
                            nb_test_failed++;
                            ret = -1;
                        }
                        else {
                            test_status[i] = test_success;
                        }
                    }
                    else if (stress_minutes == 0) {
                        fprintf(stdout, "Test number %d (%s) is bypassed.\n", (int)i, test_table[i].test_name);
                    }
                }
            }
            else {
                for (int arg_num = optind; arg_num < argc; arg_num++) {
                    int test_number = get_test_number(argv[arg_num]);

                    if (test_number < 0) {
                        fprintf(stderr, "Incorrect test name: %s\n", argv[arg_num]);
                        ret = usage(argv[0]);
                    }
                    else {
                        nb_test_tried++;
                        if (do_one_test(test_number, stdout) != 0) {
                            test_status[test_number] = test_failed;
                            nb_test_failed++;
                            ret = -1;
                        }
                        else if (test_status[test_number] == test_not_run) {
                            test_status[test_number] = test_success;
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

        if (nb_test_failed > 0) {
            fprintf(stdout, "Failed test(s): ");
            for (size_t i = 0; i < nb_tests; i++) {
                if (test_status[i] == test_failed) {
                    fprintf(stdout, "%s ", test_table[i].test_name);
                }
            }
            fprintf(stdout, "\n");

            if (disable_debug && retry_failed_test) {
                /* debug_printf_push_stream(stderr); */
                debug_printf_resume();
                ret = 0;
                for (size_t i = 0; i < nb_tests; i++) {
                    int is_fuzz = 0;
                    if (strcmp("stress", test_table[i].test_name) == 0 ||
                        strcmp("fuzz", test_table[i].test_name) == 0 ||
                        strcmp("fuzz_initial", test_table[i].test_name) == 0) {
                        is_fuzz = 1;
                    }
                    if (test_status[i] == test_failed) {
                        fprintf(stdout, "Retrying %s:\n", test_table[i].test_name);
                        if (is_fuzz) {
                            debug_printf_suspend();
                        }
                        if (do_one_test(i, stdout) != 0) {
                            test_status[i] = test_failed;
                            ret = -1;
                        }
                        else {
                            /* This was a Heisenbug.. */
                            test_status[i] = test_success;
                        }
                        if (is_fuzz) {
                            debug_printf_resume();
                        }
                    }
                }
                if (ret == 0) {
                    fprintf(stdout, "All tests pass after second try.\n");
                }
                else {
                    fprintf(stdout, "Still failing: ");
                    for (size_t i = 0; i < nb_tests; i++) {
                        if (test_status[i] == test_failed) {
                            fprintf(stdout, "%s ", test_table[i].test_name);
                        }
                    }
                    fprintf(stdout, "\n");
                }
            }
        }

        free(test_status);
    }
    return (ret);
}
