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

#ifndef PICOQUICTEST_H
#define PICOQUICTEST_H

#ifdef __cplusplus
extern "C" {
#endif

/* From picoquic/picoquic_utils.h */
void debug_printf_suspend();

/* Control variables for the duration of the stress test */

extern uint64_t picoquic_stress_test_duration; /* In microseconds; defaults to 2 minutes */

/* List of test functions */
int util_connection_id_print_test();
int util_connection_id_parse_test();
int util_sprintf_test();
int util_memcmp_test();
int util_threading_test();
int picohash_test();
int bytestream_test();
int cnxcreation_test();
int parseheadertest();
int incoming_initial_test();
int header_length_test();
int pn2pn64test();
int intformattest();
int sacktest();
int StreamZeroFrameTest();
int sendacktest();
int tls_api_test();
int tls_api_inject_hs_ack_test();
int tls_api_silence_test();
int tls_api_loss_test(uint64_t mask);
int tls_api_client_first_loss_test();
int tls_api_client_second_loss_test();
int tls_api_server_first_loss_test();
int tls_api_many_losses();
int tls_api_version_negotiation_test();
int tls_api_version_invariant_test();
int test_version_negotiation_spoof();
int transport_param_test();
int tls_api_sni_test();
int tls_api_alpn_test();
int tls_api_wrong_alpn_test();
int tls_api_oneway_stream_test();
int tls_api_q_and_r_stream_test();
int tls_api_q2_and_r2_stream_test();
int stateless_reset_test();
int stateless_reset_bad_test();
int stateless_reset_client_test();
int stateless_reset_handshake_test();
int immediate_close_test();
int sim_link_test();
int tls_api_very_long_stream_test();
int tls_api_very_long_max_test();
int tls_api_very_long_with_err_test();
int tls_api_very_long_congestion_test();
int tls_api_retry_test();
int tls_api_retry_large_test();
int ackrange_test();
int ack_of_ack_test();
int ack_disorder_test();
int ack_horizon_test();
int tls_api_two_connections_test();
int cleartext_aead_test();
int tls_api_multiple_versions_test();
int varint_test();
int tls_api_client_losses_test();
int tls_api_server_losses_test();
int skip_frame_test();
int keep_alive_test();
int logger_test();
int binlog_test();
int app_message_overflow_test();
int socket_test();
int test_stateless_blowback();
int ticket_store_test();
int ticket_seed_test();
int ticket_seed_from_bdp_frame_test();
int token_store_test();
int session_resume_test();
int zero_rtt_test();
int zero_rtt_loss_test();
int stop_sending_test();
int discard_stream_test();
int unidir_test();
int mtu_discovery_test();
int mtu_blocked_test();
int mtu_delayed_test();
int mtu_required_test();
int mtu_max_test();
int mtu_drop_test();
int spurious_retransmit_test();
int pn_ctr_test();
int cleartext_pn_enc_test();
int pn_enc_1rtt_test();
int tls_zero_share_test();
int transport_param_log_test();
int bad_certificate_test();
int set_verify_certificate_callback_test();
int virtual_time_test();
int tls_different_params_test();
int tls_quant_params_test();
int set_certificate_and_key_test();
int transport_param_stream_id_test();
int vn_tp_test();
int vn_compat_test();
int request_client_authentication_test();
int bad_client_certificate_test();
int nat_rebinding_test();
int nat_rebinding_loss_test();
int nat_rebinding_zero_test();
int nat_rebinding_latency_test();
int spin_bit_test();
int loss_bit_test();
int client_error_test();
int client_only_test();
int packet_enc_dec_test();
int cleartext_pn_vector_test();
int zero_rtt_spurious_test();
int zero_rtt_retry_test();
int zero_rtt_no_coal_test();
int zero_rtt_many_losses_test();
int zero_rtt_long_test();
int zero_rtt_delay_test();
int parse_frame_test();
int stress_test();
int cnx_stress_unit_test();
int cnx_stress_do_test(uint64_t duration, int nb_clients, int do_report);
int cnx_ddos_unit_test();
int cnx_ddos_test_loop(int nb_connections, uint64_t ddos_interval, const char* qlogdir);
int splay_test();
int TlsStreamFrameTest();
int draft17_vector_test();
int fuzz_test();
int random_tester_test();
int random_gauss_test();
int random_public_tester_test();
int cnxid_stash_test();
int new_cnxid_test();
int transmit_cnxid_test();
int transmit_cnxid_disable_test();
int transmit_cnxid_retire_before_test();
int transmit_cnxid_retire_disable_test();
int probe_api_test();
int migration_test();
int migration_test_long(); 
int migration_test_loss();
int migration_zero_test();
int migration_fail_test();
int cnxid_renewal_test();
int retire_cnxid_test();
int server_busy_test();
int initial_close_test();
int fuzz_initial_test();
int new_rotated_key_test();
int key_rotation_test();
int key_rotation_auto_server();
int key_rotation_auto_client();
int false_migration_test();
int nat_handshake_test();
int key_rotation_vector_test();
int key_rotation_stress_test();
int short_initial_cid_test();
int stream_id_max_test();
int stream_id_to_rank_test();
int padding_test();
int packet_trace_test();
int qlog_trace_test();
int qlog_trace_auto_test();
int qlog_trace_only_test();
int qlog_trace_ecn_test();
int path_packet_queue_test();
int perflog_test();
int rebinding_stress_test();
int many_short_loss_test();
int random_padding_test();
int ec00_zero_test();
int ec2f_second_flight_nack_test();
void eccf_corrupted_file_fuzz(int nb_trials, uint64_t seed, FILE* seed_report);
int eccf_corrupted_file_fuzz_test();
int eca1_amplification_loss_test();
int ecf1_final_loss_test();
int ec5c_silly_cid_test();
int ec9a_preemptive_amok_test();
int error_reason_test();
int ready_to_send_test();
int ready_to_skip_test();
int ready_to_zero_test();
int ready_to_zfin_test();
int cubic_test();
int cubic_jitter_test();
int satellite_basic_test();
int satellite_seeded_test();
int satellite_loss_test();
int satellite_jitter_test();
int satellite_medium_test();
int satellite_preemptive_test();
int satellite_preemptive_fc_test();
int satellite_small_test();
int satellite_small_up_test();
int satellite_cubic_test();
int satellite_cubic_loss_test();
int bdp_basic_test();
int bdp_reno_test();
int bdp_cubic_test();
int bdp_rtt_test();
int bdp_ip_test();
int bdp_delay_test();
int long_rtt_test();
int high_latency_basic_test();
int high_latency_bbr_test();
int high_latency_cubic_test();
int high_latency_probeRTT_test();
int cid_length_test();
int initial_server_close_test();
int h3zero_integer_test();
int qpack_huffman_test();
int qpack_huffman_base_test();
int h3zero_parse_qpack_test();
int h3zero_prepare_qpack_test();
int h3zero_user_agent_test();
int h3zero_null_sni_test();
int h3zero_qpack_fuzz_test();
int h3zero_stream_test();
int parse_demo_scenario_test();
int h3zero_server_test();
int h09_server_test();
int h09_header_test();
int generic_server_test();
int esni_test();
int tls_retry_token_test();
int tls_retry_token_valid_test();
int optimistic_ack_test();
int optimistic_hole_test();
int document_addresses_test();
int socket_ecn_test();
int null_sni_test();
int preferred_address_test();
int preferred_address_dis_mig_test();
int preferred_address_zero_test();
int cid_for_lb_test();
int cid_for_lb_cli_test();
int retry_protection_vector_test();
int test_copy_for_retransmit();
int test_format_for_retransmit();
int bad_coalesce_test();
int bad_cnxid_test();
int stream_splay_test();
int stream_output_test();
int stream_rank_test();
int not_before_cnxid_test();
int send_stream_blocked_test();
int stream_ack_test();
int queue_network_input_test();
int fastcc_test();
int fastcc_jitter_test();
int bbr_test();
int bbr_jitter_test();
int bbr_long_test();
int bbr_performance_test();
int bbr_slow_long_test();
int bbr_one_second_test();
int gbps_performance_test();
int bbr_asym100_test();
int bbr_asym100_nodelay_test();
int bbr_asym400_test();
int large_client_hello_test();
int fast_nat_rebinding_test();
int datagram_test();
int datagram_rt_test();
int datagram_loss_test();
int datagram_size_test();
int datagram_small_test();
int ddos_amplification_test();
int ddos_amplification_0rtt_test();
int ddos_amplification_8k_test();
int blackhole_test();
int no_ack_frequency_test();
int connection_drop_test();
int pacing_update_test();
int direct_receive_test();
int app_limit_cc_test();
int initial_race_test();
int pacing_test();
int chacha20_test();
int cnx_limit_test();
int cert_verify_bad_cert_test();
int cert_verify_bad_sni_test();
int cert_verify_null_test();
int cert_verify_null_sni_test();
int cert_verify_rsa_test();
int cid_quiescence_test();
int migration_controlled_test();
int migration_mtu_drop_test();
int monopath_basic_test();
int monopath_hole_test();
int monopath_rotation_test();
int monopath_0rtt_test();
int monopath_0rtt_loss_test();
int multipath_aead_test();
int multipath_basic_test();
int multipath_drop_first_test();
int multipath_drop_second_test();
int multipath_sat_plus_test();
int multipath_renew_test();
int multipath_rotation_test();
int multipath_nat_test();
int multipath_break1_test();
int multipath_abandon_test();
int multipath_back1_test();
int multipath_perf_test();
int multipath_qlog_test();
int simple_multipath_basic_test();
int simple_multipath_drop_first_test();
int simple_multipath_drop_second_test();
int simple_multipath_sat_plus_test();
int simple_multipath_renew_test();
int simple_multipath_rotation_test();
int simple_multipath_nat_test();
int simple_multipath_break1_test();
int simple_multipath_abandon_test();
int simple_multipath_back1_test();
int simple_multipath_perf_test();
int simple_multipath_qlog_test();
int token_reuse_api_test();
int grease_quic_bit_test();
int grease_quic_bit_one_way_test();
int pn_random_test();
int port_blocked_test();
int red_cc_test();
int multi_segment_test();
int pacing_cc_test();
int integrity_limit_test();
int excess_repeat_test();
int netperf_basic_test();
int netperf_bbr_test();
int nat_attack_test();
int config_option_letters_test();
int config_option_test();

int h3zero_post_test();
int h09_post_test();
int demo_alpn_test();
int demo_file_sanitize_test();
int demo_file_access_test();
int demo_server_file_test();
int h3zero_satellite_test();
int h09_satellite_test();
int h09_lone_fin_test();
int http_stress_test();
int http_corrupt_test();
int http_corrupt_rdpn_test();
int http_drop_test();
int http_esni_test();
int h3_long_file_name_test();
int h3_multi_file_test();
int h3_multi_file_loss_test();
int h3_multi_file_preemptive_test();
int h09_multi_file_test();
int h09_multi_file_loss_test();
int h09_multi_file_preemptive_test();

int cplusplustest();

#ifdef __cplusplus
}
#endif

#endif /* PICOQUICTEST_H */
