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

/* From picoquic/util.h */
void debug_printf_suspend();

/* Setting the solution dir when not executing from default location */
void picoquic_test_set_solution_dir(char const * solution_dir);

/* Control variables for the duration of the stress test */

extern uint64_t picoquic_stress_test_duration; /* In microseconds; defaults to 2 minutes */

/* List of test functions */
int picohash_test();
int cnxcreation_test();
int parseheadertest();
int pn2pn64test();
int intformattest();
int fnv1atest();
int sacktest();
int float16test();
int StreamZeroFrameTest();
int sendacktest();
int tls_api_test();
int tls_api_silence_test();
int tls_api_loss_test(uint64_t mask);
int tls_api_client_first_loss_test();
int tls_api_client_second_loss_test();
int tls_api_server_first_loss_test();
int tls_api_many_losses();
int tls_api_version_negotiation_test();
int transport_param_test();
int tls_api_sni_test();
int tls_api_alpn_test();
int tls_api_wrong_alpn_test();
int tls_api_oneway_stream_test();
int tls_api_q_and_r_stream_test();
int tls_api_q2_and_r2_stream_test();
int tls_api_server_reset_test();
int tls_api_bad_server_reset_test();
int sim_link_test();
int tls_api_very_long_stream_test();
int tls_api_very_long_max_test();
int tls_api_very_long_with_err_test();
int tls_api_very_long_congestion_test();
int http0dot9_test();
int tls_api_retry_test();
int ackrange_test();
int ack_of_ack_test();
int tls_api_two_connections_test();
int cleartext_aead_test();
int tls_api_multiple_versions_test();
int varint_test();
int tls_api_client_losses_test();
int tls_api_server_losses_test();
int skip_frame_test();
int keep_alive_test();
int logger_test();
int socket_test();
int ticket_store_test();
int token_store_test();
int session_resume_test();
int zero_rtt_test();
int zero_rtt_loss_test();
int stop_sending_test();
int unidir_test();
int mtu_discovery_test();
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
int request_client_authentication_test();
int bad_client_certificate_test();
int nat_rebinding_test();
int nat_rebinding_loss_test();
int spin_bit_test();
int client_error_test();
int packet_enc_dec_test();
int cleartext_pn_vector_test();
int zero_rtt_spurious_test();
int zero_rtt_retry_test();
int parse_frame_test();
int stress_test();
int splay_test();
int TlsStreamFrameTest();
int draft17_vector_test();
int fuzz_test();
int random_tester_test();
int random_public_tester_test();
int cnxid_stash_test();
int new_cnxid_test();
int transmit_cnxid_test();
int probe_api_test();
int migration_test();
int migration_test_long(); 
int migration_test_loss();
int cnxid_renewal_test();
int retire_cnxid_test();
int server_busy_test();
int initial_close_test();
int fuzz_initial_test();
int new_rotated_key_test();
int key_rotation_test();
int false_migration_test();
int nat_handshake_test();
int key_rotation_vector_test();
int key_rotation_stress_test();
int short_initial_cid_test();
int stream_id_max_test();
int stream_id_to_rank_test();
int padding_test();
int packet_trace_test();
int rebinding_stress_test();
int many_short_loss_test();
int ready_to_send_test();
int split_stream_frame_test();
int cubic_test();
int long_rtt_test();
int cid_length_test();
int initial_server_close_test();
int h3zero_integer_test();
int qpack_huffman_test();
int h3zero_parse_qpack_test();
int h3zero_prepare_qpack_test();
int h3zero_stream_test();
int parse_demo_scenario_test();
int h3zero_server_test();
int h09_server_test();
int generic_server_test();
int esni_test();
int tls_retry_token_test();
int optimistic_ack_test();
int optimistic_hole_test();
int document_addresses_test();
int socket_ecn_test();
int null_sni_test();
int preferred_address_test();
int cid_global_encrypt_test();
int cid_mask_encrypt_test();
int test_copy_for_retransmit();
int bad_coalesce_test();
int stream_splay_test();
int stream_output_test();
int stream_rank_test();
int not_before_cnxid_test();

#ifdef __cplusplus
}
#endif

#endif /* PICOQUICTEST_H */
