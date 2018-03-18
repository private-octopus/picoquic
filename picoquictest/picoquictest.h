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
int tls_api_hrr_test();
int ackrange_test();
int ack_of_ack_test();
int tls_api_two_connections_test();
int cleartext_aead_test();
int tls_api_multiple_versions_test();
int varint_test();
int tls_api_client_losses_test();
int tls_api_server_losses_test();
int skip_frame_test();
int ping_pong_test();
int keep_alive_test();
int logger_test();
int transport_parameter_client_error_test();
int socket_test();
int ticket_store_test();
int session_resume_test();
int zero_rtt_test();
int stop_sending_test();
int unidir_test();
int mtu_discovery_test();
int spurious_retransmit_test();
int wrong_keyshare_test();
int pn_ctr_test();
int cleartext_pn_enc_test();
int pn_enc_1rtt_test();
int tls_zero_share_test();
int cleartext_aead_vector_test();
int transport_param_log_test();
int bad_certificate_test();
int set_verify_certificate_callback_test();
int virtual_time_test();
int tls_different_params_test();

#ifdef __cplusplus
}
#endif

#endif /* PICOQUICTEST_H */
