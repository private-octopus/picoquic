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

#include "CppUnitTest.h"
#include "picoquictest/picoquictest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTest1
{
	TEST_CLASS(UnitTest1)
	{
	public:
        TEST_CLASS_INITIALIZE(setup) {
            // avoid large debug spew that slows down the console.
            debug_printf_suspend();
        }

	    TEST_METHOD(test_picohash)
	    {
            int ret = picohash_test();

            Assert::AreEqual(ret, 0);
	    }

        TEST_METHOD(bytestream)
        {
            int ret = bytestream_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(connection_id_print)
        {
            int ret = util_connection_id_print_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(connection_id_parse)
        {
            int ret = util_connection_id_parse_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(sprintf)
        {
            int ret = util_sprintf_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(memcmp)
        {
            int ret = util_memcmp_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(threading)
        {
            int ret = util_threading_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(random_tester)
        {
            int ret = random_tester_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(random_gauss)
        {
            int ret = random_gauss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(random_public_tester)
        {
            int ret = random_public_tester_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(splay)
        {
            int ret = splay_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_cnxcreation)
        {
            int ret = cnxcreation_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(parse_header)
        {
            int ret = parseheadertest();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(incoming_initial)
        {
            int ret = incoming_initial_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(header_length)
        {
            int ret = header_length_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_pn2pn64)
        {
            int ret = pn2pn64test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_intformat)
        {
            int ret = intformattest();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_varints)
        {
            int ret = varint_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ack_sack)
        {
            int ret = sacktest();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_skip_frames)
        {
            int ret = skip_frame_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_parse_frames)
        {
            int ret = parse_frame_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_logger)
        {
            int ret = logger_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(binlog)
        {
            int ret = binlog_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(app_message_overflow)
        {
            int ret = app_message_overflow_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_TlsStreamFrame)
        {
            int ret = TlsStreamFrameTest();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_StreamZeroFrame)
        {
            int ret = StreamZeroFrameTest();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stream_splay)
        {
            int ret = stream_splay_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stream_output)
        {
            int ret = stream_output_test();

            Assert::AreEqual(ret, 0);
        }
        TEST_METHOD(stream_retransmit_copy)
        {
            int ret = test_copy_for_retransmit();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stream_retransmit_format)
        {
            int ret = test_format_for_retransmit();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stateless_blowback) {
            int ret = test_stateless_blowback();

            Assert::AreEqual(ret, 0);
        }

		TEST_METHOD(ack_send)
		{
			int ret = sendacktest();

			Assert::AreEqual(ret, 0);
		}

        TEST_METHOD(ack_range)
        {
            int ret = ackrange_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ack_disorder)
        {
            int ret = ack_disorder_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ack_horizon)
        {
            int ret = ack_horizon_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ack_of_ack)
        {
            int ret = ack_of_ack_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_sim_link)
        {
            int ret = sim_link_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cleartext_pn_enc)
        {
            int ret = cleartext_pn_enc_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cid_for_lb)
        {
            int ret = cid_for_lb_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cid_for_lb_cli)
        {
            int ret = cid_for_lb_cli_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(retry_protection_vector)
        {
            int ret = retry_protection_vector_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(test_pn_enc_1rtt)
        {
            int ret = pn_enc_1rtt_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(new_cnxid_stash)
        {
            int ret = cnxid_stash_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(new_cnxid)
        {
            int ret = new_cnxid_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(pacing)
        {
            int ret = pacing_test();

            Assert::AreEqual(ret, 0);
        }

		TEST_METHOD(test_tls_api)
		{
			int ret = tls_api_test();

			Assert::AreEqual(ret, 0);
		}

        TEST_METHOD(tls_api_inject_hs_ack)
        {
            int ret = tls_api_inject_hs_ack_test();

            Assert::AreEqual(ret, 0);
        }
        TEST_METHOD(null_sni)
        {
            int ret = null_sni_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(test_silence)
        {
            int ret = tls_api_silence_test();

            Assert::AreEqual(ret, 0);
        }

		TEST_METHOD(test_tls_api_first_loss)
		{
			int ret = tls_api_loss_test(1ull);

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_tls_api_second_loss)
		{
			int ret = tls_api_loss_test(2ull);

			Assert::AreEqual(ret, 0);
		}

        TEST_METHOD(test_server_first_loss)
        {
            int ret = tls_api_server_first_loss_test();

            Assert::AreEqual(ret, 0);
        }

		TEST_METHOD(test_tls_api_client_losses)
		{
			int ret = tls_api_client_losses_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_tls_api_server_losses)
		{
			int ret = tls_api_server_losses_test();

			Assert::AreEqual(ret, 0);
		}

        TEST_METHOD(test_tls_api_many_losses)
        {
            int ret = tls_api_many_losses();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(datagram)
        {
            int ret = datagram_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(datagram_rt)
        {
            int ret = datagram_rt_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(datagram_loss)
        {
            int ret = datagram_loss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(datagram_size)
        {
            int ret = datagram_size_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(datagram_small)
        {
            int ret = datagram_small_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ddos_amplification)
        {
            int ret = ddos_amplification_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ddos_amplification_0rtt)
        {
            int ret = ddos_amplification_0rtt_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ddos_amplification_8k)
        {
            int ret = ddos_amplification_8k_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(blackhole)
        {
            int ret = blackhole_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(no_ack_frequency)
        {
            int ret = no_ack_frequency_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(connection_drop)
        {
            int ret = connection_drop_test();

            Assert::AreEqual(ret, 0);
        }

		TEST_METHOD(version_negotiation)
		{
			int ret = tls_api_version_negotiation_test();

			Assert::AreEqual(ret, 0);
		}

        TEST_METHOD(version_invariant)
        {
            int ret = tls_api_version_invariant_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(version_negotiation_spoof)
        {
            int ret = test_version_negotiation_spoof();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_transport_param_stream_id)
        {
            int ret = transport_param_stream_id_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(vn_tp)
        {
            int ret = vn_tp_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(vn_compat)
        {
            int ret = vn_compat_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stream_rank)
        {
            int ret = stream_rank_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stream_id_to_rank)
        {
            int ret = stream_id_to_rank_test();

            Assert::AreEqual(ret, 0);
        }

		TEST_METHOD(test_transport_param)
		{
			int ret = transport_param_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_tls_api_sni)
		{
			int ret = tls_api_sni_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_tls_api_alpn)
		{
			int ret = tls_api_alpn_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_tls_api_wrong_alpn)
		{
			int ret = tls_api_wrong_alpn_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_one_way_stream)
		{
			int ret = tls_api_oneway_stream_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_q_and_r_stream)
		{
			int ret = tls_api_q_and_r_stream_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_q2_and_r2_stream)
		{
			int ret = tls_api_q2_and_r2_stream_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(stateless_reset)
		{
			int ret = stateless_reset_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(stateless_reset_bad)
		{
			int ret = stateless_reset_bad_test();

			Assert::AreEqual(ret, 0);
		}

        TEST_METHOD(stateless_reset_client)
        {
            int ret = stateless_reset_client_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stateless_reset_handshake)
        {
            int ret = stateless_reset_handshake_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(immediate_close)
        {
            int ret = immediate_close_test();

            Assert::AreEqual(ret, 0);
        }

		TEST_METHOD(test_very_long_stream)
		{
			int ret = tls_api_very_long_stream_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_very_long_max)
		{
			int ret = tls_api_very_long_max_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_very_long_with_err)
		{
			int ret = tls_api_very_long_with_err_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_very_long_congestion)
		{
			int ret = tls_api_very_long_congestion_test();

			Assert::AreEqual(ret, 0);
		}

        TEST_METHOD(retry)
        {
            int ret = tls_api_retry_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(retry_large)
        {
            int ret = tls_api_retry_large_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(retry_token)
        {
            int ret = tls_retry_token_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(retry_token_valid)
        {
            int ret = tls_retry_token_valid_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(test_two_connections)
        {
            int ret = tls_api_two_connections_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_cleartext_aead)
        {
            int ret = cleartext_aead_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_multiple_versions)
        {
            int ret = tls_api_multiple_versions_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_keep_alive)
        {
          int ret = keep_alive_test();

          Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(integrity_limit)
        {
            int ret = integrity_limit_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(excess_repeat)
        {
            int ret = excess_repeat_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(netperf_basic)
        {
            int ret = netperf_basic_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(netperf_bbr)
        {
            int ret = netperf_bbr_test();

            Assert::AreEqual(ret, 0);
        }

        /* test disabled because the results are not consistent. */
        TEST_METHOD(nat_attack)
        {
            int ret = nat_attack_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_sockets)
        {
            int ret = socket_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_sockets_ecn)
        {
            int ret = socket_ecn_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(ticket_store)
        {
            int ret = ticket_store_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ticket_seed)
        {
            int ret = ticket_seed_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ticket_seed_from_bdp_frame)
        {
            int ret = ticket_seed_from_bdp_frame_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(token_store)
        {
            int ret = token_store_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(token_reuse_api)
        {
            int ret = token_reuse_api_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_session_resume)
        {
            int ret = session_resume_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(zero_rtt)
        {
            int ret = zero_rtt_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(zero_rtt_loss)
        {
            int ret = zero_rtt_loss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stop_sending)
        {
            int ret = stop_sending_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(discard_stream)
        {
            int ret = discard_stream_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_unidir)
        {
            int ret = unidir_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(many_short_loss)
        {
            int ret = many_short_loss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(mtu_discovery)
        {
            int ret = mtu_discovery_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(mtu_blocked)
        {
            int ret = mtu_blocked_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(mtu_delayed)
        {
            int ret = mtu_delayed_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(mtu_required)
        {
            int ret = mtu_required_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(mtu_max)
        {
            int ret = mtu_max_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(mtu_drop)
        {
            int ret = mtu_drop_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(red_cc)
        {
            int ret = red_cc_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multi_segment)
        {
            int ret = multi_segment_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(pacing_cc)
        {
            int ret = pacing_cc_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_spurious_retransmit)
        {
            int ret = spurious_retransmit_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_pn_ctr)
        {
            int ret = pn_ctr_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_tls_zero_share)
        {
            int ret = tls_zero_share_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(key_rotation_vector)
        {
            int ret = key_rotation_vector_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(draft17_vector)
        {
            int ret = draft17_vector_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(test_transport_param_log)
        {
            int ret = transport_param_log_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_bad_certificate)
        {
            int ret = bad_certificate_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(client_cert_callback)
        {
            int ret = set_verify_certificate_callback_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(client_auth)
        {
          int ret = request_client_authentication_test();

          Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_virtual_time)
        {
            int ret = virtual_time_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_different_params)
        {
            int ret = tls_different_params_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_quant_params)
        {
            int ret = tls_quant_params_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_set_certificate_and_key)
        {
            int ret = set_certificate_and_key_test();

            Assert::AreEqual(ret, 0);
        }
    
        TEST_METHOD(test_bad_client_certificate)
        {
            int ret = bad_client_certificate_test();

            Assert::AreEqual(ret, 0);
        }
    
        TEST_METHOD(nat_rebinding)
        {
            int ret = nat_rebinding_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(nat_rebinding_loss)
        {
            int ret = nat_rebinding_loss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(nat_rebinding_zero)
        {
            int ret = nat_rebinding_zero_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(nat_rebinding_latency)
        {
            int ret = nat_rebinding_latency_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(nat_rebinding_fast)
        {
            int ret = fast_nat_rebinding_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_spin_bit)
        {
            int ret = spin_bit_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(loss_bit)
        {
            int ret = loss_bit_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_client_error)
        {
            int ret = client_error_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(client_only)
        {
            int ret = client_only_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_packet_enc_dec)
        {
            int ret = packet_enc_dec_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_pn_vector)
        {
            int ret = cleartext_pn_vector_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(zero_rtt_spurious)
        {
            int ret = zero_rtt_spurious_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(zero_rtt_retry)
        {
            int ret = zero_rtt_retry_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(zero_rtt_no_coal)
        {
            int ret = zero_rtt_no_coal_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(zero_rtt_many_losses)
        {
            int ret = zero_rtt_many_losses_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(zero_rtt_long)
        {
            int ret = zero_rtt_long_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(zero_rtt_delay)
        {
            int ret = zero_rtt_delay_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cnxid_transmit)
        {
            int ret = transmit_cnxid_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cnxid_transmit_disable)
        {
            int ret = transmit_cnxid_disable_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cnxid_transmit_r_before)
        {
            int ret = transmit_cnxid_retire_before_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cnxid_transmit_r_disable){
            int ret = transmit_cnxid_retire_disable_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(test_probe_api)
        {
            int ret = probe_api_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(migration)
        {
            int ret = migration_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(migration_long)
        {
            int ret = migration_test_long();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(migration_loss)
        {
            int ret = migration_test_loss();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(migration_zero)
        {
            int ret = migration_zero_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(migration_fail)
        {
            int ret = migration_fail_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(preferred_address)
        {
            int ret = preferred_address_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(preferred_address_dis_mig)
        {
            int ret = preferred_address_dis_mig_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(preferred_address_zero)
        {
            int ret = preferred_address_zero_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(test_cnxid_renewal)
        {
            int ret = cnxid_renewal_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_retire_cnxid)
        {
            int ret = retire_cnxid_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(not_before_cnxid)
        {
            int ret = not_before_cnxid_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_server_busy)
        {
            int ret = server_busy_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(initial_close)
        {
            int ret = initial_close_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(initial_server_close)
        {
            int ret = initial_server_close_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(new_rotated_key)
        {
            int ret = new_rotated_key_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(key_rotation)
        {
            int ret = key_rotation_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(key_rotation_server)
        {
            int ret = key_rotation_auto_server();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(key_rotation_client)
        {
            int ret = key_rotation_auto_client();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(key_rotation_stress)
        {
            int ret = key_rotation_stress_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(false_migration)
        {
            int ret = false_migration_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(nat_handshake)
        {
            int ret = nat_handshake_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(short_initial_cid)
        {
            int ret = short_initial_cid_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stream_id_max)
        {
            int ret = stream_id_max_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(padding)
        {
            int ret = padding_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(packet_trace)
        {
            int ret = packet_trace_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(qlog_trace)
        {
            int ret = qlog_trace_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(qlog_trace_auto)
        {
            int ret = qlog_trace_auto_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(qlog_trace_only)
        {
            int ret = qlog_trace_only_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(qlog_trace_ecn)
        {
            int ret = qlog_trace_ecn_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(path_packet_queue)
        {
            int ret = path_packet_queue_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(perflog)
        {
            int ret = perflog_test();

            Assert::AreEqual(ret, 0);
        }
        TEST_METHOD(nat_rebinding_stress)
        {
            int ret = rebinding_stress_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(random_padding)
        {
            int ret = random_padding_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ec00_zero)
        {
            int ret = ec00_zero_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ec2f_second_flight)
        {
            int ret = ec2f_second_flight_nack_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(eccf_corrupted_fuzz)
        {
            int ret = eccf_corrupted_file_fuzz_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(eca1_amplification_loss)
        {
            int ret = eca1_amplification_loss_test();

            Assert::AreEqual(ret, 0);
        }


        TEST_METHOD(ecf1_final_loss)
        {
            int ret = ecf1_final_loss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ec5c_silly_cid)
        {
            int ret = ec5c_silly_cid_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ec9a_preemptive_amok)
        {
            int ret = ec9a_preemptive_amok_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(error_reason)
        {
            int ret = error_reason_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ready_to_send)
        {
            int ret = ready_to_send_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(ready_to_skip)
        {
            int ret = ready_to_skip_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ready_to_zero)
        {
            int ret = ready_to_zero_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(ready_to_zfin)
        {
            int ret= ready_to_zfin_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cubic)
        {
            int ret = cubic_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cubic_jitter)
        {
            int ret = cubic_jitter_test();

            Assert::AreEqual(ret, 0);
        }
        TEST_METHOD(fastcc)
        {
            int ret = fastcc_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(fastcc_jitter)
        {
            int ret = fastcc_jitter_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr)
        {
            int ret = bbr_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr_jitter)
        {
            int ret = bbr_jitter_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr_long)
        {
            int ret = bbr_long_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr_performance)
        {
            int ret = bbr_performance_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr_slow_long)
        {
            int ret = bbr_slow_long_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr_one_second)
        {
            int ret = bbr_one_second_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr_gbps)
        {
            int ret = gbps_performance_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr_asym100)
        {
            int ret = bbr_asym100_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr_asym100_nodelay)
        {
            int ret = bbr_asym100_nodelay_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bbr_asym400)
        {
            int ret = bbr_asym400_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(long_rtt)
        {
            int ret = long_rtt_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(high_latency_basic)
        {
            int ret = high_latency_basic_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(high_latency_bbr)
        {
            int ret = high_latency_bbr_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(high_latency_cubic)
        {
            int ret = high_latency_cubic_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(high_latency_probeRTT)
        {
            int ret = high_latency_probeRTT_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cid_length)
        {
            int ret = cid_length_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(optimistic_ack)
        {
            int ret = optimistic_ack_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(optimistic_hole)
        {
            int ret = optimistic_hole_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bad_coalesce)
        {
            int ret = bad_coalesce_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(bad_cnxid)
        {
            int ret = bad_cnxid_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(document_addresses)
        {
            int ret = document_addresses_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(large_client_hello) {
            int ret = large_client_hello_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(send_stream_blocked) {
            int ret = send_stream_blocked_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(stream_ack) {
            int ret = stream_ack_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(queue_network_input) {
            int ret = queue_network_input_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(pacing_update) {
            int ret = pacing_update_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(direct_receive) {
            int ret = direct_receive_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(app_limit_cc) {
            int ret = app_limit_cc_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(initial_race) {
            int ret = initial_race_test();

            Assert::AreEqual(ret, 0);
        }
        TEST_METHOD(chacha20) {
            int ret = chacha20_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cnx_limit) {
            int ret = cnx_limit_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cert_verify_bad_cert) {
            int ret = cert_verify_bad_cert_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cert_verify_bad_sni) {
            int ret = cert_verify_bad_sni_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cert_verify_null) {
            int ret = cert_verify_null_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cert_verify_null_sni) {
            int ret = cert_verify_null_sni_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cert_verify_rsa) {
            int ret = cert_verify_rsa_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cid_quiescence) {
            int ret = cid_quiescence_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(migration_controlled) {
            int ret = migration_controlled_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(migration_mtu_drop) {
            int ret = migration_mtu_drop_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(monopath_basic) {
            int ret = monopath_basic_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(monopath_hole) {
            int ret= monopath_hole_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(monopath_rotation) {
            int ret = monopath_rotation_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(monopath_0rtt) {
            int ret = monopath_0rtt_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(monopath_0rtt_loss) {
            int ret = monopath_0rtt_loss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_aead) {
            int ret = multipath_aead_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_basic) {
            int ret = multipath_basic_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_drop_first) {
            int ret = multipath_drop_first_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_drop_second) {
            int ret = multipath_drop_second_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_sat_plus) {
            int ret = multipath_sat_plus_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_renew) {
            int ret = multipath_renew_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_rotation) {
            int ret = multipath_rotation_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_nat) {
            int ret = multipath_nat_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_break1) {
            int ret = multipath_break1_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_abandon) {
            int ret = multipath_abandon_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_back1) {
            int ret = multipath_back1_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_perf) {
            int ret = multipath_perf_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(multipath_qlog) {
            int ret = multipath_qlog_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_basic) {
            int ret = simple_multipath_basic_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_drop_first) {
            int ret = simple_multipath_drop_first_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_drop_second) {
            int ret = simple_multipath_drop_second_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_sat_plus) {
            int ret = simple_multipath_sat_plus_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_renew) {
            int ret = simple_multipath_renew_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_rotation) {
            int ret = simple_multipath_rotation_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_nat) {
            int ret = simple_multipath_nat_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_break1) {
            int ret = simple_multipath_break1_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_abandon) {
            int ret = simple_multipath_abandon_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_back1) {
            int ret = simple_multipath_back1_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_perf) {
            int ret = simple_multipath_perf_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(simple_multipath_qlog) {
            int ret = simple_multipath_qlog_test();

            Assert::AreEqual(ret, 0);
        }
        TEST_METHOD(config_option_letters) {
            int ret = config_option_letters_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(config_option) {
            int ret = config_option_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_integer) {
            int ret = h3zero_integer_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(qpack_huffman) {
            int ret = qpack_huffman_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(qpack_huffman_base) {
            int ret = qpack_huffman_base_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_parse_qpack) {
            int ret = h3zero_parse_qpack_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_prepare_qpack) {
            int ret = h3zero_prepare_qpack_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_user_agent) {
            int ret = h3zero_user_agent_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_null_sni) {
            int ret = h3zero_null_sni_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_qpack_fuzz) {
            int ret = h3zero_qpack_fuzz_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_stream) {
            int ret = h3zero_stream_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(parse_demo_scenario) {
            int ret = parse_demo_scenario_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_server) {
            int ret = h3zero_server_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h09_server) {
            int ret = h09_server_test();

            Assert::AreEqual(ret, 0);
        }
        
        TEST_METHOD(h09_header) {
            int ret = h09_header_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(generic_server) {
            int ret = generic_server_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(esni) {
            int ret = esni_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_post) {
            int ret = h3zero_post_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h09_post) {
            int ret = h09_post_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(demo_alpn) {
            int ret = demo_alpn_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(demo_file_sanitize) {
            int ret = demo_file_sanitize_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(demo_file_access) {
            int ret = demo_file_access_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(demo_server_file) {
            int ret = demo_server_file_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3zero_satellite) {
            int ret = h3zero_satellite_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h09_satellite) {
            int ret = h09_satellite_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h09_lone_fin) {
            int ret = h09_lone_fin_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3_long_file_name) {
            int ret = h3_long_file_name_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h09_multi_file) {
            int ret = h09_multi_file_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h09_multi_file_loss) {
            int ret = h09_multi_file_loss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h09_multi_file_preemptive) {
            int ret = h09_multi_file_preemptive_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3_multi_file) {
            int ret = h3_multi_file_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3_multi_file_loss) {
            int ret = h3_multi_file_loss_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(h3_multi_file_preemptive) {
            int ret = h3_multi_file_preemptive_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(http_drop) {
            int ret = http_drop_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(http_esni) {
            int ret = http_esni_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(grease_quic_bit) {
            int ret = grease_quic_bit_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(grease_quic_bit_one_way) {
            int ret = grease_quic_bit_one_way_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(pn_random) {
            int ret = pn_random_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(port_blocked) {
            int ret = port_blocked_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(cplusplus) {
            int ret = cplusplustest();

            Assert::AreEqual(ret, 0);
        }
    };
}
