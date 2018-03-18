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

#include "stdafx.h"
#include "CppUnitTest.h"
#include "../picoquictest/picoquictest.h"

using namespace Microsoft::VisualStudio::CppUnitTestFramework;

namespace UnitTest1
{		
	TEST_CLASS(UnitTest1)
	{
	public:
		TEST_METHOD(test_picohash)
		{
            int ret = picohash_test();

            Assert::AreEqual(ret, 0); 
		}

        TEST_METHOD(test_cnxcreation)
        {
            int ret = cnxcreation_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_parse_header)
        {
            int ret = parseheadertest();

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

        TEST_METHOD(test_fnv1a)
        {
            int ret = fnv1atest();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_sack)
        {
            int ret = sacktest();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_float16)
        {
            int ret = float16test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_varints)
        {
            int ret = varint_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_skip_frames)
        {
            int ret = skip_frame_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_StreamZeroFrame)
        {
            int ret = StreamZeroFrameTest();

            Assert::AreEqual(ret, 0);
        }

		TEST_METHOD(test_sendack)
		{
			int ret = sendacktest();

			Assert::AreEqual(ret, 0);
		}

        TEST_METHOD(test_ackrange)
        {
            int ret = ackrange_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_ack_of_ack)
        {
            int ret = ack_of_ack_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_sim_link)
        {
            int ret = sim_link_test();

            Assert::AreEqual(ret, 0);
        }

		TEST_METHOD(test_tls_api)
		{
			int ret = tls_api_test();

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

		TEST_METHOD(test_tls_api_version_negotiation)
		{
			int ret = tls_api_version_negotiation_test();

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

		TEST_METHOD(test_server_reset)
		{
			int ret = tls_api_server_reset_test();

			Assert::AreEqual(ret, 0);
		}

		TEST_METHOD(test_bad_server_reset)
		{
			int ret = tls_api_bad_server_reset_test();

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

        TEST_METHOD(test_http0dot9)
        {
            int ret = http0dot9_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_hrr)
        {
            int ret = tls_api_hrr_test();

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

        TEST_METHOD(test_ping_pong)
        {
            int ret = ping_pong_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_keep_alive)
        {
          int ret = keep_alive_test();

          Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_logger)
        {
            int ret = logger_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_tparam_client_error)
        {
            int ret = transport_parameter_client_error_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_sockets)
        {
            int ret = socket_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_ticket_store)
        {
            int ret = ticket_store_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_session_resume)
        {
            int ret = session_resume_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_zero_rtt)
        {
            int ret = zero_rtt_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_stop_sending)
        {
            int ret = stop_sending_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_unidir)
        {
            int ret = unidir_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_mtu_discovery)
        {
            int ret = mtu_discovery_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_spurious_retransmit)
        {
            int ret = spurious_retransmit_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_wrong_keyshare)
        {
            int ret = wrong_keyshare_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_pn_ctr)
        {
            int ret = pn_ctr_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_cleartext_pn_enc)
        {
            int ret = cleartext_pn_enc_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_pn_enc_1rtt)
        {
            int ret = pn_enc_1rtt_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_tls_zero_share)
        {
            int ret = tls_zero_share_test();

            Assert::AreEqual(ret, 0);
        }

        TEST_METHOD(test_cleartext_aead_vector)
        {
            int ret = cleartext_aead_vector_test();

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

        TEST_METHOD(test_certificate_callback)
        {
            int ret = set_verify_certificate_callback_test();

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
        
	};
}
