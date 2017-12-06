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

#include <stdlib.h>
#include <string.h>
#include "../picoquic/picoquic_internal.h"

/* Start with a series of test vectors to test that 
 * encoding and decoding are OK. 
 * Then, add fuzz testing.
 */

static picoquic_transport_parameters transport_param_test1 = {
	65535, 0x400000, 65535, 0, 30, 0, 1480, 3 };

static picoquic_transport_parameters transport_param_test2 = { 
	0x1000000, 0x1000000, 0x1000000, 0, 255, 1, 1480, 3 };

static picoquic_transport_parameters transport_param_test3 = {
    0x1000000, 0x1000000, 0x1000000, 0, 255, 1, 0, 3 };

static uint8_t transport_param_reset_secret[PICOQUIC_RESET_SECRET_SIZE] = {
	1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

uint8_t client_param1[] = {
    'P', 'C', 'Q', '0',
	0, 0x24,
	0, 0, 0, 4, 0, 0, 0xFF, 0xFF,
	0, 1, 0, 4, 0, 0x40, 0, 0,
	0, 2, 0, 4, 0, 0, 0xFF, 0xFF,
	0, 3, 0, 2, 0, 0x1E,
	0, 5, 0, 2, 0x05, 0xC8,
};

uint8_t client_param2[] = {
	0x0A, 0x1A, 0x0A, 0x1A,
	0, 0x28,
	0, 0, 0, 4, 0x01, 0, 0, 0,
	0, 1, 0, 4, 0x01, 0, 0, 0,
	0, 2, 0, 4, 0x01, 0, 0, 0,
	0, 3, 0, 2, 0, 0xFF,
	0, 4, 0, 0,
	0, 5, 0, 2, 0x05, 0xC8
};

uint8_t client_param3[] = {
    0x0A, 0x1A, 0x0A, 0x1A,
    0, 0x22,
    0, 0, 0, 4, 0x01, 0, 0, 0,
    0, 1, 0, 4, 0x01, 0, 0, 0,
    0, 2, 0, 4, 0x01, 0, 0, 0,
    0, 3, 0, 2, 0, 0xFF,
    0, 4, 0, 0
};

uint8_t server_param1[] = {
    'P', 'C', 'Q', '0',
	0x0c,
    'P', 'C', 'Q', '0',
    0xFF, 0x00, 0x00, 0x07,
	0xFF, 0, 0, 5,
	0, 0x38,
	0, 0, 0, 4, 0, 0, 0xFF, 0xFF,
	0, 1, 0, 4, 0, 0x40, 0, 0,
	0, 2, 0, 4, 0, 0, 0xFF, 0xFF,
	0, 3, 0, 2, 0, 0x1E,
	0, 5, 0, 2, 0x05, 0xC8,
	0, 6, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

uint8_t server_param2[] = {
    'P', 'C', 'Q', '0',
    0x0c,
    'P', 'C', 'Q', '0',
    0xFF, 0x00, 0x00, 0x07,
	0xFF, 0, 0, 5,
	0, 0x3C,
	0, 0, 0, 4, 0x01, 0, 0, 0,
	0, 1, 0, 4, 0x01, 0, 0, 0,
	0, 2, 0, 4, 0x01, 0, 0, 0,
	0, 3, 0, 2, 0, 0xFF,
	0, 4, 0, 0,
	0, 5, 0, 2, 0x05, 0xC8,
	0, 6, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

int transport_param_one_test(int mode, uint32_t version, uint32_t proposed_version, 
	picoquic_transport_parameters * param, uint8_t * target, size_t target_length)
{
	int ret = 0;
    picoquic_quic_t quic_ctx;
	picoquic_cnx_t test_cnx;
	uint8_t buffer[256];
	size_t encoded, decoded;

    memset(&quic_ctx, 0, sizeof(quic_ctx));
	memset(&test_cnx, 0, sizeof(picoquic_cnx_t));
    test_cnx.quic = &quic_ctx;

	/* initialize the connection object to the test parameters */
	memcpy(&test_cnx.local_parameters, param, sizeof(picoquic_transport_parameters));
	// test_cnx.version = version;
    test_cnx.version_index = picoquic_get_version_index(version);
	test_cnx.proposed_version = proposed_version;
	memcpy(test_cnx.reset_secret, transport_param_reset_secret, PICOQUIC_RESET_SECRET_SIZE);

	ret = picoquic_prepare_transport_extensions(&test_cnx, mode, buffer, sizeof(buffer), &encoded);

	if (ret == 0)
	{
		if (encoded != target_length)
		{
			ret = -1;
		}
		else if (memcmp(buffer, target, target_length) != 0)
		{
			for (size_t i = 0; i < target_length; i++)
			{
				if (buffer[i] != target[i])
				{
					ret = -1;
				}
			}
			ret = -1;
		}
	}

	if (ret == 0)
	{
		ret = picoquic_receive_transport_extensions(&test_cnx, mode, buffer, encoded, &decoded);

		if (ret == 0 &&
			memcmp(&test_cnx.remote_parameters, param,
				sizeof(picoquic_transport_parameters)) != 0)
		{
			ret = -1;
		}
	}

	return ret;
}


int transport_param_decode_test(int mode, uint32_t version, uint32_t proposed_version,
    picoquic_transport_parameters * param, uint8_t * target, size_t target_length)
{
    int ret = 0;
    picoquic_quic_t quic_ctx;
    picoquic_cnx_t test_cnx;
    size_t decoded;

    memset(&quic_ctx, 0, sizeof(quic_ctx));
    memset(&test_cnx, 0, sizeof(picoquic_cnx_t));
    test_cnx.quic = &quic_ctx;

    // picoquic_init_transport_parameters(&test_cnx.remote_parameters);
    
    ret = picoquic_receive_transport_extensions(&test_cnx, mode, 
        target, target_length, &decoded);

    if (ret == 0 && decoded != target_length)
    {
        ret = -1;
    }

    if (ret == 0 &&
        memcmp(&test_cnx.remote_parameters, param,
            sizeof(picoquic_transport_parameters)) != 0)
    {
        ret = -1;
    }
    
    return ret;
}


int transport_param_fuzz_test(int mode, uint32_t version, uint32_t proposed_version,
	picoquic_transport_parameters * param, uint8_t * target, size_t target_length, uint64_t * proof)
{
	int ret = 0;
	int fuzz_ret = 0;
    picoquic_quic_t quic_ctx;
	picoquic_cnx_t test_cnx;
	uint8_t buffer[256];
	size_t decoded;
	uint8_t fuzz_byte = 1;

    memset(&quic_ctx, 0, sizeof(quic_ctx));
    memset(&test_cnx, 0, sizeof(picoquic_cnx_t));
    test_cnx.quic = &quic_ctx;

	/* test for valid arguments */
	if (target_length < 8 || target_length > sizeof(buffer))
	{
		return -1;
	}

	/* initialize the connection object to the test parameters */
	memcpy(&test_cnx.local_parameters, param, sizeof(picoquic_transport_parameters));
	test_cnx.version_index = picoquic_get_version_index(version);
	test_cnx.proposed_version = proposed_version;

	/* add computation of the proof argument to make sure the compiler 
	 * will not optimize the loop to nothing */

	*proof = 0;

	/* repeat multiple times */
	for (size_t l = 0; l < 8; l++)
	{
		for (size_t i = 0; i < target_length - l; i++)
		{
			/* copy message to buffer */
			memcpy(buffer, target, target_length);

			/* fuzz */
			for (size_t j = 0; j < l; j++)
			{
				buffer[i + j] ^= fuzz_byte;
				fuzz_byte++;
			}

			/* decode */
			fuzz_ret = picoquic_receive_transport_extensions(&test_cnx, mode, buffer, 
				target_length, &decoded);

			if (fuzz_ret != 0)
			{
				*proof += (uint64_t)fuzz_ret;
			}
			else
			{
				*proof += test_cnx.remote_parameters.initial_max_stream_data;

				if (decoded > target_length)
				{
					ret = -1;
				}
			}

		}
	}

	return ret;
}

int transport_param_test()
{
	int ret = 0;
	uint64_t proof = 0;
    uint32_t version_default = picoquic_supported_versions[0].version;

	if (ret == 0)
	{
		ret = transport_param_one_test(0, version_default, version_default,
			&transport_param_test1, client_param1, sizeof(client_param1));
	}

	if (ret == 0)
	{
		ret = transport_param_one_test(0, version_default, 0x0A1A0A1A,
			&transport_param_test2, client_param2, sizeof(client_param2));
	}

    if (ret == 0)
    {
        ret = transport_param_decode_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test3, client_param3, sizeof(client_param3));
    }

	if (ret == 0)
	{
		ret = transport_param_one_test(1, version_default, version_default,
			&transport_param_test1, server_param1, sizeof(server_param1));
	}

	if (ret == 0)
	{
		ret = transport_param_one_test(1, version_default, 0x0A1A0A1A,
			&transport_param_test2, server_param2, sizeof(server_param2));
	}

	if (ret == 0)
	{
		ret = transport_param_fuzz_test(0, version_default, 0x0A1A0A1A,
			&transport_param_test2, client_param2, sizeof(client_param2), &proof);
	}

	if (ret == 0)
	{
		ret = transport_param_fuzz_test(1, version_default, 0x0A1A0A1A,
			&transport_param_test2, server_param2, sizeof(server_param2), &proof);
	}

	return ret;
}
