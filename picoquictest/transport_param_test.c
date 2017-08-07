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
#include "../picoquic/picoquic.h"

/* Start with a series of test vectors to test that 
 * encoding and decoding are OK. 
 * Then, add fuzz testing.
 */

static picoquic_transport_parameters transport_param_test1 = {
	65535, 0x400000, 65535, 30, 0, 1480 };

static picoquic_transport_parameters transport_param_test2 = { 
	0x1000000, 0x1000000, 0x1000000, 255, 1, 1480 };

uint8_t client_param1[] = {
	0xFF, 0, 0, 5,
	0xFF, 0, 0, 5,
	0, 0x2E,
	0, 0, 0, 0, 0, 4, 0, 0, 0xFF, 0xFF,
	0, 0, 0, 1, 0, 4, 0, 0x40, 0, 0,
	0, 0, 0, 2, 0, 4, 0, 0, 0xFF, 0xFF,
	0, 0, 0, 3, 0, 2, 0, 0x1E,
	0, 0, 0, 5, 0, 2, 0x05, 0xC8,
};

uint8_t client_param2[] = {
	0xFF, 0, 0, 5,
	0x0A, 0x1A, 0x0A, 0x1A,
	0, 0x34,
	0, 0, 0, 0, 0, 4, 0x01, 0, 0, 0,
	0, 0, 0, 1, 0, 4, 0x01, 0, 0, 0,
	0, 0, 0, 2, 0, 4, 0x01, 0, 0, 0,
	0, 0, 0, 3, 0, 2, 0, 0xFF,
	0, 0, 0, 4, 0, 0,
	0, 0, 0, 5, 0, 2, 0x05, 0xC8,
};

int transport_param_client_test(uint32_t version, uint32_t proposed_version, 
	picoquic_transport_parameters * param, uint8_t * target, size_t target_length)
{
	int ret = 0;
	picoquic_cnx test_cnx = { {0} };
	uint8_t buffer[256];
	size_t encoded, decoded;

	/* initialize the connection object to the test parameters */
	memcpy(&test_cnx.local_parameters, param, sizeof(picoquic_transport_parameters));
	test_cnx.version = version;
	test_cnx.proposed_version = proposed_version;

	ret = picoquic_prepare_transport_extensions(&test_cnx, 0, buffer, sizeof(buffer), &encoded);

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
		ret = picoquic_receive_transport_extensions(&test_cnx, 0, buffer, encoded, &decoded);

		if (ret == 0 &&
			memcmp(&test_cnx.remote_parameters, param,
				sizeof(picoquic_transport_parameters)) != 0)
		{
			ret = -1;
		}
	}

	return ret;
}

int transport_param_test()
{
	int ret = 0;

	if (ret == 0)
	{
		ret = transport_param_client_test(0xFF000005, 0xFF000005,
			&transport_param_test1, client_param1, sizeof(client_param1));
	}

	if (ret == 0)
	{
		ret = transport_param_client_test(0xFF000005, 0x0A1A0A1A,
			&transport_param_test2, client_param2, sizeof(client_param2));
	}

	return ret;
}