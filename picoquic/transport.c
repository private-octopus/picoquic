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

/*
 * Management of transport parameters for PicoQUIC.
 *
 * The TLS syntax of the transport parameter extension is defined as:
 *
 *     uint32 QuicVersion
 *
 *     enum {
 *      initial_max_stream_data(0), // MUST. 32 bits, octets.
 *      initial_max_data(1),        // MUST. 32 bits, multiples of 1K octets.
 *      initial_max_stream_id(2),   // MUST. 32 bits, integer.
 *      idle_timeout(3),            // MUST. 16 bits, seconds, max 600 seconds.
 *      omit_connection_id(4),      // zero length, true if present, false if absent
 *      max_packet_size(5),         // 16 bits, up to 65527. Values below 1252 are invalid.
 *      (65535)
 *   } TransportParameterId;
 *
 *   struct {
 *      TransportParameterId parameter;
 *      opaque value<0..2^16-1>;
 *   } TransportParameter;
 *
 *   struct {
 *      select (Handshake.msg_type) {
 *         case client_hello:
 *            QuicVersion negotiated_version;
 *            QuicVersion initial_version;
 *
 *         case encrypted_extensions:
 *            QuicVersion supported_versions<2..2^8-4>;
 *
 *         case new_session_ticket:
 *            struct {};
 *      };
 *      TransportParameter parameters<30..2^16-1>;
 *   } TransportParameters;
 */

#include "picoquic.h"

typedef enum {
	picoquic_transport_parameter_initial_max_stream_data = 0,
	picoquic_transport_parameter_initial_max_data = 1,
	picoquic_transport_parameter_initial_max_stream_id = 2,
	picoquic_transport_parameter_idle_timeout = 3,
	picoquic_transport_parameter_omit_connection_id = 4,
	picoquic_transport_parameter_max_packet_size = 5
} picoquic_transport_parameter_enum;

int picoquic_prepare_transport_extensions(picoquic_cnx * cnx, int extension_mode,
	uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	size_t byte_index = 0;
	size_t min_size = 0;
	uint16_t param_size = 0;

	switch (extension_mode)
	{
	case 0: // Client hello
		min_size = 8;
		break;
	case 1: // Server encrypted extension
		min_size = 1 + 4 * picoquic_nb_supported_versions;
		break;
	default: // New session ticket
		break;
	}
	/* add the mandatory parameters */
	param_size = (4 + 2 + 4) + (4 + 2 + 4) + (4 + 2 + 4) + (4 + 2 + 2) + (4 + 2 + 2);
	if (cnx->local_parameters.omit_connection_id)
	{
		param_size += 2 + 4;
	}
	min_size += param_size + 2;

	*consumed = min_size;

	if (min_size > bytes_max)
	{
		ret = PICOQUIC_ERROR_EXTENSION_BUFFER_TOO_SMALL;
	}
	else
	{
		switch (extension_mode)
		{
		case 0: // Client hello
			picoformat_32(bytes + byte_index, cnx->version);
			byte_index += 4;
			picoformat_32(bytes + byte_index, cnx->proposed_version);
			byte_index += 4;
			break;
		case 1: // Server encrypted extension
			bytes[byte_index++] = (uint8_t) 4 * picoquic_nb_supported_versions;
			for (size_t i = 0; i < picoquic_nb_supported_versions; i++)
			{
				picoformat_32(bytes + byte_index, picoquic_supported_versions[i]);
				byte_index += 4;
			}
			break;
		default: // New session ticket
			break;
		}

		picoformat_16(bytes + byte_index, param_size);
		byte_index += 2;

		picoformat_32(bytes + byte_index, picoquic_transport_parameter_initial_max_stream_data);
		byte_index += 4;
		picoformat_16(bytes + byte_index, 4);
		byte_index += 2;
		picoformat_32(bytes + byte_index, cnx->local_parameters.initial_max_stream_data);
		byte_index += 4;

		picoformat_32(bytes + byte_index, picoquic_transport_parameter_initial_max_data);
		byte_index += 4;
		picoformat_16(bytes + byte_index, 4);
		byte_index += 2;
		picoformat_32(bytes + byte_index, cnx->local_parameters.initial_max_data);
		byte_index += 4;

		picoformat_32(bytes + byte_index, picoquic_transport_parameter_initial_max_stream_id);
		byte_index += 4;
		picoformat_16(bytes + byte_index, 4);
		byte_index += 2;
		picoformat_32(bytes + byte_index, cnx->local_parameters.initial_max_stream_id);
		byte_index += 4;

		picoformat_32(bytes + byte_index, picoquic_transport_parameter_idle_timeout);
		byte_index += 4;
		picoformat_16(bytes + byte_index, 2);
		byte_index += 2;
		picoformat_16(bytes + byte_index, cnx->local_parameters.idle_timeout);
		byte_index += 2;

		if (cnx->local_parameters.omit_connection_id)
		{
			picoformat_32(bytes + byte_index, picoquic_transport_parameter_omit_connection_id);
			byte_index += 4;
			picoformat_16(bytes + byte_index, 0);
			byte_index += 2;
		}

		picoformat_32(bytes + byte_index, picoquic_transport_parameter_max_packet_size);
		byte_index += 4;
		picoformat_16(bytes + byte_index, 2);
		byte_index += 2;
		picoformat_16(bytes + byte_index, cnx->local_parameters.max_packet_size);
		byte_index += 2;
	}
	
	return ret;
}

int picoquic_receive_transport_extensions(picoquic_cnx * cnx, int extension_mode,
	uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
	int ret = 0;
	size_t byte_index = 0;

	switch (extension_mode)
	{
	case 0: // Client hello
		if (bytes_max < 8)
		{
			ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
		}
		else
		{
			uint32_t version;
			uint32_t proposed_version;

			version = PICOPARSE_32(bytes + byte_index);
			byte_index += 4;
			proposed_version = PICOPARSE_32(bytes + byte_index);
			byte_index += 4;

			if (version != proposed_version)
			{
				for (size_t i = 0; ret == 0 && i < picoquic_nb_supported_versions; i++)
				{
					if (proposed_version == picoquic_supported_versions[i])
					{
						ret = PICOQUIC_ERROR_VERSION_NEGOTIATION_SPOOFED;
					}
				}
			}
		}
		break;
	case 1: // Server encrypted extension
	{
		if (bytes_max < 1)
		{
			ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
		}
		else
		{
			size_t supported_versions_size = bytes[byte_index++];

			if ((supported_versions_size & 3) != 0 ||
				supported_versions_size > 252 ||
				byte_index + supported_versions_size > bytes_max)
			{
				ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
			}
			else if (cnx->proposed_version == cnx->version)
			{
				byte_index += supported_versions_size;
			}
			else
			{
				size_t nb_supported_versions = supported_versions_size / 4;

				for (size_t i = 0; ret == 0 && i < nb_supported_versions; i++)
				{
					uint32_t supported_version = PICOPARSE_32(bytes + byte_index);
					byte_index += 4;
					if (supported_version == cnx->proposed_version)
					{
						ret = PICOQUIC_ERROR_VERSION_NEGOTIATION_SPOOFED;
					}
				}
			}
		}
		break;
	}
	default: // New session ticket
		break;
	}

	if (ret == 0 && byte_index + 2 > bytes_max)
	{
		ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
	}
	else
	{
		uint16_t extensions_size = PICOPARSE_16(bytes + byte_index);
		size_t extensions_end; 
		byte_index += 2;
		extensions_end = byte_index + extensions_size;

		if (extensions_end > bytes_max)
		{
			ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
		}
		else while (ret == 0 && byte_index < extensions_end)
		{
			if (byte_index + 6 > extensions_end)
			{
				ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
			}
			else
			{
				uint32_t extension_type = PICOPARSE_32(bytes + byte_index);
				uint16_t extension_length = PICOPARSE_16(bytes + byte_index + 4);
				byte_index += 6;

				if (byte_index + extension_length > extensions_end)
				{
					ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
				}
				else
				{
					switch (extension_type)
					{
					case picoquic_transport_parameter_initial_max_stream_data:
						if (extension_length != 4)
						{
							ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
						}
						else
						{
							cnx->remote_parameters.initial_max_stream_data = PICOPARSE_32(bytes + byte_index);
						}
						break;
					case picoquic_transport_parameter_initial_max_data:
						if (extension_length != 4)
						{
							ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
						}
						else
						{
							cnx->remote_parameters.initial_max_data = PICOPARSE_32(bytes + byte_index);
						}
						break;
					case picoquic_transport_parameter_initial_max_stream_id:
						if (extension_length != 4)
						{
							ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
						}
						else
						{
							cnx->remote_parameters.initial_max_stream_id = PICOPARSE_32(bytes + byte_index);
						}
						break;
					case picoquic_transport_parameter_idle_timeout:
						if (extension_length != 2)
						{
							ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
						}
						else
						{
							cnx->remote_parameters.idle_timeout = PICOPARSE_16(bytes + byte_index);
						}
						break;
					case picoquic_transport_parameter_omit_connection_id:
						if (extension_length != 0)
						{
							ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
						}
						else
						{
							cnx->remote_parameters.omit_connection_id = 1;
						}
						break;
					case picoquic_transport_parameter_max_packet_size:
						if (extension_length != 2)
						{
							ret = PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION;
						}
						else
						{
							cnx->remote_parameters.max_packet_size = PICOPARSE_16(bytes + byte_index);
						}
						break;
					default:
						/* ignore unknown extensions */				
						break;
					}

					if (ret == 0)
					{
						byte_index += extension_length;
					}
				}
			}
		}
	}

	*consumed = byte_index;

	return ret;
}