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
 *      initial_max_stream_id_bidir(2),   // MUST. 32 bits, integer.
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

#include "picoquic_internal.h"
#include <string.h>

typedef enum {
    picoquic_transport_parameter_initial_max_stream_data = 0,
    picoquic_transport_parameter_initial_max_data = 1,
    picoquic_transport_parameter_initial_max_stream_id_bidir = 2,
    picoquic_transport_parameter_idle_timeout = 3,
    picoquic_transport_parameter_omit_connection_id = 4,
    picoquic_transport_parameter_max_packet_size = 5,
    picoquic_transport_parameter_reset_secret = 6,
    picoquic_transport_parameter_ack_delay_exponent = 7,
    picoquic_transport_parameter_initial_max_stream_id_unidir = 8,
} picoquic_transport_parameter_enum;

int picoquic_prepare_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t min_size = 0;
    uint16_t param_size = 0;

    /* TODO: version code dependent on version type */

    switch (extension_mode) {
    case 0: // Client hello
        min_size = 4;
        break;
    case 1: // Server encrypted extension
        min_size = 1 + 4 + 4 * picoquic_nb_supported_versions;
        break;
    default: // New session ticket
        break;
    }
    /* add the mandatory parameters */
    param_size = (2 + 2 + 4) + (2 + 2 + 4) + (2 + 2 + 2) + (2 + 2 + 2);
    if (cnx->local_parameters.initial_max_stream_id_bidir != 0) {
        param_size += (2 + 2 + 4);
    }
    if (cnx->local_parameters.omit_connection_id) {
        param_size += 2 + 2;
    }
    if (extension_mode == 1) {
        param_size += 2 + 2 + PICOQUIC_RESET_SECRET_SIZE;
    }
    if (cnx->local_parameters.ack_delay_exponent != 3) {
        param_size += (2 + 2 + 1);
    }
    if (cnx->local_parameters.initial_max_stream_id_unidir != 0) {
        param_size += (2 + 2 + 4);
    }

    min_size += param_size + 2;

    *consumed = min_size;

    if (min_size > bytes_max) {
        ret = PICOQUIC_ERROR_EXTENSION_BUFFER_TOO_SMALL;
    } else {
        switch (extension_mode) {
        case 0: // Client hello
            picoformat_32(bytes + byte_index, cnx->proposed_version);
            byte_index += 4;
            break;
        case 1: // Server encrypted extension
            picoformat_32(bytes + byte_index,
                picoquic_supported_versions[cnx->version_index].version);
            byte_index += 4;

            bytes[byte_index++] = (uint8_t)(4 * picoquic_nb_supported_versions);
            for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
                picoformat_32(bytes + byte_index, picoquic_supported_versions[i].version);
                byte_index += 4;
            }
            break;
        default: // New session ticket
            break;
        }

        picoformat_16(bytes + byte_index, param_size);
        byte_index += 2;

        picoformat_16(bytes + byte_index, picoquic_transport_parameter_initial_max_stream_data);
        byte_index += 2;
        picoformat_16(bytes + byte_index, 4);
        byte_index += 2;
        picoformat_32(bytes + byte_index, cnx->local_parameters.initial_max_stream_data);
        byte_index += 4;

        picoformat_16(bytes + byte_index, picoquic_transport_parameter_initial_max_data);
        byte_index += 2;
        picoformat_16(bytes + byte_index, 4);
        byte_index += 2;
        picoformat_32(bytes + byte_index, cnx->local_parameters.initial_max_data);
        byte_index += 4;

        if (cnx->local_parameters.initial_max_stream_id_bidir > 0) {
            picoformat_16(bytes + byte_index, picoquic_transport_parameter_initial_max_stream_id_bidir);
            byte_index += 2;
            picoformat_16(bytes + byte_index, 4);
            byte_index += 2;
            picoformat_32(bytes + byte_index, cnx->local_parameters.initial_max_stream_id_bidir);
            byte_index += 4;
        }

        picoformat_16(bytes + byte_index, picoquic_transport_parameter_idle_timeout);
        byte_index += 2;
        picoformat_16(bytes + byte_index, 2);
        byte_index += 2;
        picoformat_16(bytes + byte_index, (uint16_t)cnx->local_parameters.idle_timeout);
        byte_index += 2;

        if (cnx->local_parameters.omit_connection_id) {
            picoformat_16(bytes + byte_index, picoquic_transport_parameter_omit_connection_id);
            byte_index += 2;
            picoformat_16(bytes + byte_index, 0);
            byte_index += 2;
        }

        picoformat_16(bytes + byte_index, picoquic_transport_parameter_max_packet_size);
        byte_index += 2;
        picoformat_16(bytes + byte_index, 2);
        byte_index += 2;
        picoformat_16(bytes + byte_index, (uint16_t)cnx->local_parameters.max_packet_size);
        byte_index += 2;

        if (extension_mode == 1) {
            picoformat_16(bytes + byte_index, picoquic_transport_parameter_reset_secret);
            byte_index += 2;
            picoformat_16(bytes + byte_index, PICOQUIC_RESET_SECRET_SIZE);
            byte_index += 2;
            memcpy(bytes + byte_index, cnx->reset_secret, PICOQUIC_RESET_SECRET_SIZE);
            byte_index += PICOQUIC_RESET_SECRET_SIZE;
        }

        if (cnx->local_parameters.ack_delay_exponent != 3) {
            picoformat_16(bytes + byte_index, picoquic_transport_parameter_ack_delay_exponent);
            byte_index += 2;
            picoformat_16(bytes + byte_index, 1);
            byte_index += 2;
            bytes[byte_index++] = cnx->local_parameters.ack_delay_exponent;
        }

        if (cnx->local_parameters.initial_max_stream_id_unidir > 0) {
            picoformat_16(bytes + byte_index, picoquic_transport_parameter_initial_max_stream_id_unidir);
            byte_index += 2;
            picoformat_16(bytes + byte_index, 4);
            byte_index += 2;
            picoformat_32(bytes + byte_index, cnx->local_parameters.initial_max_stream_id_unidir);
            byte_index += 4;
        }
    }

    return ret;
}

int picoquic_receive_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    uint32_t present_flag = 0;

    cnx->remote_parameters_received = 1;

    switch (extension_mode) {
    case 0: // Client hello
        if (bytes_max < 4) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
        } else {
            uint32_t proposed_version;

            proposed_version = PICOPARSE_32(bytes + byte_index);
            byte_index += 4;

            if (picoquic_supported_versions[cnx->version_index].version != proposed_version) {
                for (size_t i = 0; ret == 0 && i < picoquic_nb_supported_versions; i++) {
                    if (proposed_version == picoquic_supported_versions[i].version) {
                        ret = PICOQUIC_ERROR_VERSION_NEGOTIATION_SPOOFED;
                        break;
                    }
                }
            }
        }
        break;
    case 1: // Server encrypted extension
    {
        if (bytes_max < 1) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
        } else {
            if (bytes_max < byte_index + 4) {
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
            } else {
                uint32_t version;

                version = PICOPARSE_32(bytes + byte_index);
                byte_index += 4;

                if (version != picoquic_supported_versions[cnx->version_index].version) {
                    ret = PICOQUIC_ERROR_VERSION_NEGOTIATION_SPOOFED;
                }
            }

            if (ret == 0) {
                size_t supported_versions_size = bytes[byte_index++];

                if ((supported_versions_size & 3) != 0 || supported_versions_size > 252 || byte_index + supported_versions_size > bytes_max) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                } else if (cnx->proposed_version == picoquic_supported_versions[cnx->version_index].version) {
                    byte_index += supported_versions_size;
                } else {
                    size_t nb_supported_versions = supported_versions_size / 4;

                    for (size_t i = 0; ret == 0 && i < nb_supported_versions; i++) {
                        uint32_t supported_version = PICOPARSE_32(bytes + byte_index);
                        byte_index += 4;
                        if (supported_version == cnx->proposed_version) {
                            ret = PICOQUIC_ERROR_VERSION_NEGOTIATION_SPOOFED;
                        }
                    }
                }
            }
        }
        break;
    }
    default: // New session ticket
        break;
    }

    if (ret == 0 && byte_index + 2 > bytes_max) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
    } else {
        uint16_t extensions_size = PICOPARSE_16(bytes + byte_index);
        size_t extensions_end;
        byte_index += 2;
        extensions_end = byte_index + extensions_size;

        /* Set the parameters to default value zero */
        memset(&cnx->remote_parameters, 0, sizeof(picoquic_transport_parameters));
        /* Except for ack_delay_exponent, whose default is 3 */
        cnx->remote_parameters.ack_delay_exponent = 3;

        if (extensions_end > bytes_max) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
        } else
            while (ret == 0 && byte_index < extensions_end) {
                if (byte_index + 4 > extensions_end) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                } else {
                    uint16_t extension_type = PICOPARSE_16(bytes + byte_index);
                    uint16_t extension_length = PICOPARSE_16(bytes + byte_index + 2);
                    byte_index += 4;

                    if (byte_index + extension_length > extensions_end) {
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                    } else {
                        if (extension_type < 64) {
                            if ((present_flag & (1 << extension_type)) != 0) {
                                /* Malformed, already present */
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                present_flag |= (1 << extension_type);
                            }
                        }

                        switch (extension_type) {
                        case picoquic_transport_parameter_initial_max_stream_data:
                            if (extension_length != 4) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                cnx->remote_parameters.initial_max_stream_data = PICOPARSE_32(bytes + byte_index);
                            }
                            /* If we sent zero rtt data, the streams were created with the
                         * old value of the remote parameter. We need to update that.
                         */
                            picoquic_update_stream_initial_remote(cnx);
                            break;
                        case picoquic_transport_parameter_initial_max_data:
                            if (extension_length != 4) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                cnx->remote_parameters.initial_max_data = PICOPARSE_32(bytes + byte_index);
                                cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
                                cnx->max_stream_id_bidir_remote = cnx->local_parameters.initial_max_stream_id_bidir;
                            }
                            break;
                        case picoquic_transport_parameter_initial_max_stream_id_bidir:
                            if (extension_length != 4) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                cnx->remote_parameters.initial_max_stream_id_bidir = PICOPARSE_32(bytes + byte_index);
                                cnx->max_stream_id_bidir_remote = cnx->remote_parameters.initial_max_stream_id_bidir;

                                if (cnx->remote_parameters.initial_max_stream_id_bidir != 0 && (((extension_mode == 0) && (cnx->remote_parameters.initial_max_stream_id_bidir & 1) == 0) || ((extension_mode == 1) && (cnx->remote_parameters.initial_max_stream_id_bidir & 1) != 0) || ((cnx->remote_parameters.initial_max_stream_id_bidir & 2) != 0))) {
                                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                                }
                            }
                            break;
                        case picoquic_transport_parameter_idle_timeout:
                            if (extension_length != 2) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                cnx->remote_parameters.idle_timeout = PICOPARSE_16(bytes + byte_index);
                            }
                            break;
                        case picoquic_transport_parameter_omit_connection_id:
                            if (extension_length != 0) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                if ((cnx->quic->flags & picoquic_context_unconditional_cnx_id) == 0)
                                    cnx->remote_parameters.omit_connection_id = 1;
                            }
                            break;
                        case picoquic_transport_parameter_max_packet_size:
                            if (extension_length != 2) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                cnx->remote_parameters.max_packet_size = PICOPARSE_16(bytes + byte_index);
                            }
                            break;
                        case picoquic_transport_parameter_reset_secret:
                            if (extension_mode != 1) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else if (extension_length != PICOQUIC_RESET_SECRET_SIZE) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                memcpy(cnx->reset_secret, bytes + byte_index, PICOQUIC_RESET_SECRET_SIZE);
                            }
                            break;
                        case picoquic_transport_parameter_ack_delay_exponent:
                            if (extension_length != 1) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                cnx->remote_parameters.ack_delay_exponent = bytes[byte_index];
                            }
                            break;
                        case picoquic_transport_parameter_initial_max_stream_id_unidir:
                            if (extension_length != 4) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                cnx->remote_parameters.initial_max_stream_id_unidir = PICOPARSE_32(bytes + byte_index);
                                cnx->max_stream_id_unidir_remote = cnx->remote_parameters.initial_max_stream_id_unidir;

                                if (cnx->remote_parameters.initial_max_stream_id_unidir != 0 && (((extension_mode == 0) && (cnx->remote_parameters.initial_max_stream_id_unidir & 1) == 0) || ((extension_mode == 1) && (cnx->remote_parameters.initial_max_stream_id_unidir & 1) != 0) || ((cnx->remote_parameters.initial_max_stream_id_unidir & 2) == 0))) {
                                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                                }
                            }
                            break;
                        default:
                            /* ignore unknown extensions */
                            break;
                        }

                        if (ret == 0) {
                            byte_index += extension_length;
                        }
                    }
                }
            }
    }

    /* TODO: check that all required parameters are present, and
     * set default values for optional parameters */

    if (ret == 0 && (present_flag & ((1 << picoquic_transport_parameter_initial_max_stream_data) | (1 << picoquic_transport_parameter_initial_max_data) | (1 << picoquic_transport_parameter_idle_timeout))) != ((1 << picoquic_transport_parameter_initial_max_stream_data) | (1 << picoquic_transport_parameter_initial_max_data) | (1 << picoquic_transport_parameter_idle_timeout))) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
    }
    if (ret == 0 && extension_mode == 1 && (present_flag & (1 << picoquic_transport_parameter_reset_secret)) == 0) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
    }

    *consumed = byte_index;

    return ret;
}
