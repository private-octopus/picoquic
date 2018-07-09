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
 */

#include "picoquic_internal.h"
#include "util.h"
#include <string.h>

uint32_t picoquic_decode_transport_param_stream_id(uint16_t rank, int extension_mode, int stream_type) {
    uint32_t stream_id = 0;
    
    if (rank > 0) {
        stream_type |= (extension_mode == 0) ? PICOQUIC_STREAM_ID_SERVER_INITIATED : PICOQUIC_STREAM_ID_CLIENT_INITIATED;

        if (stream_type == 0) {
            stream_id = 4 * rank;
        }
        else {
            stream_id = 4 * (rank - 1) + stream_type;
        }
    }

    return stream_id;
}

uint16_t picoquic_prepare_transport_param_stream_id(uint32_t stream_id, int extension_mode, int stream_type) {
    uint16_t rank = 0;

    if (stream_id > 0) {
        stream_type |= (extension_mode == 0) ? PICOQUIC_STREAM_ID_SERVER_INITIATED: PICOQUIC_STREAM_ID_CLIENT_INITIATED;

        if (stream_type == 0) {
            rank = (uint16_t) (stream_id/4);
        } else {
            rank = (uint16_t) ((stream_id / 4) + 1);
        }
    }

    return rank;
}

uint16_t picoquic_length_transport_param_prefered_address(picoquic_transport_parameters_prefered_address_t * prefered_address)
{
    uint16_t coded_length = 0;

    if (prefered_address->ipVersion != 0) {
        uint8_t ip_length = (prefered_address->ipVersion == 4) ? 4 : 16;
        coded_length = 1 + 1 + ip_length + 2 +
            1 + prefered_address->connection_id.id_len + 16;
    }

    return coded_length;
}

uint16_t picoquic_prepare_transport_param_prefered_address(uint8_t * bytes, size_t bytes_max, 
    picoquic_transport_parameters_prefered_address_t * prefered_address)
{
    /* first compute the length */
    uint16_t byte_index = 0;
    uint8_t ip_length = (prefered_address->ipVersion == 4) ? 4 : 16;
    size_t coded_length = 1 + 1 + ip_length + 2 +
        1 + prefered_address->connection_id.id_len + 16;

    if (bytes_max >= coded_length) {
        bytes[byte_index++] = prefered_address->ipVersion;
        bytes[byte_index++] = ip_length;
        memcpy(bytes + byte_index, prefered_address->ipAddress, ip_length);
        byte_index += ip_length;
        picoformat_16(bytes + byte_index, prefered_address->port);
        byte_index += 2;
        bytes[byte_index++] = prefered_address->connection_id.id_len;
        byte_index += (uint16_t) picoquic_format_connection_id(bytes + byte_index, bytes_max - byte_index,
            prefered_address->connection_id);
        memcpy(bytes + byte_index, prefered_address->statelessResetToken, 16);
        byte_index += 16;
    }
    return byte_index;
}

size_t picoquic_decode_transport_param_prefered_address(uint8_t * bytes, size_t bytes_max,
    picoquic_transport_parameters_prefered_address_t * prefered_address)
{
    /* first compute the minimal length */
    size_t byte_index = 0;
    uint8_t ip_length = 0;
    uint8_t cnx_id_length = 0;
    size_t minimal_length = 1 + 1 + ip_length + 2 + 1 + cnx_id_length + 16;
    size_t ret = 0;

    if (bytes_max >= minimal_length) {
        prefered_address->ipVersion = bytes[byte_index++];
        ip_length = bytes[byte_index++];
        if ((ip_length == 4 && prefered_address->ipVersion == 4) ||
            (ip_length == 16 && prefered_address->ipVersion == 6)) {
            memcpy(prefered_address->ipAddress, bytes + byte_index, ip_length);
            byte_index += ip_length;
            prefered_address->port = PICOPARSE_16(bytes + byte_index);
            byte_index += 2;
            cnx_id_length = bytes[byte_index++];
            if (byte_index + cnx_id_length + 16 <= bytes_max &&
                cnx_id_length == picoquic_parse_connection_id(bytes + byte_index, cnx_id_length,
                    &prefered_address->connection_id)){
                byte_index += cnx_id_length;
                memcpy(prefered_address->statelessResetToken, bytes + byte_index, 16);
                byte_index += 16;
                ret = byte_index;
            }
        }
    }

    return ret;
}


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
        param_size += (2 + 2 + 2);
    }

    if (extension_mode == 1) {
        param_size += 2 + 2 + PICOQUIC_RESET_SECRET_SIZE;
    }
    if (cnx->local_parameters.ack_delay_exponent != 3) {
        param_size += (2 + 2 + 1);
    }
    if (cnx->local_parameters.initial_max_stream_id_unidir != 0) {
        param_size += (2 + 2 + 2);
    }
    if (cnx->local_parameters.migration_disabled != 0) {
        param_size += (2 + 2);
    }
    if (cnx->local_parameters.prefered_address.ipVersion != 0) {
        param_size += picoquic_length_transport_param_prefered_address(&cnx->local_parameters.prefered_address);
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
            uint16_t bidir = picoquic_prepare_transport_param_stream_id(
                cnx->local_parameters.initial_max_stream_id_bidir,
                extension_mode,
                PICOQUIC_STREAM_ID_BIDIR);

            picoformat_16(bytes + byte_index, picoquic_transport_parameter_initial_max_stream_id_bidir);
            byte_index += 2;
            picoformat_16(bytes + byte_index, 2);
            byte_index += 2;
            picoformat_16(bytes + byte_index, bidir);
            byte_index += 2;
        }

        picoformat_16(bytes + byte_index, picoquic_transport_parameter_idle_timeout);
        byte_index += 2;
        picoformat_16(bytes + byte_index, 2);
        byte_index += 2;
        picoformat_16(bytes + byte_index, (uint16_t)cnx->local_parameters.idle_timeout);
        byte_index += 2;

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

            uint16_t unidir = picoquic_prepare_transport_param_stream_id(
                cnx->local_parameters.initial_max_stream_id_unidir,
                extension_mode,
                PICOQUIC_STREAM_ID_UNIDIR);

            picoformat_16(bytes + byte_index, picoquic_transport_parameter_initial_max_stream_id_unidir);
            byte_index += 2;
            picoformat_16(bytes + byte_index, 2);
            byte_index += 2;
            picoformat_16(bytes + byte_index, unidir);
            byte_index += 2;
        }

        if (cnx->local_parameters.prefered_address.ipVersion != 0 &&
            byte_index + 4 <= bytes_max) {
            uint16_t param_length = picoquic_prepare_transport_param_prefered_address(
                bytes + byte_index + 4, bytes_max - byte_index - 4, &cnx->local_parameters.prefered_address);
            
            if (param_length > 0) {
                picoformat_16(bytes + byte_index, picoquic_transport_parameter_server_prefered_address);
                byte_index += 2;
                picoformat_16(bytes + byte_index, param_length);
                byte_index += 2;
                byte_index += param_length;
            }
        }

        if (cnx->local_parameters.migration_disabled != 0) {
            picoformat_16(bytes + byte_index, picoquic_transport_parameter_disable_migration);
            byte_index += 2;
            picoformat_16(bytes + byte_index, 0);
            byte_index += 2;
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
                            if (extension_length != 2) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                uint16_t bidir = PICOPARSE_16(bytes + byte_index);

                                cnx->remote_parameters.initial_max_stream_id_bidir =
                                    picoquic_decode_transport_param_stream_id(bidir, extension_mode,
                                        PICOQUIC_STREAM_ID_BIDIR);

                                cnx->max_stream_id_bidir_remote = cnx->remote_parameters.initial_max_stream_id_bidir;
                            }
                            break;
                        case picoquic_transport_parameter_idle_timeout:
                            if (extension_length != 2) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                cnx->remote_parameters.idle_timeout = PICOPARSE_16(bytes + byte_index);
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
                            if (extension_length != 2) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            } else {
                                uint16_t unidir = PICOPARSE_16(bytes + byte_index);

                                cnx->remote_parameters.initial_max_stream_id_unidir =
                                    picoquic_decode_transport_param_stream_id(unidir, extension_mode,
                                        PICOQUIC_STREAM_ID_UNIDIR);

                                cnx->max_stream_id_unidir_remote = cnx->remote_parameters.initial_max_stream_id_unidir;
                            }
                            break;
                        case picoquic_transport_parameter_server_prefered_address:
                        {
                            size_t coded_length = picoquic_decode_transport_param_prefered_address(
                                bytes + byte_index, extension_length, &cnx->remote_parameters.prefered_address);

                            if (coded_length != extension_length) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            }
                            break;
                        }
                        case picoquic_transport_parameter_disable_migration:
                            if (extension_length != 0) {
                                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
                            }
                            else {
                                cnx->remote_parameters.migration_disabled = 1;
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

    /* check that all required parameters are present, and
     * that server parameters are not sent by clients */

    if (ret == 0 && (present_flag & (
        (1 << picoquic_transport_parameter_initial_max_stream_data) | 
        (1 << picoquic_transport_parameter_initial_max_data) | 
        (1 << picoquic_transport_parameter_idle_timeout))) != 
        ((1 << picoquic_transport_parameter_initial_max_stream_data) | 
        (1 << picoquic_transport_parameter_initial_max_data) | 
            (1 << picoquic_transport_parameter_idle_timeout))) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
    }

    if (ret == 0 && extension_mode == 1 && 
        (present_flag & (1 << picoquic_transport_parameter_reset_secret)) == 0) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
    }

    if (ret == 0 && extension_mode == 0 &&
        ((present_flag & (1 << picoquic_transport_parameter_reset_secret)) != 0 ||
        (present_flag & (1 << picoquic_transport_parameter_server_prefered_address)) != 0)) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR);
    }

    *consumed = byte_index;

    return ret;
}
