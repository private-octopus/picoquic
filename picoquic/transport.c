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
#include "logwriter.h"
#include "tls_api.h"
#include <string.h>

uint8_t* picoquic_transport_param_varint_encode_old(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n64) 
{
    if (bytes + 2 > bytes_max) {
        bytes = NULL;
    }
    else {
        uint8_t * byte_l;
        size_t l;

        *bytes++ = 0;
        byte_l = bytes;
        *bytes++ = 0;
        l = picoquic_varint_encode(bytes, bytes_max - bytes, n64);
        if (l == 0) {
            bytes = NULL;
        }
        else {
            *byte_l = (uint8_t) l;
            bytes += l;
        }
    }

    return bytes;
}

uint64_t picoquic_transport_param_varint_decode(picoquic_cnx_t * cnx, uint8_t* bytes, uint64_t extension_length, int* ret) 
{
    uint64_t n64 = 0;
    uint64_t l_v = picoquic_varint_decode(bytes, (size_t)extension_length, &n64);

    if (l_v == 0 || l_v != extension_length) {
        *ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
    }

    return n64;
}

uint8_t* picoquic_transport_param_type_varint_encode_old(uint8_t* bytes, const uint8_t* bytes_max, picoquic_tp_enum tp_type, uint64_t n64)
{
    if (bytes != NULL && bytes + 2 <= bytes_max) {
        picoformat_16(bytes, (uint16_t)tp_type);
        bytes = picoquic_transport_param_varint_encode_old(bytes + 2, bytes_max, n64);
    }
    else {
        bytes = NULL;
    }
    return bytes;
}

uint8_t* picoquic_transport_param_varint_encode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t n64)
{
    if (bytes + 1 > bytes_max) {
        bytes = NULL;
    }
    else {
        uint8_t* byte_l = bytes++;
        bytes = picoquic_frames_varint_encode(bytes, bytes_max, n64);
        if (bytes != NULL) {
            *byte_l = (uint8_t)((bytes - byte_l) - 1);
        }
    }

    return bytes;
}

uint8_t* picoquic_transport_param_type_varint_encode(uint8_t* bytes, const uint8_t* bytes_max, picoquic_tp_enum tp_type, uint64_t n64)
{
    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, tp_type)) != NULL) {
        bytes = picoquic_transport_param_varint_encode(bytes, bytes_max, n64);
    }
    return bytes;
}

uint8_t* picoquic_transport_param_type_flag_encode(uint8_t* bytes, const uint8_t* bytes_max, picoquic_tp_enum tp_type)
{
    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, tp_type)) != NULL) {
        bytes = picoquic_frames_varint_encode(bytes, bytes_max, 0);
    }
    return bytes;
}

uint8_t* picoquic_transport_param_cid_encode(uint8_t* bytes, const uint8_t* bytes_max, picoquic_tp_enum tp_type, picoquic_connection_id_t * cid)
{
    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, tp_type)) != NULL) {
        /* frame encoding includes length and the value. */
        bytes = picoquic_frames_cid_encode(bytes, bytes_max, cid);
    }
    return bytes;
}

int picoquic_transport_param_cid_decode(picoquic_cnx_t * cnx, uint8_t* bytes, uint64_t extension_length, picoquic_connection_id_t* cid)
{
    int ret = 0;
    cid->id_len = (uint8_t)picoquic_parse_connection_id(bytes, (uint8_t)extension_length, cid);
    if ((size_t)cid->id_len != extension_length) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
    }

    return ret;
}

uint64_t picoquic_decode_transport_param_stream_id(uint64_t rank, int extension_mode, int stream_type) 
{
    uint64_t stream_id = 0xFFFFFFFFFFFFFFFFull;
    
    if (rank > 0) {
        stream_id = stream_type;
        stream_id += extension_mode^1;

        stream_id += 4 * (rank - 1);
    }

    return stream_id;
}

uint64_t picoquic_prepare_transport_param_stream_id(uint64_t stream_id) 
{
    uint64_t rank = 0;

    if (stream_id != 0xFFFFFFFFFFFFFFFFll) {
        rank = (uint64_t)1 +  (stream_id / 4);
    }

    return rank;
}

uint8_t* picoquic_encode_transport_param_prefered_address_old(uint8_t* bytes, uint8_t* bytes_max,
    picoquic_tp_prefered_address_t* prefered_address)
{
    /* first compute the length */
    uint16_t coded_length = 4u + 2u + 16u + 2u + 1u + prefered_address->connection_id.id_len + 16u;

    if (bytes == NULL || bytes + coded_length > bytes_max) {
        bytes = NULL;
    }
    else {
        picoformat_16(bytes, picoquic_tp_server_preferred_address);
        bytes += 2;
        picoformat_16(bytes, coded_length);
        bytes += 2;
        memcpy(bytes, prefered_address->ipv4Address, 4);
        bytes += 4;
        picoformat_16(bytes, prefered_address->ipv4Port);
        bytes += 2;
        memcpy(bytes, prefered_address->ipv6Address, 16);
        bytes += 16;
        picoformat_16(bytes, prefered_address->ipv4Port);
        bytes += 2;
        *bytes++ = prefered_address->connection_id.id_len;
        bytes += picoquic_format_connection_id(bytes, bytes_max - bytes,
            prefered_address->connection_id);
        memcpy(bytes, prefered_address->statelessResetToken, 16);
        bytes += 16;
    }

    return bytes;
}

uint8_t * picoquic_encode_transport_param_prefered_address(uint8_t * bytes, uint8_t * bytes_max,
    picoquic_tp_prefered_address_t * prefered_address)
{
    /* first compute the length */
    uint64_t coded_length = ((uint64_t)(4 + 2 + 16 + 2 + 1)) + prefered_address->connection_id.id_len + ((uint64_t)16);

    if (bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_tp_server_preferred_address)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, coded_length)) != NULL){
        if (bytes + coded_length > bytes_max) {
            bytes = NULL;
        }
        else {
            memcpy(bytes, prefered_address->ipv4Address, 4);
            bytes += 4;
            picoformat_16(bytes, prefered_address->ipv4Port);
            bytes += 2;
            memcpy(bytes, prefered_address->ipv6Address, 16);
            bytes += 16;
            picoformat_16(bytes, prefered_address->ipv4Port);
            bytes += 2;
            *bytes++ = prefered_address->connection_id.id_len;
            bytes += picoquic_format_connection_id(bytes, bytes_max - bytes,
                prefered_address->connection_id);
            memcpy(bytes, prefered_address->statelessResetToken, 16);
            bytes += 16;
        }
    }

    return bytes;
}

size_t picoquic_decode_transport_param_prefered_address(uint8_t * bytes, size_t bytes_max,
    picoquic_tp_prefered_address_t * prefered_address)
{
    /* first compute the minimal length */
    size_t byte_index = 0;
    uint8_t cnx_id_length = 0;
    size_t minimal_length = 4u + 2u + 16u + 2u + 1u /* + prefered_address->connection_id.id_len */ + 16u;
    size_t ret = 0;

    if (bytes_max >= minimal_length) {
        memcpy(prefered_address->ipv4Address, bytes + byte_index, 4);
        byte_index += 4;
        prefered_address->ipv4Port = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        memcpy(prefered_address->ipv6Address, bytes + byte_index, 16);
        byte_index += 16;
        prefered_address->ipv6Port = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        cnx_id_length = bytes[byte_index++];
        if (cnx_id_length > 0 && cnx_id_length <= PICOQUIC_CONNECTION_ID_MAX_SIZE &&
            byte_index + (size_t)cnx_id_length + 16u <= bytes_max &&
            cnx_id_length == picoquic_parse_connection_id(bytes + byte_index, cnx_id_length,
                &prefered_address->connection_id)){
            byte_index += cnx_id_length;
            memcpy(prefered_address->statelessResetToken, bytes + byte_index, 16);
            byte_index += 16;
            ret = byte_index;
            prefered_address->is_defined = 1;
        }
    }

    return ret;
}

int picoquic_prepare_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_length, size_t* consumed)
{
    int ret = 0;
    uint8_t* bytes_zero = bytes;
    uint8_t* bytes_max = bytes + bytes_length;

    bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_stream_data_bidi_local,
        cnx->local_parameters.initial_max_stream_data_bidi_local);

    bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_data,
        cnx->local_parameters.initial_max_data);

    if (cnx->local_parameters.initial_max_stream_id_bidir > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_streams_bidi,
            picoquic_prepare_transport_param_stream_id(
                cnx->local_parameters.initial_max_stream_id_bidir));
    }

    if (cnx->local_parameters.idle_timeout > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_idle_timeout,
            cnx->local_parameters.idle_timeout);
    }

    bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_max_packet_size,
        cnx->local_parameters.max_packet_size);

    if (cnx->local_parameters.ack_delay_exponent != 3) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_ack_delay_exponent,
            cnx->local_parameters.ack_delay_exponent);
    }

    if (cnx->local_parameters.initial_max_stream_id_unidir > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_streams_uni,
            picoquic_prepare_transport_param_stream_id(cnx->local_parameters.initial_max_stream_id_unidir));
    }

    if (cnx->local_parameters.prefered_address.is_defined) {
        bytes = picoquic_encode_transport_param_prefered_address(
            bytes, bytes_max, &cnx->local_parameters.prefered_address);
    }

    if (cnx->local_parameters.migration_disabled != 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_flag_encode(bytes, bytes_max, picoquic_tp_disable_migration);
    }

    if (cnx->local_parameters.initial_max_stream_data_bidi_remote > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_stream_data_bidi_remote,
            cnx->local_parameters.initial_max_stream_data_bidi_remote);
    }

    if (cnx->local_parameters.initial_max_stream_data_uni > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_initial_max_stream_data_uni,
            cnx->local_parameters.initial_max_stream_data_uni);
    }

    if (cnx->local_parameters.active_connection_id_limit > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_active_connection_id_limit,
            cnx->local_parameters.active_connection_id_limit);
    }

    if (cnx->local_parameters.max_ack_delay != PICOQUIC_ACK_DELAY_MAX_DEFAULT) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_max_ack_delay,
            (cnx->local_parameters.max_ack_delay + 999) / 1000); /* Max ACK delay in milliseconds */
    }
    bytes = picoquic_transport_param_cid_encode(bytes, bytes_max, picoquic_tp_handshake_connection_id, &cnx->path[0]->p_local_cnxid->cnx_id);

    if (extension_mode == 1){
        if (cnx->original_cnxid.id_len > 0) {
            bytes = picoquic_transport_param_cid_encode(bytes, bytes_max, picoquic_tp_original_connection_id, &cnx->original_cnxid);
            bytes = picoquic_transport_param_cid_encode(bytes, bytes_max, picoquic_tp_retry_connection_id, &cnx->initial_cnxid);
        }
        else if (cnx->is_hcid_verified) {
            bytes = picoquic_transport_param_cid_encode(bytes, bytes_max, picoquic_tp_original_connection_id, &cnx->initial_cnxid);
        }
    }

    if (extension_mode == 1) {
        if (bytes != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_tp_stateless_reset_token)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, PICOQUIC_RESET_SECRET_SIZE)) != NULL) {
            if (bytes + PICOQUIC_RESET_SECRET_SIZE < bytes_max) {
                (void)picoquic_create_cnxid_reset_secret(cnx->quic, &cnx->path[0]->p_local_cnxid->cnx_id, bytes);
                bytes += PICOQUIC_RESET_SECRET_SIZE;
            }
            else {
                bytes = NULL;
            }
        }
    }

    if (!cnx->client_mode && cnx->local_parameters.max_datagram_frame_size == 0 &&
        cnx->remote_parameters.max_datagram_frame_size > 0) {
        cnx->local_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
    }

    if (cnx->local_parameters.max_datagram_frame_size > 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_max_datagram_frame_size,
            cnx->local_parameters.max_datagram_frame_size);
    }

    if (cnx->grease_transport_parameters) {
        /* Do not use a purely random value, so we can repetitive tests */
        int n = 31 * (cnx->initial_cnxid.id[0] + cnx->client_mode) + 27;
        uint64_t v = cnx->initial_cnxid.id[1];
        while (n == picoquic_tp_test_large_chello ||
            n == picoquic_tp_enable_loss_bit_old) {
            n += 31;
        }
        v = (v << 8) + cnx->initial_cnxid.id[2];
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, n, v);
    }

    if (cnx->test_large_chello && bytes != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, picoquic_tp_test_large_chello)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, 1200)) != NULL){
        if (bytes + 1200 > bytes_max) {
            bytes = NULL;
        }
        else {
            memset(bytes, 'Q', 1200);
            bytes += 1200;
        }
    }

    if (cnx->local_parameters.enable_loss_bit > 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_enable_loss_bit,
            (cnx->local_parameters.enable_loss_bit > 1) ? 1 : 0);
    }

    if (bytes != NULL && cnx->local_parameters.min_ack_delay > 0) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_min_ack_delay,
            cnx->local_parameters.min_ack_delay);
    }

    if (cnx->local_parameters.enable_time_stamp > 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_varint_encode(bytes, bytes_max, picoquic_tp_enable_time_stamp,
            cnx->local_parameters.enable_time_stamp);
    }

    if (cnx->local_parameters.do_grease_quic_bit > 0 && bytes != NULL) {
        bytes = picoquic_transport_param_type_flag_encode(bytes, bytes_max, picoquic_tp_grease_quic_bit);
    }

    if (bytes == NULL) {
        *consumed = 0;
        ret = PICOQUIC_ERROR_EXTENSION_BUFFER_TOO_SMALL;
    }
    else {
        *consumed = bytes - bytes_zero;
        if (cnx->quic->F_log) {
            picoquic_log_transport_extension(cnx->quic->F_log, cnx, 0, 1, bytes_zero, *consumed);
        }

        if (cnx->f_binlog != NULL) {
            binlog_transport_extension(cnx, 1, NULL, 0, NULL, 0, NULL, 0, *consumed, bytes_zero);
        }
    }

    return ret;
}

void picoquic_clear_transport_extensions(picoquic_cnx_t* cnx)
{
    cnx->remote_parameters.initial_max_stream_data_bidi_local = 0;
    picoquic_update_stream_initial_remote(cnx);
    cnx->remote_parameters.initial_max_stream_data_bidi_remote = 0;
    picoquic_update_stream_initial_remote(cnx);
    cnx->remote_parameters.initial_max_stream_data_uni = 0;
    picoquic_update_stream_initial_remote(cnx);
    cnx->remote_parameters.initial_max_data = 0;
    cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
    cnx->remote_parameters.initial_max_stream_id_bidir = 0;
    cnx->max_stream_id_bidir_remote = 0;
    cnx->remote_parameters.idle_timeout = 0;
    cnx->remote_parameters.max_packet_size = 1500;
    cnx->remote_parameters.ack_delay_exponent = 3;
    cnx->remote_parameters.initial_max_stream_id_unidir = 0;
    cnx->max_stream_id_unidir_remote = 0;
    cnx->remote_parameters.migration_disabled = 0;
    cnx->remote_parameters.max_ack_delay = PICOQUIC_ACK_DELAY_MAX_DEFAULT;
    cnx->remote_parameters.max_datagram_frame_size = 0;
    cnx->remote_parameters.active_connection_id_limit = 0;
    cnx->remote_parameters.enable_loss_bit = 0;
    cnx->remote_parameters.enable_time_stamp = 0;
    cnx->remote_parameters.min_ack_delay = 0;
    cnx->remote_parameters.do_grease_quic_bit = 0;
}

int picoquic_receive_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    uint64_t present_flag = 0;
    picoquic_connection_id_t original_connection_id = picoquic_null_connection_id;
    picoquic_connection_id_t handshake_connection_id = picoquic_null_connection_id;
    picoquic_connection_id_t retry_connection_id = picoquic_null_connection_id;

    cnx->remote_parameters_received = 1;
    picoquic_clear_transport_extensions(cnx);

    if (cnx->quic->F_log) {
        picoquic_log_transport_extension(cnx->quic->F_log, cnx, 1, 1, bytes, bytes_max);
    }
    if (cnx->f_binlog != NULL) {
        binlog_transport_extension(cnx, 0, NULL, 0, NULL, 0, NULL, 0, bytes_max, bytes);
    }

    /* Set the parameters to default value zero */
    memset(&cnx->remote_parameters, 0, sizeof(picoquic_tp_t));
    /* Except for ack_delay_exponent, whose default is 3 */
    cnx->remote_parameters.ack_delay_exponent = 3;

    while (ret == 0 && byte_index < bytes_max) {
        size_t ll_type = 0;
        size_t ll_length = 0;
        uint64_t extension_type = UINT64_MAX;
        uint64_t extension_length = 0;

        if (byte_index + 2 > bytes_max) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
        }
        else {
            ll_type = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &extension_type);
            byte_index += ll_type;
            ll_length = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &extension_length);
            byte_index += ll_length;

            if (ll_type == 0 || ll_length == 0 || byte_index + extension_length > bytes_max) {
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
            }
            else {
                if (extension_type < 64) {
                    if ((present_flag & (1ull << extension_type)) != 0) {
                        /* Malformed, already present */
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                    }
                    else {
                        present_flag |= (1ull << extension_type);
                    }
                }

                switch (extension_type) {
                case picoquic_tp_initial_max_stream_data_bidi_local:
                    cnx->remote_parameters.initial_max_stream_data_bidi_local =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);

                    /* If we sent zero rtt data, the streams were created with the
                     * old value of the remote parameter. We need to update that.
                     */
                    picoquic_update_stream_initial_remote(cnx);
                    break;
                case picoquic_tp_initial_max_stream_data_bidi_remote:
                    cnx->remote_parameters.initial_max_stream_data_bidi_remote =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    /* If we sent zero rtt data, the streams were created with the
                    * old value of the remote parameter. We need to update that.
                    */
                    picoquic_update_stream_initial_remote(cnx);
                    break;
                case picoquic_tp_initial_max_stream_data_uni:
                    cnx->remote_parameters.initial_max_stream_data_uni =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    /* If we sent zero rtt data, the streams were created with the
                    * old value of the remote parameter. We need to update that.
                    */
                    picoquic_update_stream_initial_remote(cnx);
                    break;
                case picoquic_tp_initial_max_data:
                    cnx->remote_parameters.initial_max_data =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
                    break;
                case picoquic_tp_initial_max_streams_bidi: {
                    uint64_t old_limit = cnx->max_stream_id_bidir_remote;
                    cnx->remote_parameters.initial_max_stream_id_bidir =
                        picoquic_decode_transport_param_stream_id(
                            picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret), extension_mode,
                            PICOQUIC_STREAM_ID_BIDIR);

                    cnx->max_stream_id_bidir_remote =
                        (cnx->remote_parameters.initial_max_stream_id_bidir == 0xFFFFFFFF) ? 0 : cnx->remote_parameters.initial_max_stream_id_bidir;

                    picoquic_add_output_streams(cnx, old_limit, cnx->max_stream_id_bidir_remote, 1);
                    break;
                }
                case picoquic_tp_idle_timeout:
                    cnx->remote_parameters.idle_timeout = (uint32_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    break;

                case picoquic_tp_max_packet_size:
                    cnx->remote_parameters.max_packet_size = (uint32_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    break;
                case picoquic_tp_stateless_reset_token:
                    if (extension_mode != 1) {
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                    }
                    else if (extension_length != PICOQUIC_RESET_SECRET_SIZE) {
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                    }
                    else {
                        memcpy(cnx->path[0]->reset_secret, bytes + byte_index, PICOQUIC_RESET_SECRET_SIZE);
                    }
                    break;
                case picoquic_tp_ack_delay_exponent:
                    cnx->remote_parameters.ack_delay_exponent = (uint8_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    break;
                case picoquic_tp_initial_max_streams_uni: {
                    uint64_t old_limit = cnx->max_stream_id_unidir_remote;
                    cnx->remote_parameters.initial_max_stream_id_unidir =
                        picoquic_decode_transport_param_stream_id(
                            picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret), extension_mode,
                            PICOQUIC_STREAM_ID_UNIDIR);

                    cnx->max_stream_id_unidir_remote =
                        (cnx->remote_parameters.initial_max_stream_id_unidir == 0xFFFFFFFF) ? 0 : cnx->remote_parameters.initial_max_stream_id_unidir;
                    picoquic_add_output_streams(cnx, old_limit, cnx->max_stream_id_unidir_remote, 0);
                    break;
                }
                case picoquic_tp_server_preferred_address:
                {
                    uint64_t coded_length = picoquic_decode_transport_param_prefered_address(
                        bytes + byte_index, (size_t)extension_length, &cnx->remote_parameters.prefered_address);

                    if (coded_length != extension_length) {
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                    }
                    break;
                }
                case picoquic_tp_disable_migration:
                    if (extension_length != 0) {
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                    }
                    else {
                        cnx->remote_parameters.migration_disabled = 1;
                    }
                    break;
                case picoquic_tp_max_ack_delay:
                    cnx->remote_parameters.max_ack_delay = (uint32_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret) * 1000;
                    if (cnx->remote_parameters.max_ack_delay > PICOQUIC_MAX_ACK_DELAY_MAX_MS * 1000) {
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                    }
                    break;
                case picoquic_tp_original_connection_id:
                    ret = picoquic_transport_param_cid_decode(cnx, bytes + byte_index, extension_length, &original_connection_id);
                    break;
                case picoquic_tp_retry_connection_id:
                    ret = picoquic_transport_param_cid_decode(cnx, bytes + byte_index, extension_length, &retry_connection_id);
                    break;
                case picoquic_tp_handshake_connection_id:
                    ret = picoquic_transport_param_cid_decode(cnx, bytes + byte_index, extension_length, &handshake_connection_id);
                    if (ret == 0) {
                        if (picoquic_compare_connection_id(&cnx->path[0]->remote_cnxid, &handshake_connection_id) != 0) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        else {
                            cnx->is_hcid_verified = 1;
                        }
                    }
                    break;
                case picoquic_tp_active_connection_id_limit:
                    cnx->remote_parameters.active_connection_id_limit = (uint32_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    /* TODO: may need to check the value, but conditions are unclear */
                    break;
                case picoquic_tp_max_datagram_frame_size:
                    cnx->remote_parameters.max_datagram_frame_size = (uint32_t)
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    break;
                case picoquic_tp_enable_loss_bit_old:
                    /* The old loss bit definition is obsolete */
                    break;
                case picoquic_tp_enable_loss_bit: {
                    uint64_t enabled = picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    if (ret == 0) {
                        if (enabled == 0) {
                            /* Send only variant of loss bit */
                            cnx->remote_parameters.enable_loss_bit = 1;
                        }
                        else if (enabled == 1) {
                            /* Both send and receive are enabled */
                            cnx->remote_parameters.enable_loss_bit = 2;
                        }
                        else {
                            /* Only values 0 and 1 are expected */
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                    }
                    break;
                }
                case picoquic_tp_min_ack_delay:
                    cnx->remote_parameters.min_ack_delay =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);
                    /* Values of 0 and values larger that 2^24 are not expected */
                    if (ret == 0 &&
                        (cnx->remote_parameters.min_ack_delay == 0 ||
                            cnx->remote_parameters.min_ack_delay > PICOQUIC_ACK_DELAY_MIN_MAX_VALUE)) {
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
                    }
                    else {
                        if (cnx->local_parameters.max_ack_delay > 0) {
                            cnx->is_ack_frequency_negotiated = 1;
                        }
                    }
                    break;
                case picoquic_tp_enable_time_stamp: {
                    uint64_t tp_time_stamp =
                        picoquic_transport_param_varint_decode(cnx, bytes + byte_index, extension_length, &ret);

                    if (ret == 0) {
                        if (tp_time_stamp < 1 || tp_time_stamp > 3) {
                            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                        }
                        else {
                            cnx->remote_parameters.enable_time_stamp = (int)tp_time_stamp;
                        }
                    }
                    break;
                }
                case picoquic_tp_grease_quic_bit:
                    if (extension_length != 0) {
                        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                    }
                    else {
                        cnx->remote_parameters.do_grease_quic_bit = 1;
                    }
                    break;
                default:
                    /* ignore unknown extensions */
                    break;
                }

                if (ret == 0) {
                    byte_index += (size_t)extension_length;
                }
            }
        }
    }

    /* Compute the negotiated version of the time out
     */
    cnx->idle_timeout = cnx->local_parameters.idle_timeout;
    if (cnx->idle_timeout == 0 ||
        (cnx->remote_parameters.idle_timeout > 0 && cnx->remote_parameters.idle_timeout < cnx->idle_timeout)) {
        cnx->idle_timeout = cnx->remote_parameters.idle_timeout;
    }
    if (cnx->idle_timeout == 0) {
        cnx->idle_timeout = UINT64_MAX;
    }
    else {
        cnx->idle_timeout *= 1000;
    }

    if (ret == 0 && (present_flag & (1ull << picoquic_tp_max_ack_delay)) == 0) {
        cnx->remote_parameters.max_ack_delay = PICOQUIC_ACK_DELAY_MAX_DEFAULT;
    }

    if (ret == 0 && (present_flag & (1ull << picoquic_tp_active_connection_id_limit)) == 0) {
        if (cnx->path[0]->p_local_cnxid->cnx_id.id_len == 0) {
            cnx->remote_parameters.active_connection_id_limit = 0;
        }
        else {
            cnx->remote_parameters.active_connection_id_limit = PICOQUIC_NB_PATH_DEFAULT;
        }
    }

    /* Clients must not include reset token, server address, retry cid or original cid  */

    if (ret == 0 && extension_mode == 0 &&
        ((present_flag & (1ull << picoquic_tp_stateless_reset_token)) != 0 ||
        (present_flag & (1ull << picoquic_tp_server_preferred_address)) != 0 ||
            (present_flag & (1ull << picoquic_tp_original_connection_id)) != 0 ||
            (present_flag & (1ull << picoquic_tp_retry_connection_id)) != 0)) {
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
    }

    /* In the old versions, there was only one parameter: original CID. In the new versions,
     * there are also retry CID and handshake CID, and the verification logic changed. 
     * If the new extensions are not used and the version is old, we support the
     * old behavior. If the HCID extension is present, we support the new behavior.
     * Most of the verifications happen on the client side, upon receiving server
     * parameters. 
     * TODO: clean up when removing support for version 27.
     */

    if (ret == 0 && picoquic_supported_versions[cnx->version_index].version != PICOQUIC_SEVENTEENTH_INTEROP_VERSION &&
        (present_flag & (1ull << picoquic_tp_handshake_connection_id)) == 0) {
        /* HCID extension becomes mandatory after draft 27 */
        ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
    }

    if (ret == 0 && extension_mode == 1) {
        /* Reeciving server parameters */
        if ((present_flag & (1ull << picoquic_tp_handshake_connection_id)) != 0) {
            /* The HCID extension is present. Verify that the original and retry cnxid are as expected */
            if (cnx->original_cnxid.id_len != 0) {
                /* OCID should be present and match original_cid.
                 * RCID should be present and match initial_cid, since token parsing
                 * verified that initial_cid matches source CID of retry packet. */
                if ((present_flag & (1ull << picoquic_tp_retry_connection_id)) == 0 ||
                    (present_flag & (1ull << picoquic_tp_original_connection_id)) == 0 ||
                    picoquic_compare_connection_id(&cnx->original_cnxid, &original_connection_id) != 0 ||
                    picoquic_compare_connection_id(&cnx->initial_cnxid, &retry_connection_id) != 0) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                }
            }
            else {
                /* RCID should not be present, OCID should be present and match initial_cid */
                if ((present_flag & (1ull << picoquic_tp_retry_connection_id)) != 0 ||
                    (present_flag & (1ull << picoquic_tp_original_connection_id)) == 0 ||
                    picoquic_compare_connection_id(&cnx->initial_cnxid, &original_connection_id) != 0) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
                }
            }
        }
        else  if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_SEVENTEENTH_INTEROP_VERSION) {
            /* Old behavior. Original CID only present if retry */
            if (cnx->original_cnxid.id_len != 0 &&
                ((present_flag & (1ull << picoquic_tp_original_connection_id)) == 0 ||
                    picoquic_compare_connection_id(&cnx->original_cnxid, &original_connection_id) != 0)) {
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PARAMETER_ERROR, 0);
            }
        }
    }

    /* Loss bit is only enabled if negotiated by both parties */
    cnx->is_loss_bit_enabled_outgoing = (cnx->local_parameters.enable_loss_bit > 1) && (cnx->remote_parameters.enable_loss_bit > 0);
    cnx->is_loss_bit_enabled_incoming = (cnx->local_parameters.enable_loss_bit > 0) && (cnx->remote_parameters.enable_loss_bit > 1);

    /* One way delay and Quic_bit_grease only enabled if asked by client and accepted by server */
    if (cnx->client_mode) {
        cnx->is_time_stamp_enabled = 
            (cnx->local_parameters.enable_time_stamp&1) && (cnx->remote_parameters.enable_time_stamp&2);
        cnx->is_time_stamp_sent =
            (cnx->local_parameters.enable_time_stamp & 2) && (cnx->remote_parameters.enable_time_stamp & 2);
        cnx->do_grease_quic_bit = cnx->local_parameters.do_grease_quic_bit && cnx->remote_parameters.do_grease_quic_bit;
    }
    else
    {
        if (cnx->remote_parameters.enable_time_stamp) {
            int v_local = 0;
            if (cnx->remote_parameters.enable_time_stamp & 1) {
                /* Peer wants TS. Say that we can send. */
                v_local |= 2;
                cnx->is_time_stamp_sent = 1;
            }
            if (cnx->remote_parameters.enable_time_stamp & 2) {
                /* Peer can do TS. Say that we want to receive. */
                v_local |= 1;
                cnx->is_time_stamp_enabled = 1;
            }
            cnx->local_parameters.enable_time_stamp = v_local;
        }
        /* When the one way option is set, the server will grease the quic bit if the client supports that,
         * but will not announce support of the grease quic bit, thus asking the client to not set it */
        cnx->local_parameters.do_grease_quic_bit = cnx->remote_parameters.do_grease_quic_bit && !cnx->quic->one_way_grease_quic_bit;
        cnx->do_grease_quic_bit = cnx->remote_parameters.do_grease_quic_bit;
    }

    /* ACK Frequency is only enabled on server if negotiated by client */
    if (!cnx->client_mode && !cnx->is_ack_frequency_negotiated) {
        cnx->local_parameters.min_ack_delay = 0;
    }

    *consumed = byte_index;

    return ret;
}
