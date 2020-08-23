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

#include "picoquic_internal.h"
#include "logwriter.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>

/*
 * Sending logic.
 *
 * Data is sent over streams. This is instantiated by the "Post to stream" command, which
 * chains data to the head of stream structure. Data is unchained when it sent for the
 * first time.
 * 
 * Data is sent in packets, which contain stream frames and possibly other frames.
 * The retransmission logic operates on packets. If a packet is seen as lost, the
 * important frames that it contains will have to be retransmitted.
 *
 * Unacknowledged packets are kept in a chained list. Packets get removed from that
 * list during the processing of acknowledgements. Packets are marked lost when a
 * sufficiently older packet is acknowledged, or after a timer. Lost packets
 * generate new packets, which are queued in the chained list.
 */

static picoquic_stream_head_t* picoquic_find_stream_for_writing(picoquic_cnx_t* cnx,
    uint64_t stream_id, int * ret)
{
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);

    *ret = 0;

    if (stream == NULL) {
        /* Need to check that the ID is authorized */

        /* Check parity */
        if (IS_CLIENT_STREAM_ID(stream_id) != cnx->client_mode) {
            *ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
        }

        if (*ret == 0) {
            stream = picoquic_create_missing_streams(cnx, stream_id, 0);

            if (stream == NULL) {
                *ret = PICOQUIC_ERROR_MEMORY;
            }
        }
    }

    return stream;
}

int picoquic_set_app_stream_ctx(picoquic_cnx_t* cnx,
    uint64_t stream_id, void* app_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);

    if (ret == 0) {
        stream->app_stream_ctx = app_stream_ctx;
    }

    return ret;
}

int picoquic_mark_active_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_active, void * app_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);

    if (ret == 0) {
        if (is_active) {
            /* The call only fails if the stream was closed or reset */
            if (!stream->fin_requested && !stream->reset_requested &&
                cnx->callback_fn != NULL) {
                stream->is_active = 1;
                stream->app_stream_ctx = app_stream_ctx;
                picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));
            }
            else {
                ret = PICOQUIC_ERROR_CANNOT_SET_ACTIVE_STREAM;
            }
        }
        else {
            stream->is_active = 0;
        }
    }

    return ret;
}

int picoquic_mark_high_priority_stream(picoquic_cnx_t * cnx, uint64_t stream_id, int is_high_priority)
{
    if (is_high_priority) {
        cnx->high_priority_stream_id = stream_id;
    }
    else if (cnx->high_priority_stream_id == stream_id) {
        cnx->high_priority_stream_id = (uint64_t)((int64_t)-1);
    }

    return 0;
}

int picoquic_add_to_stream_with_ctx(picoquic_cnx_t* cnx, uint64_t stream_id,
    const uint8_t* data, size_t length, int set_fin, void * app_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);

    if (ret == 0 && set_fin) {
        if (stream->fin_requested) {
            /* app error, notified the fin twice*/
            if (length > 0) {
                ret = -1;
            }
        } else {
            stream->fin_requested = 1;
        }
    }

    /* If our side has sent RST_STREAM or received STOP_SENDING, we should not send anymore data. */
    if (ret == 0 && (stream->reset_sent || stream->stop_sending_received)) {
        ret = -1;
    }

    if (ret == 0 && length > 0) {
        picoquic_stream_data_node_t* stream_data = (picoquic_stream_data_node_t*)malloc(sizeof(picoquic_stream_data_node_t));

        if (stream_data == 0) {
            ret = -1;
        } else {
            stream_data->bytes = (uint8_t*)malloc(length);

            if (stream_data->bytes == NULL) {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            } else {
                picoquic_stream_data_node_t** pprevious = &stream->send_queue;
                picoquic_stream_data_node_t* next = stream->send_queue;

                memcpy(stream_data->bytes, data, length);
                stream_data->length = length;
                stream_data->offset = 0;
                stream_data->next_stream_data = NULL;

                while (next != NULL) {
                    pprevious = &next->next_stream_data;
                    next = next->next_stream_data;
                }

                *pprevious = stream_data;
            }
        }

        picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));
    }

    if (ret == 0) {
        cnx->nb_bytes_queued += length;
        stream->is_active = 0;
        stream->app_stream_ctx = app_stream_ctx;
    }

    return ret;
}

int picoquic_add_to_stream(picoquic_cnx_t* cnx, uint64_t stream_id,
    const uint8_t* data, size_t length, int set_fin)
{
    return picoquic_add_to_stream_with_ctx(cnx, stream_id, data, length, set_fin, NULL);
}

int picoquic_open_flow_control(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t expected_data_size)
{
    int ret = 0;
    uint8_t buffer[512];
    size_t length = 0;
    size_t consumed = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);

    if (cnx->cnx_state == picoquic_state_ready){
        /* Only send the update in ready state, so that the misc frame is not picked by the
         * wrong transport context.
         * TODO: find way to queue the update so it is only sent as 0RTT or 1RTT packet.
         */
        if (stream == NULL) {
            ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
        }
        else {
            uint64_t max_required = stream->consumed_offset + expected_data_size;
            uint8_t* bytes_max = buffer + sizeof(buffer);
            int more_data = 0;
            int is_pure_ack = 1;

            if (max_required > stream->maxdata_local) {
                uint8_t* bytes_next = picoquic_format_max_stream_data_frame(stream, buffer + consumed, bytes_max, &more_data, &is_pure_ack, max_required);
                bytes_next = picoquic_format_max_data_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack, expected_data_size);
                if ((length = bytes_next - buffer) > 0) {
                    ret = picoquic_queue_misc_frame(cnx, buffer, length, is_pure_ack);
                }
            }
        }
    }

    return ret;
}

void picoquic_reset_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    if (stream != NULL) {
        stream->app_stream_ctx = NULL;
    }
}

int picoquic_reset_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else {
        stream->app_stream_ctx = NULL;
        if (stream->fin_sent) {
            ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
        }
        else if (!stream->reset_requested) {
            stream->local_error = local_stream_error;
            stream->reset_requested = 1;
        }
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

uint64_t picoquic_get_next_local_stream_id(picoquic_cnx_t* cnx, int is_unidir)
{
    int stream_type_id = (cnx->client_mode ^ 1) | ((is_unidir) ? 2 : 0);

    return cnx->next_stream_id[stream_type_id];     
}

int picoquic_stop_sending(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else {
        stream->app_stream_ctx = NULL;

        if (stream->reset_received) {
            ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
        }
        else if (!stream->stop_sending_requested) {
            stream->local_stop_error = local_stream_error;
            stream->stop_sending_requested = 1;
            picoquic_insert_output_stream(cnx, stream);
        }
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

/*
 * Manage content padding
 */

size_t picoquic_pad_to_target_length(uint8_t * bytes, size_t length, size_t target)
{
    if (length < target) {
        memset(bytes + length, 0, target - length);
        length = target;
    }

    return length;
}

size_t picoquic_pad_to_policy(picoquic_cnx_t * cnx, uint8_t * bytes, size_t length, uint32_t max_length)
{
    size_t target = cnx->padding_minsize;

    if (length > target && cnx->padding_multiple != 0) {
        uint32_t delta = (length - target) % cnx->padding_multiple;

        if (delta == 0) {
            target = length;
        }
        else {
            target = length + cnx->padding_multiple - delta;
        }
    }

    if (target > max_length) {
        target = max_length;
    }

    return picoquic_pad_to_target_length(bytes, length, target);
}


/*
 * Packet management
 */

picoquic_packet_t* picoquic_create_packet(picoquic_quic_t * quic)
{
    picoquic_packet_t* packet = quic->p_first_packet;
    
    if (packet == NULL) {
        packet = (picoquic_packet_t*)malloc(sizeof(picoquic_packet_t));
    }
    else {
        quic->p_first_packet = packet->next_packet;
        quic->nb_packets_in_pool--;
    }

    if (packet != NULL) {
        memset(packet, 0, offsetof(struct st_picoquic_packet_t, bytes));
    }

    return packet;
}

void picoquic_recycle_packet(picoquic_quic_t * quic, picoquic_packet_t* packet)
{
    if (packet != NULL) {
        if (quic->nb_packets_in_pool >= PICOQUIC_MAX_PACKETS_IN_POOL) {
            free(packet);
        }
        else {
            packet->next_packet = quic->p_first_packet;
            quic->p_first_packet = packet;
            quic->nb_packets_in_pool++;
        }
    }
}

void picoquic_update_payload_length(
    uint8_t* bytes, size_t pnum_index, size_t header_length, size_t packet_length)
{
    if ((bytes[0] & 0x80) != 0 && header_length > 6 && packet_length > header_length && packet_length < 0x4000)
    {
        picoquic_varint_encode_16(bytes + pnum_index - 2, (uint16_t)(packet_length - header_length));
    }
}

size_t picoquic_create_packet_header(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    uint64_t sequence_number,
    picoquic_connection_id_t * remote_cnxid,
    picoquic_connection_id_t * local_cnxid,
    size_t header_length,
    uint8_t* bytes,
    size_t* pn_offset,
    size_t* pn_length)
{
    size_t length = 0;
    picoquic_connection_id_t dest_cnx_id =
        (cnx->client_mode && (packet_type == picoquic_packet_initial ||
            packet_type == picoquic_packet_0rtt_protected)
            && picoquic_is_connection_id_null(remote_cnxid)) ?
        cnx->initial_cnxid : *remote_cnxid;

    /* Prepare the packet header */
    if (packet_type == picoquic_packet_1rtt_protected) {
        /* Create a short packet -- using 32 bit sequence numbers for now */
        uint8_t K = (cnx->key_phase_enc) ? 0x04 : 0;
        uint8_t C = 0x40; /* set the QUIC bit */
        size_t pn_l = 4;  /* default packet length to 4 bytes */

        if (cnx->do_grease_quic_bit) {
            /* we grease the quic bit if both local and remote agreed to do so */
            C &= (uint8_t)picoquic_public_random_64();
            cnx->quic_bit_greased |= (C == 0);
        }

        length = 0;
        bytes[length++] = (K | C | picoquic_spin_function_table[cnx->spin_policy].spinbit_outgoing(cnx));
        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, dest_cnx_id);

        *pn_offset = length;
        if (header_length > length && header_length < length + 4) {
            pn_l = header_length - length;
        }
        *pn_length = pn_l;
        bytes[0] |= (pn_l - 1);
        switch (pn_l) {
        case 1:
            bytes[length] = (uint8_t)sequence_number;
            break;
        case 2:
            picoformat_16(&bytes[length], (uint16_t)sequence_number);
            break;
        case 3:
            picoformat_24(&bytes[length], (uint32_t)sequence_number);
            break;
        default:
            picoformat_32(&bytes[length], (uint32_t)sequence_number);
            break;
        }
        length += pn_l;
    }
    else {
        /* Create a long packet -- default encode PP=3 */

        switch (packet_type) {
        case picoquic_packet_initial:
            bytes[0] = 0xC3;
            break;
        case picoquic_packet_0rtt_protected:
            bytes[0] = 0xD3;
            break;
        case picoquic_packet_handshake:
            bytes[0] = 0xE3;
            break;
        case picoquic_packet_retry:
            /* Do not set PP in retry header, the bits are later used for ODCIL */
            bytes[0] = 0xF0;
            break;
        default:
            bytes[0] = 0xFF; /* Will cause an error... */
            break;
        }

        if (cnx->do_grease_quic_bit) {
            bytes[0] &= 0xBF;
        }

        length = 1;
        if ((cnx->cnx_state == picoquic_state_client_init || cnx->cnx_state == picoquic_state_client_init_sent) && packet_type == picoquic_packet_initial) {
            picoformat_32(&bytes[length], cnx->proposed_version);
        }
        else {
            picoformat_32(&bytes[length], picoquic_supported_versions[cnx->version_index].version);
        }
        length += 4;

        bytes[length++] = dest_cnx_id.id_len;
        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, dest_cnx_id);
        bytes[length++] = local_cnxid->id_len;
        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, *local_cnxid);

        /* Special case of packet initial -- encode token as part of header */
        if (packet_type == picoquic_packet_initial) {
            length += picoquic_varint_encode(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, cnx->retry_token_length);
            if (cnx->retry_token_length > 0) {
                memcpy(&bytes[length], cnx->retry_token, cnx->retry_token_length);
                length += cnx->retry_token_length;
            }
        }

        if (packet_type == picoquic_packet_retry) {
            /* No payload length and no sequence number for Retry */
            *pn_offset = 0;
            *pn_length = 0;
        } else {
            /* Reserve two bytes for payload length */
            bytes[length++] = 0;
            bytes[length++] = 0;
            /* Encode the sequence number */
            *pn_offset = length;
            *pn_length = 4;
            picoformat_32(&bytes[length], (uint32_t) sequence_number);
            length += 4;
        }
    }

    return length;
}

size_t picoquic_predict_packet_header_length(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type)
{
    uint32_t header_length = 0;

    /* The only purpose of the test below is to appease the static analyzer, so it
     * wont complain of possible NULL deref. On windows we could use "__assume(cnx != NULL)
     * but the documentation does not say anything about that for GCC and CLANG */
    if (cnx == NULL) {
        return 0;
    }

    if (packet_type == picoquic_packet_1rtt_protected) {
        /* Predict acceptable length of packet number */
        uint8_t pn_l = 4;
        int64_t delta = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence;
        if (cnx->pkt_ctx[picoquic_packet_context_application].retransmit_oldest != NULL) {
            delta -= cnx->pkt_ctx[picoquic_packet_context_application].retransmit_oldest->sequence_number;
        }
        if (delta < 262144) {
            pn_l = 3;
            if (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < 1024) {
                pn_l = 2;
                if (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < 16) {
                    pn_l = 1;
                }
            }
        }

        /* Compute length of a short packet header */
        header_length = 1 + cnx->path[0]->remote_cnxid.id_len + pn_l;
    }
    else {
        /* Compute length of a long packet header */
        header_length = 1 + /* version */ 4 + /* cnx_id length bytes */ 2;

        /* add dest-id length */
        if (cnx->client_mode && (packet_type == picoquic_packet_initial ||
            packet_type == picoquic_packet_0rtt_protected)
            && picoquic_is_connection_id_null(&cnx->path[0]->remote_cnxid)) {
            header_length += cnx->initial_cnxid.id_len;
        }
        else {
            header_length += cnx->path[0]->remote_cnxid.id_len;
        }

        /* add srce-id length */
        header_length += cnx->path[0]->p_local_cnxid->cnx_id.id_len;

        /* add length of payload length and packet number */
        header_length += 2 + 4;

        /* add length of tokens for initial packets */
        if (packet_type == picoquic_packet_initial) {
            uint8_t useless[16];
            header_length += (uint32_t)picoquic_varint_encode(useless, 16, cnx->retry_token_length);
            header_length += (uint32_t)cnx->retry_token_length;
        }
    }

    return header_length;
}

/*
 * Management of packet protection
 */
size_t picoquic_get_checksum_length(picoquic_cnx_t* cnx, picoquic_epoch_enum epoch)
{
    size_t ret = 16;

    if (cnx->crypto_context[epoch].aead_encrypt != NULL) {
        ret = picoquic_aead_get_checksum_length(cnx->crypto_context[epoch].aead_encrypt);
    }
    else {
        DBG_PRINTF("Try getting checksum for empty context, epoch %d", epoch);
    }

    return ret;
}

static size_t picoquic_protect_packet(picoquic_cnx_t* cnx, 
    picoquic_packet_type_enum ptype,
    uint8_t * bytes, 
    uint64_t sequence_number,
    picoquic_connection_id_t * remote_cnxid,
    picoquic_connection_id_t * local_cnxid,
    size_t length, size_t header_length,
    uint8_t* send_buffer, size_t send_buffer_max,
    void * aead_context, void* pn_enc,
    picoquic_path_t* path_x, uint64_t current_time)
{
    size_t send_length;
    size_t h_length;
    size_t pn_offset = 0;
    size_t sample_offset = 0;
    size_t pn_length = 0;
    size_t aead_checksum_length = picoquic_aead_get_checksum_length(aead_context);
    uint8_t first_mask = 0x0F;

    /* Create the packet header just before encrypting the content */
    h_length = picoquic_create_packet_header(cnx, ptype,
        sequence_number, remote_cnxid, local_cnxid, header_length, send_buffer, &pn_offset, &pn_length);
    if (ptype == picoquic_packet_1rtt_protected) {
        if (remote_cnxid != &path_x->remote_cnxid) {
            /* Packet is sent to a different CID: reset the spin bit and loss bit Q to 0 */
            send_buffer[0] &= 0xDF;
            path_x->q_square = 0;
        }

        if (cnx->is_loss_bit_enabled_outgoing) {
            first_mask = 0x07;
            path_x->q_square++;
            if ((path_x->q_square & PICOQUIC_LOSS_BIT_Q_HALF_PERIOD) != 0) {
                send_buffer[0] |= 0x10;
            }
            if (path_x->nb_losses_found > path_x->nb_losses_reported) {
                send_buffer[0] |= 0x08;
                path_x->nb_losses_reported++;
            }
        }
        else {
            first_mask = 0x1F;
        }
    }

    /* Make sure that the payload length is encoded in the header */
    /* Using encryption, the "payload" length also includes the encrypted packet length */
    picoquic_update_payload_length(send_buffer, pn_offset, h_length - pn_length, length + aead_checksum_length);

    /* If fuzzing is required, apply it*/
    if (cnx->quic->fuzz_fn != NULL) {
        if (h_length == header_length) {
            memcpy(bytes, send_buffer, header_length);
        }
        length = cnx->quic->fuzz_fn(cnx->quic->fuzz_ctx, cnx, bytes,
            send_buffer_max - aead_checksum_length, length, header_length);
        if (h_length == header_length) {
            memcpy(send_buffer, bytes, header_length);
        }
    }

    /* Encrypt the packet */
    send_length = picoquic_aead_encrypt_generic(send_buffer + /* header_length */ h_length,
        bytes + header_length, length - header_length,
        sequence_number, send_buffer, /* header_length */ h_length, aead_context);

    send_length += /* header_length */ h_length;

    /* if needed, log the segment before header protection is applied */
    if (cnx->quic->F_log != NULL && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || cnx->quic->use_long_log)) {
        picoquic_log_outgoing_segment(cnx->quic->F_log, 1, cnx,
            bytes, sequence_number, length,
            send_buffer, send_length, pn_length);
    }
    if (cnx->f_binlog != NULL && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || cnx->quic->use_long_log)) {
        binlog_outgoing_packet(cnx,
            bytes, sequence_number, pn_length, length,
            send_buffer, send_length, current_time);
    }

    /* Next, encrypt the PN -- The sample is located after the pn_offset */
    sample_offset = /* header_length */ pn_offset + 4;

    if (pn_offset < sample_offset)
    {
        /* This is always true, as use pn_length = 4 */
        uint8_t mask_bytes[5] = { 0, 0, 0, 0, 0 };
        uint8_t pn_l;

        picoquic_pn_encrypt(pn_enc, send_buffer + sample_offset, mask_bytes, mask_bytes, 5);
        /* Encode the first byte */
        pn_l = (send_buffer[0] & 3) + 1;
        send_buffer[0] ^= (mask_bytes[0] & first_mask);

        /* Packet encoding is 1 to 4 bytes */
        for (uint8_t i = 0; i < pn_l; i++) {
            send_buffer[pn_offset+i] ^= mask_bytes[i+1];
        }
    }

    return send_length;
}

/* Update the leaky bucket used for pacing.
 */
static void picoquic_update_pacing_bucket(picoquic_path_t * path_x, uint64_t current_time)
{
    if (path_x->pacing_bucket_nanosec < -path_x->pacing_packet_time_nanosec) {
        path_x->pacing_bucket_nanosec = -path_x->pacing_packet_time_nanosec;
    }

    if (current_time > path_x->pacing_evaluation_time) {
        path_x->pacing_bucket_nanosec += (current_time - path_x->pacing_evaluation_time) * 1000;
        path_x->pacing_evaluation_time = current_time;
        if (path_x->pacing_bucket_nanosec > path_x->pacing_bucket_max) {
            path_x->pacing_bucket_nanosec = path_x->pacing_bucket_max;
        }
    }
}

/*
 * Check pacing to see whether the next transmission is authorized.
 * If if is not, update the next wait time to reflect pacing.
 * -
 */
int picoquic_is_sending_authorized_by_pacing(picoquic_cnx_t * cnx, picoquic_path_t * path_x, uint64_t current_time, uint64_t * next_time)
{
    int ret = 1;

    picoquic_update_pacing_bucket(path_x, current_time);
    if (path_x->pacing_bucket_nanosec < path_x->pacing_packet_time_nanosec) {
        int64_t bucket_required = path_x->pacing_packet_time_nanosec - path_x->pacing_bucket_nanosec;
        uint64_t next_pacing_time = current_time + 1 + bucket_required / 1000;
        if (next_pacing_time < *next_time) {
            *next_time = next_pacing_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        ret = 0;
    }

    return ret;
}

/* Reset the pacing data after recomputing the pacing rate
 */
void picoquic_update_pacing_rate(picoquic_cnx_t * cnx, picoquic_path_t* path_x, double pacing_rate, uint64_t quantum)
{
    double packet_time = (double)path_x->send_mtu / pacing_rate;
    double quantum_time = (double)quantum / pacing_rate;
    uint64_t rtt_nanosec = path_x->smoothed_rtt * 1000;

    path_x->pacing_rate = (uint64_t)pacing_rate;

    path_x->pacing_packet_time_nanosec = (uint64_t)(packet_time * 1000000000.0);

    if (path_x->pacing_packet_time_nanosec <= 0) {
        path_x->pacing_packet_time_nanosec = 1;
        path_x->pacing_packet_time_microsec = 1;
    }
    else {
        if ((uint64_t)path_x->pacing_packet_time_nanosec > rtt_nanosec) {
            path_x->pacing_packet_time_nanosec = rtt_nanosec;
        }
        path_x->pacing_packet_time_microsec = (path_x->pacing_packet_time_nanosec + 1023ull) / 1000;
    }

    path_x->pacing_bucket_max = (uint64_t)(quantum_time * 1000000000.0);
    if (path_x->pacing_bucket_max <= 0) {
        path_x->pacing_bucket_max = 16 * path_x->pacing_packet_time_nanosec;
    }

    if (path_x->pacing_bucket_nanosec > path_x->pacing_bucket_max) {
        path_x->pacing_bucket_nanosec = path_x->pacing_bucket_max;
    }

    if (cnx->is_pacing_update_requested && path_x == cnx->path[0] &&
        cnx->callback_fn != NULL) {
        if ((path_x->pacing_rate > cnx->pacing_rate_signalled &&
            (path_x->pacing_rate - cnx->pacing_rate_signalled >= cnx->pacing_increase_threshold)) ||
            (path_x->pacing_rate < cnx->pacing_rate_signalled &&
            (cnx->pacing_rate_signalled - path_x->pacing_rate > cnx->pacing_decrease_threshold))){
            (void)cnx->callback_fn(cnx, path_x->pacing_rate, NULL, 0, picoquic_callback_pacing_changed, cnx->callback_ctx, NULL);
            cnx->pacing_rate_signalled = path_x->pacing_rate;
        }
    }
}

/*
 * Reset the pacing data after CWIN is updated.
 * The max bucket is set to contain at least 2 packets more than 1/8th of the congestion window.
 */

void picoquic_update_pacing_data(picoquic_cnx_t* cnx, picoquic_path_t * path_x, int slow_start)
{
    uint64_t rtt_nanosec = path_x->smoothed_rtt * 1000;

    if ((path_x->cwin < ((uint64_t)path_x->send_mtu) * 8) || rtt_nanosec <= 1000) {
        /* Small windows, should only relie on ACK clocking */
        path_x->pacing_bucket_max = rtt_nanosec;
        path_x->pacing_packet_time_nanosec = 1;
        path_x->pacing_packet_time_microsec = 1;

        if (path_x->pacing_bucket_nanosec > path_x->pacing_bucket_max) {
            path_x->pacing_bucket_nanosec = path_x->pacing_bucket_max;
        }
    }
    else {
        double pacing_rate = ((double)path_x->cwin / (double)rtt_nanosec) * 1000000000.0;
        uint64_t quantum = path_x->cwin / 4;

        if (quantum < 2ull * path_x->send_mtu) {
            quantum = 2ull * path_x->send_mtu;
        }
        else {
            if (slow_start && path_x->smoothed_rtt > 4*PICOQUIC_MAX_BANDWIDTH_TIME_INTERVAL_MAX) {
                const uint64_t quantum_min = 0x8000;
                if (quantum  < quantum_min){
                    quantum = quantum_min;
                }
                else {
                    uint64_t quantum2 = (uint64_t)((pacing_rate * PICOQUIC_MAX_BANDWIDTH_TIME_INTERVAL_MAX) / 1000000.0);
                    if (quantum2 > quantum_min) {
                        quantum = quantum2;
                    }
                }
            }
            else if (quantum > 16ull * path_x->send_mtu) {
                quantum = 16ull * path_x->send_mtu;
            }

        }

        if (slow_start) {
            pacing_rate *= 1.25;
        }

        picoquic_update_pacing_rate(cnx, path_x, pacing_rate, quantum);
    }
}

/* 
 * Update the pacing data after sending a packet.
 */
void picoquic_update_pacing_after_send(picoquic_path_t * path_x, uint64_t current_time)
{
    picoquic_update_pacing_bucket(path_x, current_time);

    path_x->pacing_bucket_nanosec -= path_x->pacing_packet_time_nanosec;
}

/*
 * Final steps in packet transmission: queue for retransmission, etc
 */

void picoquic_queue_for_retransmit(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    size_t length, uint64_t current_time)
{
    picoquic_packet_context_enum pc = packet->pc;

    /* Manage the double linked packet list for retransmissions */
    packet->previous_packet = NULL;
    if (cnx->pkt_ctx[pc].retransmit_newest == NULL) {
        packet->next_packet = NULL;
        cnx->pkt_ctx[pc].retransmit_oldest = packet;
    } else {
        packet->next_packet = cnx->pkt_ctx[pc].retransmit_newest;
        packet->next_packet->previous_packet = packet;
    }
    cnx->pkt_ctx[pc].retransmit_newest = packet;

    if (!packet->is_ack_trap) {
        /* Account for bytes in transit, for congestion control */
        path_x->bytes_in_transit += length;
        /* Update the pacing data */
        picoquic_update_pacing_after_send(path_x, current_time);
    }
}

picoquic_packet_t* picoquic_dequeue_retransmit_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p, int should_free)
{
    size_t dequeued_length = p->length + p->checksum_overhead;
    picoquic_packet_context_enum pc = p->pc;

    if (p->previous_packet == NULL) {
        cnx->pkt_ctx[pc].retransmit_newest = p->next_packet;
    }
    else {
        p->previous_packet->next_packet = p->next_packet;
    }

    if (p->next_packet == NULL) {
        cnx->pkt_ctx[pc].retransmit_oldest = p->previous_packet;
    }
    else {
#ifdef _DEBUG
        if (p->next_packet->pc != pc) {
            DBG_PRINTF("Inconsistent PC in queue, %d vs %d\n", p->next_packet->pc, pc);
        }

        if (p->next_packet->previous_packet != p) {
            DBG_PRINTF("Inconsistent chain of packets, pc = %d\n", pc);
        }
#endif
        p->next_packet->previous_packet = p->previous_packet;
    }

    /* Account for bytes in transit, for congestion control */

    if (p->send_path != NULL && !p->is_ack_trap) {
        if (p->send_path->bytes_in_transit > dequeued_length) {
            p->send_path->bytes_in_transit -= dequeued_length;
        }
        else {
            p->send_path->bytes_in_transit = 0;
        }
    }

    if (should_free || p->is_ack_trap) {
        picoquic_recycle_packet(cnx->quic, p);
        p = NULL;
    }
    else {
        p->next_packet = NULL;

        /* add this packet to the retransmitted list */
        if (cnx->pkt_ctx[pc].retransmitted_oldest == NULL) {
            cnx->pkt_ctx[pc].retransmitted_newest = p;
            cnx->pkt_ctx[pc].retransmitted_oldest = p;
            p->previous_packet = NULL;
        }
        else {
            cnx->pkt_ctx[pc].retransmitted_newest->next_packet = p;
            p->previous_packet = cnx->pkt_ctx[pc].retransmitted_newest;
            cnx->pkt_ctx[pc].retransmitted_newest = p;
        }
    }

    return p;
}

void picoquic_dequeue_retransmitted_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p)
{
    picoquic_packet_context_enum pc = p->pc;

    if (p->next_packet == NULL) {
        cnx->pkt_ctx[pc].retransmitted_newest = p->previous_packet;
    }
    else {
        p->next_packet->previous_packet = p->previous_packet;
    }

    if (p->previous_packet == NULL) {
        cnx->pkt_ctx[pc].retransmitted_oldest = p->next_packet;
    }
    else {
#ifdef _DEBUG
        if (p->previous_packet->pc != pc) {
            DBG_PRINTF("Inconsistent PC in queue, %d vs %d\n", p->previous_packet->pc, pc);
        }

        if (p->previous_packet->next_packet != p) {
            DBG_PRINTF("Inconsistent chain of packets, pc = %d\n", pc);
        }
#endif
        p->previous_packet->next_packet = p->next_packet;
    }

    picoquic_recycle_packet(cnx->quic, p);
}

/*
 * Inserting holes in the send sequence to trap optimistic ack.
 * return 0 if hole was inserted, !0 if packet should be freed.
 */
void picoquic_insert_hole_in_send_sequence_if_needed(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t * next_wake_time)
{
    if (cnx->quic->sequence_hole_pseudo_period == 0) {
        /* Holing disabled. Set to max value, never worry about it later */
        cnx->pkt_ctx[0].next_sequence_hole = (uint64_t)((int64_t)-1);
    } else if (cnx->cnx_state == picoquic_state_ready &&
        cnx->pkt_ctx[0].retransmit_newest != NULL &&
        cnx->pkt_ctx[0].send_sequence >= cnx->pkt_ctx[0].next_sequence_hole) {
        if (cnx->pkt_ctx[0].next_sequence_hole != 0 &&
            !cnx->pkt_ctx[0].retransmit_newest->is_ack_trap) {
            /* Insert a hole in sequence */
            picoquic_packet_t* packet = picoquic_create_packet(cnx->quic);

            if (packet != NULL) {
                packet->is_ack_trap = 1;
                packet->pc = picoquic_packet_context_application;
                packet->ptype = picoquic_packet_1rtt_protected;
                packet->send_path = cnx->path[0];
                packet->send_time = current_time;
                packet->sequence_number = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence++;
                picoquic_queue_for_retransmit(cnx, cnx->path[0], packet, 0, current_time);
                *next_wake_time = current_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                /* Simulate local loss on the Q bit square function. */
                cnx->path[0]->q_square++;
            }
        }
        /* Predict the next hole*/
        cnx->pkt_ctx[0].next_sequence_hole = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence + 3 + picoquic_public_uniform_random(cnx->quic->sequence_hole_pseudo_period);
    }
}

/*
 * Final steps of encoding and protecting the packet before sending
 */

void picoquic_finalize_and_protect_packet(picoquic_cnx_t *cnx, picoquic_packet_t * packet, int ret, 
    size_t length, size_t header_length, size_t checksum_overhead,
    size_t * send_length, uint8_t * send_buffer, size_t send_buffer_max,
    picoquic_connection_id_t * remote_cnxid,
    picoquic_connection_id_t * local_cnxid,
    picoquic_path_t * path_x, uint64_t current_time)
{
    if (length != 0 && length < header_length) {
        length = 0;
    }

    if (ret == 0 && length > 0) {
        packet->length = length;
        cnx->pkt_ctx[packet->pc].send_sequence++;
        path_x->latest_sent_time = current_time;
        path_x->path_cid_rotated = 0;
        packet->delivered_prior = path_x->delivered_last;
        packet->delivered_time_prior = path_x->delivered_time_last;
        packet->delivered_sent_prior = path_x->delivered_sent_last;
        packet->delivered_app_limited = (cnx->cnx_state < picoquic_state_ready || path_x->delivered_limited_index != 0);

        switch (packet->ptype) {
        case picoquic_packet_version_negotiation:
            /* Packet is not encrypted */
            break;
        case picoquic_packet_initial:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_initial].aead_encrypt, cnx->crypto_context[picoquic_epoch_initial].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_handshake:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt, cnx->crypto_context[picoquic_epoch_handshake].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_retry:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_0rtt].aead_encrypt, cnx->crypto_context[picoquic_epoch_0rtt].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_0rtt_protected:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number, 
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_0rtt].aead_encrypt, cnx->crypto_context[picoquic_epoch_0rtt].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_1rtt_protected:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[picoquic_epoch_1rtt].aead_encrypt, cnx->crypto_context[picoquic_epoch_1rtt].pn_enc,
                path_x, current_time);
            break;
        default:
            /* Packet type error. Do nothing at all. */
            length = 0;
            break;
        }

        *send_length = length;

        if (length > 0) {
            packet->checksum_overhead = checksum_overhead;
            picoquic_queue_for_retransmit(cnx, path_x, packet, length, current_time);
        } else {
            *send_length = 0;
        }
    }
    else {
        *send_length = 0;
    }
}

/*
 * If a retransmit is needed, fill the packet with the required
 * retransmission. Also, prune the retransmit queue as needed.
 *
 * TODO: consider that the retransmit timer is per path, from the path on
 * which the packet was first sent, but the retransmission may be on 
 * a different path, with different MTU.
 */

static uint64_t picoquic_current_retransmit_timer(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc)
{
    uint64_t rto = cnx->path[0]->retransmit_timer;

    rto <<= cnx->pkt_ctx[pc].nb_retransmit;
    if (cnx->cnx_state < picoquic_state_ready) {
        if (rto > PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER) {
            rto = PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER;
        }
    }
    else if (rto > PICOQUIC_LARGE_RETRANSMIT_TIMER &&
        cnx->path[0]->rtt_min > PICOQUIC_TARGET_SATELLITE_RTT) {
        uint64_t alt_rto = (cnx->path[0]->smoothed_rtt*3) >> 1;
        if (alt_rto < rto) {
            rto = alt_rto;
        }
    }

    return rto;
}

static int picoquic_retransmit_needed_by_packet(picoquic_cnx_t* cnx,
    picoquic_packet_t* p, uint64_t current_time, uint64_t * next_retransmit_time, int* timer_based)
{
    picoquic_packet_context_enum pc = p->pc;
    uint64_t retransmit_time;
    int64_t delta_seq = cnx->pkt_ctx[pc].highest_acknowledged - p->sequence_number;
    int should_retransmit = 0;
    int is_timer_based = 0;

    if (delta_seq > 0) {
        /* By default, we use an RTO  */
        retransmit_time = p->send_time + cnx->path[0]->retransmit_timer;
        /* RACK logic works best when the amount of reordering is not too large */
        if (delta_seq < 3) {
            /* When just a few ulterior packets are acknowledged, we work from the right edge. */
            uint64_t rack_timer_min = cnx->pkt_ctx[pc].highest_acknowledged_time +
                cnx->remote_parameters.max_ack_delay + (cnx->path[0]->smoothed_rtt >> 2);
            if (retransmit_time > rack_timer_min) {
                retransmit_time = rack_timer_min;
            }
        } else {
            /* When enough ulterior packets are acknowledged, we work from the right edge. */
            uint64_t rack_timer_min = p->send_time + (cnx->path[0]->smoothed_rtt >> 2);
            if (rack_timer_min < cnx->pkt_ctx[pc].latest_time_acknowledged) {
                retransmit_time = cnx->pkt_ctx[pc].highest_acknowledged_time;
            }
        }
    }
    else
    {
        /* There has not been any higher packet acknowledged, thus we fall back on timer logic. */
        retransmit_time = p->send_time + picoquic_current_retransmit_timer(cnx, pc);
        is_timer_based = 1;
    }

    if (p->ptype == picoquic_packet_0rtt_protected) {
        /* Special case for 0RTT packets */
        if (cnx->cnx_state != picoquic_state_ready &&
            cnx->cnx_state != picoquic_state_client_ready_start) {
            /* Set the retransmit time ahead of current time since the connection is not ready */
            retransmit_time = current_time + cnx->path[0]->smoothed_rtt + PICOQUIC_RACK_DELAY;
        } else if (!cnx->zero_rtt_data_accepted) {
            /* Zero RTT data was not accepted by the peer, the packets are considered lost */
            retransmit_time = current_time;
        }
    }

    if (current_time >= retransmit_time || (p->is_ack_trap && delta_seq > 0)) {
        should_retransmit = 1;
        *timer_based = is_timer_based;
        if (cnx->quic->sequence_hole_pseudo_period != 0 && pc == picoquic_packet_context_application && !p->is_ack_trap) {
            DBG_PRINTF("Retransmit #%d, delta=%d, timer=%d, time=%d, sent: %d, ack_t: %d, s_rtt: %d, rt: %d",
                (int)p->sequence_number, (int)delta_seq, is_timer_based, (int)current_time, (int)p->send_time, 
                (int)cnx->pkt_ctx[pc].latest_time_acknowledged, (int)cnx->path[0]->smoothed_rtt, (int) retransmit_time);
        }
    }
    
    *next_retransmit_time = retransmit_time;

    return should_retransmit;
}

int picoquic_queue_stream_frame_for_retransmit(picoquic_cnx_t* cnx, uint8_t * bytes, size_t length)
{
    int ret = 0;
    picoquic_misc_frame_header_t* misc = picoquic_create_misc_frame(bytes, length, 0);

    if (misc == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        misc->next_misc_frame = NULL;
        if (cnx->stream_frame_retransmit_queue_last == NULL) {
            cnx->stream_frame_retransmit_queue = misc;
            cnx->stream_frame_retransmit_queue_last = misc;
        }
        else {
            misc->previous_misc_frame = cnx->stream_frame_retransmit_queue_last;
            cnx->stream_frame_retransmit_queue_last->next_misc_frame = misc;
            cnx->stream_frame_retransmit_queue_last = misc;
        }
    }

    return ret;
}

int picoquic_copy_before_retransmit(picoquic_packet_t * old_p,
    picoquic_cnx_t * cnx,
    uint8_t * new_bytes,
    size_t send_buffer_max_minus_checksum,
    int * packet_is_pure_ack,
    int * do_not_detect_spurious,
    size_t * length)
{
    /* check if this is an ACK only packet */
    int ret = 0;
    int frame_is_pure_ack = 0;
    size_t frame_length = 0;
    size_t byte_index = 0; /* Used when parsing the old packet */
    
    if (old_p->is_mtu_probe) {
        if (old_p->send_path != NULL) {
            /* MTU probe was lost, presumably because of packet too big */
            old_p->send_path->mtu_probe_sent = 0;
            old_p->send_path->send_mtu_max_tried = old_p->length + old_p->checksum_overhead;
        }
        /* MTU probes should not be retransmitted */
        *packet_is_pure_ack = 1;
        *do_not_detect_spurious = 0;
    }
    else if (old_p->is_ack_trap) {
        *packet_is_pure_ack = 1;
        *do_not_detect_spurious = 0;
    }
    else {
        /* Copy the relevant bytes from one packet to the next */
        byte_index = old_p->offset;

        while (ret == 0 && byte_index < old_p->length) {
            ret = picoquic_skip_frame(&old_p->bytes[byte_index],
                old_p->length - byte_index, &frame_length, &frame_is_pure_ack);

            /* Check whether the data was already acked, which may happen in
             * case of spurious retransmissions */
            if (ret == 0 && frame_is_pure_ack == 0) {
                ret = picoquic_check_frame_needs_repeat(cnx, &old_p->bytes[byte_index],
                    frame_length, &frame_is_pure_ack);
            }

            /* Prepare retransmission if needed */
            if (ret == 0 && !frame_is_pure_ack) {
                if (PICOQUIC_IN_RANGE(old_p->bytes[byte_index], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
                    ret = picoquic_queue_stream_frame_for_retransmit(cnx, &old_p->bytes[byte_index], frame_length);
                }
                else {
                    if (frame_length > send_buffer_max_minus_checksum - *length &&
                        (old_p->ptype == picoquic_packet_0rtt_protected || old_p->ptype == picoquic_packet_1rtt_protected)) {
                        ret = picoquic_queue_misc_frame(cnx, &old_p->bytes[byte_index], frame_length, 0);
                    }
                    else {
                        memcpy(&new_bytes[*length], &old_p->bytes[byte_index], frame_length);
                        *length += frame_length;
                    }
                }
                *packet_is_pure_ack = 0;
            }
            byte_index += frame_length;
        }
    }

    return ret;
}

int picoquic_retransmit_needed(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc,
    picoquic_path_t * path_x, uint64_t current_time, uint64_t * next_wake_time,
    picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length)
{
    picoquic_packet_t* old_p = cnx->pkt_ctx[pc].retransmit_oldest;
    size_t length = 0;

    /* TODO: while packets are pure ACK, drop them from retransmit queue */
    while (old_p != NULL) {
        picoquic_path_t * old_path = old_p->send_path; /* should be the path on which the packet was transmitted */
        int should_retransmit = 0;
        int timer_based_retransmit = 0;
        uint64_t next_retransmit_time = *next_wake_time;
        uint64_t lost_packet_number = old_p->sequence_number;
        picoquic_packet_t* p_next = old_p->previous_packet;
        uint8_t * new_bytes = packet->bytes;
        int ret = 0;

        length = 0;

        /* Get the packet type */

        should_retransmit = cnx->initial_repeat_needed || 
            picoquic_retransmit_needed_by_packet(cnx, old_p, current_time, &next_retransmit_time, &timer_based_retransmit);

        if (should_retransmit == 0) {
            /*
             * Always retransmit in order. If not this one, then nothing.
             * But make an exception for 0-RTT packets.
             */
            if (old_p->ptype == picoquic_packet_0rtt_protected) {
                old_p = p_next;
                continue;
            }
            else {
                if (next_retransmit_time < *next_wake_time) {
                    *next_wake_time = next_retransmit_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
                break;
            }
        } else if (old_p->is_ack_trap){
            picoquic_dequeue_retransmit_packet(cnx, old_p, 1);
            old_p = p_next;
            continue;
        } else {
            /* check if this is an ACK only packet */
            int packet_is_pure_ack = 1;
            int do_not_detect_spurious = 1;
            int frame_is_pure_ack = 0;
            uint8_t* old_bytes = old_p->bytes;
            size_t frame_length = 0;
            size_t byte_index = 0; /* Used when parsing the old packet */
            size_t checksum_length = 0;

	        /* we'll report it where it got lost */
            if (old_path) {
                old_path->retrans_count++;
            }

            *header_length = 0;

            if (old_p->ptype == picoquic_packet_0rtt_protected) {
                /* Only retransmit as 0-RTT if contains crypto data */
                int contains_crypto = 0;
                byte_index = old_p->offset;

                if (old_p->is_evaluated == 0) {
                    while (ret == 0 && byte_index < old_p->length) {
                        if (old_bytes[byte_index] == picoquic_frame_type_crypto_hs) {
                            contains_crypto = 1;
                            packet_is_pure_ack = 0;
                            break;
                        }
                        ret = picoquic_skip_frame(&old_p->bytes[byte_index],
                            old_p->length - byte_index, &frame_length, &frame_is_pure_ack);
                        byte_index += frame_length;
                    }
                    old_p->contains_crypto = contains_crypto;
                    old_p->is_pure_ack = packet_is_pure_ack;
                    old_p->is_evaluated = 1;
                } else {
                    contains_crypto = old_p->contains_crypto;
                    packet_is_pure_ack = old_p->is_pure_ack;
                }

                if (contains_crypto) {
                    length = picoquic_predict_packet_header_length(cnx, picoquic_packet_0rtt_protected);
                    packet->ptype = picoquic_packet_0rtt_protected;
                    packet->offset = length;
                } else if (cnx->cnx_state < picoquic_state_client_ready_start) {
                    should_retransmit = 0;
                } else {
                    length = picoquic_predict_packet_header_length(cnx, picoquic_packet_1rtt_protected);
                    packet->ptype = picoquic_packet_1rtt_protected;
                    packet->offset = length;
                }
            } else {
                length = picoquic_predict_packet_header_length(cnx, old_p->ptype);
                packet->ptype = old_p->ptype;
                packet->offset = length;
            }

            if (should_retransmit != 0) {
                packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                packet->send_path = path_x;
                packet->pc = pc;

                *header_length = length;

                switch (packet->ptype) {
                case picoquic_packet_1rtt_protected:
                    checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
                    break;
                case picoquic_packet_initial:
                    checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_initial);
                    break;
                case picoquic_packet_handshake:
                    checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_handshake);
                    break;
                case picoquic_packet_0rtt_protected:
                    checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_0rtt);
                    break;
                default:
                    DBG_PRINTF("Trying to retransmit packet type %d", old_p->ptype);
                    checksum_length = 0;
                    break;
                }

                ret = picoquic_copy_before_retransmit(old_p, cnx,
                    new_bytes,
                    send_buffer_max - checksum_length,
                    &packet_is_pure_ack,
                    &do_not_detect_spurious,
                    &length);

                if (ret != 0) {
                    DBG_PRINTF("Copy before retransmit returns %d\n", ret);
                }

                /* Update the number of bytes in transit and remove old packet from queue */
                /* If not pure ack, the packet will be placed in the "retransmitted" queue,
                 * in order to enable detection of spurious restransmissions */

                if (cnx->f_binlog != NULL) {
                    binlog_packet_lost(cnx, old_p->ptype, old_p->sequence_number,
                        (timer_based_retransmit == 0) ? "repeat" : "timer",
                        (old_p->send_path == NULL) ? NULL : &old_p->send_path->remote_cnxid,
                        old_p->length, current_time);
                }
                old_p = picoquic_dequeue_retransmit_packet(cnx, old_p, packet_is_pure_ack & do_not_detect_spurious);

                /* If we have a good packet, return it */
                if (old_p == NULL || packet_is_pure_ack) {
                    length = 0;
                } else {
                    if (old_p->send_path != NULL &&
                        (old_p->length + old_p->checksum_overhead) == old_p->send_path->send_mtu) {
                        old_p->send_path->nb_mtu_losses++;
                        if (old_p->send_path->nb_mtu_losses > PICOQUIC_MTU_LOSS_THRESHOLD) {
                            picoquic_reset_path_mtu(old_p->send_path);
                            picoquic_log_app_message(cnx,
                                "Reset path MTU after %d retransmissions, %d MTU losses",
                                cnx->pkt_ctx[pc].nb_retransmit,
                                old_p->send_path->nb_mtu_losses);
                        }
                    }

                    if (timer_based_retransmit != 0) {
                        if (cnx->pkt_ctx[pc].nb_retransmit > 7 && cnx->cnx_state >= picoquic_state_ready) {
                            /*
                             * Max retransmission count was exceeded. Disconnect.
                             */
                            DBG_PRINTF("Too many retransmits of packet number %d, disconnect", (int)old_p->sequence_number);
                            cnx->cnx_state = picoquic_state_disconnected;
                            if (cnx->callback_fn) {
                                (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
                            }
                            length = 0;
                            break;
                        } else {
                            if (cnx->pkt_ctx[pc].nb_retransmit == 0 ||
                                old_p->sequence_number >= cnx->pkt_ctx[pc].retransmit_sequence) {
                                cnx->pkt_ctx[pc].nb_retransmit++;
                                cnx->pkt_ctx[pc].latest_retransmit_time = current_time;
                                cnx->pkt_ctx[pc].retransmit_sequence = packet->sequence_number;
                            }
                        }
                    }

                    if (old_p->ptype < picoquic_packet_1rtt_protected) {
                        DBG_PRINTF("Retransmit packet type %d, pc=%d, seq = %llx, is_client = %d\n",
                            old_p->ptype, old_p->pc,
                            (unsigned long long)old_p->sequence_number, cnx->client_mode);
                    }

                    /* special case for the client initial */
                    if (old_p->ptype == picoquic_packet_initial && cnx->client_mode) {
                        length = picoquic_pad_to_target_length(new_bytes, length, send_buffer_max - checksum_length);
                    }
                    packet->length = length;
                    cnx->nb_retransmission_total++;

                    if (old_path != NULL) {
                        old_path->nb_losses_found++;
                        old_path->total_bytes_lost += old_p->length;

                        if (cnx->congestion_alg != NULL && cnx->cnx_state >= picoquic_state_ready) {
                            cnx->congestion_alg->alg_notify(cnx, old_path,
                                (timer_based_retransmit == 0) ? picoquic_congestion_notification_repeat : picoquic_congestion_notification_timeout,
                                0, 0, 0, lost_packet_number, current_time);
                        }
                    }
                    
                    if (length <= packet->offset) {
                        length = 0;
                        if (!packet_is_pure_ack) {
                            /* Pace down the next retransmission so as to not pile up error upon error */
                            path_x->pacing_bucket_nanosec -= path_x->pacing_packet_time_nanosec;
                        }
                    }
                    else {
                        break;
                    }
                }
            }
        }
        /*
         * If the loop is continuing, this means that we need to look
         * at the next candidate packet.
         */
        old_p = p_next;
    }

    return (int)length;
}

/*
 * Returns true if there is nothing to repeat in the retransmission queue
 */
int picoquic_is_cnx_backlog_empty(picoquic_cnx_t* cnx)
{
    int backlog_empty = 1;

    for (picoquic_packet_context_enum pc = 0;
        backlog_empty == 1 && pc < picoquic_nb_packet_context; pc++)
    {
        picoquic_packet_t* p = cnx->pkt_ctx[pc].retransmit_oldest;

        if ((cnx->cnx_state == picoquic_state_ready) && (pc != picoquic_packet_context_application)) {
            continue;
        }

        while (p != NULL && backlog_empty == 1) {
            /* check if this is an ACK only packet */
            int ret = 0;
            int frame_is_pure_ack = 0;
            size_t frame_length = 0;
            size_t byte_index = 0; /* Used when parsing the old packet */

            byte_index = p->offset;


            while (ret == 0 && byte_index < p->length) {
                ret = picoquic_skip_frame(&p->bytes[byte_index],
                    p->length - p->offset, &frame_length, &frame_is_pure_ack);

                if (!frame_is_pure_ack) {
                    backlog_empty = 0;
                    break;
                }
                byte_index += frame_length;
            }

            p = p->previous_packet;
        }
    }

    return backlog_empty;
}

/* Decide whether MAX data need to be sent or not */
int picoquic_should_send_max_data(picoquic_cnx_t* cnx)
{
    int ret = 0;

    if (2 * cnx->data_received > cnx->maxdata_local)
        ret = 1;

    return ret;
}

/* Compute the next logical probe length */
static size_t picoquic_next_mtu_probe_length(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    size_t probe_length;

    if (path_x->send_mtu_max_tried == 0) {
        if (cnx->remote_parameters.max_packet_size > 0) {
            probe_length = cnx->remote_parameters.max_packet_size;

            if (cnx->quic->mtu_max > 0 && (int)probe_length > cnx->quic->mtu_max) {
                probe_length = cnx->quic->mtu_max;
            }
            else if (probe_length > PICOQUIC_MAX_PACKET_SIZE) {
                probe_length = PICOQUIC_MAX_PACKET_SIZE;
            }
            if (probe_length < path_x->send_mtu) {
                probe_length = path_x->send_mtu;
            }
        }
        else if (cnx->quic->mtu_max > 0) {
            probe_length = cnx->quic->mtu_max;
        }
        else {
            probe_length = PICOQUIC_PRACTICAL_MAX_MTU;
        }
    }
    else {
        if (path_x->send_mtu_max_tried > 1500) {
            probe_length = 1500;
        }
        else if (path_x->send_mtu_max_tried > 1400) {
            probe_length = 1400;
        }
        else {
            probe_length = (path_x->send_mtu + path_x->send_mtu_max_tried) / 2;
        }
    }

    return probe_length;
}

/* Decide whether to send an MTU probe */
picoquic_pmtu_discovery_status_enum picoquic_is_mtu_probe_needed(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    int ret = picoquic_pmtu_discovery_not_needed;

    if ((cnx->cnx_state == picoquic_state_ready || cnx->cnx_state == picoquic_state_client_ready_start || cnx->cnx_state == picoquic_state_server_false_start)
        && path_x->mtu_probe_sent == 0) {
        if (path_x->send_mtu_max_tried == 0 || path_x->send_mtu_max_tried > 1400) {
            /* MTU discovery is required if the chances of success are large enough
             * and there are enough packets to send to amortize the discovery cost.
             * Of course we don't know at this stage how much data will be sent 
             * on the connection; we take the amount of data queued as a proxy
             * for that. */
            uint64_t next_probe = picoquic_next_mtu_probe_length(cnx, path_x);
            if (next_probe > path_x->send_mtu) {
                if (cnx->is_pmtud_required) {
                    ret = picoquic_pmtu_discovery_required;
                }
                else {
                    uint64_t packets_to_send_before = cnx->nb_bytes_queued / path_x->send_mtu;
                    uint64_t packets_to_send_after = cnx->nb_bytes_queued / next_probe;
                    uint64_t delta = (packets_to_send_before - packets_to_send_after) * 60;
                    if (delta > next_probe) {
                        ret = picoquic_pmtu_discovery_required;
                    }
                    else {
                        ret = picoquic_pmtu_discovery_optional;
                    }
                }
            }
        }
    }

    return ret;
}

/* Prepare an MTU probe packet */
size_t picoquic_prepare_mtu_probe(picoquic_cnx_t* cnx,
    picoquic_path_t * path_x,
    size_t header_length, size_t checksum_length,
    uint8_t* bytes)
{
    size_t probe_length = picoquic_next_mtu_probe_length(cnx, path_x);
    size_t length = header_length;

    bytes[length++] = picoquic_frame_type_ping;
    memset(&bytes[length], 0, probe_length - checksum_length - length);

    return probe_length - checksum_length;
}

/* Prepare the next packet to 0-RTT packet to send in the client initial
 * state, when 0-RTT is available
 */
int picoquic_prepare_packet_0rtt(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    int padding_required, uint64_t * next_wake_time)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;
    picoquic_packet_type_enum packet_type = picoquic_packet_0rtt_protected;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    size_t length = 0;
    size_t checksum_overhead = picoquic_aead_get_checksum_length(cnx->crypto_context[1].aead_encrypt);
    uint8_t* bytes_max;
    uint8_t* bytes_next;
    int more_data = 0;
    int is_pure_ack = 1;
    int stream_tried_and_failed = 0;

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;
    if (path_x->bytes_in_transit + send_buffer_max > PICOQUIC_DEFAULT_0RTT_WINDOW) {
        if (path_x->bytes_in_transit > PICOQUIC_DEFAULT_0RTT_WINDOW) {
            send_buffer_max = 0;
        }
        else {
            send_buffer_max = (size_t)PICOQUIC_DEFAULT_0RTT_WINDOW - (size_t)path_x->bytes_in_transit;
        }
    }
    bytes_max = bytes + send_buffer_max - checksum_overhead;

    stream = picoquic_find_ready_stream(cnx);
    length = picoquic_predict_packet_header_length(cnx, packet_type);
    packet->ptype = picoquic_packet_0rtt_protected;
    packet->offset = length;
    header_length = length;
    packet->pc = picoquic_packet_context_application;
    packet->sequence_number = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence;
    packet->send_time = current_time;
    packet->send_path = path_x;
    packet->checksum_overhead = checksum_overhead;
    bytes_next = bytes + length;


    
    /* Consider sending 0-RTT */
    if ((stream == NULL && cnx->first_misc_frame == NULL && padding_required == 0) || 
        send_buffer_max < PICOQUIC_MIN_SEGMENT_SIZE) {
        length = 0;
    } else {
        /* If present, send misc frame */
        while (cnx->first_misc_frame != NULL) {
            uint8_t* bytes_misc = bytes_next;
            bytes_next = picoquic_format_first_misc_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
            if (bytes_next == bytes_misc) {
                break;
            }
        }

        /* Encode the stream frame, or frames */
        bytes_next = picoquic_format_available_stream_frames(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack, &stream_tried_and_failed, &ret);

        length = bytes_next - bytes;

        if (more_data) {
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }

        if (stream_tried_and_failed) {
            path_x->last_sender_limited_time = current_time;
        }

        /* Add padding if required */
        if (padding_required) {
            length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_max,
        &path_x->remote_cnxid,
        &path_x->p_local_cnxid->cnx_id,
        path_x, current_time);

    if (length > 0) {
        /* Accounting of zero rtt packets sent */
        cnx->nb_zero_rtt_sent++;
    }

    /* the reinsertion by wake up time will happen in the calling function */

    return ret;
}

/* Get packet type from epoch */
picoquic_packet_type_enum picoquic_packet_type_from_epoch(int epoch)
{
    picoquic_packet_type_enum ptype;

    switch (epoch) {
    case 0:
        ptype = picoquic_packet_initial;
        break;
    case 1:
        ptype = picoquic_packet_0rtt_protected;
        break;
    case 2:
        ptype = picoquic_packet_handshake;
        break;
    case 3:
        ptype = picoquic_packet_1rtt_protected;
        break;
    default:
        ptype = picoquic_packet_error;
        break;
    }

    return ptype;
}

/* Prepare a required repetition or ack in a previous context */
size_t picoquic_prepare_packet_old_context(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, picoquic_packet_t* packet, size_t send_buffer_max, uint64_t current_time,
    uint64_t* next_wake_time, size_t* header_length)
{
    picoquic_epoch_enum epoch = (pc == picoquic_packet_context_initial) ? picoquic_epoch_initial :
        (pc == picoquic_packet_context_application) ? picoquic_epoch_0rtt : picoquic_epoch_handshake;
    size_t length = 0;
    uint8_t* bytes = packet->bytes;
    int more_data = 0;
    size_t checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
    uint8_t* bytes_max = bytes + send_buffer_max - checksum_overhead;
    uint8_t* bytes_next;

    *header_length = 0;

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, send_buffer_max, header_length);
    if (length > 0 && (pc == picoquic_packet_context_handshake || cnx->pkt_ctx[picoquic_packet_context_handshake].retransmit_oldest == NULL ||
        cnx->cnx_state == picoquic_state_server_init || cnx->cnx_state == picoquic_state_server_handshake)) {
        cnx->initial_repeat_needed = 0;
    }

    if (length == 0 && cnx->pkt_ctx[pc].ack_needed != 0 &&
        pc != picoquic_packet_context_application) {
        packet->ptype =
            (pc == picoquic_packet_context_initial) ? picoquic_packet_initial :
            (pc == picoquic_packet_context_handshake) ? picoquic_packet_handshake :
                picoquic_packet_0rtt_protected;
        length = picoquic_predict_packet_header_length(cnx, packet->ptype);
        packet->offset = length;
        *header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
    }

    if (length > 0) {
        if (packet->ptype != picoquic_packet_0rtt_protected) {
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            bytes_next = picoquic_format_ack_frame(cnx, bytes + length, bytes_max, &more_data, current_time, pc);
            length = bytes_next - bytes;
        }
        packet->length = length;
        /* document the send time & overhead */
        packet->send_time = current_time;
        packet->checksum_overhead = checksum_overhead;
        packet->pc = pc;
    }

    return length;
}

/* Empty the handshake repeat queues when transitioning to the completely ready state */
void picoquic_implicit_handshake_ack(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t current_time)
{
    picoquic_packet_t* p = cnx->pkt_ctx[pc].retransmit_oldest;

    /* Remove packets from the retransmit queue */
    while (p != NULL) {
        picoquic_packet_t* p_next = p->next_packet;
        picoquic_path_t * old_path = p->send_path;

        /* Update the congestion control state for the path, but only for the packets sent
         * before the initial timer. */
        if (old_path != NULL && cnx->congestion_alg != NULL && p->send_time < cnx->start_time + PICOQUIC_INITIAL_RTT) {
            cnx->congestion_alg->alg_notify(cnx, old_path,
                picoquic_congestion_notification_acknowledgement,
                0, 0, p->length, 0, current_time);
        }
        /* Update the number of bytes in transit and remove old packet from queue */
        /* The packet will not be placed in the "retransmitted" queue */
        (void)picoquic_dequeue_retransmit_packet(cnx, p, 1);

        p = p_next;
    }
}

/* Program a migration to the server preferred address if present */
int picoquic_prepare_server_address_migration(picoquic_cnx_t* cnx)
{
    int ret = 0;

    if (cnx->remote_parameters.prefered_address.is_defined)
    {
        int ipv4_received = cnx->remote_parameters.prefered_address.ipv4Port != 0;
        int ipv6_received = cnx->remote_parameters.prefered_address.ipv6Port != 0;

        /* Add the connection ID to the local stash */
        ret = picoquic_enqueue_cnxid_stash(cnx, 1,
            cnx->remote_parameters.prefered_address.connection_id.id_len,
            cnx->remote_parameters.prefered_address.connection_id.id,
            cnx->remote_parameters.prefered_address.statelessResetToken,
            NULL);
        if (ret != 0) {
            ret = picoquic_connection_error(cnx, (uint16_t)ret, picoquic_frame_type_new_connection_id);
        }
        else if(ipv4_received || ipv6_received) {
            struct sockaddr_storage dest_addr;

            memset(&dest_addr, 0, sizeof(struct sockaddr_storage));

            /* program a migration. */
            if (ipv4_received && cnx->path[0]->peer_addr.ss_family == AF_INET) {
                /* select IPv4 */
                ipv6_received = 0;
            }

            if (ipv6_received) {
                /* configure an IPv6 sockaddr */
                struct sockaddr_in6 * d6 = (struct sockaddr_in6 *)&dest_addr;
                d6->sin6_family = AF_INET6;
                d6->sin6_port = htons(cnx->remote_parameters.prefered_address.ipv6Port);
                memcpy(&d6->sin6_addr, cnx->remote_parameters.prefered_address.ipv6Address, 16);
            }
            else {
                /* configure an IPv4 sockaddr */
                struct sockaddr_in * d4 = (struct sockaddr_in *)&dest_addr;
                d4->sin_family = AF_INET;
                d4->sin_port = htons(cnx->remote_parameters.prefered_address.ipv4Port);
                memcpy(&d4->sin_addr, cnx->remote_parameters.prefered_address.ipv4Address, 4);
            }

            /* Only send a probe if not already using that address */
            if (picoquic_compare_addr((struct sockaddr *)&dest_addr, (struct sockaddr *)&cnx->path[0]->peer_addr) != 0) {
                struct sockaddr* local_addr = NULL;
                if (cnx->path[0]->local_addr.ss_family != 0) {
                    local_addr = (struct sockaddr*) & cnx->path[0]->local_addr;
                }

                ret = picoquic_probe_new_path_ex(cnx, (struct sockaddr *)&dest_addr, local_addr,
                    picoquic_get_quic_time(cnx->quic), 1);
            }
        }
    }

    return ret;
}

/* Prepare the next packet to send when in one of the client initial states */
int picoquic_prepare_packet_client_init(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t * next_wake_time,
    int * is_initial_sent)
{
    int ret = 0;
    int tls_ready = 0;
    picoquic_packet_type_enum packet_type = 0;
    size_t checksum_overhead = 16;
    int is_cleartext_mode = 1;
    int retransmit_possible = 0;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max;
    uint8_t* bytes_next;
    size_t length = 0;
    int epoch = 0;
    int is_pure_ack = 1;
    int more_data = 0;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;

    if (*next_wake_time > cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX) {
        *next_wake_time = cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }

    cnx->initial_validated = 1; /* always validated on client */

    if (cnx->tls_stream[0].send_queue == NULL) {
        if (cnx->crypto_context[1].aead_encrypt != NULL &&
            cnx->tls_stream[1].send_queue != NULL) {
            epoch = 1;
            pc = picoquic_packet_context_application;
        } else if (cnx->crypto_context[2].aead_encrypt != NULL && 
            cnx->tls_stream[1].send_queue == NULL) {
            epoch = 2;
            pc = picoquic_packet_context_handshake;
        } 
    }

    packet_type = picoquic_packet_type_from_epoch(epoch);

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    /* Prepare header -- depend on connection state */
    switch (cnx->cnx_state) {
    case picoquic_state_client_init:
        if (cnx->retry_token_length == 0 && cnx->sni != NULL) {
            (void)picoquic_get_token(cnx->quic->p_first_token, current_time, cnx->sni, (uint16_t)strlen(cnx->sni),
                NULL, 0, &cnx->retry_token, &cnx->retry_token_length, 1);
        }
        break;
    case picoquic_state_client_init_sent:
    case picoquic_state_client_init_resent:
        retransmit_possible = 1;
        break;
    case picoquic_state_client_renegotiate:
        packet_type = picoquic_packet_initial;
        break;
    case picoquic_state_client_handshake_start:
        retransmit_possible = 1;
        break;
    case picoquic_state_client_almost_ready:
        break;
    default:
        ret = -1;
        break;
    }

    /* If context is handshake, verify first that there is no need for retransmit or ack
     * on initial context */
    int force_handshake_padding = 0;

    if (ret == 0) {
        if (epoch > picoquic_epoch_initial) {
            if (cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt != NULL) {
                if (cnx->pkt_ctx[picoquic_packet_context_initial].ack_needed) {
                    /* Apply some ack delay, because handshake from server arrive in trains */
                    uint64_t ack_delay = cnx->path[0]->smoothed_rtt / 8;
                    uint64_t ack_time;
                    if (ack_delay > PICOQUIC_ACK_DELAY_MAX) {
                        ack_delay = PICOQUIC_ACK_DELAY_MAX;
                    }
                    ack_time = cnx->pkt_ctx[picoquic_packet_context_initial].time_oldest_unack_packet_received + ack_delay;
                    if (ack_time <= current_time) {
                        force_handshake_padding = 1;
                    }
                    else if (ack_time < *next_wake_time) {
                        *next_wake_time = ack_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
                else if (!force_handshake_padding && cnx->pkt_ctx[pc].retransmit_newest != NULL) {
                    /* There is a risk of deadlock if the server is doing DDOS mitigation
                     * and does not receive the Handshake sent by the client. If more than RTT has elapsed since
                     * the last handshake packet was sent, force another one to be sent. */
                    uint64_t rto = picoquic_current_retransmit_timer(cnx, picoquic_packet_context_handshake);
                    uint64_t repeat_time = cnx->pkt_ctx[pc].retransmit_newest->send_time + rto;

                    if (repeat_time <= current_time) {
                        force_handshake_padding = 1;
                        cnx->pkt_ctx[pc].nb_retransmit++;
                    }
                    else if (repeat_time < *next_wake_time) {
                        *next_wake_time = repeat_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
            }
            else {
                length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
                    path_x, packet, send_buffer_max, current_time, next_wake_time, &header_length);
                *is_initial_sent |= (length > 0);
            }
        }
        else {
            /* There is a risk of deadlock if the server is doing DDOS mitigation
             * and does not repeat an initial or handshake packet that was lost. If more than RTT has elapsed since
             * the last initial packet was sent, force another one to be sent. */
            uint64_t rto = picoquic_current_retransmit_timer(cnx, picoquic_packet_context_initial);
            uint64_t repeat_time = cnx->path[0]->latest_sent_time + rto;
            force_handshake_padding = (repeat_time <= current_time);
        }
    }

    if (ret == 0 && epoch > picoquic_epoch_0rtt && length == 0 &&
        cnx->crypto_context[picoquic_epoch_0rtt].aead_encrypt != NULL) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_application,
            path_x, packet, send_buffer_max, current_time, next_wake_time, &header_length);
    }

    /* If there is nothing to send in previous context, check this one too */
    if (length == 0) {
        checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
        packet->checksum_overhead = checksum_overhead;
        bytes_max = bytes + send_buffer_max - checksum_overhead;
        packet->pc = pc;

        tls_ready = picoquic_is_tls_stream_ready(cnx);

        if (ret == 0 && retransmit_possible &&
            (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, send_buffer_max, &header_length)) > 0) {
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            if (epoch != picoquic_epoch_0rtt) {
                bytes_next = picoquic_format_ack_frame(cnx, bytes + length, bytes_max, &more_data, current_time, pc);
                length = bytes_next - bytes;
            } 
            /* document the send time & overhead */
            packet->length = length;
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
        }
        else if (ret == 0 && is_cleartext_mode && tls_ready == 0
            && cnx->first_misc_frame == NULL && !cnx->pkt_ctx[pc].ack_needed && !force_handshake_padding) {
            /* when in a clear text mode, only send packets if there is
            * actually something to send, or resend. */

            packet->length = 0;
        }
        else if (ret == 0) {
            if (cnx->crypto_context[epoch].aead_encrypt == NULL) {
                packet->length = 0;
            }
            else {
                length = picoquic_predict_packet_header_length(cnx, packet_type);
                packet->ptype = packet_type;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                packet->send_time = current_time;
                packet->send_path = path_x;
                bytes_next = bytes + length;
                bytes_max = bytes + send_buffer_max - checksum_overhead;

                if ((tls_ready == 0 || path_x->cwin <= path_x->bytes_in_transit)
                    && (cnx->cnx_state == picoquic_state_client_almost_ready
                        || picoquic_is_ack_needed(cnx, current_time, next_wake_time, pc) == 0)
                    && cnx->first_misc_frame == NULL && !force_handshake_padding) {
                    length = 0;
                }
                else {
                    if (epoch != 1 && cnx->pkt_ctx[pc].ack_needed) {
                        bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data, current_time, pc);
                    }

                    /* If present, send misc frame */
                    while (cnx->first_misc_frame != NULL) {
                        uint8_t* bytes_misc = bytes_next;
                        bytes_next = picoquic_format_first_misc_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                        if (bytes_next == bytes_misc) {
                            break;
                        }
                    }
                    length = bytes_next - bytes;

                    if (ret == 0 && path_x->cwin > path_x->bytes_in_transit) {
                        /* Encode the crypto handshake frame */
                        if (tls_ready != 0) {
                            /* Encode the crypto frame */
                            bytes_next = picoquic_format_crypto_hs_frame(&cnx->tls_stream[epoch],
                                bytes_next, bytes_max, &more_data, &is_pure_ack);
                            length = bytes_next - bytes;
                        }

                        if (packet_type == picoquic_packet_initial) {
                            *is_initial_sent = 1;
                            if (cnx->crypto_context[1].aead_encrypt == NULL ||
                                cnx->cnx_state == picoquic_state_client_renegotiate ||
                                cnx->original_cnxid.id_len != 0) {
                                /* Pad to minimum packet length. But don't do that if the
                                 * initial packet will be coalesced with 0-RTT packet */
                                length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
                            }
                        }
                    }

                    if (length == header_length) {
                        length = picoquic_pad_to_target_length(bytes, length, length + 8);
                    }

                    if (length > header_length && epoch == picoquic_epoch_handshake) {
                        cnx->pkt_ctx[picoquic_packet_context_initial].ack_needed = 0;
                    }

                    /* If TLS packets are sent, progress the state */
                    if (ret == 0 && tls_ready != 0 && 
                        cnx->tls_stream[epoch].send_queue == NULL) {
                        switch (cnx->cnx_state) {
                        case picoquic_state_client_init:
                            cnx->cnx_state = picoquic_state_client_init_sent;
                            break;
                        case picoquic_state_client_renegotiate:
                            cnx->cnx_state = picoquic_state_client_init_resent;
                            break;
                        case picoquic_state_client_almost_ready:
                            if (cnx->tls_stream[0].send_queue == NULL &&
                                cnx->tls_stream[1].send_queue == NULL &&
                                cnx->tls_stream[2].send_queue == NULL) {
                                cnx->cnx_state = picoquic_state_client_ready_start;
                                /* Reset the HS retransmission count, since end of flight counts as acknowledgement */
                                cnx->pkt_ctx[picoquic_packet_context_handshake].nb_retransmit = 0;
                                /* Signal the application, because data can now be sent. */
                                if (cnx->callback_fn != NULL) {
                                    if (cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_almost_ready, cnx->callback_ctx, NULL) != 0) {
                                        picoquic_log_app_message(cnx, "Callback almost ready returns error 0x%x", PICOQUIC_TRANSPORT_INTERNAL_ERROR);
                                        picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
                                    }
                                }
                            }
                            break;
                        default:
                            break;
                        }
                    }
                }
            }
        }
    }

    if (ret == 0 && length == 0) {
        /* In some circumstances, there is a risk that the handshakes stops because the
         * server is performing anti-dos mitigation and the client has nothing to repeat */
        if ((packet->ptype == picoquic_packet_initial && cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt == NULL &&
            cnx->pkt_ctx[picoquic_packet_context_initial].retransmit_newest == NULL &&
            cnx->pkt_ctx[picoquic_packet_context_initial].first_sack_item.end_of_sack_range != UINT64_MAX) ||
            (packet->ptype == picoquic_packet_handshake &&
                cnx->pkt_ctx[picoquic_packet_context_handshake].retransmit_newest == NULL &&
                cnx->pkt_ctx[picoquic_packet_context_handshake].first_sack_item.end_of_sack_range == UINT64_MAX &&
                cnx->pkt_ctx[picoquic_packet_context_handshake].send_sequence == 0))
        {
            uint64_t try_time_next = cnx->path[0]->latest_sent_time + cnx->path[0]->smoothed_rtt;
            if (current_time < try_time_next) {
                /* schedule a wake time to repeat the probing. */
                if (*next_wake_time > try_time_next) {
                    *next_wake_time = try_time_next;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
            else {
                length = header_length;
                packet->offset = length;
                if (packet->ptype == picoquic_packet_initial) {
                    /* Repeat an ACK because it helps. */
                    bytes_max = bytes + send_buffer_max - checksum_overhead;
                    bytes_next = picoquic_format_ack_frame(cnx, bytes + length, bytes_max, &more_data, current_time, pc);
                    length = bytes_next - bytes;

                    length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
                }
                else {
                    length = picoquic_pad_to_target_length(bytes, length, length + 8);
                }
            }
        }
    }

    if (ret == 0 && length == 0 && cnx->crypto_context[1].aead_encrypt != NULL) {
        ret = picoquic_prepare_packet_0rtt(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length,
                *is_initial_sent, next_wake_time);
    }
    else {
        if (ret == 0 && more_data) {
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }

        if (ret == 0 && *is_initial_sent) {
            if (packet->ptype == picoquic_packet_initial) {
                if (length > 0 && cnx->crypto_context[1].aead_encrypt == NULL && 
                    (cnx->crypto_context[2].aead_encrypt == NULL || length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE > send_buffer_max ||
                        !picoquic_is_tls_stream_ready(cnx))) {
                    length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
                }
            }
            else if (packet->ptype == picoquic_packet_handshake && length + checksum_overhead < send_buffer_max &&
                (cnx->crypto_context[3].aead_encrypt == NULL || length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE > send_buffer_max)) {
                length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
            }
            else if (packet->ptype == picoquic_packet_1rtt_protected) {
                length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
            }
        }

        if (length > 0 && packet->ptype == picoquic_packet_handshake && !is_pure_ack) {
            /* Sending an ack eliciting handshake packet terminates the use of the initial context */
            picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_initial, current_time);
            picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_initial]);
        }

        picoquic_finalize_and_protect_packet(cnx, packet,
            ret, length, header_length, checksum_overhead,
            send_length, send_buffer, send_buffer_max,
            &path_x->remote_cnxid, &path_x->p_local_cnxid->cnx_id, path_x, current_time);
    }

    return ret;
}

/* Compute the time at which to send the next challenge
 */

uint64_t picoquic_next_challenge_time(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
{
    uint64_t next_challenge_time = path_x->challenge_time;

    if (path_x->challenge_repeat_count >= 2) {
        next_challenge_time += path_x->retransmit_timer << path_x->challenge_repeat_count;
    }
    else {
        next_challenge_time += PICOQUIC_INITIAL_RETRANSMIT_TIMER;
    }

    return next_challenge_time;
}

/* Prepare the next packet to send when in one the server initial states */
int picoquic_prepare_packet_server_init(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t * next_wake_time)
{
    int ret = 0;
    int tls_ready = 0;
    picoquic_epoch_enum epoch = picoquic_epoch_initial;
    picoquic_packet_type_enum packet_type = picoquic_packet_initial;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;
    size_t checksum_overhead = 8;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max;
    uint8_t* bytes_next;
    size_t length = 0;
    int more_data = 0;
    int is_pure_ack = 1;

    if (*next_wake_time > cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX) {
        *next_wake_time = cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }

    /* The only purpose of the test below is to appease the static analyzer, so it
     * wont complain of possible NULL deref. On windows we could use "__assume(path_x != NULL)"
     * but the documentation does not say anything about that for GCC and CLANG */
    if (path_x == NULL) {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    if (cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt != NULL &&
        cnx->tls_stream[0].send_queue == NULL) {
        epoch = picoquic_epoch_handshake;
        pc = picoquic_packet_context_handshake;
        packet_type = picoquic_packet_handshake;
    }

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    if (!cnx->initial_validated &&
        (cnx->initial_data_sent + send_buffer_max) > 3 * cnx->initial_data_received){
        /* Sending more data now would break the amplication limit */
        *send_length = 0;
        return 0;
    }

    /* If context is handshake, verify first that there is no need for retransmit or ack
     * on initial context */
    if (pc == picoquic_packet_context_handshake) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_max, current_time, next_wake_time, &header_length);
    }

    if (length == 0) {
        checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
        bytes_max = bytes + send_buffer_max - checksum_overhead;
        tls_ready = (cnx->tls_stream[epoch].send_queue != NULL &&
            cnx->tls_stream[epoch].send_queue->length > cnx->tls_stream[epoch].send_queue->offset);
        length = picoquic_predict_packet_header_length(cnx, packet_type);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
        packet->pc = pc;
        bytes_next = bytes + length;

        if ((tls_ready != 0 && path_x->cwin > path_x->bytes_in_transit) 
            || cnx->pkt_ctx[pc].ack_needed) {
            bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data, current_time, pc);
            /* Encode the crypto frame */
            bytes_next = picoquic_format_crypto_hs_frame(&cnx->tls_stream[epoch],
                bytes_next, bytes_max, &more_data, &is_pure_ack);
            length = bytes_next - bytes;

            /* progress the state if the epoch data is all sent */
            if (ret == 0 && tls_ready != 0 && cnx->tls_stream[epoch].send_queue == NULL) {
                if (epoch == picoquic_epoch_handshake && picoquic_tls_client_authentication_activated(cnx->quic) == 0) {
                    cnx->cnx_state = picoquic_state_server_false_start;
                    /* On a server that does address validation, send a NEW TOKEN frame */
                    if (!cnx->client_mode && (cnx->quic->check_token || cnx->quic->provide_token)) {
                        uint8_t token_buffer[256];
                        size_t token_size;
                        picoquic_connection_id_t n_cid = picoquic_null_connection_id;

                        if (picoquic_prepare_retry_token(cnx->quic, (struct sockaddr *)&cnx->path[0]->peer_addr,
                            current_time + PICOQUIC_TOKEN_DELAY_LONG, &n_cid, &n_cid, 0,
                            token_buffer, sizeof(token_buffer), &token_size) == 0) {
                            if (picoquic_queue_new_token_frame(cnx, token_buffer, token_size) != 0) {
                                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, picoquic_frame_type_new_token);
                            }
                        }
                    }
                    if (cnx->callback_fn != NULL) {
                        if (cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_almost_ready, cnx->callback_ctx, NULL) != 0) {
                            picoquic_log_app_message(cnx, "Callback almost ready returns error 0x%x", PICOQUIC_TRANSPORT_INTERNAL_ERROR);
                            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
                        }
                    }
                }
                else {
                    cnx->cnx_state = picoquic_state_server_handshake;
                }
            }
            packet->length = length;
        }
        else  if ((length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, send_buffer_max, &header_length)) > 0) {
            /* Set the new checksum length */
            checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
            cnx->initial_repeat_needed = 0;
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            bytes_max = bytes + send_buffer_max - checksum_overhead;
            bytes_next = picoquic_format_ack_frame(cnx, bytes + length, bytes_max, &more_data, current_time, pc);
            length = bytes_next - bytes;
            packet->length = length;
            /* document the send time & overhead */
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
        }
        else if (cnx->pkt_ctx[pc].ack_needed) {
            /* when in a handshake mode, send acks asap. */
            length = picoquic_predict_packet_header_length(cnx, packet_type);
            bytes_next = bytes + length;
            bytes_max = bytes + send_buffer_max - checksum_overhead;
            bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data, current_time, pc);
            length = bytes_next - bytes;
        } else {
            length = 0;
            packet->length = 0;
        }
    }

    if (ret == 0 && length == 0 && more_data) {
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_max,
        &path_x->remote_cnxid, &path_x->p_local_cnxid->cnx_id, path_x, current_time);

    /* Account for data sent during handshake */
    if (!cnx->initial_validated) {
        cnx->initial_data_sent += *send_length;
    }

    return ret;
}

/* Prepare the next packet to send when in one the closing states */
int picoquic_prepare_packet_closing(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t * next_wake_time)
{
    int ret = 0;
    /* TODO: manage multiple streams. */
    picoquic_packet_type_enum packet_type = 0;
    size_t checksum_overhead = 8;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max;
    uint8_t* bytes_next;
    int more_data = 0;
    size_t length = 0;
    int is_pure_ack = 1;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    picoquic_epoch_enum epoch = picoquic_epoch_1rtt;

    /* The only purpose of the test below is to appease the static analyzer, so it
     * wont complain of possible NULL deref. On windows we could use "__assume(path_x != NULL)"
     * but the documentation does not say anything about that for GCC and CLANG */
    if (path_x == NULL) {
        return PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    /* Prepare header -- depend on connection state */
    /* TODO: 0-RTT work. */
    switch (cnx->cnx_state) {
    case picoquic_state_handshake_failure:
        /* TODO: check whether closing can be requested in "initial" mode */
        if (cnx->crypto_context[picoquic_epoch_handshake].aead_encrypt != NULL &&
            cnx->pkt_ctx[picoquic_packet_context_handshake].first_sack_item.start_of_sack_range != (uint64_t)((int64_t)-1)) {
            pc = picoquic_packet_context_handshake;
            packet_type = picoquic_packet_handshake;
            epoch = picoquic_epoch_handshake;
        }
        else {
            pc = picoquic_packet_context_initial;
            packet_type = picoquic_packet_initial;
        }
        break;
    case picoquic_state_handshake_failure_resend:
        pc = picoquic_packet_context_handshake;
        packet_type = picoquic_packet_handshake;
        epoch = picoquic_epoch_handshake;
        break;
    case picoquic_state_disconnecting:
        packet_type = picoquic_packet_1rtt_protected;
        break;
    case picoquic_state_closing_received:
        packet_type = picoquic_packet_1rtt_protected;
        break;
    case picoquic_state_closing:
        packet_type = picoquic_packet_1rtt_protected;
        break;
    case picoquic_state_draining:
        packet_type = picoquic_packet_1rtt_protected;
        break;
    case picoquic_state_disconnected:
        ret = PICOQUIC_ERROR_DISCONNECTED;
        break;
    default:
        ret = -1;
        break;
    }

    /* At this stage, we don't try to retransmit any old packet, whether in
     * the current context or in previous contexts. */

    checksum_overhead = picoquic_get_checksum_length(cnx, epoch);
    packet->pc = pc;
    bytes_max = bytes + send_buffer_max - checksum_overhead;

    if (ret == 0 && cnx->cnx_state == picoquic_state_closing_received) {
        /* Send a closing frame, move to closing state */
        uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

        length = picoquic_predict_packet_header_length(cnx, packet_type);
        bytes_next = bytes + length;
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;

        /* Send the disconnect frame */
        bytes_next = picoquic_format_connection_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
        length = bytes_next - bytes;

        cnx->cnx_state = picoquic_state_draining;
        *next_wake_time = exit_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    } else if (ret == 0 && cnx->cnx_state == picoquic_state_closing) {
        /* if more than 3*RTO is elapsed, move to disconnected */
        uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

        if (current_time >= exit_time) {
            cnx->cnx_state = picoquic_state_disconnected;
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        else if (current_time >= cnx->next_wake_time) {
            uint64_t delta_t = path_x->rtt_min;
            uint64_t next_time = 0;

            if (delta_t * 2 < path_x->retransmit_timer) {
                delta_t = path_x->retransmit_timer / 2;
            }
            /* if more than N packet received, repeat and erase */
            if (cnx->pkt_ctx[pc].ack_needed) {
                length = picoquic_predict_packet_header_length(
                    cnx, packet_type);
                packet->ptype = packet_type;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                packet->send_time = current_time;
                packet->send_path = path_x;
                bytes_next = bytes + length;

                /* Resend the disconnect frame */
                if (cnx->local_error == 0) {
                    bytes_next = picoquic_format_application_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                } else {
                    bytes_next = picoquic_format_connection_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                }
                length = bytes_next - bytes;
                cnx->pkt_ctx[pc].ack_needed = 0;
            }
            next_time = current_time + delta_t;
            if (next_time > exit_time) {
                next_time = exit_time;
            }

            *next_wake_time = next_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
    } else if (ret == 0 && cnx->cnx_state == picoquic_state_draining) {
        /* Nothing is ever sent in the draining state */
        /* if more than 3*RTO is elapsed, move to disconnected */
        uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

        if (current_time >= exit_time) {
            cnx->cnx_state = picoquic_state_disconnected;
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        else {
            *next_wake_time = exit_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        length = 0;
    } else if (ret == 0 && (cnx->cnx_state == picoquic_state_disconnecting || 
        cnx->cnx_state == picoquic_state_handshake_failure || 
        cnx->cnx_state == picoquic_state_handshake_failure_resend)) {
        length = picoquic_predict_packet_header_length(
            cnx, packet_type);
        bytes_next = bytes + length;
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;

        /* send either app close or connection close, depending on error code */
        uint64_t delta_t = path_x->rtt_min;

        if (2 * delta_t < path_x->retransmit_timer) {
            delta_t = path_x->retransmit_timer / 2;
        }

        /* add a final ack so receiver gets clean state */
        bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data, current_time, pc);

        /* Send the disconnect frame */
        if (cnx->local_error == 0) {
            bytes_next = picoquic_format_application_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
        }
        else {
            bytes_next = picoquic_format_connection_close_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
        }
        length = bytes_next - bytes;

        if (cnx->cnx_state == picoquic_state_handshake_failure) {
            if (pc == picoquic_packet_context_initial &&
                cnx->crypto_context[2].aead_encrypt != NULL) {
                cnx->cnx_state = picoquic_state_handshake_failure_resend;
            }
            else {
                cnx->cnx_state = picoquic_state_disconnected;
            }
        }
        else if (cnx->cnx_state == picoquic_state_handshake_failure_resend) {
            cnx->cnx_state = picoquic_state_disconnected;
        }
        else {
            cnx->cnx_state = picoquic_state_closing;
        }
        cnx->latest_progress_time = current_time;
        *next_wake_time = current_time + delta_t;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        cnx->pkt_ctx[pc].ack_needed = 0;

        if (cnx->callback_fn) {
            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
        }
    }
    else {
        length = 0;
    }

    if (length > 0 && packet->ptype == picoquic_packet_initial && cnx->client_mode) {
        length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_max,
        &path_x->remote_cnxid, &path_x->p_local_cnxid->cnx_id, path_x, current_time);

    return ret;
}

/* Create required ID, register, and format the corresponding connection ID frame */
uint8_t * picoquic_format_new_local_id_as_needed(picoquic_cnx_t* cnx, uint8_t* bytes, uint8_t * bytes_max, int * more_data, int * is_pure_ack)
{
    while ((cnx->remote_parameters.migration_disabled == 0 || cnx->remote_parameters.prefered_address.is_defined) &&
        cnx->local_parameters.migration_disabled == 0 &&
        cnx->nb_local_cnxid < (int)(cnx->remote_parameters.active_connection_id_limit) &&
        cnx->nb_local_cnxid <= PICOQUIC_NB_PATH_TARGET) {
        uint8_t* bytes0 = bytes;
        picoquic_local_cnxid_t* l_cid = picoquic_create_local_cnxid(cnx, NULL);

        if (l_cid == NULL) {
            /* OOPS, memory error */
            break;
        } else {
            bytes = picoquic_format_new_connection_id_frame(cnx, bytes, bytes_max, more_data, is_pure_ack, l_cid);

            if (bytes == bytes0) {
                /* Oops. Try again next time. */
                picoquic_delete_local_cnxid(cnx, l_cid);
                cnx->local_cnxid_sequence_next--;
                break;
            }
        }
    }

    return bytes;
}


void picoquic_ready_state_transition(picoquic_cnx_t* cnx, uint64_t current_time)
{
    /* Transition to server ready state.
     * The handshake is complete, all the handshake packets are implicitly acknowledged */
    cnx->cnx_state = picoquic_state_ready;
    cnx->is_handshake_finished = 1;
    picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_initial, current_time);
    picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_handshake, current_time);

    (void)picoquic_register_net_secret(cnx);

    if (!cnx->client_mode) {
        (void)picoquic_queue_handshake_done_frame(cnx);
    }

    /* Remove handshake and initial keys if they are still around */
    picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_initial]);
    picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_0rtt]);
    picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_handshake]);

    /* Start migration to server preferred address if present */
    if (cnx->client_mode) {
        (void)picoquic_prepare_server_address_migration(cnx);
    }

    /* Notify the application */
    if (cnx->callback_fn != NULL) {
        if (cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_ready, cnx->callback_ctx, NULL) != 0) {
            picoquic_log_app_message(cnx, "Callback ready returns error 0x%x", PICOQUIC_TRANSPORT_INTERNAL_ERROR);
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
        }
    }

    /* Ask for ACK frequency update, or initialize variables if not available */
    if (cnx->is_ack_frequency_negotiated) {
        cnx->is_ack_frequency_updated = 1;
    }
    else {
        cnx->ack_gap_remote = picoquic_compute_ack_gap(cnx, cnx->path[0]->receive_rate_max);
        cnx->ack_delay_remote = picoquic_compute_ack_delay_max(cnx->path[0]->rtt_min, PICOQUIC_ACK_DELAY_MIN);
    }

    /* Perform a check of the PN decryption key, for sanity */
    picoquic_log_pn_dec_trial(cnx);
}

/* Prepare the next packet to send when in one the ready states 
 * Lots of the same code as in the "ready" case, but we deal here with extra
 * complexity because the handshake is not finished.
 */
int picoquic_prepare_packet_almost_ready(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t* next_wake_time,
    int* is_initial_sent)
{
    int ret = 0;
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    int tls_ready = 0;
    int is_pure_ack = 1;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    size_t length = 0;
    size_t checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
    size_t send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;
    uint8_t* bytes_max = bytes + send_buffer_min_max - checksum_overhead;
    uint8_t* bytes_next = NULL;
    int more_data = 0;
    int stream_tried_and_failed = 0;

    /* Perform amplification prevention check */
    if (!cnx->initial_validated &&
        (cnx->initial_data_sent + send_buffer_min_max) > 3 * cnx->initial_data_received) {
        *send_length = 0;
        return 0;
    }

    /* Verify first that there is no need for retransmit or ack
     * on initial or handshake context. */
    if (cnx->crypto_context[picoquic_epoch_initial].aead_encrypt != NULL) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_min_max, current_time, next_wake_time, &header_length);
    }
    else {
        length = 0;
    }

    if (length == 0) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_handshake,
            path_x, packet, send_buffer_min_max, current_time, next_wake_time, &header_length);
        if (length > 0) {
            checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_handshake);
            bytes_max = bytes + send_buffer_min_max - checksum_overhead;
        }
    }
    else {
        checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_initial);
        bytes_max = bytes + send_buffer_min_max - checksum_overhead;

        *is_initial_sent = 1;
    }

    if (length > 0) {
        cnx->initial_repeat_needed = 0;

        if (cnx->client_mode && *is_initial_sent && send_buffer_min_max < length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE) {
            length = picoquic_pad_to_target_length(packet->bytes, length, send_buffer_min_max - checksum_overhead);
        }
    }

    if (length == 0) {
        tls_ready = picoquic_is_tls_stream_ready(cnx);
        packet->pc = pc;
        length = picoquic_predict_packet_header_length(
            cnx, packet_type);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
        bytes_next = bytes + length;

        if (path_x->challenge_verified == 0 && path_x->challenge_failed == 0) {
            uint64_t next_challenge_time = picoquic_next_challenge_time(cnx, path_x);
            if (next_challenge_time <= current_time || path_x->challenge_repeat_count == 0) {
                if (path_x->challenge_repeat_count < PICOQUIC_CHALLENGE_REPEAT_MAX) {
                    int ack_needed = cnx->pkt_ctx[pc].ack_needed;
                    uint8_t* bytes_challenge = bytes_next;

                    bytes_next = picoquic_format_path_challenge_frame(bytes_next, bytes_max, &more_data, &is_pure_ack,
                        path_x->challenge[path_x->challenge_repeat_count]);
                    if (bytes_next > bytes_challenge) {
                        path_x->challenge_time = current_time;
                        path_x->challenge_repeat_count++;
                    }

                    /* add an ACK just to be nice */
                    if (ack_needed) {
                        bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data, current_time, pc);
                        /* Restore the ACK needed flags, because challenges are not reliable. */
                        cnx->pkt_ctx[pc].ack_needed = ack_needed;
                    }
                }
                else {
                    if (path_x == cnx->path[0]) {
                        /* TODO: consider alt address. Also, consider other available path. */
                        DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                        picoquic_log_app_message(cnx, "%s", "Too many challenge retransmits, disconnect");
                        cnx->cnx_state = picoquic_state_disconnected;
                        if (cnx->callback_fn) {
                            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
                        }
                    }
                    else {
                        DBG_PRINTF("%s\n", "Too many challenge retransmits, abandon path");
                        picoquic_log_app_message(cnx, "%s", "Too many challenge retransmits, abandon path");
                        path_x->challenge_failed = 1;
                        cnx->path_demotion_needed = 1;
                    }
                }
            }
            else {
                if (next_challenge_time < *next_wake_time) {
                    *next_wake_time = next_challenge_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
        }

        if (path_x->response_required) {
            uint8_t* bytes_response = bytes_next;
            if ((bytes_next = picoquic_format_path_response_frame(bytes_response, bytes_max,
                &more_data, &is_pure_ack, path_x->challenge_response)) > bytes_response) {
                path_x->response_required = 0;
            }
        }

        length = bytes_next - bytes;

        if (cnx->cnx_state != picoquic_state_disconnected && path_x->challenge_verified != 0) {
            /* There are no frames yet that would be exempt from pacing control, but if there
             * was they should be sent here. */

            if (picoquic_is_sending_authorized_by_pacing(cnx, path_x, current_time, next_wake_time)) {
                /* Send here the frames that are not exempt from the pacing control,
                 * but are exempt for congestion control */
                if (picoquic_is_ack_needed(cnx, current_time, next_wake_time, pc)) {
                    bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data,
                        current_time, pc);
                }

                length = bytes_next - bytes;
                if (path_x->cwin < path_x->bytes_in_transit) {
                    cnx->cwin_blocked = 1;
                    if (cnx->congestion_alg != NULL) {
                        cnx->congestion_alg->alg_notify(cnx, path_x,
                            picoquic_congestion_notification_cwin_blocked,
                            0, 0, 0, 0, current_time);
                    }
                }
                else {
                    /* Send here the frames that are subject to both congestion and pacing control.
                     * this includes the PMTU probes.
                     * Check whether PMTU discovery is required. The call will return
                     * three values: not needed at all, optional, or required.
                     * If required, PMTU discovery takes priority over sending stream data.
                     */
                    picoquic_pmtu_discovery_status_enum pmtu_discovery_needed = picoquic_is_mtu_probe_needed(cnx, path_x);

                    /* if present, send tls data */
                    if (tls_ready) {
                        bytes_next = picoquic_format_crypto_hs_frame(&cnx->tls_stream[picoquic_epoch_1rtt],
                            bytes_next, bytes_max, &more_data, &is_pure_ack);
                    }

                    length = bytes_next - bytes;

                    if (length > header_length || pmtu_discovery_needed != picoquic_pmtu_discovery_required) {
                        /* If present, send misc frame */
                        while (cnx->first_misc_frame != NULL) {
                            uint8_t* bytes_misc = bytes_next;
                            bytes_next = picoquic_format_first_misc_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                            if (bytes_next == bytes_misc) {
                                break;
                            }
                        }

                        /* If there are not enough published CID, create and advertise */
                        if (ret == 0) {
                            bytes_next = picoquic_format_new_local_id_as_needed(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                        }

                        /* Start of CC controlled frames */
                        if (ret == 0 && length <= header_length && cnx->first_datagram != NULL) {
                            bytes_next = picoquic_format_first_datagram_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                        }

                        /* If present, send stream frames queued for retransmission */
                        if (ret == 0) {
                            bytes_next = picoquic_format_stream_frames_queued_for_retransmit(cnx, bytes_next, bytes_max,
                                &more_data, &is_pure_ack);
                        }

                        if (cnx->is_ack_frequency_updated && cnx->is_ack_frequency_negotiated) {
                            bytes_next = picoquic_format_ack_frequency_frame(cnx, bytes_next, bytes_max, &more_data);
                        }

                        bytes_next = picoquic_format_available_stream_frames(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack, &stream_tried_and_failed, &ret);

                        length = bytes_next - bytes;

                        if (length <= header_length) {
                            /* Mark the bandwidth estimation as application limited */
                            path_x->delivered_limited_index = path_x->delivered;
                            /* Notify the peer if something is blocked */
                            bytes_next = picoquic_format_blocked_frames(cnx, &bytes[length], bytes_max, &more_data, &is_pure_ack);
                            length = bytes_next - bytes;
                        }

                        if (stream_tried_and_failed) {
                            path_x->last_sender_limited_time = current_time;
                        }
                    } /* end of PMTU not required */

                    if (ret == 0 && length <= header_length && send_buffer_max > path_x->send_mtu
                        && path_x->cwin > path_x->bytes_in_transit&& pmtu_discovery_needed != picoquic_pmtu_discovery_not_needed) {
                        /* Since there is no data to send, this is an opportunity to send an MTU probe */
                        length = picoquic_prepare_mtu_probe(cnx, path_x, header_length, checksum_overhead, bytes);
                        packet->length = length;
                        packet->send_path = path_x;
                        packet->is_mtu_probe = 1;
                        path_x->mtu_probe_sent = 1;
                        is_pure_ack = 0;
                    }
                } /* end of PMTU references */
            } /* end of CC */
        } /* End of pacing */
        if (length <= header_length) {
            length = 0;
        }

        if (cnx->cnx_state != picoquic_state_disconnected) {
            /* If necessary, encode and send the keep alive packet!
             * We only send keep alive packets when no other data is sent!
             */
            if (is_pure_ack == 0)
            {
                cnx->latest_progress_time = current_time;
            }
            else if (cnx->keep_alive_interval != 0) {
                if (cnx->latest_progress_time + cnx->keep_alive_interval <= current_time && length == 0) {
                    length = picoquic_predict_packet_header_length(
                        cnx, packet_type);
                    packet->ptype = packet_type;
                    packet->pc = pc;
                    packet->offset = length;
                    header_length = length;
                    packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                    packet->send_path = path_x;
                    packet->send_time = current_time;
                    bytes[length++] = picoquic_frame_type_ping;
                    bytes[length++] = 0;
                    cnx->latest_progress_time = current_time;
                }
                else if (cnx->latest_progress_time + cnx->keep_alive_interval < *next_wake_time) {
                    *next_wake_time = cnx->latest_progress_time + cnx->keep_alive_interval;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
        }
    }

    if (ret == 0 && length > header_length) {
        if (more_data) {
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            ret = 0;
        }

        /* Ensure that all packets are properly padded before being sent. */

        if (*is_initial_sent && cnx->client_mode) {
            length = picoquic_pad_to_target_length(bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
        else {
            length = picoquic_pad_to_policy(cnx, bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_min_max,
        &path_x->remote_cnxid, &path_x->p_local_cnxid->cnx_id, path_x, current_time);

    if (*send_length > 0) {
        /* Account for data sent during handshake */
        if (!cnx->initial_validated) {
            cnx->initial_data_sent += *send_length;
        }
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);

        if (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE ||
            cnx->quic->use_long_log) {
            picoquic_cc_dump(cnx, current_time);
        }
    }

    return ret;
}

/*  Prepare the next packet to send when in the ready state */
int picoquic_prepare_packet_ready(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t* next_wake_time,
    int* is_initial_sent)
{
    int ret = 0;
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    int is_pure_ack = 1;
    size_t header_length = 0;
    size_t length = 0;
    size_t checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
    size_t send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;
    int split_repeat_queued = 0;
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max = bytes + send_buffer_min_max - checksum_overhead;
    uint8_t* bytes_next;
    int more_data = 0;
    int ack_sent = 0;

    packet->pc = pc;

    /* If there was no packet sent on this path for a long time, rotate the
     * CID prior to sending a new packet. The point is to make it harder for
     * casual observers to track traffic, especially across NAT resets */
    if (cnx->client_mode &&
        path_x->challenge_verified &&
        !path_x->path_cid_rotated &&
        path_x->latest_sent_time + PICOQUIC_CID_REFRESH_DELAY < current_time)
    {
        /* Ignore renewal failure mode, since this is an optional feature */
        (void)picoquic_renew_path_connection_id(cnx, path_x);
        path_x->path_cid_rotated = 1;
    }

    /* If the number of packets sent is larger that the max length of
     * a crypto epoch, prepare a key rotation */
    if (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence >
        cnx->crypto_epoch_sequence + cnx->crypto_epoch_length_max &&
        cnx->crypto_epoch_sequence <
        cnx->pkt_ctx[picoquic_packet_context_application].first_sack_item.end_of_sack_range) {
        if (picoquic_start_key_rotation(cnx) != 0) {
            picoquic_log_app_message(cnx, "Cannot start key rotation after %"PRIu64" packets",
                cnx->pkt_ctx[picoquic_packet_context_application].send_sequence);
        }
    }

    /* The first action is normally to retransmit lost packets. But if retransmit follows an
     * MTU drop, the stream frame will be fragmented and a fragment will be queued as a
     * misc frame. These fragments should have chance to go out before more retransmit is
     * permitted, hence the test here for the misc-frame */
    if (cnx->first_misc_frame == NULL &&
        (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, 
        send_buffer_min_max, &header_length)) > 0) {
        /* Check whether it makes sense to add an ACK at the end of the retransmission */
        /* Don't do that if it risks mixing clear text and encrypted ack */
        bytes_next = picoquic_format_ack_frame(cnx, bytes + length, bytes_max, &more_data,
            current_time, pc);
        length = bytes_next - bytes;
        /* document the send time & overhead */
        is_pure_ack = 0;
        packet->send_time = current_time;
        packet->checksum_overhead = checksum_overhead;
    }
    else if (ret == 0) {
        length = picoquic_predict_packet_header_length(
            cnx, packet_type);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
        bytes_next = bytes + length;

        /* If required, prepare challenge and response frames.
         * These frames will be sent immediately, regardless of pacing or flow control.
         */

        if (path_x->challenge_verified == 0 && path_x->challenge_failed == 0) {
            uint64_t next_challenge_time = picoquic_next_challenge_time(cnx, path_x);
            if (next_challenge_time <= current_time || path_x->challenge_repeat_count == 0) {
                if (path_x->challenge_repeat_count < PICOQUIC_CHALLENGE_REPEAT_MAX) {
                    int ack_needed = cnx->pkt_ctx[pc].ack_needed;
                    /* When blocked, repeat the path challenge or wait */
                    uint8_t* bytes_challenge = bytes_next;

                    bytes_next = picoquic_format_path_challenge_frame(bytes_next, bytes_max, &more_data, &is_pure_ack,
                        path_x->challenge[path_x->challenge_repeat_count]);
                    if (bytes_next > bytes_challenge) {
                        path_x->challenge_time = current_time;
                        path_x->challenge_repeat_count++;
                    }

                    /* add an ACK just to be nice */
                    if (ack_needed) {
                        bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data,
                            current_time, pc);
                        /* Restore the ACK needed flags, because challenges are not reliable. */
                        cnx->pkt_ctx[pc].ack_needed = ack_needed;
                    }
                }
                else {
                    if (path_x == cnx->path[0]) {
                        /* Try to find an alternate path */
                        for (int i = 1; i < cnx->nb_paths; i++) {
                            if (cnx->path[i]->challenge_failed == 0) {
                                cnx->path[0] = cnx->path[i];
                                cnx->path[i] = path_x;
                            }
                        }
                    }

                    if (path_x == cnx->path[0]) {
                        DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                        picoquic_log_app_message(cnx, "%s", "Too many challenge retransmits, disconnect");
                        cnx->cnx_state = picoquic_state_disconnected;
                        if (cnx->callback_fn) {
                            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
                        }
                    }
                    else {
                        DBG_PRINTF("%s\n", "Too many challenge retransmits, abandon path");
                        picoquic_log_app_message(cnx, "%s", "Too many challenge retransmits, abandon path");
                        path_x->challenge_failed = 1;
                    }
                }
            }
            else {
                if (next_challenge_time < *next_wake_time) {
                    *next_wake_time = next_challenge_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
        }

        if (path_x->response_required) {
            uint8_t* bytes_response = bytes_next;
            if ((bytes_next = picoquic_format_path_response_frame(bytes_response, bytes_max,
                &more_data, &is_pure_ack, path_x->challenge_response)) > bytes_response) {
                path_x->response_required = 0;
            }
        }

        /* Compute the length before pacing block */
        length = bytes_next - bytes;

        if (cnx->cnx_state != picoquic_state_disconnected && path_x->challenge_verified != 0) {
            /* There are no frames yet that would be exempt from pacing control, but if there
             * was they should be sent here. */

            if (picoquic_is_sending_authorized_by_pacing(cnx, path_x, current_time, next_wake_time)) {
                /* Send here the frames that are not exempt from the pacing control,
                 * but are exempt for congestion control */
                if (picoquic_is_ack_needed(cnx, current_time, next_wake_time, pc)) {
                    uint8_t* bytes_ack = bytes_next;
                    bytes_next = picoquic_format_ack_frame(cnx, bytes_next, bytes_max, &more_data,
                        current_time, pc);
                    ack_sent = (bytes_next > bytes_ack);
                }

                /* if necessary, prepare the MAX STREAM frames */
                if (ret == 0) {
                    bytes_next = picoquic_format_max_streams_frame_if_needed(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                }

                /* If necessary, encode the max data frame */
                if (ret == 0){
                    if (cnx->is_flow_control_limited) {
                        if (cnx->data_received + (cnx->local_parameters.initial_max_data / 2) > cnx->maxdata_local) {
                            bytes_next = picoquic_format_max_data_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack,
                                cnx->local_parameters.initial_max_data);
                        }
                    }
                    else if (2 * cnx->data_received > cnx->maxdata_local) {
                        bytes_next = picoquic_format_max_data_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack,
                            picoquic_cc_increased_window(cnx, cnx->maxdata_local));
                    }
                }

                /* If necessary, encode the max stream data frames */
                if (ret == 0 && cnx->max_stream_data_needed) {
                    bytes_next = picoquic_format_required_max_stream_data_frames(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                }

                /* If present, send misc frame */
                while (cnx->first_misc_frame != NULL) {
                    uint8_t* bytes_misc = bytes_next;
                    bytes_next = picoquic_format_first_misc_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                    if (bytes_next > bytes_misc) {
                        split_repeat_queued |=
                            PICOQUIC_IN_RANGE(*bytes_misc, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max);
                    }
                    else {
                        break;
                    }
                }

                /* Compute the length before entering the CC block */
                length = bytes_next - bytes;

                if (path_x->cwin < path_x->bytes_in_transit) {
                    cnx->cwin_blocked = 1;
                    if (cnx->congestion_alg != NULL) {
                        cnx->congestion_alg->alg_notify(cnx, path_x,
                            picoquic_congestion_notification_cwin_blocked,
                            0, 0, 0, 0, current_time);
                    }
                }
                else {
                    /* Send here the frames that are subject to both congestion and pacing control.
                     * this includes the PMTU probes.
                     * Check whether PMTU discovery is required. The call will return
                     * three values: not needed at all, optional, or required.
                     * If required, PMTU discovery takes priority over sending stream data.
                     */
                    int datagram_tried_and_failed = 0;
                    int stream_tried_and_failed = 0;
                    picoquic_pmtu_discovery_status_enum pmtu_discovery_needed = picoquic_is_mtu_probe_needed(cnx, path_x);

                    /* if present, send tls data */
                    if (picoquic_is_tls_stream_ready(cnx)) {
                        bytes_next = picoquic_format_crypto_hs_frame(&cnx->tls_stream[picoquic_epoch_1rtt],
                            bytes_next, bytes_max, &more_data, &is_pure_ack);
                    }

                    if (length > header_length || pmtu_discovery_needed != picoquic_pmtu_discovery_required) {
                        /* If there are not enough local CID published, create and advertise */
                        if (ret == 0) {
                            bytes_next = picoquic_format_new_local_id_as_needed(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                        }

                        /* Start of CC controlled frames */

                        if (ret == 0 && length <= header_length) {
                            if (cnx->first_datagram != NULL) {
                                bytes_next = picoquic_format_first_datagram_frame(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack);
                            }
                            else {
                                datagram_tried_and_failed = 1;
                            }
                        }

                        /* If present, send stream frames queued for retransmission */
                        if (ret == 0) {
                            bytes_next = picoquic_format_stream_frames_queued_for_retransmit(cnx, bytes_next, bytes_max,
                                &more_data, &is_pure_ack);
                        }

                        if (ret == 0 && cnx->is_ack_frequency_updated && cnx->is_ack_frequency_negotiated) {
                            bytes_next = picoquic_format_ack_frequency_frame(cnx, bytes_next, bytes_max, &more_data);
                        }

                        /* Encode the stream frame, or frames */
                        if (ret == 0 && !split_repeat_queued && bytes_next + 8 < bytes_max) {
                            bytes_next = picoquic_format_available_stream_frames(cnx, bytes_next, bytes_max, &more_data, &is_pure_ack, &stream_tried_and_failed, &ret);
                        }

                        length = bytes_next - bytes;

                        if (length <= header_length || is_pure_ack) {
                            /* Mark the bandwidth estimation as application limited */
                            path_x->delivered_limited_index = path_x->delivered;
                            /* Notify the peer if something is blocked */
                            bytes_next = picoquic_format_blocked_frames(cnx, &bytes[length], bytes_max, &more_data, &is_pure_ack);
                            length = bytes_next - bytes;
                        }

                        if (stream_tried_and_failed && datagram_tried_and_failed) {
                            path_x->last_sender_limited_time = current_time;
                        }
                    } /* end of PMTU not required */

                    if (ret == 0 && length <= header_length && send_buffer_max > path_x->send_mtu
                        && path_x->cwin > path_x->bytes_in_transit&& pmtu_discovery_needed != picoquic_pmtu_discovery_not_needed) {
                        /* Since there is no data to send, this is an opportunity to send an MTU probe */
                        length = picoquic_prepare_mtu_probe(cnx, path_x, header_length, checksum_overhead, bytes);
                        packet->length = length;
                        packet->send_path = path_x;
                        packet->is_mtu_probe = 1;
                        path_x->mtu_probe_sent = 1;
                        is_pure_ack = 0;
                    }
                } /* end of CC */
            } /* End of pacing */
        } /* End of challenge verified */
    }

    if (length <= header_length) {
        length = 0;
    }

    if (cnx->cnx_state != picoquic_state_disconnected) {
        if (length > 0){
            cnx->pkt_ctx[pc].ack_of_ack_requested |= !is_pure_ack;
            if (!cnx->pkt_ctx[pc].ack_of_ack_requested && ack_sent) {
                /* If we have sent many ACKs, add a PING to get an ack of ack */
                /* The number 24 is chosen to not break any of the unit tests. If the number is
                 * too small, the PING mechanism can cause delayed end of the connection, or 
                 * early breakage */
                bytes_next = bytes + length;
                if (bytes_next < bytes_max &&
                    cnx->pkt_ctx[pc].highest_acknowledged + 24 < cnx->pkt_ctx[pc].send_sequence &&
                    path_x == cnx->path[0] &&
                    cnx->pkt_ctx[pc].highest_acknowledged_time + cnx->path[0]->smoothed_rtt < current_time) {
                    /* Bundle a Ping with ACK, so as to get trigger an Acknowledgement */
                    *bytes_next++ = picoquic_frame_type_ping;
                    cnx->pkt_ctx[pc].ack_of_ack_requested = 1;
                    is_pure_ack = 0;
                    length = bytes_next - bytes;
                }
            }
        }

        if (is_pure_ack == 0)
        {
            cnx->latest_progress_time = current_time;
        }
        else if (cnx->keep_alive_interval != 0) {
            /* If necessary, encode and send the keep alive packet.
             * We only send keep alive packets when no other data is sent.
             */
            if (cnx->latest_progress_time + cnx->keep_alive_interval <= current_time && length == 0) {
                length = picoquic_predict_packet_header_length(
                    cnx, packet_type);
                packet->ptype = packet_type;
                packet->pc = pc;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                packet->send_path = path_x;
                packet->send_time = current_time;
                bytes[length++] = picoquic_frame_type_ping;
                bytes[length++] = 0;
                cnx->latest_progress_time = current_time;
            }
            else if (cnx->latest_progress_time + cnx->keep_alive_interval < *next_wake_time) {
                *next_wake_time = cnx->latest_progress_time + cnx->keep_alive_interval;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        }

        if (more_data) {
            *next_wake_time = current_time;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            ret = 0;
        }
    }

    if (ret == 0 && length > header_length) {
        /* Ensure that all packets are properly padded before being sent. */

        if (*is_initial_sent && cnx->client_mode) {
            length = picoquic_pad_to_target_length(bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
        else {
            length = picoquic_pad_to_policy(cnx, bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_min_max,
        &path_x->remote_cnxid, &path_x->p_local_cnxid->cnx_id, path_x, current_time);

    if (*send_length > 0) {
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);

        if (ret == 0 && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE ||
            cnx->quic->use_long_log)) {
            picoquic_cc_dump(cnx, current_time);
        }
    }

    return ret;
}


static int picoquic_check_idle_timer(picoquic_cnx_t* cnx, uint64_t* next_wake_time, uint64_t current_time)
{
    int ret = 0;
    uint64_t idle_timer = 0;

    if (cnx->cnx_state >= picoquic_state_ready) {
        uint64_t rto = picoquic_current_retransmit_timer(cnx, picoquic_packet_context_application);
        idle_timer = cnx->idle_timeout;
        if (idle_timer < 3 * rto) {
            idle_timer = 3 * rto;
        }
        idle_timer += cnx->latest_progress_time;

        if (idle_timer < cnx->idle_timeout) {
            idle_timer = UINT64_MAX;
        }
    }
    else {
        idle_timer = cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
    }

    if (current_time >= idle_timer) {
        /* Too long silence, break it. */
        cnx->cnx_state = picoquic_state_disconnected;
        ret = PICOQUIC_ERROR_DISCONNECTED;
        if (cnx->callback_fn) {
            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
        }
    } else if (idle_timer < *next_wake_time) {
        *next_wake_time = idle_timer;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }

    return ret;
}

/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_segment(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    uint64_t* next_wake_time, int* is_initial_sent)
{
    int ret = 0;

    /* Prepare header -- depend on connection state */
    /* TODO: 0-RTT work. */
    switch (cnx->cnx_state) {
    case picoquic_state_client_init:
    case picoquic_state_client_init_sent:
    case picoquic_state_client_init_resent:
    case picoquic_state_client_renegotiate:
    case picoquic_state_client_handshake_start:
    case picoquic_state_client_almost_ready:
        ret = picoquic_prepare_packet_client_init(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
        break;
    case picoquic_state_server_almost_ready:
    case picoquic_state_server_init:
    case picoquic_state_server_handshake:
        ret = picoquic_prepare_packet_server_init(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time);
        break;
    case picoquic_state_server_false_start:
        /*
         * Manage the end of false start transition, and if needed start
         * preparing packet in ready state.
         */
        if (cnx->cnx_state == picoquic_state_server_false_start &&
            cnx->crypto_context[3].aead_decrypt != NULL) {
            picoquic_ready_state_transition(cnx, current_time);
            return picoquic_prepare_packet_ready(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
        }
        /* Else, just fall through to almost ready behavior.
         */
    case picoquic_state_client_ready_start:
        ret = picoquic_prepare_packet_almost_ready(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
        break;
    case picoquic_state_ready:
        ret = picoquic_prepare_packet_ready(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
        break;
    case picoquic_state_handshake_failure:
    case picoquic_state_handshake_failure_resend:
    case picoquic_state_disconnecting:
    case picoquic_state_closing_received:
    case picoquic_state_closing:
    case picoquic_state_draining:
        ret = picoquic_prepare_packet_closing(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time);
        break;
    case picoquic_state_disconnected:
        ret = PICOQUIC_ERROR_DISCONNECTED;
        break;
    case picoquic_state_client_retry_received:
        DBG_PRINTF("Unexpected connection state: %d\n", cnx->cnx_state);
        ret = PICOQUIC_ERROR_UNEXPECTED_STATE;
        break;
    default:
        DBG_PRINTF("Unexpected connection state: %d\n", cnx->cnx_state);
        ret = PICOQUIC_ERROR_UNEXPECTED_STATE;
        break;
    }

    return ret;
}

/*
 * The version 1 of Quic only supports path migration, not full multipath.
 * This code finds whether there is a path being probed that could become the
 * default path, or that needs an immediate challenge sent or replied to.
 *
 * If no other path is suitable, the code returns the default path.
 */

static int picoquic_select_next_path(picoquic_cnx_t * cnx, uint64_t current_time, uint64_t * next_wake_time)
{
    int path_id = -1;
    /* Select the path */
    for (int i = 1; i < cnx->nb_paths; i++) {
        if (cnx->path[i]->path_is_demoted) {
            continue;
        }
        else if (cnx->path[i]->challenge_failed) {
            picoquic_demote_path(cnx, i, current_time);
            continue;
        }
        else if (cnx->path[i]->challenge_verified) {
            /* TODO: selection logic if multiple paths are available! */
            /* This path becomes the new default */
            picoquic_promote_path_to_default(cnx, i, current_time);
            path_id = 0;
            break;
        }
        else if (path_id < 0) {
            if (cnx->path[i]->response_required) {
                path_id = i;
            }
            else if (cnx->path[i]->challenge_required) {
                uint64_t next_challenge_time = picoquic_next_challenge_time(cnx, cnx->path[i]);
                if (cnx->path[i]->challenge_repeat_count == 0 ||
                    current_time >= next_challenge_time) {
                    /* will try this path, unless a validated path came in */
                    path_id = i;
                }
                else if (next_challenge_time < *next_wake_time) {
                    *next_wake_time = next_challenge_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
        }
    }

    if (path_id < 0) {
        path_id = 0;
    }

    return path_id;
}

/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_packet(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage * p_addr_to, struct sockaddr_storage * p_addr_from)
{

    int ret;
    picoquic_packet_t * packet = NULL;
    struct sockaddr_storage addr_to_log;
    struct sockaddr_storage addr_from_log;
    int is_initial_sent = 0;
    uint64_t next_wake_time = cnx->latest_progress_time + 2*PICOQUIC_MICROSEC_SILENCE_MAX;

    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);

    if (cnx->recycle_sooner_needed) {
        picoquic_process_sooner_packets(cnx, current_time);
    }

    memset(&addr_to_log, 0, sizeof(addr_to_log));
    memset(&addr_from_log, 0, sizeof(addr_from_log));
    *send_length = 0;

    ret = picoquic_check_idle_timer(cnx, &next_wake_time, current_time);

    if (ret == 0) {
        int path_id;

        /* Remove delete paths */
        if (cnx->path_demotion_needed) {
            picoquic_delete_abandoned_paths(cnx, current_time, &next_wake_time);
        }

        /* Check whether to insert a hole in the sequence of packets */
        if (cnx->pkt_ctx[0].send_sequence >= cnx->pkt_ctx[0].next_sequence_hole) {
            picoquic_insert_hole_in_send_sequence_if_needed(cnx, current_time, &next_wake_time);
        }

        /* Select the next path, and the corresponding addresses */
        path_id = picoquic_select_next_path(cnx, current_time, &next_wake_time);


        picoquic_store_addr(&addr_to_log, (struct sockaddr *)&cnx->path[path_id]->peer_addr);
        if (cnx->path[path_id]->local_addr.ss_family != 0) {
            picoquic_store_addr(&addr_from_log, (struct sockaddr*) & cnx->path[path_id]->local_addr);
        }

        if (p_addr_to != NULL) {
            picoquic_store_addr(p_addr_to, (struct sockaddr *)&cnx->path[path_id]->peer_addr);
        }

        if (p_addr_from != NULL) {
            picoquic_store_addr(p_addr_from, (struct sockaddr *)&cnx->path[path_id]->local_addr);
        }
       
        /* Send the available segments */
        while (ret == 0)
        {
            size_t available = send_buffer_max;
            size_t segment_length = 0;

            if (*send_length > 0) {
                send_buffer_max = cnx->path[path_id]->send_mtu;

                if (send_buffer_max < *send_length + PICOQUIC_MIN_SEGMENT_SIZE) {
                    break;
                }
                else {
                    available = send_buffer_max - *send_length;
                }
            }

            packet = picoquic_create_packet(cnx->quic);

            if (packet == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
                break;
            }
            else {
                ret = picoquic_prepare_segment(cnx, cnx->path[path_id], packet, current_time,
                    send_buffer + *send_length, available, &segment_length, &next_wake_time, &is_initial_sent);

                if (ret == 0) {
                    *send_length += segment_length;
                    if (packet->length == 0 ||
                        packet->ptype == picoquic_packet_1rtt_protected) {
                        if (packet->length == 0) {
                            picoquic_recycle_packet(cnx->quic, packet);
                            packet = NULL;
                        }
                        break;
                    }
                    else if (segment_length == 0) {
                        DBG_PRINTF("Send bug: segment length = %zu, packet length = %zu\n", segment_length, packet->length);
                        break;
                    }
                }
                else {
                    picoquic_recycle_packet(cnx->quic, packet);
                    packet = NULL;

                    if (*send_length != 0) {
                        ret = 0;
                    }
                    break;
                }

                if (cnx->quic->dont_coalesce_init) {
                    break;
                }
            }
        }
    }

    if (*send_length > 0 && is_initial_sent && *send_length < 1200 && cnx->client_mode) {
        DBG_PRINTF("%s", "BUG");
    }

    /* if needed, log that the packet is sent */
    if (*send_length > 0 && cnx->quic->F_log != NULL && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || cnx->quic->use_long_log)) {
        picoquic_log_packet_address(cnx->quic->F_log,
            picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)),
            cnx, (struct sockaddr *)&addr_to_log, 0, *send_length, current_time);
    }
    if (*send_length > 0 && cnx->f_binlog != NULL && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || cnx->quic->use_long_log)) {
        binlog_pdu(cnx->f_binlog, &cnx->initial_cnxid, 0, current_time,
            (struct sockaddr *)&addr_to_log, (struct sockaddr*)& addr_from_log, *send_length);
    }

    /* Update the wake up time for the connection */
    if (*send_length > 0 || cnx->cnx_state == picoquic_state_disconnected ) {
        next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }
    
    picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_wake_time);

    return ret;
}

int picoquic_close(picoquic_cnx_t* cnx, uint16_t reason_code)
{
    int ret = 0;

    if (cnx->cnx_state == picoquic_state_ready ||
        cnx->cnx_state == picoquic_state_server_false_start || cnx->cnx_state == picoquic_state_client_ready_start) {
        cnx->cnx_state = picoquic_state_disconnecting;
        cnx->application_error = reason_code;
    } else if (cnx->cnx_state < picoquic_state_client_ready_start) {
        cnx->cnx_state = picoquic_state_handshake_failure;
        cnx->application_error = 0;
        cnx->local_error = PICOQUIC_TRANSPORT_APPLICATION_ERROR;
    } else {
        ret = -1;
    }
    cnx->offending_frame_type = 0;

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

/* Quic context level call.
 * will send a stateless packet if one is queued, or ask the first connection in
 * the wake list to prepare a packet */

int picoquic_prepare_next_packet(picoquic_quic_t* quic,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int * if_index,
    picoquic_connection_id_t * log_cid, picoquic_cnx_t** p_last_cnx)
{
    int ret = 0;
    picoquic_stateless_packet_t* sp = picoquic_dequeue_stateless_packet(quic);

    if (p_last_cnx) {
        *p_last_cnx = NULL;
    }

    if (sp != NULL) {
        if (sp->length > send_buffer_max) {
            *send_length = 0;
        }
        else {
            memcpy(send_buffer, sp->bytes, sp->length);
            *send_length = sp->length;
            picoquic_store_addr(p_addr_to, (struct sockaddr*) & sp->addr_to);
            picoquic_store_addr(p_addr_from, (struct sockaddr*) & sp->addr_local);
            *if_index = sp->if_index_local;
            if (log_cid != NULL) {
                *log_cid = sp->initial_cid;
            }
        }
        picoquic_delete_stateless_packet(sp);
    }
    else {
        picoquic_cnx_t* cnx = picoquic_get_earliest_cnx_to_wake(quic, current_time);

        if (cnx == NULL) {
            *send_length = 0;
        }
        else {
            ret = picoquic_prepare_packet(cnx, current_time, send_buffer, send_buffer_max, send_length, p_addr_to, p_addr_from);
            if (log_cid != NULL) {
                *log_cid = cnx->initial_cnxid;
            }

            if (ret == PICOQUIC_ERROR_DISCONNECTED) {
                ret = 0;

                picoquic_log_app_message(cnx, "Closed. Retrans= %d, spurious= %d, max sp gap = %d, max sp delay = %d",
                    (int)cnx->nb_retransmission_total, (int)cnx->nb_spurious,
                    (int)cnx->path[0]->max_reorder_gap, (int)cnx->path[0]->max_spurious_rtt);

                if (quic->F_log != NULL) {
                    fflush(quic->F_log);
                }

                if (cnx->f_binlog != NULL) {
                    fflush(cnx->f_binlog);
                }

                picoquic_delete_cnx(cnx);
            }
            else {
                if (*if_index == -1) {
                    *if_index = picoquic_get_local_if_index(cnx);
                }
                if (p_last_cnx) {
                    *p_last_cnx = cnx;
                }
            }
        }
    }

    return ret;
}