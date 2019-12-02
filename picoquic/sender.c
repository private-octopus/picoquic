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
        picoquic_stream_data_t* stream_data = (picoquic_stream_data_t*)malloc(sizeof(picoquic_stream_data_t));

        if (stream_data == 0) {
            ret = -1;
        } else {
            stream_data->bytes = (uint8_t*)malloc(length);

            if (stream_data->bytes == NULL) {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            } else {
                picoquic_stream_data_t** pprevious = &stream->send_queue;
                picoquic_stream_data_t* next = stream->send_queue;

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

            if (!stream->is_output_stream) {
                stream->is_output_stream = 1;
                stream->next_output_stream = cnx->first_output_stream;
                cnx->first_output_stream = stream;
            }
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
        const uint8_t C = 0x43; /* default packet length to 4 bytes; set the QUIC bit */
        length = 0;
        bytes[length++] = (K | C | picoquic_spin_function_table[cnx->spin_policy].spinbit_outgoing(cnx));
        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, dest_cnx_id);

        *pn_offset = length;
        *pn_length = 4;
        picoformat_32(&bytes[length], (uint32_t)sequence_number);
        length += 4;
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
        /* Compute length of a short packet header */
        header_length = 1 + cnx->path[0]->remote_cnxid.id_len + 4;
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
        header_length += cnx->path[0]->local_cnxid.id_len;

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
size_t picoquic_get_checksum_length(picoquic_cnx_t* cnx, int is_cleartext_mode)
{
    size_t ret = 16;

    if (is_cleartext_mode || cnx->crypto_context[2].aead_encrypt == NULL) {
        ret = picoquic_aead_get_checksum_length(cnx->crypto_context[0].aead_encrypt);
    } else {
        ret = picoquic_aead_get_checksum_length(cnx->crypto_context[2].aead_encrypt);
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
        sequence_number, remote_cnxid, local_cnxid, send_buffer, &pn_offset, &pn_length);
    if (ptype == picoquic_packet_1rtt_protected) {
        if (remote_cnxid != &path_x->remote_cnxid) {
            /* Packet is sent to a different CID: reset the spin bit and loss bit Q to 0 */
            send_buffer[0] &= 0xDF;
            path_x->q_square = 0;
        }

        if (cnx->is_loss_bit_enabled) {
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
            send_buffer, send_length);
    }
    if (cnx->quic->f_binlog != NULL && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || cnx->quic->use_long_log)) {
        binlog_outgoing_packet(cnx->quic->f_binlog, cnx,
            bytes, sequence_number, length,
            send_buffer, send_length, current_time);
    }

    /* Next, encrypt the PN -- The sample is located after the pn_offset */
    sample_offset = /* header_length */ pn_offset + 4;

    if (pn_offset < sample_offset)
    {
        /* This is always true, as use pn_length = 4 */
        uint8_t mask_bytes[5] = { 0, 0, 0, 0, 0 };

        picoquic_pn_encrypt(pn_enc, send_buffer + sample_offset, mask_bytes, mask_bytes, 5);
        /* Decode the first byte */
        send_buffer[0] ^= (mask_bytes[0] & first_mask);

        /* Packet encoding is 1 to 4 bytes */
        for (uint8_t i = 0; i < 4; i++) {
            send_buffer[pn_offset+i] ^= mask_bytes[i+1];
        }
    }

    return send_length;
}

/* Update the leaky bucket used for pacing.
 */
static void picoquic_update_pacing_bucket(picoquic_path_t * path_x, uint64_t current_time)
{
    if (current_time > path_x->pacing_evaluation_time) {
        path_x->pacing_bucket_nanosec += (current_time - path_x->pacing_evaluation_time) << 10;
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
int picoquic_is_sending_authorized_by_pacing(picoquic_path_t * path_x, uint64_t current_time, uint64_t * next_time)
{
    int ret = 1;

    picoquic_update_pacing_bucket(path_x, current_time);

    if (path_x->pacing_bucket_nanosec <= 0) {
        uint64_t next_pacing_time = current_time + path_x->pacing_packet_time_microsec;
        if (next_pacing_time < *next_time) {
            *next_time = next_pacing_time;
        }
        ret = 0;
    }

    return ret;
}

/*
 * Reset the pacing data after CWIN is updated.
 * The max bucket is set to contain at least 2 packets more than 1/8th of the congestion window.
 */

void picoquic_update_pacing_data(picoquic_path_t * path_x)
{
    uint64_t rtt_nanosec = (path_x->smoothed_rtt << 10);

    if (path_x->cwin < ((uint64_t)path_x->send_mtu)*8) {
        /* Small windows, should only relie on ACK clocking */
        path_x->pacing_bucket_max = rtt_nanosec;
        path_x->pacing_packet_time_nanosec = 1;
        path_x->pacing_packet_time_microsec = 1;

    }
    else {

        path_x->pacing_packet_time_nanosec = (rtt_nanosec * ((uint64_t)path_x->send_mtu)) / path_x->cwin;

        if (path_x->pacing_packet_time_nanosec <= 0) {
            path_x->pacing_packet_time_nanosec = 1;
            path_x->pacing_packet_time_microsec = 1;
        }
        else {
            path_x->pacing_packet_time_microsec = (path_x->pacing_packet_time_nanosec + 1023ull) >> 10;
        }

        path_x->pacing_bucket_max = (rtt_nanosec / 4);
        if (path_x->pacing_bucket_max < 2ull * path_x->pacing_packet_time_nanosec) {
            path_x->pacing_bucket_max = 2ull * path_x->pacing_packet_time_nanosec;
        } else if (path_x->pacing_bucket_max < 10ull * path_x->pacing_packet_time_nanosec) {
            path_x->pacing_bucket_max = 10ull * path_x->pacing_packet_time_nanosec;
        }
    }
}

/* 
 * Update the pacing data after sending a packet.
 */
void picoquic_update_pacing_after_send(picoquic_path_t * path_x, uint64_t current_time)
{
    picoquic_update_pacing_bucket(path_x, current_time);

    if (path_x->pacing_bucket_nanosec < path_x->pacing_packet_time_nanosec) {
        path_x->pacing_bucket_nanosec = 0;
    } else {
        path_x->pacing_bucket_nanosec -= path_x->pacing_packet_time_nanosec;
    }
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
            cnx->pkt_ctx[pc].retransmitted_oldest->next_packet = p;
            p->previous_packet = cnx->pkt_ctx[pc].retransmitted_oldest;
            cnx->pkt_ctx[pc].retransmitted_oldest = p;
        }
    }

    return p;
}

void picoquic_dequeue_retransmitted_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p)
{
    picoquic_packet_context_enum pc = p->pc;

    if (p->previous_packet == NULL) {
        cnx->pkt_ctx[pc].retransmitted_newest = p->next_packet;
    }
    else {
        p->previous_packet->next_packet = p->next_packet;
    }

    if (p->next_packet == NULL) {
        cnx->pkt_ctx[pc].retransmitted_oldest = p->previous_packet;
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

        switch (packet->ptype) {
        case picoquic_packet_version_negotiation:
            /* Packet is not encrypted */
            break;
        case picoquic_packet_initial:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[0].aead_encrypt, cnx->crypto_context[0].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_handshake:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[2].aead_encrypt, cnx->crypto_context[2].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_retry:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[0].aead_encrypt, cnx->crypto_context[0].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_0rtt_protected:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number, 
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[1].aead_encrypt, cnx->crypto_context[1].pn_enc,
                path_x, current_time);
            break;
        case picoquic_packet_1rtt_protected:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[3].aead_encrypt, cnx->crypto_context[3].pn_enc,
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

static int picoquic_retransmit_needed_by_packet(picoquic_cnx_t* cnx,
    picoquic_packet_t* p, uint64_t current_time, uint64_t * next_retransmit_time, int* timer_based)
{
    picoquic_packet_context_enum pc = p->pc;
    uint64_t retransmit_time;
    int64_t delta_seq = cnx->pkt_ctx[pc].highest_acknowledged - p->sequence_number;
    int should_retransmit = 0;
    int is_timer_based = 0;

    if (delta_seq > 0) {
        /* By default, we use timer based RACK logic to absorb out of order deliveries */
        retransmit_time = p->send_time + cnx->path[0]->retransmit_timer; /* cnx->path[0]->smoothed_rtt + (cnx->path[0]->smoothed_rtt >> 3); */
        /* RACK logic works best when the amount of reordering is not too large */
        if (delta_seq < 3) {
            uint64_t rack_timer_min = cnx->pkt_ctx[pc].highest_acknowledged_time +
                cnx->remote_parameters.max_ack_delay + (cnx->path[0]->smoothed_rtt >> 2);
            if (retransmit_time > rack_timer_min) {
                retransmit_time = rack_timer_min;
            }
        }
    }
    else
    {
        /* There has not been any higher packet acknowledged, thus we fall back on timer logic. */
        uint64_t rto = (cnx->pkt_ctx[pc].nb_retransmit == 0) ?
            cnx->path[0]->retransmit_timer : (1000000ull << (cnx->pkt_ctx[pc].nb_retransmit - 1));
        retransmit_time = p->send_time + rto;
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

    if (retransmit_time < *next_retransmit_time) {
        *next_retransmit_time = retransmit_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
    }

    return should_retransmit;
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
                    uint8_t overflow[PICOQUIC_MAX_PACKET_SIZE];
                    size_t copied_length = 0;
                    size_t overflow_length = 0;

                    /* By default, copy to new frame, but if that does not fit also create overflow frame */
                    ret = picoquic_split_stream_frame(&old_p->bytes[byte_index], frame_length,
                        &new_bytes[*length], send_buffer_max_minus_checksum - *length, &copied_length,
                        overflow, sizeof(overflow), &overflow_length);

                    if (ret == 0) {
                        *length += copied_length;
                        if (overflow_length > 0) {
                            ret = picoquic_queue_misc_frame(cnx, overflow, overflow_length);
                        }
                    }
                }
                else {
                    if (frame_length > send_buffer_max_minus_checksum - *length &&
                        (old_p->ptype == picoquic_packet_0rtt_protected || old_p->ptype == picoquic_packet_1rtt_protected)) {
                        ret = picoquic_queue_misc_frame(cnx, &old_p->bytes[byte_index], frame_length);
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
    picoquic_path_t * path_x, uint64_t current_time, uint64_t * next_retransmit_time,
    picoquic_packet_t* packet, size_t send_buffer_max, int* is_cleartext_mode, size_t* header_length)
{
    picoquic_packet_t* old_p = cnx->pkt_ctx[pc].retransmit_oldest;
    size_t length = 0;

    /* TODO: while packets are pure ACK, drop them from retransmit queue */
    while (old_p != NULL) {
        picoquic_path_t * old_path = old_p->send_path; /* should be the path on which the packet was transmitted */
        int should_retransmit = 0;
        int timer_based_retransmit = 0;
        uint64_t lost_packet_number = old_p->sequence_number;
        picoquic_packet_t* p_next = old_p->previous_packet;
        uint8_t * new_bytes = packet->bytes;
        int ret = 0;

        length = 0;

        /* Get the packet type */

        should_retransmit = picoquic_retransmit_needed_by_packet(cnx, old_p, current_time, next_retransmit_time, &timer_based_retransmit);

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

                if (old_p->ptype == picoquic_packet_1rtt_protected || old_p->ptype == picoquic_packet_0rtt_protected) {
                    *is_cleartext_mode = 0;
                } else {
                    *is_cleartext_mode = 1;
                }

                checksum_length = picoquic_get_checksum_length(cnx, *is_cleartext_mode);

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
                old_p = picoquic_dequeue_retransmit_packet(cnx, old_p, packet_is_pure_ack & do_not_detect_spurious);

                /* If we have a good packet, return it */
                if (old_p == NULL || packet_is_pure_ack) {
                    length = 0;
                } else {
                    if (timer_based_retransmit != 0) {
                        if (cnx->pkt_ctx[pc].nb_retransmit > 4) {
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
                            cnx->pkt_ctx[pc].nb_retransmit++;
                            cnx->pkt_ctx[pc].latest_retransmit_time = current_time;
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

                        if (cnx->congestion_alg != NULL) {
                            cnx->congestion_alg->alg_notify(cnx, old_path,
                                (timer_based_retransmit == 0) ? picoquic_congestion_notification_repeat : picoquic_congestion_notification_timeout,
                                0, 0, lost_packet_number, current_time);
                        }
                    }

                    break;
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
    int padding_required)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;
    picoquic_packet_type_enum packet_type = picoquic_packet_0rtt_protected;
    size_t data_bytes = 0;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    size_t length = 0;
    size_t checksum_overhead = picoquic_aead_get_checksum_length(cnx->crypto_context[1].aead_encrypt);

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

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

    if ((stream == NULL && cnx->first_misc_frame == NULL && padding_required == 0) || 
        (PICOQUIC_DEFAULT_0RTT_WINDOW <= path_x->bytes_in_transit + send_buffer_max)) {
        length = 0;
    } else {
        /* If present, send misc frame */
        while (cnx->first_misc_frame != NULL) {
            ret = picoquic_prepare_first_misc_frame(cnx, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);

            if (ret == 0) {
                length += data_bytes;
            } else {
                break;
            }
        }

        /* Encode the stream frame, or frames */
        while (stream != NULL) {
            int is_still_active = 0;
            ret = picoquic_prepare_stream_frame(cnx, stream, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes, &is_still_active);

            if (ret == 0) {
                length += data_bytes;

                if (send_buffer_max > checksum_overhead + length + 8) {
                    stream = picoquic_find_ready_stream(cnx);
                }
                else {
                    break;
                }
            }
            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                ret = 0;
                break;
            }
        }

        /* Add padding if required */
        if (padding_required) {
            length = picoquic_pad_to_target_length(bytes, length, send_buffer_max - checksum_overhead);
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_max,
        &cnx->initial_cnxid,
        &path_x->local_cnxid,
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

/* Prepare a required repetition or ack  in a previous context */
size_t picoquic_prepare_packet_old_context(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc,
    picoquic_path_t * path_x, picoquic_packet_t* packet, size_t send_buffer_max, uint64_t current_time, 
    uint64_t * next_retransmit_time, size_t * header_length)
{
    int is_cleartext_mode = (pc == picoquic_packet_context_initial) ? 1 : 0;
    size_t length = 0;
    size_t data_bytes = 0;
    size_t checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);

    *header_length = 0;

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    if (cnx->initial_validated || cnx->initial_repeat_needed) {
        length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_retransmit_time, packet, send_buffer_max,
            &is_cleartext_mode, header_length);
        if (length > 0) {
            cnx->initial_repeat_needed = 0;
        }
    }

    if (length == 0 && cnx->pkt_ctx[pc].ack_needed != 0 && cnx->initial_validated &&
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
            if (picoquic_prepare_ack_frame(cnx, current_time, pc, &packet->bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += data_bytes;
            }
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

        /* Update the congestion control state for the path */
        if (old_path != NULL) {
            if (old_path->smoothed_rtt == PICOQUIC_INITIAL_RTT && old_path->rtt_variant == 0) {
                uint64_t rtt_estimate = current_time - p->send_time;

                picoquic_update_path_rtt(cnx, old_path, rtt_estimate, &cnx->pkt_ctx[pc], current_time, 0);
            }

            if (cnx->congestion_alg != NULL) {
                cnx->congestion_alg->alg_notify(cnx, old_path,
                    picoquic_congestion_notification_acknowledgement,
                    0, p->length, 0, current_time);
            }
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
                ret = picoquic_create_probe(cnx, (struct sockaddr *)&dest_addr, NULL);
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
    size_t checksum_overhead = 8;
    int is_cleartext_mode = 1;
    size_t data_bytes = 0;
    int retransmit_possible = 0;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    size_t length = 0;
    int epoch = 0;
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
    case picoquic_state_client_handshake_progress:
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
    if (ret == 0 && epoch > 0) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_max, current_time, next_wake_time, &header_length);
        *is_initial_sent |= (length > 0);
    }

    if (ret == 0 && epoch > 1 && length == 0) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_application,
            path_x, packet, send_buffer_max, current_time, next_wake_time, &header_length);
    }

    /* If there is nothing to send in previous context, check this one too */
    if (length == 0) {
        checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
        packet->checksum_overhead = checksum_overhead;
        packet->pc = pc;

        tls_ready = picoquic_is_tls_stream_ready(cnx);

        if (ret == 0 && retransmit_possible &&
            (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, send_buffer_max, &is_cleartext_mode, &header_length)) > 0) {
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            if (epoch != 1) {
                ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes);
                if (ret == 0) {
                    length += data_bytes;
                }
                else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                    ret = 0;
                    *next_wake_time = current_time;
                }
            } 
            /* document the send time & overhead */
            packet->length = length;
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
        }
        else if (ret == 0 && is_cleartext_mode && tls_ready == 0
            && cnx->first_misc_frame == NULL && cnx->pkt_ctx[pc].ack_needed == 0) {
            /* when in a clear text mode, only send packets if there is
            * actually something to send, or resend */

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

                if ((tls_ready == 0 || path_x->cwin <= path_x->bytes_in_transit)
                    && (cnx->cnx_state == picoquic_state_client_almost_ready
                        || picoquic_is_ack_needed(cnx, current_time, next_wake_time, pc) == 0)
                    && cnx->first_misc_frame == NULL) {
                    length = 0;
                }
                else {
                    if (epoch != 1 && cnx->pkt_ctx[pc].ack_needed) {
                        ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes);
                        if (ret == 0) {
                            length += data_bytes;
                            data_bytes = 0;
                        }
                        else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            ret = 0;
                            *next_wake_time = current_time;
                            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                        }
                    }

                    /* encode path challenge response if required */
                    if (path_x->response_required) {
                        ret = picoquic_prepare_path_response_frame(&bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes, path_x->challenge_response);
                        if (ret == 0) {
                            length += data_bytes;
                            path_x->response_required = 0;
                        }
                        else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            ret = 0;
                            *next_wake_time = current_time;
                            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                        }
                    }

                    /* If present, send misc frame */
                    while (cnx->first_misc_frame != NULL) {
                        ret = picoquic_prepare_first_misc_frame(cnx, &bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes);
                        if (ret == 0) {
                            length += data_bytes;
                            data_bytes = 0;
                        }
                        else {
                            if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                                *next_wake_time = current_time;
                                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                            }
                            break;
                        }
                    }

                    if (ret == 0 && path_x->cwin > path_x->bytes_in_transit) {
                        /* Encode the crypto handshake frame */
                        if (tls_ready != 0) {
                            ret = picoquic_prepare_crypto_hs_frame(cnx, epoch,
                                &bytes[length],
                                send_buffer_max - checksum_overhead - length, &data_bytes);

                            if (ret == 0) {
                                length += data_bytes;
                            }
                            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                                *next_wake_time = current_time;
                                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                            }
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

                    /* If stream zero packets are sent, progress the state */
                    if (ret == 0 && tls_ready != 0 && data_bytes > 0 && 
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
                                if (ret == 0) {
                                    /* Signal the application */
                                    if (cnx->callback_fn != NULL) {
                                        if (cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_almost_ready, cnx->callback_ctx, NULL) != 0) {
                                            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
                                        }
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

    if (ret == 0 && length == 0 && cnx->crypto_context[1].aead_encrypt != NULL) {
        /* Consider sending 0-RTT */
        ret = picoquic_prepare_packet_0rtt(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length,
            *is_initial_sent);
    }
    else {
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

        if (length > 0 && packet->ptype == picoquic_packet_handshake) {
            picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_initial, current_time);
        }

        picoquic_finalize_and_protect_packet(cnx, packet,
            ret, length, header_length, checksum_overhead,
            send_length, send_buffer, send_buffer_max,
            &path_x->remote_cnxid, &path_x->local_cnxid, path_x, current_time);
    }

    return ret;
}

/* Prepare the next packet to send when in one the server initial states */
int picoquic_prepare_packet_server_init(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t * next_wake_time)
{
    int ret = 0;
    int tls_ready = 0;
    int epoch = 0;
    picoquic_packet_type_enum packet_type = picoquic_packet_initial;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;
    size_t checksum_overhead = 8;
    int is_cleartext_mode = 1;
    size_t data_bytes = 0;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    size_t length = 0;

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

    if (cnx->crypto_context[2].aead_encrypt != NULL &&
        cnx->tls_stream[0].send_queue == NULL) {
        epoch = 2;
        pc = picoquic_packet_context_handshake;
        packet_type = picoquic_packet_handshake;
    }

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    /* If context is handshake, verify first that there is no need for retransmit or ack
    * on initial context */
    if ((cnx->initial_validated||cnx->initial_repeat_needed) && pc == picoquic_packet_context_handshake) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_max, current_time, next_wake_time, &header_length);
    }

    if (length == 0) {
        checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);

        tls_ready = picoquic_is_tls_stream_ready(cnx);

        length = picoquic_predict_packet_header_length(cnx, packet_type);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;
        packet->pc = pc;

        if (tls_ready != 0 && path_x->cwin <= path_x->bytes_in_transit && path_x->challenge_time == 0) {
            /* Should send a path challenge and get a reply before sending more data */
            path_x->challenge_verified = 0;
        }

        if (path_x->challenge_verified == 0 && path_x->challenge_failed == 0) {
            if (path_x->challenge_time + path_x->retransmit_timer <= current_time || path_x->challenge_time == 0) {
                if (path_x->challenge_repeat_count < PICOQUIC_CHALLENGE_REPEAT_MAX) {
                    /* When blocked, repeat the path challenge or wait */
                    if (picoquic_prepare_path_challenge_frame(&bytes[length],
                        send_buffer_max - checksum_overhead - length, &data_bytes,
                        path_x->challenge[path_x->challenge_repeat_count]) == 0) {
                        length += data_bytes;
                        path_x->challenge_time = current_time;
                        path_x->challenge_repeat_count++;

                        /* add an ACK just to be nice */
                        if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes)
                            == 0) {
                            length += data_bytes;
                        }

                        packet->length = length;
                    }
                    else if (path_x->challenge_time + path_x->retransmit_timer < *next_wake_time) {
                        *next_wake_time = path_x->challenge_time + path_x->retransmit_timer;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
                else {
                    if (path_x == cnx->path[0]) {
                        DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                        cnx->cnx_state = picoquic_state_disconnected;
                        if (cnx->callback_fn) {
                            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
                        }
                    }
                    else {
                        DBG_PRINTF("%s\n", "Too many challenge retransmits, abandon path");
                        path_x->challenge_failed = 1;
                    }
                    length = 0;
                }
            }
            else if (path_x->challenge_time + path_x->retransmit_timer < *next_wake_time) {
                *next_wake_time = path_x->challenge_time + path_x->retransmit_timer;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        }
        else if ((tls_ready != 0 && path_x->cwin > path_x->bytes_in_transit) 
            || cnx->pkt_ctx[pc].ack_needed) {
            if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += data_bytes;
                data_bytes = 0;
            }

            /* encode path challenge response if required */
            if (path_x->response_required) {
                if (picoquic_prepare_path_response_frame(&bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes, path_x->challenge_response) == 0) {
                    length += data_bytes;
                    path_x->response_required = 0;
                }
            }

            /* Encode the crypto frame */
            ret = picoquic_prepare_crypto_hs_frame(cnx, epoch, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);
            if (ret == 0) {
                length += data_bytes;
            }
            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                /* todo: reset offset to previous position? */
                ret = 0;
                *next_wake_time = current_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }

            /* progress the state if the epoch data is all sent */

            if (ret == 0 && tls_ready != 0 && data_bytes > 0 && cnx->tls_stream[epoch].send_queue == NULL) {
                if (epoch == 2 && picoquic_tls_client_authentication_activated(cnx->quic) == 0) {
                    cnx->cnx_state = picoquic_state_server_false_start;
                    /* On a server that does address validation, send a NEW TOKEN frame */
                    if (cnx->client_mode == 0 && (cnx->quic->flags&picoquic_context_check_token) != 0) {
                        uint8_t token_buffer[256];
                        size_t token_size;
                        picoquic_connection_id_t n_cid = picoquic_null_connection_id;

                        if (picoquic_prepare_retry_token(cnx->quic, (struct sockaddr *)&cnx->path[0]->peer_addr,
                            current_time + PICOQUIC_TOKEN_DELAY_LONG, &n_cid, 
                            token_buffer, sizeof(token_buffer), &token_size) == 0) {
                            if (picoquic_queue_new_token_frame(cnx, token_buffer, token_size) != 0) {
                                picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, picoquic_frame_type_new_token);
                            }
                        }
                    }
                    if (cnx->callback_fn != NULL) {
                        if (cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_almost_ready, cnx->callback_ctx, NULL) != 0) {
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
        else  if ((cnx->initial_validated || cnx->initial_repeat_needed) && 
        (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, send_buffer_max, &is_cleartext_mode, &header_length)) > 0) {
            /* Set the new checksum length */
            checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
            cnx->initial_repeat_needed = 0;
            if (cnx->initial_validated) {
                /* Check whether it makes sens to add an ACK at the end of the retransmission */
                ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes);
                if (ret == 0) {
                    length += data_bytes;
                    packet->length = length;
                }
                else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                    ret = 0;
                    *next_wake_time = current_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
            /* document the send time & overhead */
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
        }
        else if (cnx->initial_validated && cnx->pkt_ctx[pc].ack_needed) {
            /* when in a handshake mode, send acks asap. */
            length = picoquic_predict_packet_header_length(cnx, packet_type);

            ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);
            if (ret == 0) {
                length += data_bytes;
                packet->length = length;
            }
            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                ret = 0;
                *next_wake_time = current_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        } else {
            length = 0;
            packet->length = 0;
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_max,
        &path_x->remote_cnxid, &path_x->local_cnxid, path_x, current_time);

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
    int is_cleartext_mode = 1;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    size_t length = 0;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;

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
        if (cnx->crypto_context[2].aead_encrypt != NULL &&
            cnx->pkt_ctx[picoquic_packet_context_handshake].first_sack_item.start_of_sack_range != (uint64_t)((int64_t)-1)) {
            pc = picoquic_packet_context_handshake;
            packet_type = picoquic_packet_handshake;
        }
        else {
            pc = picoquic_packet_context_initial;
            packet_type = picoquic_packet_initial;
        }
        break;
    case picoquic_state_handshake_failure_resend:
        pc = picoquic_packet_context_handshake;
        packet_type = picoquic_packet_handshake;
        break;
    case picoquic_state_disconnecting:
        packet_type = picoquic_packet_1rtt_protected;
        is_cleartext_mode = 0;
        break;
    case picoquic_state_closing_received:
        packet_type = picoquic_packet_1rtt_protected;
        is_cleartext_mode = 0;
        break;
    case picoquic_state_closing:
        packet_type = picoquic_packet_1rtt_protected;
        is_cleartext_mode = 0;
        break;
    case picoquic_state_draining:
        packet_type = picoquic_packet_1rtt_protected;
        is_cleartext_mode = 0;
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

    checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
    packet->pc = pc;

    if (ret == 0 && cnx->cnx_state == picoquic_state_closing_received) {
        /* Send a closing frame, move to closing state */
        size_t consumed = 0;
        uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

        length = picoquic_predict_packet_header_length(cnx, packet_type);
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;

        /* Send the disconnect frame */
        ret = picoquic_prepare_connection_close_frame(cnx, bytes + length,
            send_buffer_max - checksum_overhead - length, &consumed);

        if (ret == 0) {
            length += consumed;
        }
        cnx->cnx_state = picoquic_state_draining;
        *next_wake_time = exit_time;
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
                size_t consumed = 0;
                length = picoquic_predict_packet_header_length(
                    cnx, packet_type);
                packet->ptype = packet_type;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                packet->send_time = current_time;
                packet->send_path = path_x;

                /* Resend the disconnect frame */
                if (cnx->local_error == 0) {
                    ret = picoquic_prepare_application_close_frame(cnx, bytes + length,
                        send_buffer_max - checksum_overhead - length, &consumed);
                } else {
                    ret = picoquic_prepare_connection_close_frame(cnx, bytes + length,
                        send_buffer_max - checksum_overhead - length, &consumed);
                }
                if (ret == 0) {
                    length += consumed;
                }
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
        packet->ptype = packet_type;
        packet->offset = length;
        header_length = length;
        packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
        packet->send_time = current_time;
        packet->send_path = path_x;

        /* send either app close or connection close, depending on error code */
        size_t consumed = 0;
        uint64_t delta_t = path_x->rtt_min;

        if (2 * delta_t < path_x->retransmit_timer) {
            delta_t = path_x->retransmit_timer / 2;
        }

        /* add a final ack so receiver gets clean state */
        ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
            send_buffer_max - checksum_overhead - length, &consumed);
        if (ret == 0) {
            length += consumed;
        }

        consumed = 0;
        /* Send the disconnect frame */
        if (cnx->local_error == 0) {
            ret = picoquic_prepare_application_close_frame(cnx, bytes + length,
                send_buffer_max - checksum_overhead - length, &consumed);
        }
        else {
            ret = picoquic_prepare_connection_close_frame(cnx, bytes + length,
                send_buffer_max - checksum_overhead - length, &consumed);
        }

        if (ret == 0) {
            length += consumed;
        }

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
        &path_x->remote_cnxid, &path_x->local_cnxid, path_x, current_time);

    return ret;
}

/* Create a new path, register it, and file the corresponding connection ID frame */
int picoquic_prepare_new_path_and_id(picoquic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max, int64_t current_time, size_t* consumed)
{
    int ret = 0;
    int path_index;

    path_index = picoquic_create_path(cnx, current_time, NULL, NULL);

    picoquic_register_path(cnx, cnx->path[path_index]);

    ret = picoquic_prepare_new_connection_id_frame(cnx, cnx->path[path_index], bytes, bytes_max, consumed);

    if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
        /* Oops. Try again next time. */
        picoquic_delete_path(cnx, path_index);
        cnx->path_sequence_next--;
        *consumed = 0;
    }

    return ret;
}

void picoquic_ready_state_transition(picoquic_cnx_t* cnx, uint64_t current_time)
{
    /* Transition to server ready state.
     * The handshake is complete, all the handshake packets are implicitly acknowledged */
    cnx->cnx_state = picoquic_state_ready;
    picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_initial, current_time);
    picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_handshake, current_time);

    /* Start migration to server preferred address if present */
    if (cnx->client_mode) {
        (void)picoquic_prepare_server_address_migration(cnx);
    }

    /* Notify the application */
    if (cnx->callback_fn != NULL) {
        if (cnx->callback_fn(cnx, 0, NULL, 0, picoquic_callback_ready, cnx->callback_ctx, NULL) != 0) {
            picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR, 0);
        }
    }
}


/*  Prepare the next packet to send when in one the ready states */
int picoquic_prepare_packet_ready(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, uint64_t * next_wake_time,
    int * is_initial_sent)
{
    int ret = 0;
    /* TODO: manage multiple streams. */
    picoquic_stream_head_t* stream = NULL;
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    int tls_ready = 0;
    int is_cleartext_mode = 0;
    int is_pure_ack = 1;
    size_t data_bytes = 0;
    size_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    size_t length = 0;
    size_t checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
    size_t send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    /*
     * Manage the end of false start transition.
     */

    if (cnx->cnx_state == picoquic_state_server_false_start &&
        cnx->crypto_context[3].aead_decrypt != NULL) {
        picoquic_ready_state_transition(cnx, current_time);
    }

    if (!cnx->is_handshake_finished && (cnx->initial_validated || cnx->initial_repeat_needed)) {
        /* Verify first that there is no need for retransmit or ack
         * on initial or handshake context. This does not deal with EOED packets,
         * as they are handled from within the general retransmission path.
         * This is needed even with implicit acks for now, because the peer may
         * be retransmitting data and thus requires acks. */

        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_min_max, current_time, next_wake_time, &header_length);

        if (length == 0) {
            length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_handshake,
                path_x, packet, send_buffer_min_max, current_time, next_wake_time, &header_length);
        }
        else {
            *is_initial_sent = 1;
        }

        if (length > 0) {
            cnx->initial_repeat_needed = 0;

            if (cnx->client_mode && *is_initial_sent && send_buffer_min_max < length + checksum_overhead + PICOQUIC_MIN_SEGMENT_SIZE) {
                length = picoquic_pad_to_target_length(packet->bytes, length, send_buffer_min_max - checksum_overhead);
            }
        }
        
        cnx->is_handshake_finished = length == 0 && cnx->cnx_state == picoquic_state_ready &&
            !cnx->pkt_ctx[picoquic_packet_context_initial].ack_needed &&
            cnx->pkt_ctx[picoquic_packet_context_initial].retransmit_oldest == NULL &&
            !cnx->pkt_ctx[picoquic_packet_context_handshake].ack_needed &&
            cnx->pkt_ctx[picoquic_packet_context_handshake].retransmit_oldest == NULL;

    }

    if (length == 0) {
        tls_ready = picoquic_is_tls_stream_ready(cnx);
        stream = picoquic_find_ready_stream(cnx);
        packet->pc = pc;

        if (cnx->initial_validated && (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_wake_time, packet, send_buffer_min_max, &is_cleartext_mode, &header_length)) > 0) {
            /* Set the new checksum length */
            checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
            /* Check whether it makes sense to add an ACK at the end of the retransmission */
            /* Don't do that if it risks mixing clear text and encrypted ack */
            if (is_cleartext_mode == 0 && packet->ptype != picoquic_packet_0rtt_protected) {
                if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                    send_buffer_min_max - checksum_overhead - length, &data_bytes)
                    == 0) {
                    length += data_bytes;
                    packet->length = length;
                }
            }
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

            if (path_x->challenge_verified == 0 && path_x->challenge_failed == 0) {
                if (path_x->challenge_time + path_x->retransmit_timer <= current_time || path_x->challenge_repeat_count == 0) {
                    if (path_x->challenge_repeat_count < PICOQUIC_CHALLENGE_REPEAT_MAX) {
                        int ack_needed = cnx->pkt_ctx[pc].ack_needed;
                        /* When blocked, repeat the path challenge or wait */
                        if (picoquic_prepare_path_challenge_frame(&bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes,
                            path_x->challenge[path_x->challenge_repeat_count]) == 0) {
                            length += data_bytes;
                            path_x->challenge_time = current_time;
                            path_x->challenge_repeat_count++;
                        }

                        /* add an ACK just to be nice */
                        ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes);
                        /* Restore the ACK needed flags, because challenges are not reliable. */
                        cnx->pkt_ctx[pc].ack_needed = ack_needed;

                        if (ret == 0) {
                            length += data_bytes;
                        }
                        else {
                            if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                *next_wake_time = current_time;
                                ret = 0;
                            }
                        }
                    } else {
                        if (path_x == cnx->path[0]) {
                            /* TODO: consider alt address. Also, consider other available path. */
                            DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                            cnx->cnx_state = picoquic_state_disconnected;
                            if (cnx->callback_fn) {
                                (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
                            }
                        }
                        else {
                            DBG_PRINTF("%s\n", "Too many challenge retransmits, abandon path");
                            path_x->challenge_failed = 1;
                        }
                    }
                }
                else {
                    if (path_x->challenge_time + path_x->retransmit_timer < *next_wake_time) {
                        *next_wake_time = path_x->challenge_time + path_x->retransmit_timer;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
            }

            if (path_x->response_required) {
                if (picoquic_prepare_path_response_frame(&bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes, path_x->challenge_response) == 0) {
                    length += data_bytes;
                    path_x->response_required = 0;
                }
            }

            if (cnx->cnx_state != picoquic_state_disconnected && path_x->challenge_verified != 0) {
                if (picoquic_is_ack_needed(cnx, current_time, next_wake_time, pc)) {
                    ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                        send_buffer_min_max - checksum_overhead - length, &data_bytes);
                    if (ret == 0) {
                        length += data_bytes;
                        if (data_bytes > 0 && !cnx->pkt_ctx[pc].ack_of_ack_requested &&
                            length + checksum_overhead < send_buffer_min_max &&
                            cnx->pkt_ctx[pc].highest_acknowledged + 64 < cnx->pkt_ctx[pc].send_sequence &&
                            path_x == cnx->path[0] &&
                            cnx->pkt_ctx[pc].highest_acknowledged_time + 2 * cnx->path[0]->smoothed_rtt < current_time) {
                            /* Bundle a Ping with ACK, so as to get trigger an Acknowledgement */
                            bytes[length++] = picoquic_frame_type_ping;
                            cnx->pkt_ctx[pc].ack_of_ack_requested = 1;
                            is_pure_ack = 0;
                        }
                    }
                    else {
                        if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            *next_wake_time = current_time;
                            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                            ret = 0;
                        }
                    }
                }

                /* if necessary, prepare the MAX STREAM frames */
                if (ret == 0) {
                    ret = picoquic_prepare_max_streams_frame_if_needed(cnx,
                        &bytes[length], send_buffer_min_max - checksum_overhead - length, &data_bytes);
                    if (ret == 0) {
                        length += data_bytes;
                        if (data_bytes > 0)
                        {
                            is_pure_ack = 0;
                        }
                    }
                    else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                        *next_wake_time = current_time;
                        ret = 0;
                    }
                }

                /* If necessary, encode the max data frame */
                if (ret == 0 && 2 * cnx->data_received > cnx->maxdata_local) {
                    ret = picoquic_prepare_max_data_frame(cnx, picoquic_cc_increased_window(cnx, cnx->maxdata_local), &bytes[length],
                        send_buffer_min_max - checksum_overhead - length, &data_bytes);

                    if (ret == 0) {
                        length += data_bytes;
                        if (data_bytes > 0)
                        {
                            is_pure_ack = 0;
                        }
                    }
                    else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                        *next_wake_time = current_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                        ret = 0;
                    }
                }

                /* If necessary, encode the max stream data frames */
                if (ret == 0 && cnx->max_stream_data_needed) {
                    ret = picoquic_prepare_required_max_stream_data_frames(cnx, &bytes[length],
                        send_buffer_min_max - checksum_overhead - length, &data_bytes);

                    if (ret == 0) {
                        length += data_bytes;
                        if (data_bytes > 0)
                        {
                            is_pure_ack = 0;
                        }
                    }
                    else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                        *next_wake_time = current_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                        ret = 0;
                    }
                }


                if (path_x->cwin < path_x->bytes_in_transit) {
                    cnx->cwin_blocked = 1;
                    if (cnx->congestion_alg != NULL) {
                        cnx->congestion_alg->alg_notify(cnx, path_x,
                            picoquic_congestion_notification_cwin_blocked,
                            0, 0, 0, current_time);
                    }
                } else if (picoquic_is_sending_authorized_by_pacing(path_x, current_time, next_wake_time)) {
                    /* Check whether PMTU discovery is required. The call will return
                     * three values: not needed at all, optional, or required.
                     * If required, PMTU discovery takes priority over sending data.
                     */
                    picoquic_pmtu_discovery_status_enum pmtu_discovery_needed = picoquic_is_mtu_probe_needed(cnx, path_x);

                    /* if present, send tls data */
                    if (tls_ready) {
                        ret = picoquic_prepare_crypto_hs_frame(cnx, 3, &bytes[length],
                            send_buffer_min_max - checksum_overhead - length, &data_bytes);

                        if (ret == 0) {
                            length += data_bytes;
                            if (data_bytes > 0)
                            {
                                is_pure_ack = 0;
                            }
                        }
                        else {
                            if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                *next_wake_time = current_time;
                                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                                ret = 0;
                            }
                        }
                    }

                    if (length > header_length || pmtu_discovery_needed != picoquic_pmtu_discovery_required) {
                        /* If present, send misc frame */
                        while (cnx->first_misc_frame != NULL) {
                            ret = picoquic_prepare_first_misc_frame(cnx, &bytes[length],
                                send_buffer_min_max - checksum_overhead - length, &data_bytes);
                            if (ret == 0) {
                                length += data_bytes;
                            }
                            else {
                                if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                    *next_wake_time = current_time;
                                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                                    ret = 0;
                                }
                                break;
                            }
                        }

                        /* If there are not enough paths, create and advertise */
                        while (ret == 0 && cnx->remote_parameters.migration_disabled == 0 &&
                            cnx->local_parameters.migration_disabled == 0 &&
                            cnx->nb_paths < (int)(cnx->remote_parameters.active_connection_id_limit + 1 - cnx->is_path_0_deleted) &&
                            cnx->nb_paths <= PICOQUIC_NB_PATH_TARGET) {
                            ret = picoquic_prepare_new_path_and_id(cnx, &bytes[length],
                                send_buffer_min_max - checksum_overhead - length,
                                current_time, &data_bytes);
                            if (ret == 0) {
                                length += data_bytes;
                            }
                            else {
                                if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                    *next_wake_time = current_time;
                                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                                    ret = 0;
                                }
                                break;
                            }
                        }

                        if (length <= header_length && cnx->first_datagram != NULL) {
                            ret = picoquic_prepare_first_datagram_frame(cnx, &bytes[length],
                                send_buffer_max - checksum_overhead - length, &data_bytes);
                            if (ret == 0) {
                                length += data_bytes;
                            }
                        }

                        /* Encode the stream frame, or frames */
                        while (stream != NULL && length + checksum_overhead < send_buffer_min_max) {
                            int is_still_active = 0;
                            ret = picoquic_prepare_stream_frame(cnx, stream, &bytes[length],
                                send_buffer_min_max - checksum_overhead - length, &data_bytes, &is_still_active);

                            if (ret == 0) {
                                length += data_bytes;
                                if (data_bytes > 0)
                                {
                                    is_pure_ack = 0;
                                }

                                if (send_buffer_max > checksum_overhead + length + 8) {
                                    stream = picoquic_find_ready_stream(cnx);
                                }
                                else {
                                    if (is_still_active) {
                                      *next_wake_time = current_time;
                                      SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                                    }
                                    break;
                                }
                            }
                            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                *next_wake_time = current_time;
                                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                                ret = 0;
                                break;
                            }
                            else {
                                break;
                            }
                        }

                        if (length <= header_length) {
                            ret = picoquic_prepare_blocked_frames(cnx, &bytes[length],
                                send_buffer_min_max - checksum_overhead - length, &data_bytes);
                            if (ret == 0) {
                                length += data_bytes;
                                if (data_bytes > 0)
                                {
                                    is_pure_ack = 0;
                                }
                            }
                        }
                    }

                    if (length > header_length) {
                        if (*is_initial_sent && cnx->client_mode) {
                            length = picoquic_pad_to_target_length(bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
                        }
                        else {
                            length = picoquic_pad_to_policy(cnx, bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
                        }
                    }
                    else if (ret == 0 && send_buffer_max > path_x->send_mtu
                        && path_x->cwin > path_x->bytes_in_transit && pmtu_discovery_needed != picoquic_pmtu_discovery_not_needed) {
                        length = picoquic_prepare_mtu_probe(cnx, path_x, header_length, checksum_overhead, bytes);
                        packet->length = length;
                        packet->send_path = path_x;
                        packet->is_mtu_probe = 1;
                        path_x->mtu_probe_sent = 1;
                        is_pure_ack = 0;
                    }
                }
            }
        }

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
    
    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_min_max,
        &path_x->remote_cnxid, &path_x->local_cnxid, path_x, current_time);

    if (*send_length > 0) {
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);

        if (ret == 0 && cnx->cc_log != NULL) {
            picoquic_cc_dump(cnx, current_time);
        }
    }

    return ret;
}

/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_segment(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    uint64_t * next_wake_time, int * is_initial_sent)
{
    int ret = 0;
  
    /* Check that the connection is still alive -- the timer is asymmetric, so client will drop faster */
    if ((cnx->cnx_state < picoquic_state_disconnecting && 
        (current_time - cnx->latest_progress_time) >= (PICOQUIC_MICROSEC_SILENCE_MAX*(2 - cnx->client_mode))) ||
        (cnx->cnx_state < picoquic_state_server_false_start &&
            current_time >= cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX))
    {
        /* Too long silence, break it. */
        cnx->cnx_state = picoquic_state_disconnected;
        ret = PICOQUIC_ERROR_DISCONNECTED;
        if (cnx->callback_fn) {
            (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
        }
    } else {
        /* Prepare header -- depend on connection state */
        /* TODO: 0-RTT work. */
        switch (cnx->cnx_state) {
        case picoquic_state_client_init:
        case picoquic_state_client_init_sent:
        case picoquic_state_client_init_resent:
        case picoquic_state_client_renegotiate:
        case picoquic_state_client_handshake_start:
        case picoquic_state_client_handshake_progress:
        case picoquic_state_client_almost_ready:
            ret = picoquic_prepare_packet_client_init(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time, is_initial_sent);
            break;
        case picoquic_state_server_almost_ready:
        case picoquic_state_server_init:
        case picoquic_state_server_handshake:
            ret = picoquic_prepare_packet_server_init(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length, next_wake_time);
            break;
        case picoquic_state_server_false_start:
        case picoquic_state_client_ready_start:
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
    }

    return ret;
}

/* Prepare next probe if one is needed, returns send_length == 0 if none necessary */
int picoquic_prepare_probe(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage * p_addr_to, int * to_len, struct sockaddr_storage * p_addr_from, int * from_len, struct sockaddr_storage * addr_to_log,
    uint64_t * next_wake_time)
{
    int ret = 0;

    *send_length = 0;

    if (send_buffer_max < PICOQUIC_INITIAL_MTU_IPV6) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else if (
        cnx->cnx_state == picoquic_state_ready || 
        cnx->cnx_state == picoquic_state_client_ready_start)
    {
        picoquic_probe_t * probe = cnx->probe_first;
        picoquic_packet_t * packet = NULL;

        while (probe != NULL) {
            if (!probe->challenge_failed && !probe->challenge_verified){
                uint64_t next_probe_time = probe->challenge_time + cnx->path[0]->retransmit_timer;
                if (probe->challenge_required || current_time >= next_probe_time) {
                    if (probe->challenge_repeat_count >= PICOQUIC_CHALLENGE_REPEAT_MAX) {
                        probe->challenge_failed = 1;
                    }
                    else {
                        break;
                    }
                }
                else if (next_probe_time < *next_wake_time) {
                    *next_wake_time = next_probe_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
            probe = probe->next_probe;
        }

        if (probe != NULL)
        {
            
            packet = picoquic_create_packet(cnx->quic);

            if (packet == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            }
            else {
                uint8_t * bytes = packet->bytes;
                size_t length = 0;
                size_t header_length = 0;
                picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
                picoquic_packet_context_enum pc = picoquic_packet_context_application;
                size_t checksum_overhead = picoquic_get_checksum_length(cnx, 0);
                size_t data_bytes = 0;
                int inactive_path_index = -1;

                length = picoquic_predict_packet_header_length(
                    cnx, packet_type);
                packet->ptype = packet_type;
                packet->offset = length;
                header_length = length;
                packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                packet->send_time = current_time;
                packet->send_path = cnx->path[0]; /* TODO: check that this can work */

                /* If there are not enough paths, create one and advertise it */
                for (int i = 1; i < cnx->nb_paths; i++)
                {
                    if (!cnx->path[i]->path_is_activated) {
                        inactive_path_index = i;
                        break;
                    }
                }

                if( inactive_path_index < 0) {
                    ret = picoquic_prepare_new_path_and_id(cnx, &bytes[length],
                        send_buffer_max - checksum_overhead - length,
                        current_time, &data_bytes);
                    if (ret == 0) {
                        length += data_bytes;
                    }
                }
                else {
                    /* Add a copy of the last created connection ID */
                    ret = picoquic_prepare_new_connection_id_frame(cnx, cnx->path[inactive_path_index], &bytes[length],
                        send_buffer_max - checksum_overhead - length, &data_bytes);
                    if (ret == 0) {
                        length += data_bytes;
                    }
                }

                if (ret == 0) {
                    /* Format the challenge frame */
                    ret = picoquic_prepare_path_challenge_frame(&bytes[length],
                        send_buffer_max - checksum_overhead - length, &data_bytes,
                        probe->challenge[probe->challenge_repeat_count]);
                    if (ret == 0) {
                        length += data_bytes;
                        probe->challenge_required = 0;
                        probe->challenge_time = current_time;
                        probe->challenge_repeat_count++;
                    }
                }

                /* Pack to min length, to verify that the path can carry a min length packet */
                if (length + checksum_overhead < PICOQUIC_INITIAL_MTU_IPV6) {
                    length = picoquic_pad_to_target_length(bytes, length, PICOQUIC_INITIAL_MTU_IPV6 - checksum_overhead);
                }

                /* set the return addresses */
                if (p_addr_to != NULL) {
                    *to_len = picoquic_store_addr(p_addr_to, (struct sockaddr*)&probe->peer_addr);
                }
                /* Remember the log address */
                (void)picoquic_store_addr(addr_to_log, (struct sockaddr*)&(probe->peer_addr));
                /* Set the source address */
                if (p_addr_from != NULL) {
                    *from_len = picoquic_store_addr(p_addr_from, (struct sockaddr*)(&probe->local_addr));
                }

                /* final protection */
                picoquic_finalize_and_protect_packet(cnx, packet,
                    ret, length, header_length, checksum_overhead,
                    send_length, send_buffer, send_buffer_max,
                    &probe->remote_cnxid, &cnx->path[0]->local_cnxid, cnx->path[0], current_time);
            }
        }
    }

    return ret;
}

/* Send alternate address challenge if required */
static int picoquic_prepare_alt_challenge(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage * p_addr_to, int * to_len, struct sockaddr_storage * p_addr_from, int * from_len,
    struct sockaddr_storage * addr_to_log, uint64_t * next_wake_time)
{
    int ret = 0;
    picoquic_packet_t * packet = NULL;
    unsigned int is_alt_challenge_still_needed = 0;

    *send_length = 0;

    if (send_buffer_max < PICOQUIC_INITIAL_MTU_IPV6) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        is_alt_challenge_still_needed = 1;
    }
    else if (
        cnx->cnx_state == picoquic_state_ready ||
        cnx->cnx_state == picoquic_state_client_ready_start)
    {
        for (int i = 0; i < cnx->nb_paths; i++) {

            if (cnx->path[i]->alt_challenge_required &&
                cnx->path[i]->alt_challenge_repeat_count > 3 &&
                current_time >= cnx->path[i]->alt_challenge_timeout) {
                /* Challenge is failing. Set required to 0. */
                cnx->path[i]->alt_challenge_required = 0;
            }

            if (((cnx->path[i]->alt_challenge_required &&
                (cnx->path[i]->alt_challenge_repeat_count == 0 ||
                    current_time >= cnx->path[i]->alt_challenge_timeout))
                || cnx->path[i]->alt_response_required)
                && !cnx->path[i]->path_is_demoted) {
                packet = picoquic_create_packet(cnx->quic);

                if (packet == NULL) {
                    ret = PICOQUIC_ERROR_MEMORY;
                }
                else {
                    uint8_t * bytes = packet->bytes;
                    size_t length = 0;
                    size_t header_length = 0;
                    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
                    picoquic_packet_context_enum pc = picoquic_packet_context_application;
                    size_t checksum_overhead = picoquic_get_checksum_length(cnx, 0);
                    size_t data_bytes = 0;

                    length = picoquic_predict_packet_header_length(
                        cnx, packet_type);
                    packet->ptype = packet_type;
                    packet->offset = length;
                    header_length = length;
                    packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                    packet->send_time = current_time;
                    packet->send_path = cnx->path[i];

                    if (cnx->path[i]->alt_challenge_required &&
                        (cnx->path[i]->alt_challenge_repeat_count == 0 ||
                            current_time >= cnx->path[i]->alt_challenge_timeout)) {
                        ret = picoquic_prepare_path_challenge_frame(&bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes,
                            cnx->path[i]->alt_challenge[cnx->path[i]->alt_challenge_repeat_count]);
                        if (ret == 0) {
                            length += data_bytes;
                            cnx->path[i]->alt_challenge_timeout = current_time + cnx->path[i]->retransmit_timer;
                            cnx->path[i]->alt_challenge_repeat_count++;
                        }
                    }

                    if (cnx->path[i]->alt_response_required) {
                        ret = picoquic_prepare_path_response_frame(&bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes, cnx->path[i]->alt_challenge_response);
                        if (ret == 0) {
                            length += data_bytes;
                            cnx->path[i]->alt_challenge_timeout = current_time + cnx->path[i]->retransmit_timer;
                        }
                        cnx->path[i]->alt_response_required = 0;
                    }

                    /* Pack to min length, to verify that the path can carry a min length packet */
                    if (length + checksum_overhead < PICOQUIC_INITIAL_MTU_IPV6) {
                        length = picoquic_pad_to_target_length(bytes, length, PICOQUIC_INITIAL_MTU_IPV6 - checksum_overhead);
                    }

                    /* set the return addresses */
                    if (p_addr_to != NULL) {
                        *to_len = picoquic_store_addr(p_addr_to, (struct sockaddr*)&cnx->path[i]->alt_peer_addr);
                    }
                    /* Remember the log address */
                    (void)picoquic_store_addr(addr_to_log, (struct sockaddr*)&cnx->path[i]->alt_peer_addr);
                    /* Set the source address */
                    if (p_addr_from != NULL) {
                        *from_len = picoquic_store_addr(p_addr_from, (struct sockaddr*)&cnx->path[i]->alt_local_addr);
                    }

                    /* final protection */
                    picoquic_finalize_and_protect_packet(cnx, packet,
                        ret, length, header_length, checksum_overhead,
                        send_length, send_buffer, send_buffer_max,
                        &cnx->path[i]->remote_cnxid, &cnx->path[0]->local_cnxid, cnx->path[0], current_time);

                    /* no need to check the other paths yet. Will check at next invocation. */
                    is_alt_challenge_still_needed = 1;
                    break;
                }

                is_alt_challenge_still_needed |= cnx->path[i]->alt_challenge_required;
                is_alt_challenge_still_needed |= cnx->path[i]->alt_response_required;
            }
            else if (cnx->path[i]->alt_challenge_required &&
                cnx->path[i]->alt_challenge_repeat_count < 4 &&
                *next_wake_time > cnx->path[i]->alt_challenge_timeout) {
                *next_wake_time = cnx->path[i]->alt_challenge_timeout;
                is_alt_challenge_still_needed = 1;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        }
    } else {
        is_alt_challenge_still_needed = 1;
    }

    cnx->alt_path_challenge_needed = is_alt_challenge_still_needed;

    return ret;
}

/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_packet(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage * p_addr_to, int * to_len, struct sockaddr_storage * p_addr_from, int * from_len)
{

    int ret = 0;
    picoquic_packet_t * packet = NULL;
    struct sockaddr_storage addr_to_log;
    uint64_t next_wake_time = cnx->latest_progress_time + PICOQUIC_MICROSEC_SILENCE_MAX * (2 - cnx->client_mode);
    int is_initial_sent=0;

    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);

    memset(&addr_to_log, 0, sizeof(addr_to_log));
    *send_length = 0;

    /* Promote successful probe */
    picoquic_promote_successful_probe(cnx, current_time);

    /* Remove delete paths */
    if (cnx->path_demotion_needed) {
        picoquic_delete_abandoned_paths(cnx, current_time, &next_wake_time);
    }

    /* Check whether to insert a hole in the sequence of packets */
    if (cnx->pkt_ctx[0].send_sequence >= cnx->pkt_ctx[0].next_sequence_hole) {
        picoquic_insert_hole_in_send_sequence_if_needed(cnx, current_time, &next_wake_time);
    }

    if (cnx->probe_first != NULL) {
        /* Remove failed probes */
        picoquic_delete_failed_probes(cnx);

        /* If probes are in waiting, send the first one */
        ret = picoquic_prepare_probe(cnx, current_time, send_buffer, send_buffer_max, send_length,
            p_addr_to, to_len, p_addr_from, from_len, &addr_to_log, &next_wake_time);
    }

    /* If alternate challenges are waiting, send them */
    if (ret == 0 && *send_length == 0 && cnx->alt_path_challenge_needed) {
        ret = picoquic_prepare_alt_challenge(cnx, current_time, send_buffer, send_buffer_max, send_length,
            p_addr_to, to_len, p_addr_from, from_len, &addr_to_log, &next_wake_time);
    }

    if (ret == 0 && *send_length == 0) {
        int path_id = -1;
        /* Select the path */
        for (int i = 1; i < cnx->nb_paths; i++) {
            if (cnx->path[i]->path_is_demoted) {
                continue;
            } else if (cnx->path[i]->challenge_verified) {
                /* TODO: selection logic if multiple paths are available! */
                /* This path becomes the new default */
                picoquic_promote_path_to_default(cnx, i, current_time);
                path_id = 0;
                break;
            }
            else if (path_id < 0) {
                if (cnx->path[i]->response_required) {
                    path_id = i;
                } else if (cnx->path[i]->challenge_required) {
                    uint64_t next_challenge_time = (cnx->path[i]->challenge_time + cnx->path[i]->retransmit_timer);
                    if (cnx->path[i]->challenge_repeat_count == 0 ||
                        current_time >= next_challenge_time) {
                        /* will try this path, unless a validated path came in */
                        path_id = i;
                    }
                    else if (next_challenge_time < next_wake_time) {
                        next_wake_time = next_challenge_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
            }
        }

        if (path_id < 0) {
            path_id = 0;
        }

        (void)picoquic_store_addr(&addr_to_log, (struct sockaddr *)&cnx->path[path_id]->peer_addr);

        if (p_addr_to != NULL && to_len != NULL) {
            *to_len = picoquic_store_addr(p_addr_to, (struct sockaddr *)&cnx->path[path_id]->peer_addr);
        }

        if (p_addr_from != NULL && from_len != NULL) {
            *from_len = picoquic_store_addr(p_addr_from, (struct sockaddr *)&cnx->path[path_id]->local_addr);
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
                }
                else {
                    picoquic_recycle_packet(cnx->quic, packet);
                    packet = NULL;

                    if (*send_length != 0) {
                        ret = 0;
                    }
                    break;
                }
            }
        }
    }

    if (*send_length > 0 && is_initial_sent && *send_length < 1200) {
        DBG_PRINTF("%s", "BUG");
    }

    /* if needed, log that the packet is sent */
    if (*send_length > 0 && cnx->quic->F_log != NULL && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || cnx->quic->use_long_log)) {
        picoquic_log_packet_address(cnx->quic->F_log,
            picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)),
            cnx, (struct sockaddr *)&addr_to_log, 0, *send_length, current_time);
    }
    if (*send_length > 0 && cnx->quic->f_binlog != NULL && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || cnx->quic->use_long_log)) {
        binlog_pdu(cnx->quic->f_binlog, &cnx->initial_cnxid, 0, current_time,
            (struct sockaddr *)&addr_to_log, *send_length);
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
        cnx->application_error = reason_code;
    } else {
        ret = -1;
    }
    cnx->offending_frame_type = 0;

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}
