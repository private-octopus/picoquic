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

#include "fnv1a.h"
#include "picoquic_internal.h"
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
 *
 * Stream 0 is special, in the sense that it cannot be closed or reset, and is not
 * subject to flow control.
 */
int picoquic_add_to_stream(picoquic_cnx_t* cnx, uint64_t stream_id,
    const uint8_t* data, size_t length, int set_fin)
{
    int ret = 0;
    int is_unidir = 0;
    picoquic_stream_head* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id, 0);

    if (stream == NULL) {
        /* Need to check that the ID is authorized */

        /* Check parity */
        if (IS_CLIENT_STREAM_ID(stream_id) != cnx->client_mode) {
            ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
        }

        if (ret == 0) {
            stream = picoquic_create_stream(cnx, stream_id);

            if (stream == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            } else if (is_unidir) {
                /* Mark the stream as already finished in remote direction */
                stream->stream_flags |= picoquic_stream_flag_fin_signalled | picoquic_stream_flag_fin_received;
            }
        }
    }

    if (ret == 0 && set_fin) {
        if ((stream->stream_flags & picoquic_stream_flag_fin_notified) != 0) {
            /* app error, notified the fin twice*/
            if (length > 0) {
                ret = -1;
            }
        } else {
            stream->stream_flags |= picoquic_stream_flag_fin_notified;
        }
    }

    /* If our side has sent RST_STREAM or received STOP_SENDING, we should not send anymore data. */
    if (ret == 0 && (STREAM_RESET_SENT(stream) || STREAM_STOP_SENDING_RECEIVED(stream))) {
        ret = -1;
    }

    if (ret == 0 && length > 0) {
        picoquic_stream_data* stream_data = (picoquic_stream_data*)malloc(sizeof(picoquic_stream_data));

        if (stream_data == 0) {
            ret = -1;
        } else {
            stream_data->bytes = (uint8_t*)malloc(length);

            if (stream_data->bytes == NULL) {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            } else {
                picoquic_stream_data** pprevious = &stream->send_queue;
                picoquic_stream_data* next = stream->send_queue;

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

    return ret;
}

int picoquic_reset_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id, 1);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if ((stream->stream_flags & picoquic_stream_flag_fin_sent) != 0) {
        ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
    }
    else if ((stream->stream_flags & picoquic_stream_flag_reset_requested) == 0) {
        stream->local_error = local_stream_error;
        stream->stream_flags |= picoquic_stream_flag_reset_requested;
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

int picoquic_stop_sending(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head* stream = NULL;

    stream = picoquic_find_stream(cnx, stream_id, 1);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if ((stream->stream_flags & picoquic_stream_flag_reset_received) != 0) {
        ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
    }
    else if ((stream->stream_flags & picoquic_stream_flag_stop_sending_requested) == 0) {
        stream->local_stop_error = local_stream_error;
        stream->stream_flags |= picoquic_stream_flag_stop_sending_requested;
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

/*
 * Packet management
 */

picoquic_packet_t* picoquic_create_packet()
{
    picoquic_packet_t* packet = (picoquic_packet_t*)malloc(sizeof(picoquic_packet_t));

    if (packet != NULL) {
        memset(packet, 0, sizeof(picoquic_packet_t));
    }

    return packet;
}

void picoquic_update_payload_length(
    uint8_t* bytes, size_t pnum_index, size_t header_length, uint32_t packet_length)
{
    if ((bytes[0] & 0x80) != 0 && header_length > 6 && packet_length > header_length && packet_length < 0x4000)
    {
        picoquic_varint_encode_16(bytes + pnum_index - 2, (uint16_t)(packet_length - header_length));
    }
}

uint32_t picoquic_predict_packet_header_length_11(
    picoquic_packet_type_enum packet_type,
    picoquic_connection_id_t dest_cnx_id,
    picoquic_connection_id_t srce_cnx_id)
{
    uint32_t length = 0;

    if (packet_type == picoquic_packet_1rtt_protected) {
        /* Compute length of a short packet header */

        length = 1 + dest_cnx_id.id_len + 4;
    }
    else {
        /* Compute length of a long packet header */
        length = 1 + /* version */ 4 + /* cnx_id prefix */ 1 + dest_cnx_id.id_len + srce_cnx_id.id_len + /* segment length */ 2 + /* seq num */ 4;
    }

    return length;
}

uint32_t picoquic_create_packet_header(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    uint64_t sequence_number,
    picoquic_connection_id_t * remote_cnxid,
    picoquic_connection_id_t * local_cnxid,
    uint8_t* bytes,
    uint32_t * pn_offset,
    uint32_t * pn_length)
{
    uint32_t length = 0;
    picoquic_connection_id_t dest_cnx_id =
        ((packet_type == picoquic_packet_initial ||
            packet_type == picoquic_packet_0rtt_protected)
            && picoquic_is_connection_id_null(*remote_cnxid)) ?
        cnx->initial_cnxid : *remote_cnxid;

    /* Prepare the packet header */
    if (packet_type == picoquic_packet_1rtt_protected) {
        /* Create a short packet -- using 32 bit sequence numbers for now */
        uint8_t K = (cnx->key_phase_enc) ? 0x40 : 0;
        const uint8_t C = 0x30;
        length = 0;
        bytes[length++] = (K | C | picoquic_spin_function_table[picoquic_supported_versions[cnx->version_index].spinbit_version].spinbit_outgoing(cnx));
        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, dest_cnx_id);

        *pn_offset = length;
        *pn_length = 4;
        picoquic_headint_encode_32(&bytes[length], sequence_number);
        length += 4;
    }
    else {
        /* Create a long packet */

        switch (packet_type) {
        case picoquic_packet_initial:
            bytes[0] = 0xFF;
            break;
        case picoquic_packet_retry:
            bytes[0] = 0xFE;
            break;
        case picoquic_packet_handshake:
            bytes[0] = 0xFD;
            break;
        case picoquic_packet_0rtt_protected:
            bytes[0] = 0xFC;
            break;
        default:
            bytes[0] = 0x80;
            break;
        }
        length = 1;
        if ((cnx->cnx_state == picoquic_state_client_init || cnx->cnx_state == picoquic_state_client_init_sent) && packet_type == picoquic_packet_initial) {
            picoformat_32(&bytes[length], cnx->proposed_version);
        }
        else {
            picoformat_32(&bytes[length],
                picoquic_supported_versions[cnx->version_index].version);
        }
        length += 4;

        bytes[length++] = picoquic_create_packet_header_cnxid_lengths(dest_cnx_id.id_len, local_cnxid->id_len);

        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, dest_cnx_id);
        length += picoquic_format_connection_id(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, *local_cnxid);

        /* Special case of packet initial -- encode token as part of header */
        if (packet_type == picoquic_packet_initial) {
            length += (uint32_t)picoquic_varint_encode(&bytes[length], PICOQUIC_MAX_PACKET_SIZE - length, cnx->retry_token_length);
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
            picoquic_headint_encode_32(&bytes[length], sequence_number);
            length += 4;
        }
    }

    return length;
}

uint32_t picoquic_predict_packet_header_length(
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
        header_length = 1 + /* version */ 4 + /* cnx_id prefix */ 1;

        /* add dest-id length */
        if ((packet_type == picoquic_packet_initial ||
            packet_type == picoquic_packet_0rtt_protected)
            && picoquic_is_connection_id_null(cnx->path[0]->remote_cnxid)) {
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
uint32_t picoquic_get_checksum_length(picoquic_cnx_t* cnx, int is_cleartext_mode)
{
    uint32_t ret = 16;

    if (is_cleartext_mode || cnx->crypto_context[2].aead_encrypt == NULL) {
        ret = picoquic_aead_get_checksum_length(cnx->crypto_context[0].aead_encrypt);
    } else {
        ret = picoquic_aead_get_checksum_length(cnx->crypto_context[2].aead_encrypt);
    }

    return ret;
}

uint32_t picoquic_protect_packet(picoquic_cnx_t* cnx, 
    picoquic_packet_type_enum ptype,
    uint8_t * bytes, 
    uint64_t sequence_number,
    picoquic_connection_id_t * remote_cnxid,
    picoquic_connection_id_t * local_cnxid,
    uint32_t length, uint32_t header_length,
    uint8_t* send_buffer, uint32_t send_buffer_max,
    void * aead_context, void* pn_enc)
{
    uint32_t send_length;
    uint32_t h_length;
    uint32_t pn_offset = 0;
    uint32_t sample_offset = 0;
    uint32_t sample_size = (uint32_t) picoquic_pn_iv_size(pn_enc);
    uint32_t pn_length = 0;
    uint32_t aead_checksum_length = (uint32_t)picoquic_aead_get_checksum_length(aead_context);

    /* Create the packet header just before encrypting the content */
    h_length = picoquic_create_packet_header(cnx, ptype,
        sequence_number, remote_cnxid, local_cnxid, send_buffer, &pn_offset, &pn_length);
    /* If the destination ID does not match the local context, reset the spin bit */
    if (ptype == picoquic_packet_1rtt_protected &&
        remote_cnxid != &cnx->path[0]->remote_cnxid) {
        /* Packet is sent to a different CID: reset the spin bits to 0 */
        send_buffer[0] &= 0xF8;
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
    send_length = (uint32_t)picoquic_aead_encrypt_generic(send_buffer + /* header_length */ h_length,
        bytes + header_length, length - header_length,
        sequence_number, send_buffer, /* header_length */ h_length, aead_context);

    send_length += /* header_length */ h_length;

    /* Next, encrypt the PN -- The sample is located after the pn_offset */
    sample_offset = /* header_length */ pn_offset + 4;

    if (sample_offset + sample_size > send_length)
    {
        sample_offset = send_length - sample_size;
    }

    if (pn_offset < sample_offset)
    {
        /* Encode */
        picoquic_pn_encrypt(pn_enc, send_buffer + sample_offset, send_buffer + /* pn_offset */ pn_offset, 
            send_buffer + /* pn_offset */ pn_offset, pn_length);
    }

    /* if needed, log the segment */
    if (cnx->quic->F_log != NULL) {
        picoquic_log_outgoing_segment(cnx->quic->F_log, 1, cnx,
            bytes, sequence_number, length,
            send_buffer, send_length);
    }

    return send_length;
}

/*
 * Reset the pacing data after CWIN is updated
 */

void picoquic_update_pacing_data(picoquic_path_t * path_x)
{
    path_x->packet_time_nano_sec = path_x->smoothed_rtt * 1000ull * path_x->send_mtu;
    path_x->packet_time_nano_sec /= path_x->cwin;

    path_x->pacing_margin_micros = 16 * path_x->packet_time_nano_sec;
    if (path_x->pacing_margin_micros > (path_x->rtt_min / 8)) {
        path_x->pacing_margin_micros = (path_x->rtt_min / 8);
    }
    if (path_x->pacing_margin_micros < 1000) {
        path_x->pacing_margin_micros = 1000;
    }
}

/* 
 * Update the pacing data after sending a packet
 */
void picoquic_update_pacing_after_send(picoquic_path_t * send_path, uint64_t current_time)
{
    if (send_path->next_pacing_time < current_time) {
        send_path->next_pacing_time = current_time;
        send_path->pacing_reminder_nano_sec = 0;
    } else {
        send_path->pacing_reminder_nano_sec += send_path->packet_time_nano_sec;
        send_path->next_pacing_time += (send_path->pacing_reminder_nano_sec >> 10);
        send_path->pacing_reminder_nano_sec &= 0x3FF;
    }
}

/*
 * Final steps in packet transmission: queue for retransmission, etc
 */

void picoquic_queue_for_retransmit(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    size_t length, uint64_t current_time)
{
    picoquic_packet_context_enum pc = packet->pc;

    /* Account for bytes in transit, for congestion control */
    path_x->bytes_in_transit += length;

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

    /* Update the pacing data */
    picoquic_update_pacing_after_send(path_x, current_time);
}

picoquic_packet_t* picoquic_dequeue_retransmit_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p, int should_free)
{
    uint32_t dequeued_length = p->length + p->checksum_overhead;
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

    if (p->send_path != NULL) {
        if (p->send_path->bytes_in_transit > dequeued_length) {
            p->send_path->bytes_in_transit -= dequeued_length;
        }
        else {
            p->send_path->bytes_in_transit = 0;
        }
    }

    if (should_free) {
        free(p);
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

    free(p);
}


/*
 * Final steps of encoding and protecting the packet before sending
 */

void picoquic_finalize_and_protect_packet(picoquic_cnx_t *cnx, picoquic_packet_t * packet, int ret, 
    uint32_t length, uint32_t header_length, uint32_t checksum_overhead,
    size_t * send_length, uint8_t * send_buffer, uint32_t send_buffer_max,
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
                send_buffer, send_buffer_max, cnx->crypto_context[0].aead_encrypt, cnx->crypto_context[0].pn_enc);
            break;
        case picoquic_packet_handshake:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[2].aead_encrypt, cnx->crypto_context[2].pn_enc);
            break;
        case picoquic_packet_retry:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[0].aead_encrypt, cnx->crypto_context[0].pn_enc);
            break;
        case picoquic_packet_0rtt_protected:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number, 
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[1].aead_encrypt, cnx->crypto_context[1].pn_enc);
            break;
        case picoquic_packet_1rtt_protected:
            length = picoquic_protect_packet(cnx, packet->ptype, packet->bytes, packet->sequence_number,
                remote_cnxid, local_cnxid,
                length, header_length,
                send_buffer, send_buffer_max, cnx->crypto_context[3].aead_encrypt, cnx->crypto_context[3].pn_enc);
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
    int64_t delta_seq = cnx->pkt_ctx[pc].highest_acknowledged - p->sequence_number;
    int should_retransmit = 0;

    if (delta_seq > 3) {
        /*
         * SACK Logic.
         * more than N packets were seen at the receiver after this one.
         */
        should_retransmit = 1;
    }
    else {
        if (p->ptype != picoquic_packet_0rtt_protected &&
            delta_seq > 0 &&
            p->send_time <= cnx->pkt_ctx[pc].latest_time_acknowledged) {
            uint64_t delta_t = (cnx->pkt_ctx[pc].latest_time_acknowledged - p->send_time) +
                (current_time - cnx->pkt_ctx[pc].highest_acknowledged_time);

            /* TODO: out of order delivery time ought to be dynamic */
            if (delta_t >= PICOQUIC_RACK_DELAY) {
                should_retransmit = 1;
            } else {
                uint64_t next_rack_time = current_time + (PICOQUIC_RACK_DELAY - delta_t);
                if (next_rack_time < *next_retransmit_time) {
                    *next_retransmit_time = next_rack_time;
                }
            }
        }

        if (should_retransmit == 0) {
            /* Don't fire yet, because of possible out of order delivery */
            int64_t time_out = current_time - p->send_time;
            uint64_t retransmit_timer = (cnx->pkt_ctx[pc].nb_retransmit == 0) ?
                cnx->path[0]->retransmit_timer : (1000000ull << (cnx->pkt_ctx[pc].nb_retransmit - 1));

            if ((uint64_t)time_out < retransmit_timer) {
                /* Do not retransmit if the timer has not yet elapsed */
                should_retransmit = 0;
                if (current_time + retransmit_timer < *next_retransmit_time) {
                    *next_retransmit_time = current_time + retransmit_timer;
                }
            } else {
                should_retransmit = 1;
                *timer_based = 1;
            }
        }
    }

    return should_retransmit;
}

int picoquic_retransmit_needed(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc,
    picoquic_path_t * path_x, uint64_t current_time, uint64_t * next_retransmit_time,
    picoquic_packet_t* packet, size_t send_buffer_max, int* is_cleartext_mode, uint32_t* header_length)
{
    picoquic_packet_t* p = cnx->pkt_ctx[pc].retransmit_oldest;
    uint32_t length = 0;

    /* TODO: while packets are pure ACK, drop them from retransmit queue */
    while (p != NULL) {
        int should_retransmit = 0;
        int timer_based_retransmit = 0;
        uint64_t lost_packet_number = p->sequence_number;
        picoquic_packet_t* p_next = p->next_packet;
        uint8_t * new_bytes = packet->bytes;
        int ret = 0;

        length = 0;
        /* Get the packet type */

        should_retransmit = picoquic_retransmit_needed_by_packet(cnx, p, current_time, next_retransmit_time, &timer_based_retransmit);

        if (should_retransmit == 0) {
            /*
             * Always retransmit in order. If not this one, then nothing.
             * But make an exception for 0-RTT packets.
             */
            if (p->ptype == picoquic_packet_0rtt_protected) {
                p = p_next;
                continue;
            } else {
                break;
            }
        } else {
            /* check if this is an ACK only packet */
            int packet_is_pure_ack = 1;
            int do_not_detect_spurious = 1;
            int frame_is_pure_ack = 0;
            uint8_t* old_bytes = p->bytes;
            size_t frame_length = 0;
            size_t byte_index = 0; /* Used when parsing the old packet */
            size_t checksum_length = 0;
            /* should be the path on which the packet was transmitted */
            picoquic_path_t * old_path = p->send_path;

	    /* we'll report it where it got lost */
	    if (old_path) old_path->retrans_count++;

            *header_length = 0;

            if (p->ptype == picoquic_packet_0rtt_protected) {
                /* Only retransmit as 0-RTT if contains crypto data */
                int contains_crypto = 0;
                byte_index = p->offset;

                if (p->is_evaluated == 0) {
                    while (ret == 0 && byte_index < p->length) {
                        if (old_bytes[byte_index] == picoquic_frame_type_crypto_hs) {
                            contains_crypto = 1;
                            packet_is_pure_ack = 0;
                            break;
                        }
                        ret = picoquic_skip_frame(&p->bytes[byte_index],
                            p->length - byte_index, &frame_length, &frame_is_pure_ack);
                        byte_index += frame_length;
                    }
                    p->contains_crypto = contains_crypto;
                    p->is_pure_ack = packet_is_pure_ack;
                    p->is_evaluated = 1;
                } else {
                    contains_crypto = p->contains_crypto;
                    packet_is_pure_ack = p->is_pure_ack;
                }

                if (contains_crypto) {
                    length = picoquic_predict_packet_header_length(cnx, picoquic_packet_0rtt_protected);
                    packet->ptype = picoquic_packet_0rtt_protected;
                    packet->offset = length;
                } else if (cnx->cnx_state < picoquic_state_client_ready) {
                    should_retransmit = 0;
                } else {
                    length = picoquic_predict_packet_header_length(cnx, picoquic_packet_1rtt_protected);
                    packet->ptype = picoquic_packet_1rtt_protected;
                    packet->offset = length;
                }
            } else {
                length = picoquic_predict_packet_header_length(cnx, p->ptype);
                packet->ptype = p->ptype;
                packet->offset = length;
            }

            if (should_retransmit != 0) {
                packet->sequence_number = cnx->pkt_ctx[pc].send_sequence;
                packet->send_path = path_x;
                packet->pc = pc;

                *header_length = length;

                if (p->ptype == picoquic_packet_1rtt_protected || p->ptype == picoquic_packet_0rtt_protected) {
                    *is_cleartext_mode = 0;
                } else {
                    *is_cleartext_mode = 1;
                }

                if (old_path != NULL && (p->length + p->checksum_overhead) > old_path->send_mtu) {
                    /* MTU probe was lost, presumably because of packet too big */
                    old_path->mtu_probe_sent = 0;
                    old_path->send_mtu_max_tried = (uint32_t)(p->length + p->checksum_overhead);
                    /* MTU probes should not be retransmitted */
                    packet_is_pure_ack = 1;
                    do_not_detect_spurious = 0;
                } else {
                    checksum_length = picoquic_get_checksum_length(cnx, *is_cleartext_mode);

                    /* Copy the relevant bytes from one packet to the next */
                    byte_index = p->offset;

                    while (ret == 0 && byte_index < p->length) {
                        ret = picoquic_skip_frame(&p->bytes[byte_index],
                            p->length - byte_index, &frame_length, &frame_is_pure_ack);

                        /* Check whether the data was already acked, which may happen in 
                         * case of spurious retransmissions */
                        if (ret == 0 && frame_is_pure_ack == 0) {
                            ret = picoquic_check_stream_frame_already_acked(cnx, &p->bytes[byte_index],
                                frame_length, &frame_is_pure_ack);
                        }

                        /* Prepare retransmission if needed */
                        if (ret == 0 && !frame_is_pure_ack) {
                            if (picoquic_is_stream_frame_unlimited(&p->bytes[byte_index])) {
                                /* Need to PAD to the end of the frame to avoid sending extra bytes */
                                while (checksum_length + length + frame_length < send_buffer_max) {
                                    new_bytes[length] = picoquic_frame_type_padding;
                                    length++;
                                }
                            }
                            memcpy(&new_bytes[length], &p->bytes[byte_index], frame_length);
                            length += (uint32_t)frame_length;
                            packet_is_pure_ack = 0;
                        }
                        byte_index += frame_length;
                    }
                }

                /* Update the number of bytes in transit and remove old packet from queue */
                /* If not pure ack, the packet will be placed in the "retransmitted" queue,
                 * in order to enable detection of spurious restransmissions */
                p = picoquic_dequeue_retransmit_packet(cnx, p, packet_is_pure_ack & do_not_detect_spurious);

                /* If we have a good packet, return it */
                if (p == NULL || packet_is_pure_ack) {
                    length = 0;
                } else {
                    if (timer_based_retransmit != 0) {
                        if (cnx->pkt_ctx[pc].nb_retransmit > 4) {
                            /*
                             * Max retransmission count was exceeded. Disconnect.
                             */
                            DBG_PRINTF("%s\n", "Too many retransmits, disconnect");
                            cnx->cnx_state = picoquic_state_disconnected;
                            if (cnx->callback_fn) {
                                (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                            }
                            length = 0;
                            break;
                        } else {
                            cnx->pkt_ctx[pc].nb_retransmit++;
                            cnx->pkt_ctx[pc].latest_retransmit_time = current_time;
                        }
                    }

                    if (should_retransmit != 0) {
                        if (p->ptype < picoquic_packet_1rtt_protected) {
                            DBG_PRINTF("Retransmit packet type %d, pc=%d, seq = %llx, is_client = %d\n",
                                p->ptype, p->pc,
                                (unsigned long long)p->sequence_number, cnx->client_mode);
                        }

                        /* special case for the client initial */
                        if (p->ptype == picoquic_packet_initial && cnx->client_mode != 0) {
                            while (length < (send_buffer_max - checksum_length)) {
                                new_bytes[length++] = 0;
                            }
                        }
                        packet->length = length;
                        cnx->nb_retransmission_total++;

                        if (cnx->congestion_alg != NULL && old_path != NULL) {
                            cnx->congestion_alg->alg_notify(old_path,
                                (timer_based_retransmit == 0) ? picoquic_congestion_notification_repeat : picoquic_congestion_notification_timeout,
                                0, 0, lost_packet_number, current_time);
                        }

                        break;
                    }
                }
            }
        }
        /*
         * If the loop is continuing, this means that we need to look
         * at the next candidate packet.
         */
        p = p_next;
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

        while (p != NULL && backlog_empty == 1) {
            /* check if this is an ACK only packet */
            int ret = 0;
            int frame_is_pure_ack = 0;
            size_t frame_length = 0;
            size_t byte_index = 0; /* Used when parsing the old packet */


            /* Copy the relevant bytes from one packet to the next */
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

/* Decide whether to send an MTU probe */
int picoquic_is_mtu_probe_needed(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    int ret = 0;

    if ((cnx->cnx_state == picoquic_state_client_ready || cnx->cnx_state == picoquic_state_server_ready)
        && path_x->mtu_probe_sent == 0 
        && (path_x->send_mtu_max_tried == 0 || (path_x->send_mtu + 10) < path_x->send_mtu_max_tried)) {
        ret = 1;
    }

    return ret;
}

/* Prepare an MTU probe packet */
uint32_t picoquic_prepare_mtu_probe(picoquic_cnx_t* cnx,
    picoquic_path_t * path_x,
    uint32_t header_length, uint32_t checksum_length,
    uint8_t* bytes)
{
    uint32_t probe_length;
    uint32_t length = header_length;
    

    if (path_x->send_mtu_max_tried == 0) {
        if (cnx->remote_parameters.max_packet_size > 0) {
            probe_length = cnx->remote_parameters.max_packet_size;
            
            if (cnx->quic->mtu_max > 0 && (int)probe_length > cnx->quic->mtu_max) {
                probe_length = cnx->quic->mtu_max;
            } else if (probe_length > PICOQUIC_MAX_PACKET_SIZE) {
                probe_length = PICOQUIC_MAX_PACKET_SIZE;
            }
            if (probe_length < path_x->send_mtu) {
                probe_length = path_x->send_mtu;
            }
        } else if (cnx->quic->mtu_max > 0) {
            probe_length = cnx->quic->mtu_max;
        } else {
            probe_length = PICOQUIC_PRACTICAL_MAX_MTU;
        }
    } else {
        probe_length = (path_x->send_mtu + path_x->send_mtu_max_tried) / 2;
    }

    bytes[length++] = picoquic_frame_type_ping;
    bytes[length++] = 0;
    memset(&bytes[length], 0, probe_length - checksum_length - length);

    return probe_length - checksum_length;
}

static uint64_t picoquic_get_challenge_wake_time(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t next_wake_time)
{
    picoquic_probe_t * probe = cnx->probe_first;

    /* Consider demotions */
    for (int i = 0; next_wake_time > current_time && i < cnx->nb_paths; i++) {
        if (cnx->path[i]->response_required) {
            next_wake_time = current_time;
            break;
        }

        if (cnx->path[i]->path_is_demoted &&
            cnx->path[i]->demotion_time < next_wake_time) {
            next_wake_time = cnx->path[i]->demotion_time;
        }

        if (cnx->path[i]->challenge_verified == 0 && cnx->path[i]->path_is_activated) {
            uint64_t next_challenge_time = cnx->path[i]->challenge_time + cnx->path[i]->retransmit_timer;

            if (next_challenge_time < next_wake_time) {
                next_wake_time = next_challenge_time;
            }
        }
    }

    /* Consider probe timers */
    while (probe != NULL && next_wake_time > current_time) {
        if (probe->challenge_verified == 0) {
            uint64_t next_challenge_time = probe->challenge_time + cnx->path[0]->retransmit_timer;

            if (next_challenge_time <= next_wake_time) {
                next_wake_time = next_challenge_time;
            }
        }
        probe = probe->next_probe;
    }

    if (next_wake_time < current_time) {
        next_wake_time = current_time;
    }

    return next_wake_time;
}

/* Prepare the next packet to 0-RTT packet to send in the client initial
 * state, when 0-RTT is available
 */
int picoquic_prepare_packet_0rtt(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    picoquic_stream_head* stream = NULL;
    picoquic_packet_type_enum packet_type = picoquic_packet_0rtt_protected;
    size_t data_bytes = 0;
    int padding_required = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    uint32_t checksum_overhead = picoquic_aead_get_checksum_length(cnx->crypto_context[1].aead_encrypt);

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

    if (packet->sequence_number == 0 && send_buffer_max < PICOQUIC_ENFORCED_INITIAL_MTU) {
        /* Special case in which the 0-RTT packet is coalesced with initial packet */
        padding_required = 1;
    }

    if ((stream == NULL && cnx->first_misc_frame == NULL && padding_required == 0) || 
        (PICOQUIC_DEFAULT_0RTT_WINDOW <= path_x->bytes_in_transit + send_buffer_max)) {
        length = 0;
    } else {
        /* If present, send misc frame */
        while (cnx->first_misc_frame != NULL) {
            ret = picoquic_prepare_first_misc_frame(cnx, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);

            if (ret == 0) {
                length += (uint32_t)data_bytes;
            } else {
                break;
            }
        }
        /* Encode the stream frame */
        if (stream != NULL) {
            ret = picoquic_prepare_stream_frame(cnx, stream, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);
            if (ret == 0) {
                length += (uint32_t) data_bytes;
            }
        }
        /* Add padding if required */
        if (padding_required) {
            while (length < send_buffer_max - checksum_overhead) {
                bytes[length++] = 0;
            }
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, (uint32_t)send_buffer_max,
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
uint32_t picoquic_prepare_packet_old_context(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc,
    picoquic_path_t * path_x, picoquic_packet_t* packet, size_t send_buffer_max, uint64_t current_time, 
    uint64_t * next_retransmit_time, uint32_t * header_length)
{
    int is_cleartext_mode = (pc == picoquic_packet_context_initial) ? 1 : 0;
    uint32_t length = 0;
    size_t data_bytes = 0;
    uint32_t checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);

    *header_length = 0;

    send_buffer_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;

    length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, next_retransmit_time, packet, send_buffer_max,
        &is_cleartext_mode, header_length);
    
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
            if (picoquic_prepare_ack_frame(cnx, current_time, pc, &packet->bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += (uint32_t)data_bytes;
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

/* Prepare the next packet to send when in one of the client initial states */
int picoquic_prepare_packet_client_init(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    int tls_ready = 0;
    picoquic_packet_type_enum packet_type = 0;
    uint64_t next_wake_time = cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;
    uint32_t checksum_overhead = 8;
    int is_cleartext_mode = 1;
    size_t data_bytes = 0;
    int retransmit_possible = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    int epoch = 0;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;

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
    /* TODO: 0-RTT work. */
    switch (cnx->cnx_state) {
    case picoquic_state_client_init:
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
            path_x, packet, send_buffer_max, current_time, &next_wake_time, &header_length);
    }

    if (ret == 0 && epoch > 1 && length == 0) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_application,
            path_x, packet, send_buffer_max, current_time, &next_wake_time, &header_length);
    }

    /* If there is nothing to send in previous context, check this one too */
    if (length == 0) {
        checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
        packet->checksum_overhead = checksum_overhead;
        packet->pc = pc;

        tls_ready = picoquic_is_tls_stream_ready(cnx);

        if (ret == 0 && retransmit_possible &&
            (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, &next_wake_time, packet, send_buffer_max, &is_cleartext_mode, &header_length)) > 0) {
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            if (epoch != 1) {
                ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes);
                if (ret == 0) {
                    length += (uint32_t)data_bytes;
                }
                else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                    ret = 0;
                    next_wake_time = current_time;
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
                        || picoquic_is_ack_needed(cnx, current_time, &next_wake_time, pc) == 0)
                    && cnx->first_misc_frame == NULL) {
                    length = 0;
                }
                else {
                    if (epoch != 1 && cnx->pkt_ctx[pc].ack_needed) {
                        ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes);
                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            data_bytes = 0;
                        }
                        else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            ret = 0;
                            next_wake_time = current_time;
                        }
                    }

                    /* encode path challenge response if required */
                    if (path_x->response_required) {
                        ret = picoquic_prepare_path_response_frame(&bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes, path_x->challenge_response);
                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            path_x->response_required = 0;
                        }
                        else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            ret = 0;
                            next_wake_time = current_time;
                        }
                    }

                    /* If present, send misc frame */
                    while (cnx->first_misc_frame != NULL) {
                        ret = picoquic_prepare_first_misc_frame(cnx, &bytes[length],
                            send_buffer_max - checksum_overhead - length, &data_bytes);
                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            data_bytes = 0;
                        }
                        else {
                            if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                                next_wake_time = current_time;
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
                                length += (uint32_t)data_bytes;
                            }
                            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                ret = 0;
                                next_wake_time = current_time;
                            }
                        }

                        if (packet_type == picoquic_packet_initial && 
                            (cnx->crypto_context[1].aead_encrypt == NULL ||
                                cnx->cnx_state == picoquic_state_client_renegotiate)) {
                            /* Pad to minimum packet length. But don't do that if the
                             * initial packet will be coalesced with 0-RTT packet */
                            while (length < send_buffer_max - checksum_overhead) {
                                bytes[length++] = 0;
                            }
                        }

                        if (packet_type == picoquic_packet_0rtt_protected) {
                            cnx->nb_zero_rtt_sent++;
                        }
                    }

                    /* If stream zero packets are sent, progress the state */
                    if (ret == 0 && tls_ready != 0 && data_bytes > 0 && 
                        cnx->tls_stream[epoch].send_queue == NULL) {
                        switch (cnx->cnx_state) {
                        case picoquic_state_client_init:
                            cnx->cnx_state = picoquic_state_client_init_sent;
                            path_x->next_pacing_time = current_time + 10000;
                            break;
                        case picoquic_state_client_renegotiate:
                            cnx->cnx_state = picoquic_state_client_init_resent;
                            break;
                        case picoquic_state_client_almost_ready:
                            if (cnx->tls_stream[0].send_queue == NULL &&
                                cnx->tls_stream[1].send_queue == NULL &&
                                cnx->tls_stream[2].send_queue == NULL) {
                                cnx->cnx_state = picoquic_state_client_ready;
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
        ret = picoquic_prepare_packet_0rtt(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length);
    }
    else {
        picoquic_finalize_and_protect_packet(cnx, packet,
            ret, length, header_length, checksum_overhead,
            send_length, send_buffer, (uint32_t)send_buffer_max,
            &path_x->remote_cnxid, &path_x->local_cnxid, path_x, current_time);
    }

    if (*send_length > 0) {
        next_wake_time = current_time;
    }

    if (cnx->cnx_state != picoquic_state_draining) {
        picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_wake_time);
    }

    return ret;
}

/* Prepare the next packet to send when in one the server initial states */
int picoquic_prepare_packet_server_init(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    int tls_ready = 0;
    int epoch = 0;
    picoquic_packet_type_enum packet_type = picoquic_packet_initial;
    picoquic_packet_context_enum pc = picoquic_packet_context_initial;
    uint32_t checksum_overhead = 8;
    int is_cleartext_mode = 1;
    size_t data_bytes = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    uint64_t next_wake_time = current_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX;

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
    if (ret == 0 && pc == picoquic_packet_context_handshake) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_max, current_time, &next_wake_time, &header_length);
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

        if (path_x->challenge_verified == 0) {
            if (path_x->challenge_failed == 0) {
                if (path_x->challenge_time + path_x->retransmit_timer <= current_time || path_x->challenge_time == 0) {
                    /* When blocked, repeat the path challenge or wait */
                    if (picoquic_prepare_path_challenge_frame(&bytes[length],
                        send_buffer_max - checksum_overhead - length, &data_bytes, path_x->challenge) == 0) {
                        length += (uint32_t)data_bytes;
                        path_x->challenge_time = current_time;
                        path_x->challenge_repeat_count++;
                    }
                    /* add an ACK just to be nice */
                    if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                        send_buffer_max - checksum_overhead - length, &data_bytes)
                        == 0) {
                        length += (uint32_t)data_bytes;
                    }

                    if (path_x->challenge_repeat_count > PICOQUIC_CHALLENGE_REPEAT_MAX) {
                        if (path_x == cnx->path[0]) {
                            DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                            cnx->cnx_state = picoquic_state_disconnected;
                            if (cnx->callback_fn) {
                                (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                            }
                        }
                        else {
                            DBG_PRINTF("%s\n", "Too many challenge retransmits, abandon path");
                            path_x->challenge_failed = 1;
                        }
                        length = 0;
                    }

                    packet->length = length;
                }
                else if (path_x->challenge_time + path_x->retransmit_timer < next_wake_time) {
                    next_wake_time = path_x->challenge_time + path_x->retransmit_timer;
                }
            }
        }
        else if ((tls_ready != 0 && path_x->cwin > path_x->bytes_in_transit) 
            || cnx->pkt_ctx[pc].ack_needed) {
            if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes)
                == 0) {
                length += (uint32_t)data_bytes;
                data_bytes = 0;
            }

            /* encode path challenge response if required */
            if (path_x->response_required) {
                if (picoquic_prepare_path_response_frame(&bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes, path_x->challenge_response) == 0) {
                    length += (uint32_t)data_bytes;
                    path_x->response_required = 0;
                }
            }

            /* Encode the stream frame */
            ret = picoquic_prepare_crypto_hs_frame(cnx, epoch, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);
            if (ret == 0) {
                length += (uint32_t)data_bytes;
            }
            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                /* todo: reset offset to previous position? */
                ret = 0;
                next_wake_time = current_time;
            }

            /* progress the state if the epoch data is all sent */

            if (ret == 0 && tls_ready != 0 && data_bytes > 0 && cnx->tls_stream[epoch].send_queue == NULL) {
                if (epoch == 2 && picoquic_tls_client_authentication_activated(cnx->quic) == 0) {
                    cnx->cnx_state = picoquic_state_server_ready;
                }
                else {
                    cnx->cnx_state = picoquic_state_server_handshake;
                }
            }

            packet->length = length;

        }
        else  if ((length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, &next_wake_time, packet, send_buffer_max, &is_cleartext_mode, &header_length)) > 0) {
            /* Set the new checksum length */
            checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
            /* Check whether it makes sens to add an ACK at the end of the retransmission */
            ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);
            if (ret == 0) {
                length += (uint32_t)data_bytes;
                packet->length = length;
            }
            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                ret = 0;
                next_wake_time = current_time;
            }
            /* document the send time & overhead */
            packet->send_time = current_time;
            packet->checksum_overhead = checksum_overhead;
        }
        else if (cnx->pkt_ctx[pc].ack_needed) {
            /* when in a handshake mode, send acks asap. */
            length = picoquic_predict_packet_header_length(cnx, packet_type);

            ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                send_buffer_max - checksum_overhead - length, &data_bytes);
            if (ret == 0) {
                length += (uint32_t)data_bytes;
                packet->length = length;
            }
            else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                ret = 0;
                next_wake_time = current_time;
            }
        } else {
            length = 0;
            packet->length = 0;
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, (uint32_t)send_buffer_max,
        &path_x->remote_cnxid, &path_x->local_cnxid, path_x, current_time);

    if (*send_length > 0) {
        next_wake_time = current_time;
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_wake_time);

    return ret;
}

/* Prepare the next packet to send when in one the closing states */
int picoquic_prepare_packet_closing(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    /* TODO: manage multiple streams. */
    picoquic_packet_type_enum packet_type = 0;
    uint32_t checksum_overhead = 8;
    int is_cleartext_mode = 1;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
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
        if (cnx->crypto_context[2].aead_encrypt != NULL) {
            pc = picoquic_packet_context_handshake;
            packet_type = picoquic_packet_handshake;
        }
        else {
            pc = picoquic_packet_context_initial;
            packet_type = picoquic_packet_initial;
        }
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

    if (length == 0) {
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
                length += (uint32_t)consumed;
            }
            cnx->cnx_state = picoquic_state_draining;
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, exit_time);
        }
        else if (ret == 0 && cnx->cnx_state == picoquic_state_closing) {
            /* if more than 3*RTO is elapsed, move to disconnected */
            uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

            if (current_time >= exit_time) {
                cnx->cnx_state = picoquic_state_disconnected;
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
                    }
                    else {
                        ret = picoquic_prepare_connection_close_frame(cnx, bytes + length,
                            send_buffer_max - checksum_overhead - length, &consumed);
                    }
                    if (ret == 0) {
                        length += (uint32_t)consumed;
                    }
                    cnx->pkt_ctx[pc].ack_needed = 0;
                }
                next_time = current_time + delta_t;
                if (next_time > exit_time) {
                    next_time = exit_time;
                }
                picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_time);
            }
        }
        else if (ret == 0 && cnx->cnx_state == picoquic_state_draining) {
            /* Nothing is ever sent in the draining state */
            /* if more than 3*RTO is elapsed, move to disconnected */
            uint64_t exit_time = cnx->latest_progress_time + 3 * path_x->retransmit_timer;

            if (current_time >= exit_time) {
                cnx->cnx_state = picoquic_state_disconnected;
            }
            else {
                picoquic_reinsert_by_wake_time(cnx->quic, cnx, exit_time);
            }
            length = 0;
        }
        else if (ret == 0 && (cnx->cnx_state == picoquic_state_disconnecting || cnx->cnx_state == picoquic_state_handshake_failure)) {
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
                length += (uint32_t)consumed;
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
                length += (uint32_t)consumed;
            }

            if (cnx->cnx_state == picoquic_state_handshake_failure) {
                cnx->cnx_state = picoquic_state_disconnected;
            }
            else {
                cnx->cnx_state = picoquic_state_closing;
            }
            cnx->latest_progress_time = current_time;
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time + delta_t);
            cnx->pkt_ctx[pc].ack_needed = 0;

            if (cnx->callback_fn) {
                (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
            }
        }
        else {
            length = 0;
        }
    }

    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, (uint32_t)send_buffer_max,
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
        *consumed = 0;
    }

    return ret;
}


/*  Prepare the next packet to send when in one the ready states */
int picoquic_prepare_packet_ready(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
    /* TODO: manage multiple streams. */
    picoquic_stream_head* stream = NULL;
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    int tls_ready = 0;
    int is_cleartext_mode = 0;
    int is_pure_ack = 1;
    size_t data_bytes = 0;
    uint32_t header_length = 0;
    uint8_t* bytes = packet->bytes;
    uint32_t length = 0;
    uint32_t checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
    uint32_t send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : (uint32_t)send_buffer_max;
    uint64_t next_wake_time = cnx->latest_progress_time + PICOQUIC_MICROSEC_SILENCE_MAX * (2 - cnx->client_mode);


    /* Verify first that there is no need for retransmit or ack
     * on initial or handshake context. This does not deal with EOED packets,
     * as they are handled from within the general retransmission path */
    if (ret == 0) {
        length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_initial,
            path_x, packet, send_buffer_min_max, current_time, &next_wake_time, &header_length);

        if (length == 0) {
            length = picoquic_prepare_packet_old_context(cnx, picoquic_packet_context_handshake,
                path_x, packet, send_buffer_min_max, current_time, &next_wake_time, &header_length);
        }
    }

    if (length == 0) {
        tls_ready = picoquic_is_tls_stream_ready(cnx);
        stream = picoquic_find_ready_stream(cnx);
        packet->pc = pc;

        if (ret == 0 && 
            (length = picoquic_retransmit_needed(cnx, pc, path_x, current_time, &next_wake_time, packet, send_buffer_min_max, &is_cleartext_mode, &header_length)) > 0) {
            /* Set the new checksum length */
            checksum_overhead = picoquic_get_checksum_length(cnx, is_cleartext_mode);
            /* Check whether it makes sense to add an ACK at the end of the retransmission */
            /* Don't do that if it risks mixing clear text and encrypted ack */
            if (is_cleartext_mode == 0 && packet->ptype != picoquic_packet_0rtt_protected) {
                if (picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                    send_buffer_min_max - checksum_overhead - length, &data_bytes)
                    == 0) {
                    length += (uint32_t)data_bytes;
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
                    /* When blocked, repeat the path challenge or wait */
                    if (picoquic_prepare_path_challenge_frame(&bytes[length],
                        send_buffer_max - checksum_overhead - length, &data_bytes, path_x->challenge) == 0) {
                        length += (uint32_t)data_bytes;
                        path_x->challenge_time = current_time;
                        path_x->challenge_repeat_count++;
                    }

                    /* add an ACK just to be nice */
                    ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                        send_buffer_max - checksum_overhead - length, &data_bytes);
                    if (ret == 0) {
                        length += (uint32_t)data_bytes;
                    }
                    else {
                        if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            next_wake_time = current_time;
                            ret = 0;
                        }
                    }

                    if (path_x->challenge_repeat_count > PICOQUIC_CHALLENGE_REPEAT_MAX) {
                        if (path_x == cnx->path[0]) {
                            DBG_PRINTF("%s\n", "Too many challenge retransmits, disconnect");
                            cnx->cnx_state = picoquic_state_disconnected;
                            if (cnx->callback_fn) {
                                (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
                            }
                        }
                        else {
                            DBG_PRINTF("%s\n", "Too many challenge retransmits, abandon path");
                            path_x->challenge_failed = 1;
                        }
                    }
                }
                else {
                    if (path_x->challenge_time + path_x->retransmit_timer < next_wake_time) {
                        next_wake_time = path_x->challenge_time + path_x->retransmit_timer;
                    }
                }
            }

            if (path_x->response_required) {
                if (picoquic_prepare_path_response_frame(&bytes[length],
                    send_buffer_max - checksum_overhead - length, &data_bytes, path_x->challenge_response) == 0) {
                    length += (uint32_t)data_bytes;
                    path_x->response_required = 0;
                }
            }

            if (cnx->cnx_state != picoquic_state_disconnected && path_x->challenge_verified != 0) {

                if (picoquic_is_ack_needed(cnx, current_time, &next_wake_time, pc)) {
                    ret = picoquic_prepare_ack_frame(cnx, current_time, pc, &bytes[length],
                        send_buffer_min_max - checksum_overhead - length, &data_bytes);
                    if (ret == 0) {
                        length += (uint32_t)data_bytes;
                    }
                    else {
                        if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            next_wake_time = current_time;
                            ret = 0;
                        }
                    }
                }

                if (path_x->cwin < path_x->bytes_in_transit) {
                    uint64_t cwin_time = current_time + path_x->smoothed_rtt;

                    if (cwin_time < next_wake_time) {
                        next_wake_time = cwin_time;
                    }
                } else {
                    /* if present, send tls data */
                    if (tls_ready) {
                        ret = picoquic_prepare_crypto_hs_frame(cnx, 3, &bytes[length],
                            send_buffer_min_max - checksum_overhead - length, &data_bytes);

                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            if (data_bytes > 0)
                            {
                                is_pure_ack = 0;
                            }
                        }
                        else {
                            if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                next_wake_time = current_time;
                                ret = 0;
                            }
                        }
                    }
                    /* If present, send misc frame */
                    while (cnx->first_misc_frame != NULL) {
                        ret = picoquic_prepare_first_misc_frame(cnx, &bytes[length],
                            send_buffer_min_max - checksum_overhead - length, &data_bytes);
                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                        }
                        else {
                            if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                next_wake_time = current_time;
                                ret = 0;
                            }
                            break;
                        }
                    }

                    /* If there are not enough paths, create and advertise */
                    while (ret == 0 && cnx->remote_parameters.migration_disabled == 0 &&
                        cnx->local_parameters.migration_disabled == 0 &&
                        cnx->nb_paths < PICOQUIC_NB_PATH_TARGET) {
                        ret = picoquic_prepare_new_path_and_id(cnx, &bytes[length],
                            send_buffer_min_max - checksum_overhead - length,
                            current_time, &data_bytes);
                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                        }
                        else {
                            if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                                next_wake_time = current_time;
                                ret = 0;
                            }
                            break;
                        }
                    }

                    /* If necessary, encode the max data frame */
                    if (ret == 0 && 2 * cnx->data_received > cnx->maxdata_local) {
                        ret = picoquic_prepare_max_data_frame(cnx, 2 * cnx->data_received, &bytes[length],
                            send_buffer_min_max - checksum_overhead - length, &data_bytes);

                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            if (data_bytes > 0)
                            {
                                is_pure_ack = 0;
                            }
                        }
                        else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            next_wake_time = current_time;
                            ret = 0;
                        }
                    }
                    /* If necessary, encode the max stream data frames */
                    if (ret == 0) {
                        ret = picoquic_prepare_required_max_stream_data_frames(cnx, &bytes[length],
                            send_buffer_min_max - checksum_overhead - length, &data_bytes);

                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            if (data_bytes > 0)
                            {
                                is_pure_ack = 0;
                            }
                        }
                        else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            next_wake_time = current_time;
                            ret = 0;
                        }
                    }

                    /* Encode the stream frame, or frames */
                    while (stream != NULL) {
                        ret = picoquic_prepare_stream_frame(cnx, stream, &bytes[length],
                            send_buffer_min_max - checksum_overhead - length, &data_bytes);

                        if (ret == 0) {
                            length += (uint32_t)data_bytes;
                            if (data_bytes > 0)
                            {
                                is_pure_ack = 0;
                            }

                            if (send_buffer_max > checksum_overhead + length + 8) {
                                stream = picoquic_find_ready_stream(cnx);
                            }
                            else {
                                break;
                            }
                        }
                        else if (ret == PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL) {
                            next_wake_time = current_time;
                            ret = 0;
                            break;
                        }
                    }

                    if (length > header_length) {
                        if ((length + checksum_overhead) <= PICOQUIC_RESET_PACKET_MIN_SIZE) {
                            uint32_t pad_size = PICOQUIC_RESET_PACKET_MIN_SIZE - checksum_overhead - length + 1;
                            for (uint32_t i = 0; i < pad_size; i++) {
                                bytes[length++] = 0;
                            }
                        }
                    }
                    else if (ret == 0 && send_buffer_max > path_x->send_mtu
                        && path_x->cwin > path_x->bytes_in_transit && picoquic_is_mtu_probe_needed(cnx, path_x)) {
                        length = picoquic_prepare_mtu_probe(cnx, path_x, header_length, checksum_overhead, bytes);
                        packet->length = length;
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
                else if (cnx->latest_progress_time + cnx->keep_alive_interval < next_wake_time) {
                    next_wake_time = cnx->latest_progress_time + cnx->keep_alive_interval;
                }
            }
        }
    }
    
    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_min_max,
        &path_x->remote_cnxid, &path_x->local_cnxid, path_x, current_time);

    if (*send_length > 0) {
        next_wake_time = current_time;
    }
    else {
        next_wake_time = picoquic_get_challenge_wake_time(cnx, current_time, next_wake_time);
    }

    /* reset the connection at its new logical position */
    picoquic_reinsert_by_wake_time(cnx->quic, cnx, next_wake_time);

    return ret;
}

/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_segment(picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length)
{
    int ret = 0;
  
    /* Check that the connection is still alive -- the timer is asymmetric, so client will drop faster */
    if ((cnx->cnx_state < picoquic_state_disconnecting && 
        (current_time - cnx->latest_progress_time) >= (PICOQUIC_MICROSEC_SILENCE_MAX*(2 - cnx->client_mode))) ||
        (cnx->cnx_state < picoquic_state_client_ready &&
            current_time >= cnx->start_time + PICOQUIC_MICROSEC_HANDSHAKE_MAX))
    {
        /* Too long silence, break it. */
        cnx->cnx_state = picoquic_state_disconnected;
        ret = PICOQUIC_ERROR_DISCONNECTED;
        if (cnx->callback_fn) {
            (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
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
            ret = picoquic_prepare_packet_client_init(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length);
            break;
        case picoquic_state_server_almost_ready:
        case picoquic_state_server_init:
        case picoquic_state_server_handshake:
            ret = picoquic_prepare_packet_server_init(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length);
            break;
        case picoquic_state_client_ready:
        case picoquic_state_server_ready:
            ret = picoquic_prepare_packet_ready(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length);
            break;
        case picoquic_state_handshake_failure:
        case picoquic_state_disconnecting:
        case picoquic_state_closing_received:
        case picoquic_state_closing:
        case picoquic_state_draining:
            ret = picoquic_prepare_packet_closing(cnx, path_x, packet, current_time, send_buffer, send_buffer_max, send_length);
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
    struct sockaddr ** p_addr_to, int * to_len, struct sockaddr ** p_addr_from, int * from_len)
{
    int ret = 0;

    *send_length = 0;

    if (send_buffer_max < PICOQUIC_INITIAL_MTU_IPV6) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
    } else if (cnx->cnx_state == picoquic_state_client_ready ||
        cnx->cnx_state == picoquic_state_server_ready) 
    {
        picoquic_probe_t * probe = cnx->probe_first;
        picoquic_packet_t * packet = NULL;

        while (probe != NULL) {
            if (!probe->challenge_failed && !probe->challenge_verified &&
                (probe->challenge_required ||
                    current_time >= probe->challenge_time + cnx->path[0]->retransmit_timer)) {
                if (probe->challenge_repeat_count >= PICOQUIC_CHALLENGE_REPEAT_MAX) {
                    probe->challenge_failed = 1;
                } else {
                    break;
                }
            }
            probe = probe->next_probe;
        }

        if (probe != NULL)
        {
            
            packet = picoquic_create_packet();

            if (packet == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            }
            else {
                uint8_t * bytes = packet->bytes;
                uint32_t length = 0;
                uint32_t header_length = 0;
                picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
                picoquic_packet_context_enum pc = picoquic_packet_context_application;
                uint32_t checksum_overhead = picoquic_get_checksum_length(cnx, 0);
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
                    }
                }

                if( inactive_path_index < 0) {
                    ret = picoquic_prepare_new_path_and_id(cnx, &bytes[length],
                        send_buffer_max - checksum_overhead - length,
                        current_time, &data_bytes);
                    if (ret == 0) {
                        length += (uint32_t)data_bytes;
                    }
                }
                else {
                    /* Add a copy of the last created connection ID */
                    ret = picoquic_prepare_new_connection_id_frame(cnx, cnx->path[inactive_path_index], &bytes[length],
                        send_buffer_max - checksum_overhead - length, &data_bytes);
                    if (ret == 0) {
                        length += (uint32_t)data_bytes;
                    }
                }

                if (ret == 0) {
                    /* Format the challenge frame */
                    ret = picoquic_prepare_path_challenge_frame(&bytes[length],
                        send_buffer_max - checksum_overhead - length, &data_bytes, probe->challenge);
                    if (ret == 0) {
                        length += (uint32_t)data_bytes;
                        probe->challenge_required = 0;
                        probe->challenge_time = current_time;
                        probe->challenge_repeat_count++;
                    }
                }

                /* Pack to min length, to verify that the path can carry a min length packet */
                if (length + checksum_overhead < PICOQUIC_INITIAL_MTU_IPV6) {
                    uint32_t pad_size = PICOQUIC_INITIAL_MTU_IPV6 - checksum_overhead - length;
                    memset(&bytes[length], 0, pad_size);
                    length += pad_size;
                }

                /* set the return addresses */
                if (p_addr_to != NULL) {
                    *p_addr_to = (struct sockaddr*)&probe->peer_addr;
                    *to_len = probe->peer_addr_len;
                }

                if (p_addr_from != NULL) {
                    *p_addr_from = (struct sockaddr*)&probe->local_addr;
                    *from_len = probe->local_addr_len;
                }

                /* final protection */
                picoquic_finalize_and_protect_packet(cnx, packet,
                    ret, length, header_length, checksum_overhead,
                    send_length, send_buffer, (uint32_t)send_buffer_max,
                    &probe->remote_cnxid, &cnx->path[0]->local_cnxid, cnx->path[0], current_time);

                /* Keep the connection alive */
                picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time);
            }
        }
    }

    return ret;
}

/* Prepare next packet to send, or nothing.. */
int picoquic_prepare_packet(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr ** p_addr_to, int * to_len, struct sockaddr ** p_addr_from, int * from_len)
{

    int ret = 0;
    picoquic_path_t * path_x = NULL;
    picoquic_packet_t * packet = NULL;
    struct sockaddr * addr_to_log = NULL;

    *send_length = 0;

    /* Remove delete paths */
    picoquic_delete_abandoned_paths(cnx, current_time);

    /* Remove failed probes */
    picoquic_delete_failed_probes(cnx);

    /* If probes are in waiting, send the first one */
    ret = picoquic_prepare_probe(cnx, current_time, send_buffer, send_buffer_max, send_length,
        p_addr_to, to_len, p_addr_from, from_len);

    if (ret == 0 && *send_length == 0) {
        /* Select the path */
        for (int i = 1; i < cnx->nb_paths; i++) {
            if (cnx->path[i]->path_is_demoted) {
                continue;
            } else if (cnx->path[i]->challenge_verified) {
                /* TODO: selection logic if multiple paths are available! */
                /* This path becomes the new default */
                picoquic_promote_path_to_default(cnx, i, current_time);
                path_x = cnx->path[0];
                break;
            }
            else if (path_x == NULL && cnx->path[i]->path_is_activated &&
                (cnx->path[i]->challenge_required &&
                    (cnx->path[i]->challenge_repeat_count == 0 ||
                    current_time >= (cnx->path[i]->challenge_time + cnx->path[i]->retransmit_timer)))) {
                /* will try this path, unless a validated path came in */
                path_x = cnx->path[i];
            }
        }

        if (path_x == NULL) {
            path_x = cnx->path[0];
        }

        if (path_x != NULL) {
            addr_to_log = (struct sockaddr *)&path_x->peer_addr;

            if (p_addr_to != NULL) {
                *p_addr_to = (struct sockaddr *)&path_x->peer_addr;
                *to_len = path_x->peer_addr_len;
            }

            if (p_addr_from != NULL) {
                *p_addr_from = (struct sockaddr *)&path_x->local_addr;
                *from_len = path_x->local_addr_len;
            }
        }


        /* Send the available segments */
        while (ret == 0)
        {
            size_t available = send_buffer_max;
            size_t segment_length = 0;

            if (*send_length > 0) {
                send_buffer_max = (path_x == NULL)? PICOQUIC_INITIAL_MTU_IPV6:path_x->send_mtu;

                if (send_buffer_max < *send_length + PICOQUIC_MIN_SEGMENT_SIZE) {
                    break;
                }
                else {
                    available = send_buffer_max - *send_length;
                }
            }

            packet = picoquic_create_packet();

            if (packet == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
                break;
            }
            else {
                ret = picoquic_prepare_segment(cnx, path_x, packet, current_time,
                    send_buffer + *send_length, available, &segment_length);

                if (ret == 0) {
                    *send_length += segment_length;
                    if (packet->length == 0 ||
                        packet->ptype == picoquic_packet_1rtt_protected) {
                        if (packet->length == 0) {
                            free(packet);
                            packet = NULL;
                        }
                        break;
                    }
                }
                else {
                    free(packet);
                    packet = NULL;

                    if (*send_length != 0) {
                        ret = 0;
                    }
                    break;
                }
            }
        }
    }

    /* if needed, log that the packet is sent */
    if (*send_length > 0 && cnx->quic->F_log != NULL) {
        picoquic_log_packet_address(cnx->quic->F_log,
            picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)),
            cnx, addr_to_log, 0, *send_length, current_time);
    }

    return ret;
}

int picoquic_close(picoquic_cnx_t* cnx, uint16_t reason_code)
{
    int ret = 0;

    if (cnx->cnx_state == picoquic_state_server_ready || cnx->cnx_state == picoquic_state_client_ready) {
        cnx->cnx_state = picoquic_state_disconnecting;
        cnx->application_error = reason_code;
    } else if (cnx->cnx_state < picoquic_state_client_ready) {
        cnx->cnx_state = picoquic_state_handshake_failure;
        cnx->application_error = reason_code;
    } else {
        ret = -1;
    }
    cnx->offending_frame_type = 0;

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}
