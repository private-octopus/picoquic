/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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
* Packet logging.
*/

#include <stdarg.h>
#include "logwriter.h"
#include "bytestream.h"
#include "tls_api.h"
#include "picotls.h"

#define VARINT_LEN(bytes) ((size_t)1 << (((bytes)[0] & 0xC0) >> 6))

static const uint8_t* picoquic_log_fixed_skip(const uint8_t* bytes, const uint8_t* bytes_max, size_t size)
{
    return bytes == NULL ? NULL : ((bytes += size) <= bytes_max ? bytes : NULL);
}

static const uint8_t* picoquic_log_varint_skip(const uint8_t* bytes, const uint8_t* bytes_max)
{
    return bytes == NULL ? NULL : (bytes < bytes_max ? picoquic_log_fixed_skip(bytes, bytes_max, VARINT_LEN(bytes)) : NULL);
}

static const uint8_t* picoquic_log_varint(const uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64)
{
    size_t len = (bytes == NULL) ? 0 : picoquic_varint_decode(bytes, bytes_max - bytes, n64);
    return len == 0 ? NULL : bytes + len;
}

static const uint8_t* picoquic_log_length(const uint8_t* bytes, const uint8_t* bytes_max, size_t* nsz)
{
    uint64_t n64 = 0;
    size_t len = (bytes == NULL) ? 0 : picoquic_varint_decode(bytes, bytes_max - bytes, &n64);
    *nsz = (size_t)n64;
    return len == 0 || *nsz != n64 ? NULL : bytes + len;
}

static void picoquic_binlog_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    if (bytes != NULL && bytes_max != NULL) {
        size_t len = bytes_max - bytes;
        uint8_t varlen[8];
        size_t l_varlen = picoquic_varint_encode(varlen, 8, len);
        fwrite(varlen, 1, l_varlen, f);
        fwrite(bytes, 1, len, f);
    }
}

static const uint8_t* picoquic_log_stream_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint8_t ftype = bytes[0];
    size_t length = 0;
    uint8_t log_buffer[256];
    int has_length = 0;
    size_t extra_bytes = 8;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1); /* type */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* stream */

    if ((ftype & 4) != 0) {
        bytes = picoquic_log_varint_skip(bytes, bytes_max); /* offset */
    }

    if ((ftype & 2) != 0) {
        bytes = picoquic_log_length(bytes, bytes_max, &length); /* length */
        has_length = 1;
    } else {
        length = bytes_max - bytes;
    }

    if (length < extra_bytes) {
        /* Add up to 8 bytes of content that can be documented in the qlog */
        extra_bytes = length;
    }

    if (has_length) {
        picoquic_binlog_frame(f, bytes_begin, bytes + extra_bytes);
    }
    else {
        uint8_t* log_next = log_buffer;
        size_t l_head = bytes - bytes_begin;

        memcpy(log_buffer, bytes_begin, l_head);
        log_next += l_head;
        if ((log_next = picoquic_frames_varint_encode(log_next, log_buffer + 256, length)) != NULL) {
            memcpy(log_next, bytes, extra_bytes);
            log_next += extra_bytes;
            picoquic_binlog_frame(f, log_buffer, log_next);
        }
        else {
            picoquic_binlog_frame(f, log_buffer, log_buffer + l_head);
        }
    }

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    return bytes;
}

static const uint8_t* picoquic_log_ack_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint8_t ftype = bytes[0];
    uint64_t nb_blocks;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);

    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint(bytes, bytes_max, &nb_blocks);

    for (uint64_t i = 0; bytes != NULL && i <= nb_blocks; i++) {
        if (i != 0) {
            bytes = picoquic_log_varint_skip(bytes, bytes_max);
        }
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
    }
    
    if (ftype == picoquic_frame_type_ack_ecn) {
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
        bytes = picoquic_log_varint_skip(bytes, bytes_max);
    }

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_reset_stream_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t * bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_stop_sending_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_close_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_length(bytes, bytes_max, &length);
    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_app_close_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_length(bytes, bytes_max, &length);
    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_max_data_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_max_stream_data_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_max_stream_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_blocked_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_stream_blocked_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_streams_blocked_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_new_connection_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    if (bytes != NULL) {
        bytes = picoquic_log_fixed_skip(bytes, bytes_max, ((size_t)1) + bytes[0]);
    }

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, PICOQUIC_RESET_SECRET_SIZE);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_retire_connection_id_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_new_token_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_length(bytes, bytes_max, &length);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_path_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1 + 8);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_crypto_hs_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);
    bytes = picoquic_log_varint_skip(bytes, bytes_max);
    bytes = picoquic_log_length(bytes, bytes_max, &length);

    picoquic_binlog_frame(f, bytes_begin, bytes);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    return bytes;
}


static const uint8_t* picoquic_log_handshake_done_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);

    picoquic_binlog_frame(f, bytes_begin, bytes);
    return bytes;
}

static const uint8_t* picoquic_log_datagram_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;
    uint8_t ftype = bytes[0];
    size_t length = 0;

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, 1);

    if (ftype & 1) {
        bytes = picoquic_log_length(bytes, bytes_max, &length);
    } else {
        length = bytes_max - bytes;
    }

    picoquic_binlog_frame(f, bytes_begin, bytes);

    bytes = picoquic_log_fixed_skip(bytes, bytes_max, length);
    return bytes;
}

static const uint8_t* picoquic_log_time_stamp_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* frame type as varint */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* time stamp as varint */

    picoquic_binlog_frame(f, bytes_begin, bytes);

    return bytes;
}

static const uint8_t* picoquic_log_ack_frequency_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    const uint8_t* bytes_begin = bytes;

    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* frame type as varint */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Seq num */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Packet tolerance */
    bytes = picoquic_log_varint_skip(bytes, bytes_max); /* Max ACK delay */

    picoquic_binlog_frame(f, bytes_begin, bytes);

    return bytes;
}

static const uint8_t* picoquic_log_erroring_frame(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    size_t frame_size = bytes_max - bytes;
    size_t copied = (frame_size > 8) ? 8 : frame_size;

    picoquic_binlog_frame(f, bytes, bytes + copied);

    return NULL;
}

static const uint8_t* picoquic_log_padding(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    picoquic_binlog_frame(f, bytes, bytes + 1);

    uint8_t ftype = bytes[0];
    while (bytes < bytes_max && bytes[0] == ftype) {
        bytes++;
    }

    return bytes;
}

void picoquic_binlog_frames(FILE * f, const uint8_t* bytes, size_t length)
{
    const uint8_t* bytes_max = bytes + length;

    while (bytes != NULL && bytes < bytes_max) {
        uint64_t ftype= 0;
        size_t ftype_ll = picoquic_varint_decode(bytes, length, &ftype);

        if (ftype_ll == 0) {
            /* Error, incorrect frame type encoding */
            bytes = NULL;
            break;
        }
        else if (ftype < 64 && ftype_ll != 1) {
            /* Error, incorrect frame type encoding */
            bytes = NULL;
            break;
        }

        if (PICOQUIC_IN_RANGE(ftype, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            bytes = picoquic_log_stream_frame(f, bytes, bytes_max);
            continue;
        }

        switch (ftype) {
        case picoquic_frame_type_ack:
        case picoquic_frame_type_ack_ecn:
            bytes = picoquic_log_ack_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_retire_connection_id:
            bytes = picoquic_log_retire_connection_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_padding:
        case picoquic_frame_type_ping:
            bytes = picoquic_log_padding(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_reset_stream:
            bytes = picoquic_log_reset_stream_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_connection_close:
            bytes = picoquic_log_close_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_application_close:
            bytes = picoquic_log_app_close_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_max_data:
            bytes = picoquic_log_max_data_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_max_stream_data:
            bytes = picoquic_log_max_stream_data_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_max_streams_bidir:
        case picoquic_frame_type_max_streams_unidir:
            bytes = picoquic_log_max_stream_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_data_blocked:
            bytes = picoquic_log_blocked_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_stream_data_blocked:
            bytes = picoquic_log_stream_blocked_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_streams_blocked_bidir:
        case picoquic_frame_type_streams_blocked_unidir:
            bytes = picoquic_log_streams_blocked_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_new_connection_id:
            bytes = picoquic_log_new_connection_id_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_stop_sending:
            bytes = picoquic_log_stop_sending_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_path_challenge:
        case picoquic_frame_type_path_response:
            bytes = picoquic_log_path_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_crypto_hs:
            bytes = picoquic_log_crypto_hs_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_new_token:
            bytes = picoquic_log_new_token_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_handshake_done:
            bytes = picoquic_log_handshake_done_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_datagram:
        case picoquic_frame_type_datagram_l:
            bytes = picoquic_log_datagram_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_ack_frequency:
            bytes = picoquic_log_ack_frequency_frame(f, bytes, bytes_max);
            break;
        case picoquic_frame_type_time_stamp:
            bytes = picoquic_log_time_stamp_frame(f, bytes, bytes_max);
            break;
        default:
            bytes = picoquic_log_erroring_frame(f, bytes, bytes_max);
            break;
        }
    }
}

void binlog_pdu(FILE* f, const picoquic_connection_id_t* cid, int receiving, uint64_t current_time,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length)
{
    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    /* Common chunk header */
    bytewrite_cid(msg, cid);
    bytewrite_vint(msg, current_time);
    bytewrite_vint(msg, ((uint64_t)picoquic_log_event_pdu_sent) + receiving);

    /* PDU information */
    bytewrite_addr(msg, addr_peer);
    bytewrite_vint(msg, packet_length);
    bytewrite_addr(msg, addr_local);

    uint8_t head[4] = { 0 };
    picoformat_32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(head, sizeof(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

void binlog_packet(FILE* f, const picoquic_connection_id_t* cid, int receiving, uint64_t current_time,
    const picoquic_packet_header* ph, const uint8_t* bytes, size_t bytes_max)
{
    long fpos0 = ftell(f);

    uint8_t head[4] = { 0 };
    (void)fwrite(head, 4, 1, f);

    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    /* Common chunk header */
    bytewrite_cid(msg, cid);
    bytewrite_vint(msg, current_time);
    bytewrite_vint(msg, ((uint64_t)picoquic_log_event_packet_sent) + receiving);

    /* packet information */
    bytewrite_vint(msg, bytes_max);

    /* packet header */
    bytewrite_int8(msg, (uint8_t)(64*ph->quic_bit_is_zero + 2 * ph->spin + ph->key_phase));
    bytewrite_vint(msg, ph->payload_length);
    bytewrite_vint(msg, ph->ptype);
    bytewrite_vint(msg, ph->pn64);

    bytewrite_cid(msg, &ph->dest_cnx_id);
    bytewrite_cid(msg, &ph->srce_cnx_id);

    if (ph->ptype != picoquic_packet_1rtt_protected &&
        ph->ptype != picoquic_packet_version_negotiation) {
        bytewrite_int32(msg, ph->vn);
    }

    if (ph->ptype == picoquic_packet_initial) {
        bytewrite_vint(msg, ph->token_length);
        bytewrite_buffer(msg, ph->token_bytes, ph->token_length);
    }

    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);

    /* frame information */
    if (ph->ptype == picoquic_packet_version_negotiation || ph->ptype == picoquic_packet_retry) {
        picoquic_binlog_frame(f, bytes + ph->offset, bytes + bytes_max);
    }
    else if (ph->ptype != picoquic_packet_error) {
        picoquic_binlog_frames(f, bytes + ph->offset, ph->payload_length);
    }

    /* re-write chunk size field */
    long fpos1 = ftell(f);

    picoformat_32(head, (uint32_t)(fpos1 - fpos0 - 4));

    (void)fseek(f, fpos0, SEEK_SET);
    (void)fwrite(head, 4, 1, f);
    (void)fseek(f, 0, SEEK_END);
}

void binlog_dropped_packet(picoquic_cnx_t* cnx,
    picoquic_packet_type_enum ptype,  size_t packet_size, int err,
    uint8_t * raw_data, uint64_t current_time)
{
    FILE* f = cnx->f_binlog;
    size_t raw_size = packet_size;
    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    if (err == PICOQUIC_ERROR_AEAD_CHECK) {
        /* Do not log on decryption error, because the buffer was randomized by decryption */
        raw_size = 0;
    } else if (raw_size > 32) {
        raw_size = 32;
    }

    bytewrite_int32(msg, 0);
    bytewrite_cid(msg, &cnx->initial_cnxid);
    bytewrite_vint(msg, current_time);
    bytewrite_vint(msg, picoquic_log_event_packet_dropped);
    bytewrite_vint(msg, ptype);
    bytewrite_vint(msg, packet_size);
    bytewrite_vint(msg, err);
    bytewrite_vint(msg, raw_size);
    (void)bytewrite_buffer(msg, raw_data, raw_size);

    /* write the frame length at the reserved spot, and save to log file*/
    picoformat_32(msg->data, (uint32_t)(msg->ptr - 4));
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

void binlog_buffered_packet(picoquic_cnx_t* cnx,
    picoquic_packet_type_enum ptype, uint64_t current_time)
{
    FILE* f = cnx->f_binlog;
    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    bytewrite_int32(msg, 0);
    bytewrite_cid(msg, &cnx->initial_cnxid);
    bytewrite_vint(msg, current_time);
    bytewrite_vint(msg, picoquic_log_event_packet_buffered);
    bytewrite_vint(msg, ptype);
    (void)bytewrite_cstr(msg, "keys_unavailable");

    /* write the frame length at the reserved spot, and save to log file*/
    picoformat_32(msg->data, (uint32_t)(msg->ptr - 4));
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}


void binlog_outgoing_packet(picoquic_cnx_t* cnx,
    uint8_t * bytes, uint64_t sequence_number, size_t pn_length, size_t length,
    uint8_t* send_buffer, size_t send_length, uint64_t current_time)
{
    FILE* f = cnx->f_binlog;

    picoquic_cnx_t* pcnx = cnx;
    picoquic_packet_header ph;
    size_t checksum_length = 16;
    struct sockaddr_in default_addr;

    const picoquic_connection_id_t * cnxid = (cnx != NULL) ? &cnx->initial_cnxid : &picoquic_null_connection_id;

    memset(&default_addr, 0, sizeof(struct sockaddr_in));
    default_addr.sin_family = AF_INET;

    picoquic_parse_packet_header((cnx == NULL) ? NULL : cnx->quic, send_buffer, send_length,
        ((cnx == NULL || cnx->path[0] == NULL) ? (struct sockaddr *)&default_addr :
        (struct sockaddr *)&cnx->path[0]->local_addr), &ph, &pcnx, 0);

    if (cnx != NULL) {
        picoquic_epoch_enum epoch = (ph.ptype == picoquic_packet_1rtt_protected) ? picoquic_epoch_1rtt :
            ((ph.ptype == picoquic_packet_0rtt_protected) ? picoquic_epoch_0rtt :
            ((ph.ptype == picoquic_packet_handshake) ? picoquic_epoch_handshake : picoquic_epoch_initial));
        if (cnx->crypto_context[epoch].aead_encrypt != NULL) {
            checksum_length = picoquic_get_checksum_length(cnx, epoch);
        }
    }

    ph.pn64 = sequence_number;
    ph.pn = (uint32_t)ph.pn64;
    if (ph.ptype != picoquic_packet_retry) {
        if (ph.pn_offset != 0) {
            ph.offset = ph.pn_offset + pn_length;
            ph.payload_length -= pn_length;
        }
    }
    if (ph.ptype != picoquic_packet_version_negotiation) {
        if (ph.payload_length > checksum_length) {
            ph.payload_length -= (uint16_t)checksum_length;
        }
        else {
            ph.payload_length = 0;
        }
    }

    binlog_packet(f, cnxid, 0, current_time, &ph, bytes, length);
}

void binlog_packet_lost(picoquic_cnx_t* cnx,
    picoquic_packet_type_enum ptype,  uint64_t sequence_number, char const * trigger,
    picoquic_connection_id_t * dcid, size_t packet_size,
    uint64_t current_time)
{
    FILE* f = cnx->f_binlog;

    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);

    bytewrite_int32(msg, 0);
    bytewrite_cid(msg, &cnx->initial_cnxid);
    bytewrite_vint(msg, current_time);
    bytewrite_vint(msg, picoquic_log_event_packet_lost);

    bytewrite_vint(msg, ptype);
    bytewrite_vint(msg, sequence_number);
    bytewrite_cstr(msg, trigger);
    if (dcid != NULL) {
        bytewrite_cid(msg, dcid);
    }
    else {
        bytewrite_int8(msg, 0);
    }
    bytewrite_vint(msg, packet_size);

    /* write the frame length at the reserved spot, and save to log file*/
    picoformat_32(msg->data, (uint32_t)(msg->ptr - 4));
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}


void binlog_transport_extension(picoquic_cnx_t* cnx, int is_local,
    uint8_t const * sni, size_t sni_len, uint8_t const* alpn, size_t alpn_len,
    const ptls_iovec_t* alpn_list, size_t alpn_count,
    size_t param_length, uint8_t * params)
{
    FILE* f = cnx->f_binlog;

    bytestream_buf stream_msg;
    bytestream* msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    bytewrite_cid(msg, &cnx->initial_cnxid);
    bytewrite_vint(msg, picoquic_get_quic_time(cnx->quic));
    bytewrite_vint(msg, picoquic_log_event_param_update);

    bytewrite_vint(msg, is_local);
    bytewrite_vint(msg, sni_len);
    if (sni_len > 0) {
        bytewrite_buffer(msg, sni, sni_len);
    }

    bytewrite_vint(msg, alpn_count);
    if (alpn_count > 0) {
        for (size_t i = 0; i < alpn_count; i++) {
            bytewrite_vint(msg, alpn_list[i].len);
            bytewrite_buffer(msg, alpn_list[i].base, alpn_list[i].len);
        }
    }

    bytewrite_vint(msg, alpn_len);
    if (alpn_len > 0) {
        bytewrite_buffer(msg, alpn, alpn_len);
    }

    bytewrite_vint(msg, param_length);
    if (param_length > 0) {
        bytewrite_buffer(msg, params, param_length);
    }

    bytestream_buf stream_head;
    bytestream* head = bytestream_buf_init(&stream_head, 4);
    bytewrite_int32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(bytestream_data(head), bytestream_length(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

void binlog_picotls_ticket(FILE* f, picoquic_connection_id_t cnx_id,
    uint8_t* ticket, uint16_t ticket_length)
{
    bytestream_buf stream_msg;
    bytestream * msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    bytewrite_cid(msg, &cnx_id);
    bytewrite_vint(msg, 0);
    bytewrite_vint(msg, picoquic_log_event_tls_key_update);

    bytewrite_vint(msg, ticket_length);
    bytewrite_buffer(msg, ticket, ticket_length);

    bytestream_buf stream_head;
    bytestream * head = bytestream_buf_init(&stream_head, 8);
    bytewrite_int32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(bytestream_data(head), bytestream_length(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);
}

FILE* create_binlog(char const* binlog_file, uint64_t creation_time);

void binlog_new_connection(picoquic_cnx_t * cnx)
{
    char const* bin_dir = (cnx->quic->binlog_dir == NULL) ? cnx->quic->qlog_dir : cnx->quic->binlog_dir;
    if (bin_dir == NULL) {
        return;
    }

    int ret = 0;

    cnx->f_binlog = picoquic_file_close(cnx->f_binlog);
    
    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), &cnx->initial_cnxid) != 0) {
        ret = -1;
    }

    char log_filename[512];
    if (ret == 0) {
        if (picoquic_sprintf(log_filename, sizeof(log_filename), NULL, "%s%s%s.%s.log",
            bin_dir, PICOQUIC_FILE_SEPARATOR, cid_name,
            (cnx->client_mode)?"client":"server") != 0) {
            ret = -1;
        }
        else {
            picoquic_string_free(cnx->binlog_file_name);
            cnx->binlog_file_name = picoquic_string_duplicate(log_filename);
        }
    }

    if (ret == 0) {
        cnx->f_binlog = create_binlog(log_filename, picoquic_get_quic_time(cnx->quic));
        if (cnx->f_binlog == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        bytestream_buf stream_msg;
        bytestream * msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
        bytewrite_cid(msg, &cnx->initial_cnxid);
        bytewrite_vint(msg, cnx->start_time);
        bytewrite_vint(msg, picoquic_log_event_new_connection);

        bytewrite_int8(msg, cnx->client_mode != 0);
        bytewrite_int32(msg, cnx->proposed_version);
        bytewrite_cid(msg, &cnx->path[0]->remote_cnxid);

        /* Algorithms used */
        bytewrite_cstr(msg, cnx->congestion_alg->congestion_algorithm_id);
        bytewrite_vint(msg, cnx->spin_policy);

        bytestream_buf stream_head;
        bytestream * head = bytestream_buf_init(&stream_head, 8);
        bytewrite_int32(head, (uint32_t)bytestream_length(msg));

        (void)fwrite(bytestream_data(head), bytestream_length(head), 1, cnx->f_binlog);
        (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, cnx->f_binlog);
    }
}

void binlog_close_connection(picoquic_cnx_t * cnx)
{
    FILE * f = cnx->f_binlog;
    if (f == NULL) {
        return;
    }

    bytestream_buf stream_msg;
    bytestream * msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    bytewrite_cid(msg, &cnx->initial_cnxid);
    bytewrite_vint(msg, picoquic_get_quic_time(cnx->quic));
    bytewrite_vint(msg, picoquic_log_event_connection_close);

    bytestream_buf stream_head;
    bytestream * head = bytestream_buf_init(&stream_head, 8);
    bytewrite_int32(head, (uint32_t)bytestream_length(msg));

    (void)fwrite(bytestream_data(head), bytestream_length(head), 1, f);
    (void)fwrite(bytestream_data(msg), bytestream_length(msg), 1, f);

    fflush(f);

    cnx->f_binlog = picoquic_file_close(cnx->f_binlog);

    if (cnx->quic->qlog_dir != NULL && cnx->quic->autoqlog_fn != NULL) {
        (void)cnx->quic->autoqlog_fn(cnx);
    }
    cnx->binlog_file_name = picoquic_string_free(cnx->binlog_file_name);
}

FILE* create_binlog(char const* binlog_file, uint64_t creation_time)
{
    FILE* f_binlog = picoquic_file_open(binlog_file, "wb");
    if (f_binlog == NULL) {
        DBG_PRINTF("Cannot open file %s for write.\n", binlog_file);
    }
    else {
        /* Write a header text with version identifier and current date  */
        bytestream_buf stream;
        bytestream* ps = bytestream_buf_init(&stream, 16);
        bytewrite_int32(ps, FOURCC('q', 'l', 'o', 'g'));
        bytewrite_int32(ps, 0x01);
        bytewrite_int64(ps, creation_time);

        if (fwrite(bytestream_data(ps), bytestream_length(ps), 1, f_binlog) <= 0) {
            DBG_PRINTF("Cannot write header for file %s.\n", binlog_file);
            f_binlog = picoquic_file_close(f_binlog);
        }
    }

    return f_binlog;
}

/*
 * Log the state of the congestion management, retransmission, etc.
 * Call either just after processing a received packet, or just after
 * sending a packet.
 */

void picoquic_cc_dump(picoquic_cnx_t* cnx, uint64_t current_time)
{
    if (cnx->f_binlog == NULL) {
        return;
    }

    bytestream_buf stream_msg;
    bytestream* ps_msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];
    picoquic_path_t* path = cnx->path[0];

    bytewrite_cid(ps_msg, &cnx->initial_cnxid);
    bytewrite_vint(ps_msg, current_time);
    bytewrite_vint(ps_msg, picoquic_log_event_cc_update);

    bytewrite_vint(ps_msg, cnx->pkt_ctx[picoquic_packet_context_application].send_sequence);

    if (pkt_ctx->highest_acknowledged != (uint64_t)(int64_t)-1) {
        bytewrite_vint(ps_msg, 1);
        bytewrite_vint(ps_msg, pkt_ctx->highest_acknowledged);
        bytewrite_vint(ps_msg, pkt_ctx->highest_acknowledged_time - cnx->start_time);
        bytewrite_vint(ps_msg, pkt_ctx->latest_time_acknowledged - cnx->start_time);
    }
    else {
        bytewrite_vint(ps_msg, 0);
    }

    bytewrite_vint(ps_msg, path->cwin);
    bytewrite_vint(ps_msg, path->one_way_delay_sample);
    bytewrite_vint(ps_msg, path->rtt_sample);
    bytewrite_vint(ps_msg, path->smoothed_rtt);
    bytewrite_vint(ps_msg, path->rtt_min);
    bytewrite_vint(ps_msg, path->bandwidth_estimate);
    bytewrite_vint(ps_msg, path->receive_rate_estimate);
    bytewrite_vint(ps_msg, path->send_mtu);
    bytewrite_vint(ps_msg, path->pacing_packet_time_microsec);
    bytewrite_vint(ps_msg, cnx->nb_retransmission_total);
    bytewrite_vint(ps_msg, cnx->nb_spurious);
    bytewrite_vint(ps_msg, cnx->cwin_blocked);
    bytewrite_vint(ps_msg, cnx->flow_blocked);
    bytewrite_vint(ps_msg, cnx->stream_blocked);

    if (cnx->congestion_alg == NULL) {
        bytewrite_vint(ps_msg, 0);
        bytewrite_vint(ps_msg, 0);
    }
    else {
        uint64_t cc_state;
        uint64_t cc_param;

        cnx->congestion_alg->alg_observe(cnx->path[0], &cc_state, &cc_param);
        bytewrite_vint(ps_msg, cc_state);
        bytewrite_vint(ps_msg, cc_param);
    }

    bytewrite_vint(ps_msg, path->max_bandwidth_estimate);
    bytewrite_vint(ps_msg, path->bytes_in_transit);

    bytestream_buf stream_head;
    bytestream* ps_head = bytestream_buf_init(&stream_head, BYTESTREAM_MAX_BUFFER_SIZE);

    bytewrite_int32(ps_head, (uint32_t)bytestream_length(ps_msg));

    (void)fwrite(bytestream_data(ps_head), bytestream_length(ps_head), 1, cnx->f_binlog);
    (void)fwrite(bytestream_data(ps_msg), bytestream_length(ps_msg), 1, cnx->f_binlog);

    cnx->cwin_blocked = 0;
    cnx->flow_blocked = 0;
    cnx->stream_blocked = 0;
}

/*
 * Write an information message frame, for free form debugging.
 */

void picoquic_binlog_message_v(picoquic_cnx_t* cnx, const char* fmt, va_list vargs)
{
    if (cnx->f_binlog == NULL) {
        return;
    }
    bytestream_buf stream_msg;
    bytestream* ps_msg = bytestream_buf_init(&stream_msg, BYTESTREAM_MAX_BUFFER_SIZE);
    size_t message_len;
    char* message_text;

    bytewrite_cid(ps_msg, &cnx->initial_cnxid);
    bytewrite_vint(ps_msg, picoquic_get_quic_time(cnx->quic));
    bytewrite_vint(ps_msg, picoquic_log_event_info_message);
#ifdef _WINDOWS
    (void)vsprintf_s((char *)(ps_msg->data + ps_msg->ptr), ps_msg->size - ps_msg->ptr, fmt, vargs);
#else
    (void)vsprintf((char*)(ps_msg->data + ps_msg->ptr), fmt, vargs);
#endif
    message_text = (char*)(ps_msg->data + ps_msg->ptr);
    message_len = strlen(message_text);
    for (size_t i = 0; i < message_len; i++) {
        int c = message_text[i];
        if (c < 0x20 || c > 0x7e) {
            message_text[i] = '?';
        }
    }
    ps_msg->ptr += message_len;

    bytestream_buf stream_head;
    bytestream* ps_head = bytestream_buf_init(&stream_head, BYTESTREAM_MAX_BUFFER_SIZE);

    bytewrite_int32(ps_head, (uint32_t)bytestream_length(ps_msg));

    (void)fwrite(bytestream_data(ps_head), bytestream_length(ps_head), 1, cnx->f_binlog);
    (void)fwrite(bytestream_data(ps_msg), bytestream_length(ps_msg), 1, cnx->f_binlog);
}