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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"

/* Helper: Write a JSON key-value pair for an integer */
static void qlog_json_uint(FILE* f, const char* key, uint64_t value) {
    fprintf(f, "\"%s\": %" PRIu64, key, value);
}

/* Helper: Write a JSON key-value pair for a string */
static void qlog_json_str(FILE* f, const char* key, const char* value) {
    fprintf(f, "\"%s\": \"%s\"", key, value);
}

/* Helper: write a binary string parameter */
const uint8_t * qlog_frame_hex_string(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, uint64_t l)
{
    int error_found = (bytes + l > bytes_max);

    fprintf(f, "\"");
    if (error_found) {
        fprintf(f, "... coding error!");
        bytes = NULL;
    }
    else {
        for (uint64_t x = 0; x < l; x++) {
            fprintf(f, "%02x", bytes[x]);
        }
        bytes += l;
    }

    fprintf(f, "\"");
    return bytes;
}


/* QLOG for frames with one parameter */
const uint8_t* qlog_frame_one_param(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, char const * p_name)
{
    uint64_t param_value;
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &param_value)) != NULL) {
        fprintf(f, ", ");
        qlog_json_uint(f, p_name, param_value);
    }
    return bytes;
}

/* QLOG for frames with two parameters */
const uint8_t* qlog_frame_two_params(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, char const* p_name1, char const* p_name2)
{
    uint64_t param_value1;
    uint64_t param_value2;
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &param_value1)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &param_value2)) != NULL) {
        fprintf(f, ", ");
        qlog_json_uint(f, p_name1, param_value1);
        fprintf(f, ", ");
        qlog_json_uint(f, p_name2, param_value2);
    }
    return bytes;
}

const uint8_t* qlog_frame_stream(FILE* f, const uint8_t* first_byte, const uint8_t* bytes_max)
{
    uint64_t stream_id;
    size_t data_length;
    uint64_t offset;
    size_t consumed;
    const uint8_t* bytes = first_byte;
    int fin;
    int ret = picoquic_parse_stream_header(
        first_byte, bytes_max - first_byte, &stream_id, &offset, &data_length, &fin, &consumed);
    if (ret != 0) {
        bytes = NULL;
    }
    else {
        bytes += consumed;
        fprintf(f, ", ");
        qlog_json_uint(f, "stream_id", stream_id);
        fprintf(f, ", ");
        qlog_json_uint(f, "offset", offset);
        fprintf(f, ", ");
        qlog_json_uint(f, "length", data_length);
        fprintf(f, ", ");
        qlog_json_uint(f, "fin", fin);
    }
    return bytes;
}

const uint8_t* qlog_frame_ack(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, int has_path_id, int has_ecn)
{
    uint64_t path_id = 0;
    uint64_t num_block;
    uint64_t largest;
    uint64_t ack_delay;
    size_t   consumed;

    if (picoquic_parse_ack_header(bytes, bytes_max - bytes, &num_block,
        (has_path_id) ? &path_id : NULL,
        &largest, &ack_delay, &consumed,
        0) != 0) {
        bytes = NULL;
    }
    else {
        bytes += consumed;
        /* write the header part */
        if (has_path_id) {
            fprintf(f, ", \"path_id\": %"PRIu64"", path_id);
        }
        fprintf(f, ", \"ack_delay\": %"PRIu64"", ack_delay);
        fprintf(f, ", \"acked_ranges\": [");
        for (uint64_t i = 0; i <= num_block; i++) {
            uint64_t skip = 0;
            int64_t start_range;
            int64_t end_range;
            uint64_t range = 0;

            if ((i != 0 &&
                (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &skip)) == NULL) ||
                (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &range)) == NULL ||
                largest < skip + range) {
                /* error in encoding of range */
                fprintf(f, "[-1, -1]");
                break;
            }
            else {
                if (i != 0) {
                    /* Skip the gap */
                    largest -= skip;
                    fprintf(f, ", ");
                }
                start_range = largest - range;
                end_range = (int64_t)largest;
                fprintf(f, "[%"PRId64", %"PRId64"]", start_range, end_range);
                largest -= range + 1;
            }
        }
        fprintf(f, "]");

        if (has_ecn && bytes != NULL) {
            char const* ecn_name[3] = { "ect0", "ect1", "ce" };
            for (int ecnx = 0; ecnx < 3; ecnx++) {
                uint64_t ecn_v = 0;
                if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &ecn_v)) != NULL) {
                    fprintf(f, ", \"%s\": %"PRIu64, ecn_name[ecnx], ecn_v);
                }
                else {
                    break;
                }
            }
        }
    }
    return bytes;
}

const uint8_t* qlog_frame_reset(FILE * f, const uint8_t * bytes, const uint8_t * bytes_max, int is_at)
{
    uint64_t stream_id;
    uint64_t error_code;
    uint64_t final_size = 0;
    uint64_t reliable_size = 0;

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &stream_id)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &error_code)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &final_size)) != NULL &&
        (is_at == 0 || (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &reliable_size)) != NULL)
        ) {
        fprintf(f, ", ");
        qlog_json_uint(f, "stream_id", stream_id);
        fprintf(f, ", ");
        qlog_json_uint(f, "error_code", error_code);
        fprintf(f, ", ");
        qlog_json_uint(f, "final_size", final_size);
        if (is_at) {
            fprintf(f, ", ");
            qlog_json_uint(f, "reliable_size", reliable_size);
        }
    }
    return bytes;
}

const uint8_t* qlog_frame_connection_close(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, int app_error)
{
    uint64_t error_code;
    uint64_t trigger_frame_type = 0;
    uint64_t reason_length = 0;

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &error_code)) != NULL &&
        (app_error || (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &trigger_frame_type)) != NULL) &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &reason_length)) != NULL) {
        fprintf(f, ", ");
        qlog_json_uint(f, "error_code", error_code);
        if (!app_error) {
            /* Documment the offending frame type */
            char const* trigger_frame_type_name = picoquic_frame_name(trigger_frame_type);
            fprintf(f, ", "); 
            if (strcmp(trigger_frame_type_name, "unknown") == 0) {
                fprintf(f, ", \"trigger_frame_type\": \"%"PRIx64"\"", trigger_frame_type);
            }
            else {
                fprintf(f, ", \"trigger_frame_type\": \"%s\"", trigger_frame_type_name);
            }
        }
        if (reason_length > 0){
            if ((size_t)(bytes_max - bytes) >= reason_length) {
                fprintf(f, ", \"reason\": \"");
                for (uint64_t i = 0; i < reason_length; i++) {
                    int c = (int)bytes[i];

                    if (c < 0x20 || c > 0x7E) {
                        c = '.';
                    }
                    fprintf(f, "%c", c);
                }
                fprintf(f, "\"");
                bytes += reason_length;
            }
            else {
                /* error in encoding of reason phrase */
                fprintf(f, ", \"reason\": \"encoding error\"");
                bytes = NULL;
            }
        }
    }
    return bytes;
}

const uint8_t* qlog_frame_max_streams(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, int is_bidir, int is_blocked)
{
    uint64_t max_streams;
    if (is_bidir){
        qlog_json_str(f, "stream_type", "bidirectional");
    }
    else {
        qlog_json_str(f, "stream_type", "unidirectional");
    }
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &max_streams)) != NULL) {
        fprintf(f, ", ");
        qlog_json_uint(f, (is_blocked)?"limit":"maximum", max_streams);
    }
    return bytes;
}

const uint8_t* picoquic_frame_new_connection_id(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, int has_path_id)
{
    uint64_t path_id = 0;
    uint64_t sequence_number;
    uint64_t retire_prior_to;
    uint8_t cid_length;

    if (has_path_id) {
        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &path_id)) == NULL) {
            return NULL;
        }
        fprintf(f, ", ");
        qlog_json_uint(f, "path_id", path_id);
    }
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &sequence_number)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &retire_prior_to)) == NULL ||
        (bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &cid_length)) == NULL) {
        return NULL;
    }
    fprintf(f, ", ");
    qlog_json_uint(f, "sequence_number", sequence_number);
    fprintf(f, ", ");
    qlog_json_uint(f, "retire_before", retire_prior_to);
    fprintf(f, ", ");
    fprintf(f, "\"connection_id\": ");
    bytes = qlog_frame_hex_string(f, bytes, bytes_max, cid_length);
    if (bytes != NULL) {
        fprintf(f, ",\"stateless_reset_token\": ");
        bytes = qlog_frame_hex_string(f, bytes, bytes_max, 16);
    }
    return bytes;
}

const uint8_t* qlog_frame_crypto_hs(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t offset;
    uint64_t length;

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &offset)) != NULL &&
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &length)) != NULL) {
        fprintf(f, ", ");
        qlog_json_uint(f, "offset", offset);
        fprintf(f, ", ");
        qlog_json_uint(f, "length", length);
        if (bytes + length <= bytes_max) {
            bytes += length;
        }
        else {
            bytes = NULL;
        }
    }
    return bytes;
}

const uint8_t* qlog_frame_new_token(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t token_length;

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &token_length)) != NULL) {
        fprintf(f, ", \"new_token\": ");
        bytes = qlog_frame_hex_string(f, bytes, bytes_max, token_length);
    }
    return bytes;
}

const uint8_t* qlog_frame_path_challenge_response(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    if (bytes + 8 > bytes_max) {
        bytes = NULL;
    }
    else {
        fprintf(f, ", \"data\": ");
        bytes = qlog_frame_hex_string(f, bytes, bytes_max, 8);
    }
    return bytes;
}


const uint8_t* qlog_frame_datagram(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, int has_length)
{

    if (has_length) {
        uint64_t length;
        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &length)) == NULL ||
            bytes + length > bytes_max) {
            return NULL;
        }
        qlog_json_uint(f, "length", length);
        bytes += length;
    }
    else {
        bytes = bytes_max;
    }
    return bytes;
}

const uint8_t* qlog_frame_ack_frequency(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t sequence_number;
    uint64_t packet_tolerance;
    uint64_t max_ack_delay;
    uint8_t ignore_order;
    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &sequence_number)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &packet_tolerance)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &max_ack_delay)) == NULL ||
        (bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &ignore_order)) == NULL) {
        return NULL;
    }
    fprintf(f, ", ");
    qlog_json_uint(f, "sequence_number", sequence_number);
    fprintf(f, ", ");
    qlog_json_uint(f, "packet_tolerance", packet_tolerance);
    fprintf(f, ", ");
    qlog_json_uint(f, "max_ack_delay", max_ack_delay);
    fprintf(f, ", ");
    qlog_json_uint(f, "ignore_order", ignore_order);
    return bytes;
}

void qlog_frame_ip_address(FILE* f, const uint8_t* addr, uint64_t addr_length)
{
    fprintf(f, "\"");
    if (addr_length == 4) {
        /* IPv4 address */
        for (int x = 0; x < 4; x++) {
            if (x != 0) {
                fprintf(f, ".");
            }
            fprintf(f, "%d", addr[x]);
        }
    }
    else if (addr_length == 16) {
        /* IPv6 address */
        for (int x = 0; x < 8; x++) {
            uint16_t w = 0;
            for (int y = 0; y < 2; y++) {
                w <<= 8;
                w += addr[x * 2 + y];
            }
            if (x != 0) {
                fprintf(f, ":");
            }
            fprintf(f, "%x", w);
        }
    }
    else {
        fprintf(f, "invalid address length %" PRIu64, addr_length);
    }
    fprintf(f, "\"");
}

const uint8_t* qlog_frame_bdp(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    uint64_t lifetime;
    uint64_t recon_bytes_in_flight;
    uint64_t recon_min_rtt;
    uint64_t saved_ip_length;
    const uint8_t* saved_ip;

    if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &lifetime)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &recon_bytes_in_flight)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &recon_min_rtt)) == NULL ||
        (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &saved_ip_length)) == NULL ||
        (saved_ip_length != 4 && saved_ip_length != 4) ||
        (bytes + saved_ip_length > bytes_max)) {
        return NULL;
    }
    saved_ip = bytes;
    bytes += saved_ip_length;

    fprintf(f, ", ");
    qlog_json_uint(f, "lifetime", lifetime);
    fprintf(f, ", ");
    qlog_json_uint(f, "recon_bytes_in_flight", recon_bytes_in_flight);
    fprintf(f, ", ");
    qlog_json_uint(f, "recon_min_rtt", recon_min_rtt);
    fprintf(f, ", ");
    fprintf(f, "\"saved_ip\": ");
    qlog_frame_ip_address(f, saved_ip, saved_ip_length);

    return bytes;
}

const uint8_t* qlog_frame_observed_address(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, picoquic_frame_type_enum_t ftype)
{
    uint64_t sequence;
    const uint8_t* addr;
    uint16_t port;

    if ((bytes = picoquic_parse_observed_address_frame(bytes, bytes_max, ftype,
        &sequence, &addr, &port)) != NULL) {
        uint64_t addr_length = (ftype & 1) == 0 ? 4 : 16;
        fprintf(f, ", ");
        qlog_json_uint(f, "sequence", sequence);
        fprintf(f, ", ");
        fprintf(f, "\"address\": ");
        qlog_frame_ip_address(f, addr, addr_length);
        qlog_json_uint(f, "port", port);
    }
    return bytes;
}

void qlog_frames(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max)
{
    int ret = 0;
    char const* comma_if_needed = "";

    while (ret == 0 && bytes != NULL && bytes < bytes_max) {
        const uint8_t* first_byte = bytes;
        uint64_t frame_id;
        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max, &frame_id)) == NULL) {
            break;
        }
        /* Open the logging line for the frame */
        fprintf(f, "%s{ \"frame_type\": \"%s\"", comma_if_needed, picoquic_frame_name(frame_id));
        comma_if_needed = ", ";

        if (PICOQUIC_IN_RANGE(frame_id, picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
            bytes = qlog_frame_stream(f, first_byte, bytes_max);
        }
        else {
            switch (frame_id) {
            case picoquic_frame_type_padding:
                while (bytes < bytes_max && *bytes == picoquic_frame_type_padding) {
                    bytes++;
                }
                break;
            case picoquic_frame_type_ping:
                break;
            case picoquic_frame_type_ack:
                bytes = qlog_frame_ack(f, first_byte, bytes_max, 0, 0);
                break;
            case picoquic_frame_type_ack_ecn:
                bytes = qlog_frame_ack(f, first_byte, bytes_max, 0, 1);
                break;
            case picoquic_frame_type_path_ack:
                bytes = qlog_frame_ack(f, first_byte, bytes_max, 1, 0);
                break;
            case picoquic_frame_type_path_ack_ecn:
                bytes = qlog_frame_ack(f, first_byte, bytes_max, 1, 1);
                break;
            case picoquic_frame_type_reset_stream:
                bytes = qlog_frame_reset(f, bytes, bytes_max, 0);
                break;
            case picoquic_frame_type_reset_stream_at:
                bytes = qlog_frame_reset(f, bytes, bytes_max, 1);
                break;
            case picoquic_frame_type_connection_close:
                bytes = qlog_frame_connection_close(f, bytes, bytes_max, 0);
                break;
            case picoquic_frame_type_application_close:
                bytes = qlog_frame_connection_close(f, bytes, bytes_max, 1);
                break;
            case picoquic_frame_type_max_data:
                bytes = qlog_frame_one_param(f, bytes, bytes_max, "maximum");
                break;
            case picoquic_frame_type_max_stream_data:
                bytes = qlog_frame_two_params(f, bytes, bytes_max, "stream_id", "maximum");
                break;
            case picoquic_frame_type_max_streams_bidir:
                bytes = qlog_frame_max_streams(f, bytes, bytes_max, 1, 0);
                break;
            case picoquic_frame_type_max_streams_unidir:
                bytes = qlog_frame_max_streams(f, bytes, bytes_max, 0, 0);
                break;
            case picoquic_frame_type_data_blocked:
                bytes = qlog_frame_one_param(f, bytes, bytes_max, "limit");
                break;
            case picoquic_frame_type_stream_data_blocked:
                bytes = qlog_frame_two_params(f, bytes, bytes_max, "stream_id", "limit");
                break;
            case picoquic_frame_type_streams_blocked_bidir:
                bytes = qlog_frame_max_streams(f, bytes, bytes_max, 1, 1);
                break;
            case picoquic_frame_type_streams_blocked_unidir:
                bytes = qlog_frame_max_streams(f, bytes, bytes_max, 0, 1);
                break;
            case picoquic_frame_type_new_connection_id:
                bytes = picoquic_frame_new_connection_id(f, bytes, bytes_max, 0);
                break;
            case picoquic_frame_type_path_new_connection_id:
                bytes = picoquic_frame_new_connection_id(f, bytes, bytes_max, 1);
                break;
            case picoquic_frame_type_stop_sending:
                bytes = qlog_frame_two_params(f, bytes, bytes_max, "stream_id", "error_code");
                break;
            case picoquic_frame_type_path_challenge:
                bytes = qlog_frame_path_challenge_response(f, bytes, bytes_max);
                break;
            case picoquic_frame_type_path_response:
                bytes = qlog_frame_path_challenge_response(f, bytes, bytes_max);
                break;
            case picoquic_frame_type_crypto_hs:
                bytes = qlog_frame_crypto_hs(f, bytes, bytes_max);
                break;
            case picoquic_frame_type_new_token:
                bytes = qlog_frame_new_token(f, bytes, bytes_max);
                break;
            case picoquic_frame_type_retire_connection_id:
                bytes = qlog_frame_one_param(f, bytes, bytes_max, "sequence_number");
                break;
            case picoquic_frame_type_path_retire_connection_id:
                bytes = qlog_frame_two_params(f, bytes, bytes_max, "path_id", "sequence_number");
                break;
            case picoquic_frame_type_handshake_done:
                break;
            case picoquic_frame_type_datagram:
                bytes = qlog_frame_datagram(f, bytes, bytes_max, 0);
                break;
            case picoquic_frame_type_datagram_l:
                bytes = qlog_frame_datagram(f, bytes, bytes_max, 1);
                break;
            case picoquic_frame_type_ack_frequency:
                bytes = qlog_frame_ack_frequency(f, bytes, bytes_max);
                break;
            case picoquic_frame_type_immediate_ack:
                break;
            case picoquic_frame_type_time_stamp:
                bytes = qlog_frame_one_param(f, bytes, bytes_max, "time_stamp");
                break;
            case picoquic_frame_type_path_abandon:
                bytes = qlog_frame_two_params(f, bytes, bytes_max, "path_id", "reason");
                break;
            case picoquic_frame_type_path_backup:
                bytes = qlog_frame_two_params(f, bytes, bytes_max, "path_id", "sequence");
                break;
            case picoquic_frame_type_bdp:
                bytes = qlog_frame_bdp(f, bytes, bytes_max);
                break;
            case picoquic_frame_type_max_path_id:
                bytes = qlog_frame_one_param(f, bytes, bytes_max, "max_path_id");
                break;
            case picoquic_frame_type_paths_blocked:
                bytes = qlog_frame_one_param(f, bytes, bytes_max, "max_path_id");
                break;
            case picoquic_frame_type_path_cid_blocked:
                bytes = qlog_frame_two_params(f, bytes, bytes_max, "path_id", "next_sequence_number");
                break;
            case picoquic_frame_type_observed_address_v4:
            case picoquic_frame_type_observed_address_v6:
                bytes = qlog_frame_observed_address(f, bytes, bytes_max, frame_id);
                break;
            default:
                qlog_json_uint(f, "unknown_frame_type", frame_id);
            }
        }
        fprintf(f, "}");
    };
}
