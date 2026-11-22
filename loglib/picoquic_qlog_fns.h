/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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

#ifndef PICOQUIC_QLOG_FNS_H
#define PICOQUIC_QLOG_FNS_H
#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include "picoquic.h"

    /* Largest number of path contexts when there is no connection to trim them. */
#define QLOG_FNS_MAX_PATH_CONTEXTS 64

    typedef struct st_qlog_fns_path_context_t {
        struct st_qlog_fns_path_context_t* next;
        uint64_t unique_path_id;
        uint64_t cwin;
        uint64_t rtt_sample;
        uint64_t smoothed_rtt;
        uint64_t rtt_min;
        uint64_t bytes_in_transit;
        uint64_t pacing_packet_time;
        uint64_t cc_state;
        uint64_t cc_param;

        unsigned int last_bw_estimate_path_limited : 1;
    } qlog_fns_path_context_t;


    typedef struct st_qlog_fns_context_t {

        FILE* f_txtlog;      /*!< The file handle of the opened output file. */

        uint32_t version_number;
        const char* cid_name; /*!< Name of the connection, default = initial connection id */
        struct sockaddr_storage addr_peer;
        struct sockaddr_storage addr_local;
        uint8_t ecn_sent;
        uint8_t ecn_received;


        uint64_t start_time;  /*!< Timestamp is very first log event reported. */
        int event_count;
        int packet_count;
        int frame_count;
        picoquic_packet_type_enum packet_type;

        qlog_fns_path_context_t* first_path_ctx;

        unsigned int trace_flow_id : 1;
        unsigned int key_phase_sent_last : 1;
        unsigned int key_phase_sent : 1;
        unsigned int key_phase_received_last : 1;
        unsigned int key_phase_received : 1;
        unsigned int spin_bit_sent_last : 1;
        unsigned int spin_bit_sent : 1;

        int state;
    } qlog_fns_context_t;

    /* Write the separator and the header of an event, and count the event. */
    void qlog_fns_event_start(qlog_fns_context_t* ctx, picoquic_path_t* path_x, uint64_t unique_path_id,
        uint64_t current_time, char const* event_class, char const* event_name);
    /* Log arrival or departure of an UDP datagram on a connection */
    void qlog_fns_pdu(picoquic_cnx_t* cnx, void* log_ctx, int receiving, uint64_t current_time,
        const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length,
        uint64_t unique_path_id, unsigned char ecn);
    /* Write the start of a packet event. qlog_fns_packet_end() closes the event. */
    void qlog_fns_packet_start(qlog_fns_context_t* ctx,
        picoquic_path_t* path_x, uint64_t unique_path_id, int receiving, uint64_t current_time,
        const struct st_picoquic_packet_header_t* ph, uint64_t byte_length);
    void qlog_fns_packet_end(qlog_fns_context_t* ctx);
    /* Write the content of a version negotiation packet or of a retry packet. */
    void qlog_fns_proposed_versions(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max);
    void qlog_fns_retry_token(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max);
    /* Write the congestion control events of a path: the values of cc that
     * differ from the values in the context of the path. If cnx is NULL,
     * the function keeps at most QLOG_FNS_MAX_PATH_CONTEXTS path contexts. */
    void qlog_fns_cc_update(qlog_fns_context_t* ctx, picoquic_cnx_t* cnx, uint64_t unique_path_id,
        uint64_t current_time, const qlog_fns_path_context_t* cc, uint64_t send_mtu);
    /* Free the path contexts. */
    void qlog_fns_delete_path_contexts(qlog_fns_context_t* ctx);
    /* Write an info message event. */
    void qlog_fns_info_message(qlog_fns_context_t* ctx, uint64_t current_time, const uint8_t* message, size_t message_len);
    /* Write the ALPN event: the SNI, the proposed ALPN list and the selected ALPN. */
    void qlog_fns_alpn_update(qlog_fns_context_t* ctx, uint64_t current_time, int is_local,
        uint8_t const* sni, size_t sni_len, uint8_t const* alpn, size_t alpn_len,
        const ptls_iovec_t* alpn_list, size_t alpn_count);
    /* Write the transport parameters event. */
    void qlog_fns_param_update(qlog_fns_context_t* ctx, uint64_t current_time, int is_local,
        uint8_t* params, size_t param_length);
    /* Write bytes as JSON-escaped content, unquoted. */
    void qlog_fns_char_content(FILE* f, const uint8_t* s, uint64_t l);
    /* Write a text and a number, with the same output as
     * fprintf(f, "%s%" PRIu64, text, value) or fprintf(f, "%s%" PRId64, text, value). */
    void qlog_fns_text_uint(FILE* f, const char* text, uint64_t value);
    void qlog_fns_text_int(FILE* f, const char* text, int64_t value);
    /* Write one frame record of a binary log as a qlog frame object. */
    void qlog_binlog_frame(FILE* f, const uint8_t* record, const uint8_t* record_end, int* frame_count);
    /* Write each transport parameter as a field of the current event. The
     * caller checks that tp holds tp_length bytes. */
    void qlog_fns_transport_extensions(FILE* f, uint8_t* tp, size_t tp_length);
    /* Write a packet_lost, packet_dropped or packet_buffered event. */
    void qlog_fns_packet_lost_event(qlog_fns_context_t* ctx, picoquic_path_t* path_x, uint64_t unique_path_id,
        uint64_t current_time, uint64_t ptype, uint64_t sequence_number,
        const uint8_t* trigger, size_t trigger_length, const uint8_t* dcid, size_t dcid_length,
        int has_packet_size, uint64_t packet_size);
    void qlog_fns_packet_dropped_event(qlog_fns_context_t* ctx, picoquic_path_t* path_x, uint64_t unique_path_id,
        uint64_t current_time, uint64_t ptype, uint64_t packet_size, uint64_t err);
    void qlog_fns_packet_buffered_event(qlog_fns_context_t* ctx, picoquic_path_t* path_x, uint64_t unique_path_id,
        uint64_t current_time, uint64_t ptype, const uint8_t* trigger, size_t trigger_length);
    /* Write the header of the qlog file, and the end of the qlog file. */
    void qlog_fns_trace_header(FILE* f, char const* cid_name, const char* mode, uint64_t start_time,
        int trace_flow_id);
    void qlog_fns_trace_end(FILE* f);

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_QLOG_FNS_H */
