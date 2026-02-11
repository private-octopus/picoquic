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
#include <stdlib.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquic_unified_log.h"
#include "picotls.h"

typedef struct st_qlog_fns_path_context_t {
    struct st_qlog_fns_path_context_t* next;
    uint64_t unique_path_id;
    uint64_t cwin;
    uint64_t rtt_sample;
    uint64_t smoothed_rtt;
    uint64_t rtt_min;
    uint64_t bytes_in_transit;
    uint64_t pacing_packet_time;
    uint64_t smoothed_rtt_for_bug;

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

#define QLOG_DECLARE_CONTEXT(ctx, cnx) qlog_fns_context_t * ctx = (qlog_fns_context_t*)cnx->qlog_ctx

const char* picoquic_packet_type_name(uint64_t ptype);

/* Helper: write a binary string parameter */
const uint8_t* qlog_frame_hex_string(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, uint64_t l);
/* Log the frames of a packet */
void qlog_frames(FILE* f, const uint8_t* bytes, const uint8_t* bytes_max, int skip_padding);

void qlog_fns_trim_path_contexts(qlog_fns_context_t* ctx, picoquic_cnx_t* cnx, qlog_fns_path_context_t* protected)
{
    qlog_fns_path_context_t* path_ctx = ctx->first_path_ctx;
    qlog_fns_path_context_t* prev_ctx = NULL;

    while (path_ctx != NULL && path_ctx != protected) {
        int found = 0;
        for (int i = 0; i < cnx->nb_paths; i++) {
            if (cnx->path[i] != NULL && cnx->path[i]->unique_path_id == path_ctx->unique_path_id) {
                found = 1;
                break;
            }
        }
        if (!found) {
            qlog_fns_path_context_t* next_ctx = path_ctx->next;
            if (prev_ctx != NULL) {
                prev_ctx->next = next_ctx;
            }
            else {
                ctx->first_path_ctx = next_ctx;
            }
            free(path_ctx);
            path_ctx = next_ctx;
        }
        else {
            prev_ctx = path_ctx;
            path_ctx = path_ctx->next;
        }   
    }
}

qlog_fns_path_context_t* qlog_fns_get_path_context(qlog_fns_context_t* ctx, picoquic_cnx_t * cnx, uint64_t unique_path_id)
{
    int nb_ctx = 0;
    qlog_fns_path_context_t* path_ctx = ctx->first_path_ctx;
    qlog_fns_path_context_t* path_ctx_prev = NULL;

    while (path_ctx != NULL) {
        if (path_ctx->unique_path_id == unique_path_id) {
            return path_ctx;
        }
        path_ctx = path_ctx->next;
        nb_ctx++;
    }
    path_ctx_prev = path_ctx;
    path_ctx = (qlog_fns_path_context_t*)malloc(sizeof(qlog_fns_path_context_t));
    if (path_ctx != NULL) {
        memset(path_ctx, 0, sizeof(qlog_fns_path_context_t));
        path_ctx->unique_path_id = unique_path_id;
        path_ctx->pacing_packet_time = 1;
        path_ctx->smoothed_rtt = PICOQUIC_INITIAL_RTT;
        if (path_ctx_prev != NULL) {
            path_ctx_prev->next = path_ctx;
        }
        else {
            ctx->first_path_ctx = path_ctx;
        }
        nb_ctx++;
    }

    if (nb_ctx > cnx->nb_paths) {
        /* Too many paths, try to trim the list */
        qlog_fns_trim_path_contexts(ctx, cnx, path_ctx);
    }

    return path_ctx;
}

/* Helper: log an IP address & port */
static void qlog_fns_log_addr(FILE* f, const struct sockaddr* addr_peer)
{
    if (addr_peer->sa_family == AF_INET) {
        struct sockaddr_in* s4 = (struct sockaddr_in*)addr_peer;
        uint8_t* addr = (uint8_t*)&s4->sin_addr;

        fprintf(f, "\"ip_v4\": \"%d.%d.%d.%d\", \"port_v4\":%d",
            addr[0], addr[1], addr[2], addr[3],
            s4->sin_port);
    }
    else {
        struct sockaddr_in6* s6 = (struct sockaddr_in6*)addr_peer;
        uint8_t* addr = (uint8_t*)&s6->sin6_addr;

        fprintf(f, " \"ip_v6\": \"");
        for (int i = 0; i < 8; i++) {
            if (i != 0) {
                fprintf(f, ":");
            }

            if (addr[2 * i] != 0) {
                fprintf(f, "%x%02x", addr[2 * i], addr[(2 * i) + 1]);
            }
            else {
                fprintf(f, "%x", addr[(2 * i) + 1]);
            }
        }
        fprintf(f, "\", \"port_v6\" :%d", s6->sin6_port);
    }
}

/* Helper: write a character string defined by pointer and length.
* Process the string for compatibility with JSON. */

void qlog_fns_chars(FILE* f, const char * s, uint64_t l)
{
    uint64_t x;

    fprintf(f, "\"");

    for (x = 0; x < l; x++) {
        int c = s[x];
        if (c == '"' || c == '\\') {
            fprintf(f, "\\%c", c);
        }
        else if (c >= ' ' && c < 127) {
            fprintf(f, "%c", c);
        }
        else {
            fprintf(f, "\\%02x", c);
        }
    }

    fprintf(f, "\"");
}


/* Helper: write the event header */

void qlog_fns_event_start(qlog_fns_context_t* ctx, picoquic_path_t* path_x, uint64_t unique_path_id,
     uint64_t current_time, char const * event_class, char const* event_name)
{
    int64_t delta_time = current_time - ctx->start_time;
    FILE* f = ctx->f_txtlog;
    uint64_t path_id = (path_x != NULL) ? path_x->unique_path_id : unique_path_id;

    if (ctx->event_count != 0) {
        fprintf(f, ",\n");
    }
    else {
        fprintf(f, "\n");
    }

    fprintf(f, "[%"PRId64", ", delta_time);
    if (ctx->trace_flow_id) {
        fprintf(f, "%"PRId64", ", path_id);
    }
    fprintf(f, "\"%s\", \"%s\", {", event_class, event_name);

    ctx->event_count++;
}


/* Log an event that cannot be attached to a specific connection */
void qlog_fns_quic_app_message(picoquic_quic_t* quic, const picoquic_connection_id_t* cid, const char* fmt, va_list vargs)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
    UNREFERENCED_PARAMETER(cid);
    UNREFERENCED_PARAMETER(fmt);
    UNREFERENCED_PARAMETER(vargs);
#endif
}

/* Log arrival or departure of an UDP datagram for an unknown connection */
void qlog_fns_quic_pdu(picoquic_quic_t* quic, int receiving, uint64_t current_time, uint64_t cid64,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
    UNREFERENCED_PARAMETER(receiving);
    UNREFERENCED_PARAMETER(current_time);
    UNREFERENCED_PARAMETER(addr_peer);
    UNREFERENCED_PARAMETER(addr_local);
    UNREFERENCED_PARAMETER(packet_length);
#endif
}

/* Log an event relating to a specific connection */
void qlog_fns_app_message(picoquic_cnx_t* cnx, const char* fmt, va_list vargs)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    FILE* f = ctx->f_txtlog;
    char message_text[2048];
    size_t message_len;

    qlog_fns_event_start(ctx, NULL, 0, picoquic_get_quic_time(cnx->quic), "info", "message");
#ifdef _WINDOWS
    size_t written = vsnprintf_s(message_text, sizeof(message_text),
        _TRUNCATE, fmt, vargs);

    message_len = (written < 0) ? sizeof(message_text) : written;
#else
    size_t written = vsnprintf(message_text, sizeof(message_text), fmt, vargs);
    if (written < 0 || written >= sizeof(message_text)) {
        message_len = sizeof(message_text) - 1;
    }
    else {
        message_len = written;
    }
#endif
    for (size_t i = 0; i < message_len; i++) {
        int c = message_text[i];
        if (c < 0x20 || c > 0x7e) {
            message_text[i] = '?';
        }
    }
    fprintf(f, " \"message\": \"");
    fwrite(message_text, message_len, 1, f);
    fprintf(f, "\"}]");
    ctx->event_count++;
}

/* Log arrival or departure of an UDP datagram on a connection */
void qlog_fns_pdu(picoquic_cnx_t* cnx, int receiving, uint64_t current_time,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length,
    uint64_t unique_path_id, unsigned char ecn)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    FILE* f = ctx->f_txtlog;
    int log_ecn = 0;

    qlog_fns_event_start(ctx, NULL, unique_path_id, current_time, "transport",
        (receiving == 0) ? "datagram_sent" : "datagram_received");

    fprintf(f, " \"byte_length\": %" PRIu64, packet_length);

    if (addr_peer->sa_family != 0 &&
        picoquic_compare_addr(addr_peer, (struct sockaddr*)&ctx->addr_peer) != 0) {
        fprintf(f, ", \"%s\" : {", (receiving == 0) ? "addr_to" : "addr_from");
        qlog_fns_log_addr(f, addr_peer);
        fprintf(f, "}");
        picoquic_store_addr(&ctx->addr_peer, addr_peer);
    }

    if (addr_local->sa_family != 0 &&
        picoquic_compare_addr(addr_local, (struct sockaddr*)&ctx->addr_local) != 0) {
        fprintf(f, ", \"%s\" : {", (receiving != 0) ? "addr_to" : "addr_from");
        qlog_fns_log_addr(f, addr_local);
        fprintf(f, "}");
        picoquic_store_addr(&ctx->addr_local, addr_local);
    }

    if (receiving) {
        log_ecn = (ecn != ctx->ecn_received);
        ctx->ecn_received = ecn;
    }
    else {
        log_ecn = (ecn != ctx->ecn_sent);
        ctx->ecn_sent = ecn;
    }
    if (log_ecn) {
        char const* ecn_strings[4] = { "Not-ECT", "ECT(1)", "ECT(0)", "CE" };
        char const* ecn_s = ecn_strings[ecn & 3];
        fprintf(f, ", \"ecn\" : \"%s\"", ecn_s);
    }

    fprintf(f, "}]");
    ctx->event_count++;
}

/* Log a decrypted packet - receiving = 1 if arrival, = 0 if sending */
void qlog_fns_packet_start(qlog_fns_context_t* ctx,
    picoquic_path_t * path_x, int receiving, uint64_t current_time,
    struct st_picoquic_packet_header_t* ph, size_t byte_length)
{
    FILE* f = ctx->f_txtlog;

    if (ph->ptype == picoquic_packet_1rtt_protected && receiving == 0) {
        if (ctx->spin_bit_sent && (ctx->spin_bit_sent_last != ph->spin)) {
            qlog_fns_event_start(ctx, path_x, 0, current_time, "transport", "spin_bit_updated");
            fprintf(f, " \"state\": %s }]", (ph->spin) ? "true" : "false");
        }
        ctx->spin_bit_sent = 1;
        ctx->spin_bit_sent_last = ph->spin;
    }

    qlog_fns_event_start(ctx, path_x, 0, current_time, "transport", (receiving == 0) ? "packet_sent" : "packet_received");

    fprintf(f, " \"packet_type\": \"%s\", \"header\": { \"packet_size\": %"PRIu64, picoquic_packet_type_name(ph->ptype),
        byte_length);

    if (ph->ptype != picoquic_packet_version_negotiation &&
        ph->ptype != picoquic_packet_retry) {
        fprintf(f, ", \"packet_number\": %"PRIu64, ph->pn64);
    }

    if (ph->ptype != picoquic_packet_1rtt_protected) {
        if (ctx->version_number != ph->vn) {
            fprintf(f, ", \"version\": \"%08x\"", ph->vn);
            ctx->version_number = ph->vn;
        }
        if (ph->ptype != picoquic_packet_version_negotiation &&
            ph->ptype != picoquic_packet_retry &&
            ph->ptype != picoquic_packet_error) {
            fprintf(f, ", \"payload_length\": %zu", ph->payload_length);
        }
    }

    if (ph->ptype != picoquic_packet_1rtt_protected && ph->srce_cnx_id.id_len > 0) {
        char scid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
        picoquic_print_connection_id_hexa(scid_name, sizeof(scid_name), &ph->srce_cnx_id);
        fprintf(f, ", \"scid\": \"%s\"", scid_name);
    }

    if (ph->dest_cnx_id.id_len > 0) {
        char dcid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
        picoquic_print_connection_id_hexa(dcid_name, sizeof(dcid_name), &ph->dest_cnx_id);
        fprintf(f, ", \"dcid\": \"%s\"", dcid_name);
    }

    if (ph->ptype == picoquic_packet_initial && ph->token_length > 0) {
        fprintf(f, ", \"token\": ");
        qlog_frame_hex_string(f, ph->token_bytes, ph->token_bytes + ph->token_length, ph->token_length);
    }

    if (ph->ptype == picoquic_packet_1rtt_protected) {
        int need_key_phase = 0;

        if (receiving == 0) {
            need_key_phase = !ctx->key_phase_sent || (ctx->key_phase_sent_last != ph->key_phase);
            ctx->key_phase_sent = 1;
            ctx->key_phase_sent_last = ph->key_phase;
        }
        else {
            need_key_phase = !ctx->key_phase_received || (ctx->key_phase_received_last != ph->key_phase);
            ctx->key_phase_received_last = ph->key_phase;
            ctx->key_phase_received = 1;
        }
        if (need_key_phase) {
            fprintf(f, ", \"key_phase\": %d", ph->key_phase);
        }
    }

    if (ph->quic_bit_is_zero) {
        fprintf(f, ", \"quic_bit\": 0");
    }
}

void qlog_fns_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, int receiving, uint64_t current_time,
    struct st_picoquic_packet_header_t* ph, const uint8_t* bytes, size_t byte_length)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    FILE* f = ctx->f_txtlog;
    
    qlog_fns_packet_start(ctx, path_x, receiving, current_time, ph, byte_length);

    ctx->packet_type = ph->ptype;

    if (ctx->packet_type == picoquic_packet_version_negotiation ||
        ctx->packet_type == picoquic_packet_retry) {
        fprintf(f, " }");
    }
    else {
        /* packet contains frames, print them */
        const uint8_t* bytes_max = bytes + byte_length;
        bytes += ph->offset;
        if (bytes + ph->payload_length < bytes_max) {
            bytes_max = bytes + ph->payload_length;
        }
        fprintf(f, " }, \"frames\": [");
        qlog_frames(f, bytes, bytes_max, ctx->packet_type == picoquic_packet_initial);
        fprintf(f, "]");
    }
    /* end of the packet */
    fprintf(f, "}]");
    ctx->packet_count++;
    ctx->event_count++;
}

/* Report that a packet was dropped due to some error */
void qlog_fns_dropped_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, struct st_picoquic_packet_header_t* ph, size_t packet_size, int err, uint64_t current_time)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    FILE* f = ctx->f_txtlog;
    qlog_fns_event_start(ctx, path_x, 0, current_time, "transport", "packet_dropped");

    if (err != PICOQUIC_ERROR_PADDING_PACKET) {
        fprintf(f, "\n    \"packet_type\" : \"%s\",",
            picoquic_packet_type_name((picoquic_packet_type_enum)ph->ptype));
    }
    fprintf(f, "\n    \"packet_size\" : %" PRIu64, packet_size);
    fprintf(f, ",\n    \"trigger\": \"%s\"", picoquic_error_name(err));
    fprintf(f, "}]");
    ctx->event_count++;
}

/* Report that packet was buffered waiting for decryption */
void qlog_fns_buffered_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_type_enum ptype, uint64_t current_time)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    FILE* f = ctx->f_txtlog;
    qlog_fns_event_start(ctx, path_x, 0, current_time, "transport", "packet_buffered");

    fprintf(f, "\n    \"type\" : \"%s\"", picoquic_packet_type_name(ptype));
    fprintf(f, ",\n    \"trigger\": \"keys_unavailable\"");
    fprintf(f, "}]");

    ctx->event_count++;
}

/* Log that a packet was formatted, ready to be sent. */
void qlog_fns_outgoing_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    uint8_t* bytes, uint64_t sequence_number, size_t pn_length, size_t length,
    uint8_t* send_buffer, size_t send_length, uint64_t current_time)
{
    picoquic_cnx_t* pcnx = cnx;
    picoquic_packet_header ph;
    size_t checksum_length = 16;
    struct sockaddr_in default_addr;

    memset(&default_addr, 0, sizeof(struct sockaddr_in));
    default_addr.sin_family = AF_INET;

    picoquic_parse_packet_header((cnx == NULL) ? NULL : cnx->quic, send_buffer, send_length,
        ((cnx == NULL || cnx->path[0] == NULL) ? (struct sockaddr*)&default_addr :
            (struct sockaddr*)&cnx->path[0]->first_tuple->local_addr), &ph, &pcnx, 0);

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

    qlog_fns_packet(cnx, path_x, 0, current_time,
        &ph, bytes, length);
}

/* Log packet lost events */
void qlog_fns_packet_lost(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_type_enum ptype, uint64_t sequence_number, char const* trigger,
    picoquic_connection_id_t* dcid, size_t packet_size,
    uint64_t current_time){
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    FILE* f = ctx->f_txtlog;
    qlog_fns_event_start(ctx, path_x, 0, current_time, "recovery", "packet_lost");
    fprintf(f, "\n    \"packet_type\" : \"%s\"", 
        picoquic_packet_type_name(ptype));
    fprintf(f, ",\n    \"packet_number\" : %" PRIu64, sequence_number);
    if (trigger != NULL && trigger[0] != 0) {
        fprintf(f, ",\n    \"trigger\": \"%s\"", trigger);
    }
    fprintf(f, ",\n    \"header\": {");
    fprintf(f, "\n        \"packet_type\" : \"%s\"", picoquic_packet_type_name(ptype));
    fprintf(f, ",\n        \"packet_number\" : %" PRIu64, sequence_number);

    if (dcid->id_len > 0) {
        fprintf(f, ",\n        \"dcid\" : ");
        qlog_frame_hex_string(f, dcid->id, dcid->id + dcid->id_len, dcid->id_len);
    }
    fprintf(f, ",\n        \"packet_size\" : %" PRIu64, packet_size);
    fprintf(f, "}}]");
}

/* log negotiated ALPN */
void qlog_fns_negotiated_alpn(picoquic_cnx_t* cnx, int is_local,
    uint8_t const* sni, size_t sni_len, uint8_t const* alpn, size_t alpn_len,
    const ptls_iovec_t* alpn_list, size_t alpn_count)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    FILE* f = ctx->f_txtlog;
    qlog_fns_event_start(ctx, NULL, 0, picoquic_get_quic_time(cnx->quic), "transport", "parameters_set");

    fprintf(f, "\n    \"owner\": \"%s\"", (is_local) ? "local" : "remote");
    if (sni_len > 0) {
        fprintf(f, ",\n    \"sni\": ");
        qlog_fns_chars(f, (const char *)sni, sni_len);
    }

    if (alpn_count > 0) {
        fprintf(f, ",\n    \"proposed_alpn\": [");

        for (size_t i = 0; i < alpn_count; i++) {
            if (i != 0) {
                fprintf(f, ", ");
            }
            qlog_fns_chars(f, (const char *)alpn_list[i].base, alpn_list[i].len);
        }
        fprintf(f, "]");
    }

    if (alpn_len > 0) {
        fprintf(f, ",\n    \"alpn\": ");
        qlog_fns_chars(f, (const char *)alpn, alpn_len);
    }

    fprintf(f, "}]");
}

/* log transport extension -- either formatted by the loacl peer (is_local=1) or received from remote peer */

void qlog_fns_vint_transport_extension(FILE* f, char const* ext_name, const uint8_t * bytes, uint64_t len)
{
    uint64_t val;
    const uint8_t* end_bytes = picoquic_frames_varint_decode(bytes, bytes + len, &val);

    if (end_bytes == NULL || end_bytes != bytes + len) {
        fprintf(f, "\"%s\" : \"invalid\"", ext_name);
    }
    else {
        fprintf(f, "\"%s\" : %" PRIu64, ext_name, val);
    }
}

void qlog_fns_boolean_transport_extension(FILE* f, char const* ext_name, const uint8_t* bytes, uint64_t len)
{
    fprintf(f, "\"%s\" : ", ext_name);
    if (len != 0) {
        (void)qlog_frame_hex_string(f, bytes, bytes + len, len);
    }
    else {
        fprintf(f, "\"\"");
    }
}

void qlog_fns_preferred_address(FILE* f, const uint8_t* bytes, uint64_t len)
{
    uint16_t port4 = 0;
    uint16_t port6 = 0;
    uint64_t cid_len;
    const uint8_t* end_bytes = bytes + len;

    fprintf(f, "\"ip_v4\": \"");
    bytes = qlog_frame_hex_string(f, bytes, end_bytes, 4);
    if (bytes != NULL) {
        bytes = picoquic_frames_uint16_decode(bytes, end_bytes, &port4);
        fprintf(f, "\", \"port_v4\":%d", port4);
    }
    if (bytes != NULL) {
        fprintf(f, ", \"ip_v6\": \"");
        for (int i = 0; i < 8 && bytes != NULL; i++) {
            uint16_t chunk = 0;
            bytes = picoquic_frames_uint16_decode(bytes, end_bytes, &chunk);
            fprintf(f, "%s%x", (i == 0) ? "" : ":", chunk);
        }
    }
    if (bytes != NULL) {
        bytes = picoquic_frames_uint16_decode(bytes, end_bytes, &port6);
        fprintf(f, "\", \"port_v6\" : %d", port6);
    }
    if (bytes != NULL) {
        fprintf(f, ", \"connection_id\": ");
        if ((bytes = picoquic_frames_varint_decode(bytes, end_bytes, &cid_len)) == NULL ||
            cid_len > PICOQUIC_CONNECTION_ID_MAX_SIZE ||
            bytes + cid_len > end_bytes) {
            fprintf(f, "\"invalid\"");
        }
        else {
            bytes = qlog_frame_hex_string(f, bytes, end_bytes, cid_len);
        }
    }
    if (bytes != NULL) {
        fprintf(f, ", \"stateless_reset_token\": ");
        bytes = qlog_frame_hex_string(f, bytes, end_bytes, 16);
    }
    if (bytes != NULL && bytes < end_bytes) {
        fprintf(f, "\", \"extra_bytes\": ");
        bytes = qlog_frame_hex_string(f, bytes, end_bytes, end_bytes - bytes);
    }
}

void qlog_fns_tp_version_negotiation(FILE* f, const uint8_t* bytes, uint64_t len)
{
    const uint8_t* end_bytes = bytes + len;
    if ((len & 3) != 0 || len == 0) {
        fprintf(f, "\"bad_length\": \"%" PRIu64, len);
    }
    else {
        fprintf(f, "\"chosen\": ");
        bytes = qlog_frame_hex_string(f, bytes, end_bytes, 4);
        if (bytes < end_bytes) {
            int is_first = 1;
            fprintf(f, ", \"others\": [");
            do {
                fprintf(f, "%s", (is_first) ? "" : ",");
                is_first = 0;
                bytes = qlog_frame_hex_string(f, bytes, end_bytes, 4);
            } while (bytes != NULL && bytes < end_bytes);
            fprintf(f, "]");
        }
    }
    fprintf(f, "}");
}

void qlog_fns_transport_extensions(FILE* f, uint8_t* tp, size_t tp_length)
{
    const uint8_t* bytes = tp;
    const uint8_t* bytes_max = bytes + tp_length;


    while (bytes != NULL && bytes < bytes_max) {
        uint64_t extension_type = UINT64_MAX;
        uint64_t extension_length = 0;
        const uint8_t* current_bytes = bytes;

        fprintf(f, ",\n    ");
        /* Read type and length */
        if ((bytes = picoquic_frames_varint_decode(bytes, bytes_max,&extension_type)) == NULL ||
            (bytes = picoquic_frames_varint_decode(bytes, bytes_max, &extension_length)) == NULL ||
            bytes + extension_length > bytes_max) {
            /* Write a meaningful error report */
            uint64_t l = (uint64_t)(bytes_max - current_bytes);
            fprintf(f, "\"Parameter_coding_error\": ");
            (void)qlog_frame_hex_string(f, current_bytes, bytes_max, l);
            break;
        }
        else {
            switch ((picoquic_tp_enum)extension_type) {
            case picoquic_tp_initial_max_stream_data_bidi_local:
            case picoquic_tp_initial_max_stream_data_bidi_remote:
            case picoquic_tp_initial_max_stream_data_uni:
            case picoquic_tp_initial_max_data:
            case picoquic_tp_initial_max_streams_bidi:
            case picoquic_tp_idle_timeout:
            case picoquic_tp_max_packet_size:
            case picoquic_tp_ack_delay_exponent:
            case picoquic_tp_initial_max_streams_uni:
            case picoquic_tp_max_ack_delay:
            case picoquic_tp_active_connection_id_limit:
            case picoquic_tp_max_datagram_frame_size:
            case picoquic_tp_enable_loss_bit:
            case picoquic_tp_min_ack_delay:
            case picoquic_tp_enable_bdp_frame:
            case picoquic_tp_initial_max_path_id:
            case picoquic_tp_address_discovery:
            case picoquic_tp_reset_stream_at:
                qlog_fns_vint_transport_extension(f, picoquic_tp_name(extension_type), bytes, extension_length);
                break;
            case picoquic_tp_stateless_reset_token:
            case picoquic_tp_original_connection_id:
            case picoquic_tp_retry_connection_id:
            case picoquic_tp_handshake_connection_id:
                fprintf(f, "\"%s\": ", picoquic_tp_name(extension_type));
                (void) qlog_frame_hex_string(f, bytes, bytes_max, extension_length);
                break;
            case picoquic_tp_server_preferred_address:
                fprintf(f, "\"%s\": ", picoquic_tp_name(extension_type));
                qlog_fns_preferred_address(f, bytes, extension_length);
                fprintf(f, "}");
                break;
            case picoquic_tp_disable_migration:
            case picoquic_tp_enable_time_stamp:
            case picoquic_tp_grease_quic_bit:
                qlog_fns_boolean_transport_extension(f, picoquic_tp_name((picoquic_tp_enum)extension_type), bytes, extension_length);
                break;
            case picoquic_tp_version_negotiation:
                fprintf(f, "\"%s\": ", picoquic_tp_name(extension_type));
                qlog_fns_tp_version_negotiation(f, bytes, extension_length);
                break;
            default:
                /* dump unknown extensions */
                fprintf(f, "\"%" PRIx64 "\": ", extension_type);
                (void)qlog_frame_hex_string(f, bytes, bytes_max, extension_length);
                break;
            }
            bytes += extension_length;
        }
    }
}

void qlog_fns_transport_extension(picoquic_cnx_t* cnx, int is_local,
    size_t param_length, uint8_t* params)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    FILE* f = ctx->f_txtlog;
    qlog_fns_event_start(ctx, NULL, 0, picoquic_get_quic_time(cnx->quic), "transport", "parameters_set");

    fprintf(f, "\n    \"owner\": \"%s\"", (is_local) ? "local" : "remote");

    qlog_fns_transport_extensions(f, params, param_length);

    fprintf(f, "}]");

    ctx->event_count++;
}

/* log TLS ticket */
void qlog_fns_tls_ticket(picoquic_cnx_t* cnx,
    uint8_t* ticket, uint16_t ticket_length)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx);
    UNREFERENCED_PARAMETER(ticket);
    UNREFERENCED_PARAMETER(ticket_length);
#endif
}

/* log congestion control parameters
* The congestion control is per path. 
* We get an event per path id. If multipath is not enabled, only path[0] is logged.
*/
void qlog_fns_cc_dump_path(picoquic_cnx_t* cnx, picoquic_path_t* path, picoquic_packet_context_t* pkt_ctx, 
    qlog_fns_context_t * ctx, qlog_fns_path_context_t * path_ctx,  uint64_t current_time)
{
    FILE* f = ctx->f_txtlog;
    /* TODO: manage the path_ctx values! Create new paths? */

    if (path->cwin != path_ctx->cwin || path->rtt_sample != path_ctx->rtt_sample ||
#if 1
        /* Bug compatibility with first implementation */
#else
        path->smoothed_rtt != path_ctx->smoothed_rtt ||
#endif
            path->rtt_min != path_ctx->rtt_min || path->bytes_in_transit != path_ctx->bytes_in_transit ||
            path->pacing.packet_time_microsec != path_ctx->pacing_packet_time
#if 1
        /* Bug compatibility with first implementation */
#else
        ||
            path->last_bw_estimate_path_limited != path_ctx->last_bw_estimate_path_limited
#endif
        ) {
        /* Something changed. Report the event. */
        char* comma = "";

        qlog_fns_event_start(ctx, path, 0, current_time, "recovery", "metrics_updated");

        if (path->cwin != path_ctx->cwin) {
            fprintf(f, "%s\"cwnd\": %" PRIu64, comma, path->cwin);
            path_ctx->cwin = path->cwin;
            comma = ",";
        }

        if (path->pacing.packet_time_microsec != path_ctx->pacing_packet_time && path->pacing.packet_time_microsec > 0) {
            double bps = ((double)path->send_mtu * 8) * 1000000.0 / path->pacing.packet_time_microsec;
            uint64_t bits_per_second = (uint64_t)bps;
            fprintf(f, "%s\"pacing_rate\": %" PRIu64, comma, bits_per_second);
            path_ctx->pacing_packet_time = path->pacing.packet_time_microsec;
            comma = ",";
        }

        if (path->bytes_in_transit != path_ctx->bytes_in_transit) {
            fprintf(f, "%s\"bytes_in_flight\": %" PRIu64, comma, path->bytes_in_transit);
            path_ctx->bytes_in_transit = path->bytes_in_transit;
            comma = ",";
        }

        if (path->smoothed_rtt != path_ctx->smoothed_rtt) {
            fprintf(f, "%s\"smoothed_rtt\": %" PRIu64, comma, path->smoothed_rtt);
#if 1
            path_ctx->smoothed_rtt_for_bug = path->smoothed_rtt;
#else
            /* Bug compatibility with first implementation */
            path_ctx->smoothed_rtt = path->smoothed_rtt;
#endif
            comma = ",";
        }

        if (path->rtt_min != path_ctx->rtt_min) {
            fprintf(f, "%s\"min_rtt\": %" PRIu64, comma, path->rtt_min);
            path_ctx->rtt_min = path->rtt_min;
            comma = ",";
        }

        if (path->rtt_sample != path_ctx->rtt_sample) {
            fprintf(f, "%s\"latest_rtt\": %" PRIu64, comma, path->rtt_sample);
            path_ctx->rtt_sample = path->rtt_sample;
            comma = ",";
        }

        if (path->last_bw_estimate_path_limited != path_ctx->last_bw_estimate_path_limited) {
            fprintf(f, "%s\"app_limited\": %u", comma, path->last_bw_estimate_path_limited);
            path_ctx->last_bw_estimate_path_limited = path->last_bw_estimate_path_limited;
            /* comma = ","; (not useful since last block of function) */
        }

        fprintf(f, "}]");
        ctx->event_count++;
    }
}

void qlog_fns_cc_dump(picoquic_cnx_t* cnx, uint64_t current_time)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;

    for (int path_index = 0; path_index < cnx->nb_paths; path_index++)
    {
        picoquic_path_t* path = cnx->path[path_index];
        if (!path->is_cc_data_updated) {
            continue;
        }
        else {
            qlog_fns_path_context_t* path_ctx = qlog_fns_get_path_context(ctx, cnx,
#if 1
                /* Bug compatibility with first version */
                cnx->path[0]->unique_path_id
#else
                path->unique_path_id
#endif
            );
            picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];
            if (cnx->is_multipath_enabled) {
                pkt_ctx = &cnx->path[path_index]->pkt_ctx;
            }
            if (path_ctx != NULL) {
                qlog_fns_cc_dump_path(cnx, path, pkt_ctx, ctx, path_ctx, current_time);
            }
            path->is_cc_data_updated = 0;
#if 1
            /* Bug compatibility with first implementation */
            break;
#endif
        }
    }
}


/* log the start of a connection */
int qlog_fns_set_file_name(picoquic_cnx_t* cnx, char* log_filename, size_t length,
    char * cid_name, size_t cid_name_size)
{
    int ret = 0;
    int sprintf_ret = -1;

    if (picoquic_print_connection_id_hexa(cid_name, cid_name_size, &cnx->initial_cnxid) != 0) {
        ret = -1;
    }
    else
    {
        if (cnx->quic->use_unique_log_names) {
            sprintf_ret = picoquic_sprintf(log_filename, length, NULL, "%s%s%s.%x.%s.qlog",
                cnx->quic->qlog_dir, PICOQUIC_FILE_SEPARATOR, cid_name, cnx->log_unique,
                (cnx->client_mode) ? "client" : "server");
        }
        else {
            sprintf_ret = picoquic_sprintf(log_filename, length, NULL, "%s%s%s.%s.qlog",
                cnx->quic->qlog_dir, PICOQUIC_FILE_SEPARATOR, cid_name,
                (cnx->client_mode) ? "client" : "server");
        }

        if (sprintf_ret != 0) {
            ret = -1;
        }
    }
    return ret;
}

void qlog_fns_start_connection_log(picoquic_cnx_t* cnx, char const * cid_name)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    FILE* f = ctx->f_txtlog;

    fprintf(f, "{ \"qlog_version\": \"draft-00\", \"title\": \"picoquic\", \"traces\": [\n");
    fprintf(f, "{ \"vantage_point\": { \"name\": \"backend-67\", \"type\": \"%s\" },\n",
        cnx->client_mode ? "client" : "server");
    fprintf(f, "\"title\": \"picoquic\", \"description\": \"%s\",", cid_name);
    if (ctx->trace_flow_id) {
        fprintf(f, "\"event_fields\": [\"relative_time\", \"path_id\", \"category\", \"event\", \"data\"],\n");
    }
    else {
        fprintf(f, "\"event_fields\": [\"relative_time\", \"category\", \"event\", \"data\"],\n");
    }
    fprintf(f, "\"configuration\": {\"time_units\": \"us\"},\n");
    fprintf(f, "\"common_fields\": { \"protocol_type\": \"QUIC_HTTP3\", \"reference_time\": \"%"PRIu64"\"},\n",
        cnx->start_time);
    fprintf(f, "\"events\": [");
    ctx->state = 1;
}

void qlog_fns_new_connection(picoquic_cnx_t* cnx)
{
    qlog_fns_context_t* ctx = NULL;
    char log_filename[512];
    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];

    /* Verify that we have enough resource */
    if (cnx->quic->qlog_dir == NULL ||
        cnx->qlog_ctx != NULL ||
        cnx->quic->current_number_of_open_logs >= cnx->quic->max_simultaneous_logs ||
        (ctx = (qlog_fns_context_t*)malloc(sizeof(qlog_fns_context_t))) == NULL) {
        return;
    }
    /* Initialize */
    memset(ctx, 0, sizeof(qlog_fns_context_t));
    ctx->start_time = cnx->start_time;
    ctx->trace_flow_id = cnx->local_parameters.initial_max_path_id > 0;
    /* Try to create the log. */
    if (qlog_fns_set_file_name(cnx, log_filename, sizeof(log_filename),
        cid_name, sizeof(cid_name)) != 0 ||
        (ctx->f_txtlog = picoquic_file_open(log_filename, "w")) == NULL) {
        free(ctx);
        return;
    }
    /* Log the connection creation event */
    cnx->qlog_ctx = ctx;
    qlog_fns_start_connection_log(cnx, cid_name);
}

/* log the end of a connection */
void qlog_fns_close_connection(picoquic_cnx_t* cnx)
{
    qlog_fns_context_t* ctx = (qlog_fns_context_t*)cnx->qlog_ctx;
    qlog_fns_path_context_t* path_ctx = ctx->first_path_ctx;
    FILE* f = ctx->f_txtlog;
    fprintf(f, "]}]}\n");
    picoquic_file_close(f);
    ctx->f_txtlog = NULL;
    /* free the context */
    while (path_ctx != NULL) {
        qlog_fns_path_context_t* next = path_ctx->next;
        free(path_ctx);
        path_ctx = next;
    }
    free(ctx);
}

/* close resource allocated for logging in QUIC context */
void qlog_fns_quic_close(picoquic_quic_t* quic)
{
    /* nothing to do, since the connection close function will free the context */
    (void)quic;
}

picoquic_unified_logging_t qlog_fns = {
    /* Per context log function */
    qlog_fns_quic_app_message,
    qlog_fns_quic_pdu,
    qlog_fns_quic_close,
    /* Per connection functions */
    qlog_fns_app_message,
    qlog_fns_pdu,
    qlog_fns_packet,
    qlog_fns_dropped_packet,
    qlog_fns_buffered_packet,
    qlog_fns_outgoing_packet,
    qlog_fns_packet_lost,
    qlog_fns_negotiated_alpn,
    qlog_fns_transport_extension,
    qlog_fns_tls_ticket,
    qlog_fns_new_connection,
    qlog_fns_close_connection,
    qlog_fns_cc_dump
};

void picoquic_fns_set_qlog(picoquic_quic_t* quic, char const* qlog_dir)
{
    quic->qlog_fns = &qlog_fns;
    quic->qlog_dir = picoquic_string_free(quic->qlog_dir);
    quic->qlog_dir = picoquic_string_duplicate(qlog_dir);
}