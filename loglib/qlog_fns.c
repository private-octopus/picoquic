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
#include "picoquic_unified_log.h"

typedef struct st_qlog_fns_path_context_t {
    uint64_t cwin;
    uint64_t rtt_sample;
    uint64_t smoothed_rtt;
    uint64_t rtt_min;
    uint64_t bytes_in_transit;
    int64_t packet_time_nanosec;

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

    qlog_fns_path_context_t** qlog_path_ctx;
    int nb_paths;

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

/* Helper: write the event header */
void qlog_fns_event_header(FILE* f, qlog_fns_context_t* ctx, int64_t delta_time, uint64_t path_id, char const* event_class, char const* event_name)
{
    fprintf(f, "[%"PRId64", ", delta_time);
    if (ctx->trace_flow_id) {
        fprintf(f, "%"PRId64", ", path_id);
    }
    fprintf(f, "\"%s\", \"%s\", {", event_class, event_name);
}


/* Log an event that cannot be attached to a specific connection */
void qlog_fns_quic_app_message(picoquic_quic_t* quic, const picoquic_connection_id_t* cid, const char* fmt, va_list vargs){}

/* Log arrival or departure of an UDP datagram for an unknown connection */
void qlog_fns_quic_pdu(picoquic_quic_t* quic, int receiving, uint64_t current_time, uint64_t cid64,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length){}

/* Log an event relating to a specific connection */
void qlog_fns_app_message(picoquic_cnx_t* cnx, const char* fmt, va_list vargs){}

/* Log arrival or departure of an UDP datagram on a connection */
void qlog_fns_pdu(picoquic_cnx_t* cnx, int receiving, uint64_t current_time,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length,
    uint64_t unique_path_id, unsigned char ecn){}

/* Log a decrypted packet - receiving = 1 if arrival, = 0 if sending */
void qlog_fns_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, int receiving, uint64_t current_time,
    struct st_picoquic_packet_header_t* ph, const uint8_t* bytes, size_t bytes_max){}

/* Report that a packet was dropped due to some error */
void qlog_fns_dropped_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, struct st_picoquic_packet_header_t* ph, size_t packet_size, int err, uint64_t current_time){}

/* Report that packet was buffered waiting for decryption */
void qlog_fns_buffered_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_type_enum ptype, uint64_t current_time){}

/* Log that a packet was formatted, ready to be sent. */
void qlog_fns_outgoing_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    uint8_t* bytes, uint64_t sequence_number, size_t pn_length, size_t length,
    uint8_t* send_buffer, size_t send_length, uint64_t current_time){}

/* Log packet lost events */
void qlog_fns_packet_lost(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_type_enum ptype, uint64_t sequence_number, char const* trigger,
    picoquic_connection_id_t* dcid, size_t packet_size,
    uint64_t current_time){}

/* log negotiated ALPN */
void qlog_fns_negotiated_alpn(picoquic_cnx_t* cnx, int is_local,
    uint8_t const* sni, size_t sni_len, uint8_t const* alpn, size_t alpn_len,
    const ptls_iovec_t* alpn_list, size_t alpn_count){}

/* log transport extension -- either formatted by the loacl peer (is_local=1) or received from remote peer */
void qlog_fns_transport_extension(picoquic_cnx_t* cnx, int is_local,
    size_t param_length, uint8_t* params){}

/* log TLS ticket */
void qlog_fns_tls_ticket(picoquic_cnx_t* cnx,
    uint8_t* ticket, uint16_t ticket_length){}

/* log the start of a connection */
void qlog_fns_new_connection(picoquic_cnx_t* cnx){}
/* log the end of a connection */
void qlog_fns_close_connection(picoquic_cnx_t* cnx){}

/* log congestion control parameters
* The congestion control is per path. 
* We get an event per path id. If multipath is not enabled, only path[0] is logged.
*/

void qlog_fns_cc_dump_path(picoquic_cnx_t* cnx, picoquic_path_t* path, picoquic_packet_context_t* pkt_ctx, 
    qlog_fns_context_t * ctx, qlog_fns_path_context_t * path_ctx,  uint64_t current_time)
{
    FILE* f = ctx->f_txtlog;

    if (path->cwin != path_ctx->cwin || path->rtt_sample != path_ctx->rtt_sample || path->smoothed_rtt != path_ctx->smoothed_rtt ||
            path->rtt_min != path_ctx->rtt_min || path->bytes_in_transit != path_ctx->bytes_in_transit ||
            path->pacing.packet_time_nanosec != path_ctx->packet_time_nanosec ||
            path->last_bw_estimate_path_limited != path_ctx->last_bw_estimate_path_limited
        ) {
        /* Something changed. Report the event. */
        int64_t delta_time = current_time - ctx->start_time;
        char* comma = "";

        if (ctx->event_count != 0) {
            fprintf(f, ",\n");
        }
        else {
            fprintf(f, "\n");
        }

        qlog_fns_event_header(f, ctx, delta_time, path->unique_path_id, "recovery", "metrics_updated");

        if (path->cwin != path_ctx->cwin) {
            fprintf(f, "%s\"cwnd\": %" PRIu64, comma, path->cwin);
            path_ctx->cwin = path->cwin;
            comma = ",";
        }

        if (path->pacing.packet_time_nanosec != path_ctx->packet_time_nanosec && path->pacing.packet_time_nanosec > 0) {
            double bps = ((double)path->send_mtu * 8) * 1000000000.0 / path->pacing.packet_time_nanosec;
            uint64_t bits_per_second = (uint64_t)bps;
            fprintf(f, "%s\"pacing_rate\": %" PRIu64, comma, bits_per_second);
            path_ctx->packet_time_nanosec = path->pacing.packet_time_nanosec;
            comma = ",";
        }

        if (path->bytes_in_transit != path_ctx->bytes_in_transit) {
            fprintf(f, "%s\"bytes_in_flight\": %" PRIu64, comma, path->bytes_in_transit);
            path_ctx->bytes_in_transit = path->bytes_in_transit;
            comma = ",";
        }

        if (path->smoothed_rtt != path_ctx->smoothed_rtt) {
            fprintf(f, "%s\"smoothed_rtt\": %" PRIu64, comma, path->smoothed_rtt);
            path_ctx->smoothed_rtt = path->smoothed_rtt;
            comma = ",";
        }

        if (path->rtt_min != path_ctx->rtt_min) {
            fprintf(f, "%s\"rtt_min\": %" PRIu64, comma, path->rtt_min);
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
            path_ctx->last_bw_estimate_path_limited = (path_ctx->last_bw_estimate_path_limited != 0);
            /* comma = ","; (not useful since last block of function) */
        }

        fprintf(f, "}]");
        ctx->event_count++;
    }
}

void qlog_fns_cc_dump(picoquic_cnx_t* cnx, uint64_t current_time)
{
    QLOG_DECLARE_CONTEXT(ctx, cnx);
    picoquic_path_t* path = cnx->path[0];
    picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[picoquic_packet_context_application];
    qlog_fns_path_context_t* path_ctx = ctx->qlog_path_ctx[0];

    if (cnx->is_multipath_enabled) {
        pkt_ctx = &cnx->path[0]->pkt_ctx;
    }

    qlog_fns_cc_dump_path(cnx, path, pkt_ctx, ctx, path_ctx, current_time);
}

/* close resource allocated for logging in QUIC context */
void qlog_fns_quic_close(picoquic_quic_t* quic)
{
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
