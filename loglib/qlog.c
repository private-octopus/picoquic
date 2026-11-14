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
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>

#include "picoquic.h"
#include "picoquic_internal.h"
#include "bytestream.h"
#include "logreader.h"
#include "logconvert.h"
#include "picoquic_qlog_fns.h"
#include "qlog.h"

typedef struct qlog_context_st {
    qlog_fns_context_t fns;

    qlog_fns_path_context_t path_ctx;
} qlog_context_t;

int qlog_chars(FILE* f, bytestream* s, uint64_t l)
{
    int error_found = (s->ptr + (size_t)l > s->size);
    size_t actual_len = error_found ? (s->size - s->ptr) : (size_t)l;

    fprintf(f, "\"");
    qlog_fns_char_content(f, s->data + s->ptr, actual_len);
    s->ptr += actual_len;

    if (error_found) {
        fprintf(f, "... coding error!");
    }

    fprintf(f, "\"");
    return (error_found) ? -1 : 0;
}

/* Write the transport parameters of a binary log record with the code of
 * qlog_fns.c. If the record has less than tp_length bytes, write the two
 * lengths instead. */
int qlog_transport_extensions(FILE* f, bytestream* s, size_t tp_length)
{
    int ret = 0;

    if (tp_length > bytestream_remain(s)) {
        fprintf(f, ",\n    \"transport_parameter_length\": %zu", tp_length);
        fprintf(f, ",\n    \"bytes_available\": %zu", bytestream_remain(s));
        ret = -1;
    }
    else {
        qlog_fns_transport_extensions(f, s->data + s->ptr, tp_length);
    }

    return ret;
}


int qlog_alpn_update(uint64_t time, bytestream* s, void* ptr)
{
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;
    FILE* f = ctx->f_txtlog;
    uint64_t owner = 0;
    uint64_t sni_length = 0;
    uint64_t alpn_length = 0;
    uint64_t alpn_count = 0;
    int ret = 0;

    ret |= byteread_vint(s, &owner);
    ret |= byteread_vint(s, &sni_length);
    qlog_fns_event_start(ctx, NULL, 0, time, "transport", "parameters_set");
    fprintf(f, "\n    \"owner\": \"%s\"", (owner) ? "local" : "remote");
    if (sni_length > 0) {
        fprintf(f, ",\n    \"sni\": ");
        ret |= qlog_chars(f, s, sni_length);
    }

    ret |= byteread_vint(s, &alpn_count);
    if (ret == 0 && alpn_count > 0) {
        fprintf(f, ",\n    \"proposed_alpn\": [");

        for (size_t i = 0; i < alpn_count; i++) {
            uint64_t len;
            if (i != 0) {
                fprintf(f, ", ");
            }
            ret |= byteread_vint(s, &len);
            ret |= qlog_chars(f, s, len);
        }
        fprintf(f, "]");
    }


    ret |= byteread_vint(s, &alpn_length);
    if (ret == 0 && alpn_length > 0) {
        fprintf(f, ",\n    \"alpn\": ");
        qlog_chars(f, s, alpn_length);
    }

    fprintf(f, "}]");

    return 0;
}


int qlog_param_update(uint64_t time, bytestream* s, void* ptr)
{
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;
    FILE* f = ctx->f_txtlog;
    uint64_t owner = 0;
    uint64_t tp_length = 0;
    int ret = 0;

    ret |= byteread_vint(s, &owner);

    qlog_fns_event_start(ctx, NULL, 0, time, "transport", "parameters_set");

    fprintf(f, "\n    \"owner\": \"%s\"", (owner)?"local":"remote");

    ret |= byteread_vint(s, &tp_length);

    if (ret == 0 && tp_length > 0) {
        qlog_transport_extensions(f, s, (size_t)tp_length);
    }
    
    fprintf(f, "}]");

    return 0;
}

/* Return a pointer to the next *length bytes of the record, and skip them.
 * If the record has fewer bytes, set *length to 0, skip the rest of the
 * record, and return NULL. */
static const uint8_t* qlog_record_bytes(bytestream* s, uint64_t* length)
{
    const uint8_t* bytes = NULL;

    if (*length <= bytestream_remain(s)) {
        bytes = s->data + s->ptr;
        s->ptr += (size_t)*length;
    }
    else {
        *length = 0;
        s->ptr = s->size;
    }

    return bytes;
}

int qlog_packet_lost(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;
    FILE* f = ctx->f_txtlog;
    uint64_t packet_type = 0;
    uint64_t sequence = 0;
    uint64_t trigger_length = 0;
    const uint8_t* trigger = NULL;
    uint8_t cid_len = 0;
    uint64_t dcid_length = 0;
    const uint8_t* dcid = NULL;
    uint64_t packet_size = 0;
    int has_packet_size = 0;

    (void)byteread_vint(s, &packet_type);
    (void)byteread_vint(s, &sequence);
    (void)byteread_vint(s, &trigger_length);
    trigger = qlog_record_bytes(s, &trigger_length);
    if (byteread_int8(s, &cid_len) == 0) {
        dcid_length = cid_len;
        dcid = qlog_record_bytes(s, &dcid_length);
    }
    has_packet_size = (byteread_vint(s, &packet_size) == 0);

    qlog_fns_event_start(ctx, NULL, path_id, time, "recovery", "packet_lost");
    qlog_fns_packet_lost_data(f, packet_type, sequence, trigger, (size_t)trigger_length,
        dcid, (size_t)dcid_length, has_packet_size, packet_size);

    return 0;
}

int qlog_packet_dropped(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;
    FILE* f = ctx->f_txtlog;
    uint64_t packet_type = 0;
    uint64_t err_code = 0;
    uint64_t packet_size = 0;
    int ret = 0;

    ret |= byteread_vint(s, &packet_type);
    ret |= byteread_vint(s, &packet_size);
    ret |= byteread_vint(s, &err_code);

    qlog_fns_event_start(ctx, NULL, path_id, time, "transport", "packet_dropped");
    qlog_fns_packet_dropped_data(f, packet_type, packet_size, err_code);

    return ret;
}

int qlog_packet_buffered(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;
    FILE* f = ctx->f_txtlog;
    uint64_t packet_type = 0;
    uint64_t trigger_length = 0;
    const uint8_t* trigger = NULL;
    int ret = 0;

    ret |= byteread_vint(s, &packet_type);
    ret |= byteread_vint(s, &trigger_length);
    trigger = qlog_record_bytes(s, &trigger_length);

    qlog_fns_event_start(ctx, NULL, path_id, time, "transport", "packet_buffered");
    qlog_fns_packet_buffered_data(f, packet_type, trigger, (size_t)trigger_length);

    return ret;
}

int qlog_pdu(uint64_t time, int rxtx, bytestream* s, void * ptr)
{
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;
    struct sockaddr_storage addr_peer = { 0 };
    struct sockaddr_storage addr_local = { 0 };
    uint64_t byte_length = 0;
    uint64_t unique_path_id = 0;
    uint8_t ecn = 0xff;

    /* Do not log an address that could not be read. */
    if (byteread_addr(s, &addr_peer) != 0) {
        memset(&addr_peer, 0, sizeof(addr_peer));
    }
    (void)byteread_vint(s, &byte_length);
    if (byteread_addr(s, &addr_local) != 0) {
        memset(&addr_local, 0, sizeof(addr_local));
    }
    (void)byteread_vint(s, &unique_path_id);
    (void)byteread_int8(s, &ecn);

    qlog_fns_pdu(NULL, ctx, rxtx, time, (struct sockaddr*)&addr_peer, (struct sockaddr*)&addr_local,
        (size_t)byte_length, unique_path_id, ecn);

    return 0;
}

int qlog_packet_start(uint64_t time, uint64_t path_id, uint64_t size, const picoquic_packet_header * ph, int rxtx, void * ptr)
{
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;

    qlog_fns_packet_start(ctx, NULL, path_id, rxtx, time, ph, size);
    ctx->frame_count = 0;

    return 0;
}

int qlog_packet_frame(bytestream * s, void * ptr)
{
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;
    FILE * f = ctx->f_txtlog;

    if (ctx->packet_type == picoquic_packet_version_negotiation) {
        qlog_fns_proposed_versions(f, s->data + s->ptr, s->data + s->size);
    }
    else if (ctx->packet_type == picoquic_packet_retry) {
        qlog_fns_retry_token(f, s->data + s->ptr, s->data + s->size);
    }
    else {
        qlog_binlog_frame(f, s->data + s->ptr, s->data + s->size, &ctx->frame_count);
    }
    return 0;
}

int qlog_packet_end(void * ptr)
{
    qlog_fns_packet_end(&((qlog_context_t*)ptr)->fns);

    return 0;
}

/* Qlog records evolution of congestion control with events of the form:
* [559,"transport","packet_sent","DEFAULT",{"packet_type":"handshake","header":{"packet_size":668,"packet_number":0}}],
* [904,"recovery","metrics_updated","default",{"bytes_in_flight":822}],
* [45228,"recovery","metrics_updated","default",{"bytes_in_flight":668,"cwnd":12154,"smoothed_rtt":46151,
*                          "min_rtt":46151,"latest_rtt":46151}],
*/

int qlog_cc_update(uint64_t time, uint64_t path_id, bytestream* s, void* ptr)
{
    int ret = 0;
    uint64_t sequence = 0;
    uint64_t packet_rcvd = 0;
    uint64_t highest_ack = UINT64_MAX;
    uint64_t high_ack_time = 0;
    uint64_t last_time_ack = 0;
    uint64_t cwin = 0;
    uint64_t one_way_delay = 0;
    uint64_t rtt_sample = 0;
    uint64_t SRTT = 0;
    uint64_t RTT_min = 0;
    uint64_t bandwidth_estimate = 0;
    uint64_t receive_rate_estimate = 0;
    uint64_t Send_MTU = 0;
    uint64_t pacing_packet_time = 0;
    uint64_t nb_retrans = 0;
    uint64_t nb_spurious = 0;
    uint64_t cwin_blkd = 0;
    uint64_t flow_blkd = 0;
    uint64_t stream_blkd = 0;
    uint64_t cc_state = 0;
    uint64_t cc_param = 0;
    uint64_t bw_max = 0;
    uint64_t bytes_in_transit = 0;
    uint64_t app_limited = 0;
    qlog_context_t* ctx = (qlog_context_t*)ptr;

    ret |= byteread_vint(s, &sequence);
    ret |= byteread_vint(s, &packet_rcvd);
    if (packet_rcvd != 0) {
        ret |= byteread_vint(s, &highest_ack);
        ret |= byteread_vint(s, &high_ack_time);
        ret |= byteread_vint(s, &last_time_ack);
    }
    ret |= byteread_vint(s, &cwin);
    ret |= byteread_vint(s, &one_way_delay);
    ret |= byteread_vint(s, &rtt_sample);
    ret |= byteread_vint(s, &SRTT);
    ret |= byteread_vint(s, &RTT_min);
    ret |= byteread_vint(s, &bandwidth_estimate);
    ret |= byteread_vint(s, &receive_rate_estimate);
    ret |= byteread_vint(s, &Send_MTU);
    ret |= byteread_vint(s, &pacing_packet_time);
    ret |= byteread_vint(s, &nb_retrans);
    ret |= byteread_vint(s, &nb_spurious);
    ret |= byteread_vint(s, &cwin_blkd);
    ret |= byteread_vint(s, &flow_blkd);
    ret |= byteread_vint(s, &stream_blkd);

    ret |= byteread_vint(s, &cc_state);
    ret |= byteread_vint(s, &cc_param);
    ret |= byteread_vint(s, &bw_max);
    ret |= byteread_vint(s, &bytes_in_transit);
    /* Not checking the app limited return, because it is not present in old bin logs */
    (void) byteread_vint(s, &app_limited);

    if (ret == 0) {
        qlog_fns_path_context_t cc = { 0 };

        cc.cwin = cwin;
        cc.rtt_sample = rtt_sample;
        cc.smoothed_rtt = SRTT;
        cc.rtt_min = RTT_min;
        cc.bytes_in_transit = bytes_in_transit;
        cc.pacing_packet_time = pacing_packet_time;
        cc.cc_state = cc_state;
        cc.cc_param = cc_param;
        cc.last_bw_estimate_path_limited = (app_limited != 0);

        qlog_fns_cc_update(&ctx->fns, &ctx->path_ctx, NULL, path_id, time, &cc, Send_MTU);
    }

    return ret;
}

int qlog_info_message(uint64_t time, bytestream* s, void* ptr)
{
    int ret = 0;
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;
    FILE* f = ctx->f_txtlog;
    uint8_t message[BYTESTREAM_MAX_BUFFER_SIZE];
    size_t message_length = 0;

    qlog_fns_event_start(ctx, NULL, 0, time, "info", "message");

    fprintf(f, " \"message\": \"");
    message_length = bytestream_remain(s);
    if (message_length > sizeof(message)) {
        message_length = sizeof(message);
    }
    memcpy(message, bytestream_ptr(s), message_length);
    for (size_t i = 0; i < message_length; i++) {
        int c = message[i];
        if (c < 0x20 || c > 0x7e) {
            message[i] = '?';
        }
    }
    fwrite(message, message_length, 1, f);
    fprintf(f, "\"}]");

    return ret;
}

int qlog_connection_start(uint64_t time, const picoquic_connection_id_t * UNUSED(cid), int client_mode,
    uint32_t UNUSED(proposed_version), const picoquic_connection_id_t* UNUSED(remote_cnxid), void* ptr)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cid);
    UNREFERENCED_PARAMETER(proposed_version);
    UNREFERENCED_PARAMETER(remote_cnxid);
#endif
    qlog_context_t* qlog = (qlog_context_t*)ptr;
    qlog_fns_context_t* ctx = &qlog->fns;
    FILE * f = ctx->f_txtlog;

    ctx->start_time = time;
    ctx->packet_count = 0;
    ctx->event_count = 0;
    ctx->version_number = 0;


    memset(&ctx->addr_peer, 0, sizeof(struct sockaddr_storage));
    memset(&ctx->addr_local, 0, sizeof(struct sockaddr_storage));

    qlog->path_ctx.cwin = 0;
    qlog->path_ctx.bytes_in_transit = 0;
    qlog->path_ctx.smoothed_rtt = PICOQUIC_INITIAL_RTT;
    qlog->path_ctx.rtt_min = 0;
    qlog->path_ctx.rtt_sample = 0;
    qlog->path_ctx.pacing_packet_time = 1;

    ctx->key_phase_sent_last = 0;
    ctx->key_phase_sent = 0;
    ctx->key_phase_received_last = 0;
    ctx->key_phase_received = 0;
    ctx->spin_bit_sent_last = 0;
    ctx->spin_bit_sent = 0;

    fprintf(f, "{ \"qlog_version\": \"draft-00\", \"title\": \"picoquic\", \"traces\": [\n");
    fprintf(f, "{ \"vantage_point\": { \"name\": \"backend-67\", \"type\": \"%s\" },\n",
        client_mode?"client":"server");

    fprintf(f, "\"title\": \"picoquic\", \"description\": \"%s\",", ctx->cid_name);
    if (ctx->trace_flow_id) {
        fprintf(f, "\"event_fields\": [\"relative_time\", \"path_id\", \"category\", \"event\", \"data\"],\n");
    } else {
        fprintf(f, "\"event_fields\": [\"relative_time\", \"category\", \"event\", \"data\"],\n");
    }
    fprintf(f, "\"configuration\": {\"time_units\": \"us\"},\n");
    fprintf(f, "\"common_fields\": { \"protocol_type\": \"QUIC_HTTP3\", \"reference_time\": \"%"PRIu64"\"},\n", ctx->start_time);
    fprintf(f, "\"events\": [");
    ctx->state = 1;
    return 0;
}

int qlog_connection_end(uint64_t UNUSED(time), void * ptr)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(time);
#endif
    qlog_fns_context_t* ctx = &((qlog_context_t*)ptr)->fns;
    FILE * f = ctx->f_txtlog;
    fprintf(f, "]}]}\n");

    ctx->state = 2;
    return 0;
}

int qlog_convert(const picoquic_connection_id_t* cid, FILE* f_binlog, const char* binlog_name, const char* txt_name, const char* out_dir, uint16_t flags)
{
    int ret = 0;
    FILE* f_txtlog = NULL;
    char cid_name[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];

    if (picoquic_print_connection_id_hexa(cid_name, sizeof(cid_name), cid) != 0) {
        DBG_PRINTF("Cannot convert connection id for %s", binlog_name);
        ret = -1;
    }
    else if (txt_name == NULL) {
        f_txtlog = open_outfile(cid_name, binlog_name, out_dir, "qlog");
    }
    else {
        f_txtlog = picoquic_file_open(txt_name, "w");
    }

    if (f_txtlog == NULL) {
        ret = -1;
    }
    else  if (ret == 0) {

        qlog_context_t qlog;

        memset(&qlog, 0, sizeof(qlog_context_t));

        qlog.fns.f_txtlog = f_txtlog;
        qlog.fns.cid_name = cid_name;
        qlog.fns.start_time = 0;
        qlog.fns.packet_count = 0;
        qlog.fns.state = 0;
        qlog.fns.trace_flow_id = (flags & 1) ? 1 : 0;

        binlog_convert_cb_t ctx;
        ctx.connection_start = qlog_connection_start;
        ctx.connection_end = qlog_connection_end;
        ctx.alpn_update = qlog_alpn_update;
        ctx.param_update = qlog_param_update;
        ctx.pdu = qlog_pdu;
        ctx.packet_start = qlog_packet_start;
        ctx.packet_frame = qlog_packet_frame;
        ctx.packet_end = qlog_packet_end;
        ctx.packet_lost = qlog_packet_lost;
        ctx.packet_dropped = qlog_packet_dropped;
        ctx.packet_buffered = qlog_packet_buffered;
        ctx.cc_update = qlog_cc_update;
        ctx.info_message = qlog_info_message;
        ctx.ptr = &qlog;

        ret = binlog_convert(f_binlog, cid, &ctx);

        if (qlog.fns.state == 1) {
            qlog_connection_end(0, &qlog);
        }

        picoquic_file_close(f_txtlog);
    }

    return ret;
}
