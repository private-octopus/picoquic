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

#include "picoquic.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>
#ifndef _WINDOWS
#include <sys/time.h>
#endif
#include "picoquic_unified_log.h"

int picoquic_register_log_functions(picoquic_quic_t* quic, picoquic_unified_logging_t * fns, void * params)
{
    int ret = -1;
    if (fns != NULL) {
        for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
            if (quic->log_fns[i] == fns) {
                /* Duplicate registration can happen, e.g., if parameters change */
                ret = 0;
                break;
            }
            if (quic->log_fns[i] == NULL) {
                quic->log_fns[i] = fns;
                quic->log_params[i] = params;
                ret = 0;
                break;
            }
        }
    }
    return ret;
}

void* picoquic_get_log_params(picoquic_quic_t* quic, picoquic_unified_logging_t* fns)
{
    void* params = NULL;
    if (fns != NULL) {
        for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
            if (quic->log_fns[i] == fns) {
                params = quic->log_params[i];
                break;
            }
        }
    }
    return params;
}

/* Close the quic level resource associated with logs */
void picoquic_log_close_logs(picoquic_quic_t* quic)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (quic->log_fns[i] != NULL) {
            quic->log_fns[i]->log_quic_close(quic, quic->log_params[i]);
            quic->log_params[i] = NULL;
        }
        else {
            break;
        }
    }
}

/* Log arrival or departure of an UDP datagram for an unknown connection */
void picoquic_log_quic_pdu(picoquic_quic_t* quic, int receiving, uint64_t current_time, uint64_t cid64,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (quic->log_fns[i] != NULL) {
            if (quic->log_fns[i]->log_quic_pdu != NULL) {
                quic->log_fns[i]->log_quic_pdu(quic, quic->log_params[i], receiving, current_time, cid64, addr_peer, addr_local, packet_length);
            }
        }
        else {
            break;
        }
    }
}

/* Log an event relating to a specific connection */

void picoquic_log_app_message_v(picoquic_cnx_t* cnx, const char* fmt, va_list vargs)
{
    PICOQUIC_THREAD_CHECK(cnx->quic);
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (cnx->log_ctx[i] != NULL) {
            cnx->quic->log_fns[i]->log_app_message(cnx, cnx->log_ctx[i], fmt, vargs);
        }
        else if (cnx->quic->log_fns[i] == NULL) {
            break;
        }
    }
}

void picoquic_log_app_message(picoquic_cnx_t* cnx, const char* fmt, ...)
{
    PICOQUIC_THREAD_CHECK(cnx->quic);
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (cnx->log_ctx[i] != NULL) {
            va_list args;
            va_start(args, fmt);
            cnx->quic->log_fns[i]->log_app_message(cnx, cnx->log_ctx[i], fmt, args);
        }
        else if (cnx->quic->log_fns[i] == NULL) {
            break;
        }
    }
}

void picoquic_log_context_free_app_message(picoquic_quic_t* quic, const picoquic_connection_id_t* cid, const char* fmt, ...)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (quic->log_fns[i] != NULL) {
            if (quic->log_fns[i]->log_quic_app_message != NULL) {
                va_list args;
                va_start(args, fmt);
                quic->log_fns[i]->log_quic_app_message(quic, quic->log_params[i], cid, fmt, args);
            }
        }
        else {
            break;
        }
    }
}

/* Log arrival or departure of an UDP datagram on a connection */
void picoquic_log_pdu(picoquic_cnx_t* cnx, int receiving, uint64_t current_time,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length,
    uint64_t unique_path_id, unsigned char ecn)
{
    PICOQUIC_THREAD_CHECK(cnx->quic);
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (cnx->log_ctx[i] != NULL) {
            cnx->quic->log_fns[i]->log_pdu(cnx, cnx->log_ctx[i], receiving, current_time, addr_peer, addr_local, packet_length,
                unique_path_id, ecn);
        }
        else if (cnx->quic->log_fns[i] == NULL) {
            break;
        }
    }
}

/* Log a decrypted packet - receiving = 1 if arrival, = 0 if sending */
void picoquic_log_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, int receiving, uint64_t current_time,
    struct st_picoquic_packet_header_t* ph, const uint8_t* bytes, size_t bytes_max)
{
    PICOQUIC_THREAD_CHECK(cnx->quic);
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (picoquic_cnx_is_still_logging(cnx)) {
            if (cnx->log_ctx[i] != NULL) {
                cnx->quic->log_fns[i]->log_packet(cnx, cnx->log_ctx[i], path_x, receiving, current_time, ph, bytes, bytes_max);
            }
            else if (cnx->quic->log_fns[i] == NULL) {
                break;
            }
        }
    }
}

/* Report that a packet was dropped due to some error */
void picoquic_log_dropped_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, struct st_picoquic_packet_header_t* ph, size_t packet_size,
    int err, uint8_t* UNUSED(raw_data), uint64_t current_time)
{
    PICOQUIC_THREAD_CHECK(cnx->quic);
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (picoquic_cnx_is_still_logging(cnx)) {
            if (cnx->log_ctx[i] != NULL) {
                cnx->quic->log_fns[i]->log_dropped_packet(cnx, cnx->log_ctx[i], path_x, ph, packet_size, err, current_time);
            }
            else if (cnx->quic->log_fns[i] == NULL) {
                break;
            }
        }
    }
}

/* Report that packet was buffered waiting for decryption */
void picoquic_log_buffered_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_packet_type_enum ptype, uint64_t current_time)
{
    PICOQUIC_THREAD_CHECK(cnx->quic);
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (picoquic_cnx_is_still_logging(cnx)) {
            if (cnx->log_ctx[i] != NULL) {
                cnx->quic->log_fns[i]->log_buffered_packet(cnx, cnx->log_ctx[i], path_x, ptype, current_time);
            }
            else if (cnx->quic->log_fns[i] == NULL) {
                break;
            }
        }
    }
}

/* Log that a packet was formatted, ready to be sent. */
void picoquic_log_outgoing_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    uint8_t* bytes, uint64_t sequence_number, size_t pn_length, size_t length,
    uint8_t* send_buffer, size_t send_length, uint64_t current_time)
{
    PICOQUIC_THREAD_CHECK(cnx->quic);
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (picoquic_cnx_is_still_logging(cnx)) {
            if (cnx->log_ctx[i] != NULL) {
                cnx->quic->log_fns[i]->log_outgoing_packet(cnx, cnx->log_ctx[i], path_x, bytes, sequence_number, pn_length, length,
                    send_buffer, send_length, current_time);
            }
            else if (cnx->quic->log_fns[i] == NULL) {
                break;
            }
        }
    }
}

/* Log packet lost events */
void picoquic_log_packet_lost(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_type_enum ptype, uint64_t sequence_number, char const* trigger,
    picoquic_connection_id_t* dcid, size_t packet_size,
    uint64_t current_time)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (picoquic_cnx_is_still_logging(cnx)) {
            if (cnx->log_ctx[i] != NULL) {
                cnx->quic->log_fns[i]->log_packet_lost(cnx, cnx->log_ctx[i], path_x, ptype, sequence_number, trigger, dcid, packet_size, current_time);
            }
            else if (cnx->quic->log_fns[i] == NULL) {
                break;
            }
        }
    }
}

/* Log ALPN negotiation, or results */
void picoquic_log_negotiated_alpn(picoquic_cnx_t* cnx, int is_local,
    uint8_t const* sni, size_t sni_len, uint8_t const* alpn, size_t alpn_len,
    const ptls_iovec_t* alpn_list, size_t alpn_count)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (cnx->log_ctx[i] != NULL) {
            cnx->quic->log_fns[i]->log_negotiated_alpn(cnx, cnx->log_ctx[i], is_local, sni, sni_len, alpn, alpn_len, alpn_list, alpn_count);
        }
        else if (cnx->quic->log_fns[i] == NULL) {
            break;
        }
    }
}

/* log transport extension -- either formatted by the loacl peer (is_local=1) or received from remote peer */
void picoquic_log_transport_extension(picoquic_cnx_t* cnx, int is_local,
    size_t param_length, uint8_t* params)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (cnx->log_ctx[i] != NULL) {
            cnx->quic->log_fns[i]->log_transport_extension(cnx, cnx->log_ctx[i], is_local, param_length, params);
        }
        else if (cnx->quic->log_fns[i] == NULL) {
            break;
        }
    }
}

/* log TLS ticket */
void picoquic_log_tls_ticket(picoquic_cnx_t* cnx, uint8_t* ticket, uint16_t ticket_length)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (cnx->log_ctx[i] != NULL) {
            cnx->quic->log_fns[i]->log_picotls_ticket(cnx, cnx->log_ctx[i], ticket, ticket_length);
        }
        else if (cnx->quic->log_fns[i] == NULL) {
            break;
        }
    }
}

/* log the start of a connection */
void picoquic_log_new_connection(picoquic_cnx_t* cnx)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (cnx->quic->log_fns[i] != NULL) {
            /* TODO: change that API to initialize the context */
            cnx->quic->log_fns[i]->log_new_connection(cnx, cnx->quic->log_params[i], &cnx->log_ctx[i]);
        }
        else {
            break;
        }
    }
}

/* log the end of a connection */
void picoquic_log_close_connection(picoquic_cnx_t* cnx)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (cnx->log_ctx[i] != NULL) {
            /* TODO: pass connection context */
            cnx->quic->log_fns[i]->log_close_connection(cnx, cnx->log_ctx[i]);
            cnx->log_ctx[i] = NULL;
        }
        else if (cnx->quic->log_fns[i] == NULL) {
            break;
        }
    }
}

/* log congestion control parameters */
void picoquic_log_cc_dump(picoquic_cnx_t* cnx, uint64_t current_time)
{
    if (cnx->memlog_call_back != NULL) {
        cnx->memlog_call_back(cnx, cnx->path[0], cnx->memlog_ctx, 0, current_time);
    }

    if (picoquic_cnx_is_still_logging(cnx) && cnx->quic->log_fns[0] != NULL) {
        picoquic_path_t* path_x;
        for (int path_index = 0; path_index < cnx->nb_paths; path_index++)
        {
            path_x = cnx->path[path_index];

            if (!path_x->is_cc_data_updated) {
                continue;
            }
            for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
                if (cnx->log_ctx[i] != NULL) {
                    cnx->quic->log_fns[i]->log_cc_dump(cnx, cnx->log_ctx[i], path_x, current_time);
                }
                else if (cnx->quic->log_fns[i] == NULL) {
                    break;
                }
            }

            path_x->is_cc_data_updated = 0;
        }
    }
}

void picoquic_log_flush(picoquic_cnx_t* cnx)
{
    for (int i = 0; i < PICOQUIC_MAX_LOG_FUNCTIONS; i++) {
        if (cnx->log_ctx[i] != NULL && cnx->quic->log_fns[i]->log_flush != NULL) {
            cnx->quic->log_fns[i]->log_flush(cnx, cnx->log_ctx[i]);
        }
        else if (cnx->quic->log_fns[i] == NULL) {
            break;
        }
    }
}
