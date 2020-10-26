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
#include "picoquic_binlog.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>
#ifndef _WINDOWS
#include <sys/time.h>
#endif
#include "picoquic_unified_log.h"

/* Log an event that cannot be attached to a specific connection */
void picoquic_log_quic_app_message(picoquic_quic_t* quic, const picoquic_connection_id_t* cid, const char* fmt, ...){}

/* Log arrival or departure of an UDP datagram for an unknown connection */
void picoquic_log_quic_pdu(picoquic_quic_t* quic, int receiving, uint64_t current_time, picoquic_connection_id_t* cid,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length){}

/* Log an event relating to a specific connection
 * TODO: replace by new implementation
 */
void picoquic_txtlog_message_v(picoquic_quic_t* quic, const picoquic_connection_id_t* cid, const char* fmt, va_list vargs);
void picoquic_binlog_message_v(picoquic_cnx_t* cnx, const char* fmt, va_list vargs);

void picoquic_log_app_message(picoquic_cnx_t* cnx, const char* fmt, ...)
{
    if (cnx->quic->F_log != NULL) {
        va_list args;
        va_start(args, fmt);
        picoquic_txtlog_message_v(cnx->quic, &cnx->initial_cnxid, fmt, args);
        va_end(args);
    }

    if (cnx->f_binlog != NULL) {
        va_list args;
        va_start(args, fmt);
        picoquic_binlog_message_v(cnx, fmt, args);
        va_end(args);
    }
}

/* Log arrival or departure of an UDP datagram on a connection */
void picoquic_log_pdu(picoquic_cnx_t* cnx, int receiving, uint64_t current_time,
    const struct sockaddr* addr_peer, const struct sockaddr* addr_local, size_t packet_length){}

/* Log a decrypted packet - receiving = 1 if arrival, = 0 if sending */
void picoquic_log_packet(picoquic_cnx_t* cnx, int receiving, uint64_t current_time,
    struct st_picoquic_packet_header_t* ph, const uint8_t* bytes, size_t bytes_max){}

/* Report that a packet was dropped due to some error */
void picoquic_log_dropped_packet(picoquic_cnx_t* cnx, struct st_picoquic_packet_header_t* ph, size_t packet_size, int err, uint8_t* raw_data, uint64_t current_time){}

/* Report that packet was buffered waiting for decryption */
void picoquic_log_buffered_packet(picoquic_cnx_t* cnx, picoquic_packet_type_enum ptype, uint64_t current_time){}

/* Log that a packet was formatted, ready to be sent. */
void picoquic_log_outgoing_packet(picoquic_cnx_t* cnx,
    uint8_t* bytes, uint64_t sequence_number, size_t pn_length, size_t length,
    uint8_t* send_buffer, size_t send_length, uint64_t current_time){}

/* Log packet lost events */
void picoquic_log_packet_lost(picoquic_cnx_t* cnx,
    picoquic_packet_type_enum ptype, uint64_t sequence_number, char const* trigger,
    picoquic_connection_id_t* dcid, size_t packet_size,
    uint64_t current_time)
{}

/* log transport extension -- either formatted by the loacl peer (is_local=1) or received from remote peer */
void picoquic_log_transport_extension(picoquic_cnx_t* cnx, int is_local,
    uint8_t const* sni, size_t sni_len, uint8_t const* alpn, size_t alpn_len,
    const ptls_iovec_t* alpn_list, size_t alpn_count,
    size_t param_length, uint8_t* params){}

/* log TLS ticket */
void picoquic_log_tls_ticket(picoquic_cnx_t* cnx,
    uint8_t* ticket, uint16_t ticket_length){}

/* log the start of a connection */
void picoquic_log_new_connection(picoquic_cnx_t* cnx){}
/* log the end of a connection */
void picoquic_log_close_connection(picoquic_cnx_t* cnx){}

/* log congestion control parameters */
void picoquic_log_cc_dump(picoquic_cnx_t* cnx, uint64_t current_time)
{
    if (picoquic_cnx_is_still_logging(cnx)) {
        if (cnx->quic->F_log != NULL) {
            cnx->quic->text_log_fns->log_cc_dump(cnx, current_time);
        }
        if (cnx->f_binlog != NULL) {
            cnx->quic->bin_log_fns->log_cc_dump(cnx, current_time);
        }
    }
}