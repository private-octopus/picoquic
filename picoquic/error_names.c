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

#include "picoquic.h"
#include "picoquic_internal.h"

char const* picoquic_error_name(uint64_t error_code)
{
    char const* e_name = "unknown";
    switch (error_code) {
        /* Protocol errors defined in the QUIC spec */
    case PICOQUIC_TRANSPORT_INTERNAL_ERROR: e_name = "internal"; break;
    case PICOQUIC_TRANSPORT_SERVER_BUSY: e_name = "server busy"; break;
    case PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR: e_name = "flow control"; break;
    case PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR: e_name = "stream limit"; break;
    case PICOQUIC_TRANSPORT_STREAM_STATE_ERROR: e_name = "stream state"; break;
    case PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR: e_name = "final offset"; break;
    case PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR: e_name = "frame format"; break;
    case PICOQUIC_TRANSPORT_PARAMETER_ERROR: e_name = "parameter"; break;
    case PICOQUIC_TRANSPORT_CONNECTION_ID_LIMIT_ERROR: e_name = "connection_id limit"; break;
    case PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION: e_name = "protocol violation"; break;
    case PICOQUIC_TRANSPORT_INVALID_TOKEN: e_name = "invalid token"; break;
    case PICOQUIC_TRANSPORT_APPLICATION_ERROR: e_name = "application"; break;
    case PICOQUIC_TRANSPORT_CRYPTO_BUFFER_EXCEEDED: e_name = "crypto buffer exceeded"; break;
    case PICOQUIC_TRANSPORT_KEY_UPDATE_ERROR: e_name = "key update"; break;
    case PICOQUIC_TRANSPORT_AEAD_LIMIT_REACHED: e_name = "aead limit"; break;
    case PICOQUIC_TLS_ALERT_WRONG_ALPN: e_name = "wrong alpn"; break;
    case PICOQUIC_TLS_HANDSHAKE_FAILED: e_name = "tls handshake failed"; break;
    case PICOQUIC_TRANSPORT_VERSION_NEGOTIATION_ERROR: e_name = "version negotiation"; break;
    case PICOQUIC_TRANSPORT_APPLICATION_ABANDON: e_name = "application abandon"; break;
    case PICOQUIC_TRANSPORT_RESOURCE_LIMIT_REACHED: e_name = "resource limit reached"; break;
    case PICOQUIC_TRANSPORT_UNSTABLE_INTERFACE: e_name = "unstable interface"; break;
    case PICOQUIC_TRANSPORT_NO_CID_AVAILABLE: e_name = "no CID available"; break;
        /* Picoquic local error codes. */
    case PICOQUIC_ERROR_DUPLICATE: e_name = "duplicate"; break;
    case PICOQUIC_ERROR_AEAD_CHECK: e_name = "aead check"; break;
    case PICOQUIC_ERROR_UNEXPECTED_PACKET: e_name = "unexpected packet"; break;
    case PICOQUIC_ERROR_MEMORY: e_name = "memory"; break;
    case PICOQUIC_ERROR_CNXID_CHECK: e_name = "connection ID check"; break;
    case PICOQUIC_ERROR_INITIAL_TOO_SHORT: e_name = ""; break;
    case PICOQUIC_ERROR_VERSION_NEGOTIATION_SPOOFED: e_name = "version negotation spoofed"; break;
    case PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION: e_name = "malformed transport extension"; break;
    case PICOQUIC_ERROR_EXTENSION_BUFFER_TOO_SMALL: e_name = "extension buffer too small"; break;
    case PICOQUIC_ERROR_ILLEGAL_TRANSPORT_EXTENSION: e_name = "illegal transport extension"; break;
    case PICOQUIC_ERROR_CANNOT_RESET_STREAM_ZERO: e_name = "cannot reset the crypto stream"; break;
    case PICOQUIC_ERROR_INVALID_STREAM_ID: e_name = "invalid stream id"; break;
    case PICOQUIC_ERROR_STREAM_ALREADY_CLOSED: e_name = "stream already closed"; break;
    case PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL: e_name = "frame buffer too small"; break;
    case PICOQUIC_ERROR_INVALID_FRAME: e_name = "invalid frame"; break;
    case PICOQUIC_ERROR_CANNOT_CONTROL_STREAM_ZERO: e_name = "cannot control the crypto stream"; break;
    case PICOQUIC_ERROR_RETRY: e_name = "retry"; break;
    case PICOQUIC_ERROR_DISCONNECTED: e_name = "disconnected"; break;
    case PICOQUIC_ERROR_DETECTED: e_name = "error detected"; break;
    case PICOQUIC_ERROR_INVALID_TICKET: e_name = "invalid ticket"; break;
    case PICOQUIC_ERROR_INVALID_FILE: e_name = "invalid file"; break;
    case PICOQUIC_ERROR_SEND_BUFFER_TOO_SMALL: e_name = "send buffer too small"; break;
    case PICOQUIC_ERROR_UNEXPECTED_STATE: e_name = "unexpected state"; break;
    case PICOQUIC_ERROR_UNEXPECTED_ERROR: e_name = "unexpected error"; break;
    case PICOQUIC_ERROR_TLS_SERVER_CON_WITHOUT_CERT: e_name = "server configuration without cert"; break;
    case PICOQUIC_ERROR_NO_SUCH_FILE: e_name = "no such file"; break;
    case PICOQUIC_ERROR_STATELESS_RESET: e_name = "stateless reset"; break;
    case PICOQUIC_ERROR_CONNECTION_DELETED: e_name = "connection deleted"; break;
    case PICOQUIC_ERROR_CNXID_SEGMENT: e_name = "connection ID segment error"; break;
    case PICOQUIC_ERROR_CNXID_NOT_AVAILABLE: e_name = "connection ID not available"; break;
    case PICOQUIC_ERROR_MIGRATION_DISABLED: e_name = "migration disabled"; break;
    case PICOQUIC_ERROR_CANNOT_COMPUTE_KEY: e_name = "cannot compute key"; break;
    case PICOQUIC_ERROR_CANNOT_SET_ACTIVE_STREAM: e_name = "cannot set active stream"; break;
    case PICOQUIC_ERROR_CANNOT_CHANGE_ACTIVE_CONTEXT: e_name = "cannot change active context"; break;
    case PICOQUIC_ERROR_INVALID_TOKEN: e_name = "invalid token"; break;
    case PICOQUIC_ERROR_INITIAL_CID_TOO_SHORT: e_name = "initial CID too short"; break;
    case PICOQUIC_ERROR_KEY_ROTATION_NOT_READY: e_name = "key rotation not ready"; break;
    case PICOQUIC_ERROR_AEAD_NOT_READY: e_name = "aead not ready"; break;
    case PICOQUIC_ERROR_NO_ALPN_PROVIDED: e_name = "no ALPN provided"; break;
    case PICOQUIC_ERROR_NO_CALLBACK_PROVIDED: e_name = "no callback provided"; break;
    case PICOQUIC_STREAM_RECEIVE_COMPLETE: e_name = "stream receive complete"; break;
    case PICOQUIC_ERROR_PACKET_HEADER_PARSING: e_name = "packet header parsing"; break;
    case PICOQUIC_ERROR_QUIC_BIT_MISSING: e_name = "QUIC bit missing"; break;
    case PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP: e_name = "terminate packet loop (not an error)"; break;
    case PICOQUIC_NO_ERROR_SIMULATE_NAT: e_name = "simulate NAT (not an error)"; break;
    case PICOQUIC_NO_ERROR_SIMULATE_MIGRATION: e_name = "simulate migration (not an error)"; break;
    case PICOQUIC_ERROR_VERSION_NOT_SUPPORTED: e_name = "version not supported"; break;
    case PICOQUIC_ERROR_IDLE_TIMEOUT: e_name = "idle timeout"; break;
    case PICOQUIC_ERROR_REPEAT_TIMEOUT: e_name = "repeat timeout"; break;
    case PICOQUIC_ERROR_HANDSHAKE_TIMEOUT: e_name = "handshake timeout"; break;
    case PICOQUIC_ERROR_SOCKET_ERROR: e_name = "socket"; break;
    case PICOQUIC_ERROR_VERSION_NEGOTIATION: e_name = "version negotiation"; break;
    case PICOQUIC_ERROR_PACKET_TOO_LONG: e_name = "packet too long"; break;
    case PICOQUIC_ERROR_PACKET_WRONG_VERSION: e_name = "wrong version"; break;
    case PICOQUIC_ERROR_PORT_BLOCKED: e_name = "port blocked"; break;
    case PICOQUIC_ERROR_DATAGRAM_TOO_LONG: e_name = "datagram too long"; break;
    case PICOQUIC_ERROR_PATH_ID_INVALID: e_name = "invalid path ID"; break;
    case PICOQUIC_ERROR_RETRY_NEEDED: e_name = "retry needed"; break;
    case PICOQUIC_ERROR_SERVER_BUSY: e_name = "server busy"; break;
    case PICOQUIC_ERROR_PATH_DUPLICATE: e_name = "duplicate path"; break;
    case PICOQUIC_ERROR_PATH_ID_BLOCKED: e_name = "blocked by lack of path ID"; break;
    case PICOQUIC_ERROR_PATH_CID_BLOCKED: e_name = "blocked by lack of CID"; break;
    case PICOQUIC_ERROR_PATH_ADDRESS_FAMILY: e_name = "path address family"; break;
    case PICOQUIC_ERROR_PATH_NOT_READY: e_name = "path not ready"; break;
    case PICOQUIC_ERROR_PATH_LIMIT_EXCEEDED: e_name = "path limit exceeded"; break;
    case PICOQUIC_ERROR_REDIRECTED: e_name = "redirected to proxy (not an error)"; break; /* Not an error: the packet was captured by a proxy, no further processing needed */

    default:
        if (error_code > 0x100 && error_code < 0x200) {
            /* Protocol errors defined in the QUIC spec */
            e_name = "crypto error alert";
        }
        else if (error_code > 0x400 && error_code < 0x500) {
            /* Picoquic error codes */
            e_name = "unknown picoquic error";
        }
        break;
    }
    return e_name;
}

void picoquic_display_error_names(picoquic_quic_t * quic)
{
    quic->get_error_name = picoquic_error_name;
}
