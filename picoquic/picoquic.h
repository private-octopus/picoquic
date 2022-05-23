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

#ifndef PICOQUIC_H
#define PICOQUIC_H

#include <stdint.h>
#include <stdarg.h>
#ifdef _WINDOWS
#include <WS2tcpip.h>
#include <Ws2def.h>
#include <winsock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define PICOQUIC_VERSION "1.01a"

#define PICOQUIC_ERROR_CLASS 0x400
#define PICOQUIC_ERROR_DUPLICATE (PICOQUIC_ERROR_CLASS + 1)
#define PICOQUIC_ERROR_AEAD_CHECK (PICOQUIC_ERROR_CLASS + 3)
#define PICOQUIC_ERROR_UNEXPECTED_PACKET (PICOQUIC_ERROR_CLASS + 4)
#define PICOQUIC_ERROR_MEMORY (PICOQUIC_ERROR_CLASS + 5)
#if 0
#define PICOQUIC_ERROR_SPURIOUS_REPEAT (PICOQUIC_ERROR_CLASS + 6)
#endif
#define PICOQUIC_ERROR_CNXID_CHECK (PICOQUIC_ERROR_CLASS + 7)
#define PICOQUIC_ERROR_INITIAL_TOO_SHORT (PICOQUIC_ERROR_CLASS + 8)
#define PICOQUIC_ERROR_VERSION_NEGOTIATION_SPOOFED (PICOQUIC_ERROR_CLASS + 9)
#define PICOQUIC_ERROR_MALFORMED_TRANSPORT_EXTENSION (PICOQUIC_ERROR_CLASS + 10)
#define PICOQUIC_ERROR_EXTENSION_BUFFER_TOO_SMALL (PICOQUIC_ERROR_CLASS + 11)
#define PICOQUIC_ERROR_ILLEGAL_TRANSPORT_EXTENSION (PICOQUIC_ERROR_CLASS + 12)
#define PICOQUIC_ERROR_CANNOT_RESET_STREAM_ZERO (PICOQUIC_ERROR_CLASS + 13)
#define PICOQUIC_ERROR_INVALID_STREAM_ID (PICOQUIC_ERROR_CLASS + 14)
#define PICOQUIC_ERROR_STREAM_ALREADY_CLOSED (PICOQUIC_ERROR_CLASS + 15)
#define PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL (PICOQUIC_ERROR_CLASS + 16)
#define PICOQUIC_ERROR_INVALID_FRAME (PICOQUIC_ERROR_CLASS + 17)
#define PICOQUIC_ERROR_CANNOT_CONTROL_STREAM_ZERO (PICOQUIC_ERROR_CLASS + 18)
#define PICOQUIC_ERROR_RETRY (PICOQUIC_ERROR_CLASS + 19)
#define PICOQUIC_ERROR_DISCONNECTED (PICOQUIC_ERROR_CLASS + 20)
#define PICOQUIC_ERROR_DETECTED (PICOQUIC_ERROR_CLASS + 21)
#define PICOQUIC_ERROR_INVALID_TICKET (PICOQUIC_ERROR_CLASS + 23)
#define PICOQUIC_ERROR_INVALID_FILE (PICOQUIC_ERROR_CLASS + 24)
#define PICOQUIC_ERROR_SEND_BUFFER_TOO_SMALL (PICOQUIC_ERROR_CLASS + 25)
#define PICOQUIC_ERROR_UNEXPECTED_STATE (PICOQUIC_ERROR_CLASS + 26)
#define PICOQUIC_ERROR_UNEXPECTED_ERROR (PICOQUIC_ERROR_CLASS + 27)
#define PICOQUIC_ERROR_TLS_SERVER_CON_WITHOUT_CERT (PICOQUIC_ERROR_CLASS + 28)
#define PICOQUIC_ERROR_NO_SUCH_FILE (PICOQUIC_ERROR_CLASS + 29)
#define PICOQUIC_ERROR_STATELESS_RESET (PICOQUIC_ERROR_CLASS + 30)
#define PICOQUIC_ERROR_CONNECTION_DELETED (PICOQUIC_ERROR_CLASS + 31)
#define PICOQUIC_ERROR_CNXID_SEGMENT (PICOQUIC_ERROR_CLASS + 32)
#define PICOQUIC_ERROR_CNXID_NOT_AVAILABLE (PICOQUIC_ERROR_CLASS + 33)
#define PICOQUIC_ERROR_MIGRATION_DISABLED (PICOQUIC_ERROR_CLASS + 34)
#define PICOQUIC_ERROR_CANNOT_COMPUTE_KEY (PICOQUIC_ERROR_CLASS + 35)
#define PICOQUIC_ERROR_CANNOT_SET_ACTIVE_STREAM (PICOQUIC_ERROR_CLASS + 36)
#define PICOQUIC_ERROR_CANNOT_CHANGE_ACTIVE_CONTEXT (PICOQUIC_ERROR_CLASS + 37)
#define PICOQUIC_ERROR_INVALID_TOKEN (PICOQUIC_ERROR_CLASS + 38)
#define PICOQUIC_ERROR_INITIAL_CID_TOO_SHORT (PICOQUIC_ERROR_CLASS + 39)
#define PICOQUIC_ERROR_KEY_ROTATION_NOT_READY (PICOQUIC_ERROR_CLASS + 40)
#define PICOQUIC_ERROR_AEAD_NOT_READY (PICOQUIC_ERROR_CLASS + 41)
#define PICOQUIC_ERROR_NO_ALPN_PROVIDED (PICOQUIC_ERROR_CLASS + 42)
#define PICOQUIC_ERROR_NO_CALLBACK_PROVIDED (PICOQUIC_ERROR_CLASS + 43)
#define PICOQUIC_STREAM_RECEIVE_COMPLETE (PICOQUIC_ERROR_CLASS + 44)
#define PICOQUIC_ERROR_PACKET_HEADER_PARSING (PICOQUIC_ERROR_CLASS + 45)
#define PICOQUIC_ERROR_QUIC_BIT_MISSING (PICOQUIC_ERROR_CLASS + 46)
#define PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP (PICOQUIC_ERROR_CLASS + 47)
#define PICOQUIC_NO_ERROR_SIMULATE_NAT (PICOQUIC_ERROR_CLASS + 48)
#define PICOQUIC_NO_ERROR_SIMULATE_MIGRATION (PICOQUIC_ERROR_CLASS + 49)
#define PICOQUIC_ERROR_VERSION_NOT_SUPPORTED (PICOQUIC_ERROR_CLASS + 50)
#define PICOQUIC_ERROR_IDLE_TIMEOUT (PICOQUIC_ERROR_CLASS + 51)
#define PICOQUIC_ERROR_REPEAT_TIMEOUT (PICOQUIC_ERROR_CLASS + 52)
#define PICOQUIC_ERROR_HANDSHAKE_TIMEOUT (PICOQUIC_ERROR_CLASS + 53)
#define PICOQUIC_ERROR_SOCKET_ERROR (PICOQUIC_ERROR_CLASS + 54)
#define PICOQUIC_ERROR_VERSION_NEGOTIATION (PICOQUIC_ERROR_CLASS + 55)
#define PICOQUIC_ERROR_PACKET_TOO_LONG (PICOQUIC_ERROR_CLASS + 56)
#define PICOQUIC_ERROR_PACKET_WRONG_VERSION (PICOQUIC_ERROR_CLASS + 57)
#define PICOQUIC_ERROR_PORT_BLOCKED (PICOQUIC_ERROR_CLASS + 58)
#define PICOQUIC_ERROR_DATAGRAM_TOO_LONG (PICOQUIC_ERROR_CLASS + 59)

/*
 * Protocol errors defined in the QUIC spec
 */
#define PICOQUIC_TRANSPORT_INTERNAL_ERROR (0x1)
#define PICOQUIC_TRANSPORT_SERVER_BUSY (0x2)
#define PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR (0x3)
#define PICOQUIC_TRANSPORT_STREAM_LIMIT_ERROR (0x4)
#define PICOQUIC_TRANSPORT_STREAM_STATE_ERROR (0x5)
#define PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR (0x6)
#define PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR (0x7)
#define PICOQUIC_TRANSPORT_PARAMETER_ERROR (0x8)
#define PICOQUIC_TRANSPORT_CONNECTION_ID_LIMIT_ERROR (0x9)
#define PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION (0xA)
#define PICOQUIC_TRANSPORT_INVALID_TOKEN (0xB)
#define PICOQUIC_TRANSPORT_APPLICATION_ERROR (0xC)
#define PICOQUIC_TRANSPORT_CRYPTO_BUFFER_EXCEEDED (0xD)
#define PICOQUIC_TRANSPORT_KEY_UPDATE_ERROR (0xE)
#define PICOQUIC_TRANSPORT_AEAD_LIMIT_REACHED (0xF) 

#define PICOQUIC_TRANSPORT_CRYPTO_ERROR(Alert) (((uint16_t)0x100) | ((uint16_t)((Alert)&0xFF)))
#define PICOQUIC_TLS_ALERT_WRONG_ALPN (0x178)
#define PICOQUIC_TLS_HANDSHAKE_FAILED (0x201)
#define PICOQUIC_TRANSPORT_VERSION_NEGOTIATION_ERROR (0x53F8)

#define PICOQUIC_MAX_PACKET_SIZE 1536
#define PICOQUIC_INITIAL_MTU_IPV4 1252
#define PICOQUIC_INITIAL_MTU_IPV6 1232
#define PICOQUIC_RESET_SECRET_SIZE 16
#define PICOQUIC_RESET_PACKET_PAD_SIZE 23
#define PICOQUIC_RESET_PACKET_MIN_SIZE (PICOQUIC_RESET_PACKET_PAD_SIZE + PICOQUIC_RESET_SECRET_SIZE)

#define PICOQUIC_LOG_PACKET_MAX_SEQUENCE 100

#define FOURCC(a, b, c, d) ((((uint32_t)(d)<<24) | ((c)<<16) | ((b)<<8) | (a)))

/*
* Connection states, useful to expose the state to the application.
*/
typedef enum {
    picoquic_state_client_init,
    picoquic_state_client_init_sent,
    picoquic_state_client_renegotiate,
    picoquic_state_client_retry_received,
    picoquic_state_client_init_resent,
    picoquic_state_server_init,
    picoquic_state_server_handshake,
    picoquic_state_client_handshake_start,
    picoquic_state_handshake_failure,
    picoquic_state_handshake_failure_resend,
    picoquic_state_client_almost_ready,
    picoquic_state_server_false_start,
    picoquic_state_server_almost_ready,
    picoquic_state_client_ready_start,
    picoquic_state_ready,
    picoquic_state_disconnecting,
    picoquic_state_closing_received,
    picoquic_state_closing,
    picoquic_state_draining,
    picoquic_state_disconnected
} picoquic_state_enum;

/* PMTUD 
 */

typedef enum {
    picoquic_pmtud_basic = 0, /* default pmtud behavior, opportunistic */
    picoquic_pmtud_required = 1, /* force pmtud asap */
    picoquic_pmtud_delayed = 2, /* only do pmtud if lots of data has to be sent */
    picoquic_pmtud_blocked = 3 /* never do pmtud */
} picoquic_pmtud_policy_enum;
/*
* Quic spin bit variants
*/

typedef enum {
    picoquic_spinbit_basic = 0, /* default spin bit behavior, as specified in spin bit draft */
    picoquic_spinbit_random = 1, /* alternative spin bit behavior, randomized for each packet */
    picoquic_spinbit_null = 2, /* null behavior, randomized per path */
    picoquic_spinbit_on = 3 /* Option used in test to avoid randomizing spin bit on/off */
} picoquic_spinbit_version_enum;

/*
* Quic loss bit variants
*/

typedef enum {
    picoquic_lossbit_none = 0, /* No support for the loss bits */
    picoquic_lossbit_send_only = 1, /* Able to send the loss bit, but not receive it */
    picoquic_lossbit_send_receive = 2, /* Able to send or receive the loss bits */
} picoquic_lossbit_version_enum;

/*
 * Provisional definition of the connection ID.
 */
#define PICOQUIC_CONNECTION_ID_MIN_SIZE 0
#define PICOQUIC_CONNECTION_ID_MAX_SIZE 20

typedef struct st_picoquic_connection_id_t {
    uint8_t id[PICOQUIC_CONNECTION_ID_MAX_SIZE];
    uint8_t id_len;
} picoquic_connection_id_t;


/* forward definition to avoid full dependency on picotls.h */
typedef struct st_ptls_iovec_t ptls_iovec_t; 

/* Detect whether error occured in TLS
 */
int picoquic_is_handshake_error(uint64_t error_code);


typedef struct st_picoquic_quic_t picoquic_quic_t;
typedef struct st_picoquic_cnx_t picoquic_cnx_t;
typedef struct st_picoquic_path_t picoquic_path_t;

typedef enum {
    picoquic_callback_stream_data = 0, /* Data received from peer on stream N */
    picoquic_callback_stream_fin, /* Fin received from peer on stream N; data is optional */
    picoquic_callback_stream_reset, /* Reset Stream received from peer on stream N; bytes=NULL, len = 0  */
    picoquic_callback_stop_sending, /* Stop sending received from peer on stream N; bytes=NULL, len = 0 */
    picoquic_callback_stateless_reset, /* Stateless reset received from peer. Stream=0, bytes=NULL, len=0 */
    picoquic_callback_close, /* Connection close. Stream=0, bytes=NULL, len=0 */
    picoquic_callback_application_close, /* Application closed by peer. Stream=0, bytes=NULL, len=0 */
    picoquic_callback_stream_gap,  /* bytes=NULL, len = length-of-gap or 0 (if unknown) */
    picoquic_callback_prepare_to_send, /* Ask application to send data in frame, see picoquic_provide_stream_data_buffer for details */
    picoquic_callback_almost_ready, /* Data can be sent, but the connection is not fully established */
    picoquic_callback_ready, /* Data can be sent and received, connection migration can be initiated */
    picoquic_callback_datagram, /* Datagram frame has been received */
    picoquic_callback_version_negotiation, /* version negotiation requested */
    picoquic_callback_request_alpn_list, /* Provide the list of supported ALPN */
    picoquic_callback_set_alpn, /* Set ALPN to negotiated value */
    picoquic_callback_pacing_changed, /* Pacing rate for the connection changed */
    picoquic_callback_prepare_datagram, /* Prepare the next datagram */
    picoquic_callback_datagram_acked, /* Ack for packet carrying datagram-frame received from peer */
    picoquic_callback_datagram_lost, /* Packet carrying datagram-frame probably lost */
    picoquic_callback_datagram_spurious /* Packet carrying datagram-frame was not really lost */
} picoquic_call_back_event_t;

typedef struct st_picoquic_tp_prefered_address_t {
    int is_defined;
    uint8_t ipv4Address[4];
    uint16_t ipv4Port;
    uint8_t ipv6Address[16];
    uint16_t ipv6Port;
    picoquic_connection_id_t connection_id;
    uint8_t statelessResetToken[16];
} picoquic_tp_prefered_address_t;

typedef struct st_picoquic_tp_version_negotiation_t {
    uint32_t current; /* Version found in TP, should match envelope */
    uint32_t previous; /* Version that triggered a VN before */
    size_t nb_received; /* Only present on client */
    uint32_t* received;
    size_t nb_supported; /* On client, list of compatible versions */
    uint32_t* supported;
} picoquic_tp_version_negotiation_t;

typedef struct st_picoquic_tp_t {
    uint64_t initial_max_stream_data_bidi_local;
    uint64_t initial_max_stream_data_bidi_remote;
    uint64_t initial_max_stream_data_uni;
    uint64_t initial_max_data;
    uint64_t initial_max_stream_id_bidir;
    uint64_t initial_max_stream_id_unidir;
    uint32_t idle_timeout;
    uint32_t max_packet_size;
    uint32_t max_ack_delay; /* stored in in microseconds for convenience */
    uint32_t active_connection_id_limit;
    uint8_t ack_delay_exponent;
    unsigned int migration_disabled;
    picoquic_tp_prefered_address_t prefered_address;
    uint32_t max_datagram_frame_size;
    int enable_loss_bit;
    int enable_time_stamp; /* (x&1) want, (x&2) can */
    uint64_t min_ack_delay;
    int do_grease_quic_bit;
    int enable_multipath;
    picoquic_tp_version_negotiation_t version_negotiation;
    int enable_bdp_frame;
} picoquic_tp_t;

/*
 * Stream types
 */
#define PICOQUIC_STREAM_ID_TYPE_MASK 3
#define PICOQUIC_STREAM_ID_CLIENT_INITIATED 0
#define PICOQUIC_STREAM_ID_SERVER_INITIATED 1
#define PICOQUIC_STREAM_ID_BIDIR 0
#define PICOQUIC_STREAM_ID_UNIDIR 2
#define PICOQUIC_STREAM_ID_CLIENT_INITIATED_BIDIR (PICOQUIC_STREAM_ID_CLIENT_INITIATED|PICOQUIC_STREAM_ID_BIDIR)
#define PICOQUIC_STREAM_ID_SERVER_INITIATED_BIDIR (PICOQUIC_STREAM_ID_SERVER_INITIATED|PICOQUIC_STREAM_ID_BIDIR)
#define PICOQUIC_STREAM_ID_CLIENT_INITIATED_UNIDIR (PICOQUIC_STREAM_ID_CLIENT_INITIATED|PICOQUIC_STREAM_ID_UNIDIR)
#define PICOQUIC_STREAM_ID_SERVER_INITIATED_UNIDIR (PICOQUIC_STREAM_ID_SERVER_INITIATED|PICOQUIC_STREAM_ID_UNIDIR)

#define PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_BIDIR (PICOQUIC_STREAM_ID_CLIENT_INITIATED_BIDIR + ((65535-1)*4))
#define PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_BIDIR (PICOQUIC_STREAM_ID_SERVER_INITIATED_BIDIR + ((65535-1)*4))
#define PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_UNIDIR (PICOQUIC_STREAM_ID_CLIENT_INITIATED_UNIDIR + ((65535-1)*4))
#define PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_UNIDIR (PICOQUIC_STREAM_ID_SERVER_INITIATED_UNIDIR + ((65535-1)*4))

/* 
* Time management. Internally, picoquic works in "virtual time", updated via the "current time" parameter
* passed through picoquic_create(), picoquic_create_cnx(), picoquic_incoming_packet(), and picoquic_prepare_packet().
*
* There are two supported modes of operation, "wall time" synchronized with the system's current time function,
* and "simulated time". Production services are expected to use wall time, tests and simulation use the
* simulated time. The simulated time is held in a 64 bit counter, the address of which is passed as 
* the "p_simulated_time" parameter to picoquic_create().
*
* The time management needs to be consistent with the functions used internally by the TLS package "picotls".
* If the argument "p_simulated_time" is NULL, picotls will use "wall time", accessed through system API.
* If the argument is set, the default time function of picotls will be overridden by a function that
* reads the value of *p_simulated_time.
*
* The function "picoquic_current_time()" reads the wall time in microseconds, using the same system calls
* as picotls. The default socket code in "picosock.[ch]" uses that time function, and returns the time
* at which messages arrived. 
*
* The function "picoquic_get_quic_time()" returns the "virtual time" used by the specified quic
* context, which can be either the current wall time or the simulated time, depending on how the
* quic context was initialized.
*/

uint64_t picoquic_current_time(); /* wall time */
uint64_t picoquic_get_quic_time(picoquic_quic_t* quic); /* connection time, compatible with simulations */

/* Callback function for providing stream data to the application,
 * and generally for notifying events from stack to application.
 * The type of event is specified in an enum picoquic_call_back_event_t.
 * For stream related calls, stream ID provides the stream number, and the
 * parameter stream_ctx provides the application supplied stream context.
 */
typedef int (*picoquic_stream_data_cb_fn)(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void * stream_ctx);

/* Callback from the TLS stack upon receiving a list of proposed ALPN in the Client Hello
 * The stack passes a <list> of io <count> vectors (base, len) each containing a proposed
 * ALPN. The implementation returns the index of the selected ALPN, or a value >= count
 * if none of the proposed ALPN is supported.
 *
 * The callback is only called if no default ALPN is specified in the Quic context.
 */
typedef size_t (*picoquic_alpn_select_fn)(picoquic_quic_t* quic, ptls_iovec_t* list, size_t count);

/* Function used during callback to provision an ALPN context. The stack 
 * issues a callback of type 
 */
int picoquic_add_proposed_alpn(void* tls_context, const char* alpn);

/* Callback function for producing a connection ID compatible
 * with the server environment.
 */

typedef void (*picoquic_connection_id_cb_fn)(picoquic_quic_t * quic, picoquic_connection_id_t cnx_id_local,
    picoquic_connection_id_t cnx_id_remote, void* cnx_id_cb_data, picoquic_connection_id_t * cnx_id_returned);

/* The fuzzer function is used to inject error in packets randomly.
 * It is called just prior to sending a packet, and can randomly
 * change the content or length of the packet.
 */
typedef uint32_t(*picoquic_fuzz_fn)(void * fuzz_ctx, picoquic_cnx_t* cnx, uint8_t * bytes, 
    size_t bytes_max, size_t length, size_t header_length);
void picoquic_set_fuzz(picoquic_quic_t* quic, picoquic_fuzz_fn fuzz_fn, void * fuzz_ctx);

/* Log application messages or other messages to the text log and binary log.
 */
void picoquic_log_app_message_v(picoquic_cnx_t* cnx, const char* fmt, va_list vargs);
void picoquic_log_app_message(picoquic_cnx_t* cnx, const char* fmt, ...);

/* Set the log level:
 * 1: log all packets
 * 0: only log the first 100 packets for each connection. */
void picoquic_set_log_level(picoquic_quic_t* quic, int log_level);

/* By default, the binary log and qlog files are named from the Initial CID
 * chosen by the client. For example, if the initial CID is set
 * to { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05 } the
 * qlog files will be named:
 *  - deadbeef0102030405.client.qlog (on the client)
 *  - deadbeef0102030405.server.qlog (on the server)
 * This works well if clients follow the guidance in RFC9000 and set the
 * files to a random value, with only a very small chance of collisions.
 * But if the client use non standard names, the risk of collision
 * increases.
 * 
 * Setting the "use unique log names" option causes the insertion
 * of a random 16 bit string in the name, as in:
 *  - deadbeef0102030405.a1ea.server.qlog (on the server)
 * Setting the option to 0 restores the default behavior.
 */
void picoquic_use_unique_log_names(picoquic_quic_t* quic, int use_unique_log_names);

/* Require randomization of initial PN numbers */
void picoquic_set_random_initial(picoquic_quic_t* quic, int random_initial);

/* Set the "packet train" mode for pacing */
void picoquic_set_packet_train_mode(picoquic_quic_t* quic, int train_mode);

/* set the padding policy.
 * The padding policy is parameterized by two variables:
 * - packets shorter than padding_min_size will be padded to that size.
 * - if packets are longer than the min_size, they will be padded to the min size plus
 *   the nearest multiple of the "padding multiple", or to the path MTU.
 *
 * Padding is done before encryption, and before adding the AEAD checksum.
 *
 * The default value of the min size is set to 39 to enable the reset process.
 * By default, the multiple is set to zero.
 * 
 * When using "packet trains", it is a good idea to also set the padding multiple, because that
 * ensures that most packets will be padded to full path MTU length.
 */
void picoquic_set_padding_policy(picoquic_quic_t* quic, uint32_t padding_min_size, uint32_t padding_multiple);

/* Require Picoquic to log the session keys in the specified files.
 * Instead of calling this API directly, consider calling the 
 * function picoquic_set_key_log_file_from_env() defined in 
 * picosocks.h */
void picoquic_set_key_log_file(picoquic_quic_t* quic, char const* keylog_filename);

/* Set the ESNI key.
 * May be called several times to set several keys.
 */
int picoquic_esni_load_key(picoquic_quic_t * quic, char const * esni_key_file_name);

/* Set the ESNI RR. Must be called after setting the ESNI key at least once. */
int picoquic_esni_server_setup(picoquic_quic_t * quic, char const * esni_rr_file_name);

/* Adjust maximum connections allowed to the specified value.
 * The maximum number cannot be set to a value higher than the limit set when the context was
 * created. Trying higher values has no effect.
 */
int picoquic_adjust_max_connections(picoquic_quic_t * quic, uint32_t max_nb_connections);

/* Get number of open connections */
uint32_t picoquic_current_number_connections(picoquic_quic_t * quic);

/* Obtain the reasons why a connection was closed */
void picoquic_get_close_reasons(picoquic_cnx_t* cnx, uint64_t* local_reason,
    uint64_t* remote_reason, uint64_t* local_application_reason,
    uint64_t* remote_application_reason);

/* Will be called to verify that the given data corresponds to the given signature.
 * This callback and the `verify_ctx` will be set by the `verify_certificate_cb_fn`.
 * If `data` and `sign` are empty buffers, an error occurred and `verify_ctx` should be freed.
 * Expect `0` as return value, when the data matches the signature.
 */

typedef int (*picoquic_verify_sign_cb_fn)(void* verify_ctx, ptls_iovec_t data, ptls_iovec_t sign);
/* Will be called to verify a certificate of a connection.
 * The arguments `verify_sign` and `verify_sign_ctx` are expected to be set, when the function returns `0`.
 * See `verify_sign_cb_fn` for more information about these arguments.
 */
typedef int (*picoquic_verify_certificate_cb_fn)(void* ctx, picoquic_cnx_t* cnx, ptls_iovec_t* certs, size_t num_certs,
                                                 picoquic_verify_sign_cb_fn* verify_sign, void** verify_sign_ctx);

/* Is called to free the verify certificate ctx */
typedef void (*picoquic_free_verify_certificate_ctx)(void* ctx);

/* Management of the blocked port list */
int picoquic_check_port_blocked(uint16_t port);
int picoquic_check_addr_blocked(const struct sockaddr* addr_from);
void picoquic_disable_port_blocking(picoquic_quic_t* quic, int is_port_blocking_disabled);

/* QUIC context create and dispose */
picoquic_quic_t* picoquic_create(uint32_t max_nb_connections,
    char const* cert_file_name, char const* key_file_name, char const * cert_root_file_name,
    char const* default_alpn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    picoquic_connection_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_data,
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    uint64_t current_time,
    uint64_t* p_simulated_time,
    char const* ticket_file_name,
    const uint8_t* ticket_encryption_key,
    size_t ticket_encryption_key_length);

void picoquic_free(picoquic_quic_t* quic);

/* Preference for low memory options.
 * setting this flag instructs picoquic to chose implementations of algorithms 
 * that use less memory while maintaining reasonable performance. For example,
 * choose the openssl implementation of AES instead of the fusion implementation,
 * which is a bit faster but requires an additional 7KB of data per connection */
int picoquic_set_low_memory_mode(picoquic_quic_t* quic, int low_memory_mode);

/* management of retry policy.
 * The cookie mode can be used to force the following behavior:
 * - if cookie_mode&1, check the token and force a retry for each incoming connection.
 * - if cookie&2, provide a token to the client after completing the handshake.
 * When the "force retry" is not set, the code will count the number of "half-open" 
 * connections. This can happen for example if the server is subject to a DDOS attack.
 * If the threshold is exceeded, the code will request a token before accepting new
 * connections, forcing DDOS attackers to reveal their IP address.
 * By default, the threshold is set to 128 connections.
 */
void picoquic_set_cookie_mode(picoquic_quic_t* quic, int cookie_mode);

/* Set cipher suite, for tests. 
 * 0: default values
 * 20: chacha20poly1305sha256
 * 128: aes128gcmsha256
 * 256: aes256gcmsha384
 * returns 0 if OK, -1 if the specified ciphersuite is not supported.
 */
int picoquic_set_cipher_suite(picoquic_quic_t* quic, int cipher_suite_id);

/* Set key exchange algorithms, for tests.
 * 0: default values
 * 20: x25519
 * 128: secp256r1
 * 256: secp256r1
 * returns 0 if OK, -1 if the specified ciphersuite is not supported.
 */
int picoquic_set_key_exchange(picoquic_quic_t* quic, int key_exchange_id);

/* Init of transport parameters per quic context */
int picoquic_set_default_tp(picoquic_quic_t* quic, picoquic_tp_t* tp);
/* Set the transport parameters per connection */
void picoquic_set_transport_parameters(picoquic_cnx_t * cnx, picoquic_tp_t const * tp);
/* Get the transport parameters per connection */
picoquic_tp_t const* picoquic_get_transport_parameters(picoquic_cnx_t* cnx, int get_local);

/* Set the TLS certificate chain(DER format) for the QUIC context. The context will take ownership over the certs pointer. */
void picoquic_set_tls_certificate_chain(picoquic_quic_t* quic, ptls_iovec_t* certs, size_t count);

/* Set the TLS root certificates (DER format) for the QUIC context. The context will take ownership over the certs pointer.
 * The root certificates will be used to verify the certificate chain of the server and client (with client authentication activated).
 * Returns `0` on success, `-1` on error while loading X509 certificate or `-2` on error while adding a cert to the certificate store.
 */
int picoquic_set_tls_root_certificates(picoquic_quic_t* quic, ptls_iovec_t* certs, size_t count);

/* Tell the TLS stack to not attempt verifying certificates */
void picoquic_set_null_verifier(picoquic_quic_t* quic);

/* Set the TLS private key(DER format) for the QUIC context. The caller is responsible for cleaning up the pointer. */
int picoquic_set_tls_key(picoquic_quic_t* quic, const uint8_t* data, size_t len);

/* Set the verify certificate callback and context. */
typedef struct st_ptls_verify_certificate_t ptls_verify_certificate_t;
int picoquic_set_verify_certificate_callback(picoquic_quic_t* quic, 
    ptls_verify_certificate_t * cb, picoquic_free_verify_certificate_ctx free_fn);

/* Set client authentication in TLS (if enabled, client is required to send certificates). */
void picoquic_set_client_authentication(picoquic_quic_t* quic, int client_authentication);

/* By default, a quic context authorizes incoming connections if the certificate and
 * private key are provided, but if client authentication is required the client context
 * will also have certificaye and key. In that case, the function "enforce_client_only"
 * can be used to specify a pure client (do_enforce=1). For peer-to-peer application
 * that expect both incoming connections, there is no need to call that API, but it
 * could be used with "do_enforce = 0". */
void picoquic_enforce_client_only(picoquic_quic_t* quic, int do_enforce);

/* Set default padding policy for the context */
void picoquic_set_default_padding(picoquic_quic_t* quic, uint32_t padding_multiple, uint32_t padding_minsize);

/* Set default spin bit policy for the context */
void picoquic_set_default_spinbit_policy(picoquic_quic_t * quic, picoquic_spinbit_version_enum default_spinbit_policy);

/* Set default loss bit policy for the context */
void picoquic_set_default_lossbit_policy(picoquic_quic_t* quic, picoquic_lossbit_version_enum default_lossbit_policy);

/* Set the multipath option for the context */
void picoquic_set_default_multipath_option(picoquic_quic_t* quic, int multipath_option);

/* Set the length of a crypto epoch -- force rotation after that many packets sent */
void picoquic_set_default_crypto_epoch_length(picoquic_quic_t* quic, uint64_t crypto_epoch_length_max);

uint64_t picoquic_get_default_crypto_epoch_length(picoquic_quic_t* quic);

/* Get the local CID length */
uint8_t picoquic_get_local_cid_length(picoquic_quic_t* quic);

/* Check whether a CID is locally defined */
int picoquic_is_local_cid(picoquic_quic_t* quic, picoquic_connection_id_t* cid);

/* Manage session tickets and retry tokens.
 * There is no explicit call to load tickets, this must be done by passing
 * the ticket store name as an argument to picoquic_create().
 */
int picoquic_load_retry_tokens(picoquic_quic_t* quic, char const* token_store_filename);
int picoquic_save_session_tickets(picoquic_quic_t* quic, char const* ticket_store_filename);
int picoquic_save_retry_tokens(picoquic_quic_t* quic, char const* token_store_filename);

/* Manage bdps */
void picoquic_set_default_bdp_frame_option(picoquic_quic_t* quic, int enable_bdp_frame);

/* Set default connection ID length for the context.
 * All valid values are supported on the client.
 * Using a null value on the server is not tested, may not work.
 * Cannot be changed if there are active connections in the context.
 * Value must be compatible with what the cnx_id_callback() expects on a server */
int picoquic_set_default_connection_id_length(picoquic_quic_t* quic, uint8_t cid_length);

void picoquic_set_default_connection_id_ttl(picoquic_quic_t* quic, uint64_t ttl_usec);

uint64_t picoquic_get_default_connection_id_ttl(picoquic_quic_t* quic);

/* Setting the max mtu that can be found or tried using path MTU discovery.
 * The API uses the traditional definition of the path MTU. The size of 
 * packet sent is the sum of the lengths of IPv4 or IPv6 header (20 or 40 bytes),
 * UDP header (8 bytes) and UDP payload. The QUIC stack can only control the
 * size of the udp payload, which is negotiated through transport parameters
 * during the handshake. The negotiated value will be set by subtracting
 * from the "mtu_max" parameter the estimated IP and UDP over, which depends
 * on the IP address used for the connection and is computed using the
 * macro "PICOQUIC_MTU_OVERHEAD".
 */
#define PICOQUIC_MTU_OVERHEAD(p_s_addr) (((p_s_addr)->sa_family==AF_INET6)?48:28)
void picoquic_set_mtu_max(picoquic_quic_t* quic, uint32_t mtu_max);


/* Set the ALPN function used to verify incoming ALPN */
void picoquic_set_alpn_select_fn(picoquic_quic_t* quic, picoquic_alpn_select_fn alpn_select_fn);

/* Set the default callback function for new connections.
 * This must be defined for every server implementation.
 */
void picoquic_set_default_callback(picoquic_quic_t * quic, picoquic_stream_data_cb_fn callback_fn, void * callback_ctx);

/* Set the minimum interval between consecutive stateless reset packets.
 * This limits the potential blowback of stateless reset packets when nder DoS attacks.
 * A value of zero will set no interval.
 * Default to PICOQUIC_MICROSEC_STATELESS_RESET_INTERVAL_DEFAULT
 */
void picoquic_set_default_stateless_reset_min_interval(picoquic_quic_t* quic, uint64_t min_interval_usec);

/* Set and get the maximum number of simultaneously logged connections.
* If that number is too high, the maximum number of open files will be hit 
* at random places in the code. A small value means that some connections may
* not be logged. Default is set to 32. */
void picoquic_set_max_simultaneous_logs(picoquic_quic_t* quic, uint32_t max_simultaneous_logs);
uint32_t picoquic_get_max_simultaneous_logs(picoquic_quic_t* quic);

/* Connection context creation and registration */
picoquic_cnx_t* picoquic_create_cnx(picoquic_quic_t* quic,
    picoquic_connection_id_t initial_cnx_id, picoquic_connection_id_t remote_cnx_id,
    const struct sockaddr* addr_to, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn, char client_mode);

picoquic_cnx_t* picoquic_create_client_cnx(picoquic_quic_t* quic,
    struct sockaddr* addr, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx);

int picoquic_start_client_cnx(picoquic_cnx_t* cnx);

/* Closing the quic connection can be done in one of three ways.
 *
 * The function "picoquic_close" performs an ordered close. The "reason code"
 * is sent to the peer, and should be visible by the peer's application,
 * unless of course the peer discards the connection before receiving
 * the closing message. The action is delayed until the next
 * packet can be sent.
 * 
 * The function "picoquic_close_immediate" performs an abrupt close. The
 * connection will immediately move to a "draining" state, no more
 * packets will be sent, no information will be provided to the peer.
 * The connection context will be kept for a very
 * limited time, until it can be safely deleted.
 * This should be safe to use inclduing inside a picoquic callback,
 * but it is a bit experimental. Please file an issue if you see a problem.
 * 
 * The function "picoquic_delete_cnx" deletes all the resource associated
 * with the connection, including the connection context. Any reference
 * to the context after making this call will cause an error, which
 * makes it unsafe to use inside a callback.
 */
int picoquic_close(picoquic_cnx_t* cnx, uint16_t application_reason_code);

void picoquic_close_immediate(picoquic_cnx_t* cnx);

void picoquic_delete_cnx(picoquic_cnx_t* cnx);

/* Support for version negotiation:
 * Setting the "desired version" parameter will trigger compatible version
 * negotiation from the current version to that desired version, if the
 * server supports the desired version.
 * If starting the connection with a new version after receiving a VN packet,
 * setting the "rejected version" parameter will provide protection against
 * downgrade attacks.
 * These parameters must be set before starting the connection.
 */

void picoquic_set_desired_version(picoquic_cnx_t* cnx, uint32_t desired_version);
void picoquic_set_rejected_version(picoquic_cnx_t* cnx, uint32_t rejected_version);

/* Support for encrypted SNI*/
int picoquic_esni_client_from_file(picoquic_cnx_t * cnx, char const * esni_rr_file_name);

/* Connection events.
 * The "probe new path" API attempts to validate a new path. If multipath is enabled,
 * the new path will come in addition to the set of existing paths; if not,
 * the new path when validated will replace the default path.
 * The "abandon path" should only be used if multipath is enabled, and if more than
 * one path is available -- otherwise, just close the connection. If the command
 * is accepted, the peer will be informed of the need to close the path, and the
 * path will be demoted after a short delay.
 */
int picoquic_probe_new_path(picoquic_cnx_t* cnx, const struct sockaddr* addr_from,
    const struct sockaddr* addr_to, uint64_t current_time);
int picoquic_abandon_path(picoquic_cnx_t* cnx, int path_id, uint64_t reason, char const* phrase);

int picoquic_renew_connection_id(picoquic_cnx_t* cnx, int path_id);

int picoquic_start_key_rotation(picoquic_cnx_t * cnx);

picoquic_quic_t* picoquic_get_quic_ctx(picoquic_cnx_t* cnx);
picoquic_cnx_t* picoquic_get_first_cnx(picoquic_quic_t* quic);
picoquic_cnx_t* picoquic_get_next_cnx(picoquic_cnx_t* cnx);
int64_t picoquic_get_next_wake_delay(picoquic_quic_t* quic,
    uint64_t current_time,
    int64_t delay_max);
int64_t picoquic_get_wake_delay(picoquic_cnx_t* cnx,
    uint64_t current_time,
    int64_t delay_max);
picoquic_cnx_t* picoquic_get_earliest_cnx_to_wake(picoquic_quic_t* quic, uint64_t max_wake_time);

uint64_t picoquic_get_next_wake_time(picoquic_quic_t* quic, uint64_t current_time);

picoquic_state_enum picoquic_get_cnx_state(picoquic_cnx_t* cnx);

void picoquic_cnx_set_padding_policy(picoquic_cnx_t * cnx, uint32_t padding_multiple, uint32_t padding_minsize);
void picoquic_cnx_get_padding_policy(picoquic_cnx_t * cnx, uint32_t * padding_multiple, uint32_t * padding_minsize);
/* Set spin bit policy for the connection */
void picoquic_cnx_set_spinbit_policy(picoquic_cnx_t * cnx, picoquic_spinbit_version_enum spinbit_policy);

/* Set max packet interval between key rotations */
void picoquic_set_crypto_epoch_length(picoquic_cnx_t* cnx, uint64_t crypto_epoch_length_max);
uint64_t picoquic_get_crypto_epoch_length(picoquic_cnx_t* cnx);

/* Set the PMTU discovery policy
 * The API picoquic_cnx_set_pmtud_required is obsolete, should use instead:
 * for is_pmtud_required = 0: picoquic_cnx_set_pmtud_policy(cnx, picoquic_pmtud_basic)
 * for is_pmtud_required = 1: picoquic_cnx_set_pmtud_policy(cnx, picoquic_pmtud_required)
 */
void picoquic_set_default_pmtud_policy(picoquic_quic_t* quic, picoquic_pmtud_policy_enum pmtud_policy);
void picoquic_cnx_set_pmtud_policy(picoquic_cnx_t* cnx, picoquic_pmtud_policy_enum pmtud_policy);
void picoquic_cnx_set_pmtud_required(picoquic_cnx_t* cnx, int is_pmtud_required);

/* Check whether the handshake is of type PSK*/
int picoquic_tls_is_psk_handshake(picoquic_cnx_t* cnx);

/* Manage addresses */
void picoquic_get_peer_addr(picoquic_cnx_t* cnx, struct sockaddr** addr);
void picoquic_get_local_addr(picoquic_cnx_t* cnx, struct sockaddr** addr);
unsigned long picoquic_get_local_if_index(picoquic_cnx_t* cnx);

int picoquic_set_local_addr(picoquic_cnx_t* cnx, struct sockaddr* addr);

/* Manage connection IDs*/
picoquic_connection_id_t picoquic_get_local_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_remote_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_initial_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_client_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_server_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_logging_cnxid(picoquic_cnx_t* cnx);

/* Manage connections */
uint64_t picoquic_get_cnx_start_time(picoquic_cnx_t* cnx);
uint64_t picoquic_is_0rtt_available(picoquic_cnx_t* cnx);

int picoquic_is_cnx_backlog_empty(picoquic_cnx_t* cnx);

void picoquic_set_callback(picoquic_cnx_t* cnx,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx);

picoquic_stream_data_cb_fn picoquic_get_default_callback_function(picoquic_quic_t * quic);

void * picoquic_get_default_callback_context(picoquic_quic_t * quic);

picoquic_stream_data_cb_fn picoquic_get_callback_function(picoquic_cnx_t * cnx);

void * picoquic_get_callback_context(picoquic_cnx_t* cnx);

/* Send extra frames */
int picoquic_queue_misc_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length, int is_pure_ack);

/* Queue a datagram frame for sending later.
 * The datagram length must be no more than PICOQUIC_DATAGRAM_QUEUE_MAX_LENGTH,
 * i.e., must fit in the minimum packet length supported by Quic. Trying to
 * queue a larger datagram will result in an error PICOQUIC_ERROR_DATAGRAM_TOO_LONG.
 */
#define PICOQUIC_DATAGRAM_QUEUE_MAX_LENGTH 1200
int picoquic_queue_datagram_frame(picoquic_cnx_t* cnx, size_t length, const uint8_t* bytes);

/* The incoming packet API is used to pass incoming packets to a 
 * Quic context. The API handles the decryption of the packets
 * and their processing in the context of connections.
 */

int picoquic_incoming_packet(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time);

int picoquic_incoming_packet_ex(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t packet_length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    picoquic_cnx_t** first_cnx,
    uint64_t current_time);

/* Applications must regularly poll the "next packet" API to obtain the
 * next packet that will be set over the network. The API for that is
 * picoquic_prepare_next_packet", which operates on a "quic context".
 * The API "picoquic_prepare_packet" does the same but for just one
 * connection at a time. 
 */

int picoquic_prepare_next_packet_ex(picoquic_quic_t* quic, 
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length, 
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index,
    picoquic_connection_id_t* log_cid, picoquic_cnx_t** p_last_cnx, size_t* send_msg_size);

int picoquic_prepare_next_packet(picoquic_quic_t* quic,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index,
    picoquic_connection_id_t* p_logcid, picoquic_cnx_t** p_last_cnx);

int picoquic_prepare_packet_ex(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index,
    size_t* send_msg_size);

int picoquic_prepare_packet(picoquic_cnx_t* cnx,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    struct sockaddr_storage* p_addr_to, struct sockaddr_storage* p_addr_from, int* if_index);

/* Socket error signalling.
 * The application code is in charge of sending the packets prepared by the stack
 * to the designated network address. If the stack tries to send a packet to an unreachable
 * destination, the application may get an error indication from the socket "sendmsg"
 * API, or its equivalent. Passing the error back to the stack allows for better
 * handling, for example closing a connection immediately if the peer's address is
 * unreachable, or cancelling a migration attempt if the new path is not available.
 *
 * The signalling is per connection, using the connection context signalled for example
 * in the p_last_cnx parameter to the picoquic_prepare_next_packet API. The p_addr_to
 * parameter indicates the peer's address, the destination of the failed transmission.
 * The p_addr_from parameter indicates the source address provided by the 
 * picoquic_prepare_next_packet API, the if_index parameter indicates the interface ID
 * suggested by the stack. The socket_err parameter may be used by the stack for logging
 * purposes.
 */
void picoquic_notify_destination_unreachable(picoquic_cnx_t* cnx,
     uint64_t current_time, struct sockaddr* addr_peer, struct sockaddr* addr_local, int if_index, int socket_err);
void picoquic_notify_destination_unreachable_by_cnxid(picoquic_quic_t* quic, picoquic_connection_id_t * cnxid,
    uint64_t current_time, struct sockaddr* addr_peer, struct sockaddr* addr_local, int if_index, int socket_err);

/* Handling of out of sequence stream data delivery.
 *
 * For applications like video communication, it is important to process stream data
 * as soon as it arrives, even if it arrives out of order. For example, it might be
 * better to play the next video frame than to wait for the complete transmission
 * of the previous one. Picoquic enables that with the "direct receive" marking. If
 * a stream is marked as "direct receive", picoquic will hand data receive on
 * that stream to the application immediately, even if it is out of sequence.
 * 
 * The data will be delivered to a direct receive callback function, which will
 * pass the pointer to the data, the stream offset and length of the data, and
 * also indicates if a fin mark was received. When the fin mark is present, the
 * fin offset of the stream is located at the sum of offset and length, and
 * the length may be null.
 *
 * The function picoquic_mark_direct_receive_stream is used to mark a stream
 * as `direct receive` and provide the callback function and context for that
 * stream. Calling that function with a NULL callback function pointer results
 * in an error.
 *
 * If stream data was queued at the time the picoquic_mark_direct_receive_stream
 * function is called, the callback will be activated immediately.
 *
 * The callback function shall return:
 * - 0 if the data was processed normally.
 * - PICOQUIC_STREAM_RECEIVE_COMPLETE if the fin bit was received once and all
 *   expected bytes on the stream have been received.
 * - An appropriate error code if an error was encountered.
 *
 * Returning an error code will cause picoquic to close the connection with the
 * corresponding transport error, or PICOQUIC_TRANSPORT_INTERNAL_ERROR if the
 * error code in the range of the PICOQUIC_ERROR_CLASS.
 */

typedef int (*picoquic_stream_direct_receive_fn)(picoquic_cnx_t* cnx,
    uint64_t stream_id, int fin, const uint8_t* bytes, uint64_t offset, size_t length,
    void* direct_receive_ctx);

int picoquic_mark_direct_receive_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, picoquic_stream_direct_receive_fn direct_receive_fn, void* direct_receive_ctx);

/* Associate stream with app context */
int picoquic_set_app_stream_ctx(picoquic_cnx_t* cnx,
    uint64_t stream_id, void* app_stream_ctx);

/* Mark stream as active, or not.
 * If a stream is active, it will be polled for data when the transport
 * is ready to send. The polling will only start after all currently
 * queued data has been sent.
 */
int picoquic_mark_active_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_active, void* v_stream_ctx);

/* Mark stream as high priority. This guarantees that the data
 * queued on this stream will be sent before data from any other
 * stream. It is used for example in the HTTP3 implementation
 * to guarantee that the "settings" frame is sent from the
 * control stream before any other frame. 
 * Priority is immediately removed when all data from that
 * stream is sent; it should be reset if new data is added 
 * for which priority handling is still required. 
 * Priority is also removed if the "is_high_priority"
 * parameter is set to 0, or if another stream is set
 * to high priority.
 */

int picoquic_mark_high_priority_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_high_priority);

/* If a stream is marked active, the application will receive a callback with
 * event type "picoquic_callback_prepare_to_send" when the transport is ready to
 * send data on a stream. The "length" argument in the call back indicates the
 * largest amount of data that can be sent, and the "bytes" argument points
 * to an opaque context structure. In order to prepare data, the application
 * needs to call "picoquic_provide_stream_data_buffer" with that context
 * pointer, with the number of bytes that it wants to write, with an indication
 * of whether or not the fin of the stream was reached, and also an indication
 * of whether or not the stream is still active. The function
 * returns the pointer to a memory address where to write the byte -- or
 * a NULL pointer in case of error. The application then copies the specified 
 * number of bytes at the provided address, and provide a return code 0 from
 * the callback in case of success, or non zero in case of error.
 */

uint8_t* picoquic_provide_stream_data_buffer(void* context, size_t nb_bytes, int is_fin, int is_still_active);

/* Queue data on a stream, so the transport can send it immediately
 * when ready. The data is copied in an intermediate buffer managed by
 * the transport. Calling this API automatically erases the "active
 * mark" that might have been set by using "picoquic_mark_active_stream".
 * It also erases the "app_stream_ctx" value set in previous calls to
 * picoquic_add_to_stream_with_ctx or picoquic_mark_active_stream
 */
int picoquic_add_to_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, const uint8_t* data, size_t length, int set_fin);

void picoquic_reset_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id);

/* Same as "picoquic_add_to_stream", but also sets the application stream context.
 * The context is used in call backs, so the application can directly process responses.
 */
int picoquic_add_to_stream_with_ctx(picoquic_cnx_t * cnx, uint64_t stream_id, const uint8_t * data, size_t length, int set_fin, void * app_stream_ctx);

/* Reset a stream, indicating that no more data will be sent on 
 * that stream and that any data currently queued can be abandoned. */
int picoquic_reset_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error);

/* Open the flow control for receiving the expected data on a stream */
int picoquic_open_flow_control(picoquic_cnx_t* cnx, uint64_t stream_id, uint64_t expected_data_size);

/* Obtain the next available stream ID in the local category */
uint64_t picoquic_get_next_local_stream_id(picoquic_cnx_t* cnx, int is_unidir);

/* Ask the peer to stop sending on a stream. The peer is expected
 * to reset that stream when receiving the "stop sending" signal. */
int picoquic_stop_sending(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error);

/* Discard stream. This is equivalent to sending a stream reset
 * and a stop sending request, and also setting the app context
 * of the stream to NULL */
int picoquic_discard_stream(picoquic_cnx_t* cnx, uint64_t stream_id, uint16_t local_stream_error);

/* The function picoquic_set_datagram_ready indicates to the stack
 * whether the application is ready to send datagrams. */
int picoquic_mark_datagram_ready(picoquic_cnx_t* cnx, int is_ready);

/* If a datagram is marked active, the application will receive a callback with
 * event type "picoquic_callback_prepare_datagram" when the transport is ready to
 * send data on a stream. The "length" argument in the call back indicates the
 * largest amount of data that can be sent, and the "bytes" argument points
 * to an opaque context structure. In order to prepare data, the application
 * needs to call "picoquic_provide_datagram_buffer" with that context
 * pointer, and with the number of bytes that it wants to write. The function
 * returns the pointer to a memory address where to write the bytes -- or
 * a NULL pointer in case of error. The application then copies the specified
 * number of bytes at the provided address, and provide a return code 0 from
 * the callback in case of success, or non zero in case of error.
 */
uint8_t* picoquic_provide_datagram_buffer(void* context, size_t length);

/* 
 * Set the optimistic ack policy. The holes will be inserted at random locations,
 * which in average will be separated by the pseudo period. By default,
 * the pseudo perio is 0, which means no hole insertion.
 */
void picoquic_set_optimistic_ack_policy(picoquic_quic_t* quic, uint32_t sequence_hole_pseudo_period);

/* Enable or disable the preemptive repeat function
 */
void picoquic_set_preemptive_repeat_policy(picoquic_quic_t* quic, int do_repeat);
void picoquic_set_preemptive_repeat_per_cnx(picoquic_cnx_t* cnx, int do_repeat);

/* Enables keep alive for a connection.
 * Keep alive interval is expressed in microseconds.
 * If `interval` is `0`, it is set to `idle_timeout / 2`.
 */
void picoquic_enable_keep_alive(picoquic_cnx_t* cnx, uint64_t interval);
/* Disables keep alive for a connection. */
void picoquic_disable_keep_alive(picoquic_cnx_t* cnx);

/* Returns if the given connection is the client. */
int picoquic_is_client(picoquic_cnx_t* cnx);

/* Returns the local error of the given connection context. */
uint64_t picoquic_get_local_error(picoquic_cnx_t* cnx);

/* Returns the remote error of the given connection context. */
uint64_t picoquic_get_remote_error(picoquic_cnx_t* cnx);

/* Returns the application error after application close */
uint64_t picoquic_get_application_error(picoquic_cnx_t* cnx);

/* Returns the remote error for the given stream. */
uint64_t picoquic_get_remote_stream_error(picoquic_cnx_t* cnx, uint64_t stream_id);


uint64_t picoquic_get_data_sent(picoquic_cnx_t * cnx);

uint64_t picoquic_get_data_received(picoquic_cnx_t * cnx);

int picoquic_cnx_is_still_logging(picoquic_cnx_t* cnx);

/* Congestion algorithm definition */

typedef enum {
    picoquic_congestion_notification_acknowledgement,
    picoquic_congestion_notification_repeat,
    picoquic_congestion_notification_timeout,
    picoquic_congestion_notification_spurious_repeat,
    picoquic_congestion_notification_rtt_measurement,
    picoquic_congestion_notification_bw_measurement,
    picoquic_congestion_notification_ecn_ec,
    picoquic_congestion_notification_cwin_blocked,
    picoquic_congestion_notification_seed_cwin,
    picoquic_congestion_notification_reset
} picoquic_congestion_notification_t;

typedef void (*picoquic_congestion_algorithm_init)(picoquic_path_t* path_x, uint64_t current_time);
typedef void (*picoquic_congestion_algorithm_notify)(
    picoquic_cnx_t* cnx,
    picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    uint64_t rtt_measurement,
    uint64_t one_way_delay,
    uint64_t nb_bytes_acknowledged,
    uint64_t lost_packet_number,
    uint64_t current_time);
typedef void (*picoquic_congestion_algorithm_delete)(picoquic_path_t* cnx);
typedef void (*picoquic_congestion_algorithm_observe)(
    picoquic_path_t* path_x, uint64_t * cc_state, uint64_t * cc_param);

typedef struct st_picoquic_congestion_algorithm_t {
    char const * congestion_algorithm_id;
    uint8_t congestion_algorithm_number;
    picoquic_congestion_algorithm_init alg_init;
    picoquic_congestion_algorithm_notify alg_notify;
    picoquic_congestion_algorithm_delete alg_delete;
    picoquic_congestion_algorithm_observe alg_observe;
} picoquic_congestion_algorithm_t;

extern picoquic_congestion_algorithm_t* picoquic_newreno_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_cubic_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_dcubic_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_fastcc_algorithm;
extern picoquic_congestion_algorithm_t* picoquic_bbr_algorithm;

#define PICOQUIC_DEFAULT_CONGESTION_ALGORITHM picoquic_newreno_algorithm;

picoquic_congestion_algorithm_t const* picoquic_get_congestion_algorithm(char const* alg_name);

void picoquic_set_default_congestion_algorithm(picoquic_quic_t* quic, picoquic_congestion_algorithm_t const* algo);

void picoquic_set_default_congestion_algorithm_by_name(picoquic_quic_t* quic, char const* alg_name);

void picoquic_set_congestion_algorithm(picoquic_cnx_t* cnx, picoquic_congestion_algorithm_t const* algo);

/* Bandwidth update and congestion control parameters value.
 * Congestion control in picoquic is characterized by three values:
 * - pacing rate, expressed in bytes per second (for example, 10Mbps would be noted as 1250000)
 * - congestion window, expressed in bytes
 * - RTT, expressed in microseconds
 * 
 * If an application subscribes to pacing rate updates, it will start receiving callback events
 * of type "picoquic_callback_pacing_changed". The subscription to the updates specifies
 * two levels:
 * - decrease threshold, in bytes per second
 * - increase threshold, in bytes per second
 * An event will be generated each time the bandwidth increases or decreases by a value
 * larger than the specified threshold. The "stream_id" parameter of the callback will 
 * indicate the new pacing rate, in bytes per second.
 *
 * By default, the threshold values are set to UINT64_MAX, and no event is generated.
 * 
 * Applications may also use a set of accessor functions to obtain the current values
 * of the key congestion control parameters, for the currently selected transmission
 * path.
 */

void picoquic_subscribe_pacing_rate_updates(picoquic_cnx_t* cnx, uint64_t decrease_threshold, uint64_t increase_threshold);
uint64_t picoquic_get_pacing_rate(picoquic_cnx_t* cnx);
uint64_t picoquic_get_cwin(picoquic_cnx_t* cnx);
uint64_t picoquic_get_rtt(picoquic_cnx_t* cnx);

#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_H */
