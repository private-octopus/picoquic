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

#define PICOQUIC_ERROR_CLASS 0x400
#define PICOQUIC_ERROR_DUPLICATE (PICOQUIC_ERROR_CLASS + 1)
#define PICOQUIC_ERROR_FNV1A_CHECK (PICOQUIC_ERROR_CLASS + 2)
#define PICOQUIC_ERROR_AEAD_CHECK (PICOQUIC_ERROR_CLASS + 3)
#define PICOQUIC_ERROR_UNEXPECTED_PACKET (PICOQUIC_ERROR_CLASS + 4)
#define PICOQUIC_ERROR_MEMORY (PICOQUIC_ERROR_CLASS + 5)
#define PICOQUIC_ERROR_SPURIOUS_REPEAT (PICOQUIC_ERROR_CLASS + 6)
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
#define PICOQUIC_ERROR_HRR (PICOQUIC_ERROR_CLASS + 19)
#define PICOQUIC_ERROR_DISCONNECTED (PICOQUIC_ERROR_CLASS + 20)
#define PICOQUIC_ERROR_DETECTED (PICOQUIC_ERROR_CLASS + 21)
#define PICOQUIC_ERROR_CANNOT_STOP_STREAM_ZERO (PICOQUIC_ERROR_CLASS + 22)
#define PICOQUIC_ERROR_INVALID_TICKET (PICOQUIC_ERROR_CLASS + 23)
#define PICOQUIC_ERROR_INVALID_FILE (PICOQUIC_ERROR_CLASS + 24)
#define PICOQUIC_ERROR_SEND_BUFFER_TOO_SMALL (PICOQUIC_ERROR_CLASS + 25)
#define PICOQUIC_ERROR_UNEXPECTED_STATE (PICOQUIC_ERROR_CLASS + 26)
#define PICOQUIC_ERROR_UNEXPECTED_ERROR (PICOQUIC_ERROR_CLASS + 27)
#define PICOQUIC_ERROR_TLS_SERVER_CON_WITHOUT_CERT (PICOQUIC_ERROR_CLASS + 28)

/*
 * Protocol errors defined in the QUIC spec
 */
#define PICOQUIC_TRANSPORT_INTERNAL_ERROR (0x1)
#define PICOQUIC_TRANSPORT_SERVER_BUSY (0x2)
#define PICOQUIC_TRANSPORT_FLOW_CONTROL_ERROR (0x3)
#define PICOQUIC_TRANSPORT_STREAM_ID_ERROR (0x4)
#define PICOQUIC_TRANSPORT_STREAM_STATE_ERROR (0x5)
#define PICOQUIC_TRANSPORT_FINAL_OFFSET_ERROR (0x6)
#define PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR (0x7)
#define PICOQUIC_TRANSPORT_TRANSPORT_PARAMETER_ERROR (0x8)
#define PICOQUIC_TRANSPORT_VERSION_NEGOTIATION_ERROR (0x9)
#define PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION (0xA)
#define PICOQUIC_TRANSPORT_UNSOLICITED_PATH_RESPONSE (0xB)
#define PICOQUIC_TRANSPORT_FRAME_ERROR(FrameType) (0x100 | ((int)FrameType))
#define PICOQUIC_TLS_HANDSHAKE_FAILED (0x201)
#define PICOQUIC_TLS_FATAL_ALERT_GENERATED (0x202)
#define PICOQUIC_TLS_FATAL_ALERT_RECEIVED (0x203)

#define PICOQUIC_MAX_PACKET_SIZE 1536
#define PICOQUIC_RESET_SECRET_SIZE 16

/*
* Connection states, useful to expose the state to the application.
*/
typedef enum {
    picoquic_state_client_init,
    picoquic_state_client_init_sent,
    picoquic_state_client_renegotiate,
    picoquic_state_client_hrr_received,
    picoquic_state_client_init_resent,
    picoquic_state_server_init,
    picoquic_state_client_handshake_start,
    picoquic_state_client_handshake_progress,
    picoquic_state_handshake_failure,
    picoquic_state_client_almost_ready,
    picoquic_state_server_almost_ready,
    picoquic_state_client_ready,
    picoquic_state_server_ready,
    picoquic_state_disconnecting,
    picoquic_state_closing_received,
    picoquic_state_closing,
    picoquic_state_draining,
    picoquic_state_disconnected,
    picoquic_state_server_send_hrr
} picoquic_state_enum;


/*
* Quic context flags
*/
typedef enum {
    picoquic_context_check_cookie = 1,
    picoquic_context_unconditional_cnx_id = 2,
    picoquic_context_client_zero_share = 4
} picoquic_context_flags;

/*
 * Provisional definition of the connection ID.
 */
#define PICOQUIC_CONNECTION_ID_SIZE 8

typedef struct st_picoquic_connection_id_t {
    uint64_t opaque64;
} picoquic_connection_id_t;

/*
* The stateless packet structure is used to temporarily store
* stateless packets before they can be sent by servers.
*/

typedef struct st_picoquic_stateless_packet_t {
    struct st_picoquic_stateless_packet_t* next_packet;
    struct sockaddr_storage addr_to;
    struct sockaddr_storage addr_local;
    unsigned long if_index_local;
    size_t length;

    uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
} picoquic_stateless_packet_t;

/*
	 * The simple packet structure is used to store packets that
	 * have been sent but are not yet acknowledged.
	 * Packets are stored in unencrypted format.
	 * The checksum length is the difference between encrypted and unencrypted.
	 */
typedef struct _picoquic_packet {
    struct _picoquic_packet* previous_packet;
    struct _picoquic_packet* next_packet;

    uint64_t sequence_number;
    uint64_t send_time;
    uint32_t length;
    uint32_t checksum_overhead;
    struct st_picoquic_path_t * send_path;

    uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
} picoquic_packet;

typedef struct st_picoquic_quic_t picoquic_quic_t;
typedef struct st_picoquic_cnx_t picoquic_cnx_t;
typedef struct st_picoquic_path_t picoquic_path_t;

typedef enum {
    picoquic_callback_no_event = 0,
    picoquic_callback_stream_fin,
    picoquic_callback_stream_reset,
    picoquic_callback_stop_sending,
    picoquic_callback_close,
    picoquic_callback_application_close
} picoquic_call_back_event_t;

/* Callback function for providing stream data to the application.
     * If stream_id is zero, this delivers misc frames or changes in
     * connection state.
     */
typedef void (*picoquic_stream_data_cb_fn)(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx);

typedef void (*cnx_id_cb_fn)(picoquic_connection_id_t cnx_id_local,
    picoquic_connection_id_t cnx_id_remote, void* cnx_id_cb_data, picoquic_connection_id_t * cnx_id_returned);

/* Will be called to verify that the given data corresponds to the given signature.
 * This callback and the `verify_ctx` will be set by the `verify_certificate_cb_fn`.
 * If `data` and `sign` are empty buffers, an error occurred and `verify_ctx` should be freed.
 * Expect `0` as return value, when the data matches the signature.
 */
typedef struct st_ptls_iovec_t ptls_iovec_t; /* forward definition to avoid full dependency on picotls.h */
typedef int (*picoquic_verify_sign_cb_fn)(void* verify_ctx, ptls_iovec_t data, ptls_iovec_t sign);
/* Will be called to verify a certificate of a connection.
 * The arguments `verify_sign` and `verify_sign_ctx` are expected to be set, when the function returns `0`.
 * See `verify_sign_cb_fn` for more information about these arguments.
 */
typedef int (*picoquic_verify_certificate_cb_fn)(void* ctx, picoquic_cnx_t* cnx, ptls_iovec_t* certs, size_t num_certs,
                                                 picoquic_verify_sign_cb_fn* verify_sign, void** verify_sign_ctx);

/* Is called to free the verify certificate ctx */
typedef void (*picoquic_free_verify_certificate_ctx)(void* ctx);

/* QUIC context create and dispose */
picoquic_quic_t* picoquic_create(uint32_t nb_connections,
    char const* cert_file_name, char const* key_file_name,
    char const* default_alpn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    cnx_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_data,
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    uint64_t current_time,
    uint64_t* p_simulated_time,
    char const* ticket_file_name,
    const uint8_t* ticket_encryption_key,
    size_t ticket_encryption_key_length);

void picoquic_free(picoquic_quic_t* quic);

/* Set cookie mode on QUIC context when under stress */
void picoquic_set_cookie_mode(picoquic_quic_t* quic, int cookie_mode);

/* Set the verify certificate callback and context. */
int picoquic_set_verify_certificate_callback(picoquic_quic_t* quic, picoquic_verify_certificate_cb_fn cb, void* ctx,
                                             picoquic_free_verify_certificate_ctx free_fn);

/* Connection context creation and registration */
picoquic_cnx_t* picoquic_create_cnx(picoquic_quic_t* quic,
    picoquic_connection_id_t cnx_id, struct sockaddr* addr, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn, char client_mode);

picoquic_cnx_t* picoquic_create_client_cnx(picoquic_quic_t* quic,
    struct sockaddr* addr, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx);

int picoquic_start_client_cnx(picoquic_cnx_t* cnx);

void picoquic_delete_cnx(picoquic_cnx_t* cnx);

int picoquic_close(picoquic_cnx_t* cnx, uint16_t reason_code);

picoquic_cnx_t* picoquic_get_first_cnx(picoquic_quic_t* quic);
picoquic_cnx_t* picoquic_get_next_cnx(picoquic_cnx_t* cnx);
int64_t picoquic_get_next_wake_delay(picoquic_quic_t* quic,
    uint64_t current_time,
    int64_t delay_max);
picoquic_cnx_t* picoquic_get_earliest_cnx_to_wake(picoquic_quic_t* quic, uint64_t max_wake_time);

picoquic_state_enum picoquic_get_cnx_state(picoquic_cnx_t* cnx);

int picoquic_tls_is_psk_handshake(picoquic_cnx_t* cnx);

void picoquic_get_peer_addr(picoquic_cnx_t* cnx, struct sockaddr** addr, int* addr_len);
void picoquic_get_local_addr(picoquic_cnx_t* cnx, struct sockaddr** addr, int* addr_len);
unsigned long picoquic_get_local_if_index(picoquic_cnx_t* cnx);

picoquic_connection_id_t picoquic_get_cnxid(picoquic_cnx_t* cnx);
picoquic_connection_id_t picoquic_get_initial_cnxid(picoquic_cnx_t* cnx);
uint64_t picoquic_get_cnx_start_time(picoquic_cnx_t* cnx);
uint64_t picoquic_is_0rtt_available(picoquic_cnx_t* cnx);

int picoquic_is_cnx_backlog_empty(picoquic_cnx_t* cnx);

void picoquic_set_callback(picoquic_cnx_t* cnx,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx);

/* Send extra frames */
int picoquic_queue_misc_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length);

/* Send and receive network packets */

picoquic_stateless_packet_t* picoquic_dequeue_stateless_packet(picoquic_quic_t* quic);
void picoquic_delete_stateless_packet(picoquic_stateless_packet_t* sp);

int picoquic_incoming_packet(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    uint64_t current_time);

picoquic_packet* picoquic_create_packet();

int picoquic_prepare_packet(picoquic_cnx_t* cnx, picoquic_packet* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length);

/* send and receive data on streams */
int picoquic_add_to_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, const uint8_t* data, size_t length, int set_fin);

int picoquic_reset_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error);

int picoquic_stop_sending(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint16_t local_stream_error);

/* Congestion algorithm definition */
typedef enum {
    picoquic_congestion_notification_acknowledgement,
    picoquic_congestion_notification_repeat,
    picoquic_congestion_notification_timeout,
    picoquic_congestion_notification_spurious_repeat,
    picoquic_congestion_notification_rtt_measurement
} picoquic_congestion_notification_t;

typedef void (*picoquic_congestion_algorithm_init)(picoquic_path_t* path_x);
typedef void (*picoquic_congestion_algorithm_notify)(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    uint64_t rtt_measurement,
    uint64_t nb_bytes_acknowledged,
    uint64_t lost_packet_number,
    uint64_t current_time);
typedef void (*picoquic_congestion_algorithm_delete)(picoquic_path_t* cnx);

typedef struct st_picoquic_congestion_algorithm_t {
    uint32_t congestion_algorithm_id;
    picoquic_congestion_algorithm_init alg_init;
    picoquic_congestion_algorithm_notify alg_notify;
    picoquic_congestion_algorithm_delete alg_delete;
} picoquic_congestion_algorithm_t;

void picoquic_set_default_congestion_algorithm(picoquic_quic_t* quic, picoquic_congestion_algorithm_t const* algo);

void picoquic_set_congestion_algorithm(picoquic_cnx_t* cnx, picoquic_congestion_algorithm_t const* algo);

/* For building a basic HTTP 0.9 test server */
int http0dot9_get(uint8_t* command, size_t command_length,
    uint8_t* response, size_t response_max, size_t* response_length);

/* Enables keep alive for a connection.
 * If `interval` is `0`, it is set to `idle_timeout / 2`.
 */
void picoquic_enable_keep_alive(picoquic_cnx_t* cnx, uint64_t interval);
/* Disables keep alive for a connection. */
void picoquic_disable_keep_alive(picoquic_cnx_t* cnx);

/* Returns if the given connection is the client. */
int picoquic_is_client(picoquic_cnx_t* cnx);

/* Returns the local error of the given connection context. */
int picoquic_get_local_error(picoquic_cnx_t* cnx);

/* Returns the remote error of the given connection context. */
int picoquic_get_remote_error(picoquic_cnx_t* cnx);

#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_H */
