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

#ifndef PICOQUIC_INTERNAL_H
#define PICOQUIC_INTERNAL_H

#include "picoquic.h"
#include "picohash.h"
#include "picotlsapi.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define PICOQUIC_MAX_PACKET_SIZE 1536
#define PICOQUIC_INITIAL_MTU_IPV4 1252
#define PICOQUIC_INITIAL_MTU_IPV6 1232
#define PICOQUIC_ENFORCED_INITIAL_MTU 1200
#define PICOQUIC_RESET_SECRET_SIZE 16

	/*
	* Supported versions
	*/
#define PICOQUIC_FIRST_INTEROP_VERSION   0xFF000005
#define PICOQUIC_INTERNAL_TEST_VERSION_1 0x50435130 

	extern const uint32_t picoquic_supported_versions[];
	extern const size_t picoquic_nb_supported_versions;
	typedef enum {
		picoquic_version_negotiate_transport = 1
	} picoquic_version_feature_flags;

	/*
	* Quic context flags
	*/
	typedef enum {
		picoquic_context_server = 1
	} picoquic_context_flags;


	/*
	 * QUIC context, defining the tables of connections,
	 * open sockets, etc.
	 */
	typedef struct st_picoquic_quic_t
	{
		void* tls_master_ctx;
		picoquic_stream_data_cb_fn default_callback_fn;
		void * default_callback_ctx;
		char const * default_alpn;
		uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE];

		uint32_t flags;

		picoquic_stateless_packet_t * pending_stateless_packet;

		struct st_picoquic_cnx_t * cnx_list;
		struct st_picoquic_cnx_t * cnx_last;

		picohash_table * table_cnx_by_id;
		picohash_table * table_cnx_by_net;
	} picoquic_quic_t;


	/*
	* Transport parameters, as defined by the QUIC transport specification
	*/

	typedef struct _picoquic_transport_parameters {
		uint32_t initial_max_stream_data;
		uint32_t initial_max_data;
		uint32_t initial_max_stream_id;
		uint32_t idle_timeout;
		uint32_t omit_connection_id;
		uint32_t max_packet_size;
	} picoquic_transport_parameters;

	/*
	 * SACK dashboard item, part of connection context.
	 */

	typedef struct _picoquic_sack_item {
		struct _picoquic_sack_item * next_sack;
		uint64_t start_of_sack_range;
		uint64_t end_of_sack_range;
		uint64_t time_stamp_last_in_range;
	} picoquic_sack_item;

	/*
	 * Types of frames
	 */
	typedef enum {
		picoquic_frame_type_padding = 0,
		picoquic_frame_type_reset_stream = 1,
		picoquic_frame_type_connection_close = 2,
		picoquic_frame_type_goaway = 3,
		picoquic_frame_type_max_data = 4,
		picoquic_frame_type_max_stream_data = 5,
		picoquic_frame_type_max_stream_id = 6,
		picoquic_frame_type_ping = 7,
		picoquic_frame_type_blocked = 8,
		picoquic_frame_type_stream_blocked = 9,
		picoquic_frame_type_stream_id_needed = 0x0a,
		picoquic_frame_type_new_connection_id = 0x0b,
		picoquic_frame_type_ack_range_min = 0xa0,
		picoquic_frame_type_ack_range_max = 0xbf,
		picoquic_frame_type_stream_range_min = 0xc0,
		picoquic_frame_type_stream_range_max = 0xcf
	} picoquic_frame_type_enum_t;

	/*
	 * Stream head.
	 * Stream contains bytes of data, which are not always delivered in order.
	 * When in order data is available, the application can read it,
	 * or a callback can be set.
	 */

	typedef struct _picoquic_stream_data {
		struct _picoquic_stream_data * next_stream_data;
		uint64_t offset;
		size_t length;
		uint8_t * bytes;
	} picoquic_stream_data;

	typedef enum picoquic_stream_flags {
		picoquic_stream_flag_fin_received = 1,
		picoquic_stream_flag_fin_signalled = 2,
		picoquic_stream_flag_fin_notified = 4,
		picoquic_stream_flag_fin_sent = 8,
		picoquic_stream_flag_reset_requested = 16,
		picoquic_stream_flag_reset_sent = 32,
		picoquic_stream_flag_reset_received = 64,
		picoquic_stream_flag_reset_signalled = 128
	} picoquic_stream_flags;

	typedef struct _picoquic_stream_head {
		struct _picoquic_stream_head * next_stream;
		uint32_t stream_id;
		uint32_t stream_flags;
		uint64_t consumed_offset;
		uint64_t fin_offset;
		uint32_t local_error;
		uint32_t remote_error;
		picoquic_stream_data * stream_data;
		uint64_t sent_offset;
		picoquic_stream_data * send_queue;
	} picoquic_stream_head;

	/*
	 * Packet sent, and queued for retransmission.
	 * The packet is not encrypted.
	 */

	typedef enum
	{
		picoquic_packet_error = 0,
		picoquic_packet_version_negotiation = 1,
		picoquic_packet_client_initial = 2,
		picoquic_packet_server_stateless = 3,
		picoquic_packet_server_cleartext = 4,
		picoquic_packet_client_cleartext = 5,
		picoquic_packet_0rtt_protected = 6,
		picoquic_packet_1rtt_protected_phi0 = 7,
		picoquic_packet_1rtt_protected_phi1 = 8,
		picoquic_packet_type_max = 9
	} picoquic_packet_type_enum;

	/*
	 * Per connection context.
	 */
	typedef struct st_picoquic_cnx_t
	{
		picoquic_quic_t * quic;

		/* Management of context retrieval tables */
		struct st_picoquic_cnx_t * next_in_table;
		struct st_picoquic_cnx_t * previous_in_table;
		struct st_picoquic_cnx_id_t * first_cnx_id;
		struct st_picoquic_net_id_t * first_net_id;

		/* Proposed and negotiated version. Feature flags denote version dependent features */
		uint32_t proposed_version;
		uint32_t version;
		uint32_t versioned_features_flags;

		/* Local and remote parameters */
		picoquic_transport_parameters local_parameters;
		picoquic_transport_parameters remote_parameters;
		/* On clients, document the SNI and ALPN expected from the server */
		/* TODO: there may be a need to propose multiple ALPN */
		char const * sni;
		char const * alpn;
		/* Call back function and context */
		picoquic_stream_data_cb_fn callback_fn;
		void * callback_ctx;

		/* connection state, ID, etc. Todo: allow for multiple cnxid */
		picoquic_state_enum cnx_state;
		uint64_t initial_cnxid;
		uint64_t server_cnxid;
		struct sockaddr_storage peer_address;
		uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
		uint32_t local_error;
		uint32_t remote_error;

		/* TLS context, TLS Send Buffer, chain of receive buffers (todo) */
		void * tls_ctx;
		struct st_ptls_buffer_t * tls_sendbuf;
		uint64_t send_sequence;
		uint32_t send_mtu;

		/* Encryption and decryption objects */
		void * aead_encrypt_ctx;
		void * aead_decrypt_ctx;

		/* Receive state */
		struct _picoquic_sack_item first_sack_item;
		uint64_t sack_block_size_max;
		uint64_t highest_ack_sent;
		uint64_t highest_ack_time;

		/* Retransmission state */
		uint64_t nb_retransmit;
		uint64_t latest_retransmit_time;
		uint64_t highest_acknowledged;
		uint64_t latest_time_acknowledged;
		uint64_t latest_ack_received_time;
		picoquic_packet * retransmit_newest;
		picoquic_packet * retransmit_oldest;

		/* Management of streams */
		picoquic_stream_head first_stream;

	} picoquic_cnx_t;

	/* Handling of stateless packets */
	picoquic_stateless_packet_t * picoquic_create_stateless_packet(picoquic_quic_t * quic);
	void picoquic_queue_stateless_packet(picoquic_quic_t * quic, picoquic_stateless_packet_t * sp);

	/* handling of retransmission queue */
	void picoquic_enqueue_retransmit_packet(picoquic_cnx_t * cnx, picoquic_packet * p);
	void picoquic_dequeue_retransmit_packet(picoquic_cnx_t * cnx, picoquic_packet * p, int should_free);

	/* Reset connection after receiving version negotiation */
	int picoquic_reset_cnx_version(picoquic_cnx_t * cnx, uint8_t * bytes, size_t length);

	/* Connection context retrieval functions */
	picoquic_cnx_t * picoquic_cnx_by_id(picoquic_quic_t * quic, uint64_t cnx_id);
	picoquic_cnx_t * picoquic_cnx_by_net(picoquic_quic_t * quic, struct sockaddr* addr);

	/* Integer parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0])<<8)|(b)[1])
#define PICOPARSE_24(b) ((((uint32_t)PICOPARSE_16(b))<<16)|((b)[2]))
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b))<<16)|PICOPARSE_16((b)+2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b))<<32)|PICOPARSE_32((b)+4))

	/* Integer formatting functions */
	void picoformat_16(uint8_t *bytes, uint16_t n16);
	void picoformat_32(uint8_t *bytes, uint32_t n32);
	void picoformat_64(uint8_t *bytes, uint64_t n64);

	/* utilities */
	char * picoquic_string_create(const char * original, size_t len);
	char * picoquic_string_duplicate(const char * original);

	/* Packet parsing */


	typedef struct _picoquic_packet_header {
		uint64_t cnx_id;
		uint32_t pn;
		uint32_t vn;
		uint32_t offset;
		picoquic_packet_type_enum ptype;
		uint64_t pnmask;
		uint64_t pn64;
	} picoquic_packet_header;

	int picoquic_parse_packet_header(
		uint8_t * bytes,
		size_t length,
		picoquic_packet_header * ph);

	uint64_t picoquic_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn);

	/* handling of ACK logic */
	int picoquic_is_ack_needed(picoquic_cnx_t * cnx, uint64_t current_time);

	int picoquic_is_pn_already_received(picoquic_cnx_t * cnx, uint64_t pn64);
	int picoquic_record_pn_received(picoquic_cnx_t * cnx, uint64_t pn64, uint64_t current_microsec);
	uint16_t picoquic_deltat_to_float16(uint64_t delta_t);
	uint64_t picoquic_float16_to_deltat(uint16_t float16);

	/* stream management */
	picoquic_stream_head * picoquic_find_stream(picoquic_cnx_t * cnx, uint32_t stream_id, int create);
	picoquic_stream_head * picoquic_find_ready_stream(picoquic_cnx_t * cnx, int restricted);
	int picoquic_stream_network_input(picoquic_cnx_t * cnx, uint32_t stream_id,
		uint64_t offset, int fin, uint8_t * bytes, size_t length);
	int picoquic_decode_stream_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
		size_t bytes_max, int restricted, size_t * consumed);
	int picoquic_prepare_stream_frame(picoquic_cnx_t * cnx, picoquic_stream_head * stream,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);
	int picoquic_prepare_ack_frame(picoquic_cnx_t * cnx, uint64_t current_time,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);
	int picoquic_prepare_connection_close_frame(picoquic_cnx_t * cnx,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);

	/* send/receive */

	int picoquic_decode_frames(picoquic_cnx_t * cnx, uint8_t * bytes,
		size_t bytes_max, int restricted);

	int picoquic_skip_frame(uint8_t * bytes, size_t bytes_max, size_t * consumed, int * pure_ack);

	int picoquic_prepare_transport_extensions(picoquic_cnx_t * cnx, int extension_mode,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);

	int picoquic_receive_transport_extensions(picoquic_cnx_t * cnx, int extension_mode,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);

#ifdef  __cplusplus
}
#endif
#endif /* PICOQUIC_INTERNAL_H */
