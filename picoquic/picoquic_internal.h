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
#include "util.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define PICOQUIC_MAX_PACKET_SIZE 1536
#define PICOQUIC_INITIAL_MTU_IPV4 1252
#define PICOQUIC_INITIAL_MTU_IPV6 1232
#define PICOQUIC_ENFORCED_INITIAL_MTU 1200
#define PICOQUIC_RETRY_SECRET_SIZE 64

#define PICOQUIC_INITIAL_RTT 250000 /* 250 ms */
#define PICOQUIC_INITIAL_RETRANSMIT_TIMER 1000000 /* one second */
#define PICOQUIC_MIN_RETRANSMIT_TIMER 50000 /* 50 ms */
#define PICOQUIC_ACK_DELAY_MAX 20000 /* 20 ms */

#define PICOQUIC_MICROSEC_SILENCE_MAX 120000000 /* 120 seconds for now */
#define PICOQUIC_MICROSEC_WAIT_MAX 10000000 /* 10 seconds for now */

#define PICOQUIC_CWIN_INITIAL  (10*PICOQUIC_MAX_PACKET_SIZE)
#define PICOQUIC_CWIN_MINIMUM  (2*PICOQUIC_MAX_PACKET_SIZE)

	/*
	* Supported versions
	*/
#define PICOQUIC_FIRST_INTEROP_VERSION   0xFF000005
#define PICOQUIC_SECOND_INTEROP_VERSION  0xFF000007
#define PICOQUIC_INTERNAL_TEST_VERSION_1 0x50435130 

    typedef enum {
        picoquic_version_basic_time_stamp = 1,
        picoquic_version_long_error_codes = 2,
        picoquic_version_use_fnv1a = 4
    } picoquic_version_feature_flags;

    typedef struct st_picoquic_version_parameters_t {
        uint32_t version;
        uint32_t version_flags;
        size_t version_aead_key_length;
        uint8_t * version_aead_key;
    } picoquic_version_parameters_t;

    extern const picoquic_version_parameters_t picoquic_supported_versions[];
	extern const size_t picoquic_nb_supported_versions;
    int picoquic_get_version_index(uint32_t proposed_version);

	/*
	 * Quic context flags
	 */
	typedef enum {
		picoquic_context_server = 1,
		picoquic_context_check_cookie = 2,
		picoquic_context_unconditional_cnx_id = 4
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
        uint8_t retry_seed[PICOQUIC_RETRY_SECRET_SIZE];

		uint32_t flags;

		picoquic_stateless_packet_t * pending_stateless_packet;

		picoquic_congestion_algorithm_t const * default_congestion_alg;

		struct st_picoquic_cnx_t * cnx_list;
		struct st_picoquic_cnx_t * cnx_last;

		picohash_table * table_cnx_by_id;
		picohash_table * table_cnx_by_net;

		cnx_id_cb_fn cnx_id_callback_fn;
		void * cnx_id_callback_ctx;
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

	typedef struct st_picoquic_sack_item_t {
		struct st_picoquic_sack_item_t * next_sack;
		uint64_t start_of_sack_range;
		uint64_t end_of_sack_range;
		// uint64_t time_stamp_last_in_range;
	} picoquic_sack_item_t;

	/*
	 * Types of frames
	 */
	typedef enum {
		picoquic_frame_type_padding = 0,
		picoquic_frame_type_reset_stream = 1,
		picoquic_frame_type_connection_close = 2,
		picoquic_frame_type_application_close = 3,
		picoquic_frame_type_max_data = 4,
		picoquic_frame_type_max_stream_data = 5,
		picoquic_frame_type_max_stream_id = 6,
		picoquic_frame_type_ping = 7,
		picoquic_frame_type_blocked = 8,
		picoquic_frame_type_stream_blocked = 9,
		picoquic_frame_type_stream_id_needed = 0x0a,
		picoquic_frame_type_new_connection_id = 0x0b,
        picoquic_frame_type_stop_sending = 0x0c,
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
		picoquic_stream_flag_reset_signalled = 128,
        picoquic_stream_flag_stop_sending_requested = 256,
        picoquic_stream_flag_stop_sending_sent = 512,
        picoquic_stream_flag_stop_sending_received = 1024,
        picoquic_stream_flag_stop_sending_signalled = 2048
	} picoquic_stream_flags;

	typedef struct _picoquic_stream_head {
		struct _picoquic_stream_head * next_stream;
		uint32_t stream_id;
		uint32_t stream_flags;
		uint64_t consumed_offset;
		uint64_t fin_offset;
		uint64_t maxdata_local;
		uint64_t maxdata_remote;
		uint32_t local_error;
		uint32_t remote_error;
        uint32_t local_stop_error;
        uint32_t remote_stop_error;
		picoquic_stream_data * stream_data;
		uint64_t sent_offset;
		picoquic_stream_data * send_queue;
        picoquic_sack_item_t first_sack_item;
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
		// uint32_t version;
        int version_index;
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

        /* Peer address. To do: allow for multiple addresses */
        struct sockaddr_storage peer_addr;
        int peer_addr_len;

		/* connection state, ID, etc. Todo: allow for multiple cnxid */
		picoquic_state_enum cnx_state;
		uint64_t initial_cnxid;
		uint64_t server_cnxid;
        uint64_t start_time;
		uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
        uint32_t application_error;
		uint32_t local_error;
        uint32_t remote_application_error;
		uint32_t remote_error;

        /* Next time sending data is expected */
        uint64_t next_wake_time;

		/* TLS context, TLS Send Buffer, chain of receive buffers (todo) */
		void * tls_ctx;
		struct st_ptls_buffer_t * tls_sendbuf;
		uint64_t send_sequence;
		uint32_t send_mtu;

        /* Liveness detection */
        uint64_t latest_progress_time; /* last local time at which the connection progressed */

		/* Encryption and decryption objects */
        void * aead_encrypt_cleartext_ctx;
        void * aead_decrypt_cleartext_ctx;
        void * aead_de_encrypt_cleartext_ctx; /* used by logging functions to see what is sent. */
		void * aead_encrypt_ctx; 
		void * aead_decrypt_ctx;
        void * aead_de_encrypt_ctx; /* used by logging functions to see what is sent. */

		/* Receive state */
		picoquic_sack_item_t first_sack_item;
        uint64_t time_stamp_largest_received;
		uint64_t sack_block_size_max;
		uint64_t highest_ack_sent;
		uint64_t highest_ack_time;
		int ack_needed;

		/* Time measurement */
		uint64_t smoothed_rtt;
		uint64_t rtt_variant;
		uint64_t retransmit_timer;
		uint64_t rtt_min;

		/* Retransmission state */
		uint64_t nb_retransmit;
		uint64_t latest_retransmit_time;
		uint64_t highest_acknowledged; 
		uint64_t latest_time_acknowledged; /* time at which the highest acknowledged was sent */
		picoquic_packet * retransmit_newest;
		picoquic_packet * retransmit_oldest;

		/* Congestion control state */
		uint64_t cwin;
		uint64_t bytes_in_transit;
		void * congestion_alg_state;
		picoquic_congestion_algorithm_t const * congestion_alg;

		/* Flow control information */
		uint64_t data_sent;
		uint64_t data_received;
		uint64_t maxdata_local;
		uint64_t maxdata_remote;
		uint32_t highest_stream_id_local;
		uint32_t highest_stream_id_remote;
		uint32_t max_stream_id_local;
		uint32_t max_stream_id_remote;

		/* Management of streams */
		picoquic_stream_head first_stream;

	} picoquic_cnx_t;

    /* Init of transport parameters */
    void picoquic_init_transport_parameters(picoquic_transport_parameters * tp);

	/* Handling of stateless packets */
	picoquic_stateless_packet_t * picoquic_create_stateless_packet(picoquic_quic_t * quic);
	void picoquic_queue_stateless_packet(picoquic_quic_t * quic, picoquic_stateless_packet_t * sp);

    /* Registration of connection ID in server context */
    int picoquic_register_cnx_id(picoquic_quic_t * quic, picoquic_cnx_t * cnx, uint64_t cnx_id);

	/* handling of retransmission queue */
	void picoquic_enqueue_retransmit_packet(picoquic_cnx_t * cnx, picoquic_packet * p);
	void picoquic_dequeue_retransmit_packet(picoquic_cnx_t * cnx, picoquic_packet * p, int should_free);

	/* Reset connection after receiving version negotiation */
	int picoquic_reset_cnx_version(picoquic_cnx_t * cnx, uint8_t * bytes, size_t length);

    /* Notify error on connection */
    int picoquic_connection_error(picoquic_cnx_t * cnx, uint32_t local_error);

	/* Connection context retrieval functions */
	picoquic_cnx_t * picoquic_cnx_by_id(picoquic_quic_t * quic, uint64_t cnx_id);
	picoquic_cnx_t * picoquic_cnx_by_net(picoquic_quic_t * quic, struct sockaddr* addr);

    /* Next time is used to order the list of available connections,
     * so ready connections are polled first */
    void picoquic_reinsert_by_wake_time(picoquic_quic_t * quic, picoquic_cnx_t * cnx);

    void picoquic_cnx_set_next_wake_time(picoquic_cnx_t * cnx, uint64_t current_time);

	/* Integer parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0])<<8)|(b)[1])
#define PICOPARSE_24(b) ((((uint32_t)PICOPARSE_16(b))<<16)|((b)[2]))
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b))<<16)|PICOPARSE_16((b)+2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b))<<32)|PICOPARSE_32((b)+4))

	/* Integer formatting functions */
	void picoformat_16(uint8_t *bytes, uint16_t n16);
	void picoformat_32(uint8_t *bytes, uint32_t n32);
	void picoformat_64(uint8_t *bytes, uint64_t n64);

    size_t picoquic_varint_encode(uint8_t *bytes, size_t max_bytes, uint64_t n64);
    size_t picoquic_varint_decode(uint8_t *bytes, size_t max_bytes, uint64_t * n64);

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

    int picoquic_parse_stream_header(
		const uint8_t * bytes, size_t bytes_max,
		uint32_t * stream_id, uint64_t * offset, size_t * data_length,
		size_t * consumed);

	int picoquic_parse_ack_header(
		uint8_t const * bytes, size_t bytes_max, uint64_t target_sequence,
		unsigned * num_block, unsigned * num_ts, uint64_t * largest,
		uint64_t * ack_delay, unsigned * mm, size_t * consumed,
        uint32_t version_flags);
  
	uint64_t picoquic_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn);

    size_t picoquic_decrypt_cleartext(picoquic_cnx_t * cnx,
        uint8_t * bytes, size_t length, picoquic_packet_header * ph);

	/* handling of ACK logic */
	int picoquic_is_ack_needed(picoquic_cnx_t * cnx, uint64_t current_time);

	int picoquic_is_pn_already_received(picoquic_cnx_t * cnx, uint64_t pn64);
	int picoquic_record_pn_received(picoquic_cnx_t * cnx, uint64_t pn64, uint64_t current_microsec);
	uint16_t picoquic_deltat_to_float16(uint64_t delta_t);
	uint64_t picoquic_float16_to_deltat(uint16_t float16);

    int picoquic_update_sack_list(picoquic_sack_item_t * sack,
        uint64_t pn64_min, uint64_t pn64_max,
        uint64_t * sack_block_size_max);
    /*
     * Check whether the data fills a hole. returns 0 if it does, -1 otherwise.
     */
    int picoquic_check_sack_list(picoquic_sack_item_t * sack,
        uint64_t pn64_min, uint64_t pn64_max);

    /*
     * Process ack of ack
     */
    int picoquic_process_ack_of_ack_frame(
        picoquic_sack_item_t * first_sack,
        uint8_t * bytes, size_t bytes_max, size_t * consumed, uint32_t version_flags);

	/* stream management */
	picoquic_stream_head * picoquic_find_stream(picoquic_cnx_t * cnx, uint32_t stream_id, int create);
	picoquic_stream_head * picoquic_find_ready_stream(picoquic_cnx_t * cnx, int restricted);
	int picoquic_stream_network_input(picoquic_cnx_t * cnx, uint32_t stream_id,
		uint64_t offset, int fin, uint8_t * bytes, size_t length, uint64_t current_time);
	int picoquic_decode_stream_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
		size_t bytes_max, int restricted, size_t * consumed, uint64_t current_time);
	int picoquic_prepare_stream_frame(picoquic_cnx_t * cnx, picoquic_stream_head * stream,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);
	int picoquic_prepare_ack_frame(picoquic_cnx_t * cnx, uint64_t current_time,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);
	int picoquic_prepare_connection_close_frame(picoquic_cnx_t * cnx,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);
        int picoquic_prepare_application_close_frame(picoquic_cnx_t * cnx,
                uint8_t * bytes, size_t bytes_max, size_t * consumed);
	int picoquic_prepare_required_max_stream_data_frames(picoquic_cnx_t * cnx,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);
	int picoquic_prepare_max_data_frame(picoquic_cnx_t * cnx, uint64_t maxdata_increase,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);
    void picoquic_clear_stream(picoquic_stream_head * stream);

	/* send/receive */

	int picoquic_decode_frames(picoquic_cnx_t * cnx, uint8_t * bytes,
		size_t bytes_max, int restricted, uint64_t current_time);

	int picoquic_skip_frame(uint8_t * bytes, size_t bytes_max, size_t * consumed, 
        int * pure_ack, uint32_t version_flags);

    int picoquic_decode_closing_frames(picoquic_cnx_t * cnx, uint8_t * bytes,
        size_t bytes_max, int *closing_received);

	int picoquic_prepare_transport_extensions(picoquic_cnx_t * cnx, int extension_mode,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);

	int picoquic_receive_transport_extensions(picoquic_cnx_t * cnx, int extension_mode,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);

#ifdef  __cplusplus
}
#endif
#endif /* PICOQUIC_INTERNAL_H */
