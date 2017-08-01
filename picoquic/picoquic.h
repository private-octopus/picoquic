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
#include <winsock2.h>
#include <Ws2def.h>
#include <WS2tcpip.h>
#include "picohash.h"
#include "picotlsapi.h"

#ifdef  __cplusplus
extern "C" {
#endif

#define PICOQUIC_MAX_PACKET_SIZE 1536

#define PICOQUIC_ERROR_CLASS 0x400
#define PICOQUIC_ERROR_DUPLICATE (PICOQUIC_ERROR_CLASS  + 1)
#define PICOQUIC_ERROR_FNV1A_CHECK (PICOQUIC_ERROR_CLASS  + 2)
#define PICOQUIC_ERROR_AEAD_CHECK (PICOQUIC_ERROR_CLASS  + 3)
#define PICOQUIC_ERROR_UNEXPECTED_PACKET (PICOQUIC_ERROR_CLASS  + 4)
#define PICOQUIC_ERROR_MEMORY (PICOQUIC_ERROR_CLASS  + 5)
#define PICOQUIC_ERROR_SPURIOUS_REPEAT (PICOQUIC_ERROR_CLASS  + 6)

	/*
	 * Supported versions
	 */
	extern const uint32_t picoquic_supported_versions[];
	extern const size_t picoquic_nb_supported_versions;
    /*
     * Quic context flags
     */
    typedef enum {
        picoquic_context_server = 1
    } picoquic_context_flags;

	/*
	 * The stateless packet structure is used to temporarily store
	 * stateless packets before they can be sent by servers.
	 */

	typedef struct _picoquic_stateless_packet {
		struct _picoquic_packet * next_packet;
		struct sockaddr_storage addr_to;
		size_t length;

		uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
	} picoquic_stateless_packet;

    /*
     * QUIC context, defining the tables of connections,
     * open sockets, etc.
     */
    typedef struct _picoquic_quic
    {
        void* tls_master_ctx;

        uint32_t flags;

		picoquic_stateless_packet * pending_stateless_packet;

        struct _picoquic_cnx * cnx_list;
        struct _picoquic_cnx * cnx_last;

        picohash_table * table_cnx_by_id;
        picohash_table * table_cnx_by_net;
    } picoquic_quic;

    /*
     * Connection context, and links between context and addresses
     */
    typedef enum
    {
        picoquic_state_client_init, 
		picoquic_state_client_init_sent,
        picoquic_state_server_init,
        picoquic_state_client_handshake_start,
        picoquic_state_client_handshake_progress,
        picoquic_state_client_almost_ready,
        picoquic_state_client_ready,
        picoquic_state_server_handshake_progress,
        picoquic_state_server_almost_ready,
        picoquic_state_server_ready,
        picoquic_state_disconnecting,
        picoquic_state_disconnected
    } picoquic_state_enum;

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

    typedef struct _picoquic_stream_head {
        struct _picoquic_stream_head * next_stream;
        uint64_t stream_id;
        uint64_t consumed_offset;
        uint64_t fin_offset;
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
        picoquic_packet_public_reset = 9,
        picoquic_packet_type_max = 10
    } picoquic_packet_type_enum;

	/*
	 * The simple packet structure is used to store packets that
	 * have been sent but are not yet acknowledged.
	 */
    typedef struct _picoquic_packet {
        struct _picoquic_packet * previous_packet;
        struct _picoquic_packet * next_packet;

        uint64_t sequence_number;
		uint64_t send_time;
        size_t length;

        uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
    } picoquic_packet;

    /*
     * Per connection context.
     */
    typedef struct _picoquic_cnx
    {
        picoquic_quic * quic;

        /* Management of context retrieval tables */
        struct _picoquic_cnx * next_in_table;
        struct _picoquic_cnx * previous_in_table;
        struct _picoquic_cnx_id * first_cnx_id;
        struct _picoquic_net_id * first_net_id;

		/* Proposed and negotiated version */
		uint32_t proposed_version;
        uint32_t version;

        /* connection state, ID, etc. Todo: allow for multiple cnxid */
        picoquic_state_enum cnx_state;
        uint64_t initial_cnxid;
        uint64_t server_cnxid;
        struct sockaddr_storage peer_address;

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

        /* Retransmission state */
		uint64_t highest_acknowledged;
		uint64_t latest_time_acknowledged;
		uint64_t latest_ack_received_time;
		picoquic_packet * retransmit_newest;
		picoquic_packet * retransmit_oldest;

        /* Management of streams */
        picoquic_stream_head first_stream;

    } picoquic_cnx;

    /* QUIC context create and dispose */
    picoquic_quic * picoquic_create(uint32_t nb_connections, char * cert_file_name, char * key_file_name);
    void picoquic_free(picoquic_quic * quic);

	/* Handling of stateless packets */
	picoquic_stateless_packet * picoquic_create_stateless_packet(picoquic_quic * quic);
	void picoquic_delete_stateless_packet(picoquic_stateless_packet * sp);
	void picoquic_queue_stateless_packet(picoquic_quic * quic, picoquic_stateless_packet * sp);
	picoquic_stateless_packet * picoquic_dequeue_stateless_packet(picoquic_quic * quic);

    /* Connection context creation and registration */
    picoquic_cnx * picoquic_create_cnx(picoquic_quic * quic, 
        uint64_t cnx_id, struct sockaddr * addr, uint64_t start_time, uint32_t preferred_version);
    void picoquic_delete_cnx(picoquic_cnx * cnx);

    /* Connection context retrieval functions */
    picoquic_cnx * picoquic_cnx_by_id(picoquic_quic * quic, uint64_t cnx_id);
    picoquic_cnx * picoquic_cnx_by_net(picoquic_quic * quic, struct sockaddr* addr);

    int picoquic_close(picoquic_cnx * cnx);

/* Integer parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0])<<8)|(b)[1])
#define PICOPARSE_24(b) ((((uint32_t)PICOPARSE_16(b))<<16)|((b)[2]))
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b))<<16)|PICOPARSE_16((b)+2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b))<<32)|PICOPARSE_32((b)+4))

/* Integer formatting functions */
    void picoformat_16(uint8_t *bytes, uint16_t n16);
    void picoformat_32(uint8_t *bytes, uint32_t n32);
    void picoformat_64(uint8_t *bytes, uint64_t n64);

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
    int picoquic_is_pn_already_received(picoquic_cnx * cnx, uint64_t pn64);
    int picoquic_record_pn_received(picoquic_cnx * cnx, uint64_t pn64, uint64_t current_microsec);
    uint16_t picoquic_deltat_to_float16(uint64_t delta_t);
    uint64_t picoquic_float16_to_deltat(uint16_t float16);

    /* stream management */
    int picoquic_stream_input(picoquic_cnx * cnx, uint32_t stream_id, 
        uint64_t offset, int fin, uint8_t * bytes, size_t length);
    int picoquic_decode_stream_frame(picoquic_cnx * cnx, uint8_t * bytes,
        size_t bytes_max, int restricted, size_t * consumed);
    int picoquic_prepare_stream_frame(picoquic_cnx * cnx, picoquic_stream_head * stream,
        uint8_t * bytes, size_t bytes_max, size_t * consumed);
	int picoquic_prepare_ack_frame(picoquic_cnx * cnx, uint64_t current_time,
		uint8_t * bytes, size_t bytes_max, size_t * consumed);
    int picoquic_add_to_stream(picoquic_cnx * cnx, uint32_t stream_id, uint8_t * data, size_t length);
    int picoquic_prepare_connection_close_frame(picoquic_cnx * cnx,
        uint8_t * bytes, size_t bytes_max, size_t * consumed);

    /* send/receive */

	int picoquic_incoming_packet(
		picoquic_quic * quic,
		uint8_t * bytes,
		uint32_t length,
		struct sockaddr * addr_from,
		uint64_t current_time);

    picoquic_packet * picoquic_create_packet();

    int picoquic_prepare_packet(picoquic_cnx * cnx, picoquic_packet * packet,
		uint64_t current_time, uint8_t * send_buffer, size_t send_buffer_max, size_t * send_length);

    int picoquic_decode_frames(picoquic_cnx * cnx, uint8_t * bytes,
        size_t bytes_max, int restricted);

	int picoquic_skip_frame(uint8_t * bytes, size_t bytes_max, size_t * consumed, int * pure_ack);

#ifdef  __cplusplus
}
#endif

#endif /* PICOQUIC_H */
