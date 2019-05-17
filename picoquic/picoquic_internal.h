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

#include "picohash.h"
#include "picosplay.h"
#include "picoquic.h"
#include "picotlsapi.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef PICOQUIC_MAX_PACKET_SIZE
#define PICOQUIC_MAX_PACKET_SIZE 1536
#endif
#define PICOQUIC_MIN_SEGMENT_SIZE 256
#define PICOQUIC_INITIAL_MTU_IPV4 1252
#define PICOQUIC_INITIAL_MTU_IPV6 1232
#define PICOQUIC_ENFORCED_INITIAL_MTU 1200
#define PICOQUIC_ENFORCED_INITIAL_CID_LENGTH 8
#define PICOQUIC_PRACTICAL_MAX_MTU 1440
#define PICOQUIC_RETRY_SECRET_SIZE 64
#define PICOQUIC_DEFAULT_0RTT_WINDOW 4096
#define PICOQUIC_NB_PATH_TARGET 9
#define PICOQUIC_MAX_PACKETS_IN_POOL 0x8000

#define PICOQUIC_NUMBER_OF_EPOCHS 4
#define PICOQUIC_NUMBER_OF_EPOCH_OFFSETS (PICOQUIC_NUMBER_OF_EPOCHS+1)

#define PICOQUIC_INITIAL_RTT 250000 /* 250 ms */
#define PICOQUIC_TARGET_RENO_RTT 100000 /* 100 ms */
#define PICOQUIC_INITIAL_RETRANSMIT_TIMER 1000000 /* one second */
#define PICOQUIC_MIN_RETRANSMIT_TIMER 50000 /* 50 ms */
#define PICOQUIC_ACK_DELAY_MAX 10000 /* 10 ms */
#define PICOQUIC_ACK_DELAY_MAX_DEFAULT 25000 /* 25 ms, per protocol spec */
#define PICOQUIC_ACK_DELAY_MIN 1000 /* 10 ms */
#define PICOQUIC_RACK_DELAY 10000 /* 10 ms */
#define PICOQUIC_MAX_ACK_DELAY_MAX_MS 0x4000 /* 2<14 ms */
#define PICOQUIC_TOKEN_DELAY_LONG (24*60*60*1000000ull) /* 24 hours */
#define PICOQUIC_TOKEN_DELAY_SHORT (2*60*1000000ull) /* 2 minutes */

#define PICOQUIC_SPURIOUS_RETRANSMIT_DELAY_MAX 1000000 /* one second */

#define PICOQUIC_MICROSEC_SILENCE_MAX 120000000 /* 120 seconds for now */
#define PICOQUIC_MICROSEC_HANDSHAKE_MAX 15000000 /* 15 seconds for now */
#define PICOQUIC_MICROSEC_WAIT_MAX 10000000 /* 10 seconds for now */

#define PICOQUIC_CWIN_INITIAL (10 * PICOQUIC_MAX_PACKET_SIZE)
#define PICOQUIC_CWIN_MINIMUM (2 * PICOQUIC_MAX_PACKET_SIZE)

#define PICOQUIC_SPIN_RESERVE_MOD_256 17

#define PICOQUIC_CHALLENGE_REPEAT_MAX 3

/*
    * Types of frames
    */
typedef enum {
    picoquic_frame_type_padding = 0,
    picoquic_frame_type_ping = 1,
    picoquic_frame_type_ack = 0x02,
    picoquic_frame_type_ack_ecn = 0x03,
    picoquic_frame_type_reset_stream = 0x04,
    picoquic_frame_type_stop_sending = 0x05,
    picoquic_frame_type_crypto_hs = 0x06,
    picoquic_frame_type_new_token = 0x07,
    picoquic_frame_type_stream_range_min = 0x08,
    picoquic_frame_type_stream_range_max = 0x0f,
    picoquic_frame_type_max_data = 0x10,
    picoquic_frame_type_max_stream_data = 0x11,
    picoquic_frame_type_max_streams_bidir = 0x12,
    picoquic_frame_type_max_streams_unidir = 0x13,
    picoquic_frame_type_data_blocked = 0x14,
    picoquic_frame_type_stream_data_blocked = 0x15,
    picoquic_frame_type_streams_blocked_bidir = 0x16,
    picoquic_frame_type_streams_blocked_unidir = 0x17,
    picoquic_frame_type_new_connection_id = 0x18,
    picoquic_frame_type_retire_connection_id = 0x19,
    picoquic_frame_type_path_challenge = 0x1a,
    picoquic_frame_type_path_response = 0x1b,
    picoquic_frame_type_connection_close = 0x1c,
    picoquic_frame_type_application_close = 0x1d
} picoquic_frame_type_enum_t;

typedef struct st_picoquic_packet_header_t {
    picoquic_connection_id_t dest_cnx_id;
    picoquic_connection_id_t srce_cnx_id;
    uint32_t pn;
    uint32_t vn;
    uint32_t offset;
    uint32_t pn_offset;
    picoquic_packet_type_enum ptype;
    uint64_t pnmask;
    uint64_t pn64;
    uint16_t payload_length;
    int version_index;
    int epoch;
    picoquic_packet_context_enum pc;

    unsigned int key_phase : 1;
    unsigned int spin : 1;
    unsigned int has_spin_bit : 1;
    unsigned int has_reserved_bit_set : 1;

    uint32_t token_length;
    uint8_t * token_bytes;
    uint16_t pl_val;
} picoquic_packet_header;

/* PMTU discovery requirement status */

    typedef enum {
        picoquic_pmtu_discovery_not_needed = 0,
        picoquic_pmtu_discovery_optional,
        picoquic_pmtu_discovery_required
    } picoquic_pmtu_discovery_status_enum;

    /*
     * Efficient range operations that assume range containing bitfields.
     * Namely, it assumes max&min==min, min&bits==0, max&bits==bits.
     */
#define PICOQUIC_IN_RANGE(v, min, max)                  (((v) & ~((min)^(max))) == (min))
     // Is v between min and max and has all given bits set/clear?
#define PICOQUIC_BITS_SET_IN_RANGE(  v, min, max, bits) (((v) & ~((min)^(max)^(bits))) == ((min)^(bits)))
#define PICOQUIC_BITS_CLEAR_IN_RANGE(v, min, max, bits) (((v) & ~((min)^(max)^(bits))) == (min))


/*
 * Supported versions
 */
#if 0
#define PICOQUIC_FIRST_INTEROP_VERSION 0xFF000005
#define PICOQUIC_SECOND_INTEROP_VERSION 0xFF000007
#define PICOQUIC_THIRD_INTEROP_VERSION 0xFF000008
#define PICOQUIC_FOURTH_INTEROP_VERSION 0xFF000009
#define PICOQUIC_FIFTH_INTEROP_VERSION 0xFF00000B
#define PICOQUIC_SIXTH_INTEROP_VERSION 0xFF00000C
#define PICOQUIC_SEVENTH_INTEROP_VERSION 0xFF00000D
#define PICOQUIC_EIGHT_INTEROP_VERSION 0xFF00000E
#define PICOQUIC_NINTH_INTEROP_VERSION 0xFF00000F
#define PICOQUIC_NINTH_BIS_INTEROP_VERSION 0xFF000010
#define PICOQUIC_TENTH_INTEROP_VERSION 0xFF000011
#define PICOQUIC_ELEVENTH_INTEROP_VERSION 0xFF000012
#endif
#define PICOQUIC_TWELFTH_INTEROP_DRAFT19 0xFF000013
#define PICOQUIC_TWELFTH_INTEROP_VERSION 0xFF000014
#define PICOQUIC_INTERNAL_TEST_VERSION_1 0x50435130
#define PICOQUIC_INTERNAL_TEST_VERSION_2 0x50435131

#define PICOQUIC_INTEROP_VERSION_INDEX 1



 /*
  * Flags used to describe the capabilities of different versions.
  */

typedef enum {
    picoquic_version_no_flag = 0
} picoquic_version_feature_flags;


typedef void(*picoquic_spinbit_incoming_fn)(picoquic_cnx_t * cnx, picoquic_path_t * path_x, picoquic_packet_header * ph);
typedef uint8_t(*picoquic_spinbit_outgoing_fn)(picoquic_cnx_t * cnx);

typedef struct st_picoquic_spinbit_def_t {
    picoquic_spinbit_incoming_fn spinbit_incoming;
    picoquic_spinbit_outgoing_fn spinbit_outgoing;
} picoquic_spinbit_def_t;

extern picoquic_spinbit_def_t picoquic_spin_function_table[];

/*
 * Codes used for representing the various types of packet encodings.
 */
typedef enum {
    picoquic_version_header_17
} picoquic_version_header_encoding;

typedef struct st_picoquic_version_parameters_t {
    uint32_t version;
    picoquic_version_header_encoding version_header_encoding;
    size_t version_aead_key_length;
    uint8_t* version_aead_key;
} picoquic_version_parameters_t;

extern const picoquic_version_parameters_t picoquic_supported_versions[];
extern const size_t picoquic_nb_supported_versions;

int picoquic_get_version_index(uint32_t proposed_version);

/*
 * Definition of the session ticket store and connection token
 * store that can be associated with a
 * client context.
 */

typedef enum {
    picoquic_tp_0rtt_max_data = 0,
    picoquic_tp_0rtt_max_stream_data_bidi_local = 1,
    picoquic_tp_0rtt_max_stream_data_bidi_remote = 2,
    picoquic_tp_0rtt_max_stream_data_uni = 3,
    picoquic_tp_0rtt_max_streams_id_bidir = 4,
    picoquic_tp_0rtt_max_streams_id_unidir = 5
} picoquic_tp_0rtt_enum;
#define PICOQUIC_NB_TP_0RTT 6

typedef struct st_picoquic_stored_ticket_t {
    struct st_picoquic_stored_ticket_t* next_ticket;
    char* sni;
    char* alpn;
    uint64_t tp_0rtt[PICOQUIC_NB_TP_0RTT];
    uint8_t* ticket;
    uint64_t time_valid_until;
    uint16_t sni_length;
    uint16_t alpn_length;
    uint16_t ticket_length;
    unsigned int was_used : 1;
} picoquic_stored_ticket_t;

int picoquic_store_ticket(picoquic_stored_ticket_t** p_first_ticket,
    uint64_t current_time,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint8_t* ticket, uint16_t ticket_length, picoquic_tp_t const * tp);
int picoquic_get_ticket(picoquic_stored_ticket_t* p_first_ticket,
    uint64_t current_time,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint8_t** ticket, uint16_t* ticket_length, picoquic_tp_t * tp, int mark_used);

int picoquic_save_tickets(const picoquic_stored_ticket_t* first_ticket,
    uint64_t current_time, char const* ticket_file_name);
int picoquic_load_tickets(picoquic_stored_ticket_t** pp_first_ticket,
    uint64_t current_time, char const* ticket_file_name);
void picoquic_free_tickets(picoquic_stored_ticket_t** pp_first_ticket);

typedef struct st_picoquic_stored_token_t {
    struct st_picoquic_stored_token_t* next_token;
    char const* sni;
    uint8_t const* token;
    uint8_t const* ip_addr;
    uint64_t time_valid_until;
    uint16_t sni_length;
    uint16_t token_length;
    uint8_t ip_addr_length;
    unsigned int was_used : 1;
} picoquic_stored_token_t;

int picoquic_store_token(picoquic_stored_token_t** p_first_token,
    uint64_t current_time,
    char const* sni, uint16_t sni_length,
    uint8_t const* ip_addr, uint8_t ip_addr_length,
    uint8_t const* token, uint16_t token_length);
int picoquic_get_token(picoquic_stored_token_t* p_first_token,
    uint64_t current_time,
    char const* sni, uint16_t sni_length,
    uint8_t const* ip_addr, uint8_t ip_addr_length,
    uint8_t** token, uint16_t* token_length, int mark_used);

int picoquic_save_tokens(const picoquic_stored_token_t* first_token,
    uint64_t current_time, char const* token_file_name);
int picoquic_load_tokens(picoquic_stored_token_t** pp_first_token,
    uint64_t current_time, char const* token_file_name);
void picoquic_free_tokens(picoquic_stored_token_t** pp_first_token);

/*
 * Transport parameters, as defined by the QUIC transport specification
 */

typedef enum {
    picoquic_tp_original_connection_id = 0,
    picoquic_tp_idle_timeout = 1,
    picoquic_tp_stateless_reset_token = 2,
    picoquic_tp_max_packet_size = 3,
    picoquic_tp_initial_max_data = 4,
    picoquic_tp_initial_max_stream_data_bidi_local = 5,
    picoquic_tp_initial_max_stream_data_bidi_remote = 6,
    picoquic_tp_initial_max_stream_data_uni = 7,
    picoquic_tp_initial_max_streams_bidi = 8,
    picoquic_tp_initial_max_streams_uni = 9,
    picoquic_tp_ack_delay_exponent = 10,
    picoquic_tp_max_ack_delay = 11,
    picoquic_tp_disable_migration = 12,
    picoquic_tp_server_preferred_address = 13
} picoquic_tp_enum;

/*
    * QUIC context, defining the tables of connections,
    * open sockets, etc.
    */
typedef struct st_picoquic_quic_t {
    void * F_log;
    char const * cc_log_dir;
    void* tls_master_ctx;
    picoquic_stream_data_cb_fn default_callback_fn;
    void* default_callback_ctx;
    char const* default_alpn;
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE];
    uint8_t retry_seed[PICOQUIC_RETRY_SECRET_SIZE];
    uint64_t* p_simulated_time;
    char const* ticket_file_name;
    char const* token_file_name;
    picoquic_stored_ticket_t* p_first_ticket;
    picoquic_stored_token_t* p_first_token;
    uint32_t mtu_max;
    uint32_t flags;
    uint32_t padding_multiple_default;
    uint32_t padding_minsize_default;
    uint32_t sequence_hole_pseudo_period; /* Optimistic ack defense */
    picoquic_spinbit_version_enum default_spin_policy;

    picoquic_stateless_packet_t* pending_stateless_packet;

    picoquic_congestion_algorithm_t const* default_congestion_alg;

    struct st_picoquic_cnx_t* cnx_list;
    struct st_picoquic_cnx_t* cnx_last;

    struct st_picoquic_cnx_t* cnx_wake_first;
    struct st_picoquic_cnx_t* cnx_wake_last;

    picohash_table* table_cnx_by_id;
    picohash_table* table_cnx_by_net;

    picoquic_packet_t * p_first_packet;
    size_t nb_packets_in_pool;

    picoquic_connection_id_cb_fn cnx_id_callback_fn;
    void* cnx_id_callback_ctx;

    void* aead_encrypt_ticket_ctx;
    void* aead_decrypt_ticket_ctx;

    picoquic_verify_certificate_cb_fn verify_certificate_callback_fn;
    picoquic_free_verify_certificate_ctx free_verify_certificate_callback_fn;
    void* verify_certificate_ctx;
    uint8_t local_cnxid_length;

    picoquic_tp_t * default_tp;

    picoquic_fuzz_fn fuzz_fn;
    void* fuzz_ctx;
    unsigned int use_long_log : 1;
} picoquic_quic_t;

picoquic_packet_context_enum picoquic_context_from_epoch(int epoch);

/*
    * SACK dashboard item, part of connection context.
    */

typedef struct st_picoquic_sack_item_t {
    struct st_picoquic_sack_item_t* next_sack;
    uint64_t start_of_sack_range;
    uint64_t end_of_sack_range;
} picoquic_sack_item_t;

/*
    * Stream head.
    * Stream contains bytes of data, which are not always delivered in order.
    * When in order data is available, the application can read it,
    * or a callback can be set.
    */

typedef struct st_picoquic_stream_data_t {
    struct st_picoquic_stream_data_t* next_stream_data;
    uint64_t offset;  /* Stream offset of the first octet in "bytes" */
    size_t length;    /* Number of octets in "bytes" */
    uint8_t* bytes;
} picoquic_stream_data_t;

typedef struct st_picoquic_stream_head_t {
    picosplay_node_t stream_node;
    struct st_picoquic_stream_head_t * next_output_stream;
    uint64_t stream_id;
    uint64_t consumed_offset;
    uint64_t fin_offset;
    uint64_t maxdata_local;
    uint64_t maxdata_remote;
    uint32_t local_error;
    uint32_t remote_error;
    uint32_t local_stop_error;
    uint32_t remote_stop_error;
    picoquic_stream_data_t* stream_data;
    uint64_t sent_offset;
    picoquic_stream_data_t* send_queue;
    void * app_stream_ctx;
    picoquic_sack_item_t first_sack_item;
    /* Flags describing the state of the stream */
    unsigned int is_active : 1; /* The application is actively managing data sending through callbacks */
    unsigned int fin_requested : 1; /* Application has requested Fin of sending stream */
    unsigned int fin_sent : 1; /* Fin sent to peer */
    unsigned int fin_received : 1; /* Fin received from peer */
    unsigned int fin_signalled : 1; /* After Fin was received from peer, Fin was signalled to the application */
    unsigned int reset_requested : 1; /* Application has requested to reset the stream */
    unsigned int reset_sent : 1; /* Reset stream sent to peer */
    unsigned int reset_received : 1; /* Reset stream received from peer */
    unsigned int reset_signalled : 1; /* After Reset stream received from peer, application was notified */
    unsigned int stop_sending_requested : 1; /* Application has requested to stop sending */
    unsigned int stop_sending_sent : 1; /* Stop sending was sent to peer */
    unsigned int stop_sending_received : 1; /* Stop sending received from peer */
    unsigned int stop_sending_signalled : 1; /* After stop sending received from peer, application was notified */
    unsigned int max_stream_updated : 1; /* After stream was closed in both directions, the max stream id number was updated */
    unsigned int stream_data_blocked_sent : 1; /* If stream_data_blocked has been sent to peer, and no data sent on stream since */
    unsigned int is_output_stream : 1; /* If stream is listed in the output list */
} picoquic_stream_head_t;

#define IS_CLIENT_STREAM_ID(id) (unsigned int)(((id) & 1) == 0)
#define IS_BIDIR_STREAM_ID(id)  (unsigned int)(((id) & 2) == 0)
#define IS_LOCAL_STREAM_ID(id, client_mode)  (unsigned int)(((id)^(client_mode)) & 1)
#define STREAM_ID_FROM_RANK(rank, client_mode, is_unidir) (((rank)<<2)|((is_unidir)<<1)|(client_mode))
#define STREAM_RANK_FROM_ID(id) ((id)>>2)
#define STREAM_TYPE_FROM_ID(id) ((id)&3)
#define NEXT_STREAM_ID_FOR_TYPE(id) ((id)+4)
/*
 * Frame queue. This is used for miscellaneous packets, such as the PONG
 * response to a PING.
 *
 * The misc frame are allocated in meory as blobs, starting with the
 * misc_frame_header, followed by the misc frame content.
 */

typedef struct st_picoquic_misc_frame_header_t {
    struct st_picoquic_misc_frame_header_t* next_misc_frame;
    size_t length;
} picoquic_misc_frame_header_t;

/*
* Per path context.
* Path contexts are created:
* - At the beginning of the connection for path[0]
* - When advertising a new connection ID to the peer.
* When a path is created, the corresponding connection ID is added to the hash table
* of connection ID in the master QUIC context, so incoming packets can be routed to
* that path. When a path is deleted, the corresponding ID is removed from the table.
*
* On the server side, paths are activated after receiving the first packet on that path.
* The server will then schedule allocate a non-zero challenge value for the path,
* consume a connection ID advertised by the client, and allocate it as remote
* connection ID for the path. (TODO: what if no new connection ID is available?).
*
* On the client side, challenges are initially sent without creating a path context,
* by "half-consuming" a connection ID sent by the peer. Challenges can be repeated
* up to 3 times before the probe is declared lost. The first response from the
* peer will arrive on an unitialized path. The client will check whether the
* challenge value correspond to a probe, and allocate the corresponding connection
* ID to the path.
*
* As soon as a path is validated, it moves to position 0. The old path[0] moves to the
* last position, and is marked as deprecated. After about 1 RTT, the path resource
* are freed. (TODO: once we actually support multipath, change that behavior.)
* (TODO: servers should only validate the path after receiving non-probing frames from
* the client.)
*
* Congestion control and spin bit management are path specific.
* Packet numbering is global.
*/

typedef struct st_picoquic_path_t {
    /* Local connection ID identifies a path */
    picoquic_connection_id_t local_cnxid;
    picoquic_connection_id_t remote_cnxid;

    struct st_picoquic_cnx_id_key_t* first_cnx_id;
    struct st_picoquic_net_id_key_t* first_net_id;

    int path_sequence;
    uint64_t remote_cnxid_sequence;

    /* Peer address. */
    struct sockaddr_storage peer_addr;
    int peer_addr_len;
    struct sockaddr_storage local_addr;
    int local_addr_len;
    unsigned long if_index_dest;
    /* Public reset secret, provisioned by the peer */
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    /* Challenge used for this path */
    uint64_t challenge_response;
    uint64_t challenge[PICOQUIC_CHALLENGE_REPEAT_MAX];
    uint64_t challenge_time;
    uint64_t demotion_time;
    uint8_t challenge_repeat_count;
    /* Alternative address, used when validating NAT rebinding */
    struct sockaddr_storage alt_peer_addr;
    int alt_peer_addr_len;
    struct sockaddr_storage alt_local_addr;
    int alt_local_addr_len;
    unsigned long alt_if_index_dest;
    /* Challenge used for the NAT rebinding tests */
    uint64_t alt_challenge_response;
    uint64_t alt_challenge[PICOQUIC_CHALLENGE_REPEAT_MAX];
    uint64_t alt_challenge_timeout;
    uint8_t alt_challenge_repeat_count;

    /* flags */
    unsigned int mtu_probe_sent : 1;
    unsigned int path_is_published : 1;
    unsigned int path_is_activated : 1;
    unsigned int challenge_required : 1;
    unsigned int challenge_verified : 1;
    unsigned int challenge_failed : 1;
    unsigned int response_required : 1;
    unsigned int path_is_demoted : 1;
    unsigned int alt_challenge_required : 1;
    unsigned int alt_response_required : 1;
    unsigned int current_spin : 1;

    /* number of retransmissions observed on path */
    uint64_t retrans_count;

    /* Time measurement */
    uint64_t max_ack_delay;
    uint64_t smoothed_rtt;
    uint64_t rtt_variant;
    uint64_t retransmit_timer;
    uint64_t rtt_min;
    uint64_t max_spurious_rtt;
    uint64_t max_reorder_delay;
    uint64_t max_reorder_gap;

    /* MTU */
    uint32_t send_mtu;
    uint32_t send_mtu_max_tried;

    /* Congestion control state */
    uint64_t cwin;
    uint64_t bytes_in_transit;
    void* congestion_alg_state;

    /*
    * Pacing uses a set of per path variables:
    * - pacing_evaluation_time: last time the path was evaluated.
    * - pacing_bucket_nanosec: number of nanoseconds of transmission time that are allowed.
    * - pacing_bucket_max: maximum value (capacity) of the leaky bucket.
    * - pacing_packet_time_nanosec: number of nanoseconds required to send a full size packet.
    * - pacing_packet_time_microsec: max of (packet_time_nano_sec/1024, 1) microsec.
    */
    uint64_t pacing_evaluation_time;
    uint64_t pacing_bucket_nanosec;
    uint64_t pacing_bucket_max;
    uint64_t pacing_packet_time_nanosec;
    uint64_t pacing_packet_time_microsec;

} picoquic_path_t;

/* Per epoch crypto context. There are four such contexts:
* 0: Initial context, with encryption based on a version dependent key,
* 1: 0-RTT context
* 2: Handshake context
* 3: Application data
*/
typedef struct st_picoquic_crypto_context_t {
    void* aead_encrypt;
    void* aead_decrypt;
    void* pn_enc; /* Used for PN encryption */
    void* pn_dec; /* Used for PN decryption */
} picoquic_crypto_context_t;

/* Per epoch sequence/packet context.
* There are three such contexts:
* 0: Application (0-RTT and 1-RTT)
* 1: Handshake
* 2: Initial
*/

typedef struct st_picoquic_packet_context_t {
    uint64_t send_sequence;

    picoquic_sack_item_t first_sack_item;
    uint64_t next_sequence_hole;
    uint64_t time_stamp_largest_received;
    uint64_t highest_ack_sent;
    uint64_t highest_ack_sent_time;
    uint64_t ack_delay_local;

    uint64_t nb_retransmit;
    uint64_t latest_retransmit_time;
    uint64_t highest_acknowledged;
    uint64_t latest_time_acknowledged; /* time at which the highest acknowledged was sent */
    uint64_t highest_acknowledged_time; /* time at which the highest ack was received */
    picoquic_packet_t* retransmit_newest;
    picoquic_packet_t* retransmit_oldest;
    picoquic_packet_t* retransmitted_newest;
    picoquic_packet_t* retransmitted_oldest;

    unsigned int ack_needed : 1;
    unsigned int ack_of_ack_requested : 1;
} picoquic_packet_context_t;

/*
* New CNX-ID description, used for storage waiting for the CNX-ID to be validated
*/
typedef struct st_picoquic_cnxid_stash_t {
    struct st_picoquic_cnxid_stash_t * next_in_stash;
    uint64_t sequence;
    picoquic_connection_id_t cnx_id;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
} picoquic_cnxid_stash_t;

/*
* Probe in progress, waiting for validation in path.
* or upon reception of the first data packet from the peer otherwise.
* TODO: re-think that logic if using null CID.
*/
typedef struct st_picoquic_probe_t {
    struct st_picoquic_probe_t * next_probe;
    uint64_t sequence;
    picoquic_connection_id_t remote_cnxid;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    /* Addresses with which the probe was sent */
    struct sockaddr_storage peer_addr;
    int peer_addr_len;
    struct sockaddr_storage local_addr;
    int local_addr_len;
    unsigned long if_index_dest;
    /* Challenge used by this probe */
    uint64_t challenge[PICOQUIC_CHALLENGE_REPEAT_MAX];
    uint64_t challenge_time;
    uint8_t challenge_repeat_count;
    /* Flags */
    unsigned int challenge_required : 1;
    unsigned int challenge_verified : 1;
    unsigned int challenge_failed : 1;
} picoquic_probe_t;

/*
* Per connection context.
*/
typedef struct st_picoquic_cnx_t {
    picoquic_quic_t* quic;

    /* Management of context retrieval tables */

    struct st_picoquic_cnx_t* next_in_table;
    struct st_picoquic_cnx_t* previous_in_table;

    /* Proposed and negotiated version. Feature flags denote version dependent features */
    uint32_t proposed_version;
    int version_index;

    /* Series of flags showing the state or choices of the connection */
    unsigned int is_0RTT_accepted : 1; /* whether 0-RTT is accepted */
    unsigned int remote_parameters_received : 1; /* whether remote parameters where received */
    unsigned int client_mode : 1; /* Is this connection the client side? */
    unsigned int key_phase_enc : 1; /* Key phase used in outgoing packets */
    unsigned int key_phase_dec : 1; /* Key phase expected in incoming packets */
    unsigned int zero_rtt_data_accepted : 1; /* Peer confirmed acceptance of zero rtt data */
    unsigned int sending_ecn_ack : 1; /* ECN data has been received, should be copied in acks */
    unsigned int sent_blocked_frame : 1; /* Blocked frame has been sent */
    unsigned int stream_blocked_bidir_sent : 1; /* If stream_blocked has been sent to peer and no stream limit update since */
    unsigned int stream_blocked_unidir_sent : 1; /* If stream_blocked has been sent to peer and no stream limit update since */
    unsigned int max_stream_data_needed : 1; /* If at least one stream needs more data */
    unsigned int path_demotion_needed : 1; /* If at least one path was recently demoted */
    unsigned int alt_path_challenge_needed : 1; /* If at least one alt path challenge is needed or in progress */
    unsigned int is_handshake_finished : 1; /* If there are no more packets to ack or retransmit in initial  or handshake contexts */

    /* Spin bit policy */
    picoquic_spinbit_version_enum spin_policy;

    /* Local and remote parameters */
    picoquic_tp_t local_parameters;
    picoquic_tp_t remote_parameters;
    /* Padding policy */
    uint32_t padding_multiple;
    uint32_t padding_minsize;

    /* On clients, document the SNI and ALPN expected from the server */
    /* TODO: there may be a need to propose multiple ALPN */
    char const* sni;
    char const* alpn;
    /* On clients, receives the maximum 0RTT size accepted by server */
    size_t max_early_data_size;
    /* Call back function and context */
    picoquic_stream_data_cb_fn callback_fn;
    void* callback_ctx;

    /* connection state, ID, etc. Todo: allow for multiple cnxid */
    picoquic_state_enum cnx_state;
    picoquic_connection_id_t initial_cnxid;
    picoquic_connection_id_t original_cnxid;
    uint64_t start_time;
    uint16_t application_error;
    uint16_t local_error;
    uint16_t remote_application_error;
    uint16_t remote_error;
    uint64_t offending_frame_type;
    uint16_t retry_token_length;
    uint8_t * retry_token;


    /* Next time sending data is expected */
    uint64_t next_wake_time;
    struct st_picoquic_cnx_t* next_by_wake_time;
    struct st_picoquic_cnx_t* previous_by_wake_time;

    /* TLS context, TLS Send Buffer, streams, epochs */
    void* tls_ctx;
    uint64_t crypto_rotation_sequence;
    uint64_t crypto_rotation_time_guard;
    struct st_ptls_buffer_t* tls_sendbuf;
    uint16_t psk_cipher_suite_id;

    picoquic_stream_head_t tls_stream[PICOQUIC_NUMBER_OF_EPOCHS]; /* Separate input/output from each epoch */
    picoquic_crypto_context_t crypto_context[PICOQUIC_NUMBER_OF_EPOCHS]; /* Encryption and decryption objects */
    picoquic_crypto_context_t crypto_context_old; /* Old encryption and decryption context after key rotation */
    picoquic_crypto_context_t crypto_context_new; /* New encryption and decryption context just before key rotation */

    /* Liveness detection */
    uint64_t latest_progress_time; /* last local time at which the connection progressed */


    /* Sequence and retransmission state */
    picoquic_packet_context_t pkt_ctx[picoquic_nb_packet_context];

    /* Statistics */
    uint64_t nb_bytes_queued;
    uint32_t nb_path_challenge_sent;
    uint32_t nb_path_response_received;
    uint32_t nb_zero_rtt_sent;
    uint32_t nb_zero_rtt_acked;
    uint64_t nb_retransmission_total;
    uint64_t nb_spurious;
    unsigned int cwin_blocked : 1;
    unsigned int flow_blocked : 1;
    unsigned int stream_blocked : 1;
    FILE * cc_log; /* File where congestion control data is logged */

    /* ECN Counters */
    uint64_t ecn_ect0_total_local;
    uint64_t ecn_ect1_total_local;
    uint64_t ecn_ce_total_local;
    uint64_t ecn_ect0_total_remote;
    uint64_t ecn_ect1_total_remote;
    uint64_t ecn_ce_total_remote;

    /* Congestion algorithm */
    picoquic_congestion_algorithm_t const* congestion_alg;

    /* Flow control information */
    uint64_t data_sent;
    uint64_t data_received;
    uint64_t maxdata_local;
    uint64_t maxdata_remote;
    uint64_t max_stream_id_bidir_local;
    uint64_t max_stream_id_bidir_local_computed;
    uint64_t max_stream_id_unidir_local;
    uint64_t max_stream_id_unidir_local_computed;
    uint64_t max_stream_id_bidir_remote;
    uint64_t max_stream_id_unidir_remote;

    /* Queue for frames waiting to be sent */
    picoquic_misc_frame_header_t* first_misc_frame;

    /* Management of streams */
    picosplay_tree_t stream_tree;
    picoquic_stream_head_t * first_output_stream;
    picoquic_stream_head_t * last_visited_stream;
    uint64_t high_priority_stream_id;
    uint64_t next_stream_id[4];

    /* If not `0`, the connection will send keep alive messages in the given interval. */
    uint64_t keep_alive_interval;

    /* Management of paths */
    picoquic_path_t ** path;
    int nb_paths;
    int nb_path_alloc;
    int path_sequence_next;
    /* Management of the CNX-ID stash */
    picoquic_cnxid_stash_t * cnxid_stash_first;
    /* Management of ongoing probes */
    picoquic_probe_t * probe_first;
} picoquic_cnx_t;

/* Load the stash of retry tokens. */
int picoquic_load_token_file(picoquic_quic_t* quic, char const * token_file_name);

/* Init of transport parameters */
int picoquic_set_default_tp(picoquic_quic_t* quic, picoquic_tp_t * tp);
void picoquic_init_transport_parameters(picoquic_tp_t* tp, int client_mode);

/* Handling of stateless packets */
picoquic_stateless_packet_t* picoquic_create_stateless_packet(picoquic_quic_t* quic);
void picoquic_queue_stateless_packet(picoquic_quic_t* quic, picoquic_stateless_packet_t* sp);

/* Registration of per path connection ID in server context */
int picoquic_register_cnx_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, picoquic_path_t* path, picoquic_connection_id_t cnx_id);

/* Management of path */
int picoquic_create_path(picoquic_cnx_t* cnx, uint64_t start_time,
    struct sockaddr* local_addr, struct sockaddr* peer_addr);
void picoquic_register_path(picoquic_cnx_t* cnx, picoquic_path_t * path_x);
void picoquic_delete_path(picoquic_cnx_t* cnx, int path_index);
void picoquic_demote_path(picoquic_cnx_t* cnx, int path_index, uint64_t current_time);
void picoquic_promote_path_to_default(picoquic_cnx_t* cnx, int path_index, uint64_t current_time);
void picoquic_delete_abandoned_paths(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t * next_wake_time);

/* Management of the CNX-ID stash */
picoquic_cnxid_stash_t * picoquic_dequeue_cnxid_stash(picoquic_cnx_t* cnx);

int picoquic_enqueue_cnxid_stash(picoquic_cnx_t * cnx,
    const uint64_t sequence, const uint8_t cid_length, const uint8_t * cnxid_bytes,
    const uint8_t * secret_bytes, picoquic_cnxid_stash_t ** pstashed);

/* Management of probes */
picoquic_probe_t * picoquic_find_probe_by_challenge(const picoquic_cnx_t* cnx, uint64_t challenge);

picoquic_probe_t * picoquic_find_probe_by_addr(const picoquic_cnx_t* cnx,
    const struct sockaddr * peer_addr, const struct sockaddr * local_addr);

void picoquic_delete_probe(picoquic_cnx_t* cnx, picoquic_probe_t * probe);
void picoquic_delete_failed_probes(picoquic_cnx_t* cnx);

/* handling of retransmission queue */
picoquic_packet_t* picoquic_dequeue_retransmit_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p, int should_free);
void picoquic_dequeue_retransmitted_packet(picoquic_cnx_t* cnx, picoquic_packet_t* p);

#if 0
/* Reset connection after receiving version negotiation */
int picoquic_reset_cnx_version(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, uint64_t current_time);
#endif

/* Reset the connection context, e.g. after retry */
int picoquic_reset_cnx(picoquic_cnx_t* cnx, uint64_t current_time);

/* Reset packet context */
void picoquic_reset_packet_context(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc);

/* Notify error on connection */
int picoquic_connection_error(picoquic_cnx_t* cnx, uint16_t local_error, uint64_t frame_type);

/* Connection context retrieval functions */
picoquic_cnx_t* picoquic_cnx_by_id(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id);
picoquic_cnx_t* picoquic_cnx_by_net(picoquic_quic_t* quic, struct sockaddr* addr);

int picoquic_retrieve_by_cnx_id_or_net_id(picoquic_quic_t* quic, picoquic_connection_id_t* cnx_id,
    struct sockaddr* addr, picoquic_cnx_t ** pcnx);

/* Reset the pacing data after CWIN is updated */
void picoquic_update_pacing_data(picoquic_path_t * path_x);

/* Next time is used to order the list of available connections,
        * so ready connections are polled first */
void picoquic_reinsert_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t next_time);

/* Integer parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0]) << 8) | (b)[1])
#define PICOPARSE_24(b) ((((uint32_t)PICOPARSE_16(b)) << 16) | ((b)[2]))
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b)) << 16) | PICOPARSE_16((b) + 2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b)) << 32) | PICOPARSE_32((b) + 4))

/* Integer formatting functions */
void picoformat_16(uint8_t* bytes, uint16_t n16);
void picoformat_32(uint8_t* bytes, uint32_t n32);
void picoformat_64(uint8_t* bytes, uint64_t n64);

size_t picoquic_varint_encode(uint8_t* bytes, size_t max_bytes, uint64_t n64);
void picoquic_varint_encode_16(uint8_t* bytes, uint16_t n16);
size_t picoquic_varint_decode(const uint8_t* bytes, size_t max_bytes, uint64_t* n64);
uint8_t* picoquic_frames_varint_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64);
size_t picoquic_varint_skip(uint8_t* bytes);

/* utilities */
char* picoquic_string_create(const char* original, size_t len);
char* picoquic_string_duplicate(const char* original);

/* Packet parsing */

int picoquic_parse_packet_header(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    int receiving);

uint32_t picoquic_create_packet_header(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type,
    uint64_t sequence_number,
    picoquic_connection_id_t * dest_cnxid,
    picoquic_connection_id_t * srce_cnxid,
    uint8_t* bytes,
    uint32_t * pn_offset,
    uint32_t * pn_length);

uint32_t  picoquic_predict_packet_header_length(
    picoquic_cnx_t* cnx,
    picoquic_packet_type_enum packet_type);

void picoquic_update_payload_length(
    uint8_t* bytes, size_t pnum_index, size_t header_length, uint32_t packet_length);

uint32_t picoquic_get_checksum_length(picoquic_cnx_t* cnx, int is_cleartext_mode);

int picoquic_is_stream_frame_unlimited(const uint8_t* bytes);
int picoquic_check_frame_needs_repeat(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, int* no_need_to_repeat);

int picoquic_parse_stream_header(
    const uint8_t* bytes, size_t bytes_max,
    uint64_t* stream_id, uint64_t* offset, size_t* data_length, int* fin,
    size_t* consumed);

int picoquic_parse_ack_header(
    uint8_t const* bytes, size_t bytes_max,
    uint64_t* num_block, uint64_t* nb_ecnx3, uint64_t* largest,
    uint64_t* ack_delay, size_t* consumed,
    uint8_t ack_delay_exponent);

uint64_t picoquic_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn);

uint32_t picoquic_protect_packet(picoquic_cnx_t* cnx,
    picoquic_packet_type_enum ptype,
    uint8_t * bytes, uint64_t sequence_number,
    picoquic_connection_id_t * remote_cnxid,
    picoquic_connection_id_t * local_cnxid,
    uint32_t length, uint32_t header_length,
    uint8_t* send_buffer, uint32_t send_buffer_max,
    void * aead_context, void* pn_enc);

void picoquic_finalize_and_protect_packet(picoquic_cnx_t *cnx, picoquic_packet_t * packet, int ret,
    uint32_t length, uint32_t header_length, uint32_t checksum_overhead,
    size_t * send_length, uint8_t * send_buffer, uint32_t send_buffer_max,
    picoquic_connection_id_t * remote_cnxid,
    picoquic_connection_id_t * local_cnxid,
    picoquic_path_t * path_x, uint64_t current_time);

void picoquic_implicit_handshake_ack(picoquic_cnx_t* cnx, picoquic_packet_context_enum pc, uint64_t current_time);
void picoquic_ready_state_transition(picoquic_cnx_t* cnx, uint64_t current_time);

int picoquic_parse_header_and_decrypt(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    uint32_t packet_length,
    struct sockaddr* addr_from,
    uint64_t current_time,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    uint32_t * consumed,
    int * new_context_created);

/* Handling of packet logging */
void picoquic_log_decrypted_segment(void* F_log, int log_cnxid, picoquic_cnx_t* cnx,
    int receiving, picoquic_packet_header * ph, uint8_t* bytes, size_t length, int ret);

void picoquic_log_outgoing_segment(void* F_log, int log_cnxid, picoquic_cnx_t* cnx,
    uint8_t * bytes,
    uint64_t sequence_number,
    uint32_t length,
    uint8_t* send_buffer, uint32_t send_length);

void picoquic_log_packet_address(FILE* F, uint64_t log_cnxid64, picoquic_cnx_t* cnx,
    struct sockaddr* addr_peer, int receiving, size_t length, uint64_t current_time);

void picoquic_log_prefix_initial_cid64(FILE* F, uint64_t log_cnxid64);

void picoquic_log_error_packet(FILE* F, uint8_t* bytes, size_t bytes_max, int ret);
void picoquic_log_processing(FILE* F, picoquic_cnx_t* cnx, size_t length, int ret);
void picoquic_log_transport_extension(FILE* F, picoquic_cnx_t* cnx, int log_cnxid);
void picoquic_log_congestion_state(FILE* F, picoquic_cnx_t* cnx, uint64_t current_time);
void picoquic_log_picotls_ticket(FILE* F, picoquic_connection_id_t cnx_id,
    uint8_t* ticket, uint16_t ticket_length);
const char * picoquic_log_fin_or_event_name(picoquic_call_back_event_t ev);
void picoquic_log_time(FILE* F, picoquic_cnx_t* cnx, uint64_t current_time,
    const char* label1, const char* label2);

#define PICOQUIC_SET_LOG(quic, F) (quic)->F_log = (void*)(F)

void picoquic_set_key_log_file(picoquic_quic_t *quic, FILE* F_keylog);

/* Handling of cc_log */
void picoquic_open_cc_dump(picoquic_cnx_t * cnx);
void picoquic_close_cc_dump(picoquic_cnx_t * cnx);
void picoquic_cc_dump(picoquic_cnx_t * cnx, uint64_t current_time); 
int picoquic_cc_log_file_to_csv(char const * bin_cc_log_name, char const * csv_cc_log_name);

/* handling of ACK logic */
int picoquic_is_ack_needed(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t * next_wake_time, picoquic_packet_context_enum pc);

int picoquic_is_pn_already_received(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc, uint64_t pn64);
int picoquic_record_pn_received(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc, uint64_t pn64, uint64_t current_microsec);
uint16_t picoquic_deltat_to_float16(uint64_t delta_t);
uint64_t picoquic_float16_to_deltat(uint16_t float16);

int picoquic_update_sack_list(picoquic_sack_item_t* sack,
    uint64_t pn64_min, uint64_t pn64_max);
/*
        * Check whether the data fills a hole. returns 0 if it does, -1 otherwise.
        */
int picoquic_check_sack_list(picoquic_sack_item_t* sack,
    uint64_t pn64_min, uint64_t pn64_max);

/*
 * Process ack of ack
 */
int picoquic_process_ack_of_ack_frame(
    picoquic_sack_item_t* first_sack,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int is_ecn_14);

void picoquic_update_path_rtt(picoquic_cnx_t* cnx, picoquic_path_t * old_path, int64_t rtt_estimate,
    picoquic_packet_context_t * pkt_ctx, uint64_t current_time, uint64_t ack_delay);

/* stream management */
picoquic_stream_head_t* picoquic_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id); 
picoquic_stream_head_t* picoquic_create_missing_streams(picoquic_cnx_t* cnx, uint64_t stream_id, int is_remote);
int picoquic_is_stream_closed(picoquic_stream_head_t* stream, int client_mode); 
int picoquic_delete_stream_if_closed(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream);

void picoquic_update_stream_initial_remote(picoquic_cnx_t* cnx);

picoquic_stream_head_t * picoquic_stream_from_node(picosplay_node_t * node);
picoquic_stream_head_t * picoquic_first_stream(picoquic_cnx_t * cnx);
picoquic_stream_head_t * picoquic_last_stream(picoquic_cnx_t * cnx);
picoquic_stream_head_t * picoquic_next_stream(picoquic_stream_head_t * stream);
picoquic_stream_head_t* picoquic_find_stream(picoquic_cnx_t* cnx, uint64_t stream_id);
void picoquic_add_output_streams(picoquic_cnx_t * cnx, uint64_t old_limit, uint64_t new_limit, unsigned int is_bidir);
picoquic_stream_head_t* picoquic_find_ready_stream(picoquic_cnx_t* cnx);
int picoquic_is_tls_stream_ready(picoquic_cnx_t* cnx);
uint8_t* picoquic_decode_stream_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    const uint8_t* bytes_max, uint64_t current_time);
int picoquic_prepare_stream_frame(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream,
    uint8_t* bytes, size_t bytes_max, size_t* consumed, int* is_still_active);
int picoquic_split_stream_frame(uint8_t* frame, size_t frame_length,
    uint8_t* b1, size_t b1_max, size_t *lb1, uint8_t* b2, size_t b2_max, size_t *lb2);
int picoquic_copy_before_retransmit(picoquic_packet_t * old_p,
    picoquic_cnx_t * cnx,
    uint8_t * new_bytes,
    size_t send_buffer_max_minus_checksum,
    int * packet_is_pure_ack,
    int * do_not_detect_spurious,
    uint32_t * length);
uint8_t* picoquic_decode_crypto_hs_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    const uint8_t* bytes_max, int epoch);
int picoquic_prepare_crypto_hs_frame(picoquic_cnx_t* cnx, int epoch,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_ack_frame(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_ack_frame_basic(picoquic_cnx_t* cnx, uint64_t current_time,
    picoquic_packet_context_enum pc,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_connection_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_application_close_frame(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_required_max_stream_data_frames(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_max_data_frame(picoquic_cnx_t* cnx, uint64_t maxdata_increase,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
void picoquic_update_max_stream_ID_local(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream);
int picoquic_prepare_max_streams_frame_if_needed(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
void picoquic_clear_stream(picoquic_stream_head_t* stream);
void picoquic_delete_stream(picoquic_cnx_t * cnx, picoquic_stream_head_t * stream);
int picoquic_prepare_path_challenge_frame(uint8_t* bytes,
    size_t bytes_max, size_t* consumed, uint64_t challenge);
int picoquic_prepare_path_response_frame(uint8_t* bytes,
    size_t bytes_max, size_t* consumed, uint64_t challenge);
int picoquic_prepare_new_connection_id_frame(picoquic_cnx_t * cnx, picoquic_path_t * path_x,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_prepare_blocked_frames(picoquic_cnx_t* cnx, uint8_t* bytes, size_t bytes_max, size_t* consumed);
int picoquic_queue_retire_connection_id_frame(picoquic_cnx_t * cnx, uint64_t sequence);
int picoquic_queue_new_token_frame(picoquic_cnx_t * cnx, uint8_t * token, size_t token_length);

int picoquic_prepare_first_misc_frame(picoquic_cnx_t* cnx, uint8_t* bytes,
    size_t bytes_max, size_t* consumed);
int picoquic_prepare_misc_frame(picoquic_misc_frame_header_t* misc_frame, uint8_t* bytes,
    size_t bytes_max, size_t* consumed);

/* send/receive */

int picoquic_decode_frames(picoquic_cnx_t* cnx, picoquic_path_t * path_x, uint8_t* bytes, size_t bytes_max,
    int epoch, struct sockaddr* addr_from, struct sockaddr* addr_to, uint64_t current_time);

int picoquic_skip_frame(uint8_t* bytes, size_t bytes_max, size_t* consumed, int* pure_ack);

int picoquic_decode_closing_frames(uint8_t* bytes,
    size_t bytes_max, int* closing_received);

uint64_t picoquic_decode_transport_param_stream_id(uint64_t rank, int extension_mode, int stream_type);
uint64_t picoquic_prepare_transport_param_stream_id(uint64_t stream_id);

int picoquic_prepare_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);

int picoquic_receive_transport_extensions(picoquic_cnx_t* cnx, int extension_mode,
    uint8_t* bytes, size_t bytes_max, size_t* consumed);

picoquic_misc_frame_header_t* picoquic_create_misc_frame(const uint8_t* bytes, size_t length);

#ifdef __cplusplus
}
#endif
#endif /* PICOQUIC_INTERNAL_H */
