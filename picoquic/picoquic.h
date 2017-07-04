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
    /*
     * Quic context flags
     */
    typedef enum {
        picoquic_context_client = 0,
        picoquic_context_server = 1
    } picoquic_context_flags;
    /*
     * QUIC context, defining the tables of connections,
     * open sockets, etc.
     */
    typedef struct _picoquic_quic
    {
        picotlsapi tls_api;

        uint32_t flags;

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
        picoquic_state_server_init,
        picoquic_state_client_handshake_start,
        picoquic_state_client_handshake_progress,
        picoquic_state_client_ready,
        picoquic_state_server_handshake_progress,
        picoquic_state_server_ready,
        picoquic_state_disconnected
    } picoquic_state_enum;

    /*
     * SACK dashboard item, part of conenction context.
     */

    typedef struct _picoquic_sack_item {
        struct _picoquic_sack_item * next_sack;
        uint64_t start_of_sack_range;
        uint64_t end_of_sack_range;
        uint64_t time_stamp_last_in_range;
    } picoquic_sack_item;

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

        /* negotiated version */
        uint32_t version;

        /* connection state, ID, etc. Todo: allow for multiple cnxid */
        picoquic_state_enum cnx_state;
        uint64_t initial_cnxid;
        uint64_t server_cnxid;
        struct sockaddr_storage peer_address;

        /* TLS context, TLS Send Buffer, chain of receive buffers (todo) */
        void * tls_ctx;
        struct st_ptls_buffer_t * tls_sendbuf;

        /* Receive state */
        struct _picoquic_sack_item first_sack_item;
        uint64_t sack_block_size_max;

        /* Retransmission state */

    } picoquic_cnx;

    /* QUIC context create and dispose */
    picoquic_quic * picoquic_create(uint32_t nb_connections);
    void picoquic_free(picoquic_quic * quic);

    /* Connection context creation and registration */
    picoquic_cnx * picoquic_create_cnx(picoquic_quic * quic, 
        uint64_t cnx_id, struct sockaddr * addr);
    void picoquic_delete_cnx(picoquic_cnx * cnx);

    /* Connection context retrieval functions */
    picoquic_cnx * picoquic_cnx_by_id(picoquic_quic * quic, uint64_t cnx_id);
    picoquic_cnx * picoquic_cnx_by_net(picoquic_quic * quic, struct sockaddr* addr);


/* Integer parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0])<<8)|(b)[1])
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b))<<16)|PICOPARSE_16((b)+2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b))<<32)|PICOPARSE_32((b)+4))

/* Integer formatting functions */
    void picoformat_16(uint8_t *bytes, uint16_t n16);
    void picoformat_32(uint8_t *bytes, uint32_t n32);
    void picoformat_64(uint8_t *bytes, uint64_t n64);

/* Packet parsing */

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

#ifdef  __cplusplus
}
#endif

#endif /* PICOQUIC_H */
