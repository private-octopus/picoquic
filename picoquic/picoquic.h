#ifndef PICOQUIC_H
#define PICOQUIC_H

#include <stdint.h>
#include <winsock2.h>
#include <Ws2def.h>
#include <WS2tcpip.h>
#include "picohash.h"

#ifdef  __cplusplus
extern "C" {
#endif

    /*
     * QUIC context, defining the tables of connections,
     * open sockets, etc.
     */
    typedef struct _picoquic_quic
    {
        picohash_table * table_cnx_by_id;
        picohash_table * table_cnx_by_net;

    } picoquic_quic;

    /*
     * Connection context, and links between context and addresses
     */

    typedef struct _picoquic_cnx
    {
        picoquic_quic * quic;
        struct _picoquic_cnx * next_in_table;
        struct _picoquic_cnx_id * first_cnx_id;
        struct _picoquic_net_id * first_net_id;

        uint64_t last_sequence_sent;
        uint64_t last_sequence_received;
    } picoquic_cnx;

    /* QUIC context create and dispose */
    picoquic_quic * picoquic_create(uint32_t nb_connections);
    void picoquic_free(picoquic_quic * quic);

    /* Context retrieval functions */
    picoquic_cnx * get_cnx_by_id(picoquic_quic * quic, uint64_t cnx_id);
    picoquic_cnx * get_cnx_by_net(picoquic_quic * quic, struct sockaddr* addr);


/* Parsing macros */
#define PICOPARSE_16(b) ((((uint16_t)(b)[0])<<8)|(b)[1])
#define PICOPARSE_32(b) ((((uint32_t)PICOPARSE_16(b))<<16)|PICOPARSE_16((b)+2))
#define PICOPARSE_64(b) ((((uint64_t)PICOPARSE_32(b))<<16)|PICOPARSE_32((b)+4))



#ifdef  __cplusplus
}
#endif

#endif /* PICOQUIC_H */
