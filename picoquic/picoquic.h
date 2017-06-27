#ifndef PICOQUIC_H
#define PICOQUIC_H

#include <stdint.h>

#ifdef  __cplusplus
extern "C" {
#endif

    /*
     * Connection context, and links between context and addresses
     */

    typedef struct _picoquic_cnx
    {
        struct _picoquic_cnx * next_in_table;
        uint64_t last_sequence_sent;
        uint64_t last_sequence_received;

    } picoquic_cnx;

    /*
     * Structures used in the hash table of connections
     */
    typedef struct _picoquic_cnx_id
    {
        struct _picoquic_cnx * next_in_bin;


    } picoquic_cnx_id;


#ifdef  __cplusplus
}
#endif

#endif /* PICOQUIC_H */
