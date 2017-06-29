#include "../picoquic/picoquic.h"
#include <stdlib.h>
#include <malloc.h>

/* 
 * Cnx creation unit test
 * - Create QUIC context
 * - Create a set of connections, with variations:
 * - IPv4 or IPv6 address
 * - Different ports
 * - either no connection ID or a connection ID.
 *
 *  - Verify that all these connections can be retrieved using their
 *    registered attributes.
 *  - Verify that a non registered connection can be retrieved.
 *
 *  - Delete connections first-middle-last.
 *  - Verify that deleted connections cannot be retrieved, and the others can.
 *
 *  - delete QUIC context.
 */

int cnxcreation_test()
{
    picoquic_quic * quic;
    struct sockaddr_in test4[3];
    struct sockaddr_in6 test6[2];
    uint64_t test_cnx_id[5] = { 0, 1, 2, 3, 4 };
    struct sockaddr * test_cnx_addr[5] = { 
        &test4[0], &test4[1], &test4[2], &test6[0], &test6[1] };



}