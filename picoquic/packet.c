/*
 * Processing of an incoming packet.
 * - Has to find the proper context, based on either the 64 bit context ID
 *   or a combination of source address, source port and partial context value.
 * - Has to find the sequence number, based on partial values and windows.
 * - For initial packets, has to perform version checks.
 */

#include <stdint.h>
#include "picoquic.h"

int picoquic_incoming_packet(
    uint8_t * bytes,
    uint32_t length,
    struct soackaddr * addr_from)
{
    /* Parse the clear text header */
    uint8_t first_byte = bytes[0];
    uint64_t cnx_id;
    uint32_t pn;
    uint32_t vn;
    uint32_t offset;

    if ((first_byte & 0x80) != 0)
    {
        /* long packet format */
        cnx_id = PICOPARSE_64(&bytes[1]);
        pn = PICOPARSE_64(&bytes[9]);
        vn = PICOPARSE_64(&bytes[13]);
        offset = 17;

        /* Get CNX by CNX_ID */
    }
    else
    {
        /* short format */
        if ((first_byte & 0x40) != 0)
        {
            cnx_id = PICOPARSE_64(&bytes[1]);
            offset = 9;
            /* need to identify CNX by CNX_ID */
        }
        else
        {
            /* need to identify CNX by socket ID */
            offset = 1;
        }
        /* Get the length of pn from the CNX */
    }
}

