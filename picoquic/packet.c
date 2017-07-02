/*
 * Processing of an incoming packet.
 * - Has to find the proper context, based on either the 64 bit context ID
 *   or a combination of source address, source port and partial context value.
 * - Has to find the sequence number, based on partial values and windows.
 * - For initial packets, has to perform version checks.
 */

#include <stdint.h>
#include "picoquic.h"
#include "fnv1a.h"

int picoquic_parse_packet_header(
    uint8_t * bytes,
    size_t length,
    picoquic_packet_header * ph)
{
    uint8_t first_byte = bytes[0];

    ph->pn64 = 0;

    if ((first_byte & 0x80) != 0)
    {
        /* long packet format */
        ph->cnx_id = PICOPARSE_64(&bytes[1]);
        ph->pn = PICOPARSE_32(&bytes[9]);
        ph->vn = PICOPARSE_32(&bytes[13]);
        ph->pnmask = 0xFFFFFFFF00000000ull;
        ph->offset = 17;
        ph->ptype = (picoquic_packet_type_enum)first_byte & 0x7F;
        if (ph->ptype >= picoquic_packet_type_max)
        {
            ph->ptype = picoquic_packet_error;
        }
    }
    else
    {
        /* short format */
        ph->vn = 0;

        if ((first_byte & 0x40) != 0)
        {
            ph->cnx_id = PICOPARSE_64(&bytes[1]);
            ph->offset = 9;
            /* may identify CNX by CNX_ID */
        }
        else
        {
            /* need to identify CNX by socket ID */
            ph->cnx_id = 0;
            ph->offset = 1;
        }

        if ((first_byte & 0x20) == 0)
        {
            ph->ptype = picoquic_packet_1rtt_protected_phi0;
        }
        else
        {
            ph->ptype = picoquic_packet_1rtt_protected_phi1;
        }

        /* TODO: Get the length of pn from the CNX */
        switch (first_byte & 0x1F)
        {
        case 1:
            ph->pn = bytes[ph->offset];
            ph->pnmask = 0xFFFFFFFFFFFFFF00ull;
            ph->offset += 2;
            break;
        case 2:
            ph->pn = PICOPARSE_16(&bytes[ph->offset]);
            ph->pnmask = 0xFFFFFFFFFFFF0000ull;
            ph->offset += 2;
            break;
        case 3:
            ph->pn = PICOPARSE_32(&bytes[ph->offset]);
            ph->pnmask = 0xFFFFFFFF00000000ull;
            ph->offset += 4;
            break;
        default:
            ph->ptype = picoquic_packet_error;
            break;
        }
    }

    return ((ph->ptype == picoquic_packet_error) ? -1 : 0);
}

/* The packet number logic */
uint64_t picoquic_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn)
{
    uint64_t expected = highest + 1;
    uint64_t not_mask_plus_one = (~mask) + 1;
    uint64_t pn64 = (expected&mask) | pn;

    if (pn64 < expected)
    {
        uint64_t delta1 = expected - pn64;
        uint64_t delta2 = not_mask_plus_one - delta1;
        if (delta2 < delta1)
        {
            pn64 += not_mask_plus_one;
        }
    }
    else
    {
        uint64_t delta1 = pn64 - expected;
        uint64_t delta2 = not_mask_plus_one - delta1;

        if (delta2 <= delta1 &&
            (pn64&mask) > 0)
        {
            /* Out of sequence packet from previous roll */
            pn64 -= not_mask_plus_one;
        }
    }
    
    return pn64;
}

int picoquic_incoming_packet(
    picoquic_quic * quic,
    uint8_t * bytes,
    uint32_t length,
    struct sockaddr * addr_from)
{
    int ret = 0;
    picoquic_cnx * cnx = NULL;
    picoquic_packet_header ph;
    size_t decoded_length = 0;

    /* Parse the clear text header */
    ret = picoquic_parse_packet_header(bytes, length, &ph);

    /* Retrieve the connection context */
    if (ret == 0)
    {
        cnx = picoquic_cnx_by_net(quic, addr_from);

        if (cnx == NULL && ph.cnx_id != 0)
        {
            cnx = picoquic_cnx_by_id(quic, ph.cnx_id);
        }
    }

    if (ret == 0 && cnx == NULL)
    {
        if (ph.ptype != picoquic_packet_client_initial ||
            (quic->flags&picoquic_context_server) != 0)
        {
            /* Unexpected packet, drop and log. */
            ret = -1;
        }
        else
        {
            decoded_length = fnv1a_check(bytes, length);
            if (decoded_length == 0)
            {
                ret = -1;
            }
            else
            {
                /* TODO: version negotiation. */
                /* TODO: if wrong version, send version negotiation, do not go any further */
                /* if listening is OK, listen */
                cnx = picoquic_create_cnx(quic, ph.cnx_id, addr_from);
                if (cnx == NULL)
                {
                    ret = -1;
                }
                else
                {
                    /* processing of client initial packet */
                    /* initialization of context */
                    /* registration of context */
                }
            }
        }
    }
    else
    {
        /* Build a packet number to 64 bits */
        ph.pn64 = picoquic_get_packet_number64(
            cnx->highest_number_received, ph.pnmask, ph.pn);
        /* TODO: verify that the packet is new */


        /* Verify that the packet decrypts correctly */
        if (ret == 0)
        {
            switch (ph.ptype)
            {
            case picoquic_packet_version_negotiation:
                if (cnx->cnx_state == picoquic_state_client_handshake_start)
                {
                    /* Verify the checksum */
                    /* Proceed with version negotiation*/
                    /* Process version negotiation */
                    /* Schedule repeat of initial message */
                }
                else
                {
                    /* This is an unexpected packet. Log and drop.*/
                }
                break;
            case picoquic_packet_client_initial:
                /* Not expected here. Log and ignore. */
                ret = -1;
                break;
            case picoquic_packet_server_stateless:
                /* Not implemented yet. Log and ignore. */
                ret = -1;
                break;
            case picoquic_packet_server_cleartext:
                if (cnx->cnx_state == picoquic_state_client_handshake_start ||
                    cnx->cnx_state == picoquic_state_client_handshake_progress)
                {
                    /* Verify the checksum */
                    /* Perform the handshake negotiation */
                    /* Progress the state, etc. */
                }
                else
                {
                    /* Not expected. Log and ignore. */
                    ret = -1;
                }
            case picoquic_packet_client_cleartext:
                if (cnx->cnx_state == picoquic_state_server_handshake_progress)
                {
                    /* check the FN1V checksum */
                    decoded_length = fnv1a_check(bytes, length);
                    /* perform the negotiation */
                }
                break;
            case picoquic_packet_0rtt_protected:
                /* TODO : decrypt with 0RTT key */
                /* Not implemented. Log and ignore */
                ret = -1;
                break;
            case picoquic_packet_1rtt_protected_phi0:
            case picoquic_packet_1rtt_protected_phi1:
                /* TODO : roll key based on PHI */
                /* TODO : decrypt with 1RTT key of epoch */
                decoded_length = 0;
                break;
            case picoquic_packet_public_reset:
                /* TODO : check whether the secret matches */
                /* Not implemented. Log and ignore */
                ret = -1;
                break;
            default:
                /* Packet type error. Log and ignore */
                ret = -1;
                break;
            }
        }
    }

    if (ret == 0 && cnx != NULL)
    {
        /* Schedule the next transmission */
    }

    return ret;
}


/*
 * Packet sequence recording prepares the next ACK:
 *
 * Maintain largest acknowledged number & the timestamp of that
 * arrival used to calculate the ACK delay.
 *
 * Maintain the lis of ACK 
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|[Num Blocks(8)]|   NumTS (8)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Largest Acknowledged (8/16/32/64)            ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        ACK Delay (16)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     ACK Block Section (*)                   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Timestamp Section (*)                   ...
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

 */
int packet_sequence_recording(picoquic_cnx * cnx, uint64_t pn64)
{
    return -1;
}