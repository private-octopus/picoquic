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
#include "tls_api.h"

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

/*
 * Processing of a version renegotiation packet.
 *
 * From the specification: When the client receives a Version Negotiation packet 
 * from the server, it should select an acceptable protocol version. If the server
 * lists an acceptable version, the client selects that version and reattempts to
 * create a connection using that version. Though the contents of a packet might
 * not change in response to version negotiation, a client MUST increase the packet
 * number it uses on every packet it sends. Packets MUST continue to use long headers
 * and MUST include the new negotiated protocol version.
 */
int picoquic_incoming_version_negotiation(
	picoquic_cnx * cnx,
	uint8_t * bytes,
	uint32_t length,
	struct sockaddr * addr_from,
	picoquic_packet_header * ph,
	uint64_t current_time)
{
	/* Parse the content */
	size_t byte_index = ph->offset;
	int ret = -1;

	if (ph->cnx_id != cnx->initial_cnxid ||
		ph->vn != cnx->version ||
		(cnx->retransmit_newest == NULL || ph->pn64 > cnx->retransmit_newest->sequence_number) ||
		(cnx->retransmit_oldest == NULL || ph->pn64 < cnx->retransmit_oldest->sequence_number))
	{
		/* Packet that do not match the "echo" checks should be logged and ignored */
		ret = 0;
	}
	else
	{
		/* Trying to renegotiate the version, just ignore the packet if not good. */
		ret = picoquic_reset_cnx_version( cnx, bytes + ph->offset, length - ph->offset);
	}

	return ret;
}

/*
 * Check that the version is supported. If that fails,
 * best effort attemt to send a version negotiation packet if
 * an initial message is received with an unsupported version
 */

int picoquic_verify_version(
	picoquic_quic * quic,
	uint8_t * bytes,
	uint32_t length,
	struct sockaddr * addr_from,
	picoquic_packet_header * ph,
	uint64_t current_time)
{
	int ret = -1;

	for (size_t i = 0; i < picoquic_nb_supported_versions; i++)
	{
		if (picoquic_supported_versions[i] == ph->vn)
		{
			ret = 0;
			break;
		}
	}

	if (ret != 0)
	{
		picoquic_stateless_packet * sp = picoquic_create_stateless_packet(quic);

		if (sp != NULL)
		{
			uint8_t * bytes = sp->bytes;
			size_t byte_index = 0;
			/* Packet type set to version negotiation */
			bytes[byte_index++] = 0x80 | picoquic_packet_version_negotiation;
			/* Copy the incoming header */
			picoformat_64(bytes + byte_index, ph->cnx_id);
			byte_index += 8;
			picoformat_32(bytes + byte_index, ph->pn);
			byte_index += 4;
			picoformat_32(bytes + byte_index, ph->vn);
			byte_index += 4;
			/* Set the payload to the list of versions */
			for (size_t i = 0; i < picoquic_nb_supported_versions; i++)
			{
				picoformat_32(bytes + byte_index, picoquic_supported_versions[i]);
				byte_index += 4;
			}

			sp->length = byte_index;
			memset(&sp->addr_to, 0, sizeof(sp->addr_to));
			memcpy(&sp->addr_to, addr_from,
				(addr_from->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
			picoquic_queue_stateless_packet(quic, sp);
		}
	}

	return ret;
}

/*
 * Processing of an incoming client initial packet,
 * on an unknown connection context.
 */

picoquic_cnx * picoquic_incoming_initial(
    picoquic_quic * quic,
    uint8_t * bytes,
    uint32_t length,
    struct sockaddr * addr_from,
    picoquic_packet_header * ph,
	uint64_t current_time)
{
    picoquic_cnx * cnx = NULL;
    size_t decoded_length = 0;

    if (ph->ptype != picoquic_packet_client_initial ||
        (quic->flags&picoquic_context_server) == 0 ||
		length < PICOQUIC_ENFORCED_INITIAL_MTU)
	{
        /* TODO: may want to send stateless reject */
        /* Unexpected packet, drop and log. */
    }
    else
    {
        decoded_length = fnv1a_check(bytes, length);
        if (decoded_length == 0)
        {
            /* Incorrect checksum, drop and log. */		
        }
        else if (picoquic_verify_version(quic, bytes, length, addr_from, ph, current_time) == 0)
        {
            /* TODO: if wrong version, send version negotiation, do not go any further */
            /* if listening is OK, listen */
            cnx = picoquic_create_cnx(quic, ph->cnx_id, addr_from, current_time, 0);

			if (cnx != NULL)
			{
				int ret = 0;
				uint32_t seq_init = 0;
				
				ret = picoquic_decode_frames(cnx,
                    bytes +ph->offset, decoded_length - ph->offset, 1);

                /* processing of client initial packet */
                if (ret == 0)
                {
                    /* initialization of context & creation of data */
                    /* TODO: find path to send data produced by TLS. */
                    ret = picoquic_tlsinput_stream_zero(cnx);
                }

                if (ret != 0)
                {
                    /* This is bad. should just delete the context, log the packet, etc */
					picoquic_delete_cnx(cnx);
					free(cnx);
					cnx = NULL;
                }
            }
        }
    }

    return cnx;
}

/*
 * Processing of a server clear text packet.
 */

int picoquic_incoming_server_cleartext(
    picoquic_cnx * cnx,
    uint8_t * bytes,
    uint32_t length, 
    picoquic_packet_header * ph)
{
    int ret = 0;
    size_t decoded_length = 0;

    if (cnx->cnx_state == picoquic_state_client_init_sent ||
		cnx->cnx_state == picoquic_state_client_init_resent)
    {
        cnx->cnx_state = picoquic_state_client_handshake_start;
    }

    if (cnx->cnx_state == picoquic_state_client_handshake_start ||
        cnx->cnx_state == picoquic_state_client_handshake_progress)
    {
        /* Verify the checksum */
        decoded_length = fnv1a_check(bytes, length);
        if (decoded_length == 0)
        {
            /* Incorrect checksum, drop and log. */
			ret = PICOQUIC_ERROR_FNV1A_CHECK;
        }
        else
        {
			/* Check the server cnx id */
			if (cnx->server_cnxid == 0)
			{
				cnx->server_cnxid = ph->cnx_id;
			}
			else
			{
				if (cnx->server_cnxid != ph->cnx_id)
				{
					ret = -1; /* protocol error */
				}
			}

			if (ret == 0)
			{
				/* Accept the incoming frames */
				ret = picoquic_decode_frames(cnx,
					bytes + ph->offset, decoded_length - ph->offset, 1);
			}

            /* processing of client initial packet */
            if (ret == 0)
            {
                /* initialization of context & creation of data */
                /* TODO: find path to send data produced by TLS. */
                ret = picoquic_tlsinput_stream_zero(cnx);
            }

            if (ret != 0)
            {
                /* This is bad. should just delete the context, log the packet, etc */
            }
        }
    }
    else
    {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_SPURIOUS_REPEAT;
    }

    return ret;
}

/*
 * Processing of client clear text packet.
 */
int picoquic_incoming_client_cleartext(
    picoquic_cnx * cnx,
    uint8_t * bytes,
    uint32_t length,
    picoquic_packet_header * ph)
{
    int ret = 0;
    size_t decoded_length = 0;

    if (cnx->cnx_state == picoquic_state_server_almost_ready ||
        cnx->cnx_state == picoquic_state_server_ready)
    {
        /* Verify the checksum */
        decoded_length = fnv1a_check(bytes, length);
        if (decoded_length == 0)
        {
            /* Incorrect checksum, drop and log. */
			ret = PICOQUIC_ERROR_FNV1A_CHECK;
        }
		else if (ph->cnx_id != cnx->server_cnxid)
		{
			ret = PICOQUIC_ERROR_CNXID_CHECK;
		}
		else
        {
            /* Accept the incoming frames */
            ret = picoquic_decode_frames(cnx,
                bytes + ph->offset, decoded_length - ph->offset, 1);

            /* processing of client clear text packet */
            if (ret == 0)
            {
                /* initialization of context & creation of data */
                /* TODO: find path to send data produced by TLS. */
                ret = picoquic_tlsinput_stream_zero(cnx);
            }

            if (ret != 0)
            {
                /* This is bad. should just delete the context, log the packet, etc */
            }
        }
    }
    else
    {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}
/*
* Processing of client encrypted packet.
*/
int picoquic_incoming_encrypted(
    picoquic_cnx * cnx,
    uint8_t * bytes,
    uint32_t length,
    picoquic_packet_header * ph)
{
    int ret = 0;
    size_t decoded_length = 0;

    if (cnx->cnx_state == picoquic_state_client_almost_ready ||
        cnx->cnx_state == picoquic_state_client_ready ||
        cnx->cnx_state == picoquic_state_server_almost_ready ||
        cnx->cnx_state == picoquic_state_server_ready)
    {
        /* AEAD Decrypt, in place */
        decoded_length = picoquic_aead_decrypt(cnx, bytes + ph->offset,
            bytes + ph->offset, length - ph->offset, ph->pn, bytes, ph->offset);

        if (decoded_length > (length - ph->offset))
        {
            /* Bad packet should be ignored */
			ret = PICOQUIC_ERROR_AEAD_CHECK;
        }
        else
        {
            /* Accept the incoming frames */
            ret = picoquic_decode_frames(cnx,
                bytes + ph->offset, decoded_length, 0);

            /* processing of client encrypted packet */
            if (ret == 0)
            {
                /* initialization of context & creation of data */
                ret = picoquic_tlsinput_stream_zero(cnx);
            }

            if (ret != 0)
            {
                /* This is bad. should just delete the context, log the packet, etc */
            }
        }
    }
    else
    {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}


/*
 * Processing of the packet that was just received from the network.
 */

int picoquic_incoming_packet(
    picoquic_quic * quic,
    uint8_t * bytes,
    uint32_t length,
    struct sockaddr * addr_from,
	uint64_t current_time)
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

    if (ret == 0)
    {
        if (cnx == NULL)
        {
            cnx = picoquic_incoming_initial(quic, bytes, length, addr_from, &ph, current_time);
        }
        else
        {
            /* Build a packet number to 64 bits */
            ph.pn64 = picoquic_get_packet_number64(
                cnx->first_sack_item.end_of_sack_range, ph.pnmask, ph.pn);

            /* verify that the packet is new */
			if (picoquic_is_pn_already_received(cnx, ph.pn64) != 0)
			{
				ret = PICOQUIC_ERROR_DUPLICATE;
			}

            /* Verify that the packet decrypts correctly */
            if (ret == 0)
            {
                switch (ph.ptype)
                {
                case picoquic_packet_version_negotiation:
                    if (cnx->cnx_state == picoquic_state_client_init_sent)
                    {
                        /* Verify the checksum */
                        /* Proceed with version negotiation*/
                        /* Process version negotiation */
                        /* Schedule repeat of initial message */
						ret = picoquic_incoming_version_negotiation(
							cnx, bytes, length, addr_from, &ph, current_time);
                    }
                    else
                    {
                        /* This is an unexpected packet. Log and drop.*/
                    }
                    break;
                case picoquic_packet_client_initial:
                    /* Not expected here. Treat as a duplicate. */
					if (ph.cnx_id == cnx->initial_cnxid)
						ret = PICOQUIC_ERROR_SPURIOUS_REPEAT;
					else
						ret = -1;
                    break;
                case picoquic_packet_server_stateless:
                    /* Not implemented yet. Log and ignore. */
                    ret = -1;
                    break;
                case picoquic_packet_server_cleartext:
                    ret = picoquic_incoming_server_cleartext(cnx, bytes, length, &ph);
                    break;
                case picoquic_packet_client_cleartext:
                    ret = picoquic_incoming_client_cleartext(cnx, bytes, length, &ph);
                    break;
                case picoquic_packet_0rtt_protected:
                    /* TODO : decrypt with 0RTT key */
                    /* Not implemented. Log and ignore */
                    ret = -1;
                    break;
                case picoquic_packet_1rtt_protected_phi0:
                case picoquic_packet_1rtt_protected_phi1:
                    ret = picoquic_incoming_encrypted(cnx, bytes, length, &ph);
                    /* TODO : roll key based on PHI */
                    /* decrypt with 1RTT key of epoch */
                    /* Not implemented yet. */
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
    }

	if (ret == 0 || ret == PICOQUIC_ERROR_SPURIOUS_REPEAT)
	{
		if (cnx != NULL && ph.ptype != picoquic_packet_version_negotiation)
		{
			/* Mark the sequence number as received */
			ret = picoquic_record_pn_received(cnx, ph.pn64, current_time);
		}
	}
	else if (ret == PICOQUIC_ERROR_AEAD_CHECK ||
		ret == PICOQUIC_ERROR_DUPLICATE ||
		ret == PICOQUIC_ERROR_FNV1A_CHECK)
	{
		/* Bad packets are dropped silently */
		ret = 0;
	}

    return ret;
}
