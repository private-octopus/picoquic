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

#include "fnv1a.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*
 * The new packet header parsing is version dependent
 */

int picoquic_parse_packet_header(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx)
{
    int ret = 0;

    /* Is this a long header of a short header? -- in any case, we need at least 17 bytes */
    if ((bytes[0] & 0x80) == 0x80) {
        if (length < 17) {
            ret = -1;
        } else {
            /* If this is a long header, the bytes at position 9--12 describe the version */
            ph->offset = 1 + picoquic_parse_connection_id(bytes + 1, &ph->cnx_id);
            ph->vn = PICOPARSE_32(bytes + ph->offset);
            ph->offset += 4;

            if (ph->vn == 0) {
                /* VN = zero identifies a version negotiation packet */
                ph->ptype = picoquic_packet_version_negotiation;
                ph->pn = 0;
                ph->pnmask = 0;
                ph->pn_offset = 0;
                ph->version_index = -1;

                if (*pcnx == NULL) {
                    *pcnx = picoquic_cnx_by_id(quic, ph->cnx_id);

                    if (*pcnx == NULL) {
                        *pcnx = picoquic_cnx_by_net(quic, addr_from);

                        if (*pcnx != NULL &&
                            picoquic_compare_connection_id(&(*pcnx)->initial_cnxid, &ph->cnx_id) != 0)
                        {
                            *pcnx = NULL;
                        }
                    }
                }
            }
            else {
                char context_by_addr = 0;

                ph->pn_offset = ph->offset;
                ph->pn = PICOPARSE_32(bytes + ph->offset);
                ph->version_index = picoquic_get_version_index(ph->vn);
                ph->offset += 4;
                ph->pnmask = 0xFFFFFFFF00000000ull;

                if (ph->version_index < 0) {
                    ph->offset = 17;
                    ph->ptype = picoquic_packet_error;
                }
                else {
                    /* Is the context found by using the `addr_from`? */

                    /* Retrieve the connection context */
                    if (*pcnx == NULL) {
                        *pcnx = picoquic_cnx_by_id(quic, ph->cnx_id);

                        /* TODO: something for the case of client initial, e.g. source IP + initial CNX_ID */
                        if (*pcnx == NULL) {
                            *pcnx = picoquic_cnx_by_net(quic, addr_from);

                            if (*pcnx != NULL)
                            {
                                context_by_addr = 1;
                            }
                        }
                    }

                    /* If the version is supported now, the format field in the version table
                     * describes the encoding. */
                    switch (picoquic_supported_versions[ph->version_index].version_header_encoding) {
                    case picoquic_version_header_09:
                    case picoquic_version_header_10:
                        switch (bytes[0]) {
                        case 0xFF:
                            ph->ptype = picoquic_packet_client_initial;
                            break;
                        case 0xFE:
                            ph->ptype = picoquic_packet_server_stateless;
                            break;
                        case 0xFD:
                            ph->ptype = picoquic_packet_handshake;
                            break;
                        case 0xFC:
                            ph->ptype = picoquic_packet_0rtt_protected;
                            break;
                        default:
                            ph->ptype = picoquic_packet_error;
                            break;
                        }
                    }

                    /* If the context was found by using `addr_from`, but the packet type
                     * does not allow that, reset the context to NULL. */
                    if (context_by_addr)
                    {
                        if (ph->ptype == picoquic_packet_client_initial || ph->ptype == picoquic_packet_0rtt_protected)
                        {
                            if (picoquic_compare_connection_id(&(*pcnx)->initial_cnxid, &ph->cnx_id) != 0) {
                                *pcnx = NULL;
                            }
                        } else if (ph->ptype != picoquic_packet_handshake &&
                            ph->ptype != picoquic_packet_server_stateless ) {
                            *pcnx = NULL;
                        }
                    }
                }
            }
        }
    } else {
        /* If this is a short header, it should be possible to retrieve the connection
         * context. We don't want to check first by address, because there may be
         * several established connections to the same address. So, we first check
         * by connection ID, if it is not omitted.
         *
         * Note that bit 0x40 of the first byte is classified as part of the QUIC invariants.
         */

        ph->cnx_id = picoquic_null_connection_id;
        ph->vn = 0;
        ph->pn = 0;

        if ((bytes[0] & 0x40) == 0) {
            if (length >= 1 + sizeof(picoquic_connection_id_t)) {
                /* We can identify the connection by its ID */
                ph->offset = 1 + picoquic_parse_connection_id(bytes + 1, &ph->cnx_id);
                /* TODO: should consider using combination of CNX ID and ADDR_FROM */
                if (*pcnx == NULL)
                {
                    *pcnx = picoquic_cnx_by_id(quic, ph->cnx_id);
                }
            } else {
                ph->ptype = picoquic_packet_error;
                ph->offset = length;
            }
        } else {
            ph->offset = 1;
        }

        if (*pcnx == NULL) {
            *pcnx = picoquic_cnx_by_net(quic, addr_from);
        }

        if (*pcnx != NULL) {
            ph->version_index = (*pcnx)->version_index;
            /* If the connection is identified, decode the short header per version ID */
            switch (picoquic_supported_versions[ph->version_index].version_header_encoding) {
            case picoquic_version_header_09:

                if ((bytes[0] & 0x20) == 0) {
                    ph->ptype = picoquic_packet_1rtt_protected_phi0;
                }
                else {
                    ph->ptype = picoquic_packet_1rtt_protected_phi1;
                }

                ph->pn_offset = ph->offset;

                switch (bytes[0] & 0x1F) {
                case 0x1F:
                    ph->pn = bytes[ph->offset];
                    ph->pnmask = 0xFFFFFFFFFFFFFF00ull;
                    ph->offset += 1;
                    break;
                case 0x1E:
                    ph->pn = PICOPARSE_16(&bytes[ph->offset]);
                    ph->pnmask = 0xFFFFFFFFFFFF0000ull;
                    ph->offset += 2;
                    break;
                case 0x1D:
                    ph->pn = PICOPARSE_32(&bytes[ph->offset]);
                    ph->pnmask = 0xFFFFFFFF00000000ull;
                    ph->offset += 4;
                    break;
                default:
                    ph->ptype = picoquic_packet_error;
                    break;
                }
                break;

            case picoquic_version_header_10:

                if ((bytes[0] & 0x20) == 0) {
                    ph->ptype = picoquic_packet_1rtt_protected_phi0;
                } else {
                    ph->ptype = picoquic_packet_1rtt_protected_phi1;
                }

                ph->pn_offset = ph->offset;

                switch (bytes[0] & 0x1F) {
                case 0:
                    ph->pn = bytes[ph->offset];
                    ph->pnmask = 0xFFFFFFFFFFFFFF00ull;
                    ph->offset += 1;
                    break;
                case 1:
                    ph->pn = PICOPARSE_16(&bytes[ph->offset]);
                    ph->pnmask = 0xFFFFFFFFFFFF0000ull;
                    ph->offset += 2;
                    break;
                case 2:
                    ph->pn = PICOPARSE_32(&bytes[ph->offset]);
                    ph->pnmask = 0xFFFFFFFF00000000ull;
                    ph->offset += 4;
                    break;
                default:
                    ph->ptype = picoquic_packet_error;
                    break;
                }
            }

            if (length < ph->offset) {
                ret = -1;
            }
        }
        else {
            /* If the connection is not identified, classify the packet as unknown.
             * it may trigger a retry */
            ph->ptype = picoquic_packet_error;
        }
    }

    return ret;
}

/* Check whether a packet was sent in clear text */
int picoquic_is_packet_encrypted(
    picoquic_cnx_t* cnx,
    uint8_t byte_zero)
{
    int ret = 0;

    /* Is this a long header of a short header? */
    if ((byte_zero & 0x80) == 0x80) {
        switch (picoquic_supported_versions[cnx->version_index].version_header_encoding) {
        case picoquic_version_header_09:
        case picoquic_version_header_10:
            switch (byte_zero) {
            case 0xFC: /* picoquic_packet_0rtt_protected*/
                ret = 1;
                break;
            default:
                break;
            }
        }
    } else {
        /* If this is a short header, we know that the packet is encrypted  */
        ret = 1;
    }

    return ret;
}

/* The packet number logic */
uint64_t picoquic_get_packet_number64(uint64_t highest, uint64_t mask, uint32_t pn)
{
    uint64_t expected = highest + 1;
    uint64_t not_mask_plus_one = (~mask) + 1;
    uint64_t pn64 = (expected & mask) | pn;

    if (pn64 < expected) {
        uint64_t delta1 = expected - pn64;
        uint64_t delta2 = not_mask_plus_one - delta1;
        if (delta2 < delta1) {
            pn64 += not_mask_plus_one;
        }
    } else {
        uint64_t delta1 = pn64 - expected;
        uint64_t delta2 = not_mask_plus_one - delta1;

        if (delta2 <= delta1 && (pn64 & mask) > 0) {
            /* Out of sequence packet from previous roll */
            pn64 -= not_mask_plus_one;
        }
    }

    return pn64;
}

/*
 * Apply packet number decryption. This may require updating the 
 * sequence number and the offset 
 */
size_t  picoquic_decrypt_packet(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length, picoquic_packet_header* ph, 
    void * pn_enc, void* aead_context, int * already_received)
{
    /*
     * If needed, decrypt the packet number, in place.
     */
    size_t decoded = length + 32;

    *already_received = 0;

    if ((picoquic_supported_versions[cnx->version_index].version_flags&picoquic_version_use_pn_encryption) != 0)
    {
        if (pn_enc != NULL)
        {
            /* The sample is located at the offset */
            size_t sample_offset = ph->offset;
            size_t aead_checksum_length = picoquic_aead_get_checksum_length(aead_context);
            if (sample_offset + aead_checksum_length > length)
            {
                sample_offset = length - aead_checksum_length;
            }
            if (ph->pn_offset < sample_offset)
            {
                /* Decode */
                picoquic_pn_encrypt(pn_enc, bytes + sample_offset, bytes + ph->pn_offset, bytes + ph->pn_offset, sample_offset - ph->pn_offset);
                /* TODO: what if varint? */
                /* Update the packet number in the PH structure */
                switch (sample_offset - ph->pn_offset)
                {
                case 1:
                    ph->pn = bytes[ph->pn_offset];
                    ph->pnmask = 0xFFFFFFFFFFFFFF00ull;
                    break;
                case 2:
                    ph->pn = PICOPARSE_16(&bytes[ph->pn_offset]);
                    ph->pnmask = 0xFFFFFFFFFFFF0000ull;
                    break;
                case 4:
                    ph->pn = PICOPARSE_32(&bytes[ph->pn_offset]);
                    ph->pnmask = 0xFFFFFFFF00000000ull;
                    break;
                default:
                    /* Unexpected value -- keep ph as is. */
                    break;
                }
            }
        } else {
            /* The pn_enc algorithm was not initialized. Avoid crash! */
            ph->pn = 0xFFFFFFFF;
            ph->pnmask = 0xFFFFFFFF00000000ull;

        }
    }

    /* Build a packet number to 64 bits */
    ph->pn64 = picoquic_get_packet_number64(
        cnx->first_sack_item.end_of_sack_range, ph->pnmask, ph->pn);

    /* verify that the packet is new */
    if (picoquic_is_pn_already_received(cnx, ph->pn64) != 0) {
        /* Set error type: already received */
        *already_received = 1;
    } else {
        /* Attempt to decrypt the packet */
        decoded = picoquic_aead_decrypt_generic(bytes + ph->offset,
            bytes + ph->offset, length - ph->offset, ph->pn64, bytes, ph->offset, aead_context);
    }

    return decoded;
}

/*
 * Decode an incoming clear text packet.
 * This is done "in place"
 */
size_t picoquic_decrypt_cleartext(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length, picoquic_packet_header* ph,
    int * already_received)
{
    size_t decoded_length = picoquic_decrypt_packet(cnx, bytes, length, ph,
        cnx->pn_dec_cleartext, cnx->aead_decrypt_cleartext_ctx, already_received);

    if (decoded_length > (length - ph->offset)) {
        /* detect an error */
        decoded_length = 0;
    } else {
        decoded_length += ph->offset;
    }

    return decoded_length;
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
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    uint32_t length,
    struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(addr_from);
#endif
    /* Parse the content */
    int ret = -1;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(addr_from);
#endif

    if (picoquic_compare_connection_id(&ph->cnx_id, &cnx->initial_cnxid) != 0 || ph->vn != 0) {
        /* Packet that do not match the "echo" checks should be logged and ignored */
        ret = 0;
    }

    if (ret != 0) {
        /* Trying to renegotiate the version, just ignore the packet if not good. */
        ret = picoquic_reset_cnx_version(cnx, bytes + ph->offset, length - ph->offset, current_time);
    }

    return ret;
}

/*
 * Send a version negotiation packet in response to an incoming packet
 * sporting the wrong version number.
 */

int picoquic_prepare_version_negotiation(
    picoquic_quic_t* quic,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph)
{
    int ret = -1;
    picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(quic);

    if (sp != NULL) {
        uint8_t* bytes = sp->bytes;
        size_t byte_index = 0;

        /* Packet type set to random value for version negotiation */
        picoquic_public_random(bytes + byte_index, 1);
        bytes[byte_index++] |= 0x80;
        /* Copy the incoming connection ID */
        byte_index += picoquic_format_connection_id(bytes + byte_index, ph->cnx_id);
        /* Set the version number to zero */
        picoformat_32(bytes + byte_index, 0);
        byte_index += 4;

        /* Set the payload to the list of versions */
        for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
            picoformat_32(bytes + byte_index, picoquic_supported_versions[i].version);
            byte_index += 4;
        }
        /* Set length and addresses, and queue. */
        sp->length = byte_index;
        memset(&sp->addr_to, 0, sizeof(sp->addr_to));
        memcpy(&sp->addr_to, addr_from,
            (addr_from->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        memset(&sp->addr_local, 0, sizeof(sp->addr_local));
        memcpy(&sp->addr_local, addr_to,
            (addr_to->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        sp->if_index_local = if_index_to;
        picoquic_queue_stateless_packet(quic, sp);
    }

    return ret;
}

/*
 * Process an unexpected connection ID. This could be an old packet from a 
 * previous connection. If the packet type correspond to an encrypted value,
 * the server can respond with a public reset
 */
void picoquic_process_unexpected_cnxid(
    picoquic_quic_t* quic,
    uint32_t length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph)
{
    if ((ph->ptype == picoquic_packet_1rtt_protected_phi0 || ph->ptype == picoquic_packet_1rtt_protected_phi1) && length > 26) {
        picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(quic);

        if (sp != NULL) {
            uint8_t* bytes = sp->bytes;
            size_t byte_index = 0;
            size_t pad_size = (size_t)(picoquic_public_uniform_random(length - 26) + 26 - 17);
            /* Packet type set to short header, with cnxid, key phase 0, 1 byte seq */
            bytes[byte_index++] = 0x41;
            /* Copy the connection ID */
            byte_index += picoquic_format_connection_id(bytes + byte_index, ph->cnx_id);
            /* Add some random bytes to look good. */
            picoquic_public_random(bytes + byte_index, pad_size);
            byte_index += pad_size;
            /* Add the public reset secret */
            (void)picoquic_create_cnxid_reset_secret(quic, ph->cnx_id, bytes + byte_index);
            byte_index += PICOQUIC_RESET_SECRET_SIZE;
            sp->length = byte_index;
            memset(&sp->addr_to, 0, sizeof(sp->addr_to));
            memcpy(&sp->addr_to, addr_from,
                (addr_from->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memset(&sp->addr_local, 0, sizeof(sp->addr_local));
            memcpy(&sp->addr_local, addr_to,
                (addr_to->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            sp->if_index_local = if_index_to;
            picoquic_queue_stateless_packet(quic, sp);
        }
    }
}

/*
 * Queue a stateless reset packet
 */

void picoquic_queue_stateless_reset(picoquic_cnx_t* cnx,
    picoquic_packet_header* ph, struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to)
{
    picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(cnx->quic);
    size_t checksum_length = 8;
    uint8_t cleartext[PICOQUIC_MAX_PACKET_SIZE];

    if (sp != NULL) {
        uint8_t* bytes = cleartext;
        size_t byte_index = 0;
        size_t data_bytes = 0;
        size_t header_length = 0;
        size_t pn_offset = 0;

        /* Packet type set to long header, with cnxid */
        bytes[byte_index++] = 0x80 | 0x7E;
        /* Copy the connection ID */
        byte_index += picoquic_format_connection_id(bytes + byte_index, ph->cnx_id);
        /* Copy the version number */
        picoformat_32(bytes + byte_index, ph->vn);
        byte_index += 4;
        /* Copy the sequence number */
        pn_offset = byte_index;
        picoformat_32(bytes + byte_index, ph->pn);
        byte_index += 4;

        header_length = byte_index;

        /* Copy the stream zero data */
        if (picoquic_prepare_stream_frame(cnx, &cnx->first_stream, bytes + byte_index,
                PICOQUIC_MAX_PACKET_SIZE - byte_index - checksum_length, &data_bytes)
            == 0) {

            byte_index += data_bytes;

            /* AEAD Encrypt, to the send buffer */
            sp->length = picoquic_protect_packet(cnx, cleartext, ph->pn,
                byte_index, header_length, pn_offset,
                sp->bytes, cnx->aead_encrypt_cleartext_ctx, cnx->pn_enc_cleartext);

            memset(&sp->addr_to, 0, sizeof(sp->addr_to));
            memcpy(&sp->addr_to, addr_from,
                (addr_from->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memset(&sp->addr_local, 0, sizeof(sp->addr_local));
            memcpy(&sp->addr_local, addr_to,
                (addr_to->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            sp->if_index_local = if_index_to;
            picoquic_queue_stateless_packet(cnx->quic, sp);
        } else {
            picoquic_delete_stateless_packet(sp);
        }
    }
}

/*
 * Processing of an incoming client initial packet,
 * on an unknown connection context.
 */

int picoquic_incoming_initial(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph,
    uint64_t current_time,
    picoquic_cnx_t** p_cnx)
{
    picoquic_cnx_t* cnx = NULL;
    size_t decoded_length = 0;
    int already_received = 0;
    int ret = 0;

    *p_cnx = NULL;

    if (length < PICOQUIC_ENFORCED_INITIAL_MTU) {
        /* Unexpected packet. Reject, drop and log. */
        ret = PICOQUIC_ERROR_INITIAL_TOO_SHORT;
    } else {
        /* if listening is OK, listen */
        cnx = picoquic_create_cnx(quic, ph->cnx_id, addr_from, current_time, ph->vn, NULL, NULL, 0);

        if (cnx != NULL) {
            decoded_length = picoquic_decrypt_cleartext(cnx, bytes, length, ph, &already_received);

            if (decoded_length == 0) {
                /* Incorrect checksum, drop and log. */
                picoquic_delete_cnx(cnx);
                cnx = NULL;
                ret = PICOQUIC_ERROR_FNV1A_CHECK;
            } else {

                ret = picoquic_decode_frames(cnx,
                    bytes + ph->offset, decoded_length - ph->offset, 1, current_time);

                /* processing of client initial packet */
                if (ret == 0) {
                    /* initialization of context & creation of data */
                    /* TODO: find path to send data produced by TLS. */
                    ret = picoquic_tlsinput_stream_zero(cnx);

                    if (cnx->cnx_state == picoquic_state_server_send_hrr) {
                        picoquic_queue_stateless_reset(cnx, ph, addr_from, addr_to, if_index_to);
                        cnx->cnx_state = picoquic_state_disconnected;
                    }
                }

                if (ret != 0 || cnx->cnx_state == picoquic_state_disconnected) {
                    /* This is bad. should just delete the context, log the packet, etc */
                    picoquic_delete_cnx(cnx);
                    cnx = NULL;
                    ret = 0;
                } else {
                    /* remember the local address on which the initial packet arrived. */
                    cnx->path[0]->if_index_dest = if_index_to;
                    cnx->path[0]->dest_addr_len = (addr_to->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                    memcpy(&cnx->path[0]->dest_addr, addr_to, cnx->path[0]->dest_addr_len);
                    *p_cnx = cnx;
                }
            }
        }
    }

    return ret;
}

/*
 * Processing of a server stateless packet.
 *
 * The packet number and connection ID fields echo the corresponding fields from the 
 * triggering client packet. This allows a client to verify that the server received its packet.
 *
 * A Server Stateless Retry packet is never explicitly acknowledged in an ACK frame by a client.
 * Receiving another Client Initial packet implicitly acknowledges a Server Stateless Retry packet.
 *
 * After receiving a Server Stateless Retry packet, the client uses a new Client Initial packet 
 * containing the next cryptographic handshake message. The client retains the state of its 
 * cryptographic handshake, but discards all transport state. In effect, the next cryptographic
 * handshake message is sent on a new connection. The new Client Initial packet is sent in a 
 * packet with a newly randomized packet number and starting at a stream offset of 0.
 *
 * Continuing the cryptographic handshake is necessary to ensure that an attacker cannot force
 * a downgrade of any cryptographic parameters. In addition to continuing the cryptographic 
 * handshake, the client MUST remember the results of any version negotiation that occurred 
 * (see Section 7.1). The client MAY also retain any observed RTT or congestion state that it 
 * has accumulated for the flow, but other transport state MUST be discarded.
 */

int picoquic_incoming_server_stateless(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    uint32_t length,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;
    size_t decoded_length = 0;
    int already_received = 0;

    if (cnx->cnx_state != picoquic_state_client_init_sent && cnx->cnx_state != picoquic_state_client_init_resent) {
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    } else {
        /* Verify the checksum */
        decoded_length = picoquic_decrypt_cleartext(cnx, bytes, length, ph, &already_received);
        if (decoded_length == 0) {
            /* Incorrect checksum, drop and log. */
            ret = (already_received)? PICOQUIC_ERROR_DUPLICATE:PICOQUIC_ERROR_FNV1A_CHECK;
        } else {
            /* Verify that the header is a proper echo of what was sent */
            if (ph->vn != picoquic_supported_versions[cnx->version_index].version || (cnx->retransmit_newest == NULL || ph->pn64 > cnx->retransmit_newest->sequence_number) || (cnx->retransmit_oldest == NULL || ph->pn64 < cnx->retransmit_oldest->sequence_number)) {
                /* Packet that do not match the "echo" checks should be logged and ignored */
                ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
            }
        }

        if (ret == 0) {
            /* Accept the incoming frames */
            ret = picoquic_decode_frames(cnx,
                bytes + ph->offset, decoded_length - ph->offset, 1, current_time);
        }

        /* processing of the TLS message */
        if (ret == 0) {
            /* set the state to HRR received, will trigger behavior when processing stream zero */
            cnx->cnx_state = picoquic_state_client_hrr_received;
            /* Remove the resume ticket if any */
            picoquic_tlscontext_remove_ticket(cnx);
            /* submit the embedded message (presumably HRR) to stream zero */
            ret = picoquic_tlsinput_stream_zero(cnx);
            if (ret == 0)
            {
                /* reset the initial CNX_ID to the version sent by the server */
                cnx->initial_cnxid = ph->cnx_id;

                /* reset the clear text AEAD */
                if (cnx->aead_encrypt_cleartext_ctx != NULL) {
                    picoquic_aead_free(cnx->aead_encrypt_cleartext_ctx);
                    cnx->aead_encrypt_cleartext_ctx = NULL;
                }

                if (cnx->aead_decrypt_cleartext_ctx != NULL) {
                    picoquic_aead_free(cnx->aead_decrypt_cleartext_ctx);
                    cnx->aead_decrypt_cleartext_ctx = NULL;
                }

                if (cnx->aead_de_encrypt_cleartext_ctx != NULL) {
                    picoquic_aead_free(cnx->aead_de_encrypt_cleartext_ctx);
                    cnx->aead_de_encrypt_cleartext_ctx = NULL;
                }

                if (cnx->pn_enc_cleartext != NULL)
                {
                    picoquic_pn_enc_free(cnx->pn_enc_cleartext);
                    cnx->pn_enc_cleartext = NULL;
                }

                if (cnx->pn_dec_cleartext != NULL)
                {
                    picoquic_pn_enc_free(cnx->pn_dec_cleartext);
                    cnx->pn_dec_cleartext = NULL;
                }

                if (cnx->aead_0rtt_decrypt_ctx != NULL) {
                    picoquic_aead_free(cnx->aead_0rtt_decrypt_ctx);
                    cnx->aead_0rtt_decrypt_ctx = NULL;
                }

                if (cnx->aead_0rtt_encrypt_ctx != NULL) {
                    picoquic_aead_free(cnx->aead_0rtt_encrypt_ctx);
                    cnx->aead_0rtt_encrypt_ctx = NULL;
                }

                if (cnx->pn_enc_0rtt != NULL)
                {
                    picoquic_pn_enc_free(cnx->pn_enc_0rtt);
                    cnx->pn_enc_0rtt = NULL;
                }

                /* Reinit the clear text AEAD */
                ret = picoquic_setup_cleartext_aead_contexts(cnx);
            }
        }
        if (ret == 0) {
            /* Mark the packet as not required for ack */
            ret = PICOQUIC_ERROR_HRR;
        }
    }

    return ret;
}

/*
 * Processing of a server clear text packet.
 */

int picoquic_incoming_server_cleartext(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    uint32_t length,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(if_index_to);
#endif
    int ret = 0;
    size_t decoded_length = 0;
    int already_received = 0;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(if_index_to);
#endif

    if (cnx->cnx_state == picoquic_state_client_init_sent || cnx->cnx_state == picoquic_state_client_init_resent) {
        cnx->cnx_state = picoquic_state_client_handshake_start;
    }

    if (cnx->cnx_state == picoquic_state_client_handshake_start || cnx->cnx_state == picoquic_state_client_handshake_progress) {
        /* Verify the checksum */
        decoded_length = picoquic_decrypt_cleartext(cnx, bytes, length, ph, &already_received);
        if (decoded_length == 0) {
            /* Incorrect checksum, drop and log. */
            ret = (already_received)? PICOQUIC_ERROR_DUPLICATE:PICOQUIC_ERROR_FNV1A_CHECK;
        } else {
            /* Check the server cnx id */
            if (picoquic_is_connection_id_null(cnx->server_cnxid)) {
                /* On first response from the server, copy the cnx ID and the incoming address */
                cnx->server_cnxid = ph->cnx_id;
                cnx->path[0]->dest_addr_len = (addr_to->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
                memcpy(&cnx->path[0]->dest_addr, addr_to, cnx->path[0]->dest_addr_len);

                (void)picoquic_register_cnx_id(cnx->quic, cnx, cnx->server_cnxid);
            } else if (picoquic_compare_connection_id(&cnx->server_cnxid, &ph->cnx_id) != 0) {
                ret = PICOQUIC_ERROR_CNXID_CHECK; /* protocol error */
            }

            if (ret == 0) {
                /* Accept the incoming frames */
                ret = picoquic_decode_frames(cnx,
                    bytes + ph->offset, decoded_length - ph->offset, 1, current_time);
            }

            /* processing of client initial packet */
            if (ret == 0) {
                /* initialization of context & creation of data */
                /* TODO: find path to send data produced by TLS. */
                ret = picoquic_tlsinput_stream_zero(cnx);
            }

            if (ret != 0) {
                /* This is bad. should just delete the context, log the packet, etc */
            }
        }
    } else {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_SPURIOUS_REPEAT;
    }

    return ret;
}

/*
 * Processing of client clear text packet.
 */
int picoquic_incoming_client_cleartext(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    uint32_t length,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;
    size_t decoded_length = 0; 
    int already_received = 0;

    if (cnx->cnx_state == picoquic_state_server_almost_ready || cnx->cnx_state == picoquic_state_server_ready) {
        /* Verify the checksum */
        decoded_length = picoquic_decrypt_cleartext(cnx, bytes, length, ph, &already_received);
        if (decoded_length == 0) {
            /* Incorrect checksum, drop and log. */
            ret = (already_received)?PICOQUIC_ERROR_DUPLICATE:PICOQUIC_ERROR_FNV1A_CHECK;
        } else if (picoquic_compare_connection_id(&ph->cnx_id, &cnx->server_cnxid) != 0) {
            ret = PICOQUIC_ERROR_CNXID_CHECK;
        } else {
            /* Accept the incoming frames */
            ret = picoquic_decode_frames(cnx,
                bytes + ph->offset, decoded_length - ph->offset, 1, current_time);

            /* processing of client clear text packet */
            if (ret == 0) {
                /* initialization of context & creation of data */
                /* TODO: find path to send data produced by TLS. */
                ret = picoquic_tlsinput_stream_zero(cnx);
            }

            if (ret != 0) {
                /* This is bad. should just delete the context, log the packet, etc */
            }
        }
    } else {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}

/*
* Processing of stateless reset packet.
*/
int picoquic_incoming_stateless_reset(
    picoquic_cnx_t* cnx)
{
    /* Stateless reset. The connection should be abandonned */
    cnx->cnx_state = picoquic_state_disconnected;

    if (cnx->callback_fn) {
        (cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
    }

    return PICOQUIC_ERROR_AEAD_CHECK;
}

/*
 * Processing of 0-RTT packet 
 */

int picoquic_incoming_0rtt(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    uint32_t length,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;
    size_t decoded_length = 0;
    int already_received = 0;

    if (picoquic_compare_connection_id(&ph->cnx_id , &cnx->initial_cnxid)!=0) {
        ret = PICOQUIC_ERROR_CNXID_CHECK;
    } else if ((cnx->cnx_state == picoquic_state_server_almost_ready || cnx->cnx_state == picoquic_state_server_ready) &&
        cnx->aead_0rtt_decrypt_ctx != NULL) {
        /* AEAD Decrypt, in place */
        decoded_length = picoquic_decrypt_packet(cnx, bytes, length, ph, cnx->pn_enc_0rtt,
            cnx->aead_0rtt_decrypt_ctx, &already_received);

        if (already_received){
            ret = PICOQUIC_ERROR_DUPLICATE;
        } else if (decoded_length > (length - ph->offset)) {
            ret = PICOQUIC_ERROR_AEAD_CHECK;
        } else if (ph->vn != picoquic_supported_versions[cnx->version_index].version) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
        } else {
            /* Accept the incoming frames */
            ret = picoquic_decode_frames(cnx,
                bytes + ph->offset, decoded_length, 0, current_time);

            /* Yell if there is data coming on stream zero */
            if (ret == 0) {
                picoquic_stream_data* data = cnx->first_stream.stream_data;

                if (data != NULL && data->offset < cnx->first_stream.consumed_offset) {
                    ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
                }
            }
        }
    } else {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}

/*
 * Processing of client encrypted packet.
 */
int picoquic_incoming_encrypted(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    uint32_t length,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;
    size_t decoded_length = 0;
    int already_received = 0;

    if (picoquic_compare_connection_id(&ph->cnx_id, &cnx->server_cnxid) != 0 && (!picoquic_is_connection_id_null(ph->cnx_id) || cnx->local_parameters.omit_connection_id == 0)) {
        ret = PICOQUIC_ERROR_CNXID_CHECK;
    } else if (
        cnx->cnx_state >= picoquic_state_client_almost_ready && cnx->cnx_state <= picoquic_state_closing) {
        /* Check the possible reset before performaing in place AEAD decrypt */
        int cmp_reset_secret = memcmp(bytes + length - PICOQUIC_RESET_SECRET_SIZE,
                cnx->reset_secret, PICOQUIC_RESET_SECRET_SIZE);

        /* AEAD Decrypt, in place */
        decoded_length = picoquic_decrypt_packet(cnx, bytes, length, ph, cnx->pn_dec,
            cnx->aead_decrypt_ctx, &already_received);

        if (decoded_length > (length - ph->offset)) {
            /* Bad packet should be ignored -- unless it is actually a server reset */
            if (ph->vn == 0 && length >= (9 + PICOQUIC_RESET_SECRET_SIZE) && cmp_reset_secret == 0) {
                ret = picoquic_incoming_stateless_reset(cnx);
            } else {
                ret = (already_received)? PICOQUIC_ERROR_DUPLICATE:PICOQUIC_ERROR_AEAD_CHECK;
            }
        } else {
            /* only look for closing frames in closing mode */
            if (cnx->cnx_state == picoquic_state_closing) {
                int closing_received = 0;

                ret = picoquic_decode_closing_frames(
                    bytes + ph->offset, decoded_length, &closing_received,
                    picoquic_supported_versions[cnx->version_index].version);

                if (ret == 0) {
                    if (closing_received) {
                        if (cnx->client_mode) {
                            cnx->cnx_state = picoquic_state_disconnected;
                        } else {
                            cnx->cnx_state = picoquic_state_draining;
                        }
                    } else {
                        cnx->ack_needed = 1;
                    }
                }
            } else
                /* all frames are ignored in draining mode, or after receiving a closing frame */
                if (cnx->cnx_state == picoquic_state_draining || cnx->cnx_state == picoquic_state_closing_received) {
            }
            /* VN = 0 indicates "long" header encoding, which is now banned.
             * The error is only generated if the packet can be properly
             * decrypted. */
            else if (ph->vn != 0) {
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
            } else {
                /* Accept the incoming frames */
                ret = picoquic_decode_frames(cnx,
                    bytes + ph->offset, decoded_length, 0, current_time);
            }

            if (ret == 0) {
                /* Processing of TLS messages  */
                ret = picoquic_tlsinput_stream_zero(cnx);
            }
        }
    } else {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}

/*
* Processing of the packet that was just received from the network.
*/

int picoquic_incoming_packet(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    uint64_t current_time)
{
    int ret = 0;
    picoquic_cnx_t* cnx = NULL;
    picoquic_packet_header ph;

    /* Parse the clear text header. Ret == 0 means an incorrect packet that could not be parsed */
    ret = picoquic_parse_packet_header(quic, bytes, length, addr_from, &ph, &cnx);

    if (ret == 0) {
        if (cnx == NULL) {
            if (ph.ptype == picoquic_packet_client_initial) {
                ph.pn64 = ph.pn;
                ret = picoquic_incoming_initial(quic, bytes, length, addr_from, addr_to, if_index_to, &ph, current_time, &cnx);
            } else if (ph.version_index < 0 && ph.vn != 0) {
                /* use the result of parsing to consider version negotiation */
                picoquic_prepare_version_negotiation(quic, addr_from, addr_to, if_index_to, &ph);
            } else {
                /* Unexpected packet. Reject, drop and log. */
                if (!picoquic_is_connection_id_null(ph.cnx_id)) {
                    picoquic_process_unexpected_cnxid(quic, length, addr_from, addr_to, if_index_to, &ph);
                }
                ret = PICOQUIC_ERROR_DETECTED;
            }
        } else {
            /* Build a packet number to 64 bits */
            ph.pn64 = picoquic_get_packet_number64(
                cnx->first_sack_item.end_of_sack_range, ph.pnmask, ph.pn);
            if (ret == 0) {
                switch (ph.ptype) {
                case picoquic_packet_version_negotiation:
                    if (cnx->cnx_state == picoquic_state_client_init_sent) {
                        /* Proceed with version negotiation*/
                        ret = picoquic_incoming_version_negotiation(
                            cnx, bytes, length, addr_from, &ph, current_time);
                    } else {
                        /* This is an unexpected packet. Log and drop.*/
                        ret = PICOQUIC_ERROR_DETECTED;
                    }
                    break;
                case picoquic_packet_client_initial:
                    /* Not expected here. Treat as a duplicate. */
                    if (picoquic_compare_connection_id(&ph.cnx_id, &cnx->initial_cnxid) == 0)
                        ret = PICOQUIC_ERROR_SPURIOUS_REPEAT;
                    else
                        ret = PICOQUIC_ERROR_DETECTED;
                    break;
                case picoquic_packet_server_stateless:
                    ret = picoquic_incoming_server_stateless(cnx, bytes, length, &ph, current_time);
                    break;
                case picoquic_packet_handshake:
                    if (cnx->client_mode)
                    {
                        ret = picoquic_incoming_server_cleartext(cnx, bytes, length, addr_to, if_index_to, &ph, current_time);
                    }
                    else
                    {
                        ret = picoquic_incoming_client_cleartext(cnx, bytes, length, &ph, current_time);
                    }
                    break;
                case picoquic_packet_0rtt_protected:
                    /* TODO : decrypt with 0RTT key */
                    ret = picoquic_incoming_0rtt(cnx, bytes, length, &ph, current_time);
                    break;
                case picoquic_packet_1rtt_protected_phi0:
                case picoquic_packet_1rtt_protected_phi1:
                    ret = picoquic_incoming_encrypted(cnx, bytes, length, &ph, current_time);
                    /* TODO : roll key based on PHI */
                    break;
                default:
                    /* Packet type error. Log and ignore */
                    ret = PICOQUIC_ERROR_DETECTED;
                    break;
                }
            }
        }
    }

    if (ret == 0 || ret == PICOQUIC_ERROR_SPURIOUS_REPEAT) {
        if (cnx != NULL && ph.ptype != picoquic_packet_version_negotiation) {
            /* Mark the sequence number as received */
            ret = picoquic_record_pn_received(cnx, ph.pn64, current_time);
        }
    } else if (ret == PICOQUIC_ERROR_DUPLICATE) {
        /* Bad packets are dropped silently, but duplicates should be acknowledged */
        if (cnx != NULL) {
            cnx->ack_needed = 1;
        }
        ret = 0;
    } else if (ret == PICOQUIC_ERROR_AEAD_CHECK || ret == PICOQUIC_ERROR_INITIAL_TOO_SHORT ||
        ret == PICOQUIC_ERROR_UNEXPECTED_PACKET || ret == PICOQUIC_ERROR_FNV1A_CHECK || 
        ret == PICOQUIC_ERROR_CNXID_CHECK || ret == PICOQUIC_ERROR_HRR || ret == PICOQUIC_ERROR_DETECTED) {
        /* Bad packets are dropped silently */
        ret = 0;
    }
    else if (ret == 1)
    {
        /* wonder what happened ! */
        ret = 0;
    }

    if (cnx != NULL) {
        picoquic_cnx_set_next_wake_time(cnx, current_time);
    }

    return ret;
}
