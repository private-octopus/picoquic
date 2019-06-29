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

/**
 * If the version is not know, need special code as long as we support
 * draft-20 and the corresponding format */

int picoquic_is_old_header_invariant(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    picoquic_packet_header* ph)
{
    int ret = 0; /* return 1 if old invariant */
    if ((ph->vn & 0xFFFFFF00) == 0xFF000000) {
        /* Draft versions before #20 use the old invariants */
        int draft_nb = ph->vn & 0xFF;
        ret = (draft_nb <= 20) ? 1 : 0;
    }
    else if (ph->vn != 0 && (
        (ph->vn & 0xFFFFFFF0) == 0 ||
        ph->vn == PICOQUIC_INTERNAL_TEST_VERSION_1 ||
        ph->vn == PICOQUIC_INTERNAL_TEST_VERSION_2)) {
        /* Final versions and internal versions use the new invariants */
        ret = 0;
    } else {
        /* Cases where the version is either NULL, or one of the greasing
         * values, or maybe a proprietary value. We first do a heuristic test
         * based on the plausibility of the CID values. */
        uint8_t l_dest_id1, l_srce_id1, l_dest_id2, l_srce_id2, l1, l2;

        picoquic_parse_packet_header_cnxid_lengths(bytes[5], &l_dest_id1, &l_srce_id1);
        l_dest_id2 = bytes[5];
        l1 = 5 + 1 + l_dest_id1 + l_srce_id1;
        if (l1 > length) {
            ret = 0;
        } else if (l_dest_id2 > 20u || 5u + l_dest_id2 + 1u > length) {
            /* if packet is old invariant, this test will succeed whenever the
             * destination id is longer than 4, which covers a lot of cases */
            ret = 1;
        }
        else {
            l_srce_id2 = bytes[5 + l_dest_id2 + 1];
            l2 = 5 + l_dest_id2 + 1 + l_dest_id2;
            if (l_dest_id2 > 20 || l2 > length) {
                /* If packet is old invarion, bytes[l_srce_id2] will likely be 
                 * a random number, so this test will succeed more than 90% of the time. */
                ret = 1;
            }
            else if (ph->vn == 0) {
                /* Heuristics have failed. Check whether this can be parsed reasonably
                 * as a version negotiation, i.e. header plus list of versions */
                if (((length - l1) % 4) != 0) {
                    /* Parsing with old invariant would result in malformed packets */
                    ret = 0;
                } else if (((length - l2) % 4) != 0){
                    /* Parsing with new invariant would result in malformed packets */
                    ret = 1;
                }
                else if (l_srce_id1 < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH) {
                    /* In a VN packet, source should copy inital CID */
                    ret = 0;
                }
                else if (l_srce_id2 < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH) {
                    ret = 1;
                }
                else if (l_dest_id1 == quic->local_cnxid_length && 
                    l_dest_id2 != quic->local_cnxid_length) {
                    /* plausible old VN response to local request */
                    ret = 1;
                }
                else if (l_dest_id2 == quic->local_cnxid_length &&
                    l_dest_id1 != quic->local_cnxid_length) {
                    /* plausible new VN response to local request */
                    ret = 0;
                }
                else {
                    /* Running out of heuristics, just pick version = new */
                    ret = 0;
                }
            }
            else {
                /* Unknown version, not a version negotiation packet.
                 * Check whether it can plausibly parse as an Initial packet */
                if (l_dest_id1 < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH) {
                    /* Initial CID mismatch if old version. This is a very strong test,
                     * since the most significant nibble of dest length can only take
                     * values 0 or 1 in new format, i.e. length 0 or 4 in old format */
                    ret = 0;
                }
                else {
                    /* we don't know, so let's assume old version. */
                    ret = 1;
                }
            }
        }
    }
    ph->is_old_invariant = ret;

    return ret;
}

/*
 * The packet header parsing is version dependent
 */

int picoquic_parse_packet_header(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    int receiving)
{
    int ret = 0;

    /* Initialize the PH structure to zero, but version index to -1 (error) */
    memset(ph, 0, sizeof(picoquic_packet_header));
    ph->version_index = -1;

    /* Is this a long header of a short header? -- in any case, we need at least 17 bytes */
    if ((bytes[0] & 0x80) == 0x80) {
        if (length < 6) {
            ret = -1;
        } else {
            uint8_t l_dest_id, l_srce_id;
            uint32_t i_srce_id;

            /* The bytes at position 1..4 describe the version */
            ph->vn = PICOPARSE_32(bytes + 1);
            if (picoquic_is_old_header_invariant(quic, bytes, length, ph)) {
                /* Obtain the connection ID lengths from the byte following the version */
                picoquic_parse_packet_header_cnxid_lengths(bytes[5], &l_dest_id, &l_srce_id);

                i_srce_id = 6 + l_dest_id;
            }
            else {
                l_dest_id = bytes[5];
                if (6u + l_dest_id + 1u > length) {
                    l_srce_id = 255;
                    i_srce_id = length;
                }
                else {
                    l_srce_id = bytes[6 + l_dest_id];
                    i_srce_id = 6 + l_dest_id + 1;
                }
            }
            /* Required length: at least one length byte and at least one seqnum byte
             * after the srce id*/
            if (i_srce_id + l_srce_id + 2 > (int) length) {
                /* malformed packet */
                ret = -1;
            }
            else {         
                (void)picoquic_parse_connection_id(bytes + 6, l_dest_id, &ph->dest_cnx_id);
                (void)picoquic_parse_connection_id(bytes + i_srce_id, l_srce_id, &ph->srce_cnx_id);
                ph->offset = i_srce_id + l_srce_id;
                
                if (ph->vn == 0) {
                    /* VN = zero identifies a version negotiation packet */
                    ph->ptype = picoquic_packet_version_negotiation;
                    ph->pc = picoquic_packet_context_initial;
                    ph->payload_length = (uint16_t) ((length > ph->offset) ? length - ph->offset : 0);
                    ph->pl_val = ph->payload_length; /* saving the value found in the packet */

                    if (*pcnx == NULL && quic != NULL) {
                        /* The version negotiation should always include the cnx-id sent by the client */
                        if (ph->dest_cnx_id.id_len > 0) {
                            *pcnx = picoquic_cnx_by_id(quic, ph->dest_cnx_id);
                        }
                        else {
                            *pcnx = picoquic_cnx_by_net(quic, addr_from);

                            if (*pcnx != NULL && (*pcnx)->path[0]->local_cnxid.id_len != 0) {
                                *pcnx = NULL;
                            }
                        }
                    }
                }
                else {
                    char context_by_addr = 0;
                    uint64_t payload_length = 0;
                    uint32_t var_length = 0; 

                    ph->version_index = picoquic_get_version_index(ph->vn);

                    if (ph->version_index >= 0) {
                        /* If the version is supported now, the format field in the version table
                        * describes the encoding. */
                        switch (picoquic_supported_versions[ph->version_index].version_header_encoding) {
                        case picoquic_version_header_17:
                            ph->spin = 0;
                            ph->has_spin_bit = 0;
                            switch ((bytes[0] >> 4) & 7) {
                            case 4: /* Initial */
                            {
                                /* special case of the initial packets. They contain a retry token between the header
                                * and the encrypted payload */
                                uint64_t tok_len = 0;
                                size_t l_tok_len = picoquic_varint_decode(bytes + ph->offset, length - ph->offset, &tok_len);

                                ph->ptype = picoquic_packet_initial;
                                ph->pc = picoquic_packet_context_initial;
                                ph->epoch = 0;
                                if (l_tok_len == 0) {
                                    /* packet is malformed */
                                    ph->offset = length;
                                    ph->ptype = picoquic_packet_error;
                                    ph->pc = 0;
                                }
                                else {
                                    ph->token_length = (uint32_t)tok_len;
                                    ph->token_bytes = bytes + ph->offset + (uint32_t)l_tok_len;
                                    ph->offset += (uint32_t)(l_tok_len + (size_t)tok_len);
                                }

                                break;
                            }
                            case 5: /* 0-RTT Protected */
                                ph->ptype = picoquic_packet_0rtt_protected;
                                ph->pc = picoquic_packet_context_application;
                                ph->epoch = 1;
                                break;
                            case 6: /* Handshake */
                                ph->ptype = picoquic_packet_handshake;
                                ph->pc = picoquic_packet_context_handshake;
                                ph->epoch = 2;
                                break;
                            case 7: /* Retry */
                                ph->ptype = picoquic_packet_retry;
                                ph->pc = picoquic_packet_context_initial;
                                ph->epoch = 0;
                                break;
                            default: /* Not a valid packet type */
                                DBG_PRINTF("Packet type is not recognized: 0x%02x\n", bytes[0]);
                                ph->ptype = picoquic_packet_error;
                                ph->version_index = -1;
                                ph->pc = 0;
                                break;
                            }
                            break;
                        default:
                            /* version is not supported */
                            DBG_PRINTF("Version (%x) is recognized but encoding not supported\n", ph->vn);
                            ph->ptype = picoquic_packet_error;
                            ph->version_index = -1;
                            ph->pc = 0;
                            break;
                        }
                    }

                    if (ph->ptype == picoquic_packet_retry) {
                        /* No segment length or sequence number in retry packets */
                        if (length > ph->offset) {
                            payload_length = (uint16_t)length - ph->offset;
                        }
                        else {
                            payload_length = 0;
                            ph->ptype = picoquic_packet_error;
                        }
                    } else {
                        if (ph->offset < length) {
                            var_length = (uint32_t)picoquic_varint_decode(bytes + ph->offset,
                                length - ph->offset, &payload_length);
                        }

                        if (var_length <= 0 || ph->offset + var_length + payload_length > length ||
                            ph->version_index < 0) {
                            ph->ptype = picoquic_packet_error;
                            ph->payload_length = (uint16_t)((length > ph->offset) ? length - ph->offset : 0);
                            ph->pl_val = ph->payload_length;
                        }
                    }
                    
                    if (ph->ptype != picoquic_packet_error)
                    {
                        ph->pl_val = (uint16_t)payload_length;
                        ph->payload_length = (uint16_t)payload_length;
                        ph->offset += var_length;
                        ph->pn_offset = ph->offset;

                        /* Retrieve the connection context */
                        if (*pcnx == NULL) {
                            if (ph->dest_cnx_id.id_len != 0) {
                                *pcnx = picoquic_cnx_by_id(quic, ph->dest_cnx_id);
                            }

                            /* TODO: something for the case of client initial, e.g. source IP + initial CNX_ID */
                            if (*pcnx == NULL) {
                                *pcnx = picoquic_cnx_by_net(quic, addr_from);

                                if (*pcnx != NULL)
                                {
                                    context_by_addr = 1;
                                }
                            }
                        }

                        /* If the context was found by using `addr_from`, but the packet type
                         * does not allow that, reset the context to NULL. */
                        if (context_by_addr)
                        {
                            if ((*pcnx)->client_mode) {
                                if ((*pcnx)->path[0]->local_cnxid.id_len != 0) {
                                    *pcnx = NULL;
                                }
                            } else if (ph->ptype != picoquic_packet_initial && ph->ptype != picoquic_packet_0rtt_protected)
                            {
                                *pcnx = NULL;
                            } else if (picoquic_compare_connection_id(&(*pcnx)->initial_cnxid, &ph->dest_cnx_id) != 0) {
                                *pcnx = NULL;
                            }
                        }
                    }
                }
            }
        }
    } else {
        /* If this is a short header, it should be possible to retrieve the connection
         * context. This depends on whether the quic context requires cnx_id or not.
         */
         uint8_t cnxid_length = (receiving == 0 && *pcnx != NULL) ? (*pcnx)->path[0]->remote_cnxid.id_len : quic->local_cnxid_length;
         ph->pc = picoquic_packet_context_application;
         ph->pl_val = 0; /* No actual payload length in short headers */

         if ((int)length >= 1 + cnxid_length) {
             /* We can identify the connection by its ID */
             ph->offset = (uint32_t)( 1 + picoquic_parse_connection_id(bytes + 1, cnxid_length, &ph->dest_cnx_id));
             /* TODO: should consider using combination of CNX ID and ADDR_FROM */
             if (*pcnx == NULL)
             {
                 if (quic->local_cnxid_length > 0) {
                     *pcnx = picoquic_cnx_by_id(quic, ph->dest_cnx_id);
                 }
                 else {
                     *pcnx = picoquic_cnx_by_net(quic, addr_from);
                 }
             }
         } else {
             ph->ptype = picoquic_packet_error;
             ph->offset = length;
             ph->payload_length = 0;
         }
      
         if (*pcnx != NULL) {
             ph->epoch = 3;
             ph->version_index = (*pcnx)->version_index;
             /* If the connection is identified, decode the short header per version ID */
             switch (picoquic_supported_versions[ph->version_index].version_header_encoding) {
             case picoquic_version_header_17:
                 if ((bytes[0] & 0x40) != 0x40) {
                     /* Check for QUIC bit failed! */
                     ph->ptype = picoquic_packet_error;
                 }
                 else {
                     ph->ptype = picoquic_packet_1rtt_protected;
                 }
                 ph->has_spin_bit = 1;
                 ph->spin = (bytes[0] >> 5) & 1;
                 ph->pn_offset = ph->offset;
                 ph->pn = 0;
                 ph->pnmask = 0;
                 ph->key_phase = ((bytes[0] >> 2) & 1); /* Initialize here so that simple tests with unencrypted headers can work */
                 break;
             }

             if (length < ph->offset || ph->ptype == picoquic_packet_error) {
                 ret = -1;
                 ph->payload_length = 0;
             } else {
                 ph->payload_length = (uint16_t)(length - ph->offset);
             }
         } else {
             /* This may be a packet to a forgotten connection */
             ph->ptype = picoquic_packet_1rtt_protected;
             ph->payload_length = (uint16_t)((length > ph->offset)?length - ph->offset:0);
         }
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
 * Remove header protection 
 */
int picoquic_remove_header_protection(picoquic_cnx_t* cnx,
    uint8_t* bytes, picoquic_packet_header* ph)
{
    int ret = 0;
    size_t length = ph->offset + ph->payload_length; /* this may change after decrypting the PN */
    void * pn_enc = NULL;

    pn_enc = cnx->crypto_context[ph->epoch].pn_dec;

    if (pn_enc != NULL)
    {
        /* The header length is not yet known, will only be known after the sequence number is decrypted */
        size_t mask_length = 5;
        size_t sample_offset = ph->pn_offset + 4;
        size_t sample_size = picoquic_pn_iv_size(pn_enc);
        uint8_t mask_bytes[5] = { 0, 0, 0, 0, 0 };

        if (sample_offset + sample_size > length)
        {
            /* return an error */
            /* Invalid packet format. Avoid crash! */
            ph->pn = 0xFFFFFFFF;
            ph->pnmask = 0xFFFFFFFF00000000ull;
            ph->offset = ph->pn_offset;

            DBG_PRINTF("Invalid packet length, type: %d, epoch: %d, pc: %d, pn-offset: %d, length: %d\n",
                ph->ptype, ph->epoch, ph->pc, (int)ph->pn_offset, (int)length);
        }
        else
        {   /* Decode */
            uint8_t first_byte = bytes[0];
            uint8_t first_mask = ((first_byte & 0x80) == 0x80) ? 0x0F : 0x1F;
            uint8_t pn_l;
            uint32_t pn_val = 0;

            picoquic_pn_encrypt(pn_enc, bytes + sample_offset, mask_bytes, mask_bytes, mask_length);
            /* Decode the first byte */
            first_byte ^= (mask_bytes[0] & first_mask);
            pn_l = (first_byte & 3) + 1;
            ph->pnmask = (0xFFFFFFFFFFFFFFFFull);
            bytes[0] = first_byte;

            /* Packet encoding is 1 to 4 bytes */
            for (uint8_t i = 1; i <= pn_l; i++) {
                pn_val <<= 8;
                bytes[ph->offset] ^= mask_bytes[i];
                pn_val += bytes[ph->offset++];
                ph->pnmask <<= 8;
            }

            ph->pn = pn_val;
            ph->payload_length -= pn_l;
            /* Only set the key phase byte if short header */
            if (ph->ptype == picoquic_packet_1rtt_protected) {
                ph->key_phase = ((first_byte >> 2) & 1);
            }

            /* Build a packet number to 64 bits */
            ph->pn64 = picoquic_get_packet_number64(
                cnx->pkt_ctx[ph->pc].first_sack_item.end_of_sack_range, ph->pnmask, ph->pn);

            /* Check the reserved bits */
            ph->has_reserved_bit_set = ((first_byte & 0x80) == 0) &&
                ((first_byte & 0x18) != 0);
        }
    }
    else {
        /* The pn_enc algorithm was not initialized. Avoid crash! */
        ph->pn = 0xFFFFFFFF;
        ph->pnmask = 0xFFFFFFFF00000000ull;
        ph->offset = ph->pn_offset;
        ph->pn64 = 0xFFFFFFFFFFFFFFFFull;

        DBG_PRINTF("PN dec not ready, type: %d, epoch: %d, pc: %d, pn: %d\n",
            ph->ptype, ph->epoch, ph->pc, (int)ph->pn);

        ret = -1;
    }

    return ret;
}

/*
 * Remove packet protection
 */
size_t picoquic_remove_packet_protection(picoquic_cnx_t* cnx,
    uint8_t* bytes, picoquic_packet_header* ph,
    uint64_t current_time, int * already_received)
{
    size_t decoded;
    int ret = 0;

    /* verify that the packet is new */
    if (already_received != NULL && picoquic_is_pn_already_received(cnx, ph->pc, ph->pn64) != 0) {
        /* Set error type: already received */
        *already_received = 1;
    }
    else {
        *already_received = 0;
    }

    if (ph->epoch == 3) {
        /* Manage key rotation */
        if (ph->key_phase == cnx->key_phase_dec) {
            /* AEAD Decrypt, in place */
            decoded = picoquic_aead_decrypt_generic(bytes + ph->offset,
                bytes + ph->offset, ph->payload_length, ph->pn64, bytes, ph->offset, cnx->crypto_context[3].aead_decrypt);
        }
        else if (ph->pn64 < cnx->crypto_rotation_sequence) {
            /* This packet claims to be encoded with the old key */
            if (current_time > cnx->crypto_rotation_time_guard) {
                /* Too late. Ignore the packet. Could be some kind of attack. */
                decoded = ph->payload_length + 1;
            }
            else if (cnx->crypto_context_old.aead_decrypt != NULL) {
                decoded = picoquic_aead_decrypt_generic(bytes + ph->offset,
                    bytes + ph->offset, ph->payload_length, ph->pn64, bytes, ph->offset, cnx->crypto_context_old.aead_decrypt);
            }
            else {
                /* old context is either not yet available, or already removed */
                decoded = ph->payload_length + 1;
            }
        }
        else {
            /* TODO: check that this is larger than last received with current key */
            /* These could only be a new key */
            if (cnx->crypto_context_new.aead_decrypt == NULL &&
                cnx->crypto_context_new.aead_encrypt == NULL) {
                /* If the new context was already computed, don't do it again */
                ret = picoquic_compute_new_rotated_keys(cnx);
            }
            /* if decoding succeeds, the rotation should be validated */
            if (ret == 0 && cnx->crypto_context_new.aead_decrypt != NULL) {
                decoded = picoquic_aead_decrypt_generic(bytes + ph->offset,
                    bytes + ph->offset, ph->payload_length, ph->pn64, bytes, ph->offset, cnx->crypto_context_new.aead_decrypt);

                if (decoded <= ph->payload_length) {
                    /* Rotation only if the packet was correctly decrypted with the new key */
                    cnx->crypto_rotation_time_guard = current_time + cnx->path[0]->retransmit_timer;
                    cnx->crypto_rotation_sequence = ph->pn64;
                    picoquic_apply_rotated_keys(cnx, 0);

                    if (cnx->crypto_context_new.aead_encrypt != NULL) {
                        /* If that move was not already validated, move to the new encryption keys */
                        picoquic_apply_rotated_keys(cnx, 1);
                    }
                }
            }
            else {
                /* new context could not be computed  */
                decoded = ph->payload_length + 1;
            }
        }
    }
    else {
        /* TODO: get rid of handshake some time after handshake complete */
        /* For all the other epochs, there is a single crypto context and no key rotation */
        if (cnx->crypto_context[ph->epoch].aead_decrypt != NULL) {
            decoded = picoquic_aead_decrypt_generic(bytes + ph->offset,
                bytes + ph->offset, ph->payload_length, ph->pn64, bytes, ph->offset, cnx->crypto_context[ph->epoch].aead_decrypt);
        }
        else {
            decoded = ph->payload_length + 1;
        }
    }
    
    /* by conventions, values larger than input indicate error */
    return decoded;
}

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
    int * new_ctx_created)
{
    /* Parse the clear text header. Ret == 0 means an incorrect packet that could not be parsed */
    int already_received = 0;
    size_t decoded_length = 0;
    int ret = picoquic_parse_packet_header(quic, bytes, length, addr_from, ph, pcnx, 1);

    *new_ctx_created = 0;

    if (ret == 0) {
        if (ph->ptype != picoquic_packet_version_negotiation && ph->ptype != picoquic_packet_retry) {
            /* TODO: clarify length, payload length, packet length -- special case of initial packet */
            length = ph->offset + ph->payload_length;
            *consumed = length;

            if (*pcnx == NULL) {
                if (ph->ptype == picoquic_packet_initial) {
                    /* Create a connection context if the CI is acceptable */
                    if (packet_length < PICOQUIC_ENFORCED_INITIAL_MTU) {
                        /* Unexpected packet. Reject, drop and log. */
                        ret = PICOQUIC_ERROR_INITIAL_TOO_SHORT;
                    }
                    else if (ph->dest_cnx_id.id_len < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH) {
                        /* Initial CID too short -- ignore the packet */
                        ret = PICOQUIC_ERROR_INITIAL_CID_TOO_SHORT;
                    }
                    else {
                        /* if listening is OK, listen */
                        *pcnx = picoquic_create_cnx(quic, ph->dest_cnx_id, ph->srce_cnx_id, addr_from, current_time, ph->vn, NULL, NULL, 0);
                        *new_ctx_created = (*pcnx == NULL) ? 0 : 1;
                    }
                }
            }

            if (ret == 0) {
                if (*pcnx != NULL) {
                    /* Remove header protection at this point */
                    ret = picoquic_remove_header_protection(*pcnx, bytes, ph);

                    if (ret == 0) {
                        decoded_length = picoquic_remove_packet_protection(*pcnx, bytes, ph, current_time, &already_received);
                    }
                    else {
                        decoded_length = ph->payload_length + 1;
                    }

                    /* TODO: consider the error "too soon" */
                    if (decoded_length > (length - ph->offset)) {
                        if (ph->ptype == picoquic_packet_1rtt_protected &&
                            length >= PICOQUIC_RESET_PACKET_MIN_SIZE &&
                            memcmp(bytes + length - PICOQUIC_RESET_SECRET_SIZE,
                            (*pcnx)->path[0]->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
                            ret = PICOQUIC_ERROR_STATELESS_RESET;
                        }
                        else {
                            ret = PICOQUIC_ERROR_AEAD_CHECK;
                            if (*new_ctx_created) {
                                picoquic_delete_cnx(*pcnx);
                                *pcnx = NULL;
                                *new_ctx_created = 0;
                            }
                        }
                    }
                    else if (already_received != 0) {
                        ret = PICOQUIC_ERROR_DUPLICATE;
                    }
                    else {
                        ph->payload_length = (uint16_t)decoded_length;
                    }
                }
                else if (ph->ptype == picoquic_packet_1rtt_protected)
                {
                    /* This may be a stateless reset */
                    *pcnx = picoquic_cnx_by_net(quic, addr_from);

                    if (*pcnx != NULL && length >= PICOQUIC_RESET_PACKET_MIN_SIZE &&
                        memcmp(bytes + length - PICOQUIC_RESET_SECRET_SIZE,
                        (*pcnx)->path[0]->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
                        ret = PICOQUIC_ERROR_STATELESS_RESET;
                    }
                    else {
                        *pcnx = NULL;
                    }
                }
            }
        }
        else {
            *consumed = length;
        }
    }
    
    return ret;
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
    /* Parse the content */
    int ret = -1;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(bytes);
    UNREFERENCED_PARAMETER(length);
    UNREFERENCED_PARAMETER(addr_from);
    UNREFERENCED_PARAMETER(current_time);
#endif

    if (picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->path[0]->local_cnxid) != 0 || ph->vn != 0) {
        /* Packet that do not match the "echo" checks should be logged and ignored */
        ret = 0;
    } else {
        /* TODO: add DOS resilience */
        /* Signal VN to the application */
        if (cnx->callback_fn && length > ph->offset) {
            (void)(cnx->callback_fn)(cnx, 0, bytes + ph->offset, length - ph->offset,
                picoquic_callback_version_negotiation, cnx->callback_ctx, NULL);
        }
        /* TODO: consider rewriting the version negotiation code */
        DBG_PRINTF("%s", "Disconnect upon receiving version negotiation.\n");
        cnx->cnx_state = picoquic_state_disconnected;
        ret = 0;
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
        uint32_t rand_vn;

        /* Packet type set to random value for version negotiation */
        picoquic_public_random(bytes + byte_index, 1);
        bytes[byte_index++] |= 0x80;
        /* Set the version number to zero */
        picoformat_32(bytes + byte_index, 0);
        byte_index += 4;
        if (ph->is_old_invariant) {
            /* Encode the ID lengths */
            bytes[byte_index++] = picoquic_create_packet_header_cnxid_lengths(ph->srce_cnx_id.id_len, ph->dest_cnx_id.id_len);
            /* Copy the incoming connection ID */
            byte_index += picoquic_format_connection_id(bytes + byte_index, PICOQUIC_MAX_PACKET_SIZE - byte_index, ph->srce_cnx_id);
            byte_index += picoquic_format_connection_id(bytes + byte_index, PICOQUIC_MAX_PACKET_SIZE - byte_index, ph->dest_cnx_id);
        }
        else {
            bytes[byte_index++] = ph->srce_cnx_id.id_len;
            byte_index += picoquic_format_connection_id(bytes + byte_index, PICOQUIC_MAX_PACKET_SIZE - byte_index, ph->srce_cnx_id);
            bytes[byte_index++] = ph->dest_cnx_id.id_len;
            byte_index += picoquic_format_connection_id(bytes + byte_index, PICOQUIC_MAX_PACKET_SIZE - byte_index, ph->dest_cnx_id);
        }
        /* Set the payload to the list of versions */
        for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
            picoformat_32(bytes + byte_index, picoquic_supported_versions[i].version);
            byte_index += 4;
        }
        /* Add random reserved value as grease, but be careful to not match proposed version */
        do {
            rand_vn = (((uint32_t)picoquic_public_random_64()) & 0x0F0F0F0F) | 0x0A0A0A0A;
        } while (rand_vn == ph->vn);
        picoformat_32(bytes + byte_index, rand_vn);
        byte_index += 4;

        /* Set length and addresses, and queue. */
        sp->length = byte_index;
        memset(&sp->addr_to, 0, sizeof(sp->addr_to));
        memcpy(&sp->addr_to, addr_from,
            (addr_from->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        memset(&sp->addr_local, 0, sizeof(sp->addr_local));
        memcpy(&sp->addr_local, addr_to,
            (addr_to->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        sp->if_index_local = if_index_to;
        sp->cnxid_log64 = picoquic_val64_connection_id(ph->dest_cnx_id);

        if (quic->F_log != NULL) {
            picoquic_log_outgoing_segment(quic->F_log, 1, NULL,
                bytes, 0, (uint32_t)sp->length,
                bytes, (uint32_t)sp->length);
        }

        picoquic_queue_stateless_packet(quic, sp);
    }

    return ret;
}

/*
 * Process an unexpected connection ID. This could be an old packet from a 
 * previous connection. If the packet type correspond to an encrypted value,
 * the server can respond with a public reset.
 *
 * Per draft 14, the stateless reset starts with the packet code 0K110000.
 * The packet has after the first byte at least 23 random bytes, and then
 * the 16 bytes reset token.
 */
void picoquic_process_unexpected_cnxid(
    picoquic_quic_t* quic,
    uint32_t length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph)
{
    if (length > PICOQUIC_RESET_PACKET_MIN_SIZE && 
        ph->ptype == picoquic_packet_1rtt_protected) {
        picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(quic);
        if (sp != NULL) {
            uint32_t pad_size = length - PICOQUIC_RESET_SECRET_SIZE -1;
            uint8_t* bytes = sp->bytes;
            size_t byte_index = 0;

            if (pad_size > PICOQUIC_RESET_PACKET_PAD_SIZE) {
                pad_size = (uint32_t)picoquic_public_uniform_random(pad_size - PICOQUIC_RESET_PACKET_PAD_SIZE)
                    + PICOQUIC_RESET_PACKET_PAD_SIZE;
            }
            else {
                pad_size = PICOQUIC_RESET_PACKET_PAD_SIZE;
            }

            /* Packet type set to short header, randomize the 5 lower bits */
            bytes[byte_index++] = 0x30 | (uint8_t)(picoquic_public_random_64() & 0x1F);

            /* Add the random bytes */
            picoquic_public_random(bytes + byte_index, pad_size);
            byte_index += pad_size;
            /* Add the public reset secret */
            (void)picoquic_create_cnxid_reset_secret(quic, ph->dest_cnx_id, bytes + byte_index);
            byte_index += PICOQUIC_RESET_SECRET_SIZE;
            sp->length = byte_index;
            memset(&sp->addr_to, 0, sizeof(sp->addr_to));
            memcpy(&sp->addr_to, addr_from,
                (addr_from->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            memset(&sp->addr_local, 0, sizeof(sp->addr_local));
            memcpy(&sp->addr_local, addr_to,
                (addr_to->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
            sp->if_index_local = if_index_to;
            sp->cnxid_log64 = picoquic_val64_connection_id(ph->dest_cnx_id);

            if (quic->F_log != NULL) {
                picoquic_log_prefix_initial_cid64(quic->F_log, sp->cnxid_log64);
                fprintf(quic->F_log, "Unexpected connection ID, sending stateless reset.\n");
            }


            picoquic_queue_stateless_packet(quic, sp);
        }
    }
}

/*
 * Queue a stateless retry packet
 */

void picoquic_queue_stateless_retry(picoquic_cnx_t* cnx,
    picoquic_packet_header* ph, struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    uint8_t * token,
    size_t token_length)
{
    picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(cnx->quic);
    size_t checksum_length = picoquic_get_checksum_length(cnx, 1);

    if (sp != NULL) {
        uint8_t* bytes = sp->bytes;
        uint32_t byte_index = 0;
        size_t data_bytes = 0;
        uint32_t header_length = 0;
        uint32_t pn_offset;
        uint32_t pn_length;

        cnx->path[0]->remote_cnxid = ph->srce_cnx_id;

        byte_index = header_length = picoquic_create_packet_header(cnx, picoquic_packet_retry,
            0, &cnx->path[0]->remote_cnxid, &cnx->path[0]->local_cnxid,
            bytes, &pn_offset, &pn_length);

        /* Encode ODCIL in bottom 4 bits of first byte */
        bytes[0] |= picoquic_create_packet_header_cnxid_lengths(0, cnx->initial_cnxid.id_len);

        /* Encode DCIL */
        byte_index += picoquic_format_connection_id(bytes + byte_index,
            PICOQUIC_MAX_PACKET_SIZE - byte_index - checksum_length, cnx->initial_cnxid);
        byte_index += (uint32_t)data_bytes;
        memcpy(&bytes[byte_index], token, token_length);
        byte_index += (uint32_t)token_length;

        sp->length = byte_index;


        memset(&sp->addr_to, 0, sizeof(sp->addr_to));
        memcpy(&sp->addr_to, addr_from,
            (addr_from->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        memset(&sp->addr_local, 0, sizeof(sp->addr_local));
        memcpy(&sp->addr_local, addr_to,
            (addr_to->sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        sp->if_index_local = if_index_to;
        sp->cnxid_log64 = picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx));

        if (cnx->quic->F_log != NULL) {
            picoquic_log_outgoing_segment(cnx->quic->F_log, 1, cnx,
                bytes, 0, (uint32_t)sp->length,
                bytes, (uint32_t)sp->length);
        }

        picoquic_queue_stateless_packet(cnx->quic, sp);
    }
}

/*
 * Processing of initial or handshake messages when they are not expected
 * any more. These messages could be used in a DOS attack against the
 * connection, but they could also be legit messages sent by a peer
 * that does not implement implicit ACK. They are processed to not
 * cause any side effect, but to still generate ACK if the client
 * needs them.
 */

void picoquic_ignore_incoming_handshake(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    picoquic_packet_header* ph)
{
    /* The data starts at ph->index, and its length
     * is ph->payload_length. */
    int ret = 0;
    uint32_t byte_index = 0;
    int ack_needed = 0;
    picoquic_packet_context_enum pc;
    
    if (ph->ptype == picoquic_packet_initial) {
        pc = picoquic_packet_context_initial;
    }
    else if (ph->ptype == picoquic_packet_handshake) {
        pc = picoquic_packet_context_handshake;
    }
    else {
        /* Not expected! */
        return;
    }

    bytes += ph->offset;

    while (ret == 0 && byte_index < ph->payload_length) {
        size_t frame_length = 0;
        int frame_is_pure_ack = 0;
        ret = picoquic_skip_frame(cnx, &bytes[byte_index],
            ph->payload_length - byte_index, &frame_length, &frame_is_pure_ack);
        byte_index += (uint32_t)frame_length;
        if (frame_is_pure_ack == 0) {
            ack_needed = 1;
        }
    }

    /* If the packet contains ackable data, mark ack needed
     * in the relevant packet context */
    if (ret == 0 && ack_needed) {
        cnx->pkt_ctx[pc].ack_needed = 1;
    }
}

/*
 * Processing of an incoming client initial packet,
 * on an unknown connection context.
 */

int picoquic_incoming_initial(
    picoquic_cnx_t** pcnx,
    uint8_t* bytes,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph,
    uint64_t current_time,
    int new_context_created)
{
    int ret = 0;

    if ((*pcnx)->cnx_state == picoquic_state_ready ) {
        if (picoquic_supported_versions[(*pcnx)->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
            /* Ignoring handshake frames in ready state, but sending ACK
             * if the client mistakenly repeats them */
            picoquic_ignore_incoming_handshake(*pcnx, bytes, ph);
        }
        return ret;
    }

    /* Logic to test the retry token.
     * TODO: this should probably be implemented as a callback */
    if (((*pcnx)->quic->flags&picoquic_context_check_token) &&
        (*pcnx)->cnx_state == picoquic_state_server_init &&
        ((*pcnx)->quic->flags&picoquic_context_server_busy) == 0) {
        if (picoquic_verify_retry_token((*pcnx)->quic, addr_from, current_time,
            &(*pcnx)->original_cnxid, ph->token_bytes, ph->token_length) != 0) {
            uint8_t token_buffer[256];
            uint32_t token_size;

            if (picoquic_prepare_retry_token((*pcnx)->quic, addr_from, 
                current_time + PICOQUIC_TOKEN_DELAY_SHORT, &ph->dest_cnx_id,
                token_buffer, (uint32_t)sizeof(token_buffer), &token_size) != 0){ 
                ret = PICOQUIC_ERROR_MEMORY;
            }
            else {
                picoquic_queue_stateless_retry(*pcnx, ph,
                    addr_from, addr_to, if_index_to, token_buffer, token_size);
                ret = PICOQUIC_ERROR_RETRY;
            }
        }
    }

    if ((*pcnx)->quic->flags&picoquic_context_server_busy) {
        (*pcnx)->local_error = PICOQUIC_TRANSPORT_SERVER_BUSY;
        (*pcnx)->cnx_state = picoquic_state_handshake_failure;
    }
    else if ((*pcnx)->initial_cnxid.id_len < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH) {
        (*pcnx)->local_error = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
        (*pcnx)->cnx_state = picoquic_state_handshake_failure;
    } else {
        /* Document the incoming addresses */
        if ((*pcnx)->path[0]->local_addr_len == 0 && addr_to != NULL) {
            (*pcnx)->path[0]->local_addr_len = picoquic_store_addr(&(*pcnx)->path[0]->local_addr, addr_to);
        }
        if ((*pcnx)->path[0]->peer_addr_len == 0 && addr_from != NULL) {
            (*pcnx)->path[0]->peer_addr_len = picoquic_store_addr(&(*pcnx)->path[0]->peer_addr, addr_from);
        }
        /* decode the incoming frames */
        if (ret == 0) {
            ret = picoquic_decode_frames(*pcnx, (*pcnx)->path[0],
                bytes + ph->offset, ph->payload_length, ph->epoch, addr_from, addr_to, current_time);
        }

        /* processing of client initial packet */
        if (ret == 0) {
            /* initialization of context & creation of data */
            /* TODO: find path to send data produced by TLS. */
            ret = picoquic_tls_stream_process(*pcnx);
        }
    }

    if (ret != 0 || (*pcnx)->cnx_state == picoquic_state_disconnected) {
        /* This is bad. If this is an initial attempt, delete the connection */
        if (new_context_created) {
            picoquic_delete_cnx(*pcnx);
            *pcnx = NULL;
            ret = PICOQUIC_ERROR_CONNECTION_DELETED;
        }
    }

    return ret;
}

/*
 * Processing of a server retry
 *
 * The packet number and connection ID fields echo the corresponding fields from the 
 * triggering client packet. This allows a client to verify that the server received its packet.
 *
 * A Server Stateless Retry packet is never explicitly acknowledged in an ACK frame by a client.
 * Receiving another Client Initial packet implicitly acknowledges a Server Stateless Retry packet.
 *
 * After receiving a Server Stateless Retry packet, the client uses a new Client Initial packet 
 * containing the next token. In effect, the next cryptographic
 * handshake message is sent on a new connection. 
 */

int picoquic_incoming_retry(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;
    size_t token_length = 0;
    uint8_t * token = NULL;

    if ((cnx->cnx_state != picoquic_state_client_init_sent && cnx->cnx_state != picoquic_state_client_init_resent) ||
        cnx->original_cnxid.id_len != 0) {
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    } else {
        /* Verify that the header is a proper echo of what was sent */
        if (ph->vn != picoquic_supported_versions[cnx->version_index].version) {
            /* Packet that do not match the "echo" checks should be logged and ignored */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        } else if (ph->pn64 != 0) {
            /* after draft-12, PN is required to be 0 */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        }
    }

    if (ret == 0) {
        /* Parse the retry frame */
        size_t byte_index = ph->offset;
        uint8_t odcil;
        uint8_t unused_cil;

        picoquic_parse_packet_header_cnxid_lengths(bytes[0], &unused_cil, &odcil);


        if (odcil != cnx->initial_cnxid.id_len || odcil + 1 > ph->payload_length ||
            memcmp(cnx->initial_cnxid.id, &bytes[byte_index], odcil) != 0) {
            /* malformed ODCIL, or does not match initial cid; ignore */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        } else {
            byte_index += odcil;
            token_length = ph->offset + ph->payload_length - byte_index;

            if (token_length > 0) {
                token = malloc(token_length);
                if (token == NULL) {
                    ret = PICOQUIC_ERROR_MEMORY;
                } else {
                    memcpy(token, &bytes[byte_index], token_length);
                }
            }
        }
    }

    if (ret == 0) {
        /* if this is the first reset, reset the original cid */
        if (cnx->original_cnxid.id_len == 0) {
            cnx->original_cnxid = cnx->initial_cnxid;
        }
        /* reset the initial CNX_ID to the version sent by the server */
        cnx->initial_cnxid = ph->srce_cnx_id;

        /* keep a copy of the retry token */
        if (cnx->retry_token != NULL) {
            free(cnx->retry_token);
        }
        cnx->retry_token = token;
        cnx->retry_token_length = (uint16_t)token_length;

        picoquic_reset_cnx(cnx, current_time);

        /* Mark the packet as not required for ack */
        ret = PICOQUIC_ERROR_RETRY;
    }

    return ret;
}

/*
 * Processing of a server clear text packet.
 */

int picoquic_incoming_server_cleartext(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(addr_to);
    UNREFERENCED_PARAMETER(if_index_to);
#endif

    if (cnx->cnx_state == picoquic_state_client_init_sent || cnx->cnx_state == picoquic_state_client_init_resent) {
        cnx->cnx_state = picoquic_state_client_handshake_start;
    }

    int restricted = cnx->cnx_state != picoquic_state_client_handshake_start && cnx->cnx_state != picoquic_state_client_handshake_progress;

    /* Check the server cnx id */
    if (picoquic_is_connection_id_null(cnx->path[0]->remote_cnxid) && restricted == 0) {
        /* On first response from the server, copy the cnx ID and the incoming address */
        cnx->path[0]->remote_cnxid = ph->srce_cnx_id;
        cnx->path[0]->local_addr_len = picoquic_store_addr(&cnx->path[0]->local_addr, addr_to);
    }
    else if (picoquic_compare_connection_id(&cnx->path[0]->remote_cnxid, &ph->srce_cnx_id) != 0) {
        ret = PICOQUIC_ERROR_CNXID_CHECK; /* protocol error */
    }


    if (ret == 0) {
        if (cnx->cnx_state == picoquic_state_ready ||
            (ph->ptype == picoquic_packet_initial && 
                (cnx->cnx_state == picoquic_state_client_handshake_start ||
                    cnx->cnx_state == picoquic_state_client_handshake_progress ||
                    cnx->cnx_state == picoquic_state_client_almost_ready ||
                    cnx->cnx_state == picoquic_state_client_ready_start)
                    && 
                cnx->crypto_context[2].aead_decrypt != NULL &&
                cnx->crypto_context[2].aead_encrypt != NULL &&
                cnx->pkt_ctx[picoquic_packet_context_handshake].first_sack_item.end_of_sack_range
                != (uint64_t)((int64_t)-1))) {
            if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
                /* Ignoring handshake frames in ready state, but sending ACK
                 * if the client mistakenly repeats them */
                picoquic_ignore_incoming_handshake(cnx, bytes, ph);
            }
        }
        else {
            /* Accept the incoming frames */

            if (ph->payload_length == 0) {
                /* empty payload! */
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
            }
            else {
                ret = picoquic_decode_frames(cnx, cnx->path[0],
                    bytes + ph->offset, ph->payload_length, ph->epoch, NULL, addr_to, current_time);
            }

            /* processing of initial packet */
            if (ret == 0 && restricted == 0) {
                ret = picoquic_tls_stream_process(cnx);

                /* If the handshake keys have been received there is no need to
                 * repeat the initial packet any more */

                if (ret == 0 && cnx->crypto_context[2].aead_decrypt != NULL &&
                    cnx->crypto_context[2].aead_encrypt != NULL)
                {
                    picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_initial, current_time);
                }
            }

            if (ret != 0) {
                /* This is bad. should just delete the context, log the packet, etc */
            }
        }
    }


    return ret;
}

/*
 * Processing of client handshake packet.
 */
int picoquic_incoming_client_handshake(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;

    if (cnx->cnx_state == picoquic_state_server_init
        || cnx->cnx_state == picoquic_state_server_handshake
        || cnx->cnx_state == picoquic_state_server_almost_ready
        || cnx->cnx_state == picoquic_state_server_false_start
        || cnx->cnx_state == picoquic_state_ready) {
        if (picoquic_compare_connection_id(&ph->srce_cnx_id, &cnx->path[0]->remote_cnxid) != 0) {
            ret = PICOQUIC_ERROR_CNXID_CHECK;
        } else if (cnx->cnx_state == picoquic_state_ready) {
            if (picoquic_supported_versions[cnx->version_index].version == PICOQUIC_TWELFTH_INTEROP_VERSION) {
                /* Ignoring handshake frames in ready state, but sending ACK
                 * if the client mistakenly repeats them */
                picoquic_ignore_incoming_handshake(cnx, bytes, ph);
            }
        } else {
            /* Accept the incoming frames */
            if (ph->payload_length == 0) {
                /* empty payload! */
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
            }
            else {
                ret = picoquic_decode_frames(cnx, cnx->path[0],
                    bytes + ph->offset, ph->payload_length, ph->epoch, NULL, NULL, current_time);
            }
            /* processing of client clear text packet */
            if (ret == 0) {
                /* initialization of context & creation of data */
                /* TODO: find path to send data produced by TLS. */
                ret = picoquic_tls_stream_process(cnx);
            }

            if (ret != 0) {
                /* This is bad. should just delete the context, log the packet, etc */
            }
        }
    }
    else {
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
        (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_stateless_reset, cnx->callback_ctx, NULL);
    }

    return PICOQUIC_ERROR_AEAD_CHECK;
}

/*
 * Processing of 0-RTT packet
 */

int picoquic_incoming_0rtt(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;

    if (!(picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->initial_cnxid) == 0 ||
        picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->path[0]->local_cnxid) == 0) ||
        picoquic_compare_connection_id(&ph->srce_cnx_id, &cnx->path[0]->remote_cnxid) != 0) {
        ret = PICOQUIC_ERROR_CNXID_CHECK;
    } else if (cnx->cnx_state == picoquic_state_server_almost_ready || 
        cnx->cnx_state == picoquic_state_server_false_start ||
        (cnx->cnx_state == picoquic_state_ready && !cnx->is_1rtt_received)) {
        if (ph->vn != picoquic_supported_versions[cnx->version_index].version) {
            ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
        } else {
            /* Accept the incoming frames */
            if (ph->payload_length == 0) {
                /* empty payload! */
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
            }
            else {
                ret = picoquic_decode_frames(cnx, cnx->path[0],
                    bytes + ph->offset, ph->payload_length, ph->epoch, NULL, NULL, current_time);
            }

            if (ret == 0) {
                /* Processing of TLS messages -- EOED */
                ret = picoquic_tls_stream_process(cnx);
            }
        }
    } else {
        /* Not expected. Log and ignore. */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}

/*
 * Find path of incoming encrypted packet. (This code is not used during the
 * handshake, or if the connection is closing.)
 *
 * Check whether this matches a path defined by Local & Remote Addr, Local CNXID:
 *  - if local CID length > 0 and does not match: no match;
 *  - if local addr defined and does not match: no match;
 *  - if peer addr defined and does not match: no match.
 *
 * If no path matches: new path. Check whether the addresses match a pending probe.
 * If they do, merge probe, retain probe's CID as dest CID. If they don't, get CID
 * from stash or use null CID if peer uses null CID; initiated required probing. If
 * no CID available, accept packet but no not create a path.
 *
 * If CNXID matches but address don't, use NAT rebinding logic. Keep track of
 * the new addresses without deleting the old ones, and launch challenges on both old
 * and new addresses. If the challenge on the new address succeeds, it is promoted.
 * But if traffic comes from the old address after that, there will be new
 * challenges, and it too will be promoted in turn.
 *
 * If path matched: existing path. If peer address changed: NAT rebinding. If
 * source address changed: if undef, update; else NAT rebinding. If NAT rebinding:
 * change the probe secret; mark probe as required.
 */

int picoquic_find_incoming_path(picoquic_cnx_t* cnx, picoquic_packet_header * ph,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    uint64_t current_time,
    int * p_path_id)
{
    int ret = 0;
    int path_id = -1;
    int new_challenge_required = 0;

    if (cnx->path[0]->local_cnxid.id_len > 0) {
        /* Paths must have been created in advance, when the local connection ID was
         * created and announced to the peer.
         */
        for (int i = 0; i < cnx->nb_paths; i++) {
            if (picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->path[i]->local_cnxid) == 0) {
                path_id = i;
                break;
            }
        }

        if (path_id < 0) {
            ret = PICOQUIC_ERROR_CNXID_CHECK;
        }
    }
    else if (ph->dest_cnx_id.id_len != 0) {
        ret = PICOQUIC_ERROR_CNXID_CHECK;
    }
    else {
        /* Paths to the peer are strictly defined by the address pairs, and are not
         * created in advance, because the address pair is unpredictable */
        for (int i = 0; i < cnx->nb_paths; i++) {
            if (picoquic_compare_addr((struct sockaddr *)&cnx->path[i]->peer_addr,
                addr_from) == 0 &&
                (cnx->path[i]->local_addr_len == 0 ||
                    picoquic_compare_addr((struct sockaddr *)&cnx->path[i]->local_addr,
                        addr_to) == 0)) {
                path_id = i;
                break;
            }
        }

        if (path_id < 0) {
            ret = picoquic_create_path(cnx, current_time, addr_to, addr_from);
            if (ret == 0) {
                path_id = cnx->nb_paths - 1;
                cnx->path[path_id]->path_is_published = 1; /* No need to send NEW CNXID frame */
                picoquic_register_path(cnx, cnx->path[path_id]);
                new_challenge_required = 1;
            }
        }
    }

    if (ret == 0 && cnx->path[path_id]->local_addr_len == 0) {
        cnx->path[path_id]->local_addr_len = picoquic_store_addr(&cnx->path[path_id]->local_addr, addr_to);
    }


    if (ret == 0) {
        if (picoquic_compare_addr((struct sockaddr *)&cnx->path[path_id]->peer_addr, addr_from) == 0) {
            if (picoquic_compare_addr((struct sockaddr *)&cnx->path[path_id]->local_addr, addr_to) != 0) {
                picoquic_store_addr(&cnx->path[path_id]->local_addr, addr_to);
            }
            /* All is good. Consider the path activated */
            cnx->path[path_id]->path_is_activated = 1;
        }
        else {
            /* If this is a newly activated path, try document the remote connection ID
             * and request a probe if this is possible. Else, treat this as a NAT rebinding
             * and request a probe */
            if (!picoquic_is_connection_id_null(cnx->path[0]->remote_cnxid) &&
                picoquic_is_connection_id_null(cnx->path[path_id]->remote_cnxid)) {
                /* if there is a probe in progress, find it. */
                picoquic_probe_t * probe = picoquic_find_probe_by_addr(cnx, addr_from, addr_to);
                if (probe != NULL) {
                    cnx->path[path_id]->path_is_activated = 1;
                    cnx->path[path_id]->remote_cnxid = probe->remote_cnxid;
                    cnx->path[path_id]->remote_cnxid_sequence = probe->sequence;
                    for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
                        cnx->path[path_id]->challenge[ichal] = probe->challenge[ichal];
                    }
                    cnx->path[path_id]->challenge_time = probe->challenge_time;
                    cnx->path[path_id]->challenge_repeat_count = probe->challenge_repeat_count;
                    cnx->path[path_id]->challenge_required = probe->challenge_required;
                    cnx->path[path_id]->challenge_verified = probe->challenge_verified;
                    cnx->path[path_id]->challenge_failed = probe->challenge_failed;

                    picoquic_delete_probe(cnx, probe);
                    /* No challenge required, since we already sent one for the probe. */
                    cnx->path[path_id]->peer_addr_len = picoquic_store_addr(&cnx->path[path_id]->peer_addr, addr_from);
                    cnx->path[path_id]->local_addr_len = picoquic_store_addr(&cnx->path[path_id]->local_addr, addr_to);
                }
                else if (picoquic_compare_addr((struct sockaddr *)&cnx->path[0]->peer_addr,
                    (struct sockaddr *)addr_from) == 0 &&
                    picoquic_compare_addr((struct sockaddr *)&cnx->path[0]->local_addr,
                        addr_to) == 0) {
                    /* Only the connection ID changed from path 0. Use the path[0] remote ID, validate this path, invalidate path[0]. */
                    cnx->path[path_id]->remote_cnxid = cnx->path[0]->remote_cnxid;
                    cnx->path[path_id]->remote_cnxid_sequence = cnx->path[0]->remote_cnxid_sequence;
                    memcpy(cnx->path[path_id]->reset_secret, cnx->path[0]->reset_secret,
                        PICOQUIC_RESET_SECRET_SIZE);
                    cnx->path[path_id]->path_is_activated = 1;
                    cnx->path[path_id]->challenge_required = cnx->path[0]->challenge_required;
                    for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
                        cnx->path[path_id]->challenge[ichal] = cnx->path[0]->challenge[ichal];
                    }
                    cnx->path[path_id]->challenge_time = cnx->path[0]->challenge_time;
                    cnx->path[path_id]->challenge_repeat_count = cnx->path[0]->challenge_repeat_count;
                    cnx->path[path_id]->challenge_required = cnx->path[0]->challenge_required;
                    cnx->path[path_id]->challenge_verified = cnx->path[0]->challenge_verified;
                    cnx->path[path_id]->challenge_failed = cnx->path[0]->challenge_failed;
                    cnx->path[path_id]->peer_addr_len = picoquic_store_addr(&cnx->path[path_id]->peer_addr, addr_from);
                    cnx->path[path_id]->local_addr_len = picoquic_store_addr(&cnx->path[path_id]->local_addr, addr_to);
                    cnx->path[0]->remote_cnxid = picoquic_null_connection_id;
                    picoquic_promote_path_to_default(cnx, path_id, current_time);
                    path_id = 0;
                    /* No new challenge required there */
                    new_challenge_required = 0;
                }
                else if (cnx->path[path_id]->path_is_activated == 0) {
                    /* The peer is probing for a new path */
                    /* If there is no matching probe, try find a stashed ID */
                    picoquic_cnxid_stash_t * available_cnxid = picoquic_dequeue_cnxid_stash(cnx);
                    if (available_cnxid != NULL) {
                        cnx->path[path_id]->remote_cnxid = available_cnxid->cnx_id;
                        cnx->path[path_id]->remote_cnxid_sequence = available_cnxid->sequence;
                        memcpy(cnx->path[path_id]->reset_secret, available_cnxid->reset_secret,
                            PICOQUIC_RESET_SECRET_SIZE);
                        cnx->path[path_id]->path_is_activated = 1;
                        free(available_cnxid);
                        /* New challenge required there */
                        new_challenge_required = 1;
                        cnx->path[path_id]->peer_addr_len = picoquic_store_addr(&cnx->path[path_id]->peer_addr, addr_from);
                        cnx->path[path_id]->local_addr_len = picoquic_store_addr(&cnx->path[path_id]->local_addr, addr_to);
                    }
                    else {
                        /* Do not activate the path if no connection ID is available */
                        cnx->path[path_id]->path_is_activated = 0;
                        cnx->path[path_id]->challenge_required = 0;
                        new_challenge_required = 0;
                    }
                }
            }
            else {
                /* Since the CNXID is documented but the addresses do not match, consider this as
                 * a NAT rebinding attempt. We will only keep one such attempt validated at a time. */
                if ((picoquic_compare_addr((struct sockaddr *)&cnx->path[path_id]->alt_peer_addr,
                    (struct sockaddr *)addr_from) == 0 &&
                    picoquic_compare_addr((struct sockaddr *)&cnx->path[path_id]->alt_local_addr,
                        addr_to) == 0)) {
                    /* New packet received for the same alt address */
                    if (current_time > cnx->path[path_id]->alt_challenge_timeout) {
                        cnx->path[path_id]->alt_challenge_timeout = 0;
                        cnx->path[path_id]->alt_challenge_required = 1;
                        cnx->path[path_id]->alt_challenge_repeat_count = 0;
                        cnx->alt_path_challenge_needed = 1;
                    }
                }
                else if (((cnx->path[path_id]->alt_peer_addr_len == 0 &&
                    cnx->path[path_id]->alt_local_addr_len == 0) ||
                    cnx->path[path_id]->alt_challenge_timeout > current_time) &&
                    ph->pn64 >= cnx->pkt_ctx[picoquic_packet_context_application].first_sack_item.end_of_sack_range) {
                    /* The addresses are different, and this is a most recent
                     * packet. This probably indicates a NAT rebinding, but it could also be
                     * some kind of attack. */
                    cnx->path[path_id]->alt_peer_addr_len = picoquic_store_addr(&cnx->path[path_id]->alt_peer_addr, addr_from);
                    cnx->path[path_id]->alt_local_addr_len = picoquic_store_addr(&cnx->path[path_id]->alt_local_addr, addr_to);
                    for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
                        cnx->path[path_id]->alt_challenge[ichal] = picoquic_public_random_64();
                    }
                    cnx->path[path_id]->alt_challenge_required = 1;
                    cnx->path[path_id]->alt_challenge_timeout = 0;
                    cnx->path[path_id]->alt_challenge_repeat_count = 0;
                    cnx->alt_path_challenge_needed = 1;
                    /* Require a new challenge on the normal path */
                    new_challenge_required = 1;
                }
                else {
                    /* Can't use the new addresses. Treat packet as if it was just received
                     * on the matching path, ignore the addresses for most purposes,
                     * do not require a new challenge */
                }
            }
        }
    }


    if (ret == 0 && new_challenge_required) {
        /* Reset the path challenge */
        cnx->path[path_id]->challenge_required = 1;
        for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
            cnx->path[path_id]->challenge[ichal] = picoquic_public_random_64();
        }
        cnx->path[path_id]->challenge_verified = 0;
        cnx->path[path_id]->challenge_time = current_time;
        cnx->path[path_id]->challenge_repeat_count = 0;
    }

    *p_path_id = path_id;

    return ret;
}

/*
 * ECN Accounting. This is only called if the packet was processed successfully.
 */
void picoquic_ecn_accounting(picoquic_cnx_t* cnx,
    unsigned char received_ecn, int path_id)
{
    if (path_id == 0) {
        switch (received_ecn & 0x03) {
        case 0x00:
            break;
        case 0x01: /* ECN_ECT_1 */
            cnx->ecn_ect1_total_local++;
            cnx->sending_ecn_ack |= 1;
            break;
        case 0x02: /* ECN_ECT_0 */
            cnx->ecn_ect0_total_local++;
            cnx->sending_ecn_ack |= 1;
            break;
        case 0x03: /* ECN_CE */
            cnx->ecn_ce_total_local++;
            cnx->sending_ecn_ack |= 1;
            break;
        }
    }
}

/*
 * Processing of client encrypted packet.
 */
int picoquic_incoming_encrypted(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    picoquic_packet_header* ph,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned char received_ecn,
    uint64_t current_time)
{
    int ret = 0;
    int path_id = -1;

    /* Check the packet */
    if (cnx->cnx_state < picoquic_state_client_almost_ready) {
        /* handshake is not complete. Just ignore the packet */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }
    else if (cnx->cnx_state == picoquic_state_disconnected) {
        /* Connection is disconnected. Just ignore the packet */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }
    else {
        /* Packet is correct */

        /* TODO: consider treatment of migration during closing mode */

        /* Do not process data in closing or draining modes */
        if (cnx->cnx_state >= picoquic_state_closing_received) {
            /* only look for closing frames in closing modes */
            if (cnx->cnx_state == picoquic_state_closing) {
                int closing_received = 0;

                ret = picoquic_decode_closing_frames(
                    cnx, bytes + ph->offset, ph->payload_length, &closing_received);

                if (ret == 0) {
                    if (closing_received) {
                        if (cnx->client_mode) {
                            cnx->cnx_state = picoquic_state_disconnected;
                        }
                        else {
                            cnx->cnx_state = picoquic_state_draining;
                        }
                    }
                    else {
                        cnx->pkt_ctx[ph->pc].ack_needed = 1;
                    }
                }
            }
            else {
                /* Just ignore the packets in closing received or draining mode */
                ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
            }
        }
        else {
            if (ph->payload_length == 0) {
                /* empty payload! */
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
            }
            else if (ph->has_reserved_bit_set) {
                /* Reserved bits were not set to zero */
                ret = picoquic_connection_error(cnx, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION, 0);
            }
            else {
                /* Find the arrival path and update its state */
                ret = picoquic_find_incoming_path(cnx, ph, addr_from, addr_to, current_time, &path_id);
            }

            if (ret == 0) {
                picoquic_path_t * path_x = cnx->path[path_id];

                cnx->is_1rtt_received = 1;
                picoquic_spin_function_table[cnx->spin_policy].spinbit_incoming(cnx, path_x, ph);
                /* Accept the incoming frames */
                ret = picoquic_decode_frames(cnx, cnx->path[path_id], 
                    bytes + ph->offset, ph->payload_length, ph->epoch, addr_from, addr_to, current_time);
            }

            if (ret == 0) {
                /* Perform ECN accounting */
                picoquic_ecn_accounting(cnx, received_ecn, path_id);
                /* Processing of TLS messages  */
                ret = picoquic_tls_stream_process(cnx);
            }

            if (ret == 0 && cnx->cc_log != NULL) {
                picoquic_cc_dump(cnx, current_time);
            }
        }
    }

    return ret;
}

/*
* Processing of the packet that was just received from the network.
*/

int picoquic_incoming_segment(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t length,
    uint32_t packet_length,
    uint32_t * consumed,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time,
    picoquic_connection_id_t * previous_dest_id)
{
    int ret = 0;
    picoquic_cnx_t* cnx = NULL;
    picoquic_packet_header ph;
    int new_context_created = 0;

    /* Parse the header and decrypt the segment */
    ret = picoquic_parse_header_and_decrypt(quic, bytes, length, packet_length, addr_from,
        current_time, &ph, &cnx, consumed, &new_context_created);

    /* Verify that the segment coalescing is for the same destination ID */
    if (ret == 0) {
        if (picoquic_is_connection_id_null(*previous_dest_id)) {
            /* This is the first segment in the incoming packet */
            *previous_dest_id = ph.dest_cnx_id;

            /* if needed, log that the packet is received */
            if (quic->F_log != NULL && (cnx == NULL || cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || quic->use_long_log)) {
                picoquic_log_packet_address(quic->F_log,
                    picoquic_val64_connection_id((cnx == NULL) ? ph.dest_cnx_id : picoquic_get_logging_cnxid(cnx)),
                    cnx, addr_from, 1, packet_length, current_time);
            }
        }
        else if (picoquic_compare_connection_id(previous_dest_id, &ph.dest_cnx_id) != 0) {
            ret = PICOQUIC_ERROR_CNXID_SEGMENT;
        }
    }

    /* Log the incoming segment */
    if (quic->F_log != NULL && (cnx == NULL || cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || quic->use_long_log)) {
        picoquic_log_decrypted_segment(quic->F_log, 1, cnx, 1, &ph, bytes, (uint32_t)*consumed, ret);
    }

    if (ret == 0) {
        if (cnx == NULL) {
            if (ph.version_index < 0 && ph.vn != 0) {
                if (packet_length >= PICOQUIC_ENFORCED_INITIAL_MTU) {
                    /* use the result of parsing to consider version negotiation */
                    picoquic_prepare_version_negotiation(quic, addr_from, addr_to, if_index_to, &ph);
                }
            }
            else {
                /* Unexpected packet. Reject, drop and log. */
                if (!picoquic_is_connection_id_null(ph.dest_cnx_id)) {
                    picoquic_process_unexpected_cnxid(quic, length, addr_from, addr_to, if_index_to, &ph);
                }
                ret = PICOQUIC_ERROR_DETECTED;
            }
        }
        else {
            switch (ph.ptype) {
            case picoquic_packet_version_negotiation:
                if (cnx->cnx_state == picoquic_state_client_init_sent) {
                    /* Proceed with version negotiation*/
                    ret = picoquic_incoming_version_negotiation(
                        cnx, bytes, length, addr_from, &ph, current_time);
                }
                else {
                    /* This is an unexpected packet. Log and drop.*/
                    DBG_PRINTF("Unexpected packet (%d), type: %d, epoch: %d, pc: %d, pn: %d\n",
                        cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int) ph.pn);
                    ret = PICOQUIC_ERROR_DETECTED;
                }
                break;
            case picoquic_packet_initial:
                /* Initial packet: either crypto handshakes or acks. */
                if ((!cnx->client_mode && picoquic_compare_connection_id(&ph.dest_cnx_id, &cnx->initial_cnxid) == 0) ||
                    picoquic_compare_connection_id(&ph.dest_cnx_id, &cnx->path[0]->local_cnxid) == 0) {
                    /* Verify that the source CID matches expectation */
                    if (picoquic_is_connection_id_null(cnx->path[0]->remote_cnxid)) {
                        cnx->path[0]->remote_cnxid = ph.srce_cnx_id;
                    } else if (picoquic_compare_connection_id(&cnx->path[0]->remote_cnxid, &ph.srce_cnx_id) != 0) {
                        DBG_PRINTF("Error wrong srce cnxid (%d), type: %d, epoch: %d, pc: %d, pn: %d\n",
                            cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn);
                        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
                    }
                    if (ret == 0) {
                        if (cnx->client_mode == 0) {
                            /* TODO: finish processing initial connection packet */
                            ret = picoquic_incoming_initial(&cnx, bytes,
                                addr_from, addr_to, if_index_to, &ph, current_time, new_context_created);
                        }
                        else {
                            /* TODO: this really depends on the current receive epoch */
                            ret = picoquic_incoming_server_cleartext(cnx, bytes, addr_to, if_index_to, &ph, current_time);
                        }
                    }
                } else {
                    DBG_PRINTF("Error detected (%d), type: %d, epoch: %d, pc: %d, pn: %d\n",
                        cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn);
                    ret = PICOQUIC_ERROR_DETECTED;
                }
                break;
            case picoquic_packet_retry:
                /* TODO: server retry is completely revised in the new version. */
                ret = picoquic_incoming_retry(cnx, bytes, &ph, current_time);
                break;
            case picoquic_packet_handshake:
                if (cnx->client_mode)
                {
                    ret = picoquic_incoming_server_cleartext(cnx, bytes, addr_to, if_index_to, &ph, current_time);
                }
                else
                {
                    ret = picoquic_incoming_client_handshake(cnx, bytes, &ph, current_time);
                }
                break;
            case picoquic_packet_0rtt_protected:
                ret = picoquic_incoming_0rtt(cnx, bytes, &ph, current_time);
                break;
            case picoquic_packet_1rtt_protected:
                ret = picoquic_incoming_encrypted(cnx, bytes, &ph, addr_from, addr_to, received_ecn, current_time);
                break;
            default:
                /* Packet type error. Log and ignore */
                DBG_PRINTF("Unexpected packet type (%d), type: %d, epoch: %d, pc: %d, pn: %d\n",
                    cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int) ph.pn);
                ret = PICOQUIC_ERROR_DETECTED;
                break;
            }
        }
    } else if (ret == PICOQUIC_ERROR_STATELESS_RESET) {
        ret = picoquic_incoming_stateless_reset(cnx);
    }

    if (ret == 0 || ret == PICOQUIC_ERROR_SPURIOUS_REPEAT) {
        if (cnx != NULL && cnx->cnx_state != picoquic_state_disconnected &&
            ph.ptype != picoquic_packet_version_negotiation) {
            /* Mark the sequence number as received */
            ret = picoquic_record_pn_received(cnx, ph.pc, ph.pn64, current_time);
        }
        if (cnx != NULL) {
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time);
        }
    } else if (ret == PICOQUIC_ERROR_DUPLICATE) {
        /* Bad packets are dropped silently, but duplicates should be acknowledged */
        if (cnx != NULL) {
            cnx->pkt_ctx[ph.pc].ack_needed = 1;
        }
        ret = -1;
    } else if (ret == PICOQUIC_ERROR_AEAD_CHECK || ret == PICOQUIC_ERROR_INITIAL_TOO_SHORT ||
        ret == PICOQUIC_ERROR_INITIAL_CID_TOO_SHORT ||
        ret == PICOQUIC_ERROR_UNEXPECTED_PACKET || ret == PICOQUIC_ERROR_FNV1A_CHECK || 
        ret == PICOQUIC_ERROR_CNXID_CHECK || 
        ret == PICOQUIC_ERROR_RETRY || ret == PICOQUIC_ERROR_DETECTED ||
        ret == PICOQUIC_ERROR_CONNECTION_DELETED ||
        ret == PICOQUIC_ERROR_CNXID_SEGMENT) {
        /* Bad packets are dropped silently */

        DBG_PRINTF("Packet (%d) dropped, t: %d, e: %d, pc: %d, pn: %d, l: %d, ret : %x\n",
            (cnx == NULL) ? -1 : cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn, 
            length, ret);

        if (ret == PICOQUIC_ERROR_AEAD_CHECK) {
            ret = 0;
        }
        else {
            ret = -1;
        }
        if (cnx != NULL) {
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time);
        }
    } else if (ret == 1) {
        /* wonder what happened ! */
        DBG_PRINTF("Packet (%d) get ret=1, t: %d, e: %d, pc: %d, pn: %d, l: %d\n",
            (cnx == NULL) ? -1 : cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn, length);
        ret = -1;
    }
    else if (ret != 0) {
        DBG_PRINTF("Packet (%d) error, t: %d, e: %d, pc: %d, pn: %d, l: %d, ret : %x\n",
            (cnx == NULL) ? -1 : cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn, length, ret);
        ret = -1;
    }

    return ret;
}

int picoquic_incoming_packet(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    uint32_t packet_length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time)
{
    uint32_t consumed_index = 0;
    int ret = 0;
    picoquic_connection_id_t previous_destid = picoquic_null_connection_id;


    while (consumed_index < packet_length) {
        uint32_t consumed = 0;

        ret = picoquic_incoming_segment(quic, bytes + consumed_index, 
            packet_length - consumed_index, packet_length,
            &consumed, addr_from, addr_to, if_index_to, received_ecn, current_time, &previous_destid);

        received_ecn = 0; /* Avoid doublecounting ECN bits in coalesced packets */

        if (ret == 0) {
            consumed_index += consumed;
        } else {
            ret = 0;
            break;
        }
    }

    return ret;
}
