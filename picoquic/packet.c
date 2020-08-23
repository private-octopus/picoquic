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

#include "picoquic_internal.h"
#include "logwriter.h"
#include "tls_api.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

uint8_t* picoquic_frames_varint_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n64);
uint8_t* picoquic_frames_varlen_decode(uint8_t* bytes, const uint8_t* bytes_max, size_t* n);
uint8_t* picoquic_frames_uint8_decode(uint8_t* bytes, const uint8_t* bytes_max, uint8_t* n);
uint8_t* picoquic_frames_uint16_decode(uint8_t* bytes, const uint8_t* bytes_max, uint16_t* n);
uint8_t* picoquic_frames_uint32_decode(uint8_t* bytes, const uint8_t* bytes_max, uint32_t* n);
uint8_t* picoquic_frames_uint64_decode(uint8_t* bytes, const uint8_t* bytes_max, uint64_t* n);
uint8_t* picoquic_frames_cid_decode(uint8_t* bytes, const uint8_t* bytes_max, picoquic_connection_id_t* n);

int picoquic_parse_long_packet_header(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t length,
    struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx)
{
    int ret = 0;

    const uint8_t* bytes_start = bytes;
    const uint8_t* bytes_max = bytes + length;
    uint8_t flags = 0;

    if ((bytes = picoquic_frames_uint8_decode(bytes, bytes_max, &flags)) == NULL ||
        (bytes = picoquic_frames_uint32_decode(bytes, bytes_max, &ph->vn)) == NULL ||
        (bytes = picoquic_frames_cid_decode(bytes, bytes_max, &ph->dest_cnx_id)) == NULL ||
        (bytes = picoquic_frames_cid_decode(bytes, bytes_max, &ph->srce_cnx_id)) == NULL) {
        ret = -1;
    }

    if (ret == 0) {
        ph->offset = bytes - bytes_start;

        if (ph->vn == 0) {
            /* VN = zero identifies a version negotiation packet */
            ph->ptype = picoquic_packet_version_negotiation;
            ph->pc = picoquic_packet_context_initial;
            ph->payload_length = (uint16_t)((length > ph->offset) ? length - ph->offset : 0);
            ph->pl_val = ph->payload_length; /* saving the value found in the packet */

            if (*pcnx == NULL && quic != NULL) {
                /* The version negotiation should always include the cnx-id sent by the client */
                if (quic->local_cnxid_length == 0) {
                    *pcnx = picoquic_cnx_by_net(quic, addr_from);
                } else if (ph->dest_cnx_id.id_len == quic->local_cnxid_length){
                    *pcnx = picoquic_cnx_by_id(quic, ph->dest_cnx_id);
                }
            }
        }
        else {
            size_t payload_length = 0;

            ph->version_index = picoquic_get_version_index(ph->vn);

            if (ph->version_index >= 0) {
                /* If the version is supported now, the format field in the version table
                * describes the encoding. */
                ph->spin = 0;
                ph->has_spin_bit = 0;
                ph->quic_bit_is_zero = (flags & 0x40) == 0;

                switch ((flags >> 4) & 3) {
                case 0: /* Initial */
                {
                    /* special case of the initial packets. They contain a retry token between the header
                    * and the encrypted payload */
                    size_t tok_len = 0;
                    bytes = picoquic_frames_varlen_decode(bytes, bytes_max, &tok_len);

                    size_t bytes_left = bytes_max - bytes;

                    ph->epoch = picoquic_epoch_initial;
                    if (bytes == NULL || bytes_left < tok_len) {
                        /* packet is malformed */
                        ph->ptype = picoquic_packet_error;
                        ph->pc = 0;
                        ph->offset = length;
                    }
                    else {
                        ph->ptype = picoquic_packet_initial;
                        ph->pc = picoquic_packet_context_initial;
                        ph->token_length = tok_len;
                        ph->token_bytes = bytes;
                        bytes += tok_len;
                        ph->offset = bytes - bytes_start;
                    }

                    break;
                }
                case 1: /* 0-RTT Protected */
                    ph->ptype = picoquic_packet_0rtt_protected;
                    ph->pc = picoquic_packet_context_application;
                    ph->epoch = picoquic_epoch_0rtt;
                    break;
                case 2: /* Handshake */
                    ph->ptype = picoquic_packet_handshake;
                    ph->pc = picoquic_packet_context_handshake;
                    ph->epoch = picoquic_epoch_handshake;
                    break;
                case 3: /* Retry */
                    ph->ptype = picoquic_packet_retry;
                    ph->pc = picoquic_packet_context_initial;
                    ph->epoch = picoquic_epoch_initial;
                    break;
                default: /* Not a valid packet type */
                    DBG_PRINTF("Packet type is not recognized: 0x%02x\n", flags);
                    ph->ptype = picoquic_packet_error;
                    ph->version_index = -1;
                    ph->pc = 0;
                    break;
                }
            }
            else {
                DBG_PRINTF("Version is not recognized: 0x%08x\n", ph->vn);
                ph->ptype = picoquic_packet_error;
                ph->pc = 0;
            }

            if (ph->ptype == picoquic_packet_retry) {
                /* No segment length or sequence number in retry packets */
                if (length > ph->offset) {
                    payload_length = length - ph->offset;
                }
                else {
                    payload_length = 0;
                    ph->ptype = picoquic_packet_error;
                }
            }
            else if (ph->ptype != picoquic_packet_error) {
                bytes = picoquic_frames_varlen_decode(bytes, bytes_max, &payload_length);

                size_t bytes_left = (bytes_max > bytes) ? bytes_max - bytes : 0;
                if (bytes == NULL || bytes_left < payload_length || ph->version_index < 0) {
                    ph->ptype = picoquic_packet_error;
                    ph->payload_length = (uint16_t)((length > ph->offset) ? length - ph->offset : 0);
                    ph->pl_val = ph->payload_length;
                }
            }

            if (ph->ptype != picoquic_packet_error)
            {
                ph->pl_val = (uint16_t)payload_length;
                ph->payload_length = (uint16_t)payload_length;
                ph->offset = bytes - bytes_start;
                ph->pn_offset = ph->offset;

                /* Retrieve the connection context */
                if (*pcnx == NULL) {
                    if (quic->local_cnxid_length == 0) {
                        *pcnx = picoquic_cnx_by_net(quic, addr_from);
                    }
                    else
                    {
                        if (ph->dest_cnx_id.id_len == quic->local_cnxid_length) {
                            *pcnx = picoquic_cnx_by_id(quic, ph->dest_cnx_id);
                        }

                        if (*pcnx == NULL && (ph->ptype == picoquic_packet_initial || ph->ptype == picoquic_packet_0rtt_protected)) {
                            *pcnx = picoquic_cnx_by_icid(quic, &ph->dest_cnx_id, addr_from);
                        }
                        else if (*pcnx == NULL) {
                            DBG_PRINTF("Dropped packet of type %d, no connection", ph->ptype);
                        }
                    }
                }

                if (ph->quic_bit_is_zero && *pcnx != NULL && !(*pcnx)->local_parameters.do_grease_quic_bit) {
                    ph->ptype = picoquic_packet_error;
                }
            }
            else {
                /* Try to find the connection context, for logging purpose. */
                if (*pcnx == NULL) {
                    if (quic->local_cnxid_length == 0) {
                        *pcnx = picoquic_cnx_by_net(quic, addr_from);
                    }
                    else if (ph->dest_cnx_id.id_len == quic->local_cnxid_length) {
                        *pcnx = picoquic_cnx_by_id(quic, ph->dest_cnx_id);
                    }
                }
            }
        }
    }
    return ret;
}

int picoquic_parse_short_packet_header(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t length,
    struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    int receiving)
{
    int ret = 0;
    /* If this is a short header, it should be possible to retrieve the connection
     * context. This depends on whether the quic context requires cnx_id or not.
     */
    uint8_t cnxid_length = (receiving == 0 && *pcnx != NULL) ? (*pcnx)->path[0]->remote_cnxid.id_len : quic->local_cnxid_length;
    ph->pc = picoquic_packet_context_application;
    ph->pl_val = 0; /* No actual payload length in short headers */

    if ((int)length >= 1 + cnxid_length) {
        /* We can identify the connection by its ID */
        ph->offset = (size_t)1 + picoquic_parse_connection_id(bytes + 1, cnxid_length, &ph->dest_cnx_id);
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
    }
    else {
        ph->ptype = picoquic_packet_error;
        ph->offset = length;
        ph->payload_length = 0;
    }

    if (*pcnx != NULL) {
        int has_loss_bit = (receiving && (*pcnx)->is_loss_bit_enabled_incoming) || ((!receiving && (*pcnx)->is_loss_bit_enabled_outgoing));
        ph->epoch = picoquic_epoch_1rtt;
        ph->version_index = (*pcnx)->version_index;
        ph->quic_bit_is_zero = (bytes[0] & 0x40) == 0;

        if (!ph->quic_bit_is_zero ||(*pcnx)->local_parameters.do_grease_quic_bit) {
            /* We do not check the quic bit if the local endpoint advertised greasing. */
            ph->ptype = picoquic_packet_1rtt_protected;
        } else {
            /* Check for QUIC bit failed! */
            ph->ptype = picoquic_packet_error;
        }

        ph->has_spin_bit = 1;
        ph->spin = (bytes[0] >> 5) & 1;
        ph->pn_offset = ph->offset;
        ph->pn = 0;
        ph->pnmask = 0;
        ph->key_phase = ((bytes[0] >> 2) & 1); /* Initialize here so that simple tests with unencrypted headers can work */

        if (has_loss_bit) {
            ph->has_loss_bits = 1;
            ph->loss_bit_L = (bytes[0] >> 3) & 1;
            ph->loss_bit_Q = (bytes[0] >> 4) & 1;
        }
        if (length < ph->offset || ph->ptype == picoquic_packet_error) {
            ret = -1;
            ph->payload_length = 0;
        }
        else {
            ph->payload_length = (uint16_t)(length - ph->offset);
        }
    }
    else {
        /* This may be a packet to a forgotten connection */
        ph->ptype = picoquic_packet_1rtt_protected;
        ph->payload_length = (uint16_t)((length > ph->offset) ? length - ph->offset : 0);
    }
    return ret;
}

int picoquic_parse_packet_header(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t length,
    struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    int receiving)
{
    int ret = 0;

    /* Initialize the PH structure to zero, but version index to -1 (error) */
    memset(ph, 0, sizeof(picoquic_packet_header));
    ph->version_index = -1;

    /* Is this a long header or a short header? -- in any case, we need at least 17 bytes */
    if ((bytes[0] & 0x80) == 0x80) {
        ret = picoquic_parse_long_packet_header(quic, bytes, length, addr_from, ph, pcnx);
    } else {
        ret = picoquic_parse_short_packet_header(quic, bytes, length, addr_from, ph, pcnx, receiving);
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

/* Debug code used to test whether the PN decryption works as expected.
 */

void picoquic_log_pn_dec_trial(picoquic_cnx_t* cnx)
{
    if (cnx->quic->log_pn_dec && (cnx->quic->F_log != NULL || cnx->f_binlog != NULL)){
        void* pn_dec = cnx->crypto_context[picoquic_epoch_1rtt].pn_dec;
        void* pn_enc = cnx->crypto_context[picoquic_epoch_1rtt].pn_enc;
        uint8_t test_iv[32] = {
            0, 1, 3, 4, 4, 6, 7, 8, 9,
            0, 1, 3, 4, 4, 6, 7, 8, 9,
            0, 1, 3, 4, 4, 6, 7, 8, 9,
            0, 1 };
        size_t mask_length = 5;
        uint8_t mask_bytes[5] = { 0, 0, 0, 0, 0 };
        uint8_t demask_bytes[5] = { 0, 0, 0, 0, 0 };

        if (pn_enc != NULL) {
            picoquic_pn_encrypt(pn_enc, test_iv, mask_bytes, mask_bytes, mask_length);
        }

        if (pn_dec != NULL) {
            picoquic_pn_encrypt(pn_dec, test_iv, demask_bytes, demask_bytes, mask_length);
        }

        picoquic_log_app_message(cnx, "1RTT PN ENC/DEC, Phi: %d, signature = %02x%02x%02x%02x%02x, %02x%02x%02x%02x%02x",
            cnx->key_phase_enc,
            mask_bytes[0], mask_bytes[1], mask_bytes[2], mask_bytes[3], mask_bytes[4],
            demask_bytes[0], demask_bytes[1], demask_bytes[2], demask_bytes[3], demask_bytes[4]);
    }
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
            uint8_t first_mask = ((first_byte & 0x80) == 0x80) ? 0x0F : (cnx->is_loss_bit_enabled_incoming)?0x07:0x1F;
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
            ph->has_reserved_bit_set = ((first_byte & 0x80) == 0 && !cnx->is_loss_bit_enabled_incoming &&
                (first_byte & 0x18) != 0);
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

        ret = PICOQUIC_ERROR_AEAD_NOT_READY;
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
    if (already_received != NULL) {
        if (picoquic_is_pn_already_received(cnx, ph->pc, ph->pn64) != 0) {
            /* Set error type: already received */
            *already_received = 1;
        }
        else {
            *already_received = 0;
        }
    }

    if (ph->epoch == picoquic_epoch_1rtt) {
        /* Manage key rotation */
        if (ph->key_phase == cnx->key_phase_dec) {
            /* AEAD Decrypt, in place */
            decoded = picoquic_aead_decrypt_generic(bytes + ph->offset,
                bytes + ph->offset, ph->payload_length, ph->pn64, bytes, ph->offset, cnx->crypto_context[picoquic_epoch_1rtt].aead_decrypt);
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
                    cnx->nb_crypto_key_rotations++;

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

    /* Add here a check that the PN key is still valid. */
    if (decoded > ph->payload_length) {
        picoquic_log_pn_dec_trial(cnx);
    }
    
    /* by conventions, values larger than input indicate error */
    return decoded;
}

int picoquic_parse_header_and_decrypt(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t length,
    size_t packet_length,
    struct sockaddr* addr_from,
    uint64_t current_time,
    picoquic_packet_header* ph,
    picoquic_cnx_t** pcnx,
    size_t * consumed,
    int * new_ctx_created)
{
    /* Parse the clear text header. Ret == 0 means an incorrect packet that could not be parsed */
    int already_received = 0;
    size_t decoded_length = 0;
    int ret = picoquic_parse_packet_header(quic, bytes, length, addr_from, ph, pcnx, 1);

    *new_ctx_created = 0;

    if (ret == 0 ) {
        if (ph->ptype != picoquic_packet_version_negotiation && 
            ph->ptype != picoquic_packet_retry && ph->ptype != picoquic_packet_error) {
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
                        /* If an incoming connection was created, register the ICID */
                        *new_ctx_created = (*pcnx == NULL) ? 0 : 1;
                        if (*pcnx == NULL) {
                            DBG_PRINTF("%s", "Cannot create connection context\n");
                        }
                        else if (quic->F_log) {
                            picoquic_log_packet_address(quic->F_log, picoquic_val64_connection_id(ph->dest_cnx_id),
                                *pcnx, addr_from, 1, length, current_time);
                            fflush(quic->F_log);
                        }
                    }
                }
            }
            else if (!(*pcnx)->client_mode && ph->ptype == picoquic_packet_initial && packet_length < PICOQUIC_ENFORCED_INITIAL_MTU) {
                /* Unexpected packet. Reject, drop and log. */
                ret = PICOQUIC_ERROR_INITIAL_TOO_SHORT;
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

                    if (decoded_length > (length - ph->offset)) {
                        if (ph->ptype == picoquic_packet_1rtt_protected &&
                            length >= PICOQUIC_RESET_PACKET_MIN_SIZE &&
                            memcmp(bytes + length - PICOQUIC_RESET_SECRET_SIZE,
                            (*pcnx)->path[0]->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
                            ret = PICOQUIC_ERROR_STATELESS_RESET;
                        }
                        else {
                            if (ret != PICOQUIC_ERROR_AEAD_NOT_READY) {
                                ret = PICOQUIC_ERROR_AEAD_CHECK;
                            }
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
                    /* This may be a stateless reset.
                     * We test the address + putative reset secret pair against the hash table
                     * of registered secrets. If there is a match, the corresponding connection is
                     * found and the packet is marked as Stateless Reset */

                    if (length >= PICOQUIC_RESET_PACKET_MIN_SIZE) {
                        *pcnx = picoquic_cnx_by_secret(quic, bytes + length - PICOQUIC_RESET_SECRET_SIZE, addr_from);
                        if (*pcnx != NULL) {
                            ret = PICOQUIC_ERROR_STATELESS_RESET;
                        }
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
    size_t length,
    struct sockaddr* addr_from,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(addr_from);
    UNREFERENCED_PARAMETER(current_time);
#endif

    /* Check the connection state */
    if (cnx->cnx_state != picoquic_state_client_init_sent) {
        /* This is an unexpected packet. Log and drop.*/
        DBG_PRINTF("Unexpected VN packet (%d), state %d, type: %d, epoch: %d, pc: %d, pn: %d\n",
            cnx->client_mode, cnx->cnx_state, ph->ptype, ph->epoch, ph->pc, (int)ph->pn);
    } else if (picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->path[0]->p_local_cnxid->cnx_id) != 0 || ph->vn != 0) {
        /* Packet that do not match the "echo" checks should be logged and ignored */
        DBG_PRINTF("VN packet (%d), does not pass echo test.\n", cnx->client_mode);
        ret = PICOQUIC_ERROR_DETECTED;
    } else {
        /* Add DOS resilience */
        uint8_t * v_bytes = bytes + ph->offset;
        uint8_t* bytes_max = bytes + length;
        int nb_vn = 0;
        while (v_bytes < bytes_max) {
            uint32_t vn = 0;
            if ((v_bytes = picoquic_frames_uint32_decode(v_bytes, bytes_max, &vn)) == NULL){
                DBG_PRINTF("VN packet (%d), length %zu, coding error after %d version numbers.\n",
                    cnx->client_mode, length, nb_vn);
                ret = PICOQUIC_ERROR_DETECTED;
                break;
            } else if (vn == cnx->proposed_version) {
                DBG_PRINTF("VN packet (%d), proposed_version[%d] = 0x%08x.\n", cnx->client_mode, nb_vn, vn);
                ret = PICOQUIC_ERROR_DETECTED;
                break;
            }
            nb_vn++;
        }
        if (ret == 0) {
            if (nb_vn == 0) {
                DBG_PRINTF("VN packet (%d), does not propose any version.\n", cnx->client_mode);
                ret = PICOQUIC_ERROR_DETECTED;
            }
            else {
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
        }
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
    picoquic_cnx_t* cnx = NULL;

    /* Verify that this is not a spurious error by checking whether a connection context
     * already exists */
    if (ph->dest_cnx_id.id_len == quic->local_cnxid_length) {
        if (quic->local_cnxid_length == 0) {
            cnx = picoquic_cnx_by_net(quic, addr_from);
        }
        else {
            cnx = picoquic_cnx_by_id(quic, ph->dest_cnx_id);
        }
    }
    if (cnx == NULL) {
        cnx = picoquic_cnx_by_icid(quic, &ph->dest_cnx_id, addr_from);
    }

    /* If no connection context exists, send back a version negotiation */
    if (cnx == NULL) {
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

            bytes[byte_index++] = ph->srce_cnx_id.id_len;
            byte_index += picoquic_format_connection_id(bytes + byte_index, PICOQUIC_MAX_PACKET_SIZE - byte_index, ph->srce_cnx_id);
            bytes[byte_index++] = ph->dest_cnx_id.id_len;
            byte_index += picoquic_format_connection_id(bytes + byte_index, PICOQUIC_MAX_PACKET_SIZE - byte_index, ph->dest_cnx_id);

            /* Set the payload to the list of versions */
            for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
                picoformat_32(bytes + byte_index, picoquic_supported_versions[i].version);
                byte_index += 4;
            }
            /* Add random reserved value as grease, but be careful to not match proposed version */
            do {
                rand_vn = (((uint32_t)picoquic_public_random_64()) & 0xF0F0F0F0) | 0x0A0A0A0A;
            } while (rand_vn == ph->vn);
            picoformat_32(bytes + byte_index, rand_vn);
            byte_index += 4;

            /* Set length and addresses, and queue. */
            sp->length = byte_index;
            picoquic_store_addr(&sp->addr_to, addr_from);
            picoquic_store_addr(&sp->addr_local, addr_to);
            sp->if_index_local = if_index_to;
            sp->initial_cid = ph->dest_cnx_id;
            sp->cnxid_log64 = picoquic_val64_connection_id(sp->initial_cid);
            sp->ptype = picoquic_packet_version_negotiation;

            if (quic->F_log != NULL) {
                picoquic_log_outgoing_segment(quic->F_log, 1, NULL,
                    bytes, 0, sp->length,
                    bytes, sp->length, 0);
            }

            picoquic_queue_stateless_packet(quic, sp);
        }
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
    size_t length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph)
{
    if (length > PICOQUIC_RESET_PACKET_MIN_SIZE && 
        ph->ptype == picoquic_packet_1rtt_protected) {
        picoquic_stateless_packet_t* sp = picoquic_create_stateless_packet(quic);
        if (sp != NULL) {
            size_t pad_size = length - PICOQUIC_RESET_SECRET_SIZE -1;
            uint8_t* bytes = sp->bytes;
            size_t byte_index = 0;

            if (pad_size > PICOQUIC_RESET_PACKET_PAD_SIZE) {
                pad_size = (size_t)picoquic_public_uniform_random(pad_size - PICOQUIC_RESET_PACKET_PAD_SIZE)
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
            (void)picoquic_create_cnxid_reset_secret(quic, &ph->dest_cnx_id, bytes + byte_index);
            byte_index += PICOQUIC_RESET_SECRET_SIZE;
            sp->length = byte_index;
            sp->ptype = picoquic_packet_1rtt_protected;
            picoquic_store_addr(&sp->addr_to, addr_from);
            picoquic_store_addr(&sp->addr_local, addr_to);
            sp->if_index_local = if_index_to;
            sp->initial_cid = ph->dest_cnx_id;
            sp->cnxid_log64 = picoquic_val64_connection_id(sp->initial_cid);

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
    void * integrity_aead = picoquic_find_retry_protection_context(cnx, 1);
    size_t checksum_length = (integrity_aead == NULL) ? 0 : picoquic_aead_get_checksum_length(integrity_aead);

    if (sp != NULL) {
        uint8_t* bytes = sp->bytes;
        size_t byte_index = 0;
        size_t header_length = 0;
        size_t pn_offset;
        size_t pn_length;

        cnx->path[0]->remote_cnxid = ph->srce_cnx_id;

        byte_index = header_length = picoquic_create_packet_header(cnx, picoquic_packet_retry,
            0, &cnx->path[0]->remote_cnxid, &cnx->path[0]->p_local_cnxid->cnx_id, 0,
            bytes, &pn_offset, &pn_length);

        /* In the old drafts, there is no header protection and the sender copies the ODCID
         * in the packet. In the recent draft, the ODCID is not sent but
         * is verified as part of integrity checksum */
        if (integrity_aead == NULL) {
            bytes[byte_index++] = cnx->initial_cnxid.id_len;
            byte_index += picoquic_format_connection_id(bytes + byte_index,
                PICOQUIC_MAX_PACKET_SIZE - byte_index - checksum_length, cnx->initial_cnxid);
        }

        /* Add the token */
        memcpy(&bytes[byte_index], token, token_length);
        byte_index += token_length;

        /* Encode the retry integrity protection if required. */
        byte_index = picoquic_encode_retry_protection(integrity_aead, bytes, PICOQUIC_MAX_PACKET_SIZE, byte_index, &cnx->initial_cnxid);

        sp->length = byte_index;

        sp->ptype = picoquic_packet_1rtt_protected;

        picoquic_store_addr(&sp->addr_to, addr_from);
        picoquic_store_addr(&sp->addr_local, addr_to);
        sp->if_index_local = if_index_to;
        sp->cnxid_log64 = picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx));

        if (cnx->quic->F_log != NULL) {
            picoquic_log_outgoing_segment(cnx->quic->F_log, 1, cnx,
                bytes, 0, sp->length,
                bytes, sp->length, pn_length);
        }
        if (cnx->f_binlog != NULL) {
            binlog_outgoing_packet(cnx,
                bytes, 0, pn_length, sp->length,
                bytes, sp->length, picoquic_get_quic_time(cnx->quic));
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
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    /* The data starts at ph->index, and its length
     * is ph->payload_length. */
    int ret = 0;
    size_t byte_index = 0;
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
        ret = picoquic_skip_frame(&bytes[byte_index],
            ph->payload_length - byte_index, &frame_length, &frame_is_pure_ack);
        byte_index += frame_length;
        if (frame_is_pure_ack == 0) {
            ack_needed = 1;
        }
    }

    /* If the packet contains ackable data, mark ack needed
     * in the relevant packet context */
    if (ret == 0 && ack_needed) {
        picoquic_set_ack_needed(cnx, current_time, pc);
    }
}

/*
 * Processing of an incoming client initial packet,
 * on an unknown connection context.
 */

int picoquic_incoming_client_initial(
    picoquic_cnx_t** pcnx,
    uint8_t* bytes,
    size_t packet_length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph,
    uint64_t current_time,
    int new_context_created)
{
    int ret = 0;

    /* Logic to test the retry token.
     * TODO: this should probably be implemented as a callback */
    if (((*pcnx)->quic->check_token) &&
        (*pcnx)->cnx_state == picoquic_state_server_init &&
        !(*pcnx)->quic->server_busy) {
        if (picoquic_verify_retry_token((*pcnx)->quic, addr_from, current_time,
            &(*pcnx)->original_cnxid, &ph->dest_cnx_id, ph->pn,
            ph->token_bytes, ph->token_length, new_context_created) != 0) {
            if (ph->token_length != 0) {
                (void)picoquic_connection_error(*pcnx, PICOQUIC_TRANSPORT_INVALID_TOKEN, 0);
                ret = PICOQUIC_ERROR_INVALID_TOKEN;
            }
            else {
                uint8_t token_buffer[256];
                size_t token_size;

                if (picoquic_prepare_retry_token((*pcnx)->quic, addr_from,
                    current_time + PICOQUIC_TOKEN_DELAY_SHORT, &ph->dest_cnx_id,
                    &(*pcnx)->path[0]->p_local_cnxid->cnx_id, ph->pn,
                    token_buffer, sizeof(token_buffer), &token_size) != 0) {
                    ret = PICOQUIC_ERROR_MEMORY;
                }
                else {
                    picoquic_queue_stateless_retry(*pcnx, ph,
                        addr_from, addr_to, if_index_to, token_buffer, token_size);
                    ret = PICOQUIC_ERROR_RETRY;
                }
            }
        }
        else {
            (*pcnx)->initial_validated = 1;
        }
    }

    if (ret == 0) {
        if (picoquic_compare_connection_id(&ph->dest_cnx_id, &(*pcnx)->path[0]->p_local_cnxid->cnx_id) == 0) {
            (*pcnx)->initial_validated = 1;
        }

        if (!(*pcnx)->initial_validated && (*pcnx)->pkt_ctx[picoquic_packet_context_initial].retransmit_oldest != NULL
            && packet_length >= PICOQUIC_ENFORCED_INITIAL_MTU) {
            (*pcnx)->initial_repeat_needed = 1;
        }

        if ((*pcnx)->cnx_state == picoquic_state_server_init && 
            (*pcnx)->quic->server_busy) {
            (*pcnx)->local_error = PICOQUIC_TRANSPORT_SERVER_BUSY;
            (*pcnx)->cnx_state = picoquic_state_handshake_failure;
        }
        else if ((*pcnx)->cnx_state == picoquic_state_server_init && 
            (*pcnx)->initial_cnxid.id_len < PICOQUIC_ENFORCED_INITIAL_CID_LENGTH) {
            (*pcnx)->local_error = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
            (*pcnx)->cnx_state = picoquic_state_handshake_failure;
        }
        else if ((*pcnx)->cnx_state < picoquic_state_server_almost_ready) {
            /* Document the incoming addresses */
            if ((*pcnx)->path[0]->local_addr.ss_family == 0 && addr_to != NULL) {
                picoquic_store_addr(&(*pcnx)->path[0]->local_addr, addr_to);
            }
            if ((*pcnx)->path[0]->peer_addr.ss_family == 0 && addr_from != NULL) {
                picoquic_store_addr(&(*pcnx)->path[0]->peer_addr, addr_from);
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
        else if ((*pcnx)->cnx_state < picoquic_state_ready) {
            /* Require an acknowledgement if the packet contains ackable frames */
            picoquic_ignore_incoming_handshake(*pcnx, bytes, ph, current_time);
        }
        else {
            /* Initial keys should have been discarded, treat packet as unexpected */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        }
    }

    if (ret == PICOQUIC_ERROR_INVALID_TOKEN && (*pcnx)->cnx_state == picoquic_state_handshake_failure) {
        ret = 0;
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
        void * integrity_aead = picoquic_find_retry_protection_context(cnx, 0);
        size_t byte_index = ph->offset;
        size_t data_length = ph->offset + ph->payload_length;

        /* Assume that is aead context is null, this is the old format and the 
         * integrity shall be verifed by checking the ODCID */
        if (integrity_aead == NULL) {
            uint8_t odcil = bytes[byte_index++];

            if (odcil != cnx->initial_cnxid.id_len || (size_t)odcil + 1u > ph->payload_length ||
                memcmp(cnx->initial_cnxid.id, &bytes[byte_index], odcil) != 0) {
                /* malformed ODCIL, or does not match initial cid; ignore */
                ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
                picoquic_log_app_message(cnx, "Retry packet rejected: odcid check failed");
            }
            else {
                byte_index += odcil;
            }
        }
        else {
            ret = picoquic_verify_retry_protection(integrity_aead, bytes, &data_length, byte_index, &cnx->initial_cnxid);

            picoquic_log_app_message(cnx, "Retry packet rejected: integrity check failed");
        }

        if (ret == 0) {
            token_length = data_length - byte_index;

            if (token_length > 0) {
                token = malloc(token_length);
                if (token == NULL) {
                    ret = PICOQUIC_ERROR_MEMORY;
                }
                else {
                    memcpy(token, &bytes[byte_index], token_length);
                }
            }
        }
    }

    if (ret == 0) {
        /* Close the log, because it is keyed by initial_cnxid */
        binlog_close_connection(cnx);
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

int picoquic_incoming_server_initial(
    picoquic_cnx_t* cnx,
    uint8_t* bytes,
    struct sockaddr* addr_to,
    unsigned long if_index_to,
    picoquic_packet_header* ph,
    uint64_t current_time)
{
    int ret = 0;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(if_index_to);
#endif

    if (cnx->cnx_state == picoquic_state_client_init_sent || cnx->cnx_state == picoquic_state_client_init_resent) {
        cnx->cnx_state = picoquic_state_client_handshake_start;
    }

    /* Check the server cnx id */
    if ((!picoquic_is_connection_id_null(&cnx->path[0]->remote_cnxid) || cnx->cnx_state > picoquic_state_client_handshake_start) &&
        picoquic_compare_connection_id(&cnx->path[0]->remote_cnxid, &ph->srce_cnx_id) != 0) {
        ret = PICOQUIC_ERROR_CNXID_CHECK; /* protocol error */
    }

    if (ret == 0) {
        if (cnx->cnx_state <= picoquic_state_client_handshake_start) {
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
            if (ret == 0) {
                ret = picoquic_tls_stream_process(cnx);
            }
        }
        else if (cnx->cnx_state < picoquic_state_ready) {
            /* Require an acknowledgement if the packet contains ackable frames */
            picoquic_ignore_incoming_handshake(cnx, bytes, ph, current_time);
        }
        else {
            /* Initial keys should have been discarded, treat packet as unexpected */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        }
    }

    return ret;
}


int picoquic_incoming_server_handshake(
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
    int restricted = cnx->cnx_state != picoquic_state_client_handshake_start;
    
    if (picoquic_compare_connection_id(&cnx->path[0]->remote_cnxid, &ph->srce_cnx_id) != 0) {
        ret = PICOQUIC_ERROR_CNXID_CHECK; /* protocol error */
    }


    if (ret == 0) {
        if (cnx->cnx_state < picoquic_state_ready) {
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
            }
        }
        else {
            /* Initial keys should have been discarded, treat packet as unexpected */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
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

    cnx->initial_validated = 1;

    if (cnx->cnx_state < picoquic_state_server_almost_ready) {
        if (picoquic_compare_connection_id(&ph->srce_cnx_id, &cnx->path[0]->remote_cnxid) != 0) {
            ret = PICOQUIC_ERROR_CNXID_CHECK;
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
                /* Any successful handshake packet is an explicit ack of initial packets */
                picoquic_implicit_handshake_ack(cnx, picoquic_packet_context_initial, current_time);
                picoquic_crypto_context_free(&cnx->crypto_context[picoquic_epoch_initial]);

                /* If TLS data present, progress the TLS state */
                ret = picoquic_tls_stream_process(cnx);

                /* If TLS FIN has been received, the server side handshake is ready */
                if (!cnx->client_mode && cnx->cnx_state < picoquic_state_ready && picoquic_is_tls_complete(cnx)) {
                    picoquic_ready_state_transition(cnx, current_time);
                }
            }
        }
    }
    else if (cnx->cnx_state <= picoquic_state_ready) {
        /* Because the client is never guaranteed to discard handshake keys,
         * we need to keep it for the duration of the connection.
         * Process the incoming frames, ignore them, but 
         * require an acknowledgement if the packet contains ackable frames */
        picoquic_ignore_incoming_handshake(cnx, bytes, ph, current_time);
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
        picoquic_compare_connection_id(&ph->dest_cnx_id, &cnx->path[0]->p_local_cnxid->cnx_id) == 0) ||
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
                cnx->nb_zero_rtt_received++;
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
Find path of incoming packet

A path is defined by a pair of addresses. The path is created by the client
when it learns about a new local or remote address. It is created by the
server when it receives data from a not yet identified address pair.

We associate a local CID with a path. This is the CID that the peer uses
to send packet. This is a loose association. When a packet is received, the
packet is associated with a path based on the address tuple. If this is a
new tuple, a new path should be created, unless too many paths have been
created already (some heuristics needed there). 

Different scenarios play here:

 - If the incoming CID has not yet been seen, we treat arrival as a
   migration attempt and pursue the validation sequence.

 - If this is the same incoming CID as an existing path, we treat it
   as an indication of NAT rebinding. We may need some heuristic to
   decide whether this is legit or an attack. If this may be legit, we
   create a new path and send challenges on both the new and the old path.

 - If this is the same tuple and a different incoming CID, we treat that
   as an attempt by the peer to change the CID for privacy reason. On this
   event, the server picks a new CID for the path if available. (May need
   some safety there, e.g. only pick a new CID if the incoming CID sequence
   is higher than the old one.)
   
NAT rebinding should only happen if the address was changed in the
network, either by a NAT or by an attacker. NATs are:

 - rare but not unheard of in front of servers

 - rare with IPv6
 
  - rare if the connection is sustained
  
A small problem here is that the QUIC test suite include some pretty
unrealistic NAT rebinding simulations, so we cannot be too strict. In
order to pass the test suites, we will accept the first rebinding
attempt as genuine, and be more picky with the next ones. They may have
to wait until validation timers expire.

Local CID are kept in a list, and are associated with paths by a reference.
If a local CID is retired, the reference is zeroed. When a new packet arrives
on path with a new CID, the reference is reset.

If we cannot associate an existing path with a packet and also
cannot create a new path, we treat the packet as arriving on the
default path.
*/

int picoquic_find_incoming_path(picoquic_cnx_t* cnx, picoquic_packet_header* ph,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    uint64_t current_time,
    int* p_path_id)
{
    int ret = 0;
    int partial_match_path = -1;
    int nat_rebinding_path = -1;
    int nat_rebinding_total = 0;
    int path_id = picoquic_find_path_by_address(cnx, addr_to, addr_from, &partial_match_path);

    if (path_id < 0 && partial_match_path >= 0) {
        /* Document the source address and promote to full match. */
        path_id = partial_match_path;
        picoquic_store_addr(&cnx->path[path_id]->local_addr, addr_to);
    }

    if (path_id >= 0) {
        /* Packet arriving on an existing path */
        if (cnx->path[path_id]->p_local_cnxid == NULL) {
            /* First packet from the peer. Remember the CNX ID. No further action */
            cnx->path[path_id]->p_local_cnxid = picoquic_find_local_cnxid(cnx, &ph->dest_cnx_id);
        } else if (picoquic_compare_connection_id(&cnx->path[path_id]->p_local_cnxid->cnx_id, &ph->dest_cnx_id) != 0) {
            /* The peer switched to a new CID */
            cnx->path[path_id]->p_local_cnxid = picoquic_find_local_cnxid(cnx, &ph->dest_cnx_id);
            if (cnx->client_mode == 0 && cnx->cnxid_stash_first != NULL && path_id == 0) {
                /* If on a server, dereference the current CID, and pick a new one */
                (void)picoquic_renew_connection_id(cnx, path_id);
            }
        }
    }
    else {
        /* No valid path. Need to create one, but only if this is
         * within our resource boundaries. This is the place where
         * we might want to do some heuristics.
         *
         * Check whether this is a duplicate of an existing path.
         */

        for (int i = 0; i < cnx->nb_paths; i++) {
            if (cnx->path[i]->p_local_cnxid != NULL &&
                picoquic_compare_connection_id(&cnx->path[i]->p_local_cnxid->cnx_id, &ph->dest_cnx_id) == 0) {
                if (nat_rebinding_total == 0) {
                    nat_rebinding_path = i;
                }
                nat_rebinding_total++;
            }
        }

        if (cnx->nb_paths < PICOQUIC_NB_PATH_TARGET
            && picoquic_create_path(cnx, current_time, addr_to, addr_from) > 0) {
            /* The peer is probing for a new path, or there was a path rebinding */
            path_id = cnx->nb_paths - 1;

            if (!cnx->client_mode && cnx->local_parameters.prefered_address.is_defined) {
                struct sockaddr_storage dest_addr;

                memset(&dest_addr, 0, sizeof(struct sockaddr_storage));

                /* program a migration. */
                if (addr_to->sa_family== AF_INET) {
                    /* configure an IPv4 sockaddr */
                    struct sockaddr_in* d4 = (struct sockaddr_in*) & dest_addr;
                    d4->sin_family = AF_INET;
                    d4->sin_port = htons(cnx->local_parameters.prefered_address.ipv4Port);
                    memcpy(&d4->sin_addr, cnx->local_parameters.prefered_address.ipv4Address, 4);
                } else if (addr_to->sa_family == AF_INET6){
                    /* configure an IPv6 sockaddr */
                    struct sockaddr_in6* d6 = (struct sockaddr_in6*) & dest_addr;
                    d6->sin6_family = AF_INET6;
                    d6->sin6_port = htons(cnx->local_parameters.prefered_address.ipv6Port);
                    memcpy(&d6->sin6_addr, cnx->local_parameters.prefered_address.ipv6Address, 16);
                }
                if (picoquic_compare_addr(addr_to, (struct sockaddr*) & dest_addr) == 0) {
                    cnx->path[path_id]->path_is_preferred_path = 1;
                }
            }

            if (picoquic_assign_peer_cnxid_to_path(cnx, path_id) != 0){
                /* Copy the destination ID from an existing path */
                int alt_path = (nat_rebinding_path >= 0) ? nat_rebinding_path : 0;
                cnx->path[path_id]->remote_cnxid = cnx->path[alt_path]->remote_cnxid;
                cnx->path[path_id]->remote_cnxid_sequence = cnx->path[alt_path]->remote_cnxid_sequence;
                memcpy(cnx->path[path_id]->reset_secret, cnx->path[alt_path]->reset_secret,
                    PICOQUIC_RESET_SECRET_SIZE);
            }

            cnx->path[path_id]->path_is_published = 1; 
            cnx->path[path_id]->p_local_cnxid = picoquic_find_local_cnxid(cnx, &ph->dest_cnx_id);
            picoquic_register_path(cnx, cnx->path[path_id]);
            picoquic_set_path_challenge(cnx, path_id, current_time);

            /* If this is a NAT rebinding, also set a challenge on the original path */
            if (nat_rebinding_path >= 0) {
                /* Treat this as a NAT rebinding. Mark the old path for validation */
                picoquic_set_path_challenge(cnx, nat_rebinding_path, current_time);
            }
        }
        else {
            DBG_PRINTF("%s", "Cannot create new path for incoming packet");
            if (nat_rebinding_path >= 0) {
                path_id = nat_rebinding_path;
            }
            else {
                path_id = 0;
            }
        }
    }

    *p_path_id = path_id;

    return ret;
}

/*
 * ECN Accounting. This is only called if the packet was processed successfully.
 */
void picoquic_ecn_accounting(picoquic_cnx_t* cnx,
    unsigned char received_ecn, picoquic_packet_context_enum pc)
{
    switch (received_ecn & 0x03) {
    case 0x00:
        break;
    case 0x01: /* ECN_ECT_1 */
        cnx->pkt_ctx[pc].ecn_ect1_total_local++;
        cnx->pkt_ctx[pc].sending_ecn_ack |= 1;
        break;
    case 0x02: /* ECN_ECT_0 */
        cnx->pkt_ctx[pc].ecn_ect0_total_local++;
        cnx->pkt_ctx[pc].sending_ecn_ack |= 1;
        break;
    case 0x03: /* ECN_CE */
        cnx->pkt_ctx[pc].ecn_ce_total_local++;
        cnx->pkt_ctx[pc].sending_ecn_ack |= 1;
        break;
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
                    bytes + ph->offset, ph->payload_length, &closing_received);

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
                        picoquic_set_ack_needed(cnx, current_time, ph->pc);
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
                /* Compute receive bandwidth */
                cnx->path[path_id]->received += ph->offset + ph->payload_length + 
                    picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
                if (cnx->path[path_id]->receive_rate_epoch == 0) {
                    cnx->path[path_id]->received_prior = cnx->path[path_id]->received;
                    cnx->path[path_id]->receive_rate_epoch = current_time;
                }
                else {
                    uint64_t delta = current_time - cnx->path[path_id]->receive_rate_epoch;
                    if (delta > cnx->path[path_id]->smoothed_rtt && delta > PICOQUIC_BANDWIDTH_TIME_INTERVAL_MIN) {
                        cnx->path[path_id]->receive_rate_estimate = ((cnx->path[path_id]->received - cnx->path[path_id]->received_prior)*1000000) / delta;
                        cnx->path[path_id]->received_prior = cnx->path[path_id]->received;
                        cnx->path[path_id]->receive_rate_epoch = current_time;
                        if (cnx->path[path_id]->receive_rate_estimate > cnx->path[path_id]->receive_rate_max) {
                            cnx->path[path_id]->receive_rate_max = cnx->path[path_id]->receive_rate_estimate;
                            if (path_id == 0 && !cnx->is_ack_frequency_negotiated) {
                                cnx->ack_gap_remote = picoquic_compute_ack_gap(cnx, cnx->path[0]->receive_rate_max);
                            }
                        }
                    }
                }

                /* Processing of TLS messages  */
                ret = picoquic_tls_stream_process(cnx);
            }

            if (ret == 0 && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE ||
                cnx->quic->use_long_log)) {
                picoquic_cc_dump(cnx, current_time);
            }
        }
    }

    return ret;
}

/* Processing of packets received before they could be fully decrypted
 */
int  picoquic_incoming_not_decrypted(
    picoquic_cnx_t* cnx,
    picoquic_packet_header* ph,
    uint64_t current_time,
    uint8_t * bytes,
    size_t length,
    struct sockaddr * addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn)
{
    int buffered = 0;

    if (cnx->cnx_state < picoquic_state_ready) {
        if (cnx->path[0]->p_local_cnxid->cnx_id.id_len > 0 &&
            picoquic_compare_connection_id(&cnx->path[0]->p_local_cnxid->cnx_id, &ph->dest_cnx_id) == 0)
        {
            /* verifying the destination cnx id is a strong hint that the peer is responding */
            if (cnx->path[0]->smoothed_rtt == PICOQUIC_INITIAL_RTT
                && cnx->path[0]->rtt_variant == 0 &&
                current_time - cnx->start_time < cnx->path[0]->smoothed_rtt) {
                /* We received a first packet from the peer! */
                picoquic_update_path_rtt(cnx, cnx->path[0], cnx->start_time, current_time, 0);
            }

            if (length <= PICOQUIC_MAX_PACKET_SIZE &&
                ((ph->ptype == picoquic_packet_handshake && cnx->client_mode) || ph->ptype == picoquic_packet_1rtt_protected)) {
                /* stash a copy of the incoming message for processing once the keys are available */
                picoquic_stateless_packet_t* packet = picoquic_create_stateless_packet(cnx->quic);

                if (packet != NULL) {
                    packet->length = length;
                    packet->ptype = ph->ptype;
                    memcpy(packet->bytes, bytes, length);
                    packet->next_packet = cnx->first_sooner;
                    cnx->first_sooner = packet;
                    picoquic_store_addr(&packet->addr_local, addr_to);
                    picoquic_store_addr(&packet->addr_to, addr_from);
                    packet->if_index_local = if_index_to;
                    packet->received_ecn = received_ecn;
                    buffered = 1;
                }
            }
        }
    }

    return buffered;
}

/*
* Processing of the packet that was just received from the network.
*/

int picoquic_incoming_segment(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t length,
    size_t packet_length,
    size_t* consumed,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time,
    picoquic_connection_id_t* previous_dest_id)
{
    int ret = 0;
    picoquic_cnx_t* cnx = NULL;
    picoquic_packet_header ph;
    int new_context_created = 0;
    int is_first_segment = 0;
    int is_buffered = 0;

    /* Parse the header and decrypt the segment */
    ret = picoquic_parse_header_and_decrypt(quic, bytes, length, packet_length, addr_from,
        current_time, &ph, &cnx, consumed, &new_context_created);

    picoquic_connection_id_t* log_cnxid = (cnx != NULL) ? &cnx->initial_cnxid : &ph.dest_cnx_id;

    /* Verify that the segment coalescing is for the same destination ID */
    if (picoquic_is_connection_id_null(previous_dest_id)) {
        /* This is the first segment in the incoming packet */
        *previous_dest_id = ph.dest_cnx_id;
        is_first_segment = 1;

        /* if needed, log that the packet is received */
        if (quic->F_log != NULL && (cnx == NULL || cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || quic->use_long_log)) {
            picoquic_log_packet_address(quic->F_log,
                picoquic_val64_connection_id((cnx == NULL) ? ph.dest_cnx_id : picoquic_get_logging_cnxid(cnx)),
                cnx, addr_from, 1, packet_length, current_time);
        }
        if (cnx != NULL && cnx->f_binlog != NULL && (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || quic->use_long_log)) {
            binlog_pdu(cnx->f_binlog, log_cnxid, 1, current_time, addr_from, addr_to, packet_length);
        }
    }
    else {
        if (ret == 0 && picoquic_compare_connection_id(previous_dest_id, &ph.dest_cnx_id) != 0) {
            ret = PICOQUIC_ERROR_CNXID_SEGMENT;
        }
    }
    /* Store packet if received in advance of encryption keys */
    if (ret == PICOQUIC_ERROR_AEAD_NOT_READY &&
        cnx != NULL) {
        is_buffered = picoquic_incoming_not_decrypted(cnx, &ph, current_time, bytes, length, addr_from, addr_to, if_index_to, received_ecn);
    }

    /* Log the incoming packet */
    if (quic->F_log != NULL && (cnx == NULL || cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || quic->use_long_log)) {
        picoquic_log_decrypted_segment(quic->F_log, 1, cnx, 1, &ph, bytes, *consumed, ret);
    }
    if (cnx != NULL && cnx->f_binlog != NULL && (quic->use_long_log ||
         cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE)) {
        if (ret == 0) {
            binlog_packet(cnx->f_binlog, log_cnxid, 1, current_time, &ph, bytes, *consumed);
        }
        else if (is_buffered) {
            binlog_buffered_packet(cnx, ph.ptype, current_time);
        } else {
            binlog_dropped_packet(cnx, ph.ptype, length, ret, bytes, current_time);
        }
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
                if (!picoquic_is_connection_id_null(&ph.dest_cnx_id)) {
                    picoquic_process_unexpected_cnxid(quic, length, addr_from, addr_to, if_index_to, &ph);
                }
                ret = PICOQUIC_ERROR_DETECTED;
            }
        }
        else {
            cnx->quic_bit_received_0 |= ph.quic_bit_is_zero;
            switch (ph.ptype) {
            case picoquic_packet_version_negotiation:
                ret = picoquic_incoming_version_negotiation(
                    cnx, bytes, length, addr_from, &ph, current_time);
                break;
            case picoquic_packet_initial:
                /* Initial packet: either crypto handshakes or acks. */
                if ((!cnx->client_mode && picoquic_compare_connection_id(&ph.dest_cnx_id, &cnx->initial_cnxid) == 0) ||
                    picoquic_compare_connection_id(&ph.dest_cnx_id, &cnx->path[0]->p_local_cnxid->cnx_id) == 0) {
                    /* Verify that the source CID matches expectation */
                    if (picoquic_is_connection_id_null(&cnx->path[0]->remote_cnxid)) {
                        cnx->path[0]->remote_cnxid = ph.srce_cnx_id;
                    } else if (picoquic_compare_connection_id(&cnx->path[0]->remote_cnxid, &ph.srce_cnx_id) != 0) {
                        DBG_PRINTF("Error wrong srce cnxid (%d), type: %d, epoch: %d, pc: %d, pn: %d\n",
                            cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn);
                        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
                    }
                    if (ret == 0) {
                        if (cnx->client_mode == 0) {
                            if (is_first_segment) {
                                /* Account for the data received in handshake, but only
                                 * count the packet once. Do not count it again if it is not
                                 * the first segment in packet */
                                cnx->initial_data_received += packet_length;
                            }
                            ret = picoquic_incoming_client_initial(&cnx, bytes, packet_length,
                                addr_from, addr_to, if_index_to, &ph, current_time, new_context_created);
                        }
                        else {
                            /* TODO: this really depends on the current receive epoch */
                            ret = picoquic_incoming_server_initial(cnx, bytes, addr_to, if_index_to, &ph, current_time);
                        }
                    }
                } else {
                    DBG_PRINTF("Error detected (%d), type: %d, epoch: %d, pc: %d, pn: %d\n",
                        cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn);
                    ret = PICOQUIC_ERROR_DETECTED;
                }
                break;
            case picoquic_packet_retry:
                ret = picoquic_incoming_retry(cnx, bytes, &ph, current_time);
                break;
            case picoquic_packet_handshake:
                if (cnx->client_mode)
                {
                    ret = picoquic_incoming_server_handshake(cnx, bytes, addr_to, if_index_to, &ph, current_time);
                }
                else
                {
                    ret = picoquic_incoming_client_handshake(cnx, bytes, &ph, current_time);
                }
                break;
            case picoquic_packet_0rtt_protected:
                if (is_first_segment) {
                    /* Account for the data received in handshake, but only
                     * count the packet once. Do not count it again if it is not
                     * the first segment in packet */
                    cnx->initial_data_received += packet_length;
                }
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
    else if (ret == PICOQUIC_ERROR_AEAD_CHECK &&
        ph.ptype == picoquic_packet_handshake &&
        cnx != NULL &&
        (cnx->cnx_state == picoquic_state_client_init_sent || cnx->cnx_state == picoquic_state_client_init_resent))
    {
        /* Indicates that the server probably sent initial and handshake but initial was lost */
        if (cnx->pkt_ctx[picoquic_packet_context_initial].retransmit_oldest != NULL &&
            cnx->pkt_ctx[picoquic_packet_context_initial].nb_retransmit == 0) {
            /* Reset the retransmit timer to start retransmission immediately */
            cnx->path[0]->retransmit_timer = current_time -
                cnx->pkt_ctx[picoquic_packet_context_initial].retransmit_oldest->send_time;
        }
    }

    if (ret == 0) {
        if (cnx != NULL && cnx->cnx_state != picoquic_state_disconnected &&
            ph.ptype != picoquic_packet_version_negotiation) {
            /* Mark the sequence number as received */
            ret = picoquic_record_pn_received(cnx, ph.pc, ph.pn64, current_time);
            /* Perform ECN accounting */
            picoquic_ecn_accounting(cnx, received_ecn, ph.pc);
        }
        if (cnx != NULL) {
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, current_time);
        }
    } else if (ret == PICOQUIC_ERROR_DUPLICATE) {
        /* Bad packets are dropped silently, but duplicates should be acknowledged */
        if (cnx != NULL) {
            picoquic_set_ack_needed(cnx, current_time, ph.pc);
        }
        ret = -1;
    } else if (ret == PICOQUIC_ERROR_AEAD_CHECK || ret == PICOQUIC_ERROR_INITIAL_TOO_SHORT ||
        ret == PICOQUIC_ERROR_INITIAL_CID_TOO_SHORT ||
        ret == PICOQUIC_ERROR_UNEXPECTED_PACKET || 
        ret == PICOQUIC_ERROR_CNXID_CHECK || 
        ret == PICOQUIC_ERROR_RETRY || ret == PICOQUIC_ERROR_DETECTED ||
        ret == PICOQUIC_ERROR_CONNECTION_DELETED ||
        ret == PICOQUIC_ERROR_CNXID_SEGMENT ||
        ret == PICOQUIC_ERROR_AEAD_NOT_READY) {
        /* Bad packets are dropped silently */

        DBG_PRINTF("Packet (%d) dropped, t: %d, e: %d, pc: %d, pn: %d, l: %zu, ret : 0x%x\n",
            (cnx == NULL) ? -1 : cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn, 
            length, ret);

        if (ret == PICOQUIC_ERROR_AEAD_CHECK || ret == PICOQUIC_ERROR_AEAD_NOT_READY) {
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
        DBG_PRINTF("Packet (%d) get ret=1, t: %d, e: %d, pc: %d, pn: %d, l: %zu\n",
            (cnx == NULL) ? -1 : cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn, length);
        ret = -1;
    }
    else if (ret != 0) {
        DBG_PRINTF("Packet (%d) error, t: %d, e: %d, pc: %d, pn: %d, l: %zu, ret : 0x%x\n",
            (cnx == NULL) ? -1 : cnx->client_mode, ph.ptype, ph.epoch, ph.pc, (int)ph.pn, length, ret);
        ret = -1;
    }

    return ret;
}

int picoquic_incoming_packet(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t packet_length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time)
{
    size_t consumed_index = 0;
    int ret = 0;
    picoquic_connection_id_t previous_destid = picoquic_null_connection_id;


    while (consumed_index < packet_length) {
        size_t consumed = 0;

        ret = picoquic_incoming_segment(quic, bytes + consumed_index, 
            packet_length - consumed_index, packet_length,
            &consumed, addr_from, addr_to, if_index_to, received_ecn, current_time, &previous_destid);

        if (ret == 0) {
            consumed_index += consumed;
            if (consumed == 0) {
                DBG_PRINTF("%s", "Receive bug, ret = 0 && consumed = 0\n");
                break;
            }
        } else {
            ret = 0;
            break;
        }
    }

    return ret;
}

/* Processing of stashed packets after acquiring encryption context */
void picoquic_process_sooner_packets(picoquic_cnx_t* cnx, uint64_t current_time)
{
    picoquic_stateless_packet_t* packet = cnx->first_sooner;
    picoquic_stateless_packet_t* previous = NULL;

    cnx->recycle_sooner_needed = 0;

    while (packet != NULL) {
        picoquic_stateless_packet_t* next_packet = packet->next_packet;
        int could_try_now = 1;
        picoquic_epoch_enum epoch = 0;
        switch (packet->ptype) {
        case picoquic_packet_handshake:
            epoch = picoquic_epoch_handshake;
            break;
        case picoquic_packet_1rtt_protected:
            epoch = picoquic_epoch_1rtt;
            break;
        default:
            could_try_now = 0;
            break;
        }

        if (could_try_now &&
            (cnx->crypto_context[epoch].aead_decrypt != NULL || cnx->crypto_context[epoch].pn_dec != NULL))
        {
            int ret;

            DBG_PRINTF("De-stashing packet type %d, %d bytes", (int)packet->ptype, (int)packet->length);
            ret = picoquic_incoming_packet(cnx->quic, packet->bytes, packet->length,
                (struct sockaddr*) & packet->addr_to, (struct sockaddr*) & packet->addr_local, packet->if_index_local, packet->received_ecn, current_time);

            if (ret != 0) {
                DBG_PRINTF("Processing sooner packet type %d returns %d (0x%d)", (int)packet->ptype, ret, ret);
            }

            if (previous == NULL) {
                cnx->first_sooner = packet->next_packet;
            }
            else {
                previous->next_packet = packet->next_packet;
            }
            picoquic_delete_stateless_packet(packet);
        }
        else {
            previous = packet;
        }

        packet = next_packet;
    }
}