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

#include "picoquic_internal.h"


/*
* Packet sequence recording prepares the next ACK:
*
* Maintain largest acknowledged number & the timestamp of that
* arrival used to calculate the ACK delay.
*
* Maintain the lis of ACK
*/

/*
 * Check whether the packet was already received.
 */
int picoquic_is_pn_already_received(picoquic_cnx_t * cnx, uint64_t pn64)
{
    int is_received = 0;
    picoquic_sack_item * sack = &cnx->first_sack_item;

    do
    {
        if (pn64 > sack->end_of_sack_range)
            break;
        else if (pn64 >= sack->start_of_sack_range)
        {
            is_received = 1;
            break;
        }
        else
        {
            sack = sack->next_sack;
        }
    } while (sack != NULL);

    return is_received;
}

/*
 * Packet was already received and checksum, etc. was properly verified.
 * Record it in the chain.
 */

int picoquic_record_pn_received(picoquic_cnx_t * cnx, uint64_t pn64, uint64_t current_microsec)
{
    int ret = 0;
    picoquic_sack_item * sack = &cnx->first_sack_item;
    picoquic_sack_item * previous = NULL;

    if (sack->start_of_sack_range == 0 &&
        sack->end_of_sack_range == 0)
    {
        /* This is the first packet ever received.. */
        sack->start_of_sack_range = pn64;
        sack->end_of_sack_range = pn64;
        sack->time_stamp_last_in_range = current_microsec;
        cnx->sack_block_size_max = 1;
    }
    else 
    do
    {
        if (pn64 > sack->end_of_sack_range)
        {
            if (pn64 == sack->end_of_sack_range + 1)
            {
                /* if this actually fills the hole, merge with previous item */
                if (previous != NULL && pn64 + 1 >= previous->start_of_sack_range)
                {
                    uint64_t block_size;
                    previous->start_of_sack_range = sack->start_of_sack_range;
                    previous->next_sack = sack->next_sack;
                    block_size = previous->end_of_sack_range - previous->start_of_sack_range;
                    if (block_size > cnx->sack_block_size_max)
                    {
                        cnx->sack_block_size_max = block_size;
                    }
                    free(sack);
                }
                else
                {
                    /* add 1 item at end of range */
                    sack->end_of_sack_range = pn64;
                    sack->time_stamp_last_in_range = current_microsec;
                }
                break;
            }
            else if (previous != NULL && pn64 + 1 == previous->start_of_sack_range)
            {
                uint64_t block_size;
                /* just extend the previous range */
                previous->start_of_sack_range = pn64;
                block_size = previous->end_of_sack_range - previous->start_of_sack_range;
                if (block_size > cnx->sack_block_size_max)
                {
                    cnx->sack_block_size_max = block_size;
                }
            }
            else
            {
                /* Found a new hole */
                picoquic_sack_item * new_hole = (picoquic_sack_item *)malloc(sizeof(picoquic_sack_item));
                if (new_hole == NULL)
                {
                    /* memory error. That's infortunate */
                    ret = -1;
                }
                else
                {
                    /* swap old and new, so it works even if previous == NULL */
                    new_hole->start_of_sack_range = sack->start_of_sack_range;
                    new_hole->end_of_sack_range = sack->end_of_sack_range;
                    new_hole->time_stamp_last_in_range = sack->time_stamp_last_in_range;
                    new_hole->next_sack = sack->next_sack;
                    sack->start_of_sack_range = pn64;
                    sack->end_of_sack_range = pn64;
                    sack->time_stamp_last_in_range = current_microsec;
                    sack->next_sack = new_hole;
                }
            }
            break;
        }
        else if (pn64 >= sack->start_of_sack_range)
        {
            /* packet was already received */
            ret = 1;
            break;
        }
        else if (sack->next_sack == NULL)
        {
            if (pn64 + 1 == sack->start_of_sack_range)
            {
                uint64_t block_size;
                sack->start_of_sack_range = pn64;
                block_size = sack->end_of_sack_range - sack->start_of_sack_range;
                if (block_size > cnx->sack_block_size_max)
                {
                    cnx->sack_block_size_max = block_size;
                }
            }
            else
            {
                /* this is an old packet, beyond the current range of SACK */
                /* Found a new hole */
                picoquic_sack_item * new_hole = (picoquic_sack_item *)malloc(sizeof(picoquic_sack_item));
                if (new_hole == NULL)
                {
                    /* memory error. That's infortunate */
                    ret = -1;
                }
                else
                {
                    /* Create new hole at the tail. */
                    new_hole->start_of_sack_range = pn64;
                    new_hole->end_of_sack_range = pn64;
                    new_hole->time_stamp_last_in_range = current_microsec;
                    new_hole->next_sack = NULL;
                    sack->next_sack = new_hole;
                }
            }
            break;
        }
        else
        {
            previous = sack;
            sack = sack->next_sack;
        }
    } while (sack != NULL);

    return ret;
}

/*
 * Manage the received ACK.
 * This is expressed as a series of SACK blocks, of the form "last acknowledged, size"
 */

int picoquic_record_sack(picoquic_cnx_t * cnx, uint64_t pn64, uint64_t block_size)
{
    return -1;
}


/*
 * Float16 format required for encoding the time deltas in current QUIC draft.
 *
 * The time format used in the ACK frame above is a 16-bit unsigned float with 
 * 11 explicit bits of mantissa and 5 bits of explicit exponent, specifying time 
 * in microseconds. The bit format is loosely modeled after IEEE 754. For example,
 * 1 microsecond is represented as 0x1, which has an exponent of zero, presented 
 * in the 5 high order bits, and mantissa of 1, presented in the 11 low order bits.
 * When the explicit exponent is greater than zero, an implicit high-order 12th bit
 * of 1 is assumed in the mantissa. For example, a floating value of 0x800 has an 
 * explicit exponent of 1, as well as an explicit mantissa of 0, but then has an
 * effective mantissa of 4096 (12th bit is assumed to be 1). Additionally, the actual
 * exponent is one-less than the explicit exponent, and the value represents 4096 
 * microseconds. Any values larger than the representable range are clamped to 0xFFFF.
 */

uint16_t picoquic_deltat_to_float16(uint64_t delta_t)
{
    uint16_t ret;
    uint64_t exponent = 0;
    uint64_t mantissa = delta_t;

    while (mantissa > 0x0FFFLLU)
    {
        exponent++;
        mantissa >>= 1;
    }

    if (exponent > 30)
    {
        ret = 0xFFFF;
    }
    else if (mantissa & 0x0800LLU)
    {
        ret = (uint16_t)((mantissa & 0x07FFLLU) | ((exponent+1) << 11));
    }
    else
    {
        ret = (uint16_t)(mantissa);
    }

    return ret;
}

uint64_t picoquic_float16_to_deltat(uint16_t float16)
{
    int exponent = float16 >> 11;
    uint64_t ret = (float16 & 0x07FF);

    if (exponent != 0)
    {
        ret |= (0x0800);
        ret <<= (exponent - 1);
    }
    return ret;
}

/*
 * Encoding an ACK frame from the SACK list

 The type byte for a ACK frame contains embedded flags, 
 and is formatted as 101NLLMM. These bits are parsed as follows:

  * The first three bits must be set to 101 indicating that this is an ACK frame.

  * The N bit indicates whether the frame contains a Num Blocks field.

  * The two LL bits encode the length of the Largest Acknowledged field. 
    The values 00, 01, 02, and 03 indicate lengths of 8, 16, 32, and 
    64 bits respectively.

  * The two MM bits encode the length of the ACK Block Length fields. The values 
    00, 01, 02, and 03 indicate lengths of 8, 16, 32, and 64 bits respectively.

 
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

int picoquic_encode_sack_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
    size_t bytes_max, size_t * nb_bytes, uint64_t current_time)
{
    int ret = -1;
    size_t nb_blocks = 0;
    picoquic_sack_item * previous_sack = &cnx->first_sack_item;
    picoquic_sack_item * sack = cnx->first_sack_item.next_sack;
    uint64_t block_size;
    uint8_t ack_type = 0xA8;
    uint8_t mm = 0;
    int length_mm = 1;
    size_t byte_index = 0;

    if (cnx->sack_block_size_max < 0xFFFF)
    {
        if (cnx->sack_block_size_max > 0xFF)
        {
            mm = 1;
            length_mm = 2;
        }
    }
    else if (cnx->sack_block_size_max <= 0xFFFFFFFF)
    {
        mm = 2;
        length_mm = 4;
    }
    else
    {
        mm = 3;
        length_mm = 8;
    }

    if (bytes_max < 1u + 2u + 4u + 2u + length_mm)
    {
        *nb_bytes = 0;
        ret = -1;
    }
    else
    {
        ack_type |= mm;
        bytes[byte_index++] = ack_type;

        if (sack != NULL)
        {
            /* reserve space for encoding the nb_blocks and nb_time_stamps later */
            byte_index += 2;
        }
        /*
         * Encode the max received.
         */
        picoformat_32(bytes + byte_index, (uint32_t)cnx->first_sack_item.end_of_sack_range);
        byte_index += 4;
        /*
         * Encode the ack delay
         */
        picoformat_16(bytes + byte_index, picoquic_deltat_to_float16(
            current_time - cnx->first_sack_item.time_stamp_last_in_range));
        byte_index += 4;
        /*
         * From the spec:
         * 0                   1                   2                   3
         * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |              First ACK Block Length (8/16/32/64)            ...
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |  [Gap 1 (8)]  |       [ACK Block 1 Length (8/16/32/64)]     ...
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |  [Gap 2 (8)]  |       [ACK Block 2 Length (8/16/32/64)]     ...
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * ...
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * |  [Gap N (8)]  |       [ACK Block N Length (8/16/32/64)]     ...
         * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
         * Notice the 'reverse order" of blocks
         */
         /* Encode first ACK block length */
        block_size = cnx->first_sack_item.end_of_sack_range - cnx->first_sack_item.start_of_sack_range;
        switch (mm)
        {
        case 0:
            bytes[byte_index] = (uint8_t)block_size;
            break;
        case 1:
            picoformat_16(bytes + byte_index, (uint16_t)block_size);
            break;
        case 2:
            picoformat_32(bytes + byte_index, (uint32_t)block_size);
            break;
        case 3:
            picoformat_64(bytes + byte_index, block_size);
            break;
        default:
            break;
        }
        byte_index += length_mm;

        /* Encode each block */
        while (sack != NULL && nb_blocks < 255)
        {
            uint64_t gap = previous_sack->start_of_sack_range - sack->end_of_sack_range - 1;
            uint32_t blocks_needed = (uint32_t)((gap + 254) / 255);

            block_size = sack->end_of_sack_range - sack->start_of_sack_range;
            if (nb_blocks + blocks_needed > 255 ||
                (byte_index + blocks_needed*(1 + length_mm)) > bytes_max)
            {
                break;
            }

            while (gap > 255)
            {
                /* Encode a null block */
                bytes[byte_index++] = 255;
                for (int i = 0; i < length_mm; i++)
                {
                    bytes[byte_index++] = 0;
                }
                gap -= 255;
            }
            bytes[byte_index++] = (uint8_t) gap;
            switch (mm)
            {
            case 0:
                bytes[byte_index] = (uint8_t)block_size;
                break;
            case 1:
                picoformat_16(bytes + byte_index, (uint16_t)block_size);
                break;
            case 2:
                picoformat_32(bytes + byte_index, (uint32_t)block_size);
                break;
            case 3:
                picoformat_64(bytes + byte_index, block_size);
                break;
            default:
                break;
            }
            byte_index += length_mm;
            nb_blocks += blocks_needed;
            previous_sack = sack;
            sack = sack->next_sack;
        }

        /*
         * encode the time stamps: we never send a list in this version of the code.
         * to do: consider the last received? Would be a way to help RTT computation
         * and evaluation of out of order deliveries.
         */

        if (cnx->first_sack_item.next_sack != NULL)
        {
            bytes[1] = (uint8_t)nb_blocks;
            bytes[2] = 0;
        }

        *nb_bytes = byte_index;
    }
    return ret;
}

int picoquic_decode_sack_frame(picoquic_cnx_t * cnx, uint8_t * bytes,
    size_t bytes_max, size_t * nb_bytes, uint64_t current_time)
{
    return -1;
}