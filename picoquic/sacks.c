#include "picoquic.h"


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

/*
 * Check whether the packet was already received.
 */
int picoquic_is_pn_already_received(picoquic_cnx * cnx, uint64_t pn64)
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

int picoquic_record_pn_received(picoquic_cnx * cnx, uint64_t pn64)
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
    }
    else 
    do
    {
        if (pn64 > sack->end_of_sack_range)
        {
            if (pn64 == sack->end_of_sack_range + 1)
            {
                /* add 1 item at end of range */
                sack->end_of_sack_range = pn64;

                /* if this actually fills the hole, merge with previous item */
                if (previous != NULL && pn64 + 1 >= previous->start_of_sack_range)
                {
                    previous->start_of_sack_range = sack->start_of_sack_range;
                    previous->next_sack = sack->next_sack;
                    free(sack);
                }
                break;
            }
            else if (previous != NULL && pn64 + 1 == previous->start_of_sack_range)
            {
                /* just extend the previous range */
                previous->start_of_sack_range = pn64;
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
                    new_hole->next_sack = sack->next_sack;
                    sack->start_of_sack_range = pn64;
                    sack->end_of_sack_range = pn64;
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
                sack->start_of_sack_range = pn64;
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
                    /* swap old and new, so it works even if previous == NULL */
                    new_hole->start_of_sack_range = pn64;
                    new_hole->end_of_sack_range = pn64;
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
        ret = (uint16_t)((mantissa & 0x07FFLLU) | ((exponent + 1) << 11));
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
