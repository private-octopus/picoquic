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
                    previous->next_sack = sack;
                    free(sack);
                }
                break;
            }
            else
            {
                if (previous != NULL && pn64 + 1 >= previous->start_of_sack_range)
                {
                    /* just extend the previous range */
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
            }
        }
        else if (pn64 >= sack->start_of_sack_range)
        {
            /* packet was already received */
            break;
        }
        else if (sack->next_sack == NULL)
        {
            /* this is an old packet, beyond the current range of SACK */
            /* TODO: manage "old and forgettable" test */
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
        else
        {
            sack = sack->next_sack;
        }
    } while (sack != NULL);

    return ret;
}
