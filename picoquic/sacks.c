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
#include <stdlib.h>

/*
* Packet sequence recording prepares the next ACK:
*
* Maintain largest acknowledged number & the timestamp of that
* arrival used to calculate the ACK delay.
*
* Maintain the list of ACK
*/

/*
 * Check whether the packet was already received.
 */
int picoquic_is_pn_already_received(picoquic_cnx_t* cnx, 
    picoquic_packet_context_enum pc, uint64_t pn64)
{
    int is_received = 0;
    picoquic_sack_item_t* sack = &cnx->pkt_ctx[pc].first_sack_item;

    if (sack->start_of_sack_range != (uint64_t)((int64_t)-1)) {
        do {
            if (pn64 > sack->end_of_sack_range)
                break;
            else if (pn64 >= sack->start_of_sack_range) {
                is_received = 1;
                break;
            }
            else {
                sack = sack->next_sack;
            }
        } while (sack != NULL);
    }

    return is_received;
}

/*
 * Packet was already received and checksum, etc. was properly verified.
 * Record it in the chain.
 */

int picoquic_update_sack_list(picoquic_sack_item_t* sack,
    uint64_t pn64_min, uint64_t pn64_max)
{
    int ret = 1; /* duplicate by default, reset to 0 if update found */
    picoquic_sack_item_t* previous = NULL;

    if (sack->start_of_sack_range == (uint64_t)((int64_t)-1)) {
        /* This is the first packet ever received.. */
        sack->start_of_sack_range = pn64_min;
        sack->end_of_sack_range = pn64_max;
        ret = 0;
    } else {
        do {
            if (pn64_max > sack->end_of_sack_range) {
                ret = 0;

                if (pn64_min <= sack->end_of_sack_range + 1) {
                    /* if this actually fills the hole, merge with previous item */
                    if (previous != NULL && pn64_max + 1 >= previous->start_of_sack_range) {
                        previous->start_of_sack_range = sack->start_of_sack_range;
                        previous->next_sack = sack->next_sack;
                        free(sack);
                        sack = previous;
                    } else {
                        /* add at end of range */
                        sack->end_of_sack_range = pn64_max;
                    }

                    /* Check whether there is a need to continue */
                    if (pn64_min >= sack->start_of_sack_range) {
                        break;
                    } else if (sack->next_sack == NULL) {
                        /* Last in range. Just expand. */
                        sack->start_of_sack_range = pn64_min;
                        break;
                    } else {
                        /* Continue with reminder of range */
                        pn64_max = sack->start_of_sack_range - 1;
                        previous = sack;
                        sack = sack->next_sack;
                    }
                } else if (previous != NULL && pn64_max + 1 >= previous->start_of_sack_range) {
                    /* Extend the previous range */
                    previous->start_of_sack_range = pn64_min;
                    break;
                } else {
                    /* Found a new hole */
                    picoquic_sack_item_t* new_hole = (picoquic_sack_item_t*)malloc(sizeof(picoquic_sack_item_t));
                    if (new_hole == NULL) {
                        /* memory error. That's infortunate */
                        ret = -1;
                    } else {
                        /* swap old and new, so it works even if previous == NULL */
                        new_hole->start_of_sack_range = sack->start_of_sack_range;
                        new_hole->end_of_sack_range = sack->end_of_sack_range;
                        new_hole->next_sack = sack->next_sack;
                        sack->start_of_sack_range = pn64_min;
                        sack->end_of_sack_range = pn64_max;
                        sack->next_sack = new_hole;
                    }
                    /* No need to continue, everything is consumed. */
                    break;
                }
            } else if (pn64_max >= sack->start_of_sack_range) {
                if (pn64_min < sack->start_of_sack_range) {
                    ret = 0;

                    if (sack->next_sack == NULL) {
                        /* Just extend the last range */
                        sack->start_of_sack_range = pn64_min;
                        break;
                    } else {
                        /* continue with reminder. */
                        pn64_max = sack->start_of_sack_range - 1;
                        previous = sack;
                        sack = sack->next_sack;
                    }
                } else {
                    /*comple overlap */
                    break;
                }
            } else if (sack->next_sack == NULL) {
                ret = 0;
                if (pn64_max + 1 == sack->start_of_sack_range) {
                    sack->start_of_sack_range = pn64_min;
                } else {
                    /* this is an old packet, beyond the current range of SACK */
                    /* Found a new hole */
                    picoquic_sack_item_t* new_hole = (picoquic_sack_item_t*)malloc(sizeof(picoquic_sack_item_t));
                    if (new_hole == NULL) {
                        /* memory error. That's infortunate */
                        ret = -1;
                    } else {
                        /* Create new hole at the tail. */
                        new_hole->start_of_sack_range = pn64_min;
                        new_hole->end_of_sack_range = pn64_max;
                        new_hole->next_sack = NULL;
                        sack->next_sack = new_hole;
                    }
                }
                break;
            } else {
                previous = sack;
                sack = sack->next_sack;
            }
        } while (sack != NULL);
    }

    return ret;
}

int picoquic_record_pn_received(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc, uint64_t pn64,
    uint64_t current_microsec)
{
    int ret = 0;
    picoquic_sack_item_t* sack = &cnx->pkt_ctx[pc].first_sack_item;

    if (sack->start_of_sack_range == (uint64_t)((int64_t)-1)) {
        /* This is the first packet ever received.. */
        sack->start_of_sack_range = pn64;
        sack->end_of_sack_range = pn64;
        cnx->pkt_ctx[pc].time_stamp_largest_received = current_microsec;
    } 
    else {
        if (pn64 > sack->end_of_sack_range) {
            cnx->pkt_ctx[pc].time_stamp_largest_received = current_microsec;
        }

        ret = picoquic_update_sack_list(sack, pn64, pn64);
    }

    return ret;
}

/*
 * Check whether the data fills a hole. returns 0 if it does, -1 otherwise.
 */
int picoquic_check_sack_list(picoquic_sack_item_t* sack,
    uint64_t pn64_min, uint64_t pn64_max)
{
    int ret = -1; /* duplicate by default, reset to 0 if update found */

    if (sack->start_of_sack_range == (uint64_t)((int64_t)-1)) {
        ret = 0;
    } else {
        for(;;) {
            if (pn64_max > sack->end_of_sack_range) {
                ret = 0;
                break;
            } else if (pn64_max >= sack->start_of_sack_range) {
                if (pn64_min < sack->start_of_sack_range) {
                    ret = 0;
                } else {
                    /*complete overlap */
                    ret = -1;
                }
                break;
            } else if (sack->next_sack == NULL) {
                ret = 0;
                break;
            } else {
                sack = sack->next_sack;
            }
        };
    }

    return ret;
}
