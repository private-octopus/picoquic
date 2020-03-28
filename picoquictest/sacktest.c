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
#include <string.h>

/*
 * Test of the SACK functionality
 */

static const uint64_t test_pn64[] = {
    3, 4, 0, 2, 7, 8, 11, 12, 13, 17, 19, 21, 18, 16, 20, 10, 5, 6, 9, 1, 14, 15
};

static const size_t nb_test_pn64 = sizeof(test_pn64) / sizeof(uint64_t);

struct expected_ack_t {
    uint64_t highest_received;
    uint64_t last_range;
    uint8_t num_blocks;
};

static struct expected_ack_t expected_ack[] = {
    { 3, 0, 0 },
    { 4, 1, 0 },
    { 4, 1, 1 },
    { 4, 2, 1 },
    { 7, 0, 2 },
    { 8, 1, 2 },
    { 11, 0, 3 },
    { 12, 1, 3 },
    { 13, 2, 3 },
    { 17, 0, 4 },
    { 19, 0, 5 },
    { 21, 0, 6 },
    { 21, 0, 5 },
    { 21, 0, 5 },
    { 21, 5, 4 },
    { 21, 5, 4 },
    { 21, 5, 4 },
    { 21, 5, 3 },
    { 21, 5, 2 },
    { 21, 5, 1 },
    { 21, 5, 1 },
    { 21, 21, 0 }
};

int sacktest()
{
    int ret = 0;
    picoquic_cnx_t cnx;
    uint64_t current_time = 0;
    uint64_t highest_seen = 0;
    uint64_t highest_seen_time = 0;
    picoquic_packet_context_enum pc = 0;

    memset(&cnx, 0, sizeof(cnx));
    cnx.pkt_ctx[pc].first_sack_item.start_of_sack_range = (uint64_t)((int64_t)-1);

    /* Do a basic test with packet zero */

    if (picoquic_is_pn_already_received(&cnx, pc, 0) != 0) {
        ret = -1;
    }

    if (picoquic_record_pn_received(&cnx, pc, 0, current_time) != 0) {
        ret = -1;
    }

    if (picoquic_is_pn_already_received(&cnx, pc, 0) == 0) {
        ret = -1;
    }

    if (cnx.pkt_ctx[pc].first_sack_item.start_of_sack_range != 0 ||
        cnx.pkt_ctx[pc].first_sack_item.end_of_sack_range != 0 ||
        cnx.pkt_ctx[pc].first_sack_item.next_sack != NULL) {
        ret = -1;
    }
    else {
        /* reset for the next test */
        memset(&cnx, 0, sizeof(cnx));
        cnx.pkt_ctx[pc].first_sack_item.start_of_sack_range = (uint64_t)((int64_t)-1);
    }

    for (size_t i = 0; ret == 0 && i < nb_test_pn64; i++) {
        current_time = i * 100 + 1;

        if (test_pn64[i] > highest_seen) {
            highest_seen = test_pn64[i];
            highest_seen_time = current_time;
        }

        if (picoquic_record_pn_received(&cnx, pc, test_pn64[i], current_time) != 0) {
            ret = -1;
        }

        for (size_t j = 0; ret == 0 && j <= i; j++) {
            if (picoquic_is_pn_already_received(&cnx, pc, test_pn64[j]) == 0) {
                ret = -1;
            }

            if (picoquic_record_pn_received(&cnx, pc, test_pn64[j], current_time) != 1) {
                ret = -1;
            }
        }

        for (size_t j = i + 1; ret == 0 && j < nb_test_pn64; j++) {
            if (picoquic_is_pn_already_received(&cnx, pc, test_pn64[j]) != 0) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        if (cnx.pkt_ctx[pc].first_sack_item.end_of_sack_range != 21 || 
            cnx.pkt_ctx[pc].first_sack_item.start_of_sack_range != 0 || 
            cnx.pkt_ctx[pc].time_stamp_largest_received != highest_seen_time ||
            cnx.pkt_ctx[pc].first_sack_item.next_sack != NULL) {
            ret = -1;
        }
    }

    /* Reset the sack lists*/
    while (cnx.pkt_ctx[pc].first_sack_item.next_sack != NULL) {
        picoquic_sack_item_t * next = cnx.pkt_ctx[pc].first_sack_item.next_sack;
        cnx.pkt_ctx[pc].first_sack_item.next_sack = next->next_sack;
        free(next);
    }

    return ret;
}

static void ack_range_mask(uint64_t* mask, uint64_t highest, uint64_t range)
{
    for (uint64_t i = 0; i < range; i++) {
        *mask |= 1ull << (highest & 63);
        highest--;
    }
}

static int basic_ack_parse(uint8_t* bytes, size_t bytes_max,
    struct expected_ack_t* expected_ack, uint64_t expected_mask)
{
    int ret = 0;
    size_t byte_index = 1;
    uint8_t first_byte = bytes[0];
    uint64_t num_block = 0;
    uint64_t largest = 0;
    uint64_t last_range = 0;
    uint64_t ack_range = 0;
    uint64_t acked_mask = 0;
    uint64_t gap_begin = 0;
    size_t l_largest = 0;
    size_t l_delay = 0;
    size_t l_num_block = 0;
    size_t l_last_range = 0;

    if (first_byte != picoquic_frame_type_ack) {
        ret = -1;
    } else {
        /* Largest */
        if (byte_index < bytes_max) {
            l_largest = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &largest);
            byte_index += l_largest;
        }

        /* ACK delay */
        if (byte_index < bytes_max) {
            l_delay = picoquic_varint_skip(bytes + byte_index);
            byte_index += l_delay;
        }

        /* Num blocks */
        if (byte_index < bytes_max) {
            l_num_block = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &num_block);
            byte_index += l_num_block;
        }

        /* last range */
        if (byte_index < bytes_max) {
            l_last_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &last_range);
            byte_index += l_last_range;
        }

        if (l_largest == 0 || l_delay == 0 || l_num_block == 0 || l_last_range == 0 || byte_index > bytes_max) {
            ret = -1;
        } else {
            if (last_range <= largest) {
                ack_range_mask(&acked_mask, largest, last_range + 1);
                gap_begin = largest - last_range - 1;
            } else {
                ret = -1;
            }

            for (int i = 0; ret == 0 && i < num_block; i++) {
                size_t l_gap = 0;
                size_t l_range = 0;
                uint64_t gap;

                /* Decode the gap */
                if (byte_index < bytes_max) {
                    l_gap = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &gap);
                    byte_index += l_gap;
                    gap += 1;
                }
                /* decode the range */
                if (byte_index < bytes_max) {
                    l_range = picoquic_varint_decode(bytes + byte_index, bytes_max - byte_index, &ack_range);
                    byte_index += l_range;
                }
                if (l_gap == 0 || l_range == 0) {
                    ret = -1;
                } else if (gap > gap_begin) {
                    ret = -1;
                } else {
                    gap_begin -= gap;

                    if (gap_begin >= ack_range) {
                        /* mark the range as received */
                        ack_range_mask(&acked_mask, gap_begin, ++ack_range);

                        /* start of next gap */
                        gap_begin -= ack_range;
                    } else {
                        ret = -1;
                    }
                }
            }
        }

        if (ret == 0) {
            if (byte_index != bytes_max) {
                ret = -1;
            }
        }

        if (ret == 0) {
            if (largest != expected_ack->highest_received || last_range != expected_ack->last_range || num_block != expected_ack->num_blocks) {
                ret = -1;
            }
        }

        if (ret == 0) {
            if (acked_mask != expected_mask) {
                ret = -1;
            }
        }
    }

    return ret;
}

int sendacktest()
{
    int ret = 0;
    picoquic_cnx_t cnx;
    uint64_t current_time;
    uint64_t received_mask = 0;
    uint8_t bytes[256];
    picoquic_packet_context_enum pc = 0;

    memset(&cnx, 0, sizeof(cnx));
    cnx.pkt_ctx[pc].first_sack_item.start_of_sack_range = (uint64_t)((int64_t)-1);
    cnx.sending_ecn_ack = 0; /* don't write an ack_ecn frame */

    for (size_t i = 0; ret == 0 && i < nb_test_pn64; i++) {
        current_time = i * 100;

        if (picoquic_record_pn_received(&cnx, pc, test_pn64[i], current_time) != 0) {
            ret = -1;
        }

        if (ret == 0) {
            int more_data = 0;
            uint8_t* bytes_next = picoquic_format_ack_frame(&cnx, bytes, bytes + sizeof(bytes), &more_data, 0, pc);

            received_mask |= 1ull << (test_pn64[i] & 63);

            if (ret == 0) {
                ret = basic_ack_parse(bytes, bytes_next - bytes, &expected_ack[i], received_mask);
            }

            if (ret != 0) {
                ret = -1; /* useless code, but helps with checkpointing */
            }
        }
    }

    return ret;
}

typedef struct st_test_ack_range_t {
    uint64_t range_min;
    uint64_t range_max;
} test_ack_range_t;

static const test_ack_range_t ack_range[] = {
    { 1, 1000 },
    { 0, 0 },
    { 3001, 4000 },
    { 4001, 5000 },
    { 6001, 7000 },
    { 5001, 6000 },
    { 1501, 2500 },
    { 501, 1500 },
    { 501, 7500 }
};

static const size_t nb_ack_range = sizeof(ack_range) / sizeof(test_ack_range_t);

int ackrange_test()
{
    int ret = 0;
    picoquic_sack_item_t sack0;

    memset(&sack0, 0, sizeof(picoquic_sack_item_t));
    sack0.start_of_sack_range = (uint64_t)((int64_t)-1);

    for (size_t i = 0; i < nb_ack_range; i++) {
        ret = picoquic_check_sack_list(&sack0,
            ack_range[i].range_min, ack_range[i].range_max);

        if (ret == 0) {
            ret = picoquic_update_sack_list(&sack0,
                ack_range[i].range_min, ack_range[i].range_max);
        }

        for (size_t j = 0; j < i; j++) {
            if (picoquic_check_sack_list(&sack0,
                    ack_range[j].range_min, ack_range[j].range_max)
                == 0) {
                ret = -1;
                break;
            }
        }

        if (ret != 0) {
            break;
        }
    }

    if (ret == 0 && sack0.start_of_sack_range != 0) {
        ret = -1;
    }

    if (ret == 0 && sack0.end_of_sack_range != 7500) {
        ret = -1;
    }

    if (ret == 0 && sack0.next_sack != NULL) {
        ret = -1;
    }

    return ret;
}
