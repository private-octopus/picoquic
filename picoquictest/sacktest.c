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

#include <stdlib.h>
#include <string.h>
#include <stdlib.h>
#include "../picoquic/picoquic_internal.h"

/*
 * Test of the SACK functionality
 */

static const uint64_t test_pn64[] = {
    3, 4, 2, 7, 8, 11, 12, 13, 17, 19, 21, 18, 16, 20, 10, 5, 6, 9, 1, 14, 15
};

static const size_t nb_test_pn64 = sizeof(test_pn64) / sizeof(uint64_t);

struct expected_ack_t
{
	uint64_t highest_received;
	uint64_t last_range;
	uint8_t num_blocks;
};

static struct expected_ack_t expected_ack[] =
{
	{3, 0, 0},
	{4, 1, 0},
	{4, 2, 0},
	{7, 0, 1},
	{8, 1, 1},
	{11, 0, 2},
	{ 12, 1, 2 },
	{ 13, 2, 2 },
	{ 17, 0, 3 },
	{19, 0, 4},
	{21, 0, 5},
	{21, 0, 4},
	{21, 0, 4},
	{21, 5, 3},
	{21, 5, 3},
	{ 21, 5, 3 },
	{21, 5, 2},
	{21, 5, 1},
	{ 21, 5, 1 },
	{ 21, 5, 1 },
	{ 21, 20, 0 }
};

int sacktest()
{
    int ret = 0;
    picoquic_cnx_t cnx;
    uint64_t current_time;
    uint64_t highest_seen = 0;
    uint64_t highest_seen_time = 0;

    memset(&cnx, 0, sizeof(cnx));

    for (size_t i = 0; ret == 0 && i < nb_test_pn64; i++)
    {
        current_time = i * 100;

        if (test_pn64[i] > highest_seen)
        {
            highest_seen = test_pn64[i];
            highest_seen_time = current_time;
        }

        if (picoquic_record_pn_received(&cnx, test_pn64[i], current_time) != 0)
        {
            ret = -1;
        }

        for (size_t j = 0; ret == 0 && j <= i; j++)
        {
            if (picoquic_is_pn_already_received(&cnx, test_pn64[j]) == 0)
            {
                ret = -1;
            }

            if (picoquic_record_pn_received(&cnx, test_pn64[j], current_time) != 1)
            {
                ret = -1;
            }
        }

        for (size_t j = i+1; ret == 0 && j < nb_test_pn64; j++)
        {
            if (picoquic_is_pn_already_received(&cnx, test_pn64[j]) != 0)
            {
                ret = -1;
            }
        }
    }

    if (ret == 0)
    {
        if (cnx.first_sack_item.end_of_sack_range != 21 ||
            cnx.first_sack_item.start_of_sack_range != 1 ||
            cnx.time_stamp_largest_received != highest_seen_time ||
            cnx.first_sack_item.next_sack != NULL)
        {
            ret = -1;
        }
    }

    return ret;
}

static void ack_range_mask(uint64_t * mask, uint64_t highest, uint64_t range)
{
	for (uint64_t i = 0; i < range; i++)
	{
		*mask |= 1ull << (highest & 63);
		highest--;
	}
}

static int basic_ack_parse(uint8_t * bytes, size_t bytes_max,
	struct expected_ack_t * expected_ack, uint64_t expected_mask,
    uint32_t version_flags)
{
	int ret = 0;
	size_t byte_index = 1;
	uint8_t first_byte = bytes[0];
	int has_num_block = (first_byte >> 4) & 1;
	int num_block = 0;
	int num_ts;
	int ll = (first_byte >> 2) & 3;
	int mm = (first_byte & 3);
	uint64_t largest;
	uint64_t last_range;
	uint64_t ack_range;
	uint64_t acked_mask = 0;
	uint64_t gap_begin;

	if (first_byte < 0xA0 || first_byte > 0xBF)
	{
		ret = -1;
	}
	else
	{
		if (has_num_block)
		{
			num_block = bytes[byte_index++];
		}

        if ((version_flags&picoquic_version_basic_time_stamp) != 0)
        {
            num_ts = bytes[byte_index++];
        }
        else
        {
            num_ts = 0;
        }

		/* decoding the largest */
		switch (ll)
		{
		case 0:
			largest = bytes[byte_index++];
			break;
		case 1:
			largest = PICOPARSE_16(bytes + byte_index);
			byte_index += 2;
			break;
		case 2:
			largest = PICOPARSE_32(bytes + byte_index);
			byte_index += 4;
			break;
		case 3:
			largest = PICOPARSE_64(bytes + byte_index);
			byte_index += 8;
			break;
		}
		/* ACK delay */
		byte_index += 2;

		/* last range */
		switch (mm)
		{
		case 0:
			last_range = bytes[byte_index++];
			break;
		case 1:
			last_range = PICOPARSE_16(bytes + byte_index);
			byte_index += 2;
			break;
		case 2:
			last_range = PICOPARSE_32(bytes + byte_index);
			byte_index += 4;
			break;
		case 3:
			last_range = PICOPARSE_64(bytes + byte_index);
			byte_index += 8;
			break;
		}

		if (last_range < largest)
		{
			ack_range_mask(&acked_mask, largest, last_range + 1);
			gap_begin = largest - last_range - 1;
		}
		else
		{
			ret = -1;
		}

		for (int i = 0; ret == 0 && i < num_block; i++)
		{
			/* Skip the gap */
			if (gap_begin < bytes[byte_index])
			{
				ret = -1;
			}
			else
			{
				gap_begin -= bytes[byte_index++];

				switch (mm)
				{
				case 0:
					ack_range = bytes[byte_index++];
					byte_index += 1;
					break;
				case 1:
					ack_range = PICOPARSE_16(bytes + byte_index);
					byte_index += 2;
					break;
				case 2:
					ack_range = PICOPARSE_32(bytes + byte_index);
					byte_index += 4;
					break;
				case 3:
					ack_range = PICOPARSE_64(bytes + byte_index);
					byte_index += 8;
					break;
				}

				if (gap_begin >= ack_range)
				{
					/* mark the range as received */
					ack_range_mask(&acked_mask, gap_begin, ack_range);

					/* start of next gap */
					gap_begin -= ack_range;
				}
				else
				{
					ret = -1;
				}
			}
		}

		if (ret == 0)
		{
			byte_index += num_ts * 3;

			if (byte_index != bytes_max)
			{
				ret = -1;
			}
		}

		if (ret == 0)
		{
			if (largest != expected_ack->highest_received ||
				last_range != expected_ack->last_range ||
				num_block != expected_ack->num_blocks)
			{
				ret = -1;
			}
		}

		if (ret == 0)
		{
			if (acked_mask != expected_mask)
			{
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
	size_t consumed;

	memset(&cnx, 0, sizeof(cnx));

	for (size_t i = 0; ret == 0 && i < nb_test_pn64; i++)
	{
		current_time = i * 100;

		if (picoquic_record_pn_received(&cnx, test_pn64[i], current_time) != 0)
		{
			ret = -1;
		}

		if (ret == 0)
		{
			consumed = 0;
			ret = picoquic_prepare_ack_frame(&cnx, 0, bytes, sizeof(bytes), &consumed);

			received_mask |= 1ull << (test_pn64[i] & 63);

			if (ret == 0)
			{
				ret = basic_ack_parse(bytes, consumed, &expected_ack[i], received_mask,
                    picoquic_supported_versions[cnx.version_index].version_flags);
			}
		}
	}

	return ret;
}

typedef struct st_test_ack_range_t
{
    uint64_t range_min;
    uint64_t range_max;
} test_ack_range_t;

static const test_ack_range_t ack_range[] = {
    { 0, 1000 },
    { 3001, 4000},
    { 4001, 5000},
    { 6001, 7000},
    { 5001, 6000},
    { 1501, 2500},
    { 501, 1500},
    { 501, 7500}
};

static const size_t nb_ack_range = sizeof(ack_range) / sizeof(test_ack_range_t);

int ackrange_test()
{
    int ret = 0;
    picoquic_sack_item_t sack0;
    uint64_t blockmax = 0;

    memset(&sack0, 0, sizeof(picoquic_sack_item_t));

    for (size_t i = 0; i < nb_ack_range; i++)
    {
        ret = picoquic_check_sack_list(&sack0,
            ack_range[i].range_min, ack_range[i].range_max);

        if (ret == 0)
        {
            ret = picoquic_update_sack_list(&sack0,
                ack_range[i].range_min, ack_range[i].range_max, &blockmax);
        }

        for (size_t j = 0; j < i; j++)
        {
            if (picoquic_check_sack_list(&sack0,
                ack_range[j].range_min, ack_range[j].range_max) == 0)
            {
                ret = -1;
                break;
            }
        }

        if (ret != 0)
        {
            break;
        }
    }

    if (ret == 0 && blockmax != 7500)
    {
        ret = -1;
    }

    if (ret == 0 && sack0.start_of_sack_range != 0)
    {
        ret = -1;
    }

    if (ret == 0 && sack0.end_of_sack_range != 7500)
    {
        ret = -1;
    }

    if (ret == 0 && sack0.next_sack != NULL)
    {
        ret = -1;
    }

    return ret;
}