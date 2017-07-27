#include <stdlib.h>
#include <string.h>
#include "../picoquic/picoquic.h"

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
    picoquic_cnx cnx;
    uint64_t current_time;
    uint64_t highest_seen = 0;
    uint64_t highest_seen_time;

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
            cnx.first_sack_item.time_stamp_last_in_range != highest_seen_time ||
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
	struct expected_ack_t * expected_ack, uint64_t expected_mask)
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
		num_ts = bytes[byte_index++];

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
			byte_index += 1;
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
	picoquic_cnx cnx;
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
				ret = basic_ack_parse(bytes, consumed, &expected_ack[i], received_mask);
			}
		}
	}

	return ret;
}