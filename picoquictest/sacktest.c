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

        for (int j = i+1; ret == 0 && j < nb_test_pn64; j++)
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