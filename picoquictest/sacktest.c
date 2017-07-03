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

    memset(&cnx, 0, sizeof(cnx));

    for (int i = 0; ret == 0 && i < nb_test_pn64; i++)
    {
        if (picoquic_record_pn_received(&cnx, test_pn64[i]) != 0)
        {
            ret = -1;
        }

        for (int j = 0; ret == 0 && j <= i; j++)
        {
            if (picoquic_is_pn_already_received(&cnx, test_pn64[j]) == 0)
            {
                ret = -1;
            }

            if (picoquic_record_pn_received(&cnx, test_pn64[j]) != 1)
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
            cnx.first_sack_item.next_sack != NULL)
        {
            ret = -1;
        }
    }

    return ret;
}