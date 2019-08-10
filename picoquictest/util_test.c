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
#ifdef _WINDOWS
#include <malloc.h>
#endif
#include <string.h>

static const picoquic_connection_id_t expected_cnxid[4] = {
    { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0 } , 16 },
    { { 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0, 0, 0, 0, 0, 0, 0, 0 } , 8 },
    { { 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } , 2 },
    { { 0x77, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } , 1 },
};

static const char* expected_str[4] = {
    "000102030405060708090a0b0c0d0e0f",
    "fedcba9876543210",
    "cafe",
    "77"
};

static size_t test_cases = sizeof(expected_cnxid) / sizeof(picoquic_connection_id_t);

int util_connection_id_print_test()
{
    int ret = 0;  
    char cnxid_str[2 * PICOQUIC_CONNECTION_ID_MAX_SIZE + 1];
  
    for (size_t i = 0; i < test_cases; ++i)
    {
        int result = picoquic_print_connection_id_hexa(cnxid_str, sizeof(cnxid_str), &expected_cnxid[i]);
        if (result != 0) {
            DBG_PRINTF("picoquic_print_connection_id_hexa failed with: %d\n", result);
            ret = -1;
        }
        if (strcmp(cnxid_str, expected_str[i]) != 0) {
            DBG_PRINTF("result: %s, expected: %s\n", cnxid_str, expected_str[i]);
            ret = -1;
        }
    }

    // Test invalid call
    if (picoquic_print_connection_id_hexa("", 0, &expected_cnxid[0]) == 0) {
        DBG_PRINTF("%s", "picoquic_print_connection_id_hexa did not fail\n");
        ret = -1;
    }

    return ret;
}

int util_connection_id_parse_test()
{
    int ret = 0;  
    for (size_t i = 0; i < test_cases; ++i) {
        picoquic_connection_id_t cnxid;
        uint8_t id_len = picoquic_parse_connection_id_hexa(expected_str[i], strlen(expected_str[i]), &cnxid);
        if (id_len != expected_cnxid[i].id_len) {
            DBG_PRINTF("Wrong length returned. result: %d, expected: %d\n", id_len, expected_cnxid[i].id_len);
            ret = -1;
        }
        if (picoquic_compare_connection_id(&cnxid, &expected_cnxid[i]) != 0) {
            DBG_PRINTF("%s", "the returned connection id is different than expected.\n");
            ret = -1;
        }
    }
    return ret;
}

int util_sprintf_test()
{
    int ret = 0;
    char str[8];
    if (picoquic_sprintf(str, sizeof(str), "%s%s", "foo", "bar") != 0) {
        DBG_PRINTF("%s", "'foobar' test failed.\n");
        ret = -1;
    }
    if (picoquic_sprintf(str, sizeof(str), "%s%c%s", "foo", PICOQUIC_FILE_SEPARATOR, "bar") != 0) {
        DBG_PRINTF("%s", "'foo/bar' test failed.\n");
        ret = -1;
    }
    if (picoquic_sprintf(str, sizeof(str), "%s%c%s", "fooo", PICOQUIC_FILE_SEPARATOR, "bar") == 0) {
        DBG_PRINTF("%s", "'fooo/bar' test failed.\n");
        ret = -1;
    }
    if (picoquic_sprintf(str, sizeof(str), "%s%c%s", "fooo", PICOQUIC_FILE_SEPARATOR, "barr") == 0) {
        DBG_PRINTF("%s", "'fooo/barr' test failed.\n");
        ret = -1;
    }
    return ret;
}