/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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
#include <string.h>
#include "h3zero.h"

/*
 * Test of the prefixed integer encoding
 */

static uint8_t h3zero_pref31_val10[] = { 0xCA }; 
static uint8_t h3zero_pref31_val31[] = { 0xDF, 0 };
static uint8_t h3zero_pref31_val1337[] = { 0xDF, 0x9A, 0x0A };
static uint8_t h3zero_pref127_val0[] = { 0x80 };
static uint8_t h3zero_pref127_valmax[] = { 
    0xFF, 0x80, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3F };
static uint8_t h3zero_pref7_err1[] = { 0x07 };
static uint8_t h3zero_pref7_err2[] = { 0x07, 0xFF, 0xFF, 0x80, 0x80, 0x80 };

typedef struct st_h3zero_test_integer_case_t {
    uint64_t test_value;
    uint8_t mask;
    uint8_t * encoding;
    size_t encoding_length;
} h3zero_test_integer_case_t;

static h3zero_test_integer_case_t h3zero_int_case[] = {
    { 10, 0x1F, h3zero_pref31_val10, sizeof(h3zero_pref31_val10)},
    { 31, 0x1F, h3zero_pref31_val31, sizeof(h3zero_pref31_val31)},
    { 1337, 0x1F, h3zero_pref31_val1337, sizeof(h3zero_pref31_val1337)},
    { 0, 0x7F, h3zero_pref127_val0, sizeof(h3zero_pref127_val0)},
    { 0x3FFFFFFFFFFFFFFFull, 0x7F, h3zero_pref127_valmax, sizeof(h3zero_pref127_valmax)},
    { 0xFFFFFFFFFFFFFFFFull, 0x07, h3zero_pref7_err1, sizeof(h3zero_pref7_err1)},
    { 0xFFFFFFFFFFFFFFFFull, 0x07, h3zero_pref7_err2, sizeof(h3zero_pref7_err2)}
};

static size_t nb_h3zero_int_case = sizeof(h3zero_int_case) / sizeof(h3zero_test_integer_case_t);

int h3zero_integer_test() 
{
    int ret = 0;
    for (size_t i = 0; ret == 0 && i < nb_h3zero_int_case; i++) {
        uint64_t val;
        uint8_t * bytes;

        bytes = h3zero_qpack_int_decode(
            h3zero_int_case[i].encoding,
            h3zero_int_case[i].encoding + h3zero_int_case[i].encoding_length,
            h3zero_int_case[i].mask,
            &val);

        if (h3zero_int_case[i].test_value == 0xFFFFFFFFFFFFFFFFull) {
            /* verify that error is properly detected */
            if (bytes != NULL) {
                DBG_PRINTF("Failed to detect error case %d\n", (int)i);
                ret = -1;
            }
        }
        else {
            if (bytes == NULL) {
                DBG_PRINTF("Failed to decode case %d\n", (int)i);
                ret = -1;
            }
            else if ((bytes - h3zero_int_case[i].encoding) != h3zero_int_case[i].encoding_length) {
                DBG_PRINTF("Bad decoding length case %d\n", (int)i);
                ret = -1;
            }
            else if (val != h3zero_int_case[i].test_value) {
                DBG_PRINTF("Bad decoded value case %d\n", (int)i);
                ret = -1;
            }
            else {
                uint8_t target[16];

                memset(target, 0x55, sizeof(target));
                target[0] = h3zero_int_case[i].encoding[0] & ~h3zero_int_case[i].mask;

                bytes = h3zero_qpack_int_encode(target, target + sizeof(target),
                    h3zero_int_case[i].mask, h3zero_int_case[i].test_value);

                if (bytes == NULL) {
                    DBG_PRINTF("Failed to encode case %d\n", (int)i);
                    ret = -1;
                }
                else if ((bytes - target) != h3zero_int_case[i].encoding_length) {
                    DBG_PRINTF("Bad encoding length case %d\n", (int)i);
                    ret = -1;
                }
                else if (memcmp(target, h3zero_int_case[i].encoding,
                    h3zero_int_case[i].encoding_length) != 0) {
                    DBG_PRINTF("Bad encoding case %d\n", (int)i);
                    ret = -1;
                }
            }
        }
    }

    return ret;
}

/* Test decoding of basic QPACK messages */

#define QPACK_TEST_HEADER_BLOCK_PREFIX 0,0
#define QPACK_TEST_HEADER_BLOCK_PREFIX2 0,0x7F,0x18
#define QPACK_TEST_HEADER_INDEX_HTML 'i', 'n', 'd', 'e', 'x', '.', 'h', 't', 'm', 'l'
#define QPACK_TEST_HEADER_INDEX_HTML_LEN 10
#define QPACK_TEST_HEADER_PATH ':', 'p', 'a', 't', 'h'
#define QPACK_TEST_HEADER_PATH_LEN 5
#define QPACK_TEST_HEADER_STATUS ':', 's', 't', 'a', 't', 'u', 's'
#define QPACK_TEST_HEADER_STATUS_LEN 7

static uint8_t qpack_test_get_slash[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0|17, 0xC0 | 1};
static uint8_t qpack_test_get_slash_prefix[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX2, 0xC0 | 17, 0xC0 | 1 };
static uint8_t qpack_test_get_index_html[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0x50 | 1,
    QPACK_TEST_HEADER_INDEX_HTML_LEN, QPACK_TEST_HEADER_INDEX_HTML };
static uint8_t qpack_test_get_index_html_long[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 
    0x20 | QPACK_TEST_HEADER_PATH_LEN, QPACK_TEST_HEADER_PATH,
    QPACK_TEST_HEADER_INDEX_HTML_LEN, QPACK_TEST_HEADER_INDEX_HTML };
static uint8_t qpack_test_status_404[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 27 };
static uint8_t qpack_test_status_404_code[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x50 | 0x0F, 13, 3, '4', '0', '4' };
static uint8_t qpack_test_status_404_long[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x20|0x07, 
    QPACK_TEST_HEADER_STATUS_LEN - 7, QPACK_TEST_HEADER_STATUS,
    3, '4', '0', '4' };
static uint8_t qpack_test_response_html[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 25, 0xC0 | 52 };

static uint8_t qpack_test_string_index_html[] = { QPACK_TEST_HEADER_INDEX_HTML };
static uint8_t qpack_test_string_slash[] = { '/' };

typedef struct st_qpack_test_case_t {
    uint8_t * bytes;
    size_t bytes_length;
    h3zero_header_parts_t parts;
} qpack_test_case_t;

static qpack_test_case_t qpack_test_case[] = {
    {
        qpack_test_get_slash, sizeof(qpack_test_get_slash),
        { h3zero_method_get, qpack_test_string_slash, 1, 0, 0}
    },
    {
        qpack_test_get_slash_prefix, sizeof(qpack_test_get_slash_prefix),
        { h3zero_method_get, qpack_test_string_slash, 1, 0, 0}
    },
    {
        qpack_test_get_index_html, sizeof(qpack_test_get_index_html),
        { h3zero_method_get, qpack_test_string_index_html, QPACK_TEST_HEADER_INDEX_HTML_LEN, 0, 0}
    },
    {
        qpack_test_get_index_html_long, sizeof(qpack_test_get_index_html_long),
        { h3zero_method_get, qpack_test_string_index_html, QPACK_TEST_HEADER_INDEX_HTML_LEN, 0, 0}
    },
    {
        qpack_test_status_404, sizeof(qpack_test_status_404),
        { 0, NULL, 0, 404, 0}
    },
    {
        qpack_test_status_404_code, sizeof(qpack_test_status_404_code),
        { 0, NULL, 0, 404, 0}
    },
    {
        qpack_test_status_404_long, sizeof(qpack_test_status_404_long),
        { 0, NULL, 0, 404, 0}
    },
    {
        qpack_test_response_html, sizeof(qpack_test_response_html),
        { 0, NULL, 0, 200, h3zero_content_type_text_html}
    }
};

static size_t nb_qpack_test_case = sizeof(qpack_test_case) / sizeof(qpack_test_case_t);

static int h3zero_parse_qpack_test_one(size_t i, uint8_t * data, size_t data_length)
{
    int ret = 0;
    uint8_t * bytes;
    h3zero_header_parts_t parts;

    bytes = h3zero_parse_qpack_header_frame(data, data + data_length, &parts);

    if (bytes == 0) {
        DBG_PRINTF("Qpack case %d cannot be parsed", i);
        ret = -1;
    }
    else if ((bytes - data) != data_length) {
        DBG_PRINTF("Qpack case %d parse wrong length", i);
        ret = -1;
    }
    else if (parts.method != qpack_test_case[i].parts.method) {
        DBG_PRINTF("Qpack case %d parse wrong method", i);
        ret = -1;
    }
    else if (parts.path_length != qpack_test_case[i].parts.path_length) {
        DBG_PRINTF("Qpack case %d parse wrong path length", i);
        ret = -1;
    }
    else if (parts.path == NULL && qpack_test_case[i].parts.path != NULL) {
        DBG_PRINTF("Qpack case %d parse path not null", i);
        ret = -1;
    }
    else if (parts.path != NULL && qpack_test_case[i].parts.path == NULL) {
        DBG_PRINTF("Qpack case %d parse null path", i);
        ret = -1;
    }
    else if (parts.path != NULL && parts.path_length > 0 &&
        memcmp(parts.path, qpack_test_case[i].parts.path, parts.path_length) != 0) {
        DBG_PRINTF("Qpack case %d parse wrong path", i);
        ret = -1;
    }
    else if (parts.status != qpack_test_case[i].parts.status) {
        DBG_PRINTF("Qpack case %d parse wrong status", i);
        ret = -1;
    }
    else if (parts.content_type != qpack_test_case[i].parts.content_type) {
        DBG_PRINTF("Qpack case %d parse wrong content_type", i);
        ret = -1;
    }

    return ret;
}

int h3zero_parse_qpack_test()
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_qpack_test_case; i++) {
        ret = h3zero_parse_qpack_test_one(i,
            qpack_test_case[i].bytes, qpack_test_case[i].bytes_length);
    }

    return ret;
}

/*
 * Prepare frames of the different supported types, and 
 * verify that they can be decoded as expected
 */
int h3zero_prepare_qpack_test()
{
    int ret = 0;
    int qpack_compare_test[] = { 0, 2, 4, 7, -1 };
    
    for (int i = 0; ret == 0 && qpack_compare_test[i] >= 0; i++) {
        uint8_t buffer[256];
        uint8_t * bytes_max = &buffer[0] + sizeof(buffer);
        uint8_t * bytes = NULL;
        int j = qpack_compare_test[i];

        if (qpack_test_case[j].parts.path != NULL) {
            /* Create a request header */
            bytes = h3zero_create_request_header_frame(buffer, bytes_max,
                qpack_test_case[j].parts.path, qpack_test_case[j].parts.path_length);
        }
        else if (qpack_test_case[j].parts.content_type != 0) {
            bytes = h3zero_create_response_header_frame(buffer, bytes_max,
                qpack_test_case[j].parts.content_type);
        } else if (qpack_test_case[j].parts.status == 404) {
            bytes = h3zero_create_not_found_header_frame(buffer, bytes_max);
        }

        if (bytes == NULL) {
            DBG_PRINTF("Prepare qpack test %d failed\n", j);
            ret = -1;
        }
        else {
            ret = h3zero_parse_qpack_test_one((size_t)j, buffer, bytes - buffer);
        }
    }

    return ret;
}