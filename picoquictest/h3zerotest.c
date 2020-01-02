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

#include <string.h>
#include <stdlib.h>
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "h3zero.h"
#include "democlient.h"
#include "demoserver.h"
/* Include picotls.h in order to support tests of ESNI */
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include "picotls.h"
#include "tls_api.h"

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

/* Test of QPACK Huffman decoding */
static uint8_t qpack_huffman_test_1[] = { 0xce, 0x64, 0x97, 0x75, 0x65, 0x2c, 0x9f };
static uint8_t qpack_huffman_test_2[] = { 0x1d, 0x75, 0xd0, 0x62, 0x0d, 0x26, 0x3d, 0x4c, 0x4e, 0x9a, 0x68 };
static uint8_t qpack_huffman_test_3[] = { 0x7c, 0x40 };
static uint8_t qpack_huffman_test_4[] = { 0x60, 0x22, 0x65, 0xaf };
static uint8_t qpack_huffman_data_1[] = { 'L', 'i', 't', 'e', 'S', 'p', 'e', 'e', 'd' };
static uint8_t qpack_huffman_data_2[] = { 'a', 'p', 'p', 'l', 'i', 'c', 'a', 't', 'i', 'o', 'n', '/', 'h', 't', 'm', 'l' };
static uint8_t qpack_huffman_data_3[] = { '9', '2', '0' };
static uint8_t qpack_huffman_data_4[] = { '/', '1', '2', '3', '4' };

typedef struct st_qpack_huffman_test_case_t {
    uint8_t * test;
    size_t test_size;
    uint8_t * result;
    size_t result_size;
} qpack_huffman_test_case_t;

static qpack_huffman_test_case_t qpack_huffman_test_case[] = {
    { qpack_huffman_test_1, sizeof(qpack_huffman_test_1),
    qpack_huffman_data_1, sizeof(qpack_huffman_data_1)},
    { qpack_huffman_test_2, sizeof(qpack_huffman_test_2),
    qpack_huffman_data_2, sizeof(qpack_huffman_data_2)},
    { qpack_huffman_test_3, sizeof(qpack_huffman_test_3),
    qpack_huffman_data_3, sizeof(qpack_huffman_data_3)},
    { qpack_huffman_test_4, sizeof(qpack_huffman_test_4),
    qpack_huffman_data_4, sizeof(qpack_huffman_data_4)}
};

static size_t nb_qpack_huffman_test_case = sizeof(qpack_huffman_test_case) / sizeof(qpack_huffman_test_case_t);

int qpack_huffman_test()
{
    int ret = 0;
    uint8_t data[256];
    size_t nb_data;

    for (size_t i = 0; ret == 0 && i < nb_qpack_huffman_test_case; i++) {
        ret = hzero_qpack_huffman_decode(
            qpack_huffman_test_case[i].test,
            qpack_huffman_test_case[i].test + qpack_huffman_test_case[i].test_size,
            data, sizeof(data), &nb_data);
        if (ret == 0) {
            if (nb_data != qpack_huffman_test_case[i].result_size) {
                DBG_PRINTF("Huffman test %d bad length (%d vs %d)\n", (int)i,
                    (int)nb_data, (int)qpack_huffman_test_case[i].result_size);
                ret = -1;
            }
            else if (memcmp(qpack_huffman_test_case[i].result, data, nb_data) != 0) {
                DBG_PRINTF("Huffman test %d does not match \n", (int)i);
                ret = -1;
            }
        }
        else {
            DBG_PRINTF("Huffman cannot decode test %d\n", (int)i);
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
#define QPACK_TEST_HEADER_QPACK_PATH 0xFD, 0xFD, 0xFD 
#define QPACK_TEST_HEADER_DEQPACK_PATH 'Z', 'Z', 'Z'

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
static uint8_t qpack_test_status_405_code[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x50 | 0x0F, 13, 3, '4', '0', '5', 0xFF, 
    (uint8_t)(H3ZERO_QPACK_ALLOW_GET - 63)};

static uint8_t qpack_test_get_zzz[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0x50 | 1,
    0x80 | 3, QPACK_TEST_HEADER_QPACK_PATH };

static uint8_t qpack_test_get_1234[] = {
    0x00, 0x00, 0xd1, 0xd7, 0x51, 0x84, 0x60, 0x22,
    0x65, 0xaf, 0x50, 0x94, 0x49, 0x50, 0x95, 0xeb,
    0xb0, 0xdd, 0xc6, 0x92, 0x9c, 0x89, 0x3d, 0x76,
    0xa1, 0x72, 0x1e, 0x9b, 0x8d, 0x34, 0xcb, 0x3f
};

static uint8_t qpack_test_get_ats[] = {
    0x00, 0x00, 0x50, 0x8a, 0xed, 0x69, 0x88, 0xb9,
    0xe6, 0xb0, 0xab, 0x90, 0xf4, 0xff, 0xd1, 0xc1,
    0xd7
};

static uint8_t qpack_test_get_ats2[] = {
    0x00, 0x00, 0x50, 0x90, 0x49, 0x50, 0x95, 0xeb,
    0xb0, 0xdd, 0xc6, 0x92, 0x9c, 0x89, 0x3d, 0x76,
    0xa1, 0x72, 0x1e, 0x9f, 0xd1, 0xc1, 0xd7
};

static uint8_t qpack_test_post_zzz[] = {
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 20, 0x50 | 1,
    0x80 | 3, QPACK_TEST_HEADER_QPACK_PATH, 0xC0 | 53
};

static uint8_t qpack_test_string_index_html[] = { QPACK_TEST_HEADER_INDEX_HTML };
static uint8_t qpack_test_string_slash[] = { '/' };
static uint8_t qpack_test_string_zzz[] = { 'Z', 'Z', 'Z' };
static uint8_t qpack_test_string_1234[] = { '/', '1', '2', '3', '4' };


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
    },
    {
        qpack_test_status_405_code, sizeof(qpack_test_status_405_code),
        { 0, NULL, 0, 405, 0}
    },
    {
        qpack_test_get_zzz, sizeof(qpack_test_get_zzz),
        { h3zero_method_get, qpack_test_string_zzz, sizeof(qpack_test_string_zzz), 0, 0}
    },
    {
        qpack_test_get_1234, sizeof(qpack_test_get_1234),
        { h3zero_method_get, qpack_test_string_1234, sizeof(qpack_test_string_1234), 0, 0}
    },
    {
        qpack_test_get_ats, sizeof(qpack_test_get_ats),
        { h3zero_method_get, qpack_test_string_slash, sizeof(qpack_test_string_slash), 0, 0}
    },
    {
        qpack_test_get_ats2, sizeof(qpack_test_get_ats2),
        { h3zero_method_get, qpack_test_string_slash, sizeof(qpack_test_string_slash), 0, 0}
    },
    {
        qpack_test_post_zzz, sizeof(qpack_test_post_zzz),
        { h3zero_method_post, qpack_test_string_zzz, sizeof(qpack_test_string_zzz), 0, h3zero_content_type_text_plain}
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

    if (parts.path != NULL) {
        free((uint8_t *)parts.path);
        *((uint8_t **)&parts.path) = NULL;
    }

    return ret;
}

int h3zero_parse_qpack_test()
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_qpack_test_case; i++) {
        ret = h3zero_parse_qpack_test_one(i,
            qpack_test_case[i].bytes, qpack_test_case[i].bytes_length);
        if (ret != 0) {
            DBG_PRINTF("Parse QPACK test %d fails.\n", i);
        }
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
    int qpack_compare_test[] = { 0, 2, 4, 7, 8, 13, -1 };
    
    for (int i = 0; ret == 0 && qpack_compare_test[i] >= 0; i++) {
        uint8_t buffer[256];
        uint8_t * bytes_max = &buffer[0] + sizeof(buffer);
        uint8_t * bytes = NULL;
        int j = qpack_compare_test[i];

        if (qpack_test_case[j].parts.path != NULL) {
            if (qpack_test_case[j].parts.method == h3zero_method_get)
            {
                /* Create a request header */
                bytes = h3zero_create_request_header_frame(buffer, bytes_max,
                    qpack_test_case[j].parts.path, qpack_test_case[j].parts.path_length, "example.com");
            }
            else  if (qpack_test_case[j].parts.method == h3zero_method_post)
            {
                /* Create a post header */
                bytes = h3zero_create_post_header_frame(buffer, bytes_max,
                    qpack_test_case[j].parts.path, qpack_test_case[j].parts.path_length, "example.com", h3zero_content_type_text_plain);
            }
            else {
                DBG_PRINTF("Case %d, unexpected method: %d\n", j, qpack_test_case[j].parts.method);
                ret = -1;
                break;
            }
        }
        else if (qpack_test_case[j].parts.content_type != 0) {
            bytes = h3zero_create_response_header_frame(buffer, bytes_max,
                qpack_test_case[j].parts.content_type);
        } else if (qpack_test_case[j].parts.status == 404) {
            bytes = h3zero_create_not_found_header_frame(buffer, bytes_max);
        } else if (qpack_test_case[j].parts.status == 405) {
            bytes = h3zero_create_bad_method_header_frame(buffer, bytes_max);
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

/*
 * Test of the stream decoding filter
 */

static uint8_t h3zero_stream_test1[] = {
    h3zero_frame_header, 4,
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 17, 0xC0 | 1 };

#define H3ZERO_STREAM_TEST2_DATA 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l'

static uint8_t h3zero_stream_test2_data[] = { H3ZERO_STREAM_TEST2_DATA };

static uint8_t h3zero_stream_test2[] = {
    h3zero_frame_header, 4,
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 25, 0xC0 | 52,
    h3zero_frame_data, 12,
    H3ZERO_STREAM_TEST2_DATA };

static uint8_t h3zero_stream_test3[] = {
    h3zero_frame_header, 0x40, 4,
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0xC0 | 25, 0xC0 | 52,
    h3zero_frame_data, 12,
    H3ZERO_STREAM_TEST2_DATA,
    h3zero_frame_header, 8,
    QPACK_TEST_HEADER_BLOCK_PREFIX, 0x50 | 0x0F, 13, 3, '4', '0', '4'
};

static uint8_t h3zero_stream_test_grease[] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
    0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xfe, 0x12, 0x47, 0x52, 0x45, 0x41, 0x53, 0x45,
    0x20, 0x69, 0x73, 0x20, 0x74, 0x68, 0x65, 0x20,
    0x77, 0x6f, 0x72, 0x64, 0x01, 0x1f, 0x00, 0x00,
    0xd1, 0xd7, 0x50, 0x90, 0x49, 0x50, 0x95, 0xeb,
    0xb0, 0xdd, 0xc6, 0x92, 0x9c, 0x89, 0x3d, 0x76,
    0xa1, 0x72, 0x1e, 0x9f, 0xc1, 0x5f, 0x50, 0x85,
    0xed, 0x69, 0x89, 0x39, 0x7f
};

int h3zero_stream_test_one_split(uint8_t * bytes, size_t nb_bytes, size_t split,
    uint8_t * data_ref, size_t data_len, int has_trailer)
{
    int ret = 0;
    h3zero_data_stream_state_t stream_state;
    uint8_t * bmax[2] = { bytes + split, bytes + nb_bytes };
    size_t nb_data = 0;
    uint8_t data[64];
    size_t available_data;
    uint16_t error_found;

    memset(&stream_state, 0, sizeof(h3zero_data_stream_state_t));

    for (int i = 0; ret == 0 && i < 2; i++) {
        while (bytes != NULL && bytes < bmax[i]) {
            bytes = h3zero_parse_data_stream(bytes, bmax[i], &stream_state, &available_data, &error_found);
            if (bytes != NULL && available_data > 0) {
                if (nb_data + available_data > 64) {
                    ret = -1;
                }
                else {
                    memcpy(&data[nb_data], bytes, available_data);
                    bytes += available_data;
                    nb_data += available_data;
                }
            }
        }
    }

    if (ret == 0) {
        if (bytes != bmax[1]) {
            DBG_PRINTF("%s", "did not parse to the end!\n");
            ret = -1;
        }
        else if (stream_state.frame_header_parsed) {
            DBG_PRINTF("%s", "stopped with frame not parsed\n");
            ret = -1;
        }
        else if (!stream_state.header_found) {
            DBG_PRINTF("%s", "did not parse the first header\n");
            ret = -1;
        }
        else if (nb_data != data_len) {
            DBG_PRINTF("%s", "did not get right amount of data (%d vs %d)\n",
                (int)nb_data, (int)data_len);
            ret = -1;
        }
        else if (nb_data != 0 && memcmp(data, data_ref, nb_data) != 0) {
            DBG_PRINTF("%s", "did not get right amount of data (%d vs %d)\n",
                (int)nb_data, (int)data_len);
            ret = -1;
        }
        else if (has_trailer && !stream_state.trailer_found) {
            DBG_PRINTF("%s", "did not parse the trailer\n");
            ret = -1;
        }
        else if (!has_trailer && stream_state.trailer_found) {
            DBG_PRINTF("%s", "found an extra trailer\n");
            ret = -1;
        }
    }

    h3zero_delete_data_stream_state(&stream_state);
    return ret;
}

int h3zero_stream_test_one(uint8_t * bytes, size_t nb_bytes,
    uint8_t * data_ref, size_t data_len, int has_trailer)
{
    int ret = 0;

    for (size_t split = 0; ret == 0 && split < data_len; split++) {
        ret = h3zero_stream_test_one_split(bytes, nb_bytes, split, data_ref, data_len, has_trailer);
    }

    return ret;
}

int h3zero_stream_test()
{
    int ret = h3zero_stream_test_one(h3zero_stream_test1, sizeof(h3zero_stream_test1), NULL, 0, 0);

    if (ret == 0) {
        ret = h3zero_stream_test_one(h3zero_stream_test2, sizeof(h3zero_stream_test2), 
            h3zero_stream_test2_data, sizeof(h3zero_stream_test2_data), 0);
    }

    if (ret == 0) {
        ret = h3zero_stream_test_one(h3zero_stream_test3, sizeof(h3zero_stream_test3),
            h3zero_stream_test2_data, sizeof(h3zero_stream_test2_data), 1);
    }

    if (ret == 0) {
        ret = h3zero_stream_test_one(h3zero_stream_test_grease, sizeof(h3zero_stream_test_grease),
            NULL, 0, 0);
    }

    return ret;
}

/*
 * Test the scenario parsing function
 */

char * parse_demo_scenario_text1 = "/;t:test.html;8:0:b:main.jpg;12:0:/bla/bla/";
char * parse_demo_scenario_text2 = "/;b:main.jpg;t:test.html;";
char * parse_demo_scenario_text3 = "*1000:/";
char * parse_demo_scenario_text4 = "/cgi-sink:1000000;4:/";

static const picoquic_demo_stream_desc_t parse_demo_scenario_desc1[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "_", 0, 0},
    { 0, 4, 0, "test.html", "test.html", 0, 0 },
    { 0, 8, 0, "main.jpg", "main.jpg", 1, 0 },
    { 0, 12, 0, "/bla/bla/", "_bla_bla_", 0, 0 }
};

static const picoquic_demo_stream_desc_t parse_demo_scenario_desc2[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "_", 0, 0 },
    { 0, 4, 0, "main.jpg", "main.jpg", 1, 0 },
    { 0, 8, 4, "test.html", "test.html", 0, 0 }
};

static const picoquic_demo_stream_desc_t parse_demo_scenario_desc3[] = {
    { 1000, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "_", 0, 0 }
};

static const picoquic_demo_stream_desc_t parse_demo_scenario_desc4[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/cgi-sink", "_cgi-sink", 0, 1000000 },
    { 0, 4, 0, "/", "_", 0, 0 }
};

int parse_demo_scenario_test_one(char * text, size_t nb_streams_ref, picoquic_demo_stream_desc_t const * desc_ref)
{
    size_t nb_streams = 0;
    picoquic_demo_stream_desc_t * desc = NULL;
    int ret = demo_client_parse_scenario_desc(text, &nb_streams, &desc);

    if (ret == 0) {
        if (nb_streams != nb_streams_ref) {
            ret = -1;
        }
        else {
            for (size_t i = 0; ret == 0 && i < nb_streams; i++) {
                if (desc[i].stream_id != desc_ref[i].stream_id) {
                    ret = -1;
                } else if (desc[i].previous_stream_id != desc_ref[i].previous_stream_id) {
                    ret = -1;
                }
                else if (desc[i].is_binary != desc_ref[i].is_binary) {
                    ret = -1;
                }
                else if (strcmp(desc[i].doc_name, desc_ref[i].doc_name) != 0) {
                    ret = -1;
                }
                else if (strcmp(desc[i].f_name, desc_ref[i].f_name) != 0) {
                    ret = -1;
                }
                else if (desc[i].post_size !=  desc_ref[i].post_size) {
                    ret = -1;
                }
            }
        }
    }
    else {
        ret = -1;
    }

    if (desc != NULL) {
        demo_client_delete_scenario_desc(nb_streams, desc);
    }

    return ret;
}

int parse_demo_scenario_test()
{
    int ret = parse_demo_scenario_test_one(parse_demo_scenario_text1,
        sizeof(parse_demo_scenario_desc1) / sizeof(picoquic_demo_stream_desc_t),
        parse_demo_scenario_desc1);

    if (ret == 0){
        ret = parse_demo_scenario_test_one(parse_demo_scenario_text2,
            sizeof(parse_demo_scenario_desc2) / sizeof(picoquic_demo_stream_desc_t),
            parse_demo_scenario_desc2);
    }

    if (ret == 0) {
        ret = parse_demo_scenario_test_one(parse_demo_scenario_text3,
            sizeof(parse_demo_scenario_desc3) / sizeof(picoquic_demo_stream_desc_t),
            parse_demo_scenario_desc3);
    }

    if (ret == 0) {
        ret = parse_demo_scenario_test_one(parse_demo_scenario_text4,
            sizeof(parse_demo_scenario_desc4) / sizeof(picoquic_demo_stream_desc_t),
            parse_demo_scenario_desc4);
    }

    return ret;
}

/*
 * Set a connection between an H3 client and an H3 server over
 * network simulation.
 */
static const picoquic_demo_stream_desc_t demo_test_scenario[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/", "root.html", 0, 0 },
    { 0, 4, 0, "12345", "doc-12345.txt", 0, 0 },
    { 0, 8, 4, "post-test", "post-test.html", 0, 12345 }
};

static size_t const nb_demo_test_scenario = sizeof(demo_test_scenario) / sizeof(picoquic_demo_stream_desc_t);

static size_t const demo_test_stream_length[] = {
    128,
    12345,
    190
};

uint64_t demo_server_test_time_from_esni_rr(char const * esni_rr_file)
{
    uint8_t esnikeys[2048];
    size_t esnikeys_len;
    uint64_t not_before = 0;
    uint64_t not_after = 0;
    uint64_t esni_start = 0;
    uint16_t version = 0;
    uint16_t l;

    /* Load the rr file */
    if (picoquic_esni_load_rr(esni_rr_file, esnikeys, sizeof(esnikeys), &esnikeys_len) == 0)
    {
        size_t byte_index = 0;

        if (byte_index + 2 <= esnikeys_len) {
            version = PICOPARSE_16(&esnikeys[byte_index]);
            byte_index += 2;
        }
        /* 4 bytes checksum */
        byte_index += 4;
        /* If > V2, 16 bits length + published SNI */
        if (version != 0xFF01 && byte_index + 2 <= esnikeys_len) {
            l = PICOPARSE_16(&esnikeys[byte_index]);
            byte_index += (size_t)l + 2;
        }
        /* 16 bits length + key exchanges */
        if (byte_index + 2 <= esnikeys_len) {
            l = PICOPARSE_16(&esnikeys[byte_index]);
            byte_index += (size_t)l + 2;
        }
        /* 16 bits length + ciphersuites */
        if (byte_index + 2 <= esnikeys_len) {
            l = PICOPARSE_16(&esnikeys[byte_index]);
            byte_index += (size_t)l + 2;
        }
        /* 16 bits padded length */
        byte_index += 2;
        /* 64 bits not before */
        if (byte_index + 8 <= esnikeys_len) {
            not_before = PICOPARSE_64(&esnikeys[byte_index]);
            byte_index += 8;
        }
        /* 64 bits not after */
        if (byte_index + 8 <= esnikeys_len) {
            not_after = PICOPARSE_64(&esnikeys[byte_index]);
        }
        else {
            not_after = not_before;
        }
        /* 16 bits length + extensions. ignored */
    }
    esni_start = ((not_before + not_after) / 2) * 1000000;

    return esni_start;
}

static int demo_server_test(char const * alpn, picoquic_stream_data_cb_fn server_callback_fn, void * server_param,
    int do_esni, const picoquic_demo_stream_desc_t * demo_scenario, size_t nb_scenario, size_t const * demo_length,
    int do_sat, uint64_t completion_target)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t time_out;
    int nb_trials = 0;
    int was_active = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_demo_callback_ctx_t callback_ctx;
    int ret;
    /* Locate the esni record and key files */
    char test_server_esni_key_file[512];
    char test_server_esni_rr_file[512];
    picoquic_tp_t client_parameters;

    if (do_esni) {
        ret = picoquic_get_input_path(test_server_esni_key_file, sizeof(test_server_esni_key_file), picoquic_test_solution_dir, PICOQUIC_TEST_FILE_ESNI_KEY);

        if (ret == 0) {
            ret = picoquic_get_input_path(test_server_esni_rr_file, sizeof(test_server_esni_rr_file), picoquic_test_solution_dir, PICOQUIC_TEST_FILE_ESNI_RR);
        }

        if (ret == 0) {
            simulated_time = demo_server_test_time_from_esni_rr(test_server_esni_rr_file);
        }
    }

    ret = picoquic_demo_client_initialize_context(&callback_ctx, demo_scenario, nb_scenario, alpn, 0);

    if (ret == 0) {
        ret = tls_api_init_ctx(&test_ctx,
            PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, alpn, &simulated_time, NULL, NULL, 0, 1, 0);

        if (ret == 0 && do_sat) {
            /* For the satellite test, set long delays, 10 Mbps one way, 1 Mbps the other way */
            const uint64_t satellite_latency = 300000;
            test_ctx->c_to_s_link->microsec_latency = satellite_latency;
            test_ctx->c_to_s_link->picosec_per_byte = 8000000;
            test_ctx->s_to_c_link->microsec_latency = satellite_latency;
            test_ctx->s_to_c_link->picosec_per_byte = 800000;
            picoquic_set_default_congestion_algorithm(test_ctx->qserver, picoquic_bbr_algorithm);
            picoquic_set_congestion_algorithm(test_ctx->cnx_client, picoquic_bbr_algorithm);
            picoquic_set_cc_log(test_ctx->qserver, ".");
            memset(&client_parameters, 0, sizeof(picoquic_tp_t));
            picoquic_init_transport_parameters(&client_parameters, 1);
            client_parameters.enable_one_way_delay = 1;
            picoquic_set_transport_parameters(test_ctx->cnx_client, &client_parameters);
        }
    }

    if (ret != 0) {
        DBG_PRINTF("Could not create the QUIC test contexts for V=%x\n", PICOQUIC_INTERNAL_TEST_VERSION_1);
    }
    else if (test_ctx == NULL || test_ctx->cnx_client == NULL || test_ctx->qserver == NULL) {
        DBG_PRINTF("%s", "Connections where not properly created!\n");
        ret = -1;
    }

    /* The default procedure creates connections using the test callback.
     * We want to replace that by the H3 callback */

    if (ret == 0) {
        picoquic_set_default_callback(test_ctx->qserver, server_callback_fn, server_param);
        picoquic_set_callback(test_ctx->cnx_client, picoquic_demo_client_callback, &callback_ctx);
        if (do_esni) {
            /* Add the esni parameters to the server */
            if (ret == 0) {
                ret = picoquic_esni_load_key(test_ctx->qserver, test_server_esni_key_file);
            }

            if (ret == 0) {
                ret = picoquic_esni_server_setup(test_ctx->qserver, test_server_esni_rr_file);
            }

            /* Add the SNI parameters to the client */
            if (ret == 0) {
                ret = picoquic_esni_client_from_file(test_ctx->cnx_client, test_server_esni_rr_file);
            }
        }
        if (ret == 0) {
            ret = picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    if (ret == 0) {
        ret = picoquic_demo_client_start_streams(test_ctx->cnx_client, &callback_ctx, PICOQUIC_DEMO_STREAM_ID_INITIAL);
    }

    /* Simulate the connection from the client side. */
    time_out = simulated_time + 30000000;
    while (ret == 0 && picoquic_get_cnx_state(test_ctx->cnx_client) != picoquic_state_disconnected) {
        ret = tls_api_one_sim_round(test_ctx, &simulated_time, time_out, &was_active);

        if (picoquic_is_cnx_backlog_empty(test_ctx->cnx_client)) {
            if (callback_ctx.nb_open_streams == 0) {
                ret = picoquic_close(test_ctx->cnx_client, 0);
            }
            else if (simulated_time > callback_ctx.last_interaction_time &&
                simulated_time - callback_ctx.last_interaction_time > 10000000ull) {
                (void)picoquic_close(test_ctx->cnx_client, 0);
                ret = -1;
            }
        }

        if (++nb_trials > 100000) {
            ret = -1;
            break;
        }
    }

    /* Verify that the data was properly received. */
    for (size_t i = 0; ret == 0 && i < nb_scenario; i++) {
        picoquic_demo_client_stream_ctx_t* stream = callback_ctx.first_stream;

        while (stream != NULL && stream->stream_id != demo_scenario[i].stream_id) {
            stream = stream->next_stream;
        }

        if (stream == NULL) {
            DBG_PRINTF("Scenario stream %d is missing\n", (int)i);
            ret = -1;
        }
        else if (stream->F != NULL) {
            DBG_PRINTF("Scenario stream %d, file was not closed\n", (int)i);
            ret = -1;
        }
        else if (stream->received_length < demo_length[i]) {
            DBG_PRINTF("Scenario stream %d, only %d bytes received\n", 
                (int)i, (int)stream->received_length);
            ret = -1;
        }
        else if (stream->post_sent < demo_scenario[i].post_size) {
            DBG_PRINTF("Scenario stream %d, only %d bytes sent\n",
                (int)i, (int)stream->post_sent);
            ret = -1;
        }
    }

    /* Verify that ESNI was properly negotiated, ut only if ESNI is supported in local version of Picotls */
#ifdef PTLS_ESNI_NONCE_SIZE
    if (ret == 0 && do_esni) {
        if (picoquic_esni_version(test_ctx->cnx_client) == 0) {
            DBG_PRINTF("%s", "ESNI not negotiated for client connection.\n");
            ret = -1;
        } else if (picoquic_esni_version(test_ctx->cnx_server) == 0) {
            DBG_PRINTF("%s", "ESNI not negotiated for server connection.\n");
            ret = -1;
        } else if(picoquic_esni_version(test_ctx->cnx_client) != picoquic_esni_version(test_ctx->cnx_server)) {
            DBG_PRINTF("ESNI client version %d, server version %d.\n",
                picoquic_esni_version(test_ctx->cnx_client), picoquic_esni_version(test_ctx->cnx_server));
                ret = -1;
        }
        else if (memcmp(picoquic_esni_nonce(test_ctx->cnx_client), picoquic_esni_nonce(test_ctx->cnx_server), PTLS_ESNI_NONCE_SIZE) != 0) {
            DBG_PRINTF("%s", "Client and server nonce do not match.\n");
            ret = -1;
        }
    }
#endif

    if (ret == 0 && completion_target != 0) {
        if (simulated_time > completion_target) {
            DBG_PRINTF("Test uses %llu microsec instead of %llu", simulated_time, completion_target);
            ret = -1;
        }
    }

    picoquic_demo_client_delete_context(&callback_ctx);

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }
    
    return ret;
}

int h3zero_server_test()
{
    return demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_server_callback, NULL, 0, demo_test_scenario, nb_demo_test_scenario, demo_test_stream_length, 0, 0);
}

int h09_server_test()
{
    return demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, NULL, 0, demo_test_scenario, nb_demo_test_scenario, demo_test_stream_length, 0, 0);
}

int generic_server_test()
{
    char const* alpn_09 = PICOHTTP_ALPN_HQ_LATEST;
    char const* alpn_3 = PICOHTTP_ALPN_H3_LATEST;
    int ret = demo_server_test(alpn_09, picoquic_demo_server_callback, NULL, 0, demo_test_scenario, nb_demo_test_scenario, demo_test_stream_length, 0, 0);

    if (ret != 0) {
        DBG_PRINTF("Generic server test fails for %s\n", alpn_09);
    }
    else {
        ret = demo_server_test(alpn_3, picoquic_demo_server_callback, NULL, 0, demo_test_scenario, nb_demo_test_scenario, demo_test_stream_length, 0, 0);

        if (ret != 0) {
            DBG_PRINTF("Generic server test fails for %s\n", alpn_3);
        }
    }

    return ret;
}

int esni_test()
{
    return demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_server_callback, NULL, 1, demo_test_scenario, nb_demo_test_scenario, demo_test_stream_length, 0, 0);
}

/* Test the server side post API */

/* Sample callback used for demonstrating the callback API.
 * The transaction returns the MD5 of the posted data */

#define PICOQUIC_ECHO_SIZE_MAX 8192

typedef struct st_hzero_post_echo_ctx_t {
    size_t nb_received;
    size_t nb_echo;
    size_t nb_sent;
    uint8_t buf[PICOQUIC_ECHO_SIZE_MAX];
} hzero_post_echo_ctx_t;

int h3zero_test_ping_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t event, picohttp_server_stream_ctx_t* stream_ctx)
{
    int ret = 0;
    hzero_post_echo_ctx_t* ctx = (hzero_post_echo_ctx_t*)stream_ctx->path_callback_ctx;

    switch (event) {
    case picohttp_callback_get: /* Received a get command */
        break;
    case picohttp_callback_post: /* Received a post command */
        if (ctx == NULL) {
            ctx = (hzero_post_echo_ctx_t*)malloc(sizeof(hzero_post_echo_ctx_t));
            if (ctx == NULL) {
                /* cannot handle the stream -- TODO: reset stream? */
                return -1;
            }
            else {
                memset(ctx, 0, sizeof(hzero_post_echo_ctx_t));
                stream_ctx->path_callback_ctx = (void *) ctx;
            }
        }
        else {
            /* unexpected. Should not have a context here */
            return -1;
        }
        break;
    case picohttp_callback_post_data: /* Data received from peer on stream N */
        /* Add data to echo size */
        if (ctx == NULL) {
            ret = -1;
        }
        else { 
            if (ctx->nb_received < PICOQUIC_ECHO_SIZE_MAX) {
                size_t available = PICOQUIC_ECHO_SIZE_MAX - ctx->nb_received;
                size_t copied = (available > length) ? length : available;
                memcpy(ctx->buf + ctx->nb_received, bytes, copied);
                ctx->nb_echo += copied;
            }
            ctx->nb_received += length;
        }
        break;
    case picohttp_callback_post_fin: /* All posted data have been received, prepare the response now. */
        if (ctx != NULL) {
            if (ctx->nb_echo <= length) {
                memcpy(bytes, ctx->buf, ctx->nb_echo);
            }
            ret = (int)ctx->nb_echo;
        }
        else {
            ret = -1;
        }
        break;
    case picohttp_callback_provide_data:
        if (ctx == NULL || ctx->nb_sent > ctx->nb_echo) {
            ret = -1;
        }
        else
        {
            /* Provide data. */
            uint8_t* buffer;
            size_t available = ctx->nb_echo - ctx->nb_sent;
            int is_fin = 1;

            if (available > length) {
                available = length;
                is_fin = 0;
            }

            buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
            if (buffer != NULL) {
                memcpy(buffer, ctx->buf + ctx->nb_sent, available);
                ctx->nb_sent += available;
                ret = 0;
            }
            else {
                ret = -1;
            }
        }
        break;
    case picohttp_callback_reset: /* stream is abandoned */
        stream_ctx->path_callback = NULL;
        stream_ctx->path_callback_ctx = NULL;
       
        if (ctx != NULL) {
            free(ctx);
        }
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}

static const picoquic_demo_stream_desc_t post_test_scenario[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/ping", "ping-test.html", 0, 2345 }
};

picohttp_server_path_item_t ping_test_item = {
    "/ping",
    5,
    h3zero_test_ping_callback
};

picohttp_server_parameters_t ping_test_param = {
    NULL,
    &ping_test_item,
    1
};


static size_t const nb_post_test_scenario = sizeof(post_test_scenario) / sizeof(picoquic_demo_stream_desc_t);

static size_t const post_test_stream_length[] = { 2345 };

int h3zero_post_test()
{
    return demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_server_callback, (void*)&ping_test_param, 0, post_test_scenario, nb_post_test_scenario, post_test_stream_length, 0, 0);
}

int h09_post_test()
{
    return demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, (void*)&ping_test_param, 0, post_test_scenario, nb_post_test_scenario, post_test_stream_length, 0, 0);
}

int demo_file_sanitize_test()
{
    int ret = 0;
    char const* good[] = {
        "/index.html", "/example.com.txt", "/5000000", "/123_45.png", "/a-b-C-Z"
    };
    size_t nb_good = sizeof(good) / sizeof(char const*);
    char const* bad[] = {
        "/../index.html", "example.com.txt", "/5000000/", "/.123_45.png", "/a-b-C-Z\\..\\password.txt"
    };
    size_t nb_bad = sizeof(bad) / sizeof(char const*);

    for (size_t i = 0; ret == 0 && i < nb_good; i++) {
        if (demo_server_is_path_sane((uint8_t*)good[i], strlen(good[i])) != 0) {
            DBG_PRINTF("Found good frame not good: %s\n", good[i]);
            ret = -1;
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_bad; i++) {
        if (demo_server_is_path_sane((uint8_t*)bad[i], strlen(bad[i])) == 0) {
            DBG_PRINTF("Found bad frame not bad: %s\n", bad[i]);
            ret = -1;
        }
    }

    return ret;
}

int demo_file_access_test()
{
    int ret = 0;
#ifdef _WINDOWS
    char const* folder = ".\\";
#else
    char const* folder = "./";
#endif
    char const* path = "/x1234x5678.zzz";
    char const* bad_path = "/../etc/passwd";
    size_t f_size = 0;
    size_t echo_size = 0;
    char buf[128];
    const int nb_blocks = 16;

    FILE* F = picoquic_file_open(path + 1, "wb");

    if (F == NULL) {
        DBG_PRINTF("Cannot create file: %s", path + 1);
        ret = -1;
    }
    else {
        for (int i = 0; i < nb_blocks; i++) {
            memset(buf, i, sizeof(buf));
            fwrite(buf, 1, sizeof(buf), F);
            f_size += sizeof(buf);
        }
        F = picoquic_file_close(F);
    }

    if (ret == 0) {
        ret = demo_server_try_file_path((uint8_t*)path, strlen(path), &echo_size, &F, folder);
        if (ret != 0) {
            DBG_PRINTF("Could not try file path <%s> <%s>, ret = %d", folder, path, ret);
        }
        else if (echo_size != f_size) {
            DBG_PRINTF("Found size = %d instead of %d", (int)echo_size, (int)f_size);
            ret = -1;
        }
        else {
            for (int i = 0; ret == 0 && i < nb_blocks; i++) {
                int nb_read = (int)fread(buf, 1, sizeof(buf), F);
                if (nb_read != (int)sizeof(buf)) {
                    ret = -1;
                }
                else {
                    for (size_t j = 0; j < sizeof(buf); j++) {
                        if (buf[j] != i) {
                            ret = -1;
                            break;
                        }
                    }
                }
            }
        }

        if (F != NULL) {
            F = picoquic_file_close(F);
        }
    }

    if (ret == 0) {
        ret = remove(path + 1);
        if (ret != 0) {
            DBG_PRINTF("Could not remove %s", path + 1);
        }
    }

    if (ret == 0) {
        if (demo_server_try_file_path((uint8_t*)path, strlen(path), &echo_size, &F, folder) == 0) {
            DBG_PRINTF("Could open deleted file path <%s> <%s>", folder, path);
            ret = -1;
        }
        if (F != NULL) {
            F = picoquic_file_close(F);
        }
    }

    if (ret == 0) {
        if (demo_server_try_file_path((uint8_t*)bad_path, strlen(bad_path), &echo_size, &F, folder) == 0) {
            DBG_PRINTF("Could open deleted bad path <%s> <%s>", folder, bad_path);
            ret = -1;
        }
        if (F != NULL) {
            F = picoquic_file_close(F);
        }
    }

    return ret;
}


#define PICOQUIC_TEST_FILE_DEMO_FOLDER "picoquictest"

static const picoquic_demo_stream_desc_t file_test_scenario[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/file_test_ref.txt", "file_test_ref.txt", 0, 0 }
};

static size_t const demo_file_test_stream_length[] = {
    4499
};

static size_t nb_file_test_scenario = sizeof(file_test_scenario) / sizeof(picoquic_demo_stream_desc_t);

int serve_file_test_set_param(picohttp_server_parameters_t* file_param, char * buf, size_t buf_size)
{
    int ret = picoquic_get_input_path(buf, buf_size, picoquic_test_solution_dir, PICOQUIC_TEST_FILE_DEMO_FOLDER);

    memset(file_param, 0, sizeof(picohttp_server_parameters_t));
    file_param->web_folder = buf;

    return ret;
}


int demo_server_file_test()
{
    int ret = 0;
    char file_name_buffer[1024];
    picohttp_server_parameters_t file_param;

    ret = serve_file_test_set_param(&file_param, file_name_buffer, sizeof(file_name_buffer));

    if (ret == 0 && (ret = demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_server_callback, (void*)&file_param, 0, file_test_scenario, nb_file_test_scenario, demo_file_test_stream_length, 0, 0)) != 0) {
        DBG_PRINTF("H3 server (%s) file test fails, ret = %d\n", PICOHTTP_ALPN_H3_LATEST, ret);
    }

    if (ret == 0 && (ret = demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, (void*)&file_param, 0, file_test_scenario, nb_file_test_scenario, demo_file_test_stream_length, 0, 0)) != 0) {
        DBG_PRINTF("H09 server (%s) file test fails, ret = %d\n", PICOHTTP_ALPN_HQ_LATEST, ret);
    }

    if (ret == 0 && (ret = demo_server_test(PICOHTTP_ALPN_H3_LATEST, picoquic_demo_server_callback, (void*)&file_param, 0, file_test_scenario, nb_file_test_scenario, demo_file_test_stream_length, 0, 0)) != 0) {
        DBG_PRINTF("Demo server (%s) file test fails, ret = %d\n", PICOHTTP_ALPN_H3_LATEST, ret);
    }

    if (ret == 0 && (ret = demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_demo_server_callback, (void*)&file_param, 0, file_test_scenario, nb_file_test_scenario, demo_test_stream_length, 0, 0)) != 0) {
        DBG_PRINTF("Demo server (%s) file test fails, ret = %d\n", PICOHTTP_ALPN_HQ_LATEST, ret);
    }

    return ret;
}

static const picoquic_demo_stream_desc_t satellite_test_scenario[] = {
    { 0, 0, PICOQUIC_DEMO_STREAM_ID_INITIAL, "/10000000", "bin10M.txt", 0, 0 }
};

static const size_t nb_satellite_test_scenario = sizeof(satellite_test_scenario) / sizeof(picoquic_demo_stream_desc_t);

int h3zero_satellite_test()
{
    return demo_server_test(PICOHTTP_ALPN_H3_LATEST, h3zero_server_callback, NULL, 0, satellite_test_scenario, nb_satellite_test_scenario, demo_test_stream_length, 1, 10700000);
}

int h09_satellite_test()
{
    return demo_server_test(PICOHTTP_ALPN_HQ_LATEST, picoquic_h09_server_callback, NULL, 0, satellite_test_scenario, nb_satellite_test_scenario, demo_test_stream_length, 1, 10750000);
}