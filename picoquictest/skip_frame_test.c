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

#include "tls_api.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>

#include "logreader.h"
#include "qlog.h"

/*
 * Test of the skip frame API.
 * This test is only defined for the varint encodings -- the older fixed int
 * versions are obsolete by now.
 */

static uint8_t test_frame_type_padding[] = { 0, 0, 0 };

static uint8_t test_frame_type_reset_stream[] = {
    picoquic_frame_type_reset_stream,
    17,
    1,
    1
};

static uint8_t test_type_connection_close[] = {
    picoquic_frame_type_connection_close,
    0x80, 0x00, 0xCF, 0xFF, 0,
    9,
    '1', '2', '3', '4', '5', '6', '7', '8', '9'
};

static uint8_t test_type_application_close[] = {
    picoquic_frame_type_application_close,
    0,
    0
};

static uint8_t test_type_application_close_reason[] = {
    picoquic_frame_type_application_close,
    0x44, 4,
    4,
    't', 'e', 's', 't'
};

static uint8_t test_frame_type_max_data[] = {
    picoquic_frame_type_max_data,
    0xC0, 0, 0x01, 0, 0, 0, 0, 0
};

static uint8_t test_frame_type_max_stream_data[] = {
    picoquic_frame_type_max_stream_data,
    1,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_max_streams_bidir[] = {
    picoquic_frame_type_max_streams_bidir,
    0x41, 0
};

static uint8_t test_frame_type_max_streams_unidir[] = {
    picoquic_frame_type_max_streams_unidir,
    0x41, 7
};

static uint8_t test_frame_type_ping[] = {
    picoquic_frame_type_ping
};

static uint8_t test_frame_type_blocked[] = {
    picoquic_frame_type_data_blocked,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_stream_blocked[] = {
    picoquic_frame_type_stream_data_blocked,
    0x80, 1, 0, 0,
    0x80, 0x02, 0, 0
};

static uint8_t test_frame_type_streams_blocked_bidir[] = {
    picoquic_frame_type_streams_blocked_bidir,
    0x41, 0
};

static uint8_t test_frame_type_streams_blocked_unidir[] = {
    picoquic_frame_type_streams_blocked_unidir,
    0x81, 2, 3, 4
};

static uint8_t test_frame_type_new_connection_id[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_stop_sending[] = {
    picoquic_frame_type_stop_sending,
    17,
    0x17
};

static uint8_t test_frame_type_path_challenge[] = {
    picoquic_frame_type_path_challenge,
    1, 2, 3, 4, 5, 6, 7, 8
};

static uint8_t test_frame_type_path_response[] = {
    picoquic_frame_type_path_response,
    1, 2, 3, 4, 5, 6, 7, 8
};

static uint8_t test_frame_type_new_token[] = {
    picoquic_frame_type_new_token,
    17, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
};

static uint8_t test_frame_type_ack[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12
};
static uint8_t test_frame_type_ack_ecn[] = {
    picoquic_frame_type_ack_ecn,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0,
    5, 12,
    3, 0, 1
};

static uint8_t test_frame_type_stream_range_min[] = {
    picoquic_frame_type_stream_range_min,
    1,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_stream_range_max[] = {
    picoquic_frame_type_stream_range_min + 2 + 4,
    1,
    0x44, 0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_crypto_hs[] = {
    picoquic_frame_type_crypto_hs,
    0,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};


static uint8_t test_frame_type_retire_connection_id[] = {
    picoquic_frame_type_retire_connection_id,
    1
};

static uint8_t test_frame_type_datagram[] = {
    picoquic_frame_type_datagram,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_datagram_l[] = {
    picoquic_frame_type_datagram_l,
    0x10,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_handshake_done[] = {
    picoquic_frame_type_handshake_done
};

static uint8_t test_frame_type_ack_frequency[] = {
    0x40, picoquic_frame_type_ack_frequency,
    17, 0x0A, 0x44, 0x20
};

static uint8_t test_frame_type_time_stamp[] = {
    (uint8_t)(0x40 | (picoquic_frame_type_time_stamp >> 8)), (uint8_t)(picoquic_frame_type_time_stamp & 0xFF),
    0x44, 0
};

#define TEST_SKIP_ITEM(n, x, a, l, e) \
    {                              \
        n, x, sizeof(x), a, l, e     \
    }

test_skip_frames_t test_skip_list[] = {
    TEST_SKIP_ITEM("padding", test_frame_type_padding, 1, 0, 0),
    TEST_SKIP_ITEM("reset_stream", test_frame_type_reset_stream, 0, 0, 3),
    TEST_SKIP_ITEM("connection_close", test_type_connection_close, 0, 0, 3),
    TEST_SKIP_ITEM("application_close", test_type_application_close, 0, 0, 3),
    TEST_SKIP_ITEM("application_close", test_type_application_close_reason, 0, 0, 3),
    TEST_SKIP_ITEM("max_data", test_frame_type_max_data, 0, 0, 3),
    TEST_SKIP_ITEM("max_stream_data", test_frame_type_max_stream_data, 0, 0, 3),
    TEST_SKIP_ITEM("max_streams_bidir", test_frame_type_max_streams_bidir, 0, 0, 3),
    TEST_SKIP_ITEM("max_streams_unidir", test_frame_type_max_streams_unidir, 0, 0, 3),
    TEST_SKIP_ITEM("ping", test_frame_type_ping, 0, 0, 3),
    TEST_SKIP_ITEM("blocked", test_frame_type_blocked, 0, 0, 3),
    TEST_SKIP_ITEM("stream_data_blocked", test_frame_type_stream_blocked, 0, 0, 3),
    TEST_SKIP_ITEM("streams_blocked_bidir", test_frame_type_streams_blocked_bidir, 0, 0, 3),
    TEST_SKIP_ITEM("streams_blocked_unidir", test_frame_type_streams_blocked_unidir, 0, 0, 3),
    TEST_SKIP_ITEM("new_connection_id", test_frame_type_new_connection_id, 0, 0, 3),
    TEST_SKIP_ITEM("stop_sending", test_frame_type_stop_sending, 0, 0, 3),
    TEST_SKIP_ITEM("challenge", test_frame_type_path_challenge, 1, 0, 3),
    TEST_SKIP_ITEM("response", test_frame_type_path_response, 1, 0, 3),
    TEST_SKIP_ITEM("new_token", test_frame_type_new_token, 0, 0, 3),
    TEST_SKIP_ITEM("ack", test_frame_type_ack, 1, 0, 3),
    TEST_SKIP_ITEM("ack_ecn", test_frame_type_ack_ecn, 1, 0, 3),
    TEST_SKIP_ITEM("stream_min", test_frame_type_stream_range_min, 0, 1, 3),
    TEST_SKIP_ITEM("stream_max", test_frame_type_stream_range_max, 0, 0, 3),
    TEST_SKIP_ITEM("crypto_hs", test_frame_type_crypto_hs, 0, 0, 2),
    TEST_SKIP_ITEM("retire_connection_id", test_frame_type_retire_connection_id, 0, 0, 3),
    TEST_SKIP_ITEM("datagram", test_frame_type_datagram, 1, 1, 3),
    TEST_SKIP_ITEM("datagram_l", test_frame_type_datagram_l, 1, 0, 3),
    TEST_SKIP_ITEM("handshake_done", test_frame_type_handshake_done, 0, 0, 3),
    TEST_SKIP_ITEM("ack_frequency", test_frame_type_ack_frequency, 0, 0, 3),
    TEST_SKIP_ITEM("time_stamp", test_frame_type_time_stamp, 1, 0, 3)
};

size_t nb_test_skip_list = sizeof(test_skip_list) / sizeof(test_skip_frames_t);

static uint8_t test_frame_type_bad_reset_stream_offset[] = {
    picoquic_frame_type_reset_stream,
    17,
    1,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_reset_stream[] = {
    picoquic_frame_type_reset_stream,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    1,
    1
};

static uint8_t test_type_bad_connection_close[] = {
    picoquic_frame_type_connection_close,
    0x80, 0x00, 0xCF, 0xFF, 0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    '1', '2', '3', '4', '5', '6', '7', '8', '9'
};


static uint8_t test_type_bad_application_close[] = {
    picoquic_frame_type_application_close,
    0x44, 4,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    't', 'e', 's', 't'
};

static uint8_t test_frame_type_bad_max_stream_stream[] = {
    picoquic_frame_type_max_stream_data,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x80, 0x01, 0, 0
};

static uint8_t test_frame_type_max_bad_streams_bidir[] = {
    picoquic_frame_type_max_streams_bidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_max_streams_unidir[] = {
    picoquic_frame_type_max_streams_unidir,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static uint8_t test_frame_type_bad_new_cid_length[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0,
    0x3F,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_new_cid_retire[] = {
    picoquic_frame_type_new_connection_id,
    7,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_stop_sending[] = {
    picoquic_frame_type_stop_sending,
    19,
    0x17
};

static uint8_t test_frame_type_bad_new_token[] = {
    picoquic_frame_type_new_token,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17
};

static uint8_t test_frame_type_bad_ack_range[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,
    5, 12
};

static uint8_t test_frame_type_bad_ack_gaps[] = {
    picoquic_frame_type_ack,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    2,
    5,
    0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    5, 12
};

static uint8_t test_frame_type_bad_ack_blocks[] = {
    picoquic_frame_type_ack_ecn,
    0xC0, 0, 0, 1, 2, 3, 4, 5,
    0x44, 0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    5,
    0, 0,
    5, 12,
    3, 0, 1
};

static uint8_t test_frame_type_bad_crypto_hs[] = {
    picoquic_frame_type_crypto_hs,
    0,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_type_bad_datagram[] = {
    picoquic_frame_type_datagram_l,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};

static uint8_t test_frame_stream_hang[] = {
    0x01, 0x00, 0x0D, 0xFF, 0xFF, 0xFF, 0x01, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};



test_skip_frames_t test_frame_error_list[] = {
    TEST_SKIP_ITEM("bad_reset_stream_offset", test_frame_type_bad_reset_stream_offset, 0, 0, 3),
    TEST_SKIP_ITEM("bad_reset_stream", test_frame_type_bad_reset_stream, 0, 0, 3),
    TEST_SKIP_ITEM("bad_connection_close", test_type_bad_connection_close, 0, 0, 3),
    TEST_SKIP_ITEM("bad_application_close", test_type_bad_application_close, 0, 0, 3),
    TEST_SKIP_ITEM("bad_max_stream_stream", test_frame_type_bad_max_stream_stream, 0, 0, 3),
    TEST_SKIP_ITEM("bad_max_streams_bidir", test_frame_type_max_bad_streams_bidir, 0, 0, 3),
    TEST_SKIP_ITEM("bad_max_streams_unidir", test_frame_type_bad_max_streams_unidir, 0, 0, 3),
    TEST_SKIP_ITEM("bad_new_connection_id_length", test_frame_type_bad_new_cid_length, 0, 0, 3),
    TEST_SKIP_ITEM("bad_new_connection_id_retire", test_frame_type_bad_new_cid_retire, 0, 0, 3),
    TEST_SKIP_ITEM("bad_stop_sending", test_frame_type_bad_stop_sending, 0, 0, 3),
    TEST_SKIP_ITEM("bad_new_token", test_frame_type_bad_new_token, 0, 0, 3),
    TEST_SKIP_ITEM("bad_ack_range", test_frame_type_bad_ack_range, 1, 0, 3),
    TEST_SKIP_ITEM("bad_ack_gaps", test_frame_type_bad_ack_gaps, 1, 0, 3),
    TEST_SKIP_ITEM("bad_ack_blocks", test_frame_type_bad_ack_blocks, 1, 0, 3),
    TEST_SKIP_ITEM("bad_crypto_hs", test_frame_type_bad_crypto_hs, 0, 0, 2),
    TEST_SKIP_ITEM("bad_datagram", test_frame_type_bad_datagram, 1, 0, 3),
    TEST_SKIP_ITEM("stream_hang", test_frame_stream_hang, 1, 0, 3)
};

size_t nb_test_frame_error_list = sizeof(test_frame_error_list) / sizeof(test_skip_frames_t);

static size_t format_random_packet(uint8_t * bytes, size_t bytes_max, uint64_t * random_context, int epoch)
{
    size_t byte_index = 0;

    while (byte_index < bytes_max) {
        /* Pick a frame from the test list */
        uint64_t r = picoquic_test_uniform_random(random_context, nb_test_skip_list);
        if (epoch == -1 || test_skip_list[r].epoch == epoch) {
            /* stack it in the packet */
            if (byte_index + test_skip_list[r].len >= bytes_max) {
                break;
            }
            else {
                memcpy(bytes + byte_index, test_skip_list[r].val, test_skip_list[r].len);
                byte_index += test_skip_list[r].len;
                if (test_skip_list[r].must_be_last) {
                    break;
                }
            }
        }
    }

    return byte_index;
}

static int skip_test_packet(uint8_t * bytes, size_t bytes_max)
{
    int pure_ack;
    int ret = 0;
    size_t byte_index = 0;
    picoquic_cnx_t cnx;
    memset(&cnx, 0, sizeof(cnx));

    while (ret == 0 && byte_index < bytes_max) {
        size_t consumed;
        ret = picoquic_skip_frame(bytes + byte_index, bytes_max - byte_index, &consumed, &pure_ack);
        if (ret == 0) {
            byte_index += consumed;
        }
    }

    return ret;
}

static void skip_test_fuzz_packet(uint8_t * target, uint8_t * source, size_t bytes_max, uint64_t * random_context)
{
    size_t fuzz_index = (size_t) picoquic_test_uniform_random(random_context, bytes_max);
    size_t fuzz_length = (size_t) (picoquic_test_uniform_random(random_context, 8) + 1);
    uint64_t fuzz_data = picoquic_test_random(random_context);

    memcpy(target, source, bytes_max);

    for (size_t i = 0; i < fuzz_length && fuzz_index + i < bytes_max; i++) {
        target[fuzz_index + i] = (uint8_t)(fuzz_data & 0xFF);
        fuzz_data >>= 8;
    }
}

int skip_frame_test()
{
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t fuzz_buffer[PICOQUIC_MAX_PACKET_SIZE];
    const uint8_t extra_bytes[4] = { 0xFF, 0, 0, 0 };
    uint64_t random_context = 0xBABED011;
    int fuzz_count = 0;
    int fuzz_fail = 0;
    picoquic_cnx_t cnx;

    memset(&cnx, 0, sizeof(cnx)); /* Null value gets default test version */

    for (size_t i = 0; i < nb_test_skip_list; i++) {
        for (int sharp_end = 0; sharp_end < 2; sharp_end++) {
            size_t consumed = 0;
            size_t byte_max = 0;
            int pure_ack;
            int t_ret = 0;

            memcpy(buffer, test_skip_list[i].val, test_skip_list[i].len);
            byte_max = test_skip_list[i].len;
            if (test_skip_list[i].must_be_last == 0 && sharp_end == 0) {
                memcpy(buffer + byte_max, extra_bytes, sizeof(extra_bytes));
                byte_max += sizeof(extra_bytes);
            }

            t_ret = picoquic_skip_frame(buffer, byte_max, &consumed, &pure_ack);

            if (t_ret != 0) {
                DBG_PRINTF("Skip frame <%s> fails, ret = %d\n", test_skip_list[i].name, t_ret);
                ret = t_ret;
            }
            else if (consumed != test_skip_list[i].len) {
                DBG_PRINTF("Skip frame <%s> fails, wrong length, %d instead of %d\n",
                    test_skip_list[i].name, (int)consumed, (int)test_skip_list[i].len);
                ret = -1;
            }
            else if (pure_ack != test_skip_list[i].is_pure_ack) {
                DBG_PRINTF("Skip frame <%s> fails, wrong pure ack, %d instead of %d\n",
                    test_skip_list[i].name, (int)pure_ack, (int)test_skip_list[i].is_pure_ack);
                ret = -1;
            }
        }
    }

    /* Check a series of known bad packets. We are checking that an error is
     * detected and no adverse code issue happens. */
    for (size_t i = 0; i < nb_test_frame_error_list; i++) {
        for (int sharp_end = 0; sharp_end < 2; sharp_end++) {
            size_t consumed = 0;
            size_t byte_max = 0;
            int pure_ack;
            int t_ret = 0;

            memcpy(buffer, test_frame_error_list[i].val, test_frame_error_list[i].len);
            byte_max = test_frame_error_list[i].len;
            if (test_frame_error_list[i].must_be_last == 0 && sharp_end == 0) {
                memcpy(buffer + byte_max, extra_bytes, sizeof(extra_bytes));
                byte_max += sizeof(extra_bytes);
            }

            t_ret = picoquic_skip_frame(buffer, byte_max, &consumed, &pure_ack);

            if (t_ret == 0) {
                DBG_PRINTF("Skip error frame <%s> does not fails, ret = %d\n", test_frame_error_list[i].name, t_ret);
            }
        }
    }

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context, -1);

        ret = skip_test_packet(buffer, bytes_max);
        if (ret != 0) {
            DBG_PRINTF("Skip packet <%d> fails, ret = %d\n", i, ret);
        } else {
            /* do the actual fuzz test */
            int suspended = debug_printf_reset(1);
            for (size_t j = 0; j < 100; j++) {
                skip_test_fuzz_packet(fuzz_buffer, buffer, bytes_max, &random_context);
                if (skip_test_packet(fuzz_buffer, bytes_max) != 0) {
                    fuzz_fail++;
                }
                fuzz_count++;
            }
            (void)debug_printf_reset(suspended);
        }
    }

    if (ret == 0) {
        DBG_PRINTF("Fuzz skip test passes after %d trials, %d error detected\n",
            fuzz_count, fuzz_fail);
    }

    return ret;
}

int parse_test_packet(picoquic_quic_t* qclient, struct sockaddr* saddr, uint64_t simulated_time,
    uint8_t * buffer, size_t byte_max, int epoch,  int* ack_needed)
{
    int ret = 0;
    picoquic_packet_context_enum pc = picoquic_context_from_epoch(epoch);
    picoquic_cnx_t* cnx = picoquic_create_cnx(qclient,
        picoquic_null_connection_id, picoquic_null_connection_id, saddr,
        simulated_time, 0, "test-sni", "test-alpn", 1);


    *ack_needed = 0;

    if (cnx == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
        ret = -1;
    }
    else {
        /* Stupid fix to ensure that the NCID decoding test will not protest */
        cnx->path[0]->remote_cnxid.id_len = 8;

        cnx->pkt_ctx[0].send_sequence = 0x0102030406;

        /* create a local cid  which can be retired with a connection_id_retire frame */
        (void)picoquic_create_local_cnxid(cnx, NULL);

        /* enable time stamp so it can be used in test */
        cnx->is_time_stamp_enabled = 1;

        /* Set min ack delay so there is no issue with ack frequency frame */
        cnx->is_ack_frequency_negotiated = 1;
        cnx->remote_parameters.min_ack_delay = 1000;

        /* if testing handshake done, set state to ready so frame is ignored. */
        if (epoch == 3) {
            cnx->cnx_state = picoquic_state_ready;
        }

        ret = picoquic_decode_frames(cnx, cnx->path[0], buffer, byte_max, epoch, NULL, NULL, simulated_time);

        *ack_needed = cnx->pkt_ctx[pc].ack_needed;

        if (ret == 0 &&
            (cnx->cnx_state == picoquic_state_disconnecting ||
                cnx->cnx_state == picoquic_state_handshake_failure)) {
            ret = -1;
        }

        picoquic_delete_cnx(cnx);

    }

    return ret;
}

int parse_frame_test()
{
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t fuzz_buffer[PICOQUIC_MAX_PACKET_SIZE];
    const uint8_t extra_bytes[4] = { 0, 0, 0, 0 };
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    picoquic_quic_t * qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    uint64_t random_context = 0x12345678;
    int fuzz_fail = 0;
    int fuzz_count = 0;

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    if (qclient == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }

    for (size_t i = 0x0C; ret == 0 && i < nb_test_skip_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            size_t byte_max = 0;
            int t_ret = 0;
            int ack_needed = 0;

            memcpy(buffer, test_skip_list[i].val, test_skip_list[i].len);
            byte_max = test_skip_list[i].len;
            if (test_skip_list[i].must_be_last == 0 && sharp_end == 0) {
                /* add some padding to check that the end of frame is detected properly */
                memcpy(buffer + byte_max, extra_bytes, sizeof(extra_bytes));
                byte_max += sizeof(extra_bytes);
            }

            t_ret = parse_test_packet(qclient, (struct sockaddr*) & saddr, simulated_time,
                buffer, byte_max, test_skip_list[i].epoch, &ack_needed);

            if (t_ret != 0) {
                DBG_PRINTF("Parse frame <%s> fails, ret = %d\n", test_skip_list[i].name, t_ret);
                ret = t_ret;
            }
            else if ((ack_needed != 0 && test_skip_list[i].is_pure_ack != 0) ||
                (ack_needed == 0 && test_skip_list[i].is_pure_ack == 0)) {
                DBG_PRINTF("Parse frame <%s> fails, ack needed: %d, expected pure ack: %d\n",
                    test_skip_list[i].name, ack_needed, (int)test_skip_list[i].is_pure_ack);
                ret = -1;
            }
        }
    }

    /* Decode a series of known bad packets */
    for (size_t i = 0; ret == 0 && i < nb_test_frame_error_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            size_t byte_max = 0;
            int t_ret = 0;
            int ack_needed = 0;

            memcpy(buffer, test_frame_error_list[i].val, test_frame_error_list[i].len);
            byte_max = test_frame_error_list[i].len;
            if (test_frame_error_list[i].must_be_last == 0 && sharp_end == 0) {
                /* add some padding to check that the end of frame is detected properly */
                memcpy(buffer + byte_max, extra_bytes, sizeof(extra_bytes));
                byte_max += sizeof(extra_bytes);
            }

            t_ret = parse_test_packet(qclient, (struct sockaddr*) & saddr, simulated_time,
                buffer, byte_max, test_frame_error_list[i].epoch, &ack_needed);

            if (t_ret == 0) {
                DBG_PRINTF("Parse error frame <%s> does not fails, ret = %d\n", test_frame_error_list[i].name, t_ret);
                ret = -1;
            }
        }
    }

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        int ack_needed;
        size_t bytes_max = sizeof(buffer);
        size_t byte_index;

        /* Pick a frame at random and copy it at the beginning of the packet */
        uint64_t r;
        do {
            r = picoquic_test_uniform_random(&random_context, nb_test_skip_list);
        } while (test_skip_list[r].epoch != 3);
        memcpy(buffer, test_skip_list[r].val, test_skip_list[r].len);
        byte_index = test_skip_list[r].len;

        if (!test_skip_list[r].must_be_last) {
            r = picoquic_test_uniform_random(&random_context, 4);

            switch (r) {
            case 0:
                memcpy(buffer + byte_index, test_frame_type_ack, sizeof(test_frame_type_ack));
                byte_index += sizeof(test_frame_type_ack);
                break;
            case 1:
                memcpy(buffer + byte_index, test_frame_type_stream_range_max, sizeof(test_frame_type_stream_range_max));
                byte_index += sizeof(test_frame_type_stream_range_max);
                break;
            case 2:
                memset(buffer + byte_index, 0, bytes_max - byte_index);
                byte_index = bytes_max;
                break;
            default:
                break;
            }
        }
        bytes_max = byte_index;

        ret = parse_test_packet(qclient, (struct sockaddr*) & saddr, simulated_time,
            buffer, bytes_max, 3, &ack_needed);
        if (ret != 0)
        {
            DBG_PRINTF("Skip packet <%d> fails, ret = %d\n", i, ret);
        } else {
            /* do the actual fuzz test */
            int suspended = debug_printf_reset(1);
            for (size_t j = 0; j < 100; j++) {
                skip_test_fuzz_packet(fuzz_buffer, buffer, bytes_max, &random_context);
                if (parse_test_packet(qclient, (struct sockaddr*) & saddr, simulated_time,
                    fuzz_buffer, bytes_max, 3, &ack_needed) != 0) {
                    fuzz_fail++;
                }
                fuzz_count++;
            }
            (void)debug_printf_reset(suspended);
        }
    }

    if (ret == 0) {
        DBG_PRINTF("Fuzz skip test passes after %d trials, %d error detected\n",
            fuzz_count, fuzz_fail);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

void picoquic_log_frames(FILE* F, uint64_t cnx_id64, uint8_t* bytes, size_t length);
void picoquic_binlog_frames(FILE* F, uint8_t* bytes, size_t length);

static char const* log_test_file = "log_test.txt";
static char const* log_error_test_file = "log_error_test.txt";
static char const* log_fuzz_test_file = "log_fuzz_test.txt";
static char const* log_packet_test_file = "log_fuzz_test.txt";
static char const* binlog_test_file = "01020304.client.log";
static char const* binlog_error_test_file = "binlog_error_test.txt";
static char const* binlog_fuzz_test_file = "binlog_fuzz_test.log";
static char const* qlog_test_file = "01020304.qlog";

#define LOG_TEST_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "log_test_ref.txt"
#define BINLOG_TEST_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "binlog_ref.log"
#define QLOG_TEST_REF "picoquictest" PICOQUIC_FILE_SEPARATOR "binlog_ref.qlog"

static int compare_lines(char const* b1, char const* b2)
{
    while (*b1 != 0 && *b2 != 0) {
        if (*b1 != *b2) {
            break;
        }
        b1++;
        b2++;
    }

    while (*b1 == '\n' || *b1 == '\r') {
        b1++;
    }

    while (*b2 == '\n' || *b2 == '\r') {
        b2++;
    }

    return (*b1 == 0 && *b2 == 0) ? 0 : -1;
}

int picoquic_compare_text_files(char const * fname1, char const * fname2, FILE * F1, FILE * F2)
{
    int ret = 0;
    int nb_line = 0;

    char buffer1[256];
    char buffer2[256];

    while (ret == 0 && fgets(buffer1, sizeof(buffer1), F1) != NULL) {
        nb_line++;
        if (fgets(buffer2, sizeof(buffer2), F2) == NULL) {
            /* F2 is too short */
            DBG_PRINTF("File %s is shorter than %s\n", fname2, fname1);
            DBG_PRINTF("    Missing line %d: %s", nb_line, buffer1);
            ret = -1;
        } else {
            ret = compare_lines(buffer1, buffer2);
            if (ret != 0)
            {
                DBG_PRINTF("File %s differs %s at line %d\n", fname2, fname1, nb_line);
                DBG_PRINTF("    Got: %s", buffer1);
                DBG_PRINTF("    Vs:  %s", buffer2);
            }
        }
    }

    if (ret == 0 && fgets(buffer2, sizeof(buffer2), F2) != NULL) {
        /* F2 is too long */
        DBG_PRINTF("File %s is longer than %s\n", fname2, fname1);
        DBG_PRINTF("    Extra line %d: %s", nb_line+1, buffer2);
        ret = -1;
    }

    return ret;
}

static int picoquic_compare_binary_files(char const* fname1, char const* fname2, FILE* f1, FILE* f2)
{
    int more_data = 0;
    int ret = 0;

    do
    {
        uint8_t buffer1[256];
        uint8_t buffer2[256];
        size_t len1 = fread(buffer1, 1, sizeof(buffer1), f1);
        size_t len2 = fread(buffer2, 1, sizeof(buffer2), f2);

        if (ret == 0 && len1 != len2) {
            DBG_PRINTF("Length %s=%z, %s=%z", fname1, len1, fname2, len2);
            ret = -1;
        }
        if (ret == 0 && memcmp(buffer1, buffer2, len1) != 0) {
            DBG_PRINTF("Content does not match for  %s, %s", fname1, fname2);
            ret = -1;
        }

        more_data = len1 == sizeof(buffer1);

    } while (ret == 0 && more_data);

    return ret;
}

int picoquic_test_compare_files(char const* fname1, char const* fname2, const char* mode,
    int (*compare)(char const* fname1, char const* fname2, FILE* f1, FILE* f2))
{
    FILE* f1 = picoquic_file_open(fname1, mode);
    FILE* f2 = picoquic_file_open(fname2, mode);
    int ret = 0;

    if (f1 == NULL || f2 == NULL) {
        DBG_PRINTF("Cannot open file %s\n", f1 == NULL ? fname1 : fname2);
        ret = -1;
    }
    else {
        ret = compare(fname1, fname2, f1, f2);
    }

    (void)picoquic_file_close(f1);
    (void)picoquic_file_close(f2);

    return ret;
}

int picoquic_test_compare_text_files(char const* fname1, char const* fname2)
{
    return picoquic_test_compare_files(fname1, fname2, "r", picoquic_compare_text_files);
}

int picoquic_test_compare_binary_files(char const* fname1, char const* fname2)
{
    return picoquic_test_compare_files(fname1, fname2, "rb", picoquic_compare_binary_files);
}

uint8_t log_test_ticket[] = {
    0x00, 0x00, 0x01, 0x68, 0x87, 0x88, 0x91, 0x60,
    0x00, 0x17, 0x13, 0x02, 0x00, 0x00, 0x3d, 0x00,
    0x00, 0x1c, 0x20, 0x3f, 0xc0, 0x96, 0x0b, 0x08,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x20, 0x70, 0x95, 0x61, 0xe2, 0xaa, 0x2b,
    0x6d, 0x59, 0x20, 0x6f, 0xbe, 0x00, 0xa5, 0x2f,
    0x1d, 0x2f, 0x59, 0x36, 0xb1, 0x65, 0x6a, 0xc4,
    0xdb, 0xb5, 0xde, 0x20, 0x3c, 0x85, 0x74, 0xf4,
    0xe8, 0x97, 0x00, 0x08, 0x00, 0x2a, 0x00, 0x04,
    0xff, 0xff, 0xff, 0xff, 0x00, 0x30, 0xc1, 0xcd,
    0xe8, 0x9f, 0x4c, 0x9d, 0x7c, 0x58, 0x14, 0xd6,
    0x09, 0xb7, 0xac, 0x01, 0xe1, 0xcb, 0xca, 0x4e,
    0x9c, 0xb6, 0x72, 0x72, 0x21, 0xa4, 0xd8, 0x58,
    0x3d, 0xf5, 0x58, 0x1e, 0x7d, 0x2a, 0x22, 0x38,
    0xa4, 0x00, 0xa0, 0xae, 0x08, 0x61, 0xb2, 0xa7,
    0x08, 0xab, 0xe5, 0xe2, 0xd4, 0x16 };

static const picoquic_connection_id_t logger_test_cid =
{ { 11, 12, 13, 14, 15, 16, 17, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 8 };

int logger_test()
{
    FILE* F = NULL;
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t fuzz_buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t random_context = 0xF00BAB;
    picoquic_cnx_t cnx;
    picoquic_quic_t quic;
    memset(&cnx, 0, sizeof(cnx));

    if ((F = picoquic_file_open(log_test_file, "w")) == NULL) {
        DBG_PRINTF("failed to open file:%s\n", log_test_file);
        ret = -1;
    }
    else {
        for (size_t i = 0; i < nb_test_skip_list; i++) {
            picoquic_log_frames(F, 0, test_skip_list[i].val, test_skip_list[i].len);
        }
        picoquic_log_picotls_ticket(F, logger_test_cid,
            log_test_ticket, (uint16_t) sizeof(log_test_ticket));

        cnx.initial_cnxid = logger_test_cid;
        cnx.quic = &quic;
        quic.F_log = F;

        picoquic_log_app_message(&cnx, "%s.", "This is an app message test");
        picoquic_log_app_message(&cnx, "This is app message test #%d, severity %d.", 1, 2);

        (void)picoquic_file_close(F);
    }

    if (ret == 0) {
        char log_test_ref[512];

        ret = picoquic_get_input_path(log_test_ref, sizeof(log_test_ref), picoquic_solution_dir, LOG_TEST_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the log ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(log_test_file, log_test_ref);
        }
    }

    /* Create a set of randomized packets. Verify that they can be logged without
     * causing the dreaded "Unknown frame" message */

    for (size_t i = 0; ret == 0 && i < 100; i++) {
        char log_line[1024];
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context, -1);

        if ((F = picoquic_file_open(log_packet_test_file, "w")) == NULL) {
            DBG_PRINTF("failed to open file:%s\n", log_packet_test_file);
            ret = -1;
            break;
        }
        else {
            ret &= fprintf(F, "Log packet test #%d\n", (int)i);
            picoquic_log_frames(F, 0, buffer, bytes_max);
            (void)picoquic_file_close(F);
        }

        if ((F = picoquic_file_open(log_packet_test_file, "w")) == NULL) {
            DBG_PRINTF("failed to open file:%s\n", log_packet_test_file);
            ret = PICOQUIC_ERROR_INVALID_FILE;
            break;
        } else {
            while (fgets(log_line, (int)sizeof(log_line), F) != NULL) {
                /* skip blanks */
                size_t byte_index = 0;

                while (byte_index < sizeof(log_line) &&
                    (log_line[byte_index] == ' ' || log_line[byte_index] == '\t')) {
                    byte_index++;
                }

                if (byte_index + 7u < sizeof(log_line) &&
                    memcmp(&log_line[byte_index], "Unknown", 7) == 0)
                {
                    DBG_PRINTF("Packet log test #%d failed, unknown frame.\n", (int)i);
                    ret = -1;
                    break;
                }
            }
            (void)picoquic_file_close(F);
        }
    }


    /* Log a series of known bad packets  */
    for (size_t i = 0; ret == 0 && i < nb_test_frame_error_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            uint8_t extra_bytes[4] = { 0, 0, 0, 0 };
            size_t bytes_max = 0;
            FILE* F = NULL;

            if ((F = picoquic_file_open(log_error_test_file, "w")) == NULL) {
                DBG_PRINTF("failed to open file:%s\n", log_error_test_file);
                ret = PICOQUIC_ERROR_INVALID_FILE;
                break;
            }

            memcpy(buffer, test_frame_error_list[i].val, test_frame_error_list[i].len);
            bytes_max = test_frame_error_list[i].len;
            if (test_frame_error_list[i].must_be_last == 0 && sharp_end == 0) {
                /* add some padding to check that the end of frame is detected properly */
                memcpy(buffer + bytes_max, extra_bytes, sizeof(extra_bytes));
                bytes_max += sizeof(extra_bytes);
            }

            picoquic_log_frames(F, 0, buffer, bytes_max);

            (void)picoquic_file_close(F);
        }
    }

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context, -1);

        if ((F = picoquic_file_open(log_fuzz_test_file, "w")) == NULL) {
            DBG_PRINTF("failed to open file:%s\n", log_fuzz_test_file);
            ret = PICOQUIC_ERROR_INVALID_FILE;
            break;
        }

        ret &= fprintf(F, "Log fuzz test #%d\n", (int)i);
        picoquic_log_frames(F, 0, buffer, bytes_max);

        /* Attempt to log fuzzed packets, and hope nothing crashes */
        for (size_t j = 0; j < 100; j++) {
            ret &= fprintf(F, "Log fuzz test #%d, packet %d\n", (int)i, (int)j);
            fflush(F);
            skip_test_fuzz_packet(fuzz_buffer, buffer, bytes_max, &random_context);
            picoquic_log_frames(F, 0, fuzz_buffer, bytes_max);
        }
        (void)picoquic_file_close(F);
    }

    return ret;
}

// From logwriter.c
FILE* create_binlog(char const* binlog_file, uint64_t creation_time);

void binlog_new_connection(picoquic_cnx_t* cnx);

void binlog_packet(FILE* f, const picoquic_connection_id_t* cid, int receiving, uint64_t current_time,
    const picoquic_packet_header* ph, const uint8_t* bytes, size_t bytes_max);

int binlog_test()
{
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t fuzz_buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t random_context = 0xF00BAB;
    int ret = 0;

    const picoquic_connection_id_t initial_cid = {
        { 1, 2, 3, 4 }, 4
    };

    const picoquic_connection_id_t dest_cid = {
        { 5, 6, 7, 8 }, 4
    };

    char log_test_ref[512];
    int ret_bin = picoquic_get_input_path(log_test_ref, sizeof(log_test_ref), picoquic_solution_dir, BINLOG_TEST_REF);

    char qlog_test_ref[512];
    int ret_qlog = picoquic_get_input_path(qlog_test_ref, sizeof(qlog_test_ref), picoquic_solution_dir, QLOG_TEST_REF);

    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    } else if (ret_bin != 0 || ret_qlog != 0) {
        DBG_PRINTF("%s", "Cannot set the log ref file name.\n");
        ret = -1;
    }
    else {
        picoquic_set_binlog(quic, ".");        
        picoquic_set_default_spinbit_policy(quic, picoquic_spinbit_null);

        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(struct sockaddr_in));
        picoquic_cnx_t* cnx = picoquic_create_cnx(quic, initial_cid, dest_cid, (struct sockaddr*) & saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
            ret = -1;
        } else {
            for (size_t i = 0; i < nb_test_skip_list; i++) {

                picoquic_packet_header ph;
                memset(&ph, 0, sizeof(ph));

                ph.ptype = picoquic_packet_1rtt_protected;
                ph.pn64 = i;
                ph.dest_cnx_id = initial_cid;
                ph.srce_cnx_id = dest_cid;

                ph.offset = 0;
                ph.payload_length = test_skip_list[i].len;

                binlog_packet(cnx->f_binlog, &initial_cid, 0, 0, &ph, test_skip_list[i].val, test_skip_list[i].len);
            }

            picoquic_delete_cnx(cnx);
        }
    }

    picoquic_free(quic);

    if (ret == 0) {
        ret_bin = picoquic_test_compare_binary_files(binlog_test_file, log_test_ref);
        if (ret_bin != 0) {
            DBG_PRINTF("%s", "Unexpected content in binary log file.\n");
        }

        /* Convert to QLOG and verify */
        uint64_t log_time = 0;
        FILE* f_binlog = picoquic_open_cc_log_file_for_read(binlog_test_file, &log_time);
        
        ret = qlog_convert(&initial_cid, f_binlog, binlog_test_file, NULL, ".");
        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot convert the binary log into QLOG.\n");
        } else {
            /* When changing the reference QLOG file please verify the new file at:
                https://qvis.edm.uhasselt.be/#/files */
            ret_qlog = picoquic_test_compare_text_files(qlog_test_file, qlog_test_ref);
            if (ret_qlog != 0) {
                DBG_PRINTF("%s", "Unexpected content in QLOG log file.\n");
            }
        }

        if (ret_bin != 0 || ret_qlog != 0) {
            ret = -1;
        }
    }


    /* Log a series of known bad packets  */
    for (size_t i = 0; ret == 0 && i < nb_test_frame_error_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            uint8_t extra_bytes[4] = { 0, 0, 0, 0 };
            size_t bytes_max = 0;
            FILE* F = NULL;

            if ((F = picoquic_file_open(binlog_error_test_file, "wb")) == NULL) {
                DBG_PRINTF("failed to open file:%s\n", binlog_error_test_file);
                ret = PICOQUIC_ERROR_INVALID_FILE;
                break;
            }

            memcpy(buffer, test_frame_error_list[i].val, test_frame_error_list[i].len);
            bytes_max = test_frame_error_list[i].len;
            if (test_frame_error_list[i].must_be_last == 0 && sharp_end == 0) {
                /* add some padding to check that the end of frame is detected properly */
                memcpy(buffer + bytes_max, extra_bytes, sizeof(extra_bytes));
                bytes_max += sizeof(extra_bytes);
            }

            picoquic_binlog_frames(F, buffer, bytes_max);

            (void)picoquic_file_close(F);
        }
    }

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context, -1);
        FILE* F;

        if ((F = picoquic_file_open(binlog_fuzz_test_file, "wb")) == NULL) {
            DBG_PRINTF("failed to open file:%s\n", log_fuzz_test_file);
            ret = PICOQUIC_ERROR_INVALID_FILE;
            break;
        }

        picoquic_binlog_frames(F, buffer, bytes_max);

        /* Attempt to log fuzzed packets, and hope nothing crashes */
        for (size_t j = 0; j < 100; j++) {
            fflush(F);
            skip_test_fuzz_packet(fuzz_buffer, buffer, bytes_max, &random_context);
            picoquic_binlog_frames(F, fuzz_buffer, bytes_max);
        }
        (void)picoquic_file_close(F);
    }

    return ret;
}

/* Basic test of connection ID stash, part of migration support  */
static const picoquic_cnxid_stash_t stash_test_case[] = {
    { NULL,  1,{ { 0, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 },
{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } },
{ NULL,  2,{ { 1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 },
{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 } },
{ NULL,  3,{ { 2, 3, 4, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 },
{ 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17 } }
};

static const picoquic_connection_id_t stash_test_init_local =
    { { 11, 11, 11, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 };

static const picoquic_connection_id_t stash_test_init_remote =
{ { 99, 99, 99, 99, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4 };

static const size_t nb_stash_test_case = sizeof(stash_test_case) / sizeof(picoquic_cnxid_stash_t);

static int cnxid_stash_compare(int test_mode, picoquic_cnxid_stash_t * stashed, size_t i)
{
    int ret = 0;

    if (stashed == NULL) {
        DBG_PRINTF("Test %d, cannot dequeue cnxid %d.\n", test_mode, i);
        ret = -1;
    }
    else if (stashed->sequence != stash_test_case[i].sequence) {
        DBG_PRINTF("Test %d, cnxid %d, sequence %d instead of %d.\n", test_mode, i,
            stashed->sequence, stash_test_case[i].sequence);
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&stashed->cnx_id, &stash_test_case[i].cnx_id) != 0) {
        DBG_PRINTF("Test %d, cnxid %d, CNXID values do not match.\n", test_mode, i);
        ret = -1;
    }
    else if (memcmp(&stashed->reset_secret, &stash_test_case[i].reset_secret, PICOQUIC_RESET_SECRET_SIZE) != 0) {
        DBG_PRINTF("Test %d, cnxid %d, secrets do not match.\n", test_mode, i);
        ret = -1;
    }

    return ret;
}

int cnxid_stash_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    picoquic_quic_t * qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);


    memset(&saddr, 0, sizeof(struct sockaddr_in));
    if (qclient == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }

    /* First test: enqueue and dequeue immediately */
    /* Second test: enqueue all and then dequeue - verify order */
    /* Third test: enqueue all and then delete the connection */
    for (int test_mode = 0; ret == 0 && test_mode < 3; test_mode++) {
        picoquic_cnx_t * cnx = picoquic_create_cnx(qclient,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        picoquic_cnxid_stash_t * stashed = NULL;

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
            ret = -1;
        } else {
            /* init the various connection id to a length compatible with test */
            cnx->path[0]->p_local_cnxid->cnx_id = stash_test_init_local;
            cnx->path[0]->remote_cnxid = stash_test_init_remote;
        }

        for (size_t i = 0; ret == 0 && i < nb_stash_test_case; i++) {
            ret = picoquic_enqueue_cnxid_stash(cnx,
                stash_test_case[i].sequence, stash_test_case[i].cnx_id.id_len,
                stash_test_case[i].cnx_id.id, stash_test_case[i].reset_secret, &stashed);
            if (ret != 0) {
                DBG_PRINTF("Test %d, cannot stash cnxid %d, err %x.\n", test_mode, i, ret);
            } else {
                if (stashed == NULL) {
                    DBG_PRINTF("Test %d, cannot stash cnxid %d (duplicate).\n", test_mode, i);
                    ret = -1;
                }
                else if (test_mode == 0) {
                    stashed = picoquic_dequeue_cnxid_stash(cnx);
                    ret = cnxid_stash_compare(test_mode, stashed, i);
                }
            }
        }

        /* Dequeue all in mode 1, verify order */
        if (test_mode == 1) {
            for (size_t i = 0; ret == 0 && i < nb_stash_test_case; i++) {
                stashed = picoquic_dequeue_cnxid_stash(cnx);
                ret = cnxid_stash_compare(test_mode, stashed, i);
            }
        }

        /* Verify nothing left in queue in mode 0, 1 */
        if (test_mode < 2) {
            stashed = picoquic_dequeue_cnxid_stash(cnx);
            if (stashed != NULL) {
                DBG_PRINTF("Test %d, unexpected cnxid left, #%d.\n", test_mode, (int)stashed->sequence);
                ret = -1;
            }
        }

        /* Delete the connecton and free the stash */
        picoquic_delete_cnx(cnx);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

int new_cnxid_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    picoquic_quic_t * qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    picoquic_cnx_t * cnx = NULL;
    uint8_t frame_buffer[256];
    size_t consumed = 0;

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = 1000;

    if (qclient == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    } else {
        cnx = picoquic_create_cnx(qclient,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
            ret = -1;
        }
        else {
            /* Create a new local CID */
            picoquic_local_cnxid_t* local_cid = picoquic_create_local_cnxid(cnx, NULL);
            
            if (local_cid == NULL) {
                DBG_PRINTF("%s", "Cannot create local cnxid\n");
                ret = -1;
            }
            if (cnx->nb_local_cnxid != 2) {
                DBG_PRINTF("Expected 2 CID, got %d\n", cnx->nb_local_cnxid);
                ret = -1;
            }
            else if (cnx->local_cnxid_first == NULL || cnx->local_cnxid_first->next == NULL) {
                DBG_PRINTF("%s", "Pointer to CID is NULL in cnx context\n");
                ret = -1;
            }

            if (ret == 0) {
                int more_data = 0;
                int is_pure_ack = 1;
                uint8_t* bytes_next = picoquic_format_new_connection_id_frame(cnx, frame_buffer, frame_buffer + sizeof(frame_buffer),
                    &more_data, &is_pure_ack, local_cid);

                consumed = bytes_next - frame_buffer;

                if (consumed == 0) {
                    ret = -1;
                    DBG_PRINTF("Cannot encode new connection ID frame, ret = %x\n", ret);
                }
            }

            if (ret == 0) {
                size_t skipped = 0;
                int pure_ack = 0;

                ret = picoquic_skip_frame(frame_buffer, sizeof(frame_buffer), &skipped, &pure_ack);

                if (ret != 0) {
                    DBG_PRINTF("Cannot skip connection ID frame, ret = %x\n", ret);
                }
                else if (skipped != consumed) {
                    DBG_PRINTF("Skipped %d bytes instead of %d\n", (int)skipped, (int)consumed);
                    ret = -1;
                }
                else if (pure_ack != 0) {
                    DBG_PRINTF("Pure ACK = %d instead of 0\n", (int)pure_ack);
                    ret = -1;
                }
            }
            /* Delete the connecton and free the stash */
            picoquic_delete_cnx(cnx);
        }

        picoquic_free(qclient);
    }

    return ret;
}

/*
 * Test the copy for retransmit function
 */

#define SPLIT_FRAME_TEST_SOURCE_CONTENT_67 \
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, \
   11, 12, 13, 14, 15, 16, 17, 18, 19, 20, \
   21, 22, 23, 24, 25, 26, 27, 28, 29, 30, \
   31, 32, 33, 34, 35, 36, 37, 38, 39, 40, \
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, \
   51, 52, 53, 54, 55, 56, 57, 58, 59, 60, \
   61, 62, 63, 64, 65, 66, 67

#define SPLIT_FRAME_TEST_SOURCE_CONTENT_INIT_32 \
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, \
   11, 12, 13, 14, 15, 16, 17, 18, 19, 20, \
   21, 22, 23, 24, 25, 26, 27, 28, 29, 30, \
   31, 32

#define SPLIT_FRAME_TEST_SOURCE_CONTENT_LAST_35 \
   33, 34, 35, 36, 37, 38, 39, 40, \
   41, 42, 43, 44, 45, 46, 47, 48, 49, 50, \
   51, 52, 53, 54, 55, 56, 57, 58, 59, 60, \
   61, 62, 63, 64, 65, 66, 67

#define COPY_PACKET_CID_DEST 1,2,3,4,5,6,7,8

#define SIZEOF_CID_DEST 8

#define COPY_PACKET_HEADER_1RTT 0x43, COPY_PACKET_CID_DEST, 0, 0, 0, 1

#define SIZEOF_1RTT_HEADER (SIZEOF_CID_DEST + 5)

#define SPLIT_FRAME_TEST_SOURCE_68_77 68,69,70,71,72,73,74,75,76,77

static uint8_t ct_stream0_data[] = { SPLIT_FRAME_TEST_SOURCE_CONTENT_67, SPLIT_FRAME_TEST_SOURCE_68_77 };

static uint8_t ct_test_packet1[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min | 2, 0x00, 0x40, 67,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67
};

static uint8_t ct_test_packet2[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67 };

static uint8_t ct_test_packet3[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67, SPLIT_FRAME_TEST_SOURCE_68_77
};

static uint8_t ct_test_packet4[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x40, 67, 0x0A,
    SPLIT_FRAME_TEST_SOURCE_68_77,
    picoquic_frame_type_stream_range_min, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67
};

uint8_t ct_test_packet4_first_frame[] = {
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x40, 67, 0x0A,
    SPLIT_FRAME_TEST_SOURCE_68_77 };

static uint8_t ct_test_packet5[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x40, 67, 0x0A,
    SPLIT_FRAME_TEST_SOURCE_68_77,
    picoquic_frame_type_stream_range_min | 2, 0x00, 0x40, 67,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67
};

static uint8_t ct_test_packet6[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x40, 67, 0x0A,
    SPLIT_FRAME_TEST_SOURCE_68_77,
    picoquic_frame_type_stream_range_min, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_INIT_32
};

static uint8_t ct_test_mtu_probe[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_ping,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static uint8_t ct_test_ack[] = {
    COPY_PACKET_HEADER_1RTT,
    picoquic_frame_type_ack,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

typedef struct st_copy_retransmit_test_case_t {
    uint8_t* packet;
    uint32_t packet_length;
    uint32_t offset;
    int is_mtu_probe;
    int is_ack_trap;
    size_t copy_max;
    uint8_t* b1_expected;
    size_t b1_length;
    size_t b1_offset;
    uint8_t* b2_expected;
    size_t b2_length;
    uint8_t* b3_expected;
    size_t b3_length;
    int is_pure_ack_expected;
} copy_retransmit_test_case_t;

static copy_retransmit_test_case_t copy_retransmit_case[] = {
    {
        ct_test_packet1,
        (uint32_t) sizeof(ct_test_packet1),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        PICOQUIC_MAX_PACKET_SIZE,
        ct_test_packet1,
        (uint32_t) SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet1 + SIZEOF_1RTT_HEADER,
        sizeof(ct_test_packet1) - SIZEOF_1RTT_HEADER,
        NULL,
        0,
        0
    },
    {
        ct_test_packet2,
        (uint32_t)sizeof(ct_test_packet2),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        PICOQUIC_MAX_PACKET_SIZE,
        ct_test_packet1,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet2 + SIZEOF_1RTT_HEADER,
        sizeof(ct_test_packet2) - SIZEOF_1RTT_HEADER,
        NULL,
        0,
        0
    },
    {
        ct_test_packet2,
        (uint32_t)sizeof(ct_test_packet2),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        (uint32_t) sizeof(ct_test_packet2),
        ct_test_packet2,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet2 + SIZEOF_1RTT_HEADER,
        sizeof(ct_test_packet2) - SIZEOF_1RTT_HEADER,
        NULL,
        0,
        0
    },
    {
        ct_test_packet3,
        (uint32_t) sizeof(ct_test_packet3),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        (uint32_t) sizeof(ct_test_packet3),
        ct_test_packet3,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet3 + SIZEOF_1RTT_HEADER,
        sizeof(ct_test_packet3) - SIZEOF_1RTT_HEADER,
        NULL,
        0,
        0
    },
    {
        ct_test_packet4,
        (uint32_t) sizeof(ct_test_packet4),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        (uint32_t) sizeof(ct_test_packet4),
        ct_test_packet4,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet4_first_frame,
        sizeof(ct_test_packet4_first_frame),
        NULL,
        0,
        0
    },
    {
        ct_test_packet4,
        (uint32_t) sizeof(ct_test_packet4),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        PICOQUIC_MAX_PACKET_SIZE,
        ct_test_packet5,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet4_first_frame,
        sizeof(ct_test_packet4_first_frame),
        NULL,
        0,
        0
    },
    {
        ct_test_packet4,
        (uint32_t) sizeof(ct_test_packet4),
        (uint32_t) SIZEOF_1RTT_HEADER,
        0,
        0,
        (uint32_t) sizeof(ct_test_packet6),
        ct_test_packet6,
        (uint32_t)SIZEOF_1RTT_HEADER,
        (uint32_t) SIZEOF_1RTT_HEADER,
        ct_test_packet4_first_frame,
        sizeof(ct_test_packet4_first_frame),
        NULL,
        0,
        0
    },
    {
        ct_test_mtu_probe,
        (uint32_t) sizeof(ct_test_mtu_probe),
        (uint32_t) SIZEOF_1RTT_HEADER,
        1,
        0,
        PICOQUIC_MAX_PACKET_SIZE,
        NULL, 0, 0,
        NULL, 0,
        NULL, 0,
        1
    },
    {
        ct_test_ack,
        (uint32_t)sizeof(ct_test_ack),
        (uint32_t)SIZEOF_1RTT_HEADER,
        0,
        1,
        (uint32_t)SIZEOF_1RTT_HEADER,
        NULL, 0, 0,
        NULL, 0,
        NULL, 0,
        1
    },
    {
        NULL,
        0,
        0,
        0,
        1,
        PICOQUIC_MAX_PACKET_SIZE,
        NULL, 0, 0,
        NULL, 0,
        NULL, 0,
        1
    }
};

size_t nb_copy_retransmit_case = sizeof(copy_retransmit_case) / sizeof(copy_retransmit_test_case_t);

int test_copy_for_retransmit()
{
    picoquic_quic_t * qtest = NULL;
    picoquic_cnx_t * cnx = NULL;
    int ret = 0;
    picoquic_packet_t old_p;
    uint8_t new_bytes[PICOQUIC_MAX_PACKET_SIZE];
    size_t length = 0;
    int packet_is_pure_ack = 0;
    int do_not_detect_spurious = 1;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;

    memset(&saddr, 0, sizeof(struct sockaddr_in));

    /* Initialize the connection context */
    qtest = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    if (qtest == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }

    /* Perform the tests */
    for (size_t i = 0; ret == 0 && i < nb_copy_retransmit_case; i++) {
        cnx = picoquic_create_cnx(qtest,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
            ret = -1;
            break;
        }
        /* Initialize stream 0 */
        if ((ret = picoquic_add_to_stream(cnx, 0, ct_stream0_data, sizeof(ct_stream0_data), 0)) != 0) {
            DBG_PRINTF("%s", "Cannot initialize stream 0\n");
            ret = -1;
            break;
        }

        /* Initialize the old packet */
        memset(&old_p, 0, sizeof(picoquic_packet_t));
        if (copy_retransmit_case[i].packet_length > 0) {
            memcpy(old_p.bytes, copy_retransmit_case[i].packet, copy_retransmit_case[i].packet_length);
            old_p.length = copy_retransmit_case[i].packet_length;
        }
        old_p.offset = copy_retransmit_case[i].offset;
        old_p.is_mtu_probe = copy_retransmit_case[i].is_mtu_probe;
        old_p.is_ack_trap = copy_retransmit_case[i].is_ack_trap;
        old_p.send_path = cnx->path[0];

        length = copy_retransmit_case[i].b1_offset;

        ret = picoquic_copy_before_retransmit(&old_p, cnx, new_bytes,
            copy_retransmit_case[i].copy_max,
            &packet_is_pure_ack,
            &do_not_detect_spurious,
            &length);

        if (ret != 0) {
            DBG_PRINTF("Cannot perform copy for test[%d]\n", i);
        } else if (packet_is_pure_ack != copy_retransmit_case[i].is_pure_ack_expected) {
            /* Check whether pure ack matches expectation */
            DBG_PRINTF("Is pure ack mismatch on test[%d], got %d\n", i,
                packet_is_pure_ack);
            ret = -1;
        }
        else if (!packet_is_pure_ack) {
            /* Compare bytes and length to expected */
            if (length != copy_retransmit_case[i].b1_length) {
                DBG_PRINTF("Length mismatch on test[%d], got %d vs %d\n", i,
                    packet_is_pure_ack, length,
                    copy_retransmit_case[i].b1_length);
                ret = -1;
            }
            else if (memcmp(new_bytes + copy_retransmit_case[i].b1_offset,
                copy_retransmit_case[i].b1_expected + copy_retransmit_case[i].b1_offset,
                length - copy_retransmit_case[i].b1_offset) != 0) {
                DBG_PRINTF("Value mismatch on test[%d]\n", i);
                ret = -1;
            }
            else {
                if (copy_retransmit_case[i].b2_expected == NULL) {
                    if (cnx->stream_frame_retransmit_queue != NULL) {
                        DBG_PRINTF("Unexpected stream frame in test[%d]\n", i);
                        ret = -1;
                    }
                }
                else if (cnx->stream_frame_retransmit_queue == NULL) {
                    DBG_PRINTF("Missing stream frame in test[%d]\n", i);
                    ret = -1;
                }
                else if (copy_retransmit_case[i].b2_length != cnx->stream_frame_retransmit_queue->length) {
                    DBG_PRINTF("Mismatching stream frame lenght in test[%d]\n", i);
                    ret = -1;
                }
                else if (memcmp(((uint8_t*)cnx->stream_frame_retransmit_queue) + sizeof(picoquic_misc_frame_header_t),
                    copy_retransmit_case[i].b2_expected, cnx->stream_frame_retransmit_queue->length) != 0) {
                    DBG_PRINTF("Mismatching stream frame in test[%d]\n", i);
                    ret = -1;
                }

                if (ret == 0) {
                    if (copy_retransmit_case[i].b3_expected == NULL) {
                        if (cnx->first_misc_frame != NULL) {
                            DBG_PRINTF("Unexpected misc frame in test[%d]\n", i);
                            ret = -1;
                        }
                    }
                    else if (cnx->first_misc_frame == NULL) {
                        DBG_PRINTF("Missing misc frame in test[%d]\n", i);
                        ret = -1;
                    }
                    else if (copy_retransmit_case[i].b3_length != cnx->first_misc_frame->length) {
                        DBG_PRINTF("Mismatching misc frame lenght in test[%d]\n", i);
                        ret = -1;
                    }
                    else if (memcmp(((uint8_t*)cnx->first_misc_frame) + sizeof(picoquic_misc_frame_header_t),
                        copy_retransmit_case[i].b3_expected, cnx->first_misc_frame->length) != 0) {
                        DBG_PRINTF("Mismatching misc frame in test[%d]\n", i);
                        ret = -1;
                    }
                }
            }
        }
        /* Free the extra frames */
        if (cnx != NULL) {
            picoquic_delete_cnx(cnx);
        }
    }

    /* Free the connection context */
    if (qtest != NULL) {
        picoquic_free(qtest);
    }
    return ret;
}

/* Test of the function that copies and split queued stream frames
 * before retransmit */
typedef struct st_format_retransmit_test_case_t {
    uint8_t* frame;
    uint32_t frame_length;
    size_t frame_split_min;
} frame_retransmit_test_case_t;

#define SIZEOF_CONTENT_67 67
#define SIZEOF_CONTENT_68_77 10
#define SIZEOF_CONTENT_77 (SIZEOF_CONTENT_67 + SIZEOF_CONTENT_68_77)
#define OFFSET_TEST 0x3fffffff
#define OFFSET_TEST_E 0xbf,0xff,0xff,0xff
#define OFFSET_TEST_67 0x40000042
#define OFFSET_TEST_E67 0xC0,0,0,0,0x40,0,0,0x42

static uint8_t fr_test_data_ldef[] = { 
    picoquic_frame_type_stream_range_min | 3, 0x00, 0x40, SIZEOF_CONTENT_77,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67, SPLIT_FRAME_TEST_SOURCE_68_77 };
#define SPLIT_FRAME_TEST_MIN_DATA 7

static uint8_t fr_test_data_lundef[] = { 
    picoquic_frame_type_stream_range_min | 1, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67, SPLIT_FRAME_TEST_SOURCE_68_77 };

static uint8_t fr_test_data_lundef_offset[] = {
    picoquic_frame_type_stream_range_min | 4, 0x00, OFFSET_TEST_E,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67, SPLIT_FRAME_TEST_SOURCE_68_77 };
#define SPLIT_FRAME_TEST_OFFSET_MIN_DATA 13

static frame_retransmit_test_case_t fr_test_cases[] = {
    { fr_test_data_ldef, sizeof(fr_test_data_ldef), SPLIT_FRAME_TEST_MIN_DATA },
    { fr_test_data_lundef, sizeof(fr_test_data_lundef), SPLIT_FRAME_TEST_MIN_DATA },
    { fr_test_data_lundef_offset, sizeof(fr_test_data_lundef_offset),
        SPLIT_FRAME_TEST_OFFSET_MIN_DATA }
};

static size_t nb_fr_test_cases = sizeof(fr_test_cases) / sizeof(frame_retransmit_test_case_t);

static int test_format_for_retransmit_one(uint8_t* frame, size_t frame_length, size_t packet_length, size_t min_size)
{
    picoquic_quic_t* qtest = NULL;
    picoquic_cnx_t* cnx = NULL;
    int ret = 0;
    uint8_t new_bytes[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t* bytes_max = new_bytes + packet_length;
    uint8_t* next_bytes = NULL;
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    int is_pure_ack = 1;
    int fin = 0;
    uint64_t stream_id = 0;
    uint64_t offset = 0;
    size_t data_length = 0;
    uint8_t* data_val = frame;
    size_t consumed = 0;
    int fin1 = 1;
    uint64_t stream_id1 = 0;
    uint64_t offset1 = 0;
    size_t data_length1 = 0;
    size_t pad1 = 0;
    uint8_t* data_val1 = NULL;
    size_t consumed1 = 0;
    int fin2 = 1;
    uint64_t stream_id2 = 0;
    uint64_t offset2 = 0;
    size_t data_length2 = 0;
    uint8_t* data_val2 = NULL;
    size_t consumed2 = 0;
    picoquic_misc_frame_header_t* misc = NULL;

    memset(&saddr, 0, sizeof(struct sockaddr_in));

    /* Verify and parse the input arguments */
    if (packet_length > sizeof(new_bytes)) {
        DBG_PRINTF("Message size %zu > %zu\n", packet_length, sizeof(new_bytes));
        ret = -1;
    }
    else {
        if ((ret = picoquic_parse_stream_header(frame, frame_length, &stream_id, &offset, &data_length, &fin, &consumed)) != 0) {
            DBG_PRINTF("%s", "Cannot parse test frame\n");
        }
        else if (consumed + data_length != frame_length) {
            DBG_PRINTF("Frame length parses as %zu instead of %zu\n", consumed + data_length, frame_length);
            ret = -1;
        }
        else {
            data_val = frame + consumed;
        }
    }

    /* Initialize the connection context */
    if (ret == 0) {
        qtest = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, NULL, NULL, simulated_time,
            &simulated_time, NULL, NULL, 0);
        if (qtest == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC context\n");
            ret = -1;
        }
        else {
            cnx = picoquic_create_cnx(qtest,
                picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr*) & saddr,
                simulated_time, 0, "test-sni", "test-alpn", 1);

            if (cnx == NULL) {
                ret = -1;
            }
            else {
                /* Create stream 0 so the later tests succeed */
                memset(new_bytes, 0, sizeof(new_bytes));
                if ((ret = picoquic_add_to_stream(cnx, 0, new_bytes, sizeof(new_bytes), 0)) != 0) {
                    DBG_PRINTF("%s", "Cannot initialize stream 0\n");
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0) {
        misc = picoquic_create_misc_frame(frame, frame_length, 0);

        if (misc == NULL) {
            DBG_PRINTF("%s", "Cannot create mix frame\n");
            ret = -1;
        }
        else {
            cnx->stream_frame_retransmit_queue = misc;
            cnx->stream_frame_retransmit_queue_last = misc;
            memset(new_bytes, 0, sizeof(new_bytes));

            next_bytes = picoquic_format_stream_frame_for_retransmit(cnx, new_bytes, bytes_max, &is_pure_ack);

            if (next_bytes == NULL) {
                DBG_PRINTF("%s", "Cannot format frame for retransmit\n");
                ret = -1;
            }
            else if (next_bytes == new_bytes && packet_length > min_size) {
                DBG_PRINTF("Cannot format frame for in %zu bytes\n", packet_length);
                ret = -1;
            }
        }
    }

    if (ret == 0 && next_bytes > new_bytes) {
        /* Verify that the encoded frame can be properly decoded */
        size_t consumed = 0;
        uint8_t* bytes = new_bytes;
        while (*bytes == 0 && bytes < bytes_max) {
            pad1++;
            bytes++;
        }
        if ((ret = picoquic_parse_stream_header(bytes, bytes_max - bytes, &stream_id1, &offset1, &data_length1,
            &fin1, &consumed1)) != 0) {
            DBG_PRINTF("%s", "Cannot parse copied frame\n");
        }
        else {
            data_val1 = bytes + consumed1;
            if (data_val1 + data_length1 > bytes_max) {
                DBG_PRINTF("Copied frame too long, %zu + %zu + %zu bytes vs %zu\n", pad1, consumed, data_length1, packet_length);
                ret = -1;
            }
        }
        if (ret == 0) {
            if (stream_id1 != stream_id) {
                DBG_PRINTF("Stream_id1 = %" PRIu64 "instead of %" PRIu64 ".\n", stream_id1, stream_id);
                ret = -1;
            }
            else if (offset1 != offset) {
                DBG_PRINTF("Offset1 = %" PRIu64 "instead of %" PRIu64 ".\n", offset1, offset);
                ret = -1;
            }
            else if (data_length1 == 0 && data_length != 0) {
                DBG_PRINTF("Data_length1 = 0 vs %zu.\n", data_length);
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        if (cnx->stream_frame_retransmit_queue != NULL) {
            /* verify that the leftover frame can be properly decoded */
            misc = cnx->stream_frame_retransmit_queue;

            if (misc->length > frame_length) {
                DBG_PRINTF("Misc frame now too long, %zu vs %zu\n", misc->length, frame_length);
                ret = -1;
            }
            else {
                uint8_t* misc_frame = ((uint8_t*)misc) + sizeof(picoquic_misc_frame_header_t);

                if ((ret = picoquic_parse_stream_header(misc_frame, misc->length, &stream_id2, &offset2, &data_length2,
                    &fin2, &consumed2)) != 0) {
                    DBG_PRINTF("%s", "Cannot parse copied frame\n");
                }
                else {
                    data_val2 = misc_frame + consumed2;
                    if (consumed2 + data_length2 > misc->length) {
                        DBG_PRINTF("Leftover frame too long, %zu + %zu bytes vs %zu\n", consumed2, data_length2, misc->length);
                        ret = -1;
                    }
                    else if (stream_id2 != stream_id) {
                        DBG_PRINTF("Stream_id1 = %" PRIu64 "instead of %" PRIu64 ".\n", stream_id1, stream_id);
                        ret = -1;
                    }
                    else if (next_bytes == new_bytes) {
                        /* The leftover frame should be equivalent to the original frame */
                        if (data_length2 != data_length) {
                            DBG_PRINTF("Data_length2 = %zu vs %zu.\n", data_length2, data_length);
                            ret = -1;
                        }
                        else if (offset2 != offset) {
                            DBG_PRINTF("Offset2 = %" PRIu64 " vs %" PRIu64 ".\n", offset2, offset);
                            ret = -1;
                        }
                        else if (fin2 != fin) {
                            DBG_PRINTF("Fin2 = %d vs %d.\n", fin2, fin);
                            ret = -1;
                        }
                        else if (memcmp(data_val, data_val2, data_length) != 0) {
                            DBG_PRINTF("%s", "Leftover data != original data\n");
                            ret = -1;
                        }
                    }
                }
            }
        }
        else
        {
            if (next_bytes == new_bytes) {
                /* Nothing was produced! */
                if (data_length != 0 || fin) {
                    DBG_PRINTF("Nothing produced, data length %zu, fin %d\n", data_length, fin);
                    ret = -1;
                }
            }
            else {
                /* Copied frame should be equivalent to original frame */
                if (data_length1 != data_length) {
                    DBG_PRINTF("Data_length1 = %zu vs %zu.\n", data_length1, data_length);
                    ret = -1;
                }
                else if (fin1 != fin) {
                    DBG_PRINTF("Fin1 = %d vs %d.\n", fin1, fin);
                    ret = -1;
                }
                else if (data_val1 != NULL && memcmp(data_val, data_val1, data_length) != 0) {
                    DBG_PRINTF("%s", "Copied data != original data\n");
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0 && next_bytes != new_bytes && cnx->stream_frame_retransmit_queue != NULL) {
        /* The two frames combined should be equivalent to the original frame */
        if (data_length1 == 0 || data_length2 == 0) {
            DBG_PRINTF("Data_lengths = %zu + %zu vs %zu.\n", data_length1, data_length2, data_length);
            ret = -1;
        } else if (data_length1 + data_length2 != data_length) {
            DBG_PRINTF("Data_lengths = %zu + %zu vs %zu.\n", data_length1, data_length2, data_length);
            ret = -1;
        } else if (offset2 != offset + data_length1) {
            DBG_PRINTF("offset2 = %" PRIu64 " vs %" PRIu64 " + %zu.\n", offset2, offset, data_length1);
            ret = -1;
        }
        else if (fin1 != 0) {
            DBG_PRINTF("fin bits %d, %dvs %d.\n", fin1, fin2, fin);
            ret = -1;
        }
        else if (memcmp(data_val, data_val1, data_length1) != 0) {
            DBG_PRINTF("Copied data != original data [0..%zu[\n", data_length1);
            ret = -1;
        }
        else if (memcmp(data_val + data_length1, data_val2, data_length2) != 0) {
            DBG_PRINTF("Leftover data != original data [%zu..%zu[\n", data_length1, data_length);
            ret = -1;
        }
    }

    /* Free the connection context */
    if (cnx != NULL) {
        picoquic_delete_cnx(cnx);
    }

    if (qtest != NULL) {
        picoquic_free(qtest);
    }
    return ret;
}

int test_format_for_retransmit()
{
    int ret = 0;
    for (size_t i = 0; ret == 0 && i < nb_fr_test_cases; i++) {
        /* Full length tests */
        for (size_t j = 0; ret == 0 && j < 4; j++) {
            ret = test_format_for_retransmit_one(
                fr_test_cases[i].frame, fr_test_cases[i].frame_length, fr_test_cases[i].frame_length + j,
                fr_test_cases[i].frame_split_min);
        }
        /* Silly length tests */
        for (size_t j = 0; ret == 0 && j < 4; j++) {
            if (fr_test_cases[i].frame_split_min < j) {
                break;
            }
            ret = test_format_for_retransmit_one(
                fr_test_cases[i].frame, fr_test_cases[i].frame_length, fr_test_cases[i].frame_split_min - j,
                fr_test_cases[i].frame_split_min);
        }
        /* Medium length tests */
        if (ret == 0) {
            ret = test_format_for_retransmit_one(
                fr_test_cases[i].frame, fr_test_cases[i].frame_length, fr_test_cases[i].frame_split_min + 1,
                fr_test_cases[i].frame_split_min);
        }
        if (ret == 0) {
            ret = test_format_for_retransmit_one(
                fr_test_cases[i].frame, fr_test_cases[i].frame_length, fr_test_cases[i].frame_length - 1,
                fr_test_cases[i].frame_split_min);
        }
        if (ret == 0) {
            ret = test_format_for_retransmit_one(
                fr_test_cases[i].frame, fr_test_cases[i].frame_length, 
                (fr_test_cases[i].frame_length + fr_test_cases[i].frame_split_min)/2,
                fr_test_cases[i].frame_split_min);
        }
        if (ret != 0) {
            DBG_PRINTF("Format for retransmit test case %zu fails.\n", i);
        }
    }

    return ret;
}

/* Testing the sending of blocked frames */
struct st_stream_blocked_test_t {
    uint64_t stream_id;
    int is_id_blocked;
    int is_data_blocked;
    int is_client;
    int expect_bidir_blocked;
    int expect_unidir_blocked;
    int expect_data_blocked;
};

static const struct st_stream_blocked_test_t stream_blocked_test[] = {
    { 4, 1, 0, 1, 0, 0, 0},
    { 4, 1, 1, 0, 0, 0, 1},
    { 4, 0, 1, 0, 0, 0, 1}
};

static const size_t nb_stream_blocked_test = sizeof(stream_blocked_test) / sizeof(struct st_stream_blocked_test_t);

int send_stream_blocked_test_one(const struct st_stream_blocked_test_t * test)
{
    int ret = 0;
    uint8_t buf[1024];
    uint8_t bytes[1024];
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);
    picoquic_cnx_t * cnx = NULL;
    struct sockaddr_storage addr;
    picoquic_stream_head_t* stream = NULL;

    if (quic == NULL) {
        ret = -1;
    }
    else {
        ret = picoquic_store_text_addr(&addr, "10.0.0.1", 1234);
        if (ret == 0) {
            cnx = picoquic_create_client_cnx(quic, (struct sockaddr*) & addr, simulated_time, 0, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, NULL, NULL);
            if (cnx == NULL) {
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        /* Setup the initial conditions */
        if (!test->is_client) {
            cnx->client_mode = 0;
        }
        if (test->is_id_blocked) {
            cnx->remote_parameters.initial_max_stream_id_bidir = 4;
            cnx->remote_parameters.initial_max_stream_id_unidir = 0;
        }
        else {
            cnx->remote_parameters.initial_max_stream_id_bidir = 1024;
            cnx->remote_parameters.initial_max_stream_id_unidir = 1024;
        }

        cnx->max_stream_id_bidir_remote = cnx->remote_parameters.initial_max_stream_id_bidir;
        cnx->max_stream_id_unidir_remote = cnx->remote_parameters.initial_max_stream_id_unidir;

        if (test->is_data_blocked) {
            cnx->remote_parameters.initial_max_stream_data_bidi_local = 0;
            cnx->remote_parameters.initial_max_stream_data_bidi_remote = 0;
            cnx->remote_parameters.initial_max_stream_data_uni = 0;
            cnx->remote_parameters.initial_max_data = PICOQUIC_DEFAULT_0RTT_WINDOW;
        }
        else {
            cnx->remote_parameters.initial_max_stream_data_bidi_local = 100000;
            cnx->remote_parameters.initial_max_stream_data_bidi_remote = 100000;
            cnx->remote_parameters.initial_max_stream_data_uni = 100000;
            cnx->remote_parameters.initial_max_data = 1000000;
        }
        cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;

        /* Create the stream so it picks the required parameters */
        stream = picoquic_create_stream(cnx, test->stream_id);
        if (stream != NULL) {
            memset(buf, 0, sizeof(buf));
            ret = picoquic_add_to_stream(cnx, test->stream_id, buf, sizeof(buf), 0);
        }
        if (stream == NULL) {
            DBG_PRINTF("Could not find stream #%d", (int)test->stream_id);
            ret = -1;
        }
        if (ret == 0) {
            /* Call the blocked frame API */
            uint8_t* bytes_next;
            int is_pure_ack = 1;
            int more_data = 0;

            bytes_next = picoquic_format_one_blocked_frame(cnx, bytes, bytes + sizeof(bytes), &more_data, &is_pure_ack, stream);

            if (bytes_next != bytes && (is_pure_ack || more_data)) {
                DBG_PRINTF("Error formatting blocked frames, stream: %" PRIu64", length: %zu, more: %d, pure ack: %d",
                    test->stream_id, bytes_next - bytes, more_data, is_pure_ack);
                ret = -1;
            }
        }

        if (ret == 0 &&
            test->expect_bidir_blocked != cnx->stream_blocked_bidir_sent){
            DBG_PRINTF("Stream blocked bidir: %d vs %d", test->expect_bidir_blocked, cnx->stream_blocked_bidir_sent);
            ret = -1;
        }

        if (ret == 0 &&
            test->expect_unidir_blocked != cnx->stream_blocked_unidir_sent) {
            DBG_PRINTF("Stream blocked bidir: %d vs %d", test->expect_unidir_blocked, cnx->stream_blocked_unidir_sent);
            ret = -1;
        }

        if (ret == 0 &&
            test->expect_data_blocked != stream->stream_data_blocked_sent) {
            DBG_PRINTF("Stream data blocked: %d vs %d", test->expect_data_blocked, stream->stream_data_blocked_sent);
            ret = -1;
        }

    }
    

    if (quic != NULL) {
        picoquic_free(quic);
    }

    return ret;
}

int send_stream_blocked_test()
{
    int ret = 0;

    for (size_t i = 0; ret == 0 && i < nb_stream_blocked_test; i++) {
        if ((ret = send_stream_blocked_test_one(&stream_blocked_test[i])) != 0) {
            DBG_PRINTF("Stream blocked test %d failed", (int)i);
        }
    }

    return ret;
}

int picoquic_queue_network_input(picosplay_tree_t* tree, uint64_t consumed_offset,
    uint64_t stream_ofs, const uint8_t* bytes, size_t length, int* new_data_available);

int64_t picoquic_stream_data_node_compare(void* l, void* r);
picosplay_node_t* picoquic_stream_data_node_create(void* value);
void picoquic_stream_data_node_delete(void* tree, picosplay_node_t* node);
void* picoquic_stream_data_node_value(picosplay_node_t* node);

int queue_network_input_test()
{
    int ret = 0;

    const size_t expected_length[3] = { 4, 2, 4 };
    const uint8_t expected[3][4] = {
        { 0, 1, 2, 3 },
        { 4, 5 },
        { 6, 7, 8, 9 }
    };

    const uint8_t data[10] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
    int new_data_available = 0;

    picosplay_tree_t* tree = picosplay_new_tree(
        picoquic_stream_data_node_compare,
        picoquic_stream_data_node_create,
        picoquic_stream_data_node_delete,
        picoquic_stream_data_node_value);

    /* Fill 0..3 */
    new_data_available = 0;
    if ((ret = picoquic_queue_network_input(tree, 0, 0, data, 4, &new_data_available)) != 0) {
        DBG_PRINTF("picoquic_queue_network_input(0, 0, 4) failed (%d)", ret);
    } else if (new_data_available == 0) {
        DBG_PRINTF("new_data_available doesn't signal new data (%d)", new_data_available);
        ret = 1;
    }

    /* Fill 6..9 */
    if (ret == 0) {
        new_data_available = 0;
        if ((ret = picoquic_queue_network_input(tree, 0, 6, data + 6, 4, &new_data_available)) != 0) {
            DBG_PRINTF("picoquic_queue_network_input(0, 6, 4) failed (%d)", ret);
        } else if (new_data_available == 0) {
            DBG_PRINTF("new_data_available doesn't signal new data (%d)", new_data_available);
            ret = 1;
        }
    }

    /* Fill the gap from 4..5 with a chunk from 2..7 */
    if (ret == 0) {
        new_data_available = 0;
        if ((ret = picoquic_queue_network_input(tree, 0, 2, data + 2, 6, &new_data_available)) != 0) {
            DBG_PRINTF("picoquic_queue_network_input(0, 2, 6) failed (%d)", ret);
        } else if (new_data_available == 0) {
            DBG_PRINTF("new_data_available signals new data (%d)", new_data_available);
            ret = 1;
        }
    }

    /* No new data delivered by chunk 2..7 */
    if (ret == 0) {
        new_data_available = 0;
        if ((ret = picoquic_queue_network_input(tree, 0, 2, data, 6, &new_data_available)) != 0) {
            DBG_PRINTF("picoquic_queue_network_input(0, 2, 6) failed (%d)", ret);
        }

        if (new_data_available != 0) {
            DBG_PRINTF("new_data_available signals new data (%d)", new_data_available);
            ret = 1;
        }
    }

    if (ret == 0) {
        picoquic_stream_data_node_t* next = (picoquic_stream_data_node_t*)picosplay_first(tree);
        for (int i = 0; i < 3; ++i) {
            if (next == NULL) {
                DBG_PRINTF("tree does not contain enough data (%d chunks vs 3 exptected)", i);
                ret = 1;
                break;
            }
            else {
                if (expected_length[i] != next->length
                    || memcmp(next->bytes, expected[i], next->length) != 0) {
                    DBG_PRINTF("tree does not contain correct data (length: %zu vs %zu expected)", next->length, expected_length[i]);
                    ret = 1;
                    break;
                }
            }
            next = (picoquic_stream_data_node_t*)picosplay_next(&next->stream_data_node);
        }
    }

    return ret;
}