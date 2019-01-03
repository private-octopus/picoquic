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

/*
 * Test of the skip frame API.
 * This test is only defined for the varint encodings -- the older fixed int
 * versions are obsolete by now.
 */

static uint8_t test_frame_type_padding[] = { 0, 0, 0 };

static uint8_t test_frame_type_reset_stream[] = {
    picoquic_frame_type_reset_stream,
    17,
    0, 1,
    1
};

static uint8_t test_type_connection_close[] = {
    picoquic_frame_type_connection_close,
    0xcf, 0xff, 0x00,
    9,
    '1', '2', '3', '4', '5', '6', '7', '8', '9'
};

static uint8_t test_type_application_close[] = {
    picoquic_frame_type_application_close,
    0, 0,
    0
};

static uint8_t test_type_application_close_reason[] = {
    picoquic_frame_type_application_close,
    4, 4,
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
    0x80, 0x01, 0, 0
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
    8,
    1, 2, 3, 4, 5, 6, 7, 8,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF
};
static uint8_t test_frame_type_stop_sending[] = {
    picoquic_frame_type_stop_sending,
    17,
    0x40, 0
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
    TEST_SKIP_ITEM("retire_connection_id", test_frame_type_retire_connection_id, 0, 0, 3)
};

size_t nb_test_skip_list = sizeof(test_skip_list) / sizeof(test_skip_frames_t);

/*
 * export a list of test frames, to be used in other test
 */




/* Pseudo random generation suitable for tests. Guaranties that the
* same seed will produce the same sequence, allows for specific
* random sequence for a given test. 
* Adapted from http://xoroshiro.di.unimi.it/splitmix64.c,
* Written in 2015 by Sebastiano Vigna (vigna@acm.org)  */

uint64_t picoquic_test_random(uint64_t * random_context)
{
    uint64_t z = (*random_context += 0x9e3779b97f4a7c15);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
    z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
    return z ^ (z >> 31);
}

void picoquic_test_random_bytes(uint64_t * random_context, uint8_t * bytes, size_t bytes_max)
{
    size_t byte_index = 0;

    while (byte_index < bytes_max) {
        uint64_t v = picoquic_test_random(random_context);

        for (int i = 0; i < 8 && byte_index < bytes_max; i++) {
            bytes[byte_index++] = v & 0xFF;
            v >>= 8;
        }
    }
}

uint64_t picoquic_test_uniform_random(uint64_t * random_context, uint64_t rnd_max)
{

    uint64_t rnd = 0;

    if (rnd_max > 0) {
        uint64_t rnd_min = ((uint64_t)((int64_t)-1)) % rnd_max;

        do {
            rnd = picoquic_test_random(random_context);
        } while (rnd < rnd_min);
        rnd %= rnd_max;
    }

    return rnd;
}

static size_t format_random_packet(uint8_t * bytes, size_t bytes_max, uint64_t * random_context)
{
    size_t byte_index = 0;

    while (byte_index < bytes_max) {
        /* Pick a frame from the test list */
        uint64_t r = picoquic_test_uniform_random(random_context, nb_test_skip_list);
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

    return byte_index;
}

static int skip_test_packet(uint8_t * bytes, size_t bytes_max)
{
    int pure_ack;
    int ret = 0;
    size_t byte_index = 0;

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

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context);
        
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


int parse_frame_test()
{
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    const uint8_t extra_bytes[4] = { 0, 0, 0, 0 };
    uint64_t simulated_time = 0;
    struct sockaddr_in saddr;
    picoquic_packet_context_enum pc = 0;
    picoquic_quic_t * qclient = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);


    memset(&saddr, 0, sizeof(struct sockaddr_in));
    if (qclient == NULL) {
        DBG_PRINTF("%s", "Cannot create QUIC context\n");
        ret = -1;
    }

    for (size_t i = 0x0C; ret == 0 && i < nb_test_skip_list; i++) {
        for (int sharp_end = 0; ret == 0 && sharp_end < 2; sharp_end++) {
            size_t byte_max = 0;
            int t_ret = 0;
            picoquic_cnx_t * cnx = picoquic_create_cnx(qclient, 
                picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
                simulated_time, 0, "test-sni", "test-alpn", 1);

            /* Stupid fix to ensure that the NCID decoding test will not protest */
            cnx->path[0]->remote_cnxid.id_len = 8;

            if (cnx == NULL) {
                DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
                ret = -1;
            }
            else {

                memcpy(buffer, test_skip_list[i].val, test_skip_list[i].len);
                byte_max = test_skip_list[i].len;
                if (test_skip_list[i].must_be_last == 0 && sharp_end == 0) {
                    /* add some padding to check that the end of frame is detected properly */
                    memcpy(buffer + byte_max, extra_bytes, sizeof(extra_bytes));
                    byte_max += sizeof(extra_bytes);
                }

                pc = picoquic_context_from_epoch(test_skip_list[i].epoch);

                cnx->pkt_ctx[0].send_sequence = 0x0102030406;

                t_ret = picoquic_decode_frames(cnx, cnx->path[0], buffer, byte_max, test_skip_list[i].epoch, NULL, NULL, simulated_time);

                if (t_ret != 0) {
                    DBG_PRINTF("Parse frame <%s> fails, ret = %d\n", test_skip_list[i].name, t_ret);
                    ret = t_ret;
                }
                else if ((cnx->pkt_ctx[pc].ack_needed != 0 && test_skip_list[i].is_pure_ack != 0) ||
                    (cnx->pkt_ctx[pc].ack_needed == 0 && test_skip_list[i].is_pure_ack == 0)) {
                    DBG_PRINTF("Parse frame <%s> fails, ack needed: %d, expected pure ack: %d\n",
                        test_skip_list[i].name, (int)cnx->pkt_ctx[pc].ack_needed, (int)test_skip_list[i].is_pure_ack);
                    ret = -1;
                }

                picoquic_delete_cnx(cnx);
            }
        }
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

void picoquic_log_frames(FILE* F, uint64_t cnx_id64, uint8_t* bytes, size_t length);

static char const* log_test_file = "log_test.txt";
static char const* log_fuzz_test_file = "log_fuzz_test.txt";
static char const* log_packet_test_file = "log_fuzz_test.txt";

#ifdef _WINDOWS
#define LOG_TEST_REF "picoquictest\\log_test_ref.txt"
#else
#define LOG_TEST_REF "picoquictest/log_test_ref.txt"
#endif

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

int picoquic_test_compare_files(char const* fname1, char const* fname2)
{
    FILE* F1 = NULL;
    FILE* F2 = NULL;
    int ret = 0;
    int nb_line = 0;

#ifdef _WINDOWS
    errno_t err = fopen_s(&F1, fname1, "r");
    if (err != 0) {
        DBG_PRINTF("Cannot open file %s\n", fname1);
        ret = -1;
    } else {
        err = fopen_s(&F2, fname2, "r");
        if (err != 0) {
            DBG_PRINTF("Cannot open file %s\n", fname2);
            ret = -1;
        }
    }
#else
    F1 = fopen(fname1, "r");
    if (F1 == NULL) {
        ret = -1;
    } else {
        F2 = fopen(fname2, "r");
        if (F2 == NULL) {
            ret = -1;
        }
    }
#endif
    if (ret == 0 && F1 != NULL && F2 != NULL) {
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
    }

    if (F1 != NULL) {
        fclose(F1);
    }

    if (F2 != NULL) {
        fclose(F2);
    }

    return ret;
}

int logger_test()
{
    FILE* F = NULL;
    int ret = 0;
    uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint8_t fuzz_buffer[PICOQUIC_MAX_PACKET_SIZE];
    uint64_t random_context = 0xF00BAB;

#ifdef _WINDOWS
    if (fopen_s(&F, log_test_file, "w") != 0) {
        ret = -1;
    }
#else
    F = fopen(log_test_file, "w");
    if (F == NULL) {
        ret = -1;
    }
#endif

    for (size_t i = 0; i < nb_test_skip_list; i++) {
        picoquic_log_frames(F, 0, test_skip_list[i].val, test_skip_list[i].len);
    }

    fclose(F);
    F = NULL;

    if (ret == 0) {
        char log_test_ref[512];

        ret = picoquic_get_input_path(log_test_ref, sizeof(log_test_ref), picoquic_test_solution_dir, LOG_TEST_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the log ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_files(log_test_file, log_test_ref);
        }
    }

    /* Create a set of randomized packets. Verify that they can be logged without 
     * causing the dreaded "Unknown frame" message */

    for (size_t i = 0; ret == 0 && i < 100; i++) {
        char log_line[1024];
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context);
#ifdef _WINDOWS
        if (fopen_s(&F, log_packet_test_file, "w") != 0) {
            ret = -1;
            break;
        }
#else
        F = fopen(log_packet_test_file, "w");
        if (F == NULL) {
            ret = -1;
            break;
        }
#endif
        ret &= fprintf(F, "Log packet test #%d\n", (int)i);
        picoquic_log_frames(F, 0, buffer, bytes_max);
        fclose(F);

#ifdef _WINDOWS
        if (fopen_s(&F, log_packet_test_file, "w") != 0 || F == NULL) {
            ret = -1;
            break;
        }
#else
        F = fopen(log_packet_test_file, "w");
        if (F == NULL) {
            ret = -1;
            break;
        }
#endif
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
                DBG_PRINTF("Packet log test #%d failed, unknown frame.\n", (int) i);
                ret = -1;
                break;
            }
        }
        fclose(F);
    }

    /* Do a minimal fuzz test */
    for (size_t i = 0; ret == 0 && i < 100; i++) {
        size_t bytes_max = format_random_packet(buffer, sizeof(buffer), &random_context);
#ifdef _WINDOWS
        if (fopen_s(&F, log_fuzz_test_file, "w") != 0) {
            ret = -1;
            break;
        }
#else
        F = fopen(log_fuzz_test_file, "w");
        if (F == NULL) {
            ret = -1;
            break;
        }
#endif
        ret &= fprintf(F, "Log fuzz test #%d\n", (int)i);
        picoquic_log_frames(F, 0, buffer, bytes_max);

        /* Attempt to log fuzzed packets, and hope nothing crashes */
        for (size_t j = 0; j < 100; j++) {
            ret &= fprintf(F, "Log fuzz test #%d, packet %d\n", (int)i, (int)j);
            fflush(F);
            skip_test_fuzz_packet(fuzz_buffer, buffer, bytes_max, &random_context);
            picoquic_log_frames(F, 0, fuzz_buffer, bytes_max);
        }
        fclose(F);
        F = NULL;
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
            cnx->path[0]->local_cnxid = stash_test_init_local;
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
    }

    if (ret == 0) {
        cnx = picoquic_create_cnx(qclient,
            picoquic_null_connection_id, picoquic_null_connection_id, (struct sockaddr *) &saddr,
            simulated_time, 0, "test-sni", "test-alpn", 1);

        if (cnx == NULL) {
            DBG_PRINTF("%s", "Cannot create QUIC CNX context\n");
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Create a new path */
        int path_index;
        saddr.sin_port = 1000;
        path_index = picoquic_create_path(cnx, simulated_time, (struct sockaddr *)&saddr, NULL);

        if (path_index != 1) {
            DBG_PRINTF("Cannot create new path, index = %d\n", path_index);
            ret = -1;
        }
        else if (cnx->nb_paths != 2) {
            DBG_PRINTF("Expected 2 paths, got %d\n", cnx->nb_paths);
            ret = -1;
        }
        else {
            picoquic_register_path(cnx, cnx->path[path_index]);
        }
    }

    if (ret == 0) {
        ret = picoquic_prepare_new_connection_id_frame(cnx, cnx->path[1],
            frame_buffer, sizeof(frame_buffer), &consumed);

        if (ret != 0) {
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


    if (cnx != NULL)
    {
        /* Delete the connecton and free the stash */
        picoquic_delete_cnx(cnx);
    }

    if (qclient != NULL) {
        picoquic_free(qclient);
    }

    return ret;
}

/* Test the split frame process. We start with a variety of stream data frames, and
 * verify that the split process works correctly. This tests the stream header encoding 
 * and length encoding functions used in the prepare_stream_frame function, without
 * having side effects on the state of a connection.
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

uint8_t split_frame_source_stream0_lundef[] = {
    picoquic_frame_type_stream_range_min, 0x00, 
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67 };

uint8_t split_frame_source_stream0_lundef_fin[] = {
    picoquic_frame_type_stream_range_min|1, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67 };

uint8_t split_frame_source_stream0_ldef[] = {
    picoquic_frame_type_stream_range_min|2, 0x00, 0x40, 67,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67 };

uint8_t split_frame_source_stream0_lundef_offset[] = {
    picoquic_frame_type_stream_range_min | 4, 0x00, 0x80, 0x01, 0x00, 0x01,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67 };

uint8_t split_frame_source_stream0_ldef_offset[] = {
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x80, 0x01, 0x00, 0x01, 0x40, 67,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67 };

uint8_t split_frame_source_stream257_ldef_offset_fin[] = {
    picoquic_frame_type_stream_range_min | 7, 0x41, 0x01, 0x80, 0x01, 0x00, 0x01, 0x40, 67,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_67 };

uint8_t split_frame_source_stream257_l0_offset_fin[] = {
    picoquic_frame_type_stream_range_min | 7, 0x41, 0x01, 0x80, 0x01, 0x00, 0x01, 0x00 };

uint8_t split_frame_source_stream257_undef0_offset_fin[] = {
    picoquic_frame_type_stream_range_min | 5, 0x41, 0x01, 0x80, 0x01, 0x00, 0x01 };

uint8_t split_frame_source_stream257_undef0_offset_copied_fin[] = {
    0, picoquic_frame_type_stream_range_min | 5, 0x41, 0x01, 0x80, 0x01, 0x00, 0x01 };


uint8_t split_frame_source_stream0_lundef_init32[] = {
    picoquic_frame_type_stream_range_min, 0x00,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_INIT_32 };

uint8_t split_frame_source_stream0_ldef_last35[] = {
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x20, 35,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_LAST_35 };

uint8_t split_frame_source_stream0_ldef_last35_fin[] = {
    picoquic_frame_type_stream_range_min | 7, 0x00, 0x20, 35,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_LAST_35 };

uint8_t split_frame_source_stream0_lundef_offset_init32[] = {
    picoquic_frame_type_stream_range_min | 4, 0x00, 0x80, 0x01, 0x00, 0x01,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_INIT_32 };

uint8_t split_frame_source_stream0_ldef_offset_last35[] = {
    picoquic_frame_type_stream_range_min | 6, 0x00, 0x80, 0x01, 0x00, 0x21, 35,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_LAST_35 };

uint8_t split_frame_source_stream257_lundef_offset_init32[] = {
    picoquic_frame_type_stream_range_min | 4, 0x41, 0x01, 0x80, 0x01, 0x00, 0x01,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_INIT_32 };

uint8_t split_frame_source_stream257_ldef_offset_fin_last35[] = {
    picoquic_frame_type_stream_range_min | 7,0x41, 0x01, 0x80, 0x01, 0x00, 0x21, 35,
    SPLIT_FRAME_TEST_SOURCE_CONTENT_LAST_35 };

uint8_t split_frame_source_stream257_ldef0_offset_fin[] = {
    picoquic_frame_type_stream_range_min | 7, 0x41, 0x01, 0x80, 0x01, 0x00, 0x01, 0x00 };

typedef struct st_split_frame_test_case_t {
    uint8_t* frame;
    size_t frame_length;
    size_t b1_max;
    uint8_t* b1_expected;
    size_t b1_length;
    size_t b2_max;
    uint8_t* b2_expected;
    size_t b2_length;
    int ret_expected;
} split_frame_test_case_t;

split_frame_test_case_t split_test_case[] = {
    /* First series of test expects identical copies on first frame, nothing on second */
    {
        split_frame_source_stream0_lundef, sizeof(split_frame_source_stream0_lundef),
        sizeof(split_frame_source_stream0_lundef),
        split_frame_source_stream0_lundef, sizeof(split_frame_source_stream0_lundef),
        1024, NULL, 0, 0
    } /* 0 */,
    {
        split_frame_source_stream0_lundef_fin, sizeof(split_frame_source_stream0_lundef_fin),
        sizeof(split_frame_source_stream0_lundef_fin),
        split_frame_source_stream0_lundef_fin, sizeof(split_frame_source_stream0_lundef_fin),
        1024, NULL, 0, 0
    } /* 1 */,
    {
        split_frame_source_stream0_ldef, sizeof(split_frame_source_stream0_ldef),
        sizeof(split_frame_source_stream0_ldef),
        split_frame_source_stream0_ldef, sizeof(split_frame_source_stream0_ldef),
        1024, NULL, 0, 0
    } /* 2 */,
    {
        split_frame_source_stream0_lundef_offset, sizeof(split_frame_source_stream0_lundef_offset),
        sizeof(split_frame_source_stream0_lundef_offset),
        split_frame_source_stream0_lundef_offset, sizeof(split_frame_source_stream0_lundef_offset),
        1024, NULL, 0, 0
    } /* 3 */,
    {
        split_frame_source_stream0_ldef_offset, sizeof(split_frame_source_stream0_ldef_offset),
        sizeof(split_frame_source_stream0_ldef_offset),
        split_frame_source_stream0_ldef_offset, sizeof(split_frame_source_stream0_ldef_offset),
        1024, NULL, 0, 0
    } /* 4 */,
    {
        split_frame_source_stream257_ldef_offset_fin, sizeof(split_frame_source_stream257_ldef_offset_fin),
        sizeof(split_frame_source_stream257_ldef_offset_fin),
        split_frame_source_stream257_ldef_offset_fin, sizeof(split_frame_source_stream257_ldef_offset_fin),
        1024, NULL, 0, 0
    } /* 5 */,
    {
        split_frame_source_stream257_l0_offset_fin, sizeof(split_frame_source_stream257_l0_offset_fin),
        sizeof(split_frame_source_stream257_undef0_offset_copied_fin),
        split_frame_source_stream257_undef0_offset_copied_fin, sizeof(split_frame_source_stream257_undef0_offset_copied_fin),
        1024, NULL, 0, 0
    } /* 6 */,
    {
        split_frame_source_stream257_undef0_offset_fin, sizeof(split_frame_source_stream257_undef0_offset_fin),
        sizeof(split_frame_source_stream257_undef0_offset_fin),
        split_frame_source_stream257_undef0_offset_fin, sizeof(split_frame_source_stream257_undef0_offset_fin),
        1024, NULL, 0, 0
    } /* 7 */,

    /* Second series of test expects 32 data bytes on first frame, reminder on second */
    {
        split_frame_source_stream0_lundef, sizeof(split_frame_source_stream0_lundef),
        sizeof(split_frame_source_stream0_lundef_init32),
        split_frame_source_stream0_lundef_init32, sizeof(split_frame_source_stream0_lundef_init32),
        1024, 
        split_frame_source_stream0_ldef_last35, sizeof(split_frame_source_stream0_ldef_last35),
        0
    } /* 8 */,
    {
        split_frame_source_stream0_lundef_fin, sizeof(split_frame_source_stream0_lundef_fin),
        sizeof(split_frame_source_stream0_lundef_init32),
        split_frame_source_stream0_lundef_init32, sizeof(split_frame_source_stream0_lundef_init32),
        1024,
        split_frame_source_stream0_ldef_last35_fin, sizeof(split_frame_source_stream0_ldef_last35_fin),
        0
    } /* 9 */,
    {
        split_frame_source_stream0_ldef, sizeof(split_frame_source_stream0_ldef),
        sizeof(split_frame_source_stream0_lundef_init32),
        split_frame_source_stream0_lundef_init32, sizeof(split_frame_source_stream0_lundef_init32),
        1024,
        split_frame_source_stream0_ldef_last35, sizeof(split_frame_source_stream0_ldef_last35),
        0
    } /* 10 */,
    {
        split_frame_source_stream0_lundef_offset, sizeof(split_frame_source_stream0_lundef_offset),
        sizeof(split_frame_source_stream0_lundef_offset_init32),
        split_frame_source_stream0_lundef_offset_init32, sizeof(split_frame_source_stream0_lundef_offset_init32),
        1024,
        split_frame_source_stream0_ldef_offset_last35, sizeof(split_frame_source_stream0_ldef_offset_last35),
        0
    } /* 11 */,
    {
        split_frame_source_stream0_ldef_offset, sizeof(split_frame_source_stream0_ldef_offset),
        sizeof(split_frame_source_stream0_lundef_offset_init32),
        split_frame_source_stream0_lundef_offset_init32, sizeof(split_frame_source_stream0_lundef_offset_init32),
        1024,
        split_frame_source_stream0_ldef_offset_last35, sizeof(split_frame_source_stream0_ldef_offset_last35),
        0
    } /* 12 */,
    {
        split_frame_source_stream257_ldef_offset_fin, sizeof(split_frame_source_stream257_ldef_offset_fin),
        sizeof(split_frame_source_stream257_lundef_offset_init32),
        split_frame_source_stream257_lundef_offset_init32, sizeof(split_frame_source_stream257_lundef_offset_init32),
        1024,
        split_frame_source_stream257_ldef_offset_fin_last35, sizeof(split_frame_source_stream257_ldef_offset_fin_last35),
        0
    } /* 13 */,

    /* special cases */
    {
        split_frame_source_stream257_undef0_offset_fin, sizeof(split_frame_source_stream257_undef0_offset_fin),
        256,
        split_frame_source_stream257_ldef0_offset_fin, sizeof(split_frame_source_stream257_ldef0_offset_fin),
        1024, NULL, 0, 0
    } /* 14 */,
    {
        split_frame_source_stream257_undef0_offset_fin, sizeof(split_frame_source_stream257_undef0_offset_fin),
        3, NULL, 0,
        1024,
        split_frame_source_stream257_ldef0_offset_fin, sizeof(split_frame_source_stream257_ldef0_offset_fin),
        0
    } /* 15 */,
    {
        split_frame_source_stream257_undef0_offset_fin, sizeof(split_frame_source_stream257_undef0_offset_fin),
        3, NULL, 0,
        3, NULL, 0,
        PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL
    } /* 16 */,
    {
        split_frame_source_stream257_ldef_offset_fin, sizeof(split_frame_source_stream257_ldef_offset_fin),
        sizeof(split_frame_source_stream257_lundef_offset_init32),
        split_frame_source_stream257_lundef_offset_init32, sizeof(split_frame_source_stream257_lundef_offset_init32),
        32, NULL, 0,
        PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL
    } /* 17 */
};

size_t nb_split_test_case = sizeof(split_test_case) / sizeof(split_frame_test_case_t);

int split_stream_frame_test()
{
    int ret = 0;
    uint8_t b1[256];
    uint8_t b2[1024];

    for (size_t i = 0; ret == 0 && i < nb_split_test_case; i++) {
        size_t b1_length = 0;
        size_t b2_length = 0;

        int case_ret = picoquic_split_stream_frame(
            split_test_case[i].frame,
            split_test_case[i].frame_length,
            b1,
            split_test_case[i].b1_max,
            &b1_length,
            b2,
            split_test_case[i].b2_max,
            &b2_length);

        if (case_ret != split_test_case[i].ret_expected) {
            DBG_PRINTF("Testcase %d returns 0x%x instead of 0x%x\n", (int)i, ret, split_test_case[i].ret_expected);
            ret = -1;
        }
        else if (case_ret == 0) {
            if (b1_length != split_test_case[i].b1_length) {
                DBG_PRINTF("Testcase %d b1_length %d instead of %d\n", (int)i, b1_length, split_test_case[i].b1_length);
                ret = -1;
            }
            else if (b1_length > 0 && memcmp(b1, split_test_case[i].b1_expected, b1_length) != 0) {
                DBG_PRINTF("Testcase %d b1 values differ\n", (int)i);
                ret = -1;
            }
            else if (b2_length != split_test_case[i].b2_length) {
                DBG_PRINTF("Testcase %d b2_length %d instead of %d\n", (int)i, b2_length, split_test_case[i].b2_length);
                ret = -1;
            }
            else if (b2_length > 0 && memcmp(b2, split_test_case[i].b2_expected, b2_length) != 0) {
                DBG_PRINTF("Testcase %d b2 values differ\n", (int)i);
                ret = -1;
            }
        }    
    }

    return ret;

}