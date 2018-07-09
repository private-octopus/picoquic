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

#include "../picoquic/picoquic_internal.h"
#include "../picoquic/util.h"
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>

/* Start with a series of test vectors to test that 
 * encoding and decoding are OK. 
 * Then, add fuzz testing.
 */

#define TRANSPORT_PREFERED_ADDRESS_NULL \
    { 0, { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 0, \
    { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },0 }, \
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }} 

static picoquic_transport_parameters transport_param_test1 = {
    65535, 0x400000, 65533, 65535, 30, 1480, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_transport_parameters transport_param_test2 = {
    0x1000000, 0x1000000, 1, 0, 255, 1480, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_transport_parameters transport_param_test3 = {
    0x1000000, 0x1000000, 1, 0, 255, 0, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_transport_parameters transport_param_test4 = {
    65535, 0x400000, 65532, 0, 30, 1480, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_transport_parameters transport_param_test5 = {
    0x1000000, 0x1000000, 4, 0, 255, 1480, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_transport_parameters transport_param_test6 = {
    0x10000, 0xffffffff, 0, 0, 30, 1480, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_transport_parameters transport_param_test7 = {
    8192, 16384, 5, 0, 10, 1472, 17, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_transport_parameters transport_param_test8 = {
    65535, 0x400000, 0, 0, 30, 1480, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_transport_parameters transport_param_test9 = {
    0x1000000, 0x1000000, 4, 0, 255, 1480, 3, 0,
    { 4, { 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 4433,
    {{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },4},
        { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }}
};

static picoquic_transport_parameters transport_param_test10 = {
    65535, 0x400000, 65533, 65535, 30, 1480, 3, 1, TRANSPORT_PREFERED_ADDRESS_NULL
};

static uint8_t transport_param_reset_secret[PICOQUIC_RESET_SECRET_SIZE] = {
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

uint8_t client_param1[] = {
    'P', 'C', 'Q', '0',
    0, 0x28,
    0, 0, 0, 4, 0, 0, 0xFF, 0xFF,
    0, 1, 0, 4, 0, 0x40, 0, 0,
    0, 2, 0, 2, 0x40, 0x00,
    0, 3, 0, 2, 0, 0x1E,
    0, 5, 0, 2, 0x05, 0xC8,
    0, 8, 0, 2, 0x40, 0x00
};

uint8_t client_param2[] = {
    0x0A, 0x1A, 0x0A, 0x1A,
    0, 0x22,
    0, 0, 0, 4, 0x01, 0, 0, 0,
    0, 1, 0, 4, 0x01, 0, 0, 0,
    0, 2, 0, 2, 0, 0x01,
    0, 3, 0, 2, 0x0, 0xFF,
    0, 5, 0, 2, 0x05, 0xC8
};

uint8_t client_param3[] = {
    0x0A, 0x1A, 0x0A, 0x1A,
    0, 0x1C,
    0, 0, 0, 4, 0x01, 0, 0, 0,
    0, 1, 0, 4, 0x01, 0, 0, 0,
    0, 2, 0, 2, 0, 0x01,
    0, 3, 0, 2, 0, 0xFF
};

uint8_t client_param4[] = {
    0x0A, 0x1A, 0x0A, 0x1A,
    0, 0x1C,
    0, 0, 0, 4, 0, 0x01, 0, 0,
    0, 1, 0, 4, 0xFF, 0xFF, 0xFF, 0xFF,
    0, 3, 0, 2, 0, 0x1E,
    0, 5, 0, 2, 0x05, 0xC8
};

uint8_t client_param5[] = {
    0xBA, 0xBA, 0xBA, 0xBA,
    0, 0x27,
    0, 0x03, 0, 0x02, 0, 0x0A,
    0, 0x02, 0, 0x02, 0, 0x02,
    0, 0x00, 0, 0x04, 0, 0, 0x20, 0,
    0, 0x01, 0, 0x04, 0, 0, 0x40, 0,
    0, 0x05, 0, 0x02, 0x05, 0xC0,
    0, 0x07, 0, 0x01, 0x11
};

uint8_t server_param1[] = {
    'P', 'C', 'Q', '0',
    0x08,
    'P', 'C', 'Q', '0',
    0xFF, 0x00, 0x00, 0x0D,
    0, 0x36,
    0, 0, 0, 4, 0, 0, 0xFF, 0xFF,
    0, 1, 0, 4, 0, 0x40, 0, 0,
    0, 2, 0, 2, 0x3F, 0xFF,
    0, 3, 0, 2, 0, 0x1E,
    0, 5, 0, 2, 0x05, 0xC8,
    0, 6, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

uint8_t server_param2[] = {
    'P', 'C', 'Q', '0',
    0x08,
    'P', 'C', 'Q', '0',
    0xFF, 0x00, 0x00, 0x0D,
    0, 0x36,
    0, 0, 0, 4, 0x01, 0, 0, 0,
    0, 1, 0, 4, 0x01, 0, 0, 0,
    0, 2, 0, 2, 0, 1,
    0, 3, 0, 2, 0, 0xFF,
    0, 5, 0, 2, 0x05, 0xC8,
    0, 6, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

uint8_t client_param8[] = {
    'P', 'C', 'Q', '0',
    0, 0x1C,
    0, 0, 0, 4, 0, 0, 0xFF, 0xFF,
    0, 1, 0, 4, 0, 0x40, 0, 0,
    0, 3, 0, 2, 0, 0x1E,
    0, 5, 0, 2, 0x05, 0xC8,
};

uint8_t server_param3[] = {
    'P', 'C', 'Q', '0',
    0x08,
    'P', 'C', 'Q', '0',
    0xFF, 0x00, 0x00, 0x0D,
    0, 87,
    0, 0, 0, 4, 0x01, 0, 0, 0,
    0, 1, 0, 4, 0x01, 0, 0, 0,
    0, 2, 0, 2, 0, 1,
    0, 3, 0, 2, 0, 0xFF,
    0, 5, 0, 2, 0x05, 0xC8,
    0, 6, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    0, 4, 0, 29,
    4, 4, 10, 0, 0, 1, 0x11, 0x51, 4, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

uint8_t client_param9[] = {
    'P', 'C', 'Q', '0',
    0, 0x2C,
    0, 0, 0, 4, 0, 0, 0xFF, 0xFF,
    0, 1, 0, 4, 0, 0x40, 0, 0,
    0, 2, 0, 2, 0x40, 0x00,
    0, 3, 0, 2, 0, 0x1E,
    0, 5, 0, 2, 0x05, 0xC8,
    0, 8, 0, 2, 0x40, 0x00,
    0, 9, 0, 0
};

static int transport_param_compare(picoquic_transport_parameters* param, picoquic_transport_parameters* ref) {
    int ret = 0;

    if (param->initial_max_stream_data != ref->initial_max_stream_data) {
        ret = -1;
    }
    else if (param->initial_max_data != ref->initial_max_data) {
        ret = -1;
    }
    else if (param->initial_max_stream_id_bidir != ref->initial_max_stream_id_bidir) {
        ret = -1;
    }
    else if (param->initial_max_stream_id_unidir != ref->initial_max_stream_id_unidir) {
        ret = -1;
    }
    else if (param->idle_timeout != ref->idle_timeout) {
        ret = -1;
    }
    else if (param->prefered_address.ipVersion != ref->prefered_address.ipVersion) {
        ret = -1;
    }
    else if (param->prefered_address.ipVersion != 0) {
        int ip_len = (param->prefered_address.ipVersion == 4) ? 4 : 16;
        if (memcmp(param->prefered_address.ipAddress, ref->prefered_address.ipAddress, ip_len) != 0) {
            ret = -1;
        }
        else if (param->prefered_address.port != ref->prefered_address.port) {
            ret = -1;
        }
        else if (picoquic_compare_connection_id(&param->prefered_address.connection_id, &ref->prefered_address.connection_id) != 0) {
            ret = -1;
        }
        else if (memcmp(param->prefered_address.statelessResetToken, ref->prefered_address.statelessResetToken, 16) != 0) {
            ret = -1;
        }
    }

    return ret;
}

int transport_param_one_test(int mode, uint32_t version, uint32_t proposed_version,
    picoquic_transport_parameters* param, uint8_t* target, size_t target_length)
{
    int ret = 0;
    picoquic_quic_t quic_ctx;
    picoquic_cnx_t test_cnx;
    uint8_t buffer[256];
    size_t encoded, decoded;

    memset(&quic_ctx, 0, sizeof(quic_ctx));
    memset(&test_cnx, 0, sizeof(picoquic_cnx_t));
    test_cnx.quic = &quic_ctx;

    /* initialize the connection object to the test parameters */
    memcpy(&test_cnx.local_parameters, param, sizeof(picoquic_transport_parameters));
    // test_cnx.version = version;
    test_cnx.version_index = picoquic_get_version_index(version);
    test_cnx.proposed_version = proposed_version;
    memcpy(test_cnx.reset_secret, transport_param_reset_secret, PICOQUIC_RESET_SECRET_SIZE);

    ret = picoquic_prepare_transport_extensions(&test_cnx, mode, buffer, sizeof(buffer), &encoded);

    if (ret == 0) {
        if (encoded != target_length) {
            ret = -1;
        } else if (memcmp(buffer, target, target_length) != 0) {
            for (size_t i = 0; i < target_length; i++) {
                if (buffer[i] != target[i]) {
                    ret = -1;
                }
            }
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = picoquic_receive_transport_extensions(&test_cnx, mode, buffer, encoded, &decoded);

        if (ret == 0 && transport_param_compare(&test_cnx.remote_parameters, param) != 0) {
            ret = -1;
        }
    }

    return ret;
}

int transport_param_decode_test(int mode, uint32_t version, uint32_t proposed_version,
    picoquic_transport_parameters* param, uint8_t* target, size_t target_length)
{
    int ret = 0;
    picoquic_quic_t quic_ctx;
    picoquic_cnx_t test_cnx;
    size_t decoded;

    memset(&quic_ctx, 0, sizeof(quic_ctx));
    memset(&test_cnx, 0, sizeof(picoquic_cnx_t));
    test_cnx.quic = &quic_ctx;

    ret = picoquic_receive_transport_extensions(&test_cnx, mode,
        target, target_length, &decoded);

    if (ret == 0 && decoded != target_length) {
        ret = -1;
    }

    if (ret == 0 && transport_param_compare(&test_cnx.remote_parameters, param) != 0) {
        ret = -1;
    }

    return ret;
}

int transport_param_fuzz_test(int mode, uint32_t version, uint32_t proposed_version,
    picoquic_transport_parameters* param, uint8_t* target, size_t target_length, uint64_t* proof)
{
    int ret = 0;
    int fuzz_ret = 0;
    picoquic_quic_t quic_ctx;
    picoquic_cnx_t test_cnx;
    uint8_t buffer[256];
    size_t decoded;
    uint8_t fuzz_byte = 1;

    memset(&quic_ctx, 0, sizeof(quic_ctx));
    memset(&test_cnx, 0, sizeof(picoquic_cnx_t));
    test_cnx.quic = &quic_ctx;

    /* test for valid arguments */
    if (target_length < 8 || target_length > sizeof(buffer)) {
        return -1;
    }

    debug_printf_suspend();

    /* initialize the connection object to the test parameters */
    memcpy(&test_cnx.local_parameters, param, sizeof(picoquic_transport_parameters));
    test_cnx.version_index = picoquic_get_version_index(version);
    test_cnx.proposed_version = proposed_version;

    /* add computation of the proof argument to make sure the compiler 
	 * will not optimize the loop to nothing */

    *proof = 0;

    /* repeat multiple times */
    for (size_t l = 0; l < 8; l++) {
        for (size_t i = 0; i < target_length - l; i++) {
            /* copy message to buffer */
            memcpy(buffer, target, target_length);

            /* fuzz */
            for (size_t j = 0; j < l; j++) {
                buffer[i + j] ^= fuzz_byte;
                fuzz_byte++;
            }

            /* Try various bad lengths */
            for (size_t dl = 0; dl < target_length; dl += l + 7)
            {
                /* decode */
                fuzz_ret = picoquic_receive_transport_extensions(&test_cnx, mode, buffer,
                    target_length - dl, &decoded);

                if (fuzz_ret != 0) {
                    *proof += (uint64_t)fuzz_ret;
                }
                else {
                    *proof += test_cnx.remote_parameters.initial_max_stream_data;

                    if (decoded > target_length - dl) {
                        ret = -1;
                    }
                }
            }
        }
    }

    debug_printf_resume();

    return ret;
}

int transport_param_test()
{
    int ret = 0;
    uint64_t proof = 0;
    uint32_t version_default = picoquic_supported_versions[0].version;

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, version_default,
            &transport_param_test1, client_param1, sizeof(client_param1));
    }

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test2, client_param2, sizeof(client_param2));
    }

    if (ret == 0) {
        ret = transport_param_decode_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test3, client_param3, sizeof(client_param3));
    }

    if (ret == 0) {
        ret = transport_param_one_test(1, version_default, version_default,
            &transport_param_test4, server_param1, sizeof(server_param1));
    }

    if (ret == 0) {
        ret = transport_param_one_test(1, version_default, 0x0A1A0A1A,
            &transport_param_test5, server_param2, sizeof(server_param2));
    }

    if (ret == 0) {
        ret = transport_param_decode_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test6, client_param4, sizeof(client_param4));
    }

    if (ret == 0) {
        ret = transport_param_decode_test(0, version_default, 0xBABABABA,
            &transport_param_test7, client_param5, sizeof(client_param5));
    }

    if (ret == 0) {
        ret = transport_param_decode_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test8, client_param8, sizeof(client_param8));
    }

    if (ret == 0) {
        ret = transport_param_decode_test(1, version_default, 0x0A1A0A1A,
            &transport_param_test9, server_param3, sizeof(server_param3));
    }

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, version_default,
            &transport_param_test10, client_param9, sizeof(client_param9));
    }

    if (ret == 0)
    {
        DBG_PRINTF("%s", "Starting transport parameters fuzz test.\n");

        if (ret == 0) {
            ret = transport_param_fuzz_test(0, version_default, 0x0A1A0A1A,
                &transport_param_test2, client_param2, sizeof(client_param2), &proof);
        }

        if (ret == 0) {
            ret = transport_param_fuzz_test(1, version_default, 0x0A1A0A1A,
                &transport_param_test2, server_param2, sizeof(server_param2), &proof);
        }

        DBG_PRINTF("%s", "End of transport parameters fuzz test.\n");
    }
    return ret;
}

/*
 * Verify that we can properly log all the transport parameters.
 */
static char const* log_tp_test_file = "log_tp_test.txt";
static char const* log_tp_fuzz_file = "log_tp_fuzz_test.txt";

#ifdef _WINDOWS
#ifndef _WINDOWS64
static char const* log_tp_test_ref = "..\\picoquictest\\log_tp_test_ref.txt";
#else
static char const* log_tp_test_ref = "..\\..\\picoquictest\\log_tp_test_ref.txt";
#endif
#else
static char const* log_tp_test_ref = "picoquictest/log_tp_test_ref.txt";
#endif

void picoquic_log_transport_extension_content(FILE* F, int log_cnxid, uint64_t cnx_id_64,
    uint8_t * bytes, size_t bytes_max, int client_mode,
    uint32_t initial_version, uint32_t final_version);

static void transport_param_log_test_one(FILE * F, uint8_t * bytes, size_t bytes_max, int client_mode)
{
    picoquic_log_transport_extension_content(F, 1, 0x0102030405060708ull, bytes, bytes_max, client_mode,
        0x0A1A0A1A, picoquic_supported_versions[0].version);
    fprintf(F, "\n");
}

static int transport_param_log_fuzz_test(int client_mode, uint8_t* target, size_t target_length)
{
    int ret = 0;
    uint8_t buffer[256];
    uint8_t fuzz_byte = 1;


    /* test for valid arguments */
    if (target_length < 8 || target_length > sizeof(buffer)) {
        return -1;
    }

    debug_printf_suspend();

    /* repeat multiple times */
    for (size_t l = 0; l < 8; l++) {
        for (size_t i = 0; i < target_length - l; i++) {
            FILE *F;
#ifdef _WINDOWS
            if (fopen_s(&F, log_tp_fuzz_file, "w") != 0) {
                ret = -1;
            }
#else
            F = fopen(log_tp_fuzz_file, "w");
            if (F == NULL) {
                ret = -1;
            }
#endif
            if (ret == 0)
            {
                /* copy message to buffer */
                memcpy(buffer, target, target_length);

                /* fuzz */
                for (size_t j = 0; j < l; j++) {
                    buffer[i + j] ^= fuzz_byte;
                    fuzz_byte++;
                }

                /* Try various bad lengths */
                for (size_t dl = 0; dl < target_length; dl += l + 7)
                {
                    /* log */
                    transport_param_log_test_one(F, buffer, target_length - dl, client_mode);
                }
            }

            if (F != NULL)
            {
                fclose(F);
            }
        }
    }

    debug_printf_resume();

    return ret;
}

int transport_param_log_test()
{
    FILE* F = NULL;
    int ret = 0;

#ifdef _WINDOWS
    if (fopen_s(&F, log_tp_test_file, "w") != 0) {
        ret = -1;
    }
#else
    F = fopen(log_tp_test_file, "w");
    if (F == NULL) {
        ret = -1;
    }
#endif

    if (ret == 0) {
        transport_param_log_test_one(F, client_param1, sizeof(client_param1), 0);
        transport_param_log_test_one(F, client_param2, sizeof(client_param2), 0);
        transport_param_log_test_one(F, client_param3, sizeof(client_param3), 0);
        transport_param_log_test_one(F, server_param1, sizeof(server_param1), 1);
        transport_param_log_test_one(F, server_param2, sizeof(server_param2), 1);
        transport_param_log_test_one(F, client_param4, sizeof(client_param4), 0);
        transport_param_log_test_one(F, client_param5, sizeof(client_param5), 0);
        transport_param_log_test_one(F, server_param3, sizeof(server_param3), 1);
    }

    if (F != NULL)
    {
        fclose(F);
    }

    if (ret == 0)
    {
        ret = picoquic_test_compare_files(log_tp_test_file, log_tp_test_ref);
    }

    if (ret == 0)
    {
        DBG_PRINTF("Doing fuzz test of transport parameter logging into %s\n", log_tp_fuzz_file);


        if (ret == 0) {
            ret = transport_param_log_fuzz_test(0, client_param2, sizeof(client_param2));
        }

        if (ret == 0) {
            ret = transport_param_log_fuzz_test(1, server_param2, sizeof(server_param2));
        }

        DBG_PRINTF("Fuzz test of transport parameter was successful.\n", log_tp_fuzz_file);
    }

    return ret;
}

typedef struct st_transport_param_stream_id_test_t {
    int extension_mode;
    int stream_id_type;
    int rank;
    int stream_id;
} transport_param_stream_id_test_t;

transport_param_stream_id_test_t const transport_param_stream_id_test_table[] = {
    { 0, PICOQUIC_STREAM_ID_BIDIR, 0, 0 },
    { 1, PICOQUIC_STREAM_ID_BIDIR, 0, 0 },
    { 0, PICOQUIC_STREAM_ID_UNIDIR, 0, 0 },
    { 1, PICOQUIC_STREAM_ID_UNIDIR, 0, 0 },
    { 0, PICOQUIC_STREAM_ID_BIDIR,  1, PICOQUIC_STREAM_ID_SERVER_INITIATED_BIDIR },
    { 1, PICOQUIC_STREAM_ID_BIDIR, 1, PICOQUIC_STREAM_ID_CLIENT_INITIATED_BIDIR + 4},
    { 0, PICOQUIC_STREAM_ID_UNIDIR, 1, PICOQUIC_STREAM_ID_SERVER_INITIATED_UNIDIR },
    { 1, PICOQUIC_STREAM_ID_UNIDIR, 1, PICOQUIC_STREAM_ID_CLIENT_INITIATED_UNIDIR },
    { 0, PICOQUIC_STREAM_ID_BIDIR, 65535, PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_BIDIR },
    { 1, PICOQUIC_STREAM_ID_BIDIR, 65535, PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_BIDIR },
    { 0, PICOQUIC_STREAM_ID_UNIDIR, 65535, PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_UNIDIR },
    { 1, PICOQUIC_STREAM_ID_UNIDIR, 65535, PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_UNIDIR },
    { 0, PICOQUIC_STREAM_ID_BIDIR, 5, 17},
    { 1, PICOQUIC_STREAM_ID_BIDIR, 5, 20 }
};

static size_t const nb_transport_param_stream_id_test_table =
    sizeof(transport_param_stream_id_test_table) / sizeof(transport_param_stream_id_test_t);

uint32_t picoquic_decode_transport_param_stream_id(uint16_t rank, int extension_mode, int stream_type);
uint16_t picoquic_prepare_transport_param_stream_id(uint32_t stream_id, int extension_mode, int stream_type);

int transport_param_stream_id_test() {
    int ret = 0;

    /* Decoding test */
    for (size_t i = 0; i < nb_transport_param_stream_id_test_table; i++) {
        uint16_t rank = picoquic_prepare_transport_param_stream_id(
            transport_param_stream_id_test_table[i].stream_id,
            transport_param_stream_id_test_table[i].extension_mode,
            transport_param_stream_id_test_table[i].stream_id_type);

        if (rank != transport_param_stream_id_test_table[i].rank) {
            DBG_PRINTF("TP Stream prepare ID [%d] fails. Rank= 0x%x, expected 0x%x, got 0x%x\n", i,
                transport_param_stream_id_test_table[i].stream_id,
                transport_param_stream_id_test_table[i].rank,
                rank);
            ret = -1;
        }
    }

    /* Encoding test */
    for (size_t i = 0; i < nb_transport_param_stream_id_test_table; i++) {
        uint32_t stream_id = picoquic_decode_transport_param_stream_id(
            transport_param_stream_id_test_table[i].rank,
            transport_param_stream_id_test_table[i].extension_mode,
            transport_param_stream_id_test_table[i].stream_id_type);

        if (stream_id != transport_param_stream_id_test_table[i].stream_id) {
            DBG_PRINTF("TP Stream decode ID [%d] fails. Rank= 0x%x, expected 0x%x, got 0x%x\n", i,
                transport_param_stream_id_test_table[i].rank,
                transport_param_stream_id_test_table[i].stream_id,
                stream_id);
            ret = -1;
        }
    }

    return ret;
}