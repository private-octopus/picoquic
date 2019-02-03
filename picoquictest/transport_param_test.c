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

#include "picoquic_internal.h"
#include "util.h"
#include "tls_api.h"
#include "picoquictest_internal.h"

/* The transport parameter tests operate by comparing the decoding of test vectors
 * to the expected value. Some vectors are also used to verify that the encoding
 * of the expected value matches the vector. 
 * 
 * The test vectors have dependencies on the list of supported protocol versions
 * "picoquic_supported_versions" defined in "quicctx.c". If that list is updated,
 * the test vectors also need to be updated. This is done by updating the
 * definition of two macros.
 *
 * The first dependency is on the default protocol version, which by convention
 * is the first element in the list of supported versions. The four bytes
 * representing that version number are documented in the macro
 * TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES.
 *
 * The second dependency is on the list of supported versions, which is returned
 * by the server. The encoding of this list of parameters is documented in the
 * macro TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_BYTES. The first byte encodes
 * the length of the list, then there are 4 bytes for each version, in the
 * expected order.
 * 
 * The log test operates on the same test vectors, andproduces a text file 
 * "log_tp_test.txt" with their text renderings. If the test vectors
 * are updated to match the new list of versions, the text will change and
 * will not match the expected value in "picoquictest/log_tp_test_ref.txt".
 * This can be fixed by running the test once, manually inspecting the
 * output, verifying that the differences are only in the list of versions,
 * and then updating the reference version to match the output.
 */

#define TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES 'P', 'C', 'Q', '1'
#define TRANSPORT_PARAMETERS_FAILED_VERSION_BYTES 'P', 'C', 'Q', '0'
#define TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_BYTES \
     0x10, 'P', 'C', 'Q', '1', 'P', 'C', 'Q', '0', 0xFF, 0x00, 0x00, 0x12, 0xFF, 0x00, 0x00, 0x11

#define TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_ERROR1 \
     0x10, 'P', 'C', 'Q', '0', 0xFF, 0x00, 0x00, 0x10, 0xFF, 0x00, 0x00, 0x0F

#define TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_ERROR2 \
     0x0F, 'P', 'C', 'Q', '1', 'P', 'C', 'Q', '0', 0xFF, 0x00, 0x00, 0x10, 0xFF, 0x00, 0x00

#define TRANSPORT_PREFERED_ADDRESS_NULL \
    { 0, { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 0, \
    { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },0 }, \
    { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }} 

static picoquic_tp_t transport_param_test1 = {
    65535, 0, 0, 0x400000, 65533, 65535, 30, 1480, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 3, 0,  TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_tp_t transport_param_test2 = {
    0x1000000, 0, 0, 0x1000000, 1, 0, 255, 1480, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_tp_t transport_param_test3 = {
    0x1000000, 0, 0, 0x1000000, 1, 0, 255, 0, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_tp_t transport_param_test4 = {
    65535, 0, 0, 0x400000, 65532, 0, 30, 1480, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_tp_t transport_param_test5 = {
    0x1000000, 0, 0, 0x1000000, 4, 0, 255, 1480, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_tp_t transport_param_test6 = {
    0x10000, 0, 0, 0xffffffff, 0, 0, 30, 1480, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_tp_t transport_param_test7 = {
    8192, 0, 0, 16384, 5, 0, 10, 1472, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 17, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_tp_t transport_param_test8 = {
    65535, 0, 0, 0x400000, 0, 0, 30, 1480, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 3, 0, TRANSPORT_PREFERED_ADDRESS_NULL
};

static picoquic_tp_t transport_param_test9 = {
    0x1000000, 0, 0, 0x1000000, 4, 0, 255, 1480, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 3, 0,
    { 4, { 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, 4433,
    {{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },4},
        { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 }}
};

static picoquic_tp_t transport_param_test10 = {
    65535, 0, 0, 0x400000, 65533, 65535, 30, 1480, PICOQUIC_ACK_DELAY_MAX_DEFAULT, 3, 1, TRANSPORT_PREFERED_ADDRESS_NULL
};

uint8_t client_param1[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    0, 0x2B,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi, 0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_initial_max_streams_uni, 0, 4, 0x80, 0, 0x40, 0x00
};

uint8_t client_param2[] = {
    0x0A, 0x1A, 0x0A, 0x1A,
    0, 0x21,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_data, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi, 0, 1, 0x01,
    0, picoquic_tp_idle_timeout, 0, 2, 0x40, 0xFF,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8
};

uint8_t client_param3[] = {
    0x0A, 0x1A, 0x0A, 0x1A,
    0, 0x1B,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_data, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi, 0, 1, 0x01,
    0, picoquic_tp_idle_timeout, 0, 2, 0x40, 0xFF
};

uint8_t client_param4[] = {
    0x0A, 0x1A, 0x0A, 0x1A,
    0, 0x1F,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0x01, 0, 0,
    0, picoquic_tp_initial_max_data, 0, 8, 0xC0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8
};

uint8_t client_param5[] = {
    0xBA, 0xBA, 0xBA, 0xBA,
    0, 0x26,
    0, picoquic_tp_idle_timeout, 0, 0x02, 0x40, 0x0A,
    0, picoquic_tp_initial_max_streams_bidi, 0, 1, 0x02,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 0x04, 0x80, 0, 0x20, 0,
    0, picoquic_tp_initial_max_data, 0, 0x04, 0x80, 0, 0x40, 0,
    0, picoquic_tp_max_packet_size, 0, 0x02, 0x45, 0xC0,
    0, picoquic_tp_ack_delay_exponent, 0, 0x01, 0x11
};

uint8_t server_param1[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_BYTES,
    0, 0x37,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi,  0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_stateless_reset_token, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

uint8_t server_param2[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_BYTES,
    0, 0x35,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_data, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi, 0, 1, 2,
    0, picoquic_tp_idle_timeout, 0, 2, 0x40, 0xFF,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_stateless_reset_token, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

uint8_t client_param8[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    0, 0x1B,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
};

uint8_t server_param3[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_BYTES,
    0, 86,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_data, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi, 0, 1, 2,
    0, picoquic_tp_idle_timeout, 0, 2, 0x40, 0xFF,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_stateless_reset_token, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    0, picoquic_tp_server_preferred_address, 0, 29,
    4, 4, 10, 0, 0, 1, 0x11, 0x51, 4, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

uint8_t client_param9[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    0, 0x2F,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi,  0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_initial_max_streams_uni,  0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_disable_migration, 0, 0
};

/* Error 1: wrong version, does not match value in the connection context */
uint8_t client_param_err1[] = {
    TRANSPORT_PARAMETERS_FAILED_VERSION_BYTES,
    0, 0x2B,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi,  0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_initial_max_streams_uni, 0, 2, 0x80, 0, 0x40, 0x00
};

/* Error 2: wrong option length, larger than message size */
uint8_t client_param_err2[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    0, 0x2B,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi,  0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_initial_max_streams_uni, 0, 2, 0x80, 0, 0x40, 0x00
};

/* Error 3: wrong option length, one byte shorter than last parameter */
uint8_t client_param_err3[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    0, 0x28,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi,  0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_initial_max_streams_uni, 0, 2, 0x80, 0, 0x40, 0x00
};

/* Error 4: parameter 0 not the right size */
uint8_t client_param_err4[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    0, 0x25,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 2, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi,  0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_initial_max_streams_uni, 0, 2, 0x80, 0, 0x40, 0x00
};

/* Error 5: parameter 1 not the right size */
uint8_t client_param_err5[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    0, 0x29,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_data, 0, 2, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_streams_bidi,  0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_initial_max_streams_uni, 0, 2, 0x80, 0, 0x40, 0x00
};

/* Error 6: parameter 2 not the right size */
uint8_t client_param_err6[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    0, 0x2B,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_data, 0, 4, 0x40, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_initial_max_streams_uni, 0, 4, 0x80, 0, 0x40, 0x00
};

/* Error 7: parameter 3 not the right size */
uint8_t client_param_err7[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    0, 0x2C,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi,  0, 4, 0x00, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 4, 0, 0, 0, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_initial_max_streams_uni, 0, 4, 0x80, 0, 0x40, 0x00
};

/* Error 8: error in encoding of supported versions (length too short) */
uint8_t server_param_err8[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_ERROR1
};

/* Error 9: error in encoding of supported versions (not multiple of 4) */
uint8_t server_param_err9[] = {
    TRANSPORT_PARAMETERS_DEFAULT_VERSION_BYTES,
    TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_ERROR2,
    0, 0x32,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x80, 0, 0xFF, 0xFF,
    0, picoquic_tp_initial_max_data, 0, 4, 0x80, 0x40, 0, 0,
    0, picoquic_tp_initial_max_streams_bidi,  0, 4, 0x80, 0, 0x40, 0x00,
    0, picoquic_tp_idle_timeout, 0, 1, 0x1E,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_stateless_reset_token, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

/* Error 10: wrong version presented by server */
uint8_t server_param_err10[] = {
    TRANSPORT_PARAMETERS_FAILED_VERSION_BYTES,
    TRANSPORT_PARAMETERS_SUPPORTED_VERSIONS_BYTES,
    0, 87,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_data, 0, 4, 0x81, 0, 0, 0,
    0, picoquic_tp_initial_max_stream_data_bidi_local, 0, 2, 0, 2,
    0, picoquic_tp_idle_timeout, 0, 2, 0x40, 0xFF,
    0, picoquic_tp_max_packet_size, 0, 2, 0x45, 0xC8,
    0, picoquic_tp_stateless_reset_token, 0, 16, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    0, picoquic_tp_server_preferred_address, 0, 29,
    4, 4, 10, 0, 0, 1, 0x11, 0x51, 4, 1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16
};

typedef struct st_transport_param_error_test_t {
    int mode;
    uint8_t * target;
    size_t target_length;
    uint16_t local_error;
} transport_param_error_test_t;

static transport_param_error_test_t transport_param_error_case[] = {
    { 0, client_param_err1, sizeof(client_param_err1), PICOQUIC_TRANSPORT_VERSION_NEGOTIATION_ERROR},
    { 0, client_param_err2, sizeof(client_param_err2), PICOQUIC_TRANSPORT_PARAMETER_ERROR},
    { 0, client_param_err3, sizeof(client_param_err3), PICOQUIC_TRANSPORT_PARAMETER_ERROR},
    { 0, client_param_err4, sizeof(client_param_err4), PICOQUIC_TRANSPORT_PARAMETER_ERROR},
    { 0, client_param_err5, sizeof(client_param_err5), PICOQUIC_TRANSPORT_PARAMETER_ERROR},
    { 0, client_param_err6, sizeof(client_param_err6), PICOQUIC_TRANSPORT_PARAMETER_ERROR},
    { 0, client_param_err7, sizeof(client_param_err7), PICOQUIC_TRANSPORT_PARAMETER_ERROR},
    { 1, server_param_err8, sizeof(server_param_err8), PICOQUIC_TRANSPORT_PARAMETER_ERROR},
    { 1, server_param_err9, sizeof(server_param_err9), PICOQUIC_TRANSPORT_PARAMETER_ERROR},
    { 1, server_param_err10, sizeof(server_param_err10), PICOQUIC_TRANSPORT_VERSION_NEGOTIATION_ERROR}
};

static size_t nb_transport_param_error_case = sizeof(transport_param_error_case) / sizeof(transport_param_error_test_t);

/*
 * Before testing the transport parameters, test the encoding of stream_id
 */

int stream_id_to_rank_test()
{
    int ret = 0;
    uint16_t test_rank[5] = { 0, 1, 2, 13833, 65535 };

    for (int stream_type = 0; stream_type < 4; stream_type += 2) {
        for (int extension_mode = 0; extension_mode < 2; extension_mode ++) {
            for (int rank_id = 0; rank_id < 5; rank_id++) {
                uint32_t stream_id = picoquic_decode_transport_param_stream_id(test_rank[rank_id], extension_mode, stream_type);
                uint16_t decoded_rank = picoquic_prepare_transport_param_stream_id(stream_id); 
                uint32_t decoded_stream_id = picoquic_decode_transport_param_stream_id(decoded_rank, extension_mode, stream_type);

                if (decoded_rank != test_rank[rank_id] || decoded_stream_id != stream_id) {
                    ret = -1;
                    DBG_PRINTF("Extension mode %d, stream type %d, rank %d -> stream %d -> rank %d\n",
                        extension_mode, stream_type, test_rank[rank_id], stream_id, decoded_rank, decoded_stream_id);
                }
            }
        }
    }

    return ret;
}

static int transport_param_compare(picoquic_tp_t* param, picoquic_tp_t* ref) {
    int ret = 0;

    if (param->initial_max_stream_data_bidi_local != ref->initial_max_stream_data_bidi_local) {
        ret = -1;
    }
    else if (param->initial_max_stream_data_bidi_remote != ref->initial_max_stream_data_bidi_remote) {
        DBG_PRINTF("initial_max_stream_data_bidi_remote: got %d, expected %d\n",
            param->initial_max_stream_data_bidi_remote, ref->initial_max_stream_data_bidi_remote);
        ret = -1;
    }
    else if (param->initial_max_stream_data_uni != ref->initial_max_stream_data_uni) {
        DBG_PRINTF("initial_max_stream_data_uni: got %d, expected %d\n",
            param->initial_max_stream_data_uni, ref->initial_max_stream_data_uni);
        ret = -1;
    }
    else if (param->initial_max_data != ref->initial_max_data) {
        DBG_PRINTF("initial_max_data: got %d, expected %d\n",
            param->initial_max_data, ref->initial_max_data);
        ret = -1;
    }
    else if (param->initial_max_stream_id_bidir != ref->initial_max_stream_id_bidir) {
        DBG_PRINTF("initial_max_stream_id_bidir: got %d, expected %d\n",
            param->initial_max_stream_id_bidir, ref->initial_max_stream_id_bidir);
        ret = -1;
    }
    else if (param->initial_max_stream_id_unidir != ref->initial_max_stream_id_unidir) {
        DBG_PRINTF("initial_max_stream_id_unidir: got %d, expected %d\n",
            param->initial_max_stream_id_unidir, ref->initial_max_stream_id_unidir);
        ret = -1;
    }
    else if (param->idle_timeout != ref->idle_timeout) {
        DBG_PRINTF("idle_timeout: got %d, expected %d\n",
            param->idle_timeout, ref->idle_timeout);
        ret = -1;
    }
    else if (param->prefered_address.ipVersion != ref->prefered_address.ipVersion) {
        DBG_PRINTF("prefered_address.ipVersion: got %d, expected %d\n",
            param->prefered_address.ipVersion, ref->prefered_address.ipVersion);
        ret = -1;
    }
    else if (param->prefered_address.ipVersion != 0) {
        int ip_len = (param->prefered_address.ipVersion == 4) ? 4 : 16;
        if (memcmp(param->prefered_address.ipAddress, ref->prefered_address.ipAddress, ip_len) != 0) {
            DBG_PRINTF("%s", "prefered_address.ipAddress: values don't match\n");
            ret = -1;
        }
        else if (param->prefered_address.port != ref->prefered_address.port) {
            DBG_PRINTF("prefered_address.port: got %d, expected %d\n",
                param->prefered_address.port, ref->prefered_address.port);
            ret = -1;
        }
        else if (picoquic_compare_connection_id(&param->prefered_address.connection_id, &ref->prefered_address.connection_id) != 0) {
            DBG_PRINTF("%s", "prefered_address.connection_id: values don't match\n");
            ret = -1;
        }
        else if (memcmp(param->prefered_address.statelessResetToken, ref->prefered_address.statelessResetToken, 16) != 0) {
            DBG_PRINTF("%s", "prefered_address.statelessResetToken: values don't match\n");
            ret = -1;
        }
    }

    return ret;
}

int transport_param_set_contexts(picoquic_quic_t ** quic_ctx, picoquic_cnx_t ** test_cnx, uint64_t * p_simulated_time, int mode)
{
    int ret = 0;
    picoquic_connection_id_t initial_cnx_id = { { 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0 }, 8 };
    picoquic_connection_id_t remote_cnx_id = { { 0, 1, 2, 3, 4, 5, 6, 7,  0, 0, 0, 0, 0, 0, 0, 0 }, 8 };
    struct sockaddr_in addr;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];

    *quic_ctx = NULL;
    *test_cnx = NULL;

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_test_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_test_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_test_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {

        memset(&addr, 0, sizeof(struct sockaddr_in));
        addr.sin_family = AF_INET;

        *quic_ctx = picoquic_create(8,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            PICOQUIC_TEST_ALPN, NULL, NULL, NULL, NULL, NULL,
            *p_simulated_time, p_simulated_time, NULL, NULL, 1);


        if (*quic_ctx != NULL) {
            *test_cnx = picoquic_create_cnx(*quic_ctx, initial_cnx_id, remote_cnx_id,
                (struct sockaddr*) &addr, 0, 0, "sni", "alpn", (mode == 0) ? 1 : 0);
        }

        if (*quic_ctx == NULL || *test_cnx == NULL) {
            ret = -1;
        }
    }

    return ret;
}

int transport_param_one_test(int mode, uint32_t version, uint32_t proposed_version,
    picoquic_tp_t* param, uint8_t* target, size_t target_length)
{
    int ret;
    picoquic_quic_t * quic_ctx;
    picoquic_cnx_t * test_cnx;
    uint8_t buffer[256];
    size_t encoded, decoded; 
    uint64_t simulated_time = 0;

    ret = transport_param_set_contexts(&quic_ctx, &test_cnx, &simulated_time, mode);

    if (ret == 0) {
        /* initialize the connection object to the test parameters */
        memcpy(&test_cnx->local_parameters, param, sizeof(picoquic_tp_t));
        // test_cnx.version = version;
        test_cnx->version_index = picoquic_get_version_index(version);
        test_cnx->proposed_version = proposed_version;

        ret = picoquic_prepare_transport_extensions(test_cnx, mode, buffer, sizeof(buffer), &encoded);
    }
    else {
        DBG_PRINTF("%s", "Could not create the test context\n");
    }

    if (ret == 0) {
        if (encoded != target_length) {
            DBG_PRINTF("Encoded length: expected %d, got %d\n",
                (int)encoded, (int)target_length);
            ret = -1;
        } else {
            if (mode == 0) {
                if (memcmp(buffer, target, target_length) != 0) {
                    DBG_PRINTF("%s", "Encoded values don't match\n");
                    ret = -1;
                }
            }
            else {
                uint8_t target_secret[PICOQUIC_RESET_SECRET_SIZE];

                (void)picoquic_create_cnxid_reset_secret(quic_ctx, test_cnx->path[0]->local_cnxid,
                    target_secret);

                if (memcmp(buffer, target, target_length - PICOQUIC_RESET_SECRET_SIZE) != 0) {
                    DBG_PRINTF("%s", "Encoded values up to reset secret don't match\n");
                    ret = -1;
                } else if (memcmp(buffer + target_length - PICOQUIC_RESET_SECRET_SIZE, target_secret,
                    PICOQUIC_RESET_SECRET_SIZE) != 0) {
                    DBG_PRINTF("%s", "Reset secret doesn't match expected value\n");
                    ret = -1;
                }
            }
        }
    }

    if (ret == 0) {
        ret = picoquic_receive_transport_extensions(test_cnx, mode, buffer, encoded, &decoded);

        if (ret == 0 && transport_param_compare(&test_cnx->remote_parameters, param) != 0) {
            DBG_PRINTF("%s", "Parameter values don't match\n");
            ret = -1;
        }
    }

    if (test_cnx != NULL) {
        picoquic_delete_cnx(test_cnx);
    }

    if (quic_ctx != NULL) {
        picoquic_free(quic_ctx);
    }

    return ret;
}

int transport_param_decode_test(int mode, uint32_t version, uint32_t proposed_version,
    picoquic_tp_t* param, uint8_t* target, size_t target_length)
{
    int ret = 0;
    picoquic_quic_t * quic_ctx = NULL;
    picoquic_cnx_t * test_cnx = NULL;
    uint64_t simulated_time = 0;
    size_t decoded;

    ret = transport_param_set_contexts(&quic_ctx, &test_cnx, &simulated_time, mode);

    if (ret == 0) {
        ret = picoquic_receive_transport_extensions(test_cnx, mode,
            target, target_length, &decoded);
        if (ret != 0) {
            DBG_PRINTF("Decoding returns %x\n", ret);
        }
    }

    if (ret == 0 && decoded != target_length) {
        DBG_PRINTF("Decoded length: got %d, expected %d\n",
            (int)decoded, (int)target_length);
        ret = -1;
    }

    if (ret == 0 && transport_param_compare(&test_cnx->remote_parameters, param) != 0) {
        DBG_PRINTF("%s", "Parameter values don't match\n");
        ret = -1;
    }

    if (test_cnx != NULL) {
        picoquic_delete_cnx(test_cnx);
    }

    if (quic_ctx != NULL) {
        picoquic_free(quic_ctx);
    }

    return ret;
}

int transport_param_error_test(int mode, uint8_t* target, size_t target_length, uint16_t local_error)
{
    int ret = 0;
    picoquic_quic_t * quic_ctx = NULL;
    picoquic_cnx_t * test_cnx = NULL;
    uint64_t simulated_time = 0;
    size_t decoded;

    ret = transport_param_set_contexts(&quic_ctx, &test_cnx, &simulated_time, mode);

    if (ret == 0) {
        int err_ret = picoquic_receive_transport_extensions(test_cnx, mode,
            target, target_length, &decoded);
        if (err_ret == 0) {
            DBG_PRINTF("Decoding returns %x\n", err_ret);
            ret = -1;
        }
        else if (test_cnx->cnx_state != picoquic_state_disconnecting &&
            test_cnx->cnx_state != picoquic_state_handshake_failure) {
            DBG_PRINTF("Unexpected connection state %d\n", test_cnx->cnx_state);
            ret = -1;
        }
        else if (test_cnx->local_error != local_error) {
            DBG_PRINTF("Unexpected local error 0x%x instead of 0x%x\n", test_cnx->local_error, local_error);
            ret = -1;
        }
    }

    if (test_cnx != NULL) {
        picoquic_delete_cnx(test_cnx);
    }

    if (quic_ctx != NULL) {
        picoquic_free(quic_ctx);
    }

    return ret;
}

int transport_param_fuzz_test(int mode, uint32_t version, uint32_t proposed_version,
    picoquic_tp_t* param, uint8_t* target, size_t target_length, uint64_t* proof)
{
    int ret = 0;
    int fuzz_ret = 0;
    picoquic_quic_t * quic_ctx = NULL;
    picoquic_cnx_t * test_cnx = NULL;
    uint64_t simulated_time = 0;
    uint8_t buffer[256];
    size_t decoded;
    uint8_t fuzz_byte = 1;
    int suspended = debug_printf_reset(1);

    /* test for valid arguments */
    if (target_length < 8 || target_length > sizeof(buffer)) {
        return -1;
    }


    ret = transport_param_set_contexts(&quic_ctx, &test_cnx, &simulated_time, mode);

    if (ret == 0) {
        /* initialize the connection object to the test parameters */
        memcpy(&test_cnx->local_parameters, param, sizeof(picoquic_tp_t));
        test_cnx->version_index = picoquic_get_version_index(version);
        test_cnx->proposed_version = proposed_version;
    }

    /* add computation of the proof argument to make sure the compiler 
	 * will not optimize the loop to nothing */

    *proof = 0;

    /* repeat multiple times */
    for (size_t l = 1; ret == 0 && l <= 8; l++) {
        for (size_t i = l; i <= target_length; i++) {
            /* copy message to buffer */
            memcpy(buffer, target, target_length);

            /* fuzz */
            for (size_t j = i - l; j < i; j++) {
                buffer[j] ^= fuzz_byte;
                fuzz_byte++;
            }

            /* Try various bad lengths */
            for (size_t dl = 0; dl < target_length; dl += l + 6)
            {
                /* decode */
                fuzz_ret = picoquic_receive_transport_extensions(test_cnx, mode, buffer,
                    target_length - dl, &decoded);

                if (fuzz_ret != 0) {
                    *proof += (uint64_t)fuzz_ret;
                }
                else {
                    *proof += test_cnx->remote_parameters.initial_max_stream_data_bidi_local;

                    if (decoded > target_length - dl) {
                        ret = -1;
                    }
                }
            }
        }
    }

    (void)debug_printf_reset(suspended);

    if (test_cnx != NULL) {
        picoquic_delete_cnx(test_cnx);
    }

    if (quic_ctx != NULL) {
        picoquic_free(quic_ctx);
    }

    return ret;
}

int transport_param_test()
{
    int ret = 0;
    uint64_t proof = 0;
    uint32_t version_default = picoquic_supported_versions[0].version;

    ret = transport_param_one_test(0, version_default, version_default,
        &transport_param_test1, client_param1, sizeof(client_param1));
    if (ret != 0) {
        DBG_PRINTF("Param test TP1, CP1 returns %x\n", ret);
    } else {
        ret = transport_param_one_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test2, client_param2, sizeof(client_param2));
        if (ret != 0) {
            DBG_PRINTF("Param test TP2, CP2 returns %x\n", ret);
        }
    }

    if (ret == 0) {
        ret = transport_param_decode_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test3, client_param3, sizeof(client_param3));
        if (ret != 0) {
            DBG_PRINTF("Decode test TP3, CP3 returns %x\n", ret);
        }
    }

    if (ret == 0) {
        ret = transport_param_one_test(1, version_default, version_default,
            &transport_param_test4, server_param1, sizeof(server_param1));
        if (ret != 0) {
            DBG_PRINTF("Param test TP4, SP1 returns %x\n", ret);
        }
    }

    if (ret == 0) {
        ret = transport_param_one_test(1, version_default, 0x0A1A0A1A,
            &transport_param_test5, server_param2, sizeof(server_param2));
        if (ret != 0) {
            DBG_PRINTF("Param test TP5, SP2 returns %x\n", ret);
        }
    }

    if (ret == 0) {
        ret = transport_param_decode_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test6, client_param4, sizeof(client_param4));
        if (ret != 0) {
            DBG_PRINTF("Decode test TP6, CP4 returns %x\n", ret);
        }
    }

    if (ret == 0) {
        ret = transport_param_decode_test(0, version_default, 0xBABABABA,
            &transport_param_test7, client_param5, sizeof(client_param5));
        if (ret != 0) {
            DBG_PRINTF("Decode test TP7, CP5 returns %x\n", ret);
        }
    }

    if (ret == 0) {
        ret = transport_param_decode_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test8, client_param8, sizeof(client_param8));
        if (ret != 0) {
            DBG_PRINTF("Decode test TP8, CP8 returns %x\n", ret);
        }
    }

    if (ret == 0) {
        ret = transport_param_decode_test(1, version_default, 0x0A1A0A1A,
            &transport_param_test9, server_param3, sizeof(server_param3));
        if (ret != 0) {
            DBG_PRINTF("Decode test TP9, SP3 returns %x\n", ret);
        }
    }

    if (ret == 0) {
        ret = transport_param_one_test(0, version_default, version_default,
            &transport_param_test10, client_param9, sizeof(client_param9));
        if (ret != 0) {
            DBG_PRINTF("Param test TP10, CP9 returns %x\n", ret);
        }
    }

    for (size_t i = 0; ret == 0 && i < nb_transport_param_error_case; i++) {
        ret = transport_param_error_test(transport_param_error_case[i].mode, transport_param_error_case[i].target, 
            transport_param_error_case[i].target_length, transport_param_error_case[i].local_error);
        if (ret != 0) {
            DBG_PRINTF("Param error test %d fails\n", (int)i);
        }
    }

    if (ret == 0)
    {
        DBG_PRINTF("%s", "Starting transport parameters fuzz test.\n");
        
        ret = transport_param_fuzz_test(0, version_default, 0x0A1A0A1A,
            &transport_param_test2, client_param2, sizeof(client_param2), &proof);

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
#define LOG_TP_TEST_REF "picoquictest\\log_tp_test_ref.txt"
#else
#define LOG_TP_TEST_REF "picoquictest/log_tp_test_ref.txt"
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
    int suspended = debug_printf_reset(1);


    /* test for valid arguments */
    if (target_length < 8 || target_length > sizeof(buffer)) {
        return -1;
    }


    /* repeat multiple times */
    for (size_t l = 1; l <= 8; l++) {
        for (size_t i = l; i <= target_length; i++) {
            FILE *F;
#ifdef _WINDOWS
            if (fopen_s(&F, log_tp_fuzz_file, "w") != 0) {
                if (F != NULL) {
                    fclose(F);
                    F = NULL;
                }
            }
#else
            F = fopen(log_tp_fuzz_file, "w");
#endif

            if (F == NULL) {
                ret = -1;
            }
            else {
                /* copy message to buffer */
                memcpy(buffer, target, target_length);

                /* fuzz */
                for (size_t j = i - l; j < i; j++) {
                    buffer[j] ^= fuzz_byte;
                    fuzz_byte++;
                }

                /* Try various bad lengths */
                for (size_t dl = 0; dl < target_length; dl += l + 6)
                {
                    /* log */
                    transport_param_log_test_one(F, buffer, target_length - dl, client_mode);
                }
            }
            fclose(F);
        }
    }

    (void) debug_printf_reset(suspended);

    return ret;
}

int transport_param_log_test()
{
    FILE* F = NULL;
    int ret = 0;

#ifdef _WINDOWS
    if (fopen_s(&F, log_tp_test_file, "w") != 0) {
        ret = -1;
        if (F != NULL) {
            fclose(F);
            F = NULL;
        }
    }
#else
    F = fopen(log_tp_test_file, "w");
#endif

    if (F != NULL) {
        char log_tp_test_ref[512];

        transport_param_log_test_one(F, client_param1, sizeof(client_param1), 0);
        transport_param_log_test_one(F, client_param2, sizeof(client_param2), 0);
        transport_param_log_test_one(F, client_param3, sizeof(client_param3), 0);
        transport_param_log_test_one(F, server_param1, sizeof(server_param1), 1);
        transport_param_log_test_one(F, server_param2, sizeof(server_param2), 1);
        transport_param_log_test_one(F, client_param4, sizeof(client_param4), 0);
        transport_param_log_test_one(F, client_param5, sizeof(client_param5), 0);
        transport_param_log_test_one(F, server_param3, sizeof(server_param3), 1);

        fclose(F);

        ret = picoquic_get_input_path(log_tp_test_ref, sizeof(log_tp_test_ref), picoquic_test_solution_dir, LOG_TP_TEST_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the log TP ref file name.\n");
        } else {
            ret = picoquic_test_compare_files(log_tp_test_file, log_tp_test_ref);
        }
    }

    if (ret == 0)
    {
        DBG_PRINTF("Doing fuzz test of transport parameter logging into %s\n", log_tp_fuzz_file);

        ret = transport_param_log_fuzz_test(0, client_param2, sizeof(client_param2));

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
    { 0, PICOQUIC_STREAM_ID_BIDIR, 0, 0xFFFFFFFF },
    { 1, PICOQUIC_STREAM_ID_BIDIR, 0, 0xFFFFFFFF },
    { 0, PICOQUIC_STREAM_ID_UNIDIR, 0, 0xFFFFFFFF },
    { 1, PICOQUIC_STREAM_ID_UNIDIR, 0, 0xFFFFFFFF },
    { 0, PICOQUIC_STREAM_ID_BIDIR,  1, PICOQUIC_STREAM_ID_SERVER_INITIATED_BIDIR },
    { 1, PICOQUIC_STREAM_ID_BIDIR, 1, PICOQUIC_STREAM_ID_CLIENT_INITIATED_BIDIR },
    { 0, PICOQUIC_STREAM_ID_UNIDIR, 1, PICOQUIC_STREAM_ID_SERVER_INITIATED_UNIDIR },
    { 1, PICOQUIC_STREAM_ID_UNIDIR, 1, PICOQUIC_STREAM_ID_CLIENT_INITIATED_UNIDIR },
    { 0, PICOQUIC_STREAM_ID_BIDIR, 65535, PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_BIDIR },
    { 1, PICOQUIC_STREAM_ID_BIDIR, 65535, PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_BIDIR },
    { 0, PICOQUIC_STREAM_ID_UNIDIR, 65535, PICOQUIC_STREAM_ID_SERVER_MAX_INITIAL_UNIDIR },
    { 1, PICOQUIC_STREAM_ID_UNIDIR, 65535, PICOQUIC_STREAM_ID_CLIENT_MAX_INITIAL_UNIDIR },
    { 0, PICOQUIC_STREAM_ID_BIDIR, 5, 17},
    { 1, PICOQUIC_STREAM_ID_BIDIR, 6, 20 }
};

static size_t const nb_transport_param_stream_id_test_table =
    sizeof(transport_param_stream_id_test_table) / sizeof(transport_param_stream_id_test_t);

int transport_param_stream_id_test() {
    int ret = 0;

    /* Decoding test */
    for (size_t i = 0; i < nb_transport_param_stream_id_test_table; i++) {
        uint16_t rank = picoquic_prepare_transport_param_stream_id(
            transport_param_stream_id_test_table[i].stream_id);

        if (rank != transport_param_stream_id_test_table[i].rank) {
            DBG_PRINTF("TP Stream prepare ID [%d] fails. Stream= 0x%x, expected rank 0x%x, got 0x%x\n", i,
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
            DBG_PRINTF("TP Stream decode ID [%d] fails. Rank= 0x%x, expected stream 0x%x, got 0x%x\n", i,
                transport_param_stream_id_test_table[i].rank,
                transport_param_stream_id_test_table[i].stream_id,
                stream_id);
            ret = -1;
        }
    }

    return ret;
}
