/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
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
#include <stdio.h>
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "democlient.h"
#include "demoserver.h"
#ifdef _WINDOWS
#include "wincompat.h"
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif
#if 0
/* Include picotls.h in order to support tests of ESNI */
#include "picotls.h"
#include "tls_api.h"
#endif
#include "autoqlog.h"
#include "picoquic_binlog.h"
#include "pico_webtransport.h"

/* testing:
 * uint8_t * h3zero_varint_from_stream(uint8_t* bytes, uint8_t* bytes_max, uint64_t * result, uint8_t * buffer, size_t* buffer_length)
 *
 * start with a stream encoding, made of a set of bytes, encoding a number of varint puls some extra bytes.
 * the state is captured in a decoded varint vector of size N.
 * the vector is initialized to UINT64_MAX.
 * the logic:
 *   get the encoded buffer that contains the encoded value of the varints, as a string of bytes
 *   feed that buffer to the decoder in multiple ways:
 *    - all bytes at once,
 *    - one byte at a time,
 *    - two bytes at a time.
 *   The decoder itself will try to decode the next varint in the record, and consume bytes.
 *   if the varint value is not UINT64_MAX, go to the next one, etc.
 */

typedef struct st_h3zero_varint_stream_test_t {
    uint64_t v_int[4];
    uint64_t targets[4];
    size_t nb_targets;
    uint8_t buffer[16];
    size_t buffer_length;
    uint8_t bytes[64];
    size_t nb_bytes;
    size_t nb_processed;
} h3zero_varint_stream_test_t;

static int h3zero_varint_stream_test_init(h3zero_varint_stream_test_t * hvst, uint64_t * targets, size_t nb_targets)
{
    int ret = 0;
    uint8_t * bytes = hvst->bytes;
    uint8_t * bytes_max = bytes + sizeof(hvst->bytes);

    memset(hvst, 0, sizeof(h3zero_varint_stream_test_t));
    if (nb_targets > 4) {
        ret = -1;
    }
    else {
        hvst->nb_targets = nb_targets;
        for (size_t i = 0; i < nb_targets && i < 4; i++) {
            hvst->targets[i] = targets[i];
            hvst->v_int[i] = UINT64_MAX;
            bytes = picoquic_frames_varint_encode(bytes, bytes_max, targets[i]);
            if (bytes == NULL) {
                ret = -1;
                break;
            }
        }
        if (ret == 0) {
            hvst->nb_bytes = bytes - hvst->bytes;
        }
    }
    return ret;
}

int h3zero_varint_stream_chunk_test(uint64_t * targets, size_t nb_targets, size_t chunk_bytes)
{
    h3zero_varint_stream_test_t hvst;
    int ret = h3zero_varint_stream_test_init(&hvst, targets, nb_targets);
    size_t nb_not_64max = 0;
    size_t nb_chunks = 0;
    uint8_t* bytes = hvst.bytes;
    uint8_t* bytes_max = hvst.bytes + hvst.nb_bytes;
    uint8_t* chunk_start;
    uint8_t* chunk_end;

    while (ret == 0) {
        chunk_start = hvst.bytes + chunk_bytes * nb_chunks;
        chunk_end = chunk_start + chunk_bytes;
        if (chunk_start >= bytes_max) {
            /* nothing more to feed */
            break;
        }
        else if (chunk_end >= bytes_max) {
            chunk_end = bytes_max;
        }
        nb_chunks++;
        bytes = chunk_start;
        while (bytes != NULL && bytes < chunk_end) {
            bytes = h3zero_varint_from_stream(bytes, chunk_end, &hvst.v_int[nb_not_64max], hvst.buffer, &hvst.buffer_length);
            if (hvst.v_int[nb_not_64max] != UINT64_MAX) {
                nb_not_64max++;
                if (nb_not_64max >= nb_targets) {
                    break;
                }
                continue;
            }
        }
        if (nb_not_64max >= nb_targets) {
            break;
        }
    }
    if (nb_not_64max < nb_targets) {
        ret = -1;
    }
    else {
        for (size_t i = 0; ret == 0 && i < nb_targets; i++) {
            if (hvst.v_int[i] != targets[i]) {
                ret = -1;
                break;
            }
        }
    }
    return ret;
}

int h3zero_varint_stream_test()
{
    int ret = 0;
    uint64_t targets[4] = { 132, 4, 0x10001, 0x10000001 };

    for (size_t nb_targets = 1; ret == 0 && nb_targets <= 4; nb_targets++) {
        for (size_t j = 0; ret == 0 && j < 4; j++) {
            size_t chunk_bytes = (size_t)(1 << j);
            ret = h3zero_varint_stream_chunk_test(targets, nb_targets, chunk_bytes);
            if (ret == -1) {
                DBG_PRINTF("varint_stream test fails for chunks size= %zu, nb_target=%zu", chunk_bytes, nb_targets);
            }
        }
    }
    return ret;
}

/*
 * Test of
 *  uint8_t* h3zero_parse_remote_unidir_stream(
 *     uint8_t* bytes, uint8_t* bytes_max,
 *     h3zero_stream_ctx_t* stream_ctx,
 *     h3zero_callback_ctx_t* ctx,
 *     uint64_t * error_found)
 * 
 * uint8_t* h3zero_parse_incoming_remote_stream(
 *    uint8_t* bytes, uint8_t* bytes_max,
 *    h3zero_stream_ctx_t* stream_ctx,
 *    h3zero_callback_ctx_t* ctx)
 * 
 * The test requires that a valid context is defined:
 * 
 * h3zero_stream_ctx_t: incoming stream context.
 */

int incoming_unidir_test_fn(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t fin_or_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    return 0;
}

int h3zero_set_test_context(picoquic_quic_t** quic, picoquic_cnx_t** cnx, h3zero_callback_ctx_t** h3_ctx, uint64_t * simulated_time)
{
    int ret = picoquic_test_set_minimal_cnx_with_time(quic, cnx, simulated_time);
    
    if (ret == 0) {
        *h3_ctx = h3zero_callback_create_context(NULL);
        if (*h3_ctx == NULL) {
            ret = -1;
        }
        else {
            picoquic_set_callback(*cnx, h3zero_callback, *h3_ctx);
        }
    }

    return ret;
}

int h3zero_incoming_unidir_test()
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = h3zero_set_test_context(&quic, &cnx, &h3_ctx, &simulated_time);
    uint64_t stream_id = 3;
    h3zero_stream_ctx_t* control_stream_ctx;
    h3zero_stream_ctx_t* stream_ctx = NULL;
    uint8_t unidir_input[] = { 0x40, 0x54, 0x04, 0xf0 };

    if (ret == 0) {
        control_stream_ctx  = picowt_set_control_stream(cnx, h3_ctx);
        if (control_stream_ctx == NULL) {
            ret = -1;
        }
        else {
            unidir_input[2] = (uint8_t)control_stream_ctx->stream_id;
            /* Need to program a stream prefix that matches the connection */
            ret = h3zero_declare_stream_prefix(h3_ctx, control_stream_ctx->stream_id, incoming_unidir_test_fn, NULL);
        }
    }

    if (ret == 0) {
        stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, h3_ctx, 1, 1);
        if (stream_ctx == NULL) {
            ret = -1;
        }
    }
    
    picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx);

    if (ret == 0) {
        int success = 0;

        for (size_t i = 0; ret == 0 && i < 4; i++) {
            uint8_t * bytes = &unidir_input[i];
            uint8_t * bytes_max = bytes + 1;
            bytes = h3zero_parse_incoming_remote_stream(bytes, bytes_max, stream_ctx, h3_ctx);
            if (bytes == bytes_max) {
                continue;
            }
            else if (bytes == NULL) {
                ret = -1;
            }
            else if (bytes != &unidir_input[3]) {
                ret = -1;
            }
            else {
                success = 1;
            }
        }
        if (!success) {
            ret = -1;
        }
    }
    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

/*
* A fraction of the control stream parsing is covered by normal usage :
* -receive h3 settings on control stream,
* -receive web transport control stream.
* This leaves testing gaps :
* -Data received on setting streams after the setting frame
* -Data received on streams that should be ignored.
* 
* The interesting stream types are:
* 
* h3zero_stream_type_control: settings stream
* h3zero_stream_type_push (ignored)
* h3zero_stream_type_qpack_encoder (ignored)
* h3zero_stream_type_qpack_decoder (ignored)
* some random type (ignored)
* 
* The test data on the streams is made of frames. Supported frame types
* are:
* - h3zero_frame_settings
* - h3zero_frame_data
* - h3zero_frame_header
* - h3zero_frame_push_promise
* - h3zero_frame_webtransport_stream
*/

uint8_t* h3zero_parse_remote_unidir_stream(
    uint8_t* bytes, uint8_t* bytes_max,
    h3zero_stream_ctx_t* stream_ctx,
    h3zero_callback_ctx_t* ctx,
    uint64_t* error_found);

uint8_t* h3zero_test_get_setting_frame(uint8_t* bytes, uint8_t* bytes_max)
{
    h3zero_settings_t settings = { 0 };

    bytes = h3zero_settings_encode(bytes, bytes_max, &settings);

    return bytes;
}

uint8_t* h3zero_get_pretend_frame(uint8_t* bytes, uint8_t* bytes_max, uint64_t frame_type)
{
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, frame_type)) == NULL ||
        bytes + 2 >= bytes_max) {
        bytes = NULL;
    }
    else {
        size_t len = bytes_max - bytes - 2;
        if (len > 16) {
            len = 16;
        }
        *bytes++ = (uint8_t)len;
        memset(bytes, 0xaa, len);
        bytes += len;
    }

    return bytes;
}

uint8_t* h3zero_test_submit_frame(uint8_t* bytes, uint8_t* bytes_max, h3zero_stream_ctx_t* stream_ctx, h3zero_callback_ctx_t* h3_ctx, uint64_t* error_found)
{
    uint8_t* next_bytes = NULL;
    for (int i = 0; i < 16 && next_bytes < bytes_max; i++) {
        next_bytes = (i == 7) ? bytes_max : bytes + 1;
        if (next_bytes > bytes_max) {
            next_bytes = bytes_max;
        }
        if ((bytes = h3zero_parse_remote_unidir_stream(bytes, next_bytes, stream_ctx, h3_ctx, error_found)) != next_bytes) {
            bytes = NULL;
            break;
        }
    }
    return bytes;
}

int h3zero_unidir_error_test()
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = h3zero_set_test_context(&quic, &cnx, &h3_ctx, &simulated_time);
    const uint64_t stream_id[5] = { 3, 7, 11, 13, 17 };
    h3zero_stream_ctx_t * stream_ctx[5] = { NULL, NULL, NULL, NULL, NULL };
    uint64_t stream_type[5] = { h3zero_stream_type_control, h3zero_stream_type_push,
        h3zero_stream_type_qpack_encoder, h3zero_stream_type_qpack_decoder,
        123456789 };
    uint64_t frame_type[5] = { h3zero_frame_settings, h3zero_frame_data, 
        h3zero_frame_header, h3zero_frame_push_promise, 123456789 };
    uint8_t buffer[256];
    uint8_t* bytes = NULL;
    uint8_t* last_byte = NULL;
    uint8_t* bytes_max = buffer + sizeof(buffer);
    uint64_t error_found = 0;

    for (int i = 0; ret == 0 && i < 5; i++) {
        if ((stream_ctx[i] = h3zero_find_or_create_stream(cnx, stream_id[i], h3_ctx, 1, 1)) == NULL) {
            ret = -1;
        }
        else if ((bytes = picoquic_frames_varint_encode(buffer, bytes_max, stream_type[i])) != NULL) {
            if (i == 0) {
                bytes = h3zero_test_get_setting_frame(bytes, bytes_max);
            }
            else {
                bytes = h3zero_get_pretend_frame(bytes, bytes_max, frame_type[i]);
            }
        }
        if (bytes == NULL) {
            ret = -1;
        }
        else {
            last_byte = bytes;
            bytes = h3zero_test_submit_frame(buffer, last_byte, stream_ctx[i], h3_ctx, &error_found);
            if (bytes != last_byte ||
                error_found != 0 || !h3_ctx->settings.settings_received) {
                ret = -1;
            }
        }
    }
    /* add random frame to settings, after settings received */

    /* receive a settings frame again, after settings received. */

    /* clean up everything */
    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int h3zero_setting_submit(int is_after_settings, uint64_t frame_type, int expect_skip)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = h3zero_set_test_context(&quic, &cnx, &h3_ctx, &simulated_time);
    uint8_t buffer[256];
    uint8_t* bytes = NULL;
    uint8_t* last_byte = NULL;
    uint8_t* bytes_max = buffer + sizeof(buffer);
    uint64_t error_found = 0;
    h3zero_stream_ctx_t* stream_ctx;

    if (ret != 0 ||
        (stream_ctx = h3zero_find_or_create_stream(cnx, 3, h3_ctx, 1, 1)) == NULL ||
        (bytes = picoquic_frames_varint_encode(buffer, bytes_max, h3zero_stream_type_control)) == NULL ||
        (is_after_settings &&
            (bytes = h3zero_test_get_setting_frame(bytes, bytes_max)) == NULL) ||
        (bytes = h3zero_get_pretend_frame(bytes, bytes_max, frame_type)) == NULL){
        ret = -1; /* format error */
    }

    else {
        last_byte = bytes;
        bytes = h3zero_test_submit_frame(buffer, last_byte, stream_ctx, h3_ctx, &error_found);
        if (expect_skip) {
            if (bytes == NULL || error_found != 0) {
                ret = -1;
            }
        }
        else {
            if (bytes != NULL || error_found == 0) {
                ret = -1;
            }
        }
    }

    /* clean up everything */
    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}


int h3zero_setting_error_test()
{
    uint64_t unexpected_frames[4] = { h3zero_frame_settings, h3zero_frame_data,
        h3zero_frame_header, h3zero_frame_push_promise };

    /* send a frame that is not a setting frames. This is an error */
    int ret = h3zero_setting_submit(0, 1234567, 0);
    /* Add unexpected frame after setting */
    for (int i = 0; ret == 0 && i < 4; i++) {
        ret = h3zero_setting_submit(1, unexpected_frames[i], 0);
    }
    /* add random frame to settings, after settings received */
    if (ret == 0) {
        ret = h3zero_setting_submit(1, 12345678, 1);
    }

    return ret;
}

/* Unit test of data callback.
* 
* we want to exercise `h3zero_callback_data` without actually setting up connections.
* The client will have started a bidir stream context, properly initialized.
* The test program will simulate arrival of frames in this context, until
* FIN or Reset of the stream.

int h3zero_callback_data(picoquic_cnx_t* cnx,
	uint64_t stream_id, uint8_t* bytes, size_t length,
	picoquic_call_back_event_t fin_or_event, h3zero_callback_ctx_t* ctx,
	h3zero_stream_ctx_t* stream_ctx, uint64_t* fin_stream_id)
*
* The client when sending the command initialized the name of the file
* in stream_ctx->file_path.
* After that, the client will receive header frame and data frame,
* until the FIN.
 */
int h3zero_process_h3_client_data(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, h3zero_callback_ctx_t* ctx,
    h3zero_stream_ctx_t* stream_ctx, uint64_t* fin_stream_id);

typedef struct st_client_data_test_spec {
    uint64_t stream_type;
    unsigned int expect_error : 1;
    unsigned int skip_header : 1;
    unsigned int trailer_after_header : 1;
    unsigned int add_trailer : 1;
    unsigned int data_after_trailer : 1;
    unsigned int split_data : 1;
    unsigned int split_submit : 1;
    unsigned int split_fin : 1;
    unsigned int short_length : 1;

} client_data_test_spec_t;

int h3zero_client_data_set_file_name(h3zero_stream_ctx_t* stream_ctx, char const* path_name)
{
    int ret = 0;
    if ((stream_ctx->file_path = picoquic_string_duplicate(path_name)) == NULL) {
        ret = -1;
    }
    else {
        /* ensure that no data is present */
        FILE* F = picoquic_file_open(stream_ctx->file_path, "w");
        if (F == NULL) {
            ret = -1;
        }
        else {
            (void)picoquic_file_close(F);
        }
    }
    return ret;
}

uint8_t* h3zero_client_data_get_response(uint8_t * bytes, uint8_t * bytes_max)
{
    uint8_t* length_byte = NULL;
    uint8_t* data_byte = NULL;
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, h3zero_frame_header)) != NULL) {
        if (bytes + 2 < bytes_max) {
            length_byte = bytes;
            bytes += 2;
            data_byte = bytes;
        }
        else {
            bytes = NULL;
        }
    }
    if (bytes != NULL) {
        bytes = h3zero_create_response_header_frame_ex(bytes, bytes_max,
            h3zero_content_type_text_html, "test client data");
    }
    if (bytes != NULL) {
        size_t sz = bytes - data_byte;
        length_byte[0] = 0x40 + (uint8_t)(sz >> 8);
        length_byte[1] = (uint8_t)(sz & 0xff);
    }
    return bytes;
}

uint8_t* h3zero_client_data_frame(uint8_t* bytes, uint8_t* bytes_max, size_t data_length)
{
    if ((bytes = picoquic_frames_varint_encode(bytes, bytes_max, h3zero_frame_data)) != NULL &&
        (bytes = picoquic_frames_varint_encode(bytes, bytes_max, data_length)) != NULL) {
        if (bytes + data_length > bytes_max) {
            bytes = NULL;
        }
        else {
            memset(bytes, 0xda, data_length);
            bytes += data_length;
        }
    }
    return bytes;
}

uint8_t* h3zero_client_data_frames(uint8_t* bytes, uint8_t* bytes_max, size_t data_length, unsigned int split_data)
{
    size_t l1 = (split_data) ? data_length / 2 : 0;

    if (l1 > 0 && (bytes = h3zero_client_data_frame(bytes, bytes_max, l1)) == NULL){
        bytes = NULL;
    }
    else {
        bytes = h3zero_client_data_frame(bytes, bytes_max, data_length - l1);
    }
    return bytes;
}

int h3zero_client_data_submit(picoquic_cnx_t * cnx, uint64_t  stream_id, uint8_t* bytes, size_t length, 
    h3zero_callback_ctx_t* h3_ctx, h3zero_stream_ctx_t* stream_ctx, uint64_t * finstream_id,
    client_data_test_spec_t* spec)
{
    int ret = 0;
    size_t chunk = (spec->split_submit) ? 7 : length;
    size_t submitted = 0;
    picoquic_call_back_event_t fin_or_event = picoquic_callback_stream_data;

    if (spec->short_length) {
        length--;
    }

    while (ret == 0 && submitted < length) {
        size_t next_chunk = chunk;
        if (submitted + next_chunk >= length) {
            next_chunk = length - submitted;
            if (!spec->split_fin) {
                fin_or_event = picoquic_callback_stream_fin;
            }
        }
        ret = h3zero_process_h3_client_data(cnx, stream_id, bytes + submitted, next_chunk, fin_or_event, h3_ctx,
            stream_ctx, finstream_id);
        submitted += next_chunk;
    }
    if (ret == 0 && spec->split_fin) {
        ret = h3zero_process_h3_client_data(cnx, stream_id, NULL, 0, picoquic_callback_stream_fin, h3_ctx,
            stream_ctx, finstream_id);
    }
    if (cnx->cnx_state != picoquic_state_ready) {
        ret = -1;
    }
    return ret;
}

int h3zero_client_data_test_one(client_data_test_spec_t * spec)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = h3zero_set_test_context(&quic, &cnx, &h3_ctx, &simulated_time);
    uint8_t buffer[1024];
    uint8_t* bytes = NULL;
    uint8_t* bytes_max = buffer + sizeof(buffer);
    uint64_t stream_id = 4;
    uint64_t fin_stream_id = UINT64_MAX;
    size_t data_length = 128;
    h3zero_stream_ctx_t* stream_ctx = NULL;
    char const* path_name = "h3zero_test_client_data.html";

    if (ret == 0 && (stream_ctx = h3zero_find_or_create_stream(cnx, 4, h3_ctx, 1, 1)) == NULL) {
        ret = -1;
    }
    else {
        cnx->cnx_state = picoquic_state_ready;
        ret = h3zero_client_data_set_file_name(stream_ctx, path_name);
        if (ret == 0) {
            stream_ctx->is_open = 1;
        }
    }
    bytes = buffer;

    /* Encode a stream header */
    if (ret == 0 && !spec->skip_header && 
        (bytes = h3zero_client_data_get_response(bytes, bytes_max)) == NULL){
        ret = -1;
    }
    /* encode a stray trailer */
    if (ret == 0 && spec->trailer_after_header &&
        (bytes = h3zero_client_data_get_response(bytes, bytes_max)) == NULL) {
        ret = -1;
    }
    /* Encode a data frame (or 2?)*/
    if (ret == 0 &&
        (bytes = h3zero_client_data_frames(bytes, bytes_max, data_length, spec->split_data)) == NULL) {
        ret = -1;
    }
    /* Encode a stream trailer */
    if (ret == 0 && spec->add_trailer &&
        (bytes = h3zero_client_data_get_response(bytes, bytes_max)) == NULL) {
        ret = -1;
    }

    /* Encode a data frame after the trailer, causing an error */
    if (ret == 0 && spec->data_after_trailer &&
        (bytes = h3zero_client_data_frames(bytes, bytes_max, 15, 0)) == NULL) {
        ret = -1;
    }

    /* submit as incoming data */
    if (ret == 0) {
        int data_ret = h3zero_client_data_submit(cnx, stream_id, buffer, bytes - buffer, h3_ctx, stream_ctx, &fin_stream_id, spec);
        /* verify that the result is as expected */
        if (spec->expect_error) {
            if (data_ret == 0) {
                ret = -1;
            }
        }
        else {
            if (data_ret != 0) {
                ret = -1;
            }
            else {
                /* verify that the stream is properly removed */
                FILE* Fbis = picoquic_file_open(path_name, "r");
                if (Fbis == NULL) {
                    /* error -- the file remained open! */
                    ret = -1;
                }
                else {
                    long sz;
                    fseek(Fbis, 0, SEEK_END);
                    sz = ftell(Fbis);
                    (void)picoquic_file_close(Fbis);
                    if (sz != data_length) {
                        ret = -1;
                    }
                }
            }
        }
    }

    /* clean up everything */
    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}


int h3zero_client_open_stream_file(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx, h3zero_stream_ctx_t* stream_ctx);

int h3zero_error_client_stream_test()
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    uint64_t simulated_time = 0;
    int ret = h3zero_set_test_context(&quic, &cnx, &h3_ctx, &simulated_time);
    h3zero_stream_ctx_t* stream_ctx = NULL;
    char const* path_name = "no_such_path/bad_path\\h3zero_test_client_data.html";

    if (ret == 0 && (stream_ctx = h3zero_find_or_create_stream(cnx, 4, h3_ctx, 1, 1)) == NULL) {
        ret = -1;
    }
    else {
        cnx->cnx_state = picoquic_state_ready;
        if ((stream_ctx->file_path = picoquic_string_duplicate(path_name)) == NULL) {
            ret = -1;
        } else {
            stream_ctx->is_open = 1;

            if (h3zero_client_open_stream_file(cnx, h3_ctx, stream_ctx) == 0) {
                ret = -1;
            }
        }
    }

    /* clean up everything */
    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}


int h3zero_client_data_test()
{
    client_data_test_spec_t spec = { 0 };
    int ret = h3zero_client_data_test_one(&spec);

    if (ret == 0) {
        memset(&spec, 0, sizeof(spec));
        spec.split_data = 1;
        ret = h3zero_client_data_test_one(&spec);
    }

    if (ret == 0) {
        memset(&spec, 0, sizeof(spec));
        spec.split_fin = 1;
        ret = h3zero_client_data_test_one(&spec);
    }

    if (ret == 0) {
        memset(&spec, 0, sizeof(spec));
        spec.split_submit = 1;
        ret = h3zero_client_data_test_one(&spec);
    }

    if (ret == 0) {
        memset(&spec, 0, sizeof(spec));
        spec.add_trailer = 1;
        ret = h3zero_client_data_test_one(&spec);
    }

    if (ret == 0) {
        memset(&spec, 0, sizeof(spec));
        spec.expect_error = 1;
        spec.short_length = 1;
        ret = h3zero_client_data_test_one(&spec);
    }

    if (ret == 0) {
        memset(&spec, 0, sizeof(spec));
        spec.expect_error = 1;
        spec.skip_header = 1;
        ret = h3zero_client_data_test_one(&spec);
    }

    if (ret == 0) {
        memset(&spec, 0, sizeof(spec));
        spec.expect_error = 1;
        spec.trailer_after_header = 1;
        ret = h3zero_client_data_test_one(&spec);
    }

    if (ret == 0) {
        memset(&spec, 0, sizeof(spec));
        spec.expect_error = 1;
        spec.add_trailer = 1;
        spec.data_after_trailer = 1;
        ret = h3zero_client_data_test_one(&spec);
    }

    if (ret == 0) {
        ret = h3zero_error_client_stream_test();
    }

    return ret;
}




/* Tests of the datagram and capsule protocol */

typedef struct st_test_datagram_ctx_t {
    int nb_datagrams_received;
} test_datagram_ctx_t;


int h3zero_test_datagram_cb(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t wt_event,
    struct st_h3zero_stream_ctx_t* stream_ctx,
    void* path_app_ctx)
{
    int ret = 0;
    switch (wt_event) {
    case picohttp_callback_connecting:
        break;
    case picohttp_callback_connect:
        break;
    case picohttp_callback_connect_refused:
        break;
    case picohttp_callback_connect_accepted:
        break;
    case picohttp_callback_post_fin:
    case picohttp_callback_post_data:
        break;
    case picohttp_callback_provide_data: /* Stack is ready to send chunk of response */
        /* We assume that the required stream headers have already been pushed,
        * and that the stream context is already set. Just send the data.
        */
        break;
    case picohttp_callback_post_datagram:
    {
        test_datagram_ctx_t* dg_ctx = (test_datagram_ctx_t*)path_app_ctx;
        if (dg_ctx != NULL) {
            dg_ctx->nb_datagrams_received += 1;
        }
        break;
    }
    case picohttp_callback_provide_datagram: /* Stack is ready to send a datagram */
        break;
    case picohttp_callback_reset: /* Stream has been abandoned. */
        break;
    case picohttp_callback_free: /* Used during clean up the stream. Only cause the freeing of memory. */
        /* Free the memory attached to the stream */
        break;
    case picohttp_callback_deregister:
        break;
    default:
        /* protocol error */
        ret = -1;
        break;
    }
    return ret;
}

uint8_t capsule_datagram[] = {
    0, /* Datagram capsule type = 0 */
    5, /* length = 5 */
    1, 2, 3, 4, 5
};

int h3zero_capsule_receive_chunks(const uint8_t * capsule_bytes, size_t capsule_size, size_t chunk_size, int is_stored)
{
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    h3zero_callback_ctx_t* h3_ctx = NULL;
    h3zero_stream_ctx_t* stream_ctx = NULL;
    uint64_t simulated_time = 0;
    h3zero_capsule_t capsule = { 0 };
    test_datagram_ctx_t dg_ctx = { 0 };
    int ret = h3zero_set_test_context(&quic, &cnx, &h3_ctx, &simulated_time);

    if (ret == 0 && chunk_size > PICOQUIC_MAX_PACKET_SIZE) {
        ret = -1;
    }

    if (ret == 0) {
        ret = h3zero_declare_stream_prefix(h3_ctx, 4, h3zero_test_datagram_cb, &dg_ctx);
    }

    if (ret == 0) {
        /* simulate arrival of a capsule */
        size_t bytes_received = 0;

        capsule.is_stored = is_stored;

        while (ret == 0 && bytes_received < capsule_size) {
            size_t this_chunk = (bytes_received + chunk_size > capsule_size) ? capsule_size - bytes_received : chunk_size;
            uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
            const uint8_t* next_bytes;
            memset(buffer, 0xff, sizeof(buffer));
            memcpy(buffer, capsule_bytes + bytes_received, this_chunk);
            if ((next_bytes = h3zero_accumulate_capsule(buffer, buffer + chunk_size, &capsule, stream_ctx)) == NULL) {
                ret = -1;
            }
            else {
                size_t consumed = next_bytes - buffer;
                bytes_received += consumed;
                if ((consumed < chunk_size && bytes_received < capsule_size) ||
                    bytes_received > capsule_size) {
                    ret = -1;
                }
            }
        }

        if (ret == 0 && (!capsule.is_length_known || !capsule.is_stored)){
            ret = -1;
        }
    }

    if (capsule.capsule_buffer != NULL) {
        free(capsule.capsule_buffer);
        capsule.capsule_buffer = NULL;
    }

    picoquic_set_callback(cnx, NULL, NULL);
    h3zero_callback_delete_context(cnx, h3_ctx);
    picoquic_test_delete_minimal_cnx(&quic, &cnx);

    return ret;
}

int h3zero_capsule_test()
{
    int ret = 0;
    size_t test_chunk[3] = { sizeof(capsule_datagram), sizeof(capsule_datagram) - 1, 1 };

    for (int i = 0; ret == 0 && i < 3; i++) {
        ret = h3zero_capsule_receive_chunks(capsule_datagram, sizeof(capsule_datagram), test_chunk[i], i == 0);
        if (ret != 0) {
            DBG_PRINTF("Capsule receive chunk=%zu/%zu fails", test_chunk[i], sizeof(capsule_datagram));
        }
    }

    return ret;
}