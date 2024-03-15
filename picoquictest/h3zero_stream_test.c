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
    if (nb_targets >= 4) {
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
    uint8_t* bytes = hvst.bytes;
    uint8_t* bytes_max = hvst.bytes + hvst.nb_bytes;

    while (ret == 0) {
        nb_not_64max = 0;
        for (size_t i = 0; i < nb_targets; i++) {
            if (hvst.v_int[i] != UINT64_MAX) {
                nb_not_64max++;
            }
        }
        if (nb_not_64max >= nb_targets) {
            break;
        }
        uint8_t* bytes_max = hvst.bytes + hvst.nb_bytes;
        if (bytes >= bytes_max) {
            /* nothing more to feed */
            break;
        }
        if (bytes_max > bytes + chunk_bytes) {
            bytes_max = bytes + chunk_bytes;
        }
        bytes = h3zero_varint_from_stream(bytes, bytes_max, &hvst.v_int[nb_not_64max], hvst.buffer, &hvst.buffer_length);
    }
    if (nb_not_64max < nb_targets) {
        ret = -1;
    }
    for (size_t i = 0; ret == 0 && i < nb_targets; i++) {
        if (hvst.v_int[i] != targets[i]) {
            ret = -1;
            break;
        }
    }
    return ret;
}

int h3zero_varint_stream_test()
{
    int ret = 0;
    uint64_t targets[4] = { 132, 4, 0x10001, 0x10000001 };

    for (size_t nb_targets = 1; ret = 0 && nb_targets <= 4; nb_targets++) {
        for (size_t j = 0; ret == 0 && j < 4; j++) {
            size_t chunk_bytes = (size_t)(1 << j);
            ret = h3zero_varint_stream_chunk_test(targets, nb_targets, chunk_bytes);
        }
    }
    return ret;
}