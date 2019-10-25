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
#include "picoquictest_internal.h"
#include <stdlib.h>
#include <string.h>
#include "qinqproto.h"

uint8_t* picoquic_frames_varint_skip(uint8_t* bytes, const uint8_t* bytes_max);

struct st_qinq_test_rh_t {
    uint64_t direction;
    uint64_t hcid;
    size_t address_length;
    uint8_t address[16];
    uint16_t port;
    picoquic_connection_id_t cid;
};

static uint8_t qinq_rh1[] = {
    QINQ_PROTO_RESERVE_HEADER, 0, 1, 4, 10, 0, 0, 1, 1, 167, 4, 0x01, 0x02, 0x03, 0x04
};

static struct st_qinq_test_rh_t rh1 = {
    0, 1, 4, {10, 0, 0, 1}, 443, { { 0x01, 0x02, 0x03, 0x04}, 4}
};

static uint8_t qinq_rh2[] = {
    QINQ_PROTO_RESERVE_HEADER, 1, 2, 16,
    0x20, 0x01, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
    0x12, 0x34, 8, 11, 12, 13, 14, 15, 16, 17, 18
};

static struct st_qinq_test_rh_t rh2 = {
    1, 2, 16, {0x20, 0x01, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, 
    0x1234, { { 11, 12, 13, 14, 15, 16, 17, 18}, 8}
};

static int qinq_test_one_rh(const struct st_qinq_test_rh_t* rh, size_t length, uint8_t* message)
{
    int ret = 0;
    uint64_t direction= UINT64_MAX;
    uint64_t hcid = UINT64_MAX;
    size_t address_length = 0;
    uint8_t const *address = NULL;
    uint16_t port = 0;
    picoquic_connection_id_t cid = { {0}, 0 };
    uint8_t* bytes = message;
    uint8_t* bytes_max = message + length;

    if ((bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL) {
        bytes = picoqinq_decode_reserve_header(bytes, bytes_max, &direction, &hcid, &address_length, &address, &port, &cid);
    }

    if (bytes == NULL) {
        ret = -1;
        DBG_PRINTF("Parsing reserve header returns: %d\n", ret);
    }
    else if (bytes_max > bytes) {
        DBG_PRINTF("Bytes remain after parsing reserve header: %llu\n",
            (unsigned long long)(bytes_max - bytes));
        ret = -1;
    }
    else if (direction != rh->direction) {
        DBG_PRINTF("Wrong direction: %d\n", direction);
        ret = -1;
    }
    else if (hcid != rh->hcid) {
        DBG_PRINTF("Wrong hcid: %d\n", hcid);
        ret = -1;
    }
    else if (address_length != rh->address_length) {
        DBG_PRINTF("Wrong address_length: %d\n", address_length);
        ret = -1;
    }
    else if (memcmp(address, rh->address, address_length) != 0) {
        DBG_PRINTF("Wrong address: { %d, %d, %d, %d, ... }\n", address[0], address[1], address[2], address[3]);
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&cid, &rh->cid) != 0) {
        DBG_PRINTF("Wrong CID: %d: { %d, %d, %d, %d, ... }\n", cid.id_len, cid.id[0], cid.id[1], cid.id[2], cid.id[3]);
        ret = -1;
    }

    if (ret == 0) {
        uint8_t buf[256];
        
        bytes_max = buf + sizeof(buf);

        bytes = picoqinq_encode_reserve_header(buf, bytes_max, direction, hcid, address_length, address, port, &cid);
        if (bytes == NULL) {
            ret = -1;
            DBG_PRINTF("Preparing reserve header returns: %d\n", ret);
        }
        else if (bytes - buf != length) {
            DBG_PRINTF("Preparing reserve header wrong length: %llu\n", (unsigned long long)(bytes - buf));
            ret = -1;
        }
        else if (memcmp(buf, message, length) != 0) {
            DBG_PRINTF("%s", "Prepared reserve header does not match\n");
            ret = -1;
        }
    }

    return ret;
}

int qinq_rh_test()
{
    int ret;

    if ((ret = qinq_test_one_rh(&rh1, sizeof(qinq_rh1), qinq_rh1)) == 0) {
        ret = qinq_test_one_rh(&rh2, sizeof(qinq_rh2), qinq_rh2);
    }

    return ret;
}