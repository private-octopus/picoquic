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
    QINQ_PROTO_RESERVE_HEADER, 0, 1, 4, 10, 0, 0, 1, 1, 187, 4, 0x01, 0x02, 0x03, 0x04
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
    struct sockaddr_storage addr_s;
    struct sockaddr_storage addr_target;

    memset(&addr_target, 0, sizeof(struct sockaddr_storage));

    if (rh->address_length == 4) {
        struct sockaddr_in* addr4 = (struct sockaddr_in*) & addr_target;
        addr4->sin_family = AF_INET;
        memcpy(&addr4->sin_addr, rh->address, 4);
        addr4->sin_port = rh->port;
    }
    else if (rh->address_length == 16) {
        struct sockaddr_in6* addr6 = (struct sockaddr_in6*) & addr_target;
        addr6->sin6_family = AF_INET6;
        memcpy(&addr6->sin6_addr, rh->address, 16);
        addr6->sin6_port = rh->port;
    }

    if ((bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL) {
        bytes = picoqinq_decode_reserve_header(bytes, bytes_max, &direction, &hcid, &addr_s, &cid);
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
    else if (picoquic_compare_addr((struct sockaddr *)&addr_target, (struct sockaddr*) & addr_s) != 0){
        DBG_PRINTF("Wrong address, family: %d\n", addr_s.ss_family);
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&cid, &rh->cid) != 0) {
        DBG_PRINTF("Wrong CID: %d: { %d, %d, %d, %d, ... }\n", cid.id_len, cid.id[0], cid.id[1], cid.id[2], cid.id[3]);
        ret = -1;
    }

    if (ret == 0) {
        uint8_t buf[256];
        
        bytes_max = buf + sizeof(buf);

        bytes = picoqinq_encode_reserve_header(buf, bytes_max, direction, hcid, (struct sockaddr *)&addr_target, &cid);
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

struct st_qinq_test_rcid_t {
    picoquic_connection_id_t cid;
};

static uint8_t qinq_rcid1[] = {
    QINQ_PROTO_RESERVE_CID, 4, 0x01, 0x02, 0x03, 0x04
};

static struct st_qinq_test_rcid_t rcid1 = {
    { { 0x01, 0x02, 0x03, 0x04}, 4}
};

static uint8_t qinq_rcid2[] = {
    QINQ_PROTO_RESERVE_CID, 8, 11, 12, 13, 14, 15, 16, 17, 18
};

static struct st_qinq_test_rcid_t rcid2 = {
    { { 11, 12, 13, 14, 15, 16, 17, 18}, 8}
};

static int qinq_test_one_cid(const struct st_qinq_test_rcid_t* rcid, size_t length, uint8_t* message)
{
    int ret = 0;
    picoquic_connection_id_t cid = { {0}, 0 };
    uint8_t* bytes = message;
    uint8_t* bytes_max = message + length;

    if ((bytes = picoquic_frames_varint_skip(bytes, bytes_max)) != NULL) {
        bytes = picoqinq_decode_reserve_cid(bytes, bytes_max, &cid);
    }

    if (bytes == NULL) {
        ret = -1;
        DBG_PRINTF("Parsing reserve cid returns: %d\n", ret);
    }
    else if (bytes_max > bytes) {
        DBG_PRINTF("Bytes remain after parsing reserve cid: %llu\n",
            (unsigned long long)(bytes_max - bytes));
        ret = -1;
    }
    else if (picoquic_compare_connection_id(&cid, &rcid->cid) != 0) {
        DBG_PRINTF("Wrong CID: %d: { %d, %d, %d, %d, ... }\n", cid.id_len, cid.id[0], cid.id[1], cid.id[2], cid.id[3]);
        ret = -1;
    }

    if (ret == 0) {
        uint8_t buf[256];

        bytes_max = buf + sizeof(buf);

        bytes = picoqinq_encode_reserve_cid(buf, bytes_max, &cid);
        if (bytes == NULL) {
            ret = -1;
            DBG_PRINTF("Preparing reserve cid returns: %d\n", ret);
        }
        else if (bytes - buf != length) {
            DBG_PRINTF("Preparing reserve cid wrong length: %llu\n", (unsigned long long)(bytes - buf));
            ret = -1;
        }
        else if (memcmp(buf, message, length) != 0) {
            DBG_PRINTF("%s", "Prepared reserve cid does not match\n");
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

    if (ret == 0 &&
        (ret = qinq_test_one_cid(&rcid1, sizeof(qinq_rcid1), qinq_rcid1)) == 0) {
        ret = qinq_test_one_cid(&rcid2, sizeof(qinq_rcid2), qinq_rcid2);
    }

    return ret;
}

static struct st_qinq_test_rh_t* header_list[] = { &rh1, &rh2 };
size_t header_list_nb = sizeof(header_list) / sizeof(struct st_qinq_test_rh_t*);

uint8_t qinq_dg1[] = {
    0,  4, 10, 0, 0, 1, 1, 187, 0x0, 0x01, 0x02, 0x03, 0x04, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };
uint8_t qinq_dg1c[] = {
    1,  0x0, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };
uint8_t qinq_dg2[] = {
    0,  16, 0x20, 0x01, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0x12, 0x34, 0xCF, 0xff, 0x00, 0x00, 0x17, 8, 11, 12, 13, 14, 15, 16, 17, 18, 8, 41, 42, 43, 44, 45, 46, 47, 48, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };
uint8_t qinq_dg2c[] = {
    2,  0xCF, 0xff, 0x00, 0x00, 0x17, 8, 41, 42, 43, 44, 45, 46, 47, 48, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef };

struct st_qinq_test_dg_t {
    uint64_t hcid;
    size_t address_length;
    uint8_t * address;
    uint16_t port;
    picoquic_connection_id_t cid;
    uint8_t * dg;
    size_t dg_length;
    uint8_t * packet;
    size_t packet_length;
    size_t parsed_bytes;
};

static struct st_qinq_test_dg_t dg_list[] = {
    { 0, 4, &qinq_dg1[2], 443, {{0}, 0}, qinq_dg1, sizeof(qinq_dg1), &qinq_dg1[8], sizeof(qinq_dg1) - 8, 8},
    { 1, 4, &qinq_dg1[2], 443, {{0x01, 0x02, 0x03, 0x04}, 4}, qinq_dg1c, sizeof(qinq_dg1c), &qinq_dg1[8], sizeof(qinq_dg1) - 8, 1 },
    { 0, 16, &qinq_dg2[2], 0x1234, {{0}, 0}, qinq_dg2, sizeof(qinq_dg2), &qinq_dg2[20], sizeof(qinq_dg2) - 20, 20 },
    { 2, 16, &qinq_dg2[2], 0x1234, {{ 11, 12, 13, 14, 15, 16, 17, 18}, 8}, qinq_dg2c, sizeof(qinq_dg2c), &qinq_dg2[20], sizeof(qinq_dg2) - 20, 1}
};

size_t dg_list_nb = sizeof(dg_list) / sizeof(struct st_qinq_test_dg_t);

int qinq_incoming_datagram_parse_test()
{
    int ret = 0;
    picoqinq_header_compression_t* hc_head = NULL;

    for (size_t i = 0; ret == 0 && i < header_list_nb; i++) {
        struct sockaddr_storage addr_s;
        if (qinq_copy_address(&addr_s, header_list[i]->address_length, header_list[i]->address, header_list[i]->port) != 0) {
            DBG_PRINTF("Cannot copy address #%d, length: %d\n", (int)i, (int)header_list[i]->address_length);
            ret = -1;
        }
        else {
            picoqinq_header_compression_t* hc = picoqinq_create_header(i + 1, (struct sockaddr*) & addr_s, &header_list[i]->cid, 0);
            if (hc == NULL) {
                DBG_PRINTF("Cannot create hc #%d\n", (int)i);
                ret = -1;
            }
            else {
                picoqinq_reserve_header(hc, &hc_head);
            }
        }
    }

    /* Unit test of datagram parser */
    for (size_t i = 0; ret == 0 && i < dg_list_nb; i++) {
        struct sockaddr_storage addr_s;
        struct sockaddr_storage addr_ref;
        if (qinq_copy_address(&addr_ref, dg_list[i].address_length, dg_list[i].address, dg_list[i].port) != 0) {
            DBG_PRINTF("Cannot copy address #%d, length: %d\n", (int)i, (int)dg_list[i].address_length);
            ret = -1;
        }
        else {
            picoquic_connection_id_t* cid;
            uint8_t* bytes = dg_list[i].dg;
            uint8_t* bytes_max = bytes + dg_list[i].dg_length;

            bytes = picoqinq_decode_datagram_header(bytes, bytes_max, &addr_s, &cid, &hc_head, 0);
            if (bytes == NULL) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d] fails\n", (int)i);
            }
            else if (picoquic_compare_addr((struct sockaddr*) & addr_s, (struct sockaddr*) & addr_ref) != 0) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: address mismatch\n", (int)i);
            }
            else if (cid == NULL && dg_list[i].cid.id_len > 0) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: cid not parsed\n", (int)i);
            }
            else if (cid != NULL && dg_list[i].cid.id_len == 0) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: unexpected cid parsed\n", (int)i);
            }
            else if (dg_list[i].cid.id_len > 0 && picoquic_compare_connection_id(&dg_list[i].cid, cid) != 0) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: cid mismatch\n", (int)i);
            }
            else if (bytes - dg_list[i].dg != dg_list[i].parsed_bytes) {
                ret = -1;
                DBG_PRINTF("Parsing header of dg[%d]: parsed bytes count mismatch\n", (int)i);
            }
        }
    }

    /* Unit test of datagram to packet */
    for (size_t i = 0; ret == 0 && i < dg_list_nb; i++) {
        struct sockaddr_storage addr_s;
        struct sockaddr_storage addr_ref;
        if (qinq_copy_address(&addr_ref, dg_list[i].address_length, dg_list[i].address, dg_list[i].port) != 0) {
            DBG_PRINTF("Cannot copy address #%d, length: %d\n", (int)i, (int)dg_list[i].address_length);
            ret = -1;
        }
        else {
            uint8_t* bytes = dg_list[i].dg;
            uint8_t* bytes_max = bytes + dg_list[i].dg_length;
            uint8_t packet[1024];
            size_t packet_length;
            picoquic_connection_id_t* cid = NULL;
            ret = picoqinq_datagram_to_packet(bytes, bytes_max, &addr_s, &cid, packet, sizeof(packet), &packet_length, &hc_head, 0);
            if (ret != 0) {
                DBG_PRINTF("Packeting of dg[%d] fails\n", (int)i);
            }
            else if (picoquic_compare_addr((struct sockaddr*) & addr_s, (struct sockaddr*) & addr_ref) != 0) {
                ret = -1;
                DBG_PRINTF("Packeting of dg[%d]: address mismatch\n", (int)i);
            }
            else if (cid == NULL && dg_list[i].cid.id_len > 0) {
                ret = -1;
                DBG_PRINTF("Packeting of dg[%d]: cid not parsed\n", (int)i);
            }
            else if (cid != NULL && dg_list[i].cid.id_len == 0) {
                ret = -1;
                DBG_PRINTF("Packeting of dg[%d]: unexpected cid parsed\n", (int)i);
            }
            else if (dg_list[i].cid.id_len > 0 && picoquic_compare_connection_id(&dg_list[i].cid, cid) != 0) {
                ret = -1;
                DBG_PRINTF("Packeting of dg[%d]: cid mismatch\n", (int)i);
            }
            else if (packet_length != dg_list[i].packet_length) {
                ret = -1;
                DBG_PRINTF("Packeting  of dg[%d]: packet length mismatch\n", (int)i);
            }
            else if (memcmp(dg_list[i].packet, packet, packet_length) != 0) {
                ret = -1;
                DBG_PRINTF("Packeting  of dg[%d]: packet mismatch\n", (int)i);
            }
        }
    }

    /* Finally */
    while (hc_head != NULL) {
        picoqinq_header_compression_t* hc = hc_head;
        hc_head = hc->next_hc;
        free(hc);
    }

    return ret;
}