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

#ifndef PICOQUICTEST_INTERNAL_H
#define PICOQUICTEST_INTERNAL_H

#include "../picoquic/picoquic_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* SNI, ALPN, Stores and Certificates used for test
 */

#define PICOQUIC_TEST_SNI "test.example.com"
#define PICOQUIC_TEST_ALPN "picoquic-test"

#ifdef _WINDOWS
#ifdef _WINDOWS64
#define PICOQUIC_TEST_SERVER_CERT "..\\..\\certs\\cert.pem"
#define PICOQUIC_TEST_SERVER_BAD_CERT "..\\..\\certs\\badcert.pem"
#define PICOQUIC_TEST_SERVER_KEY "..\\..\\certs\\key.pem"
#define PICOQUIC_TEST_CERT_STORE "..\\..\\certs\\test-ca.crt"
#else
#define PICOQUIC_TEST_SERVER_CERT "..\\certs\\cert.pem"
#define PICOQUIC_TEST_SERVER_BAD_CERT "..\\certs\\badcert.pem"
#define PICOQUIC_TEST_SERVER_KEY "..\\certs\\key.pem"
#define PICOQUIC_TEST_CERT_STORE "..\\certs\\test-ca.crt"
#endif
#else
#define PICOQUIC_TEST_SERVER_CERT "certs/cert.pem"
#define PICOQUIC_TEST_SERVER_BAD_CERT "certs/badcert.pem"
#define PICOQUIC_TEST_SERVER_KEY "certs/key.pem"
#define PICOQUIC_TEST_CERT_STORE "certs/test-ca.crt"
#endif

/* Really basic network simulator, only simulates a simple link using a
 * packet structure.
 * Init: link creation. Returns a link structure with defined bandwidth,
 * latency, loss pattern and initial time. The link is empty. The loss
 * pattern is a 64 bit bit mask.
 * Submit packet of length L at time t. The packet is queued to the link.
 * Get packet out of link at time T + L + Queue.
 */

typedef struct st_picoquictest_sim_packet_t {
    struct st_picoquictest_sim_packet_t* next_packet;
    uint64_t sent_time;
    uint64_t arrival_time;
    size_t length;
    struct sockaddr_storage addr_from;
    struct sockaddr_storage addr_to;
    uint8_t bytes[PICOQUIC_MAX_PACKET_SIZE];
} picoquictest_sim_packet_t;

typedef struct st_picoquictest_sim_link_t {
    uint64_t next_send_time;
    uint64_t queue_time;
    uint64_t queue_delay_max;
    uint64_t picosec_per_byte;
    uint64_t microsec_latency;
    uint64_t* loss_mask;
    uint64_t packets_dropped;
    uint64_t packets_sent;
    picoquictest_sim_packet_t* first_packet;
    picoquictest_sim_packet_t* last_packet;
} picoquictest_sim_link_t;

picoquictest_sim_link_t* picoquictest_sim_link_create(double data_rate_in_gps,
    uint64_t microsec_latency, uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t current_time);

void picoquictest_sim_link_delete(picoquictest_sim_link_t* link);

picoquictest_sim_packet_t* picoquictest_sim_link_create_packet();

uint64_t picoquictest_sim_link_next_arrival(picoquictest_sim_link_t* link, uint64_t current_time);

picoquictest_sim_packet_t* picoquictest_sim_link_dequeue(picoquictest_sim_link_t* link,
    uint64_t current_time);

void picoquictest_sim_link_submit(picoquictest_sim_link_t* link, picoquictest_sim_packet_t* packet,
    uint64_t current_time);

int test_one_pn_enc_pair(uint8_t * seqnum, size_t seqnum_len, void * pn_enc, void * pn_dec, uint8_t * sample);

int picoquic_test_compare_files(char const* fname1, char const* fname2);

uint64_t picoquic_test_random(uint64_t * random_context);
uint64_t picoquic_test_uniform_random(uint64_t * random_context, uint64_t rnd_max);

#ifdef __cplusplus
}
#endif

#endif