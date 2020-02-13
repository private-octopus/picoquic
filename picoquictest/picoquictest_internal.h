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

#include "picoquic_internal.h"
#include "picoquictest_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

/*  ALPN used for test
 */

#define PICOQUIC_TEST_ALPN "picoquic-test"

#if 0

#define PICOQUIC_TEST_SNI "test.example.com"

#ifdef _WINDOWS
#define PICOQUIC_TEST_FILE_SERVER_CERT "certs\\cert.pem"
#define PICOQUIC_TEST_FILE_SERVER_BAD_CERT "certs\\badcert.pem"
#define PICOQUIC_TEST_FILE_SERVER_KEY "certs\\key.pem"
#define PICOQUIC_TEST_FILE_CERT_STORE "certs\\test-ca.crt"
#define PICOQUIC_TEST_FILE_ESNI_KEY "certs\\esni-secp256r1.key"
#define PICOQUIC_TEST_FILE_ESNI_RR "certs\\esni-rr.bin"
#else
#define PICOQUIC_TEST_FILE_SERVER_CERT "certs/cert.pem"
#define PICOQUIC_TEST_FILE_SERVER_BAD_CERT "certs/badcert.pem"
#define PICOQUIC_TEST_FILE_SERVER_KEY "certs/key.pem"
#define PICOQUIC_TEST_FILE_CERT_STORE "certs/test-ca.crt"
#define PICOQUIC_TEST_FILE_ESNI_KEY "certs/esni-secp256r1.key"
#define PICOQUIC_TEST_FILE_ESNI_RR "certs/esni-rr.bin"
#endif

 /* To set the solution directory for tests */
extern char const * picoquic_test_solution_dir;
#endif

#if 0
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
    uint64_t jitter;
    uint64_t jitter_seed;
    picoquictest_sim_packet_t* first_packet;
    picoquictest_sim_packet_t* last_packet;
} picoquictest_sim_link_t;
#endif

#define PICOQUIC_TEST_SNI "test.example.com"
#define PICOQUIC_TEST_ALPN "picoquic-test"
#define PICOQUIC_TEST_WRONG_ALPN "picoquic-bla-bla"
#define PICOQUIC_TEST_MAX_TEST_STREAMS 18

typedef enum {
    test_api_fail_data_on_unknown_stream = 1,
    test_api_fail_recv_larger_than_sent = 2,
    test_api_fail_fin_received_twice = 4,
    test_api_fail_cannot_send_response = 8,
    test_api_fail_cannot_send_query = 16,
    test_api_fail_data_does_not_match = 32,
    test_api_fail_unexpected_frame = 64,
    test_api_bad_stream0_data = 128
} test_api_fail_mode;

typedef struct st_test_api_stream_desc_t {
    uint64_t stream_id;
    uint64_t previous_stream_id;
    size_t q_len;
    size_t r_len;
} test_api_stream_desc_t;

typedef struct st_test_api_stream_t {
    uint64_t stream_id;
    uint64_t previous_stream_id;
    int q_sent;
    int r_sent;
    picoquic_call_back_event_t q_received;
    picoquic_call_back_event_t r_received;
    size_t q_len;
    size_t q_recv_nb;
    size_t r_len;
    size_t r_recv_nb;
    uint8_t* q_src;
    uint8_t* q_rcv;
    uint8_t* r_src;
    uint8_t* r_rcv;
} test_api_stream_t;

typedef struct st_test_api_callback_t {
    int client_mode;
    int fin_received;
    int error_detected;
    uint32_t nb_bytes_received;
} test_api_callback_t;

typedef struct st_picoquic_test_tls_api_ctx_t {
    picoquic_quic_t* qclient;
    picoquic_quic_t* qserver;
    picoquic_cnx_t* cnx_client;
    picoquic_cnx_t* cnx_server;
    int client_use_nat;
    int server_use_multiple_addresses;
    int client_use_multiple_addresses;
    int do_bad_coalesce_test;
    struct sockaddr_in client_addr;
    struct sockaddr_in server_addr;
    test_api_callback_t client_callback;
    test_api_callback_t server_callback;
    size_t nb_test_streams;
    test_api_stream_t test_stream[PICOQUIC_TEST_MAX_TEST_STREAMS];
    picoquictest_sim_link_t* c_to_s_link;
    picoquictest_sim_link_t* s_to_c_link;
    int received_version_negotiation;

    /* Stream 0 is reserved for the "infinite stream" simulation */
    size_t stream0_target;
    size_t stream0_sent;
    size_t stream0_received;
    int stream0_test_option;
    int stream0_flow_release;

    int sum_data_received_at_server;
    int sum_data_received_at_client;
    int test_finished;
    int streams_finished;
    int reset_received;

    /* Blackhole period if needed */
    uint64_t blackhole_start;
    uint64_t blackhole_end;

} picoquic_test_tls_api_ctx_t;

typedef struct st_test_skip_frames_t {
    char const* name;
    uint8_t* val;
    size_t len;
    int is_pure_ack;
    int must_be_last;
    int epoch;
} test_skip_frames_t;

extern test_skip_frames_t test_skip_list[];

extern size_t nb_test_skip_list;

#if 0

picoquictest_sim_link_t* picoquictest_sim_link_create(double data_rate_in_gps,
    uint64_t microsec_latency, uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t current_time);

void picoquictest_sim_link_delete(picoquictest_sim_link_t* link);

picoquictest_sim_packet_t* picoquictest_sim_link_create_packet();

uint64_t picoquictest_sim_link_next_arrival(picoquictest_sim_link_t* link, uint64_t current_time);

picoquictest_sim_packet_t* picoquictest_sim_link_dequeue(picoquictest_sim_link_t* link,
    uint64_t current_time);

void picoquictest_sim_link_submit(picoquictest_sim_link_t* link, picoquictest_sim_packet_t* packet,
    uint64_t current_time);
#endif

int tls_api_init_ctx(picoquic_test_tls_api_ctx_t** pctx, uint32_t proposed_version,
    char const* sni, char const* alpn, uint64_t* p_simulated_time,
    char const* ticket_file_name, char const* token_file_name, 
    int force_zero_share, int delayed_init, int use_bad_crypt);

void tls_api_delete_ctx(picoquic_test_tls_api_ctx_t* test_ctx);

int tls_api_connection_loop(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* loss_mask, uint64_t queue_delay_max, uint64_t* simulated_time);

int tls_api_one_sim_round(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time, uint64_t time_out, int* was_active);

void picoquic_set_test_address(struct sockaddr_in * addr, uint32_t addr_val, uint16_t port);

int test_one_pn_enc_pair(uint8_t * seqnum, size_t seqnum_len, void * pn_enc, void * pn_dec, uint8_t * sample);

int picoquic_test_compare_text_files(char const* fname1, char const* fname2);
int picoquic_test_compare_binary_files(char const* fname1, char const* fname2);

int picoquic_get_test_address(const char* ip_address_text, int server_port,
    struct sockaddr_storage* server_address);

int tls_api_one_scenario_test(test_api_stream_desc_t* scenario,
    size_t sizeof_scenario, size_t stream0_target,
    uint64_t init_loss_mask, uint64_t max_data, uint64_t queue_delay_max,
    uint32_t proposed_version, uint64_t max_completion_microsec,
    picoquic_tp_t* client_params, picoquic_tp_t* server_params);

uint64_t demo_server_test_time_from_esni_rr(char const* esni_rr_file);

#ifdef __cplusplus
}
#endif

#endif