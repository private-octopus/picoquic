/*
* Author: Christian Huitema
* Copyright (c) 2020, Private Octopus, Inc.
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
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquictest_internal.h"
#include "tls_api.h"
#include "picoquic_binlog.h"
#include "logreader.h"
#include "qlog.h"


/* This file includes a series of tests covering edge cases, typically
 * derived from observing failures in the interop runner. The failures
 * correspond to specific sequences in which specific packets were dropped,
 * leading to a failure state from which the connection did not
 * recover. Many of these failures involve 0-RTT connections.
 */

static char const* edge_case_ticket_file = "edge_case_ticket_file.bin";
static char const* edge_case_token_file = "edge_case_token_file.bin";

static test_api_stream_desc_t test_scenario_edge_case[] = {
    { 4, 0, 128, 1000 }
};

void edge_case_reset_scenario(picoquic_test_tls_api_ctx_t* test_ctx)
{

    for (size_t i = 0; i < test_ctx->nb_test_streams; i++) {
        test_ctx->test_stream[i].q_received = 0;
        test_ctx->test_stream[i].q_sent = 0;
        test_ctx->test_stream[i].r_received = 0;
        test_ctx->test_stream[i].r_sent = 0;
        test_ctx->test_stream[i].q_recv_nb = 0;
        test_ctx->test_stream[i].r_recv_nb = 0;
    }
    test_ctx->sum_data_received_at_server = 0;
    test_ctx->sum_data_received_at_client = 0;
    test_ctx->test_finished = 0;
    test_ctx->streams_finished = 0;
}

int edge_case_prepare(picoquic_test_tls_api_ctx_t** p_test_ctx, uint8_t edge_case_id, int zero_rtt, uint64_t* simulated_time, uint64_t loss_mask, int nb_init_rounds)
{
    picoquic_connection_id_t initial_cid = { { 0xed, 0x9e, 0xca, 0x5e, 0, 0, 0, 0}, 8 };
    uint64_t latency = 17000;
    int ret = 0;
    FILE* F;

    initial_cid.id[4] = edge_case_id;
    initial_cid.id[5] = zero_rtt;

    /* Make sure that the ticket and token files are empty */
    F = picoquic_file_open(edge_case_ticket_file, "wb");
    if (F != NULL) {
        picoquic_file_close(F);
    }
    F = picoquic_file_open(edge_case_token_file, "wb");
    if (F != NULL) {
        picoquic_file_close(F);
    }
    /* Create the test context */
    if (ret == 0) {
        ret = tls_api_init_ctx_ex(p_test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, simulated_time, edge_case_ticket_file, edge_case_token_file, 0, 1, 0, &initial_cid);
    }
    /* Set the binlog */
    if (ret == 0) {
        picoquic_set_binlog((*p_test_ctx)->qclient, ".");
        picoquic_set_binlog((*p_test_ctx)->qserver, ".");
    }
    /* Set the link latency */
    if (ret == 0) {
        (*p_test_ctx)->c_to_s_link->microsec_latency = latency;
        (*p_test_ctx)->s_to_c_link->microsec_latency = latency;
    }
    /* Set PMTUD policy & ACK Frequency policy */
    if (ret == 0){
        if (edge_case_id == 0xcf) {
            (*p_test_ctx)->cnx_client->local_parameters.min_ack_delay = 0;
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_blocked);
        }
        else if (edge_case_id == 0xa1) {
            (*p_test_ctx)->cnx_client->local_parameters.min_ack_delay = 0;
            (*p_test_ctx)->qserver->test_large_server_flight = 1;
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_blocked);
        }
        else if (edge_case_id == 0xf1) {
            (*p_test_ctx)->cnx_client->local_parameters.min_ack_delay = 0;
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_blocked);
        }
        else if (edge_case_id == 0x5c) {
            (*p_test_ctx)->cnx_client->local_parameters.min_ack_delay = 0;
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_blocked);
        }
        else {
            picoquic_cnx_set_pmtud_policy((*p_test_ctx)->cnx_client, picoquic_pmtud_delayed);
            picoquic_set_default_pmtud_policy((*p_test_ctx)->qclient, picoquic_pmtud_delayed);
        }
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(*p_test_ctx, test_scenario_edge_case, sizeof(test_scenario_edge_case));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* If zero RTT is required, run a single connection */
    if (ret == 0) {
        if (!zero_rtt) {
            int ret = picoquic_start_client_cnx((*p_test_ctx)->cnx_client);

            if (ret != 0)
            {
                DBG_PRINTF("%s", "Could not initialize connection for the client\n");
            }
        }
        else {
            uint32_t ticket_version = 0;
            int ret = tls_api_one_scenario_body_connect(*p_test_ctx, simulated_time, 0, 0, 0);

            /* Finish sending data */
            if (ret == 0) {
                uint64_t zero_loss = 0;
                ret = tls_api_data_sending_loop(*p_test_ctx, &zero_loss, simulated_time, 0);

                if (ret != 0)
                {
                    DBG_PRINTF("Data sending loop returns %d\n", ret);
                }
            }

            if (ret == 0) {
                /* wait for the session ticket to arrive */
                ret = session_resume_wait_for_ticket(*p_test_ctx, simulated_time);
            }

            if (ret == 0) {
                ret = tls_api_one_scenario_body_verify(*p_test_ctx, simulated_time, 1000000);
            }

            if (ret == 0 && (*p_test_ctx)->qclient->p_first_ticket == NULL) {
                DBG_PRINTF("No session ticket after first connection, t=%" PRIu64, *simulated_time);
            }
            else {
                ticket_version = (*p_test_ctx)->qclient->p_first_ticket->version;
            }

            if (ret == 0) {
                /* delete the client connection and create a new one. */
                picoquic_delete_cnx((*p_test_ctx)->cnx_client);
                (*p_test_ctx)->cnx_client = NULL;
                (*p_test_ctx)->cnx_server = NULL;
                edge_case_reset_scenario(*p_test_ctx);
                initial_cid.id[5] = 0;

                (*p_test_ctx)->cnx_client = picoquic_create_cnx((*p_test_ctx)->qclient, initial_cid,
                    picoquic_null_connection_id,
                    (struct sockaddr*)&(*p_test_ctx)->server_addr, *simulated_time,
                    ticket_version, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);

                if ((*p_test_ctx)->cnx_client == NULL) {
                    ret = -1;

                    if (ret != 0)
                    {
                        DBG_PRINTF("Create second connection returns %d\n", ret);
                    }
                }
            }
            if (ret == 0) {
                /* Start the client connection */
                ret = picoquic_start_client_cnx((*p_test_ctx)->cnx_client);

                if (ret != 0)
                {
                    DBG_PRINTF("Start second connection returns %d\n", ret);
                }
                else {
                    ret = test_api_queue_initial_queries((*p_test_ctx), 0);

                    if (ret != 0)
                    {
                        DBG_PRINTF("Restart scenario returns %d\n", ret);
                    }
                }
            }
        }
    }


    /* Execute the expected number of rounds */
    if (ret == 0) {
        int nb_trials = 0;
        int nb_inactive = 0;
        uint64_t loss_target = loss_mask >> nb_init_rounds;
        loss_target |= loss_mask << (64 - nb_init_rounds);

        (*p_test_ctx)->c_to_s_link->loss_mask = &loss_mask;
        (*p_test_ctx)->s_to_c_link->loss_mask = &loss_mask;

        /* Set preemtive repeat on server */
        if (edge_case_id != 0xf1 && edge_case_id != 0x5c) {
            picoquic_set_preemptive_repeat_policy((*p_test_ctx)->qserver, 1);
        }

        while (ret == 0 && nb_trials < 4*nb_init_rounds && nb_inactive < 256 && loss_mask != loss_target) {
            int was_active = 0;

            nb_trials++;

            ret = tls_api_one_sim_round(*p_test_ctx, simulated_time, 0, &was_active);

            if (ret < 0)
            {
                break;
            }

            if (was_active) {
                nb_inactive = 0;
            }
            else {
                nb_inactive++;
            }

            if ((*p_test_ctx)->test_finished) {
                break;
            }
        }
        if (loss_mask != loss_target) {
            DBG_PRINTF("Stop after %d trials, %d inactive, loss_mask = %" PRIu64,
                nb_trials, nb_inactive, loss_mask);
        }
    }

    return ret;
}

int edge_case_complete(picoquic_test_tls_api_ctx_t* test_ctx, uint64_t* simulated_time, uint64_t duration_max)
{
    int ret = 0;
    uint64_t loss_mask = 0;

    ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, simulated_time);
    if (ret != 0)
    {
        DBG_PRINTF("Connect loop returns %d\n", ret);
    }

    /* Finish sending data */
    test_ctx->immediate_exit = 1;

    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, simulated_time, duration_max);
    }

    return ret;
}

/* Edge case zero: verify that the common code
 * works.
 */
int ec00_zero_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = edge_case_prepare(&test_ctx, 0, 1, &simulated_time, 0, 4);

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 40000);
    }

    if (ret == 0) {
        if (test_ctx->cnx_client->nb_zero_rtt_acked == 0) {
            DBG_PRINTF("Nb 0RTT acked = %d", test_ctx->cnx_client->nb_zero_rtt_acked);
            ret = -1;
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Reproduce and fix a specific error:
 * - 0RTT packet was lost
 * - Client second flight arrives at peer, but handshake ACK is lost
 * - Handshake Done is lost
 * Client appears stuck repeating second flight, intead of trying to
 * make progress and send data.
 * 
 * This is unlocked by enabling retransmission of data in "client almost ready"
 * state. 
 */

int ec2f_second_flight_nack_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0b111000001;
    uint8_t test_case_id = 0x2f;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 1, &simulated_time, initial_losses, 9);

    if (ret == 0) {
        if (test_ctx->cnx_client->cnx_state >= picoquic_state_ready ||
            test_ctx->cnx_server->cnx_state != picoquic_state_ready) {
            DBG_PRINTF("Unexpected state, client: %d, server: %d",
                test_ctx->cnx_client->cnx_state, test_ctx->cnx_server->cnx_state);
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 360000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Try reproduce a corrupt file transmission occuring
 * during a lossy handshake. At some point, the server
 * sent random content instead of repeating the original packet
 * content. Attempts to just reproduce the sequence in
 * the interop runner failed, so instead we add a specialized
 * fuzzer. Running that fuzzer in ASAN/UBSAN builds might
 * detect the corruption some day.
 */

void eccf_corrupted_file_fuzz(int nb_trials, uint64_t seed, FILE* F)
{
    uint64_t random_context = (seed == 0)?0x1234567887654321ull:seed;

    for (int i = 0; i < nb_trials; i++) {
        uint64_t simulated_time = 0;
        picoquic_test_tls_api_ctx_t* test_ctx = NULL;
        uint64_t initial_losses = random_context & 0xFFFFFFFF86ull;
        uint8_t test_case_id = 0xcf;
        int ret = 0;

        (void)picoquic_test_random(&random_context);

        ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 40);

        if (ret == 0) {
            ret = edge_case_complete(test_ctx, &simulated_time, 15000000);
        }

        if (ret != 0 && F != NULL) {
            fprintf(F, "0x%" PRIx64 ", %" PRIu64 ", %d, %" PRIu64 "\n",
                initial_losses, initial_losses, ret, simulated_time);
        }

        if (test_ctx != NULL) {
            tls_api_delete_ctx(test_ctx);
            test_ctx = NULL;
        }
    }
}

int eccf_corrupted_file_fuzz_test()
{
    int ret = 0;
    FILE* F = picoquic_file_open("ECCF_Fuzz_report.csv", "w");
    if (F == NULL) {
        ret = -1;
    }
    else {
        (void)fprintf(F, "Seed_hex, Seed, Ret, Elapsed\n");
        eccf_corrupted_file_fuzz(50, 0, F);
        picoquic_file_close(F);
    }
    return ret;
}

/* Amplification test using large 
 * server hello with losses.
 */
int eca1_amplification_loss_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0b0111111110100;
    uint8_t test_case_id = 0xa1;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 16);

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 15000000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Loss of final closing packet, verify that overall time
 * is acceptable.
 */

int ecf1_final_loss_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t final_losses = 0xb10;
    uint8_t test_case_id = 0xf1;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, 0, 20);
    uint64_t zero_loss_mask = 0;

    /* Finish the connection */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &zero_loss_mask, 0, &simulated_time);
        if (ret != 0)
        {
            DBG_PRINTF("Connect loop returns %d\n", ret);
        }
    }
    /* Finish sending data */
    test_ctx->immediate_exit = 1;

    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &zero_loss_mask, &simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }
    /* Simulate losses during closing */
    if (ret == 0) {
        ret = tls_api_close_with_losses(test_ctx, &simulated_time, final_losses);
    }

    if (ret == 0 && simulated_time > 10000000) {
        DBG_PRINTF("Took %" PRIu64 "us to complete, too long", simulated_time);
        ret = -1;
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Some traces show the CID packet from the server being dropped,
 * then repeated a couple time, with one success but a drop
 * of the clien't ack, and the server then sending a bogus repeat.
 */

int ec5c_silly_cid_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0b0000011110000010000100;
    uint8_t test_case_id = 0x5c;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 48);

    if (ret == 0) {
        if (test_ctx->cnx_server == NULL) {
            DBG_PRINTF("Unexpected state, client: %d, server: NULL",
                test_ctx->cnx_client->cnx_state);

        } else if (test_ctx->cnx_client->cnx_state != picoquic_state_ready ||
            test_ctx->cnx_server->cnx_state != picoquic_state_ready) {
            DBG_PRINTF("Unexpected state, client: %d, server: %d",
                test_ctx->cnx_client->cnx_state, test_ctx->cnx_server->cnx_state);
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = edge_case_complete(test_ctx, &simulated_time, 600000);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Some traces show that if a connection close from the client is dropped and
 * then the client goes away, the server can produce a vast number of
 * preemptive repeats before giving up. Repro, then verify.
 */

int ec9a_preemptive_amok_test()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t initial_losses = 0b100000000000;
    uint8_t test_case_id = 0x9a;
    uint64_t cnx_server_idle_timeout = 0;
    uint64_t cnx_server_nb_preemptive_repeat = 0;
    int ret = edge_case_prepare(&test_ctx, test_case_id, 0, &simulated_time, initial_losses, 12);

    if (ret == 0) {
        if (test_ctx->cnx_server == NULL) {
            DBG_PRINTF("Unexpected state, client: %d, server: NULL",
                test_ctx->cnx_client->cnx_state);
            ret = -1;
        }
        else if ( test_ctx->cnx_server->cnx_state != picoquic_state_ready ||
            !test_ctx->test_finished || 
            test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].pending_first == NULL){
            DBG_PRINTF("Unexpected state, server: %d, test finished: %d, queue for repeat %s",
                test_ctx->cnx_server->cnx_state, test_ctx->test_finished, 
                (test_ctx->cnx_server->pkt_ctx[picoquic_packet_context_application].pending_first == NULL)?"empty":"full");
            ret = -1;
        }
    }
    /* Do a loop involving only the server */
    if (ret == 0) {
        uint8_t buffer[PICOQUIC_MAX_PACKET_SIZE];
        size_t send_length;
        size_t send_msg_size;
        struct sockaddr_storage addr_to;
        struct sockaddr_storage addr_from;
        int if_index;
        picoquic_connection_id_t log_id;
        picoquic_cnx_t * last_cnx;
        int loop_count = 0;
        int send_count = 0;
        const int send_count_max = 50;
        uint64_t repeat_begin = simulated_time;
        uint64_t repeat_duration = 0;

        cnx_server_idle_timeout = test_ctx->cnx_server->idle_timeout;
        cnx_server_nb_preemptive_repeat = test_ctx->cnx_server->nb_preemptive_repeat;

        picoquic_reinsert_by_wake_time(test_ctx->qserver, test_ctx->cnx_server, simulated_time);

        while (test_ctx->qserver->current_number_connections > 0 && test_ctx->cnx_server->cnx_state == picoquic_state_ready && loop_count < 10000 && ret == 0) {
            loop_count++;
            cnx_server_nb_preemptive_repeat = test_ctx->cnx_server->nb_preemptive_repeat;
            simulated_time = picoquic_get_next_wake_time(test_ctx->qserver, simulated_time);
            ret = picoquic_prepare_next_packet_ex(test_ctx->qserver, simulated_time, buffer,
                sizeof(buffer), &send_length, &addr_to, &addr_from, &if_index, &log_id,
                &last_cnx, &send_msg_size);
            if (ret != 0) {
                DBG_PRINTF("Prepare next returns an error: %d (0x%x)", ret, ret);
            }
            else if (send_length > 0) {
                send_count++;
            }
        }

        if (ret == 0) {
            repeat_duration = simulated_time - repeat_begin;
            if (send_count > send_count_max) {
                DBG_PRINTF("Repeated %d packets, more that the %d expected",
                    send_count, send_count_max);
                ret = -1;
            }
            else if (repeat_duration > cnx_server_idle_timeout) {
                DBG_PRINTF("End at t=%" PRIu64 ", later than %" PRIu64,
                    simulated_time, cnx_server_idle_timeout);
                ret = -1;
            }
            else if (cnx_server_nb_preemptive_repeat == 0) {
                DBG_PRINTF("%s", "No preemptive repeat");
                ret = -1;
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* testing the negotiation of the idle timeout.
*/
int idle_timeout_test_one(uint8_t test_id, uint64_t client_timeout, uint64_t server_timeout, uint64_t expected_timeout)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_connection_id_t initial_cid = { { 0x41, 0x9e, 0x00, 0x94, 0, 0, 0, 0}, 8 };
    uint64_t half_time = (expected_timeout == UINT64_MAX) ? 20000000 : (expected_timeout / 2);
    uint64_t full_time = (expected_timeout == UINT64_MAX) ? 600000000 : (half_time + 100000);
    int ret = 0;

    initial_cid.id[4] = test_id;

    /* Create the test context */
    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
    }
    /* Set the binlog */
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qclient, ".");
        picoquic_set_binlog(test_ctx->qserver, ".");
        /* Set the timeout */
        picoquic_set_default_idle_timeout(test_ctx->qclient, client_timeout);
        picoquic_set_default_idle_timeout(test_ctx->qserver, server_timeout);
        /* Directly set the timeout in the client parameters,
           because the connection context is already created */
        test_ctx->cnx_client->local_parameters.max_idle_timeout = client_timeout;
    }

    /* Do the connection */
    if (ret == 0) {
        test_ctx->cnx_client->max_early_data_size = 0;

        if ((ret = picoquic_start_client_cnx(test_ctx->cnx_client)) == 0) {
            ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
        }
    }

    /* Verify the timer negotiation */
    if (ret == 0) {
        if (test_ctx->cnx_client->local_parameters.max_idle_timeout != client_timeout) {
            DBG_PRINTF("Idle timeout test %d. Client parameter set to %" PRIu64 " instead of %" PRIu64 "\n",
                test_id, test_ctx->cnx_client->local_parameters.max_idle_timeout, client_timeout);
            ret = -1;
        }
        if (test_ctx->cnx_server->local_parameters.max_idle_timeout != server_timeout) {
            DBG_PRINTF("Idle timeout test %d. Server parameter set to %" PRIu64 " instead of %" PRIu64 "\n",
                test_id, test_ctx->cnx_server->local_parameters.max_idle_timeout, server_timeout);
            ret = -1;
        }
        if (test_ctx->cnx_client->idle_timeout != expected_timeout) {
            DBG_PRINTF("Idle timeout test %d. Client negotiated %" PRIu64 " instead of %" PRIu64 "\n",
                test_id, test_ctx->cnx_client->idle_timeout, expected_timeout);
            ret = -1;
        }
        if (test_ctx->cnx_server->idle_timeout != expected_timeout) {
            DBG_PRINTF("Idle timeout test %d. Server negotiated %" PRIu64 " instead of %" PRIu64 "\n",
                test_id, test_ctx->cnx_server->idle_timeout, expected_timeout);
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Wait for half time. Expectation: connections are still up */
        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, half_time);
        if (ret != 0 || !((TEST_CLIENT_READY && TEST_SERVER_READY))) {
            DBG_PRINTF("Idle timeout test %d. Broke early, time = %" PRIu64 "\n", test_id, simulated_time);
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Wait for full time. Expectation: connections are down, unless timeout == 0 */
        ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, full_time);

        if (ret == 0){
            if (TEST_CLIENT_READY && TEST_SERVER_READY) {
                if (expected_timeout != UINT64_MAX) {
                    DBG_PRINTF("Idle timeout test %d. Waited too long, time = %" PRIu64 "\n", test_id, simulated_time);
                    ret = -1;
                }
            }
            else {
                if (expected_timeout == UINT64_MAX) {
                    DBG_PRINTF("Idle timeout test %d. Broke early, time = %" PRIu64 "\n", test_id, simulated_time);
                    ret = -1;
                }
            }
        }
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int idle_timeout_test()
{
    int ret = 0;

    if ((ret = idle_timeout_test_one(1, 30000, 30000, 30000000)) == 0 &&
        (ret = idle_timeout_test_one(2, 60000, 20000, 20000000)) == 0 &&
        (ret = idle_timeout_test_one(3, 20000, 60000, 20000000)) == 0 &&
        (ret = idle_timeout_test_one(4, 5000, 300000, 5000000)) == 0 &&
        (ret = idle_timeout_test_one(5, 300000, 5000, 5000000)) == 0 &&
        (ret = idle_timeout_test_one(6, 0, 5000, 5000000)) == 0 &&
        (ret = idle_timeout_test_one(7, 0, 60000, 60000000)) == 0 &&
        (ret = idle_timeout_test_one(8, 5000, 0, 5000000)) == 0 &&
        (ret = idle_timeout_test_one(9, 60000, 0, 60000000)) == 0 &&
        (ret = idle_timeout_test_one(10, 0, 0, UINT64_MAX)) == 0) {
        DBG_PRINTF("%s", "All idle timeout tests pass.\n");
    }
    return ret;
}

/* Testing that connection attempt against a non responding server
 * finishes after the timeout value.
 */

int idle_server_test_one(uint8_t test_id, uint64_t client_timeout, uint64_t handshake_timeout, uint64_t expected_timeout)
{
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    uint64_t simulated_time = 0;
    uint64_t target_timeout;
    uint64_t loss_mask = 0;
    picoquic_connection_id_t initial_cid = { { 0x41, 0x9e, 0xc0, 0x99, 0, 0, 0, 0}, 8 };
    uint8_t send_buffer[PICOQUIC_MAX_PACKET_SIZE];
    int ret = 0;

    initial_cid.id[4] = test_id;

    /* derive target timeout form spec */
    target_timeout = handshake_timeout;
    if (handshake_timeout == 0) {
        target_timeout = client_timeout * 1000;
        if (client_timeout == 0) {
            target_timeout = PICOQUIC_MICROSEC_HANDSHAKE_MAX;
        }
    }

    /* Create the test context */
    if (ret == 0) {
        ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
            PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);
    }

    /* Set the binlog */
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qclient, ".");
        /* Set the timeout */
        picoquic_set_default_idle_timeout(test_ctx->qclient, client_timeout);
        if (handshake_timeout > 0) {
            picoquic_set_default_handshake_timeout(test_ctx->qclient, handshake_timeout);
        }
        /* Directly set the timeout in the client parameters,
        because the connection context is already created */
        test_ctx->cnx_client->local_parameters.max_idle_timeout = client_timeout;
        /* Start the client */
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    /* Run a simulation loop -- the server never responds. */
    if (ret == 0) {
        int nb_trials = 0;
        while (ret == 0 && simulated_time < expected_timeout) {
            size_t send_length = 0;
            struct sockaddr_storage addr_to;
            struct sockaddr_storage addr_from;

            ret = picoquic_prepare_packet_ex(test_ctx->cnx_client, simulated_time,
                send_buffer, sizeof(send_buffer), &send_length,
                &addr_to, &addr_from, 0, NULL);
            if (ret != 0) {
                break;
            }
            else if (test_ctx->cnx_client->cnx_state == picoquic_state_disconnected) {
                break;
            }
            else if (simulated_time > test_ctx->cnx_client->next_wake_time) {
                DBG_PRINTF("Idle server test %d. Bug, simulation is walking back in time.", test_id);
                ret = -1;
            }
            else if (nb_trials >= 512) {
                DBG_PRINTF("Idle server test %d. Bug, simulation exceeds %d steps.", test_id, nb_trials);
                ret = -1;
            }
            else {
                nb_trials++;
                simulated_time = test_ctx->cnx_client->next_wake_time;
            }
        }
    }

    if ((ret == 0 && test_ctx->cnx_client->cnx_state == picoquic_state_disconnected) ||
        ret == PICOQUIC_ERROR_DISCONNECTED) {
        if (simulated_time < target_timeout) {
            DBG_PRINTF("Idle server test %d. Client gave up too soon, time = %" PRIu64 "\n", test_id, simulated_time);
            ret = -1;
        }
        else {
            ret = 0;
        }
    }
    else if (ret == 0) {
        DBG_PRINTF("Idle server test %d. Client did not disconnect, time = %" PRIu64 "\n", test_id, simulated_time);
        ret = -1;
    }
    else {
        DBG_PRINTF("Idle server test %d. ret=0x%x, time = %" PRIu64 "\n", ret, test_id, simulated_time);
    }

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int idle_server_test()
{
    int ret = 0;

    if ((ret = idle_server_test_one(1, 30000, 0, 30100000)) == 0 &&
        (ret = idle_server_test_one(2, 60000, 0, 60100000)) == 0 &&
        (ret = idle_server_test_one(3, 5000, 0, 5100000)) == 0 &&
        (ret = idle_server_test_one(4, 0, 0, 30100000)) == 0 &&
        (ret = idle_server_test_one(5, 0, 10000, 10100000)) == 0 &&
        (ret = idle_server_test_one(6, 20000, 60000, 60100000)) == 0 &&
        (ret = idle_server_test_one(7, 60000, 5000, 5100000)) == 0){
        DBG_PRINTF("%s", "All idle timeout tests pass.\n");
    }
    return ret;
}