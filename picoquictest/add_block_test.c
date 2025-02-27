/*
* Author: Christian Huitema
* Copyright (c) 2025, Private Octopus, Inc.
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
#include <stdint.h>
#include <math.h>
#include "picoquic.h"
#include "picoquic_utils.h"
#include "picoquictest_internal.h"
#include "picoquic_binlog.h"

/* Testing the API "picoquic_add_block_to_stream"
*
* Do a simple scenario:
* - allocate blocks at the application level, with set size.
* - shall test several block sizes
* - implement app logic: chain blocks at start, 1 at a time,
*   2 at a time, when the previous one is done.
* - verify that the sending completes
* - verify that the received content matches what was sent.
 */

#define ADD_BLOCK_TEST_ALPN "ADD_BLOCK_TEST"
#define add_block_test_unique_1 0x1111111111111111uul
#define add_block_test_unique_2 0x2222222222222222uul
#define add_block_test_max_block_nb 10
#define add_block_test_max_sent 0x100000

#define add_block_test_block_unknown 1
#define add_block_test_block_not_sent 2
#define add_block_test_block_already_reported 4
#define add_block_test_block_already_sent 8
#define add_block_test_block_send_failed 16


 /* mediatest test specification */
typedef struct st_add_block_test_spec_t {
    int test_id;
    int do_loss;
} add_block_test_spec_t;

typedef struct st_add_block_test_stream_t {
    /* we only use one stream, but we use this data type to test that the context is passed correctly */
    uint64_t unique_value;
} add_block_test_stream_t;

typedef struct st_add_block_test_block_t {
    /* we only use one stream, but we use this data type to test that the context is passed correctly */
    struct st_add_block_test_ctx_t* block_test_ctx;
    int block_id;
    int block_was_sent;
    int block_was_confirmed;
    int block_is_trigger;
} add_block_test_block_t;

typedef struct st_add_block_test_ctx_t {
    picoquic_quic_t* quic[2]; /* QUIC Context for client[0] or server[1] */
    picoquictest_sim_link_t* link[2]; /* Link from client to server [0] and back [1] */
    struct sockaddr_storage addr[2]; /* addresses of client [0] and server [1] */
    picoquic_cnx_t* cnx_client;
    picoquic_cnx_t* cnx_server;
    uint64_t simulated_time;
    uint64_t stream_id;
    uint8_t* test_data;
    uint8_t* recv_data;
    size_t test_data_length;
    size_t send_offset;
    size_t recv_length;
    int fin_sent;
    int fin_recv;
    add_block_test_block_t block[add_block_test_max_block_nb];
    int next_block_id;
    add_block_test_stream_t client_stream;
    add_block_test_stream_t server_stream;
} add_block_test_ctx_t;

add_block_test_ctx_t* current_ctx = NULL;
int error_found = 0;

void add_block_test_send(add_block_test_ctx_t* add_block_ctx, int block_id);

int picoquic_add_block_to_stream(picoquic_cnx_t* cnx, uint64_t stream_id,
    const uint8_t* data, size_t length, int set_fin, void* app_stream_ctx,
    picoquic_block_sent_fn block_sent_fn, void* block_sent_ctx);

void add_block_test_sent_fn(const uint8_t* data, void* v_block_sent_ctx)
{
    add_block_test_block_t* block_sent_ctx = (add_block_test_block_t*)v_block_sent_ctx;

    if (block_sent_ctx->block_test_ctx != current_ctx ||
        block_sent_ctx->block_id >= add_block_test_max_block_nb ||
        &block_sent_ctx->block_test_ctx->block[block_sent_ctx->block_id] != block_sent_ctx) {
        /* This is really bad. */
        error_found |= add_block_test_block_unknown;
    }
    else if (!block_sent_ctx->block_was_sent) {
        error_found |= add_block_test_block_not_sent;
    }
    else if (block_sent_ctx->block_was_confirmed) {
        error_found |= add_block_test_block_already_reported;
    }
    else {
        block_sent_ctx->block_was_confirmed = 1;
        if (block_sent_ctx->block_is_trigger) {
            add_block_test_send(block_sent_ctx->block_test_ctx, block_sent_ctx->block_id + 1);
        }
    }
}

void add_block_test_send(add_block_test_ctx_t* add_block_ctx, int block_id)
{
    for (int i = 0; i <= block_id; i++) {
        int new_id = add_block_ctx->next_block_id;

        if (new_id >= add_block_test_max_block_nb || add_block_ctx->send_offset >= add_block_ctx->test_data_length) {
            /* we are done */
            break;
        }
        else if (add_block_ctx->block[new_id].block_was_sent) {
            /* This is really bad */
            error_found |= add_block_test_block_already_sent;
            break;
        }
        else {
            size_t length = add_block_ctx->send_offset;
            int set_fin = 0;
            if (length == 0) {
                length = 128;
            }
            if (add_block_ctx->send_offset + length >= add_block_ctx->test_data_length ||
                new_id == (add_block_test_max_block_nb - 1)) {
                length = add_block_ctx->test_data_length - add_block_ctx->send_offset;
                set_fin = 1;
            }
            add_block_ctx->block[new_id].block_was_sent = 1;
            add_block_ctx->block[new_id].block_is_trigger = (i == 0);
            add_block_ctx->block[new_id].block_id = new_id;
            add_block_ctx->block[new_id].block_test_ctx = add_block_ctx;
            add_block_ctx->next_block_id = new_id + 1;
            
            if (picoquic_add_block_to_stream(add_block_ctx->cnx_client,
                add_block_ctx->stream_id,
                add_block_ctx->test_data + add_block_ctx->send_offset,
                length, set_fin, &add_block_ctx->client_stream,
                add_block_test_sent_fn, &add_block_ctx->block[new_id]) != 0) {
                error_found |= add_block_test_block_send_failed;
                break;
            }
            else {
                add_block_ctx->send_offset += length;
            }
        }
    }
}

int add_block_test_recv(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, add_block_test_ctx_t* add_block_ctx, void* v_stream_ctx)
{
    int ret = 0;

    if (cnx == add_block_ctx->cnx_client) {
        /* the client is not expected to receive data. It MAY receive a FIN mark */
        if (fin_or_event != picoquic_callback_stream_fin || length > 0) {
            ret = -1;
        }
    }
    else if (cnx->quic != add_block_ctx->quic[1]) {
        /* Not from the expected server */
        ret = -1;
    }
    else if (stream_id != add_block_ctx->stream_id){
        /* not the expected stream */
        ret = -1;
    }
    else if (add_block_ctx->recv_length + length > add_block_ctx->test_data_length) {
        /* too much data */
        ret = -1;
    }
    else {
        if (length > 0) {
            memcpy(add_block_ctx->recv_data + add_block_ctx->recv_length, bytes, length);
        }
        add_block_ctx->recv_length += length;
        if (fin_or_event == picoquic_callback_stream_fin) {
            add_block_ctx->fin_recv = 1;
        }
    }
    return ret;
}

int add_block_test_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    add_block_test_ctx_t* add_block_ctx = (add_block_test_ctx_t*)callback_ctx;

    if (add_block_ctx == NULL) {
        /* This should never happen, because the callback context is initialized
            * when creating the client connection. */
        return -1;
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            ret = add_block_test_recv(cnx, stream_id, bytes, length, fin_or_event, add_block_ctx, v_stream_ctx);
            break;
        case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
            ret = -1;
            /* Fall through */
        case picoquic_callback_stream_reset: /* Server reset stream #x */
            ret = -1;
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            fprintf(stdout, "Connection closed.\n");
            /* Mark the connection as completed */
            add_block_ctx->fin_sent = 1;
            add_block_ctx->fin_recv = 1;
            /* Remove the application callback */
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* We do not expect that */
            ret = -1;
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            ret = -1;
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API -- we do not expect to use that in this test. */
            ret = -1;
            break;
        case picoquic_callback_almost_ready:
            fprintf(stdout, "Connection to the server completed, almost ready.\n");
            break;
        case picoquic_callback_ready:
            /* TODO: Check that the transport parameters are what the sample expects */
            fprintf(stdout, "Connection to the server confirmed.\n");
            break;
        default:
            /* unexpected -- just ignore. */
            break;
        }
    }
    if (ret != 0) {
        DBG_PRINTF("Callback error, event %d, ret=%d", fin_or_event, ret);
    }

    return ret;
}

/* Process arrival of a packet from a link */
int add_block_test_packet_arrival(add_block_test_ctx_t* add_block_ctx, int link_id, int is_losing_data, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_dequeue(add_block_ctx->link[link_id], add_block_ctx->simulated_time);

    if (packet == NULL) {
        /* unexpected, probably bug in test program */
        ret = -1;
    }
    else {
        *is_active = 1;

        if (!is_losing_data) {
            ret = picoquic_incoming_packet(add_block_ctx->quic[link_id],
                packet->bytes, (uint32_t)packet->length,
                (struct sockaddr*)&packet->addr_from,
                (struct sockaddr*)&packet->addr_to, 0, 0,
                add_block_ctx->simulated_time);
        }

        free(packet);
    }

    return ret;
}


/* Packet departure from selected node */
int add_block_test_packet_departure(add_block_test_ctx_t* add_block_ctx, int node_id, int* is_active)
{
    int ret = 0;
    picoquictest_sim_packet_t* packet = picoquictest_sim_link_create_packet();

    if (packet == NULL) {
        /* memory error during test. Something is really wrong. */
        ret = -1;
    }
    else {
        /* check whether there is something to send */
        int if_index = 0;

        ret = picoquic_prepare_next_packet(add_block_ctx->quic[node_id], add_block_ctx->simulated_time,
            packet->bytes, PICOQUIC_MAX_PACKET_SIZE, &packet->length,
            &packet->addr_to, &packet->addr_from, &if_index, NULL, NULL);

        if (ret != 0)
        {
            /* useless test, but makes it easier to add a breakpoint under debugger */
            free(packet);
            ret = -1;
        }
        else if (packet->length > 0) {
            /* Only one link per node */
            int link_id = 1 - node_id;

            /* If the source address is not set, set it */
            if (packet->addr_from.ss_family == 0) {
                picoquic_store_addr(&packet->addr_from, (struct sockaddr*)&add_block_ctx->addr[link_id]);
            }
            /* send now. */
            *is_active = 1;
            picoquictest_sim_link_submit(add_block_ctx->link[link_id], packet, add_block_ctx->simulated_time);
        }
        else {
            free(packet);
        }
    }

    return ret;
}

/* Simulation step */
int add_block_test_step(add_block_test_ctx_t* add_block_ctx, int is_losing_data, int* is_active)
{
    int ret = 0;
    uint64_t next_arrival_time = UINT64_MAX;
    int arrival_index = -1;
    uint64_t next_departure_time = UINT64_MAX;
    int departure_index = -1;
    int need_frame_departure = 0;
    uint64_t next_frame_time = UINT64_MAX;
    uint64_t next_time;
    /* Check earliest packet arrival */
    for (int i = 0; i < 2; i++) {
        uint64_t arrival = picoquictest_sim_link_next_arrival(add_block_ctx->link[i], next_arrival_time);
        if (arrival < next_arrival_time) {
            next_arrival_time = arrival;
            arrival_index = i;
        }
    }
    next_time = next_arrival_time;

    /* Check earliest packet departure */
    for (int i = 0; i < 2; i++) {
        uint64_t departure = picoquic_get_next_wake_time(add_block_ctx->quic[i], add_block_ctx->simulated_time);
        if (departure < next_departure_time) {
            next_departure_time = departure;
            departure_index = i;
        }
    }
    if (next_time > next_departure_time) {
        next_time = next_departure_time;
    }

    /* Update the time now, because the call to "active stream" reads the simulated time. */
    if (next_time > add_block_ctx->simulated_time) {
        add_block_ctx->simulated_time = next_time;
    }
    else {
        next_time = add_block_ctx->simulated_time;
    }

    if (ret == 0) {
        /* Perform earliest action */
        if (next_arrival_time <= next_time) {
            /* Process next packet from simulated link */
            ret = add_block_test_packet_arrival(add_block_ctx, arrival_index, is_losing_data, is_active);
        }
        else {
            /* Prepare next packet from selected connection */
            ret = add_block_test_packet_departure(add_block_ctx, departure_index, is_active);
        }
    }
    if (ret < 0) {
        DBG_PRINTF("Simulation fails at T=%" PRIu64, add_block_ctx->simulated_time);
    }

    return ret;
}

int add_block_test_is_finished(add_block_test_ctx_t* add_block_ctx)
{
    int is_finished = add_block_ctx->fin_sent && add_block_ctx->fin_recv;
    if (is_finished) {
        DBG_PRINTF("Test finished at %" PRIu64, add_block_ctx->simulated_time);
    }
    return is_finished;
}

void add_block_test_delete_ctx(add_block_test_ctx_t* add_block_ctx)
{
    /* Delete the links */
    for (int i = 0; i < 2; i++) {
        if (add_block_ctx->link[i] != NULL) {
            picoquictest_sim_link_delete(add_block_ctx->link[i]);
        }
    }
    /* Delete the QUIC contexts */
    for (int i = 0; i < 2; i++) {
        if (add_block_ctx->quic[i] != NULL) {
            picoquic_free(add_block_ctx->quic[i]);
        }
    }
    /* delete the data blocks */
    if (add_block_ctx->test_data) {
        free(add_block_ctx->test_data);
        add_block_ctx->test_data = NULL;
    }

    if (add_block_ctx->recv_data) {
        free(add_block_ctx->recv_data);
        add_block_ctx->recv_data = NULL;
    }

    /* Free the context */
    free(add_block_ctx);
}

add_block_test_ctx_t* add_block_test_configure()
{
    int ret = 0;
    add_block_test_ctx_t* add_block_ctx = NULL;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];
    picoquic_connection_id_t icid = { { 0xad, 0xdb, 0x10, 0xc8, 0, 0, 0, 0}, 8 };

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_SERVER_KEY);
    }
    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir, PICOQUIC_TEST_FILE_CERT_STORE);
    }
    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    }
    else {
        add_block_ctx = (add_block_test_ctx_t*)malloc(sizeof(add_block_test_ctx_t));
        if (add_block_ctx == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        memset(add_block_ctx, 0, sizeof(add_block_test_ctx_t));
        /* Create the QUIC contexts */
        add_block_ctx->quic[0] = picoquic_create(4, NULL, NULL, test_server_cert_store_file, NULL, add_block_test_callback,
            (void*)add_block_ctx, NULL, NULL, NULL, add_block_ctx->simulated_time, &add_block_ctx->simulated_time, NULL, NULL, 0);
        add_block_ctx->quic[1] = picoquic_create(4,
            test_server_cert_file, test_server_key_file, test_server_cert_store_file,
            ADD_BLOCK_TEST_ALPN, add_block_test_callback, (void*)add_block_ctx, NULL, NULL, NULL,
            add_block_ctx->simulated_time, &add_block_ctx->simulated_time, NULL, NULL, 0);

        if (add_block_ctx->quic[0] == NULL || add_block_ctx->quic[1] == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        /* Do not use randomization by default during tests */
        for (int i = 0; i < 2; i++) {
            picoquic_set_random_initial(add_block_ctx->quic[i], 0);
        }
        /* Init of the IP addresses */
        for (uint16_t i = 0; i < 2; i++) {
            picoquic_set_test_address((struct sockaddr_in*)&add_block_ctx->addr[i], 0x0A000001 + i, 1234 + i);
        }
        /* register the links */
        for (int i = 0; i < 2; i++) {
            add_block_ctx->link[i] = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
            if (add_block_ctx->link[i] == NULL) {
                ret = -1;
                break;
            }
        }
    }

    if (ret == 0) {
        /* allocate the test data */
        add_block_ctx->test_data = (uint8_t*)malloc(add_block_test_max_sent);
        add_block_ctx->recv_data = (uint8_t*)malloc(add_block_test_max_sent);
        if (add_block_ctx->test_data == NULL || add_block_ctx->recv_data == NULL) {
            ret = -1;
        }
        else {
            uint64_t rdx = 0xdeeddaadd00dd11dull;
            add_block_ctx->test_data_length = add_block_test_max_sent;

            for (size_t i = 0; i < add_block_ctx->test_data_length; i++) {
                add_block_ctx->test_data[i] = (uint8_t)(rdx & 0xff);
                rdx *= 101;
                rdx += 0xbadc0ffee;
                rdx += i;
            }
            memset(add_block_ctx->recv_data, 0, add_block_ctx->test_data_length);
        }
    }

    if (ret == 0) {
        /* Create the client connection. */
        add_block_ctx->cnx_client = picoquic_create_cnx(add_block_ctx->quic[0],
            icid, picoquic_null_connection_id,
            (struct sockaddr*)&add_block_ctx->addr[1], add_block_ctx->simulated_time, 0, PICOQUIC_TEST_SNI, ADD_BLOCK_TEST_ALPN, 1);
        /* Start the connection and create the context */
        if (add_block_ctx->cnx_client == NULL) {
            ret = -1;
        }
        else {
            /* Find the first client unidir stream */
            add_block_ctx->stream_id = picoquic_get_next_local_stream_id(add_block_ctx->cnx_client, 1);
            /* Queue the first block */
            add_block_test_send(add_block_ctx, 0);
            /* start the connection */
            if (picoquic_start_client_cnx(add_block_ctx->cnx_client) != 0) {
                picoquic_delete_cnx(add_block_ctx->cnx_client);
                ret = -1;
            }
        }
    }

    if (ret != 0 && add_block_ctx != NULL) {
        add_block_test_delete_ctx(add_block_ctx);
        add_block_ctx = NULL;
    }

    return add_block_ctx;
}

int add_block_test_loop(add_block_test_ctx_t* add_block_ctx, uint64_t simulated_time_max, int is_losing_data, int* is_finished)
{
    int ret = 0;
    int nb_steps = 0;
    int nb_inactive = 0;

    /* Run the simulation until done */
    while (ret == 0 && !(*is_finished) && nb_steps < 100000 && nb_inactive < 512 && add_block_ctx->simulated_time < simulated_time_max && !error_found) {
        int is_active = 0;
        nb_steps += 1;
        ret = add_block_test_step(add_block_ctx, is_losing_data, &is_active);
        if (is_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive += 1;
        }
        *is_finished = add_block_test_is_finished(add_block_ctx);
    }

    return ret;
}

/* One test */
int add_block_test()
{
    int ret = 0;
    int is_finished = 0;

    /* set the configuration */
    add_block_test_ctx_t* add_block_ctx = add_block_test_configure();
    current_ctx = add_block_ctx;
    if (add_block_ctx == NULL) {
        ret = -1;
    }

    /* Run the simulation until done */
    if (ret == 0) {
        ret = add_block_test_loop(add_block_ctx, 30000000, 0, &is_finished);
    }

    /* Check that the simulation ran to the end. */
    if (ret == 0) {
        if (error_found) {
            ret = -1;
        }
        else if (!is_finished) {
            ret = -1;
        }
        else if (add_block_ctx->recv_length != add_block_ctx->test_data_length) {
            ret = -1;
        }
        else if (memcmp(add_block_ctx->recv_data, add_block_ctx->test_data, add_block_ctx->test_data_length) != 0) {
            ret = -1;
        }
    }

    if (add_block_ctx != NULL) {
        add_block_test_delete_ctx(add_block_ctx);
    }
    return ret;
}