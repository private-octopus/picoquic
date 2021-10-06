/*
* Author: Christian Huitema
* Copyright (c) 2021, Private Octopus, Inc.
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

/*
* Datagram communication tests.
*/


#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "picoquic_binlog.h"
#include "csv.h"
#include "qlog.h"
#include "autoqlog.h"
#include "picoquic_logger.h"
#include "performance_log.h"
#include "picoquictest.h"

/*
 * Test whether datagrams are sent and received properly
 */
typedef struct st_test_datagram_send_recv_ctx_t {
    int dg_target[2];
    int dg_sent[2];
    int dg_recv[2];
    uint64_t send_delay;
    uint64_t next_gen_time;
    int is_ready[2];
} test_datagram_send_recv_ctx_t;

int test_datagram_check_ready(test_datagram_send_recv_ctx_t* dg_ctx, int client_mode, uint64_t current_time)
{
    dg_ctx->is_ready[client_mode] = (dg_ctx->dg_sent[client_mode] < dg_ctx->dg_target[client_mode] &&
        current_time >= dg_ctx->next_gen_time);
    return dg_ctx->is_ready[client_mode];
}

int test_datagram_send(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length, void* datagram_send_ctx)
{
    int ret = 0;
    test_datagram_send_recv_ctx_t* dg_ctx = datagram_send_ctx;
    uint64_t current_time = picoquic_get_quic_time(picoquic_get_quic_ctx(cnx));

    if (dg_ctx->dg_sent[cnx->client_mode] < dg_ctx->dg_target[cnx->client_mode] &&
        current_time >= dg_ctx->next_gen_time){
        size_t available = length - (size_t)(dg_ctx->dg_sent[cnx->client_mode]%6);
        uint8_t* buffer = picoquic_provide_datagram_buffer(bytes, available);
        if (buffer != NULL) {
            memset(buffer, 'd', available);
            dg_ctx->dg_sent[cnx->client_mode]++;
            dg_ctx->next_gen_time += dg_ctx->send_delay;
            picoquic_mark_datagram_ready(cnx, test_datagram_check_ready(dg_ctx, cnx->client_mode, current_time));
        }
        else {
            ret = -1;
        }
    }
    else {
        picoquic_mark_datagram_ready(cnx, test_datagram_check_ready(dg_ctx, cnx->client_mode, current_time));
    }
    return ret;
}


int test_datagram_recv(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length, void* datagram_recv_ctx)
{
    test_datagram_send_recv_ctx_t* dg_ctx = datagram_recv_ctx;
    dg_ctx->dg_recv[cnx->client_mode] += 1;
    return 0;
}

int datagram_test_one(test_datagram_send_recv_ctx_t *dg_ctx)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0xda, 0xda, 0x01, 0, 0, 0, 0, 0}, 8 };
    picoquic_congestion_algorithm_t* ccalgo = picoquic_bbr_algorithm;
    /* picoquic_tp_t server_parameters; */
    picoquic_tp_t client_parameters;
    int nb_trials = 0;
    int nb_inactive = 0;
    int ret;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0,
        &initial_cid);
    
    /* Set the test contexts for sending and receiving datagrams */
    test_ctx->datagram_recv_fn = test_datagram_recv;
    test_ctx->datagram_recv_ctx = dg_ctx;
    test_ctx->datagram_send_fn = test_datagram_send;
    test_ctx->datagram_send_ctx = dg_ctx;
    /* Set the congestion control  */
    picoquic_set_default_congestion_algorithm(test_ctx->qserver, ccalgo);
    picoquic_set_congestion_algorithm(test_ctx->cnx_client, ccalgo);
    test_ctx->qserver->use_long_log = 1;
    picoquic_set_binlog(test_ctx->qserver, ".");
    test_ctx->qclient->use_long_log = 1;
    picoquic_set_binlog(test_ctx->qclient, ".");
    /* Set parameters */
    /* picoquic_init_transport_parameters(&server_parameters, 0); */
    picoquic_init_transport_parameters(&client_parameters, 1);
    /* server_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE; */
    client_parameters.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
    picoquic_set_transport_parameters(test_ctx->cnx_client, &client_parameters);
    /* ret = picoquic_set_default_tp(test_ctx->qserver, &server_parameters); */
    /* Now, start the client connection */
    ret = picoquic_start_client_cnx(test_ctx->cnx_client);

    if (ret == 0) {
        /* Perform a connection loop to verify it goes OK */
        ret = tls_api_connection_loop(test_ctx, &loss_mask,
            2 * test_ctx->c_to_s_link->microsec_latency, &simulated_time);

        if (ret != 0)
        {
            DBG_PRINTF("Connection loop returns %d\n", ret);
        }
        else {
            /* Verify datagrams are negotiated */
            if (test_ctx->cnx_client->remote_parameters.max_datagram_frame_size != PICOQUIC_MAX_PACKET_SIZE ||
                test_ctx->cnx_server->remote_parameters.max_datagram_frame_size != PICOQUIC_MAX_PACKET_SIZE) {
                DBG_PRINTF("Datagram size badly negotiated: %zu, %zu",
                    test_ctx->cnx_client->remote_parameters.max_datagram_frame_size,
                    test_ctx->cnx_server->remote_parameters.max_datagram_frame_size);
                ret = -1;
            }
        }
    }
    /* Mark that datagrams are ready */
    if (ret == 0) {
        picoquic_mark_datagram_ready(test_ctx->cnx_client, 1);
        picoquic_mark_datagram_ready(test_ctx->cnx_server, 1);
    }

    /* Send datagrams for specified time */
    while (ret == 0 && nb_trials < 2048 && nb_inactive < 16) {
        int was_active = 0;
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, &simulated_time, 0, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
        if (dg_ctx->dg_recv[0] == dg_ctx->dg_target[1] &&
            dg_ctx->dg_recv[1] == dg_ctx->dg_target[0]) {
            break;
        }
        /* Simulate wake up when data is ready for real time operation */
        if (!dg_ctx->is_ready[0] && test_datagram_check_ready(dg_ctx, 0, simulated_time)) {
            picoquic_mark_datagram_ready(test_ctx->cnx_server, 1);
        }
        if (!dg_ctx->is_ready[1] && test_datagram_check_ready(dg_ctx, 1, simulated_time)) {
            picoquic_mark_datagram_ready(test_ctx->cnx_client, 1);
        }
    }
    if (ret == 0) {
        /* Verify datagrams have been received */
        if (dg_ctx->dg_recv[0] != dg_ctx->dg_target[1] ||
            dg_ctx->dg_recv[1] != dg_ctx->dg_target[0]) {
            DBG_PRINTF("Did not receive expected datagrams after %d trials, %d inactive",
                nb_trials, nb_inactive);
            for (int i = 0; i < 2; i++) {
                DBG_PRINTF("dg_target[%d]=%d, dg_sent[%d]=%d, dg_recv[%d]=%d",
                    i, dg_ctx->dg_target[i], i, dg_ctx->dg_sent[i], 1 - i, dg_ctx->dg_recv[1 - i]);
            }
            ret = -1;
        }
    }

    /* And then free the resource */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

int datagram_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };

    dg_ctx.dg_target[0] = 5;
    dg_ctx.dg_target[1] = 5;

    return datagram_test_one(&dg_ctx);
}

int datagram_rt_test()
{
    test_datagram_send_recv_ctx_t dg_ctx = { 0 };

    dg_ctx.dg_target[0] = 100;
    dg_ctx.dg_target[1] = 100;
    dg_ctx.send_delay = 20000;
    dg_ctx.next_gen_time = 100000;


    return datagram_test_one(&dg_ctx);
}