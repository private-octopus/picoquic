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

/* Add the additional links for multipath scenario */
static int multipath_test_add_links(picoquic_test_tls_api_ctx_t* test_ctx, int mtu_drop)
{
    int ret = 0;
    /* Initialize the second client address */
    test_ctx->client_addr_2 = test_ctx->client_addr;
    test_ctx->client_addr_2.sin_port += 17;
    /* register the links */
    test_ctx->c_to_s_link_2 = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
    test_ctx->s_to_c_link_2 = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);

    if (test_ctx->c_to_s_link_2 == NULL || test_ctx->s_to_c_link_2 == NULL) {
        ret = -1;
    }
    else if (mtu_drop) {
        test_ctx->c_to_s_link_2->path_mtu = (PICOQUIC_INITIAL_MTU_IPV4 + test_ctx->c_to_s_link->path_mtu) / 2;
        test_ctx->s_to_c_link_2->path_mtu = (PICOQUIC_INITIAL_MTU_IPV4 + test_ctx->s_to_c_link->path_mtu) / 2;
    }

    return ret;
}

/* Add the additional links for multipath scenario */
static void multipath_test_kill_links(picoquic_test_tls_api_ctx_t* test_ctx)
{
    /* Make sure that nothing gets sent on the old links */
    test_ctx->c_to_s_link->next_send_time = UINT64_MAX;
    test_ctx->s_to_c_link->next_send_time = UINT64_MAX;
}

/* wait until the migration completes */
int wait_client_migration_done(picoquic_test_tls_api_ctx_t* test_ctx,
    uint64_t* simulated_time)
{
    int ret = 0;
    uint64_t time_out = *simulated_time + 4000000;
    int nb_trials = 0;
    int nb_inactive = 0;
    int was_active = 0;
    struct sockaddr_storage old_srce;
    struct sockaddr_storage old_dest;

    /* Check the selected path */
    picoquic_store_addr(&old_srce, (struct sockaddr*)&test_ctx->cnx_client->path[0]->local_addr);
    picoquic_store_addr(&old_dest, (struct sockaddr*) & test_ctx->cnx_client->path[0]->peer_addr);


    while (*simulated_time < time_out &&
        test_ctx->cnx_client->cnx_state == picoquic_state_ready &&
        nb_trials < 1024 &&
        nb_inactive < 64 &&
        picoquic_compare_addr((struct sockaddr *) & old_srce, (struct sockaddr*) & test_ctx->cnx_client->path[0]->local_addr) == 0 &&
        picoquic_compare_addr((struct sockaddr*) & old_dest, (struct sockaddr*) & test_ctx->cnx_client->path[0]->peer_addr) == 0 &&
        ret == 0) {
        was_active = 0;
        nb_trials++;

        ret = tls_api_one_sim_round(test_ctx, simulated_time, time_out, &was_active);

        if (was_active) {
            nb_inactive = 0;
        }
        else {
            nb_inactive++;
        }
    }

    if (ret == 0 && (test_ctx->cnx_client->cnx_state != picoquic_state_ready ||
        (picoquic_compare_addr((struct sockaddr*) & old_srce, (struct sockaddr*) & test_ctx->cnx_client->path[0]->local_addr) == 0 &&
            picoquic_compare_addr((struct sockaddr*) & old_dest, (struct sockaddr*) & test_ctx->cnx_client->path[0]->peer_addr) == 0)))
    {
        DBG_PRINTF("Could not complete migration, client state = %d\n",
            test_ctx->cnx_client->cnx_state);
        ret = -1;
    }

    return ret;
}


/* Controlled migration test.
 * Create a basic connection.
 * Run until the handshake is done.
 * Start a migration.
 * Verify that the transfer completes */

#define MIGRATION_TRACE_BIN "migration_trace.bin"


static test_api_stream_desc_t test_scenario_multipath[] = {
    { 4, 0, 257, 1000000 },
    { 8, 4, 257, 1000000 }
#if 0
    ,
    { 12, 8, 257, 1000000 },
    { 16, 12, 257, 1000000 }
#endif
};

int migration_test_one(int mtu_drop)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t max_completion_microsec = 1800000;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x1a, 0x10, 0xc0, 4, 5, 6, 7, 8}, 8 };
    int ret;

    if (mtu_drop) {
        initial_cid.id[2] = 0xcd;
    }
    
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 0, 0, &initial_cid);

    if (mtu_drop) {
        /* The MTU drop test is specifically orientated towards verifying retransmissions,
         * which requires simulating losses */
        loss_mask |= (1 << 31);
    }

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }
    else {
        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
    }

    /* establish the connection*/
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_multipath, sizeof(test_scenario_multipath));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* wait until the client (and thus the server) is ready */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Add the multipath links and initiate the migration */
    if (ret == 0) {
        ret = multipath_test_add_links(test_ctx, mtu_drop);
    }

    if (ret == 0) {
        ret = picoquic_probe_new_path(test_ctx->cnx_client, (struct sockaddr*) & test_ctx->server_addr,
            (struct sockaddr*) & test_ctx->client_addr_2, simulated_time);
    }

    /* Check that the migration succeeds */
    if (ret == 0) {
        ret = wait_client_migration_done(test_ctx, &simulated_time);
    }

    /* Kill the old links, so nothing more can be sent there */
    if (ret == 0) {
        multipath_test_kill_links(test_ctx);
    }

    /* Perform a data sending loop */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    /* Check that the transmission succeeded */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, max_completion_microsec);
    }

    /* Check that the default client address on the server was migrated,
     * as well as the default source address on the client */
    if (ret == 0 && test_ctx->cnx_server == NULL) {
        /* No server connection! */
        ret = -1;
    }

    if (ret == 0) {
        struct sockaddr* c_addr_at_server = NULL;
        struct sockaddr* c_addr_at_client = NULL;
        picoquic_get_peer_addr(test_ctx->cnx_server, &c_addr_at_server);
        picoquic_get_local_addr(test_ctx->cnx_client, &c_addr_at_client);

        if (picoquic_compare_addr((struct sockaddr*) & test_ctx->client_addr_2, c_addr_at_server) != 0 ||
            picoquic_compare_addr((struct sockaddr*) & test_ctx->client_addr_2, c_addr_at_client) != 0) {
            /* Migration was not completed */
            ret = -1;
        }
    }

    /* Delete the context */
    if (test_ctx == NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int migration_controlled_test()
{
    return migration_test_one(0);
}

int migration_mtu_drop_test()
{
    return migration_test_one(1);
}