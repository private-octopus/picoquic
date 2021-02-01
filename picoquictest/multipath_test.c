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

/* Add the additional links for multipath scenario */
static int multipath_test_add_links(picoquic_test_tls_api_ctx_t* test_ctx, int mtu_drop)
{
    int ret = 0;
    /* Initialize the second client address */
    test_ctx->client_addr_2 = test_ctx->client_addr;
    test_ctx->client_addr_2.sin_port += 17;
    /* register the links */
    test_ctx->c_to_s_link_2 = picoquictest_sim_link_create(0.01, 10000, NULL, 20000, 0);
    test_ctx->s_to_c_link_2 = picoquictest_sim_link_create(0.01, 10000, NULL, 20000, 0);

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
static void multipath_test_kill_links(picoquic_test_tls_api_ctx_t* test_ctx, int link_id)
{
    /* Make sure that nothing gets sent on the old links */
    if (link_id == 0) {
        test_ctx->c_to_s_link->next_send_time = UINT64_MAX;
        test_ctx->c_to_s_link->is_switched_off = 1;
        test_ctx->s_to_c_link->next_send_time = UINT64_MAX;
        test_ctx->s_to_c_link->is_switched_off = 1;
    }
    else {
        test_ctx->c_to_s_link_2->next_send_time = UINT64_MAX;
        test_ctx->c_to_s_link_2->is_switched_off = 1;
        test_ctx->s_to_c_link_2->next_send_time = UINT64_MAX;
        test_ctx->s_to_c_link_2->is_switched_off = 1;
    }
}

/* Add the additional links for multipath scenario */
static void multipath_test_sat_links(picoquic_test_tls_api_ctx_t* test_ctx, int link_id)
{
    if (link_id == 0) {
        /* Use low throughput for terrestrial link. */
        test_ctx->c_to_s_link->picosec_per_byte = 8000000ull; /* Simulate 1 Mbps */
        test_ctx->s_to_c_link->picosec_per_byte = 8000000ull; /* Simulate 1 Mbps */
    }
    else {
        /* Use higher latency for satellite link */
        const uint64_t sat_latency = 300000;

        test_ctx->c_to_s_link_2->microsec_latency = sat_latency;
        test_ctx->s_to_c_link_2->microsec_latency = sat_latency;
        test_ctx->c_to_s_link_2->queue_delay_max = 2*sat_latency;
        test_ctx->s_to_c_link_2->queue_delay_max = 2*sat_latency;
    }
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
};

int migration_test_one(int mtu_drop)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    uint64_t max_completion_microsec = 2000000;
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
        multipath_test_kill_links(test_ctx, 0);
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

/*
 * Test of actual multipath, by opposition to only migration.
 */


void multipath_init_params(picoquic_tp_t *test_parameters, int enable_time_stamp)
{
    memset(test_parameters, 0, sizeof(picoquic_tp_t));

    picoquic_init_transport_parameters(test_parameters, 1);

    test_parameters->enable_multipath = 1;
    test_parameters->enable_time_stamp = 3;
}

/* wait until the migration completes */
int wait_multipath_ready(picoquic_test_tls_api_ctx_t* test_ctx,
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
    picoquic_store_addr(&old_srce, (struct sockaddr*) & test_ctx->cnx_client->path[0]->local_addr);
    picoquic_store_addr(&old_dest, (struct sockaddr*) & test_ctx->cnx_client->path[0]->peer_addr);


    while (*simulated_time < time_out &&
        ret == 0 &&
        test_ctx->cnx_client->cnx_state == picoquic_state_ready &&
        nb_trials < 1024 &&
        nb_inactive < 64 &&
        (test_ctx->cnx_client->nb_paths != 2 ||
        !test_ctx->cnx_client->path[1]->challenge_verified ||
        (test_ctx->cnx_server == NULL || (test_ctx->cnx_server->nb_paths != 2 ||
        !test_ctx->cnx_server->path[1]->challenge_verified)))){
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
        (test_ctx->cnx_client->nb_paths != 2 ||
            !test_ctx->cnx_client->path[1]->challenge_verified) ||
            (test_ctx->cnx_server == NULL || (test_ctx->cnx_server->nb_paths != 2 ||
                !test_ctx->cnx_server->path[1]->challenge_verified)))) {
        DBG_PRINTF("Could not establish multipath, client state = %d\n",
            test_ctx->cnx_client->cnx_state);
        ret = -1;
    }

    return ret;
}

typedef enum {
    multipath_test_basic = 0,
    multipath_test_drop_first,
    multipath_test_drop_second,
    multipath_test_sat_plus,
    multipath_test_renew,
    multipath_test_rotation,
    multipath_test_nat
} multipath_test_enum_t;

int multipath_test_one(uint64_t max_completion_microsec, multipath_test_enum_t test_id)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x1b, 0x11, 0xc0, 4, 5, 6, 7, 8}, 8 };
    picoquic_tp_t server_parameters;
    uint64_t original_r_cid_sequence = 1;
    int ret;

    /* Create the context but delay initialization, so the multipath option can be set */
    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }
    else {
        int is_sat_test = (test_id == multipath_test_sat_plus);
        if (is_sat_test) {
            /* Simulate an asymmetric "satellite and landline" scenario */
            multipath_test_sat_links(test_ctx, 0);
        }
        test_ctx->c_to_s_link->queue_delay_max = 2 * test_ctx->c_to_s_link->microsec_latency;
        test_ctx->s_to_c_link->queue_delay_max = 2 * test_ctx->s_to_c_link->microsec_latency;

        if (test_id == multipath_test_rotation) {
            picoquic_set_default_crypto_epoch_length(test_ctx->qserver, 200);
        }

        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        /* Set the multipath option at both client and server */
        multipath_init_params(&server_parameters, is_sat_test);
        picoquic_set_default_tp(test_ctx->qserver, &server_parameters);
        test_ctx->cnx_client->local_parameters.enable_multipath = 1;
        test_ctx->cnx_client->local_parameters.enable_time_stamp = is_sat_test;
        /* Initialize the client connection */
        picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    /* establish the connection */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 2 * test_ctx->s_to_c_link->microsec_latency, &simulated_time);
    }
    /* verify that multipath is negotiated on both sides */
    if (ret == 0) {
        if (!test_ctx->cnx_client->is_multipath_enabled || !test_ctx->cnx_server->is_multipath_enabled) {
            DBG_PRINTF("Multipath not fully negotiated (c=%d, s=%d)",
                test_ctx->cnx_client->is_multipath_enabled, test_ctx->cnx_server->is_multipath_enabled);
            ret = -1;
        }
    }

    /* wait until the client (and thus the server) is ready */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_multipath, sizeof(test_scenario_multipath));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Add the multipath links and initiate the migration */
    if (ret == 0) {
        ret = multipath_test_add_links(test_ctx, 0);
        if (ret == 0 && test_id == multipath_test_sat_plus) {
            /* Simulate an asymmetric "satellite and landline" scenario */
            multipath_test_sat_links(test_ctx, 1);
        }
    }

    if (ret == 0) {
        ret = picoquic_probe_new_path(test_ctx->cnx_client, (struct sockaddr*) & test_ctx->server_addr,
            (struct sockaddr*) & test_ctx->client_addr_2, simulated_time);
    }

    /* Check that the two paths are established */
    if (ret == 0) {
        /* TODO */
        ret = wait_multipath_ready(test_ctx, &simulated_time);
    }

    if (ret == 0 && (test_id == multipath_test_drop_first || test_id == multipath_test_drop_second ||
        test_id == multipath_test_renew || test_id == multipath_test_nat)) {
        /* If testing a final link drop before completion, perform a 
         * partial sending loop and then kill the initial link */
        if (ret == 0) {
            uint64_t timeout = (test_id == multipath_test_renew)? /*max_completion_microsec/4*/320000:640000;

            ret = tls_api_wait_for_timeout(test_ctx, &simulated_time, timeout);

            if (ret != 0)
            {
                DBG_PRINTF("Wait for %" PRIu64 "us returns %d\n", timeout, ret);
            }
        }
        if (ret == 0) {
            if (test_id == multipath_test_renew) {
                ret = picoquic_renew_connection_id(test_ctx->cnx_client, 1);
            }
            else if (test_id == multipath_test_nat) {
                /* Change the client address */
                test_ctx->client_addr_natted = test_ctx->client_addr;
                test_ctx->client_addr_natted.sin_port += 7;
                test_ctx->client_use_nat = 1;
            }
            else {
                multipath_test_kill_links(test_ctx, (test_id == multipath_test_drop_first) ? 0 : 1);
            }
        }
    }
    /* Perform a final data sending loop, this time to completion  */
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

    if (ret == 0 && test_id == multipath_test_renew) {
        if (test_ctx->cnx_client->path[1]->p_remote_cnxid->sequence == original_r_cid_sequence) {
            DBG_PRINTF("Remote CID on client path 1 is still %" PRIu64 "\n", original_r_cid_sequence);
            ret = -1;
        } else if (test_ctx->cnx_server->path[1]->p_remote_cnxid->sequence == original_r_cid_sequence) {
            DBG_PRINTF("Remote CID on server path 1 is still %" PRIu64 "\n", original_r_cid_sequence);
            ret = -1;
        }
        else if (test_ctx->cnx_server->path[1]->p_local_cnxid->sequence == original_r_cid_sequence) {
            DBG_PRINTF("Local CID on server path 1 is still %" PRIu64 "\n", original_r_cid_sequence);
            ret = -1;
        }
    }

    if (ret == 0 && test_id == multipath_test_rotation) {
        if (test_ctx->cnx_server->nb_crypto_key_rotations == 0) {
            DBG_PRINTF("%s", "No key rotation observed.\n");
            ret = -1;
        }
    }

    /* Delete the context */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

/* Basic multipath test. Set up two links in parallel, verify that both are used and that
 * the overall transmission is shorterthan if only one link was used.
 */

int multipath_basic_test()
{
    uint64_t max_completion_microsec = 1350000;

    return multipath_test_one(max_completion_microsec, multipath_test_basic);
}

/* Drop first multipath test. Set up two links in parallel, start using them, then
 * drop the first one of them. Check that the transmission succeeds.
 */

int multipath_drop_first_test()
{
    uint64_t max_completion_microsec = 2250000;

    return multipath_test_one(max_completion_microsec, multipath_test_drop_first);
}

/* Drop second multipath test. Set up two links in parallel, start using them, then
 * drop the second one of them. Check that the transmission succeeds.
 */

int multipath_drop_second_test()
{
    uint64_t max_completion_microsec = 2250000;

    return multipath_test_one(max_completion_microsec, multipath_test_drop_second);
}

/* Simulate the combination of a satellite link and a low latency low bandwidth
 * terrestrial link
 */
int multipath_sat_plus_test()
{
    uint64_t max_completion_microsec = 5000000;

    return  multipath_test_one(max_completion_microsec, multipath_test_sat_plus);
}

/* Test the renewal of the connection ID on a path
 */
int multipath_renew_test()
{
    uint64_t max_completion_microsec = 3000000;

    return  multipath_test_one(max_completion_microsec, multipath_test_renew);
}

/* Test key rotation in a multipath setup
 */
int multipath_rotation_test()
{
    uint64_t max_completion_microsec = 3000000;

    return  multipath_test_one(max_completion_microsec, multipath_test_rotation);
}

/* Test NAT rebinding in a multipath setup
 */
int multipath_nat_test()
{
    uint64_t max_completion_microsec = 1600000;

    return  multipath_test_one(max_completion_microsec, multipath_test_nat);
}
/* Monopath tests:
 * Enable the multipath option, but use only a single path. The gal of the tests is to verify that
 * these "monopath" scenarios perform just as well as if multipath was not enabled.
 */

typedef enum {
    monopath_test_basic = 0,
    monopath_test_hole,
    monopath_test_rotation
} monopath_test_enum_t;

/* Basic connection with the multicast option enabled. */
int monopath_test_one(monopath_test_enum_t test_case)
{
    uint64_t simulated_time = 0;
    const uint64_t latency = 10000;
    picoquic_tp_t client_parameters;
    picoquic_tp_t server_parameters;
    picoquic_connection_id_t initial_cid = { {0xba, 0xba, 1, 0, 0, 0, 0, 0}, 8 };
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = 0;

    multipath_init_params(&client_parameters, 0);
    multipath_init_params(&server_parameters, 0);

    ret = tls_api_one_scenario_init_ex(&test_ctx, &simulated_time, PICOQUIC_INTERNAL_TEST_VERSION_1, &client_parameters, &server_parameters, &initial_cid, 0);

    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    /* Simulate satellite links: 250 mbps, 300ms delay in each direction */
    /* Set the congestion algorithm to specified value. Also, request a packet trace */
    if (ret == 0) {
        /* set the delay estimate, then launch the test */
        test_ctx->c_to_s_link->microsec_latency = latency;
        test_ctx->s_to_c_link->microsec_latency = latency;

        picoquic_set_binlog(test_ctx->qserver, ".");
        test_ctx->qserver->use_long_log = 1;
        /* set the binary log on the client side */
        picoquic_set_binlog(test_ctx->qclient, ".");
        test_ctx->qclient->use_long_log = 1;
        /* Since the client connection was created before the binlog was set, force log of connection header */
        binlog_new_connection(test_ctx->cnx_client);

        if (test_case == monopath_test_hole) {
            /* set the optimistic ack policy, to trigger hole insertion at the server */
            picoquic_set_optimistic_ack_policy(test_ctx->qserver, 29);
            /* Reset the uniform random test */
            picoquic_public_random_seed_64(RANDOM_PUBLIC_TEST_SEED, 1);
        }

        if (test_case == monopath_test_rotation) {
            picoquic_set_default_crypto_epoch_length(test_ctx->qserver, 200);
        }

        ret = tls_api_one_scenario_body(test_ctx, &simulated_time,
            test_scenario_multipath, sizeof(test_scenario_multipath), 0, 0, 0, 2 * latency,
            2200000);
    }

    if (ret == 0){
        if (test_case == monopath_test_hole) {
            if (test_ctx->cnx_server->nb_packet_holes_inserted == 0) {
                DBG_PRINTF("%s", "No holes inserted\n");
                ret = -1;
            }
        }
        else if (test_case == monopath_test_rotation) {
            if (test_ctx->cnx_server->nb_crypto_key_rotations == 0) {
                DBG_PRINTF("%s", "No key rotation observed.\n");
                ret = -1;
            }
        }
    }

    /* Free the resource, which will close the log file.
     */

    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
        test_ctx = NULL;
    }

    return ret;
}

/* Basic connection with the multicast option enabled. */
int monopath_basic_test()
{
    return monopath_test_one(monopath_test_basic);
}

/* Testing the defense against opportunistic acks. */
int monopath_hole_test()
{
    return monopath_test_one(monopath_test_hole);
}

/* Testing key rotation in monopath context. */
int monopath_rotation_test()
{
    return monopath_test_one(monopath_test_rotation);
}

/* The zero RTT test uses the unipath code, with a special parameter.
 * Test both regular 0RTT set up, and case of losses.
 */
int zero_rtt_test_one(int use_badcrypt, int hardreset, uint64_t early_loss,
    unsigned int no_coal, unsigned int long_data, uint64_t extra_delay, int do_multipath);

int monopath_0rtt_test()
{
    return zero_rtt_test_one(0, 0, 0, 0, 0, 0, 1);
}

int monopath_0rtt_loss_test()
{
    int ret = 0;

    for (unsigned int i = 1; ret == 0 && i < 16; i++) {
        uint64_t early_loss = 1ull << i;
        ret = zero_rtt_test_one(0, 0, early_loss, 0, 0, 0, 1);
        if (ret != 0) {
            DBG_PRINTF("Monopath 0 RTT test fails when packet #%d is lost.\n", i);
        }
    }

    return ret;
}

/*
 * Test the multipath variant of AEAD encrypt and decrypt.
 */
int multipath_aead_test()
{
    int ret = 0;
    const uint8_t mp_aead_secret[32] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 35, 26, 27, 28, 29, 30, 31
    };
    /* Create AEAD contexts for encryption and decryption */
    void* aead_encrypt = picoquic_setup_test_aead_context(1, mp_aead_secret);
    void* aead_decrypt = picoquic_setup_test_aead_context(0, mp_aead_secret);

    if (aead_encrypt == NULL || aead_decrypt == NULL) {
        DBG_PRINTF("%s", "Could not create the AEAD contexts.\n");
        ret = -1;
    }
    else {
        /* For a series of path_id, verify that encryption and decryption works */
        const uint64_t path_id_test[] = { 0, 1, 2, 0x0123456789abcdefull };
        const size_t nb_paths = sizeof(path_id_test) / sizeof(uint64_t);
        uint64_t sequence = 12345;
        const char* aad_str = "This is a test";
        const size_t aad_len = strlen(aad_str);
        const uint8_t* aad = (const uint8_t*)aad_str;
        const char* test_input_str = "The quick brown fox jumps over the lazy dog";
        const size_t test_input_len = strlen(test_input_str);
        const uint8_t* test_input = (const uint8_t*)test_input_str;
        uint8_t encrypted[256];
        uint8_t decrypted[256];
        size_t encrypted_length;
        size_t decrypted_length;

        for (size_t i = 0; ret == 0 &&  i < nb_paths; i++) {
            encrypted_length = picoquic_aead_encrypt_mp(encrypted, test_input, test_input_len,
                path_id_test[i], sequence, aad, aad_len, aead_encrypt);
            for (size_t j = 0; ret == 0 && j < nb_paths; j++) {
                decrypted_length = picoquic_aead_decrypt_mp(decrypted, encrypted, encrypted_length,
                    path_id_test[j], sequence, aad, aad_len, aead_decrypt);
                if (i != j) {
                    if (decrypted_length <= encrypted_length) {
                        DBG_PRINTF("Unexpected success, path id encode 0x%" PRIx64 ", decode 0x%"PRIx64"\n",
                            path_id_test[i], path_id_test[j]);
                        ret = -1;
                    }
                }
                else if (decrypted_length > encrypted_length) {
                    DBG_PRINTF("Unexpected error, path id 0x%" PRIx64 "\n", path_id_test[i]);
                    ret = -1;
                }
                else if (decrypted_length != test_input_len) {
                    DBG_PRINTF("Length don't match, path id 0x%" PRIx64 ", in: %zu, out %zu\n",
                        path_id_test[i], test_input_len, decrypted_length);
                    ret = -1;
                }
                else if (memcmp(decrypted, test_input, test_input_len) != 0) {
                    DBG_PRINTF("Decoded doesn't match encoded, path id 0x%" PRIx64 "\n", path_id_test[i]);
                    ret = -1;
                }
            }
        }
    }

    if (aead_encrypt != NULL) {
        picoquic_aead_free(aead_encrypt);
    }
    if (aead_decrypt != NULL) {
        picoquic_aead_free(aead_decrypt);
    }

    return ret;
}

/* Test the log of multipath connections
 */

#define MULTIPATH_TRACE_BIN  "0807060504030201.server.log"
#define MULTIPATH_QLOG "multipath_qlog_test.qlog"
#ifdef _WINDOWS
#define MULTIPATH_QLOG_REF "picoquictest\\multipath_qlog_ref.txt"
#else
#define MULTIPATH_QLOG_REF "picoquictest/multipath_qlog_ref.txt"
#endif

static test_api_stream_desc_t test_scenario_multipath_qlog[] = {
    { 4, 0, 257, 10000 },
    { 8, 4, 257, 10000 }
};

static const picoquic_connection_id_t qlog_multipath_initial_cid = { {8, 7, 6, 5, 4, 3, 2, 1}, 8 };

int multipath_trace_test_one()
{
    uint64_t simulated_time = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    int ret = tls_api_init_ctx(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0);
    
    picoquic_connection_id_t cnxfn_data_client = { {1, 1, 1, 1, 1, 1, 1, 1}, 8 };
    picoquic_connection_id_t cnxfn_data_server = { {2, 2, 2, 2, 2, 2, 2, 2}, 8 };
    uint8_t reset_seed_client[PICOQUIC_RESET_SECRET_SIZE] = { 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25 };
    uint8_t reset_seed_server[PICOQUIC_RESET_SECRET_SIZE] = { 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35 };
    picoquic_tp_t server_parameters;
    picoquic_tp_t client_parameters;
    uint64_t loss_mask = 0;
    
    if (ret == 0 && test_ctx == NULL) {
        ret = -1;
    }

    (void)picoquic_file_delete(MULTIPATH_TRACE_BIN, NULL);

    /* Set the logging policy on the server side, to store data in the
     * current working directory, and run a basic test scenario */
    if (ret == 0) {
        picoquic_set_binlog(test_ctx->qserver, ".");
        picoquic_set_default_spinbit_policy(test_ctx->qserver, picoquic_spinbit_on);
        picoquic_set_default_spinbit_policy(test_ctx->qclient, picoquic_spinbit_on);
        picoquic_set_default_lossbit_policy(test_ctx->qserver, picoquic_lossbit_send_receive);
        picoquic_set_default_lossbit_policy(test_ctx->qclient, picoquic_lossbit_send_receive);
        test_ctx->qserver->cnx_id_callback_ctx = (void*)&cnxfn_data_server;
        test_ctx->qserver->cnx_id_callback_fn = qlog_trace_cid_fn;
        test_ctx->qclient->cnx_id_callback_ctx = (void*)&cnxfn_data_client;
        test_ctx->qclient->cnx_id_callback_fn = qlog_trace_cid_fn;
        memcpy(test_ctx->qclient->reset_seed, reset_seed_client, PICOQUIC_RESET_SECRET_SIZE);
        memcpy(test_ctx->qserver->reset_seed, reset_seed_server, PICOQUIC_RESET_SECRET_SIZE);
        test_ctx->qserver->use_constant_challenges = 1;
        test_ctx->qclient->use_constant_challenges = 1;
        /* Fix the buffer sizes in the simulation */
        test_ctx->c_to_s_link->queue_delay_max = 2 * test_ctx->c_to_s_link->microsec_latency;
        test_ctx->s_to_c_link->queue_delay_max = 2 * test_ctx->s_to_c_link->microsec_latency;
        /* Set the multipath option at both client and server */
        multipath_init_params(&server_parameters, 1);
        picoquic_set_default_tp(test_ctx->qserver, &server_parameters);
        multipath_init_params(&client_parameters, 1);
        picoquic_set_default_tp(test_ctx->qclient, &server_parameters);

        /* Force ciphersuite to AES128, so Client Hello has a constant format */
        if (picoquic_set_cipher_suite(test_ctx->qclient, 128) != 0) {
            DBG_PRINTF("Could not set ciphersuite to %d", 128);
        }
        if (picoquic_set_key_exchange(test_ctx->qclient, 128) != 0) {
            DBG_PRINTF("Could not set key exchange to %d", 128);
        }
        /* Delete the old connection */
        picoquic_delete_cnx(test_ctx->cnx_client);
        /* re-create a client connection, this time picking up the required connection ID */
        test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
            qlog_multipath_initial_cid, picoquic_null_connection_id,
            (struct sockaddr*) & test_ctx->server_addr, 0,
            PICOQUIC_INTERNAL_TEST_VERSION_1, PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, 1);
        if (test_ctx->cnx_client == NULL) {
            DBG_PRINTF("%s", "Could not create the new client connection");
            ret = -1;
        }
        else {
            /* Initialize the client connection */
            picoquic_start_client_cnx(test_ctx->cnx_client);
        }
    }

    /* establish the connection */
    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 2 * test_ctx->s_to_c_link->microsec_latency, &simulated_time);
    }
    /* verify that multipath is negotiated on both sides */
    if (ret == 0) {
        if (!test_ctx->cnx_client->is_multipath_enabled || !test_ctx->cnx_server->is_multipath_enabled) {
            DBG_PRINTF("Multipath not fully negotiated (c=%d, s=%d)",
                test_ctx->cnx_client->is_multipath_enabled, test_ctx->cnx_server->is_multipath_enabled);
            ret = -1;
        }
    }

    /* wait until the client (and thus the server) is ready */
    if (ret == 0) {
        ret = wait_client_connection_ready(test_ctx, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_multipath_qlog, sizeof(test_scenario_multipath_qlog));

        if (ret != 0)
        {
            DBG_PRINTF("Init send receive scenario returns %d\n", ret);
        }
    }

    /* Add the multipath links and initiate the migration */
    if (ret == 0) {
        ret = multipath_test_add_links(test_ctx, 0);
    }

    if (ret == 0) {
        ret = picoquic_probe_new_path(test_ctx->cnx_client, (struct sockaddr*) & test_ctx->server_addr,
            (struct sockaddr*) & test_ctx->client_addr_2, simulated_time);
    }

    /* Check that the two paths are established */
    if (ret == 0) {
        ret = wait_multipath_ready(test_ctx, &simulated_time);
    }

    /* Perform a final data sending loop, this time to completion  */
    if (ret == 0) {
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);

        if (ret != 0)
        {
            DBG_PRINTF("Data sending loop returns %d\n", ret);
        }
    }

    /* Check that the transmission succeeded */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 2000000);
    }

    /* Add a gratuitous bad packet to test "packet dropped" log */
    if (ret == 0 && test_ctx->cnx_server != NULL) {
        uint8_t p[256];

        memset(p, 0, sizeof(p));
        memcpy(p + 1, test_ctx->cnx_server->path[0]->p_local_cnxid->cnx_id.id, test_ctx->cnx_server->path[0]->p_local_cnxid->cnx_id.id_len);
        p[0] |= 64;
        (void)picoquic_incoming_packet(test_ctx->qserver, p, sizeof(p), (struct sockaddr*) & test_ctx->cnx_server->path[0]->peer_addr,
            (struct sockaddr*) & test_ctx->cnx_server->path[0]->local_addr, 0, test_ctx->recv_ecn_server, simulated_time);
    }

    /* Delete the context, which will close the log file. */
    if (test_ctx != NULL) {
        tls_api_delete_ctx(test_ctx);
    }

    return ret;
}

int multipath_qlog_test()
{
    int ret = 0;

    (void)picoquic_file_delete(MULTIPATH_QLOG, NULL);

    ret = multipath_trace_test_one();

    /* Create a QLOG file from the .log file */
    if (ret == 0) {
        uint64_t log_time = 0;
        uint16_t flags;

        FILE* f_binlog = picoquic_open_cc_log_file_for_read(MULTIPATH_TRACE_BIN, &flags, &log_time);
        if (f_binlog == NULL) {
            ret = -1;
        }
        else {
            ret = qlog_convert(&qlog_multipath_initial_cid, f_binlog, MULTIPATH_TRACE_BIN, MULTIPATH_QLOG, NULL, flags);
            picoquic_file_close(f_binlog);
        }
    }

    /* compare the log file to the expected value */
    if (ret == 0)
    {
        char qlog_trace_test_ref[512];

        ret = picoquic_get_input_path(qlog_trace_test_ref, sizeof(qlog_trace_test_ref), picoquic_solution_dir,
            MULTIPATH_QLOG_REF);

        if (ret != 0) {
            DBG_PRINTF("%s", "Cannot set the qlog trace test ref file name.\n");
        }
        else {
            ret = picoquic_test_compare_text_files(MULTIPATH_QLOG, qlog_trace_test_ref);
        }
    }

    return ret;
}