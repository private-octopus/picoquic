/*
* Author: Christian Huitema
* Copyright (c) 2026, Private Octopus, Inc.
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
#include "picoquic_c4.h"
#include "tls_api.h"
#include "picoquic_qlog.h"

/* End to end test of SCONE implementation, verifying that we are correctly
* sending and receiving indications.
* Study 4 variants: no scone, scone client only, scone server only, both.
* Indications should only be sent in client cases.
* Scone negotiation should reflect the setup.
* We should see a scone indication in both directions if both support it,
* and none if either the client or the server does not support it.
* The connection should succeed in all cases.
* 
* The test requires simulating an on device path to check for scone indications
* and scone packets, and to set the indication.
*/

#define SCONE_ADVICE_TEST 80
#define SCONE_ADVICE_TEST_BPS 1000000000ull /* 80 */

typedef struct st_scone_aqm_state_t {
struct st_picoquictest_aqm_t super;
    int first_seen;
    int indicator_first;
    int indicator_after;
    int nb_advices;
    int nb_seen;
    int do_loss;
    int nb_dropped;
} scone_aqm_state_t;

void scone_aqm_submit(picoquictest_aqm_t* self, picoquictest_sim_link_t* link,
    picoquictest_sim_packet_t* packet, uint64_t current_time)
{
    scone_aqm_state_t* scone_aqm_state = (scone_aqm_state_t*)self;
    int should_drop = 0;

    if (packet->length > 2 &&
        packet->bytes[packet->length - 2] == ((SCONE_INDICATOR >> 8) & 0xff) &&
        packet->bytes[packet->length - 1] == (SCONE_INDICATOR & 0xff)) {
        if (scone_aqm_state->first_seen) {
            scone_aqm_state->indicator_after += 1;
        }
        else {
            scone_aqm_state->indicator_first = 1;
        }
        should_drop = scone_aqm_state->do_loss;
    }
    scone_aqm_state->first_seen = 1;

    if (packet->length > 5 &&
        (packet->bytes[0] & 0x80) != 0 &&
        (packet->bytes[1] & 0x7f) == ((SCONE_VERSION_BASE >> 24) & 0x7f) &&
        (packet->bytes[2] & 0xff) == ((SCONE_VERSION_BASE >> 16) & 0xff) &&
        (packet->bytes[3] & 0xff) == ((SCONE_VERSION_BASE >> 8) & 0xff) &&
        (packet->bytes[4] & 0xff) == (SCONE_VERSION_BASE & 0xff)) {
        unsigned int current_signal = ((packet->bytes[0] & 0x3f) << 1) + ((packet->bytes[1] & 0x80) >> 7);

        scone_aqm_state->nb_seen += 1;
        if (current_signal == 0x7f) {
            packet->bytes[0] = (packet->bytes[0] & 0xc0) | ((SCONE_ADVICE_TEST >> 1) & 0x3f);
            packet->bytes[1] = (packet->bytes[1] & 0x7f) | ((SCONE_ADVICE_TEST&1) << 7);
            scone_aqm_state->nb_advices += 1;
        }
        should_drop = scone_aqm_state->do_loss;
    }
    scone_aqm_state->nb_dropped += should_drop;
    picoquictest_sim_link_enqueue(link, packet, current_time, should_drop);
}

void scone_aqm_release(picoquictest_aqm_t* self, picoquictest_sim_link_t* link)
{
    free(self);
    link->aqm_state = NULL;
}

void scone_aqm_reset(picoquictest_aqm_t* UNUSED(self), picoquictest_sim_link_t* UNUSED(link), uint64_t UNUSED(current_time))
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(self);
    UNREFERENCED_PARAMETER(link);
    UNREFERENCED_PARAMETER(current_time);
#endif
}

int scone_aqm_configure(picoquictest_sim_link_t* link, int do_loss)
{
    int ret = 0;
    /* Create a configuration */
    scone_aqm_state_t* scone_aqm_state = (scone_aqm_state_t*)malloc(sizeof(scone_aqm_state_t));

    if (scone_aqm_state == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memset(scone_aqm_state, 0, sizeof(scone_aqm_state_t));
        scone_aqm_state->super.submit = scone_aqm_submit;
        scone_aqm_state->super.release = scone_aqm_release;
        scone_aqm_state->super.reset = scone_aqm_reset;
        scone_aqm_state->do_loss = do_loss;

        link->aqm_state = &scone_aqm_state->super;
    }
    return ret;
}

/* The test configuration:
* - sets the transport parameters on servers and client connection per configuration.
* - loads the test AQM in the c_to_s and s_to_c links.
* - runs a standard scenario, long enough to enter the ready phase.
* - verifies that transport parameters are negotiated properly.
* - uses the scone aqm state to verify that the indicators were set as expected.
* - verifies that the advice was received as expected.
*/

static test_api_stream_desc_t test_scenario_scone[] = {
    { 4, 0, 257, 1000000 }
};

typedef struct st_scone_e2e_test_t {
    int scone_client;
    int scone_server;
    int simulate_client_loss;
    int simulate_server_loss;
} scone_e2e_test_t;

int scone_e2e_test_one(uint8_t test_id, scone_e2e_test_t * spec)
{
    uint64_t simulated_time = 0;
    uint64_t loss_mask = 0;
    picoquic_test_tls_api_ctx_t* test_ctx = NULL;
    picoquic_connection_id_t initial_cid = { {0x5c, 0x0e, 0, 0, 0, 0, 0, 0}, 8 };
    int ret;

    initial_cid.id[2] = test_id;

    ret = tls_api_init_ctx_ex(&test_ctx, PICOQUIC_INTERNAL_TEST_VERSION_1,
        PICOQUIC_TEST_SNI, PICOQUIC_TEST_ALPN, &simulated_time, NULL, NULL, 0, 1, 0, &initial_cid);

    if (ret == 0) {
        /* Set the CC algorithm to selected value */
        picoquic_set_default_congestion_algorithm(test_ctx->qserver, c4_algorithm);
        /* ask logs */
        picoquic_set_qlog(test_ctx->qserver, ".");
        picoquic_set_qlog(test_ctx->qclient, ".");
        test_ctx->qserver->use_long_log = 1;
        /* set transport parameters per configuration */
        if (spec->scone_client) {
            test_ctx->qclient->default_tp.is_scone_supported = 1;
            test_ctx->cnx_client->local_parameters.is_scone_supported = 1;
        }
        if (spec->scone_server) {
            test_ctx->qserver->default_tp.is_scone_supported = 1;
        }

        /* Configure the scone AQM on the two links. */
        ret = scone_aqm_configure(test_ctx->c_to_s_link, spec->simulate_client_loss);
        ret = scone_aqm_configure(test_ctx->s_to_c_link, spec->simulate_server_loss);
    }


    if (ret == 0) {
        ret = picoquic_start_client_cnx(test_ctx->cnx_client);
    }

    if (ret == 0) {
        ret = tls_api_connection_loop(test_ctx, &loss_mask, 0, &simulated_time);
    }

    /* Prepare to send data */
    if (ret == 0) {
        ret = test_api_init_send_recv_scenario(test_ctx, test_scenario_scone, sizeof(test_scenario_scone));
    }

    /* try to complete the data sending loop */
    if (ret == 0) {
        loss_mask = 0;
        ret = tls_api_data_sending_loop(test_ctx, &loss_mask, &simulated_time, 0);
    }

    /* verify that the transmission was complete */
    if (ret == 0) {
        ret = tls_api_one_scenario_body_verify(test_ctx, &simulated_time, 0);
    }

    /* verify that the transport parameters are as expected  */
    if (ret == 0){
        scone_aqm_state_t* scone_aqm_client = (scone_aqm_state_t*)test_ctx->c_to_s_link->aqm_state;
        scone_aqm_state_t* scone_aqm_server = (scone_aqm_state_t*)test_ctx->s_to_c_link->aqm_state;

        if (spec->simulate_client_loss || spec->simulate_server_loss) {
            if (spec->simulate_client_loss && scone_aqm_client->nb_dropped < 2) {
                ret = -1;
            }
            if (spec->simulate_server_loss && scone_aqm_server->nb_dropped == 0) {
                ret = -1;
            }
        }
        else {
            if (spec->scone_client) {
                if (!test_ctx->cnx_server->remote_parameters.is_scone_supported) {
                    ret = -1;
                }
                else if (scone_aqm_client->indicator_first == 0) {
                    ret = -1;
                }
            }
            else {
                if (test_ctx->cnx_server->remote_parameters.is_scone_supported) {
                    ret = -1;
                }
                else if (scone_aqm_client->indicator_first ||
                    scone_aqm_client->indicator_after) {
                    ret = -1;
                }
            }

            if (spec->scone_server) {
                if (!test_ctx->cnx_client->remote_parameters.is_scone_supported) {
                    ret = -1;
                }
            }
            else {
                if (test_ctx->cnx_client->remote_parameters.is_scone_supported) {
                    ret = -1;
                }
            }

            if (spec->scone_client && spec->scone_server) {
                if (test_ctx->cnx_client->path[0]->scone_advice_last == 0 ||
                    test_ctx->cnx_server->path[0]->scone_advice_last == 0) {
                    ret = -1;
                }
            }
            else {
                if (test_ctx->cnx_client->path[0]->scone_advice_last != 0 ||
                    test_ctx->cnx_server->path[0]->scone_advice_last != 0) {
                    ret = -1;
                }
                else if (scone_aqm_client->nb_seen > 0 ||
                    scone_aqm_server->nb_seen) {
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

int scone_basic_test(void)
{
    scone_e2e_test_t spec = {
        .scone_client = 1,
        .scone_server = 1
    };

    return scone_e2e_test_one(0, &spec);
}

int scone_client_test(void)
{
    scone_e2e_test_t spec = {
        .scone_client = 1,
        .scone_server = 0
    };

    return scone_e2e_test_one(1, &spec);
}

int scone_loss_test(void)
{
    scone_e2e_test_t spec = {
        .scone_client = 1,
        .scone_server = 1,
        .simulate_client_loss = 1,
        .simulate_server_loss = 1
    };

    return scone_e2e_test_one(2, &spec);
}

int scone_loss_client_test(void)
{
    scone_e2e_test_t spec = {
        .scone_client = 1,
        .scone_server = 1,
        .simulate_client_loss = 1
    };

    return scone_e2e_test_one(3, &spec);
}

int scone_loss_server_test(void)
{
    scone_e2e_test_t spec = {
        .scone_client = 1,
        .scone_server = 1,
        .simulate_server_loss = 1
    };

    return scone_e2e_test_one(4, &spec);
}

int scone_none_test(void)
{
    scone_e2e_test_t spec = {
        .scone_client = 0,
        .scone_server = 0
    };

    return scone_e2e_test_one(5, &spec);
}

int scone_server_test(void)
{
    scone_e2e_test_t spec = {
        .scone_client = 0,
        .scone_server = 1
    };

    return scone_e2e_test_one(6, &spec);
}