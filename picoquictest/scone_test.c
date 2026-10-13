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
    int short_header_seen;
    int indicator_first;
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

    /* We want to test whether the client sent a SCONE indication. This
    * indication may be sent in the first packet, and it may be repeated in any
    * of the long header packets in the client's first flight, including for
    * example 0RTT packets. It should probably not be set in the following
    * "handshake" packets, but the last bits of an AEAD checksum may occasionally
    * create a false positive.
    * 
    * We will mark the checksum as seen if the first packet is a long header packet,
    * and it contains the SCONE indication. We will ignore occurence of the
    * scone header in the consecutive long header packets.
     */
    if (packet->length > 2 && (packet->bytes[0] & 0x80) != 0){
        if (packet->bytes[packet->length - 2] == ((SCONE_INDICATOR >> 8) & 0xff) &&
            packet->bytes[packet->length - 1] == (SCONE_INDICATOR & 0xff)) {
            if (!scone_aqm_state->first_seen) {
                scone_aqm_state->indicator_first = 1;
            }
            scone_aqm_state->first_seen = 1;
            should_drop = scone_aqm_state->do_loss;
        }
    }
    else if ((packet->bytes[0] & 0x80) == 0) {
        scone_aqm_state->short_header_seen = 1;
    }

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
                else if (scone_aqm_client->indicator_first) {
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

/* Direct-call tests for a handful of scone.c branches that the end-to-end tests above
 * never reach, because a real handshake always supplies a length-2-or-more buffer, only
 * ever sends the indicator once per connection, and never runs out of packet buffer
 * space mid-format. */

uint8_t* picoquic_scone_format_packet(uint8_t* bytes, const uint8_t* bytes_max, unsigned int signal,
    picoquic_connection_id_t* dcid, picoquic_connection_id_t* scid);

/* picoquic_scone_padding's length < 2 path -- both the length == 0 sub-case (no write
 * at all) and the length == 1 sub-case (writes a single zero byte) -- is never reached
 * by the end-to-end tests, which always pad a real packet tail of several bytes. */
int scone_padding_short_length_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint8_t buffer[4] = { 0xff, 0xff, 0xff, 0xff };

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        ret = -1;
    }
    else {
        picoquic_scone_padding(cnx, buffer, 0);
        if (buffer[0] != 0xff) {
            ret = -1;
        }
        if (ret == 0) {
            picoquic_scone_padding(cnx, buffer, 1);
            if (buffer[0] != 0) {
                ret = -1;
            }
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);
    return ret;
}

/* picoquic_scone_padding only logs and sets is_scone_indicator_sent on the first call;
 * a second call on the same connection skips the "already sent" branch -- never
 * exercised, since the end-to-end tests only pad the very first packet once per test. */
int scone_padding_indicator_already_sent_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint8_t buffer[8];

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        ret = -1;
    }
    else {
        picoquic_scone_padding(cnx, buffer, sizeof(buffer));
        if (!cnx->is_scone_indicator_sent) {
            ret = -1;
        }
        else {
            /* Second call: indicator already sent, must not log again, but should
             * still pad with the indicator bytes. */
            picoquic_scone_padding(cnx, buffer, sizeof(buffer));
            if (buffer[sizeof(buffer) - 2] != (uint8_t)((SCONE_INDICATOR >> 8) & 0xff) ||
                buffer[sizeof(buffer) - 1] != (uint8_t)(SCONE_INDICATOR & 0xff)) {
                ret = -1;
            }
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);
    return ret;
}

/* picoquic_scone_format_packet rejects a buffer too small to hold the fixed 5 byte
 * header plus at least one byte per CID -- never exercised, since every end-to-end
 * test formats into a full-size packet buffer. */
int scone_format_packet_too_small_test(void)
{
    int ret = 0;
    uint8_t buffer[4];

    if (picoquic_scone_format_packet(buffer, buffer + sizeof(buffer), 127, NULL, NULL) != NULL) {
        DBG_PRINTF("%s", "picoquic_scone_format_packet did not reject a too-small buffer");
        ret = -1;
    }
    return ret;
}

/* picoquic_scone_prepare's "format_packet failed" branch was never exercised -- reached
 * here by supplying a packet buffer too small to hold the scone header. */
int scone_prepare_format_failure_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;
    uint8_t packet_buffer[4];
    size_t segment_length = 0;
    uint64_t next_wake_time = 0;
    int is_initial_sent = 0;

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        ret = -1;
    }
    else {
        if (picoquic_scone_prepare(cnx, cnx->path[0], NULL, 0, packet_buffer, sizeof(packet_buffer),
            &segment_length, &next_wake_time, &is_initial_sent) != PICOQUIC_ERROR_UNEXPECTED_ERROR) {
            DBG_PRINTF("%s", "picoquic_scone_prepare did not report a too-small packet buffer");
            ret = -1;
        }
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);
    return ret;
}

/* picoquic_scone_report: the path_index < 0 guard, and the callback_fn == NULL guard,
 * are never exercised -- the end-to-end tests only ever call it with a real path index
 * and a real callback. */
int scone_report_guards_test(void)
{
    int ret = 0;
    picoquic_quic_t* quic = NULL;
    picoquic_cnx_t* cnx = NULL;

    if (picoquic_test_set_minimal_cnx(&quic, &cnx) != 0) {
        ret = -1;
    }
    else {
        uint64_t saved_indication = cnx->quic->scone_indication;
        picoquic_stream_data_cb_fn saved_callback_fn = cnx->callback_fn;
        uint64_t saved_advice = cnx->path[0]->scone_advice_last;

        cnx->quic->scone_indication = 12345;
        picoquic_scone_report(cnx, -1);
        if (cnx->quic->scone_indication != 12345) {
            DBG_PRINTF("%s", "picoquic_scone_report acted on a negative path index");
            ret = -1;
        }

        if (ret == 0) {
            cnx->callback_fn = NULL;
            picoquic_scone_report(cnx, 0);
            if (cnx->quic->scone_indication != 0 || cnx->path[0]->scone_advice_last != 12345) {
                DBG_PRINTF("%s", "picoquic_scone_report did not record advice when callback_fn is NULL");
                ret = -1;
            }
        }

        cnx->quic->scone_indication = saved_indication;
        cnx->callback_fn = saved_callback_fn;
        cnx->path[0]->scone_advice_last = saved_advice;
    }
    picoquic_test_delete_minimal_cnx(&quic, &cnx);
    return ret;
}