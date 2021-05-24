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

#ifdef _WINDOWS
#include "wincompat.h"
#endif
#include "picoquic_internal.h"
#include "tls_api.h"
#include "picoquic_utils.h"
#include "picotls.h"
#include "picoquic_lb.h"
#include <string.h>
#include "picoquictest_internal.h"

/* Test of the CID generation function.
 */
#define CID_ENCRYPTION_KEY 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16

#define NB_LB_CONFIG_TEST 3

picoquic_load_balancer_config_t cid_for_lb_test_config[NB_LB_CONFIG_TEST] = {
    {
        picoquic_load_balancer_cid_clear,
        3,
        0,
        0,
        8,
        0x08,
        0x0123,
        { 0 }
    },
    {
        picoquic_load_balancer_cid_stream_cipher,
        4,
        8,
        0,
        13,
        0x8B,
        0x2345,
        { CID_ENCRYPTION_KEY }
    },
    {
        picoquic_load_balancer_cid_block_cipher,
        2,
        0,
        4,
        17,
        0x97,
        0x3456,
        { CID_ENCRYPTION_KEY }
    }
};

picoquic_connection_id_t cid_for_lb_test_ref[NB_LB_CONFIG_TEST] = {
    { { 0x08, 0x00, 0x01, 0x23, 0x84, 0x85, 0x86, 0x87 }, 8 },
    { { 0x8b, 0x7b, 0x37, 0xbe, 0x1c, 0x7c, 0xe2, 0x62, 0x28, 0x66, 0xd9, 0xf1, 0x7a }, 13},
    { { 0x97, 0x42, 0xa4, 0x35, 0x97, 0x2b, 0xfc, 0x60, 0x51, 0x69, 0x1d, 0x28, 0x1a, 0x65, 0x13, 0xcf, 0x4a }, 17 }
};

int cid_for_lb_test_one(picoquic_quic_t* quic, int test_id, picoquic_load_balancer_config_t* config,
    picoquic_connection_id_t* target_cid)
{
    int ret = 0;
    picoquic_connection_id_t result;

    /* Configure the policy */
    ret = picoquic_lb_compat_cid_config(quic, config);

    if (ret != 0) {
        DBG_PRINTF("CID test #%d fails, could not configure the context.\n", test_id);
    }
    else {
        /* Create a CID. */
        memset(&result, 0, sizeof(picoquic_connection_id_t));
        for (size_t i = 0; i < quic->local_cnxid_length; i++) {
            result.id[i] = (uint8_t)(0x80 + i);
        }
        result.id_len = quic->local_cnxid_length;

        if (quic->cnx_id_callback_fn) {
            quic->cnx_id_callback_fn(quic, picoquic_null_connection_id, picoquic_null_connection_id,
                quic->cnx_id_callback_ctx, &result);
        }

        if (picoquic_compare_connection_id(&result, target_cid) != 0) {
            DBG_PRINTF("CID test #%d fails, result does not match.\n", test_id);
            ret = -1;
        }
        else {
            uint64_t server_id64 = picoquic_lb_compat_cid_verify(quic, quic->cnx_id_callback_ctx, &result);

            if (server_id64 != config->server_id64) {
                DBG_PRINTF("CID test #%d fails, server id decode to %" PRIu64 " instead of %" PRIu64,
                    test_id, server_id64, config->server_id64);
                ret = -1;
            }
        }
    }

    /* Free the configured policy */
    picoquic_lb_compat_cid_config_free(quic);

    return ret;
}


int cid_for_lb_test()
{
    int ret = 0;
    uint64_t simulated_time = 0;
    picoquic_quic_t* quic = picoquic_create(8, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL, NULL, NULL, simulated_time,
        &simulated_time, NULL, NULL, 0);

    if (quic == NULL) {
        DBG_PRINTF("%s", "Could not create the quic context.");
    }
    else {
        for (int i = 0; i < NB_LB_CONFIG_TEST && ret == 0; i++) {
            ret = cid_for_lb_test_one(quic, i, &cid_for_lb_test_config[i], &cid_for_lb_test_ref[i]);
        }

        if (quic != NULL) {
            picoquic_free(quic);
        }
    }
    return ret;
}