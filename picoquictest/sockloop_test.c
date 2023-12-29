/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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
#include "autoqlog.h"

/* 
* Testing the socket loop.
* This requires sending packets through sockets, etc. We do that by using a 
* single QUIC context as both server and client, using a local socket to
* loop packets between the client and server connections.
 */

int sockloop_quic_config()
{
    int ret = 0;
    char test_server_cert_file[512];
    char test_server_key_file[512];
    char test_server_cert_store_file[512];

    ret = picoquic_get_input_path(test_server_cert_file, sizeof(test_server_cert_file), picoquic_solution_dir,
        (use_ecdsa)?PICOQUIC_TEST_FILE_SERVER_CERT_ECDSA:PICOQUIC_TEST_FILE_SERVER_CERT);

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_key_file, sizeof(test_server_key_file), picoquic_solution_dir,
            (use_ecdsa)?PICOQUIC_TEST_FILE_SERVER_KEY_ECDSA:PICOQUIC_TEST_FILE_SERVER_KEY);
    }

    if (ret == 0) {
        ret = picoquic_get_input_path(test_server_cert_store_file, sizeof(test_server_cert_store_file), picoquic_solution_dir,
            PICOQUIC_TEST_FILE_CERT_STORE);
    }

    if (ret != 0) {
        DBG_PRINTF("%s", "Cannot set the cert, key or store file names.\n");
    } else {
        test_ctx = (picoquic_test_tls_api_ctx_t*)
            malloc(sizeof(picoquic_test_tls_api_ctx_t));

        if (test_ctx == NULL) {
            ret = -1;
        } else {
            /* Init to NULL */
            memset(test_ctx, 0, sizeof(picoquic_test_tls_api_ctx_t));
            test_ctx->client_callback.client_mode = 1;

            /* Init of the IP addresses */
            memset(&test_ctx->client_addr, 0, sizeof(struct sockaddr_in));
            test_ctx->client_addr.sin_family = AF_INET;
#ifdef _WINDOWS
            test_ctx->client_addr.sin_addr.S_un.S_addr = htonl(0x0A000002);
#else
            test_ctx->client_addr.sin_addr.s_addr = htonl(0x0A000002);
#endif
            test_ctx->client_addr.sin_port = htons(1234);

            memset(&test_ctx->server_addr, 0, sizeof(struct sockaddr_in));
            test_ctx->server_addr.sin_family = AF_INET;
#ifdef _WINDOWS
            test_ctx->server_addr.sin_addr.S_un.S_addr = htonl(0x0A000001);
#else
            test_ctx->server_addr.sin_addr.s_addr = htonl(0x0A000001);
#endif
            test_ctx->server_addr.sin_port = htons(4321);

            /* Test the creation of the client and server contexts */
            test_ctx->qclient = picoquic_create(8, NULL, NULL, test_server_cert_store_file, NULL, test_api_callback,
                (void*)&test_ctx->client_callback, NULL, NULL, NULL, *p_simulated_time,
                p_simulated_time, ticket_file_name, NULL, 0);

            if (token_file_name != NULL) {
                (void)picoquic_load_token_file(test_ctx->qclient, token_file_name);
            }

            test_ctx->qserver = picoquic_create(nb_connections,
                test_server_cert_file, test_server_key_file, test_server_cert_store_file,
                (alpn == NULL)?PICOQUIC_TEST_ALPN:alpn, test_api_callback, (void*)&test_ctx->server_callback, NULL, NULL, NULL,
                *p_simulated_time, p_simulated_time, NULL,
                (use_bad_crypt == 0) ? test_ticket_encrypt_key : test_ticket_badcrypt_key,
                (use_bad_crypt == 0) ? sizeof(test_ticket_encrypt_key) : sizeof(test_ticket_badcrypt_key));

            if (test_ctx->qclient == NULL || test_ctx->qserver == NULL) {
                ret = -1;
            }
            else if (cid_zero){
                test_ctx->qclient->local_cnxid_length = 0;
            }

            if (ret == 0) {
                /* Do not use randomization by default during tests */
                picoquic_set_random_initial(test_ctx->qclient, 0);
                picoquic_set_random_initial(test_ctx->qserver, 0);
            }

            /* register the links */
            if (ret == 0) {
                test_ctx->c_to_s_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);
                test_ctx->s_to_c_link = picoquictest_sim_link_create(0.01, 10000, NULL, 0, 0);

                if (test_ctx->c_to_s_link == NULL || test_ctx->s_to_c_link == NULL) {
                    ret = -1;
                }
            }

            if (ret == 0) {
                /* Create the send buffer as requested */
                if (send_buffer_size == 0) {
                    test_ctx->send_buffer_size = PICOQUIC_MAX_PACKET_SIZE;
                }
                else {
                    test_ctx->send_buffer_size = send_buffer_size;
                    test_ctx->use_udp_gso = 1;
                }
                test_ctx->send_buffer = (uint8_t*)malloc(test_ctx->send_buffer_size);
                if (test_ctx->send_buffer == NULL) {
                    ret = -1;
                }
            }

            if (ret == 0) {
                /* Apply the zero share parameter if required */
                if (force_zero_share != 0)
                {
                    test_ctx->qclient->client_zero_share = 1;
                }
                /* Do not use hole insertion by default */
                picoquic_set_optimistic_ack_policy(test_ctx->qclient, 0);
                picoquic_set_optimistic_ack_policy(test_ctx->qserver, 0);

                /* Create a client connection */
                test_ctx->cnx_client = picoquic_create_cnx(test_ctx->qclient,
                    (icid == NULL)? picoquic_null_connection_id: *icid,
                    picoquic_null_connection_id,
                    (struct sockaddr*)&test_ctx->server_addr, *p_simulated_time,
                    proposed_version, sni, alpn, 1);

                if (test_ctx->cnx_client == NULL) {
                    ret = -1;
                }
                else if (delayed_init == 0) {
                    ret = picoquic_start_client_cnx(test_ctx->cnx_client);
                }
            }
        }
    }
    /* Create a client connection */

}