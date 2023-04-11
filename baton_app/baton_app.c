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

/* This is the client side implementation of the "baton" app,
 * built on top of picoquic using web transport.
 * It is mostly a test that we have the right architecture for developing web transport.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <picosocks.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <h3zero.h>
#include <h3zero_common.h>
#include <picoquic_packet_loop.h>
#include <autoqlog.h>
#include "wt_baton.h"
#include "pico_webtransport.h"

int wt_baton_client(char const* server_name, int server_port, char const* path, int nb_rounds);
int baton_client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode,
    void* callback_ctx, void* callback_arg);

static void usage(char const * sample_name)
{
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "    %s server_name port path [nb_rounds]\n", sample_name);
    exit(1);
}

int get_port(char const* sample_name, char const* port_arg)
{
    int server_port = atoi(port_arg);
    if (server_port <= 0) {
        fprintf(stderr, "Invalid port: %s\n", port_arg);
        usage(sample_name);
    }

    return server_port;
}

int main(int argc, char** argv)
{
    int ret = 0;
#ifdef _WINDOWS
    WSADATA wsaData = { 0 };
    (void)WSA_START(MAKEWORD(2, 2), &wsaData);
#endif

    if (argc < 4 || argc > 5) {
        usage(argv[0]);
    }
    else {
        char const* server_name = argv[1];
        int server_port = get_port(argv[0], argv[2]);
        char const * path = argv[3];
        int nb_rounds = 4;

        ret = wt_baton_client(server_name, server_port, path, nb_rounds);

        if (ret != 0) {
            fprintf(stderr, "Baton dropped, ret=%d\n", ret);
        }
    }
    exit(ret);
}

/* Client:
* - Create the QUIC context.
* - Open the sockets
* - Find the server's address
* - Create a client context and a client connection.
* - On a forever loop:
*     - get the next wakeup time
*     - wait for arrival of message on sockets until that time
*     - if a message arrives, process it.
*     - else, check whether there is something to send.
*       if there is, send it.
* - The loop breaks if the client connection is finished.
*/

#define PICOQUIC_BATON_CLIENT_TICKET_STORE "baton_ticket_store.bin";
#define PICOQUIC_BATON_CLIENT_TOKEN_STORE "baton_token_store.bin";
#define PICOQUIC_BATON_CLIENT_QLOG_DIR ".";

int wt_baton_client(char const * server_name, int server_port, char const * path, int nb_turns_required)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    char const* sni = "test";
    picoquic_quic_t* quic = NULL;
    char const* ticket_store_filename = PICOQUIC_BATON_CLIENT_TICKET_STORE;
    char const* token_store_filename = PICOQUIC_BATON_CLIENT_TOKEN_STORE;
    char const* qlog_dir = PICOQUIC_BATON_CLIENT_QLOG_DIR;
    picoquic_cnx_t* cnx = NULL;
    uint64_t current_time = picoquic_current_time();
    wt_baton_ctx_t baton_ctx = { 0 };
        picohttp_server_stream_ctx_t* stream_ctx = NULL;
    h3zero_callback_ctx_t* h3zero_cb = NULL;

    /* Get the server's address */
    if (ret == 0) {
        int is_name = 0;

        ret = picoquic_get_server_address(server_name, server_port, &server_address, &is_name);
        if (ret != 0) {
            fprintf(stderr, "Cannot get the IP address for <%s> port <%d>", server_name, server_port);
        }
        else if (is_name) {
            sni = server_name;
        }
    }

    /* Create a QUIC context
    */
    if (ret == 0) {
        quic = picoquic_create(
                8,
                NULL, /* Cert */
                NULL, /* Key file */
                NULL, /* trust file */
                "h3",
                NULL, /* default_callback_fn */
                NULL, /* default_callback_ctx */
                NULL,
                NULL,
                NULL, /* Reset seed is only for servers */
                current_time,
                NULL, /* Not using simulated time */
                ticket_store_filename,
                NULL, /* Only server need the ticket_encryption_key */
                0 /* Only server need the ticket_encryption_key length */ );

        if (quic == NULL) {
            fprintf(stderr, "Could not create quic context\n");
            ret = -1;
        }
        else {
            if (picoquic_load_retry_tokens(quic, token_store_filename) != 0) {
                fprintf(stderr, "No token file present. Will create one as <%s>.\n", token_store_filename);
            }

            picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

            picoquic_set_key_log_file_from_env(quic);
            picoquic_set_qlog(quic, qlog_dir);
            picoquic_set_log_level(quic, 1);
        }
    }

    /* Initialize the callback context and create the connection context.
    * We use minimal options on the client side, keeping the transport
    * parameter values set by default for picoquic. This could be fixed later.
    */

    if (ret == 0) {
        /* use the generic H3 callback */
        /* Set the client callback context */
        h3zero_cb = h3zero_callback_create_context(NULL);
        if (h3zero_cb == NULL) {
            ret = 1;
        }
    }
    if (ret == 0) {
        ret = 0;
    }
    if (ret == 0) {
        printf("Starting connection to %s, port %d\n", server_name, server_port);

        /* Create a client connection */
        cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*) & server_address, current_time, 0, sni, "h3", 1);
        if (cnx == NULL) {
            fprintf(stderr, "Could not create connection context\n");
            ret = -1;
        }
        else {
            picowt_set_transport_parameters(cnx);
            picoquic_set_callback(cnx, h3zero_callback, h3zero_cb);
            /* Initialize the callback context. First, create a bidir stream */
            wt_baton_ctx_init(&baton_ctx, h3zero_cb, NULL, NULL);
            baton_ctx.is_client = 1;
            baton_ctx.server_path = path;
            baton_ctx.nb_turns_required = nb_turns_required;

            /* Create a stream context for the connect call. */
            stream_ctx = wt_baton_create_stream(cnx, 1, &baton_ctx);
            if (stream_ctx == NULL) {
                ret = -1;
            }
            else {
                baton_ctx.connection_ready = 1;
                baton_ctx.is_client = 1;
                stream_ctx->is_open = 1;
                stream_ctx->path_callback = wt_baton_callback;
                stream_ctx->path_callback_ctx = &baton_ctx;
                /* send the WT CONNECT */
                ret = picowt_connect(cnx, stream_ctx, &h3zero_cb->stream_prefixes, baton_ctx.server_path, wt_baton_callback, &baton_ctx);
            }

            /* Client connection parameters could be set here, before starting the connection. */
            if (ret == 0) {
                ret = picoquic_start_client_cnx(cnx);
            }
            if (ret < 0) {
                fprintf(stderr, "Could not activate connection\n");
            } else {
                /* Printing out the initial CID, which is used to identify log files */
                picoquic_connection_id_t icid = picoquic_get_initial_cnxid(cnx);
                printf("Initial connection ID: ");
                for (uint8_t i = 0; i < icid.id_len; i++) {
                    printf("%02x", icid.id[i]);
                }
                printf("\n");
                /* Perform the initialization, settings and QPACK streams
                 */
                ret = h3zero_protocol_init(cnx);
            }
        }
    }

    /* Wait for packets */
    ret = picoquic_packet_loop(quic, 0, server_address.ss_family, 0, 0, 0, baton_client_loop_cb, &baton_ctx);

    /* Done. At this stage, we could print out statistics, etc. */
    /* baton_client_report(&baton_ctx); */

    if (h3zero_cb != NULL)
    {
        h3zero_callback_delete_context(cnx, h3zero_cb);
    }

    /* Save tickets and tokens, and free the QUIC context */
    if (quic != NULL) {
        if (picoquic_save_session_tickets(quic, ticket_store_filename) != 0) {
            fprintf(stderr, "Could not store the saved session tickets.\n");
        }
        if (picoquic_save_retry_tokens(quic, token_store_filename) != 0) {
            fprintf(stderr, "Could not save tokens to <%s>.\n", token_store_filename);
        }
        picoquic_free(quic);
    }

    return ret;
}

/* Client socket loop 
 */

 /* Sample client,  loop call back management.
 * The function "picoquic_packet_loop" will call back the application when it is ready to
 * receive or send packets, after receiving a packet, and after sending a packet.
 * We implement here a minimal callback that instruct  "picoquic_packet_loop" to exit
 * when the connection is complete.
 */

int baton_client_loop_cb(picoquic_quic_t* quic, picoquic_packet_loop_cb_enum cb_mode, 
    void* callback_ctx, void * callback_arg)
{
    int ret = 0;
    wt_baton_ctx_t * cb_ctx = (wt_baton_ctx_t*)callback_ctx;

    if (cb_ctx == NULL) {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else {
        switch (cb_mode) {
        case picoquic_packet_loop_ready:
            fprintf(stdout, "Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            if (cb_ctx->connection_closed) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            break;
        case picoquic_packet_loop_after_send:
            if (cb_ctx->connection_closed) {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            break;
        case picoquic_packet_loop_port_update:
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}
