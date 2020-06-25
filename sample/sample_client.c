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

/* The "sample" project builds a simple file transfer program that can be
 * instantiated in client or server mode. The "sample_client" implements
 * the client components of the sample application.
 *
 * Developing the client requires two main components:
 *  - the client "callback" that implements the client side of the
 *    application protocol, managing the client side application context
 *    for the connection.
 *  - the client loop, that reads messages on the socket, submits them
 *    to the Quic context, let the client prepare messages, and send
 *    them on the appropriate socket.
 */

#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include <picoquic_utils.h>
#include <picosocks.h>
#include "picoquic_sample.h"

 /* Client context and callback management:
  *
  * The client application context is created before the connection
  * is created. It contains the list of files that will be required
  * from the server.
  * On initial start, the client creates all the stream contexts 
  * that will be needed for the requested files, and marks all
  * these contexts as active.
  * Each stream context includes:
  *  - description of the stream state:
  *      name sent or not, FILE open or not, stream reset or not,
  *      stream finished or not.
  *  - index of the file in the list.
  *  - number of file name bytes sent.
  *  - stream ID.
  *  - the FILE pointer for reading the data.
  * Server side stream context is created when the client starts the
  * stream. It is closed when the file transmission
  * is finished, or when the stream is abandoned.
  *
  * The server side callback is a large switch statement, with one entry
  * for each of the call back events.
  */

typedef struct st_sample_client_stream_ctx_t {
    struct st_sample_client_stream_ctx_t* next_stream;
    size_t file_rank;
    uint64_t stream_id;
    size_t name_length;
    size_t name_sent_length;
    FILE* F;
    size_t bytes_received;
    unsigned int is_name_sent : 1;
    unsigned int is_file_open : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} sample_client_stream_ctx_t;

typedef struct st_sample_client_ctx_t {
    char const* default_dir;
    char const** file_names;
    sample_client_stream_ctx_t* first_stream;
    sample_client_stream_ctx_t* last_stream;
    int nb_files;
    int is_disconnected;
} sample_client_ctx_t;

static int sample_client_create_stream(picoquic_cnx_t* cnx,
    sample_client_ctx_t* client_ctx, int file_rank)
{
    int ret = 0;
    sample_client_stream_ctx_t* stream_ctx = (sample_client_stream_ctx_t*)
        malloc(sizeof(sample_client_stream_ctx_t));

    if (stream_ctx == NULL) {
        fprintf(stdout, "Memory Error, cannot create stream for file number %d\n", (int)file_rank);
        ret = -1;
    }
    else {
        memset(stream_ctx, 0, sizeof(sample_client_stream_ctx_t));
        if (client_ctx->first_stream == NULL) {
            client_ctx->first_stream = stream_ctx;
            client_ctx->last_stream = stream_ctx;
        }
        else {
            client_ctx->last_stream->next_stream = stream_ctx;
            client_ctx->last_stream = stream_ctx;
        }
        stream_ctx->file_rank = file_rank;
        stream_ctx->stream_id = (uint64_t)4 * file_rank;
        stream_ctx->name_length = strlen(client_ctx->file_names[file_rank]);

        /* Mark the stream as active. The callback will be asked to provide data when 
         * the connection is ready. */
        ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
        if (ret != 0) {
            fprintf(stdout, "Error %d, cannot initialize stream for file number %d\n", ret, (int)file_rank);
        }
    }

    return ret;
}

static void sample_client_free_context(sample_client_ctx_t* client_ctx)
{
    sample_client_stream_ctx_t* stream_ctx;

    while ((stream_ctx = client_ctx->first_stream) != NULL) {
        client_ctx->first_stream = stream_ctx->next_stream;
        if (stream_ctx->F != NULL) {
            (void)picoquic_file_close(stream_ctx->F);
        }
        free(stream_ctx);
    }
    client_ctx->last_stream = NULL;
}


int sample_client_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    sample_client_ctx_t* ctx = (sample_client_ctx_t*)callback_ctx;
    sample_client_stream_ctx_t* stream_ctx = (sample_client_stream_ctx_t*)v_stream_ctx;

    if (callback_ctx == NULL) {
        /* This should never happen, because the callback context for the client is initialized 
         * when creating the client connection. */
        return -1;
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            break;
        case picoquic_callback_stream_reset: /* Server reset stream #x */
        case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
            /* Mark stream as abandoned, close the file, etc. */
            picoquic_reset_stream(cnx, stream_id, 0);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            /* Delete the server application context */
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The server should never receive a version negotiation response */
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_prepare_to_send:
            /* Active sending API */
            /* ret = h3zero_client_callback_prepare_to_send(cnx, stream_id, stream_ctx, (void*)bytes, length, ctx); */
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what the sample expects */
            break;
        default:
            /* unexpected -- just ignore. */
            break;
        }
    }

    return ret;
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

int sample_client(char const * server_name, int server_port, char const * default_dir, 
    int nb_files, char const ** file_names)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    char const* sni = PICOQUIC_SAMPLE_SNI;
    SOCKET_TYPE fd = INVALID_SOCKET;
    picoquic_quic_t* quic = NULL;
    char const* ticket_store_filename = "sample_ticket_store.bin";
    char const* token_store_filename = "sample_token_store.bin";
    char const* binlog_filename = "sample_client_log.bin";
    sample_client_ctx_t client_ctx = { 0 };
    picoquic_cnx_t* cnx = NULL;
    uint8_t recv_buffer[1536];
    int recv_length = 0;
    uint8_t send_buffer[1536];
    size_t send_length = 0;
    uint64_t current_time = picoquic_current_time();
    int64_t delay_max = 10000000;

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

    /* Open a UDP socket */
    if (ret == 0) {
        fd = picoquic_open_client_socket(server_address.ss_family);
        if (fd == INVALID_SOCKET) {
            fprintf(stderr, "Cannot open a client socket");
            ret = -1;
        }
    }

    /* Create a QUIC context. It could be used for many connections, but in this sample we
     * will use it for just one connection. 
     * The sample code exercises just a small subset of the QUIC context configuration options:
     * - use files to store tickets and tokens in order to manage retry and 0-RTT
     * - set the congestion control algorithm to BBR
     * - enable logging of encryption keys for wireshark debugging.
     * - instantiate a binary log option, and log all packets.
     */
    if (ret == 0) {
        quic = picoquic_create(1, NULL, NULL, NULL, PICOQUIC_SAMPLE_ALPN, sample_client_callback, NULL,
            NULL, NULL, NULL, current_time, NULL,
            ticket_store_filename, NULL, 0);
        ret = -1;

        if (quic == NULL) {
            ret = -1;
        }
        else {
            if (picoquic_load_retry_tokens(quic, token_store_filename) != 0) {
                fprintf(stderr, "Could not load tokens from <%s>.\n", token_store_filename);
            }

            picoquic_set_default_congestion_algorithm(quic, picoquic_bbr_algorithm);

            picoquic_set_key_log_file_from_env(quic);
            picoquic_set_binlog(quic, binlog_filename);
            picoquic_set_log_level(quic, 1);
        }
    }

    /* Initialize the callback context and create the connection context.
     * We use minimal options on the client side, keeping the transport
     * parameter values set by default for picoquic. This could be fixed later.
     */
    if (ret == 0) {
        client_ctx.default_dir = default_dir;
        client_ctx.file_names = file_names;
        client_ctx.nb_files = nb_files;

        /* Create a client connection */
        cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*) & server_address, current_time, 0, sni, PICOQUIC_SAMPLE_ALPN, 1);

        if (cnx == NULL) {
            ret = -1;
        }
        else {
            /* Client connection parameters could be set here, before starting the connection. */
            ret = picoquic_start_client_cnx(cnx);
        }

        /* Create a stream context for all the files that should be downloaded */
        for (int i = 0; i < client_ctx.nb_files; i++) {
            ret = sample_client_create_stream(cnx, &client_ctx, i);
        }
    }

    /* Run a loop until the client connection finishes, either because it broke or
     * because all the files are donloaded */
    while (ret == 0 && !client_ctx.is_disconnected) {
        int64_t delta_t;
        int from_length;
        int to_length;
        struct sockaddr_storage peer_addr;
        struct sockaddr_storage local_addr;
        unsigned long if_index = 0;
        unsigned char received_ecn;
        picoquic_connection_id_t log_cid;
        int sock_ret = 0;
        int sock_err = 0;

        /* Compute how long to wait until the next packet can be sent. */
        delta_t = picoquic_get_next_wake_delay(quic, current_time, delay_max);

        /* Check whether packets arrive before delta_t */
        recv_length = picoquic_select(&fd, 1,
            &peer_addr, &from_length,
            &local_addr, &to_length, &if_index, &received_ecn,
            recv_buffer, sizeof(recv_buffer),
            delta_t, &current_time);

        if (recv_length < 0) {
            fprintf(stderr, "Could not receive packets on socket");
            ret = -1;
        }
        else {
            uint64_t loop_time = current_time;

            if (recv_length > 0) {
                /* Submit the packet to the server */
                (void)picoquic_incoming_packet(quic, recv_buffer,
                    (size_t)recv_length, (struct sockaddr*) & peer_addr,
                    (struct sockaddr*) & local_addr, if_index, received_ecn,
                    current_time);
            }
            else {
                /* No incoming packet, so check whether there is something to send */
                ret = picoquic_prepare_next_packet(quic, picoquic_current_time(),
                    send_buffer, sizeof(send_buffer), &send_length,
                    &peer_addr, &local_addr, &if_index, &log_cid);

                if (ret == 0 && send_length > 0) {
                    /* Send the packet that was just prepared */
                    sock_ret = picoquic_send_through_socket(fd,
                        (struct sockaddr*) & peer_addr, (struct sockaddr*) & local_addr, if_index,
                        (const char*)send_buffer, (int)send_length, &sock_err);
                    if (sock_ret <= 0) {
                        picoquic_log_app_message(quic, &log_cid, "Could not send message to AF_to=%d, AF_from=%d, ret=%d, err=%d",
                            peer_addr.ss_family, local_addr.ss_family, sock_ret, sock_err);
                    }
                }
            }
        }
    }

    /* Done. At this stage, we could print out statistics, etc. */


    /* Free the QUIC context */
    if (quic != NULL) {
        picoquic_free(quic);
    }

    /* Free the Client context */
    sample_client_free_context(&client_ctx);

    return 0;
}