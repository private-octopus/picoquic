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

/* The "multicast" project builds a simple file transfer program that can be
 * instantiated in client or server mode. The "multicast_client" implements
 * the client components of the multicast application.
 *
 * Developing the client requires two main components:
 *  - the client "callback" that implements the client side of the
 *    application protocol, managing the client side application context
 *    for the connection.
 *  - the client loop, that reads messages on the socket, submits them
 *    to the Quic context, let the client prepare messages, and send
 *    them on the appropriate socket.
 *
 * The Multicast Client uses the "qlog" option to produce Quic Logs as defined
 * in https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/.
 * This is an optional feature, which requires linking with the "loglib" library,
 * and using the picoquic_set_qlog() API defined in "autoqlog.h". When a connection
 * completes, the code saves the log as a file named after the Initial Connection
 * ID (in hexa), with the suffix ".client.qlog".
 */

#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include "picoquic_internal.h"
#include <picoquic_utils.h>
#include <picosocks.h>
#include <autoqlog.h>
#include <picoquic_packet_loop.h>
#include "picoquic_multicast.h"

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

typedef struct st_multicast_client_stream_ctx_t
{
    struct st_multicast_client_stream_ctx_t *next_stream;
    size_t file_rank;
    uint64_t stream_id;
    size_t name_length;
    size_t name_sent_length;
    FILE *F;
    size_t bytes_received;
    uint64_t remote_error;
    unsigned int is_name_sent : 1;
    unsigned int is_file_open : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} multicast_client_stream_ctx_t;

typedef struct st_multicast_client_ctx_t
{
    picoquic_cnx_t *cnx;
    char const *default_dir;
    char const *saved_alpn;
    char const **file_names;
    multicast_client_stream_ctx_t *first_stream;
    multicast_client_stream_ctx_t *last_stream;
    struct sockaddr_storage server_address;
    struct sockaddr_storage multicast_group_address;
    int notified_ready;
    int nb_files;
    int nb_files_received;
    int nb_files_failed;
    int is_disconnected;
    int multipath_allowed;
    int multipath_initiated;
    int multipath_state;
    int multipath_probe_done;
    uint16_t second_path_unique_id;
    uint16_t local_port;
    uint16_t alt_port;
} multicast_client_ctx_t;

static int multicast_client_create_stream(picoquic_cnx_t *cnx,
                                          multicast_client_ctx_t *client_ctx, int file_rank)
{
    int ret = 0;
    multicast_client_stream_ctx_t *stream_ctx = (multicast_client_stream_ctx_t *)
        malloc(sizeof(multicast_client_stream_ctx_t));

    if (stream_ctx == NULL)
    {
        fprintf(stdout, "crstr: Memory Error, cannot create stream for file number %d\n", (int)file_rank);
        ret = -1;
    }
    else
    {
        memset(stream_ctx, 0, sizeof(multicast_client_stream_ctx_t));
        if (client_ctx->first_stream == NULL)
        {
            client_ctx->first_stream = stream_ctx;
            client_ctx->last_stream = stream_ctx;
        }
        else
        {
            client_ctx->last_stream->next_stream = stream_ctx;
            client_ctx->last_stream = stream_ctx;
        }
        stream_ctx->file_rank = file_rank;
        stream_ctx->stream_id = picoquic_get_next_local_stream_id(client_ctx->cnx, 0);
        stream_ctx->name_length = strlen(client_ctx->file_names[file_rank]);

        /* Mark the stream as active. The callback will be asked to provide data when
         * the connection is ready. */
        ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
        if (ret != 0)
        {
            fprintf(stdout, "crstr: Error %d, cannot initialize stream for file number %d\n", ret, (int)file_rank);
        }
        else
        {
            picoquic_set_stream_path_affinity(cnx, stream_ctx->stream_id, client_ctx->second_path_unique_id);
            printf("crstr: Opened stream %d for file %s\n", 4 * file_rank, client_ctx->file_names[file_rank]);
        }
    }

    return ret;
}

static void multicast_client_report(multicast_client_ctx_t *client_ctx)
{
    multicast_client_stream_ctx_t *stream_ctx = client_ctx->first_stream;

    while (stream_ctx != NULL)
    {
        char const *status;
        if (stream_ctx->is_stream_finished)
        {
            status = "complete";
        }
        else if (stream_ctx->is_stream_reset)
        {
            status = "reset";
        }
        else
        {
            status = "unknown status";
        }
        printf("%s: %s, received %zu bytes", client_ctx->file_names[stream_ctx->file_rank], status, stream_ctx->bytes_received);
        if (stream_ctx->is_stream_reset && stream_ctx->remote_error != PICOQUIC_MULTICAST_NO_ERROR)
        {
            char const *error_text = "unknown error";
            switch (stream_ctx->remote_error)
            {
            case PICOQUIC_MULTICAST_INTERNAL_ERROR:
                error_text = "internal error";
                break;
            case PICOQUIC_MULTICAST_NAME_TOO_LONG_ERROR:
                error_text = "internal error";
                break;
            case PICOQUIC_MULTICAST_NO_SUCH_FILE_ERROR:
                error_text = "no such file";
                break;
            case PICOQUIC_MULTICAST_FILE_READ_ERROR:
                error_text = "file read error";
                break;
            case PICOQUIC_MULTICAST_FILE_CANCEL_ERROR:
                error_text = "cancelled";
                break;
            default:
                break;
            }
            printf(", error 0x%" PRIx64 " -- %s", stream_ctx->remote_error, error_text);
        }
        printf("\n");
        stream_ctx = stream_ctx->next_stream;
    }

    for (int i = 0; i < client_ctx->cnx->nb_paths; i++)
    {
        printf("Path[%d], packets sent: %" PRIu64 "\n", i,
               client_ctx->cnx->path[i]->pkt_ctx.send_sequence);
    }
}

static void multicast_client_free_context(multicast_client_ctx_t *client_ctx)
{
    multicast_client_stream_ctx_t *stream_ctx;

    while ((stream_ctx = client_ctx->first_stream) != NULL)
    {
        client_ctx->first_stream = stream_ctx->next_stream;
        if (stream_ctx->F != NULL)
        {
            (void)picoquic_file_close(stream_ctx->F);
        }
        free(stream_ctx);
    }
    client_ctx->last_stream = NULL;
}

/* Create the required additional path for testing multicast data sending */
int multicast_client_create_additional_path(picoquic_cnx_t *cnx, multicast_client_ctx_t *cb_ctx)
{
    int ret = 0;
    struct sockaddr *addr_group = NULL;
    struct sockaddr *addr_local = NULL;

    struct sockaddr_storage addr_local_storage;
    int need_to_wait = 0;

    // CHECK MC: Check if ports are correct below (currently set to zero)

    if (cb_ctx->multipath_state != 0)
    {
        fprintf(stdout, "crpth: Error while creating additional path: multipath_state is already 1\n");
        return 1;
    }

    if (picoquic_store_text_addr(&cb_ctx->multicast_group_address, PICOQUIC_MULTICAST_GROUP_IP, PICOQUIC_MULTICAST_GROUP_PORT) != 0)
    {
        fprintf(stdout, "crpth: Error while parsing PICOQUIC_MULTICAST_GROUP_IP: %s:%d\n", PICOQUIC_MULTICAST_GROUP_IP, PICOQUIC_MULTICAST_GROUP_PORT);
        return 1;
    }

    picoquic_store_addr(&addr_local_storage, (struct sockaddr *)&cb_ctx->cnx->path[0]->local_addr);
    if (addr_local_storage.ss_family == AF_INET6)
    {
        ((struct sockaddr_in6 *)&addr_local_storage)->sin6_port = htons(cb_ctx->alt_port);
    }
    else
    {
        ((struct sockaddr_in *)&addr_local_storage)->sin_port = htons(cb_ctx->alt_port);
    }

    addr_group = (struct sockaddr *)&cb_ctx->multicast_group_address;
    addr_local = (struct sockaddr *)&addr_local_storage;

    // TODO MC: Rewrite this to join the multicast group instead of just creating an additional path to the multicast source IP

    cb_ctx->multipath_state = 1; /* Unless we detect a transient error, mark this path as tried */
    if ((ret = picoquic_probe_new_path_ex(cb_ctx->cnx, (struct sockaddr *)&cb_ctx->server_address,
                                          addr_local, 0, picoquic_get_quic_time(picoquic_get_quic_ctx(cnx)), 0)) != 0)
    {
        /* Check whether the code returned a transient error */
        if (ret == PICOQUIC_ERROR_PATH_ID_BLOCKED ||
            ret == PICOQUIC_ERROR_PATH_CID_BLOCKED ||
            ret == PICOQUIC_ERROR_PATH_NOT_READY)
        {
            cb_ctx->multipath_state = 0; /* oops, not ready yet, need to keep looping */
            need_to_wait = 1;
            ret = 0;
        }
        else
        {
            fprintf(stdout, "crpth: Probe new path failed with exit code %d\n", ret);
        }
    }
    else
    {
        fprintf(stdout, "crpth: New path added, total paths available: %d\n", cb_ctx->cnx->nb_paths);
    }

    if (!need_to_wait)
    {
        cb_ctx->multipath_probe_done = 1;
    }

    return ret;
}

int multicast_client_callback(picoquic_cnx_t *cnx,
                              uint64_t stream_id, uint8_t *bytes, size_t length,
                              picoquic_call_back_event_t fin_or_event, void *callback_ctx, void *v_stream_ctx)
{
    int ret = 0;
    multicast_client_ctx_t *client_ctx = (multicast_client_ctx_t *)callback_ctx;
    multicast_client_stream_ctx_t *stream_ctx = (multicast_client_stream_ctx_t *)v_stream_ctx;

    if (client_ctx == NULL)
    {
        /* This should never happen, because the callback context for the client is initialized
         * when creating the client connection. */
        return -1;
    }

    if (ret == 0)
    {
        switch (fin_or_event)
        {
        // CHECK MC: Maybe set flag here to react to in the other callback
        case picoquic_callback_path_available:
            client_ctx->second_path_unique_id = stream_id; /* stream id is used as unique path id here */

            fprintf(stdout, "app: NEW PATH AVAILABLE, total number of paths: %i", cnx->nb_paths);
            fprintf(stdout, ", unique path id: %i\n", client_ctx->second_path_unique_id);

            /* Create a stream context for all the files that should be downloaded */
            for (int i = 0; ret == 0 && i < client_ctx->nb_files; i++)
            {
                ret = multicast_client_create_stream(cnx, client_ctx, i);
                if (ret < 0)
                {
                    fprintf(stderr, "client: Could not initiate stream for file %s\n", client_ctx->file_names[i]);
                }
            }

            break;
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            if (stream_ctx == NULL)
            {
                /* This is unexpected, as all contexts were declared when initializing the
                 * connection. */
                return -1;
            }
            else if (!stream_ctx->is_name_sent)
            {
                /* Unexpected: should not receive data before sending the file name to the server */
                return -1;
            }
            else if (stream_ctx->is_stream_reset || stream_ctx->is_stream_finished)
            {
                /* Unexpected: receive after fin */
                return -1;
            }
            else
            {
                if (stream_ctx->F == NULL)
                {
                    /* Open the file to receive the data. This is done at the last possible moment,
                     * to minimize the number of files open simultaneously.
                     * When formatting the file_path, verify that the directory name is zero-length,
                     * or terminated by a proper file separator.
                     */
                    char file_path[1024];
                    size_t dir_len = strlen(client_ctx->default_dir);
                    size_t file_name_len = strlen(client_ctx->file_names[stream_ctx->file_rank]);

                    if (dir_len > 0 && dir_len < sizeof(file_path))
                    {
                        memcpy(file_path, client_ctx->default_dir, dir_len);
                        if (file_path[dir_len - 1] != PICOQUIC_FILE_SEPARATOR[0])
                        {
                            file_path[dir_len] = PICOQUIC_FILE_SEPARATOR[0];
                            dir_len++;
                        }
                    }

                    if (dir_len + file_name_len + 1 >= sizeof(file_path))
                    {
                        /* Unexpected: could not format the file name */
                        fprintf(stderr, "app: Could not format the file path.\n");
                        ret = -1;
                    }
                    else
                    {
                        memcpy(file_path + dir_len, client_ctx->file_names[stream_ctx->file_rank],
                               file_name_len);
                        file_path[dir_len + file_name_len] = 0;
                        stream_ctx->F = picoquic_file_open(file_path, "wb");

                        if (stream_ctx->F == NULL)
                        {
                            /* Could not open the file */
                            fprintf(stderr, "app: Could not open the file: %s\n", file_path);
                            ret = -1;
                        }
                    }
                }

                if (ret == 0 && length > 0)
                {
                    /* write the received bytes to the file */
                    if (fwrite(bytes, length, 1, stream_ctx->F) != 1)
                    {
                        /* Could not write file to disk */
                        fprintf(stderr, "app: Could not write data to disk.\n");
                        ret = -1;
                    }
                    else
                    {
                        stream_ctx->bytes_received += length;
                    }
                }

                if (ret == 0 && fin_or_event == picoquic_callback_stream_fin)
                {
                    stream_ctx->F = picoquic_file_close(stream_ctx->F);
                    stream_ctx->is_stream_finished = 1;
                    client_ctx->nb_files_received++;

                    if ((client_ctx->nb_files_received + client_ctx->nb_files_failed) >= client_ctx->nb_files)
                    {
                        /* everything is done, close the connection */
                        ret = picoquic_close(cnx, 0);
                    }
                }
            }
            break;
        case picoquic_callback_stop_sending: /* Should not happen, treated as reset */
            /* Mark stream as abandoned, close the file, etc. */
            picoquic_reset_stream(cnx, stream_id, 0);
            /* Fall through */
        case picoquic_callback_stream_reset: /* Server reset stream #x */
            if (stream_ctx == NULL)
            {
                /* This is unexpected, as all contexts were declared when initializing the
                 * connection. */
                return -1;
            }
            else if (stream_ctx->is_stream_reset || stream_ctx->is_stream_finished)
            {
                /* Unexpected: receive after fin */
                return -1;
            }
            else
            {
                stream_ctx->remote_error = picoquic_get_remote_stream_error(cnx, stream_id);
                stream_ctx->is_stream_reset = 1;
                client_ctx->nb_files_failed++;

                if ((client_ctx->nb_files_received + client_ctx->nb_files_failed) >= client_ctx->nb_files)
                {
                    /* everything is done, close the connection */
                    fprintf(stdout, "app: All done, closing the connection.\n");
                    ret = picoquic_close(cnx, 0);
                }
            }
            break;
        case picoquic_callback_stateless_reset:
            fprintf(stdout, "app: Received a stateless reset.\n");
            break;
        case picoquic_callback_close:
            fprintf(stdout, "app: Received request to close connection\n");
            client_ctx->is_disconnected = 1;
            break;
        case picoquic_callback_application_close:
            fprintf(stdout, "app: Received request to close application.\n");
            /* Mark the connection as completed */
            client_ctx->is_disconnected = 1;
            /* Remove the application callback */
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            /* The client did not get the right version.
             * TODO: some form of negotiation?
             */
            fprintf(stdout, "app: Received a version negotiation request:");
            for (size_t byte_index = 0; byte_index + 4 <= length; byte_index += 4)
            {
                uint32_t vn = 0;
                for (int i = 0; i < 4; i++)
                {
                    vn <<= 8;
                    vn += bytes[byte_index + i];
                }
                fprintf(stdout, "%s%08x", (byte_index == 0) ? " " : ", ", vn);
            }
            fprintf(stdout, "\n");
            break;
        case picoquic_callback_stream_gap:
            /* This callback is never used. */
            break;
        case picoquic_callback_prepare_to_send:
            // CALLED ONCE PER STREAM (FILE)
            /* Active sending API */

            if (stream_ctx == NULL)
            {
                /* Decidedly unexpected */
                return -1;
            }
            else if (stream_ctx->name_sent_length < stream_ctx->name_length)
            {
                uint8_t *buffer;
                size_t available = stream_ctx->name_length - stream_ctx->name_sent_length;
                int is_fin = 1;

                /* The length parameter marks the space available in the packet */
                if (available > length)
                {
                    available = length;
                    is_fin = 0;
                }
                /* Needs to retrieve a pointer to the actual buffer
                 * the "bytes" parameter points to the sending context
                 */
                buffer = picoquic_provide_stream_data_buffer(bytes, available, is_fin, !is_fin);
                if (buffer != NULL)
                {
                    char const *filename = client_ctx->file_names[stream_ctx->file_rank];
                    memcpy(buffer, filename + stream_ctx->name_sent_length, available);
                    stream_ctx->name_sent_length += available;
                    stream_ctx->is_name_sent = is_fin;
                }
                else
                {
                    fprintf(stderr, "\napp: Error, coulfd not get data buffer.\n");
                    ret = -1;
                }
            }
            else
            {
                /* Nothing to send, just return */
            }
            break;
        case picoquic_callback_almost_ready:
            fprintf(stdout, "app: Connection to the server completed, almost ready.\n");
            break;
        case picoquic_callback_ready:
            /* TODO: Check that the transport parameters are what the multicast expects */
            fprintf(stdout, "app: Connection to the server confirmed.\n");

            break;
        default:
            /* unexpected -- just ignore. */
            break;
        }
    }

    return ret;
}

/* Multicast client,  loop call back management.
 * The function "picoquic_packet_loop" will call back the application when it is ready to
 * receive or send packets, after receiving a packet, and after sending a packet.
 * We implement here a minimal callback that instruct "picoquic_packet_loop" to exit
 * when the connection is complete.
 */

static int multicast_client_loop_cb(picoquic_quic_t *quic, picoquic_packet_loop_cb_enum cb_mode,
                                    void *callback_ctx, void *callback_arg)
{
    int ret = 0;
    multicast_client_ctx_t *cb_ctx = (multicast_client_ctx_t *)callback_ctx;

    if (cb_ctx == NULL)
    {
        ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
    }
    else
    {
        switch (cb_mode)
        {
        case picoquic_packet_loop_ready:
            picoquic_packet_loop_options_t *options = (picoquic_packet_loop_options_t *)callback_arg;
            options->provide_alt_port = 1;
            fprintf(stdout, "netloop: Waiting for packets.\n");
            break;
        case picoquic_packet_loop_after_receive:
            break;
        case picoquic_packet_loop_after_send:
            if (picoquic_get_cnx_state(cb_ctx->cnx) == picoquic_state_disconnected)
            {
                ret = PICOQUIC_NO_ERROR_TERMINATE_PACKET_LOOP;
            }
            else
            {
                // CHECK MC: The code below is adapted from picoquicdemo, currently not executed.
                // It seems that the state is never be reached
                if (picoquic_get_cnx_state(cb_ctx->cnx) == picoquic_state_client_almost_ready && cb_ctx->notified_ready == 0)
                {
                    // CHECK MC: Check if handshake check below is needed
                    /* if almost ready, display results of negotiation */
                    if (picoquic_tls_is_psk_handshake(cb_ctx->cnx))
                    {
                        fprintf(stdout, "netloop: The session was properly resumed!\n");
                        picoquic_log_app_message(cb_ctx->cnx,
                                                 "%s", "netloop: The session was properly resumed!");
                    }

                    // CHECK MC: The following is copied from picoquicdemo, check if 0-RTT should be supported
                    if (cb_ctx->cnx->zero_rtt_data_accepted)
                    {
                        fprintf(stdout, "netloop: Zero RTT data is accepted!\n");
                        picoquic_log_app_message(cb_ctx->cnx,
                                                 "%s", "netloop: Zero RTT data is accepted!");
                    }

                    if (cb_ctx->cnx->alpn != NULL)
                    {
                        fprintf(stdout, "netloop: Negotiated ALPN: %s\n", cb_ctx->cnx->alpn);
                        picoquic_log_app_message(cb_ctx->cnx,
                                                 "netloop: Negotiated ALPN: %s", cb_ctx->cnx->alpn);
                        cb_ctx->saved_alpn = picoquic_string_duplicate(cb_ctx->cnx->alpn);
                    }
                    cb_ctx->notified_ready = 1;
                }

                // CHECK MC: Check conditions here (in which state the new path will be opened?)
                if (picoquic_get_cnx_state(cb_ctx->cnx) >= picoquic_state_server_almost_ready && cb_ctx->multipath_initiated == 0)
                {
                    int is_already_allowed = 0;
                    if ((ret = picoquic_subscribe_new_path_allowed(cb_ctx->cnx, &is_already_allowed)) == 0)
                    {
                        if (is_already_allowed)
                        {
                            ret = multicast_client_create_additional_path(cb_ctx->cnx, cb_ctx);
                            if (ret == 0)
                            {
                                fprintf(stdout, "netloop: New path for multicast successfully opened with cnx_state %d\n", picoquic_get_cnx_state(cb_ctx->cnx));
                            }
                            else
                            {
                                fprintf(stdout, "netloop: Failed to open additional path with cnx_state %d\n", picoquic_get_cnx_state(cb_ctx->cnx));
                            }
                            cb_ctx->multipath_initiated = 1;
                        }
                        else
                        {
                            if (cb_ctx->cnx->is_subscribed_to_path_allowed)
                            {
                                fprintf(stdout, "netloop: Multipath not allowed: Transient error with cnx_state %d\n", picoquic_get_cnx_state(cb_ctx->cnx));
                            }
                        }
                    }
                    else
                    {
                        cb_ctx->multipath_initiated = 1;
                        fprintf(stdout, "netloop: Multipath permission check failed\n");
                    }
                }
            }

            break;
        case picoquic_packet_loop_port_update:
            break;
        case picoquic_packet_loop_alt_port:
            cb_ctx->alt_port = *((uint16_t *)callback_arg);
            fprintf(stdout, "netloop: ALT PORT SET: %i\n", cb_ctx->alt_port);
            break;
        default:
            ret = PICOQUIC_ERROR_UNEXPECTED_ERROR;
            break;
        }
    }
    return ret;
}

/* Prepare the context used by the simple client:
 * - Create the QUIC context.
 * - Open the sockets
 * - Find the server's address
 * - Initialize the client context and create a client connection.
 */
static int multicast_client_init(char const *server_name, int server_port, char const *default_dir,
                                 char const *ticket_store_filename, char const *token_store_filename,
                                 struct sockaddr_storage *server_address, picoquic_quic_t **quic, picoquic_cnx_t **cnx, multicast_client_ctx_t *client_ctx)
{
    int ret = 0;
    char const *sni = PICOQUIC_MULTICAST_SNI;
    char const *qlog_dir = PICOQUIC_MULTICAST_CLIENT_QLOG_DIR;
    uint64_t current_time = picoquic_current_time();

    *quic = NULL;
    *cnx = NULL;

    /* Get the server's address */
    if (ret == 0)
    {
        int is_name = 0;

        ret = picoquic_get_server_address(server_name, server_port, server_address, &is_name);
        if (ret != 0)
        {
            fprintf(stderr, "init: Cannot get the IP address for <%s> port <%d>", server_name, server_port);
        }
        else if (is_name)
        {
            sni = server_name;
        }
    }

    /* Create a QUIC context. It could be used for many connections, but in this multicast we
     * will use it for just one connection.
     * The multicast code exercises just a small subset of the QUIC context configuration options:
     * - use files to store tickets and tokens in order to manage retry and 0-RTT
     * - set the congestion control algorithm to BBR
     * - enable logging of encryption keys for wireshark debugging.
     * - instantiate a binary log option, and log all packets.
     */
    if (ret == 0)
    {
        *quic = picoquic_create(1, NULL, NULL, NULL, PICOQUIC_MULTICAST_ALPN, NULL, NULL,
                                NULL, NULL, NULL, current_time, NULL,
                                ticket_store_filename, NULL, 0);

        if (*quic == NULL)
        {
            fprintf(stderr, "init: Could not create quic context\n");
            ret = -1;
        }
        else
        {
            if (picoquic_load_retry_tokens(*quic, token_store_filename) != 0)
            {
                fprintf(stderr, "init: No token file present. Will create one as <%s>.\n", token_store_filename);
            }

            picoquic_set_default_congestion_algorithm(*quic, picoquic_bbr_algorithm);
            picoquic_enable_sslkeylog(*quic, 1);
            picoquic_set_key_log_file_from_env(*quic);
            picoquic_set_qlog(*quic, qlog_dir);
            picoquic_set_log_level(*quic, 1);
            picoquic_enable_path_callbacks_default(*quic, 1);

            // Always enable multicast
            picoquic_set_default_multicast_option(*quic, 1);
            picoquic_set_default_multicast_client_params(*quic, NULL);
            printf("init: Accept multicast: %s.\n", ((*quic)->default_multicast_option) ? "Yes" : "No");
        }
    }
    /* Initialize the callback context and create the connection context.
     * We use minimal options on the client side, keeping the transport
     * parameter values set by default for picoquic. This could be fixed later.
     */

    if (ret == 0)
    {
        client_ctx->default_dir = default_dir;

        printf("init: Starting connection to %s, port %d\n", server_name, server_port);

        /* Create a client connection */
        *cnx = picoquic_create_cnx(*quic, picoquic_null_connection_id, picoquic_null_connection_id,
                                   (struct sockaddr *)server_address, current_time, 0, sni, PICOQUIC_MULTICAST_ALPN, 1);

        if (*cnx == NULL)
        {
            fprintf(stderr, "init: Could not create connection context\n");
            ret = -1;
        }
        else
        {
            /* Document connection in client's context */
            client_ctx->cnx = *cnx;
            /* Set the client callback context */
            picoquic_set_callback(*cnx, multicast_client_callback, client_ctx);
            /* Client connection parameters could be set here, before starting the connection. */
            ret = picoquic_start_client_cnx(*cnx);
            if (ret < 0)
            {
                fprintf(stderr, "init: Could not activate connection\n");
            }
            else
            {
                /* Printing out the initial CID, which is used to identify log files */
                picoquic_connection_id_t icid = picoquic_get_initial_cnxid(*cnx);
                printf("init: Initial connection ID: ");
                for (uint8_t i = 0; i < icid.id_len; i++)
                {
                    printf("%02x", icid.id[i]);
                }
                printf("\n");
            }
        }
    }

    return ret;
}

/* Client:
 * - Call the init function to:
 *    - Create the QUIC context.
 *    - Open the sockets
 *    - Find the server's address
 *    - Create a client context and a client connection.
 * - Initialize the list of required files based on the CLI parameters.
 * - On a forever loop:
 *     - get the next wakeup time
 *     - wait for arrival of message on sockets until that time
 *     - if a message arrives, process it.
 *     - else, check whether there is something to send.
 *       if there is, send it.
 * - The loop breaks if the client connection is finished.
 */

int picoquic_multicast_client(char const *server_name, int server_port, char const *default_dir,
                              int nb_files, char const **file_names)
{
    int ret = 0;
    struct sockaddr_storage server_address;
    picoquic_quic_t *quic = NULL;
    picoquic_cnx_t *cnx = NULL;
    multicast_client_ctx_t client_ctx = {0};
    picoquic_packet_loop_param_t param = {0};
    char const *ticket_store_filename = PICOQUIC_MULTICAST_CLIENT_TICKET_STORE;
    char const *token_store_filename = PICOQUIC_MULTICAST_CLIENT_TOKEN_STORE;

    ret = multicast_client_init(server_name, server_port, default_dir,
                                ticket_store_filename, token_store_filename,
                                &server_address, &quic, &cnx, &client_ctx);

    if (ret == 0)
    {
        /* Initialize all the streams contexts from the list of streams passed on the API. */
        client_ctx.file_names = file_names;
        client_ctx.nb_files = nb_files;
        client_ctx.server_address = server_address;
    }

    param.local_af = server_address.ss_family;
    param.local_port = (uint16_t)picoquic_uniform_random(30000) + 20000;
    param.extra_socket_required = 1;
    param.prefer_extra_socket = 0;
    client_ctx.local_port = param.local_port;

    /* Wait for packets */
    ret = picoquic_packet_loop_v2(quic, &param, multicast_client_loop_cb, &client_ctx);

    if (ret == 0)
    {
        fprintf(stdout, "client: Enable multicast: %s.\n", (client_ctx.cnx->is_multicast_enabled) ? "Success" : "Refused");
    }

    /* Done. At this stage, we could print out statistics, etc. */
    multicast_client_report(&client_ctx);

    /* Save tickets and tokens, and free the QUIC context */
    if (quic != NULL)
    {
        if (picoquic_save_session_tickets(quic, ticket_store_filename) != 0)
        {
            fprintf(stderr, "client: Could not store the saved session tickets.\n");
        }
        if (picoquic_save_retry_tokens(quic, token_store_filename) != 0)
        {
            fprintf(stderr, "client: Could not save tokens to <%s>.\n", token_store_filename);
        }
        picoquic_free(quic);
    }

    /* Free the Client context */
    multicast_client_free_context(&client_ctx);

    return ret;
}
