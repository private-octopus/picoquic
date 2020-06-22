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
 * instantiated in client or server mode. The "sample_server" implements
 * the server components of the sample application. 
 *
 * Developing the server requires two main components:
 *  - the server "callback" that implements the server side of the
 *    application protocol, managing a server side application context
 *    for each connection.
 *  - the server loop, that reads messages on the socket, submits them
 *    to the Quic context, let the server prepare messages, and send
 *    them on the appropriate socket.
 */


#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>

/* Server context and callback management:
 *
 * The server side application context is created for each new connection,
 * and is freed when the connection is closed. It contains a list of
 * server side stream contexts, one for each stream open on the
 * connection. Each stream context includes:
 *  - description of the stream state:
 *      name_read or not, FILE open or not, stream reset or not,
 *      stream finished or not.
 *  - the number of file name bytes already read.
 *  - the name of the file requested by the client.
 *  - the FILE pointer for reading the data.
 * Server side stream context is created when the client starts the
 * stream. It is closed when the file transmission
 * is finished, or when the stream is abandoned.
 *
 * The server side callback is a large switch statement, with one entry
 * for each of the call back events.
 */

typedef struct st_sample_server_stream_ctx_t {
    struct st_sample_server_stream_ctx_t* next_stream;
    uint64_t stream_id;
    FILE* F;
    uint8_t file_name[256];
    size_t name_length;
    unsigned int is_name_read : 1;
    unsigned int is_file_open : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} sample_server_stream_ctx_t;

typedef struct st_sample_server_ctx_t {
    char const* default_dir;
    sample_server_stream_ctx_t* first_stream;
} sample_server_ctx_t;

int sample_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    sample_server_ctx_t* ctx = (sample_server_ctx_t*)callback_ctx;
    sample_server_stream_ctx_t* stream_ctx = (sample_server_stream_ctx_t*)v_stream_ctx;

    /* If this is the first reference to the connection, the application context is set
     * to the default value defined for the server. This default value contains the pointer
     * to the file directory in which all files are defined.
     */
    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        ctx = (sample_server_ctx_t *)malloc(sizeof(sample_server_ctx_t));
        if (ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else {
            sample_server_ctx_t* d_ctx = (sample_server_ctx_t*)picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx));
            if (d_ctx != NULL) {
                memcpy(ctx, d_ctx, sizeof(sample_server_ctx_t));
            }
            else {
                /* This really is an error case: the default connection context should never be NULL */
                memset(ctx, 0, sizeof(sample_server_ctx_t));
                ctx->default_dir = "";
            }
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
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
            /*ret = h3zero_server_callback_prepare_to_send(cnx, stream_id, stream_ctx, (void*)bytes, length, ctx);*/
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what the sample expects */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

/* Server loop setup:
 * - Create the QUIC context.
 * - Open the sockets
 * - On a forever loop:
 *     - get the next wakeup time
 *     - wait for arrival of message on sockets until that time
 *     - if a message arrives, process it.
 *     - else, check whether there is something to send.
 *       if there is, send it.
 * - The loop breaks if the socket return an error. 
 */

int sample_server()
{
    return 0;
}