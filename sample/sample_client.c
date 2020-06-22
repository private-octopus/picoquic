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
    uint64_t stream_id;
    FILE* F;
    size_t file_rank;
    size_t name_length;
    size_t name_sent_length;
    unsigned int is_name_sent : 1;
    unsigned int is_file_open : 1;
    unsigned int is_stream_reset : 1;
    unsigned int is_stream_finished : 1;
} sample_client_stream_ctx_t;

typedef struct st_sample_client_ctx_t {
    char const* default_dir;
    char const** file_names;
    sample_client_stream_ctx_t* first_stream;
} sample_client_ctx_t;

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

int sample_client()
{
    return 0;
}