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

#include "picoquic_internal.h"
#include "tls_api.h"
#include "picoquictest_internal.h"
#ifdef _WINDOWS
#include "wincompat.h"
#else
#include <signal.h>
#endif
#include <picotls.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>

/* TODO: do we really need global variables? */
uint64_t cnx_stress_test_duration = 120000000; /* Default to 4 minutes */
size_t cnx_stress_nb_clients = 1000; /* Default to 1000 clients */
uint64_t stress_random_ctx = 0xBabaC001BaddBab1ull;
uint32_t cnx_stress_max_message_before_drop = 25;
uint32_t cnx_stress_max_message_before_migrate = 8;

typedef struct st_cnx_stress_stream_ctx_t {
    /* For receive streams, just look at the first 16 bytes,
     * ignore the following until everything is received 
     * For send streams, send the first bytes, followed by
     * random or fixed data up to message size. */
    uint64_t stream_id;
    uint64_t send_time;
    uint64_t nb_bytes_expected;
    size_t nb_bytes_received;
    size_t nb_bytes_sent;
} cnx_stress_stream_ctx_t;

typedef struct st_cnx_stress_cnx_callback_ctx_t {
    struct st_cnx_stress_ctx_t* stress_ctx;
    picoquic_cnx_t* cnx;
    uint64_t next_steam_send;
    cnx_stress_stream_ctx_t* active_stream;
} cnx_stress_cnx_callback_ctx_t;

typedef enum {
    cnx_stress_event_none(0),
    cnx_stress_event_new_message,
    cnx_stress_event_client_creation,
    cnx_stress_event_client_arrival,
    cnx_stress_event_client_prepare,
    cnx_stress_event_server_arrival,
    cnx_stress_event_server_prepare
} cnx_stress_event_enum;

typedef struct st_cnx_stress_ctx_t {
    uint64_t simulated_time;
    picoquic_quic_t* qserver;
    picoquic_quic_t* qclient;
    struct sockaddr_in server_addr;
    struct sockaddr_in client_addr;
    int nb_clients;
    int nb_servers;
    int nb_client_target;
    uint64_t client_creation_interval;
    uint64_t next_client_creation_time;
    uint64_t client_deletion_interval;
    uint64_t next_client_deletion_time;
    uint64_t message_creation_interval;
    uint64_t message_creation_interval;
    /* The array of client and server contexts are created with size "nb_client target"
     * during the initialization of the test. The variables nb_clients and nb_servers
     * hold the number of clients and servers actually created. */
    cnx_stress_client_t * c_ctx;
    cnx_stress_server_t* c_ctx;
} cnx_stress_ctx_t;

/*
 * Portable abort call, should work on Linux and Windows.
 * We deliberately do not call the ASSERT macros, becuse these
 * macros can be made no-op if compiled with NDEBUG
 */

static int stress_debug_break(int break_if_fuzzing)
{
    if (picoquic_fuzz_in_progress == 0 || break_if_fuzzing) {
#ifdef _WINDOWS
        DebugBreak();
#else
        raise(SIGTRAP);
#endif
        return -1;
    }

    return 0;
}


/* Callback context and protocol handling.
 * Nothing really special here? For message sending, assume short messages,
 * just use the write and forget API. For message receiving, process to
 * parse the message protocol in real time.
 * Stream context for receive: created when first data arrives on the stream.
 * Context accumulate the message ID from the first 8 bytes, then ignores the
 * rest of the data.
 */
cnx_stress_cnx_ctx_t* cnx_stress_callback_create_context(cnx_stress_ctx_t stress_ctx,
    picoquic_cnx_t* cnx) {
    cnx_stress_cnx_ctx_t* cnx_ctx = (cnx_stress_cnx_ctx_t*)malloc(sizeof(cnx_stress_cnx_ctx_t));
    if (cnx_ctx != NULL) {
        memset(cnx_ctx, 0, sizeof(cnx_stress_cnx_ctx_t));
        cnx_ctx->stress_ctx = stress_ctx;
        cnx_ctx->cnx = cnx;
    }
    return cnx_ctx;
}

int cnx_stress_callback_data(cnx_stress_cnx_ctx_t* cnx_ctx,
    cnx_stress_stream_ctx_t* stream_ctx, uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event)
{
    /* If this is the first reference to the stream, create a context */

    /* Handle arrival of data on the stream: decode stream header if not yet received. */

    /* If FIN received: if not enough data, record an error. Else,
     * accumulate the statistics. */

}

int cnx_stress_callback_prepare_to_send(cnx_stress_cnx_ctx_t* cnx_ctx,
    cnx_stress_stream_ctx_t* stream_ctx, uint64_t stream_id, stream_id,
    uint8_t* bytes, size_t length)
{
    /* If the first 16 bytes have not been sent yet, send them */
    /* Fill the reminder with data */
    /* Handle end of stream */
}

int cnx_stress_initiate_message(cnx_stress_cnx_ctx_t* cnx_ctx,
    uint64_t nb_bytes_expected)
{
    /* Create a stream context. */
    /* Initialize an active stream. */
}

int cnx_stress_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    cnx_stress_cnx_ctx_t* cnx_ctx = (cnx_stress_cnx_ctx_t*)callback_ctx;
    cnx_stress_stream_ctx_t* stream_ctx = (cnx_stress_stream_ctx_t*)v_stream_ctx;

    if (cnx_ctx == NULL) {
        /* Unexpected error: for the clients the contexts are created by the
         * application before starting the connection. For the server, the
         * connections are created with a default context */
        picoquic_close(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
        return -1;
    }
    else if (cnx_ctx->cnx == NULL) {
        /* In the case of server connections, the connection is NULL for the
         * default context. It should be initialized with a proper context */
        cnx_ctx = cnx_stress_callback_create_context(cnx_ctx->cnx_stress_ctx, cnx);
        if (cnx_ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
            return -1;
        }
        else {
            picoquic_set_callback(cnx, cnx_stress_callback, cnx_ctx);
        }
    }

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* Data arrival on stream #x, maybe with fin mark */
        ret = cnx_stress_callback_data(cnx, stream_ctx, stream_id, bytes, length, fin_or_event, cnx_ctx);
        break;
    case picoquic_callback_stream_reset: /* Client reset stream #x */
    case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
        /* TODO: probably no need for this in the test application. */
        break;
    case picoquic_callback_stateless_reset:
    case picoquic_callback_close: /* Received connection close */
    case picoquic_callback_application_close: /* Received application close */
        cnx_stress_callback_delete_context(cnx_ctx);
        picoquic_set_callback(cnx, NULL, NULL);
        break;
    case picoquic_callback_stream_gap:
        /* Gap indication, when unreliable streams are supported */
        /* Should trigger a failure */
        break;
    case picoquic_callback_prepare_to_send:
        ret = cnx_stress_callback_prepare_to_send(cnx, stream_id, stream_ctx, (void*)bytes, length, cnx_ctx);
        break;
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        /* Check that the transport parameters are what DoQ expects */
        if (cnx_stress_check_tp(cnx_ctx, cnx) != 0) {
            (void)picoquic_close(cnx, cnx_stress_ERROR_PROTOCOL);
        }
        break;
    case picoquic_callback_datagram:/* No datagram support in DoQ */
        break;
    case picoquic_callback_version_negotiation:
        break;
    case picoquic_callback_request_alpn_list: /* Provide the list of supported ALPN */
    case picoquic_callback_set_alpn: /* Set ALPN to negotiated value */
        break;
    default:
        /* unexpected */
        break;
    }

    return ret;
}

/* Handling of data messages.
 * The simulation generates messages at specified intervals, in turn from
 * the server and from the client. For each message, the simulation
 * picks a target connection from the connections already established.
 * This requires being able to select a connection context at random
 * from those established on the client side or the server side.
 * We need a structure for that, so we can retrieve the connection context,
 * with the following constraints:
 * 1) Light weigth
 * 2) Synchronized with creation and deletion of contexts at clients or server.
 * The synchronization will be achieved through the per connection callback
 * mechanism. The callback context holds the index of the connection in the
 * array. It is initialized on the client side when the connection is
 * created, and on the server side when the connection context is created.
 * It is deleted and the pointer set to null when the "end of connection"
 * callback is received.
 * We need to monitor the transmission delay of messages, in simulation time.
 * For that, we encode the sending time in the message, and retrieve it when
 * the message is received.
 * Each message is sent on its own one-way stream, delineated by the end of
 * stream mechanism. The connection parameters set these "allowed stream"
 * parameters to a large enough value to not cause flow control issues.
 * To do: should we keep an array of message departure and arrival times for
 * fine grain statistics, is it enough to compute min, max, average and stdev?
 */

/* Loop -- manage arrival of clients, traffic, messages, etc. */
int cnx_stress_loop_step(cnx_stress_ctx_t * stress_ctx)
{
    cnx_stress_event_enum next_event = cnx_stress_event_none;
    uint64_t next_time = UINT64_MAX;

    /* Is it time to inject a new connection? */
    /* Is it time to delete a connection? */
    /* Is it time to inject a message ? */
    /* Is it time for client message arrival? */
    /* Is it time for client message preparation? */
    /* Is it time for server message arrival? */
    /* Is it time for server message preparation? */
    /* Update the simulation time based on next time */
    /* Execute the selected action */
}

/* Connection stress:
 *
 *  Create a QUIC context for the server
 *  Create a QUIC context for the client
 *  Create simulated links from client to server and vice-versa
 *  In a loop, until the desired number of connections is obtained
 *      Create a new connection on the client
 *      Queue a first message on that client connection
 *      Run the simulated send/receive loop for a small number of iterations
 *   Once all clients are created
 *       Run the simulation until the desired time interval has passed
 *  In a loop, close each of the connections
 *
 * All that while getting statistics on:
 *
 *   The simulated connection establishment delays
 *   The simulated message delays from injection to delivery
 *   Whether undesirable events occur, e.g., loss of connections
 *   The "real time" required to run the test for the simulated time
 *
 */

static const uint8_t cnx_stress_ticket_encrypt_key[32] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
};


int cnx_stress_create_cnx()
{

}

static void stress_delete_client_context(int client_index, cnx_stress_ctx_t * stress_ctx)
{
    cnx_stress_client_t * ctx = stress_ctx->c_ctx[client_index];
    cnx_stress_cnx_callback_ctx_t* cb_ctx;

    if (ctx != NULL) {
        while (ctx->qclient->cnx_list != NULL) {
            cb_ctx = (cnx_stress_cnx_callback_ctx_t*)
                picoquic_get_callback_context(ctx->qclient->cnx_list);
            free(cb_ctx);
            picoquic_set_callback(ctx->qclient->cnx_list, NULL, NULL);
            picoquic_delete_cnx(ctx->qclient->cnx_list);
        }

        if (ctx->qclient != NULL) {
            picoquic_free(ctx->qclient);
            ctx->qclient = NULL;
        }

        if (ctx->c_to_s_link != NULL) {
            picoquictest_sim_link_delete(ctx->c_to_s_link);
            ctx->c_to_s_link = NULL;
        }

        if (ctx->s_to_c_link != NULL) {
            picoquictest_sim_link_delete(ctx->s_to_c_link);
            ctx->s_to_c_link = NULL;
        }
        free(ctx);

        stress_ctx->c_ctx[client_index] = NULL;
    }
}

static int cnx_stress_test()
{
    int ret = 0;
    cnx_stress_ctx_t stress_ctx;
    double run_time_seconds = 0;
    double target_seconds = 0;
    double wall_time_seconds = 0;
    uint64_t wall_time_start = picoquic_current_time();
    uint64_t nb_connections = 0;
    uint64_t sim_time_next_log = 1000000;
    const int nb_clients = (const int)cnx_stress_nb_clients;

    stress_random_ctx = 0xBabaC001BaddBab1ull;

    picoquic_fuzz_in_progress = (fuzz_fn == NULL) ? 0 : 1;

    /* Initialization */
    memset(&stress_ctx, 0, sizeof(cnx_stress_ctx_t));
    stress_ctx.nb_clients = nb_clients;

    return ret;
}

