/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "picoquic.h"
#include "qinqproto.h"
#include "qinqclient.h"
#include "picohash.h"

/*
 * Datagram call back, process Quic datagrams received from a qinq server.
 */
int picoqinq_client_callback_datagram(picoqinq_client_callback_ctx_t* ctx, uint8_t* bytes0, size_t length)
{
    /* Decode the datagram and queue it for input processing by the quic context */
    int ret = 0;

    /* TODO */
    struct sockaddr_storage addr_s;
    uint8_t* bytes_max = bytes0 + length;
    picoquic_connection_id_t * cid = NULL;
    uint8_t* bytes = picoqinq_decode_datagram_header(bytes0, bytes_max, &addr_s, &cid, &ctx->receive_hc);

    return ret;
}

/* Per stream context.
 *
 * QINQ uses streams to send protocol elements such as registration of connection IDs.
 * The "end of stream" marks the end of a protocol element. When it is received, the
 * protocol machine is called, and the response is posted on the stream.
 */

picoqinq_client_stream_ctx_t* picoqinq_find_or_create_client_stream(picoquic_cnx_t* cnx, uint64_t stream_id, picoqinq_client_callback_ctx_t* ctx, int should_create)
{
    picoqinq_client_stream_ctx_t* stream_ctx = NULL;

    /* if stream is already present, check its state. New bytes? */
    stream_ctx = ctx->first_stream;
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL && should_create) {
        stream_ctx = (picoqinq_client_stream_ctx_t*)
            malloc(sizeof(picoqinq_client_stream_ctx_t));
        if (stream_ctx == NULL) {
            /* Could not handle this stream */
            picoquic_reset_stream(cnx, stream_id, PICOQINQ_ERROR_INTERNAL);
        }
        else {
            memset(stream_ctx, 0, sizeof(picoqinq_client_stream_ctx_t));
            stream_ctx->next_stream = ctx->first_stream;
            ctx->first_stream = stream_ctx;
            stream_ctx->stream_id = stream_id;
        }
    }

    return stream_ctx;
}


void picoqinq_forget_client_stream(picoqinq_client_callback_ctx_t* ctx, picoqinq_client_stream_ctx_t* stream_ctx)
{
    if (ctx != NULL && stream_ctx != NULL) {
        picoqinq_client_stream_ctx_t** previous_link = &ctx->first_stream;
        while (*previous_link != NULL && *previous_link != stream_ctx) {
            previous_link = &(*previous_link)->next_stream;
        }
        if (*previous_link == stream_ctx) {
            *previous_link = stream_ctx->next_stream;
        }
        free(stream_ctx);
    }
}

int picoqinq_client_callback_data(picoquic_cnx_t* cnx, picoqinq_client_stream_ctx_t* stream_ctx, uint64_t stream_id, uint8_t* bytes, size_t length, picoquic_call_back_event_t fin_or_event, picoqinq_client_callback_ctx_t* callback_ctx)
{
    int ret = 0;

    if (stream_ctx == NULL) {
        stream_ctx = picoqinq_find_or_create_client_stream(cnx, stream_id, callback_ctx, 1);
    }

    if (stream_ctx == NULL) {
        /* not enough resource */
        ret = picoquic_stop_sending(cnx, stream_id, PICOQINQ_ERROR_INTERNAL);
    } else if (stream_ctx->data_received + length > sizeof(stream_ctx->frame)) {
        /* Message too big. */
        ret = -1;
    }
    else {
        if (length > 0) {
            memcpy(&stream_ctx->frame[stream_ctx->data_received], bytes, length);
            stream_ctx->data_received += length;
        }

        if (fin_or_event == picoquic_callback_stream_fin) {
            /* TODO: decode the message and validate the transaction  */
            if (ret == 0) {
                /* TODO: ret = picoquic_add_to_stream(cnx, stream_id, response, response_length, 1); */
            }
            else {
                /* Reset the stream */
                ret = picoquic_reset_stream(cnx, stream_id, PICOQINQ_ERROR_PROTOCOL);
            }
        }
    }
    return ret;
}

/*
 * QINQ client call back.
 *
 * Create a context for each client connection.
 * 
 * The context holds:
 *  - a list of per stream context, used for managing incoming and outgoing requests.
 *  - a list of the connection ID that are registered for this context
 *  - the identity of the client, if it is known.
 */

picoqinq_client_callback_ctx_t* picoqinq_client_callback_create_context(picoqinq_ctx_t* qinq_ctx)
{
    picoqinq_client_callback_ctx_t* ctx = (picoqinq_client_callback_ctx_t*)
        malloc(sizeof(picoqinq_client_callback_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(picoqinq_client_callback_ctx_t));
        ctx->first_stream = NULL;
    }
    return ctx;
}

void picoqinq_client_callback_delete_context(picoqinq_client_callback_ctx_t* ctx)
{
    if (ctx != NULL) {
        picoqinq_client_stream_ctx_t* stream_ctx = NULL;
        /* Manage the list of streams. */
        while (1) {
            picoqinq_client_stream_ctx_t* stream_ctx = ctx->first_stream;
            if (stream_ctx != NULL) {
                ctx->first_stream = stream_ctx->next_stream;
                free(stream_ctx);
            }
            else {
                break;
            }
        }
        /* TODO: manage the list of CID. */
        /* TODO: manage identity. */
        free(ctx);
    }
}


int picoqinq_client_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    picoqinq_client_callback_ctx_t* ctx = NULL;
    picoqinq_client_stream_ctx_t* stream_ctx = (picoqinq_client_stream_ctx_t*)v_stream_ctx;

    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx))) {
        ctx = picoqinq_client_callback_create_context(
            (picoqinq_ctx_t*)picoquic_get_default_callback_context(picoquic_get_quic_ctx(cnx)));
        if (ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else {
            picoquic_set_callback(cnx, picoqinq_client_callback, ctx);
        }
    }
    else {
        ctx = (picoqinq_client_callback_ctx_t*)callback_ctx;
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            ret = picoqinq_client_callback_data(cnx, stream_ctx, stream_id, bytes, length, fin_or_event, ctx);
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            picoqinq_forget_client_stream(ctx, stream_ctx);
            picoquic_reset_stream(cnx, stream_id, 0);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            picoqinq_client_callback_delete_context(ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            break;
        case picoquic_callback_stream_gap:
            /* Gap indication, when unreliable streams are supported */
            if (stream_ctx == NULL) {
                stream_ctx = picoqinq_find_or_create_client_stream(cnx, stream_id, ctx, 0);
            }
            if (stream_ctx != NULL) {
                /* Reset the stream status */
                picoqinq_forget_client_stream(ctx, stream_ctx);
                stream_ctx = NULL;
                picoquic_reset_stream(cnx, stream_id, 0);
            }
            picoquic_stop_sending(cnx, stream_id, PICOQINQ_ERROR_INTERNAL);
            break;
        case picoquic_callback_prepare_to_send:
            /* Used for active streams  -- is this really needed? */
            /* ret = picoqinq_client_callback_prepare_to_send(cnx, stream_id, stream_ctx, (void*)bytes, length, ctx); */
            break;
        case picoquic_callback_datagram:
            /* Process the datagram, which contains an address and a QUIC packet */
            ret = picoqinq_client_callback_datagram(ctx, bytes, length);
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what QINQ expects */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

/*
 * Manage an outgoing packet, sending it as a datagram to the proxy.
 * 
 */

int picoqinq_forward_outgoing_packet(
    picoquic_quic_t* quic,
    uint8_t* bytes,
    size_t packet_length,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    unsigned char received_ecn,
    uint64_t current_time)
{
    return -1;
}


