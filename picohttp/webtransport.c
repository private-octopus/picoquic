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

/*
 * Web Transport API implementation for Picoquic.
 * 
 * Expected usage:
 *  - quic server is multipurpose, serves H3 pages, posts, etc., in addition to web socket.
 *  - WT acting as client learns of a connection to the intended server. TBD: generic
 *    connection also used for something else, or specialized connection?
 *  - WT client issues CONNECT on connection, which creates a WT context.
 *  - Server side, WT responder is notified of connect, which creates a WT context.
 *  - Both client and server could open streams
 * 
 * Architecture:
 * 
 *    -- quic events generate picoquic callbacks.
 *    -- web transport state established when processing CONNECT
 *    -- web transport intercepts related callbacks:
 *        -- incoming unidir streams starting with specified frame
 *        -- incoming bidir streams starting with specified frame
 *        -- datagrams starting with specified ID
 *    -- mapping of picoquic callbacks to WT callbacks
 * 
 * 
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <picoquic.h>
#include "picoquic_utils.h"
#include "h3zero_common.h"
#include "pico_webtransport.h"

/* web transport set parameters
* Set the parameters adequate for web transport, including:
* - initial number of bidir and unidir streams to 63
* - initial max data per stream to 0x3FFF (16K -1)
* - datagram length to PICOQUIC_MAX_PACKET_SIZE
*/
static void picowt_set_transport_parameters_values(const picoquic_tp_t* tp_current, picoquic_tp_t* tp_new)
{
    if (tp_current != NULL) {
        memcpy(tp_new, tp_current, sizeof(picoquic_tp_t));
    }
    else {
        memset(tp_new, 0, sizeof(picoquic_tp_t));
    }
    if (tp_new->initial_max_data < 0x3FFF) {
        tp_new->initial_max_data = 0x3FFF;
    }
    if (tp_new->initial_max_stream_data_bidi_local < 0x3FFF) {
        tp_new->initial_max_stream_data_bidi_local = 0x3FFF;
    }
    if (tp_new->initial_max_stream_data_bidi_remote < 0x3FFF) {
        tp_new->initial_max_stream_data_bidi_remote = 0x3FFF;
    }
    if (tp_new->initial_max_stream_data_uni < 0x3FFF) {
        tp_new->initial_max_stream_data_uni = 0x3FFF;
    }
    if (tp_new->initial_max_stream_id_bidir < 0x3F) {
        tp_new->initial_max_stream_id_bidir = 0x3F;
    }
    if (tp_new->initial_max_stream_id_unidir < 0x3F) {
        tp_new->initial_max_stream_id_unidir = 0x3F;
    }
    if (tp_new->max_datagram_frame_size == 0) {
        tp_new->max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
    }
}

void picowt_set_transport_parameters(picoquic_cnx_t* cnx)
{
    const picoquic_tp_t* tp_current = picoquic_get_transport_parameters(cnx, 1);
    picoquic_tp_t tp_new;
    picowt_set_transport_parameters_values(tp_current, &tp_new);
    picoquic_set_transport_parameters(cnx, &tp_new);
}

/* Web transport commands */

/* Web transport initiate, client side
* cnx: an established QUIC connection, set to ALPN=H3.
* stream_ctx: a new stream, created for the purpose of sending the connect request
* wt_callback: callback function to use in the web transport connection.
* wt_ctx: application level context for that connection.
* 
* This will reserve a bidir stream, and send a "connect" frame on that
* stream. The client will receive a WT event when the response comes
* back. 
* 
* This should create a WT connection context, which will be associated with
* the stream ID. This is associated with the connection itself. Do we have
* an H3 context for the connection?
*/

int picowt_connect(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx,  picohttp_server_stream_ctx_t* stream_ctx, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx)
{
    /* register the stream ID as session ID */
    int ret = h3zero_declare_stream_prefix(ctx, stream_ctx->stream_id, wt_callback, wt_ctx);
    if (cnx != NULL) {
        picoquic_log_app_message(cnx, "Allocated prefix for control stream %" PRIu64, stream_ctx->stream_id);
    }
    /* Declare the outgoing connection through the callback, so it can update its own state */
    ret = wt_callback(cnx, NULL, 0, picohttp_callback_connecting, stream_ctx, wt_ctx);

    if (ret == 0) {
        /* Format and send the connect frame. */
        uint8_t buffer[1024];
        uint8_t* bytes = buffer;
        uint8_t* bytes_max = bytes + 1024;

        *bytes++ = h3zero_frame_header;
        bytes += 2; /* reserve two bytes for frame length */

        bytes = h3zero_create_connect_header_frame(bytes, bytes_max, (const uint8_t*)path, strlen(path), "webtransport", NULL,
            H3ZERO_USER_AGENT_STRING);

        if (bytes == NULL) {
            ret = -1;
        }
        else {
            /* Encode the header length */
            size_t header_length = bytes - &buffer[3];
            if (header_length < 64) {
                buffer[1] = (uint8_t)(header_length);
                memmove(&buffer[2], &buffer[3], header_length);
                bytes--;
            }
            else {
                buffer[1] = (uint8_t)((header_length >> 8) | 0x40);
                buffer[2] = (uint8_t)(header_length & 0xFF);
            }
            size_t connect_length = bytes - buffer;
            stream_ctx->ps.stream_state.is_upgrade_requested = 1;
            ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, buffer, connect_length,
                    0, stream_ctx);
        }

        if (ret != 0) {
            /* remove the stream prefix */
            h3zero_delete_stream_prefix(cnx, ctx, stream_ctx->stream_id);
        }
    }
    return ret;
}

/*
CLOSE_WEBTRANSPORT_SESSION Capsule {
    Type (i) = CLOSE_WEBTRANSPORT_SESSION,
    Length (i),
    Application Error Code (32),
    Application Error Message (..8192),
}
*/
#define PICOWT_CLOSE_WEBTRANSPORT_SESSION 0x2843

int picowt_send_close_session_message(picoquic_cnx_t* cnx, 
    picohttp_server_stream_ctx_t* control_stream_ctx, 
    uint32_t picowt_err, const char* err_msg)
{
    uint8_t buffer[512];
    int ret = 0;
    /* Compute the length */
    size_t length = 4;
    size_t err_msg_len = 0;
    uint8_t* bytes;
    uint8_t* bytes_max = buffer + sizeof(buffer);

    if (control_stream_ctx->ps.stream_state.is_fin_sent) {
        /* cannot send! */
        ret = -1;
    }
    else {
        /* Compute the length */
        if (err_msg != NULL) {
            err_msg_len = strlen(err_msg);
        }
        length += err_msg_len;
        /* Encode the capsule */
        if ((bytes = picoquic_frames_varint_encode(buffer, bytes_max,
            PICOWT_CLOSE_WEBTRANSPORT_SESSION)) != NULL &&
            (bytes = picoquic_frames_varint_encode(bytes, bytes_max, length)) != NULL &&
            (bytes = picoquic_frames_uint32_encode(bytes, bytes_max, picowt_err)) != NULL)
        {
            if (bytes + err_msg_len > bytes_max) {
                bytes = NULL;
            }
            else if (err_msg_len > 0) {
                memcpy(bytes, err_msg, err_msg_len);
                bytes += err_msg_len;
            }
        }
        if (bytes == NULL) {
            /* This might happen if the error message is too long */
            ret = -1;
        }
        else {
            /* Write the capsule*/
            ret = picoquic_add_to_stream(cnx, control_stream_ctx->stream_id, buffer, bytes - buffer, 1);
            control_stream_ctx->ps.stream_state.is_fin_sent = 1;
        }
    }
    return ret;
}

/* Receive a WT capsule.
 */
int picowt_receive_capsule(picoquic_cnx_t *cnx, const uint8_t* bytes, const uint8_t* bytes_max, picowt_capsule_t * capsule)
{
    int ret = 0;
    const uint8_t* bytes_next = h3zero_accumulate_capsule(bytes, bytes_max, &capsule->h3_capsule);

    if (bytes_next == NULL) {
        picoquic_log_app_message(cnx, "Cannot parse %zu capsule bytes", bytes_max - bytes);
        ret = -1;
    }
    else if (capsule->h3_capsule.is_stored) {
        if (capsule->h3_capsule.capsule_type != PICOWT_CLOSE_WEBTRANSPORT_SESSION) {
            picoquic_log_app_message(cnx, "Unexpected web transport capsule type: %" PRIu64, capsule->h3_capsule.capsule_type);
            ret = -1;
        }
        else if (capsule->h3_capsule.capsule_length < 4) {
            picoquic_log_app_message(cnx, "Web transport capsule too short, %zu bytes", capsule->h3_capsule.capsule_length);
            ret = -1;
        }
        else {
            capsule->error_msg = picoquic_frames_uint32_decode(
                capsule->h3_capsule.capsule, capsule->h3_capsule.capsule + capsule->h3_capsule.capsule_length,
                &capsule->error_code);
            capsule->error_msg_len = capsule->h3_capsule.capsule_length - 4;
        }
    }
    return ret;
}

void picowt_release_capsule(picowt_capsule_t* capsule)
{
    h3zero_release_capsule(&capsule->h3_capsule);
}