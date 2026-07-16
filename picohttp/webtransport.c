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
#include "picoquic_internal.h"
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
    tp_new->is_reset_stream_at_enabled = 1;
}

void picowt_set_transport_parameters(picoquic_cnx_t* cnx)
{
    const picoquic_tp_t* tp_current = picoquic_get_transport_parameters(cnx, 1);
    picoquic_tp_t tp_new;
    picowt_set_transport_parameters_values(tp_current, &tp_new);
    picoquic_set_transport_parameters(cnx, &tp_new);
}

void picowt_set_default_transport_parameters(picoquic_quic_t* quic)
{
    quic->default_tp.is_reset_stream_at_enabled = 1;
    if (quic->default_tp.max_datagram_frame_size == 0) {
        quic->default_tp.max_datagram_frame_size = PICOQUIC_MAX_PACKET_SIZE;
    }
}

/* Web transport commands */

/**
* Create stream: when a stream is created locally. 
* Send the stream header. Associate the stream with a per_stream
* app context. mark the stream as active, per batn protocol.
*/
static h3zero_stream_ctx_t* picowt_create_stream_ctx(picoquic_cnx_t* cnx, int is_bidir, h3zero_callback_ctx_t* h3_ctx, 
    uint64_t control_stream_id)
{
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, !is_bidir);
    h3zero_stream_ctx_t* stream_ctx = h3zero_find_or_create_stream(
        cnx, stream_id, h3_ctx, 1, 1);
    if (stream_ctx != NULL) {
        /* Associate the stream with a per_stream context */
        stream_ctx->ps.stream_state.stream_type = (is_bidir) ? h3zero_frame_webtransport_stream : h3zero_stream_type_webtransport;
        stream_ctx->ps.stream_state.control_stream_id = control_stream_id;
        if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
            DBG_PRINTF("Could not set context for stream %"PRIu64, stream_id);
        }
    }
    return stream_ctx;
}

h3zero_stream_ctx_t* picowt_create_local_stream(picoquic_cnx_t* cnx, int is_bidir, h3zero_callback_ctx_t* h3_ctx,
    uint64_t control_stream_id)
{
    h3zero_stream_ctx_t* stream_ctx = picowt_create_stream_ctx(cnx, is_bidir, h3_ctx, control_stream_id);
    if (stream_ctx != NULL) {
        /* Write the first required bytes for sending the context ID */
        uint8_t stream_header[16];
        int ret;

        uint8_t* bytes = stream_header;
        bytes = picoquic_frames_varint_encode(bytes, stream_header + 16, 
            (is_bidir)?h3zero_frame_webtransport_stream:h3zero_stream_type_webtransport);
        bytes = picoquic_frames_varint_encode(bytes, stream_header + 16, control_stream_id);
        if ((ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, stream_header, bytes - stream_header, 0, stream_ctx)) != 0) {
            /* something went wrong */
            DBG_PRINTF("Could not add data for stream %"PRIu64 ", ret = %d", stream_ctx->stream_id, ret);
            h3zero_delete_stream(cnx, h3_ctx, stream_ctx);
            stream_ctx = NULL;
        }
    }
    return(stream_ctx);
}


int picowt_reset_stream(picoquic_cnx_t* cnx, h3zero_stream_ctx_t * stream_ctx, uint64_t local_stream_error)
{
    /* Compute the length of the preamble:
    * if is local:
    *    varint(h3zero_frame_webtransport_stream or h3zero_stream_type_webtransport): 2 bytes
    *    + varint (control stream_id)
    * else if is bidir:
    *    resetting a remotely created half of a bidir stream. Just reset.
    * else: can't do that.
    * 
    * if both sides of the stream are closed, delete the H3 stream context.
     */
    int ret = 0;
    int is_bidir = IS_BIDIR_STREAM_ID(stream_ctx->stream_id);
    int is_local = IS_LOCAL_STREAM_ID(stream_ctx->stream_id, cnx->client_mode);

    if (!is_local && !is_bidir) {
        ret = -1;
    }
    else {
        size_t reliable_size = 0;
        if (is_local) {
            reliable_size = 2 + picoquic_frames_varint_encode_length(stream_ctx->ps.stream_state.control_stream_id);
        }
        ret = picoquic_reset_stream_at(cnx, stream_ctx->stream_id, local_stream_error, reliable_size);
        stream_ctx->ps.stream_state.is_fin_sent = 1;
    }

    return ret;
}

/* Web transport initiate, client side. Start with two parameters:
* cnx: an established QUIC connection, set to ALPN=H3.
* h3_ctx: the http3 connection context.
* 
* The web transport connection is set in four phases:
* 
* 1- Create an h3zero stream context for the control stream, using
*    the API picowt_set_control_stream.
* 
* 2- Prepare the application state before the connection. This may
*    include documenting the control stream context.
* 
* 3- Call the picowt_connect API to prepare and queue the web transport
*    connect message. The API takes the following parameters:
* 
*      - cnx: QUIC connection context
*      - stream_ctx: the stream context returned by `picowt_set_control_stream`
*      - path: the path parameter for the connect request
*      - wt_callback: the path callback used for the application
*      - wt_ctx: the web transport application context associated with the path callback
* 
* 4- Make sure that the application is ready to process incoming streams.
*/

h3zero_stream_ctx_t* picowt_set_control_stream(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* h3_ctx)
{
    uint64_t stream_id = picoquic_get_next_local_stream_id(cnx, 0);
    h3zero_stream_ctx_t* stream_ctx = h3zero_find_or_create_stream(
        cnx, stream_id, h3_ctx, 1, 1);
    if (stream_ctx != NULL) {
        /* Associate the stream with a per_stream context */
        if (picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx) != 0) {
            DBG_PRINTF("Could not set context for stream %"PRIu64, stream_id);
            h3zero_delete_stream(cnx, h3_ctx, stream_ctx);
            stream_ctx = NULL;
        }
    }
    return stream_ctx;
}

int picowt_prepare_client_cnx(picoquic_quic_t* quic, struct sockaddr* server_address,
    picoquic_cnx_t** p_cnx, h3zero_callback_ctx_t** p_h3_ctx,
    h3zero_stream_ctx_t** p_stream_ctx,
    uint64_t current_time, const char* sni)
{
    int ret = 0;


    /* use the generic H3 callback */
    /* Set the client callback context */
    if ((*p_h3_ctx == NULL && (*p_h3_ctx = h3zero_callback_create_context(NULL)) == NULL) ||
        (*p_cnx == NULL && ((*p_cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id,
            (struct sockaddr*)server_address, current_time, 0, sni, "h3", 1)) == NULL)) ||
        ((*p_stream_ctx = picowt_set_control_stream(*p_cnx, *p_h3_ctx)) == NULL)) {
        ret = 1;
    }
    else
    {
        picowt_set_transport_parameters(*p_cnx);
        picoquic_set_callback(*p_cnx, h3zero_callback, *p_h3_ctx);
    }
    return ret;
}

/* set web transport protocol to selected value.
*/
int picowt_set_wt_protocol(h3zero_stream_ctx_t* stream_ctx, const char* selected_protocol)
{
    int ret = 0;
    if (stream_ctx->ps.stream_state.wt_protocol != NULL) {
        ret = -1;
    }
    else if ((stream_ctx->ps.stream_state.wt_protocol = picoquic_string_duplicate(selected_protocol)) == NULL) {
        ret = -1; /* memory allocation failed */
    }
    return ret;
}

/*
* Set selected web transport protocol
* - Compare the incoming 'wt_available_protocol" to the server list.
* - If there is a match, set the selected protocol in the context, and return 0.
* - If there is no match, return -1.
*/
int picowt_select_wt_protocol(h3zero_stream_ctx_t* stream_ctx, char const* supported)
{
    char candidate[256];
    size_t candidate_length;
    char const* a = (char const *)stream_ctx->ps.stream_state.header.wt_available_protocols;
    size_t s_len = strlen(supported);
    int ret = -1;

    while (a != NULL && *a != 0) {
        /* isolate the next available */
        int overflowed = 0;
        candidate_length = 0;

        while (*a == ' ' || *a == '\t') {
            a++;
        }
        while (*a != ',' && *a != 0 && *a != ' ' && *a != '\t') {
            /* Skip quotes - HTTP structured fields use quoted strings */
            if (*a != '"') {
                if (candidate_length >= 254) {
                    overflowed = 1;
                }
                else {
                    candidate[candidate_length] = *a;
                    candidate_length++;
                }
            }
            a++;
        }
        while (*a == ' ' || *a == '\t') {
            a++;
        }
        candidate[candidate_length] = 0;
        if (*a == ',') {
            a++;
        }
        else if (*a != 0) {
            a = NULL;
        }
        if (candidate_length > 0 && !overflowed) {
            /* check whether there is a match*/
            size_t os = 0;
            while (os + candidate_length <= s_len) {
                if (supported[os] == ' ' || supported[os] == '\t' || supported[os] == ',') {
                    os++;
                }
                else {
                    if ((os + candidate_length == s_len ||
                        supported[os + candidate_length] == ' ' ||
                        supported[os + candidate_length] == '\t' ||
                        supported[os + candidate_length] == ',') &&
                        memcmp(&supported[os], candidate, candidate_length) == 0) {
                        /* found it. set the value. */
                        ret = picowt_set_wt_protocol(stream_ctx, candidate);
                        a = NULL;
                        break;
                    }
                    else while (os + candidate_length <= s_len &&
                        supported[os] != ' ' && supported[os] != '\t' && supported[os] != ',') {
                        os++;
                    }
                }
            }
        }
    }
    return ret;
}

const char* picowt_get_authority(h3zero_stream_ctx_t* stream_ctx)
{
    return (const char*)stream_ctx->ps.stream_state.header.authority;
}

static const char* picowt_connect_protocol_from_settings(const h3zero_settings_t* settings)
{
    return (settings != NULL && settings->webtransport_enabled > 0) ?
        H3ZERO_WEBTRANSPORT_H3_PROTOCOL : H3ZERO_WEBTRANSPORT_H3_PROTOCOL_OLD;
}

static int picowt_webtransport_requirements_met(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx)
{
    const picoquic_tp_t* remote_tp = (cnx == NULL) ? NULL : picoquic_get_transport_parameters(cnx, 0);
    int has_webtransport_settings = ctx != NULL &&
        (ctx->settings.webtransport_enabled > 0 || ctx->settings.webtransport_max_sessions > 0);
    int has_connect_settings = ctx != NULL &&
        (ctx->settings.webtransport_enabled == 0 || ctx->settings.enable_connect_protocol);

    return ctx != NULL &&
        ctx->settings.settings_received &&
        ctx->settings.h3_datagram &&
        has_webtransport_settings &&
        has_connect_settings &&
        remote_tp != NULL &&
        remote_tp->max_datagram_frame_size > 0 &&
        remote_tp->is_reset_stream_at_enabled;
}

static int picowt_format_connect_frame(h3zero_stream_ctx_t* stream_ctx,
    const char* authority, const char* path, const char* connect_protocol,
    char const* wt_available_protocols, uint8_t* extra, size_t extra_length,
    size_t* connect_length)
{
    int ret = 0;
    uint8_t* bytes = stream_ctx->frame;
    uint8_t* bytes_max = stream_ctx->frame + sizeof(stream_ctx->frame);

    *bytes++ = h3zero_frame_header;
    bytes += 2; /* reserve two bytes for frame length */

    bytes = h3zero_create_connect_header_frame(bytes, bytes_max, authority,
        (const uint8_t*)path, strlen(path), connect_protocol, NULL,
        H3ZERO_USER_AGENT_STRING, wt_available_protocols);

    if (bytes == NULL) {
        ret = -1;
    }
    else {
        size_t header_length = bytes - &stream_ctx->frame[3];
        if (header_length < 64) {
            stream_ctx->frame[1] = (uint8_t)(header_length);
            memmove(&stream_ctx->frame[2], &stream_ctx->frame[3], header_length);
            bytes--;
        }
        else {
            stream_ctx->frame[1] = (uint8_t)((header_length >> 8) | 0x40);
            stream_ctx->frame[2] = (uint8_t)(header_length & 0xFF);
        }

        *connect_length = bytes - stream_ctx->frame;
        stream_ctx->ps.stream_state.is_upgrade_requested = 1;

        if (extra != NULL && extra_length > 0) {
            if (*connect_length + extra_length > sizeof(stream_ctx->frame)) {
                ret = -1;
            }
            else {
                memcpy(stream_ctx->frame + *connect_length, extra, extra_length);
                *connect_length += extra_length;
            }
        }
    }

    return ret;
}

typedef struct st_picowt_pending_connect_t {
    char* authority;
    char* path;
    char* wt_available_protocols;
    uint8_t* extra;
    size_t extra_length;
} picowt_pending_connect_t;

static void picowt_delete_pending_connect(picowt_pending_connect_t* pending)
{
    if (pending != NULL) {
        free(pending->authority);
        free(pending->path);
        free(pending->wt_available_protocols);
        free(pending->extra);
        free(pending);
    }
}

void picowt_clear_pending_connect(h3zero_callback_ctx_t* ctx, h3zero_stream_ctx_t* stream_ctx)
{
    if (ctx != NULL &&
        (stream_ctx == NULL || ctx->pending_wt_connect == stream_ctx)) {
        picowt_delete_pending_connect(ctx->pending_wt_connect_data);
        ctx->pending_wt_connect_data = NULL;
        ctx->pending_wt_connect = NULL;
    }
}

static int picowt_set_pending_connect(h3zero_callback_ctx_t* ctx,
    h3zero_stream_ctx_t* stream_ctx,
    const char* authority, const char* path, char const* wt_available_protocols,
    uint8_t* extra, size_t extra_length)
{
    int ret = 0;
    picowt_pending_connect_t* pending = NULL;

    if (ctx == NULL || stream_ctx == NULL ||
        (ctx->pending_wt_connect != NULL && ctx->pending_wt_connect != stream_ctx)) {
        ret = -1;
    }
    else {
        picowt_clear_pending_connect(ctx, stream_ctx);
    }
    if (ret == 0) {
        pending = (picowt_pending_connect_t*)malloc(sizeof(picowt_pending_connect_t));
        if (pending == NULL) {
            ret = -1;
        }
        else {
            memset(pending, 0, sizeof(picowt_pending_connect_t));
        }
    }
    if (ret == 0 &&
        ((authority != NULL &&
            (pending->authority = picoquic_string_duplicate(authority)) == NULL) ||
        (pending->path = picoquic_string_duplicate(path)) == NULL ||
        (wt_available_protocols != NULL &&
            (pending->wt_available_protocols =
                picoquic_string_duplicate(wt_available_protocols)) == NULL))) {
        ret = -1;
    }
    else if (ret == 0 && extra != NULL && extra_length > 0) {
        pending->extra = (uint8_t*)malloc(extra_length);
        if (pending->extra == NULL) {
            ret = -1;
        }
        else {
            memcpy(pending->extra, extra, extra_length);
            pending->extra_length = extra_length;
        }
    }

    if (ret == 0) {
        ctx->pending_wt_connect = stream_ctx;
        ctx->pending_wt_connect_data = pending;
    }
    else {
        picowt_delete_pending_connect(pending);
    }

    return ret;
}

static int picowt_send_pending_connect(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx,
    h3zero_stream_ctx_t* stream_ctx)
{
    int ret;
    size_t connect_length = 0;
    picowt_pending_connect_t* pending = (ctx == NULL ||
        ctx->pending_wt_connect != stream_ctx) ? NULL :
        ctx->pending_wt_connect_data;

    if (pending == NULL) {
        ret = -1;
    }
    else {
        ret = picowt_format_connect_frame(stream_ctx,
            pending->authority, pending->path,
            picowt_connect_protocol_from_settings(&ctx->settings),
            pending->wt_available_protocols, pending->extra,
            pending->extra_length, &connect_length);
    }

    if (ret == 0) {
        ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id,
            stream_ctx->frame, connect_length, 0, stream_ctx);
    }

    if (ret == 0) {
        picowt_clear_pending_connect(ctx, stream_ctx);
    }

    return ret;
}

int picowt_process_pending_connect(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx)
{
    int ret = 0;

    if (ctx != NULL && ctx->pending_wt_connect != NULL) {
        h3zero_stream_ctx_t* stream_ctx = ctx->pending_wt_connect;
        uint64_t stream_id = stream_ctx->stream_id;

        if (picowt_webtransport_requirements_met(cnx, ctx)) {
            ret = picowt_send_pending_connect(cnx, ctx, stream_ctx);
        }
        else {
            picoquic_log_app_message(cnx,
                "Deferred WebTransport CONNECT on stream %" PRIu64 " rejected by peer settings",
                stream_id);
            if (stream_ctx->path_callback != NULL) {
                (void)stream_ctx->path_callback(cnx, NULL, 0,
                    picohttp_callback_connect_refused,
                    stream_ctx, stream_ctx->path_callback_ctx);
            }
            h3zero_delete_stream_prefix(cnx, ctx, stream_id);
            picowt_clear_pending_connect(ctx, stream_ctx);
        }
    }

    return ret;
}

/*
* Connect
*/

int picowt_connect_ex(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx,  h3zero_stream_ctx_t* stream_ctx, 
    const char * authority, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx,
    char const* wt_available_protocols, uint8_t * extra, size_t extra_length)
{
    /* register the stream ID as session ID */
    int ret = 0;
    if (h3zero_find_stream_prefix(ctx, stream_ctx->stream_id) == NULL) {
        ret = h3zero_declare_stream_prefix(ctx, stream_ctx->stream_id, wt_callback, wt_ctx);
    }
    if (ret == 0 && cnx != NULL) {
        picoquic_log_app_message(cnx, "Allocated prefix for control stream %" PRIu64, stream_ctx->stream_id);
    }

    if (ret == 0) {
        size_t connect_length = 0;

        /* set the required stream parameters for the state of the stream. */
        stream_ctx->is_open = 1;
        stream_ctx->path_callback = wt_callback;
        stream_ctx->path_callback_ctx = wt_ctx;

        /* Declare the outgoing connection through the callback, so it can update its own state */
        ret = wt_callback(cnx, NULL, 0, picohttp_callback_connecting, stream_ctx, wt_ctx);

        if (ret == 0) {
            if (!ctx->settings.settings_received) {
                ret = picowt_set_pending_connect(ctx, stream_ctx, authority, path,
                    wt_available_protocols, extra, extra_length);
                if (cnx != NULL) {
                    picoquic_log_app_message(cnx,
                        "Deferred WebTransport CONNECT on stream %" PRIu64 " until peer SETTINGS",
                        stream_ctx->stream_id);
                }
            }
            else if (!picowt_webtransport_requirements_met(cnx, ctx)) {
                if (stream_ctx->path_callback != NULL) {
                    (void)stream_ctx->path_callback(cnx, NULL, 0,
                        picohttp_callback_connect_refused,
                        stream_ctx, stream_ctx->path_callback_ctx);
                }
                ret = -1;
            }
            else {
                ret = picowt_format_connect_frame(stream_ctx, authority, path,
                    picowt_connect_protocol_from_settings(&ctx->settings),
                    wt_available_protocols, extra, extra_length, &connect_length);
            }

            if (ret == 0 && connect_length > 0) {
                ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id,
                    stream_ctx->frame, connect_length, 0, stream_ctx);
            }
        }
    }

    if (ret != 0) {
        picowt_clear_pending_connect(ctx, stream_ctx);
        h3zero_delete_stream_prefix(cnx, ctx, stream_ctx->stream_id);
    }

    return ret;
}

int picowt_connect(picoquic_cnx_t* cnx, h3zero_callback_ctx_t* ctx, h3zero_stream_ctx_t* stream_ctx,
    const char* authority, const char* path, picohttp_post_data_cb_fn wt_callback, void* wt_ctx, char const* wt_available_protocols)
{
    return picowt_connect_ex(cnx, ctx, stream_ctx, authority, path, wt_callback, wt_ctx, wt_available_protocols, NULL, 0);
}

/*
CLOSE_WEBTRANSPORT_SESSION Capsule {
    Type (i) = CLOSE_WEBTRANSPORT_SESSION,
    Length (i),
    Application Error Code (32),
    Application Error Message (..8192),
}
*/

int picowt_send_close_session_message(picoquic_cnx_t* cnx, 
    h3zero_stream_ctx_t* control_stream_ctx, 
    uint32_t picowt_err, const char* err_msg)
{
    uint8_t buffer[512];
    int ret = 0;
    /* Compute the length */
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

        if ((bytes = picoquic_frames_uint32_encode(buffer, bytes_max, picowt_err)) == NULL ||
            bytes + err_msg_len > bytes_max) {
            ret = -1;
        }
        else {
            if (err_msg_len > 0) {
                memcpy(bytes, err_msg, err_msg_len);
                bytes += err_msg_len;
            }
            ret = h3zero_send_capsule(cnx, control_stream_ctx, picowt_capsule_close_webtransport_session,
                bytes - buffer, buffer, 1 /* Set fin, because we are claosing this stream */);
        }
    }
    return ret;
}

/*
DRAIN_WEBTRANSPORT_SESSION Capsule {
    Type (i) = DRAIN_WEBTRANSPORT_SESSION,
    Length (i) = 0
}
*/

int picowt_send_drain_session_message(picoquic_cnx_t* cnx, 
    h3zero_stream_ctx_t* control_stream_ctx)
{
    int ret = 0;
    uint8_t null_msg[] = { 0 };

    if (control_stream_ctx->ps.stream_state.is_fin_sent) {
        /* cannot send! */
        ret = -1;
    }
    else {
        ret = h3zero_send_capsule(cnx, control_stream_ctx, picowt_capsule_drain_webtransport_session,
            0, null_msg, 0 /* Do not set fin, there could be other capsules */);
    }

    return ret;
}


/* Receive a WT capsule.
* With web transport, we expect three types of capsule:
* - Datagram, if datagram was not negotiated at the QUIC level,
* - Drain session,
* - Close session.
* 
*/
int picowt_receive_capsule(picoquic_cnx_t* cnx, const uint8_t* bytes, const uint8_t* bytes_max, picowt_capsule_t * capsule)
{
    int ret = 0; 
    
    while (ret == 0 && bytes < bytes_max) {
        const uint8_t* bytes_first = bytes;

        bytes = h3zero_accumulate_capsule(bytes, bytes_max, &capsule->h3_capsule);

        if (bytes == NULL) {
            picoquic_log_app_message(cnx, "Cannot parse %zu capsule bytes", bytes_max - bytes_first);
            ret = -1;
            break;
        }
        else{
            if (capsule->h3_capsule.is_stored) {
                switch (capsule->h3_capsule.capsule_type) {
                case picowt_capsule_drain_webtransport_session:
                    if (capsule->h3_capsule.capsule_length != 0) {
                        picoquic_log_app_message(cnx, "Web transport drain capsule length must be zero, got %zu bytes",
                            capsule->h3_capsule.capsule_length);
                        ret = -1;
                    }
                    else {
                        capsule->error_code = 0;
                        capsule->error_msg = NULL;
                        capsule->error_msg_len = 0;
                        picoquic_log_app_message(cnx, "Received web transport drain session capsule");
                    }
                    break;
                case picowt_capsule_close_webtransport_session:
                    if (capsule->h3_capsule.capsule_length < 4) {
                        picoquic_log_app_message(cnx, "Web transport capsule too short, %zu bytes", capsule->h3_capsule.capsule_length);
                        ret = -1;
                    }
                    else {
                        char text[256];
                        size_t text_len = 0;
                        capsule->error_msg = picoquic_frames_uint32_decode(
                            capsule->h3_capsule.capsule_buffer, capsule->h3_capsule.capsule_buffer + capsule->h3_capsule.capsule_length,
                            &capsule->error_code);
                        capsule->error_msg_len = capsule->h3_capsule.capsule_length - 4;
                        text_len = (capsule->error_msg_len > 255) ? 255 : capsule->error_msg_len;
                        if (text_len > 0) {
                            memcpy(text, capsule->error_msg, text_len);
                        }
                        text[text_len] = 0;
                        picoquic_log_app_message(cnx,
                            "Received web transport session capsule, type: 0x%" PRIx64 " (close session), error: %" PRIx32 " (%s)",
                            capsule->h3_capsule.capsule_type,
                            capsule->error_code, text);
                    }
                    break;
                default:
                    picoquic_log_app_message(cnx, "Unexpected web transport capsule type: 0x%" PRIx64, capsule->h3_capsule.capsule_type);
                    break;
                }
            }
        }
    }

    return ret;
}

void picowt_release_capsule(picowt_capsule_t* capsule)
{
    h3zero_release_capsule(&capsule->h3_capsule);
    capsule->error_code = 0;
    capsule->error_msg = NULL;
    capsule->error_msg_len = 0;
}

void picowt_deregister(picoquic_cnx_t* cnx,
    h3zero_callback_ctx_t* h3_ctx,
    h3zero_stream_ctx_t* control_stream_ctx)
{
    picosplay_node_t* previous = NULL;
    uint64_t control_stream_id = control_stream_ctx->stream_id;

    picowt_clear_pending_connect(h3_ctx, control_stream_ctx);

    /* Free the streams created for this session */
    while (1) {
        picosplay_node_t* next = (previous == NULL) ? picosplay_first(&h3_ctx->h3_stream_tree) : picosplay_next(previous);
        if (next == NULL) {
            break;
        }
        else {
            h3zero_stream_ctx_t* stream_ctx =
                (h3zero_stream_ctx_t*)picohttp_stream_node_value(next);

            if (control_stream_id == stream_ctx->ps.stream_state.control_stream_id &&
                control_stream_id != stream_ctx->stream_id) {
                stream_ctx->ps.stream_state.control_stream_id = UINT64_MAX;
                stream_ctx->path_callback = NULL;
                stream_ctx->path_callback_ctx = NULL;
                h3zero_forget_stream(cnx, stream_ctx);
                picosplay_delete_hint(&h3_ctx->h3_stream_tree, next);
            }
            else {
                previous = next;
            }
        }
    }
    /* Then deregister the control stream */
    if (!control_stream_ctx->ps.stream_state.is_fin_sent) {
        picoquic_add_to_stream(cnx, control_stream_ctx->stream_id, NULL, 0, 1);
        control_stream_ctx->ps.stream_state.is_fin_sent = 1;
    }
    picoquic_unlink_app_stream_ctx(cnx, control_stream_ctx->stream_id);
    picoquic_log_app_message(cnx, "Prefix for control stream %"PRIu64 " was unregistered", control_stream_id);
}
