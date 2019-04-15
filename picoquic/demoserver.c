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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "picoquic_internal.h"
#include "tls_api.h"
#include "h3zero.h"
#include "democlient.h"
#include "demoserver.h"

/*
 * Create and delete server side connection context
 */
static h3zero_server_callback_ctx_t * h3zero_server_callback_create_context()
{
    h3zero_server_callback_ctx_t* ctx = (h3zero_server_callback_ctx_t*)
        malloc(sizeof(h3zero_server_callback_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(h3zero_server_callback_ctx_t));
        ctx->first_stream = NULL;
        ctx->buffer = (uint8_t*)malloc(H3ZERO_RESPONSE_MAX);
        if (ctx->buffer == NULL) {
            free(ctx);
            ctx = NULL;
        }
        else {
            ctx->buffer_max = H3ZERO_RESPONSE_MAX;
        }
    }

    return ctx;
}

static void h3zero_server_callback_delete_context(h3zero_server_callback_ctx_t* ctx)
{
    h3zero_server_stream_ctx_t * stream_ctx;

    while ((stream_ctx = ctx->first_stream) != NULL) {
        ctx->first_stream = stream_ctx->next_stream;
        free(stream_ctx);
    }

    if (ctx->buffer != NULL) {
        free(ctx->buffer);
        ctx->buffer = NULL;
    }

    free(ctx);
}

static h3zero_server_stream_ctx_t * h3zero_find_or_create_stream(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    h3zero_server_callback_ctx_t* ctx,
    int should_create)
{
    h3zero_server_stream_ctx_t * stream_ctx = ctx->first_stream;

    /* if stream is already present, check its state. New bytes? */
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL && should_create) {
        stream_ctx = (h3zero_server_stream_ctx_t*)
            malloc(sizeof(h3zero_server_stream_ctx_t));
        if (stream_ctx == NULL) {
            /* Could not handle this stream */
            picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
        }
        else {
            memset(stream_ctx, 0, sizeof(h3zero_server_stream_ctx_t));
            stream_ctx->next_stream = ctx->first_stream;
            ctx->first_stream = stream_ctx;
            stream_ctx->stream_id = stream_id;
        }
    }

    return stream_ctx;
}

/*
 * Incoming data call back.
 * Create context if not yet present.
 * Create stream context if not yet present.
 * Different behavior for unidir and bidir.
 */

static char const * h3zero_default_page = "\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML>\r\n<HEAD>\r\n<TITLE>\
Picoquic HTTP 3 service\
</TITLE>\r\n</HEAD><BODY>\r\n\
<h1>Simple HTTP 3 Responder</h1>\r\n\
<p>GET / or GET /index.html returns this text</p>\r\n\
<p>Get /NNNNN returns txt document of length NNNNN bytes(decimal)</p>\r\n\
<p>Any other command will result in an error, and an empty response.</p>\r\n\
<h1>Enjoy!</h1>\r\n\
</BODY></HTML>\r\n";

static int h3zero_server_parse_path(const uint8_t * path, size_t path_length, uint32_t * echo_size)
{
    int ret = 0;

    *echo_size = 0;
    if (path == NULL || path_length == 0 || path[0] != '/') {
        ret = -1;
    }
    else if (path_length > 1 && (path_length != 11 || memcmp(path, "/index.html", 11) != 0)) {
        uint32_t x = 0;
        for (size_t i = 1; i < path_length; i++) {
            if (path[i] < '0' || path[i] > '9') {
                ret = -1;
                break;
            }
            x *= 10;
            x += path[i] - '0';
        }

        if (ret == 0) {
            *echo_size = x;
        }
    }

    return ret;
}

static int h3zero_server_parse_request_frame(
    picoquic_cnx_t* cnx,
    h3zero_server_stream_ctx_t * stream_ctx)
{
    int ret = 0;
    uint8_t * bytes = stream_ctx->frame;
    uint8_t * bytes_max = bytes + stream_ctx->received_length;
    h3zero_data_stream_state_t stream_state;
    size_t available_data;
    uint16_t error_found = 0;

    memset(&stream_state, 0, sizeof(h3zero_data_stream_state_t));

    while (bytes != NULL && bytes < bytes_max) {
        /* Parse the incoming data, looking for a header frame, ignoring data frame and unknown frames */
        bytes = h3zero_parse_data_stream(bytes, bytes_max, &stream_state, &available_data, &error_found);
    }

    if (bytes != NULL && (bytes != bytes_max || !stream_state.header_found)) {
        error_found = H3ZERO_MALFORMED_FRAME(h3zero_frame_header);
        bytes = NULL;
    }

    if (bytes == NULL) {
        ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, error_found);
    }
    else {
        /* Prepare response header */
        uint8_t buffer[1024]; 
        uint8_t * o_bytes = &buffer[0];
        uint8_t * o_bytes_max = o_bytes + sizeof(buffer);
        size_t response_length = 0;

        *o_bytes++ = h3zero_frame_header;
        o_bytes += 2; /* reserve two bytes for frame length */

        /* Parse path */
        if (stream_state.header.method != h3zero_method_get) {
            /* No such method supported -- error 405, header include "allow GET" */
            o_bytes = h3zero_create_bad_method_header_frame(o_bytes, o_bytes_max);
        }
        else if (h3zero_server_parse_path(stream_state.header.path, stream_state.header.path_length, &stream_ctx->echo_length) != 0) {
            /* If unknown, 404 */
            o_bytes = h3zero_create_not_found_header_frame(o_bytes, o_bytes_max);
        }
        else {
            /* If known, create response header frame */
            o_bytes = h3zero_create_response_header_frame(o_bytes, o_bytes_max,
                (stream_ctx->echo_length == 0) ? h3zero_content_type_text_html :
                h3zero_content_type_text_plain);
            if (o_bytes != NULL) {
                response_length = (stream_ctx->echo_length == 0) ?
                    strlen(h3zero_default_page) : stream_ctx->echo_length;
            }
        }

        if (o_bytes == NULL) {
            ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INTERNAL_ERROR);
        }
        else {
            size_t header_length = o_bytes - &buffer[3];
            buffer[1] = (uint8_t)((header_length >> 8) | 0x40);
            buffer[2] = (uint8_t)(header_length & 0xFF);

            if (response_length > 0) {
                size_t ld = 0;

                if (o_bytes + 2 < o_bytes_max) {
                    *o_bytes++ = h3zero_frame_data;
                    ld = picoquic_varint_encode(o_bytes, o_bytes_max - o_bytes, response_length);
                }

                if (ld == 0) {
                    o_bytes = NULL;
                }
                else {
                    o_bytes += ld;

                    if (stream_ctx->echo_length == 0) {
                        size_t test_length = strlen(h3zero_default_page);

                        if (o_bytes + test_length <= o_bytes_max) {
                            memcpy(o_bytes, h3zero_default_page, test_length);
                            o_bytes += test_length;
                        }
                        else {
                            o_bytes = NULL;
                        }
                    }
                }
            }

            if (o_bytes != NULL) {
                ret = picoquic_add_to_stream(cnx, stream_ctx->stream_id,
                    buffer, o_bytes - buffer,
                    (stream_ctx->echo_length == 0) ? 1 : 0);
                if (ret != 0) {
                    o_bytes = NULL;
                }
            }

            if (o_bytes == NULL) {
                ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INTERNAL_ERROR);
            }
            else if (stream_ctx->echo_length != 0) {
                ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1);
            }
        }
    }

    h3zero_delete_data_stream_state(&stream_state);

    return ret;
}

static int h3zero_server_callback_data(
    picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event,
    h3zero_server_callback_ctx_t* ctx)
{
    int ret = 0;
    h3zero_server_stream_ctx_t * stream_ctx = NULL;

    /* Find whether this is bidir or unidir stream */
    if (IS_BIDIR_STREAM_ID(stream_id)) {
        /* If client bidir stream, absorb data until end, then
         * parse the header */
        if (!IS_CLIENT_STREAM_ID(stream_id)) {
            /* Should never happen */
            ret = picoquic_stop_sending(cnx, stream_id, H3ZERO_WRONG_STREAM);
            picoquic_reset_stream(cnx, stream_id, H3ZERO_WRONG_STREAM);
        }
        else {
            /* Find or create stream context */
            stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 1);

            if (stream_ctx == NULL) {
                ret = picoquic_stop_sending(cnx, stream_id, H3ZERO_INTERNAL_ERROR);

                if (ret == 0) {
                    ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
                }
            }
            else {
                /* Push received bytes at selected offset */
                if (stream_ctx->received_length + length > sizeof(stream_ctx->frame)) {
                    /* Too long, unexpected */
                    ret = picoquic_stop_sending(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
                    picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
                }
                else {
                    memcpy(&stream_ctx->frame[stream_ctx->received_length], bytes, length);
                    stream_ctx->received_length += length;

                    if (fin_or_event == picoquic_callback_stream_fin) {
                        /* Parse the request header and process it. */
                        ret = h3zero_server_parse_request_frame(cnx, stream_ctx);
                    }
                }
            }
        }
    }
    else {
        /* TODO: If unidir stream, check what type of stream */
        /* TODO: If this is a control stream, and setting is not received yet,
         * wait for the setting frame, then process it and move the
         * state to absorbing.*/
         /* TODO: Beside control stream, we also absorb the push streams and
          * the reserved streams (*1F). In fact, we implement that by
          * just switching the state to absorbing. */
          /* For now, do nothing, just ignore the data */
    }

    return ret;
}

int h3zero_server_callback_prepare_to_send(picoquic_cnx_t* cnx,
    uint64_t stream_id, void* context, size_t space,
    h3zero_server_callback_ctx_t* ctx)
{

    int ret = -1;
    h3zero_server_stream_ctx_t * stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 0);

    if (stream_ctx == NULL) {
        ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
    }
    else if (stream_ctx->echo_sent < stream_ctx->echo_length) {
        uint8_t * buffer;
        size_t available = stream_ctx->echo_length - stream_ctx->echo_sent;
        int is_fin = 1;

        if (available > space) {
            available = space;
            is_fin = 0;
        }

        buffer = picoquic_provide_stream_data_buffer(context, available, is_fin, !is_fin);
        if (buffer != NULL) {
            /* TODO: fill buffer with some text */
            memset(buffer, 0x5A, available);
            stream_ctx->echo_sent += (uint32_t)available;
            ret = 0;
        }
    }

    return ret;
}

static int h3zero_server_init(picoquic_cnx_t* cnx)
{
    uint8_t decoder_stream_head = 0x03;
    uint8_t encoder_stream_head = 0x02;
    int ret = picoquic_add_to_stream(cnx, 3, h3zero_default_setting_frame, h3zero_default_setting_frame_size, 0);

    if (ret == 0) {
        /* set the stream #3 to be the next stream to write! */
        ret = picoquic_mark_high_priority_stream(cnx, 3, 1);
    }

    if (ret == 0) {
        /* set the stream 7 as the encoder stream, although we do not actually create dynamic codes. */
        ret = picoquic_add_to_stream(cnx, 7, &encoder_stream_head, 1, 0);
    }

    if (ret == 0) {
        /* set the stream 11 as the decoder stream, although we do not actually create dynamic codes. */
        ret = picoquic_add_to_stream(cnx, 11, &decoder_stream_head, 1, 0);
    }

    return ret;
}

/*
 * HTTP 3.0 demo server call back.
 */
int h3zero_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    int ret = 0;
    h3zero_server_callback_ctx_t* ctx = (h3zero_server_callback_ctx_t*)callback_ctx;
    h3zero_server_stream_ctx_t* stream_ctx = NULL;

    if (ctx == NULL) {
        ctx = h3zero_server_callback_create_context();
        if (ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else {
            picoquic_set_callback(cnx, h3zero_server_callback, ctx);
            ret = h3zero_server_init(cnx);
        }
    }

    if (ret == 0) {
        switch (fin_or_event) {
        case picoquic_callback_stream_data:
        case picoquic_callback_stream_fin:
            /* Data arrival on stream #x, maybe with fin mark */
            ret = h3zero_server_callback_data(cnx, stream_id, bytes, length, fin_or_event, ctx);
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            /* TODO: special case for uni streams. */
            stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 0);
            if (stream_ctx != NULL) {
                stream_ctx->status = h3zero_server_stream_status_finished;
            }
            picoquic_reset_stream(cnx, stream_id, 0);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            h3zero_server_callback_delete_context(ctx);
            picoquic_set_callback(cnx, h3zero_server_callback, NULL);
            break;
        case picoquic_callback_stream_gap:
            /* Gap indication, when unreliable streams are supported */
            stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 0);
            if (stream_ctx != NULL) {
                stream_ctx->status = h3zero_server_stream_status_finished;
            }
            picoquic_stop_sending(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
            break;
        case picoquic_callback_prepare_to_send:
            /* Used for active streams */
            ret = h3zero_server_callback_prepare_to_send(cnx, stream_id, (void*)bytes, length, ctx);
            break;
        case picoquic_callback_almost_ready:
        case picoquic_callback_ready:
            /* Check that the transport parameters are what Http3 expects */
            break;
        default:
            /* unexpected */
            break;
        }
    }

    return ret;
}

/* The HTTP 0.9 server code is used for early test of the QUIC transport functions. 
 * The simple server provides simple responses, precanned index files or randomly
 * generated content */

static const char* bad_request_message = "<html><head><title>Bad Request</title></head><body>Bad request. Why don't you try \"GET /doc-456789.html\"?</body></html>";

static char* strip_endofline(char* buf, size_t bufmax, char const* line)
{
    for (size_t i = 0; i < bufmax; i++) {
        int c = line[i];

        if (c == 0 || c == '\r' || c == '\n') {
            buf[i] = 0;
            break;
        }
        else {
            buf[i] = (char) c;
        }
    }

    buf[bufmax - 1] = 0;
    return buf;
}


static picoquic_h09_server_callback_ctx_t* first_server_callback_create_context()
{
    picoquic_h09_server_callback_ctx_t* ctx = (picoquic_h09_server_callback_ctx_t*)
        malloc(sizeof(picoquic_h09_server_callback_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(picoquic_h09_server_callback_ctx_t));
        ctx->first_stream = NULL;
        ctx->buffer = (uint8_t*)malloc(PICOQUIC_FIRST_RESPONSE_MAX);
        if (ctx->buffer == NULL) {
            free(ctx);
            ctx = NULL;
        }
        else {
            ctx->buffer_max = PICOQUIC_FIRST_RESPONSE_MAX;
        }
    }

    return ctx;
}

static void picoquic_h09_server_callback_delete_context(picoquic_h09_server_callback_ctx_t* ctx)
{
    picoquic_h09_server_stream_ctx_t* stream_ctx;

    while ((stream_ctx = ctx->first_stream) != NULL) {
        ctx->first_stream = stream_ctx->next_stream;
        free(stream_ctx);
    }

    if (ctx->buffer != NULL) {
        free(ctx->buffer);
        ctx->buffer = NULL;
    }

    free(ctx);
}

int picoquic_h09_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    picoquic_h09_server_callback_ctx_t* ctx = (picoquic_h09_server_callback_ctx_t*)callback_ctx;
    picoquic_h09_server_stream_ctx_t* stream_ctx = NULL;

    if (cnx->quic->F_log != NULL) {
        fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
        picoquic_log_time(cnx->quic->F_log, cnx, picoquic_current_time(), "", " : ");
        fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", %" PRIst " bytes, fin=%d (%s)\n",
            stream_id, length, fin_or_event, picoquic_log_fin_or_event_name(fin_or_event));
    }

    if (fin_or_event == picoquic_callback_prepare_to_send) {
        /* Unexpected call. */
        return -1;
    }

    if (fin_or_event == picoquic_callback_almost_ready ||
        fin_or_event == picoquic_callback_ready) {
        return 0;
    }

    if (fin_or_event == picoquic_callback_close ||
        fin_or_event == picoquic_callback_application_close ||
        fin_or_event == picoquic_callback_stateless_reset) {
        if (ctx != NULL) {
            picoquic_h09_server_callback_delete_context(ctx);
            picoquic_set_callback(cnx, picoquic_h09_server_callback, NULL);
        }
        fflush(stdout);
        return 0;
    }

    if (ctx == NULL) {
        picoquic_h09_server_callback_ctx_t* new_ctx = first_server_callback_create_context();
        if (new_ctx == NULL) {
            /* cannot handle the connection */
            if (cnx->quic->F_log != NULL) {
                fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                fprintf(cnx->quic->F_log, "Memory error, cannot allocate application context\n");
            }

            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return 0;
        }
        else {
            picoquic_set_callback(cnx, picoquic_h09_server_callback, new_ctx);
            ctx = new_ctx;
        }
    }

    stream_ctx = ctx->first_stream;

    /* if stream is already present, check its state. New bytes? */
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL) {
        stream_ctx = (picoquic_h09_server_stream_ctx_t*)
            malloc(sizeof(picoquic_h09_server_stream_ctx_t));
        if (stream_ctx == NULL) {
            /* Could not handle this stream */
            picoquic_reset_stream(cnx, stream_id, 500);
            return 0;
        }
        else {
            memset(stream_ctx, 0, sizeof(picoquic_h09_server_stream_ctx_t));
            stream_ctx->next_stream = ctx->first_stream;
            ctx->first_stream = stream_ctx;
            stream_ctx->stream_id = stream_id;
        }
    }

    /* verify state and copy data to the stream buffer */
    if (fin_or_event == picoquic_callback_stop_sending) {
        stream_ctx->status = picoquic_h09_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        if (cnx->quic->F_log != NULL) {
            printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            printf("Server CB, Stop Sending Stream: %" PRIu64 ", resetting the local stream.\n",
                stream_id);
        }
        return 0;
    }
    else if (fin_or_event == picoquic_callback_stream_reset) {
        stream_ctx->status = picoquic_h09_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        if (cnx->quic->F_log != NULL) {
            fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            fprintf(cnx->quic->F_log, "Server CB, Reset Stream: %" PRIu64 ", resetting the local stream.\n",
                stream_id);
        }
        return 0;
    }
    else if (stream_ctx->status == picoquic_h09_server_stream_status_finished || stream_ctx->command_length + length > (PICOQUIC_FIRST_COMMAND_MAX - 1)) {
        if (fin_or_event == picoquic_callback_stream_fin && length == 0) {
            /* no problem, this is fine. */
        }
        else {
            /* send after fin, or too many bytes => reset! */
            picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_STREAM_STATE_ERROR);
            if (cnx->quic->F_log != NULL) {
                fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", RESET, too long or after FIN\n",
                    stream_id);
            }
        }
        return 0;
    }
    else if (fin_or_event == picoquic_callback_stream_gap) {
        /* We do not support this, yet */
        stream_ctx->status = picoquic_h09_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
        if (cnx->quic->F_log != NULL) {
            fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", RESET, stream gaps not supported\n", stream_id);
        }
        return 0;
    }
    else if (fin_or_event == picoquic_callback_stream_data || fin_or_event == picoquic_callback_stream_fin) {
        int crlf_present = 0;

        if (length > 0) {
            memcpy(&stream_ctx->command[stream_ctx->command_length],
                bytes, length);
            stream_ctx->command_length += length;
            for (size_t i = 0; i < length; i++) {
                if (bytes[i] == '\r' || bytes[i] == '\n') {
                    crlf_present = 1;
                    break;
                }
            }
        }

        /* if FIN present, process request through http 0.9 */
        if ((fin_or_event == picoquic_callback_stream_fin || crlf_present != 0) && stream_ctx->response_length == 0) {
            char buf[256];

            stream_ctx->command[stream_ctx->command_length] = 0;
            /* if data generated, just send it. Otherwise, just FIN the stream. */
            stream_ctx->status = picoquic_h09_server_stream_status_finished;
            if (http0dot9_get(stream_ctx->command, stream_ctx->command_length,
                ctx->buffer, ctx->buffer_max, &stream_ctx->response_length)
                != 0) {
                if (cnx->quic->F_log != NULL) {
                    fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                    fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", Reply with bad request message after command: %s\n",
                        stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));
                }

                // picoquic_reset_stream(cnx, stream_id, 404);

                (void)picoquic_add_to_stream(cnx, stream_ctx->stream_id, (const uint8_t *)bad_request_message,
                    strlen(bad_request_message), 1);
            }
            else {
                if (cnx->quic->F_log != NULL) {
                    fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                    fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", Processing command: %s\n",
                        stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));
                }
                picoquic_add_to_stream(cnx, stream_id, ctx->buffer,
                    stream_ctx->response_length, 1);
            }
        }
        else if (stream_ctx->response_length == 0) {
            char buf[256];
            stream_ctx->command[stream_ctx->command_length] = 0;
            if (cnx->quic->F_log != NULL) {
                fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", Partial command: %s\n",
                    stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));
                fflush(cnx->quic->F_log);
            }
        }
    }
    else {
        /* Unknown event */
        stream_ctx->status = picoquic_h09_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
        if (cnx->quic->F_log != NULL) {
            fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", unexpected event\n", stream_id);
        }
        return 0;
    }

    /* that's it */
    return 0;
}

/* Generic callback. On first instantiation of a connection, will get the
 * negotiated ALPN, and provision the appropriate callback.
 */

int picoquic_demo_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    int ret = 0;
    picoquic_alpn_enum alpn_code = picoquic_alpn_undef;
    char const * alpn = picoquic_tls_get_negotiated_alpn(cnx);

    if (alpn != NULL) {
        alpn_code = picoquic_parse_alpn(alpn);
    }

    switch (alpn_code) {
    case picoquic_alpn_http_3:
        ret = h3zero_server_callback(cnx, stream_id, bytes, length, fin_or_event, callback_ctx);
        break;
    case picoquic_alpn_http_0_9:
    default:
        ret = picoquic_h09_server_callback(cnx, stream_id, bytes, length, fin_or_event, callback_ctx);
        break;
    }

    return ret;
}