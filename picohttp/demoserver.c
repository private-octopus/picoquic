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
        ctx->buffer = (uint8_t*)malloc(PICOHTTP_RESPONSE_MAX);
        if (ctx->buffer == NULL) {
            free(ctx);
            ctx = NULL;
        }
        else {
            ctx->buffer_max = PICOHTTP_RESPONSE_MAX;
        }
    }

    return ctx;
}

static void h3zero_server_callback_delete_context(h3zero_server_callback_ctx_t* ctx)
{
    picohttp_server_stream_ctx_t * stream_ctx;

    while ((stream_ctx = ctx->first_stream) != NULL) {
        ctx->first_stream = stream_ctx->next_stream;
        if (stream_ctx->path_callback != NULL) {
            (void)stream_ctx->path_callback(NULL, NULL, 0, picohttp_callback_reset, stream_ctx->path_callback_ctx, stream_ctx);
        }
        free(stream_ctx);
    }

    if (ctx->buffer != NULL) {
        free(ctx->buffer);
        ctx->buffer = NULL;
    }

    free(ctx);
}

static picohttp_server_stream_ctx_t * h3zero_find_or_create_stream(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    h3zero_server_callback_ctx_t* ctx,
    int should_create)
{
    picohttp_server_stream_ctx_t * stream_ctx = NULL;

    /* if stream is already present, check its state. New bytes? */
    stream_ctx = ctx->first_stream;
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL && should_create) {
        stream_ctx = (picohttp_server_stream_ctx_t*)
            malloc(sizeof(picohttp_server_stream_ctx_t));
        if (stream_ctx == NULL) {
            /* Could not handle this stream */
            picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
        }
        else {
            memset(stream_ctx, 0, sizeof(picohttp_server_stream_ctx_t));
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

static char const * demo_server_default_page = "\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML>\r\n<HEAD>\r\n<TITLE>\
Picoquic HTTP 3 service\
</TITLE>\r\n</HEAD><BODY>\r\n\
<h1>Simple HTTP 3 Responder</h1>\r\n\
<p>GET / or GET /index.html returns this text</p>\r\n\
<p>Get /NNNNN returns txt document of length NNNNN bytes(decimal)</p>\r\n\
<p>Any other command will result in an error, and an empty response.</p>\r\n\
<h1>Enjoy!</h1>\r\n\
</BODY></HTML>\r\n";

static char const * demo_server_post_response_header = "\
200 OK\r\n\
Content-Type: text/html\r\n\
\r\n";

static char const * demo_server_post_response_page = "\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML>\r\n<HEAD>\r\n<TITLE>\
Picoquic POST Response\
</TITLE>\r\n</HEAD><BODY>\r\n\
<h1>POST successful</h1>\r\n\
<p>Received %d bytes.\r\n\
</BODY></HTML>\r\n";

static int demo_server_parse_path(const uint8_t * path, size_t path_length, size_t * echo_size)
{
    /* TODO-POST: consider known URL for post from table? */
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

/* Processing of the request frame.
 * This function is called after the client's stream is closed,
 * after verifying that a request was received */

static int h3zero_server_process_request_frame(
    picoquic_cnx_t* cnx,
    picohttp_server_stream_ctx_t * stream_ctx,
    picoquic_demoserver_path_item_t* path_table,
    size_t path_table_nb)
{
    /* Prepare response header */
    uint8_t buffer[1024];
    uint8_t post_response[1024];
    uint8_t * o_bytes = &buffer[0];
    uint8_t * o_bytes_max = o_bytes + sizeof(buffer);
    size_t response_length = 0;
    int ret = 0;

    *o_bytes++ = h3zero_frame_header;
    o_bytes += 2; /* reserve two bytes for frame length */

    if (stream_ctx->stream_state.header.method != h3zero_method_get &&
        stream_ctx->stream_state.header.method != h3zero_method_post) {
        /* No such method supported -- error 405, header include "allow GET. POST" */
        o_bytes = h3zero_create_bad_method_header_frame(o_bytes, o_bytes_max);
    }
    else if (stream_ctx->stream_state.header.method == h3zero_method_get &&
        demo_server_parse_path(stream_ctx->stream_state.header.path, stream_ctx->stream_state.header.path_length, &stream_ctx->echo_length) != 0) {
        /* If unknown, 404 */
        o_bytes = h3zero_create_not_found_header_frame(o_bytes, o_bytes_max);
        /* TODO: consider known-url?data construct */
    }
    else {
        if (stream_ctx->stream_state.header.method == h3zero_method_post) {
            int path_item = picohttp_find_path_item(stream_ctx->stream_state.header.path, stream_ctx->stream_state.header.path_length, path_table, path_table_nb);
            if (path_item >= 0) {
                /* TODO-POST: move this code to post-fin callback.*/
                stream_ctx->path_callback(cnx, (uint8_t *) stream_ctx->stream_state.header.path, stream_ctx->stream_state.header.path_length, picohttp_callback_post, NULL, stream_ctx);
            }
            else {
                /* Prepare generic POST response */
                (void)picoquic_sprintf((char*)post_response, sizeof(post_response), &response_length, demo_server_post_response_page, (int)stream_ctx->post_received);
            }
            stream_ctx->echo_length = 0;
        }
        else {
            response_length = (stream_ctx->echo_length == 0) ?
                strlen(demo_server_default_page) : stream_ctx->echo_length;
        }
        /* If known, create response header frame */
        o_bytes = h3zero_create_response_header_frame(o_bytes, o_bytes_max,
            (stream_ctx->echo_length == 0) ? h3zero_content_type_text_html :
            h3zero_content_type_text_plain);
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
                o_bytes += ld; if (stream_ctx->echo_length == 0) {

                    if (o_bytes + response_length <= o_bytes_max) {
                        memcpy(o_bytes, (stream_ctx->stream_state.header.method == h3zero_method_post) ? post_response : (uint8_t *)demo_server_default_page, response_length);
                        o_bytes += response_length;
                    }
                    else {
                        o_bytes = NULL;
                    }
                }
            }
        }

        if (o_bytes != NULL) {
            ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id,
                buffer, o_bytes - buffer,
                (stream_ctx->echo_length == 0) ? 1 : 0, stream_ctx);
            if (ret != 0) {
                o_bytes = NULL;
            }
        }

        if (o_bytes == NULL) {
            ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INTERNAL_ERROR);
        }
        else if (stream_ctx->echo_length != 0) {
            ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
        }
    }

    return ret;
}

/* Server call back, data processing.
 * The bidir client streams can support either a GET or a POST command.
 * In all case, the stream is a set of frames.
 * For GET streams: a request frame, with possibly some extension frames.
 * For POST streams: a request frame, with a set of data frames.
 * In both cases, the first request frame is parsed, and then data is
 * read. The actual response is only sent when all data has been received.
 * For GET requests, receiving data frames is an error.
 * For get commands, the answer depends on the "path" property.
 * For POST commands, the answer depends on the amount of data.
 * Stream state include:
 * - Receiving frame
 * - waiting next frame
 * - receiving data frame
 */

static int h3zero_server_callback_data(
    picoquic_cnx_t* cnx, picohttp_server_stream_ctx_t * stream_ctx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event,
    h3zero_server_callback_ctx_t* ctx)
{
    int ret = 0;

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
            if (stream_ctx == NULL) {
                stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 1);
            }

            if (stream_ctx == NULL) {
                ret = picoquic_stop_sending(cnx, stream_id, H3ZERO_INTERNAL_ERROR);

                if (ret == 0) {
                    ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
                }
            }
            else {
                uint16_t error_found = 0;
                size_t available_data = 0;
                uint8_t * bytes_max = bytes + length;
                while (bytes < bytes_max) {
                    bytes = h3zero_parse_data_stream(bytes, bytes_max, &stream_ctx->stream_state, &available_data, &error_found);
                    if (bytes == NULL) {
                        ret = picoquic_close(cnx, error_found);
                        break;
                    }
                    else if (available_data > 0) {
                        /* Received data for a POST command. */
                        if (stream_ctx->path_callback != NULL) {
                            /* if known URL, pass the data to URL specific callback. */
                            ret = stream_ctx->path_callback(cnx, bytes, available_data, picohttp_callback_post_data, stream_ctx->path_callback_ctx, stream_ctx);
                        }
                        else {
                            stream_ctx->post_received += available_data;
                            bytes += available_data;
                        }
                    }
                }
                
                if (fin_or_event == picoquic_callback_stream_fin) {
                    /* Process the request header. */
                    if (stream_ctx->stream_state.header_found) {
                        /* TODO-POST: verify that request is parsed on the fly */
                        ret = h3zero_server_process_request_frame(cnx, stream_ctx, ctx->path_table, ctx->path_table_nb);
                    }
                    else {
                        /* Unexpected end of stream before the header is received */
                        ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_MALFORMED_FRAME(h3zero_frame_header));
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
    uint64_t stream_id, picohttp_server_stream_ctx_t * stream_ctx,
    void * context, size_t space, h3zero_server_callback_ctx_t* ctx)
{

    int ret = -1;

    if (stream_ctx == NULL) {
        stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 0);
    }

    if (stream_ctx == NULL) {
        ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
    }
    else {
        if (stream_ctx->path_callback != NULL) {
            /* Get data from callback context of specific URL */
            ret = stream_ctx->path_callback(cnx, context, space, picohttp_callback_provide_data, stream_ctx->path_callback_ctx, stream_ctx);
        }
        else {
            /* default reply for known URL */
            ret = demo_client_prepare_to_send(context, space, stream_ctx->echo_length, &stream_ctx->echo_sent);
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

int picohttp_find_path_item(const uint8_t * path, size_t path_length, const picoquic_demoserver_path_item_t * path_table, size_t path_table_nb)
{
    size_t i = 0;

    while (i < path_table_nb) {
        if (path_length >= path_table[i].path_length && memcmp(path, path_table[i].path, path_table[i].path_length) == 0){
            return (int)i;
        }
        i++;
    }
    return -1;
}

/*
 * HTTP 3.0 demo server call back.
 */
int h3zero_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    h3zero_server_callback_ctx_t* ctx = (h3zero_server_callback_ctx_t*)callback_ctx;
    picohttp_server_stream_ctx_t* stream_ctx = (picohttp_server_stream_ctx_t*)v_stream_ctx;

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
            ret = h3zero_server_callback_data(cnx, stream_ctx, stream_id, bytes, length, fin_or_event, ctx);
            break;
        case picoquic_callback_stream_reset: /* Client reset stream #x */
        case picoquic_callback_stop_sending: /* Client asks server to reset stream #x */
            /* TODO: special case for uni streams. */
            if (stream_ctx == NULL) {
                stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 0);
            }
            if (stream_ctx != NULL) {
                /* reset post callback. */
                if (stream_ctx->path_callback != NULL) {
                    ret = stream_ctx->path_callback(NULL, NULL, 0, picohttp_callback_reset, stream_ctx->path_callback_ctx, stream_ctx);
                }
                stream_ctx->status = picohttp_server_stream_status_finished;
            }
            picoquic_reset_stream(cnx, stream_id, 0);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            h3zero_server_callback_delete_context(ctx);
            picoquic_set_callback(cnx, h3zero_server_callback, NULL);
            break;
        case picoquic_callback_version_negotiation:
            break;
        case picoquic_callback_stream_gap:
            /* Gap indication, when unreliable streams are supported */
            if (stream_ctx == NULL) {
                stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 0);
            }
            if (stream_ctx != NULL) {
                if (stream_ctx->path_callback != NULL) {
                    ret = stream_ctx->path_callback(NULL, NULL, 0, picohttp_callback_reset, stream_ctx->path_callback_ctx, stream_ctx);
                }
                stream_ctx->status = picohttp_server_stream_status_finished;
            }
            picoquic_stop_sending(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
            break;
        case picoquic_callback_prepare_to_send:
            /* Used for active streams */
            ret = h3zero_server_callback_prepare_to_send(cnx, stream_id, stream_ctx, (void*)bytes, length, ctx);
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

static const char* bad_request_message = "<html><head><title>Bad Request</title></head><body>Bad request. Why don't you try \"GET /456789\"?</body></html>";

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
    }

    return ctx;
}

static void picoquic_h09_server_callback_delete_context(picoquic_h09_server_callback_ctx_t* ctx)
{
    picohttp_server_stream_ctx_t* stream_ctx;

    while ((stream_ctx = ctx->first_stream) != NULL) {
        ctx->first_stream = stream_ctx->next_stream;
        free(stream_ctx);
    }

    free(ctx);
}


static int picoquic_h09_server_parse_method(uint8_t* command, size_t command_length, size_t * consumed)
{
    int byte_index = 0;
    int ret = -1;

    if (command_length >= 3 && (command[0] == 'G' || command[0] == 'g') && (command[1] == 'E' || command[1] == 'e') && (command[2] == 'T' || command[2] == 't')) {
        ret = 0;
        byte_index = 3;
    } else if (command_length >= 4 && (command[0] == 'P' || command[0] == 'p') && (command[1] == 'O' || command[1] == 'o') && (command[2] == 'S' || command[2] == 's') && (command[3] == 'T' || command[3] == 't')) {
        ret = 1;
        byte_index = 4;
    }

    if (consumed) {
        *consumed = byte_index;
    }

    return ret;
}

static void picoquic_h09_server_parse_protocol(uint8_t* command, size_t command_length, int * proto, size_t * consumed)
{
    size_t byte_index = (command_length > 0)?command_length -1:0;
    size_t last_proto_index;
    int space_count = 0;

    *proto = 0;

    /* skip white space at the end */
    for (;;) {
        int c = command[byte_index];

        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            space_count++;
            if (byte_index > 0) {
                byte_index--;
            }
            else {
                break;
            }
        }
        else {
            break;
        }
    }
    *consumed = space_count;
    last_proto_index = byte_index;

    /* find non space char */
    while (byte_index > 0) {
        int c = command[byte_index];

        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            byte_index++;
            break;
        }
        else {
            byte_index--;
        }
    }

    /* Parse protocol version */
    if (last_proto_index - byte_index == 7 &&
        command[byte_index + 6] == '.' &&
        command[byte_index + 4] == '/' &&
        (command[byte_index + 3] == 'p' || command[byte_index + 3] == 'P') &&
        (command[byte_index + 2] == 't' || command[byte_index + 2] == 'T') &&
        (command[byte_index + 1] == 't' || command[byte_index + 1] == 'T') &&
        (command[byte_index] == 'h' || command[byte_index] == 'H')) {
        int bad_version = 0;
        if (command[byte_index + 5] == '1' && (command[byte_index + 7] == '0' || command[byte_index + 7] == '1')) {
            *proto = 1;
        }
        else if (command[byte_index + 5] == '0' && command[byte_index + 7] == '9') {
            *proto = 0;
        }
        else {
            bad_version = 1;
        }

        if (!bad_version) {
            *consumed += 8;

            if (byte_index > 0) {
                byte_index--;
                while (byte_index > 0 && (command[byte_index] == ' ' || command[byte_index] == '\t')) {
                    byte_index--;
                    *consumed += 1;
                }
            }
        }
    }
}

static int picoquic_h09_server_process_command(uint8_t* command, size_t command_length, int * method, size_t * echo_length)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t consumed;
    int proto;


    *echo_length = 0;

    /* Find first line of command, ignore the rest */
    for (size_t i = 0; i < command_length; i++) {
        if (command[i] == '\r' || command[i] == '\n') {
            command_length = i;
            break;
        }
    }

    /* Parse protocol version and strip white spaces at the end of the command */
    picoquic_h09_server_parse_protocol(command, command_length, &proto, &consumed);
    command_length -= consumed;

    /* parse the method */
    *method = picoquic_h09_server_parse_method(command, command_length, &consumed);

    if (*method < 0) {
        ret = -1;
    } else {
        byte_index = consumed;

        /* Skip at list one space */
        while (command_length > byte_index && (command[byte_index] == ' ' || command[byte_index] == '\t')) {
            byte_index++;
        }

        if (byte_index >= command_length) {
            ret = -1;
        }
    }

    /* if the input is in incorrect form, return 0 length error message */
    if (ret == 0 && *method != 1) {
        ret = demo_server_parse_path(command + byte_index, command_length - byte_index, echo_length);
    }

    return ret;
}

/*
 * Process the incoming data. 
 * We can expect the following:
 * - Initial command line: {GET|POST} <path> [HTTP/{0.9|1.0|1.1}] /r/n
 * - Additional command lines concluded with /r/n
 * - Empty line: /r/n
 * - Posted data
 * This can be interrupted at any time by a FIN mark. In the case of the 
 * GET command, there should not be any posted data. 
 * The server should parse the initial line to gather the type of command
 * and the name of the document. It should then parse data until the fin
 * mark is received.
 * The additional headers are ignored.
 * The amount of posted data is counted, will be used to prepare the response.
 *
 * The response is sent after the FIN is received (POST) or after the 
 * header line is fully parsed (GET).
 */

int picoquic_h09_server_process_data(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, picohttp_server_stream_ctx_t* stream_ctx)
{
    int ret = 0;
    size_t processed = 0;

    while (processed < length) {
        if (stream_ctx->status == picohttp_server_stream_status_none) {
            /* If the command has not been received yet, try to process it */
            int crlf_present = 0;

            while (processed < length && crlf_present == 0) {
                if (bytes[processed] == '\r' || bytes[processed] == '\n') {
                    crlf_present = 1;
                }
                else if (stream_ctx->command_length < sizeof(stream_ctx->frame)) {
                    stream_ctx->frame[stream_ctx->command_length++] = bytes[processed];
                }
                else {
                    /* Too much data */
                    crlf_present = 1;
                }
                processed++;
            }

            if (crlf_present) {
                stream_ctx->status = picohttp_server_stream_status_crlf;
            }

            if (crlf_present || fin_or_event == picoquic_callback_stream_fin) {
                /* Parse the command */
                stream_ctx->method = picoquic_h09_server_parse_method(stream_ctx->frame, stream_ctx->command_length, NULL);
            }
        }
        else if (stream_ctx->status == picohttp_server_stream_status_crlf) {
            if (bytes[processed] == '\n') {
                /* empty line */
                stream_ctx->status = picohttp_server_stream_status_receiving;
            }
            else if (bytes[processed] != '\r') {
                stream_ctx->status = picohttp_server_stream_status_header;
            }
            processed++;
        }
        else if (stream_ctx->status == picohttp_server_stream_status_header) {
            if (bytes[processed] == '\n') {
                stream_ctx->status = picohttp_server_stream_status_crlf;
            }
            processed++;
        }
        else if (stream_ctx->status == picohttp_server_stream_status_receiving) {
            if (stream_ctx->path_callback != NULL) {
                /* pass data to selected API */
                ret = stream_ctx->path_callback(cnx, bytes + processed, length - processed, picohttp_callback_post_data, stream_ctx->path_callback_ctx, stream_ctx);
                /* TODO-POST: how to handle errors ?*/
            }
            else {
                /* default processing: ignore the data, just count the bytes */
                stream_ctx->post_received += length - processed;
                processed = length;
            }
        }
        else {
            /* No more processing expected on this stream. */
            processed = length;
        }
    }

    /* if FIN present, process request through http 0.9 */
    if (fin_or_event == picoquic_callback_stream_fin || (stream_ctx->method == 0 && stream_ctx->status == picohttp_server_stream_status_crlf)) {
        char buf[256];

        stream_ctx->frame[stream_ctx->command_length] = 0;
        /* if data generated, just send it. Otherwise, just FIN the stream. */
        stream_ctx->status = picohttp_server_stream_status_finished;

        if (picoquic_h09_server_process_command(stream_ctx->frame, stream_ctx->command_length, &stream_ctx->method, &stream_ctx->echo_length)
            != 0) {
            if (cnx->quic->F_log != NULL) {
                fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", Reply with bad request message after command: %s\n",
                    stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->frame));
            }

            stream_ctx->response_length = strlen(bad_request_message);
            (void)picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, (const uint8_t *)bad_request_message,
                stream_ctx->response_length, 1, (void *)stream_ctx);
        } else {
            if (cnx->quic->F_log != NULL) {
                fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", Processing command: %s\n",
                    stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->frame));
            }
            if (stream_ctx->echo_length > 0) {
                picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, (void *)stream_ctx);
            }
            else if (stream_ctx->method == 1) {
                uint8_t post_response[512];

                if (stream_ctx->path_callback != NULL) {
                    /* TODO-POST: Process the response to a POST.
                     * We have to distinguish three scenarios:
                     * - Something went wrong => return an error.
                     * - Large response => support callbacks for read. By convention, ret = 0?
                     * - Short response => provide it now.
                     */
                    ret = stream_ctx->path_callback(cnx, post_response, sizeof(post_response), picohttp_callback_post_fin, stream_ctx->path_callback_ctx, stream_ctx);
                    if (ret < 0) {
                        /* TODO-POST: process an error */
                    }
                    else{
                        /* TODO-POST: format the post response header -- get content type from plug in context */
                        /* content length only present if known. */
                        /* Push response header */

                        if (ret > 0 && ret < sizeof(post_response)) {
                            /* For short responses, post directly. 
                             * TODO-POST: for long responses, we expect that the application
                             * will have set a data provision shortcut. Verify that! */
                            picoquic_add_to_stream_with_ctx(cnx, stream_id, post_response,
                                stream_ctx->response_length, 1, (void*)stream_ctx);
                        }
                    }
                }
                else {
                    /* Default processing, simple message with just a length received field. */
                    (void)picoquic_sprintf((char *)post_response, sizeof(post_response), &stream_ctx->response_length, demo_server_post_response_page, (int)stream_ctx->post_received);

                    picoquic_add_to_stream_with_ctx(cnx, stream_id, (uint8_t*)demo_server_post_response_header,
                        strlen(demo_server_post_response_header), 0, (void*)stream_ctx);
                    picoquic_add_to_stream_with_ctx(cnx, stream_id, (uint8_t*)post_response,
                        stream_ctx->response_length, 1, (void*)stream_ctx);
                }
                if (cnx->quic->F_log != NULL) {
                    fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                    fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", %s, %d data received\n",
                        stream_id, strip_endofline(buf, sizeof(buf), (char*)& stream_ctx->frame), (int)stream_ctx->post_received);
                }

            }
            else {
                /* Send the canned index.html response */
                stream_ctx->response_length = strlen(demo_server_default_page);
                picoquic_add_to_stream_with_ctx(cnx, stream_id, (uint8_t *)demo_server_default_page,
                    stream_ctx->response_length, 1, (void *)stream_ctx);
            } 
        }
    }
    else if (stream_ctx->response_length == 0 && stream_ctx->echo_length == 0 && stream_ctx->method == 0) {
        char buf[256];
        stream_ctx->frame[stream_ctx->command_length] = 0;
        if (cnx->quic->F_log != NULL) {
            fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", Partial command: %s\n",
                stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->frame));
            fflush(cnx->quic->F_log);
        }
    }

    return ret;
}

int picoquic_h09_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    picoquic_h09_server_callback_ctx_t* ctx = (picoquic_h09_server_callback_ctx_t*)callback_ctx;
    picohttp_server_stream_ctx_t* stream_ctx = (picohttp_server_stream_ctx_t*)v_stream_ctx;

    if (cnx->quic->F_log != NULL) {
        fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
        picoquic_log_time(cnx->quic->F_log, cnx, picoquic_current_time(), "", " : ");
        fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", %" PRIst " bytes, fin=%d (%s)\n",
            stream_id, length, fin_or_event, picoquic_log_fin_or_event_name(fin_or_event));
    }

    switch (fin_or_event) {
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        return 0;
    case picoquic_callback_version_negotiation:
        return 0;
    case picoquic_callback_close:
    case picoquic_callback_application_close:
    case picoquic_callback_stateless_reset:
            if (ctx != NULL) {
                picoquic_h09_server_callback_delete_context(ctx);
                picoquic_set_callback(cnx, picoquic_h09_server_callback, NULL);
            }
            fflush(stdout);
            return 0;
    default:
        break;
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

    if (stream_ctx == NULL) {
        stream_ctx = ctx->first_stream;

        /* if stream is already present, check its state. New bytes? */
        while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
            stream_ctx = stream_ctx->next_stream;
        }

        if (stream_ctx == NULL) {
            stream_ctx = (picohttp_server_stream_ctx_t*)
                malloc(sizeof(picohttp_server_stream_ctx_t));
            if (stream_ctx == NULL) {
                /* Could not handle this stream */
                picoquic_reset_stream(cnx, stream_id, 500);
                return 0;
            }
            else {
                memset(stream_ctx, 0, sizeof(picohttp_server_stream_ctx_t));
                stream_ctx->next_stream = ctx->first_stream;
                ctx->first_stream = stream_ctx;
                stream_ctx->stream_id = stream_id;
            }
        }
    }

    switch (fin_or_event) {
    case picoquic_callback_stop_sending:
        /* TODO-POST: notify callback. */
        stream_ctx->status = picohttp_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        if (cnx->quic->F_log != NULL) {
            printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            printf("Server CB, Stop Sending Stream: %" PRIu64 ", resetting the local stream.\n",
                stream_id);
        }
        return 0;
    case picoquic_callback_stream_reset:
        /* TODO-POST: notify callback. */
        stream_ctx->status = picohttp_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        if (cnx->quic->F_log != NULL) {
            fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            fprintf(cnx->quic->F_log, "Server CB, Reset Stream: %" PRIu64 ", resetting the local stream.\n",
                stream_id);
        }
        return 0;
    case picoquic_callback_prepare_to_send:
            /* Used for active streams */
            if (stream_ctx == NULL) {
                /* Unexpected */
                picoquic_reset_stream(cnx, stream_id, 0);
                return 0;
            }
            else {
                /* TODO-POST: notify callback. */
                return demo_client_prepare_to_send((void*)bytes, length, stream_ctx->echo_length, &stream_ctx->echo_sent);
            }
    default:
        break;
    }

    if (fin_or_event == picoquic_callback_stream_gap) {
        /* We do not support this, yet */
        stream_ctx->status = picohttp_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
        if (cnx->quic->F_log != NULL) {
            fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", RESET, stream gaps not supported\n", stream_id);
        }
        return 0;
    }
    else if (fin_or_event == picoquic_callback_stream_data || fin_or_event == picoquic_callback_stream_fin) {
        /* Data processing includes setting up post/get callback if needed */
        if (picoquic_h09_server_process_data(cnx, stream_id, bytes, length, fin_or_event, stream_ctx)) {
            /* something bad happened. */
        }
    } else {
        /* Unknown event */
        /* TODO-POST: notify callback. */
        stream_ctx->status = picohttp_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
        if (cnx->quic->F_log != NULL) {
            fprintf(cnx->quic->F_log, "%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            fprintf(cnx->quic->F_log, "Server CB, Stream: %" PRIu64 ", unexpected event\n", stream_id);
        }
    }

    /* that's it */
    return 0;
}

/* Generic callback. On first instantiation of a connection, will get the
 * negotiated ALPN, and provision the appropriate callback.
 */

int picoquic_demo_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    picoquic_alpn_enum alpn_code = picoquic_alpn_undef;
    char const * alpn = picoquic_tls_get_negotiated_alpn(cnx);

    if (alpn != NULL) {
        alpn_code = picoquic_parse_alpn(alpn);
    }

    switch (alpn_code) {
    case picoquic_alpn_http_3:
        ret = h3zero_server_callback(cnx, stream_id, bytes, length, fin_or_event, callback_ctx, v_stream_ctx);
        break;
    case picoquic_alpn_http_0_9:
    default:
        ret = picoquic_h09_server_callback(cnx, stream_id, bytes, length, fin_or_event, callback_ctx, v_stream_ctx);
        break;
    }

    return ret;
}

/* Handling of post callback */
void picohttp_set_post_callback(picohttp_server_stream_ctx_t* stream_ctx,
    picohttp_post_data_cb_fn callback_fn, void* callback_ctx)
{
    stream_ctx->path_callback = callback_fn;
    stream_ctx->path_callback_ctx = callback_ctx;
}

/* Sample callback used for demonstrating the callback API.
 * The transaction returns the MD5 of the posted data */

typedef struct st_picohttp_demo_post_sha256_ctx_t {
    void* hash_context;
    uint8_t buf[PICOQUIC_HASH_SIZE_MAX];
} picohttp_demo_post_ctx_t;

int picohttp_demo_post_sha256_callback(picoquic_cnx_t* cnx,
    uint8_t* bytes, size_t length,
    picohttp_call_back_event_t event, void* post_ctx, picohttp_server_stream_ctx_t * stream_ctx)
{
    int ret = 0;
    picohttp_demo_post_ctx_t* ctx = (picohttp_demo_post_ctx_t*)post_ctx;

    switch (event) {
    case picohttp_callback_get: /* Received a get command */
        break;
    case picohttp_callback_post: /* Received a post command */
        if (ctx == NULL) {
            ctx = (picohttp_demo_post_ctx_t*)malloc(sizeof(picohttp_demo_post_ctx_t));
            if (ctx == NULL) {
                /* cannot handle the stream -- TODO: reset stream? */
                return -1;
            }
            else {
                memset(ctx->buf, 0, PICOQUIC_HASH_SIZE_MAX);
                ctx->hash_context = picoquic_hash_create("SHA256");
                picohttp_set_post_callback(stream_ctx, picohttp_demo_post_sha256_callback, ctx);
            }
        }
        else {
            /* unexpected. Should not have a context here */
            return -1;
        }
        break;
    case picohttp_callback_post_data: /* Data received from peer on stream N */
        /* Add data to the hash context */
        if (ctx == NULL || ctx->hash_context == NULL) {
            ret = -1;
        }
        else {
            picoquic_hash_update(bytes, length, ctx->hash_context);
        }
        break;
    case picohttp_callback_post_fin: /* All posted data have been received */
        /* Finalize the hash context */
        if (ctx == NULL || ctx->hash_context == NULL) {
            ret = -1;
        }
        else {
            picoquic_hash_finalize(ctx->buf, ctx->hash_context);
            ctx->hash_context = NULL;
        }
        break;
    case picohttp_callback_provide_data:
        /* TODO-POST: provide data. Unexpected for this specific callback. */
        ret = -1;
        break;
    case picohttp_callback_reset: /* stream is abandoned */
        picohttp_set_post_callback(stream_ctx, NULL, NULL);
        if (ctx != NULL){
            if (ctx->hash_context != NULL) {
                picoquic_hash_finalize(ctx->buf, ctx->hash_context);
                ctx->hash_context = NULL;
            }
            free(ctx);
        }
        break;
    default:
        ret = -1;
        break;
    }

    return ret;
}