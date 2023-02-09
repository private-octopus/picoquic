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
#include <picotls.h>
#include "picosplay.h"
#include "picoquic_internal.h"
#include "tls_api.h"
#include "h3zero.h"
#include "democlient.h"
#include "demoserver.h"
#include "siduck.h"
#include "quicperf.h"

/* Stream context splay management */

static int64_t picohttp_stream_node_compare(void *l, void *r)
{
    /* Stream values are from 0 to 2^62-1, which means we are not worried with rollover */
    return ((picohttp_server_stream_ctx_t*)l)->stream_id - ((picohttp_server_stream_ctx_t*)r)->stream_id;
}

static picosplay_node_t * picohttp_stream_node_create(void * value)
{
    return &((picohttp_server_stream_ctx_t *)value)->http_stream_node;
}

static void * picohttp_stream_node_value(picosplay_node_t * node)
{
    return (void*)((char*)node - offsetof(struct st_picohttp_server_stream_ctx_t, http_stream_node));
}

static void picohttp_clear_stream_ctx(picohttp_server_stream_ctx_t* stream_ctx)
{
    if (stream_ctx->file_path != NULL) {
        free(stream_ctx->file_path);
        stream_ctx->file_path = NULL;
    }
    if (stream_ctx->F != NULL) {
        stream_ctx->F = picoquic_file_close(stream_ctx->F);
    }

    if (stream_ctx->path_callback != NULL) {
        (void)stream_ctx->path_callback(NULL, NULL, 0, picohttp_callback_reset, stream_ctx);
    }

    if (stream_ctx->is_h3) {
        h3zero_delete_data_stream_state(&stream_ctx->ps.stream_state);
    }
    else {
        if (stream_ctx->ps.hq.path != NULL) {
            free(stream_ctx->ps.hq.path);
        }
    }
}

static void picohttp_stream_node_delete(void * tree, picosplay_node_t * node)
{
    picohttp_server_stream_ctx_t * stream_ctx = picohttp_stream_node_value(node);

    picohttp_clear_stream_ctx(stream_ctx);

    free(stream_ctx);
}

void h3zero_delete_stream(picosplay_tree_t * http_stream_tree, picohttp_server_stream_ctx_t* stream_ctx)
{
    picosplay_delete(http_stream_tree, &stream_ctx->http_stream_node);
}

static picohttp_server_stream_ctx_t* picohttp_find_stream(picosplay_tree_t * stream_tree, uint64_t stream_id)
{
    picohttp_server_stream_ctx_t * ret = NULL;
    picohttp_server_stream_ctx_t target;
    target.stream_id = stream_id;
    picosplay_node_t * node = picosplay_find(stream_tree, (void*)&target);
    
    if (node != NULL) {
        ret = (picohttp_server_stream_ctx_t *)picohttp_stream_node_value(node);
    }

    return ret;
}

picohttp_server_stream_ctx_t * h3zero_find_or_create_stream(
    picoquic_cnx_t* cnx,
    uint64_t stream_id,
    picosplay_tree_t * stream_tree,
    int should_create,
    int is_h3)
{
    picohttp_server_stream_ctx_t * stream_ctx = picohttp_find_stream(stream_tree, stream_id);

    /* if stream is already present, check its state. New bytes? */

    if (stream_ctx == NULL && should_create) {
        stream_ctx = (picohttp_server_stream_ctx_t*)
            malloc(sizeof(picohttp_server_stream_ctx_t));
        if (stream_ctx == NULL) {
            /* Could not handle this stream */
            picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
        }
        else {
            memset(stream_ctx, 0, sizeof(picohttp_server_stream_ctx_t));
            stream_ctx->stream_id = stream_id;
            stream_ctx->is_h3 = is_h3;
            picosplay_insert(stream_tree, stream_ctx);
        }
    }

    return stream_ctx;
}

/*
 * Create and delete server side connection context
 */

void h3zero_init_stream_tree(picosplay_tree_t * h3_stream_tree)
{
    picosplay_init_tree(h3_stream_tree, picohttp_stream_node_compare, picohttp_stream_node_create, picohttp_stream_node_delete, picohttp_stream_node_value);
}

static h3zero_server_callback_ctx_t* h3zero_server_callback_create_context(picohttp_server_parameters_t* param)
{
    h3zero_server_callback_ctx_t* ctx = (h3zero_server_callback_ctx_t*)
        malloc(sizeof(h3zero_server_callback_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(h3zero_server_callback_ctx_t));

        h3zero_init_stream_tree(&ctx->h3_stream_tree);

        if (param != NULL) {
            ctx->path_table = param->path_table;
            ctx->path_table_nb = param->path_table_nb;
            ctx->web_folder = param->web_folder;
        }
    }

    return ctx;
}

static void h3zero_server_callback_delete_context(h3zero_server_callback_ctx_t* ctx)
{
    picosplay_empty_tree(&ctx->h3_stream_tree);

    free(ctx);
}


/*
 * Incoming data call back.
 * Create context if not yet present.
 * Create stream context if not yet present.
 * Different behavior for unidir and bidir.
 */

char const * h3zero_server_default_page = "\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML>\r\n<HEAD>\r\n<TITLE>\
Picoquic HTTP 3 service\
</TITLE>\r\n</HEAD><BODY>\r\n\
<h1>Simple HTTP 3 Responder</h1>\r\n\
<p>GET / or GET /index.html returns this text</p>\r\n\
<p>Get /NNNNN returns txt document of length NNNNN bytes(decimal)</p>\r\n\
<p>Any other command will result in an error, and an empty response.</p>\r\n\
<h1>Enjoy!</h1>\r\n\
</BODY></HTML>\r\n";

char const * h3zero_server_post_response_page = "\
<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\r\n<HTML>\r\n<HEAD>\r\n<TITLE>\
Picoquic POST Response\
</TITLE>\r\n</HEAD><BODY>\r\n\
<h1>POST successful</h1>\r\n\
<p>Received %d bytes.\r\n\
</BODY></HTML>\r\n";


/* Sanity check of path name to prevent directory traversal.
 * We use a simple command that check for file names mae of alpha,
 * num, hyphens and underlines, plus non repeated dots */
int demo_server_is_path_sane(const uint8_t* path, size_t path_length)
{
    int ret = 0;
    size_t i = 0;
    int past_is_dot = 0;
    int nb_good = 0;

    if (path[0] == '/') {
        i++;
    }
    else {
        ret = -1;
    }

    for (; ret == 0 && i < path_length; i++) {
        int c = path[i];
        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_') {
            nb_good++;
            past_is_dot = 0;
        }
        else if (c == '/' && i < path_length - 1 && nb_good > 0) {
            nb_good++;
        }
        else if (c == '.' && !past_is_dot && nb_good > 0){
            past_is_dot = 1;
        }
        else {
            ret = -1;
        }
    }

    if (ret == 0 && nb_good == 0) {
        ret = -1;
    }

    return ret;
}

int demo_server_try_file_path(const uint8_t* path, size_t path_length, uint64_t* echo_size,
    char** file_path, char const* web_folder, int * file_error)
{
    int ret = -1;
    size_t len = strlen(web_folder);
    size_t file_name_len = len + path_length + 1;
    char* file_name = malloc(file_name_len);
    FILE* F;

    if (file_name != NULL && demo_server_is_path_sane(path, path_length) == 0) {
        memcpy(file_name, web_folder, len);
#ifdef _WINDOWS
        if (len == 0 || file_name[len - 1] != '\\') {
            file_name[len] = '\\';
            len++;
        }
#else
        if (len == 0 || file_name[len - 1] != '/') {
            file_name[len] = '/';
            len++;
        }
#endif
        memcpy(file_name + len, path+1, path_length-1);
        len += path_length - 1;
        file_name[len] = 0;

        F = picoquic_file_open_ex(file_name, "rb", file_error);

        if (F != NULL) {
            long sz;
            fseek(F, 0, SEEK_END);
            sz = ftell(F);

            if (sz > 0) {
                *echo_size = (size_t)sz;
                fseek(F, 0, SEEK_SET);
                ret = 0;
                *file_path = file_name;
            }
            picoquic_file_close(F);
        }
    }

    if (ret != 0 && file_name != NULL){
        free(file_name);
    }

    return ret;
}

int h3zero_server_parse_path(const uint8_t * path, size_t path_length, uint64_t * echo_size, 
    char ** file_path, char const * web_folder, int * file_error)
{
    int ret = 0;

    *file_error = 0;

    if (path != NULL && path_length == 1 && path[0] == '/') {
        /* Redirect the root requests to the default index so it can be read from file if file is present */
        path = (const uint8_t *)"/index.html";
        path_length = 11;
    }

    *echo_size = 0;
    if (path == NULL || path_length == 0 || path[0] != '/') {
        ret = -1;
    }
    else if (web_folder != NULL && demo_server_try_file_path(path, path_length, echo_size,
        file_path, web_folder, file_error) == 0) {
        ret = 0;
    }
    else if (path_length > 1 && (path_length != 11 || memcmp(path, "/index.html", 11) != 0)) {
        uint64_t x = 0;
        for (size_t i = 1; i < path_length; i++) {
            if (path[i] < '0' || path[i] > '9') {
                ret = -1;
                break;
            }
            x *= 10;
            x += path[i] - '0';
            if (x > (UINT64_MAX >> 2)) {
                /* required length is more than 62 bits */
                ret = -1;
                break;
            }
        }

        if (ret == 0) {
            *echo_size = x;
        }
    }

    return ret;
}

/* Prepare to send. This is the same code as on the client side, except for the
 * delayed opening of the data file */
int h3zero_server_prepare_to_send(void* context, size_t space, picohttp_server_stream_ctx_t* stream_ctx)
{
    int ret = 0;

    if (stream_ctx->F == NULL && stream_ctx->file_path != NULL) {
        stream_ctx->F = picoquic_file_open(stream_ctx->file_path, "rb");
        if (stream_ctx->F == NULL) {
            ret = -1;
        }
    }

    if (ret == 0) {
        ret = demo_client_prepare_to_send(context, space, stream_ctx->echo_length, &stream_ctx->echo_sent,
            stream_ctx->F);
    }

    return ret;
}

/* TODO:
 * - Establish processing of CONNECT
 * 
 * Server side logic:
 * - State = h3_receive_header: accumulate bytes until header is fully received.
 *         when header is received, process it.
 *         if CONNECT, may receive a connect data frame instead.
 * - State = h3_receive_data:
 *         receive incoming data after the header.
 *         expect data frames. pass content of data frames to application.
 *         generate an error if data is not expected (GET, CONNECT-control, server side).
 * - State = h3_received_fin:
 *         end of receiving data.
 *         for POST: finalize the response
 *         for CONNECT: close the context.
 */


/* Processing of the request frame.
 * This function is called after the client's stream is closed,
 * after verifying that a request was received */

static int h3zero_server_process_request_frame(
    picoquic_cnx_t* cnx,
    picohttp_server_stream_ctx_t * stream_ctx,
    h3zero_server_callback_ctx_t * app_ctx)
{
    /* Prepare response header */
    uint8_t buffer[1024];
    uint8_t post_response[512];
    uint8_t * o_bytes = &buffer[0];
    uint8_t * o_bytes_max = o_bytes + sizeof(buffer);
    uint64_t response_length = 0;
    int ret = 0;
    int file_error = 0;

    *o_bytes++ = h3zero_frame_header;
    o_bytes += 2; /* reserve two bytes for frame length */

    if (stream_ctx->ps.stream_state.header.method == h3zero_method_get) {
        /* Manage GET */
        if (h3zero_server_parse_path(stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length,
            &stream_ctx->echo_length, &stream_ctx->file_path, app_ctx->web_folder, &file_error) != 0) {
            char log_text[256];
            picoquic_log_app_message(cnx, "Cannot find file for path: <%s> in folder <%s>, error: 0x%x",
                picoquic_uint8_to_str(log_text, 256, stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length),
                (app_ctx->web_folder == NULL) ? "NULL" : app_ctx->web_folder, file_error);
            /* If unknown, 404 */
            o_bytes = h3zero_create_not_found_header_frame(o_bytes, o_bytes_max);
            /* TODO: consider known-url?data construct */
        }
        else {
            response_length = (stream_ctx->echo_length == 0) ?
                strlen(h3zero_server_default_page) : stream_ctx->echo_length;
            o_bytes = h3zero_create_response_header_frame(o_bytes, o_bytes_max,
                (stream_ctx->echo_length == 0) ? h3zero_content_type_text_html :
                h3zero_content_type_text_plain);
        }
    }
    else if (stream_ctx->ps.stream_state.header.method == h3zero_method_post) {
        /* Manage Post. */
        if (stream_ctx->path_callback == NULL && stream_ctx->post_received == 0) {
            int path_item = picohttp_find_path_item(stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, app_ctx->path_table, app_ctx->path_table_nb);
            if (path_item >= 0) {
                /* TODO-POST: move this code to post-fin callback.*/
                stream_ctx->path_callback = app_ctx->path_table[path_item].path_callback;
                stream_ctx->path_callback(cnx, (uint8_t*)stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, picohttp_callback_post, stream_ctx);
            }
        }

        if (stream_ctx->path_callback != NULL) {
            response_length = stream_ctx->path_callback(cnx, post_response, sizeof(post_response), picohttp_callback_post_fin, stream_ctx);
        }
        else {
            /* Prepare generic POST response */
            size_t message_length = 0;
            (void)picoquic_sprintf((char*)post_response, sizeof(post_response), &message_length, h3zero_server_post_response_page, (int)stream_ctx->post_received);
            response_length = message_length;
        }

        /* If known, create response header frame */
        /* POST-TODO: provide content type of response as part of context */
        o_bytes = h3zero_create_response_header_frame(o_bytes, o_bytes_max,
            (stream_ctx->echo_length == 0) ? h3zero_content_type_text_html :
            h3zero_content_type_text_plain);
    }
    else if (stream_ctx->ps.stream_state.header.method == h3zero_method_connect) {
        /* The connect handling depends on the requested protocol */
    }
    else
    {
        /* unsupported method */
    }

    if (o_bytes == NULL) {
        ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INTERNAL_ERROR);
    }
    else {
        size_t header_length = o_bytes - &buffer[3];
        int is_fin_stream = (stream_ctx->echo_length == 0) ? 1 : 0;
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
                    if (response_length <= sizeof(post_response)) {
                        if (o_bytes + (size_t)response_length <= o_bytes_max) {
                            memcpy(o_bytes, (stream_ctx->ps.stream_state.header.method == h3zero_method_post) ? post_response : (uint8_t*)h3zero_server_default_page, (size_t)response_length);
                            o_bytes += (size_t)response_length;
                        }
                        else {
                            o_bytes = NULL;
                        }
                    }
                    else {
                        /* Large post responses are not concatenated here, but will be pulled from the data */
                        is_fin_stream = 0;
                    }
                }
            }
        }

        if (o_bytes != NULL) {
            ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id,
                buffer, o_bytes - buffer, is_fin_stream, stream_ctx);
            if (ret != 0) {
                o_bytes = NULL;
            }
        }

        if (o_bytes == NULL) {
            ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INTERNAL_ERROR);
        }
        else if (stream_ctx->echo_length != 0 || response_length > sizeof(post_response)) {
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
        /* TODO: add an exception for bidir streams set by Webtransport */
        if (!IS_CLIENT_STREAM_ID(stream_id)) {
            /* Should never happen */
            ret = picoquic_stop_sending(cnx, stream_id, H3ZERO_GENERAL_PROTOCOL_ERROR);
            picoquic_reset_stream(cnx, stream_id, H3ZERO_GENERAL_PROTOCOL_ERROR);
        }
        else {
            /* Find or create stream context */
            if (stream_ctx == NULL) {
                stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, &ctx->h3_stream_tree, 1, 1);
            }

            if (stream_ctx == NULL) {
                ret = picoquic_stop_sending(cnx, stream_id, H3ZERO_INTERNAL_ERROR);

                if (ret == 0) {
                    ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
                }
            }
            else {
                /* TODO: move this to common code with unidir, after parsing beginning of unidir? */
                uint16_t error_found = 0;
                size_t available_data = 0;
                uint8_t * bytes_max = bytes + length;
                while (bytes < bytes_max) {
                    bytes = h3zero_parse_data_stream(bytes, bytes_max, &stream_ctx->ps.stream_state, &available_data, &error_found);
                    if (bytes == NULL) {
                        ret = picoquic_close(cnx, error_found);
                        break;
                    }
                    else if (available_data > 0) {
                        if (stream_ctx->ps.stream_state.header_found && stream_ctx->post_received == 0) {
                            int path_item = picohttp_find_path_item(stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, ctx->path_table, ctx->path_table_nb);
                            if (path_item >= 0) {
                                stream_ctx->path_callback = ctx->path_table[path_item].path_callback;
                                stream_ctx->path_callback(cnx, (uint8_t*)stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, picohttp_callback_post, stream_ctx);
                            }

                            (void)picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx);
                        }

                        /* Received data for a POST command. */
                        if (stream_ctx->path_callback != NULL) {
                            /* if known URL, pass the data to URL specific callback. */
                            ret = stream_ctx->path_callback(cnx, bytes, available_data, picohttp_callback_post_data, stream_ctx);
                        }
                        stream_ctx->post_received += available_data;
                        bytes += available_data;
                    }
                }
                /* TODO:are there cases when the request header shall be processed before the FIN is received?
                 */
                
                if (ret == 0 && fin_or_event == picoquic_callback_stream_fin) {
                    /* Process the request header. */
                    if (stream_ctx->ps.stream_state.header_found) {
                        ret = h3zero_server_process_request_frame(cnx, stream_ctx, ctx);
                    }
                    else {
                        /* Unexpected end of stream before the header is received */
                        ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_FRAME_ERROR);
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
        /* TODO: consider web transport */
    }

    return ret;
}

int h3zero_server_callback_prepare_to_send(picoquic_cnx_t* cnx,
    uint64_t stream_id, picohttp_server_stream_ctx_t * stream_ctx,
    void * context, size_t space, h3zero_server_callback_ctx_t* ctx)
{

    int ret = -1;

    if (stream_ctx == NULL) {
        stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, &ctx->h3_stream_tree, 0, 1);
    }

    if (stream_ctx == NULL) {
        ret = picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
    }
    else {
        if (stream_ctx->path_callback != NULL) {
            /* Get data from callback context of specific URL */
            ret = stream_ctx->path_callback(cnx, context, space, picohttp_callback_provide_data, stream_ctx);
        }
        /* TODO: add case for web transport */
        else {
            /* default reply for known URL */
            ret = h3zero_server_prepare_to_send(context, space, stream_ctx);
            if (stream_ctx->echo_sent >= stream_ctx->echo_length) {
                h3zero_delete_stream(&ctx->h3_stream_tree, stream_ctx);
                picoquic_unlink_app_stream_ctx(cnx, stream_id);
            }
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
        ret = picoquic_set_stream_priority(cnx, 3, 0);
    }

    if (ret == 0) {
        /* set the stream 7 as the encoder stream, although we do not actually create dynamic codes. */
        ret = picoquic_add_to_stream(cnx, 7, &encoder_stream_head, 1, 0);
        if (ret == 0) {
            ret = picoquic_set_stream_priority(cnx, 7, 1);
        }
    }

    if (ret == 0) {
        /* set the stream 11 as the decoder stream, although we do not actually create dynamic codes. */
        ret = picoquic_add_to_stream(cnx, 11, &decoder_stream_head, 1, 0);
        if (ret == 0) {
            ret = picoquic_set_stream_priority(cnx, 11, 1);
        }
    }

    return ret;
}

int picohttp_find_path_item(const uint8_t * path, size_t path_length, const picohttp_server_path_item_t * path_table, size_t path_table_nb)
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
    h3zero_server_callback_ctx_t* ctx = NULL;
    picohttp_server_stream_ctx_t* stream_ctx = (picohttp_server_stream_ctx_t*)v_stream_ctx;

    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(cnx->quic)) {
        ctx = h3zero_server_callback_create_context((picohttp_server_parameters_t *)callback_ctx);
        if (ctx == NULL) {
            /* cannot handle the connection */
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return -1;
        }
        else {
            picoquic_set_callback(cnx, h3zero_server_callback, ctx);
            ret = h3zero_server_init(cnx);
        }
    } else{
        ctx = (h3zero_server_callback_ctx_t*)callback_ctx;
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
                stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, &ctx->h3_stream_tree, 0, 1);
            }
            if (stream_ctx != NULL) {
                /* reset post callback. */
                if (stream_ctx->path_callback != NULL) {
                    ret = stream_ctx->path_callback(NULL, NULL, 0, picohttp_callback_reset, stream_ctx);
                }

                if (stream_ctx->F != NULL) {
                    stream_ctx->F = picoquic_file_close(stream_ctx->F);
                }
            }
            picoquic_reset_stream(cnx, stream_id, 0);
            break;
        case picoquic_callback_stateless_reset:
        case picoquic_callback_close: /* Received connection close */
        case picoquic_callback_application_close: /* Received application close */
            h3zero_server_callback_delete_context(ctx);
            picoquic_set_callback(cnx, NULL, NULL);
            break;
        case picoquic_callback_version_negotiation:
            break;
        case picoquic_callback_stream_gap:
            /* Gap indication, when unreliable streams are supported */
            if (stream_ctx == NULL) {
                stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, &ctx->h3_stream_tree, 0, 1);
            }
            if (stream_ctx != NULL) {
                if (stream_ctx->path_callback != NULL) {
                    ret = stream_ctx->path_callback(NULL, NULL, 0, picohttp_callback_reset, stream_ctx);
                }
                stream_ctx->ps.hq.status = picohttp_server_stream_status_finished;
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






