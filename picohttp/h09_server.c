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
#ifdef _WINDOWS
#include "wincompat.h"
#include "ws2ipdef.h"
#pragma warning(disable:4100)
#endif
#include "picoquic_internal.h"
#include "h3zero.h"
#include "h3zero_common.h"
#include "h09_common.h"
#include "h09_server.h"
#include "democlient.h"
#include "demoserver.h"
#include "quicperf.h"

/* The HTTP 0.9 server code is used for early test of the QUIC transport functions. 
 * The simple server provides simple responses, precanned index files or randomly
 * generated content */


static const char* bad_request_message = "<html><head><title>Bad Request</title></head><body>Bad request. Why don't you try \"GET /456789\"?</body></html>";

static int picohttp_server_parse_commandline(uint8_t* command, size_t command_length, h3zero_stream_ctx_t* stream_ctx)
{
    return h09_server_parse_commandline(command, command_length, &stream_ctx->ps.hq);
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

int picoquic_h09_server_process_data_header(
    const uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event,
    h3zero_stream_ctx_t* stream_ctx,
    size_t * r_processed)
{
    int ret = 0;
    size_t processed = 0;

    while (ret == 0 && processed < length) {
        if (stream_ctx->ps.hq.status == picohttp_server_stream_status_none) {
            /* If the command has not been received yet, try to process it */
            int crlf_present = 0;

            while (processed < length && crlf_present == 0) {
                if (bytes[processed] == '\r') {
                    /* Ignore \r, so end of header is either CRLF/CRLF, of just LF/LF, or maybe LF/CR/LF */
                }
                else if (bytes[processed] == '\n') {
                    crlf_present = 1;
                }
                else if (stream_ctx->ps.hq.command_length < sizeof(stream_ctx->ps.hq.frame) - 1) {
                    stream_ctx->ps.hq.frame[stream_ctx->ps.hq.command_length++] = bytes[processed];
                }
                else {
                    /* Too much data */
                    stream_ctx->ps.hq.method = -1;
                    ret = -1;
                    break;
                }
                processed++;
            }

            if (crlf_present) {
                stream_ctx->ps.hq.status = picohttp_server_stream_status_crlf;
            }

            if (crlf_present || fin_or_event == picoquic_callback_stream_fin) {
                /* Parse the command */
                ret = picohttp_server_parse_commandline(stream_ctx->ps.hq.frame, stream_ctx->ps.hq.command_length, stream_ctx);
            }
        }
        else if (stream_ctx->ps.hq.status == picohttp_server_stream_status_crlf) {
            if (bytes[processed] == '\n') {
                /* empty line */
                stream_ctx->ps.hq.status = picohttp_server_stream_status_receiving;
            }
            else if (bytes[processed] != '\r') {
                stream_ctx->ps.hq.status = picohttp_server_stream_status_header;
            }
            processed++;
        }
        else if (stream_ctx->ps.hq.status == picohttp_server_stream_status_header) {
            if (bytes[processed] == '\n') {
                stream_ctx->ps.hq.status = picohttp_server_stream_status_crlf;
            }
            processed++;
        }
        else
        {
            break;
        }
    }

    *r_processed = processed;
    return ret;
}

int picoquic_h09_server_process_data(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, 
    picoquic_h09_server_callback_ctx_t* app_ctx,
    h3zero_stream_ctx_t* stream_ctx)
{
    int ret = 0;
    size_t processed = 0;

    ret = picoquic_h09_server_process_data_header(bytes, length, fin_or_event, stream_ctx, &processed);

    if (ret == 0 && processed < length) {
        if (stream_ctx->ps.hq.status == picohttp_server_stream_status_receiving) {
            /* Received data for a POST command. */
            size_t available = length - processed;

            if (stream_ctx->sfs.post_received == 0 && available > 0) {
                int path_item = picohttp_find_path_item(stream_ctx->ps.hq.path, stream_ctx->ps.hq.path_length, app_ctx->path_table, app_ctx->path_table_nb);
                if (path_item >= 0) {
                    stream_ctx->sfs.path_callback = app_ctx->path_table[path_item].path_callback;
                    stream_ctx->sfs.path_callback(cnx, (uint8_t*)stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, picohttp_callback_post, stream_ctx, 
                        app_ctx->path_table[path_item].path_app_ctx);
                }
                stream_ctx->sfs.post_received += available;
                (void)picoquic_set_app_stream_ctx(cnx, stream_id, stream_ctx);
            }

            if (stream_ctx->sfs.path_callback != NULL) {
                /* pass data to selected API */
                ret = stream_ctx->sfs.path_callback(cnx, bytes + processed, available, picohttp_callback_post_data, stream_ctx, stream_ctx->sfs.path_callback_ctx);
                /* TODO-POST: how to handle errors ?*/
            }
            stream_ctx->sfs.post_received += available;
            processed = length;
        }
        else {
            /* No more processing expected on this stream. */
            processed = length;
        }
    }

    /* if FIN present, process request through http 0.9 */
    if (ret == 0 && stream_ctx->ps.hq.status != picohttp_server_stream_status_finished) {
        if (fin_or_event == picoquic_callback_stream_fin || (stream_ctx->ps.hq.method == 0 && stream_ctx->ps.hq.status == picohttp_server_stream_status_crlf)) {
            char buf[1024];
            uint8_t post_response[512];
            int is_bad_request = 0;
            int is_not_found = 0;

            stream_ctx->ps.hq.frame[stream_ctx->ps.hq.command_length] = 0;
            stream_ctx->ps.hq.status = picohttp_server_stream_status_finished;

            picoquic_log_app_message(cnx, "Server CB, Stream: %" PRIu64 ", Processing command: %s\n",
                stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->ps.hq.frame));

            if (stream_ctx->ps.hq.method == 0) {
                int file_error = 0;
                if (h3zero_server_parse_path(stream_ctx->ps.hq.path, stream_ctx->ps.hq.path_length,
                    &stream_ctx->sfs.echo_length, &stream_ctx->file_path, app_ctx->web_folder, &file_error)) {
                    char log_text[256];
                    picoquic_log_app_message(cnx, "Cannot find file for path: <%s> in folder <%s>, error: 0x%x",
                        picoquic_uint8_to_str(log_text, 256, stream_ctx->ps.hq.path, stream_ctx->ps.hq.path_length),
                        (app_ctx->web_folder==NULL)?"NULL": app_ctx->web_folder, file_error);
                    is_not_found = 1;
                }
            }
            else if (stream_ctx->ps.hq.method == 1) {
                if (stream_ctx->sfs.post_received == 0) {
                    int path_item = picohttp_find_path_item(stream_ctx->ps.hq.path, stream_ctx->ps.hq.path_length, app_ctx->path_table, app_ctx->path_table_nb);
                    if (path_item >= 0) {
                        /* TODO-POST: move this code to post-fin callback.*/
                        stream_ctx->sfs.path_callback = app_ctx->path_table[path_item].path_callback;
                        stream_ctx->sfs.path_callback(cnx, (uint8_t*)stream_ctx->ps.stream_state.header.path, stream_ctx->ps.stream_state.header.path_length, picohttp_callback_post, 
                            stream_ctx, app_ctx->path_table[path_item].path_app_ctx);
                    }
                }

                if (stream_ctx->sfs.path_callback != NULL) {
                    stream_ctx->sfs.response_length = stream_ctx->sfs.path_callback(cnx, post_response, sizeof(post_response), picohttp_callback_post_fin, stream_ctx,
                        stream_ctx->sfs.path_callback_ctx);
                    if (stream_ctx->sfs.response_length == 0) {
                        is_bad_request = 1;
                    }
                }
                else {
                    /* Prepare generic POST response */
                    size_t message_length = 0;
                    (void)picoquic_sprintf((char*)post_response, sizeof(post_response), &message_length, h3zero_server_post_response_page, (int)stream_ctx->sfs.post_received);
                    stream_ctx->sfs.response_length = message_length;
                }
                stream_ctx->sfs.echo_length = 0;
            }
            else {
                is_bad_request = 1;
            }

            if (is_bad_request || is_not_found) {
                /* If this is HTTP1, send an HTTP1 OK message, with the appropriate content type */
                if (stream_ctx->ps.hq.proto != 0) {
                    size_t header_length = 0;

                    picoquic_sprintf(buf, sizeof(buf), &header_length, "%s\r\n\r\n",
                        (is_not_found) ? "404 Not Found" : "400 Bad Request");
                    picoquic_add_to_stream_with_ctx(cnx, stream_id, (uint8_t*)buf, header_length, 0, (void*)stream_ctx);
                }

                picoquic_log_app_message(cnx, "Server CB, Stream: %" PRIu64 ", Reply with bad request message after command: %s\n",
                    stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->ps.hq.frame));

                stream_ctx->sfs.response_length = strlen(bad_request_message);
                (void)picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, (const uint8_t*)bad_request_message,
                    (size_t)stream_ctx->sfs.response_length, 1, (void*)stream_ctx);
            }
            else {
                /* If this is HTTP1, send an HTTP1 OK message, with the appropriate content type */
                if (stream_ctx->ps.hq.proto != 0) {
                    size_t header_length = 0;

                    picoquic_sprintf(buf, sizeof(buf), &header_length, "200 OK\r\nContent-Type:%s\r\n\r\n",
                        (stream_ctx->sfs.echo_length == 0 || stream_ctx->ps.hq.method == 1) ? "text/plain" : "test/html");
                    picoquic_add_to_stream_with_ctx(cnx, stream_id, (uint8_t*)buf, header_length, 0, (void*)stream_ctx);
                }

                if (stream_ctx->sfs.response_length == 0 && stream_ctx->sfs.echo_length == 0) {
                    /* Send the canned index.html response */
                    stream_ctx->sfs.response_length = strlen(h3zero_server_default_page);
                    picoquic_add_to_stream_with_ctx(cnx, stream_id, (uint8_t*)h3zero_server_default_page,
                        (size_t)stream_ctx->sfs.response_length, 1, (void*)stream_ctx);
                }
                else if (stream_ctx->sfs.echo_length == 0 && stream_ctx->sfs.response_length < sizeof(post_response)) {
                    /* For short responses, post directly.
                     * TODO-POST: for long responses, we expect that the application
                     * will have set a data provision shortcut. Verify that! */
                    picoquic_add_to_stream_with_ctx(cnx, stream_id, post_response,
                        (size_t)stream_ctx->sfs.response_length, 1, (void*)stream_ctx);
                }
                else {
                    picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1, stream_ctx);
                }
            }
        }
        else if (stream_ctx->sfs.response_length == 0 && stream_ctx->sfs.echo_length == 0 && stream_ctx->ps.hq.method == 0) {
            char buf[256];
            if (stream_ctx->ps.hq.command_length < sizeof(stream_ctx->ps.hq.frame)){
                stream_ctx->ps.hq.frame[stream_ctx->ps.hq.command_length] = 0;

                picoquic_log_app_message(cnx, "Server CB, Stream: %" PRIu64 ", Partial command: %s\n",
                    stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->ps.hq.frame));
            }
            else {

            }
        }
    }

    return ret;
}


static void picoquic_h09_server_callback_delete_context(picoquic_h09_server_callback_ctx_t* ctx)
{

    picosplay_empty_tree(&ctx->h3_stream_tree);

    free(ctx);
}


static picoquic_h09_server_callback_ctx_t* first_server_callback_create_context(picohttp_server_parameters_t* param)
{
    picoquic_h09_server_callback_ctx_t* ctx = (picoquic_h09_server_callback_ctx_t*)
        malloc(sizeof(picoquic_h09_server_callback_ctx_t));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(picoquic_h09_server_callback_ctx_t));

        h3zero_init_stream_tree(&ctx->h3_stream_tree);

        if (param != NULL) {
            ctx->path_table = param->path_table;
            ctx->path_table_nb = param->path_table_nb;
            ctx->web_folder = param->web_folder;
        }
    }

    return ctx;
}

int picoquic_h09_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    picoquic_h09_server_callback_ctx_t* ctx = NULL;
    h3zero_stream_ctx_t* stream_ctx = (h3zero_stream_ctx_t*)v_stream_ctx;

    if (picoquic_cnx_is_still_logging(cnx)) {
        picoquic_log_app_message(cnx, "Server CB, Stream: %" PRIu64 ", %" PRIst " bytes, fin=%d\n",
            stream_id, length, fin_or_event);
    }

    if (callback_ctx == NULL || callback_ctx == picoquic_get_default_callback_context(cnx->quic)) {
        picoquic_h09_server_callback_ctx_t* new_ctx = first_server_callback_create_context((picohttp_server_parameters_t*)callback_ctx);
        if (new_ctx == NULL) {
            /* cannot handle the connection */
            picoquic_log_app_message(cnx, "Memory error, cannot allocate application context\n");
            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return 0;
        }
        else {
            picoquic_set_callback(cnx, picoquic_h09_server_callback, new_ctx);
            ctx = new_ctx;
        }
    }
    else {
        ctx = (picoquic_h09_server_callback_ctx_t*)callback_ctx;
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
            if (ctx != NULL ) {
                picoquic_h09_server_callback_delete_context(ctx);
                picoquic_set_callback(cnx, NULL, NULL);
            }
            fflush(stdout);
            return 0;
    default:
        break;
    }

    if (stream_ctx == NULL) {
        stream_ctx = h3zero_find_or_create_stream(cnx, stream_id, ctx, 1, 0);
    }

    switch (fin_or_event) {
    case picoquic_callback_stop_sending:
        /* TODO-POST: notify callback. */
        stream_ctx->ps.hq.status = picohttp_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        picoquic_log_app_message(cnx, "Server CB, Stop Sending Stream: %" PRIu64 ", resetting the local stream.\n", stream_id);
        if (stream_ctx != NULL && stream_ctx->F != NULL) {
            stream_ctx->F = picoquic_file_close(stream_ctx->F);
        }
        return 0;
    case picoquic_callback_stream_reset:
        /* TODO-POST: notify callback. */
        stream_ctx->ps.hq.status = picohttp_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        picoquic_log_app_message(cnx, "Server CB, Reset Stream: %" PRIu64 ", resetting the local stream.\n", stream_id);

        if (stream_ctx != NULL && stream_ctx->F != NULL) {
            stream_ctx->F = picoquic_file_close(stream_ctx->F);
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
                if (stream_ctx->sfs.path_callback != NULL) {
                    return stream_ctx->sfs.path_callback(cnx, bytes, length, picohttp_callback_provide_data, stream_ctx, stream_ctx->sfs.path_callback_ctx);
                }
                else {
                    /* TODO-POST: notify callback. */
                    int ret = h3zero_server_prepare_to_send((void*)bytes, length, stream_ctx);
                    if (stream_ctx->sfs.echo_sent >= stream_ctx->sfs.echo_length) {
                        h3zero_delete_stream(cnx, ctx, stream_ctx);
                    }
                    return ret;
                }
            }
    default:
        break;
    }

    if (fin_or_event == picoquic_callback_stream_gap) {
        /* We do not support this, yet */
        stream_ctx->ps.hq.status = picohttp_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
        picoquic_log_app_message(cnx, "Server CB, Stream: %" PRIu64 ", RESET, stream gaps not supported\n", stream_id);
        return 0;
    }
    else if (fin_or_event == picoquic_callback_stream_data || fin_or_event == picoquic_callback_stream_fin) {
        /* Data processing includes setting up post/get callback if needed */
        if (picoquic_h09_server_process_data(cnx, stream_id, bytes, length, fin_or_event, ctx, stream_ctx)) {
            /* something bad happened. */
        }
    } else {
        /* Unknown event */
        /* TODO-POST: notify callback. */
        stream_ctx->ps.hq.status = picohttp_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
        picoquic_log_app_message(cnx, "Server CB, Stream: %" PRIu64 ", unexpected event\n", stream_id);
    }

    /* that's it */
    return 0;
}
