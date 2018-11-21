/*
* Author: Christian Huitema
* Copyright (c) 2017, Private Octopus, Inc.
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
 * Basic implementation of HTTP3, suitable for a minimal test responder.
 * The traffic generation is similar to that of the http0dot9 test:
 * - Receive a get request on a client bidir stream.
 * - Parse the header to find the required document
 * - Generate the corresponding document in memory
 * The "request" is expected to be an H3 request header frame, encoded with QPACK
 * The "response" will include a response header frame and one or several data frames.
 * QPACK encoding only uses the static dictionary.
 * The server will start the connection by sending a setting frame, which will
 * specify a zero-length dynamic dictionary for QPACK.
 */
#include <string.h>
#include "picoquic_internal.h"
#include "h3zero.h"

h3zero_qpack_static_t qpack_static[] = { 
	{ 0, http_pseudo_header_authority, NULL},
	{ 1, http_pseudo_header_path, "/"},
	{ 2, http_header_age, "0"},
	{ 3, http_header_content_disposition, NULL},
	{ 4, http_header_content_length, "0"},
	{ 5, http_header_cookie, NULL},
	{ 6, http_header_date, NULL},
	{ 7, http_header_etag, NULL},
	{ 8, http_header_if_modified_since, NULL},
	{ 9, http_header_if_none_match, NULL},
	{ 10, http_header_last_modified, NULL},
	{ 11, http_header_link, NULL},
	{ 12, http_header_location, NULL},
	{ 13, http_header_referer, NULL},
	{ 14, http_header_set_cookie, NULL},
	{ 15, http_pseudo_header_method, "CONNECT"},
	{ 16, http_pseudo_header_method, "DELETE"},
	{ 17, http_pseudo_header_method, "GET"},
	{ 18, http_pseudo_header_method, "HEAD"},
	{ 19, http_pseudo_header_method, "OPTIONS"},
	{ 20, http_pseudo_header_method, "POST"},
	{ 21, http_pseudo_header_method, "PUT"},
	{ 22, http_pseudo_header_scheme, "http"},
	{ 23, http_pseudo_header_scheme, "https"},
	{ 24, http_pseudo_header_status, "103"},
	{ 25, http_pseudo_header_status, "200"},
	{ 26, http_pseudo_header_status, "304"},
	{ 27, http_pseudo_header_status, "404"},
	{ 28, http_pseudo_header_status, "503"},
	{ 29, http_header_accept, "*/*"},
	{ 30, http_header_accept, "application/dns-message"},
	{ 31, http_header_accept_encoding, "gzip, deflate, br"},
	{ 32, http_header_accept_ranges, "bytes"},
	{ 33, http_header_access_control_allow_headers, "cache-control"},
	{ 34, http_header_access_control_allow_headers, "content-type"},
	{ 35, http_header_access_control_allow_origin, "*"},
	{ 36, http_header_cache_control, "max-age=0"},
	{ 37, http_header_cache_control, "max-age=2592000"},
	{ 38, http_header_cache_control, "max-age=604800"},
	{ 39, http_header_cache_control, "no-cache"},
	{ 40, http_header_cache_control, "no-store"},
	{ 41, http_header_cache_control, "public, max-age=31536000"},
	{ 42, http_header_content_encoding, "br"},
	{ 43, http_header_content_encoding, "gzip"},
	{ 44, http_header_content_type, "application/dns-message"},
	{ 45, http_header_content_type, "application/javascript"},
	{ 46, http_header_content_type, "application/json"},
	{ 47, http_header_content_type, "application/x-www-form-urlencoded"},
	{ 48, http_header_content_type, "image/gif"},
	{ 49, http_header_content_type, "image/jpeg"},
	{ 50, http_header_content_type, "image/png"},
	{ 51, http_header_content_type, "text/css"},
	{ 52, http_header_content_type, "text/html; charset=utf-8"},
	{ 53, http_header_content_type, "text/plain"},
	{ 54, http_header_content_type, "text/plain;charset=utf-8"},
	{ 55, http_header_range, "bytes=0-"},
	{ 56, http_header_strict_transport_security, "max-age=31536000"},
	{ 57, http_header_strict_transport_security, "max-age=31536000; includesubdomains"},
	{ 58, http_header_strict_transport_security, "max-age=31536000; includesubdomains; preload"},
	{ 59, http_header_vary, "accept-encoding"},
	{ 60, http_header_vary, "origin"},
	{ 61, http_header_x_content_type_options, "nosniff"},
	{ 62, http_header_x_xss_protection, "1; mode=block"},
	{ 63, http_pseudo_header_status, "100"},
	{ 64, http_pseudo_header_status, "204"},
	{ 65, http_pseudo_header_status, "206"},
	{ 66, http_pseudo_header_status, "302"},
	{ 67, http_pseudo_header_status, "400"},
	{ 68, http_pseudo_header_status, "403"},
	{ 69, http_pseudo_header_status, "421"},
	{ 70, http_pseudo_header_status, "425"},
	{ 71, http_pseudo_header_status, "500"},
	{ 72, http_header_accept_language, NULL},
	{ 73, http_header_access_control_allow_credentials, "FALSE"},
	{ 74, http_header_access_control_allow_credentials, "TRUE"},
	{ 75, http_header_access_control_allow_headers, "*"},
	{ 76, http_header_access_control_allow_methods, "get"},
	{ 77, http_header_access_control_allow_methods, "get, post, options"},
	{ 78, http_header_access_control_allow_methods, "options"},
	{ 79, http_header_access_control_expose_headers, "content-length"},
	{ 80, http_header_access_control_request_headers, "content-type"},
	{ 81, http_header_access_control_request_method, "get"},
	{ 82, http_header_access_control_request_method, "post"},
	{ 83, http_header_alt_svc, "clear"},
	{ 84, http_header_authorization, NULL},
	{ 85, http_header_content_security_policy, "script-src 'none'; object-src 'none'; base-uri 'none'"},
	{ 86, http_header_early_data, "1"},
	{ 87, http_header_expect_ct, NULL},
	{ 88, http_header_forwarded, NULL},
	{ 89, http_header_if_range, NULL},
	{ 90, http_header_origin, NULL},
	{ 91, http_header_purpose, "prefetch"},
	{ 92, http_header_server, NULL},
	{ 93, http_header_timing_allow_origin, "*"},
	{ 94, http_header_upgrade_insecure_requests, "1"},
	{ 95, http_header_user_agent, NULL},
	{ 96, http_header_x_forwarded_for, NULL},
	{ 97, http_header_x_frame_options, "deny"},
	{ 98, http_header_x_frame_options, "sameorigin"}
};

 /*
  * Setting frame.
  * The setting frame is encoded as as set of 16 bit identifiers and varint values.
  */

const uint8_t h3zero_default_setting_frame[] = {
    6, (uint8_t)h3zero_frame_settings,
	0, (uint8_t)h3zero_setting_header_table_size, 0,
	0, (uint8_t)h3zero_qpack_blocked_streams, 0
};

uint8_t * h3zero_parse_setting_frame(h3zero_settings_t * settings, uint8_t * bytes, uint8_t * bytes_max) 
{
    return NULL;
}

/*
 * Header frame.
 * The header frame is encoded using QPACK.
 */
uint8_t * h3zero_create_header_frame(h3zero_settings_t * settings, uint8_t * bytes, uint8_t * bytes_max)
{
    return NULL;
}

uint8_t * h3zero_parse_header_frame(h3zero_settings_t * settings, uint8_t * bytes, uint8_t * bytes_max)
{
    return NULL;
}

/*
 * Data frame.
 * Process as it goes. Associate with an h3zero stream
 */

#if 0
 /*
  * Incoming data.
  * TODO: should incorporate the H3 state machine.
  *
  * Stream state:
  * - Uni stream: Control, type 'C'; unique, set at beginning of connection
  * - Uni Stream: Push, 'P'
  * - Uni stream, extension, type = N*0x1F; should be ignored.
  * - Bidir stream (client): send request, receive response.
  * For uni streams: receive type, then frames
  * For bidi stream: receive header frame from client, check method, should be get; check resource name; prime return.
  *                  send header frame, then data frame, then FIN.
  * Before any transmission, open control stream, send setting frame.
  * also, obtain settings from peer.
  *
  * Stream = sequence of frames, until fin.
  */

void h3zero_server_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx)
{
    h3zero_server_callback_ctx_t* ctx = (h3zero_server_callback_ctx_t*)callback_ctx;
    h3zero_server_stream_ctx_t* stream_ctx = NULL;

    printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
    picoquic_log_time(stdout, cnx, picoquic_current_time(), "", " : ");
    printf("Server CB, Stream: %" PRIu64 ", %" PRIst " bytes, fin=%d (%s)\n",
        stream_id, length, fin_or_event, picoquic_log_fin_or_event_name(fin_or_event));

    if (fin_or_event == picoquic_callback_close ||
        fin_or_event == picoquic_callback_application_close ||
        fin_or_event == picoquic_callback_stateless_reset) {
        if (ctx != NULL) {
            h3zero_callback_delete_context(ctx);
            picoquic_set_callback(cnx, h3zero_server_callback, NULL);
        }
        fflush(stdout);
        return;
    }

    if (fin_or_event == picoquic_callback_challenge_response) {
        fflush(stdout);
        return;
    }

    if (ctx == NULL) {
        h3zero_server_callback_ctx_t* new_ctx = h3zero_callback_create_context();
        if (new_ctx == NULL) {
            /* cannot handle the connection */
            printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            printf("Memory error, cannot allocate application context\n");

            picoquic_close(cnx, PICOQUIC_ERROR_MEMORY);
            return;
        }
        else {
            picoquic_set_callback(cnx, h3zero_server_callback, new_ctx);
            ctx = new_ctx;
        }
    }

    stream_ctx = ctx->first_stream;

    /* if stream is already present, check its state. New bytes? */
    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    if (stream_ctx == NULL) {
        stream_ctx = (h3zero_server_stream_ctx_t*)
            malloc(sizeof(h3zero_server_stream_ctx_t));
        if (stream_ctx == NULL) {
            /* Could not handle this stream */
            picoquic_reset_stream(cnx, stream_id, 500);
            return;
        }
        else {
            memset(stream_ctx, 0, sizeof(h3zero_server_stream_ctx_t));
            stream_ctx->next_stream = ctx->first_stream;
            ctx->first_stream = stream_ctx;
            stream_ctx->stream_id = stream_id;
        }
    }

    /* verify state and copy data to the stream buffer */
    if (fin_or_event == picoquic_callback_stop_sending) {
        stream_ctx->status = h3zero_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
        printf("Server CB, Stop Sending Stream: %" PRIu64 ", resetting the local stream.\n",
            stream_id);
        return;
    }
    else if (fin_or_event == picoquic_callback_stream_reset) {
        stream_ctx->status = h3zero_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, 0);
        printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
        printf("Server CB, Reset Stream: %" PRIu64 ", resetting the local stream.\n",
            stream_id);
        return;
    }
    else if (stream_ctx->status == h3zero_server_stream_status_finished || stream_ctx->command_length + length > (H3ZERO_COMMAND_MAX - 1)) {
        if (fin_or_event == picoquic_callback_stream_fin && length == 0) {
            /* no problem, this is fine. */
        }
        else {
            /* send after fin, or too many bytes => reset! */
            picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_STREAM_STATE_ERROR);
            printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            printf("Server CB, Stream: %" PRIu64 ", RESET, too long or after FIN\n",
                stream_id);
        }
        return;
    }
    else if (fin_or_event == picoquic_callback_stream_gap) {
        /* We do not support this, yet */
        stream_ctx->status = h3zero_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION);
        printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
        printf("Server CB, Stream: %" PRIu64 ", RESET, stream gaps not supported\n", stream_id);
        return;
    }
    else if (fin_or_event == picoquic_callback_no_event || fin_or_event == picoquic_callback_stream_fin) {
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

        /* if FIN present, process request through http 3 */
        if ((fin_or_event == picoquic_callback_stream_fin || crlf_present != 0) && stream_ctx->response_length == 0) {
            char buf[256];

            stream_ctx->command[stream_ctx->command_length] = 0;
            /* if data generated, just send it. Otherwise, just FIN the stream. */
            stream_ctx->status = h3zero_server_stream_status_finished;
            if (http0dot9_get(stream_ctx->command, stream_ctx->command_length,
                ctx->buffer, ctx->buffer_max, &stream_ctx->response_length)
                != 0) {
                printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                printf("Server CB, Stream: %" PRIu64 ", Reply with bad request message after command: %s\n",
                    stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));

                // picoquic_reset_stream(cnx, stream_id, 404);

                (void)picoquic_add_to_stream(cnx, stream_ctx->stream_id, (const uint8_t *)bad_request_message,
                    strlen(bad_request_message), 1);
            }
            else {
                printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
                printf("Server CB, Stream: %" PRIu64 ", Processing command: %s\n",
                    stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));
                picoquic_add_to_stream(cnx, stream_id, ctx->buffer,
                    stream_ctx->response_length, 1);
            }
        }
        else if (stream_ctx->response_length == 0) {
            char buf[256];

            printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
            stream_ctx->command[stream_ctx->command_length] = 0;
            printf("Server CB, Stream: %" PRIu64 ", Partial command: %s\n",
                stream_id, strip_endofline(buf, sizeof(buf), (char*)&stream_ctx->command));
            fflush(stdout);
        }
    }
    else {
        /* Unknown event */
        stream_ctx->status = h3zero_server_stream_status_finished;
        picoquic_reset_stream(cnx, stream_id, PICOQUIC_TRANSPORT_INTERNAL_ERROR);
        printf("%" PRIx64 ": ", picoquic_val64_connection_id(picoquic_get_logging_cnxid(cnx)));
        printf("Server CB, Stream: %" PRIu64 ", unexpected event\n", stream_id);
        return;
    }

    /* that's it */
}
#endif