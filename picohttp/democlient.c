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
#include "h3zero.h"
#include "democlient.h"

/*
 * Code common to H3 and H09 clients
 */

static picoquic_demo_client_stream_ctx_t* picoquic_demo_client_find_stream(
    picoquic_demo_callback_ctx_t* ctx, uint64_t stream_id)
{
    picoquic_demo_client_stream_ctx_t * stream_ctx = ctx->first_stream;

    while (stream_ctx != NULL && stream_ctx->stream_id != stream_id) {
        stream_ctx = stream_ctx->next_stream;
    }

    return stream_ctx;
}


int demo_client_prepare_to_send(void * context, size_t space, size_t echo_length, size_t * echo_sent)
{
    int ret = 0;

    if (*echo_sent < echo_length) {
        uint8_t * buffer;
        size_t available = echo_length - *echo_sent;
        int is_fin = 1;

        if (available > space) {
            available = space;
            is_fin = 0;
        }

        buffer = picoquic_provide_stream_data_buffer(context, available, is_fin, !is_fin);
        if (buffer != NULL) {
            int r = (74 - (*echo_sent % 74)) - 2;

            /* TODO: fill buffer with some text */
            memset(buffer, 0x5A, available);

            while (r < (int)available) {
                if (r >= 0) {
                    buffer[r] = '\r';
                }
                r++;
                if (r >= 0 && (unsigned int)r < available) {
                    buffer[r] = '\n';
                }
                r += 73;
            }
            *echo_sent += (uint32_t)available;
            ret = 0;
        }
        else {
            ret = -1;
        }
    }

    return ret;
}

/*
 * H3Zero client. This is a simple client that conforms to HTTP 3.0,
 * but the client implementation is barebone.
 */

int h3zero_client_create_stream_request(
    uint8_t * buffer, size_t max_bytes, uint8_t const * path, size_t path_len, size_t post_size, const char * host, size_t * consumed)
{
    int ret = 0;
    uint8_t * o_bytes = buffer;
    uint8_t * o_bytes_max = o_bytes + max_bytes;

    *consumed = 0;

    if (max_bytes < 3) {
        o_bytes = NULL;
    }
    else {
        /* Create the request frame for the specified document */
        *o_bytes++ = h3zero_frame_header;
        o_bytes += 2; /* reserve two bytes for frame length */
        if (post_size == 0) {
            o_bytes = h3zero_create_request_header_frame(o_bytes, o_bytes_max,
                (const uint8_t *)path, path_len, host);
        }
        else {
            o_bytes = h3zero_create_post_header_frame(o_bytes, o_bytes_max,
                (const uint8_t *)path, path_len, host, h3zero_content_type_text_plain);
        }
    }

    if (o_bytes == NULL) {
        ret = -1;
    }
    else {
        size_t header_length = o_bytes - &buffer[3];
        if (header_length < 64) {
            buffer[1] = (uint8_t)(header_length);
            memmove(&buffer[2], &buffer[3], header_length);
            o_bytes--;
        }
        else {
            buffer[1] = (uint8_t)((header_length >> 8) | 0x40);
            buffer[2] = (uint8_t)(header_length & 0xFF);
        }

        if (post_size > 0) {
            /* Add initial DATA frame for POST */
            size_t ll = 0;

            if (o_bytes < o_bytes_max) {
                *o_bytes++ = h3zero_frame_data;
                ll = picoquic_varint_encode(o_bytes, o_bytes_max - o_bytes, post_size);
                o_bytes += ll;
            }
            if (ll == 0) {
                ret = -1;
            }
            else {
                *consumed = o_bytes - buffer;
            }
        }
        else {
            *consumed = o_bytes - buffer;
        }
    }

    return ret;
}

int h3zero_client_init(picoquic_cnx_t* cnx)
{
    uint8_t decoder_stream_head = 0x03;
    uint8_t encoder_stream_head = 0x02;
    int ret = picoquic_add_to_stream(cnx, 2, h3zero_default_setting_frame, h3zero_default_setting_frame_size, 0);

    if (ret == 0) {
		/* set the stream #2 to be the next stream to write! */
        ret = picoquic_mark_high_priority_stream(cnx, 2, 1);
    }

    if (ret == 0) {
        /* set the stream 6 as the encoder stream, although we do not actually create dynamic codes. */
        ret = picoquic_add_to_stream(cnx, 6, &encoder_stream_head, 1, 0);
    }

    if (ret == 0) {
        /* set the stream 10 as the decoder stream, although we do not actually create dynamic codes. */
        ret = picoquic_add_to_stream(cnx, 10, &decoder_stream_head, 1, 0);
    }


    return ret;
}

/* HTTP 0.9 client. 
 * This is the client that was used for QUIC interop testing prior
 * to availability of HTTP 3.0. It allows for testing transport
 * functions without dependencies on the HTTP layer. Instead, it
 * uses the simplistic HTTP 0.9 definition, in which a command
 * would simply be "GET /document.html\n\r\n\r".
 */

int h09_demo_client_prepare_stream_open_command(
    uint8_t * command, size_t max_size, uint8_t const* path, size_t path_len, size_t post_size, char const * host, size_t * consumed)
{

    if (post_size == 0) {
        if (path_len + 6 >= max_size) {
            return -1;
        }

        command[0] = 'G';
        command[1] = 'E';
        command[2] = 'T';
        command[3] = ' ';
        if (path_len > 0) {
            memcpy(&command[4], path, path_len);
        }
        command[path_len + 4] = '\r';
        command[path_len + 5] = '\n';
        command[path_len + 6] = 0;

        *consumed = path_len + 6;
    }
    else {
        size_t byte_index = 0;
        char const * post_head = "POST ";
        char const * post_middle = " HTTP/1.0\r\nHost: ";
        char const * post_trail = "\r\nContent-Type: text/plain\r\n\r\n";
        size_t host_len = (host == NULL) ? 0 : strlen(host);
        if (path_len + host_len + strlen(post_head) + strlen(post_middle) + strlen(post_trail) >= max_size) {
            return -1;
        }
        memcpy(command, post_head, strlen(post_head));
        byte_index = strlen(post_head);
        memcpy(command + byte_index, path, path_len);
        byte_index += path_len;
        memcpy(command + byte_index, post_middle, strlen(post_middle));
        byte_index += strlen(post_middle);
        if (host != NULL) {
            memcpy(command + byte_index, host, host_len);
        }
        byte_index += host_len;
        memcpy(command + byte_index, post_trail, strlen(post_trail));
        byte_index += strlen(post_trail);
        command[byte_index] = 0;
        *consumed = byte_index;
    }

    return 0;
}

/*
 * Unified procedures used for H3 and H09 clients
 */

static int picoquic_demo_client_open_stream(picoquic_cnx_t* cnx,
    picoquic_demo_callback_ctx_t* ctx,
    uint64_t stream_id, char const* doc_name, char const* fname, int is_binary, size_t post_size, int nb_repeat)
{
    int ret = 0;
    uint8_t buffer[1024];
    picoquic_demo_client_stream_ctx_t* stream_ctx = (picoquic_demo_client_stream_ctx_t*)
        malloc(sizeof(picoquic_demo_client_stream_ctx_t));

    if (stream_ctx == NULL) {
		fprintf(stdout, "Memory Error, cannot create stream context %d\n", (int)stream_id);
        ret = -1;
    }
    else {
        ctx->nb_open_streams++;
        ctx->nb_client_streams++;
        memset(stream_ctx, 0, sizeof(picoquic_demo_client_stream_ctx_t));
        stream_ctx->next_stream = ctx->first_stream;
        ctx->first_stream = stream_ctx;
        stream_ctx->stream_id = stream_id + 4*nb_repeat;
        stream_ctx->post_size = post_size;

        if (ctx->no_disk) {
            stream_ctx->F = NULL;
        }
        else {
            char const * x_name = fname;
            char repeat_name[512];
            if (nb_repeat > 0) {
#ifdef _WINDOWS
                ret = sprintf_s(repeat_name, sizeof(repeat_name), "r%dx%s", nb_repeat, fname) <= 0;
#else
                ret = sprintf(repeat_name, "r%dx%s", nb_repeat, fname) <= 0;
#endif
                x_name = repeat_name;
            }
            if (ret == 0) {
                stream_ctx->F = picoquic_file_open(x_name, (is_binary == 0) ? "w" : "wb");
                if (stream_ctx->F == NULL) {
                    ret = -1;
                }
            }
            else {
                stream_ctx->F = NULL;
            }
        }
        if (ret == 0) {
            stream_ctx->is_open = 1;
        }else {
            fprintf(stdout, "Cannot create file: %s\n", fname);
        }
    }

    if (ret == 0) {
        size_t request_length = 0;
        uint8_t name_buffer[512];
        uint8_t * path;
        size_t path_len;

		/* make sure that the doc name is properly formated */
        path = (uint8_t *)doc_name;
        path_len = strlen(doc_name);
        if (doc_name[0] != '/' && path_len + 1 <= sizeof(name_buffer)) {
            name_buffer[0] = '/';
            if (path_len > 0) {
                memcpy(&name_buffer[1], doc_name, path_len);
            }
            path = name_buffer;
            path_len++;
            name_buffer[path_len] = 0;
        }

        /* Format the protocol specific request */
        switch (ctx->alpn) {
        case picoquic_alpn_http_3:
            ret = h3zero_client_create_stream_request(
                buffer, sizeof(buffer), path, path_len, post_size, cnx->sni, &request_length);
            break;
        case picoquic_alpn_http_0_9:
        default:
            ret = h09_demo_client_prepare_stream_open_command(
                buffer, sizeof(buffer), path, path_len, post_size, cnx->sni, &request_length);
            break;
        }

		/* Send the request */

        if (ret == 0) {
            ret = picoquic_add_to_stream_with_ctx(cnx, stream_ctx->stream_id, buffer, request_length,
                (post_size > 0)?0:1, stream_ctx);
            if (post_size > 0) {
                ret = picoquic_mark_active_stream(cnx, stream_id, 1, stream_ctx);
            }
        }

        if (ret != 0) {
            fprintf(stdout, "Cannot send %s command for stream(%d): %s\n", (post_size==0)?"GET":"POST", (int)stream_ctx->stream_id, path);
        }
        else if (nb_repeat == 0) {
            fprintf(stdout, "Opening stream %d to %s %s\n", (int)stream_ctx->stream_id, (post_size == 0) ? "GET" : "POST", path);
        }
    }

    return ret;
}

static int picoquic_demo_client_close_stream(
    picoquic_demo_callback_ctx_t* ctx, picoquic_demo_client_stream_ctx_t* stream_ctx)
{
    int ret = 0;
    if (stream_ctx != NULL && stream_ctx->is_open) {
        if (stream_ctx->F != NULL) {
            fclose(stream_ctx->F);
            stream_ctx->F = NULL;
        }
        stream_ctx->is_open = 0;
        ctx->nb_open_streams--;
        ret = 1;
    }
    return ret;
}

int picoquic_demo_client_start_streams(picoquic_cnx_t* cnx,
    picoquic_demo_callback_ctx_t* ctx, uint64_t fin_stream_id)
{
    int ret = 0;

    /* First perform ALPN specific initialization.
	 * This will trigger sending the "settings" in H3 mode */
    if (fin_stream_id == PICOQUIC_DEMO_STREAM_ID_INITIAL) {
        switch (ctx->alpn) {
        case picoquic_alpn_http_3:
            ret = h3zero_client_init(cnx);
            break;
        default:
            break;
        }
    }

	/* Open all the streams scheduled after the stream that
	 * just finished */
    for (size_t i = 0; ret == 0 && i < ctx->nb_demo_streams; i++) {
        if (ctx->demo_stream[i].previous_stream_id == fin_stream_id) {
            int repeat_nb = 0;
            do {
                ret = picoquic_demo_client_open_stream(cnx, ctx, ctx->demo_stream[i].stream_id,
                    ctx->demo_stream[i].doc_name,
                    ctx->demo_stream[i].f_name,
                    ctx->demo_stream[i].is_binary,
                    (size_t)ctx->demo_stream[i].post_size,
                    repeat_nb);
                repeat_nb++;
            } while (ret == 0 && repeat_nb < ctx->demo_stream[i].repeat_count);

            if (ret == 0 && repeat_nb > 1) {
                fprintf(stdout, "Repeated stream opening %d times.\n", repeat_nb);
            }
        }
    }

    return ret;
}

int picoquic_demo_client_callback(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint8_t* bytes, size_t length,
    picoquic_call_back_event_t fin_or_event, void* callback_ctx, void* v_stream_ctx)
{
    int ret = 0;
    uint64_t fin_stream_id = PICOQUIC_DEMO_STREAM_ID_INITIAL;
    picoquic_demo_callback_ctx_t* ctx = (picoquic_demo_callback_ctx_t*)callback_ctx;
    picoquic_demo_client_stream_ctx_t* stream_ctx = (picoquic_demo_client_stream_ctx_t *)v_stream_ctx;

    ctx->last_interaction_time = picoquic_get_quic_time(cnx->quic);
    ctx->progress_observed = 1;

    switch (fin_or_event) {
    case picoquic_callback_stream_data:
    case picoquic_callback_stream_fin:
        /* Data arrival on stream #x, maybe with fin mark */
        /* TODO: parse the frames. */
        /* TODO: check settings frame */
        if (stream_ctx == NULL) {
            stream_ctx = picoquic_demo_client_find_stream(ctx, stream_id);
        }
        if (stream_ctx != NULL && stream_ctx->is_open && (stream_ctx->F != NULL || ctx->no_disk != 0)) {
            if (length > 0) {
                switch (ctx->alpn) {
                case picoquic_alpn_http_3: {
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
                            if (ctx->no_disk == 0) {
                                ret = (fwrite(bytes, 1, available_data, stream_ctx->F) > 0) ? 0 : -1;
                            }
                            stream_ctx->received_length += available_data;
                            bytes += available_data;
                        }
                    }
                    break;
                }
                case picoquic_alpn_http_0_9:
                default:
                    if (ctx->no_disk == 0) {
                        ret = (fwrite(bytes, 1, length, stream_ctx->F) > 0) ? 0 : -1;
                    }
                    stream_ctx->received_length += length;
                    break;
                }
            }

            if (fin_or_event == picoquic_callback_stream_fin) {
                if (picoquic_demo_client_close_stream(ctx, stream_ctx)) {
                    fin_stream_id = stream_id;
                    if (stream_id <= 64) {
                        fprintf(stdout, "Stream %d ended after %d bytes\n",
                            (int)stream_id, (int)stream_ctx->received_length);
                    }
                }
            }
        }
        break;
    case picoquic_callback_stream_reset: /* Server reset stream #x */
    case picoquic_callback_stop_sending: /* Server asks client to reset stream #x */
        /* TODO: special case for uni streams. */
        if (stream_ctx == NULL) {
            stream_ctx = picoquic_demo_client_find_stream(ctx, stream_id);
        }
        if (picoquic_demo_client_close_stream(ctx, stream_ctx)) {
            fin_stream_id = stream_id;
            fprintf(stdout, "Stream %d reset after %d bytes\n",
                (int)stream_id, (int)stream_ctx->received_length);
        }
        picoquic_reset_stream(cnx, stream_id, 0);
        /* TODO: higher level notify? */
        break;
    case picoquic_callback_stateless_reset:
        fprintf(stdout, "Received a stateless reset.\n");
        break;
    case picoquic_callback_close: /* Received connection close */
        fprintf(stdout, "Received a request to close the connection.\n");
        break;
    case picoquic_callback_application_close: /* Received application close */
        fprintf(stdout, "Received a request to close the application.\n");
        break;
    case picoquic_callback_version_negotiation:
        fprintf(stdout, "Received a version negotiation request:");
        for (size_t byte_index = 0; byte_index + 4 <= length; byte_index += 4) {
            uint32_t vn = PICOPARSE_32(bytes + byte_index);
            fprintf(stdout, "%s%x", (byte_index == 0)?" ":", ", vn);
        }
        fprintf(stdout, "\n");
        break;
    case picoquic_callback_stream_gap:
        /* Gap indication, when unreliable streams are supported */
        fprintf(stdout, "Received a gap indication.\n");
        if (stream_ctx == NULL) {
            stream_ctx = picoquic_demo_client_find_stream(ctx, stream_id);
        }
        if (picoquic_demo_client_close_stream(ctx, stream_ctx)) {
            fin_stream_id = stream_id;
            fprintf(stdout, "Stream %d reset after %d bytes\n",
                (int)stream_id, (int)stream_ctx->received_length);
        }
        /* TODO: Define what error. Stop sending? */
        picoquic_reset_stream(cnx, stream_id, H3ZERO_INTERNAL_ERROR);
        break;
    case picoquic_callback_prepare_to_send:
        /* Used on client when posting data */
            /* Used for active streams */
        if (stream_ctx == NULL) {
            /* Unexpected */
            picoquic_reset_stream(cnx, stream_id, 0);
            return 0;
        }
        else {
            return demo_client_prepare_to_send((void*)bytes, length, stream_ctx->post_size, &stream_ctx->post_sent);
        }
    case picoquic_callback_almost_ready:
    case picoquic_callback_ready:
        break;
    default:
        /* unexpected */
        break;
    }

    if (ret == 0 && fin_stream_id != PICOQUIC_DEMO_STREAM_ID_INITIAL) {
         /* start next batch of streams! */
		 ret = picoquic_demo_client_start_streams(cnx, ctx, fin_stream_id);
    }

    /* that's it */
    return ret;
}

typedef struct st_picoquic_alpn_list_t {
    picoquic_alpn_enum alpn_code;
    char const * alpn_val;
} picoquic_alpn_list_t;

static picoquic_alpn_list_t alpn_list[] = {
    { picoquic_alpn_http_0_9, "hq-18"},
    { picoquic_alpn_http_3, "h3-19" },
    { picoquic_alpn_http_3, "h3-20" },
    { picoquic_alpn_http_3, "h3-22" },
    { picoquic_alpn_http_0_9, "hq-19"},
    { picoquic_alpn_http_0_9, "hq-20"},
    { picoquic_alpn_http_0_9, "hq-22"},
    { picoquic_alpn_http_3, "h3" },
};

static size_t nb_alpn_list = sizeof(alpn_list) / sizeof(picoquic_alpn_list_t);

picoquic_alpn_enum picoquic_parse_alpn(char const * alpn)
{
    picoquic_alpn_enum code = picoquic_alpn_undef;

    if (alpn != NULL) {
        for (size_t i = 0; i < nb_alpn_list; i++) {
            if (strcmp(alpn_list[i].alpn_val, alpn) == 0) {
                code = alpn_list[i].alpn_code;
                break;
            }
        }
    }
	
    return code;
}

int picoquic_demo_client_initialize_context(
    picoquic_demo_callback_ctx_t* ctx,
    picoquic_demo_stream_desc_t const * demo_stream,
	size_t nb_demo_streams,
	char const * alpn,
    int no_disk)
{
    memset(ctx, 0, sizeof(picoquic_demo_callback_ctx_t));
    ctx->demo_stream = demo_stream;
    ctx->nb_demo_streams = nb_demo_streams;
    ctx->alpn = picoquic_parse_alpn(alpn);
    ctx->no_disk = no_disk;
    return 0;
}


static void picoquic_demo_client_delete_stream_context(picoquic_demo_callback_ctx_t* ctx,
    picoquic_demo_client_stream_ctx_t * stream_ctx)
{
    int removed_from_context = 0;

    h3zero_delete_data_stream_state(&stream_ctx->stream_state);

    if (stream_ctx->F != NULL) {
        fclose(stream_ctx->F);
    }

    if (stream_ctx == ctx->first_stream) {
        ctx->first_stream = stream_ctx->next_stream;
        removed_from_context = 1;
    }
    else {
        picoquic_demo_client_stream_ctx_t * previous = ctx->first_stream;

        while (previous != NULL) {
            if (previous->next_stream == stream_ctx) {
                previous->next_stream = stream_ctx->next_stream;
                removed_from_context = 1;
                break;
            }
            else {
                previous = previous->next_stream;
            }
        }
    }

    if (removed_from_context) {
        ctx->nb_client_streams--;
    }

    free(stream_ctx);
}

void picoquic_demo_client_delete_context(picoquic_demo_callback_ctx_t* ctx)
{
    picoquic_demo_client_stream_ctx_t * stream_ctx;

    while ((stream_ctx = ctx->first_stream) != NULL) {
        picoquic_demo_client_delete_stream_context(ctx, stream_ctx);
    }
}

char const * demo_client_parse_stream_spaces(char const * text) {
    while (*text == ' ' || *text == '\t' || *text == '\n' || *text == '\r') {
        text++;
    }
    return text;
}

char const * demo_client_parse_stream_repeat(char const * text, int * number)
{
    int rep = 0;

    if (*text == '*') {
        text++;
        while (text[0] >= '0' && text[0] <= '9') {
            rep *= 10;
            rep += *text++ - '0';
        }

        text = demo_client_parse_stream_spaces(text);

        if (*text == ':') {
            text++;
        }
        else {
            text = NULL;
        }
    }
    *number = rep;

    return text;
}

char const * demo_client_parse_stream_number(char const * text, uint64_t default_number, uint64_t * number)
{
    if (text[0] < '0' || text[0] > '9') {
        *number = default_number;
    }
    else {
        *number = 0;
        do {
            *number *= 10;
            *number += *text++ - '0';
        } while (text[0] >= '0' && text[0] <= '9');

        text = demo_client_parse_stream_spaces(text);

        if (*text == ':') {
            text++;
        }
        else {
            text = NULL;
        }
    }

    return text;
}

char const * demo_client_parse_stream_format(char const * text, int default_format, int * is_binary)
{
    char const * orig = text;

    if (text[0] != 'b' && text[0] != 't') {
        *is_binary = default_format;
    }
    else {
        *is_binary = (text[0] == 'b') ? 1 : 0;

        text = demo_client_parse_stream_spaces(++text);

        if (*text == ':') {
            text++;
        }
        else {
            text = orig;
        }
    }

    return text;
}

char const * demo_client_parse_stream_path(char const * text, 
    char ** path, char ** f_name)
{
    size_t l_path = 0;
    int is_complete = 0;
    int need_dup = 0;

    while (text != NULL) {
        char c = text[l_path];

        if (c == 0 || c == ';' || c == ':') {
            is_complete = 1;
            break;
        }
        
        if (c == '/') {
            need_dup = 1;
        }

        l_path++;
    }

    if (is_complete) {
        *path = (char *)malloc(l_path + 1);
        if (*path == NULL) {
            is_complete = 0;
        }
        else {
            if (need_dup) {
                *f_name = (char *)malloc(l_path + 1);
                if (*f_name == NULL) {
                    is_complete = 0;
                    free(*path);
                    *path = NULL;
                }
            }
        }
    }

    if (is_complete) {
        memcpy(*path, text, l_path);
        (*path)[l_path] = 0;
        if (need_dup) {
            for (size_t i = 0; i < l_path; i++) {
                (*f_name)[i] = (text[i] == '/') ? '_' : text[i];
            }
            (*f_name)[l_path] = 0;
        }
        else {
            *f_name = *path;
        }

        text += l_path;

        if (*text == ':') {
            text++;
        }
    }
    else {
        text = NULL;
    }
    
    return text;
}

char const * demo_client_parse_post_size(char const * text, uint64_t * post_size)
{
    if (text[0] < '0' || text[0] > '9') {
        *post_size = 0;
    }
    else {
        *post_size = 0;
        do {
            *post_size *= 10;
            *post_size += *text++ - '0';
        } while (text[0] >= '0' && text[0] <= '9');

        text = demo_client_parse_stream_spaces(text);

        if (*text == ':') {
            text++;
        }
        else if (*text != 0 && *text != ';'){
            text = NULL;
        }
    }

    return text;
}


char const * demo_client_parse_stream_desc(char const * text, uint64_t default_stream, uint64_t default_previous,
    picoquic_demo_stream_desc_t * desc)
{
    text = demo_client_parse_stream_repeat(text, &desc->repeat_count);

    if (text != NULL) {
        text = demo_client_parse_stream_number(text, default_stream, &desc->stream_id);
    }

    if (text != NULL) {
        text = demo_client_parse_stream_number(
            demo_client_parse_stream_spaces(text), default_previous, &desc->previous_stream_id);
    }

    if (text != NULL) {
        text = demo_client_parse_stream_format(
            demo_client_parse_stream_spaces(text), 0, &desc->is_binary);
    }
    
    if (text != NULL){
        text = demo_client_parse_stream_path(
            demo_client_parse_stream_spaces(text), (char **)&desc->doc_name, (char **)&desc->f_name);
    }

    if (text != NULL) {
        text = demo_client_parse_post_size(demo_client_parse_stream_spaces(text), &desc->post_size);
    }

    /* Skip the final ';' */
    if (text != NULL && *text == ';') {
        text++;
    }

    return text;
}

void demo_client_delete_scenario_desc(size_t nb_streams, picoquic_demo_stream_desc_t * desc)
{
    for (size_t i = 0; i < nb_streams; i++) {
        if (desc[i].f_name != desc[i].doc_name && desc[i].f_name != NULL) {
            free((char*)desc[i].f_name);
            *(char**)(&desc[i].f_name) = NULL;
        }
        if (desc[i].doc_name != NULL) {
            free((char*)desc[i].doc_name);
            *(char**)(&desc[i].doc_name) = NULL;
        }
    }
    free(desc);
}

size_t demo_client_parse_nb_stream(char const * text) {
    size_t n = 0;
    int after_semi = 1;

    while (*text != 0) {
        if (*text++ == ';') {
            n++;
            after_semi = 0;
        }
        else {
            after_semi = 1;
        }
    }

    n += after_semi;

    return n;
}

int demo_client_parse_scenario_desc(char const * text, size_t * nb_streams, picoquic_demo_stream_desc_t ** desc)
{
    int ret = 0;
    /* first count the number of streams and allocate memory */
    size_t nb_desc = demo_client_parse_nb_stream(text);
    size_t i = 0;
    uint64_t previous = PICOQUIC_DEMO_STREAM_ID_INITIAL;
    uint64_t stream_id = 0;

    *desc = (picoquic_demo_stream_desc_t *)malloc(nb_desc*sizeof(picoquic_demo_stream_desc_t));

    if (*desc == NULL) {
        *nb_streams = 0;
        ret = -1;
    }
    else {
        while (text != NULL ) {
            text = demo_client_parse_stream_spaces(text);
            if (*text == 0) {
                break;
            }
            if (i >= nb_desc) {
                /* count was wrong! */
                break;
            }
            else {
                text = demo_client_parse_stream_desc(text, stream_id, previous, &(*desc)[i]);
                if (text != NULL) {
                    stream_id = (*desc)[i].stream_id + 4;
                    previous = (*desc)[i].stream_id;
                    i++;
                }
            }
        }

        *nb_streams = i;

        if (text == NULL) {
            ret = -1;
        }
    }

    return ret;
}
