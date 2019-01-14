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

/*
 * Transport parameters.
 * HTTP/3 does not use server-initiated bidirectional streams;
 * clients MUST omit or specify a value of zero for the QUIC
 * transport parameter initial_max_bidi_streams.
 * Both clients and servers SHOULD send a value of three or
 * greater for the QUIC transport parameter initial_max_uni_streams.
 */

/*
 * Prefixed integers are used throughout QPACK encoding. This is 
 * defined in RFC 7541.
 *
 * If the value is small enough, the encoding uses a single byte:
 *      0   1   2   3   4   5   6   7
 *   +---+---+---+---+---+---+---+---+
 *   | ? | ? | ? |       Value       |
 *   +---+---+---+-------------------+
 * If the value is long, use a multibyte encoding:
 *     0   1   2   3   4   5   6   7
 *   +---+---+---+---+---+---+---+---+
 *   | ? | ? | ? | 1   1   1   1   1 |
 *   +---+---+---+-------------------+
 *   | 1 |    Value-(2^N-1) LSB      |
 *   +---+---------------------------+
 *                  ...
 *   +---+---------------------------+
 *   | 0 |    Value-(2^N-1) MSB      |
 *   +---+---------------------------+
 * Integers can be up to 62 bit longs.
 */

uint8_t * h3zero_qpack_int_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask,  uint64_t val)
{
    if (bytes == NULL || bytes >= bytes_max) {
        return NULL;
    }

    if (val < mask) {
        *bytes++ |= val;
    }
    else {
        val -= mask;
        *bytes++ |= mask;
        while (val > 0x80 && bytes < bytes_max) {
            *bytes++ = 0x80 | (val & 0x7F);
            val >>= 7;
        }

        if (bytes < bytes_max) {
            *bytes++ = val;
        }
        else {
            bytes = NULL;
        }
    }

    return bytes;
}

uint8_t * h3zero_qpack_int_decode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask, uint64_t *val)
{

    if (bytes == NULL || bytes >= bytes_max) {
        *val = 0;
        return NULL;
    }

    *val = *bytes++ & mask;

    if (*val == mask) {
        int shift = 0;
        int complete = 0;
        uint64_t v = 0;

        while (bytes < bytes_max && shift < 62) {
            v |= (((uint64_t)bytes[0]) & 0x7Full) << shift;
            if (((*bytes++) & 0x80) == 0) {
                complete = 1;
                break;
            }
            shift += 7;
        }

        if (shift >= 62 || bytes > bytes_max || !complete) {
            bytes = NULL;
        }
        else {
            *val = v + mask;
        }
    }

    return bytes;
}

/*
 * Table of QPACK static code
 */

h3zero_qpack_static_t qpack_static[] = {
    { 0, http_pseudo_header_authority, NULL, 0},
    { 1, http_pseudo_header_path, "/", 0},
    { 2, http_header_age, "0", 0},
    { 3, http_header_content_disposition, NULL, 0},
    { 4, http_header_content_length, "0", 0},
    { 5, http_header_cookie, NULL, 0},
    { 6, http_header_date, NULL, 0},
    { 7, http_header_etag, NULL, 0},
    { 8, http_header_if_modified_since, NULL, 0},
    { 9, http_header_if_none_match, NULL, 0},
    { 10, http_header_last_modified, NULL, 0},
    { 11, http_header_link, NULL, 0},
    { 12, http_header_location, NULL, 0},
    { 13, http_header_referer, NULL, 0},
    { 14, http_header_set_cookie, NULL, 0},    
    { 15, http_pseudo_header_method, "CONNECT", h3zero_method_connect},
    { 16, http_pseudo_header_method, "DELETE", h3zero_method_delete},
    { 17, http_pseudo_header_method, "GET", h3zero_method_get},
    { 18, http_pseudo_header_method, "HEAD", h3zero_method_head},
    { 19, http_pseudo_header_method, "OPTIONS", h3zero_method_options},
    { 20, http_pseudo_header_method, "POST", h3zero_method_post},
    { 21, http_pseudo_header_method, "PUT", h3zero_method_put},
    { 22, http_pseudo_header_scheme, "http", 0},
    { 23, http_pseudo_header_scheme, "https", 0},
    { 24, http_pseudo_header_status, "103", 103},
    { 25, http_pseudo_header_status, "200", 200},
    { 26, http_pseudo_header_status, "304", 304},
    { 27, http_pseudo_header_status, "404", 404},
    { 28, http_pseudo_header_status, "503", 503},
    { 29, http_header_accept, "*/*", 0},
    { 30, http_header_accept, "application/dns-message", 0},
    { 31, http_header_accept_encoding, "gzip, deflate, br", 0},
    { 32, http_header_accept_ranges, "bytes", 0},
    { 33, http_header_access_control_allow_headers, "cache-control", 0},
    { 34, http_header_access_control_allow_headers, "content-type", 0},
    { 35, http_header_access_control_allow_origin, "*", 0},
    { 36, http_header_cache_control, "max-age=0", 0},
    { 37, http_header_cache_control, "max-age=2592000", 0},
    { 38, http_header_cache_control, "max-age=604800", 0},
    { 39, http_header_cache_control, "no-cache", 0},
    { 40, http_header_cache_control, "no-store", 0},
    { 41, http_header_cache_control, "public, max-age=31536000", 0},
    { 42, http_header_content_encoding, "br", 0},
    { 43, http_header_content_encoding, "gzip", 0},
    { 44, http_header_content_type, "application/dns-message", 0},
    { 45, http_header_content_type, "application/javascript", 0},
    { 46, http_header_content_type, "application/json", 0},
    { 47, http_header_content_type, "application/x-www-form-urlencoded", 0},
    { 48, http_header_content_type, "image/gif", h3zero_content_type_image_gif},
    { 49, http_header_content_type, "image/jpeg", h3zero_content_type_image_jpeg},
    { 50, http_header_content_type, "image/png", h3zero_content_type_image_png},
    { 51, http_header_content_type, "text/css", 0},
    { 52, http_header_content_type, "text/html; charset=utf-8", h3zero_content_type_text_html},
    { 53, http_header_content_type, "text/plain", h3zero_content_type_text_plain},
    { 54, http_header_content_type, "text/plain;charset=utf-8", h3zero_content_type_text_plain},
    { 55, http_header_range, "bytes=0-", 0},
    { 56, http_header_strict_transport_security, "max-age=31536000", 0},
    { 57, http_header_strict_transport_security, "max-age=31536000; includesubdomains", 0},
    { 58, http_header_strict_transport_security, "max-age=31536000; includesubdomains; preload", 0},
    { 59, http_header_vary, "accept-encoding", 0},
    { 60, http_header_vary, "origin", 0},
    { 61, http_header_x_content_type_options, "nosniff", 0},
    { 62, http_header_x_xss_protection, "1; mode=block", 0},
    { 63, http_pseudo_header_status, "100", 100},
    { 64, http_pseudo_header_status, "204", 204},
    { 65, http_pseudo_header_status, "206", 206},
    { 66, http_pseudo_header_status, "302", 302},
    { 67, http_pseudo_header_status, "400", 400},
    { 68, http_pseudo_header_status, "403", 403},
    { 69, http_pseudo_header_status, "421", 421},
    { 70, http_pseudo_header_status, "425", 425},
    { 71, http_pseudo_header_status, "500", 500},
    { 72, http_header_accept_language, NULL, 0},
    { 73, http_header_access_control_allow_credentials, "FALSE", 0},
    { 74, http_header_access_control_allow_credentials, "TRUE", 0},
    { 75, http_header_access_control_allow_headers, "*", 0},
    { 76, http_header_access_control_allow_methods, "get", 0},
    { 77, http_header_access_control_allow_methods, "get, post, options", 0},
    { 78, http_header_access_control_allow_methods, "options", 0},
    { 79, http_header_access_control_expose_headers, "content-length", 0},
    { 80, http_header_access_control_request_headers, "content-type", 0},
    { 81, http_header_access_control_request_method, "get", 0},
    { 82, http_header_access_control_request_method, "post", 0},
    { 83, http_header_alt_svc, "clear", 0},
    { 84, http_header_authorization, NULL, 0},
    { 85, http_header_content_security_policy, "script-src 'none'; object-src 'none'; base-uri 'none'", 0},
    { 86, http_header_early_data, "1", 0},
    { 87, http_header_expect_ct, NULL, 0},
    { 88, http_header_forwarded, NULL, 0},
    { 89, http_header_if_range, NULL, 0},
    { 90, http_header_origin, NULL, 0},
    { 91, http_header_purpose, "prefetch", 0},
    { 92, http_header_server, NULL, 0},
    { 93, http_header_timing_allow_origin, "*", 0},
    { 94, http_header_upgrade_insecure_requests, "1", 0},
    { 95, http_header_user_agent, NULL, 0},
    { 96, http_header_x_forwarded_for, NULL, 0},
    { 97, http_header_x_frame_options, "deny", 0},
    { 98, http_header_x_frame_options, "sameorigin", 0}
};

size_t h3zero_qpack_nb_static = sizeof(qpack_static) / sizeof(h3zero_qpack_static_t);

/* 
 * Minimal QPACK parsing.
 *
 * This is used for header frames, which start with:
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * |   Required Insert Count (8+)  |
 * +---+---------------------------+
 * | S |      Delta Base (7+)      |
 * +---+---------------------------+
 *
 * followed by 
 * +---+---------------------------+
 * |      Compressed Headers     ...
 * +-------------------------------+
 *
 * Since H3zero only support static entries, we expect the required
 * Insert count to be zero, and we always ignore the Base delta.
 * The Base is encoded as sign-and-modulus integer (on 1 byte?)
 *
 * We expect the following types of compressed content:
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 1 | S |      Index (6+)       |
 * +---+---+-----------------------+
 *
 * Index reference with static bit S set to 1, and the index describing an entry
 * in the static table.
 *
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 1 | N | S |Name Index (4+)|
 * +---+---+---+---+---------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * Literal header field with name reference, expecting S bit to 1. Set N bits
 * to 0, ignore on read. 
 *   0   1   2   3   4   5   6   7
 * +---+---+---+---+---+---+---+---+
 * | 0 | 0 | 1 | N | H |NameLen(3+)|
 * +---+---+---+---+---+-----------+
 * |  Name String (Length bytes)   |
 * +---+---------------------------+
 * | H |     Value Length (7+)     |
 * +---+---------------------------+
 * |  Value String (Length bytes)  |
 * +-------------------------------+
 *
 * Literal Header Field Without Name Reference. The N bit is set to zero on write,
 * ignored on read. The H bit is alsways zero, since we do not implement Huffman
 * encoding.
 */

h3zero_method_enum h3zero_get_method_by_name(uint8_t * name, size_t name_length) {
    int const method_index[] = { 15, 16, 17, 18, 19, 20, 21, -1 };
    h3zero_method_enum method = h3zero_method_not_supported;

    for (int i = 0; method_index[i] >= 0; i++) {
        if (strlen(qpack_static[method_index[i]].content) == name_length &&
            memcmp(qpack_static[method_index[i]].content, name, name_length) == 0) {
            method = (h3zero_method_enum)qpack_static[method_index[i]].enum_as_int;
            break;
        }
    }

    return method;
}

h3zero_content_type_enum h3zero_get_content_type_by_name(uint8_t * name, size_t name_length) {
    int const content_type_index[] = { 
        44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, -1 };
    h3zero_content_type_enum content_type = h3zero_content_type_not_supported;

    for (int i = 0; content_type_index[i] >= 0; i++) {
        if (strlen(qpack_static[content_type_index[i]].content) == name_length &&
            memcmp(qpack_static[content_type_index[i]].content, name, name_length) == 0) {
            content_type = (h3zero_content_type_enum)
                qpack_static[content_type_index[i]].enum_as_int;
            break;
        }
    }

    return content_type;
}

int h3zero_parse_status(uint8_t * content, size_t content_length)
{
    int val = 0;

    for (size_t i = 0; i < content_length; i++) {
        if (content[i] >= '0' && content[i] <= '9') {
            val *= 10;
            val += content[i] - '0';
        }
        else {
            val = -1;
            break;
        }
    }

    return val;
}

uint8_t * h3zero_parse_qpack_header_value(uint8_t * bytes, uint8_t * bytes_max,
    http_header_enum_t header, h3zero_header_parts_t * parts)
{
    uint64_t v_length;

    bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x7F, &v_length);
    if (bytes != NULL) {
        if (bytes + v_length > bytes_max) {
            bytes = NULL;
        } else if (bytes[0] & 0x80) {
            /* Huffman encoding is not supported */
            bytes = NULL;
        } else {
            switch (header) {
            case http_pseudo_header_method:
                if (parts->method != h3zero_method_none) {
                    /* Duplicate method! */
                    bytes = 0;
                }
                else {
                    parts->method = h3zero_get_method_by_name(bytes, v_length);
                }
                break;
            case http_header_content_type:
                if (parts->content_type != h3zero_content_type_none) {
                    /* Duplicate content type! */
                    bytes = 0;
                }
                else {
                    parts->content_type = h3zero_get_content_type_by_name(bytes, v_length);
                }
                break;
            case http_pseudo_header_status:
                if (parts->status != 0) {
                    /* Duplicate content type! */
                    bytes = 0;
                }
                else {
                    /* TODO: decimal to binary */
                    parts->status = h3zero_parse_status(bytes, v_length);
                }
                break;
            case http_pseudo_header_path:
                if (parts->path != NULL) {
                    /* Duplicate path! */
                    bytes = 0;
                }
                else {
                    parts->path = bytes;
                    parts->path_length = (size_t)v_length;
                }
                break;
            default:
                break;
            }

            if (bytes != NULL) {
                bytes += v_length;
            }
        }
    }

    return bytes;
}

int h3zero_get_interesting_header_type(uint8_t * name, size_t name_length)
{
    char const  * interesting_header_name[] = {
     ":method", ":path", ":status", "content-type", NULL };
    const http_header_enum_t interesting_header[] = {
        http_pseudo_header_method, http_pseudo_header_path,
        http_pseudo_header_status, http_header_content_type };
    http_header_enum_t val = http_header_unknown;

    for (int i = 0; interesting_header_name[i] != NULL; i++) {
        if (strlen(interesting_header_name[i]) == name_length &&
            memcmp(interesting_header_name[i], name, name_length) == 0) {
            val = interesting_header[i];
            break;
        }
    }

    return val;
}

uint8_t * h3zero_parse_qpack_header_frame(uint8_t * bytes, uint8_t * bytes_max, 
    h3zero_header_parts_t * parts)
{
    memset(parts, 0, sizeof(h3zero_header_parts_t));

    if (bytes == NULL || bytes >= bytes_max) {
        return NULL;
    }

    /* parse base, expect 0 insert */
    if (bytes[0] != 0) {
        /* unexpected value */
        bytes = NULL;
    }
    else {
        uint64_t delta_base;
        bytes = h3zero_qpack_int_decode(bytes + 1, bytes_max, 0x80, &delta_base);
    }

    while (bytes != NULL && bytes < bytes_max) {
        if ((bytes[0] & 0xC0) == 0xC0) {
            /* Index reference with static encoding */
            uint64_t s_index;

            bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x3F, &s_index);

            if (s_index > h3zero_qpack_nb_static) {
                /* Index out of range */
                bytes = NULL;
            }
            else {
                switch (qpack_static[s_index].header) {
                case http_pseudo_header_method:
                    if (parts->method != h3zero_method_none) {
                        /* Duplicate method! */
                        bytes = 0;
                    }
                    else {
                        parts->method = (h3zero_method_enum) qpack_static[s_index].enum_as_int;
                    }
                    break;
                case http_header_content_type:
                    if (parts->content_type != h3zero_content_type_none) {
                        /* Duplicate content type! */
                        bytes = 0;
                    }
                    else {
                        parts->content_type = (h3zero_content_type_enum)qpack_static[s_index].enum_as_int;
                    }
                    break;
                case http_pseudo_header_status:
                    if (parts->status != 0) {
                        /* Duplicate content type! */
                        bytes = 0;
                    }
                    else {
                        parts->status = qpack_static[s_index].enum_as_int;
                    }
                    break;
                case http_pseudo_header_path:
                    if (parts->path != NULL) {
                        /* Duplicate path! */
                        bytes = 0;
                    }
                    else {
                        parts->path = qpack_static[s_index].content;
                        parts->path_length = strlen(qpack_static[s_index].content);
                    }
                    break;
                default:
                    break;
                }
            }
        }
        else if ((bytes[0] & 0xD0) == 0x50) {
            /* Literal header field with name reference, static encoding */
            uint64_t s_index;

            bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x0F, &s_index);
            if (bytes != NULL) {
                if (s_index > h3zero_qpack_nb_static) {
                    /* Index out of range */
                    bytes = NULL;
                } else {
                    bytes = h3zero_parse_qpack_header_value(bytes, bytes_max,
                        qpack_static[s_index].header, parts);
                }
            }
        }
        else if ((bytes[0] & 0xE8) == 0x20) {
            /* Literal Header Field Without Name Reference, static, no Hufman */
            uint64_t n_length;
            uint64_t v_length;

            bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x07, &n_length);
            if (bytes != NULL) {
                if (bytes + n_length > bytes_max) {
                    bytes = NULL;
                } else {
                    /* TO DO: check for interesting values */
                    http_header_enum_t header_type = h3zero_get_interesting_header_type(bytes, n_length);
                    bytes += n_length;
                    bytes = h3zero_parse_qpack_header_value(bytes, bytes_max,
                        header_type, parts);
                }
            }
        }
        else {
            /* unexpected encoding */
            bytes = NULL;
        }
    }

    return bytes;
}

/*
 * Setting frame.
 * The setting frame is encoded as as set of 16 bit identifiers and varint values.
 * For convenience, we set the first byte to the letter 'C' that identifies
 * a control stream.
 */

const uint8_t h3zero_default_setting_frame[] = {
    'C',
    6, /* Length, excluding the type byte */
    (uint8_t)h3zero_frame_settings, /* frame type */
    0, (uint8_t)h3zero_setting_header_table_size, 0, /* 16 bit type, then value*/
    0, (uint8_t)h3zero_qpack_blocked_streams, 0 /* 16 bit type, then value*/
};

uint8_t * h3zero_parse_setting_frame(h3zero_settings_t * settings, uint8_t * bytes, uint8_t * bytes_max)
{
    return NULL;
}

/*
 * Server or client initialization.
 * Send the setting frame on the control stream.
 * This is the first available unidirectional server stream, i.e. stream 1
 * for a client, stream 3 for a server.
 */
int h3zero_send_initial_settings(picoquic_cnx_t * cnx, uint64_t stream_id) {
    int ret = picoquic_add_to_stream(cnx, stream_id, h3zero_default_setting_frame,
        sizeof(h3zero_default_setting_frame), 0);
    return ret;
}

/*
 * Header frame.
 * The HEADERS frame (type=0x1) is used to carry a header block,
 * compressed using QPACK.
 * It is always the first frame sent on the stream, whether by the client or
 * by the server.
 *
 * On the client side, this will include the minimal required frames for
 * a request according to 
 * https://developers.google.com/web/fundamentals/performance/http2/:
 *      :method: GET
 *        :path: /index.html
 *     :version: HTTP/3.0
 *      :scheme: HTTPS
 *   user-agent: Picoquic-H3zero/0.1
 * On the server side, this should be:
 *     :status: 200
 *    :version: HTTP/3.0
 *    server: Picoquic-H3zero/0.1
 * Plus one of:
 *  http_header_content_type: "text/html; charset=utf-8"
 *  http_header_content_type: "text/plain;charset=utf-8"
 *  http_header_content_type: "image/gif"
 *  http_header_content_type: "image/jpeg"
 *  http_header_content_type: "image/png"
 *
 * Followed by a series of data frames.
 *
 * If a request cannot be server, the server will return an error:
 *   :status: 404
 * Followed by nothing.
 */
uint8_t * h3zero_create_request_header_frame(uint8_t * bytes, uint8_t * bytes_max, 
    char * doc_name)
{
    return NULL;
}

uint8_t * h3zero_create_response_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_content_type_enum doc_type)
{
    return NULL;
}

uint8_t * h3zero_create_not_found_header_frame(uint8_t * bytes, uint8_t * bytes_max)
{
    return NULL;
}

uint8_t * h3zero_parse_request_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    char * path, size_t path_length)
{
    return NULL;
}

uint8_t * h3zero_parse_response_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    int * status, h3zero_content_type_enum * doc_type)
{
    while (bytes < bytes_max) {

    }
    return NULL;
}

/*
 * Data frame.
 * Process as it goes. Associate with an h3zero stream
 */

#if 0
 /*
  * Incoming data.
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