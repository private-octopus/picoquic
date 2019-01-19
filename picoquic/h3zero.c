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
#include <stdlib.h>
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
            *bytes++ = (uint8_t) val;
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
        bytes = h3zero_qpack_int_decode(bytes + 1, bytes_max, 0x7F, &delta_base);
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
                        parts->path = (const uint8_t *) qpack_static[s_index].content;
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
 * If the path does not exist, the server will return an error:
 *   :status: 404
 * Followed by nothing.
 * If the method is not supported, the server will return error
 * 405, with header "allow GET"
 */

static uint8_t * h3zero_qpack_code_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t prefix, uint8_t mask, uint64_t code) 
{
    if (bytes != NULL) {
        if (bytes + 1 > bytes_max) {
            bytes = NULL;
        }
        else {
            *bytes = prefix;
            bytes = h3zero_qpack_int_encode(bytes, bytes_max, mask, code);
        }
    }

    return bytes;
}

uint8_t * h3zero_create_request_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length)
{
    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;
    /* Method: GET */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_GET);
    /* Path: doc_name. Use literal plus reference format */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0x50, 0x0F, H3ZERO_QPACK_CODE_PATH);
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0x00, 0x7F, path_length);
    if (bytes != NULL && path_length > 0) {
        if (bytes + path_length > bytes_max) {
            bytes = NULL;
        }
        else {
            memcpy(bytes, (uint8_t *)path, path_length);
            bytes += path_length;
        }
    }

    return bytes;
}

uint8_t * h3zero_create_response_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_content_type_enum doc_type)
{

    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;

    /* Status = 200 */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_200);

    /* Content type header */
    if (bytes != NULL) {
        int code = -1;
        for (size_t i = 0; i < h3zero_qpack_nb_static; i++) {
            if (qpack_static[i].header == http_header_content_type &&
                qpack_static[i].enum_as_int == doc_type) {
                code = qpack_static[i].index;
                break;
            }
        }

        if (code < 0) {
            /* Error, no such content */
            bytes = NULL;
        }
        else {
            bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, code);
        }
    }

    return bytes;
}

uint8_t * h3zero_create_not_found_header_frame(uint8_t * bytes, uint8_t * bytes_max)
{
    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;
    /* Status = 404 */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_404);

    return bytes;
}

uint8_t * h3zero_create_bad_method_header_frame(uint8_t * bytes, uint8_t * bytes_max)
{
    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;
    /* Status = 405 -- use 404 code to get reference to 'status' header */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0x50, 0x0F, H3ZERO_QPACK_CODE_404);
    if (bytes != NULL) {
        *bytes++ = 3;
        *bytes++ = '4';
        *bytes++ = '0';
        *bytes++ = '5';
    }
    /* Only the GET method is allowed */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_ALLOW_GET);

    return bytes;
}

/*
 * Setting frame.
 * The setting frame is encoded as as set of 16 bit identifiers and varint values.
 * For convenience, we set the first byte to the letter 'C' that identifies
 * a control stream.
 */

static uint8_t const h3zero_default_setting_frame_val[] = {
    'C',
    6, /* Length, excluding the type byte */
    (uint8_t)h3zero_frame_settings, /* frame type */
    0, (uint8_t)h3zero_setting_header_table_size, 0, /* 16 bit type, then value*/
    0, (uint8_t)h3zero_qpack_blocked_streams, 0 /* 16 bit type, then value*/
};

uint8_t const * h3zero_default_setting_frame = h3zero_default_setting_frame_val;

const size_t h3zero_default_setting_frame_size = sizeof(h3zero_default_setting_frame_val);

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
<p>GET / returns this text</p>\r\n\
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
    else if (path_length > 1) {
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

    uint64_t frame_length;
    uint8_t * bytes = stream_ctx->frame;
    uint8_t * bytes_max = bytes + stream_ctx->received_length;
    uint8_t buffer[1024]; /* used to compose the response */

    /* Parse frame length, verify length */
    size_t ll = picoquic_varint_decode(stream_ctx->frame, stream_ctx->received_length, &frame_length);

    /* Verify frame type = request header */
    if (ll == 0) {
        ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INCOMPLETE_REQUEST);
    }
    else if (ll + 1 + frame_length < stream_ctx->received_length){
        ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INCOMPLETE_REQUEST);
    }
    else if (stream_ctx->frame[ll] != h3zero_frame_header) {
        ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_UNEXPECTED_FRAME);
    }
    else {
        /* Parse request header, verify length */
        h3zero_header_parts_t parts;

        bytes = h3zero_parse_qpack_header_frame(bytes + ll + 1, bytes_max, &parts);

        if (bytes == NULL || bytes != bytes_max) {
            ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, 
                H3ZERO_MALFORMED_FRAME(h3zero_frame_header));
        }
        else {
            uint8_t * o_bytes = &buffer[0]; 
            uint8_t * o_bytes_max = o_bytes + sizeof(buffer);
            size_t response_length = 0;

            o_bytes += 2; /* reserve two bytes for frame length */
            *o_bytes++ = h3zero_frame_header;

            /* Parse path */
            if (parts.method != h3zero_method_get) {
                /* No such method supported -- error 405, header include "allow GET" */
                o_bytes = h3zero_create_bad_method_header_frame(o_bytes, o_bytes_max);
            }
            else if (h3zero_server_parse_path(parts.path, parts.path_length, &stream_ctx->echo_length) != 0) {
                /* If unknown, 404 */
                o_bytes = h3zero_create_not_found_header_frame(o_bytes, o_bytes_max);
            }
            else {
                /* If known, create response header frame */
                o_bytes = h3zero_create_response_header_frame(o_bytes, o_bytes_max,
                    (stream_ctx->echo_length == 0) ? h3zero_content_type_text_html :
                    h3zero_content_type_text_plain);

                response_length = (stream_ctx->echo_length == 0) ?
                    strlen(h3zero_default_page) : stream_ctx->echo_length;
            }

            if (o_bytes != NULL) {
                size_t header_length = o_bytes - &buffer[3];
                buffer[0] = (uint8_t)((header_length >> 8) | 0x40);
                buffer[1] = (uint8_t)(header_length &0xFF);

                if (response_length > 0) {
                    size_t ld = picoquic_varint_encode(o_bytes, o_bytes_max - o_bytes, response_length);

                    if (ld == 0) {
                        o_bytes = NULL;
                    }
                    else {
                        o_bytes += ld;
                        if (o_bytes < o_bytes_max) {
                            *o_bytes++ = h3zero_frame_data;

                            if (stream_ctx->echo_length == 0) {
                                size_t test_length = strlen(h3zero_default_page);

                                if (o_bytes + test_length <= o_bytes_max) {
                                    memcpy(o_bytes, h3zero_default_page, test_length);
                                    o_bytes += test_length;
                                }
                                else {
                                    o_bytes = 0;
                                }
                            }
                        }
                        else {
                            o_bytes = NULL;
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
                
                if (o_bytes == NULL){
                    ret = picoquic_reset_stream(cnx, stream_ctx->stream_id, H3ZERO_INTERNAL_ERROR);
                }
                else if (stream_ctx->echo_length != 0) {
                    ret = picoquic_mark_active_stream(cnx, stream_ctx->stream_id, 1);
                }
            }
        }
    }

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
    } else if (stream_ctx->echo_sent < stream_ctx->echo_length){
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
            stream_ctx->echo_sent += (uint32_t) available;
            ret = 0;
        }
    }

    return ret;
}

/*
 * Server call back.
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
        }
    }

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
    default:
        /* unexpected */
        break;
    }

    return ret;
}
