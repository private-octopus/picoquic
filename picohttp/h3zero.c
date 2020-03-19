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
        while (val >= 0x80 && bytes < bytes_max) {
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
 * ignored on read. The H bit is always zero, since we do not implement Huffman
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
    int is_huffman;
    uint8_t * decoded = NULL;
    size_t decoded_length;
    uint8_t deHuff[256];

    is_huffman = (bytes[0] >> 7) & 1;
    bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x7F, &v_length);
    if (bytes != NULL) {
        if (bytes + v_length > bytes_max) {
            bytes = NULL;
        } else {
            if (is_huffman && hzero_qpack_huffman_decode(
                bytes, bytes + v_length, deHuff, sizeof(deHuff), &decoded_length) == 0)
            {
                decoded = deHuff;
            }
            else {
                decoded = bytes;
                decoded_length = (size_t) v_length;
            }

            switch (header) {
            case http_pseudo_header_method:
                if (parts->method != h3zero_method_none) {
                    /* Duplicate method! */
                    bytes = 0;
                }
                else {
                    parts->method = h3zero_get_method_by_name(decoded, decoded_length);
                }
                break;
            case http_header_content_type:
                if (parts->content_type != h3zero_content_type_none) {
                    /* Duplicate content type! */
                    bytes = 0;
                }
                else {
                    parts->content_type = h3zero_get_content_type_by_name(decoded, decoded_length);
                }
                break;
            case http_pseudo_header_status:
                if (parts->status != 0) {
                    /* Duplicate content type! */
                    bytes = 0;
                }
                else {
                    /* TODO: decimal to binary */
                    parts->status = h3zero_parse_status(decoded, decoded_length);
                }
                break;
            case http_pseudo_header_path:
                if (parts->path != NULL) {
                    /* Duplicate path! */
                    bytes = 0;
                }
                else {
                    parts->path = malloc(decoded_length+1);
                    if (parts->path == NULL) {
                        bytes = 0;
                        parts->path_length = 0;
                    }
                    else {
                        memcpy((void *)parts->path, decoded, decoded_length);
                        ((uint8_t *)(parts->path))[decoded_length] = 0;
                        parts->path_length = (size_t)decoded_length;
                    }
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

int h3zero_get_interesting_header_type(uint8_t * name, size_t name_length, int is_huffman)
{
    char const  * interesting_header_name[] = {
     ":method", ":path", ":status", "content-type", NULL };
    const http_header_enum_t interesting_header[] = {
        http_pseudo_header_method, http_pseudo_header_path,
        http_pseudo_header_status, http_header_content_type };
    http_header_enum_t val = http_header_unknown;
    uint8_t deHuff[256];

    if (is_huffman) {
        size_t nb_decoded = 0;
        if (hzero_qpack_huffman_decode(name, name + name_length, deHuff, sizeof(deHuff), &nb_decoded) == 0){
            name = deHuff;
            name_length = nb_decoded;
        }
    }

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
                        bytes = NULL;
                    }
                    else {
                        parts->content_type = (h3zero_content_type_enum)qpack_static[s_index].enum_as_int;
                    }
                    break;
                case http_pseudo_header_status:
                    if (parts->status != 0) {
                        /* Duplicate content type! */
                        bytes = NULL;
                    }
                    else {
                        parts->status = qpack_static[s_index].enum_as_int;
                    }
                    break;
                case http_pseudo_header_path:
                    if (parts->path != NULL) {
                        /* Duplicate path! */
                        bytes = NULL;
                    }
                    else {
                        parts->path_length = strlen(qpack_static[s_index].content);
                        parts->path = malloc(parts->path_length + 1);
                        if (parts->path == NULL) {
                            /* internal error */
                            bytes = NULL;
                        }
                        else {
                            memcpy((uint8_t *)parts->path, qpack_static[s_index].content, parts->path_length);
                            ((uint8_t*)parts->path)[parts->path_length] = 0;
                        }
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
        else if ((bytes[0] & 0xE0) == 0x20) {
            /* Literal Header Field Without Name Reference */
            uint64_t n_length;
            int is_huffman = (bytes[0] >> 3) & 1;

            bytes = h3zero_qpack_int_decode(bytes, bytes_max, 0x07, &n_length);
            if (bytes != NULL) {
                if (bytes + n_length > bytes_max) {
                    bytes = NULL;
                }
                else {
                    http_header_enum_t header_type = h3zero_get_interesting_header_type(bytes, (size_t)n_length, is_huffman);
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

static uint8_t * h3zero_qpack_literal_plus_ref_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint64_t code, uint8_t const * val, size_t val_length)
{
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0x50, 0x0F, code);
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0x00, 0x7F, val_length);
    if (bytes != NULL && val_length > 0) {
        if (bytes + val_length > bytes_max) {
            bytes = NULL;
        }
        else {
            memcpy(bytes, val, val_length);
            bytes += val_length;
        }
    }

    return bytes;
}

uint8_t * h3zero_encode_content_type(uint8_t * bytes, uint8_t * bytes_max, h3zero_content_type_enum content_type)
{
    /* Content type header */
    if (bytes != NULL) {
        int code = -1;
        for (size_t i = 0; i < h3zero_qpack_nb_static; i++) {
            if (qpack_static[i].header == http_header_content_type &&
                qpack_static[i].enum_as_int == content_type) {
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

uint8_t * h3zero_create_post_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length, char const * host, h3zero_content_type_enum content_type)
{
    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;
    /* Method */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_POST);
    /* Scheme: HTTPS */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_SCHEME_HTTPS);
    /* Path: doc_name. Use literal plus reference format */
    bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_CODE_PATH, path, path_length);
    /*Authority: host. Use literal plus reference format */
    if (host != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_AUTHORITY, (uint8_t const *)host, strlen(host));
    }
    /* Document type */
    bytes = h3zero_encode_content_type(bytes, bytes_max, content_type);

    return bytes;
}

uint8_t * h3zero_create_request_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length, char const * host)
{
    if (bytes == NULL || bytes + 2 > bytes_max) {
        return NULL;
    }
    /* Push 2 NULL bytes for request header: base, and delta */
    *bytes++ = 0;
    *bytes++ = 0;
    /* Method: GET */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_CODE_GET);
    /* Scheme: HTTPS */
    bytes = h3zero_qpack_code_encode(bytes, bytes_max, 0xC0, 0x3F, H3ZERO_QPACK_SCHEME_HTTPS);
    /* Path: doc_name. Use literal plus reference format */
    bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_CODE_PATH, path, path_length);
    /*Authority: host. Use literal plus reference format */
    if (host != NULL) {
        bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_AUTHORITY, (uint8_t const *)host, strlen(host));
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
    bytes = h3zero_encode_content_type(bytes, bytes_max, doc_type);

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
    /* Allow GET and POST */
    bytes = h3zero_qpack_literal_plus_ref_encode(bytes, bytes_max, H3ZERO_QPACK_ALLOW_GET, (uint8_t *)"GET, POST", 9);

    return bytes;
}

/* Parsing of a data stream. This is implemented as a filter, with a set of states:
 * 
 * - Reading frame length: obtaining the length and type of the next frame.
 * - Reading header frame: obtaining the bytes of the header frame.
 *   When all bytes are obtained, the header is parsed and the header
 *   structure is documented. State moves back to initial, with header-read
 *   flag set. Having two frame headers before a data frame is a bug.
 * - Reading unknown frame: unknown frames can happen at any point in
 *   the stream, and should just be ignored.
 * - Reading data frame: the frame header indicated a data frame of
 *   length N. Treat the following N bytes as data.
 * 
 * There may be several data frames in a stream. The application will pick
 * the bytes and treat them as data.
 */

uint8_t * h3zero_parse_data_stream(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_data_stream_state_t * stream_state, size_t * available_data, uint16_t * error_found)
{
    *available_data = 0;
    *error_found = 0;

    if (bytes == NULL || bytes >= bytes_max) {
        *error_found = H3ZERO_INTERNAL_ERROR;
        return NULL;
    }

    if (!stream_state->frame_header_parsed) {
        size_t frame_type_length;
        size_t frame_header_length;

        if (stream_state->frame_header_read < 1) {
            stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
        }
        frame_type_length = picoquic_varint_skip(stream_state->frame_header);

        while (stream_state->frame_header_read < frame_type_length && bytes < bytes_max) {
            stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
        }

        if (stream_state->frame_header_read < frame_type_length) {
            /* No change in state, wait for more bytes */
            return bytes;
        }

        (void)picoquic_varint_decode(stream_state->frame_header, frame_type_length,
            &stream_state->current_frame_type);

        while (stream_state->frame_header_read < frame_type_length + 1) {
            stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
        }

        frame_header_length = picoquic_varint_skip(stream_state->frame_header + frame_type_length) + frame_type_length;

        if (frame_header_length > sizeof(stream_state->frame_header)) {
            *error_found = H3ZERO_INTERNAL_ERROR;
            return NULL; /* This should never happen! */
        }

        while (stream_state->frame_header_read < frame_header_length && bytes < bytes_max) {
            stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
        }

        if (stream_state->frame_header_read >= frame_header_length) {
            (void)picoquic_varint_decode(stream_state->frame_header + frame_type_length, frame_header_length - frame_type_length,
                &stream_state->current_frame_length);
            stream_state->current_frame_read = 0;
            stream_state->frame_header_parsed = 1;

            if (stream_state->current_frame_type == h3zero_frame_data) {
                if (!stream_state->header_found || stream_state->trailer_found) {
                    /* protocol error */
                    *error_found = H3ZERO_FRAME_UNEXPECTED;
                    bytes = NULL;
                }
            }
            else if (stream_state->current_frame_type == h3zero_frame_header) {
                if (stream_state->header_found && (!stream_state->data_found || stream_state->trailer_found)) {
                    /* protocol error */
                    *error_found = H3ZERO_FRAME_UNEXPECTED;
                    bytes = NULL;
                }
                else if (stream_state->current_frame_length > 0x10000) {
                    /* error, excessive load */
                    *error_found = H3ZERO_INTERNAL_ERROR;
                    bytes = NULL;
                }
                else {
                    stream_state->current_frame = (uint8_t *)malloc((size_t)stream_state->current_frame_length);
                    if (stream_state->current_frame == NULL) {
                        /* error, internal error */
                        *error_found = H3ZERO_INTERNAL_ERROR;
                        bytes = NULL;
                    }
                }
            }
            else if (stream_state->current_frame_type == h3zero_frame_cancel_push || 
                stream_state->current_frame_type == h3zero_frame_goaway ||
                stream_state->current_frame_type == h3zero_frame_max_push_id) {
                *error_found = H3ZERO_GENERAL_PROTOCOL_ERROR;
                bytes = NULL;
            }
            else if (stream_state->current_frame_type == h3zero_frame_settings) {
                *error_found = H3ZERO_FRAME_UNEXPECTED;
                bytes = NULL;
            }
        }
        return bytes;
    }
    else {
        size_t available = bytes_max - bytes;

        if (stream_state->current_frame_read + available > stream_state->current_frame_length) {
            available = (size_t)(stream_state->current_frame_length - stream_state->current_frame_read);
        }

        if (stream_state->current_frame_type == h3zero_frame_header) {
            memcpy(stream_state->current_frame + stream_state->current_frame_read, bytes, available);
            stream_state->current_frame_read += available;
            bytes += available;

            if (stream_state->current_frame_read >= stream_state->current_frame_length) {
                uint8_t *parsed;
                h3zero_header_parts_t * parts = (stream_state->header_found) ?
                    &stream_state->trailer : &stream_state->header;
                stream_state->trailer_found = stream_state->header_found;
                stream_state->header_found = 1;
                /* parse */
                parsed = h3zero_parse_qpack_header_frame(stream_state->current_frame,
                    stream_state->current_frame + stream_state->current_frame_length, parts);
                if (parsed == NULL || (size_t)(parsed - stream_state->current_frame) != stream_state->current_frame_length) {
                    /* protocol error */
                    *error_found = H3ZERO_FRAME_ERROR;
                    bytes = NULL;
                }
                /* free resource */
                stream_state->frame_header_parsed = 0;
                stream_state->frame_header_read = 0;
                free(stream_state->current_frame);
                stream_state->current_frame = NULL;
            }
        }
        else if (stream_state->current_frame_type == h3zero_frame_data) {
            *available_data = (size_t) available;
            stream_state->current_frame_read += available; 
            if (stream_state->current_frame_read >= stream_state->current_frame_length) {
                stream_state->frame_header_parsed = 0;
                stream_state->frame_header_read = 0;
                stream_state->data_found = 1;
            }
        }
        else {
            /* Unknown frame type, should just be ignored */
            stream_state->current_frame_read += available;
            bytes += available;
            if (stream_state->current_frame_read >= stream_state->current_frame_length) {
                stream_state->frame_header_parsed = 0;
                stream_state->frame_header_read = 0;
            }
        }     
    }

    return bytes;
}

void h3zero_delete_data_stream_state(h3zero_data_stream_state_t * stream_state)
{
    if (stream_state->header_found && stream_state->header.path != NULL) {
        free((uint8_t*)stream_state->header.path);
        *((uint8_t**)&stream_state->header.path) = NULL;
    }

    if (stream_state->trailer_found && stream_state->trailer.path != NULL) {
        free((uint8_t*)stream_state->trailer.path);
        *((uint8_t**)&stream_state->trailer.path) = NULL;
    }

    if (stream_state->current_frame != NULL) {
        free(stream_state->current_frame);
        stream_state->current_frame = NULL;
    }
}

/*
 * Setting frame.
 * The setting frame is encoded as as set of 16 bit identifiers and varint values.
 * For convenience, we set the first byte to the integer 0 that identifies
 * a control stream.
 */

static uint8_t const h3zero_default_setting_frame_val[] = {
    0, /* Control Stream ID, varint = 0 */
    (uint8_t)h3zero_frame_settings, /* var int frame type ( < 64) */
    4, /* Length of setting frame content */
    (uint8_t)h3zero_setting_header_table_size, 0, /* var int type ( < 64), then var int value (0) */
    (uint8_t)h3zero_qpack_blocked_streams, 0 /* var int type ( < 64),  then var int value (0) Control*/
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
        h3zero_default_setting_frame_size, 0);
    return ret;
}

/* There is no way in QPACK to prevent sender from using Huffman 
 * encoding. We need a simple decoding function to be used 
 * when they do that */
typedef struct st_h3zero_qpack_huffman_code_t {
    uint64_t right_shift_hex;
    int nb_bits;
    int code;
} h3zero_qpack_huffman_code_t;

/* The table of code is ordered by values */
h3zero_qpack_huffman_code_t h3zero_qpack_huffman_table[] = {
    { 0x0 , 5 , 48 }, /* index:  0   |00000  */
    { 0x1 , 5 , 49 }, /* index:  1   |00001  */
    { 0x2 , 5 , 50 }, /* index:  2   |00010  */
    { 0x3 , 5 , 97 }, /* index:  3   |00011  */
    { 0x4 , 5 , 99 }, /* index:  4   |00100  */
    { 0x5 , 5 , 101 }, /* index:  5   |00101  */
    { 0x6 , 5 , 105 }, /* index:  6   |00110  */
    { 0x7 , 5 , 111 }, /* index:  7   |00111  */
    { 0x8 , 5 , 115 }, /* index:  8   |01000  */
    { 0x9 , 5 , 116 }, /* index:  9   |01001  */
    { 0x14 , 6 , 32 }, /* index:  10   |010100  */
    { 0x15 , 6 , 37 }, /* index:  11   |010101  */
    { 0x16 , 6 , 45 }, /* index:  12   |010110  */
    { 0x17 , 6 , 46 }, /* index:  13   |010111  */
    { 0x18 , 6 , 47 }, /* index:  14   |011000  */
    { 0x19 , 6 , 51 }, /* index:  15   |011001  */
    { 0x1a , 6 , 52 }, /* index:  16   |011010  */
    { 0x1b , 6 , 53 }, /* index:  17   |011011  */
    { 0x1c , 6 , 54 }, /* index:  18   |011100  */
    { 0x1d , 6 , 55 }, /* index:  19   |011101  */
    { 0x1e , 6 , 56 }, /* index:  20   |011110  */
    { 0x1f , 6 , 57 }, /* index:  21   |011111  */
    { 0x20 , 6 , 61 }, /* index:  22   |100000  */
    { 0x21 , 6 , 65 }, /* index:  23   |100001  */
    { 0x22 , 6 , 95 }, /* index:  24   |100010  */
    { 0x23 , 6 , 98 }, /* index:  25   |100011  */
    { 0x24 , 6 , 100 }, /* index:  26   |100100  */
    { 0x25 , 6 , 102 }, /* index:  27   |100101  */
    { 0x26 , 6 , 103 }, /* index:  28   |100110  */
    { 0x27 , 6 , 104 }, /* index:  29   |100111  */
    { 0x28 , 6 , 108 }, /* index:  30   |101000  */
    { 0x29 , 6 , 109 }, /* index:  31   |101001  */
    { 0x2a , 6 , 110 }, /* index:  32   |101010  */
    { 0x2b , 6 , 112 }, /* index:  33   |101011  */
    { 0x2c , 6 , 114 }, /* index:  34   |101100  */
    { 0x2d , 6 , 117 }, /* index:  35   |101101  */
    { 0x5c , 7 , 58 }, /* index:  36   |1011100  */
    { 0x5d , 7 , 66 }, /* index:  37   |1011101  */
    { 0x5e , 7 , 67 }, /* index:  38   |1011110  */
    { 0x5f , 7 , 68 }, /* index:  39   |1011111  */
    { 0x60 , 7 , 69 }, /* index:  40   |1100000  */
    { 0x61 , 7 , 70 }, /* index:  41   |1100001  */
    { 0x62 , 7 , 71 }, /* index:  42   |1100010  */
    { 0x63 , 7 , 72 }, /* index:  43   |1100011  */
    { 0x64 , 7 , 73 }, /* index:  44   |1100100  */
    { 0x65 , 7 , 74 }, /* index:  45   |1100101  */
    { 0x66 , 7 , 75 }, /* index:  46   |1100110  */
    { 0x67 , 7 , 76 }, /* index:  47   |1100111  */
    { 0x68 , 7 , 77 }, /* index:  48   |1101000  */
    { 0x69 , 7 , 78 }, /* index:  49   |1101001  */
    { 0x6a , 7 , 79 }, /* index:  50   |1101010  */
    { 0x6b , 7 , 80 }, /* index:  51   |1101011  */
    { 0x6c , 7 , 81 }, /* index:  52   |1101100  */
    { 0x6d , 7 , 82 }, /* index:  53   |1101101  */
    { 0x6e , 7 , 83 }, /* index:  54   |1101110  */
    { 0x6f , 7 , 84 }, /* index:  55   |1101111  */
    { 0x70 , 7 , 85 }, /* index:  56   |1110000  */
    { 0x71 , 7 , 86 }, /* index:  57   |1110001  */
    { 0x72 , 7 , 87 }, /* index:  58   |1110010  */
    { 0x73 , 7 , 89 }, /* index:  59   |1110011  */
    { 0x74 , 7 , 106 }, /* index:  60   |1110100  */
    { 0x75 , 7 , 107 }, /* index:  61   |1110101  */
    { 0x76 , 7 , 113 }, /* index:  62   |1110110  */
    { 0x77 , 7 , 118 }, /* index:  63   |1110111  */
    { 0x78 , 7 , 119 }, /* index:  64   |1111000  */
    { 0x79 , 7 , 120 }, /* index:  65   |1111001  */
    { 0x7a , 7 , 121 }, /* index:  66   |1111010  */
    { 0x7b , 7 , 122 }, /* index:  67   |1111011  */
    { 0xf8 , 8 , 38 }, /* index:  68   |11111000  */
    { 0xf9 , 8 , 42 }, /* index:  69   |11111001  */
    { 0xfa , 8 , 44 }, /* index:  70   |11111010  */
    { 0xfb , 8 , 59 }, /* index:  71   |11111011  */
    { 0xfc , 8 , 88 }, /* index:  72   |11111100  */
    { 0xfd , 8 , 90 }, /* index:  73   |11111101  */
    { 0x3f8 , 10 , 33 }, /* index:  74   |11111110|00  */
    { 0x3f9 , 10 , 34 }, /* index:  75   |11111110|01  */
    { 0x3fa , 10 , 40 }, /* index:  76   |11111110|10  */
    { 0x3fb , 10 , 41 }, /* index:  77   |11111110|11  */
    { 0x3fc , 10 , 63 }, /* index:  78   |11111111|00  */
    { 0x7fa , 11 , 39 }, /* index:  79   |11111111|010  */
    { 0x7fb , 11 , 43 }, /* index:  80   |11111111|011  */
    { 0x7fc , 11 , 124 }, /* index:  81   |11111111|100  */
    { 0xffa , 12 , 35 }, /* index:  82   |11111111|1010  */
    { 0xffb , 12 , 62 }, /* index:  83   |11111111|1011  */
    { 0x1ff8 , 13 , 0 }, /* index:  84   |11111111|11000  */
    { 0x1ff9 , 13 , 36 }, /* index:  85   |11111111|11001  */
    { 0x1ffa , 13 , 64 }, /* index:  86   |11111111|11010  */
    { 0x1ffb , 13 , 91 }, /* index:  87   |11111111|11011  */
    { 0x1ffc , 13 , 93 }, /* index:  88   |11111111|11100  */
    { 0x1ffd , 13 , 126 }, /* index:  89   |11111111|11101  */
    { 0x3ffc , 14 , 94 }, /* index:  90   |11111111|111100  */
    { 0x3ffd , 14 , 125 }, /* index:  91   |11111111|111101  */
    { 0x7ffc , 15 , 60 }, /* index:  92   |11111111|1111100  */
    { 0x7ffd , 15 , 96 }, /* index:  93   |11111111|1111101  */
    { 0x7ffe , 15 , 123 }, /* index:  94   |11111111|1111110  */
    { 0x7fff0 , 19 , 92 }, /* index:  95   |11111111|11111110|000  */
    { 0x7fff1 , 19 , 195 }, /* index:  96   |11111111|11111110|001  */
    { 0x7fff2 , 19 , 208 }, /* index:  97   |11111111|11111110|010  */
    { 0xfffe6 , 20 , 128 }, /* index:  98   |11111111|11111110|0110  */
    { 0xfffe7 , 20 , 130 }, /* index:  99   |11111111|11111110|0111  */
    { 0xfffe8 , 20 , 131 }, /* index:  100   |11111111|11111110|1000  */
    { 0xfffe9 , 20 , 162 }, /* index:  101   |11111111|11111110|1001  */
    { 0xfffea , 20 , 184 }, /* index:  102   |11111111|11111110|1010  */
    { 0xfffeb , 20 , 194 }, /* index:  103   |11111111|11111110|1011  */
    { 0xfffec , 20 , 224 }, /* index:  104   |11111111|11111110|1100  */
    { 0xfffed , 20 , 226 }, /* index:  105   |11111111|11111110|1101  */
    { 0x1fffdc , 21 , 153 }, /* index:  106   |11111111|11111110|11100  */
    { 0x1fffdd , 21 , 161 }, /* index:  107   |11111111|11111110|11101  */
    { 0x1fffde , 21 , 167 }, /* index:  108   |11111111|11111110|11110  */
    { 0x1fffdf , 21 , 172 }, /* index:  109   |11111111|11111110|11111  */
    { 0x1fffe0 , 21 , 176 }, /* index:  110   |11111111|11111111|00000  */
    { 0x1fffe1 , 21 , 177 }, /* index:  111   |11111111|11111111|00001  */
    { 0x1fffe2 , 21 , 179 }, /* index:  112   |11111111|11111111|00010  */
    { 0x1fffe3 , 21 , 209 }, /* index:  113   |11111111|11111111|00011  */
    { 0x1fffe4 , 21 , 216 }, /* index:  114   |11111111|11111111|00100  */
    { 0x1fffe5 , 21 , 217 }, /* index:  115   |11111111|11111111|00101  */
    { 0x1fffe6 , 21 , 227 }, /* index:  116   |11111111|11111111|00110  */
    { 0x1fffe7 , 21 , 229 }, /* index:  117   |11111111|11111111|00111  */
    { 0x1fffe8 , 21 , 230 }, /* index:  118   |11111111|11111111|01000  */
    { 0x3fffd2 , 22 , 129 }, /* index:  119   |11111111|11111111|010010  */
    { 0x3fffd3 , 22 , 132 }, /* index:  120   |11111111|11111111|010011  */
    { 0x3fffd4 , 22 , 133 }, /* index:  121   |11111111|11111111|010100  */
    { 0x3fffd5 , 22 , 134 }, /* index:  122   |11111111|11111111|010101  */
    { 0x3fffd6 , 22 , 136 }, /* index:  123   |11111111|11111111|010110  */
    { 0x3fffd7 , 22 , 146 }, /* index:  124   |11111111|11111111|010111  */
    { 0x3fffd8 , 22 , 154 }, /* index:  125   |11111111|11111111|011000  */
    { 0x3fffd9 , 22 , 156 }, /* index:  126   |11111111|11111111|011001  */
    { 0x3fffda , 22 , 160 }, /* index:  127   |11111111|11111111|011010  */
    { 0x3fffdb , 22 , 163 }, /* index:  128   |11111111|11111111|011011  */
    { 0x3fffdc , 22 , 164 }, /* index:  129   |11111111|11111111|011100  */
    { 0x3fffdd , 22 , 169 }, /* index:  130   |11111111|11111111|011101  */
    { 0x3fffde , 22 , 170 }, /* index:  131   |11111111|11111111|011110  */
    { 0x3fffdf , 22 , 173 }, /* index:  132   |11111111|11111111|011111  */
    { 0x3fffe0 , 22 , 178 }, /* index:  133   |11111111|11111111|100000  */
    { 0x3fffe1 , 22 , 181 }, /* index:  134   |11111111|11111111|100001  */
    { 0x3fffe2 , 22 , 185 }, /* index:  135   |11111111|11111111|100010  */
    { 0x3fffe3 , 22 , 186 }, /* index:  136   |11111111|11111111|100011  */
    { 0x3fffe4 , 22 , 187 }, /* index:  137   |11111111|11111111|100100  */
    { 0x3fffe5 , 22 , 189 }, /* index:  138   |11111111|11111111|100101  */
    { 0x3fffe6 , 22 , 190 }, /* index:  139   |11111111|11111111|100110  */
    { 0x3fffe7 , 22 , 196 }, /* index:  140   |11111111|11111111|100111  */
    { 0x3fffe8 , 22 , 198 }, /* index:  141   |11111111|11111111|101000  */
    { 0x3fffe9 , 22 , 228 }, /* index:  142   |11111111|11111111|101001  */
    { 0x3fffea , 22 , 232 }, /* index:  143   |11111111|11111111|101010  */
    { 0x3fffeb , 22 , 233 }, /* index:  144   |11111111|11111111|101011  */
    { 0x7fffd8 , 23 , 1 }, /* index:  145   |11111111|11111111|1011000  */
    { 0x7fffd9 , 23 , 135 }, /* index:  146   |11111111|11111111|1011001  */
    { 0x7fffda , 23 , 137 }, /* index:  147   |11111111|11111111|1011010  */
    { 0x7fffdb , 23 , 138 }, /* index:  148   |11111111|11111111|1011011  */
    { 0x7fffdc , 23 , 139 }, /* index:  149   |11111111|11111111|1011100  */
    { 0x7fffdd , 23 , 140 }, /* index:  150   |11111111|11111111|1011101  */
    { 0x7fffde , 23 , 141 }, /* index:  151   |11111111|11111111|1011110  */
    { 0x7fffdf , 23 , 143 }, /* index:  152   |11111111|11111111|1011111  */
    { 0x7fffe0 , 23 , 147 }, /* index:  153   |11111111|11111111|1100000  */
    { 0x7fffe1 , 23 , 149 }, /* index:  154   |11111111|11111111|1100001  */
    { 0x7fffe2 , 23 , 150 }, /* index:  155   |11111111|11111111|1100010  */
    { 0x7fffe3 , 23 , 151 }, /* index:  156   |11111111|11111111|1100011  */
    { 0x7fffe4 , 23 , 152 }, /* index:  157   |11111111|11111111|1100100  */
    { 0x7fffe5 , 23 , 155 }, /* index:  158   |11111111|11111111|1100101  */
    { 0x7fffe6 , 23 , 157 }, /* index:  159   |11111111|11111111|1100110  */
    { 0x7fffe7 , 23 , 158 }, /* index:  160   |11111111|11111111|1100111  */
    { 0x7fffe8 , 23 , 165 }, /* index:  161   |11111111|11111111|1101000  */
    { 0x7fffe9 , 23 , 166 }, /* index:  162   |11111111|11111111|1101001  */
    { 0x7fffea , 23 , 168 }, /* index:  163   |11111111|11111111|1101010  */
    { 0x7fffeb , 23 , 174 }, /* index:  164   |11111111|11111111|1101011  */
    { 0x7fffec , 23 , 175 }, /* index:  165   |11111111|11111111|1101100  */
    { 0x7fffed , 23 , 180 }, /* index:  166   |11111111|11111111|1101101  */
    { 0x7fffee , 23 , 182 }, /* index:  167   |11111111|11111111|1101110  */
    { 0x7fffef , 23 , 183 }, /* index:  168   |11111111|11111111|1101111  */
    { 0x7ffff0 , 23 , 188 }, /* index:  169   |11111111|11111111|1110000  */
    { 0x7ffff1 , 23 , 191 }, /* index:  170   |11111111|11111111|1110001  */
    { 0x7ffff2 , 23 , 197 }, /* index:  171   |11111111|11111111|1110010  */
    { 0x7ffff3 , 23 , 231 }, /* index:  172   |11111111|11111111|1110011  */
    { 0x7ffff4 , 23 , 239 }, /* index:  173   |11111111|11111111|1110100  */
    { 0xffffea , 24 , 9 }, /* index:  174   |11111111|11111111|11101010  */
    { 0xffffeb , 24 , 142 }, /* index:  175   |11111111|11111111|11101011  */
    { 0xffffec , 24 , 144 }, /* index:  176   |11111111|11111111|11101100  */
    { 0xffffed , 24 , 145 }, /* index:  177   |11111111|11111111|11101101  */
    { 0xffffee , 24 , 148 }, /* index:  178   |11111111|11111111|11101110  */
    { 0xffffef , 24 , 159 }, /* index:  179   |11111111|11111111|11101111  */
    { 0xfffff0 , 24 , 171 }, /* index:  180   |11111111|11111111|11110000  */
    { 0xfffff1 , 24 , 206 }, /* index:  181   |11111111|11111111|11110001  */
    { 0xfffff2 , 24 , 215 }, /* index:  182   |11111111|11111111|11110010  */
    { 0xfffff3 , 24 , 225 }, /* index:  183   |11111111|11111111|11110011  */
    { 0xfffff4 , 24 , 236 }, /* index:  184   |11111111|11111111|11110100  */
    { 0xfffff5 , 24 , 237 }, /* index:  185   |11111111|11111111|11110101  */
    { 0x1ffffec , 25 , 199 }, /* index:  186   |11111111|11111111|11110110|0  */
    { 0x1ffffed , 25 , 207 }, /* index:  187   |11111111|11111111|11110110|1  */
    { 0x1ffffee , 25 , 234 }, /* index:  188   |11111111|11111111|11110111|0  */
    { 0x1ffffef , 25 , 235 }, /* index:  189   |11111111|11111111|11110111|1  */
    { 0x3ffffe0 , 26 , 192 }, /* index:  190   |11111111|11111111|11111000|00  */
    { 0x3ffffe1 , 26 , 193 }, /* index:  191   |11111111|11111111|11111000|01  */
    { 0x3ffffe2 , 26 , 200 }, /* index:  192   |11111111|11111111|11111000|10  */
    { 0x3ffffe3 , 26 , 201 }, /* index:  193   |11111111|11111111|11111000|11  */
    { 0x3ffffe4 , 26 , 202 }, /* index:  194   |11111111|11111111|11111001|00  */
    { 0x3ffffe5 , 26 , 205 }, /* index:  195   |11111111|11111111|11111001|01  */
    { 0x3ffffe6 , 26 , 210 }, /* index:  196   |11111111|11111111|11111001|10  */
    { 0x3ffffe7 , 26 , 213 }, /* index:  197   |11111111|11111111|11111001|11  */
    { 0x3ffffe8 , 26 , 218 }, /* index:  198   |11111111|11111111|11111010|00  */
    { 0x3ffffe9 , 26 , 219 }, /* index:  199   |11111111|11111111|11111010|01  */
    { 0x3ffffea , 26 , 238 }, /* index:  200   |11111111|11111111|11111010|10  */
    { 0x3ffffeb , 26 , 240 }, /* index:  201   |11111111|11111111|11111010|11  */
    { 0x3ffffec , 26 , 242 }, /* index:  202   |11111111|11111111|11111011|00  */
    { 0x3ffffed , 26 , 243 }, /* index:  203   |11111111|11111111|11111011|01  */
    { 0x3ffffee , 26 , 255 }, /* index:  204   |11111111|11111111|11111011|10  */
    { 0x7ffffde , 27 , 203 }, /* index:  205   |11111111|11111111|11111011|110  */
    { 0x7ffffdf , 27 , 204 }, /* index:  206   |11111111|11111111|11111011|111  */
    { 0x7ffffe0 , 27 , 211 }, /* index:  207   |11111111|11111111|11111100|000  */
    { 0x7ffffe1 , 27 , 212 }, /* index:  208   |11111111|11111111|11111100|001  */
    { 0x7ffffe2 , 27 , 214 }, /* index:  209   |11111111|11111111|11111100|010  */
    { 0x7ffffe3 , 27 , 221 }, /* index:  210   |11111111|11111111|11111100|011  */
    { 0x7ffffe4 , 27 , 222 }, /* index:  211   |11111111|11111111|11111100|100  */
    { 0x7ffffe5 , 27 , 223 }, /* index:  212   |11111111|11111111|11111100|101  */
    { 0x7ffffe6 , 27 , 241 }, /* index:  213   |11111111|11111111|11111100|110  */
    { 0x7ffffe7 , 27 , 244 }, /* index:  214   |11111111|11111111|11111100|111  */
    { 0x7ffffe8 , 27 , 245 }, /* index:  215   |11111111|11111111|11111101|000  */
    { 0x7ffffe9 , 27 , 246 }, /* index:  216   |11111111|11111111|11111101|001  */
    { 0x7ffffea , 27 , 247 }, /* index:  217   |11111111|11111111|11111101|010  */
    { 0x7ffffeb , 27 , 248 }, /* index:  218   |11111111|11111111|11111101|011  */
    { 0x7ffffec , 27 , 250 }, /* index:  219   |11111111|11111111|11111101|100  */
    { 0x7ffffed , 27 , 251 }, /* index:  220   |11111111|11111111|11111101|101  */
    { 0x7ffffee , 27 , 252 }, /* index:  221   |11111111|11111111|11111101|110  */
    { 0x7ffffef , 27 , 253 }, /* index:  222   |11111111|11111111|11111101|111  */
    { 0x7fffff0 , 27 , 254 }, /* index:  223   |11111111|11111111|11111110|000  */
    { 0xfffffe2 , 28 , 2 }, /* index:  224   |11111111|11111111|11111110|0010  */
    { 0xfffffe3 , 28 , 3 }, /* index:  225   |11111111|11111111|11111110|0011  */
    { 0xfffffe4 , 28 , 4 }, /* index:  226   |11111111|11111111|11111110|0100  */
    { 0xfffffe5 , 28 , 5 }, /* index:  227   |11111111|11111111|11111110|0101  */
    { 0xfffffe6 , 28 , 6 }, /* index:  228   |11111111|11111111|11111110|0110  */
    { 0xfffffe7 , 28 , 7 }, /* index:  229   |11111111|11111111|11111110|0111  */
    { 0xfffffe8 , 28 , 8 }, /* index:  230   |11111111|11111111|11111110|1000  */
    { 0xfffffe9 , 28 , 11 }, /* index:  231   |11111111|11111111|11111110|1001  */
    { 0xfffffea , 28 , 12 }, /* index:  232   |11111111|11111111|11111110|1010  */
    { 0xfffffeb , 28 , 14 }, /* index:  233   |11111111|11111111|11111110|1011  */
    { 0xfffffec , 28 , 15 }, /* index:  234   |11111111|11111111|11111110|1100  */
    { 0xfffffed , 28 , 16 }, /* index:  235   |11111111|11111111|11111110|1101  */
    { 0xfffffee , 28 , 17 }, /* index:  236   |11111111|11111111|11111110|1110  */
    { 0xfffffef , 28 , 18 }, /* index:  237   |11111111|11111111|11111110|1111  */
    { 0xffffff0 , 28 , 19 }, /* index:  238   |11111111|11111111|11111111|0000  */
    { 0xffffff1 , 28 , 20 }, /* index:  239   |11111111|11111111|11111111|0001  */
    { 0xffffff2 , 28 , 21 }, /* index:  240   |11111111|11111111|11111111|0010  */
    { 0xffffff3 , 28 , 23 }, /* index:  241   |11111111|11111111|11111111|0011  */
    { 0xffffff4 , 28 , 24 }, /* index:  242   |11111111|11111111|11111111|0100  */
    { 0xffffff5 , 28 , 25 }, /* index:  243   |11111111|11111111|11111111|0101  */
    { 0xffffff6 , 28 , 26 }, /* index:  244   |11111111|11111111|11111111|0110  */
    { 0xffffff7 , 28 , 27 }, /* index:  245   |11111111|11111111|11111111|0111  */
    { 0xffffff8 , 28 , 28 }, /* index:  246   |11111111|11111111|11111111|1000  */
    { 0xffffff9 , 28 , 29 }, /* index:  247   |11111111|11111111|11111111|1001  */
    { 0xffffffa , 28 , 30 }, /* index:  248   |11111111|11111111|11111111|1010  */
    { 0xffffffb , 28 , 31 }, /* index:  249   |11111111|11111111|11111111|1011  */
    { 0xffffffc , 28 , 127 }, /* index:  250   |11111111|11111111|11111111|1100  */
    { 0xffffffd , 28 , 220 }, /* index:  251   |11111111|11111111|11111111|1101  */
    { 0xffffffe , 28 , 249 }, /* index:  252   |11111111|11111111|11111111|1110  */
    { 0x3ffffffc , 30 , 10 }, /* index:  253   |11111111|11111111|11111111|111100  */
    { 0x3ffffffd , 30 , 13 }, /* index:  254   |11111111|11111111|11111111|111101  */
    { 0x3ffffffe , 30 , 22 }, /* index:  255   |11111111|11111111|11111111|111110  */
    { 0x3fffffff , 30 , 256 }, /* index:  256   |11111111|11111111|11111111|111111  */
};

size_t nb_h3zero_qpack_huffman_table = sizeof(h3zero_qpack_huffman_table) / sizeof(h3zero_qpack_huffman_code_t);

typedef struct st_h3zero_qpack_huffman_index_t {
    uint64_t range_max;
    int start_index;
} h3zero_qpack_huffman_index_t;

h3zero_qpack_huffman_index_t h3zero_qpack_index[] = {
    { 0x50000000 , 0 }, /* index:  10   |010100  */
    { 0xb8000000 , 10 }, /* index:  36   |1011100  */
    { 0xf8000000 , 36 }, /* index:  68   |11111000  */
    { 0xfe000000 , 68 }, /* index:  74   |11111110|00  */
    { 0xff000000 , 74 }, /* index:  78   |11111111|00  */
    { 0xff400000 , 78 }, /* index:  79   |11111111|010  */
    { 0xffa00000 , 79 }, /* index:  82   |11111111|1010  */
    { 0xffc00000 , 82 }, /* index:  84   |11111111|11000  */
    { 0xfff00000 , 84 }, /* index:  90   |11111111|111100  */
    { 0xfff80000 , 92 }, /* index:  92   |11111111|1111100  */
    { 0xfffe0000 , -3 }, /* index:  95   |11111111|11111110|000  */
    { 0xfffe6000 , 95 }, /* index:  98   |11111111|11111110|0110  */
    { 0xfffee000 , 98 }, /* index:  106   |11111111|11111110|11100  */
    { 0xffff0000 , 106 }, /* index:  110   |11111111|11111111|00000  */
    { 0xffff4800 , 110 }, /* index:  119   |11111111|11111111|010010  */
    { 0xffffb000 , 119 }, /* index:  145   |11111111|11111111|1011000  */
    { 0xffffea00 , 145 }, /* index:  174   |11111111|11111111|11101010  */
    { 0xfffff600 , 174 }, /* index:  186   |11111111|11111111|11110110|0  */
    { 0xfffff800 , 186 }, /* index:  190   |11111111|11111111|11111000|00  */
    { 0xfffffbc0 , 190 }, /* index:  205   |11111111|11111111|11111011|110  */
    { 0xfffffe20 , 205 }, /* index:  224   |11111111|11111111|11111110|0010  */
    { 0xfffffff0 , 224 }, /* index:  253   |11111111|11111111|11111111|111100  */
    { 0x100000000ull , 253 }, /* index:  256   |11111111|11111111|11111111|111111  */
};

size_t nb_h3zero_qpack_index = sizeof(h3zero_qpack_index) / sizeof(h3zero_qpack_huffman_index_t);

int hzero_qpack_huffman_decode(uint8_t * bytes, uint8_t * bytes_max, uint8_t * decoded, size_t max_decoded, size_t * nb_decoded) {
    int ret = 0;
    uint64_t val_in = 0;
    int bits_in = 0;
    uint64_t top_32;
    int consumed_bits = 0;
    size_t decoded_index = 0;
    int available_bits = 8 * ((int)(bytes_max - bytes));
    int start_index;

    while (bytes < bytes_max || bits_in > 0) {
        start_index = -1;

        /* Refill the registry */
        while (bits_in < 57 && bytes < bytes_max) {
            uint64_t added = *bytes++;
            int shift = 64 - bits_in - 8;
            added <<= shift;
            val_in |= added;
            bits_in += 8;
        }

        /* check top 8 bits */
        top_32 = (val_in >> 32) & 0xFFFFFFFF;

        for (size_t i = 0; i < nb_h3zero_qpack_index; i++) {
            if (top_32 < h3zero_qpack_index[i].range_max) {
                start_index = h3zero_qpack_index[i].start_index;
                break;
            }
        }

        if (start_index < 0) {
            /* decoding error */
            ret = -1;
            break;
        }
        else {
            int nb_bits = h3zero_qpack_huffman_table[start_index].nb_bits;

            if (nb_bits > bits_in) {
                /* error, not enough bits for this code.
                 * exit the decoder */
                if (consumed_bits + 7 < available_bits) {
                    /* this is an actual error! */
                    ret = -1;
                }
                break;
            }
            else {
                uint64_t symbol = val_in >> (64 - nb_bits);
                uint64_t symbol_index = start_index + symbol -
                    h3zero_qpack_huffman_table[start_index].right_shift_hex;

                if (symbol_index > nb_h3zero_qpack_huffman_table ||
                    h3zero_qpack_huffman_table[symbol_index].code > 255) {
                    /* bad access to the tables */
                    ret = -1;
                    break;
                } else if (decoded_index < max_decoded) {
                    decoded[decoded_index++] = (uint8_t) h3zero_qpack_huffman_table[symbol_index].code;
                    consumed_bits += nb_bits;
                    if (nb_bits < 64) {
                        val_in <<= nb_bits;
                        bits_in -= nb_bits;
                    }
                    else {
                        val_in = 0;
                        bits_in = 0;
                    }
                }
                else {
                    /* input is too long */
                    break;
                }
            }
        }
    }

    *nb_decoded = decoded_index;

    return ret;
}