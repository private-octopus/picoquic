/*
* Author: Christian Huitema
* Copyright (c) 2018, Private Octopus, Inc.
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
#ifndef H3ZERO_H
#define H3ZERO_H

#define H3ZERO_NO_ERROR 0x0000 /* No error */
#define H3ZERO_WRONG_SETTING_DIRECTION 0x0001 /* Setting sent in wrong direction */
#define H3ZERO_PUSH_REFUSED 0x0002 /* Client refused pushed content */
#define H3ZERO_INTERNAL_ERROR 0x0003 /* Internal error */
#define H3ZERO_PUSH_ALREADY_IN_CACHE 0x0004 /* Pushed content already cached */
#define H3ZERO_REQUEST_CANCELLED 0x0005 /* Data no longer needed */
#define H3ZERO_INCOMPLETE_REQUEST 0x0006 /* Stream terminated early */
#define H3ZERO_CONNECT_ERROR 0x0007 /* TCP reset or error on CONNECT request */
#define H3ZERO_EXCESSIVE_LOAD 0x0008 /* Peer generating excessive load */
#define H3ZERO_VERSION_FALLBACK 0x0009 /* Retry over HTTP/1.1 */
#define H3ZERO_WRONG_STREAM 0x000A /* A frame was sent on the wrong stream */
#define H3ZERO_LIMIT_EXCEEDED 0x000B /* An identifier limit was exceeded */
#define H3ZERO_DUPLICATE_PUSH 0x000C /* Push ID was fulfilled multiple times */
#define H3ZERO_UNKNOWN_STREAM_TYPE 0x000D /* Unknown unidirectional stream type */
#define H3ZERO_WRONG_STREAM_COUNT 0x000E /* Too many unidirectional streams */
#define H3ZERO_CLOSED_CRITICAL_STREAM 0x000F /* Critical stream was closed */
#define H3ZERO_WRONG_STREAM_DIRECTION 0x0010 /* Unidirectional stream in wrong direction */
#define H3ZERO_EARLY_RESPONSE 0x0011 /* Remainder of request not needed */
#define H3ZERO_MISSING_SETTINGS 0x0012 /* No SETTINGS frame received */
#define H3ZERO_UNEXPECTED_FRAME 0x0013 /* Frame not permitted in the current state */
#define H3ZERO_MALFORMED_FRAME(frame_type) (0x0100|frame_type) /* Error in frame formatting */


typedef enum {
	h3zero_frame_data = 0,
    h3zero_frame_header = 1,
    h3zero_frame_priority = 2,
    h3zero_frame_cancel_push = 3,
    h3zero_frame_settings = 4,
    h3zero_frame_push_promise = 5,
    h3zero_frame_goaway = 7,
    h3zero_frame_max_push_id = 0xd,
    h3zero_frame_reserved_base = 0xb,
    h3zero_frame_reserved_delta = 0x1f
} h3zero_frame_type_enum_t;

typedef enum {
    h3zero_setting_reserved = 0x0,
	h3zero_setting_header_table_size = 0x1,
    h3zero_setting_num_placeholder = 0x9, 
    h3zero_setting_max_header_list_size = 0x6,
	h3zero_qpack_blocked_streams = 0x07,
	h3zero_setting_grease_signature =0x0a0a,
    h3zero_setting_grease_mask = 0x0f0f
} h3zero_settings_enum_t;

typedef enum {
    http_header_unknown = 0,
    http_pseudo_header_authority,
    http_pseudo_header_path,
    http_header_age,
    http_header_content_disposition,
    http_header_content_length,
    http_header_cookie,
    http_header_date,
    http_header_etag,
    http_header_if_modified_since,
    http_header_if_none_match,
    http_header_last_modified,
    http_header_link,
    http_header_location,
    http_header_referer,
    http_header_set_cookie,
    http_pseudo_header_method,
    http_pseudo_header_scheme,
    http_pseudo_header_status,
    http_header_accept,
    http_header_accept_encoding,
    http_header_accept_ranges,
    http_header_access_control_allow_headers,
    http_header_access_control_allow_origin,
    http_header_cache_control,
    http_header_content_encoding,
    http_header_content_type,
    http_header_range,
    http_header_strict_transport_security,
    http_header_vary,
    http_header_x_content_type_options,
    http_header_x_xss_protection,
    http_header_accept_language,
    http_header_access_control_allow_credentials,
    http_header_access_control_allow_methods,
    http_header_access_control_expose_headers,
    http_header_access_control_request_headers,
    http_header_access_control_request_method,
    http_header_alt_svc,
    http_header_authorization,
    http_header_content_security_policy,
    http_header_early_data,
    http_header_expect_ct,
    http_header_forwarded,
    http_header_if_range,
    http_header_origin,
    http_header_purpose,
    http_header_server,
    http_header_timing_allow_origin,
    http_header_upgrade_insecure_requests,
    http_header_user_agent,
    http_header_x_forwarded_for,
    http_header_x_frame_options,
	http_header_max
} http_header_enum_t;

#define H3ZERO_QPACK_CODE_GET 17
#define H3ZERO_QPACK_CODE_POST 20
#define H3ZERO_QPACK_CODE_PATH 1
#define H3ZERO_QPACK_CODE_404 27
#define H3ZERO_QPACK_CODE_200 25
#define H3ZERO_QPACK_ALLOW_GET 76
#define H3ZERO_QPACK_AUTHORITY 0
#define H3ZERO_QPACK_SCHEME_HTTPS 23
#define H3ZERO_QPACK_TEXT_PLAIN 53

typedef struct st_h3zero_qpack_static_t {
    int index;
    http_header_enum_t header;
    char const * content;
    int enum_as_int; /* Documented for some interesting values */
} h3zero_qpack_static_t;

typedef struct st_h3zero_settings_t {
    unsigned int header_size;
    unsigned int blocked_streams;
} h3zero_settings_t;

typedef enum {
    h3zero_content_type_none = 0,
    h3zero_content_type_not_supported,
    h3zero_content_type_text_html,
    h3zero_content_type_text_plain,
    h3zero_content_type_image_gif,
    h3zero_content_type_image_jpeg,
    h3zero_content_type_image_png,
    h3zero_content_type_dns_message,
    h3zero_content_type_javascript,
    h3zero_content_type_json,
    h3zero_content_type_www_form_urlencoded,
    h3zero_content_type_text_css
} h3zero_content_type_enum;

typedef enum {
    h3zero_method_none = 0,
    h3zero_method_not_supported,
    h3zero_method_connect,
    h3zero_method_delete,
    h3zero_method_get,
    h3zero_method_head,
    h3zero_method_options,
    h3zero_method_post,
    h3zero_method_put
} h3zero_method_enum;

typedef struct st_h3zero_header_parts_t {
    h3zero_method_enum method;
    uint8_t const * path;
    size_t path_length;
    int status;
    h3zero_content_type_enum content_type;
    unsigned int path_is_huffman : 1;
} h3zero_header_parts_t;

extern uint8_t const * h3zero_default_setting_frame;

extern const size_t h3zero_default_setting_frame_size;

uint8_t * h3zero_qpack_int_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask, uint64_t val);
uint8_t * h3zero_qpack_int_decode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask, uint64_t *val);

uint8_t * h3zero_parse_qpack_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_header_parts_t * parts);
uint8_t * h3zero_create_request_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length, char const * host);
uint8_t * h3zero_create_post_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length, char const * host,
    h3zero_content_type_enum content_type);
uint8_t * h3zero_create_response_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_content_type_enum doc_type);
uint8_t * h3zero_create_not_found_header_frame(uint8_t * bytes, uint8_t * bytes_max);
uint8_t * h3zero_create_bad_method_header_frame(uint8_t * bytes, uint8_t * bytes_max);

/* Parsing of a data stream. This is implemented as a filter, with a set of states:
 *
 * - Reading frame length: obtaining the length and type of the next frame.
 * - Reading header frame: obtaining the bytes of the data frame.
 *   When all bytes are obtained, the header is parsed and the header
 *   structure is documented. State moves back to initial, with header-read
 *   flag set. Having two frame headers before a data frame is a bug.
 * - Reading data frame: the frame header indicated a data frame of
 *   length N. Treat the following N bytes as data.
 *
 * There may be several data frames in a stream. The application will pick
 * the bytes and treat them as data.
 */

typedef struct st_h3zero_data_stream_state_t {
    h3zero_header_parts_t header;
    h3zero_header_parts_t trailer;
    uint8_t * current_frame;
    uint64_t current_frame_type;
    uint64_t current_frame_length;
    uint64_t current_frame_read;
    uint8_t frame_header[16];
    size_t frame_header_read;
    unsigned int frame_header_parsed : 1;
    unsigned int header_found : 1;
    unsigned int data_found : 1;
    unsigned int trailer_found : 1;
} h3zero_data_stream_state_t;

uint8_t * h3zero_parse_data_stream(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_data_stream_state_t * stream_state, size_t * available_data, uint16_t * error_found);

void h3zero_delete_data_stream_state(h3zero_data_stream_state_t * stream_state);

int hzero_qpack_huffman_decode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t * decoded, size_t max_decoded, size_t * nb_decoded);

#endif /* H3ZERO_H */