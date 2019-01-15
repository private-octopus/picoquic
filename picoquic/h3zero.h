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

#include <stdint.h>

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
    h3zero_setting_num_placeholder = 0x3, 
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
#define H3ZERO_QPACK_CODE_PATH 1
#define H3ZERO_QPACK_CODE_404 27
#define H3ZERO_QPACK_CODE_200 25

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

/*
 * Server side callback contexts
 */

#define H3ZERO_COMMAND_MAX 256

typedef enum {
    h3zero_server_stream_status_none = 0,
    h3zero_server_stream_status_receiving,
    h3zero_server_stream_status_finished
} h3zero_server_stream_status_t;

typedef struct st_h3zero_server_stream_ctx_t {
    struct st_h3zero_server_stream_ctx_t* next_stream;
    h3zero_server_stream_status_t status;
    uint64_t stream_id;
    size_t command_length;
    size_t response_length;
    uint8_t command[H3ZERO_COMMAND_MAX];
} h3zero_server_stream_ctx_t;

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
} h3zero_header_parts_t;

typedef struct st_picoquic_first_server_callback_ctx_t {
    h3zero_server_stream_ctx_t* first_stream;
    size_t buffer_max;
    uint8_t* buffer;
} h3zero_server_callback_ctx_t;


uint8_t * h3zero_qpack_int_encode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask, uint64_t val);
uint8_t * h3zero_qpack_int_decode(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t mask, uint64_t *val);

uint8_t * h3zero_parse_qpack_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_header_parts_t * parts);

uint8_t * h3zero_create_request_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    uint8_t const * path, size_t path_length);
uint8_t * h3zero_create_response_header_frame(uint8_t * bytes, uint8_t * bytes_max,
    h3zero_content_type_enum doc_type);
uint8_t * h3zero_create_not_found_header_frame(uint8_t * bytes, uint8_t * bytes_max);



#endif /* H3ZERO_H */