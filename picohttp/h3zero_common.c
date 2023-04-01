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

/* Common code used by the server and the client implementations.
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <picotls.h>
#include "picosplay.h"
#include "picoquic.h"
#include "picoquic_utils.h"
#include "tls_api.h"
#include "h3zero.h"
#include "h3zero_common.h"



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

void * picohttp_stream_node_value(picosplay_node_t * node)
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
		(void)stream_ctx->path_callback(NULL, NULL, 0, picohttp_callback_free, stream_ctx, stream_ctx->path_callback_ctx);
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

picohttp_server_stream_ctx_t* picohttp_find_stream(picosplay_tree_t * stream_tree, uint64_t stream_id)
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
			if (!IS_BIDIR_STREAM_ID(stream_id)) {
				if (IS_LOCAL_STREAM_ID(stream_id, picoquic_is_client(cnx))) {
					stream_ctx->ps.stream_state.is_fin_received = 1;
				}
				else {
					stream_ctx->ps.stream_state.is_fin_sent = 1;
				}
			}
			
			picosplay_insert(stream_tree, stream_ctx);
		}
	}

	return stream_ctx;
}

void h3zero_init_stream_tree(picosplay_tree_t * h3_stream_tree)
{
	picosplay_init_tree(h3_stream_tree, picohttp_stream_node_compare, picohttp_stream_node_create, picohttp_stream_node_delete, picohttp_stream_node_value);
}


/* Declare a stream prefix, such as used by webtransport or masque
 */

h3zero_stream_prefix_t* h3zero_find_stream_prefix(h3zero_stream_prefixes_t* prefixes, uint64_t prefix)
{
	h3zero_stream_prefix_t* prefix_ctx = prefixes->first;

	while (prefix_ctx != NULL) {
		if (prefix_ctx->prefix == prefix) {
			break;
		}
		prefix_ctx = prefix_ctx->next;
	}

	return prefix_ctx;
}

int h3zero_declare_stream_prefix(h3zero_stream_prefixes_t* prefixes, uint64_t prefix, picohttp_post_data_cb_fn function_call, void* function_ctx)
{
	int ret = 0;
	h3zero_stream_prefix_t* prefix_ctx = h3zero_find_stream_prefix(prefixes, prefix);

	if (prefix_ctx == NULL) {
		prefix_ctx = (h3zero_stream_prefix_t*)malloc(sizeof(h3zero_stream_prefix_t));
		if (prefix_ctx == NULL) {
			ret = -1;
		}
		else {
			memset(prefix_ctx, 0, sizeof(h3zero_stream_prefix_t));
			prefix_ctx->prefix = prefix;
			prefix_ctx->function_call = function_call;
			prefix_ctx->function_ctx = function_ctx;
			if (prefixes->last == NULL) {
				prefixes->first = prefix_ctx;
			}
			else {
				prefixes->last->next = prefix_ctx;
			}
			prefix_ctx->previous = prefixes->last;
			prefixes->last = prefix_ctx;
		}
	}
	else {
		ret = -1;
	}
	return ret;
}

void h3zero_delete_stream_prefix(h3zero_stream_prefixes_t* prefixes, uint64_t prefix)
{
	h3zero_stream_prefix_t* prefix_ctx = h3zero_find_stream_prefix(prefixes, prefix);
	if (prefix_ctx != NULL) {
		if (prefix_ctx->previous == NULL) {
			prefixes->first = prefix_ctx->next;
		}
		else {
			prefix_ctx->previous->next = prefix_ctx->next;
		}
		if (prefix_ctx->next == NULL) {
			prefixes->last = prefix_ctx->previous;
		}
		else {
			prefix_ctx->next->previous = prefix_ctx->previous;
		}
		free(prefix_ctx);
	}
}

void h3zero_delete_all_stream_prefixes(picoquic_cnx_t * cnx, h3zero_stream_prefixes_t* prefixes)
{
	h3zero_stream_prefix_t* next;

	while ((next = prefixes->first) != NULL) {
		/* Request the app to clean up its memory */
		if (next->function_call != NULL) {
			(void)next->function_call(cnx, NULL, 0, picohttp_callback_free,
				NULL, next->function_ctx);
		}
		if (prefixes->first == next){
			/* the prefix was not deleted as part of app cleanup */
			h3zero_delete_stream_prefix(prefixes, next->prefix);
		}
	}
}

uint64_t h3zero_parse_stream_prefix(uint8_t* buffer_8, size_t* nb_in_buffer, uint8_t* data, size_t data_length, size_t * nb_read)
{
	uint64_t prefix = UINT64_MAX;

	*nb_read = 0;
	while (*nb_read < data_length) {
		size_t v_len = (*nb_in_buffer > 0)?VARINT_LEN_T(buffer_8, size_t):8;
		if (*nb_in_buffer < v_len) {
			buffer_8[*nb_in_buffer] = data[*nb_read];
			*nb_read += 1;
			*nb_in_buffer += 1;
		}
		if (*nb_in_buffer >= v_len) {
			(void)picoquic_frames_uint64_decode(buffer_8, buffer_8 + 8, &prefix);
			break;
		}
	}

	return prefix;
}

int h3zero_client_init(picoquic_cnx_t* cnx)
{
	uint8_t decoder_stream_head = 0x03;
	uint8_t encoder_stream_head = 0x02;
	int ret = picoquic_add_to_stream(cnx, 2, h3zero_default_setting_frame, h3zero_default_setting_frame_size, 0);

	if (ret == 0) {
		/* set the stream #2 to be the next stream to write! */
		ret = picoquic_set_stream_priority(cnx, 2, 0);
	}

	if (ret == 0) {
		/* set the stream 6 as the encoder stream, although we do not actually create dynamic codes. */
		ret = picoquic_add_to_stream(cnx, 6, &encoder_stream_head, 1, 0);
		if (ret == 0) {
			ret = picoquic_set_stream_priority(cnx, 6, 1);
		}
	}

	if (ret == 0) {
		/* set the stream 10 as the decoder stream, although we do not actually create dynamic codes. */
		ret = picoquic_add_to_stream(cnx, 10, &decoder_stream_head, 1, 0);
		if (ret == 0) {
			ret = picoquic_set_stream_priority(cnx, 10, 1);
		}
	}


	return ret;
}

/* Parse the first bytes of an unidir stream, and determine what to do with that stream.
 */
uint8_t* h3zero_parse_incoming_remote_stream(
	uint8_t* bytes, uint8_t* bytes_max,
	picohttp_server_stream_ctx_t* stream_ctx,
	picosplay_tree_t* stream_tree, h3zero_stream_prefixes_t* prefixes)
{
	h3zero_data_stream_state_t* stream_state = &stream_ctx->ps.stream_state;
	size_t frame_type_length = 0;

	if (!stream_state->frame_header_parsed) {
		if (stream_state->frame_header_read < 1) {
			stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
		}
		frame_type_length = VARINT_LEN_T(stream_state->frame_header, size_t);
		while (stream_state->frame_header_read < frame_type_length && bytes < bytes_max) {
			stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
		}
		if (stream_state->frame_header_read >= frame_type_length) {
			int is_wt_context_id_required = 0;
			int is_error = 0;

			(void)picoquic_frames_varint_decode(stream_state->frame_header, stream_state->frame_header + frame_type_length,
				&stream_state->current_frame_type);

			if (IS_BIDIR_STREAM_ID(stream_ctx->stream_id)) {
				switch (stream_state->current_frame_type) {
				case h3zero_frame_webtransport_stream:
					is_wt_context_id_required = 1;
					break;
				default:
					is_error = 1;
					break;
				}
			}
			else {
				switch (stream_state->current_frame_type) {
				case h3zero_stream_type_control: /* used to send/receive setting frame and other control frames. Ignored for now. */
					break;
				case h3zero_stream_type_push: /* Push type not supported in h3zero settings */
					is_error = 1;
					break;
				case h3zero_stream_type_qpack_encoder: /* not required since not using dynamic table */
					break;
				case h3zero_stream_type_qpack_decoder: /* not required since not using dynamic table */
					break;
				case h3zero_stream_type_webtransport: /* unidir stream is used as specified in web transport */
					is_wt_context_id_required = 1;
					break;
				default:
					bytes = NULL;
					break;
				}
			}

			if (!is_wt_context_id_required) {
				stream_state->frame_header_parsed = 1;
			} else {
				size_t context_id_length = 1;
				while (stream_state->frame_header_read < frame_type_length + 1 && bytes < bytes_max) {
					stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
				}
				context_id_length = VARINT_LEN_T((stream_state->frame_header + frame_type_length), size_t);
				while (stream_state->frame_header_read < frame_type_length + context_id_length && bytes < bytes_max) {
					stream_state->frame_header[stream_state->frame_header_read++] = *bytes++;
				}
				if (stream_state->frame_header_read >= frame_type_length  + context_id_length) {
					h3zero_stream_prefix_t* stream_prefix;

					(void)picoquic_frames_varint_decode(stream_state->frame_header + frame_type_length, 
						stream_state->frame_header + frame_type_length + context_id_length, &stream_ctx->control_stream_id);
					stream_prefix = h3zero_find_stream_prefix(prefixes, stream_ctx->control_stream_id);
					if (stream_prefix == NULL) {
						bytes = NULL;
					}
					else {
						stream_ctx->path_callback = stream_prefix->function_call;
						stream_ctx->path_callback_ctx = stream_prefix->function_ctx;
					}
					stream_state->frame_header_parsed = 1;
				}
			}
		}
	}
	return bytes;
}
