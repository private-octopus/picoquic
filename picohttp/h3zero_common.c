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

int h3zero_declare_stream_prefix(h3zero_stream_prefixes_t* prefixes, uint64_t prefix, void* function_call, void* function_ctx)
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
