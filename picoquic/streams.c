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

#include <stdlib.h>
#include <string.h>
#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include "picosplay.h"

/* stream data splay management */
int64_t picoquic_stream_data_node_compare(void* l, void* r)
{
    /* Offset values are from 0 to 2^62-1, which means we are not worried with rollover */
    return ((picoquic_stream_data_node_t*)l)->offset - ((picoquic_stream_data_node_t*)r)->offset;
}

picosplay_node_t* picoquic_stream_data_node_create(void* value)
{
    return &((picoquic_stream_data_node_t*)value)->stream_data_node;
}


void* picoquic_stream_data_node_value(picosplay_node_t* node)
{
    return (void*)((char*)node - offsetof(struct st_picoquic_stream_data_node_t, stream_data_node));
}

void picoquic_stream_data_node_recycle(picoquic_stream_data_node_t* stream_data)
{
    if (stream_data->quic->nb_data_nodes_in_pool < PICOQUIC_MAX_PACKETS_IN_POOL) {
        stream_data->next_stream_data = stream_data->quic->p_first_data_node;
        stream_data->quic->p_first_data_node = stream_data;
        stream_data->quic->nb_data_nodes_in_pool++;
    }
    else {
        stream_data->quic->nb_data_nodes_allocated--;
        free(stream_data);
    }
}

void picoquic_stream_data_node_delete(void* UNUSED(tree), picosplay_node_t* node)
{
    picoquic_stream_data_node_t* stream_data = (picoquic_stream_data_node_t*)picoquic_stream_data_node_value(node);

    picoquic_stream_data_node_recycle(stream_data);
}

picoquic_stream_data_node_t* picoquic_stream_data_node_alloc(picoquic_quic_t* quic)
{
    picoquic_stream_data_node_t* stream_data = quic->p_first_data_node;

    if (stream_data == NULL) {
        stream_data = (picoquic_stream_data_node_t*)
            malloc(sizeof(picoquic_stream_data_node_t));

        if (stream_data != NULL) {
            /* It might be sufficient to zero the metadata, but zeroing everything
             * appears safer, and does not confuse checkers like valgrind.
             */
            memset(stream_data, 0, sizeof(picoquic_stream_data_node_t));
            stream_data->quic = quic;
            quic->nb_data_nodes_allocated++;
            if (quic->nb_data_nodes_allocated > quic->nb_data_nodes_allocated_max) {
                quic->nb_data_nodes_allocated_max = quic->nb_data_nodes_allocated;
            }
        }
    }
    else {
        quic->p_first_data_node = stream_data->next_stream_data;
        stream_data->next_stream_data = NULL;
        stream_data->bytes = NULL;
        quic->nb_data_nodes_in_pool--;
    }

    return stream_data;
}

/* Stream splay management */

static int64_t picoquic_stream_node_compare(void* l, void* r)
{
    /* STream values are from 0 to 2^62-1, which means we are not worried with rollover */
    return ((picoquic_stream_head_t*)l)->stream_id - ((picoquic_stream_head_t*)r)->stream_id;
}

static picosplay_node_t* picoquic_stream_node_create(void* value)
{
    return &((picoquic_stream_head_t*)value)->stream_node;
}


static void* picoquic_stream_node_value(picosplay_node_t* node)
{
    return (void*)((char*)node - offsetof(struct st_picoquic_stream_head_t, stream_node));
}

void picoquic_clear_stream(picoquic_stream_head_t* stream)
{
    picoquic_stream_queue_node_t* ready = stream->send_queue;
    picoquic_stream_queue_node_t* next;

    while ((next = ready) != NULL) {
        ready = next->next_stream_data;
        if (next->bytes != NULL) {
            free(next->bytes);
        }
        free(next);
    }
    stream->send_queue = NULL;
    if (stream->is_output_stream) {
        picoquic_remove_output_stream(stream->cnx, stream);
    }
    picosplay_empty_tree(&stream->stream_data_tree);
    picoquic_sack_list_free(&stream->sack_list);
}


static void picoquic_stream_node_delete(void* UNUSED(tree), picosplay_node_t* node)
{
    picoquic_stream_head_t* stream = picoquic_stream_node_value(node);

    picoquic_clear_stream(stream);

    free(stream);
}

void picoquic_init_tls_tree(picoquic_cnx_t* cnx, int epoch) {
    picosplay_init_tree(&cnx->tls_stream[epoch].stream_data_tree, picoquic_stream_data_node_compare, picoquic_stream_data_node_create, picoquic_stream_data_node_delete, picoquic_stream_data_node_value);
}

void picoquic_init_stream_tree(picoquic_cnx_t* cnx)
{
    picosplay_init_tree(&cnx->stream_tree, picoquic_stream_node_compare, picoquic_stream_node_create, picoquic_stream_node_delete, picoquic_stream_node_value);
}

/* Adding data to stream, managing priorities, etc. */

static picoquic_stream_head_t* picoquic_find_stream_for_writing(picoquic_cnx_t* cnx,
    uint64_t stream_id, int* ret)
{
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);

    *ret = 0;

    if (stream == NULL) {
        /* Need to check that the ID is authorized */

        /* Check parity */
        if (IS_CLIENT_STREAM_ID(stream_id) != cnx->client_mode) {
            *ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
        }

        if (*ret == 0) {
            if (stream_id < cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]) {
                *ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
            }
            else {
                stream = picoquic_create_missing_streams(cnx, stream_id, 0);
                if (stream == NULL) {
                    *ret = PICOQUIC_ERROR_MEMORY;
                }
            }
        }
    }

    return stream;
}

int picoquic_set_app_stream_ctx(picoquic_cnx_t* cnx,
    uint64_t stream_id, void* app_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);
    if (ret == 0) {
        stream->app_stream_ctx = app_stream_ctx;
    }

    return ret;
}

void picoquic_unlink_app_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t* stream;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    stream = picoquic_find_stream(cnx, stream_id);
    if (stream != NULL) {
        stream->app_stream_ctx = NULL;
    }
}


int picoquic_mark_active_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_active, void* app_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);
    if (ret == 0) {
        if (is_active) {
            /* The call only fails if the stream was closed or reset */
            if (!stream->fin_requested &&
                (!stream->reset_requested || picoquic_check_sack_list(&stream->sack_list, 0, stream->reliable_size) == 0) &&
                cnx->callback_fn != NULL) {
                stream->app_stream_ctx = app_stream_ctx;
                if (!stream->is_active) {
                    stream->is_active = 1;
                    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));
                }
            }
            else {
                ret = PICOQUIC_ERROR_CANNOT_SET_ACTIVE_STREAM;
            }
        }
        else {
            stream->is_active = 0;
            stream->app_stream_ctx = app_stream_ctx;
        }
    }

    return ret;
}

int picoquic_mark_active_stream_v2(picoquic_cnx_t* cnx,
    uint64_t stream_id, int is_active)
{
    int ret = 0;
    picoquic_stream_head_t* stream;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);
    if (ret == 0) {
        if (is_active) {
            if (!stream->fin_requested &&
                (!stream->reset_requested || picoquic_check_sack_list(&stream->sack_list, 0, stream->reliable_size) == 0) &&
                cnx->callback_fn != NULL) {
                if (!stream->is_active) {
                    stream->is_active = 1;
                    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));
                }
            }
            else {
                ret = PICOQUIC_ERROR_CANNOT_SET_ACTIVE_STREAM;
            }
        }
        else {
            stream->is_active = 0;
        }
    }

    return ret;
}

int picoquic_set_stream_not_coalesced(picoquic_cnx_t* cnx, uint64_t stream_id, int is_not_coalesced)
{
    int ret = 0;
    picoquic_stream_head_t* stream;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);
    if (ret == 0) {
        stream->is_not_coalesced = is_not_coalesced;
    }

    return ret;
}


void picoquic_set_default_priority(picoquic_quic_t* quic, uint8_t default_stream_priority)
{
    PICOQUIC_THREAD_CHECK(quic);
    quic->default_stream_priority = default_stream_priority;
}

int picoquic_set_stream_priority(picoquic_cnx_t* cnx, uint64_t stream_id, uint8_t stream_priority)
{
    int ret = 0;
    picoquic_stream_head_t* stream;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);
    if (ret == 0) {
        stream->stream_priority = stream_priority;
        picoquic_reorder_output_stream(cnx, stream);
    }

    return ret;
}

int picoquic_mark_high_priority_stream(picoquic_cnx_t* cnx, uint64_t stream_id, int is_high_priority)
{
    int ret;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    if (is_high_priority) {
        cnx->high_priority_stream_id = stream_id;
    }
    else if (cnx->high_priority_stream_id == stream_id) {
        cnx->high_priority_stream_id = UINT64_MAX;
    }

    ret = picoquic_set_stream_priority(cnx, stream_id, (is_high_priority) ? 0 : cnx->quic->default_stream_priority);

    return ret;
}

int picoquic_add_to_stream_with_ctx(picoquic_cnx_t* cnx, uint64_t stream_id,
    const uint8_t* data, size_t length, int set_fin, void* app_stream_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    stream = picoquic_find_stream_for_writing(cnx, stream_id, &ret);
    if (ret == 0 && set_fin) {
        if (stream->fin_requested) {
            /* app error, notified the fin twice*/
            if (length > 0) {
                ret = -1;
            }
        }
        else {
            stream->fin_requested = 1;
        }
    }

    /* If our side has sent RST_STREAM or received STOP_SENDING, we should not send anymore data. */
    if (ret == 0 && (stream->reset_sent || stream->stop_sending_received)) {
        ret = -1;
    }

    if (ret == 0 && length > 0) {
        picoquic_stream_queue_node_t* stream_data = (picoquic_stream_queue_node_t*)
            malloc(sizeof(picoquic_stream_queue_node_t));
        if (stream_data == 0) {
            ret = -1;
        }
        else {
            stream_data->bytes = (uint8_t*)malloc(length);

            if (stream_data->bytes == NULL) {
                free(stream_data);
                stream_data = NULL;
                ret = -1;
            }
            else {
                picoquic_stream_queue_node_t** pprevious = &stream->send_queue;
                picoquic_stream_queue_node_t* next = stream->send_queue;

                memcpy(stream_data->bytes, data, length);
                stream_data->length = length;
                stream_data->offset = 0;
                stream_data->next_stream_data = NULL;

                while (next != NULL) {
                    pprevious = &next->next_stream_data;
                    next = next->next_stream_data;
                }

                *pprevious = stream_data;
            }
        }

    }

    if (ret == 0) {
        if (length > 0 || set_fin) {
            picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));
        }
        cnx->nb_bytes_queued += length;
        stream->is_active = 0;
        stream->app_stream_ctx = app_stream_ctx;
    }

    return ret;
}

int picoquic_add_to_stream(picoquic_cnx_t* cnx, uint64_t stream_id,
    const uint8_t* data, size_t length, int set_fin)
{
    return picoquic_add_to_stream_with_ctx(cnx, stream_id, data, length, set_fin, NULL);
}


void picoquic_reset_stream_ctx(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t* stream;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    if ((stream = picoquic_find_stream(cnx, stream_id)) != NULL) {
        stream->app_stream_ctx = NULL;
    }
}

int picoquic_reset_stream_at(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint64_t local_stream_error, uint64_t reliable_size)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    if (reliable_size > 0 && !cnx->is_reset_stream_at_enabled) {
        ret = PICOQUIC_ERROR_ILLEGAL_TRANSPORT_EXTENSION;
    }
    else if ((stream = picoquic_find_stream(cnx, stream_id)) == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else {
        stream->app_stream_ctx = NULL;
        if (stream->fin_sent && picoquic_check_sack_list(&stream->sack_list, 0, stream->fin_offset) == 0) {
            ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
        }
        else if (!stream->reset_requested) {
            stream->local_error = local_stream_error;
            stream->reset_requested = 1;
            stream->reliable_size = reliable_size;
        }
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

int picoquic_reset_stream(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint64_t local_stream_error)
{
    return picoquic_reset_stream_at(cnx, stream_id, local_stream_error, 0);
}

uint64_t picoquic_get_next_local_stream_id(picoquic_cnx_t* cnx, int is_unidir)
{
    /* This code could be written as:
     * int stream_type_id = ((cnx->client_mode ^ 1) | ((is_unidir) ? 2 : 0));
     * but Visual Studio produces an obnoxious error message about
     * mixing bitwise or and logical or. */
    int stream_type_id = cnx->client_mode ^ 1;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    if (is_unidir) {
        stream_type_id |= 2;
    }

    return cnx->next_stream_id[stream_type_id];
}

int picoquic_stop_sending(picoquic_cnx_t* cnx,
    uint64_t stream_id, uint64_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else {
        stream->app_stream_ctx = NULL;

        if (stream->reset_received) {
            ret = PICOQUIC_ERROR_STREAM_ALREADY_CLOSED;
        }
        else if (!stream->stop_sending_requested) {
            stream->local_stop_error = local_stream_error;
            stream->stop_sending_requested = 1;
            picoquic_insert_output_stream(cnx, stream);
        }
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

int picoquic_discard_stream(picoquic_cnx_t* cnx, uint64_t stream_id, uint16_t local_stream_error)
{
    int ret = 0;
    picoquic_stream_head_t* stream = NULL;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    stream = picoquic_find_stream(cnx, stream_id);

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else {
        if (IS_BIDIR_STREAM_ID(stream_id) || !IS_CLIENT_STREAM_ID(stream_id)) {
            ret = picoquic_stop_sending(cnx, stream_id, local_stream_error);
            if (ret == PICOQUIC_ERROR_STREAM_ALREADY_CLOSED) {
                ret = 0;
            }
        }
        if (ret == 0 &&
            (IS_BIDIR_STREAM_ID(stream_id) || IS_CLIENT_STREAM_ID(stream_id))) {
            ret = picoquic_reset_stream(cnx, stream_id, local_stream_error);
            if (ret == PICOQUIC_ERROR_STREAM_ALREADY_CLOSED) {
                ret = 0;
            }
        }
        stream->app_stream_ctx = NULL;
        stream->is_discarded = 1;
    }

    return ret;
}


/* Management of streams */

picoquic_stream_head_t* picoquic_stream_from_node(picosplay_node_t* node)
{
#ifdef TOO_CAUTIOUS
    return(picoquic_stream_head_t*)((node == NULL) ? NULL : picoquic_stream_node_value(node));
#else
    return (picoquic_stream_head_t*)node;
#endif
}

picoquic_stream_head_t* picoquic_first_stream(picoquic_cnx_t* cnx)
{
#ifdef TOO_CAUTIOUS
    return picoquic_stream_from_node(picosplay_first(&cnx->stream_tree));
#else
    return (picoquic_stream_head_t*)picosplay_first(&cnx->stream_tree);
#endif
}

picoquic_stream_head_t* picoquic_last_stream(picoquic_cnx_t* cnx)
{
#ifdef TOO_CAUTIOUS
    return picoquic_stream_from_node(picosplay_last(&cnx->stream_tree));
#else
    return (picoquic_stream_head_t*)picosplay_last(&cnx->stream_tree);
#endif
}

int picoquic_compare_stream_priority(picoquic_stream_head_t* stream, picoquic_stream_head_t* other) {
    int ret = 1;
    if (stream->stream_priority < other->stream_priority) {
        ret = -1;
    }
    else if (stream->stream_priority == other->stream_priority) {
        if (stream->stream_id < other->stream_id) {
            ret = -1;
        }
        else if (stream->stream_id == other->stream_id) {
            ret = 0;
        }
    }
    return ret;
}

/* This code assumes that the stream is not currently present in the output stream.
 */
void picoquic_insert_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    if (stream->is_output_stream == 0)
    {
        if (IS_CLIENT_STREAM_ID(stream->stream_id) == cnx->client_mode) {
            if (stream->stream_id > ((IS_BIDIR_STREAM_ID(stream->stream_id)) ? cnx->max_stream_id_bidir_remote : cnx->max_stream_id_unidir_remote)) {
                return;
            }
        }

        if (cnx->last_output_stream == NULL) {
            /* insert first stream */
            cnx->last_output_stream = stream;
            cnx->first_output_stream = stream;
        }
        else if (picoquic_compare_stream_priority(stream, cnx->last_output_stream) >= 0) {
            /* insert after last stream. Common case for most applications. */
            stream->previous_output_stream = cnx->last_output_stream;
            cnx->last_output_stream->next_output_stream = stream;
            cnx->last_output_stream = stream;
        }
        else {
            picoquic_stream_head_t* current = cnx->first_output_stream;

            while (current != NULL) {
                int cmp = picoquic_compare_stream_priority(stream, current);

                if (cmp < 0) {
                    /* insert before the current stream, then break */
                    stream->previous_output_stream = current->previous_output_stream;
                    if (stream->previous_output_stream == NULL) {
                        cnx->first_output_stream = stream;
                    }
                    else {
                        stream->previous_output_stream->next_output_stream = stream;
                    }
                    current->previous_output_stream = stream;
                    stream->next_output_stream = current;
                    break;
                }
                else if (cmp == 0) {
                    /* Stream is already there. This is unexpected */
                    break;
                }
                else {
                    current = current->next_output_stream;
                }
            }
            if (current == NULL) {
                /* insert after last stream */
                stream->previous_output_stream = cnx->last_output_stream;
                cnx->last_output_stream->next_output_stream = stream;
                cnx->last_output_stream = stream;
            }
        }

        stream->is_output_stream = 1;
    }
}

void picoquic_remove_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    if (stream->is_output_stream) {
        stream->is_output_stream = 0;

        if (stream->previous_output_stream == NULL) {
            cnx->first_output_stream = stream->next_output_stream;
        }
        else {
            stream->previous_output_stream->next_output_stream = stream->next_output_stream;
        }

        if (stream->next_output_stream == NULL) {
            cnx->last_output_stream = stream->previous_output_stream;
        }
        else {
            stream->next_output_stream->previous_output_stream = stream->previous_output_stream;
        }
        stream->previous_output_stream = NULL;
        stream->next_output_stream = NULL;
    }
}

/* Reorder streams by priorities and rank.
 * A stream is deemed out of order if:
 * - the previous stream in the list has a higher priority, or
 * - the new stream has a lower priority.
 */
void picoquic_reorder_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    if (stream->is_output_stream) {
        if ((stream->previous_output_stream != NULL &&
            picoquic_compare_stream_priority(stream, stream->previous_output_stream) < 0) ||
            (stream->next_output_stream != NULL &&
                picoquic_compare_stream_priority(stream, stream->next_output_stream) > 0)) {
            picoquic_remove_output_stream(cnx, stream);
            stream->is_output_stream = 0;
            picoquic_insert_output_stream(cnx, stream);
        }
    }
}

picoquic_stream_head_t* picoquic_next_stream(picoquic_stream_head_t* stream)
{
    return (picoquic_stream_head_t*)picosplay_next((picosplay_node_t*)stream);
}

picoquic_stream_head_t* picoquic_find_stream(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t target;
    target.stream_id = stream_id;

    return (picoquic_stream_head_t*)picosplay_find(&cnx->stream_tree, (void*)&target);
}

void picoquic_add_output_streams(picoquic_cnx_t* cnx, uint64_t old_limit, uint64_t new_limit, unsigned int is_bidir)
{
    uint64_t old_rank = STREAM_RANK_FROM_ID(old_limit);
    uint64_t first_new_id = STREAM_ID_FROM_RANK(old_rank + 1ull, cnx->client_mode, !is_bidir);
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, first_new_id);

    while (stream) {
        if (stream->stream_id > old_limit) {
            if (stream->stream_id > new_limit) {
                break;
            }
            if (IS_LOCAL_STREAM_ID(stream->stream_id, cnx->client_mode) && IS_BIDIR_STREAM_ID(stream->stream_id) == is_bidir) {
                picoquic_insert_output_stream(cnx, stream);
            }
        }
        stream = picoquic_next_stream(stream);
    }
}

picoquic_stream_head_t* picoquic_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t* stream = (picoquic_stream_head_t*)malloc(sizeof(picoquic_stream_head_t));
    if (stream != NULL) {
        memset(stream, 0, sizeof(picoquic_stream_head_t));
        picoquic_sack_list_init(&stream->sack_list);
    }

    if (stream != NULL) {
        int is_output_stream = 0;
        stream->stream_id = stream_id;
        stream->cnx = cnx;

        if (IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
            if (IS_BIDIR_STREAM_ID(stream_id)) {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_local;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_remote;
                is_output_stream = stream->stream_id <= cnx->max_stream_id_bidir_remote;

            }
            else {
                stream->maxdata_local = 0;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_uni;
                is_output_stream = stream->stream_id <= cnx->max_stream_id_unidir_remote;
            }
        }
        else {
            if (IS_BIDIR_STREAM_ID(stream_id)) {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_remote;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_local;
                is_output_stream = 1;
            }
            else {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_uni;
                stream->maxdata_remote = 0;
                is_output_stream = 0;
            }
        }

        stream->stream_priority = cnx->quic->default_stream_priority;

        picosplay_init_tree(&stream->stream_data_tree, picoquic_stream_data_node_compare, picoquic_stream_data_node_create, picoquic_stream_data_node_delete, picoquic_stream_data_node_value);

        picosplay_insert(&cnx->stream_tree, stream);
        if (is_output_stream) {
            picoquic_insert_output_stream(cnx, stream);
        }
        else {
            picoquic_remove_output_stream(cnx, stream);
            picoquic_delete_stream_if_closed(cnx, stream);
        }

        if (stream_id >= cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]) {
            cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)] = NEXT_STREAM_ID_FOR_TYPE(stream_id);
        }
    }

    return stream;
}

void picoquic_delete_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t* stream)
{
    picosplay_delete(&cnx->stream_tree, stream);
}

int picoquic_mark_direct_receive_stream(picoquic_cnx_t* cnx, uint64_t stream_id, picoquic_stream_direct_receive_fn direct_receive_fn, void* direct_receive_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream;
    picoquic_stream_data_node_t* data;
    PICOQUIC_THREAD_CHECK(cnx->quic);

    if ((stream = picoquic_find_stream(cnx, stream_id)) == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if (!IS_BIDIR_STREAM_ID(stream_id) && IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if (direct_receive_fn == NULL) {
        /* This is illegal! */
        ret = PICOQUIC_ERROR_NO_CALLBACK_PROVIDED;
    }
    else {
        stream->direct_receive_fn = direct_receive_fn;
        stream->direct_receive_ctx = direct_receive_ctx;
        /* If there is pending data, pass it. */
        while ((data = (picoquic_stream_data_node_t*)picosplay_first(&stream->stream_data_tree)) != NULL) {
            size_t length = data->length;
            uint64_t offset = data->offset;

            if (offset < stream->consumed_offset) {
                if (offset + length < stream->consumed_offset) {
                    length = 0;
                }
                else {
                    size_t delta_offset = (size_t)(stream->consumed_offset - offset);
                    length -= delta_offset;
                    offset += delta_offset;
                }
            }

            if (length > 0) {
                ret = direct_receive_fn(cnx, stream_id, 0, data->bytes, offset, length, direct_receive_ctx);
            }

            if (ret == 0) {
                picosplay_delete_hint(&stream->stream_data_tree, &data->stream_data_node);
            }
            else {
                break;
            }
        }

        /* If there is a fin offset, pass it. */
        if (ret == 0 && stream->fin_received && !stream->fin_signalled) {
            uint8_t fin_bytes[8];
            ret = direct_receive_fn(cnx, stream_id, 1, fin_bytes, stream->fin_offset, 0, direct_receive_ctx);
        }
    }

    return ret;
}

picoquic_stream_head_t* picoquic_find_ready_stream_path(picoquic_cnx_t* cnx, picoquic_path_t* path_x, int is_coalesced)
{
    picoquic_stream_head_t* first_stream = cnx->first_output_stream;
    picoquic_stream_head_t* stream = first_stream;
    picoquic_stream_head_t* found_stream = NULL;


    /* Look for a ready stream */
    while (stream != NULL) {
        int has_data = 0;
        picoquic_stream_head_t* next_stream = stream->next_output_stream;

        if (next_stream != NULL && is_coalesced && next_stream->is_not_coalesced) {
            stream = next_stream->next_output_stream;
            continue;
        }

        if (found_stream != NULL && stream->stream_priority > found_stream->stream_priority) {
            /* All the streams at that priority level have been examined,
             * the current selection is validated */
            break;
        }

        /* The tests for "have data" should excatly replicate the tests in
         * the formating of a stream frame */
        if (stream->stop_sending_requested && !stream->stop_sending_sent) {
            /* will send a stop sending frame.
            * this takes precedence over FIFO vs round-robin processing */
            found_stream = stream;
            has_data = 1;
            break;
        }
        else if (stream->reset_sent) {
            /* No data will be sent after a reset */
            has_data = 0;
        }
        else if (stream->reset_requested &&
            (stream->reliable_size == 0 || picoquic_check_sack_list(&stream->sack_list, 0, stream->reliable_size))) {
            /* will queue a reset frame --
            * this takes precedence over FIFO vs round-robin processing */
            found_stream = stream;
            has_data = 1;
            break;
        }
        else if (cnx->maxdata_remote > cnx->data_sent && stream->sent_offset < stream->maxdata_remote && (stream->is_active ||
            (stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset) ||
            (stream->fin_requested && !stream->fin_sent))) {
            has_data = 1;
        }
        else {
            has_data = 0;
        }

        /* implement affinity scheduling */
        if (has_data && path_x != NULL && stream->affinity_path != path_x && stream->affinity_path != NULL) {
            /* Only consider the streams that meet path affinity requirements */
            has_data = 0;
        }

        if (has_data) {
            /* Check that this stream is actually available for sending data */
            if (stream->sent_offset == 0) {
                if (IS_CLIENT_STREAM_ID(stream->stream_id) == cnx->client_mode) {
                    if (stream->stream_id > ((IS_BIDIR_STREAM_ID(stream->stream_id)) ? cnx->max_stream_id_bidir_remote : cnx->max_stream_id_unidir_remote)) {
                        has_data = 0;
                    }
                }
            }
            if (has_data) {
                /* Something can be sent */
                if ((stream->stream_priority & 1) != 0) {
                    /* This priority level requests FIFO processing, so we return the first available stream */
                    found_stream = stream;
                    break;
                }
                else if (found_stream == NULL || stream->last_time_data_sent < found_stream->last_time_data_sent) {
                    /* Select this stream, but need to check if another stream should go before in round robin order */
                    found_stream = stream;
                }
            }
        }
        else if (((stream->fin_requested && stream->fin_sent) || (stream->reset_requested && stream->reset_sent)) && (!stream->stop_sending_requested || stream->stop_sending_sent)) {
            /* If stream is exhausted, remove from output list */
            picoquic_remove_output_stream(cnx, stream);

            picoquic_delete_stream_if_closed(cnx, stream);
        }
        else {
            if (stream->is_active ||
                (stream->send_queue != NULL && stream->send_queue->length > stream->send_queue->offset)) {
                if (stream->sent_offset >= stream->maxdata_remote) {
                    cnx->stream_blocked = 1;
                }
                else if (cnx->maxdata_remote <= cnx->data_sent) {
                    cnx->flow_blocked = 1;
                }
            }
        }
        stream = next_stream;
    }

    return found_stream;
}

picoquic_stream_head_t* picoquic_find_ready_stream(picoquic_cnx_t* cnx)
{
    return picoquic_find_ready_stream_path(cnx, NULL, 0);
}
