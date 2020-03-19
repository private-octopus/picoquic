#include "picoquic_internal.h"
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

#include "picoquic_internal.h"
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

picoquic_stored_ticket_t* picoquic_format_ticket(uint64_t time_valid_until,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint8_t* ticket, uint16_t ticket_length, picoquic_tp_t const * tp)
{
    size_t ticket_size = sizeof(picoquic_stored_ticket_t) + sni_length + 1 + alpn_length + 1 + ticket_length;
    picoquic_stored_ticket_t* stored = (picoquic_stored_ticket_t*)malloc(ticket_size);
    
    if (stored != NULL) {
        char* next_p = ((char*)stored) + sizeof(picoquic_stored_ticket_t);

        memset(stored, 0, ticket_size);
        stored->time_valid_until = time_valid_until;
        stored->sni = next_p;
        stored->sni_length = sni_length;
        memcpy(next_p, sni, sni_length);
        next_p += sni_length;
        *next_p++ = 0;

        stored->alpn = next_p;
        stored->alpn_length = alpn_length;
        memcpy(next_p, alpn, alpn_length);
        next_p += alpn_length;
        *next_p++ = 0;

        if (tp != NULL) {
            stored->tp_0rtt[picoquic_tp_0rtt_max_data] = tp->initial_max_data;
            stored->tp_0rtt[picoquic_tp_0rtt_max_stream_data_bidi_local] = tp->initial_max_stream_data_bidi_local;
            stored->tp_0rtt[picoquic_tp_0rtt_max_stream_data_bidi_remote] = tp->initial_max_stream_data_bidi_remote;
            stored->tp_0rtt[picoquic_tp_0rtt_max_stream_data_uni] = tp->initial_max_stream_data_uni;
            stored->tp_0rtt[picoquic_tp_0rtt_max_streams_id_bidir] = tp->initial_max_stream_id_bidir;
            stored->tp_0rtt[picoquic_tp_0rtt_max_streams_id_unidir] = tp->initial_max_stream_id_unidir;
        }

        stored->ticket = (uint8_t*)next_p;
        stored->ticket_length = ticket_length;
        memcpy(next_p, ticket, ticket_length);
    }

    return stored;
}

int picoquic_serialize_ticket(const picoquic_stored_ticket_t * ticket, uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
    int ret = 0;
    size_t byte_index = 0;
    size_t required_length;

    /* Compute serialized length */
    required_length = (size_t)(8 + 2 + 2 + 2) + ticket->sni_length + ticket->alpn_length + ticket->ticket_length;
    /* Serialize */
    if (required_length > bytes_max) {
        ret = PICOQUIC_ERROR_FRAME_BUFFER_TOO_SMALL;
        *consumed = 0;
    } else {
        picoformat_64(bytes + byte_index, ticket->time_valid_until);
        byte_index += 8;

        picoformat_16(bytes + byte_index, ticket->sni_length);
        byte_index += 2;
        memcpy(bytes + byte_index, ticket->sni, ticket->sni_length);
        byte_index += ticket->sni_length;

        picoformat_16(bytes + byte_index, ticket->alpn_length);
        byte_index += 2;
        memcpy(bytes + byte_index, ticket->alpn, ticket->alpn_length);
        byte_index += ticket->alpn_length;

        for (int i = 0; i < PICOQUIC_NB_TP_0RTT; i++) {
            picoformat_64(bytes + byte_index, ticket->tp_0rtt[i]);
            byte_index += 8;
        }

        picoformat_16(bytes + byte_index, ticket->ticket_length);
        byte_index += 2;
        memcpy(bytes + byte_index, ticket->ticket, ticket->ticket_length);
        byte_index += ticket->ticket_length;

        *consumed = byte_index;
    }

    return ret;
}

int picoquic_deserialize_ticket(picoquic_stored_ticket_t ** ticket, uint8_t * bytes, size_t bytes_max, size_t * consumed)
{
    int ret = 0;
    uint64_t time_valid_until = 0;
    size_t required_length = 8 + 2 + 2 + PICOQUIC_NB_TP_0RTT * 8 + 2;
    size_t byte_index = 0;
    size_t sni_index = 0;
    size_t alpn_index = 0;
    size_t ticket_index = 0;
    uint16_t sni_length = 0;
    uint16_t alpn_length = 0;
    uint16_t ticket_length = 0;
    uint64_t tp_0rtt[PICOQUIC_NB_TP_0RTT] = { 0, 0, 0, 0, 0, 0 };

    *consumed = 0;
    *ticket = NULL;

    if (required_length < bytes_max) {
        time_valid_until = PICOPARSE_64(bytes);
        byte_index = 8;
        sni_length = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        sni_index = byte_index;
        required_length += sni_length;
        byte_index += sni_length;
    }

    if (required_length < bytes_max) {
        alpn_length = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        alpn_index = byte_index;
        required_length += alpn_length;
        byte_index += alpn_length;
    }

    if (required_length < bytes_max) {
        for (int i = 0; i < PICOQUIC_NB_TP_0RTT; i++) {
            tp_0rtt[i] = PICOPARSE_64(bytes + byte_index);
            byte_index += 8;
        }
    }

    if (required_length < bytes_max) {
        ticket_length = PICOPARSE_16(bytes + byte_index);
        byte_index += 2;
        ticket_index = byte_index;
        required_length += ticket_length;
    }

    if (required_length > bytes_max) {
        *ticket = NULL;
        ret = PICOQUIC_ERROR_INVALID_TICKET;
    } else {
        *ticket = picoquic_format_ticket(time_valid_until, (const char *)(bytes + sni_index), sni_length,
            (const char *)(bytes + alpn_index), alpn_length, bytes + ticket_index, ticket_length, NULL);
        if (*ticket == NULL) {
            ret = PICOQUIC_ERROR_MEMORY;
        }
        else {
            for (int i=0; i< PICOQUIC_NB_TP_0RTT; i++) {
                (*ticket)->tp_0rtt[i] = tp_0rtt[i];
            }
            *consumed = required_length;
        }
    }

    return ret;
}

int picoquic_store_ticket(picoquic_stored_ticket_t** pp_first_ticket,
    uint64_t current_time,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint8_t* ticket, uint16_t ticket_length, picoquic_tp_t const * tp)
{
    int ret = 0;

    if (ticket_length < 17) {
        ret = PICOQUIC_ERROR_INVALID_TICKET;
    } else {
        uint64_t ticket_issued_time;
        uint64_t ttl_seconds;
        uint64_t time_valid_until;

        ticket_issued_time = PICOPARSE_64(ticket);
        ttl_seconds = PICOPARSE_32(ticket + 13);

        if (ttl_seconds > (7 * 24 * 3600)) {
            ttl_seconds = (7 * 24 * 3600);
        }

        time_valid_until = (ticket_issued_time * 1000) + (ttl_seconds * 1000000);

        if (current_time != 0 && time_valid_until < current_time) {
            ret = PICOQUIC_ERROR_INVALID_TICKET;
        } else {
            picoquic_stored_ticket_t* stored = picoquic_format_ticket(time_valid_until, sni, sni_length,
                    alpn, alpn_length, ticket, ticket_length, tp);
            if (stored == NULL) {
                ret = PICOQUIC_ERROR_MEMORY;
            }
            else {
                picoquic_stored_ticket_t* next;
                picoquic_stored_ticket_t** pprevious;

                stored->next_ticket = next = *pp_first_ticket;
                *pp_first_ticket = stored;
                pprevious = &stored->next_ticket;

                /* Now remove the old tickets for that SNI & ALPN */
                while (next != NULL) {
                    if (next->time_valid_until <= stored->time_valid_until && next->sni_length == sni_length && next->alpn_length == alpn_length && memcmp(next->sni, sni, sni_length) == 0 && memcmp(next->alpn, alpn, alpn_length) == 0) {
                        picoquic_stored_ticket_t* deleted = next;
                        next = next->next_ticket;
                        *pprevious = next;
                        memset(&deleted->ticket, 0, deleted->ticket_length);
                        free(deleted);
                    } else {
                        pprevious = &next->next_ticket;
                        next = next->next_ticket;
                    }
                }
            }
        }
    }

    return ret;
}

int picoquic_get_ticket(picoquic_stored_ticket_t* p_first_ticket,
    uint64_t current_time,
    char const* sni, uint16_t sni_length, char const* alpn, uint16_t alpn_length,
    uint8_t** ticket, uint16_t* ticket_length, picoquic_tp_t * tp, int mark_used)
{
    int ret = 0;
    picoquic_stored_ticket_t* next = p_first_ticket;

    while (next != NULL) {
        if (next->time_valid_until > current_time && next->sni_length == sni_length && next->alpn_length == alpn_length && memcmp(next->sni, sni, sni_length) == 0 && memcmp(next->alpn, alpn, alpn_length) == 0 && next->was_used == 0) {
            break;
        } else {
            next = next->next_ticket;
        }
    }

    if (next == NULL) {
        *ticket = NULL;
        *ticket_length = 0;
        ret = -1;
    } else {
        if (tp != NULL) {
            tp->initial_max_data = next->tp_0rtt[picoquic_tp_0rtt_max_data];
            tp->initial_max_stream_data_bidi_local = next->tp_0rtt[picoquic_tp_0rtt_max_stream_data_bidi_local];
            tp->initial_max_stream_data_bidi_remote = next->tp_0rtt[picoquic_tp_0rtt_max_stream_data_bidi_remote];
            tp->initial_max_stream_data_uni = next->tp_0rtt[picoquic_tp_0rtt_max_stream_data_uni];
            tp->initial_max_stream_id_bidir = next->tp_0rtt[picoquic_tp_0rtt_max_streams_id_bidir];
            tp->initial_max_stream_id_unidir = next->tp_0rtt[picoquic_tp_0rtt_max_streams_id_unidir];
        }
        *ticket = next->ticket;
        *ticket_length = next->ticket_length;
        next->was_used = mark_used;
    }

    return ret;
}

int picoquic_save_tickets(const picoquic_stored_ticket_t* first_ticket,
    uint64_t current_time,
    char const* ticket_file_name)
{
    int ret = 0;
    FILE* F = NULL;
    const picoquic_stored_ticket_t* next = first_ticket;

    if ((F = picoquic_file_open(ticket_file_name, "wb")) == NULL) {
        ret = -1;
    } else {
        while (ret == 0 && next != NULL) {
            /* Only store the tickets that are valid going forward */
            if (next->time_valid_until > current_time && next->was_used == 0) {
                /* Compute the serialized size */
                uint8_t buffer[2048];
                size_t record_size;

                ret = picoquic_serialize_ticket(next, buffer, sizeof(buffer), &record_size);

                if (ret == 0) {
                    if (fwrite(&record_size, 4, 1, F) != 1 || fwrite(buffer, 1, record_size, F) != record_size) {
                        ret = PICOQUIC_ERROR_INVALID_FILE;
                        break;
                    }
                }
            }
            next = next->next_ticket;
        }
        (void)picoquic_file_close(F);
    }

    return ret;
}

int picoquic_load_tickets(picoquic_stored_ticket_t** pp_first_ticket,
    uint64_t current_time, char const* ticket_file_name)
{
    int ret = 0;
    int file_err = 0;
    FILE* F = NULL;
    picoquic_stored_ticket_t* previous = NULL;
    picoquic_stored_ticket_t* next = NULL;
    uint32_t record_size;
    uint32_t storage_size;


    if ((F = picoquic_file_open_ex(ticket_file_name, "rb", &file_err)) == NULL) {
        ret = (file_err == ENOENT) ? PICOQUIC_ERROR_NO_SUCH_FILE : -1;
    }

    while (ret == 0) {
        if (fread(&storage_size, 4, 1, F) != 1) {
            /* end of file */
            break;
        }
        else if (storage_size > 2048 ||
            (record_size = storage_size + offsetof(struct st_picoquic_stored_ticket_t, time_valid_until)) > 2048) {
            ret = PICOQUIC_ERROR_INVALID_FILE;
            break;
        }
        else {
            uint8_t buffer[2048];
            if (fread(buffer, 1, storage_size, F)
                != storage_size) {
                ret = PICOQUIC_ERROR_INVALID_FILE;
            }
            else {
                size_t consumed = 0;
                ret = picoquic_deserialize_ticket(&next, buffer, storage_size, &consumed);

                if (ret == 0 && (consumed != storage_size || next == NULL)) {
                    ret = PICOQUIC_ERROR_INVALID_FILE;
                }

                if (ret == 0 && next != NULL) {
                    if (next->time_valid_until < current_time) {
                        free(next);
                        next = NULL;
                    }
                    else {
                        next->sni = ((char*)next) + sizeof(picoquic_stored_ticket_t);
                        next->alpn = next->sni + next->sni_length + 1;
                        next->ticket = (uint8_t*)(next->alpn + next->alpn_length + 1);
                        next->next_ticket = NULL;
                        if (previous == NULL) {
                            *pp_first_ticket = next;
                        }
                        else {
                            previous->next_ticket = next;
                        }

                        previous = next;
                    }
                }
            }
        }
    }

    picoquic_file_close(F);

    return ret;
}

void picoquic_free_tickets(picoquic_stored_ticket_t** pp_first_ticket)
{
    picoquic_stored_ticket_t* next;

    while ((next = *pp_first_ticket) != NULL) {
        *pp_first_ticket = next->next_ticket;

        free(next);
    }
}

int picoquic_save_session_tickets(picoquic_quic_t* quic, char const* ticket_store_filename)
{
    return picoquic_save_tickets(quic->p_first_ticket, picoquic_get_quic_time(quic), ticket_store_filename);
}

int picoquic_load_retry_tokens(picoquic_quic_t* quic, char const* token_store_filename)
{
    return picoquic_load_tokens(&quic->p_first_token, picoquic_get_quic_time(quic), token_store_filename);
}

int picoquic_save_retry_tokens(picoquic_quic_t* quic, char const* ticket_store_filename)
{
    return picoquic_save_tokens(quic->p_first_token, picoquic_get_quic_time(quic), ticket_store_filename);
}