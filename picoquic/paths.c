/*
* Author: Christian Huitema
* Copyright (c) 2025, Private Octopus, Inc.
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
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>

/* Path management logic.
 */

uint64_t  picoquic_tuple_challenge_time(picoquic_path_t* path_x, picoquic_tuple_t* tuple, uint64_t current_time);

uint8_t* picoquic_prepare_tuple_challenge_frames(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_tuple_t* tuple, picoquic_packet_context_enum pc,
    uint8_t* bytes_next, uint8_t* bytes_max,
    int* more_data, int* is_pure_ack, int* is_challenge_padding_needed,
    uint64_t current_time, uint64_t* next_wake_time)
{
    if (tuple->challenge_verified == 0 && tuple->challenge_failed == 0) {
        uint64_t next_challenge_time = picoquic_tuple_challenge_time(path_x, tuple, current_time);

        if (next_challenge_time > current_time) {
            if (next_challenge_time < *next_wake_time) {
                *next_wake_time = next_challenge_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        }
        else {
            uint8_t* bytes_challenge = bytes_next;

            if (tuple->challenge_repeat_count < PICOQUIC_CHALLENGE_REPEAT_MAX) {
                /* When blocked, repeat the path challenge or wait */

                bytes_next = picoquic_format_path_challenge_frame(bytes_next, bytes_max, more_data, is_pure_ack,
                    tuple->challenge[tuple->challenge_repeat_count]);
                if (bytes_next > bytes_challenge) {
                    tuple->challenge_time = current_time;
                    tuple->challenge_repeat_count++;
                    if (!tuple->is_nat_rebinding) {
                        if (cnx->client_mode || ((path_x->bytes_sent + PICOQUIC_ENFORCED_INITIAL_MTU) <= path_x->received)) {
                            *is_challenge_padding_needed = 1;
                        }
                        else {
                            /* Sending a full size packet would defeat the amplification limits, so we take
                             * advantage of the escape clause in RFC 9000, "An endpoint MUST expand datagrams
                             * that contain a PATH_CHALLENGE frame to at least the smallest allowed maximum
                             * datagram size of 1200 bytes, unless the anti-amplification limit for the path
                             * does not permit sending a datagram of this size."
                             */
                            *is_challenge_padding_needed = 0;
                        }
                    }
                    else {
                        /* never pad the packets sent in response to NAT rebinding. */
                        *is_challenge_padding_needed = 0;
                    }
                }

                /* Reset the next challenge time to match the new challenge count */
                next_challenge_time = picoquic_tuple_challenge_time(path_x, tuple, current_time);
                if (next_challenge_time < *next_wake_time) {
                    *next_wake_time = next_challenge_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                }
            }
            else {
                /* This particular tuple failed.
                 * Update its status, and move it to the end of the list.
                 */
                picoquic_tuple_t* next_tuple = path_x->first_tuple;
                picoquic_tuple_t* previous_tuple = NULL;

                tuple->challenge_failed = 1;
                tuple->demotion_time = current_time + (path_x->retransmit_timer << PICOQUIC_CHALLENGE_REPEAT_MAX);

                while (next_tuple != NULL) {
                    if (next_tuple == tuple) {
                        if (previous_tuple == NULL) {
                            path_x->first_tuple = next_tuple->next_tuple;
                            next_tuple = path_x->first_tuple;
                        }
                        else
                        {
                            previous_tuple->next_tuple = next_tuple->next_tuple;
                            next_tuple = previous_tuple->next_tuple;
                        }
                    }
                    else {
                        previous_tuple = next_tuple;
                        next_tuple = next_tuple->next_tuple;

                    }
                }
                if (previous_tuple == NULL) {
                    path_x->first_tuple = tuple;
                }
                else
                {
                    previous_tuple->next_tuple = tuple;
                }
                tuple->next_tuple = NULL;
            }
        }
    }

    if (tuple->response_required) {
        uint8_t* bytes_response = bytes_next;
        if ((bytes_next = picoquic_format_path_response_frame(bytes_response, bytes_max,
            more_data, is_pure_ack, tuple->challenge_response)) > bytes_response) {
            tuple->response_required = 0;
            *is_challenge_padding_needed |= cnx->client_mode || ((path_x->bytes_sent + PICOQUIC_ENFORCED_INITIAL_MTU) <= path_x->received);
        }
    }

    /* TODO: consider adding an address discovery frame. */

    return bytes_next;
}

uint8_t* picoquic_prepare_path_challenge_frames(picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_packet_context_enum pc, int is_nominal_ack_path,
    uint8_t* bytes_next, uint8_t* bytes_max,
    int* more_data, int* is_pure_ack, int* is_challenge_padding_needed,
    uint64_t current_time, uint64_t* next_wake_time)
{
    return picoquic_prepare_tuple_challenge_frames(cnx, path_x, path_x->first_tuple, pc,
        bytes_next, bytes_max, more_data, is_pure_ack, is_challenge_padding_needed,
        current_time, next_wake_time);
}

 /* Prepare packet containing only path control frames. */
int picoquic_prepare_path_control_packet(picoquic_cnx_t* cnx, picoquic_path_t* path_x, picoquic_tuple_t* tuple,
    picoquic_packet_t* packet,
    uint64_t current_time, uint8_t* send_buffer, size_t send_buffer_max, size_t* send_length,
    uint64_t* next_wake_time)
{
    int ret = 0;
    picoquic_packet_type_enum packet_type = picoquic_packet_1rtt_protected;
    picoquic_packet_context_enum pc = picoquic_packet_context_application;
    int is_pure_ack = 1;
    size_t header_length = 0;
    size_t length = 0;
    size_t checksum_overhead = picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
    size_t send_buffer_min_max = (send_buffer_max > path_x->send_mtu) ? path_x->send_mtu : send_buffer_max;
    uint8_t* bytes = packet->bytes;
    uint8_t* bytes_max = bytes + send_buffer_min_max - checksum_overhead;
    uint8_t* bytes_next;
    int more_data = 0;
    int is_challenge_padding_needed = 0;
    picoquic_packet_context_t* pkt_ctx = (cnx->is_multipath_enabled) ?
        &path_x->pkt_ctx :
        &cnx->pkt_ctx[picoquic_packet_context_application];

    /* TODO: will use the local CID specified for the path. There should be a distinct
    * CID specified for the tuple.
     */
    packet->pc = picoquic_packet_context_application;

    length = picoquic_predict_packet_header_length(
        cnx, packet_type, pkt_ctx);
    packet->ptype = packet_type;
    packet->offset = length;
    header_length = length;
    packet->sequence_number = pkt_ctx->send_sequence;
    packet->send_time = current_time;
    packet->send_path = path_x;
    bytes_next = bytes + length;

    /* If required, prepare challenge and response frames.
     * These frames will be sent immediately, regardless of pacing or flow control.
     */
    bytes_next = picoquic_prepare_tuple_challenge_frames(cnx, path_x, tuple, pc,
        bytes_next, bytes_max, &more_data, &is_pure_ack, &is_challenge_padding_needed,
        current_time, next_wake_time);

    /* Compute the length before pacing block */
    length = bytes_next - bytes;

    if (cnx->is_address_discovery_provider) {
        /* If a new address was learned, prepare an observed address frame */
        /* TODO: tie this code to processing of paths */
        bytes_next = picoquic_prepare_observed_address_frame(bytes_next, bytes_max,
            path_x, tuple, current_time, next_wake_time, &more_data, &is_pure_ack);
    }

    if (ret == 0 && length > header_length) {
        /* Ensure that all packets are properly padded before being sent. */

        if (is_challenge_padding_needed && length < PICOQUIC_ENFORCED_INITIAL_MTU) {
            length = picoquic_pad_to_target_length(bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
        else {
            length = picoquic_pad_to_policy(cnx, bytes, length, (uint32_t)(send_buffer_min_max - checksum_overhead));
        }
    }
    else {
        length = 0;
    }
    packet->length = length;
    picoquic_finalize_and_protect_packet(cnx, packet,
        ret, length, header_length, checksum_overhead,
        send_length, send_buffer, send_buffer_min_max,
        path_x, current_time);

    if (*send_length > 0) {
        *next_wake_time = current_time;
        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);

        if (ret == 0 && picoquic_cnx_is_still_logging(cnx)) {
            picoquic_log_cc_dump(cnx, current_time);
        }
    }
    return ret;
}


/* picoquic_tuple_challenge_time:
 * Compute the time at which the next challenge for that path should be sent.
 */
uint64_t  picoquic_tuple_challenge_time(picoquic_path_t* path_x, picoquic_tuple_t* tuple, uint64_t current_time)
{
    /* "Challenge time" holds the time at which the last challenge was set. We
     * use the value to compute an estimate of the RTT */
    uint64_t next_challenge_time = tuple->challenge_time;

    if (tuple->challenge_repeat_count == 0) {
        next_challenge_time = current_time;
    }
    else {
        if (tuple->challenge_repeat_count >= 2) {
            next_challenge_time += path_x->retransmit_timer << (tuple->challenge_repeat_count - 1);
        }
        else {
            next_challenge_time += PICOQUIC_INITIAL_RETRANSMIT_TIMER;
        }
    }

    return next_challenge_time;
}

/* Remove old tuples that are not needed anymore.
 */
void picoquic_delete_demoted_tuples(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t* next_wake_time)
{
    for (int path_index = 0; path_index < cnx->nb_paths; path_index++) {
        picoquic_path_t* path_x = cnx->path[path_index];
        if (!path_x->path_is_demoted) {
            /* examine each tuple record */
            picoquic_tuple_t* tuple = path_x->first_tuple;
            picoquic_tuple_t* next_tuple;

            while (tuple != NULL && (next_tuple = tuple->next_tuple) != NULL) {
                if (next_tuple->challenge_failed) {
                    if (current_time > next_tuple->demotion_time) {
                        picoquic_delete_tuple(path_x, next_tuple);
                        continue;
                    }
                    else if (*next_wake_time > next_tuple->demotion_time) {
                        *next_wake_time = next_tuple->demotion_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
                tuple = next_tuple;
            }
        }
    }
    cnx->tuple_demotion_needed = 0;
}

 /* picoquic_check_path_control_needed:
  * Find whether a path needs to send a challenge or a response.
  * Todo: consider the need to keep alive the paths marked as "backup"
  */
picoquic_tuple_t* picoquic_check_path_control_needed(picoquic_cnx_t* cnx, picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time)
{
    /* examine each tuple record */
    picoquic_tuple_t* tuple = path_x->first_tuple;

    while (tuple != NULL) {
        if (tuple->challenge_failed) {
            if (tuple != path_x->first_tuple && current_time > tuple->demotion_time) {
                cnx->tuple_demotion_needed = 1;
            }
            /* go to next tuple */
        }
        else if (tuple->response_required) {
            /* selected */
            break;
        }
        else if (tuple->challenge_required && !tuple->challenge_verified) {
            uint64_t next_challenge_time = picoquic_tuple_challenge_time(path_x, tuple, current_time);
            if (current_time >= next_challenge_time) {
                // TODO: Figure out what should really happen here, but break; causes constant path challenging.
                // break;
            }
            else if (next_challenge_time < *next_wake_time) {
                *next_wake_time = next_challenge_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
        }
        tuple = tuple->next_tuple;
    }
    return tuple;
}

/* Find available paths:
* Check that there is at least one available path. If not, promote one of the candidates.
*/
int picoquic_verify_path_available(picoquic_cnx_t* cnx, picoquic_path_t** next_path, uint64_t* min_retransmit, uint64_t current_time)
{
    int backup_index = -1;
    int nb_available = 0;
    uint64_t best_available_retransmit = UINT64_MAX;
    uint64_t best_backup_retransmit = UINT64_MAX;

    *min_retransmit = 0;

    for (int path_index = 0; path_index < cnx->nb_paths; path_index++) {
        picoquic_path_t* path_x = cnx->path[path_index];
        if (path_x->first_tuple->challenge_verified &&
            !path_x->path_is_demoted) {
            /* Set the congestion algorithm if not already done */
            if (cnx->congestion_alg != NULL && path_x->congestion_alg_state == NULL) {
                cnx->congestion_alg->alg_init(cnx, path_x, cnx->congestion_alg_option_string, current_time);
            }
            /* track the available paths */
            if (path_x->path_is_backup) {
                if (backup_index < 0 || path_x->nb_retransmit < best_backup_retransmit) {
                    best_backup_retransmit = path_x->nb_retransmit;
                    backup_index = path_index;
                }
            }
            else
            {
                if (path_x->nb_retransmit < best_available_retransmit) {
                    best_available_retransmit = path_x->nb_retransmit;
                    *next_path = path_x;
                    nb_available = 0;
                }
                nb_available++;
            }
        }
    }
    if (best_available_retransmit > 0 && best_backup_retransmit < best_available_retransmit) {
        cnx->path[backup_index]->path_is_backup = 0;
        *next_path = cnx->path[backup_index];
        nb_available = 1;
        *min_retransmit = best_backup_retransmit;
        /* TODO: some logging. Queue PATH_AVAILABLE frame? */
    }
    else
    {
        *min_retransmit = best_available_retransmit;
    }
    return nb_available;
}

/*
 * Produce a sorting of available paths
 */

void picoquic_sort_available_paths(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_path_t** next_path, uint64_t min_retransmit, picoquic_tuple_t** next_tuple)
{
    int data_path_cwin = -1;
    int data_path_pacing = -1;
    uint64_t pacing_time_next = UINT64_MAX;
    uint64_t last_sent_pacing = UINT64_MAX;
    uint64_t last_sent_cwin = UINT64_MAX;
    int i_min_rtt = -1;
    int is_min_rtt_pacing_ok = 0;
    int is_ack_needed = 0;
    picoquic_stream_head_t* next_stream = picoquic_find_ready_stream(cnx);
    int affinity_path_id = -1;

    /* Several paths are available. We will chose from that.
     */
    for (int path_index = 0; path_index < cnx->nb_paths; path_index++) {
        picoquic_path_t* path_x = cnx->path[path_index];
        /* Clear the nominal ack path flag from all path -- it will be reset to the low RTT path later */
        path_x->is_nominal_ack_path = 0;
        /* Only continue processing if the path is available */
        if (path_x->path_is_backup || !path_x->first_tuple->challenge_verified || path_x->path_is_demoted || path_x->nb_retransmit > min_retransmit) {
            continue;
        }
        /* This path is a candidate for min rtt */
        if (i_min_rtt < 0 ||
            path_x->nb_retransmit < cnx->path[i_min_rtt]->nb_retransmit ||
            (path_x->nb_retransmit == cnx->path[i_min_rtt]->nb_retransmit &&
                path_x->rtt_min < cnx->path[i_min_rtt]->rtt_min)) {
            i_min_rtt = path_index;
            is_min_rtt_pacing_ok = 0;
        }
        path_x->polled++;
        /* Find the best path authorized by pacing and then by congestion control,
         * taking into account affinity, datagrams, etc.
         */
        if (picoquic_is_sending_authorized_by_pacing(cnx, path_x, current_time, &pacing_time_next)) {
            if (path_x->last_sent_time < last_sent_pacing) {
                last_sent_pacing = path_x->last_sent_time;
                data_path_pacing = path_index;
                if (path_index == i_min_rtt) {
                    is_min_rtt_pacing_ok = 1;
                }
            }
            if (path_x->bytes_in_transit < path_x->cwin &&
                path_x->bytes_in_transit < cnx->quic->cwin_max) {
                if (path_x->last_sent_time < last_sent_cwin) {
                    last_sent_cwin = path_x->last_sent_time;
                    data_path_cwin = path_index;
                }
                if (affinity_path_id < 0) {
                    /* we select here the first path that is either ready to send on
                        * the highest priority stream with affinity on this path, or
                        * ready to send datagrams on this path. */
                    if (next_stream != NULL && path_x == next_stream->affinity_path) {
                        affinity_path_id = path_index;
                    }
                    else if (path_x->is_datagram_ready || cnx->is_datagram_ready) {
                        affinity_path_id = path_index;
                    }
                }
            }
            else {
                path_x->congested++;
            }
        }
        else {
            path_x->paced++;
        }
    }
    /* Putting it all together:
     * - fix the nominal ACK path that we erased.
     * - retain the ACK
     */

    if (i_min_rtt >= 0) {
        is_ack_needed = picoquic_is_ack_needed(cnx, current_time, next_wake_time, 0, 0);
        cnx->path[i_min_rtt]->is_nominal_ack_path = 1;
    }

    if (is_ack_needed && is_min_rtt_pacing_ok) {
        *next_path = cnx->path[i_min_rtt];
    }
    else if (data_path_cwin >= 0) {
        /* if there is a path ready to send the most urgent data, select it */
        if (affinity_path_id >= 0) {
            *next_path = cnx->path[affinity_path_id];
        }
        else {
            *next_path = cnx->path[data_path_cwin];
        }
    }
    else if (data_path_pacing >= 0) {
        *next_path = cnx->path[data_path_pacing];
    }
    else {
        /* No path is ready at all. Set the next wake time to the min of current
         * value and next pacing time.
         */
        if (pacing_time_next < *next_wake_time) {
            *next_wake_time = pacing_time_next;
            SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
        }
        *next_path = cnx->path[0];
    }
    (*next_path)->selected++;
    *next_tuple = (*next_path)->first_tuple;
}

/*
* For each path:
*    - For each tuple:
*         - if a first challenge is required now, the path/tuple is selected immediately.
*         - if a response is required now, the path/tuple is selected immediately.
*         - if a challenge or a response is required after the current time:
*               - the next time is update.
* If there is not an immediate selection:
*    for each path in available mode. in round robin order:
*       - if there is data or ACK to send:
*           the path is selected, with first tuple.
* If no path selected:
*    select the default path or tuple.
 */
void picoquic_select_next_path_tuple(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_path_t** next_path, picoquic_tuple_t** next_tuple)
{
    int nb_available = 0;
    uint64_t min_retransmit = 0;

    *next_path = NULL;
    *next_tuple = NULL;

    /* First check whether path contol messages are needed */
    for (int path_index = 0; path_index < cnx->nb_paths; path_index++)
    {
        if (cnx->path[path_index]->path_is_demoted) {
            continue;
        }
        else if (cnx->is_multipath_enabled && cnx->path[path_index]->first_tuple->challenge_failed && !cnx->path[path_index]->path_abandon_sent) {
            (void)picoquic_abandon_path(cnx, cnx->path[path_index]->unique_path_id, PICOQUIC_TRANSPORT_UNSTABLE_INTERFACE, NULL, current_time);
        }
        else if ((*next_tuple = picoquic_check_path_control_needed(cnx, cnx->path[path_index], current_time, next_wake_time)) != NULL) {
            *next_path = cnx->path[path_index];
            (*next_path)->challenger++;
            break;
        }
        else if (cnx->nb_paths > 0 && cnx->path[path_index]->first_tuple->challenge_verified && cnx->path[path_index]->nb_retransmit > 0 &&
            cnx->cnx_state == picoquic_state_ready && cnx->path[path_index]->bytes_in_transit == 0) {
            cnx->path[path_index]->is_multipath_probe_needed = 1;
            *next_path = cnx->path[path_index];
            *next_tuple = (*next_path)->first_tuple;
            (*next_path)->challenger++;
            break;
        }
    }
    if (*next_path != NULL) {
        /* we are done */
    }
    else  if (cnx->nb_paths == 1) {
        /* No choice, just use this path -- this is the default if multipath is not selected. */
        *next_path = cnx->path[0];
        *next_tuple = (*next_path)->first_tuple;
    }
    else if ((nb_available = picoquic_verify_path_available(cnx, next_path, &min_retransmit, current_time)) < 2) {
        /* Only 0 or 1 path to chose from. Just select that. */
        if (*next_path == NULL) {
            *next_path = cnx->path[0];
        }
        *next_tuple = (*next_path)->first_tuple;
    }
    else {
        /* Several paths are available. We will chose from that, looking at
        * available path that can send ACK, or paced data, or congestion
        * controlled data.
         */
        picoquic_sort_available_paths(cnx, current_time, next_wake_time, next_path, min_retransmit, next_tuple);
    }
}




 /*
 Find path of incoming packet

 A path is defined by a pair of addresses. The path is created by the client
 when it learns about a new local or remote address. It is created by the
 server when it receives data from a not yet identified address pair.

 We associate a local CID with a path. This is the CID that the peer uses
 to send packet. This is a loose association. When a packet is received, the
 packet is associated with a path based on the address tuple. If this is a
 new tuple, a new path should be created, unless too many paths have been
 created already (some heuristics needed there).

 Different scenarios play here:

  - If the incoming CID has not yet been seen, we treat arrival as a
    migration attempt and pursue the validation sequence.

  - If this is the same incoming CID as an existing path, we treat it
    as an indication of NAT rebinding. We may need some heuristic to
    decide whether this is legit or an attack. If this may be legit, we
    create a new path and send challenges on both the new and the old path.

  - If this is the same tuple and a different incoming CID, we treat that
    as an attempt by the peer to change the CID for privacy reason. On this
    event, the server picks a new CID for the path if available. (May need
    some safety there, e.g. only pick a new CID if the incoming CID sequence
    is higher than the old one.)

 NAT rebinding should only happen if the address was changed in the
 network, either by a NAT or by an attacker. NATs are:

  - rare but not unheard of in front of servers

  - rare with IPv6

   - rare if the connection is sustained

 A small problem here is that the QUIC test suite include some pretty
 unrealistic NAT rebinding simulations, so we cannot be too strict. In
 order to pass the test suites, we will accept the first rebinding
 attempt as genuine, and be more picky with the next ones. They may have
 to wait until validation timers expire.

 Local CID are kept in a list, and are associated with paths by a reference.
 If a local CID is retired, the reference is zeroed. When a new packet arrives
 on path with a new CID, the reference is reset.

 If we cannot associate an existing path with a packet and also
 cannot create a new path, we treat the packet as arriving on the
 default path.
 */

int picoquic_find_incoming_path(picoquic_cnx_t* cnx, picoquic_packet_header* ph,
    struct sockaddr* addr_from,
    struct sockaddr* addr_to,
    int if_index_to,
    uint64_t current_time,
    int* p_path_id,
    int* path_is_not_allocated)
{
    int ret = 0;
    picoquic_path_t* path_x = NULL;
    picoquic_tuple_t* tuple = NULL;
    int path_id = (ph->l_cid == NULL) ? 0 : picoquic_find_path_by_unique_id(cnx, ph->l_cid->path_id);

    if (path_id < 0) {
        /* Either this path has not yet been created, or it was already destroyed.
        * The packet decryption was successful, which means that the CID is valid,
        * but on the server side we might have a "probe".
         */
        if (cnx->nb_paths < PICOQUIC_NB_PATH_TARGET &&
            (cnx->quic->is_port_blocking_disabled || !picoquic_check_addr_blocked(addr_from)) &&
            picoquic_create_path(cnx, current_time, addr_to, addr_from, if_index_to, ph->l_cid->path_id) > 0) {
            /* if we do create a new path, it should have the right path_id. We cannot
            * assume that paths will be created in the full order, so that means we may
            * have to create "empty" paths in invalid state. Or, more simply,
            * create a path and override the unique path id, which should be OK
            * as that unique ID does not exist.
            * TODO: modify path creation to force path_id, return error if impossible.
             */
            path_id = cnx->nb_paths - 1;
            path_x = cnx->path[path_id];

            /* when creating the path, we need to copy the dest CID and chose
             * destination CID with the matching path ID.
             */
            path_x->first_tuple->p_local_cnxid = picoquic_find_local_cnxid(cnx, path_x->unique_path_id, &ph->dest_cnx_id);
            picoquic_assign_peer_cnxid_to_tuple(cnx, path_x, path_x->first_tuple);
        }
    }
    else
    {
        path_x = cnx->path[path_id];
        tuple = path_x->first_tuple;

        /* If the local CID is not set, set it */
        if (path_x->first_tuple->p_local_cnxid == NULL) {
            path_x->first_tuple->p_local_cnxid = picoquic_find_local_cnxid(cnx, path_x->unique_path_id, &ph->dest_cnx_id);
            if (!cnx->client_mode && cnx->is_multipath_enabled && path_x->first_tuple->challenge_verified) {
                /* If the peer renewed its connection id, the retire connection ID frame may already
                 * have arrived on a separate path. If the server noticed that, it should also renew
                 * its "remote path" ID */
                (void)picoquic_renew_connection_id(cnx, path_id);
            }
        }

        /* Treat the special case of the unkown local address, which should only happen
         * for clients and for the first tuple. */
        if (path_x->first_tuple->local_addr.ss_family == AF_UNSPEC) {
            picoquic_store_addr(&cnx->path[path_id]->first_tuple->local_addr, addr_to);
        }

        /* Look for the best match among existing tuples */
        while (tuple != NULL) {
            /* If the addresses match, we are good. */
            if (picoquic_compare_addr(addr_from, (struct sockaddr*)&tuple->peer_addr) == 0 &&
                picoquic_compare_addr(addr_to, (struct sockaddr*)&tuple->local_addr) == 0) {
                break;
            }
            else
            {
                tuple = tuple->next_tuple;
            }
        }
        if (tuple == NULL) {
            /* If the addresses do not match, we have two possibilities:
            * either the creation of a new tuple, or a NAT rebinding on an existing tuple.
            * In all cases, we need to create a new tuple. In the NAt rebinding cases, we
            * may be a bit more agressive, i.e., immediately promote the new tuple
            * as the default.
            */

            if (picoquic_check_cid_for_new_tuple(cnx, path_x->unique_path_id) == 0 &&
                (tuple = picoquic_create_tuple(path_x, addr_to, addr_from, if_index_to)) != NULL) {
                if (picoquic_assign_peer_cnxid_to_tuple(cnx, path_x, tuple) == 0) {
                    picoquic_set_tuple_challenge(tuple, current_time, cnx->quic->use_constant_challenges);
                    tuple->challenge_required = 1;
                }
            }
            /* TODO: clean up in case of failure. */
        }
        else {
            /* If the addresses do match, but the CID do not, we have a case of NAT rebinding.
             */
            if (tuple == path_x->first_tuple &&
                picoquic_compare_connection_id(&path_x->first_tuple->p_local_cnxid->cnx_id, &ph->dest_cnx_id) != 0) {
                path_x->first_tuple->p_local_cnxid = picoquic_find_local_cnxid(cnx, path_x->unique_path_id, &ph->dest_cnx_id);
                if (cnx->client_mode == 0) {
                    (void)picoquic_renew_connection_id(cnx, path_id);
                }
            }
        }
    }
    *p_path_id = path_id;
    cnx->path[path_id]->last_packet_received_at = current_time;

    return ret;
}
