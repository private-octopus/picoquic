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
#include "picoquic_unified_log.h"
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>

/* Packet loss recovery logic. This is an implementation of the RACK
 * algorithm, with two key functions:
 * 
 * - picoquic_retransmit_needed: perform the packet number based loss
 *   detection.
 * - picoquic_pto_needed: perform the timer based loss detection.
 * 
 * We expect the pto code to be called only if there
 * is nothing else to send on a specific pass -- cwin is blocked,
 * application is inactive. 
 */


 /* picoquic_retransmit_needed_by_packet:
 * Answer the question, should this packet be considered lost?
 *
 * The principal way to answer this question is by using the RACK
 * algorithm. Did the peer already acknowledge packets sent on the
 * same path after this packet? If yes,
 * there are only two possibilities, out of order delivery that was not yet acked,
 * or packet loss. For simplicity, we assume that out of order delivery
 * is unlikely if three packets were sent between this packet and the
 * acknowledged packet, or if an out of order delivery delay
 * is 1/4 of the path RTT was past.
 * In the pure RACK algorithm, the only other retransmission happens
 * if the last packet sent on the path has not yet been acknowledged
 * after a retransmission delay. We implement that, but we are also
 * worried about detecting link-cuts soon enough. We also consider
 * packet losts if they have not been acknowledged for two retransmission
 * delays, and if we have performed at least one PTO previously.
 */

static int picoquic_retransmit_needed_by_packet(picoquic_cnx_t* cnx,
    picoquic_packet_t* p, uint64_t current_time, uint64_t* next_retransmit_time, int* timer_based)
{
    picoquic_packet_context_enum pc = p->pc;
    uint64_t retransmit_time;
    int64_t delta_seq = 0;
    int64_t delta_sent = 0;
    uint64_t rack_timer_min;
    int should_retransmit = 0;
    int is_timer_based = 0;

    if (p->send_path == NULL) {
        /* This is a bug. Can only happen if the sending path has been
        * deleted, in which case the packet should be retransmitted immediately */
        is_timer_based = 0;
        should_retransmit = 1;
        retransmit_time = current_time;
    }
    else if (p->ptype == picoquic_packet_0rtt_protected && !cnx->zero_rtt_data_accepted) {
        /* Zero RTT data was not accepted by the peer, the packets are considered lost */
        retransmit_time = current_time;
        should_retransmit = 1;
    }
    else if (p->ptype == picoquic_packet_0rtt_protected && cnx->cnx_state != picoquic_state_ready &&
        cnx->cnx_state != picoquic_state_client_ready_start) {
        /* Set the retransmit time ahead of current time since the connection is not ready */
        retransmit_time = current_time + p->send_path->smoothed_rtt + PICOQUIC_RACK_DELAY;
    }
    else {
        delta_seq = p->send_path->path_packet_acked_number - p->path_packet_number;
        if (delta_seq >= 3) {
            /* Last acknowledged packet is ways ahead. That means this packet
            * is most probably lost.
            */
            retransmit_time = current_time;
        }
        else if (delta_seq > 0) {
            /* Set a timer relative to that last packet */
            int64_t rack_delay = (p->send_path->smoothed_rtt >> 2);

            delta_sent = p->send_path->path_packet_acked_time_sent - p->send_time;
            if (rack_delay > PICOQUIC_RACK_DELAY / 2) {
                rack_delay = PICOQUIC_RACK_DELAY / 2;
            }
            retransmit_time = p->send_time + p->send_path->retransmit_timer;
            rack_timer_min = p->send_path->path_packet_acked_received + rack_delay
                - delta_sent + cnx->remote_parameters.max_ack_delay;
            if (retransmit_time > rack_timer_min) {
                retransmit_time = rack_timer_min;
            }
        }
        else {
            /* Find the last packet in the queue, which may be this one.
            * Compute a timer from the time this last packet was sent.
            * If the timer has elapsed, this packet should be resent,
            * in a timer based manner. If not, set the timer to
            * the specified value. */
            picoquic_packet_t* last_packet = p->send_path->path_packet_last;
            uint64_t idle_peer_start = p->send_time;
            uint64_t retransmit_timer = picoquic_current_retransmit_timer(cnx, p->send_path);
            uint64_t idle_peer_timer = idle_peer_start + 2 * retransmit_timer;

            if (idle_peer_start < p->send_path->path_packet_acked_time_sent) {
                idle_peer_start = p->send_path->path_packet_acked_time_sent;
            }
            if (last_packet == NULL) {
                last_packet = p;
            }
            is_timer_based = 1;
            retransmit_time = last_packet->send_time + picoquic_current_retransmit_timer(cnx, p->send_path);
            if (retransmit_time > idle_peer_timer) {
                retransmit_time = idle_peer_timer;
                is_timer_based &= (p->send_path->nb_retransmit == 0);
            }
        }

        if (current_time >= retransmit_time || (p->is_ack_trap && delta_seq > 0)) {
            should_retransmit = 1;
            if (cnx->quic->sequence_hole_pseudo_period != 0 && pc == picoquic_packet_context_application && !p->is_ack_trap) {
                DBG_PRINTF("Retransmit #%d, delta=%d, timer=%d, time=%d, sent: %d, ack_t: %d, s_rtt: %d, rt: %d",
                    (int)p->sequence_number, (int)delta_seq, is_timer_based, (int)current_time, (int)p->send_time,
                    (int)p->send_path->path_packet_acked_received, (int)p->send_path->smoothed_rtt, (int)retransmit_time);
            }
        }
    }

    *timer_based = is_timer_based;
    *next_retransmit_time = retransmit_time;

    return should_retransmit;
}

int picoquic_copy_before_retransmit(picoquic_packet_t * old_p,
    picoquic_cnx_t * cnx,
    uint8_t * new_bytes,
    size_t send_buffer_max_minus_checksum,
    int * packet_is_pure_ack,
    int * do_not_detect_spurious,
    int force_queue,
    size_t * length,
    int * add_to_data_repeat_queue)
{
    /* check if this is an ACK only packet */
    int ret = 0;
    int frame_is_pure_ack = 0;
    size_t frame_length = 0;
    size_t byte_index = 0; /* Used when parsing the old packet */

    if (old_p->is_mtu_probe) {
        if (old_p->send_path != NULL) {
            /* MTU probe was lost, presumably because of packet too big */
            old_p->send_path->mtu_probe_sent = 0;
            if (!force_queue) {
                old_p->send_path->send_mtu_max_tried = old_p->length + old_p->checksum_overhead;
            }
        }
        /* MTU probes should not be retransmitted */
        *packet_is_pure_ack = 1;
        *do_not_detect_spurious = 0;
    }
    else if (old_p->is_ack_trap) {
        *packet_is_pure_ack = 1;
        *do_not_detect_spurious = 1;
    }
    else if (old_p->is_multipath_probe) {
        *packet_is_pure_ack = 0;
        *do_not_detect_spurious = 1;
    }
    else if (old_p->was_preemptively_repeated) {
        *packet_is_pure_ack = 1;
        *do_not_detect_spurious = 1;
    }
    else {
        /* Copy the relevant bytes from one packet to the next */
        byte_index = old_p->offset;

        while (ret == 0 && byte_index < old_p->length) {
            ret = picoquic_skip_frame(&old_p->bytes[byte_index],
                old_p->length - byte_index, &frame_length, &frame_is_pure_ack);

            /* Check whether the data was already acked, which may happen in
            * case of spurious retransmissions */
            if (ret == 0 && frame_is_pure_ack == 0) {
                ret = picoquic_check_frame_needs_repeat(cnx, &old_p->bytes[byte_index],
                    frame_length, old_p->ptype, &frame_is_pure_ack, do_not_detect_spurious, NULL);
            }

            /* Keep track of datagram frames that are possibly lost */
            if (ret == 0 &&
                PICOQUIC_IN_RANGE(old_p->bytes[byte_index], picoquic_frame_type_datagram, picoquic_frame_type_datagram_l) &&
                cnx->callback_fn != NULL) {
                uint8_t frame_id;
                uint64_t content_length;
                uint8_t* content_bytes = &old_p->bytes[byte_index];

                /* Parse and skip type and length */
                content_bytes = picoquic_decode_datagram_frame_header(content_bytes, content_bytes + frame_length,
                    &frame_id, &content_length);
                if (content_bytes != NULL) {
                    ret = (cnx->callback_fn)(cnx, old_p->send_time, content_bytes, (size_t)content_length,
                        picoquic_callback_datagram_lost, cnx->callback_ctx, NULL);
                }
                picoquic_log_app_message(cnx, "Datagram lost, PN=%" PRIu64 ", Sent: %" PRIu64,
                    old_p->sequence_number, old_p->send_time);
            }

            /* Prepare retransmission if needed */
            if (ret == 0) {
                if (!frame_is_pure_ack) {
                    if (PICOQUIC_IN_RANGE(old_p->bytes[byte_index], picoquic_frame_type_stream_range_min, picoquic_frame_type_stream_range_max)) {
                        * add_to_data_repeat_queue = 1;
                    }
                    else {
                        if ((force_queue || frame_length > send_buffer_max_minus_checksum - *length) &&
                            (old_p->ptype == picoquic_packet_0rtt_protected ||
                                old_p->ptype == picoquic_packet_1rtt_protected)) {
                            ret = picoquic_queue_misc_frame(cnx, &old_p->bytes[byte_index], frame_length, 0);
                        }
                        else {
                            memcpy(&new_bytes[*length], &old_p->bytes[byte_index], frame_length);
                            *length += frame_length;
                        }
                    }
                    *packet_is_pure_ack = 0;
                }
                byte_index += frame_length;
            }
        }
    }

    return ret;
}

int picoquic_is_packet_ack_soliciting(picoquic_packet_t * packet)
{
    /* check if this is an ACK soliciting packet */
    int is_ack_soliciting = 0;

    if (packet->is_evaluated) {
        is_ack_soliciting = packet->is_ack_soliciting;
    } else {
        /* Trap packets are never supposed to elicit an ACK. */
        /* For other packets, we need to look at the frames inside. */
        if (!packet->is_ack_trap) {
            size_t frame_length = 0;
            size_t byte_index = packet->offset;

            while (byte_index < packet->length) {
                int frame_is_pure_ack = 0;
                if (picoquic_skip_frame(&packet->bytes[byte_index],
                    packet->length - byte_index, &frame_length, &frame_is_pure_ack) != 0) {
                    /* Malformed packet. Ignore it. Do not expect an ack */
                    break;
                }
                if (!frame_is_pure_ack) {
                    is_ack_soliciting = 1;
                    break;
                }
            }
        }
        packet->is_ack_soliciting = is_ack_soliciting;
        packet->is_evaluated = 1;
    }

    return is_ack_soliciting;
}

static int picoquic_retransmit_needed_packet(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
    picoquic_packet_t* old_p,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length,
    int* continue_next)
{
    size_t length = 0;
    *continue_next = 0;

    /* TODO: while packets are pure ACK, drop them from retransmit queue */
    picoquic_path_t* old_path = old_p->send_path; /* should be the path on which the packet was transmitted */
    int should_retransmit = 0;
    int timer_based_retransmit = 0;
    uint64_t next_retransmit_time = *next_wake_time;
    uint64_t lost_packet_number = old_p->path_packet_number;
    uint8_t* new_bytes = packet->bytes;
    int ret = 0;

    length = 0;

    /* Get the packet type */
    should_retransmit = cnx->initial_repeat_needed ||
        picoquic_retransmit_needed_by_packet(cnx, old_p, current_time, &next_retransmit_time, &timer_based_retransmit);

    if (should_retransmit == 0) {
        /*
        * Always retransmit in order. If not this one, then nothing.
        * But make an exception for 0-RTT packets.
        */
        if (old_p->ptype == picoquic_packet_0rtt_protected) {
            *continue_next = 1;
        }
        else {
            if (next_retransmit_time < *next_wake_time) {
                *next_wake_time = next_retransmit_time;
                SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
            }
            /* Will not continue */
            *continue_next = 0;
        }
    }
    else if (old_p->is_ack_trap) {
        picoquic_dequeue_retransmit_packet(cnx, pkt_ctx, old_p, 1, 0);
        *continue_next = 1;
    }
    else {
        /* check if this is an ACK only packet */
        int packet_is_pure_ack = 1;
        int do_not_detect_spurious = 1;
        size_t checksum_length = 0;
        int add_to_data_repeat_queue = 0;

        /* we'll report it where it got lost */
        if (old_path) {
            old_path->retrans_count++;
        }

        *header_length = 0;

        if (old_p->ptype == picoquic_packet_0rtt_protected) {
            if (cnx->cnx_state < picoquic_state_client_ready_start) {
                should_retransmit = 0;
            }
            else {
                length = picoquic_predict_packet_header_length(cnx, picoquic_packet_1rtt_protected, pkt_ctx);
                packet->ptype = picoquic_packet_1rtt_protected;
                packet->offset = length;
            }
        }
        else {
            length = picoquic_predict_packet_header_length(cnx, old_p->ptype, pkt_ctx);
            packet->ptype = old_p->ptype;
            packet->offset = length;
        }

        if (should_retransmit != 0 && (old_p->ptype == picoquic_packet_initial || old_p->ptype == picoquic_packet_handshake)) {
            /* Need to verify that there is no coalescing issue! */
            if (old_p->length > send_buffer_max) {
                picoquic_log_app_message(cnx, "Delay retransmission in type %d, seq %" PRIu64 ", buffer too small",
                    old_p->ptype, old_p->sequence_number);
                return 0;
            }
        }

        if (should_retransmit != 0) {
            packet->sequence_number = pkt_ctx->send_sequence;
            packet->send_path = path_x;
            packet->pc = pc;
            *header_length = length;

            switch (packet->ptype) {
            case picoquic_packet_1rtt_protected:
                checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_1rtt);
                break;
            case picoquic_packet_initial:
                checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_initial);
                break;
            case picoquic_packet_handshake:
                checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_handshake);
                break;
            case picoquic_packet_0rtt_protected:
                checksum_length = picoquic_get_checksum_length(cnx, picoquic_epoch_0rtt);
                break;
            default:
                DBG_PRINTF("Trying to retransmit packet type %d", old_p->ptype);
                checksum_length = 0;
                break;
            }

            ret = picoquic_copy_before_retransmit(old_p, cnx,
                new_bytes,
                send_buffer_max - checksum_length,
                &packet_is_pure_ack,
                &do_not_detect_spurious, 0,
                &length,
                &add_to_data_repeat_queue);

            if (ret != 0) {
                DBG_PRINTF("Copy before retransmit returns %d\n", ret);
            }

            /* Update the number of bytes in transit and remove old packet from queue */
            /* If not pure ack, the packet will be placed in the "retransmitted" queue,
            * in order to enable detection of spurious restransmissions */

            picoquic_log_packet_lost(cnx, old_p->send_path, old_p->ptype, old_p->sequence_number,
                (timer_based_retransmit == 0) ? "repeat" : "timer",
                (old_p->send_path == NULL) ? NULL : &old_p->send_path->p_remote_cnxid->cnx_id,
                old_p->length, current_time);


            if (old_p->send_path != NULL && (cnx->is_multipath_enabled || cnx->is_simple_multipath_enabled)) {
                /* If ack only packets are lost, bundle a ping next time an ACK is sent on that path */
                old_p->send_path->is_ack_lost = 1;
            }
            /* Keep track of the path, as "old_p->send_path" will be zeroed when dequeued */
            old_path = old_p->send_path;
            old_p = picoquic_dequeue_retransmit_packet(cnx, pkt_ctx, old_p, packet_is_pure_ack & do_not_detect_spurious,
                add_to_data_repeat_queue);

            /* If we have a good packet, return it */
            if (old_p == NULL || packet_is_pure_ack) {
                length = 0;
                *continue_next = 1;
            }
            else {
                int exit_early = 0;
                if (old_path != NULL) {
                    old_path->lost++;
                }
                if (old_path != NULL &&
                    (old_p->length + old_p->checksum_overhead) == old_path->send_mtu &&
                    cnx->cnx_state >= picoquic_state_ready) {
                    old_path->nb_mtu_losses++;
                    if (old_path->nb_mtu_losses > PICOQUIC_MTU_LOSS_THRESHOLD) {
                        picoquic_reset_path_mtu(old_path);
                        picoquic_log_app_message(cnx,
                            "Reset path MTU after %d retransmissions, %d MTU losses",
                            old_path->nb_retransmit,
                            old_path->nb_mtu_losses);
                    }
                }

                if (timer_based_retransmit != 0) {
                    /* First, keep track of retransmissions per path, in order to
                    * manage scheduling in multipath setup */
                    if (old_path != NULL &&
                        old_p->path_packet_number > old_path->path_packet_acked_number &&
                        old_p->send_time > old_path->last_loss_event_detected) {
                        old_path->nb_retransmit++;
                        old_path->last_loss_event_detected = current_time;
                        if (old_path->nb_retransmit > 7 &&
                            cnx->cnx_state >= picoquic_state_ready) {
                            /* Max retransmission reached for this path */
                            DBG_PRINTF("%s\n", "Too many data retransmits, abandon path");
                            picoquic_log_app_message(cnx, "%s", "Too many data retransmits, abandon path");
                            old_path->challenge_failed = 1;
                            cnx->path_demotion_needed = 1;
                        }
                    }

                    /* Then, manage the total number of retransmissions across all paths. */
                    if ((old_path == NULL || old_path->nb_retransmit > 7) &&
                        cnx->cnx_state >= picoquic_state_ready) {
                        /* TODO: only disconnect if there is no other available path */
                        int all_paths_bad = 1;
                        if (cnx->is_multipath_enabled || cnx->is_simple_multipath_enabled) {
                            for (int path_id = 0; path_id < cnx->nb_paths; path_id++) {
                                if (cnx->path[path_id]->nb_retransmit < 8) {
                                    all_paths_bad = 0;
                                    break;
                                }
                            }
                        }
                        if (all_paths_bad) {
                            /*
                            * Max retransmission count was exceeded. Disconnect.
                            */
                            DBG_PRINTF("Too many retransmits of packet number %d, disconnect", (int)old_p->sequence_number);
                            cnx->local_error = PICOQUIC_ERROR_REPEAT_TIMEOUT;
                            picoquic_connection_disconnect(cnx);
                            length = 0;
                            *continue_next = 0;
                            exit_early = 1;
                        }
                    }
                }

                if (!exit_early) {

                    if (old_p->ptype < picoquic_packet_1rtt_protected) {
                        DBG_PRINTF("Retransmit packet type %d, pc=%d, seq = %llx, is_client = %d\n",
                            old_p->ptype, old_p->pc,
                            (unsigned long long)old_p->sequence_number, cnx->client_mode);
                    }

                    /* special case for the client initial */
                    if (old_p->ptype == picoquic_packet_initial && cnx->client_mode) {
                        length = picoquic_pad_to_target_length(new_bytes, length, send_buffer_max - checksum_length);
                    }
                    packet->length = length;
                    cnx->nb_retransmission_total++;

                    if (old_path != NULL) {
                        old_path->nb_losses_found++;
                        old_path->total_bytes_lost += old_p->length;
                        if (timer_based_retransmit) {
                            old_path->is_pto_required = 1;
                        }

                        if (cnx->congestion_alg != NULL && cnx->cnx_state >= picoquic_state_ready) {
                            cnx->congestion_alg->alg_notify(cnx, old_path,
                                (timer_based_retransmit == 0) ? picoquic_congestion_notification_repeat : picoquic_congestion_notification_timeout,
                                0, 0, 0, lost_packet_number, current_time);
                        }
                    }

                    if (length <= packet->offset) {
                        length = 0;
                        packet->length = 0;
                        packet->offset = 0;
                        if (!packet_is_pure_ack) {
                            /* Pace down the next retransmission so as to not pile up error upon error.
                            * We only do that if theree are enough tokens in the bucket to allow at least
                            * one packet out. Otherwise, there is a risk of creating a waiting loop that
                            * only stops when all queued packets have been processed.
                            */
                            if (path_x->pacing_bucket_nanosec > path_x->pacing_packet_time_nanosec) {
                                path_x->pacing_bucket_nanosec -= path_x->pacing_packet_time_nanosec;
                            }
                        }
                        /*
                        * If the loop is continuing, this means that we need to look
                        * at the next candidate packet. 
                        */
                        *continue_next = (timer_based_retransmit == 0);
                    }
                    else {
                        *continue_next = 0;
                    }
                }
            }
        }
    }

    return (int)length;
}

static int picoquic_retransmit_needed_loop(picoquic_cnx_t* cnx, picoquic_packet_context_t* pkt_ctx,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length)
{
    int continue_next = 1;
    int ret = 0;
    picoquic_packet_t* old_p = pkt_ctx->pending_first;

    /* Call the per packet routine in a loop */
    while (old_p != 0 && continue_next) {
        picoquic_packet_t* p_next = old_p->packet_next;
        ret = picoquic_retransmit_needed_packet(cnx, pkt_ctx, old_p, pc, path_x, current_time,
            next_wake_time, packet, send_buffer_max, header_length, &continue_next);
        old_p = p_next;
    }

    return ret;
}

int picoquic_retransmit_needed(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc,
    picoquic_path_t* path_x, uint64_t current_time, uint64_t* next_wake_time,
    picoquic_packet_t* packet, size_t send_buffer_max, size_t* header_length)
{
    int length = 0;

    if (pc == picoquic_packet_context_application && cnx->is_multipath_enabled) {
        /* If multipath is enabled, should check for retransmission on all paths */
        picoquic_remote_cnxid_t* r_cid = cnx->cnxid_stash_first;

        while (r_cid != NULL) {
            if (length == 0) {
                length = picoquic_retransmit_needed_loop(cnx, &r_cid->pkt_ctx, pc, path_x, current_time,
                    next_wake_time, packet, send_buffer_max, header_length);
            }
            else {
                /* If more retransmission are queued, set the timer appropriately */
                int timer_based_retransmit = 0;
                uint64_t next_retransmit_time = *next_wake_time;

                if (r_cid->pkt_ctx.pending_first != NULL) {
                    if (picoquic_retransmit_needed_by_packet(cnx, r_cid->pkt_ctx.pending_first,
                        current_time, &next_retransmit_time, &timer_based_retransmit)) {
                        *next_wake_time = current_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                        break;
                    }
                    else if (next_retransmit_time < *next_wake_time) {
                        *next_wake_time = next_retransmit_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
            }
            r_cid = r_cid->next;
        }
    }
    else if (cnx->is_simple_multipath_enabled && cnx->cnx_state == picoquic_state_ready) {
        /* The per-path algorithm excludes the packets that were sent on
        * a path now deleted. The path is set to NULL. */
        picoquic_packet_context_t* pkt_ctx = &cnx->pkt_ctx[pc];
        picoquic_packet_t* old_p = pkt_ctx->pending_first;
        int continue_next = 1;

        while (old_p != NULL && old_p->send_path == NULL && continue_next) {
            picoquic_packet_t* p_next = old_p->packet_next;
            length = picoquic_retransmit_needed_packet(cnx, pkt_ctx, old_p, pc, path_x, current_time,
                next_wake_time, packet, send_buffer_max, header_length, &continue_next);
            old_p = p_next;
        }
        /* Find the path with the lowest repeat wait? */
        for (int i_path = 0; i_path < cnx->nb_paths; i_path++) {
            old_p = cnx->path[i_path]->path_packet_first;

            if (length == 0) {
                continue_next = 1;

                /* Call the per packet routine in a loop */
                while (old_p != 0 && continue_next) {
                    picoquic_packet_t* p_next = old_p->path_packet_next;
                    if (old_p->pc == pc) {
                        length = picoquic_retransmit_needed_packet(cnx, &cnx->pkt_ctx[pc], old_p, pc, path_x, current_time,
                            next_wake_time, packet, send_buffer_max, header_length, &continue_next);
                    }
                    old_p = p_next;
                }
            }
            else {
                /* If more retransmission are queued, set the timer appropriately */
                int timer_based_retransmit = 0;
                uint64_t next_retransmit_time = *next_wake_time;

                if (old_p != NULL){
                    if (picoquic_retransmit_needed_by_packet(cnx, old_p,
                        current_time, &next_retransmit_time, &timer_based_retransmit)) {
                        *next_wake_time = current_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                        break;
                    }
                    else if (next_retransmit_time < *next_wake_time) {
                        *next_wake_time = next_retransmit_time;
                        SET_LAST_WAKE(cnx->quic, PICOQUIC_SENDER);
                    }
                }
            }
        }
    }
    else {
        length = picoquic_retransmit_needed_loop(cnx, &cnx->pkt_ctx[pc], pc, path_x, current_time, next_wake_time,
            packet, send_buffer_max, header_length);
    }

    return length;
}

/* PTO logic, timer based.
* If the sending time of the last packet plus the retransmit timer
* is elapsed, something should be resent on that path. However,
* this should only occur if the "last packet" is ACK eliciting, i.e.,
* not "is pure ACK".
* 
* Testing whether a packet is a "pure ACK" involves checking whether
* at least on frame in the packet would solicit an acknowledgement.
* This could be costly.
* 
* We could question whether "pure ACK" packets should placed in the
* retransmitted queue. Keeping them would allow "ack of ack"
* processing in case of spurious repeat.
 */
int picoquic_pto_needed_on_path(picoquic_cnx_t* cnx, picoquic_path_t * path_x,
    uint64_t current_time, uint64_t* next_retransmit_time)
{
    uint64_t retransmit_time = UINT64_MAX;
    int should_retransmit = 0;
    picoquic_packet_t* last_packet = path_x->path_packet_last;

    /* find the "last packet" that is not a pure acknowledgement */
    while (last_packet != NULL) {
        /* Find out whether a packet is ACK soliciting */
        if (!picoquic_is_packet_ack_soliciting(last_packet)){
            last_packet = last_packet->path_packet_previous;
            continue;
        }
    }
    /* If there is no ack soliciting packet in queue, last_packet will be NULL */
    if (last_packet != NULL) {
        retransmit_time = last_packet->send_time + picoquic_current_retransmit_timer(cnx, path_x);
        if (current_time >= retransmit_time) {
            should_retransmit = 1;
            retransmit_time = current_time;
        }
    }
    *next_retransmit_time = retransmit_time;

    return should_retransmit;
}

/* In single path operation, just check the default path.
 * Format a probe packet -- possibly send data from the
 * oldest no acked packet.
 * 
 * The decision to only resend the last packet over a timeout
 * is a tradeoff between delays and efficiency. Resending
 * sooner would result in lower latencies, at a risk of
 * many more spurious retransmissions. We may consider a
 * control variable to pilot that tradeoff.
 */


/* In multipath operation, we may need to check all paths.
 * If a path is PTO eligible, it will be marked as "PTO requested".
 * 
 * The multipath scheduler will avoid sending more data packets
 * on a path subject to timeout loss. When packets are declared lost,
 * the frames in these packets could be resent on any other path.
 * However, the PTO system will only detect these losses when
 * one of the packets is finally acknowledged, or when the path
 * is finally considered broken. This will affect global delays.
 * 
 * If there are other paths available, it might be a good idea
 * to do an opportunistic copy of the last packets onto
 * other paths, without waiting for those packets to be formally
 * declared as lost. Or, these packets could be "presumed lost"
 * after maybe 1 or 2 PTO, so they could be resent on other
 * paths.
 */