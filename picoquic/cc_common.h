/*
* Author: Christian Huitema
* Copyright (c) 2019, Private Octopus, Inc.
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

#ifndef CC_COMMON_H
#define CC_COMMON_H

#define PICOQUIC_MIN_MAX_RTT_SCOPE 7

typedef struct st_picoquic_min_max_rtt_t {
    uint64_t last_rtt_sample_time;
    uint64_t rtt_filtered_min;
    int nb_rtt_excess;
    int sample_current;
    int is_init;
    int past_threshold;
    int threshold_count;
    uint64_t sample_min;
    uint64_t sample_max;
    uint64_t samples[PICOQUIC_MIN_MAX_RTT_SCOPE];
} picoquic_min_max_rtt_t;

uint64_t picoquic_cc_get_sequence_number(picoquic_cnx_t* cnx);

uint64_t picoquic_cc_get_ack_number(picoquic_cnx_t* cnx);

void picoquic_filter_rtt_min_max(picoquic_min_max_rtt_t* rtt_track, uint64_t rtt);

int picoquic_hystart_test(picoquic_min_max_rtt_t* rtt_track, uint64_t rtt_measurement, uint64_t packet_time, uint64_t current_time, int is_one_way_delay_enabled);

void picoquic_hystart_increase(picoquic_path_t* path_x, picoquic_min_max_rtt_t* rtt_filter, uint64_t nb_delivered);

int picoquic_cc_was_cwin_blocked(picoquic_cnx_t* cnx, uint64_t last_sequence_blocked);

#endif