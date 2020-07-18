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

#include "picoquic_internal.h"
#include <stdlib.h>
#include <string.h>
#include "cc_common.h"


#define FASTCC_MIN_ACK_DELAY_FOR_BANDWIDTH 5000
#define FASTCC_BANDWIDTH_FRACTION 0.5
#define FASTCC_REPEAT_THRESHOLD 4
#define FASTCC_BETA 0.125
#define FASTCC_BETA_HEAVY_LOSS 0.5
#define FASTCC_EVAL_ALPHA 0.25
#define FASTCC_DELAY_THRESHOLD_MAX 25000
#define FASTCC_NB_PERIOD 6
#define FASTCC_PERIOD 1000000


typedef enum {
    picoquic_fastcc_initial = 0,
    picoquic_fastcc_eval,
    picoquic_fastcc_freeze
} picoquic_fastcc_alg_state_t;

typedef struct st_picoquic_fastcc_state_t {
    picoquic_fastcc_alg_state_t alg_state;
    uint64_t end_of_freeze; /* When to exit the freeze state */
    uint64_t last_ack_time;
    uint64_t ack_interval;
    uint64_t nb_bytes_ack;
    uint64_t nb_bytes_ack_since_rtt; /* accumulate byte count until RTT measured */
    uint64_t end_of_epoch;
    uint64_t recovery_sequence;
    uint64_t rtt_min;
    uint64_t delay_threshold;
    uint64_t rolling_rtt_min; /* Min RTT measured for this epoch */
    uint64_t last_rtt_min[FASTCC_NB_PERIOD];
    int nb_cc_events;
    picoquic_min_max_rtt_t rtt_filter;
} picoquic_fastcc_state_t;

uint64_t picoquic_fastcc_delay_threshold(uint64_t rtt_min)
{
    uint64_t delay = rtt_min / 8;
    if (delay > FASTCC_DELAY_THRESHOLD_MAX) {
        delay = FASTCC_DELAY_THRESHOLD_MAX;
    }
    return delay;
}

void picoquic_fastcc_reset(picoquic_fastcc_state_t* fastcc_state, picoquic_path_t* path_x, uint64_t current_time)
{
    memset(fastcc_state, 0, sizeof(picoquic_fastcc_state_t));
    fastcc_state->alg_state = picoquic_fastcc_initial;
    fastcc_state->rtt_min = path_x->smoothed_rtt;
    fastcc_state->rolling_rtt_min = fastcc_state->rtt_min;
    fastcc_state->delay_threshold = picoquic_fastcc_delay_threshold(fastcc_state->rtt_min);
    fastcc_state->end_of_epoch = current_time + FASTCC_PERIOD;
    path_x->cwin = PICOQUIC_CWIN_INITIAL;
}

void picoquic_fastcc_init(picoquic_path_t* path_x, uint64_t current_time)
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_fastcc_state_t* fastcc_state = path_x->congestion_alg_state;
    
    if (fastcc_state == NULL) {
        fastcc_state = (picoquic_fastcc_state_t*)malloc(sizeof(picoquic_fastcc_state_t));
    }
    
    if (fastcc_state != NULL) {
        memset(fastcc_state, 0, sizeof(picoquic_fastcc_state_t));
        memset(fastcc_state, 0, sizeof(picoquic_fastcc_state_t));
        fastcc_state->alg_state = picoquic_fastcc_initial;
        fastcc_state->rtt_min = path_x->smoothed_rtt;
        fastcc_state->rolling_rtt_min = fastcc_state->rtt_min;
        fastcc_state->delay_threshold = picoquic_fastcc_delay_threshold(fastcc_state->rtt_min);
        fastcc_state->end_of_epoch = current_time + FASTCC_PERIOD;
        path_x->cwin = PICOQUIC_CWIN_INITIAL;
    }

    path_x->congestion_alg_state = (void*)fastcc_state;
}

static void fastcc_shrink_on_event(picoquic_cnx_t* cnx,
    picoquic_path_t* path_x, picoquic_fastcc_state_t* fastcc_state, 
    int is_heavy_loss, uint64_t current_time)
{
    if (fastcc_state->alg_state != picoquic_fastcc_freeze) {
        fastcc_state->alg_state = picoquic_fastcc_freeze;
        fastcc_state->end_of_freeze = current_time + fastcc_state->rtt_min;
        fastcc_state->recovery_sequence = picoquic_cc_get_sequence_number(cnx);
        if (is_heavy_loss) {
            path_x->cwin -= (uint64_t)(FASTCC_BETA_HEAVY_LOSS * (double)path_x->cwin);
        }
        else {
            path_x->cwin -= (uint64_t)(FASTCC_BETA * (double)path_x->cwin);
        }
        if (path_x->cwin < PICOQUIC_CWIN_MINIMUM) {
            path_x->cwin = PICOQUIC_CWIN_MINIMUM;
        }
        picoquic_update_pacing_data(cnx, path_x, 0);
    }
}

static void fastcc_process_cc_event(picoquic_cnx_t * cnx, 
    picoquic_path_t* path_x, picoquic_fastcc_state_t* fastcc_state, uint64_t current_time)
{
    fastcc_state->nb_cc_events++;
    if (fastcc_state->nb_cc_events >= FASTCC_REPEAT_THRESHOLD) {
        /* Too many events, reduce the window */
        fastcc_shrink_on_event(cnx, path_x, fastcc_state, 0, current_time);
    }
}


/*
 * Properly implementing fastcc requires managing a number of
 * signals, such as packet losses or acknowledgements. We attempt
 * to condensate all that in a single API, which could be shared
 * by many different congestion control algorithms.
 */
void picoquic_fastcc_notify(
    picoquic_cnx_t* cnx, picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    uint64_t rtt_measurement,
    uint64_t one_way_delay,
    uint64_t nb_bytes_acknowledged,
    uint64_t lost_packet_number,
    uint64_t current_time)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(lost_packet_number);
#endif
    picoquic_fastcc_state_t* fastcc_state = (picoquic_fastcc_state_t*)path_x->congestion_alg_state;

    if (fastcc_state != NULL) {
        if (fastcc_state->alg_state == picoquic_fastcc_freeze && 
            (current_time > fastcc_state->end_of_freeze ||
                fastcc_state->recovery_sequence <= picoquic_cc_get_ack_number(cnx))) {
            fastcc_state->alg_state = picoquic_fastcc_eval;
            fastcc_state->nb_cc_events = 0;
            fastcc_state->nb_bytes_ack_since_rtt = 0;
        }

        switch (notification) {
        case picoquic_congestion_notification_acknowledgement: 
            if (fastcc_state->alg_state != picoquic_fastcc_freeze) {
                /* Count the bytes since last RTT measurement */
                fastcc_state->nb_bytes_ack_since_rtt += nb_bytes_acknowledged;
                /* Compute pacing data. */
                picoquic_update_pacing_data(cnx, path_x, 0);
            }
            break;  
        case picoquic_congestion_notification_ecn_ec:
            if (fastcc_state->alg_state != picoquic_fastcc_freeze &&
                cnx->cnx_state >= picoquic_state_ready) {
                /* Count ECN as maybe cc events */
                fastcc_process_cc_event(cnx, path_x, fastcc_state, current_time);
            }
            break;
        case picoquic_congestion_notification_repeat:
        case picoquic_congestion_notification_timeout:
            if (fastcc_state->alg_state != picoquic_fastcc_freeze) {
                if (cnx->cnx_state >= picoquic_state_ready &&
                    picoquic_hystart_loss_test(&fastcc_state->rtt_filter, notification, lost_packet_number)) {
                    fastcc_shrink_on_event(cnx, path_x, fastcc_state, 1, current_time);
                }
                else {
                    /* Count packet losses as maybe cc events */
                    fastcc_process_cc_event(cnx, path_x, fastcc_state, current_time);
                }
            }
            break;
        case picoquic_congestion_notification_spurious_repeat:
            if (fastcc_state->nb_cc_events > 0) {
                fastcc_state->nb_cc_events--;
            }
            break;
        case picoquic_congestion_notification_rtt_measurement:
        {
            uint64_t delta_rtt = 0;

            picoquic_filter_rtt_min_max(&fastcc_state->rtt_filter, rtt_measurement);

            if (fastcc_state->rtt_filter.is_init) {
                /* We use the maximum of the last samples as the candidate for the
                 * min RTT, in order to filter the rtt jitter */
                if (current_time > fastcc_state->end_of_epoch) {
                    /* If end of epoch, reset the min RTT to min of remembered periods,
                     * and roll the period. */
                    fastcc_state->rtt_min = (uint64_t)((int64_t)-1);
                    for (int i = FASTCC_NB_PERIOD - 1; i > 0; i--) {
                        fastcc_state->last_rtt_min[i] = fastcc_state->last_rtt_min[i - 1];
                        if (fastcc_state->last_rtt_min[i] > 0 &&
                            fastcc_state->last_rtt_min[i] < fastcc_state->rtt_min) {
                            fastcc_state->rtt_min = fastcc_state->last_rtt_min[i];
                        }
                    }
                    fastcc_state->delay_threshold = picoquic_fastcc_delay_threshold(fastcc_state->rtt_min);
                    fastcc_state->last_rtt_min[0] = fastcc_state->rolling_rtt_min;
                    fastcc_state->rolling_rtt_min = fastcc_state->rtt_filter.sample_max;
                    fastcc_state->end_of_epoch = current_time + FASTCC_PERIOD;
                }
                else if (fastcc_state->rtt_filter.sample_max < fastcc_state->rolling_rtt_min || fastcc_state->rolling_rtt_min == 0) {
                    /* If not end of epoch, update the rolling minimum */
                    fastcc_state->rolling_rtt_min = fastcc_state->rtt_filter.sample_max;
                    if (fastcc_state->rolling_rtt_min < fastcc_state->rtt_min) {
                        fastcc_state->rtt_min = fastcc_state->rolling_rtt_min;
                    }
                }
            }

            if (fastcc_state->alg_state != picoquic_fastcc_freeze) {
                if (rtt_measurement < fastcc_state->rtt_min) {
                    fastcc_state->delay_threshold = picoquic_fastcc_delay_threshold(fastcc_state->rtt_min);
                }
                else {
                    delta_rtt = rtt_measurement - fastcc_state->rtt_min;
                }

                if (delta_rtt < fastcc_state->delay_threshold) {
                    double alpha = 1.0;
                    fastcc_state->nb_cc_events = 0;

                    if (fastcc_state->alg_state != picoquic_fastcc_initial) {
                        alpha -= ((double)delta_rtt / (double)fastcc_state->delay_threshold);
                        alpha *= FASTCC_EVAL_ALPHA;
                    }

                    /* Increase the window if it is not frozen */
                    if (path_x->last_time_acked_data_frame_sent > path_x->last_sender_limited_time) {
                        path_x->cwin += (uint64_t)(alpha * (double)fastcc_state->nb_bytes_ack_since_rtt);
                    }
                    fastcc_state->nb_bytes_ack_since_rtt = 0;
                }
                else {
                    /* May well be congested */
                    fastcc_process_cc_event(cnx, path_x, fastcc_state, current_time);
                }
            }
        }
        break;
        case picoquic_congestion_notification_cwin_blocked:
            break;
        case picoquic_congestion_notification_reset:
            picoquic_fastcc_reset(fastcc_state, path_x, current_time);
            break;
        default:
            /* ignore */
            break;
        }
    }
}

/* Release the state of the congestion control algorithm */
void picoquic_fastcc_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}


/* Observe the state of congestion control */

void picoquic_fastcc_observe(picoquic_path_t* path_x, uint64_t* cc_state, uint64_t* cc_param)
{
    picoquic_fastcc_state_t* fastcc_state = (picoquic_fastcc_state_t*)path_x->congestion_alg_state;
    *cc_state = (uint64_t)fastcc_state->alg_state;
    *cc_param = fastcc_state->rolling_rtt_min;
}

/* Definition record for the FAST CC algorithm */

#define picoquic_fastcc_ID "fast" 

picoquic_congestion_algorithm_t picoquic_fastcc_algorithm_struct = {
    picoquic_fastcc_ID, 4,
    picoquic_fastcc_init,
    picoquic_fastcc_notify,
    picoquic_fastcc_delete,
    picoquic_fastcc_observe
};

picoquic_congestion_algorithm_t* picoquic_fastcc_algorithm = &picoquic_fastcc_algorithm_struct;
