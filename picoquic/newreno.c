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
#include <stdlib.h>

typedef enum {
    picoquic_newreno_alg_slow_start = 0,
    picoquic_newreno_alg_recovery,
    picoquic_newreno_alg_congestion_avoidance
} picoquic_newreno_alg_state_t;

typedef struct st_picoquic_newreno_state_t {
    picoquic_newreno_alg_state_t alg_state;
    uint64_t residual_ack;
    uint64_t ssthresh;
    uint64_t recovery_start;
} picoquic_newreno_state_t;

void picoquic_newreno_init(picoquic_path_t* path_x)
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_newreno_state_t* nr_state = (picoquic_newreno_state_t*)malloc(sizeof(picoquic_newreno_state_t));
    path_x->congestion_alg_state = (void*)nr_state;

    if (path_x->congestion_alg_state != NULL) {
        nr_state->alg_state = picoquic_newreno_alg_slow_start;
        nr_state->ssthresh = (uint64_t)((int64_t)-1);
        path_x->cwin = PICOQUIC_CWIN_INITIAL;
        nr_state->residual_ack = 0;
    }
}

/* The recovery state last 1 RTT, during which parameters will be frozen
 */
static void picoquic_newreno_enter_recovery(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_newreno_state_t* nr_state,
    uint64_t current_time)
{
    nr_state->ssthresh = path_x->cwin / 2;
    if (nr_state->ssthresh < PICOQUIC_CWIN_MINIMUM) {
        nr_state->ssthresh = PICOQUIC_CWIN_MINIMUM;
    }

    if (notification == picoquic_congestion_notification_timeout) {
        path_x->cwin = PICOQUIC_CWIN_MINIMUM;
    } else {
        path_x->cwin = nr_state->ssthresh;
    }

    nr_state->recovery_start = current_time;

    nr_state->residual_ack = 0;

    nr_state->alg_state = picoquic_newreno_alg_recovery;
}

/*
 * Properly implementing New Reno requires managing a number of
 * signals, such as packet losses or acknowledgements. We attempt
 * to condensate all that in a single API, which could be shared
 * by many different congestion control algorithms.
 */
void picoquic_newreno_notify(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    uint64_t rtt_measurement,
    uint64_t nb_bytes_acknowledged,
    uint64_t lost_packet_number,
    uint64_t current_time)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(rtt_measurement);
    UNREFERENCED_PARAMETER(lost_packet_number);
#endif
    picoquic_newreno_state_t* nr_state = (picoquic_newreno_state_t*)path_x->congestion_alg_state;

    if (nr_state != NULL) {
        switch (nr_state->alg_state) {
        case picoquic_newreno_alg_slow_start:
            switch (notification) {
            case picoquic_congestion_notification_acknowledgement:
                path_x->cwin += nb_bytes_acknowledged;
                /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                if (path_x->cwin >= nr_state->ssthresh) {
                    nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
                }
                break;
            case picoquic_congestion_notification_repeat:
            case picoquic_congestion_notification_timeout:
                /* enter recovery */
                picoquic_newreno_enter_recovery(path_x, notification, nr_state, current_time);
                break;
            case picoquic_congestion_notification_spurious_repeat:
                break;
            case picoquic_congestion_notification_rtt_measurement:
                /* TODO: consider using RTT increases as signal to get out of slow start */
                break;
            default:
                /* ignore */
                break;
            }
            break;
        case picoquic_newreno_alg_recovery:
            /* If the notification is coming less than 1RTT after start,
			 * ignore it. */
            if (current_time - nr_state->recovery_start > path_x->rtt_min) {
                switch (notification) {
                case picoquic_congestion_notification_acknowledgement:
                    /* exit recovery, move to CA or SS, depending on CWIN */
                    nr_state->alg_state = picoquic_newreno_alg_slow_start;
                    path_x->cwin += nb_bytes_acknowledged;
                    /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                    if (path_x->cwin >= nr_state->ssthresh) {
                        nr_state->alg_state = picoquic_newreno_alg_congestion_avoidance;
                    }
                    break;
                case picoquic_congestion_notification_repeat:
                case picoquic_congestion_notification_timeout:
                    /* re-enter recovery */
                    picoquic_newreno_enter_recovery(path_x, notification, nr_state, current_time);
                    break;
                case picoquic_congestion_notification_spurious_repeat:
                    /* To do: if spurious repeat of initial loss detected,
					 * exit recovery and reset threshold to pre-entry cwin.
					 */
                    break;
                case picoquic_congestion_notification_rtt_measurement:
                default:
                    /* ignore */
                    break;
                }
            }
            break;
        case picoquic_newreno_alg_congestion_avoidance:
            switch (notification) {
            case picoquic_congestion_notification_acknowledgement: {
                uint64_t complete_ack = nb_bytes_acknowledged + nr_state->residual_ack;
                nr_state->residual_ack = complete_ack % path_x->cwin;
                path_x->cwin += complete_ack / path_x->cwin;
                break;
            }
            case picoquic_congestion_notification_repeat:
            case picoquic_congestion_notification_timeout:
                /* re-enter recovery */
                picoquic_newreno_enter_recovery(path_x, notification, nr_state, current_time);
                break;
            case picoquic_congestion_notification_spurious_repeat:
            case picoquic_congestion_notification_rtt_measurement:
            default:
                /* ignore */
                break;
            }
            break;
        default:
            break;
        }

        /* Compute pacing data */
        picoquic_update_pacing_data(path_x);
    }
}

/* Release the state of the congestion control algorithm */
void picoquic_newreno_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}

/* Definition record for the New Reno algorithm */

#define PICOQUIC_NEWRENO_ID 0x4E523838 /* NR88 */

picoquic_congestion_algorithm_t picoquic_newreno_algorithm_struct = {
    PICOQUIC_NEWRENO_ID,
    picoquic_newreno_init,
    picoquic_newreno_notify,
    picoquic_newreno_delete
};

picoquic_congestion_algorithm_t* picoquic_newreno_algorithm = &picoquic_newreno_algorithm_struct;
