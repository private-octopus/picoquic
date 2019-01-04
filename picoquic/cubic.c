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

typedef enum {
    picoquic_cubic_alg_slow_start = 0,
    picoquic_cubic_alg_recovery,
    picoquic_cubic_alg_tcp_friendly,
    picoquic_cubic_alg_congestion_avoidance
} picoquic_cubic_alg_state_t;


typedef struct st_picoquic_cubic_state_t {
    picoquic_cubic_alg_state_t alg_state;
    uint64_t start_of_epoch;
    uint64_t K;
    uint64_t W_max;
    uint64_t W_last_max;
    uint64_t beta_16;
    uint64_t C;
    uint64_t ssthresh;

    uint64_t residual_ack;
} picoquic_cubic_state_t;

void picoquic_cubic_init(picoquic_path_t* path_x)
{
    /* Initialize the state of the congestion control algorithm */
    picoquic_cubic_state_t* cubic_state = (picoquic_cubic_state_t*)malloc(sizeof(picoquic_cubic_state_t));
    path_x->congestion_alg_state = (void*)cubic_state;

    if (path_x->congestion_alg_state != NULL) {
        cubic_state->alg_state = picoquic_cubic_alg_slow_start;
        cubic_state->ssthresh = (uint64_t)((int64_t)-1);
        cubic_state->W_last_max = cubic_state->ssthresh;
        cubic_state->W_max = cubic_state->ssthresh;

        path_x->cwin = PICOQUIC_CWIN_INITIAL;
        cubic_state->residual_ack = 0;
        /* cubic_beta_16 = 7/8 */
        cubic_state->beta_16 = 0xE000;
        cubic_state->start_of_epoch = 0;
    }
}

/* On entering congestion avoidance, need to compute the new coefficients
 * of the cubit curve */
static void picoquic_cubic_enter_avoidance(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{
    cubic_state->alg_state = picoquic_cubic_alg_congestion_avoidance;
    cubic_state->start_of_epoch = current_time;

    /* Compute the new K */
    cubic_state->K = cubic_root(W_max*(1 - beta_cubic) / C);
}

/* The recovery state last 1 RTT, during which parameters will be frozen
 */
static void picoquic_cubic_enter_recovery(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{
    /* Update similar to new reno, but different beta */
    cubic_state->W_max = path_x->cwin;
    /* Apply fast convergence */
    if (cubic_state->W_max < cubic_state->W_last_max) {
        cubic_state->W_last_max = cubic_state->W_max;
        cubic_state->W_max = (cubic_state->W_max * (0x10000 + cubic_state->beta_16) >> 17); // further reduce W_max
    }
    else {
        cubic_state->W_last_max = cubic_state->W_max;
    }
    /* Compute the new ssthresh */
    cubic_state->ssthresh = (cubic_state->W_max * cubic_state->beta_16)>>16;
    if (cubic_state->ssthresh < PICOQUIC_CWIN_MINIMUM) {
        cubic_state->ssthresh = PICOQUIC_CWIN_MINIMUM;
    }

    if (notification == picoquic_congestion_notification_timeout) {
        path_x->cwin = PICOQUIC_CWIN_MINIMUM;
        cubic_state->start_of_epoch = current_time;
        cubic_state->alg_state = picoquic_cubic_alg_slow_start;
    } else {
        path_x->cwin = cubic_state->ssthresh;
        /* Enter congestion avoidance immediately */
        picoquic_cubic_enter_avoidance(path_x, notification, cubic_state, current_time);
    }
}

/* On spurious repeat notification, do something smart. */
static void picoquic_cubic_correct_spurious(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{

}

static void picoquic_cubic_W_cubic(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{
    W_cubic(t) = C * (t - K) ^ 3 + W_max;
}

static void picoquic_cubic_W_est(picoquic_path_t* path_x,
    picoquic_congestion_notification_t notification,
    picoquic_cubic_state_t* cubic_state,
    uint64_t current_time)
{
    W_est(t) = W_max * beta_cubic +
        [3 * (1 - beta_cubic) / (1 + beta_cubic)] * (t / RTT);
}

/*
 * Properly implementing Cubic requires managing a number of
 * signals, such as packet losses or acknowledgements. We attempt
 * to condensate all that in a single API, which could be shared
 * by many different congestion control algorithms.
 */
void picoquic_cubic_notify(picoquic_path_t* path_x,
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
    picoquic_cubic_state_t* cubic_state = (picoquic_cubic_state_t*)path_x->congestion_alg_state;

    if (cubic_state != NULL) {
        switch (cubic_state->alg_state) {
        case picoquic_cubic_alg_slow_start:
            switch (notification) {
            case picoquic_congestion_notification_acknowledgement:
                path_x->cwin += nb_bytes_acknowledged;
                /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                if (path_x->cwin >= cubic_state->ssthresh) {
                    picoquic_cubic_enter_avoidance(path_x, notification, cubic_state, current_time);
                }
                break;
            case picoquic_congestion_notification_repeat:
            case picoquic_congestion_notification_timeout:
                /* enter recovery */
                picoquic_cubic_enter_recovery(path_x, notification, cubic_state, current_time);
                break;
            case picoquic_congestion_notification_spurious_repeat:
                /* Immediately exit the previous recovery */
                if (path_x->cwin < 2 * cubic_state->ssthresh) {
                    path_x->cwin = 2 * cubic_state->ssthresh;
                    cubic_state->alg_state = picoquic_cubic_alg_congestion_avoidance;
                }
                break;
            case picoquic_congestion_notification_rtt_measurement:
                /* TODO: consider using RTT increases as signal to get out of slow start */
                break;
            default:
                /* ignore */
                break;
            }
            break;
        case picoquic_cubic_alg_recovery:
            /* If the notification is coming less than 1RTT after start,
			 * ignore it. */
            if (current_time - cubic_state->start_of_epoch > path_x->rtt_min) {
                switch (notification) {
                case picoquic_congestion_notification_acknowledgement:
                    /* exit recovery, move to CA or SS, depending on CWIN */
                    cubic_state->alg_state = picoquic_cubic_alg_slow_start;
                    path_x->cwin += nb_bytes_acknowledged;
                    /* if cnx->cwin exceeds SSTHRESH, exit and go to CA */
                    if (path_x->cwin >= cubic_state->ssthresh) {
                        cubic_state->alg_state = picoquic_cubic_alg_congestion_avoidance;
                    }
                    break;
                case picoquic_congestion_notification_repeat:
                case picoquic_congestion_notification_timeout:
                    /* re-enter recovery */
                    picoquic_cubic_enter_recovery(path_x, notification, cubic_state, current_time);
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
        case picoquic_cubic_alg_tcp_friendly:
            switch (notification) {
            case picoquic_congestion_notification_acknowledgement: {
                /* Compute the cubic formula */
                /* Compute the w_est formula */
                /* Pick the largest */
                /* if cubic is larger, switch to cubic mode */
                break;
            }
            case picoquic_congestion_notification_repeat:
            case picoquic_congestion_notification_timeout:
                /* re-enter recovery */
                picoquic_cubic_enter_recovery(path_x, notification, cubic_state, current_time);
                break;
            case picoquic_congestion_notification_spurious_repeat:
            case picoquic_congestion_notification_rtt_measurement:
            default:
                /* ignore */
                break;
            }
            break;
        case picoquic_cubic_alg_congestion_avoidance:
            switch (notification) {
            case picoquic_congestion_notification_acknowledgement: {
                /* Compute the cubic formula */
                /* Compute the w_est formula */
                /* Pick the largest */
                break;
            }
            case picoquic_congestion_notification_repeat:
            case picoquic_congestion_notification_timeout:
                /* re-enter recovery */
                picoquic_cubic_enter_recovery(path_x, notification, cubic_state, current_time);
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
void picoquic_cubic_delete(picoquic_path_t* path_x)
{
    if (path_x->congestion_alg_state != NULL) {
        free(path_x->congestion_alg_state);
        path_x->congestion_alg_state = NULL;
    }
}

/* Definition record for the New Reno algorithm */

#define picoquic_cubic_ID 0x43424942 /* CBIC */

picoquic_congestion_algorithm_t picoquic_cubic_algorithm_struct = {
    picoquic_cubic_ID,
    picoquic_cubic_init,
    picoquic_cubic_notify,
    picoquic_cubic_delete
};

picoquic_congestion_algorithm_t* picoquic_cubic_algorithm = &picoquic_cubic_algorithm_struct;
