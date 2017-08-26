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

typedef enum
{
	picoquic_newreno_alg_not_initialized = 0,
	picoquic_newreno_alg_slow_start,
	picoquic_newreno_alg_recovery,
	picoquic_newreno_alg_congestion_avoidance
} picoquic_newreno_alg_state_t;

typedef struct st_picoquic_newreno_state_t {
	picoquic_newreno_alg_state_t alg_state;

} picoquic_newreno_state_t;

void picoquic_newreno_init(picoquic_cnx_t * cnx)
{
	/* Initialize the state of the congestion control algorithm */
}

/*
 * Properly implementing New Reno requires managing a number of
 * signals, such as packet losses or acknowledgements. We attempt
 * to condensate all that in a single API, which could be shared
 * by many different congestion control algorithms.
 */
void picoquic_newreno_ack(picoquic_cnx_t * cnx,
	uint64_t rtt_measurement,
	uint64_t nb_bytes_acknowledged,
	uint64_t lost_packet_number,
	int timer_fired)
{
	/* Initialize the state of the congestion control algorithm */
}