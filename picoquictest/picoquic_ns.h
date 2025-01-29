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

#ifndef PICOQUIC_NS_H
#define PICOQUIC_NS_H

/* Simple picoquic simulation.
* The implementation depends on the libraries:
*  - picoquic-core
*  - picoquic-log
*  - picohttp-core
*  - picoquic-test
 */

#include <picoquic.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_picoquic_ns_spec_t {
    uint64_t main_start_time;
    uint64_t main_target_time;
    uint64_t background_start_time;
    const char* main_scenario_text;
    const char* background_scenario_text;
    picoquic_congestion_algorithm_t* main_cc_algo;
    picoquic_congestion_algorithm_t* background_cc_algo;
    int nb_connections;
    double data_rate_in_gbps; /* datarate, server to clients, defaults to 10 mbps */
    uint64_t latency; /* one way latency, microseconds, both directions */
    uint64_t jitter; /* delay jitter, microseconds, both directions */
    uint64_t queue_delay_max; /* if specified, specify the max buffer queuing for the link, in microseconds */
    uint64_t l4s_max; /* if specified, specify the max buffer queuing for the link, in microseconds */
    picoquic_connection_id_t icid; /* if specified, set the ICID of connections. Last byte will be overwriten by connection number */
    char const* qlog_dir; /* if specified, set the qlog directory, and request qlog traces. */
} picoquic_ns_spec_t;

int picoquic_ns(picoquic_ns_spec_t* spec);

#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_NS_H */