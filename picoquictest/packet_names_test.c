/*
* Author: Christian Huitema
* Copyright (c) 2026, Private Octopus, Inc.
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

#include "picoquic.h"
#include "picoquic_internal.h"
#include "picoquic_utils.h"
#include <string.h>

/* picoquic_packet_type_name is only reached, in the existing test suite, through qlog
 * output for the packet types that actually appear on the wire in normal connections
 * (initial, handshake, 0RTT, 1RTT) -- never for the internal-only "error" placeholder,
 * for version negotiation or retry packets logged by every scenario, nor for the
 * "scone"/"type_max" values. Call it directly for every enum value plus one out-of-range
 * value, checking that each case returns a distinct, non-NULL string. */
int packet_names_test(void)
{
    int ret = 0;
    const picoquic_packet_type_enum ptypes[] = {
        picoquic_packet_error,
        picoquic_packet_version_negotiation,
        picoquic_packet_initial,
        picoquic_packet_retry,
        picoquic_packet_handshake,
        picoquic_packet_0rtt_protected,
        picoquic_packet_1rtt_protected,
        picoquic_packet_scone,
        picoquic_packet_type_max
    };
    const char* names[sizeof(ptypes) / sizeof(picoquic_packet_type_enum)];
    size_t nb_ptypes = sizeof(ptypes) / sizeof(picoquic_packet_type_enum);

    for (size_t i = 0; ret == 0 && i < nb_ptypes; i++) {
        names[i] = picoquic_packet_type_name((uint64_t)ptypes[i]);
        if (names[i] == NULL) {
            DBG_PRINTF("picoquic_packet_type_name(%d) returned NULL", (int)ptypes[i]);
            ret = -1;
        }
        for (size_t j = 0; ret == 0 && j < i; j++) {
            if (strcmp(names[i], names[j]) == 0) {
                DBG_PRINTF("picoquic_packet_type_name(%d) and (%d) both return \"%s\"",
                    (int)ptypes[i], (int)ptypes[j], names[i]);
                ret = -1;
            }
        }
    }

    if (ret == 0) {
        /* Out of range value should fall to the same "unknown" default as type_max. */
        const char* out_of_range = picoquic_packet_type_name((uint64_t)picoquic_packet_type_max + 1);
        const char* at_max = picoquic_packet_type_name((uint64_t)picoquic_packet_type_max);
        if (out_of_range == NULL || strcmp(out_of_range, at_max) != 0) {
            DBG_PRINTF("%s", "picoquic_packet_type_name did not treat an out-of-range value as unknown");
            ret = -1;
        }
    }

    return ret;
}
