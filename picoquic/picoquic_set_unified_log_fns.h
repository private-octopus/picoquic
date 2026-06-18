/*
* Author: OpenMOQ contributors
* Copyright (c) 2026, OpenMOQ contributors
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
* USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef PICOQUIC_SET_UNIFIED_LOG_FNS_H
#define PICOQUIC_SET_UNIFIED_LOG_FNS_H

#include "picoquic.h"
#include "picoquic_unified_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Selector for picoquic_set_unified_log_fns().
 *
 * Picoquic stores three independent slots for unified-log callbacks and
 * dispatches events to every populated slot; clearing one (passing NULL fns)
 * does not affect the others. The built-in backends populate them as follows:
 *
 *   PICOQUIC_LOG_SLOT_TEXT — populated by picoquic_set_textlog()
 *   PICOQUIC_LOG_SLOT_BIN  — populated by picoquic_set_binlog()
 *   PICOQUIC_LOG_SLOT_QLOG — populated by picoquic_set_qlog()
 *
 * A custom backend (e.g. a C++ wrapper routing into a native logging
 * framework) typically takes the TEXT slot, since its purpose
 * ("human-readable per-event log") matches.
 */
typedef enum {
    PICOQUIC_LOG_SLOT_TEXT = 0,
    PICOQUIC_LOG_SLOT_BIN  = 1,
    PICOQUIC_LOG_SLOT_QLOG = 2
} picoquic_log_slot_t;

/* Install a custom unified-log callback struct on the picoquic context.
 *
 * Mirrors what picoquic_set_textlog / set_binlog / set_qlog do for their
 * built-in backends; intended for external consumers who want to implement
 * their own picoquic_unified_logging_t (for example, to route events into
 * a native logging framework such as folly XLOG, glog, or spdlog) without
 * reaching into picoquic_internal.h.
 *
 * The caller retains ownership of fns. picoquic stores the pointer as-is
 * and does not copy or free it, so fns must remain valid for the lifetime
 * of the picoquic context — process-lifetime static storage is the typical
 * pattern (mirroring the built-in textlog_functions / binlog_functions /
 * qlog_fns structs).
 *
 * Pass fns == NULL to clear the slot (e.g. to disable a previously
 * installed custom backend without affecting the others).
 *
 * @param quic the picoquic context (must be non-null)
 * @param slot which slot to populate (TEXT, BIN, or QLOG)
 * @param fns  pointer to the unified logging struct, or NULL to clear
 * @return 0 on success, -1 on invalid arguments
 */
int picoquic_set_unified_log_fns(
    picoquic_quic_t* quic,
    picoquic_log_slot_t slot,
    picoquic_unified_logging_t* fns);

#ifdef __cplusplus
}
#endif

#endif /* PICOQUIC_SET_UNIFIED_LOG_FNS_H */
