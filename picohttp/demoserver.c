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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#ifdef _WINDOWS
#include "wincompat.h"
#include "ws2ipdef.h"
#pragma warning(disable:4100)
#endif
#include "picoquic_internal.h"
#include "h3zero.h"
#include "h09_server.h"
#include "democlient.h"
#include "demoserver.h"
#include "quicperf.h"

/* Callback from the TLS stack upon receiving a list of proposed ALPN in the Client Hello */
size_t picoquic_demo_server_callback_select_alpn(picoquic_quic_t* quic, picoquic_iovec_t* list, size_t count)
{
    size_t ret = count;
    picoquic_alpn_enum alpn_code = picoquic_alpn_undef;
    picoquic_cnx_t* cnx = quic->cnx_in_progress;

    for (size_t i = 0; i < count; i++) {
        if ((alpn_code = picoquic_parse_alpn_nz((const char *)list[i].base, list[i].len)) != picoquic_alpn_undef) {
            ret = i;
            break;
        }
    }

    if (alpn_code != picoquic_alpn_undef && cnx != NULL) {
        void* default_callback_ctx = picoquic_get_default_callback_context(quic);
        switch (alpn_code) {
        case picoquic_alpn_http_3:
            picoquic_set_callback(cnx, h3zero_callback, default_callback_ctx);
            break;
        case picoquic_alpn_quicperf:
            picoquic_set_callback(cnx, quicperf_callback, default_callback_ctx);
            break;
        case picoquic_alpn_http_0_9:
            picoquic_set_callback(cnx, picoquic_h09_server_callback, default_callback_ctx);
            break;
        default:
            break;
        }
    }

    return ret;
}
