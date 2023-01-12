/*
* Author: Christian Huitema
* Copyright (c) 2023, Private Octopus, Inc.
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

/*
 * Web Transport API implementation for Picoquic.
 * 
 * Architecture:
 * 
 *    -- quic events generate picoquic callbacks.
 *    -- web transport state established when processing CONNECT
 *    -- web transport intercepts related callbacks:
 *        -- incoming unidir streams starting with specified frame
 *        -- incoming bidir streams starting with specified frame
 *        -- datagrams starting with specified ID
 *    -- mapping of picoquic callbacks to WT callbacks
 * 
 */

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <picoquic.h>
#include "picoquic_internal.h"
#include "pico_webtransport.h"

void picowt_register(picoquic_quic_t* quic, const char* uri, picowt_ready_cb_fn wt_callback, void* wt_ctx)
{
    /* Add the uri to a registry list in the quic or w3 context. */
}