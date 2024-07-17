/*
* Author: Christian Huitema
* Copyright (c) 2024, Private Octopus, Inc.
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

#ifndef PICOMASK_H
#define PICOMASK_H

#include "picohash.h"
#include "picoquic.h"
#include "picoquic_utils.h"

/*
* Context is split between two levels:
* - The global context of the picomask service, which
*   holds for example the list of all connection contexts,
*   the global list of incoming VCID, etc.
* - The per connection entry, which holds the state
*   and the queue of packets for a given connect-udp
*   connection.
* The global context is initialized when starting the
* service.
*/


typedef struct st_picomask_ctx_t {
    picohash_table* table_udp_ctx;
    uint64_t picomask_number_next;

} picomask_ctx_t;

typedef struct st_picomask_cnx_ctx_t {
    picohash_item hash_item;
    uint64_t picomask_number;
    picoquic_cnx_t* cnx;
    uint64_t stream_id;
    struct sockaddr_storage target_addr;

    /* Management of capsule protocol on control stream */

} picomask_cnx_ctx_t;

#endif /* PICOMASK_H */
