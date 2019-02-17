#include "picoquic.h"
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
#include "tls_api.h"
#include <stdlib.h>
#include <string.h>
#ifndef _WINDOWS
#include <sys/time.h>
#endif


/*
* Structures used in the hash table of connections
*/
typedef struct st_picoquic_cnx_id_key_t {
    picoquic_connection_id_t cnx_id;
    picoquic_cnx_t* cnx;
    picoquic_path_t* path;
    struct st_picoquic_cnx_id_key_t* next_cnx_id;
} picoquic_cnx_id_key_t;

typedef struct st_picoquic_net_id_key_t {
    struct sockaddr_storage saddr;
    picoquic_cnx_t* cnx;
    picoquic_path_t* path;
    struct st_picoquic_net_id_key_t* next_net_id;
} picoquic_net_id_key_t;

/* Hash and compare for CNX hash tables */
static uint64_t picoquic_cnx_id_hash(void* key)
{
    picoquic_cnx_id_key_t* cid = (picoquic_cnx_id_key_t*)key;

    /* TODO: should scramble the value for security and DOS protection */
    return picoquic_val64_connection_id(cid->cnx_id);
}

static int picoquic_cnx_id_compare(void* key1, void* key2)
{
    picoquic_cnx_id_key_t* cid1 = (picoquic_cnx_id_key_t*)key1;
    picoquic_cnx_id_key_t* cid2 = (picoquic_cnx_id_key_t*)key2;

    return picoquic_compare_connection_id(&cid1->cnx_id, &cid2->cnx_id);
}

static uint64_t picoquic_net_id_hash(void* key)
{
    picoquic_net_id_key_t* net = (picoquic_net_id_key_t*)key;

    return picohash_bytes((uint8_t*)&net->saddr, sizeof(net->saddr));
}

static int picoquic_net_id_compare(void* key1, void* key2)
{
    picoquic_net_id_key_t* net1 = (picoquic_net_id_key_t*)key1;
    picoquic_net_id_key_t* net2 = (picoquic_net_id_key_t*)key2;

    return memcmp(&net1->saddr, &net2->saddr, sizeof(net1->saddr));
}

#if 0
/* Not used yet, should be used in ordering connections by wake time. */
static int picoquic_compare_cnx_waketime(void * v_cnxleft, void * v_cnxright) {
    /* Example:  return *((int*)l) - *((int*)r); */
    int ret = 0;
    if (v_cnxleft != v_cnxright) {
        picoquic_cnx_t * cnx_l = (picoquic_cnx_t *)v_cnxleft;
        picoquic_cnx_t * cnx_r = (picoquic_cnx_t *)v_cnxright;

        if (cnx_l->next_wake_time > cnx_r->next_wake_time) {
            ret = 1;
        }
        else if (cnx_l->next_wake_time < cnx_r->next_wake_time) {
            ret = -1;
        }
        else {
            if (((intptr_t)v_cnxleft) > ((intptr_t)v_cnxright)) {
                ret = 1;
            }
            else {
                ret = -1;
            }
        }
    }
    return ret;
}
#endif

picoquic_packet_context_enum picoquic_context_from_epoch(int epoch)
{
    static picoquic_packet_context_enum const pc[4] = {
        picoquic_packet_context_initial,
        picoquic_packet_context_application,
        picoquic_packet_context_handshake,
        picoquic_packet_context_application
    };

    return (epoch >= 0 && epoch < 4) ? pc[epoch] : 0;
}

/*
 * Supported versions. Specific versions may mandate different processing of different
 * formats.
 * The first version in the list is the preferred version.
 * The protection of clear text packets will be a function of the version negotiation.
 */

static uint8_t picoquic_cleartext_internal_test_1_salt[] = {
    0x30, 0x67, 0x16, 0xd7, 0x63, 0x75, 0xd5, 0x55,
    0x4b, 0x2f, 0x60, 0x5e, 0xef, 0x78, 0xd8, 0x33,
    0x3d, 0xc1, 0xca, 0x36
};

static uint8_t picoquic_cleartext_draft_17_salt[] = {
     0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4,
     0x1b, 0xef, 0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae,
     0x48, 0x5e, 0x09, 0xa0
};

/* Support for draft 13! */
const picoquic_version_parameters_t picoquic_supported_versions[] = {
    { PICOQUIC_INTERNAL_TEST_VERSION_2,
        picoquic_version_header_17,
        sizeof(picoquic_cleartext_internal_test_1_salt),
        picoquic_cleartext_internal_test_1_salt },
    { PICOQUIC_INTERNAL_TEST_VERSION_1,
        picoquic_version_header_17,
        sizeof(picoquic_cleartext_internal_test_1_salt),
        picoquic_cleartext_internal_test_1_salt },
    { PICOQUIC_ELEVENTH_INTEROP_VERSION,
        picoquic_version_header_17,
        sizeof(picoquic_cleartext_draft_17_salt),
        picoquic_cleartext_draft_17_salt },
    { PICOQUIC_TENTH_INTEROP_VERSION,
        picoquic_version_header_17,
        sizeof(picoquic_cleartext_draft_17_salt),
        picoquic_cleartext_draft_17_salt }
};

const size_t picoquic_nb_supported_versions = sizeof(picoquic_supported_versions) / sizeof(picoquic_version_parameters_t);


/* QUIC context create and dispose */
picoquic_quic_t* picoquic_create(uint32_t nb_connections,
    char const* cert_file_name,
    char const* key_file_name, 
    char const * cert_root_file_name,
    char const* default_alpn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    cnx_id_cb_fn cnx_id_callback,
    void* cnx_id_callback_ctx,
    uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    uint64_t current_time,
    uint64_t* p_simulated_time,
    char const* ticket_file_name,
    const uint8_t* ticket_encryption_key,
    size_t ticket_encryption_key_length)
{
    picoquic_quic_t* quic = (picoquic_quic_t*)malloc(sizeof(picoquic_quic_t));
    int ret = 0;

    if (quic != NULL) {
        /* TODO: winsock init */
        /* TODO: open UDP sockets - maybe */
        memset(quic, 0, sizeof(picoquic_quic_t));

        quic->default_callback_fn = default_callback_fn;
        quic->default_callback_ctx = default_callback_ctx;
        quic->default_congestion_alg = PICOQUIC_DEFAULT_CONGESTION_ALGORITHM;
        quic->default_alpn = picoquic_string_duplicate(default_alpn);
        quic->cnx_id_callback_fn = cnx_id_callback;
        quic->cnx_id_callback_ctx = cnx_id_callback_ctx;
        quic->p_simulated_time = p_simulated_time;
        quic->local_ctx_length = 8; /* TODO: should be lower on clients-only implementation */
        quic->padding_multiple_default = 0; /* TODO: consider default = 128 */
        quic->padding_minsize_default = PICOQUIC_RESET_PACKET_MIN_SIZE;

        if (cnx_id_callback != NULL) {
            quic->flags |= picoquic_context_unconditional_cnx_id;
        }

        if (ticket_file_name != NULL) {
            quic->ticket_file_name = ticket_file_name;
            ret = picoquic_load_tickets(&quic->p_first_ticket, current_time, ticket_file_name);

            if (ret == PICOQUIC_ERROR_NO_SUCH_FILE) {
                DBG_PRINTF("Ticket file <%s> not created yet.\n", ticket_file_name);
                ret = 0;
            }
            else if (ret != 0) {
                DBG_PRINTF("Cannot load tickets from <%s>\n", ticket_file_name);
            }
        }

        if (ret == 0) {
            quic->table_cnx_by_id = picohash_create(nb_connections * 4,
                picoquic_cnx_id_hash, picoquic_cnx_id_compare);

            quic->table_cnx_by_net = picohash_create(nb_connections * 4,
                picoquic_net_id_hash, picoquic_net_id_compare);

            if (quic->table_cnx_by_id == NULL || quic->table_cnx_by_net == NULL) {
                ret = -1;
                DBG_PRINTF("%s", "Cannot initialize hash tables\n");
            }
            else if (picoquic_master_tlscontext(quic, cert_file_name, key_file_name, cert_root_file_name, ticket_encryption_key, ticket_encryption_key_length) != 0) {
                ret = -1;
                DBG_PRINTF("%s", "Cannot create TLS context \n");
            }
            else {
                /* the random generator was initialized as part of the TLS context.
                 * Use it to create the seed for generating the per context stateless
                 * resets. */

                if (!reset_seed)
                    picoquic_crypto_random(quic, quic->reset_seed, sizeof(quic->reset_seed));
                else
                    memcpy(quic->reset_seed, reset_seed, sizeof(quic->reset_seed));
            }
        }
        
        if (ret != 0) {
            picoquic_free(quic);
            quic = NULL;
        }
    }

    return quic;
}

int picoquic_load_token_file(picoquic_quic_t* quic, char const * token_file_name)
{
    uint64_t current_time = picoquic_get_quic_time(quic);
    int ret = picoquic_load_tokens(&quic->p_first_token, current_time, token_file_name);

    if (ret == PICOQUIC_ERROR_NO_SUCH_FILE) {
        DBG_PRINTF("Ticket file <%s> not created yet.\n", token_file_name);
        ret = 0;
    }
    else if (ret != 0) {
        DBG_PRINTF("Cannot load tickets from <%s>\n", token_file_name);
    }

    if (ret == 0) {
        quic->token_file_name = token_file_name;
    }

    return ret;
}

int picoquic_set_default_tp(picoquic_quic_t* quic, picoquic_tp_t * tp)
{
    int ret = 0;

    if (quic->default_tp == NULL) {
        quic->default_tp = (picoquic_tp_t *)malloc(sizeof(picoquic_tp_t));
    }

    if (quic->default_tp == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memcpy(quic->default_tp, tp, sizeof(picoquic_tp_t));
    }

    return ret;
}

void picoquic_set_default_padding(picoquic_quic_t* quic, uint32_t padding_multiple, uint32_t padding_minsize)
{
    quic->padding_minsize_default = padding_minsize;
    quic->padding_multiple_default = padding_multiple;
}

void picoquic_set_default_spinbit_policy(picoquic_quic_t * quic, picoquic_spinbit_version_enum default_spinbit_policy)
{
    quic->default_spin_policy = default_spinbit_policy;
}

void picoquic_free(picoquic_quic_t* quic)
{
    if (quic != NULL) {
        if (quic->aead_encrypt_ticket_ctx != NULL) {
            picoquic_aead_free(quic->aead_encrypt_ticket_ctx);
            quic->aead_encrypt_ticket_ctx = NULL;
        }

        if (quic->aead_decrypt_ticket_ctx != NULL) {
            picoquic_aead_free(quic->aead_decrypt_ticket_ctx);
            quic->aead_decrypt_ticket_ctx = NULL;
        }

        if (quic->default_alpn != NULL) {
            free((void*)quic->default_alpn);
            quic->default_alpn = NULL;
        }

        /* delete the stored tickets */
        picoquic_free_tickets(&quic->p_first_ticket);

        /* delete all pending packets */
        while (quic->pending_stateless_packet != NULL) {
            picoquic_stateless_packet_t* to_delete = quic->pending_stateless_packet;
            quic->pending_stateless_packet = to_delete->next_packet;
            free(to_delete);
        }

        /* delete all the connection contexts */
        while (quic->cnx_list != NULL) {
            picoquic_delete_cnx(quic->cnx_list);
        }

        if (quic->table_cnx_by_id != NULL) {
            picohash_delete(quic->table_cnx_by_id, 1);
        }

        if (quic->table_cnx_by_net != NULL) {
            picohash_delete(quic->table_cnx_by_net, 1);
        }

        if (quic->verify_certificate_ctx != NULL &&
            quic->free_verify_certificate_callback_fn != NULL) {
            (quic->free_verify_certificate_callback_fn)(quic->verify_certificate_ctx);
            quic->verify_certificate_ctx = NULL;
        }

        if (quic->verify_certificate_callback_fn != NULL) {
            picoquic_dispose_verify_certificate_callback(quic, 1);
        }

        if (quic->default_tp != NULL) {
            free(quic->default_tp);
            quic->default_tp = NULL;
        }

        /* Delete the picotls context */
        if (quic->tls_master_ctx != NULL) {
            picoquic_master_tlscontext_free(quic);

            free(quic->tls_master_ctx);
            quic->tls_master_ctx = NULL;
        }

        free(quic);
    }
}

void picoquic_set_null_verifier(picoquic_quic_t* quic) {
    picoquic_dispose_verify_certificate_callback(quic, 1);
}

void picoquic_set_cookie_mode(picoquic_quic_t* quic, int cookie_mode)
{
    if (cookie_mode) {
        quic->flags |= picoquic_context_check_token;
        picoquic_crypto_random(quic, quic->retry_seed, PICOQUIC_RETRY_SECRET_SIZE);
    } else {
        quic->flags &= ~picoquic_context_check_token;
    }
}

picoquic_stateless_packet_t* picoquic_create_stateless_packet(picoquic_quic_t* quic)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(quic);
#endif
    return (picoquic_stateless_packet_t*)malloc(sizeof(picoquic_stateless_packet_t));
}

void picoquic_delete_stateless_packet(picoquic_stateless_packet_t* sp)
{
    free(sp);
}

void picoquic_queue_stateless_packet(picoquic_quic_t* quic, picoquic_stateless_packet_t* sp)
{
    picoquic_stateless_packet_t** pnext = &quic->pending_stateless_packet;

    while ((*pnext) != NULL) {
        pnext = &(*pnext)->next_packet;
    }

    *pnext = sp;
    sp->next_packet = NULL;
}

picoquic_stateless_packet_t* picoquic_dequeue_stateless_packet(picoquic_quic_t* quic)
{
    picoquic_stateless_packet_t* sp = quic->pending_stateless_packet;

    if (sp != NULL) {
        quic->pending_stateless_packet = sp->next_packet;
        sp->next_packet = NULL;

        if (quic->F_log != NULL) {
            picoquic_log_packet_address(quic->F_log, sp->cnxid_log64,
                NULL, (struct sockaddr*)&sp->addr_to, 0, sp->length, picoquic_get_quic_time(quic));
        }
    }

    return sp;
}

/* Connection context creation and registration */
int picoquic_register_cnx_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, picoquic_path_t * path_x, picoquic_connection_id_t cnx_id)
{
    int ret = 0;
    picohash_item* item;
    picoquic_cnx_id_key_t* key = (picoquic_cnx_id_key_t*)malloc(sizeof(picoquic_cnx_id_key_t));

    if (key == NULL) {
        ret = -1;
    } else {
        key->cnx_id = cnx_id;
        key->cnx = cnx;
        key->path = path_x;
        key->next_cnx_id = NULL;

        item = picohash_retrieve(quic->table_cnx_by_id, key);

        if (item != NULL) {
            ret = -1;
        } else {
            ret = picohash_insert(quic->table_cnx_by_id, key);

            if (ret == 0) {
                key->next_cnx_id = path_x->first_cnx_id;
                path_x->first_cnx_id = key;
            }
        }
    }

    return ret;
}

static void picoquic_set_hash_key_by_address(picoquic_net_id_key_t * key, struct sockaddr* addr)
{
    memset(&key->saddr, 0, sizeof(struct sockaddr_storage));

    if (addr->sa_family == AF_INET) {
        struct sockaddr_in * key4 = (struct sockaddr_in *) &key->saddr;
        struct sockaddr_in * s4 = (struct sockaddr_in *) addr;

#ifdef _WINDOWS
        key4->sin_addr.S_un.S_addr = s4->sin_addr.S_un.S_addr;
#else
        key4->sin_addr.s_addr = s4->sin_addr.s_addr;
#endif
        key4->sin_family = s4->sin_family;
        key4->sin_port = s4->sin_port;
    }
    else {
        struct sockaddr_in6 * key6 = (struct sockaddr_in6 *) &key->saddr;
        struct sockaddr_in6 * s6 = (struct sockaddr_in6 *) addr;
        memcpy(&key6->sin6_addr, &s6->sin6_addr, sizeof(struct in6_addr));
        key6->sin6_family = s6->sin6_family;
        key6->sin6_port = s6->sin6_port;
        /* TODO: special code for local addresses may be needed if scope is specified */
    }
}

int picoquic_register_net_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, picoquic_path_t * path_x, struct sockaddr* addr)
{
    int ret = 0;
    picohash_item* item;
    picoquic_net_id_key_t* key = (picoquic_net_id_key_t*)malloc(sizeof(picoquic_net_id_key_t));

    if (key == NULL) {
        ret = -1;
    } else {
        picoquic_set_hash_key_by_address(key, addr);

        key->cnx = cnx;
        key->path = path_x;

        item = picohash_retrieve(quic->table_cnx_by_net, key);

        if (item != NULL) {
            ret = -1;
        } else {
            ret = picohash_insert(quic->table_cnx_by_net, key);

            if (ret == 0) {
                key->next_net_id = path_x->first_net_id;
                path_x->first_net_id = key;
            }
        }
    }

    if (key != NULL && ret != 0) {
        free(key);
    }

    return ret;
}

void picoquic_init_transport_parameters(picoquic_tp_t* tp, int client_mode)
{
    tp->initial_max_stream_data_bidi_local = 0x200000;
    tp->initial_max_stream_data_bidi_remote = 65635;
    tp->initial_max_stream_data_uni = 65535;
    tp->initial_max_data = 0x100000;
    if (client_mode) {
        tp->initial_max_stream_id_bidir = 65533;
        tp->initial_max_stream_id_unidir = 65535;
    } else {
        tp->initial_max_stream_id_bidir = 65532;
        tp->initial_max_stream_id_unidir = 65534;
    }
    tp->idle_timeout = PICOQUIC_MICROSEC_HANDSHAKE_MAX/1000000;
    tp->max_packet_size = PICOQUIC_PRACTICAL_MAX_MTU;
    tp->ack_delay_exponent = 3;
}


/* management of the list of connections in context */

picoquic_cnx_t* picoquic_get_first_cnx(picoquic_quic_t* quic)
{
    return quic->cnx_list;
}

picoquic_cnx_t* picoquic_get_next_cnx(picoquic_cnx_t* cnx)
{
    return cnx->next_in_table;
}

static void picoquic_insert_cnx_in_list(picoquic_quic_t* quic, picoquic_cnx_t* cnx)
{
    if (quic->cnx_list != NULL) {
        quic->cnx_list->previous_in_table = cnx;
        cnx->next_in_table = quic->cnx_list;
    } else {
        quic->cnx_last = cnx;
        cnx->next_in_table = NULL;
    }
    quic->cnx_list = cnx;
    cnx->previous_in_table = NULL;
}

static void picoquic_remove_cnx_from_list(picoquic_cnx_t* cnx)
{
    if (cnx->next_in_table == NULL) {
        cnx->quic->cnx_last = cnx->previous_in_table;
    } else {
        cnx->next_in_table->previous_in_table = cnx->previous_in_table;
    }

    if (cnx->previous_in_table == NULL) {
        cnx->quic->cnx_list = cnx->next_in_table;
    }
    else {
        cnx->previous_in_table->next_in_table = cnx->next_in_table;
    }
}

/* Management of the list of connections, sorted by wake time */

static void picoquic_remove_cnx_from_wake_list(picoquic_cnx_t* cnx)
{
    if (cnx->next_by_wake_time == NULL) {
        cnx->quic->cnx_wake_last = cnx->previous_by_wake_time;
    } else {
        cnx->next_by_wake_time->previous_by_wake_time = cnx->previous_by_wake_time;
    }
    
    if (cnx->previous_by_wake_time == NULL) {
        cnx->quic->cnx_wake_first = cnx->next_by_wake_time;
    } else {
        cnx->previous_by_wake_time->next_by_wake_time = cnx->next_by_wake_time;
    }
}

static void picoquic_insert_cnx_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx)
{
    picoquic_cnx_t * cnx_next = quic->cnx_wake_first;
    picoquic_cnx_t * previous = NULL;
    while (cnx_next != NULL && cnx_next->next_wake_time <= cnx->next_wake_time) {
        previous = cnx_next;
        cnx_next = cnx_next->next_by_wake_time;
    }
    
    cnx->previous_by_wake_time = previous;
    if (previous == NULL) {
        quic->cnx_wake_first = cnx;

    } else {
        previous->next_by_wake_time = cnx;
    }
    
    cnx->next_by_wake_time = cnx_next;

    if (cnx_next == NULL) {
        quic->cnx_wake_last = cnx;
    } else { 
        cnx_next->previous_by_wake_time = cnx;
    }
}

void picoquic_reinsert_by_wake_time(picoquic_quic_t* quic, picoquic_cnx_t* cnx, uint64_t next_time)
{
    picoquic_remove_cnx_from_wake_list(cnx);
    cnx->next_wake_time = next_time;
    picoquic_insert_cnx_by_wake_time(quic, cnx);
}

picoquic_cnx_t* picoquic_get_earliest_cnx_to_wake(picoquic_quic_t* quic, uint64_t max_wake_time)
{
    picoquic_cnx_t * cnx = quic->cnx_wake_first;
    if (cnx != NULL && max_wake_time != 0 && cnx->next_wake_time > max_wake_time)
    {
        cnx = NULL;
    }

    return cnx;
}


int64_t picoquic_get_next_wake_delay(picoquic_quic_t* quic,
    uint64_t current_time, int64_t delay_max)
{
    int64_t wake_delay = delay_max;

    if (quic->cnx_wake_first != NULL) {
        if (quic->cnx_wake_first->next_wake_time > current_time) {
            wake_delay = quic->cnx_wake_first->next_wake_time - current_time;
            
            if (wake_delay > delay_max) {
                wake_delay = delay_max;
            }
        }
        else {
            wake_delay = 0;
        }
    } else {
        wake_delay = delay_max;
    }

    return wake_delay;
}

/* Other context management functions */

int picoquic_get_version_index(uint32_t proposed_version)
{
    int ret = -1;

    for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
        if (picoquic_supported_versions[i].version == proposed_version) {
            ret = (int)i;
            break;
        }
    }

    return ret;
}


static void picoquic_create_random_cnx_id(picoquic_quic_t* quic, picoquic_connection_id_t * cnx_id, uint8_t id_length)
{
    if (id_length > 0) {
        picoquic_crypto_random(quic, cnx_id->id, id_length);
    }
    if (id_length < sizeof(cnx_id->id)) {
        memset(cnx_id->id + 8, 0, sizeof(cnx_id->id) - id_length);
    }
    cnx_id->id_len = id_length;
}

/* Path management -- returns the index of the path that was created. */

int picoquic_create_path(picoquic_cnx_t* cnx, uint64_t start_time, struct sockaddr* local_addr, struct sockaddr* peer_addr)
{
    int ret = -1;

    if (cnx->nb_paths >= cnx->nb_path_alloc)
    {
        int new_alloc = (cnx->nb_path_alloc == 0) ? 1 : 2 * cnx->nb_path_alloc;
        picoquic_path_t ** new_path = (picoquic_path_t **)malloc(new_alloc * sizeof(picoquic_path_t *));

        if (new_path != NULL)
        {
            if (cnx->path != NULL)
            {
                if (cnx->nb_paths > 0)
                {
                    memcpy(new_path, cnx->path, cnx->nb_paths * sizeof(picoquic_path_t *));
                }
                free(cnx->path);
            }
            cnx->path = new_path;
            cnx->nb_path_alloc = new_alloc;
        }
    }

    if (cnx->nb_paths < cnx->nb_path_alloc)
    {
        picoquic_path_t * path_x = (picoquic_path_t *)malloc(sizeof(picoquic_path_t));

        if (path_x != NULL)
        {
            memset(path_x, 0, sizeof(picoquic_path_t));
            /* Register the sequence number */
            path_x->path_sequence = cnx->path_sequence_next;
            cnx->path_sequence_next++;

            /* Set the addresses */
            path_x->peer_addr_len = picoquic_store_addr(&path_x->peer_addr, peer_addr);
            path_x->local_addr_len = picoquic_store_addr(&path_x->local_addr, local_addr);

            /* Set the challenge used for this path */
            path_x->challenge = picoquic_public_random_64();

            /* Initialize the reset secret to a random value. This
            * will prevent spurious matches to an all zero value, for example.
            * The real value will be set when receiving the transport parameters.
            */
            picoquic_public_random(path_x->reset_secret, PICOQUIC_RESET_SECRET_SIZE);

            /* Initialize per path time measurement */
            path_x->smoothed_rtt = PICOQUIC_INITIAL_RTT;
            path_x->rtt_variant = 0;
            path_x->retransmit_timer = PICOQUIC_INITIAL_RETRANSMIT_TIMER;
            path_x->rtt_min = 0;

            /* Initialize per path congestion control state */
            path_x->cwin = PICOQUIC_CWIN_INITIAL;
            path_x->bytes_in_transit = 0;
            path_x->congestion_alg_state = NULL;

            /* Initialize per path pacing state */
            path_x->pacing_evaluation_time = start_time;
            path_x->pacing_bucket_nanosec = 16;
            path_x->pacing_bucket_max = 16;
            path_x->pacing_packet_time_nanosec = 1;
            path_x->pacing_packet_time_microsec = 1;

            /* Initialize the MTU */
            path_x->send_mtu = (peer_addr == NULL || peer_addr->sa_family == AF_INET) ? PICOQUIC_INITIAL_MTU_IPV4 : PICOQUIC_INITIAL_MTU_IPV6;

            /* Record the path */
            cnx->path[cnx->nb_paths] = path_x;
            ret = cnx->nb_paths++;
        }
    }

    return ret;
}

/*
 * Register the path in the hash tables
 */
void picoquic_register_path(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{
    if (picoquic_is_connection_id_null(path_x->local_cnxid)) {
        picoquic_create_random_cnx_id(cnx->quic, &path_x->local_cnxid, cnx->quic->local_ctx_length);

        if (cnx->quic->cnx_id_callback_fn)
            cnx->quic->cnx_id_callback_fn(cnx->quic, path_x->local_cnxid, cnx->initial_cnxid,
                cnx->quic->cnx_id_callback_ctx, &path_x->local_cnxid);
    }

    if (!picoquic_is_connection_id_null(path_x->local_cnxid)) {
        (void)picoquic_register_cnx_id(cnx->quic, cnx, path_x, path_x->local_cnxid);
    }

    if (path_x->peer_addr_len != 0) {
        (void)picoquic_register_net_id(cnx->quic, cnx, cnx->path[0], (struct sockaddr *)&path_x->peer_addr);
    }
}

/* To delete a path, we need to delete the data allocated to the path: search items in
 * the hash tables, and congestion algorithm context. Then delete the path data itself,
 * and finally remove the path reference from the table of paths in the connection
 * context.
 */

static void picoquic_clear_path_data(picoquic_cnx_t* cnx, picoquic_path_t * path_x) 
{
    /* Remove the registration in hash tables */
    while (path_x->first_cnx_id != NULL) {
        picohash_item* item;
        picoquic_cnx_id_key_t* cnx_id_key = path_x->first_cnx_id;
        path_x->first_cnx_id = cnx_id_key->next_cnx_id;
        cnx_id_key->next_cnx_id = NULL;

        item = picohash_retrieve(cnx->quic->table_cnx_by_id, cnx_id_key);
        if (item != NULL) {
            picohash_item_delete(cnx->quic->table_cnx_by_id, item, 1);
        }
    }

    while (path_x->first_net_id != NULL) {
        picohash_item* item;
        picoquic_net_id_key_t* net_id_key = path_x->first_net_id;
        path_x->first_net_id = net_id_key->next_net_id;
        net_id_key->next_net_id = NULL;

        item = picohash_retrieve(cnx->quic->table_cnx_by_net, net_id_key);
        if (item != NULL) {
            picohash_item_delete(cnx->quic->table_cnx_by_net, item, 1);
        }
    }
    /* Remove the congestion data */
    if (cnx->congestion_alg != NULL) {
        cnx->congestion_alg->alg_delete(path_x);
    }

    /* Free the record */
    free(path_x);
}

void picoquic_delete_path(picoquic_cnx_t* cnx, int path_index)
{
    picoquic_path_t * path_x = cnx->path[path_index];
    picoquic_packet_t* p = NULL;

    DBG_PRINTF("delete path[%d] (%x)\n", path_index, path_x);
    if (cnx->quic->F_log != NULL) {
        fflush(cnx->quic->F_log);
    }
        
    /* Remove old path data from retransmit queue */
    for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++)
    {
        p = cnx->pkt_ctx[pc].retransmit_newest;

        while (p != NULL) {
            if (p->send_path == path_x) {
                DBG_PRINTF("Erase path for packet pc: %d, seq:%d\n", pc, p->sequence_number);
                p->send_path = NULL;
            }
            p = p->next_packet;
        }

        p = cnx->pkt_ctx[pc].retransmitted_newest;
        while (p != NULL) {
            if (p->send_path == path_x) {
                DBG_PRINTF("Erase path for old packet pc: %d, seq:%d\n", pc, p->sequence_number);
                p->send_path = NULL;
            }
            p = p->next_packet;
        }
    }
    /* Free the data */
    picoquic_clear_path_data(cnx, path_x);


    /* Compact the path table  */
    for (int i = path_index + 1; i < cnx->nb_paths; i++) {
        cnx->path[i-1] = cnx->path[i];
    }

    cnx->nb_paths--;
    cnx->path[cnx->nb_paths] = NULL;
}

/*
 * Path challenges may be abandoned if they are tried too many times without success. 
 */

void picoquic_delete_abandoned_paths(picoquic_cnx_t* cnx, uint64_t current_time, uint64_t * next_wake_time)
{
    int path_index_good = 1;
    int path_index_current = 1;

    while (path_index_current < cnx->nb_paths) {
        if (cnx->path[path_index_current]->challenge_failed ||
            (cnx->path[path_index_current]->path_is_demoted &&
                current_time >= cnx->path[path_index_current]->demotion_time)) {
            /* Only increment the current index */
            path_index_current++;
        } else {
            if (cnx->path[path_index_current]->path_is_demoted &&
                current_time < cnx->path[path_index_current]->demotion_time &&
                *next_wake_time > cnx->path[path_index_current]->demotion_time) {
                *next_wake_time = cnx->path[path_index_current]->demotion_time;
            }

            if (path_index_current > path_index_good) {
                /* swap the path indexed good with current */
                picoquic_path_t * path_x = cnx->path[path_index_current];
                cnx->path[path_index_current] = cnx->path[path_index_good];
                cnx->path[path_index_good] = path_x;
            }
            /* increment both indices */
            path_index_current++;
            path_index_good++;
        }
    }

    while (cnx->nb_paths > path_index_good) {
        int d_path = cnx->nb_paths - 1;
        if (!picoquic_is_connection_id_null(cnx->path[d_path]->remote_cnxid)) {
            (void)picoquic_queue_retire_connection_id_frame(cnx, cnx->path[d_path]->remote_cnxid_sequence);
        }
        picoquic_delete_path(cnx, d_path);
    }

    /* TODO: what if there are no paths left? */
}

/* 
 * Demote path, compute the effective time for demotion.
 */
void picoquic_demote_path(picoquic_cnx_t* cnx, int path_index, uint64_t current_time)
{
    if (!cnx->path[path_index]->path_is_demoted) {
        uint64_t demote_timer = cnx->path[path_index]->retransmit_timer;

        if (demote_timer < PICOQUIC_INITIAL_RETRANSMIT_TIMER) {
            demote_timer = PICOQUIC_INITIAL_RETRANSMIT_TIMER;
        }

        cnx->path[path_index]->path_is_demoted = 1;
        cnx->path[path_index]->demotion_time = current_time + 3* demote_timer;
    }
}

/* Promote path to default. This happens when a new path is verified, at the end
 * of a migration, and becomes the new default path.
 */

void picoquic_promote_path_to_default(picoquic_cnx_t* cnx, int path_index, uint64_t current_time)
{
    if (path_index > 0 && path_index < cnx->nb_paths) {
        picoquic_path_t * path_x = cnx->path[path_index];

        /* Set the congestion algorithm for the new path */
        if (cnx->congestion_alg != NULL) {
            cnx->congestion_alg->alg_init(path_x);
        }

        /* Mark old path as demoted */
        picoquic_demote_path(cnx, 0, current_time);

        /* Swap */
        cnx->path[path_index] = cnx->path[0];
        cnx->path[0] = path_x;
    }
}

/*
 * Manage the stash of connection IDs sent by the peer 
 */

picoquic_cnxid_stash_t * picoquic_dequeue_cnxid_stash(picoquic_cnx_t * cnx)
{
    picoquic_cnxid_stash_t * stashed = NULL;

    if (cnx != NULL && cnx->cnxid_stash_first != NULL) {
        stashed = cnx->cnxid_stash_first;
        cnx->cnxid_stash_first = stashed->next_in_stash;
    }

    return stashed;
}

int picoquic_enqueue_cnxid_stash(picoquic_cnx_t * cnx,
    const uint64_t sequence, const uint8_t cid_length, const uint8_t * cnxid_bytes, 
    const uint8_t * secret_bytes, picoquic_cnxid_stash_t ** pstashed)
{
    int ret = 0;
    int is_duplicate = 0;
    picoquic_connection_id_t cnx_id;
    picoquic_cnxid_stash_t * next_stash = NULL;
    picoquic_cnxid_stash_t * last_stash = NULL;
    picoquic_cnxid_stash_t * stashed = NULL;

    /* verify the format */
    if (picoquic_parse_connection_id(cnxid_bytes, cid_length, &cnx_id) == 0) {
        ret = PICOQUIC_TRANSPORT_FRAME_FORMAT_ERROR;
    }

    if (ret == 0 && cnx->path[0]->remote_cnxid.id_len == 0) {
        /* Protocol error. The peer is using null length cnx_id */
        ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
    }

    /* Verify that the proposed CID is not already in use */
    for (int i = 0; ret == 0 && i < cnx->nb_paths; i++) {
        if (sequence == cnx->path[i]->remote_cnxid_sequence) {
            if (picoquic_compare_connection_id(&cnx_id, &cnx->path[i]->remote_cnxid) == 0)
            {
                if (memcmp(secret_bytes, cnx->path[i]->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
                    is_duplicate = 1;
                    break;
                }
                else {
                    DBG_PRINTF("Path %d, Cnx_id: %02x%02x%02x%02x..., Reset = %02x%02x%02x%02x... vs %02x%02x%02x%02x...\n",
                        i,
                        cnx->path[i]->remote_cnxid.id[0], cnx->path[i]->remote_cnxid.id[1],
                        cnx->path[i]->remote_cnxid.id[2], cnx->path[i]->remote_cnxid.id[3],
                        secret_bytes[0], secret_bytes[1], secret_bytes[2], secret_bytes[3],
                        cnx->path[i]->reset_secret[0], cnx->path[i]->reset_secret[1],
                        cnx->path[i]->reset_secret[2], cnx->path[i]->reset_secret[3]);
                    ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
                }
                break;
            }
            else {
                DBG_PRINTF("Path %d, Sequence %d, Cnx_id: %02x%02x%02x%02x..., vs %02x%02x%02x%02x...\n",
                    i, (int)sequence,
                    cnx->path[i]->remote_cnxid.id[0], cnx->path[i]->remote_cnxid.id[1],
                    cnx->path[i]->remote_cnxid.id[2], cnx->path[i]->remote_cnxid.id[3],
                    cnx_id.id[0], cnx_id.id[1], cnx_id.id[2], cnx_id.id[3]);
                ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
            }
        }
        else if (picoquic_compare_connection_id(&cnx_id, &cnx->path[i]->remote_cnxid) == 0) {
            DBG_PRINTF("Path %d, Cnx_id: %02x%02x%02x%02x..., Sequence %d vs. %d\n",
                i, cnx_id.id[0], cnx_id.id[1], cnx_id.id[2], cnx_id.id[3],
                (int)sequence, (int)cnx->path[i]->remote_cnxid_sequence);
            ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
        }
    }

    if (ret == 0 && is_duplicate == 0) {
        picoquic_probe_t * next_probe = cnx->probe_first;

        while (ret == 0 && next_probe != NULL) {
            if (sequence == next_probe->sequence) {
                if (picoquic_compare_connection_id(&cnx_id, &next_probe->remote_cnxid) == 0)
                {
                    if (memcmp(secret_bytes, next_probe->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
                        is_duplicate = 1;
                        break;
                    }
                    else {
                        ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
                    }
                    break;
                }
                else {
                    ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
                }
            }
            else if (picoquic_compare_connection_id(&cnx_id, &next_probe->remote_cnxid) == 0) {
                ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
            }

            next_probe = next_probe->next_probe;
        }
    }

    if (ret == 0 && is_duplicate == 0) {
        next_stash = cnx->cnxid_stash_first;

        while (next_stash != NULL) {
            if (picoquic_compare_connection_id(&cnx_id, &next_stash->cnx_id) == 0)
            {
                if (next_stash->sequence == sequence &&
                    memcmp(secret_bytes, next_stash->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
                    is_duplicate = 1;
                }
                else {
                    ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
                }
                break;
            }
            else if (next_stash->sequence == sequence) {
                ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
            }
            last_stash = next_stash;
            next_stash = next_stash->next_in_stash;
        }
    }

    if (ret == 0 && is_duplicate == 0) {
        stashed = (picoquic_cnxid_stash_t *)malloc(sizeof(picoquic_cnxid_stash_t));

        if (stashed == NULL) {
            ret = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
        } else {
            (void)picoquic_parse_connection_id(cnxid_bytes, cid_length, &stashed->cnx_id);
            stashed->sequence = sequence;
            memcpy(stashed->reset_secret, secret_bytes, PICOQUIC_RESET_SECRET_SIZE);
            stashed->next_in_stash = NULL;

            if (last_stash == NULL) {
                cnx->cnxid_stash_first = stashed;
            }
            else {
                last_stash->next_in_stash = stashed;
            }
        }
    }

    /* the return argument is only used in tests */

    if (pstashed != NULL) {
        *pstashed = stashed;
    }

    return ret;
}

/*
 * Start using a new connection ID for the existing connection
 */

int picoquic_renew_connection_id(picoquic_cnx_t* cnx)
{
    int ret = 0;
    picoquic_cnxid_stash_t * stashed = NULL;

    if (cnx->remote_parameters.migration_disabled != 0 ||
        cnx->local_parameters.migration_disabled != 0) {
        /* Do not switch cnx_id if migration is disabled */
        ret = PICOQUIC_ERROR_MIGRATION_DISABLED;
    }
    else {
        stashed = picoquic_dequeue_cnxid_stash(cnx);

        if (stashed == NULL) {
            ret = PICOQUIC_ERROR_CNXID_NOT_AVAILABLE;
        } else {
            ret = picoquic_queue_retire_connection_id_frame(cnx, cnx->path[0]->remote_cnxid_sequence);
            cnx->path[0]->remote_cnxid = stashed->cnx_id;
            cnx->path[0]->remote_cnxid_sequence = stashed->sequence;
            memcpy(cnx->path[0]->reset_secret, stashed->reset_secret,
                PICOQUIC_RESET_SECRET_SIZE);
            free(stashed);
        }
    }

    return ret;
}

/*
 * Manage the list of ongoing probes.
 */

picoquic_probe_t * picoquic_find_probe_by_challenge(const picoquic_cnx_t* cnx, uint64_t challenge)
{
    picoquic_probe_t * next = cnx->probe_first;

    if (challenge != 0) {
        while (next != NULL) {
            if (next->challenge == challenge) {
                break;
            }
            next = next->next_probe;
        }
    }

    return next;
}

picoquic_probe_t * picoquic_find_probe_by_addr(const picoquic_cnx_t* cnx,
    const struct sockaddr * peer_addr, const struct sockaddr * local_addr) 
{
    picoquic_probe_t * next = cnx->probe_first;
    picoquic_probe_t * partial_match = NULL;

    while (next != NULL) {
        if (picoquic_compare_addr((struct sockaddr *)&next->peer_addr, peer_addr) == 0) {
            if (next->local_addr_len == 0) {
                partial_match = next;
            }
            else if (picoquic_compare_addr((struct sockaddr *)&next->local_addr, local_addr) == 0) {
                break;
            }
        }
        next = next->next_probe;
    }

    if (next == NULL && partial_match != NULL) {
        next = partial_match;
    }

    return next;
}


void picoquic_delete_probe(picoquic_cnx_t* cnx, picoquic_probe_t * probe)
{
    picoquic_probe_t * previous = NULL;
    picoquic_probe_t * next = cnx->probe_first;

    while (next != NULL) {
        if (next == probe) {
            if (previous == NULL) {
                cnx->probe_first = probe->next_probe;
            }
            else {
                previous->next_probe = probe->next_probe;
            }
            break;
        }
        else {
            previous = next;
            next = next->next_probe;
        }
    }

    free(probe);
}

/*
 * Probes may be abandoned if they are tried too many times without success. 
 */

void picoquic_delete_failed_probes(picoquic_cnx_t* cnx)
{
    picoquic_probe_t * probe = cnx->probe_first;
    picoquic_probe_t * previous = NULL;

    while (probe != NULL) {
        if (probe->challenge_failed) {
            picoquic_probe_t * abandoned = probe;
            probe = probe->next_probe;

            if (previous == NULL) {
                cnx->probe_first = probe;
            }
            else {
                previous->next_probe = probe;
            }

            /* Before deleting, post a notification to the peer */
            (void)picoquic_queue_retire_connection_id_frame(cnx, abandoned->sequence);

            free(abandoned);
        }
        else {
            previous = probe;
            probe = probe->next_probe;
        }
    }
}

int picoquic_create_probe(picoquic_cnx_t* cnx, const struct sockaddr* addr_to, const struct sockaddr* addr_from)
{
    int ret = 0;
    picoquic_probe_t * probe = NULL;
    picoquic_cnxid_stash_t * stashed = NULL;

    /* TODO: Check for duplicates: is there a similar outgoing probe? */

    if (cnx->remote_parameters.migration_disabled != 0 ||
        cnx->local_parameters.migration_disabled != 0) {
        /* Do not send probes if migration is disabled */
        ret = PICOQUIC_ERROR_MIGRATION_DISABLED;
    }
    else {
        /* Create the probe */
        probe = (picoquic_probe_t *)malloc(sizeof(picoquic_probe_t));

        if (probe == NULL) {
            ret = PICOQUIC_ERROR_MEMORY;
        }
        else {
            stashed = picoquic_dequeue_cnxid_stash(cnx);

            if (stashed == NULL) {
                ret = PICOQUIC_ERROR_CNXID_NOT_AVAILABLE;
                free(probe);
                probe = NULL;
            }
            else {
                memset(probe, 0, sizeof(picoquic_probe_t));

                probe->sequence = stashed->sequence;
                probe->remote_cnxid = stashed->cnx_id;
                memcpy(probe->reset_secret, stashed->reset_secret, PICOQUIC_RESET_SECRET_SIZE);
                free(stashed);

                probe->peer_addr_len = picoquic_store_addr(&probe->peer_addr, addr_to);
                probe->local_addr_len = picoquic_store_addr(&probe->local_addr, addr_from);

                probe->challenge_required = 1;
                probe->challenge = picoquic_public_random_64();

                probe->next_probe = cnx->probe_first;
                cnx->probe_first = probe;
            }
        }
    }

    return ret;
}

/* Connection management
 */

picoquic_cnx_t* picoquic_create_cnx(picoquic_quic_t* quic,
    picoquic_connection_id_t initial_cnx_id, picoquic_connection_id_t remote_cnx_id, 
    struct sockaddr* addr_to, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn, char client_mode)
{
    picoquic_cnx_t* cnx = (picoquic_cnx_t*)malloc(sizeof(picoquic_cnx_t));

    if (cnx != NULL) {
        int ret;

        memset(cnx, 0, sizeof(picoquic_cnx_t));
        /* Should return 0, since this is the first path */
        ret = picoquic_create_path(cnx, start_time, NULL, addr_to);

        if (ret != 0) {
            free(cnx);
            cnx = NULL;
        } else {
            cnx->next_wake_time = start_time;
            cnx->start_time = start_time;
            cnx->client_mode = client_mode;

            cnx->quic = quic;
            picoquic_insert_cnx_in_list(quic, cnx);
            picoquic_insert_cnx_by_wake_time(quic, cnx);
            /* Do not require verification for default path */
            cnx->path[0]->challenge_verified = 1;

            cnx->high_priority_stream_id = (uint64_t)((int64_t)-1);
        }
    }

    if (cnx != NULL) {
        if (quic->default_tp == NULL) {
            picoquic_init_transport_parameters(&cnx->local_parameters, cnx->client_mode);
        } else {
            memcpy(&cnx->local_parameters, quic->default_tp, sizeof(picoquic_tp_t));
            /* If the default parameters include preferred address, document it */
            if (cnx->local_parameters.prefered_address.is_defined) {
                /* Create an additional path */
                if (picoquic_create_path(cnx, start_time, NULL, NULL) == 1) {
                    /* register it, so the cnx_id is defined */
                    picoquic_register_path(cnx, cnx->path[1]);
                    /* copy the connection ID */
                    cnx->local_parameters.prefered_address.connection_id = cnx->path[1]->local_cnxid;
                    /* Create the reset secret */
                    (void)picoquic_create_cnxid_reset_secret(cnx->quic, cnx->path[1]->local_cnxid,
                        cnx->local_parameters.prefered_address.statelessResetToken);
                }
            }
        }
        if (cnx->quic->mtu_max > 0)
        {
            cnx->local_parameters.max_packet_size = cnx->quic->mtu_max;
        }


        /* Initialize local flow control variables to advertised values */
        cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data);
        cnx->max_stream_id_bidir_local = cnx->local_parameters.initial_max_stream_id_bidir;
        cnx->max_stream_id_bidir_local_computed = cnx->max_stream_id_bidir_local;
        cnx->max_stream_id_unidir_local = cnx->local_parameters.initial_max_stream_id_unidir;
        cnx->max_stream_id_unidir_local_computed = cnx->max_stream_id_unidir_local;

        /* Initialize remote variables to some plausible value. 
		 * Hopefully, this will be overwritten by the parameters received in
		 * the TLS transport parameter extension */
        cnx->maxdata_remote = PICOQUIC_DEFAULT_0RTT_WINDOW;
        cnx->remote_parameters.initial_max_stream_data_bidi_remote = PICOQUIC_DEFAULT_0RTT_WINDOW;
        cnx->remote_parameters.initial_max_stream_data_uni = PICOQUIC_DEFAULT_0RTT_WINDOW;
        cnx->max_stream_id_bidir_remote = (cnx->client_mode)?4:0;
        cnx->max_stream_id_unidir_remote = 0;

        /* Initialize padding policy to default for context */
        cnx->padding_multiple = quic->padding_multiple_default;
        cnx->padding_minsize = quic->padding_minsize_default;

        /* Initialize spin policy, ensure that at least 1/8th of connections do not spin */
        cnx->spin_policy = quic->default_spin_policy;
        if (cnx->spin_policy == picoquic_spinbit_basic) {
            uint8_t rand256 = (uint8_t)picoquic_public_random_64();
            if (rand256 < PICOQUIC_SPIN_RESERVE_MOD_256) {
                cnx->spin_policy = picoquic_spinbit_null;
            }
        }

        if (sni != NULL) {
            cnx->sni = picoquic_string_duplicate(sni);
        }

        if (alpn != NULL) {
            cnx->alpn = picoquic_string_duplicate(alpn);
        }

        cnx->callback_fn = quic->default_callback_fn;
        cnx->callback_ctx = quic->default_callback_ctx;
        cnx->congestion_alg = quic->default_congestion_alg;

        if (cnx->client_mode) {
            if (preferred_version == 0) {
                cnx->proposed_version = picoquic_supported_versions[0].version;
                cnx->version_index = 0;
            } else {
                cnx->version_index = picoquic_get_version_index(preferred_version);
                if (cnx->version_index < 0) {
                    cnx->version_index = PICOQUIC_INTEROP_VERSION_INDEX;
                    if ((preferred_version & 0x0A0A0A0A) == 0x0A0A0A0A) {
                        /* This is a hack, to allow greasing the cnx ID */
                        cnx->proposed_version = preferred_version;

                    } else {
                        cnx->proposed_version = picoquic_supported_versions[PICOQUIC_INTEROP_VERSION_INDEX].version;
                    }
                } else {
                    cnx->proposed_version = preferred_version;
                }
            }

            cnx->cnx_state = picoquic_state_client_init;
            if (picoquic_is_connection_id_null(initial_cnx_id)) {
                picoquic_create_random_cnx_id(quic, &initial_cnx_id, 8);
            }

            cnx->initial_cnxid = initial_cnx_id;
        } else {
            for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
                cnx->tls_stream[epoch].send_queue = NULL;
            }
            cnx->cnx_state = picoquic_state_server_init;
            cnx->initial_cnxid = initial_cnx_id;
            cnx->path[0]->remote_cnxid = remote_cnx_id;

            cnx->version_index = picoquic_get_version_index(preferred_version);
            if (cnx->version_index < 0) {
                /* TODO: this is an internal error condition, should not happen */
                cnx->version_index = 0;
                cnx->proposed_version = picoquic_supported_versions[0].version;
            } else {
                cnx->proposed_version = preferred_version;
            }
        }

        for (picoquic_packet_context_enum pc = 0;
            pc < picoquic_nb_packet_context; pc++) {
            cnx->pkt_ctx[pc].first_sack_item.start_of_sack_range = (uint64_t)((int64_t)-1);
            cnx->pkt_ctx[pc].first_sack_item.end_of_sack_range = 0;
            cnx->pkt_ctx[pc].first_sack_item.next_sack = NULL;
            cnx->pkt_ctx[pc].highest_ack_sent = 0;
            cnx->pkt_ctx[pc].highest_ack_sent_time = start_time;
            cnx->pkt_ctx[pc].time_stamp_largest_received = (uint64_t)((int64_t)-1);
            cnx->pkt_ctx[pc].send_sequence = 0;
            cnx->pkt_ctx[pc].nb_retransmit = 0;
            cnx->pkt_ctx[pc].latest_retransmit_time = 0;
            cnx->pkt_ctx[pc].retransmit_newest = NULL;
            cnx->pkt_ctx[pc].retransmit_oldest = NULL;
            cnx->pkt_ctx[pc].highest_acknowledged = cnx->pkt_ctx[pc].send_sequence - 1;
            cnx->pkt_ctx[pc].latest_time_acknowledged = start_time;
            cnx->pkt_ctx[pc].highest_acknowledged_time = start_time;
            cnx->pkt_ctx[pc].ack_needed = 0;
            cnx->pkt_ctx[pc].ack_delay_local = PICOQUIC_ACK_DELAY_MAX;
        }

        cnx->latest_progress_time = start_time;

        for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
            cnx->tls_stream[epoch].stream_id = 0;
            cnx->tls_stream[epoch].consumed_offset = 0;
            cnx->tls_stream[epoch].fin_offset = 0;
            cnx->tls_stream[epoch].next_stream = NULL;
            cnx->tls_stream[epoch].stream_data = NULL;
            cnx->tls_stream[epoch].sent_offset = 0;
            cnx->tls_stream[epoch].local_error = 0;
            cnx->tls_stream[epoch].remote_error = 0;
            cnx->tls_stream[epoch].maxdata_local = (uint64_t)((int64_t)-1);
            cnx->tls_stream[epoch].maxdata_remote = (uint64_t)((int64_t)-1);
            /* No need to reset the state flags, as they are not used for the crypto stream */
        }

        cnx->congestion_alg = cnx->quic->default_congestion_alg;
        if (cnx->congestion_alg != NULL) {
            cnx->congestion_alg->alg_init(cnx->path[0]);
        }
    }

    /* Only initialize TLS after all parameters have been set */

    if (picoquic_tlscontext_create(quic, cnx, start_time) != 0) {
        /* Cannot just do partial creation! */
        picoquic_delete_cnx(cnx);
        cnx = NULL;
    }

    if (cnx != NULL) {
        if (picoquic_setup_initial_traffic_keys(cnx)) {
            /* Cannot initialize aead for initial packets */
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }

    if (cnx != NULL) {
        picoquic_register_path(cnx, cnx->path[0]);

        picoquic_open_cc_dump(cnx);
    }

    return cnx;
}

picoquic_cnx_t* picoquic_create_client_cnx(picoquic_quic_t* quic,
    struct sockaddr* addr, uint64_t start_time, uint32_t preferred_version,
    char const* sni, char const* alpn, picoquic_stream_data_cb_fn callback_fn, void* callback_ctx)
{
    picoquic_cnx_t* cnx = picoquic_create_cnx(quic, picoquic_null_connection_id, picoquic_null_connection_id, addr, start_time, preferred_version, sni, alpn, 1);

    if (cnx != NULL) {
        int ret;

        if (callback_fn != NULL)
            cnx->callback_fn = callback_fn;
        if (callback_ctx != NULL)
            cnx->callback_ctx = callback_ctx;
        ret = picoquic_initialize_tls_stream(cnx);
        if (ret != 0) {
            /* Cannot just do partial initialization! */
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }

    return cnx;
}

int picoquic_start_client_cnx(picoquic_cnx_t * cnx)
{
    int ret = picoquic_initialize_tls_stream(cnx);

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

void picoquic_set_transport_parameters(picoquic_cnx_t * cnx, picoquic_tp_t const * tp)
{
    cnx->local_parameters = *tp;

    if (cnx->quic->mtu_max > 0)
    {
        cnx->local_parameters.max_packet_size = cnx->quic->mtu_max;
    }

    /* Initialize local flow control variables to advertised values */

    cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data);
    cnx->max_stream_id_bidir_local = cnx->local_parameters.initial_max_stream_id_bidir;
    cnx->max_stream_id_unidir_local = cnx->local_parameters.initial_max_stream_id_unidir;
}

void picoquic_get_peer_addr(picoquic_cnx_t* cnx, struct sockaddr** addr, int* addr_len)
{
    *addr = (struct sockaddr*)&cnx->path[0]->peer_addr;
    *addr_len = cnx->path[0]->peer_addr_len;
}

void picoquic_get_local_addr(picoquic_cnx_t* cnx, struct sockaddr** addr, int* addr_len)
{
    *addr = (struct sockaddr*)&cnx->path[0]->local_addr;
    *addr_len = cnx->path[0]->local_addr_len;
}

unsigned long picoquic_get_local_if_index(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->if_index_dest;
}

picoquic_connection_id_t picoquic_get_local_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->local_cnxid;
}

picoquic_connection_id_t picoquic_get_remote_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->remote_cnxid;
}

picoquic_connection_id_t picoquic_get_initial_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->initial_cnxid;
}

picoquic_connection_id_t picoquic_get_client_cnxid(picoquic_cnx_t* cnx)
{
    return (cnx->client_mode)?cnx->path[0]->local_cnxid: cnx->path[0]->remote_cnxid;
}

picoquic_connection_id_t picoquic_get_server_cnxid(picoquic_cnx_t* cnx)
{
    return (cnx->client_mode) ? cnx->path[0]->remote_cnxid : cnx->path[0]->local_cnxid;
}

picoquic_connection_id_t picoquic_get_logging_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->initial_cnxid;
}

uint64_t picoquic_get_cnx_start_time(picoquic_cnx_t* cnx)
{
    return cnx->start_time;
}

picoquic_state_enum picoquic_get_cnx_state(picoquic_cnx_t* cnx)
{
    return cnx->cnx_state;
}

uint64_t picoquic_is_0rtt_available(picoquic_cnx_t* cnx)
{
    return (cnx->crypto_context[1].aead_encrypt == NULL) ? 0 : 1;
}

void picoquic_cnx_set_padding_policy(picoquic_cnx_t * cnx, uint32_t padding_multiple, uint32_t padding_minsize)
{
    cnx->padding_multiple = padding_multiple;
    cnx->padding_minsize = padding_minsize;
}

void picoquic_cnx_get_padding_policy(picoquic_cnx_t * cnx, uint32_t * padding_multiple, uint32_t * padding_minsize)
{
    *padding_multiple = cnx->padding_multiple;
    *padding_minsize = cnx->padding_minsize;
}

void picoquic_cnx_set_spinbit_policy(picoquic_cnx_t * cnx, picoquic_spinbit_version_enum spinbit_policy)
{
    cnx->spin_policy = spinbit_policy;
}

/*
 * Provide clock time
 */
uint64_t picoquic_current_time()
{
    uint64_t now;
#ifdef _WINDOWS
    FILETIME ft;
    /*
    * The GetSystemTimeAsFileTime API returns  the number
    * of 100-nanosecond intervals since January 1, 1601 (UTC),
    * in FILETIME format.
    */
    GetSystemTimeAsFileTime(&ft);

    /*
    * Convert to plain 64 bit format, without making
    * assumptions about the FILETIME structure alignment.
    */
    now = ft.dwHighDateTime;
    now <<= 32;
    now |= ft.dwLowDateTime;
    /*
    * Convert units from 100ns to 1us
    */
    now /= 10;
    /*
    * Account for microseconds elapsed between 1601 and 1970.
    */
    now -= 11644473600000000ULL;
#else
    struct timeval tv;
    (void)gettimeofday(&tv, NULL);
    now = (tv.tv_sec * 1000000ull) + tv.tv_usec;
#endif
    return now;
}

/*
* Get the same time simulation as used for TLS
*/

uint64_t picoquic_get_quic_time(picoquic_quic_t* quic)
{
    uint64_t now;
    if (quic->p_simulated_time == NULL) {
        now = picoquic_current_time();
    }
    else {
        now = *quic->p_simulated_time;
    }

    return now;
}

void picoquic_connection_id_production_callback(picoquic_quic_t * quic, picoquic_connection_id_t cnx_id_local, picoquic_connection_id_t cnx_id_remote, void * cnx_id_cb_data, picoquic_connection_id_t * cnx_id_returned)
{
    picoquic_connection_id_encrypt_ctx_t* ctx = (picoquic_connection_id_encrypt_ctx_t*)cnx_id_cb_data;

    /* Initialize with either random value or */
    memset(cnx_id_returned, 0, sizeof(picoquic_connection_id_t));
    if (ctx->cnx_id_select == picoquic_connection_id_remote) {
        /* Keeping this for compatibility with old buggy version */
        cnx_id_local = cnx_id_remote;
    } else {
        /* setting value to random data */
        picoquic_public_random(cnx_id_local.id, quic->local_ctx_length);
    }
    cnx_id_local.id_len = quic->local_ctx_length;

    /* Apply substitution under mask */
    for (uint8_t i = 0; i < cnx_id_local.id_len; i++) {
        cnx_id_returned->id[i] = (cnx_id_local.id[i] & ctx->cnx_id_mask.id[i]) | ctx->cnx_id_val.id[i];
    }
    cnx_id_returned->id_len = quic->local_ctx_length;

    /* Apply encryption if required */
    switch (ctx->cnx_id_select) {
    case picoquic_connection_id_encrypt_basic:
        /* encryption under mask */
        if (ctx->cid_enc == NULL) {
            int ret = picoquic_cid_get_under_mask_ctx(&ctx->cid_enc, quic->reset_seed);
            if (ret != 0) {
                DBG_PRINTF("Cannot create CID encryption context, ret=%d\n", ret);
            }
        }
        if (ctx->cid_enc != NULL) {
            picoquic_cid_encrypt_under_mask(ctx->cid_enc, cnx_id_returned, &ctx->cnx_id_mask, cnx_id_returned);
        }
        break;
    case picoquic_connection_id_encrypt_global:
        /* global encryption */
        if (ctx->cid_enc == NULL) {
            int ret = picoquic_cid_get_encrypt_global_ctx(&ctx->cid_enc, 1, quic->reset_seed, quic->local_ctx_length);
            if (ret != 0) {
                DBG_PRINTF("Cannot create CID encryption context, ret=%d\n", ret);
            }
        }
        if (ctx->cid_enc != NULL) {
            picoquic_cid_encrypt_global(ctx->cid_enc, cnx_id_returned, cnx_id_returned);
        }
        break;
    default:
        /* Leave it unencrypted */
        break;
    }
}

picoquic_connection_id_encrypt_ctx_t * picoquic_connection_id_production_create_ctx(
    char const * select_type, char const * default_value_hex, char const * mask_hex)
{
    picoquic_connection_id_encrypt_ctx_t* ctx = (picoquic_connection_id_encrypt_ctx_t*)
        malloc(sizeof(picoquic_connection_id_encrypt_ctx_t));

    if (ctx != NULL) {
        size_t lv, lm;
        memset(ctx, 0, sizeof(picoquic_connection_id_encrypt_ctx_t));
        ctx->cnx_id_select = atoi(select_type);
        /* TODO: find an alternative to parsing a 64 bit integer */
        lv = picoquic_parse_connection_id_hexa(default_value_hex, strlen(default_value_hex), &ctx->cnx_id_val);
        lm = picoquic_parse_connection_id_hexa(mask_hex, strlen(mask_hex), &ctx->cnx_id_val);

        if (lm == 0 || lv == 0 || lm != lv) {
            free(ctx);
            ctx = NULL;
        }
    }

    return ctx;
}

void picoquic_connection_id_production_free_ctx(void * cnx_id_cb_data)
{
    picoquic_connection_id_encrypt_ctx_t* ctx = (picoquic_connection_id_encrypt_ctx_t*)cnx_id_cb_data;

    if (ctx != NULL && ctx->cid_enc != NULL) {
        switch (ctx->cnx_id_select) {
        case picoquic_connection_id_encrypt_basic:
            /* encryption under mask */
            picoquic_cid_free_under_mask_ctx(ctx->cid_enc);
            break;
        case picoquic_connection_id_encrypt_global:
            /* global encryption */
            picoquic_cid_free_encrypt_global_ctx(ctx->cid_enc);
            break;
        default:
            /* Guessing for the most common, assuming free will work... */
            picoquic_cid_free_under_mask_ctx(ctx->cid_enc);
            break;
        }
        ctx->cid_enc = NULL;
    }
    free(cnx_id_cb_data);
}

void picoquic_set_fuzz(picoquic_quic_t * quic, picoquic_fuzz_fn fuzz_fn, void * fuzz_ctx)
{
    quic->fuzz_fn = fuzz_fn;
    quic->fuzz_ctx = fuzz_ctx;
}

void picoquic_set_cc_log(picoquic_quic_t * quic, char const * cc_log_dir)
{
    quic->cc_log_dir = cc_log_dir;
}

int picoquic_set_default_connection_id_length(picoquic_quic_t* quic, uint8_t cid_length)
{
    int ret = 0;

    if (cid_length != quic->local_ctx_length) {
        if (cid_length != 0 && (cid_length < 4 || cid_length > 18)) {
            ret = PICOQUIC_ERROR_CNXID_CHECK;
        }
        else if (quic->cnx_list != NULL) {
            ret = PICOQUIC_ERROR_CANNOT_CHANGE_ACTIVE_CONTEXT;
        }
        else {
            quic->local_ctx_length = cid_length;
        }
    }

    return ret;
}

void picoquic_set_default_callback(picoquic_quic_t* quic,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx)
{
    quic->default_callback_fn = callback_fn;
    quic->default_callback_ctx = callback_ctx;
}

void picoquic_set_callback(picoquic_cnx_t* cnx,
    picoquic_stream_data_cb_fn callback_fn, void* callback_ctx)
{
    cnx->callback_fn = callback_fn;
    cnx->callback_ctx = callback_ctx;
}

picoquic_stream_data_cb_fn picoquic_get_default_callback_function(picoquic_quic_t* quic)
{
    return quic->default_callback_fn;
}

void * picoquic_get_default_callback_context(picoquic_quic_t* quic)
{
    return quic->default_callback_ctx;
}

picoquic_stream_data_cb_fn picoquic_get_callback_function(picoquic_cnx_t * cnx)
{
    return cnx->callback_fn;
}

void * picoquic_get_callback_context(picoquic_cnx_t * cnx)
{
    return cnx->callback_ctx;
}

picoquic_misc_frame_header_t* picoquic_create_misc_frame(const uint8_t* bytes, size_t length) {
    uint8_t* misc_frame = (uint8_t*)malloc(sizeof(picoquic_misc_frame_header_t) + length);

    if (misc_frame == NULL) {
        return NULL;
    } else {
        picoquic_misc_frame_header_t* head = (picoquic_misc_frame_header_t*)misc_frame;
        head->length = length;
        memcpy(misc_frame + sizeof(picoquic_misc_frame_header_t), bytes, length);

        return head;
    }
}

int picoquic_queue_misc_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length)
{
    int ret = 0;
    picoquic_misc_frame_header_t* misc_frame = picoquic_create_misc_frame(bytes, length);

    if (misc_frame == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    } else {
        misc_frame->next_misc_frame = cnx->first_misc_frame;
        cnx->first_misc_frame = misc_frame;
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

void picoquic_clear_stream(picoquic_stream_head* stream)
{
    picoquic_stream_data** pdata[2];
    pdata[0] = &stream->stream_data;
    pdata[1] = &stream->send_queue;

    for (int i = 0; i < 2; i++) {
        picoquic_stream_data* next;

        while ((next = *pdata[i]) != NULL) {
            *pdata[i] = next->next_stream_data;

            if (next->bytes != NULL) {
                free(next->bytes);
            }
            free(next);
        }
    }
}

void picoquic_reset_packet_context(picoquic_cnx_t* cnx,
    picoquic_packet_context_enum pc)
{
    /* TODO: special case for 0-RTT packets! */
    picoquic_packet_context_t * pkt_ctx = &cnx->pkt_ctx[pc];

    while (pkt_ctx->retransmit_newest != NULL) {
        (void)picoquic_dequeue_retransmit_packet(cnx, pkt_ctx->retransmit_newest, 1);
    }
    
    while (pkt_ctx->retransmitted_newest != NULL) {
        picoquic_dequeue_retransmitted_packet(cnx, pkt_ctx->retransmitted_newest);
    }

    pkt_ctx->retransmitted_oldest = NULL;

    while (pkt_ctx->first_sack_item.next_sack != NULL) {
        picoquic_sack_item_t * next = pkt_ctx->first_sack_item.next_sack;
        pkt_ctx->first_sack_item.next_sack = next->next_sack;
        free(next);
    }

    pkt_ctx->first_sack_item.start_of_sack_range = (uint64_t)((int64_t)-1);
    pkt_ctx->first_sack_item.end_of_sack_range = 0;
}

/*
* Reset the version to a new supported value.
*
* Can only happen after sending the client init packet.
* Result of reset:
*
* - connection ID is not changed.
* - sequence number is not changed.
* - all queued 0-RTT retransmission will be considered lost (to do with 0-RTT)
* - Client Initial packet is considered lost, free. A new one will have to be formatted.
* - Stream 0 is reset, all data is freed.
* - TLS API is called again.
* - State changes.
*/

int picoquic_reset_cnx(picoquic_cnx_t* cnx, uint64_t current_time)
{
    int ret = 0;

    /* Delete the packets queued for retransmission */
    for (picoquic_packet_context_enum pc = 0;
        pc < picoquic_nb_packet_context; pc++) {
        /* Do not reset the application context, in order to keep the 0-RTT
         * packets, and to keep using the same sequence number space in
         * the new connection */
        if (pc != picoquic_packet_context_application) {
            picoquic_reset_packet_context(cnx, pc);
        }
    }

    /* Reset the crypto stream */
    for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
        picoquic_clear_stream(&cnx->tls_stream[epoch]);
        cnx->tls_stream[epoch].consumed_offset = 0;
        cnx->tls_stream[epoch].fin_offset = 0;
        cnx->tls_stream[epoch].sent_offset = 0;
        /* No need to reset the state flags, are they are not used for the crypto stream */
    }

    /* Reset the ECN data */
    cnx->ecn_ect0_total_local = 0;
    cnx->ecn_ect1_total_local = 0;
    cnx->ecn_ce_total_local = 0;
    cnx->ecn_ect0_total_remote = 0;
    cnx->ecn_ect1_total_remote = 0;
    cnx->ecn_ce_total_remote = 0;

    for (int k = 0; k < 4; k++) {
        picoquic_crypto_context_free(&cnx->crypto_context[k]);
    }

    picoquic_crypto_context_free(&cnx->crypto_context_new);

    ret = picoquic_setup_initial_traffic_keys(cnx);

    /* Reset the TLS context, Re-initialize the tls connection */
    if (cnx->tls_ctx != NULL) {
        picoquic_tlscontext_free(cnx->tls_ctx);
        cnx->tls_ctx = NULL;
    }
    if (ret == 0) {
        ret = picoquic_tlscontext_create(cnx->quic, cnx, current_time);
    }
    if (ret == 0) {
        ret = picoquic_initialize_tls_stream(cnx);
    }

    return ret;
}

int picoquic_reset_cnx_version(picoquic_cnx_t* cnx, uint8_t* bytes, size_t length, uint64_t current_time)
{
    /* First parse the incoming connection negotiation to choose the
	* new version. If none is available, return an error */
    size_t byte_index = 0;
    uint32_t proposed_version = 0;
    int ret = -1;

    if (cnx->cnx_state == picoquic_state_client_init || cnx->cnx_state == picoquic_state_client_init_sent) {
        while (cnx->cnx_state != picoquic_state_client_renegotiate && byte_index + 4 <= length) {
            /* parsing the list of proposed versions encoded in renegotiation packet */
            proposed_version = PICOPARSE_32(bytes + byte_index);
            byte_index += 4;

            for (size_t i = 0; i < picoquic_nb_supported_versions; i++) {
                if (proposed_version == picoquic_supported_versions[i].version) {
                    cnx->version_index = (int)i;
                    cnx->cnx_state = picoquic_state_client_renegotiate;
                    break;
                }
            }
        }

        if (cnx->cnx_state != picoquic_state_client_renegotiate) {
            /* No acceptable version */
            ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
        } else {
            ret = picoquic_reset_cnx(cnx, current_time);
        }
    }
    else {
        /* Not in a state for negotiation */
        ret = PICOQUIC_ERROR_UNEXPECTED_PACKET;
    }

    return ret;
}

int picoquic_connection_error(picoquic_cnx_t* cnx, uint16_t local_error, uint64_t frame_type)
{
    if (cnx->cnx_state == picoquic_state_ready || 
        cnx->cnx_state == picoquic_state_client_ready_start || cnx->cnx_state == picoquic_state_server_false_start) {
        cnx->local_error = local_error;
        cnx->cnx_state = picoquic_state_disconnecting;

        DBG_PRINTF("Protocol error (%x)", local_error);
    } else if (cnx->cnx_state < picoquic_state_server_false_start) {
        if (cnx->cnx_state != picoquic_state_handshake_failure) {
            cnx->local_error = local_error;
        }
        cnx->cnx_state = picoquic_state_handshake_failure;

        DBG_PRINTF("Protocol error %x", local_error);
    }

    cnx->offending_frame_type = frame_type;

    return PICOQUIC_ERROR_DETECTED;
}

int picoquic_start_key_rotation(picoquic_cnx_t* cnx)
{
    int ret = picoquic_compute_new_rotated_keys(cnx);

    if (ret == 0) {
        picoquic_apply_rotated_keys(cnx, 1);

        picoquic_crypto_context_free(&cnx->crypto_context_old);
    }

    return ret;
}

void picoquic_delete_cnx(picoquic_cnx_t* cnx)
{
    picoquic_stream_head* stream;
    picoquic_misc_frame_header_t* misc_frame;
    picoquic_cnxid_stash_t* stashed_cnxid;

    if (cnx != NULL) {
        if (cnx->cnx_state < picoquic_state_disconnected) {
            /* Give the application a chance to clean up its state */
            cnx->cnx_state = picoquic_state_disconnected;
            if (cnx->callback_fn) {
                (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx);
            }
        }

        if (cnx->alpn != NULL) {
            free((void*)cnx->alpn);
            cnx->alpn = NULL;
        }

        if (cnx->sni != NULL) {
            free((void*)cnx->sni);
            cnx->sni = NULL;
        }
        
        picoquic_remove_cnx_from_list(cnx);
        picoquic_remove_cnx_from_wake_list(cnx);

        for (int i = 0; i < 4; i++) {
            picoquic_crypto_context_free(&cnx->crypto_context[i]);
        }

        picoquic_crypto_context_free(&cnx->crypto_context_new);

        for (picoquic_packet_context_enum pc = 0;
            pc < picoquic_nb_packet_context; pc++) {
            picoquic_reset_packet_context(cnx, pc);
        }

        while ((misc_frame = cnx->first_misc_frame) != NULL) {
            cnx->first_misc_frame = misc_frame->next_misc_frame;
            free(misc_frame);
        }
        for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
            picoquic_clear_stream(&cnx->tls_stream[epoch]);
        }

        while ((stream = cnx->first_stream) != NULL) {
            cnx->first_stream = stream->next_stream;
            picoquic_clear_stream(stream);
            free(stream);
        }

        if (cnx->tls_ctx != NULL) {
            picoquic_tlscontext_free(cnx->tls_ctx);
            cnx->tls_ctx = NULL;
        }

        if (cnx->path != NULL)
        {
            while (cnx->nb_paths > 0) {
                picoquic_delete_path(cnx, cnx->nb_paths - 1);
            }

            free(cnx->path);
            cnx->path = NULL;
        }

        while ((stashed_cnxid = picoquic_dequeue_cnxid_stash(cnx)) != NULL) {
            free(stashed_cnxid);
        }

        while (cnx->probe_first != NULL) {
            picoquic_delete_probe(cnx, cnx->probe_first);
        }

        picoquic_close_cc_dump(cnx);

        free(cnx);
    }
}

int picoquic_is_handshake_error(uint16_t error_code)
{
    return ((error_code & 0xFF00) == PICOQUIC_TRANSPORT_CRYPTO_ERROR(0) ||
        error_code == PICOQUIC_TLS_HANDSHAKE_FAILED);
}

/* Context retrieval functions */
picoquic_cnx_t* picoquic_cnx_by_id(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_cnx_id_key_t key;

    memset(&key, 0, sizeof(key));
    key.cnx_id = cnx_id;

    item = picohash_retrieve(quic->table_cnx_by_id, &key);

    if (item != NULL) {
        ret = ((picoquic_cnx_id_key_t*)item->key)->cnx;
    }
    return ret;
}

picoquic_cnx_t* picoquic_cnx_by_net(picoquic_quic_t* quic, struct sockaddr* addr)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_net_id_key_t key;

    picoquic_set_hash_key_by_address(&key, addr);

    item = picohash_retrieve(quic->table_cnx_by_net, &key);

    if (item != NULL) {
        ret = ((picoquic_net_id_key_t*)item->key)->cnx;
    }
    return ret;
}

int picoquic_retrieve_by_cnx_id_or_net_id(picoquic_quic_t * quic, picoquic_connection_id_t * cnx_id, 
    struct sockaddr * addr, picoquic_cnx_t ** pcnx)
{
    if (cnx_id->id_len > 0) {
        *pcnx = picoquic_cnx_by_id(quic, *cnx_id);
    }
    else {
        *pcnx = picoquic_cnx_by_net(quic, addr);

        if (*pcnx != NULL && (*pcnx)->path[0]->local_cnxid.id_len != 0) {
            *pcnx = NULL;
        }
    }
    return 0;
}

/*
 * Set or reset the congestion control algorithm
 */

void picoquic_set_default_congestion_algorithm(picoquic_quic_t* quic, picoquic_congestion_algorithm_t const* alg)
{
    quic->default_congestion_alg = alg;
}

/*
 * Set the optimistic ack policy
 */

void picoquic_set_optimistic_ack_policy(picoquic_quic_t* quic, uint32_t sequence_hole_pseudo_period)
{
    quic->sequence_hole_pseudo_period = sequence_hole_pseudo_period;
}

void picoquic_set_congestion_algorithm(picoquic_cnx_t* cnx, picoquic_congestion_algorithm_t const* alg)
{
    if (cnx->congestion_alg != NULL) {
        if (cnx->path != NULL) {
            for (int i = 0; i < cnx->nb_paths; i++) {
                cnx->congestion_alg->alg_delete(cnx->path[i]);
            }
        }
    }

    cnx->congestion_alg = alg;

    if (cnx->congestion_alg != NULL) {
        if (cnx->path != NULL) {
            for (int i = 0; i < cnx->nb_paths; i++) {
                cnx->congestion_alg->alg_init(cnx->path[i]);
            }
        }
    }
}

void picoquic_enable_keep_alive(picoquic_cnx_t* cnx, uint64_t interval)
{
    if (interval == 0) {
        /* Examine the transport parameters */
        uint64_t idle_timeout = cnx->local_parameters.idle_timeout;

        if (cnx->cnx_state >= picoquic_state_client_ready_start && idle_timeout > cnx->remote_parameters.idle_timeout) {
            idle_timeout = cnx->remote_parameters.idle_timeout;
        }
        /* convert to microseconds */
        idle_timeout *= 1000000;
        /* set interval to half that value */
        cnx->keep_alive_interval = idle_timeout / 2;
    } else {
        cnx->keep_alive_interval = interval;
    }
}

void picoquic_disable_keep_alive(picoquic_cnx_t* cnx)
{
    cnx->keep_alive_interval = 0;
}

int picoquic_set_verify_certificate_callback(picoquic_quic_t* quic, picoquic_verify_certificate_cb_fn cb, void* ctx,
                                             picoquic_free_verify_certificate_ctx free_fn) {
    picoquic_dispose_verify_certificate_callback(quic, quic->verify_certificate_callback_fn != NULL);

    quic->verify_certificate_callback_fn = cb;
    quic->free_verify_certificate_callback_fn = free_fn;
    quic->verify_certificate_ctx = ctx;

    return picoquic_enable_custom_verify_certificate_callback(quic);
}

int picoquic_is_client(picoquic_cnx_t* cnx)
{
    return cnx->client_mode;
}

int picoquic_get_local_error(picoquic_cnx_t* cnx)
{
    return cnx->local_error;
}

int picoquic_get_remote_error(picoquic_cnx_t* cnx)
{
    return cnx->remote_error;
}

uint64_t picoquic_get_data_sent(picoquic_cnx_t* cnx)
{
    return cnx->data_sent;
}

uint64_t picoquic_get_data_received(picoquic_cnx_t* cnx)
{
    return cnx->data_received;
}

void picoquic_set_client_authentication(picoquic_quic_t* quic, int client_authentication) {
    picoquic_tls_set_client_authentication(quic, client_authentication);
}
