
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

#include "picoquic.h"
#include "picoquic_internal.h"
#include "logwriter.h"
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
    picoquic_local_cnxid_t* l_cid;
    struct st_picoquic_cnx_id_key_t* next_cnx_id;
} picoquic_cnx_id_key_t;

typedef struct st_picoquic_net_id_key_t {
    struct sockaddr_storage saddr;
    picoquic_cnx_t* cnx;
    picoquic_path_t* path;
    struct st_picoquic_net_id_key_t* next_net_id;
} picoquic_net_id_key_t;

typedef struct st_picoquic_net_icid_key_t {
    struct sockaddr_storage saddr;
    picoquic_connection_id_t icid;
    picoquic_cnx_t* cnx;
} picoquic_net_icid_key_t;

typedef struct st_picoquic_net_secret_key_t {
    struct sockaddr_storage saddr;
    uint8_t reset_secret[PICOQUIC_RESET_SECRET_SIZE];
    picoquic_cnx_t* cnx;
} picoquic_net_secret_key_t;

/* Hash and compare for CNX hash tables */
static uint64_t picoquic_cnx_id_hash(const void* key)
{
    const picoquic_cnx_id_key_t* cid = (const picoquic_cnx_id_key_t*)key;
    return picoquic_connection_id_hash(&cid->cnx_id);
}

static int picoquic_cnx_id_compare(const void* key1, const void* key2)
{
    const picoquic_cnx_id_key_t* cid1 = (const picoquic_cnx_id_key_t*)key1;
    const picoquic_cnx_id_key_t* cid2 = (const picoquic_cnx_id_key_t*)key2;

    return picoquic_compare_connection_id(&cid1->cnx_id, &cid2->cnx_id);
}

static uint64_t picoquic_net_id_hash(const void* key)
{
    const picoquic_net_id_key_t* net = (const picoquic_net_id_key_t*)key;

    // return picohash_bytes((uint8_t*)&net->saddr, sizeof(net->saddr));
    return picoquic_hash_addr((struct sockaddr*) & net->saddr);
}

static int picoquic_net_id_compare(const void* key1, const void* key2)
{
    const picoquic_net_id_key_t* net1 = (const picoquic_net_id_key_t*)key1;
    const picoquic_net_id_key_t* net2 = (const picoquic_net_id_key_t*)key2;

    return picoquic_compare_addr((struct sockaddr*) & net1->saddr, (struct sockaddr*) & net2->saddr);
}

static uint64_t picoquic_net_icid_hash(const void* key)
{
    const picoquic_net_icid_key_t* net_icid = (const picoquic_net_icid_key_t*)key;

    return picohash_hash_mix(picoquic_hash_addr((struct sockaddr*) & net_icid->saddr), 
        picoquic_connection_id_hash(&net_icid->icid));

}

static int picoquic_net_icid_compare(const void* key1, const void* key2)
{
    const picoquic_net_icid_key_t* net_icid1 = (const picoquic_net_icid_key_t*)key1;
    const picoquic_net_icid_key_t* net_icid2 = (const picoquic_net_icid_key_t*)key2;
    int ret = picoquic_compare_addr((struct sockaddr*) & net_icid1->saddr, (struct sockaddr*) & net_icid2->saddr);
    if (ret == 0) {
        ret = picoquic_compare_connection_id(&net_icid1->icid, &net_icid2->icid);
    }

    return ret;
}

static uint64_t picoquic_net_secret_hash(const void* key)
{
    const picoquic_net_secret_key_t* net_secret = (const picoquic_net_secret_key_t*)key;

    return picohash_hash_mix(picoquic_hash_addr((struct sockaddr*) & net_secret->saddr),
        picohash_bytes(net_secret->reset_secret, PICOQUIC_RESET_SECRET_SIZE));

}

static int picoquic_net_secret_compare(const void* key1, const void* key2)
{
    const picoquic_net_secret_key_t* net_secret1 = (const picoquic_net_secret_key_t*)key1;
    const picoquic_net_secret_key_t* net_secret2 = (const picoquic_net_secret_key_t*)key2;
    int ret = picoquic_compare_addr((struct sockaddr*) & net_secret1->saddr, (struct sockaddr*) & net_secret2->saddr);

    if (ret == 0) {
#ifdef PICOQUIC_USE_CONSTANT_TIME_MEMCMP
        ret = picoquic_constant_time_memcmp(net_secret1->reset_secret, net_secret2->reset_secret, PICOQUIC_RESET_SECRET_SIZE);
#else
        ret = memcmp(net_secret1->reset_secret, net_secret2->reset_secret, PICOQUIC_RESET_SECRET_SIZE);
#endif
    }
    return ret;
}

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

/* Token reuse management */

static int64_t picoquic_registered_token_compare(void* l, void* r)
{
    /* STream values are from 0 to 2^62-1, which means we are not worried with rollover */
    picoquic_registered_token_t* rt_l = (picoquic_registered_token_t*)l;
    picoquic_registered_token_t* rt_r = (picoquic_registered_token_t*)r;
    int64_t ret = rt_l->token_time - rt_r->token_time;
    if (ret == 0) {
        ret = rt_l->token_hash - rt_r->token_hash;
    }
    return ret;
}

static picosplay_node_t* picoquic_registered_token_create(void* value)
{
    return &((picoquic_registered_token_t*)value)->registered_token_node;
}


static void* picoquic_registered_token_value(picosplay_node_t* node)
{
    return (void*)((char*)node - offsetof(struct st_picoquic_registered_token_t, registered_token_node));
}

static void picoquic_registered_token_delete(void* tree, picosplay_node_t* node)
{
    picoquic_registered_token_t* rt = (picoquic_registered_token_t*)picoquic_registered_token_value(node);
    free(rt);
}

int picoquic_registered_token_check_reuse(picoquic_quic_t * quic,
    const uint8_t * token, size_t token_length, uint64_t expiry_time)
{
    int ret = -1;
    if (token_length >= 8) {
        picoquic_registered_token_t* rt = (picoquic_registered_token_t*)malloc(sizeof(picoquic_registered_token_t));
        if (rt != NULL) {
            picosplay_node_t* rt_n = NULL;
            memset(rt, 0, sizeof(picoquic_registered_token_t));
            rt->token_time = expiry_time;
            rt->token_hash = PICOPARSE_64(token + token_length - 8);
            rt->count = 1;
            rt_n = picosplay_find(&quic->token_reuse_tree, rt);
            if (rt_n != NULL) {
                free(rt);
                rt = (picoquic_registered_token_t*)picoquic_registered_token_value(rt_n);
                rt->count++;
                DBG_PRINTF("Token reuse detected, count=%d", rt->count);
            }
            else {
                (void)picosplay_insert(&quic->token_reuse_tree, rt);
                ret = 0;
            }
        }
    }

    return ret;
}

void picoquic_registered_token_clear(picoquic_quic_t* quic, uint64_t expiry_time_max)
{
    int end_reached = 0;
    do {
        picoquic_registered_token_t* rt_first = (picoquic_registered_token_t*)
            picoquic_registered_token_value(picosplay_first(&quic->token_reuse_tree));
        if (rt_first == NULL || rt_first->token_time >= expiry_time_max) {
            end_reached = 1;
        }
        else {
            picosplay_delete_hint(&quic->token_reuse_tree, &rt_first->registered_token_node);
        }
    } while (!end_reached);
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

static uint8_t picoquic_cleartext_draft_23_salt[] = {
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a,
    0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65,
    0xbe, 0xf9, 0xf5, 0x02
};

uint8_t picoquic_retry_protection_key_25[32] = {
    0x65, 0x6e, 0x61, 0xe3, 0x36, 0xae, 0x94, 0x17, 0xf7, 0xf0, 0xed, 0xd8, 0xd7, 0x8d, 0x46, 0x1e,
    0x2a, 0xa7, 0x08, 0x4a, 0xba, 0x7a, 0x14, 0xc1, 0xe9, 0xf7, 0x26, 0xd5, 0x57, 0x09, 0x16, 0x9a };

static uint8_t picoquic_cleartext_draft_29_salt[] = {
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c,
    0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0,
    0x43, 0x90, 0xa8, 0x99
};

uint8_t picoquic_retry_protection_key_29[32] = {
    0x8b, 0x0d, 0x37, 0xeb, 0x85, 0x35, 0x02, 0x2e, 0xbc, 0x8d, 0x76, 0xa2, 0x07, 0xd8, 0x0d, 0xf2,
    0x26, 0x46, 0xec, 0x06, 0xdc, 0x80, 0x96, 0x42, 0xc3, 0x0a, 0x8b, 0xaa, 0x2b, 0xaa, 0xff, 0x4c };

const picoquic_version_parameters_t picoquic_supported_versions[] = {
    { PICOQUIC_NINETEENTH_INTEROP_VERSION,
        sizeof(picoquic_cleartext_draft_29_salt),
        picoquic_cleartext_draft_29_salt,
        sizeof(picoquic_retry_protection_key_29),
        picoquic_retry_protection_key_29 },
    { PICOQUIC_EIGHTEENTH_INTEROP_VERSION,
        sizeof(picoquic_cleartext_draft_23_salt),
        picoquic_cleartext_draft_23_salt,
        sizeof(picoquic_retry_protection_key_25),
        picoquic_retry_protection_key_25 },
    { PICOQUIC_SEVENTEENTH_INTEROP_VERSION,
        sizeof(picoquic_cleartext_draft_23_salt),
        picoquic_cleartext_draft_23_salt,
        sizeof(picoquic_retry_protection_key_25),
        picoquic_retry_protection_key_25 },
    { PICOQUIC_INTERNAL_TEST_VERSION_2,
        sizeof(picoquic_cleartext_internal_test_1_salt),
        picoquic_cleartext_internal_test_1_salt, 
        sizeof(picoquic_retry_protection_key_25),
        picoquic_retry_protection_key_25},
    { PICOQUIC_INTERNAL_TEST_VERSION_1,
        sizeof(picoquic_cleartext_internal_test_1_salt),
        picoquic_cleartext_internal_test_1_salt,
        sizeof(picoquic_retry_protection_key_25),
        picoquic_retry_protection_key_25 }
};

const size_t picoquic_nb_supported_versions = sizeof(picoquic_supported_versions) / sizeof(picoquic_version_parameters_t);

/* Manage token reuse registry */


/* QUIC context create and dispose */
picoquic_quic_t* picoquic_create(uint32_t nb_connections,
    char const* cert_file_name,
    char const* key_file_name, 
    char const * cert_root_file_name,
    char const* default_alpn,
    picoquic_stream_data_cb_fn default_callback_fn,
    void* default_callback_ctx,
    picoquic_connection_id_cb_fn cnx_id_callback,
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
        quic->local_cnxid_length = 8; /* TODO: should be lower on clients-only implementation */
        quic->padding_multiple_default = 0; /* TODO: consider default = 128 */
        quic->padding_minsize_default = PICOQUIC_RESET_PACKET_MIN_SIZE;
        quic->crypto_epoch_length_max = PICOQUIC_DEFAULT_CRYPTO_EPOCH_LENGTH;

        if (cnx_id_callback != NULL) {
            quic->unconditional_cnx_id = 1;
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
                ret = 0;
            }
        }

        if (ret == 0) {
            quic->table_cnx_by_id = picohash_create((size_t)nb_connections * 4,
                picoquic_cnx_id_hash, picoquic_cnx_id_compare);

            quic->table_cnx_by_net = picohash_create((size_t)nb_connections * 4,
                picoquic_net_id_hash, picoquic_net_id_compare);

            quic->table_cnx_by_icid = picohash_create((size_t)nb_connections,
                picoquic_net_icid_hash, picoquic_net_icid_compare);

            quic->table_cnx_by_secret = picohash_create((size_t)nb_connections * 4,
                picoquic_net_secret_hash, picoquic_net_secret_compare);

            picosplay_init_tree(&quic->token_reuse_tree, picoquic_registered_token_compare,
                picoquic_registered_token_create, picoquic_registered_token_delete, picoquic_registered_token_value);

            if (quic->table_cnx_by_id == NULL || quic->table_cnx_by_net == NULL ||
                quic->table_cnx_by_icid == NULL || quic->table_cnx_by_secret == NULL) {
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
                 * resets and the retry tokens */

                if (!reset_seed)
                    picoquic_crypto_random(quic, quic->reset_seed, sizeof(quic->reset_seed));
                else
                    memcpy(quic->reset_seed, reset_seed, sizeof(quic->reset_seed));

                picoquic_crypto_random(quic, quic->retry_seed, sizeof(quic->retry_seed));

                /* If there is no root certificate context specified, use a null certifier. */
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

void picoquic_set_default_crypto_epoch_length(picoquic_quic_t* quic, uint64_t crypto_epoch_length_max)
{
    quic->crypto_epoch_length_max = (crypto_epoch_length_max == 0) ?
        PICOQUIC_DEFAULT_CRYPTO_EPOCH_LENGTH : crypto_epoch_length_max;
}

uint64_t picoquic_get_default_crypto_epoch_length(picoquic_quic_t* quic)
{
    return quic->crypto_epoch_length_max;
}

void picoquic_set_crypto_epoch_length(picoquic_cnx_t* cnx, uint64_t crypto_epoch_length_max)
{
    cnx->crypto_epoch_length_max = (crypto_epoch_length_max == 0) ?
        PICOQUIC_DEFAULT_CRYPTO_EPOCH_LENGTH : crypto_epoch_length_max;
}

uint64_t picoquic_get_crypto_epoch_length(picoquic_cnx_t* cnx)
{
    return cnx->crypto_epoch_length_max;
}


uint8_t picoquic_get_local_cid_length(picoquic_quic_t* quic)
{
    return quic->local_cnxid_length;
}

int picoquic_is_local_cid(picoquic_quic_t* quic, picoquic_connection_id_t* cid)
{
    return (cid->id_len == quic->local_cnxid_length &&
        picoquic_cnx_by_id(quic, *cid) != NULL);
}

void picoquic_free(picoquic_quic_t* quic)
{
    if (quic != NULL) {

        /* delete all the connection contexts -- do this before any other
         * action, as deleting connections may add packets to queues or
         * change connection lists */
        while (quic->cnx_list != NULL) {
            picoquic_delete_cnx(quic->cnx_list);
        }

        /* Delete TLS and AEAD cntexts */
        picoquic_delete_retry_protection_contexts(quic);

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

        /* Deelete the reused tokens tree */
        picosplay_empty_tree(&quic->token_reuse_tree);

        /* delete packets in pool */
        while (quic->p_first_packet != NULL) {
            picoquic_packet_t * p = quic->p_first_packet->next_packet;
            free(quic->p_first_packet);
            quic->p_first_packet = p;
        }

        /* delete all pending stateless packets */
        while (quic->pending_stateless_packet != NULL) {
            picoquic_stateless_packet_t* to_delete = quic->pending_stateless_packet;
            quic->pending_stateless_packet = to_delete->next_packet;
            free(to_delete);
        }

        if (quic->table_cnx_by_id != NULL) {
            picohash_delete(quic->table_cnx_by_id, 1);
        }

        if (quic->table_cnx_by_net != NULL) {
            picohash_delete(quic->table_cnx_by_net, 1);
        }

        if (quic->table_cnx_by_icid != NULL) {
            picohash_delete(quic->table_cnx_by_icid, 1);
        }

        if (quic->table_cnx_by_secret != NULL) {
            picohash_delete(quic->table_cnx_by_secret, 1);
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

        quic->binlog_dir = picoquic_string_free(quic->binlog_dir);
        quic->qlog_dir = picoquic_string_free(quic->qlog_dir);

        free(quic);
    }
}

void picoquic_set_null_verifier(picoquic_quic_t* quic) {
    picoquic_dispose_verify_certificate_callback(quic, 1);
}

void picoquic_set_cookie_mode(picoquic_quic_t* quic, int cookie_mode)
{
    if (cookie_mode&1) {
        quic->check_token = 1;
    } else {
        quic->check_token = 0;
    }

    if (cookie_mode & 2) {
        quic->provide_token = 1;
    }
    else {
        quic->provide_token = 0;
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

int picoquic_cnx_is_still_logging(picoquic_cnx_t* cnx)
{
    int ret =
        (cnx->pkt_ctx[picoquic_packet_context_application].send_sequence < PICOQUIC_LOG_PACKET_MAX_SEQUENCE || cnx->quic->use_long_log);

    return ret;
}

/* Connection context creation and registration */
int picoquic_register_cnx_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, picoquic_local_cnxid_t* l_cid)
{
    int ret = 0;
    picohash_item* item;
    picoquic_cnx_id_key_t* key = (picoquic_cnx_id_key_t*)malloc(sizeof(picoquic_cnx_id_key_t));

    if (key == NULL) {
        ret = -1;
    } else {
        key->cnx_id = l_cid->cnx_id;
        key->cnx = cnx;
        key->l_cid = l_cid;
        key->next_cnx_id = NULL;

        item = picohash_retrieve(quic->table_cnx_by_id, key);

        if (item != NULL) {
            ret = -1;
        } else {
            ret = picohash_insert(quic->table_cnx_by_id, key);

            if (ret == 0) {
                key->next_cnx_id = l_cid->first_cnx_id;
                l_cid->first_cnx_id = key;
            }
        }
    }

    return ret;
}

int picoquic_register_net_id(picoquic_quic_t* quic, picoquic_cnx_t* cnx, picoquic_path_t * path_x, struct sockaddr* addr)
{
    int ret = 0;
    picohash_item* item;
    picoquic_net_id_key_t* key = (picoquic_net_id_key_t*)malloc(sizeof(picoquic_net_id_key_t));

    if (key == NULL) {
        ret = -1;
    } else {
        memset(key, 0, sizeof(picoquic_net_id_key_t));
        picoquic_store_addr(&key->saddr, addr);

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

/* The initial CID and the reset secret are tracked in specific tables:
 *
 * - quic->table_cnx_by_icid: keyed by client address and initial CID. Created
 *   when the connection for the specified initial CID and address is created
 *   by the server (or the peer receiving the connection in P2P cases)
 * - quic->table_cnx_by_secret: keyed by peer address and reset secret for
 *   the default path of the connection (cnx->path[0]).
 *
 * In both cases, the address is that associated to the default path. The
 * path can be updated after migration, either by an address change or by
 * a change of CID and secret while keeping the address constant.
 *
 * If either the default address or the default reset secret changes, the
 * old table entry is updated to track the new address and secret. The
 * entry is kept up to date until the connection closes.
 *
 * Migration can only happen after a connection is established, but
 * packets could still arrive after that, maybe due to network delays.
 * In order to keep the design simple, the ICID entry is created once, and
 * kept for the duration of the connection.
 *
 * To facilitate management, the hash table keys are remembered in the
 * connection context as:
 *
 * - cnx->reset_secret_key
 * - cnx->net_icid_key
 */

int picoquic_register_net_icid(picoquic_cnx_t* cnx)
{
    int ret = 0;
    picohash_item* item;
    picoquic_net_icid_key_t* key = (picoquic_net_icid_key_t*)malloc(sizeof(picoquic_net_icid_key_t));

    if (key == NULL) {
        ret = -1;
    }
    else {
        memset(key, 0, sizeof(picoquic_net_icid_key_t));
        picoquic_store_addr(&key->saddr, (struct sockaddr *)&cnx->path[0]->peer_addr);
        key->icid = cnx->initial_cnxid;

        key->cnx = cnx;

        item = picohash_retrieve(cnx->quic->table_cnx_by_icid, key);

        if (item != NULL) {
            ret = -1;
        }
        else {
            ret = picohash_insert(cnx->quic->table_cnx_by_icid, key);

            if (ret == 0) {
                cnx->net_icid_key = key;
            }
        }
    }

    if (key != NULL && ret != 0) {
        free(key);
    }

    return ret;
}

int picoquic_register_net_secret(picoquic_cnx_t* cnx)
{
    int ret = 0;
    picohash_item* item;
    picoquic_net_secret_key_t* key = (picoquic_net_secret_key_t*)malloc(sizeof(picoquic_net_secret_key_t));

    if (key == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else {
        memset(key, 0, sizeof(picoquic_net_secret_key_t));
        picoquic_store_addr(&key->saddr, (struct sockaddr *)&cnx->path[0]->peer_addr);
        memcpy(key->reset_secret, cnx->path[0]->reset_secret, PICOQUIC_RESET_SECRET_SIZE);

        key->cnx = cnx;

        item = picohash_retrieve(cnx->quic->table_cnx_by_secret, key);

        if (item != NULL) {
            ret = -1;
        } 
        else {
            ret = picohash_insert(cnx->quic->table_cnx_by_secret, key);
            
            if (ret == 0) {
                if (cnx->reset_secret_key != NULL) {
                    picohash_delete_key(cnx->quic->table_cnx_by_secret, cnx->reset_secret_key, 1);
                }
                cnx->reset_secret_key = key;
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
        tp->initial_max_stream_id_bidir = 2049;
        tp->initial_max_stream_id_unidir = 2051;
    } else {
        tp->initial_max_stream_id_bidir = 2048;
        tp->initial_max_stream_id_unidir = 2050;
    }
    tp->idle_timeout = PICOQUIC_MICROSEC_HANDSHAKE_MAX/1000;
    tp->max_packet_size = PICOQUIC_PRACTICAL_MAX_MTU;
    tp->max_datagram_frame_size = 0;
    tp->ack_delay_exponent = 3;
    tp->active_connection_id_limit = PICOQUIC_NB_PATH_TARGET;
    tp->max_ack_delay = PICOQUIC_ACK_DELAY_MAX;
    tp->enable_loss_bit = 2;
    tp->min_ack_delay = PICOQUIC_ACK_DELAY_MIN;
    tp->enable_time_stamp = 0;
}


/* management of the list of connections in context */

picoquic_quic_t* picoquic_get_quic_ctx(picoquic_cnx_t* cnx)
{
    return (cnx == NULL)?NULL:cnx->quic;
}

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

    if (cnx->net_icid_key != NULL) {
        picohash_delete_key(cnx->quic->table_cnx_by_icid, cnx->net_icid_key, 1);
        cnx->net_icid_key = NULL;
    }

    if (cnx->reset_secret_key != NULL) {
        picohash_delete_key(cnx->quic->table_cnx_by_secret, cnx->reset_secret_key, 1);
        cnx->reset_secret_key = NULL;
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

uint64_t picoquic_get_next_wake_time(picoquic_quic_t* quic, uint64_t current_time)
{
    uint64_t wake_time = UINT64_MAX;

    if (quic->pending_stateless_packet != NULL) {
        wake_time = current_time;
    } else if (quic->cnx_wake_first != NULL) {
        wake_time = quic->cnx_wake_first->next_wake_time;
    }

    return wake_time;
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
        memset(cnx_id->id + id_length, 0, sizeof(cnx_id->id) - id_length);
    }
    cnx_id->id_len = id_length;
}

/* Path management -- returns the index of the path that was created. */

int picoquic_create_path(picoquic_cnx_t* cnx, uint64_t start_time, const struct sockaddr* local_addr, const struct sockaddr* peer_addr)
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
            picoquic_store_addr(&path_x->peer_addr, peer_addr);
            picoquic_store_addr(&path_x->local_addr, local_addr);

            /* Set the challenge used for this path */
            for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
                path_x->challenge[ichal] = picoquic_public_random_64();
            }

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
 * Register the path in the hash tables.
 * This only registers the address associated with the path.
 */
void picoquic_register_path(picoquic_cnx_t* cnx, picoquic_path_t * path_x)
{

    if (path_x->peer_addr.ss_family != 0) {
        (void)picoquic_register_net_id(cnx->quic, cnx, cnx->path[0], (struct sockaddr *)&path_x->peer_addr);
    }

    path_x->path_is_registered = 1;
}

/* To delete a path, we need to delete the data allocated to the path: search items in
 * the hash tables, and congestion algorithm context. Then delete the path data itself,
 * and finally remove the path reference from the table of paths in the connection
 * context.
 */

static void picoquic_clear_path_data(picoquic_cnx_t* cnx, picoquic_path_t * path_x) 
{
    while (path_x->first_net_id != NULL) {
        picohash_item* item;
        picoquic_net_id_key_t* net_id_key = path_x->first_net_id;
        path_x->first_net_id = net_id_key->next_net_id;
        net_id_key->next_net_id = NULL;

        item = picohash_retrieve(cnx->quic->table_cnx_by_net, net_id_key);
        if (item != NULL) {
            picohash_delete_item(cnx->quic->table_cnx_by_net, item, 1);
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

    if (cnx->quic->F_log != NULL) {
        fflush(cnx->quic->F_log);
    }
        
    /* Remove old path data from retransmit queue */
    for (picoquic_packet_context_enum pc = 0; pc < picoquic_nb_packet_context; pc++)
    {
        p = cnx->pkt_ctx[pc].retransmit_newest;

        while (p != NULL) {
            if (p->send_path == path_x) {
                DBG_PRINTF("Erase path for packet pc: %d, seq:%" PRIu64 "\n", pc, p->sequence_number);
                p->send_path = NULL;
            }
            p = p->next_packet;
        }

        p = cnx->pkt_ctx[pc].retransmitted_newest;
        while (p != NULL) {
            if (p->send_path == path_x) {
                DBG_PRINTF("Erase path for old packet pc: %d, seq:%" PRIu64 "\n", pc, p->sequence_number);
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
    unsigned int is_demotion_in_progress = 0;

    while (path_index_current < cnx->nb_paths) {
        if (cnx->path[path_index_current]->challenge_failed ||
            (cnx->path[path_index_current]->path_is_demoted &&
                current_time >= cnx->path[path_index_current]->demotion_time) ||
            (path_index_current > 0 && cnx->path[path_index_current]->challenge_verified &&
                cnx->path[path_index_current]->latest_sent_time + cnx->idle_timeout < current_time)) {
            /* Demote any failed path */
            if (!cnx->path[path_index_current]->path_is_demoted) {
                picoquic_demote_path(cnx, path_index_current, current_time);
            }
            /* Only increment the current index */
            is_demotion_in_progress |= cnx->path[path_index_current]->path_is_demoted;
            path_index_current++;
        } else {
            if (cnx->path[path_index_current]->path_is_demoted &&
                current_time < cnx->path[path_index_current]->demotion_time){
                is_demotion_in_progress |= 1;
                if (*next_wake_time > cnx->path[path_index_current]->demotion_time) {
                    *next_wake_time = cnx->path[path_index_current]->demotion_time;
                    SET_LAST_WAKE(cnx->quic, PICOQUIC_QUICCTX);
                }
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
        if (!picoquic_is_connection_id_null(&cnx->path[d_path]->remote_cnxid)) {
            (void)picoquic_queue_retire_connection_id_frame(cnx, cnx->path[d_path]->remote_cnxid_sequence);
        }
        picoquic_delete_path(cnx, d_path);
    }

    /* TODO: what if there are no paths left? */
    cnx->path_demotion_needed = is_demotion_in_progress;
}

/* 
 * Demote path, compute the effective time for demotion.
 */
void picoquic_demote_path(picoquic_cnx_t* cnx, int path_index, uint64_t current_time)
{
    if (!cnx->path[path_index]->path_is_demoted) {
        uint64_t demote_timer = cnx->path[path_index]->retransmit_timer;

        if (demote_timer < PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER) {
            demote_timer = PICOQUIC_INITIAL_MAX_RETRANSMIT_TIMER;
        }

        cnx->path[path_index]->path_is_demoted = 1;
        cnx->path[path_index]->demotion_time = current_time + 3* demote_timer;
        cnx->path_demotion_needed = 1;
    }
}

/* Promote path to default. This happens when a new path is verified, at the end
 * of a migration, and becomes the new default path.
 */

void picoquic_promote_path_to_default(picoquic_cnx_t* cnx, int path_index, uint64_t current_time)
{
    if (path_index > 0 && path_index < cnx->nb_paths) {
        picoquic_path_t * path_x = cnx->path[path_index];

        if (cnx->path[path_index]->path_is_preferred_path) {
            /* this is a migration to the preferred path requested by the server */
            if (cnx->client_mode) {
                cnx->remote_parameters.migration_disabled = 0;
            }
            else {
                cnx->local_parameters.migration_disabled = 0;
            }
        }

        if (cnx->quic->F_log != NULL || cnx->f_binlog != NULL) {
            char src_ip[128];
            char dst_ip[128];

            picoquic_log_app_message(cnx, "Path %d promoted to default at T=%fs, Local: %s, Remote: %s",
                path_index, (double)(current_time - cnx->start_time) / 1000000.0,
                picoquic_addr_text((struct sockaddr*) & cnx->path[path_index]->local_addr, src_ip, sizeof(src_ip)),
                picoquic_addr_text((struct sockaddr*) & cnx->path[path_index]->peer_addr, dst_ip, sizeof(dst_ip)));
        }

        /* Set the congestion algorithm for the new path */
        if (cnx->congestion_alg != NULL) {
            cnx->congestion_alg->alg_init(path_x, current_time);
        }

        /* Mark old path as demoted */
        picoquic_demote_path(cnx, 0, current_time);

        /* Swap */
        cnx->path[path_index] = cnx->path[0];
        cnx->path[0] = path_x;

        /* Update the secret */
        (void)picoquic_register_net_secret(cnx);
    }
}

/* Set or renew challenge for a path */
void picoquic_set_path_challenge(picoquic_cnx_t* cnx, int path_id, uint64_t current_time)
{
    if (!cnx->path[path_id]->challenge_required || cnx->path[path_id]->challenge_verified) {
        /* Reset the path challenge */
        cnx->path[path_id]->challenge_required = 1;
        for (int ichal = 0; ichal < PICOQUIC_CHALLENGE_REPEAT_MAX; ichal++) {
            cnx->path[path_id]->challenge[ichal] = picoquic_public_random_64();
        }
        cnx->path[path_id]->challenge_verified = 0;
        cnx->path[path_id]->challenge_time = current_time;
        cnx->path[path_id]->challenge_repeat_count = 0;
    }
}

/* Find path by address pair
 */
int picoquic_find_path_by_address(picoquic_cnx_t* cnx, const struct sockaddr* addr_to, 
    const struct sockaddr* addr_from, int * partial_match)
{
    int path_id = -1;
    int is_null_from = 0;
    struct sockaddr_storage null_addr;

    *partial_match = -1;

    if (addr_from != NULL || addr_to != NULL) {
        if (addr_from == NULL || addr_to == NULL) {
            memset(&null_addr, 0, sizeof(struct sockaddr_storage));
            if (addr_from == NULL) {
                addr_from = (struct sockaddr*) & null_addr;
            }
            else {
                addr_to = (struct sockaddr*) & null_addr;
            }
            is_null_from = 1;
        }

        /* Find whether an existing path matches the  pair of addresses */
        for (int i = 0; i < cnx->nb_paths; i++) {
            if (picoquic_compare_addr((struct sockaddr*) & cnx->path[i]->peer_addr,
                addr_from) == 0) {
                if (cnx->path[i]->local_addr.ss_family == 0) {
                    *partial_match = i;
                }
                else if (picoquic_compare_addr((struct sockaddr*) & cnx->path[i]->local_addr,
                    addr_to) == 0) {
                    path_id = i;
                    break;
                }
            }

            if (path_id < 0 && is_null_from) {
                path_id = *partial_match;
                *partial_match = -1;
            }
        }
    }

    return path_id;
}

/* Assign CID to path */
int picoquic_assign_peer_cnxid_to_path(picoquic_cnx_t* cnx, int path_id)
{
    int ret = -1;
    picoquic_cnxid_stash_t* available_cnxid = picoquic_dequeue_cnxid_stash(cnx);

    if (available_cnxid != NULL) {
        cnx->path[path_id]->remote_cnxid = available_cnxid->cnx_id;
        cnx->path[path_id]->remote_cnxid_sequence = available_cnxid->sequence;
        memcpy(cnx->path[path_id]->reset_secret, available_cnxid->reset_secret,
            PICOQUIC_RESET_SECRET_SIZE);
        free(available_cnxid);
        ret = 0;
    }

    return ret;
}

/* Create a new path in order to trigger a migration */
int picoquic_probe_new_path_ex(picoquic_cnx_t* cnx, const struct sockaddr* addr_from,
    const struct sockaddr* addr_to, uint64_t current_time, int to_preferred_address)
{
    int ret = 0;
    int partial_match_path = -1;
    int path_id = -1;

    if ((cnx->remote_parameters.migration_disabled && !to_preferred_address ) ||
        cnx->local_parameters.migration_disabled) {
        /* Do not create new paths if migration is disabled */
        ret = PICOQUIC_ERROR_MIGRATION_DISABLED;
        DBG_PRINTF("Tried to create probe with migration disabled = %d", cnx->remote_parameters.migration_disabled);
    }
    else if ((path_id = picoquic_find_path_by_address(cnx, addr_to, addr_from, &partial_match_path)) >= 0) {
        /* This path already exists. Will not create it, but will restore it in working order if disabled. */
        ret = -1;
    }
    else if (partial_match_path >= 0 && addr_from->sa_family == 0) {
        /* This path already exists. Will not create it, but will restore it in working order if disabled. */
        ret = -1;
    }
    else if (cnx->cnxid_stash_first == NULL) {
        /* No CNXID available yet. */
        ret = -1;
    }
    else if (cnx->nb_paths >= PICOQUIC_NB_PATH_TARGET) {
        /* Too many paths created already */
        ret = -1;
    }
    else if (picoquic_create_path(cnx, current_time, addr_to, addr_from) > 0) {
        path_id = cnx->nb_paths - 1;
        ret = picoquic_assign_peer_cnxid_to_path(cnx, path_id);

        if (ret != 0) {
            /* delete the path that was just created! */
            picoquic_delete_path(cnx, path_id);
        }
        else {
            cnx->path[path_id]->path_is_published = 1;
            picoquic_register_path(cnx, cnx->path[path_id]);
            picoquic_set_path_challenge(cnx, path_id, current_time);
            cnx->path[path_id]->path_is_preferred_path = to_preferred_address;
        }
    }

    return ret;
}

int picoquic_probe_new_path(picoquic_cnx_t* cnx, const struct sockaddr* addr_from,
    const struct sockaddr* addr_to, uint64_t current_time)
{
    return picoquic_probe_new_path_ex(cnx, addr_from, addr_to, current_time, 0);
}

/* Reset the path MTU, for example if too many packet losses are detected */
void picoquic_reset_path_mtu(picoquic_path_t* path_x)
{
    /* Re-initialize the MTU */
    path_x->send_mtu = (path_x->peer_addr.ss_family == 0 || path_x->peer_addr.ss_family == AF_INET) ?
        PICOQUIC_INITIAL_MTU_IPV4 : PICOQUIC_INITIAL_MTU_IPV6;
    /* Reset the MTU discovery context */
    path_x->send_mtu_max_tried = 0;
    path_x->mtu_probe_sent = 0;
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

int picoquic_enqueue_cnxid_stash(picoquic_cnx_t* cnx,
    const uint64_t sequence, const uint8_t cid_length, const uint8_t* cnxid_bytes,
    const uint8_t* secret_bytes, picoquic_cnxid_stash_t** pstashed)
{
    int ret = 0;
    int is_duplicate = 0;
    size_t nb_cid_received = 0;
    picoquic_connection_id_t cnx_id;
    picoquic_cnxid_stash_t* next_stash = cnx->cnxid_stash_first;
    picoquic_cnxid_stash_t* last_stash = NULL;
    picoquic_cnxid_stash_t* stashed = NULL;
    uint64_t cnxid_mask = 0;

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
        if (cnx->path[i]->remote_cnxid.id_len > 0) {
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
            else if (memcmp(secret_bytes, &cnx->path[i]->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
                DBG_PRINTF("Path %d, Cnx_id: %02x%02x%02x%02x..., Sequence %d vs. %d, same secret\n",
                    i, cnx_id.id[0], cnx_id.id[1], cnx_id.id[2], cnx_id.id[3],
                    (int)sequence, (int)cnx->path[i]->remote_cnxid_sequence);
                ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
            }
            else {
                if (!cnx->path[i]->path_is_demoted) {
                    uint64_t check = ((uint64_t)1) << cnx->path[i]->remote_cnxid_sequence;
                    if ((cnxid_mask & check) == 0) {
                        nb_cid_received++;
                        cnxid_mask |= check;
                    }
                }
            }
        }
    }
    
    while (ret == 0 && is_duplicate == 0 && next_stash != NULL) {
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
        else if (memcmp(secret_bytes, next_stash->reset_secret, PICOQUIC_RESET_SECRET_SIZE) == 0) {
            ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
        }
        else {
            nb_cid_received++;
        }
        last_stash = next_stash;
        next_stash = next_stash->next_in_stash;
    }

    if (ret == 0 && is_duplicate == 0) {
        if (nb_cid_received >= cnx->local_parameters.active_connection_id_limit) {
            ret = PICOQUIC_TRANSPORT_CONNECTION_ID_LIMIT_ERROR;
        }
        else {
            stashed = (picoquic_cnxid_stash_t*)malloc(sizeof(picoquic_cnxid_stash_t));

            if (stashed == NULL) {
                ret = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
            }
            else {
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
    }

    /* the return argument is only used in tests */

    if (pstashed != NULL) {
        *pstashed = stashed;
    }

    return ret;
}

int picoquic_remove_not_before_cid(picoquic_cnx_t* cnx, uint64_t not_before, uint64_t current_time)
{
    int ret = 0;
    picoquic_cnxid_stash_t * next_stash = cnx->cnxid_stash_first;
    picoquic_cnxid_stash_t * previous_stash = NULL;

    while (ret == 0 && next_stash != NULL) {
        if (next_stash->sequence < not_before) {
            ret = picoquic_queue_retire_connection_id_frame(cnx, next_stash->sequence);
            if (ret == 0){
                next_stash = next_stash->next_in_stash;
                if (previous_stash == NULL) {
                    cnx->cnxid_stash_first = next_stash;
                }
                else {
                    previous_stash->next_in_stash = next_stash;
                }
            }
        }
        else {
            previous_stash = next_stash;
            next_stash = next_stash->next_in_stash;
        }
    }

    /* We need to stop transmitting data to the old CID. But we cannot just delete
     * the correspondng paths,because there may be some data in transit. We must
     * also ensure that at least one default path migrates successfully to a
     * valid CID. As long as new CID are available, we can simply replace the
     * old one by a new one. If no CID is available, the old path should be marked
     * as failing, and thus scheduled for deletion after a time-out */

    for (int i = 0; ret == 0 && i < cnx->nb_paths; i++) {
        if (cnx->path[i]->remote_cnxid_sequence < not_before &&
            cnx->path[i]->remote_cnxid.id_len > 0 && 
            !cnx->path[i]->path_is_demoted) {
            ret = picoquic_renew_connection_id(cnx, i);
            if (ret != 0) {
                DBG_PRINTF("Renew CNXID returns %x\n", ret);
                if (i == 0) {
                    ret = PICOQUIC_TRANSPORT_PROTOCOL_VIOLATION;
                }
                else {
                    ret = 0;
                    picoquic_demote_path(cnx, i, current_time);
                }
            }
        }
    }

    return ret;
}

/* Start using a new connection ID for the existing path
 */
int picoquic_renew_path_connection_id(picoquic_cnx_t* cnx, picoquic_path_t* path_x)
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
            /* Count the references to the remote cnxid */
            int nb_cnxid_ref = 0;

            for (int i = 0; i < cnx->nb_paths; i++) {
                if (cnx->path[i]->remote_cnxid_sequence == path_x->remote_cnxid_sequence) {
                    nb_cnxid_ref++;
                }
            }

            if (nb_cnxid_ref <= 1) {
                /* if this was the last reference, retire the old cnxid */
                if (picoquic_queue_retire_connection_id_frame(cnx, path_x->remote_cnxid_sequence) != 0) {
                    DBG_PRINTF("Could not properly retire CID[%" PRIu64 "]", path_x->remote_cnxid_sequence);
                }
            }

            /* Install the new value */
            path_x->remote_cnxid = stashed->cnx_id;
            path_x->remote_cnxid_sequence = stashed->sequence;
            memcpy(path_x->reset_secret, stashed->reset_secret,
                PICOQUIC_RESET_SECRET_SIZE);
            free(stashed);

            /* If default path, reset the secret pointer */
            if (path_x == cnx->path[0]) {
                ret = picoquic_register_net_secret(cnx);
            }
        }
    }

    return ret;
}

int picoquic_renew_connection_id(picoquic_cnx_t* cnx, int path_id)
{
    int ret;

    if (path_id >= cnx->nb_paths) {
        ret = -1;
    }
    else {
        ret = picoquic_renew_path_connection_id(cnx, cnx->path[path_id]);
    }

    return ret;
}

/* stream data splay management */
int64_t picoquic_stream_data_node_compare(void* l, void* r)
{
    /* Offset values are from 0 to 2^62-1, which means we are not worried with rollover */
    return ((picoquic_stream_data_node_t*)l)->offset - ((picoquic_stream_data_node_t*)r)->offset;
}

picosplay_node_t* picoquic_stream_data_node_create(void* value)
{
    return &((picoquic_stream_data_node_t*)value)->stream_data_node;
}


void* picoquic_stream_data_node_value(picosplay_node_t* node)
{
    return (void*)((char*)node - offsetof(struct st_picoquic_stream_data_node_t, stream_data_node));
}


void picoquic_stream_data_node_delete(void* tree, picosplay_node_t* node)
{
    picoquic_stream_data_node_t* stream_data = (picoquic_stream_data_node_t*)picoquic_stream_data_node_value(node);

    if (stream_data->bytes != NULL) {
        free(stream_data->bytes);
        stream_data->bytes = NULL;
    }

    free(stream_data);
}

/* Stream splay management */

static int64_t picoquic_stream_node_compare(void *l, void *r)
{
    /* STream values are from 0 to 2^62-1, which means we are not worried with rollover */
    return ((picoquic_stream_head_t*)l)->stream_id - ((picoquic_stream_head_t*)r)->stream_id;
}

static picosplay_node_t * picoquic_stream_node_create(void * value)
{
    return &((picoquic_stream_head_t *)value)->stream_node;
}


static void * picoquic_stream_node_value(picosplay_node_t * node)
{
    return (void*)((char*)node - offsetof(struct st_picoquic_stream_head_t, stream_node));
}

void picoquic_clear_stream(picoquic_stream_head_t* stream)
{
    picoquic_stream_data_node_t* ready = stream->send_queue;
    picoquic_stream_data_node_t* next;

    while ((next = ready) != NULL) {
        ready = next->next_stream_data;

        if (next->bytes != NULL) {
            free(next->bytes);
        }
        free(next);
    }

    picosplay_empty_tree(&stream->stream_data_tree);

    while (stream->first_sack_item.next_sack != NULL) {
        picoquic_sack_item_t * sack = stream->first_sack_item.next_sack;
        stream->first_sack_item.next_sack = sack->next_sack;
        free(sack);
    }
}


static void picoquic_stream_node_delete(void * tree, picosplay_node_t * node)
{
    picoquic_stream_head_t * stream = picoquic_stream_node_value(node);

    picoquic_clear_stream(stream);

    free(stream);
}

/* Management of streams */

picoquic_stream_head_t * picoquic_stream_from_node(picosplay_node_t * node)
{
#ifdef TOO_CAUTIOUS
    return(picoquic_stream_head_t *)((node == NULL)?NULL:picoquic_stream_node_value(node));
#else
    return (picoquic_stream_head_t *)node;
#endif
}

picoquic_stream_head_t * picoquic_first_stream(picoquic_cnx_t* cnx)
{
#ifdef TOO_CAUTIOUS
    return picoquic_stream_from_node(picosplay_first(&cnx->stream_tree));
#else
    return (picoquic_stream_head_t *)picosplay_first(&cnx->stream_tree);
#endif
}

picoquic_stream_head_t * picoquic_last_stream(picoquic_cnx_t* cnx)
{
#ifdef TOO_CAUTIOUS
    return picoquic_stream_from_node(picosplay_last(&cnx->stream_tree));
#else
    return (picoquic_stream_head_t *)picosplay_last(&cnx->stream_tree);
#endif
}

void picoquic_insert_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t * stream)
{
    if (stream->is_output_stream == 0) {
        if (stream->stream_id == cnx->high_priority_stream_id) {
            /* insert in front */
            stream->previous_output_stream = NULL;
            stream->next_output_stream = cnx->first_output_stream;
            if (cnx->first_output_stream != NULL) {
                cnx->first_output_stream->previous_output_stream = stream;
            }
            cnx->first_output_stream = stream;
        } else {
            stream->previous_output_stream = cnx->last_output_stream;
            stream->next_output_stream = NULL;
            if (cnx->last_output_stream == NULL) {
                cnx->first_output_stream = stream;
                cnx->last_output_stream = stream;
            }
            else {
                cnx->last_output_stream->next_output_stream = stream;
                cnx->last_output_stream = stream;
            }
        }
        stream->is_output_stream = 1;
    }
}

void picoquic_remove_output_stream(picoquic_cnx_t* cnx, picoquic_stream_head_t * stream, picoquic_stream_head_t * previous_stream)
{
    if (stream->is_output_stream) {
        stream->is_output_stream = 0;

        if (stream->previous_output_stream == NULL) {
            cnx->first_output_stream = stream->next_output_stream;
        }
        else {
            stream->previous_output_stream->next_output_stream = stream->next_output_stream;
        }

        if (stream->next_output_stream == NULL) {
            cnx->last_output_stream = stream->previous_output_stream;
        }
        else {
            stream->next_output_stream->previous_output_stream = stream->previous_output_stream;
        }
    }
}

picoquic_stream_head_t * picoquic_next_stream(picoquic_stream_head_t * stream)
{
    return (picoquic_stream_head_t *)picosplay_next((picosplay_node_t *)stream);
}

picoquic_stream_head_t* picoquic_find_stream(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t target;
    target.stream_id = stream_id;

    return (picoquic_stream_head_t *)picosplay_find(&cnx->stream_tree, (void*)&target);
}

void picoquic_add_output_streams(picoquic_cnx_t* cnx, uint64_t old_limit, uint64_t new_limit, unsigned int is_bidir)
{
    uint64_t old_rank = STREAM_RANK_FROM_ID(old_limit);
    uint64_t first_new_id = STREAM_ID_FROM_RANK(old_rank + 1ull, !cnx->client_mode, !is_bidir);
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, first_new_id );

    while (stream) {
        if (stream->stream_id > old_limit) {
            if (stream->stream_id > new_limit) {
                break;
            }
            if (IS_LOCAL_STREAM_ID(stream->stream_id, cnx->client_mode) && IS_BIDIR_STREAM_ID(stream->stream_id) == is_bidir) {
                picoquic_insert_output_stream(cnx, stream);
            }
        }
        stream = picoquic_next_stream(stream);
    }
}

picoquic_stream_head_t* picoquic_create_stream(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    picoquic_stream_head_t* stream = (picoquic_stream_head_t*)malloc(sizeof(picoquic_stream_head_t));
    if (stream != NULL) {
        int is_output_stream = 0;
        memset(stream, 0, sizeof(picoquic_stream_head_t));
        stream->stream_id = stream_id;

        if (IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
            if (IS_BIDIR_STREAM_ID(stream_id)) {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_local;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_remote;
                is_output_stream = stream->stream_id <= cnx->max_stream_id_bidir_remote;

            }
            else {
                stream->maxdata_local = 0;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_uni;
                is_output_stream = stream->stream_id <= cnx->max_stream_id_unidir_remote;
            }
        }
        else {
            if (IS_BIDIR_STREAM_ID(stream_id)) {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_bidi_remote;
                stream->maxdata_remote = cnx->remote_parameters.initial_max_stream_data_bidi_local;
                is_output_stream = 1;
            }
            else {
                stream->maxdata_local = cnx->local_parameters.initial_max_stream_data_uni;
                stream->maxdata_remote = 0;
                is_output_stream = 0;
            }
        }

        picosplay_init_tree(&stream->stream_data_tree, picoquic_stream_data_node_compare, picoquic_stream_data_node_create, picoquic_stream_data_node_delete, picoquic_stream_data_node_value);

        picosplay_insert(&cnx->stream_tree, stream);
        if (is_output_stream) {
            picoquic_insert_output_stream(cnx, stream);
        }
        else {
            picoquic_remove_output_stream(cnx, stream, NULL);
            picoquic_delete_stream_if_closed(cnx, stream);
        }

        if (stream_id >= cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)]) {
            cnx->next_stream_id[STREAM_TYPE_FROM_ID(stream_id)] = NEXT_STREAM_ID_FOR_TYPE(stream_id);
        }
    }

    return stream;
}

void picoquic_delete_stream(picoquic_cnx_t * cnx, picoquic_stream_head_t* stream)
{
    picosplay_delete(&cnx->stream_tree, stream);
}

int picoquic_mark_direct_receive_stream(picoquic_cnx_t* cnx, uint64_t stream_id, picoquic_stream_direct_receive_fn direct_receive_fn, void* direct_receive_ctx)
{
    int ret = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    picoquic_stream_data_node_t* data;

    if (stream == NULL) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if (!IS_BIDIR_STREAM_ID(stream_id) && IS_LOCAL_STREAM_ID(stream_id, cnx->client_mode)) {
        ret = PICOQUIC_ERROR_INVALID_STREAM_ID;
    }
    else if (direct_receive_fn == NULL) {
        /* This is illegal! */
        ret = PICOQUIC_ERROR_NO_CALLBACK_PROVIDED;
    }
    else {
        stream->direct_receive_fn = direct_receive_fn;
        stream->direct_receive_ctx = direct_receive_ctx;
        /* If there is pending data, pass it. */
        while ((data = (picoquic_stream_data_node_t*)picosplay_first(&stream->stream_data_tree)) != NULL) {
            size_t length = data->length;
            uint64_t offset = data->offset;
            uint8_t* bytes = data->bytes;

            if (offset < stream->consumed_offset) {
                if (offset + length < stream->consumed_offset) {
                    length = 0;
                }
                else {
                    size_t delta_offset = (size_t)(stream->consumed_offset - offset);
                    length -= delta_offset;
                    offset += delta_offset;
                }
            }

            if (length > 0) {
                ret = direct_receive_fn(cnx, stream_id, 0, bytes, offset, length, direct_receive_ctx);
            }

            if (ret == 0) {
                picosplay_delete_hint(&stream->stream_data_tree, &data->stream_data_node);
            }
            else {
                break;
            }
        }

        /* If there is a fin offset, pass it. */
        if (ret == 0 && stream->fin_received && !stream->fin_signalled) {
            uint8_t fin_bytes[8];
            ret = direct_receive_fn(cnx, stream_id, 1, fin_bytes, stream->fin_offset, 0, direct_receive_ctx);
        }
    }

    return ret;
}


/* Management of local CID.
 * Local CID are created and registered on demand.
 */

picoquic_local_cnxid_t* picoquic_create_local_cnxid(picoquic_cnx_t* cnx, picoquic_connection_id_t* suggested_value)
{
    picoquic_local_cnxid_t* l_cid = NULL;
    int is_unique = 0;

    l_cid = (picoquic_local_cnxid_t*)malloc(sizeof(picoquic_local_cnxid_t));

    if (l_cid != NULL) {
        memset(l_cid, 0, sizeof(picoquic_local_cnxid_t));
        if (cnx->quic->local_cnxid_length == 0) {
            is_unique = 1;
        }
        else {
            for (int i = 0; i < 32; i++) {
                if (i == 0 && suggested_value != NULL) {
                    l_cid->cnx_id = *suggested_value;
                }
                else {
                    picoquic_create_random_cnx_id(cnx->quic, &l_cid->cnx_id, cnx->quic->local_cnxid_length);

                    if (cnx->quic->cnx_id_callback_fn) {
                        cnx->quic->cnx_id_callback_fn(cnx->quic, l_cid->cnx_id, cnx->initial_cnxid,
                            cnx->quic->cnx_id_callback_ctx, &l_cid->cnx_id);
                    }
                }

                if (picoquic_cnx_by_id(cnx->quic, l_cid->cnx_id) == NULL) {
                    is_unique = 1;
                    break;
                }
            }
        }

        if (is_unique) {
            picoquic_local_cnxid_t* previous = NULL;
            picoquic_local_cnxid_t* next = cnx->local_cnxid_first;

            while (next != NULL) {
                previous = next;
                next = next->next;
            }

            if (previous == NULL) {
                cnx->local_cnxid_first = l_cid;
            }
            else {
                previous->next = l_cid;
            }

            l_cid->sequence = cnx->local_cnxid_sequence_next++;
            cnx->nb_local_cnxid++;

            if (cnx->quic->local_cnxid_length > 0) {
                picoquic_register_cnx_id(cnx->quic, cnx, l_cid);
            }
        }
        else {
            free(l_cid);
            l_cid = NULL;
        }
    }

    return l_cid;
}

void picoquic_delete_local_cnxid(picoquic_cnx_t* cnx, picoquic_local_cnxid_t* l_cid)
{
    picoquic_local_cnxid_t* previous = NULL;
    picoquic_local_cnxid_t* next = cnx->local_cnxid_first;


    /* Set l_cid references to NULL in path contexts */
    for (int i = 0; i < cnx->nb_paths; i++) {
        if (cnx->path[i]->p_local_cnxid == l_cid) {
            cnx->path[i]->p_local_cnxid = NULL;
        }
    }

    /* Remove from list */
    while (next != NULL) {
        if (next == l_cid) {
            if (previous == NULL) {
                cnx->local_cnxid_first = next->next;
            }
            else {
                previous->next = next->next;
            }
            cnx->nb_local_cnxid--;
            break;
        }
        else {
            previous = next;
            next = next->next;
        }
    }

    if (l_cid->cnx_id.id_len > 0) {
        /* Remove the registration in hash tables */
        if (l_cid->first_cnx_id != NULL) {
            picohash_item* item;
            picoquic_cnx_id_key_t* cnx_id_key = l_cid->first_cnx_id;

            item = picohash_retrieve(cnx->quic->table_cnx_by_id, cnx_id_key);
            if (item != NULL) {
                picohash_delete_item(cnx->quic->table_cnx_by_id, item, 1);
            }

            l_cid->first_cnx_id = NULL;
        }
    }

    /* Delete and done */
    free(l_cid);
}

void picoquic_retire_local_cnxid(picoquic_cnx_t* cnx, uint64_t sequence)
{
    picoquic_local_cnxid_t* local_cnxid = cnx->local_cnxid_first;

    while (local_cnxid != NULL) {
        if (local_cnxid->sequence == sequence) {
            break;
        }
        else {
            local_cnxid = local_cnxid->next;
        }
    }

    if (local_cnxid != NULL) {
        picoquic_delete_local_cnxid(cnx, local_cnxid);
    }
}

picoquic_local_cnxid_t* picoquic_find_local_cnxid(picoquic_cnx_t* cnx, picoquic_connection_id_t* cnxid)
{
    picoquic_local_cnxid_t* local_cnxid = cnx->local_cnxid_first;

    while (local_cnxid != NULL) {
        if (picoquic_compare_connection_id(&local_cnxid->cnx_id, cnxid) == 0) {
            break;
        }
        else {
            local_cnxid = local_cnxid->next;
        }
    }
    
    return local_cnxid;
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
        picoquic_local_cnxid_t* cnxid0;

        memset(cnx, 0, sizeof(picoquic_cnx_t));
        cnx->start_time = start_time;
        cnx->client_mode = client_mode;
        if (client_mode) {
            if (picoquic_is_connection_id_null(&initial_cnx_id)) {
                picoquic_create_random_cnx_id(quic, &initial_cnx_id, 8);
            }
        }
        cnx->initial_cnxid = initial_cnx_id;
        cnx->quic = quic;
        /* Create the connection ID number 0 */
        cnxid0 = picoquic_create_local_cnxid(cnx, NULL);
        
        /* Should return 0, since this is the first path */
        ret = picoquic_create_path(cnx, start_time, NULL, addr_to);

        if (ret != 0 || cnxid0 == NULL) {
            free(cnx);
            cnx = NULL;
        } else {
            cnx->next_wake_time = start_time;
            SET_LAST_WAKE(quic, PICOQUIC_QUICCTX);
            picoquic_insert_cnx_in_list(quic, cnx);
            picoquic_insert_cnx_by_wake_time(quic, cnx);
            /* Do not require verification for default path */
            cnx->path[0]->p_local_cnxid = cnxid0;
            cnx->path[0]->challenge_verified = 1;

            cnx->high_priority_stream_id = (uint64_t)((int64_t)-1);
            for (int i = 0; i < 4; i++) {
                cnx->next_stream_id[i] = i;
            }
            picoquic_register_path(cnx, cnx->path[0]);
        }
    }

    if (cnx != NULL) {
        if (quic->default_tp == NULL) {
            picoquic_init_transport_parameters(&cnx->local_parameters, cnx->client_mode);
        } else {
            memcpy(&cnx->local_parameters, quic->default_tp, sizeof(picoquic_tp_t));
            /* If the default parameters include preferred address, document it */
            if (cnx->local_parameters.prefered_address.is_defined) {
                /* Create an additional CID */
                picoquic_local_cnxid_t* cnxid1 = picoquic_create_local_cnxid(cnx, NULL);
                if (cnxid1 != NULL){
                    /* copy the connection ID into the local parameter */
                    cnx->local_parameters.prefered_address.connection_id = cnxid1->cnx_id;
                    /* Create the reset secret */
                    (void)picoquic_create_cnxid_reset_secret(cnx->quic, &cnxid1->cnx_id,
                        cnx->local_parameters.prefered_address.statelessResetToken);
                }
            }
        }
        /* If local connection ID size is null, don't allow migration */
        if (quic->local_cnxid_length == 0) {
            cnx->local_parameters.migration_disabled = 1;
        }

        if (cnx->quic->mtu_max > 0)
        {
            cnx->local_parameters.max_packet_size = cnx->quic->mtu_max;
        }

        /* Initialize local flow control variables to advertised values */
        cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data);
        cnx->max_stream_id_bidir_local = cnx->local_parameters.initial_max_stream_id_bidir;
        cnx->max_stream_id_bidir_local_computed = STREAM_TYPE_FROM_ID(cnx->local_parameters.initial_max_stream_id_bidir);
        cnx->max_stream_id_unidir_local = cnx->local_parameters.initial_max_stream_id_unidir;
        cnx->max_stream_id_unidir_local_computed = STREAM_TYPE_FROM_ID(cnx->local_parameters.initial_max_stream_id_unidir);

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
        else if (cnx->spin_policy == picoquic_spinbit_on) {
            /* Option used in test to avoid randomizing spin bit on/off */
            cnx->spin_policy = picoquic_spinbit_basic;
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

        /* Initialize key rotation interval to default value */
        cnx->crypto_epoch_length_max = quic->crypto_epoch_length_max;

        /* Perform different initializations for clients and servers */
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

            if (!quic->is_cert_store_not_empty || sni == NULL) {
                /* This is a hack. The open SSL certifier crashes if no name is specified,
                 * and always fails if no certificate is stored, so we just use a NULL verifier */
                DBG_PRINTF("%s -- certificate will not be verified.\n",
                    (sni == NULL) ? "No server name specified" : "No root crt list specified");

                picoquic_set_null_verifier(quic);
            }
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
        }

        cnx->latest_progress_time = start_time;

        for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
            cnx->tls_stream[epoch].stream_id = 0;
            cnx->tls_stream[epoch].consumed_offset = 0;
            cnx->tls_stream[epoch].fin_offset = 0;
            cnx->tls_stream[epoch].stream_node.left = NULL;
            cnx->tls_stream[epoch].stream_node.parent = NULL;
            cnx->tls_stream[epoch].stream_node.right = NULL;
            cnx->tls_stream[epoch].sent_offset = 0;
            cnx->tls_stream[epoch].local_error = 0;
            cnx->tls_stream[epoch].remote_error = 0;
            cnx->tls_stream[epoch].maxdata_local = (uint64_t)((int64_t)-1);
            cnx->tls_stream[epoch].maxdata_remote = (uint64_t)((int64_t)-1);

            picosplay_init_tree(&cnx->tls_stream[epoch].stream_data_tree, picoquic_stream_data_node_compare, picoquic_stream_data_node_create, picoquic_stream_data_node_delete, picoquic_stream_data_node_value);

            /* No need to reset the state flags, as they are not used for the crypto stream */
        }
        
        cnx->ack_frequency_sequence_local = (uint64_t)((int64_t)-1);
        cnx->ack_gap_local = 2;
        cnx->ack_frequency_delay_local = PICOQUIC_ACK_DELAY_MAX_DEFAULT;
        cnx->ack_frequency_sequence_remote = (uint64_t)((int64_t)-1);
        cnx->ack_gap_remote = 2;
        cnx->ack_delay_remote = PICOQUIC_ACK_DELAY_MAX_DEFAULT;

        picosplay_init_tree(&cnx->stream_tree, picoquic_stream_node_compare, picoquic_stream_node_create, picoquic_stream_node_delete, picoquic_stream_node_value);

        cnx->congestion_alg = cnx->quic->default_congestion_alg;
        if (cnx->congestion_alg != NULL) {
            cnx->congestion_alg->alg_init(cnx->path[0], start_time);
        }
    }

    /* Only initialize TLS after all parameters have been set */
    if (cnx != NULL && picoquic_tlscontext_create(quic, cnx, start_time) != 0) {
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

    if (cnx != NULL && !client_mode && quic->local_cnxid_length > 0) {
        if (picoquic_register_net_icid(cnx) != 0) {
            DBG_PRINTF("%s", "Could not register the ICID in table.\n");
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }

    if (cnx != NULL) {
        binlog_new_connection(cnx);
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
        ret = picoquic_initialize_tls_stream(cnx, picoquic_get_quic_time(quic));
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
    int ret = picoquic_initialize_tls_stream(cnx, picoquic_get_quic_time(cnx->quic));
    /* A remote session ticket may have been loaded as part of initializing TLS,
     * and remote parameters may have been initialized to the initial value
     * of the previous session. Apply these new parameters. */
    cnx->maxdata_remote = cnx->remote_parameters.initial_max_data;
    cnx->max_stream_id_bidir_remote = cnx->remote_parameters.initial_max_stream_id_bidir;
    cnx->max_stream_id_unidir_remote = cnx->remote_parameters.initial_max_stream_id_unidir;

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

picoquic_tp_t const* picoquic_get_transport_parameters(picoquic_cnx_t* cnx, int get_local)
{
    return(get_local) ? &cnx->local_parameters : &cnx->remote_parameters;
}

void picoquic_get_peer_addr(picoquic_cnx_t* cnx, struct sockaddr** addr)
{
    *addr = (struct sockaddr*)&cnx->path[0]->peer_addr;
}

void picoquic_get_local_addr(picoquic_cnx_t* cnx, struct sockaddr** addr)
{
    *addr = (struct sockaddr*)&cnx->path[0]->local_addr;
}

unsigned long picoquic_get_local_if_index(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->if_index_dest;
}

picoquic_connection_id_t picoquic_get_local_cnxid(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->p_local_cnxid->cnx_id;
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
    return (cnx->client_mode)?cnx->path[0]->p_local_cnxid->cnx_id : cnx->path[0]->remote_cnxid;
}

picoquic_connection_id_t picoquic_get_server_cnxid(picoquic_cnx_t* cnx)
{
    return (cnx->client_mode) ? cnx->path[0]->remote_cnxid : cnx->path[0]->p_local_cnxid->cnx_id;
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
    return (cnx->crypto_context[picoquic_epoch_0rtt].aead_encrypt == NULL) ? 0 : 1;
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

void picoquic_cnx_set_pmtud_required(picoquic_cnx_t* cnx, int is_pmtud_required)
{
    cnx->is_pmtud_required = is_pmtud_required;
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
    GetSystemTimePreciseAsFileTime(&ft);

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

void picoquic_connection_id_callback(picoquic_quic_t * quic, picoquic_connection_id_t cnx_id_local, picoquic_connection_id_t cnx_id_remote, void * cnx_id_cb_data, picoquic_connection_id_t * cnx_id_returned)
{
    picoquic_connection_id_callback_ctx_t* ctx = (picoquic_connection_id_callback_ctx_t*)cnx_id_cb_data;

    quic->local_cnxid_length = ctx->cnx_id_val.id_len;

    /* Initialize with either random value or */
    memset(cnx_id_returned, 0, sizeof(picoquic_connection_id_t));
    if (ctx->cnx_id_select == picoquic_connection_id_remote) {
        /* Keeping this for compatibility with old buggy version */
        cnx_id_local = cnx_id_remote;
    } else {
        /* setting value to random data */
        picoquic_public_random(cnx_id_local.id, quic->local_cnxid_length);
    }
    cnx_id_local.id_len = quic->local_cnxid_length;

    /* Apply substitution under mask */
    for (uint8_t i = 0; i < cnx_id_local.id_len; i++) {
        cnx_id_returned->id[i] = (cnx_id_local.id[i] & ctx->cnx_id_mask.id[i]) | ctx->cnx_id_val.id[i];
    }
    cnx_id_returned->id_len = quic->local_cnxid_length;

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
    default:
        /* Leave it unencrypted */
        break;
    }
}

picoquic_connection_id_callback_ctx_t * picoquic_connection_id_callback_create_ctx(
    char const * select_type, char const * default_value_hex, char const * mask_hex)
{
    picoquic_connection_id_callback_ctx_t* ctx = (picoquic_connection_id_callback_ctx_t*)
        malloc(sizeof(picoquic_connection_id_callback_ctx_t));

    if (ctx != NULL) {
        size_t lv, lm;
        memset(ctx, 0, sizeof(picoquic_connection_id_callback_ctx_t));
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

void picoquic_connection_id_callback_free_ctx(void * cnx_id_cb_data)
{
    picoquic_connection_id_callback_ctx_t* ctx = (picoquic_connection_id_callback_ctx_t*)cnx_id_cb_data;

    if (ctx != NULL && ctx->cid_enc != NULL) {
        switch (ctx->cnx_id_select) {
        case picoquic_connection_id_encrypt_basic:
            /* encryption under mask */
            picoquic_cid_free_under_mask_ctx(ctx->cid_enc);
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

int picoquic_set_binlog(picoquic_quic_t * quic, char const * binlog_dir)
{
    quic->binlog_dir = picoquic_string_free(quic->binlog_dir);
    quic->binlog_dir = picoquic_string_duplicate(binlog_dir);
    return 0;
}

int picoquic_set_textlog(picoquic_quic_t* quic, char const* textlog_file)
{
    int ret = 0;
    FILE* F_log;

    if (quic->F_log != NULL && quic->should_close_log) {
        (void)picoquic_file_close(quic->F_log);
        quic->F_log = NULL;
    }

    if (textlog_file != NULL) {
        F_log = picoquic_file_open(textlog_file, "w");
        if (F_log == NULL) {
            DBG_PRINTF("Cannot create log file <%s>\n", textlog_file);
            ret = -1;
        }
        else {
            quic->F_log = F_log;
            quic->should_close_log = 1;
        }
    }

    return ret;
}

void picoquic_set_log_level(picoquic_quic_t* quic, int log_level)
{
    /* Only two level for now: log first 100 packets, or log everything. */
    quic->use_long_log = (log_level > 0) ? 1 : 0;
}

int picoquic_set_default_connection_id_length(picoquic_quic_t* quic, uint8_t cid_length)
{
    int ret = 0;

    if (cid_length != quic->local_cnxid_length) {
        if (cid_length > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
            ret = PICOQUIC_ERROR_CNXID_CHECK;
        }
        else if (quic->cnx_list != NULL) {
            ret = PICOQUIC_ERROR_CANNOT_CHANGE_ACTIVE_CONTEXT;
        }
        else {
            quic->local_cnxid_length = cid_length;
        }
    }

    return ret;
}

void picoquic_set_mtu_max(picoquic_quic_t* quic, uint32_t mtu_max)
{
    quic->mtu_max = mtu_max;
}

void picoquic_set_alpn_select_fn(picoquic_quic_t* quic, picoquic_alpn_select_fn alpn_select_fn)
{
    if (quic->default_alpn != NULL) {
        free((void *)quic->default_alpn);
        quic->default_alpn = NULL;
    }
    quic->alpn_select_fn = alpn_select_fn;
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

picoquic_misc_frame_header_t* picoquic_create_misc_frame(const uint8_t* bytes, size_t length, int is_pure_ack)
{
    size_t l_alloc = sizeof(picoquic_misc_frame_header_t) + length;

    if (l_alloc < sizeof(picoquic_misc_frame_header_t)) {
        return NULL;
    }
    else {
        picoquic_misc_frame_header_t* head = (picoquic_misc_frame_header_t*)malloc(l_alloc);
        if (head != NULL) {
            memset(head, 0, sizeof(picoquic_misc_frame_header_t));
            head->length = length;
            head->is_pure_ack = is_pure_ack;
            memcpy(((uint8_t *)head) + sizeof(picoquic_misc_frame_header_t), bytes, length);
        }
        return head;
    }
}

int picoquic_queue_misc_or_dg_frame(picoquic_cnx_t * cnx, picoquic_misc_frame_header_t** first, 
    picoquic_misc_frame_header_t** last, const uint8_t* bytes, size_t length, int is_pure_ack)
{
    int ret = 0;
    picoquic_misc_frame_header_t* misc_frame = picoquic_create_misc_frame(bytes, length, is_pure_ack);

    if (misc_frame == NULL) {
        ret = PICOQUIC_ERROR_MEMORY;
    } else {
        if (*last == NULL) {
            *first = misc_frame;
            *last = misc_frame;
        }
        else {
            (*last)->next_misc_frame = misc_frame;
            misc_frame->previous_misc_frame = *last;
            *last = misc_frame;
        }
    }

    picoquic_reinsert_by_wake_time(cnx->quic, cnx, picoquic_get_quic_time(cnx->quic));

    return ret;
}

int picoquic_queue_misc_frame(picoquic_cnx_t* cnx, const uint8_t* bytes, size_t length, int is_pure_ack)
{
    return picoquic_queue_misc_or_dg_frame(cnx, &cnx->first_misc_frame, &cnx->last_misc_frame, bytes, length, is_pure_ack);
}

void picoquic_delete_misc_or_dg(picoquic_misc_frame_header_t** first, picoquic_misc_frame_header_t** last, picoquic_misc_frame_header_t* frame)
{
    if (frame->next_misc_frame) {
        frame->next_misc_frame->previous_misc_frame = frame->previous_misc_frame;
    }
    else {
        *last = frame->previous_misc_frame;
    }

    if (frame->previous_misc_frame) {
        frame->previous_misc_frame->next_misc_frame = frame->next_misc_frame;
    }
    else {
        *first = frame->next_misc_frame;
    }

    free(frame);
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
    /* Reset the ECN data */
    pkt_ctx->ecn_ect0_total_local = 0;
    pkt_ctx->ecn_ect1_total_local = 0;
    pkt_ctx->ecn_ce_total_local = 0;
    pkt_ctx->ecn_ect0_total_remote = 0;
    pkt_ctx->ecn_ect1_total_remote = 0;
    pkt_ctx->ecn_ce_total_remote = 0;
}

/*
* Reset the connection after an incoming retry packet.
*
* Can only happen after sending the client init packet.
* Result of reset:
*
* - connection ID is not changed.
* - sequence number is not changed.
* - all queued 0-RTT retransmission will be considered lost (to do with 0-RTT)
* - Client Initial packet is considered lost, free. A new one will have to be formatted.
* - TLS stream is reset, all TLS data is freed.
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

    binlog_new_connection(cnx);

    if (ret == 0) {
        ret = picoquic_tlscontext_create(cnx->quic, cnx, current_time);
    }
    if (ret == 0) {
        ret = picoquic_initialize_tls_stream(cnx, current_time);
    }

    return ret;
}

int picoquic_connection_error(picoquic_cnx_t* cnx, uint16_t local_error, uint64_t frame_type)
{
    if (cnx->cnx_state == picoquic_state_ready || 
        cnx->cnx_state == picoquic_state_client_ready_start || cnx->cnx_state == picoquic_state_server_false_start) {
        if (local_error > PICOQUIC_ERROR_CLASS) {
            cnx->local_error = PICOQUIC_TRANSPORT_INTERNAL_ERROR;
        }
        else {
            cnx->local_error = local_error;
        }
        cnx->cnx_state = picoquic_state_disconnecting;

        picoquic_log_app_message(cnx, "Protocol error 0x%x", local_error);
        DBG_PRINTF("Protocol error (%x)", local_error);
    } else if (cnx->cnx_state < picoquic_state_server_false_start) {
        if (cnx->cnx_state != picoquic_state_handshake_failure &&
            cnx->cnx_state != picoquic_state_handshake_failure_resend) {
            cnx->local_error = local_error;
            cnx->cnx_state = picoquic_state_handshake_failure;

            DBG_PRINTF("Protocol error %x", local_error);
        }
    }

    cnx->offending_frame_type = frame_type;

    return PICOQUIC_ERROR_DETECTED;
}

int picoquic_start_key_rotation(picoquic_cnx_t* cnx)
{
    int ret = 0;

    /* Verify that a packet of the previous rotation was acked*/
    if (cnx->cnx_state != picoquic_state_ready ||
        cnx->crypto_epoch_sequence >
        cnx->pkt_ctx[picoquic_packet_context_application].first_sack_item.end_of_sack_range) {
        ret = PICOQUIC_ERROR_KEY_ROTATION_NOT_READY;
    }
    else {
        ret = picoquic_compute_new_rotated_keys(cnx);
    }

    if (ret == 0) {
        picoquic_apply_rotated_keys(cnx, 1);
        picoquic_crypto_context_free(&cnx->crypto_context_old);
        cnx->crypto_epoch_sequence = cnx->pkt_ctx[picoquic_packet_context_application].send_sequence;
    }

    return ret;
}

void picoquic_delete_sooner_packets(picoquic_cnx_t* cnx)
{
    picoquic_stateless_packet_t* packet = cnx->first_sooner;

    while (packet != NULL) {
        picoquic_stateless_packet_t* next_packet = packet->next_packet;
        picoquic_delete_stateless_packet(packet);
        packet = next_packet;
    }
    cnx->first_sooner = NULL;
}

void picoquic_delete_cnx(picoquic_cnx_t* cnx)
{
    picoquic_cnxid_stash_t* stashed_cnxid;

    if (cnx != NULL) {
        binlog_close_connection(cnx);

        if (cnx->cnx_state < picoquic_state_disconnected) {
            /* Give the application a chance to clean up its state */
            cnx->cnx_state = picoquic_state_disconnected;
            if (cnx->callback_fn) {
                (void)(cnx->callback_fn)(cnx, 0, NULL, 0, picoquic_callback_close, cnx->callback_ctx, NULL);
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

        if (cnx->retry_token != NULL) {
            free(cnx->retry_token);
            cnx->retry_token = NULL;
        }

        picoquic_delete_sooner_packets(cnx);

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

        while (cnx->first_misc_frame != NULL) {
            picoquic_delete_misc_or_dg(&cnx->first_misc_frame, &cnx->last_misc_frame, cnx->first_misc_frame);
        }

        while (cnx->first_datagram != NULL) {
            picoquic_delete_misc_or_dg(&cnx->first_datagram, &cnx->last_datagram, cnx->first_datagram);
        }

        for (int epoch = 0; epoch < PICOQUIC_NUMBER_OF_EPOCHS; epoch++) {
            picoquic_clear_stream(&cnx->tls_stream[epoch]);
        }

        picosplay_empty_tree(&cnx->stream_tree);

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

        while (cnx->local_cnxid_first != NULL) {
            picoquic_delete_local_cnxid(cnx, cnx->local_cnxid_first);
        }

        while ((stashed_cnxid = picoquic_dequeue_cnxid_stash(cnx)) != NULL) {
            free(stashed_cnxid);
        }

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

    memset(&key, 0, sizeof(key));
    picoquic_store_addr(&key.saddr, addr);

    item = picohash_retrieve(quic->table_cnx_by_net, &key);

    if (item != NULL) {
        ret = ((picoquic_net_id_key_t*)item->key)->cnx;
    }
    return ret;
}

picoquic_cnx_t* picoquic_cnx_by_icid(picoquic_quic_t* quic, picoquic_connection_id_t* icid,
    struct sockaddr* addr)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_net_icid_key_t key;

    memset(&key, 0, sizeof(key));
    picoquic_store_addr(&key.saddr, addr);
    key.icid = *icid;

    item = picohash_retrieve(quic->table_cnx_by_icid, &key);

    if (item != NULL) {
        ret = ((picoquic_net_icid_key_t*)item->key)->cnx;
    }
    return ret;
}

picoquic_cnx_t* picoquic_cnx_by_secret(picoquic_quic_t* quic, uint8_t* reset_secret, struct sockaddr* addr)
{
    picoquic_cnx_t* ret = NULL;
    picohash_item* item;
    picoquic_net_secret_key_t key;

    memset(&key, 0, sizeof(key));
    picoquic_store_addr(&key.saddr, addr);
    memcpy(key.reset_secret, reset_secret, PICOQUIC_RESET_SECRET_SIZE);

    item = picohash_retrieve(quic->table_cnx_by_secret, &key);

    if (item != NULL) {
        ret = ((picoquic_net_secret_key_t*)item->key)->cnx;
    }
    return ret;
}

/* Get congestion control algorithm by name */
picoquic_congestion_algorithm_t const* picoquic_get_congestion_algorithm(char const* alg_name)
{
    picoquic_congestion_algorithm_t const* alg = NULL;
    if (alg_name != NULL) {
        if (strcmp(alg_name, "reno") == 0) {
            alg = picoquic_newreno_algorithm;
        }
        else if (strcmp(alg_name, "cubic") == 0) {
            alg = picoquic_cubic_algorithm;
        }
        else if (strcmp(alg_name, "dcubic") == 0) {
            alg = picoquic_dcubic_algorithm;
        }
        else if (strcmp(alg_name, "fast") == 0) {
            alg = picoquic_fastcc_algorithm;
        }
        else if (strcmp(alg_name, "bbr") == 0) {
            alg = picoquic_bbr_algorithm;
        }
        else {
            alg = NULL;
        }
    }
    return alg;
}
/*
 * Set or reset the congestion control algorithm
 */

void picoquic_set_default_congestion_algorithm(picoquic_quic_t* quic, picoquic_congestion_algorithm_t const* alg)
{
    quic->default_congestion_alg = alg;
}

void picoquic_set_default_congestion_algorithm_by_name(picoquic_quic_t* quic, char const * alg_name)
{
    quic->default_congestion_alg = picoquic_get_congestion_algorithm(alg_name);
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
                cnx->congestion_alg->alg_init(cnx->path[i], picoquic_get_quic_time(cnx->quic));
            }
        }
    }
}

void picoquic_subscribe_pacing_rate_updates(picoquic_cnx_t* cnx, uint64_t decrease_threshold, uint64_t increase_threshold)
{
    cnx->pacing_decrease_threshold = decrease_threshold;
    cnx->pacing_increase_threshold = increase_threshold;
    cnx->is_pacing_update_requested = (decrease_threshold != UINT64_MAX || increase_threshold != UINT64_MAX);
}

uint64_t picoquic_get_pacing_rate(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->pacing_rate;
}

uint64_t picoquic_get_cwin(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->cwin;
}

uint64_t picoquic_get_rtt(picoquic_cnx_t* cnx)
{
    return cnx->path[0]->smoothed_rtt;
}

int picoquic_set_local_addr(picoquic_cnx_t* cnx, struct sockaddr* addr)
{
    int ret = 0;

    if (cnx != NULL && cnx->path[0] != NULL && cnx->path[0]->local_addr.ss_family == 0) {
        picoquic_store_addr(&cnx->path[0]->local_addr, addr);
        ret = (cnx->path[0]->local_addr.ss_family == 0) ? -1 : 0;
    }
    else {
        ret = -1;
    }

    return ret;
}

void picoquic_enable_keep_alive(picoquic_cnx_t* cnx, uint64_t interval)
{
    if (interval == 0) {
        /* Use the negotiated value */
        uint64_t idle_timeout = cnx->idle_timeout;
        /* Ensure at least 3 PTO*/
        if (idle_timeout < 3 * cnx->path[0]->retransmit_timer) {
            idle_timeout = 3 * cnx->path[0]->retransmit_timer;
        }
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

uint64_t picoquic_get_remote_stream_error(picoquic_cnx_t* cnx, uint64_t stream_id)
{
    uint64_t remote_error = 0;
    picoquic_stream_head_t* stream = picoquic_find_stream(cnx, stream_id);
    if (stream != NULL) {
        remote_error = stream->remote_error;
    }
    return remote_error;
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

/* Load balancer support is defined in https://datatracker.ietf.org/doc/draft-ietf-quic-load-balancers/
 * The draft defines methods for encoding a server ID in a connection identifier, and optionally
 * obfuscating or encrypting the CID value. The CID are generated by the individual servers,
 * based on configuration options provided by the load balancer. The draft also defines
 * methods for generating retry tokens either by a protection box colocated with the
 * load balancer, or at the individual server, with methods for letting individual
 * servers retrieve information from the tokens.
 */

static void picoquic_lb_compat_cid_generate_clear(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t * lb_ctx, picoquic_connection_id_t* cnx_id_returned)
{
    cnx_id_returned->id[0] = lb_ctx->first_byte;
    memcpy(cnx_id_returned->id + 1, lb_ctx->server_id, lb_ctx->server_id_length);
}

static void picoquic_lb_compat_cid_generate_obfuscated(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t* cnx_id_returned)
{
    uint64_t obfuscation_max = (UINT64_MAX - lb_ctx->server_id64) / lb_ctx->divider;
    uint64_t obfuscator = 0;
    uint64_t obfuscated;

    cnx_id_returned->id[0] = lb_ctx->first_byte;
    for (size_t i = 0; i < lb_ctx->routing_bits_length; i++) {
        obfuscator <<= 8;
        obfuscator += cnx_id_returned->id[i + 1];
        obfuscator %= obfuscation_max;
    }
    obfuscated = obfuscator* lb_ctx->divider;
    obfuscated += lb_ctx->server_id64;

    for (size_t i = 0; i < lb_ctx->routing_bits_length; i++) {
        size_t j = lb_ctx->routing_bits_length - i; /* varies from lb_ctx->routing_bits_length to 1 */
        cnx_id_returned->id[j] = (uint8_t)obfuscated;
        obfuscated >>= 8;
    }
}

static void picoquic_lb_compat_cid_one_pass_stream(void * enc_ctx, uint8_t * nonce, size_t nonce_length, uint8_t * target, size_t target_length)
{
    uint8_t mask[16];
    /* Set the obfuscation value */
    memset(mask, 0, sizeof(mask));
    memcpy(mask, nonce, nonce_length);
    /* Encrypt with ECB */
    picoquic_aes128_ecb_encrypt(enc_ctx, mask, mask, sizeof(mask));
    /* Apply the mask */
    for (size_t i = 0; i < target_length; i++) {
        target[i] ^= mask[i];
    }
}

static void picoquic_lb_compat_cid_generate_stream_cipher(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t* cnx_id_returned)
{
    size_t id_offset = 1 + lb_ctx->nonce_length;
    /* Prepare a clear text server ID */
    cnx_id_returned->id[0] = lb_ctx->first_byte;
    memcpy(cnx_id_returned->id + id_offset, lb_ctx->server_id, lb_ctx->server_id_length);
    /* First pass -- obtain intermediate server ID */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, cnx_id_returned->id + 1, lb_ctx->nonce_length,
        cnx_id_returned->id + id_offset, lb_ctx->server_id_length);
    /* Second pass -- obtain encrypted nonce */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, 
        cnx_id_returned->id + id_offset, lb_ctx->server_id_length,
        cnx_id_returned->id + 1, lb_ctx->nonce_length);
    /* Third pass -- obtain encrypted server-id */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, cnx_id_returned->id + 1, lb_ctx->nonce_length,
        cnx_id_returned->id + id_offset, lb_ctx->server_id_length);
}

static void picoquic_lb_compat_cid_generate_block_cipher(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t* cnx_id_returned)
{
    cnx_id_returned->id[0] = lb_ctx->first_byte;
    /* Copy the server ID */
    memcpy(cnx_id_returned->id + 1, lb_ctx->server_id, lb_ctx->server_id_length);
    /* Set the zeropad value */
    memset(cnx_id_returned->id + 1 + lb_ctx->server_id_length, 0, lb_ctx->zero_pad_length);
    /* encrypt 16 bytes */
    picoquic_aes128_ecb_encrypt(lb_ctx->cid_encryption_context, cnx_id_returned->id + 1, cnx_id_returned->id + 1, 16);
    cnx_id_returned->id[0] = lb_ctx->first_byte;
}

void picoquic_lb_compat_cid_generate(picoquic_quic_t* quic, picoquic_connection_id_t cnx_id_local,
    picoquic_connection_id_t cnx_id_remote, void* cnx_id_cb_data, picoquic_connection_id_t* cnx_id_returned)
{
    picoquic_load_balancer_cid_context_t* lb_ctx = (picoquic_load_balancer_cid_context_t*)cnx_id_cb_data;
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(cnx_id_local);
    UNREFERENCED_PARAMETER(cnx_id_remote);
#endif
    switch (lb_ctx->method) {
    case picoquic_load_balancer_cid_clear:
        picoquic_lb_compat_cid_generate_clear(quic, lb_ctx, cnx_id_returned);
        break;
    case picoquic_load_balancer_cid_obfuscated:
        picoquic_lb_compat_cid_generate_obfuscated(quic, lb_ctx, cnx_id_returned);
        break;
    case picoquic_load_balancer_cid_stream_cipher:
        picoquic_lb_compat_cid_generate_stream_cipher(quic, lb_ctx, cnx_id_returned);
        break;
    case picoquic_load_balancer_cid_block_cipher:
        picoquic_lb_compat_cid_generate_block_cipher(quic, lb_ctx, cnx_id_returned);
        break;
    default:
        /* Error, unknown method */
        break;
    }
}

static uint64_t picoquic_lb_compat_cid_verify_clear(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t const* cnx_id)
{
    uint64_t s_id64 = 0;

    for (size_t i = 0; i < lb_ctx->server_id_length; i++) {
        s_id64 <<= 8;
        s_id64 += cnx_id->id[i + 1];
    }

    return s_id64;
}

static uint64_t picoquic_lb_compat_cid_verify_obfuscated(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t const* cnx_id)
{
    uint64_t s_id64 = 0;

    for (size_t i = 0; i < lb_ctx->routing_bits_length; i++) {
        s_id64 <<= 8;
        s_id64 += cnx_id->id[i + 1];
        s_id64 %= lb_ctx->divider;
    }

    return s_id64;
}

static uint64_t picoquic_lb_compat_cid_verify_stream_cipher(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t const* cnx_id)
{
    size_t id_offset = 1 + lb_ctx->nonce_length;
    uint64_t s_id64 = 0;
    picoquic_connection_id_t target = *cnx_id;
    /* First pass -- obtain intermediate server ID */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, target.id + 1, lb_ctx->nonce_length,
        target.id + id_offset, lb_ctx->server_id_length);
    /* Second pass -- obtain nonce */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context,
        target.id + id_offset, lb_ctx->server_id_length, target.id + 1, lb_ctx->nonce_length);
    /* First pass -- obtain server-id */
    picoquic_lb_compat_cid_one_pass_stream(lb_ctx->cid_encryption_context, target.id + 1, lb_ctx->nonce_length,
        target.id + id_offset, lb_ctx->server_id_length);

    /* decode the server ID */
    for (size_t i = 0; i < lb_ctx->server_id_length; i++) {
        s_id64 <<= 8;
        s_id64 += target.id[id_offset + i];
    }

    return s_id64;
}

static uint64_t picoquic_lb_compat_cid_verify_block_cipher(picoquic_quic_t* quic,
    picoquic_load_balancer_cid_context_t* lb_ctx, picoquic_connection_id_t const* cnx_id)
{
    uint8_t decoded[16];
    uint64_t s_id64 = 0;

    /* decrypt 16 bytes */
    picoquic_aes128_ecb_encrypt(lb_ctx->cid_decryption_context, decoded, cnx_id->id + 1, 16);

    /* Check that the nonce is all zeros */
    for (size_t i = 0; i < lb_ctx->zero_pad_length; i++) {
        if (decoded[i + lb_ctx->server_id_length] != 0) {
            s_id64 = UINT64_MAX;
            break;
        }
    }
    /* Decode the server ID */
    if (s_id64 == 0) {
        for (size_t i = 0; i < lb_ctx->server_id_length; i++) {
            s_id64 <<= 8;
            s_id64 += decoded[i];
        }
    }

    return s_id64;
}

uint64_t picoquic_lb_compat_cid_verify(picoquic_quic_t* quic, void* cnx_id_cb_data, picoquic_connection_id_t const* cnx_id)
{
    picoquic_load_balancer_cid_context_t* lb_ctx = (picoquic_load_balancer_cid_context_t*)cnx_id_cb_data;
    uint64_t server_id64;

    if (cnx_id->id_len != lb_ctx->connection_id_length) {
        server_id64 = UINT64_MAX;
    }
    else {
        switch (lb_ctx->method) {
        case picoquic_load_balancer_cid_clear:
            server_id64 = picoquic_lb_compat_cid_verify_clear(quic, lb_ctx, cnx_id);
            break;
        case picoquic_load_balancer_cid_obfuscated:
            server_id64 = picoquic_lb_compat_cid_verify_obfuscated(quic, lb_ctx, cnx_id);
            break;
        case picoquic_load_balancer_cid_stream_cipher:
            server_id64 = picoquic_lb_compat_cid_verify_stream_cipher(quic, lb_ctx, cnx_id);
            break;
        case picoquic_load_balancer_cid_block_cipher:
            server_id64 = picoquic_lb_compat_cid_verify_block_cipher(quic, lb_ctx, cnx_id);
            break;
        default:
            /* Error, unknown method */
            server_id64 = UINT64_MAX;
            break;
        }
    }

    return server_id64;
}

int picoquic_lb_compat_cid_config(picoquic_quic_t* quic, picoquic_load_balancer_config_t * lb_config)
{
    int ret = 0;

    if (quic->cnx_list != NULL && quic->local_cnxid_length != lb_config->connection_id_length) {
        /* Error. Changing the CID length now will break existing connections */
        ret = -1;
    }
    else if (quic->cnx_id_callback_fn != NULL && quic->cnx_id_callback_ctx != NULL){
        /* Error. Some other CID generation is configured, cannot be changed */
        ret = -1;
    }
    else {
        /* Verify that the method is supported and the parameters are compatible.
         * If valid, configure the connection ID generation */
        if (lb_config->connection_id_length > PICOQUIC_CONNECTION_ID_MAX_SIZE) {
            ret = -1;
        }
        else {
            switch (lb_config->method) {
            case picoquic_load_balancer_cid_clear:
                /* Require at least 2 bytes to make the CID unique */
                if (lb_config->server_id_length + 1 + 2 > lb_config->connection_id_length) {
                    ret = -1;
                }
                break;
            case picoquic_load_balancer_cid_obfuscated:
                /* Require at least 2 bytes to obfuscate the server CID,
                 * cannot handle undivided values larger than 8 bytes */
                if (lb_config->routing_bits_length + 1 > lb_config->connection_id_length ||
                    lb_config->server_id_length + 2 > lb_config->routing_bits_length ||
                    lb_config->routing_bits_length > 8 ||
                    lb_config->divider == 0) {
                    ret = -1;
                }
                break;
            case picoquic_load_balancer_cid_stream_cipher:
                /* Nonce length must be 8 to 16 bytes, CID should be long enough */
                if (lb_config->nonce_length < 8 || lb_config->nonce_length > 16 ||
                    lb_config->nonce_length + lb_config->server_id_length + 1 > lb_config->connection_id_length) {
                    ret = -1;
                }
                break;
            case picoquic_load_balancer_cid_block_cipher:
                /* CID should include a whole AES-ECB block,
                 * there should be at least 2 bytes available for uniqueness,
                 * zero padding length should be 4 bytes for security */
                if (lb_config->connection_id_length < 17 ||
                    lb_config->server_id_length + lb_config->zero_pad_length + 1 + 2 > lb_config->connection_id_length ||
                    lb_config->zero_pad_length < 4 ) {
                    ret = -1;
                }
                break;
            default:
                /* Error, unknown method */
                ret = -1;
                break;
            }
        }
        if (ret == 0) {
            /* Create a copy */
            picoquic_load_balancer_cid_context_t* lb_ctx = (picoquic_load_balancer_cid_context_t*)malloc(sizeof(picoquic_load_balancer_cid_context_t));

            if (lb_ctx == NULL) {
                ret = -1;
            }
            else {
                /* if allocated, create the necessary encryption contexts or variables */
                uint64_t s_id64 = lb_config->server_id64;
                memset(lb_ctx, 0, sizeof(picoquic_load_balancer_cid_context_t));
                lb_ctx->method = lb_config->method;
                lb_ctx->server_id_length = lb_config->server_id_length;
                lb_ctx->routing_bits_length = lb_config->routing_bits_length;
                lb_ctx->nonce_length = lb_config->nonce_length;
                lb_ctx->zero_pad_length = lb_config->zero_pad_length;
                lb_ctx->connection_id_length = lb_config->connection_id_length;
                lb_ctx->first_byte = lb_config->first_byte;
                lb_ctx->server_id64 = lb_config->server_id64;
                lb_ctx->divider = lb_config->divider;
                lb_ctx->cid_encryption_context = NULL;
                lb_ctx->cid_decryption_context = NULL;
                /* Compute the server ID bytes and set encryption contexts */
                for (size_t i = 0; i < lb_ctx->server_id_length; i++) {
                    size_t j = lb_ctx->server_id_length - i - 1;
                    lb_ctx->server_id[j] = (uint8_t)s_id64;
                    s_id64 >>= 8;
                }
                if (s_id64 != 0) {
                    /* Server ID not long enough to encode actual value */
                    ret = -1;
                } else if (lb_config->method == picoquic_load_balancer_cid_stream_cipher ||
                    lb_config->method == picoquic_load_balancer_cid_block_cipher) {
                    lb_ctx->cid_encryption_context = picoquic_aes128_ecb_create(1, lb_config->cid_encryption_key);
                    if (lb_ctx->cid_encryption_context == NULL) {
                        ret = -1;
                    }
                    else if (lb_config->method == picoquic_load_balancer_cid_block_cipher) {
                        lb_ctx->cid_decryption_context = picoquic_aes128_ecb_create(0, lb_config->cid_encryption_key);
                        if (lb_ctx->cid_decryption_context == NULL) {
                            picoquic_aes128_ecb_free(lb_ctx->cid_encryption_context);
                            lb_ctx->cid_encryption_context = NULL;
                            ret = -1;
                        }
                    }
                }
                if (ret != 0) {
                    /* if context allocation failed, free the copy */
                    free(lb_ctx);
                    lb_ctx = NULL;
                } else {
                    /* Configure the CID generation */
                    quic->local_cnxid_length = lb_ctx->connection_id_length;
                    quic->cnx_id_callback_fn = picoquic_lb_compat_cid_generate;
                    quic->cnx_id_callback_ctx = (void*)lb_ctx;
                }
            }
        }
    }

    return ret;
}

void picoquic_lb_compat_cid_config_free(picoquic_quic_t* quic)
{
    if (quic->cnx_id_callback_fn == picoquic_lb_compat_cid_generate &&
        quic->cnx_id_callback_ctx != NULL) {
        picoquic_load_balancer_config_t* lb_config = (picoquic_load_balancer_config_t*)quic->cnx_id_callback_ctx;
        /* Release the encryption contexts so as to avoid memory leaks */
        /* Free the data */
        free(lb_config);
        /* Reset the Quic context */
        quic->cnx_id_callback_fn = NULL;
        quic->cnx_id_callback_ctx = NULL;
    }
}