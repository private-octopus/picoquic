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

#include <stdlib.h>
#include <string.h>
#include "picoquic_internal.h"
#include "tls_api.h"

/*
 * Default congestion algorithm
 */
extern picoquic_congestion_algorithm_t * picoquic_newreno_algorithm;

#define PICOQUIC_DEFAULT_CONGESTION_ALGORITHM picoquic_newreno_algorithm;

/*
* Structures used in the hash table of connections
*/
typedef struct st_picoquic_cnx_id_t
{
    uint64_t cnx_id;
    picoquic_cnx_t * cnx;
    struct st_picoquic_cnx_id_t * next_cnx_id;
} picoquic_cnx_id;

typedef struct st_picoquic_net_id_t
{
    struct sockaddr_storage saddr;
    picoquic_cnx_t * cnx;
    struct st_picoquic_net_id_t * next_net_id;
} picoquic_net_id;

/* Hash and compare for CNX hash tables */
static uint64_t picoquic_cnx_id_hash(void * key)
{
    picoquic_cnx_id * cid = (picoquic_cnx_id *)key;

    /* TODO: should scramble the value for security and DOS protection */

    return cid->cnx_id;
}

static int picoquic_cnx_id_compare(void * key1, void * key2)
{
    picoquic_cnx_id * cid1 = (picoquic_cnx_id *)key1;
    picoquic_cnx_id * cid2 = (picoquic_cnx_id *)key2;

    return (cid1->cnx_id == cid2->cnx_id) ? 0 : -1;
}

static uint64_t picoquic_net_id_hash(void * key)
{
    picoquic_net_id * net = (picoquic_net_id *)key;

    return picohash_bytes((uint8_t *)&net->saddr, sizeof(net->saddr));
}

static int picoquic_net_id_compare(void * key1, void * key2)
{
    picoquic_net_id * net1 = (picoquic_net_id *)key1;
    picoquic_net_id * net2 = (picoquic_net_id *)key2;

    return memcmp(&net1->saddr, &net2->saddr, sizeof(net1->saddr));
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
    0x3d, 0xc1, 0xca, 0x36 };

static uint8_t picoquic_cleartext_version_1_salt[] = {
    0xaf, 0xc8, 0x24, 0xec, 0x5f, 0xc7, 0x7e, 0xca,
    0x1e, 0x9d, 0x36, 0xf3, 0x7f, 0xb2, 0xd4, 0x65,
    0x18, 0xc3, 0x66, 0x39 };

const picoquic_version_parameters_t picoquic_supported_versions[] = {
    { PICOQUIC_INTERNAL_TEST_VERSION_1, 0,
    picoquic_version_header_08,
    sizeof(picoquic_cleartext_internal_test_1_salt), 
    picoquic_cleartext_internal_test_1_salt },
    { PICOQUIC_THIRD_INTEROP_VERSION, 0,
    picoquic_version_header_08,
    sizeof(picoquic_cleartext_version_1_salt),
    picoquic_cleartext_version_1_salt },
    { PICOQUIC_SECOND_INTEROP_VERSION, 
    picoquic_version_bidir_only | picoquic_version_old_aead_secret |
    picoquic_version_short_pings | picoquic_version_fix_ints| picoquic_version_old_parameters,
    picoquic_version_header_05_07,
    sizeof(picoquic_cleartext_version_1_salt), picoquic_cleartext_version_1_salt }
};

const size_t picoquic_nb_supported_versions = sizeof(picoquic_supported_versions) / 
    sizeof(picoquic_version_parameters_t);

/* QUIC context create and dispose */
picoquic_quic_t * picoquic_create(uint32_t nb_connections, 
	char const * cert_file_name,
	char const * key_file_name,
	char const * default_alpn,
	picoquic_stream_data_cb_fn default_callback_fn,
	void * default_callback_ctx,
	cnx_id_cb_fn cnx_id_callback,
	void * cnx_id_callback_ctx,
	uint8_t reset_seed[PICOQUIC_RESET_SECRET_SIZE],
    uint64_t current_time,
    uint64_t * p_simulated_time,
    char const * ticket_file_name,
    const uint8_t * ticket_encryption_key,
    size_t ticket_encryption_key_length)
{
    picoquic_quic_t * quic = (picoquic_quic_t *)malloc(sizeof(picoquic_quic_t));
    int ret = 0;

    if (quic != NULL)
    {
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

		if (cnx_id_callback != NULL)
		{
			quic->flags |= picoquic_context_unconditional_cnx_id;
		}

        if (cert_file_name != NULL)
        {
            quic->flags |= picoquic_context_server;
        }
        else if (ticket_file_name != NULL)
        {
            quic->ticket_file_name = ticket_file_name;
            ret = picoquic_load_tickets(&quic->p_first_ticket, current_time, ticket_file_name);
        }

        quic->table_cnx_by_id = picohash_create(nb_connections * 4,
            picoquic_cnx_id_hash, picoquic_cnx_id_compare);

        quic->table_cnx_by_net = picohash_create(nb_connections * 4,
            picoquic_net_id_hash, picoquic_net_id_compare);

        if (quic->table_cnx_by_id == NULL ||
            quic->table_cnx_by_net == NULL ||
            picoquic_master_tlscontext(quic, cert_file_name, key_file_name,
                ticket_encryption_key, ticket_encryption_key_length) != 0)
        {
            picoquic_free(quic);
            quic = NULL;
        }
		else
		{
			/* the random generator was initialized as part of the TLS context. 
			 * Use it to create the seed for generating the per context stateless
			 * resets. */

			if (!reset_seed)
				picoquic_crypto_random(quic, quic->reset_seed, sizeof(quic->reset_seed));
			else
				memcpy(quic->reset_seed, reset_seed, sizeof(quic->reset_seed));
		}
    }

    return quic;
}

void picoquic_free(picoquic_quic_t * quic)
{
    if (quic != NULL)
    {
        if (quic->aead_encrypt_ticket_ctx != NULL)
        {
            picoquic_aead_free(quic->aead_encrypt_ticket_ctx);
            quic->aead_encrypt_ticket_ctx = NULL;
        }

        if (quic->aead_decrypt_ticket_ctx != NULL)
        {
            picoquic_aead_free(quic->aead_decrypt_ticket_ctx);
            quic->aead_decrypt_ticket_ctx = NULL;
        }

		if (quic->default_alpn != NULL)
		{
			free((void*)quic->default_alpn);
			quic->default_alpn = NULL;
		}

        /* delete the stored tickets */
        picoquic_free_tickets(&quic->p_first_ticket);

		/* delete all pending packets */
		while (quic->pending_stateless_packet != NULL)
		{
			picoquic_stateless_packet_t * to_delete = quic->pending_stateless_packet;
			quic->pending_stateless_packet = to_delete->next_packet;
			free(to_delete);
		}

        /* delete all the connection contexts */
        while (quic->cnx_list != NULL)
        {
            picoquic_delete_cnx(quic->cnx_list);
        }

        if (quic->table_cnx_by_id != NULL)
        {
            picohash_delete(quic->table_cnx_by_id, 1);
        }

        if (quic->table_cnx_by_net != NULL)
        {
            picohash_delete(quic->table_cnx_by_net, 1);
        }

        /* Delete the picotls context */
        if (quic->tls_master_ctx != NULL)
        {
			picoquic_master_tlscontext_free(quic);

            free(quic->tls_master_ctx);
            quic->tls_master_ctx = NULL;
        }
    }
}

void picoquic_set_cookie_mode(picoquic_quic_t * quic, int cookie_mode)
{
    if (cookie_mode)
    {
        quic->flags |= picoquic_context_check_cookie;
        picoquic_crypto_random(quic, quic->retry_seed, PICOQUIC_RETRY_SECRET_SIZE);
    }
    else
    {
        quic->flags &= ~picoquic_context_check_cookie;
    }
}

picoquic_stateless_packet_t * picoquic_create_stateless_packet(picoquic_quic_t * quic)
{
	return (picoquic_stateless_packet_t *)malloc(sizeof(picoquic_stateless_packet_t));
}

void picoquic_delete_stateless_packet(picoquic_stateless_packet_t * sp)
{
	free(sp);
}

void picoquic_queue_stateless_packet(picoquic_quic_t * quic, picoquic_stateless_packet_t * sp)
{
	picoquic_stateless_packet_t ** pnext = &quic->pending_stateless_packet;

	while ((*pnext) != NULL)
	{
		pnext = &(*pnext)->next_packet;
	}

	*pnext = sp;
	sp->next_packet = NULL;
}

picoquic_stateless_packet_t * picoquic_dequeue_stateless_packet(picoquic_quic_t * quic)
{
	picoquic_stateless_packet_t * sp = quic->pending_stateless_packet;

	if (sp != NULL)
	{
		quic->pending_stateless_packet = sp->next_packet;
		sp->next_packet = NULL;
	}

	return sp;
}

/* Connection context creation and registration */
int picoquic_register_cnx_id(picoquic_quic_t * quic, picoquic_cnx_t * cnx, uint64_t cnx_id)
{
    int ret = 0;
    picohash_item * item;
    picoquic_cnx_id * key = (picoquic_cnx_id *)malloc(sizeof(picoquic_cnx_id));

    if (key == NULL)
    {
        ret = -1;
    }
    else
    {
        key->cnx_id = cnx_id;
        key->cnx = cnx;
        key->next_cnx_id = NULL;

        item = picohash_retrieve(quic->table_cnx_by_id, key);

        if (item != NULL)
        {
            ret = -1;
        }
        else
        {
            ret = picohash_insert(quic->table_cnx_by_id, key);

            if (ret == 0)
            {
                key->next_cnx_id = cnx->first_cnx_id;
                cnx->first_cnx_id = key;
            }
        }
    }

    return ret;
}

int picoquic_register_net_id(picoquic_quic_t * quic, picoquic_cnx_t * cnx, struct sockaddr * addr)
{
    int ret = 0;
    picohash_item * item;
    picoquic_net_id * key = (picoquic_net_id *)malloc(sizeof(picoquic_net_id));

    if (key == NULL)
    {
        ret = -1;
    }
    else
    {
        memset(&key->saddr, 0, sizeof(key->saddr));
        if (addr->sa_family == AF_INET)
        {
            memcpy(&key->saddr, addr, sizeof(struct sockaddr_in));
        }
        else
        {
            memcpy(&key->saddr, addr, sizeof(struct sockaddr_in6));
        }
        key->cnx = cnx;

        item = picohash_retrieve(quic->table_cnx_by_net, key);

        if (item != NULL)
        {
            ret = -1;
        }
        else
        {
            ret = picohash_insert(quic->table_cnx_by_net, key);

            if (ret == 0)
            {
                key->next_net_id = cnx->first_net_id;
                cnx->first_net_id = key;
            }
        }
    }

    if (key != NULL && ret != 0)
    {
        free(key);
    }

    return ret;
}

void picoquic_init_transport_parameters(picoquic_transport_parameters * tp, int is_server)
{
	tp->initial_max_stream_data = 65535;
	tp->initial_max_data = 0x100000;
    if (is_server == 0)
    {
        tp->initial_max_stream_id_bidir = 65533;
        tp->initial_max_stream_id_unidir = 65535;
    }
    else
    {
        tp->initial_max_stream_id_bidir = 65532;
        tp->initial_max_stream_id_unidir = 65534;

    }
	tp->idle_timeout = 30;
	tp->omit_connection_id = 0;
	tp->max_packet_size = PICOQUIC_MAX_PACKET_SIZE - 16 - 40;
    tp->ack_delay_exponent = 3;
}

static void picoquic_insert_cnx_by_wake_time(picoquic_quic_t * quic, picoquic_cnx_t * cnx)
{
    picoquic_cnx_t * cnx_next = quic->cnx_list;
    picoquic_cnx_t * previous = NULL;
    while (cnx_next != NULL &&
        cnx_next->next_wake_time <= cnx->next_wake_time)
    {
        previous = cnx_next;
        cnx_next = cnx_next->next_in_table;
    }

    cnx->previous_in_table = previous;
    if (previous == NULL)
    {
        quic->cnx_list = cnx;
    }
    else
    {
        previous->next_in_table = cnx;
    }

    cnx->next_in_table = cnx_next;

    if (cnx_next == NULL)
    {
        quic->cnx_last = cnx;
    }
    else
    {
        cnx_next->previous_in_table = cnx;
    }
}

void picoquic_reinsert_by_wake_time(picoquic_quic_t * quic, picoquic_cnx_t * cnx)
{
    if (cnx->next_in_table == NULL)
    {
        quic->cnx_last = cnx->previous_in_table;
    }
    else
    {
        cnx->next_in_table->previous_in_table = cnx->previous_in_table;
    }

    if (cnx->previous_in_table == NULL)
    {
        quic->cnx_list = cnx->next_in_table;
    }
    else
    {
        cnx->previous_in_table->next_in_table = cnx->next_in_table;
    }

    picoquic_insert_cnx_by_wake_time(quic, cnx);
}


int picoquic_get_version_index(uint32_t proposed_version)
{
    int ret = -1;

    for (size_t i = 0; i < picoquic_nb_supported_versions; i++)
    {
        if (picoquic_supported_versions[i].version == proposed_version)
        {
            ret = (int)i;
            break;
        }
    }

    return ret;
}

picoquic_cnx_t * picoquic_create_cnx(picoquic_quic_t * quic, 
    uint64_t cnx_id, struct sockaddr * addr, uint64_t start_time, uint32_t preferred_version,
	char const * sni, char const * alpn)
{
    picoquic_cnx_t * cnx = (picoquic_cnx_t *)malloc(sizeof(picoquic_cnx_t));
    uint32_t random_sequence;

    if (cnx != NULL)
    {
        memset(cnx, 0, sizeof(picoquic_cnx_t));

        cnx->next_wake_time = start_time;
        cnx->start_time = start_time;

        cnx->quic = quic;
        picoquic_insert_cnx_by_wake_time(quic, cnx);
    }

    if (cnx != NULL)
    {
        cnx->peer_addr_len = (int)((addr->sa_family == AF_INET) ?
            sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
        memcpy(&cnx->peer_addr, addr, cnx->peer_addr_len);

		picoquic_init_transport_parameters(&cnx->local_parameters, quic->flags&picoquic_context_server);
        /* Special provision for test -- create a deliberate transport parameters error */
        if (sni != NULL && (quic->flags&picoquic_context_server) == 0 && strcmp(sni, PICOQUIC_ERRONEOUS_SNI) == 0)
        {
            /* Illegal value: server limits should be odd */
            cnx->local_parameters.initial_max_stream_id_bidir = 0x202;
        }
		// picoquic_init_transport_parameters(&cnx->remote_parameters);
		/* Initialize local flow control variables to advertised values */
        if ((picoquic_supported_versions[cnx->version_index].version_flags &
            picoquic_version_fix_ints) == 0)
        {
            cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data);
        }
        else
        {
            cnx->maxdata_local = ((uint64_t)cnx->local_parameters.initial_max_data) << 10;
        }
		cnx->max_stream_id_bidir_local = cnx->local_parameters.initial_max_stream_id_bidir;
        cnx->max_stream_id_unidir_local = cnx->local_parameters.initial_max_stream_id_unidir;

		/* Initialize remote variables to some plausible value. 
		 * Hopefully, this will be overwritten by the parameters received in
		 * the TLS transport parameter extension */
		cnx->maxdata_remote = PICOQUIC_DEFAULT_0RTT_WINDOW;
        cnx->remote_parameters.initial_max_stream_data = PICOQUIC_DEFAULT_0RTT_WINDOW;
		cnx->max_stream_id_bidir_remote = 4;
        cnx->max_stream_id_unidir_remote = 2;

		if (sni != NULL)
		{
			cnx->sni = picoquic_string_duplicate(sni);
		}

		if (alpn != NULL)
		{
			cnx->alpn = picoquic_string_duplicate(alpn);
		}

		cnx->callback_fn = quic->default_callback_fn;
		cnx->callback_ctx = quic->default_callback_ctx;
		cnx->congestion_alg = quic->default_congestion_alg;

		if ((quic->flags &picoquic_context_server) == 0)
		{
			if (preferred_version == 0)
			{
				cnx->proposed_version = picoquic_supported_versions[0].version;
                cnx->version_index = 0;
			}
			else
			{
                cnx->version_index = picoquic_get_version_index(preferred_version);
                if (cnx->version_index < 0)
                {
                    cnx->version_index = 0;
                    if ((preferred_version & 0x0A0A0A0A) == 0x0A0A0A0A)
                    {
                        /* This is a hack, to allow greasing the cnx ID */
                        cnx->proposed_version = preferred_version;
                    }
                    else
                    {
                        cnx->proposed_version = picoquic_supported_versions[0].version;
                    }
                }
                else
                {
                    cnx->proposed_version = preferred_version;
                }
			}
			cnx->local_parameters.omit_connection_id = 1;

			cnx->cnx_state = picoquic_state_client_init;
			if (cnx_id == 0)
			{
				picoquic_crypto_random(quic, &cnx_id, sizeof(uint64_t));
			}

			if (quic->cnx_id_callback_fn)
				cnx_id = quic->cnx_id_callback_fn(cnx_id, 0, quic->cnx_id_callback_ctx);

			cnx->initial_cnxid = cnx_id;
			cnx->server_cnxid = 0;
			/* Initialize the reset secret to a random value. This
			 * will prevent spurious matches to an all zero value, for example.
			 * The real value will be set when receiving the transport parameters. 
			 */
			picoquic_crypto_random(quic, cnx->reset_secret, PICOQUIC_RESET_SECRET_SIZE);
		}
        else
        {
            cnx->first_stream.send_queue = NULL;
            cnx->cnx_state = picoquic_state_server_init;
            cnx->initial_cnxid = cnx_id;
			picoquic_crypto_random(quic, &cnx->server_cnxid, sizeof(uint64_t));

			if (quic->cnx_id_callback_fn)
				cnx->server_cnxid = quic->cnx_id_callback_fn(cnx->server_cnxid, cnx->initial_cnxid,
						quic->cnx_id_callback_ctx);

			(void)picoquic_create_cnxid_reset_secret(quic, cnx->server_cnxid,
				cnx->reset_secret);

            cnx->version_index = picoquic_get_version_index(preferred_version);
            if (cnx->version_index < 0)
            {
                /* TODO: this is an internal error condition, should not happen */
                cnx->version_index = 0;
                cnx->proposed_version = picoquic_supported_versions[0].version;
            }
            else
            {
                cnx->proposed_version = preferred_version;
            }
        }

		if (cnx != NULL)
		{
			cnx->first_sack_item.start_of_sack_range = 0;
			cnx->first_sack_item.end_of_sack_range = 0;
			cnx->first_sack_item.next_sack = NULL;
			cnx->sack_block_size_max = 0;
			cnx->highest_ack_sent = 0;
			cnx->highest_ack_time = start_time;
            cnx->time_stamp_largest_received = start_time;

			cnx->first_stream.stream_id = 0;
			cnx->first_stream.consumed_offset = 0;
			cnx->first_stream.stream_flags = 0;
			cnx->first_stream.fin_offset = 0;
			cnx->first_stream.next_stream = NULL;
			cnx->first_stream.stream_data = NULL;
			cnx->first_stream.sent_offset = 0;
			cnx->first_stream.local_error = 0;
			cnx->first_stream.remote_error = 0;
			cnx->first_stream.maxdata_local = (uint64_t)((int64_t)-1);
			cnx->first_stream.maxdata_remote = (uint64_t)((int64_t)-1);

			cnx->aead_decrypt_ctx = NULL;
			cnx->aead_encrypt_ctx = NULL;
            cnx->aead_de_encrypt_ctx = NULL;

            /* Set the initial sequence randomly between 1 and 2^31 - 1 
             * The spec does not require avoiding the value 0, but doing
             * so minimizes risks of triggering bugs in other implementations.
             */
            do
            {
                picoquic_crypto_random(quic, &random_sequence, sizeof(uint32_t));
                random_sequence &= 0x7FFFFFFF;
            } while (random_sequence == 0);
            cnx->send_sequence = random_sequence;

			cnx->send_mtu = (addr == NULL || addr->sa_family == AF_INET)?
				PICOQUIC_INITIAL_MTU_IPV4 : PICOQUIC_INITIAL_MTU_IPV6;

			cnx->nb_retransmit = 0;
			cnx->latest_retransmit_time = 0;

			cnx->retransmit_newest = NULL;
			cnx->retransmit_oldest = NULL;
			cnx->highest_acknowledged = cnx->send_sequence - 1;

			cnx->latest_time_acknowledged = start_time;
			cnx->latest_progress_time = start_time;
			cnx->ack_needed = 0;


			/* Time measurement */
			cnx->smoothed_rtt = PICOQUIC_INITIAL_RTT;
			cnx->rtt_variant = 0;
			cnx->retransmit_timer = PICOQUIC_INITIAL_RETRANSMIT_TIMER;
			cnx->rtt_min = 0;

            cnx->ack_delay_local = 10000;

			/* Congestion control state */
			cnx->cwin = PICOQUIC_CWIN_INITIAL;
			cnx->bytes_in_transit = 0;
			cnx->congestion_alg_state = NULL;
			cnx->congestion_alg = cnx->quic->default_congestion_alg;
			if (cnx->congestion_alg != NULL)
			{
				cnx->congestion_alg->alg_init(cnx);
			}
            /* Pacing state */
            cnx->packet_time_nano_sec = 0;
            cnx->pacing_reminder_nano_sec = 0;
            cnx->pacing_margin_micros = 1000;
            cnx->next_pacing_time = start_time;
		}
    }

	/* Only initialize TLS after all parameters have been set */

	if (picoquic_tlscontext_create(quic, cnx, start_time) != 0)
	{
		/* Cannot just do partial creation! */
		picoquic_delete_cnx(cnx);
		cnx = NULL;
	}
	else if ((quic->flags &picoquic_context_server) == 0)
	{
		/* Initialize the tls connection */
		int ret = picoquic_initialize_stream_zero(cnx);

		if (ret != 0)
		{
			/* Cannot just do partial initialization! */
			picoquic_delete_cnx(cnx);
			cnx = NULL;
		}
	}

    if (cnx != NULL)
    {
        cnx->aead_encrypt_cleartext_ctx = NULL;
        cnx->aead_decrypt_cleartext_ctx = NULL;
        cnx->aead_de_encrypt_cleartext_ctx = NULL;

        if (picoquic_setup_cleartext_aead_contexts(cnx,
            (quic->flags &picoquic_context_server) != 0) != 0)
        {
            /* Cannot initialize clear text aead */
            picoquic_delete_cnx(cnx);
            cnx = NULL;
        }
    }

    if (cnx != NULL)
    {
        if (cnx->server_cnxid != 0)
        {
            (void)picoquic_register_cnx_id(quic, cnx, cnx->server_cnxid);
        }

        if (addr != NULL)
        {
            (void)picoquic_register_net_id(quic, cnx, addr);
        }
    }

    return cnx;
}

picoquic_cnx_t * picoquic_create_client_cnx(picoquic_quic_t * quic, 
	struct sockaddr * addr, uint64_t start_time, uint32_t preferred_version,
	char const * sni, char const * alpn, picoquic_stream_data_cb_fn callback_fn, void * callback_ctx)
{
	picoquic_cnx_t * cnx = picoquic_create_cnx(quic, 0, addr, start_time, preferred_version, sni, alpn);

	if (cnx != NULL)
	{
		if (callback_fn != NULL)
			cnx->callback_fn = callback_fn;
		if (callback_ctx != NULL)
			cnx->callback_ctx = callback_ctx;
	}

	return cnx;
}

void picoquic_get_peer_addr(picoquic_cnx_t * cnx, struct sockaddr ** addr, int * addr_len)
{
    *addr = (struct sockaddr *) &cnx->peer_addr;
    *addr_len = cnx->peer_addr_len;
}

void picoquic_get_local_addr(picoquic_cnx_t * cnx, struct sockaddr ** addr, int * addr_len)
{
    *addr = (struct sockaddr *) &cnx->dest_addr;
    *addr_len = cnx->dest_addr_len;
}

unsigned long picoquic_get_local_if_index(picoquic_cnx_t * cnx)
{
    return cnx->if_index_dest;
}

uint64_t picoquic_get_cnxid(picoquic_cnx_t * cnx)
{
    return cnx->server_cnxid;
}

uint64_t picoquic_get_initial_cnxid(picoquic_cnx_t * cnx)
{
    return cnx->initial_cnxid;
}


uint64_t picoquic_get_cnx_start_time(picoquic_cnx_t * cnx)
{
    return cnx->start_time;
}

picoquic_state_enum picoquic_get_cnx_state(picoquic_cnx_t * cnx)
{
	return cnx->cnx_state;
}

picoquic_cnx_t * picoquic_get_first_cnx(picoquic_quic_t * quic)
{
	return quic->cnx_list;
}


picoquic_cnx_t * picoquic_get_next_cnx(picoquic_cnx_t * cnx)
{
    return cnx->next_in_table;
}


int64_t picoquic_get_next_wake_delay(picoquic_quic_t * quic, 
    uint64_t current_time, int64_t delay_max)
{
    int64_t wake_delay;

    if (quic->cnx_list != NULL)
    {
        if (quic->cnx_list->next_wake_time > current_time)
        {
            wake_delay = quic->cnx_list->next_wake_time - current_time;

            if (wake_delay > delay_max)
            {
                wake_delay = delay_max;
            }
        }
        else
        {
            wake_delay = 0;
        }
    }
    else
    {
        wake_delay = delay_max;
    }

    return wake_delay;
}


void picoquic_set_callback(picoquic_cnx_t * cnx,
    picoquic_stream_data_cb_fn callback_fn, void * callback_ctx)
{
    cnx->callback_fn = callback_fn;
    cnx->callback_ctx = callback_ctx;
}

int picoquic_queue_misc_frame(picoquic_cnx_t * cnx, const uint8_t * bytes, size_t length)
{
    int ret = 0;
    uint8_t * misc_frame = (uint8_t *) malloc(sizeof(picoquic_misc_frame_header_t) + length);

    if (misc_frame == NULL)
    {
        ret = PICOQUIC_ERROR_MEMORY;
    }
    else
    {
        picoquic_misc_frame_header_t * head = (picoquic_misc_frame_header_t*)misc_frame;
        head->length = length;
        memcpy(misc_frame + sizeof(picoquic_misc_frame_header_t), bytes, length);
        head->next_misc_frame = cnx->first_misc_frame;
        cnx->first_misc_frame = head;
    }

    return ret;
}

void picoquic_clear_stream(picoquic_stream_head * stream)
{
    picoquic_stream_data ** pdata[2];
    pdata[0] = &stream->stream_data;
    pdata[1] = &stream->send_queue;

    for (int i = 0; i < 2; i++)
    {
        picoquic_stream_data * next; 

        while ((next = *pdata[i]) != NULL)
        {
            *pdata[i] = next->next_stream_data;

            if (next->bytes != NULL)
            {
                free(next->bytes);
            }
            free(next);
        }
    }
}

void picoquic_enqueue_retransmit_packet(picoquic_cnx_t * cnx, picoquic_packet * p)
{
	if (cnx->retransmit_oldest == NULL)
	{
		p->previous_packet = NULL;
		cnx->retransmit_newest = p;
	}
	else
	{
		cnx->retransmit_oldest->next_packet = p;
		p->previous_packet = cnx->retransmit_oldest;
	}
	p->next_packet = NULL;
	cnx->retransmit_oldest = p;

	/* Account for bytes in transit, for congestion control */
	cnx->bytes_in_transit += p->length;
}

void picoquic_dequeue_retransmit_packet(picoquic_cnx_t * cnx, picoquic_packet * p, int should_free)
{
	if (p->previous_packet == NULL)
	{
		cnx->retransmit_newest = p->next_packet;
	}
	else
	{
		p->previous_packet->next_packet = p->next_packet;
	}

	if (p->next_packet == NULL)
	{
		cnx->retransmit_oldest = p->previous_packet;
	}
	else
	{
		p->next_packet->previous_packet = p->previous_packet;
	}

	/* Account for bytes in transit, for congestion control */
	if (cnx->retransmit_newest == NULL)
	{
		cnx->bytes_in_transit = 0;
	}
	else
	{
		size_t dequeued_length = p->length + p->checksum_overhead;

		if (cnx->bytes_in_transit > dequeued_length)
		{
			cnx->bytes_in_transit -= dequeued_length;
		}
		else
		{
			cnx->bytes_in_transit = 0;
		}
	}

    if (should_free)
    {
        free(p);
    }
    else
    {
        p->next_packet = NULL;

        /* add this packet to the retransmitted list */
        if (cnx->retransmitted_oldest == NULL)
        {
            cnx->retransmitted_newest = p;
            p->previous_packet = NULL;
        }
        else
        {
            cnx->retransmitted_oldest->next_packet = p;
            p->previous_packet = cnx->retransmitted_oldest;
            cnx->retransmitted_oldest = p;
        }
    }
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

int picoquic_reset_cnx_version(picoquic_cnx_t * cnx, uint8_t * bytes, size_t length, uint64_t current_time)
{
	/* First parse the incoming connection negotiation to choose the
	* new version. If none is available, return an error */
	size_t byte_index = 0;
	uint32_t proposed_version = 0;
	int ret = -1;

	if (cnx->cnx_state == picoquic_state_client_init ||
		cnx->cnx_state == picoquic_state_client_init_sent)
	{
		while (cnx->cnx_state != picoquic_state_client_renegotiate && 
			byte_index + 4 <= length)
		{
			/* parsing the list of proposed versions encoded in renegotiation packet */
			proposed_version = PICOPARSE_32(bytes + byte_index);
			byte_index += 4;

			for (size_t i = 0; i < picoquic_nb_supported_versions; i++)
			{
				if (proposed_version == picoquic_supported_versions[i].version)
				{
                    cnx->version_index = (int) i;
					cnx->cnx_state = picoquic_state_client_renegotiate;

                    /* TODO: Reset the clear text context */

					/* Delete the packets queued for retransmission */
					while (cnx->retransmit_newest != NULL)
					{
						picoquic_dequeue_retransmit_packet(cnx, cnx->retransmit_newest, 1);
					}

					/* Reset the streams */
					picoquic_clear_stream(&cnx->first_stream);
					cnx->first_stream.consumed_offset = 0;
					cnx->first_stream.stream_flags = 0;
					cnx->first_stream.fin_offset = 0;
					cnx->first_stream.sent_offset = 0;
                    /* TODO: reset clear text AEAD */

					/* Reset the TLS context, Re-initialize the tls connection */
					picoquic_tlscontext_free(cnx->tls_ctx);
					cnx->tls_ctx = NULL;
					ret = picoquic_tlscontext_create(cnx->quic, cnx, current_time);
					if (ret == 0)
					{
						ret = picoquic_initialize_stream_zero(cnx);
					}

                    if (cnx->aead_encrypt_cleartext_ctx != NULL)
                    {
                        picoquic_aead_free(cnx->aead_encrypt_cleartext_ctx);
                        cnx->aead_encrypt_cleartext_ctx = NULL;
                    }

                    if (cnx->aead_decrypt_cleartext_ctx != NULL)
                    {
                        picoquic_aead_free(cnx->aead_decrypt_cleartext_ctx);
                        cnx->aead_decrypt_cleartext_ctx = NULL;
                    }

                    if (cnx->aead_de_encrypt_cleartext_ctx != NULL)
                    {
                        picoquic_aead_free(cnx->aead_de_encrypt_cleartext_ctx);
                        cnx->aead_de_encrypt_cleartext_ctx = NULL;
                    }

                    if (cnx->aead_0rtt_decrypt_ctx != NULL)
                    {
                        picoquic_aead_free(cnx->aead_0rtt_decrypt_ctx);
                        cnx->aead_0rtt_decrypt_ctx = NULL;
                    }

                    if (cnx->aead_0rtt_encrypt_ctx != NULL)
                    {
                        picoquic_aead_free(cnx->aead_0rtt_encrypt_ctx);
                        cnx->aead_0rtt_encrypt_ctx = NULL;
                    }

                    if (ret == 0)
                    {
                        ret = picoquic_setup_cleartext_aead_contexts(cnx,
                            (cnx->quic->flags &picoquic_context_server) != 0);
                    }
					break;
				}
			}
		}
	}

	return ret;
}

int picoquic_connection_error(picoquic_cnx_t * cnx, uint32_t local_error)
{
    if (cnx->cnx_state == picoquic_state_client_ready ||
        cnx->cnx_state == picoquic_state_server_ready)
    {
        cnx->local_error = local_error;
        cnx->cnx_state = picoquic_state_disconnecting;

        DBG_PRINTF("Protocol error %x", local_error);
    }
    else if (cnx->cnx_state < picoquic_state_client_ready)
    {
        cnx->local_error = local_error;
        cnx->cnx_state = picoquic_state_handshake_failure;

        DBG_PRINTF("Protocol error %x", local_error);

    }

    return PICOQUIC_ERROR_DETECTED;
}

void picoquic_delete_cnx(picoquic_cnx_t * cnx)
{
    picoquic_stream_head * stream;
    picoquic_misc_frame_header_t * misc_frame;

    if (cnx != NULL)
    {
		if (cnx->alpn != NULL)
		{
			free((void*)cnx->alpn);
			cnx->alpn = NULL;
		}

		if (cnx->sni != NULL)
		{
			free((void*)cnx->sni);
			cnx->sni = NULL;
		}

        while (cnx->first_cnx_id != NULL)
        {
            picohash_item * item;
            picoquic_cnx_id * cnx_id_key = cnx->first_cnx_id;
            cnx->first_cnx_id = cnx_id_key->next_cnx_id;
            cnx_id_key->next_cnx_id = NULL;

            item = picohash_retrieve(cnx->quic->table_cnx_by_id, cnx_id_key);
            if (item != NULL)
            {
                picohash_item_delete(cnx->quic->table_cnx_by_id, item, 1);
            }
        }

        while (cnx->first_net_id != NULL)
        {
            picohash_item * item;
            picoquic_net_id * net_id_key = cnx->first_net_id;
            cnx->first_net_id = net_id_key->next_net_id;
            net_id_key->next_net_id = NULL;

            item = picohash_retrieve(cnx->quic->table_cnx_by_net, net_id_key);
            if (item != NULL)
            {
                picohash_item_delete(cnx->quic->table_cnx_by_net, item, 1);
            }
        }

        if (cnx->next_in_table == NULL)
        {
            cnx->quic->cnx_last = cnx->previous_in_table;
        }
        else
        {
            cnx->next_in_table->previous_in_table = cnx->previous_in_table;
        }

        if (cnx->previous_in_table == NULL)
        {
            cnx->quic->cnx_list = cnx->next_in_table;
        }
        else
        {
            cnx->previous_in_table->next_in_table = cnx->next_in_table;
        }

        if (cnx->aead_encrypt_cleartext_ctx != NULL)
        {
            picoquic_aead_free(cnx->aead_encrypt_cleartext_ctx);
            cnx->aead_encrypt_cleartext_ctx = NULL;
        }

        if (cnx->aead_decrypt_cleartext_ctx != NULL)
        {
            picoquic_aead_free(cnx->aead_decrypt_cleartext_ctx);
            cnx->aead_decrypt_cleartext_ctx = NULL;
        }

        if (cnx->aead_de_encrypt_cleartext_ctx != NULL)
        {
            picoquic_aead_free(cnx->aead_de_encrypt_cleartext_ctx);
            cnx->aead_de_encrypt_cleartext_ctx = NULL;
        }

        if (cnx->aead_decrypt_ctx != NULL)
        {
            picoquic_aead_free(cnx->aead_decrypt_ctx);
            cnx->aead_decrypt_ctx = NULL;
        }

        if (cnx->aead_encrypt_ctx != NULL)
        {
            picoquic_aead_free(cnx->aead_encrypt_ctx);
            cnx->aead_encrypt_ctx = NULL;
        }

        if (cnx->aead_de_encrypt_ctx != NULL)
        {
            picoquic_aead_free(cnx->aead_de_encrypt_ctx);
            cnx->aead_encrypt_ctx = NULL;
        }

		while (cnx->retransmit_newest != NULL)
		{
			picoquic_dequeue_retransmit_packet(cnx, cnx->retransmit_newest, 1);
		}

        while (cnx->retransmitted_newest != NULL)
        {
            picoquic_packet * p = cnx->retransmitted_newest;
            cnx->retransmitted_newest = p->next_packet;
            free(p);
        }
        cnx->retransmitted_oldest = NULL;

        while ((misc_frame = cnx->first_misc_frame) != NULL)
        {
            cnx->first_misc_frame = misc_frame->next_misc_frame;
            free(misc_frame);
        }

        while ((stream = cnx->first_stream.next_stream) != NULL)
        {
            cnx->first_stream.next_stream = stream->next_stream;
            picoquic_clear_stream(stream);
            free(stream);
        }
        picoquic_clear_stream(&cnx->first_stream);

        if (cnx->tls_ctx != NULL)
        {
            picoquic_tlscontext_free(cnx->tls_ctx);
            cnx->tls_ctx = NULL;
        }

		if (cnx->congestion_alg != NULL)
		{
			cnx->congestion_alg->alg_delete(cnx);
		}

        free(cnx);
    }
}

/* Context retrieval functions */
picoquic_cnx_t * picoquic_cnx_by_id(picoquic_quic_t * quic, uint64_t cnx_id)
{
    picoquic_cnx_t * ret = NULL;
    picohash_item * item;
    picoquic_cnx_id key = { 0 };
    key.cnx_id = cnx_id;

    item = picohash_retrieve(quic->table_cnx_by_id, &key);

    if (item != NULL)
    {
        ret = ((picoquic_cnx_id *)item->key)->cnx;
    }
    return ret;
}

picoquic_cnx_t * picoquic_cnx_by_net(picoquic_quic_t * quic, struct sockaddr* addr)
{
    picoquic_cnx_t * ret = NULL;
    picohash_item * item;
    picoquic_net_id key = { {0} };

    if (addr->sa_family == AF_INET)
    {
        memcpy(&key.saddr, addr, sizeof(struct sockaddr_in));
    }
    else
    {
        memcpy(&key.saddr, addr, sizeof(struct sockaddr_in6));
    }

    item = picohash_retrieve(quic->table_cnx_by_net, &key);

    if (item != NULL)
    {
        ret = ((picoquic_net_id *)item->key)->cnx;
    }
    return ret;
}

/*
 * Set or reset the congestion control algorithm
 */

void picoquic_set_default_congestion_algorithm(picoquic_quic_t * quic, picoquic_congestion_algorithm_t const * alg)
{
	quic->default_congestion_alg = alg;
}

void picoquic_set_congestion_algorithm(picoquic_cnx_t * cnx, picoquic_congestion_algorithm_t const * alg)
{
	if (cnx->congestion_alg != NULL)
	{
		cnx->congestion_alg->alg_delete(cnx);
	}

	cnx->congestion_alg = alg;

	if (cnx->congestion_alg != NULL)
	{
		cnx->congestion_alg->alg_init(cnx);
	}
}
