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

    // TODO: should scramble the value for security and DOS protection

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

const uint32_t picoquic_supported_versions[] = {
	PICOQUIC_FIRST_INTEROP_VERSION,
	PICOQUIC_INTERNAL_TEST_VERSION_1
};

const size_t picoquic_nb_supported_versions = sizeof(picoquic_supported_versions) / sizeof(uint32_t);


/* QUIC context create and dispose */
picoquic_quic_t * picoquic_create(uint32_t nb_connections, 
	char * cert_file_name, 
	char * key_file_name,
	char const * default_alpn,
	picoquic_stream_data_cb_fn default_callback_fn,
	void * default_callback_ctx)
{
    picoquic_quic_t * quic = (picoquic_quic_t *)malloc(sizeof(picoquic_quic_t));

    if (quic != NULL)
    {
        /* TODO: winsock init */
        /* TODO: open UDP sockets - maybe */

        quic->flags = 0;

		quic->pending_stateless_packet = NULL;

		quic->default_callback_fn = default_callback_fn;
		quic->default_callback_ctx = default_callback_ctx;
		quic->default_alpn = picoquic_string_duplicate(default_alpn);

        if (cert_file_name != NULL)
        {
            quic->flags |= picoquic_context_server;
        }

        quic->cnx_list = NULL;
        quic->cnx_last = NULL;

        quic->table_cnx_by_id = picohash_create(nb_connections * 4,
            picoquic_cnx_id_hash, picoquic_cnx_id_compare);

        quic->table_cnx_by_net = picohash_create(nb_connections * 4,
            picoquic_net_id_hash, picoquic_net_id_compare);

        if (quic->table_cnx_by_id == NULL ||
            quic->table_cnx_by_net == NULL ||
            picoquic_master_tlscontext(quic, cert_file_name, key_file_name) != 0)
        {
            picoquic_free(quic);
            quic = NULL;
        }
    }

    return quic;
}

void picoquic_free(picoquic_quic_t * quic)
{
    if (quic != NULL)
    {
        /* TODO: close the network sockets */

		if (quic->default_alpn != NULL)
		{
			free(quic->default_alpn);
			quic->default_alpn = NULL;
		}

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


void picoquic_int_transport_parameters(picoquic_transport_parameters * tp)
{
	tp->initial_max_stream_data = 65535;
	tp->initial_max_data = 0x400000;
	tp->initial_max_stream_id = 65535;
	tp->idle_timeout = 30;
	tp->omit_connection_id = 0;
	tp->max_packet_size = PICOQUIC_MAX_PACKET_SIZE - 16 - 40;
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

        if (quic->cnx_list != NULL)
        {
            quic->cnx_list->previous_in_table = cnx;
        }
        else
        {
            quic->cnx_last = cnx;
        }
        cnx->next_in_table = quic->cnx_list;
        cnx->previous_in_table = NULL;
        quic->cnx_list = cnx;
        cnx->quic = quic;
    }

    if (cnx != NULL)
    {
		picoquic_int_transport_parameters(&cnx->local_parameters);
		picoquic_int_transport_parameters(&cnx->remote_parameters);

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

		if ((quic->flags &picoquic_context_server) == 0)
		{
			int ret = 0;

			if (preferred_version == 0)
			{
				cnx->proposed_version = picoquic_supported_versions[0];
			}
			else
			{
				cnx->proposed_version = preferred_version;
			}
			cnx->version = cnx->proposed_version;

			cnx->cnx_state = picoquic_state_client_init;
			if (cnx_id == 0)
			{
				picoquic_crypto_random(quic, &cnx_id, sizeof(uint64_t));
			}
			cnx->initial_cnxid = cnx_id;
			cnx->server_cnxid = 0;
		}
        else
        {
            cnx->first_stream.send_queue = NULL;
            cnx->cnx_state = picoquic_state_server_init;
            cnx->initial_cnxid = cnx_id;
			picoquic_crypto_random(quic, &cnx->server_cnxid, sizeof(uint64_t));
        }

		if (cnx != NULL)
		{

			cnx->first_sack_item.start_of_sack_range = 0;
			cnx->first_sack_item.end_of_sack_range = 0;
			cnx->first_sack_item.next_sack = NULL;
			cnx->sack_block_size_max = 0;

			cnx->first_stream.stream_id = 0;
			cnx->first_stream.consumed_offset = 0;
			cnx->first_stream.stream_flags = 0;
			cnx->first_stream.fin_offset = 0;
			cnx->first_stream.next_stream = NULL;
			cnx->first_stream.stream_data = NULL;
			cnx->first_stream.sent_offset = 0;

			cnx->aead_decrypt_ctx = NULL;
			cnx->aead_encrypt_ctx = NULL;

			picoquic_crypto_random(quic, &random_sequence, sizeof(uint32_t));
			cnx->send_sequence = random_sequence;

			cnx->send_mtu = (addr == NULL || addr->sa_family == AF_INET)?
				PICOQUIC_INITIAL_MTU_IPV4 : PICOQUIC_INITIAL_MTU_IPV6;

			cnx->nb_retransmit = 0;
			cnx->latest_retransmit_time = 0;

			cnx->retransmit_newest = NULL;
			cnx->retransmit_oldest = NULL;
			cnx->highest_acknowledged = cnx->send_sequence - 1;
			cnx->latest_time_acknowledged = start_time;
			cnx->latest_ack_received_time = start_time;
		}
    }

	/* Only initialize TLS after all parameters have been set */

	if (picoquic_tlscontext_create(quic, cnx) != 0)
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
        if (cnx_id != 0)
        {
            (void)picoquic_register_cnx_id(quic, cnx, cnx_id);
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

picoquic_state_enum picoquic_get_cnx_state(picoquic_cnx_t * cnx)
{
	return cnx->cnx_state;
}

picoquic_cnx_t * picoquic_get_first_cnx(picoquic_quic_t * quic)
{
	return quic->cnx_list;
}

void picoquic_clear_stream(picoquic_stream_head * stream)
{
    picoquic_stream_data ** pdata[2] = { &stream->stream_data, &stream->send_queue };

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

	if (should_free)
	{
		free(p);
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

int picoquic_reset_cnx_version(picoquic_cnx_t * cnx, uint8_t * bytes, size_t length)
{
	/* First parse the incoming connection negotiation to choose the
	* new version. If none is available, return an error */
	size_t byte_index = 0;
	uint32_t proposed_version = 0;
	int ret = 0;

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
				if (proposed_version == picoquic_supported_versions[i])
				{
					cnx->version = proposed_version;
					cnx->cnx_state = picoquic_state_client_renegotiate;

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

					/* Reset the TLS context, Re-initialize the tls connection */
					picoquic_tlscontext_free(cnx->tls_ctx);
					cnx->tls_ctx = NULL;
					ret = picoquic_tlscontext_create(cnx->quic, cnx);
					if (ret == 0)
					{
						ret = picoquic_initialize_stream_zero(cnx);
					}
					break;
				}
			}
		}
	}

	return ret;
}

void picoquic_delete_cnx(picoquic_cnx_t * cnx)
{
    picoquic_stream_head * stream;

    if (cnx != NULL)
    {
		if (cnx->alpn != NULL)
		{
			free(cnx->alpn);
			cnx->alpn = NULL;
		}

		if (cnx->sni != NULL)
		{
			free(cnx->sni);
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

		while (cnx->retransmit_newest != NULL)
		{
			picoquic_dequeue_retransmit_packet(cnx, cnx->retransmit_newest, 1);
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
    picoquic_net_id key = { 0 };

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
