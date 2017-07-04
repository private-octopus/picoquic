#include "picoquic.h"

/*
* Structures used in the hash table of connections
*/
typedef struct _picoquic_cnx_id
{
    uint64_t cnx_id;
    picoquic_cnx * cnx;
    struct _picoquic_cnx_id * next_cnx_id;
} picoquic_cnx_id;

typedef struct _picoquic_net_id
{
    struct sockaddr_storage saddr;
    picoquic_cnx * cnx;
    struct _picoquic_net_id * next_net_id;
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

/* QUIC context create and dispose */
picoquic_quic * picoquic_create(uint32_t nb_connections)
{
    picoquic_quic * quic = (picoquic_quic *)malloc(sizeof(picoquic_quic));

    if (quic != NULL)
    {
        /* TODO: winsock init */
        /* TODO: open UDP sockets - maybe */

        quic->flags = 0;

        quic->cnx_list = NULL;
        quic->cnx_last = NULL;

        quic->table_cnx_by_id = picohash_create(nb_connections * 4,
            picoquic_cnx_id_hash, picoquic_cnx_id_compare);

        quic->table_cnx_by_net = picohash_create(nb_connections * 4,
            picoquic_net_id_hash, picoquic_net_id_compare);

        if (quic->table_cnx_by_id == NULL ||
            quic->table_cnx_by_net == NULL)
        {
            picoquic_free(quic);
            quic = NULL;
        }
    }

    return quic;
}

void picoquic_free(picoquic_quic * quic)
{
    if (quic != NULL)
    {
        /* TODO: close the network sockets */

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
    }
}

/* Connection context creation and registration */
int picoquic_register_cnx_id(picoquic_quic * quic, picoquic_cnx * cnx, uint64_t cnx_id)
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

int picoquic_register_net_id(picoquic_quic * quic, picoquic_cnx * cnx, struct sockaddr * addr)
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

picoquic_cnx * picoquic_create_cnx(picoquic_quic * quic,
    uint64_t cnx_id, struct sockaddr * addr)
{
    picoquic_cnx * cnx = (picoquic_cnx *)malloc(sizeof(picoquic_cnx));

    if (cnx != NULL)
    {
        memset(cnx, 0, sizeof(picoquic_cnx));
        if (cnx_id != 0)
        {
            (void)picoquic_register_cnx_id(quic, cnx, cnx_id);
        }

        if (addr != NULL)
        {
            (void)picoquic_register_net_id(quic, cnx, addr);
        }

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

        cnx->first_sack_item.start_of_sack_range = 0;
        cnx->first_sack_item.end_of_sack_range = 0;
        cnx->first_sack_item.next_sack = NULL;
        cnx->sack_block_size_max = 0;
    }

    return cnx;
}

void picoquic_delete_cnx(picoquic_cnx * cnx)
{
    if (cnx != NULL)
    {
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

        free(cnx);
    }
}

/* Context retrieval functions */
picoquic_cnx * picoquic_cnx_by_id(picoquic_quic * quic, uint64_t cnx_id)
{
    picoquic_cnx * ret = NULL;
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

picoquic_cnx * picoquic_cnx_by_net(picoquic_quic * quic, struct sockaddr* addr)
{
    picoquic_cnx * ret = NULL;
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
