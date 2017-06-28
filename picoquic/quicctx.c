#include "picoquic.h"

/*
* Structures used in the hash table of connections
*/
typedef struct _picoquic_cnx_id
{
    uint64_t cnx_id;
    picoquic_cnx * cnx;
    struct picoquic_cnx_id * next_cnx_id;
} picoquic_cnx_id;

typedef struct _picoquic_net_id
{
    uint64_t cnx_id;
    struct sockaddr_storage saddr;
    struct picoquic_cnx_id * next_cnx_id;
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

    return picohash_bytes(&net->saddr, sizeof(net->saddr));
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
        /* TODO: chain of connections - maybe */

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
        /* TODO: delete all the connection contexts */
        /* TODO: close the network connections */

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

/* Context retrieval functions */
picoquic_cnx * get_cnx_by_id(picoquic_quic * quic, uint64_t cnx_id)
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

picoquic_cnx * get_cnx_by_net(picoquic_quic * quic, struct sockaddr* addr)
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

    item = picohash_retrieve(quic->table_cnx_by_id, &key);

    if (item != NULL)
    {
        ret = ((picoquic_cnx_id *)item->key)->cnx;
    }
    return ret;
}
