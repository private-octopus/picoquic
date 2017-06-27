/*
 * Basic hash implementation, like we have seen tons off already.
 */
#include <stdlib.h>
#include "picohash.h"


picohash_table * picohash_create(size_t nb_bin,
    uint64_t(*picohash_hash) (void *),
    int(*picohash_compare)(void *, void *))
{
    picohash_table * t = (picohash_table *)malloc(sizeof(picohash_table));
    if (t != NULL)
    {
        t->hash_bin = (picohash_item **)malloc(sizeof(picohash_item *)*nb_bin);

        if (t->hash_bin == NULL)
        {
            free(t);
            t = NULL;
        }
        else
        {
            (void)memset(t->hash_bin, 0, sizeof(picohash_item *)*nb_bin);
            t->nb_bin = nb_bin;
            t->count = 0;
            t->picohash_hash = picohash_hash;
            t->picohash_compare = picohash_compare;
        }
    }

    return t;
}

picohash_item * picohash_retrieve(picohash_table * hash_table, void * key)
{
    uint64_t hash = hash_table->picohash_hash(key);
    uint32_t bin = hash % hash_table->nb_bin;
    picohash_item * item = hash_table->hash_bin[bin];

    while (item != NULL)
    {
        if (hash_table->picohash_compare(key, item->key) == 0)
        {
            break;
        }
        else
        {
            item = item->next_in_bin;
        }
    }
}

int picohash_insert(picohash_table * hash_table, void* key)
{
    uint64_t hash = hash_table->picohash_hash(key);
    uint32_t bin = hash % hash_table->nb_bin;
    int ret = 0;
    picohash_item * item = (picohash_item *)malloc(sizeof(picohash_item));
    
    if (item == NULL)
    {
        ret = -1;
    }
    else
    {
        item->hash = hash;
        item->key = key;
        item->next_in_bin = hash_table->hash_bin[bin];
    }
    
    return ret;
}

void picohash_item_delete(picohash_table * hash_table, picohash_item * item, int delete_key_too)
{
    uint32_t bin = item->hash % hash_table->nb_bin;
    picohash_item * previous = hash_table->hash_bin[bin];
    
    if (previous == item)
    {
        hash_table->hash_bin[bin] = item->next_in_bin;
    }
    else while (previous != NULL)
    {
        if (previous->next_in_bin == item)
        {
            previous->next_in_bin = item->next_in_bin;
            break;
        }
        else
        {
            previous = previous->next_in_bin;
        }
    }

    if (delete_key_too)
    {
        free(item->key);
    }

    free(item);
}

void picohash_delete(picohash_table * hash_table, int delete_key_too)
{
    for (uint32_t i = 0; i < hash_table->nb_bin; i++)
    {
        while (hash_table->hash_bin[i] != NULL)
        {
            /* TODO: could be faster */
            picohash_item_delete(hash_table, hash_table->hash_bin[i], delete_key_too);
        }
    }

    free(hash_table->hash_bin);
    free(hash_table);
}