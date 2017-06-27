/*
 * Context hash.
 * Retrieve an object based on a hash of a context ID, or alternatively based on
 * source address and port number.
 */
#ifndef PICOHASH_H
#define PICOHASH_H
#include <stdint.h>


#ifdef  __cplusplus
extern "C" {
#endif


    typedef struct _picohash_item
    {
        uint64_t hash;
        struct _picohash_item * next_in_bin;
        void * key;
    } picohash_item;


    typedef struct picohash_table
    {
        /* TODO: lock ! */
        picohash_item ** hash_bin;
        size_t nb_bin;
        size_t count;
        uint64_t(*picohash_hash) (void *);
        int(*picohash_compare)(void *, void *);
    } picohash_table;

    picohash_table * picohash_create(size_t nb_bin,
        uint64_t(*picohash_hash) (void *),
        int(*picohash_compute)(void *, void *));

    picohash_item * picohash_retrieve(picohash_table * hash_table, void * key);

    int picohash_insert(picohash_table * hash_table, void* key);

    void picohash_item_delete(picohash_table * hash_table, picohash_item * item, int delete_key_too);

    void picohash_delete(picohash_table * hash_table, int delete_key_too);


#ifdef  __cplusplus
}
#endif

#endif /* PICOHASH_H */