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

/*
 * Basic hash implementation, like we have seen tons off already.
 */
#include "picohash.h"
#include <stdlib.h>
#include <string.h>

picohash_table* picohash_create(size_t nb_bin,
    uint64_t (*picohash_hash)(void*),
    int (*picohash_compare)(void*, void*))
{
    picohash_table* t = (picohash_table*)malloc(sizeof(picohash_table));
    if (t != NULL) {
        t->hash_bin = (picohash_item**)malloc(sizeof(picohash_item*) * nb_bin);

        if (t->hash_bin == NULL) {
            free(t);
            t = NULL;
        } else {
            (void)memset(t->hash_bin, 0, sizeof(picohash_item*) * nb_bin);
            t->nb_bin = nb_bin;
            t->count = 0;
            t->picohash_hash = picohash_hash;
            t->picohash_compare = picohash_compare;
        }
    }

    return t;
}

picohash_item* picohash_retrieve(picohash_table* hash_table, void* key)
{
    uint64_t hash = hash_table->picohash_hash(key);
    uint32_t bin = (uint32_t)(hash % hash_table->nb_bin);
    picohash_item* item = hash_table->hash_bin[bin];

    while (item != NULL) {
        if (hash_table->picohash_compare(key, item->key) == 0) {
            break;
        } else {
            item = item->next_in_bin;
        }
    }

    return item;
}

int picohash_insert(picohash_table* hash_table, void* key)
{
    uint64_t hash = hash_table->picohash_hash(key);
    uint32_t bin = (uint32_t)(hash % hash_table->nb_bin);
    int ret = 0;
    picohash_item* item = (picohash_item*)malloc(sizeof(picohash_item));

    if (item == NULL) {
        ret = -1;
    } else {
        item->hash = hash;
        item->key = key;
        item->next_in_bin = hash_table->hash_bin[bin];
        hash_table->hash_bin[bin] = item;
        hash_table->count++;
    }

    return ret;
}

void picohash_item_delete(picohash_table* hash_table, picohash_item* item, int delete_key_too)
{
    uint32_t bin = (uint32_t)(item->hash % hash_table->nb_bin);
    picohash_item* previous = hash_table->hash_bin[bin];

    if (previous == item) {
        hash_table->hash_bin[bin] = item->next_in_bin;
    } else
        while (previous != NULL) {
            if (previous->next_in_bin == item) {
                previous->next_in_bin = item->next_in_bin;
                break;
            } else {
                previous = previous->next_in_bin;
            }
        }

    if (delete_key_too) {
        free(item->key);
    }

    free(item);
}

void picohash_delete(picohash_table* hash_table, int delete_key_too)
{
    for (uint32_t i = 0; i < hash_table->nb_bin; i++) {
        while (hash_table->hash_bin[i] != NULL) {
            /* TODO: could be faster */
            picohash_item_delete(hash_table, hash_table->hash_bin[i], delete_key_too);
        }
    }

    free(hash_table->hash_bin);
    free(hash_table);
}

uint64_t picohash_bytes(uint8_t* key, uint32_t length)
{
    uint64_t hash = 0xDEADBEEF;

    for (uint32_t i = 0; i < length; i++) {
        hash ^= key[i];
        hash ^= ((hash << 31) ^ (hash >> 17));
    }

    return hash;
}