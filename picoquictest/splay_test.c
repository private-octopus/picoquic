/*
* Author: Christian Huitema
* Copyright (c) 2018, Private Octopus, Inc.
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
*
* This code is copied and adapted from https://github.com/lrem/splay,
* copyright (c) Remigiusz Modrzejewski 2014, filed on Github with MIT license.
*/

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "picoquic_utils.h"
#include "picosplay.h"
#include "picorbtree.h"

typedef struct st_int_node_t {
    int v;
    picosplay_node_t node;
} int_node_t;

typedef struct st_picorbtree_test_item_t {
    unsigned char tag;
    unsigned char key_bytes[sizeof(uint64_t)];
    unsigned int serial;
    int live;
    picorbtree_node_t node;
} picorbtree_test_item_t;

static uint64_t picorbtree_test_key(const picorbtree_test_item_t* item)
{
    uint64_t key;
    memcpy(&key, item->key_bytes, sizeof(key));
    return key;
}

static picorbtree_test_item_t* picorbtree_test_value(picorbtree_node_t* node)
{
    return (picorbtree_test_item_t*)((char*)node - offsetof(picorbtree_test_item_t, node));
}

static int picorbtree_test_contains(picorbtree_node_t* root, const picorbtree_node_t* node)
{
    if (root == NULL) {
        return 0;
    }
    return root == node || picorbtree_test_contains(root->left, node) ||
        picorbtree_test_contains(root->right, node);
}

static int picorbtree_test_walk(picorbtree_node_t* node, picorbtree_node_t* parent,
    uint64_t* last_key, unsigned int* last_serial, int* have_last, size_t* count)
{
    int left_black_height, right_black_height;
    picorbtree_test_item_t* item;

    if (node == NULL) {
        return 1;
    }
    if (node->parent != parent ||
        (node->color != 0 && node->color != 1) ||
        (node->color != 0 && ((node->left != NULL && node->left->color != 0) ||
            (node->right != NULL && node->right->color != 0)))) {
        return 0;
    }
    left_black_height = picorbtree_test_walk(node->left, node, last_key, last_serial, have_last, count);
    item = picorbtree_test_value(node);
    if (left_black_height == 0 || (*have_last &&
        (picorbtree_test_key(item) < *last_key ||
            (picorbtree_test_key(item) == *last_key && item->serial < *last_serial)))) {
        return 0;
    }
    *last_key = picorbtree_test_key(item);
    *last_serial = item->serial;
    *have_last = 1;
    (*count)++;
    right_black_height = picorbtree_test_walk(node->right, node, last_key, last_serial, have_last, count);
    if (right_black_height != left_black_height) {
        return 0;
    }
    return left_black_height + (node->color == 0);
}

static picorbtree_node_t* picorbtree_test_expected_first(picorbtree_test_item_t* items, size_t item_count)
{
    picorbtree_test_item_t* first = NULL;
    size_t i;

    for (i = 0; i < item_count; i++) {
        uint64_t item_key;
        uint64_t first_key;

        if (!items[i].live) {
            continue;
        }
        if (first == NULL) {
            first = &items[i];
            continue;
        }
        item_key = picorbtree_test_key(&items[i]);
        first_key = picorbtree_test_key(first);
        if (item_key < first_key || (item_key == first_key && items[i].serial < first->serial)) {
            first = &items[i];
        }
    }
    return first == NULL ? NULL : &first->node;
}

static int picorbtree_test_check(picorbtree_tree_t* tree, picorbtree_test_item_t* items, size_t item_count)
{
    uint64_t last_key = 0;
    unsigned int last_serial = 0;
    int have_last = 0;
    size_t count = 0;
    size_t model_count = 0;
    size_t i;

    if ((tree->root != NULL && (tree->root->parent != NULL || tree->root->color != 0)) ||
        picorbtree_test_walk(tree->root, NULL, &last_key, &last_serial, &have_last, &count) == 0) {
        return -1;
    }
    for (i = 0; i < item_count; i++) {
        if (items[i].live) {
            model_count++;
        }
        if (items[i].live != picorbtree_test_contains(tree->root, &items[i].node)) {
            return -1;
        }
    }
    if (count != model_count || tree->size != model_count ||
        picorbtree_first(tree) != picorbtree_test_expected_first(items, item_count)) {
        return -1;
    }
    return 0;
}

int rbtree_test(void)
{
    static const uint64_t keys[] = { UINT64_MAX, 0, UINT64_C(1) << 63, 7, UINT64_MAX, 7, 0, 42, UINT64_C(1) << 63, 3, 9, 1 };
    picorbtree_test_item_t items[sizeof(keys) / sizeof(keys[0])];
    picorbtree_tree_t tree;
    const size_t item_count = sizeof(items) / sizeof(items[0]);
    size_t i;
    unsigned int serial = (unsigned int)item_count;

    memset(items, 0, sizeof(items));
    picorbtree_init(&tree, offsetof(picorbtree_test_item_t, key_bytes), offsetof(picorbtree_test_item_t, node));
    for (i = 0; i < item_count; i++) {
        memcpy(items[i].key_bytes, &keys[i], sizeof(keys[i]));
        items[i].serial = (unsigned int)i;
        items[i].live = 1;
        if (picorbtree_insert(&tree, &items[i]) != &items[i].node ||
            picorbtree_test_check(&tree, items, item_count) != 0) {
            return -1;
        }
    }

    /* Deleting the second node with key 7 must remove exactly that embedded node. */
    picorbtree_delete_hint(&tree, &items[5].node);
    items[5].live = 0;
    if (items[5].node.parent != NULL || items[5].node.left != NULL || items[5].node.right != NULL ||
        items[5].node.color != 0 || picorbtree_test_contains(tree.root, &items[5].node) ||
        !picorbtree_test_contains(tree.root, &items[3].node) ||
        picorbtree_test_check(&tree, items, item_count) != 0) {
        return -1;
    }

    for (i = 0; i < 48; i++) {
        size_t index = (i * 7 + 3) % item_count;

        if (items[index].live) {
            picorbtree_delete_hint(&tree, &items[index].node);
            items[index].live = 0;
            if (items[index].node.parent != NULL || items[index].node.left != NULL ||
                items[index].node.right != NULL || items[index].node.color != 0) {
                return -1;
            }
        }
        else {
            uint64_t key = keys[(i + i / item_count) % item_count];
            memcpy(items[index].key_bytes, &key, sizeof(key));
            items[index].serial = serial++;
            items[index].live = 1;
            if (picorbtree_insert(&tree, &items[index]) != &items[index].node) {
                return -1;
            }
        }
        if (picorbtree_test_check(&tree, items, item_count) != 0) {
            return -1;
        }
    }
    for (i = 0; i < item_count; i++) {
        if (items[i].live) {
            picorbtree_delete_hint(&tree, &items[i].node);
            items[i].live = 0;
            if (picorbtree_test_check(&tree, items, item_count) != 0) {
                return -1;
            }
        }
    }
    return tree.root == NULL && tree.size == 0 ? 0 : -1;
}

static int_node_t * new_int_node(int x) {
    int_node_t * i_n = (int_node_t *)malloc(sizeof(int_node_t));
    if (i_n != NULL) {
        i_n->v = x;
    }
    return i_n;
}

static int64_t compare_int(void* l, void* r) {

    return (int64_t)((int_node_t*)l)->v - ((int_node_t*)r)->v;
}

static picosplay_node_t * create_int_node(void * value)
{
    return &((int_node_t *)value)->node;
}


static void * int_node_value(picosplay_node_t * node)
{
    return (void*)((char*)node - offsetof(struct st_int_node_t, node));
}

static void delete_int_node(void* UNUSED(tree), picosplay_node_t* node)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tree);
#endif
    free(int_node_value(node));
}

static int check_node_sanity(picosplay_node_t *x, void *floor, void *ceil, picosplay_comparator comp) {
    int count = 0;

    if (x != NULL) {
        count = 1;
        if (x->left != NULL) {
            if (x->left->parent == x) {
                void *new_floor;
                if (floor == NULL || comp(int_node_value(x), floor) < 0)
                    new_floor = int_node_value(x);
                else
                    new_floor = floor;
                count += check_node_sanity(x->left, new_floor, ceil, comp);
            }
            else {
                DBG_PRINTF("%s", "Invalid node, left->parent != node.\n");
                count = -1;
            }
        }
        if (x->right != NULL && count > 0) {
            if (x->right->parent == x) {
                void *new_ceil;
                if (ceil == NULL || comp(int_node_value(x), ceil) > 0)
                    new_ceil = int_node_value(x);
                else
                    new_ceil = ceil;
                count += check_node_sanity(x->right, floor, new_ceil, comp);
            }
            else {
                DBG_PRINTF("%s", "Invalid node, left->parent != node.\n");
                count = -1;
            }
        }
    }

    return count;
}

/* Test both legal member orders. The leading byte makes the key offset non-zero. */
typedef struct st_splay_u64_node_first_t {
    picosplay_node_t node;
    uint64_t key;
    unsigned int serial;
} splay_u64_node_first_t;

typedef struct st_splay_u64_key_first_t {
    unsigned char tag;
    unsigned char key_bytes[sizeof(uint64_t)];
    unsigned int serial;
    picosplay_node_t node;
} splay_u64_key_first_t;

typedef struct st_splay_u64_key_zero_t {
    uint64_t key;
    picosplay_node_t node;
    unsigned int serial;
} splay_u64_key_zero_t;

typedef struct st_splay_u64_layout_t {
    size_t key_offset;
    size_t node_offset;
    size_t serial_offset;
    void* (*new_value)(uint64_t, unsigned int);
    picosplay_node_t* (*create)(void*);
    void* (*value)(picosplay_node_t*);
    picosplay_delete_node delete_node;
} splay_u64_layout_t;

static picosplay_node_t* splay_u64_deleted;

static void* splay_u64_node_first_new(uint64_t key, unsigned int serial)
{
    splay_u64_node_first_t* value = (splay_u64_node_first_t*)malloc(sizeof(*value));
    if (value != NULL) { value->key = key; value->serial = serial; }
    return value;
}

static picosplay_node_t* splay_u64_node_first_create(void* value) { return &((splay_u64_node_first_t*)value)->node; }
static picosplay_node_t* splay_u64_create_fail(void* UNUSED(value)) { return NULL; }
static void* splay_u64_node_first_value(picosplay_node_t* node) { return (char*)node - offsetof(splay_u64_node_first_t, node); }
static void splay_u64_node_first_delete(void* UNUSED(tree), picosplay_node_t* node)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tree);
#endif
    splay_u64_deleted = node;
    free(splay_u64_node_first_value(node));
}

static void* splay_u64_key_first_new(uint64_t key, unsigned int serial)
{
    splay_u64_key_first_t* value = (splay_u64_key_first_t*)malloc(sizeof(*value));
    if (value != NULL) { value->tag = 0; memcpy(value->key_bytes, &key, sizeof(key)); value->serial = serial; }
    return value;
}

static picosplay_node_t* splay_u64_key_first_create(void* value) { return &((splay_u64_key_first_t*)value)->node; }
static void* splay_u64_key_first_value(picosplay_node_t* node) { return (char*)node - offsetof(splay_u64_key_first_t, node); }
static void splay_u64_key_first_delete(void* UNUSED(tree), picosplay_node_t* node)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tree);
#endif
    splay_u64_deleted = node;
    free(splay_u64_key_first_value(node));
}

static void* splay_u64_key_zero_new(uint64_t key, unsigned int serial)
{
    splay_u64_key_zero_t* value = (splay_u64_key_zero_t*)malloc(sizeof(*value));
    if (value != NULL) { value->key = key; value->serial = serial; }
    return value;
}

static picosplay_node_t* splay_u64_key_zero_create(void* value) { return &((splay_u64_key_zero_t*)value)->node; }
static void* splay_u64_key_zero_value(picosplay_node_t* node) { return (char*)node - offsetof(splay_u64_key_zero_t, node); }
static void splay_u64_key_zero_delete(void* UNUSED(tree), picosplay_node_t* node)
{
#ifdef _WINDOWS
    UNREFERENCED_PARAMETER(tree);
#endif
    splay_u64_deleted = node;
    free(splay_u64_key_zero_value(node));
}

static uint64_t splay_u64_key(const splay_u64_layout_t* layout, const void* value)
{
    uint64_t key;
    memcpy(&key, (const char*)value + layout->key_offset, sizeof(key));
    return key;
}

static unsigned int splay_u64_serial(const splay_u64_layout_t* layout, const void* value)
{
    unsigned int serial;
    memcpy(&serial, (const char*)value + layout->serial_offset, sizeof(serial));
    return serial;
}

static int splay_u64_check_node(picosplay_node_t* node, picosplay_node_t* parent, const splay_u64_layout_t* layout,
    uint64_t* last_key, unsigned int* last_serial, int* have_last)
{
    int count, right_count;
    void* value;
    uint64_t key;
    unsigned int serial;
    if (node == NULL) return 0;
    if (node->parent != parent) return -1;
    count = splay_u64_check_node(node->left, node, layout, last_key, last_serial, have_last);
    if (count < 0) return -1;
    value = layout->value(node);
    key = splay_u64_key(layout, value);
    serial = splay_u64_serial(layout, value);
    if (*have_last && (key < *last_key || (key == *last_key && serial < *last_serial))) return -1;
    *last_key = key; *last_serial = serial; *have_last = 1;
    right_count = splay_u64_check_node(node->right, node, layout, last_key, last_serial, have_last);
    return right_count < 0 ? -1 : count + right_count + 1;
}

static int splay_u64_check(picosplay_tree_t* tree, const splay_u64_layout_t* layout, int expected)
{
    uint64_t last_key = 0;
    unsigned int last_serial = 0;
    int have_last = 0;
    int count = 0;
    picosplay_node_t* node;
    if (splay_u64_check_node(tree->root, NULL, layout, &last_key, &last_serial, &have_last) != expected || tree->size != expected) return -1;
    for (node = picosplay_first(tree); node != NULL; node = picosplay_next(node)) count++;
    if (count != expected) return -1;
    count = 0;
    for (node = picosplay_last(tree); node != NULL; node = picosplay_previous(node)) count++;
    return count == expected ? 0 : -1;
}

static int splay64_u64_check(picosplay64u_tree_t* tree, const splay_u64_layout_t* layout, int expected)
{
    uint64_t last_key = 0;
    unsigned int last_serial = 0;
    int have_last = 0;
    int count = 0;
    picosplay_node_t* node;
    if (splay_u64_check_node(tree->root, NULL, layout, &last_key, &last_serial, &have_last) != expected || tree->size != expected) return -1;
    for (node = picosplay64u_first(tree); node != NULL; node = picosplay_next(node)) count++;
    if (count != expected) return -1;
    count = 0;
    for (node = picosplay64u_last(tree); node != NULL; node = picosplay_previous(node)) count++;
    return count == expected ? 0 : -1;
}

static int splay_u64_record_index(picosplay_node_t* node, picosplay_node_t** records, size_t count)
{
    size_t i;
    for (i = 0; i < count; i++) if (records[i] == node) return (int)i;
    return -1;
}

static int splay_u64_layout_test(const splay_u64_layout_t* layout, picosplay_comparator comp)
{
    static const uint64_t keys[] = { UINT64_MAX, 0, UINT64_C(1) << 63, 7, UINT64_MAX, 7, 0, 42, UINT64_C(1) << 63, 3, 9, 1 };
    picosplay_tree_t tree;
    picosplay_node_t* records[sizeof(keys) / sizeof(keys[0])] = { 0 };
    size_t i;
    int count = 0, ret = 0;
    uint64_t key;
    void* probe = layout->new_value(0, 0);

    if (probe == NULL) return -1;

    picosplay_init_tree(&tree, comp, layout->create, layout->delete_node, layout->value);
    if (picosplay_find(&tree, probe) != NULL || picosplay_find_previous(&tree, probe) != NULL ||
        picosplay_first(&tree) != NULL || picosplay_last(&tree) != NULL) { free(probe); return -1; }
    picosplay_delete(&tree, probe);
    picosplay_delete_hint(&tree, NULL);
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]) && ret == 0; i++) {
        void* value = layout->new_value(keys[i], (unsigned int)i);
        records[i] = value == NULL ? NULL : picosplay_insert(&tree, value);
        if (records[i] == NULL || tree.root != records[i] || splay_u64_check(&tree, layout, ++count) != 0) ret = -1;
        if (i == 0 && (picosplay_find_previous(&tree, probe) != NULL ||
            picosplay_find(&tree, probe) != NULL || tree.root != records[i])) ret = -1;
    }
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]) && ret == 0; i++) {
        picosplay_node_t* found;
        picosplay_node_t* previous;
        memcpy((char*)probe + layout->key_offset, &keys[i], sizeof(keys[i]));
        found = picosplay_find(&tree, probe);
        previous = picosplay_find_previous(&tree, probe);
        if (found == NULL || tree.root != found || splay_u64_key(layout, layout->value(found)) != keys[i] || previous == NULL ||
            splay_u64_key(layout, layout->value(previous)) != keys[i] || splay_u64_check(&tree, layout, count) != 0) ret = -1;
    }
    if (ret == 0) {
        picosplay_node_t* root = tree.root;
        picosplay_node_t* previous;
        key = 6;
        memcpy((char*)probe + layout->key_offset, &key, sizeof(key));
        previous = picosplay_find_previous(&tree, probe);
        if (picosplay_find(&tree, probe) != NULL || previous == NULL || tree.root != root ||
            splay_u64_key(layout, layout->value(previous)) != 3) ret = -1;
        else {
            picosplay_delete(&tree, probe);
            if (splay_u64_check(&tree, layout, count) != 0) ret = -1;
        }
    }
    if (ret == 0) {
        int index;
        splay_u64_deleted = NULL;
        key = 7;
        memcpy((char*)probe + layout->key_offset, &key, sizeof(key));
        picosplay_delete(&tree, probe);
        index = splay_u64_record_index(splay_u64_deleted, records, sizeof(records) / sizeof(records[0]));
        if (index < 0 || splay_u64_check(&tree, layout, --count) != 0) ret = -1;
        else records[index] = NULL;
    }
    if (ret == 0) {
        splay_u64_deleted = NULL;
        picosplay_delete_hint(&tree, records[0]);
        if (splay_u64_deleted != records[0] || splay_u64_check(&tree, layout, --count) != 0) ret = -1;
        records[0] = NULL;
    }
    /* Deterministic deletion order rechecks every remaining parent/order link. */
    for (i = 0; i < sizeof(records) / sizeof(records[0]) && ret == 0; i++) if (records[(i * 5 + 1) % (sizeof(records) / sizeof(records[0]))] != NULL) {
        size_t j = (i * 5 + 1) % (sizeof(records) / sizeof(records[0]));
        picosplay_delete_hint(&tree, records[j]); records[j] = NULL;
        if (splay_u64_check(&tree, layout, --count) != 0) ret = -1;
    }
    free(probe);
    picosplay_empty_tree(&tree);
    picosplay_delete_hint(&tree, NULL);
    return ret == 0 && tree.root == NULL && tree.size == 0 ? 0 : -1;
}

static int splay64_u64_layout_test(const splay_u64_layout_t* layout)
{
    static const uint64_t keys[] = { UINT64_MAX, 0, UINT64_C(1) << 63, 7, UINT64_MAX, 7, 0, 42, UINT64_C(1) << 63, 3, 9, 1 };
    picosplay64u_tree_t tree;
    picosplay_node_t* records[sizeof(keys) / sizeof(keys[0])] = { 0 };
    size_t i;
    int count = 0, ret = 0;

    picosplay64u_init_tree(&tree, layout->key_offset, layout->node_offset, layout->create, layout->delete_node);
    if (picosplay64u_find(&tree, 0) != NULL || picosplay64u_find_previous(&tree, UINT64_MAX) != NULL ||
        picosplay64u_first(&tree) != NULL || picosplay64u_last(&tree) != NULL) return -1;
    picosplay64u_delete(&tree, 0);
    picosplay64u_delete_hint(&tree, NULL);
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]) && ret == 0; i++) {
        void* value = layout->new_value(keys[i], (unsigned int)i);
        records[i] = value == NULL ? NULL : picosplay64u_insert(&tree, value);
        if (records[i] == NULL || tree.root != records[i] || splay64_u64_check(&tree, layout, ++count) != 0) ret = -1;
        if (i == 0 && (picosplay64u_find_previous(&tree, UINT64_MAX - 1) != NULL ||
            picosplay64u_find(&tree, 0) != NULL || tree.root != records[i])) ret = -1;
    }
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]) && ret == 0; i++) {
        picosplay_node_t* found = picosplay64u_find(&tree, keys[i]);
        picosplay_node_t* previous = picosplay64u_find_previous(&tree, keys[i]);
        if (found == NULL || tree.root != found || splay_u64_key(layout, layout->value(found)) != keys[i] || previous == NULL ||
            splay_u64_key(layout, layout->value(previous)) != keys[i] || splay64_u64_check(&tree, layout, count) != 0) ret = -1;
    }
    if (ret == 0) {
        picosplay_node_t* root = tree.root;
        picosplay_node_t* previous = picosplay64u_find_previous(&tree, 6);
        if (picosplay64u_find(&tree, 6) != NULL || previous == NULL || tree.root != root ||
            splay_u64_key(layout, layout->value(previous)) != 3) ret = -1;
        else {
            picosplay64u_delete(&tree, 6);
            if (splay64_u64_check(&tree, layout, count) != 0) ret = -1;
        }
    }
    if (ret == 0) {
        int index;
        splay_u64_deleted = NULL;
        picosplay64u_delete(&tree, 7);
        index = splay_u64_record_index(splay_u64_deleted, records, sizeof(records) / sizeof(records[0]));
        if (index < 0 || splay64_u64_check(&tree, layout, --count) != 0) ret = -1;
        else records[index] = NULL;
    }
    if (ret == 0) {
        splay_u64_deleted = NULL;
        picosplay64u_delete_hint(&tree, records[0]);
        if (splay_u64_deleted != records[0] || splay64_u64_check(&tree, layout, --count) != 0) ret = -1;
        records[0] = NULL;
    }
    /* Deterministic deletion order rechecks every remaining parent/order link. */
    for (i = 0; i < sizeof(records) / sizeof(records[0]) && ret == 0; i++) if (records[(i * 5 + 1) % (sizeof(records) / sizeof(records[0]))] != NULL) {
        size_t j = (i * 5 + 1) % (sizeof(records) / sizeof(records[0]));
        picosplay64u_delete_hint(&tree, records[j]); records[j] = NULL;
        if (splay64_u64_check(&tree, layout, --count) != 0) ret = -1;
    }
    picosplay64u_empty_tree(&tree);
    picosplay64u_delete_hint(&tree, NULL);
    return ret == 0 && tree.root == NULL && tree.size == 0 ? 0 : -1;
}

static int64_t splay_u64_generic_compare(void* left, void* right)
{
    uint64_t l = ((splay_u64_node_first_t*)left)->key, r = ((splay_u64_node_first_t*)right)->key;
    return l < r ? -1 : l > r;
}

static int64_t splay_u64_key_first_compare(void* left, void* right)
{
    uint64_t l, r;
    memcpy(&l, ((splay_u64_key_first_t*)left)->key_bytes, sizeof(l));
    memcpy(&r, ((splay_u64_key_first_t*)right)->key_bytes, sizeof(r));
    return l < r ? -1 : l > r;
}

static int64_t splay_u64_key_zero_compare(void* left, void* right)
{
    uint64_t l = ((splay_u64_key_zero_t*)left)->key, r = ((splay_u64_key_zero_t*)right)->key;
    return l < r ? -1 : l > r;
}

static int splay_uint64_test(void)
{
    splay_u64_layout_t node_first = { offsetof(splay_u64_node_first_t, key), offsetof(splay_u64_node_first_t, node), offsetof(splay_u64_node_first_t, serial), splay_u64_node_first_new, splay_u64_node_first_create, splay_u64_node_first_value, splay_u64_node_first_delete };
    splay_u64_layout_t key_first = { offsetof(splay_u64_key_first_t, key_bytes), offsetof(splay_u64_key_first_t, node), offsetof(splay_u64_key_first_t, serial), splay_u64_key_first_new, splay_u64_key_first_create, splay_u64_key_first_value, splay_u64_key_first_delete };
    splay_u64_layout_t key_zero = { offsetof(splay_u64_key_zero_t, key), offsetof(splay_u64_key_zero_t, node), offsetof(splay_u64_key_zero_t, serial), splay_u64_key_zero_new, splay_u64_key_zero_create, splay_u64_key_zero_value, splay_u64_key_zero_delete };
    picosplay_tree_t failed_create;
    void* value = node_first.new_value(0, 0);

    if (value == NULL) return -1;
    picosplay_init_tree(&failed_create, splay_u64_generic_compare, splay_u64_create_fail, node_first.delete_node, node_first.value);
    if (picosplay_insert(&failed_create, value) != NULL || failed_create.root != NULL || failed_create.size != 0) { free(value); return -1; }
    free(value);
    return splay_u64_layout_test(&node_first, splay_u64_generic_compare) ||
        splay_u64_layout_test(&key_first, splay_u64_key_first_compare) ||
        splay_u64_layout_test(&key_zero, splay_u64_key_zero_compare);
}

static int splay64_uint64_test(void)
{
    splay_u64_layout_t node_first = { offsetof(splay_u64_node_first_t, key), offsetof(splay_u64_node_first_t, node), offsetof(splay_u64_node_first_t, serial), splay_u64_node_first_new, splay_u64_node_first_create, splay_u64_node_first_value, splay_u64_node_first_delete };
    /* key_bytes starts at odd offset one; the node remains naturally aligned. */
    splay_u64_layout_t key_first = { offsetof(splay_u64_key_first_t, key_bytes), offsetof(splay_u64_key_first_t, node), offsetof(splay_u64_key_first_t, serial), splay_u64_key_first_new, splay_u64_key_first_create, splay_u64_key_first_value, splay_u64_key_first_delete };
    splay_u64_layout_t key_zero = { offsetof(splay_u64_key_zero_t, key), offsetof(splay_u64_key_zero_t, node), offsetof(splay_u64_key_zero_t, serial), splay_u64_key_zero_new, splay_u64_key_zero_create, splay_u64_key_zero_value, splay_u64_key_zero_delete };
    static const uint64_t keys[] = { 0, UINT64_C(1) << 63, UINT64_MAX };
    picosplay_tree_t generic;
    picosplay64u_tree_t direct, failed_create;
    splay_u64_node_first_t probe = { { 0 }, 0, 0 };
    size_t i;
    void* value;

    /* A rejected create callback leaves the tree empty and does not take ownership. */
    picosplay64u_init_tree(&failed_create, node_first.key_offset, node_first.node_offset, splay_u64_create_fail, node_first.delete_node);
    value = node_first.new_value(0, 0);
    if (value == NULL) return -1;
    if (picosplay64u_insert(&failed_create, value) != NULL || failed_create.root != NULL || failed_create.size != 0) { free(value); return -1; }
    free(value);
    picosplay64u_empty_tree(NULL);

    /* Generic and direct trees agree at the unsigned boundaries. */
    picosplay_init_tree(&generic, splay_u64_generic_compare, node_first.create, node_first.delete_node, node_first.value);
    picosplay64u_init_tree(&direct, node_first.key_offset, node_first.node_offset, node_first.create, node_first.delete_node);
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        void* generic_value = node_first.new_value(keys[i], (unsigned int)i);
        void* direct_value = node_first.new_value(keys[i], (unsigned int)i);
        if (generic_value == NULL || direct_value == NULL) {
            free(generic_value); free(direct_value); picosplay_empty_tree(&generic); picosplay64u_empty_tree(&direct); return -1;
        }
        if (picosplay_insert(&generic, generic_value) == NULL) {
            free(generic_value); free(direct_value); picosplay_empty_tree(&generic); picosplay64u_empty_tree(&direct); return -1;
        }
        if (picosplay64u_insert(&direct, direct_value) == NULL) {
            free(direct_value); picosplay_empty_tree(&generic); picosplay64u_empty_tree(&direct); return -1;
        }
        if (splay_u64_key(&node_first, node_first.value(generic.root)) != keys[i] || splay_u64_key(&node_first, node_first.value(direct.root)) != keys[i]) {
            picosplay_empty_tree(&generic); picosplay64u_empty_tree(&direct); return -1;
        }
    }
    for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        picosplay_node_t* generic_found;
        picosplay_node_t* direct_found;
        probe.key = keys[i];
        generic_found = picosplay_find(&generic, &probe);
        direct_found = picosplay64u_find(&direct, keys[i]);
        if (generic_found == NULL || direct_found == NULL || generic.root != generic_found || direct.root != direct_found ||
            splay_u64_key(&node_first, node_first.value(generic_found)) != splay_u64_key(&node_first, node_first.value(direct_found))) {
            picosplay_empty_tree(&generic); picosplay64u_empty_tree(&direct); return -1;
        }
    }
    picosplay_empty_tree(&generic);
    picosplay64u_empty_tree(&direct);
    return splay64_u64_layout_test(&node_first) || splay64_u64_layout_test(&key_first) || splay64_u64_layout_test(&key_zero);
}

int splay_test(void) {
    int ret = 0;
    int count = 0;
    picosplay_tree_t *tree = picosplay_new_tree(&compare_int, create_int_node, delete_int_node, int_node_value);
    int values[] = {5, 7, 1, 3, 13, 9, 11};
    int values_first[] = { 5, 5, 1, 1, 1, 1, 1 };
    int values_last[] = { 5, 7, 7, 7, 13, 13, 13 };
    int previous_test[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14 };
    int previous_value[] = { -1, 1, 1, 3, 3, 5, 5, 7, 7, 9, 9, 11, 11, 13, 13 };
    int value2_first[] = { 1, 1, 3, 9, 9, 11, 0 };
    int value2_last[] = { 13, 13, 13, 13, 11, 11, 0 };

    if (tree == NULL) {
        DBG_PRINTF("%s", "Cannot create tree.\n");
        ret = -1;
    }
    else {
        for (int i = 0; ret == 0 && i < 7; i++) {
            picosplay_insert(tree, new_int_node(values[i]));
            /* Verify sanity and count after each insertion */
            count = check_node_sanity(tree->root, NULL, NULL, &compare_int);
            if (count != i + 1) {
                DBG_PRINTF("Insert v[%d] = %d, expected %d nodes, got %d instead\n",
                    i, values[i], i + 1, count);
                ret = -1;
            }
            else if (tree->size != count) {
                DBG_PRINTF("Insert v[%d] = %d, expected tree size %d, got %d instead\n",
                    i, values[i], count, tree->size);
                ret = -1;
            }
            else if (((int_node_t*)int_node_value(picosplay_first(tree)))->v != values_first[i]) {
                DBG_PRINTF("Insert v[%d] = %d, expected first = %d, got %d instead\n",
                    i, values[i],
                    values_first[i], ((int_node_t*)int_node_value(picosplay_first(tree)))->v);
                ret = -1;
            }
            else if (((int_node_t*)int_node_value(picosplay_last(tree)))->v != values_last[i]) {
                DBG_PRINTF("Insert v[%d] = %d, expected first = %d, got %d instead\n",
                    i, values[i],
                    values_last[i], ((int_node_t*)int_node_value(picosplay_last(tree)))->v);
                ret = -1;
            }
        }

        for (int i = 0; ret == 0 && i < 15; i++) {
            int_node_t x;
            picosplay_node_t* y;
            
            x.v = previous_test[i];
            y = picosplay_find(tree, (void*)&x);

            if (previous_value[i] == previous_test[i]) {
                if (y == NULL) {
                    DBG_PRINTF("Find v[%d] = %d, expected = %d, got NULL instead\n",
                        i, previous_test[i], previous_value[i]);
                    ret = -1;
                }
                else {
                    int v = ((int_node_t*)int_node_value(y))->v;
                    if (v != previous_value[i]) {
                        DBG_PRINTF("Find v[%d] = %d, expected = %d, got %d instead\n",
                            i, previous_test[i], previous_value[i], v);
                        ret = -1;
                    }
                }
            }
            else {
                if (y != NULL) {
                    DBG_PRINTF("Find v[%d], expected NULL, got %d instead\n",
                        i, ((int_node_t*)int_node_value(y))->v);
                    ret = -1;
                }
            }
        }

        for (int i = 0; ret == 0 && i < 15; i++) {
            int_node_t x;
            picosplay_node_t* y;

            x.v = previous_test[i];
            y = picosplay_find_previous(tree, (void*)&x);

            if (previous_value[i] >= 0) {
                if (y == NULL) {
                    DBG_PRINTF("Next v[%d] = %d, expected = %d, got NULL instead\n",
                        i, previous_test[i], previous_value[i]);
                    ret = -1;
                }
                else {
                    int v = ((int_node_t*)int_node_value(y))->v;
                    if (v != previous_value[i]) {
                        DBG_PRINTF("next v[%d] = %d, expected = %d, got %d instead\n",
                            i, previous_test[i], previous_value[i], v);
                        ret = -1;
                    }
                }
            }
            else {
                if (y != NULL) {
                    DBG_PRINTF("Next v[%d], expected NULL, got %d instead\n",
                        i, ((int_node_t*)int_node_value(y))->v);
                    ret = -1;
                }
            }
        }

        for (int i = 0; ret == 0 && i < 7; i++) {
            int_node_t to_delete = { 0 };
            to_delete.v = values[i];
            picosplay_delete(tree, &to_delete);
            /* Verify sanity and count after each deletion */
            count = check_node_sanity(tree->root, NULL, NULL, &compare_int);
            if (count != 6 - i) {
                DBG_PRINTF("Delete v[%d] = %d, expected %d nodes, got %d instead\n",
                    i, values[i], 6 - i, count);
                ret = -1;
            }
            else if (tree->size != count) {
                DBG_PRINTF("Insert v[%d] = %d, expected tree size %d, got %d instead\n",
                    i, values[i], count, tree->size);
                ret = -1;
            }
            else if (i < 6) {
                if (((int_node_t*)int_node_value(picosplay_first(tree)))->v != value2_first[i]) {
                    DBG_PRINTF("Delete v[%d] = %d, expected first = %d, got %d instead\n",
                        i, values[i], value2_first[i], ((int_node_t*)int_node_value(picosplay_first(tree)))->v);
                    ret = -1;
                }
                else if (((int_node_t*)int_node_value(picosplay_last(tree)))->v != value2_last[i]) {
                    DBG_PRINTF("Delete v[%d] = %d, expected first = %d, got %d instead\n",
                        i, values[i], value2_last[i], ((int_node_t*)int_node_value(picosplay_last(tree)))->v);
                    ret = -1;
                }
            }
        }

        if (ret == 0 && tree->root != NULL) {
            DBG_PRINTF("%s", "Final tree root should be NULL, is not.\n");
            ret = -1;
        }
        picosplay_empty_tree(tree);
        free(tree);
        tree = NULL;
    }

    if (ret == 0) {
        ret = splay_uint64_test();
    }
    if (ret == 0) {
        ret = splay64_uint64_test();
    }
    return ret;
}
