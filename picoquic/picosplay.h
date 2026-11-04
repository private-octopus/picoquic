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

#ifndef PICOSPLAY_H
#define PICOSPLAY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_picosplay_node_t {
    struct st_picosplay_node_t *parent, *left, *right;
} picosplay_node_t;

typedef int64_t(*picosplay_comparator)(void *left, void *right);
typedef picosplay_node_t * (*picosplay_create)(void * value);
typedef void(*picosplay_delete_node)(void * tree, picosplay_node_t * node);
typedef void* (*picosplay_node_value)(picosplay_node_t * node);

typedef struct st_picosplay_tree_t {
    picosplay_node_t *root;
    picosplay_comparator comp;
    picosplay_create create; 
    picosplay_delete_node delete_node;
    picosplay_node_value node_value;
    int size;
} picosplay_tree_t;


void picosplay_init_tree(picosplay_tree_t* tree, picosplay_comparator comp, picosplay_create create, picosplay_delete_node delete_node, picosplay_node_value node_value);
picosplay_tree_t* picosplay_new_tree(picosplay_comparator comp, picosplay_create create, picosplay_delete_node delete_node, picosplay_node_value node_value);
picosplay_node_t* picosplay_insert(picosplay_tree_t *tree, void *value);
picosplay_node_t* picosplay_find(picosplay_tree_t *tree, void *value);
picosplay_node_t* picosplay_find_previous(picosplay_tree_t* tree, void* value);
picosplay_node_t* picosplay_first(picosplay_tree_t *tree);
picosplay_node_t* picosplay_previous(picosplay_node_t* node);
picosplay_node_t* picosplay_next(picosplay_node_t *node);
picosplay_node_t* picosplay_last(picosplay_tree_t *tree);
#if 0
/* analyzer flags a memory leak in this code. We do not use it yet. */
/* TODO: fix memory leak before restoring this. */
void* picosplay_contents(picosplay_tree_t *tree);
#endif
void picosplay_delete(picosplay_tree_t *tree, void *value);
void picosplay_delete_hint(picosplay_tree_t *tree, picosplay_node_t *node);
void picosplay_empty_tree(picosplay_tree_t *tree);

/* Unsigned integer keys, with no comparison or node-value callback. Both
 * offsets are relative to the value object; create returns its embedded node.
 * Keys must remain unchanged while linked. Unaligned keys are supported.
 * Equal keys retain insertion order in an in-order traversal.
 * Find/delete take the key itself. Find splays a matching node; find_previous
 * returns the greatest key <= the query without splaying. Creation/deletion
 * callbacks follow the generic API and receive this tree on deletion.
 * Nodes share picosplay_previous/picosplay_next with the generic tree.
 */
typedef struct st_picosplay64u_tree_t {
    picosplay_node_t* root;
    picosplay_create create;
    picosplay_delete_node delete_node;
    size_t key_offset;
    size_t node_offset;
    int size;
} picosplay64u_tree_t;

void picosplay64u_init_tree(picosplay64u_tree_t* tree, size_t key_offset, size_t node_offset,
    picosplay_create create, picosplay_delete_node delete_node);
picosplay_node_t* picosplay64u_insert(picosplay64u_tree_t* tree, void* value);
picosplay_node_t* picosplay64u_find(picosplay64u_tree_t* tree, uint64_t key);
picosplay_node_t* picosplay64u_find_previous(picosplay64u_tree_t* tree, uint64_t key);
picosplay_node_t* picosplay64u_first(picosplay64u_tree_t* tree);
picosplay_node_t* picosplay64u_last(picosplay64u_tree_t* tree);
void picosplay64u_delete(picosplay64u_tree_t* tree, uint64_t key);
void picosplay64u_delete_hint(picosplay64u_tree_t* tree, picosplay_node_t* node);
void picosplay64u_empty_tree(picosplay64u_tree_t* tree);

#ifdef __cplusplus
}
#endif

#endif /* PICOSPLAY_H */
