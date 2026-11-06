/*
* Copyright (c) 2026, Private Octopus, Inc.
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

#ifndef PICORBTREE_H
#define PICORBTREE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Intrusive red-black tree for uint64_t keys. The key and node offsets are
 * relative to the value object. Keys need not be naturally aligned, but must
 * not change while their value is linked. Equal keys are ordered by insertion
 * order when traversed in-order.
 */
typedef struct st_picorbtree_node_t {
    struct st_picorbtree_node_t* parent;
    struct st_picorbtree_node_t* left;
    struct st_picorbtree_node_t* right;
    uint8_t color;
} picorbtree_node_t;

typedef struct st_picorbtree_tree_t {
    picorbtree_node_t* root;
    size_t size;
    size_t key_offset;
    size_t node_offset;
} picorbtree_tree_t;

void picorbtree_init(picorbtree_tree_t* tree, size_t key_offset, size_t node_offset);
picorbtree_node_t* picorbtree_insert(picorbtree_tree_t* tree, void* value);
picorbtree_node_t* picorbtree_first(const picorbtree_tree_t* tree);
void picorbtree_delete_hint(picorbtree_tree_t* tree, picorbtree_node_t* node);

#ifdef __cplusplus
}
#endif

#endif /* PICORBTREE_H */
