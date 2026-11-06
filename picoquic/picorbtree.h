/*
 * MIT License
 *
 * Copyright (c) 2017 Private Octopus
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
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
