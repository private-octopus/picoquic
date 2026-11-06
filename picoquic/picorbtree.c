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

#include <string.h>
#include "picorbtree.h"

#define PICORBTREE_BLACK 0u
#define PICORBTREE_RED 1u

static unsigned int picorbtree_color(const picorbtree_node_t* node)
{
    return (node == NULL) ? PICORBTREE_BLACK : node->color;
}

static void picorbtree_set_color(picorbtree_node_t* node, unsigned int color)
{
    if (node != NULL) {
        node->color = (uint8_t)color;
    }
}

static uint64_t picorbtree_key_at(const picorbtree_tree_t* tree, const void* value)
{
    uint64_t key;

    memcpy(&key, (const uint8_t*)value + tree->key_offset, sizeof(key));
    return key;
}

static uint64_t picorbtree_node_key(const picorbtree_tree_t* tree, const picorbtree_node_t* node)
{
    return picorbtree_key_at(tree, (const uint8_t*)node - tree->node_offset);
}

static void picorbtree_replace(picorbtree_tree_t* tree, picorbtree_node_t* old_node, picorbtree_node_t* replacement)
{
    if (old_node->parent == NULL) {
        tree->root = replacement;
    }
    else if (old_node == old_node->parent->left) {
        old_node->parent->left = replacement;
    }
    else {
        old_node->parent->right = replacement;
    }

    if (replacement != NULL) {
        replacement->parent = old_node->parent;
    }
}

static void picorbtree_rotate_left(picorbtree_tree_t* tree, picorbtree_node_t* node)
{
    picorbtree_node_t* right = node->right;

    node->right = right->left;
    if (right->left != NULL) {
        right->left->parent = node;
    }
    picorbtree_replace(tree, node, right);
    right->left = node;
    node->parent = right;
}

static void picorbtree_rotate_right(picorbtree_tree_t* tree, picorbtree_node_t* node)
{
    picorbtree_node_t* left = node->left;

    node->left = left->right;
    if (left->right != NULL) {
        left->right->parent = node;
    }
    picorbtree_replace(tree, node, left);
    left->right = node;
    node->parent = left;
}

static void picorbtree_insert_fix(picorbtree_tree_t* tree, picorbtree_node_t* node)
{
    while (node->parent != NULL && picorbtree_color(node->parent) == PICORBTREE_RED) {
        picorbtree_node_t* parent = node->parent;
        picorbtree_node_t* grandparent = parent->parent;
        picorbtree_node_t* uncle;

        if (parent == grandparent->left) {
            uncle = grandparent->right;
            if (picorbtree_color(uncle) == PICORBTREE_RED) {
                picorbtree_set_color(parent, PICORBTREE_BLACK);
                picorbtree_set_color(uncle, PICORBTREE_BLACK);
                picorbtree_set_color(grandparent, PICORBTREE_RED);
                node = grandparent;
            }
            else {
                if (node == parent->right) {
                    node = parent;
                    picorbtree_rotate_left(tree, node);
                    parent = node->parent;
                    grandparent = parent->parent;
                }
                picorbtree_set_color(parent, PICORBTREE_BLACK);
                picorbtree_set_color(grandparent, PICORBTREE_RED);
                picorbtree_rotate_right(tree, grandparent);
            }
        }
        else {
            uncle = grandparent->left;
            if (picorbtree_color(uncle) == PICORBTREE_RED) {
                picorbtree_set_color(parent, PICORBTREE_BLACK);
                picorbtree_set_color(uncle, PICORBTREE_BLACK);
                picorbtree_set_color(grandparent, PICORBTREE_RED);
                node = grandparent;
            }
            else {
                if (node == parent->left) {
                    node = parent;
                    picorbtree_rotate_right(tree, node);
                    parent = node->parent;
                    grandparent = parent->parent;
                }
                picorbtree_set_color(parent, PICORBTREE_BLACK);
                picorbtree_set_color(grandparent, PICORBTREE_RED);
                picorbtree_rotate_left(tree, grandparent);
            }
        }
    }

    picorbtree_set_color(tree->root, PICORBTREE_BLACK);
}

static picorbtree_node_t* picorbtree_minimum(picorbtree_node_t* node)
{
    while (node != NULL && node->left != NULL) {
        node = node->left;
    }
    return node;
}

static void picorbtree_delete_fix(picorbtree_tree_t* tree, picorbtree_node_t* node, picorbtree_node_t* parent)
{
    /* A NULL node is black. Restore its missing black height before returning. */
    while (node != tree->root && picorbtree_color(node) == PICORBTREE_BLACK) {
        picorbtree_node_t* sibling;

        if (node == parent->left) {
            sibling = parent->right;
            if (picorbtree_color(sibling) == PICORBTREE_RED) {
                picorbtree_set_color(sibling, PICORBTREE_BLACK);
                picorbtree_set_color(parent, PICORBTREE_RED);
                picorbtree_rotate_left(tree, parent);
                sibling = parent->right;
            }
            if (picorbtree_color(sibling->left) == PICORBTREE_BLACK &&
                picorbtree_color(sibling->right) == PICORBTREE_BLACK) {
                picorbtree_set_color(sibling, PICORBTREE_RED);
                node = parent;
                parent = node->parent;
            }
            else {
                if (picorbtree_color(sibling->right) == PICORBTREE_BLACK) {
                    picorbtree_set_color(sibling->left, PICORBTREE_BLACK);
                    picorbtree_set_color(sibling, PICORBTREE_RED);
                    picorbtree_rotate_right(tree, sibling);
                    sibling = parent->right;
                }
                picorbtree_set_color(sibling, picorbtree_color(parent));
                picorbtree_set_color(parent, PICORBTREE_BLACK);
                picorbtree_set_color(sibling->right, PICORBTREE_BLACK);
                picorbtree_rotate_left(tree, parent);
                node = tree->root;
                parent = NULL;
            }
        }
        else {
            sibling = parent->left;
            if (picorbtree_color(sibling) == PICORBTREE_RED) {
                picorbtree_set_color(sibling, PICORBTREE_BLACK);
                picorbtree_set_color(parent, PICORBTREE_RED);
                picorbtree_rotate_right(tree, parent);
                sibling = parent->left;
            }
            if (picorbtree_color(sibling->right) == PICORBTREE_BLACK &&
                picorbtree_color(sibling->left) == PICORBTREE_BLACK) {
                picorbtree_set_color(sibling, PICORBTREE_RED);
                node = parent;
                parent = node->parent;
            }
            else {
                if (picorbtree_color(sibling->left) == PICORBTREE_BLACK) {
                    picorbtree_set_color(sibling->right, PICORBTREE_BLACK);
                    picorbtree_set_color(sibling, PICORBTREE_RED);
                    picorbtree_rotate_left(tree, sibling);
                    sibling = parent->left;
                }
                picorbtree_set_color(sibling, picorbtree_color(parent));
                picorbtree_set_color(parent, PICORBTREE_BLACK);
                picorbtree_set_color(sibling->left, PICORBTREE_BLACK);
                picorbtree_rotate_right(tree, parent);
                node = tree->root;
                parent = NULL;
            }
        }
    }

    picorbtree_set_color(node, PICORBTREE_BLACK);
}

void picorbtree_init(picorbtree_tree_t* tree, size_t key_offset, size_t node_offset)
{
    memset(tree, 0, sizeof(*tree));
    tree->key_offset = key_offset;
    tree->node_offset = node_offset;
}

picorbtree_node_t* picorbtree_insert(picorbtree_tree_t* tree, void* value)
{
    picorbtree_node_t* node = (picorbtree_node_t*)((uint8_t*)value + tree->node_offset);
    picorbtree_node_t* parent = NULL;
    picorbtree_node_t** link = &tree->root;
    uint64_t key = picorbtree_key_at(tree, value);

    memset(node, 0, sizeof(*node));
    node->color = PICORBTREE_RED;

    while (*link != NULL) {
        parent = *link;
        link = (key < picorbtree_node_key(tree, parent)) ?
            &parent->left : &parent->right;
    }

    node->parent = parent;
    *link = node;
    tree->size++;
    picorbtree_insert_fix(tree, node);

    return node;
}

picorbtree_node_t* picorbtree_first(const picorbtree_tree_t* tree)
{
    return picorbtree_minimum(tree->root);
}

void picorbtree_delete_hint(picorbtree_tree_t* tree, picorbtree_node_t* node)
{
    if (node != NULL) {
        picorbtree_node_t* replacement;
        picorbtree_node_t* replacement_parent;
        picorbtree_node_t* successor = node;
        unsigned int successor_color = successor->color;

        if (node->left == NULL) {
            replacement = node->right;
            replacement_parent = node->parent;
            picorbtree_replace(tree, node, replacement);
        }
        else if (node->right == NULL) {
            replacement = node->left;
            replacement_parent = node->parent;
            picorbtree_replace(tree, node, replacement);
        }
        else {
            /* Move the successor node itself, preserving every other node identity. */
            successor = picorbtree_minimum(node->right);
            successor_color = successor->color;
            replacement = successor->right;
            if (successor->parent == node) {
                replacement_parent = successor;
            }
            else {
                replacement_parent = successor->parent;
                picorbtree_replace(tree, successor, replacement);
                successor->right = node->right;
                successor->right->parent = successor;
            }
            picorbtree_replace(tree, node, successor);
            successor->left = node->left;
            successor->left->parent = successor;
            successor->color = node->color;
        }

        tree->size--;
        node->parent = NULL;
        node->left = NULL;
        node->right = NULL;
        if (successor_color == PICORBTREE_BLACK) {
            picorbtree_delete_fix(tree, replacement, replacement_parent);
        }
        node->color = PICORBTREE_BLACK;
    }
}
