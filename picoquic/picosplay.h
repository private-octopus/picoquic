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

typedef int (*picosplay_comparator)(void *left, void *right);

typedef struct picosplay_node {
    struct picosplay_node *parent, *left, *right;
    void *value;
} picosplay_node;

typedef struct picosplay_tree {
    picosplay_node *root;
    picosplay_comparator comp;
    int size;
} picosplay_tree;

void picosplay_init_tree(picosplay_tree* tree, picosplay_comparator comp);
picosplay_tree* picosplay_new_tree(picosplay_comparator comp);
picosplay_node* picosplay_insert(picosplay_tree *tree, void *value);
picosplay_node* picosplay_find(picosplay_tree *tree, void *value);
picosplay_node* picosplay_first(picosplay_tree *tree);
picosplay_node* picosplay_next(picosplay_node *node);
picosplay_node* picosplay_last(picosplay_tree *tree);
void* picosplay_contents(picosplay_tree *tree);
void picosplay_delete(picosplay_tree *tree, void *value);
void picosplay_delete_hint(picosplay_tree *tree, picosplay_node *node);
void picosplay_empty_tree(picosplay_tree *tree);

#endif /* PICOSPLAY_H */
