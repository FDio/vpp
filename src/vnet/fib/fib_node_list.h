/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/**
 * @brief a hetrogeneous w.r.t. FIB node type, list of FIB nodes.
 * Since we cannot use C pointers, due to memeory reallocs, the next/prev
 * are described as an index to an element. Each element contains a pointer
 * (key:{type, index}) to a FIB node.
 */

#ifndef __FIB_NODE_LIST_H__
#define __FIB_NODE_LIST_H__

#include <vnet/fib/fib_node.h>

extern fib_node_list_t fib_node_list_create(void);
extern void fib_node_list_destroy(fib_node_list_t *list);

extern u32 fib_node_list_push_front(fib_node_list_t head,
                                    int owner_id,
                                    fib_node_type_t type,
                                    fib_node_index_t index);
extern u32 fib_node_list_push_back(fib_node_list_t head,
                                   int owner_id,
                                   fib_node_type_t type,
                                   fib_node_index_t index);
extern void fib_node_list_remove(fib_node_list_t head,
                                 u32 sibling);
extern void fib_node_list_elt_remove(u32 sibling);

extern int fib_node_list_advance(u32 sibling);

extern int fib_node_list_get_front(fib_node_list_t head,
                                   fib_node_ptr_t *ptr);

extern int fib_node_list_elt_get_next(u32 elt,
                                      fib_node_ptr_t *ptr);

extern u32 fib_node_list_get_size(fib_node_list_t head);

/**
 * @brief Callback function invoked during a list walk
 */
typedef walk_rc_t (*fib_node_list_walk_cb_t)(fib_node_ptr_t *owner,
                                             void *args);

extern void fib_node_list_walk(fib_node_list_t head,
                               fib_node_list_walk_cb_t fn,
                               void *args);

extern void fib_node_list_memory_show(void);

#endif
