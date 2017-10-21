/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/**
 * bier_entry : The BIER entry
 *
 * The interface to the BIER entry is through a bier_entry_t* rather
 * than an index. This is becuase the BIER table allocates the entries
 * in a contiguous array once and only once when the table is created.
 * this is done for forwarding performance. The entry is thus not subject
 * to realloc, and does not need to be malloc'd when a route to that
 * bit-position is first learned.
 *
 */

#ifndef __BIER_ENTRY_H__
#define __BIER_ENTRY_H__

#include <vlib/vlib.h>
#include <vnet/fib/fib_node.h>
#include <vnet/bier/bier_types.h>

/**
 * Forward declarations
 */
struct bier_route_update_t_;
struct bier_fmask_db_t_;

/**
 * The BIER entry
 *
 * the BIER entry is the representation of a BIER forwarding egress router (BFER)
 * (or the egress PE) that is assigned a bit position.
 */
typedef struct bier_entry_t_ {
    /**
     * linkage into the FIB graph
     */
    fib_node_t be_node;

    /**
     * The index of the BIER table in which this entry resides
     */
    index_t be_bti;

    /**
     * the bit position this entry represents.
     *  this is the key table insertion
     */
    bier_bp_t be_bp;

    /**
     * the FIB path-list this entry resolves through.
     * the path-list is itself resoved on the entry's fmasks
     */
    fib_node_index_t be_path_list;
    /**
     * sibling index on the path list
     */
    fib_node_index_t be_sibling_index;
} bier_entry_t;

extern index_t bier_entry_create(index_t bti,
                                 bier_bp_t bp);
extern void bier_entry_delete(index_t bei);

extern void bier_entry_path_add(index_t bei,
                                const fib_route_path_t *brp);

extern int bier_entry_path_remove(index_t bei,
                                  const fib_route_path_t *brp);

extern u8* format_bier_entry(u8* s, va_list *ap);

extern void bier_entry_contribute_forwarding(index_t bei,
                                             dpo_id_t *dpo);

extern bier_entry_t *bier_entry_pool;
always_inline bier_entry_t* bier_entry_get(index_t bei)
{
    return (&bier_entry_pool[bei]);
}
#endif
