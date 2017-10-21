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

#ifndef __BIER_TABLE_H__
#define __BIER_TABLE_H__

#include <vlib/vlib.h>
#include <vnet/fib/fib_types.h>
#include <vnet/bier/bier_types.h>
#include <vnet/bier/bier_entry.h>

#include <vnet/dpo/dpo.h>

/**
 * Forward declarations
 */
struct bier_route_update_t_;

/**
 * A BIER Table is the bit-indexed forwarding table.
 * Each entry (bit-position) represents one destination, and its reachability
 *
 * The number of entries in a table is thus the maximum supported
 * bit-position. Since this is smal <4096, the table is a flat arry
 */
typedef struct bier_table_t_ {
    /**
     * Save the MPLS local label associated with the table
     */
    mpls_label_t bt_ll;

    /**
     * The path-list used for the ECMP-tables
     */
    fib_node_index_t bt_pl;

    /**
     * The index of the lfib entry created for this table.
     * Only the EOS is required.
     */
    fib_node_index_t bt_lfei;

    /**
     * Number of locks on the table
     */
    u16 bt_locks;

    /**
     * Entries in the table
     * This is a vector sized to the appropriate number of entries
     * given the table's supported Bit-string length
     */
    index_t *bt_entries;

    /**
     * Everything before this declaration is unused in the switch path
     */
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

    /**
     * The identity/key or the table. we need the hdr_len in the data-path
     */
    bier_table_id_t bt_id;

    /**
     * f-masks in the ECMP table
     * This is a vector sized to the appropriate number of entries
     * given the table's supported Bit-string length.
     * In the ECMP table the LB choice has been pre-resolved, so each entry
     * links to just one f-mask, i.e. there is a 1:1 mapping of bit-position to
     * fmask. For efficient forwarding we collapse the fmasks up to the table.
     */
    index_t *bt_fmasks;
} bier_table_t;

STATIC_ASSERT((sizeof(bier_table_t) <= 2*CLIB_CACHE_LINE_BYTES),
              "BIER table fits on 2 cache lines");

extern index_t bier_table_add_or_lock(const bier_table_id_t *id,
                                      mpls_label_t ll);
extern void bier_table_unlock(const bier_table_id_t *id);

extern void bier_table_route_add(const bier_table_id_t *bti,
                                 bier_bp_t bp,
                                 fib_route_path_t *brp);
extern void bier_table_route_remove(const bier_table_id_t *bti,
                                    bier_bp_t bp,
                                    fib_route_path_t *brp);

extern void bier_table_show_all(vlib_main_t * vm,
                                bier_show_flags_t flags);

extern const bier_table_id_t *bier_table_get_id(index_t bti);

extern u8 *format_bier_table (u8 *s, va_list *args);
extern u8 *format_bier_table_entry (u8 *s, va_list *args);

extern index_t bier_table_ecmp_create_and_lock(const bier_table_id_t *id);
extern void bier_table_ecmp_unlock(index_t bti);
extern void bier_table_ecmp_set_fmask(index_t bti,
                                      bier_bp_t bp,
                                      index_t bfmi);

extern void bier_table_contribute_forwarding(index_t bti,
                                             dpo_id_t *dpo);

/**
 * Types and functions to walk the ECMP tables of a main table
 */
typedef void (*bier_table_ecmp_walk_fn_t)(index_t btei,
                                          void *ctx);
extern void bier_table_ecmp_walk(index_t bti,
                                 bier_table_ecmp_walk_fn_t fn,
                                 void *ctx);
extern int bier_table_is_main (const bier_table_t *bt);

/**
 * Types and functions to walk all the BIER Tables
 */
typedef void (*bier_tables_walk_fn_t)(const bier_table_t *bt,
                                      void *ctx);
extern void bier_tables_walk(bier_tables_walk_fn_t fn,
                             void *ctx);

/**
 * Types and functions to walk all the entries in one BIER Table
 */
typedef void (*bier_table_walk_fn_t)(const bier_table_t *bt,
                                     const bier_entry_t *be,
                                     void *ctx);
extern void bier_table_walk(const bier_table_id_t *id,
                            bier_table_walk_fn_t fn,
                            void *ctx);

/*
 * provided for fast data plane access.
 */
extern bier_table_t *bier_table_pool;

static inline bier_table_t *
bier_table_get (index_t bti)
{
    return (pool_elt_at_index(bier_table_pool, bti));
}

static inline const index_t
bier_table_lookup (const bier_table_t *bt,
                   bier_bp_t bp)
{
    return (bt->bt_entries[BIER_BP_TO_INDEX(bp)]);
}

static inline const index_t
bier_table_fwd_lookup (const bier_table_t *bt,
                       bier_bp_t bp)
{
    return (bt->bt_fmasks[BIER_BP_TO_INDEX(bp)]);
}

#endif
