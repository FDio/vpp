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

#ifndef __BIER_DISP_TABLE_H__
#define __BIER_DISP_TABLE_H__

#include <vnet/ip/ip.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/replicate_dpo.h>

#include <vnet/bier/bier_types.h>
#include <vnet/bier/bier_disp_entry.h>

/**
 * @brief
 *   A protocol Independent IP multicast FIB table
 */
typedef struct bier_disp_table_t_
{
    /**
     * number of locks on the table
     */
    u16 bdt_locks;

    /**
     * Table ID (hash key) for this FIB.
     */
    u32 bdt_table_id;

    /**
     * The lookup DB based on sender BP. Value is the index of the
     * BIER disp object.
     */
    index_t bdt_db[BIER_BP_MAX];
} bier_disp_table_t;

/**
 * @brief
 *  Format the description/name of the table
 */
extern u8* format_bier_disp_table(u8* s, va_list *ap);

extern void bier_disp_table_entry_path_add(u32 table_id,
                                           bier_bp_t src,
                                           bier_hdr_proto_id_t payload_proto,
                                           const fib_route_path_t *rpath);

extern void bier_disp_table_entry_path_remove(u32 table_id,
                                              bier_bp_t src,
                                              bier_hdr_proto_id_t payload_proto,
                                              const fib_route_path_t *paths);

extern index_t bier_disp_table_find(u32 table_id);


extern index_t bier_disp_table_add_or_lock(u32 table_id);
extern void bier_disp_table_unlock_w_table_id(u32 table_id);

extern void bier_disp_table_unlock(index_t bdti);
extern void bier_disp_table_lock(index_t bdti);
extern void bier_disp_table_contribute_forwarding(index_t bdti,
                                                  dpo_id_t *dpo);

/**
 * Types and functions to walk all the entries in one BIER Table
 */
typedef void (*bier_disp_table_walk_fn_t)(const bier_disp_table_t *bdt,
                                          const bier_disp_entry_t *bde,
                                          u16 bp,
                                          void *ctx);
extern void bier_disp_table_walk(u32 table_id,
                                 bier_disp_table_walk_fn_t fn,
                                 void *ctx);

/**
 * @brief
 * Get a pointer to a FIB table
 */
extern bier_disp_table_t *bier_disp_table_pool;

static inline bier_disp_table_t *
bier_disp_table_get (index_t bdti)
{
    return (pool_elt_at_index(bier_disp_table_pool, bdti));
}

static inline index_t
bier_disp_table_lookup (index_t bdti,
                        bier_hdr_src_id_t src)
{
    bier_disp_table_t *bdt;

    bdt = bier_disp_table_get(bdti);

    return (bdt->bdt_db[src]);
}

#endif
