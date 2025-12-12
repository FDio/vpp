/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/**
 * bier_disposition : The BIER disposition object
 *
 * A BIER disposition object is used to pop the BIER header for for-us
 * packets and steer the packet down the payload protocol specific graph
 */

#ifndef __BIER_DISP_ENTRY_H__
#define __BIER_DISP_ENTRY_H__

#include <vnet/bier/bier_types.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/dpo.h>

/**
 * The BIER disposition object
 */
typedef struct bier_disp_entry_t_ {
    /**
     * Required for pool_get_aligned
     */
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

    /**
     * The DPO contributed from the per-payload protocol parents
     * on cacheline 1.
     */
    struct
    {
        dpo_id_t bde_dpo;
        u32 bde_rpf_id;
    } bde_fwd[BIER_HDR_N_PROTO];

    /**
     * number of locks
     */
    u32 bde_locks;

    /**
     * The path-lists used by per-payload protocol parents.
     * We don't add the disp entry to the graph as a sibling
     * since there is nothing we can do with the updates to
     * forwarding.
     */
    fib_node_index_t bde_pl[BIER_HDR_N_PROTO];
} bier_disp_entry_t;

extern index_t bier_disp_entry_add_or_lock(void);
extern void bier_disp_entry_path_add(index_t bdei,
                                     bier_hdr_proto_id_t pproto,
                                     const fib_route_path_t *rpaths);
extern int bier_disp_entry_path_remove(index_t bdei,
                                       bier_hdr_proto_id_t pproto,
                                       const fib_route_path_t *rpaths);

extern void bier_disp_entry_unlock(index_t bdi);
extern void bier_disp_entry_lock(index_t bdi);

extern u8* format_bier_disp_entry(u8* s, va_list *ap);

extern void bier_disp_entry_contribute_forwarding(index_t bdi,
                                                  dpo_id_t *dpo);

extern bier_disp_entry_t *bier_disp_entry_pool;

always_inline bier_disp_entry_t*
bier_disp_entry_get (index_t bdi)
{
    return (pool_elt_at_index(bier_disp_entry_pool, bdi));
}

#endif
