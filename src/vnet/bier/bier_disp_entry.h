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
 * bier_dispositon : The BIER dispositon object
 *
 * A BIER dispositon object is used to pop the BIER header for for-us
 * packets and steer the packet down the payload protocol specific graph
 */

#ifndef __BIER_DISP_ENTRY_H__
#define __BIER_DISP_ENTRY_H__

#include <vnet/bier/bier_types.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/dpo.h>

/**
 * The BIER dispositon object
 */
typedef struct bier_disp_entry_t_ {
    /**
     * The DPO contirubted from the per-payload protocol parents
     * on cachline 1.
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
