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

#ifndef __MFIB_ENTRY_H__
#define __MFIB_ENTRY_H__

#include <vnet/fib/fib_node.h>
#include <vnet/mfib/mfib_types.h>
#include <vnet/mfib/mfib_itf.h>
#include <vnet/ip/ip.h>
#include <vnet/dpo/dpo.h>

/**
 * An entry in a FIB table.
 *
 * This entry represents a route added to the FIB that is stored
 * in one of the FIB tables.
 */
typedef struct mfib_entry_t_ {
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
    /**
     * Base class. The entry's node representation in the graph.
     */
    fib_node_t mfe_node;
    /**
     * The prefix of the route
     */
    mfib_prefix_t mfe_prefix;
    /**
     * The index of the FIB table this entry is in
     */
    u32 mfe_fib_index;

    /**
     * A vector of sources contributing forwarding
     */
    struct mfib_entry_src_t_ *mfe_srcs;

    /**
     * The path-list of which this entry is a child
     */
    fib_node_index_t mfe_pl;

    /**
     * The sibling index on the path-list
     */
    u32 mfe_sibling;

    /**
     * 2nd cache line has the members used in the data plane
     */
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline1);

    /**
     * The DPO used for forwarding; replicate, drop, etc..
     */
    dpo_id_t mfe_rep;

    /**
     * Route flags
     */
    mfib_entry_flags_t mfe_flags;

    /**
     * RPF-ID used when the packets ingress not from an interface
     */
    fib_rpf_id_t mfe_rpf_id;

    /**
     * A hash table of interfaces
     */
    mfib_itf_t *mfe_itfs;
} mfib_entry_t;

#define MFIB_ENTRY_FORMAT_BRIEF   (0x0)
#define MFIB_ENTRY_FORMAT_DETAIL  (0x1)
#define MFIB_ENTRY_FORMAT_DETAIL2 (0x2)

extern u8 *format_mfib_entry(u8 * s, va_list * args);


extern fib_node_index_t mfib_entry_create(u32 fib_index,
                                          mfib_source_t source,
                                          const mfib_prefix_t *prefix,
                                          fib_rpf_id_t rpf_id,
                                          mfib_entry_flags_t entry_flags);

extern int mfib_entry_update(fib_node_index_t fib_entry_index,
                             mfib_source_t source,
                             mfib_entry_flags_t entry_flags,
                             fib_rpf_id_t rpf_id,
                             index_t rep_dpo);

extern void mfib_entry_path_update(fib_node_index_t fib_entry_index,
                                   mfib_source_t source,
                                   const fib_route_path_t *rpath);


extern int mfib_entry_path_remove(fib_node_index_t fib_entry_index,
                                  mfib_source_t source,
                                  const fib_route_path_t *rpath);

extern int mfib_entry_delete(fib_node_index_t mfib_entry_index,
                             mfib_source_t source);

extern int mfib_entry_cmp_for_sort(void *i1, void *i2);

extern u32 mfib_entry_child_add(fib_node_index_t mfib_entry_index,
                                fib_node_type_t type,
                                fib_node_index_t child_index);
extern void mfib_entry_child_remove(fib_node_index_t mfib_entry_index,
                                    u32 sibling_index);

extern void mfib_entry_lock(fib_node_index_t fib_entry_index);
extern void mfib_entry_unlock(fib_node_index_t fib_entry_index);

extern const mfib_prefix_t *mfib_entry_get_prefix(fib_node_index_t fib_entry_index);
extern u32 mfib_entry_get_fib_index(fib_node_index_t fib_entry_index);
extern int mfib_entry_is_sourced(fib_node_index_t fib_entry_index,
                                 mfib_source_t source);
extern u32 mfib_entry_get_stats_index(fib_node_index_t fib_entry_index);

extern const dpo_id_t*mfib_entry_contribute_ip_forwarding(
    fib_node_index_t mfib_entry_index);

extern void mfib_entry_contribute_forwarding(
    fib_node_index_t mfib_entry_index,
    fib_forward_chain_type_t type,
    dpo_id_t *dpo);

extern fib_route_path_t* mfib_entry_encode(fib_node_index_t fib_entry_index);

extern void mfib_entry_module_init(void);


extern mfib_entry_t *mfib_entry_pool;

static inline mfib_entry_t *
mfib_entry_get (fib_node_index_t index)
{
    return (pool_elt_at_index(mfib_entry_pool, index));
}
static inline fib_node_index_t
mfib_entry_get_index (const mfib_entry_t *mfe)
{
    return (mfe - mfib_entry_pool);
}


static inline mfib_itf_t *
mfib_entry_itf_find (mfib_itf_t *itfs,
                     u32 sw_if_index)
{
    uword *p;

    p = hash_get(itfs, sw_if_index);

    if (NULL != p)
    {
        return (mfib_itf_get(p[0]));
    }

    return (NULL);
}

static inline mfib_itf_t *
mfib_entry_get_itf (const mfib_entry_t *mfe,
                    u32 sw_if_index)
{
    return (mfib_entry_itf_find(mfe->mfe_itfs, sw_if_index));
}

#endif
