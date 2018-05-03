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

#ifndef __MFIB_ITF_H__
#define __MFIB_ITF_H__

#include <vlib/vlib.h>
#include <vnet/mfib/mfib_types.h>

/**
 * @brief An interface associated with a particular MFIB entry
 */
typedef struct mfib_itf_t_
{
    /**
     * Required for pool_get_aligned
     */
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

    /**
     * @brief Forwarding Flags on the entry - checked in the data-path
     */
    mfib_itf_flags_t mfi_flags;

    /**
     * The SW IF index that this MFIB interface represents
     */
    u32 mfi_sw_if_index;

    /**
     * The index of the signal in the pending list
     */
    u32 mfi_si;

    /**
     * A hash table of path-inidices that are contributing flags to this interface.
     * Since paths with next-hops can be on the same interface and each of those
     * paths can contribute different flags, we need to maintain the flag
     * contribution from each path, and use a combination for forwarding.
     */
    uword *mfi_hash;
} mfib_itf_t;

/**
 * update an interface from a path.
 * returns 1 if the entry is removed, i.e. has no flags left, as a result
 * of the update.
 */
extern int mfib_itf_update(mfib_itf_t *itf,
                           fib_node_index_t path_index,
                           mfib_itf_flags_t mfi_flags);

extern index_t mfib_itf_create(fib_node_index_t path_index,
                               mfib_itf_flags_t mfi_flags);

extern void mfib_itf_delete(mfib_itf_t *itf);

extern u8 *format_mfib_itf(u8 * s, va_list * args);

extern mfib_itf_t *mfib_itf_pool;

/**
 * Get the MFIB interface representation
 */
static inline mfib_itf_t *
mfib_itf_get (index_t mi)
{
    return (pool_elt_at_index(mfib_itf_pool, mi));
}

static inline index_t
mfib_itf_get_index (const mfib_itf_t *mfi)
{
    return (mfi - mfib_itf_pool);
}

#endif
