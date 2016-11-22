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
     * @brief Falags on the entry
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
} mfib_itf_t;


extern index_t mfib_itf_create(u32 sw_if_index,
                               mfib_itf_flags_t mfi_flags);
extern void mfib_itf_delete(mfib_itf_t *mfi);

extern u8 *format_mfib_itf(u8 * s, va_list * args);

extern mfib_itf_t *mfib_itf_pool;

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
