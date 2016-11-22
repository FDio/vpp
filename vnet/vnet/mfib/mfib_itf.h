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

typedef struct mfib_itf_t_
{
    mfib_itf_flags_t mfi_flags;
    u32 mfi_sw_if_index;
} mfib_itf_t;


extern index_t mfib_itf_create(u32 sw_if_index,
                               mfib_itf_flags_t mfi_flags);

extern u8 *format_mfib_itf(u8 * s, va_list * args);

extern mfib_itf_t *mfib_itf_pool;

static inline mfib_itf_t *
mfib_itf_get (index_t mi)
{
    return (pool_elt_at_index(mfib_itf_pool, mi));
}

#endif
