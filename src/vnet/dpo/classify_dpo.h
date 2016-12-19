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

#ifndef __CLASSIFY_DPO_H__
#define __CLASSIFY_DPO_H__

#include <vnet/vnet.h>
#include <vnet/mpls/packet.h>
#include <vnet/dpo/dpo.h>

/**
 * A representation of an MPLS label for imposition in the data-path
 */
typedef struct classify_dpo_t
{
    dpo_proto_t cd_proto;

    u32 cd_table_index;

    /**
     * Number of locks/users of the label
     */
    u16 cd_locks;
} classify_dpo_t;

extern index_t classify_dpo_create(dpo_proto_t proto,
                                   u32 classify_table_index);

extern u8* format_classify_dpo(u8 *s, va_list *args);

/*
 * Encapsulation violation for fast data-path access
 */
extern classify_dpo_t *classify_dpo_pool;

static inline classify_dpo_t *
classify_dpo_get (index_t index)
{
    return (pool_elt_at_index(classify_dpo_pool, index));
}

extern void classify_dpo_module_init(void);

#endif
