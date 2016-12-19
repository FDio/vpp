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

#ifndef __SIXRD_DPO_H__
#define __SIXRD_DPO_H__

#include <vnet/vnet.h>
#include <vnet/dpo/dpo.h>

/**
 * A representation of a 6RD DPO
 */
typedef struct sixrd_dpo_t
{
    /**
     * The dat-plane protocol
     */
    dpo_proto_t sd_proto;

    /**
     * the SIXRD domain index
     */
    u32 sd_domain;

    /**
     * Number of locks/users of the label
     */
    u16 sd_locks;
} sixrd_dpo_t;

extern void sixrd_dpo_create (dpo_proto_t dproto,
			      u32 domain_index,
			      dpo_id_t *dpo);

/*
 * Encapsulation violation for fast data-path access
 */
extern sixrd_dpo_t *sixrd_dpo_pool;
extern dpo_type_t sixrd_dpo_type;

static inline sixrd_dpo_t *
sixrd_dpo_get (index_t index)
{
    return (pool_elt_at_index(sixrd_dpo_pool, index));
}

extern void sixrd_dpo_module_init(void);

#endif
