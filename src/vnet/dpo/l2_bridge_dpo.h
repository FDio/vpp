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

#ifndef __L2_BRIDGE_DPO_H__
#define __L2_BRIDGE_DPO_H__

#include <vnet/dpo/dpo.h>

/**
 * @brief
 * The data-path object representing an L2 bridge.
 * If a packet encounters an object of this type in the L3 data-path, it
 * is injected back into the L2 bridge.
 */
typedef struct l2_bridge_dpo_t_
{
    /**
     * The Software interface index that the packets will output on
     */
    u32 l2b_sw_if_index;

    /**
     * number of locks.
     */
    u16 l2b_locks;
} l2_bridge_dpo_t;

extern void l2_bridge_dpo_add_or_lock (u32 sw_if_index,
                                       dpo_id_t *dpo);

extern void l2_bridge_dpo_module_init(void);

/**
 * @brief pool of all interface DPOs
 */
l2_bridge_dpo_t *l2_bridge_dpo_pool;

static inline l2_bridge_dpo_t *
l2_bridge_dpo_get (index_t index)
{
    return (pool_elt_at_index(l2_bridge_dpo_pool, index));
}

#endif
