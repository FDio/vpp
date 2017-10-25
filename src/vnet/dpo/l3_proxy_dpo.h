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
 * @brief
 * The data-path object representing L3 proxy. An L3 proxy is when VPP has
 * an address in the FIB that is also assigned to an attached host.
 */

#ifndef __L3_PROXY_DPO_H__
#define __L3_PROXY_DPO_H__

#include <vnet/dpo/dpo.h>
#include <vnet/ip/ip6.h>

typedef struct l3_proxy_dpo_t_
{
    /**
     * The Software interface index on which traffic is l3_proxyd
     */
    u32 l3p_sw_if_index;

    /**
     * number oflocks.
     */
    u16 l3p_locks;
} l3_proxy_dpo_t;

extern void l3_proxy_dpo_add_or_lock (dpo_proto_t proto,
                                      u32 sw_if_index,
                                      dpo_id_t *dpo);

extern void l3_proxy_dpo_module_init(void);

/**
 * @brief pool of all l3_proxy DPOs
 */
l3_proxy_dpo_t *l3_proxy_dpo_pool;

static inline l3_proxy_dpo_t *
l3_proxy_dpo_get (index_t index)
{
    return (pool_elt_at_index(l3_proxy_dpo_pool, index));
}

#endif
