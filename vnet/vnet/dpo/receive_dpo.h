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
 * The data-path object representing receiveing the packet, i.e. it's for-us
 */

#ifndef __RECEIVE_DPO_H__
#define __RECEIVE_DPO_H__

#include <vnet/dpo/dpo.h>
#include <vnet/ip/ip6.h>

typedef struct receive_dpo_t_
{
    /**
     * The Software interface index on which traffic is received
     */
    u32 rd_sw_if_index;

    /**
     * The address on the receive interface. packet are destined to this address
     */
    ip46_address_t rd_addr;

    /**
     * number oflocks.
     */
    u16 rd_locks;
} receive_dpo_t;

extern void receive_dpo_add_or_lock (dpo_proto_t proto,
                                     u32 sw_if_index,
                                     const ip46_address_t *nh_addr,
                                     dpo_id_t *dpo);

extern void receive_dpo_module_init(void);

/**
 * @brief pool of all receive DPOs
 */
receive_dpo_t *receive_dpo_pool;

static inline receive_dpo_t *
receive_dpo_get (index_t index)
{
    return (pool_elt_at_index(receive_dpo_pool, index));
}

#endif
