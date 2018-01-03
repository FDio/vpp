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

#ifndef __DVR_DPO_H__
#define __DVR_DPO_H__

#include <vnet/dpo/dpo.h>

/**
 * @brief
 * The DVR DPO. Used as the resolving object for a DVR route.
 * This is used, in place of the usual L3 Adjacency, to retransmit
 * the packet with the original L2 header intact but also to run L3 features.
 * After running L3 features the packet is re-injected back into the L2 path
 * so it can pick up the necessary VLAN tags of the egress interface.
 * This re-injection is done with an output feature.
 */
typedef struct dvr_dpo_t_
{
    /**
     * The Software interface index that the packets will output on
     */
    u32 dd_sw_if_index;

    /**
     * The protocol of packets using this DPO
     */
    dpo_proto_t dd_proto;

    /**
     * number of locks.
     */
    u16 dd_locks;
} dvr_dpo_t;

extern void dvr_dpo_add_or_lock (u32 sw_if_index,
                                 dpo_proto_t dproto,
                                 dpo_id_t *dpo);

extern void dvr_dpo_module_init(void);

/**
 * @brief pool of all interface DPOs
 */
dvr_dpo_t *dvr_dpo_pool;

static inline dvr_dpo_t *
dvr_dpo_get (index_t index)
{
    return (pool_elt_at_index(dvr_dpo_pool, index));
}

#endif
