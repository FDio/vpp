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

#ifndef __INTERFACE_RX_DPO_H__
#define __INTERFACE_RX_DPO_H__

#include <vnet/dpo/dpo.h>

/**
 * @brief
 * The data-path object representing a change of receive interface.
 * If a packet encounters an object of this type in the data-path, it's
 * RX interface is changed.
 */
typedef struct interface_rx_dpo_t_
{
    /**
     * The Software interface index that the packets will be given
     * as the ingress/rx interface
     */
    u32 ido_sw_if_index;

    /**
     * next VLIB node. A '<proto>-input' node.
     */
    u32 ido_next_node;

    /**
     * DPO protocol that the packets will have as they 'ingress'
     * on this interface
     */
    dpo_proto_t ido_proto;

    /**
     * number of locks.
     */
    u16 ido_locks;
} interface_rx_dpo_t;

extern void interface_rx_dpo_add_or_lock (dpo_proto_t proto,
                                          u32 sw_if_index,
                                          dpo_id_t *dpo);

extern void interface_rx_dpo_module_init(void);

/**
 * @brief pool of all interface DPOs
 */
interface_rx_dpo_t *interface_rx_dpo_pool;

static inline interface_rx_dpo_t *
interface_rx_dpo_get (index_t index)
{
    return (pool_elt_at_index(interface_rx_dpo_pool, index));
}

#endif
