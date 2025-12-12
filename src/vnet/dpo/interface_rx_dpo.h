/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
extern interface_rx_dpo_t *interface_rx_dpo_pool;

static inline interface_rx_dpo_t *
interface_rx_dpo_get (index_t index)
{
    return (pool_elt_at_index(interface_rx_dpo_pool, index));
}

#endif
