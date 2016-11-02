/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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

#ifndef __MPLS_TUNNEL_H__
#define __MPLS_TUNNEL_H__

#include <vnet/mpls/mpls.h>

/**
 * @brief A uni-directional MPLS tunnel
 */
typedef struct mpls_tunnel_t_
{
    /**
     * @brief The tunnel hooks into the FIB control plane graph.
     */
    fib_node_t mt_node;

    /**
     * @brief If the tunnel is an L2 tunnel, this is the link type ETHERNET
     * adjacency
     */
    adj_index_t mt_l2_adj;

    /**
     * @brief on a L2 tunnel this is the VLIB arc from the L2-tx to the l2-midchain
     */
    u32 mt_l2_tx_arc;

    /**
     * @brief The path-list over which the tunnel's destination is reachable
     */
    fib_node_index_t mt_path_list;

    /**
     * @brief sibling index on the path-list so notifications are received.
     */
    u32 mt_sibling_index;

    /**
     * @brief The Label stack to apply to egress packets
     */
    mpls_label_t *mt_label_stack;

    /**
     * @brief Flag to indicate the tunnel is only for L2 traffic, that is
     * this tunnel belongs in a bridge domain.
     */
    u8 mt_l2_only;

    /**
     * @brief The HW interface index of the tunnel interfaces
     */
    u32 mt_hw_if_index;

    /**
     * @brief The SW interface index of the tunnel interfaces
     */
    u32 mt_sw_if_index;

} mpls_tunnel_t;

/**
 * @brief Create a new MPLS tunnel
 */
extern void vnet_mpls_tunnel_add (fib_route_path_t *rpath,
				  mpls_label_t *label_stack,
				  u8 l2_only,
				  u32 *sw_if_index);

extern void vnet_mpls_tunnel_del (u32 sw_if_index);

extern const mpls_tunnel_t *mpls_tunnel_get(u32 index);

/**
 * @brief Callback function invoked while walking MPLS tunnels
 */
typedef void (*mpls_tunnel_walk_cb_t)(u32 index, void *ctx);

/**
 * @brief Walk all the MPLS tunnels
 */
extern void mpls_tunnel_walk(mpls_tunnel_walk_cb_t cb,
			     void *ctx);

#endif
