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
#include <vnet/fib/fib_path_ext.h>

typedef enum mpls_tunnel_attribute_t_
{
    MPLS_TUNNEL_ATTRIBUTE_FIRST = 0,
    /**
     * @brief The tunnel is L2 only
     */
    MPLS_TUNNEL_ATTRIBUTE_L2 = MPLS_TUNNEL_ATTRIBUTE_FIRST,
    /**
     * @brief The tunnel has an underlying multicast LSP
     */
    MPLS_TUNNEL_ATTRIBUTE_MCAST,
    MPLS_TUNNEL_ATTRIBUTE_LAST = MPLS_TUNNEL_ATTRIBUTE_MCAST,
} mpls_tunnel_attribute_t;

#define MPLS_TUNNEL_ATTRIBUTES {		  \
    [MPLS_TUNNEL_ATTRIBUTE_MCAST]  = "multicast", \
    [MPLS_TUNNEL_ATTRIBUTE_L2]     = "L2",   \
}
#define FOR_EACH_MPLS_TUNNEL_ATTRIBUTE(_item)		\
    for (_item = MPLS_TUNNEL_ATTRIBUTE_FIRST;		\
	 _item <= MPLS_TUNNEL_ATTRIBUTE_LAST;		\
	 _item++)

typedef enum mpls_tunnel_flag_t_ {
    MPLS_TUNNEL_FLAG_NONE   = 0,
    MPLS_TUNNEL_FLAG_L2     = (1 << MPLS_TUNNEL_ATTRIBUTE_L2),
    MPLS_TUNNEL_FLAG_MCAST  = (1 << MPLS_TUNNEL_ATTRIBUTE_MCAST),
} __attribute__ ((packed)) mpls_tunnel_flags_t;


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
     * @brief Tunnel flags
     */
    mpls_tunnel_flags_t mt_flags;

    /**
     * @brief User defined name tag for this MPLS Tunnel.
     */
    u8 mt_tag[64];

    /**
     * @brief If the tunnel is an L2 tunnel, this is the link type ETHERNET
     * load-balance
     */
    dpo_id_t mt_l2_lb;

    /**
     * @brief The HW interface index of the tunnel interfaces
     */
    u32 mt_hw_if_index;

    /**
     * @brief The SW interface index of the tunnel interfaces
     */
    u32 mt_sw_if_index;

    /**
     * @brief The path-list over which the tunnel's destination is reachable
     */
    fib_node_index_t mt_path_list;

    /**
     * @brief sibling index on the path-list so notifications are received.
     */
    u32 mt_sibling_index;

    /**
     * A vector of path extensions o hold the label stack for each path
     */
    fib_path_ext_list_t mt_path_exts;
} mpls_tunnel_t;

/**
 * @brief Create a new MPLS tunnel
 * @return the SW Interface index of the newly created tunnel
 */
extern u32 vnet_mpls_tunnel_create (u8 l2_only,
                                    u8 is_multicast,
                                    u8 *description);

/**
 * @brief Add a path to an MPLS tunnel
 */
extern void vnet_mpls_tunnel_path_add (u32 sw_if_index,
                                       fib_route_path_t *rpath);

/**
 * @brief remove a path from a tunnel.
 * @return the number of remaining paths. 0 implies the tunnel can be deleted
 */
extern int vnet_mpls_tunnel_path_remove (u32 sw_if_index,
                                         fib_route_path_t *rpath);

/**
 * @brief return the tunnel index from the sw_if_index
 */
extern int vnet_mpls_tunnel_get_index (u32 sw_if_index);

/**
 * @brief Delete an MPLS tunnel
 */
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
