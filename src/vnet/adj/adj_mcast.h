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
 * @brief Mcast Adjacency
 *
 * The multicast adjacency forwards IP traffic on an interface toward a multicast
 * group address. This is a different type of adjacency to a unicast adjacency
 * since the application of the MAC header is different, and so the VLIB node
 * visited is also different. DPO types have different VLIB nodes.
 */

#ifndef __ADJ_MCAST_H__
#define __ADJ_MCAST_H__

#include <vnet/adj/adj_types.h>
#include <vnet/adj/adj_midchain.h>

/**
 * @brief
 *  Add (and lock) a new or lock an existing mcast adjacency
 *
 * @param proto
 *  The protocol for the neighbours that we wish to mcast
 *
 * @param link_type
 *  A description of the protocol of the packets that will forward
 *  through this adj. On an ethernet interface this is the MAC header's
 *  ether-type
 *
 * @param sw_if_index
 *  The interface on which to mcast
 */
extern adj_index_t adj_mcast_add_or_lock(fib_protocol_t proto,
                                         vnet_link_t link_type,
					 u32 sw_if_index);

/**
 * @brief
 *  Update the rewrite string for an existing adjacecny.
 *
 * @param
 *  The index of the adj to update
 *
 * @param
 *  The new rewrite
 *
 * @param
 *  The offset in the rewrite a which to write in packet's
 *  IP Address
 *
 * @param
 *  The mask to apply to the packet berfore the rewrite.
 */
extern void adj_mcast_update_rewrite(adj_index_t adj_index,
                                     u8 *rewrite,
                                     u8 offset,
                                     u32 mask);

/**
 * @brief
 *  Update the rewrite string for an existing adjacecny and
 *  Convert the adjacency into a midchain
 *
 * @param
 *  The index of the adj to update
 *
 * @param
 *  The new rewrite
 */
extern void adj_mcast_midchain_update_rewrite(adj_index_t adj_index,
                                              adj_midchain_fixup_t fixup,
                                              adj_flags_t flags,
                                              u8 *rewrite,
                                              u8 offset,
                                              u32 mask);
/**
 * @brief Walk the multicast Adjacencies on a given interface
 */
extern void adj_mcast_walk (u32 sw_if_index,
                            fib_protocol_t adj_nh_proto,
                            adj_walk_cb_t cb,
                            void *ctx);

/**
 * @brief Format/display a mcast adjacency.
 */
extern u8* format_adj_mcast(u8* s, va_list *ap);
extern u8* format_adj_mcast_midchain(u8* s, va_list *ap);

/**
 * @brief Get the sze of the mcast adj DB. Test purposes only.
 */
extern u32 adj_mcast_db_size(void);

/**
 * @brief
 *  Module initialisation
 */
extern void adj_mcast_module_init(void);

#endif
