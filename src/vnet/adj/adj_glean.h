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
 * @brief Glean Adjacency
 *
 * A gleean adjacency represent the need to discover new peers on an
 * attached link. Packets that hit a glean adjacency will generate an
 * ARP/ND packet addessesed to the packet's destination address.
 * Note this is different to an incomplete neighbour adjacency, which
 * does not send ARP/ND requests to the packet's destination address,
 * but instead to the next-hop address of the adjacency itself.
 */

#ifndef __ADJ_GLEAN_H__
#define __ADJ_GLEAN_H__

#include <vnet/adj/adj_types.h>

/**
 * @brief
 *  Add (and lock) a new or lock an existing glean adjacency
 *
 * @param proto
 *  The protocol for the neighbours that we wish to glean
 *
 * @param sw_if_index
 *  The interface on which to glean
 *
 * @param nh_addr
 *  the address applied to the interface on which to glean. This
 *  as the source address in packets when the ARP/ND packet is sent
 */
extern adj_index_t adj_glean_add_or_lock(fib_protocol_t proto,
                                         vnet_link_t linkt,
					 u32 sw_if_index,
					 const fib_prefix_t *conn);

/**
 * @brief Get an existing glean
 *
 * @return INVALID if it does not exist
 */
extern adj_index_t adj_glean_get(fib_protocol_t proto,
                                 u32 sw_if_index,
                                 const ip46_address_t *nh_addr);

/**
 * adj_glean_update_rewrite
 *
 * Called by an adjacency provider (an interface type) to configure
 * a glean adj (i.e. and adjacency linked to a connected prefix) to
 * its default behaviour.
 * Other interface types (i.e. 6RD tunnels) can can choose not to use
 * glean behaviour on an adjacency liked to a connected prefix.
 */
extern void adj_glean_update_rewrite(adj_index_t adj_index);
extern void adj_glean_update_rewrite_itf(u32 sw_if_index);

/**
 * Return the source address from the glean
 */
const ip46_address_t *adj_glean_get_src(fib_protocol_t proto,
                                        u32 sw_if_index,
                                        const ip46_address_t *nh_addr);

/**
 * @brief Format/display a glean adjacency.
 */
extern u8* format_adj_glean(u8* s, va_list *ap);

/**
 * Walk all the gleans on an interface
 */
extern void adj_glean_walk (u32 sw_if_index,
                            adj_walk_cb_t,
                            void *);

/**
 * @brief
 *  Module initialisation
 */
extern void adj_glean_module_init(void);

/**
 * @brief
 *  Return the size of the adjacency database. for testing purposes
 */
extern u32 adj_glean_db_size(void);

#endif
