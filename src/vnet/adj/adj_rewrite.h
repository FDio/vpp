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
 * A rewrite adjacency has no key, and thus cannot be 'found' from the
 * FIB resolution code. the client therefore needs to maange these adjacencies
 */

#ifndef __ADJ_REWRITE_H__
#define __ADJ_REWRITE_H__

#include <vnet/adj/adj_types.h>

/**
 * @brief
 *  Add (and lock) a new or lock an existing neighbour adjacency
 *
 * @param nh_proto
 *  The protocol for the next-hop address (v4 or v6)
 *
 * @param link_type
 *  A description of the protocol of the packets that will forward
 *  through this adj. On an ethernet interface this is the MAC header's
 *  ether-type
 *
 * @param sw_if_index
 *  The interface on which the peer resides
 *
 * @param rewrite
 *  The rewrite to prepend to packets
 */
extern adj_index_t adj_rewrite_add_and_lock(fib_protocol_t nh_proto,
					    vnet_link_t link_type,
					    u32 sw_if_index,
					    u8 *rewrite);

#endif
