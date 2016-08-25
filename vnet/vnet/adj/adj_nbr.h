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
 * Neighbour Adjacency sub-type. These adjs represent an L3 peer on a
 * connected link. 
 */

#ifndef __ADJ_NBR_H__
#define __ADJ_NBR_H__

#include <vnet/vnet.h>
#include <vnet/adj/adj_types.h>
#include <vnet/fib/fib_node.h>
#include <vnet/dpo/dpo.h>

extern adj_index_t adj_nbr_add_or_lock(fib_protocol_t nh_proto,
				       fib_link_t link_type,
				       const ip46_address_t *nh_addr,
				       u32 sw_if_index);
extern adj_index_t adj_nbr_add_or_lock_w_rewrite(fib_protocol_t nh_proto,
						 fib_link_t link_type,
						 const ip46_address_t *nh_addr,
						 u32 sw_if_index,
						 u8 *rewrite);
extern void adj_nbr_update_rewrite(adj_index_t adj_index,
				   u8 *rewrite);
extern void adj_nbr_update_rewrite_header(adj_index_t adj_index,
					  vnet_rewrite_header_t *rwh);
extern void adj_nbr_module_init(void);

/*
 * for testing purposes
 */
extern u32 adj_nbr_db_size(void);

#endif
