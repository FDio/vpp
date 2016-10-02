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

#include <vnet/adj/adj.h>
#include <vnet/adj/adj_internal.h>

/**
 * adj_rewrite_add_and_lock
 *
 * A rewrite sub-type has the rewrite string provided, but no key
 */
adj_index_t
adj_rewrite_add_and_lock (fib_protocol_t nh_proto,
			  fib_link_t link_type,
			  u32 sw_if_index,
			  u8 *rewrite)
{
    ip_adjacency_t *adj;

    adj = adj_alloc(nh_proto);

    adj->lookup_next_index = IP_LOOKUP_NEXT_REWRITE;
    adj->ia_link = link_type;
    adj->rewrite_header.sw_if_index = sw_if_index;

    ASSERT(NULL != rewrite);

    vnet_rewrite_for_sw_interface(vnet_get_main(),
				  adj_fib_link_2_vnet(link_type),
				  adj->rewrite_header.sw_if_index,
				  adj_get_rewrite_node(link_type)->index,
				  rewrite,
				  &adj->rewrite_header,
				  sizeof (adj->rewrite_data));

    adj_lock(adj_get_index(adj));

    return (adj_get_index(adj));
}
