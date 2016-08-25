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
 * A grouping of the remaining sub-types. One sub-types per-file seems
 * to be overkill
 */

#ifndef __ADJ_SUBTYPES_H__
#define __ADJ_SUBTYPES_H__

#include <vnet/adj/adj_types.h>


extern adj_index_t adj_rewrite_add_and_lock(fib_protocol_t nh_proto,
					    fib_link_t link_type,
					    u32 sw_if_index,
					    u8 *rewrite);

extern adj_index_t adj_map_add_or_lock(fib_protocol_t proto,
				       u32 next_index,
				       u32 map_index);
extern void adj_map_update(adj_index_t adj_index,
			   u32 map_index);
extern adj_index_t adj_sr_add_or_lock(fib_protocol_t proto,
				      u32 next_index,
				      u32 sr_index);

#endif
