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

#ifndef __ADJ_GLEAN_H__
#define __ADJ_GLEAN_H__

#include <vnet/adj/adj_types.h>

extern adj_index_t adj_glean_add_or_lock(fib_protocol_t proto,
					 u32 sw_if_index,
					 const ip46_address_t *nh_addr);

extern void adj_glean_remove (fib_protocol_t proto,
			      u32 sw_if_index);

void adj_glean_module_init(void);

#endif
