/*
 * ip_neighboor_watch.h: ip neighbor event handling
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#ifndef __IP_NEIGHBOR_WATCH_H__
#define __IP_NEIGHBOR_WATCH_H__

#include <vnet/ip-neighbor/ip_neighbor_types.h>

extern void ip_neighbor_watch (const ip46_address_t * ip,
			       ip46_type_t type,
			       u32 sw_if_index,
			       const ip_neighbor_watcher_t * watch);
extern void ip_neighbor_unwatch (const ip46_address_t * ip,
				 ip46_type_t type,
				 u32 sw_if_index,
				 const ip_neighbor_watcher_t * watch);

extern void ip_neighbor_publish (index_t ipni,
				 ip_neighbor_event_flags_t flags);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
