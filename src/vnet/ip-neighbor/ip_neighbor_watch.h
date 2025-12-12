/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

/* ip_neighboor_watch.h: ip neighbor event handling */

#ifndef __IP_NEIGHBOR_WATCH_H__
#define __IP_NEIGHBOR_WATCH_H__

#include <vnet/ip-neighbor/ip_neighbor_types.h>

extern void ip_neighbor_watch (const ip_address_t * ip,
			       u32 sw_if_index,
			       const ip_neighbor_watcher_t * watch);
extern void ip_neighbor_unwatch (const ip_address_t * ip,
				 u32 sw_if_index,
				 const ip_neighbor_watcher_t * watch);

extern void ip_neighbor_publish (index_t ipni,
				 ip_neighbor_event_flags_t flags);

#endif
