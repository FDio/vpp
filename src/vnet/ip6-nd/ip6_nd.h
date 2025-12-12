/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/* ip6_neighboor.h: ip6 neighbor structures */

#ifndef __IP6_ND_H__
#define __IP6_ND_H__

#include <vnet/ip/ip6_packet.h>

extern int ip6_nd_proxy_add (u32 sw_if_index, const ip6_address_t * addr);
extern int ip6_nd_proxy_del (u32 sw_if_index, const ip6_address_t * addr);
extern int ip6_nd_proxy_enable_disable (u32 sw_if_index, u8 enable);

#endif /* included_ip6_neighbor_h */
