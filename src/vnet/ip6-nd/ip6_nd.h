/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/* ip6_neighboor.h: ip6 neighbor structures */

#ifndef __IP6_ND_H__
#define __IP6_ND_H__

#include <vnet/ip/ip6_packet.h>

typedef enum ip6_nd_proxy_if_flags_t_
{
  IP6_ND_PROXY_IF_FLAG_NONE = 0,
  IP6_ND_PROXY_IF_FLAG_NO_DST_FILTER = (1 << 0),
} ip6_nd_proxy_if_flags_t;

typedef enum ip6_nd_punt_reason_type_t_
{
  IP6_ND_PUNT_NA,
  IP6_ND_PUNT_N_REASONS,
} ip6_nd_punt_reason_type_t;

typedef struct ip6_nd_t_
{
  /* local information */
  u32 sw_if_index;

  /* stats */
  u32 n_solicitations_rcvd;
  u32 n_solicitations_dropped;
} ip6_nd_t;

typedef struct ip6_nd_main_t_
{
  ip6_nd_t *ip6_nd_pool;
  u8 *i6nd_sw_if_indexes;
  vlib_punt_hdl_t i6nd_punt_client;
  vlib_punt_reason_t ip6nd_punt_reason[IP6_ND_PUNT_N_REASONS];
} ip6_nd_main_t;

extern int ip6_nd_proxy_add (u32 sw_if_index, const ip6_address_t * addr);
extern int ip6_nd_proxy_del (u32 sw_if_index, const ip6_address_t * addr);
extern int ip6_nd_proxy_enable_disable (u32 sw_if_index, u8 enable, ip6_nd_proxy_if_flags_t flags);
extern ip6_nd_main_t ip6_nd_main;

#endif /* included_ip6_neighbor_h */
