/*
 * ip_neighbor.h: ip neighbor generic services
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

#ifndef __INCLUDE_IP_NEIGHBOR_TYPES_H__
#define __INCLUDE_IP_NEIGHBOR_TYPES_H__

#include <vnet/ip/ip6_packet.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/fib/fib_types.h>

#define foreach_ip_neighbor_flag                 \
  _(STATIC, 1 << 0, "static", "S")               \
  _(DYNAMIC, 1 << 1, "dynamic", "D")             \
  _(NO_FIB_ENTRY, 1 << 2, "no-fib-entry", "N")   \
  _(PENDING, 1 << 3, "pending", "P")             \
  _(STALE, 1 << 4, "stale", "A")                 \

typedef enum ip_neighbor_flags_t_
{
  IP_NEIGHBOR_FLAG_NONE = 0,
#define _(a,b,c,d) IP_NEIGHBOR_FLAG_##a = b,
  foreach_ip_neighbor_flag
#undef _
} __clib_packed ip_neighbor_flags_t;

typedef struct ip_neighbor_watcher_t_
{
  u32 ipw_pid;
  u32 ipw_client;
  int ipw_api_version;
} ip_neighbor_watcher_t;

extern u8 *format_ip_neighbor_watcher (u8 * s, va_list * args);

typedef struct ip_neighbor_key_t_
{
  ip46_address_t ipnk_ip;
  ip46_type_t ipnk_type;
  u32 ipnk_sw_if_index;
} ip_neighbor_key_t;

/**
 * A representation of an IP neighbour/peer
 */
typedef struct ip_neighbor_t_
{
  /**
   * The idempotent key
   */
  ip_neighbor_key_t *ipn_key;

  /**
   * The learned MAC address of the neighbour
   */
  mac_address_t ipn_mac;

  /**
   * Falgs for this object
   */
  ip_neighbor_flags_t ipn_flags;

  /**
   * Aging related data
   *  - last time the neighbour was probed
   *  - number of probes - 3 and it's dead
   */
  f64 ipn_time_last_updated;
  u8 ipn_n_probes;
  index_t ipn_elt;

  /**
   * The index of the adj fib created for this neighbour
   */
  fib_node_index_t ipn_fib_entry_index;
} ip_neighbor_t;

extern u8 *format_ip_neighbor_flags (u8 * s, va_list * args);
extern u8 *format_ip_neighbor_key (u8 * s, va_list * args);
extern u8 *format_ip_neighbor (u8 * s, va_list * args);

extern ip_neighbor_t *ip_neighbor_get (index_t ipni);

typedef struct ip_neighbor_learn_t_
{
  ip46_address_t ip;
  ip46_type_t type;
  mac_address_t mac;
  u32 sw_if_index;
} ip_neighbor_learn_t;


typedef enum ip_neighbor_event_flags_t_
{
  IP_NEIGHBOR_EVENT_ADDED = (1 << 0),
  IP_NEIGHBOR_EVENT_REMOVED = (1 << 1),
} ip_neighbor_event_flags_t;

typedef struct ip_neighbor_event_t_
{
  ip_neighbor_watcher_t ipne_watch;
  ip_neighbor_event_flags_t ipne_flags;
  ip_neighbor_t ipne_nbr;
} ip_neighbor_event_t;

extern void ip_neighbor_clone (const ip_neighbor_t * ipn,
			       ip_neighbor_t * clone);

extern void ip_neighbor_free (ip_neighbor_t * ipn);



#endif /* __INCLUDE_IP_NEIGHBOR_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
