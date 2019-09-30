/*
 *
 * ip6_neighboor.h: ip6 neighbor structures
 *
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

#ifndef __IP6_RA_H__
#define __IP6_RA_H__

#include <vnet/fib/fib_types.h>

extern int ip6_ra_config (vlib_main_t * vm, u32 sw_if_index,
			  u8 suppress, u8 managed, u8 other,
			  u8 ll_option, u8 send_unicast, u8 cease,
			  u8 use_lifetime, u32 lifetime,
			  u32 initial_count, u32 initial_interval,
			  u32 max_interval, u32 min_interval, u8 is_no);

extern int ip6_ra_prefix (vlib_main_t * vm, u32 sw_if_index,
			  ip6_address_t * prefix_addr, u8 prefix_len,
			  u8 use_default, u32 val_lifetime,
			  u32 pref_lifetime, u8 no_advertise,
			  u8 off_link, u8 no_autoconfig,
			  u8 no_onlink, u8 is_no);

typedef struct
{
  u32 irt;
  u32 mrt;
  u32 mrc;
  u32 mrd;
} icmp6_send_router_solicitation_params_t;

extern void icmp6_send_router_solicitation (vlib_main_t * vm,
					    u32 sw_if_index,
					    u8 stop,
					    const
					    icmp6_send_router_solicitation_params_t
					    * params);

typedef struct
{
  fib_prefix_t prefix;
  u8 flags;
  u32 valid_time;
  u32 preferred_time;
} ra_report_prefix_info_t;

typedef struct
{
  ip6_address_t router_address;
  u32 sw_if_index;
  u8 current_hop_limit;
  u8 flags;
  u16 router_lifetime_in_sec;
  u32 neighbor_reachable_time_in_msec;
  u32 time_in_msec_between_retransmitted_neighbor_solicitations;
  u8 slla[6];
  u32 mtu;
  ra_report_prefix_info_t *prefixes;
} ip6_ra_report_t;


typedef void (*ip6_ra_report_notify_t) (const ip6_ra_report_t * rap);

extern void ip6_ra_report_register (ip6_ra_report_notify_t fn);
extern void ip6_ra_report_unregister (ip6_ra_report_notify_t fn);

#endif /* included_ip6_neighbor_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
