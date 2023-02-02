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

/* advertised prefix option */
typedef struct
{
  /* basic advertised information */
  ip6_address_t prefix;
  u8 prefix_len;
  int adv_on_link_flag;
  int adv_autonomous_flag;
  u32 adv_valid_lifetime_in_secs;
  u32 adv_pref_lifetime_in_secs;

  /* advertised values are computed from these times if decrementing */
  f64 valid_lifetime_expires;
  f64 pref_lifetime_expires;

  /* local information */
  int enabled;
  int deprecated_prefix_flag;
  int decrement_lifetime_flag;

#define MIN_ADV_VALID_LIFETIME 7203 /* seconds */
#define DEF_ADV_VALID_LIFETIME 2592000
#define DEF_ADV_PREF_LIFETIME  604800

  /* extensions are added here, mobile, DNS etc.. */
} ip6_radv_prefix_t;

typedef struct
{
  u32 irt;
  u32 mrt;
  u32 mrc;
  u32 mrd;
} icmp6_send_router_solicitation_params_t;

typedef struct ip6_ra_t_
{
  /* advertised config information, zero means unspecified  */
  u8 curr_hop_limit;
  int adv_managed_flag;
  int adv_other_flag;
  u16 adv_router_lifetime_in_sec;
  u32 adv_neighbor_reachable_time_in_msec;
  u32 adv_time_in_msec_between_retransmitted_neighbor_solicitations;

  /* mtu option */
  u32 adv_link_mtu;

  /* local information */
  u32 sw_if_index;
  int send_radv;  /* radv on/off on this interface -  set by config */
  int cease_radv; /* we are ceasing  to send  - set byf config */
  int send_unicast;
  int adv_link_layer_address;
  int prefix_option;
  int failed_device_check;
  int ref_count;

  /* prefix option */
  ip6_radv_prefix_t *adv_prefixes_pool;

  /* Hash table mapping address to index in interface advertised  prefix pool.
   */
  mhash_t address_to_prefix_index;

  f64 max_radv_interval;
  f64 min_radv_interval;
  f64 min_delay_between_radv;
  f64 max_delay_between_radv;
  f64 max_rtr_default_lifetime;

  f64 last_radv_time;
  f64 last_multicast_time;
  f64 next_multicast_time;

  u32 initial_adverts_count;
  f64 initial_adverts_interval;
  u32 initial_adverts_sent;

  /* stats */
  u32 n_advertisements_sent;
  u32 n_solicitations_rcvd;
  u32 n_solicitations_dropped;

  /* router solicitations sending state */
  u8 keep_sending_rs; /* when true then next fields are valid */
  icmp6_send_router_solicitation_params_t params;
  f64 sleep_interval;
  f64 due_time;
  u32 n_left;
  f64 start_time;
  vlib_buffer_t *buffer;

  u32 seed;

} ip6_ra_t;

extern ip6_ra_t *ip6_ra_get_itf (u32 sw_if_index);

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

typedef walk_rc_t (*ip6_ra_itf_walk_fn_t) (u32 sw_if_index, void *ctx);

extern void ip6_ra_itf_walk (ip6_ra_itf_walk_fn_t fn, void *ctx);

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
extern void ip6_ra_update_secondary_radv_info (ip6_address_t * address,
					       u8 prefix_len,
					       u32 primary_sw_if_index,
					       u32 valid_time,
					       u32 preferred_time);
extern u8 ip6_ra_adv_enabled (u32 sw_if_index);
#endif /* included_ip6_neighbor_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
