/*
 * l2tp.h : L2TPv3 tunnel support
 *
 * Copyright (c) 2013 Cisco and/or its affiliates.
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

#ifndef __included_l2tp_h__
#define __included_l2tp_h__

#include <vlib/vlib.h>
#include <vnet/ip/ip.h>
#include <vnet/l2tp/packet.h>

typedef struct
{
  /* ip6 addresses */
  ip6_address_t our_address;
  ip6_address_t client_address;

  /* l2tpv3 header parameters */
  u64 local_cookie[2];
  u64 remote_cookie;
  u32 local_session_id;
  u32 remote_session_id;

  /* tunnel interface */
  u32 hw_if_index;
  u32 sw_if_index;

  /* fib index used for outgoing encapsulated packets */
  u32 encap_fib_index;

  u8 l2tp_hdr_size;
  u8 l2_sublayer_present;
  u8 cookie_flags;		/* in host byte order */

  u8 admin_up;
} l2t_session_t;

typedef enum
{
  L2T_LOOKUP_SRC_ADDRESS = 0,
  L2T_LOOKUP_DST_ADDRESS,
  L2T_LOOKUP_SESSION_ID,
} ip6_to_l2_lookup_t;

typedef struct
{
  /* session pool */
  l2t_session_t *sessions;

  /* ip6 -> l2 hash tables. Make up your minds, people... */
  uword *session_by_src_address;
  uword *session_by_dst_address;
  uword *session_by_session_id;

  ip6_to_l2_lookup_t lookup_type;

  /* Counters */
  vlib_combined_counter_main_t counter_main;

  /* vector of free l2tpv3 tunnel interfaces */
  u32 *free_l2tpv3_tunnel_hw_if_indices;

  /* show device instance by real device instance */
  u32 *dev_inst_by_real;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

} l2t_main_t;

/* Packet trace structure */
typedef struct
{
  int is_user_to_network;
  u32 session_index;
  ip6_address_t our_address;
  ip6_address_t client_address;
} l2t_trace_t;

extern l2t_main_t l2t_main;
extern vlib_node_registration_t l2t_encap_node;
extern vlib_node_registration_t l2t_decap_node;
extern vlib_node_registration_t l2t_decap_local_node;

enum
{
  SESSION_COUNTER_USER_TO_NETWORK = 0,
  SESSION_COUNTER_NETWORK_TO_USER,
};

static inline u32
session_index_to_counter_index (u32 session_index, u32 counter_id)
{
  return ((session_index << 1) + counter_id);
}

u8 *format_l2t_trace (u8 * s, va_list * args);

typedef struct
{
  /* Any per-interface config would go here */
} ip6_l2tpv3_config_t;

uword unformat_pg_l2tp_header (unformat_input_t * input, va_list * args);

void l2tp_encap_init (vlib_main_t * vm);
void l2tp_decap_init (void);
int create_l2tpv3_ipv6_tunnel (l2t_main_t * lm,
			       ip6_address_t * client_address,
			       ip6_address_t * our_address,
			       u32 local_session_id,
			       u32 remote_session_id,
			       u64 local_cookie,
			       u64 remote_cookie,
			       int l2_sublayer_present,
			       u32 encap_fib_index, u32 * sw_if_index);

int l2tpv3_set_tunnel_cookies (l2t_main_t * lm,
			       u32 sw_if_index,
			       u64 new_local_cookie, u64 new_remote_cookie);

int l2tpv3_interface_enable_disable (vnet_main_t * vnm,
				     u32 sw_if_index, int enable_disable);

#endif /* __included_l2tp_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
