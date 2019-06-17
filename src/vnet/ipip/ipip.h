/*
 * ipip.h: types/functions for ipip.
 *
 * Copyright (c) 2018 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or aipiped to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef included_ipip_h
#define included_ipip_h

#include <vnet/adj/adj_types.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/format.h>
#include <vnet/ip/ip.h>
#include <vnet/vnet.h>

extern vnet_hw_interface_class_t ipip_hw_interface_class;

#define foreach_ipip_error				\
  /* Must be first. */					\
  _(DECAP_PKTS, "packets decapsulated")			\
  _(BAD_PROTOCOL, "bad protocol")			\
  _(NO_TUNNEL, "no tunnel")				\
  _(FRAGMENTED_PACKET, "fragmented outer packet")

typedef enum
{
#define _(sym, str) IPIP_ERROR_##sym,
  foreach_ipip_error
#undef _
    IPIP_N_ERROR,
} ipip_error_t;

/**
 * @brief IPIP Tunnel key
 */
typedef enum
{
  IPIP_TRANSPORT_IP4,
  IPIP_TRANSPORT_IP6,
} ipip_transport_t;

typedef struct
{
  ip46_address_t src;
  ip46_address_t dst;
  ipip_transport_t transport;
  u32 fib_index;
} __attribute__ ((packed)) ipip_tunnel_key_t;

typedef enum
{
  IPIP_MODE_P2P = 0,
  IPIP_MODE_6RD,
} ipip_mode_t;

/**
 * @brief A representation of a IPIP tunnel
 */
typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  ipip_mode_t mode;
  ipip_transport_t transport;
  ipip_tunnel_key_t *key;
  ip46_address_t tunnel_src;
  ip46_address_t tunnel_dst;
  u32 fib_index;
  u32 hw_if_index;
  u32 sw_if_index;
  u32 dev_instance;		/* Real device instance in tunnel vector */
  u32 user_instance;		/* Instance name being shown to user */
  u8 tc_tos;

  struct
  {
    ip6_address_t ip6_prefix;
    ip4_address_t ip4_prefix;
    u8 ip6_prefix_len;
    u8 ip4_prefix_len;
    u8 shift;
    bool security_check;
    u32 ip6_fib_index;
  } sixrd;
} ipip_tunnel_t;

typedef struct
{
  ipip_tunnel_t *tunnels;
  uword *tunnel_by_key;
  u32 *tunnel_index_by_sw_if_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Record used instances */
  uword *instance_used;

  bool ip4_protocol_registered;
  bool ip6_protocol_registered;
} ipip_main_t;

extern ipip_main_t ipip_main;
extern vlib_node_registration_t ipip4_input_node;
extern vlib_node_registration_t ipip6_input_node;

/*
 * sixrd_get_addr_net
 */
static_always_inline u32
sixrd_get_addr_net (const ipip_tunnel_t * t, u64 dal)
{
  /* 1:1 mode */
  if (t->sixrd.ip4_prefix_len == 32)
    return (t->sixrd.ip4_prefix.as_u32);

  dal = clib_net_to_host_u64 (dal);

  /* Grab 32 - ip4_prefix_len bits out of IPv6 address from offset
   * ip6_prefix_len */
  u32 mask = ~(~0ULL << (32 - t->sixrd.ip4_prefix_len));
  u32 ip4 =
    clib_net_to_host_u32 (t->sixrd.
			  ip4_prefix.as_u32) | ((u32) (dal >> t->sixrd.
						       shift) & mask);
  return clib_host_to_net_u32 (ip4);
}

int ipip_add_tunnel (ipip_transport_t transport, u32 instance,
		     ip46_address_t * src, ip46_address_t * dst,
		     u32 fib_index, u8 tc_tos, u32 * sw_if_indexp);
int ipip_del_tunnel (u32 sw_if_index);
int sixrd_add_tunnel (ip6_address_t * ip6_prefix, u8 ip6_prefix_len,
		      ip4_address_t * ip4_prefix, u8 ip4_prefix_len,
		      ip4_address_t * ip4_src, bool security_check,
		      u32 ip4_fib_index, u32 ip6_fib_index,
		      u32 * sw_if_index);
int sixrd_del_tunnel (u32 sw_if_index);
void ipip_tunnel_db_add (ipip_tunnel_t * t, ipip_tunnel_key_t * key);
void ipip_tunnel_db_remove (ipip_tunnel_t * t);
ipip_tunnel_t *ipip_tunnel_db_find (ipip_tunnel_key_t * key);
ipip_tunnel_t *ipip_tunnel_db_find_by_sw_if_index (u32 sw_if_index);

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
