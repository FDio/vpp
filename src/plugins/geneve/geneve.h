/*
 * Copyright (c) 2017 SUSE LLC.
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
#ifndef included_vnet_geneve_h
#define included_vnet_geneve_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>

#include <geneve/geneve_packet.h>

#include <vnet/ip/ip.h>
#include <vnet/ip/vtep.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/udp/udp_local.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>

#define SUPPORT_OPTIONS_HEADER 0

typedef CLIB_PACKED (struct
		     {
		     ip4_header_t ip4;	/* 20 bytes */
		     udp_header_t udp;	/* 8 bytes */
		     geneve_header_t geneve;	/* Min 8 bytes, Max 260 bytes */
		     }) ip4_geneve_header_t;

typedef CLIB_PACKED (struct
		     {
		     ip6_header_t ip6;	/* 40 bytes */
		     udp_header_t udp;	/* 8 bytes */
		     geneve_header_t geneve;	/* Min 8 bytes, Max 260 bytes */
		     }) ip6_geneve_header_t;

typedef CLIB_PACKED (struct
		     {
		     /*
		      * Key fields: ip source and geneve vni on incoming GENEVE packet
		      * all fields in NET byte order
		      */
		     union
		     {
		     struct
		     {
		     u32 remote;
		     u32 vni;	/* shifted left 8 bits */
		     };
		     u64 as_u64;
		     };
		     }) geneve4_tunnel_key_t;

typedef CLIB_PACKED (struct
		     {
		     /*
		      * Key fields: ip source and geneve vni on incoming GENEVE packet
		      * all fields in NET byte order
		      */
		     ip6_address_t remote;
		     u32 vni;	/* shifted left 8 bits */
		     }) geneve6_tunnel_key_t;

typedef struct
{
  u32 tunnel_index;
  u32 vni;
} geneve_encap_trace_t;

typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 *rewrite;

  /* FIB DPO for IP forwarding of GENEVE encap packet */
  dpo_id_t next_dpo;

  /* geneve VNI in HOST byte order */
  u32 vni;

  /* geneve OPTIONS LEN in HOST byte order */
#if SUPPORT_OPTIONS_HEADER==1
  u8 options_len;
#endif

  /* tunnel local and remote addresses */
  ip46_address_t local;
  ip46_address_t remote;

  /* mcast packet output intfc index (used only if remote is mcast) */
  u32 mcast_sw_if_index;

  /* decap next index */
  u32 decap_next_index;

  /* The FIB index for local/remote addresses */
  u32 encap_fib_index;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on GENEVE tunnel is unicast or mcast)
   * sending unicast GENEVE encap packets or receiving mcast GENEVE packets
   */
  fib_node_index_t fib_entry_index;
  adj_index_t mcast_adj_index;

  /**
   * The tunnel is a child of the FIB entry for its desintion. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;

  u8 l3_mode;
} geneve_tunnel_t;

#define foreach_geneve_input_next        \
_(DROP, "error-drop")                   \
_(L2_INPUT, "l2-input")

typedef enum
{
#define _(s,n) GENEVE_INPUT_NEXT_##s,
  foreach_geneve_input_next
#undef _
    GENEVE_INPUT_N_NEXT,
} geneve_input_next_t;

typedef enum
{
#define geneve_error(n,s) GENEVE_ERROR_##n,
#include <geneve/geneve_error.def>
#undef geneve_error
  GENEVE_N_ERROR,
} geneve_input_error_t;

typedef struct
{
  /* vector of encap tunnel instances */
  geneve_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword *geneve4_tunnel_by_key;	/* keyed on ipv4.remote + vni */
  uword *geneve6_tunnel_by_key;	/* keyed on ipv6.remote + vni */

  /* local VTEP IPs ref count used by geneve-bypass node to check if
     received GENEVE packet DIP matches any local VTEP address */
  vtep_table_t vtep_table;

  /* mcast shared info */
  uword *mcast_shared;		/* keyed on mcast ip46 addr */

  /* Mapping from sw_if_index to tunnel index */
  u32 *tunnel_index_by_sw_if_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  u16 msg_id_base;
  /* cache for last 8 geneve tunnel */
#ifdef CLIB_HAVE_VEC512
  vtep4_cache_t vtep4_u512;
#endif

} geneve_main_t;

extern geneve_main_t geneve_main;

extern vlib_node_registration_t geneve4_input_node;
extern vlib_node_registration_t geneve6_input_node;
extern vlib_node_registration_t geneve4_encap_node;
extern vlib_node_registration_t geneve6_encap_node;

u8 *format_geneve_encap_trace (u8 * s, va_list * args);

typedef struct
{
  u8 is_add;

  /* we normally use is_ip4, but since this adds to the
   * structure, this seems less of abreaking change */
  u8 is_ip6;
  ip46_address_t local, remote;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 vni;
  u8 l3_mode;
} vnet_geneve_add_del_tunnel_args_t;

int vnet_geneve_add_del_tunnel
  (vnet_geneve_add_del_tunnel_args_t * a, u32 * sw_if_indexp);

void vnet_int_geneve_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable);
#endif /* included_vnet_geneve_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
