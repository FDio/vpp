/*
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
#ifndef included_vnet_vxlan_gbp_h
#define included_vnet_vxlan_gbp_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_24_8.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan-gbp/vxlan_gbp_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;	/* 20 bytes */
  udp_header_t udp;	/* 8 bytes */
  vxlan_gbp_header_t vxlan_gbp;	/* 8 bytes */
}) ip4_vxlan_gbp_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;	/* 40 bytes */
  udp_header_t udp;	/* 8 bytes */
  vxlan_gbp_header_t vxlan_gbp;	/* 8 bytes */
}) ip6_vxlan_gbp_header_t;
/* *INDENT-ON* */

/*
* Key fields: remote ip, vni on incoming VXLAN packet
* all fields in NET byte order
*/
typedef clib_bihash_kv_16_8_t vxlan4_gbp_tunnel_key_t;

/*
* Key fields: remote ip, vni and fib index on incoming VXLAN packet
* ip, vni fields in NET byte order
* fib index field in host byte order
*/
typedef clib_bihash_kv_24_8_t vxlan6_gbp_tunnel_key_t;

typedef enum vxlan_gbp_tunnel_mode_t_
{
  VXLAN_GBP_TUNNEL_MODE_L2,
  VXLAN_GBP_TUNNEL_MODE_L3,
} vxlan_gbp_tunnel_mode_t;

extern u8 *format_vxlan_gbp_tunnel_mode (u8 * s, va_list * args);

typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* FIB DPO for IP forwarding of VXLAN encap packet */
  dpo_id_t next_dpo;

  /* flags */
  u16 flags;

  /* vxlan VNI in HOST byte order */
  u32 vni;

  /* tunnel src and dst addresses */
  ip46_address_t src;
  ip46_address_t dst;

  /* mcast packet output intfc index (used only if dst is mcast) */
  u32 mcast_sw_if_index;

  /* The FIB index for src/dst addresses */
  u32 encap_fib_index;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /** Next node after VxLAN-GBP encap */
  uword encap_next_node;

  /**
   * Tunnel mode.
   * L2 tunnels decap to L2 path, L3 tunnels to the L3 path
   */
  vxlan_gbp_tunnel_mode_t mode;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on VXLAN-GBP tunnel is unicast or mcast)
   * sending unicast VXLAN-GBP encap packets or receiving mcast VXLAN-GBP packets
   */
  fib_node_index_t fib_entry_index;
  adj_index_t mcast_adj_index;

  /**
   * The tunnel is a child of the FIB entry for its destination. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;

  u32 dev_instance;		/* Real device instance in tunnel vector */
  u32 user_instance;		/* Instance name being shown to user */

    vnet_declare_rewrite (VLIB_BUFFER_PRE_DATA_SIZE);
} vxlan_gbp_tunnel_t;

#define foreach_vxlan_gbp_input_next         \
  _(DROP, "error-drop")                      \
  _(NO_TUNNEL, "error-punt")                 \
  _(L2_INPUT, "l2-input")                    \
  _(IP4_INPUT, "ip4-input")                  \
  _(IP6_INPUT, "ip6-input")

typedef enum
{
#define _(s,n) VXLAN_GBP_INPUT_NEXT_##s,
  foreach_vxlan_gbp_input_next
#undef _
    VXLAN_GBP_INPUT_N_NEXT,
} vxlan_gbp_input_next_t;

typedef enum
{
#define vxlan_gbp_error(n,s) VXLAN_GBP_ERROR_##n,
#include <vnet/vxlan-gbp/vxlan_gbp_error.def>
#undef vxlan_gbp_error
  VXLAN_GBP_N_ERROR,
} vxlan_gbp_input_error_t;

/**
 * Call back function packets that do not match a configured tunnel
 */
typedef vxlan_gbp_input_next_t (*vxlan_bgp_no_tunnel_t) (vlib_buffer_t * b,
							 u32 thread_index,
							 u8 is_ip6);

typedef struct
{
  /* vector of encap tunnel instances */
  vxlan_gbp_tunnel_t *tunnels;

  /* lookup tunnel by key */
  clib_bihash_16_8_t vxlan4_gbp_tunnel_by_key;	/* keyed on ipv4.dst + fib + vni */
  clib_bihash_24_8_t vxlan6_gbp_tunnel_by_key;	/* keyed on ipv6.dst + fib + vni */

  /* local VTEP IPs ref count used by vxlan-bypass node to check if
     received VXLAN packet DIP matches any local VTEP address */
  uword *vtep4;			/* local ip4 VTEPs keyed on their ip4 addr */
  uword *vtep6;			/* local ip6 VTEPs keyed on their ip6 addr */

  /* mcast shared info */
  uword *mcast_shared;		/* keyed on mcast ip46 addr */

  /* Mapping from sw_if_index to tunnel index */
  u32 *tunnel_index_by_sw_if_index;

  /* On demand udp port registration */
  u32 udp_ports_registered;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Record used instances */
  uword *instance_used;
} vxlan_gbp_main_t;

extern vxlan_gbp_main_t vxlan_gbp_main;

extern vlib_node_registration_t vxlan4_gbp_input_node;
extern vlib_node_registration_t vxlan6_gbp_input_node;
extern vlib_node_registration_t vxlan4_gbp_encap_node;
extern vlib_node_registration_t vxlan6_gbp_encap_node;
extern void vxlan_gbp_register_udp_ports (void);
extern void vxlan_gbp_unregister_udp_ports (void);

u8 *format_vxlan_gbp_encap_trace (u8 * s, va_list * args);

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  u32 instance;
  vxlan_gbp_tunnel_mode_t mode;
  ip46_address_t src, dst;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 vni;
} vnet_vxlan_gbp_tunnel_add_del_args_t;

int vnet_vxlan_gbp_tunnel_add_del
  (vnet_vxlan_gbp_tunnel_add_del_args_t * a, u32 * sw_if_indexp);
int vnet_vxlan_gbp_tunnel_del (u32 sw_if_indexp);

void vnet_int_vxlan_gbp_bypass_mode (u32 sw_if_index, u8 is_ip6,
				     u8 is_enable);

u32 vnet_vxlan_gbp_get_tunnel_index (u32 sw_if_index);

#endif /* included_vnet_vxlan_gbp_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
