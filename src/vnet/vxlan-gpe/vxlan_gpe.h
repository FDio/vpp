/*
 * Copyright (c) 2015 Cisco and/or its affiliates.
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
/**
 *  @file
 *  @brief VXLAN GPE definitions
 *
*/
#ifndef included_vnet_vxlan_gpe_h
#define included_vnet_vxlan_gpe_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/vtep.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan-gpe/vxlan_gpe_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>

/**
 * @brief VXLAN GPE header struct
 *
 */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  /** 20 bytes */
  ip4_header_t ip4;
  /** 8 bytes */
  udp_header_t udp;
  /** 8 bytes */
  vxlan_gpe_header_t vxlan;
}) ip4_vxlan_gpe_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  /** 40 bytes */
  ip6_header_t ip6;
  /** 8 bytes */
  udp_header_t udp;
  /** 8 bytes */
  vxlan_gpe_header_t vxlan;
}) ip6_vxlan_gpe_header_t;
/* *INDENT-ON* */

/**
 * @brief Key struct for IPv4 VXLAN GPE tunnel.
 * Key fields: local remote, vni, udp-port
 * all fields in NET byte order
 * VNI shifted 8 bits
 */
/* *INDENT-OFF* */
typedef CLIB_PACKED(struct {
  union {
    struct {
      u32 local;
      u32 remote;

      u32 vni;
      u32 port;
    };
    u64 as_u64[2];
  };
}) vxlan4_gpe_tunnel_key_t;
/* *INDENT-ON* */

/**
 * @brief Key struct for IPv6 VXLAN GPE tunnel.
 * Key fields: local remote, vni, udp-port
 * all fields in NET byte order
 * VNI shifted 8 bits
 */
/* *INDENT-OFF* */
typedef CLIB_PACKED(struct {
  ip6_address_t local;
  ip6_address_t remote;
  u32 vni;
  u32 port;
}) vxlan6_gpe_tunnel_key_t;
/* *INDENT-ON* */

typedef union
{
  struct
  {
    u32 tunnel_index;
    u16 next_index;
    u8 error;
  };
  u64 as_u64;
} vxlan_gpe_decap_info_t;

/**
 * @brief Struct for VXLAN GPE tunnel
 */
typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /** Rewrite string. $$$$ embed vnet_rewrite header */
  u8 *rewrite;

  /** encapsulated protocol */
  u8 protocol;

  /* FIB DPO for IP forwarding of VXLAN-GPE encap packet */
  dpo_id_t next_dpo;
  /** tunnel local address */
  ip46_address_t local;
  /** tunnel remote address */
  ip46_address_t remote;
  /** local udp-port **/
  u16 local_port;
  /** remote udp-port **/
  u16 remote_port;

  /* mcast packet output intfc index (used only if dst is mcast) */
  u32 mcast_sw_if_index;

  /** FIB indices - tunnel partner lookup here */
  u32 encap_fib_index;
  /** FIB indices - inner IP packet lookup here */
  u32 decap_fib_index;

  /** VXLAN GPE VNI in HOST byte order, shifted left 8 bits */
  u32 vni;

  /** vnet intfc hw_if_index */
  u32 hw_if_index;
  /** vnet intfc sw_if_index */
  u32 sw_if_index;

  /** flags */
  u32 flags;

  /** rewrite size for dynamic plugins like iOAM */
  u8 rewrite_size;

  /** Next node after VxLAN-GPE encap */
  uword encap_next_node;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on VXLAN-GPE tunnel is unicast or mcast)
   * sending unicast VXLAN-GPE encap packets or receiving mcast VXLAN-GPE packets
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

} vxlan_gpe_tunnel_t;

/** Flags for vxlan_gpe_tunnel_t */
#define VXLAN_GPE_TUNNEL_IS_IPV4	1

/** next nodes for VXLAN GPE input */
#define foreach_vxlan_gpe_input_next        \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(L2_INPUT, "l2-input")

/** struct for next nodes for VXLAN GPE input */
typedef enum
{
#define _(s,n) VXLAN_GPE_INPUT_NEXT_##s,
  foreach_vxlan_gpe_input_next
#undef _
    VXLAN_GPE_INPUT_N_NEXT,
} vxlan_gpe_input_next_t;

/** struct for VXLAN GPE errors */
typedef enum
{
#define vxlan_gpe_error(n,s) VXLAN_GPE_ERROR_##n,
#include <vnet/vxlan-gpe/vxlan_gpe_error.def>
#undef vxlan_gpe_error
  VXLAN_GPE_N_ERROR,
} vxlan_gpe_input_error_t;

/** Struct for VXLAN GPE node state */
typedef struct
{
  /** vector of encap tunnel instances */
  vxlan_gpe_tunnel_t *tunnels;

  /** lookup IPv4 VXLAN GPE tunnel by key */
  uword *vxlan4_gpe_tunnel_by_key;
  /** lookup IPv6 VXLAN GPE tunnel by key */
  uword *vxlan6_gpe_tunnel_by_key;

  /* local VTEP IPs ref count used by vxlan-bypass node to check if
     received VXLAN packet DIP matches any local VTEP address */
  vtep_table_t vtep_table;
  /* mcast shared info */
  uword *mcast_shared;		/* keyed on mcast ip46 addr */
  /** Free vlib hw_if_indices */
  u32 *free_vxlan_gpe_tunnel_hw_if_indices;

  /** Mapping from sw_if_index to tunnel index */
  u32 *tunnel_index_by_sw_if_index;

  /** State convenience vlib_main_t */
  vlib_main_t *vlib_main;
  /** State convenience vnet_main_t */
  vnet_main_t *vnet_main;

  /* cache for last 8 vxlan_gpe tunnel */
#ifdef CLIB_HAVE_VEC512
  vtep4_cache_t vtep4_u512;
#endif

  /** List of next nodes for the decap indexed on protocol */
  uword decap_next_node_list[VXLAN_GPE_PROTOCOL_MAX];
} vxlan_gpe_main_t;

extern vxlan_gpe_main_t vxlan_gpe_main;

extern vlib_node_registration_t vxlan_gpe_encap_node;
extern vlib_node_registration_t vxlan4_gpe_input_node;
extern vlib_node_registration_t vxlan6_gpe_input_node;

u8 *format_vxlan_gpe_encap_trace (u8 * s, va_list * args);

/** Struct for VXLAN GPE add/del args */
typedef struct
{
  u8 is_add;
  u8 is_ip6;
  ip46_address_t local, remote;
  u8 protocol;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_fib_index;
  u32 vni;
  u16 local_port;
  u16 remote_port;
} vnet_vxlan_gpe_add_del_tunnel_args_t;


int vnet_vxlan_gpe_add_del_tunnel
  (vnet_vxlan_gpe_add_del_tunnel_args_t * a, u32 * sw_if_indexp);


int vxlan4_gpe_rewrite (vxlan_gpe_tunnel_t * t, u32 extension_size,
			u8 protocol_override, uword encap_next_node);
int vxlan6_gpe_rewrite (vxlan_gpe_tunnel_t * t, u32 extension_size,
			u8 protocol_override, uword encap_next_node);

/**
 * @brief Struct for defining VXLAN GPE next nodes
 */
typedef enum
{
  VXLAN_GPE_ENCAP_NEXT_IP4_LOOKUP,
  VXLAN_GPE_ENCAP_NEXT_IP6_LOOKUP,
  VXLAN_GPE_ENCAP_NEXT_DROP,
  VXLAN_GPE_ENCAP_N_NEXT
} vxlan_gpe_encap_next_t;


void vxlan_gpe_unregister_decap_protocol (u8 protocol_id,
					  uword next_node_index);

void vxlan_gpe_register_decap_protocol (u8 protocol_id,
					uword next_node_index);

void vnet_int_vxlan_gpe_bypass_mode (u32 sw_if_index, u8 is_ip6,
				     u8 is_enable);

#endif /* included_vnet_vxlan_gpe_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
