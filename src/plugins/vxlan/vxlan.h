/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2015 Cisco and/or its affiliates.
 */

#ifndef included_vnet_vxlan_h
#define included_vnet_vxlan_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vppinfra/bihash_16_8.h>
#include <vppinfra/bihash_24_8.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/vtep.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vxlan/vxlan_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp_packet.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;	/* 20 bytes */
  udp_header_t udp;	/* 8 bytes */
  vxlan_header_t vxlan;	/* 8 bytes */
}) ip4_vxlan_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;	/* 40 bytes */
  udp_header_t udp;	/* 8 bytes */
  vxlan_header_t vxlan;	/* 8 bytes */
}) ip6_vxlan_header_t;

/*
* Key fields: remote ip, vni on incoming VXLAN packet
* all fields in NET byte order
*/
typedef clib_bihash_kv_16_8_t vxlan4_tunnel_key_t;

/*
* Key fields: remote ip, vni and fib index on incoming VXLAN packet
* ip, vni fields in NET byte order
* fib index field in host byte order
*/
typedef clib_bihash_kv_24_8_t vxlan6_tunnel_key_t;

typedef union
{
  struct
  {
    u32 sw_if_index;		/* unicast - input interface / mcast - stats interface */
    union
    {
      struct			/* unicast action */
      {
	u16 next_index;
	u8 error;
      };
      ip4_address_t local_ip;	/* used as dst ip for mcast pkts to assign them to unicast tunnel */
    };
  };
  u64 as_u64;
} vxlan_decap_info_t;

/*
 * Per-endpoint state. P2P tunnels have exactly one; P2MP tunnels have a
 * vector of these (one per remote VTEP), stored in vxlan_tunnel_t.endpoints.
 */
typedef struct
{
  /* remote VTEP address (tunnel dst) */
  ip46_address_t dst;

  /* FIB DPO for IP forwarding of encap packets toward this endpoint */
  dpo_id_t next_dpo;

  /**
   * Linkage into the FIB object graph.
   * For unicast endpoints this is tracked as a child of the FIB entry
   * for dst so we get back-walked when the route changes.
   */
  fib_node_t node;

  /* FIB entry index and sibling for dst /32 route tracking */
  fib_node_index_t fib_entry_index;
  u32 sibling_index;

  /* back-pointers to recover vxlan_tunnel_t from fib_node_t */
  u32 tunnel_index; /* index into vxlan_main.tunnels pool */
  u32 ep_index;	    /* pool index into vxlan_main.endpoint_pool (self-index) */

  /* pre-built outer header template: ip4+udp+vxlan or ip6+udp+vxlan */
  VNET_DECLARE_REWRITE;
} vxlan_endpoint_t;

typedef struct
{
  /* Required for pool_get_aligned */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /*
   * Indices into vxlan_main.endpoint_pool, one per remote VTEP.
   * P2P tunnels have exactly one element; P2MP tunnels have one per VTEP.
   * Pool indices are used (rather than direct pointers) so that pool
   * reallocation never invalidates fib_node_t pointers within each endpoint.
   */
  u32 *endpoint_indices;

  /* vxlan VNI in HOST byte order */
  u32 vni;

  /* local VTEP source address */
  ip46_address_t src;

  /* udp-ports */
  u16 src_port;
  u16 dst_port;

  /* mcast packet output intfc index (used only if dst is mcast) */
  u32 mcast_sw_if_index;

  /* decap next index */
  u16 decap_next_index;

  /* The FIB index for src/dst addresses */
  u32 encap_fib_index;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /* kept for ABI compatibility */
  adj_index_t mcast_adj_index;

  u32 flow_index;		/* infra flow index */
  u32 dev_instance;		/* Real device instance in tunnel vector */
  u32 user_instance;		/* Instance name being shown to user */

  /* true for P2MP tunnels (no fixed dst endpoint) */
  u8 is_p2mp;
} vxlan_tunnel_t;

#define foreach_vxlan_input_next        \
_(DROP, "error-drop")                   \
_(L2_INPUT, "l2-input")

typedef enum
{
#define _(s,n) VXLAN_INPUT_NEXT_##s,
  foreach_vxlan_input_next
#undef _
    VXLAN_INPUT_N_NEXT,
} vxlan_input_next_t;

typedef enum
{
#define vxlan_error(n,s) VXLAN_ERROR_##n,
#include <vxlan/vxlan_error.def>
#undef vxlan_error
  VXLAN_N_ERROR,
} vxlan_input_error_t;

typedef struct
{
  /* vector of encap tunnel instances */
  vxlan_tunnel_t *tunnels;

  /* lookup tunnel by key */
  clib_bihash_16_8_t
    vxlan4_tunnel_by_key; /* keyed on ipv4.dst + src_port + fib + vni */
  clib_bihash_24_8_t
    vxlan6_tunnel_by_key; /* keyed on ipv6.dst + src_port + fib + vni */

  /* local VTEP IPs ref count used by vxlan-bypass node to check if
     received VXLAN packet DIP matches any local VTEP address */
  vtep_table_t vtep_table;

  /* mcast shared info */
  uword *mcast_shared;		/* keyed on mcast ip46 addr */

  /* Mapping from sw_if_index to tunnel index */
  u32 *tunnel_index_by_sw_if_index;

  /* Global pool of per-endpoint state. Using a pool ensures elements never
   * move after allocation, which is required because each embeds a fib_node_t
   * that may be linked into the FIB dependency graph. */
  vxlan_endpoint_t *endpoint_pool;

  /* graph node state */
  uword *bm_ip4_bypass_enabled_by_sw_if;
  uword *bm_ip6_bypass_enabled_by_sw_if;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

  /* Record used instances */
  uword *instance_used;
  u32 flow_id_start;

  /* cache for last 8 vxlan tunnel */
  vtep4_cache_t vtep4_u512;

} vxlan_main_t;

extern vxlan_main_t vxlan_main;

extern vlib_node_registration_t vxlan4_input_node;
extern vlib_node_registration_t vxlan6_input_node;
extern vlib_node_registration_t vxlan4_encap_node;
extern vlib_node_registration_t vxlan6_encap_node;
extern vlib_node_registration_t vxlan4_p2mp_encap_node;
extern vlib_node_registration_t vxlan6_p2mp_encap_node;
extern vlib_node_registration_t vxlan4_flow_input_node;

u8 *format_vxlan_encap_trace (u8 * s, va_list * args);

typedef struct
{
  u8 is_add;

  /* we normally use is_ip4, but since this adds to the
   * structure, this seems less of a breaking change */
  u8 is_ip6;
  u8 is_l3;
  /* if set, create a P2MP tunnel with no initial endpoint */
  u8 is_p2mp;
  u32 instance;
  ip46_address_t src, dst;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 vni;
  u16 src_port;
  u16 dst_port;
} vnet_vxlan_add_del_tunnel_args_t;

int vnet_vxlan_add_del_tunnel
  (vnet_vxlan_add_del_tunnel_args_t * a, u32 * sw_if_indexp);

int vnet_vxlan_add_del_endpoint (u32 tunnel_sw_if_index, ip46_address_t *dst, bool is_add);

void vnet_int_vxlan_bypass_mode (u32 sw_if_index, u8 is_ip6, u8 is_enable);

int vnet_vxlan_add_del_rx_flow (u32 hw_if_index, u32 t_imdex, int is_add);

u32 vnet_vxlan_get_tunnel_index (u32 sw_if_index);
#endif /* included_vnet_vxlan_h */
