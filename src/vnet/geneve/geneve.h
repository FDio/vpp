/*
 *------------------------------------------------------------------
 * Copyright (c) 2016 Intel and/or its affiliates.
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
 *------------------------------------------------------------------
 */

#ifndef included_vnet_geneve_h
#define included_vnet_geneve_h

#include <vppinfra/lock.h>
#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_output.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/udp/udp.h>
#include <vnet/dpo/dpo.h>
#include <vnet/adj/adj_types.h>


typedef struct
{
  u8 ver_len;
  u8 flags;
  u16 protocol;
  u32 vni_rsv;
} geneve_header_t;

static inline u32
vnet_get_vni (geneve_header_t * h)
{
  u32 vni_reserved_host_byte_order;

  vni_reserved_host_byte_order = clib_net_to_host_u32 (h->vni_rsv);
  return vni_reserved_host_byte_order >> 8;
}

static inline void
vnet_set_vni_and_flags (geneve_header_t * h, u32 vni)
{
  h->vni_rsv = clib_host_to_net_u32 (vni << 8);
}

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct {
  u16 class;
  u8 type;
  u8 length;
}) geneve_opt_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip4_header_t ip4;            /* 20 bytes */
  udp_header_t udp;            /* 8 bytes */
  geneve_header_t geneve;	       /* 8 bytes */
}) ip4_geneve_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED(struct
{
  ip6_header_t ip6;            /* 40 bytes */
  udp_header_t udp;            /* 8 bytes */
  geneve_header_t geneve;     /* 8 bytes */
}) ip6_geneve_header_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and geneve vni on incoming geneve packet
   * all fields in NET byte order
   */
  union {
    struct {
      u32 src;
      u32 vni;
    };
    u64 as_u64;
  };
}) geneve4_tunnel_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip src and geneve vni on incoming geneve packet
   * all fields in NET byte order
   */
  ip6_address_t src;
  u32 vni;
}) geneve6_tunnel_key_t;
/* *INDENT-ON* */

typedef struct
{
  /* Rewrite string */
  u8 *rewrite;

  /* FIB DPO for IP forwarding of geneve encap packet */
  dpo_id_t next_dpo;

  /* geneve vni in HOST byte order */
  u32 vni;

  /* protocol type */
  u8 protocol;

  /* variable metadata */
  u8 opt_len;
  u8 *opt_data;

  /* tunnel src and dst addresses */
  ip46_address_t src;
  ip46_address_t dst;

  /* mcast packet output intf index (used only if dst is mcast) */
  u32 mcast_sw_if_index;

  /* decap next index */
  u32 decap_next_index;

  /* The FIB index for src/dst addresses */
  u32 encap_fib_index;

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on geneve tunnel is unicast or mcast)
   * sending unicast geneve encap packets or receiving mcast geneve packets
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
} geneve_tunnel_t;

#define foreach_geneve_input_next        \
_(DROP, "error-drop")                  \
_(L2_INPUT, "l2-input")

typedef enum
{
#define _(s,n) geneve_INPUT_NEXT_##s,
  foreach_geneve_input_next
#undef _
    geneve_INPUT_N_NEXT,
} geneve_input_next_t;

typedef struct
{
  /* vector of encap tunnel instances */
  geneve_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword *geneve4_tunnel_by_key;	/* keyed on ipv4.dst + vni */
  uword *geneve6_tunnel_by_key;	/* keyed on ipv6.dst + vni */

  /* local VTEP IPs ref count used by geneve-bypass node to check if
     received geneve packet DIP matches any local VTEP address */
  uword *vtep4;			/* local ip4 VTEPs keyed on their ip4 addr */
  uword *vtep6;			/* local ip6 VTEPs keyed on their ip6 addr */

  /* mcast shared info */
  uword *mcast_shared;		/* keyed on mcast ip46 addr */

  /* Free vlib hw_if_indices */
  u32 *free_geneve_tunnel_hw_if_indices;

  /* Mapping from sw_if_index to tunnel index */
  u32 *tunnel_index_by_sw_if_index;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} geneve_main_t;

geneve_main_t geneve_main;

extern vlib_node_registration_t geneve4_input_node;
extern vlib_node_registration_t geneve6_input_node;
extern vlib_node_registration_t geneve4_encap_node;
extern vlib_node_registration_t geneve6_encap_node;

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  ip46_address_t src, dst;
  u32 mcast_sw_if_index;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 vni;
  u8 protocol;
  /* variable metadata */
  u8 opt_len;
  u8 *opt_data;
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
