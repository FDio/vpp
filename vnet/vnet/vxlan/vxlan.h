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
#ifndef included_vnet_vxlan_h
#define included_vnet_vxlan_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/l2/l2_bd.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan/vxlan_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/udp.h>

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;            /* 20 bytes */
  udp_header_t udp;            /* 8 bytes */
  vxlan_header_t vxlan;        /* 8 bytes */
}) ip4_vxlan_header_t;

typedef CLIB_PACKED(struct {
  /* 
   * Key fields: ip src and vxlan vni on incoming VXLAN packet
   * all fields in NET byte order
   */
  union {
    struct {
      u32 src;
      u32 vni;                 /* shifted left 8 bits */
    };
    u64 as_u64;
  };
}) vxlan_tunnel_key_t;

typedef struct {
  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 * rewrite;

  /* decap next index */
  u32 decap_next_index;

  /* tunnel src and dst addresses */
  ip4_address_t src;
  ip4_address_t dst;

  /* vxlan VNI in HOST byte order */
  u32 vni;

  /* L3 FIB index and L2 BD ID */
  u16 encap_fib_index;          /* tunnel partner IP lookup here */

  /* vnet intfc hw/sw_if_index */
  u16 hw_if_index;
  u32 sw_if_index;
} vxlan_tunnel_t;

#define foreach_vxlan_input_next        \
_(DROP, "error-drop")                   \
_(L2_INPUT, "l2-input")                 \
_(IP4_INPUT, "ip4-input")               \
_(IP6_INPUT, "ip6-input")

typedef enum {
#define _(s,n) VXLAN_INPUT_NEXT_##s,
  foreach_vxlan_input_next
#undef _
  VXLAN_INPUT_N_NEXT,
} vxlan_input_next_t;

typedef enum {
#define vxlan_error(n,s) VXLAN_ERROR_##n,
#include <vnet/vxlan/vxlan_error.def>
#undef vxlan_error
  VXLAN_N_ERROR,
} vxlan_input_error_t;

typedef struct {
  /* vector of encap tunnel instances */
  vxlan_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword * vxlan_tunnel_by_key;

  /* Free vlib hw_if_indices */
  u32 * free_vxlan_tunnel_hw_if_indices;

  /* Dummy rewrite for deleted vxlan_tunnels with hw_if_indices as above */
  u64 dummy_str [sizeof(ip4_vxlan_header_t)/sizeof(u64) + 2];
#define vxlan_dummy_rewrite ((u8 *) &vxlan_main.dummy_str[1])

  /* Mapping from sw_if_index to tunnel index */
  u32 * tunnel_index_by_sw_if_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} vxlan_main_t;

vxlan_main_t vxlan_main;

vlib_node_registration_t vxlan_input_node;
vlib_node_registration_t vxlan_encap_node;

u8 * format_vxlan_encap_trace (u8 * s, va_list * args);

typedef struct {
  u8 is_add;
  ip4_address_t src, dst;
  u32 encap_fib_index;
  u32 decap_next_index;
  u32 vni;
} vnet_vxlan_add_del_tunnel_args_t;

int vnet_vxlan_add_del_tunnel 
(vnet_vxlan_add_del_tunnel_args_t *a, u32 * sw_if_indexp);

#endif /* included_vnet_vxlan_h */
