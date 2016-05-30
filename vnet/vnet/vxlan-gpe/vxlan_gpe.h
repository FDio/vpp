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
#ifndef included_vnet_vxlan_gpe_h
#define included_vnet_vxlan_gpe_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/vxlan-gpe/vxlan_gpe_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/udp.h>


typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  udp_header_t udp;             /* 8 bytes */
  vxlan_gpe_header_t vxlan;     /* 8 bytes */
}) ip4_vxlan_gpe_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;             /* 40 bytes */
  udp_header_t udp;             /* 8 bytes */
  vxlan_gpe_header_t vxlan;     /* 8 bytes */
}) ip6_vxlan_gpe_header_t;

typedef CLIB_PACKED(struct {
  /* 
   * Key fields: local remote, vni 
   * all fields in NET byte order
   */
  union {
    struct {
      u32 local;
      u32 remote;
      u32 vni;                      /* shifted 8 bits */
      u32 pad;
    };
    u64 as_u64[2];
  };
}) vxlan4_gpe_tunnel_key_t;

typedef CLIB_PACKED(struct {
  /*
   * Key fields: local remote, vni
   * all fields in NET byte order
   */
  ip6_address_t local;
  ip6_address_t remote;
  u32 vni;                      /* shifted 8 bits */
}) vxlan6_gpe_tunnel_key_t;

typedef struct {
  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 * rewrite;

  /* encapsulated protocol */
  u8 protocol;

  /* tunnel src and dst addresses */
  ip46_address_t local;
  ip46_address_t remote;

  /* FIB indices */
  u32 encap_fib_index;          /* tunnel partner lookup here */
  u32 decap_fib_index;          /* inner IP lookup here */

  /* vxlan VNI in HOST byte order, shifted left 8 bits */
  u32 vni;

  /*decap next index*/
  u32 decap_next_index;

  /* vnet intfc hw/sw_if_index */
  u32 hw_if_index;
  u32 sw_if_index;

  union { /* storage for the hash key */
	vxlan4_gpe_tunnel_key_t key4;
	vxlan6_gpe_tunnel_key_t key6;
  };

  /* flags */
  u32 flags;
} vxlan_gpe_tunnel_t;

/* Flags for vxlan_gpe_tunnel_t.flags */
#define VXLAN_GPE_TUNNEL_IS_IPV4	1

#define foreach_vxlan_gpe_input_next        \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(ETHERNET_INPUT, "ethernet-input")             

typedef enum {
#define _(s,n) VXLAN_GPE_INPUT_NEXT_##s,
  foreach_vxlan_gpe_input_next
#undef _
  VXLAN_GPE_INPUT_N_NEXT,
} vxlan_gpe_input_next_t;

typedef enum {
#define vxlan_gpe_error(n,s) VXLAN_GPE_ERROR_##n,
#include <vnet/vxlan-gpe/vxlan_gpe_error.def>
#undef vxlan_gpe_error
  VXLAN_GPE_N_ERROR,
} vxlan_gpe_input_error_t;

typedef struct {
  /* vector of encap tunnel instances */
  vxlan_gpe_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword * vxlan4_gpe_tunnel_by_key;
  uword * vxlan6_gpe_tunnel_by_key;

  /* Free vlib hw_if_indices */
  u32 * free_vxlan_gpe_tunnel_hw_if_indices;

  /* Mapping from sw_if_index to tunnel index */
  u32 * tunnel_index_by_sw_if_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} vxlan_gpe_main_t;

vxlan_gpe_main_t vxlan_gpe_main;

extern vlib_node_registration_t vxlan_gpe_encap_node;
extern vlib_node_registration_t vxlan4_gpe_input_node;
extern vlib_node_registration_t vxlan6_gpe_input_node;

u8 * format_vxlan_gpe_encap_trace (u8 * s, va_list * args);

typedef struct {
  u8 is_add;
  u8 is_ip6;
  ip46_address_t local, remote;
  u8 protocol;
  u32 encap_fib_index;
  u32 decap_fib_index;
  u32 decap_next_index;
  u32 vni;
} vnet_vxlan_gpe_add_del_tunnel_args_t;


int vnet_vxlan_gpe_add_del_tunnel 
(vnet_vxlan_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp);





#endif /* included_vnet_vxlan_gpe_h */
