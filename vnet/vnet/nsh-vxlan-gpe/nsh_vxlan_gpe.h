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
#ifndef included_vnet_nsh_vxlan_gpe_h
#define included_vnet_nsh_vxlan_gpe_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/gre/gre.h>
#include <vnet/nsh-gre/nsh_gre_packet.h>
#include <vnet/nsh-vxlan-gpe/vxlan_gpe_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/udp.h>

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  udp_header_t udp;             /* 8 bytes */
  vxlan_gpe_header_t vxlan;     /* 8 bytes */
  nsh_header_t nsh;   		/* 28 bytes */
}) ip4_vxlan_gpe_and_nsh_header_t;

typedef CLIB_PACKED(struct {
  /* 
   * Key fields: ip src, vxlan vni, nsh spi_si 
   * all fields in NET byte order
   */
  union {
    struct {
      u32 src;
      u32 vni;                      /* shifted 8 bits */
      u32 spi_si;
      u32 pad;
    };
    u64 as_u64[2];
  };
}) nsh_vxlan_gpe_tunnel_key_t;

typedef struct {
  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 * rewrite;

  /* decap next index */
  u32 decap_next_index;

  /* tunnel src and dst addresses */
  ip4_address_t src;
  ip4_address_t dst;

  /* FIB indices */
  u32 encap_fib_index;          /* tunnel partner lookup here */
  u32 decap_fib_index;          /* inner IP lookup here */

  /* vxlan VNI in HOST byte order, shifted left 8 bits */
  u32 vni;

  /* vnet intfc hw/sw_if_index */
  u32 hw_if_index;
  u32 sw_if_index;

  /* NSH header fields in HOST byte order */
  u8 ver_o_c;
  u8 length;
  u8 md_type;
  u8 next_protocol;
  u32 spi_si;
    
  /* Context headers, always present, in HOST byte order */
  u32 c1, c2, c3, c4;
  u32 * tlvs;
} nsh_vxlan_gpe_tunnel_t;

#define foreach_nsh_vxlan_gpe_input_next        \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(ETHERNET_INPUT, "ethernet-input")             \
_(NSH_VXLAN_GPE_ENCAP, "nsh-vxlan-gpe-encap")

typedef enum {
#define _(s,n) NSH_VXLAN_GPE_INPUT_NEXT_##s,
  foreach_nsh_vxlan_gpe_input_next
#undef _
  NSH_VXLAN_GPE_INPUT_N_NEXT,
} nsh_vxlan_gpe_input_next_t;

typedef enum {
#define nsh_vxlan_gpe_error(n,s) NSH_VXLAN_GPE_ERROR_##n,
#include <vnet/nsh-vxlan-gpe/nsh_vxlan_gpe_error.def>
#undef nsh_vxlan_gpe_error
  NSH_VXLAN_GPE_N_ERROR,
} nsh_vxlan_gpe_input_error_t;

typedef struct {
  /* vector of encap tunnel instances */
  nsh_vxlan_gpe_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword * nsh_vxlan_gpe_tunnel_by_key;

  /* Free vlib hw_if_indices */
  u32 * free_nsh_vxlan_gpe_tunnel_hw_if_indices;

  /* show device instance by real device instance */
  u32 * dev_inst_by_real;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} nsh_vxlan_gpe_main_t;

nsh_vxlan_gpe_main_t nsh_vxlan_gpe_main;

extern vlib_node_registration_t nsh_vxlan_gpe_input_node;
extern vlib_node_registration_t nsh_vxlan_gpe_encap_node;

u8 * format_nsh_vxlan_gpe_encap_trace (u8 * s, va_list * args);

typedef struct {
  u8 is_add;
  ip4_address_t src, dst;
  u32 encap_fib_index;
  u32 decap_fib_index;
  u32 decap_next_index;
  u32 vni;
  u8 ver_o_c;
  u8 length;
  u8 md_type;
  u8 next_protocol;
  u32 spi_si;
  u32 c1, c2, c3, c4;
  u32 * tlvs;
} vnet_nsh_vxlan_gpe_add_del_tunnel_args_t;

int vnet_nsh_vxlan_gpe_add_del_tunnel 
(vnet_nsh_vxlan_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp);

#endif /* included_vnet_nsh_vxlan_gpe_h */
