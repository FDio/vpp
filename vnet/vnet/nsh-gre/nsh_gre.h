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
#ifndef included_vnet_nsh_gre_h
#define included_vnet_nsh_gre_h

#include <vnet/vnet.h>
#include <vnet/gre/gre.h>
#include <vnet/nsh-gre/nsh_gre_packet.h>
#include <vnet/ip/ip4_packet.h>

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  gre_header_t gre;             /* 4 bytes */
  nsh_header_t nsh;   		/* 28 bytes */
}) ip4_gre_and_nsh_header_t;

typedef struct {
  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 * rewrite;

  /* tunnel src and dst addresses */
  ip4_address_t src;
  ip4_address_t dst;

  /* FIB indices */
  u32 encap_fib_index;          /* tunnel partner lookup here */
  u32 decap_fib_index;          /* inner IP lookup here */

  /* when decapsulating, send pkts here */
  u32 decap_next_index;

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
} nsh_gre_tunnel_t;

#define foreach_nsh_gre_input_next              \
  _ (DROP, "error-drop")                        \
  _ (IP4_INPUT, "ip4-input")                    \
  _ (IP6_INPUT, "ip6-input")                    \
  _ (ETHERNET_INPUT, "ethernet-input")

typedef enum {
#define _(s,n) NSH_INPUT_NEXT_##s,
  foreach_nsh_gre_input_next
#undef _
  NSH_INPUT_N_NEXT,
} nsh_gre_input_next_t;

typedef enum {
#define nsh_gre_error(n,s) NSH_GRE_ERROR_##n,
#include <vnet/nsh-gre/nsh_gre_error.def>
#undef nsh_gre_error
  NSH_GRE_N_ERROR,
} nsh_gre_input_error_t;

typedef struct {
  /* vector of encap tunnel instances */
  nsh_gre_tunnel_t *tunnels;

  /* lookup tunnel by tunnel partner src address */
  uword * nsh_gre_tunnel_by_src_address;

  /* Free vlib hw_if_indices */
  u32 * free_nsh_gre_tunnel_hw_if_indices;

  /* show device instance by real device instance */
  u32 * dev_inst_by_real;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} nsh_gre_main_t;

nsh_gre_main_t nsh_gre_main;

extern vlib_node_registration_t nsh_gre_input_node;
extern vlib_node_registration_t nsh_gre_encap_node;

u8 * format_nsh_gre_encap_trace (u8 * s, va_list * args);

typedef struct {
  u8 is_add;
  ip4_address_t src, dst;
  u32 encap_fib_index;
  u32 decap_fib_index;
  u32 decap_next_index;
  u8 ver_o_c;
  u8 length;
  u8 md_type;
  u8 next_protocol;
  u32 spi_si;
  u32 c1, c2, c3, c4;
  u32 * tlvs;
} vnet_nsh_gre_add_del_tunnel_args_t;

int vnet_nsh_gre_add_del_tunnel (vnet_nsh_gre_add_del_tunnel_args_t *a, 
                                 u32 * sw_if_indexp);

#endif /* included_vnet_nsh_gre_h */
