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
#include <vnet/nsh/nsh_packet.h>
#include <vnet/nsh-vxlan-gpe/vxlan_gpe_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/udp.h>


typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  udp_header_t udp;             /* 8 bytes */
  vxlan_gpe_header_t vxlan;     /* 8 bytes */
}) ip4_vxlan_gpe_header_t;

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
}) vxlan_gpe_tunnel_key_t;

typedef struct {
  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 * rewrite;

  /* next protocol */
  vxlan_gpe_next_protocol_t next_protocol;

  /* tunnel src and dst addresses */
  ip4_address_t local;
  ip4_address_t remote;

  /* FIB indices */
  u32 encap_fib_index;          /* tunnel partner lookup here */
  u32 decap_fib_index;          /* inner IP lookup here */

  /* vxlan VNI in HOST byte order, shifted left 8 bits */
  u32 vni;

  /* vnet intfc hw/sw_if_index */
  u32 hw_if_index;
  u32 sw_if_index;

} vxlan_gpe_tunnel_t;


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
//alagalah end

#define foreach_vxlan_gpe_input_next        \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(ETHERNET_INPUT, "ethernet-input")             \
_(NSH_INPUT, "nsh-input")

typedef enum {
#define _(s,n) VXLAN_GPE_INPUT_NEXT_##s,
  foreach_vxlan_gpe_input_next
#undef _
  VXLAN_GPE_INPUT_N_NEXT,
} vxlan_gpe_input_next_t;

typedef enum {
#define vxlan_gpe_error(n,s) VXLAN_GPE_ERROR_##n,
#include <vnet/nsh-vxlan-gpe/vxlan_gpe_error.def>
#undef vxlan_gpe_error
  VXLAN_GPE_N_ERROR,
} vxlan_gpe_input_error_t;

typedef struct {
  /* vector of encap tunnel instances */
  vxlan_gpe_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword * vxlan_gpe_tunnel_by_key;

  /* Free vlib hw_if_indices */
  u32 * free_vxlan_gpe_tunnel_hw_if_indices;

  /* show device instance by real device instance */
  u32 * dev_inst_by_real;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} vxlan_gpe_main_t;

vxlan_gpe_main_t vxlan_gpe_main;


typedef struct {
  /* vector of encap tunnel instances */
  vxlan_gpe_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword * vxlan_gpe_tunnel_by_key;

  /* Free vlib hw_if_indices */
  u32 * free_vxlan_gpe_tunnel_hw_if_indices;

  /* show device instance by real device instance */
  u32 * dev_inst_by_real;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} vxlan_gpe_main_t;

vxlan_gpe_main_t vxlan_gpe_main;


extern vlib_node_registration_t vxlan_gpe_encap_node;
extern vlib_node_registration_t vxlan_gpe_input_node;

u8 * format_nsh_vxlan_gpe_encap_trace (u8 * s, va_list * args);
u8 * format_vxlan_gpe_encap_trace (u8 * s, va_list * args);

typedef struct {
  u8 is_add;
  ip4_address_t local, remote;
  vxlan_gpe_next_protocol_t next_protocol;
  u32 encap_fib_index;
  u32 decap_fib_index;
  u32 decap_next_index;
  u32 vni;
} vnet_vxlan_gpe_add_del_tunnel_args_t;


int vnet_vxlan_gpe_add_del_tunnel 
(vnet_vxlan_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp);


/***********************************************
 *
 *  alagalah begin NSH specific stuff to go to 
 *  new module
 *
 **********************************************/
/* alagalah
   This gets ripped out and taken to NSH node in subsequent patch

 */

u8 * format_nsh_input_map_trace (u8 * s, va_list * args);

/* Statistics (not really errors) */
#define foreach_nsh_input_error    \
_(MAPPED, "NSH header found and mapped")


// alagalah - need to test if this can be moved to an NSH header 
typedef enum {
#define _(sym,str) NSH_INPUT_ERROR_##sym,
    foreach_nsh_input_error
#undef _
    NSH_INPUT_N_ERROR,
} nsh_input_error_t;

#define foreach_nsh_input_next        \
  _(DROP, "error-drop") \
  _(DECAP_ETHERNET_LOOKUP, "ethernet-input" )	\
  _(DECAP_IP4_INPUT,  "ip4-lookup") \
  _(DECAP_IP6_INPUT,  "ip6-lookup" ) \
  _(ENCAP_GRE, "gre-encap" ) \
  _(ENCAP_VXLANGPE, "vxlan-gpe-encap" ) \
  _(ENCAP_ETHERNET, "error-drop")

typedef enum {
#define _(s,n) NSH_INPUT_NEXT_##s,
  foreach_nsh_input_next
#undef _
  NSH_INPUT_N_NEXT,
} nsh_input_next_t;

typedef struct {
  u32 nsh_key;
  u32 map_to_key; // NSH key
  u32 encap_index;
  u32 is_add;
} vnet_nsh_add_del_map_args_t;

typedef struct {
  u8 is_add;
  nsh_header_t nsh;
} vnet_nsh_add_del_entry_args_t;


#endif /* included_vnet_nsh_vxlan_gpe_h */
