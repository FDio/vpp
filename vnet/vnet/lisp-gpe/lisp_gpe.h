/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#ifndef included_vnet_lisp_gpe_h
#define included_vnet_lisp_gpe_h

#include <vppinfra/error.h>
#include <vppinfra/mhash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/udp.h>
#include <vnet/lisp-cp/lisp_types.h>
#include <vnet/lisp-gpe/lisp_gpe_packet.h>

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  udp_header_t udp;             /* 8 bytes */
  lisp_gpe_header_t lisp;       /* 8 bytes */
}) ip4_udp_lisp_gpe_header_t;

typedef CLIB_PACKED (struct {
  ip6_header_t ip6;             /* 40 bytes */
  udp_header_t udp;             /* 8 bytes */
  lisp_gpe_header_t lisp;       /* 8 bytes */
}) ip6_udp_lisp_gpe_header_t;

typedef struct
{
  union
  {
    struct
    {
      ip_prefix_t eid;          /* within the dp only ip and mac can be eids */
      ip_address_t dst_loc;
      u32 iid;
    };
    u8 as_u8[40];
  };
} lisp_gpe_tunnel_key_t;

typedef struct
{
  /* Rewrite string. $$$$ embed vnet_rewrite header */
  u8 * rewrite;

  /* decap next index */
  u32 decap_next_index;

  /* tunnel src and dst addresses */
  ip_address_t src;
  ip_address_t dst;

  /* FIB indices */
  u32 encap_fib_index;          /* tunnel partner lookup here */
  u32 decap_fib_index;          /* inner IP lookup here */

  /* vnet intfc hw/sw_if_index */
  u32 hw_if_index;
  u32 sw_if_index;

  /* LISP header fields in HOST byte order */
  u8 flags;
  u8 ver_res;
  u8 res;
  u8 next_protocol;
  u32 vni;
} lisp_gpe_tunnel_t;

#define foreach_lisp_gpe_ip_input_next          \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(ETHERNET_INPUT, "ethernet-input")

typedef enum {
#define _(s,n) LISP_GPE_INPUT_NEXT_##s,
  foreach_lisp_gpe_ip_input_next
#undef _
  LISP_GPE_INPUT_N_NEXT,
} lisp_gpe_input_next_t;

typedef enum {
#define lisp_gpe_error(n,s) LISP_GPE_ERROR_##n,
#include <vnet/lisp-gpe/lisp_gpe_error.def>
#undef lisp_gpe_error
  LISP_GPE_N_ERROR,
} lisp_gpe_error_t;

/* As a first step, reuse v4 fib. The goal of the typedef is to shield
 * consumers from future updates that may result in the lisp ip4 fib diverging
 * from ip4 fib */
typedef ip4_fib_t ip4_src_fib_t;

typedef struct ip6_src_fib
{
  BVT(clib_bihash) ip6_lookup_table;

  /* bitmap/vector of mask widths to search */
  uword * non_empty_dst_address_length_bitmap;
  u8 * prefix_lengths_in_search_order;
  ip6_address_t fib_masks[129];
  i32 dst_address_length_refcounts[129];

  /* ip6 lookup table config parameters */
  u32 lookup_table_nbuckets;
  uword lookup_table_size;
} ip6_src_fib_t;

typedef struct lisp_gpe_main
{
  /* Pool of src fibs that are paired with dst fibs */
  ip4_src_fib_t * ip4_src_fibs;
  ip6_src_fib_t * ip6_src_fibs;

  /* vector of encap tunnel instances */
  lisp_gpe_tunnel_t * tunnels;

  /* lookup tunnel by key */
  mhash_t lisp_gpe_tunnel_by_key;

  /* lookup decap tunnel termination sw_if_index by vni and vice versa */
  uword * tunnel_term_sw_if_index_by_vni;
  uword * vni_by_tunnel_term_sw_if_index;

  /* Free vlib hw_if_indices */
  u32 * free_lisp_gpe_tunnel_hw_if_indices;

  /* Lookup lisp-gpe interfaces by vrf */
  uword * lisp_gpe_hw_if_index_by_table_id;

  /* Lookup lgpe_ipX_lookup_next by vrf */
  uword * lgpe_ip4_lookup_next_index_by_table_id;
  uword * lgpe_ip6_lookup_next_index_by_table_id;

  /* next node indexes that point ip4/6 lookup to lisp gpe ip lookup */
  u32 ip4_lookup_next_lgpe_ip4_lookup;
  u32 ip6_lookup_next_lgpe_ip6_lookup;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ip4_main_t * im4;
  ip6_main_t * im6;
  ip_lookup_main_t * lm4;
  ip_lookup_main_t * lm6;
  u8 is_en;
} lisp_gpe_main_t;

lisp_gpe_main_t lisp_gpe_main;

extern vlib_node_registration_t lgpe_ip4_lookup_node;
extern vlib_node_registration_t lgpe_ip6_lookup_node;
extern vlib_node_registration_t lisp_gpe_ip4_input_node;
extern vlib_node_registration_t lisp_gpe_ip6_input_node;

u8 *
format_lisp_gpe_header_with_length (u8 * s, va_list * args);

typedef struct
{
  u8 is_add;
  u32 table_id; /* vrf */
  u32 vni;      /* host byte order */
} vnet_lisp_gpe_add_del_iface_args_t;

u8
vnet_lisp_gpe_enable_disable_status(void);
void
vnet_lisp_gpe_add_del_iface (vnet_lisp_gpe_add_del_iface_args_t *a,
			     u32 * hw_if_indexp);

typedef struct
{
  u8 is_en;
} vnet_lisp_gpe_enable_disable_args_t;

clib_error_t *
vnet_lisp_gpe_enable_disable (vnet_lisp_gpe_enable_disable_args_t *a);

typedef enum
{
  NO_ACTION,
  FORWARD_NATIVE,
  SEND_MAP_REQUEST,
  DROP
} negative_fwd_actions_e;

typedef struct
{
  u8 is_add;

  /* type of mapping */
  u8 is_negative;
  negative_fwd_actions_e action;

  /* local and remote eids */
  gid_address_t seid; /* TODO convert to ip4, ip6, mac ? */
  gid_address_t deid;

  /* local and remote locators (underlay attachment points) */
  ip_address_t slocator;
  ip_address_t dlocator;

  /* FIB indices to lookup remote locator at encap and inner IP at decap */
  u32 encap_fib_index;
  u32 decap_fib_index;

  u32 decap_next_index; /* TODO is this really needed? */

  /* VNI/tenant id in HOST byte order */
  u32 vni;

  /* vrf where fwd entry should be inserted */
  u32 table_id;
} vnet_lisp_gpe_add_del_fwd_entry_args_t;

int
vnet_lisp_gpe_add_del_fwd_entry (vnet_lisp_gpe_add_del_fwd_entry_args_t *a,
				 u32 * hw_if_indexp);

int
ip_sd_fib_add_del_route (lisp_gpe_main_t * lgm, ip_prefix_t * dst_prefix,
                         ip_prefix_t * src_prefix, u32 table_id,
                         ip_adjacency_t * add_adj, u8 is_add);
u32
ip_sd_fib_get_route (lisp_gpe_main_t * lgm, ip_prefix_t * dst_prefix,
                     ip_prefix_t * src_prefix, u32 table_id);

#define foreach_lgpe_ip4_lookup_next    \
  _(DROP, "error-drop")                 \
  _(LISP_CP_LOOKUP, "lisp-cp-lookup")

typedef enum lgpe_ip4_lookup_next
{
#define _(sym,str) LGPE_IP4_LOOKUP_NEXT_##sym,
  foreach_lgpe_ip4_lookup_next
#undef _
  LGPE_IP4_LOOKUP_N_NEXT,
} lgpe_ip4_lookup_next_t;

#define foreach_lgpe_ip6_lookup_next     \
  _(DROP, "error-drop")                 \
  _(LISP_CP_LOOKUP, "lisp-cp-lookup")

typedef enum lgpe_ip6_lookup_next
{
#define _(sym,str) LGPE_IP6_LOOKUP_NEXT_##sym,
  foreach_lgpe_ip6_lookup_next
#undef _
  LGPE_IP6_LOOKUP_N_NEXT,
} lgpe_ip6_lookup_next_t;

u8 * format_vnet_lisp_gpe_status (u8 * s, va_list * args);

#endif /* included_vnet_lisp_gpe_h */
