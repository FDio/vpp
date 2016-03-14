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
#ifndef included_vnet_mpls_gre_h
#define included_vnet_mpls_gre_h

#include <vnet/vnet.h>
#include <vnet/gre/gre.h>
#include <vnet/mpls-gre/packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ethernet/ethernet.h>

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  gre_header_t gre;             /* 4 bytes */
  mpls_unicast_header_t labels[0];   /* 4 bytes each */
}) ip4_gre_and_mpls_header_t;

extern vnet_hw_interface_class_t mpls_gre_hw_interface_class;

typedef enum {
#define mpls_error(n,s) MPLS_ERROR_##n,
#include <vnet/mpls-gre/error.def>
#undef mpls_error
  MPLS_N_ERROR,
} mpls_gre_error_t;

/* 
 * No protocol info, MPLS labels don't have a next-header field 
 * presumably the label field tells all...
 */

typedef struct {
  ip4_address_t tunnel_src;
  ip4_address_t tunnel_dst;
  ip4_address_t intfc_address;
  u32 mask_width;
  u32 inner_fib_index;
  u32 outer_fib_index;
  u32 encap_index;
  u32 hw_if_index;              /* L2 x-connect capable tunnel intfc */
  u8 * rewrite_data;
  u8 l2_only;
} mpls_gre_tunnel_t;

typedef struct {
  u8 tunnel_dst[6];
  ip4_address_t intfc_address;
  u32 tx_sw_if_index;
  u32 inner_fib_index;
  u32 mask_width;
  u32 encap_index;
  u32 hw_if_index;
  u8 * rewrite_data;
  u8 l2_only;
} mpls_eth_tunnel_t;

typedef struct {
  mpls_unicast_header_t *labels;
  /* only for policy tunnels */
  u8 * rewrite;
  u32 output_next_index;
} mpls_encap_t;

typedef struct {
  u32 tx_fib_index;
  u32 next_index;               /* e.g. ip4/6-input, l2-input */
} mpls_decap_t;

typedef struct {
  /* pool of gre tunnel instances */
  mpls_gre_tunnel_t *gre_tunnels;
  u32 * free_gre_sw_if_indices;

  /* pool of ethernet tunnel instances */
  mpls_eth_tunnel_t *eth_tunnels;
  u32 * free_eth_sw_if_indices;

  /* Encap side: map (fib, dst_address) to mpls label stack */
  mpls_encap_t * encaps;
  uword * mpls_encap_by_fib_and_dest;

  /* Decap side: map rx label to FIB */
  mpls_decap_t * decaps;
  uword * mpls_decap_by_rx_fib_and_label;

  /* mpls-o-e policy tunnel next index for ip4-classify */
  u32 ip_classify_mpls_policy_encap_next_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} mpls_main_t;

mpls_main_t mpls_main;

format_function_t format_mpls_protocol;
format_function_t format_mpls_header;
format_function_t format_mpls_header_with_length;
format_function_t format_mpls_gre_header_with_length;
format_function_t format_mpls_eth_header_with_length;
format_function_t format_mpls_unicast_label;
format_function_t format_mpls_encap_index;

extern vlib_node_registration_t mpls_input_node;
extern vlib_node_registration_t mpls_policy_encap_node;

extern vnet_device_class_t mpls_gre_device_class;

/* Parse mpls protocol as 0xXXXX or protocol name.
   In either host or network byte order. */
unformat_function_t unformat_mpls_protocol_host_byte_order;
unformat_function_t unformat_mpls_protocol_net_byte_order;
unformat_function_t unformat_mpls_label_net_byte_order;
unformat_function_t unformat_mpls_gre_header;
unformat_function_t unformat_pg_mpls_gre_header;

/* Parse mpls header. */
unformat_function_t unformat_mpls_header;
unformat_function_t unformat_pg_mpls_header;

/* manually added to the interface output node in mpls.c */
#define MPLS_GRE_OUTPUT_NEXT_LOOKUP	1
#define MPLS_GRE_OUTPUT_NEXT_DROP	VNET_INTERFACE_TX_NEXT_DROP

mpls_encap_t * 
mpls_encap_by_fib_and_dest (mpls_main_t * mm, u32 rx_fib, u32 dst_address);

int mpls_label_from_fib_id_and_dest (mpls_main_t *gm, u32 fib_id,
                                     u32 dst_address, u32 *labelp);

int vnet_mpls_gre_add_del_tunnel (ip4_address_t *src,
                                  ip4_address_t *dst,
                                  ip4_address_t *intfc,
                                  u32 mask_width,
                                  u32 inner_fib_id, u32 outer_fib_id,
                                  u32 * tunnel_intfc_sw_if_index,
                                  u8 l2_only,
                                  u8 is_add);

int vnet_mpls_ethernet_add_del_tunnel (u8 *dst,
                                       ip4_address_t *intfc,
                                       u32 mask_width,
                                       u32 inner_fib_id, 
                                       u32 tx_sw_if_index,
                                       u32 * tunnel_sw_if_index,
                                       u8 l2_only,
                                       u8 is_add);

int vnet_mpls_gre_delete_fib_tunnels (u32 fib_id);

int mpls_fib_reset_labels (u32 fib_id);

int vnet_mpls_add_del_decap (u32 rx_fib_id, 
                             u32 tx_fib_id,
                             u32 label_host_byte_order, 
                             int s_bit, int next_index, int is_add);

int vnet_mpls_add_del_encap (ip4_address_t *dest, u32 fib_id, 
                             u32 *labels_host_byte_order,
                             u32 policy_tunnel_index,
                             int no_dst_hash, u32 * indexp, int is_add);

int vnet_mpls_policy_tunnel_add_rewrite (mpls_main_t * mm, 
                                         mpls_encap_t * e, 
                                         u32 policy_tunnel_index);
typedef struct {
  u32 lookup_miss;

  /* Tunnel-id / index in tunnel vector */
  u32 tunnel_id;

  /* mpls encap index */
  u32 mpls_encap_index;

  /* pkt length */
  u32 length;

  /* tunnel ip4 addresses */
  ip4_address_t src;
  ip4_address_t dst;
} mpls_gre_tx_trace_t;

u8 * format_mpls_gre_tx_trace (u8 * s, va_list * args);
u8 * format_mpls_gre_header (u8 * s, va_list * args);

#define foreach_mpls_input_next			\
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(L2_OUTPUT, "l2-output")

typedef enum {
#define _(s,n) MPLS_INPUT_NEXT_##s,
  foreach_mpls_input_next
#undef _
  MPLS_INPUT_N_NEXT,
} mpls_input_next_t;


typedef struct {
  u32 lookup_miss;

  /* Tunnel-id / index in tunnel vector */
  u32 tunnel_id;

  /* output interface */
  u32 tx_sw_if_index;

  /* mpls encap index */
  u32 mpls_encap_index;

  /* pkt length */
  u32 length;

  u8 dst[6];
} mpls_eth_tx_trace_t;

u8 * format_mpls_eth_tx_trace (u8 * s, va_list * args);

#endif /* included_vnet_mpls_gre_h */
