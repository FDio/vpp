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
#ifndef included_vnet_lisp_gpe_h
#define included_vnet_lisp_gpe_h

#include <vppinfra/error.h>
#include <vppinfra/hash.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/l2/l2_input.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/lisp-gpe/lisp_gpe_packet.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/udp.h>

typedef CLIB_PACKED (struct {
  ip4_header_t ip4;             /* 20 bytes */
  udp_header_t udp;             /* 8 bytes */
  lisp_gpe_header_t lisp;       /* 8 bytes */
}) ip4_udp_lisp_gpe_header_t;

typedef CLIB_PACKED(struct {
  /* 
   * Key fields: ip src, LISP iid, ??? $$$$$$$$$ correct answer ???
   * all fields in NET byte order
   */
  union {
    struct {
      u32 src;
      u32 iid;
    };
    u64 as_u64[1];
  };
}) lisp_gpe_tunnel_key_t;

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

  /* vnet intfc hw/sw_if_index */
  u32 hw_if_index;
  u32 sw_if_index;

  /* LISP header fields in HOST byte order */
  u8 flags;
  u8 ver_res;
  u8 res;
  u8 next_protocol;
  u32 iid;
} lisp_gpe_tunnel_t;

#define foreach_lisp_gpe_input_next             \
_(DROP, "error-drop")                           \
_(IP4_INPUT, "ip4-input")                       \
_(IP6_INPUT, "ip6-input")                       \
_(ETHERNET_INPUT, "ethernet-input")             \
_(LISP_GPE_ENCAP, "lisp-gpe-encap")

typedef enum {
#define _(s,n) LISP_GPE_INPUT_NEXT_##s,
  foreach_lisp_gpe_input_next
#undef _
  LISP_GPE_INPUT_N_NEXT,
} lisp_gpe_input_next_t;

typedef enum {
#define lisp_gpe_error(n,s) LISP_GPE_ERROR_##n,
#include <vnet/lisp-gpe/lisp_gpe_error.def>
#undef lisp_gpe_error
  LISP_GPE_N_ERROR,
} lisp_gpe_input_error_t;

typedef struct {
  /* vector of encap tunnel instances */
  lisp_gpe_tunnel_t *tunnels;

  /* lookup tunnel by key */
  uword * lisp_gpe_tunnel_by_key;

  /* Free vlib hw_if_indices */
  u32 * free_lisp_gpe_tunnel_hw_if_indices;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} lisp_gpe_main_t;

lisp_gpe_main_t lisp_gpe_main;

extern vlib_node_registration_t lisp_gpe_input_node;
extern vlib_node_registration_t lisp_gpe_encap_node;

u8 * format_lisp_gpe_encap_trace (u8 * s, va_list * args);
u8 * format_lisp_gpe_header_with_length (u8 * s, va_list * args);

typedef struct {
  u8 is_add;
  ip4_address_t src, dst;
  u32 encap_fib_index;
  u32 decap_fib_index;
  u32 decap_next_index;
  u8 flags;
  u8 ver_res;
  u8 res;
  u8 next_protocol;
  u32 iid;                      /* host byte order */
} vnet_lisp_gpe_add_del_tunnel_args_t;

int vnet_lisp_gpe_add_del_tunnel 
(vnet_lisp_gpe_add_del_tunnel_args_t *a, u32 * sw_if_indexp);

u8 * format_lisp_gpe_header_with_length (u8 * s, va_list * args);

#endif /* included_vnet_lisp_gpe_h */
