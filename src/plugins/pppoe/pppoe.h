/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Intel and/or its affiliates.
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

#ifndef included_vnet_pppoe_h
#define included_vnet_pppoe_h

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
#include <vnet/fib/fib_table.h>


typedef struct
{
  u8 ver_type;
  u8 code;
  u16 session_id;
  u16 length;
  u16 ppp_proto;
} pppoe_header_t;

#define PPPOE_VER_TYPE 0x11

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip client_ip on incoming pppoe packet
   * all fields in NET byte order
   */
  u32 client_ip;

}) pppoe4_session_key_t;
/* *INDENT-ON* */

/* *INDENT-OFF* */
typedef CLIB_PACKED
(struct {
  /*
   * Key fields: ip client_ip on incoming pppoe packet
   * all fields in NET byte order
   */
  ip6_address_t client_ip;

}) pppoe6_session_key_t;
/* *INDENT-ON* */

typedef struct
{
  /* Rewrite string */
  u8 *rewrite;

  /* FIB DPO for IP forwarding of pppoe encap packet */
  dpo_id_t next_dpo;

  /* pppoe session_id in HOST byte order */
  u16 session_id;

  /* session client addresses */
  ip46_address_t client_ip;

  /* the index of tx interface for pppoe encaped packet */
  u32 encap_if_index;

  /** FIB indices - inner IP packet lookup here */
  u32 decap_fib_index;

  u8 local_mac[6];
  u8 client_mac[6];

  /* vnet intfc index */
  u32 sw_if_index;
  u32 hw_if_index;

  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /*
   * The FIB entry for (depending on pppoe session is unicast or mcast)
   * sending unicast pppoe encap packets or receiving mcast pppoe packets
   */
  fib_node_index_t fib_entry_index;

  /**
   * The session is a child of the FIB entry for its destination. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The sessions sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;

} pppoe_session_t;

#define foreach_pppoe_input_next        \
_(DROP, "error-drop")                  \
_(IP4_INPUT, "ip4-input")              \
_(IP6_INPUT, "ip6-input" )             \

typedef enum
{
#define _(s,n) PPPOE_INPUT_NEXT_##s,
  foreach_pppoe_input_next
#undef _
    PPPOE_INPUT_N_NEXT,
} pppoe_input_next_t;

typedef enum
{
#define pppoe_error(n,s) PPPOE_ERROR_##n,
#include <pppoe/pppoe_error.def>
#undef pppoe_error
  PPPOE_N_ERROR,
} pppoe_input_error_t;

typedef struct
{
  /* vector of encap session instances */
  pppoe_session_t *sessions;

  /* lookup session by key */
  uword *pppoe4_session_by_key;	/* keyed on ipv4.client_ip*/
  uword *pppoe6_session_by_key;	/* keyed on ipv6.client_ip */

  /* Free vlib hw_if_indices */
  u32 *free_pppoe_session_hw_if_indices;

  /* Mapping from sw_if_index to session index */
  u32 *session_index_by_sw_if_index;

  /**
   * Node type for registering to fib changes.
   */
  fib_node_type_t fib_node_type;

  /* API message ID base */
  u16 msg_id_base;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;

} pppoe_main_t;

pppoe_main_t pppoe_main;

extern vlib_node_registration_t pppoe_input_node;
extern vlib_node_registration_t pppoe_encap_node;

u8 *format_pppoe_encap_trace (u8 * s, va_list * args);

typedef struct
{
  u8 is_add;
  u8 is_ip6;
  u16 session_id;
  ip46_address_t client_ip;
  u32 encap_if_index;
  u32 decap_fib_index;
  u8 local_mac[6];
  u8 client_mac[6];
} vnet_pppoe_add_del_session_args_t;

int vnet_pppoe_add_del_session
  (vnet_pppoe_add_del_session_args_t * a, u32 * sw_if_indexp);

#endif /* included_vnet_pppoe_h */


/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
