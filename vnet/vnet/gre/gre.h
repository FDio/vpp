/*
 * gre.h: types/functions for gre.
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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

#ifndef included_gre_h
#define included_gre_h

#include <vnet/vnet.h>
#include <vnet/gre/packet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/pg/pg.h>
#include <vnet/ip/format.h>
#include <vnet/adj/adj_types.h>

extern vnet_hw_interface_class_t gre_hw_interface_class;

typedef enum {
#define gre_error(n,s) GRE_ERROR_##n,
#include <vnet/gre/error.def>
#undef gre_error
  GRE_N_ERROR,
} gre_error_t;

typedef struct {
  /* Name (a c string). */
  char * name;

  /* GRE protocol type in host byte order. */
  gre_protocol_t protocol;

  /* Node which handles this type. */
  u32 node_index;

  /* Next index for this type. */
  u32 next_index;
} gre_protocol_info_t;

typedef struct {
  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /**
   * The tunnel's source/local address
   */
  ip4_address_t tunnel_src;
  /**
   * The tunnel's destination/remote address
   */
  ip4_address_t tunnel_dst;
  /**
   * The FIB in which the src.dst address are present
   */
  u32 outer_fib_index;
  u32 hw_if_index;
  u32 sw_if_index;
  u8 teb;

  /**
   * The FIB entry sourced by the tunnel for its destination prefix
   */
  fib_node_index_t fib_entry_index;

  /**
   * The tunnel is a child of the FIB entry for its desintion. This is
   * so it receives updates when the forwarding information for that entry
   * changes.
   * The tunnels sibling index on the FIB entry's dependency list.
   */
  u32 sibling_index;

  /**
   * The index of the midchain adjacency created for this tunnel
   */
  adj_index_t adj_index[FIB_LINK_NUM];
} gre_tunnel_t;

typedef struct {
  /* pool of tunnel instances */
  gre_tunnel_t *tunnels;

  gre_protocol_info_t * protocol_infos;

  /* Hash tables mapping name/protocol to protocol info index. */
  uword * protocol_info_by_name, * protocol_info_by_protocol;
  /* Hash mapping src/dst addr pair to tunnel */
  uword * tunnel_by_key;

  /* Free vlib hw_if_indices */
  u32 * free_gre_tunnel_hw_if_indices;

  /* Mapping from sw_if_index to tunnel index */
  u32 * tunnel_index_by_sw_if_index;

  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
} gre_main_t;

/**
 * @brief IPv4 and GRE header.
 *
*/
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  gre_header_t gre;
}) ip4_and_gre_header_t;

always_inline gre_protocol_info_t *
gre_get_protocol_info (gre_main_t * em, gre_protocol_t protocol)
{
  uword * p = hash_get (em->protocol_info_by_protocol, protocol);
  return p ? vec_elt_at_index (em->protocol_infos, p[0]) : 0;
}

gre_main_t gre_main;

/* Register given node index to take input for given gre type. */
void
gre_register_input_type (vlib_main_t * vm,
			 gre_protocol_t protocol,
			 u32 node_index);

void gre_set_adjacency (vnet_rewrite_header_t * rw,
			uword max_data_bytes,
			gre_protocol_t protocol);

format_function_t format_gre_protocol;
format_function_t format_gre_header;
format_function_t format_gre_header_with_length;

extern vlib_node_registration_t gre_input_node;
extern vnet_device_class_t gre_device_class;

/* Parse gre protocol as 0xXXXX or protocol name.
   In either host or network byte order. */
unformat_function_t unformat_gre_protocol_host_byte_order;
unformat_function_t unformat_gre_protocol_net_byte_order;

/* Parse gre header. */
unformat_function_t unformat_gre_header;
unformat_function_t unformat_pg_gre_header;

void
gre_register_input_protocol (vlib_main_t * vm,
			     gre_protocol_t protocol,
			     u32 node_index);

/* manually added to the interface output node in gre.c */
#define GRE_OUTPUT_NEXT_LOOKUP	1

typedef struct {
  u8 is_add;

  ip4_address_t src, dst;
  u32 outer_fib_id;
  u8 teb;
} vnet_gre_add_del_tunnel_args_t;

int vnet_gre_add_del_tunnel
  (vnet_gre_add_del_tunnel_args_t *a, u32 * sw_if_indexp);

#endif /* included_gre_h */
