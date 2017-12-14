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
#include <vnet/pg/pg.h>
#include <vnet/ip/format.h>
#include <vnet/adj/adj_types.h>

extern vnet_hw_interface_class_t gre_hw_interface_class;

typedef enum
{
#define gre_error(n,s) GRE_ERROR_##n,
#include <vnet/gre/error.def>
#undef gre_error
  GRE_N_ERROR,
} gre_error_t;

/**
 * A GRE payload protocol registration
 */
typedef struct
{
  /** Name (a c string). */
  char *name;

  /** GRE protocol type in host byte order. */
  gre_protocol_t protocol;

  /** Node which handles this type. */
  u32 node_index;

  /** Next index for this type. */
  u32 next_index;
} gre_protocol_info_t;

/**
 * @brief The GRE tunnel type
 */
typedef enum gre_tunnel_tyoe_t_
{
  /**
   * L3 GRE (i.e. this tunnel is in L3 mode)
   */
  GRE_TUNNEL_TYPE_L3,
  /**
   * Transparent Ethernet Bridging - the tunnel is in L2 mode
   */
  GRE_TUNNEL_TYPE_TEB,
} gre_tunnel_type_t;

#define GRE_TUNNEL_TYPE_NAMES {    \
    [GRE_TUNNEL_TYPE_L3] = "L3",   \
    [GRE_TUNNEL_TYPE_TEB] = "TEB", \
}

#define GRE_TUNNEL_N_TYPES ((gre_tunnel_type_t)GRE_TUNNEL_TYPE_TEB+1)

/**
 * @brief Key for a IPv4 GRE Tunnel
 */
typedef struct gre_tunnel_key4_t_
{
  /**
   * Source and destination IP addresses
   */
  union
  {
    struct
    {
      ip4_address_t gtk_src;
      ip4_address_t gtk_dst;
    };
    u64 gtk_as_u64;
  };

  /**
   * The FIB table the src,dst addresses are in.
   * tunnels with the same IP addresses in different FIBs are not
   * the same tunnel
   */
  u32 gtk_fib_index;
} __attribute__ ((packed)) gre_tunnel_key4_t;

/**
 * @brief Key for a IPv6 GRE Tunnel
 * We use a different type so that the V4 key hash is as small as possible
 */
typedef struct gre_tunnel_key6_t_
{
  /**
   * Source and destination IP addresses
   */
  ip6_address_t gtk_src;
  ip6_address_t gtk_dst;

  /**
   * The FIB table the src,dst addresses are in.
   * tunnels with the same IP addresses in different FIBs are not
   * the same tunnel
   */
  u32 gtk_fib_index;
} __attribute__ ((packed)) gre_tunnel_key6_t;

/**
 * Union of the two possible key types
 */
typedef union gre_tunnel_key_t_
{
  gre_tunnel_key4_t gtk_v4;
  gre_tunnel_key6_t gtk_v6;
} gre_tunnel_key_t;

/**
 * @brief A representation of a GRE tunnel
 */
typedef struct
{
  /**
   * Linkage into the FIB object graph
   */
  fib_node_t node;

  /**
   * The hash table's key stored in separate memory since the tunnel_t
   * memory can realloc.
   */
  gre_tunnel_key_t *key;

  /**
   * The tunnel's source/local address
   */
  ip46_address_t tunnel_src;
  /**
   * The tunnel's destination/remote address
   */
  fib_prefix_t tunnel_dst;
  /**
   * The FIB in which the src.dst address are present
   */
  u32 outer_fib_index;
  u32 hw_if_index;
  u32 sw_if_index;
  gre_tunnel_type_t type;

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
   * on a L2 tunnel this is the VLIB arc from the L2-tx to the l2-midchain
   */
  u32 l2_tx_arc;

  /**
   * an L2 tunnel always rquires an L2 midchain. cache here for DP.
   */
  adj_index_t l2_adj_index;
} gre_tunnel_t;

/**
 * @brief GRE related global data
 */
typedef struct
{
  /**
   * pool of tunnel instances
   */
  gre_tunnel_t *tunnels;

  /**
   * GRE payload protocol registrations
   */
  gre_protocol_info_t *protocol_infos;

  /**
   *  Hash tables mapping name/protocol to protocol info index.
   */
  uword *protocol_info_by_name, *protocol_info_by_protocol;

  /**
   * Hash mapping ipv4 src/dst addr pair to tunnel
   */
  uword *tunnel_by_key4;

  /**
   * Hash mapping ipv6 src/dst addr pair to tunnel
   */
  uword *tunnel_by_key6;

  /**
   * Free vlib hw_if_indices.
   * A free list per-tunnel type since the interfaces ctreated are fo different
   * types and we cannot change the type.
   */
  u32 *free_gre_tunnel_hw_if_indices[GRE_TUNNEL_N_TYPES];

  /**
   * Mapping from sw_if_index to tunnel index
   */
  u32 *tunnel_index_by_sw_if_index;

  /* Sparse vector mapping gre protocol in network byte order
     to next index. */
  u16 *next_by_protocol;

  /* convenience */
  vlib_main_t *vlib_main;
  vnet_main_t *vnet_main;
} gre_main_t;

/**
 * @brief IPv4 and GRE header.
 */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip4_header_t ip4;
  gre_header_t gre;
}) ip4_and_gre_header_t;
/* *INDENT-ON* */

/**
 * @brief IPv6 and GRE header.
 */
/* *INDENT-OFF* */
typedef CLIB_PACKED (struct {
  ip6_header_t ip6;
  gre_header_t gre;
}) ip6_and_gre_header_t;
/* *INDENT-ON* */

always_inline gre_protocol_info_t *
gre_get_protocol_info (gre_main_t * em, gre_protocol_t protocol)
{
  uword *p = hash_get (em->protocol_info_by_protocol, protocol);
  return p ? vec_elt_at_index (em->protocol_infos, p[0]) : 0;
}

extern gre_main_t gre_main;

/* Register given node index to take input for given gre type. */
void
gre_register_input_type (vlib_main_t * vm,
			 gre_protocol_t protocol, u32 node_index);

extern clib_error_t *gre_interface_admin_up_down (vnet_main_t * vnm,
						  u32 hw_if_index, u32 flags);

extern void gre_tunnel_stack (adj_index_t ai);
extern void gre_update_adj (vnet_main_t * vnm,
			    u32 sw_if_index, adj_index_t ai);

format_function_t format_gre_protocol;
format_function_t format_gre_header;
format_function_t format_gre_header_with_length;

extern vlib_node_registration_t gre4_input_node;
extern vlib_node_registration_t gre6_input_node;
extern vnet_device_class_t gre_device_class;
extern vnet_device_class_t gre_device_teb_class;

/* Parse gre protocol as 0xXXXX or protocol name.
   In either host or network byte order. */
unformat_function_t unformat_gre_protocol_host_byte_order;
unformat_function_t unformat_gre_protocol_net_byte_order;

/* Parse gre header. */
unformat_function_t unformat_gre_header;
unformat_function_t unformat_pg_gre_header;

void
gre_register_input_protocol (vlib_main_t * vm,
			     gre_protocol_t protocol, u32 node_index);

/* manually added to the interface output node in gre.c */
#define GRE_OUTPUT_NEXT_LOOKUP	1

typedef struct
{
  u8 is_add;

  ip46_address_t src, dst;
  u8 is_ipv6;
  u32 outer_fib_id;
  u8 teb;
} vnet_gre_add_del_tunnel_args_t;

int vnet_gre_add_del_tunnel
  (vnet_gre_add_del_tunnel_args_t * a, u32 * sw_if_indexp);

static inline void
gre_mk_key4 (const ip4_address_t * src,
	     const ip4_address_t * dst,
	     u32 fib_index, gre_tunnel_key4_t * key)
{
  key->gtk_src = *src;
  key->gtk_dst = *dst;
  key->gtk_fib_index = fib_index;
}

static inline int
gre_match_key4 (const gre_tunnel_key4_t * key1,
		const gre_tunnel_key4_t * key2)
{
  return ((key1->gtk_as_u64 == key2->gtk_as_u64) &&
	  (key1->gtk_fib_index == key2->gtk_fib_index));
}

static inline void
gre_mk_key6 (const ip6_address_t * src,
	     const ip6_address_t * dst,
	     u32 fib_index, gre_tunnel_key6_t * key)
{
  key->gtk_src = *src;
  key->gtk_dst = *dst;
  key->gtk_fib_index = fib_index;
}

static inline int
gre_match_key6 (const gre_tunnel_key6_t * key1,
		const gre_tunnel_key6_t * key2)
{
  return ((key1->gtk_src.as_u64[0] == key2->gtk_src.as_u64[0]) &&
	  (key1->gtk_src.as_u64[1] == key2->gtk_src.as_u64[1]) &&
	  (key1->gtk_dst.as_u64[0] == key2->gtk_dst.as_u64[0]) &&
	  (key1->gtk_dst.as_u64[1] == key2->gtk_dst.as_u64[1]) &&
	  (key1->gtk_fib_index == key2->gtk_fib_index));
}

#endif /* included_gre_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
