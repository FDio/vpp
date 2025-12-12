/* SPDX-License-Identifier: Apache-2.0 OR MIT
 * Copyright (c) 2015 Cisco and/or its affiliates.
 * Copyright (c) 2008 Eliot Dresselhaus
 */

/* ip/ip_lookup.h: ip (4 or 6) lookup structures, adjacencies, ... */

/**
 * @file
 * Definitions for all things IP (v4|v6) unicast and multicast lookup related.
 *
 * - Adjacency definitions and registration.
 * - Callbacks on route add.
 * - Callbacks on interface address change.
 */
#ifndef included_ip_lookup_h
#define included_ip_lookup_h

//#include <vnet/vnet.h>
#include <vlib/vlib.h>
#include <vlib/buffer.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip_types.h>
#include <vnet/fib/fib_node.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/dpo.h>
///#include <vnet/feature/feature.h>

/* An all zeros address */
extern const ip46_address_t zero_addr;

typedef enum ip_interface_address_flags_t_
{
  IP_INTERFACE_ADDRESS_FLAG_STALE = (1 << 0),
} __clib_packed ip_interface_address_flags_t;

typedef struct
{
  fib_prefix_t prefix;

  u32 sw_if_index;
} ip_interface_prefix_key_t;

typedef struct
{
  /* key - prefix and sw_if_index */
  ip_interface_prefix_key_t key;

  /* number of addresses in this prefix on the interface */
  u16 ref_count;

  /* index of the interface address used as a default source address */
  u32 src_ia_index;
} ip_interface_prefix_t;

typedef struct
{
  /* Key for mhash; in fact, just a byte offset into mhash key vector. */
  u32 address_key;

  /* Interface which has this address. */
  u32 sw_if_index;

  /* Address (prefix) length for this interface. */
  u16 address_length;

  /* flags relating to this prefix */
  ip_interface_address_flags_t flags;

  /* Next and previous pointers for doubly linked list of
     addresses per software interface. */
  u32 next_this_sw_interface;
  u32 prev_this_sw_interface;
} ip_interface_address_t;

typedef enum
{
  IP_LOCAL_NEXT_DROP,
  IP_LOCAL_NEXT_PUNT,
  IP_LOCAL_NEXT_ICMP,
  IP_LOCAL_NEXT_REASSEMBLY,
  IP_LOCAL_N_NEXT,
} ip_local_next_t;

struct ip_lookup_main_t;

typedef struct ip_lookup_main_t
{
  /** Pool of addresses that are assigned to interfaces. */
  ip_interface_address_t *if_address_pool;

  /** Hash table mapping address to index in interface address pool. */
  mhash_t address_to_if_address_index;

  /** Head of doubly linked list of interface addresses for each software interface.
     ~0 means this interface has no address. */
  u32 *if_address_pool_index_by_sw_if_index;

  /** Pool of prefixes containing addresses assigned to interfaces */
  ip_interface_prefix_t *if_prefix_pool;

  /** Hash table mapping prefix to index in interface prefix pool */
  mhash_t prefix_to_if_prefix_index;

  /** First table index to use for this interface, ~0 => none */
  u32 *classify_table_index_by_sw_if_index;

  /** Feature arc indices */
  u8 mcast_feature_arc_index;
  u8 ucast_feature_arc_index;
  u8 output_feature_arc_index;

  /** Number of bytes in a fib result.  Must be at least
     sizeof (uword).  First word is always adjacency index. */
  u32 fib_result_n_bytes, fib_result_n_words;

  /** 1 for ip6; 0 for ip4. */
  u32 is_ip6;

  /** Either format_ip4_address_and_length or format_ip6_address_and_length. */
  format_function_t *format_address_and_length;

  /** Table mapping ip protocol to ip[46]-local node next index. */
  u8 local_next_by_ip_protocol[256];

  /** IP_BUILTIN_PROTOCOL_{TCP,UDP,ICMP,OTHER} by protocol in IP header. */
  u8 builtin_protocol_by_ip_protocol[256];
} ip_lookup_main_t;

u8 *format_ip_flow_hash_config (u8 * s, va_list * args);
uword unformat_ip_flow_hash_config (unformat_input_t *input, va_list *args);

always_inline void
ip_lookup_set_buffer_fib_index (u32 * fib_index_by_sw_if_index,
				vlib_buffer_t * b)
{
  vnet_buffer (b)->ip.fib_index =
    vec_elt (fib_index_by_sw_if_index, vnet_buffer (b)->sw_if_index[VLIB_RX]);
  vnet_buffer (b)->ip.fib_index =
    ((vnet_buffer (b)->sw_if_index[VLIB_TX] ==  (u32) ~ 0) ?
     vnet_buffer (b)->ip.fib_index :
     vnet_buffer (b)->sw_if_index[VLIB_TX]);
}

void ip_lookup_init (ip_lookup_main_t * lm, u32 ip_lookup_node_index);
bool fib_prefix_validate (const fib_prefix_t *prefix);

#endif /* included_ip_lookup_h */
