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
/*
 * ip/ip4.h: ip4 main include file
 *
 * Copyright (c) 2008 Eliot Dresselhaus
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *  NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 *  LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 *  OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 *  WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef included_ip_ip4_h
#define included_ip_ip4_h

#include <vnet/ip/ip4_mtrie.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip_feature_registration.h>

typedef struct ip4_fib_t {
  /* Hash table for each prefix length mapping. */
  uword * adj_index_by_dst_address[33];

  /* Temporary vectors for holding new/old values for hash_set. */
  uword * new_hash_values, * old_hash_values;

  /* Mtrie for fast lookups.  Hash is used to maintain overlapping prefixes. */
  ip4_fib_mtrie_t mtrie;

  /* Table ID (hash key) for this FIB. */
  u32 table_id;

  /* Index into FIB vector. */
  u32 index;

  /* flow hash configuration */
  u32 flow_hash_config;

  /* N-tuple classifier indices */
  u32 fwd_classify_table_index;
  u32 rev_classify_table_index;

} ip4_fib_t;

struct ip4_main_t;

typedef void (ip4_add_del_route_function_t)
  (struct ip4_main_t * im,
   uword opaque,
   ip4_fib_t * fib,
   u32 flags,
   ip4_address_t * address,
   u32 address_length,
   void * old_result,
   void * new_result);

typedef struct {
  ip4_add_del_route_function_t * function;
  uword required_flags;
  uword function_opaque;
} ip4_add_del_route_callback_t;

typedef void (ip4_add_del_interface_address_function_t)
  (struct ip4_main_t * im,
   uword opaque,
   u32 sw_if_index,
   ip4_address_t * address,
   u32 address_length,
   u32 if_address_index,
   u32 is_del);

typedef struct {
  ip4_add_del_interface_address_function_t * function;
  uword function_opaque;
} ip4_add_del_interface_address_callback_t;

/**
 * @brief IPv4 main type.
 *
 * State of IPv4 VPP processing including:
 * - FIBs
 * - Feature indices used in feature topological sort
 * - Feature node run time references
 */

typedef struct ip4_main_t {
  ip_lookup_main_t lookup_main;

  /** Vector of FIBs. */
  ip4_fib_t * fibs;

  u32 fib_masks[33];

  /** Table index indexed by software interface. */
  u32 * fib_index_by_sw_if_index;

  /** Hash table mapping table id to fib index.
     ID space is not necessarily dense; index space is dense. */
  uword * fib_index_by_table_id;

  /** Vector of functions to call when routes are added/deleted. */
  ip4_add_del_route_callback_t * add_del_route_callbacks;

  /** Hash table mapping interface route rewrite adjacency index by sw if index. */
  uword * interface_route_adj_index_by_sw_if_index;

  /** Functions to call when interface address changes. */
  ip4_add_del_interface_address_callback_t * add_del_interface_address_callbacks;

  /** Template used to generate IP4 ARP packets. */
  vlib_packet_template_t ip4_arp_request_packet_template;

  /** Feature path configuration lists */
  vnet_ip_feature_registration_t * next_uc_feature;
  vnet_ip_feature_registration_t * next_mc_feature;

  /** Built-in unicast feature path indice, see @ref ip_feature_init_cast()  */
  u32 ip4_unicast_rx_feature_check_access;
  /** Built-in unicast feature path indice, see @ref ip_feature_init_cast()  */
  u32 ip4_unicast_rx_feature_source_reachable_via_rx;
  /** Built-in unicast feature path indice, see @ref ip_feature_init_cast()  */
  u32 ip4_unicast_rx_feature_source_reachable_via_any;
  /** Built-in unicast feature path indice, see @ref ip_feature_init_cast()  */
  u32 ip4_unicast_rx_feature_policer_classify;
  /** Built-in unicast feature path indice, see @ref ip_feature_init_cast()  */
  u32 ip4_unicast_rx_feature_ipsec;
  /** Built-in unicast feature path indice, see @ref ip_feature_init_cast()  */
  u32 ip4_unicast_rx_feature_vpath;
  /** Built-in unicast feature path indice, see @ref ip_feature_init_cast()  */
  u32 ip4_unicast_rx_feature_lookup;
  /** Built-in unicast feature path indice, see @ref ip_feature_init_cast()  */
  u32 ip4_unicast_rx_feature_source_and_port_range_check;

  /** Built-in multicast feature path indices */
  u32 ip4_multicast_rx_feature_vpath;
  /** Built-in multicast feature path indices */
  u32 ip4_multicast_rx_feature_lookup;

  /** Save results for show command */
  char ** feature_nodes[VNET_N_CAST];

  /** Seed for Jenkins hash used to compute ip4 flow hash. */
  u32 flow_hash_seed;

  /** @brief Template information for VPP generated packets */
  struct {
    /** TTL to use for host generated packets. */
    u8 ttl;

    /** TOS byte to use for host generated packets. */
    u8 tos;

    u8 pad[2];
  } host_config;
} ip4_main_t;

/** Global ip4 main structure. */
extern ip4_main_t ip4_main;

#define VNET_IP4_UNICAST_FEATURE_INIT(x,...)                    \
  __VA_ARGS__ vnet_ip_feature_registration_t uc_##x;            \
static void __vnet_add_feature_registration_uc_##x (void)       \
  __attribute__((__constructor__)) ;                            \
static void __vnet_add_feature_registration_uc_##x (void)       \
{                                                               \
  ip4_main_t * im = &ip4_main;                                  \
  uc_##x.next = im->next_uc_feature;                            \
  im->next_uc_feature = &uc_##x;                                \
}                                                               \
__VA_ARGS__ vnet_ip_feature_registration_t uc_##x 

#define VNET_IP4_MULTICAST_FEATURE_INIT(x,...)                  \
  __VA_ARGS__ vnet_ip_feature_registration_t mc_##x;            \
static void __vnet_add_feature_registration_mc_##x (void)       \
  __attribute__((__constructor__)) ;                            \
static void __vnet_add_feature_registration_mc_##x (void)       \
{                                                               \
  ip4_main_t * im = &ip4_main;                                  \
  mc_##x.next = im->next_mc_feature;                            \
  im->next_mc_feature = &mc_##x;                                \
}                                                               \
__VA_ARGS__ vnet_ip_feature_registration_t mc_##x 


/** Global ip4 input node.  Errors get attached to ip4 input node. */
extern vlib_node_registration_t ip4_input_node;
extern vlib_node_registration_t ip4_lookup_node;
extern vlib_node_registration_t ip4_rewrite_node;
extern vlib_node_registration_t ip4_rewrite_local_node;
extern vlib_node_registration_t ip4_arp_node;

u32 ip4_fib_lookup_with_table (ip4_main_t * im, u32 fib_index, ip4_address_t * dst,
			       u32 disable_default_route);

always_inline u32
ip4_fib_lookup_buffer (ip4_main_t * im, u32 fib_index, ip4_address_t * dst,
		       vlib_buffer_t * b)
{
  return ip4_fib_lookup_with_table (im, fib_index, dst,
				    /* disable_default_route */ 0);
}

always_inline u32
ip4_fib_lookup (ip4_main_t * im, u32 sw_if_index, ip4_address_t * dst)
{
  u32 fib_index = vec_elt (im->fib_index_by_sw_if_index, sw_if_index);
  return ip4_fib_lookup_with_table (im, fib_index, dst,
				    /* disable_default_route */ 0);
}

always_inline uword
ip4_destination_matches_route (ip4_main_t * im,
			       ip4_address_t * key,
			       ip4_address_t * dest,
			       uword dest_length)
{ return 0 == ((key->data_u32 ^ dest->data_u32) & im->fib_masks[dest_length]); }

always_inline uword
ip4_destination_matches_interface (ip4_main_t * im,
				   ip4_address_t * key,
				   ip_interface_address_t * ia)
{
  ip4_address_t * a = ip_interface_address_get_address (&im->lookup_main, ia);
  return ip4_destination_matches_route (im, key, a, ia->address_length);
}

/* As above but allows for unaligned destinations (e.g. works right from IP header of packet). */
always_inline uword
ip4_unaligned_destination_matches_route (ip4_main_t * im,
					 ip4_address_t * key,
					 ip4_address_t * dest,
					 uword dest_length)
{ return 0 == ((clib_mem_unaligned (&key->data_u32, u32) ^ dest->data_u32) & im->fib_masks[dest_length]); }

always_inline int
ip4_src_address_for_packet (ip4_main_t * im, vlib_buffer_t * p, ip4_address_t * src, u32 sw_if_index)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_interface_address_t * ia = ip_interface_address_for_packet (lm, p, sw_if_index);
  if (ia == NULL)
    return -1;
  ip4_address_t * a = ip_interface_address_get_address (lm, ia);
  *src = a[0];
  return 0;
}

/* Find interface address which matches destination. */
always_inline ip4_address_t *
ip4_interface_address_matching_destination (ip4_main_t * im, ip4_address_t * dst, u32 sw_if_index,
					    ip_interface_address_t ** result_ia)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_interface_address_t * ia;
  ip4_address_t * result = 0;

  foreach_ip_interface_address (lm, ia, sw_if_index, 
                                1 /* honor unnumbered */,
  ({
    ip4_address_t * a = ip_interface_address_get_address (lm, ia);
    if (ip4_destination_matches_route (im, dst, a, ia->address_length))
      {
	result = a;
	break;
      }
  }));
  if (result_ia)
    *result_ia = result ? ia : 0;
  return result;
}

clib_error_t *
ip4_add_del_interface_address (vlib_main_t * vm, u32 sw_if_index,
			       ip4_address_t * address, u32 address_length,
			       u32 is_del);

int ip4_address_compare (ip4_address_t * a1, ip4_address_t * a2);

/* Add/del a route to the FIB. */

#define IP4_ROUTE_FLAG_ADD (0 << 0)
#define IP4_ROUTE_FLAG_DEL (1 << 0)
#define IP4_ROUTE_FLAG_TABLE_ID  (0 << 1)
#define IP4_ROUTE_FLAG_FIB_INDEX (1 << 1)
#define IP4_ROUTE_FLAG_KEEP_OLD_ADJACENCY (1 << 2)
#define IP4_ROUTE_FLAG_NO_REDISTRIBUTE (1 << 3)
/* Not last add/del in group.  Facilities batching requests into packets. */
#define IP4_ROUTE_FLAG_NOT_LAST_IN_GROUP (1 << 4)
/* Dynamic route created via ARP reply. */
#define IP4_ROUTE_FLAG_NEIGHBOR (1 << 5)

typedef struct {
  /* IP4_ROUTE_FLAG_* */
  u32 flags;

  /* Either index of fib or table_id to hash and get fib.
     IP4_ROUTE_FLAG_FIB_INDEX specifies index; otherwise table_id is assumed. */
  u32 table_index_or_table_id;

  /* Destination address (prefix) and length. */
  ip4_address_t dst_address;
  u32 dst_address_length;

  /* Adjacency to use for this destination. */
  u32 adj_index;

  /* If specified adjacencies to add and then
     use for this destination.  add_adj/n_add_adj
     are override adj_index if specified. */
  ip_adjacency_t * add_adj;
  u32 n_add_adj;
} ip4_add_del_route_args_t;

/**
 * \brief Get or create an IPv4 fib.
 *
 * Get or create an IPv4 fib with the provided fib ID or index.
 * The fib ID is a possibly-sparse user-defined value while
 * the fib index defines the position of the fib in the fib vector.
 *
 * \param im
 *      ip4_main pointer.
 * \param table_index_or_id
 *      The table index if \c IP4_ROUTE_FLAG_FIB_INDEX bit is set in \p flags.
 *      Otherwise, when set to \c ~0, an arbitrary and unused fib ID is picked
 *      and can be retrieved with \c ret->table_id.
 *      Otherwise, the fib ID to be used to retrieve or create the desired fib.
 * \param flags
 *      Indicates whether \p table_index_or_id is the fib index or ID.
 *      When the bit \c IP4_ROUTE_FLAG_FIB_INDEX is set, \p table_index_or_id
 *      is considered as the fib index, and the fib ID otherwise.
 * \returns A pointer to the retrieved or created fib.
 *
 * \remark When getting a fib with the fib index, the fib MUST already exist.
 */
ip4_fib_t *
find_ip4_fib_by_table_index_or_id (ip4_main_t * im, 
                                   u32 table_index_or_id, u32 flags);

void ip4_add_del_route (ip4_main_t * im, ip4_add_del_route_args_t * args);

void ip4_add_del_route_next_hop (ip4_main_t * im,
                                 u32 flags,
                                 ip4_address_t * dst_address,
                                 u32 dst_address_length,
                                 ip4_address_t * next_hop,
                                 u32 next_hop_sw_if_index,
                                 u32 next_hop_weight, u32 adj_index, 
                                 u32 explicit_fib_index);

u32
ip4_route_get_next_hop_adj (ip4_main_t * im,
			    u32 fib_index,
			    ip4_address_t *next_hop,
			    u32 next_hop_sw_if_index,
			    u32 explicit_fib_index);

void *
ip4_get_route (ip4_main_t * im,
	       u32 fib_index_or_table_id,
	       u32 flags,
	       u8 * address,
	       u32 address_length);

void
ip4_foreach_matching_route (ip4_main_t * im,
			    u32 table_index_or_table_id,
			    u32 flags,
			    ip4_address_t * address,
			    u32 address_length,
			    ip4_address_t ** results,
			    u8 ** result_lengths);

void ip4_delete_matching_routes (ip4_main_t * im,
				 u32 table_index_or_table_id,
				 u32 flags,
				 ip4_address_t * address,
				 u32 address_length);

void ip4_maybe_remap_adjacencies (ip4_main_t * im,
				  u32 table_index_or_table_id,
				  u32 flags);

void ip4_adjacency_set_interface_route (vnet_main_t * vnm,
					ip_adjacency_t * adj,
					u32 sw_if_index,
					u32 if_address_index);

ip4_address_t *
ip4_interface_first_address (ip4_main_t * im, u32 sw_if_index,
                             ip_interface_address_t ** result_ia);

/* Send an ARP request to see if given destination is reachable on given interface. */
clib_error_t *
ip4_probe_neighbor (vlib_main_t * vm, ip4_address_t * dst, u32 sw_if_index);

clib_error_t *
ip4_set_arp_limit (u32 arp_limit);

uword
ip4_udp_register_listener (vlib_main_t * vm,
			   u16 dst_port,
			   u32 next_node_index);

void 
ip4_icmp_register_type (vlib_main_t * vm, icmp4_type_t type, 
                        u32 node_index);

u16 ip4_tcp_udp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0, ip4_header_t * ip0);

void ip4_register_protocol (u32 protocol, u32 node_index);

serialize_function_t serialize_vnet_ip4_main, unserialize_vnet_ip4_main;

int vnet_set_ip4_flow_hash (u32 table_id, u32 flow_hash_config);

void ip4_mtrie_init (ip4_fib_mtrie_t * m);

int vnet_set_ip4_classify_intfc (vlib_main_t * vm, u32 sw_if_index, 
                                 u32 table_index);

/* Compute flow hash.  We'll use it to select which adjacency to use for this
   flow.  And other things. */
always_inline u32
ip4_compute_flow_hash (ip4_header_t * ip, u32 flow_hash_config)
{
    tcp_header_t * tcp = (void *) (ip + 1);
    u32 a, b, c, t1, t2;
    uword is_tcp_udp = (ip->protocol == IP_PROTOCOL_TCP
			|| ip->protocol == IP_PROTOCOL_UDP);

    t1 = (flow_hash_config & IP_FLOW_HASH_SRC_ADDR) 
        ? ip->src_address.data_u32 : 0;
    t2 = (flow_hash_config & IP_FLOW_HASH_DST_ADDR) 
        ? ip->dst_address.data_u32 : 0;
    
    a = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t2 : t1;
    b = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t1 : t2;
    b ^= (flow_hash_config & IP_FLOW_HASH_PROTO) ? ip->protocol : 0;

    t1 = is_tcp_udp ? tcp->ports.src : 0;
    t2 = is_tcp_udp ? tcp->ports.dst : 0;
    
    t1 = (flow_hash_config & IP_FLOW_HASH_SRC_PORT) ? t1 : 0;
    t2 = (flow_hash_config & IP_FLOW_HASH_DST_PORT) ? t2 : 0;

    c = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ?
        (t1<<16) | t2 : (t2<<16) | t1;

    hash_v3_mix32 (a, b, c);
    hash_v3_finalize32 (a, b, c);

    return c;
}

#endif /* included_ip_ip4_h */
