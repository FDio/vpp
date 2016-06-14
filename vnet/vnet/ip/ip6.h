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
 * ip/ip6.h: ip6 main include file
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

#ifndef included_ip_ip6_h
#define included_ip_ip6_h

#include <vlib/mc.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <vnet/ip/lookup.h>
#include <stdbool.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.h>

/*
 * Default size of the ip6 fib hash table
 */
#define IP6_FIB_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define IP6_FIB_DEFAULT_HASH_MEMORY_SIZE (32<<20)

typedef struct {
  ip6_address_t addr;
  u32 dst_address_length;
  u32 vrf_index;
} ip6_fib_key_t;

typedef struct {
  /* Table ID (hash key) for this FIB. */
  u32 table_id;

  /* Index into FIB vector. */
  u32 index;

  /* flow hash configuration */
  u32 flow_hash_config;
} ip6_fib_t;

struct ip6_main_t;

typedef void (ip6_add_del_route_function_t)
  (struct ip6_main_t * im,
   uword opaque,
   ip6_fib_t * fib,
   u32 flags,
   ip6_address_t * address,
   u32 address_length,
   void * old_result,
   void * new_result);

typedef struct {
  ip6_add_del_route_function_t * function;
  uword required_flags;
  uword function_opaque;
} ip6_add_del_route_callback_t;

typedef void (ip6_add_del_interface_address_function_t)
  (struct ip6_main_t * im,
   uword opaque,
   u32 sw_if_index,
   ip6_address_t * address,
   u32 address_length,
   u32 if_address_index,
   u32 is_del);

typedef struct {
  ip6_add_del_interface_address_function_t * function;
  uword function_opaque;
} ip6_add_del_interface_address_callback_t;

typedef struct ip6_main_t {
  BVT(clib_bihash) ip6_lookup_table;

  ip_lookup_main_t lookup_main;

  /* bitmap / refcounts / vector of mask widths to search */
  uword * non_empty_dst_address_length_bitmap;
  u8 * prefix_lengths_in_search_order;
  i32 dst_address_length_refcounts[129];
  
  /* Vector of FIBs. */
  ip6_fib_t * fibs;

  ip6_address_t fib_masks[129];

  /* Table index indexed by software interface. */
  u32 * fib_index_by_sw_if_index;

  /* Hash table mapping table id to fib index.
     ID space is not necessarily dense; index space is dense. */
  uword * fib_index_by_table_id;

  /* Vector of functions to call when routes are added/deleted. */
  ip6_add_del_route_callback_t * add_del_route_callbacks;

  /* Hash table mapping interface rewrite adjacency index by sw if index. */
  uword * interface_route_adj_index_by_sw_if_index;

  /* Functions to call when interface address changes. */
  ip6_add_del_interface_address_callback_t * add_del_interface_address_callbacks;

  /* Template used to generate IP6 neighbor solicitation packets. */
  vlib_packet_template_t discover_neighbor_packet_template;

  /* ip6 lookup table config parameters */
  u32 lookup_table_nbuckets;
  uword lookup_table_size;

  /* feature path configuration lists */
  vnet_ip_feature_registration_t * next_uc_feature;
  vnet_ip_feature_registration_t * next_mc_feature;

  /* Built-in unicast feature path indices, see ip_feature_init_cast(...)  */
  u32 ip6_unicast_rx_feature_check_access;
  u32 ip6_unicast_rx_feature_ipsec;
  u32 ip6_unicast_rx_feature_l2tp_decap;
  u32 ip6_unicast_rx_feature_vpath;
  u32 ip6_unicast_rx_feature_lookup;

  /* Built-in multicast feature path indices */
  u32 ip6_multicast_rx_feature_vpath;
  u32 ip6_multicast_rx_feature_lookup;

  /* Seed for Jenkins hash used to compute ip6 flow hash. */
  u32 flow_hash_seed;

  struct {
    /* TTL to use for host generated packets. */
    u8 ttl;

    u8 pad[3];
  } host_config;

  /* HBH processing enabled? */
  u8 hbh_enabled;
} ip6_main_t;

/* Global ip6 main structure. */
extern ip6_main_t ip6_main;

#define VNET_IP6_UNICAST_FEATURE_INIT(x,...)                    \
  __VA_ARGS__ vnet_ip_feature_registration_t uc_##x;            \
static void __vnet_add_feature_registration_uc_##x (void)       \
  __attribute__((__constructor__)) ;                            \
static void __vnet_add_feature_registration_uc_##x (void)       \
{                                                               \
  ip6_main_t * im = &ip6_main;                                  \
  uc_##x.next = im->next_uc_feature;                            \
  im->next_uc_feature = &uc_##x;                                \
}                                                               \
__VA_ARGS__ vnet_ip_feature_registration_t uc_##x 

#define VNET_IP6_MULTICAST_FEATURE_INIT(x,...)                  \
  __VA_ARGS__ vnet_ip_feature_registration_t mc_##x;            \
static void __vnet_add_feature_registration_mc_##x (void)       \
  __attribute__((__constructor__)) ;                            \
static void __vnet_add_feature_registration_mc_##x (void)       \
{                                                               \
  ip6_main_t * im = &ip6_main;                                  \
  mc_##x.next = im->next_mc_feature;                            \
  im->next_mc_feature = &mc_##x;                                \
}                                                               \
__VA_ARGS__ vnet_ip_feature_registration_t mc_##x 

/* Global ip6 input node.  Errors get attached to ip6 input node. */
extern vlib_node_registration_t ip6_input_node;
extern vlib_node_registration_t ip6_rewrite_node;
extern vlib_node_registration_t ip6_rewrite_local_node;
extern vlib_node_registration_t ip6_discover_neighbor_node;

extern vlib_node_registration_t ip6_icmp_neighbor_discovery_event_node;

/* ipv6 neighbor discovery - timer/event types */
typedef enum {
  ICMP6_ND_EVENT_INIT,
} ip6_icmp_neighbor_discovery_event_type_t;

typedef union {
  u32 add_del_swindex;
  struct {
    u32 up_down_swindex;
    u32 fib_index;
  } up_down_event;
} ip6_icmp_neighbor_discovery_event_data_t;

u32 ip6_fib_lookup (ip6_main_t * im, u32 sw_if_index, ip6_address_t * dst);
u32 ip6_fib_lookup_with_table (ip6_main_t * im, u32 fib_index, 
                               ip6_address_t * dst);

/**
 * \brief Get or create an IPv6 fib.
 *
 * Get or create an IPv6 fib with the provided fib ID or index.
 * The fib ID is a possibly-sparse user-defined value while
 * the fib index defines the position of the fib in the fib vector.
 *
 * \param im
 *      ip6_main pointer.
 * \param table_index_or_id
 *      The table index if \c IP6_ROUTE_FLAG_FIB_INDEX bit is set in \p flags.
 *      Otherwise, when set to \c ~0, an arbitrary and unused fib ID is picked
 *      and can be retrieved with \c ret->table_id.
 *      Otherwise, it is the fib ID to be used to retrieve or create the desired fib.
 * \param flags
 *      Indicates whether \p table_index_or_id is the fib index or ID.
 *      When the bit \c IP6_ROUTE_FLAG_FIB_INDEX is set, \p table_index_or_id
 *      is considered as the fib index, and the fib ID otherwise.
 * \return A pointer to the retrieved or created fib.
 *
 * \remark When getting a fib with the fib index, the fib MUST already exist.
 */
ip6_fib_t * find_ip6_fib_by_table_index_or_id (ip6_main_t * im, 
                                               u32 table_index_or_id, 
                                               u32 flags);

always_inline uword
ip6_destination_matches_route (ip6_main_t * im,
			       ip6_address_t * key,
			       ip6_address_t * dest,
			       uword dest_length)
{
  int i;
  for (i = 0; i < ARRAY_LEN (key->as_uword); i++)
    {
      if ((key->as_uword[i] ^ dest->as_uword[i]) & im->fib_masks[dest_length].as_uword[i])
	return 0;
    }
  return 1;
}

always_inline uword
ip6_destination_matches_interface (ip6_main_t * im,
				   ip6_address_t * key,
				   ip_interface_address_t * ia)
{
  ip6_address_t * a = ip_interface_address_get_address (&im->lookup_main, ia);
  return ip6_destination_matches_route (im, key, a, ia->address_length);
}

/* As above but allows for unaligned destinations (e.g. works right from IP header of packet). */
always_inline uword
ip6_unaligned_destination_matches_route (ip6_main_t * im,
					 ip6_address_t * key,
					 ip6_address_t * dest,
					 uword dest_length)
{
  int i;
  for (i = 0; i < ARRAY_LEN (key->as_uword); i++)
    {
      if ((clib_mem_unaligned (&key->as_uword[i], uword) ^ dest->as_uword[i]) & im->fib_masks[dest_length].as_uword[i])
	return 0;
    }
  return 1;
}

always_inline void
ip6_src_address_for_packet (ip6_main_t * im, vlib_buffer_t * p, ip6_address_t * src, u32 sw_if_index)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_interface_address_t * ia = ip_interface_address_for_packet (lm, p, sw_if_index);
  ip6_address_t * a = ip_interface_address_get_address (lm, ia);
  *src = a[0];
}

always_inline u32
ip6_src_lookup_for_packet (ip6_main_t * im, vlib_buffer_t * b, ip6_header_t * i)
{
  if (vnet_buffer (b)->ip.adj_index[VLIB_RX] == ~0)
    vnet_buffer (b)->ip.adj_index[VLIB_RX]
      = ip6_fib_lookup (im, vnet_buffer (b)->sw_if_index[VLIB_RX],
			&i->src_address);
  return vnet_buffer (b)->ip.adj_index[VLIB_RX];
}

/* Find interface address which matches destination. */
always_inline ip6_address_t *
ip6_interface_address_matching_destination (ip6_main_t * im, ip6_address_t * dst, u32 sw_if_index,
					    ip_interface_address_t ** result_ia)
{
  ip_lookup_main_t * lm = &im->lookup_main;
  ip_interface_address_t * ia;
  ip6_address_t * result = 0;

  foreach_ip_interface_address (lm, ia, sw_if_index, 
                                1 /* honor unnumbered */,
  ({
    ip6_address_t * a = ip_interface_address_get_address (lm, ia);
    if (ip6_destination_matches_route (im, dst, a, ia->address_length))
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
ip6_add_del_interface_address (vlib_main_t * vm, u32 sw_if_index,
			       ip6_address_t * address, u32 address_length,
			       u32 is_del);

int ip6_address_compare (ip6_address_t * a1, ip6_address_t * a2);

/* Add/del a route to the FIB. */

#define IP6_ROUTE_FLAG_ADD (0 << 0)
#define IP6_ROUTE_FLAG_DEL (1 << 0)
#define IP6_ROUTE_FLAG_TABLE_ID  (0 << 1)
#define IP6_ROUTE_FLAG_FIB_INDEX (1 << 1)
#define IP6_ROUTE_FLAG_KEEP_OLD_ADJACENCY (1 << 2)
#define IP6_ROUTE_FLAG_NO_REDISTRIBUTE (1 << 3)
#define IP6_ROUTE_FLAG_NOT_LAST_IN_GROUP (1 << 4)
/* Dynamic route created via neighbor discovery. */
#define IP6_ROUTE_FLAG_NEIGHBOR (1 << 5)

typedef struct {
  /* IP6_ROUTE_FLAG_* */
  u32 flags;

  /* Either index of fib or table_id to hash and get fib.
     IP6_ROUTE_FLAG_FIB_INDEX specifies index; otherwise table_id is assumed. */
  u32 table_index_or_table_id;

  /* Destination address (prefix) and length. */
  ip6_address_t dst_address;
  u32 dst_address_length;

  /* Adjacency to use for this destination. */
  u32 adj_index;

  /* If specified adjacencies to add and then
     use for this destination.  add_adj/n_add_adj
     are override adj_index if specified. */
  ip_adjacency_t * add_adj;
  u32 n_add_adj;
} ip6_add_del_route_args_t;

void ip6_add_del_route (ip6_main_t * im, ip6_add_del_route_args_t * args);

void ip6_add_del_route_next_hop (ip6_main_t * im,
				 u32 flags,
				 ip6_address_t * dst_address,
				 u32 dst_address_length,
				 ip6_address_t * next_hop,
				 u32 next_hop_sw_if_index,
				 u32 next_hop_weight, u32 adj_index,
                                 u32 explicit_fib_index);
u32
ip6_get_route (ip6_main_t * im,
	       u32 fib_index_or_table_id,
	       u32 flags,
	       ip6_address_t * address,
	       u32 address_length);

void
ip6_foreach_matching_route (ip6_main_t * im,
			    u32 table_index_or_table_id,
			    u32 flags,
			    ip6_address_t * address,
			    u32 address_length,
			    ip6_address_t ** results,
			    u8 ** result_length);

void ip6_delete_matching_routes (ip6_main_t * im,
				 u32 table_index_or_table_id,
				 u32 flags,
				 ip6_address_t * address,
				 u32 address_length);

void ip6_maybe_remap_adjacencies (ip6_main_t * im,
				  u32 table_index_or_table_id,
				  u32 flags);

void ip6_adjacency_set_interface_route (vnet_main_t * vnm,
					ip_adjacency_t * adj,
					u32 sw_if_index,
					u32 if_address_index);

u32
vnet_ip6_neighbor_glean_add(u32 fib_index, void * next_hop_arg);

clib_error_t *
ip6_probe_neighbor (vlib_main_t * vm, ip6_address_t * dst, u32 sw_if_index);

clib_error_t *
ip6_set_neighbor_limit (u32 neighbor_limit);

uword
ip6_udp_register_listener (vlib_main_t * vm,
			   u16 dst_port,
			   u32 next_node_index);

u16 ip6_tcp_udp_icmp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0, ip6_header_t * ip0, int *bogus_lengthp);

void ip6_register_protocol (u32 protocol, u32 node_index);

serialize_function_t serialize_vnet_ip6_main, unserialize_vnet_ip6_main;

int
vnet_set_ip6_ethernet_neighbor (vlib_main_t * vm,
                                u32 sw_if_index,
                                ip6_address_t * a,
                                u8 * link_layer_address,
                                uword n_bytes_link_layer_address,
                                int is_static);
int
vnet_unset_ip6_ethernet_neighbor (vlib_main_t * vm,
                                  u32 sw_if_index,
                                  ip6_address_t * a,
                                  u8 * link_layer_address,
                                  uword n_bytes_link_layer_address);
void
vnet_ip6_fib_init (ip6_main_t * im, u32 fib_index);

void 
ip6_link_local_address_from_ethernet_mac_address (ip6_address_t *ip,
                                                  u8 *mac);

void 
ip6_ethernet_mac_address_from_link_local_address (u8 *mac, 
                                                  ip6_address_t *ip);

int vnet_set_ip6_flow_hash (u32 table_id, u32 flow_hash_config);

int
ip6_neighbor_ra_config(vlib_main_t * vm, u32 sw_if_index, 
		       u8 surpress, u8 managed, u8 other,
		       u8 ll_option,  u8 send_unicast,  u8 cease, 
		       u8 use_lifetime,  u32 lifetime,
		       u32 initial_count,  u32 initial_interval,  
		       u32 max_interval,  u32 min_interval,
		       u8 is_no);

int
ip6_neighbor_ra_prefix(vlib_main_t * vm, u32 sw_if_index,  
		       ip6_address_t *prefix_addr,  u8 prefix_len,
		       u8 use_default,  u32 val_lifetime, u32 pref_lifetime,
		       u8 no_advertise,  u8 off_link, u8 no_autoconfig, u8 no_onlink,
		       u8 is_no);


clib_error_t *
enable_ip6_interface(vlib_main_t * vm,
		     u32 sw_if_index);

clib_error_t * 
disable_ip6_interface(vlib_main_t * vm,
		     u32 sw_if_index);

int
ip6_interface_enabled(vlib_main_t * vm,
                      u32 sw_if_index);

clib_error_t *
set_ip6_link_local_address(vlib_main_t * vm,
			   u32 sw_if_index,
			   ip6_address_t *address,
			   u8 address_length);

void vnet_register_ip6_neighbor_resolution_event(vnet_main_t * vnm, 
                                                 void * address_arg,
                                                 uword node_index,
                                                 uword type_opaque,
                                                 uword data);

int vnet_set_ip6_classify_intfc (vlib_main_t * vm, u32 sw_if_index, 
                                 u32 table_index);
extern vlib_node_registration_t ip6_lookup_node;

/* Compute flow hash.  We'll use it to select which Sponge to use for this
   flow.  And other things. */
always_inline u32
ip6_compute_flow_hash (ip6_header_t * ip, u32 flow_hash_config)
{
    tcp_header_t * tcp = (void *) (ip + 1);
    u64 a, b, c;
    u64 t1, t2;
    uword is_tcp_udp = (ip->protocol == IP_PROTOCOL_TCP
			|| ip->protocol == IP_PROTOCOL_UDP);

    t1 = (ip->src_address.as_u64[0] ^ ip->src_address.as_u64[1]);
    t1 = (flow_hash_config & IP_FLOW_HASH_SRC_ADDR) ? t1 : 0;
    
    t2 = (ip->dst_address.as_u64[0] ^ ip->dst_address.as_u64[1]);
    t2 = (flow_hash_config & IP_FLOW_HASH_DST_ADDR) ? t2 : 0;
    
    a = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t2 : t1;
    b = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t1 : t2;
    b ^= (flow_hash_config & IP_FLOW_HASH_PROTO) ? ip->protocol : 0;

    t1 = is_tcp_udp ? tcp->ports.src : 0;
    t2 = is_tcp_udp ? tcp->ports.dst : 0;

    t1 = (flow_hash_config & IP_FLOW_HASH_SRC_PORT) ? t1 : 0;
    t2 = (flow_hash_config & IP_FLOW_HASH_DST_PORT) ? t2 : 0;
    
    c = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ?
        ((t1<<16) | t2) : ((t2<<16) | t1);

    hash_mix64 (a, b, c);
    return (u32) c;
}

/*
 * Hop-by-Hop handling
 */
typedef struct {
  /* Array of function pointers to HBH option handling routines */
  int (*options[256])(vlib_buffer_t *b, ip6_header_t *ip, ip6_hop_by_hop_option_t *opt);
  u8 *(*trace[256])(u8 *s, ip6_hop_by_hop_option_t *opt);
} ip6_hop_by_hop_main_t;

extern ip6_hop_by_hop_main_t ip6_hop_by_hop_main;

int ip6_hbh_register_option (u8 option,
			     int options(vlib_buffer_t *b, ip6_header_t *ip, ip6_hop_by_hop_option_t *opt),
			     u8 *trace(u8 *s, ip6_hop_by_hop_option_t *opt));
int ip6_hbh_unregister_option (u8 option);

/* Flag used by IOAM code. Classifier sets it pop-hop-by-hop checks it */
#define OI_DECAP   100

#endif /* included_ip_ip6_h */
