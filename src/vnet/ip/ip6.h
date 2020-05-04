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

#include <vlib/buffer.h>
#include <vnet/ethernet/packet.h>
#include <vnet/ethernet/mac_address.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/ip/ip46_address.h>
#include <vnet/ip/ip6_hop_by_hop_packet.h>
#include <vnet/ip/lookup.h>
#include <vnet/ip/ip_interface.h>
#include <stdbool.h>
#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_template.h>
#include <vnet/util/radix.h>
#include <vnet/util/throttle.h>

/*
 * Default size of the ip6 fib hash table
 */
#define IP6_FIB_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define IP6_FIB_DEFAULT_HASH_MEMORY_SIZE (32<<20)

typedef struct
{
  ip6_address_t addr;
  u32 dst_address_length;
  u32 vrf_index;
} ip6_fib_key_t;

typedef struct
{
  /* required for pool_get_aligned. */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Table ID (hash key) for this FIB. */
  u32 table_id;

  /* Index into FIB vector. */
  u32 index;
} ip6_fib_t;

typedef struct ip6_mfib_t
{
  /* required for pool_get_aligned. */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /* Table ID (hash key) for this FIB. */
  u32 table_id;

  /* Index into FIB vector. */
  u32 index;
} ip6_mfib_t;

struct ip6_main_t;

typedef void (ip6_add_del_interface_address_function_t)
  (struct ip6_main_t * im,
   uword opaque,
   u32 sw_if_index,
   ip6_address_t * address,
   u32 address_length, u32 if_address_index, u32 is_del);

typedef struct
{
  ip6_add_del_interface_address_function_t *function;
  uword function_opaque;
} ip6_add_del_interface_address_callback_t;

typedef void (ip6_table_bind_function_t)
  (struct ip6_main_t * im,
   uword opaque, u32 sw_if_index, u32 new_fib_index, u32 old_fib_index);

typedef struct
{
  ip6_table_bind_function_t *function;
  uword function_opaque;
} ip6_table_bind_callback_t;

/**
 * Enumeration of the FIB table instance types
 */
typedef enum ip6_fib_table_instance_type_t_
{
    /**
     * This table stores the routes that are used to forward traffic.
     * The key is the prefix, the result the adjacency to forward on.
     */
  IP6_FIB_TABLE_FWDING,
    /**
     * The table that stores ALL routes learned by the DP.
     * Some of these routes may not be ready to install in forwarding
     * at a given time.
     * The key in this table is the prefix, the result is the fib_entry_t
     */
  IP6_FIB_TABLE_NON_FWDING,
} ip6_fib_table_instance_type_t;

#define IP6_FIB_NUM_TABLES (IP6_FIB_TABLE_NON_FWDING+1)

/**
 * A representation of a single IP6 table
 */
typedef struct ip6_fib_table_instance_t_
{
  /* The hash table */
  clib_bihash_24_8_t ip6_hash;

  /* bitmap / refcounts / vector of mask widths to search */
  uword *non_empty_dst_address_length_bitmap;
  u8 *prefix_lengths_in_search_order;
  i32 dst_address_length_refcounts[129];
} ip6_fib_table_instance_t;

/**
 * A representation of a single IP6 mfib table
 */
typedef struct ip6_mfib_table_instance_t_
{
  /* The hash table */
  clib_bihash_40_8_t ip6_mhash;

  /* bitmap / refcounts / vector of mask widths to search */
  uword *non_empty_dst_address_length_bitmap;
  u16 *prefix_lengths_in_search_order;
  i32 dst_address_length_refcounts[257];
} ip6_mfib_table_instance_t;

typedef struct ip6_main_t
{
  /**
   * The two FIB tables; fwding and non-fwding
   */
  ip6_fib_table_instance_t ip6_table[IP6_FIB_NUM_TABLES];

  /**
   * the single MFIB table
   */
  ip6_mfib_table_instance_t ip6_mtable;

  ip_lookup_main_t lookup_main;

  /* Pool of FIBs. */
  struct fib_table_t_ *fibs;

  /* Pool of V6 FIBs. */
  ip6_fib_t *v6_fibs;

  /** Vector of MFIBs. */
  struct mfib_table_t_ *mfibs;

  /* Network byte orders subnet mask for each prefix length */
  ip6_address_t fib_masks[129];

  /* Table index indexed by software interface. */
  u32 *fib_index_by_sw_if_index;

  /** Table index indexed by software interface. */
  u32 *mfib_index_by_sw_if_index;

  /* IP6 enabled count by software interface */
  u8 *ip_enabled_by_sw_if_index;

  /* Hash table mapping table id to fib index.
     ID space is not necessarily dense; index space is dense. */
  uword *fib_index_by_table_id;

  /** Hash table mapping table id to multicast fib index.
     ID space is not necessarily dense; index space is dense. */
  uword *mfib_index_by_table_id;

  /* Hash table mapping interface rewrite adjacency index by sw if index. */
  uword *interface_route_adj_index_by_sw_if_index;

  /* Functions to call when interface address changes. */
    ip6_add_del_interface_address_callback_t
    * add_del_interface_address_callbacks;

  /** Functions to call when interface to table biding changes. */
  ip6_table_bind_callback_t *table_bind_callbacks;

  /* ip6 lookup table config parameters */
  u32 lookup_table_nbuckets;
  uword lookup_table_size;

  /* Seed for Jenkins hash used to compute ip6 flow hash. */
  u32 flow_hash_seed;

  struct
  {
    /* TTL to use for host generated packets. */
    u8 ttl;

    u8 pad[3];
  } host_config;

  /* HBH processing enabled? */
  u8 hbh_enabled;

  /** ND throttling */
  throttle_t nd_throttle;
} ip6_main_t;

#define ND_THROTTLE_BITS 512

/* Global ip6 main structure. */
extern ip6_main_t ip6_main;

/* Global ip6 input node.  Errors get attached to ip6 input node. */
extern vlib_node_registration_t ip6_input_node;
extern vlib_node_registration_t ip6_rewrite_node;
extern vlib_node_registration_t ip6_rewrite_mcast_node;
extern vlib_node_registration_t ip6_rewrite_local_node;
extern vlib_node_registration_t ip6_discover_neighbor_node;
extern vlib_node_registration_t ip6_glean_node;
extern vlib_node_registration_t ip6_midchain_node;
extern vlib_node_registration_t ip6_punt_node;

extern void ip6_forward_next_trace (vlib_main_t * vm,
				    vlib_node_runtime_t * node,
				    vlib_frame_t * frame,
				    vlib_rx_or_tx_t which_adj_index);

always_inline uword
ip6_destination_matches_route (const ip6_main_t * im,
			       const ip6_address_t * key,
			       const ip6_address_t * dest, uword dest_length)
{
  int i;
  for (i = 0; i < ARRAY_LEN (key->as_uword); i++)
    {
      if ((key->as_uword[i] ^ dest->as_uword[i]) & im->
	  fib_masks[dest_length].as_uword[i])
	return 0;
    }
  return 1;
}

always_inline uword
ip6_destination_matches_interface (ip6_main_t * im,
				   ip6_address_t * key,
				   ip_interface_address_t * ia)
{
  ip6_address_t *a = ip_interface_address_get_address (&im->lookup_main, ia);
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
      if ((clib_mem_unaligned (&key->as_uword[i], uword) ^ dest->as_uword[i])
	  & im->fib_masks[dest_length].as_uword[i])
	return 0;
    }
  return 1;
}

/* Find interface address which matches destination. */
always_inline ip6_address_t *
ip6_interface_address_matching_destination (ip6_main_t * im,
					    const ip6_address_t * dst,
					    u32 sw_if_index,
					    ip_interface_address_t **
					    result_ia)
{
  ip_lookup_main_t *lm = &im->lookup_main;
  ip_interface_address_t *ia;
  ip6_address_t *result = 0;

  /* *INDENT-OFF* */
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
  /* *INDENT-ON* */
  if (result_ia)
    *result_ia = result ? ia : 0;
  return result;
}

clib_error_t *ip6_add_del_interface_address (vlib_main_t * vm,
					     u32 sw_if_index,
					     ip6_address_t * address,
					     u32 address_length, u32 is_del);
void ip6_sw_interface_enable_disable (u32 sw_if_index, u32 is_enable);

/**
 * @brief get first IPv6 interface address
 */
ip6_address_t *ip6_interface_first_address (ip6_main_t * im, u32 sw_if_index);

int ip6_address_compare (ip6_address_t * a1, ip6_address_t * a2);

uword
ip6_udp_register_listener (vlib_main_t * vm,
			   u16 dst_port, u32 next_node_index);

u16 ip6_tcp_udp_icmp_compute_checksum (vlib_main_t * vm, vlib_buffer_t * p0,
				       ip6_header_t * ip0,
				       int *bogus_lengthp);

void ip6_register_protocol (u32 protocol, u32 node_index);
void ip6_unregister_protocol (u32 protocol);
void ip6_local_hop_by_hop_register_protocol (u32 protocol, u32 node_index);

serialize_function_t serialize_vnet_ip6_main, unserialize_vnet_ip6_main;

int vnet_set_ip6_flow_hash (u32 table_id,
			    flow_hash_config_t flow_hash_config);

u8 *format_ip6_forward_next_trace (u8 * s, va_list * args);

u32 ip6_tcp_udp_icmp_validate_checksum (vlib_main_t * vm, vlib_buffer_t * p0);

void ip6_punt_policer_add_del (u8 is_add, u32 policer_index);
void ip6_punt_redirect_add (u32 rx_sw_if_index,
			    u32 tx_sw_if_index, ip46_address_t * nh);
void ip6_punt_redirect_add_paths (u32 rx_sw_if_index,
				  fib_route_path_t * paths);
void ip6_punt_redirect_del (u32 rx_sw_if_index);

int vnet_set_ip6_classify_intfc (vlib_main_t * vm, u32 sw_if_index,
				 u32 table_index);
extern vlib_node_registration_t ip6_lookup_node;

/* Compute flow hash.  We'll use it to select which Sponge to use for this
   flow.  And other things. */
always_inline u32
ip6_compute_flow_hash (const ip6_header_t * ip,
		       flow_hash_config_t flow_hash_config)
{
  tcp_header_t *tcp;
  u64 a, b, c;
  u64 t1, t2;
  uword is_tcp_udp = 0;
  u8 protocol = ip->protocol;

  if (PREDICT_TRUE
      ((ip->protocol == IP_PROTOCOL_TCP)
       || (ip->protocol == IP_PROTOCOL_UDP)))
    {
      is_tcp_udp = 1;
      tcp = (void *) (ip + 1);
    }
  else if (ip->protocol == IP_PROTOCOL_IP6_HOP_BY_HOP_OPTIONS)
    {
      ip6_hop_by_hop_header_t *hbh = (ip6_hop_by_hop_header_t *) (ip + 1);
      if ((hbh->protocol == IP_PROTOCOL_TCP) ||
	  (hbh->protocol == IP_PROTOCOL_UDP))
	{
	  is_tcp_udp = 1;
	  tcp = (tcp_header_t *) ((u8 *) hbh + ((hbh->length + 1) << 3));
	}
      protocol = hbh->protocol;
    }

  t1 = (ip->src_address.as_u64[0] ^ ip->src_address.as_u64[1]);
  t1 = (flow_hash_config & IP_FLOW_HASH_SRC_ADDR) ? t1 : 0;

  t2 = (ip->dst_address.as_u64[0] ^ ip->dst_address.as_u64[1]);
  t2 = (flow_hash_config & IP_FLOW_HASH_DST_ADDR) ? t2 : 0;

  a = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t2 : t1;
  b = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ? t1 : t2;

  t1 = is_tcp_udp ? tcp->src : 0;
  t2 = is_tcp_udp ? tcp->dst : 0;

  t1 = (flow_hash_config & IP_FLOW_HASH_SRC_PORT) ? t1 : 0;
  t2 = (flow_hash_config & IP_FLOW_HASH_DST_PORT) ? t2 : 0;

  if (flow_hash_config & IP_FLOW_HASH_SYMMETRIC)
    {
      if (b < a)
	{
	  c = a;
	  a = b;
	  b = c;
	}
      if (t2 < t1)
	{
	  t2 += t1;
	  t1 = t2 - t1;
	  t2 = t2 - t1;
	}
    }

  b ^= (flow_hash_config & IP_FLOW_HASH_PROTO) ? protocol : 0;
  c = (flow_hash_config & IP_FLOW_HASH_REVERSE_SRC_DST) ?
    ((t1 << 16) | t2) : ((t2 << 16) | t1);

  hash_mix64 (a, b, c);
  return (u32) c;
}

/* ip6_locate_header
 *
 * This function is to search for the header specified by the protocol number
 * in find_hdr_type.
 * This is used to locate a specific IPv6 extension header
 * or to find transport layer header.
 *   1. If the find_hdr_type < 0 then it finds and returns the protocol number and
 *   offset stored in *offset of the transport or ESP header in the chain if
 *   found.
 *   2. If a header with find_hdr_type > 0 protocol number is found then the
 *      offset is stored in *offset and protocol number of the header is
 *      returned.
 *   3. If find_hdr_type is not found or packet is malformed or
 *      it is a non-first fragment -1 is returned.
 */
always_inline int
ip6_locate_header (vlib_buffer_t * p0,
		   ip6_header_t * ip0, int find_hdr_type, u32 * offset)
{
  u8 next_proto = ip0->protocol;
  u8 *next_header;
  u8 done = 0;
  u32 cur_offset;
  u8 *temp_nxthdr = 0;
  u32 exthdr_len = 0;

  next_header = ip6_next_header (ip0);
  cur_offset = sizeof (ip6_header_t);
  while (1)
    {
      done = (next_proto == find_hdr_type);
      if (PREDICT_FALSE
	  (next_header >=
	   (u8 *) vlib_buffer_get_current (p0) + p0->current_length))
	{
	  //A malicious packet could set an extension header with a too big size
	  return (-1);
	}
      if (done)
	break;
      if ((!ip6_ext_hdr (next_proto)) || next_proto == IP_PROTOCOL_IP6_NONXT)
	{
	  if (find_hdr_type < 0)
	    break;
	  return -1;
	}
      if (next_proto == IP_PROTOCOL_IPV6_FRAGMENTATION)
	{
	  ip6_frag_hdr_t *frag_hdr = (ip6_frag_hdr_t *) next_header;
	  u16 frag_off = ip6_frag_hdr_offset (frag_hdr);
	  /* Non first fragment return -1 */
	  if (frag_off)
	    return (-1);
	  exthdr_len = sizeof (ip6_frag_hdr_t);
	  temp_nxthdr = next_header + exthdr_len;
	}
      else if (next_proto == IP_PROTOCOL_IPSEC_AH)
	{
	  exthdr_len =
	    ip6_ext_authhdr_len (((ip6_ext_header_t *) next_header));
	  temp_nxthdr = next_header + exthdr_len;
	}
      else
	{
	  exthdr_len =
	    ip6_ext_header_len (((ip6_ext_header_t *) next_header));
	  temp_nxthdr = next_header + exthdr_len;
	}
      next_proto = ((ip6_ext_header_t *) next_header)->next_hdr;
      next_header = temp_nxthdr;
      cur_offset += exthdr_len;
    }

  *offset = cur_offset;
  return (next_proto);
}

u8 *format_ip6_hop_by_hop_ext_hdr (u8 * s, va_list * args);
/*
 * Hop-by-Hop handling
 */
typedef struct
{
  /* Array of function pointers to HBH option handling routines */
  int (*options[256]) (vlib_buffer_t * b, ip6_header_t * ip,
		       ip6_hop_by_hop_option_t * opt);
  u8 *(*trace[256]) (u8 * s, ip6_hop_by_hop_option_t * opt);
  uword next_override;
} ip6_hop_by_hop_main_t;

extern ip6_hop_by_hop_main_t ip6_hop_by_hop_main;

int ip6_hbh_register_option (u8 option,
			     int options (vlib_buffer_t * b,
					  ip6_header_t * ip,
					  ip6_hop_by_hop_option_t * opt),
			     u8 * trace (u8 * s,
					 ip6_hop_by_hop_option_t * opt));
int ip6_hbh_unregister_option (u8 option);
void ip6_hbh_set_next_override (uword next);

/**
 * Push IPv6 header to buffer
 *
 * @param vm - vlib_main
 * @param b - buffer to write the header to
 * @param src - source IP
 * @param dst - destination IP
 * @param prot - payload proto
 * @param flow_label - flow label
 *
 * @return - pointer to start of IP header
 */
always_inline void *
vlib_buffer_push_ip6_custom (vlib_main_t * vm, vlib_buffer_t * b,
			     ip6_address_t * src, ip6_address_t * dst,
			     int proto, u32 flow_label)
{
  ip6_header_t *ip6h;
  u16 payload_length;

  /* make some room */
  ip6h = vlib_buffer_push_uninit (b, sizeof (ip6_header_t));
  ASSERT (flow_label < 1 << 20);
  ip6h->ip_version_traffic_class_and_flow_label =
    clib_host_to_net_u32 ((0x6 << 28) | flow_label);

  /* calculate ip6 payload length */
  payload_length = vlib_buffer_length_in_chain (vm, b);
  payload_length -= sizeof (*ip6h);

  ip6h->payload_length = clib_host_to_net_u16 (payload_length);

  ip6h->hop_limit = 0xff;
  ip6h->protocol = proto;
  clib_memcpy_fast (ip6h->src_address.as_u8, src->as_u8,
		    sizeof (ip6h->src_address));
  clib_memcpy_fast (ip6h->dst_address.as_u8, dst->as_u8,
		    sizeof (ip6h->src_address));
  vnet_buffer (b)->l3_hdr_offset = (u8 *) ip6h - b->data;
  b->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID;

  return ip6h;
}

/**
 * Push IPv6 header to buffer
 *
 * @param vm - vlib_main
 * @param b - buffer to write the header to
 * @param src - source IP
 * @param dst - destination IP
 * @param prot - payload proto
 *
 * @return - pointer to start of IP header
 */
always_inline void *
vlib_buffer_push_ip6 (vlib_main_t * vm, vlib_buffer_t * b,
		      ip6_address_t * src, ip6_address_t * dst, int proto)
{
  return vlib_buffer_push_ip6_custom (vm, b, src, dst, proto,
				      0 /* flow label */ );

}

always_inline u32
vlib_buffer_get_ip6_fib_index (vlib_buffer_t * b)
{
  u32 fib_index, sw_if_index;
  sw_if_index = vnet_buffer (b)->sw_if_index[VLIB_RX];
  fib_index = vnet_buffer (b)->sw_if_index[VLIB_TX];
  return (fib_index == (u32) ~ 0) ?
    vec_elt (ip6_main.fib_index_by_sw_if_index, sw_if_index) : fib_index;
}
#endif /* included_ip_ip6_h */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
