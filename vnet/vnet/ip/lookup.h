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
 * ip/ip_lookup.h: ip (4 or 6) lookup structures, adjacencies, ...
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

#include <vnet/vnet.h>
#include <vlib/buffer.h>
#include <vnet/ip/ip4_packet.h>
#include <vnet/ip/ip6_packet.h>
#include <vnet/fib/fib_node.h>
#include <vnet/dpo/dpo.h>
#include <vnet/ip/ip_feature_registration.h>

/** @brief Common (IP4/IP6) next index stored in adjacency. */
typedef enum {
  /** Adjacency to drop this packet. */
  IP_LOOKUP_NEXT_DROP,
  /** Adjacency to punt this packet. */
  IP_LOOKUP_NEXT_PUNT,

  /** This packet is for one of our own IP addresses. */
  IP_LOOKUP_NEXT_LOCAL,

  /** This packet matches an "incomplete adjacency" and packets
     need to be passed to ARP to find rewrite string for
     this destination. */
  IP_LOOKUP_NEXT_ARP,

  /** This packet matches an "interface route" and packets
     need to be passed to ARP to find rewrite string for
     this destination. */
  IP_LOOKUP_NEXT_GLEAN,

  /** This packet is to be rewritten and forwarded to the next
     processing node.  This is typically the output interface but
     might be another node for further output processing. */
  IP_LOOKUP_NEXT_REWRITE,

  /** This packets follow a load-balance */
  IP_LOOKUP_NEXT_LOAD_BALANCE,

  /** This packets follow a mid-chain adjacency */
  IP_LOOKUP_NEXT_MIDCHAIN,

  /** This packets needs to go to ICMP error */
  IP_LOOKUP_NEXT_ICMP_ERROR,

  IP_LOOKUP_N_NEXT,
} ip_lookup_next_t;

typedef enum {
  IP4_LOOKUP_N_NEXT = IP_LOOKUP_N_NEXT,
} ip4_lookup_next_t;

typedef enum {
  /* Hop-by-hop header handling */
  IP6_LOOKUP_NEXT_HOP_BY_HOP = IP_LOOKUP_N_NEXT,
  IP6_LOOKUP_NEXT_ADD_HOP_BY_HOP,
  IP6_LOOKUP_NEXT_POP_HOP_BY_HOP,
  IP6_LOOKUP_N_NEXT,
} ip6_lookup_next_t;

#define IP4_LOOKUP_NEXT_NODES {					\
    [IP_LOOKUP_NEXT_DROP] = "ip4-drop",				\
    [IP_LOOKUP_NEXT_PUNT] = "ip4-punt",				\
    [IP_LOOKUP_NEXT_LOCAL] = "ip4-local",			\
    [IP_LOOKUP_NEXT_ARP] = "ip4-arp",				\
    [IP_LOOKUP_NEXT_GLEAN] = "ip4-glean",			\
    [IP_LOOKUP_NEXT_REWRITE] = "ip4-rewrite-transit",		\
    [IP_LOOKUP_NEXT_MIDCHAIN] = "ip4-midchain",		        \
    [IP_LOOKUP_NEXT_LOAD_BALANCE] = "ip4-load-balance",		\
    [IP_LOOKUP_NEXT_ICMP_ERROR] = "ip4-icmp-error",		\
}

#define IP6_LOOKUP_NEXT_NODES {					\
    [IP_LOOKUP_NEXT_DROP] = "ip6-drop",				\
    [IP_LOOKUP_NEXT_PUNT] = "ip6-punt",				\
    [IP_LOOKUP_NEXT_LOCAL] = "ip6-local",			\
    [IP_LOOKUP_NEXT_ARP] = "ip6-discover-neighbor",		\
    [IP_LOOKUP_NEXT_GLEAN] = "ip6-glean",			\
    [IP_LOOKUP_NEXT_REWRITE] = "ip6-rewrite",			\
    [IP_LOOKUP_NEXT_MIDCHAIN] = "ip6-midchain",			\
    [IP_LOOKUP_NEXT_LOAD_BALANCE] = "ip6-load-balance",		\
    [IP_LOOKUP_NEXT_ICMP_ERROR] = "ip6-icmp-error",		\
    [IP6_LOOKUP_NEXT_HOP_BY_HOP] = "ip6-hop-by-hop",		\
    [IP6_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip6-add-hop-by-hop",	\
    [IP6_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip6-pop-hop-by-hop",	\
}

/** Flow hash configuration */
#define IP_FLOW_HASH_SRC_ADDR (1<<0)
#define IP_FLOW_HASH_DST_ADDR (1<<1)
#define IP_FLOW_HASH_PROTO (1<<2)
#define IP_FLOW_HASH_SRC_PORT (1<<3)
#define IP_FLOW_HASH_DST_PORT (1<<4)
#define IP_FLOW_HASH_REVERSE_SRC_DST (1<<5)

/** Default: 5-tuple without the "reverse" bit */
#define IP_FLOW_HASH_DEFAULT (0x1F)

#define foreach_flow_hash_bit                   \
_(src, IP_FLOW_HASH_SRC_ADDR)                   \
_(dst, IP_FLOW_HASH_DST_ADDR)                   \
_(sport, IP_FLOW_HASH_SRC_PORT)                 \
_(dport, IP_FLOW_HASH_DST_PORT)                 \
_(proto, IP_FLOW_HASH_PROTO)	                \
_(reverse, IP_FLOW_HASH_REVERSE_SRC_DST)

/**
 * A flow hash configuration is a mask of the flow hash options
 */
typedef u32 flow_hash_config_t;

/**
 * Forward delcartion
 */
struct ip_adjacency_t_;

/**
 * @brief A function type for post-rewrite fixups on midchain adjacency
 */
typedef void (*adj_midchain_fixup_t)(vlib_main_t * vm,
				     struct ip_adjacency_t_ *adj,
				     vlib_buffer_t * b0);

/** @brief IP unicast adjacency.
    @note cache aligned.
*/
typedef struct ip_adjacency_t_ {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

  /** Number of adjecencies in block.  Greater than 1 means multipath;
     otherwise equal to 1. */
  u16 n_adj;

  /** Next hop after ip4-lookup. */
  union {
    ip_lookup_next_t lookup_next_index : 16;
    u16 lookup_next_index_as_int;
  };

  /** Interface address index for this local/arp adjacency. */
  u32 if_address_index;

  /** Force re-lookup in a different FIB. ~0 => normal behavior */
  u16 mcast_group_index;  

  /** Highest possible perf subgraph arc interposition, e.g. for ip6 ioam */
  u16 saved_lookup_next_index;

  /*
   * link/ether-type
   */
  u8 ia_link;
  u8 ia_nh_proto;

  union {
    /**
     * IP_LOOKUP_NEXT_ARP/IP_LOOKUP_NEXT_REWRITE
     *
     * neighbour adjacency sub-type;
     */
      struct {
	  ip46_address_t next_hop;
      } nbr;
      /**
       * IP_LOOKUP_NEXT_MIDCHAIN
       *
       * A nbr adj that is also recursive. Think tunnels.
       * A nbr adj can transition to be of type MDICHAIN
       * so be sure to leave the two structs with the next_hop
       * fields aligned.
       */
      struct {
	  /**
	   * The recursive next-hop
	   */
	  ip46_address_t next_hop;
	  /**
	   * The node index of the tunnel's post rewrite/TX function.
	   */
	  u32 tx_function_node;
	  /**
	   * The next DPO to use
	   */
	  dpo_id_t next_dpo;
	  /**
	   * A function to perform the post-rewrite fixup
	   */
	  adj_midchain_fixup_t fixup_func;
      } midchain;
      /**
       * IP_LOOKUP_NEXT_GLEAN
       *
       * Glean the address to ARP for from the packet's destination
       */
      struct {
	  ip46_address_t receive_addr;
      } glean;
  } sub_type;

  CLIB_CACHE_LINE_ALIGN_MARK(cacheline1);

  /* Rewrite in second/third cache lines */
  vnet_declare_rewrite (VLIB_BUFFER_PRE_DATA_SIZE);

  /*
   * member not accessed in the data plane are relgated to the
   * remaining cachelines
   */
  fib_node_t ia_node;
} ip_adjacency_t;

_Static_assert((STRUCT_OFFSET_OF(ip_adjacency_t, cacheline0) == 0),
	       "IP adjacency cachline 0 is not offset");
_Static_assert((STRUCT_OFFSET_OF(ip_adjacency_t, cacheline1) ==
		CLIB_CACHE_LINE_BYTES),
	       "IP adjacency cachline 1 is more than one cachline size offset");

/* An all zeros address */
extern const ip46_address_t zero_addr;

/* IP multicast adjacency. */
typedef struct {
  /* Handle for this adjacency in adjacency heap. */
  u32 heap_handle;

  /* Number of adjecencies in block. */
  u32 n_adj;

  /* Rewrite string. */
  vnet_declare_rewrite (64 - 2*sizeof(u32));
} ip_multicast_rewrite_t;

typedef struct {
  /* ip4-multicast-rewrite next index. */
  u32 next_index;

  u8 n_rewrite_bytes;

  u8 rewrite_string[64 - 1*sizeof(u32) - 1*sizeof(u8)];
} ip_multicast_rewrite_string_t;

typedef struct {
  ip_multicast_rewrite_t * rewrite_heap;

  ip_multicast_rewrite_string_t * rewrite_strings;

  /* Negative rewrite string index; >= 0 sw_if_index.
     Sorted.  Used to hash. */
  i32 ** adjacency_id_vector;

  uword * adjacency_by_id_vector;
} ip_multicast_lookup_main_t;

typedef struct {
  /* Key for mhash; in fact, just a byte offset into mhash key vector. */
  u32 address_key;

  /* Interface which has this address. */
  u32 sw_if_index;

  /* Adjacency for neighbor probe (ARP) for this interface address. */
  u32 neighbor_probe_adj_index;

  /* Address (prefix) length for this interface. */
  u16 address_length;

  /* Will be used for something eventually.  Primary vs. secondary? */
  u16 flags;

  /* Next and previous pointers for doubly linked list of
     addresses per software interface. */
  u32 next_this_sw_interface;
  u32 prev_this_sw_interface;
} ip_interface_address_t;

typedef enum {
  IP_LOCAL_NEXT_DROP,
  IP_LOCAL_NEXT_PUNT,
  IP_LOCAL_NEXT_UDP_LOOKUP,
  IP_LOCAL_NEXT_ICMP,
  IP_LOCAL_N_NEXT,
} ip_local_next_t;

struct ip_lookup_main_t;

typedef struct ip_lookup_main_t {
  /* Adjacency heap. */
  ip_adjacency_t * adjacency_heap;

  /** load-balance  packet/byte counters indexed by LB index. */
  vlib_combined_counter_main_t load_balance_counters;

  /** any-tx-feature-enabled interface bitmap */
  uword * tx_sw_if_has_ip_output_features;

  /** count of enabled features, per sw_if_index, to maintain bitmap */
  i16 * tx_feature_count_by_sw_if_index;

  /** Pool of addresses that are assigned to interfaces. */
  ip_interface_address_t * if_address_pool;

  /** Hash table mapping address to index in interface address pool. */
  mhash_t address_to_if_address_index;

  /** Head of doubly linked list of interface addresses for each software interface.
     ~0 means this interface has no address. */
  u32 * if_address_pool_index_by_sw_if_index;

  /** First table index to use for this interface, ~0 => none */
  u32 * classify_table_index_by_sw_if_index;

  /** rx unicast, multicast, tx interface/feature configuration. */
  ip_config_main_t feature_config_mains[VNET_N_IP_FEAT];

  /** Number of bytes in a fib result.  Must be at least
     sizeof (uword).  First word is always adjacency index. */
  u32 fib_result_n_bytes, fib_result_n_words;

  format_function_t * format_fib_result;

  /** 1 for ip6; 0 for ip4. */
  u32 is_ip6;

  /** Either format_ip4_address_and_length or format_ip6_address_and_length. */
  format_function_t * format_address_and_length;

  /** Special adjacency format functions */
  format_function_t ** special_adjacency_format_functions;

  /** Table mapping ip protocol to ip[46]-local node next index. */
  u8 local_next_by_ip_protocol[256];

  /** IP_BUILTIN_PROTOCOL_{TCP,UDP,ICMP,OTHER} by protocol in IP header. */
  u8 builtin_protocol_by_ip_protocol[256];
} ip_lookup_main_t;

always_inline ip_adjacency_t *
ip_get_adjacency (ip_lookup_main_t * lm,
		  u32 adj_index)
{
  ip_adjacency_t * adj;

  adj = vec_elt_at_index (lm->adjacency_heap, adj_index);

  return adj;
}

#define ip_prefetch_adjacency(lm,adj_index,type)		\
do {								\
  ip_adjacency_t * _adj = (lm)->adjacency_heap + (adj_index);	\
  CLIB_PREFETCH (_adj, sizeof (_adj[0]), type);			\
} while (0)

/* Create new block of given number of contiguous adjacencies. */
ip_adjacency_t *
ip_add_adjacency (ip_lookup_main_t * lm,
		  ip_adjacency_t * adj,
		  u32 n_adj,
		  u32 * adj_index_result);

clib_error_t *
ip_interface_address_add_del (ip_lookup_main_t * lm,
			      u32 sw_if_index,
			      void * address,
			      u32 address_length,
			      u32 is_del,
			      u32 * result_index);

u8 *
format_ip_flow_hash_config (u8 * s, va_list * args);

always_inline ip_interface_address_t *
ip_get_interface_address (ip_lookup_main_t * lm, void * addr_fib)
{
  uword * p = mhash_get (&lm->address_to_if_address_index, addr_fib);
  return p ? pool_elt_at_index (lm->if_address_pool, p[0]) : 0;
}

u32
fib_table_id_find_fib_index (fib_protocol_t proto,
			     u32 table_id);

always_inline void *
ip_interface_address_get_address (ip_lookup_main_t * lm, ip_interface_address_t * a)
{ return mhash_key_to_mem (&lm->address_to_if_address_index, a->address_key); }

#define foreach_ip_interface_address(lm,a,sw_if_index,loop,body)        \
do {                                                                    \
    vnet_main_t *_vnm = vnet_get_main();                                     \
    u32 _sw_if_index = sw_if_index;                                     \
    vnet_sw_interface_t *_swif;                                         \
    _swif = vnet_get_sw_interface (_vnm, _sw_if_index);                 \
                                                                        \
    /*                                                                  \
     * Loop => honor unnumbered interface addressing.                   \
     */                                                                 \
    if (loop && _swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED)       \
      _sw_if_index = _swif->unnumbered_sw_if_index;                     \
    u32 _ia =                                                           \
      (vec_len((lm)->if_address_pool_index_by_sw_if_index)              \
       > (_sw_if_index))                                                \
        ? vec_elt ((lm)->if_address_pool_index_by_sw_if_index,          \
                   (_sw_if_index)) : (u32)~0;                           \
    ip_interface_address_t * _a;                                        \
    while (_ia != ~0)                                                   \
    {                                                                   \
        _a = pool_elt_at_index ((lm)->if_address_pool, _ia);            \
        _ia = _a->next_this_sw_interface;                               \
        (a) = _a;                                                       \
        body;                                                           \
    }                                                                   \
} while (0)

void ip_lookup_init (ip_lookup_main_t * lm, u32 ip_lookup_node_index);

#endif /* included_ip_lookup_h */
