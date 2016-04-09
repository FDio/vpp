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

#ifndef included_ip_lookup_h
#define included_ip_lookup_h

#include <vnet/vnet.h>
#include <vlib/buffer.h>
#include <vnet/ip/ip4_packet.h>

/* Next index stored in adjacency. */
typedef enum {
  /* Packet does not match any route in table. */
  IP_LOOKUP_NEXT_MISS,

  /* Adjacency says to drop or punt this packet. */
  IP_LOOKUP_NEXT_DROP,
  IP_LOOKUP_NEXT_PUNT,

  /* This packet is for one of our own IP addresses. */
  IP_LOOKUP_NEXT_LOCAL,

  /* This packet matches an "interface route" and packets
     need to be passed to ARP to find rewrite string for
     this destination. */
  IP_LOOKUP_NEXT_ARP,

  /* This packet is to be rewritten and forwarded to the next
     processing node.  This is typically the output interface but
     might be another node for further output processing. */
  IP_LOOKUP_NEXT_REWRITE,

  /* This packet needs to be classified */
  IP_LOOKUP_NEXT_CLASSIFY,

  /* This packet needs to go to MAP - RFC7596, RFC7597 */
  IP_LOOKUP_NEXT_MAP,

  /* This packet needs to go to MAP with Translation - RFC7599 */
  IP_LOOKUP_NEXT_MAP_T,

  /* This packets needs to go to 6RD (RFC5969) */
  IP_LOOKUP_NEXT_SIXRD,

  /* Hop-by-hop header handling */
  IP_LOOKUP_NEXT_HOP_BY_HOP,
  IP_LOOKUP_NEXT_ADD_HOP_BY_HOP,
  IP_LOOKUP_NEXT_POP_HOP_BY_HOP,

  IP_LOOKUP_N_NEXT,
} ip_lookup_next_t;

#define IP4_LOOKUP_NEXT_NODES {					\
    [IP_LOOKUP_NEXT_MISS] = "ip4-miss",				\
    [IP_LOOKUP_NEXT_DROP] = "ip4-drop",				\
    [IP_LOOKUP_NEXT_PUNT] = "ip4-punt",				\
    [IP_LOOKUP_NEXT_LOCAL] = "ip4-local",			\
    [IP_LOOKUP_NEXT_ARP] = "ip4-arp",				\
    [IP_LOOKUP_NEXT_REWRITE] = "ip4-rewrite-transit",		\
    [IP_LOOKUP_NEXT_CLASSIFY] = "ip4-classify",			\
    [IP_LOOKUP_NEXT_MAP] = "ip4-map",				\
    [IP_LOOKUP_NEXT_MAP_T] = "ip4-map-t",			\
    [IP_LOOKUP_NEXT_SIXRD] = "ip4-sixrd",			\
    [IP_LOOKUP_NEXT_HOP_BY_HOP] = "ip4-hop-by-hop",		\
    [IP_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip4-add-hop-by-hop",	\
    [IP_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip4-pop-hop-by-hop",	\
}

#define IP6_LOOKUP_NEXT_NODES {					\
    [IP_LOOKUP_NEXT_MISS] = "ip6-miss",				\
    [IP_LOOKUP_NEXT_DROP] = "ip6-drop",				\
    [IP_LOOKUP_NEXT_PUNT] = "ip6-punt",				\
    [IP_LOOKUP_NEXT_LOCAL] = "ip6-local",			\
    [IP_LOOKUP_NEXT_ARP] = "ip6-discover-neighbor",		\
    [IP_LOOKUP_NEXT_REWRITE] = "ip6-rewrite",			\
    [IP_LOOKUP_NEXT_CLASSIFY] = "ip6-classify",			\
    [IP_LOOKUP_NEXT_MAP] = "ip6-map",				\
    [IP_LOOKUP_NEXT_MAP_T] = "ip6-map-t",			\
    [IP_LOOKUP_NEXT_SIXRD] = "ip6-sixrd",			\
    [IP_LOOKUP_NEXT_HOP_BY_HOP] = "ip6-hop-by-hop",		\
    [IP_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip6-add-hop-by-hop",	\
    [IP_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip6-pop-hop-by-hop",	\
}

/* Flow hash configuration */
#define IP_FLOW_HASH_SRC_ADDR (1<<0)
#define IP_FLOW_HASH_DST_ADDR (1<<1)
#define IP_FLOW_HASH_PROTO (1<<2)
#define IP_FLOW_HASH_SRC_PORT (1<<3)
#define IP_FLOW_HASH_DST_PORT (1<<4)
#define IP_FLOW_HASH_REVERSE_SRC_DST (1<<5)

/* Default: 5-tuple without the "reverse" bit */
#define IP_FLOW_HASH_DEFAULT (0x1F)

#define foreach_flow_hash_bit                   \
_(src, IP_FLOW_HASH_SRC_ADDR)                   \
_(dst, IP_FLOW_HASH_DST_ADDR)                   \
_(sport, IP_FLOW_HASH_SRC_PORT)                 \
_(dport, IP_FLOW_HASH_DST_PORT)                 \
_(proto, IP_FLOW_HASH_PROTO)	                \
_(reverse, IP_FLOW_HASH_REVERSE_SRC_DST)

/* IP unicast adjacency. */
typedef struct {
  CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);
  /* Handle for this adjacency in adjacency heap. */
  u32 heap_handle;

  STRUCT_MARK(signature_start);

  /* Interface address index for this local/arp adjacency. */
  u32 if_address_index;

  /* Number of adjecencies in block.  Greater than 1 means multipath;
     otherwise equal to 1. */
  u16 n_adj;

  /* Next hop after ip4-lookup. */
  union {
    ip_lookup_next_t lookup_next_index : 16;
    u16 lookup_next_index_as_int;
  };

  /* Force re-lookup in a different FIB. ~0 => normal behavior */
  i16 explicit_fib_index;
  u16 mcast_group_index;  

  /* Highest possible perf subgraph arc interposition, e.g. for ip6 ioam */
  u16 saved_lookup_next_index;

  union {
    /* IP_LOOKUP_NEXT_ARP only */
    struct {
      union {
        ip4_address_t ip4;
      } next_hop;
      u32 next_adj_index_with_same_next_hop;
    } arp;
    /* IP_LOOKUP_NEXT_CLASSIFY only */
    struct {
      u16 table_index;
    } classify;
  };

  STRUCT_MARK(signature_end);

  /* Number of FIB entries sharing this adjacency */
  u32 share_count;
  /* Use this adjacency instead */
  u32 next_adj_with_signature;

  CLIB_CACHE_LINE_ALIGN_MARK(cacheline1);

  /* Rewrite in second/third cache lines */
  vnet_declare_rewrite (VLIB_BUFFER_PRE_DATA_SIZE);
} ip_adjacency_t;

static inline uword
vnet_ip_adjacency_signature (ip_adjacency_t * adj)
{
  uword signature = 0xfeedfaceULL;

  /* Skip heap handle, sum everything up to but not including share_count */
  signature = hash_memory
      (STRUCT_MARK_PTR(adj, signature_start),
       STRUCT_OFFSET_OF(ip_adjacency_t, signature_end)
       - STRUCT_OFFSET_OF(ip_adjacency_t, signature_start),
       signature);

  /* and the rewrite */
  signature = hash_memory (&adj->rewrite_header, VLIB_BUFFER_PRE_DATA_SIZE,
                             signature);
  return signature;
}

static inline int
vnet_ip_adjacency_share_compare (ip_adjacency_t * a1, ip_adjacency_t *a2)
{
  if (memcmp (STRUCT_MARK_PTR(a1, signature_start),
              STRUCT_MARK_PTR(a2, signature_start),
              STRUCT_OFFSET_OF(ip_adjacency_t, signature_end)
              - STRUCT_OFFSET_OF(ip_adjacency_t, signature_start)))
    return 0;
  if (memcmp (&a1->rewrite_header, &a2->rewrite_header,
              VLIB_BUFFER_PRE_DATA_SIZE))
    return 0;
  return 1;
}

/* Index into adjacency table. */
typedef u32 ip_adjacency_index_t;

typedef struct {
  /* Directly connected next-hop adjacency index. */
  u32 next_hop_adj_index;

  /* Path weight for this adjacency. */
  u32 weight;
} ip_multipath_next_hop_t;

typedef struct {
  /* Adjacency index of first index in block. */
  u32 adj_index;
  
  /* Power of 2 size of adjacency block. */
  u32 n_adj_in_block;

  /* Number of prefixes that point to this adjacency. */
  u32 reference_count;

  /* Normalized next hops are used as hash keys: they are sorted by weight
     and weights are chosen so they add up to 1 << log2_n_adj_in_block (with
     zero-weighted next hops being deleted).
     Unnormalized next hops are saved so that control plane has a record of exactly
     what the RIB told it. */
  struct {
    /* Number of hops in the multipath. */
    u32 count;

    /* Offset into next hop heap for this block. */
    u32 heap_offset;

    /* Heap handle used to for example free block when we're done with it. */
    u32 heap_handle;
  } normalized_next_hops, unnormalized_next_hops;
} ip_multipath_adjacency_t;

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

typedef void (* ip_add_del_adjacency_callback_t) (struct ip_lookup_main_t * lm,
						  u32 adj_index,
						  ip_adjacency_t * adj,
						  u32 is_del);

typedef struct {
  vnet_config_main_t config_main;

  u32 * config_index_by_sw_if_index;
} ip_config_main_t;

typedef struct ip_lookup_main_t {
  /* Adjacency heap. */
  ip_adjacency_t * adjacency_heap;

  /* Adjacency packet/byte counters indexed by adjacency index. */
  vlib_combined_counter_main_t adjacency_counters;

  /* Heap of (next hop, weight) blocks.  Sorted by next hop. */
  ip_multipath_next_hop_t * next_hop_heap;

  /* Indexed by heap_handle from ip_adjacency_t. */
  ip_multipath_adjacency_t * multipath_adjacencies;

  /* Adjacency by signature hash */
  uword * adj_index_by_signature;

  /* Temporary vectors for looking up next hops in hash. */
  ip_multipath_next_hop_t * next_hop_hash_lookup_key;
  ip_multipath_next_hop_t * next_hop_hash_lookup_key_normalized;

  /* Hash table mapping normalized next hops and weights
     to multipath adjacency index. */
  uword * multipath_adjacency_by_next_hops;

  u32 * adjacency_remap_table;
  u32 n_adjacency_remaps;

  /* If average error per adjacency is less than this threshold adjacency block
     size is accepted. */
  f64 multipath_next_hop_error_tolerance;

  /* Adjacency index for routing table misses, local punts, and drops. */
  u32 miss_adj_index, drop_adj_index, local_adj_index;

  /* Miss adjacency is always first in adjacency table. */
#define IP_LOOKUP_MISS_ADJ_INDEX 0

  ip_add_del_adjacency_callback_t * add_del_adjacency_callbacks;

  /* Pool of addresses that are assigned to interfaces. */
  ip_interface_address_t * if_address_pool;

  /* Hash table mapping address to index in interface address pool. */
  mhash_t address_to_if_address_index;

  /* Head of doubly linked list of interface addresses for each software interface.
     ~0 means this interface has no address. */
  u32 * if_address_pool_index_by_sw_if_index;

  /* First table index to use for this interface, ~0 => none */
  u32 * classify_table_index_by_sw_if_index;

  /* rx/tx interface/feature configuration. */
  ip_config_main_t rx_config_mains[VNET_N_CAST], tx_config_main;

  /* Number of bytes in a fib result.  Must be at least
     sizeof (uword).  First word is always adjacency index. */
  u32 fib_result_n_bytes, fib_result_n_words;

  format_function_t * format_fib_result;

  /* 1 for ip6; 0 for ip4. */
  u32 is_ip6;

  /* Either format_ip4_address_and_length or format_ip6_address_and_length. */
  format_function_t * format_address_and_length;

  /* Table mapping ip protocol to ip[46]-local node next index. */
  u8 local_next_by_ip_protocol[256];

  /* IP_BUILTIN_PROTOCOL_{TCP,UDP,ICMP,OTHER} by protocol in IP header. */
  u8 builtin_protocol_by_ip_protocol[256];
} ip_lookup_main_t;

always_inline ip_adjacency_t *
ip_get_adjacency (ip_lookup_main_t * lm,
		  u32 adj_index)
{
  ip_adjacency_t * adj;

  adj = vec_elt_at_index (lm->adjacency_heap, adj_index);

  ASSERT (adj->heap_handle != ~0);

  return adj;
}

#define ip_prefetch_adjacency(lm,adj_index,type)		\
do {								\
  ip_adjacency_t * _adj = (lm)->adjacency_heap + (adj_index);	\
  CLIB_PREFETCH (_adj, sizeof (_adj[0]), type);			\
} while (0)

static inline void
ip_register_add_del_adjacency_callback(ip_lookup_main_t * lm,
				       ip_add_del_adjacency_callback_t cb)
{
  vec_add1(lm->add_del_adjacency_callbacks, cb);
}

always_inline void
ip_call_add_del_adjacency_callbacks (ip_lookup_main_t * lm, u32 adj_index, u32 is_del)
{
  ip_adjacency_t * adj;
  uword i;
  adj = ip_get_adjacency (lm, adj_index);
  for (i = 0; i < vec_len (lm->add_del_adjacency_callbacks); i++)
    lm->add_del_adjacency_callbacks[i] (lm, adj_index, adj, is_del);
}

/* Create new block of given number of contiguous adjacencies. */
ip_adjacency_t *
ip_add_adjacency (ip_lookup_main_t * lm,
		  ip_adjacency_t * adj,
		  u32 n_adj,
		  u32 * adj_index_result);

void ip_del_adjacency (ip_lookup_main_t * lm, u32 adj_index);
void
ip_update_adjacency (ip_lookup_main_t * lm,
		     u32 adj_index,
		     ip_adjacency_t * copy_adj);

static inline int
ip_adjacency_is_multipath(ip_lookup_main_t * lm, u32 adj_index)
{
  if (vec_len(lm->multipath_adjacencies) < adj_index - 1)
    return 0;

  return (lm->multipath_adjacencies[adj_index].adj_index == adj_index &&
	  lm->multipath_adjacencies[adj_index].n_adj_in_block > 0);
}

void
ip_multipath_adjacency_free (ip_lookup_main_t * lm,
			     ip_multipath_adjacency_t * a);

u32
ip_multipath_adjacency_add_del_next_hop (ip_lookup_main_t * lm,
					 u32 is_del,
					 u32 old_mp_adj_index,
					 u32 next_hop_adj_index,
					 u32 next_hop_weight,
					 u32 * new_mp_adj_index);

clib_error_t *
ip_interface_address_add_del (ip_lookup_main_t * lm,
			      u32 sw_if_index,
			      void * address,
			      u32 address_length,
			      u32 is_del,
			      u32 * result_index);

always_inline ip_interface_address_t *
ip_get_interface_address (ip_lookup_main_t * lm, void * addr_fib)
{
  uword * p = mhash_get (&lm->address_to_if_address_index, addr_fib);
  return p ? pool_elt_at_index (lm->if_address_pool, p[0]) : 0;
}

always_inline void *
ip_interface_address_get_address (ip_lookup_main_t * lm, ip_interface_address_t * a)
{ return mhash_key_to_mem (&lm->address_to_if_address_index, a->address_key); }

always_inline ip_interface_address_t *
ip_interface_address_for_packet (ip_lookup_main_t * lm, vlib_buffer_t * b, u32 sw_if_index)
{
  ip_adjacency_t * adj;
  u32 if_address_index;

  adj = ip_get_adjacency (lm, vnet_buffer (b)->ip.adj_index[VLIB_TX]);

  ASSERT (adj->lookup_next_index == IP_LOOKUP_NEXT_ARP
	  || adj->lookup_next_index == IP_LOOKUP_NEXT_LOCAL);
  if_address_index = adj->if_address_index;
  if_address_index = (if_address_index == ~0 ?
		      vec_elt (lm->if_address_pool_index_by_sw_if_index, sw_if_index)
		      : if_address_index);

  return pool_elt_at_index (lm->if_address_pool, if_address_index);
}

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
