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
/**
 * An adjacency is a representation of an attached L3 peer.
 *
 * Adjacency Sub-types:
 *   - neighbour: a representation of an attached L3 peer.
 *                Key:{addr,interface,link/ether-type}
 *           SHARED
 *   - glean: used to drive ARP/ND for packets destined to a local sub-net.
 *            'glean' mean use the packet's destination address as the target
 *            address in the ARP packet.
 *          UNSHARED. Only one per-interface.
 *   - midchain: a neighbour adj on a virtual/tunnel interface.
 *
 * The API to create and update the adjacency is very sub-type specific. This
 * is intentional as it encourages the user to carefully consider which adjacency
 * sub-type they are really using, and hence assign it data in the appropriate
 * sub-type space in the union of sub-types. This prevents the adj becoming a
 * disorganised dumping group for 'my features needs a u16 somewhere' data. It
 * is important to enforce this approach as space in the adjacency is a premium,
 * as we need it to fit in 1 cache line.
 *
 * the API is also based around an index to an adjacency not a raw pointer. This
 * is so the user doesn't suffer the same limp inducing firearm injuries that
 * the author suffered as the adjacencies can realloc.
 */

#ifndef __ADJ_H__
#define __ADJ_H__

#include <vnet/adj/adj_types.h>
#include <vnet/adj/adj_nbr.h>
#include <vnet/adj/adj_glean.h>
#include <vnet/adj/rewrite.h>

/** @brief Common (IP4/IP6) next index stored in adjacency. */
typedef enum
{
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

  /** This packets follow a mid-chain adjacency */
  IP_LOOKUP_NEXT_MIDCHAIN,

  /** This packets needs to go to ICMP error */
  IP_LOOKUP_NEXT_ICMP_ERROR,

  /** Multicast Adjacency. */
  IP_LOOKUP_NEXT_MCAST,

  /** Broadcast Adjacency. */
  IP_LOOKUP_NEXT_BCAST,

  /** Multicast Midchain Adjacency. An Adjacency for sending multicast packets
   *  on a tunnel/virtual interface */
  IP_LOOKUP_NEXT_MCAST_MIDCHAIN,

  IP_LOOKUP_N_NEXT,
} __attribute__ ((packed)) ip_lookup_next_t;

typedef enum
{
  IP4_LOOKUP_N_NEXT = IP_LOOKUP_N_NEXT,
} ip4_lookup_next_t;

typedef enum
{
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
    [IP_LOOKUP_NEXT_REWRITE] = "ip4-rewrite",    		\
    [IP_LOOKUP_NEXT_MCAST] = "ip4-rewrite-mcast",	        \
    [IP_LOOKUP_NEXT_BCAST] = "ip4-rewrite-bcast",               \
    [IP_LOOKUP_NEXT_MIDCHAIN] = "ip4-midchain",		        \
    [IP_LOOKUP_NEXT_MCAST_MIDCHAIN] = "ip4-mcast-midchain",     \
    [IP_LOOKUP_NEXT_ICMP_ERROR] = "ip4-icmp-error",		\
}

#define IP6_LOOKUP_NEXT_NODES {					\
    [IP_LOOKUP_NEXT_DROP] = "ip6-drop",				\
    [IP_LOOKUP_NEXT_PUNT] = "ip6-punt",				\
    [IP_LOOKUP_NEXT_LOCAL] = "ip6-local",			\
    [IP_LOOKUP_NEXT_ARP] = "ip6-discover-neighbor",		\
    [IP_LOOKUP_NEXT_GLEAN] = "ip6-glean",			\
    [IP_LOOKUP_NEXT_REWRITE] = "ip6-rewrite",			\
    [IP_LOOKUP_NEXT_BCAST] = "ip6-rewrite-bcast",		\
    [IP_LOOKUP_NEXT_MCAST] = "ip6-rewrite-mcast",		\
    [IP_LOOKUP_NEXT_MIDCHAIN] = "ip6-midchain",			\
    [IP_LOOKUP_NEXT_MCAST_MIDCHAIN] = "ip6-mcast-midchain",     \
    [IP_LOOKUP_NEXT_ICMP_ERROR] = "ip6-icmp-error",		\
    [IP6_LOOKUP_NEXT_HOP_BY_HOP] = "ip6-hop-by-hop",		\
    [IP6_LOOKUP_NEXT_ADD_HOP_BY_HOP] = "ip6-add-hop-by-hop",	\
    [IP6_LOOKUP_NEXT_POP_HOP_BY_HOP] = "ip6-pop-hop-by-hop",	\
}

/**
 * The special broadcast address (to construct a broadcast adjacency
 */
extern const ip46_address_t ADJ_BCAST_ADDR;

/**
 * Forward declaration
 */
struct ip_adjacency_t_;

/**
 * @brief A function type for post-rewrite fixups on midchain adjacency
 */
typedef void (*adj_midchain_fixup_t) (vlib_main_t * vm,
				      const struct ip_adjacency_t_ * adj,
				      vlib_buffer_t * b0,
                                      const void *data);

/**
 * @brief Flags on an IP adjacency
 */
typedef enum adj_attr_t_
{
    /**
     * Currently a sync walk is active. Used to prevent re-entrant walking
     */
    ADJ_ATTR_SYNC_WALK_ACTIVE = 0,

    /**
     * Packets TX through the midchain do not increment the interface
     * counters. This should be used when the adj is associated with an L2
     * interface and that L2 interface is in a bridge domain. In that case
     * the packet will have traversed the interface's TX node, and hence have
     * been counted, before it traverses ths midchain
     */
    ADJ_ATTR_MIDCHAIN_NO_COUNT,
    /**
     * When stacking midchains on a fib-entry extract the choice from the
     * load-balance returned based on an IP hash of the adj's rewrite
     */
    ADJ_ATTR_MIDCHAIN_IP_STACK,
    /**
     * If the midchain were to stack on its FIB entry a loop would form.
     */
    ADJ_ATTR_MIDCHAIN_LOOPED,
    /**
     * the fixup function is standard IP4o4 header
     */
    ADJ_ATTR_MIDCHAIN_FIXUP_IP4O4_HDR,
    /**
     * the fixup function performs the flow hash
     * this means the flow hash is performed on the inner
     * header, where the entropy is higher.
     */
    ADJ_ATTR_MIDCHAIN_FIXUP_FLOW_HASH,
}  adj_attr_t;

#define ADJ_ATTR_NAMES {                                        \
    [ADJ_ATTR_SYNC_WALK_ACTIVE] = "walk-active",                \
    [ADJ_ATTR_MIDCHAIN_NO_COUNT] = "midchain-no-count",         \
    [ADJ_ATTR_MIDCHAIN_IP_STACK] = "midchain-ip-stack",         \
    [ADJ_ATTR_MIDCHAIN_LOOPED] = "midchain-looped",             \
    [ADJ_ATTR_MIDCHAIN_FIXUP_IP4O4_HDR] = "midchain-ip4o4-hdr-fixup",   \
    [ADJ_ATTR_MIDCHAIN_FIXUP_FLOW_HASH] = "midchain-flow-hash",   \
}

#define FOR_EACH_ADJ_ATTR(_attr)                        \
    for (_attr = ADJ_ATTR_SYNC_WALK_ACTIVE;             \
	 _attr <= ADJ_ATTR_MIDCHAIN_FIXUP_FLOW_HASH;    \
	 _attr++)

/**
 * @brief Flags on an IP adjacency
 */
typedef enum adj_flags_t_
{
    ADJ_FLAG_NONE = 0,
    ADJ_FLAG_SYNC_WALK_ACTIVE = (1 << ADJ_ATTR_SYNC_WALK_ACTIVE),
    ADJ_FLAG_MIDCHAIN_NO_COUNT = (1 << ADJ_ATTR_MIDCHAIN_NO_COUNT),
    ADJ_FLAG_MIDCHAIN_IP_STACK = (1 << ADJ_ATTR_MIDCHAIN_IP_STACK),
    ADJ_FLAG_MIDCHAIN_LOOPED = (1 << ADJ_ATTR_MIDCHAIN_LOOPED),
    ADJ_FLAG_MIDCHAIN_FIXUP_IP4O4_HDR = (1 << ADJ_ATTR_MIDCHAIN_FIXUP_IP4O4_HDR),
    ADJ_FLAG_MIDCHAIN_FIXUP_FLOW_HASH = (1 << ADJ_ATTR_MIDCHAIN_FIXUP_FLOW_HASH),
}  __attribute__ ((packed)) adj_flags_t;

/**
 * @brief Format adjacency flags
 */
extern u8* format_adj_flags(u8 * s, va_list * args);

/**
 * @brief IP unicast adjacency.
 *  @note cache aligned.
 *
 * An adjacency is a representation of a peer on a particular link.
 */
typedef struct ip_adjacency_t_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);

  /**
   * Linkage into the FIB node graph. First member since this type
   * has 8 byte alignment requirements.
   */
  fib_node_t ia_node;
  /**
   * feature [arc] config index
   */
  u32 ia_cfg_index;

  union
  {
    /**
     * IP_LOOKUP_NEXT_ARP/IP_LOOKUP_NEXT_REWRITE
     *
     * neighbour adjacency sub-type;
     */
    struct
    {
      ip46_address_t next_hop;
    } nbr;
      /**
       * IP_LOOKUP_NEXT_MIDCHAIN
       *
       * A nbr adj that is also recursive. Think tunnels.
       * A nbr adj can transition to be of type MIDCHAIN
       * so be sure to leave the two structs with the next_hop
       * fields aligned.
       */
    struct
    {
      /**
       * The recursive next-hop.
       *  This field MUST be at the same memory location as
       *   sub_type.nbr.next_hop
       */
      ip46_address_t next_hop;
      /**
       * The next DPO to use
       */
      dpo_id_t next_dpo;
      /**
       * A function to perform the post-rewrite fixup
       */
      adj_midchain_fixup_t fixup_func;
      /**
       * Fixup data passed back to the client in the fixup function
       */
      const void *fixup_data;
      /**
       * the FIB entry this midchain resolves through. required for recursive
       * loop detection.
       */
      fib_node_index_t fei;

      /** spare space */
      u8 __ia_midchain_pad[4];

    } midchain;
    /**
     * IP_LOOKUP_NEXT_GLEAN
     *
     * Glean the address to ARP for from the packet's destination.
     * Technically these aren't adjacencies, i.e. they are not a
     * representation of a peer. One day we might untangle this coupling
     * and use a new Glean DPO.
     */
    struct
    {
      ip46_address_t receive_addr;
    } glean;
  } sub_type;

  CLIB_CACHE_LINE_ALIGN_MARK (cacheline1);

  /** Rewrite in second and third cache lines */
  VNET_DECLARE_REWRITE;

  /**
   * more control plane members that do not fit on the first cacheline
   */
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline3);

  /**
   * A sorted vector of delegates
   */
  struct adj_delegate_t_ *ia_delegates;

  /**
   * The VLIB node in which this adj is used to forward packets
   */
  u32 ia_node_index;

  /**
   * Next hop after ip4-lookup.
   *  This is not accessed in the rewrite nodes.
   * 1-bytes
   */
  ip_lookup_next_t lookup_next_index;

  /**
   * link/ether-type
   * 1 bytes
   */
  vnet_link_t ia_link;

  /**
   * The protocol of the neighbor/peer. i.e. the protocol with
   * which to interpret the 'next-hop' attributes of the sub-types.
   * 1-bytes
   */
  fib_protocol_t ia_nh_proto;

  /**
   * Flags on the adjacency
   * 1-bytes
   */
  adj_flags_t ia_flags;

  /**
   * Free space on the fourth cacheline (not used in the DP)
   */
  u8 __ia_pad[48];
} ip_adjacency_t;

STATIC_ASSERT ((STRUCT_OFFSET_OF (ip_adjacency_t, cacheline0) == 0),
	       "IP adjacency cacheline 0 is not offset");
STATIC_ASSERT ((STRUCT_OFFSET_OF (ip_adjacency_t, cacheline1) ==
		CLIB_CACHE_LINE_BYTES),
	       "IP adjacency cacheline 1 is more than one cacheline size offset");
#if defined __x86_64__
STATIC_ASSERT ((STRUCT_OFFSET_OF (ip_adjacency_t, cacheline3) ==
		3 * CLIB_CACHE_LINE_BYTES),
	       "IP adjacency cacheline 3 is more than one cacheline size offset");
/* An adj fits into 4 cachelines on your average machine */
STATIC_ASSERT_SIZEOF (ip_adjacency_t, 4 * 64);
#endif

/**
 * @brief
 *   Take a reference counting lock on the adjacency
 */
extern void adj_lock(adj_index_t adj_index);
/**
 * @brief
 *   Release a reference counting lock on the adjacency
 */
extern void adj_unlock(adj_index_t adj_index);

/**
 * @brief
 *  Add a child dependent to an adjacency. The child will
 *  thus be informed via its registered back-walk function
 *  when the adjacency state changes.
 */
extern u32 adj_child_add(adj_index_t adj_index,
			 fib_node_type_t type,
			 fib_node_index_t child_index);
/**
 * @brief
 *  Remove a child dependent
 */
extern void adj_child_remove(adj_index_t adj_index,
			     u32 sibling_index);

/**
 * @brief Walk the Adjacencies on a given interface
 */
extern void adj_walk (u32 sw_if_index,
		      adj_walk_cb_t cb,
		      void *ctx);

/**
 * @brief Return the link type of the adjacency
 */
extern vnet_link_t adj_get_link_type (adj_index_t ai);

/**
 * @brief Return the sw interface index of the adjacency.
 */
extern u32 adj_get_sw_if_index (adj_index_t ai);

/**
 * @brief Return true if the adjacency is 'UP', i.e. can be used for forwarding.
 * 0 is down, !0 is up.
 */
extern int adj_is_up (adj_index_t ai);

/**
 * @brief Return the link type of the adjacency
 */
extern const u8* adj_get_rewrite (adj_index_t ai);

/**
 * @brief descend the FIB graph looking for loops
 *
 * @param ai
 *  The adj index to traverse
 *
 * @param entry_indicies)
 *  A pointer to a vector of FIB entries already visited.
 */
extern int adj_recursive_loop_detect (adj_index_t ai,
                                      fib_node_index_t **entry_indicies);

/**
 * @brief
 * The global adjacency pool. Exposed for fast/inline data-plane access
 */
extern ip_adjacency_t *adj_pool;

/**
 * @brief 
 * Adjacency packet counters
 */
extern vlib_combined_counter_main_t adjacency_counters;

/**
 * @brief Global Config for enabling per-adjacency counters
 * This is configurable because it comes with  a non-negligible
 * performance cost. */
extern int adj_per_adj_counters;

/**
 * @brief
 * Get a pointer to an adjacency object from its index
 */
static inline ip_adjacency_t *
adj_get (adj_index_t adj_index)
{
    return (pool_elt_at_index(adj_pool, adj_index));
}

static inline int
adj_is_valid(adj_index_t adj_index)
{
  return !(pool_is_free_index(adj_pool, adj_index));
}

/**
 * @brief Get the global configuration option for enabling per-adj counters
 */
static inline int 
adj_are_counters_enabled (void)
{
    return (adj_per_adj_counters);
}

#endif
