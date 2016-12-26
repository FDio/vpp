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
 * @brief
 * A Data-Path Object is an object that represents actions that are
 * applied to packets are they are switched through VPP's data-path.
 * 
 * The DPO can be considered to be like is a base class that is specialised
 * by other objects to provide concreate actions
 *
 * The VLIB graph nodes are graph of DPO types, the DPO graph is a graph of
 * instances.
 */

#ifndef __DPO_H__
#define __DPO_H__

#include <vnet/vnet.h>

/**
 * @brief An index for adjacencies.
 * Alas 'C' is not typesafe enough to b0rk when a u32 is used instead of
 * an index_t. However, for us humans, we can glean much more intent
 * from the declaration
 *  foo barindex_t t);
 * than we can from
 *  foo bar(u32 t);
 */
typedef u32 index_t;

/**
 * @brief Invalid index - used when no index is known
 * blazoned capitals INVALID speak volumes where ~0 does not.
 */
#define INDEX_INVALID ((index_t)(~0))

/**
 * @brief Data path protocol.
 * Actions performed on packets in the data-plane can be described and represented
 * by protocol independent objects, i.e. ADJACENCY, but the spceifics actions
 * required during ADJACENCY processing can be protocol dependent. For example,
 * the adjacency rewrite node performs a ip4 checksum calculation,  ip6 and MPLS
 * do not, all 3 perform a TTL decrement. The VLIB graph nodes are thus protocol
 * dependent, and thus each graph edge/arc is too.
 * When programming a DPO's next node arc from child to parent it is thus required
 * to know the parent's data-path protocol so the correct arc index can be used.
 */
typedef enum dpo_proto_t_
{
#if CLIB_DEBUG > 0
    DPO_PROTO_IP4 = 1,
#else
    DPO_PROTO_IP4 = 0,
#endif
    DPO_PROTO_IP6,
    DPO_PROTO_ETHERNET,
    DPO_PROTO_MPLS,
} __attribute__((packed)) dpo_proto_t;

#define DPO_PROTO_NUM ((dpo_proto_t)(DPO_PROTO_MPLS+1))
#define DPO_PROTO_NONE ((dpo_proto_t)(DPO_PROTO_NUM+1))

#define DPO_PROTOS {		\
    [DPO_PROTO_IP4]  = "ip4",	\
    [DPO_PROTO_IP6]  = "ip6",	\
    [DPO_PROTO_ETHERNET]  = "ethernet", \
    [DPO_PROTO_MPLS] = "mpls",	\
}

#define FOR_EACH_DPO_PROTO(_proto)    \
    for (_proto = DPO_PROTO_IP4;      \
	 _proto <= DPO_PROTO_MPLS;    \
	 _proto++)

/**
 * @brief Common types of data-path objects
 * New types can be dynamically added using dpo_register_new_type()
 */
typedef enum dpo_type_t_ {
    /**
     * A non-zero value first so we can spot unitialisation errors
     */
    DPO_FIRST,
    DPO_DROP,
    DPO_IP_NULL,
    DPO_PUNT,
    /**
     * @brief load-balancing over a choice of [un]equal cost paths
     */
    DPO_LOAD_BALANCE,
    DPO_ADJACENCY,
    DPO_ADJACENCY_INCOMPLETE,
    DPO_ADJACENCY_MIDCHAIN,
    DPO_ADJACENCY_GLEAN,
    DPO_RECEIVE,
    DPO_LOOKUP,
    DPO_LISP_CP,
    DPO_CLASSIFY,
    DPO_MPLS_LABEL,
    DPO_LAST,
} __attribute__((packed)) dpo_type_t;

#define DPO_TYPE_NUM DPO_LAST

#define DPO_TYPES {			\
    [DPO_FIRST] = "dpo-invalid",	\
    [DPO_DROP] = "dpo-drop",	\
    [DPO_IP_NULL] = "dpo-ip-null",		\
    [DPO_PUNT] = "dpo-punt",	\
    [DPO_ADJACENCY] = "dpo-adjacency",	\
    [DPO_ADJACENCY_INCOMPLETE] = "dpo-adjacency-incomplete",	\
    [DPO_ADJACENCY_MIDCHAIN] = "dpo-adjacency-midcahin",	\
    [DPO_ADJACENCY_GLEAN] = "dpo-glean",	\
    [DPO_RECEIVE] = "dpo-receive",	\
    [DPO_LOOKUP] = "dpo-lookup",	\
    [DPO_LOAD_BALANCE] = "dpo-load-balance",	\
    [DPO_LISP_CP] = "dpo-lisp-cp",	\
    [DPO_CLASSIFY] = "dpo-classify",	\
    [DPO_MPLS_LABEL] = "dpo-mpls-label"	\
}

/**
 * @brief The identity of a DPO is a combination of its type and its
 * instance number/index of objects of that type
 */
typedef struct dpo_id_t_ {
    /**
     * the type
     */
    dpo_type_t dpoi_type;
    /**
     * the data-path protocol of the type.
     */
    dpo_proto_t dpoi_proto;
    /**
     * The next VLIB node to follow.
     */
    u16 dpoi_next_node;
    /**
     * the index of objects of that type
     */
    index_t dpoi_index;
} __attribute__ ((aligned(sizeof(u64)))) dpo_id_t;

STATIC_ASSERT(sizeof(dpo_id_t) <= sizeof(u64),
	      "DPO ID is greater than sizeof u64 "
	      "atomic updates need to be revisited");

/**
 * @brief An initialiser for DPOs declared on the stack.
 * Thenext node is set to 0 since VLIB graph nodes should set 0 index to drop.
 */
#define DPO_INVALID                \
{                                  \
    .dpoi_type = DPO_FIRST,        \
    .dpoi_proto = DPO_PROTO_NONE,  \
    .dpoi_index = INDEX_INVALID,   \
    .dpoi_next_node = 0,           \
}

/**
 * @brief Return true if the DPO object is valid, i.e. has been initialised.
 */
static inline int
dpo_id_is_valid (const dpo_id_t *dpoi)
{
    return (dpoi->dpoi_type != DPO_FIRST &&
	    dpoi->dpoi_index != INDEX_INVALID);
}

extern dpo_proto_t vnet_link_to_dpo_proto(vnet_link_t linkt);

/**
 * @brief
 *  Take a reference counting lock on the DPO
 */
extern void dpo_lock(dpo_id_t *dpo);

/**
 * @brief
 *  Release a reference counting lock on the DPO
 */
extern void dpo_unlock(dpo_id_t *dpo);

/**
 * @brief Set/create a DPO ID
 * The DPO will be locked.
 *
 * @param dpo
 *  The DPO object to configure
 *
 * @param type
 *  The dpo_type_t of the DPO
 *
 * @param proto
 *  The dpo_proto_t of the DPO
 *
 * @param index
 *  The type specific index of the DPO
 */
extern void dpo_set(dpo_id_t *dpo,
		    dpo_type_t type,
		    dpo_proto_t proto,
		    index_t index);

/**
 * @brief reset a DPO ID
 * The DPO will be unlocked.
 *
 * @param dpo
 *  The DPO object to reset
 */
extern void dpo_reset(dpo_id_t *dpo);

/**
 * @brief compare two DPOs for equality
 */
extern int dpo_cmp(const dpo_id_t *dpo1,
		   const dpo_id_t *dpo2);

/**
 * @brief
 *  atomic copy a data-plane object.
 * This is safe to use when the dst DPO is currently switching packets
 */
extern void dpo_copy(dpo_id_t *dst,
		     const dpo_id_t *src);

/**
 * @brief Return TRUE is the DPO is any type of adjacency
 */
extern int dpo_is_adj(const dpo_id_t *dpo);

/**
 * @biref Format a DPO_id_t oject
 */
extern u8 *format_dpo_id(u8 * s, va_list * args);

/**
 * @biref format a DPO type
 */
extern u8 *format_dpo_type(u8 * s, va_list * args);

/**
 * @brief format a DPO protocol
 */
extern u8 *format_dpo_proto(u8 * s, va_list * args);

/**
 * @brief
 *  Set and stack a DPO.
 *  The DPO passed is set to the parent DPO and the necessary
 *  VLIB graph arcs are created. The child_type and child_proto
 * are used to get the VLID nodes from which the arcs are added.
 *
 * @param child_type
 *  Child DPO type.
 *
 * @param child_proto
 *  Child DPO proto
 *
 * @parem dpo
 *  This is the DPO to stack and set.
 *
 * @paren parent_dpo
 *  The parent DPO to stack onto.
 */
extern void dpo_stack(dpo_type_t child_type,
                      dpo_proto_t child_proto,
                      dpo_id_t *dpo,
                      const dpo_id_t *parent_dpo);

/**
 * @brief 
 *  Set and stack a DPO.
 *  The DPO passed is set to the parent DPO and the necessary
 *  VLIB graph arcs are created, from the child_node passed.
 *
 * @param child_node
 *  The VLIB grpah node index to create an arc from to the parent
 *
 * @parem dpo
 *  This is the DPO to stack and set.
 *
 * @paren parent_dpo
 *  The parent DPO to stack onto.
 */ 
extern void dpo_stack_from_node(u32 child_node,
                                dpo_id_t *dpo,
                                const dpo_id_t *parent);

/**
 * @brief  A lock function registered for a DPO type
 */
typedef void (*dpo_lock_fn_t)(dpo_id_t *dpo);

/**
 * @brief An unlock function registered for a DPO type
 */
typedef void (*dpo_unlock_fn_t)(dpo_id_t *dpo);

/**
 * @brief An memory usage show command
 */
typedef void (*dpo_mem_show_t)(void);

/**
 * @brief A virtual function table regisitered for a DPO type
 */
typedef struct dpo_vft_t_
{
    /**
     * A reference counting lock function
     */
    dpo_lock_fn_t dv_lock;
    /**
     * A reference counting unlock function
     */
    dpo_lock_fn_t dv_unlock;
    /**
     * A format function
     */
    format_function_t *dv_format;
    /**
     * A show memory usage function
     */
    dpo_mem_show_t dv_mem_show;
} dpo_vft_t;


/**
 * @brief For a given DPO type Register:
 *   - a virtual function table
 *   - a NULL terminated array of graph nodes from which that object type
 *     will originate packets, i.e. the nodes in which the object type will be
 *     the parent DPO in the DP graph. The ndoes are per-data-path protocol
 *     (see above).
 *
 * @param type
 *  The type being registered. 
 *
 * @param vft
 *  The virtual function table to register for the type.
 *
 * @param nodes
 *  The string description of the per-protocol VLIB graph nodes.
 */
extern void dpo_register(dpo_type_t type,
			 const dpo_vft_t *vft,
			 const char * const * const * nodes);

/**
 * @brief Create and register a new DPO type.
 *
 * This can be used by plugins to create new DPO types that are not listed
 * in dpo_type_t enum
 *
 * @param vft
 *  The virtual function table to register for the type.
 *
 * @param nodes
 *  The string description of the per-protocol VLIB graph nodes.
 *
 * @return The new dpo_type_t
 */
extern dpo_type_t dpo_register_new_type(const dpo_vft_t *vft,
					const char * const * const * nodes);

#endif
