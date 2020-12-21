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

#ifndef __FIB_NODE_H__
#define __FIB_NODE_H__

#include <vnet/fib/fib_types.h>

/**
 * The types of nodes in a FIB graph
 */
typedef enum fib_node_type_t_ {
    /**
     * Marker. New types after this one.
     */
    FIB_NODE_TYPE_FIRST = 0,
    /**
     * See the respective fib_*.h files for descriptions of these objects.
     */
    FIB_NODE_TYPE_WALK,
    FIB_NODE_TYPE_ENTRY,
    FIB_NODE_TYPE_MFIB_ENTRY,
    FIB_NODE_TYPE_PATH_LIST,
    FIB_NODE_TYPE_PATH,
    FIB_NODE_TYPE_ADJ,
    FIB_NODE_TYPE_MPLS_ENTRY,
    FIB_NODE_TYPE_MPLS_TUNNEL,
    FIB_NODE_TYPE_LISP_GPE_FWD_ENTRY,
    FIB_NODE_TYPE_LISP_ADJ,
    FIB_NODE_TYPE_VXLAN_TUNNEL,
    FIB_NODE_TYPE_MAP_E,
    FIB_NODE_TYPE_VXLAN_GPE_TUNNEL,
    FIB_NODE_TYPE_GENEVE_TUNNEL,
    FIB_NODE_TYPE_UDP_ENCAP,
    FIB_NODE_TYPE_BIER_FMASK,
    FIB_NODE_TYPE_BIER_ENTRY,
    FIB_NODE_TYPE_VXLAN_GBP_TUNNEL,
    FIB_NODE_TYPE_IPSEC_SA,
    FIB_NODE_TYPE_IP_PUNT_REDIRECT,
    FIB_NODE_TYPE_ENTRY_TRACK,
    /**
     * Marker. New types before this one. leave the test last.
     */
    FIB_NODE_TYPE_TEST,
    FIB_NODE_TYPE_LAST = FIB_NODE_TYPE_TEST,
} __attribute__ ((packed)) fib_node_type_t;

#define FIB_NODE_TYPE_MAX (FIB_NODE_TYPE_LAST + 1)

#define FIB_NODE_TYPES {					\
    [FIB_NODE_TYPE_ENTRY]     = "entry",			\
    [FIB_NODE_TYPE_MFIB_ENTRY] = "mfib-entry",			\
    [FIB_NODE_TYPE_WALK]      = "walk",				\
    [FIB_NODE_TYPE_PATH_LIST] = "path-list",			\
    [FIB_NODE_TYPE_PATH]      = "path",				\
    [FIB_NODE_TYPE_MPLS_ENTRY] = "mpls-entry",			\
    [FIB_NODE_TYPE_MPLS_TUNNEL] = "mpls-tunnel",		\
    [FIB_NODE_TYPE_ADJ] = "adj",				\
    [FIB_NODE_TYPE_LISP_GPE_FWD_ENTRY] = "lisp-gpe-fwd-entry",	\
    [FIB_NODE_TYPE_LISP_ADJ] = "lisp-adj",			\
    [FIB_NODE_TYPE_VXLAN_TUNNEL] = "vxlan-tunnel",		\
    [FIB_NODE_TYPE_MAP_E] = "map-e",				\
    [FIB_NODE_TYPE_VXLAN_GPE_TUNNEL] = "vxlan-gpe-tunnel",	\
    [FIB_NODE_TYPE_UDP_ENCAP] = "udp-encap",			\
    [FIB_NODE_TYPE_BIER_FMASK] = "bier-fmask",			\
    [FIB_NODE_TYPE_BIER_ENTRY] = "bier-entry",			\
    [FIB_NODE_TYPE_VXLAN_GBP_TUNNEL] = "vxlan-gbp-tunnel",	\
    [FIB_NODE_TYPE_IPSEC_SA] = "ipsec-sa",                      \
    [FIB_NODE_TYPE_IP_PUNT_REDIRECT] = "ip-punt-redirect",      \
    [FIB_NODE_TYPE_ENTRY_TRACK] = "fib-entry-track"             \
}

/**
 * Reasons for backwalking the FIB object graph
 */
typedef enum fib_node_back_walk_reason_t_ {
    /**
     * Marker. Add new ones after.
     */
    FIB_NODE_BW_REASON_FIRST = 0,
    /**
     * Walk to re-resolve the child.
     * Used when the parent is no longer a valid resolution target
     */
    FIB_NODE_BW_REASON_RESOLVE = FIB_NODE_BW_REASON_FIRST,
    /**
     * Walk to re-evaluate the forwarding contributed by the parent.
     * Used when a parent's forwarding changes and the child needs to
     * incorporate this change in its forwarding.
     */
    FIB_NODE_BW_REASON_EVALUATE,
    /**
     * A resolving interface has come up
     */
    FIB_NODE_BW_REASON_INTERFACE_UP,
    /**
     * A resolving interface has gone down
     */
    FIB_NODE_BW_REASON_INTERFACE_DOWN,
    /**
     * A resolving interface has been deleted.
     */
    FIB_NODE_BW_REASON_INTERFACE_DELETE,
    /**
     * Walk to re-collapse the multipath adjs when the rewrite of
     * a unipath adjacency changes
     */
    FIB_NODE_BW_REASON_ADJ_UPDATE,
    /**
     * Walk update the adjacency MTU
     */
    FIB_NODE_BW_REASON_ADJ_MTU,
    /**
     * Walk to update children to inform them the adjacency is now down.
     */
    FIB_NODE_BW_REASON_ADJ_DOWN,
    /**
     * Marker. Add new before and update
     */
    FIB_NODE_BW_REASON_LAST = FIB_NODE_BW_REASON_ADJ_DOWN,
} fib_node_back_walk_reason_t;

#define FIB_NODE_BW_REASONS {			            \
    [FIB_NODE_BW_REASON_RESOLVE] = "resolve",	            \
    [FIB_NODE_BW_REASON_EVALUATE] = "evaluate",             \
    [FIB_NODE_BW_REASON_INTERFACE_UP] = "if-up",            \
    [FIB_NODE_BW_REASON_INTERFACE_DOWN] = "if-down",        \
    [FIB_NODE_BW_REASON_INTERFACE_DELETE] = "if-delete",    \
    [FIB_NODE_BW_REASON_ADJ_UPDATE] = "adj-update",         \
    [FIB_NODE_BW_REASON_ADJ_MTU] = "adj-mtu",               \
    [FIB_NODE_BW_REASON_ADJ_DOWN] = "adj-down",             \
}

#define FOR_EACH_FIB_NODE_BW_REASON(_item) \
    for (_item = FIB_NODE_BW_REASON_FIRST; \
	 _item <= FIB_NODE_BW_REASON_LAST; \
	 _item++)

/**
 * Flags enum constructed from the reaons
 */
typedef enum fib_node_bw_reason_flag_t_ {
    FIB_NODE_BW_REASON_FLAG_NONE = 0,
    FIB_NODE_BW_REASON_FLAG_RESOLVE = (1 << FIB_NODE_BW_REASON_RESOLVE),
    FIB_NODE_BW_REASON_FLAG_EVALUATE = (1 << FIB_NODE_BW_REASON_EVALUATE),
    FIB_NODE_BW_REASON_FLAG_INTERFACE_UP = (1 << FIB_NODE_BW_REASON_INTERFACE_UP),
    FIB_NODE_BW_REASON_FLAG_INTERFACE_DOWN = (1 << FIB_NODE_BW_REASON_INTERFACE_DOWN),
    FIB_NODE_BW_REASON_FLAG_INTERFACE_DELETE = (1 << FIB_NODE_BW_REASON_INTERFACE_DELETE),
    FIB_NODE_BW_REASON_FLAG_ADJ_UPDATE = (1 << FIB_NODE_BW_REASON_ADJ_UPDATE),
    FIB_NODE_BW_REASON_FLAG_ADJ_MTU = (1 << FIB_NODE_BW_REASON_ADJ_MTU),
    FIB_NODE_BW_REASON_FLAG_ADJ_DOWN = (1 << FIB_NODE_BW_REASON_ADJ_DOWN),
} __attribute__ ((packed)) fib_node_bw_reason_flag_t;

STATIC_ASSERT(sizeof(fib_node_bw_reason_flag_t) < 2,
	      "BW Reason enum < 2 byte. Consequences for cover_upd_res_t");

extern u8 *format_fib_node_bw_reason(u8 *s, va_list *args);

/**
 * Flags on the walk
 */
typedef enum fib_node_bw_flags_t_
{
    FIB_NODE_BW_FLAG_NONE = 0,
    /**
     * Force the walk to be synchronous
     */
    FIB_NODE_BW_FLAG_FORCE_SYNC = (1 << 0),
} fib_node_bw_flags_t;

/**
 * Forward declarations
 */
struct fib_node_t_;

/**
 * A representation of one pointer to another node.
 * To fully qualify a node, one must know its type and its index so it
 * can be retrieved from the appropriate pool. Direct pointers to nodes
 * are forbidden, since all nodes are allocated from pools, which are vectors,
 * and thus subject to realloc at any time.
 */
typedef struct fib_node_ptr_t_ {
    /**
     * node type
     */
    fib_node_type_t fnp_type;
    /**
     * node's index
     */
    fib_node_index_t fnp_index;
} fib_node_ptr_t;

/**
 * @brief A list of FIB nodes.
 */
typedef u32 fib_node_list_t;

/**
 * Context passed between object during a back walk.
 */
typedef struct fib_node_back_walk_ctx_t_ {
    /**
     * The reason/trigger for the backwalk
     */
    fib_node_bw_reason_flag_t fnbw_reason;

    /**
     * additional flags for the walk
     */
    fib_node_bw_flags_t fnbw_flags;

    /**
     * the number of levels the walk has already traversed.
     * this value is maintained by the walk infra, tp limit the depth of
     * a walk so it does not run indefinately the presence of a loop/cycle
     * in the graph.
     */
    u32 fnbw_depth;
} fib_node_back_walk_ctx_t;

/**
 * We consider a depth of 32 to be sufficient to cover all sane
 * network topologies. Anything more is then an indication that
 * there is a loop/cycle in the FIB graph.
 * Note that all object types contribute to 1 to the depth.
 */
#define FIB_NODE_GRAPH_MAX_DEPTH ((u32)32)

/**
 * A callback function for walking a node dependency list
 */
typedef int (*fib_node_ptr_walk_t)(fib_node_ptr_t *depend,
				   void *ctx);

/**
 * A list of dependent nodes.
 * This is currently implemented as a hash_table of fib_node_ptr_t
 */
typedef fib_node_ptr_t fib_node_ptr_list_t;

/**
 * Return code from a back walk function
 */
typedef enum fib_node_back_walk_rc_t_ {
    FIB_NODE_BACK_WALK_MERGE,
    FIB_NODE_BACK_WALK_CONTINUE,
} fib_node_back_walk_rc_t;

/**
 * Function definition to backwalk a FIB node
 */
typedef fib_node_back_walk_rc_t (*fib_node_back_walk_t)(
    struct fib_node_t_ *node,
    fib_node_back_walk_ctx_t *ctx);

/**
 * Function definition to get a FIB node from its index
 */
typedef struct fib_node_t_* (*fib_node_get_t)(fib_node_index_t index);

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
typedef void (*fib_node_last_lock_gone_t)(struct fib_node_t_ *node);

/**
 * Function definition to display the amount of memory used by a type.
 * Implementations should call fib_show_memory_usage()
 */
typedef void (*fib_node_memory_show_t)(void);

/**
 * A FIB graph nodes virtual function table
 */
typedef struct fib_node_vft_t_ {
    fib_node_get_t fnv_get;
    fib_node_last_lock_gone_t fnv_last_lock;
    fib_node_back_walk_t fnv_back_walk;
    format_function_t *fnv_format;
    fib_node_memory_show_t fnv_mem_show;
} fib_node_vft_t;

/**
 * An node in the FIB graph
 *
 * Objects in the FIB form a graph.
 */
typedef struct fib_node_t_ {
    /**
     * The node's type. make sure we are dynamic/down casting correctly
     */
    fib_node_type_t fn_type;

    /**
     * Some pad space the concrete/derived type is free to use
     */
    u16 fn_pad;

    /**
     * Vector of nodes that depend upon/use/share this node
     */
    fib_node_list_t fn_children;

    /**
     * Number of dependents on this node. This number includes the number
     * of children
     */
    u32 fn_locks;
} fib_node_t;

STATIC_ASSERT(sizeof(fib_node_t) == 12, "FIB node type is growing");

/**
 * @brief
 *  Register the function table for a given type
 *
 * @param ft
 *  FIB node type
 *
 * @param vft
 * virtual function table
 */
extern void fib_node_register_type (fib_node_type_t ft,
				    const fib_node_vft_t *vft);

/**
 * @brief
 *  Create a new FIB node type and Register the function table for it.
 *
 * @param vft
 * virtual function table
 *
 * @return new FIB node type
 */
extern fib_node_type_t fib_node_register_new_type (const fib_node_vft_t *vft);

/**
 * @brief Show the memory usage for a type
 *
 * This should be invoked by the type in response to the infra calling
 * its registered memory show function
 *
 * @param name the name of the type
 * @param in_use_elts The number of elements in use
 * @param allocd_elts The number of allocated pool elemenets
 * @param size_elt The size of one element
 */
extern void fib_show_memory_usage(const char *name,
				  u32 in_use_elts,
				  u32 allocd_elts,
				  size_t size_elt);

extern void fib_node_init(fib_node_t *node,
			  fib_node_type_t ft);
extern void fib_node_deinit(fib_node_t *node);

extern void fib_node_lock(fib_node_t *node);
extern void fib_node_unlock(fib_node_t *node);

extern u32 fib_node_get_n_children(fib_node_type_t parent_type,
                                   fib_node_index_t parent_index);
extern u32 fib_node_child_add(fib_node_type_t parent_type,
			      fib_node_index_t parent_index,
			      fib_node_type_t child_type,
			      fib_node_index_t child_index);
extern void fib_node_child_remove(fib_node_type_t parent_type,
                                  fib_node_index_t parent_index,
                                  fib_node_index_t sibling_index);

extern fib_node_back_walk_rc_t fib_node_back_walk_one(fib_node_ptr_t *ptr,
                                                      fib_node_back_walk_ctx_t *ctx);

extern u8* fib_node_children_format(fib_node_list_t list,
				    u8 *s);

extern const char* fib_node_type_get_name(fib_node_type_t type);

static inline int
fib_node_index_is_valid (fib_node_index_t ni)
{
    return (FIB_NODE_INDEX_INVALID != ni);
}

#endif

