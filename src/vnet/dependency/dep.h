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

#ifndef __DEP_H__
#define __DEP_H__

#include <vlib/vlib.h>

typedef u8 dep_type_t;

#define DEP_TYPE_FIRST 0

typedef u32 dep_index_t;

#define DEP_INDEX_INVALID ((u32) ~0)

/**
 * Reasons for backwalking the dependency object graph
 * resolve  - Walk to re-resolve the child.
 *            Used when the parent is no longer a valid resolution target
 * evaluate - Walk to re-evaluate the forwarding contributed by the parent.
 *            Used when a parent's forwarding changes and the child needs to
 *            incorporate this change in its forwarding.
 * if-up    - A resolving interface has come up
 * if-down  - A resolving interface has gone down
 * if-bind  - A resolving interface has been bound to another table
 * if-delete - A resolving interface has been deleted.
 * adj-update- Walk to re-collapse the multipath adjs when the rewrite of
 *             a unipath adjacency changes
 * adj-mtu   - Walk update the adjacency MTU
 * adj-down  -Walk to update children to inform them the adjacency is now down.
 */
#define foreach_dep_back_walk_reason                                          \
  _ (RESOLVE, "resovle")                                                      \
  _ (EVALUATE, "evaulate")                                                    \
  _ (INTERFACE_UP, "if-up")                                                   \
  _ (INTERFACE_DOWN, "if-down")                                               \
  _ (INTERFACE_BIND, "if-bind")                                               \
  _ (INTERFACE_DELETE, "if-delete")                                           \
  _ (ADJ_UPDATE, "adj-update")                                                \
  _ (ADJ_MTU, "adj-mtu")                                                      \
  _ (ADJ_DOWN, "adj-down")

typedef enum dep_bw_reason_t_
{
#define _(a, b) DEP_BW_REASON_##a,
  foreach_dep_back_walk_reason
#undef _
} __clib_packed dep_bw_reason_t;

#define DEP_BW_N_REASONS (DEP_BW_REASON_ADJ_DOWN + 1)

#define FOR_EACH_DEP_BW_REASON(_item)                                         \
  for (_item = DEP_BW_REASON_FIRST; _item <= DEP_BW_REASON_LAST; _item++)

typedef enum dep_bw_reason_flag_t_
{
  DEP_BW_REASON_FLAG_NONE,
#define _(a, b) DEP_BW_REASON_FLAG_##a = (1 << DEP_BW_REASON_##a),
  foreach_dep_back_walk_reason
#undef _
} __clib_packed dep_bw_reason_flag_t;

STATIC_ASSERT (sizeof (dep_bw_reason_flag_t) < 3, "BW Reason enum < 3 byte");

extern u8 *format_dep_bw_reason (u8 *s, va_list *args);

/**
 * Walk return code
 */
typedef enum walk_rc_t_
{
  WALK_STOP,
  WALK_CONTINUE,
} walk_rc_t;

/**
 * Flags on the walk
 */
typedef enum dep_bw_flags_t_
{
  DEP_BW_FLAG_NONE = 0,
  /**
   * Force the walk to be synchronous
   */
  DEP_BW_FLAG_FORCE_SYNC = (1 << 0),
} dep_bw_flags_t;

/**
 * Context passed between object during a back walk.
 */
typedef struct dep_back_walk_ctx_t_
{
  /**
   * The reason/trigger for the backwalk
   */
  dep_bw_reason_flag_t dbw_reason;

  /**
   * additional flags for the walk
   */
  dep_bw_flags_t dbw_flags;

  /**
   * the number of levels the walk has already traversed.
   * this value is maintained by the walk infra, tp limit the depth of
   * a walk so it does not run indefinately the presence of a loop/cycle
   * in the graph.
   */
  u32 dbw_depth;

  /**
   * Additional data associated with the reason the walk is occuring
   */
  union
  {
    struct
    {
      u32 dbw_from_fib_index;
      u32 dbw_to_fib_index;
    } interface_bind;
  };
} dep_back_walk_ctx_t;

/**
 * A representation of one pointer to another node.
 * To fully qualify a node, one must know its type and its index so it
 * can be retrieved from the appropriate pool. Direct pointers to nodes
 * are forbidden, since all nodes are allocated from pools, which are vectors,
 * and thus subject to realloc at any time.
 */
typedef struct dep_ptr_t_
{
  /**
   * node type
   */
  dep_type_t dp_type;
  /**
   * node's index
   */
  dep_index_t dp_index;
} dep_ptr_t;

/**
 * @brief A list of FIB nodes.
 */
typedef u32 dep_list_t;

/**
 * An node in the FIB graph
 *
 * Objects in the FIB form a graph.
 */
typedef struct dep_t_
{
  /**
   * The node's type. make sure we are dynamic/down casting correctly
   */
  dep_type_t d_type;

  /**
   * Some pad space the concrete/derived type is free to use
   */
  u16 d_pad;

  /**
   * Vector of nodes that depend upon/use/share this node
   */
  dep_list_t d_children;

  /**
   * Number of dependents on this node. This number includes the number
   * of children
   */
  u32 d_locks;
} dep_t;

STATIC_ASSERT_SIZEOF (dep_t, 12);

/**
 * A list of dependent nodes.
 * This is currently implemented as a hash_table of dep_ptr_t
 */
typedef dep_ptr_t dep_ptr_list_t;

/**
 * Return code from a back walk function
 */
typedef enum dep_back_walk_rc_t_
{
  DEP_BACK_WALK_MERGE,
  DEP_BACK_WALK_CONTINUE,
} dep_back_walk_rc_t;

/**
 * Function definition to backwalk a FIB node
 */
typedef dep_back_walk_rc_t (*dep_back_walk_t) (struct dep_t_ *node,
					       dep_back_walk_ctx_t *ctx);

/**
 * Function definition to get a FIB node from its index
 */
typedef dep_t *(*dep_get_t) (dep_index_t index);

/**
 * Function definition to inform the FIB node that its last lock has gone.
 */
typedef void (*dep_last_lock_gone_t) (dep_t *node);

/**
 * A FIB graph nodes virtual function table
 */
typedef struct dep_vft_t_
{
  dep_get_t dv_get;
  dep_last_lock_gone_t dv_last_lock;
  dep_back_walk_t dv_back_walk;
} dep_vft_t;

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
extern dep_type_t dep_register_type (const char *name, const dep_vft_t *vft);

extern void dep_init (dep_t *node, dep_type_t dt);
extern void dep_deinit (dep_t *node);

extern void dep_lock (dep_t *node);
extern void dep_unlock (dep_t *node);

extern u32 dep_get_n_children (dep_type_t parent_type,
			       dep_index_t parent_index);
extern u32 dep_child_add (dep_type_t parent_type, dep_index_t parent_index,
			  dep_type_t child_type, dep_index_t child_index);
extern void dep_child_remove (dep_type_t parent_type, dep_index_t parent_index,
			      dep_index_t sibling_index);

extern dep_back_walk_rc_t dep_back_walk_one (dep_ptr_t *ptr,
					     dep_back_walk_ctx_t *ctx);

extern u8 *dep_children_format (dep_list_t list, u8 *s);

extern const char *dep_type_get_name (dep_type_t type);

static inline int
dep_index_is_valid (dep_index_t di)
{
  return (DEP_INDEX_INVALID != di);
}

#endif

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
