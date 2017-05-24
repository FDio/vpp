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

#ifndef __FIB_PATH_LIST_H__
#define __FIB_PATH_LIST_H__

#include <vlib/vlib.h>
#include <vnet/adj/adj.h>

#include <vnet/fib/fib_node.h>
#include <vnet/fib/fib_path.h>

/**
 * Enumeration of path-list flags.
 */
typedef enum fib_path_list_attribute_t_ {
    /**
     * Marker. Add new flags after this one.
     */
    FIB_PATH_LIST_ATTRIBUTE_FIRST = 0,
    /**
     * This path list is shareable. Shareable path-lists
     * are inserted into the path-list data-base.
     * All path-list are inherently shareable, the reason we share some and
     * not others is to limit the size of the path-list database. This DB must
     * be searched for each route update.
     */
    FIB_PATH_LIST_ATTRIBUTE_SHARED = FIB_PATH_LIST_ATTRIBUTE_FIRST,
    /**
     * explicit drop path-list. Used when the entry source needs to 
     * force a drop, despite the fact the path info is present.
     */
    FIB_PATH_LIST_ATTRIBUTE_DROP,
    /**
     * explicit local path-list.
     */
    FIB_PATH_LIST_ATTRIBUTE_LOCAL,
    /**
     * exclusive path-list. Exclusive means the path will resolve via the
     * exclusive (user provided) adj.
     */
    FIB_PATH_LIST_ATTRIBUTE_EXCLUSIVE,
    /**
     * resolved path-list
     */
    FIB_PATH_LIST_ATTRIBUTE_RESOLVED,
    /**
     * looped path-list. one path looped implies the whole list is
     */
    FIB_PATH_LIST_ATTRIBUTE_LOOPED,
    /**
     * a popular path-ist is one that is shared amongst many entries.
     * Path list become popular as they gain more children, but they
     * don't become unpopular as they lose them.
     */
    FIB_PATH_LIST_ATTRIBUTE_POPULAR,
    /**
     * no uRPF - do not generate unicast RPF list for this path-list
     */
    FIB_PATH_LIST_ATTRIBUTE_NO_URPF,
    /**
     * Marher. Add new flags before this one, and then update it.
     */
    FIB_PATH_LIST_ATTRIBUTE_LAST = FIB_PATH_LIST_ATTRIBUTE_NO_URPF,
} fib_path_list_attribute_t;

typedef enum fib_path_list_flags_t_ {
    FIB_PATH_LIST_FLAG_NONE      = 0,
    FIB_PATH_LIST_FLAG_SHARED    = (1 << FIB_PATH_LIST_ATTRIBUTE_SHARED),
    FIB_PATH_LIST_FLAG_DROP      = (1 << FIB_PATH_LIST_ATTRIBUTE_DROP),
    FIB_PATH_LIST_FLAG_LOCAL     = (1 << FIB_PATH_LIST_ATTRIBUTE_LOCAL),
    FIB_PATH_LIST_FLAG_EXCLUSIVE = (1 << FIB_PATH_LIST_ATTRIBUTE_EXCLUSIVE),
    FIB_PATH_LIST_FLAG_RESOLVED  = (1 << FIB_PATH_LIST_ATTRIBUTE_RESOLVED),
    FIB_PATH_LIST_FLAG_LOOPED    = (1 << FIB_PATH_LIST_ATTRIBUTE_LOOPED),
    FIB_PATH_LIST_FLAG_POPULAR   = (1 << FIB_PATH_LIST_ATTRIBUTE_POPULAR),
    FIB_PATH_LIST_FLAG_NO_URPF   = (1 << FIB_PATH_LIST_ATTRIBUTE_NO_URPF),
} fib_path_list_flags_t;

#define FIB_PATH_LIST_ATTRIBUTES {       		 \
    [FIB_PATH_LIST_ATTRIBUTE_SHARED]    = "shared",	 \
    [FIB_PATH_LIST_ATTRIBUTE_RESOLVED]  = "resolved",	 \
    [FIB_PATH_LIST_ATTRIBUTE_DROP]      = "drop",	 \
    [FIB_PATH_LIST_ATTRIBUTE_EXCLUSIVE] = "exclusive",   \
    [FIB_PATH_LIST_ATTRIBUTE_LOCAL]     = "local",       \
    [FIB_PATH_LIST_ATTRIBUTE_LOOPED]    = "looped",	 \
    [FIB_PATH_LIST_ATTRIBUTE_POPULAR]   = "popular",	 \
    [FIB_PATH_LIST_ATTRIBUTE_NO_URPF]   = "no-uRPF",	 \
}

#define FOR_EACH_PATH_LIST_ATTRIBUTE(_item)		\
    for (_item = FIB_PATH_LIST_ATTRIBUTE_FIRST;		\
	 _item <= FIB_PATH_LIST_ATTRIBUTE_LAST;		\
	 _item++)

extern fib_node_index_t fib_path_list_create(fib_path_list_flags_t flags,
					     const fib_route_path_t *paths);
extern fib_node_index_t fib_path_list_create_special(dpo_proto_t nh_proto,
						     fib_path_list_flags_t flags,
						     const dpo_id_t *dpo);

extern fib_node_index_t fib_path_list_copy_and_path_add(
    fib_node_index_t pl_index,
    fib_path_list_flags_t flags,
    const fib_route_path_t *path);
extern fib_node_index_t fib_path_list_copy_and_path_remove(
    fib_node_index_t pl_index,
    fib_path_list_flags_t flags,
    const fib_route_path_t *path);
extern fib_node_index_t fib_path_list_path_add (
    fib_node_index_t path_list_index,
    const fib_route_path_t *rpaths);
extern fib_node_index_t fib_path_list_path_remove (
    fib_node_index_t path_list_index,
    const fib_route_path_t *rpaths);

extern u32 fib_path_list_get_n_paths(fib_node_index_t pl_index);

extern void fib_path_list_contribute_forwarding(fib_node_index_t path_list_index,
						fib_forward_chain_type_t type,
						dpo_id_t *dpo);
extern void fib_path_list_contribute_urpf(fib_node_index_t path_index,
					  index_t urpf);
extern index_t fib_path_list_get_urpf(fib_node_index_t path_list_index);
extern index_t fib_path_list_get_adj(fib_node_index_t path_list_index,
				     fib_forward_chain_type_t type);

extern u32 fib_path_list_child_add(fib_node_index_t pl_index,
				   fib_node_type_t type,
				   fib_node_index_t child_index);
extern void fib_path_list_child_remove(fib_node_index_t pl_index,
				       fib_node_index_t sibling_index);
extern void fib_path_list_back_walk(fib_node_index_t pl_index,
				    fib_node_back_walk_ctx_t *ctx);
extern void fib_path_list_lock(fib_node_index_t pl_index);
extern void fib_path_list_unlock(fib_node_index_t pl_index);
extern int fib_path_list_recursive_loop_detect(fib_node_index_t path_list_index,
					       fib_node_index_t **entry_indicies);
extern u32 fib_path_list_get_resolving_interface(fib_node_index_t path_list_index);
extern int fib_path_list_is_looped(fib_node_index_t path_list_index);
extern int fib_path_list_is_popular(fib_node_index_t path_list_index);
extern dpo_proto_t fib_path_list_get_proto(fib_node_index_t path_list_index);
extern u8 * fib_path_list_format(fib_node_index_t pl_index,
				 u8 * s);
extern index_t fib_path_list_lb_map_add_or_lock(fib_node_index_t pl_index,
                                                const fib_node_index_t *pis);
extern u32 fib_path_list_find_rpath (fib_node_index_t path_list_index,
                                     const fib_route_path_t *rpath);

/**
 * A callback function type for walking a path-list's paths
 */
typedef fib_path_list_walk_rc_t (*fib_path_list_walk_fn_t)(
    fib_node_index_t pl_index,
    fib_node_index_t path_index,
    void *ctx);

extern void fib_path_list_walk(fib_node_index_t pl_index,
			       fib_path_list_walk_fn_t func,
			       void *ctx);

extern void fib_path_list_module_init(void);

extern void fib_path_list_module_init(void);

/*
 * functions for testing.
 */
u32 fib_path_list_pool_size(void);
u32 fib_path_list_db_size(void);

#endif
