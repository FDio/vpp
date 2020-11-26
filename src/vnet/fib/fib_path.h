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
 * Given a route of the form;
 *   q.r.s.t/Y
 *     via <interface> <next-hop>
 *
 * The prefix is: q.r.s.t./Y
 * the path is: 'via <interface> <next-hop>
 *
 * The path is the description of where to send the traffic, and the
 * the prefix is a description of which traffic to send.
 * It is the aim of the FIB to resolve the path, i.e. to find the corresponding
 * adjacency to match the path's description.
 */

#ifndef __FIB_PATH_H__
#define __FIB_PATH_H__

#include <vnet/ip/ip.h>
#include <vnet/dpo/load_balance.h>

#include <vnet/fib/fib_types.h>
#include <vnet/adj/adj_types.h>
#include <vnet/bier/bier_types.h>

/**
 * Enurmeration of path configuration attributes
 */
typedef enum fib_path_cfg_attribute_t_ {
    /**
     * Marker. Add new types after this one.
     */
    FIB_PATH_CFG_ATTRIBUTE_FIRST = 0,
    /**
     * The path is forced to a drop, whatever the next-hop info says.
     * something somewhere knows better...
     */
    FIB_PATH_CFG_ATTRIBUTE_DROP = FIB_PATH_CFG_ATTRIBUTE_FIRST,
    /**
     * The path uses an adj that is exclusive. I.e. it is known only by
     * the source of the route.
     */
    FIB_PATH_CFG_ATTRIBUTE_EXCLUSIVE,
    /**
     * Recursion constraint via host
     */
    FIB_PATH_CFG_ATTRIBUTE_RESOLVE_HOST,
    /**
     * Recursion constraint via attached
     */
    FIB_PATH_CFG_ATTRIBUTE_RESOLVE_ATTACHED,
    /**
     * The path is attached
     */
    FIB_PATH_CFG_ATTRIBUTE_ATTACHED,
    /**
     * The path is a for-us path
     */
    FIB_PATH_CFG_ATTRIBUTE_INTF_RX,
    /**
     * The path is a deag with rpf-id
     */
    FIB_PATH_CFG_ATTRIBUTE_RPF_ID,
    /**
     * The path is an interface recieve
     */
    FIB_PATH_CFG_ATTRIBUTE_LOCAL,
    /**
     * The path reolves via an ICMP unreachable
     */
    FIB_PATH_CFG_ATTRIBUTE_ICMP_UNREACH,
    /**
     * The path reolves via an ICMP prohibit
     */
    FIB_PATH_CFG_ATTRIBUTE_ICMP_PROHIBIT,
    /**
     * The path reolves via a classify
     */
    FIB_PATH_CFG_ATTRIBUTE_CLASSIFY,
    /**
     * The deag path does a source lookup
     */
    FIB_PATH_CFG_ATTRIBUTE_DEAG_SRC,
    /**
     * The path pops a Psuedo Wire Control Word
     */
    FIB_PATH_CFG_ATTRIBUTE_POP_PW_CW,
    /**
     * The path is a glean
     */
    FIB_PATH_CFG_ATTRIBUTE_GLEAN,
    /**
     * Marker. Add new types before this one, then update it.
     */
    FIB_PATH_CFG_ATTRIBUTE_LAST = FIB_PATH_CFG_ATTRIBUTE_GLEAN,
} __attribute__ ((packed)) fib_path_cfg_attribute_t;

/**
 * The maximum number of path attributes
 */
#define FIB_PATH_CFG_ATTRIBUTE_MAX (FIB_PATH_CFG_ATTRIBUTE_LAST + 1)

#define FIB_PATH_CFG_ATTRIBUTES {			\
    [FIB_PATH_CFG_ATTRIBUTE_DROP]  = "drop",	        \
    [FIB_PATH_CFG_ATTRIBUTE_EXCLUSIVE] = "exclusive",	\
    [FIB_PATH_CFG_ATTRIBUTE_RESOLVE_HOST] = "resolve-host", \
    [FIB_PATH_CFG_ATTRIBUTE_RESOLVE_ATTACHED] = "resolve-attached", \
    [FIB_PATH_CFG_ATTRIBUTE_LOCAL] = "local",	        \
    [FIB_PATH_CFG_ATTRIBUTE_ICMP_UNREACH] = "icmp-unreach",   \
    [FIB_PATH_CFG_ATTRIBUTE_ICMP_PROHIBIT] = "icmp-prohibit", \
    [FIB_PATH_CFG_ATTRIBUTE_CLASSIFY] = "classify", \
    [FIB_PATH_CFG_ATTRIBUTE_ATTACHED] = "attached",	\
    [FIB_PATH_CFG_ATTRIBUTE_INTF_RX] = "interface-rx",	\
    [FIB_PATH_CFG_ATTRIBUTE_RPF_ID] = "rpf-id",         \
    [FIB_PATH_CFG_ATTRIBUTE_DEAG_SRC] = "deag-src",     \
    [FIB_PATH_CFG_ATTRIBUTE_POP_PW_CW] = "pop-pw-cw",   \
    [FIB_PATH_CFG_ATTRIBUTE_GLEAN] = "glean",           \
}

#define FOR_EACH_FIB_PATH_CFG_ATTRIBUTE(_item) \
    for (_item = FIB_PATH_CFG_ATTRIBUTE_FIRST; \
	 _item <= FIB_PATH_CFG_ATTRIBUTE_LAST; \
	 _item++)

/**
 * Path config flags from the attributes
 */
typedef enum fib_path_cfg_flags_t_ {
    FIB_PATH_CFG_FLAG_NONE  = 0,
    FIB_PATH_CFG_FLAG_DROP  = (1 << FIB_PATH_CFG_ATTRIBUTE_DROP),
    FIB_PATH_CFG_FLAG_EXCLUSIVE = (1 << FIB_PATH_CFG_ATTRIBUTE_EXCLUSIVE),
    FIB_PATH_CFG_FLAG_RESOLVE_HOST = (1 << FIB_PATH_CFG_ATTRIBUTE_RESOLVE_HOST),
    FIB_PATH_CFG_FLAG_RESOLVE_ATTACHED = (1 << FIB_PATH_CFG_ATTRIBUTE_RESOLVE_ATTACHED),
    FIB_PATH_CFG_FLAG_LOCAL = (1 << FIB_PATH_CFG_ATTRIBUTE_LOCAL),
    FIB_PATH_CFG_FLAG_ICMP_UNREACH = (1 << FIB_PATH_CFG_ATTRIBUTE_ICMP_UNREACH),
    FIB_PATH_CFG_FLAG_ICMP_PROHIBIT = (1 << FIB_PATH_CFG_ATTRIBUTE_ICMP_PROHIBIT),
    FIB_PATH_CFG_FLAG_CLASSIFY = (1 << FIB_PATH_CFG_ATTRIBUTE_CLASSIFY),
    FIB_PATH_CFG_FLAG_ATTACHED = (1 << FIB_PATH_CFG_ATTRIBUTE_ATTACHED),
    FIB_PATH_CFG_FLAG_INTF_RX = (1 << FIB_PATH_CFG_ATTRIBUTE_INTF_RX),
    FIB_PATH_CFG_FLAG_RPF_ID = (1 << FIB_PATH_CFG_ATTRIBUTE_RPF_ID),
    FIB_PATH_CFG_FLAG_DEAG_SRC = (1 << FIB_PATH_CFG_ATTRIBUTE_DEAG_SRC),
    FIB_PATH_CFG_FLAG_POP_PW_CW = (1 << FIB_PATH_CFG_ATTRIBUTE_POP_PW_CW),
    FIB_PATH_CFG_FLAG_GLEAN = (1 << FIB_PATH_CFG_ATTRIBUTE_GLEAN),
} __attribute__ ((packed)) fib_path_cfg_flags_t;

typedef enum fib_path_format_flags_t_
{
    FIB_PATH_FORMAT_FLAGS_NONE = 0,
    FIB_PATH_FORMAT_FLAGS_ONE_LINE = (1 << 0),
} fib_format_path_flags_t;

extern u8 *format_fib_path(u8 *s, va_list *args);

extern fib_node_index_t fib_path_create(fib_node_index_t pl_index,
					const fib_route_path_t *path);
extern fib_node_index_t fib_path_create_special(fib_node_index_t pl_index,
						dpo_proto_t nh_proto,
						fib_path_cfg_flags_t flags,
						const dpo_id_t *dpo);

extern int fib_path_cmp(fib_node_index_t path_index1,
			fib_node_index_t path_index2);
extern int fib_path_cmp_for_sort(void * a1, void * a2);
extern int fib_path_cmp_w_route_path(fib_node_index_t path_index,
				     const fib_route_path_t *rpath);
extern fib_node_index_t fib_path_copy(fib_node_index_t path_index,
				      fib_node_index_t path_list_index);
extern int fib_path_resolve(fib_node_index_t path_index);
extern int fib_path_is_resolved(fib_node_index_t path_index);
extern int fib_path_is_recursive_constrained(fib_node_index_t path_index);
extern int fib_path_is_exclusive(fib_node_index_t path_index);
extern int fib_path_is_deag(fib_node_index_t path_index);
extern int fib_path_is_looped(fib_node_index_t path_index);
extern dpo_proto_t fib_path_get_proto(fib_node_index_t path_index);
extern void fib_path_destroy(fib_node_index_t path_index);
extern uword fib_path_hash(fib_node_index_t path_index);
extern load_balance_path_t * fib_path_append_nh_for_multipath_hash(
    fib_node_index_t path_index,
    fib_forward_chain_type_t fct,
    load_balance_path_t *hash_key);
extern void fib_path_stack_mpls_disp(fib_node_index_t path_index,
                                     dpo_proto_t payload_proto,
                                     fib_mpls_lsp_mode_t mode,
                                     dpo_id_t *dpo);
extern void fib_path_contribute_forwarding(fib_node_index_t path_index,
					   fib_forward_chain_type_t type,
					   dpo_id_t *dpo);
extern void fib_path_contribute_urpf(fib_node_index_t path_index,
				     index_t urpf);
extern adj_index_t fib_path_get_adj(fib_node_index_t path_index);
extern int fib_path_recursive_loop_detect(fib_node_index_t path_index,
					  fib_node_index_t **entry_indicies);
extern u32 fib_path_get_resolving_interface(fib_node_index_t fib_entry_index);
extern index_t fib_path_get_resolving_index(fib_node_index_t path_index);
extern u16 fib_path_get_weight(fib_node_index_t path_index);
extern u16 fib_path_get_preference(fib_node_index_t path_index);
extern u32 fib_path_get_rpf_id(fib_node_index_t path_index);

extern void fib_path_module_init(void);

/**
 * Path encode context to use when walking a path-list
 * to encode paths
 */
typedef struct fib_path_encode_ctx_t_
{
    fib_route_path_t *rpaths;
} fib_path_encode_ctx_t;

extern fib_path_list_walk_rc_t fib_path_encode(fib_node_index_t path_list_index,
                                               fib_node_index_t path_index,
                                               const struct fib_path_ext_t_ *ext_list,
                                               void *ctx);

#endif
