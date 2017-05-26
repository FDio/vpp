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

#ifndef __FIB_PATH_EXT_H__
#define __FIB_PATH_EXT_H__

#include <vnet/mpls/mpls.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/load_balance.h>

/**
 * A description of the type of path extension
 */
typedef enum fib_path_ext_type_t_
{
    /**
     * An MPLS extension that maintains the path's outgoing labels,
     */
    FIB_PATH_EXT_MPLS,
    /**
     * A adj-source extension indicating the path's refinement criteria
     * result
     */
    FIB_PATH_EXT_ADJ,
} fib_path_ext_type_t;

/**
 * Flags present on an ADJ sourced path-extension
 */
typedef enum fib_path_ext_adj_attr_t_
{
    FIB_PATH_EXT_ADJ_ATTR_REFINES_COVER,
} fib_path_ext_adj_attr_t;

typedef enum fib_path_ext_adj_flags_t_
{
    FIB_PATH_EXT_ADJ_FLAG_NONE = 0,
    FIB_PATH_EXT_ADJ_FLAG_REFINES_COVER = (1 << FIB_PATH_EXT_ADJ_ATTR_REFINES_COVER),
} fib_path_ext_adj_flags_t;

#define FIB_PATH_EXT_ADJ_ATTR_NAMES {                               \
    [FIB_PATH_EXT_ADJ_ATTR_REFINES_COVER] = "refines-cover",        \
}

#define FOR_EACH_PATH_EXT_ADJ_ATTR(_item)               \
    for (_item = FIB_PATH_EXT_ADJ_ATTR_REFINES_COVER;   \
         _item <= FIB_PATH_EXT_ADJ_ATTR_REFINES_COVER;  \
         _item++)

/**
 * A path extension is a per-entry addition to the forwarding information
 * when packets are sent for that entry over that path.
 *
 * For example:
 *    ip route add 1.1.1.1/32 via 10.10.10.10 out-label 100
 *
 * The out-going MPLS label value 100 is a path-extension. It is a value sepcific
 * to the entry 1.1.1.1/32 and valid only when packets are sent via 10.10.10.10.
 */
typedef struct fib_path_ext_t_
{
    /**
     * A description of the path that is being extended.
     * This description is used to match this extension with the [changing]
     * instance of a fib_path_t that is extended
     */
    fib_route_path_t fpe_path;
#define fpe_label_stack fpe_path.frp_label_stack

    union {
        /**
         * For an ADJ type extension
         *
         * Flags describing the adj state
         */
        fib_path_ext_adj_flags_t fpe_adj_flags;
    };

    /**
     * The type of path extension
     */
    fib_path_ext_type_t fpe_type;

    /**
     * The index of the path. This is the global index, not the path's
     * position in the path-list.
     */
    fib_node_index_t fpe_path_index;
} __attribute__ ((packed))  fib_path_ext_t;

extern u8 * format_fib_path_ext(u8 * s, va_list * args);

extern int fib_path_ext_cmp(fib_path_ext_t *path_ext,
			    const fib_route_path_t *rpath);

extern void fib_path_ext_resolve(fib_path_ext_t *path_ext,
				 fib_node_index_t path_list_index);

extern load_balance_path_t *fib_path_ext_stack(fib_path_ext_t *path_ext,
                                               fib_forward_chain_type_t fct,
                                               fib_forward_chain_type_t imp_null_fct,
                                               load_balance_path_t *nhs);

extern fib_path_ext_t * fib_path_ext_list_push_back (fib_path_ext_list_t *list,
                                                     fib_node_index_t path_list_index,
                                                     fib_path_ext_type_t ext_type,
                                                     const fib_route_path_t *rpath);

extern fib_path_ext_t * fib_path_ext_list_insert (fib_path_ext_list_t *list,
                                                  fib_node_index_t path_list_index,
                                                  fib_path_ext_type_t ext_type,
                                                  const fib_route_path_t *rpath);

extern u8* format_fib_path_ext_list (u8 * s, va_list * args);

extern void fib_path_ext_list_remove (fib_path_ext_list_t *list,
                                      fib_path_ext_type_t ext_type,
                                      const fib_route_path_t *rpath);

extern fib_path_ext_t * fib_path_ext_list_find (const fib_path_ext_list_t *list,
                                                fib_path_ext_type_t ext_type,
                                                const fib_route_path_t *rpath);
extern fib_path_ext_t * fib_path_ext_list_find_by_path_index (const fib_path_ext_list_t *list,
                                                              fib_node_index_t path_index);
extern void fib_path_ext_list_resolve(fib_path_ext_list_t *list,
                                      fib_node_index_t path_list_index);

extern int fib_path_ext_list_length(const fib_path_ext_list_t *list);
extern void fib_path_ext_list_flush(fib_path_ext_list_t *list);

#endif

