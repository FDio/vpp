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

    /**
     * The index of the path. This is the global index, not the path's
     * position in the path-list.
     */
    fib_node_index_t fpe_path_index;
} fib_path_ext_t;

struct fib_entry_t_;

extern u8 * format_fib_path_ext(u8 * s, va_list * args);

extern void fib_path_ext_init(fib_path_ext_t *path_ext,
			      fib_node_index_t path_list_index,
			      const fib_route_path_t *rpath);

extern int fib_path_ext_cmp(fib_path_ext_t *path_ext,
			    const fib_route_path_t *rpath);

extern void fib_path_ext_resolve(fib_path_ext_t *path_ext,
				 fib_node_index_t path_list_index);

extern load_balance_path_t *fib_path_ext_stack(fib_path_ext_t *path_ext,
                                               fib_forward_chain_type_t fct,
                                               fib_forward_chain_type_t imp_null_fct,
                                               load_balance_path_t *nhs);

#endif

