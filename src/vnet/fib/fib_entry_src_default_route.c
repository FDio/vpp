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

#include "fib_entry.h"
#include "fib_entry_src.h"

/**
 * Source initialisation Function 
 */
static void
fib_entry_src_default_route_init (fib_entry_src_t *src)
{
    src->fes_flags = FIB_ENTRY_SRC_FLAG_NONE;
}

static void
fib_entry_src_default_route_remove (fib_entry_src_t *src)
{
    src->fes_pl = FIB_NODE_INDEX_INVALID;
}

static void
fib_entry_src_default_route_add (fib_entry_src_t *src,
				 const fib_entry_t *entry,
				 fib_entry_flag_t flags,
				 dpo_proto_t proto,
				 const dpo_id_t *dpo)
{
    src->fes_pl = fib_path_list_create_special(proto,
					       FIB_PATH_LIST_FLAG_DROP,
					       dpo);
}

const static fib_entry_src_vft_t interface_src_vft = {
    .fesv_init = fib_entry_src_default_route_init,
    .fesv_add = fib_entry_src_default_route_add,
    .fesv_remove = fib_entry_src_default_route_remove,
};

void
fib_entry_src_default_route_register (void)
{
    fib_entry_src_register(FIB_SOURCE_DEFAULT_ROUTE, &interface_src_vft);    
}


