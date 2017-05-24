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
#include "fib_path_list.h"

/**
 * Source initialisation Function 
 */
static void
fib_entry_src_lisp_init (fib_entry_src_t *src)
{
}

/**
 * Source deinitialisation Function 
 */
static void
fib_entry_src_lisp_deinit (fib_entry_src_t *src)
{
}

static void
fib_entry_src_lisp_path_swap (fib_entry_src_t *src,
			      const fib_entry_t *entry,
			      fib_path_list_flags_t pl_flags,
			     const fib_route_path_t *paths)
{
    src->fes_pl = fib_path_list_create((FIB_PATH_LIST_FLAG_SHARED | pl_flags),
				       paths);
}

static void
fib_entry_src_lisp_path_add (fib_entry_src_t *src,
			    const fib_entry_t *entry,
			    fib_path_list_flags_t pl_flags,
			    const fib_route_path_t *paths)
{
    if (FIB_NODE_INDEX_INVALID == src->fes_pl)
    {	
	src->fes_pl =
	    fib_path_list_create((FIB_PATH_LIST_FLAG_SHARED | pl_flags), paths);
    }
    else
    {
	src->fes_pl =
	    fib_path_list_copy_and_path_add(src->fes_pl,
					    (FIB_PATH_LIST_FLAG_SHARED | pl_flags),
					    paths);
    }
}

static void
fib_entry_src_lisp_path_remove (fib_entry_src_t *src,
			       fib_path_list_flags_t pl_flags,
			       const fib_route_path_t *paths)
{
    if (FIB_NODE_INDEX_INVALID != src->fes_pl)
    {
	src->fes_pl =
	    fib_path_list_copy_and_path_remove(src->fes_pl,
					       (FIB_PATH_LIST_FLAG_SHARED | pl_flags),
					       paths);
    }
}

static void
fib_entry_src_lisp_add (fib_entry_src_t *src,
                        const fib_entry_t *entry,
                        fib_entry_flag_t flags,
                        dpo_proto_t proto,
                        const dpo_id_t *dpo)
{
    if (FIB_ENTRY_FLAG_NONE != flags)
    {
	src->fes_pl = fib_path_list_create_special(
	                  proto,
			  fib_entry_src_flags_2_path_list_flags(flags),
			  dpo);
    }
}

static void
fib_entry_src_lisp_remove (fib_entry_src_t *src)
{
    src->fes_pl = FIB_NODE_INDEX_INVALID;
}

static void
fib_entry_src_lisp_set_data (fib_entry_src_t *src,
                             const fib_entry_t *entry,
                             const void *data)
{
    src->lisp.fesl_fib_index = *(u32*)data;
}

static const void*
fib_entry_src_lisp_get_data (fib_entry_src_t *src,
                             const fib_entry_t *entry)
{
    return (&(src->lisp.fesl_fib_index));
}

const static fib_entry_src_vft_t api_src_vft = {
    .fesv_init = fib_entry_src_lisp_init,
    .fesv_deinit = fib_entry_src_lisp_deinit,
    .fesv_add = fib_entry_src_lisp_add,
    .fesv_remove = fib_entry_src_lisp_remove,
    .fesv_path_add = fib_entry_src_lisp_path_add,
    .fesv_path_swap = fib_entry_src_lisp_path_swap,
    .fesv_path_remove = fib_entry_src_lisp_path_remove,
    .fesv_set_data = fib_entry_src_lisp_set_data,
    .fesv_get_data = fib_entry_src_lisp_get_data,
};

void
fib_entry_src_lisp_register (void)
{
    fib_entry_src_register(FIB_SOURCE_LISP, &api_src_vft);
}
