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

#include <vnet/fib/fib_entry.h>
#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_path_ext.h>

/**
 * Source initialisation Function 
 */
static void
fib_entry_src_api_init (fib_entry_src_t *src)
{
}

/**
 * Source deinitialisation Function 
 */
static void
fib_entry_src_api_deinit (fib_entry_src_t *src)
{
}

static void
fib_entry_src_api_path_swap (fib_entry_src_t *src,
                             const fib_entry_t *entry,
			     fib_path_list_flags_t pl_flags,
			     const fib_route_path_t *rpaths)
{
    const fib_route_path_t *rpath;

    fib_path_ext_list_flush(&src->fes_path_exts);

    src->fes_pl = fib_path_list_create((FIB_PATH_LIST_FLAG_SHARED | pl_flags),
				       rpaths);

    vec_foreach(rpath, rpaths)
    {
        if (NULL != rpath->frp_label_stack)
        {
            fib_path_ext_list_push_back(&src->fes_path_exts,
                                        src->fes_pl,
                                        FIB_PATH_EXT_MPLS,
                                        rpath);
        }
    }
}

static void
fib_entry_src_api_path_add (fib_entry_src_t *src,
			    const fib_entry_t *entry,
			    fib_path_list_flags_t pl_flags,
			    const fib_route_path_t *rpaths)
{
    const fib_route_path_t *rpath;

    if (FIB_NODE_INDEX_INVALID == src->fes_pl)
    {	
	src->fes_pl =
	    fib_path_list_create((FIB_PATH_LIST_FLAG_SHARED | pl_flags), rpaths);
    }
    else
    {
	src->fes_pl =
	    fib_path_list_copy_and_path_add(src->fes_pl,
					    (FIB_PATH_LIST_FLAG_SHARED | pl_flags),
					    rpaths);
    }

    /*
     * re-resolve all the path-extensions with the new path-list
     */
    fib_path_ext_list_resolve(&src->fes_path_exts, src->fes_pl);

    /*
     * if the path has a label we need to add a path extension
     */
    vec_foreach(rpath, rpaths)
    {
        if (NULL != rpath->frp_label_stack)
        {
            fib_path_ext_list_insert(&src->fes_path_exts,
                                     src->fes_pl,
                                     FIB_PATH_EXT_MPLS,
                                     rpath);
        }
    }
}

static void
fib_entry_src_api_path_remove (fib_entry_src_t *src,
			       fib_path_list_flags_t pl_flags,
			       const fib_route_path_t *rpaths)
{
    const fib_route_path_t *rpath;

    if (FIB_NODE_INDEX_INVALID != src->fes_pl)
    {
	src->fes_pl =
	    fib_path_list_copy_and_path_remove(src->fes_pl,
					       (FIB_PATH_LIST_FLAG_SHARED | pl_flags),
					       rpaths);
        /*
         * remove the path-extension for the path
         */
        vec_foreach(rpath, rpaths)
        {
            fib_path_ext_list_remove(&src->fes_path_exts, FIB_PATH_EXT_MPLS, rpath);
        };
        /*
         * resolve the remaining extensions
         */
        fib_path_ext_list_resolve(&src->fes_path_exts, src->fes_pl);
    }
}

static void
fib_entry_src_api_add (fib_entry_src_t *src,
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
fib_entry_src_api_remove (fib_entry_src_t *src)
{
    src->fes_pl = FIB_NODE_INDEX_INVALID;
}

const static fib_entry_src_vft_t api_src_vft = {
    .fesv_init = fib_entry_src_api_init,
    .fesv_deinit = fib_entry_src_api_deinit,
    .fesv_add = fib_entry_src_api_add,
    .fesv_remove = fib_entry_src_api_remove,
    .fesv_path_add = fib_entry_src_api_path_add,
    .fesv_path_swap = fib_entry_src_api_path_swap,
    .fesv_path_remove = fib_entry_src_api_path_remove,
};

void
fib_entry_src_api_register (void)
{
    fib_entry_src_register(FIB_SOURCE_PLUGIN_HI, &api_src_vft);
    fib_entry_src_register(FIB_SOURCE_API, &api_src_vft);
    fib_entry_src_register(FIB_SOURCE_CLI, &api_src_vft);
    fib_entry_src_register(FIB_SOURCE_DHCP, &api_src_vft);
    fib_entry_src_register(FIB_SOURCE_IP6_ND_PROXY, &api_src_vft);
    fib_entry_src_register(FIB_SOURCE_SR, &api_src_vft);
}
