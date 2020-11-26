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
#include "fib_internal.h"
#include "fib_table.h"
#include "fib_entry_cover.h"
#include "fib_attached_export.h"

/**
 * Source initialisation Function 
 */
static void
fib_entry_src_interface_init (fib_entry_src_t *src)
{
    src->u.interface.fesi_cover = FIB_NODE_INDEX_INVALID;
    src->u.interface.fesi_sibling = FIB_NODE_INDEX_INVALID;
}

static void
fib_entry_src_interface_add (fib_entry_src_t *src,
                             const fib_entry_t *entry,
                             fib_entry_flag_t flags,
                             dpo_proto_t proto,
                             const dpo_id_t *dpo)
{
    src->fes_pl = fib_path_list_create_special(
                      proto,
                      fib_entry_src_flags_2_path_list_flags(flags),
                      dpo);
}

static void
fib_entry_src_interface_remove (fib_entry_src_t *src)
{
    src->fes_pl = FIB_NODE_INDEX_INVALID;
    ASSERT(src->u.interface.fesi_sibling == ~0);
}

static int
fib_entry_src_interface_update_glean (fib_entry_t *cover,
                                      const fib_entry_t *local)
{
    fib_entry_src_t *src;
    adj_index_t ai;

    src = fib_entry_src_find (cover, FIB_SOURCE_INTERFACE);

    if (NULL == src)
    {
        /*
         * The cover is not an interface source, no work
         */
        return 0;
    }

    ai = fib_path_list_get_adj(src->fes_pl,
                               fib_entry_get_default_chain_type(cover));

    if (INDEX_INVALID != ai)
    {
        ip_adjacency_t *adj;

        adj = adj_get(ai);

        if (IP_LOOKUP_NEXT_GLEAN == adj->lookup_next_index)
        {
            /*
             * the connected prefix will link to a glean on a non-p2p
             * interface.
             * Ensure we are updating with a host in the connected's subnet
             */
            if (fib_prefix_is_cover(&adj->sub_type.glean.rx_pfx,
                                    &local->fe_prefix))
            {
                adj->sub_type.glean.rx_pfx.fp_addr = local->fe_prefix.fp_addr;
                return (1);
            }
        }
    }

    return (0);
}

static walk_rc_t
fib_entry_src_interface_update_glean_walk (fib_entry_t *cover,
                                           fib_node_index_t covered,
                                           void *ctx)
{
    if (fib_entry_src_interface_update_glean(cover, fib_entry_get(covered)))
        return (WALK_STOP);

    return (WALK_CONTINUE);
}

static void
fib_entry_src_interface_path_swap (fib_entry_src_t *src,
				   const fib_entry_t *entry,
				   fib_path_list_flags_t pl_flags,
				   const fib_route_path_t *paths)
{
    src->fes_pl = fib_path_list_create(pl_flags, paths);
}

/*
 * Source activate. 
 * Called when the source is teh new longer best source on the entry
 */
static int
fib_entry_src_interface_activate (fib_entry_src_t *src,
				  const fib_entry_t *fib_entry)
{
    fib_entry_t *cover;

    if (FIB_ENTRY_FLAG_LOCAL & src->fes_entry_flags)
    {
	/*
	 * Track the covering attached/connected cover. This is so that
	 * during an attached export of the cover, this local prefix is
	 * also exported
	 */
	src->u.interface.fesi_cover =
	    fib_table_get_less_specific(fib_entry->fe_fib_index,
					&fib_entry->fe_prefix);

	ASSERT(FIB_NODE_INDEX_INVALID != src->u.interface.fesi_cover);

	cover = fib_entry_get(src->u.interface.fesi_cover);

	src->u.interface.fesi_sibling =
	    fib_entry_cover_track(cover, fib_entry_get_index(fib_entry));

        fib_entry_src_interface_update_glean(cover, fib_entry);
    }

    return (!0);
}


/*
 * Source Deactivate. 
 * Called when the source is no longer best source on the entry
 */
static void
fib_entry_src_interface_deactivate (fib_entry_src_t *src,
				    const fib_entry_t *fib_entry)
{
    fib_entry_t *cover;

    /*
     * remove the dependency on the covering entry
     */
    if (FIB_NODE_INDEX_INVALID != src->u.interface.fesi_cover)
    {
	cover = fib_entry_get(src->u.interface.fesi_cover);

	fib_entry_cover_untrack(cover, src->u.interface.fesi_sibling);

	src->u.interface.fesi_cover = FIB_NODE_INDEX_INVALID;
	src->u.interface.fesi_sibling = ~0;

        fib_entry_cover_walk(cover,
                             fib_entry_src_interface_update_glean_walk,
                             NULL);
    }
}

static fib_entry_src_cover_res_t
fib_entry_src_interface_cover_change (fib_entry_src_t *src,
				      const fib_entry_t *fib_entry)
{
    fib_entry_src_cover_res_t res = {
	.install = !0,
	.bw_reason = FIB_NODE_BW_REASON_FLAG_NONE,
    };

    if (FIB_NODE_INDEX_INVALID == src->u.interface.fesi_cover)
    {
	/*
	 * not tracking the cover. surprised we got poked?
	 */
	return (res);
    }

    /*
     * this function is called when this entry's cover has a more specific
     * entry inserted benaeth it. That does not necessarily mean that this
     * entry is covered by the new prefix. check that
     */
    if (src->u.interface.fesi_cover !=
        fib_table_get_less_specific(fib_entry->fe_fib_index,
                                    &fib_entry->fe_prefix))
    {
	fib_entry_src_interface_deactivate(src, fib_entry);
	fib_entry_src_interface_activate(src, fib_entry);
    }
    return (res);
}

static void
fib_entry_src_interface_installed (fib_entry_src_t *src,
				   const fib_entry_t *fib_entry)
{
    /*
     * The interface source now rules! poke our cover to get exported
     */
    fib_entry_t *cover;

    if (FIB_NODE_INDEX_INVALID != src->u.interface.fesi_cover)
    {
	cover = fib_entry_get(src->u.interface.fesi_cover);

	fib_attached_export_covered_added(cover,
					  fib_entry_get_index(fib_entry));
    }
}

static u8*
fib_entry_src_interface_format (fib_entry_src_t *src,
				u8* s)
{
    return (format(s, " cover:%d", src->u.interface.fesi_cover));
}

const static fib_entry_src_vft_t interface_src_vft = {
    .fesv_init = fib_entry_src_interface_init,
    .fesv_add = fib_entry_src_interface_add,
    .fesv_remove = fib_entry_src_interface_remove,
    .fesv_path_swap = fib_entry_src_interface_path_swap,
    .fesv_activate = fib_entry_src_interface_activate,
    .fesv_deactivate = fib_entry_src_interface_deactivate,
    .fesv_format = fib_entry_src_interface_format,
    .fesv_installed = fib_entry_src_interface_installed,
    .fesv_cover_change = fib_entry_src_interface_cover_change,
    /*
     * not concerned about updates to the cover. the cover will
     * decide to export or not
     */
};

void
fib_entry_src_interface_register (void)
{
    fib_entry_src_behaviour_register(FIB_SOURCE_BH_INTERFACE,
                                     &interface_src_vft);
}
