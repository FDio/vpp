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
#include "fib_table.h"
#include "fib_entry_cover.h"
#include "fib_attached_export.h"

/**
 * Source initialisation Function 
 */
static void
fib_entry_src_adj_init (fib_entry_src_t *src)
{
    src->adj.fesa_cover = FIB_NODE_INDEX_INVALID;
    src->adj.fesa_sibling = FIB_NODE_INDEX_INVALID;
}

static void
fib_entry_src_adj_path_swap (fib_entry_src_t *src,
			     const fib_entry_t *entry,
			     fib_path_list_flags_t pl_flags,
			     const fib_route_path_t *paths)
{
    src->fes_pl = fib_path_list_create(pl_flags, paths);
}

static void
fib_entry_src_adj_remove (fib_entry_src_t *src)
{
    src->fes_pl = FIB_NODE_INDEX_INVALID;
}


/*
 * Source activate. 
 * Called when the source is the new longer best source on the entry
 */
static int
fib_entry_src_adj_activate (fib_entry_src_t *src,
			    const fib_entry_t *fib_entry)
{
    fib_entry_t *cover;

    /*
     * find the covering prefix. become a dependent thereof.
     * there should always be a cover, though it may be the default route.
     */
    src->adj.fesa_cover = fib_table_get_less_specific(fib_entry->fe_fib_index,
						      &fib_entry->fe_prefix);

    ASSERT(FIB_NODE_INDEX_INVALID != src->adj.fesa_cover);
    ASSERT(fib_entry_get_index(fib_entry) != src->adj.fesa_cover);

    cover = fib_entry_get(src->adj.fesa_cover);

    ASSERT(cover != fib_entry);

    src->adj.fesa_sibling =
	fib_entry_cover_track(cover,
			      fib_entry_get_index(fib_entry));

    /*
     * if the cover is attached on the same interface as this adj source then
     * install the FIB entry via the adj. otherwise install a drop.
     * This prevents ARP/ND entries that on interface X that do not belong
     * on X's subnet from being added to the FIB. To do so would allow
     * nefarious gratuitous ARP requests from attracting traffic to the sender.
     *
     * and yes, I really do mean attached and not connected.
     * this abomination;
     *   ip route add 10.0.0.0/24 Eth0
     * is attached. and we want adj-fibs to install on Eth0.
     */
    if (FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags_i(cover))
    {
        u32 cover_itf = fib_entry_get_resolving_interface(src->adj.fesa_cover);
        u32 adj_itf = fib_path_list_get_resolving_interface(src->fes_pl);

        if (cover_itf == adj_itf)
        {
            return (1);
        }
        else
        {
            /*
             * if the interface the adj is on is unnumbered to the
             * cover's, then allow that too.
             */
            vnet_sw_interface_t *swif;

            swif = vnet_get_sw_interface (vnet_get_main(), adj_itf);

            if (swif->flags & VNET_SW_INTERFACE_FLAG_UNNUMBERED &&
                cover_itf == swif->unnumbered_sw_if_index)
            {
                return (1);
            }
        }
    }
    return (0);
}

/*
 * Source Deactivate. 
 * Called when the source is no longer best source on the entry
 */
static void
fib_entry_src_adj_deactivate (fib_entry_src_t *src,
			      const fib_entry_t *fib_entry)
{
    fib_entry_t *cover;

    /*
     * remove the depednecy on the covering entry
     */
    ASSERT(FIB_NODE_INDEX_INVALID != src->adj.fesa_cover);
    cover = fib_entry_get(src->adj.fesa_cover);

    fib_entry_cover_untrack(cover, src->adj.fesa_sibling);

    /*
     * tell the cover this entry no longer needs exporting
     */
    fib_attached_export_covered_removed(cover, fib_entry_get_index(fib_entry));

    src->adj.fesa_cover = FIB_NODE_INDEX_INVALID;
}

static u8*
fib_entry_src_adj_format (fib_entry_src_t *src,
			 u8* s)
{
    return (format(s, "cover:%d", src->adj.fesa_cover));
}

static void
fib_entry_src_adj_installed (fib_entry_src_t *src,
			     const fib_entry_t *fib_entry)
{
    /*
     * The adj source now rules! poke our cover to get exported
     */
    fib_entry_t *cover;

    ASSERT(FIB_NODE_INDEX_INVALID != src->adj.fesa_cover);
    cover = fib_entry_get(src->adj.fesa_cover);

    fib_attached_export_covered_added(cover,
				      fib_entry_get_index(fib_entry));
}

static fib_entry_src_cover_res_t
fib_entry_src_adj_cover_change (fib_entry_src_t *src,
				const fib_entry_t *fib_entry)
{
    fib_entry_src_cover_res_t res = {
	.install = !0,
	.bw_reason = FIB_NODE_BW_REASON_FLAG_NONE,
    };

    fib_entry_src_adj_deactivate(src, fib_entry);

    res.install = fib_entry_src_adj_activate(src, fib_entry);

    if (res.install) {
	/*
	 * ADJ fib can install
	 */
	res.bw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE;
    }

    return (res);
}

/*
 * fib_entry_src_adj_cover_update
 */
static fib_entry_src_cover_res_t
fib_entry_src_adj_cover_update (fib_entry_src_t *src,
                                const fib_entry_t *fib_entry)
{
    /*
     * the cover has updated, i.e. its forwarding or flags
     * have changed. do'nt decativate/activate here, since this
     * prefix is updated during the covers walk.
     */
    fib_entry_src_cover_res_t res = {
	.install = !0,
	.bw_reason = FIB_NODE_BW_REASON_FLAG_NONE,
    };
    fib_entry_t *cover;

    ASSERT(FIB_NODE_INDEX_INVALID != src->adj.fesa_cover);

    cover = fib_entry_get(src->adj.fesa_cover);

    res.install = (FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags_i(cover));

    return (res);
}

const static fib_entry_src_vft_t adj_src_vft = {
    .fesv_init = fib_entry_src_adj_init,
    .fesv_path_swap = fib_entry_src_adj_path_swap,
    .fesv_remove = fib_entry_src_adj_remove,
    .fesv_activate = fib_entry_src_adj_activate,
    .fesv_deactivate = fib_entry_src_adj_deactivate,
    .fesv_format = fib_entry_src_adj_format,
    .fesv_installed = fib_entry_src_adj_installed,
    .fesv_cover_change = fib_entry_src_adj_cover_change,
    .fesv_cover_update = fib_entry_src_adj_cover_update,
};

void
fib_entry_src_adj_register (void)
{
    fib_entry_src_register(FIB_SOURCE_ADJ, &adj_src_vft);
}
