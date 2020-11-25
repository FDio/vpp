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
#include "fib_path_ext.h"

/**
 * Source initialisation Function
 */
static void
fib_entry_src_adj_init (fib_entry_src_t *src)
{
    src->u.adj.fesa_cover = FIB_NODE_INDEX_INVALID;
    src->u.adj.fesa_sibling = FIB_NODE_INDEX_INVALID;
}

static void
fib_entry_src_adj_path_add (fib_entry_src_t *src,
                            const fib_entry_t *entry,
                            fib_path_list_flags_t pl_flags,
                            const fib_route_path_t *paths)
{
    const fib_route_path_t *rpath;

    if (FIB_NODE_INDEX_INVALID == src->fes_pl)
    {
        src->fes_pl = fib_path_list_create(pl_flags, paths);
    }
    else
    {
        src->fes_pl = fib_path_list_copy_and_path_add(src->fes_pl,
                                                      pl_flags,
                                                      paths);
    }

    /*
     * resolve the existing extensions
     */
    fib_path_ext_list_resolve(&src->fes_path_exts, src->fes_pl);

    /*
     * and new extensions
     */
    vec_foreach(rpath, paths)
    {
        fib_path_ext_list_insert(&src->fes_path_exts,
                                 src->fes_pl,
                                 FIB_PATH_EXT_ADJ,
                                 rpath);
    }
}

static void
fib_entry_src_adj_path_remove (fib_entry_src_t *src,
                               fib_path_list_flags_t pl_flags,
                               const fib_route_path_t *rpaths)
{
    const fib_route_path_t *rpath;

    if (FIB_NODE_INDEX_INVALID != src->fes_pl)
    {
        src->fes_pl = fib_path_list_copy_and_path_remove(src->fes_pl,
                                                         pl_flags,
                                                         rpaths);
    }

    /*
     * remove the path-extension for the path
     */
    vec_foreach(rpath, rpaths)
    {
        fib_path_ext_list_remove(&src->fes_path_exts, FIB_PATH_EXT_ADJ, rpath);
    };
    /*
     * resolve the remaining extensions
     */
    fib_path_ext_list_resolve(&src->fes_path_exts, src->fes_pl);
}

static void
fib_entry_src_adj_path_swap (fib_entry_src_t *src,
                             const fib_entry_t *entry,
                             fib_path_list_flags_t pl_flags,
                             const fib_route_path_t *paths)
{
    const fib_route_path_t *rpath;

    /*
     * flush all the old extensions before we create a brand new path-list
     */
    fib_path_ext_list_flush(&src->fes_path_exts);

    src->fes_pl = fib_path_list_create(pl_flags, paths);

    /*
     * and new extensions
     */
    vec_foreach(rpath, paths)
    {
        fib_path_ext_list_push_back(&src->fes_path_exts,
                                    src->fes_pl,
                                    FIB_PATH_EXT_ADJ,
                                    rpath);
    }
}

static void
fib_entry_src_adj_remove (fib_entry_src_t *src)
{
    src->fes_pl = FIB_NODE_INDEX_INVALID;

    if (FIB_NODE_INDEX_INVALID != src->u.adj.fesa_cover)
    {
        fib_entry_cover_untrack(fib_entry_get(src->u.adj.fesa_cover),
                                src->u.adj.fesa_sibling);
    }
}

/*
 * Add a path-extension indicating whether this path is resolved,
 * because it passed the refinement check
 */
static void
fib_enty_src_adj_update_path_ext (fib_entry_src_t *src,
                                  fib_node_index_t path_index,
                                  fib_path_ext_adj_flags_t flags)
{
    fib_path_ext_t *path_ext;

    path_ext = fib_path_ext_list_find_by_path_index(&src->fes_path_exts,
                                                    path_index);

    if (NULL != path_ext)
    {
        path_ext->fpe_adj_flags = flags;
    }
    else
    {
        ASSERT(!"no path extension");
    }
}

typedef struct fib_entry_src_path_list_walk_cxt_t_
{
    fib_entry_src_t *src;
    u32 cover_itf;
    fib_path_ext_adj_flags_t flags;
} fib_entry_src_path_list_walk_cxt_t;

static fib_path_list_walk_rc_t
fib_entry_src_adj_path_list_walk (fib_node_index_t pl_index,
                                  fib_node_index_t path_index,
                                  void *arg)
{
    fib_entry_src_path_list_walk_cxt_t *ctx;
    u32 adj_itf;

    ctx = arg;
    adj_itf = fib_path_get_resolving_interface(path_index);

    if (ctx->cover_itf == adj_itf)
    {
        fib_enty_src_adj_update_path_ext(ctx->src, path_index,
                                         FIB_PATH_EXT_ADJ_FLAG_REFINES_COVER);
        ctx->flags |= FIB_PATH_EXT_ADJ_FLAG_REFINES_COVER;
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
            ctx->cover_itf == swif->unnumbered_sw_if_index)
        {
            fib_enty_src_adj_update_path_ext(ctx->src, path_index,
                                             FIB_PATH_EXT_ADJ_FLAG_REFINES_COVER);
            ctx->flags |= FIB_PATH_EXT_ADJ_FLAG_REFINES_COVER;
        }
        else
        {
            fib_enty_src_adj_update_path_ext(ctx->src, path_index,
                                             FIB_PATH_EXT_ADJ_FLAG_NONE);
        }
    }
    return (FIB_PATH_LIST_WALK_CONTINUE);
}

static int
fib_entry_src_adj_activate (fib_entry_src_t *src,
                            const fib_entry_t *fib_entry)
{
    fib_entry_t *cover;

    /*
     * find the covering prefix. become a dependent thereof.
     * there should always be a cover, though it may be the default route.
     */
    src->u.adj.fesa_cover = fib_table_get_less_specific(fib_entry->fe_fib_index,
                                                        &fib_entry->fe_prefix);

    ASSERT(FIB_NODE_INDEX_INVALID != src->u.adj.fesa_cover);
    ASSERT(fib_entry_get_index(fib_entry) != src->u.adj.fesa_cover);

    cover = fib_entry_get(src->u.adj.fesa_cover);

    ASSERT(cover != fib_entry);

    src->u.adj.fesa_sibling =
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
    if (FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags_i(cover) ||
        (FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags_for_source(src->u.adj.fesa_cover,
                                                                  FIB_SOURCE_INTERFACE)))
    {
        fib_entry_src_path_list_walk_cxt_t ctx = {
            .cover_itf = fib_entry_get_resolving_interface(src->u.adj.fesa_cover),
            .flags = FIB_PATH_EXT_ADJ_FLAG_NONE,
            .src = src,
        };

        fib_path_list_walk(src->fes_pl,
                           fib_entry_src_adj_path_list_walk,
                           &ctx);

        /*
         * active the entry is one of the paths refines the cover.
         */
        return (FIB_PATH_EXT_ADJ_FLAG_REFINES_COVER & ctx.flags);
    }
    return (0);
}

/*
 * Source re-activate.
 * Called when the source path lit has changed and the source is still
 * the best source
 */
static int
fib_entry_src_adj_reactivate (fib_entry_src_t *src,
                              const fib_entry_t *fib_entry)
{
    fib_entry_src_path_list_walk_cxt_t ctx = {
        .cover_itf = fib_entry_get_resolving_interface(src->u.adj.fesa_cover),
        .flags = FIB_PATH_EXT_ADJ_FLAG_NONE,
        .src = src,
    };

    fib_path_list_walk(src->fes_pl,
                       fib_entry_src_adj_path_list_walk,
                       &ctx);

    return (FIB_PATH_EXT_ADJ_FLAG_REFINES_COVER & ctx.flags);
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
     * remove the dependency on the covering entry
     */
    if (FIB_NODE_INDEX_INVALID == src->u.adj.fesa_cover)
    {
        /*
         * this is the case if the entry is in the non-forwarding trie
         */
        return;
    }

    cover = fib_entry_get(src->u.adj.fesa_cover);
    fib_entry_cover_untrack(cover, src->u.adj.fesa_sibling);

    /*
     * tell the cover this entry no longer needs exporting
     */
    fib_attached_export_covered_removed(cover, fib_entry_get_index(fib_entry));

    src->u.adj.fesa_cover = FIB_NODE_INDEX_INVALID;
    src->u.adj.fesa_sibling = FIB_NODE_INDEX_INVALID;
}

static u8*
fib_entry_src_adj_format (fib_entry_src_t *src,
                         u8* s)
{
    return (format(s, " cover:%d", src->u.adj.fesa_cover));
}

static void
fib_entry_src_adj_installed (fib_entry_src_t *src,
                             const fib_entry_t *fib_entry)
{
    /*
     * The adj source now rules! poke our cover to get exported
     */
    fib_entry_t *cover;

    ASSERT(FIB_NODE_INDEX_INVALID != src->u.adj.fesa_cover);
    cover = fib_entry_get(src->u.adj.fesa_cover);

    fib_attached_export_covered_added(cover,
                                      fib_entry_get_index(fib_entry));
}

static fib_entry_src_cover_res_t
fib_entry_src_adj_cover_change (fib_entry_src_t *src,
                                const fib_entry_t *fib_entry)
{
    fib_entry_src_cover_res_t res = {
        .install = 0,
        .bw_reason = FIB_NODE_BW_REASON_FLAG_NONE,
    };

    /*
     * not interested in a change to the cover if the cover
     * is not being tracked, i.e. the source is not active
     */
    if (FIB_NODE_INDEX_INVALID == src->u.adj.fesa_cover)
        return res;

    fib_entry_src_adj_deactivate(src, fib_entry);

    res.install = fib_entry_src_adj_activate(src, fib_entry);

    if (res.install) {
        /*
         * ADJ fib can install
         */
        res.bw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE;
    }

    FIB_ENTRY_DBG(fib_entry, "adj-src-cover-changed");
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
     * have changed. don't deactivate/activate here, since this
     * prefix is updated during the covers walk.
     */
    fib_entry_src_cover_res_t res = {
        .install = 0,
        .bw_reason = FIB_NODE_BW_REASON_FLAG_NONE,
    };
    fib_entry_t *cover;

    /*
     * If there is no cover, then the source is not active and we can ignore
     * this update
     */
    if (FIB_NODE_INDEX_INVALID != src->u.adj.fesa_cover)
    {
        cover = fib_entry_get(src->u.adj.fesa_cover);

        res.install = (FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags_i(cover));

        FIB_ENTRY_DBG(fib_entry, "adj-src-cover-updated");
    }
    return (res);
}

const static fib_entry_src_vft_t adj_src_vft = {
    .fesv_init = fib_entry_src_adj_init,
    .fesv_path_swap = fib_entry_src_adj_path_swap,
    .fesv_path_add = fib_entry_src_adj_path_add,
    .fesv_path_remove = fib_entry_src_adj_path_remove,
    .fesv_remove = fib_entry_src_adj_remove,
    .fesv_activate = fib_entry_src_adj_activate,
    .fesv_deactivate = fib_entry_src_adj_deactivate,
    .fesv_reactivate = fib_entry_src_adj_reactivate,
    .fesv_format = fib_entry_src_adj_format,
    .fesv_installed = fib_entry_src_adj_installed,
    .fesv_cover_change = fib_entry_src_adj_cover_change,
    .fesv_cover_update = fib_entry_src_adj_cover_update,
};

void
fib_entry_src_adj_register (void)
{
    fib_entry_src_behaviour_register(FIB_SOURCE_BH_ADJ, &adj_src_vft);
}
