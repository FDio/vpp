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

#include <vlib/vlib.h>
#include <vnet/ip/format.h>
#include <vnet/ip/lookup.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/drop_dpo.h>

#include "fib_entry_src.h"
#include "fib_entry_src_rr.h"
#include "fib_entry_cover.h"
#include "fib_entry.h"
#include "fib_table.h"

/*
 * Source initialisation Function
 */
static void
fib_entry_src_interpose_init (fib_entry_src_t *src)
{
    src->u.interpose.fesi_cover = FIB_NODE_INDEX_INVALID;
    src->u.interpose.fesi_sibling = FIB_NODE_INDEX_INVALID;
}

/*
 * Source deinitialisation Function
 */
static void
fib_entry_src_interpose_deinit (fib_entry_src_t *src)
{
    ASSERT(src->u.interpose.fesi_cover == FIB_NODE_INDEX_INVALID);

    src->u.interpose.fesi_cover = FIB_NODE_INDEX_INVALID;
    src->u.interpose.fesi_sibling = FIB_NODE_INDEX_INVALID;

    dpo_reset(&src->u.interpose.fesi_dpo);
}

static fib_entry_src_t *
fib_entry_src_rr_get_next_best (const fib_entry_src_t *src,
                                const fib_entry_t *fib_entry)
{
    fib_entry_src_t *next_src, *best_src = NULL;
    fib_source_t source;

    FOR_EACH_SRC_ADDED(fib_entry, next_src, source,
    ({
        /*
         * skip to the next best source after this one
         */
        if (source <= src->fes_src)
        {
            continue;
        }
        else
        {
            best_src = next_src;
            break;
        }
    }));

    return (best_src);
}

/*
 * Source activation. Called when the source is the new best source on the entry
 */
static int
fib_entry_src_interpose_activate (fib_entry_src_t *src,
                                  const fib_entry_t *fib_entry)
{
    fib_entry_src_t *best_src;
    fib_node_index_t old_pl;
    fib_entry_t *cover;

    old_pl = src->fes_pl;
    src->fes_pl = FIB_NODE_INDEX_INVALID;

    /*
     * The goal here is to find a path-list that will contribute forwarding
     * for the entry.
     * First check this entry for other sources that have a path-list
     */
    best_src = fib_entry_src_rr_get_next_best(src, fib_entry);

    if (NULL != best_src)
    {
        const fib_entry_src_vft_t *vft;

        best_src->fes_flags |= FIB_ENTRY_SRC_FLAG_CONTRIBUTING;
        vft = fib_entry_src_get_vft(best_src);
        /*
         * there is another source for this entry. activate it so it
         * can provide forwarding
         */
        if (NULL != vft->fesv_activate)
        {
            if (vft->fesv_activate(best_src, fib_entry))
            {
                /*
                 * next best source activated ok, use its path list
                 */
                src->fes_pl = best_src->fes_pl;
            }
        }
        else
        {
            /*
             * next best source does not require activation, use its path list
             */
            src->fes_pl = best_src->fes_pl;
        }
    }
    else
    {
        /*
         * find the covering prefix. become a dependent thereof.
         * for IP there should always be a cover, though it may be the default route.
         * For MPLS there is never a cover.
         */
        if (FIB_PROTOCOL_MPLS == fib_entry->fe_prefix.fp_proto)
        {
            src->fes_pl = fib_path_list_create_special(DPO_PROTO_MPLS,
                                                       FIB_PATH_LIST_FLAG_DROP,
                                                       NULL);
        }
        else
        {
            src->u.interpose.fesi_cover =
                fib_table_get_less_specific(fib_entry->fe_fib_index,
                                            &fib_entry->fe_prefix);

            ASSERT(FIB_NODE_INDEX_INVALID != src->u.interpose.fesi_cover);

            cover = fib_entry_get(src->u.interpose.fesi_cover);

            src->u.interpose.fesi_sibling =
                fib_entry_cover_track(cover, fib_entry_get_index(fib_entry));

            /*
             * if the cover is attached then install an attached-host path
             * (like an adj-fib). Otherwise inherit the forwarding from the cover
             */
            if (FIB_ENTRY_FLAG_ATTACHED & fib_entry_get_flags_i(cover))
            {
                fib_entry_src_rr_resolve_via_connected(src, fib_entry, cover);
            }
            else
            {
                fib_entry_src_rr_use_covers_pl(src, fib_entry, cover);
            }
        }
    }

    fib_path_list_unlock(old_pl);
    fib_path_list_lock(src->fes_pl);

    /*
     * return go for install
     */
    return (!0);
}

/**
 * Source Deactivate.
 * Called when the source is no longer best source on the entry
 */
static void
fib_entry_src_interpose_deactivate (fib_entry_src_t *src,
                                    const fib_entry_t *fib_entry)
{
    fib_entry_t *cover;

    if (FIB_NODE_INDEX_INVALID != src->u.interpose.fesi_cover)
    {
        /*
         * remove the depednecy on the covering entry, if that's
         * what was contributing the path-list
         */
        cover = fib_entry_get(src->u.interpose.fesi_cover);
        fib_entry_cover_untrack(cover, src->u.interpose.fesi_sibling);
        src->u.interpose.fesi_cover = FIB_NODE_INDEX_INVALID;
    }
    else
    {
        fib_entry_src_t *best_src;

        best_src = fib_entry_src_rr_get_next_best(src, fib_entry);

        if (best_src)
        {
            best_src->fes_flags &= ~FIB_ENTRY_SRC_FLAG_CONTRIBUTING;
            /*
             * there is another source for this entry. activate it so it
             * can provide forwarding
             */
            FIB_ENTRY_SRC_VFT_INVOKE(best_src, fesv_deactivate,
                                     (best_src, fib_entry));
        }
    }

    fib_path_list_unlock(src->fes_pl);
    src->fes_pl = FIB_NODE_INDEX_INVALID;
    src->fes_entry_flags &= ~FIB_ENTRY_FLAGS_RR_INHERITED;
}

static int
fib_entry_src_interpose_reactivate (fib_entry_src_t *src,
                                    const fib_entry_t *fib_entry)
{
    fib_entry_src_interpose_deactivate(src, fib_entry);
    return (fib_entry_src_interpose_activate(src, fib_entry));
}

static fib_entry_src_cover_res_t
fib_entry_src_interpose_cover_change (fib_entry_src_t *src,
                                      const fib_entry_t *fib_entry)
{
    fib_entry_src_cover_res_t res = {
       .install = !0,
       .bw_reason = FIB_NODE_BW_REASON_FLAG_NONE,
    };

    if (FIB_NODE_INDEX_INVALID == src->u.interpose.fesi_cover)
    {
       /*
        * the source may be added, but it is not active
        * if it is not tracking the cover.
        */
       return (res);
    }

    /*
     * this function is called when this entry's cover has a more specific
     * entry inserted benaeth it. That does not necessarily mean that this
     * entry is covered by the new prefix. check that
     */
    if (src->u.interpose.fesi_cover !=
        fib_table_get_less_specific(fib_entry->fe_fib_index,
                                    &fib_entry->fe_prefix))
    {
       fib_entry_src_interpose_deactivate(src, fib_entry);
       fib_entry_src_interpose_activate(src, fib_entry);

       /*
        * dependent children need to re-resolve to the new forwarding info
        */
       res.bw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE;
    }
    return (res);
}

static void
fib_entry_src_interpose_add (fib_entry_src_t *src,
                             const fib_entry_t *entry,
                             fib_entry_flag_t flags,
                             dpo_proto_t proto,
                             const dpo_id_t *dpo)
{
    dpo_copy(&src->u.interpose.fesi_dpo, dpo);
}

static void
fib_entry_src_interpose_remove (fib_entry_src_t *src)
{
    dpo_reset(&src->u.interpose.fesi_dpo);
}

static void
fib_entry_src_interpose_set_data (fib_entry_src_t *src,
                                  const fib_entry_t *fib_entry,
                                  const void *data)
{
    const dpo_id_t *dpo = data;

    dpo_copy(&src->u.interpose.fesi_dpo, dpo);
}

/**
 * Contribute forwarding to interpose in the chain
 */
const dpo_id_t* fib_entry_src_interpose_contribute(const fib_entry_src_t *src,
                                                   const fib_entry_t *fib_entry)
{
    return (&src->u.interpose.fesi_dpo);
}

static void
fib_entry_src_interpose_copy (const fib_entry_src_t *orig_src,
                              const fib_entry_t *fib_entry,
                              fib_entry_src_t *copy_src)
{
    copy_src->u.interpose.fesi_cover = orig_src->u.interpose.fesi_cover;

    if (FIB_NODE_INDEX_INVALID != copy_src->u.interpose.fesi_cover)
    {
        fib_entry_t *cover;

        cover = fib_entry_get(orig_src->u.interpose.fesi_cover);
        copy_src->u.interpose.fesi_sibling =
            fib_entry_cover_track(cover, fib_entry_get_index(fib_entry));
    }

    dpo_copy(&copy_src->u.interpose.fesi_dpo,
             &orig_src->u.interpose.fesi_dpo);
}

static void
fib_entry_src_interpose_flag_change (fib_entry_src_t *src,
                                     const fib_entry_t *fib_entry,
                                     fib_entry_flag_t new_flags)
{
    if (!(new_flags & FIB_ENTRY_FLAG_INTERPOSE))
    {
        /*
         * stop tracking the source contributing forwarding
         * and reset the interposer DPO
         */
        fib_entry_src_interpose_deactivate(src, fib_entry);
        fib_entry_src_interpose_deinit(src);
    }
}

static u8*
fib_entry_src_interpose_format (fib_entry_src_t *src,
                                u8* s)
{
    s = format(s, " cover:%d interpose:\n%U%U",
               src->u.interpose.fesi_cover,
               format_white_space, 6,
               format_dpo_id, &src->u.interpose.fesi_dpo, 8);

    return (s);
}

const static fib_entry_src_vft_t interpose_src_vft = {
    .fesv_init = fib_entry_src_interpose_init,
    .fesv_deinit = fib_entry_src_interpose_deinit,
    .fesv_activate = fib_entry_src_interpose_activate,
    .fesv_reactivate = fib_entry_src_interpose_reactivate,
    .fesv_deactivate = fib_entry_src_interpose_deactivate,
    .fesv_cover_change = fib_entry_src_interpose_cover_change,
    .fesv_cover_update = fib_entry_src_rr_cover_update,
    .fesv_format = fib_entry_src_interpose_format,
    .fesv_add = fib_entry_src_interpose_add,
    .fesv_remove = fib_entry_src_interpose_remove,
    .fesv_contribute_interpose = fib_entry_src_interpose_contribute,
    .fesv_set_data = fib_entry_src_interpose_set_data,
    .fesv_copy = fib_entry_src_interpose_copy,
    .fesv_flags_change = fib_entry_src_interpose_flag_change,
};

void
fib_entry_src_interpose_register (void)
{
    fib_entry_src_register(FIB_SOURCE_INTERPOSE, &interpose_src_vft);
}
