/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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


#include <vnet/mfib/mfib_entry_src.h>
#include <vnet/mfib/mfib_entry_cover.h>
#include <vnet/mfib/mfib_table.h>
#include <vnet/fib/fib_path_list.h>

static void
mfib_entry_src_rr_deactiviate (mfib_entry_t *mfib_entry,
                               mfib_entry_src_t *msrc)
{
    mfib_entry_t *cover;

    /*
     * remove the depednecy on the covering entry
     */
    if (FIB_NODE_INDEX_INVALID != msrc->mfes_cover)
    {
	cover = mfib_entry_get(msrc->mfes_cover);
	mfib_entry_cover_untrack(cover, msrc->mfes_sibling);
	msrc->mfes_cover = FIB_NODE_INDEX_INVALID;
    }

    fib_path_list_unlock(msrc->mfes_pl);
    msrc->mfes_pl = FIB_NODE_INDEX_INVALID;
    msrc->mfes_itfs = NULL;
    msrc->mfes_exts = NULL;
}

static void
mfib_entry_src_rr_activiate (mfib_entry_t *mfib_entry,
                             mfib_entry_src_t *msrc)
{
    mfib_entry_src_t *csrc;
    mfib_entry_t *cover;

    msrc->mfes_cover = mfib_table_get_less_specific(mfib_entry->mfe_fib_index,
                                                    &mfib_entry->mfe_prefix);

    ASSERT(FIB_NODE_INDEX_INVALID != msrc->mfes_cover);

    cover = mfib_entry_get(msrc->mfes_cover);

    msrc->mfes_sibling =
	mfib_entry_cover_track(cover, mfib_entry_get_index(mfib_entry));

    csrc = mfib_entry_get_best_src(cover);

    msrc->mfes_pl = csrc->mfes_pl;
    fib_path_list_lock(msrc->mfes_pl);
    msrc->mfes_route_flags = csrc->mfes_route_flags;
    msrc->mfes_itfs = csrc->mfes_itfs;
    msrc->mfes_exts = csrc->mfes_exts;
    msrc->mfes_rpf_id = csrc->mfes_rpf_id;
}

static mfib_src_res_t
mfib_entry_src_rr_cover_change (mfib_entry_t *mfib_entry,
                                mfib_entry_src_t *msrc)
{
    mfib_entry_src_rr_deactiviate(mfib_entry, msrc);
    mfib_entry_src_rr_activiate(mfib_entry, msrc);

    return (MFIB_SRC_REEVALUATE);
}

static mfib_src_res_t
mfib_entry_src_rr_cover_update (mfib_entry_t *mfib_entry,
                                mfib_entry_src_t *msrc)
{
    /*
     * path lists are updated (i.e. not shared) in the mfib world,
     * so there's no need to check for a new one. but we do need to
     * copy down any new flags and input interfaces
     */
    mfib_entry_t *cover;

    cover = mfib_entry_get(msrc->mfes_cover);

    msrc->mfes_route_flags = cover->mfe_flags;
    msrc->mfes_itfs = cover->mfe_itfs;
    msrc->mfes_rpf_id = cover->mfe_rpf_id;

    return (MFIB_SRC_REEVALUATE);
}

void
mfib_entry_src_rr_module_init (void)
{
    mfib_entry_src_vft mvft = {
        .mev_activate = mfib_entry_src_rr_activiate,
        .mev_deactivate = mfib_entry_src_rr_deactiviate,
        .mev_cover_change = mfib_entry_src_rr_cover_change,
        .mev_cover_update = mfib_entry_src_rr_cover_update,
    };

    mfib_entry_src_register(MFIB_SOURCE_RR, &mvft);
}
