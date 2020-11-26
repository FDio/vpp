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

#include <vnet/mfib/mfib_entry_cover.h>
#include <vnet/mfib/mfib_entry_src.h>
#include <vnet/fib/fib_node_list.h>

u32
mfib_entry_cover_track (mfib_entry_t* cover,
		       fib_node_index_t covered)
{
    mfib_entry_delegate_t *mfed;

    MFIB_ENTRY_DBG(cover, "cover-track %d", covered);

    ASSERT(mfib_entry_get_index(cover) != covered);

    mfed = mfib_entry_delegate_get(cover, MFIB_ENTRY_DELEGATE_COVERED);

    if (NULL == mfed)
    {
        mfed = mfib_entry_delegate_find_or_add(cover, MFIB_ENTRY_DELEGATE_COVERED);
        mfed->mfd_list = fib_node_list_create();
    }

    return (fib_node_list_push_front(mfed->mfd_list,
                                     0, FIB_NODE_TYPE_MFIB_ENTRY,
                                     covered));
}

void
mfib_entry_cover_untrack (mfib_entry_t* cover,
			 u32 tracked_index)
{
    mfib_entry_delegate_t *mfed;

    MFIB_ENTRY_DBG(cover, "cover-untrack @ %d", tracked_index);

    mfed = mfib_entry_delegate_get(cover, MFIB_ENTRY_DELEGATE_COVERED);

    if (NULL == mfed)
        return;

    fib_node_list_remove(mfed->mfd_list, tracked_index);

    if (0 == fib_node_list_get_size(mfed->mfd_list))
    {
        fib_node_list_destroy(&mfed->mfd_list);
        mfib_entry_delegate_remove(cover, MFIB_ENTRY_DELEGATE_COVERED);        
    }
}

/**
 * Internal struct to hold user supplied paraneters for the cover walk
 */
typedef struct mfib_enty_cover_walk_ctx_t_ {
    mfib_entry_t *cover;
    mfib_entry_covered_walk_t walk;
    void *ctx;
} mfib_enty_cover_walk_ctx_t;

static walk_rc_t
mfib_entry_cover_walk_node_ptr (fib_node_ptr_t *depend,
                                void *args)
{
    mfib_enty_cover_walk_ctx_t *ctx = args;

    ctx->walk(ctx->cover, depend->fnp_index, ctx->ctx);

    return (WALK_CONTINUE);
}

void
mfib_entry_cover_walk (mfib_entry_t *cover,
		      mfib_entry_covered_walk_t walk,
		      void *args)
{
    mfib_entry_delegate_t *mfed;

    mfed = mfib_entry_delegate_get(cover, MFIB_ENTRY_DELEGATE_COVERED);

    if (NULL == mfed)
        return;

    mfib_enty_cover_walk_ctx_t ctx = {
        .cover = cover,
        .walk = walk,
        .ctx = args,
    };

    fib_node_list_walk(mfed->mfd_list,
                       mfib_entry_cover_walk_node_ptr,
                       &ctx);
}

static int
mfib_entry_cover_change_one (mfib_entry_t *cover,
			    fib_node_index_t covered,
			    void *args)
{
    fib_node_index_t new_cover;

    /*
     * The 3 entries involved here are:
     *   cover - the least specific. It will cover both the others
     *  new_cover - the enty just inserted below the cover
     *  covered - the entry that was tracking the cover.
     *
     * The checks below are to determine if new_cover is a cover for covered.
     */
    new_cover = pointer_to_uword(args);

    if (FIB_NODE_INDEX_INVALID == new_cover)
    {
	/*
	 * nothing has been inserted, which implies the cover was removed.
	 * 'cover' is thus the new cover.
	 */
	mfib_entry_cover_changed(covered);
    }
    else if (new_cover != covered)
    {
	const mfib_prefix_t *pfx_covered, *pfx_new_cover;

	pfx_covered = mfib_entry_get_prefix(covered);
	pfx_new_cover = mfib_entry_get_prefix(new_cover);

	if (mfib_prefix_is_cover(pfx_new_cover, pfx_covered))
	{
	    mfib_entry_cover_changed(covered);
	}
    }
    /* continue */
    return (1);
}

void
mfib_entry_cover_change_notify (fib_node_index_t cover_index,
                                fib_node_index_t covered)
{
    mfib_entry_t *cover;

    cover = mfib_entry_get(cover_index);

    mfib_entry_cover_walk(cover, 
                          mfib_entry_cover_change_one,
                          uword_to_pointer(covered, void*));
}

static int
mfib_entry_cover_update_one (mfib_entry_t *cover,
			    fib_node_index_t covered,
			    void *args)
{
    mfib_entry_cover_updated(covered);

    /* continue */
    return (1);
}

void
mfib_entry_cover_update_notify (mfib_entry_t *mfib_entry)
{
    mfib_entry_cover_walk(mfib_entry, 
			 mfib_entry_cover_update_one,
			 NULL);
}
