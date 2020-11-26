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

#include <vnet/fib/fib_entry_cover.h>
#include <vnet/fib/fib_entry_src.h>
#include <vnet/fib/fib_node_list.h>
#include <vnet/fib/fib_entry_delegate.h>

u32
fib_entry_cover_track (fib_entry_t* cover,
		       fib_node_index_t covered)
{
    fib_entry_delegate_t *fed;

    FIB_ENTRY_DBG(cover, "cover-track %d", covered);

    ASSERT(fib_entry_get_index(cover) != covered);

    fed = fib_entry_delegate_find(cover, FIB_ENTRY_DELEGATE_COVERED);

    if (NULL == fed)
    {
        fed = fib_entry_delegate_find_or_add(cover, FIB_ENTRY_DELEGATE_COVERED);
        fed->fd_list = fib_node_list_create();
    }

    return (fib_node_list_push_front(fed->fd_list,
                                     0, FIB_NODE_TYPE_ENTRY,
                                     covered));
}

void
fib_entry_cover_untrack (fib_entry_t* cover,
			 u32 tracked_index)
{
    fib_entry_delegate_t *fed;

    FIB_ENTRY_DBG(cover, "cover-untrack @ %d", tracked_index);

    fed = fib_entry_delegate_find(cover, FIB_ENTRY_DELEGATE_COVERED);

    if (NULL == fed)
        return;

    fib_node_list_remove(fed->fd_list, tracked_index);

    if (0 == fib_node_list_get_size(fed->fd_list))
    {
        fib_node_list_destroy(&fed->fd_list);
        fib_entry_delegate_remove(cover, FIB_ENTRY_DELEGATE_COVERED);        
    }
}

/**
 * Internal struct to hold user supplied parameters for the cover walk
 */
typedef struct fib_enty_cover_walk_ctx_t_ {
    fib_entry_t *cover;
    fib_entry_covered_walk_t walk;
    void *ctx;
} fib_enty_cover_walk_ctx_t;

static walk_rc_t
fib_entry_cover_walk_node_ptr (fib_node_ptr_t *depend,
			       void *args)
{
    fib_enty_cover_walk_ctx_t *ctx = args;

    ctx->walk(ctx->cover, depend->fnp_index, ctx->ctx);

    return (WALK_CONTINUE);
}

void
fib_entry_cover_walk (fib_entry_t *cover,
		      fib_entry_covered_walk_t walk,
		      void *args)
{
    fib_entry_delegate_t *fed;

    fed = fib_entry_delegate_find(cover, FIB_ENTRY_DELEGATE_COVERED);

    if (NULL == fed)
        return;

    fib_enty_cover_walk_ctx_t ctx = {
        .cover = cover,
        .walk = walk,
        .ctx = args,
    };

    fib_node_list_walk(fed->fd_list,
                       fib_entry_cover_walk_node_ptr,
                       &ctx);
}

static walk_rc_t
fib_entry_cover_change_one (fib_entry_t *cover,
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
	fib_entry_cover_changed(covered);
    }
    else if (new_cover != covered)
    {
	const fib_prefix_t *pfx_covered, *pfx_new_cover;

	pfx_covered = fib_entry_get_prefix(covered);
	pfx_new_cover = fib_entry_get_prefix(new_cover);

	if (fib_prefix_is_cover(pfx_new_cover, pfx_covered))
	{
	    fib_entry_cover_changed(covered);
	}
    }
    return (WALK_CONTINUE);
}

void
fib_entry_cover_change_notify (fib_node_index_t cover_index,
			       fib_node_index_t covered)
{
    fib_entry_t *cover;

    cover = fib_entry_get(cover_index);

    fib_entry_cover_walk(cover, 
			 fib_entry_cover_change_one,
			 uword_to_pointer(covered, void*));
}

static walk_rc_t
fib_entry_cover_update_one (fib_entry_t *cover,
			    fib_node_index_t covered,
			    void *args)
{
    fib_entry_cover_updated(covered);

    return (WALK_CONTINUE);
}

void
fib_entry_cover_update_notify (fib_entry_t *fib_entry)
{
    fib_entry_cover_walk(fib_entry, 
			 fib_entry_cover_update_one,
			 NULL);
}
