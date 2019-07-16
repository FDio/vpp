/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/fib/fib_entry_track.h>
#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_delegate.h>
#include <vnet/fib/fib_walk.h>

static fib_entry_delegate_t *
fib_entry_track_delegate_add (u32 fib_index,
                              const fib_prefix_t *prefix)
{
    fib_entry_delegate_t *fed;
    fib_node_index_t fei;

    fei = fib_table_entry_special_add(fib_index,
                                      prefix,
                                      FIB_SOURCE_RR,
                                      FIB_ENTRY_FLAG_NONE);

    fed = fib_entry_delegate_find_or_add(fib_entry_get(fei),
                                         FIB_ENTRY_DELEGATE_TRACK);

    fib_node_init(&fed->fd_track.fedt_node,
                  FIB_NODE_TYPE_ENTRY_TRACK);

    fed->fd_entry_index = fei;
    fed->fd_track.fedt_sibling =
        fib_entry_child_add(fei,
                            FIB_NODE_TYPE_ENTRY_TRACK,
                            fib_entry_delegate_get_index(fed));

    return (fed);
}

fib_node_index_t
fib_entry_track (u32 fib_index,
                 const fib_prefix_t *prefix,
                 fib_node_type_t child_type,
                 index_t child_index,
                 u32 *sibling)
{
    fib_entry_delegate_t *fed;
    fib_node_index_t fei;

    fei = fib_table_lookup_exact_match(fib_index, prefix);

    if (INDEX_INVALID == fei ||
        NULL == (fed = fib_entry_delegate_find(fib_entry_get(fei),
                                               FIB_ENTRY_DELEGATE_TRACK)))
    {
        fed = fib_entry_track_delegate_add(fib_index, prefix);
    }

    /*
     * add this child to the entry's delegate
     */
    *sibling = fib_node_child_add(FIB_NODE_TYPE_ENTRY_TRACK,
                                  fib_entry_delegate_get_index(fed),
                                  child_type,
                                  child_index);

    return (fed->fd_entry_index);
}

void
fib_entry_untrack (fib_node_index_t fei,
                   u32 sibling)
{
    fib_entry_delegate_t *fed;

    fed = fib_entry_delegate_find(fib_entry_get(fei),
                                  FIB_ENTRY_DELEGATE_TRACK);

    if (NULL != fed)
    {
        fib_node_child_remove(FIB_NODE_TYPE_ENTRY_TRACK,
                              fib_entry_delegate_get_index(fed),
                              sibling);
        /* if this is the last child the delegate will be removed. */
    }
    /* else untracked */
}

static fib_node_t *
fib_entry_track_get_node (fib_node_index_t index)
{
    fib_entry_delegate_t *fed;

    fed = fib_entry_delegate_get(index);
    return (&fed->fd_track.fedt_node);
}

static fib_entry_delegate_t*
fib_entry_delegate_from_fib_node (fib_node_t *node)
{
    ASSERT(FIB_NODE_TYPE_ENTRY_TRACK == node->fn_type);
    return ((fib_entry_delegate_t *) (((char *) node) -
                                      STRUCT_OFFSET_OF (fib_entry_delegate_t,
                                                        fd_track.fedt_node)));
}

static void
fib_entry_track_last_lock_gone (fib_node_t *node)
{
    fib_entry_delegate_t *fed;
    fib_node_index_t fei;
    u32 sibling;

    fed = fib_entry_delegate_from_fib_node(node);
    fei = fed->fd_entry_index;
    sibling = fed->fd_track.fedt_sibling;

    /*
     * the tracker has no more children so it can be removed,
     * and the FIB entry unsourced.
     * remove the delegate first, then unlock the fib entry,
     * since the delegate may be holding the last lock
     */
    fib_entry_delegate_remove(fib_entry_get(fei),
                              FIB_ENTRY_DELEGATE_TRACK);
    /* having removed the deletegate the fed object is now toast */
    fib_entry_child_remove(fei, sibling);

    fib_table_entry_delete_index(fei, FIB_SOURCE_RR);
}

static fib_node_back_walk_rc_t
fib_entry_track_back_walk_notify (fib_node_t *node,
                                  fib_node_back_walk_ctx_t *ctx)
{
    fib_entry_delegate_t *fed;

    fed = fib_entry_delegate_from_fib_node(node);

    /*
     * propagate the walk to the delgate's children
     */
    
    fib_walk_sync(FIB_NODE_TYPE_ENTRY_TRACK,
                  fib_entry_delegate_get_index(fed),
                  ctx);

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

static void
fib_entry_track_show_memory (void)
{
}

/*
 * The FIB entry tracker's graph node virtual function table
 */
static const fib_node_vft_t fib_entry_track_vft = {
    .fnv_get = fib_entry_track_get_node,
    .fnv_last_lock = fib_entry_track_last_lock_gone,
    .fnv_back_walk = fib_entry_track_back_walk_notify,
    .fnv_mem_show = fib_entry_track_show_memory,
};

void
fib_entry_track_module_init (void)
{
    fib_node_register_type(FIB_NODE_TYPE_ENTRY_TRACK, &fib_entry_track_vft);
}
