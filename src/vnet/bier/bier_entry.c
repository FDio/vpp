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

#include <vnet/bier/bier_entry.h>
#include <vnet/bier/bier_update.h>

#include <vnet/fib/fib_path_list.h>

#include <vnet/bier/bier_fmask_db.h>
#include <vnet/bier/bier_fmask.h>
#include <vnet/bier/bier_table.h>

bier_entry_t *bier_entry_pool;

static index_t
bier_entry_get_index (const bier_entry_t *be)
{
    return (be - bier_entry_pool);
}

static fib_path_list_walk_rc_t
bier_entry_link_walk (fib_node_index_t pl_index,
                      fib_node_index_t path_index,
                      void *arg)
{
    bier_entry_t *be = arg;
    index_t bfmi;

    bfmi = fib_path_get_resolving_index(path_index);
    bier_fmask_link(bfmi, be->be_bp);

    return (FIB_PATH_LIST_WALK_CONTINUE);
}

static fib_path_list_walk_rc_t
bier_entry_unlink_walk (fib_node_index_t pl_index,
                        fib_node_index_t path_index,
                        void *arg)
{
    bier_entry_t *be = arg;
    index_t bfmi;

    bfmi = fib_path_get_resolving_index(path_index);
    bier_fmask_unlink(bfmi, be->be_bp);

    return (FIB_PATH_LIST_WALK_CONTINUE);
}

index_t
bier_entry_create (index_t bti,
                   bier_bp_t bp)
{
    bier_entry_t *be;

    pool_get(bier_entry_pool, be);

    be->be_bp = bp;
    be->be_bti = bti;
    be->be_path_list = FIB_NODE_INDEX_INVALID;

    return (bier_entry_get_index(be));
}

void
bier_entry_delete (index_t bei)
{
    bier_entry_t *be;

    be = bier_entry_get(bei);

    /*
     * if we still ahve a path-list, unlink from it
     */
    if (FIB_NODE_INDEX_INVALID != be->be_path_list)
    {
        fib_path_list_walk(be->be_path_list,
                           bier_entry_unlink_walk,
                           be);
        fib_path_list_child_remove(be->be_path_list,
                                   be->be_sibling_index);
    }

    pool_put(bier_entry_pool, be);
}

static void
bier_entry_table_ecmp_walk_add_fmask (index_t btei,
                                      void *arg)
{
    bier_entry_t *be = arg;;

    /*
     * choose a fmask from the entry's resolved set to add
     * to ECMP table's lookup table
     */
    if (FIB_NODE_INDEX_INVALID != be->be_path_list)
    {
        const bier_table_id_t *btid;
        dpo_id_t dpo = DPO_INVALID;
        const dpo_id_t *choice;
        load_balance_t *lb;

        btid = bier_table_get_id(btei);

        fib_path_list_contribute_forwarding(be->be_path_list,
                                            FIB_FORW_CHAIN_TYPE_BIER,
                                            &dpo);

        /*
         * select the appropriate bucket from the LB
         */
        ASSERT(dpo.dpoi_type == DPO_LOAD_BALANCE);

        lb = load_balance_get(dpo.dpoi_index);

        choice = load_balance_get_bucket_i(lb,
                                           btid->bti_ecmp &
                                           (lb->lb_n_buckets_minus_1));

        if (choice->dpoi_type == DPO_BIER_FMASK)
        {
            bier_table_ecmp_set_fmask(btei, be->be_bp,
                                      choice->dpoi_index);
        }
        else
        {
            /*
             * any other type results in a drop, which we represent
             * with an empty bucket
             */
            bier_table_ecmp_set_fmask(btei, be->be_bp,
                                      INDEX_INVALID);
        }

        dpo_reset(&dpo);
    }
    else
    {
        /*
         * no fmasks left. insert a drop
         */
        bier_table_ecmp_set_fmask(btei, be->be_bp, INDEX_INVALID);
    }
}

void
bier_entry_path_add (index_t bei,
                     const fib_route_path_t *rpaths)
{
    fib_node_index_t old_pl_index;
    bier_entry_t *be;

    be = bier_entry_get(bei);
    old_pl_index = be->be_path_list;

    /*
     * lock the path-list so it does not go away before we unlink
     * from its resolved fmasks
     */
    fib_path_list_lock(old_pl_index);

    if (FIB_NODE_INDEX_INVALID == be->be_path_list)
    {
        old_pl_index = FIB_NODE_INDEX_INVALID;
        be->be_path_list = fib_path_list_create((FIB_PATH_LIST_FLAG_SHARED |
                                                 FIB_PATH_LIST_FLAG_NO_URPF),
                                                rpaths);
        be->be_sibling_index = fib_path_list_child_add(be->be_path_list,
                                                       FIB_NODE_TYPE_BIER_ENTRY,
                                                       bier_entry_get_index(be));
    }
    else
    {

        old_pl_index = be->be_path_list;

        be->be_path_list =
            fib_path_list_copy_and_path_add(old_pl_index,
                                            (FIB_PATH_LIST_FLAG_SHARED |
                                             FIB_PATH_LIST_FLAG_NO_URPF),
                                            rpaths);

        fib_path_list_child_remove(old_pl_index,
                                   be->be_sibling_index);
        be->be_sibling_index = fib_path_list_child_add(be->be_path_list,
                                                       FIB_NODE_TYPE_BIER_ENTRY,
                                                       bier_entry_get_index(be));
    }
    /*
     * link the entry's bit-position to each fmask in the new path-list
     * then unlink from the old.
     */
    fib_path_list_walk(be->be_path_list,
                       bier_entry_link_walk,
                       be);
    if (FIB_NODE_INDEX_INVALID != old_pl_index)
    {
        fib_path_list_walk(old_pl_index,
                           bier_entry_unlink_walk,
                           be);
    }

    /*
     * update the ECNP tables with the new choice
     */
    bier_table_ecmp_walk(be->be_bti,
                         bier_entry_table_ecmp_walk_add_fmask,
                         be);

    /*
     * symmetric unlock. The old path-list may not exist hereinafter
     */
    fib_path_list_unlock(old_pl_index);
}

int
bier_entry_path_remove (index_t bei,
                        const fib_route_path_t *rpaths)
{
    fib_node_index_t old_pl_index;
    bier_entry_t *be;

    be = bier_entry_get(bei);
    old_pl_index = be->be_path_list;

    fib_path_list_lock(old_pl_index);

    ASSERT (FIB_NODE_INDEX_INVALID != be->be_path_list);

    be->be_path_list =
        fib_path_list_copy_and_path_remove(old_pl_index,
                                           (FIB_PATH_LIST_FLAG_SHARED |
                                            FIB_PATH_LIST_FLAG_NO_URPF),
                                           rpaths);

    if (be->be_path_list != old_pl_index)
    {
        /*
         * a path was removed
         */
        fib_path_list_child_remove(old_pl_index,
                                   be->be_sibling_index);

        if (FIB_NODE_INDEX_INVALID != be->be_path_list)
        {
            /*
             * link the entry's bit-position to each fmask in the new path-list
             * then unlink from the old.
             */
            fib_path_list_walk(be->be_path_list,
                               bier_entry_link_walk,
                               be);
            be->be_sibling_index =
                fib_path_list_child_add(be->be_path_list,
                                        FIB_NODE_TYPE_BIER_ENTRY,
                                        bier_entry_get_index(be));
        }

        fib_path_list_walk(old_pl_index,
                           bier_entry_unlink_walk,
                           be);
    }
    fib_path_list_unlock(old_pl_index);


    /*
     * update the ECNP tables with the new choice
     */
    bier_table_ecmp_walk(be->be_bti,
                         bier_entry_table_ecmp_walk_add_fmask,
                         be);

    return (fib_path_list_get_n_paths(be->be_path_list));
}

void
bier_entry_contribute_forwarding(index_t bei,
                                 dpo_id_t *dpo)
{
    bier_entry_t *be = bier_entry_get(bei);

    fib_path_list_contribute_forwarding(be->be_path_list,
                                        FIB_FORW_CHAIN_TYPE_BIER,
                                        dpo);
}

u8*
format_bier_entry (u8* s, va_list *ap)
{
    index_t bei = va_arg(*ap, index_t);
    bier_show_flags_t flags = va_arg(*ap, bier_show_flags_t);

    bier_entry_t *be = bier_entry_get(bei);

    s = format(s, " bp:%d\n", be->be_bp);
    s = fib_path_list_format(be->be_path_list, s);

    if (flags & BIER_SHOW_DETAIL)
    {
        dpo_id_t dpo = DPO_INVALID;

        bier_entry_contribute_forwarding(bei, &dpo);

        s = format(s, " forwarding:\n");
        s = format(s, "  %U",
                   format_dpo_id, &dpo, 2);
        s = format(s, "\n");
    }

    return (s);
}

static fib_node_t *
bier_entry_get_node (fib_node_index_t index)
{
    bier_entry_t *be = bier_entry_get(index);
    return (&(be->be_node));
}

static bier_entry_t*
bier_entry_get_from_node (fib_node_t *node)
{
    return ((bier_entry_t*)(((char*)node) -
                            STRUCT_OFFSET_OF(bier_entry_t,
                                             be_node)));
}

static void
bier_entry_last_lock_gone (fib_node_t *node)
{
    /*
     * the lifetime of the entry is managed by the table.
     */
    ASSERT(0);
}

/*
 * A back walk has reached this BIER entry
 */
static fib_node_back_walk_rc_t
bier_entry_back_walk_notify (fib_node_t *node,
                             fib_node_back_walk_ctx_t *ctx)
{
    /*
     * re-populate the ECMP tables with new choices
     */
    bier_entry_t *be = bier_entry_get_from_node(node);

    bier_table_ecmp_walk(be->be_bti,
                         bier_entry_table_ecmp_walk_add_fmask,
                         be);

    /*
     * no need to propagate further up the graph.
     */
    return (FIB_NODE_BACK_WALK_CONTINUE);
}

/*
 * The BIER fmask's graph node virtual function table
 */
static const fib_node_vft_t bier_entry_vft = {
    .fnv_get = bier_entry_get_node,
    .fnv_last_lock = bier_entry_last_lock_gone,
    .fnv_back_walk = bier_entry_back_walk_notify,
};

clib_error_t *
bier_entry_module_init (vlib_main_t * vm)
{
    fib_node_register_type (FIB_NODE_TYPE_BIER_ENTRY, &bier_entry_vft);

    return (NULL);
}

VLIB_INIT_FUNCTION (bier_entry_module_init);
