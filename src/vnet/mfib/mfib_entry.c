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

#include <vnet/mfib/mfib_entry.h>
#include <vnet/mfib/mfib_entry_src.h>
#include <vnet/mfib/mfib_entry_cover.h>
#include <vnet/fib/fib_path_list.h>
#include <vnet/fib/fib_walk.h>

#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/replicate_dpo.h>

/**
 * the logger
 */
vlib_log_class_t mfib_entry_logger;

/**
 * Pool of path extensions
 */
static mfib_path_ext_t *mfib_path_ext_pool;

/**
 * String names for each source
 */
static const char *mfib_source_names[] = MFIB_SOURCE_NAMES;

/*
 * Pool for all fib_entries
 */
mfib_entry_t *mfib_entry_pool;

static fib_node_t *
mfib_entry_get_node (fib_node_index_t index)
{
    return ((fib_node_t*)mfib_entry_get(index));
}

static fib_protocol_t
mfib_entry_get_proto (const mfib_entry_t * mfib_entry)
{
    return (mfib_entry->mfe_prefix.fp_proto);
}

fib_forward_chain_type_t
mfib_entry_get_default_chain_type (const mfib_entry_t *mfib_entry)
{
    switch (mfib_entry->mfe_prefix.fp_proto)
    {
    case FIB_PROTOCOL_IP4:
        return (FIB_FORW_CHAIN_TYPE_MCAST_IP4);
    case FIB_PROTOCOL_IP6:
        return (FIB_FORW_CHAIN_TYPE_MCAST_IP6);
    case FIB_PROTOCOL_MPLS:
        ASSERT(0);
        break;
    }
    return (FIB_FORW_CHAIN_TYPE_MCAST_IP4);
}

static u8 *
format_mfib_entry_dpo (u8 * s, va_list * args)
{
    index_t fei = va_arg(*args, index_t);
    CLIB_UNUSED(u32 indent) = va_arg(*args, u32);

    return (format(s, "%U",
                   format_mfib_entry, fei,
                   MFIB_ENTRY_FORMAT_BRIEF));
}

static inline mfib_path_ext_t *
mfib_entry_path_ext_get (index_t mi)
{
    return (pool_elt_at_index(mfib_path_ext_pool, mi));
}

static u8 *
format_mfib_entry_path_ext (u8 * s, va_list * args)
{
    mfib_path_ext_t *path_ext;
    index_t mpi = va_arg(*args, index_t);

    path_ext = mfib_entry_path_ext_get(mpi);
    return (format(s, "path:%d flags:%U",
                   path_ext->mfpe_path,
                   format_mfib_itf_flags, path_ext->mfpe_flags));
}

u8 *
format_mfib_entry (u8 * s, va_list * args)
{
    fib_node_index_t fei, mfi;
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;
    u32 sw_if_index;
    int level;

    fei = va_arg (*args, fib_node_index_t);
    level = va_arg (*args, int);
    mfib_entry = mfib_entry_get(fei);

    s = format (s, "%U", format_mfib_prefix, &mfib_entry->mfe_prefix);
    s = format (s, ": %U", format_mfib_entry_flags, mfib_entry->mfe_flags);

    if (level >= MFIB_ENTRY_FORMAT_DETAIL)
    {
        fib_node_index_t path_index, mpi;

        s = format (s, "\n");
        s = format (s, " fib:%d", mfib_entry->mfe_fib_index);
        s = format (s, " index:%d", mfib_entry_get_index(mfib_entry));
        s = format (s, " locks:%d\n", mfib_entry->mfe_node.fn_locks);
        vec_foreach(msrc, mfib_entry->mfe_srcs)
        {
            s = format (s, "  src:%s locks:%d:",
                        mfib_source_names[msrc->mfes_src],
                        msrc->mfes_ref_count);
            if (msrc->mfes_cover != FIB_NODE_INDEX_INVALID)
            {
                s = format (s, " cover:%d", msrc->mfes_cover);
            }
            s = format (s, " %U\n", format_mfib_entry_flags, msrc->mfes_flags);
            if (FIB_NODE_INDEX_INVALID != msrc->mfes_pl)
            {
                s = fib_path_list_format(msrc->mfes_pl, s);
            }
            s = format (s, "    Extensions:\n");
            hash_foreach(path_index, mpi, msrc->mfes_exts,
            ({
                s = format(s, "     %U\n", format_mfib_entry_path_ext, mpi);
            }));
            s = format (s, "    Interface-Forwarding:\n");
            hash_foreach(sw_if_index, mfi, msrc->mfes_itfs,
            ({
                s = format(s, "    %U\n", format_mfib_itf, mfi);
            }));
        }
    }

    s = format(s, "\n  Interfaces:");
    hash_foreach(sw_if_index, mfi, mfib_entry->mfe_itfs,
    ({
        s = format(s, "\n  %U", format_mfib_itf, mfi);
    }));
    if (MFIB_RPF_ID_NONE != mfib_entry->mfe_rpf_id)
    {
        s = format(s, "\n  RPF-ID:%d", mfib_entry->mfe_rpf_id);
    }
    s = format(s, "\n  %U-chain\n  %U",
               format_fib_forw_chain_type,
               mfib_entry_get_default_chain_type(mfib_entry),
               format_dpo_id,
               &mfib_entry->mfe_rep,
               2);
    s = format(s, "\n");

    if (level >= MFIB_ENTRY_FORMAT_DETAIL2)
    {
        s = format(s, "\nchildren:");
        s = fib_node_children_format(mfib_entry->mfe_node.fn_children, s);
    }

    return (s);
}

static mfib_entry_t*
mfib_entry_from_fib_node (fib_node_t *node)
{
    ASSERT(FIB_NODE_TYPE_MFIB_ENTRY == node->fn_type);
    return ((mfib_entry_t*)node);
}

static int
mfib_entry_src_cmp_for_sort (void * v1,
                             void * v2)
{
    mfib_entry_src_t *esrc1 = v1, *esrc2 = v2;

    return (esrc1->mfes_src - esrc2->mfes_src);
}

static void
mfib_entry_src_init (mfib_entry_t *mfib_entry,
                     mfib_source_t source)

{
    mfib_entry_src_t esrc = {
        .mfes_pl = FIB_NODE_INDEX_INVALID,
        .mfes_flags = MFIB_ENTRY_FLAG_NONE,
        .mfes_src = source,
        .mfes_cover = FIB_NODE_INDEX_INVALID,
        .mfes_sibling = FIB_NODE_INDEX_INVALID,
        .mfes_ref_count = 1,
    };

    vec_add1(mfib_entry->mfe_srcs, esrc);
    vec_sort_with_function(mfib_entry->mfe_srcs,
                           mfib_entry_src_cmp_for_sort);
}

static mfib_entry_src_t *
mfib_entry_src_find (const mfib_entry_t *mfib_entry,
                    mfib_source_t source,
                    u32 *index)

{
    mfib_entry_src_t *esrc;
    int ii;

    ii = 0;
    vec_foreach(esrc, mfib_entry->mfe_srcs)
    {
        if (esrc->mfes_src == source)
        {
            if (NULL != index)
            {
                *index = ii;
            }
            return (esrc);
        }
        else
        {
            ii++;
        }
    }

    return (NULL);
}

static mfib_entry_src_t *
mfib_entry_src_find_or_create (mfib_entry_t *mfib_entry,
                               mfib_source_t source)
{
    mfib_entry_src_t *msrc;

    msrc = mfib_entry_src_find(mfib_entry, source, NULL);

    if (NULL == msrc)
    {
        mfib_entry_src_init(mfib_entry, source);
        msrc = mfib_entry_src_find(mfib_entry, source, NULL);
    }

    return (msrc);
}

static mfib_entry_src_t *
mfib_entry_src_update (mfib_entry_t *mfib_entry,
                       mfib_source_t source,
                       fib_rpf_id_t rpf_id,
                       mfib_entry_flags_t entry_flags)
{
    mfib_entry_src_t *msrc;

    msrc = mfib_entry_src_find_or_create(mfib_entry, source);

    msrc->mfes_flags = entry_flags;
    msrc->mfes_rpf_id = rpf_id;

    return (msrc);
}

static mfib_entry_src_t *
mfib_entry_src_update_and_lock (mfib_entry_t *mfib_entry,
                                mfib_source_t source,
                                fib_rpf_id_t rpf_id,
                                mfib_entry_flags_t entry_flags)
{
    mfib_entry_src_t *msrc;

    msrc = mfib_entry_src_update(mfib_entry, source, rpf_id, entry_flags);

    msrc->mfes_ref_count++;

    return (msrc);
}

mfib_entry_src_t*
mfib_entry_get_best_src (const mfib_entry_t *mfib_entry)
{
    mfib_entry_src_t *bsrc;

    /*
     * the enum of sources is deliberately arranged in priority order
     */
    if (0 == vec_len(mfib_entry->mfe_srcs))
    {
        bsrc = NULL;
    }
    else
    {
        bsrc = vec_elt_at_index(mfib_entry->mfe_srcs, 0);
    }

    return (bsrc);
}

static mfib_source_t
mfib_entry_get_best_source (const mfib_entry_t *mfib_entry)
{
    mfib_entry_src_t *bsrc;

    bsrc = mfib_entry_get_best_src(mfib_entry);

    return (bsrc->mfes_src);
}

int
mfib_entry_is_sourced (fib_node_index_t mfib_entry_index,
                       mfib_source_t source)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);

    return (NULL != mfib_entry_src_find(mfib_entry, source, NULL));
}

int
mfib_entry_is_host (fib_node_index_t mfib_entry_index)
{
    return (mfib_prefix_is_host(mfib_entry_get_prefix(mfib_entry_index)));
}


static void
mfib_entry_src_flush (mfib_entry_src_t *msrc)
{
    u32 sw_if_index;
    index_t mfii;

    hash_foreach(sw_if_index, mfii, msrc->mfes_itfs,
    ({
        mfib_itf_delete(mfib_itf_get(mfii));
    }));
    hash_free(msrc->mfes_itfs);
    msrc->mfes_itfs = NULL;
    fib_path_list_unlock(msrc->mfes_pl);
}

static void
mfib_entry_src_remove (mfib_entry_t *mfib_entry,
                       mfib_source_t source)

{
    mfib_entry_src_t *msrc;
    u32 index = ~0;

    msrc = mfib_entry_src_find(mfib_entry, source, &index);

    if (NULL != msrc)
    {
        ASSERT(0 != msrc->mfes_ref_count);
        msrc->mfes_ref_count--;

        if (0 == msrc->mfes_ref_count)
        {
            mfib_entry_src_deactivate(mfib_entry, msrc);
            mfib_entry_src_flush(msrc);

            vec_del1(mfib_entry->mfe_srcs, index);
            if (vec_len (mfib_entry->mfe_srcs) > 1)
                vec_sort_with_function(mfib_entry->mfe_srcs,
                                       mfib_entry_src_cmp_for_sort);
        }
    }
}

u32
mfib_entry_child_add (fib_node_index_t mfib_entry_index,
                      fib_node_type_t child_type,
                      fib_node_index_t child_index)
{
    return (fib_node_child_add(FIB_NODE_TYPE_MFIB_ENTRY,
                               mfib_entry_index,
                               child_type,
                               child_index));
};

void
mfib_entry_child_remove (fib_node_index_t mfib_entry_index,
                         u32 sibling_index)
{
    fib_node_child_remove(FIB_NODE_TYPE_MFIB_ENTRY,
                          mfib_entry_index,
                          sibling_index);
}

static mfib_entry_t *
mfib_entry_alloc (u32 fib_index,
                  const mfib_prefix_t *prefix,
                  fib_node_index_t *mfib_entry_index)
{
    mfib_entry_t *mfib_entry;

    pool_get_aligned(mfib_entry_pool, mfib_entry, CLIB_CACHE_LINE_BYTES);

    fib_node_init(&mfib_entry->mfe_node,
                  FIB_NODE_TYPE_MFIB_ENTRY);

    /*
     * Some of the members require non-default initialisation
     * so we also init those that don't and thus save on the call to clib_memset.
     */
    mfib_entry->mfe_flags = 0;
    mfib_entry->mfe_fib_index = fib_index;
    mfib_entry->mfe_prefix = *prefix;
    mfib_entry->mfe_srcs = NULL;
    mfib_entry->mfe_itfs = NULL;
    mfib_entry->mfe_rpf_id = MFIB_RPF_ID_NONE;
    mfib_entry->mfe_pl = FIB_NODE_INDEX_INVALID;

    dpo_reset(&mfib_entry->mfe_rep);

    *mfib_entry_index = mfib_entry_get_index(mfib_entry);

    MFIB_ENTRY_DBG(mfib_entry, "alloc");

    return (mfib_entry);
}

static inline mfib_path_ext_t *
mfib_entry_path_ext_find (mfib_path_ext_t *exts,
                          fib_node_index_t path_index)
{
    uword *p;

    p = hash_get(exts, path_index);

    if (NULL != p)
    {
        return (mfib_entry_path_ext_get(p[0]));
    }

    return (NULL);
}

static mfib_path_ext_t*
mfib_path_ext_add (mfib_entry_src_t *msrc,
                   fib_node_index_t path_index,
                   mfib_itf_flags_t mfi_flags)
{
    mfib_path_ext_t *path_ext;

    pool_get(mfib_path_ext_pool, path_ext);

    path_ext->mfpe_flags = mfi_flags;
    path_ext->mfpe_path = path_index;

    hash_set(msrc->mfes_exts, path_index,
             path_ext - mfib_path_ext_pool);

    return (path_ext);
}

static void
mfib_path_ext_remove (mfib_entry_src_t *msrc,
                      fib_node_index_t path_index)
{
    mfib_path_ext_t *path_ext;

    path_ext = mfib_entry_path_ext_find(msrc->mfes_exts, path_index);

    hash_unset(msrc->mfes_exts, path_index);
    pool_put(mfib_path_ext_pool, path_ext);
}

typedef struct mfib_entry_collect_forwarding_ctx_t_
{
    load_balance_path_t * next_hops;
    fib_forward_chain_type_t fct;
    mfib_entry_src_t *msrc;
} mfib_entry_collect_forwarding_ctx_t;

static fib_path_list_walk_rc_t
mfib_entry_src_collect_forwarding (fib_node_index_t pl_index,
                                   fib_node_index_t path_index,
                                   void *arg)
{
    mfib_entry_collect_forwarding_ctx_t *ctx;
    load_balance_path_t *nh;

    ctx = arg;

    /*
     * if the path is not resolved, don't include it.
     */
    if (!fib_path_is_resolved(path_index))
    {
        return (FIB_PATH_LIST_WALK_CONTINUE);
    }

    /*
     * If the path is not forwarding to use it
     */
    mfib_path_ext_t *path_ext;
    
    path_ext = mfib_entry_path_ext_find(ctx->msrc->mfes_exts,
                                        path_index);

    if (NULL != path_ext &&
        !(path_ext->mfpe_flags & MFIB_ITF_FLAG_FORWARD))
    {
        return (FIB_PATH_LIST_WALK_CONTINUE);
    }
    
    switch (ctx->fct)
    {
    case FIB_FORW_CHAIN_TYPE_MCAST_IP4:
    case FIB_FORW_CHAIN_TYPE_MCAST_IP6:
        /*
         * EOS traffic with no label to stack, we need the IP Adj
         */
        vec_add2(ctx->next_hops, nh, 1);

        nh->path_index = path_index;
        nh->path_weight = fib_path_get_weight(path_index);
        fib_path_contribute_forwarding(path_index, ctx->fct, &nh->path_dpo);
        break;

    case FIB_FORW_CHAIN_TYPE_UNICAST_IP4:
    case FIB_FORW_CHAIN_TYPE_UNICAST_IP6:
    case FIB_FORW_CHAIN_TYPE_MPLS_NON_EOS:
    case FIB_FORW_CHAIN_TYPE_MPLS_EOS:
    case FIB_FORW_CHAIN_TYPE_ETHERNET:
    case FIB_FORW_CHAIN_TYPE_NSH:
    case FIB_FORW_CHAIN_TYPE_BIER:
        ASSERT(0);
        break;
    }

    return (FIB_PATH_LIST_WALK_CONTINUE);
}

static void
mfib_entry_stack (mfib_entry_t *mfib_entry,
                  mfib_entry_src_t *msrc)
{
    dpo_proto_t dp;

    dp = fib_proto_to_dpo(mfib_entry_get_proto(mfib_entry));

    /*
     * unlink the enty from the previous path list.
     */
    if (FIB_NODE_INDEX_INVALID != mfib_entry->mfe_pl)
    {
        fib_path_list_child_remove(mfib_entry->mfe_pl,
                                   mfib_entry->mfe_sibling);
    }

    if (NULL != msrc)
    {
        mfib_entry_collect_forwarding_ctx_t ctx = {
            .next_hops = NULL,
            .fct = mfib_entry_get_default_chain_type(mfib_entry),
            .msrc = msrc,
        };

        /*
         * link the entry to the path-list.
         * The entry needs to be a child so that we receive the back-walk
         * updates to recalculate forwarding.
         */
        mfib_entry->mfe_pl = msrc->mfes_pl;
        mfib_entry->mfe_flags = msrc->mfes_flags;
        mfib_entry->mfe_itfs = msrc->mfes_itfs;
        mfib_entry->mfe_rpf_id = msrc->mfes_rpf_id;

        if (FIB_NODE_INDEX_INVALID != mfib_entry->mfe_pl)
        {
            mfib_entry->mfe_sibling =
                fib_path_list_child_add(mfib_entry->mfe_pl,
                                        FIB_NODE_TYPE_MFIB_ENTRY,
                                        mfib_entry_get_index(mfib_entry));

            fib_path_list_walk(mfib_entry->mfe_pl,
                               mfib_entry_src_collect_forwarding,
                               &ctx);
        }
        if (!(MFIB_ENTRY_FLAG_EXCLUSIVE & mfib_entry->mfe_flags))
        {
            if (NULL == ctx.next_hops)
            {
                /*
                 * no next-hops, stack directly on the drop
                 */
                dpo_stack(DPO_MFIB_ENTRY, dp,
                          &mfib_entry->mfe_rep,
                          drop_dpo_get(dp));
            }
            else
            {
                /*
                 * each path contirbutes a next-hop. form a replicate
                 * from those choices.
                 */
                if (!dpo_id_is_valid(&mfib_entry->mfe_rep) ||
                    dpo_is_drop(&mfib_entry->mfe_rep))
                {
                    dpo_id_t tmp_dpo = DPO_INVALID;

                    dpo_set(&tmp_dpo,
                            DPO_REPLICATE, dp,
                            replicate_create(0, dp));

                    dpo_stack(DPO_MFIB_ENTRY, dp,
                              &mfib_entry->mfe_rep,
                              &tmp_dpo);

                    dpo_reset(&tmp_dpo);
                }
                replicate_multipath_update(&mfib_entry->mfe_rep,
                                           ctx.next_hops);
            }
        }
        else
        {
            /*
             * for exclusive routes the source provided a replicate DPO
             * which we stashed in the special path list with one path,
             * so we can stack directly on that.
             */
            ASSERT(1 == vec_len(ctx.next_hops));

            if (NULL != ctx.next_hops)
            {
                dpo_stack(DPO_MFIB_ENTRY, dp,
                          &mfib_entry->mfe_rep,
                          &ctx.next_hops[0].path_dpo);
                dpo_reset(&ctx.next_hops[0].path_dpo);
                vec_free(ctx.next_hops);
            }
            else
            {
                dpo_stack(DPO_MFIB_ENTRY, dp,
                          &mfib_entry->mfe_rep,
                          drop_dpo_get(dp));
            }
        }
    }
    else
    {
        dpo_stack(DPO_MFIB_ENTRY, dp,
                  &mfib_entry->mfe_rep,
                  drop_dpo_get(dp));
    }

    /*
     * time for walkies fido.
     */
    fib_node_back_walk_ctx_t bw_ctx = {
        .fnbw_reason = FIB_NODE_BW_REASON_FLAG_EVALUATE,
    };

    fib_walk_sync(FIB_NODE_TYPE_MFIB_ENTRY,
                  mfib_entry_get_index(mfib_entry),
                  &bw_ctx);
}

static fib_node_index_t
mfib_entry_src_path_add (mfib_entry_src_t *msrc,
                         const fib_route_path_t *rpath)
{
    fib_node_index_t path_index;
    fib_route_path_t *rpaths;

    ASSERT(!(MFIB_ENTRY_FLAG_EXCLUSIVE & msrc->mfes_flags));

    /*
     * path-lists require a vector of paths
     */
    rpaths = NULL;
    vec_add1(rpaths, rpath[0]);

    if (FIB_NODE_INDEX_INVALID == msrc->mfes_pl)
    {
        /* A non-shared path-list */
        msrc->mfes_pl = fib_path_list_create(FIB_PATH_LIST_FLAG_NO_URPF,
                                             NULL);
        fib_path_list_lock(msrc->mfes_pl);
    }

    path_index = fib_path_list_path_add(msrc->mfes_pl, rpaths);

    vec_free(rpaths);

    return (path_index);
}

static fib_node_index_t
mfib_entry_src_path_remove (mfib_entry_src_t *msrc,
                            const fib_route_path_t *rpath)
{
    fib_node_index_t path_index;
    fib_route_path_t *rpaths;

    ASSERT(!(MFIB_ENTRY_FLAG_EXCLUSIVE & msrc->mfes_flags));

    /*
     * path-lists require a vector of paths
     */
    rpaths = NULL;
    vec_add1(rpaths, rpath[0]);

    path_index = fib_path_list_path_remove(msrc->mfes_pl, rpaths);

    vec_free(rpaths);

    return (path_index);
}

static void
mfib_entry_recalculate_forwarding (mfib_entry_t *mfib_entry,
                                   mfib_source_t old_best)
{
    mfib_entry_src_t *bsrc, *osrc;

    /*
     * copy the forwarding data from the bast source
     */
    bsrc = mfib_entry_get_best_src(mfib_entry);
    osrc = mfib_entry_src_find(mfib_entry, old_best, NULL);

    if (NULL != bsrc)
    {
        if (bsrc->mfes_src != old_best)
        {
            /*
             * we are changing from one source to another
             * deactivate the old, and activate the new
             */
            mfib_entry_src_deactivate(mfib_entry, osrc);
            mfib_entry_src_activate(mfib_entry, bsrc);
        }
    }
    else
    {
        mfib_entry_src_deactivate(mfib_entry, osrc);
    }

    mfib_entry_stack(mfib_entry, bsrc);
    mfib_entry_cover_update_notify(mfib_entry);
}


fib_node_index_t
mfib_entry_create (u32 fib_index,
                   mfib_source_t source,
                   const mfib_prefix_t *prefix,
                   fib_rpf_id_t rpf_id,
                   mfib_entry_flags_t entry_flags,
                   index_t repi)
{
    fib_node_index_t mfib_entry_index;
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;

    mfib_entry = mfib_entry_alloc(fib_index, prefix,
                                  &mfib_entry_index);
    msrc = mfib_entry_src_update(mfib_entry, source,
                                 rpf_id, entry_flags);

    if (INDEX_INVALID != repi)
    {
        /*
         * The source is providing its own replicate DPO.
         * Create a sepcial path-list to manage it, that way
         * this entry and the source are equivalent to a normal
         * entry
         */
        fib_node_index_t old_pl_index;
        dpo_proto_t dp;
        dpo_id_t dpo = DPO_INVALID;

        dp = fib_proto_to_dpo(mfib_entry_get_proto(mfib_entry));
        old_pl_index = msrc->mfes_pl;

        dpo_set(&dpo, DPO_REPLICATE, dp, repi);

        msrc->mfes_pl =
            fib_path_list_create_special(dp,
                                         FIB_PATH_LIST_FLAG_EXCLUSIVE,
                                         &dpo);

        dpo_reset(&dpo);
        fib_path_list_lock(msrc->mfes_pl);
        fib_path_list_unlock(old_pl_index);
    }

    mfib_entry_recalculate_forwarding(mfib_entry, MFIB_SOURCE_NONE);

    return (mfib_entry_index);
}

static int
mfib_entry_ok_for_delete (mfib_entry_t *mfib_entry)
{
    return (0 == vec_len(mfib_entry->mfe_srcs));
}

static int
mfib_entry_src_ok_for_delete (const mfib_entry_src_t *msrc)
{
    return ((INDEX_INVALID == msrc->mfes_cover &&
             MFIB_ENTRY_FLAG_NONE == msrc->mfes_flags &&
             0 == fib_path_list_get_n_paths(msrc->mfes_pl)));
}


static void
mfib_entry_update_i (mfib_entry_t *mfib_entry,
                     mfib_entry_src_t *msrc,
                     mfib_source_t current_best,
                     index_t repi)
{
    if (INDEX_INVALID != repi)
    {
        /*
         * The source is providing its own replicate DPO.
         * Create a sepcial path-list to manage it, that way
         * this entry and the source are equivalent to a normal
         * entry
         */
        fib_node_index_t old_pl_index;
        dpo_proto_t dp;
        dpo_id_t dpo = DPO_INVALID;

        dp = fib_proto_to_dpo(mfib_entry_get_proto(mfib_entry));
        old_pl_index = msrc->mfes_pl;

        dpo_set(&dpo, DPO_REPLICATE, dp, repi);

        msrc->mfes_pl =
            fib_path_list_create_special(dp,
                                         FIB_PATH_LIST_FLAG_EXCLUSIVE,
                                         &dpo);

        dpo_reset(&dpo);
        fib_path_list_lock(msrc->mfes_pl);
        fib_path_list_unlock(old_pl_index);
    }

    if (mfib_entry_src_ok_for_delete(msrc))
    {
        /*
         * this source has no interfaces and no flags.
         * it has nothing left to give - remove it
         */
        mfib_entry_src_remove(mfib_entry, msrc->mfes_src);
    }

    mfib_entry_recalculate_forwarding(mfib_entry, current_best);
}

int
mfib_entry_special_add (fib_node_index_t mfib_entry_index,
                        mfib_source_t source,
                        mfib_entry_flags_t entry_flags,
                        fib_rpf_id_t rpf_id,
                        index_t repi)
{
    mfib_source_t current_best;
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    current_best = mfib_entry_get_best_source(mfib_entry);

    msrc = mfib_entry_src_update_and_lock(mfib_entry, source, rpf_id,
                                          entry_flags);

    mfib_entry_update_i(mfib_entry, msrc, current_best, repi);

    return (mfib_entry_ok_for_delete(mfib_entry));
}

int
mfib_entry_update (fib_node_index_t mfib_entry_index,
                   mfib_source_t source,
                   mfib_entry_flags_t entry_flags,
                   fib_rpf_id_t rpf_id,
                   index_t repi)
{
    mfib_source_t current_best;
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    current_best = mfib_entry_get_best_source(mfib_entry);
    msrc = mfib_entry_src_update(mfib_entry, source, rpf_id, entry_flags);

    mfib_entry_update_i(mfib_entry, msrc, current_best, repi);

    return (mfib_entry_ok_for_delete(mfib_entry));
}

static void
mfib_entry_itf_add (mfib_entry_src_t *msrc,
                    u32 sw_if_index,
                    index_t mi)
{
    hash_set(msrc->mfes_itfs, sw_if_index, mi);
}

static void
mfib_entry_itf_remove (mfib_entry_src_t *msrc,
                       u32 sw_if_index)
{
    mfib_itf_t *mfi;

    mfi = mfib_entry_itf_find(msrc->mfes_itfs, sw_if_index);

    mfib_itf_delete(mfi);

    hash_unset(msrc->mfes_itfs, sw_if_index);
}

void
mfib_entry_path_update (fib_node_index_t mfib_entry_index,
                        mfib_source_t source,
                        const fib_route_path_t *rpath,
                        mfib_itf_flags_t itf_flags)
{
    fib_node_index_t path_index;
    mfib_source_t current_best;
    mfib_path_ext_t *path_ext;
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;
    mfib_itf_flags_t old;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    ASSERT(NULL != mfib_entry);
    current_best = mfib_entry_get_best_source(mfib_entry);
    msrc = mfib_entry_src_find_or_create(mfib_entry, source);

    /*
     * add the path to the path-list. If it's a duplicate we'll get
     * back the original path.
     */
    path_index = mfib_entry_src_path_add(msrc, rpath);

    /*
     * find the path extension for that path
     */
    path_ext = mfib_entry_path_ext_find(msrc->mfes_exts, path_index);

    if (NULL == path_ext)
    {
        old = MFIB_ITF_FLAG_NONE;
        path_ext = mfib_path_ext_add(msrc, path_index, itf_flags);
    }
    else
    {
        old = path_ext->mfpe_flags;
        path_ext->mfpe_flags = itf_flags;
    }

    /*
     * Has the path changed its contribution to the input interface set.
     * Which only paths with interfaces can do...
     */
    if (~0 != rpath[0].frp_sw_if_index)
    {
        mfib_itf_t *mfib_itf;

        if (old != itf_flags)
        {
            /*
             * change of flag contributions
             */
            mfib_itf = mfib_entry_itf_find(msrc->mfes_itfs,
                                           rpath[0].frp_sw_if_index);

            if (NULL == mfib_itf)
            {
                mfib_entry_itf_add(msrc,
                                   rpath[0].frp_sw_if_index,
                                   mfib_itf_create(path_index, itf_flags));
            }
            else
            {
                if (mfib_itf_update(mfib_itf,
                                    path_index,
                                    itf_flags))
                {
                    /*
                     * no more interface flags on this path, remove
                     * from the data-plane set
                     */
                    mfib_entry_itf_remove(msrc, rpath[0].frp_sw_if_index);
                }
            }
        }
    }

    mfib_entry_recalculate_forwarding(mfib_entry, current_best);
}

/*
 * mfib_entry_path_remove
 *
 * remove a path from the entry.
 * return the mfib_entry's index if it is still present, INVALID otherwise.
 */
int
mfib_entry_path_remove (fib_node_index_t mfib_entry_index,
                        mfib_source_t source,
                        const fib_route_path_t *rpath)
{
    fib_node_index_t path_index;
    mfib_source_t current_best;
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    ASSERT(NULL != mfib_entry);
    current_best = mfib_entry_get_best_source(mfib_entry);
    msrc = mfib_entry_src_find(mfib_entry, source, NULL);

    if (NULL == msrc)
    {
        /*
         * there are no paths left for this source
         */
        return (mfib_entry_ok_for_delete(mfib_entry));
    }

    /*
     * remove the path from the path-list. If it's not there we'll get
     * back invalid
     */
    path_index = mfib_entry_src_path_remove(msrc, rpath);

    if (FIB_NODE_INDEX_INVALID != path_index)
    {
        /*
         * don't need the extension, nor the interface anymore
         */
        mfib_path_ext_remove(msrc, path_index);
        if (~0 != rpath[0].frp_sw_if_index)
        {
            mfib_itf_t *mfib_itf;

            mfib_itf = mfib_entry_itf_find(msrc->mfes_itfs,
                                           rpath[0].frp_sw_if_index);

            if (mfib_itf_update(mfib_itf,
                                path_index,
                                MFIB_ITF_FLAG_NONE))
            {
                /*
                 * no more interface flags on this path, remove
                 * from the data-plane set
                 */
                mfib_entry_itf_remove(msrc, rpath[0].frp_sw_if_index);
            }
        }
    }

    if (mfib_entry_src_ok_for_delete(msrc))
    {
        /*
         * this source has no interfaces and no flags.
         * it has nothing left to give - remove it
         */
        mfib_entry_src_remove(mfib_entry, source);
    }

    mfib_entry_recalculate_forwarding(mfib_entry, current_best);

    return (mfib_entry_ok_for_delete(mfib_entry));
}

/**
 * mfib_entry_delete
 *
 * The source is withdrawing all the paths it provided
 */
int
mfib_entry_delete (fib_node_index_t mfib_entry_index,
                   mfib_source_t source)
{
    mfib_source_t current_best;
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    current_best = mfib_entry_get_best_source(mfib_entry);
    mfib_entry_src_remove(mfib_entry, source);

    mfib_entry_recalculate_forwarding(mfib_entry, current_best);

    return (mfib_entry_ok_for_delete(mfib_entry));
}

static int
fib_ip4_address_compare (ip4_address_t * a1,
                         ip4_address_t * a2)
{
    /*
     * IP addresses are unsiged ints. the return value here needs to be signed
     * a simple subtraction won't cut it.
     * If the addresses are the same, the sort order is undefiend, so phoey.
     */
    return ((clib_net_to_host_u32(a1->data_u32) >
             clib_net_to_host_u32(a2->data_u32) ) ?
            1 : -1);
}

static int
fib_ip6_address_compare (ip6_address_t * a1,
                         ip6_address_t * a2)
{
  int i;
  for (i = 0; i < ARRAY_LEN (a1->as_u16); i++)
  {
      int cmp = (clib_net_to_host_u16 (a1->as_u16[i]) -
                 clib_net_to_host_u16 (a2->as_u16[i]));
      if (cmp != 0)
          return cmp;
  }
  return 0;
}

static int
mfib_entry_cmp (fib_node_index_t mfib_entry_index1,
                fib_node_index_t mfib_entry_index2)
{
    mfib_entry_t *mfib_entry1, *mfib_entry2;
    int cmp = 0;

    mfib_entry1 = mfib_entry_get(mfib_entry_index1);
    mfib_entry2 = mfib_entry_get(mfib_entry_index2);

    switch (mfib_entry1->mfe_prefix.fp_proto)
    {
    case FIB_PROTOCOL_IP4:
        cmp = fib_ip4_address_compare(&mfib_entry1->mfe_prefix.fp_grp_addr.ip4,
                                      &mfib_entry2->mfe_prefix.fp_grp_addr.ip4);

        if (0 == cmp)
        {
            cmp = fib_ip4_address_compare(&mfib_entry1->mfe_prefix.fp_src_addr.ip4,
                                          &mfib_entry2->mfe_prefix.fp_src_addr.ip4);
        }
        break;
    case FIB_PROTOCOL_IP6:
        cmp = fib_ip6_address_compare(&mfib_entry1->mfe_prefix.fp_grp_addr.ip6,
                                      &mfib_entry2->mfe_prefix.fp_grp_addr.ip6);

        if (0 == cmp)
        {
            cmp = fib_ip6_address_compare(&mfib_entry1->mfe_prefix.fp_src_addr.ip6,
                                          &mfib_entry2->mfe_prefix.fp_src_addr.ip6);
        }
        break;
    case FIB_PROTOCOL_MPLS:
        ASSERT(0);
        cmp = 0;
        break;
    }

    if (0 == cmp) {
        cmp = (mfib_entry1->mfe_prefix.fp_len - mfib_entry2->mfe_prefix.fp_len);
    }
    return (cmp);
}

int
mfib_entry_cmp_for_sort (void *i1, void *i2)
{
    fib_node_index_t *mfib_entry_index1 = i1, *mfib_entry_index2 = i2;

    return (mfib_entry_cmp(*mfib_entry_index1,
                           *mfib_entry_index2));
}

static void
mfib_entry_last_lock_gone (fib_node_t *node)
{
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;

    mfib_entry = mfib_entry_from_fib_node(node);

    dpo_reset(&mfib_entry->mfe_rep);

    MFIB_ENTRY_DBG(mfib_entry, "last-lock");

    vec_foreach(msrc, mfib_entry->mfe_srcs)
    {
        mfib_entry_src_flush(msrc);
    }

    vec_free(mfib_entry->mfe_srcs);

    fib_node_deinit(&mfib_entry->mfe_node);
    pool_put(mfib_entry_pool, mfib_entry);
}

u32
mfib_entry_get_stats_index (fib_node_index_t fib_entry_index)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(fib_entry_index);

    return (mfib_entry->mfe_rep.dpoi_index);
}

/*
 * mfib_entry_back_walk_notify
 *
 * A back walk has reach this entry.
 */
static fib_node_back_walk_rc_t
mfib_entry_back_walk_notify (fib_node_t *node,
                            fib_node_back_walk_ctx_t *ctx)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_from_fib_node(node);
    mfib_entry_recalculate_forwarding(mfib_entry,
                                      mfib_entry_get_best_source(mfib_entry));

    return (FIB_NODE_BACK_WALK_CONTINUE);
}

static void
mfib_entry_show_memory (void)
{
    fib_show_memory_usage("multicast-Entry",
                          pool_elts(mfib_entry_pool),
                          pool_len(mfib_entry_pool),
                          sizeof(mfib_entry_t));
}

/*
 * The MFIB entry's graph node virtual function table
 */
static const fib_node_vft_t mfib_entry_vft = {
    .fnv_get = mfib_entry_get_node,
    .fnv_last_lock = mfib_entry_last_lock_gone,
    .fnv_back_walk = mfib_entry_back_walk_notify,
    .fnv_mem_show = mfib_entry_show_memory,
};

void
mfib_entry_lock (fib_node_index_t mfib_entry_index)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);

    fib_node_lock(&mfib_entry->mfe_node);
}

void
mfib_entry_unlock (fib_node_index_t mfib_entry_index)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);

    fib_node_unlock(&mfib_entry->mfe_node);
}

static void
mfib_entry_dpo_lock (dpo_id_t *dpo)
{
}
static void
mfib_entry_dpo_unlock (dpo_id_t *dpo)
{
}

const static dpo_vft_t mfib_entry_dpo_vft = {
    .dv_lock = mfib_entry_dpo_lock,
    .dv_unlock = mfib_entry_dpo_unlock,
    .dv_format = format_mfib_entry_dpo,
    .dv_mem_show = mfib_entry_show_memory,
};

const static char* const mfib_entry_ip4_nodes[] =
{
    "ip4-mfib-forward-rpf",
    NULL,
};
const static char* const mfib_entry_ip6_nodes[] =
{
    "ip6-mfib-forward-rpf",
    NULL,
};

const static char* const * const mfib_entry_nodes[DPO_PROTO_NUM] =
{
    [DPO_PROTO_IP4]  = mfib_entry_ip4_nodes,
    [DPO_PROTO_IP6]  = mfib_entry_ip6_nodes,
};

void
mfib_entry_module_init (void)
{
    fib_node_register_type (FIB_NODE_TYPE_MFIB_ENTRY, &mfib_entry_vft);
    dpo_register(DPO_MFIB_ENTRY, &mfib_entry_dpo_vft, mfib_entry_nodes);
    mfib_entry_logger = vlib_log_register_class("mfib", "entry");
}

void
mfib_entry_encode (fib_node_index_t mfib_entry_index,
                  fib_route_path_encode_t **api_rpaths)
{
    fib_route_path_encode_t *api_rpath;
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *bsrc;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    bsrc = mfib_entry_get_best_src(mfib_entry);

    if (FIB_NODE_INDEX_INVALID != bsrc->mfes_pl)
    {
        fib_path_list_walk_w_ext(bsrc->mfes_pl,
                                 NULL,
                                 fib_path_encode,
                                 api_rpaths);
    }

    vec_foreach(api_rpath, *api_rpaths)
    {
        mfib_itf_t *mfib_itf;

        mfib_itf = mfib_entry_itf_find(bsrc->mfes_itfs,
                                       api_rpath->rpath.frp_sw_if_index);
        if (mfib_itf)
        {
            api_rpath->rpath.frp_mitf_flags = mfib_itf->mfi_flags;
        }
    }
}

const mfib_prefix_t *
mfib_entry_get_prefix (fib_node_index_t mfib_entry_index)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);

    return (&mfib_entry->mfe_prefix);
}

u32
mfib_entry_get_fib_index (fib_node_index_t mfib_entry_index)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);

    return (mfib_entry->mfe_fib_index);
}

const dpo_id_t*
mfib_entry_contribute_ip_forwarding (fib_node_index_t mfib_entry_index)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);

    return (&mfib_entry->mfe_rep);
}

void
mfib_entry_contribute_forwarding (fib_node_index_t mfib_entry_index,
                                  fib_forward_chain_type_t type,
                                  mfib_entry_fwd_flags_t flags,
                                  dpo_id_t *dpo)
{
    /*
     * An IP mFIB entry can only provide a forwarding chain that
     * is the same IP proto as the prefix.
     * No use-cases (i know of) for other combinations.
     */
    mfib_entry_t *mfib_entry;
    dpo_proto_t dp;

    mfib_entry = mfib_entry_get(mfib_entry_index);

    dp = fib_proto_to_dpo(mfib_entry->mfe_prefix.fp_proto);

    if (type == mfib_forw_chain_type_from_dpo_proto(dp))
    {
        replicate_t * rep;

        rep = replicate_get(mfib_entry->mfe_rep.dpoi_index);

        if ((rep->rep_flags & REPLICATE_FLAGS_HAS_LOCAL) &&
            (flags & MFIB_ENTRY_FWD_FLAG_NO_LOCAL))
        {
            /*
             * caller does not want the local paths that the entry has
             */
            dpo_set(dpo, DPO_REPLICATE, rep->rep_proto,
                    replicate_dup(REPLICATE_FLAGS_NONE,
                                  mfib_entry->mfe_rep.dpoi_index));
        }
        else
        {
            dpo_copy(dpo, &mfib_entry->mfe_rep);
        }
    }
    else
    {
        dpo_copy(dpo, drop_dpo_get(dp));
    }
}

/*
 * fib_entry_cover_changed
 *
 * this entry is tracking its cover and that cover has changed.
 */
void
mfib_entry_cover_changed (fib_node_index_t mfib_entry_index)
{
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;
    mfib_src_res_t res;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    msrc = mfib_entry_get_best_src(mfib_entry);

    res = mfib_entry_src_cover_change(mfib_entry, msrc);

    if (MFIB_SRC_REEVALUATE == res)
    {
        mfib_entry_recalculate_forwarding(mfib_entry, msrc->mfes_src);
    }
    MFIB_ENTRY_DBG(mfib_entry, "cover-changed");
}

/*
 * mfib_entry_cover_updated
 *
 * this entry is tracking its cover and that cover has been updated
 * (i.e. its forwarding information has changed).
 */
void
mfib_entry_cover_updated (fib_node_index_t mfib_entry_index)
{
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;
    mfib_src_res_t res;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    msrc = mfib_entry_get_best_src(mfib_entry);

    res = mfib_entry_src_cover_update(mfib_entry, msrc);

    if (MFIB_SRC_REEVALUATE == res)
    {
        mfib_entry_recalculate_forwarding(mfib_entry, msrc->mfes_src);
    }
    MFIB_ENTRY_DBG(mfib_entry, "cover-updated");
}

u32
mfib_entry_pool_size (void)
{
    return (pool_elts(mfib_entry_pool));
}

static clib_error_t *
show_mfib_entry_command (vlib_main_t * vm,
                        unformat_input_t * input,
                        vlib_cli_command_t * cmd)
{
    fib_node_index_t fei;

    if (unformat (input, "%d", &fei))
    {
        /*
         * show one in detail
         */
        if (!pool_is_free_index(mfib_entry_pool, fei))
        {
            vlib_cli_output (vm, "%d@%U",
                             fei,
                             format_mfib_entry, fei,
                             MFIB_ENTRY_FORMAT_DETAIL2);
        }
        else
        {
            vlib_cli_output (vm, "entry %d invalid", fei);
        }
    }
    else
    {
        /*
         * show all
         */
        vlib_cli_output (vm, "FIB Entries:");
        pool_foreach_index(fei, mfib_entry_pool,
        ({
            vlib_cli_output (vm, "%d@%U",
                             fei,
                             format_mfib_entry, fei,
                             MFIB_ENTRY_FORMAT_BRIEF);
        }));
    }

    return (NULL);
}

/*?
 * This commnad displays an entry, or all entries, in the mfib tables indexed by their unique
 * numerical indentifier.
 ?*/
VLIB_CLI_COMMAND (show_mfib_entry, static) = {
  .path = "show mfib entry",
  .function = show_mfib_entry_command,
  .short_help = "show mfib entry",
};
