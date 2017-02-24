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
#include <vnet/fib/fib_path_list.h>

#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/replicate_dpo.h>

/**
 * Debug macro
 */
#ifdef MFIB_DEBUG
#DEFIne MFIB_ENTRY_DBG(_e, _fmt, _args...)		\
{                                                       \
    u8*__tmp = NULL;					\
    __tmp = format(__tmp, "e:[%d:%U",                   \
                   mfib_entry_get_index(_e),		\
                   format_ip46_address,			\
                   &_e->mfe_prefix.fp_grp_addr,		\
                   IP46_TYPE_ANY);			\
    __tmp = format(__tmp, "/%d,",			\
                   _e->mfe_prefix.fp_len);		\
    __tmp = format(__tmp, "%U]",                        \
                   mfib_entry_get_index(_e),		\
                   format_ip46_address,			\
                   &_e->mfe_prefix.fp_src_addr,		\
                   IP46_TYPE_ANY);			\
    __tmp = format(__tmp, _fmt, ##_args);		\
    clib_warning("%s", __tmp);				\
    vec_free(__tmp);					\
}
#else
#define MFIB_ENTRY_DBG(_e, _fmt, _args...)
#endif

/**
 * The source of an MFIB entry
 */
typedef struct mfib_entry_src_t_
{
    /**
     * Which source this is
     */
    mfib_source_t mfes_src;

    /**
     * The path-list of forwarding interfaces
     */
    fib_node_index_t mfes_pl;

    /**
     * Route flags
     */
    mfib_entry_flags_t mfes_flags;

    /**
     * The hash table of all interfaces
     */
    mfib_itf_t *mfes_itfs;
} mfib_entry_src_t;

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
        s = format (s, "\n");
        s = format (s, " fib:%d", mfib_entry->mfe_fib_index);
        s = format (s, " index:%d", mfib_entry_get_index(mfib_entry));
        s = format (s, " locks:%d\n", mfib_entry->mfe_node.fn_locks);
        vec_foreach(msrc, mfib_entry->mfe_srcs)
        {
            s = format (s, "  src:%s", mfib_source_names[msrc->mfes_src]);
            s = format (s, ": %U\n", format_mfib_entry_flags, msrc->mfes_flags);
            if (FIB_NODE_INDEX_INVALID != msrc->mfes_pl)
            {
                s = fib_path_list_format(msrc->mfes_pl, s);
            }
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
#if CLIB_DEBUG > 0
    ASSERT(FIB_NODE_TYPE_MFIB_ENTRY == node->fn_type);
#endif
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
    mfib_entry_src_t *esrc;

    esrc = mfib_entry_src_find(mfib_entry, source, NULL);

    if (NULL == esrc)
    {
        mfib_entry_src_init(mfib_entry, source);
    }

    return (mfib_entry_src_find(mfib_entry, source, NULL));
}

static mfib_entry_src_t*
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
        mfib_entry_src_flush(msrc);
        vec_del1(mfib_entry->mfe_srcs, index);
    }
}

static int
mfib_entry_src_n_itfs (const mfib_entry_src_t *msrc)
{
    return (hash_elts(msrc->mfes_itfs));
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

    fib_path_list_unlock(mfib_entry->mfe_parent);
    vec_free(mfib_entry->mfe_srcs);

    fib_node_deinit(&mfib_entry->mfe_node);
    pool_put(mfib_entry_pool, mfib_entry);
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
    // FIXME - re-evalute

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

    pool_get(mfib_entry_pool, mfib_entry);

    fib_node_init(&mfib_entry->mfe_node,
                  FIB_NODE_TYPE_MFIB_ENTRY);

    /*
     * Some of the members require non-default initialisation
     * so we also init those that don't and thus save on the call to memset.
     */
    mfib_entry->mfe_flags = 0;
    mfib_entry->mfe_fib_index = fib_index;
    mfib_entry->mfe_prefix = *prefix;
    mfib_entry->mfe_parent = FIB_NODE_INDEX_INVALID;
    mfib_entry->mfe_sibling = FIB_NODE_INDEX_INVALID;
    mfib_entry->mfe_srcs = NULL;
    mfib_entry->mfe_itfs = NULL;

    dpo_reset(&mfib_entry->mfe_rep);

    *mfib_entry_index = mfib_entry_get_index(mfib_entry);

    MFIB_ENTRY_DBG(mfib_entry, "alloc");

    return (mfib_entry);
}

typedef struct mfib_entry_collect_forwarding_ctx_t_
{
    load_balance_path_t * next_hops;
    fib_forward_chain_type_t fct;
} mfib_entry_collect_forwarding_ctx_t;

static int
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
        return (!0);
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
        ASSERT(0);
        break;
    }

    return (!0);
}

static void
mfib_entry_stack (mfib_entry_t *mfib_entry)
{
    dpo_proto_t dp;

    dp = fib_proto_to_dpo(mfib_entry_get_proto(mfib_entry));

    if (FIB_NODE_INDEX_INVALID != mfib_entry->mfe_parent)
    {
        mfib_entry_collect_forwarding_ctx_t ctx = {
            .next_hops = NULL,
            .fct = mfib_entry_get_default_chain_type(mfib_entry),
        };

        fib_path_list_walk(mfib_entry->mfe_parent,
                           mfib_entry_src_collect_forwarding,
                           &ctx);

        if (!(MFIB_ENTRY_FLAG_EXCLUSIVE & mfib_entry->mfe_flags))
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
        else
        {
            /*
             * for exclusive routes the source provided a replicate DPO
             * we we stashed inthe special path list with one path
             * so we can stack directly on that.
             */
            ASSERT(1 == vec_len(ctx.next_hops));

            dpo_stack(DPO_MFIB_ENTRY, dp,
                      &mfib_entry->mfe_rep,
                      &ctx.next_hops[0].path_dpo);
            dpo_reset(&ctx.next_hops[0].path_dpo);
            vec_free(ctx.next_hops);
        }
    }
    else
    {
        dpo_stack(DPO_MFIB_ENTRY, dp,
                  &mfib_entry->mfe_rep,
                  drop_dpo_get(dp));
    }
}

static void
mfib_entry_forwarding_path_add (mfib_entry_src_t *msrc,
                                const fib_route_path_t *rpath)
{
    fib_node_index_t old_pl_index;
    fib_route_path_t *rpaths;

    ASSERT(!(MFIB_ENTRY_FLAG_EXCLUSIVE & msrc->mfes_flags));

    /*
     * path-lists require a vector of paths
     */
    rpaths = NULL;
    vec_add1(rpaths, rpath[0]);

    old_pl_index = msrc->mfes_pl;

    if (FIB_NODE_INDEX_INVALID == msrc->mfes_pl)
    {
        msrc->mfes_pl =
            fib_path_list_create(FIB_PATH_LIST_FLAG_NO_URPF,
                                 rpaths);
    }
    else
    {
        msrc->mfes_pl =
            fib_path_list_copy_and_path_add(msrc->mfes_pl,
                                            FIB_PATH_LIST_FLAG_NO_URPF,
                                            rpaths);
    }
    fib_path_list_lock(msrc->mfes_pl);
    fib_path_list_unlock(old_pl_index);

    vec_free(rpaths);
}

static int
mfib_entry_forwarding_path_remove (mfib_entry_src_t *msrc,
                                   const fib_route_path_t *rpath)
{
    fib_node_index_t old_pl_index;
    fib_route_path_t *rpaths;

    ASSERT(!(MFIB_ENTRY_FLAG_EXCLUSIVE & msrc->mfes_flags));

    /*
     * path-lists require a vector of paths
     */
    rpaths = NULL;
    vec_add1(rpaths, rpath[0]);

    old_pl_index = msrc->mfes_pl;

    msrc->mfes_pl =
        fib_path_list_copy_and_path_remove(msrc->mfes_pl,
                                           FIB_PATH_LIST_FLAG_NONE,
                                           rpaths);

    fib_path_list_lock(msrc->mfes_pl);
    fib_path_list_unlock(old_pl_index);

    vec_free(rpaths);

    return (FIB_NODE_INDEX_INVALID != msrc->mfes_pl);
}

static void
mfib_entry_recalculate_forwarding (mfib_entry_t *mfib_entry)
{
    fib_node_index_t old_pl_index;
    mfib_entry_src_t *bsrc;

    old_pl_index = mfib_entry->mfe_parent;

    /*
     * copy the forwarding data from the bast source
     */
    bsrc = mfib_entry_get_best_src(mfib_entry);

    if (NULL == bsrc)
    {
        mfib_entry->mfe_parent = FIB_NODE_INDEX_INVALID;
    }
    else
    {
        mfib_entry->mfe_parent = bsrc->mfes_pl;
        mfib_entry->mfe_flags = bsrc->mfes_flags;
        mfib_entry->mfe_itfs = bsrc->mfes_itfs;
    }

    /*
     * re-stack the entry on the best forwarding info.
     */
    if (old_pl_index != mfib_entry->mfe_parent ||
        FIB_NODE_INDEX_INVALID == old_pl_index)
    {
        mfib_entry_stack(mfib_entry);

        fib_path_list_lock(mfib_entry->mfe_parent);
        fib_path_list_unlock(old_pl_index);
    }
}


fib_node_index_t
mfib_entry_create (u32 fib_index,
                   mfib_source_t source,
                   const mfib_prefix_t *prefix,
                   mfib_entry_flags_t entry_flags)
{
    fib_node_index_t mfib_entry_index;
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;

    mfib_entry = mfib_entry_alloc(fib_index, prefix,
                                  &mfib_entry_index);
    msrc = mfib_entry_src_find_or_create(mfib_entry, source);
    msrc->mfes_flags = entry_flags;

    mfib_entry_recalculate_forwarding(mfib_entry);

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
    return ((MFIB_ENTRY_FLAG_NONE == msrc->mfes_flags &&
             0 == mfib_entry_src_n_itfs(msrc)));
}

int
mfib_entry_update (fib_node_index_t mfib_entry_index,
                   mfib_source_t source,
                   mfib_entry_flags_t entry_flags,
                   index_t repi)
{
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    msrc = mfib_entry_src_find_or_create(mfib_entry, source);
    msrc->mfes_flags = entry_flags;

    if (INDEX_INVALID != repi)
    {
        /*
         * The source is providing its own replicate DPO.
         * Create a sepcial path-list to manage it, that way
         * this entry and the source are equivalent to a normal
         * entry
         */
        fib_node_index_t old_pl_index;
        fib_protocol_t fp;
        dpo_id_t dpo = DPO_INVALID;

        fp = mfib_entry_get_proto(mfib_entry);
        old_pl_index = msrc->mfes_pl;

        dpo_set(&dpo, DPO_REPLICATE,
                fib_proto_to_dpo(fp),
                repi);

        msrc->mfes_pl =
            fib_path_list_create_special(fp,
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
        mfib_entry_src_remove(mfib_entry, source);
    }

    mfib_entry_recalculate_forwarding(mfib_entry);

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
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;
    mfib_itf_t *mfib_itf;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    ASSERT(NULL != mfib_entry);
    msrc = mfib_entry_src_find_or_create(mfib_entry, source);

    /*
     * search for the interface in the current set
     */
    mfib_itf = mfib_entry_itf_find(msrc->mfes_itfs,
                                   rpath[0].frp_sw_if_index);

    if (NULL == mfib_itf)
    {
        /*
         * this is a path we do not yet have. If it is forwarding then we
         * add it to the replication set
         */
        if (itf_flags & MFIB_ITF_FLAG_FORWARD)
        {
            mfib_entry_forwarding_path_add(msrc, rpath);
        }
        /*
         * construct a new ITF for this entry's list
         */
        mfib_entry_itf_add(msrc,
                           rpath[0].frp_sw_if_index,
                           mfib_itf_create(rpath[0].frp_sw_if_index,
                                           itf_flags));
    }
    else
    {
        int was_forwarding = !!(mfib_itf->mfi_flags & MFIB_ITF_FLAG_FORWARD);
        int is_forwarding  = !!(itf_flags & MFIB_ITF_FLAG_FORWARD);

        if (!was_forwarding && is_forwarding)
        {
            mfib_entry_forwarding_path_add(msrc, rpath);
        }
        else if (was_forwarding && !is_forwarding)
        {
            mfib_entry_forwarding_path_remove(msrc, rpath);
        }
        /*
         * packets in flight see these updates.
         */
        mfib_itf->mfi_flags = itf_flags;
    }

    mfib_entry_recalculate_forwarding(mfib_entry);
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
    mfib_entry_t *mfib_entry;
    mfib_entry_src_t *msrc;
    mfib_itf_t *mfib_itf;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    ASSERT(NULL != mfib_entry);
    msrc = mfib_entry_src_find(mfib_entry, source, NULL);

    if (NULL == msrc)
    {
        /*
         * there are no paths left for this source
         */
        return (mfib_entry_ok_for_delete(mfib_entry));
    }

    /*
     * search for the interface in the current set
     */
    mfib_itf = mfib_entry_itf_find(msrc->mfes_itfs,
                                   rpath[0].frp_sw_if_index);

    if (NULL == mfib_itf)
    {
        /*
         * removing a path that does not exist
         */
        return (mfib_entry_ok_for_delete(mfib_entry));
    }

    /*
     * we have this path. If it is forwarding then we
     * remove it to the replication set
     */
    if (mfib_itf->mfi_flags & MFIB_ITF_FLAG_FORWARD)
    {
        mfib_entry_forwarding_path_remove(msrc, rpath);
    }

    /*
     * remove the interface/path from this entry's list
     */
    mfib_entry_itf_remove(msrc, rpath[0].frp_sw_if_index);

    if (mfib_entry_src_ok_for_delete(msrc))
    {
        /*
         * this source has no interfaces and no flags.
         * it has nothing left to give - remove it
         */
        mfib_entry_src_remove(mfib_entry, source);
    }

    mfib_entry_recalculate_forwarding(mfib_entry);

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
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    mfib_entry_src_remove(mfib_entry, source);

    mfib_entry_recalculate_forwarding(mfib_entry);

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
}

void
mfib_entry_encode (fib_node_index_t mfib_entry_index,
                  fib_route_path_encode_t **api_rpaths)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    if (FIB_NODE_INDEX_INVALID != mfib_entry->mfe_parent)
    {
        fib_path_list_walk(mfib_entry->mfe_parent,
                           fib_path_encode,
                           api_rpaths);
    }
}


void
mfib_entry_get_prefix (fib_node_index_t mfib_entry_index,
                      mfib_prefix_t *pfx)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);
    *pfx = mfib_entry->mfe_prefix;
}

u32
mfib_entry_get_fib_index (fib_node_index_t mfib_entry_index)
{
    mfib_entry_t *mfib_entry;

    mfib_entry = mfib_entry_get(mfib_entry_index);

    return (mfib_entry->mfe_fib_index);
}

void
mfib_entry_contribute_forwarding (fib_node_index_t mfib_entry_index,
                                  fib_forward_chain_type_t type,
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

    if (type == fib_forw_chain_type_from_dpo_proto(dp))
    {
        dpo_copy(dpo, &mfib_entry->mfe_rep);
    }
    else
    {
        dpo_copy(dpo, drop_dpo_get(dp));
    }
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
