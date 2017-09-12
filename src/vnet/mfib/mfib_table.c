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
#include <vnet/dpo/drop_dpo.h>

#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/ip4_mfib.h>
#include <vnet/mfib/ip6_mfib.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/mfib/mfib_signal.h>

mfib_table_t *
mfib_table_get (fib_node_index_t index,
                fib_protocol_t proto)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
        return (pool_elt_at_index(ip4_main.mfibs, index));
    case FIB_PROTOCOL_IP6:
        return (pool_elt_at_index(ip6_main.mfibs, index));
    case FIB_PROTOCOL_MPLS:
        break;
    }
    ASSERT(0);
    return (NULL);
}

static inline fib_node_index_t
mfib_table_lookup_i (const mfib_table_t *mfib_table,
                     const mfib_prefix_t *prefix)
{
    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
        return (ip4_mfib_table_lookup(&mfib_table->v4,
                                      &prefix->fp_src_addr.ip4,
                                      &prefix->fp_grp_addr.ip4,
                                      prefix->fp_len));
    case FIB_PROTOCOL_IP6:
        return (ip6_mfib_table_lookup(&mfib_table->v6,
                                      &prefix->fp_src_addr.ip6,
                                      &prefix->fp_grp_addr.ip6,
                                      prefix->fp_len));
    case FIB_PROTOCOL_MPLS:
        break;
    }
    return (FIB_NODE_INDEX_INVALID);
}

fib_node_index_t
mfib_table_lookup (u32 fib_index,
                   const mfib_prefix_t *prefix)
{
    return (mfib_table_lookup_i(mfib_table_get(fib_index, prefix->fp_proto), prefix));
}

static inline fib_node_index_t
mfib_table_lookup_exact_match_i (const mfib_table_t *mfib_table,
                                 const mfib_prefix_t *prefix)
{
    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
        return (ip4_mfib_table_lookup_exact_match(&mfib_table->v4,
                                                  &prefix->fp_grp_addr.ip4,
                                                  &prefix->fp_src_addr.ip4,
                                                  prefix->fp_len));
    case FIB_PROTOCOL_IP6:
        return (ip6_mfib_table_lookup_exact_match(&mfib_table->v6,
                                                  &prefix->fp_grp_addr.ip6,
                                                  &prefix->fp_src_addr.ip6,
                                                  prefix->fp_len));
    case FIB_PROTOCOL_MPLS:
        break;
    }
    return (FIB_NODE_INDEX_INVALID);
}

fib_node_index_t
mfib_table_lookup_exact_match (u32 fib_index,
                              const mfib_prefix_t *prefix)
{
    return (mfib_table_lookup_exact_match_i(mfib_table_get(fib_index,
                                                          prefix->fp_proto),
                                            prefix));
}

static void
mfib_table_entry_remove (mfib_table_t *mfib_table,
                         const mfib_prefix_t *prefix,
                         fib_node_index_t fib_entry_index)
{
    vlib_smp_unsafe_warning();

    mfib_table->mft_total_route_counts--;

    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
        ip4_mfib_table_entry_remove(&mfib_table->v4,
                                    &prefix->fp_grp_addr.ip4,
                                    &prefix->fp_src_addr.ip4,
                                    prefix->fp_len);
        break;
    case FIB_PROTOCOL_IP6:
        ip6_mfib_table_entry_remove(&mfib_table->v6,
                                    &prefix->fp_grp_addr.ip6,
                                    &prefix->fp_src_addr.ip6,
                                    prefix->fp_len);
        break;
    case FIB_PROTOCOL_MPLS:
        ASSERT(0);
        break;
    }

    mfib_entry_unlock(fib_entry_index);
}

static void
mfib_table_entry_insert (mfib_table_t *mfib_table,
                         const mfib_prefix_t *prefix,
                         fib_node_index_t mfib_entry_index)
{
    vlib_smp_unsafe_warning();

    mfib_entry_lock(mfib_entry_index);
    mfib_table->mft_total_route_counts++;

    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
        ip4_mfib_table_entry_insert(&mfib_table->v4,
                                    &prefix->fp_grp_addr.ip4,
                                    &prefix->fp_src_addr.ip4,
                                    prefix->fp_len,
                                    mfib_entry_index);
        break;
    case FIB_PROTOCOL_IP6:
        ip6_mfib_table_entry_insert(&mfib_table->v6,
                                    &prefix->fp_grp_addr.ip6,
                                    &prefix->fp_src_addr.ip6,
                                    prefix->fp_len,
                                    mfib_entry_index);
        break;
    case FIB_PROTOCOL_MPLS:
        break;
    }
}

fib_node_index_t
mfib_table_entry_update (u32 fib_index,
                         const mfib_prefix_t *prefix,
                         mfib_source_t source,
                         fib_rpf_id_t rpf_id,
                         mfib_entry_flags_t entry_flags)
{
    fib_node_index_t mfib_entry_index;
    mfib_table_t *mfib_table;

    mfib_table = mfib_table_get(fib_index, prefix->fp_proto);
    mfib_entry_index = mfib_table_lookup_exact_match_i(mfib_table, prefix);

    if (FIB_NODE_INDEX_INVALID == mfib_entry_index)
    {
        if (MFIB_ENTRY_FLAG_NONE != entry_flags)
        {
            /*
             * update to a non-existing entry with non-zero flags
             */
            mfib_entry_index = mfib_entry_create(fib_index, source,
                                                 prefix, rpf_id,
                                                 entry_flags);

            mfib_table_entry_insert(mfib_table, prefix, mfib_entry_index);
        }
        /*
         * else
         *   the entry doesn't exist and the request is to set no flags
         *   the result would be an entry that doesn't exist - so do nothing
         */
    }
    else
    {
        mfib_entry_lock(mfib_entry_index);

        if (mfib_entry_update(mfib_entry_index,
                              source,
                              entry_flags,
                              rpf_id,
                              INDEX_INVALID))
        {
            /*
             * this update means we can now remove the entry.
             */
            mfib_table_entry_remove(mfib_table, prefix, mfib_entry_index);
        }

        mfib_entry_unlock(mfib_entry_index);
    }

    return (mfib_entry_index);
}

fib_node_index_t
mfib_table_entry_path_update (u32 fib_index,
                              const mfib_prefix_t *prefix,
                              mfib_source_t source,
                              const fib_route_path_t *rpath,
                              mfib_itf_flags_t itf_flags)
{
    fib_node_index_t mfib_entry_index;
    mfib_table_t *mfib_table;

    mfib_table = mfib_table_get(fib_index, prefix->fp_proto);
    mfib_entry_index = mfib_table_lookup_exact_match_i(mfib_table, prefix);

    if (FIB_NODE_INDEX_INVALID == mfib_entry_index)
    {
        mfib_entry_index = mfib_entry_create(fib_index,
                                             source,
                                             prefix,
                                             MFIB_RPF_ID_NONE,
                                             MFIB_ENTRY_FLAG_NONE);

        mfib_table_entry_insert(mfib_table, prefix, mfib_entry_index);
    }

    mfib_entry_path_update(mfib_entry_index,
                           source,
                           rpath,
                           itf_flags);

    return (mfib_entry_index);
}

void
mfib_table_entry_path_remove (u32 fib_index,
                              const mfib_prefix_t *prefix,
                              mfib_source_t source,
                              const fib_route_path_t *rpath)
{
    fib_node_index_t mfib_entry_index;
    mfib_table_t *mfib_table;

    mfib_table = mfib_table_get(fib_index, prefix->fp_proto);
    mfib_entry_index = mfib_table_lookup_exact_match_i(mfib_table, prefix);

    if (FIB_NODE_INDEX_INVALID == mfib_entry_index)
    {
        /*
         * removing an etry that does not exist. i'll allow it.
         */
    }
    else
    {
        int no_more_sources;

        /*
         * don't nobody go nowhere
         */
        mfib_entry_lock(mfib_entry_index);

        no_more_sources = mfib_entry_path_remove(mfib_entry_index,
                                                 source,
                                                 rpath);

        if (no_more_sources)
        {
            /*
             * last source gone. remove from the table
             */
            mfib_table_entry_remove(mfib_table, prefix, mfib_entry_index);
        }

        mfib_entry_unlock(mfib_entry_index);
    }
}

fib_node_index_t
mfib_table_entry_special_add (u32 fib_index,
                              const mfib_prefix_t *prefix,
                              mfib_source_t source,
                              mfib_entry_flags_t entry_flags,
                              index_t rep_dpo)
{
    fib_node_index_t mfib_entry_index;
    mfib_table_t *mfib_table;

    mfib_table = mfib_table_get(fib_index, prefix->fp_proto);
    mfib_entry_index = mfib_table_lookup_exact_match_i(mfib_table, prefix);

    if (FIB_NODE_INDEX_INVALID == mfib_entry_index)
    {
        mfib_entry_index = mfib_entry_create(fib_index,
                                             source,
                                             prefix,
                                             MFIB_RPF_ID_NONE,
                                             MFIB_ENTRY_FLAG_NONE);

        mfib_table_entry_insert(mfib_table, prefix, mfib_entry_index);
    }

    mfib_entry_update(mfib_entry_index, source,
                      (MFIB_ENTRY_FLAG_EXCLUSIVE | entry_flags),
                      MFIB_RPF_ID_NONE,
                      rep_dpo);

    return (mfib_entry_index);
}

static void
mfib_table_entry_delete_i (u32 fib_index,
                           fib_node_index_t mfib_entry_index,
                           const mfib_prefix_t *prefix,
                           mfib_source_t source)
{
    mfib_table_t *mfib_table;

    mfib_table = mfib_table_get(fib_index, prefix->fp_proto);

    /*
     * don't nobody go nowhere
     */
    mfib_entry_lock(mfib_entry_index);

    if (mfib_entry_delete(mfib_entry_index, source))
    {
        /*
         * last source gone. remove from the table
         */
        mfib_table_entry_remove(mfib_table, prefix, mfib_entry_index);
    }
    /*
     * else
     *   still has sources, leave it be.
     */

    mfib_entry_unlock(mfib_entry_index);
}

void
mfib_table_entry_delete (u32 fib_index,
                         const mfib_prefix_t *prefix,
                         mfib_source_t source)
{
    fib_node_index_t mfib_entry_index;

    mfib_entry_index = mfib_table_lookup_exact_match(fib_index, prefix);

    if (FIB_NODE_INDEX_INVALID == mfib_entry_index)
    {
        /*
         * removing an etry that does not exist.
         * i'll allow it, but i won't like it.
         */
        clib_warning("%U not in FIB", format_mfib_prefix, prefix);
    }
    else
    {
        mfib_table_entry_delete_i(fib_index, mfib_entry_index,
                                  prefix, source);
    }
}

void
mfib_table_entry_delete_index (fib_node_index_t mfib_entry_index,
                               mfib_source_t source)
{
    mfib_prefix_t prefix;

    mfib_entry_get_prefix(mfib_entry_index, &prefix);

    mfib_table_entry_delete_i(mfib_entry_get_fib_index(mfib_entry_index),
                              mfib_entry_index, &prefix, source);
}

u32
mfib_table_get_index_for_sw_if_index (fib_protocol_t proto,
                                      u32 sw_if_index)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
        return (ip4_mfib_table_get_index_for_sw_if_index(sw_if_index));
    case FIB_PROTOCOL_IP6:
        return (ip6_mfib_table_get_index_for_sw_if_index(sw_if_index));
    case FIB_PROTOCOL_MPLS:
        ASSERT(0);
        break;
    }
    return (~0);
}

u32
mfib_table_find (fib_protocol_t proto,
                 u32 table_id)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
        return (ip4_mfib_index_from_table_id(table_id));
    case FIB_PROTOCOL_IP6:
        return (ip6_mfib_index_from_table_id(table_id));
    case FIB_PROTOCOL_MPLS:
        ASSERT(0);
        break;
    }
    return (~0);
}

static u32
mfib_table_find_or_create_and_lock_i (fib_protocol_t proto,
                                      u32 table_id,
                                      mfib_source_t src,
                                      const u8 *name)
{
    mfib_table_t *mfib_table;
    fib_node_index_t fi;

    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
        fi = ip4_mfib_table_find_or_create_and_lock(table_id, src);
        break;
    case FIB_PROTOCOL_IP6:
        fi = ip6_mfib_table_find_or_create_and_lock(table_id, src);
        break;
    case FIB_PROTOCOL_MPLS:
    default:
        return (~0);
    }

    mfib_table = mfib_table_get(fi, proto);

    if (NULL == mfib_table->mft_desc)
    {
        if (name && name[0])
        {
            mfib_table->mft_desc = format(NULL, "%s", name);
        }
        else
        {
            mfib_table->mft_desc = format(NULL, "%U-VRF:%d",
                                          format_fib_protocol, proto,
                                          table_id);
        }
    }

    return (fi);
}

u32
mfib_table_find_or_create_and_lock (fib_protocol_t proto,
                                    u32 table_id,
                                    mfib_source_t src)
{
    return (mfib_table_find_or_create_and_lock_i(proto, table_id,
                                                 src, NULL));
}

u32
mfib_table_find_or_create_and_lock_w_name (fib_protocol_t proto,
                                           u32 table_id,
                                           mfib_source_t src,
                                           const u8 *name)
{
    return (mfib_table_find_or_create_and_lock_i(proto, table_id,
                                                 src, name));
}

/**
 * @brief Table flush context. Store the indicies of matching FIB entries
 * that need to be removed.
 */
typedef struct mfib_table_flush_ctx_t_
{
    /**
     * The list of entries to flush
     */
    fib_node_index_t *mftf_entries;

    /**
     * The source we are flushing
     */
    mfib_source_t mftf_source;
} mfib_table_flush_ctx_t;

static int
mfib_table_flush_cb (fib_node_index_t mfib_entry_index,
                     void *arg)
{
    mfib_table_flush_ctx_t *ctx = arg;

    if (mfib_entry_is_sourced(mfib_entry_index, ctx->mftf_source))
    {
        vec_add1(ctx->mftf_entries, mfib_entry_index);
    }
    return (1);
}

void
mfib_table_flush (u32 mfib_index,
                  fib_protocol_t proto,
                  mfib_source_t source)
{
    fib_node_index_t *mfib_entry_index;
    mfib_table_flush_ctx_t ctx = {
        .mftf_entries = NULL,
        .mftf_source = source,
    };

    mfib_table_walk(mfib_index, proto,
                    mfib_table_flush_cb,
                    &ctx);

    vec_foreach(mfib_entry_index, ctx.mftf_entries)
    {
        mfib_table_entry_delete_index(*mfib_entry_index, source);
    }

    vec_free(ctx.mftf_entries);
}

static void
mfib_table_destroy (mfib_table_t *mfib_table)
{
    vec_free(mfib_table->mft_desc);

    switch (mfib_table->mft_proto)
    {
    case FIB_PROTOCOL_IP4:
        ip4_mfib_table_destroy(&mfib_table->v4);
        break;
    case FIB_PROTOCOL_IP6:
        ip6_mfib_table_destroy(&mfib_table->v6);
        break;
    case FIB_PROTOCOL_MPLS:
        ASSERT(0);
        break;
    }
}

void
mfib_table_unlock (u32 fib_index,
                   fib_protocol_t proto,
                   mfib_source_t source)
{
    mfib_table_t *mfib_table;

    mfib_table = mfib_table_get(fib_index, proto);
    mfib_table->mft_locks[source]--;
    mfib_table->mft_locks[MFIB_TABLE_TOTAL_LOCKS]--;

    if (0 == mfib_table->mft_locks[source])
    {
        /*
         * The source no longer needs the table. flush any routes
         * from it just in case
         */
        mfib_table_flush(fib_index, proto, source);
    }

    if (0 == mfib_table->mft_locks[MFIB_TABLE_TOTAL_LOCKS])
    {
        /*
         * no more locak from any source - kill it
         */
	mfib_table_destroy(mfib_table);
    }
}

void
mfib_table_lock (u32 fib_index,
                 fib_protocol_t proto,
                 mfib_source_t source)
{
    mfib_table_t *mfib_table;

    mfib_table = mfib_table_get(fib_index, proto);
    mfib_table->mft_locks[source]++;
    mfib_table->mft_locks[MFIB_TABLE_TOTAL_LOCKS]++;
}

void
mfib_table_walk (u32 fib_index,
                 fib_protocol_t proto,
                 mfib_table_walk_fn_t fn,
                 void *ctx)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	ip4_mfib_table_walk(ip4_mfib_get(fib_index), fn, ctx);
	break;
    case FIB_PROTOCOL_IP6:
	ip6_mfib_table_walk(ip6_mfib_get(fib_index), fn, ctx);
	break;
    case FIB_PROTOCOL_MPLS:
	break;
    }
}

u8*
format_mfib_table_name (u8* s, va_list ap)
{
    fib_node_index_t fib_index = va_arg(ap, fib_node_index_t);
    fib_protocol_t proto = va_arg(ap, int); // int promotion
    mfib_table_t *mfib_table;

    mfib_table = mfib_table_get(fib_index, proto);

    s = format(s, "%v", mfib_table->mft_desc);

    return (s);
}

static clib_error_t *
mfib_module_init (vlib_main_t * vm)
{
    clib_error_t * error;

    if ((error = vlib_call_init_function (vm, fib_module_init)))
        return (error);
    if ((error = vlib_call_init_function (vm, rn_module_init)))
        return (error);

    mfib_entry_module_init();
    mfib_signal_module_init();

    return (error);
}

VLIB_INIT_FUNCTION(mfib_module_init);
