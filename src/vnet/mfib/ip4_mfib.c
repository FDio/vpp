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

#include <vnet/mfib/ip4_mfib.h>

#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/mfib_entry.h>

static const mfib_prefix_t all_zeros =
{
    .fp_proto = FIB_PROTOCOL_IP4,
};
static const mfib_prefix_t ip4_specials[] =
{
    /* ALL prefixes are in network order */
    {
        /* (*,224.0.0.1)/32 - all hosts */
        .fp_grp_addr = {
            .ip4.data_u32 = 0x010000e0,
        },
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
    },
    {
        /* (*,224.0.0.2)/32 - all routers */
        .fp_grp_addr = {
            .ip4.data_u32 = 0x020000e0,
        },
        .fp_len = 32,
        .fp_proto = FIB_PROTOCOL_IP4,
    },
};

static u32
ip4_create_mfib_with_table_id (u32 table_id,
                               mfib_source_t src)
{
    mfib_table_t *mfib_table;

    pool_get_aligned(ip4_main.mfibs, mfib_table, CLIB_CACHE_LINE_BYTES);
    clib_memset(mfib_table, 0, sizeof(*mfib_table));

    mfib_table->mft_proto = FIB_PROTOCOL_IP4;
    mfib_table->mft_index =
        mfib_table->v4.index =
            (mfib_table - ip4_main.mfibs);

    hash_set (ip4_main.mfib_index_by_table_id,
              table_id,
              mfib_table->mft_index);

    mfib_table->mft_table_id =
        mfib_table->v4.table_id =
            table_id;

    mfib_table_lock(mfib_table->mft_index, FIB_PROTOCOL_IP4, src);

    /*
     * add the default route into the new FIB
     */
    mfib_table_entry_update(mfib_table->mft_index,
                            &all_zeros,
                            MFIB_SOURCE_DEFAULT_ROUTE,
                            MFIB_RPF_ID_NONE,
                            MFIB_ENTRY_FLAG_DROP);

    const fib_route_path_t path = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_addr = zero_addr,
        .frp_sw_if_index = ~0,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_flags = FIB_ROUTE_PATH_LOCAL,
        .frp_mitf_flags = MFIB_ITF_FLAG_FORWARD,
    };
    int ii;

    for (ii = 0; ii < ARRAY_LEN(ip4_specials); ii++)
    {
        mfib_table_entry_path_update(mfib_table->mft_index,
                                     &ip4_specials[ii],
                                     MFIB_SOURCE_SPECIAL,
                                     &path);
    }

    return (mfib_table->mft_index);
}

void
ip4_mfib_table_destroy (ip4_mfib_t *mfib)
{
    mfib_table_t *mfib_table = (mfib_table_t*)mfib;
    int ii;

    /*
     * remove all the specials we added when the table was created.
     */
    mfib_table_entry_delete(mfib_table->mft_index,
                            &all_zeros,
                            MFIB_SOURCE_DEFAULT_ROUTE);

    for (ii = 0; ii < ARRAY_LEN(ip4_specials); ii++)
    {
        mfib_table_entry_delete(mfib_table->mft_index,
                                &ip4_specials[ii],
                                MFIB_SOURCE_SPECIAL);
    }

    /*
     * validate no more routes.
     */
    ASSERT(0 == mfib_table->mft_total_route_counts);
    ASSERT(~0 != mfib_table->mft_table_id);

    hash_unset (ip4_main.mfib_index_by_table_id, mfib_table->mft_table_id);
    pool_put(ip4_main.mfibs, mfib_table);
}

void
ip4_mfib_interface_enable_disable (u32 sw_if_index, int is_enable)
{
    const fib_route_path_t path = {
        .frp_proto = DPO_PROTO_IP4,
        .frp_addr = zero_addr,
        .frp_sw_if_index = sw_if_index,
        .frp_fib_index = ~0,
        .frp_weight = 1,
        .frp_mitf_flags = MFIB_ITF_FLAG_ACCEPT,
    };
    u32 mfib_index;
    int ii;

    vec_validate (ip4_main.mfib_index_by_sw_if_index, sw_if_index);
    mfib_index = ip4_mfib_table_get_index_for_sw_if_index(sw_if_index);

    for (ii = 0; ii < ARRAY_LEN(ip4_specials); ii++)
    {
        if (is_enable)
        {
            mfib_table_entry_path_update(mfib_index,
                                         &ip4_specials[ii],
                                         MFIB_SOURCE_SPECIAL,
                                         &path);
        }
        else
        {
            mfib_table_entry_path_remove(mfib_index,
                                         &ip4_specials[ii],
                                         MFIB_SOURCE_SPECIAL,
                                         &path);
        }
    }
}

u32
ip4_mfib_table_find_or_create_and_lock (u32 table_id,
                                        mfib_source_t src)
{
    u32 index;

    index = ip4_mfib_index_from_table_id(table_id);
    if (~0 == index)
        return ip4_create_mfib_with_table_id(table_id, src);
    mfib_table_lock(index, FIB_PROTOCOL_IP4, src);

    return (index);
}

u32
ip4_mfib_table_get_index_for_sw_if_index (u32 sw_if_index)
{
    if (sw_if_index >= vec_len(ip4_main.mfib_index_by_sw_if_index))
    {
        /*
         * This is the case for interfaces that are not yet mapped to
         * a IP table
         */
        return (~0);
    }
    return (ip4_main.mfib_index_by_sw_if_index[sw_if_index]);
}

#define IPV4_MFIB_GRP_LEN(_len)\
    (_len > 32 ? 32 : _len)

#define IP4_MFIB_MK_KEY(_grp, _src, _len, _key)                         \
{                                                                       \
    _key  = ((u64)(_grp->data_u32 &                                     \
                   ip4_main.fib_masks[IPV4_MFIB_GRP_LEN(_len)])) << 32; \
    _key |= _src->data_u32;                                             \
}
#define IP4_MFIB_MK_GRP_KEY(_grp, _len, _key)                           \
{                                                                       \
    _key  = ((u64)(_grp->data_u32 &                                     \
                   ip4_main.fib_masks[IPV4_MFIB_GRP_LEN(_len)])) << 32; \
}

/*
 * ip4_fib_table_lookup_exact_match
 *
 * Exact match prefix lookup
 */
fib_node_index_t
ip4_mfib_table_lookup_exact_match (const ip4_mfib_t *mfib,
                                   const ip4_address_t *grp,
                                   const ip4_address_t *src,
                                   u32 len)
{
    uword * hash, * result;
    u64 key;

    hash = mfib->fib_entry_by_dst_address[len];
    IP4_MFIB_MK_KEY(grp, src, len, key);

    result = hash_get(hash, key);

    if (NULL != result) {
        return (result[0]);
    }
    return (FIB_NODE_INDEX_INVALID);
}

/*
 * ip4_fib_table_lookup
 *
 * Longest prefix match
 */
fib_node_index_t
ip4_mfib_table_lookup (const ip4_mfib_t *mfib,
                       const ip4_address_t *src,
                       const ip4_address_t *grp,
                       u32 len)
{
    uword * hash, * result;
    i32 mask_len;
    u64 key;

    mask_len = len;

    if (PREDICT_TRUE(64 == mask_len))
    {
        hash = mfib->fib_entry_by_dst_address[mask_len];
        IP4_MFIB_MK_KEY(grp, src, mask_len, key);

        result = hash_get (hash, key);

        if (NULL != result) {
            return (result[0]);
        }
    }

    for (mask_len = (len == 64 ? 32 : len); mask_len >= 0; mask_len--)
    {
        hash = mfib->fib_entry_by_dst_address[mask_len];
        IP4_MFIB_MK_GRP_KEY(grp, mask_len, key);

        result = hash_get (hash, key);

        if (NULL != result) {
            return (result[0]);
        }
    }
    return (FIB_NODE_INDEX_INVALID);
}

fib_node_index_t
ip4_mfib_table_get_less_specific (const ip4_mfib_t *mfib,
                                  const ip4_address_t *src,
                                  const ip4_address_t *grp,
                                  u32 len)
{
    u32 mask_len;

    /*
     * in the absence of a tree structure for the table that allows for an O(1)
     * parent get, a cheeky way to find the cover is to LPM for the prefix with
     * mask-1.
     * there should always be a cover, though it may be the default route. the
     * default route's cover is the default route.
     */
    if (len == 64)
    {
        /* go from (S,G) to (*,G*) */
        mask_len = 32;
    }
    else if (len != 0)
    {
	mask_len = len - 1;
    }
    else
    {
        mask_len = len;
    }

    return (ip4_mfib_table_lookup(mfib, src, grp, mask_len));
}

void
ip4_mfib_table_entry_insert (ip4_mfib_t *mfib,
                             const ip4_address_t *grp,
                             const ip4_address_t *src,
                             u32 len,
                             fib_node_index_t fib_entry_index)
{
    uword * hash, * result;
    u64 key;

    IP4_MFIB_MK_KEY(grp, src, len, key);
    hash = mfib->fib_entry_by_dst_address[len];
    result = hash_get (hash, key);

    if (NULL == result) {
        /*
         * adding a new entry
         */
        if (NULL == hash) {
            hash = hash_create (32 /* elts */, sizeof (uword));
            hash_set_flags (hash, HASH_FLAG_NO_AUTO_SHRINK);
        }
        hash = hash_set(hash, key, fib_entry_index);
        mfib->fib_entry_by_dst_address[len] = hash;
    }
    else
    {
        ASSERT(0);
    }
}

void
ip4_mfib_table_entry_remove (ip4_mfib_t *mfib,
                             const ip4_address_t *grp,
                             const ip4_address_t *src,
                             u32 len)
{
    uword * hash, * result;
    u64 key;

    IP4_MFIB_MK_KEY(grp, src, len, key);
    hash = mfib->fib_entry_by_dst_address[len];
    result = hash_get (hash, key);

    if (NULL == result)
    {
        /*
         * removing a non-existent entry. i'll allow it.
         */
    }
    else
    {
        hash_unset(hash, key);
    }

    mfib->fib_entry_by_dst_address[len] = hash;
}

void
ip4_mfib_table_walk (ip4_mfib_t *mfib,
                     mfib_table_walk_fn_t fn,
                     void *ctx)
{
    int i;

    for (i = 0; i < ARRAY_LEN (mfib->fib_entry_by_dst_address); i++)
    {
	uword * hash = mfib->fib_entry_by_dst_address[i];

	if (NULL != hash)
	{
	    hash_pair_t * p;

	    hash_foreach_pair (p, hash,
	    ({
		fn(p->value[0], ctx);
	    }));
	}
    }
}

u8 *
format_ip4_mfib_table_memory (u8 * s, va_list * args)
{
    mfib_table_t *mfib_table;
    u64 total_memory;

    total_memory = 0;

    pool_foreach (mfib_table, ip4_main.mfibs,
    ({
        ip4_mfib_t *mfib = &mfib_table->v4;
        uword mfib_size;
        int i;

        mfib_size = 0;

        for (i = 0; i < ARRAY_LEN (mfib->fib_entry_by_dst_address); i++)
        {
            uword * hash = mfib->fib_entry_by_dst_address[i];

            if (NULL != hash)
            {
                mfib_size += hash_bytes(hash);
            }
        }

        total_memory += mfib_size;
    }));

    s = format(s, "%=30s %=6d %=12ld\n",
               "IPv4 multicast",
               pool_elts(ip4_main.mfibs), total_memory);

    return (s);
}

static void
ip4_mfib_table_show_all (ip4_mfib_t *mfib,
                         vlib_main_t * vm)
{
    fib_node_index_t *mfib_entry_indicies;
    fib_node_index_t *mfib_entry_index;
    int i;

    mfib_entry_indicies = NULL;

    for (i = 0; i < ARRAY_LEN (mfib->fib_entry_by_dst_address); i++)
    {
        uword * hash = mfib->fib_entry_by_dst_address[i];

        if (NULL != hash)
        {
            hash_pair_t * p;

            hash_foreach_pair (p, hash,
            ({
                vec_add1(mfib_entry_indicies, p->value[0]);
            }));
        }
    }

    vec_sort_with_function(mfib_entry_indicies, mfib_entry_cmp_for_sort);

    vec_foreach(mfib_entry_index, mfib_entry_indicies)
    {
        vlib_cli_output(vm, "%U",
                        format_mfib_entry,
                        *mfib_entry_index,
                        MFIB_ENTRY_FORMAT_BRIEF);
    }

    vec_free(mfib_entry_indicies);
}

static void
ip4_mfib_table_show_one (ip4_mfib_t *mfib,
                         vlib_main_t * vm,
                         ip4_address_t *src,
                         ip4_address_t *grp,
                         u32 mask_len)
{
    vlib_cli_output(vm, "%U",
                    format_mfib_entry,
                    ip4_mfib_table_lookup(mfib, src, grp, mask_len),
                    MFIB_ENTRY_FORMAT_DETAIL);
}

static clib_error_t *
ip4_show_mfib (vlib_main_t * vm,
               unformat_input_t * input,
               vlib_cli_command_t * cmd)
{
    ip4_main_t * im4 = &ip4_main;
    mfib_table_t *mfib_table;
    int verbose, matching, memory;
    ip4_address_t grp, src = {{0}};
    u32 mask = 32;
    u64 total_hash_memory;
    int i, table_id = -1, fib_index = ~0;

    verbose = 1;
    memory = matching = 0;
    total_hash_memory = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
        if (unformat (input, "brief") || unformat (input, "summary")
            || unformat (input, "sum"))
            verbose = 0;
        else if (unformat (input, "mem") || unformat (input, "memory"))
            memory = 1;
        else if (unformat (input, "%U %U",
                           unformat_ip4_address, &src,
                           unformat_ip4_address, &grp))
        {
            matching = 1;
            mask = 64;
        }
        else if (unformat (input, "%U/%d", unformat_ip4_address, &grp, &mask))
        {
            clib_memset(&src, 0, sizeof(src));
            matching = 1;
        }
        else if (unformat (input, "%U", unformat_ip4_address, &grp))
        {
            clib_memset(&src, 0, sizeof(src));
            matching = 1;
            mask = 32;
        }
        else if (unformat (input, "table %d", &table_id))
            ;
        else if (unformat (input, "index %d", &fib_index))
            ;
        else
            break;
    }

    pool_foreach (mfib_table, im4->mfibs,
    ({
        ip4_mfib_t *mfib = &mfib_table->v4;

        if (table_id >= 0 && table_id != (int)mfib->table_id)
            continue;
        if (fib_index != ~0 && fib_index != (int)mfib->index)
            continue;

        if (memory)
        {
            uword hash_size;

            hash_size = 0;

	    for (i = 0; i < ARRAY_LEN (mfib->fib_entry_by_dst_address); i++)
	    {
		uword * hash = mfib->fib_entry_by_dst_address[i];
                if (NULL != hash)
                {
                    hash_size += hash_bytes(hash);
                }
            }
            if (verbose)
                vlib_cli_output (vm, "%U hash:%d",
                                 format_mfib_table_name, mfib->index,
                                 FIB_PROTOCOL_IP4,
                                 hash_size);
            total_hash_memory += hash_size;
            continue;
        }

        vlib_cli_output (vm, "%U, fib_index:%d flags:%U",
                         format_mfib_table_name, mfib->index, FIB_PROTOCOL_IP4,
                         mfib->index,
                         format_mfib_table_flags, mfib_table->mft_flags);

        /* Show summary? */
        if (! verbose)
        {
            vlib_cli_output (vm, "%=20s%=16s", "Prefix length", "Count");
            for (i = 0; i < ARRAY_LEN (mfib->fib_entry_by_dst_address); i++)
            {
                uword * hash = mfib->fib_entry_by_dst_address[i];
                uword n_elts = hash_elts (hash);
                if (n_elts > 0)
                    vlib_cli_output (vm, "%20d%16d", i, n_elts);
            }
            continue;
        }

        if (!matching)
        {
            ip4_mfib_table_show_all(mfib, vm);
        }
        else
        {
            ip4_mfib_table_show_one(mfib, vm, &src, &grp, mask);
        }
    }));
    if (memory)
        vlib_cli_output (vm, "totals: hash:%ld", total_hash_memory);

    return 0;
}

/*?
 * This command displays the IPv4 MulticasrFIB Tables (VRF Tables) and
 * the route entries for each table.
 *
 * @note This command will run for a long time when the FIB tables are
 * comprised of millions of entries. For those senarios, consider displaying
 * a single table or summary mode.
 *
 * @cliexpar
 * Example of how to display all the IPv4 Multicast FIB tables:
 * @cliexstart{show ip fib}
 * ipv4-VRF:0, fib_index 0
 * (*, 0.0.0.0/0):  flags:D,
 *  Interfaces:
 *  multicast-ip4-chain
 *   [@1]: dpo-drop ip4
 * (*, 232.1.1.1/32):
 * Interfaces:
 *  test-eth1: Forward,
 *  test-eth2: Forward,
 *  test-eth0: Accept,
 * multicast-ip4-chain
 * [@2]: dpo-replicate: [index:1 buckets:2 to:[0:0]]
 *   [0] [@1]: ipv4-mcast: test-eth1: IP4: d0:d1:d2:d3:d4:01 -> 01:00:05:00:00:00
 *   [1] [@1]: ipv4-mcast: test-eth2: IP4: d0:d1:d2:d3:d4:02 -> 01:00:05:00:00:00
 *
 * @cliexend
 * Example of how to display a summary of all IPv4 FIB tables:
 * @cliexstart{show ip fib summary}
 * ipv4-VRF:0, fib_index 0, flow hash: src dst sport dport proto
 *     Prefix length         Count
 *                    0               1
 *                    8               2
 *                   32               4
 * ipv4-VRF:7, fib_index 1, flow hash: src dst sport dport proto
 *     Prefix length         Count
 *                    0               1
 *                    8               2
 *                   24               2
 *                   32               4
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip4_show_mfib_command, static) = {
    .path = "show ip mfib",
    .short_help = "show ip mfib [summary] [table <table-id>] [index <fib-id>] [<grp-addr>[/<mask>]] [<grp-addr>] [<src-addr> <grp-addr>]",
    .function = ip4_show_mfib,
};
/* *INDENT-ON* */
