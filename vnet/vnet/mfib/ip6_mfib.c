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

#include <vppinfra/bihash_40_8.h>
#include <vppinfra/bihash_template.c>

#include <vnet/mfib/ip6_mfib.h>

#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/fib/ip6_fib.h>

/*
 * Default size of the ip6 fib hash table
 */
#define IP6_MFIB_DEFAULT_HASH_NUM_BUCKETS (64 * 1024)
#define IP6_MFIB_DEFAULT_HASH_MEMORY_SIZE (32<<20)

/**
 * @brief The Global Hash table for all IPv6 multicast routes.
 *   The key is {table-id, len, grp, src}
 */
typedef struct ip6_mfib_table_t_
{
    /* The hash table for (S,G) */
    clib_bihash_40_8_t sg_hash;

    /* A standard unicast hash tabke for the (*,G/M) */
    ip6_fib_table_instance_t g_hash; 
} ip6_mfib_table_t;

static ip6_mfib_table_t ip6_mfib_table;

static const mfib_prefix_t ip6_specials[] = {
    {
	/* (*,*)/0 */
        .fp_src_addr = {
            .ip6.as_u64 = {0, 0},
        },
        .fp_grp_addr = {
            .ip6.as_u64 = {0, 0},
        },
        .fp_len  = 0,
        .fp_proto = FIB_PROTOCOL_IP6,
    },
};

static void
ip6_mfib_prefix_hton (const mfib_prefix_t *src,
                      mfib_prefix_t *dst)
{
    dst->fp_proto = src->fp_proto;
    dst->fp_len = src->fp_len;
    dst->fp_src_addr.ip6.as_u64[0] =
        clib_host_to_net_u64(src->fp_src_addr.ip6.as_u64[0]);
    dst->fp_src_addr.ip6.as_u64[1] =
        clib_host_to_net_u64(src->fp_src_addr.ip6.as_u64[1]);
    dst->fp_grp_addr.ip6.as_u64[0] =
        clib_host_to_net_u64(src->fp_grp_addr.ip6.as_u64[0]);
    dst->fp_grp_addr.ip6.as_u64[1] =
        clib_host_to_net_u64(src->fp_grp_addr.ip6.as_u64[1]);
}

static u32
ip6_create_mfib_with_table_id (u32 table_id)
{
    mfib_table_t *mfib_table;

    pool_get_aligned(ip6_main.mfibs, mfib_table, CLIB_CACHE_LINE_BYTES);
    memset(mfib_table, 0, sizeof(*mfib_table));

    mfib_table->mft_proto = FIB_PROTOCOL_IP6;
    mfib_table->mft_index =
	mfib_table->v4.index =
	    (mfib_table - ip6_main.mfibs);

    hash_set (ip6_main.mfib_index_by_table_id,
              table_id,
              mfib_table->mft_index);

    mfib_table->mft_table_id =
	mfib_table->v4.table_id =
	    table_id;
    
    mfib_table_lock(mfib_table->mft_index, FIB_PROTOCOL_IP6);

    /*
     * add the special entries into the new FIB
     */
    int ii;

    for (ii = 0; ii < ARRAY_LEN(ip6_specials); ii++)
    {
	mfib_prefix_t prefix;

        ip6_mfib_prefix_hton(&ip6_specials[ii], &prefix);

	mfib_table_entry_update(mfib_table->mft_index,
                                &prefix,
                                MFIB_SOURCE_DEFAULT_ROUTE,
                                MFIB_ENTRY_FLAG_DROP);
    }

    return (mfib_table->mft_index);
}

void
ip6_mfib_table_destroy (ip6_mfib_t *mfib)
{
    mfib_table_t *mfib_table = (mfib_table_t*)mfib;
    int ii;

    /*
     * remove all the specials we added when the table was created.
     */
    for (ii = 0; ii < ARRAY_LEN(ip6_specials); ii++)
    {
        fib_node_index_t mfei;
	mfib_prefix_t prefix;

        ip6_mfib_prefix_hton(&ip6_specials[ii], &prefix);

	mfei = mfib_table_lookup(mfib_table->mft_index, &prefix);
        mfib_table_entry_delete_index(mfei, MFIB_SOURCE_DEFAULT_ROUTE);
    }

    /*
     * validate no more routes.
     */
    ASSERT(0 == mfib_table->mft_total_route_counts);
    ASSERT(~0 != mfib_table->mft_table_id);

    hash_unset (ip6_main.mfib_index_by_table_id, mfib_table->mft_table_id);
    pool_put(ip6_main.mfibs, mfib_table);
}

u32
ip6_mfib_table_find_or_create_and_lock (u32 table_id)
{
    u32 index;

    index = ip6_mfib_index_from_table_id(table_id);
    if (~0 == index)
	return ip6_create_mfib_with_table_id(table_id);
    mfib_table_lock(index, FIB_PROTOCOL_IP6);

    return (index);
}

u32
ip6_mfib_table_get_index_for_sw_if_index (u32 sw_if_index)
{
    if (sw_if_index >= vec_len(ip6_main.mfib_index_by_sw_if_index))
    {
	/*
	 * This is the case for interfaces that are not yet mapped to
	 * a IP table
	 */
	return (~0);
    }
    return (ip6_main.mfib_index_by_sw_if_index[sw_if_index]);
}

#define IP6_MFIB_MK_KEY(_index, _grp, _src, _key)                 \
{                                                                 \
    (_key)->key[0] = (_grp)->as_u64[0];                           \
    (_key)->key[1] = (_grp)->as_u64[1];                           \
    (_key)->key[2] = (_src)->as_u64[0];                           \
    (_key)->key[3] = (_src)->as_u64[1];                           \
    (_key)->key[4] = ((u64)(_index));                             \
}

/*
 * ip6_fib_table_lookup_exact_match
 *
 * Exact match prefix lookup
 */
fib_node_index_t
ip6_mfib_table_lookup_exact_match (const ip6_mfib_t *mfib,
                                   const ip6_address_t *grp,
                                   const ip6_address_t *src,
                                   u32 len)
{
    clib_bihash_kv_40_8_t kv, value;
    const ip6_mfib_table_t *table;
    int rv;

    table = &ip6_mfib_table;

    if (len == 256)
    {
        IP6_MFIB_MK_KEY(mfib->index, grp, src, &kv);
      
        rv = clib_bihash_search_inline_2_40_8(&table->sg_hash, &kv, &value);
        if (rv == 0)
            return value.value;
    }

    return (ip6_fib_table_lookup_exact_match_i(&table->g_hash, mfib->index, grp, len));
}

/*
 * ip6_fib_table_lookup
 *
 * Longest prefix match
 */
fib_node_index_t
ip6_mfib_table_lookup (const ip6_mfib_t *mfib,
                       const ip6_address_t *src,
                       const ip6_address_t *grp,
                       u32 len)
{
    clib_bihash_kv_40_8_t kv, value;
    const ip6_mfib_table_t *table;
    int rv;

    table = &ip6_mfib_table;

    if (len == 256)
    {
        IP6_MFIB_MK_KEY(mfib->index, grp, src, &kv);
      
        rv = clib_bihash_search_inline_2_40_8(&table->sg_hash, &kv, &value);
        if (rv == 0)
            return value.value;
    }

    return (ip6_fib_table_lookup_i(&table->g_hash, mfib->index, grp, len));
}

void
ip6_mfib_table_entry_insert (ip6_mfib_t *mfib,
                             const ip6_address_t *grp,
                             const ip6_address_t *src,
                             u32 len,
                             fib_node_index_t mfib_entry_index)
{
    clib_bihash_kv_40_8_t kv;
    ip6_mfib_table_t *table;

    table = &ip6_mfib_table;

    if (len == 256)
    {
        IP6_MFIB_MK_KEY(mfib->index, grp, src, &kv);
        kv.value = mfib_entry_index;

        clib_bihash_add_del_40_8(&table->sg_hash, &kv, 1);
    }
    else
    {
        ip6_fib_table_insert_i(&table->g_hash, mfib->index, grp, len, mfib_entry_index);
    }
}

void
ip6_mfib_table_entry_remove (ip6_mfib_t *mfib,
                             const ip6_address_t *grp,
                             const ip6_address_t *src,
                             u32 len)
{
    clib_bihash_kv_40_8_t kv;
    ip6_mfib_table_t *table;

    table = &ip6_mfib_table;

    if (len == 256)
    {
        IP6_MFIB_MK_KEY(mfib->index, grp, src, &kv);

        clib_bihash_add_del_40_8(&table->sg_hash, &kv, 0);
    }
    else
    {
        ip6_fib_table_remove_i(&table->g_hash, mfib->index, grp, len);
    }
}

static clib_error_t *
ip6_mfib_module_init (vlib_main_t * vm)
{
    ip6_mfib_table_t *table;

    table = &ip6_mfib_table;

    clib_bihash_init_40_8 (&table->sg_hash,
                           "ip6 MFIB (S,G) fwding table",
                           IP6_MFIB_DEFAULT_HASH_NUM_BUCKETS,
                           IP6_MFIB_DEFAULT_HASH_MEMORY_SIZE);
    clib_bihash_init_24_8 (&table->g_hash.ip6_hash,
                           "ip6 MFIB (*,G/m) fwding table",
                           IP6_MFIB_DEFAULT_HASH_NUM_BUCKETS,
                           IP6_MFIB_DEFAULT_HASH_MEMORY_SIZE);

    return (NULL);
}

VLIB_INIT_FUNCTION(ip6_mfib_module_init);

static void
ip6_mfib_table_show_one (ip6_mfib_t *mfib,
                         vlib_main_t * vm,
                         ip6_address_t *src,
                         ip6_address_t *grp,
                         u32 mask_len)
{
    vlib_cli_output(vm, "%U",
                    format_mfib_entry,
                    ip6_mfib_table_lookup(mfib, src, grp, mask_len),
                    MFIB_ENTRY_FORMAT_DETAIL);
}

typedef struct ip6_mfib_show_ctx_t_ {
    u32 fib_index;
    fib_node_index_t *entries;
} ip6_mfib_show_ctx_t;

static void
ip6_mfib_table_collect_entries (clib_bihash_kv_24_8_t * kvp,
			       void *arg)
{
    ip6_mfib_show_ctx_t *ctx = arg;

    if (kvp->key[4] == ctx->fib_index)
    {
	vec_add1(ctx->entries, kvp->value);
    }
}

static void
ip6_mfib_table_show_all (ip6_mfib_t *mfib,
			vlib_main_t * vm)
{
    fib_node_index_t *mfib_entry_index;
    ip6_mfib_show_ctx_t ctx = {
	.fib_index = mfib->index,
	.entries = NULL,
    };

    clib_bihash_foreach_key_value_pair_40_8(&ip6_mfib_table.sg_hash,
                                            ip6_mfib_table_collect_entries,
                                            &ctx);
    clib_bihash_foreach_key_value_pair_24_8(&ip6_mfib_table.g_hash.ip6_hash,
                                            ip6_mfib_table_collect_entries,
                                            &ctx);

    vec_sort_with_function(ctx.entries, fib_entry_cmp_for_sort);

    vec_foreach(mfib_entry_index, ctx.entries)
    {
	vlib_cli_output(vm, "%U",
                        format_mfib_entry,
                        *mfib_entry_index,
                        MFIB_ENTRY_FORMAT_BRIEF);
    }

    vec_free(ctx.entries);
}

static clib_error_t *
ip6_show_mfib (vlib_main_t * vm,
               unformat_input_t * input,
               vlib_cli_command_t * cmd)
{
    ip6_main_t * im4 = &ip6_main;
    mfib_table_t *mfib_table;
    int verbose, matching;
    ip6_address_t grp, src = {{0}};
    u32 mask = 32;
    int table_id = -1, fib_index = ~0;

    verbose = 1;
    matching = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "brief") || unformat (input, "summary")
	    || unformat (input, "sum"))
	    verbose = 0;

	else if (unformat (input, "%U %U",
                           unformat_ip6_address, &src,
                           unformat_ip6_address, &grp))
        {
	    matching = 1;
            mask = 64;
        }
	else if (unformat (input, "%U", unformat_ip6_address, &grp))
        {
            matching = 1;
            mask = 32;
        }
	else if (unformat (input, "%U/%d",
			   unformat_ip6_address, &grp, &mask))
	    matching = 1;
	else if (unformat (input, "table %d", &table_id))
	    ;
	else if (unformat (input, "index %d", &fib_index))
	    ;
	else
	    break;
    }

    pool_foreach (mfib_table, im4->mfibs,
    ({
	ip6_mfib_t *mfib = &mfib_table->v6;

	if (table_id >= 0 && table_id != (int)mfib->table_id)
	    continue;
	if (fib_index != ~0 && fib_index != (int)mfib->index)
	    continue;

	vlib_cli_output (vm, "%U, fib_index %d",
			 format_mfib_table_name, mfib->index, FIB_PROTOCOL_IP6,
			 mfib->index);

	/* Show summary? */
	if (! verbose)
	{
	    /* vlib_cli_output (vm, "%=20s%=16s", "Prefix length", "Count"); */
	    /* for (i = 0; i < ARRAY_LEN (mfib->fib_entry_by_dst_address); i++) */
	    /* { */
	    /*     uword * hash = mfib->fib_entry_by_dst_address[i]; */
	    /*     uword n_elts = hash_elts (hash); */
	    /*     if (n_elts > 0) */
	    /*         vlib_cli_output (vm, "%20d%16d", i, n_elts); */
	    /* } */
	    continue;
	}

	if (!matching)
	{
	    ip6_mfib_table_show_all(mfib, vm);
	}
	else
	{
	    ip6_mfib_table_show_one(mfib, vm, &src, &grp, mask);
	}
    }));

    return 0;
}

/*
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
 *  multicast-ip6-chain
 *   [@1]: dpo-drop ip6
 * (*, 232.1.1.1/32):
 * Interfaces:
 *  test-eth1: Forward,
 *  test-eth2: Forward,
 *  test-eth0: Accept,
 * multicast-ip6-chain
 * [@2]: dpo-replicate: [index:1 buckets:2 to:[0:0]]
 *   [0] [@1]: ipv4-mcast: test-eth1: IP6: d0:d1:d2:d3:d4:01 -> 01:00:05:00:00:00
 *   [1] [@1]: ipv4-mcast: test-eth2: IP6: d0:d1:d2:d3:d4:02 -> 01:00:05:00:00:00
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
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip6_show_fib_command, static) = {
    .path = "show ip6 mfib",
    .short_help = "show ip mfib [summary] [table <table-id>] [index <fib-id>] [<grp-addr>[/<mask>]] [<grp-addr>] [<src-addr> <grp-addr>]",
    .function = ip6_show_mfib,
};
/* *INDENT-ON* */
