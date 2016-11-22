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

#include <vnet/mfib/ip6_mfib.h>

#include <vnet/mfib/mfib_table.h>
#include <vnet/mfib/mfib_entry.h>
#include <vnet/fib/ip6_fib.h>

/**
 * The number of bytes in an address/ask key in the radix tree
 * First byte is the length in bytes.
 */
#define IP6_MFIB_KEY_LEN 33

/**
 * Key and mask for radix
 */
typedef struct ip6_mfib_key_t_
{
    u8 key[IP6_MFIB_KEY_LEN];
    u8 mask[IP6_MFIB_KEY_LEN];
} ip6_mfib_key_t;

/**
 * An object that is inserted into the radix tree.
 * Since it's in the tree and has pointers, it cannot realloc and so cannot
 * come from a vlib pool.
 */
typedef struct ip6_mfib_node_t_
{
    struct radix_node i6mn_nodes[2];
    ip6_mfib_key_t i6mn_key;
    index_t i6mn_entry;
} ip6_mfib_node_t;

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
	mfib_table->v6.index =
	    (mfib_table - ip6_main.mfibs);

    hash_set (ip6_main.mfib_index_by_table_id,
              table_id,
              mfib_table->mft_index);

    mfib_table->mft_table_id =
	mfib_table->v6.table_id =
	    table_id;
    
    mfib_table_lock(mfib_table->mft_index, FIB_PROTOCOL_IP6);

    rn_inithead0(&mfib_table->v6.rhead, 0);

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

#define IP6_MFIB_MK_RKEY(_grp, _src, _len, _key)                    \
{                                                                   \
    (_key)->key[0] = 33;                                            \
    memcpy((_key)->key+1, _grp, 16);                                \
    memcpy((_key)->key+17, _src, 16);                               \
                                                                    \
    (_key)->mask[0] = 33;                                           \
    if (_len <= 128)                                                \
    {                                                               \
        memcpy((_key)->mask+1, &ip6_main.fib_masks[_len], 16);      \
        memset((_key)->mask+17, 0, 16);                             \
    }                                                               \
    else                                                            \
    {                                                               \
        ASSERT(_len == 256);                                        \
        memcpy((_key)->mask+1, &ip6_main.fib_masks[128], 16);       \
        memcpy((_key)->mask+17, &ip6_main.fib_masks[128], 16);      \
    }                                                               \
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
    ip6_mfib_node_t *i6mn;
    ip6_mfib_key_t key;

    IP6_MFIB_MK_RKEY(grp, src, len, &key);

    i6mn = (ip6_mfib_node_t*) rn_lookup(key.key, key.mask,
                                        (struct radix_node_head *)&mfib->rhead);

    if (NULL == i6mn)
    {
        return (INDEX_INVALID);
    }

    return (i6mn->i6mn_entry);
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
    ip6_mfib_node_t *i6mn;
    ip6_mfib_key_t key;

    IP6_MFIB_MK_RKEY(grp, src, len, &key);

    i6mn = (ip6_mfib_node_t*) rn_search_m(key.key,
                                          mfib->rhead.rnh_treetop,
                                          key.mask);

    ASSERT(NULL != i6mn);

    return (i6mn->i6mn_entry);
}

void
ip6_mfib_table_entry_insert (ip6_mfib_t *mfib,
                             const ip6_address_t *grp,
                             const ip6_address_t *src,
                             u32 len,
                             fib_node_index_t mfib_entry_index)
{
    ip6_mfib_node_t *i6mn = clib_mem_alloc(sizeof(*i6mn));

    memset(i6mn, 0, sizeof(*i6mn));

    IP6_MFIB_MK_RKEY(grp, src, len, &i6mn->i6mn_key);
    i6mn->i6mn_entry = mfib_entry_index;

    if (NULL == rn_addroute(i6mn->i6mn_key.key,
                            i6mn->i6mn_key.mask,
                            &mfib->rhead,
                            i6mn->i6mn_nodes))
    {
        ASSERT(0);
    }
}

void
ip6_mfib_table_entry_remove (ip6_mfib_t *mfib,
                             const ip6_address_t *grp,
                             const ip6_address_t *src,
                             u32 len)
{
    ip6_mfib_node_t *i6mn;
    ip6_mfib_key_t key;

    IP6_MFIB_MK_RKEY(grp, src, len, &key);

    i6mn = (ip6_mfib_node_t*) rn_delete(key.key, key.mask, &mfib->rhead);

    clib_mem_free(i6mn);
}

static clib_error_t *
ip6_mfib_module_init (vlib_main_t * vm)
{
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


static int
ip6_mfib_table_collect_entries (struct radix_node *rn, void *arg)
{
    ip6_mfib_show_ctx_t *ctx = arg;
    ip6_mfib_node_t *i6mn;

    i6mn = (ip6_mfib_node_t*) rn;

    vec_add1(ctx->entries, i6mn->i6mn_entry);

    return (0);
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

    rn_walktree(&mfib->rhead,
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
