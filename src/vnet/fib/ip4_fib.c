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

#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/fib/ip4_fib.h>

/*
 * A table of pefixes to be added to tables and the sources for them
 */
typedef struct ip4_fib_table_special_prefix_t_ {
    fib_prefix_t ift_prefix;
    fib_source_t ift_source;
    fib_entry_flag_t ift_flag;
} ip4_fib_table_special_prefix_t;

static const ip4_fib_table_special_prefix_t ip4_specials[] = {
    {
	/* 0.0.0.0/0*/
	.ift_prefix = {
	    .fp_addr = {
		.ip4.data_u32 = 0,
	    },
	    .fp_len  = 0,
	    .fp_proto = FIB_PROTOCOL_IP4,
	},
	.ift_source = FIB_SOURCE_DEFAULT_ROUTE,
	.ift_flag   = FIB_ENTRY_FLAG_DROP,
    },
    {
	/* 0.0.0.0/32*/
	.ift_prefix = {
	    .fp_addr = {
		.ip4.data_u32 = 0,
	    },
	    .fp_len  = 32,
	    .fp_proto = FIB_PROTOCOL_IP4,
	},
	.ift_source = FIB_SOURCE_DEFAULT_ROUTE,
	.ift_flag   = FIB_ENTRY_FLAG_DROP,
    },
    {
	/*
	 * 240.0.0.0/4
	 * drop class E
	 */
	.ift_prefix = {
	    .fp_addr = {
		.ip4.data_u32 = 0xf0000000,
	    },
	    .fp_len   = 4,
	    .fp_proto = FIB_PROTOCOL_IP4,
	},
	.ift_source = FIB_SOURCE_SPECIAL,
	.ift_flag   = FIB_ENTRY_FLAG_DROP,

    },
    {
	/*
	 * 224.0.0.0/4
	 * drop all mcast
	 */
	.ift_prefix = {
	    .fp_addr = {
		.ip4.data_u32 = 0xe0000000,
	    },
	    .fp_len   = 4,
	    .fp_proto = FIB_PROTOCOL_IP4,
	},
	.ift_source = FIB_SOURCE_SPECIAL,
	.ift_flag    = FIB_ENTRY_FLAG_DROP,
    },
    {
	/*
	 * 255.255.255.255/32
	 * drop, but we'll allow it to be usurped by the likes of DHCP
	 */
	.ift_prefix = {
	    .fp_addr = {
		.ip4.data_u32 = 0xffffffff,
	    },
	    .fp_len   = 32,
	    .fp_proto = FIB_PROTOCOL_IP4,
	},
	.ift_source = FIB_SOURCE_DEFAULT_ROUTE,
	.ift_flag   = FIB_ENTRY_FLAG_DROP,
    }
};


static u32
ip4_create_fib_with_table_id (u32 table_id,
                              fib_source_t src)
{
    fib_table_t *fib_table;
    ip4_fib_t *v4_fib;

    pool_get_aligned(ip4_main.fibs, fib_table, CLIB_CACHE_LINE_BYTES);
    memset(fib_table, 0, sizeof(*fib_table));

    pool_get_aligned(ip4_main.v4_fibs, v4_fib, CLIB_CACHE_LINE_BYTES);

    ASSERT((fib_table - ip4_main.fibs) ==
           (v4_fib - ip4_main.v4_fibs));

    fib_table->ft_proto = FIB_PROTOCOL_IP4;
    fib_table->ft_index =
	v4_fib->index =
	    (fib_table - ip4_main.fibs);

    hash_set (ip4_main.fib_index_by_table_id, table_id, fib_table->ft_index);

    fib_table->ft_table_id =
	v4_fib->table_id =
	    table_id;
    fib_table->ft_flow_hash_config = IP_FLOW_HASH_DEFAULT;
    v4_fib->fwd_classify_table_index = ~0;
    v4_fib->rev_classify_table_index = ~0;
    
    fib_table_lock(fib_table->ft_index, FIB_PROTOCOL_IP4, src);

    ip4_mtrie_init(&v4_fib->mtrie);

    /*
     * add the special entries into the new FIB
     */
    int ii;

    for (ii = 0; ii < ARRAY_LEN(ip4_specials); ii++)
    {
	fib_prefix_t prefix = ip4_specials[ii].ift_prefix;

	prefix.fp_addr.ip4.data_u32 =
	    clib_host_to_net_u32(prefix.fp_addr.ip4.data_u32);

	fib_table_entry_special_add(fib_table->ft_index,
				    &prefix,
				    ip4_specials[ii].ift_source,
				    ip4_specials[ii].ift_flag);
    }

    return (fib_table->ft_index);
}

void
ip4_fib_table_destroy (u32 fib_index)
{
    fib_table_t *fib_table = pool_elt_at_index(ip4_main.fibs, fib_index);
    ip4_fib_t *v4_fib = pool_elt_at_index(ip4_main.v4_fibs, fib_index);
    int ii;

    /*
     * remove all the specials we added when the table was created.
     * In reverse order so the default route is last.
     */
    for (ii = ARRAY_LEN(ip4_specials) - 1; ii >= 0; ii--)
    {
	fib_prefix_t prefix = ip4_specials[ii].ift_prefix;

	prefix.fp_addr.ip4.data_u32 =
	    clib_host_to_net_u32(prefix.fp_addr.ip4.data_u32);

	fib_table_entry_special_remove(fib_table->ft_index,
				       &prefix,
				       ip4_specials[ii].ift_source);
    }

    /*
     * validate no more routes.
     */
    ASSERT(0 == fib_table->ft_total_route_counts);
    FOR_EACH_FIB_SOURCE(ii)
    {
	ASSERT(0 == fib_table->ft_src_route_counts[ii]);
    }

    if (~0 != fib_table->ft_table_id)
    {
	hash_unset (ip4_main.fib_index_by_table_id, fib_table->ft_table_id);
    }

    ip4_mtrie_free(&v4_fib->mtrie);

    pool_put(ip4_main.v4_fibs, v4_fib);
    pool_put(ip4_main.fibs, fib_table);
}


u32
ip4_fib_table_find_or_create_and_lock (u32 table_id,
                                       fib_source_t src)
{
    u32 index;

    index = ip4_fib_index_from_table_id(table_id);
    if (~0 == index)
	return ip4_create_fib_with_table_id(table_id, src);

    fib_table_lock(index, FIB_PROTOCOL_IP4, src);

    return (index);
}

u32
ip4_fib_table_create_and_lock (fib_source_t src)
{
    return (ip4_create_fib_with_table_id(~0, src));
}

u32
ip4_fib_table_get_index_for_sw_if_index (u32 sw_if_index)
{
    if (sw_if_index >= vec_len(ip4_main.fib_index_by_sw_if_index))
    {
	/*
	 * This is the case for interfaces that are not yet mapped to
	 * a IP table
	 */
	return (~0);
    }
    return (ip4_main.fib_index_by_sw_if_index[sw_if_index]);
}

/*
 * ip4_fib_table_lookup_exact_match
 *
 * Exact match prefix lookup
 */
fib_node_index_t
ip4_fib_table_lookup_exact_match (const ip4_fib_t *fib,
				  const ip4_address_t *addr,
				  u32 len)
{
    uword * hash, * result;
    u32 key;

    hash = fib->fib_entry_by_dst_address[len];
    key  = (addr->data_u32 & ip4_main.fib_masks[len]);

    result = hash_get(hash, key);

    if (NULL != result) {
	return (result[0]);
    }
    return (FIB_NODE_INDEX_INVALID);
}

/*
 * ip4_fib_table_lookup_adj
 *
 * Longest prefix match
 */
index_t
ip4_fib_table_lookup_lb (ip4_fib_t *fib,
			 const ip4_address_t *addr)
{
    fib_node_index_t fei;

    fei = ip4_fib_table_lookup(fib, addr, 32);

    if (FIB_NODE_INDEX_INVALID != fei)
    {
	const dpo_id_t *dpo;

	dpo = fib_entry_contribute_ip_forwarding(fei);

	return (dpo->dpoi_index);
    }
    return (INDEX_INVALID);
}

/*
 * ip4_fib_table_lookup
 *
 * Longest prefix match
 */
fib_node_index_t
ip4_fib_table_lookup (const ip4_fib_t *fib,
		      const ip4_address_t *addr,
		      u32 len)
{
    uword * hash, * result;
    i32 mask_len;
    u32 key;

    for (mask_len = len; mask_len >= 0; mask_len--)
    {
	hash = fib->fib_entry_by_dst_address[mask_len];
	key = (addr->data_u32 & ip4_main.fib_masks[mask_len]);

	result = hash_get (hash, key);

	if (NULL != result) {
	    return (result[0]);
	}
    }
    return (FIB_NODE_INDEX_INVALID);
}

void
ip4_fib_table_entry_insert (ip4_fib_t *fib,
			    const ip4_address_t *addr,
			    u32 len,
			    fib_node_index_t fib_entry_index)
{
    uword * hash, * result;
    u32 key;

    key = (addr->data_u32 & ip4_main.fib_masks[len]);
    hash = fib->fib_entry_by_dst_address[len];
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
	fib->fib_entry_by_dst_address[len] = hash;
    }
    else
    {
	ASSERT(0);
    }
}

void
ip4_fib_table_entry_remove (ip4_fib_t *fib,
			    const ip4_address_t *addr,
			    u32 len)
{
    uword * hash, * result;
    u32 key;

    key = (addr->data_u32 & ip4_main.fib_masks[len]);
    hash = fib->fib_entry_by_dst_address[len];
    result = hash_get (hash, key);

    if (NULL == result)
    {
	/*
	 * removing a non-existant entry. i'll allow it.
	 */
    }
    else 
    {
	hash_unset(hash, key);
    }

    fib->fib_entry_by_dst_address[len] = hash;
}

void
ip4_fib_table_fwding_dpo_update (ip4_fib_t *fib,
				 const ip4_address_t *addr,
				 u32 len,
				 const dpo_id_t *dpo)
{
    ip4_fib_mtrie_route_add(&fib->mtrie, addr, len, dpo->dpoi_index);
}

void
ip4_fib_table_fwding_dpo_remove (ip4_fib_t *fib,
				 const ip4_address_t *addr,
				 u32 len,
				 const dpo_id_t *dpo,
                                 u32 cover_index)
{
    fib_prefix_t cover_prefix = {
        .fp_len = 0,
    };
    const dpo_id_t *cover_dpo;

    /*
     * We need to pass the MTRIE the LB index and address length of the
     * covering prefix, so it can fill the plys with the correct replacement
     * for the entry being removed
     */
    fib_entry_get_prefix(cover_index, &cover_prefix);
    cover_dpo = fib_entry_contribute_ip_forwarding(cover_index);

    ip4_fib_mtrie_route_del(&fib->mtrie,
                            addr, len, dpo->dpoi_index,
                            cover_prefix.fp_len,
                            cover_dpo->dpoi_index);
}

void
ip4_fib_table_walk (ip4_fib_t *fib,
                    fib_table_walk_fn_t fn,
                    void *ctx)
{
    int i;

    for (i = 0; i < ARRAY_LEN (fib->fib_entry_by_dst_address); i++)
    {
	uword * hash = fib->fib_entry_by_dst_address[i];

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

/**
 * Walk show context
 */
typedef struct ip4_fib_show_walk_ctx_t_
{
    fib_node_index_t *ifsw_indicies;
} ip4_fib_show_walk_ctx_t;

static int
ip4_fib_show_walk_cb (fib_node_index_t fib_entry_index,
                      void *arg)
{
    ip4_fib_show_walk_ctx_t *ctx = arg;

    vec_add1(ctx->ifsw_indicies, fib_entry_index);

    return (1);
}

static void
ip4_fib_table_show_all (ip4_fib_t *fib,
			vlib_main_t * vm)
{
    ip4_fib_show_walk_ctx_t ctx = {
        .ifsw_indicies = NULL,
    };
    fib_node_index_t *fib_entry_index;

    ip4_fib_table_walk(fib, ip4_fib_show_walk_cb, &ctx);
    vec_sort_with_function(ctx.ifsw_indicies,
                           fib_entry_cmp_for_sort);

    vec_foreach(fib_entry_index, ctx.ifsw_indicies)
    {
	vlib_cli_output(vm, "%U",
                        format_fib_entry,
                        *fib_entry_index,
                        FIB_ENTRY_FORMAT_BRIEF);
    }

    vec_free(ctx.ifsw_indicies);
}

static void
ip4_fib_table_show_one (ip4_fib_t *fib,
			vlib_main_t * vm,
			ip4_address_t *address,
			u32 mask_len,
                        int detail)
{    
    vlib_cli_output(vm, "%U",
                    format_fib_entry,
                    ip4_fib_table_lookup(fib, address, mask_len),
                    (detail ?
                     FIB_ENTRY_FORMAT_DETAIL2 :
                     FIB_ENTRY_FORMAT_DETAIL));
}

static clib_error_t *
ip4_show_fib (vlib_main_t * vm,
	      unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
    ip4_main_t * im4 = &ip4_main;
    fib_table_t * fib_table;
    int verbose, matching, mtrie;
    ip4_address_t matching_address;
    u32 matching_mask = 32;
    int i, table_id = -1, fib_index = ~0;
    int detail = 0;

    verbose = 1;
    matching = 0;
    mtrie = 0;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "brief") || unformat (input, "summary")
	    || unformat (input, "sum"))
	    verbose = 0;

	else if (unformat (input, "detail") || unformat (input, "det"))
	    detail = 1;

	else if (unformat (input, "mtrie"))
	    mtrie = 1;

	else if (unformat (input, "%U/%d",
			   unformat_ip4_address, &matching_address, &matching_mask))
	    matching = 1;

	else if (unformat (input, "%U", unformat_ip4_address, &matching_address))
	    matching = 1;

	else if (unformat (input, "table %d", &table_id))
	    ;
	else if (unformat (input, "index %d", &fib_index))
	    ;
	else
	    break;
    }

    pool_foreach (fib_table, im4->fibs,
    ({
	ip4_fib_t *fib = pool_elt_at_index(im4->v4_fibs, fib_table->ft_index);
        fib_source_t source;
        u8 *s = NULL;

	if (table_id >= 0 && table_id != (int)fib->table_id)
	    continue;
	if (fib_index != ~0 && fib_index != (int)fib->index)
	    continue;

	s = format(s, "%U, fib_index:%d, flow hash:[%U] locks:[",
                   format_fib_table_name, fib->index,
                   FIB_PROTOCOL_IP4,
                   fib->index,
                   format_ip_flow_hash_config,
                   fib_table->ft_flow_hash_config);
	FOR_EACH_FIB_SOURCE(source)
        {
            if (0 != fib_table->ft_locks[source])
            {
                s = format(s, "%U:%d, ",
                           format_fib_source, source,
                           fib_table->ft_locks[source]);
            }
        }
        s = format (s, "]");
        vlib_cli_output (vm, "%v", s);
        vec_free(s);

	/* Show summary? */
	if (! verbose)
	{
	    vlib_cli_output (vm, "%=20s%=16s", "Prefix length", "Count");
	    for (i = 0; i < ARRAY_LEN (fib->fib_entry_by_dst_address); i++)
	    {
		uword * hash = fib->fib_entry_by_dst_address[i];
		uword n_elts = hash_elts (hash);
		if (n_elts > 0)
		    vlib_cli_output (vm, "%20d%16d", i, n_elts);
	    }
	    continue;
	}
	if (mtrie)
        {
	    vlib_cli_output (vm, "%U", format_ip4_fib_mtrie, &fib->mtrie);
            continue;
        }

	if (!matching)
	{
	    ip4_fib_table_show_all(fib, vm);
	}
	else
	{
	    ip4_fib_table_show_one(fib, vm, &matching_address,
                                   matching_mask, detail);
	}
    }));

    return 0;
}

/*?
 * This command displays the IPv4 FIB Tables (VRF Tables) and the route
 * entries for each table.
 *
 * @note This command will run for a long time when the FIB tables are
 * comprised of millions of entries. For those senarios, consider displaying
 * a single table or summary mode.
 *
 * @cliexpar
 * Example of how to display all the IPv4 FIB tables:
 * @cliexstart{show ip fib}
 * ipv4-VRF:0, fib_index 0, flow hash: src dst sport dport proto
 * 0.0.0.0/0
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:0 buckets:1 uRPF:0 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 0.0.0.0/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:1 buckets:1 uRPF:1 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 6.0.1.2/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:30 buckets:1 uRPF:29 to:[0:0]]
 *     [0] [@3]: arp-ipv4: via 6.0.0.1 af_packet0
 * 7.0.0.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:31 buckets:4 uRPF:30 to:[0:0]]
 *     [0] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
 *     [1] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
 *     [2] [@3]: arp-ipv4: via 6.0.0.2 af_packet0
 *     [3] [@3]: arp-ipv4: via 6.0.0.1 af_packet0
 * 224.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:3 buckets:1 uRPF:3 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 240.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:2 buckets:1 uRPF:2 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 255.255.255.255/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:4 buckets:1 uRPF:4 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * ipv4-VRF:7, fib_index 1, flow hash: src dst sport dport proto
 * 0.0.0.0/0
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:12 buckets:1 uRPF:11 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 0.0.0.0/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:13 buckets:1 uRPF:12 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 172.16.1.0/24
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:17 buckets:1 uRPF:16 to:[0:0]]
 *     [0] [@4]: ipv4-glean: af_packet0
 * 172.16.1.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:18 buckets:1 uRPF:17 to:[1:84]]
 *     [0] [@2]: dpo-receive: 172.16.1.1 on af_packet0
 * 172.16.1.2/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:21 buckets:1 uRPF:20 to:[0:0]]
 *     [0] [@5]: ipv4 via 172.16.1.2 af_packet0: IP4: 02:fe:9e:70:7a:2b -> 26:a5:f6:9c:3a:36
 * 172.16.2.0/24
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:19 buckets:1 uRPF:18 to:[0:0]]
 *     [0] [@4]: ipv4-glean: af_packet1
 * 172.16.2.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:20 buckets:1 uRPF:19 to:[0:0]]
 *     [0] [@2]: dpo-receive: 172.16.2.1 on af_packet1
 * 224.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:15 buckets:1 uRPF:14 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 240.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:14 buckets:1 uRPF:13 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 255.255.255.255/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:16 buckets:1 uRPF:15 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * @cliexend
 * Example of how to display a single IPv4 FIB table:
 * @cliexstart{show ip fib table 7}
 * ipv4-VRF:7, fib_index 1, flow hash: src dst sport dport proto
 * 0.0.0.0/0
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:12 buckets:1 uRPF:11 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 0.0.0.0/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:13 buckets:1 uRPF:12 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 172.16.1.0/24
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:17 buckets:1 uRPF:16 to:[0:0]]
 *     [0] [@4]: ipv4-glean: af_packet0
 * 172.16.1.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:18 buckets:1 uRPF:17 to:[1:84]]
 *     [0] [@2]: dpo-receive: 172.16.1.1 on af_packet0
 * 172.16.1.2/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:21 buckets:1 uRPF:20 to:[0:0]]
 *     [0] [@5]: ipv4 via 172.16.1.2 af_packet0: IP4: 02:fe:9e:70:7a:2b -> 26:a5:f6:9c:3a:36
 * 172.16.2.0/24
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:19 buckets:1 uRPF:18 to:[0:0]]
 *     [0] [@4]: ipv4-glean: af_packet1
 * 172.16.2.1/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:20 buckets:1 uRPF:19 to:[0:0]]
 *     [0] [@2]: dpo-receive: 172.16.2.1 on af_packet1
 * 224.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:15 buckets:1 uRPF:14 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 240.0.0.0/8
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:14 buckets:1 uRPF:13 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * 255.255.255.255/32
 *   unicast-ip4-chain
 *   [@0]: dpo-load-balance: [index:16 buckets:1 uRPF:15 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
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
VLIB_CLI_COMMAND (ip4_show_fib_command, static) = {
    .path = "show ip fib",
    .short_help = "show ip fib [summary] [table <table-id>] [index <fib-id>] [<ip4-addr>[/<mask>]] [mtrie] [detail]",
    .function = ip4_show_fib,
};
/* *INDENT-ON* */
