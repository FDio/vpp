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

#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/fib_table.h>
#include <vnet/dpo/ip6_ll_dpo.h>

#include <vppinfra/bihash_24_8.h>
#include <vppinfra/bihash_template.c>

ip6_fib_fwding_table_instance_t ip6_fib_fwding_table;

/* ip6 lookup table config parameters */
u32 ip6_fib_table_nbuckets;
uword ip6_fib_table_size;

typedef struct ip6_fib_hash_key_t_
{
  ip6_address_t addr;
  u8 len;
} ip6_fib_hash_key_t;

static void
ip6_fib_hash_load_specials (u32 fib_index)
{
    fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_len = 0,
	.fp_addr = {
	    .ip6 = {
		{ 0, 0, },
	    },
	}
    };

    /*
     * Add the default route.
     */
    fib_table_entry_special_add(fib_index,
				&pfx,
				FIB_SOURCE_DEFAULT_ROUTE,
				FIB_ENTRY_FLAG_DROP);

    /*
     * all link local via the link local lookup DPO
     */
    pfx.fp_addr.ip6.as_u64[0] = clib_host_to_net_u64 (0xFE80000000000000ULL);
    pfx.fp_addr.ip6.as_u64[1] = 0;
    pfx.fp_len = 10;
    fib_table_entry_special_dpo_add(fib_index,
                                    &pfx,
                                    FIB_SOURCE_SPECIAL,
                                    FIB_ENTRY_FLAG_NONE,
                                    ip6_ll_dpo_get());
}

static u32
create_fib_with_table_id (u32 table_id,
                          fib_source_t src,
                          fib_table_flags_t flags,
                          u8 *desc)
{
    fib_table_t *fib_table;
    ip6_fib_t *v6_fib;

    pool_get(ip6_main.fibs, fib_table);
    pool_get_aligned(ip6_main.v6_fibs, v6_fib, CLIB_CACHE_LINE_BYTES);

    clib_memset(fib_table, 0, sizeof(*fib_table));
    clib_memset(v6_fib, 0, sizeof(*v6_fib));

    ASSERT((fib_table - ip6_main.fibs) ==
           (v6_fib - ip6_main.v6_fibs));

    fib_table->ft_proto = FIB_PROTOCOL_IP6;
    fib_table->ft_index =
	    v6_fib->index =
                (fib_table - ip6_main.fibs);

    hash_set(ip6_main.fib_index_by_table_id, table_id, fib_table->ft_index);

    fib_table->ft_table_id =
	v6_fib->table_id =
	    table_id;
    fib_table->ft_flow_hash_config = IP_FLOW_HASH_DEFAULT;
    fib_table->ft_flags = flags;
    fib_table->ft_desc = desc;

    fib_table_lock(fib_table->ft_index, FIB_PROTOCOL_IP6, src);

    v6_fib->fib_entry_by_dst_address = hash_create_mem(2, sizeof(ip6_fib_hash_key_t), sizeof(fib_node_index_t));

    /*
     * add the special entries into the new FIB
     */
    ip6_fib_hash_load_specials (fib_table->ft_index);

    return (fib_table->ft_index);
}

u32
ip6_fib_table_find_or_create_and_lock (u32 table_id,
                                       fib_source_t src)
{
    uword * p;

    p = hash_get (ip6_main.fib_index_by_table_id, table_id);
    if (NULL == p)
	return create_fib_with_table_id(table_id, src,
                                        FIB_TABLE_FLAG_NONE,
                                        NULL);

    fib_table_lock(p[0], FIB_PROTOCOL_IP6, src);

    return (p[0]);
}

u32
ip6_fib_table_create_and_lock (fib_source_t src,
                               fib_table_flags_t flags,
                               u8 *desc)
{
    return (create_fib_with_table_id(~0, src, flags, desc));
}

void
ip6_fib_table_destroy (u32 fib_index)
{
    /*
     * all link local first ...
     */
    fib_prefix_t pfx = {
	.fp_proto = FIB_PROTOCOL_IP6,
	.fp_len = 10,
	.fp_addr = {
	    .ip6 = {
                .as_u8 = {
                    [0] = 0xFE,
                    [1] = 0x80,
                },
	    },
	}
    };
    fib_table_entry_delete(fib_index,
                           &pfx,
                           FIB_SOURCE_SPECIAL);

    /*
     * ... then the default route.
     */
    pfx.fp_addr.ip6.as_u64[0] = 0;
    pfx.fp_len = 00;
    fib_table_entry_special_remove(fib_index,
				   &pfx,
				   FIB_SOURCE_DEFAULT_ROUTE);

    fib_table_t *fib_table = fib_table_get(fib_index, FIB_PROTOCOL_IP6);
    fib_source_t source;

    /*
     * validate no more routes.
     */
#if CLIB_DEBUG > 0
    if (0 != fib_table->ft_total_route_counts)
        fib_table_assert_empty(fib_table);
#endif

    vec_foreach_index(source, fib_table->ft_src_route_counts)
    {
	ASSERT(0 == fib_table->ft_src_route_counts[source]);
    }

    if (~0 != fib_table->ft_table_id)
    {
	hash_unset (ip6_main.fib_index_by_table_id, fib_table->ft_table_id);
    }
    vec_free (fib_table->ft_locks);
    vec_free(fib_table->ft_src_route_counts);
    hash_free(pool_elt_at_index(ip6_main.v6_fibs, fib_index)->fib_entry_by_dst_address);
    pool_put_index(ip6_main.v6_fibs, fib_table->ft_index);
    pool_put(ip6_main.fibs, fib_table);
}

static void
ip6_fib_table_mk_key (ip6_fib_hash_key_t *key, const ip6_address_t *addr, u8 len)
{
  const ip6_address_t *mask = &ip6_main.fib_masks[len];
  key->addr.as_u64[0] = addr->as_u64[0] & mask->as_u64[0];
  key->addr.as_u64[1] = addr->as_u64[1] & mask->as_u64[1];
  key->len = len;
}

fib_node_index_t
ip6_fib_table_lookup (u32 fib_index,
		      const ip6_address_t *addr,
		      u32 len)
{
    uword *hash = pool_elt_at_index(ip6_main.v6_fibs, fib_index)->fib_entry_by_dst_address;
    ip6_fib_hash_key_t key;
    i32 mask_len;
    uword *result;

    for (mask_len = len; mask_len >= 0; mask_len--)
    {
      ip6_fib_table_mk_key (&key, addr, mask_len);
      result = hash_get_mem(hash, &key);
      if (result) {
	  return result[0];
      }
    }

    return FIB_NODE_INDEX_INVALID;
}

fib_node_index_t
ip6_fib_table_lookup_exact_match (u32 fib_index,
				  const ip6_address_t *addr,
				  u32 len)
{
    uword *hash = pool_elt_at_index(ip6_main.v6_fibs, fib_index)->fib_entry_by_dst_address;
    ip6_fib_hash_key_t key;
    ip6_fib_table_mk_key (&key, addr, len);
    uword *result = hash_get(hash, &key);
    return result ? result[0] : FIB_NODE_INDEX_INVALID;
}

void
ip6_fib_table_entry_remove (u32 fib_index,
			    const ip6_address_t *addr,
			    u32 len)
{
    uword **hash = &pool_elt_at_index(ip6_main.v6_fibs, fib_index)->fib_entry_by_dst_address;
    ip6_fib_hash_key_t key;
    ip6_fib_table_mk_key (&key, addr, len);
    hash_unset_mem_free(hash, &key);
}

void
ip6_fib_table_entry_insert (u32 fib_index,
			    const ip6_address_t *addr,
			    u32 len,
			    fib_node_index_t fib_entry_index)
{
    uword **hash = &pool_elt_at_index(ip6_main.v6_fibs, fib_index)->fib_entry_by_dst_address;
    ip6_fib_hash_key_t key;
    ip6_fib_table_mk_key (&key, addr, len);
    ASSERT (0 == hash_get(*hash, &key) && "entry already exists");
    hash_set_mem_alloc(hash, &key, fib_entry_index);
}

u32 ip6_fib_table_fwding_lookup_with_if_index (ip6_main_t * im,
					       u32 sw_if_index,
					       const ip6_address_t * dst)
{
    u32 fib_index = vec_elt (im->fib_index_by_sw_if_index, sw_if_index);
    return ip6_fib_table_fwding_lookup(fib_index, dst);
}

u32
ip6_fib_table_get_index_for_sw_if_index (u32 sw_if_index)
{
    if (sw_if_index >= vec_len(ip6_main.fib_index_by_sw_if_index))
    {
	/*
	 * This is the case for interfaces that are not yet mapped to
	 * a IP table
	 */
	return (~0);
    }
    return (ip6_main.fib_index_by_sw_if_index[sw_if_index]);
}

static void
compute_prefix_lengths_in_search_order (ip6_fib_fwding_table_instance_t *table)
{
    u8 *old, *prefix_lengths_in_search_order = NULL;
    int i;

    /*
     * build the list in a scratch space then cutover so the workers
     * can continue uninterrupted.
     */
    old = table->prefix_lengths_in_search_order;

    /* Note: bitmap reversed so this is in fact a longest prefix match */
    clib_bitmap_foreach (i, table->non_empty_dst_address_length_bitmap)
     {
	int dst_address_length = 128 - i;
	vec_add1(prefix_lengths_in_search_order, dst_address_length);
    }

    table->prefix_lengths_in_search_order = prefix_lengths_in_search_order;

    /*
     * let the workers go once round the track before we free the old set
     */
    vlib_worker_wait_one_loop();
    vec_free(old);
}

void
ip6_fib_table_fwding_dpo_update (u32 fib_index,
				 const ip6_address_t *addr,
				 u32 len,
				 const dpo_id_t *dpo)
{
    ip6_fib_fwding_table_instance_t *table;
    clib_bihash_kv_24_8_t kv;
    ip6_address_t *mask;
    u64 fib;

    table = &ip6_fib_fwding_table;
    mask = &ip6_main.fib_masks[len];
    fib = ((u64)((fib_index))<<32);

    kv.key[0] = addr->as_u64[0] & mask->as_u64[0];
    kv.key[1] = addr->as_u64[1] & mask->as_u64[1];
    kv.key[2] = fib | len;
    kv.value = dpo->dpoi_index;

    clib_bihash_add_del_24_8(&table->ip6_hash, &kv, 1);

    if (0 == table->dst_address_length_refcounts[len]++)
    {
        table->non_empty_dst_address_length_bitmap =
            clib_bitmap_set (table->non_empty_dst_address_length_bitmap,
                             128 - len, 1);
        compute_prefix_lengths_in_search_order (table);
    }
}

void
ip6_fib_table_fwding_dpo_remove (u32 fib_index,
				 const ip6_address_t *addr,
				 u32 len,
				 const dpo_id_t *dpo)
{
    ip6_fib_fwding_table_instance_t *table;
    clib_bihash_kv_24_8_t kv;
    ip6_address_t *mask;
    u64 fib;

    table = &ip6_fib_fwding_table;
    mask = &ip6_main.fib_masks[len];
    fib = ((u64)((fib_index))<<32);

    kv.key[0] = addr->as_u64[0] & mask->as_u64[0];
    kv.key[1] = addr->as_u64[1] & mask->as_u64[1];
    kv.key[2] = fib | len;
    kv.value = dpo->dpoi_index;

    clib_bihash_add_del_24_8(&table->ip6_hash, &kv, 0);

    /* refcount accounting */
    ASSERT (table->dst_address_length_refcounts[len] > 0);
    if (--table->dst_address_length_refcounts[len] == 0)
    {
	table->non_empty_dst_address_length_bitmap =
            clib_bitmap_set (table->non_empty_dst_address_length_bitmap,
                             128 - len, 0);
	compute_prefix_lengths_in_search_order (table);
    }
}

void
ip6_fib_table_walk (u32 fib_index,
                    fib_table_walk_fn_t fn,
                    void *arg)
{
    const fib_prefix_t root = {
        .fp_proto = FIB_PROTOCOL_IP6,
        // address and length default to all 0
    };
    /* A full tree walk is the dengenerate case of a sub-tree from
     * the very root */
    return (ip6_fib_table_sub_tree_walk(fib_index, &root, fn, arg));
}

void
ip6_fib_table_sub_tree_walk (u32 fib_index,
                             const fib_prefix_t *root,
                             fib_table_walk_fn_t fn,
                             void *arg)
{
    uword *hash = pool_elt_at_index(ip6_main.v6_fibs, fib_index)->fib_entry_by_dst_address;
    const ip6_fib_hash_key_t *key, *sub_tree;
    ip6_fib_hash_key_t *sub_trees = 0;
    u32 fei;

    /*
     * There is no efficient way to walk this hash table.
     * so we walk over all entries and check it is covered by the root.
     */
    hash_foreach_mem(key, fei, hash, ({
	/* check if the prefix is covered by the root */
	if (!ip6_destination_matches_route(&ip6_main, &key->addr, &root->fp_addr.ip6, root->fp_len))
	  continue; /* not covered by root, ignore */

	/* exclude sub-trees the walk does not want to explore */
	vec_foreach (sub_tree, sub_trees)
	  {
	    if (ip6_destination_matches_route(&ip6_main, &key->addr, &sub_tree->addr, sub_tree->len))
	      goto ignore_sub_tree;
	  }

	switch (fn(fei, arg))
	  {
	  case FIB_TABLE_WALK_STOP:
	    goto done;
	  case FIB_TABLE_WALK_CONTINUE:
	    break;
	  case FIB_TABLE_WALK_SUB_TREE_STOP:
	    vec_add1(sub_trees, *key);
	    break;
	  }

ignore_sub_tree:;
    }));

done:
    vec_free(sub_trees);
}

typedef struct ip6_fib_show_ctx_t_ {
    fib_node_index_t *entries;
} ip6_fib_show_ctx_t;

static fib_table_walk_rc_t
ip6_fib_table_show_walk (fib_node_index_t fib_entry_index,
                         void *arg)
{
    ip6_fib_show_ctx_t *ctx = arg;

    vec_add1(ctx->entries, fib_entry_index);

    return (FIB_TABLE_WALK_CONTINUE);
}

static void
ip6_fib_table_show_all (ip6_fib_t *fib,
			vlib_main_t * vm)
{
    fib_node_index_t *fib_entry_index;
    ip6_fib_show_ctx_t ctx = {
	.entries = NULL,
    };

    ip6_fib_table_walk(fib->index, ip6_fib_table_show_walk, &ctx);
    vec_sort_with_function(ctx.entries, fib_entry_cmp_for_sort);

    vec_foreach(fib_entry_index, ctx.entries)
    {
	vlib_cli_output(vm, "%U",
                        format_fib_entry,
                        *fib_entry_index,
                        FIB_ENTRY_FORMAT_BRIEF);
    }

    vec_free(ctx.entries);
}

static void
ip6_fib_table_show_one (ip6_fib_t *fib,
			vlib_main_t * vm,
			ip6_address_t *address,
			u32 mask_len,
                        int detail)
{
    vlib_cli_output(vm, "%U",
                    format_fib_entry,
                    ip6_fib_table_lookup(fib->index, address, mask_len),
                    (detail ?
                     FIB_ENTRY_FORMAT_DETAIL2:
                     FIB_ENTRY_FORMAT_DETAIL));
}

u8 *
format_ip6_fib_table_memory (u8 * s, va_list * args)
{
    uword bytes_inuse;

    bytes_inuse = alloc_arena_next(&ip6_fib_fwding_table.ip6_hash);

    s = format(s, "%=30s %=6d %=12ld\n",
               "IPv6 unicast",
               pool_elts(ip6_main.fibs),
               bytes_inuse);
    return (s);
}

void
ip6_fib_table_show (vlib_main_t *vm, fib_table_t *fib_table, int summary)
{
    ip6_main_t * im6 = &ip6_main;
    ip6_fib_t *fib = pool_elt_at_index(im6->v6_fibs, fib_table->ft_index);
    fib_source_t source;
    u8 *s = NULL;

    s = format(s, "%U, fib_index:%d, flow hash:[%U] epoch:%d flags:%U locks:[",
	       format_fib_table_name, fib->index,
	       FIB_PROTOCOL_IP6,
	       fib->index,
	       format_ip_flow_hash_config,
	       fib_table->ft_flow_hash_config,
	       fib_table->ft_epoch,
	       format_fib_table_flags, fib_table->ft_flags);

    vec_foreach_index(source, fib_table->ft_locks)
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
    if (summary)
    {
	u32 count_by_prefix_length[129];
	const ip6_fib_hash_key_t *key;
	u32 fei;
	int len;

	vlib_cli_output (vm, "%=20s%=16s", "Prefix length", "Count");

	clib_memset (count_by_prefix_length, 0, sizeof(count_by_prefix_length));

	hash_foreach_mem(key, fei, fib->fib_entry_by_dst_address, ({
	    ASSERT(key->len <= 128);
	    count_by_prefix_length[key->len]++;
	}));

	for (len = 128; len >= 0; len--)
	{
	    if (count_by_prefix_length[len])
		vlib_cli_output (vm, "%=20d%=16lld",
				 len, count_by_prefix_length[len]);
	}
    }
}

static clib_error_t *
ip6_show_fib (vlib_main_t * vm,
	      unformat_input_t * input,
	      vlib_cli_command_t * cmd)
{
    ip6_main_t * im6 = &ip6_main;
    fib_table_t *fib_table;
    ip6_fib_t * fib;
    int verbose, matching;
    ip6_address_t matching_address;
    u32 mask_len  = 128;
    int table_id = -1, fib_index = ~0;
    int detail = 0;
    int hash = 0;

    verbose = 1;
    matching = 0;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "brief")   ||
	    unformat (input, "summary") ||
	    unformat (input, "sum"))
	    verbose = 0;
 
	else if (unformat (input, "detail")   ||
                 unformat (input, "det"))
	    detail = 1;

	else if (unformat (input, "hash") ||
                 unformat (input, "mem") ||
                 unformat (input, "memory"))
	    hash = 1;

	else if (unformat (input, "%U/%d",
			   unformat_ip6_address, &matching_address, &mask_len))
	    matching = 1;

	else if (unformat (input, "%U", unformat_ip6_address, &matching_address))
	    matching = 1;

	else if (unformat (input, "table %d", &table_id))
	    ;
	else if (unformat (input, "index %d", &fib_index))
	    ;
	else
	    break;
    }

    if (hash)
    {
        vlib_cli_output (vm, "IPv6 Forwarding Hash Table:\n%U\n",
                         BV (format_bihash),
                         &ip6_fib_fwding_table.ip6_hash,
                         detail);
        return (NULL);
    }

    pool_foreach (fib_table, im6->fibs)
     {
	fib = pool_elt_at_index(im6->v6_fibs, fib_table->ft_index);
	if (table_id >= 0 && table_id != (int)fib->table_id)
	    continue;
	if (fib_index != ~0 && fib_index != (int)fib->index)
	    continue;
        if (fib_table->ft_flags & FIB_TABLE_FLAG_IP6_LL)
            continue;

	ip6_fib_table_show(vm, fib_table, !verbose);
	if (!verbose)
	  continue;

	if (!matching)
	{
	    ip6_fib_table_show_all(fib, vm);
	}
	else
	{
	    ip6_fib_table_show_one(fib, vm, &matching_address, mask_len, detail);
	}
    }

    return 0;
}

/*?
 * This command displays the IPv6 FIB Tables (VRF Tables) and the route
 * entries for each table.
 *
 * @note This command will run for a long time when the FIB tables are
 * comprised of millions of entries. For those scenarios, consider displaying
 * in summary mode.
 *
 * @cliexpar
 * @parblock
 * Example of how to display all the IPv6 FIB tables:
 * @cliexstart{show ip6 fib}
 * ipv6-VRF:0, fib_index 0, flow hash: src dst sport dport proto
 * @::/0
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:5 buckets:1 uRPF:5 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * fe80::/10
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:10 buckets:1 uRPF:10 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::1/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:8 buckets:1 uRPF:8 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::2/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:7 buckets:1 uRPF:7 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::16/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:9 buckets:1 uRPF:9 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::1:ff00:0/104
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:6 buckets:1 uRPF:6 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ipv6-VRF:8, fib_index 1, flow hash: src dst sport dport proto
 * @::/0
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:21 buckets:1 uRPF:20 to:[0:0]]
 *     [0] [@0]: dpo-drop ip6
 * @::a:1:1:0:4/126
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:27 buckets:1 uRPF:26 to:[0:0]]
 *     [0] [@4]: ipv6-glean: af_packet0
 * @::a:1:1:0:7/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:28 buckets:1 uRPF:27 to:[0:0]]
 *     [0] [@2]: dpo-receive: @::a:1:1:0:7 on af_packet0
 * fe80::/10
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:26 buckets:1 uRPF:25 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * fe80::fe:3eff:fe3e:9222/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:29 buckets:1 uRPF:28 to:[0:0]]
 *     [0] [@2]: dpo-receive: fe80::fe:3eff:fe3e:9222 on af_packet0
 * ff02::1/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:24 buckets:1 uRPF:23 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::2/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:23 buckets:1 uRPF:22 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::16/128
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:25 buckets:1 uRPF:24 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * ff02::1:ff00:0/104
 *   unicast-ip6-chain
 *   [@0]: dpo-load-balance: [index:22 buckets:1 uRPF:21 to:[0:0]]
 *     [0] [@2]: dpo-receive
 * @cliexend
 *
 * Example of how to display a summary of all IPv6 FIB tables:
 * @cliexstart{show ip6 fib summary}
 * ipv6-VRF:0, fib_index 0, flow hash: src dst sport dport proto
 *     Prefix length         Count
 *          128                3
 *          104                1
 *          10                 1
 *           0                 1
 * ipv6-VRF:8, fib_index 1, flow hash: src dst sport dport proto
 *     Prefix length         Count
 *          128                5
 *          126                1
 *          104                1
 *          10                 1
 *           0                 1
 * @cliexend
 * @endparblock
 ?*/
VLIB_CLI_COMMAND (ip6_show_fib_command, static) = {
    .path = "show ip6 fib",
    .short_help = "show ip6 fib [summary] [table <table-id>] [index <fib-id>] [<ip6-addr>[/<width>]] [detail]",
    .function = ip6_show_fib,
};

static clib_error_t *
ip6_config (vlib_main_t * vm, unformat_input_t * input)
{
  uword heapsize = 0;
  u32 nbuckets = 0;
  char *default_name = 0;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "hash-buckets %d", &nbuckets))
          ;
      else if (unformat (input, "heap-size %U",
			 unformat_memory_size, &heapsize))
	;
      else if (unformat (input, "default-table-name %s", &default_name))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  ip6_fib_table_nbuckets = nbuckets;
  ip6_fib_table_size = heapsize;
  fib_table_default_names[FIB_PROTOCOL_IP6] = default_name;

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (ip6_config, "ip6");

static clib_error_t *
ip6_fib_init (vlib_main_t * vm)
{
    if (ip6_fib_table_nbuckets == 0)
        ip6_fib_table_nbuckets = IP6_FIB_DEFAULT_HASH_NUM_BUCKETS;

    ip6_fib_table_nbuckets = 1 << max_log2 (ip6_fib_table_nbuckets);

    if (ip6_fib_table_size == 0)
        ip6_fib_table_size = IP6_FIB_DEFAULT_HASH_MEMORY_SIZE;

    clib_bihash_init_24_8 (&(ip6_fib_fwding_table.ip6_hash),
                           "ip6 FIB fwding table",
                           ip6_fib_table_nbuckets, ip6_fib_table_size);

    return (NULL);
}

VLIB_INIT_FUNCTION (ip6_fib_init) =
{
  .runs_before = VLIB_INITS("ip6_lookup_init"),
};
