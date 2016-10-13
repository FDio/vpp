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
	 * 240.0.0.0/8
	 * drop class E
	 */
	.ift_prefix = {
	    .fp_addr = {
		.ip4.data_u32 = 0xf0000000,
	    },
	    .fp_len   = 8,
	    .fp_proto = FIB_PROTOCOL_IP4,
	},
	.ift_source = FIB_SOURCE_SPECIAL,
	.ift_flag   = FIB_ENTRY_FLAG_DROP,

    },
    {
	/*
	 * 224.0.0.0/8
	 * drop all mcast
	 */
	.ift_prefix = {
	    .fp_addr = {
		.ip4.data_u32 = 0xe0000000,
	    },
	    .fp_len   = 8,
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
ip4_create_fib_with_table_id (u32 table_id)
{
    fib_table_t *fib_table;

    pool_get_aligned(ip4_main.fibs, fib_table, CLIB_CACHE_LINE_BYTES);
    memset(fib_table, 0, sizeof(*fib_table));

    fib_table->ft_proto = FIB_PROTOCOL_IP4;
    fib_table->ft_index =
	fib_table->v4.index =
	    (fib_table - ip4_main.fibs);

    hash_set (ip4_main.fib_index_by_table_id, table_id, fib_table->ft_index);

    fib_table->ft_table_id =
	fib_table->v4.table_id =
	    table_id;
    fib_table->ft_flow_hash_config = 
	fib_table->v4.flow_hash_config =
	    IP_FLOW_HASH_DEFAULT;
    fib_table->v4.fwd_classify_table_index = ~0;
    fib_table->v4.rev_classify_table_index = ~0;
    
    fib_table_lock(fib_table->ft_index, FIB_PROTOCOL_IP4);

    ip4_mtrie_init(&fib_table->v4.mtrie);

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
				    ip4_specials[ii].ift_flag,
				    ADJ_INDEX_INVALID);
    }

    return (fib_table->ft_index);
}

void
ip4_fib_table_destroy (ip4_fib_t *fib)
{
    fib_table_t *fib_table = (fib_table_t*)fib;
    int ii;

    /*
     * remove all the specials we added when the table was created.
     */
    for (ii = 0; ii < ARRAY_LEN(ip4_specials); ii++)
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
    pool_put(ip4_main.fibs, fib_table);
}


u32
ip4_fib_table_find_or_create_and_lock (u32 table_id)
{
    u32 index;

    index = ip4_fib_index_from_table_id(table_id);
    if (~0 == index)
	return ip4_create_fib_with_table_id(table_id);

    fib_table_lock(index, FIB_PROTOCOL_IP4);

    return (index);
}

u32
ip4_fib_table_create_and_lock (void)
{
    return (ip4_create_fib_with_table_id(~0));
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

flow_hash_config_t
ip4_fib_table_get_flow_hash_config (u32 fib_index)
{
    return (ip4_fib_get(fib_index)->flow_hash_config);
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
    ip4_fib_mtrie_add_del_route(fib, *addr, len, dpo->dpoi_index, 0); // ADD
}

void
ip4_fib_table_fwding_dpo_remove (ip4_fib_t *fib,
				 const ip4_address_t *addr,
				 u32 len,
				 const dpo_id_t *dpo)
{
    ip4_fib_mtrie_add_del_route(fib, *addr, len, dpo->dpoi_index, 1); // DELETE
}

static void
ip4_fib_table_show_all (ip4_fib_t *fib,
			vlib_main_t * vm)
{
    fib_node_index_t *fib_entry_indicies;
    fib_node_index_t *fib_entry_index;
    int i;

    fib_entry_indicies = NULL;

    for (i = 0; i < ARRAY_LEN (fib->fib_entry_by_dst_address); i++)
    {
	uword * hash = fib->fib_entry_by_dst_address[i];

	if (NULL != hash)
	{
	    hash_pair_t * p;

	    hash_foreach_pair (p, hash,
	    ({
		vec_add1(fib_entry_indicies, p->value[0]);
	    }));
	}
    }

    vec_sort_with_function(fib_entry_indicies, fib_entry_cmp_for_sort);

    vec_foreach(fib_entry_index, fib_entry_indicies)
    {
	vlib_cli_output(vm, "%U",
                        format_fib_entry,
                        *fib_entry_index,
                        FIB_ENTRY_FORMAT_BRIEF);
    }

    vec_free(fib_entry_indicies);
}

static void
ip4_fib_table_show_one (ip4_fib_t *fib,
			vlib_main_t * vm,
			ip4_address_t *address,
			u32 mask_len)
{    
    vlib_cli_output(vm, "%U",
                    format_fib_entry,
                    ip4_fib_table_lookup(fib, address, mask_len),
                    FIB_ENTRY_FORMAT_DETAIL);
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

    verbose = 1;
    matching = 0;
    mtrie = 0;
    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	if (unformat (input, "brief") || unformat (input, "summary")
	    || unformat (input, "sum"))
	    verbose = 0;

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
	ip4_fib_t *fib = &fib_table->v4;

	if (table_id >= 0 && table_id != (int)fib->table_id)
	    continue;
	if (fib_index != ~0 && fib_index != (int)fib->index)
	    continue;

	vlib_cli_output (vm, "%U, fib_index %d, flow hash: %U", 
			 format_fib_table_name, fib->index, FIB_PROTOCOL_IP4,
			 fib->index,
			 format_ip_flow_hash_config, fib->flow_hash_config);

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

	if (!matching)
	{
	    ip4_fib_table_show_all(fib, vm);
	}
	else
	{
	    ip4_fib_table_show_one(fib, vm, &matching_address, matching_mask);
	}

	if (mtrie)
	    vlib_cli_output (vm, "%U", format_ip4_fib_mtrie, &fib->mtrie);
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
 * Table 0, fib_index 0, flow hash: src dst sport dport proto
 *      Destination         Packets          Bytes         Adjacency
 * 172.16.2.0/24                      0               0 weight 1, index 5
 *                                                       172.16.2.1/24
 * 172.16.2.1/32                      0               0 weight 1, index 6
 *                                                       172.16.2.1/24
 * Table 7, fib_index 1, flow hash: dst sport dport proto
 *      Destination         Packets          Bytes         Adjacency
 * 172.16.1.0/24                      0               0 weight 1, index 3
 *                                                       172.16.1.1/24
 * 172.16.1.1/32                      1              98 weight 1, index 4
 *                                                       172.16.1.1/24
 * 172.16.1.2/32                      0               0 weight 1, index 7
 *                                                      GigabitEthernet2/0/0
 *                                                      IP4: 02:fe:6a:07:39:6f -> 16:d9:e0:91:79:86
 * @cliexend
 * Example of how to display a single IPv4 FIB table:
 * @cliexstart{show ip fib table 7}
 * Table 7, fib_index 1, flow hash: dst sport dport proto
 *      Destination         Packets          Bytes         Adjacency
 * 172.16.1.0/24                      0               0 weight 1, index 3
 *                                                       172.16.1.1/24
 * 172.16.1.1/32                      1              98 weight 1, index 4
 *                                                       172.16.1.1/24
 * 172.16.1.2/32                      0               0 weight 1, index 7
 *                                                      GigabitEthernet2/0/0
 *                                                      IP4: 02:fe:6a:07:39:6f -> 16:d9:e0:91:79:86
 * @cliexend
 * Example of how to display a summary of all IPv4 FIB tables:
 * @cliexstart{show ip fib summary}
 * Table 0, fib_index 0, flow hash: src dst sport dport proto
 *     Prefix length         Count
 *                   24               1
 *                   32               1
 * Table 7, fib_index 1, flow hash: dst sport dport proto
 *     Prefix length         Count
 *                   24               1
 *                   32               2
 * @cliexend
 ?*/
/* *INDENT-OFF* */
VLIB_CLI_COMMAND (ip4_show_fib_command, static) = {
    .path = "show ip fib",
    .short_help = "show ip fib [mtrie] [summary] [table <n>] [<ip4-addr>] [clear] [include-empty]",
    .function = ip4_show_fib,
};
/* *INDENT-ON* */
