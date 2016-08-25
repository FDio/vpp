/*
 * lfib.h: The Label/MPLS FIB
 *
 * Copyright (c) 2012 Cisco and/or its affiliates.
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
/**
 * An LFIB table;
 *
 * The entries in the table are programmed wtih one or more MOIs. These MOIs
 * may result in different forwarding actions for end-of-stack (EOS) and non-EOS
 * packets. Whether the two actions are the same more often than they are
 * different, or vice versa, is a function of the deployment in which the router
 * is used and thus not predictable.
 * The desgin choice to make with an LFIB table is:
 *  1 - 20 bit key: label only.
 *      When the EOS and non-EOS actions differ the result is a 'EOS-choice' object.
 *  2 - 21 bit key: label and EOS-bit.
 *      The result is then the specific action based on EOS-bit.
 *
 * 20 bit key:
 *   Advantages:
 *    - lower memory overhead, since there are few DB entries.
 *   Disadvantages:
 *    - slower DP performance in the case the chains differ, as more objects are
 *      encounterd in the switch path
 *
 * 21 bit key:
 *   Advantages:
 *    - faster DP performance
 *   Disadvantages
 *    - increased memory footprint.
 *
 * Switching between schemes based on observed/measured action similarity is not
 * considered on the grounds of complexity and flip-flopping.
 *
 * VPP mantra - favour performance over memory. We choose a 21 bit key.  
 */

#include <vnet/lfib/lfib.h>
#include <vnet/lfib/lfib_table.h>
#include <vnet/lfib/lfib_entry.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/mpls/mpls_types.h>

/**
 * All lookups in an LFIB table must result in a DPO of type load-balance.
 * This is the default result which links to drop
 */
static index_t lfib_drop_dpo_index = INDEX_INVALID;

lfib_table_t*
lfib_table_create (void)
{
    lfib_table_t *lft;
    int i;

    if (INDEX_INVALID == lfib_drop_dpo_index)
    {
	lfib_drop_dpo_index = load_balance_create(1, DPO_PROTO_MPLS, 0);
	load_balance_set_bucket(lfib_drop_dpo_index,
				0,
                                drop_dpo_get(DPO_PROTO_MPLS));
    }

    lft = clib_mem_alloc_aligned(sizeof(lfib_table_t),
				 CLIB_CACHE_LINE_BYTES);

    lft->lft_entries = hash_create(0, sizeof(fib_node_index_t));
    for (i = 0; i < LFIB_DB_SIZE; i++)
    {
	/*
	 * initialise each DPO in the data-path lookup table
	 * to be the special MPLS drop
	 */
	lft->lft_lbs[i] = lfib_drop_dpo_index;
    }

    return (lft);
}

void
lfib_table_delete (lfib_table_t *lft)
{
    hash_delete(lft->lft_entries);
    clib_mem_free(lft);
}

static fib_node_index_t
lfib_table_entry_lookup (lfib_table_t *lft,
			 mpls_label_t label,
			 mpls_eos_bit_t eos)
{
    uword *p;

    p = hash_get(lft->lft_entries, lfib_entry_mk_key(label, eos));

    if (NULL == p)
	return FIB_NODE_INDEX_INVALID;

    return p[0];
}

fib_node_index_t
lfib_table_lookup (fib_node_index_t lfib_index,
		   mpls_label_t label,
		   mpls_eos_bit_t eos)
{
    lfib_t *lfib;

    lfib = lfib_get(lfib_index);

    if (NULL != lfib)
    {
	return (lfib_table_entry_lookup(lfib->lf_table, label, eos));
    }
    return (FIB_NODE_INDEX_INVALID);
}


static void
lfib_table_entry_insert (lfib_table_t *lft,
			 mpls_label_t label,
			 mpls_eos_bit_t eos,
			 fib_node_index_t lfei)
{
    lfib_entry_lock(lfei);

    hash_set(lft->lft_entries, lfib_entry_mk_key(label, eos), lfei);
}

static void
lfib_table_entry_delete_i (lfib_table_t *lft,
			   mpls_label_t key,
			   fib_node_index_t lfei)
{
    hash_unset(lft->lft_entries, key);
    lfib_entry_unlock(lfei);
}


fib_node_index_t
lfib_table_entry_add_from_ip_fib_entry (u32 table_id,
					mpls_label_t label,
					mpls_eos_bit_t eos,
					fib_node_index_t fib_entry_index)
{
    fib_node_index_t lfe;
    lfib_t *lfib;

    lfib = lfib_find(table_id);

    if (NULL == lfib)
        return (FIB_NODE_INDEX_INVALID);;

    lfe = lfib_table_entry_lookup(lfib->lf_table, label, eos);

    /*
     * we don't expect a clash in the table when adding a special
     */
    ASSERT(FIB_NODE_INDEX_INVALID == lfe);

    lfe = lfib_entry_create_from_ip_fib_entry(lfib->lf_index, label,
					      eos, fib_entry_index);
    lfib_table_entry_insert(lfib->lf_table, label, eos, lfe);

    return (lfe);
}

fib_node_index_t
lfib_table_entry_path_add (u32 lfib_index,
			   mpls_label_t label,
                           mpls_eos_bit_t eos,
                           fib_protocol_t next_hop_proto,
			   const ip46_address_t *next_hop,
			   u32 next_hop_sw_if_index,
			   u32 next_hop_fib_index,
			   u32 next_hop_weight,
                           mpls_label_t next_hop_label,
			   fib_route_path_flags_t pf)
{
    fib_route_path_t path = {
	.frp_addr = (NULL == next_hop? zero_addr : *next_hop),
	.frp_sw_if_index = next_hop_sw_if_index,
	.frp_fib_index = next_hop_fib_index,
	.frp_weight = next_hop_weight,
	.frp_flags = pf,
	.frp_label = next_hop_label,
        .frp_proto = next_hop_proto,
    };
    fib_route_path_t *paths = NULL;
    fib_node_index_t lfe;

    vec_add1(paths, path);

    lfe = lfib_table_entry_path_add2(lfib_index, label, eos, paths);

    vec_free(paths);

    return (lfe);
}

fib_node_index_t
lfib_table_entry_special_create (u32 lfib_index,
                                 mpls_label_t label,
                                 mpls_eos_bit_t eos,
                                 const dpo_id_t *dpo)
{
    fib_node_index_t lfe;
    lfib_t *lfib;

    lfib = lfib_get(lfib_index);
    lfe = lfib_table_entry_lookup(lfib->lf_table, label, eos);

    /*
     * we don't expect a clash in the table when adding a special
     */
    ASSERT(FIB_NODE_INDEX_INVALID == lfe);

    lfe = lfib_entry_special_create(lfib->lf_index, label, eos, dpo);
    lfib_table_entry_insert(lfib->lf_table, label, eos, lfe);

    return (lfe);
}


void
lfib_table_entry_delete (fib_node_index_t lfei)
{
    u32 lfib_index;

    lfib_index = lfib_entry_get_fib_index(lfei);

    lfib_table_entry_delete_i(lfib_get(lfib_index)->lf_table,
			      lfib_entry_get_key(lfei),
			      lfei);
}

fib_node_index_t
lfib_table_entry_path_add2 (u32 lfib_index,
                            mpls_label_t label,
                            mpls_eos_bit_t eos,
                            const fib_route_path_t *rpaths)
{
    fib_node_index_t lfe;
    lfib_t *lfib;

    lfib = lfib_get(lfib_index);
    lfe = lfib_table_entry_lookup(lfib->lf_table, label, eos);

    if (FIB_NODE_INDEX_INVALID == lfe)
    {
        lfe = lfib_entry_create(lfib->lf_index, label, eos, rpaths);        
        lfib_table_entry_insert(lfib->lf_table, label, eos, lfe);
    }
    else
    {
        lfib_entry_path_add2(lfe, rpaths);
    }

    return (lfe);
}

void
lfib_forwarding_table_update (u32 index,
			      mpls_label_t label,
			      mpls_eos_bit_t eos,
			      const dpo_id_t *dpo)
{
    mpls_label_t key;
    lfib_t *lfib;

    lfib = lfib_get(index);

    ASSERT(DPO_LOAD_BALANCE == dpo->dpoi_type);

    key = lfib_entry_mk_key(label, eos);

    lfib->lf_table->lft_lbs[key] = dpo->dpoi_index;
}

void
lfib_forwarding_table_reset (u32 index,
                             mpls_label_t label,
                             mpls_eos_bit_t eos)
{
    mpls_label_t key;
    lfib_t *lfib;

    lfib = lfib_get(index);
    key = lfib_entry_mk_key(label, eos);

    lfib->lf_table->lft_lbs[key] = lfib_drop_dpo_index;
}

static void
lfib_table_show_all (lfib_t *lfib,
		     vlib_main_t * vm)
{
    fib_node_index_t lfei;
    mpls_label_t key;

    hash_foreach(key, lfei, lfib->lf_table->lft_entries,
    ({
	lfib_entry_show(lfei,
			LFIB_ENTRY_FORMAT_BRIEF,
			vm);
    }));
}

static void
lfib_table_show_one (lfib_t *lfib,
		     mpls_label_t label,
		     vlib_main_t * vm)
{    
    fib_node_index_t lfei;
    mpls_eos_bit_t eos;

    FOR_EACH_MPLS_EOS_BIT(eos)
    {    
	lfei = lfib_table_entry_lookup(lfib->lf_table, label, eos);

	if (FIB_NODE_INDEX_INVALID != lfei)
	{
	    lfib_entry_show(lfei,
			    LFIB_ENTRY_FORMAT_DETAIL,
			    vm);
	}
    }
}

static clib_error_t *
lfib_show (vlib_main_t * vm,
	   unformat_input_t * input,
	   vlib_cli_command_t * cmd)
{
    mpls_label_t label;
    lfib_t * lfib;
    int table_id;

    table_id = -1;
    label = MPLS_LABEL_INVALID;

    while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
	/* if (unformat (input, "brief") || unformat (input, "summary") */
	/*     || unformat (input, "sum")) */
	/*     verbose = 0; */

	if (unformat (input, "%d", &label))
	    continue;
	else if (unformat (input, "table %d", &table_id))
	    ;
	else
	    break;
    }

    pool_foreach (lfib, lfib_main.lfibs,
    ({
	if (table_id >= 0 && table_id != (int)lfib->lf_table_id)
	    continue;

	vlib_cli_output (vm, "Table %d, fib_index %d locks:%d", 
			 lfib->lf_table_id, lfib->lf_index, lfib->lf_locks);

	if (MPLS_LABEL_INVALID == label)
	{
	    lfib_table_show_all(lfib, vm);
	}
	else
	{
	    lfib_table_show_one(lfib, label, vm);
	}
    }));

    return 0;
}

VLIB_CLI_COMMAND (lfib_show_command, static) = {
    .path = "show mpls lfib",
    .short_help = "show mpls fib [summary] [table <n>]",
    .function = lfib_show,
};
