/*
 * mpls_fib.h: The Label/MPLS FIB
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
 * An MPLS_FIB table;
 *
 * The entries in the table are programmed wtih one or more MOIs. These MOIs
 * may result in different forwarding actions for end-of-stack (EOS) and non-EOS
 * packets. Whether the two actions are the same more often than they are
 * different, or vice versa, is a function of the deployment in which the router
 * is used and thus not predictable.
 * The desgin choice to make with an MPLS_FIB table is:
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

#include <vnet/fib/fib_table.h>
#include <vnet/fib/mpls_fib.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/dpo/drop_dpo.h>
#include <vnet/dpo/punt_dpo.h>
#include <vnet/dpo/lookup_dpo.h>
#include <vnet/mpls/mpls.h>

/**
 * All lookups in an MPLS_FIB table must result in a DPO of type load-balance.
 * This is the default result which links to drop
 */
static index_t mpls_fib_drop_dpo_index = INDEX_INVALID;

static inline u32
mpls_fib_entry_mk_key (mpls_label_t label,
		       mpls_eos_bit_t eos)
{
    ASSERT(eos <= 1);
    return (label << 1 | eos);
}

u32
mpls_fib_index_from_table_id (u32 table_id)
{
    mpls_main_t *mm = &mpls_main;
    uword * p;

    p = hash_get (mm->fib_index_by_table_id, table_id);
    if (!p)
	return FIB_NODE_INDEX_INVALID;

    return p[0];
}

static u32
mpls_fib_create_with_table_id (u32 table_id,
                               fib_source_t src)
{
    dpo_id_t dpo = DPO_INVALID;
    fib_table_t *fib_table;
    mpls_eos_bit_t eos;
    mpls_fib_t *mf;
    int i;

    pool_get(mpls_main.fibs, fib_table);
    pool_get_aligned(mpls_main.mpls_fibs, mf, CLIB_CACHE_LINE_BYTES);

    ASSERT((fib_table - mpls_main.fibs) ==
           (mf - mpls_main.mpls_fibs));

    clib_memset(fib_table, 0, sizeof(*fib_table));

    fib_table->ft_proto = FIB_PROTOCOL_MPLS;
    fib_table->ft_index = (fib_table - mpls_main.fibs);

    hash_set (mpls_main.fib_index_by_table_id, table_id, fib_table->ft_index);

    fib_table->ft_table_id = table_id;
    fib_table->ft_flow_hash_config = MPLS_FLOW_HASH_DEFAULT;
    
    fib_table_lock(fib_table->ft_index, FIB_PROTOCOL_MPLS, src);

    if (INDEX_INVALID == mpls_fib_drop_dpo_index)
    {
	mpls_fib_drop_dpo_index = load_balance_create(1, DPO_PROTO_MPLS, 0);
	load_balance_set_bucket(mpls_fib_drop_dpo_index,
				0,
                                drop_dpo_get(DPO_PROTO_MPLS));
    }

    mf->mf_entries = hash_create(0, sizeof(fib_node_index_t));
    for (i = 0; i < MPLS_FIB_DB_SIZE; i++)
    {
	/*
	 * initialise each DPO in the data-path lookup table
	 * to be the special MPLS drop
	 */
	mf->mf_lbs[i] = mpls_fib_drop_dpo_index;
    }

    /*
     * non-default forwarding for the special labels.
     */
    fib_prefix_t prefix = {
	.fp_proto = FIB_PROTOCOL_MPLS,
	.fp_payload_proto = DPO_PROTO_MPLS,
    };

    /*
     * PUNT the router alert, both EOS and non-eos
     */
    prefix.fp_label = MPLS_IETF_ROUTER_ALERT_LABEL;
    FOR_EACH_MPLS_EOS_BIT(eos)
    {
	prefix.fp_eos = eos;
        fib_table_entry_special_dpo_add(fib_table->ft_index,
					&prefix,
					FIB_SOURCE_SPECIAL,
					FIB_ENTRY_FLAG_EXCLUSIVE,
					punt_dpo_get(DPO_PROTO_MPLS));
    }

    /*
     * IPv4 explicit NULL EOS lookup in the interface's IPv4 table
     */
    prefix.fp_label = MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL;
    prefix.fp_payload_proto = DPO_PROTO_IP4;
    prefix.fp_eos = MPLS_EOS;

    lookup_dpo_add_or_lock_w_fib_index(0, // unused
                                       DPO_PROTO_IP4,
                                       LOOKUP_UNICAST,
                                       LOOKUP_INPUT_DST_ADDR,
                                       LOOKUP_TABLE_FROM_INPUT_INTERFACE,
                                       &dpo);
    fib_table_entry_special_dpo_add(fib_table->ft_index,
				    &prefix,
				    FIB_SOURCE_SPECIAL,
				    FIB_ENTRY_FLAG_EXCLUSIVE,
                                    &dpo);

    prefix.fp_payload_proto = DPO_PROTO_MPLS;
    prefix.fp_eos = MPLS_NON_EOS;

    lookup_dpo_add_or_lock_w_fib_index(0, //unsued
                                       DPO_PROTO_MPLS,
                                       LOOKUP_UNICAST,
                                       LOOKUP_INPUT_DST_ADDR,
                                       LOOKUP_TABLE_FROM_INPUT_INTERFACE,
                                       &dpo);
    fib_table_entry_special_dpo_add(fib_table->ft_index,
				    &prefix,
				    FIB_SOURCE_SPECIAL,
				    FIB_ENTRY_FLAG_EXCLUSIVE,
                                    &dpo);

    /*
     * IPv6 explicit NULL EOS lookup in the interface's IPv6 table
     */
    prefix.fp_label = MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL;
    prefix.fp_payload_proto = DPO_PROTO_IP6;
    prefix.fp_eos = MPLS_EOS;

    lookup_dpo_add_or_lock_w_fib_index(0, //unused
                                       DPO_PROTO_IP6,
                                       LOOKUP_UNICAST,
                                       LOOKUP_INPUT_DST_ADDR,
                                       LOOKUP_TABLE_FROM_INPUT_INTERFACE,
                                       &dpo);
    fib_table_entry_special_dpo_add(fib_table->ft_index,
				    &prefix,
				    FIB_SOURCE_SPECIAL,
				    FIB_ENTRY_FLAG_EXCLUSIVE,
                                    &dpo);

    prefix.fp_payload_proto = DPO_PROTO_MPLS;
    prefix.fp_eos = MPLS_NON_EOS;
    lookup_dpo_add_or_lock_w_fib_index(0, // unsued
                                       DPO_PROTO_MPLS,
                                       LOOKUP_UNICAST,
                                       LOOKUP_INPUT_DST_ADDR,
                                       LOOKUP_TABLE_FROM_INPUT_INTERFACE,
                                       &dpo);
    fib_table_entry_special_dpo_add(fib_table->ft_index,
				    &prefix,
				    FIB_SOURCE_SPECIAL,
				    FIB_ENTRY_FLAG_EXCLUSIVE,
                                    &dpo);

    return (fib_table->ft_index);
}

u32
mpls_fib_table_find_or_create_and_lock (u32 table_id,
                                        fib_source_t src)
{
    u32 index;

    index = mpls_fib_index_from_table_id(table_id);
    if (~0 == index)
	return mpls_fib_create_with_table_id(table_id, src);

    fib_table_lock(index, FIB_PROTOCOL_MPLS, src);

    return (index);
}
u32
mpls_fib_table_create_and_lock (fib_source_t src)
{
    return (mpls_fib_create_with_table_id(~0, src));
}

void
mpls_fib_table_destroy (u32 fib_index)
{
    fib_table_t *fib_table = pool_elt_at_index(mpls_main.fibs, fib_index);
    mpls_fib_t *mf = pool_elt_at_index(mpls_main.mpls_fibs, fib_index);
    fib_prefix_t prefix = {
	.fp_proto = FIB_PROTOCOL_MPLS,
    };
    mpls_label_t special_labels[] = {
	MPLS_IETF_ROUTER_ALERT_LABEL,
	MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL,
	MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL,
    };
    mpls_eos_bit_t eos;
    u32 ii;

    for (ii = 0; ii < ARRAY_LEN(special_labels); ii++)
    {
	FOR_EACH_MPLS_EOS_BIT(eos)
	{
	    prefix.fp_label = special_labels[ii];
	    prefix.fp_eos   = eos;

	    fib_table_entry_delete(fib_table->ft_index,
				   &prefix,
				   FIB_SOURCE_SPECIAL);
	}
    }
    if (~0 != fib_table->ft_table_id)
    {
	hash_unset(mpls_main.fib_index_by_table_id,
		   fib_table->ft_table_id);
    }
    hash_free(mf->mf_entries);

    pool_put(mpls_main.mpls_fibs, mf);
    pool_put(mpls_main.fibs, fib_table);
}

fib_node_index_t
mpls_fib_table_lookup (const mpls_fib_t *mf,
		       mpls_label_t label,
		       mpls_eos_bit_t eos)
{
    uword *p;

    p = hash_get(mf->mf_entries, mpls_fib_entry_mk_key(label, eos));

    if (NULL == p)
	return FIB_NODE_INDEX_INVALID;

    return p[0];
}

void
mpls_fib_table_entry_insert (mpls_fib_t *mf,
			     mpls_label_t label,
			     mpls_eos_bit_t eos,
			     fib_node_index_t lfei)
{
    hash_set(mf->mf_entries, mpls_fib_entry_mk_key(label, eos), lfei);
}

void
mpls_fib_table_entry_remove (mpls_fib_t *mf,
			     mpls_label_t label,
			     mpls_eos_bit_t eos)
{
    hash_unset(mf->mf_entries, mpls_fib_entry_mk_key(label, eos));
}

void
mpls_fib_forwarding_table_update (mpls_fib_t *mf,
				  mpls_label_t label,
				  mpls_eos_bit_t eos,
				  const dpo_id_t *dpo)
{
    mpls_label_t key;

    ASSERT((DPO_LOAD_BALANCE == dpo->dpoi_type) ||
           (DPO_REPLICATE == dpo->dpoi_type));
    if (CLIB_DEBUG > 0)
    {
        if (DPO_REPLICATE == dpo->dpoi_type)
            ASSERT(dpo->dpoi_index & MPLS_IS_REPLICATE);
        if (DPO_LOAD_BALANCE == dpo->dpoi_type)
            ASSERT(!(dpo->dpoi_index & MPLS_IS_REPLICATE));
    }
    key = mpls_fib_entry_mk_key(label, eos);

    mf->mf_lbs[key] = dpo->dpoi_index;
}

void
mpls_fib_forwarding_table_reset (mpls_fib_t *mf,
				 mpls_label_t label,
				 mpls_eos_bit_t eos)
{
    mpls_label_t key;

    key = mpls_fib_entry_mk_key(label, eos);

    mf->mf_lbs[key] = mpls_fib_drop_dpo_index;
}

void
mpls_fib_table_walk (mpls_fib_t *mpls_fib,
                     fib_table_walk_fn_t fn,
                     void *ctx)
{
    fib_node_index_t lfei;
    mpls_label_t key;

    hash_foreach(key, lfei, mpls_fib->mf_entries,
    ({
	fn(lfei, ctx);
    }));
}

u8 *
format_mpls_fib_table_memory (u8 * s, va_list * args)
{
    u64 n_tables, mem;

    n_tables = pool_elts(mpls_main.fibs);
    mem = n_tables * sizeof(mpls_fib_t);
    s = format(s, "%=30s %=6ld %=8ld\n", "MPLS", n_tables, mem);

    return (s);
}

static void
mpls_fib_table_show_all (const mpls_fib_t *mpls_fib,
			 vlib_main_t * vm)
{
    fib_node_index_t lfei, *lfeip, *lfeis = NULL;
    mpls_label_t key;

    hash_foreach(key, lfei, mpls_fib->mf_entries,
    ({
	vec_add1(lfeis, lfei);
    }));

    vec_sort_with_function(lfeis, fib_entry_cmp_for_sort);

    vec_foreach(lfeip, lfeis)
    {
	vlib_cli_output (vm, "%U",
			 format_fib_entry, *lfeip,
			 FIB_ENTRY_FORMAT_DETAIL);
    }
    vec_free(lfeis);
}

static void
mpls_fib_table_show_one (const mpls_fib_t *mpls_fib,
			 mpls_label_t label,
			 vlib_main_t * vm)
{    
    fib_node_index_t lfei;
    mpls_eos_bit_t eos;

    FOR_EACH_MPLS_EOS_BIT(eos)
    {    
	lfei = mpls_fib_table_lookup(mpls_fib, label, eos);

	if (FIB_NODE_INDEX_INVALID != lfei)
	{
	    vlib_cli_output (vm, "%U", 
			     format_fib_entry, lfei, FIB_ENTRY_FORMAT_DETAIL);
	}
    }
}

static clib_error_t *
mpls_fib_show (vlib_main_t * vm,
	       unformat_input_t * input,
	       vlib_cli_command_t * cmd)
{
    fib_table_t * fib_table;
    mpls_label_t label;
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

    pool_foreach (fib_table, mpls_main.fibs,
    ({
        fib_source_t source;
        u8 *s = NULL;

	if (table_id >= 0 && table_id != fib_table->ft_table_id)
	    continue;

	s = format (s, "%v, fib_index:%d locks:[",
                    fib_table->ft_desc, mpls_main.fibs - fib_table);
	FOR_EACH_FIB_SOURCE(source)
        {
            if (0 != fib_table->ft_locks[source])
            {
                s = format(s, "%U:%d, ",
                           format_fib_source, source,
                           fib_table->ft_locks[source]);
            }
        }
        vlib_cli_output (vm, "%v]", s);

	if (MPLS_LABEL_INVALID == label)
	{
	    mpls_fib_table_show_all(mpls_fib_get(fib_table->ft_index), vm);
	}
	else
	{
	    mpls_fib_table_show_one(mpls_fib_get(fib_table->ft_index), label, vm);
	}
    }));

    return 0;
}

VLIB_CLI_COMMAND (mpls_fib_show_command, static) = {
    .path = "show mpls fib",
    .short_help = "show mpls fib [summary] [table <n>]",
    .function = mpls_fib_show,
};
