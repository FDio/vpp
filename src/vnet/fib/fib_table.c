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

#include <vnet/fib/fib_table.h>
#include <vnet/fib/fib_entry_cover.h>
#include <vnet/fib/fib_internal.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/fib/ip6_fib.h>
#include <vnet/fib/mpls_fib.h>

fib_table_t *
fib_table_get (fib_node_index_t index,
	       fib_protocol_t proto)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	return (pool_elt_at_index(ip4_main.fibs, index));
    case FIB_PROTOCOL_IP6:
	return (pool_elt_at_index(ip6_main.fibs, index));
    case FIB_PROTOCOL_MPLS:
	return (pool_elt_at_index(mpls_main.fibs, index));
    }
    ASSERT(0);
    return (NULL);
}

static inline fib_node_index_t
fib_table_lookup_i (fib_table_t *fib_table,
		    const fib_prefix_t *prefix)
{
    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	return (ip4_fib_table_lookup(&fib_table->v4,
				     &prefix->fp_addr.ip4,
				     prefix->fp_len));
    case FIB_PROTOCOL_IP6:
	return (ip6_fib_table_lookup(fib_table->ft_index,
				     &prefix->fp_addr.ip6,
				     prefix->fp_len));
    case FIB_PROTOCOL_MPLS:
	return (mpls_fib_table_lookup(&fib_table->mpls,
				      prefix->fp_label,
				      prefix->fp_eos));
    }
    return (FIB_NODE_INDEX_INVALID);
}

fib_node_index_t
fib_table_lookup (u32 fib_index,
		  const fib_prefix_t *prefix)
{
    return (fib_table_lookup_i(fib_table_get(fib_index, prefix->fp_proto), prefix));
}

static inline fib_node_index_t
fib_table_lookup_exact_match_i (const fib_table_t *fib_table,
				const fib_prefix_t *prefix)
{
    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	return (ip4_fib_table_lookup_exact_match(&fib_table->v4,
						 &prefix->fp_addr.ip4,
						 prefix->fp_len));
    case FIB_PROTOCOL_IP6:
	return (ip6_fib_table_lookup_exact_match(fib_table->ft_index,
						 &prefix->fp_addr.ip6,
						 prefix->fp_len));
    case FIB_PROTOCOL_MPLS:
	return (mpls_fib_table_lookup(&fib_table->mpls,
				      prefix->fp_label,
				      prefix->fp_eos));
    }
    return (FIB_NODE_INDEX_INVALID);
}

fib_node_index_t
fib_table_lookup_exact_match (u32 fib_index,
			      const fib_prefix_t *prefix)
{
    return (fib_table_lookup_exact_match_i(fib_table_get(fib_index,
							 prefix->fp_proto),
					   prefix));
}

static fib_node_index_t
fib_table_get_less_specific_i (fib_table_t *fib_table,
			       const fib_prefix_t *prefix)
{
    fib_prefix_t pfx;

    pfx = *prefix;

    if (FIB_PROTOCOL_MPLS == pfx.fp_proto)
    {
	return (FIB_NODE_INDEX_INVALID);
    }

    /*
     * in the absence of a tree structure for the table that allows for an O(1)
     * parent get, a cheeky way to find the cover is to LPM for the prefix with
     * mask-1.
     * there should always be a cover, though it may be the default route. the
     * default route's cover is the default route.
     */
    if (pfx.fp_len != 0) {
	pfx.fp_len -= 1;
    }

    return (fib_table_lookup_i(fib_table, &pfx));    
}

fib_node_index_t
fib_table_get_less_specific (u32 fib_index,
			     const fib_prefix_t *prefix)
{
    return (fib_table_get_less_specific_i(fib_table_get(fib_index,
							prefix->fp_proto),
					  prefix));
}

static void
fib_table_entry_remove (fib_table_t *fib_table,
			const fib_prefix_t *prefix,
			fib_node_index_t fib_entry_index)
{
    vlib_smp_unsafe_warning();

    fib_table->ft_total_route_counts--;

    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	ip4_fib_table_entry_remove(&fib_table->v4,
				   &prefix->fp_addr.ip4,
				   prefix->fp_len);
	break;
    case FIB_PROTOCOL_IP6:
	ip6_fib_table_entry_remove(fib_table->ft_index,
				   &prefix->fp_addr.ip6,
				   prefix->fp_len);
	break;
    case FIB_PROTOCOL_MPLS:
	mpls_fib_table_entry_remove(&fib_table->mpls,
				    prefix->fp_label,
				    prefix->fp_eos);
	break;
    }

    fib_entry_unlock(fib_entry_index);
}

static void
fib_table_post_insert_actions (fib_table_t *fib_table,
			       const fib_prefix_t *prefix,
			       fib_node_index_t fib_entry_index)
{
    fib_node_index_t fib_entry_cover_index;

    /*
     * no cover relationships in the MPLS FIB
     */
    if (FIB_PROTOCOL_MPLS == prefix->fp_proto)
	return;

    /*
     * find and inform the covering entry that a new more specific
     * has been inserted beneath it
     */
    fib_entry_cover_index = fib_table_get_less_specific_i(fib_table, prefix);
    /*
     * the indicies are the same when the default route is first added
     */
    if (fib_entry_cover_index != fib_entry_index)
    {
	fib_entry_cover_change_notify(fib_entry_cover_index,
				      fib_entry_index);
    }
}

static void
fib_table_entry_insert (fib_table_t *fib_table,
			const fib_prefix_t *prefix,
			fib_node_index_t fib_entry_index)
{
    vlib_smp_unsafe_warning();

    fib_entry_lock(fib_entry_index);
    fib_table->ft_total_route_counts++;

    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	ip4_fib_table_entry_insert(&fib_table->v4,
				   &prefix->fp_addr.ip4,
				   prefix->fp_len,
				   fib_entry_index);
	break;
    case FIB_PROTOCOL_IP6:
	ip6_fib_table_entry_insert(fib_table->ft_index,
				   &prefix->fp_addr.ip6,
				   prefix->fp_len,
				   fib_entry_index);
	break;
    case FIB_PROTOCOL_MPLS:
	mpls_fib_table_entry_insert(&fib_table->mpls,
				    prefix->fp_label,
				    prefix->fp_eos,
				    fib_entry_index);
	break;
    }

    fib_table_post_insert_actions(fib_table, prefix, fib_entry_index);
}

void
fib_table_fwding_dpo_update (u32 fib_index,
			     const fib_prefix_t *prefix,
			     const dpo_id_t *dpo)
{
    vlib_smp_unsafe_warning();

    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	return (ip4_fib_table_fwding_dpo_update(ip4_fib_get(fib_index),
						&prefix->fp_addr.ip4,
						prefix->fp_len,
						dpo));
    case FIB_PROTOCOL_IP6:
	return (ip6_fib_table_fwding_dpo_update(fib_index,
						&prefix->fp_addr.ip6,
						prefix->fp_len,
						dpo));
    case FIB_PROTOCOL_MPLS:
	return (mpls_fib_forwarding_table_update(mpls_fib_get(fib_index),
						 prefix->fp_label,
						 prefix->fp_eos,
						 dpo));
    }
}

void
fib_table_fwding_dpo_remove (u32 fib_index,
			     const fib_prefix_t *prefix,
			     const dpo_id_t *dpo)
{
    vlib_smp_unsafe_warning();

    switch (prefix->fp_proto)
    {
    case FIB_PROTOCOL_IP4:
	return (ip4_fib_table_fwding_dpo_remove(ip4_fib_get(fib_index),
						&prefix->fp_addr.ip4,
						prefix->fp_len,
						dpo));
    case FIB_PROTOCOL_IP6:
	return (ip6_fib_table_fwding_dpo_remove(fib_index,
						&prefix->fp_addr.ip6,
						prefix->fp_len,
						dpo));
    case FIB_PROTOCOL_MPLS:
	return (mpls_fib_forwarding_table_reset(mpls_fib_get(fib_index),
						prefix->fp_label,
						prefix->fp_eos));
    }
}


fib_node_index_t
fib_table_entry_special_dpo_add (u32 fib_index,
                                 const fib_prefix_t *prefix,
                                 fib_source_t source,
                                 fib_entry_flag_t flags,
                                 const dpo_id_t *dpo)
{
    fib_node_index_t fib_entry_index;
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, prefix->fp_proto);
    fib_entry_index = fib_table_lookup_exact_match_i(fib_table, prefix);

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
    {
	fib_entry_index = fib_entry_create_special(fib_index, prefix,
						   source, flags,
						   dpo);

	fib_table_entry_insert(fib_table, prefix, fib_entry_index);
        fib_table->ft_src_route_counts[source]++;
    }
    else
    {
        int was_sourced;

        was_sourced = fib_entry_is_sourced(fib_entry_index, source);
	fib_entry_special_add(fib_entry_index, source, flags, dpo);

        if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
        {
            fib_table->ft_src_route_counts[source]++;
        }
    }


    return (fib_entry_index);
}

fib_node_index_t
fib_table_entry_special_dpo_update (u32 fib_index,
				    const fib_prefix_t *prefix,
				    fib_source_t source,
				    fib_entry_flag_t flags,
				    const dpo_id_t *dpo)
{
    fib_node_index_t fib_entry_index;
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, prefix->fp_proto);
    fib_entry_index = fib_table_lookup_exact_match_i(fib_table, prefix);

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
    {
	fib_entry_index = fib_entry_create_special(fib_index, prefix,
						   source, flags,
						   dpo);

	fib_table_entry_insert(fib_table, prefix, fib_entry_index);
        fib_table->ft_src_route_counts[source]++;
    }
    else
    {
        int was_sourced;

        was_sourced = fib_entry_is_sourced(fib_entry_index, source);

	if (was_sourced)
	    fib_entry_special_update(fib_entry_index, source, flags, dpo);
	else
	    fib_entry_special_add(fib_entry_index, source, flags, dpo);

        if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
        {
            fib_table->ft_src_route_counts[source]++;
        }
    }

    return (fib_entry_index);
}

fib_node_index_t
fib_table_entry_special_add (u32 fib_index,
			     const fib_prefix_t *prefix,
			     fib_source_t source,
			     fib_entry_flag_t flags)
{
    fib_node_index_t fib_entry_index;
    dpo_id_t tmp_dpo = DPO_INVALID;

    dpo_copy(&tmp_dpo, drop_dpo_get(fib_proto_to_dpo(prefix->fp_proto)));
 
    fib_entry_index = fib_table_entry_special_dpo_add(fib_index, prefix, source,
                                                      flags, &tmp_dpo);

    dpo_unlock(&tmp_dpo);

    return (fib_entry_index);
}

void
fib_table_entry_special_remove (u32 fib_index,
				const fib_prefix_t *prefix,
				fib_source_t source)
{
    /*
     * 1 is it present
     *   yes => remove source
     *    2 - is it still sourced?
     *      no => cover walk
     */
    fib_node_index_t fib_entry_index;
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, prefix->fp_proto);
    fib_entry_index = fib_table_lookup_exact_match_i(fib_table, prefix);

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
    {
	/*
	 * removing an etry that does not exist. i'll allow it.
	 */
    }
    else
    {
	fib_entry_src_flag_t src_flag;
        int was_sourced;

	/*
	 * don't nobody go nowhere
	 */
	fib_entry_lock(fib_entry_index);
        was_sourced = fib_entry_is_sourced(fib_entry_index, source);

	src_flag = fib_entry_special_remove(fib_entry_index, source);

	if (!(FIB_ENTRY_SRC_FLAG_ADDED & src_flag))
	{
	    /*
	     * last source gone. remove from the table
	     */
	    fib_table_entry_remove(fib_table, prefix, fib_entry_index);

	    /*
	     * now the entry is no longer in the table, we can
	     * inform the entries that it covers to re-calculate their cover
	     */
	    fib_entry_cover_change_notify(fib_entry_index,
					  FIB_NODE_INDEX_INVALID);
	}
	/*
	 * else
	 *   still has sources, leave it be.
	 */
        if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
        {
            fib_table->ft_src_route_counts[source]--;
        }

	fib_entry_unlock(fib_entry_index);
    }
}

/**
 * fib_table_route_path_fixup
 *
 * Convert attached hosts to attached next-hops.
 * 
 * This special case is required because an attached path will link to a
 * glean, and the FIB entry will have the interface or API/CLI source. When
 * the ARP/ND process is completes then that source (which will provide a
 * complete adjacency) will be lower priority and so the FIB entry will
 * remain linked to a glean and traffic will never reach the hosts. For
 * an ATTAHCED_HOST path we can link the path directly to the [incomplete]
 * adjacency.
 */
static void
fib_table_route_path_fixup (const fib_prefix_t *prefix,
			    fib_route_path_t *path)
{
    if (fib_prefix_is_host(prefix) &&
	ip46_address_is_zero(&path->frp_addr) &&
	path->frp_sw_if_index != ~0)
    {
	path->frp_addr = prefix->fp_addr;
        path->frp_flags |= FIB_ROUTE_PATH_ATTACHED;
    }
}		  

fib_node_index_t
fib_table_entry_path_add (u32 fib_index,
			  const fib_prefix_t *prefix,
			  fib_source_t source,
			  fib_entry_flag_t flags,
			  fib_protocol_t next_hop_proto,
			  const ip46_address_t *next_hop,
			  u32 next_hop_sw_if_index,
			  u32 next_hop_fib_index,
			  u32 next_hop_weight,
			  mpls_label_t *next_hop_labels,
			  fib_route_path_flags_t path_flags)
{
    fib_route_path_t path = {
	.frp_proto = next_hop_proto,
	.frp_addr = (NULL == next_hop? zero_addr : *next_hop),
	.frp_sw_if_index = next_hop_sw_if_index,
	.frp_fib_index = next_hop_fib_index,
	.frp_weight = next_hop_weight,
	.frp_flags = path_flags,
	.frp_label_stack = next_hop_labels,
    };
    fib_node_index_t fib_entry_index;
    fib_route_path_t *paths = NULL;

    vec_add1(paths, path);

    fib_entry_index = fib_table_entry_path_add2(fib_index, prefix,
						source, flags, paths);

    vec_free(paths);
    return (fib_entry_index);
}

fib_node_index_t
fib_table_entry_path_add2 (u32 fib_index,
			   const fib_prefix_t *prefix,
			   fib_source_t source,
			   fib_entry_flag_t flags,
			   fib_route_path_t *rpath)
{
    fib_node_index_t fib_entry_index;
    fib_table_t *fib_table;
    u32 ii;

    fib_table = fib_table_get(fib_index, prefix->fp_proto);
    fib_entry_index = fib_table_lookup_exact_match_i(fib_table, prefix);

    for (ii = 0; ii < vec_len(rpath); ii++)
    {
	fib_table_route_path_fixup(prefix, &rpath[ii]);
    }

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
    {
	fib_entry_index = fib_entry_create(fib_index, prefix,
					   source, flags,
					   rpath);

	fib_table_entry_insert(fib_table, prefix, fib_entry_index);
        fib_table->ft_src_route_counts[source]++;
    }
    else
    {
        int was_sourced;

        was_sourced = fib_entry_is_sourced(fib_entry_index, source);
	fib_entry_path_add(fib_entry_index, source, flags, rpath);;

        if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
        {
            fib_table->ft_src_route_counts[source]++;
        }
    }

    return (fib_entry_index);
}

void
fib_table_entry_path_remove2 (u32 fib_index,
			      const fib_prefix_t *prefix,
			      fib_source_t source,
			      fib_route_path_t *rpath)
{
    /*
     * 1 is it present
     *   yes => remove source
     *    2 - is it still sourced?
     *      no => cover walk
     */
    fib_node_index_t fib_entry_index;
    fib_table_t *fib_table;
    u32 ii;

    fib_table = fib_table_get(fib_index, prefix->fp_proto);
    fib_entry_index = fib_table_lookup_exact_match_i(fib_table, prefix);

    for (ii = 0; ii < vec_len(rpath); ii++)
    {
	fib_table_route_path_fixup(prefix, &rpath[ii]);
    }

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
    {
	/*
	 * removing an etry that does not exist. i'll allow it.
	 */
    }
    else
    {
	fib_entry_src_flag_t src_flag;
        int was_sourced;

	/*
	 * don't nobody go nowhere
	 */
	fib_entry_lock(fib_entry_index);
        was_sourced = fib_entry_is_sourced(fib_entry_index, source);

	src_flag = fib_entry_path_remove(fib_entry_index, source, rpath);

	if (!(FIB_ENTRY_SRC_FLAG_ADDED & src_flag))
	{
	    /*
	     * last source gone. remove from the table
	     */
	    fib_table_entry_remove(fib_table, prefix, fib_entry_index);

	    /*
	     * now the entry is no longer in the table, we can
	     * inform the entries that it covers to re-calculate their cover
	     */
	    fib_entry_cover_change_notify(fib_entry_index,
					  FIB_NODE_INDEX_INVALID);
	}
	/*
	 * else
	 *   still has sources, leave it be.
	 */
        if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
        {
            fib_table->ft_src_route_counts[source]--;
        }

	fib_entry_unlock(fib_entry_index);
    }
}

void
fib_table_entry_path_remove (u32 fib_index,
			     const fib_prefix_t *prefix,
			     fib_source_t source,
			     fib_protocol_t next_hop_proto,
			     const ip46_address_t *next_hop,
			     u32 next_hop_sw_if_index,
			     u32 next_hop_fib_index,
			     u32 next_hop_weight,
			     fib_route_path_flags_t path_flags)
{
    /*
     * 1 is it present
     *   yes => remove source
     *    2 - is it still sourced?
     *      no => cover walk
     */
    fib_route_path_t path = {
	.frp_proto = next_hop_proto,
	.frp_addr = (NULL == next_hop? zero_addr : *next_hop),
	.frp_sw_if_index = next_hop_sw_if_index,
	.frp_fib_index = next_hop_fib_index,
	.frp_weight = next_hop_weight,
	.frp_flags = path_flags,
    };
    fib_route_path_t *paths = NULL;

    fib_table_route_path_fixup(prefix, &path);
    vec_add1(paths, path);

    fib_table_entry_path_remove2(fib_index, prefix, source, paths);

    vec_free(paths);
}

static int
fib_route_path_cmp_for_sort (void * v1,
			     void * v2)
{
    return (fib_route_path_cmp(v1, v2));
}

fib_node_index_t
fib_table_entry_update (u32 fib_index,
			const fib_prefix_t *prefix,
			fib_source_t source,
			fib_entry_flag_t flags,
			fib_route_path_t *paths)
{
    fib_node_index_t fib_entry_index;
    fib_table_t *fib_table;
    u32 ii;

    fib_table = fib_table_get(fib_index, prefix->fp_proto);
    fib_entry_index = fib_table_lookup_exact_match_i(fib_table, prefix);

    for (ii = 0; ii < vec_len(paths); ii++)
    {
	fib_table_route_path_fixup(prefix, &paths[ii]);
    }
    /*
     * sort the paths provided by the control plane. this means
     * the paths and the extension on the entry will be sorted.
     */
    vec_sort_with_function(paths, fib_route_path_cmp_for_sort);

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
    {
    	fib_entry_index = fib_entry_create(fib_index, prefix,
    					   source, flags,
					   paths);

    	fib_table_entry_insert(fib_table, prefix, fib_entry_index);
        fib_table->ft_src_route_counts[source]++;
    }
    else
    {
        int was_sourced;

        was_sourced = fib_entry_is_sourced(fib_entry_index, source);
    	fib_entry_update(fib_entry_index, source, flags, paths);

        if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
        {
            fib_table->ft_src_route_counts[source]++;
        }
    }

    return (fib_entry_index);
}

fib_node_index_t
fib_table_entry_update_one_path (u32 fib_index,
				 const fib_prefix_t *prefix,
				 fib_source_t source,
				 fib_entry_flag_t flags,
				 fib_protocol_t next_hop_proto,
				 const ip46_address_t *next_hop,
				 u32 next_hop_sw_if_index,
				 u32 next_hop_fib_index,
				 u32 next_hop_weight,
				 mpls_label_t *next_hop_labels,
				 fib_route_path_flags_t path_flags)
{
    fib_node_index_t fib_entry_index;
    fib_route_path_t path = {
	.frp_proto = next_hop_proto,
	.frp_addr = (NULL == next_hop? zero_addr : *next_hop),
	.frp_sw_if_index = next_hop_sw_if_index,
	.frp_fib_index = next_hop_fib_index,
	.frp_weight = next_hop_weight,
	.frp_flags = path_flags,
	.frp_label_stack = next_hop_labels,
    };
    fib_route_path_t *paths = NULL;

    fib_table_route_path_fixup(prefix, &path);
    vec_add1(paths, path);

    fib_entry_index = 
	fib_table_entry_update(fib_index, prefix, source, flags, paths);

    vec_free(paths);

    return (fib_entry_index);
}

static void
fib_table_entry_delete_i (u32 fib_index,
			  fib_node_index_t fib_entry_index,
			  const fib_prefix_t *prefix,
			  fib_source_t source)
{
    fib_entry_src_flag_t src_flag;
    fib_table_t *fib_table;
    int was_sourced;

    fib_table = fib_table_get(fib_index, prefix->fp_proto);
    was_sourced = fib_entry_is_sourced(fib_entry_index, source);

    /*
     * don't nobody go nowhere
     */
    fib_entry_lock(fib_entry_index);

    src_flag = fib_entry_delete(fib_entry_index, source);

    if (!(FIB_ENTRY_SRC_FLAG_ADDED & src_flag))
    {
	/*
	 * last source gone. remove from the table
	 */
	fib_table_entry_remove(fib_table, prefix, fib_entry_index);

	/*
	 * now the entry is no longer in the table, we can
	 * inform the entries that it covers to re-calculate their cover
	 */
	fib_entry_cover_change_notify(fib_entry_index,
				      FIB_NODE_INDEX_INVALID);
    }
    /*
     * else
     *   still has sources, leave it be.
     */
    if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
    {
        fib_table->ft_src_route_counts[source]--;
    }

    fib_entry_unlock(fib_entry_index);
}

void
fib_table_entry_delete (u32 fib_index,
			const fib_prefix_t *prefix,
			fib_source_t source)
{
    fib_node_index_t fib_entry_index;

    fib_entry_index = fib_table_lookup_exact_match(fib_index, prefix);

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
    {
	/*
	 * removing an etry that does not exist.
	 * i'll allow it, but i won't like it.
	 */
	clib_warning("%U not in FIB", format_fib_prefix, prefix);
    }
    else
    {
	fib_table_entry_delete_i(fib_index, fib_entry_index, prefix, source);
    }
}

void
fib_table_entry_delete_index (fib_node_index_t fib_entry_index,
			      fib_source_t source)
{
    fib_prefix_t prefix;

    fib_entry_get_prefix(fib_entry_index, &prefix);

    fib_table_entry_delete_i(fib_entry_get_fib_index(fib_entry_index),
                             fib_entry_index, &prefix, source);
}

fib_node_index_t
fib_table_entry_local_label_add (u32 fib_index,
				 const fib_prefix_t *prefix,
				 mpls_label_t label)
{
    fib_node_index_t fib_entry_index;
 
    fib_entry_index = fib_table_lookup_exact_match(fib_index, prefix);

    if (FIB_NODE_INDEX_INVALID == fib_entry_index ||
	!fib_entry_is_sourced(fib_entry_index, FIB_SOURCE_MPLS))
    {
	/*
	 * only source the prefix once. this allows the label change
	 * operation to work
	 */
	fib_entry_index = fib_table_entry_special_dpo_add(fib_index, prefix,
							  FIB_SOURCE_MPLS,
							  FIB_ENTRY_FLAG_NONE,
							  NULL);
    }

    fib_entry_set_source_data(fib_entry_index, FIB_SOURCE_MPLS, &label);

    return (fib_entry_index);
}

void
fib_table_entry_local_label_remove (u32 fib_index,
				    const fib_prefix_t *prefix,
				    mpls_label_t label)
{
    fib_node_index_t fib_entry_index;
    const void *data;
    mpls_label_t pl;

    fib_entry_index = fib_table_lookup_exact_match(fib_index, prefix);

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
        return;

    data = fib_entry_get_source_data(fib_entry_index, FIB_SOURCE_MPLS);

    if (NULL == data)
        return;

    pl = *(mpls_label_t*)data;

    if (pl != label)
        return;

    pl = MPLS_LABEL_INVALID;

    fib_entry_set_source_data(fib_entry_index, FIB_SOURCE_MPLS, &pl);
    fib_table_entry_special_remove(fib_index,
				   prefix,
				   FIB_SOURCE_MPLS);
}

u32
fib_table_get_index_for_sw_if_index (fib_protocol_t proto,
				     u32 sw_if_index)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	return (ip4_fib_table_get_index_for_sw_if_index(sw_if_index));
    case FIB_PROTOCOL_IP6:
	return (ip6_fib_table_get_index_for_sw_if_index(sw_if_index));
    case FIB_PROTOCOL_MPLS:
	return (mpls_fib_table_get_index_for_sw_if_index(sw_if_index));
    }
    return (~0);
}

flow_hash_config_t
fib_table_get_flow_hash_config (u32 fib_index,
				fib_protocol_t proto)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	return (ip4_fib_table_get_flow_hash_config(fib_index));
    case FIB_PROTOCOL_IP6:
	return (ip6_fib_table_get_flow_hash_config(fib_index));
    case FIB_PROTOCOL_MPLS:
	return (mpls_fib_table_get_flow_hash_config(fib_index));
    }
    return (0);
}


u32
fib_table_get_table_id_for_sw_if_index (fib_protocol_t proto,
					u32 sw_if_index)
{
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_table_get_index_for_sw_if_index(
				  proto, sw_if_index),
			      proto);

    return ((NULL != fib_table ? fib_table->ft_table_id : ~0));
}

u32
fib_table_find (fib_protocol_t proto,
		u32 table_id)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	return (ip4_fib_index_from_table_id(table_id));
    case FIB_PROTOCOL_IP6:
	return (ip6_fib_index_from_table_id(table_id));
    case FIB_PROTOCOL_MPLS:
	return (mpls_fib_index_from_table_id(table_id));
    }
    return (~0);
}

u32
fib_table_find_or_create_and_lock (fib_protocol_t proto,
				   u32 table_id)
{
    fib_table_t *fib_table;
    fib_node_index_t fi;

    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	fi = ip4_fib_table_find_or_create_and_lock(table_id);
        break;
    case FIB_PROTOCOL_IP6:
	fi = ip6_fib_table_find_or_create_and_lock(table_id);
        break;
    case FIB_PROTOCOL_MPLS:
	fi = mpls_fib_table_find_or_create_and_lock(table_id);
        break;
    default:
        return (~0);        
    }

    fib_table = fib_table_get(fi, proto);

    fib_table->ft_desc = format(NULL, "%U-VRF:%d",
                                format_fib_protocol, proto,
                                table_id);

    return (fi);
}

u32
fib_table_create_and_lock (fib_protocol_t proto,
                           const char *const fmt,
                           ...)
{
    fib_table_t *fib_table;
    fib_node_index_t fi;
    va_list ap;

    va_start(ap, fmt);

    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	fi = ip4_fib_table_create_and_lock();
        break;
    case FIB_PROTOCOL_IP6:
	fi = ip6_fib_table_create_and_lock();
        break;
     case FIB_PROTOCOL_MPLS:
	fi = mpls_fib_table_create_and_lock();
        break;
   default:
        return (~0);        
    }

    fib_table = fib_table_get(fi, proto);

    fib_table->ft_desc = va_format(fib_table->ft_desc, fmt, &ap);

    va_end(ap);
    return (fi);
}

static void
fib_table_destroy (fib_table_t *fib_table)
{
    vec_free(fib_table->ft_desc);

    switch (fib_table->ft_proto)
    {
    case FIB_PROTOCOL_IP4:
	ip4_fib_table_destroy(&fib_table->v4);
	break;
    case FIB_PROTOCOL_IP6:
	ip6_fib_table_destroy(fib_table->ft_index);
	break;
    case FIB_PROTOCOL_MPLS:
	mpls_fib_table_destroy(&fib_table->mpls);
	break;
    }
}

void
fib_table_walk (u32 fib_index,
                fib_protocol_t proto,
                fib_table_walk_fn_t fn,
                void *ctx)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	ip4_fib_table_walk(ip4_fib_get(fib_index), fn, ctx);
	break;
    case FIB_PROTOCOL_IP6:
	ip6_fib_table_walk(fib_index, fn, ctx);
	break;
    case FIB_PROTOCOL_MPLS:
	mpls_fib_table_walk(mpls_fib_get(fib_index), fn, ctx);
	break;
    }
}

void
fib_table_unlock (u32 fib_index,
		  fib_protocol_t proto)
{
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);
    fib_table->ft_locks--;

    if (0 == fib_table->ft_locks)
    {
	fib_table_destroy(fib_table);
    }
}
void
fib_table_lock (u32 fib_index,
		fib_protocol_t proto)
{
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);
    fib_table->ft_locks++;
}

u32
fib_table_get_num_entries (u32 fib_index,
			   fib_protocol_t proto,
			   fib_source_t source)
{
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);

    return (fib_table->ft_src_route_counts[source]);
}

u8*
format_fib_table_name (u8* s, va_list ap)
{
    fib_node_index_t fib_index = va_arg(ap, fib_node_index_t);
    fib_protocol_t proto = va_arg(ap, int); // int promotion
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);

    s = format(s, "%v", fib_table->ft_desc);

    return (s);
}

/**
 * @brief Table flush context. Store the indicies of matching FIB entries
 * that need to be removed.
 */
typedef struct fib_table_flush_ctx_t_
{
    /**
     * The list of entries to flush
     */
    fib_node_index_t *ftf_entries;

    /**
     * The source we are flushing
     */
    fib_source_t ftf_source;
} fib_table_flush_ctx_t;

static int
fib_table_flush_cb (fib_node_index_t fib_entry_index,
                    void *arg)
{
    fib_table_flush_ctx_t *ctx = arg;

    if (fib_entry_is_sourced(fib_entry_index, ctx->ftf_source))
    {
        vec_add1(ctx->ftf_entries, fib_entry_index);
    }
    return (1);
}


void
fib_table_flush (u32 fib_index,
		 fib_protocol_t proto,
		 fib_source_t source)
{
    fib_node_index_t *fib_entry_index;
    fib_table_flush_ctx_t ctx = {
        .ftf_entries = NULL,
        .ftf_source = source,
    };

    fib_table_walk(fib_index, proto,
                   fib_table_flush_cb,
                   &ctx);

    vec_foreach(fib_entry_index, ctx.ftf_entries)
    {
        fib_table_entry_delete_index(*fib_entry_index, source);
    }

    vec_free(ctx.ftf_entries);
}
