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

const static char * fib_table_flags_strings[] = FIB_TABLE_ATTRIBUTES;

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
	return (ip4_fib_table_lookup(ip4_fib_get(fib_table->ft_index),
				     &prefix->fp_addr.ip4,
				     prefix->fp_len));
    case FIB_PROTOCOL_IP6:
	return (ip6_fib_table_lookup(fib_table->ft_index,
				     &prefix->fp_addr.ip6,
				     prefix->fp_len));
    case FIB_PROTOCOL_MPLS:
	return (mpls_fib_table_lookup(mpls_fib_get(fib_table->ft_index),
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
	return (ip4_fib_table_lookup_exact_match(ip4_fib_get(fib_table->ft_index),
						 &prefix->fp_addr.ip4,
						 prefix->fp_len));
    case FIB_PROTOCOL_IP6:
	return (ip6_fib_table_lookup_exact_match(fib_table->ft_index,
						 &prefix->fp_addr.ip6,
						 prefix->fp_len));
    case FIB_PROTOCOL_MPLS:
	return (mpls_fib_table_lookup(mpls_fib_get(fib_table->ft_index),
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
	ip4_fib_table_entry_remove(ip4_fib_get(fib_table->ft_index),
				   &prefix->fp_addr.ip4,
				   prefix->fp_len);
	break;
    case FIB_PROTOCOL_IP6:
	ip6_fib_table_entry_remove(fib_table->ft_index,
				   &prefix->fp_addr.ip6,
				   prefix->fp_len);
	break;
    case FIB_PROTOCOL_MPLS:
	mpls_fib_table_entry_remove(mpls_fib_get(fib_table->ft_index),
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
     * find  the covering entry
     */
    fib_entry_cover_index = fib_table_get_less_specific_i(fib_table, prefix);
    /*
     * the indicies are the same when the default route is first added
     */
    if (fib_entry_cover_index != fib_entry_index)
    {
        /*
         * push any inherting sources from the cover onto the covered
         */
        fib_entry_inherit(fib_entry_cover_index,
                          fib_entry_index);

        /*
         * inform the covering entry that a new more specific
         * has been inserted beneath it.
         * If the prefix that has been inserted is a host route
         * then it is not possible that it will be the cover for any
         * other entry, so we can elide the walk. This is particularly
         * beneficial since there are often many host entries sharing the
         * same cover (i.e. ADJ or RR sourced entries).
         */
        if (!fib_entry_is_host(fib_entry_index))
        {
            fib_entry_cover_change_notify(fib_entry_cover_index,
                                          fib_entry_index);
        }
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
	ip4_fib_table_entry_insert(ip4_fib_get(fib_table->ft_index),
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
	mpls_fib_table_entry_insert(mpls_fib_get(fib_table->ft_index),
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
						dpo,
                                                fib_table_get_less_specific(fib_index,
                                                                            prefix)));
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

static void
fib_table_source_count_inc (fib_table_t *fib_table,
                            fib_source_t source)
{
    vec_validate (fib_table->ft_src_route_counts, source);
    fib_table->ft_src_route_counts[source]++;
}

static void
fib_table_source_count_dec (fib_table_t *fib_table,
                            fib_source_t source)
{
    vec_validate (fib_table->ft_src_route_counts, source);
    fib_table->ft_src_route_counts[source]--;
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
        fib_table_source_count_inc(fib_table, source);
    }
    else
    {
        int was_sourced;

        was_sourced = fib_entry_is_sourced(fib_entry_index, source);
	fib_entry_special_add(fib_entry_index, source, flags, dpo);

        if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
        {
        fib_table_source_count_inc(fib_table, source);
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
        fib_table_source_count_inc(fib_table, source);
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
            fib_table_source_count_inc(fib_table, source);
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
            fib_table_source_count_dec(fib_table, source);
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
                            fib_entry_flag_t *eflags,
			    fib_route_path_t *path)
{
    /*
     * not all zeros next hop &&
     * is recursive path &&
     * nexthop is same as the route's address
     */
    if ((!ip46_address_is_zero(&path->frp_addr)) &&
        (~0 == path->frp_sw_if_index) &&
        (0 == ip46_address_cmp(&path->frp_addr, &prefix->fp_addr)))
    {
        /* Prefix recurses via itself */
	path->frp_flags |= FIB_ROUTE_PATH_DROP;
    }
    if (!(path->frp_flags & FIB_ROUTE_PATH_LOCAL) &&
        fib_prefix_is_host(prefix) &&
	ip46_address_is_zero(&path->frp_addr) &&
	path->frp_sw_if_index != ~0 &&
        path->frp_proto != DPO_PROTO_ETHERNET)
    {
	path->frp_addr = prefix->fp_addr;
        path->frp_flags |= FIB_ROUTE_PATH_ATTACHED;
    }
    else if ((*eflags & FIB_ENTRY_FLAG_CONNECTED) &&
             !(*eflags & FIB_ENTRY_FLAG_LOCAL))
    {
        if (ip46_address_is_zero(&path->frp_addr))
        {
            path->frp_flags |= FIB_ROUTE_PATH_GLEAN;
            fib_prefix_normalize(prefix, &path->frp_connected);
        }
    }
    if (*eflags & FIB_ENTRY_FLAG_DROP)
    {
	path->frp_flags |= FIB_ROUTE_PATH_DROP;
    }
    if (*eflags & FIB_ENTRY_FLAG_LOCAL)
    {
	path->frp_flags |= FIB_ROUTE_PATH_LOCAL;
    }
    if (*eflags & FIB_ENTRY_FLAG_EXCLUSIVE)
    {
	path->frp_flags |= FIB_ROUTE_PATH_EXCLUSIVE;
    }
    if (path->frp_flags & FIB_ROUTE_PATH_LOCAL)
    {
        *eflags |= FIB_ENTRY_FLAG_LOCAL;

        if (path->frp_sw_if_index != ~0)
        {
            *eflags |= FIB_ENTRY_FLAG_CONNECTED;
        }
    }
}

fib_node_index_t
fib_table_entry_path_add (u32 fib_index,
			  const fib_prefix_t *prefix,
			  fib_source_t source,
			  fib_entry_flag_t flags,
			  dpo_proto_t next_hop_proto,
			  const ip46_address_t *next_hop,
			  u32 next_hop_sw_if_index,
			  u32 next_hop_fib_index,
			  u32 next_hop_weight,
			  fib_mpls_label_t *next_hop_labels,
			  fib_route_path_flags_t path_flags)
{
    fib_route_path_t path = {
	.frp_proto = next_hop_proto,
	.frp_addr = (NULL == next_hop? zero_addr : *next_hop),
	.frp_sw_if_index = next_hop_sw_if_index,
	.frp_fib_index = next_hop_fib_index,
	.frp_weight = next_hop_weight,
	.frp_flags = path_flags,
        .frp_rpf_id = INDEX_INVALID,
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

static int
fib_route_path_cmp_for_sort (void * v1,
			     void * v2)
{
    return (fib_route_path_cmp(v1, v2));
}

fib_node_index_t
fib_table_entry_path_add2 (u32 fib_index,
			   const fib_prefix_t *prefix,
			   fib_source_t source,
			   fib_entry_flag_t flags,
			   fib_route_path_t *rpaths)
{
    fib_node_index_t fib_entry_index;
    fib_table_t *fib_table;
    u32 ii;

    fib_table = fib_table_get(fib_index, prefix->fp_proto);
    fib_entry_index = fib_table_lookup_exact_match_i(fib_table, prefix);

    for (ii = 0; ii < vec_len(rpaths); ii++)
    {
	fib_table_route_path_fixup(prefix, &flags, &rpaths[ii]);
    }
    /*
     * sort the paths provided by the control plane. this means
     * the paths and the extension on the entry will be sorted.
     */
    vec_sort_with_function(rpaths, fib_route_path_cmp_for_sort);

    if (FIB_NODE_INDEX_INVALID == fib_entry_index)
    {
	fib_entry_index = fib_entry_create(fib_index, prefix,
					   source, flags,
					   rpaths);

	fib_table_entry_insert(fib_table, prefix, fib_entry_index);
        fib_table_source_count_inc(fib_table, source);
    }
    else
    {
        int was_sourced;

        was_sourced = fib_entry_is_sourced(fib_entry_index, source);
	fib_entry_path_add(fib_entry_index, source, flags, rpaths);;

        if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
        {
            fib_table_source_count_inc(fib_table, source);
        }
    }

    return (fib_entry_index);
}

void
fib_table_entry_path_remove2 (u32 fib_index,
			      const fib_prefix_t *prefix,
			      fib_source_t source,
			      fib_route_path_t *rpaths)
{
    /*
     * 1 is it present
     *   yes => remove source
     *    2 - is it still sourced?
     *      no => cover walk
     */
    fib_node_index_t fib_entry_index;
    fib_route_path_t *rpath;
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
         * if it's not sourced, then there's nowt to remove
         */
        was_sourced = fib_entry_is_sourced(fib_entry_index, source);
        if (!was_sourced)
        {
            return;
        }

        /*
	 * don't nobody go nowhere
	 */
	fib_entry_lock(fib_entry_index);

        vec_foreach(rpath, rpaths)
        {
            fib_entry_flag_t eflags;

            eflags = fib_entry_get_flags_for_source(fib_entry_index,
                                                    source);
            fib_table_route_path_fixup(prefix, &eflags, rpath);
        }

	src_flag = fib_entry_path_remove(fib_entry_index, source, rpaths);

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
            fib_table_source_count_dec(fib_table, source);
        }

	fib_entry_unlock(fib_entry_index);
    }
}

void
fib_table_entry_path_remove (u32 fib_index,
			     const fib_prefix_t *prefix,
			     fib_source_t source,
			     dpo_proto_t next_hop_proto,
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

    vec_add1(paths, path);

    fib_table_entry_path_remove2(fib_index, prefix, source, paths);

    vec_free(paths);
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
	fib_table_route_path_fixup(prefix, &flags, &paths[ii]);
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
        fib_table_source_count_inc(fib_table, source);
    }
    else
    {
        int was_sourced;

        was_sourced = fib_entry_is_sourced(fib_entry_index, source);
    	fib_entry_update(fib_entry_index, source, flags, paths);

        if (was_sourced != fib_entry_is_sourced(fib_entry_index, source))
        {
            fib_table_source_count_inc(fib_table, source);
        }
    }

    return (fib_entry_index);
}

fib_node_index_t
fib_table_entry_update_one_path (u32 fib_index,
				 const fib_prefix_t *prefix,
				 fib_source_t source,
				 fib_entry_flag_t flags,
				 dpo_proto_t next_hop_proto,
				 const ip46_address_t *next_hop,
				 u32 next_hop_sw_if_index,
				 u32 next_hop_fib_index,
				 u32 next_hop_weight,
				 fib_mpls_label_t *next_hop_labels,
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
        fib_table_source_count_dec(fib_table, source);
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
        if (0)
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
    const fib_prefix_t *prefix;

    prefix = fib_entry_get_prefix(fib_entry_index);

    fib_table_entry_delete_i(fib_entry_get_fib_index(fib_entry_index),
                             fib_entry_index, prefix, source);
}

u32
fib_table_entry_get_stats_index (u32 fib_index,
                                 const fib_prefix_t *prefix)
{
    return (fib_entry_get_stats_index(
                fib_table_lookup_exact_match(fib_index, prefix)));
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
    fib_table_t *fib;

    fib = fib_table_get(fib_index, proto);

    return (fib->ft_flow_hash_config);
}

flow_hash_config_t
fib_table_get_default_flow_hash_config (fib_protocol_t proto)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
    case FIB_PROTOCOL_IP6:
	return (IP_FLOW_HASH_DEFAULT);

    case FIB_PROTOCOL_MPLS:
	return (MPLS_FLOW_HASH_DEFAULT);
    }

    ASSERT(0);
    return (IP_FLOW_HASH_DEFAULT);
}

/**
 * @brief Table set flow hash config context.
 */
typedef struct fib_table_set_flow_hash_config_ctx_t_
{
    /**
     * the flow hash config to set
     */
    flow_hash_config_t hash_config;
} fib_table_set_flow_hash_config_ctx_t;

static fib_table_walk_rc_t
fib_table_set_flow_hash_config_cb (fib_node_index_t fib_entry_index,
                                   void *arg)
{
    fib_table_set_flow_hash_config_ctx_t *ctx = arg;

    fib_entry_set_flow_hash_config(fib_entry_index, ctx->hash_config);

    return (FIB_TABLE_WALK_CONTINUE);
}

void
fib_table_set_flow_hash_config (u32 fib_index,
                                fib_protocol_t proto,
                                flow_hash_config_t hash_config)
{
    fib_table_set_flow_hash_config_ctx_t ctx = {
        .hash_config = hash_config,
    };
    fib_table_t *fib;

    fib = fib_table_get(fib_index, proto);
    fib->ft_flow_hash_config = hash_config;

    fib_table_walk(fib_index, proto,
                   fib_table_set_flow_hash_config_cb,
                   &ctx);
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
fib_table_get_table_id (u32 fib_index,
                        fib_protocol_t proto)
{
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);

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

static u32
fib_table_find_or_create_and_lock_i (fib_protocol_t proto,
                                     u32 table_id,
                                     fib_source_t src,
                                     const u8 *name)
{
    fib_table_t *fib_table;
    fib_node_index_t fi;

    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	fi = ip4_fib_table_find_or_create_and_lock(table_id, src);
        break;
    case FIB_PROTOCOL_IP6:
	fi = ip6_fib_table_find_or_create_and_lock(table_id, src);
        break;
    case FIB_PROTOCOL_MPLS:
	fi = mpls_fib_table_find_or_create_and_lock(table_id, src);
        break;
    default:
        return (~0);        
    }

    fib_table = fib_table_get(fi, proto);

    if (NULL == fib_table->ft_desc)
    {
        if (name && name[0])
        {
            fib_table->ft_desc = format(NULL, "%s", name);
        }
        else
        {
            fib_table->ft_desc = format(NULL, "%U-VRF:%d",
                                        format_fib_protocol, proto,
                                        table_id);
        }
    }

    return (fi);
}

u32
fib_table_find_or_create_and_lock (fib_protocol_t proto,
				   u32 table_id,
                                   fib_source_t src)
{
    return (fib_table_find_or_create_and_lock_i(proto, table_id,
                                                src, NULL));
}

u32
fib_table_find_or_create_and_lock_w_name (fib_protocol_t proto,
                                          u32 table_id,
                                          fib_source_t src,
                                          const u8 *name)
{
    return (fib_table_find_or_create_and_lock_i(proto, table_id,
                                                src, name));
}

u32
fib_table_create_and_lock (fib_protocol_t proto,
                           fib_source_t src,
                           const char *const fmt,
                           ...)
{
    fib_table_t *fib_table;
    fib_node_index_t fi;
    va_list ap;


    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	fi = ip4_fib_table_create_and_lock(src);
        break;
    case FIB_PROTOCOL_IP6:
	fi = ip6_fib_table_create_and_lock(src, FIB_TABLE_FLAG_NONE, NULL);
        break;
     case FIB_PROTOCOL_MPLS:
	fi = mpls_fib_table_create_and_lock(src);
        break;
   default:
        return (~0);        
    }

    fib_table = fib_table_get(fi, proto);

    va_start(ap, fmt);

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
	ip4_fib_table_destroy(fib_table->ft_index);
	break;
    case FIB_PROTOCOL_IP6:
	ip6_fib_table_destroy(fib_table->ft_index);
	break;
    case FIB_PROTOCOL_MPLS:
	mpls_fib_table_destroy(fib_table->ft_index);
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
fib_table_sub_tree_walk (u32 fib_index,
                         fib_protocol_t proto,
                         const fib_prefix_t *root,
                         fib_table_walk_fn_t fn,
                         void *ctx)
{
    switch (proto)
    {
    case FIB_PROTOCOL_IP4:
	ip4_fib_table_sub_tree_walk(ip4_fib_get(fib_index), root, fn, ctx);
	break;
    case FIB_PROTOCOL_IP6:
	ip6_fib_table_sub_tree_walk(fib_index, root, fn, ctx);
	break;
    case FIB_PROTOCOL_MPLS:
	break;
    }
}

static void
fib_table_lock_dec (fib_table_t *fib_table,
                    fib_source_t source)
{
    vec_validate(fib_table->ft_locks, source);

    fib_table->ft_locks[source]--;
    fib_table->ft_total_locks--;
}

static void
fib_table_lock_inc (fib_table_t *fib_table,
                    fib_source_t source)
{
    vec_validate(fib_table->ft_locks, source);

    ASSERT(fib_table->ft_total_locks < (0xffffffff - 1));
    fib_table->ft_locks[source]++;
    fib_table->ft_total_locks++;
}

void
fib_table_unlock (u32 fib_index,
		  fib_protocol_t proto,
                  fib_source_t source)
{
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);
    fib_table_lock_dec(fib_table, source);

    if (0 == fib_table->ft_total_locks)
    {
        /*
         * no more locak from any source - kill it
         */
	fib_table_destroy(fib_table);
    }
}

void
fib_table_lock (u32 fib_index,
		fib_protocol_t proto,
                fib_source_t source)
{
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);

    fib_table_lock_inc(fib_table, source);
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
format_fib_table_name (u8* s, va_list* ap)
{
    fib_node_index_t fib_index = va_arg(*ap, fib_node_index_t);
    fib_protocol_t proto = va_arg(*ap, int); // int promotion
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);

    s = format(s, "%v", fib_table->ft_desc);

    return (s);
}

u8*
format_fib_table_flags (u8 *s, va_list *args)
{
    fib_table_flags_t flags = va_arg(*args, int);
    fib_table_attribute_t attr;

    if (!flags)
    {
        return format(s, "none");
    }

    FOR_EACH_FIB_TABLE_ATTRIBUTE(attr) {
        if (1 << attr & flags) {
            s = format(s, "%s", fib_table_flags_strings[attr]);
        }
    }

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

static fib_table_walk_rc_t
fib_table_flush_cb (fib_node_index_t fib_entry_index,
                    void *arg)
{
    fib_table_flush_ctx_t *ctx = arg;

    if (fib_entry_is_sourced(fib_entry_index, ctx->ftf_source))
    {
        vec_add1(ctx->ftf_entries, fib_entry_index);
    }
    return (FIB_TABLE_WALK_CONTINUE);
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

static fib_table_walk_rc_t
fib_table_mark_cb (fib_node_index_t fib_entry_index,
                   void *arg)
{
    fib_table_flush_ctx_t *ctx = arg;

    if (fib_entry_is_sourced(fib_entry_index, ctx->ftf_source))
    {
        fib_entry_mark(fib_entry_index, ctx->ftf_source);
    }
    return (FIB_TABLE_WALK_CONTINUE);
}

void
fib_table_mark (u32 fib_index,
                fib_protocol_t proto,
                fib_source_t source)
{
    fib_table_flush_ctx_t ctx = {
        .ftf_source = source,
    };
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);

    fib_table->ft_epoch++;
    fib_table->ft_flags |= FIB_TABLE_FLAG_RESYNC;

    fib_table_walk(fib_index, proto,
                   fib_table_mark_cb,
                   &ctx);
}

static fib_table_walk_rc_t
fib_table_sweep_cb (fib_node_index_t fib_entry_index,
                    void *arg)
{
    fib_table_flush_ctx_t *ctx = arg;

    if (fib_entry_is_marked(fib_entry_index, ctx->ftf_source))
    {
        vec_add1(ctx->ftf_entries, fib_entry_index);
    }
    return (FIB_TABLE_WALK_CONTINUE);
}

void
fib_table_sweep (u32 fib_index,
                 fib_protocol_t proto,
                 fib_source_t source)
{
    fib_table_flush_ctx_t ctx = {
        .ftf_source = source,
    };
    fib_node_index_t *fib_entry_index;
    fib_table_t *fib_table;

    fib_table = fib_table_get(fib_index, proto);

    fib_table->ft_flags &= ~FIB_TABLE_FLAG_RESYNC;

    fib_table_walk(fib_index, proto,
                   fib_table_sweep_cb,
                   &ctx);

    vec_foreach(fib_entry_index, ctx.ftf_entries)
    {
        fib_table_entry_delete_index(*fib_entry_index, source);
    }

    vec_free(ctx.ftf_entries);
}

u8 *
format_fib_table_memory (u8 *s, va_list *args)
{
    s = format(s, "%U", format_ip4_fib_table_memory);
    s = format(s, "%U", format_ip6_fib_table_memory);
    s = format(s, "%U", format_mpls_fib_table_memory);

    return (s);
}
