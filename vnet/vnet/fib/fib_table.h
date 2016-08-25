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

#ifndef __FIB_TABLE_H__
#define __FIB_TABLE_H__

#include <vnet/ip/ip.h>
#include <vnet/adj/adj.h>
#include <vnet/fib/fib_entry.h>
#include <vnet/mpls/mpls_types.h>
#include <vnet/mpls/packet.h>

/**
 * A protocol Independent FIB table
 */
typedef struct fib_table_t_
{
    /**
     * A union of the protocol specific FIBs that provide the
     * underlying LPM mechanism.
     * This element is first in the struct so that it is in the
     * first cache line.
     */
    union {
	ip4_fib_t v4;
	ip6_fib_t v6;
    };

    /**
     * Which protocol this table serves. Used to switch on the union above.
     */
    fib_protocol_t ft_proto;

    /**
     * number of locks on the table
     */
    u16 ft_locks;

    /**
     * Table ID (hash key) for this FIB.
     */
    u32 ft_table_id;

    /**
     * Index into FIB vector.
     */
    fib_node_index_t ft_index;

    /**
     * flow hash configuration
     */
    u32 ft_flow_hash_config;

    /**
     * Per-source route counters
     */
    u32 ft_src_route_counts[FIB_SOURCE_MAX];
    u32 ft_total_route_counts;

    /**
     * Table description
     */
    u8* ft_desc;
} fib_table_t;

extern u8* format_fib_table_name(u8* s, va_list ap);

extern fib_node_index_t fib_table_lookup(u32 fib_index,
					 const fib_prefix_t *prefix);
extern fib_node_index_t fib_table_lookup_exact_match(u32 fib_index,
						     const fib_prefix_t *prefix);

extern fib_node_index_t fib_table_get_less_specific(u32 fib_index,
						    const fib_prefix_t *prefix);

extern fib_node_index_t fib_table_entry_special_add(u32 fib_index,
						    const fib_prefix_t *prefix,
						    fib_source_t source,
						    fib_entry_flag_t stype,
						    adj_index_t adj_index);

extern fib_node_index_t fib_table_entry_special_dpo_add(u32 fib_index,
                                                        const fib_prefix_t *prefix,
                                                        fib_source_t source,
                                                        fib_entry_flag_t stype,
                                                        const dpo_id_t *dpo);

extern void fib_table_entry_special_remove(u32 fib_index,
					   const fib_prefix_t *prefix,
					   fib_source_t source);

extern fib_node_index_t fib_table_entry_path_add(u32 fib_index,
						 const fib_prefix_t *prefix,
						 fib_source_t source,
						 fib_entry_flag_t flags,
						 const ip46_address_t *next_hop,
						 u32 next_hop_sw_if_index,
						 u32 next_hop_fib_index,
						 u32 next_hop_weight,
						 mpls_label_t next_hop_label,
						 fib_route_path_flags_t pf);
extern fib_node_index_t fib_table_entry_path_add2(u32 fib_index,
						  const fib_prefix_t *prefix,
						  fib_source_t source,
						  fib_entry_flag_t flags,
						  const fib_route_path_t *rpath);

extern void fib_table_entry_path_remove(u32 fib_index,
					const fib_prefix_t *prefix,
					fib_source_t source,
					const ip46_address_t *next_hop,
					u32 next_hop_sw_if_index,
					u32 next_hop_fib_index,
					u32 next_hop_weight,
					fib_route_path_flags_t pf);
extern void fib_table_entry_path_remove2(u32 fib_index,
					 const fib_prefix_t *prefix,
					 fib_source_t source,
					 const fib_route_path_t *paths);

extern fib_node_index_t fib_table_entry_update(u32 fib_index,
					       const fib_prefix_t *prefix,
					       fib_source_t source,
					       fib_entry_flag_t flags,
					       const fib_route_path_t *paths);
extern fib_node_index_t fib_table_entry_update_one_path(u32 fib_index,
							const fib_prefix_t *prefix,
							fib_source_t source,
							fib_entry_flag_t flags,
							const ip46_address_t *next_hop,
							u32 next_hop_sw_if_index,
							u32 next_hop_fib_index,
							u32 next_hop_weight,
							mpls_label_t next_hop_label,
							fib_route_path_flags_t pf);

extern fib_node_index_t fib_table_entry_local_label_add(u32 fib_index,
							const fib_prefix_t *prefix,
							mpls_label_t label);
extern void fib_table_entry_local_label_remove(u32 fib_index,
					       const fib_prefix_t *prefix,
					       mpls_label_t label);

extern void fib_table_entry_delete(u32 fib_index,
				   const fib_prefix_t *prefix,
				   fib_source_t source);
extern void fib_table_entry_delete_index(fib_node_index_t entry_index,
					 fib_source_t source);

extern void fib_table_fwding_dpo_update(u32 fib_index,
					const fib_prefix_t *prefix,
					const dpo_id_t *dpo);
extern void fib_table_fwding_dpo_remove(u32 fib_index,
					const fib_prefix_t *prefix,
					const dpo_id_t *dpo);

extern void fib_table_flush(u32 fib_index,
			    fib_protocol_t proto,
			    fib_source_t source);

extern u32 fib_table_get_index_for_sw_if_index(fib_protocol_t proto,
					       u32 sw_if_index);
extern u32 fib_table_get_table_id_for_sw_if_index(fib_protocol_t proto,
						  u32 sw_if_index);

extern u32 fib_table_get_from_table_id(fib_protocol_t proto, u32 table_id);

extern u32 fib_table_find_or_create_and_lock(fib_protocol_t proto,
					     u32 table_id);

/**
 * \brief
 *  Create a new table with no table ID. This means it does not get
 * added to the hash-table and so can only be found by using the index returned.
 */
extern u32 fib_table_create_and_lock(fib_protocol_t proto,
                                     const char *const fmt,
                                     ...);

typedef int (*fib_table_walker)(fib_prefix_t *prefix,
				fib_node_index_t fei,
				adj_index_t ai,
				void *ctx);

extern void fib_table_walk(u32 fib_index,
			   fib_protocol_t proto,
			   fib_table_walker cb,
			   void *ctx);

extern flow_hash_config_t fib_table_get_flow_hash_config(u32 fib_index,
							 fib_protocol_t proto);

extern void fib_table_unlock(u32 fib_index,
			     fib_protocol_t proto);
extern void fib_table_lock(u32 fib_index,
			   fib_protocol_t proto);

extern u32 fib_table_get_num_entries(u32 fib_index,
				     fib_protocol_t proto,
				     fib_source_t source);

extern fib_table_t *fib_table_get(fib_node_index_t index,
				  fib_protocol_t proto);

#endif
