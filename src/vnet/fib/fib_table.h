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
#include <vnet/mpls/mpls.h>
#include <vnet/mpls/packet.h>

/**
 * Flags for the source data
 */
typedef enum fib_table_attribute_t_ {
    /**
     * Marker. Add new values after this one.
     */
    FIB_TABLE_ATTRIBUTE_FIRST,
    /**
     * the table is for IP6 link local addresses
     */
    FIB_TABLE_ATTRIBUTE_IP6_LL = FIB_TABLE_ATTRIBUTE_FIRST,
    /**
     * the table is currently resync-ing
     */
    FIB_TABLE_ATTRIBUTE_RESYNC,
    /**
     * Marker. add new entries before this one.
     */
    FIB_TABLE_ATTRIBUTE_LAST = FIB_TABLE_ATTRIBUTE_RESYNC,
} fib_table_attribute_t;

#define FIB_TABLE_ATTRIBUTE_MAX (FIB_TABLE_ATTRIBUTE_LAST+1)

#define FIB_TABLE_ATTRIBUTES {		         \
    [FIB_TABLE_ATTRIBUTE_IP6_LL]  = "ip6-ll",	 \
    [FIB_TABLE_ATTRIBUTE_RESYNC]  = "resync",    \
}

#define FOR_EACH_FIB_TABLE_ATTRIBUTE(_item)      	\
    for (_item = FIB_TABLE_ATTRIBUTE_FIRST;		\
	 _item < FIB_TABLE_ATTRIBUTE_MAX;		\
	 _item++)

typedef enum fib_table_flags_t_ {
    FIB_TABLE_FLAG_NONE   = 0,
    FIB_TABLE_FLAG_IP6_LL  = (1 << FIB_TABLE_ATTRIBUTE_IP6_LL),
    FIB_TABLE_FLAG_RESYNC  = (1 << FIB_TABLE_ATTRIBUTE_RESYNC),
} __attribute__ ((packed)) fib_table_flags_t;

extern u8* format_fib_table_flags(u8 *s, va_list *args);

/**
 * @brief 
 *   A protocol Independent FIB table
 */
typedef struct fib_table_t_
{
    /**
     * Which protocol this table serves. Used to switch on the union above.
     */
    fib_protocol_t ft_proto;

    /**
     * Table flags
     */
    fib_table_flags_t ft_flags;

    /**
     * per-source number of locks on the table
     */
    u32 *ft_locks;
    u32 ft_total_locks;

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
    u32 *ft_src_route_counts;

    /**
     * Total route counters
     */
    u32 ft_total_route_counts;

    /**
     * Epoch - number of resyncs performed
     */
    u32 ft_epoch;

    /**
     * Table description
     */
    u8* ft_desc;
} fib_table_t;

/**
 * @brief
 *  Format the description/name of the table
 */
extern u8* format_fib_table_name(u8* s, va_list *ap);

/**
 * @brief
 *  Perfom a longest prefix match in the non-forwarding table
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix to lookup
 *
 * @return
 *  The index of the fib_entry_t for the best match, which may be the default route
 */
extern fib_node_index_t fib_table_lookup(u32 fib_index,
					 const fib_prefix_t *prefix);

/**
 * @brief
 *  Perfom an exact match in the non-forwarding table
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix to lookup
 *
 * @return
 *  The index of the fib_entry_t for the exact match, or INVALID
 *  is there is no match.
 */
extern fib_node_index_t fib_table_lookup_exact_match(u32 fib_index,
						     const fib_prefix_t *prefix);

/**
 * @brief
 *  Get the less specific (covering) prefix
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix to lookup
 *
 * @return
 *  The index of the less specific fib_entry_t.
 */
extern fib_node_index_t fib_table_get_less_specific(u32 fib_index,
						    const fib_prefix_t *prefix);

/**
 * @brief
 *  Add a 'special' entry to the FIB.
 *  A special entry is an entry that the FIB is not expect to resolve
 *  via the usual mechanisms (i.e. recurisve or neighbour adj DB lookup).
 *  Instead the will link to a DPO valid for the source and/or the flags.
 *  This add is reference counting per-source. So n 'removes' are required
 *  for n 'adds', if the entry is no longer required.
 *  If the source needs to provide non-default forwarding use:
 *  fib_table_entry_special_dpo_add()
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix to add
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 * @param flags
 *  Flags for the entry.
 *
 * @return
 *  the index of the fib_entry_t that is created (or exists already).
 */
extern fib_node_index_t fib_table_entry_special_add(u32 fib_index,
						    const fib_prefix_t *prefix,
						    fib_source_t source,
						    fib_entry_flag_t flags);

/**
 * @brief
 *  Add a 'special' entry to the FIB that links to the DPO passed
 *  A special entry is an entry that the FIB is not expect to resolve
 *  via the usual mechanisms (i.e. recurisve or neighbour adj DB lookup).
 *  Instead the client/source provides the DPO to link to.
 *  This add is reference counting per-source. So n 'removes' are required
 *  for n 'adds', if the entry is no longer required.
 *
  * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix to add
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 * @param flags
 *  Flags for the entry.
 *
 * @param dpo
 *  The DPO to link to.
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t fib_table_entry_special_dpo_add(u32 fib_index,
                                                        const fib_prefix_t *prefix,
                                                        fib_source_t source,
                                                        fib_entry_flag_t stype,
                                                        const dpo_id_t *dpo);

/**
 * @brief
 *  Update a 'special' entry to the FIB that links to the DPO passed
 *  A special entry is an entry that the FIB is not expect to resolve
 *  via the usual mechanisms (i.e. recurisve or neighbour adj DB lookup).
 *  Instead the client/source provides the DPO to link to.
 *  Special entries are add/remove reference counted per-source. So n
 * 'removes' are required for n 'adds', if the entry is no longer required.
 *  An 'update' is an 'add' if no 'add' has already been called, otherwise an 'add'
 * is therefore assumed to act on the reference instance of that add.
 *
 * @param fib_entry_index
 *  The index of the FIB entry to update
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 * @param flags
 *  Flags for the entry.
 *
 * @param dpo
 *  The DPO to link to.
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t fib_table_entry_special_dpo_update (u32 fib_index,
							    const fib_prefix_t *prefix,
							    fib_source_t source,
							    fib_entry_flag_t stype,
							    const dpo_id_t *dpo);

/**
 * @brief
 *  Remove a 'special' entry from the FIB.
 *  This add is reference counting per-source. So n 'removes' are required
 *  for n 'adds', if the entry is no longer required.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix to remove
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 */
extern void fib_table_entry_special_remove(u32 fib_index,
					   const fib_prefix_t *prefix,
					   fib_source_t source);

/**
 * @brief
 *  Add one path to an entry (aka route) in the FIB. If the entry does not
 *  exist, it will be created.
 * See the documentation for fib_route_path_t for more descirptions of
 * the path parameters.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to add
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 * @param flags
 *  Flags for the entry.
 *
 * @paran next_hop_proto
 *  The protocol of the next hop. This cannot be derived in the event that
 * the next hop is all zeros.
 *
 * @param next_hop
 *  The address of the next-hop.
 *
 * @param sw_if_index
 *  The index of the interface.
 *
 * @param next_hop_fib_index,
 *  The fib index of the next-hop for recursive resolution
 *
 * @param next_hop_weight
 *  [un]equal cost path weight
 *
 * @param  next_hop_label_stack
 *  The path's out-going label stack. NULL is there is none.
 *
 * @param  pf
 *  Flags for the path
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t fib_table_entry_path_add(u32 fib_index,
						 const fib_prefix_t *prefix,
						 fib_source_t source,
						 fib_entry_flag_t flags,
						 dpo_proto_t next_hop_proto,
						 const ip46_address_t *next_hop,
						 u32 next_hop_sw_if_index,
						 u32 next_hop_fib_index,
						 u32 next_hop_weight,
						 fib_mpls_label_t *next_hop_label_stack,
						 fib_route_path_flags_t pf);
/**
 * @brief
 *  Add n paths to an entry (aka route) in the FIB. If the entry does not
 *  exist, it will be created.
 * See the documentation for fib_route_path_t for more descirptions of
 * the path parameters.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to add
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 * @param flags
 *  Flags for the entry.
 *
 * @param rpaths
 *  A vector of paths. Not const since they may be modified.
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t fib_table_entry_path_add2(u32 fib_index,
						  const fib_prefix_t *prefix,
						  fib_source_t source,
						  fib_entry_flag_t flags,
						  fib_route_path_t *rpath);

/**
 * @brief
 * remove one path to an entry (aka route) in the FIB. If this is the entry's
 * last path, then the entry will be removed, unless it has other sources.
 * See the documentation for fib_route_path_t for more descirptions of
 * the path parameters.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to add
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 * @paran next_hop_proto
 *  The protocol of the next hop. This cannot be derived in the event that
 * the next hop is all zeros.
 *
 * @param next_hop
 *  The address of the next-hop.
 *
 * @param sw_if_index
 *  The index of the interface.
 *
 * @param next_hop_fib_index,
 *  The fib index of the next-hop for recursive resolution
 *
 * @param next_hop_weight
 *  [un]equal cost path weight
 *
 * @param  pf
 *  Flags for the path
 */
extern void fib_table_entry_path_remove(u32 fib_index,
					const fib_prefix_t *prefix,
					fib_source_t source,
					dpo_proto_t next_hop_proto,
					const ip46_address_t *next_hop,
					u32 next_hop_sw_if_index,
					u32 next_hop_fib_index,
					u32 next_hop_weight,
					fib_route_path_flags_t pf);

/**
 * @brief
 * Remove n paths to an entry (aka route) in the FIB. If this is the entry's
 * last path, then the entry will be removed, unless it has other sources.
 * See the documentation for fib_route_path_t for more descirptions of
 * the path parameters.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to add
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 * @param rpaths
 *  A vector of paths.
 */
extern void fib_table_entry_path_remove2(u32 fib_index,
					 const fib_prefix_t *prefix,
					 fib_source_t source,
					 fib_route_path_t *paths);

/**
 * @brief
 *  Update an entry to have a new set of paths. If the entry does not
 *  exist, it will be created.
 * The difference between an 'path-add' and an update, is that path-add is
 * an incremental addition of paths, whereas an update is a wholesale swap.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to add
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 * @param rpaths
 *  A vector of paths. Not const since they may be modified.
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t fib_table_entry_update(u32 fib_index,
					       const fib_prefix_t *prefix,
					       fib_source_t source,
					       fib_entry_flag_t flags,
					       fib_route_path_t *paths);

/**
 * @brief
 *  Update the entry to have just one path. If the entry does not
 *  exist, it will be created.
 * See the documentation for fib_route_path_t for more descirptions of
 * the path parameters.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to add
 *
 * @param source
 *  The ID of the client/source adding the entry.
 *
 * @param flags
 *  Flags for the entry.
 *
 * @paran next_hop_proto
 *  The protocol of the next hop. This cannot be derived in the event that
 * the next hop is all zeros.
 *
 * @param next_hop
 *  The address of the next-hop.
 *
 * @param sw_if_index
 *  The index of the interface.
 *
 * @param next_hop_fib_index,
 *  The fib index of the next-hop for recursive resolution
 *
 * @param next_hop_weight
 *  [un]equal cost path weight
 *
 * @param  next_hop_label_stack
 *  The path's out-going label stack. NULL is there is none.
 *
 * @param  pf
 *  Flags for the path
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t fib_table_entry_update_one_path(u32 fib_index,
							const fib_prefix_t *prefix,
							fib_source_t source,
							fib_entry_flag_t flags,
							dpo_proto_t next_hop_proto,
							const ip46_address_t *next_hop,
							u32 next_hop_sw_if_index,
							u32 next_hop_fib_index,
							u32 next_hop_weight,
							fib_mpls_label_t *next_hop_label_stack,
							fib_route_path_flags_t pf);

/**
 * @brief
 *  Add a MPLS local label for the prefix/route. If the entry does not
 *  exist, it will be created. In theory more than one local label can be
 *  added, but this is not yet supported.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to which to add the label
 *
 * @param label
 *  The MPLS label to add
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t fib_table_entry_local_label_add(u32 fib_index,
							const fib_prefix_t *prefix,
							mpls_label_t label);
/**
 * @brief
 *  remove a MPLS local label for the prefix/route.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to which to add the label
 *
 * @param label
 *  The MPLS label to add
 */
extern void fib_table_entry_local_label_remove(u32 fib_index,
					       const fib_prefix_t *prefix,
					       mpls_label_t label);

/**
 * @brief
 *  Delete a FIB entry. If the entry has no more sources, then it is
 * removed from the table.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @param prefix
 *  The prefix for the entry to remove
 *
 * @param source
 *  The ID of the client/source adding the entry.
 */
extern void fib_table_entry_delete(u32 fib_index,
				   const fib_prefix_t *prefix,
				   fib_source_t source);

/**
 * @brief
 *  Delete a FIB entry. If the entry has no more sources, then it is
 * removed from the table.
 *
 * @param entry_index
 *  The index of the FIB entry
 *
 * @param source
 *  The ID of the client/source adding the entry.
 */
extern void fib_table_entry_delete_index(fib_node_index_t entry_index,
					 fib_source_t source);

/**
 * @brief
 *  Return the stats index for a FIB entry
 * @param fib_index
 *  The table's FIB index
 * @param prefix
 *  The entry's prefix's
 */
extern u32 fib_table_entry_get_stats_index(u32 fib_index,
                                           const fib_prefix_t *prefix);

/**
 * @brief
 *  Flush all entries from a table for the source
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @paran proto
 *  The protocol of the entries in the table
 *
 * @param source
 *  the source to flush
 */
extern void fib_table_flush(u32 fib_index,
			    fib_protocol_t proto,
			    fib_source_t source);

/**
 * @brief
 *  Resync all entries from a table for the source
 *  this is the mark part of the mark and sweep algorithm.
 *  All entries in this FIB that are sourced by 'source' are marked
 *  as stale.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @paran proto
 *  The protocol of the entries in the table
 *
 * @param source
 *  the source to flush
 */
extern void fib_table_mark(u32 fib_index,
                           fib_protocol_t proto,
                           fib_source_t source);

/**
 * @brief
 *  Signal that the table has converged, i.e. all updates are complete.
 *  this is the sweep part of the mark and sweep algorithm.
 *  All entries in this FIB that are sourced by 'source' and marked
 *  as stale are flushed.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @paran proto
 *  The protocol of the entries in the table
 *
 * @param source
 *  the source to flush
 */
extern void fib_table_sweep(u32 fib_index,
                            fib_protocol_t proto,
                            fib_source_t source);

/**
 * @brief
 *  Get the index of the FIB bound to the interface
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @param sw_if_index
 *  The interface index
 *
 * @return fib_index
 *  The index of the FIB
 */
extern u32 fib_table_get_index_for_sw_if_index(fib_protocol_t proto,
					       u32 sw_if_index);

/**
 * @brief
 *  Get the Table-ID of the FIB bound to the interface
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @param sw_if_index
 *  The interface index
 *
 * @return fib_index
 *  The tableID of the FIB
 */
extern u32 fib_table_get_table_id_for_sw_if_index(fib_protocol_t proto,
						  u32 sw_if_index);

/**
 * @brief
 *  Get the Table-ID of the FIB from protocol and index
 *
 * @param fib_index
 *  The FIB index
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @return fib_index
 *  The tableID of the FIB
 */
extern u32 fib_table_get_table_id(u32 fib_index, fib_protocol_t proto);

/**
 * @brief
 *  Get the index of the FIB for a Table-ID. This DOES NOT create the
 * FIB if it does not exist.
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @param table-id
 *  The Table-ID
 *
 * @return fib_index
 *  The index of the FIB, which may be INVALID.
 */
extern u32 fib_table_find(fib_protocol_t proto, u32 table_id);


/**
 * @brief
 *  Get the index of the FIB for a Table-ID. This DOES create the
 * FIB if it does not exist.
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @param table-id
 *  The Table-ID
 *
 * @return fib_index
 *  The index of the FIB
 *
 * @param source
 *  The ID of the client/source.
 */
extern u32 fib_table_find_or_create_and_lock(fib_protocol_t proto,
					     u32 table_id,
                                             fib_source_t source);

/**
 * @brief
 *  Get the index of the FIB for a Table-ID. This DOES create the
 * FIB if it does not exist.
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @param table-id
 *  The Table-ID
 *
 * @return fib_index
 *  The index of the FIB
 *
 * @param source
 *  The ID of the client/source.
 *
 * @param name
 *  The client is choosing the name they want the table to have
 */
extern u32 fib_table_find_or_create_and_lock_w_name(fib_protocol_t proto,
                                                    u32 table_id,
                                                    fib_source_t source,
                                                    const u8 *name);

/**
 * @brief
 *  Create a new table with no table ID. This means it does not get
 * added to the hash-table and so can only be found by using the index returned.
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @param fmt
 *  A string to describe the table
 *
 * @param source
 *  The ID of the client/source.
 *
 * @return fib_index
 *  The index of the FIB
 */
extern u32 fib_table_create_and_lock(fib_protocol_t proto,
                                     fib_source_t source,
                                     const char *const fmt,
                                     ...);

/**
 * @brief
 *  Get the flow hash configured used by the table
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @paran proto
 *  The protocol the packets the flow hash will be calculated for.
 *
 * @return The flow hash config
 */
extern flow_hash_config_t fib_table_get_flow_hash_config(u32 fib_index,
							 fib_protocol_t proto);

/**
 * @brief
 *  Get the flow hash configured used by the protocol
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @return The flow hash config
 */
extern flow_hash_config_t fib_table_get_default_flow_hash_config(fib_protocol_t proto);

/**
 * @brief
 *  Set the flow hash configured used by the table
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @param hash_config
 *  The flow-hash config to set
 *
 * @return none
 */
extern void fib_table_set_flow_hash_config(u32 fib_index,
                                           fib_protocol_t proto,
                                           flow_hash_config_t hash_config);

/**
 * @brief
 * Take a reference counting lock on the table
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @param source
 *  The ID of the client/source.
 */ 
extern void fib_table_unlock(u32 fib_index,
			     fib_protocol_t proto,
                             fib_source_t source);

/**
 * @brief
 * Release a reference counting lock on the table. When the last lock
 * has gone. the FIB is deleted.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @param source
 *  The ID of the client/source.
 */ 
extern void fib_table_lock(u32 fib_index,
			   fib_protocol_t proto,
                           fib_source_t source);

/**
 * @brief
 * Return the number of entries in the FIB added by a given source.
 *
 * @param fib_index
 *  The index of the FIB
 *
 * @paran proto
 *  The protocol of the FIB (and thus the entries therein)
 *
 * @return number of sourced entries.
 */ 
extern u32 fib_table_get_num_entries(u32 fib_index,
				     fib_protocol_t proto,
				     fib_source_t source);

/**
 * @brief
 * Get a pointer to a FIB table
 */
extern fib_table_t *fib_table_get(fib_node_index_t index,
				  fib_protocol_t proto);

/**
 * @brief return code controlling how a table walk proceeds
 */
typedef enum fib_table_walk_rc_t_
{
    /**
     * Continue on to the next entry
     */
    FIB_TABLE_WALK_CONTINUE,
    /**
     * Do no traverse down this sub-tree
     */
    FIB_TABLE_WALK_SUB_TREE_STOP,
    /**
     * Stop the walk completely
     */
    FIB_TABLE_WALK_STOP,
} fib_table_walk_rc_t;

/**
 * @brief Call back function when walking entries in a FIB table
 */
typedef fib_table_walk_rc_t (*fib_table_walk_fn_t)(fib_node_index_t fei,
                                                   void *ctx);

/**
 * @brief Walk all entries in a FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void fib_table_walk(u32 fib_index,
                           fib_protocol_t proto,
                           fib_table_walk_fn_t fn,
                           void *ctx);

/**
 * @brief Walk all entries in a FIB table
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void fib_table_walk_w_src(u32 fib_index,
                                 fib_protocol_t proto,
                                 fib_source_t src,
                                 fib_table_walk_fn_t fn,
                                 void *ctx);

/**
 * @brief Walk all entries in a sub-tree FIB table. The 'root' paraneter
 * is the prefix at the root of the sub-tree.
 * N.B: This is NOT safe to deletes. If you need to delete walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void fib_table_sub_tree_walk(u32 fib_index,
                                    fib_protocol_t proto,
                                    const fib_prefix_t *root,
                                    fib_table_walk_fn_t fn,
                                    void *ctx);

/**
 * @brief format (display) the memory used by the FIB tables
 */
extern u8 *format_fib_table_memory(u8 *s, va_list *args);

/**
 * Debug function
 */
#if CLIB_DEBUG > 0
extern void fib_table_assert_empty(const fib_table_t *fib_table);
#endif


#endif
