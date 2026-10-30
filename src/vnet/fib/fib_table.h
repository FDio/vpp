/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
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
 *  Default names for IP4, IP6, and MPLS FIB table index 0.
 *  Nominally like "ipv4-VRF:0", but this will override that name if set
 *  in a config section of the startup.conf file.
 */
extern char *fib_table_default_names[FIB_PROTOCOL_MAX];

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
__clib_export extern fib_node_index_t fib_table_lookup(u32 fib_index,
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
__clib_export extern fib_node_index_t fib_table_lookup_exact_match(u32 fib_index,
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
__clib_export extern fib_node_index_t fib_table_entry_special_add(u32 fib_index,
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
__clib_export extern fib_node_index_t fib_table_entry_special_dpo_add(u32 fib_index,
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
__clib_export extern fib_node_index_t fib_table_entry_special_dpo_update (u32 fib_index,
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
__clib_export extern void fib_table_entry_special_remove(u32 fib_index,
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
__clib_export extern fib_node_index_t fib_table_entry_path_add(u32 fib_index,
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
__clib_export extern fib_node_index_t fib_table_entry_path_add2(u32 fib_index,
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
__clib_export extern void fib_table_entry_path_remove(u32 fib_index,
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
__clib_export extern void fib_table_entry_path_remove2(u32 fib_index,
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
__clib_export extern fib_node_index_t fib_table_entry_update(u32 fib_index,
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
__clib_export extern fib_node_index_t fib_table_entry_update_one_path(u32 fib_index,
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
__clib_export extern fib_node_index_t fib_table_entry_local_label_add(u32 fib_index,
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
__clib_export extern void fib_table_entry_local_label_remove(u32 fib_index,
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
__clib_export extern void fib_table_entry_delete(u32 fib_index,
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
__clib_export extern void fib_table_entry_delete_index(fib_node_index_t entry_index,
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
__clib_export extern void fib_table_flush(u32 fib_index,
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
__clib_export extern void fib_table_mark(u32 fib_index,
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
__clib_export extern void fib_table_sweep(u32 fib_index,
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
__clib_export extern u32 fib_table_get_index_for_sw_if_index(fib_protocol_t proto,
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
__clib_export extern u32 fib_table_get_table_id_for_sw_if_index(fib_protocol_t proto,
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
__clib_export extern u32 fib_table_get_table_id(u32 fib_index, fib_protocol_t proto);

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
 *  The index of the FIB, which may be INVALID. A table ID with no FIB yields
 *  ~0. This function neither validates the table ID nor logs a warning, so a
 *  caller must check the result before passing it to fib_table_get_or_null()
 *  or to any of the entry points below, where ~0 is rejected as a bad index.
 */
__clib_export extern u32 fib_table_find(fib_protocol_t proto, u32 table_id);


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
__clib_export extern u32 fib_table_find_or_create_and_lock(fib_protocol_t proto,
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
__clib_export extern u32 fib_table_create_and_lock(fib_protocol_t proto,
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
__clib_export extern flow_hash_config_t fib_table_get_flow_hash_config(u32 fib_index,
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
__clib_export extern void fib_table_set_flow_hash_config(u32 fib_index,
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
__clib_export extern void fib_table_unlock(u32 fib_index,
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
__clib_export extern void fib_table_lock(u32 fib_index,
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
__clib_export extern u32 fib_table_get_num_entries(u32 fib_index,
				     fib_protocol_t proto,
				     fib_source_t source);

/**
 * @brief
 * Get a pointer to a FIB table
 *
 * This function does not validate the index. The index is used to index the
 * per-protocol FIB pool as given, so ~0, an out-of-range index and a free pool
 * slot all resolve to a pointer outside the pool. Use fib_table_get_or_null()
 * unless the index is known to name a live table.
 */
__clib_export extern fib_table_t *fib_table_get(fib_node_index_t index,
				  fib_protocol_t proto);

/**
 * @brief
 * Get a pointer to a FIB table, validating the index
 *
 * Unlike fib_table_get(), this rejects ~0, an out-of-range index and a
 * free pool slot, and returns NULL instead. Callers that derive the index
 * from an interface binding or from another untrusted source must use this
 * accessor.
 *
 * The entry points declared in this header handle a table index in one of
 * three ways.
 *
 * fib_table_get() is the only accessor that returns a table pointer without
 * validating the index; it indexes the pool as given.
 *
 * fib_table_lookup(), fib_table_lookup_exact_match(),
 * fib_table_get_table_id() and format_fib_table_name() call this function and
 * log nothing, because they run per entry on lookup and show paths, where a
 * warning per call would flood the log. In that order they return
 * FIB_NODE_INDEX_INVALID, FIB_NODE_INDEX_INVALID, ~0 and the string
 * "unknown".
 *
 * fib_table_get_table_id_for_sw_if_index(), which derives the index from a
 * sw_if_index first, is silent in the same way and returns ~0.
 * fib_table_entry_delete(), fib_table_entry_local_label_remove() and
 * fib_table_entry_get_stats_index() reach this function through
 * fib_table_lookup_exact_match(); the first two return without touching an
 * entry, and the last returns ~0, the value an entry without a load-balance
 * DPO already yields.
 *
 * The remaining entry points call this function through
 * fib_table_get_checked(), which reports a rejected index with clib_warning()
 * naming the entry point whose check fired: fib_table_get_less_specific(),
 * fib_table_entry_special_dpo_add(), fib_table_entry_special_dpo_update(),
 * fib_table_entry_special_remove(), fib_table_entry_path_add2(),
 * fib_table_entry_path_remove2(), fib_table_entry_update(),
 * fib_table_lock(), fib_table_unlock(), fib_table_get_flow_hash_config(),
 * fib_table_set_flow_hash_config(), fib_table_get_num_entries(),
 * fib_table_walk(), fib_table_sub_tree_walk(), fib_table_mark() and
 * fib_table_sweep(). fib_table_entry_special_add(),
 * fib_table_entry_path_add(), fib_table_entry_path_remove(),
 * fib_table_entry_update_one_path(), fib_table_entry_local_label_add(),
 * fib_table_flush() and fib_table_walk_w_src() report the name of the entry
 * point they delegate to instead of their own. fib_table_fwding_dpo_update()
 * and fib_table_fwding_dpo_remove(), declared in fib_internal.h, check and
 * report under their own names.
 *
 * A rejected index yields the failure value of the entry point that rejected
 * it. For the checking entry points above that is: nothing for those that only
 * walk or update the table, FIB_NODE_INDEX_INVALID for those returning a
 * fib_node_index_t, 0 for fib_table_get_num_entries(), the protocol default
 * for fib_table_get_flow_hash_config(), and ~0 for
 * fib_table_find_or_create_and_lock(),
 * fib_table_find_or_create_and_lock_w_name() and fib_table_create_and_lock().
 * Those three take a table ID rather than a fib_index and validate the index
 * that the protocol specific create returns; their warnings name
 * fib_table_find_or_create_and_lock_i() and fib_table_create_and_lock().
 */
__clib_export extern fib_table_t *fib_table_get_or_null(u32 fib_index,
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
__clib_export extern void fib_table_walk(u32 fib_index,
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
extern void fib_table_assert_empty(const fib_table_t *fib_table);


#endif
