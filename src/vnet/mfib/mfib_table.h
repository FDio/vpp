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

#ifndef __MFIB_TABLE_H__
#define __MFIB_TABLE_H__

#include <vnet/ip/ip.h>
#include <vnet/adj/adj.h>
#include <vnet/dpo/replicate_dpo.h>

#include <vnet/mfib/mfib_types.h>

/**
 * Keep a lock per-source and a total
 */
#define MFIB_TABLE_N_LOCKS (MFIB_N_SOURCES+1)
#define MFIB_TABLE_TOTAL_LOCKS MFIB_N_SOURCES

/**
 * @brief
 *   A protocol Independent IP multicast FIB table
 */
typedef struct mfib_table_t_
{
    /**
     * A union of the protocol specific FIBs that provide the
     * underlying LPM mechanism.
     * This element is first in the struct so that it is in the
     * first cache line.
     */
    union {
        ip4_mfib_t v4;
        ip6_mfib_t v6;
    };

    /**
     * Which protocol this table serves. Used to switch on the union above.
     */
    fib_protocol_t mft_proto;

    /**
     * number of locks on the table
     */
    u16 mft_locks[MFIB_TABLE_N_LOCKS];

    /**
     * Table ID (hash key) for this FIB.
     */
    u32 mft_table_id;

    /**
     * Index into FIB vector.
     */
    fib_node_index_t mft_index;

    /**
     * Total route counters
     */
    u32 mft_total_route_counts;

    /**
     * Table description
     */
    u8* mft_desc;
} mfib_table_t;

/**
 * @brief
 *  Format the description/name of the table
 */
extern u8* format_mfib_table_name(u8* s, va_list ap);

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
extern fib_node_index_t mfib_table_lookup(u32 fib_index,
                                         const mfib_prefix_t *prefix);

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
extern fib_node_index_t mfib_table_lookup_exact_match(u32 fib_index,
                                                      const mfib_prefix_t *prefix);

/**
 * @brief
 * Add a new (with no replication) or lock an existing entry
 *
 * @param prefix
 *  The prefix for the entry to add
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t mfib_table_entry_update(u32 fib_index,
                                                const mfib_prefix_t *prefix,
                                                mfib_source_t source,
                                                fib_rpf_id_t rpf_id,
                                                mfib_entry_flags_t flags);

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
 *  A vector of paths.
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t mfib_table_entry_path_update(u32 fib_index,
                                                     const mfib_prefix_t *prefix,
                                                     mfib_source_t source,
                                                     const fib_route_path_t *rpath,
                                                     mfib_itf_flags_t flags);

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
extern void mfib_table_entry_path_remove(u32 fib_index,
                                         const mfib_prefix_t *prefix,
                                         mfib_source_t source,
                                         const fib_route_path_t *paths);



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
extern void mfib_table_entry_delete(u32 fib_index,
                                    const mfib_prefix_t *prefix,
                                    mfib_source_t source);

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
extern void mfib_table_entry_delete_index(fib_node_index_t entry_index,
                                          mfib_source_t source);

/**
 * @brief
 *  Add a 'special' entry to the mFIB that links to the DPO passed
 *  A special entry is an entry that the FIB is not expect to resolve
 *  via the usual mechanisms (i.e. recurisve or neighbour adj DB lookup).
 *  Instead the client/source provides the index of a replicate DPO to link to.
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
 * @param rep_dpo
 *  The replicate DPO index to link to.
 *
 * @return
 *  the index of the fib_entry_t that is created (or existed already).
 */
extern fib_node_index_t mfib_table_entry_special_add(u32 fib_index,
                                                     const mfib_prefix_t *prefix,
                                                     mfib_source_t source,
                                                     mfib_entry_flags_t flags,
                                                     index_t rep_dpo);

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
extern void mfib_table_flush(u32 fib_index,
                             fib_protocol_t proto,
                             mfib_source_t source);

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
extern u32 mfib_table_get_index_for_sw_if_index(fib_protocol_t proto,
                                                u32 sw_if_index);

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
extern u32 mfib_table_find(fib_protocol_t proto, u32 table_id);


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
extern u32 mfib_table_find_or_create_and_lock(fib_protocol_t proto,
                                              u32 table_id,
                                              mfib_source_t source);


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
extern void mfib_table_unlock(u32 fib_index,
                              fib_protocol_t proto,
                              mfib_source_t source);

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
extern void mfib_table_lock(u32 fib_index,
                            fib_protocol_t proto,
                            mfib_source_t source);

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
extern u32 mfib_table_get_num_entries(u32 fib_index,
                                      fib_protocol_t proto);

/**
 * @brief
 * Get a pointer to a FIB table
 */
extern mfib_table_t *mfib_table_get(fib_node_index_t index,
                                    fib_protocol_t proto);

/**
 * @brief Call back function when walking entries in a FIB table
 */
typedef int (*mfib_table_walk_fn_t)(fib_node_index_t fei,
                                    void *ctx);

/**
 * @brief Walk all entries in a FIB table
 * N.B: This is NOT safe to deletes. If you need to delete, walk the whole
 * table and store elements in a vector, then delete the elements
 */
extern void mfib_table_walk(u32 fib_index,
                            fib_protocol_t proto,
                            mfib_table_walk_fn_t fn,
                            void *ctx);

#endif
