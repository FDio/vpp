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
 * The label or MPLS FIB.
 *
 * some nomencleture:
 *  FEC: Forwarding equivalent class. A 
 *  FPI: A description of the FEC. For example; all traffic destined to 10.0.0.0/24,
 *       pseudo-wire 3, CEs A, B and C, MPLS label 19, etc.
 *  MOI: MPLS output information. A description of how to forward a packet that
 *       matches a given label.
 *
 * The lfib instance is a database indexed by an MPLS label. There are potentially
 * many lfibs in the system. ingress MPLS labelled packets are lookuped up in the
 * appropriate lfib instance to determine the next actions.
 *
 * What the lfib isn't
 *  - an FPI DB. The lfib is not indexed on FPI. Or more strictly the only FPI it
 *    suuports is an MPLS label.
 *  - A manager of the router's label space - the label switch database. This
 *    function must be provided by another entity in the system. Consequently
 *    this lfib will treat all MOIs for the same label as EMCP.
 *    There is also therefore no conecpt of a 'source' like there is in IP FIB.
 *    All contentions are expected to be resolved by the LSD. For labels this is
 *    a safe assumption as the label space is a locally (even with SR) managed
 *    resource, and so contentions are resolved when the resource is assigned.
 */
#ifndef __LFIB_H__
#define __LFIB_H__

#include <vnet/vnet.h>
#include <vnet/fib/fib_types.h>

/**
 * The representation of a single LFIB instance
 */
typedef struct lfib_t_ 
{
    /**
     * The LFIB's table.
     * This is a pointer to a table, since the lfib_t objects live in a
     * reallocable vector. We don't want to be copying the large tables.
     * cache line performace is moot - there is a very low likelihood the label
     * we lookup will lie on the same cachline as this pointer does - the table
     * being rather large an'all.
     */
    struct lfib_table_t_ *lf_table;

    /**
     * The table ID is an identifier given by the control plane
     */
    u32 lf_table_id;

    /**
     * The index is this LFIBs's place in the vector of all LFIBs
     */
    u32 lf_index;

    /**
     * A description of the Table
     */
    u8 *lf_desc;

    /**
     * Number of locks on the table.
     */
    u16 lf_locks;

    
} lfib_t;

/**
 * LFIB main
 */
typedef struct lfib_main_t_
{
    /**
     * A pool of all the lfbis
     */
    lfib_t *lfibs;

    /**
     * A hash table to lookup the lfib by table ID
     */
    uword *lfib_index_by_table_id;
} lfib_main_t;

/**
 * Global instance of lfbi main
 */
extern lfib_main_t lfib_main;

static inline lfib_t*
lfib_get (fib_node_index_t index)
{
    if (!pool_is_free_index(lfib_main.lfibs, index))
	return (pool_elt_at_index(lfib_main.lfibs, index));
    return (NULL);
}

extern u32 lfib_find_or_create_and_lock(u32 table_id);
extern lfib_t * lfib_find(u32 table_id);

extern void lfib_unlock(u32 table_id);
extern void lfib_lock(u32 index);

extern u8 *format_lfib_table_name(u8 * s, va_list * args);


#endif
