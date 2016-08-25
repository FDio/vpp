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

#include <vnet/lfib/lfib.h>
#include <vnet/lfib/lfib_table.h>
#include <vnet/mpls/mpls_types.h>
#include <vnet/dpo/punt_dpo.h>
#include <vnet/dpo/lookup_dpo.h>

lfib_main_t lfib_main;

static void
lfib_init (lfib_t *lfib)
{
    lfib->lf_table = lfib_table_create();
}


static inline u32
lfib_index_from_table_id (u32 table_id)
{
    lfib_main_t *lfm = &lfib_main;
    uword * p;

    p = hash_get (lfm->lfib_index_by_table_id, table_id);
    if (!p)
	return FIB_NODE_INDEX_INVALID;

    return p[0];
}

static inline lfib_t*
lfib_create (u32 table_id,
             const char *fmt,
             ...)
{
    dpo_id_t dpo = DPO_NULL;
    mpls_eos_bit_t eos;
    lfib_t * lfib;
    va_list ap;

    va_start(ap, fmt);

    pool_get_aligned(lfib_main.lfibs, lfib, CLIB_CACHE_LINE_BYTES);

    lfib->lf_table_id = table_id;
    lfib->lf_index = lfib - lfib_main.lfibs;
    lfib->lf_desc = va_format(lfib->lf_desc, fmt, &ap);
    lfib_init(lfib);

    hash_set (lfib_main.lfib_index_by_table_id,
	      table_id,
	      lfib->lf_index);

    /*
     * non-default forwarding for the special labels.
     */

    /*
     * PUNT the router alert, both EOS and non-eos
     */
    FOR_EACH_MPLS_EOS_BIT(eos)
    {  
        lfib_table_entry_special_create(lfib->lf_index,
                                        MPLS_IETF_ROUTER_ALERT_LABEL,
                                        eos,
                                        punt_dpo_get(DPO_PROTO_MPLS));
    }

    /*
     * IPv4 explicit NULL EOS lookup in the interface's IPv4 table
     */
    lookup_dpo_add_or_lock_w_fib_index(0, // unused
                                       DPO_PROTO_IP4,
                                       LOOKUP_INPUT_DST_ADDR,
                                       LOOKUP_TABLE_FROM_INPUT_INTERFACE,
                                       &dpo);
    lfib_table_entry_special_create(lfib->lf_index,
                                    MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL,
                                    MPLS_EOS,
                                    &dpo);
    lookup_dpo_add_or_lock_w_fib_index(0, //unsued
                                       DPO_PROTO_MPLS,
                                       LOOKUP_INPUT_DST_ADDR,
                                       LOOKUP_TABLE_FROM_INPUT_INTERFACE,
                                       &dpo);
    lfib_table_entry_special_create(lfib->lf_index,
                                    MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL,
                                    MPLS_NON_EOS,
                                    &dpo);

    /*
     * IPv6 explicit NULL EOS lookup in the interface's IPv6 table
     */
    lookup_dpo_add_or_lock_w_fib_index(0, //unused
                                       DPO_PROTO_IP6,
                                       LOOKUP_INPUT_DST_ADDR,
                                       LOOKUP_TABLE_FROM_INPUT_INTERFACE,
                                       &dpo);
    lfib_table_entry_special_create(lfib->lf_index,
                                    MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL,
                                    MPLS_EOS,
                                    &dpo);
    lookup_dpo_add_or_lock_w_fib_index(0, // unsued
                                       DPO_PROTO_MPLS,
                                       LOOKUP_INPUT_DST_ADDR,
                                       LOOKUP_TABLE_FROM_INPUT_INTERFACE,
                                       &dpo);
    lfib_table_entry_special_create(lfib->lf_index,
                                    MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL,
                                    MPLS_NON_EOS,
                                    &dpo);

    va_end(ap);
    return (lfib);
}

static void
lfib_destroy (lfib_t *lfib)
{
    mpls_eos_bit_t eos;

    FOR_EACH_MPLS_EOS_BIT(eos)
    {  
        lfib_table_entry_delete(
            lfib_table_lookup(lfib->lf_index,
                              MPLS_IETF_ROUTER_ALERT_LABEL,
                              eos));
        lfib_table_entry_delete(
            lfib_table_lookup(lfib->lf_index,
                              MPLS_IETF_IPV6_EXPLICIT_NULL_LABEL,
                              eos));
        lfib_table_entry_delete(
            lfib_table_lookup(lfib->lf_index,
                              MPLS_IETF_IPV4_EXPLICIT_NULL_LABEL,
                              eos));

    }
    hash_unset(lfib_main.lfib_index_by_table_id,
               lfib->lf_table_id);

    lfib_table_delete(lfib->lf_table);
    pool_put(lfib_main.lfibs, lfib);
}

void
lfib_lock (u32 index)
{
    lfib_t *lfib;

    lfib = lfib_get(index);

    ASSERT (NULL != lfib);

    lfib->lf_locks++;
}

void
lfib_unlock (u32 index)
{
    lfib_t *lfib;

    lfib = lfib_get(index);

    ASSERT (NULL != lfib);

    lfib->lf_locks--;

    if (0 == lfib->lf_locks)
    {
        lfib_destroy(lfib);
    }
}

u32
lfib_find_or_create_and_lock (u32 table_id)
{
    fib_node_index_t index;
    lfib_t *lfib;

    index = lfib_index_from_table_id(table_id);
    if (FIB_NODE_INDEX_INVALID == index)
    {
	lfib = lfib_create(table_id,
                           "LFIB: table-id:%d",
                           table_id);
    }
    else
    {
        lfib = lfib_get(index);
    }

    lfib->lf_locks++;

    return (lfib->lf_index);
}

lfib_t *
lfib_find (u32 table_id)
{
    fib_node_index_t index;
    lfib_t *lfib = NULL;

    index = lfib_index_from_table_id(table_id);
    if (FIB_NODE_INDEX_INVALID != index)
    {
        lfib = lfib_get(index);
    }

    return (lfib);
}

u8 *
format_lfib_table_name (u8 * s, va_list * args)
{
    u32 table_id = va_arg(args, u32);
    lfib_t *lfib;
    u32 index;

    index = lfib_index_from_table_id(table_id);
    if (FIB_NODE_INDEX_INVALID == index)
	return (format(s, "LFIB %d does not exist", table_id));

    lfib = lfib_get(index);

    return (format(s, "%v", lfib->lf_desc)); 
}
