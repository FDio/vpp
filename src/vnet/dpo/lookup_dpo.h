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

#ifndef __LOOKUP_DPO_H__
#define __LOOKUP_DPO_H__

#include <vnet/vnet.h>
#include <vnet/fib/fib_types.h>
#include <vnet/dpo/dpo.h>

/**
 * Switch to use the packet's source or destination address for lookup
 */
typedef enum lookup_input_t_ {
    LOOKUP_INPUT_SRC_ADDR,
    LOOKUP_INPUT_DST_ADDR,
} __attribute__ ((packed)) lookup_input_t;

#define LOOKUP_INPUTS {                         \
    [LOOKUP_INPUT_SRC_ADDR] = "src-address",    \
    [LOOKUP_INPUT_DST_ADDR] = "dst-address",    \
}

/**
 * Switch to use the packet's source or destination address for lookup
 */
typedef enum lookup_table_t_ {
    LOOKUP_TABLE_FROM_INPUT_INTERFACE,
    LOOKUP_TABLE_FROM_CONFIG,
} __attribute__ ((packed)) lookup_table_t;

#define LOOKUP_TABLES {                                   \
    [LOOKUP_TABLE_FROM_INPUT_INTERFACE] = "table-input-interface",    \
    [LOOKUP_TABLE_FROM_CONFIG] = "table-configured",         \
}

/**
 * Switch to use the packet's source or destination address for lookup
 */
typedef enum lookup_cast_t_ {
    LOOKUP_UNICAST,
    LOOKUP_MULTICAST,
} __attribute__ ((packed)) lookup_cast_t;

#define LOOKUP_CASTS {                 \
    [LOOKUP_UNICAST]   = "unicast",    \
    [LOOKUP_MULTICAST] = "multicast",  \
}

/**
 * A representation of an MPLS label for imposition in the data-path
 */
typedef struct lookup_dpo_t
{
    /**
     * The FIB, or interface from which to get a FIB, in which to perform
     * the next lookup;
     */
    fib_node_index_t lkd_fib_index;

    /**
     * The protocol of the FIB for the lookup, and hence
     * the protocol of the packet
     */
    dpo_proto_t lkd_proto;

    /**
     * Switch to use src or dst address
     */
    lookup_input_t lkd_input;

    /**
     * Switch to use the table index passed, or the table of the input interface
     */
    lookup_table_t lkd_table;

    /**
     * Unicast of rmulticast FIB lookup
     */
    lookup_cast_t lkd_cast;

    /**
     * Number of locks
     */
    u16 lkd_locks;
} lookup_dpo_t;

extern void lookup_dpo_add_or_lock_w_fib_index(fib_node_index_t fib_index,
                                               dpo_proto_t proto,
                                               lookup_cast_t cast,
                                               lookup_input_t input,
                                               lookup_table_t table,
                                               dpo_id_t *dpo);
extern void lookup_dpo_add_or_lock_w_table_id(u32 table_id,
                                              dpo_proto_t proto,
                                              lookup_cast_t cast,
                                              lookup_input_t input,
                                              lookup_table_t table,
                                              dpo_id_t *dpo);

extern u8* format_lookup_dpo(u8 *s, va_list *args);

/*
 * Encapsulation violation for fast data-path access
 */
extern lookup_dpo_t *lookup_dpo_pool;

static inline lookup_dpo_t *
lookup_dpo_get (index_t index)
{
    return (pool_elt_at_index(lookup_dpo_pool, index));
}

extern void lookup_dpo_module_init(void);

#endif
