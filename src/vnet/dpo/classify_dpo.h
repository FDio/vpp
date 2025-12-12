/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

#ifndef __CLASSIFY_DPO_H__
#define __CLASSIFY_DPO_H__

#include <vnet/vnet.h>
#include <vnet/mpls/packet.h>
#include <vnet/dpo/dpo.h>

/**
 * A representation of an MPLS label for imposition in the data-path
 */
typedef struct classify_dpo_t
{
    /**
     * required for pool_get_aligned.
     */
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

    dpo_proto_t cd_proto;

    u32 cd_table_index;

    /**
     * Number of locks/users of the label
     */
    u16 cd_locks;
} classify_dpo_t;

extern index_t classify_dpo_create(dpo_proto_t proto,
                                   u32 classify_table_index);

extern u8* format_classify_dpo(u8 *s, va_list *args);

/*
 * Encapsulation violation for fast data-path access
 */
extern classify_dpo_t *classify_dpo_pool;

static inline classify_dpo_t *
classify_dpo_get (index_t index)
{
    return (pool_elt_at_index(classify_dpo_pool, index));
}

extern void classify_dpo_module_init(void);

#endif
