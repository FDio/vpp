/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2016 Cisco and/or its affiliates.
 */

/**
 * @brief
 * The data-path object representing L3 proxy. An L3 proxy is when VPP has
 * an address in the FIB that is also assigned to an attached host.
 */

#ifndef __L3_PROXY_DPO_H__
#define __L3_PROXY_DPO_H__

#include <vnet/dpo/dpo.h>

typedef struct l3_proxy_dpo_t_
{
    /**
     * required for pool_get_aligned.
     *  memebers used in the switch path come first!
     */
    CLIB_CACHE_LINE_ALIGN_MARK(cacheline0);

    /**
     * The Software interface index on which traffic is l3_proxyd
     */
    u32 l3p_sw_if_index;

    /**
     * number oflocks.
     */
    u16 l3p_locks;
} l3_proxy_dpo_t;

extern void l3_proxy_dpo_add_or_lock (dpo_proto_t proto,
                                      u32 sw_if_index,
                                      dpo_id_t *dpo);

extern void l3_proxy_dpo_module_init(void);

/**
 * @brief pool of all l3_proxy DPOs
 */
extern l3_proxy_dpo_t *l3_proxy_dpo_pool;

static inline l3_proxy_dpo_t *
l3_proxy_dpo_get (index_t index)
{
    return (pool_elt_at_index(l3_proxy_dpo_pool, index));
}

#endif
