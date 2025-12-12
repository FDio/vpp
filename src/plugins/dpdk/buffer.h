/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017-2019 Cisco and/or its affiliates.
 */

#ifndef include_dpdk_buffer_h
#define include_dpdk_buffer_h

#define rte_mbuf_from_vlib_buffer(x) (((struct rte_mbuf *)x) - 1)
#define vlib_buffer_from_rte_mbuf(x) ((vlib_buffer_t *)(x+1))

extern struct rte_mempool **dpdk_mempool_by_buffer_pool_index;
extern struct rte_mempool **dpdk_no_cache_mempool_by_buffer_pool_index;

clib_error_t *dpdk_buffer_pools_create (vlib_main_t * vm);

#endif /* include_dpdk_buffer_h */

/** @endcond */
