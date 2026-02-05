/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_nat_h__
#define __included_nat_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/ip/ip46_address.h>

#define NAT_INVALID_TENANT_IDX	(sfdp_tenant_index_t) (~0)
#define NAT_ALLOC_POOL_ARRAY_SZ 13

#define foreach_nat_tenant_flag _ (SNAT, 0x1, "snat")

enum
{
#define _(name, x, str) NAT_TENANT_FLAG_##name = (x),
  foreach_nat_tenant_flag
#undef _
    NAT_TENANT_N_FLAGS
};

typedef struct
{
  u16 flags;
  u32 reverse_context;
  uword out_alloc_pool_idx;
  uword fib_index;
} nat_tenant_t;

#define foreach_nat_rewrite_op                                                \
  _ (SADDR, 0x1, "src-addr")                                                  \
  _ (SPORT, 0x2, "src-port")                                                  \
  _ (DADDR, 0x4, "dst-addr")                                                  \
  _ (DPORT, 0x8, "dst-port")                                                  \
  _ (ICMP_ID, 0x10, "icmp-id")                                                \
  _ (TXFIB, 0x20, "tx-fib")

typedef enum
{
#define _(sym, x, s) NAT_REWRITE_OP_##sym = x,
  foreach_nat_rewrite_op
#undef _
} nat_rewrite_op_t;
typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cache0);
  struct
  {
    ip4_address_t saddr, daddr;
    u16 sport;
    u16 dport;
    u32 fib_index;
    u16 icmp_id;
    u8 proto;
  } rewrite;
  u32 ops; /* see nat_rewrite_op_t */
  uword l3_csum_delta;
  uword l4_csum_delta;
  session_version_t version;
} nat_rewrite_data_t;
STATIC_ASSERT_SIZEOF (nat_rewrite_data_t, CLIB_CACHE_LINE_BYTES);

typedef struct
{
  CLIB_CACHE_LINE_ALIGN_MARK (cache0);
  u16 flags;
  u16 num;
  ip4_address_t addr[NAT_ALLOC_POOL_ARRAY_SZ];
  ip4_address_t *remaining;
} nat_alloc_pool_t;
STATIC_ASSERT_SIZEOF (nat_alloc_pool_t, CLIB_CACHE_LINE_BYTES);

typedef struct
{
  u32 *tenant_idx_by_sw_if_idx; /* vec */
  nat_tenant_t *tenants;	/* vec */
  nat_alloc_pool_t *alloc_pool; /* pool of allocation pools */
  nat_rewrite_data_t *flows;	/* by flow_index */
  uword *alloc_pool_idx_by_id;	/* hash */
  u16 msg_id_base;
} nat_main_t;

extern nat_main_t nat_main;

clib_error_t *nat_external_interface_set_tenant (nat_main_t *nat, u32 sw_if_index,
						 sfdp_tenant_id_t tenant_id, u8 unset);

clib_error_t *nat_alloc_pool_add_del (nat_main_t *nat, u32 alloc_pool_id,
				      u8 is_del, ip4_address_t *addr);

clib_error_t *nat_tenant_set_snat (nat_main_t *nat, sfdp_tenant_id_t tenant_id,
				   u32 outside_tenant_id, u32 table_id, u32 alloc_pool_id,
				   u8 unset);
format_function_t format_sfdp_nat_rewrite;
#endif