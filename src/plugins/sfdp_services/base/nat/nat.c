/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/nat/nat.h>
#include <vppinfra/pool.h>

clib_error_t *
nat_external_interface_set_tenant (nat_main_t *nat, u32 sw_if_index,
				   u32 tenant_id, u8 unset)
{
  sfdp_main_t *sfdp = &sfdp_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  vnet_main_t *vnm = vnet_get_main ();
  u16 *config;

  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (0, "Tenant with id %d not found");

  vec_validate (nat->tenants, kv.value);
  vec_validate (nat->tenant_idx_by_sw_if_idx, sw_if_index);
  config = nat->tenant_idx_by_sw_if_idx + sw_if_index;

  if (config[0] == NAT_INVALID_TENANT_IDX && unset)
    return clib_error_return (
      0, "Outside tenant %d is not configured on interface %U", tenant_id,
      format_vnet_sw_if_index_name, vnm, sw_if_index);

  if (config[0] != NAT_INVALID_TENANT_IDX && !unset)
    return clib_error_return (0, "Interface %U is already configured",
			      format_vnet_sw_if_index_name, vnm, sw_if_index);

  if (!unset)
    {
      vnet_feature_enable_disable ("ip4-unicast", "nat-external-input",
				   sw_if_index, 1, 0, 0);
      config[0] = kv.value;
    }

  else
    {
      vnet_feature_enable_disable ("ip4-unicast", "nat-external-input",
				   sw_if_index, 0, 0, 0);
      config[0] = NAT_INVALID_TENANT_IDX;
    }

  return 0;
}

clib_error_t *
nat_alloc_pool_add_del (nat_main_t *nat, u32 alloc_pool_id, u8 is_del,
			ip4_address_t *addr)
{
  u16 alloc_pool_idx;
  uword *val = hash_get (nat->alloc_pool_idx_by_id, alloc_pool_id);

  if (!val && is_del)
    return clib_error_return (0, "Allocation pool %d does not exist",
			      alloc_pool_id);
  if (val && !is_del)
    return clib_error_return (0, "Existing allocation pool with id %d",
			      alloc_pool_id);

  if (is_del)
    {
      pool_put_index (nat->alloc_pool, val[0]);
      hash_unset (nat->alloc_pool_idx_by_id, alloc_pool_id);
    }
  else
    {
      nat_alloc_pool_t *alloc_pool;
      uword num = vec_len (addr);
      uword num_static = clib_min (num, NAT_ALLOC_POOL_ARRAY_SZ);
      pool_get_zero (nat->alloc_pool, alloc_pool);
      alloc_pool->num = num;
      alloc_pool_idx = alloc_pool - nat->alloc_pool;
      num -= num_static;
      for (int i = 0; i < num_static; i++)
	alloc_pool->addr[i] = addr[i];
      if (num > 0)
	{
	  addr += num_static;
	  vec_validate (alloc_pool->remaining, num);
	  for (int i = 0; i < num; i++)
	    alloc_pool->remaining[i] = addr[i];
	}
      hash_set (nat->alloc_pool_idx_by_id, alloc_pool_id, alloc_pool_idx);
    }
  return 0;
}

clib_error_t *
nat_tenant_set_snat (nat_main_t *nat, u32 tenant_id, u32 outside_tenant_id,
		     u32 table_id, u32 alloc_pool_id, u8 unset)
{
  ip4_main_t *im = &ip4_main;
  uword *fib_index = hash_get (im->fib_index_by_table_id, table_id);
  uword *out_alloc_pool_idx =
    hash_get (nat->alloc_pool_idx_by_id, alloc_pool_id);
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  sfdp_main_t *sfdp = &sfdp_main;
  nat_tenant_t *tenant;
  sfdp_tenant_t *outside_tenant;
  uword tenant_idx;
  uword outside_tenant_idx;

  if (!unset && !fib_index)
    return clib_error_return (0, "Unknown table %d", table_id);

  if (!unset && !out_alloc_pool_idx)
    return clib_error_return (0, "Unknown allocation pool %d", alloc_pool_id);

  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (0, "Unknown tenant %d", tenant_id);

  tenant_idx = kv.value;
  kv.key = outside_tenant_id;
  kv.value = 0;
  if (!unset && clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (0, "Unknown tenant %d", tenant_id);
  else
    outside_tenant_idx = kv.value;

  vec_validate (nat->tenants, tenant_idx);
  tenant = vec_elt_at_index (nat->tenants, tenant_idx);

  if (unset && !(tenant->flags & NAT_TENANT_FLAG_SNAT))
    return clib_error_return (0, "SNAT is not set on tenant %d", tenant_id);

  if (!unset && (tenant->flags & NAT_TENANT_FLAG_SNAT))
    return clib_error_return (0, "SNAT is already set on tenant %d",
			      tenant_id);

  if (unset)
    {
      tenant->flags &= ~NAT_TENANT_FLAG_SNAT;
      tenant->fib_index = ~0;
      tenant->out_alloc_pool_idx = ~0;
      tenant->reverse_context = ~0;
    }
  else
    {
      outside_tenant = sfdp_tenant_at_index (sfdp, outside_tenant_idx);
      tenant->flags |= NAT_TENANT_FLAG_SNAT;
      tenant->fib_index = fib_index[0];
      tenant->out_alloc_pool_idx = out_alloc_pool_idx[0];
      tenant->reverse_context = outside_tenant->context_id;
    }
  return 0;
}

static clib_error_t *
nat_init (vlib_main_t *vm)
{
  nat_main_t *nat = &nat_main;
  sfdp_main_t *sfdp = &sfdp_main;

  nat->alloc_pool_idx_by_id = hash_create (0, sizeof (uword));
  vec_validate (nat->flows, (2ULL << sfdp->log2_sessions) - 1);

  return 0;
}
VLIB_INIT_FUNCTION (nat_init);

clib_error_t *
nat_add_del_sw_interface (vnet_main_t *vnm, u32 sw_if_index, u32 is_add)
{
  nat_main_t *nat = &nat_main;
  uword old_size = vec_len (nat->tenant_idx_by_sw_if_idx);
  if (sw_if_index >= old_size)
    {
      vec_validate (nat->tenant_idx_by_sw_if_idx, sw_if_index);
      for (int i = old_size; i <= sw_if_index; i++)
	nat->tenant_idx_by_sw_if_idx[i] = NAT_INVALID_TENANT_IDX;
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (nat_add_del_sw_interface);
nat_main_t nat_main;