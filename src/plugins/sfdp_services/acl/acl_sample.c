/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <acl/acl_sample.h>

static void
acl_sample_validate_tenant_lc (u16 tenant_idx)
{
  sfdp_acl_main_t *vam = &sfdp_acl_main;
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_tenant_t *tenant = sfdp_tenant_at_index (sfdp, tenant_idx);
  u32 lc;

  if (vec_elt_at_index (vam->lc_by_tenant_idx, tenant_idx)[0] != ~0)
    return;

  lc = acl_plugin.get_lookup_context_index (vam->acl_user_id,
					    tenant->tenant_id, 0);
  vec_elt_at_index (vam->lc_by_tenant_idx, tenant_idx)[0] = lc;
};

clib_error_t *
sfdp_acl_sample_tenant_set_acl (sfdp_acl_main_t *vam, u64 tenant_id,
				u32 acl_index, bool disable)
{
  sfdp_main_t *sfdp = &sfdp_main;
  clib_error_t *err = 0;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  u16 tenant_idx;
  u32 lc;
  u32 *acl_vec = 0;
  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    {
      err = clib_error_return (0, "Invalid tenant id: %llu", tenant_id);
      return err;
    }
  tenant_idx = kv.value;
  acl_sample_validate_tenant_lc (tenant_idx);
  lc = vam->lc_by_tenant_idx[tenant_idx];
  if (!disable)
    vec_add1 (acl_vec, acl_index);
  acl_plugin.set_acl_vec_for_context (lc, acl_vec);
  vec_free (acl_vec);
  return err;
}

static clib_error_t *
acl_sample_init (vlib_main_t *vm)
{
  sfdp_acl_main_t *vam = &sfdp_acl_main;
  sfdp_main_t *sfdp = &sfdp_main;
  clib_error_t *err = acl_plugin_exports_init (&acl_plugin);
  int i;
  if (err)
    return err;

  vam->acl_user_id =
    acl_plugin.register_user_module ("sfdp ACL plugin", "tenant id", NULL);

  vec_validate (vam->lc_by_tenant_idx, (1ULL << sfdp->log2_tenants) - 1);

  vec_foreach_index (i, vam->lc_by_tenant_idx)
    vam->lc_by_tenant_idx[i] = ~0;

  return 0;
}

VLIB_MAIN_LOOP_ENTER_FUNCTION (acl_sample_init) = {

};

sfdp_acl_main_t sfdp_acl_main;
acl_plugin_methods_t acl_plugin;