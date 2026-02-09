/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include "vnet/api_errno.h"
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/classifier_input/classifier_input.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/feature/feature.h>
#include <vppinfra/pool.h>

sfdp_classifier_input_main_t sfdp_classifier_input_main;

int
sfdp_classifier_input_set_table (u32 table_index, u8 is_del)
{
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  vnet_classify_main_t *vcm = &vnet_classify_main;

  if (is_del)
    {
      if (scim->classify_table_index == ~0)
	return VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND;

      scim->classify_table_index = ~0;
    }
  else
    {
      if (pool_is_free_index (vcm->tables, table_index))
	return VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND;

      scim->classify_table_index = table_index;
    }

  return 0;
}

int
sfdp_classifier_input_add_del_session (u32 tenant_id, const u8 *match, u32 match_len, u8 is_del)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  vnet_classify_table_t *t;
  u32 tenant_idx;
  int rv;

  if (scim->classify_table_index == ~0)
    return VNET_API_ERROR_NO_SUCH_TABLE;

  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  tenant_idx = kv.value;

  if (pool_is_free_index (vcm->tables, scim->classify_table_index))
    return VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND;
  t = pool_elt_at_index (vcm->tables, scim->classify_table_index);

  /* Validate match length */
  u32 expected_match_len = (t->skip_n_vectors + t->match_n_vectors) * sizeof (u32x4);
  if (match_len != expected_match_len)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_del)
    {
      u32 hash = vnet_classify_hash_packet (t, (u8 *) match);
      vnet_classify_entry_t *e = vnet_classify_find_entry (t, (u8 *) match, hash, 0);

      if (!e)
	return VNET_API_ERROR_NO_SUCH_ENTRY;

      u32 opaque_index = e->opaque_index;
      /* Delete the session from the classifier */
      rv = vnet_classify_add_del_session (vcm, scim->classify_table_index, match,
					  0, /* hit_next_index - not used for delete */
					  0, /* opaque_index - not used for delete */
					  0, /* advance */
					  0, /* action */
					  0, /* metadata */
					  0 /* is_add = 0 */);

      /* Clear the tenant mapping */
      if (!pool_is_free_index (scim->tenant_idx_by_opaque_index, opaque_index))
	pool_put_index (scim->tenant_idx_by_opaque_index, opaque_index);

      return rv;
    }

  /* Adding a session */
  /* Allocate a unique opaque_index for this session */
  u32 *tenant_entry;
  pool_get (scim->tenant_idx_by_opaque_index, tenant_entry);
  u32 opaque_index = tenant_entry - scim->tenant_idx_by_opaque_index;
  *tenant_entry = tenant_idx;

  rv = vnet_classify_add_del_session (
    vcm, scim->classify_table_index, match, ~0, /* hit_next_index - use default */
    opaque_index, 0 /* advance */, CLASSIFY_ACTION_NONE, 0 /* metadata */, 1 /* is_add = 1 */);

  if (rv)
    {
      /* Clear the mapping on failure */
      pool_put_index (scim->tenant_idx_by_opaque_index, opaque_index);
    }

  return rv;
}

int
sfdp_classifier_input_enable_disable_interface (u32 sw_if_index, u8 is_enable, u8 is_ip6)
{
  if (is_ip6)
    return vnet_feature_enable_disable ("ip6-unicast", "sfdp-classifier-input-ip6", sw_if_index,
					is_enable, 0, 0);
  else
    return vnet_feature_enable_disable ("ip4-unicast", "sfdp-classifier-input-ip4", sw_if_index,
					is_enable, 0, 0);
}

static clib_error_t *
sfdp_classifier_input_init (vlib_main_t *vm)
{
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;

  scim->classify_table_index = ~0;
  scim->tenant_idx_by_opaque_index = 0;

  return 0;
}

VLIB_INIT_FUNCTION (sfdp_classifier_input_init);
