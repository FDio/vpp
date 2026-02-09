/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include "vnet/api_errno.h"
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/classifier_input/classifier_input.h>
#include <vnet/classify/vnet_classify.h>
#include <vnet/feature/feature.h>

sfdp_classifier_input_main_t sfdp_classifier_input_main;

int
sfdp_classifier_input_set_table (u32 sw_if_index, u32 table_index, u8 is_ip6, u8 is_del)
{
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  sfdp_classifier_input_proto_t ip =
    is_ip6 ? SFDP_CLASSIFIER_INPUT_PROTO_IP6 : SFDP_CLASSIFIER_INPUT_PROTO_IP4;

  if (is_del)
    {
      if (sw_if_index >= vec_len (scim->classify_table_index_by_sw_if_index[ip]) ||
	  vec_elt (scim->classify_table_index_by_sw_if_index[ip], sw_if_index) == ~0)
	return VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND;

      vec_elt (scim->classify_table_index_by_sw_if_index[ip], sw_if_index) = ~0;
    }
  else
    {
      if (pool_is_free_index (vcm->tables, table_index))
	return VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND;

      vec_validate_init_empty (scim->classify_table_index_by_sw_if_index[ip], sw_if_index, ~0);
      vec_elt (scim->classify_table_index_by_sw_if_index[ip], sw_if_index) = table_index;
    }

  return 0;
}

int
sfdp_classifier_input_add_del_session (u32 tenant_id, u32 sw_if_index, u8 is_ip6, const u8 *match,
				       u32 match_len, u8 is_del)
{
  sfdp_main_t *sfdp = &sfdp_main;
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;
  vnet_classify_main_t *vcm = &vnet_classify_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  sfdp_classifier_input_proto_t ip =
    is_ip6 ? SFDP_CLASSIFIER_INPUT_PROTO_IP6 : SFDP_CLASSIFIER_INPUT_PROTO_IP4;
  vnet_classify_table_t *t;
  u32 tenant_idx;
  u32 table_index;
  int rv;

  if (sw_if_index >= vec_len (scim->classify_table_index_by_sw_if_index[ip]))
    return VNET_API_ERROR_NO_SUCH_TABLE;

  table_index = vec_elt (scim->classify_table_index_by_sw_if_index[ip], sw_if_index);
  if (table_index == ~0)
    return VNET_API_ERROR_NO_SUCH_TABLE;

  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return VNET_API_ERROR_NO_SUCH_ENTRY;

  tenant_idx = kv.value;

  if (pool_is_free_index (vcm->tables, table_index))
    return VNET_API_ERROR_CLASSIFY_TABLE_NOT_FOUND;
  t = pool_elt_at_index (vcm->tables, table_index);

  u32 expected_match_len = (t->skip_n_vectors + t->match_n_vectors) * sizeof (u32x4);
  if (match_len != expected_match_len)
    return VNET_API_ERROR_INVALID_VALUE;

  if (is_del)
    {
      rv = vnet_classify_add_del_session (vcm, table_index, match, 0, /* hit_next_index */
					  0,			      /* opaque_index */
					  0,			      /* advance */
					  0,			      /* action */
					  0,			      /* metadata */
					  0 /* is_add */);
      return rv;
    }

  /* Store tenant_idx directly as opaque_index — no separate pool needed */
  rv = vnet_classify_add_del_session (vcm, table_index, match, ~0, /* hit_next_index */
				      tenant_idx,		   /* opaque_index */
				      0 /* advance */, CLASSIFY_ACTION_NONE, 0 /* metadata */,
				      1 /* is_add */);
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

  scim->classify_table_index_by_sw_if_index[SFDP_CLASSIFIER_INPUT_PROTO_IP4] = 0;
  scim->classify_table_index_by_sw_if_index[SFDP_CLASSIFIER_INPUT_PROTO_IP6] = 0;

  return 0;
}

VLIB_INIT_FUNCTION (sfdp_classifier_input_init);
