/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_sfdp_classifier_input_h__
#define __included_sfdp_classifier_input_h__

#include <vlib/vlib.h>
#include <vnet/sfdp/sfdp.h>
#include <vnet/classify/vnet_classify.h>

typedef struct
{
  u32 *tenant_idx_by_opaque_index;
  u32 classify_table_index;
  u16 msg_id_base;
} sfdp_classifier_input_main_t;

extern sfdp_classifier_input_main_t sfdp_classifier_input_main;

int sfdp_classifier_input_set_table (u32 table_index, u8 is_del);
int sfdp_classifier_input_add_del_session (u32 tenant_id, const u8 *match, u32 match_len,
					   u8 is_del);
int sfdp_classifier_input_enable_disable_interface (u32 sw_if_index, u8 is_enable, u8 is_ip6);

always_inline int
sfdp_classifier_input_get_tenant_idx (u32 opaque_index, u16 *tenant_idx)
{
  sfdp_classifier_input_main_t *scim = &sfdp_classifier_input_main;

  if (pool_is_free_index (scim->tenant_idx_by_opaque_index, opaque_index))
    return -1;

  u32 val = scim->tenant_idx_by_opaque_index[opaque_index];
  if (val == ~0)
    return -1;

  *tenant_idx = (u16) val;
  return 0;
}

#endif /* __included_sfdp_classifier_input_h__ */
