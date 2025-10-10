/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/interface_input/interface_input.h>
#include <vppinfra/pool.h>

clib_error_t *
sfdp_interface_input_set_tenant (sfdp_interface_input_main_t *vim,
				 u32 sw_if_index, u32 tenant_id, u8 unset)
{
  sfdp_main_t *sfdp = &sfdp_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  vnet_main_t *vnm = vnet_get_main ();
  u16 *config;

  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (0, "Tenant with id %d not found");

  vec_validate (vim->tenant_idx_by_sw_if_idx, sw_if_index);
  config = vim->tenant_idx_by_sw_if_idx + sw_if_index;

  if (config[0] == ((u16) ~0) && unset)
    return clib_error_return (
      0, "Outside tenant %d is not configured on interface %U", tenant_id,
      format_vnet_sw_if_index_name, vnm, sw_if_index);

  if (config[0] != (u16) (~0) && !unset)
    return clib_error_return (0, "Interface %U is already configured",
			      format_vnet_sw_if_index_name, vnm, sw_if_index);

  if (!unset)
    {
      vnet_feature_enable_disable ("ip4-unicast", "sfdp-interface-input",
				   sw_if_index, 1, 0, 0);
      config[0] = kv.value;
    }

  else
    {
      vnet_feature_enable_disable ("ip4-unicast", "sfdp-interface-input",
				   sw_if_index, 0, 0, 0);
      config[0] = (u16) (~0);
    }

  return 0;
}

clib_error_t *
sfdp_interface_input_add_del_sw_interface (vnet_main_t *vnm, u32 sw_if_index,
					   u32 is_add)
{
  sfdp_interface_input_main_t *vim = &sfdp_interface_input_main;
  uword old_size = vec_len (vim->tenant_idx_by_sw_if_idx);
  if (sw_if_index >= old_size)
    {
      vec_validate (vim->tenant_idx_by_sw_if_idx, sw_if_index);
      for (int i = old_size; i <= sw_if_index; i++)
	vim->tenant_idx_by_sw_if_idx[i] = (u16) (~0);
    }
  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (sfdp_interface_input_add_del_sw_interface);
sfdp_interface_input_main_t sfdp_interface_input_main;