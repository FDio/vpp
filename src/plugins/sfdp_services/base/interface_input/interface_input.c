/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include "vnet/sfdp/common.h"
#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/interface_input/interface_input.h>
#include <vppinfra/pool.h>

clib_error_t *
sfdp_interface_input_set_tenant (sfdp_interface_input_main_t *vim, u32 sw_if_index,
				 sfdp_tenant_id_t tenant_id, u8 is_ip6, u8 unset)
{
  sfdp_main_t *sfdp = &sfdp_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  vnet_main_t *vnm = vnet_get_main ();
  sfdp_tenant_index_t *config;
  u8 proto = is_ip6 ? SFDP_INTERFACE_INPUT_PROTO_IP6 : SFDP_INTERFACE_INPUT_PROTO_IP4;

  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (0, "Tenant with id %d not found");

  vec_validate (vim->tenant_idx_by_sw_if_idx[proto], sw_if_index);
  config = vim->tenant_idx_by_sw_if_idx[proto] + sw_if_index;

  if (config[0] == INTERFACE_INPUT_INVALID_TENANT_IDX && unset)
    return clib_error_return (0, "Tenant %d is not configured on interface %U for proto %s",
			      tenant_id, format_vnet_sw_if_index_name, vnm, sw_if_index,
			      is_ip6 ? "ip6" : "ip4");

  if (config[0] != INTERFACE_INPUT_INVALID_TENANT_IDX && !unset)
    return clib_error_return (0, "Interface %U is already configured for proto %s",
			      format_vnet_sw_if_index_name, vnm, sw_if_index,
			      is_ip6 ? "ip6" : "ip4");

  if (!unset)
    {
      /* Enable SFDP feature arc for either IP4 or IP6*/
      if (is_ip6)
	vnet_feature_enable_disable ("ip6-unicast", "sfdp-interface-input-ip6", sw_if_index, 1, 0,
				     0);
      else
	vnet_feature_enable_disable ("ip4-unicast", "sfdp-interface-input-ip4", sw_if_index, 1, 0,
				     0);

      config[0] = kv.value;
    }

  else
    {
      /* Disable feature arc for either IP4 and IP6 */
      if (is_ip6)
	vnet_feature_enable_disable ("ip6-unicast", "sfdp-interface-input-ip6", sw_if_index, 0, 0,
				     0);
      else
	vnet_feature_enable_disable ("ip4-unicast", "sfdp-interface-input-ip4", sw_if_index, 0, 0,
				     0);

      config[0] = INTERFACE_INPUT_INVALID_TENANT_IDX;
    }

  return 0;
}

clib_error_t *
sfdp_interface_input_add_del_sw_interface (vnet_main_t *vnm, u32 sw_if_index,
					   u32 is_add)
{
  sfdp_interface_input_main_t *vim = &sfdp_interface_input_main;

  /* reset for ip4 interface */
  uword old_size = vec_len (vim->tenant_idx_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP4]);
  if (sw_if_index >= old_size)
    {
      vec_validate (vim->tenant_idx_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP4], sw_if_index);
      for (int i = old_size; i <= sw_if_index; i++)
	vim->tenant_idx_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP4][i] =
	  INTERFACE_INPUT_INVALID_TENANT_IDX;
    }

  /* reset for ip6 interface */
  old_size = vec_len (vim->tenant_idx_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP6]);
  if (sw_if_index >= old_size)
    {
      vec_validate (vim->tenant_idx_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP6], sw_if_index);
      for (int i = old_size; i <= sw_if_index; i++)
	vim->tenant_idx_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP6][i] =
	  INTERFACE_INPUT_INVALID_TENANT_IDX;
    }

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (sfdp_interface_input_add_del_sw_interface);
sfdp_interface_input_main_t sfdp_interface_input_main;