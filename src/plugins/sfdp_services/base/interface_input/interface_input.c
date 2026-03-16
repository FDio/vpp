/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/sfdp/sfdp.h>
#include <sfdp_services/base/interface_input/interface_input.h>
#include <vppinfra/pool.h>

clib_error_t *
sfdp_interface_input_set_tenant (sfdp_interface_input_main_t *vim, u32 sw_if_index, u32 tenant_id,
				 u8 is_ip6, u8 is_lookup_offload, u8 unset)
{
  sfdp_main_t *sfdp = &sfdp_main;
  clib_bihash_kv_8_8_t kv = { .key = tenant_id, .value = 0 };
  vnet_main_t *vnm = vnet_get_main ();
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);
  sfdp_interface_input_config_t *config;
  u8 proto = is_ip6 ? SFDP_INTERFACE_INPUT_PROTO_IP6 : SFDP_INTERFACE_INPUT_PROTO_IP4;
  int rv;

  if (!sw)
    return clib_error_create ("interface with sw_if_index %d does not exists", sw_if_index);

  if (clib_bihash_search_inline_8_8 (&sfdp->tenant_idx_by_id, &kv))
    return clib_error_return (0, "Tenant with id %d not found");

  vec_validate (vim->config_by_sw_if_idx[proto], sw_if_index);
  config = vec_elt_at_index (vim->config_by_sw_if_idx[proto], sw_if_index);

  if (config->tenant_idx == (u16) (~0) && unset)
    return clib_error_return (0, "Tenant %d is not configured on interface %U for proto %s",
			      tenant_id, format_vnet_sw_if_index_name, vnm, sw_if_index,
			      is_ip6 ? "ip6" : "ip4");

  if (config->tenant_idx != (u16) (~0) && !unset)
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

      /* We need to configure twice as much flows than sessions, since we have the forward and
       * reverse flows */
      rv = sfdp_flow_offload_configure (vnm, sw->hw_if_index, 2 * sfdp_num_sessions ());
      if (rv)
	return clib_error_create ("failed to configure TCP/UDP async flow offload: %d", rv);

      config->tenant_idx = kv.value;
      config->offload_enabled = is_lookup_offload;
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

      rv = sfdp_flow_offload_deconfigure (vnm, sw->hw_if_index);
      if (rv)
	return clib_error_create ("failed to deconfigure TCP/UDP async flow offload: %d", rv);

      config->tenant_idx = (u16) (~0);
      config->offload_enabled = 0;
    }

  return 0;
}

clib_error_t *
sfdp_interface_input_add_del_sw_interface (vnet_main_t *vnm, u32 sw_if_index,
					   u32 is_add)
{
  sfdp_interface_input_main_t *vim = &sfdp_interface_input_main;
  vnet_sw_interface_t *sw = vnet_get_sw_interface (vnm, sw_if_index);

  if (!sw)
    return clib_error_create ("interface with sw_if_index %d does not exists", sw_if_index);

  /* reset for ip4 interface */
  uword old_size = vec_len (vim->config_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP4]);
  if (sw_if_index >= old_size)
    {
      vec_validate (vim->config_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP4], sw_if_index);
      for (int i = old_size; i <= sw_if_index; i++)
	{
	  sfdp_interface_input_config_t *config =
	    vec_elt_at_index (vim->config_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP4], i);
	  config->tenant_idx = (u16) (~0);
	  config->offload_enabled = 0;
	}
    }

  /* reset for ip6 interface */
  old_size = vec_len (vim->config_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP6]);
  if (sw_if_index >= old_size)
    {
      vec_validate (vim->config_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP6], sw_if_index);
      for (int i = old_size; i <= sw_if_index; i++)
	{
	  sfdp_interface_input_config_t *config =
	    vec_elt_at_index (vim->config_by_sw_if_idx[SFDP_INTERFACE_INPUT_PROTO_IP6], i);
	  config->tenant_idx = (u16) (~0);
	  config->offload_enabled = 0;
	}
    }

  return 0;
}

VNET_SW_INTERFACE_ADD_DEL_FUNCTION (sfdp_interface_input_add_del_sw_interface);
sfdp_interface_input_main_t sfdp_interface_input_main;
