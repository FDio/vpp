/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2023 Cisco and/or its affiliates.
 */

#include <vlib/vlib.h>
#include <tracenode/tracenode.h>

tracenode_main_t tracenode_main;

int
tracenode_feature_enable_disable (u32 sw_if_index, bool is_pcap, bool enable)
{
  tracenode_main_t *tnm = &tracenode_main;
  char *node_name = is_pcap ? "pcap-filtering" : "trace-filtering";
  int rv = 0;

  if (pool_is_free_index (tnm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (clib_bitmap_get (tnm->feature_enabled_by_sw_if, sw_if_index) == enable)
    return 0;

  if ((rv = vnet_feature_enable_disable ("ip4-unicast", node_name, sw_if_index,
					 enable, 0, 0)) != 0)
    return rv;

  if ((rv = vnet_feature_enable_disable ("ip6-unicast", node_name, sw_if_index,
					 enable, 0, 0)) != 0)
    return rv;

  tnm->feature_enabled_by_sw_if =
    clib_bitmap_set (tnm->feature_enabled_by_sw_if, sw_if_index, enable);

  return 0;
}

static clib_error_t *
tracenode_init (vlib_main_t *vm)
{
  tracenode_main_t *tnm = &tracenode_main;
  clib_error_t *error = 0;

  memset (tnm, 0, sizeof (*tnm));

  tnm->vnet_main = vnet_get_main ();

  error = tracenode_plugin_api_hookup (vm);

  return error;
}

VLIB_INIT_FUNCTION (tracenode_init);
