/*
 * Copyright (c) 2023 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <vlib/vlib.h>
#include <tracenode/tracenode.h>
#include <vnet/ip/reass/ip4_full_reass.h>
#include <vnet/ip/reass/ip6_full_reass.h>

tracenode_main_t tracenode_main;

int
vnet_enable_disable_tracenode_feature (u32 sw_if_index, bool is_pcap,
				       bool enable)
{
  tracenode_main_t *tnm = &tracenode_main;
  char *node_name = is_pcap ? "pcap-filtering" : "trace-filtering";
  int rv = 0;

  if (pool_is_free_index (tnm->vnet_main->interface_main.sw_interfaces,
			  sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;

  if (clib_bitmap_get (tnm->feature_enabled_by_sw_if, sw_if_index) == enable)
    return 0;

  if ((rv = ip4_full_reass_enable_disable_with_refcnt (sw_if_index, enable)) !=
      0)
    return rv;

  if ((rv = ip6_full_reass_enable_disable_with_refcnt (sw_if_index, enable)) !=
      0)
    return rv;

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
  tnm->feature_enabled_by_sw_if = 0;

  error = tracenode_plugin_api_hookup (vm);

  return error;
}

VLIB_INIT_FUNCTION (tracenode_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
