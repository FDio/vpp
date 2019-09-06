/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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
#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vnet/ethernet/ethernet.h>
#include <vnet/feature/feature.h>
#include <vnet/l2/l2_in_out_feat_arc.h>

int
vnet_sw_interface_gso_enable_disable (u32 sw_if_index, u8 enable)
{
  ethernet_interface_t *eif;
  vnet_sw_interface_t *si;
  ethernet_main_t *em;
  vnet_main_t *vnm;

  vnm = vnet_get_main ();
  em = &ethernet_main;
  si = vnet_get_sw_interface (vnm, sw_if_index);

  /*
   * only ethernet HW interfaces are supported at this time
   */
  if (si->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    {
      //return clib_error_return (0, "interface type is not hardware");
      return (VNET_API_ERROR_INVALID_VALUE);
    }

  eif = ethernet_get_interface (em, si->hw_if_index);

  if (!eif)
    {
      //return clib_error_return (0, "interface should be ethernet interface");
      return (VNET_API_ERROR_FEATURE_DISABLED);
    }

  vnet_feature_enable_disable ("ip4-output", "gso-ip4", sw_if_index, enable,
			       0, 0);
  vnet_feature_enable_disable ("ip6-output", "gso-ip6", sw_if_index, enable,
			       0, 0);

  vnet_l2_feature_enable_disable ("l2-output-nonip", "gso-l2-nonip",
				  sw_if_index, enable, 0, 0);
  vnet_l2_feature_enable_disable ("l2-output-ip4", "gso-l2-ip4",
				  sw_if_index, enable, 0, 0);
  vnet_l2_feature_enable_disable ("l2-output-ip6", "gso-l2-ip6",
				  sw_if_index, enable, 0, 0);

  return (0);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
