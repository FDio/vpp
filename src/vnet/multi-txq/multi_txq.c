/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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
#include <vnet/feature/feature.h>
#include <vnet/multi-txq/multi_txq.h>

multi_txq_main_t multi_txq_main;

int
vnet_sw_interface_multi_txq_enable_disable (u32 sw_if_index, u32 num_txqs,
					    u8 enable)
{
  vlib_main_t *vm = vlib_get_main ();
  vnet_hw_interface_t *hw =
    vnet_get_sup_hw_interface (vnet_get_main (), sw_if_index);

  vlib_worker_thread_barrier_sync (vm);

  vnet_feature_enable_disable ("interface-output", "multi-txq", sw_if_index,
			       enable, &num_txqs, sizeof (u32));
  vlib_node_add_next (vlib_get_main (), multi_txq_node.index,
		      hw->tx_node_index);
  vnet_feature_modify_end_node (
    vnet_get_feature_arc_index ("interface-output"), sw_if_index,
    hw->tx_node_index);

  vlib_worker_thread_barrier_release (vm);
  return (0);
}

static clib_error_t *
multi_txq_init (vlib_main_t *vm)
{
  multi_txq_main_t *mtm = &multi_txq_main;

  clib_memset (mtm, 0, sizeof (mtm[0]));
  mtm->vlib_main = vm;
  mtm->vnet_main = vnet_get_main ();

  return 0;
}

VLIB_INIT_FUNCTION (multi_txq_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
