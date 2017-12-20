/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
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

#include <stdint.h>
#include <vlib/vlib.h>
#include <vlib/unix/unix.h>
#include <vnet/bonding/node.h>
#include <lacp/node.h>

static void
lacp_set_port_selected (vlib_main_t * vm, slave_if_t * sif)
{
  /* Handle loopback port */
  if (!memcmp (sif->partner.system, sif->actor.system, 6) &&
      (sif->partner.key == sif->actor.key))
    {
      sif->loopback_port = 1;
      sif->actor.state &= ~LACP_STATE_AGGREGATION;
    }
  sif->selected = LACP_PORT_SELECTED;

  switch (sif->mux_state)
    {
    case LACP_MUX_STATE_DETACHED:
      break;
    case LACP_MUX_STATE_WAITING:
      if (!sif->ready)
	return;
      break;
    case LACP_MUX_STATE_ATTACHED:
      if (!(sif->partner.state & LACP_STATE_SYNCHRONIZATION))
	return;
      break;
    case LACP_MUX_STATE_COLLECTING_DISTRIBUTING:
      break;
    default:
      break;
    }
  lacp_machine_dispatch (&lacp_mux_machine, vm, sif, LACP_MUX_EVENT_SELECTED,
			 &sif->mux_state);
}

void
lacp_selection_logic (vlib_main_t * vm, slave_if_t * sif)
{
  slave_if_t *sif2;
  bond_if_t *bif;
  u32 *sw_if_index;

  bif = bond_get_master_by_dev_instance (sif->bif_dev_instance);
  vec_foreach (sw_if_index, bif->slaves)
  {
    sif2 = bond_get_slave_by_sw_if_index (*sw_if_index);
    if (sif2 && (sif2->actor.state & LACP_STATE_SYNCHRONIZATION) &&
	(sif2->ready_n == 0))
      goto out;
  }

  vec_foreach (sw_if_index, bif->slaves)
  {
    sif2 = bond_get_slave_by_sw_if_index (*sw_if_index);
    if (sif2)
      {
	sif2->ready = 1;
	if (sif2->selected == LACP_PORT_SELECTED)
	  lacp_machine_dispatch (&lacp_mux_machine, vm, sif2,
				 LACP_MUX_EVENT_READY, &sif2->mux_state);
      }
  }
out:
  lacp_set_port_selected (vm, sif);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
