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
#include <vnet/bonding/lacp/node.h>
#include <vnet/bonding/lacp/machine.h>
#include <vnet/bonding/lacp/mux_machine.h>

static void
lacp_set_port_selected (vlib_main_t * vm, slave_if_t * sif)
{
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
  bond_main_t *bm = &bond_main;
  slave_if_t *sif2;
  bond_if_t *bif;
  u32 *sw_if_index;
  uword *p;

  bif = pool_elt_at_index (bm->interfaces, sif->bif_dev_instance);
  vec_foreach (sw_if_index, bif->slaves)
  {
    p = hash_get (bm->neighbor_by_sw_if_index, *sw_if_index);
    sif2 = pool_elt_at_index (bm->neighbors, p[0]);
    if ((sif2->actor.state & LACP_STATE_SYNCHRONIZATION) &&
	(sif2->ready_n == 0))
      goto out;
  }

  vec_foreach (sw_if_index, bif->slaves)
  {
    p = hash_get (bm->neighbor_by_sw_if_index, *sw_if_index);
    sif2 = pool_elt_at_index (bm->neighbors, p[0]);
    sif2->ready = 1;
    lacp_machine_dispatch (&lacp_mux_machine, vm, sif2,
			   LACP_MUX_EVENT_READY, &sif2->mux_state);
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
