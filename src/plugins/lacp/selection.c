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

static int
lacp_set_port_selected (vlib_main_t *vm, bond_if_t *bif, member_if_t *mif)
{
  uword p;
  member_if_t *mif2;

  /* Handle loopback port */
  if (!memcmp (mif->partner.system, mif->actor.system, 6) &&
      (mif->partner.key == mif->actor.key))
    {
      mif->loopback_port = 1;
      mif->actor.state &= ~LACP_STATE_AGGREGATION;
      mif->selected = LACP_PORT_UNSELECTED;
      lacp_machine_dispatch (&lacp_mux_machine, vm, mif,
			     LACP_MUX_EVENT_UNSELECTED, &mif->mux_state);
      return LACP_ERROR_LOOPBACK_PORT;
    }
  if (vec_len (bif->active_members))
    {
      p = *vec_elt_at_index (bif->active_members, 0);
      mif2 = bond_get_member_by_sw_if_index (p);
      if (mif2 && ((mif2->partner.key != mif->partner.key) ||
		   memcmp (mif2->partner.system, mif->partner.system, 6)))
	{
	  mif->selected = LACP_PORT_UNSELECTED;
	  lacp_machine_dispatch (&lacp_mux_machine, vm, mif,
				 LACP_MUX_EVENT_UNSELECTED, &mif->mux_state);
	  return LACP_ERROR_BAD_KEY;
	}
    }
  mif->selected = LACP_PORT_SELECTED;

  switch (mif->mux_state)
    {
    case LACP_MUX_STATE_DETACHED:
      break;
    case LACP_MUX_STATE_WAITING:
      if (!mif->ready)
	return LACP_ERROR_NONE;
      break;
    case LACP_MUX_STATE_ATTACHED:
      if (!(mif->partner.state & LACP_STATE_SYNCHRONIZATION))
	return LACP_ERROR_NONE;
      break;
    case LACP_MUX_STATE_COLLECTING_DISTRIBUTING:
      break;
    default:
      break;
    }
  return lacp_machine_dispatch (&lacp_mux_machine, vm, mif,
				LACP_MUX_EVENT_SELECTED, &mif->mux_state);
}

int
lacp_selection_logic (vlib_main_t *vm, member_if_t *mif)
{
  member_if_t *mif2;
  bond_if_t *bif;
  u32 *sw_if_index;

  bif = bond_get_bond_if_by_dev_instance (mif->bif_dev_instance);
  vec_foreach (sw_if_index, bif->members)
  {
    mif2 = bond_get_member_by_sw_if_index (*sw_if_index);
    if (mif2 && (mif2->actor.state & LACP_STATE_SYNCHRONIZATION) &&
	(mif2->ready_n == 0))
      goto out;
  }

  vec_foreach (sw_if_index, bif->members)
  {
    mif2 = bond_get_member_by_sw_if_index (*sw_if_index);
    if (mif2)
      {
	mif2->ready = 1;
	if (mif2->selected == LACP_PORT_SELECTED)
	  lacp_machine_dispatch (&lacp_mux_machine, vm, mif2,
				 LACP_MUX_EVENT_READY, &mif2->mux_state);
      }
  }
out:
  return lacp_set_port_selected (vm, bif, mif);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
