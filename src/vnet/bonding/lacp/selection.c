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
#include <vnet/bonding/lacp/node.h>
#include <vnet/bonding/lacp/machine.h>
#include <vnet/bonding/lacp/mux_machine.h>

void
lacp_selection_logic (vlib_main_t * vm, lacp_neighbor_t * n)
{
  n->selected = LACP_PORT_SELECTED;
  lacp_machine_dispatch (&lacp_mux_machine, vm, n, LACP_MUX_EVENT_SELECTED,
			 &n->mux_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
