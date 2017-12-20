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

#define _GNU_SOURCE

#include <vnet/bonding/node.h>
#include <vnet/bonding/lacp/node.h>
#include <vnet/bonding/lacp/tx_machine.h>

/*
 *  LACP State = TRANSMIT
 */
static lacp_fsm_state_t lacp_tx_state_transmit[] = {
  {LACP_ACTION_TRANSMIT, LACP_TX_STATE_TRANSMIT},	// event 0 BEGIN
  {LACP_ACTION_TRANSMIT, LACP_TX_STATE_TRANSMIT},	// event 1 NTT
};

static lacp_fsm_machine_t lacp_tx_fsm_table[] = {
  {lacp_tx_state_transmit},
};

lacp_machine_t lacp_tx_machine = {
  lacp_tx_fsm_table,
  lacp_tx_debug_func,
};

int
lacp_tx_action_transmit (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;
  f64 now = vlib_time_now (vm);

  if (!lacp_timer_is_running (sif->periodic_timer))
    return 0;

  // No more than 3 LACPDUs per fast interval
  if (now <= (sif->last_lacpdu_time + 0.333))
    return 0;

  if (sif->ntt)
    {
      lacp_send_lacp_pdu (vm, sif);
    }
  sif->ntt = 0;

  return 0;
}

static u8 *
format_tx_event (u8 * s, va_list * args)
{
  static lacp_event_struct lacp_tx_event_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_tx_event
#undef _
    {.str = NULL}
  };
  int e = va_arg (*args, int);
  lacp_event_struct *event_entry =
    (lacp_event_struct *) & lacp_tx_event_array;

  if (e >= (sizeof (lacp_tx_event_array) / sizeof (*event_entry)))
    s = format (s, "Bad event %d", e);
  else
    s = format (s, "%s", event_entry[e].str);

  return s;
}

void
lacp_tx_debug_func (slave_if_t * sif, int event, int state,
		    lacp_fsm_state_t * transition)
{
  clib_warning ("%U-TX: event %U, old state %U, new state %U",
		format_vnet_sw_if_index_name, vnet_get_main (),
		sif->sw_if_index, format_tx_event,
		event, format_tx_sm_state, state, format_tx_sm_state,
		transition->next_state);
}

void
lacp_init_tx_machine (vlib_main_t * vm, slave_if_t * sif)
{
  lacp_machine_dispatch (&lacp_tx_machine, vm, sif, LACP_TX_EVENT_BEGIN,
			 &sif->tx_state);
  if (sif->is_passive == 0)
    lacp_machine_dispatch (&lacp_tx_machine, vm, sif, LACP_TX_EVENT_NTT,
			   &sif->tx_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
