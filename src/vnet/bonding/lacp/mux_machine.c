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

#include <vnet/bonding/lacp/node.h>
#include <vnet/bonding/lacp/mux_machine.h>
#include <vnet/bonding/lacp/tx_machine.h>

/*
 *  LACP State = UNKNOWN
 */
static lacp_fsm_state_t lacp_mux_state_begin[] = {
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 0 BEGIN
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 1 SELECTED
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 2 STANDBY
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 3 UNSELECTED
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 4 READY
};

/*
 *  LACP State = DETACHED
 */
static lacp_fsm_state_t lacp_mux_state_detached[] = {
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 0 BEGIN
  {LACP_ACTION_WAITING, LACP_MUX_STATE_WAITING},	// event 1 SELECTED
  {LACP_ACTION_WAITING, LACP_MUX_STATE_WAITING},	// event 2 STANDBY
  {LACP_NOACTION, LACP_MUX_STATE_DETACHED},	// event 3 UNSELECTED
  {LACP_NOACTION, LACP_MUX_STATE_DETACHED},	// event 4 READY
};

/*
 *  LACP State = ATTACHED
 */
static lacp_fsm_state_t lacp_mux_state_attached[] = {
  {LACP_NOACTION, LACP_MUX_STATE_ATTACHED},	// event 0 BEGIN
  {LACP_ACTION_COLLECTING_DISTRIBUTING, LACP_MUX_STATE_COLLECTING_DISTRIBUTING},	// event 1 SELECTED
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 2 STANDBY
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 3 UNSELECTED
  {LACP_ACTION_COLLECTING_DISTRIBUTING, LACP_MUX_STATE_COLLECTING_DISTRIBUTING},	// event 4 READY
};

/*
 *  LACP State = WAITING
 */
static lacp_fsm_state_t lacp_mux_state_waiting[] = {
  {LACP_NOACTION, LACP_MUX_STATE_WAITING},	// event 0 BEGIN
  {LACP_ACTION_WAITING, LACP_MUX_STATE_WAITING},	// event 1 SELECTED
  {LACP_NOACTION, LACP_MUX_STATE_WAITING},	// event 2 STANDBY
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 3 UNSELECTED
  {LACP_ACTION_ATTACHED, LACP_MUX_STATE_ATTACHED},	// event 4 READY
};

/*
 *  LACP State = COLLECTING_DISTRIBUTING
 */
static lacp_fsm_state_t lacp_mux_state_collecting_distributing[] = {
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 0 BEGIN
  {LACP_NOACTION, LACP_MUX_STATE_COLLECTING_DISTRIBUTING},	// event 1 SELECTED
  {LACP_ACTION_ATTACHED, LACP_MUX_STATE_ATTACHED},	// event 2 STANDBY
  {LACP_ACTION_ATTACHED, LACP_MUX_STATE_ATTACHED},	// event 3 UNSELECTED
  {LACP_NOACTION, LACP_MUX_STATE_COLLECTING_DISTRIBUTING},	// event 4 READY
};

static lacp_fsm_machine_t lacp_mux_fsm_table[] = {
  {lacp_mux_state_begin},
  {lacp_mux_state_detached},
  {lacp_mux_state_attached},
  {lacp_mux_state_waiting},
  {lacp_mux_state_collecting_distributing},
};

lacp_machine_t lacp_mux_machine = {
  lacp_mux_fsm_table,
  lacp_mux_debug_func,
};

static void
lacp_detach_mux_from_aggregator (vlib_main_t * vm, lacp_neighbor_t * n)
{
  n->actor.state &= ~LACP_STATE_SYNCHRONIZATION;
  n->actor.state &= ~LACP_STATE_SYNCHRONIZATION;
  n->actor.state &= ~LACP_STATE_COLLECTING;
  n->ntt = 1;
  lacp_machine_dispatch (&lacp_tx_machine, vm, n, LACP_TX_EVENT_NTT,
			 &n->tx_state);
}

static void
lacp_disable_collecting_distributing (vlib_main_t * vm, lacp_neighbor_t * n)
{
}

static void
lacp_enable_collecting_distributing (vlib_main_t * vm, lacp_neighbor_t * n)
{
  n->actor.state |= LACP_STATE_SYNCHRONIZATION | LACP_STATE_COLLECTING |
    LACP_STATE_DISTRIBUTING;
  n->ntt = 1;
  lacp_machine_dispatch (&lacp_tx_machine, vm, n, LACP_TX_EVENT_NTT,
			 &n->tx_state);
}

static void
lacp_attach_mux_to_aggregator (vlib_main_t * vm, lacp_neighbor_t * n)
{
  n->actor.state |= LACP_STATE_SYNCHRONIZATION;
  n->actor.state &= ~LACP_STATE_SYNCHRONIZATION;
  n->actor.state &= ~LACP_STATE_COLLECTING;
  n->ntt = 1;
  lacp_machine_dispatch (&lacp_tx_machine, vm, n, LACP_TX_EVENT_NTT,
			 &n->tx_state);
}

int
lacp_mux_action_detached (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  lacp_detach_mux_from_aggregator (vm, n);
  n->actor.state &= ~LACP_STATE_SYNCHRONIZATION;
  n->actor.state &= ~LACP_STATE_COLLECTING;
  lacp_disable_collecting_distributing (vm, n);
  n->actor.state &= ~LACP_STATE_DISTRIBUTING;
  n->ntt = 1;
  lacp_machine_dispatch (&lacp_tx_machine, vm, n, LACP_TX_EVENT_NTT,
			 &n->tx_state);

  return 0;
}

int
lacp_mux_action_attached (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  lacp_attach_mux_to_aggregator (vm, n);
  n->actor.state |= LACP_STATE_SYNCHRONIZATION;
  n->actor.state &= ~LACP_STATE_COLLECTING;
  lacp_disable_collecting_distributing (vm, n);
  n->actor.state &= ~LACP_STATE_DISTRIBUTING;
  n->ntt = 1;
  lacp_machine_dispatch (&lacp_tx_machine, vm, n, LACP_TX_EVENT_NTT,
			 &n->tx_state);

  return 0;
}

int
lacp_mux_action_waiting (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  if (n->wait_while_timer == 0.0)
    n->wait_while_timer = vlib_time_now (vm) + LACP_AGGREGATE_WAIT_TIME;

  return 0;
}

int
lacp_mux_action_collecting_distributing (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  n->actor.state |= LACP_STATE_DISTRIBUTING;
  lacp_enable_collecting_distributing (vm, n);
  n->actor.state |= LACP_STATE_COLLECTING;
  n->ntt = 1;
  lacp_machine_dispatch (&lacp_tx_machine, vm, n, LACP_TX_EVENT_NTT,
			 &n->tx_state);

  return 0;
}

static u8 *
format_mux_event (u8 * s, va_list * args)
{
  static lacp_event_struct lacp_mux_event_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_mux_event
#undef _
    {.str = NULL}
  };
  int e = va_arg (*args, int);
  lacp_event_struct *event_entry =
    (lacp_event_struct *) & lacp_mux_event_array;

  if (e >= (sizeof (lacp_mux_event_array) / sizeof (*event_entry)))
    s = format (s, "Bad event %d", e);
  else
    s = format (s, "%s", event_entry[e].str);

  return s;
}

u8 *
format_mux_sm_state (u8 * s, va_list * args)
{
  static lacp_state_struct lacp_mux_sm_state_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_mux_sm_state
#undef _
    {.str = NULL}
  };
  int state = va_arg (*args, int);
  lacp_state_struct *state_entry =
    (lacp_state_struct *) & lacp_mux_sm_state_array;

  if (state >= (sizeof (lacp_mux_sm_state_array) / sizeof (*state_entry)))
    s = format (s, "Bad state %d", state);
  else
    s = format (s, "%s", state_entry[state].str);

  return s;
}

void
lacp_mux_debug_func (int event, int state, lacp_fsm_state_t * transition)
{
  clib_warning ("MUX: event %U, old state %U, new state %U", format_mux_event,
		event, format_mux_sm_state, state, format_mux_sm_state,
		transition->next_state);
}

void
lacp_init_mux_machine (vlib_main_t * vm, lacp_neighbor_t * n)
{
  lacp_machine_dispatch (&lacp_mux_machine, vm, n, LACP_MUX_EVENT_BEGIN,
			 &n->mux_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
