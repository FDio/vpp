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

#include <vlib/vlib.h>
#include <vnet/bonding/node.h>
#include <lacp/node.h>

/*
 *  LACP State = DETACHED
 */
static lacp_fsm_state_t lacp_mux_state_detached[] = {
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 0 BEGIN
  {LACP_ACTION_WAITING, LACP_MUX_STATE_WAITING},	// event 1 SELECTED
  {LACP_ACTION_WAITING, LACP_MUX_STATE_WAITING},	// event 2 STANDBY
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 3 UNSELECTED
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 4 READY
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 5 SYNC
};

/*
 *  LACP State = WAITING
 */
static lacp_fsm_state_t lacp_mux_state_waiting[] = {
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 0 BEGIN
  {LACP_ACTION_WAITING, LACP_MUX_STATE_WAITING},	// event 1 SELECTED
  {LACP_ACTION_WAITING, LACP_MUX_STATE_WAITING},	// event 2 STANDBY
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 3 UNSELECTED
  {LACP_ACTION_ATTACHED, LACP_MUX_STATE_ATTACHED},	// event 4 READY
  {LACP_ACTION_WAITING, LACP_MUX_STATE_WAITING},	// event 5 SYNC
};

/*
 *  LACP State = ATTACHED
 */
static lacp_fsm_state_t lacp_mux_state_attached[] = {
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 0 BEGIN
  {LACP_ACTION_ATTACHED, LACP_MUX_STATE_ATTACHED},	// event 1 SELECTED
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 2 STANDBY
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 3 UNSELECTED
  {LACP_ACTION_ATTACHED, LACP_MUX_STATE_ATTACHED},	// event 4 READY
  {LACP_ACTION_COLLECTING_DISTRIBUTING, LACP_MUX_STATE_COLLECTING_DISTRIBUTING},	// event 5_SYNC
};

/*
 *  LACP State = COLLECTING_DISTRIBUTING
 */
static lacp_fsm_state_t lacp_mux_state_collecting_distributing[] = {
  {LACP_ACTION_DETACHED, LACP_MUX_STATE_DETACHED},	// event 0 BEGIN
  {LACP_ACTION_COLLECTING_DISTRIBUTING, LACP_MUX_STATE_COLLECTING_DISTRIBUTING},	// event 1 SELECTED
  {LACP_ACTION_COLLECTING_DISTRIBUTING, LACP_MUX_STATE_COLLECTING_DISTRIBUTING},	// event 2 STANDBY
  {LACP_ACTION_ATTACHED, LACP_MUX_STATE_ATTACHED},	// event 3 UNSELECTED
  {LACP_ACTION_COLLECTING_DISTRIBUTING, LACP_MUX_STATE_COLLECTING_DISTRIBUTING},	// event 4 READY
  {LACP_ACTION_COLLECTING_DISTRIBUTING, LACP_MUX_STATE_COLLECTING_DISTRIBUTING},	// event 5 SYNC
};

static lacp_fsm_machine_t lacp_mux_fsm_table[] = {
  {lacp_mux_state_detached},
  {lacp_mux_state_waiting},
  {lacp_mux_state_attached},
  {lacp_mux_state_collecting_distributing},
};

lacp_machine_t lacp_mux_machine = {
  lacp_mux_fsm_table,
  lacp_mux_debug_func,
};

static void
lacp_detach_mux_from_aggregator (vlib_main_t * vm, slave_if_t * sif)
{
  sif->actor.state &= ~LACP_STATE_SYNCHRONIZATION;
  sif->ready = 0;
  sif->ready_n = 0;
}

static void
lacp_attach_mux_to_aggregator (vlib_main_t * vm, slave_if_t * sif)
{
  sif->actor.state |= LACP_STATE_SYNCHRONIZATION;
}

int
lacp_mux_action_detached (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;
  lacp_main_t *lm = &lacp_main;

  lacp_detach_mux_from_aggregator (vm, sif);
  sif->actor.state &= ~LACP_STATE_COLLECTING;
  bond_disable_collecting_distributing (vm, sif);
  sif->actor.state &= ~LACP_STATE_DISTRIBUTING;
  sif->ntt = 1;
  lacp_start_periodic_timer (lm->vlib_main, sif, 0);

  if (sif->selected == LACP_PORT_SELECTED)
    lacp_machine_dispatch (&lacp_mux_machine, vm, sif,
			   LACP_MUX_EVENT_SELECTED, &sif->mux_state);

  if (sif->selected == LACP_PORT_STANDBY)
    lacp_machine_dispatch (&lacp_mux_machine, vm, sif, LACP_MUX_EVENT_STANDBY,
			   &sif->mux_state);

  return 0;
}

int
lacp_mux_action_attached (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;
  lacp_main_t *lm = &lacp_main;

  lacp_attach_mux_to_aggregator (vm, sif);
  sif->actor.state &= ~LACP_STATE_COLLECTING;
  bond_disable_collecting_distributing (vm, sif);
  sif->actor.state &= ~LACP_STATE_DISTRIBUTING;
  sif->ntt = 1;
  lacp_start_periodic_timer (lm->vlib_main, sif, 0);

  if ((sif->selected == LACP_PORT_UNSELECTED) ||
      (sif->selected == LACP_PORT_STANDBY))
    lacp_machine_dispatch (&lacp_mux_machine, vm, sif,
			   LACP_MUX_EVENT_UNSELECTED, &sif->mux_state);

  if ((sif->selected == LACP_PORT_SELECTED) &&
      (sif->partner.state & LACP_STATE_SYNCHRONIZATION))
    lacp_machine_dispatch (&lacp_mux_machine, vm, sif, LACP_MUX_EVENT_SYNC,
			   &sif->mux_state);
  return 0;
}

int
lacp_mux_action_waiting (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;
  lacp_main_t *lm = &lacp_main;

  if (!lacp_timer_is_running (sif->wait_while_timer))
    lacp_start_wait_while_timer (lm->vlib_main, sif,
				 LACP_AGGREGATE_WAIT_TIME);

  if ((sif->selected == LACP_PORT_SELECTED) && sif->ready)
    lacp_machine_dispatch (&lacp_mux_machine, vm, sif,
			   LACP_MUX_EVENT_READY, &sif->mux_state);

  if (sif->selected == LACP_PORT_UNSELECTED)
    lacp_machine_dispatch (&lacp_mux_machine, vm, sif,
			   LACP_MUX_EVENT_UNSELECTED, &sif->mux_state);

  return 0;
}

int
lacp_mux_action_collecting_distributing (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;
  lacp_main_t *lm = &lacp_main;

  sif->actor.state |= LACP_STATE_SYNCHRONIZATION | LACP_STATE_COLLECTING |
    LACP_STATE_DISTRIBUTING;
  bond_enable_collecting_distributing (vm, sif);
  sif->ntt = 1;
  lacp_start_periodic_timer (lm->vlib_main, sif, 0);
  if ((sif->selected == LACP_PORT_UNSELECTED) ||
      (sif->selected == LACP_PORT_STANDBY) ||
      !(sif->partner.state & LACP_STATE_SYNCHRONIZATION))
    lacp_machine_dispatch (&lacp_mux_machine, vm, sif,
			   LACP_MUX_EVENT_UNSELECTED, &sif->mux_state);


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

void
lacp_mux_debug_func (slave_if_t * sif, int event, int state,
		     lacp_fsm_state_t * transition)
{
  clib_warning ("%U-MUX: event %U, old state %U, new state %U",
		format_vnet_sw_if_index_name, vnet_get_main (),
		sif->sw_if_index, format_mux_event,
		event, format_mux_sm_state, state, format_mux_sm_state,
		transition->next_state);
}

void
lacp_init_mux_machine (vlib_main_t * vm, slave_if_t * sif)
{
  lacp_machine_dispatch (&lacp_mux_machine, vm, sif, LACP_MUX_EVENT_BEGIN,
			 &sif->mux_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
