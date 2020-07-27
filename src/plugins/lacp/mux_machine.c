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
lacp_detach_mux_from_aggregator (vlib_main_t * vm, member_if_t * mif)
{
  mif->actor.state &= ~LACP_STATE_SYNCHRONIZATION;
  mif->ready = 0;
  mif->ready_n = 0;
}

static void
lacp_attach_mux_to_aggregator (vlib_main_t * vm, member_if_t * mif)
{
  mif->actor.state |= LACP_STATE_SYNCHRONIZATION;
}

int
lacp_mux_action_detached (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  lacp_detach_mux_from_aggregator (vm, mif);
  mif->actor.state &= ~LACP_STATE_COLLECTING;
  bond_disable_collecting_distributing (vm, mif);
  mif->actor.state &= ~LACP_STATE_DISTRIBUTING;
  mif->ntt = 1;
  lacp_start_periodic_timer (vm, mif, 0);

  if (mif->selected == LACP_PORT_SELECTED)
    lacp_machine_dispatch (&lacp_mux_machine, vm, mif,
			   LACP_MUX_EVENT_SELECTED, &mif->mux_state);

  if (mif->selected == LACP_PORT_STANDBY)
    lacp_machine_dispatch (&lacp_mux_machine, vm, mif, LACP_MUX_EVENT_STANDBY,
			   &mif->mux_state);

  return 0;
}

int
lacp_mux_action_attached (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  lacp_attach_mux_to_aggregator (vm, mif);
  mif->actor.state &= ~LACP_STATE_COLLECTING;
  bond_disable_collecting_distributing (vm, mif);
  mif->actor.state &= ~LACP_STATE_DISTRIBUTING;
  mif->ntt = 1;
  lacp_start_periodic_timer (vm, mif, 0);

  if ((mif->selected == LACP_PORT_UNSELECTED) ||
      (mif->selected == LACP_PORT_STANDBY))
    lacp_machine_dispatch (&lacp_mux_machine, vm, mif,
			   LACP_MUX_EVENT_UNSELECTED, &mif->mux_state);

  if ((mif->selected == LACP_PORT_SELECTED) &&
      (mif->partner.state & LACP_STATE_SYNCHRONIZATION))
    lacp_machine_dispatch (&lacp_mux_machine, vm, mif, LACP_MUX_EVENT_SYNC,
			   &mif->mux_state);
  return 0;
}

int
lacp_mux_action_waiting (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  if (!lacp_timer_is_running (mif->wait_while_timer))
    lacp_start_wait_while_timer (vm, mif, LACP_AGGREGATE_WAIT_TIME);

  if ((mif->selected == LACP_PORT_SELECTED) && mif->ready)
    lacp_machine_dispatch (&lacp_mux_machine, vm, mif,
			   LACP_MUX_EVENT_READY, &mif->mux_state);

  if (mif->selected == LACP_PORT_UNSELECTED)
    lacp_machine_dispatch (&lacp_mux_machine, vm, mif,
			   LACP_MUX_EVENT_UNSELECTED, &mif->mux_state);

  return 0;
}

int
lacp_mux_action_collecting_distributing (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  mif->actor.state |= LACP_STATE_SYNCHRONIZATION | LACP_STATE_COLLECTING |
    LACP_STATE_DISTRIBUTING;
  bond_enable_collecting_distributing (vm, mif);
  mif->ntt = 1;
  lacp_start_periodic_timer (vm, mif, 0);
  if ((mif->selected == LACP_PORT_UNSELECTED) ||
      (mif->selected == LACP_PORT_STANDBY) ||
      !(mif->partner.state & LACP_STATE_SYNCHRONIZATION))
    lacp_machine_dispatch (&lacp_mux_machine, vm, mif,
			   LACP_MUX_EVENT_UNSELECTED, &mif->mux_state);


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
  lacp_event_struct *event_entry = lacp_mux_event_array;

  if (e >= (sizeof (lacp_mux_event_array) / sizeof (*event_entry)))
    s = format (s, "Bad event %d", e);
  else
    s = format (s, "%s", event_entry[e].str);

  return s;
}

void
lacp_mux_debug_func (member_if_t * mif, int event, int state,
		     lacp_fsm_state_t * transition)
{
  vlib_worker_thread_t *w = vlib_worker_threads + os_get_thread_index ();
  /* *INDENT-OFF* */
  ELOG_TYPE_DECLARE (e) =
    {
      .format = "%s",
      .format_args = "T4",
    };
  /* *INDENT-ON* */
  struct
  {
    u32 event;
  } *ed = 0;

  ed = ELOG_TRACK_DATA (&vlib_global_main.elog_main, e, w->elog_track);
  ed->event =
    elog_string (&vlib_global_main.elog_main, "%U-MUX: %U, %U->%U%c",
		 format_vnet_sw_if_index_name, vnet_get_main (),
		 mif->sw_if_index, format_mux_event, event,
		 format_mux_sm_state, state, format_mux_sm_state,
		 transition->next_state, 0);
}

void
lacp_init_mux_machine (vlib_main_t * vm, member_if_t * mif)
{
  lacp_machine_dispatch (&lacp_mux_machine, vm, mif, LACP_MUX_EVENT_BEGIN,
			 &mif->mux_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
