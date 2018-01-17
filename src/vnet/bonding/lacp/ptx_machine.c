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
#include <vnet/bonding/lacp/ptx_machine.h>
#include <vnet/bonding/lacp/tx_machine.h>

/*
 *  LACP State = UNKNOWN
 */
static lacp_fsm_state_t lacp_ptx_state_begin[] = {
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 0 BEGIN
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 1 NO_PERIODIC
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 2 START_PERIODIC
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 3 LONG_TIMEOUT
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 4 TIMER_EXPIRED
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 5 SHORT_TIMEOUT
};

/*
 *  LACP State = NO_PERIODIC
 */
static lacp_fsm_state_t lacp_ptx_state_no_periodic[] = {
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 0 BEGIN
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 1 NO_PERIODIC
  {LACP_ACTION_FAST_PERIODIC, LACP_PTX_STATE_FAST_PERIODIC},	// event 2 START_PERIODIC
  {LACP_NOACTION, LACP_PTX_STATE_NO_PERIODIC},	// event 3 LONG_TIMEOUT
  {LACP_NOACTION, LACP_PTX_STATE_NO_PERIODIC},	// event 4 TIMER_EXPIRED
  {LACP_NOACTION, LACP_PTX_STATE_NO_PERIODIC},	// event 5 SHORT_TIMEOUT
};

/*
 *  LACP State = SLOW_PERIODIC
 */
static lacp_fsm_state_t lacp_ptx_state_slow_periodic[] = {
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 0 BEGIN
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 1 NO_PERIODIC
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 2 START_PERIODIC
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 3 LONG_TIMEOUT
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 4 TIMER_EXPIRED
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 5 SHORT_TIMEOUT
};

/*
 *  LACP State = FAST_PERIODIC
 */
static lacp_fsm_state_t lacp_ptx_state_fast_periodic[] = {
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 0 BEGIN
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 1 NO_PERIODIC
  {LACP_ACTION_FAST_PERIODIC, LACP_PTX_STATE_FAST_PERIODIC},	// event 2 START_PERIODIC
  {LACP_ACTION_FAST_PERIODIC, LACP_PTX_STATE_FAST_PERIODIC},	// event 3 LONG_TIMEOUT
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 4 TIMER_EXPIRED
  {LACP_ACTION_FAST_PERIODIC, LACP_PTX_STATE_FAST_PERIODIC},	// event 5 SHORT_TIMEOUT
};

/*
 *  LACP State = PERIODIC_TX
 */
static lacp_fsm_state_t lacp_ptx_state_periodic_tx[] = {
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 0 BEGIN
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 1 NO_PERIODIC
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 2 START_PERIODIC
  {LACP_ACTION_FAST_PERIODIC, LACP_PTX_STATE_FAST_PERIODIC},	// event 3 LONG_TIMEOUT
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 4 TIMER_EXPIRED
  {LACP_ACTION_FAST_PERIODIC, LACP_PTX_STATE_FAST_PERIODIC},	// event 5 SHORT_TIMEOUT
};


static lacp_fsm_machine_t lacp_ptx_fsm_table[] = {
  {lacp_ptx_state_begin},
  {lacp_ptx_state_no_periodic},
  {lacp_ptx_state_slow_periodic},
  {lacp_ptx_state_fast_periodic},
  {lacp_ptx_state_periodic_tx},
};

lacp_machine_t lacp_ptx_machine = {
  lacp_ptx_fsm_table,
  lacp_ptx_debug_func,
};

int
lacp_ptx_action_no_periodic (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  sif->periodic_timer = 0.0;

  if (sif->lacp_enabled || sif->port_enabled ||
      ((sif->actor.state & LACP_STATE_LACP_ACTIVITY) &&
       (sif->partner.state & LACP_STATE_LACP_ACTIVITY)))
    lacp_machine_dispatch (&lacp_ptx_machine, vm, sif,
			   LACP_PTX_EVENT_START_PERIODIC, &sif->ptx_state);

  return 0;
}

int
lacp_ptx_action_slow_periodic (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  sif->periodic_timer = vlib_time_now (vm) + LACP_SLOW_PERIODIC_TIMER;

  return 0;
}

int
lacp_ptx_action_fast_periodic (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  sif->periodic_timer = vlib_time_now (vm) + LACP_FAST_PERIODIC_TIMER;

  return 0;
}

int
lacp_ptx_action_timer_expired (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  sif->ntt = 1;
  lacp_machine_dispatch (&lacp_tx_machine, vm, sif, LACP_TX_EVENT_NTT,
			 &sif->tx_state);
  if (sif->partner.state & LACP_STATE_LACP_TIMEOUT)
    lacp_machine_dispatch (&lacp_ptx_machine, vm, sif,
			   LACP_PTX_EVENT_SHORT_TIMEOUT, &sif->ptx_state);
  else
    lacp_machine_dispatch (&lacp_ptx_machine, vm, sif,
			   LACP_PTX_EVENT_LONG_TIMEOUT, &sif->ptx_state);

  return 0;
}

static u8 *
format_ptx_event (u8 * s, va_list * args)
{
  static lacp_event_struct lacp_ptx_event_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_ptx_event
#undef _
    {.str = NULL}
  };
  int e = va_arg (*args, int);
  lacp_event_struct *event_entry =
    (lacp_event_struct *) & lacp_ptx_event_array;

  if (e >= (sizeof (lacp_ptx_event_array) / sizeof (*event_entry)))
    s = format (s, "Bad event %d", e);
  else
    s = format (s, "%s", event_entry[e].str);

  return s;
}

u8 *
format_ptx_sm_state (u8 * s, va_list * args)
{
  static lacp_state_struct lacp_ptx_sm_state_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_ptx_sm_state
#undef _
    {.str = NULL}
  };
  int state = va_arg (*args, int);
  lacp_state_struct *state_entry =
    (lacp_state_struct *) & lacp_ptx_sm_state_array;

  if (state >= (sizeof (lacp_ptx_sm_state_array) / sizeof (*state_entry)))
    s = format (s, "Bad state %d", state);
  else
    s = format (s, "%s", state_entry[state].str);

  return s;
}

void
lacp_ptx_debug_func (int event, int state, lacp_fsm_state_t * transition)
{
  clib_warning ("PTX: event %U, old state %U, new state %U", format_ptx_event,
		event, format_ptx_sm_state, state, format_ptx_sm_state,
		transition->next_state);
}

void
lacp_init_ptx_machine (vlib_main_t * vm, slave_if_t * sif)
{
  lacp_machine_dispatch (&lacp_ptx_machine, vm, sif, LACP_PTX_EVENT_BEGIN,
			 &sif->ptx_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
