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
#include <lacp/node.h>

/*
 *  LACP State = NO_PERIODIC
 */
static lacp_fsm_state_t lacp_ptx_state_no_periodic[] = {
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 0 NO_PERIODIC
  {LACP_ACTION_SLOW_PERIODIC, LACP_PTX_STATE_SLOW_PERIODIC},	// event 1 LONG_TIMEOUT
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 2 TIMER_EXPIRED
  {LACP_ACTION_FAST_PERIODIC, LACP_PTX_STATE_FAST_PERIODIC},	// event 3 SHORT_TIMEOUT
};

/*
 *  LACP State = FAST_PERIODIC
 */
static lacp_fsm_state_t lacp_ptx_state_fast_periodic[] = {
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 0 NO_PERIODIC
  {LACP_ACTION_SLOW_PERIODIC, LACP_PTX_STATE_SLOW_PERIODIC},	// event 1 LONG_TIMEOUT
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 2 TIMER_EXPIRED
  {LACP_ACTION_FAST_PERIODIC, LACP_PTX_STATE_FAST_PERIODIC},	// event 3 SHORT_TIMEOUT
};

/*
 *  LACP State = SLOW_PERIODIC
 */
static lacp_fsm_state_t lacp_ptx_state_slow_periodic[] = {
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 0 NO_PERIODIC
  {LACP_ACTION_SLOW_PERIODIC, LACP_PTX_STATE_SLOW_PERIODIC},	// event 1 LONG_TIMEOUT
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 2 TIMER_EXPIRED
  {LACP_ACTION_FAST_PERIODIC, LACP_PTX_STATE_FAST_PERIODIC},	// event 3 SHORT_TIMEOUT
};

/*
 *  LACP State = PERIODIC_TX
 */
static lacp_fsm_state_t lacp_ptx_state_periodic_tx[] = {
  {LACP_ACTION_NO_PERIODIC, LACP_PTX_STATE_NO_PERIODIC},	// event 0 NO_PERIODIC
  {LACP_NOACTION, LACP_PTX_STATE_PERIODIC_TX},	// event 1 LONG_TIMEOUT
  {LACP_ACTION_TIMER_EXPIRED, LACP_PTX_STATE_PERIODIC_TX},	// event 2 TIMER_EXPIRED
  {LACP_NOACTION, LACP_PTX_STATE_PERIODIC_TX},	// event 3 SHORT_TIMEOUT
};


static lacp_fsm_machine_t lacp_ptx_fsm_table[] = {
  {lacp_ptx_state_no_periodic},
  {lacp_ptx_state_fast_periodic},
  {lacp_ptx_state_slow_periodic},
  {lacp_ptx_state_periodic_tx},
};

lacp_machine_t lacp_ptx_machine = {
  lacp_ptx_fsm_table,
  lacp_ptx_debug_func,
};

int
lacp_ptx_action_no_periodic (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  lacp_stop_timer (&mif->periodic_timer);
  lacp_ptx_post_short_timeout_event (vm, mif);
  return 0;
}

int
lacp_ptx_action_slow_periodic (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;
  u8 timer_expired;

  if (!(mif->partner.state & LACP_STATE_LACP_ACTIVITY) &&
      !(mif->actor.state & LACP_STATE_LACP_ACTIVITY))
    lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			   LACP_PTX_EVENT_NO_PERIODIC, &mif->ptx_state);
  else
    {
      if (lacp_timer_is_running (mif->periodic_timer) &&
	  lacp_timer_is_expired (vm, mif->periodic_timer))
	timer_expired = 1;
      else
	timer_expired = 0;

      lacp_schedule_periodic_timer (vm, mif);

      if (timer_expired || (mif->partner.state & LACP_STATE_LACP_TIMEOUT))
	lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			       LACP_PTX_EVENT_TIMER_EXPIRED, &mif->ptx_state);
    }

  return 0;
}

int
lacp_ptx_action_fast_periodic (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;
  u8 timer_expired;

  if (!(mif->partner.state & LACP_STATE_LACP_ACTIVITY) &&
      !(mif->actor.state & LACP_STATE_LACP_ACTIVITY))
    lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			   LACP_PTX_EVENT_NO_PERIODIC, &mif->ptx_state);
  else
    {
      if (lacp_timer_is_running (mif->periodic_timer) &&
	  lacp_timer_is_expired (vm, mif->periodic_timer))
	timer_expired = 1;
      else
	timer_expired = 0;

      lacp_start_periodic_timer (vm, mif, LACP_FAST_PERIODIC_TIMER);

      if (timer_expired)
	lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			       LACP_PTX_EVENT_TIMER_EXPIRED, &mif->ptx_state);

      if (!(mif->partner.state & LACP_STATE_LACP_TIMEOUT))
	lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			       LACP_PTX_EVENT_LONG_TIMEOUT, &mif->ptx_state);
    }

  return 0;
}

int
lacp_ptx_action_timer_expired (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  if (!(mif->partner.state & LACP_STATE_LACP_ACTIVITY) &&
      !(mif->actor.state & LACP_STATE_LACP_ACTIVITY))
    lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			   LACP_PTX_EVENT_NO_PERIODIC, &mif->ptx_state);
  else
    {
      mif->ntt = 1;
      lacp_machine_dispatch (&lacp_tx_machine, vm, mif, LACP_TX_EVENT_NTT,
			     &mif->tx_state);
      if (mif->partner.state & LACP_STATE_LACP_TIMEOUT)
	lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			       LACP_PTX_EVENT_SHORT_TIMEOUT, &mif->ptx_state);
      else
	lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			       LACP_PTX_EVENT_LONG_TIMEOUT, &mif->ptx_state);
    }

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
  lacp_event_struct *event_entry = lacp_ptx_event_array;

  if (e >= (sizeof (lacp_ptx_event_array) / sizeof (*event_entry)))
    s = format (s, "Bad event %d", e);
  else
    s = format (s, "%s", event_entry[e].str);

  return s;
}

void
lacp_ptx_debug_func (member_if_t * mif, int event, int state,
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
    elog_string (&vlib_global_main.elog_main, "%U-PTX: %U, %U->%U%c",
		 format_vnet_sw_if_index_name, vnet_get_main (),
		 mif->sw_if_index, format_ptx_event, event,
		 format_ptx_sm_state, state, format_ptx_sm_state,
		 transition->next_state, 0);
}

void
lacp_init_ptx_machine (vlib_main_t * vm, member_if_t * mif)
{
  lacp_machine_dispatch (&lacp_ptx_machine, vm, mif,
			 LACP_PTX_EVENT_NO_PERIODIC, &mif->ptx_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
