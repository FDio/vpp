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
 *  LACP State = INITIALIZE
 */
static lacp_fsm_state_t lacp_rx_state_initialize[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_PORT_DISABLED},	// event 0 BEGIN
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_PORT_DISABLED},	// event 1 PORT_DISABLED
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_PORT_DISABLED},	// event 2 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_INITIALIZE},	// event 3 LACP_ENABLED
  {LACP_NOACTION, LACP_RX_STATE_INITIALIZE},	// event 4 LACP_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_INITIALIZE},	// event 5 PDU_RECEIVED
  {LACP_NOACTION, LACP_RX_STATE_INITIALIZE},	// event 6 TIMER_EXPIRED
};

/*
 *  LACP State = PORT_DISABLED
 */
static lacp_fsm_state_t lacp_rx_state_port_disabled[] = {
  {LACP_ACTION_PORT_DISABLED, LACP_RX_STATE_PORT_DISABLED},	// event 0 BEGIN
  {LACP_ACTION_PORT_DISABLED, LACP_RX_STATE_PORT_DISABLED},	// event 1 PORT_DISABLED
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 2 PORT_MOVED
  {LACP_ACTION_EXPIRED, LACP_RX_STATE_EXPIRED},	// event 3 LACP_ENABLED
  {LACP_ACTION_LACP_DISABLED, LACP_RX_STATE_LACP_DISABLED},	// event 4 LACP_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_PORT_DISABLED},	// event 5 PDU_RECEIVED
  {LACP_NOACTION, LACP_RX_STATE_PORT_DISABLED},	// event 6 TIMER_EXPIRED
};

/*
 *  LACP State = EXPIRED
 */
static lacp_fsm_state_t lacp_rx_state_expired[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_NOACTION, LACP_RX_STATE_EXPIRED},	// event 1 PORT_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_EXPIRED},	// event 2 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_EXPIRED},	// event 3 LACP_ENABLED
  {LACP_NOACTION, LACP_RX_STATE_EXPIRED},	// event 4 LACP_DISABLED
  {LACP_ACTION_CURRENT, LACP_RX_STATE_CURRENT},	// event 5 PDU_RECEIVED
  {LACP_ACTION_DEFAULTED, LACP_RX_STATE_DEFAULTED},	// event 6 TIMER_EXPIRED
};

/*
 *  LACP State = LACP_DISABLED
 */
static lacp_fsm_state_t lacp_rx_state_lacp_disabled[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_NOACTION, LACP_RX_STATE_LACP_DISABLED},	// event 1 PORT_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_LACP_DISABLED},	// event 2 PORT_MOVED
  {LACP_ACTION_EXPIRED, LACP_RX_STATE_EXPIRED},	// event 3 LACP_ENABLED XXX
  {LACP_ACTION_LACP_DISABLED, LACP_RX_STATE_LACP_DISABLED},	// event 4 LACP_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_LACP_DISABLED},	// event 5 PDU_RECEIVED
  {LACP_NOACTION, LACP_RX_STATE_LACP_DISABLED},	// event 6 TIMER_EXPIRED
};

/*
 *  LACP State = DEFAULTED
 */
static lacp_fsm_state_t lacp_rx_state_defaulted[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_NOACTION, LACP_RX_STATE_DEFAULTED},	// event 1 PORT_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_DEFAULTED},	// event 2 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_DEFAULTED},	// event 3 LACP_ENABLED
  {LACP_ACTION_LACP_DISABLED, LACP_RX_STATE_LACP_DISABLED},	// event 4 LACP_DISABLED
  {LACP_ACTION_CURRENT, LACP_RX_STATE_CURRENT},	// event 5 PDU_RECEIVED
  {LACP_ACTION_DEFAULTED, LACP_RX_STATE_DEFAULTED},	// event 6 TIMER_EXPIRED
};

/*
 *  LACP State = CURRENT
 */
static lacp_fsm_state_t lacp_rx_state_current[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_NOACTION, LACP_RX_STATE_CURRENT},	// event 1 PORT_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_CURRENT},	// event 1 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_CURRENT},	// event 2 LACP_ENABLED
  {LACP_ACTION_LACP_DISABLED, LACP_RX_STATE_LACP_DISABLED},	// event 3 LACP_DISABLED
  {LACP_ACTION_CURRENT, LACP_RX_STATE_CURRENT},	// event 4 PDU_RECEIVED
  {LACP_ACTION_EXPIRED, LACP_RX_STATE_EXPIRED},	// event 5 TIMER_EXPIRED
};

static lacp_fsm_machine_t lacp_rx_fsm_table[] = {
  {lacp_rx_state_initialize},
  {lacp_rx_state_port_disabled},
  {lacp_rx_state_expired},
  {lacp_rx_state_lacp_disabled},
  {lacp_rx_state_defaulted},
  {lacp_rx_state_current},
};

lacp_machine_t lacp_rx_machine = {
  lacp_rx_fsm_table,
  lacp_rx_debug_func,
};

static void
lacp_set_port_unselected (vlib_main_t * vm, member_if_t * mif)
{
  mif->selected = LACP_PORT_UNSELECTED;

  switch (mif->mux_state)
    {
    case LACP_MUX_STATE_DETACHED:
      break;
    case LACP_MUX_STATE_WAITING:
      break;
    case LACP_MUX_STATE_ATTACHED:
      return;
      break;
    case LACP_MUX_STATE_COLLECTING_DISTRIBUTING:
      if (mif->partner.state & LACP_STATE_SYNCHRONIZATION)
	return;
      break;
    default:
      break;
    }
  lacp_machine_dispatch (&lacp_mux_machine, vm, mif,
			 LACP_MUX_EVENT_UNSELECTED, &mif->mux_state);
}

static void
lacp_update_default_selected (vlib_main_t * vm, member_if_t * mif)
{
  if ((mif->partner_admin.state & LACP_STATE_AGGREGATION) !=
      (mif->partner.state & LACP_STATE_AGGREGATION) ||
      memcmp (&mif->partner, &mif->partner_admin,
	      sizeof (mif->partner) - sizeof (mif->partner.state)))
    {
      lacp_set_port_unselected (vm, mif);
    }
}

static void
lacp_record_default (member_if_t * mif)
{
  mif->partner = mif->partner_admin;
  mif->actor.state |= LACP_STATE_DEFAULTED;
}

static void
lacp_update_selected (vlib_main_t * vm, member_if_t * mif)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) mif->last_rx_pkt;

  if ((lacpdu->actor.port_info.state & LACP_STATE_AGGREGATION) !=
      (mif->partner.state & LACP_STATE_AGGREGATION) ||
      memcmp (&mif->partner, &lacpdu->actor.port_info,
	      sizeof (mif->partner) - sizeof (mif->partner.state)))
    {
      lacp_set_port_unselected (vm, mif);
    }
}

static void
lacp_update_ntt (vlib_main_t * vm, member_if_t * mif)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) mif->last_rx_pkt;
  u8 states = LACP_STATE_LACP_ACTIVITY | LACP_STATE_LACP_TIMEOUT |
    LACP_STATE_SYNCHRONIZATION | LACP_STATE_AGGREGATION;

  if ((states & lacpdu->partner.port_info.state) !=
      (states & mif->actor.state)
      || memcmp (&mif->actor, &lacpdu->partner.port_info,
		 sizeof (mif->actor) - sizeof (mif->actor.state)))
    {
      mif->ntt = 1;
      lacp_start_periodic_timer (vm, mif, 0);
    }
}

/*
 * compare lacpdu partner info against mif->partner. Return 1 if they match, 0
 * otherwise.
 */
static u8
lacp_compare_partner (member_if_t * mif)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) mif->last_rx_pkt;

  if ((!memcmp (&mif->partner, &lacpdu->actor.port_info,
		sizeof (mif->partner) - sizeof (mif->partner.state)) &&
       ((mif->actor.state & LACP_STATE_AGGREGATION) ==
	(lacpdu->partner.port_info.state & LACP_STATE_AGGREGATION))) ||
      ((lacpdu->actor.port_info.state & LACP_STATE_AGGREGATION) == 0))
    return 1;

  return 0;
}

static void
lacp_record_pdu (vlib_main_t * vm, member_if_t * mif)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) mif->last_rx_pkt;
  u8 match;

  /* Transition PTX out of NO_PERIODIC if needed */
  if (!(mif->partner.state & LACP_STATE_LACP_ACTIVITY) &&
      (lacpdu->actor.port_info.state & LACP_STATE_LACP_ACTIVITY))
    lacp_ptx_post_short_timeout_event (vm, mif);
  match = lacp_compare_partner (mif);
  mif->partner = lacpdu->actor.port_info;
  mif->actor.state &= ~LACP_STATE_DEFAULTED;
  if (match && (lacpdu->actor.port_info.state & LACP_STATE_SYNCHRONIZATION))
    mif->partner.state |= LACP_STATE_SYNCHRONIZATION;
  else
    mif->partner.state &= ~LACP_STATE_SYNCHRONIZATION;
}

static void
lacp_set_port_moved (vlib_main_t * vm, member_if_t * mif, u8 val)
{
  mif->port_moved = val;

  if (mif->port_moved)
    lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			   LACP_RX_EVENT_PORT_MOVED, &mif->rx_state);
  else if (!mif->port_enabled)
    lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			   LACP_RX_EVENT_PORT_DISABLED, &mif->rx_state);
}

int
lacp_rx_action_initialize (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  lacp_set_port_unselected (vm, mif);
  lacp_record_default (mif);
  mif->actor.state &= ~LACP_STATE_EXPIRED;
  lacp_set_port_moved (vm, mif, 0);
  /* UCT */
  lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			 LACP_RX_EVENT_BEGIN, &mif->rx_state);

  return 0;
}

int
lacp_rx_action_port_disabled (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  mif->partner.state &= ~LACP_STATE_SYNCHRONIZATION;
  if (mif->port_moved)
    {
      lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			     LACP_RX_EVENT_PORT_MOVED, &mif->rx_state);
    }
  if (mif->port_enabled)
    {
      if (mif->lacp_enabled)
	lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			       LACP_RX_EVENT_LACP_ENABLED, &mif->rx_state);
      else
	lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			       LACP_RX_EVENT_LACP_DISABLED, &mif->rx_state);
    }

  return 0;
}

int
lacp_rx_action_expired (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;
  u8 timer_expired;

  mif->partner.state &= ~LACP_STATE_SYNCHRONIZATION;
  mif->partner.state |= LACP_STATE_LACP_TIMEOUT;
  lacp_ptx_post_short_timeout_event (vm, mif);
  if (lacp_timer_is_running (mif->current_while_timer) &&
      lacp_timer_is_expired (vm, mif->current_while_timer))
    timer_expired = 1;
  else
    timer_expired = 0;
  lacp_start_current_while_timer (vm, mif, mif->ttl_in_seconds);
  mif->actor.state |= LACP_STATE_EXPIRED;
  if (timer_expired)
    lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			   LACP_RX_EVENT_TIMER_EXPIRED, &mif->rx_state);
  if (mif->last_rx_pkt && vec_len (mif->last_rx_pkt))
    lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			   LACP_RX_EVENT_PDU_RECEIVED, &mif->rx_state);

  return 0;
}

int
lacp_rx_action_lacp_disabled (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  lacp_set_port_unselected (vm, mif);
  lacp_record_default (mif);
  mif->partner.state &= ~LACP_STATE_AGGREGATION;
  mif->actor.state &= ~LACP_STATE_EXPIRED;

  return 0;
}

int
lacp_rx_action_defaulted (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  lacp_stop_timer (&mif->current_while_timer);
  lacp_update_default_selected (vm, mif);
  lacp_record_default (mif);
  mif->actor.state &= ~LACP_STATE_EXPIRED;
  if (mif->last_rx_pkt && vec_len (mif->last_rx_pkt))
    lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			   LACP_RX_EVENT_PDU_RECEIVED, &mif->rx_state);

  return 0;
}

static int
lacp_port_is_moved (vlib_main_t * vm, member_if_t * mif)
{
  bond_main_t *bm = &bond_main;
  member_if_t *mif2;
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) mif->last_rx_pkt;

  /* *INDENT-OFF* */
  pool_foreach (mif2, bm->neighbors) {
      {
	if ((mif != mif2) && (mif2->rx_state == LACP_RX_STATE_PORT_DISABLED) &&
	    !memcmp (mif2->partner.system,
		     lacpdu->partner.port_info.system, 6) &&
	    (mif2->partner.port_number == lacpdu->partner.port_info.port_number))
	  return 1;
      }
  }
  /* *INDENT-ON* */

  return 0;
}

int
lacp_rx_action_current (void *p1, void *p2)
{
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;

  lacp_update_selected (vm, mif);
  lacp_update_ntt (vm, mif);
  lacp_record_pdu (vm, mif);
  lacp_start_current_while_timer (vm, mif, mif->ttl_in_seconds);
  mif->actor.state &= ~LACP_STATE_EXPIRED;
  if (lacp_port_is_moved (vm, mif))
    lacp_set_port_moved (vm, mif, 1);
  lacp_selection_logic (vm, mif);

  return 0;
}

static u8 *
format_rx_event (u8 * s, va_list * args)
{
  static lacp_event_struct lacp_rx_event_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_rx_event
#undef _
    {.str = NULL}
  };
  int e = va_arg (*args, int);
  lacp_event_struct *event_entry = lacp_rx_event_array;

  if (e >= (sizeof (lacp_rx_event_array) / sizeof (*event_entry)))
    s = format (s, "Bad event %d", e);
  else
    s = format (s, "%s", event_entry[e].str);

  return s;
}

void
lacp_rx_debug_func (member_if_t * mif, int event, int state,
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
  ed->event = elog_string (&vlib_global_main.elog_main, "%U-RX: %U, %U->%U%c",
			   format_vnet_sw_if_index_name, vnet_get_main (),
			   mif->sw_if_index, format_rx_event, event,
			   format_rx_sm_state, state, format_rx_sm_state,
			   transition->next_state, 0);
}

void
lacp_init_rx_machine (vlib_main_t * vm, member_if_t * mif)
{
  lacp_machine_dispatch (&lacp_rx_machine, vm, mif, LACP_RX_EVENT_BEGIN,
			 &mif->rx_state);
  lacp_machine_dispatch (&lacp_rx_machine, vm, mif,
			 LACP_RX_EVENT_LACP_ENABLED, &mif->rx_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
