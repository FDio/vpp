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
#include <vnet/bonding/lacp/rx_machine.h>
#include <vnet/bonding/lacp/mux_machine.h>
#include <vnet/bonding/lacp/tx_machine.h>

/*
 *  LACP State = UNKNOWN
 */
static lacp_fsm_state_t lacp_rx_state_begin[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_NOACTION, LACP_RX_STATE_UNKNOWN},	// event 1 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_UNKNOWN},	// event 2 LACP_ENABLED
  {LACP_NOACTION, LACP_RX_STATE_UNKNOWN},	// event 3 LACP_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_UNKNOWN},	// event 4 PDU_RECEIVED
  {LACP_NOACTION, LACP_RX_STATE_UNKNOWN},	// event 5 TIMER_EXPIRED
};

/*
 *  LACP State = INITIALIZE
 */
static lacp_fsm_state_t lacp_rx_state_initialize[] = {
  {LACP_NOACTION, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_NOACTION, LACP_RX_STATE_INITIALIZE},	// event 1 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_INITIALIZE},	// event 2 LACP_ENABLED
  {LACP_NOACTION, LACP_RX_STATE_INITIALIZE},	// event 3 LACP_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_INITIALIZE},	// event 4 PDU_RECEIVED
  {LACP_ACTION_EXPIRED, LACP_RX_STATE_EXPIRED},	// event 5 TIMER_EXPIRED
};

/*
 *  LACP State = PORT_DISABLED
 */
static lacp_fsm_state_t lacp_rx_state_port_disabled[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 1 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_PORT_DISABLED},	// event 2 LACP_ENABLED
  {LACP_ACTION_LACP_DISABLED, LACP_RX_STATE_LACP_DISABLED},	// event 3 LACP_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_PORT_DISABLED},	// event 4 PDU_RECEIVED
  {LACP_NOACTION, LACP_RX_STATE_PORT_DISABLED},	// event 5 TIMER_EXPIRED
};

/*
 *  LACP State = EXPIRED
 */
static lacp_fsm_state_t lacp_rx_state_expired[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_ACTION_PORT_DISABLED, LACP_RX_STATE_PORT_DISABLED},	// event 1 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_EXPIRED},	// event 2 LACP_ENABLED
  {LACP_ACTION_LACP_DISABLED, LACP_RX_STATE_LACP_DISABLED},	// event 3 LACP_DISABLED
  {LACP_ACTION_CURRENT, LACP_RX_STATE_CURRENT},	// event 4 PDU_RECEIVED
  {LACP_ACTION_DEFAULTED, LACP_RX_STATE_DEFAULTED},	// event 5 TIMER_EXPIRED
};

/*
 *  LACP State = LACP_DISABLED
 */
static lacp_fsm_state_t lacp_rx_state_lacp_disabled[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_NOACTION, LACP_RX_STATE_LACP_DISABLED},	// event 1 PORT_MOVED
  {LACP_ACTION_EXPIRED, LACP_RX_STATE_EXPIRED},	// event 2 LACP_ENABLED XXX
  {LACP_ACTION_LACP_DISABLED, LACP_RX_STATE_LACP_DISABLED},	// event 3 LACP_DISABLED
  {LACP_NOACTION, LACP_RX_STATE_LACP_DISABLED},	// event 4 PDU_RECEIVED
  {LACP_NOACTION, LACP_RX_STATE_LACP_DISABLED},	// event 5 TIMER_EXPIRED
};

/*
 *  LACP State = CURRENT
 */
static lacp_fsm_state_t lacp_rx_state_current[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_NOACTION, LACP_RX_STATE_CURRENT},	// event 1 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_CURRENT},	// event 2 LACP_ENABLED
  {LACP_ACTION_LACP_DISABLED, LACP_RX_STATE_LACP_DISABLED},	// event 3 LACP_DISABLED
  {LACP_ACTION_CURRENT, LACP_RX_STATE_CURRENT},	// event 4 PDU_RECEIVED
  {LACP_ACTION_EXPIRED, LACP_RX_STATE_EXPIRED},	// event 5 TIMER_EXPIRED
};

/*
 *  LACP State = DEFAULTED
 */
static lacp_fsm_state_t lacp_rx_state_defaulted[] = {
  {LACP_ACTION_INITIALIZE, LACP_RX_STATE_INITIALIZE},	// event 0 BEGIN
  {LACP_NOACTION, LACP_RX_STATE_DEFAULTED},	// event 1 PORT_MOVED
  {LACP_NOACTION, LACP_RX_STATE_DEFAULTED},	// event 2 LACP_ENABLED
  {LACP_ACTION_LACP_DISABLED, LACP_RX_STATE_LACP_DISABLED},	// event 3 LACP_DISABLED
  {LACP_ACTION_CURRENT, LACP_RX_STATE_CURRENT},	// event 4 PDU_RECEIVED
  {LACP_NOACTION, LACP_RX_STATE_DEFAULTED},	// event 5 TIMER_EXPIRED
};

static lacp_fsm_machine_t lacp_rx_fsm_table[] = {
  {lacp_rx_state_begin},
  {lacp_rx_state_initialize},
  {lacp_rx_state_port_disabled},
  {lacp_rx_state_expired},
  {lacp_rx_state_lacp_disabled},
  {lacp_rx_state_current},
  {lacp_rx_state_defaulted},
};

lacp_machine_t lacp_rx_machine = {
  lacp_rx_fsm_table,
  lacp_rx_debug_func,
};

static void
lacp_update_default_selected (lacp_neighbor_t * n)
{
  if ((n->partner_admin.state & LACP_STATE_AGGREGATION) !=
      (n->partner.state & LACP_STATE_AGGREGATION) ||
      memcmp (&n->partner, &n->partner_admin,
	      sizeof (n->partner) - sizeof (n->partner.state)))
    {
      n->selected = LACP_PORT_SELECTED;
      //      lacp_machine_dispatch (&lacp_mux_machine, vm, n,
      //                             LACP_MUX_EVENT_SELECTED, &n->mux_state);
    }
}

static void
lacp_record_default (lacp_neighbor_t * n)
{
  n->partner = n->partner_admin;
  n->actor.state |= LACP_STATE_DEFAULTED;
}

static void
lacp_update_selected (vlib_main_t * vm, lacp_neighbor_t * n)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) n->last_rx_pkt;

  if ((lacpdu->actor.port_info.state & LACP_STATE_AGGREGATION) !=
      (n->partner.state & LACP_STATE_AGGREGATION) ||
      memcmp (&n->partner, &lacpdu->actor.port_info,
	      sizeof (n->partner) - sizeof (n->partner.state)))
    {
      n->selected = LACP_PORT_UNSELECTED;
      lacp_machine_dispatch (&lacp_mux_machine, vm, n,
			     LACP_MUX_EVENT_UNSELECTED, &n->mux_state);
    }
}

static void
lacp_update_ntt (vlib_main_t * vm, lacp_neighbor_t * n)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) n->last_rx_pkt;
  u8 states = LACP_STATE_LACP_ACTIVITY | LACP_STATE_LACP_TIMEOUT |
    LACP_STATE_SYNCHRONIZATION | LACP_STATE_AGGREGATION;

  if ((states & lacpdu->partner.port_info.state) != (states & n->actor.state)
      || memcmp (&n->actor, &lacpdu->partner.port_info,
		 sizeof (n->actor) - sizeof (n->actor.state)))
    {
      n->ntt = 1;
      lacp_machine_dispatch (&lacp_tx_machine, vm, n, LACP_TX_EVENT_NTT,
			     &n->tx_state);
    }
}

/*
 * compare lacpdu partner info against n->partner. Return 1 if they match, 0
 * otherwise.
 */
static u8
lacp_compare_partner (lacp_neighbor_t * n)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) n->last_rx_pkt;

  if ((!memcmp (&n->partner, &lacpdu->actor.port_info,
		sizeof (n->partner) - sizeof (n->partner.state)) &&
       ((n->actor.state & LACP_STATE_AGGREGATION) ==
	(lacpdu->partner.port_info.state & LACP_STATE_AGGREGATION))) ||
      ((lacpdu->actor.port_info.state & LACP_STATE_AGGREGATION) == 0))
    return 1;

  return 0;
}

static void
lacp_record_pdu (lacp_neighbor_t * n)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) n->last_rx_pkt;
  u8 match;

  match = lacp_compare_partner (n);
  n->partner = lacpdu->actor.port_info;
  n->actor.state &= ~LACP_STATE_DEFAULTED;
  if (match && (lacpdu->actor.port_info.state & LACP_STATE_SYNCHRONIZATION))
    n->partner.state |= LACP_STATE_SYNCHRONIZATION;
  else
    n->partner.state &= ~LACP_STATE_SYNCHRONIZATION;
}

int
lacp_rx_action_initialize (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  n->port_enabled = 1;
  n->selected = LACP_PORT_UNSELECTED;
  lacp_machine_dispatch (&lacp_mux_machine, vm, n, LACP_MUX_EVENT_UNSELECTED,
			 &n->mux_state);
  lacp_record_default (n);
  n->actor.state &= ~LACP_STATE_EXPIRED;
  n->port_moved = 0;

  if (n->port_enabled)
    {
      if (n->lacp_enabled)
	lacp_machine_dispatch (&lacp_rx_machine, vm, n,
			       LACP_RX_EVENT_TIMER_EXPIRED, &n->rx_state);
      else
	lacp_machine_dispatch (&lacp_rx_machine, vm, n,
			       LACP_RX_EVENT_TIMER_EXPIRED, &n->rx_state);
    }

  return 0;
}

int
lacp_rx_action_port_disabled (void *p1, void *p2)
{
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  n->partner.state &= ~LACP_STATE_SYNCHRONIZATION;
  // post partner sync event to mux
  return 0;
}

int
lacp_rx_action_expired (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  n->partner.state &= ~LACP_STATE_SYNCHRONIZATION;
  n->partner.state |= LACP_STATE_LACP_TIMEOUT;
  n->current_while_timer = vlib_time_now (vm) + n->ttl_in_seconds;
  n->actor.state |= LACP_STATE_EXPIRED;
  return 0;
}

int
lacp_rx_action_lacp_disabled (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  n->selected = LACP_PORT_UNSELECTED;
  lacp_machine_dispatch (&lacp_mux_machine, vm, n, LACP_MUX_EVENT_UNSELECTED,
			 &n->mux_state);
  lacp_record_default (n);
  n->partner.state &= ~LACP_STATE_AGGREGATION;
  n->actor.state &= ~LACP_STATE_EXPIRED;
  return 0;
}

int
lacp_rx_action_defaulted (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  lacp_update_default_selected (n);
  lacp_record_default (n);
  n->actor.state &= ~LACP_STATE_EXPIRED;
  lacp_selection_logic (vm, n);
  return 0;
}

int
lacp_rx_action_current (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  lacp_neighbor_t *n = (lacp_neighbor_t *) p2;

  lacp_update_selected (vm, n);
  lacp_update_ntt (vm, n);
  lacp_record_pdu (n);
  n->current_while_timer = vlib_time_now (vm) + n->ttl_in_seconds;
  n->actor.state &= ~LACP_STATE_EXPIRED;
  lacp_selection_logic (vm, n);
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
  lacp_event_struct *event_entry =
    (lacp_event_struct *) & lacp_rx_event_array;

  if (e >= (sizeof (lacp_rx_event_array) / sizeof (*event_entry)))
    s = format (s, "Bad event %d", e);
  else
    s = format (s, "%s", event_entry[e].str);

  return s;
}

u8 *
format_rx_sm_state (u8 * s, va_list * args)
{
  static lacp_state_struct lacp_rx_sm_state_array[] = {
#define _(b, s, n) {.bit = b, .str = #s, },
    foreach_lacp_rx_sm_state
#undef _
    {.str = NULL}
  };
  int state = va_arg (*args, int);
  lacp_state_struct *state_entry =
    (lacp_state_struct *) & lacp_rx_sm_state_array;

  if (state >= (sizeof (lacp_rx_sm_state_array) / sizeof (*state_entry)))
    s = format (s, "Bad state %d", state);
  else
    s = format (s, "%s", state_entry[state].str);

  return s;
}

void
lacp_rx_debug_func (int event, int state, lacp_fsm_state_t * transition)
{
  clib_warning ("RX: event %U, old state %U, new state %U", format_rx_event,
		event, format_rx_sm_state, state, format_rx_sm_state,
		transition->next_state);
}

void
lacp_init_rx_machine (vlib_main_t * vm, lacp_neighbor_t * n)
{
  lacp_machine_dispatch (&lacp_rx_machine, vm, n, LACP_RX_EVENT_BEGIN,
			 &n->rx_state);
  lacp_machine_dispatch (&lacp_rx_machine, vm, n, LACP_RX_EVENT_LACP_ENABLED,
			 &n->rx_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
