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
#include <vnet/bonding/lacp/ptx_machine.h>

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
lacp_update_default_selected (vlib_main_t * vm, slave_if_t * sif)
{
  if ((sif->partner_admin.state & LACP_STATE_AGGREGATION) !=
      (sif->partner.state & LACP_STATE_AGGREGATION) ||
      memcmp (&sif->partner, &sif->partner_admin,
	      sizeof (sif->partner) - sizeof (sif->partner.state)))
    {
      sif->selected = LACP_PORT_UNSELECTED;
      lacp_machine_dispatch (&lacp_mux_machine, vm, sif,
			     LACP_MUX_EVENT_UNSELECTED, &sif->mux_state);
    }
}

static void
lacp_record_default (slave_if_t * sif)
{
  sif->partner = sif->partner_admin;
  sif->actor.state |= LACP_STATE_DEFAULTED;
}

static void
lacp_update_selected (vlib_main_t * vm, slave_if_t * sif)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) sif->last_rx_pkt;

  if ((lacpdu->actor.port_info.state & LACP_STATE_AGGREGATION) !=
      (sif->partner.state & LACP_STATE_AGGREGATION) ||
      memcmp (&sif->partner, &lacpdu->actor.port_info,
	      sizeof (sif->partner) - sizeof (sif->partner.state)))
    {
      sif->selected = LACP_PORT_UNSELECTED;
      lacp_machine_dispatch (&lacp_mux_machine, vm, sif,
			     LACP_MUX_EVENT_UNSELECTED, &sif->mux_state);
    }
}

static void
lacp_update_ntt (vlib_main_t * vm, slave_if_t * sif)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) sif->last_rx_pkt;
  u8 states = LACP_STATE_LACP_ACTIVITY | LACP_STATE_LACP_TIMEOUT |
    LACP_STATE_SYNCHRONIZATION | LACP_STATE_AGGREGATION;

  if ((states & lacpdu->partner.port_info.state) !=
      (states & sif->actor.state)
      || memcmp (&sif->actor, &lacpdu->partner.port_info,
		 sizeof (sif->actor) - sizeof (sif->actor.state)))
    {
      sif->ntt = 1;
      lacp_machine_dispatch (&lacp_tx_machine, vm, sif, LACP_TX_EVENT_NTT,
			     &sif->tx_state);
    }
}

/*
 * compare lacpdu partner info against sif->partner. Return 1 if they match, 0
 * otherwise.
 */
static u8
lacp_compare_partner (slave_if_t * sif)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) sif->last_rx_pkt;

  if ((!memcmp (&sif->partner, &lacpdu->actor.port_info,
		sizeof (sif->partner) - sizeof (sif->partner.state)) &&
       ((sif->actor.state & LACP_STATE_AGGREGATION) ==
	(lacpdu->partner.port_info.state & LACP_STATE_AGGREGATION))) ||
      ((lacpdu->actor.port_info.state & LACP_STATE_AGGREGATION) == 0))
    return 1;

  return 0;
}

static void
lacp_record_pdu (slave_if_t * sif)
{
  lacp_pdu_t *lacpdu = (lacp_pdu_t *) sif->last_rx_pkt;
  u8 match;

  match = lacp_compare_partner (sif);
  sif->partner = lacpdu->actor.port_info;
  sif->actor.state &= ~LACP_STATE_DEFAULTED;
  if (match && (lacpdu->actor.port_info.state & LACP_STATE_SYNCHRONIZATION))
    sif->partner.state |= LACP_STATE_SYNCHRONIZATION;
  else
    sif->partner.state &= ~LACP_STATE_SYNCHRONIZATION;
}

int
lacp_rx_action_initialize (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  sif->port_enabled = 1;
  sif->selected = LACP_PORT_UNSELECTED;
  lacp_machine_dispatch (&lacp_mux_machine, vm, sif,
			 LACP_MUX_EVENT_UNSELECTED, &sif->mux_state);
  lacp_record_default (sif);
  sif->actor.state &= ~LACP_STATE_EXPIRED;
  sif->port_moved = 0;

  if (sif->port_enabled)
    {
      if (sif->lacp_enabled)
	lacp_machine_dispatch (&lacp_rx_machine, vm, sif,
			       LACP_RX_EVENT_TIMER_EXPIRED, &sif->rx_state);
      else
	lacp_machine_dispatch (&lacp_rx_machine, vm, sif,
			       LACP_RX_EVENT_TIMER_EXPIRED, &sif->rx_state);
    }

  return 0;
}

int
lacp_rx_action_port_disabled (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  sif->partner.state &= ~LACP_STATE_SYNCHRONIZATION;
  // post partner sync event to mux
  lacp_selection_logic (vm, sif);

  return 0;
}

int
lacp_rx_action_expired (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  sif->partner.state &= ~LACP_STATE_SYNCHRONIZATION;
  sif->partner.state |= LACP_STATE_LACP_TIMEOUT;
  lacp_machine_dispatch (&lacp_ptx_machine, vm, sif,
			 LACP_PTX_EVENT_SHORT_TIMEOUT, &sif->ptx_state);
  sif->current_while_timer = vlib_time_now (vm) + LACP_SHORT_TIMOUT_TIME;
  sif->actor.state |= LACP_STATE_EXPIRED;
  // post event to mux?
  lacp_selection_logic (vm, sif);

  return 0;
}

int
lacp_rx_action_lacp_disabled (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  sif->selected = LACP_PORT_UNSELECTED;
  lacp_machine_dispatch (&lacp_mux_machine, vm, sif,
			 LACP_MUX_EVENT_UNSELECTED, &sif->mux_state);
  lacp_record_default (sif);
  sif->partner.state &= ~LACP_STATE_AGGREGATION;
  sif->actor.state &= ~LACP_STATE_EXPIRED;
  lacp_selection_logic (vm, sif);

  return 0;
}

int
lacp_rx_action_defaulted (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  lacp_update_default_selected (vm, sif);
  lacp_record_default (sif);
  sif->actor.state &= ~LACP_STATE_EXPIRED;
  lacp_selection_logic (vm, sif);

  return 0;
}

int
lacp_rx_action_current (void *p1, void *p2)
{
  vlib_main_t *vm = (vlib_main_t *) p1;
  slave_if_t *sif = (slave_if_t *) p2;

  lacp_update_selected (vm, sif);
  lacp_update_ntt (vm, sif);
  lacp_record_pdu (sif);
  sif->current_while_timer = vlib_time_now (vm) + sif->ttl_in_seconds;
  sif->actor.state &= ~LACP_STATE_EXPIRED;
  lacp_selection_logic (vm, sif);

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
lacp_init_rx_machine (vlib_main_t * vm, slave_if_t * sif)
{
  lacp_machine_dispatch (&lacp_rx_machine, vm, sif, LACP_RX_EVENT_BEGIN,
			 &sif->rx_state);
  lacp_machine_dispatch (&lacp_rx_machine, vm, sif,
			 LACP_RX_EVENT_LACP_ENABLED, &sif->rx_state);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
