/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#define _GNU_SOURCE

#include <vnet/bonding/node.h>
#include <lacp/node.h>

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
  vlib_main_t *vm = p1;
  member_if_t *mif = p2;
  f64 now = vlib_time_now (vm);

  if (!lacp_timer_is_running (mif->periodic_timer))
    return 0;

  // No more than 3 LACPDUs per fast interval
  if (now <= (mif->last_lacpdu_sent_time + 0.333))
    return 0;

  if (mif->ntt)
    {
      lacp_send_lacp_pdu (vm, mif);
      lacp_schedule_periodic_timer (vm, mif);
    }
  mif->ntt = 0;

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
  lacp_event_struct *event_entry = lacp_tx_event_array;

  if (e >= (sizeof (lacp_tx_event_array) / sizeof (*event_entry)))
    s = format (s, "Bad event %d", e);
  else
    s = format (s, "%s", event_entry[e].str);

  return s;
}

void
lacp_tx_debug_func (member_if_t * mif, int event, int state,
		    lacp_fsm_state_t * transition)
{
  vlib_worker_thread_t *w = vlib_worker_threads + os_get_thread_index ();
  ELOG_TYPE_DECLARE (e) =
    {
      .format = "%s",
      .format_args = "T4",
    };
  struct
  {
    u32 event;
  } *ed = 0;

  ed = ELOG_TRACK_DATA (vlib_get_elog_main (), e, w->elog_track);
  ed->event = elog_string (
    vlib_get_elog_main (), "%U-TX: %U, %U->%U%c", format_vnet_sw_if_index_name,
    vnet_get_main (), mif->sw_if_index, format_tx_event, event,
    format_tx_sm_state, state, format_tx_sm_state, transition->next_state, 0);
}

void
lacp_init_tx_machine (vlib_main_t * vm, member_if_t * mif)
{
  lacp_machine_dispatch (&lacp_tx_machine, vm, mif, LACP_TX_EVENT_BEGIN,
			 &mif->tx_state);
}
