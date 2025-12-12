/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2017 Cisco and/or its affiliates.
 */

#ifndef	__LACP_TX_MACHINE_H__
#define	__LACP_TX_MACHINE_H__

#include <stdint.h>
#include <lacp/machine.h>

#define foreach_lacp_tx_event          \
  _(0, BEGIN, "begin")                 \
  _(1, NTT, "Need To Transmit")

typedef enum
{
#define _(a, b, c) LACP_TX_EVENT_##b = (a),
  foreach_lacp_tx_event
#undef _
} lacp_tx_event_t;

#define foreach_lacp_tx_sm_state       \
  _(0, TRANSMIT, "transmit PDU")

typedef enum
{
#define _(a, b, c) LACP_TX_STATE_##b = (a),
  foreach_lacp_tx_sm_state
#undef _
} lacp_tx_sm_state_t;

extern lacp_machine_t lacp_tx_machine;

int lacp_tx_action_transmit (void *p1, void *p2);
void lacp_tx_debug_func (member_if_t * mif, int event, int state,
			 lacp_fsm_state_t * transition);

#define LACP_ACTION_TRANSMIT LACP_ACTION_ROUTINE(lacp_tx_action_transmit)

#endif /* __LACP_TX_MACHINE_H__ */
