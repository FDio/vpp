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

#ifndef	__VNET_BONDING_LACP_TX_MACHINE_H__
#define	__VNET_BONDING_LACP_TX_MACHINE_H__

#include <stdint.h>
#include <vnet/bonding/lacp/machine.h>

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
void lacp_tx_debug_func (slave_if_t * sif, int event, int state,
			 lacp_fsm_state_t * transition);

#define LACP_ACTION_TRANSMIT LACP_ACTION_ROUTINE(lacp_tx_action_transmit)

#endif /* __VNET_BONDING_LACP_TX_MACHINE_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
