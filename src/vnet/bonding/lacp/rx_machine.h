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

#ifndef	__VNET_BONDING_LACP_RX_MACHINE_H__
#define	__VNET_BONDING_LACP_RX_MACHINE_H__

#include <stdint.h>
#include <vnet/bonding/lacp/machine.h>

#define foreach_lacp_rx_event          \
  _(0, BEGIN, "begin")                 \
  _(1, PORT_DISABLED, "port disabled") \
  _(2, PORT_MOVED, "port moved")       \
  _(3, LACP_ENABLED, "lacp enabled")   \
  _(4, LACP_DISABLED, "lacp disabled") \
  _(5, PDU_RECEIVED, "pdu received")   \
  _(6, TIMER_EXPIRED, "timer expired")

typedef enum
{
#define _(a, b, c) LACP_RX_EVENT_##b = (a),
  foreach_lacp_rx_event
#undef _
} lacp_rx_event_t;

#define foreach_lacp_rx_sm_state       \
  _(0, INITIALIZE, "initialize")       \
  _(1, PORT_DISABLED, "port disabled") \
  _(2, EXPIRED, "expired")             \
  _(3, LACP_DISABLED, "lacp disabled") \
  _(4, DEFAULTED, "defaulted")         \
  _(5, CURRENT, "current")

typedef enum
{
#define _(a, b, c) LACP_RX_STATE_##b = (a),
  foreach_lacp_rx_sm_state
#undef _
} lacp_rx_sm_state_t;

extern lacp_machine_t lacp_rx_machine;

int lacp_rx_action_initialize (void *, void *);
int lacp_rx_action_port_disabled (void *, void *);
int lacp_rx_action_pdu_received (void *, void *);
int lacp_rx_action_expired (void *, void *);
int lacp_rx_action_lacp_disabled (void *, void *);
int lacp_rx_action_defaulted (void *, void *);
int lacp_rx_action_current (void *, void *);
void lacp_rx_debug_func (slave_if_t * sif, int event, int state,
			 lacp_fsm_state_t * transition);
u8 *format_rx_sm_state (u8 * s, va_list * args);

#define LACP_ACTION_INITIALIZE \
  LACP_ACTION_ROUTINE(lacp_rx_action_initialize)
#define LACP_ACTION_PORT_DISABLED \
  LACP_ACTION_ROUTINE(lacp_rx_action_port_disabled)
#define LACP_ACTION_EXPIRED \
  LACP_ACTION_ROUTINE(lacp_rx_action_expired)
#define LACP_ACTION_LACP_DISABLED \
  LACP_ACTION_ROUTINE(lacp_rx_action_lacp_disabled)
#define LACP_ACTION_DEFAULTED LACP_ACTION_ROUTINE(lacp_rx_action_defaulted)
#define LACP_ACTION_CURRENT LACP_ACTION_ROUTINE(lacp_rx_action_current)

#endif /* __VNET_BONDING_LACP_RX_MACHINE_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
