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

#ifndef	__VNET_BONDING_LACP_MUX_MACHINE_H__
#define	__VNET_BONDING_LACP_MUX_MACHINE_H__

#include <stdint.h>
#include <vnet/bonding/lacp/machine.h>

#define foreach_lacp_mux_event          \
  _(0, BEGIN, "begin")                  \
  _(1, SELECTED, "selected")            \
  _(2, STANDBY, "standby")              \
  _(3, UNSELECTED, "unselected")        \
  _(4, READY, "ready")                  \
  _(5, SYNC, "sync")

typedef enum
{
#define _(a, b, c) LACP_MUX_EVENT_##b = (a),
  foreach_lacp_mux_event
#undef _
} lacp_mux_event_t;

#define foreach_lacp_mux_sm_state       \
  _(0, DETACHED, "detached")            \
  _(1, WAITING, "waiting")              \
  _(2, ATTACHED, "attached")            \
  _(3, COLLECTING_DISTRIBUTING, "collecting distributing")

typedef enum
{
#define _(a, b, c) LACP_MUX_STATE_##b = (a),
  foreach_lacp_mux_sm_state
#undef _
} lacp_mux_sm_state_t;

extern lacp_machine_t lacp_mux_machine;

int lacp_mux_action_detached (void *p1, void *p2);
int lacp_mux_action_attached (void *p1, void *p2);
int lacp_mux_action_waiting (void *p1, void *p2);
int lacp_mux_action_collecting_distributing (void *p1, void *p2);
void lacp_mux_debug_func (slave_if_t * sif, int event, int state,
			  lacp_fsm_state_t * transition);
void lacp_disable_collecting_distributing (vlib_main_t * vm,
					   slave_if_t * sif);
void lacp_enable_collecting_distributing (vlib_main_t * vm, slave_if_t * sif);

#define LACP_ACTION_DETACHED LACP_ACTION_ROUTINE(lacp_mux_action_detached)
#define LACP_ACTION_ATTACHED LACP_ACTION_ROUTINE(lacp_mux_action_attached)
#define LACP_ACTION_WAITING LACP_ACTION_ROUTINE(lacp_mux_action_waiting)
#define LACP_ACTION_COLLECTING_DISTRIBUTING \
  LACP_ACTION_ROUTINE(lacp_mux_action_collecting_distributing)

static inline void
lacp_start_wait_while_timer (vlib_main_t * vm, slave_if_t * sif,
			     u8 expiration)
{
  sif->wait_while_timer = vlib_time_now (vm) + expiration;
}

#endif /* __VNET_BONDING_LACP_MUX_MACHINE_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
