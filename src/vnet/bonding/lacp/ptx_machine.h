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

#ifndef	__VNET_BONDING_LACP_PTX_MACHINE_H__
#define	__VNET_BONDING_LACP_PTX_MACHINE_H__

#include <stdint.h>
#include <vnet/bonding/lacp/machine.h>

#define foreach_lacp_ptx_event          \
  _(0, BEGIN, "begin")                  \
  _(1, LONG_TIMEOUT, "long tiemout")    \
  _(2, TIMER_EXPIRED, "timer expired")  \
  _(3, SHORT_TIMEOUT, "short timeout")

typedef enum
{
#define _(a, b, c) LACP_PTX_EVENT_##b = (a),
  foreach_lacp_ptx_event
#undef _
} lacp_ptx_event_t;

#define foreach_lacp_ptx_sm_state       \
  _(0, NO_PERIODIC, "no periodic")      \
  _(1, FAST_PERIODIC, "fast periodic")  \
  _(2, SLOW_PERIODIC, "slow periodic")  \
  _(3, PERIODIC_TX, "periodic transmission")

typedef enum
{
#define _(a, b, c) LACP_PTX_STATE_##b = (a),
  foreach_lacp_ptx_sm_state
#undef _
} lacp_ptx_sm_state_t;

extern lacp_machine_t lacp_ptx_machine;

int lacp_ptx_action_no_periodic (void *p1, void *p2);
int lacp_ptx_action_slow_periodic (void *p1, void *p2);
int lacp_ptx_action_fast_periodic (void *p1, void *p2);
int lacp_ptx_action_timer_expired (void *p1, void *p2);
void lacp_ptx_debug_func (slave_if_t * sif, int event, int state,
			  lacp_fsm_state_t * transition);

#define LACP_ACTION_NO_PERIODIC \
  LACP_ACTION_ROUTINE(lacp_ptx_action_no_periodic)
#define LACP_ACTION_SLOW_PERIODIC \
  LACP_ACTION_ROUTINE(lacp_ptx_action_slow_periodic)
#define LACP_ACTION_FAST_PERIODIC \
  LACP_ACTION_ROUTINE(lacp_ptx_action_fast_periodic)
#define LACP_ACTION_TIMER_EXPIRED \
  LACP_ACTION_ROUTINE(lacp_ptx_action_timer_expired)

static inline void
lacp_start_periodic_timer (vlib_main_t * vm, slave_if_t * sif, u8 expiration)
{
  sif->periodic_timer = vlib_time_now (vm) + expiration;
}

#endif /* __VNET_BONDING_LACP_PTX_MACHINE_H__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
