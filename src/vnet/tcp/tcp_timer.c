/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2020 Cisco and/or its affiliates.
 */

#include <vnet/tcp/tcp_timer.h>
#include <vppinfra/tw_timer_template.c>

void
tcp_timer_initialize_wheel (tcp_timer_wheel_t * tw,
			    void (*expired_timer_cb) (u32 *), f64 now)
{
  ASSERT (tw->timers == 0);
  tw_timer_wheel_init_tcp_twsl (tw, expired_timer_cb, TCP_TIMER_TICK, ~0);
  tw->last_run_time = now;
}
