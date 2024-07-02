/*
 * Copyright (c) 2020 Cisco and/or its affiliates.
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

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
