/*
 * Copyright (c) 2016-2019 Cisco and/or its affiliates.
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
#ifndef __included_tcp_timer_h__
#define __included_tcp_timer_h__

#include <vnet/tcp/tcp_types.h>

always_inline void
tcp_timer_set (tcp_timer_wheel_t * tw, tcp_connection_t * tc, u8 timer_id,
	       u32 interval)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  ASSERT (tc->timers[timer_id] == TCP_TIMER_HANDLE_INVALID);
  tc->timers[timer_id] = tw_timer_start_16t_2w_512sl (tw, tc->c_c_index,
						      timer_id, interval);
}

always_inline void
tcp_timer_reset (tcp_timer_wheel_t * tw, tcp_connection_t * tc, u8 timer_id)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  tc->pending_timers &= ~(1 << timer_id);
  if (tc->timers[timer_id] == TCP_TIMER_HANDLE_INVALID)
    return;

  tw_timer_stop_16t_2w_512sl (tw, tc->timers[timer_id]);
  tc->timers[timer_id] = TCP_TIMER_HANDLE_INVALID;
}

always_inline void
tcp_timer_update (tcp_timer_wheel_t * tw, tcp_connection_t * tc, u8 timer_id,
		  u32 interval)
{
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  if (tc->timers[timer_id] != TCP_TIMER_HANDLE_INVALID)
    tw_timer_update_16t_2w_512sl (tw, tc->timers[timer_id], interval);
  else
    tc->timers[timer_id] = tw_timer_start_16t_2w_512sl (tw, tc->c_c_index,
							timer_id, interval);
}

always_inline void
tcp_retransmit_timer_set (tcp_timer_wheel_t * tw, tcp_connection_t * tc)
{
  ASSERT (tc->snd_una != tc->snd_una_max);
  tcp_timer_set (tw, tc, TCP_TIMER_RETRANSMIT,
		 clib_max (tc->rto * TCP_TO_TIMER_TICK, 1));
}

always_inline void
tcp_retransmit_timer_reset (tcp_timer_wheel_t * tw, tcp_connection_t * tc)
{
  tcp_timer_reset (tw, tc, TCP_TIMER_RETRANSMIT);
}

always_inline void
tcp_retransmit_timer_force_update (tcp_timer_wheel_t * tw,
				   tcp_connection_t * tc)
{
  tcp_timer_update (tw, tc, TCP_TIMER_RETRANSMIT,
		    clib_max (tc->rto * TCP_TO_TIMER_TICK, 1));
}

always_inline void
tcp_persist_timer_set (tcp_timer_wheel_t * tw, tcp_connection_t * tc)
{
  /* Reuse RTO. It's backed off in handler */
  tcp_timer_set (tw, tc, TCP_TIMER_PERSIST,
		 clib_max (tc->rto * TCP_TO_TIMER_TICK, 1));
}

always_inline void
tcp_persist_timer_update (tcp_timer_wheel_t * tw, tcp_connection_t * tc)
{
  u32 interval;

  if (seq_leq (tc->snd_una, tc->snd_congestion + tc->burst_acked))
    interval = 1;
  else
    interval = clib_max (tc->rto * TCP_TO_TIMER_TICK, 1);

  tcp_timer_update (tw, tc, TCP_TIMER_PERSIST, interval);
}

always_inline void
tcp_persist_timer_reset (tcp_timer_wheel_t * tw, tcp_connection_t * tc)
{
  tcp_timer_reset (tw, tc, TCP_TIMER_PERSIST);
}

always_inline void
tcp_retransmit_timer_update (tcp_timer_wheel_t * tw, tcp_connection_t * tc)
{
  if (tc->snd_una == tc->snd_nxt)
    {
      tcp_retransmit_timer_reset (tw, tc);
      if (tc->snd_wnd < tc->snd_mss)
	tcp_persist_timer_update (tw, tc);
    }
  else
    tcp_timer_update (tw, tc, TCP_TIMER_RETRANSMIT,
		      clib_max (tc->rto * TCP_TO_TIMER_TICK, 1));
}

always_inline u8
tcp_timer_is_active (tcp_connection_t * tc, tcp_timers_e timer)
{
  return tc->timers[timer] != TCP_TIMER_HANDLE_INVALID;
}

#endif /* __included_tcp_timer_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
