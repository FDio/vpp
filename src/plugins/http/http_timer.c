/*
 * Copyright (c) 2022 Cisco and/or its affiliates.
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

#include <http/http_timer.h>
#include <vnet/session/session.h>

http_tw_ctx_t http_tw_ctx;

static uword http_timer_process (vlib_main_t *vm, vlib_node_runtime_t *rt,
				 vlib_frame_t *f);

static void
http_timer_process_expired_cb (u32 *expired_timers)
{
  http_tw_ctx_t *twc = &http_tw_ctx;
  u32 hs_handle;
  int i;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session handle. The first bit is the timer id */
      hs_handle = expired_timers[i] & 0x7FFFFFFF;
      twc->invalidate_cb (hs_handle);
    }
  for (i = 0; i < vec_len (expired_timers); i++)
    {
      /* Get session handle. The first bit is the timer id */
      hs_handle = expired_timers[i] & 0x7FFFFFFF;
      HTTP_DBG (1, "rpc to hc [%u]%x", hs_handle >> 24,
		hs_handle & 0x00FFFFFF);
      session_send_rpc_evt_to_thread (hs_handle >> 24, twc->rpc_cb,
				      uword_to_pointer (hs_handle, void *));
    }
}

VLIB_REGISTER_NODE (http_timer_process_node) = {
  .function = http_timer_process,
  .type = VLIB_NODE_TYPE_PROCESS,
  .name = "http-timer-process",
  .state = VLIB_NODE_STATE_DISABLED,
};

static uword
http_timer_process (vlib_main_t *vm, vlib_node_runtime_t *rt, vlib_frame_t *f)
{
  http_tw_ctx_t *twc = &http_tw_ctx;
  f64 now, timeout = 1.0;
  uword *event_data = 0;
  uword __clib_unused event_type;

  while (vlib_node_get_state (vm, http_timer_process_node.index) !=
	 VLIB_NODE_STATE_DISABLED)
    {
      vlib_process_wait_for_event_or_clock (vm, timeout);
      now = vlib_time_now (vm);
      event_type = vlib_process_get_events (vm, (uword **) &event_data);

      /* expire timers */
      clib_spinlock_lock (&twc->tw_lock);
      tw_timer_expire_timers_2t_1w_2048sl (&twc->tw, now);
      clib_spinlock_unlock (&twc->tw_lock);

      vec_reset_length (event_data);
    }
  return 0;
}

void
http_timers_set_state (vlib_main_t *vm, bool enabled)
{
  vlib_node_t *n;

  vlib_node_set_state (
    vm, http_timer_process_node.index,
    (enabled ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED));
  if (enabled)
    {
      n = vlib_get_node (vm, http_timer_process_node.index);
      vlib_start_process (vm, n->runtime_index);
    }
}

void
http_timers_init (vlib_main_t *vm, http_conn_timeout_fn *rpc_cb,
		  http_conn_invalidate_timer_fn *invalidate_cb)
{
  http_tw_ctx_t *twc = &http_tw_ctx;

  ASSERT (twc->tw.timers == 0);

  tw_timer_wheel_init_2t_1w_2048sl (&twc->tw, http_timer_process_expired_cb,
				    1.0 /* timer interval */, ~0);
  clib_spinlock_init (&twc->tw_lock);
  twc->rpc_cb = rpc_cb;
  twc->invalidate_cb = invalidate_cb;

  http_timers_set_state (vm, true);
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
