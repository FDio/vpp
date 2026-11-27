/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

#include <float.h>
#include <math.h>
#include <http/http_timer.h>

#define HTTP_TIMEOUTS_PER_LOOP 32

static void http_timer_update_time (f64 now, u8 thread_index);

static inline bool
http_timer_has_work (const http_worker_t *wrk)
{
  return wrk->n_timers || wrk->n_pending_timers;
}

static inline void
http_timer_unregister_if_idle (http_worker_t *wrk)
{
  if (!http_timer_has_work (wrk))
    session_register_update_time_fn_w_thread (http_timer_update_time, 0, wrk->vm->thread_index);
}

static inline void
http_conn_timer_cancel_expiry (http_worker_t *wrk, http_ctx_t *hc)
{
  ASSERT (hc->timer_expiry_slot && wrk->n_pending_timers);
  wrk->timer_wheel.expired_timer_handles[hc->timer_expiry_slot - 1] = ~0;
  hc->timer_expiry_slot = 0;
  if (--wrk->n_pending_timers == 0)
    {
      vec_reset_length (wrk->timer_wheel.expired_timer_handles);
      wrk->timer_expiry_cursor = 0;
    }
}

void
http_conn_timer_start (http_ctx_t *hc)
{
  clib_thread_index_t thread_index = hc->c_thread_index;
  http_worker_t *wrk = http_worker_get (thread_index);
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &wrk->timer_wheel;

  ASSERT (thread_index == vlib_get_thread_index ());
  ASSERT (hc->timer_handle == HTTP_TIMER_HANDLE_INVALID);

  f64 now = vlib_time_now (wrk->vm);
  bool first_timer = !http_timer_has_work (wrk);
  if (hc->timer_expiry_slot)
    http_conn_timer_cancel_expiry (wrk, hc);
  if (!wrk->n_timers)
    {
      /* Resume on a whole-second boundary after the wheel was idle. Zero
       * means uninitialized to the timer wheel, even during the first second. */
      f64 last_tick = floor (now);
      tw->last_run_time = last_tick == 0.0 ? DBL_MIN : last_tick;
      tw->next_run_time = last_tick + tw->timer_interval;
    }
  hc->timer_handle = tw_timer_start_1t_3w_1024sl_ov (
    tw, hc->hc_hc_index, 0, http_conn_timer_interval (tw, hc->hc_timeout, now));
  wrk->n_timers++;
  if (first_timer)
    session_register_update_time_fn_w_thread (http_timer_update_time, 1, thread_index);
}

void
http_conn_timer_stop (http_ctx_t *hc)
{
  clib_thread_index_t thread_index = hc->c_thread_index;
  http_worker_t *wrk = http_worker_get (thread_index);

  ASSERT (thread_index == vlib_get_thread_index ());
  if (hc->timer_expiry_slot)
    http_conn_timer_cancel_expiry (wrk, hc);
  else if (hc->timer_handle != HTTP_TIMER_HANDLE_INVALID)
    {
      tw_timer_stop_1t_3w_1024sl_ov (&wrk->timer_wheel, hc->timer_handle);
      hc->timer_handle = HTTP_TIMER_HANDLE_INVALID;
      ASSERT (wrk->n_timers > 0);
      wrk->n_timers--;
    }
  else
    return;

  http_timer_unregister_if_idle (wrk);
}

static void
http_timer_collect_expirations (http_worker_t *wrk, f64 now)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &wrk->timer_wheel;
  clib_thread_index_t thread_index = wrk->vm->thread_index;
  u32 *expired = tw_timer_expire_timers_1t_3w_1024sl_ov (tw, now);

  /* Keep ticks aligned when the callback runs past a boundary. */
  tw->next_run_time = tw->last_run_time + tw->timer_interval;
  if (!vec_len (expired))
    return;

  /* The wheel has freed these handles. Keep the batch until it is dispatched
   * or canceled so I/O and cleanup can identify pending expirations. */
  u32 *hc_index;
  vec_foreach (hc_index, expired)
    {
      http_ctx_t *hc = http_ctx_get_w_thread (*hc_index, thread_index);
      hc->timer_handle = HTTP_TIMER_HANDLE_INVALID;
      hc->timer_expiry_slot = hc_index - expired + 1;
    }

  ASSERT (wrk->n_timers >= vec_len (expired));
  wrk->n_pending_timers = vec_len (expired);
  wrk->n_timers -= wrk->n_pending_timers;
  wrk->timer_dispatch_loop = wrk->vm->main_loop_count;
}

static void
http_timer_dispatch_pending (http_worker_t *wrk)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &wrk->timer_wheel;
  u32 remaining = vec_len (tw->expired_timer_handles) - wrk->timer_expiry_cursor;
  u32 budget = clib_min (remaining, HTTP_TIMEOUTS_PER_LOOP);

  wrk->timer_dispatch_queued = false;
  wrk->timer_dispatch_loop = wrk->vm->main_loop_count;
  for (u32 i = 0; i < budget && wrk->n_pending_timers; i++)
    {
      u32 hc_index = tw->expired_timer_handles[wrk->timer_expiry_cursor++];
      if (hc_index == ~0)
	continue;

      http_ctx_t *hc = http_ctx_get_w_thread (hc_index, wrk->vm->thread_index);
      http_conn_timer_cancel_expiry (wrk, hc);
      http_timer_unregister_if_idle (wrk);
      http_conn_timeout (hc);
    }
}

static void
http_timer_dispatch_rpc (CLIB_UNUSED (session_t *ts))
{
  http_timer_dispatch_pending (http_worker_get (vlib_get_thread_index ()));
}

static void
http_timer_queue_dispatch (http_worker_t *wrk)
{
  clib_thread_index_t thread_index = wrk->vm->thread_index;

  /* With workers and no poll-main, session-input is disabled on main. */
  if (thread_index == 0 && vlib_num_workers () && !session_main.poll_main)
    {
      http_timer_dispatch_pending (wrk);
      return;
    }

  /* Queue behind HTTP RX events, including those left by an earlier
   * session-input run that exhausted its event budget. */
  app_worker_t *app_wrk = application_get_default_worker (application_get (http_main.app_index));
  session_event_t evt = {
    .event_type = SESSION_CTRL_EVT_RPC,
    .rpc_args = { .fp = http_timer_dispatch_rpc },
  };
  wrk->timer_dispatch_queued = true;
  app_worker_add_event_custom (app_wrk, thread_index, &evt);
}

static void
http_timer_update_time (f64 now, u8 thread_index)
{
  http_worker_t *wrk = http_worker_get (thread_index);

  ASSERT (thread_index == vlib_get_thread_index ());
  /* Keep a queued dispatch tied to its batch even if RX cancels every entry. */
  if (!wrk->timer_dispatch_queued)
    {
      if (PREDICT_FALSE (wrk->n_pending_timers))
	{
	  /* Give session I/O a full loop before queuing the close. */
	  if (wrk->timer_dispatch_loop != wrk->vm->main_loop_count)
	    http_timer_queue_dispatch (wrk);
	}
      else if (PREDICT_FALSE (now >= wrk->timer_wheel.next_run_time))
	http_timer_collect_expirations (wrk, now);
    }

  if (PREDICT_FALSE (wrk->n_pending_timers &&
		     vlib_node_get_state (wrk->vm, session_queue_node.index) ==
		       VLIB_NODE_STATE_INTERRUPT))
    vlib_node_set_interrupt_pending (wrk->vm, session_queue_node.index);
}

void
http_timers_disable (void)
{
  http_worker_t *wrk;
  clib_thread_index_t thread_index;
  u32 *handles = 0, *handle;
  http_ctx_t *hc;

  ASSERT (vlib_thread_is_main_w_barrier ());
  vec_foreach (wrk, http_main.wrk)
    {
      tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &wrk->timer_wheel;
      tw_timer_1t_3w_1024sl_ov_t *timer;

      thread_index = wrk - http_main.wrk;
      /* Detaching the HTTP app discards any queued dispatch. */
      wrk->timer_dispatch_queued = false;
      if (http_timer_has_work (wrk))
	session_register_update_time_fn_w_thread (http_timer_update_time, 0, thread_index);

      vec_foreach (handle, tw->expired_timer_handles)
	if (*handle != ~0)
	  http_conn_timer_cancel_expiry (wrk, http_ctx_get_w_thread (*handle, thread_index));

      if (!wrk->n_timers)
	continue;

      /* Detach can leave transport cleanup queued until sessions run again.
       * Invalidate connection handles now, then drain the wheel. */
      pool_foreach (timer, tw->timers)
	{
	  if (timer->user_handle == ~0) /* wheel slot head */
	    continue;
	  hc = http_ctx_get_w_thread (timer->user_handle, thread_index);
	  vec_add1 (handles, hc->timer_handle);
	  hc->timer_handle = HTTP_TIMER_HANDLE_INVALID;
	}
      vec_foreach (handle, handles)
	tw_timer_stop_1t_3w_1024sl_ov (tw, *handle);
      vec_reset_length (handles);
      wrk->n_timers = 0;
    }
  vec_free (handles);
}
