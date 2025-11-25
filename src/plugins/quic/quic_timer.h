/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_timer_h__
#define __included_quic_timer_h__

#include <quic/quic.h>

#define QUIC_TSTAMP_RESOLUTION	  0.001	      /* QUIC tick resolution (1ms) */
#define QUIC_DEFAULT_CONN_TIMEOUT (30 * 1000) /* 30 seconds */

static_always_inline void
quic_update_time (f64 now, u8 thread_index)
{
  quic_main_t *qm = &quic_main;
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw =
    &quic_wrk_ctx_get (qm, thread_index)->timer_wheel;

  quic_wrk_ctx_get (qm, thread_index)->time_now = (int64_t) (now * 1000.f);
  tw_timer_expire_timers_1t_3w_1024sl_ov (tw, now);
}

static_always_inline void
quic_stop_ctx_timer (tw_timer_wheel_1t_3w_1024sl_ov_t *tw, quic_ctx_t *ctx)
{
  if (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID)
    return;
  tw_timer_stop_1t_3w_1024sl_ov (tw, ctx->timer_handle);
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
}

static_always_inline void
quic_update_timer (quic_worker_ctx_t *wc, quic_ctx_t *ctx,
		   int64_t next_timeout)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &wc->timer_wheel;
  int64_t next_interval;
  session_t *quic_session;
  int rv;

  /*  This timeout is in ms which is the unit of our timer */
  next_interval = next_timeout - wc->time_now;

  if (next_timeout == 0 || next_interval <= 0)
    {
      if (ctx->c_s_index == QUIC_SESSION_INVALID)
	{
	  next_interval = 1;
	}
      else
	{
	  quic_session = session_get (ctx->c_s_index, ctx->c_thread_index);
	  if (svm_fifo_set_event (quic_session->tx_fifo))
	    {
	      rv = session_program_tx_io_evt (quic_session->handle,
					      SESSION_IO_EVT_TX);
	      if (PREDICT_FALSE (rv))
		{
		  QUIC_ERR ("Failed to enqueue builtin_tx %d", rv);
		}
	    }
	  return;
	}
    }

  ASSERT (vlib_get_thread_index () == ctx->c_thread_index ||
	  vlib_get_thread_index () == 0);

  QUIC_DBG (4, "Timer set to %ld (int %ld) for ctx %u", next_timeout,
	    next_interval, ctx->c_c_index);

  if (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID)
    {
      if (next_timeout == INT64_MAX)
	{
	  QUIC_DBG (4, "timer for ctx %u already stopped", ctx->c_c_index);
	  return;
	}
      ctx->timer_handle =
	tw_timer_start_1t_3w_1024sl_ov (tw, ctx->c_c_index, 0, next_interval);
    }
  else
    {
      if (next_timeout == INT64_MAX)
	{
	  quic_stop_ctx_timer (tw, ctx);
	  QUIC_DBG (4, "Stopping timer for ctx %u", ctx->c_c_index);
	}
      else
	{
	  tw_timer_update_1t_3w_1024sl_ov (tw, ctx->timer_handle,
					   next_interval);
	}
    }
}

#endif /* __included_quic_timer_h__ */
