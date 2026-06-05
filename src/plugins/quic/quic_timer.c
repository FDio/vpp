/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <quic/quic_timer.h>
#include <vppinfra/tw_timer_template.c>

void
quic_timer_initialize_wheel (quic_timer_wheel_t *tw, void (*expired_timer_cb) (u32 *), f64 now)
{
  ASSERT (tw->timers == 0);
  tw_timer_wheel_init_quic_twslov (tw, expired_timer_cb, QUIC_TIMER_INTERVAL, ~0);
  tw->last_run_time = now;
}

__clib_export void
quic_stop_conn_accept_timer (quic_worker_ctx_t *wc, quic_ctx_t *ctx)
{
  quic_timer_wheel_t *tw = &wc->timer_wheel;
  quic_stop_conn_timer (tw, ctx, QUIC_TIMER_ACCEPT);
}

__clib_export void
quic_stop_conn_tx_timer (quic_worker_ctx_t *wc, quic_ctx_t *ctx)
{
  quic_timer_wheel_t *tw = &wc->timer_wheel;
  quic_stop_conn_timer (tw, ctx, QUIC_TIMER_TX);
}

__clib_export void
quic_update_conn_tx_timer (quic_worker_ctx_t *wc, quic_ctx_t *ctx, int64_t next_timeout)
{
  quic_timer_wheel_t *tw = &wc->timer_wheel;
  int64_t next_interval;
  session_t *quic_session;
  int rv;

  ASSERT (!quic_ctx_is_stream (ctx));
  /*  This timeout is in ms which is the unit of our timer */
  next_interval = next_timeout - wc->time_now;
  if (next_timeout == 0 || next_interval <= 0)
    {
      if (ctx->c_s_index == QUIC_SESSION_INVALID || ctx->flags & QUIC_F_NO_APP_SESSION ||
	  ctx->conn_state == QUIC_CONN_STATE_HANDSHAKE)
	{
	  next_interval = 1;
	}
      else
	{
	  quic_session = session_get (ctx->c_s_index, ctx->c_thread_index);
	  if (svm_fifo_set_event (quic_session->tx_fifo))
	    {
	      rv = session_program_tx_io_evt (quic_session->handle, SESSION_IO_EVT_TX);
	      if (PREDICT_FALSE (rv))
		{
		  QUIC_ERR ("Failed to enqueue builtin_tx %d", rv);
		}
	    }
	  return;
	}
    }

  ASSERT (vlib_get_thread_index () == ctx->c_thread_index || vlib_get_thread_index () == 0);

  QUIC_DBG (4, "Timer set to %ld (int %ld) for ctx %u", next_timeout, next_interval,
	    ctx->c_c_index);

  if (ctx->timers[QUIC_TIMER_TX] == QUIC_TIMER_HANDLE_INVALID)
    {
      if (next_timeout == INT64_MAX)
	{
	  QUIC_DBG (4, "timer for ctx %u already stopped", ctx->c_c_index);
	  return;
	}
      quic_start_conn_timer (tw, ctx, QUIC_TIMER_TX, next_interval);
    }
  else
    {
      if (next_timeout == INT64_MAX)
	quic_stop_conn_timer (tw, ctx, QUIC_TIMER_TX);
      else
	tw_timer_update_quic_twslov (tw, ctx->timers[QUIC_TIMER_TX], next_interval);
    }
}
