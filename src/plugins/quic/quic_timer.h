/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_timer_h__
#define __included_quic_timer_h__

#include <quic/quic.h>

#define QUIC_TIMER_INTERVAL	  0.001	      /* QUIC tick resolution (1ms) */
#define QUIC_DEFAULT_CONN_TIMEOUT (30 * 1000) /* 30 seconds */

void quic_timer_initialize_wheel (quic_timer_wheel_t *tw, void (*expired_timer_cb) (u32 *),
				  f64 now);

static_always_inline void
quic_update_time (f64 now, u8 thread_index)
{
  quic_main_t *qm = &quic_main;
  quic_timer_wheel_t *tw = &quic_wrk_ctx_get (qm, thread_index)->timer_wheel;

  quic_wrk_ctx_get (qm, thread_index)->time_now = (int64_t) (now * 1000.f);
  tw_timer_expire_timers_quic_twslov (tw, now);
}

static_always_inline void
quic_conn_timer_start (quic_timer_wheel_t *tw, quic_ctx_t *ctx, quic_timers_t timer_id,
		       u32 interval)
{
  ASSERT (!quic_ctx_is_stream (ctx));
  ASSERT (ctx->timers[timer_id] == QUIC_TIMER_HANDLE_INVALID);
  QUIC_DBG (4, "Started timer for ctx %u, timer_id %u", ctx->c_c_index, timer_id);
  ctx->timers[timer_id] = tw_timer_start_quic_twslov (tw, ctx->c_c_index, timer_id, interval);
}

static_always_inline void
quic_conn_timer_stop (quic_timer_wheel_t *tw, quic_ctx_t *ctx, quic_timers_t timer_id)
{
  ASSERT (!quic_ctx_is_stream (ctx));
  QUIC_DBG (4, "Stopped timer for ctx %u, timer_id %u", ctx->c_c_index, timer_id);
  if (ctx->timers[timer_id] == QUIC_TIMER_HANDLE_INVALID)
    return;
  tw_timer_stop_quic_twslov (tw, ctx->timers[timer_id]);
  ctx->timers[timer_id] = QUIC_TIMER_HANDLE_INVALID;
}

void quic_conn_tx_timer_update (quic_worker_ctx_t *wc, quic_ctx_t *ctx, int64_t next_timeout);

void quic_conn_tx_timer_stop (quic_worker_ctx_t *wc, quic_ctx_t *ctx);

void quic_conn_accept_timer_stop (quic_worker_ctx_t *wc, quic_ctx_t *ctx);

#endif /* __included_quic_timer_h__ */
