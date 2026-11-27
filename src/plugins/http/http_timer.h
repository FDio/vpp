/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2022 Cisco and/or its affiliates.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP_TIMER_H_
#define SRC_PLUGINS_HTTP_HTTP_TIMER_H_

#include <http/http_private.h>

#define HTTP_CONN_TIMEOUT	  60
#define HTTP_TIMER_HANDLE_INVALID ((u32) ~0)

void http_timers_disable (void);
void http_conn_timer_start (http_ctx_t *hc);
void http_conn_timer_stop (http_ctx_t *hc);
void http_conn_timeout (http_ctx_t *hc);

static inline u64
http_conn_timer_interval (const tw_timer_wheel_1t_3w_1024sl_ov_t *tw, u32 timeout, f64 now)
{
  /* Account for whole ticks that have elapsed since the wheel last ran. */
  return timeout + (u64) clib_max (now - tw->last_run_time, 0.0);
}

static inline void
http_conn_timer_update (http_ctx_t *hc)
{
  ASSERT (hc->c_thread_index == vlib_get_thread_index ());
  if (PREDICT_FALSE (hc->timer_handle == HTTP_TIMER_HANDLE_INVALID))
    {
      /* Activity can supersede an expiration waiting for dispatch. */
      if (hc->timer_expiry_slot)
	http_conn_timer_start (hc);
      return;
    }

  http_worker_t *wrk = http_worker_get (hc->c_thread_index);
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw = &wrk->timer_wheel;
  f64 now = vlib_time_now (wrk->vm);
  tw_timer_update_1t_3w_1024sl_ov (tw, hc->timer_handle,
				   http_conn_timer_interval (tw, hc->hc_timeout, now));
}

#endif /* SRC_PLUGINS_HTTP_HTTP_TIMER_H_ */
