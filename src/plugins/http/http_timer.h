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

#ifndef SRC_PLUGINS_HTTP_HTTP_TIMER_H_
#define SRC_PLUGINS_HTTP_HTTP_TIMER_H_

#include <http/http.h>
#include <vppinfra/tw_timer_2t_1w_2048sl.h>

#define HTTP_CONN_TIMEOUT 60

typedef void (http_conn_timeout_fn) (void *);

typedef struct http_tw_ctx_
{
  tw_timer_wheel_2t_1w_2048sl_t tw;
  clib_spinlock_t tw_lock;
  http_conn_timeout_fn *cb_fn;
} http_tw_ctx_t;

extern http_tw_ctx_t http_tw_ctx;

void http_timers_init (vlib_main_t *vm, http_conn_timeout_fn *cb_fn);

static inline void
http_conn_timer_start (http_conn_t *hc)
{
  http_tw_ctx_t *twc = &http_tw_ctx;
  u32 hs_handle;
  u64 timeout;

  timeout = HTTP_CONN_TIMEOUT;
  hs_handle = hc->c_thread_index << 24 | hc->c_c_index;

  clib_spinlock_lock (&twc->tw_lock);
  hc->timer_handle =
    tw_timer_start_2t_1w_2048sl (&twc->tw, hs_handle, 0, timeout);
  clib_spinlock_unlock (&twc->tw_lock);
}

static inline void
http_conn_timer_stop (http_conn_t *hc)
{
  http_tw_ctx_t *twc = &http_tw_ctx;

  if (hc->timer_handle == ~0)
    return;

  clib_spinlock_lock (&twc->tw_lock);
  tw_timer_stop_2t_1w_2048sl (&twc->tw, hc->timer_handle);
  hc->timer_handle = ~0;
  clib_spinlock_unlock (&twc->tw_lock);
}

static inline void
http_conn_timer_update (http_conn_t *hc)
{
  http_tw_ctx_t *twc = &http_tw_ctx;
  u64 timeout;

  if (hc->timer_handle == ~0)
    return;

  timeout = HTTP_CONN_TIMEOUT;

  clib_spinlock_lock (&twc->tw_lock);
  tw_timer_update_2t_1w_2048sl (&twc->tw, hc->timer_handle, timeout);
  clib_spinlock_unlock (&twc->tw_lock);
}

#endif /* SRC_PLUGINS_HTTP_HTTP_TIMER_H_ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
