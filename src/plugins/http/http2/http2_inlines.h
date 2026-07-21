/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#ifndef SRC_PLUGINS_HTTP_HTTP2_INLINES_H_
#define SRC_PLUGINS_HTTP_HTTP2_INLINES_H_

#include <http/http2/http2.h>

static_always_inline void
http2_conn_schedule_w_worker (http_worker_t *wrk, http_ctx_t *hc)
{
  http_ctx_t *he;

  if (!clib_llist_elt_is_linked (hc, sched_list) && !(hc->flags & HTTP_CONN_F_TS_DESCHED))
    {
      he = clib_llist_elt (wrk->ctx_pool, wrk->sched_head);
      clib_llist_add_tail (wrk->ctx_pool, sched_list, hc, he);
    }
}

static_always_inline void
http2_req_schedule_data_tx_w_worker (http_worker_t *wrk, http_ctx_t *hc, http_ctx_t *req)
{
  http_ctx_t *he;

  ASSERT (!clib_llist_elt_is_linked (req, stream_sched_list));
  he = clib_llist_elt (wrk->ctx_pool, hc->old_tx_streams);
  clib_llist_add_tail (wrk->ctx_pool, stream_sched_list, req, he);
}

static_always_inline int
http2_req_update_peer_window (http_worker_t *wrk, http_ctx_t *hc, http_ctx_t *req, i64 delta)
{
  i64 new_value;

  new_value = (i64) req->peer_stream_window + delta;
  if (new_value > HTTP2_WIN_SIZE_MAX)
    return -1;
  req->peer_stream_window = (i32) new_value;
  HTTP_DBG (1, "new window size %ld", req->peer_stream_window);
  /* settings change can make stream window negative */
  if (req->peer_stream_window <= 0)
    {
      HTTP_DBG (1, "descheduling need stream window update");
      req->req_flags |= HTTP_REQ_F_NEED_WINDOW_UPDATE;
      if (clib_llist_elt_is_linked (req, stream_sched_list))
	clib_llist_remove (wrk->ctx_pool, stream_sched_list, req);
      return 0;
    }
  if (req->req_flags & HTTP_REQ_F_NEED_WINDOW_UPDATE)
    {
      req->req_flags &= ~HTTP_REQ_F_NEED_WINDOW_UPDATE;
      if (!clib_llist_elt_is_linked (req, stream_sched_list))
	http2_req_schedule_data_tx_w_worker (wrk, hc, req);
      if (hc->peer_window > 0)
	http2_conn_schedule_w_worker (wrk, hc);
    }
  return 0;
}

#endif /* SRC_PLUGINS_HTTP_HTTP2_INLINES_H_ */
