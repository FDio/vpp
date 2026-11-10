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
http2_req_tx_empty_eof (http_ctx_t *req)
{
  return req->tx_buf.vft &&
	 (req->req_flags & (HTTP_REQ_F_TX_STREAMING | HTTP_REQ_F_TX_EOF)) ==
	   (HTTP_REQ_F_TX_STREAMING | HTTP_REQ_F_TX_EOF) &&
	 !http_io_as_max_read (req);
}

/* Return nonzero if DATA work needs another scheduler pass. */
static_always_inline int
http2_sched_dispatch_data_queue (http_worker_t *wrk, http_ctx_t *hc, u8 *n_emissions,
				 u8 max_emissions)
{
  http_ctx_t *head = clib_llist_elt (wrk->ctx_pool, hc->old_tx_streams);
  clib_llist_index_t ri = clib_llist_next_index (head, stream_sched_list);
  http_ctx_t *req;

  /* TODO: RFC9218 Prioritization (urgency will be weight) */
  while (ri != hc->old_tx_streams && !http_io_ts_check_write_thresh (hc) &&
	 *n_emissions < max_emissions)
    {
      ASSERT (hc->flags & HTTP_CONN_F_HAS_REQUEST);
      req = clib_llist_elt (wrk->ctx_pool, ri);
      ri = clib_llist_next_index (req, stream_sched_list);
      /* Empty END_STREAM DATA is not flow controlled. */
      if (!hc->peer_window && !http2_req_tx_empty_eof (req))
	continue;
      HTTP_DBG (1, "sending data req_index %x", ((http_req_handle_t) req->hr_req_handle).req_index);
      clib_llist_remove (wrk->ctx_pool, stream_sched_list, req);
      if (PREDICT_FALSE (req->dispatch_data_cb (req, hc, n_emissions)))
	return 1;
      /* revisit requeued streams while credit remains */
      if (hc->peer_window > 0)
	ri = clib_llist_next_index (head, stream_sched_list);
    }
  return ri != hc->old_tx_streams;
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
  /* Late credit must not restart an already finished streaming producer. */
  if ((req->req_flags & HTTP_REQ_F_TX_STREAMING) && !req->tx_buf.vft)
    return 0;
  /* settings change can make stream window negative */
  if (req->peer_stream_window <= 0 && !http2_req_tx_empty_eof (req))
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
