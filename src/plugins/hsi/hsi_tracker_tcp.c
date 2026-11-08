/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <hsi/hsi_tracker_private.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vppinfra/atomics.h>

int
hsi_tcp_session_is_cleanup_ready (session_t *s)
{
  tcp_connection_t *tc = hsi_tcp_connection_at_session (s);

  return (tc->cfg_flags & TCP_CFG_F_TRACKED) && tc->state == TCP_STATE_CLOSED;
}

session_handle_t
hsi_tcp_session_cleanup_peer_handle (session_t *s)
{
  tcp_connection_t *tc = hsi_tcp_connection_at_session (s);
  hsi_tcp_drain_t *drain;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  drain = hsi_tcp_drain_get (s->thread_index, hsi_session_conn_key_from_session (s));
  if (drain)
    return drain->peer_session_handle;

  if (hsi_tcp_connection_is_committed (tc))
    return hsi_tcp_tracker_from_connection (tc)->peer_session_handle;

  return SESSION_INVALID_HANDLE;
}

static void
hsi_tcp_fin_wait_unregister_time_update_rpc (void *arg)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  wrk->tcp_fin_wait_time_unregister_pending = 0;
  if (!wrk->tcp_fin_wait_time_registered || hash_elts (wrk->tcp_fin_wait_by_session_conn))
    return;

  session_register_update_time_fn_w_thread (hsi_tcp_fin_wait_update_time, 0, thread_index);
  wrk->tcp_fin_wait_time_registered = 0;
  /* All entries left were deleted */
  clib_fifo_reset (wrk->tcp_fin_wait_fifo);
}

static_always_inline void
hsi_tcp_fin_wait_maybe_unregister_time_update (clib_thread_index_t thread_index)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  if (!wrk->tcp_fin_wait_time_registered || wrk->tcp_fin_wait_time_unregister_pending ||
      hash_elts (wrk->tcp_fin_wait_by_session_conn))
    return;

  /* Defer unregister so the session update-time vector is not mutated while
   * session code is iterating it. */
  wrk->tcp_fin_wait_time_unregister_pending = 1;
  hsi_send_rpc_force (thread_index, hsi_tcp_fin_wait_unregister_time_update_rpc, 0);
}

static_always_inline void
hsi_tcp_fin_wait_del_key (clib_thread_index_t thread_index, uword key)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  if (!hash_get (wrk->tcp_fin_wait_by_session_conn, key))
    return;

  hash_unset (wrk->tcp_fin_wait_by_session_conn, key);
  hsi_tcp_fin_wait_maybe_unregister_time_update (thread_index);
}

static_always_inline void
hsi_tcp_fin_wait_del (tcp_connection_t *tc)
{
  hsi_tcp_fin_wait_del_key (tc->c_thread_index, hsi_tcp_session_conn_key_from_connection (tc));
}

static void
hsi_tcp_drain_unregister_time_update_rpc (void *arg)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  wrk->tcp_drain_time_unregister_pending = 0;
  if (!wrk->tcp_drain_time_registered || pool_elts (wrk->tcp_drains))
    return;

  session_register_update_time_fn_w_thread (hsi_tcp_drain_update_time, 0, thread_index);
  wrk->tcp_drain_time_registered = 0;
  vec_reset_length (wrk->tcp_drain_update_handles);
}

static_always_inline void
hsi_tcp_drain_maybe_register_time_update (clib_thread_index_t thread_index)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  wrk->tcp_drain_time_unregister_pending = 0;
  if (wrk->tcp_drain_time_registered)
    return;

  session_register_update_time_fn_w_thread (hsi_tcp_drain_update_time, 1, thread_index);
  wrk->tcp_drain_time_registered = 1;
}

static_always_inline void
hsi_tcp_drain_maybe_unregister_time_update (clib_thread_index_t thread_index)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  if (!wrk->tcp_drain_time_registered || wrk->tcp_drain_time_unregister_pending ||
      pool_elts (wrk->tcp_drains))
    return;

  /* Defer unregister so the session update-time vector is not mutated while
   * session code is iterating it. */
  wrk->tcp_drain_time_unregister_pending = 1;
  hsi_send_rpc_force (thread_index, hsi_tcp_drain_unregister_time_update_rpc, 0);
}
static_always_inline void
hsi_tcp_fin_wait_maybe_register_time_update (clib_thread_index_t thread_index)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  wrk->tcp_fin_wait_time_unregister_pending = 0;
  if (wrk->tcp_fin_wait_time_registered)
    return;

  session_register_update_time_fn_w_thread (hsi_tcp_fin_wait_update_time, 1, thread_index);
  wrk->tcp_fin_wait_time_registered = 1;
}

static void
hsi_tcp_drain_stop (tcp_connection_t *tc)
{
  hsi_tcp_drain_t *drain;
  hsi_worker_t *wrk;
  u32 n_dropped;
  u32 drain_index;
  uword key;

  key = hsi_tcp_session_conn_key_from_connection (tc);
  drain_index = hsi_tcp_drain_index_get (tc->c_thread_index, key);
  if (drain_index == HSI_TCP_DRAIN_INDEX_INVALID)
    return;

  wrk = hsi_worker_get (tc->c_thread_index);
  drain = pool_elt_at_index (wrk->tcp_drains, drain_index);
  n_dropped = hsi_drain_drop_cached_buffers (vlib_get_main_by_index (tc->c_thread_index),
					     &drain->cached_buffers, &drain->cached_bytes);
  hsi_worker_counter_add (wrk, tcp_drain_cache_dropped, n_dropped);

  hash_unset (wrk->tcp_drain_by_session_conn, key);
  hsi_tcp_drain_pool_put_index (wrk, drain_index);
  hsi_tcp_drain_maybe_unregister_time_update (tc->c_thread_index);
}
void
hsi_tcp_session_cleanup_state (session_t *s)
{
  tcp_connection_t *tc = hsi_tcp_connection_at_session (s);

  hsi_tcp_fin_wait_del (tc);
  hsi_tcp_drain_stop (tc);
}

static int hsi_tcp_drain_transport_closed (session_t *s, tcp_connection_t *tc,
					   hsi_tcp_drain_t *drain);
static int hsi_tcp_drain_try_complete (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain,
				       f64 now);

static void
hsi_tcp_track_abort_session_inline (session_t *s, u8 send_rst)
{
  hsi_tcp_drain_t *drain;
  tcp_connection_t *tc;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  tc = hsi_tcp_connection_at_session (s);
  if (!(tc->cfg_flags & TCP_CFG_F_TRACKED))
    return;

  drain = hsi_tcp_drain_get (s->thread_index, hsi_session_conn_key_from_session (s));
  if (drain && hsi_tcp_drain_transport_closed (s, tc, drain))
    return;

  if (tc->state != TCP_STATE_CLOSED)
    {
      if (send_rst)
	tcp_send_reset (tc);
      tcp_connection_timers_reset (tc);
      tcp_cong_recovery_off (tc);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
    }

  /* Closed by hsi, not tcp */
  if (drain)
    {
      drain->flags |= HSI_TCP_DRAIN_F_HSI_CLOSED;
      drain->state = HSI_TCP_DRAIN_STATE_FAILED;
    }

  hsi_session_program_cleanup (s);
}

static void
hsi_tcp_track_abort_msg (session_handle_t session_handle, u8 send_rst)
{
  session_handle_tu_t sh = { .handle = session_handle };
  session_t *s;

  s = hsi_session_get_owned_if_valid (sh);
  if (s)
    hsi_tcp_track_abort_session_inline (s, send_rst);
}

static void
hsi_tcp_track_send_abort (session_handle_t session_handle)
{
  session_handle_tu_t sh = { .handle = session_handle };

  if (session_handle == SESSION_INVALID_HANDLE)
    return;

  hsi_mq_send_handle (sh.thread_index, HSI_MSG_TCP_ABORT, session_handle);
}

static_always_inline u8 hsi_tcp_drain_flag_is_set (hsi_tcp_drain_t *drain,
						   hsi_tcp_drain_flags_t flag);

static void
hsi_tcp_track_send_abort_silent (session_handle_t session_handle)
{
  session_handle_tu_t sh = { .handle = session_handle };

  if (session_handle == SESSION_INVALID_HANDLE)
    return;

  hsi_mq_send_handle (sh.thread_index, HSI_MSG_TCP_ABORT_SILENT, session_handle);
}

static void
hsi_tcp_drain_fail_pair_silent (hsi_tcp_drain_t *drain)
{
  if (hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_ABORT_SENT))
    return;

  drain->state = HSI_TCP_DRAIN_STATE_FAILED;
  drain->flags |= HSI_TCP_DRAIN_F_ABORT_SENT;
  hsi_tcp_track_send_abort_silent (drain->peer_session_handle);
  hsi_tcp_track_send_abort_silent (drain->session_handle);
}

/*
 * Pretend rx fifo can only fit what is already buffered, so tcp advertises a
 * zero window, also on data it sends while draining. Only the session's own
 * thread changes the size and it's restored before fifos are freed, so fifo
 * segment accounting is not touched.
 */
static_always_inline void
hsi_tcp_drain_clamp_rx_fifo (session_t *s)
{
  svm_fifo_t *f = s->rx_fifo;
  u32 cursize = svm_fifo_max_dequeue_prod (f);

  if (f->shr->size > cursize)
    f->shr->size = cursize;
}

void
hsi_tcp_session_restore_fifos (session_t *s)
{
  hsi_tcp_drain_t *drain;

  drain = hsi_tcp_drain_get (s->thread_index, hsi_session_conn_key_from_session (s));
  if (drain && drain->rx_fifo_size && s->rx_fifo)
    s->rx_fifo->shr->size = drain->rx_fifo_size;
}

static_always_inline void
hsi_tcp_send_zero_wnd_ack (session_t *s, tcp_connection_t *tc)
{
  /* Tcp won't shrink an advertised window, so start from a zero window and,
   * with no rx fifo space, it stays closed */
  hsi_tcp_drain_clamp_rx_fifo (s);
  tc->rcv_wnd = 0;
  tcp_send_ack (tc);
}

static_always_inline u8
hsi_tcp_segment_data_len (void *ip_hdr, tcp_header_t *tcp_hdr, u8 is_ip4, u32 *data_len)
{
  u32 tcp_hdr_len = tcp_header_bytes (tcp_hdr);

  if (PREDICT_FALSE (tcp_hdr_len < sizeof (*tcp_hdr)))
    return 0;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;
      u32 ip_hdr_len = ip4_header_bytes (ip4);
      u32 ip_len = clib_net_to_host_u16 (ip4->length);

      if (PREDICT_FALSE (ip_len < ip_hdr_len + tcp_hdr_len))
	return 0;

      *data_len = ip_len - ip_hdr_len - tcp_hdr_len;
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      u32 payload_len = clib_net_to_host_u16 (ip6->payload_length);

      if (PREDICT_FALSE (payload_len < tcp_hdr_len))
	return 0;

      *data_len = payload_len - tcp_hdr_len;
    }

  return 1;
}

static_always_inline u8
hsi_tcp_segment_in_rcv_wnd (tcp_connection_t *tc, u32 seq, u32 seq_end, u32 rcv_wnd)
{
  return seq_geq (seq_end, tc->rcv_las) && seq_leq (seq, tc->rcv_nxt + rcv_wnd);
}

#define HSI_TCP_TRACKED_MAX_WND (TCP_WND_MAX << TCP_MAX_WND_SCALE)

/*
 * Tracked connections only splice segments and endpoints validate them, so
 * accept anything within a max window of the highest seq seen. That includes
 * out of order segments, retransmits, keepalives and window probes. Resets
 * tear down the pair, so they must be within the window advertised at commit
 * of the highest seq seen. Below it too, as receivers ack below it if segments
 * were lost and endpoints that lost the connection reset with that ack.
 */
static_always_inline u8
hsi_tcp_tracked_segment_in_wnd (tcp_connection_t *tc, u32 seq, u32 seq_end, u8 rst)
{
  if (PREDICT_FALSE (rst))
    return seq_geq (seq, tc->rcv_nxt - tc->rcv_wnd) && seq_leq (seq, tc->rcv_nxt + tc->rcv_wnd);

  return seq_gt (seq_end, tc->rcv_nxt - HSI_TCP_TRACKED_MAX_WND) &&
	 seq_leq (seq, tc->rcv_nxt + HSI_TCP_TRACKED_MAX_WND);
}

static_always_inline void
hsi_tcp_update_snd_wnd (tcp_connection_t *tc, u32 seq, u32 ack, tcp_header_t *tcp_hdr)
{
  u32 snd_wnd;

  if (seq_lt (tc->snd_wl1, seq) || (tc->snd_wl1 == seq && seq_leq (tc->snd_wl2, ack)))
    {
      snd_wnd = clib_net_to_host_u16 (tcp_hdr->window) << tc->snd_wscale;
      tc->snd_wnd = snd_wnd;
      tc->snd_wl1 = seq;
      tc->snd_wl2 = ack;
    }
}

/*
 * Tcp still sends while draining but hsi consumes the acks, so update tcp's
 * retransmit and persist timers, recovery and scheduling like tcp input would.
 */
static void
hsi_tcp_drain_update_tcp_on_ack (tcp_connection_t *tc, u32 bytes_acked)
{
  tcp_worker_ctx_t *wrk = tcp_get_worker (tc->c_thread_index);

  if (bytes_acked)
    {
      if (tcp_in_recovery (tc) && seq_geq (tc->snd_una, tc->snd_congestion))
	tcp_cong_recovery_off (tc);
      if (!tcp_in_recovery (tc) && tc->rto_boff)
	{
	  tc->rto_boff = 0;
	  tcp_update_rto (tc);
	}
      tcp_retransmit_timer_update (&wrk->timer_wheel, tc);
    }

  if (tc->snd_wnd)
    {
      if (PREDICT_FALSE (tcp_timer_is_active (tc, TCP_TIMER_PERSIST)))
	tcp_persist_timer_reset (&wrk->timer_wheel, tc);
      if (PREDICT_FALSE (tcp_is_descheduled (tc)))
	transport_connection_reschedule (&tc->connection);
    }
  else if (!tcp_timer_is_active (tc, TCP_TIMER_RETRANSMIT) &&
	   !tcp_timer_is_active (tc, TCP_TIMER_PERSIST))
    tcp_persist_timer_set (&wrk->timer_wheel, tc);
}
static void
hsi_tcp_track_snapshot (session_t *s, tcp_connection_t *tc, hsi_tcp_track_snapshot_t *snap)
{
  snap->session_handle = session_handle (s);
  snap->conn_index = tc->c_c_index;
  snap->thread_index = tc->c_thread_index;
  snap->fib_index = tc->c_fib_index;
  snap->lcl_ip = tc->c_lcl_ip;
  snap->rmt_ip = tc->c_rmt_ip;
  snap->lcl_port = tc->c_lcl_port;
  snap->rmt_port = tc->c_rmt_port;
  snap->snd_nxt = tc->snd_nxt;
  snap->rcv_nxt = tc->rcv_nxt;
  snap->snd_wnd = tc->snd_wnd;
  snap->ts_now = tcp_tstamp (tc);
  snap->tsval_recent = tc->tsval_recent;
  snap->rcv_wscale = tc->rcv_wscale;
  snap->snd_wscale = tc->snd_wscale;
  snap->next_node_opaque = tc->next_node_opaque;
}

static_always_inline u8
hsi_tcp_drain_flag_is_set (hsi_tcp_drain_t *drain, hsi_tcp_drain_flags_t flag)
{
  return !!(drain->flags & flag);
}

static_always_inline void
hsi_tcp_drain_flag_set (hsi_tcp_drain_t *drain, hsi_tcp_drain_flags_t flag, u8 is_set)
{
  if (is_set)
    drain->flags |= flag;
  else
    drain->flags &= ~flag;
}

static_always_inline void
hsi_tcp_drain_sample (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain)
{
  ASSERT (s->thread_index == vlib_get_thread_index ());
  hsi_drain_sample_fifos (s, &drain->rx_deq, &drain->tx_deq);
  hsi_tcp_drain_flag_set (drain, HSI_TCP_DRAIN_F_RX_OOO, svm_fifo_has_ooo_data (s->rx_fifo));
  drain->snd_una = tc->snd_una;
  drain->snd_nxt = tc->snd_nxt;
}

/*
 * Sessions only drain what they send. Their rx fifo is their peer's tx fifo, so
 * the peer drains it, but its dequeues still count as progress.
 */
static_always_inline int
hsi_tcp_drain_sample_needs_drain (hsi_tcp_drain_t *drain)
{
  if (drain->tx_deq || hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_RX_OOO))
    return 1;

  return drain->snd_una != drain->snd_nxt;
}

static_always_inline u8
hsi_tcp_drain_sample_changed (hsi_tcp_drain_t *drain, hsi_tcp_drain_t *sample)
{
  return drain->rx_deq != sample->rx_deq || drain->tx_deq != sample->tx_deq ||
	 ((drain->flags ^ sample->flags) & HSI_TCP_DRAIN_F_RX_OOO) ||
	 drain->snd_una != sample->snd_una || drain->snd_nxt != sample->snd_nxt;
}

static int
hsi_tcp_drain_update_and_needs_drain (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain,
				      f64 now)
{
  hsi_tcp_drain_t sample = {};
  int needs_drain;

  hsi_tcp_drain_sample (s, tc, &sample);

  if (hsi_tcp_drain_sample_changed (drain, &sample))
    {
      drain->rx_deq = sample.rx_deq;
      drain->tx_deq = sample.tx_deq;
      hsi_tcp_drain_flag_set (drain, HSI_TCP_DRAIN_F_RX_OOO,
			      hsi_tcp_drain_flag_is_set (&sample, HSI_TCP_DRAIN_F_RX_OOO));
      drain->snd_una = sample.snd_una;
      drain->snd_nxt = sample.snd_nxt;
      drain->last_progress_time = now;
      drain->flags &= ~HSI_TCP_DRAIN_F_STALLED;
    }

  needs_drain = hsi_tcp_drain_sample_needs_drain (&sample);
  if (needs_drain && !hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_STALLED) &&
      now - drain->last_progress_time > hsi_main.tcp_drain_no_progress_timeout)
    {
      hsi_worker_counter_inc (hsi_worker_get (drain->thread_index), tcp_drain_stalled);
      drain->flags |= HSI_TCP_DRAIN_F_STALLED;
      drain->state = HSI_TCP_DRAIN_STATE_FAILED;
      return -1;
    }

  return needs_drain;
}

static_always_inline int
hsi_tcp_track_needs_drain (session_t *s, tcp_connection_t *tc)
{
  hsi_tcp_drain_t sample = {};

  hsi_tcp_drain_sample (s, tc, &sample);
  return hsi_tcp_drain_sample_needs_drain (&sample);
}

static void
hsi_tcp_drain_fail_pair (hsi_tcp_drain_t *drain)
{
  if (hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_ABORT_SENT))
    return;

  drain->state = HSI_TCP_DRAIN_STATE_FAILED;
  drain->flags |= HSI_TCP_DRAIN_F_ABORT_SENT;
  hsi_tcp_track_send_abort (drain->peer_session_handle);
  hsi_tcp_track_send_abort (drain->session_handle);
}

static hsi_tcp_drain_t *
hsi_tcp_drain_start (session_t *s, session_t *peer_s, tcp_connection_t *tc,
		     tcp_connection_t *peer_tc)
{
  clib_thread_index_t thread_index = s->thread_index;
  hsi_tcp_drain_t *drain;
  hsi_worker_t *wrk;
  u32 drain_index;
  uword key;
  f64 now;

  ASSERT (thread_index == vlib_get_thread_index ());

  key = hsi_session_conn_key_from_session (s);
  drain = hsi_tcp_drain_get (thread_index, key);
  if (drain)
    return drain;

  wrk = hsi_worker_get (thread_index);
  drain = hsi_tcp_drain_pool_get (wrk, &drain_index);
  hash_set (wrk->tcp_drain_by_session_conn, key, drain_index);

  hsi_session_take_ownership (s);
  hsi_tcp_track_snapshot (s, tc, &drain->snapshot);
  now = vlib_time_now (vlib_get_main ());

  drain->session_handle = session_handle (s);
  drain->peer_session_handle = session_handle (peer_s);
  drain->conn_index = tc->c_c_index;
  drain->peer_conn_index = peer_tc->c_c_index;
  drain->thread_index = thread_index;
  drain->start_time = now;
  drain->last_progress_time = now;
  hsi_tcp_drain_sample (s, tc, drain);
  drain->state = HSI_TCP_DRAIN_STATE_DRAINING;
  drain->rx_fifo_size = svm_fifo_size (s->rx_fifo);
  drain->rcv_wnd = tc->rcv_wnd;
  tc->cfg_flags |= TCP_CFG_F_TRACKED;
  hsi_tcp_send_zero_wnd_ack (s, tc);
  drain->flags |= HSI_TCP_DRAIN_F_WND_CLAMPED;
  hsi_worker_counter_inc (wrk, tcp_drain_started);
  hsi_tcp_drain_maybe_register_time_update (thread_index);
  hsi_drain_program_tx (s);
  hsi_drain_program_peer_tx (s, drain->peer_session_handle);

  return drain;
}

static_always_inline void
hsi_tcp_fin_wait_add (tcp_connection_t *tc, f64 start)
{
  hsi_worker_t *wrk = hsi_worker_get (tc->c_thread_index);
  hsi_tcp_fin_wait_elt_t elt = {
    .key = hsi_tcp_session_conn_key_from_connection (tc),
    .start = start,
  };

  hash_set (wrk->tcp_fin_wait_by_session_conn, elt.key, 1);
  /* All entries have the same timeout, so they expire in the order added */
  clib_fifo_add1 (wrk->tcp_fin_wait_fifo, elt);

  hsi_tcp_fin_wait_maybe_register_time_update (tc->c_thread_index);
}

static_always_inline int
hsi_tcp_track_connections_compatible (tcp_connection_t *tc0, tcp_connection_t *tc1)
{
  if (tc0->c_is_ip4 != tc1->c_is_ip4)
    return 0;
  if (!!tcp_opts_tstamp (&tc0->rcv_opts) != !!tcp_opts_tstamp (&tc1->rcv_opts))
    return 0;
  if (!!tcp_opts_sack_permitted (&tc0->rcv_opts) != !!tcp_opts_sack_permitted (&tc1->rcv_opts))
    return 0;

  return 1;
}

static_always_inline int
hsi_tcp_track_is_possible (tcp_connection_t *tc0, tcp_connection_t *tc1)
{
  if (tc0->cfg_flags & TCP_CFG_F_TRACKED)
    return 0;
  if (tc1->cfg_flags & TCP_CFG_F_TRACKED)
    return 0;

  return hsi_tcp_track_connections_compatible (tc0, tc1);
}

static void
hsi_tcp_drain_start_msg (hsi_tcp_drain_start_req_t *a)
{
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_handle_tu_t peer_sh = { .handle = a->peer_session_handle };
  session_t *s, *peer_s;
  tcp_connection_t *tc, *peer_tc;
  hsi_tcp_drain_t *drain;

  ASSERT (sh.thread_index == vlib_get_thread_index ());
  s = session_get_from_handle_if_valid (sh);
  peer_s = hsi_session_peer_get_if_valid (peer_sh);
  if (!s || !peer_s)
    {
      hsi_worker_counter_inc (hsi_worker_get (sh.thread_index), tcp_track_peer_rpc_failed);
      hsi_tcp_track_send_abort (a->session_handle);
      hsi_tcp_track_send_abort (a->peer_session_handle);
      return;
    }

  tc = hsi_tcp_connection_at_session (s);
  peer_tc = hsi_tcp_connection_at_session (peer_s);
  ASSERT (!(tc->cfg_flags & TCP_CFG_F_TRACKED));
  ASSERT (peer_tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (hsi_tcp_track_connections_compatible (tc, peer_tc));
  hsi_session_save_app_wrk (s, a->flags);
  drain = hsi_tcp_drain_start (s, peer_s, tc, peer_tc);

  /* App handed off session but it might have been closed while the message
   * was pending. Drains also can't fill rx holes. Either way fail the pair */
  if (!hsi_track_sessions_compatible (s, peer_s) || svm_fifo_has_ooo_data (s->rx_fifo))
    {
      hsi_tcp_drain_fail_pair (drain);
      return;
    }

  hsi_tcp_drain_try_complete (s, tc, drain, vlib_time_now (vlib_get_main ()));
}

static void
hsi_tcp_track_send_drain_start (session_t *s, session_t *peer_s, hsi_track_flags_t flags)
{
  hsi_msg_t msg = { .type = HSI_MSG_TCP_DRAIN_START };

  ASSERT (s->thread_index == vlib_get_thread_index ());
  msg.tcp_drain_start.session_handle = session_handle (peer_s);
  msg.tcp_drain_start.peer_session_handle = session_handle (s);
  msg.tcp_drain_start.flags = flags;
  hsi_mq_send (peer_s->thread_index, &msg);
}

static void
hsi_tcp_tracker_init (hsi_tcp_tracker_t *trk, tcp_connection_t *tc, hsi_tcp_track_snapshot_t *self,
		      hsi_tcp_track_snapshot_t *peer)
{
  clib_memset (trk, 0, sizeof (*trk));

  trk->magic = HSI_TCP_TRACKER_MAGIC;
  trk->cc_algo = tcp_cc_algo_get (TCP_CC_NEWRENO);
  trk->peer_session_handle = peer->session_handle;
  trk->peer_conn_index = peer->conn_index;
  trk->tx_fib_index = peer->fib_index;
  trk->tx_lcl_ip = peer->lcl_ip;
  trk->tx_rmt_ip = peer->rmt_ip;
  trk->tx_lcl_port = peer->lcl_port;
  trk->tx_rmt_port = peer->rmt_port;

  /*
   * At commit, tc->rcv_nxt maps to peer->snd_nxt and tc->snd_nxt maps to
   * peer->rcv_nxt. The peer tuple is kept as the transmit rewrite tuple.
   */
  trk->seq_delta = (i32) (peer->snd_nxt - tc->rcv_nxt);
  trk->ack_delta = (i32) (peer->rcv_nxt - tc->snd_nxt);
  /* Peer maps timestamps with the same snapshots, so echoes map back exactly */
  trk->tsval_delta = (i32) (peer->ts_now - self->tsval_recent);
  trk->tsecr_delta = (i32) (peer->tsval_recent - self->ts_now);
  trk->wnd_delta = (i8) tc->snd_wscale - (i8) peer->rcv_wscale;
  trk->next_node_opaque = tc->next_node_opaque;
  trk->peer_next_node_opaque = peer->next_node_opaque;
}

static void
hsi_tcp_track_cleanup_tcp_state (tcp_connection_t *tc)
{
  if (tc->cc_algo && tc->cc_algo->cleanup)
    tc->cc_algo->cleanup (tc);

  vec_free (tc->snd_sacks);
  vec_free (tc->snd_sacks_fl);
  vec_free (tc->rcv_opts.sacks);
  pool_free (tc->sack_sb.holes);
  clib_memset (&tc->sack_sb, 0, sizeof (tc->sack_sb));
  scoreboard_init (&tc->sack_sb);

  if (tc->cfg_flags & TCP_CFG_F_BYTE_TRACKER)
    {
      tcp_bt_cleanup (tc);
    }
}

static void
hsi_tcp_track_cleanup_pending_tx (session_t *s, tcp_connection_t *tc)
{
  s->flags &= ~SESSION_F_CUSTOM_TX;
  if (s->tx_fifo)
    svm_fifo_unset_event (s->tx_fifo);

  tcp_cong_recovery_off (tc);
  tc->flags &= ~(TCP_CONN_SNDACK | TCP_CONN_RXT_PENDING | TCP_CONN_DEQ_PENDING);
  tc->pending_dupacks = 0;
  tc->snd_sack_pos = 0;
  tc->snd_rxt_bytes = 0;
  tc->rxt_delivered = 0;
}

static void
hsi_tcp_drain_flush_cached_buffers (tcp_connection_t *tc)
{
  hsi_tcp_drain_t *drain;
  hsi_worker_t *wrk;
  vlib_main_t *vm;
  u32 *cached, *forward = 0, *drops = 0;
  u32 i, fwd_node_index, fwd_opaque;
  uword key;

  key = hsi_tcp_session_conn_key_from_connection (tc);
  drain = hsi_tcp_drain_get (tc->c_thread_index, key);
  if (!drain || !vec_len (drain->cached_buffers))
    return;

  vm = vlib_get_main_by_index (tc->c_thread_index);
  wrk = hsi_worker_get (tc->c_thread_index);
  cached = drain->cached_buffers;
  drain->cached_buffers = 0;
  drain->cached_bytes = 0;

  hsi_tcp_tracker_t *trk = hsi_tcp_tracker_get (tc);

  /* If tcp output is overridden, forward through the override with our opaque,
   * because we send from this worker. See hsi.h */
  if (tc->next_node_index)
    {
      fwd_node_index =
	vlib_get_next_node (vm, tcp_node_index (output, tc->c_is_ip4), tc->next_node_index)->index;
      fwd_opaque = trk->next_node_opaque;
    }
  else
    {
      fwd_node_index = tc->c_is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
      fwd_opaque = trk->peer_next_node_opaque;
    }

  for (i = 0; i < vec_len (cached); i++)
    {
      hsi_tcp_tracked_action_t action;
      tcp_header_t *tcp_hdr;
      vlib_buffer_t *b;
      void *ip_hdr;

      b = vlib_get_buffer (vm, cached[i]);
      ip_hdr = vlib_buffer_get_current (b);
      tcp_hdr = tc->c_is_ip4 ? ip4_next_header ((ip4_header_t *) ip_hdr) :
			       ip6_next_header ((ip6_header_t *) ip_hdr);

      action = hsi_tcp_handle_tracked_connection (vm, b, tc, ip_hdr, tcp_hdr, tc->c_is_ip4, 0);
      if (action == HSI_TCP_TRACKED_ACTION_FORWARD)
	{
	  vnet_buffer (b)->tcp.next_node_opaque = fwd_opaque;
	  vec_add1 (forward, cached[i]);
	  if (PREDICT_FALSE (tcp_rst (tcp_hdr)))
	    {
	      i++;
	      break;
	    }
	}
      else
	vec_add1 (drops, cached[i]);
    }

  for (; i < vec_len (cached); i++)
    vec_add1 (drops, cached[i]);

  if (vec_len (forward))
    {
      hsi_drain_enqueue_cached_buffers (vm, fwd_node_index, forward);
      hsi_worker_counter_add (wrk, tcp_drain_cache_flushed, vec_len (forward));
    }

  if (vec_len (drops))
    {
      vlib_buffer_free (vm, drops, vec_len (drops));
      hsi_worker_counter_add (wrk, tcp_drain_cache_dropped, vec_len (drops));
    }

  vec_free (forward);
  vec_free (drops);
  vec_free (cached);
}

static void
hsi_tcp_track_commit_connection (tcp_connection_t *tc, hsi_tcp_track_snapshot_t *self,
				 hsi_tcp_track_snapshot_t *peer)
{
  hsi_tcp_track_cleanup_tcp_state (tc);
  hsi_tcp_tracker_init (hsi_tcp_tracker_from_connection (tc), tc, self, peer);

  tc->cfg_flags |= TCP_CFG_F_TRACKED;
  tc->c_flags |= TRANSPORT_CONNECTION_F_SPLICED;
  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
}

/* Replay packets cached while draining. Must be done once the peer, if on the
 * same thread, is also committed because replayed fins update the peer */
static void
hsi_tcp_track_commit_flush (tcp_connection_t *tc)
{
  hsi_worker_t *wrk = hsi_worker_get (tc->c_thread_index);

  hsi_tcp_drain_flush_cached_buffers (tc);
  if (hsi_tcp_drain_get (tc->c_thread_index, hsi_tcp_session_conn_key_from_connection (tc)))
    hsi_worker_counter_inc (wrk, tcp_drain_completed);
  hsi_tcp_drain_stop (tc);
}

/*
 * Ack that reopens the window closed while draining, to what the peer endpoint
 * advertises. Built from the session's commit snapshot, so seq, ack and
 * timestamps are consistent with what the tracker forwards afterwards. Sent
 * through tcp output, so it leaves like any other segment of the connection,
 * e.g., honoring its output node override.
 */
static void
hsi_tcp_send_window_update (tcp_connection_t *tc, hsi_tcp_track_snapshot_t *self,
			    hsi_tcp_track_snapshot_t *peer)
{
  vlib_main_t *vm = vlib_get_main ();
  tcp_options_t _opts = {}, *opts = &_opts;
  u32 bi, wnd, next_index, *to_next;
  u8 opts_len = 0;
  tcp_header_t *th;
  vlib_buffer_t *b;
  vlib_frame_t *f;

  ASSERT (tc->c_thread_index == vm->thread_index);

  /* Tracker validates resets against the reopened window */
  wnd = clib_min (peer->snd_wnd >> self->rcv_wscale, TCP_WND_MAX);
  tc->rcv_wnd = wnd << self->rcv_wscale;

  if (PREDICT_FALSE (vlib_buffer_alloc (vm, &bi, 1) != 1))
    return;

  b = vlib_get_buffer (vm, bi);
  b->flags |= VNET_BUFFER_F_LOCALLY_ORIGINATED;
  b->total_length_not_including_first_buffer = 0;
  b->current_data = 0;
  vnet_buffer (b)->tcp.flags = 0;
  vlib_buffer_make_headroom (b, TRANSPORT_MAX_HDRS_LEN);

  if (tcp_opts_tstamp (&tc->rcv_opts))
    {
      opts->flags |= TCP_OPTS_FLAG_TSTAMP;
      opts->tsval = self->ts_now;
      opts->tsecr = self->tsval_recent;
      opts_len = TCP_OPTION_LEN_TIMESTAMP + 2 * TCP_OPTION_LEN_NOOP;
    }

  th = vlib_buffer_push_tcp (b, self->lcl_port, self->rmt_port, self->snd_nxt, self->rcv_nxt,
			     sizeof (tcp_header_t) + opts_len, TCP_FLAG_ACK, wnd);
  tcp_options_write ((u8 *) (th + 1), opts);
  th->checksum = tcp_compute_checksum (tc, b);

  /* tcp output adds the ip header and picks the next node */
  vnet_buffer (b)->tcp.connection_index = tc->c_c_index;
  next_index = tc->c_is_ip4 ? tcp4_output_node.index : tcp6_output_node.index;

  f = vlib_get_frame_to_node (vm, next_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = bi;
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, next_index, f);
}

/* Returns 1 if session was committed, in which case caller must flush */
static int
hsi_tcp_track_commit_no_flush (session_t *s, hsi_tcp_track_snapshot_t *self,
			       hsi_tcp_track_snapshot_t *peer)
{
  hsi_tcp_drain_t *drain;
  tcp_connection_t *tc;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  tc = hsi_tcp_connection_at_session (s);
  if (hsi_tcp_connection_is_committed (tc))
    return 0;

  drain = hsi_tcp_drain_get (s->thread_index, hsi_session_conn_key_from_session (s));

  /* Closed while draining. If not by hsi, tcp closed it */
  if (tc->state == TCP_STATE_CLOSED)
    {
      ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
      if (drain)
	hsi_tcp_drain_transport_closed (s, tc, drain);
      return 0;
    }

  /* Drain failed and aborts are on their way */
  if (drain && drain->state == HSI_TCP_DRAIN_STATE_FAILED)
    return 0;

  /* Window was closed while draining */
  if (drain)
    hsi_tcp_send_window_update (tc, self, peer);

  hsi_session_take_ownership (s);
  tcp_connection_timers_reset (tc);
  hsi_tcp_track_cleanup_pending_tx (s, tc);
  hsi_tcp_track_commit_connection (tc, self, peer);
  s->session_state = SESSION_STATE_TRANSPORT_CLOSED;
  hsi_session_cleanup_fifos (s);

  return 1;
}

static void
hsi_tcp_track_commit (session_t *s, hsi_tcp_track_snapshot_t *self, hsi_tcp_track_snapshot_t *peer)
{
  if (hsi_tcp_track_commit_no_flush (s, self, peer))
    hsi_tcp_track_commit_flush (hsi_tcp_connection_at_session (s));
}

static void
hsi_tcp_track_ready_msg (hsi_tcp_track_ready_req_t *a)
{
  session_handle_tu_t sh = { .handle = a->session_handle };
  hsi_tcp_drain_t *drain;
  tcp_connection_t *tc;
  session_t *s;

  ASSERT (sh.thread_index == vlib_get_thread_index ());
  /* Aborts clean up pairs that are gone */
  s = hsi_session_get_owned_if_valid (sh);
  if (!s)
    return;

  tc = hsi_tcp_connection_at_session (s);
  if (!(tc->cfg_flags & TCP_CFG_F_TRACKED) || hsi_tcp_connection_is_committed (tc))
    return;

  drain = hsi_tcp_drain_get (sh.thread_index, hsi_session_conn_key_from_session (s));
  if (!drain || !hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_COMMITTER))
    return;

  drain->peer_snapshot = a->snapshot;
  drain->flags |= HSI_TCP_DRAIN_F_PEER_READY;
  hsi_tcp_drain_try_complete (s, tc, drain, vlib_time_now (vlib_get_main ()));
}

static void
hsi_tcp_track_commit_msg (hsi_tcp_track_commit_req_t *a)
{
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_t *s;

  ASSERT (sh.thread_index == vlib_get_thread_index ());
  s = hsi_session_get_owned_if_valid (sh);
  if (s)
    hsi_tcp_track_commit (s, &a->self, &a->peer);
  else
    {
      hsi_worker_counter_inc (hsi_worker_get (sh.thread_index), tcp_track_peer_rpc_failed);
      hsi_tcp_track_send_abort (a->session_handle);
      hsi_tcp_track_send_abort (a->peer.session_handle);
    }
}

static void
hsi_tcp_track_send_commit (session_handle_t peer_handle, hsi_tcp_track_snapshot_t *self,
			   hsi_tcp_track_snapshot_t *peer)
{
  session_handle_tu_t peer_sh = { .handle = peer_handle };
  hsi_msg_t msg = { .type = HSI_MSG_TCP_TRACK_COMMIT };

  ASSERT (peer->thread_index == vlib_get_thread_index ());
  msg.tcp_track_commit.session_handle = peer_handle;
  msg.tcp_track_commit.self = *self;
  msg.tcp_track_commit.peer = *peer;
  hsi_mq_send (peer_sh.thread_index, &msg);
}

static void
hsi_tcp_track_send_ready (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain)
{
  session_handle_tu_t peer_sh = { .handle = drain->peer_session_handle };
  hsi_msg_t msg = { .type = HSI_MSG_TCP_TRACK_READY };

  msg.tcp_track_ready.session_handle = drain->peer_session_handle;
  hsi_tcp_track_snapshot (s, tc, &msg.tcp_track_ready.snapshot);
  hsi_mq_send (peer_sh.thread_index, &msg);
}

/*
 * Draining connection closed but not by hsi, so tcp closed it, e.g., because
 * it gave up retransmitting, and it will delete it. Abort the peer and hand the
 * session back to the session layer, which frees it when tcp deletes the
 * connection. Returns 1 if that was the case.
 */
static int
hsi_tcp_drain_transport_closed (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain)
{
  if (PREDICT_TRUE (tc->state != TCP_STATE_CLOSED) || hsi_tcp_connection_is_committed (tc) ||
      hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_HSI_CLOSED))
    return 0;

  hsi_worker_counter_inc (hsi_worker_get (s->thread_index), tcp_drain_transport_closed);
  if (!hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_ABORT_SENT))
    hsi_tcp_track_send_abort (drain->peer_session_handle);
  /* Session lingers until tcp deletes the connection, no tx without fifos */
  hsi_tcp_track_cleanup_pending_tx (s, tc);
  hsi_session_cleanup_fifos (s);
  hsi_tcp_session_cleanup_state (s);
  hsi_session_release (s);

  return 1;
}

/*
 * Across workers, the session hsi_track_pair was called on commits the pair.
 * Its peer was taken over later, so it reports when it's drained, with the
 * snapshot to commit with, only once the app can't add data to its fifos.
 * Both commit with the same snapshots.
 */
static int
hsi_tcp_drain_try_complete_remote (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain)
{
  hsi_tcp_track_snapshot_t snap, peer_snap;

  if (!hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_COMMITTER))
    {
      if (!hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_READY_SENT))
	{
	  drain->flags |= HSI_TCP_DRAIN_F_READY_SENT;
	  hsi_tcp_track_send_ready (s, tc, drain);
	}
      return 0;
    }

  if (!hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_PEER_READY) ||
      hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_COMMIT_SENT))
    return 0;

  drain->flags |= HSI_TCP_DRAIN_F_COMMIT_SENT;
  /* Commit frees the drain */
  peer_snap = drain->peer_snapshot;
  hsi_tcp_track_snapshot (s, tc, &snap);
  hsi_tcp_track_send_commit (drain->peer_session_handle, &peer_snap, &snap);
  hsi_tcp_track_commit (s, &snap, &peer_snap);

  return 1;
}

static int
hsi_tcp_drain_try_complete (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain, f64 now)
{
  session_handle_tu_t peer_sh;
  hsi_tcp_track_snapshot_t snap, peer_snap;
  u8 committed, peer_committed;
  tcp_connection_t *peer_tc;
  hsi_tcp_drain_t *peer_drain;
  session_t *peer_s;
  int rv;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  ASSERT (drain);

  if (hsi_tcp_connection_is_committed (tc))
    return 1;

  if (hsi_tcp_drain_transport_closed (s, tc, drain))
    return -1;

  if (drain->state == HSI_TCP_DRAIN_STATE_FAILED)
    return -1;

  /* Peer drains the shared fifo, keep the window closed */
  hsi_tcp_drain_clamp_rx_fifo (s);

  peer_sh.handle = drain->peer_session_handle;
  peer_s = hsi_session_peer_get_if_valid (peer_sh);
  if (!peer_s)
    {
      hsi_worker_counter_inc (hsi_worker_get (s->thread_index), tcp_track_peer_rpc_failed);
      hsi_tcp_drain_fail_pair (drain);
      return -1;
    }

  rv = hsi_tcp_drain_update_and_needs_drain (s, tc, drain, now);
  if (rv < 0)
    {
      hsi_tcp_drain_fail_pair (drain);
      return -1;
    }
  if (rv)
    return 0;

  if (s->thread_index != peer_s->thread_index)
    return hsi_tcp_drain_try_complete_remote (s, tc, drain);

  peer_tc = hsi_tcp_connection_at_session (peer_s);
  if (!(peer_tc->cfg_flags & TCP_CFG_F_TRACKED) || peer_tc->state == TCP_STATE_CLOSED)
    return 0;

  peer_drain =
    hsi_tcp_drain_get (peer_tc->c_thread_index, hsi_tcp_session_conn_key_from_connection (peer_tc));
  if (peer_drain)
    {
      if (peer_drain->state == HSI_TCP_DRAIN_STATE_FAILED)
	return -1;
      rv = hsi_tcp_drain_update_and_needs_drain (peer_s, peer_tc, peer_drain, now);
      if (rv < 0)
	{
	  hsi_tcp_drain_fail_pair (peer_drain);
	  return -1;
	}
      if (rv)
	return 0;
    }

  hsi_tcp_track_snapshot (s, tc, &snap);
  hsi_tcp_track_snapshot (peer_s, peer_tc, &peer_snap);

  committed = hsi_tcp_track_commit_no_flush (s, &snap, &peer_snap);
  peer_committed = hsi_tcp_track_commit_no_flush (peer_s, &peer_snap, &snap);
  if (committed)
    hsi_tcp_track_commit_flush (tc);
  if (peer_committed)
    hsi_tcp_track_commit_flush (peer_tc);

  return 1;
}

hsi_tcp_tracked_action_t
hsi_tcp_drain_cache_buffer (vlib_main_t *vm, vlib_buffer_t *b, tcp_connection_t *tc, void *ip_hdr,
			    tcp_header_t *tcp_hdr, u8 is_ip4, u8 send_rst_on_drain_fail,
			    u8 *cleanup_session)
{
  hsi_tcp_drain_t *drain;
  hsi_worker_t *wrk;
  session_t *s;
  u32 data_len, seq, seq_end, ack, len;
  u32 bytes_acked = 0;
  uword key;
  u8 rst;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (!hsi_tcp_connection_is_committed (tc));
  ASSERT (tc->c_thread_index == vm->thread_index);

  key = hsi_tcp_session_conn_key_from_connection (tc);
  drain = hsi_tcp_drain_get (tc->c_thread_index, key);
  if (!drain)
    return HSI_TCP_TRACKED_ACTION_DROP;
  if (PREDICT_FALSE (drain->state == HSI_TCP_DRAIN_STATE_FAILED))
    return HSI_TCP_TRACKED_ACTION_DROP;

  wrk = hsi_worker_get (tc->c_thread_index);

  if (PREDICT_FALSE (!hsi_tcp_segment_data_len (ip_hdr, tcp_hdr, is_ip4, &data_len)))
    goto drop;

  seq = clib_net_to_host_u32 (tcp_hdr->seq_number);
  ack = clib_net_to_host_u32 (tcp_hdr->ack_number);
  rst = tcp_rst (tcp_hdr);
  seq_end = seq + data_len + (rst ? 0 : tcp_fin (tcp_hdr));

  if (PREDICT_FALSE (tcp_syn (tcp_hdr)))
    goto drop;

  /* Data sent before the remote saw the zero window is still accepted */
  if (PREDICT_FALSE (!hsi_tcp_segment_in_rcv_wnd (tc, seq, seq_end, drain->rcv_wnd)))
    goto drop;

  if (tcp_ack (tcp_hdr))
    {
      if (PREDICT_FALSE (seq_gt (ack, tc->snd_nxt)))
	goto drop;
      if (seq_gt (ack, tc->snd_una))
	{
	  bytes_acked = ack - tc->snd_una;
	  tc->snd_una = ack;
	  session_tx_fifo_dequeue_drop (&tc->connection, bytes_acked);
	  tcp_validate_txf_size (tc, tc->snd_nxt - tc->snd_una);
	}
      hsi_tcp_update_snd_wnd (tc, seq, ack, tcp_hdr);
      hsi_tcp_drain_update_tcp_on_ack (tc, bytes_acked);
    }
  else if (!rst)
    goto drop;

  if (PREDICT_FALSE (rst))
    {
      hsi_worker_counter_inc (wrk, tcp_drain_cache_dropped);
      if (send_rst_on_drain_fail)
	hsi_tcp_drain_fail_pair (drain);
      else
	hsi_tcp_drain_fail_pair_silent (drain);
      if (cleanup_session)
	*cleanup_session = HSI_CLEANUP_DRAIN_FAILURE;
      return HSI_TCP_TRACKED_ACTION_DROP;
    }

  s = session_get (tc->c_s_index, tc->c_thread_index);
  ASSERT (s->thread_index == vm->thread_index);

  /* Pure acks only ack data tcp sent, so they are consumed, not replayed */
  if (!data_len && !tcp_fin (tcp_hdr))
    {
      if (bytes_acked && svm_fifo_max_dequeue_cons (s->tx_fifo))
	session_program_tx_io_evt (session_handle (s), SESSION_IO_EVT_TX);
      hsi_tcp_drain_try_complete (s, tc, drain, vlib_time_now (vm));
      return HSI_TCP_TRACKED_ACTION_DROP;
    }

  len = vlib_buffer_length_in_chain (vm, b);
  if (PREDICT_FALSE (!hsi_drain_cache_has_room (drain->cached_buffers, drain->cached_bytes, len,
						hsi_main.tcp_drain_cache_max_packets,
						HSI_TCP_DRAIN_CACHE_MAX_BYTES)))
    {
      hsi_worker_counter_inc (wrk, tcp_drain_cache_overflow);
      if (send_rst_on_drain_fail)
	hsi_tcp_drain_fail_pair (drain);
      else
	hsi_tcp_drain_fail_pair_silent (drain);
      if (cleanup_session)
	*cleanup_session = HSI_CLEANUP_DRAIN_FAILURE;
      goto drop;
    }

  hsi_drain_cache_buffer (&drain->cached_buffers, &drain->cached_bytes,
			  vlib_get_buffer_index (vm, b), len);

  if (!hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_WND_CLAMPED))
    {
      hsi_tcp_send_zero_wnd_ack (s, tc);
      drain->flags |= HSI_TCP_DRAIN_F_WND_CLAMPED;
    }

  hsi_worker_counter_inc (wrk, tcp_drain_cached);

  if (bytes_acked && svm_fifo_max_dequeue_cons (s->tx_fifo))
    session_program_tx_io_evt (session_handle (s), SESSION_IO_EVT_TX);
  hsi_tcp_drain_try_complete (s, tc, drain, vlib_time_now (vm));

  return HSI_TCP_TRACKED_ACTION_HELD;

drop:
  hsi_worker_counter_inc (wrk, tcp_drain_cache_dropped);
  return HSI_TCP_TRACKED_ACTION_DROP;
}

int
hsi_tcp_try_complete_drain (vlib_main_t *vm, tcp_connection_t *tc)
{
  hsi_tcp_drain_t *drain;
  session_t *s;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (!hsi_tcp_connection_is_committed (tc));
  ASSERT (tc->c_thread_index == vm->thread_index);

  drain = hsi_tcp_drain_get (tc->c_thread_index, hsi_tcp_session_conn_key_from_connection (tc));
  if (!drain)
    return 0;

  s = session_get (tc->c_s_index, tc->c_thread_index);
  ASSERT (s->thread_index == vm->thread_index);

  return hsi_tcp_drain_try_complete (s, tc, drain, vlib_time_now (vm)) == 1;
}

void
hsi_tcp_drain_update_time (f64 time_now, u8 thread_index)
{
  hsi_tcp_drain_t *drain;
  session_handle_t *handles, *handle;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (thread_index);
  if (!pool_elts (wrk->tcp_drains))
    {
      hsi_tcp_drain_maybe_unregister_time_update (thread_index);
      return;
    }

  /* Acks and peer messages complete drains, so only check periodically for
   * timeouts and transports tcp closed */
  if (time_now < wrk->tcp_drain_next_scan)
    return;
  wrk->tcp_drain_next_scan = time_now + HSI_TCP_DRAIN_SCAN_INTERVAL;

  handles = wrk->tcp_drain_update_handles;
  vec_reset_length (handles);
  pool_foreach (drain, wrk->tcp_drains)
    {
      vec_add1 (handles, drain->session_handle);
    }
  wrk->tcp_drain_update_handles = handles;

  vec_foreach (handle, handles)
    {
      session_handle_tu_t sh = { .handle = *handle };
      tcp_connection_t *tc;
      session_t *s;

      s = session_get_from_handle_if_valid (sh);
      if (!s)
	continue;
      ASSERT (s->thread_index == thread_index);

      tc = hsi_tcp_connection_at_session (s);
      if (!(tc->cfg_flags & TCP_CFG_F_TRACKED) || hsi_tcp_connection_is_committed (tc))
	continue;

      drain = hsi_tcp_drain_get (thread_index, hsi_session_conn_key_from_session (s));
      if (drain)
	hsi_tcp_drain_try_complete (s, tc, drain, time_now);
    }

  hsi_tcp_drain_maybe_unregister_time_update (thread_index);
}

int
hsi_track_tcp (session_t *s, session_t *peer_s, hsi_track_flags_t flags)
{
  tcp_connection_t *tc0, *tc1;
  hsi_tcp_track_snapshot_t snap0, snap1;
  hsi_tcp_drain_t *drain;
  hsi_worker_t *wrk;
  u8 is_same_thread;

  tc0 = hsi_tcp_connection_at_session (s);
  tc1 = hsi_tcp_connection_at_session (peer_s);
  is_same_thread = s->thread_index == peer_s->thread_index;
  wrk = hsi_worker_get (s->thread_index);

  if (!hsi_tcp_track_is_possible (tc0, tc1))
    {
      if ((tc0->cfg_flags | tc1->cfg_flags) & TCP_CFG_F_TRACKED)
	hsi_worker_counter_inc (wrk, tcp_track_fail_tracked);
      else
	hsi_worker_counter_inc (wrk, tcp_track_fail_options);
      return -1;
    }

  /* Drains can't fill rx holes because hsi intercepts the retransmits */
  if (svm_fifo_has_ooo_data (s->rx_fifo) ||
      (is_same_thread && svm_fifo_has_ooo_data (peer_s->rx_fifo)))
    {
      hsi_worker_counter_inc (wrk, tcp_track_fail_ooo);
      return -1;
    }

  hsi_session_save_app_wrk (s, flags);

  if (!is_same_thread)
    {
      drain = hsi_tcp_drain_start (s, peer_s, tc0, tc1);
      drain->flags |= HSI_TCP_DRAIN_F_COMMITTER;
      hsi_tcp_track_send_drain_start (s, peer_s, flags);
      return 0;
    }

  hsi_session_save_app_wrk (peer_s, flags);

  if (hsi_tcp_track_needs_drain (s, tc0) || hsi_tcp_track_needs_drain (peer_s, tc1))
    {
      hsi_tcp_drain_start (s, peer_s, tc0, tc1);
      hsi_tcp_drain_start (peer_s, s, tc1, tc0);
      return 0;
    }

  hsi_tcp_track_snapshot (s, tc0, &snap0);
  hsi_tcp_track_snapshot (peer_s, tc1, &snap1);

  hsi_tcp_track_commit (s, &snap0, &snap1);
  hsi_tcp_track_commit (peer_s, &snap1, &snap0);

  return 0;
}
static_always_inline u8
hsi_tcp_tracker_cleanup_try_lock (hsi_tcp_tracker_t *trk)
{
  u32 old_flags;

  old_flags = clib_atomic_fetch_or (&trk->flags, HSI_TRACKER_F_CLEANUP_PENDING);
  return !(old_flags & HSI_TRACKER_F_CLEANUP_PENDING);
}

static_always_inline void
hsi_tcp_tracker_cleanup_mark_pending (hsi_tcp_tracker_t *trk)
{
  clib_atomic_fetch_or (&trk->flags, HSI_TRACKER_F_CLEANUP_PENDING);
}

static_always_inline void
hsi_tcp_track_schedule_cleanup_pair (tcp_connection_t *tc, hsi_tcp_tracker_t *trk,
				     hsi_tcp_cleanup_reason_t reason)
{
  session_handle_tu_t peer_sh = { .handle = trk->peer_session_handle };
  hsi_tcp_tracker_t *cleanup_trk, *peer_trk = 0;
  tcp_connection_t *peer_tc;
  session_t *peer_s;
  session_t *local_s;
  hsi_worker_t *wrk;
  session_handle_t local_handle, first;
  u8 local_uses_remote_fifos, peer_uses_remote_fifos;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (hsi_tcp_connection_is_committed (tc));
  ASSERT (trk->peer_session_handle != SESSION_INVALID_HANDLE);

  if (trk->flags & HSI_TRACKER_F_CLEANUP_PENDING)
    return;

  local_handle = session_make_handle (tc->c_s_index, tc->c_thread_index);

  peer_s = hsi_session_peer_get_if_valid (peer_sh);
  if (peer_s)
    {
      peer_tc = hsi_tcp_connection_at_session (peer_s);
      ASSERT (peer_tc->cfg_flags & TCP_CFG_F_TRACKED);
      if (hsi_tcp_connection_is_committed (peer_tc))
	peer_trk = hsi_tcp_tracker_from_connection (peer_tc);
    }

  cleanup_trk = trk;
  if (peer_trk && trk->peer_session_handle < local_handle)
    cleanup_trk = peer_trk;

  if (!hsi_tcp_tracker_cleanup_try_lock (cleanup_trk))
    {
      hsi_tcp_tracker_cleanup_mark_pending (trk);
      return;
    }

  hsi_tcp_tracker_cleanup_mark_pending (trk);
  if (peer_trk)
    hsi_tcp_tracker_cleanup_mark_pending (peer_trk);

  wrk = hsi_worker_get (tc->c_thread_index);
  hsi_worker_counter_inc (wrk, tcp_cleanup_scheduled);
  if (reason == HSI_TCP_CLEANUP_REASON_RST)
    hsi_worker_counter_inc (wrk, tcp_rst_cleanup);
  else
    hsi_worker_counter_inc (wrk, tcp_fin_cleanup);

  /* Peer removes its fin-wait entry on its own thread when cleaned up */
  hsi_tcp_fin_wait_del (tc);

  local_s = session_get_from_handle_safe ((session_handle_tu_t){ .handle = local_handle });
  ASSERT (local_s);
  local_uses_remote_fifos = hsi_session_uses_remote_fifos (local_s);
  peer_uses_remote_fifos =
    peer_s && hsi_session_is_hsi_owned (peer_s) && hsi_session_uses_remote_fifos (peer_s);

  if (local_uses_remote_fifos && !peer_uses_remote_fifos)
    first = local_handle;
  else
    first = trk->peer_session_handle;
  hsi_session_send_cleanup_pair (first);
}

static_always_inline u8
hsi_tcp_tracker_fin_done (hsi_tcp_tracker_t *trk)
{
  return (trk->flags & HSI_TRACKER_F_FIN_DONE) == HSI_TRACKER_F_FIN_DONE;
}

static_always_inline u8
hsi_tcp_tracker_fin_received (hsi_tcp_tracker_t *trk)
{
  return trk->flags & HSI_TRACKER_F_FIN_RCVD;
}

static void
hsi_tcp_track_arm_fin_wait (tcp_connection_t *tc, hsi_tcp_tracker_t *trk)
{
  if (trk->flags & (HSI_TRACKER_F_FIN_WAIT | HSI_TRACKER_F_CLEANUP_PENDING))
    return;

  clib_atomic_fetch_or (&trk->flags, HSI_TRACKER_F_FIN_WAIT);
  trk->fin_wait_start = vlib_time_now (vlib_get_main ());
  hsi_worker_counter_inc (hsi_worker_get (tc->c_thread_index), tcp_fin_wait_started);
  hsi_tcp_fin_wait_add (tc, trk->fin_wait_start);
}

/* Pair not ready for cleanup, check it again after another timeout */
static void
hsi_tcp_fin_wait_rearm (tcp_connection_t *tc, hsi_tcp_tracker_t *trk, f64 now)
{
  trk->fin_wait_start = now;
  hsi_tcp_fin_wait_add (tc, now);
}

static void
hsi_tcp_track_maybe_cleanup_pair (tcp_connection_t *tc, hsi_tcp_tracker_t *trk)
{
  session_handle_tu_t peer_sh = { .handle = trk->peer_session_handle };
  tcp_connection_t *peer_tc;
  hsi_tcp_tracker_t *peer_trk;
  session_t *peer_s;

  if (!hsi_tcp_tracker_fin_received (trk))
    return;

  if (trk->flags & HSI_TRACKER_F_CLEANUP_PENDING)
    return;

  peer_s = hsi_session_peer_get_if_valid (peer_sh);
  if (!peer_s)
    return;

  peer_tc = hsi_tcp_connection_at_session (peer_s);
  ASSERT (peer_tc->cfg_flags & TCP_CFG_F_TRACKED);
  if (!hsi_tcp_connection_is_committed (peer_tc))
    return;

  peer_trk = hsi_tcp_tracker_from_connection (peer_tc);
  if (hsi_tcp_tracker_fin_done (trk) && hsi_tcp_tracker_fin_done (peer_trk))
    {
      hsi_tcp_track_schedule_cleanup_pair (tc, trk, HSI_TCP_CLEANUP_REASON_FIN);
      return;
    }

  /* Both fins seen and one acked. Other side might never ack its fin */
  if (hsi_tcp_tracker_fin_received (peer_trk) &&
      (hsi_tcp_tracker_fin_done (trk) || hsi_tcp_tracker_fin_done (peer_trk)))
    hsi_tcp_track_arm_fin_wait (tc, trk);
}

void
hsi_tcp_fin_wait_update_time (f64 time_now, u8 thread_index)
{
  hsi_tcp_tracker_t *trk, *peer_trk;
  hsi_tcp_fin_wait_elt_t *elt, e;
  session_handle_tu_t peer_sh;
  tcp_connection_t *tc, *peer_tc;
  session_t *peer_s;
  hsi_worker_t *wrk;
  session_t *s;

  wrk = hsi_worker_get (thread_index);
  if (!hash_elts (wrk->tcp_fin_wait_by_session_conn))
    {
      hsi_tcp_fin_wait_maybe_unregister_time_update (thread_index);
      return;
    }

  while (clib_fifo_elts (wrk->tcp_fin_wait_fifo))
    {
      elt = clib_fifo_head (wrk->tcp_fin_wait_fifo);
      /* Deleted entries are dropped when they get to the head */
      if (hash_get (wrk->tcp_fin_wait_by_session_conn, elt->key) &&
	  time_now - elt->start < hsi_main.tcp_fin_wait_timeout)
	break;

      /* Handling the entry might add new ones */
      clib_fifo_sub1 (wrk->tcp_fin_wait_fifo, e);
      if (!hash_get (wrk->tcp_fin_wait_by_session_conn, e.key))
	continue;

      session_handle_tu_t sh = {
	.handle = session_make_handle (hsi_session_conn_key_session_index (e.key), thread_index),
      };

      s = session_get_from_handle_if_valid (sh);
      if (!s || s->connection_index != hsi_session_conn_key_conn_index (e.key))
	{
	  hsi_tcp_fin_wait_del_key (thread_index, e.key);
	  continue;
	}

      tc = hsi_tcp_connection_at_session (s);
      if (!(tc->cfg_flags & TCP_CFG_F_TRACKED) || !hsi_tcp_connection_is_committed (tc))
	{
	  hsi_tcp_fin_wait_del_key (thread_index, e.key);
	  continue;
	}

      trk = hsi_tcp_tracker_from_connection (tc);
      if (trk->magic != HSI_TCP_TRACKER_MAGIC || !(trk->flags & HSI_TRACKER_F_FIN_WAIT) ||
	  (trk->flags & HSI_TRACKER_F_CLEANUP_PENDING))
	{
	  hsi_tcp_fin_wait_del_key (thread_index, e.key);
	  continue;
	}

      /* Entry added before the tracker was rearmed */
      if (trk->fin_wait_start != e.start)
	continue;

      peer_sh.handle = trk->peer_session_handle;
      peer_s = hsi_session_peer_get_if_valid (peer_sh);
      if (!peer_s)
	{
	  hsi_tcp_fin_wait_del_key (thread_index, e.key);
	  hsi_tcp_tracker_cleanup_mark_pending (trk);
	  hsi_session_cleanup (s);
	  continue;
	}

      peer_tc = hsi_tcp_connection_at_session (peer_s);
      if (!(peer_tc->cfg_flags & TCP_CFG_F_TRACKED) || !hsi_tcp_connection_is_committed (peer_tc))
	{
	  hsi_tcp_fin_wait_rearm (tc, trk, time_now);
	  continue;
	}

      peer_trk = hsi_tcp_tracker_from_connection (peer_tc);
      if (!hsi_tcp_tracker_fin_received (trk) || !hsi_tcp_tracker_fin_received (peer_trk))
	{
	  hsi_tcp_fin_wait_rearm (tc, trk, time_now);
	  continue;
	}

      hsi_worker_counter_inc (hsi_worker_get (thread_index), tcp_fin_wait_cleanup);
      hsi_tcp_track_schedule_cleanup_pair (tc, trk, HSI_TCP_CLEANUP_REASON_FIN);
    }

  hsi_tcp_fin_wait_maybe_unregister_time_update (thread_index);
}

static void
hsi_tcp_mark_fin_acked (tcp_connection_t *tc, u32 ack)
{
  hsi_tcp_tracker_t *trk;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (hsi_tcp_connection_is_committed (tc));

  trk = hsi_tcp_tracker_get (tc);
  if ((trk->flags & HSI_TRACKER_F_FIN_RCVD) && seq_geq (ack, tc->rcv_nxt))
    clib_atomic_fetch_or (&trk->flags, HSI_TRACKER_F_FIN_ACKED);

  hsi_tcp_track_maybe_cleanup_pair (tc, trk);
}

static void
hsi_tcp_mark_fin_acked_msg (hsi_tcp_fin_ack_req_t *a)
{
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_t *s;

  ASSERT (sh.thread_index == vlib_get_thread_index ());
  s = hsi_session_get_owned_if_valid (sh);
  if (s && hsi_tcp_connection_is_committed (hsi_tcp_connection_at_session (s)))
    hsi_tcp_mark_fin_acked (hsi_tcp_connection_at_session (s), a->ack);
}

static void
hsi_tcp_send_fin_acked (session_handle_t session_handle, u32 ack)
{
  session_handle_tu_t sh = { .handle = session_handle };
  hsi_msg_t msg = { .type = HSI_MSG_TCP_FIN_ACKED };

  msg.tcp_fin_ack.session_handle = session_handle;
  msg.tcp_fin_ack.ack = ack;
  hsi_mq_send (sh.thread_index, &msg);
}

static void
hsi_tcp_track_peer_fin_acked (hsi_tcp_tracker_t *trk, u32 ack, clib_thread_index_t thread_index)
{
  session_handle_tu_t peer_sh = { .handle = trk->peer_session_handle };
  session_t *peer_s;
  u32 peer_ack;

  peer_ack = ack + trk->ack_delta;
  if (peer_sh.thread_index == thread_index)
    {
      peer_s = hsi_session_get_owned_if_valid (peer_sh);
      if (!peer_s || !hsi_tcp_connection_is_committed (hsi_tcp_connection_at_session (peer_s)))
	return;
      hsi_tcp_mark_fin_acked (hsi_tcp_connection_at_session (peer_s), peer_ack);
    }
  else
    hsi_tcp_send_fin_acked (trk->peer_session_handle, peer_ack);
}

static void
hsi_tcp_track_pending_peer_fin_ack_update (hsi_tcp_tracker_t *trk, u32 ack,
					   clib_thread_index_t thread_index)
{
  ASSERT (trk->flags & HSI_TRACKER_F_PEER_FIN_PENDING);

  if (seq_lt (ack, trk->peer_fin_ack))
    return;

  clib_atomic_fetch_and (&trk->flags, ~HSI_TRACKER_F_PEER_FIN_PENDING);
  hsi_tcp_track_peer_fin_acked (trk, ack, thread_index);
}

static void
hsi_tcp_track_pending_peer_fin_ack (hsi_tcp_tracker_t *trk, tcp_header_t *tcp_hdr, u32 ack, u8 rst,
				    clib_thread_index_t thread_index)
{
  ASSERT (trk->flags & HSI_TRACKER_F_PEER_FIN_PENDING);

  if (!tcp_ack (tcp_hdr) || rst)
    return;

  hsi_tcp_track_pending_peer_fin_ack_update (trk, ack, thread_index);
}

static void
hsi_tcp_mark_peer_fin_pending (tcp_connection_t *tc, u32 ack)
{
  hsi_tcp_tracker_t *trk;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (hsi_tcp_connection_is_committed (tc));

  trk = hsi_tcp_tracker_get (tc);
  trk->peer_fin_ack = ack - trk->ack_delta;
  clib_atomic_fetch_or (&trk->flags, HSI_TRACKER_F_PEER_FIN_PENDING);

  hsi_tcp_track_pending_peer_fin_ack_update (trk, tc->snd_una, tc->c_thread_index);
}

static void
hsi_tcp_mark_peer_fin_pending_msg (hsi_tcp_peer_fin_req_t *a)
{
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_t *s;

  ASSERT (sh.thread_index == vlib_get_thread_index ());
  s = hsi_session_get_owned_if_valid (sh);
  if (s && hsi_tcp_connection_is_committed (hsi_tcp_connection_at_session (s)))
    hsi_tcp_mark_peer_fin_pending (hsi_tcp_connection_at_session (s), a->ack);
}

static void
hsi_tcp_send_peer_fin_pending (session_handle_t session_handle, u32 ack)
{
  session_handle_tu_t sh = { .handle = session_handle };
  hsi_msg_t msg = { .type = HSI_MSG_TCP_PEER_FIN_PENDING };

  msg.tcp_peer_fin.session_handle = session_handle;
  msg.tcp_peer_fin.ack = ack;
  hsi_mq_send (sh.thread_index, &msg);
}

static void
hsi_tcp_arm_peer_fin_pending (hsi_tcp_tracker_t *trk, u32 ack, clib_thread_index_t thread_index)
{
  session_handle_tu_t peer_sh = { .handle = trk->peer_session_handle };
  session_t *peer_s;

  if (peer_sh.thread_index == thread_index)
    {
      peer_s = hsi_session_get_owned_if_valid (peer_sh);
      if (!peer_s || !hsi_tcp_connection_is_committed (hsi_tcp_connection_at_session (peer_s)))
	return;
      hsi_tcp_mark_peer_fin_pending (hsi_tcp_connection_at_session (peer_s), ack);
    }
  else
    hsi_tcp_send_peer_fin_pending (trk->peer_session_handle, ack);
}

static_always_inline u8
hsi_tcp_validate_and_update_state (tcp_connection_t *tc, hsi_tcp_tracker_t *trk,
				   tcp_header_t *tcp_hdr, u32 data_len, u32 *seq, u32 *ack)
{
  u32 seq_end;
  u8 rst;

  *seq = clib_net_to_host_u32 (tcp_hdr->seq_number);
  *ack = clib_net_to_host_u32 (tcp_hdr->ack_number);
  rst = tcp_rst (tcp_hdr);
  seq_end = *seq + data_len + (rst ? 0 : tcp_fin (tcp_hdr));

  if (PREDICT_FALSE (tcp_syn (tcp_hdr)))
    return 0;

  if (PREDICT_FALSE (!hsi_tcp_tracked_segment_in_wnd (tc, *seq, seq_end, rst)))
    return 0;

  /* Ack might cover data not yet acked, endpoint validates it */
  if (PREDICT_FALSE (rst))
    return 1;

  if (tcp_ack (tcp_hdr))
    {
      if (seq_gt (*ack, tc->snd_nxt))
	tc->snd_nxt = *ack;
      if (seq_gt (*ack, tc->snd_una))
	tc->snd_una = *ack;
      hsi_tcp_update_snd_wnd (tc, *seq, *ack, tcp_hdr);
    }
  else
    return 0;

  /* Highest seq seen, so out of order data and fins also move it */
  if (seq_gt (seq_end, tc->rcv_nxt))
    tc->rcv_nxt = seq_end;

  if (PREDICT_FALSE (tcp_fin (tcp_hdr)))
    clib_atomic_fetch_or (&trk->flags, HSI_TRACKER_F_FIN_RCVD);

  return 1;
}

static_always_inline u16
hsi_tcp_translate_window (u16 window, hsi_tcp_tracker_t *trk)
{
  u32 wnd = clib_net_to_host_u16 (window);

  if (trk->wnd_delta > 0)
    wnd = clib_min (wnd << trk->wnd_delta, 0xffff);
  else if (trk->wnd_delta < 0)
    wnd >>= -trk->wnd_delta;

  return clib_host_to_net_u16 ((u16) wnd);
}

static_always_inline void
hsi_tcp_rewrite_options (tcp_header_t *tcp_hdr, hsi_tcp_tracker_t *trk)
{
  u8 *data = (u8 *) (tcp_hdr + 1);
  u8 *end = (u8 *) tcp_hdr + tcp_header_bytes (tcp_hdr);
  u8 kind, opt_len;
  u32 v;

  while (data < end)
    {
      kind = data[0];
      if (kind == TCP_OPTION_EOL)
	break;
      if (kind == TCP_OPTION_NOOP)
	{
	  data += 1;
	  continue;
	}

      if (data + 1 >= end)
	break;

      opt_len = data[1];
      if (opt_len < 2 || data + opt_len > end)
	break;

      if (kind == TCP_OPTION_TIMESTAMP && opt_len == TCP_OPTION_LEN_TIMESTAMP)
	{
	  v = clib_mem_unaligned (data + 2, u32);
	  v = clib_host_to_net_u32 (clib_net_to_host_u32 (v) + trk->tsval_delta);
	  clib_mem_unaligned (data + 2, u32) = v;

	  v = clib_mem_unaligned (data + 6, u32);
	  if (v)
	    v = clib_host_to_net_u32 (clib_net_to_host_u32 (v) + trk->tsecr_delta);
	  clib_mem_unaligned (data + 6, u32) = v;
	}
      else if (kind == TCP_OPTION_SACK_BLOCK && opt_len >= 10 &&
	       !((opt_len - 2) % TCP_OPTION_LEN_SACK_BLOCK))
	{
	  u8 *sack = data + 2;

	  while (sack + TCP_OPTION_LEN_SACK_BLOCK <= data + opt_len)
	    {
	      v = clib_mem_unaligned (sack, u32);
	      v = clib_host_to_net_u32 (clib_net_to_host_u32 (v) + trk->ack_delta);
	      clib_mem_unaligned (sack, u32) = v;

	      v = clib_mem_unaligned (sack + 4, u32);
	      v = clib_host_to_net_u32 (clib_net_to_host_u32 (v) + trk->ack_delta);
	      clib_mem_unaligned (sack + 4, u32) = v;

	      sack += TCP_OPTION_LEN_SACK_BLOCK;
	    }
	}

      data += opt_len;
    }
}

static_always_inline void
hsi_tcp_update_checksums (vlib_main_t *vm, vlib_buffer_t *b, void *ip_hdr, tcp_header_t *tcp_hdr,
			  u8 is_ip4, u8 csum_offload)
{
  vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
					VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
					VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);

  tcp_hdr->checksum = 0;
  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;

      if (csum_offload)
	{
	  ip4->checksum = 0;
	  vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
					      VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
	}
      else
	{
	  ip4->checksum = ip4_header_checksum (ip4);
	  tcp_hdr->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
	}
    }
  else if (csum_offload)
    vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      int bogus = 0;

      tcp_hdr->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
    }
}

hsi_tcp_tracked_action_t
hsi_tcp_handle_tracked_connection (vlib_main_t *vm, vlib_buffer_t *b, tcp_connection_t *tc,
				   void *ip_hdr, tcp_header_t *tcp_hdr, u8 is_ip4,
				   u8 *cleanup_session)
{
  hsi_tcp_tracker_t *trk;
  u32 data_len, seq, ack;
  u8 fin, fin_seen, rst;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  trk = hsi_tcp_tracker_get (tc);
  fin = tcp_fin (tcp_hdr);
  fin_seen = trk->flags & HSI_TRACKER_F_FIN_RCVD;
  rst = tcp_rst (tcp_hdr);

  if (PREDICT_FALSE (!hsi_tcp_segment_data_len (ip_hdr, tcp_hdr, is_ip4, &data_len)))
    return HSI_TCP_TRACKED_ACTION_DROP;

  if (PREDICT_FALSE (!hsi_tcp_validate_and_update_state (tc, trk, tcp_hdr, data_len, &seq, &ack)))
    return HSI_TCP_TRACKED_ACTION_DROP;

  if (PREDICT_FALSE (trk->flags & HSI_TRACKER_F_PEER_FIN_PENDING))
    hsi_tcp_track_pending_peer_fin_ack (trk, tcp_hdr, ack, rst, tc->c_thread_index);

  if (PREDICT_FALSE (fin && !rst && !fin_seen))
    hsi_tcp_arm_peer_fin_pending (trk, tc->rcv_nxt, tc->c_thread_index);

  tcp_hdr->seq_number = clib_host_to_net_u32 (seq + trk->seq_delta);

  if (tcp_ack (tcp_hdr))
    tcp_hdr->ack_number = clib_host_to_net_u32 (ack + trk->ack_delta);

  tcp_hdr->window = hsi_tcp_translate_window (tcp_hdr->window, trk);
  if (tcp_header_bytes (tcp_hdr) > sizeof (*tcp_hdr))
    hsi_tcp_rewrite_options (tcp_hdr, trk);

  tcp_hdr->src_port = trk->tx_lcl_port;
  tcp_hdr->dst_port = trk->tx_rmt_port;
  /* ip lookup uses tx sw_if_index as fib index */
  vnet_buffer (b)->sw_if_index[VLIB_TX] = trk->tx_fib_index;
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  vnet_buffer (b)->l4_hdr_offset = (u8 *) tcp_hdr - b->data;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;

      ip4->src_address = trk->tx_lcl_ip.ip4;
      ip4->dst_address = trk->tx_rmt_ip.ip4;
      b->flags |= VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP6;
      hsi_tcp_update_checksums (vm, b, ip4, tcp_hdr, is_ip4, tcp_csum_offload (tc));
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;

      ip6->src_address = trk->tx_lcl_ip.ip6;
      ip6->dst_address = trk->tx_rmt_ip.ip6;
      b->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP4;
      hsi_tcp_update_checksums (vm, b, ip6, tcp_hdr, is_ip4, tcp_csum_offload (tc));
    }

  trk->packets += 1;
  trk->bytes += vlib_buffer_length_in_chain (vm, b);

  if (PREDICT_FALSE (rst))
    {
      hsi_tcp_track_schedule_cleanup_pair (tc, trk, HSI_TCP_CLEANUP_REASON_RST);
      if (cleanup_session)
	*cleanup_session = HSI_CLEANUP_TRACK_COMPLETE;
    }
  else if (PREDICT_FALSE (trk->flags & HSI_TRACKER_F_FIN_MASK))
    {
      hsi_tcp_track_maybe_cleanup_pair (tc, trk);
      if (cleanup_session && (trk->flags & HSI_TRACKER_F_CLEANUP_PENDING))
	*cleanup_session = HSI_CLEANUP_TRACK_COMPLETE;
    }

  return HSI_TCP_TRACKED_ACTION_FORWARD;
}

static const char *
hsi_tcp_drain_state_name (hsi_tcp_drain_state_t state)
{
  switch (state)
    {
    case HSI_TCP_DRAIN_STATE_DRAINING:
      return "draining";
    case HSI_TCP_DRAIN_STATE_READY:
      return "ready";
    case HSI_TCP_DRAIN_STATE_FAILED:
      return "failed";
    default:
      return "unknown";
    }
}

static u8 *
format_hsi_tcp_tracker_flags (u8 *s, va_list *args)
{
  u32 flags = va_arg (*args, u32);
  char *sep = "";

  if (!flags)
    return format (s, "none");

#define _(flag, str)                                                                               \
  if (flags & (flag))                                                                              \
    {                                                                                              \
      s = format (s, "%s%s", sep, (str));                                                          \
      sep = ",";                                                                                   \
      flags &= ~(flag);                                                                            \
    }
  _ (HSI_TRACKER_F_CLEANUP_PENDING, "cleanup-pending");
  _ (HSI_TRACKER_F_FIN_RCVD, "fin-rx");
  _ (HSI_TRACKER_F_FIN_ACKED, "fin-acked");
  _ (HSI_TRACKER_F_PEER_FIN_PENDING, "peer-fin-pending");
  _ (HSI_TRACKER_F_FIN_WAIT, "fin-wait");
#undef _

  if (flags)
    s = format (s, "%sunknown:0x%x", sep, flags);

  return s;
}

void
hsi_tracker_show_tcp (vlib_main_t *vm, u32 i, hsi_worker_t *wrk, f64 now)
{
  hsi_tcp_drain_t *drain;
  tcp_connection_t *tc;
  hsi_tcp_tracker_t *trk;

  if (pool_elts (wrk->tcp_drains) || hash_elts (wrk->tcp_fin_wait_by_session_conn))
    vlib_cli_output (vm, "thread %u tcp-drain-active %u tcp-fin-wait-active %u", i,
		     (u32) pool_elts (wrk->tcp_drains),
		     (u32) hash_elts (wrk->tcp_fin_wait_by_session_conn));

  pool_foreach (drain, wrk->tcp_drains)
    {
      u32 peer_thread =
	session_thread_from_handle ((session_handle_tu_t){ .handle = drain->peer_session_handle });

      vlib_cli_output (vm,
		       "thread %u tcp-drain session 0x%lx peer 0x%lx peer-thread %u "
		       "state %s cache %u/%u bytes %u age %.3f idle %.3f",
		       i, drain->session_handle, drain->peer_session_handle, peer_thread,
		       hsi_tcp_drain_state_name (drain->state), vec_len (drain->cached_buffers),
		       hsi_main.tcp_drain_cache_max_packets, drain->cached_bytes,
		       now - drain->start_time, now - drain->last_progress_time);
    }

  pool_foreach (tc, tcp_main.wrk[i].connections)
    {
      if (!(tc->cfg_flags & TCP_CFG_F_TRACKED) || !hsi_tcp_connection_is_committed (tc))
	continue;

      trk = hsi_tcp_tracker_from_connection (tc);
      if (trk->magic != HSI_TCP_TRACKER_MAGIC)
	continue;

      vlib_cli_output (
	vm,
	"thread %u tcp-tracked session 0x%lx peer 0x%lx peer-thread %u "
	"flags %U peer-fin-ack %u seq-delta %d ack-delta %d "
	"packets %lu bytes %lu",
	i, session_make_handle (tc->c_s_index, tc->c_thread_index), trk->peer_session_handle,
	session_thread_from_handle ((session_handle_tu_t){ .handle = trk->peer_session_handle }),
	format_hsi_tcp_tracker_flags, trk->flags, trk->peer_fin_ack, trk->seq_delta, trk->ack_delta,
	trk->packets, trk->bytes);
    }
}

void
hsi_tcp_handle_msg (hsi_msg_t *msg)
{
  switch (msg->type)
    {
    case HSI_MSG_TCP_DRAIN_START:
      hsi_tcp_drain_start_msg (&msg->tcp_drain_start);
      break;
    case HSI_MSG_TCP_TRACK_COMMIT:
      hsi_tcp_track_commit_msg (&msg->tcp_track_commit);
      break;
    case HSI_MSG_TCP_TRACK_READY:
      hsi_tcp_track_ready_msg (&msg->tcp_track_ready);
      break;
    case HSI_MSG_TCP_FIN_ACKED:
      hsi_tcp_mark_fin_acked_msg (&msg->tcp_fin_ack);
      break;
    case HSI_MSG_TCP_PEER_FIN_PENDING:
      hsi_tcp_mark_peer_fin_pending_msg (&msg->tcp_peer_fin);
      break;
    case HSI_MSG_TCP_ABORT:
      hsi_tcp_track_abort_msg (msg->session_handle, 1 /* send_rst */);
      break;
    case HSI_MSG_TCP_ABORT_SILENT:
      hsi_tcp_track_abort_msg (msg->session_handle, 0 /* send_rst */);
      break;
    default:
      ASSERT (0);
      break;
    }
}
