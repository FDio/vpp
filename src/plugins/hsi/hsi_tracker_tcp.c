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

  if (tc->state == TCP_STATE_CLOSED)
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
  vec_reset_length (wrk->tcp_fin_wait_update_keys);
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
  session_send_rpc_evt_to_thread_force (thread_index, hsi_tcp_fin_wait_unregister_time_update_rpc,
					0);
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
  session_send_rpc_evt_to_thread_force (thread_index, hsi_tcp_drain_unregister_time_update_rpc, 0);
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

static void
hsi_tcp_track_abort_session (session_t *s)
{
  tcp_connection_t *tc;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  tc = hsi_tcp_connection_at_session (s);
  if (!(tc->cfg_flags & TCP_CFG_F_TRACKED))
    return;

  if (tc->state != TCP_STATE_CLOSED)
    {
      tcp_send_reset (tc);
      tcp_connection_timers_reset (tc);
      tcp_cong_recovery_off (tc);
      tcp_connection_set_state (tc, TCP_STATE_CLOSED);
    }

  hsi_session_cleanup (s);
}

static void
hsi_tcp_track_abort_rpc (void *arg)
{
  session_handle_tu_t sh = { .handle = pointer_to_uword (arg) };
  session_t *s;

  s = session_get_from_handle_if_valid (sh);
  if (s)
    hsi_tcp_track_abort_session (s);
}

static void
hsi_tcp_track_send_abort (session_handle_t session_handle)
{
  session_handle_tu_t sh = { .handle = session_handle };

  if (session_handle == SESSION_INVALID_HANDLE)
    return;

  session_send_rpc_evt_to_thread_force (sh.thread_index, hsi_tcp_track_abort_rpc,
					uword_to_pointer (session_handle, void *));
}

static_always_inline void
hsi_tcp_send_zero_wnd_ack (tcp_connection_t *tc)
{
  u32 rcv_wnd = tc->rcv_wnd;

  tc->rcv_wnd = 0;
  tcp_send_ack (tc);
  tc->rcv_wnd = rcv_wnd;
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
hsi_tcp_segment_in_rcv_wnd (tcp_connection_t *tc, u32 seq, u32 seq_end)
{
  return seq_geq (seq_end, tc->rcv_las) && seq_leq (seq, tc->rcv_nxt + tc->rcv_wnd);
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
  snap->ts_now = tcp_tstamp (tc);
  snap->tsval_recent = tc->tsval_recent;
  snap->rcv_wscale = tc->rcv_wscale;
  snap->snd_wscale = tc->snd_wscale;
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
  hsi_drain_sample_fifos (s, &drain->rx_deq, &drain->tx_deq);
  hsi_tcp_drain_flag_set (drain, HSI_TCP_DRAIN_F_RX_OOO, svm_fifo_has_ooo_data (s->rx_fifo));
  drain->snd_una = tc->snd_una;
  drain->snd_nxt = tc->snd_nxt;
}

static_always_inline int
hsi_tcp_drain_sample_needs_drain (hsi_tcp_drain_t *drain)
{
  if (drain->rx_deq || drain->tx_deq || hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_RX_OOO))
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
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_tcp_drain_t *drain;
  hsi_worker_t *wrk;
  u32 drain_index;
  uword key;
  f64 now;

  ASSERT (s->thread_index == thread_index);

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
  drain->peer_thread_index = peer_s->thread_index;
  drain->start_time = now;
  drain->last_progress_time = now;
  hsi_tcp_drain_sample (s, tc, drain);
  drain->state = HSI_TCP_DRAIN_STATE_DRAINING;
  tc->cfg_flags |= TCP_CFG_F_TRACKED;
  hsi_tcp_send_zero_wnd_ack (tc);
  drain->flags |= HSI_TCP_DRAIN_F_WND_CLAMPED;
  hsi_worker_counter_inc (wrk, tcp_drain_started);
  hsi_tcp_drain_maybe_register_time_update (thread_index);

  return drain;
}

static_always_inline void
hsi_tcp_fin_wait_add (tcp_connection_t *tc)
{
  hsi_worker_t *wrk = hsi_worker_get (tc->c_thread_index);
  uword key = hsi_tcp_session_conn_key_from_connection (tc);

  if (!hash_get (wrk->tcp_fin_wait_by_session_conn, key))
    hash_set (wrk->tcp_fin_wait_by_session_conn, key, 1);

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
hsi_tcp_drain_start_req_free_rpc (void *arg)
{
  hsi_tcp_drain_start_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->tcp_drain_start_reqs, a);
}

static void
hsi_tcp_drain_start_rpc (void *arg)
{
  hsi_tcp_drain_start_req_t *a = arg;
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_handle_tu_t peer_sh = { .handle = a->peer_session_handle };
  session_t *s, *peer_s;
  tcp_connection_t *tc, *peer_tc;

  s = session_get_from_handle_if_valid (sh);
  peer_s = session_get_from_handle_safe (peer_sh);
  if (!s || !peer_s)
    {
      hsi_worker_counter_inc (hsi_worker_get (vlib_get_thread_index ()), tcp_track_peer_rpc_failed);
      hsi_tcp_track_send_abort (a->session_handle);
      hsi_tcp_track_send_abort (a->peer_session_handle);
      goto done;
    }

  ASSERT (hsi_track_sessions_compatible (s, peer_s));

  tc = hsi_tcp_connection_at_session (s);
  peer_tc = hsi_tcp_connection_at_session (peer_s);
  ASSERT (!(tc->cfg_flags & TCP_CFG_F_TRACKED));
  ASSERT (peer_tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (hsi_tcp_track_connections_compatible (tc, peer_tc));
  hsi_tcp_drain_start (s, peer_s, tc, peer_tc);

done:
  session_send_rpc_evt_to_thread (a->owner_thread, hsi_tcp_drain_start_req_free_rpc, a);
}

static void
hsi_tcp_track_send_drain_start (session_t *s, session_t *peer_s)
{
  hsi_tcp_drain_start_req_t *a;
  hsi_worker_t *wrk;
  clib_thread_index_t thread_index;

  thread_index = s->thread_index;
  ASSERT (thread_index == vlib_get_thread_index ());
  wrk = hsi_worker_get (thread_index);
  pool_get_zero (wrk->tcp_drain_start_reqs, a);

  a->owner_thread = thread_index;
  a->session_handle = session_handle (peer_s);
  a->peer_session_handle = session_handle (s);
  session_send_rpc_evt_to_thread (peer_s->thread_index, hsi_tcp_drain_start_rpc, a);
}

static void
hsi_tcp_tracker_init (hsi_tcp_tracker_t *trk, tcp_connection_t *tc, hsi_tcp_track_snapshot_t *peer)
{
  clib_memset (trk, 0, sizeof (*trk));

  trk->magic = HSI_TCP_TRACKER_MAGIC;
  trk->peer_session_handle = peer->session_handle;
  trk->peer_conn_index = peer->conn_index;
  trk->peer_thread_index = peer->thread_index;
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
  trk->tsval_delta = (i32) (peer->ts_now - tc->tsval_recent);
  trk->tsecr_delta = (i32) (peer->tsval_recent - tcp_tstamp (tc));
  trk->wnd_delta = (i8) tc->snd_wscale - (i8) peer->rcv_wscale;
}

static void
hsi_tcp_track_cleanup_tcp_state (tcp_connection_t *tc)
{
  vec_free (tc->snd_sacks);
  vec_free (tc->snd_sacks_fl);
  vec_free (tc->rcv_opts.sacks);
  pool_free (tc->sack_sb.holes);
  clib_memset (&tc->sack_sb, 0, sizeof (tc->sack_sb));
  scoreboard_init (&tc->sack_sb);

  if (tc->cfg_flags & TCP_CFG_F_RATE_SAMPLE)
    {
      tcp_bt_cleanup (tc);
      tc->cfg_flags &= ~TCP_CFG_F_RATE_SAMPLE;
    }
}

static void
hsi_tcp_drain_flush_cached_buffers (tcp_connection_t *tc)
{
  hsi_tcp_drain_t *drain;
  hsi_worker_t *wrk;
  vlib_main_t *vm;
  u32 *cached, *forward = 0, *drops = 0;
  uword key;
  u32 i;

  key = hsi_tcp_session_conn_key_from_connection (tc);
  drain = hsi_tcp_drain_get (tc->c_thread_index, key);
  if (!drain || !vec_len (drain->cached_buffers))
    return;

  vm = vlib_get_main_by_index (tc->c_thread_index);
  wrk = hsi_worker_get (tc->c_thread_index);
  cached = drain->cached_buffers;
  drain->cached_buffers = 0;
  drain->cached_bytes = 0;

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

      action = hsi_tcp_handle_tracked_connection (vm, b, tc, ip_hdr, tcp_hdr, tc->c_is_ip4);
      if (action == HSI_TCP_TRACKED_ACTION_FORWARD)
	{
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
      hsi_drain_enqueue_cached_buffers (
	vm, tc->c_is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index, forward);
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
hsi_tcp_track_commit_connection (tcp_connection_t *tc, hsi_tcp_track_snapshot_t *peer)
{
  hsi_worker_t *wrk = hsi_worker_get (tc->c_thread_index);

  hsi_tcp_track_cleanup_tcp_state (tc);
  hsi_tcp_tracker_init (hsi_tcp_tracker_from_connection (tc), tc, peer);

  tc->cfg_flags |= TCP_CFG_F_TRACKED;
  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
  hsi_tcp_drain_flush_cached_buffers (tc);
  if (hsi_tcp_drain_get (tc->c_thread_index, hsi_tcp_session_conn_key_from_connection (tc)))
    hsi_worker_counter_inc (wrk, tcp_drain_completed);
  hsi_tcp_drain_stop (tc);
}

static void
hsi_tcp_track_commit (session_t *s, hsi_tcp_track_snapshot_t *peer)
{
  tcp_connection_t *tc;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  tc = hsi_tcp_connection_at_session (s);
  if (tc->state == TCP_STATE_CLOSED)
    {
      ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
      return;
    }

  hsi_session_take_ownership (s);
  tcp_connection_timers_reset (tc);
  tcp_cong_recovery_off (tc);
  hsi_tcp_track_commit_connection (tc, peer);
  s->session_state = SESSION_STATE_TRANSPORT_CLOSED;
  hsi_session_cleanup_fifos (s);
}

static void
hsi_tcp_track_commit_req_free_rpc (void *arg)
{
  hsi_tcp_track_commit_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->tcp_track_commit_reqs, a);
}

static void
hsi_tcp_track_commit_rpc (void *arg)
{
  hsi_tcp_track_commit_req_t *a = arg;
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_t *s;

  s = session_get_from_handle_if_valid (sh);
  if (s)
    hsi_tcp_track_commit (s, &a->peer);
  else
    {
      hsi_worker_counter_inc (hsi_worker_get (vlib_get_thread_index ()), tcp_track_peer_rpc_failed);
      hsi_tcp_track_send_abort (a->session_handle);
      hsi_tcp_track_send_abort (a->peer.session_handle);
    }

  session_send_rpc_evt_to_thread (a->owner_thread, hsi_tcp_track_commit_req_free_rpc, a);
}

static void
hsi_tcp_track_send_commit (session_t *peer_s, hsi_tcp_track_snapshot_t *peer)
{
  hsi_tcp_track_commit_req_t *a;
  hsi_worker_t *wrk;
  clib_thread_index_t thread_index;

  thread_index = peer->thread_index;
  ASSERT (thread_index == vlib_get_thread_index ());
  wrk = hsi_worker_get (thread_index);
  pool_get_zero (wrk->tcp_track_commit_reqs, a);

  a->owner_thread = thread_index;
  a->session_handle = session_handle (peer_s);
  a->peer = *peer;
  session_send_rpc_evt_to_thread (peer_s->thread_index, hsi_tcp_track_commit_rpc, a);
}

static int
hsi_tcp_drain_try_complete (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain, f64 now)
{
  session_handle_tu_t peer_sh;
  hsi_tcp_track_snapshot_t snap, peer_snap;
  tcp_connection_t *peer_tc;
  hsi_tcp_drain_t *peer_drain = 0;
  session_t *peer_s;
  int rv;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());
  ASSERT (drain);

  if (tc->state == TCP_STATE_CLOSED)
    return 1;

  if (drain->state == HSI_TCP_DRAIN_STATE_FAILED)
    return -1;

  peer_sh.handle = drain->peer_session_handle;
  peer_s = session_get_from_handle_safe (peer_sh);
  if (!peer_s)
    {
      hsi_worker_counter_inc (hsi_worker_get (s->thread_index), tcp_track_peer_rpc_failed);
      hsi_tcp_drain_fail_pair (drain);
      return -1;
    }

  peer_tc = hsi_tcp_connection_at_session (peer_s);
  if (!(peer_tc->cfg_flags & TCP_CFG_F_TRACKED))
    return 0;

  rv = hsi_tcp_drain_update_and_needs_drain (s, tc, drain, now);
  if (rv < 0)
    {
      hsi_tcp_drain_fail_pair (drain);
      return -1;
    }
  if (rv)
    return 0;

  if (s->thread_index == peer_s->thread_index)
    {
      peer_drain = hsi_tcp_drain_get (peer_tc->c_thread_index,
				      hsi_tcp_session_conn_key_from_connection (peer_tc));
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
    }
  else if (peer_s->rx_fifo && peer_s->tx_fifo && hsi_tcp_track_needs_drain (peer_s, peer_tc))
    return 0;

  if (s->thread_index != peer_s->thread_index)
    {
      if (drain->session_handle > drain->peer_session_handle)
	return 0;
      if (hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_COMMIT_SENT))
	return 0;
      drain->flags |= HSI_TCP_DRAIN_F_COMMIT_SENT;
    }

  hsi_tcp_track_snapshot (s, tc, &snap);
  hsi_tcp_track_snapshot (peer_s, peer_tc, &peer_snap);

  if (s->thread_index == peer_s->thread_index)
    {
      hsi_tcp_track_commit (s, &peer_snap);
      hsi_tcp_track_commit (peer_s, &snap);
      return 1;
    }

  hsi_tcp_track_send_commit (peer_s, &snap);
  hsi_tcp_track_commit (s, &peer_snap);
  return 1;
}

hsi_tcp_tracked_action_t
hsi_tcp_drain_cache_buffer (vlib_main_t *vm, vlib_buffer_t *b, tcp_connection_t *tc, void *ip_hdr,
			    tcp_header_t *tcp_hdr, u8 is_ip4)
{
  hsi_tcp_drain_t *drain;
  hsi_worker_t *wrk;
  session_t *s;
  u32 data_len, seq, seq_end, ack, len;
  u32 bytes_acked = 0;
  uword key;
  u8 rst;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (tc->state != TCP_STATE_CLOSED);
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

  if (PREDICT_FALSE (!hsi_tcp_segment_in_rcv_wnd (tc, seq, seq_end)))
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
    }
  else if (!rst)
    goto drop;

  len = vlib_buffer_length_in_chain (vm, b);
  if (PREDICT_FALSE (!hsi_drain_cache_has_room (drain->cached_buffers, drain->cached_bytes, len,
						hsi_main.tcp_drain_cache_max_packets,
						HSI_TCP_DRAIN_CACHE_MAX_BYTES)))
    {
      hsi_worker_counter_inc (wrk, tcp_drain_cache_overflow);
      hsi_tcp_drain_fail_pair (drain);
      goto drop;
    }

  hsi_drain_cache_buffer (&drain->cached_buffers, &drain->cached_bytes,
			  vlib_get_buffer_index (vm, b), len);

  if (!hsi_tcp_drain_flag_is_set (drain, HSI_TCP_DRAIN_F_WND_CLAMPED))
    {
      hsi_tcp_send_zero_wnd_ack (tc);
      drain->flags |= HSI_TCP_DRAIN_F_WND_CLAMPED;
    }

  hsi_worker_counter_inc (wrk, tcp_drain_cached);

  s = session_get (tc->c_s_index, tc->c_thread_index);
  ASSERT (s->thread_index == vm->thread_index);
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
  ASSERT (tc->state != TCP_STATE_CLOSED);
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

      s = session_get_from_handle_safe (sh);
      if (!s || s->thread_index != thread_index)
	continue;

      tc = hsi_tcp_connection_at_session (s);
      if (!(tc->cfg_flags & TCP_CFG_F_TRACKED) || tc->state == TCP_STATE_CLOSED)
	continue;

      drain = hsi_tcp_drain_get (thread_index, hsi_session_conn_key_from_session (s));
      if (drain)
	hsi_tcp_drain_try_complete (s, tc, drain, time_now);
    }

  hsi_tcp_drain_maybe_unregister_time_update (thread_index);
}

int
hsi_track_tcp (session_t *s, session_t *peer_s)
{
  tcp_connection_t *tc0, *tc1;
  hsi_tcp_track_snapshot_t snap0, snap1;
  u8 is_same_thread;

  tc0 = hsi_tcp_connection_at_session (s);
  tc1 = hsi_tcp_connection_at_session (peer_s);
  is_same_thread = s->thread_index == peer_s->thread_index;

  if (!hsi_tcp_track_is_possible (tc0, tc1))
    return -1;

  if (hsi_tcp_track_needs_drain (s, tc0) || hsi_tcp_track_needs_drain (peer_s, tc1))
    {
      hsi_tcp_drain_start (s, peer_s, tc0, tc1);
      if (is_same_thread)
	hsi_tcp_drain_start (peer_s, s, tc1, tc0);
      else
	hsi_tcp_track_send_drain_start (s, peer_s);
      return 0;
    }

  if (is_same_thread)
    {
      hsi_tcp_track_snapshot (s, tc0, &snap0);
      hsi_tcp_track_snapshot (peer_s, tc1, &snap1);

      hsi_tcp_track_commit (s, &snap1);
      hsi_tcp_track_commit (peer_s, &snap0);

      return 0;
    }

  hsi_tcp_track_snapshot (s, tc0, &snap0);
  hsi_tcp_track_snapshot (peer_s, tc1, &snap1);

  hsi_tcp_track_send_commit (peer_s, &snap0);
  hsi_tcp_track_commit (s, &snap1);

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
  u8 local_shared, peer_shared;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (tc->state == TCP_STATE_CLOSED);
  ASSERT (trk->peer_session_handle != SESSION_INVALID_HANDLE);

  local_handle = session_make_handle (tc->c_s_index, tc->c_thread_index);

  peer_s = session_get_from_handle_safe (peer_sh);
  if (peer_s)
    {
      peer_tc = hsi_tcp_connection_at_session (peer_s);
      ASSERT (peer_tc->cfg_flags & TCP_CFG_F_TRACKED);
      if (peer_tc->state == TCP_STATE_CLOSED)
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

  wrk = hsi_worker_get (vlib_get_thread_index ());
  hsi_worker_counter_inc (wrk, tcp_cleanup_scheduled);
  if (reason == HSI_TCP_CLEANUP_REASON_RST)
    hsi_worker_counter_inc (wrk, tcp_rst_cleanup);
  else
    hsi_worker_counter_inc (wrk, tcp_fin_cleanup);

  hsi_tcp_fin_wait_del (tc);
  if (peer_trk)
    hsi_tcp_fin_wait_del (peer_tc);

  local_s = session_get_from_handle_safe ((session_handle_tu_t){ .handle = local_handle });
  ASSERT (local_s);
  local_shared = hsi_session_uses_shared_fifos (local_s);
  peer_shared =
    peer_s && hsi_session_is_hsi_owned (peer_s) && hsi_session_uses_shared_fifos (peer_s);

  if (local_shared && !peer_shared)
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

  trk->flags |= HSI_TRACKER_F_FIN_WAIT;
  trk->fin_wait_start = vlib_time_now (vlib_get_main ());
  hsi_worker_counter_inc (hsi_worker_get (tc->c_thread_index), tcp_fin_wait_started);
  hsi_tcp_fin_wait_add (tc);
}

static void
hsi_tcp_track_maybe_cleanup_pair (tcp_connection_t *tc, hsi_tcp_tracker_t *trk)
{
  session_handle_tu_t peer_sh = { .handle = trk->peer_session_handle };
  tcp_connection_t *peer_tc;
  hsi_tcp_tracker_t *peer_trk;
  session_t *peer_s;

  if (!hsi_tcp_tracker_fin_done (trk))
    return;

  peer_s = session_get_from_handle_safe (peer_sh);
  if (!peer_s)
    return;

  peer_tc = hsi_tcp_connection_at_session (peer_s);
  ASSERT (peer_tc->cfg_flags & TCP_CFG_F_TRACKED);
  if (peer_tc->state != TCP_STATE_CLOSED)
    return;

  peer_trk = hsi_tcp_tracker_from_connection (peer_tc);
  if (hsi_tcp_tracker_fin_done (peer_trk))
    {
      hsi_tcp_track_schedule_cleanup_pair (tc, trk, HSI_TCP_CLEANUP_REASON_FIN);
      return;
    }

  if (hsi_tcp_tracker_fin_received (peer_trk))
    hsi_tcp_track_arm_fin_wait (tc, trk);
}

void
hsi_tcp_fin_wait_update_time (f64 time_now, u8 thread_index)
{
  hsi_tcp_tracker_t *trk, *peer_trk;
  session_handle_tu_t peer_sh;
  tcp_connection_t *tc, *peer_tc;
  session_t *peer_s;
  hsi_worker_t *wrk;
  hash_pair_t *hp;
  uword *keyp, *keys;
  session_t *s;

  wrk = hsi_worker_get (thread_index);
  if (!hash_elts (wrk->tcp_fin_wait_by_session_conn))
    {
      hsi_tcp_fin_wait_maybe_unregister_time_update (thread_index);
      return;
    }

  keys = wrk->tcp_fin_wait_update_keys;
  vec_reset_length (keys);
  hash_foreach_pair (hp, wrk->tcp_fin_wait_by_session_conn, ({ vec_add1 (keys, hp->key); }));
  wrk->tcp_fin_wait_update_keys = keys;

  vec_foreach (keyp, keys)
    {
      session_handle_tu_t sh = {
	.handle = session_make_handle (hsi_session_conn_key_session_index (*keyp), thread_index),
      };

      s = session_get_from_handle_if_valid (sh);
      if (!s || s->connection_index != hsi_session_conn_key_conn_index (*keyp))
	{
	  hsi_tcp_fin_wait_del_key (thread_index, *keyp);
	  continue;
	}

      tc = hsi_tcp_connection_at_session (s);
      if (!(tc->cfg_flags & TCP_CFG_F_TRACKED) || tc->state != TCP_STATE_CLOSED)
	{
	  hsi_tcp_fin_wait_del_key (thread_index, *keyp);
	  continue;
	}

      trk = hsi_tcp_tracker_from_connection (tc);
      if (trk->magic != HSI_TCP_TRACKER_MAGIC || !(trk->flags & HSI_TRACKER_F_FIN_WAIT) ||
	  (trk->flags & HSI_TRACKER_F_CLEANUP_PENDING))
	{
	  hsi_tcp_fin_wait_del_key (thread_index, *keyp);
	  continue;
	}

      if (time_now - trk->fin_wait_start < hsi_main.tcp_fin_wait_timeout)
	continue;

      peer_sh.handle = trk->peer_session_handle;
      peer_s = session_get_from_handle_safe (peer_sh);
      if (!peer_s)
	{
	  hsi_tcp_fin_wait_del_key (thread_index, *keyp);
	  hsi_tcp_tracker_cleanup_mark_pending (trk);
	  hsi_session_cleanup (s);
	  continue;
	}

      peer_tc = hsi_tcp_connection_at_session (peer_s);
      if (!(peer_tc->cfg_flags & TCP_CFG_F_TRACKED) || peer_tc->state != TCP_STATE_CLOSED)
	continue;

      peer_trk = hsi_tcp_tracker_from_connection (peer_tc);
      if (!hsi_tcp_tracker_fin_received (trk) || !hsi_tcp_tracker_fin_received (peer_trk))
	continue;

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
  ASSERT (tc->state == TCP_STATE_CLOSED);

  trk = hsi_tcp_tracker_get (tc);
  if ((trk->flags & HSI_TRACKER_F_FIN_RCVD) && seq_geq (ack, tc->rcv_nxt))
    trk->flags |= HSI_TRACKER_F_FIN_ACKED;

  hsi_tcp_track_maybe_cleanup_pair (tc, trk);
}

static void
hsi_tcp_fin_ack_req_free_rpc (void *arg)
{
  hsi_tcp_fin_ack_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->tcp_fin_ack_reqs, a);
}

static void
hsi_tcp_mark_fin_acked_rpc (void *arg)
{
  hsi_tcp_fin_ack_req_t *a = arg;
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_t *s;

  s = session_get_from_handle_if_valid (sh);
  if (s)
    hsi_tcp_mark_fin_acked (hsi_tcp_connection_at_session (s), a->ack);

  session_send_rpc_evt_to_thread (a->owner_thread, hsi_tcp_fin_ack_req_free_rpc, a);
}

static void
hsi_tcp_send_fin_acked (session_t *s, u32 ack)
{
  hsi_tcp_fin_ack_req_t *a;
  hsi_worker_t *wrk;
  clib_thread_index_t thread_index = vlib_get_thread_index ();

  wrk = hsi_worker_get (thread_index);
  pool_get_zero (wrk->tcp_fin_ack_reqs, a);

  a->owner_thread = thread_index;
  a->session_handle = session_handle (s);
  a->ack = ack;
  session_send_rpc_evt_to_thread_force (s->thread_index, hsi_tcp_mark_fin_acked_rpc, a);
}

static void
hsi_tcp_track_peer_fin_acked (hsi_tcp_tracker_t *trk, u32 ack)
{
  session_handle_tu_t peer_sh = { .handle = trk->peer_session_handle };
  session_t *peer_s;
  u32 peer_ack;

  peer_s = session_get_from_handle_safe (peer_sh);
  if (!peer_s)
    return;

  peer_ack = ack + trk->ack_delta;
  if (peer_s->thread_index == vlib_get_thread_index ())
    hsi_tcp_mark_fin_acked (hsi_tcp_connection_at_session (peer_s), peer_ack);
  else
    hsi_tcp_send_fin_acked (peer_s, peer_ack);
}

static void
hsi_tcp_track_pending_peer_fin_ack_update (hsi_tcp_tracker_t *trk, u32 ack)
{
  ASSERT (trk->flags & HSI_TRACKER_F_PEER_FIN_PENDING);

  if (seq_lt (ack, trk->peer_fin_ack))
    return;

  trk->flags &= ~HSI_TRACKER_F_PEER_FIN_PENDING;
  hsi_tcp_track_peer_fin_acked (trk, ack);
}

static void
hsi_tcp_track_pending_peer_fin_ack (hsi_tcp_tracker_t *trk, tcp_header_t *tcp_hdr, u32 ack, u8 rst)
{
  ASSERT (trk->flags & HSI_TRACKER_F_PEER_FIN_PENDING);

  if (!tcp_ack (tcp_hdr) || rst)
    return;

  hsi_tcp_track_pending_peer_fin_ack_update (trk, ack);
}

static void
hsi_tcp_mark_peer_fin_pending (tcp_connection_t *tc, u32 ack)
{
  hsi_tcp_tracker_t *trk;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (tc->state == TCP_STATE_CLOSED);

  trk = hsi_tcp_tracker_get (tc);
  trk->peer_fin_ack = ack - trk->ack_delta;
  trk->flags |= HSI_TRACKER_F_PEER_FIN_PENDING;

  hsi_tcp_track_pending_peer_fin_ack_update (trk, tc->snd_una);
}

static void
hsi_tcp_peer_fin_req_free_rpc (void *arg)
{
  hsi_tcp_peer_fin_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->tcp_peer_fin_reqs, a);
}

static void
hsi_tcp_mark_peer_fin_pending_rpc (void *arg)
{
  hsi_tcp_peer_fin_req_t *a = arg;
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_t *s;

  s = session_get_from_handle_if_valid (sh);
  if (s)
    hsi_tcp_mark_peer_fin_pending (hsi_tcp_connection_at_session (s), a->ack);

  session_send_rpc_evt_to_thread (a->owner_thread, hsi_tcp_peer_fin_req_free_rpc, a);
}

static void
hsi_tcp_send_peer_fin_pending (session_t *s, u32 ack)
{
  hsi_tcp_peer_fin_req_t *a;
  hsi_worker_t *wrk;
  clib_thread_index_t thread_index = vlib_get_thread_index ();

  wrk = hsi_worker_get (thread_index);
  pool_get_zero (wrk->tcp_peer_fin_reqs, a);

  a->owner_thread = thread_index;
  a->session_handle = session_handle (s);
  a->ack = ack;
  session_send_rpc_evt_to_thread_force (s->thread_index, hsi_tcp_mark_peer_fin_pending_rpc, a);
}

static void
hsi_tcp_arm_peer_fin_pending (hsi_tcp_tracker_t *trk, u32 ack)
{
  session_handle_tu_t peer_sh = { .handle = trk->peer_session_handle };
  session_t *peer_s;

  peer_s = session_get_from_handle_safe (peer_sh);
  if (!peer_s)
    return;

  if (peer_s->thread_index == vlib_get_thread_index ())
    hsi_tcp_mark_peer_fin_pending (hsi_tcp_connection_at_session (peer_s), ack);
  else
    hsi_tcp_send_peer_fin_pending (peer_s, ack);
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

  if (PREDICT_FALSE (!hsi_tcp_segment_in_rcv_wnd (tc, *seq, seq_end)))
    return 0;

  if (PREDICT_FALSE (rst))
    {
      if (tcp_ack (tcp_hdr) && seq_gt (*ack, tc->snd_nxt))
	return 0;
      return 1;
    }

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

  if (seq_leq (*seq, tc->rcv_nxt) && seq_gt (seq_end, tc->rcv_nxt))
    {
      tc->rcv_nxt = seq_end;
      tc->rcv_las = tc->rcv_nxt;
    }

  if (PREDICT_FALSE (tcp_fin (tcp_hdr)))
    trk->flags |= HSI_TRACKER_F_FIN_RCVD;

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
				   void *ip_hdr, tcp_header_t *tcp_hdr, u8 is_ip4)
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
    hsi_tcp_track_pending_peer_fin_ack (trk, tcp_hdr, ack, rst);

  if (PREDICT_FALSE (fin && !rst && !fin_seen))
    hsi_tcp_arm_peer_fin_pending (trk, tc->rcv_nxt);

  tcp_hdr->seq_number = clib_host_to_net_u32 (seq + trk->seq_delta);

  if (tcp_ack (tcp_hdr))
    tcp_hdr->ack_number = clib_host_to_net_u32 (ack + trk->ack_delta);

  tcp_hdr->window = hsi_tcp_translate_window (tcp_hdr->window, trk);
  if (tcp_header_bytes (tcp_hdr) > sizeof (*tcp_hdr))
    hsi_tcp_rewrite_options (tcp_hdr, trk);

  tcp_hdr->src_port = trk->tx_lcl_port;
  tcp_hdr->dst_port = trk->tx_rmt_port;
  vnet_buffer (b)->ip.fib_index = trk->tx_fib_index;
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
    hsi_tcp_track_schedule_cleanup_pair (tc, trk, HSI_TCP_CLEANUP_REASON_RST);
  else if (PREDICT_FALSE (trk->flags & HSI_TRACKER_F_FIN_MASK))
    hsi_tcp_track_maybe_cleanup_pair (tc, trk);

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
      vlib_cli_output (vm,
		       "thread %u tcp-drain session 0x%lx peer 0x%lx peer-thread %u "
		       "state %s cache %u/%u bytes %u age %.3f idle %.3f",
		       i, drain->session_handle, drain->peer_session_handle,
		       drain->peer_thread_index, hsi_tcp_drain_state_name (drain->state),
		       vec_len (drain->cached_buffers), hsi_main.tcp_drain_cache_max_packets,
		       drain->cached_bytes, now - drain->start_time,
		       now - drain->last_progress_time);
    }

  pool_foreach (tc, tcp_main.wrk[i].connections)
    {
      if (!(tc->cfg_flags & TCP_CFG_F_TRACKED) || tc->state != TCP_STATE_CLOSED)
	continue;

      trk = hsi_tcp_tracker_from_connection (tc);
      if (trk->magic != HSI_TCP_TRACKER_MAGIC)
	continue;

      vlib_cli_output (vm,
		       "thread %u tcp-tracked session 0x%lx peer 0x%lx peer-thread %u "
		       "flags %U peer-fin-ack %u seq-delta %d ack-delta %d "
		       "packets %lu bytes %lu",
		       i, session_make_handle (tc->c_s_index, tc->c_thread_index),
		       trk->peer_session_handle, trk->peer_thread_index,
		       format_hsi_tcp_tracker_flags, trk->flags, trk->peer_fin_ack, trk->seq_delta,
		       trk->ack_delta, trk->packets, trk->bytes);
    }
}
