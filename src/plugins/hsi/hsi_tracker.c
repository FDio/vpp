/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <hsi/hsi_tracker.h>
#include <vnet/session/application.h>
#include <vnet/tcp/tcp_inlines.h>
#include <vppinfra/pool.h>

#define HSI_TCP_TRACKER_MAGIC		  0x48534954
#define HSI_TCP_DRAIN_INDEX_INVALID	  ((u32) ~0)
#define HSI_TCP_DRAIN_NO_PROGRESS_TIMEOUT 10.0

STATIC_ASSERT (sizeof (uword) >= sizeof (u64), "hsi drain lookup requires 64-bit keys");

typedef enum hsi_tracker_flags_
{
  HSI_TRACKER_F_CLEANUP_PENDING = 1 << 0,
  HSI_TRACKER_F_FIN_RCVD = 1 << 1,
  HSI_TRACKER_F_FIN_ACKED = 1 << 2,
  HSI_TRACKER_F_PEER_FIN_PENDING = 1 << 3,
} hsi_tracker_flags_t;

#define HSI_TRACKER_F_FIN_DONE (HSI_TRACKER_F_FIN_RCVD | HSI_TRACKER_F_FIN_ACKED)

typedef struct hsi_tcp_tracker_
{
  u32 magic;
  u32 flags;
  u32 peer_fin_ack;
  session_handle_t peer_session_handle;
  u32 peer_conn_index;
  u32 tx_fib_index;
  ip46_address_t tx_lcl_ip;
  ip46_address_t tx_rmt_ip;
  u16 tx_lcl_port;
  u16 tx_rmt_port;
  clib_thread_index_t peer_thread_index;
  i32 seq_delta;
  i32 ack_delta;
  i32 tsval_delta;
  i32 tsecr_delta;
  i8 wnd_delta;
  u64 packets;
  u64 bytes;
} hsi_tcp_tracker_t;

STATIC_ASSERT (sizeof (hsi_tcp_tracker_t) <= (STRUCT_OFFSET_OF (tcp_connection_t, bt) -
					      STRUCT_OFFSET_OF (tcp_connection_t, fr_occurences)),
	       "hsi tcp tracker must fit in unused tracked tcp fields");
STATIC_ASSERT ((STRUCT_OFFSET_OF (tcp_connection_t, fr_occurences) %
		__alignof__ (hsi_tcp_tracker_t)) == 0,
	       "hsi tcp tracker overlay must be aligned");

typedef struct hsi_udp_tracker_
{
  u32 tx_fib_index;
  ip46_address_t tx_lcl_ip;
  ip46_address_t tx_rmt_ip;
  u16 tx_lcl_port;
  u16 tx_rmt_port;
} hsi_udp_tracker_t;

STATIC_ASSERT (sizeof (hsi_udp_tracker_t) <= (STRUCT_OFFSET_OF (udp_connection_t, start_ts) -
					      STRUCT_OFFSET_OF (udp_connection_t, bytes_in)),
	       "hsi udp tracker must fit in unused tracked udp fields");
STATIC_ASSERT ((STRUCT_OFFSET_OF (udp_connection_t, bytes_in) % __alignof__ (hsi_udp_tracker_t)) ==
		 0,
	       "hsi udp tracker overlay must be aligned");

typedef struct hsi_udp_track_snapshot_
{
  session_handle_t session_handle;
  u32 conn_index;
  u32 fib_index;
  ip46_address_t lcl_ip;
  ip46_address_t rmt_ip;
  u16 lcl_port;
  u16 rmt_port;
  clib_thread_index_t thread_index;
  u8 is_ip4;
} hsi_udp_track_snapshot_t;

struct hsi_udp_track_commit_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  hsi_udp_track_snapshot_t peer;
};

typedef struct hsi_tcp_fin_ack_req_
{
  session_handle_t session_handle;
  u32 ack;
} hsi_tcp_fin_ack_req_t;

typedef struct hsi_tcp_peer_fin_req_
{
  session_handle_t session_handle;
  u32 ack;
} hsi_tcp_peer_fin_req_t;

typedef struct hsi_track_session_pair_req_
{
  session_handle_t session_handle;
  session_handle_t peer_session_handle;
} hsi_track_session_pair_req_t;

typedef enum hsi_tcp_drain_state_
{
  HSI_TCP_DRAIN_STATE_DRAINING,
  HSI_TCP_DRAIN_STATE_READY,
} hsi_tcp_drain_state_t;

struct hsi_tcp_drain_
{
  session_handle_t session_handle;
  session_handle_t peer_session_handle;
  u32 conn_index;
  u32 peer_conn_index;
  hsi_tcp_track_snapshot_t snapshot;
  clib_thread_index_t thread_index;
  clib_thread_index_t peer_thread_index;
  f64 start_time;
  f64 last_progress_time;
  u32 rx_deq;
  u32 tx_deq;
  u32 snd_una;
  u32 snd_nxt;
  u8 rx_ooo;
  u8 stalled;
  hsi_tcp_drain_state_t state;
};

struct hsi_tcp_drain_start_req_
{
  clib_thread_index_t owner_thread;
  session_handle_t session_handle;
  session_handle_t peer_session_handle;
};

static_always_inline hsi_worker_t *
hsi_worker_get (clib_thread_index_t thread_index)
{
  return vec_elt_at_index (hsi_main.wrk, thread_index);
}

static_always_inline void
hsi_session_take_ownership (session_t *s)
{
  s->app_wrk_index = APP_INVALID_INDEX;
}

static_always_inline hsi_tcp_tracker_t *
hsi_tcp_tracker_from_connection (tcp_connection_t *tc)
{
  return (hsi_tcp_tracker_t *) &tc->fr_occurences;
}

static inline hsi_tcp_tracker_t *
hsi_tcp_tracker_get (tcp_connection_t *tc)
{
  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (tc->state == TCP_STATE_CLOSED);
  return hsi_tcp_tracker_from_connection (tc);
}

static_always_inline hsi_udp_tracker_t *
hsi_udp_tracker_from_connection (udp_connection_t *uc)
{
  return (hsi_udp_tracker_t *) &uc->bytes_in;
}

static inline hsi_udp_tracker_t *
hsi_udp_tracker_get (udp_connection_t *uc)
{
  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  return hsi_udp_tracker_from_connection (uc);
}

static_always_inline tcp_connection_t *
hsi_tcp_connection_at_index (clib_thread_index_t thread_index, u32 conn_index)
{
  return tcp_main.wrk[thread_index].connections + conn_index;
}

static_always_inline tcp_connection_t *
hsi_tcp_connection_at_session (session_t *s)
{
  return hsi_tcp_connection_at_index (s->thread_index, s->connection_index);
}

static_always_inline uword
hsi_session_conn_key (u32 session_index, u32 conn_index)
{
  return ((uword) session_index << 32) | conn_index;
}

static_always_inline uword
hsi_session_conn_key_from_session (session_t *s)
{
  return hsi_session_conn_key (s->session_index, s->connection_index);
}

static_always_inline uword
hsi_tcp_session_conn_key_from_connection (tcp_connection_t *tc)
{
  return hsi_session_conn_key (tc->c_s_index, tc->c_c_index);
}

static_always_inline u32
hsi_tcp_drain_index_get (clib_thread_index_t thread_index, uword key)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);
  uword *p;

  p = hash_get (wrk->tcp_drain_by_session_conn, key);
  if (!p)
    return HSI_TCP_DRAIN_INDEX_INVALID;

  return p[0];
}

static_always_inline hsi_tcp_drain_t *
hsi_tcp_drain_get (clib_thread_index_t thread_index, uword key)
{
  hsi_worker_t *wrk;
  u32 drain_index;

  drain_index = hsi_tcp_drain_index_get (thread_index, key);
  if (drain_index == HSI_TCP_DRAIN_INDEX_INVALID)
    return 0;

  wrk = hsi_worker_get (thread_index);
  return pool_elt_at_index (wrk->tcp_drains, drain_index);
}

static_always_inline void
hsi_udp_track_peer_set (session_t *s, session_handle_t peer_handle)
{
  hsi_worker_t *wrk = hsi_worker_get (s->thread_index);

  hash_set (wrk->udp_track_peer_by_session_conn, hsi_session_conn_key_from_session (s),
	    peer_handle);
}

static_always_inline void
hsi_udp_track_peer_unset (session_t *s)
{
  hsi_worker_t *wrk = hsi_worker_get (s->thread_index);

  hash_unset (wrk->udp_track_peer_by_session_conn, hsi_session_conn_key_from_session (s));
}

static_always_inline udp_connection_t *
hsi_udp_connection_at_index (clib_thread_index_t thread_index, u32 conn_index)
{
  return udp_main.wrk[thread_index].connections + conn_index;
}

static_always_inline udp_connection_t *
hsi_udp_connection_at_session (session_t *s)
{
  return hsi_udp_connection_at_index (s->thread_index, s->connection_index);
}

static_always_inline int
hsi_track_sessions_compatible (session_t *s, session_t *peer_s)
{
  if (!peer_s || s == peer_s)
    return 0;
  if (s->session_type != peer_s->session_type)
    return 0;
  if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING ||
      peer_s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return 0;

  return 1;
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

static_always_inline void
hsi_tcp_drain_sample (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain)
{
  drain->rx_deq = svm_fifo_max_dequeue (s->rx_fifo);
  drain->tx_deq = svm_fifo_max_dequeue_cons (s->tx_fifo);
  drain->rx_ooo = svm_fifo_has_ooo_data (s->rx_fifo);
  drain->snd_una = tc->snd_una;
  drain->snd_nxt = tc->snd_nxt;
}

static_always_inline int
hsi_tcp_drain_sample_needs_drain (hsi_tcp_drain_t *drain)
{
  if (drain->rx_deq || drain->tx_deq || drain->rx_ooo)
    return 1;

  return drain->snd_una != drain->snd_nxt;
}

static_always_inline u8
hsi_tcp_drain_sample_changed (hsi_tcp_drain_t *drain, hsi_tcp_drain_t *sample)
{
  return drain->rx_deq != sample->rx_deq || drain->tx_deq != sample->tx_deq ||
	 drain->rx_ooo != sample->rx_ooo || drain->snd_una != sample->snd_una ||
	 drain->snd_nxt != sample->snd_nxt;
}

static int
hsi_tcp_drain_update_and_needs_drain (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain)
{
  hsi_tcp_drain_t sample = {};
  f64 now;
  int needs_drain;

  hsi_tcp_drain_sample (s, tc, &sample);
  now = vlib_time_now (vlib_get_main ());

  if (hsi_tcp_drain_sample_changed (drain, &sample))
    {
      drain->rx_deq = sample.rx_deq;
      drain->tx_deq = sample.tx_deq;
      drain->rx_ooo = sample.rx_ooo;
      drain->snd_una = sample.snd_una;
      drain->snd_nxt = sample.snd_nxt;
      drain->last_progress_time = now;
      drain->stalled = 0;
    }

  needs_drain = hsi_tcp_drain_sample_needs_drain (&sample);
  if (needs_drain && !drain->stalled &&
      now - drain->last_progress_time > HSI_TCP_DRAIN_NO_PROGRESS_TIMEOUT)
    {
      hsi_worker_get (vlib_get_thread_index ())->tcp_drain_stalled++;
      drain->stalled = 1;
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
  pool_get_zero (wrk->tcp_drains, drain);
  drain_index = drain - wrk->tcp_drains;
  hash_set (wrk->tcp_drain_by_session_conn, key, drain_index);

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

  return drain;
}

static void
hsi_tcp_drain_stop (tcp_connection_t *tc)
{
  hsi_worker_t *wrk;
  u32 drain_index;
  uword key;

  key = hsi_tcp_session_conn_key_from_connection (tc);
  drain_index = hsi_tcp_drain_index_get (tc->c_thread_index, key);
  if (drain_index == HSI_TCP_DRAIN_INDEX_INVALID)
    return;

  wrk = hsi_worker_get (tc->c_thread_index);
  hash_unset (wrk->tcp_drain_by_session_conn, key);
  pool_put_index (wrk->tcp_drains, drain_index);
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
    goto done;

  ASSERT (hsi_track_sessions_compatible (s, peer_s));

  tc = hsi_tcp_connection_at_session (s);
  peer_tc = hsi_tcp_connection_at_session (peer_s);
  ASSERT (!(tc->cfg_flags & TCP_CFG_F_TRACKED));
  ASSERT (hsi_tcp_track_connections_compatible (tc, peer_tc));
  hsi_tcp_drain_start (s, peer_s, tc, peer_tc);

done:
  session_send_rpc_evt_to_thread (a->owner_thread, hsi_tcp_drain_start_req_free_rpc, a);
}

static int
hsi_tcp_track_send_drain_start (session_t *s, session_t *peer_s)
{
  hsi_tcp_drain_start_req_t *a;
  hsi_worker_t *wrk;
  clib_thread_index_t thread_index;

  thread_index = vlib_get_thread_index ();
  ASSERT (thread_index == s->thread_index);
  wrk = hsi_worker_get (thread_index);
  pool_get_zero (wrk->tcp_drain_start_reqs, a);

  a->owner_thread = thread_index;
  a->session_handle = session_handle (peer_s);
  a->peer_session_handle = session_handle (s);
  session_send_rpc_evt_to_thread (peer_s->thread_index, hsi_tcp_drain_start_rpc, a);

  return 0;
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
hsi_tcp_track_commit_connection (tcp_connection_t *tc, hsi_tcp_track_snapshot_t *peer)
{
  hsi_tcp_drain_stop (tc);
  hsi_tcp_track_cleanup_tcp_state (tc);
  hsi_tcp_tracker_init (hsi_tcp_tracker_from_connection (tc), tc, peer);

  tc->cfg_flags |= TCP_CFG_F_TRACKED;
  tcp_connection_set_state (tc, TCP_STATE_CLOSED);
}

static void
hsi_tcp_track_commit (session_t *s, hsi_tcp_track_snapshot_t *peer)
{
  tcp_connection_t *tc;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  tc = hsi_tcp_connection_at_session (s);
  hsi_session_take_ownership (s);
  tcp_connection_timers_reset (tc);
  tcp_cong_recovery_off (tc);
  hsi_tcp_track_commit_connection (tc, peer);
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

  session_send_rpc_evt_to_thread (a->owner_thread, hsi_tcp_track_commit_req_free_rpc, a);
}

static int
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

  return 0;
}

static int
hsi_tcp_drain_try_complete (session_t *s, tcp_connection_t *tc, hsi_tcp_drain_t *drain)
{
  session_handle_tu_t peer_sh;
  hsi_tcp_track_snapshot_t snap, peer_snap;
  tcp_connection_t *peer_tc;
  hsi_tcp_drain_t *peer_drain = 0;
  session_t *peer_s;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());

  if (tc->state == TCP_STATE_CLOSED)
    return 1;

  if (!drain)
    return -1;

  peer_sh.handle = drain->peer_session_handle;
  peer_s = session_get_from_handle_safe (peer_sh);
  if (!peer_s)
    return -1;

  peer_tc = hsi_tcp_connection_at_session (peer_s);
  if (!(peer_tc->cfg_flags & TCP_CFG_F_TRACKED))
    return 0;

  if (hsi_tcp_drain_update_and_needs_drain (s, tc, drain))
    return 0;

  if (s->thread_index == peer_s->thread_index)
    {
      peer_drain = hsi_tcp_drain_get (peer_tc->c_thread_index,
				      hsi_tcp_session_conn_key_from_connection (peer_tc));
      if (peer_drain && hsi_tcp_drain_update_and_needs_drain (peer_s, peer_tc, peer_drain))
	return 0;
    }
  else if (hsi_tcp_track_needs_drain (peer_s, peer_tc))
    return 0;

  hsi_tcp_track_snapshot (s, tc, &snap);
  hsi_tcp_track_snapshot (peer_s, peer_tc, &peer_snap);

  if (s->thread_index == peer_s->thread_index)
    {
      hsi_tcp_track_commit (s, &peer_snap);
      hsi_tcp_track_commit (peer_s, &snap);
      return 1;
    }

  if (hsi_tcp_track_send_commit (peer_s, &snap))
    return 0;

  hsi_tcp_track_commit (s, &peer_snap);
  return 1;
}

int
hsi_tcp_try_complete_drain (tcp_connection_t *tc)
{
  session_handle_tu_t sh;
  hsi_tcp_drain_t *drain;
  session_t *s;

  ASSERT (tc->cfg_flags & TCP_CFG_F_TRACKED);
  ASSERT (tc->state != TCP_STATE_CLOSED);
  ASSERT (tc->c_thread_index == vlib_get_thread_index ());

  drain = hsi_tcp_drain_get (tc->c_thread_index, hsi_tcp_session_conn_key_from_connection (tc));
  if (!drain)
    return 0;

  sh.handle = drain->session_handle;
  s = session_get_from_handle_safe (sh);
  if (!s)
    return 0;

  return hsi_tcp_drain_try_complete (s, tc, drain) == 1;
}

static int
hsi_tcp_track_session_pair (session_t *s, session_t *peer_s)
{
  tcp_connection_t *tc0, *tc1;
  hsi_tcp_track_snapshot_t snap0, snap1;
  u8 is_same_thread;

  tc0 = hsi_tcp_connection_at_session (s);
  tc1 = hsi_tcp_connection_at_session (peer_s);
  is_same_thread = s->thread_index == peer_s->thread_index;

  ASSERT (!(tc0->cfg_flags & TCP_CFG_F_TRACKED));

  if (!hsi_tcp_track_is_possible (tc0, tc1))
    return -1;

  if (hsi_tcp_track_needs_drain (s, tc0) || hsi_tcp_track_needs_drain (peer_s, tc1))
    {
      hsi_tcp_drain_start (s, peer_s, tc0, tc1);
      if (is_same_thread)
	hsi_tcp_drain_start (peer_s, s, tc1, tc0);
      else if (hsi_tcp_track_send_drain_start (s, peer_s))
	return -1;
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

  if (hsi_tcp_track_send_commit (peer_s, &snap0))
    return -1;

  hsi_tcp_track_commit (s, &snap1);

  return 0;
}

static void
hsi_udp_track_snapshot (session_t *s, udp_connection_t *uc, hsi_udp_track_snapshot_t *snap)
{
  snap->session_handle = session_handle (s);
  snap->conn_index = uc->c_c_index;
  snap->thread_index = uc->c_thread_index;
  snap->fib_index = uc->c_fib_index;
  snap->lcl_ip = uc->c_lcl_ip;
  snap->rmt_ip = uc->c_rmt_ip;
  snap->lcl_port = uc->c_lcl_port;
  snap->rmt_port = uc->c_rmt_port;
  snap->is_ip4 = uc->c_is_ip4;
}

static_always_inline int
hsi_udp_track_connections_compatible (udp_connection_t *uc0, udp_connection_t *uc1)
{
  if (uc0->c_is_ip4 != uc1->c_is_ip4)
    return 0;

  return 1;
}

static_always_inline int
hsi_udp_track_is_possible (udp_connection_t *uc0, udp_connection_t *uc1)
{
  if (!(uc0->flags & UDP_CONN_F_CONNECTED) || !(uc1->flags & UDP_CONN_F_CONNECTED))
    return 0;
  if (uc0->cfg_flags & UDP_CFG_F_TRACKED)
    return 0;
  if (uc1->cfg_flags & UDP_CFG_F_TRACKED)
    return 0;

  return hsi_udp_track_connections_compatible (uc0, uc1);
}

static_always_inline int
hsi_udp_track_needs_drain (session_t *s)
{
  if (svm_fifo_max_dequeue (s->rx_fifo))
    return 1;

  return svm_fifo_max_dequeue_cons (s->tx_fifo) != 0;
}

static void
hsi_udp_tracker_init (hsi_udp_tracker_t *trk, hsi_udp_track_snapshot_t *peer)
{
  clib_memset (trk, 0, sizeof (*trk));

  trk->tx_fib_index = peer->fib_index;
  trk->tx_lcl_ip = peer->lcl_ip;
  trk->tx_rmt_ip = peer->rmt_ip;
  trk->tx_lcl_port = peer->lcl_port;
  trk->tx_rmt_port = peer->rmt_port;
}

static void
hsi_udp_track_commit_connection (udp_connection_t *uc, hsi_udp_track_snapshot_t *peer)
{
  hsi_udp_tracker_init (hsi_udp_tracker_from_connection (uc), peer);

  uc->cfg_flags |= UDP_CFG_F_TRACKED;
}

static void
hsi_udp_track_commit (session_t *s, hsi_udp_track_snapshot_t *peer)
{
  udp_connection_t *uc;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  uc = hsi_udp_connection_at_session (s);
  hsi_session_take_ownership (s);
  hsi_udp_track_peer_set (s, peer->session_handle);
  hsi_udp_track_commit_connection (uc, peer);
}

static void
hsi_udp_track_commit_req_free_rpc (void *arg)
{
  hsi_udp_track_commit_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->udp_track_commit_reqs, a);
}

static void
hsi_udp_track_commit_rpc (void *arg)
{
  hsi_udp_track_commit_req_t *a = arg;
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_t *s;

  s = session_get_from_handle_if_valid (sh);
  if (s)
    hsi_udp_track_commit (s, &a->peer);
  session_send_rpc_evt_to_thread (a->owner_thread, hsi_udp_track_commit_req_free_rpc, a);
}

static int
hsi_udp_track_send_commit (session_t *peer_s, hsi_udp_track_snapshot_t *peer)
{
  hsi_udp_track_commit_req_t *a;
  hsi_worker_t *wrk;
  clib_thread_index_t thread_index;

  thread_index = peer->thread_index;
  ASSERT (thread_index == vlib_get_thread_index ());
  wrk = hsi_worker_get (thread_index);
  pool_get_zero (wrk->udp_track_commit_reqs, a);

  a->owner_thread = thread_index;
  a->session_handle = session_handle (peer_s);
  a->peer = *peer;
  session_send_rpc_evt_to_thread (peer_s->thread_index, hsi_udp_track_commit_rpc, a);

  return 0;
}

static int
hsi_udp_track_session_pair (session_t *s, session_t *peer_s)
{
  hsi_udp_track_snapshot_t snap0, snap1;
  udp_connection_t *uc0, *uc1;
  u8 is_same_thread;

  uc0 = hsi_udp_connection_at_session (s);
  uc1 = hsi_udp_connection_at_session (peer_s);
  is_same_thread = s->thread_index == peer_s->thread_index;

  ASSERT (!(uc0->cfg_flags & UDP_CFG_F_TRACKED));

  if (!hsi_udp_track_is_possible (uc0, uc1))
    return -1;

  if (hsi_udp_track_needs_drain (s) || hsi_udp_track_needs_drain (peer_s))
    return -1;

  if (is_same_thread)
    {
      hsi_udp_track_snapshot (s, uc0, &snap0);
      hsi_udp_track_snapshot (peer_s, uc1, &snap1);

      hsi_udp_track_commit (s, &snap1);
      hsi_udp_track_commit (peer_s, &snap0);

      return 0;
    }

  hsi_udp_track_snapshot (s, uc0, &snap0);
  hsi_udp_track_snapshot (peer_s, uc1, &snap1);

  if (hsi_udp_track_send_commit (peer_s, &snap0))
    return -1;

  hsi_udp_track_commit (s, &snap1);

  return 0;
}

static int
hsi_track_session_pair_is_possible (session_t *s, session_t *peer_s)
{
  transport_proto_t proto;

  if (!hsi_track_sessions_compatible (s, peer_s))
    return 0;

  proto = session_get_transport_proto (s);
  switch (proto)
    {
    case TRANSPORT_PROTO_TCP:
      return hsi_tcp_track_is_possible (hsi_tcp_connection_at_session (s),
					hsi_tcp_connection_at_session (peer_s));
    case TRANSPORT_PROTO_UDP:
      return hsi_udp_track_is_possible (hsi_udp_connection_at_session (s),
					hsi_udp_connection_at_session (peer_s)) &&
	     !hsi_udp_track_needs_drain (s) && !hsi_udp_track_needs_drain (peer_s);
    default:
      return 0;
    }
}

static int
hsi_track_session_pair_do (session_t *s, session_t *peer_s)
{
  transport_proto_t proto;

  if (!hsi_track_sessions_compatible (s, peer_s))
    return -1;

  proto = session_get_transport_proto (s);
  switch (proto)
    {
    case TRANSPORT_PROTO_TCP:
      return hsi_tcp_track_session_pair (s, peer_s);
    case TRANSPORT_PROTO_UDP:
      return hsi_udp_track_session_pair (s, peer_s);
    default:
      return -1;
    }
}

static void
hsi_track_session_pair_rpc (void *arg)
{
  hsi_track_session_pair_req_t *a = arg;
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_handle_tu_t peer_sh = { .handle = a->peer_session_handle };
  session_t *s, *peer_s;
  int rv;

  s = session_get_from_handle_if_valid (sh);
  peer_s = session_get_from_handle_safe (peer_sh);
  if (!s || s->thread_index != vlib_get_thread_index () || !peer_s)
    {
      clib_mem_free (a);
      return;
    }

  rv = hsi_track_session_pair_do (s, peer_s);
  ASSERT (rv == 0);
  clib_mem_free (a);
}

__clib_export int
hsi_track_session_pair (session_t *s, session_handle_t peer_session_handle)
{
  session_handle_tu_t peer_handle = { .handle = peer_session_handle };
  hsi_track_session_pair_req_t *a;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  session_t *peer_s;

  if (!s || peer_session_handle == SESSION_INVALID_HANDLE)
    return -1;

  if (thread_index != s->thread_index)
    return -1;

  peer_s = session_get_from_handle_safe (peer_handle);
  if (!hsi_track_session_pair_is_possible (s, peer_s))
    return -1;

  if (session_get_transport_proto (s) == TRANSPORT_PROTO_UDP)
    return hsi_udp_track_session_pair (s, peer_s);

  a = clib_mem_alloc (sizeof (*a));
  clib_memset (a, 0, sizeof (*a));
  a->session_handle = session_handle (s);
  a->peer_session_handle = peer_session_handle;
  session_send_rpc_evt_to_thread_force (s->thread_index, hsi_track_session_pair_rpc, a);

  return 0;
}

static_always_inline int
hsi_tcp_session_is_cleanup_ready (session_t *s)
{
  tcp_connection_t *tc = hsi_tcp_connection_at_session (s);

  return (tc->cfg_flags & TCP_CFG_F_TRACKED) && tc->state == TCP_STATE_CLOSED;
}

static_always_inline int
hsi_udp_session_is_cleanup_ready (session_t *s)
{
  udp_connection_t *uc = hsi_udp_connection_at_session (s);

  return uc->cfg_flags & UDP_CFG_F_TRACKED;
}

static_always_inline int
hsi_session_is_cleanup_ready (session_t *s)
{
  switch (session_get_transport_proto (s))
    {
    case TRANSPORT_PROTO_TCP:
      return hsi_tcp_session_is_cleanup_ready (s);
    case TRANSPORT_PROTO_UDP:
      return hsi_udp_session_is_cleanup_ready (s);
    default:
      return 0;
    }
}

static void
hsi_session_cleanup (session_t *s)
{
  ASSERT (s->thread_index == vlib_get_thread_index ());

  if (!hsi_session_is_cleanup_ready (s))
    return;

  if (session_get_transport_proto (s) == TRANSPORT_PROTO_TCP)
    hsi_tcp_drain_stop (hsi_tcp_connection_at_session (s));
  else
    hsi_udp_track_peer_unset (s);

  session_transport_cleanup (s);
}

static void
hsi_session_cleanup_rpc (void *arg)
{
  session_handle_tu_t sh = { .handle = pointer_to_uword (arg) };
  session_t *s;

  s = session_get_from_handle_if_valid (sh);
  if (s)
    hsi_session_cleanup (s);
}

static void
hsi_session_send_cleanup (session_handle_t session_handle)
{
  session_handle_tu_t sh = { .handle = session_handle };

  session_send_rpc_evt_to_thread_force (sh.thread_index, hsi_session_cleanup_rpc,
					uword_to_pointer (session_handle, void *));
}

static_always_inline void
hsi_tcp_track_schedule_cleanup_pair (tcp_connection_t *tc, hsi_tcp_tracker_t *trk)
{
  session_handle_tu_t peer_sh = { .handle = trk->peer_session_handle };
  hsi_tcp_tracker_t *peer_trk;
  tcp_connection_t *peer_tc;
  session_t *peer_s;

  ASSERT (trk->peer_session_handle != SESSION_INVALID_HANDLE);

  if (trk->flags & HSI_TRACKER_F_CLEANUP_PENDING)
    return;

  peer_s = session_get_from_handle_safe (peer_sh);
  if (peer_s)
    {
      peer_tc = hsi_tcp_connection_at_session (peer_s);
      if ((peer_tc->cfg_flags & TCP_CFG_F_TRACKED) && peer_tc->state == TCP_STATE_CLOSED)
	{
	  peer_trk = hsi_tcp_tracker_from_connection (peer_tc);
	  if (peer_trk->flags & HSI_TRACKER_F_CLEANUP_PENDING)
	    {
	      trk->flags |= HSI_TRACKER_F_CLEANUP_PENDING;
	      return;
	    }
	  peer_trk->flags |= HSI_TRACKER_F_CLEANUP_PENDING;
	}
    }

  trk->flags |= HSI_TRACKER_F_CLEANUP_PENDING;
  hsi_session_send_cleanup (trk->peer_session_handle);
  hsi_session_send_cleanup (session_make_handle (tc->c_s_index, tc->c_thread_index));
}

static_always_inline u8
hsi_tcp_tracker_fin_done (hsi_tcp_tracker_t *trk)
{
  return (trk->flags & HSI_TRACKER_F_FIN_DONE) == HSI_TRACKER_F_FIN_DONE;
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
  if (!(peer_tc->cfg_flags & TCP_CFG_F_TRACKED) || peer_tc->state != TCP_STATE_CLOSED)
    return;

  peer_trk = hsi_tcp_tracker_from_connection (peer_tc);
  if (!hsi_tcp_tracker_fin_done (peer_trk))
    return;

  hsi_tcp_track_schedule_cleanup_pair (tc, trk);
}

static void
hsi_tcp_mark_fin_acked (tcp_connection_t *tc, u32 ack)
{
  hsi_tcp_tracker_t *trk;

  if (!(tc->cfg_flags & TCP_CFG_F_TRACKED) || tc->state != TCP_STATE_CLOSED)
    return;

  trk = hsi_tcp_tracker_get (tc);
  if ((trk->flags & HSI_TRACKER_F_FIN_RCVD) && seq_geq (ack, tc->rcv_nxt))
    trk->flags |= HSI_TRACKER_F_FIN_ACKED;

  hsi_tcp_track_maybe_cleanup_pair (tc, trk);
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

  clib_mem_free (a);
}

static void
hsi_tcp_send_fin_acked (session_t *s, u32 ack)
{
  hsi_tcp_fin_ack_req_t *a;

  a = clib_mem_alloc (sizeof (*a));
  clib_memset (a, 0, sizeof (*a));

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
hsi_tcp_track_pending_peer_fin_ack (hsi_tcp_tracker_t *trk, u32 ack)
{
  if (!(trk->flags & HSI_TRACKER_F_PEER_FIN_PENDING))
    return;

  if (seq_lt (ack, trk->peer_fin_ack))
    return;

  trk->flags &= ~HSI_TRACKER_F_PEER_FIN_PENDING;
  hsi_tcp_track_peer_fin_acked (trk, ack);
}

static void
hsi_tcp_mark_peer_fin_pending (tcp_connection_t *tc, u32 ack)
{
  hsi_tcp_tracker_t *trk;

  if (!(tc->cfg_flags & TCP_CFG_F_TRACKED) || tc->state != TCP_STATE_CLOSED)
    return;

  trk = hsi_tcp_tracker_get (tc);
  trk->peer_fin_ack = ack - trk->ack_delta;
  trk->flags |= HSI_TRACKER_F_PEER_FIN_PENDING;

  hsi_tcp_track_pending_peer_fin_ack (trk, tc->snd_una);
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

  clib_mem_free (a);
}

static void
hsi_tcp_send_peer_fin_pending (session_t *s, u32 ack)
{
  hsi_tcp_peer_fin_req_t *a;

  a = clib_mem_alloc (sizeof (*a));
  clib_memset (a, 0, sizeof (*a));

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

  if (tcp_ack (tcp_hdr) && !rst)
    hsi_tcp_track_pending_peer_fin_ack (trk, ack);

  if (fin && !rst && !fin_seen)
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
      ip4->checksum = ip4_header_checksum (ip4);
      tcp_hdr->checksum = 0;
      tcp_hdr->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
      b->flags |= VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP6;
      vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
					    VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      int bogus = 0;

      ip6->src_address = trk->tx_lcl_ip.ip6;
      ip6->dst_address = trk->tx_rmt_ip.ip6;
      tcp_hdr->checksum = 0;
      tcp_hdr->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
      b->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP4;
      vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_TCP_CKSUM);
    }

  trk->packets += 1;
  trk->bytes += vlib_buffer_length_in_chain (vm, b);

  if (PREDICT_FALSE (rst))
    hsi_tcp_track_schedule_cleanup_pair (tc, trk);
  else
    hsi_tcp_track_maybe_cleanup_pair (tc, trk);

  return HSI_TCP_TRACKED_ACTION_FORWARD;
}

void
hsi_udp_handle_tracked_connection (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc,
				   void *ip_hdr, udp_header_t *udp_hdr, u8 is_ip4)
{
  hsi_udp_tracker_t *trk;

  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  trk = hsi_udp_tracker_get (uc);

  udp_hdr->src_port = trk->tx_lcl_port;
  udp_hdr->dst_port = trk->tx_rmt_port;
  vnet_buffer (b)->ip.fib_index = trk->tx_fib_index;
  vnet_buffer (b)->l3_hdr_offset = b->current_data;
  vnet_buffer (b)->l4_hdr_offset = (u8 *) udp_hdr - b->data;

  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;

      ip4->src_address = trk->tx_lcl_ip.ip4;
      ip4->dst_address = trk->tx_rmt_ip.ip4;
      ip4->checksum = ip4_header_checksum (ip4);
      udp_hdr->checksum = 0;
      udp_hdr->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
      if (udp_hdr->checksum == 0)
	udp_hdr->checksum = 0xffff;
      b->flags |= VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP6;
      vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
					    VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      int bogus = 0;

      ip6->src_address = trk->tx_lcl_ip.ip6;
      ip6->dst_address = trk->tx_rmt_ip.ip6;
      udp_hdr->checksum = 0;
      udp_hdr->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
      if (udp_hdr->checksum == 0)
	udp_hdr->checksum = 0xffff;
      b->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP4;
      vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
    }
}
