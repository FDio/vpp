/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <hsi/hsi_tracker_private.h>
#include <vnet/ip/ip4.h>
#include <vnet/ip/ip6.h>
#include <vnet/session/session_lookup.h>
#include <vnet/session/transport.h>

int
hsi_udp_session_is_cleanup_ready (session_t *s)
{
  udp_connection_t *uc = hsi_udp_connection_at_session (s);

  return uc->cfg_flags & UDP_CFG_F_TRACKED;
}

session_handle_t
hsi_udp_session_cleanup_peer_handle (session_t *s)
{
  hsi_worker_t *wrk = hsi_worker_get (s->thread_index);
  hsi_udp_drain_t *drain;
  uword *p;

  drain = hsi_udp_drain_get (s->thread_index, hsi_session_conn_key_from_session (s));
  if (drain)
    return drain->peer_session_handle;

  p = hash_get (wrk->udp_track_peer_by_session_conn, hsi_session_conn_key_from_session (s));
  if (p)
    return p[0];

  return hsi_udp_connection_peer_handle (hsi_udp_connection_at_session (s));
}

static void
hsi_udp_drain_unregister_time_update_rpc (void *arg)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  wrk->udp_drain_time_unregister_pending = 0;
  if (!wrk->udp_drain_time_registered || pool_elts (wrk->udp_drains))
    return;

  session_register_update_time_fn_w_thread (hsi_udp_drain_update_time, 0, thread_index);
  wrk->udp_drain_time_registered = 0;
  vec_reset_length (wrk->udp_drain_update_handles);
}

static void
hsi_udp_drain_register_time_update_rpc (void *arg)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  if (wrk->udp_drain_time_registered || !pool_elts (wrk->udp_drains))
    return;

  session_register_update_time_fn_w_thread (hsi_udp_drain_update_time, 1, thread_index);
  wrk->udp_drain_time_registered = 1;
}

static void
hsi_udp_idle_unregister_time_update_rpc (void *arg)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  wrk->udp_idle_time_unregister_pending = 0;
  if (!wrk->udp_idle_time_registered || hsi_main.udp_idle_timeout > 0 ||
      hash_elts (wrk->udp_idle_by_session_conn))
    return;

  session_register_update_time_fn_w_thread (hsi_udp_idle_update_time, 0, thread_index);
  wrk->udp_idle_time_registered = 0;
  vec_reset_length (wrk->udp_idle_update_keys);
}

static void
hsi_udp_idle_register_time_update_rpc (void *arg)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  if (wrk->udp_idle_time_registered || hsi_main.udp_idle_timeout <= 0 ||
      !hash_elts (wrk->udp_idle_by_session_conn))
    return;

  session_register_update_time_fn_w_thread (hsi_udp_idle_update_time, 1, thread_index);
  wrk->udp_idle_time_registered = 1;
}

static_always_inline void
hsi_udp_drain_maybe_register_time_update (clib_thread_index_t thread_index)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  wrk->udp_drain_time_unregister_pending = 0;
  if (wrk->udp_drain_time_registered)
    return;

  session_send_rpc_evt_to_thread_force (thread_index, hsi_udp_drain_register_time_update_rpc, 0);
}

static_always_inline void
hsi_udp_drain_maybe_unregister_time_update (clib_thread_index_t thread_index)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  if (!wrk->udp_drain_time_registered || wrk->udp_drain_time_unregister_pending ||
      pool_elts (wrk->udp_drains))
    return;

  /* Defer unregister so the session update-time vector is not mutated while
   * session code is iterating it. */
  wrk->udp_drain_time_unregister_pending = 1;
  session_send_rpc_evt_to_thread_force (thread_index, hsi_udp_drain_unregister_time_update_rpc, 0);
}

static_always_inline void
hsi_udp_idle_maybe_register_time_update (clib_thread_index_t thread_index)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  if (hsi_main.udp_idle_timeout <= 0)
    return;

  wrk->udp_idle_time_unregister_pending = 0;
  if (wrk->udp_idle_time_registered)
    return;

  session_send_rpc_evt_to_thread_force (thread_index, hsi_udp_idle_register_time_update_rpc, 0);
}

static_always_inline void
hsi_udp_idle_maybe_unregister_time_update (clib_thread_index_t thread_index)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  if (!wrk->udp_idle_time_registered || wrk->udp_idle_time_unregister_pending ||
      hsi_main.udp_idle_timeout > 0 || hash_elts (wrk->udp_idle_by_session_conn))
    return;

  wrk->udp_idle_time_unregister_pending = 1;
  session_send_rpc_evt_to_thread_force (thread_index, hsi_udp_idle_unregister_time_update_rpc, 0);
}

static void
hsi_udp_idle_timeout_update_rpc (void *arg)
{
  hsi_worker_t *wrk;
  clib_thread_index_t thread_index = vlib_get_thread_index ();

  wrk = hsi_worker_get (thread_index);
  if (hsi_main.udp_idle_timeout > 0 && hash_elts (wrk->udp_idle_by_session_conn))
    hsi_udp_idle_maybe_register_time_update (thread_index);
  else
    hsi_udp_idle_maybe_unregister_time_update (thread_index);
}

void
hsi_udp_idle_timeout_update (void)
{
  hsi_worker_t *wrk;
  u32 i;

  vec_foreach_index (i, hsi_main.wrk)
    {
      wrk = vec_elt_at_index (hsi_main.wrk, i);
      if (hash_elts (wrk->udp_idle_by_session_conn) || wrk->udp_idle_time_registered)
	session_send_rpc_evt_to_thread_force (i, hsi_udp_idle_timeout_update_rpc, 0);
    }
}
static void
hsi_udp_drain_stop (udp_connection_t *uc)
{
  hsi_udp_drain_t *drain;
  hsi_worker_t *wrk;
  u32 n_dropped;
  u32 drain_index;
  uword key;

  key = hsi_udp_session_conn_key_from_connection (uc);
  drain_index = hsi_udp_drain_index_get (uc->c_thread_index, key);
  if (drain_index == HSI_UDP_DRAIN_INDEX_INVALID)
    return;

  wrk = hsi_worker_get (uc->c_thread_index);
  drain = pool_elt_at_index (wrk->udp_drains, drain_index);
  n_dropped = hsi_drain_drop_cached_buffers (vlib_get_main_by_index (uc->c_thread_index),
					     &drain->cached_buffers, &drain->cached_bytes);
  hsi_worker_counter_add (wrk, udp_drain_cache_dropped, n_dropped);

  hash_unset (wrk->udp_drain_by_session_conn, key);
  hsi_udp_drain_pool_put_index (wrk, drain_index);
  hsi_udp_drain_maybe_unregister_time_update (uc->c_thread_index);
}

static_always_inline void
hsi_udp_idle_touch (udp_connection_t *uc, f64 time_now)
{
  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  uc->start_ts = time_now;
}

static_always_inline void
hsi_udp_idle_add (udp_connection_t *uc, f64 time_now)
{
  hsi_worker_t *wrk = hsi_worker_get (uc->c_thread_index);

  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  hsi_udp_idle_touch (uc, time_now);
  hash_set (wrk->udp_idle_by_session_conn, hsi_udp_session_conn_key_from_connection (uc),
	    HSI_UDP_IDLE_STATE_ACTIVE);
  hsi_udp_idle_maybe_register_time_update (uc->c_thread_index);
}

static_always_inline void
hsi_udp_idle_del (udp_connection_t *uc)
{
  hsi_worker_t *wrk = hsi_worker_get (uc->c_thread_index);

  hash_unset (wrk->udp_idle_by_session_conn, hsi_udp_session_conn_key_from_connection (uc));
  hsi_udp_idle_maybe_unregister_time_update (uc->c_thread_index);
}

static_always_inline void
hsi_udp_track_peer_set (session_t *s, session_handle_t peer_handle)
{
  hsi_worker_t *wrk = hsi_worker_get (s->thread_index);

  hash_set (wrk->udp_track_peer_by_session_conn, hsi_session_conn_key_from_session (s),
	    peer_handle);
}

static u8
hsi_udp_track_peer_update (session_handle_t session_handle, session_handle_t peer_handle)
{
  session_handle_tu_t sh = { .handle = session_handle };
  session_t *s;
  udp_connection_t *uc;

  s = session_get_from_handle_if_valid (sh);
  if (!s)
    return 0;

  if (session_get_transport_proto (s) != TRANSPORT_PROTO_UDP)
    return 0;

  uc = hsi_udp_connection_at_session (s);
  if (!(uc->cfg_flags & UDP_CFG_F_TRACKED))
    return 0;

  hsi_udp_track_peer_set (s, peer_handle);
  if (!hsi_udp_drain_get (s->thread_index, hsi_session_conn_key_from_session (s)))
    hsi_udp_connection_peer_handle_set (uc, peer_handle);
  return 1;
}

static void
hsi_udp_peer_update_req_free_rpc (void *arg)
{
  hsi_udp_peer_update_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->udp_peer_update_reqs, a);
}

static void
hsi_udp_peer_update_rpc (void *arg)
{
  hsi_udp_peer_update_req_t *a = arg;

  if (!hsi_udp_track_peer_update (a->session_handle, a->peer_session_handle))
    {
      hsi_worker_counter_inc (hsi_worker_get (vlib_get_thread_index ()), udp_track_peer_rpc_failed);
      hsi_session_send_cleanup_pair (a->session_handle);
      hsi_session_send_cleanup_pair (a->peer_session_handle);
    }
  session_send_rpc_evt_to_thread (a->owner_thread, hsi_udp_peer_update_req_free_rpc, a);
}

static void
hsi_udp_track_peer_update_on_thread (session_handle_t session_handle,
				     session_handle_t peer_session_handle)
{
  session_handle_tu_t sh = { .handle = session_handle };
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_udp_peer_update_req_t *a;
  hsi_worker_t *wrk;

  if (sh.thread_index == thread_index)
    {
      hsi_udp_track_peer_update (session_handle, peer_session_handle);
      return;
    }

  wrk = hsi_worker_get (thread_index);
  pool_get_zero (wrk->udp_peer_update_reqs, a);
  a->owner_thread = thread_index;
  a->session_handle = session_handle;
  a->peer_session_handle = peer_session_handle;
  session_send_rpc_evt_to_thread (sh.thread_index, hsi_udp_peer_update_rpc, a);
}

static_always_inline void
hsi_udp_track_peer_unset (session_t *s)
{
  hsi_worker_t *wrk = hsi_worker_get (s->thread_index);

  hash_unset (wrk->udp_track_peer_by_session_conn, hsi_session_conn_key_from_session (s));
}

static void
hsi_udp_migrated_session_cleanup_rpc (void *arg)
{
  session_handle_tu_t sh = { .handle = pointer_to_uword (arg) };
  udp_connection_t *uc;
  session_t *s;

  s = session_get_from_handle_if_valid (sh);
  if (!s)
    return;

  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (session_get_transport_proto (s) == TRANSPORT_PROTO_UDP);
  ASSERT (!s->rx_fifo && !s->tx_fifo);

  uc = hsi_udp_connection_at_session (s);
  ASSERT (uc->flags & UDP_CONN_F_MIGRATED);
  hsi_udp_idle_del (uc);
  hsi_udp_track_peer_unset (s);
  transport_cleanup (TRANSPORT_PROTO_UDP, s->connection_index, s->thread_index);
  session_free (s);
}

udp_connection_t *
hsi_udp_migrate_tracked_connection (session_t **ps, udp_connection_t *uc)
{
  clib_thread_index_t old_thread, thread_index;
  session_handle_t old_handle, peer_handle, new_handle;
  udp_connection_t *new_uc;
  session_t *s, *new_s;

  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);

  thread_index = vlib_get_thread_index ();
  old_thread = uc->c_thread_index;
  if (old_thread == thread_index)
    return uc;

  if (hsi_udp_drain_get (old_thread, hsi_udp_session_conn_key_from_connection (uc)))
    {
      hsi_worker_counter_inc (hsi_worker_get (thread_index), udp_track_migration_failed);
      return 0;
    }

  s = *ps;
  old_handle = session_handle (s);
  peer_handle = hsi_udp_connection_peer_handle (uc);
  if (peer_handle == SESSION_INVALID_HANDLE)
    {
      hsi_worker_counter_inc (hsi_worker_get (thread_index), udp_track_migration_failed);
      return 0;
    }

  new_uc = udp_connection_clone_safe (s->connection_index, old_thread);
  new_s = session_clone_safe (s->session_index, old_thread);

  new_s->connection_index = new_uc->c_c_index;
  new_s->session_state = SESSION_STATE_TRANSPORT_CLOSED;
  new_s->app_wrk_index = APP_INVALID_INDEX;
  new_s->rx_fifo = 0;
  new_s->tx_fifo = 0;
  new_s->flags &= ~SESSION_F_IS_MIGRATING;

  new_uc->c_s_index = new_s->session_index;
  new_handle = session_handle (new_s);
  hsi_udp_track_peer_set (new_s, peer_handle);
  hsi_udp_connection_peer_handle_set (new_uc, peer_handle);
  hsi_udp_idle_add (new_uc, vlib_time_now (vlib_get_main ()));

  if (session_lookup_add_connection (&new_uc->connection, new_handle))
    {
      uc->flags &= ~UDP_CONN_F_MIGRATED;
      hsi_udp_idle_del (new_uc);
      hsi_udp_track_peer_unset (new_s);
      udp_connection_free (new_uc);
      session_free (new_s);
      hsi_worker_counter_inc (hsi_worker_get (thread_index), udp_track_migration_failed);
      return 0;
    }

  hsi_udp_track_peer_update_on_thread (peer_handle, new_handle);
  session_send_rpc_evt_to_thread_force (old_thread, hsi_udp_migrated_session_cleanup_rpc,
					uword_to_pointer (old_handle, void *));
  hsi_worker_counter_inc (hsi_worker_get (thread_index), udp_track_migrated);

  *ps = new_s;
  return new_uc;
}
void
hsi_udp_session_cleanup_state (session_t *s)
{
  udp_connection_t *uc = hsi_udp_connection_at_session (s);

  hsi_udp_drain_stop (uc);
  hsi_udp_idle_del (uc);
  hsi_udp_track_peer_unset (s);
}

static_always_inline u8
hsi_udp_idle_cleanup_try_lock (session_t *s)
{
  hsi_worker_t *wrk = hsi_worker_get (s->thread_index);
  uword key, *p;

  key = hsi_session_conn_key_from_session (s);
  p = hash_get (wrk->udp_idle_by_session_conn, key);
  if (!p || p[0] == HSI_UDP_IDLE_STATE_CLEANUP_PENDING)
    return 0;

  hash_set (wrk->udp_idle_by_session_conn, key, HSI_UDP_IDLE_STATE_CLEANUP_PENDING);
  return 1;
}

static_always_inline void
hsi_udp_idle_cleanup_mark_pending (session_t *s)
{
  hsi_worker_t *wrk = hsi_worker_get (s->thread_index);
  uword key;

  key = hsi_session_conn_key_from_session (s);
  if (hash_get (wrk->udp_idle_by_session_conn, key))
    hash_set (wrk->udp_idle_by_session_conn, key, HSI_UDP_IDLE_STATE_CLEANUP_PENDING);
}

static_always_inline void
hsi_udp_idle_schedule_cleanup_pair (session_t *s, session_t *peer_s)
{
  hsi_worker_t *wrk;

  if (!hsi_udp_idle_cleanup_try_lock (s))
    return;

  if (peer_s && peer_s->thread_index == s->thread_index)
    hsi_udp_idle_cleanup_mark_pending (peer_s);

  wrk = hsi_worker_get (s->thread_index);
  hsi_worker_counter_inc (wrk, udp_idle_timeout);
  hsi_worker_counter_inc (wrk, udp_idle_cleanup_scheduled);
  hsi_session_send_cleanup_pair (session_handle (s));
}

void
hsi_udp_idle_update_time (f64 time_now, u8 thread_index)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);
  hash_pair_t *hp;
  uword *keyp, *keys;

  if (hsi_main.udp_idle_timeout <= 0 || !hash_elts (wrk->udp_idle_by_session_conn))
    {
      hsi_udp_idle_maybe_unregister_time_update (thread_index);
      return;
    }

  keys = wrk->udp_idle_update_keys;
  vec_reset_length (keys);
  hash_foreach_pair (hp, wrk->udp_idle_by_session_conn, ({ vec_add1 (keys, hp->key); }));
  wrk->udp_idle_update_keys = keys;

  vec_foreach (keyp, keys)
    {
      session_handle_tu_t sh = {
	.handle = session_make_handle (hsi_session_conn_key_session_index (*keyp), thread_index),
      };
      session_handle_t local_handle, peer_handle;
      udp_connection_t *uc, *peer_uc = 0;
      session_t *s, *peer_s = 0;
      f64 last_activity;
      uword *state;

      state = hash_get (wrk->udp_idle_by_session_conn, *keyp);
      if (!state || state[0] == HSI_UDP_IDLE_STATE_CLEANUP_PENDING)
	continue;

      s = session_get_from_handle_if_valid (sh);
      if (!s || s->connection_index != hsi_session_conn_key_conn_index (*keyp))
	{
	  hash_unset (wrk->udp_idle_by_session_conn, *keyp);
	  continue;
	}

      uc = hsi_udp_connection_at_session (s);
      if (!(uc->cfg_flags & UDP_CFG_F_TRACKED))
	{
	  hash_unset (wrk->udp_idle_by_session_conn, *keyp);
	  continue;
	}
      if (uc->flags & UDP_CONN_F_MIGRATED)
	{
	  hash_unset (wrk->udp_idle_by_session_conn, *keyp);
	  continue;
	}

      peer_handle = hsi_udp_connection_peer_handle (uc);
      local_handle = session_handle (s);
      if (peer_handle != SESSION_INVALID_HANDLE)
	{
	  session_handle_tu_t peer_sh = { .handle = peer_handle };

	  if (peer_handle < local_handle)
	    continue;

	  peer_s = hsi_session_peer_get_if_valid (peer_sh);
	  if (peer_s && session_get_transport_proto (peer_s) == TRANSPORT_PROTO_UDP)
	    {
	      peer_uc = hsi_udp_connection_at_session (peer_s);
	      if (!(peer_uc->cfg_flags & UDP_CFG_F_TRACKED))
		{
		  peer_s = 0;
		  peer_uc = 0;
		}
	    }
	}

      last_activity = uc->start_ts;
      if (peer_uc)
	last_activity = clib_max (last_activity, peer_uc->start_ts);

      if (time_now - last_activity < hsi_main.udp_idle_timeout)
	continue;

      hsi_udp_idle_schedule_cleanup_pair (s, peer_s);
    }

  hsi_udp_idle_maybe_unregister_time_update (thread_index);
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
  u32 rx_deq, tx_deq;

  hsi_drain_sample_fifos (s, &rx_deq, &tx_deq);
  return rx_deq || tx_deq;
}

static_always_inline int
hsi_udp_peer_needs_drain_safe (session_t *s)
{
  if (!s->rx_fifo && !s->tx_fifo)
    return 0;
  if (!s->rx_fifo || !s->tx_fifo)
    return -1;

  return hsi_udp_track_needs_drain (s);
}

static_always_inline void
hsi_udp_drain_sample (session_t *s, hsi_udp_drain_t *drain)
{
  hsi_drain_sample_fifos (s, &drain->rx_deq, &drain->tx_deq);
}

static_always_inline int
hsi_udp_drain_sample_needs_drain (hsi_udp_drain_t *drain)
{
  return drain->rx_deq || drain->tx_deq;
}

static_always_inline u8
hsi_udp_drain_sample_changed (hsi_udp_drain_t *drain, hsi_udp_drain_t *sample)
{
  return drain->rx_deq != sample->rx_deq || drain->tx_deq != sample->tx_deq;
}

static int
hsi_udp_drain_update_and_needs_drain (session_t *s, hsi_udp_drain_t *drain, f64 now)
{
  hsi_udp_drain_t sample = {};
  int needs_drain;

  hsi_udp_drain_sample (s, &sample);

  if (hsi_udp_drain_sample_changed (drain, &sample))
    {
      drain->rx_deq = sample.rx_deq;
      drain->tx_deq = sample.tx_deq;
      drain->last_progress_time = now;
      drain->stalled = 0;
    }

  needs_drain = hsi_udp_drain_sample_needs_drain (&sample);
  if (needs_drain && !drain->stalled &&
      now - drain->last_progress_time > hsi_main.udp_drain_no_progress_timeout)
    {
      hsi_worker_counter_inc (hsi_worker_get (drain->thread_index), udp_drain_stalled);
      drain->stalled = 1;
      drain->state = HSI_UDP_DRAIN_STATE_FAILED;
      return -1;
    }

  return needs_drain;
}

static void
hsi_udp_drain_fail_pair (hsi_udp_drain_t *drain)
{
  if (drain->cleanup_pending)
    return;

  drain->state = HSI_UDP_DRAIN_STATE_FAILED;
  drain->cleanup_pending = 1;
  hsi_session_send_cleanup_pair (drain->session_handle);
}

static void
hsi_udp_enqueue_tracked_buffer (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc)
{
  u32 node_index, *to_next;
  vlib_frame_t *f;

  node_index = uc->c_is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index;
  f = vlib_get_frame_to_node (vm, node_index);
  to_next = vlib_frame_vector_args (f);
  to_next[0] = vlib_get_buffer_index (vm, b);
  f->n_vectors = 1;
  vlib_put_frame_to_node (vm, node_index, f);
}

static void
hsi_udp_drain_cache_req_free_rpc (void *arg)
{
  hsi_udp_drain_cache_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->udp_drain_cache_reqs, a);
}

static void
hsi_udp_drain_cache_rpc (void *arg)
{
  hsi_udp_drain_cache_req_t *a = arg;
  session_handle_tu_t sh = { .handle = a->session_handle };
  vlib_main_t *vm = vlib_get_main ();
  hsi_udp_drain_t *drain;
  udp_connection_t *uc;
  hsi_worker_t *wrk;
  udp_header_t *udp_hdr;
  session_t *s;
  void *ip_hdr;

  wrk = hsi_worker_get (vm->thread_index);
  s = session_get_from_handle_if_valid (sh);
  if (!s || session_get_transport_proto (s) != TRANSPORT_PROTO_UDP)
    goto drop;

  uc = hsi_udp_connection_at_session (s);
  if (!(uc->cfg_flags & UDP_CFG_F_TRACKED))
    goto drop;

  drain = hsi_udp_drain_get (uc->c_thread_index, hsi_udp_session_conn_key_from_connection (uc));
  if (!drain)
    {
      vlib_buffer_t *b = vlib_get_buffer (vm, a->buffer_index);

      ip_hdr = vlib_buffer_get_current (b);
      udp_hdr = uc->c_is_ip4 ? ip4_next_header ((ip4_header_t *) ip_hdr) :
			       ip6_next_header ((ip6_header_t *) ip_hdr);
      hsi_udp_handle_tracked_connection (vm, b, uc, ip_hdr, udp_hdr, uc->c_is_ip4);
      hsi_udp_enqueue_tracked_buffer (vm, b, uc);
      goto done;
    }

  if (PREDICT_FALSE (drain->state == HSI_UDP_DRAIN_STATE_FAILED))
    goto drop;

  if (PREDICT_FALSE (!hsi_drain_cache_has_room (drain->cached_buffers, drain->cached_bytes, a->len,
						hsi_main.udp_drain_cache_max_packets,
						HSI_UDP_DRAIN_CACHE_MAX_BYTES)))
    {
      hsi_worker_counter_inc (wrk, udp_drain_cache_overflow);
      hsi_udp_drain_fail_pair (drain);
      goto drop;
    }

  hsi_drain_cache_buffer (&drain->cached_buffers, &drain->cached_bytes, a->buffer_index, a->len);
  hsi_worker_counter_inc (wrk, udp_drain_cached);
  goto done;

drop:
  vlib_buffer_free_one (vm, a->buffer_index);
  hsi_worker_counter_inc (wrk, udp_drain_cache_dropped);

done:
  session_send_rpc_evt_to_thread (a->owner_thread, hsi_udp_drain_cache_req_free_rpc, a);
}

hsi_udp_tracked_action_t
hsi_udp_drain_cache_buffer_remote (vlib_main_t *vm, vlib_buffer_t *b, session_t *s,
				   udp_connection_t *uc, void *ip_hdr, udp_header_t *udp_hdr,
				   u8 is_ip4)
{
  hsi_udp_drain_cache_req_t *a;
  hsi_worker_t *wrk;
  u32 udp_len, len;

  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  ASSERT (uc->c_thread_index != vm->thread_index);

  udp_len = clib_net_to_host_u16 (udp_hdr->length);
  len = vlib_buffer_length_in_chain (vm, b);
  if (PREDICT_FALSE (udp_len < sizeof (udp_header_t) ||
		     (u32) ((u8 *) udp_hdr - (u8 *) ip_hdr) + udp_len > len))
    return HSI_UDP_TRACKED_ACTION_DROP;

  wrk = hsi_worker_get (vm->thread_index);
  pool_get_zero (wrk->udp_drain_cache_reqs, a);
  a->owner_thread = vm->thread_index;
  a->session_handle = session_handle (s);
  a->buffer_index = vlib_get_buffer_index (vm, b);
  a->len = len;

  session_send_rpc_evt_to_thread (uc->c_thread_index, hsi_udp_drain_cache_rpc, a);

  return HSI_UDP_TRACKED_ACTION_HELD;
}

hsi_udp_tracked_action_t
hsi_udp_drain_cache_buffer (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc, void *ip_hdr,
			    udp_header_t *udp_hdr, u8 is_ip4)
{
  hsi_udp_drain_t *drain;
  hsi_worker_t *wrk;
  u32 udp_len, len;
  uword key;

  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  ASSERT (uc->c_thread_index == vm->thread_index);

  key = hsi_udp_session_conn_key_from_connection (uc);
  drain = hsi_udp_drain_get (uc->c_thread_index, key);
  if (!drain)
    return HSI_UDP_TRACKED_ACTION_FORWARD;
  if (PREDICT_FALSE (drain->state == HSI_UDP_DRAIN_STATE_FAILED))
    return HSI_UDP_TRACKED_ACTION_DROP;

  wrk = hsi_worker_get (uc->c_thread_index);

  udp_len = clib_net_to_host_u16 (udp_hdr->length);
  len = vlib_buffer_length_in_chain (vm, b);
  if (PREDICT_FALSE (udp_len < sizeof (udp_header_t) ||
		     (u32) ((u8 *) udp_hdr - (u8 *) ip_hdr) + udp_len > len))
    goto drop;

  if (PREDICT_FALSE (!hsi_drain_cache_has_room (drain->cached_buffers, drain->cached_bytes, len,
						hsi_main.udp_drain_cache_max_packets,
						HSI_UDP_DRAIN_CACHE_MAX_BYTES)))
    {
      hsi_worker_counter_inc (wrk, udp_drain_cache_overflow);
      hsi_udp_drain_fail_pair (drain);
      goto drop;
    }

  hsi_drain_cache_buffer (&drain->cached_buffers, &drain->cached_bytes,
			  vlib_get_buffer_index (vm, b), len);

  hsi_worker_counter_inc (wrk, udp_drain_cached);

  return HSI_UDP_TRACKED_ACTION_HELD;

drop:
  hsi_worker_counter_inc (wrk, udp_drain_cache_dropped);
  return HSI_UDP_TRACKED_ACTION_DROP;
}

static hsi_udp_drain_t *
hsi_udp_drain_start (session_t *s, session_t *peer_s, udp_connection_t *uc,
		     udp_connection_t *peer_uc)
{
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_udp_drain_t *drain;
  hsi_worker_t *wrk;
  u32 drain_index;
  uword key;
  f64 now;

  ASSERT (s->thread_index == thread_index);

  key = hsi_session_conn_key_from_session (s);
  drain = hsi_udp_drain_get (thread_index, key);
  if (drain)
    return drain;

  wrk = hsi_worker_get (thread_index);
  drain = hsi_udp_drain_pool_get (wrk, &drain_index);
  hash_set (wrk->udp_drain_by_session_conn, key, drain_index);

  hsi_session_take_ownership (s);
  hsi_udp_track_peer_set (s, session_handle (peer_s));
  now = vlib_time_now (vlib_get_main ());

  drain->session_handle = session_handle (s);
  drain->peer_session_handle = session_handle (peer_s);
  drain->conn_index = uc->c_c_index;
  drain->peer_conn_index = peer_uc->c_c_index;
  drain->thread_index = thread_index;
  drain->peer_thread_index = peer_s->thread_index;
  drain->start_time = now;
  drain->last_progress_time = now;
  hsi_udp_drain_sample (s, drain);
  drain->state = HSI_UDP_DRAIN_STATE_DRAINING;
  uc->cfg_flags |= UDP_CFG_F_TRACKED;
  hsi_worker_counter_inc (wrk, udp_drain_started);
  hsi_udp_drain_maybe_register_time_update (thread_index);

  return drain;
}

static void
hsi_udp_drain_start_req_free_rpc (void *arg)
{
  hsi_udp_drain_start_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->udp_drain_start_reqs, a);
}

static void
hsi_udp_drain_start_rpc (void *arg)
{
  hsi_udp_drain_start_req_t *a = arg;
  session_handle_tu_t sh = { .handle = a->session_handle };
  session_handle_tu_t peer_sh = { .handle = a->peer_session_handle };
  session_t *s, *peer_s;
  udp_connection_t *uc, *peer_uc;

  s = session_get_from_handle_if_valid (sh);
  peer_s = session_get_from_handle_safe (peer_sh);
  if (!s || !peer_s)
    {
      hsi_worker_counter_inc (hsi_worker_get (vlib_get_thread_index ()), udp_track_peer_rpc_failed);
      hsi_session_send_cleanup_pair (a->session_handle);
      hsi_session_send_cleanup_pair (a->peer_session_handle);
      goto done;
    }

  ASSERT (hsi_track_sessions_compatible (s, peer_s));

  uc = hsi_udp_connection_at_session (s);
  peer_uc = hsi_udp_connection_at_session (peer_s);
  ASSERT (!(uc->cfg_flags & UDP_CFG_F_TRACKED));
  ASSERT (peer_uc->cfg_flags & UDP_CFG_F_TRACKED);
  ASSERT (hsi_udp_track_connections_compatible (uc, peer_uc));
  hsi_udp_drain_start (s, peer_s, uc, peer_uc);

done:
  session_send_rpc_evt_to_thread (a->owner_thread, hsi_udp_drain_start_req_free_rpc, a);
}

static int
hsi_udp_track_send_drain_start (session_t *s, session_t *peer_s)
{
  hsi_udp_drain_start_req_t *a;
  hsi_worker_t *wrk;
  clib_thread_index_t thread_index;

  thread_index = s->thread_index;
  ASSERT (thread_index == vlib_get_thread_index ());
  wrk = hsi_worker_get (thread_index);
  pool_get_zero (wrk->udp_drain_start_reqs, a);

  a->owner_thread = thread_index;
  a->session_handle = session_handle (peer_s);
  a->peer_session_handle = session_handle (s);
  session_send_rpc_evt_to_thread (peer_s->thread_index, hsi_udp_drain_start_rpc, a);

  return 0;
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
hsi_udp_drain_flush_cached_buffers (udp_connection_t *uc)
{
  hsi_udp_drain_t *drain;
  hsi_worker_t *wrk;
  vlib_main_t *vm;
  u32 *cached;
  uword key;
  u32 i;

  key = hsi_udp_session_conn_key_from_connection (uc);
  drain = hsi_udp_drain_get (uc->c_thread_index, key);
  if (!drain || !vec_len (drain->cached_buffers))
    return;

  vm = vlib_get_main_by_index (uc->c_thread_index);
  wrk = hsi_worker_get (uc->c_thread_index);
  cached = drain->cached_buffers;
  drain->cached_buffers = 0;
  drain->cached_bytes = 0;

  for (i = 0; i < vec_len (cached); i++)
    {
      udp_header_t *udp_hdr;
      vlib_buffer_t *b;
      void *ip_hdr;

      b = vlib_get_buffer (vm, cached[i]);
      ip_hdr = vlib_buffer_get_current (b);
      udp_hdr = uc->c_is_ip4 ? ip4_next_header ((ip4_header_t *) ip_hdr) :
			       ip6_next_header ((ip6_header_t *) ip_hdr);

      hsi_udp_handle_tracked_connection (vm, b, uc, ip_hdr, udp_hdr, uc->c_is_ip4);
    }

  hsi_drain_enqueue_cached_buffers (
    vm, uc->c_is_ip4 ? ip4_lookup_node.index : ip6_lookup_node.index, cached);
  hsi_worker_counter_add (wrk, udp_drain_cache_flushed, vec_len (cached));
  vec_free (cached);
}

static void
hsi_udp_track_commit_connection (udp_connection_t *uc, hsi_udp_track_snapshot_t *peer)
{
  hsi_worker_t *wrk = hsi_worker_get (uc->c_thread_index);

  hsi_udp_tracker_init (hsi_udp_tracker_from_connection (uc), peer);
  hsi_udp_connection_peer_handle_set (uc, peer->session_handle);

  uc->cfg_flags |= UDP_CFG_F_TRACKED;
  hsi_udp_idle_add (uc, vlib_time_now (vlib_get_main_by_index (uc->c_thread_index)));
  hsi_udp_drain_flush_cached_buffers (uc);
  if (hsi_udp_drain_get (uc->c_thread_index, hsi_udp_session_conn_key_from_connection (uc)))
    hsi_worker_counter_inc (wrk, udp_drain_completed);
  hsi_udp_drain_stop (uc);
}

static void
hsi_udp_track_commit (session_t *s, hsi_udp_track_snapshot_t *peer)
{
  udp_connection_t *uc;
  hsi_udp_drain_t *drain;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  uc = hsi_udp_connection_at_session (s);
  drain = hsi_udp_drain_get (uc->c_thread_index, hsi_udp_session_conn_key_from_connection (uc));
  if (!drain && s->session_state == SESSION_STATE_TRANSPORT_CLOSED)
    {
      ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
      return;
    }

  hsi_session_take_ownership (s);
  hsi_udp_track_peer_set (s, peer->session_handle);
  hsi_udp_track_commit_connection (uc, peer);
  s->session_state = SESSION_STATE_TRANSPORT_CLOSED;
  if (s->rx_fifo || s->tx_fifo)
    hsi_session_cleanup_fifos (s);
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
  else
    {
      hsi_worker_counter_inc (hsi_worker_get (vlib_get_thread_index ()), udp_track_peer_rpc_failed);
      hsi_session_send_cleanup_pair (a->session_handle);
      hsi_session_send_cleanup_pair (a->peer.session_handle);
    }
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
hsi_udp_drain_try_complete (session_t *s, udp_connection_t *uc, hsi_udp_drain_t *drain, f64 now)
{
  session_handle_tu_t peer_sh;
  hsi_udp_track_snapshot_t snap, peer_snap;
  udp_connection_t *peer_uc;
  hsi_udp_drain_t *peer_drain = 0;
  session_t *peer_s;
  int rv;

  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (uc->c_thread_index == vlib_get_thread_index ());

  if (!drain)
    return 1;
  if (drain->state == HSI_UDP_DRAIN_STATE_FAILED)
    {
      hsi_udp_drain_fail_pair (drain);
      return -1;
    }

  peer_sh.handle = drain->peer_session_handle;
  peer_s = hsi_session_peer_get_if_valid (peer_sh);
  if (!peer_s)
    {
      hsi_worker_counter_inc (hsi_worker_get (s->thread_index), udp_track_peer_rpc_failed);
      hsi_udp_drain_fail_pair (drain);
      return -1;
    }

  peer_uc = hsi_udp_connection_at_session (peer_s);
  if (!(peer_uc->cfg_flags & UDP_CFG_F_TRACKED))
    return 0;

  rv = hsi_udp_drain_update_and_needs_drain (s, drain, now);
  if (rv < 0)
    {
      hsi_udp_drain_fail_pair (drain);
      return -1;
    }
  if (rv)
    return 0;

  if (s->thread_index == peer_s->thread_index)
    {
      peer_drain = hsi_udp_drain_get (peer_uc->c_thread_index,
				      hsi_udp_session_conn_key_from_connection (peer_uc));
      if (peer_drain)
	{
	  if (peer_drain->state == HSI_UDP_DRAIN_STATE_FAILED)
	    return -1;
	  rv = hsi_udp_drain_update_and_needs_drain (peer_s, peer_drain, now);
	  if (rv < 0)
	    {
	      hsi_udp_drain_fail_pair (peer_drain);
	      return -1;
	    }
	  if (rv)
	    return 0;
	}
    }
  else
    {
      rv = hsi_udp_peer_needs_drain_safe (peer_s);
      if (rv < 0)
	{
	  hsi_udp_drain_fail_pair (drain);
	  return -1;
	}
      if (rv)
	return 0;
    }

  hsi_udp_track_snapshot (s, uc, &snap);
  hsi_udp_track_snapshot (peer_s, peer_uc, &peer_snap);

  if (s->thread_index == peer_s->thread_index)
    {
      hsi_udp_track_commit (s, &peer_snap);
      hsi_udp_track_commit (peer_s, &snap);
      return 1;
    }

  if (hsi_udp_track_send_commit (peer_s, &snap))
    return 0;

  hsi_udp_track_commit (s, &peer_snap);
  return 1;
}

int
hsi_udp_connection_is_draining (udp_connection_t *uc)
{
  return hsi_udp_drain_get (uc->c_thread_index, hsi_udp_session_conn_key_from_connection (uc)) != 0;
}

int
hsi_udp_try_complete_drain (vlib_main_t *vm, udp_connection_t *uc)
{
  session_handle_tu_t sh;
  hsi_udp_drain_t *drain;
  session_t *s;

  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  ASSERT (uc->c_thread_index == vm->thread_index);

  drain = hsi_udp_drain_get (uc->c_thread_index, hsi_udp_session_conn_key_from_connection (uc));
  if (!drain)
    return 1;

  sh.handle = drain->session_handle;
  s = session_get_from_handle_if_valid (sh);
  if (!s)
    {
      hsi_udp_drain_fail_pair (drain);
      return 0;
    }

  return hsi_udp_drain_try_complete (s, uc, drain, vlib_time_now (vm)) == 1;
}

void
hsi_udp_drain_update_time (f64 time_now, u8 thread_index)
{
  hsi_udp_drain_t *drain;
  session_handle_t *handles, *handle;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (thread_index);
  if (!pool_elts (wrk->udp_drains))
    {
      hsi_udp_drain_maybe_unregister_time_update (thread_index);
      return;
    }

  handles = wrk->udp_drain_update_handles;
  vec_reset_length (handles);
  pool_foreach (drain, wrk->udp_drains)
    {
      vec_add1 (handles, drain->session_handle);
    }
  wrk->udp_drain_update_handles = handles;

  vec_foreach (handle, handles)
    {
      session_handle_tu_t sh = { .handle = *handle };
      udp_connection_t *uc;
      session_t *s;

      s = session_get_from_handle_if_valid (sh);
      if (!s || s->thread_index != thread_index)
	continue;

      uc = hsi_udp_connection_at_session (s);
      if (!(uc->cfg_flags & UDP_CFG_F_TRACKED))
	continue;

      drain = hsi_udp_drain_get (thread_index, hsi_session_conn_key_from_session (s));
      if (drain)
	hsi_udp_drain_try_complete (s, uc, drain, time_now);
    }

  hsi_udp_drain_maybe_unregister_time_update (thread_index);
}

int
hsi_track_udp (session_t *s, session_t *peer_s)
{
  hsi_udp_track_snapshot_t snap0, snap1;
  udp_connection_t *uc0, *uc1;
  u8 is_same_thread;

  uc0 = hsi_udp_connection_at_session (s);
  uc1 = hsi_udp_connection_at_session (peer_s);
  is_same_thread = s->thread_index == peer_s->thread_index;

  if (!hsi_udp_track_is_possible (uc0, uc1))
    return -1;

  if (hsi_udp_track_needs_drain (s) || hsi_udp_track_needs_drain (peer_s))
    {
      hsi_udp_drain_start (s, peer_s, uc0, uc1);
      if (is_same_thread)
	hsi_udp_drain_start (peer_s, s, uc1, uc0);
      else if (hsi_udp_track_send_drain_start (s, peer_s))
	return -1;
      return 0;
    }

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
static const char *
hsi_udp_drain_state_name (hsi_udp_drain_state_t state)
{
  switch (state)
    {
    case HSI_UDP_DRAIN_STATE_DRAINING:
      return "draining";
    case HSI_UDP_DRAIN_STATE_READY:
      return "ready";
    case HSI_UDP_DRAIN_STATE_FAILED:
      return "failed";
    default:
      return "unknown";
    }
}

static const char *
hsi_udp_idle_state_name (hsi_udp_idle_state_t state)
{
  switch (state)
    {
    case HSI_UDP_IDLE_STATE_ACTIVE:
      return "active";
    case HSI_UDP_IDLE_STATE_CLEANUP_PENDING:
      return "cleanup-pending";
    default:
      return "unknown";
    }
}

void
hsi_tracker_show_udp (vlib_main_t *vm, u32 i, hsi_worker_t *wrk, f64 now)
{
  hsi_udp_drain_t *udp_drain;
  hash_pair_t *hp;

  if (pool_elts (wrk->udp_drains) || hash_elts (wrk->udp_idle_by_session_conn))
    vlib_cli_output (vm, "thread %u udp-drain-active %u udp-idle-active %u", i,
		     (u32) pool_elts (wrk->udp_drains),
		     (u32) hash_elts (wrk->udp_idle_by_session_conn));

  pool_foreach (udp_drain, wrk->udp_drains)
    {
      vlib_cli_output (vm,
		       "thread %u udp-drain session 0x%lx peer 0x%lx peer-thread %u "
		       "state %s cache %u/%u bytes %u age %.3f idle %.3f",
		       i, udp_drain->session_handle, udp_drain->peer_session_handle,
		       udp_drain->peer_thread_index, hsi_udp_drain_state_name (udp_drain->state),
		       vec_len (udp_drain->cached_buffers), hsi_main.udp_drain_cache_max_packets,
		       udp_drain->cached_bytes, now - udp_drain->start_time,
		       now - udp_drain->last_progress_time);
    }

  hash_foreach_pair (
    hp, wrk->udp_idle_by_session_conn, ({
      session_handle_tu_t sh = {
	.handle = session_make_handle (hsi_session_conn_key_session_index (hp->key), i),
      };
      udp_connection_t *uc;
      session_t *s;

      s = session_get_from_handle_if_valid (sh);
      if (s && s->connection_index == hsi_session_conn_key_conn_index (hp->key) &&
	  session_get_transport_proto (s) == TRANSPORT_PROTO_UDP)
	{
	  uc = hsi_udp_connection_at_session (s);
	  if (uc->cfg_flags & UDP_CFG_F_TRACKED)
	    vlib_cli_output (vm,
			     "thread %u udp-tracked session 0x%lx peer 0x%lx state %s "
			     "idle %.3f",
			     i, session_handle (s), hsi_udp_connection_peer_handle (uc),
			     hsi_udp_idle_state_name ((hsi_udp_idle_state_t) hp->value[0]),
			     now - uc->start_ts);
	}
    }));
}

static_always_inline void
hsi_udp_update_checksums (vlib_main_t *vm, vlib_buffer_t *b, void *ip_hdr, udp_header_t *udp_hdr,
			  u8 is_ip4, u8 csum_offload)
{
  vnet_buffer_offload_flags_clear (b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
					VNET_BUFFER_OFFLOAD_F_TCP_CKSUM |
					VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);

  udp_hdr->checksum = 0;
  if (is_ip4)
    {
      ip4_header_t *ip4 = (ip4_header_t *) ip_hdr;

      if (csum_offload)
	{
	  ip4->checksum = 0;
	  vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_IP_CKSUM |
					      VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
	}
      else
	{
	  ip4->checksum = ip4_header_checksum (ip4);
	  udp_hdr->checksum = ip4_tcp_udp_compute_checksum (vm, b, ip4);
	}
    }
  else if (csum_offload)
    vnet_buffer_offload_flags_set (b, VNET_BUFFER_OFFLOAD_F_UDP_CKSUM);
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;
      int bogus = 0;

      udp_hdr->checksum = ip6_tcp_udp_icmp_compute_checksum (vm, b, ip6, &bogus);
    }

  if (!csum_offload && udp_hdr->checksum == 0)
    udp_hdr->checksum = 0xffff;
}

void
hsi_udp_handle_tracked_connection (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc,
				   void *ip_hdr, udp_header_t *udp_hdr, u8 is_ip4)
{
  hsi_udp_tracker_t *trk;

  ASSERT (uc->cfg_flags & UDP_CFG_F_TRACKED);
  trk = hsi_udp_tracker_get (uc);
  hsi_udp_idle_touch (uc, vlib_time_now (vm));

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
      b->flags |= VNET_BUFFER_F_IS_IP4 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP6;
      hsi_udp_update_checksums (vm, b, ip4, udp_hdr, is_ip4, udp_csum_offload (uc));
    }
  else
    {
      ip6_header_t *ip6 = (ip6_header_t *) ip_hdr;

      ip6->src_address = trk->tx_lcl_ip.ip6;
      ip6->dst_address = trk->tx_rmt_ip.ip6;
      b->flags |= VNET_BUFFER_F_IS_IP6 | VNET_BUFFER_F_L3_HDR_OFFSET_VALID |
		  VNET_BUFFER_F_L4_HDR_OFFSET_VALID;
      b->flags &= ~VNET_BUFFER_F_IS_IP4;
      hsi_udp_update_checksums (vm, b, ip6, udp_hdr, is_ip4, udp_csum_offload (uc));
    }
}
