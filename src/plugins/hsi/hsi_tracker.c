/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <hsi/hsi_tracker_private.h>
#include <vnet/session/segment_manager.h>
#include <vnet/session/session_lookup.h>
#include <vnet/session/transport.h>

static_always_inline void
hsi_session_free (session_t *s)
{
  transport_proto_t proto = session_get_transport_proto (s);
  clib_thread_index_t thread_index = s->thread_index;

  s->rx_fifo = 0;
  s->tx_fifo = 0;
  session_free (s);
  hsi_worker_proto_counter_inc (hsi_worker_get (thread_index), proto, cleanup_completed);
}

static void
hsi_session_transport_cleanup (session_t *s)
{
  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (!s->rx_fifo && !s->tx_fifo);

  session_lookup_del_session (s);
  if (s->session_state != SESSION_STATE_TRANSPORT_DELETED)
    transport_cleanup (session_get_transport_proto (s), s->connection_index, s->thread_index);

  hsi_session_free (s);
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

static session_handle_t
hsi_session_cleanup_peer_handle (session_t *s)
{
  switch (session_get_transport_proto (s))
    {
    case TRANSPORT_PROTO_TCP:
      return hsi_tcp_session_cleanup_peer_handle (s);
    case TRANSPORT_PROTO_UDP:
      return hsi_udp_session_cleanup_peer_handle (s);
    default:
      return SESSION_INVALID_HANDLE;
    }
}

static void
hsi_session_fifos_cleanup_req_free_rpc (void *arg)
{
  hsi_session_fifos_cleanup_req_t *a = arg;
  hsi_worker_t *wrk;

  wrk = hsi_worker_get (vlib_get_thread_index ());
  pool_put (wrk->session_fifos_cleanup_reqs, a);
}

static void
hsi_session_fifos_cleanup_on_thread_rpc (void *arg)
{
  hsi_session_fifos_cleanup_req_t *a = arg;

  segment_manager_dealloc_fifos (a->rx_fifo, a->tx_fifo);
  session_send_rpc_evt_to_thread (a->owner_thread, hsi_session_fifos_cleanup_req_free_rpc, a);
}

static void
hsi_session_send_fifos_cleanup_on_thread (clib_thread_index_t thread_index, svm_fifo_t *rx_fifo,
					  svm_fifo_t *tx_fifo)
{
  hsi_session_fifos_cleanup_req_t *a;
  hsi_worker_t *wrk;
  clib_thread_index_t owner_thread;

  owner_thread = vlib_get_thread_index ();
  wrk = hsi_worker_get (owner_thread);
  pool_get_zero (wrk->session_fifos_cleanup_reqs, a);

  a->owner_thread = owner_thread;
  a->rx_fifo = rx_fifo;
  a->tx_fifo = tx_fifo;
  session_send_rpc_evt_to_thread_force (thread_index, hsi_session_fifos_cleanup_on_thread_rpc, a);
}

static_always_inline void
hsi_session_clear_fifos (session_t *s)
{
  s->session_state = SESSION_STATE_TRANSPORT_CLOSED;
  s->rx_fifo = 0;
  s->tx_fifo = 0;
}

void
hsi_session_cleanup_fifos (session_t *s)
{
  svm_fifo_t *rx_fifo, *tx_fifo;
  u8 local_uses_remote_fifos;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  /* session cleanup tries again to cleanup fifos */
  if (!s->rx_fifo && !s->tx_fifo)
    return;

  ASSERT (s->rx_fifo && s->tx_fifo);

  rx_fifo = s->rx_fifo;
  tx_fifo = s->tx_fifo;

  local_uses_remote_fifos = hsi_session_uses_remote_fifos (s);
  if (local_uses_remote_fifos && s->thread_index != rx_fifo->master_thread_index)
    {
      hsi_session_clear_fifos (s);
      hsi_session_send_fifos_cleanup_on_thread (rx_fifo->master_thread_index, rx_fifo, tx_fifo);
      return;
    }

  segment_manager_dealloc_fifos (rx_fifo, tx_fifo);
  hsi_session_clear_fifos (s);
}

void
hsi_session_cleanup (session_t *s)
{
  transport_proto_t proto;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  if (!hsi_session_is_cleanup_ready (s))
    return;

  hsi_session_cleanup_fifos (s);

  proto = session_get_transport_proto (s);
  if (proto == TRANSPORT_PROTO_TCP)
    hsi_tcp_session_cleanup_state (s);
  else
    hsi_udp_session_cleanup_state (s);

  hsi_session_transport_cleanup (s);
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

static void
hsi_session_cleanup_pair_rpc (void *arg)
{
  session_handle_tu_t sh = { .handle = pointer_to_uword (arg) };
  session_handle_t peer_handle = SESSION_INVALID_HANDLE;
  session_t *s;

  s = session_get_from_handle_if_valid (sh);
  if (!s)
    return;

  peer_handle = hsi_session_cleanup_peer_handle (s);
  hsi_session_cleanup (s);
  if (peer_handle != SESSION_INVALID_HANDLE)
    hsi_session_send_cleanup (peer_handle);
}

void
hsi_session_send_cleanup_pair (session_handle_t first)
{
  session_handle_tu_t sh = { .handle = first };

  session_send_rpc_evt_to_thread_force (sh.thread_index, hsi_session_cleanup_pair_rpc,
					uword_to_pointer (first, void *));
}

int
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

__clib_export int
hsi_track_session_pair (session_t *s, session_handle_t peer_session_handle)
{
  session_handle_tu_t peer_handle = { .handle = peer_session_handle };
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  hsi_worker_t *wrk;
  session_t *peer_s;
  transport_proto_t proto;
  int rv;

  /*
   * Ownership contract: return 0 means HSI has accepted both sessions and the
   * application must stop using or closing them. Any non-zero return leaves
   * ownership with the caller.
   */
  if (!s || peer_session_handle == SESSION_INVALID_HANDLE)
    return -1;

  if (thread_index != s->thread_index)
    return -1;

  wrk = hsi_worker_get (thread_index);
  proto = session_get_transport_proto (s);
  peer_s = session_get_from_handle_safe (peer_handle);
  if (!hsi_track_sessions_compatible (s, peer_s))
    {
      hsi_worker_proto_counter_inc (wrk, proto, track_failed);
      return -1;
    }

  switch (proto)
    {
    case TRANSPORT_PROTO_TCP:
      rv = hsi_track_tcp (s, peer_s);
      break;
    case TRANSPORT_PROTO_UDP:
      rv = hsi_track_udp (s, peer_s);
      break;
    default:
      rv = -1;
      break;
    }

  if (rv)
    {
      hsi_worker_proto_counter_inc (wrk, proto, track_failed);
      return rv;
    }

  hsi_worker_proto_counter_inc (wrk, proto, track_accepted);

  return 0;
}

void
hsi_tracker_show (vlib_main_t *vm)
{
  hsi_main_t *hm = &hsi_main;
  f64 now = vlib_time_now (vm);
  u32 i;

  vec_foreach_index (i, hm->wrk)
    {
      hsi_worker_t *wrk = vec_elt_at_index (hm->wrk, i);

      hsi_tracker_show_tcp (vm, i, wrk, now);
      hsi_tracker_show_udp (vm, i, wrk, now);
    }
}
