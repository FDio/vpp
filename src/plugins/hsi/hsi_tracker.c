/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco and/or its affiliates.
 */

#include <hsi/hsi_tracker_private.h>
#include <vnet/session/segment_manager.h>
#include <vnet/session/transport.h>

/*
 * Hand session back to the session layer, after which it's no longer hsi owned.
 * Session layer frees it, or hands it to the app for cleanup notifications, once
 * the transport connection is deleted.
 */
void
hsi_session_release (session_t *s)
{
  ASSERT (s->thread_index == vlib_get_thread_index ());
  ASSERT (!s->rx_fifo && !s->tx_fifo);

  hsi_worker_proto_counter_inc (hsi_worker_get (s->thread_index), session_get_transport_proto (s),
				cleanup_completed);
  hsi_session_restore_app_wrk (s);
  s->session_state = SESSION_STATE_CLOSED;
}

static void
hsi_session_transport_cleanup (session_t *s)
{
  transport_proto_t proto = session_get_transport_proto (s);
  clib_thread_index_t thread_index = s->thread_index;
  u32 conn_index = s->connection_index;
  transport_connection_t *tc = 0;

  /* Transport might have been deleted while hsi owned the session, e.g., tcp
   * reset while draining. Session state cannot be relied on because fifos
   * cleanup moves session to transport closed. Session layer already removed
   * the session from the lookup table when the transport was deleted. */
  if (s->session_state != SESSION_STATE_TRANSPORT_DELETED)
    tc = session_get_transport (s);

  hsi_session_release (s);

  if (!tc || tc->s_index != s->session_index)
    {
      s->session_state = SESSION_STATE_TRANSPORT_DELETED;
      session_program_cleanup (s);
      return;
    }

  session_transport_delete_notify (tc);

  /* Session might be freed */
  transport_cleanup (proto, conn_index, thread_index);
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
hsi_session_send_fifos_cleanup_on_thread (clib_thread_index_t thread_index, svm_fifo_t *rx_fifo,
					  svm_fifo_t *tx_fifo)
{
  hsi_msg_t msg = { .type = HSI_MSG_SESSION_FIFOS_CLEANUP };

  msg.session_fifos_cleanup.rx_fifo = rx_fifo;
  msg.session_fifos_cleanup.tx_fifo = tx_fifo;
  hsi_mq_send (thread_index, &msg);
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
  clib_thread_index_t alloc_thread;

  ASSERT (s->thread_index == vlib_get_thread_index ());

  /* session cleanup tries again to cleanup fifos */
  if (!s->rx_fifo && !s->tx_fifo)
    return;

  if (session_get_transport_proto (s) == TRANSPORT_PROTO_TCP)
    hsi_tcp_session_restore_fifos (s);

  ASSERT (s->rx_fifo && s->tx_fifo);

  rx_fifo = s->rx_fifo;
  tx_fifo = s->tx_fifo;
  alloc_thread = segment_manager_fifo_alloc_thread (rx_fifo);
  ASSERT (alloc_thread == segment_manager_fifo_alloc_thread (tx_fifo));

  /* Only the thread that allocated the fifos can free them */
  if (alloc_thread != s->thread_index)
    {
      hsi_session_clear_fifos (s);
      hsi_session_send_fifos_cleanup_on_thread (alloc_thread, rx_fifo, tx_fifo);
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

  /* Already handed back to app worker for cleanup notifications */
  if (!hsi_session_is_hsi_owned (s))
    return;

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
hsi_handle_cleanups (f64 time_now, u8 thread_index)
{
  hsi_worker_t *wrk;
  session_t *s;
  hsi_cleanup_req_t *req;

  wrk = hsi_worker_get (thread_index);
  while (clib_fifo_elts (wrk->pending_cleanups))
    {
      req = clib_fifo_head (wrk->pending_cleanups);
      if (req->free_time > time_now)
	break;
      clib_fifo_sub2 (wrk->pending_cleanups, req);
      s = session_get_from_handle_if_valid (req->sh);
      if (s)
	hsi_session_cleanup (s);
    }

  if (!clib_fifo_elts (wrk->pending_cleanups))
    {
      session_register_update_time_fn_w_thread (hsi_handle_cleanups, 0, thread_index);
      wrk->pending_cleanups_registered = 0;
    }
}

void
hsi_session_program_cleanup (session_t *s)
{
  clib_thread_index_t thread_index = s->thread_index;
  hsi_worker_t *wrk;
  hsi_cleanup_req_t *req;
  f64 now;

  wrk = hsi_worker_get (thread_index);
  now = vlib_time_now (vlib_get_main ());
  clib_fifo_add2 (wrk->pending_cleanups, req);
  req->sh = session_handle (s);
  req->free_time = now + hsi_main.postponed_cleanup_time;
  if (!wrk->pending_cleanups_registered)
    {
      session_register_update_time_fn_w_thread (hsi_handle_cleanups, 1, thread_index);
      wrk->pending_cleanups_registered = 1;
    }
}

static void
hsi_session_cleanup_msg (session_handle_t session_handle)
{
  session_handle_tu_t sh = { .handle = session_handle };
  session_t *s;

  s = session_get_from_handle_if_valid (sh);
  if (s)
    hsi_session_cleanup (s);
}

static void
hsi_session_send_cleanup (session_handle_t session_handle)
{
  session_handle_tu_t sh = { .handle = session_handle };

  hsi_mq_send_handle (sh.thread_index, HSI_MSG_SESSION_CLEANUP, session_handle);
}

static void
hsi_session_cleanup_pair_msg (session_handle_t session_handle)
{
  session_handle_tu_t sh = { .handle = session_handle };
  session_handle_t peer_handle = SESSION_INVALID_HANDLE;
  session_t *s;

  s = hsi_session_get_owned_if_valid (sh);
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

  hsi_mq_send_handle (sh.thread_index, HSI_MSG_SESSION_CLEANUP_PAIR, first);
}

static void
hsi_handle_msg (hsi_msg_t *msg)
{
  switch (msg->type)
    {
    case HSI_MSG_SESSION_CLEANUP:
      hsi_session_cleanup_msg (msg->session_handle);
      break;
    case HSI_MSG_SESSION_CLEANUP_PAIR:
      hsi_session_cleanup_pair_msg (msg->session_handle);
      break;
    case HSI_MSG_SESSION_FIFOS_CLEANUP:
      segment_manager_dealloc_fifos (msg->session_fifos_cleanup.rx_fifo,
				     msg->session_fifos_cleanup.tx_fifo);
      break;
    case HSI_MSG_TCP_DRAIN_START:
    case HSI_MSG_TCP_TRACK_COMMIT:
    case HSI_MSG_TCP_TRACK_READY:
    case HSI_MSG_TCP_FIN_ACKED:
    case HSI_MSG_TCP_PEER_FIN_PENDING:
    case HSI_MSG_TCP_ABORT:
    case HSI_MSG_TCP_ABORT_SILENT:
      hsi_tcp_handle_msg (msg);
      break;
    case HSI_MSG_UDP_DRAIN_START:
    case HSI_MSG_UDP_DRAIN_CACHE:
    case HSI_MSG_UDP_TRACK_COMMIT:
    case HSI_MSG_UDP_PEER_UPDATE:
    case HSI_MSG_UDP_MIGRATED_CLEANUP:
      hsi_udp_handle_msg (msg);
      break;
    default:
      ASSERT (0);
      break;
    }
}

/*
 * Handle all messages queued for this worker. Messages are moved to a vector
 * this worker owns first, so the queue is held only to copy them and producers
 * can add new messages, including handlers on this worker.
 */
static void
hsi_mq_handle_rpc (void *arg)
{
  hsi_worker_t *wrk = hsi_worker_get (vlib_get_thread_index ());
  hsi_msg_t *msg;
  u32 i;

  clib_spinlock_lock (&wrk->mq_lock);
  while ((msg = clib_ring_deq (wrk->mq)))
    vec_add1 (wrk->mq_msgs, *msg);
  clib_spinlock_unlock (&wrk->mq_lock);

  for (i = 0; i < vec_len (wrk->mq_msgs); i++)
    hsi_handle_msg (vec_elt_at_index (wrk->mq_msgs, i));

  vec_reset_length (wrk->mq_msgs);
}

/*
 * Queue msg for thread_index. Its queue is drained when the producer that
 * finds it empty notifies it with an rpc. Notify with the queue locked, so
 * producers that find the queue non-empty know the rpc is ahead of any
 * other rpc they send to the thread afterwards.
 */
void
hsi_mq_send (clib_thread_index_t thread_index, hsi_msg_t *msg)
{
  clib_thread_index_t cur_thread = vlib_get_thread_index ();
  hsi_worker_t *wrk = hsi_worker_get (thread_index);
  hsi_worker_t *src_wrk = hsi_worker_get (cur_thread);
  hsi_msg_t *slot;
  u8 was_empty;

  clib_spinlock_lock (&wrk->mq_lock);

  was_empty = !clib_ring_n_enq (wrk->mq);
  slot = clib_ring_enq (wrk->mq);
  if (PREDICT_FALSE (!slot))
    {
      /* Queues must be sized so this never happens */
      clib_spinlock_unlock (&wrk->mq_lock);
      hsi_worker_counter_inc (src_wrk, mq_full);
      clib_warning ("hsi mq of thread %u full", thread_index);
      ASSERT (0);
      return;
    }
  *slot = *msg;
  if (was_empty)
    session_send_rpc_evt_to_thread_force (thread_index, hsi_mq_handle_rpc, 0);

  clib_spinlock_unlock (&wrk->mq_lock);

  hsi_worker_counter_inc (src_wrk, mq_msgs);
  if (was_empty)
    {
      hsi_worker_counter_inc (src_wrk, mq_doorbells);
      hsi_rpc_count (src_wrk, thread_index == cur_thread);
    }
}

/* Allocate or resize mq, only before workers can use it */
void
hsi_mq_init (hsi_worker_t *wrk)
{
  if (!wrk->mq_lock)
    clib_spinlock_init (&wrk->mq_lock);

  if (wrk->mq && vec_len (wrk->mq) == hsi_main.mq_length)
    return;

  ASSERT (!wrk->mq || !clib_ring_n_enq (wrk->mq));
  clib_ring_free (wrk->mq);
  clib_ring_new_aligned (wrk->mq, hsi_main.mq_length, CLIB_CACHE_LINE_BYTES);
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
hsi_track_pair (hsi_track_args_t *a)
{
  session_handle_tu_t peer_handle = { .handle = a->peer_session_handle };
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  session_t *peer_s, *s = a->s;
  hsi_worker_t *wrk;
  transport_proto_t proto;
  int rv;

  /*
   * Ownership contract: return 0 means HSI has accepted both sessions and the
   * application must stop using or closing them. Any non-zero return leaves
   * ownership with the caller.
   */
  if (!s || a->peer_session_handle == SESSION_INVALID_HANDLE)
    return -1;

  if (thread_index != s->thread_index)
    return -1;

  wrk = hsi_worker_get (thread_index);
  proto = session_get_transport_proto (s);
  peer_s = session_get_from_handle_safe (peer_handle);
  if (!hsi_track_sessions_compatible (s, peer_s))
    {
      hsi_worker_proto_counter_inc (wrk, proto, track_failed);
      if (!peer_s || s == peer_s || s->session_type != peer_s->session_type)
	hsi_worker_proto_counter_inc (wrk, proto, track_fail_peer);
      else if (s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
	hsi_worker_proto_counter_inc (wrk, proto, track_fail_closing);
      else
	hsi_worker_proto_counter_inc (wrk, proto, track_fail_peer_closing);
      return -1;
    }

  switch (proto)
    {
    case TRANSPORT_PROTO_TCP:
      rv = hsi_track_tcp (s, peer_s, a->flags);
      break;
    case TRANSPORT_PROTO_UDP:
      rv = hsi_track_udp (s, peer_s, a->flags);
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

static int
hsi_track_session_pair_compat (session_t *s, session_handle_t peer_session_handle)
{
  hsi_track_args_t a = { .s = s, .peer_session_handle = peer_session_handle };

  return hsi_track_pair (&a);
}

__clib_export int
hsi_track_session_pair (session_t *s, session_handle_t peer_session_handle)
{
  return hsi_track_session_pair_compat (s, peer_session_handle);
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

static int
hsi_tcp_tracked_action_fn (vlib_main_t *vm, vlib_buffer_t *b, tcp_connection_t *tc, void *ip_hdr,
			   void *tcp_hdr, u8 is_ip4, u8 send_rst_on_drain_fail, u8 *cleanup_session)
{
  return (int) hsi_tcp_tracked_connection_action (vm, b, tc, ip_hdr, (tcp_header_t *) tcp_hdr,
						  is_ip4, send_rst_on_drain_fail, cleanup_session,
						  0 /* is_drain */);
}

static hsi_tcp_tracker_t *
hsi_tcp_tracker_get_fn (tcp_connection_t *tc)
{
  return hsi_tcp_tracker_get (tc);
}

static void
hsi_udp_tracked_action_fn (vlib_main_t *vm, vlib_buffer_t *b, udp_connection_t *uc, void *ip_hdr,
			   udp_header_t *udp_hdr, u8 is_ip4)
{
  hsi_udp_handle_tracked_connection (vm, b, uc, ip_hdr, udp_hdr, is_ip4);
}

static hsi_udp_tracker_t *
hsi_udp_tracker_get_fn (udp_connection_t *uc)
{
  return hsi_udp_tracker_get (uc);
}

static hsi_tracker_vft_t hsi_tracker_vft_ = {
  .track_session_pair = hsi_track_session_pair_compat,
  .tcp_tracked_action = hsi_tcp_tracked_action_fn,
  .tcp_tracker_get = hsi_tcp_tracker_get_fn,
  .udp_tracked_action = hsi_udp_tracked_action_fn,
  .udp_tracker_get = hsi_udp_tracker_get_fn,
  .track_pair = hsi_track_pair,
};

__clib_export hsi_tracker_vft_t *
hsi_tracker_vft_get (void)
{
  return &hsi_tracker_vft_;
}
