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

static f64
hsi_handle_cleanups (clib_thread_index_t thread_index, f64 now)
{
  hsi_worker_t *wrk;
  session_t *s;
  hsi_cleanup_req_t *req;

  wrk = hsi_worker_get (thread_index);
  while (clib_fifo_elts (wrk->pending_cleanups))
    {
      req = clib_fifo_head (wrk->pending_cleanups);
      if (req->free_time > now)
	return req->free_time;
      clib_fifo_sub2 (wrk->pending_cleanups, req);
      s = session_get_from_handle_if_valid (req->sh);
      if (s)
	hsi_session_cleanup (s);
    }

  return HSI_TIMER_NONE;
}

void
hsi_session_program_cleanup (session_t *s)
{
  clib_thread_index_t thread_index = s->thread_index;
  hsi_worker_t *wrk;
  hsi_cleanup_req_t *req;
  f64 now;

  wrk = hsi_worker_get (thread_index);
  now = vlib_time_now (vlib_get_main_by_index (thread_index));
  clib_fifo_add2 (wrk->pending_cleanups, req);
  req->sh = session_handle (s);
  req->free_time = now + hsi_main.postponed_cleanup_time;
  hsi_timer_schedule (thread_index, req->free_time);
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

  /* Callers might still use what the message refers to, so it's handled with
   * hsi timers in a later main loop, see hsi_handle_local_msgs */
  if (thread_index == cur_thread)
    {
      vec_add1 (wrk->local_msgs, *msg);
      wrk->local_msgs_loop = vlib_get_main_by_index (thread_index)->main_loop_count;
      hsi_worker_counter_inc (wrk, local_msgs);
      hsi_timer_schedule (thread_index, 0 /* asap */);
      return;
    }

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
      hsi_rpc_count (src_wrk, 0 /* is_self */);
    }
}

/*
 * Messages are handled only in a main loop after the one they were added in,
 * when frames that might refer to their sessions were processed. Messages
 * handlers add are handled in the next run.
 */
static f64
hsi_handle_local_msgs (vlib_main_t *vm, hsi_worker_t *wrk)
{
  u32 i, n_msgs = vec_len (wrk->local_msgs);
  hsi_msg_t msg;

  if (!n_msgs)
    return HSI_TIMER_NONE;

  if (wrk->local_msgs_loop == vm->main_loop_count)
    return 0;

  for (i = 0; i < n_msgs; i++)
    {
      /* Handlers might add messages */
      msg = wrk->local_msgs[i];
      hsi_handle_msg (&msg);
    }
  vec_delete (wrk->local_msgs, n_msgs, 0);

  return vec_len (wrk->local_msgs) ? 0 : HSI_TIMER_NONE;
}

/* Expired timer handles carry the timer in the top bit */
#define HSI_WHEEL_HANDLE_TIMER_SHIFT 31
#define HSI_WHEEL_HANDLE_INDEX_MASK  0x7fffffff

STATIC_ASSERT (HSI_WHEEL_N_TIMERS <= 2, "wheel supports two timers");

typedef void (*hsi_wheel_expired_fn) (clib_thread_index_t thread_index, u32 *indices, f64 now);

/* Called with the indices of all their timers that expired */
static const hsi_wheel_expired_fn hsi_wheel_expired_fns[HSI_WHEEL_N_TIMERS] = {
  [HSI_WHEEL_TIMER_UDP_IDLE] = hsi_udp_idle_expired,
};

/*
 * Arms a timer that fires in at least interval seconds, rounded up to wheel
 * ticks, or after one wheel turn if longer. Users rearm with the time left.
 * Returns the handle needed to disarm it.
 */
u32
hsi_wheel_arm (clib_thread_index_t thread_index, hsi_wheel_timer_t timer, u32 index, f64 interval,
	       f64 now)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);
  tw_timer_wheel_2t_1w_2048sl_t *tw = &wrk->wheel;
  u64 ticks;

  ASSERT (timer < HSI_WHEEL_N_TIMERS && index <= HSI_WHEEL_HANDLE_INDEX_MASK);

  if (PREDICT_FALSE (!tw->timers))
    tw_timer_wheel_init_2t_1w_2048sl (tw, 0 /* no callback */, HSI_WHEEL_TICK, ~0);
  else if (!wrk->wheel_n_armed && now - tw->last_run_time > 2 * HSI_WHEEL_TICK)
    /* Wheel is not advanced while empty, resync it on next expire instead
     * of catching up on all the ticks missed */
    tw->last_run_time = 0;

  ticks = interval > 0 ? (u64) (interval / HSI_WHEEL_TICK) + 1 : 1;
  ticks = clib_min (ticks, HSI_WHEEL_MAX_TICKS);
  wrk->wheel_n_armed += 1;
  hsi_timer_schedule (thread_index, now + HSI_WHEEL_TICK);

  return tw_timer_start_2t_1w_2048sl (tw, index, timer, ticks);
}

void
hsi_wheel_disarm (clib_thread_index_t thread_index, u32 *handle)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  if (*handle == HSI_WHEEL_HANDLE_INVALID)
    return;

  tw_timer_stop_2t_1w_2048sl (&wrk->wheel, *handle);
  *handle = HSI_WHEEL_HANDLE_INVALID;
  ASSERT (wrk->wheel_n_armed > 0);
  wrk->wheel_n_armed -= 1;
}

/* Hands expired timers to their users, returns when the wheel has to run again */
static f64
hsi_wheel_run (clib_thread_index_t thread_index, f64 now)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);
  u32 *handles, *handle, timer;

  if (!wrk->wheel_n_armed)
    return HSI_TIMER_NONE;

  handles = tw_timer_expire_timers_2t_1w_2048sl (&wrk->wheel, now);
  ASSERT (wrk->wheel_n_armed >= vec_len (handles));
  wrk->wheel_n_armed -= vec_len (handles);

  /* Copied, users rearm and the wheel reuses its vector */
  for (timer = 0; timer < HSI_WHEEL_N_TIMERS; timer++)
    vec_reset_length (wrk->wheel_expired[timer]);
  vec_foreach (handle, handles)
    vec_add1 (wrk->wheel_expired[*handle >> HSI_WHEEL_HANDLE_TIMER_SHIFT],
	      *handle & HSI_WHEEL_HANDLE_INDEX_MASK);

  for (timer = 0; timer < HSI_WHEEL_N_TIMERS; timer++)
    if (vec_len (wrk->wheel_expired[timer]))
      hsi_wheel_expired_fns[timer](thread_index, wrk->wheel_expired[timer], now);

  return wrk->wheel_n_armed ? wrk->wheel.next_run_time : HSI_TIMER_NONE;
}

static void hsi_timer_update_time (f64 now, u8 thread_index);

/* Out of line, so the per loop deadline check stays cheap */
static __clib_noinline void
hsi_timer_run (f64 now, clib_thread_index_t thread_index)
{
  vlib_main_t *vm = vlib_get_main_by_index (thread_index);
  hsi_worker_t *wrk = hsi_worker_get (thread_index);
  f64 next;

  /* Handlers schedule new work, which can only move the deadline earlier */
  wrk->timer_next = HSI_TIMER_NONE;
  next = hsi_handle_local_msgs (vm, wrk);
  next = clib_min (next, hsi_handle_cleanups (thread_index, now));
  next = clib_min (next, hsi_tcp_drain_timer (thread_index, now));
  next = clib_min (next, hsi_tcp_fin_wait_timer (thread_index, now));
  next = clib_min (next, hsi_udp_drain_timer (thread_index, now));
  next = clib_min (next, hsi_wheel_run (thread_index, now));
  next = clib_min (next, wrk->timer_next);

  if (next != HSI_TIMER_NONE)
    {
      wrk->timer_next = next;
      return;
    }

  /* Nothing pending. Safe while subscribers are being called, see
   * hsi_timer_schedule */
  session_register_update_time_fn_w_thread (hsi_timer_update_time, 0, thread_index);
  wrk->timer_registered = 0;
}

/*
 * Only session time subscriber of hsi. Registered only while the worker has
 * hsi timers pending, it checks a single deadline, so it's cheap when nothing
 * is due.
 */
static void
hsi_timer_update_time (f64 now, u8 thread_index)
{
  if (PREDICT_TRUE (now < hsi_worker_get (thread_index)->timer_next))
    return;
  hsi_timer_run (now, thread_index);
}

/*
 * Make sure hsi timers run on the worker at when, or earlier. Only the worker's
 * own thread schedules them, also from session time subscribers, which is safe
 * because the session layer walks subscribers by index.
 */
void
hsi_timer_schedule (clib_thread_index_t thread_index, f64 when)
{
  hsi_worker_t *wrk = hsi_worker_get (thread_index);

  ASSERT (thread_index == vlib_get_thread_index ());

  if (!wrk->timer_registered)
    {
      session_register_update_time_fn_w_thread (hsi_timer_update_time, 1, thread_index);
      wrk->timer_registered = 1;
      wrk->timer_next = when;
      return;
    }

  if (when < wrk->timer_next)
    wrk->timer_next = when;
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
