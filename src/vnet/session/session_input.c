/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Cisco Systems, Inc.
 */

#include <vnet/session/session.h>
#include <vnet/session/application.h>

static inline int
mq_try_lock (svm_msg_q_t *mq)
{
  int rv, n_try = 0;

  while (n_try < 100)
    {
      rv = svm_msg_q_try_lock (mq);
      if (!rv)
	return 0;
      n_try += 1;
      usleep (1);
    }

  return -1;
}

always_inline u8
mq_event_ring_index (session_evt_type_t et)
{
  return (et >= SESSION_CTRL_EVT_RPC ? SESSION_MQ_CTRL_EVT_RING :
					     SESSION_MQ_IO_EVT_RING);
}

void
app_worker_del_all_events (app_worker_t *app_wrk)
{
  session_worker_t *wrk;
  session_event_t *evt;
  u32 thread_index;
  session_t *s;

  for (thread_index = 0; thread_index < vec_len (app_wrk->wrk_evts);
       thread_index++)
    {
      while (clib_fifo_elts (app_wrk->wrk_evts[thread_index]))
	{
	  clib_fifo_sub2 (app_wrk->wrk_evts[thread_index], evt);
	  switch (evt->event_type)
	    {
	    case SESSION_CTRL_EVT_MIGRATED:
	      s = session_get (evt->session_index, thread_index);
	      transport_cleanup (session_get_transport_proto (s),
				 s->connection_index, s->thread_index);
	      session_free (s);
	      break;
	    case SESSION_CTRL_EVT_CLEANUP:
	      s = session_get (evt->as_u64[0] & 0xffffffff, thread_index);
	      if (evt->as_u64[0] >> 32 != SESSION_CLEANUP_SESSION)
		break;
	      uword_to_pointer (evt->as_u64[1], void (*) (session_t * s)) (s);
	      break;
	    case SESSION_CTRL_EVT_HALF_CLEANUP:
	      s = ho_session_get (evt->session_index);
	      pool_put_index (app_wrk->half_open_table, s->ho_index);
	      session_free (s);
	      break;
	    default:
	      break;
	    }
	}
      wrk = session_main_get_worker (thread_index);
      clib_bitmap_set (wrk->app_wrks_pending_ntf, app_wrk->wrk_index, 0);
    }
}

// /**
//  * Discards bytes from buffer chain
//  *
//  * It discards n_bytes_to_drop starting at first buffer after chain_b
//  */
// always_inline void
// session_enqueue_discard_chain_bytes (vlib_main_t * vm, vlib_buffer_t * b,
// 				     vlib_buffer_t ** chain_b,
// 				     u32 n_bytes_to_drop)
// {
//   vlib_buffer_t *next = *chain_b;
//   u32 to_drop = n_bytes_to_drop;
//   ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
//   while (to_drop && (next->flags & VLIB_BUFFER_NEXT_PRESENT))
//     {
//       next = vlib_get_buffer (vm, next->next_buffer);
//       if (next->current_length > to_drop)
// 	{
// 	  vlib_buffer_advance (next, to_drop);
// 	  to_drop = 0;
// 	}
//       else
// 	{
// 	  to_drop -= next->current_length;
// 	  next->current_length = 0;
// 	}
//     }
//   *chain_b = next;

//   if (to_drop == 0)
//     b->total_length_not_including_first_buffer -= n_bytes_to_drop;
// }

// /**
//  * Enqueue buffer chain tail
//  */
// always_inline int
// session_enqueue_chain_tail (session_t * s, vlib_buffer_t * b,
// 			    u32 offset, u8 is_in_order)
// {
//   vlib_buffer_t *chain_b;
//   u32 chain_bi, len, diff;
//   vlib_main_t *vm = vlib_get_main ();
//   u8 *data;
//   u32 written = 0;
//   int rv = 0;

//   if (is_in_order && offset)
//     {
//       diff = offset - b->current_length;
//       if (diff > b->total_length_not_including_first_buffer)
// 	return 0;
//       chain_b = b;
//       session_enqueue_discard_chain_bytes (vm, b, &chain_b, diff);
//       chain_bi = vlib_get_buffer_index (vm, chain_b);
//     }
//   else
//     chain_bi = b->next_buffer;

//   do
//     {
//       chain_b = vlib_get_buffer (vm, chain_bi);
//       data = vlib_buffer_get_current (chain_b);
//       len = chain_b->current_length;
//       if (!len)
// 	continue;
//       if (is_in_order)
// 	{
// 	  rv = svm_fifo_enqueue (s->rx_fifo, len, data);
// 	  if (rv == len)
// 	    {
// 	      written += rv;
// 	    }
// 	  else if (rv < len)
// 	    {
// 	      return (rv > 0) ? (written + rv) : written;
// 	    }
// 	  else if (rv > len)
// 	    {
// 	      written += rv;

// 	      /* written more than what was left in chain */
// 	      if (written > b->total_length_not_including_first_buffer)
// 		return written;

// 	      /* drop the bytes that have already been delivered */
// 	      session_enqueue_discard_chain_bytes (vm, b, &chain_b, rv - len);
// 	    }
// 	}
//       else
// 	{
// 	  rv = svm_fifo_enqueue_with_offset (s->rx_fifo, offset, len, data);
// 	  if (rv)
// 	    {
// 	      clib_warning ("failed to enqueue multi-buffer seg");
// 	      return -1;
// 	    }
// 	  offset += len;
// 	}
//     }
//   while ((chain_bi = (chain_b->flags & VLIB_BUFFER_NEXT_PRESENT)
// 	  ? chain_b->next_buffer : 0));

//   if (is_in_order)
//     return written;

//   return 0;
// }

void
session_flush_async_ops (session_t *s)
{
  session_worker_t *wrk = session_main_get_worker (s->thread_index);
  vlib_main_t *vm = wrk->vm;
  svm_fifo_async_op_t *op;

  svm_fifo_commit_async_ops (s->rx_fifo, &wrk->cops);

  vec_foreach (op, wrk->cops)
    vec_add1 (wrk->to_free, op->opaque);

  vlib_buffer_free (vm, wrk->to_free, vec_len (wrk->to_free));
  vec_set_len (wrk->to_free, 0);
  vec_set_len (wrk->cops, 0);
}

always_inline int
app_worker_flush_events_inline (app_worker_t *app_wrk, u32 thread_index,
				u8 is_builtin)
{
  application_t *app = application_get (app_wrk->app_index);
  svm_msg_q_t *mq = app_wrk->event_queue;
  u8 ring_index, mq_is_cong;
  session_state_t old_state;
  session_event_t *evt;
  u32 n_evts = 128, i;
  session_t *s;
  int rv;

  n_evts = clib_min (n_evts, clib_fifo_elts (app_wrk->wrk_evts[thread_index]));

  if (!is_builtin)
    {
      mq_is_cong = app_worker_mq_is_congested (app_wrk);
      if (mq_try_lock (mq))
	{
	  app_worker_set_mq_wrk_congested (app_wrk, thread_index);
	  return 0;
	}
    }

  for (i = 0; i < n_evts; i++)
    {
      evt = clib_fifo_head (app_wrk->wrk_evts[thread_index]);
      if (!is_builtin)
	{
	  ring_index = mq_event_ring_index (evt->event_type);
	  if (svm_msg_q_or_ring_is_full (mq, ring_index))
	    {
	      app_worker_set_mq_wrk_congested (app_wrk, thread_index);
	      break;
	    }
	}

      switch (evt->event_type)
	{
	case SESSION_IO_EVT_RX:
	  s = session_get (evt->session_index, thread_index);
	  s->flags &= ~SESSION_F_RX_EVT;
	  session_flush_async_ops (s);
	  /* Application didn't confirm accept yet */
	  if (PREDICT_FALSE (s->session_state == SESSION_STATE_ACCEPTING ||
			     s->session_state == SESSION_STATE_CONNECTING))
	    break;
	  app->cb_fns.builtin_app_rx_callback (s);
	  break;
	/* Handle sessions that might not be on current thread */
	case SESSION_IO_EVT_BUILTIN_RX:
	  s = session_get_from_handle_if_valid (evt->session_handle);
	  if (!s)
	    break;
	  s->flags &= ~SESSION_F_RX_EVT;
	  if (PREDICT_FALSE (s->session_state == SESSION_STATE_ACCEPTING ||
			     s->session_state == SESSION_STATE_CONNECTING))
	    break;
	  app->cb_fns.builtin_app_rx_callback (s);
	  break;
	case SESSION_IO_EVT_TX:
	  s = session_get (evt->session_index, thread_index);
	  app->cb_fns.builtin_app_tx_callback (s);
	  break;
	case SESSION_IO_EVT_TX_MAIN:
	  s = session_get_from_handle_if_valid (evt->session_handle);
	  if (!s)
	    break;
	  app->cb_fns.builtin_app_tx_callback (s);
	  break;
	case SESSION_CTRL_EVT_BOUND:
	  /* No app cb function currently */
	  if (is_builtin)
	    break;
	  mq_send_session_bound_cb (app_wrk->wrk_index, evt->as_u64[1] >> 32,
				    evt->session_handle,
				    evt->as_u64[1] & 0xffffffff);
	  break;
	case SESSION_CTRL_EVT_ACCEPTED:
	  s = session_get (evt->session_index, thread_index);
	  old_state = s->session_state;
	  if (app->cb_fns.session_accept_callback (s))
	    {
	      session_close (s);
	      s->app_wrk_index = SESSION_INVALID_INDEX;
	      break;
	    }
	  if (is_builtin)
	    {
	      if (old_state >= SESSION_STATE_TRANSPORT_CLOSING)
		{
		  session_set_state (s, old_state);
		  app_worker_close_notify (app_wrk, s);
		}
	    }
	  break;
	case SESSION_CTRL_EVT_CONNECTED:
	  if (!(evt->as_u64[1] & 0xffffffff))
	    {
	      s = session_get (evt->session_index, thread_index);
	      old_state = s->session_state;
	    }
	  else
	    s = 0;
	  rv = app->cb_fns.session_connected_callback (
	    app_wrk->wrk_index, evt->as_u64[1] >> 32, s,
	    evt->as_u64[1] & 0xffffffff);
	  if (!s)
	    break;
	  if (rv)
	    {
	      session_close (s);
	      s->app_wrk_index = SESSION_INVALID_INDEX;
	      break;
	    }
	  if (old_state >= SESSION_STATE_TRANSPORT_CLOSING)
	    {
	      session_set_state (s, old_state);
	      app_worker_close_notify (app_wrk, s);
	    }
	  break;
	case SESSION_CTRL_EVT_DISCONNECTED:
	  s = session_get (evt->session_index, thread_index);
	  app->cb_fns.session_disconnect_callback (s);
	  break;
	case SESSION_CTRL_EVT_RESET:
	  s = session_get (evt->session_index, thread_index);
	  app->cb_fns.session_reset_callback (s);
	  break;
	case SESSION_CTRL_EVT_UNLISTEN_REPLY:
	  if (is_builtin)
	    break;
	  mq_send_unlisten_reply (app_wrk, evt->session_handle,
				  evt->as_u64[1] >> 32,
				  evt->as_u64[1] & 0xffffffff);
	  break;
	case SESSION_CTRL_EVT_MIGRATED:
	  s = session_get (evt->session_index, thread_index);
	  app->cb_fns.session_migrate_callback (s, evt->as_u64[1]);
	  transport_cleanup (session_get_transport_proto (s),
			     s->connection_index, s->thread_index);
	  session_free (s);
	  /* Notify app that it has data on the new session */
	  s = session_get_from_handle (evt->as_u64[1]);
	  session_send_io_evt_to_thread (s->rx_fifo,
					 SESSION_IO_EVT_BUILTIN_RX);
	  break;
	case SESSION_CTRL_EVT_TRANSPORT_CLOSED:
	  s = session_get (evt->session_index, thread_index);
	  if (app->cb_fns.session_transport_closed_callback)
	    app->cb_fns.session_transport_closed_callback (s);
	  break;
	case SESSION_CTRL_EVT_CLEANUP:
	  s = session_get (evt->as_u64[0] & 0xffffffff, thread_index);
	  if (app->cb_fns.session_cleanup_callback)
	    app->cb_fns.session_cleanup_callback (s, evt->as_u64[0] >> 32);
	  if (evt->as_u64[0] >> 32 != SESSION_CLEANUP_SESSION)
	    break;
	  uword_to_pointer (evt->as_u64[1], void (*) (session_t * s)) (s);
	  break;
	case SESSION_CTRL_EVT_HALF_CLEANUP:
	  s = ho_session_get (evt->session_index);
	  ASSERT (session_vlib_thread_is_cl_thread ());
	  if (app->cb_fns.half_open_cleanup_callback)
	    app->cb_fns.half_open_cleanup_callback (s);
	  pool_put_index (app_wrk->half_open_table, s->ho_index);
	  session_free (s);
	  break;
	case SESSION_CTRL_EVT_APP_ADD_SEGMENT:
	  app->cb_fns.add_segment_callback (app_wrk->wrk_index,
					    evt->as_u64[1]);
	  break;
	case SESSION_CTRL_EVT_APP_DEL_SEGMENT:
	  app->cb_fns.del_segment_callback (app_wrk->wrk_index,
					    evt->as_u64[1]);
	  break;
	default:
	  clib_warning ("unexpected event: %u", evt->event_type);
	  ASSERT (0);
	  break;
	}
      clib_fifo_advance_head (app_wrk->wrk_evts[thread_index], 1);
    }

  if (!is_builtin)
    {
      svm_msg_q_unlock (mq);
      if (mq_is_cong && i == n_evts)
	app_worker_unset_wrk_mq_congested (app_wrk, thread_index);
    }

  return 0;
}

int
app_wrk_flush_wrk_events (app_worker_t *app_wrk, u32 thread_index)
{
  if (app_worker_application_is_builtin (app_wrk))
    return app_worker_flush_events_inline (app_wrk, thread_index,
					   1 /* is_builtin */);
  else
    return app_worker_flush_events_inline (app_wrk, thread_index,
					   0 /* is_builtin */);
}

static inline int
session_wrk_flush_events (session_worker_t *wrk)
{
  app_worker_t *app_wrk;
  uword app_wrk_index;
  u32 thread_index;

  thread_index = wrk->vm->thread_index;
  app_wrk_index = clib_bitmap_first_set (wrk->app_wrks_pending_ntf);

  while (app_wrk_index != ~0)
    {
      app_wrk = app_worker_get_if_valid (app_wrk_index);
      /* app_wrk events are flushed on free, so should be valid here */
      ASSERT (app_wrk != 0);
      app_wrk_flush_wrk_events (app_wrk, thread_index);

      if (!clib_fifo_elts (app_wrk->wrk_evts[thread_index]))
	clib_bitmap_set (wrk->app_wrks_pending_ntf, app_wrk->wrk_index, 0);

      app_wrk_index =
	clib_bitmap_next_set (wrk->app_wrks_pending_ntf, app_wrk_index + 1);
    }

  if (!clib_bitmap_is_zero (wrk->app_wrks_pending_ntf))
    vlib_node_set_interrupt_pending (wrk->vm, session_input_node.index);

  return 0;
}

VLIB_NODE_FN (session_input_node)
(vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 thread_index = vm->thread_index;
  session_worker_t *wrk;

  wrk = session_main_get_worker (thread_index);
  session_wrk_flush_events (wrk);

  return 0;
}

VLIB_REGISTER_NODE (session_input_node) = {
  .name = "session-input",
  .type = VLIB_NODE_TYPE_INPUT,
  .state = VLIB_NODE_STATE_DISABLED,
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */