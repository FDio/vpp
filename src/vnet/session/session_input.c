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

static int count_del_cleanup;
static int count_to_flush;
// static int count_i_flushed;
void
app_worker_del_all_events (app_worker_t *app_wrk, u32 thread_index)
{
//   session_worker_t *wrk;
  session_event_t *evt;
  session_t *s;
//   int i;

   count_to_flush = clib_fifo_elts (app_wrk->wrk_evts[thread_index]);
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
          if (evt->as_u64[0] >> 32 != SESSION_CLEANUP_SESSION)
            break;
          count_del_cleanup += 1;
          s = session_get (evt->as_u64[0] & 0xffffffff, thread_index);
          if (!evt->as_u64[1])
            {
              segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
              session_free (s);
            }
          else
            {
              uword_to_pointer (evt->as_u64[1], void (*) (session_t *s)) (s);
            }
          break;
        case SESSION_CTRL_EVT_HALF_CLEANUP:
          s = ho_session_get (evt->session_index);
          pool_put_index (app_wrk->half_open_table, s->ho_index);
          session_free (s);
          break;
        default:
          break;
        }
//       clib_fifo_advance_head (app_wrk->wrk_evts[thread_index], 1);
    }
//     count_i_flushed = i;

//   wrk = session_main_get_worker (thread_index);
//   clib_bitmap_set (wrk->app_wrks_pending_ntf, app_wrk->wrk_index, 0);
}

always_inline int
app_worker_flush_events_inline (app_worker_t *app_wrk, u32 thread_index,
				u8 is_builtin)
{
  application_t *app = application_get (app_wrk->app_index);
  svm_msg_q_t *mq = app_wrk->event_queue;
  session_event_t *evt;
  u32 n_evts = 128, i;
  u8 ring_index, mq_is_cong;
  session_t *s;

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
	  app->cb_fns.builtin_app_rx_callback (s);
	  s->flags &= ~SESSION_F_RX_EVT;
	  break;
	/* Handle sessions that might not be on current thread */
	case SESSION_IO_EVT_BUILTIN_RX:
	  s = session_get_from_handle_if_valid (evt->session_handle);
	  if (!s)
	    break;
	  app->cb_fns.builtin_app_rx_callback (s);
	  break;
	case SESSION_IO_EVT_TX:
	  s = session_get (evt->session_index, thread_index);
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
	  app->cb_fns.session_accept_callback (s);
	  break;
	case SESSION_CTRL_EVT_CONNECTED:
	  if (!(evt->as_u64[1] & 0xffffffff))
	    s = session_get (evt->session_index, thread_index);
	  else
	    s = 0;
	  app->cb_fns.session_connected_callback (app_wrk->wrk_index,
						  evt->as_u64[1] >> 32, s,
						  evt->as_u64[1] & 0xffffffff);
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
	  if (!evt->as_u64[1])
	    {
	      segment_manager_dealloc_fifos (s->rx_fifo, s->tx_fifo);
	      session_free (s);
	    }
	  else
	    {
	      uword_to_pointer (evt->as_u64[1], void (*) (session_t * s)) (s);
	    }
	  break;
	case SESSION_CTRL_EVT_HALF_CLEANUP:
	  s = ho_session_get (evt->session_index);
	  ASSERT (session_vlib_thread_is_cl_thread ());
	  if (app->cb_fns.half_open_cleanup_callback)
	    app->cb_fns.half_open_cleanup_callback (s);
	  if (vlib_thread_is_main_w_barrier ())
	    clib_warning ("request to cleanup s %u ho_index %u",
			  evt->session_index, s->ho_index);
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

      if (PREDICT_FALSE (app_wrk->is_pending_free))
        {
          app_worker_del_all_events (app_wrk, thread_index);
          clib_bitmap_set (wrk->app_wrks_pending_ntf, app_wrk->wrk_index, 0);
          app_worker_maybe_free (app_wrk, thread_index);
          app_wrk_index = clib_bitmap_next_set (wrk->app_wrks_pending_ntf,
                                                app_wrk_index + 1);
          continue;
        }

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