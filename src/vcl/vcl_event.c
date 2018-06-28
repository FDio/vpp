/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <vppinfra/fifo.h>
#include <vppinfra/pool.h>
#include <vppinfra/hash.h>
#include <vnet/api_errno.h>

#include <vcl/vppcom.h>
#include <vcl/vcl_event.h>
#include <vcl/vcl_private.h>

/**
 * @file
 * @brief VPP Communications Library (VCL) event handler.
 *
 * Definitions for generic event handling in VCL.
 */

int
vce_generate_event (vce_event_thread_t * evt, u32 ev_idx)
{
  int elts, rv = 0;
  vce_event_t *p;

  pthread_mutex_lock (&(evt->generator_lock));

  /* Check there is event data for this event */

  VCE_EVENTS_LOCK ();
  p = pool_elt_at_index (evt->vce_events, ev_idx);
  ASSERT (p);

  elts = (int) clib_fifo_free_elts (evt->event_index_fifo);
  if (PREDICT_TRUE (elts))
    {
      /* Add event to queue */
      clib_fifo_add1 (evt->event_index_fifo, ev_idx);
      pthread_cond_signal (&(evt->generator_cond));
    }
  else
    {
      rv = VNET_API_ERROR_QUEUE_FULL;
    }

  VCE_EVENTS_UNLOCK ();
  pthread_mutex_unlock (&(evt->generator_lock));

  return rv;
}

void
vce_clear_event (vce_event_thread_t * evt, u32 ev_idx)
{
  VCE_EVENTS_LOCK ();
  pool_put_index (evt->vce_events, ev_idx);
  VCE_EVENTS_UNLOCK ();
}

vce_event_t *
vce_get_event_from_index (vce_event_thread_t * evt, u32 ev_idx)
{
  vce_event_t *ev = 0;
  /* Assumes caller has obtained the spinlock (evt->events_lockp) */

  if (!pool_is_free_index (evt->vce_events, ev_idx))
    ev = pool_elt_at_index (evt->vce_events, ev_idx);

  return ev;
}

vce_event_handler_reg_t *
vce_get_event_handler (vce_event_thread_t * evt, vce_event_key_t * evk)
{
  vce_event_handler_reg_t *handler = 0;
  uword *p;

  VCE_HANDLERS_LOCK ();
  p = hash_get (evt->handlers_index_by_event_key, evk->as_u64);
  if (p)
    handler = pool_elt_at_index (evt->vce_event_handlers, p[0]);
  VCE_HANDLERS_UNLOCK ();

  return handler;
}

vce_event_handler_reg_t *
vce_register_handler (vce_event_thread_t * evt, vce_event_key_t * evk,
		      vce_event_callback_t cb, void *cb_args)
{
  vce_event_handler_reg_t *handler;
  vce_event_handler_reg_t *old_handler = 0;
  uword *p;
  u32 handler_index;

  /* TODO - multiple handler support. For now we can replace
   * and re-instate, which is useful for event recycling */

  VCE_HANDLERS_LOCK ();

  p = hash_get (evt->handlers_index_by_event_key, evk->as_u64);
  if (p)
    {
      old_handler = pool_elt_at_index (evt->vce_event_handlers, p[0]);
      /* If we are just re-registering, ignore and move on
       * else store the old handler_fn for unregister to re-instate */
      if (old_handler->handler_fn == cb)
	{

	  VCE_HANDLERS_UNLOCK ();

	  /* Signal event thread that a handler exists in case any
	   * recycled events requiring this handler are pending */
	  pthread_mutex_lock (&(evt->generator_lock));
	  pthread_cond_signal (&(evt->generator_cond));
	  pthread_mutex_unlock (&(evt->generator_lock));
	  return old_handler;
	}
    }

  pool_get (evt->vce_event_handlers, handler);
  handler_index = (u32) (handler - evt->vce_event_handlers);

  handler->handler_fn = cb;
  handler->replaced_handler_idx = (u32) ((p) ? p[0] : ~0);
  handler->ev_idx = (u32) ~ 0;	//This will be set by the event thread if event happens
  handler->evk = evk->as_u64;
  handler->handler_fn_args = cb_args;

  hash_set (evt->handlers_index_by_event_key, evk->as_u64, handler_index);

  pthread_cond_init (&(handler->handler_cond), NULL);
  pthread_mutex_init (&(handler->handler_lock), NULL);

  VCE_HANDLERS_UNLOCK ();

  /* Signal event thread that a new handler exists in case any
   * recycled events requiring this handler are pending */
  pthread_mutex_lock (&(evt->generator_lock));
  pthread_cond_signal (&(evt->generator_cond));
  pthread_mutex_unlock (&(evt->generator_lock));

  return handler;
}

int
vce_unregister_handler (vce_event_thread_t * evt,
			vce_event_handler_reg_t * handler)
{
  uword *p;
  u64 evk = handler->evk;
  u8 generate_signal = 0;

  VCE_HANDLERS_LOCK ();

  p = hash_get (evt->handlers_index_by_event_key, evk);
  if (!p)
    {
      VCE_HANDLERS_UNLOCK ();
      return VNET_API_ERROR_NO_SUCH_ENTRY;
    }

  handler = pool_elt_at_index (evt->vce_event_handlers, p[0]);

  /* If this handler replaced another handler, re-instate it */
  if (handler->replaced_handler_idx != ~0)
    {
      hash_set (evt->handlers_index_by_event_key, evk,
		handler->replaced_handler_idx);
      generate_signal = 1;
    }
  else
    {
      hash_unset (evt->handlers_index_by_event_key, evk);
    }

  pthread_mutex_destroy (&(handler->handler_lock));
  pthread_cond_destroy (&(handler->handler_cond));
  pool_put (evt->vce_event_handlers, handler);

  VCE_HANDLERS_UNLOCK ();

  if (generate_signal)
    {
      /* Signal event thread that a new handler exists in case any
       * recycled events requiring this handler are pending */
      pthread_mutex_lock (&(evt->generator_lock));
      pthread_cond_signal (&(evt->generator_cond));
      pthread_mutex_unlock (&(evt->generator_lock));
    }

  return 0;
}

void *
vce_event_thread_fn (void *arg)
{
  vce_event_thread_t *evt = (vce_event_thread_t *) arg;
  vce_event_t *ev;
  u32 ev_idx;
  vce_event_handler_reg_t *handler;
  uword *p;
  u32 recycle_count = 0;

  pthread_mutex_lock (&(evt->generator_lock));
  while (1)
    {
      uword fifo_depth = clib_fifo_elts (evt->event_index_fifo);
      while ((fifo_depth == 0) || (recycle_count == fifo_depth))
	{
	  recycle_count = 0;
	  pthread_cond_wait (&(evt->generator_cond), &(evt->generator_lock));
	  fifo_depth = clib_fifo_elts (evt->event_index_fifo);
	}

      /* Remove event */
      VCE_EVENTS_LOCK ();
      clib_fifo_sub1 (evt->event_index_fifo, ev_idx);
      ev = vce_get_event_from_index (evt, ev_idx);
      ASSERT (ev);
      if (recycle_count && ev->recycle)
	{
	  clib_fifo_add1 (evt->event_index_fifo, ev_idx);
	  VCE_EVENTS_UNLOCK ();
	  continue;
	}
      VCE_HANDLERS_LOCK ();

      p = hash_get (evt->handlers_index_by_event_key, ev->evk.as_u64);
      if (!p)
	{
	  /* If an event falls in the woods, and there is no handler to hear it,
	   * does it make any sound?
	   * I don't know either, so lets biff the event */
	  pool_put (evt->vce_events, ev);
	  VCE_EVENTS_UNLOCK ();
	  VCE_HANDLERS_UNLOCK ();
	  pthread_mutex_unlock (&(evt->generator_lock));
	}
      else
	{
	  u32 evt_recycle = ev->recycle;
	  handler = pool_elt_at_index (evt->vce_event_handlers, p[0]);
	  handler->ev_idx = ev_idx;
	  ev->recycle = 0;

	  VCE_EVENTS_UNLOCK ();
	  VCE_HANDLERS_UNLOCK ();
	  pthread_mutex_unlock (&(evt->generator_lock));

	  (handler->handler_fn) (handler);

	  VCE_EVENTS_LOCK ();
	  ev = vce_get_event_from_index (evt, ev_idx);
	  recycle_count += (!evt_recycle && ev && ev->recycle) ? 1 : 0;
	  VCE_EVENTS_UNLOCK ();
	}

      pthread_mutex_lock (&(evt->generator_lock));
    }
  return NULL;
}

int
vce_start_event_thread (vce_event_thread_t * evt, u8 max_events)
{
  clib_fifo_validate (evt->event_index_fifo, max_events);
  evt->handlers_index_by_event_key = hash_create (0, sizeof (uword));

  pthread_cond_init (&(evt->generator_cond), NULL);
  pthread_mutex_init (&(evt->generator_lock), NULL);

  clib_spinlock_init (&(evt->events_lockp));
  clib_spinlock_init (&(evt->handlers_lockp));

  return pthread_create (&(evt->thread), NULL /* attr */ ,
			 vce_event_thread_fn, evt);
}

static void *
vppcom_session_io_thread_fn (void *arg)
{
  vppcom_session_io_thread_t *evt = (vppcom_session_io_thread_t *) arg;
  u32 *session_indexes = 0, *session_index;
  int i, rv;
  u32 bytes = 0;
  vcl_session_t *session;

  while (1)
    {
      vec_reset_length (session_indexes);
      VCE_IO_SESSIONS_LOCK ();
      /* *INDENT-OFF* */
      pool_foreach (session_index, evt->active_session_indexes, ({
	vec_add1 (session_indexes, *session_index);
      }));
      /* *INDENT-ON* */
      VCE_IO_SESSIONS_UNLOCK ();
      if (session_indexes)
	{
	  for (i = 0; i < vec_len (session_indexes); ++i)
	    {
	      VCL_SESSION_LOCK_AND_GET (session_indexes[i], &session);
	      bytes = svm_fifo_max_dequeue (session->rx_fifo);
	      VCL_SESSION_UNLOCK ();

	      if (bytes)
		{
		  vppcom_ioevent_t *eio;
		  vce_event_t *ev;
		  u32 ev_idx;

		  VCL_EVENTS_LOCK ();

		  pool_get (vcm->event_thread.vce_events, ev);
		  ev_idx = (u32) (ev - vcm->event_thread.vce_events);
		  eio = vce_get_event_data (ev, sizeof (*eio));
		  ev->evk.eid = VCL_EVENT_IOEVENT_RX_FIFO;
		  ev->evk.session_index = session_indexes[i];
		  eio->bytes = bytes;
		  eio->session_index = session_indexes[i];

		  VCL_EVENTS_UNLOCK ();

		  rv = vce_generate_event (&vcm->event_thread, ev_idx);
		}
	    }
	}
      struct timespec ts;
      ts.tv_sec = 0;
      ts.tv_nsec = 1000000;	/* 1 millisecond */
      nanosleep (&ts, NULL);
    }
done:
  VCL_SESSION_UNLOCK ();
  return NULL;
}

static int
vppcom_start_io_event_thread (vppcom_session_io_thread_t * evt,
			      u8 max_sessions)
{
  pthread_cond_init (&(evt->vce_io_cond), NULL);
  pthread_mutex_init (&(evt->vce_io_lock), NULL);

  clib_spinlock_init (&(evt->io_sessions_lockp));

  return pthread_create (&(evt->thread), NULL /* attr */ ,
			 vppcom_session_io_thread_fn, evt);
}

static void
vce_registered_ioevent_handler_fn (void *arg)
{
  vce_event_handler_reg_t *reg = (vce_event_handler_reg_t *) arg;
  vppcom_ioevent_t *eio;
  vce_event_t *ev;
  u32 ioevt_ndx = (u64) (reg->handler_fn_args);
  vppcom_session_ioevent_t *ioevent, ioevent_;

  VCL_EVENTS_LOCK ();
  ev = vce_get_event_from_index (&vcm->event_thread, reg->ev_idx);
  eio = vce_get_event_data (ev, sizeof (*eio));
  VCL_EVENTS_UNLOCK ();

  VCL_IO_SESSIONS_LOCK ();
  ioevent = pool_elt_at_index (vcm->session_io_thread.ioevents, ioevt_ndx);
  ioevent_ = *ioevent;
  VCL_IO_SESSIONS_UNLOCK ();
  (ioevent_.user_cb) (eio, ioevent_.user_cb_data);
  vce_clear_event (&vcm->event_thread, reg->ev_idx);
  return;

  /*TODO - Unregister check in close for this listener */

}

void
vce_registered_listener_connect_handler_fn (void *arg)
{
  vce_event_handler_reg_t *reg = (vce_event_handler_reg_t *) arg;
  vce_event_connect_request_t *ecr;
  vce_event_t *ev;
  vppcom_endpt_t ep;

  vcl_session_t *new_session;
  int rv;

  vppcom_session_listener_t *session_listener =
    (vppcom_session_listener_t *) reg->handler_fn_args;

  VCL_EVENTS_LOCK ();
  ev = vce_get_event_from_index (&vcm->event_thread, reg->ev_idx);
  ecr = vce_get_event_data (ev, sizeof (*ecr));
  VCL_EVENTS_UNLOCK ();
  VCL_SESSION_LOCK_AND_GET (ecr->accepted_session_index, &new_session);

  ep.is_ip4 = new_session->transport.is_ip4;
  ep.port = new_session->transport.rmt_port;
  if (new_session->transport.is_ip4)
    clib_memcpy (&ep.ip, &new_session->transport.rmt_ip.ip4,
		 sizeof (ip4_address_t));
  else
    clib_memcpy (&ep.ip, &new_session->transport.rmt_ip.ip6,
		 sizeof (ip6_address_t));

  vppcom_send_accept_session_reply (new_session->vpp_handle,
				    new_session->client_context,
				    0 /* retval OK */ );
  VCL_SESSION_UNLOCK ();

  (session_listener->user_cb) (ecr->accepted_session_index, &ep,
			       session_listener->user_cb_data);

  if (vcm->session_io_thread.io_sessions_lockp)
    {
      /* Throw this new accepted session index into the rx poll thread pool */
      VCL_IO_SESSIONS_LOCK ();
      u32 *active_session_index;
      pool_get (vcm->session_io_thread.active_session_indexes,
		active_session_index);
      *active_session_index = ecr->accepted_session_index;
      VCL_IO_SESSIONS_UNLOCK ();
    }

  /*TODO - Unregister check in close for this listener */
  return;

done:
  ASSERT (0);			// If we can't get a lock or accepted session fails, lets blow up.
}

/**
 * @brief vce_poll_wait_connect_request_handler_fn
 * - used by vppcom_epoll_xxxx() for listener sessions
 * - when a vl_api_accept_session_t_handler() generates an event
 *   this callback is alerted and sets the fields that vppcom_epoll_wait()
 *   expects to see.
 *
 * @param arg - void* to be cast to vce_event_handler_reg_t*
 */
void
vce_poll_wait_connect_request_handler_fn (void *arg)
{
  vce_event_handler_reg_t *reg = (vce_event_handler_reg_t *) arg;
  vce_event_t *ev;
  /* Retrieve the VCL_EVENT_CONNECT_REQ_ACCEPTED event */
  ev = vce_get_event_from_index (&vcm->event_thread, reg->ev_idx);
  vce_event_connect_request_t *ecr = vce_get_event_data (ev, sizeof (*ecr));

  /* Add the accepted_session_index to the FIFO */
  VCL_ACCEPT_FIFO_LOCK ();
  clib_fifo_add1 (vcm->client_session_index_fifo,
		  ecr->accepted_session_index);
  VCL_ACCEPT_FIFO_UNLOCK ();

  /* Recycling the event. */
  VCL_EVENTS_LOCK ();
  ev->recycle = 1;
  clib_fifo_add1 (vcm->event_thread.event_index_fifo, reg->ev_idx);
  VCL_EVENTS_UNLOCK ();
}

int
vppcom_session_register_ioevent_cb (uint32_t session_index,
				    vppcom_session_ioevent_cb cb,
				    uint8_t rx, void *ptr)
{
  int rv = VPPCOM_OK;
  vce_event_key_t evk;
  vppcom_session_ioevent_t *ioevent;

  if (!vcm->session_io_thread.io_sessions_lockp)
    rv = vppcom_start_io_event_thread (&vcm->session_io_thread, 100);	/* DAW_TODO: ??? hard-coded value */

  if (rv == VPPCOM_OK)
    {
      void *io_evt_ndx;

      /* Register handler for ioevent on session_index */
      VCL_IO_SESSIONS_LOCK ();
      pool_get (vcm->session_io_thread.ioevents, ioevent);
      io_evt_ndx = (void *) (ioevent - vcm->session_io_thread.ioevents);
      ioevent->user_cb = cb;
      ioevent->user_cb_data = ptr;
      VCL_IO_SESSIONS_UNLOCK ();

      evk.session_index = session_index;
      evk.eid = rx ? VCL_EVENT_IOEVENT_RX_FIFO : VCL_EVENT_IOEVENT_TX_FIFO;

      (void) vce_register_handler (&vcm->event_thread, &evk,
				   vce_registered_ioevent_handler_fn,
				   io_evt_ndx);
    }
  return rv;
}

int
vppcom_session_register_listener (uint32_t session_index,
				  vppcom_session_listener_cb cb,
				  vppcom_session_listener_errcb
				  errcb, uint8_t flags, int q_len, void *ptr)
{
  int rv = VPPCOM_OK;
  vce_event_key_t evk;
  vppcom_session_listener_t *listener_args;

  if (!vcm->session_io_thread.io_sessions_lockp)
    rv = vppcom_start_io_event_thread (&vcm->session_io_thread, 100);	/* DAW_TODO: ??? hard-coded value */
  if (rv)
    {
      goto done;
    }
  rv = vppcom_session_listen (session_index, q_len);
  if (rv)
    {
      goto done;
    }

  /* Register handler for connect_request event on listen_session_index */
  listener_args = clib_mem_alloc (sizeof (vppcom_session_listener_t));	// DAW_TODO: Use a pool instead of thrashing the memory allocator!
  listener_args->user_cb = cb;
  listener_args->user_cb_data = ptr;
  listener_args->user_errcb = errcb;

  evk.session_index = session_index;
  evk.eid = VCL_EVENT_CONNECT_REQ_ACCEPTED;
  (void) vce_register_handler (&vcm->event_thread, &evk,
			       vce_registered_listener_connect_handler_fn,
			       listener_args);

done:
  return rv;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
