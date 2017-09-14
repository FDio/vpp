/*
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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
/**
 * @file
 * @brief Session and session manager
 */

#include <vnet/session/session.h>
#include <vnet/session/session_debug.h>
#include <vnet/session/application.h>
#include <vlibmemory/api.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/tcp/tcp.h>

session_manager_main_t session_manager_main;
extern transport_proto_vft_t *tp_vfts;

int
stream_session_create_i (segment_manager_t * sm, transport_connection_t * tc,
			 u8 alloc_fifos, stream_session_t ** ret_s)
{
  session_manager_main_t *smm = &session_manager_main;
  svm_fifo_t *server_rx_fifo = 0, *server_tx_fifo = 0;
  u32 fifo_segment_index;
  u32 pool_index;
  stream_session_t *s;
  u64 value;
  u32 thread_index = tc->thread_index;
  int rv;

  ASSERT (thread_index == vlib_get_thread_index ());

  /* Create the session */
  pool_get_aligned (smm->sessions[thread_index], s, CLIB_CACHE_LINE_BYTES);
  memset (s, 0, sizeof (*s));
  pool_index = s - smm->sessions[thread_index];

  /* Allocate fifos */
  if (alloc_fifos)
    {
      if ((rv = segment_manager_alloc_session_fifos (sm, &server_rx_fifo,
						     &server_tx_fifo,
						     &fifo_segment_index)))
	{
	  pool_put (smm->sessions[thread_index], s);
	  return rv;
	}
      /* Initialize backpointers */
      server_rx_fifo->master_session_index = pool_index;
      server_rx_fifo->master_thread_index = thread_index;

      server_tx_fifo->master_session_index = pool_index;
      server_tx_fifo->master_thread_index = thread_index;

      s->server_rx_fifo = server_rx_fifo;
      s->server_tx_fifo = server_tx_fifo;
      s->svm_segment_index = fifo_segment_index;
    }

  /* Initialize state machine, such as it is... */
  s->session_type = session_type_from_proto_and_ip (tc->transport_proto,
						    tc->is_ip4);
  s->session_state = SESSION_STATE_CONNECTING;
  s->thread_index = thread_index;
  s->session_index = pool_index;

  /* Attach transport to session */
  s->connection_index = tc->c_index;

  /* Attach session to transport */
  tc->s_index = s->session_index;

  /* Add to the main lookup table */
  value = stream_session_handle (s);
  stream_session_table_add_for_tc (tc, value);

  *ret_s = s;

  return 0;
}

/**
 * Discards bytes from buffer chain
 *
 * It discards n_bytes_to_drop starting at first buffer after chain_b
 */
always_inline void
session_enqueue_discard_chain_bytes (vlib_main_t * vm, vlib_buffer_t * b,
				     vlib_buffer_t ** chain_b,
				     u32 n_bytes_to_drop)
{
  vlib_buffer_t *next = *chain_b;
  u32 to_drop = n_bytes_to_drop;
  ASSERT (b->flags & VLIB_BUFFER_NEXT_PRESENT);
  while (to_drop && (next->flags & VLIB_BUFFER_NEXT_PRESENT))
    {
      next = vlib_get_buffer (vm, next->next_buffer);
      if (next->current_length > to_drop)
	{
	  vlib_buffer_advance (next, to_drop);
	  to_drop = 0;
	}
      else
	{
	  to_drop -= next->current_length;
	  next->current_length = 0;
	}
    }
  *chain_b = next;

  if (to_drop == 0)
    b->total_length_not_including_first_buffer -= n_bytes_to_drop;
}

/**
 * Enqueue buffer chain tail
 */
always_inline int
session_enqueue_chain_tail (stream_session_t * s, vlib_buffer_t * b,
			    u32 offset, u8 is_in_order)
{
  vlib_buffer_t *chain_b;
  u32 chain_bi, len, diff;
  vlib_main_t *vm = vlib_get_main ();
  u8 *data;
  u32 written = 0;
  int rv = 0;

  if (is_in_order && offset)
    {
      diff = offset - b->current_length;
      if (diff > b->total_length_not_including_first_buffer)
	return 0;
      chain_b = b;
      session_enqueue_discard_chain_bytes (vm, b, &chain_b, diff);
      chain_bi = vlib_get_buffer_index (vm, chain_b);
    }
  else
    chain_bi = b->next_buffer;

  do
    {
      chain_b = vlib_get_buffer (vm, chain_bi);
      data = vlib_buffer_get_current (chain_b);
      len = chain_b->current_length;
      if (!len)
	continue;
      if (is_in_order)
	{
	  rv = svm_fifo_enqueue_nowait (s->server_rx_fifo, len, data);
	  if (rv == len)
	    {
	      written += rv;
	    }
	  else if (rv < len)
	    {
	      return (rv > 0) ? (written + rv) : written;
	    }
	  else if (rv > len)
	    {
	      written += rv;

	      /* written more than what was left in chain */
	      if (written > b->total_length_not_including_first_buffer)
		return written;

	      /* drop the bytes that have already been delivered */
	      session_enqueue_discard_chain_bytes (vm, b, &chain_b, rv - len);
	    }
	}
      else
	{
	  rv = svm_fifo_enqueue_with_offset (s->server_rx_fifo, offset, len,
					     data);
	  if (rv)
	    {
	      clib_warning ("failed to enqueue multi-buffer seg");
	      return -1;
	    }
	  offset += len;
	}
    }
  while ((chain_bi = (chain_b->flags & VLIB_BUFFER_NEXT_PRESENT)
	  ? chain_b->next_buffer : 0));

  if (is_in_order)
    return written;

  return 0;
}

/*
 * Enqueue data for delivery to session peer. Does not notify peer of enqueue
 * event but on request can queue notification events for later delivery by
 * calling stream_server_flush_enqueue_events().
 *
 * @param tc Transport connection which is to be enqueued data
 * @param b Buffer to be enqueued
 * @param offset Offset at which to start enqueueing if out-of-order
 * @param queue_event Flag to indicate if peer is to be notified or if event
 *                    is to be queued. The former is useful when more data is
 *                    enqueued and only one event is to be generated.
 * @param is_in_order Flag to indicate if data is in order
 * @return Number of bytes enqueued or a negative value if enqueueing failed.
 */
int
stream_session_enqueue_data (transport_connection_t * tc, vlib_buffer_t * b,
			     u32 offset, u8 queue_event, u8 is_in_order)
{
  stream_session_t *s;
  int enqueued = 0, rv, in_order_off;

  s = stream_session_get (tc->s_index, tc->thread_index);

  if (is_in_order)
    {
      enqueued = svm_fifo_enqueue_nowait (s->server_rx_fifo,
					  b->current_length,
					  vlib_buffer_get_current (b));
      if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT)
			 && enqueued >= 0))
	{
	  in_order_off = enqueued > b->current_length ? enqueued : 0;
	  rv = session_enqueue_chain_tail (s, b, in_order_off, 1);
	  if (rv > 0)
	    enqueued += rv;
	}
    }
  else
    {
      rv = svm_fifo_enqueue_with_offset (s->server_rx_fifo, offset,
					 b->current_length,
					 vlib_buffer_get_current (b));
      if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && !rv))
	session_enqueue_chain_tail (s, b, offset + b->current_length, 0);
      /* if something was enqueued, report even this as success for ooo
       * segment handling */
      return rv;
    }

  if (queue_event)
    {
      /* Queue RX event on this fifo. Eventually these will need to be flushed
       * by calling stream_server_flush_enqueue_events () */
      session_manager_main_t *smm = vnet_get_session_manager_main ();
      u32 thread_index = s->thread_index;
      u32 my_enqueue_epoch = smm->current_enqueue_epoch[thread_index];

      if (s->enqueue_epoch != my_enqueue_epoch)
	{
	  s->enqueue_epoch = my_enqueue_epoch;
	  vec_add1 (smm->session_indices_to_enqueue_by_thread[thread_index],
		    s - smm->sessions[thread_index]);
	}
    }

  if (is_in_order)
    return enqueued;

  return 0;
}

/** Check if we have space in rx fifo to push more bytes */
u8
stream_session_no_space (transport_connection_t * tc, u32 thread_index,
			 u16 data_len)
{
  stream_session_t *s = stream_session_get (tc->s_index, thread_index);

  if (PREDICT_FALSE (s->session_state != SESSION_STATE_READY))
    return 1;

  if (data_len > svm_fifo_max_enqueue (s->server_rx_fifo))
    return 1;

  return 0;
}

u32
stream_session_tx_fifo_max_dequeue (transport_connection_t * tc)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  if (!s->server_tx_fifo)
    return 0;
  return svm_fifo_max_dequeue (s->server_tx_fifo);
}

int
stream_session_peek_bytes (transport_connection_t * tc, u8 * buffer,
			   u32 offset, u32 max_bytes)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return svm_fifo_peek (s->server_tx_fifo, offset, max_bytes, buffer);
}

u32
stream_session_dequeue_drop (transport_connection_t * tc, u32 max_bytes)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return svm_fifo_dequeue_drop (s->server_tx_fifo, max_bytes);
}

/**
 * Notify session peer that new data has been enqueued.
 *
 * @param s Stream session for which the event is to be generated.
 * @param block Flag to indicate if call should block if event queue is full.
 *
 * @return 0 on succes or negative number if failed to send notification.
 */
static int
stream_session_enqueue_notify (stream_session_t * s, u8 block)
{
  application_t *app;
  session_fifo_event_t evt;
  unix_shared_memory_queue_t *q;
  static u32 serial_number;

  if (PREDICT_FALSE (s->session_state == SESSION_STATE_CLOSED))
    {
      /* Session is closed so app will never clean up. Flush rx fifo */
      u32 to_dequeue = svm_fifo_max_dequeue (s->server_rx_fifo);
      if (to_dequeue)
	svm_fifo_dequeue_drop (s->server_rx_fifo, to_dequeue);
      return 0;
    }

  /* Get session's server */
  app = application_get_if_valid (s->app_index);

  if (PREDICT_FALSE (app == 0))
    {
      clib_warning ("invalid s->app_index = %d", s->app_index);
      return 0;
    }

  /* Built-in server? Hand event to the callback... */
  if (app->cb_fns.builtin_server_rx_callback)
    return app->cb_fns.builtin_server_rx_callback (s);

  /* If no event, send one */
  if (svm_fifo_set_event (s->server_rx_fifo))
    {
      /* Fabricate event */
      evt.fifo = s->server_rx_fifo;
      evt.event_type = FIFO_EVENT_APP_RX;
      evt.event_id = serial_number++;

      /* Add event to server's event queue */
      q = app->event_queue;

      /* Based on request block (or not) for lack of space */
      if (block || PREDICT_TRUE (q->cursize < q->maxsize))
	unix_shared_memory_queue_add (app->event_queue, (u8 *) & evt,
				      0 /* do wait for mutex */ );
      else
	{
	  clib_warning ("fifo full");
	  return -1;
	}
    }

  /* *INDENT-OFF* */
  SESSION_EVT_DBG(SESSION_EVT_ENQ, s, ({
      ed->data[0] = evt.event_id;
      ed->data[1] = svm_fifo_max_dequeue (s->server_rx_fifo);
  }));
  /* *INDENT-ON* */

  return 0;
}

/**
 * Flushes queue of sessions that are to be notified of new data
 * enqueued events.
 *
 * @param thread_index Thread index for which the flush is to be performed.
 * @return 0 on success or a positive number indicating the number of
 *         failures due to API queue being full.
 */
int
session_manager_flush_enqueue_events (u32 thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  u32 *session_indices_to_enqueue;
  int i, errors = 0;

  session_indices_to_enqueue =
    smm->session_indices_to_enqueue_by_thread[thread_index];

  for (i = 0; i < vec_len (session_indices_to_enqueue); i++)
    {
      stream_session_t *s0;

      /* Get session */
      s0 = stream_session_get_if_valid (session_indices_to_enqueue[i],
					thread_index);
      if (s0 == 0 || stream_session_enqueue_notify (s0, 0 /* don't block */ ))
	{
	  errors++;
	}
    }

  vec_reset_length (session_indices_to_enqueue);

  smm->session_indices_to_enqueue_by_thread[thread_index] =
    session_indices_to_enqueue;

  /* Increment enqueue epoch for next round */
  smm->current_enqueue_epoch[thread_index]++;

  return errors;
}

/**
 * Init fifo tail and head pointers
 *
 * Useful if transport uses absolute offsets for tracking ooo segments.
 */
void
stream_session_init_fifos_pointers (transport_connection_t * tc,
				    u32 rx_pointer, u32 tx_pointer)
{
  stream_session_t *s;
  s = stream_session_get (tc->s_index, tc->thread_index);
  svm_fifo_init_pointers (s->server_rx_fifo, rx_pointer);
  svm_fifo_init_pointers (s->server_tx_fifo, tx_pointer);
}

int
stream_session_connect_notify (transport_connection_t * tc, u8 is_fail)
{
  application_t *app;
  stream_session_t *new_s = 0;
  u64 handle;
  u32 opaque = 0;
  int error = 0;
  u8 st;

  st = session_type_from_proto_and_ip (tc->transport_proto, tc->is_ip4);
  handle = stream_session_half_open_lookup_handle (&tc->lcl_ip, &tc->rmt_ip,
						   tc->lcl_port, tc->rmt_port,
						   st);
  if (handle == HALF_OPEN_LOOKUP_INVALID_VALUE)
    {
      TCP_DBG ("half-open was removed!");
      return -1;
    }

  /* Cleanup half-open table */
  stream_session_half_open_table_del (tc);

  /* Get the app's index from the handle we stored when opening connection
   * and the opaque (api_context for external apps) from transport session
   * index */
  app = application_get_if_valid (handle >> 32);
  if (!app)
    return -1;

  opaque = tc->s_index;

  if (!is_fail)
    {
      segment_manager_t *sm;
      u8 alloc_fifos;
      sm = application_get_connect_segment_manager (app);
      alloc_fifos = application_is_proxy (app);
      /* Create new session (svm segments are allocated if needed) */
      if (stream_session_create_i (sm, tc, alloc_fifos, &new_s))
	{
	  is_fail = 1;
	  error = -1;
	}
      else
	new_s->app_index = app->index;
    }

  /* Notify client application */
  if (app->cb_fns.session_connected_callback (app->index, opaque, new_s,
					      is_fail))
    {
      clib_warning ("failed to notify app");
      if (!is_fail)
	stream_session_disconnect (new_s);
    }
  else
    {
      if (!is_fail)
	new_s->session_state = SESSION_STATE_READY;
    }

  return error;
}

void
stream_session_accept_notify (transport_connection_t * tc)
{
  application_t *server;
  stream_session_t *s;

  s = stream_session_get (tc->s_index, tc->thread_index);
  server = application_get (s->app_index);
  server->cb_fns.session_accept_callback (s);
}

/**
 * Notification from transport that connection is being closed.
 *
 * A disconnect is sent to application but state is not removed. Once
 * disconnect is acknowledged by application, session disconnect is called.
 * Ultimately this leads to close being called on transport (passive close).
 */
void
stream_session_disconnect_notify (transport_connection_t * tc)
{
  application_t *server;
  stream_session_t *s;

  s = stream_session_get (tc->s_index, tc->thread_index);
  server = application_get (s->app_index);
  server->cb_fns.session_disconnect_callback (s);
}

/**
 * Cleans up session and lookup table.
 */
void
stream_session_delete (stream_session_t * s)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  int rv;

  /* Delete from the main lookup table. */
  if ((rv = stream_session_table_del (s)))
    clib_warning ("hash delete error, rv %d", rv);

  /* Cleanup fifo segments */
  segment_manager_dealloc_fifos (s->svm_segment_index, s->server_rx_fifo,
				 s->server_tx_fifo);

  pool_put (smm->sessions[s->thread_index], s);
  if (CLIB_DEBUG)
    memset (s, 0xFA, sizeof (*s));
}

/**
 * Notification from transport that connection is being deleted
 *
 * This removes the session if it is still valid. It should be called only on
 * previously fully established sessions. For instance failed connects should
 * call stream_session_connect_notify and indicate that the connect has
 * failed.
 */
void
stream_session_delete_notify (transport_connection_t * tc)
{
  stream_session_t *s;

  /* App might've been removed already */
  s = stream_session_get_if_valid (tc->s_index, tc->thread_index);
  if (!s)
    return;
  stream_session_delete (s);
}

/**
 * Notify application that connection has been reset.
 */
void
stream_session_reset_notify (transport_connection_t * tc)
{
  stream_session_t *s;
  application_t *app;
  s = stream_session_get (tc->s_index, tc->thread_index);

  app = application_get (s->app_index);
  app->cb_fns.session_reset_callback (s);
}

/**
 * Accept a stream session. Optionally ping the server by callback.
 */
int
stream_session_accept (transport_connection_t * tc, u32 listener_index,
		       u8 sst, u8 notify)
{
  application_t *server;
  stream_session_t *s, *listener;
  segment_manager_t *sm;

  int rv;

  /* Find the server */
  listener = listen_session_get (sst, listener_index);
  server = application_get (listener->app_index);

  sm = application_get_listen_segment_manager (server, listener);
  if ((rv = stream_session_create_i (sm, tc, 1, &s)))
    return rv;

  s->app_index = server->index;
  s->listener_index = listener_index;
  s->session_state = SESSION_STATE_ACCEPTING;

  /* Shoulder-tap the server */
  if (notify)
    {
      server->cb_fns.session_accept_callback (s);
    }

  return 0;
}

/**
 * Ask transport to open connection to remote transport endpoint.
 *
 * Stores handle for matching request with reply since the call can be
 * asynchronous. For instance, for TCP the 3-way handshake must complete
 * before reply comes. Session is only created once connection is established.
 *
 * @param app_index Index of the application requesting the connect
 * @param st Session type requested.
 * @param tep Remote transport endpoint
 * @param res Resulting transport connection .
 */
int
stream_session_open (u32 app_index, session_type_t st,
		     transport_endpoint_t * rmt,
		     transport_connection_t ** res)
{
  transport_connection_t *tc;
  int rv;
  u64 handle;

  rv = tp_vfts[st].open (rmt);
  if (rv < 0)
    {
      clib_warning ("Transport failed to open connection.");
      return VNET_API_ERROR_SESSION_CONNECT_FAIL;
    }

  tc = tp_vfts[st].get_half_open ((u32) rv);

  /* Save app and tc index. The latter is needed to help establish the
   * connection while the former is needed when the connect notify comes
   * and we have to notify the external app */
  handle = (((u64) app_index) << 32) | (u64) tc->c_index;

  /* Add to the half-open lookup table */
  stream_session_half_open_table_add (tc, handle);

  *res = tc;

  return 0;
}

/**
 * Ask transport to listen on local transport endpoint.
 *
 * @param s Session for which listen will be called. Note that unlike
 * 	    established sessions, listen sessions are not associated to a
 * 	    thread.
 * @param tep Local endpoint to be listened on.
 */
int
stream_session_listen (stream_session_t * s, transport_endpoint_t * tep)
{
  transport_connection_t *tc;
  u32 tci;

  /* Transport bind/listen  */
  tci = tp_vfts[s->session_type].bind (s->session_index, tep);

  if (tci == (u32) ~ 0)
    return -1;

  /* Attach transport to session */
  s->connection_index = tci;
  tc = tp_vfts[s->session_type].get_listener (tci);

  /* Weird but handle it ... */
  if (tc == 0)
    return -1;

  /* Add to the main lookup table */
  stream_session_table_add_for_tc (tc, s->session_index);

  return 0;
}

/**
 * Ask transport to stop listening on local transport endpoint.
 *
 * @param s Session to stop listening on. It must be in state LISTENING.
 */
int
stream_session_stop_listen (stream_session_t * s)
{
  transport_connection_t *tc;

  if (s->session_state != SESSION_STATE_LISTENING)
    {
      clib_warning ("not a listening session");
      return -1;
    }

  tc = tp_vfts[s->session_type].get_listener (s->connection_index);
  if (!tc)
    {
      clib_warning ("no transport");
      return VNET_API_ERROR_ADDRESS_NOT_IN_USE;
    }

  stream_session_table_del_for_tc (tc);
  tp_vfts[s->session_type].unbind (s->connection_index);
  return 0;
}

void
session_send_session_evt_to_thread (u64 session_handle,
				    fifo_event_type_t evt_type,
				    u32 thread_index)
{
  static u16 serial_number = 0;
  u32 tries = 0;
  session_fifo_event_t evt;
  unix_shared_memory_queue_t *q;

  /* Fabricate event */
  evt.session_handle = session_handle;
  evt.event_type = evt_type;
  evt.event_id = serial_number++;

  q = session_manager_get_vpp_event_queue (thread_index);
  while (unix_shared_memory_queue_add (q, (u8 *) & evt, 1))
    {
      if (tries++ == 3)
	{
	  TCP_DBG ("failed to enqueue evt");
	  break;
	}
    }
}

/**
 * Disconnect session and propagate to transport. This should eventually
 * result in a delete notification that allows us to cleanup session state.
 * Called for both active/passive disconnects.
 *
 * Should be called from the session's thread.
 */
void
stream_session_disconnect (stream_session_t * s)
{
  s->session_state = SESSION_STATE_CLOSED;
  tp_vfts[s->session_type].close (s->connection_index, s->thread_index);
}

/**
 * Cleanup transport and session state.
 *
 * Notify transport of the cleanup, wait for a delete notify to actually
 * remove the session state.
 */
void
stream_session_cleanup (stream_session_t * s)
{
  int rv;

  s->session_state = SESSION_STATE_CLOSED;

  /* Delete from the main lookup table to avoid more enqueues */
  rv = stream_session_table_del (s);
  if (rv)
    clib_warning ("hash delete error, rv %d", rv);

  tp_vfts[s->session_type].cleanup (s->connection_index, s->thread_index);
}

/**
 * Allocate vpp event queue (once) per worker thread
 */
void
session_vpp_event_queue_allocate (session_manager_main_t * smm,
				  u32 thread_index)
{
  api_main_t *am = &api_main;
  void *oldheap;
  u32 event_queue_length = 2048;

  if (smm->vpp_event_queues[thread_index] == 0)
    {
      /* Allocate event fifo in the /vpe-api shared-memory segment */
      oldheap = svm_push_data_heap (am->vlib_rp);

      if (smm->configured_event_queue_length)
	event_queue_length = smm->configured_event_queue_length;

      smm->vpp_event_queues[thread_index] =
	unix_shared_memory_queue_init
	(event_queue_length,
	 sizeof (session_fifo_event_t), 0 /* consumer pid */ ,
	 0 /* (do not) send signal when queue non-empty */ );

      svm_pop_heap (oldheap);
    }
}

session_type_t
session_type_from_proto_and_ip (transport_proto_t proto, u8 is_ip4)
{
  if (proto == TRANSPORT_PROTO_TCP)
    {
      if (is_ip4)
	return SESSION_TYPE_IP4_TCP;
      else
	return SESSION_TYPE_IP6_TCP;
    }
  else
    {
      if (is_ip4)
	return SESSION_TYPE_IP4_UDP;
      else
	return SESSION_TYPE_IP6_UDP;
    }

  return SESSION_N_TYPES;
}

static clib_error_t *
session_manager_main_enable (vlib_main_t * vm)
{
  session_manager_main_t *smm = &session_manager_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  u32 preallocated_sessions_per_worker;
  int i;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  if (num_threads < 1)
    return clib_error_return (0, "n_thread_stacks not set");

  /* $$$ config parameters */
  svm_fifo_segment_init (0x200000000ULL /* first segment base VA */ ,
			 20 /* timeout in seconds */ );

  /* configure per-thread ** vectors */
  vec_validate (smm->sessions, num_threads - 1);
  vec_validate (smm->session_indices_to_enqueue_by_thread, num_threads - 1);
  vec_validate (smm->tx_buffers, num_threads - 1);
  vec_validate (smm->pending_event_vector, num_threads - 1);
  vec_validate (smm->free_event_vector, num_threads - 1);
  vec_validate (smm->current_enqueue_epoch, num_threads - 1);
  vec_validate (smm->vpp_event_queues, num_threads - 1);

  for (i = 0; i < num_threads; i++)
    {
      vec_validate (smm->free_event_vector[i], 0);
      _vec_len (smm->free_event_vector[i]) = 0;
      vec_validate (smm->pending_event_vector[i], 0);
      _vec_len (smm->pending_event_vector[i]) = 0;
    }

#if SESSION_DBG
  vec_validate (smm->last_event_poll_by_thread, num_threads - 1);
#endif

  /* Allocate vpp event queues */
  for (i = 0; i < vec_len (smm->vpp_event_queues); i++)
    session_vpp_event_queue_allocate (smm, i);

  /* Preallocate sessions */
  if (smm->preallocated_sessions)
    {
      if (num_threads == 1)
	{
	  pool_init_fixed (smm->sessions[0], smm->preallocated_sessions);
	}
      else
	{
	  int j;
	  preallocated_sessions_per_worker =
	    (1.1 * (f64) smm->preallocated_sessions /
	     (f64) (num_threads - 1));

	  for (j = 1; j < num_threads; j++)
	    {
	      pool_init_fixed (smm->sessions[j],
			       preallocated_sessions_per_worker);
	    }
	}
    }

  session_lookup_init ();

  smm->is_enabled = 1;

  /* Enable TCP transport */
  vnet_tcp_enable_disable (vm, 1);

  return 0;
}

void
session_node_enable_disable (u8 is_en)
{
  u8 state = is_en ? VLIB_NODE_STATE_POLLING : VLIB_NODE_STATE_DISABLED;
  /* *INDENT-OFF* */
  foreach_vlib_main (({
    vlib_node_set_state (this_vlib_main, session_queue_node.index,
                         state);
  }));
  /* *INDENT-ON* */
}

clib_error_t *
vnet_session_enable_disable (vlib_main_t * vm, u8 is_en)
{
  if (is_en)
    {
      if (session_manager_main.is_enabled)
	return 0;

      session_node_enable_disable (is_en);

      return session_manager_main_enable (vm);
    }
  else
    {
      session_manager_main.is_enabled = 0;
      session_node_enable_disable (is_en);
    }

  return 0;
}

clib_error_t *
session_manager_main_init (vlib_main_t * vm)
{
  session_manager_main_t *smm = &session_manager_main;
  smm->is_enabled = 0;
  return 0;
}

VLIB_INIT_FUNCTION (session_manager_main_init);

static clib_error_t *
session_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  session_manager_main_t *smm = &session_manager_main;
  u32 nitems;
  uword tmp;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "event-queue-length %d", &nitems))
	{
	  if (nitems >= 2048)
	    smm->configured_event_queue_length = nitems;
	  else
	    clib_warning ("event queue length %d too small, ignored", nitems);
	}
      else if (unformat (input, "preallocated-sessions %d",
			 &smm->preallocated_sessions))
	;
      else if (unformat (input, "v4-session-table-buckets %d",
			 &smm->configured_v4_session_table_buckets))
	;
      else if (unformat (input, "v4-halfopen-table-buckets %d",
			 &smm->configured_v4_halfopen_table_buckets))
	;
      else if (unformat (input, "v6-session-table-buckets %d",
			 &smm->configured_v6_session_table_buckets))
	;
      else if (unformat (input, "v6-halfopen-table-buckets %d",
			 &smm->configured_v6_halfopen_table_buckets))
	;
      else if (unformat (input, "v4-session-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v4_session_table_memory = tmp;
	}
      else if (unformat (input, "v4-halfopen-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v4_halfopen_table_memory = tmp;
	}
      else if (unformat (input, "v6-session-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v6_session_table_memory = tmp;
	}
      else if (unformat (input, "v6-halfopen-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->configured_v6_halfopen_table_memory = tmp;
	}
      else
	return clib_error_return (0, "unknown input `%U'",
				  format_unformat_error, input);
    }
  return 0;
}

VLIB_CONFIG_FUNCTION (session_config_fn, "session");

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
