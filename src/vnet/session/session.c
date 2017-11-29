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

static void
session_send_evt_to_thread (u64 session_handle, fifo_event_type_t evt_type,
			    u32 thread_index, void *fp, void *rpc_args)
{
  u32 tries = 0;
  session_fifo_event_t evt = { {0}, };
  unix_shared_memory_queue_t *q;

  evt.event_type = evt_type;
  if (evt_type == FIFO_EVENT_RPC)
    {
      evt.rpc_args.fp = fp;
      evt.rpc_args.arg = rpc_args;
    }
  else
    evt.session_handle = session_handle;

  q = session_manager_get_vpp_event_queue (thread_index);
  while (unix_shared_memory_queue_add (q, (u8 *) & evt, 1))
    {
      if (tries++ == 3)
	{
	  SESSION_DBG ("failed to enqueue evt");
	  break;
	}
    }
}

void
session_send_session_evt_to_thread (u64 session_handle,
				    fifo_event_type_t evt_type,
				    u32 thread_index)
{
  session_send_evt_to_thread (session_handle, evt_type, thread_index, 0, 0);
}

void
session_send_rpc_evt_to_thread (u32 thread_index, void *fp, void *rpc_args)
{
  if (thread_index != vlib_get_thread_index ())
    session_send_evt_to_thread (0, FIFO_EVENT_RPC, thread_index, fp,
				rpc_args);
  else
    {
      void (*fnp) (void *) = fp;
      fnp (rpc_args);
    }
}

stream_session_t *
session_alloc (u32 thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  stream_session_t *s;
  u8 will_expand = 0;
  pool_get_aligned_will_expand (smm->sessions[thread_index], will_expand,
				CLIB_CACHE_LINE_BYTES);
  /* If we have peekers, let them finish */
  if (PREDICT_FALSE (will_expand))
    {
      clib_spinlock_lock_if_init (&smm->peekers_write_locks[thread_index]);
      pool_get_aligned (session_manager_main.sessions[thread_index], s,
			CLIB_CACHE_LINE_BYTES);
      clib_spinlock_unlock_if_init (&smm->peekers_write_locks[thread_index]);
    }
  else
    {
      pool_get_aligned (session_manager_main.sessions[thread_index], s,
			CLIB_CACHE_LINE_BYTES);
    }
  memset (s, 0, sizeof (*s));
  s->session_index = s - session_manager_main.sessions[thread_index];
  s->thread_index = thread_index;
  return s;
}

static void
session_free (stream_session_t * s)
{
  pool_put (session_manager_main.sessions[s->thread_index], s);
  if (CLIB_DEBUG)
    memset (s, 0xFA, sizeof (*s));
}

static int
session_alloc_fifos (segment_manager_t * sm, stream_session_t * s)
{
  svm_fifo_t *server_rx_fifo = 0, *server_tx_fifo = 0;
  u32 fifo_segment_index;
  int rv;

  if ((rv = segment_manager_alloc_session_fifos (sm, &server_rx_fifo,
						 &server_tx_fifo,
						 &fifo_segment_index)))
    return rv;
  /* Initialize backpointers */
  server_rx_fifo->master_session_index = s->session_index;
  server_rx_fifo->master_thread_index = s->thread_index;

  server_tx_fifo->master_session_index = s->session_index;
  server_tx_fifo->master_thread_index = s->thread_index;

  s->server_rx_fifo = server_rx_fifo;
  s->server_tx_fifo = server_tx_fifo;
  s->svm_segment_index = fifo_segment_index;
  return 0;
}

static stream_session_t *
session_alloc_for_connection (transport_connection_t * tc)
{
  stream_session_t *s;
  u32 thread_index = tc->thread_index;

  ASSERT (thread_index == vlib_get_thread_index ());

  s = session_alloc (thread_index);
  s->session_type = session_type_from_proto_and_ip (tc->proto, tc->is_ip4);
  s->session_state = SESSION_STATE_CONNECTING;

  /* Attach transport to session and vice versa */
  s->connection_index = tc->c_index;
  tc->s_index = s->session_index;
  return s;
}

static int
session_alloc_and_init (segment_manager_t * sm, transport_connection_t * tc,
			u8 alloc_fifos, stream_session_t ** ret_s)
{
  stream_session_t *s;
  int rv;

  s = session_alloc_for_connection (tc);
  if (alloc_fifos && (rv = session_alloc_fifos (sm, s)))
    {
      session_free (s);
      *ret_s = 0;
      return rv;
    }

  /* Add to the main lookup table */
  session_lookup_add_connection (tc, session_handle (s));

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
session_enqueue_stream_connection (transport_connection_t * tc,
				   vlib_buffer_t * b, u32 offset,
				   u8 queue_event, u8 is_in_order)
{
  stream_session_t *s;
  int enqueued = 0, rv, in_order_off;

  s = session_get (tc->s_index, tc->thread_index);

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
      u32 enqueue_epoch = smm->current_enqueue_epoch[tc->proto][thread_index];

      if (s->enqueue_epoch != enqueue_epoch)
	{
	  s->enqueue_epoch = enqueue_epoch;
	  vec_add1 (smm->session_to_enqueue[tc->proto][thread_index],
		    s - smm->sessions[thread_index]);
	}
    }

  return enqueued;
}

int
session_enqueue_dgram_connection (stream_session_t * s, vlib_buffer_t * b,
				  u8 proto, u8 queue_event)
{
  int enqueued = 0, rv, in_order_off;

  if (svm_fifo_max_enqueue (s->server_rx_fifo) < b->current_length)
    return -1;
  enqueued = svm_fifo_enqueue_nowait (s->server_rx_fifo, b->current_length,
				      vlib_buffer_get_current (b));
  if (PREDICT_FALSE ((b->flags & VLIB_BUFFER_NEXT_PRESENT) && enqueued >= 0))
    {
      in_order_off = enqueued > b->current_length ? enqueued : 0;
      rv = session_enqueue_chain_tail (s, b, in_order_off, 1);
      if (rv > 0)
	enqueued += rv;
    }
  if (queue_event)
    {
      /* Queue RX event on this fifo. Eventually these will need to be flushed
       * by calling stream_server_flush_enqueue_events () */
      session_manager_main_t *smm = vnet_get_session_manager_main ();
      u32 thread_index = s->thread_index;
      u32 enqueue_epoch = smm->current_enqueue_epoch[proto][thread_index];

      if (s->enqueue_epoch != enqueue_epoch)
	{
	  s->enqueue_epoch = enqueue_epoch;
	  vec_add1 (smm->session_to_enqueue[proto][thread_index],
		    s - smm->sessions[thread_index]);
	}
    }
  return enqueued;
}

/** Check if we have space in rx fifo to push more bytes */
u8
stream_session_no_space (transport_connection_t * tc, u32 thread_index,
			 u16 data_len)
{
  stream_session_t *s = session_get (tc->s_index, thread_index);

  if (PREDICT_FALSE (s->session_state != SESSION_STATE_READY))
    return 1;

  if (data_len > svm_fifo_max_enqueue (s->server_rx_fifo))
    return 1;

  return 0;
}

u32
stream_session_tx_fifo_max_dequeue (transport_connection_t * tc)
{
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
  if (!s->server_tx_fifo)
    return 0;
  return svm_fifo_max_dequeue (s->server_tx_fifo);
}

int
stream_session_peek_bytes (transport_connection_t * tc, u8 * buffer,
			   u32 offset, u32 max_bytes)
{
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
  return svm_fifo_peek (s->server_tx_fifo, offset, max_bytes, buffer);
}

u32
stream_session_dequeue_drop (transport_connection_t * tc, u32 max_bytes)
{
  stream_session_t *s = session_get (tc->s_index, tc->thread_index);
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
session_enqueue_notify (stream_session_t * s, u8 block)
{
  application_t *app;
  session_fifo_event_t evt;
  unix_shared_memory_queue_t *q;

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
      ed->data[0] = evt.event_type;
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
session_manager_flush_enqueue_events (u8 transport_proto, u32 thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  u32 *indices;
  stream_session_t *s;
  int i, errors = 0;

  indices = smm->session_to_enqueue[transport_proto][thread_index];

  for (i = 0; i < vec_len (indices); i++)
    {
      s = session_get_if_valid (indices[i], thread_index);
      if (s == 0 || session_enqueue_notify (s, 0 /* don't block */ ))
	errors++;
    }

  vec_reset_length (indices);
  smm->session_to_enqueue[transport_proto][thread_index] = indices;
  smm->current_enqueue_epoch[transport_proto][thread_index]++;

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
  s = session_get (tc->s_index, tc->thread_index);
  svm_fifo_init_pointers (s->server_rx_fifo, rx_pointer);
  svm_fifo_init_pointers (s->server_tx_fifo, tx_pointer);
}

int
session_stream_connect_notify (transport_connection_t * tc, u8 is_fail)
{
  application_t *app;
  stream_session_t *new_s = 0;
  u64 handle;
  u32 opaque = 0;
  int error = 0;
  segment_manager_t *sm;
  u8 alloc_fifos;

  /*
   * Find connection handle and cleanup half-open table
   */
  handle = session_lookup_half_open_handle (tc);
  if (handle == HALF_OPEN_LOOKUP_INVALID_VALUE)
    {
      SESSION_DBG ("half-open was removed!");
      return -1;
    }
  session_lookup_del_half_open (tc);

  /* Get the app's index from the handle we stored when opening connection
   * and the opaque (api_context for external apps) from transport session
   * index */
  app = application_get_if_valid (handle >> 32);
  if (!app)
    return -1;
  opaque = tc->s_index;

  /*
   * Allocate new session with fifos (svm segments are allocated if needed)
   */
  if (!is_fail)
    {
      sm = application_get_connect_segment_manager (app);
      alloc_fifos = !application_is_builtin_proxy (app);
      if (session_alloc_and_init (sm, tc, alloc_fifos, &new_s))
	{
	  is_fail = 1;
	  error = -1;
	}
      else
	new_s->app_index = app->index;
    }

  /*
   * Notify client application
   */
  if (app->cb_fns.session_connected_callback (app->index, opaque, new_s,
					      is_fail))
    {
      SESSION_DBG ("failed to notify app");
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

typedef struct _session_switch_pool_args
{
  u32 session_index;
  u32 thread_index;
  u32 new_thread_index;
  u32 new_session_index;
} session_switch_pool_args_t;

static void
session_switch_pool (void *cb_args)
{
  session_switch_pool_args_t *args = (session_switch_pool_args_t *) cb_args;
  stream_session_t *s;
  ASSERT (args->thread_index == vlib_get_thread_index ());
  s = session_get (args->session_index, args->thread_index);
  s->server_tx_fifo->master_session_index = args->new_session_index;
  s->server_tx_fifo->master_thread_index = args->new_thread_index;
  tp_vfts[s->session_type].cleanup (s->connection_index, s->thread_index);
  session_free (s);
  clib_mem_free (cb_args);
}

/**
 * Move dgram session to the right thread
 */
int
session_dgram_connect_notify (transport_connection_t * tc,
			      u32 old_thread_index,
			      stream_session_t ** new_session)
{
  stream_session_t *new_s;
  session_switch_pool_args_t *rpc_args;

  /*
   * Clone half-open session to the right thread.
   */
  new_s = session_clone_safe (tc->s_index, old_thread_index);
  new_s->connection_index = tc->c_index;
  new_s->server_rx_fifo->master_session_index = new_s->session_index;
  new_s->server_rx_fifo->master_thread_index = new_s->thread_index;
  new_s->session_state = SESSION_STATE_READY;
  session_lookup_add_connection (tc, session_handle (new_s));

  /*
   * Ask thread owning the old session to clean it up and make us the tx
   * fifo owner
   */
  rpc_args = clib_mem_alloc (sizeof (*rpc_args));
  rpc_args->new_session_index = new_s->session_index;
  rpc_args->new_thread_index = new_s->thread_index;
  rpc_args->session_index = tc->s_index;
  rpc_args->thread_index = old_thread_index;
  session_send_rpc_evt_to_thread (rpc_args->thread_index, session_switch_pool,
				  rpc_args);

  tc->s_index = new_s->session_index;
  new_s->connection_index = tc->c_index;
  *new_session = new_s;
  return 0;
}

void
stream_session_accept_notify (transport_connection_t * tc)
{
  application_t *server;
  stream_session_t *s;

  s = session_get (tc->s_index, tc->thread_index);
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

  s = session_get (tc->s_index, tc->thread_index);
  server = application_get (s->app_index);
  server->cb_fns.session_disconnect_callback (s);
}

/**
 * Cleans up session and lookup table.
 */
void
stream_session_delete (stream_session_t * s)
{
  int rv;

  /* Delete from the main lookup table. */
  if ((rv = session_lookup_del_session (s)))
    clib_warning ("hash delete error, rv %d", rv);

  /* Cleanup fifo segments */
  segment_manager_dealloc_fifos (s->svm_segment_index, s->server_rx_fifo,
				 s->server_tx_fifo);
  session_free (s);
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
  s = session_get_if_valid (tc->s_index, tc->thread_index);
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
  s = session_get (tc->s_index, tc->thread_index);

  app = application_get (s->app_index);
  app->cb_fns.session_reset_callback (s);
}

/**
 * Accept a stream session. Optionally ping the server by callback.
 */
int
stream_session_accept (transport_connection_t * tc, u32 listener_index,
		       u8 notify)
{
  application_t *server;
  stream_session_t *s, *listener;
  segment_manager_t *sm;
  session_type_t sst;
  int rv;

  sst = session_type_from_proto_and_ip (tc->proto, tc->is_ip4);

  /* Find the server */
  listener = listen_session_get (sst, listener_index);
  server = application_get (listener->app_index);

  sm = application_get_listen_segment_manager (server, listener);
  if ((rv = session_alloc_and_init (sm, tc, 1, &s)))
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
 * @param opaque Opaque data (typically, api_context) the application expects
 * 		 on open completion.
 */
int
session_open (u32 app_index, session_endpoint_t * rmt, u32 opaque)
{
  transport_connection_t *tc;
  session_type_t sst;
  segment_manager_t *sm;
  stream_session_t *s;
  application_t *app;
  int rv;
  u64 handle;

  sst = session_type_from_proto_and_ip (rmt->transport_proto, rmt->is_ip4);
  rv = tp_vfts[sst].open (session_endpoint_to_transport (rmt));
  if (rv < 0)
    {
      SESSION_DBG ("Transport failed to open connection.");
      return VNET_API_ERROR_SESSION_CONNECT;
    }

  tc = tp_vfts[sst].get_half_open ((u32) rv);

  /* If transport offers a stream service, only allocate session once the
   * connection has been established.
   */
  if (transport_is_stream (rmt->transport_proto))
    {
      /* Add connection to half-open table and save app and tc index. The
       * latter is needed to help establish the connection while the former
       * is needed when the connect notify comes and we have to notify the
       * external app
       */
      handle = (((u64) app_index) << 32) | (u64) tc->c_index;
      session_lookup_add_half_open (tc, handle);

      /* Store api_context (opaque) for when the reply comes. Not the nicest
       * thing but better than allocating a separate half-open pool.
       */
      tc->s_index = opaque;
    }
  /* For dgram type of service, allocate session and fifos now.
   */
  else
    {
      app = application_get (app_index);
      sm = application_get_connect_segment_manager (app);

      if (session_alloc_and_init (sm, tc, 1, &s))
	return -1;
      s->app_index = app->index;
      s->session_state = SESSION_STATE_CONNECTING_READY;

      /* Tell the app about the new event fifo for this session */
      app->cb_fns.session_connected_callback (app->index, opaque, s, 0);
    }
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
stream_session_listen (stream_session_t * s, session_endpoint_t * sep)
{
  transport_connection_t *tc;
  u32 tci;

  /* Transport bind/listen  */
  tci = tp_vfts[s->session_type].bind (s->session_index,
				       session_endpoint_to_transport (sep));

  if (tci == (u32) ~ 0)
    return -1;

  /* Attach transport to session */
  s->connection_index = tci;
  tc = tp_vfts[s->session_type].get_listener (tci);

  /* Weird but handle it ... */
  if (tc == 0)
    return -1;

  /* Add to the main lookup table */
  session_lookup_add_connection (tc, s->session_index);
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

  session_lookup_del_connection (tc);
  tp_vfts[s->session_type].unbind (s->connection_index);
  return 0;
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
  rv = session_lookup_del_session (s);
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

transport_connection_t *
session_get_transport (stream_session_t * s)
{
  if (s->session_state != SESSION_STATE_LISTENING)
    return tp_vfts[s->session_type].get_connection (s->connection_index,
						    s->thread_index);
  return 0;
}

transport_connection_t *
listen_session_get_transport (stream_session_t * s)
{
  return tp_vfts[s->session_type].get_listener (s->connection_index);
}

int
listen_session_get_local_session_endpoint (stream_session_t * listener,
					   session_endpoint_t * sep)
{
  transport_connection_t *tc;
  tc =
    tp_vfts[listener->session_type].get_listener (listener->connection_index);
  if (!tc)
    {
      clib_warning ("no transport");
      return -1;
    }

  /* N.B. The ip should not be copied because this is the local endpoint */
  sep->port = tc->lcl_port;
  sep->transport_proto = tc->proto;
  sep->is_ip4 = tc->is_ip4;
  return 0;
}

static clib_error_t *
session_manager_main_enable (vlib_main_t * vm)
{
  session_manager_main_t *smm = &session_manager_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
  u32 preallocated_sessions_per_worker;
  int i, j;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  if (num_threads < 1)
    return clib_error_return (0, "n_thread_stacks not set");

  /* $$$ config parameters */
  svm_fifo_segment_init (0x200000000ULL /* first segment base VA */ ,
			 20 /* timeout in seconds */ );

  /* configure per-thread ** vectors */
  vec_validate (smm->sessions, num_threads - 1);
  vec_validate (smm->tx_buffers, num_threads - 1);
  vec_validate (smm->pending_event_vector, num_threads - 1);
  vec_validate (smm->pending_disconnects, num_threads - 1);
  vec_validate (smm->free_event_vector, num_threads - 1);
  vec_validate (smm->vpp_event_queues, num_threads - 1);
  vec_validate (smm->session_peekers, num_threads - 1);
  vec_validate (smm->peekers_readers_locks, num_threads - 1);
  vec_validate (smm->peekers_write_locks, num_threads - 1);

  for (i = 0; i < TRANSPORT_N_PROTO; i++)
    for (j = 0; j < num_threads; j++)
      {
	vec_validate (smm->session_to_enqueue[i], num_threads - 1);
	vec_validate (smm->current_enqueue_epoch[i], num_threads - 1);
      }

  for (i = 0; i < num_threads; i++)
    {
      vec_validate (smm->free_event_vector[i], 0);
      _vec_len (smm->free_event_vector[i]) = 0;
      vec_validate (smm->pending_event_vector[i], 0);
      _vec_len (smm->pending_event_vector[i]) = 0;
      vec_validate (smm->pending_disconnects[i], 0);
      _vec_len (smm->pending_disconnects[i]) = 0;
      if (num_threads > 1)
	{
	  clib_spinlock_init (&smm->peekers_readers_locks[i]);
	  clib_spinlock_init (&smm->peekers_write_locks[i]);
	}
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
  app_namespaces_init ();
  transport_init ();

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
  clib_error_t *error = 0;
  if (is_en)
    {
      if (session_manager_main.is_enabled)
	return 0;

      session_node_enable_disable (is_en);
      error = session_manager_main_enable (vm);
    }
  else
    {
      session_manager_main.is_enabled = 0;
      session_node_enable_disable (is_en);
    }

  return error;
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
      else if (unformat (input, "local-endpoints-table-memory %U",
			 unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000)
	    return clib_error_return (0, "memory size %llx (%lld) too large",
				      tmp, tmp);
	  smm->local_endpoints_table_memory = tmp;
	}
      else if (unformat (input, "local-endpoints-table-buckets %d",
			 &smm->local_endpoints_table_buckets))
	;
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
