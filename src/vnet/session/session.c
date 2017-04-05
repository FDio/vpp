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
#include <vlibmemory/api.h>
#include <vnet/dpo/load_balance.h>
#include <vnet/fib/ip4_fib.h>
#include <vnet/session/application.h>
#include <vnet/tcp/tcp.h>
#include <vnet/session/session_debug.h>

/**
 * Per-type vector of transport protocol virtual function tables
 */
static transport_proto_vft_t *tp_vfts;

session_manager_main_t session_manager_main;

/*
 * Session lookup key; (src-ip, dst-ip, src-port, dst-port, session-type)
 * Value: (owner thread index << 32 | session_index);
 */
void
stream_session_table_add_for_tc (transport_connection_t * tc, u64 value)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv4_t kv4;
  session_kv6_t kv6;

  switch (tc->proto)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      clib_bihash_add_del_16_8 (&smm->v4_session_hash, &kv4, 1 /* is_add */ );
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      clib_bihash_add_del_48_8 (&smm->v6_session_hash, &kv6, 1 /* is_add */ );
      break;
    default:
      clib_warning ("Session type not supported");
      ASSERT (0);
    }
}

void
stream_session_table_add (session_manager_main_t * smm, stream_session_t * s,
			  u64 value)
{
  transport_connection_t *tc;

  tc = tp_vfts[s->session_type].get_connection (s->connection_index,
						s->thread_index);
  stream_session_table_add_for_tc (tc, value);
}

static void
stream_session_half_open_table_add (session_type_t sst,
				    transport_connection_t * tc, u64 value)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv4_t kv4;
  session_kv6_t kv6;

  switch (sst)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv_from_tc (&kv4, tc);
      kv4.value = value;
      clib_bihash_add_del_16_8 (&smm->v4_half_open_hash, &kv4,
				1 /* is_add */ );
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv_from_tc (&kv6, tc);
      kv6.value = value;
      clib_bihash_add_del_48_8 (&smm->v6_half_open_hash, &kv6,
				1 /* is_add */ );
      break;
    default:
      clib_warning ("Session type not supported");
      ASSERT (0);
    }
}

int
stream_session_table_del_for_tc (transport_connection_t * tc)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv4_t kv4;
  session_kv6_t kv6;
  switch (tc->proto)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv_from_tc (&kv4, tc);
      return clib_bihash_add_del_16_8 (&smm->v4_session_hash, &kv4,
				       0 /* is_add */ );
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv_from_tc (&kv6, tc);
      return clib_bihash_add_del_48_8 (&smm->v6_session_hash, &kv6,
				       0 /* is_add */ );
      break;
    default:
      clib_warning ("Session type not supported");
      ASSERT (0);
    }

  return 0;
}

static int
stream_session_table_del (session_manager_main_t * smm, stream_session_t * s)
{
  transport_connection_t *ts;

  ts = tp_vfts[s->session_type].get_connection (s->connection_index,
						s->thread_index);
  return stream_session_table_del_for_tc (ts);
}

static void
stream_session_half_open_table_del (session_manager_main_t * smm, u8 sst,
				    transport_connection_t * tc)
{
  session_kv4_t kv4;
  session_kv6_t kv6;

  switch (sst)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv_from_tc (&kv4, tc);
      clib_bihash_add_del_16_8 (&smm->v4_half_open_hash, &kv4,
				0 /* is_add */ );
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv_from_tc (&kv6, tc);
      clib_bihash_add_del_48_8 (&smm->v6_half_open_hash, &kv6,
				0 /* is_add */ );
      break;
    default:
      clib_warning ("Session type not supported");
      ASSERT (0);
    }
}

stream_session_t *
stream_session_lookup_listener4 (ip4_address_t * lcl, u16 lcl_port, u8 proto)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv4_t kv4;
  int rv;

  make_v4_listener_kv (&kv4, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_16_8 (&smm->v4_session_hash, &kv4);
  if (rv == 0)
    return pool_elt_at_index (smm->listen_sessions[proto], (u32) kv4.value);

  /* Zero out the lcl ip */
  kv4.key[0] = 0;
  rv = clib_bihash_search_inline_16_8 (&smm->v4_session_hash, &kv4);
  if (rv == 0)
    return pool_elt_at_index (smm->listen_sessions[proto], kv4.value);

  return 0;
}

/** Looks up a session based on the 5-tuple passed as argument.
 *
 * First it tries to find an established session, if this fails, it tries
 * finding a listener session if this fails, it tries a lookup with a
 * wildcarded local source (listener bound to all interfaces)
 */
stream_session_t *
stream_session_lookup4 (ip4_address_t * lcl, ip4_address_t * rmt,
			u16 lcl_port, u16 rmt_port, u8 proto,
			u32 my_thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv4_t kv4;
  int rv;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&smm->v4_session_hash, &kv4);
  if (rv == 0)
    return stream_session_get_tsi (kv4.value, my_thread_index);

  /* If nothing is found, check if any listener is available */
  return stream_session_lookup_listener4 (lcl, lcl_port, proto);
}

stream_session_t *
stream_session_lookup_listener6 (ip6_address_t * lcl, u16 lcl_port, u8 proto)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv6_t kv6;
  int rv;

  make_v6_listener_kv (&kv6, lcl, lcl_port, proto);
  rv = clib_bihash_search_inline_48_8 (&smm->v6_session_hash, &kv6);
  if (rv == 0)
    return pool_elt_at_index (smm->listen_sessions[proto], kv6.value);

  /* Zero out the lcl ip */
  kv6.key[0] = kv6.key[1] = 0;
  rv = clib_bihash_search_inline_48_8 (&smm->v6_session_hash, &kv6);
  if (rv == 0)
    return pool_elt_at_index (smm->listen_sessions[proto], kv6.value);

  return 0;
}

/* Looks up a session based on the 5-tuple passed as argument.
 * First it tries to find an established session, if this fails, it tries
 * finding a listener session if this fails, it tries a lookup with a
 * wildcarded local source (listener bound to all interfaces) */
stream_session_t *
stream_session_lookup6 (ip6_address_t * lcl, ip6_address_t * rmt,
			u16 lcl_port, u16 rmt_port, u8 proto,
			u32 my_thread_index)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();
  session_kv6_t kv6;
  int rv;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&smm->v6_session_hash, &kv6);
  if (rv == 0)
    return stream_session_get_tsi (kv6.value, my_thread_index);

  /* If nothing is found, check if any listener is available */
  return stream_session_lookup_listener6 (lcl, lcl_port, proto);
}

stream_session_t *
stream_session_lookup_listener (ip46_address_t * lcl, u16 lcl_port, u8 proto)
{
  switch (proto)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      return stream_session_lookup_listener4 (&lcl->ip4, lcl_port, proto);
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      return stream_session_lookup_listener6 (&lcl->ip6, lcl_port, proto);
      break;
    }
  return 0;
}

static u64
stream_session_half_open_lookup (session_manager_main_t * smm,
				 ip46_address_t * lcl, ip46_address_t * rmt,
				 u16 lcl_port, u16 rmt_port, u8 proto)
{
  session_kv4_t kv4;
  session_kv6_t kv6;
  int rv;

  switch (proto)
    {
    case SESSION_TYPE_IP4_UDP:
    case SESSION_TYPE_IP4_TCP:
      make_v4_ss_kv (&kv4, &lcl->ip4, &rmt->ip4, lcl_port, rmt_port, proto);
      rv = clib_bihash_search_inline_16_8 (&smm->v4_half_open_hash, &kv4);

      if (rv == 0)
	return kv4.value;

      return (u64) ~ 0;
      break;
    case SESSION_TYPE_IP6_UDP:
    case SESSION_TYPE_IP6_TCP:
      make_v6_ss_kv (&kv6, &lcl->ip6, &rmt->ip6, lcl_port, rmt_port, proto);
      rv = clib_bihash_search_inline_48_8 (&smm->v6_half_open_hash, &kv6);

      if (rv == 0)
	return kv6.value;

      return (u64) ~ 0;
      break;
    }
  return 0;
}

transport_connection_t *
stream_session_lookup_transport4 (ip4_address_t * lcl, ip4_address_t * rmt,
				  u16 lcl_port, u16 rmt_port, u8 proto,
				  u32 my_thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  session_kv4_t kv4;
  stream_session_t *s;
  int rv;

  /* Lookup session amongst established ones */
  make_v4_ss_kv (&kv4, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_16_8 (&smm->v4_session_hash, &kv4);
  if (rv == 0)
    {
      s = stream_session_get_tsi (kv4.value, my_thread_index);

      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      my_thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = stream_session_lookup_listener4 (lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_16_8 (&smm->v4_half_open_hash, &kv4);
  if (rv == 0)
    return tp_vfts[proto].get_half_open (kv4.value & 0xFFFFFFFF);

  return 0;
}

transport_connection_t *
stream_session_lookup_transport6 (ip6_address_t * lcl, ip6_address_t * rmt,
				  u16 lcl_port, u16 rmt_port, u8 proto,
				  u32 my_thread_index)
{
  session_manager_main_t *smm = &session_manager_main;
  stream_session_t *s;
  session_kv6_t kv6;
  int rv;

  make_v6_ss_kv (&kv6, lcl, rmt, lcl_port, rmt_port, proto);
  rv = clib_bihash_search_inline_48_8 (&smm->v6_session_hash, &kv6);
  if (rv == 0)
    {
      s = stream_session_get_tsi (kv6.value, my_thread_index);

      return tp_vfts[s->session_type].get_connection (s->connection_index,
						      my_thread_index);
    }

  /* If nothing is found, check if any listener is available */
  s = stream_session_lookup_listener6 (lcl, lcl_port, proto);
  if (s)
    return tp_vfts[s->session_type].get_listener (s->connection_index);

  /* Finally, try half-open connections */
  rv = clib_bihash_search_inline_48_8 (&smm->v6_half_open_hash, &kv6);
  if (rv == 0)
    return tp_vfts[proto].get_half_open (kv6.value & 0xFFFFFFFF);

  return 0;
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

  if (smm->vpp_event_queues[thread_index] == 0)
    {
      /* Allocate event fifo in the /vpe-api shared-memory segment */
      oldheap = svm_push_data_heap (am->vlib_rp);

      smm->vpp_event_queues[thread_index] =
	unix_shared_memory_queue_init (2048 /* nels $$$$ config */ ,
				       sizeof (session_fifo_event_t),
				       0 /* consumer pid */ ,
				       0
				       /* (do not) send signal when queue non-empty */
	);

      svm_pop_heap (oldheap);
    }
}

int
stream_session_create_i (segment_manager_t * sm, transport_connection_t * tc,
			 stream_session_t ** ret_s)
{
  session_manager_main_t *smm = &session_manager_main;
  svm_fifo_t *server_rx_fifo = 0, *server_tx_fifo = 0;
  u32 fifo_segment_index;
  u32 pool_index;
  stream_session_t *s;
  u64 value;
  u32 thread_index = tc->thread_index;
  int rv;

  if ((rv = segment_manager_alloc_session_fifos (sm, &server_rx_fifo,
						 &server_tx_fifo,
						 &fifo_segment_index)))
    return rv;

  /* Create the session */
  pool_get (smm->sessions[thread_index], s);
  memset (s, 0, sizeof (*s));

  /* Initialize backpointers */
  pool_index = s - smm->sessions[thread_index];
  server_rx_fifo->server_session_index = pool_index;
  server_rx_fifo->server_thread_index = thread_index;

  server_tx_fifo->server_session_index = pool_index;
  server_tx_fifo->server_thread_index = thread_index;

  s->server_rx_fifo = server_rx_fifo;
  s->server_tx_fifo = server_tx_fifo;

  /* Initialize state machine, such as it is... */
  s->session_type = tc->proto;
  s->session_state = SESSION_STATE_CONNECTING;
  s->svm_segment_index = fifo_segment_index;
  s->thread_index = thread_index;
  s->session_index = pool_index;

  /* Attach transport to session */
  s->connection_index = tc->c_index;

  /* Attach session to transport */
  tc->s_index = s->session_index;

  /* Add to the main lookup table */
  value = (((u64) thread_index) << 32) | (u64) s->session_index;
  stream_session_table_add_for_tc (tc, value);

  *ret_s = s;

  return 0;
}

/*
 * Enqueue data for delivery to session peer. Does not notify peer of enqueue
 * event but on request can queue notification events for later delivery by
 * calling stream_server_flush_enqueue_events().
 *
 * @param tc Transport connection which is to be enqueued data
 * @param data Data to be enqueued
 * @param len Length of data to be enqueued
 * @param queue_event Flag to indicate if peer is to be notified or if event
 *                    is to be queued. The former is useful when more data is
 *                    enqueued and only one event is to be generated.
 * @return Number of bytes enqueued or a negative value if enqueueing failed.
 */
int
stream_session_enqueue_data (transport_connection_t * tc, u8 * data, u16 len,
			     u8 queue_event)
{
  stream_session_t *s;
  int enqueued;

  s = stream_session_get (tc->s_index, tc->thread_index);

  /* Make sure there's enough space left. We might've filled the pipes */
  if (PREDICT_FALSE (len > svm_fifo_max_enqueue (s->server_rx_fifo)))
    return -1;

  enqueued = svm_fifo_enqueue_nowait (s->server_rx_fifo, s->pid, len, data);

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

  return enqueued;
}

/** Check if we have space in rx fifo to push more bytes */
u8
stream_session_no_space (transport_connection_t * tc, u32 thread_index,
			 u16 data_len)
{
  stream_session_t *s = stream_session_get (tc->c_index, thread_index);

  if (PREDICT_FALSE (s->session_state != SESSION_STATE_READY))
    return 1;

  if (data_len > svm_fifo_max_enqueue (s->server_rx_fifo))
    return 1;

  return 0;
}

u32
stream_session_peek_bytes (transport_connection_t * tc, u8 * buffer,
			   u32 offset, u32 max_bytes)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return svm_fifo_peek (s->server_tx_fifo, s->pid, offset, max_bytes, buffer);
}

u32
stream_session_dequeue_drop (transport_connection_t * tc, u32 max_bytes)
{
  stream_session_t *s = stream_session_get (tc->s_index, tc->thread_index);
  return svm_fifo_dequeue_drop (s->server_tx_fifo, s->pid, max_bytes);
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
    return 0;

  /* Get session's server */
  app = application_get (s->app_index);

  /* Built-in server? Hand event to the callback... */
  if (app->cb_fns.builtin_server_rx_callback)
    return app->cb_fns.builtin_server_rx_callback (s);

  /* If no event, send one */
  if (svm_fifo_set_event (s->server_rx_fifo))
    {
      /* Fabricate event */
      evt.fifo = s->server_rx_fifo;
      evt.event_type = FIFO_EVENT_SERVER_RX;
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
      s0 = stream_session_get (session_indices_to_enqueue[i], thread_index);
      if (stream_session_enqueue_notify (s0, 0 /* don't block */ ))
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

void
stream_session_connect_notify (transport_connection_t * tc, u8 sst,
			       u8 is_fail)
{
  session_manager_main_t *smm = &session_manager_main;
  application_t *app;
  stream_session_t *new_s = 0;
  u64 handle;
  u32 api_context = 0;

  handle = stream_session_half_open_lookup (smm, &tc->lcl_ip, &tc->rmt_ip,
					    tc->lcl_port, tc->rmt_port,
					    tc->proto);
  if (handle == HALF_OPEN_LOOKUP_INVALID_VALUE)
    {
      clib_warning ("This can't be good!");
      return;
    }

  /* Get the app's index from the handle we stored when opening connection */
  app = application_get (handle >> 32);
  api_context = tc->s_index;

  if (!is_fail)
    {
      segment_manager_t *sm;
      sm = application_get_connect_segment_manager (app);

      /* Create new session (svm segments are allocated if needed) */
      if (stream_session_create_i (sm, tc, &new_s))
	return;

      new_s->app_index = app->index;
    }

  /* Notify client */
  app->cb_fns.session_connected_callback (app->index, api_context, new_s,
					  is_fail);

  /* Cleanup session lookup */
  stream_session_half_open_table_del (smm, sst, tc);
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
 * Cleans up session and associated app if needed.
 */
void
stream_session_delete (stream_session_t * s)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();

  /* Delete from the main lookup table. */
  stream_session_table_del (smm, s);

  /* Cleanup fifo segments */
  segment_manager_dealloc_fifos (s->svm_segment_index, s->server_rx_fifo,
				 s->server_tx_fifo);

  pool_put (smm->sessions[s->thread_index], s);
}

/**
 * Notification from transport that connection is being deleted
 *
 * This should be called only on previously fully established sessions. For
 * instance failed connects should call stream_session_connect_notify and
 * indicate that the connect has failed.
 */
void
stream_session_delete_notify (transport_connection_t * tc)
{
  stream_session_t *s;

  /* App might've been removed already */
  s = stream_session_get_if_valid (tc->s_index, tc->thread_index);
  if (!s)
    {
      return;
    }
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
  if ((rv = stream_session_create_i (sm, tc, &s)))
    return rv;

  s->app_index = server->index;
  s->listener_index = listener_index;

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
		     transport_endpoint_t * tep,
		     transport_connection_t ** res)
{
  transport_connection_t *tc;
  int rv;
  u64 handle;

  rv = tp_vfts[st].open (&tep->ip, tep->port);
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
  stream_session_half_open_table_add (st, tc, handle);

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
  tci = tp_vfts[s->session_type].bind (s->session_index, &tep->ip, tep->port);

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

/**
 * Disconnect session and propagate to transport. This should eventually
 * result in a delete notification that allows us to cleanup session state.
 * Called for both active/passive disconnects.
 */
void
stream_session_disconnect (stream_session_t * s)
{
//  session_fifo_event_t evt;

  s->session_state = SESSION_STATE_CLOSED;
  /* RPC to vpp evt queue in the right thread */

  tp_vfts[s->session_type].close (s->connection_index, s->thread_index);

//  {
//  /* Fabricate event */
//  evt.fifo = s->server_rx_fifo;
//  evt.event_type = FIFO_EVENT_SERVER_RX;
//  evt.event_id = serial_number++;
//
//  /* Based on request block (or not) for lack of space */
//  if (PREDICT_TRUE(q->cursize < q->maxsize))
//    unix_shared_memory_queue_add (app->event_queue, (u8 *) &evt,
//                                0 /* do wait for mutex */);
//  else
//    {
//      clib_warning("fifo full");
//      return -1;
//    }
//  }
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
  session_manager_main_t *smm = &session_manager_main;
  int rv;

  s->session_state = SESSION_STATE_CLOSED;

  /* Delete from the main lookup table to avoid more enqueues */
  rv = stream_session_table_del (smm, s);
  if (rv)
    clib_warning ("hash delete error, rv %d", rv);

  tp_vfts[s->session_type].cleanup (s->connection_index, s->thread_index);
}

void
session_register_transport (u8 type, const transport_proto_vft_t * vft)
{
  session_manager_main_t *smm = vnet_get_session_manager_main ();

  vec_validate (tp_vfts, type);
  tp_vfts[type] = *vft;

  /* If an offset function is provided, then peek instead of dequeue */
  smm->session_tx_fns[type] =
    (vft->tx_fifo_offset) ? session_tx_fifo_peek_and_snd :
    session_tx_fifo_dequeue_and_snd;
}

transport_proto_vft_t *
session_get_transport_vft (u8 type)
{
  if (type >= vec_len (tp_vfts))
    return 0;
  return &tp_vfts[type];
}

static clib_error_t *
session_manager_main_enable (vlib_main_t * vm)
{
  session_manager_main_t *smm = &session_manager_main;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 num_threads;
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
  vec_validate (smm->fifo_events, num_threads - 1);
  vec_validate (smm->evts_partially_read, num_threads - 1);
  vec_validate (smm->current_enqueue_epoch, num_threads - 1);
  vec_validate (smm->vpp_event_queues, num_threads - 1);

#if SESSION_DBG
  vec_validate (smm->last_event_poll_by_thread, num_threads - 1);
#endif

  /* Allocate vpp event queues */
  for (i = 0; i < vec_len (smm->vpp_event_queues); i++)
    session_vpp_event_queue_allocate (smm, i);

  /* $$$$ preallocate hack config parameter */
  for (i = 0; i < 200000; i++)
    {
      stream_session_t *ss;
      pool_get (smm->sessions[0], ss);
      memset (ss, 0, sizeof (*ss));
    }

  for (i = 0; i < 200000; i++)
    pool_put_index (smm->sessions[0], i);

  clib_bihash_init_16_8 (&smm->v4_session_hash, "v4 session table",
			 200000 /* $$$$ config parameter nbuckets */ ,
			 (64 << 20) /*$$$ config parameter table size */ );
  clib_bihash_init_48_8 (&smm->v6_session_hash, "v6 session table",
			 200000 /* $$$$ config parameter nbuckets */ ,
			 (64 << 20) /*$$$ config parameter table size */ );

  clib_bihash_init_16_8 (&smm->v4_half_open_hash, "v4 half-open table",
			 200000 /* $$$$ config parameter nbuckets */ ,
			 (64 << 20) /*$$$ config parameter table size */ );
  clib_bihash_init_48_8 (&smm->v6_half_open_hash, "v6 half-open table",
			 200000 /* $$$$ config parameter nbuckets */ ,
			 (64 << 20) /*$$$ config parameter table size */ );

  smm->is_enabled = 1;

  /* Enable TCP transport */
  vnet_tcp_enable_disable (vm, 1);

  return 0;
}

clib_error_t *
vnet_session_enable_disable (vlib_main_t * vm, u8 is_en)
{
  if (is_en)
    {
      if (session_manager_main.is_enabled)
	return 0;

      vlib_node_set_state (vm, session_queue_node.index,
			   VLIB_NODE_STATE_POLLING);

      return session_manager_main_enable (vm);
    }
  else
    {
      session_manager_main.is_enabled = 0;
      vlib_node_set_state (vm, session_queue_node.index,
			   VLIB_NODE_STATE_DISABLED);
    }

  return 0;
}

clib_error_t *
session_manager_main_init (vlib_main_t * vm)
{
  session_manager_main_t *smm = &session_manager_main;

  smm->vlib_main = vm;
  smm->vnet_main = vnet_get_main ();
  smm->is_enabled = 0;

  return 0;
}

VLIB_INIT_FUNCTION (session_manager_main_init)
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
