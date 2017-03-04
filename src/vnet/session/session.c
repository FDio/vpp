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

/**
 * Per-type vector of transport protocol virtual function tables
 */
static transport_proto_vft_t *tp_vfts;

session_manager_main_t session_manager_main;

/*
 * Session lookup key; (src-ip, dst-ip, src-port, dst-port, session-type)
 * Value: (owner thread index << 32 | session_index);
 */
static void
stream_session_table_add_for_tc (u8 sst, transport_connection_t * tc,
				 u64 value)
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
  stream_session_table_add_for_tc (s->session_type, tc, value);
}

static void
stream_session_half_open_table_add (u8 sst, transport_connection_t * tc,
				    u64 value)
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

static int
stream_session_table_del_for_tc (session_manager_main_t * smm, u8 sst,
				 transport_connection_t * tc)
{
  session_kv4_t kv4;
  session_kv6_t kv6;

  switch (sst)
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
  return stream_session_table_del_for_tc (smm, s->session_type, ts);
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
vpp_session_event_queue_allocate (session_manager_main_t * smm,
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

void
session_manager_get_segment_info (u32 index, u8 ** name, u32 * size)
{
  svm_fifo_segment_private_t *s;
  s = svm_fifo_get_segment (index);
  *name = s->h->segment_name;
  *size = s->ssvm.ssvm_size;
}

always_inline int
session_manager_add_segment_i (session_manager_main_t * smm,
			       session_manager_t * sm,
			       u32 segment_size, u8 * segment_name)
{
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  int rv;

  memset (ca, 0, sizeof (*ca));

  ca->segment_name = (char *) segment_name;
  ca->segment_size = segment_size;

  rv = svm_fifo_segment_create (ca);
  if (rv)
    {
      clib_warning ("svm_fifo_segment_create ('%s', %d) failed",
		    ca->segment_name, ca->segment_size);
      vec_free (segment_name);
      return -1;
    }

  vec_add1 (sm->segment_indices, ca->new_segment_index);

  return 0;
}

static int
session_manager_add_segment (session_manager_main_t * smm,
			     session_manager_t * sm)
{
  u8 *segment_name;
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  u32 add_segment_size;
  u32 default_segment_size = 128 << 10;

  memset (ca, 0, sizeof (*ca));
  segment_name = format (0, "%d-%d%c", getpid (),
			 smm->unique_segment_name_counter++, 0);
  add_segment_size =
    sm->add_segment_size ? sm->add_segment_size : default_segment_size;

  return session_manager_add_segment_i (smm, sm, add_segment_size,
					segment_name);
}

int
session_manager_add_first_segment (session_manager_main_t * smm,
				   session_manager_t * sm, u32 segment_size,
				   u8 ** segment_name)
{
  svm_fifo_segment_create_args_t _ca, *ca = &_ca;
  memset (ca, 0, sizeof (*ca));
  *segment_name = format (0, "%d-%d%c", getpid (),
			  smm->unique_segment_name_counter++, 0);
  return session_manager_add_segment_i (smm, sm, segment_size, *segment_name);
}

void
session_manager_del (session_manager_main_t * smm, session_manager_t * sm)
{
  u32 *deleted_sessions = 0;
  u32 *deleted_thread_indices = 0;
  int i, j;

  /* Across all fifo segments used by the server */
  for (j = 0; j < vec_len (sm->segment_indices); j++)
    {
      svm_fifo_segment_private_t *fifo_segment;
      svm_fifo_t **fifos;
      /* Vector of fifos allocated in the segment */
      fifo_segment = svm_fifo_get_segment (sm->segment_indices[j]);
      fifos = (svm_fifo_t **) fifo_segment->h->fifos;

      /*
       * Remove any residual sessions from the session lookup table
       * Don't bother deleting the individual fifos, we're going to
       * throw away the fifo segment in a minute.
       */
      for (i = 0; i < vec_len (fifos); i++)
	{
	  svm_fifo_t *fifo;
	  u32 session_index, thread_index;
	  stream_session_t *session;

	  fifo = fifos[i];
	  session_index = fifo->server_session_index;
	  thread_index = fifo->server_thread_index;

	  session = pool_elt_at_index (smm->sessions[thread_index],
				       session_index);

	  /* Add to the deleted_sessions vector (once!) */
	  if (!session->is_deleted)
	    {
	      session->is_deleted = 1;
	      vec_add1 (deleted_sessions,
			session - smm->sessions[thread_index]);
	      vec_add1 (deleted_thread_indices, thread_index);
	    }
	}

      for (i = 0; i < vec_len (deleted_sessions); i++)
	{
	  stream_session_t *session;

	  session =
	    pool_elt_at_index (smm->sessions[deleted_thread_indices[i]],
			       deleted_sessions[i]);

	  /* Instead of directly removing the session call disconnect */
	  stream_session_disconnect (session);

	  /*
	     stream_session_table_del (smm, session);
	     pool_put(smm->sessions[deleted_thread_indices[i]], session);
	   */
	}

      vec_reset_length (deleted_sessions);
      vec_reset_length (deleted_thread_indices);

      /* Instead of removing the segment, test when removing the session if
       * the segment can be removed
       */
      /* svm_fifo_segment_delete (fifo_segment); */
    }

  vec_free (deleted_sessions);
  vec_free (deleted_thread_indices);
}

int
session_manager_allocate_session_fifos (session_manager_main_t * smm,
					session_manager_t * sm,
					svm_fifo_t ** server_rx_fifo,
					svm_fifo_t ** server_tx_fifo,
					u32 * fifo_segment_index,
					u8 * added_a_segment)
{
  svm_fifo_segment_private_t *fifo_segment;
  u32 fifo_size, default_fifo_size = 128 << 10;	/* TODO config */
  int i;

  *added_a_segment = 0;

  /* Allocate svm fifos */
  ASSERT (vec_len (sm->segment_indices));

again:
  for (i = 0; i < vec_len (sm->segment_indices); i++)
    {
      *fifo_segment_index = sm->segment_indices[i];
      fifo_segment = svm_fifo_get_segment (*fifo_segment_index);

      fifo_size = sm->rx_fifo_size;
      fifo_size = (fifo_size == 0) ? default_fifo_size : fifo_size;
      *server_rx_fifo = svm_fifo_segment_alloc_fifo (fifo_segment, fifo_size);

      fifo_size = sm->tx_fifo_size;
      fifo_size = (fifo_size == 0) ? default_fifo_size : fifo_size;
      *server_tx_fifo = svm_fifo_segment_alloc_fifo (fifo_segment, fifo_size);

      if (*server_rx_fifo == 0)
	{
	  /* This would be very odd, but handle it... */
	  if (*server_tx_fifo != 0)
	    {
	      svm_fifo_segment_free_fifo (fifo_segment, *server_tx_fifo);
	      *server_tx_fifo = 0;
	    }
	  continue;
	}
      if (*server_tx_fifo == 0)
	{
	  if (*server_rx_fifo != 0)
	    {
	      svm_fifo_segment_free_fifo (fifo_segment, *server_rx_fifo);
	      *server_rx_fifo = 0;
	    }
	  continue;
	}
      break;
    }

  /* See if we're supposed to create another segment */
  if (*server_rx_fifo == 0)
    {
      if (sm->add_segment)
	{
	  if (*added_a_segment)
	    {
	      clib_warning ("added a segment, still cant allocate a fifo");
	      return SESSION_ERROR_NEW_SEG_NO_SPACE;
	    }

	  if (session_manager_add_segment (smm, sm))
	    return VNET_API_ERROR_URI_FIFO_CREATE_FAILED;

	  *added_a_segment = 1;
	  goto again;
	}
      else
	{
	  clib_warning ("No space to allocate fifos!");
	  return SESSION_ERROR_NO_SPACE;
	}
    }
  return 0;
}

int
stream_session_create_i (session_manager_main_t * smm, application_t * app,
			 transport_connection_t * tc,
			 stream_session_t ** ret_s)
{
  int rv;
  svm_fifo_t *server_rx_fifo = 0, *server_tx_fifo = 0;
  u32 fifo_segment_index;
  u32 pool_index, seg_size;
  stream_session_t *s;
  u64 value;
  u32 thread_index = tc->thread_index;
  session_manager_t *sm;
  u8 segment_added;
  u8 *seg_name;

  sm = session_manager_get (app->session_manager_index);

  /* Check the API queue */
  if (app->mode == APP_SERVER && application_api_queue_is_full (app))
    return SESSION_ERROR_API_QUEUE_FULL;

  if ((rv = session_manager_allocate_session_fifos (smm, sm, &server_rx_fifo,
						    &server_tx_fifo,
						    &fifo_segment_index,
						    &segment_added)))
    return rv;

  if (segment_added && app->mode == APP_SERVER)
    {
      /* Send an API message to the external server, to map new segment */
      ASSERT (app->cb_fns.add_segment_callback);

      session_manager_get_segment_info (fifo_segment_index, &seg_name,
					&seg_size);
      if (app->cb_fns.add_segment_callback (app->api_client_index, seg_name,
					    seg_size))
	return VNET_API_ERROR_URI_FIFO_CREATE_FAILED;
    }

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
  s->session_type = app->session_type;
  s->session_state = SESSION_STATE_CONNECTING;
  s->app_index = application_get_index (app);
  s->server_segment_index = fifo_segment_index;
  s->thread_index = thread_index;
  s->session_index = pool_index;

  /* Attach transport to session */
  s->connection_index = tc->c_index;

  /* Attach session to transport */
  tc->s_index = s->session_index;

  /* Add to the main lookup table */
  value = (((u64) thread_index) << 32) | (u64) s->session_index;
  stream_session_table_add_for_tc (app->session_type, tc, value);

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

  /* Fabricate event */
  evt.fifo = s->server_rx_fifo;
  evt.event_type = FIFO_EVENT_SERVER_RX;
  evt.event_id = serial_number++;
  evt.enqueue_length = svm_fifo_max_dequeue (s->server_rx_fifo);

  /* Built-in server? Hand event to the callback... */
  if (app->cb_fns.builtin_server_rx_callback)
    return app->cb_fns.builtin_server_rx_callback (s, &evt);

  /* Add event to server's event queue */
  q = app->event_queue;

  /* Based on request block (or not) for lack of space */
  if (block || PREDICT_TRUE (q->cursize < q->maxsize))
    unix_shared_memory_queue_add (app->event_queue, (u8 *) & evt,
				  0 /* do wait for mutex */ );
  else
    return -1;

  if (1)
    {
      ELOG_TYPE_DECLARE (e) =
      {
      .format = "evt-enqueue: id %d length %d",.format_args = "i4i4",};
      struct
      {
	u32 data[2];
      } *ed;
      ed = ELOG_DATA (&vlib_global_main.elog_main, e);
      ed->data[0] = evt.event_id;
      ed->data[1] = evt.enqueue_length;
    }

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

/*
 * Start listening on server's ip/port pair for requested transport.
 *
 * Creates a 'dummy' stream session with state LISTENING to be used in session
 * lookups, prior to establishing connection. Requests transport to build
 * it's own specific listening connection.
 */
int
stream_session_start_listen (u32 server_index, ip46_address_t * ip, u16 port)
{
  session_manager_main_t *smm = &session_manager_main;
  stream_session_t *s;
  transport_connection_t *tc;
  application_t *srv;
  u32 tci;

  srv = application_get (server_index);

  pool_get (smm->listen_sessions[srv->session_type], s);
  memset (s, 0, sizeof (*s));

  s->session_type = srv->session_type;
  s->session_state = SESSION_STATE_LISTENING;
  s->session_index = s - smm->listen_sessions[srv->session_type];
  s->app_index = srv->index;

  /* Transport bind/listen  */
  tci = tp_vfts[srv->session_type].bind (smm->vlib_main, s->session_index, ip,
					 port);

  /* Attach transport to session */
  s->connection_index = tci;
  tc = tp_vfts[srv->session_type].get_listener (tci);

  srv->session_index = s->session_index;

  /* Add to the main lookup table */
  stream_session_table_add_for_tc (s->session_type, tc, s->session_index);

  return 0;
}

void
stream_session_stop_listen (u32 server_index)
{
  session_manager_main_t *smm = &session_manager_main;
  stream_session_t *listener;
  transport_connection_t *tc;
  application_t *srv;

  srv = application_get (server_index);
  listener = pool_elt_at_index (smm->listen_sessions[srv->session_type],
				srv->session_index);

  tc = tp_vfts[srv->session_type].get_listener (listener->connection_index);
  stream_session_table_del_for_tc (smm, listener->session_type, tc);

  tp_vfts[srv->session_type].unbind (smm->vlib_main,
				     listener->connection_index);
  pool_put (smm->listen_sessions[srv->session_type], listener);
}

int
connect_server_add_segment_cb (application_t * ss, char *segment_name,
			       u32 segment_size)
{
  /* Does exactly nothing, but die */
  ASSERT (0);
  return 0;
}

void
connects_session_manager_init (session_manager_main_t * smm, u8 session_type)
{
  session_manager_t *sm;
  u32 connect_fifo_size = 256 << 10;	/* Config? */
  u32 default_segment_size = 1 << 20;

  pool_get (smm->session_managers, sm);
  memset (sm, 0, sizeof (*sm));

  sm->add_segment_size = default_segment_size;
  sm->rx_fifo_size = connect_fifo_size;
  sm->tx_fifo_size = connect_fifo_size;
  sm->add_segment = 1;

  session_manager_add_segment (smm, sm);
  smm->connect_manager_index[session_type] = sm - smm->session_managers;
}

void
stream_session_connect_notify (transport_connection_t * tc, u8 sst,
			       u8 is_fail)
{
  session_manager_main_t *smm = &session_manager_main;
  application_t *app;
  stream_session_t *new_s = 0;
  u64 value;

  value = stream_session_half_open_lookup (smm, &tc->lcl_ip, &tc->rmt_ip,
					   tc->lcl_port, tc->rmt_port,
					   tc->proto);
  if (value == HALF_OPEN_LOOKUP_INVALID_VALUE)
    {
      clib_warning ("This can't be good!");
      return;
    }

  app = application_get (value >> 32);

  if (!is_fail)
    {
      /* Create new session (server segments are allocated if needed) */
      if (stream_session_create_i (smm, app, tc, &new_s))
	return;

      app->session_index = stream_session_get_index (new_s);
      app->thread_index = new_s->thread_index;

      /* Allocate vpp event queue for this thread if needed */
      vpp_session_event_queue_allocate (smm, tc->thread_index);
    }

  /* Notify client */
  app->cb_fns.session_connected_callback (app->api_client_index, new_s,
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
  svm_fifo_segment_private_t *fifo_segment;
  application_t *app;

  /* Delete from the main lookup table. */
  stream_session_table_del (smm, s);

  /* Cleanup fifo segments */
  fifo_segment = svm_fifo_get_segment (s->server_segment_index);
  svm_fifo_segment_free_fifo (fifo_segment, s->server_rx_fifo);
  svm_fifo_segment_free_fifo (fifo_segment, s->server_tx_fifo);

  app = application_get_if_valid (s->app_index);

  /* No app. A possibility: after disconnect application called unbind */
  if (!app)
    return;

  if (app->mode == APP_CLIENT)
    {
      /* Cleanup app if client */
      application_del (app);
    }
  else if (app->mode == APP_SERVER)
    {
      session_manager_t *sm;
      svm_fifo_segment_private_t *fifo_segment;
      svm_fifo_t **fifos;
      u32 fifo_index;

      /* For server, see if any segments can be removed */
      sm = session_manager_get (app->session_manager_index);

      /* Delete fifo */
      fifo_segment = svm_fifo_get_segment (s->server_segment_index);
      fifos = (svm_fifo_t **) fifo_segment->h->fifos;

      fifo_index = svm_fifo_segment_index (fifo_segment);

      /* Remove segment only if it holds no fifos and not the first */
      if (sm->segment_indices[0] != fifo_index && vec_len (fifos) == 0)
	svm_fifo_segment_delete (fifo_segment);
    }

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
  session_manager_main_t *smm = &session_manager_main;
  application_t *server;
  stream_session_t *s, *listener;

  int rv;

  /* Find the server */
  listener = pool_elt_at_index (smm->listen_sessions[sst], listener_index);
  server = application_get (listener->app_index);

  if ((rv = stream_session_create_i (smm, server, tc, &s)))
    return rv;

  /* Allocate vpp event queue for this thread if needed */
  vpp_session_event_queue_allocate (smm, tc->thread_index);

  /* Shoulder-tap the server */
  if (notify)
    {
      server->cb_fns.session_accept_callback (s);
    }

  return 0;
}

int
stream_session_open (u8 sst, ip46_address_t * addr, u16 port_host_byte_order,
		     u32 app_index)
{
  transport_connection_t *tc;
  u32 tci;
  u64 value;
  int rv;

  /* Ask transport to open connection */
  rv = tp_vfts[sst].open (addr, port_host_byte_order);
  if (rv < 0)
    {
      clib_warning ("Transport failed to open connection.");
      return VNET_API_ERROR_SESSION_CONNECT_FAIL;
    }

  tci = rv;

  /* Get transport connection */
  tc = tp_vfts[sst].get_half_open (tci);

  /* Store api_client_index and transport connection index */
  value = (((u64) app_index) << 32) | (u64) tc->c_index;

  /* Add to the half-open lookup table */
  stream_session_half_open_table_add (sst, tc, value);

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
  smm->session_rx_fns[type] =
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

  for (i = 0; i < SESSION_N_TYPES; i++)
    smm->connect_manager_index[i] = INVALID_INDEX;

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
