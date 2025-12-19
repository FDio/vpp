/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2019 Cisco and/or its affiliates.
 */

#include <vnet/session/application_local.h>
#include <vnet/session/session.h>

typedef struct ct_cleanup_req_
{
  u32 ct_index;
} ct_cleanup_req_t;

typedef struct ct_worker_
{
  ct_connection_t *connections;	      /**< Per-worker connection pools */
  u32 *pending_connects;	      /**< Fifo of pending ho indices */
  ct_cleanup_req_t *pending_cleanups; /**< Fifo of pending indices */
  u8 have_connects;		      /**< Set if connect rpc pending */
  u8 have_cleanups;		      /**< Set if cleanup rpc pending */
  clib_spinlock_t pending_connects_lock; /**< Lock for pending connects */
  u32 *new_connects;			 /**< Burst of connects to be done */
} ct_worker_t;

typedef struct ct_main_
{
  ct_worker_t *wrk;			/**< Per-worker state */
  u32 n_workers;			/**< Number of vpp workers */
  u32 n_sessions;			/**< Cumulative sessions counter */
  u32 *ho_reusable;			/**< Vector of reusable ho indices */
  clib_spinlock_t ho_reuseable_lock;	/**< Lock for reusable ho indices */
  u32 **fwrk_pending_connects;		/**< First wrk pending half-opens */
  u32 fwrk_thread;			/**< First worker thread */
  u8 fwrk_have_flush;			/**< Flag for connect flush rpc */
  u8 is_init;
} ct_main_t;

static ct_main_t ct_main;

static inline ct_worker_t *
ct_worker_get (clib_thread_index_t thread_index)
{
  return &ct_main.wrk[thread_index];
}

static ct_connection_t *
ct_connection_alloc (clib_thread_index_t thread_index)
{
  ct_worker_t *wrk = ct_worker_get (thread_index);
  ct_connection_t *ct;

  pool_get_aligned_safe (wrk->connections, ct, CLIB_CACHE_LINE_BYTES);
  clib_memset (ct, 0, sizeof (*ct));
  ct->c_c_index = ct - wrk->connections;
  ct->c_thread_index = thread_index;
  ct->client_wrk = ~0;
  ct->server_wrk = ~0;
  ct->seg_ctx_index = ~0;
  ct->ct_seg_index = ~0;
  ct->peer_index = ~0;
  return ct;
}

ct_connection_t *
ct_connection_get (u32 ct_index, clib_thread_index_t thread_index)
{
  ct_worker_t *wrk = ct_worker_get (thread_index);

  if (pool_is_free_index (wrk->connections, ct_index))
    return 0;
  return pool_elt_at_index (wrk->connections, ct_index);
}

static void
ct_connection_free (ct_connection_t * ct)
{
  ct_worker_t *wrk = ct_worker_get (ct->c_thread_index);

  if (CLIB_DEBUG)
    {
      clib_memset (ct, 0xfc, sizeof (*ct));
      pool_put (wrk->connections, ct);
      return;
    }
  pool_put (wrk->connections, ct);
}

static ct_connection_t *
ct_half_open_alloc (void)
{
  ct_main_t *cm = &ct_main;
  u32 *hip;

  clib_spinlock_lock (&cm->ho_reuseable_lock);
  vec_foreach (hip, cm->ho_reusable)
    pool_put_index (cm->wrk[cm->fwrk_thread].connections, *hip);
  vec_reset_length (cm->ho_reusable);
  clib_spinlock_unlock (&cm->ho_reuseable_lock);

  return ct_connection_alloc (cm->fwrk_thread);
}

static ct_connection_t *
ct_half_open_get (u32 ho_index)
{
  ct_main_t *cm = &ct_main;
  return ct_connection_get (ho_index, cm->fwrk_thread);
}

void
ct_half_open_add_reusable (u32 ho_index)
{
  ct_main_t *cm = &ct_main;

  clib_spinlock_lock (&cm->ho_reuseable_lock);
  vec_add1 (cm->ho_reusable, ho_index);
  clib_spinlock_unlock (&cm->ho_reuseable_lock);
}

session_t *
ct_session_get_peer (session_t * s)
{
  ct_connection_t *ct, *peer_ct;
  ct = ct_connection_get (s->connection_index, s->thread_index);
  peer_ct = ct_connection_get (ct->peer_index, s->thread_index);
  if (!peer_ct)
    return 0;
  return session_get (peer_ct->c_s_index, s->thread_index);
}

void
ct_session_endpoint (session_t * ll, session_endpoint_t * sep)
{
  ct_connection_t *ct;
  ct = (ct_connection_t *) session_get_transport (ll);
  sep->transport_proto = ct->actual_tp;
  sep->port = ct->c_lcl_port;
  sep->is_ip4 = ct->c_is_ip4;
  ip_copy (&sep->ip, &ct->c_lcl_ip, ct->c_is_ip4);
}

static void
ct_session_force_disconnect_server (ct_connection_t *sct)
{
  sct->peer_index = ~0;
  session_transport_closing_notify (&sct->connection);
}

int
ct_session_connect_notify (session_t *ss, session_error_t err)
{
  u32 ss_index, opaque, thread_index;
  ct_connection_t *sct, *cct;
  app_worker_t *client_wrk;
  session_t *cs;

  ss_index = ss->session_index;
  thread_index = ss->thread_index;
  sct = (ct_connection_t *) session_get_transport (ss);
  client_wrk = app_worker_get (sct->client_wrk);
  opaque = sct->client_opaque;

  cct = ct_connection_get (sct->peer_index, thread_index);

  /* Client closed while waiting for reply from server */
  if (PREDICT_FALSE (!cct))
    {
      ct_session_force_disconnect_server (sct);
      return 0;
    }

  session_half_open_delete_notify (&cct->connection);
  cct->flags &= ~CT_CONN_F_HALF_OPEN;

  if (PREDICT_FALSE (err))
    goto connect_error;

  /*
   * Alloc client session, server session assumed to be established
   */

  ASSERT (ss->session_state >= SESSION_STATE_READY);

  cs = session_alloc (thread_index);
  ss = session_get (ss_index, thread_index);
  cs->session_type = ss->session_type;
  cs->listener_handle = SESSION_INVALID_HANDLE;
  session_set_state (cs, SESSION_STATE_CONNECTING);
  cs->app_wrk_index = client_wrk->wrk_index;
  cs->connection_index = cct->c_c_index;
  cs->opaque = opaque;
  cs->app_wrk_connect_index = SESSION_INVALID_INDEX;
  cct->c_s_index = cs->session_index;

  /* This will allocate fifos for the session. They won't be used for
   * exchanging data but they will be used to close the connection if
   * the segment manager/worker is freed */
  if ((err = app_worker_init_connected (client_wrk, cs)))
    {
      session_free (cs);
      ct_session_force_disconnect_server (sct);
      err = SESSION_E_ALLOC;
      goto connect_error;
    }

  cs->rx_fifo->ct_fifo = cct->client_tx_fifo;
  cs->tx_fifo->ct_fifo = cct->client_rx_fifo;
  cs->tx_fifo->flags |= SVM_FIFO_F_CLIENT_CT;
  cs->rx_fifo->flags |= SVM_FIFO_F_CLIENT_CT;

  session_set_state (cs, SESSION_STATE_CONNECTING);

  if (app_worker_connect_notify (client_wrk, cs, 0, opaque))
    {
      segment_manager_dealloc_fifos (cs->rx_fifo, cs->tx_fifo);
      session_free (cs);
      ct_session_force_disconnect_server (sct);
      goto cleanup_client;
    }

  cs = session_get (cct->c_s_index, cct->c_thread_index);
  session_set_state (cs, SESSION_STATE_READY);

  return 0;

connect_error:

  app_worker_connect_notify (client_wrk, 0, err, cct->client_opaque);

cleanup_client:

  if (cct->client_rx_fifo)
    segment_manager_dealloc_fifos (cct->client_rx_fifo, cct->client_tx_fifo);
  ct_connection_free (cct);

  return -1;
}

static void
ct_accept_one (clib_thread_index_t thread_index, u32 ho_index)
{
  ct_connection_t *sct, *cct, *ho;
  transport_connection_t *ll_ct;
  app_worker_t *server_wrk;
  u32 cct_index, ll_index;
  session_t *ss, *ll;

  /*
   * Alloc client ct and initialize from ho
   */
  cct = ct_connection_alloc (thread_index);
  cct_index = cct->c_c_index;

  ho = ct_half_open_get (ho_index);

  /* Unlikely but half-open session and transport could have been freed */
  if (PREDICT_FALSE (!ho))
    {
      ct_connection_free (cct);
      return;
    }

  clib_memcpy (cct, ho, sizeof (*ho));
  cct->c_c_index = cct_index;
  cct->c_thread_index = thread_index;
  cct->flags |= CT_CONN_F_HALF_OPEN;

  /* Notify session layer that half-open is on a different thread
   * and mark ho connection index reusable. Avoids another rpc
   */
  session_half_open_migrate_notify (&cct->connection);
  session_half_open_migrated_notify (&cct->connection);
  ct_half_open_add_reusable (ho_index);

  /*
   * Alloc and init server transport
   */

  ll_index = cct->peer_index;
  ll = listen_session_get (ll_index);
  sct = ct_connection_alloc (thread_index);
  /* Transport not necessarily ct but it might, so grab after sct alloc */
  ll_ct = listen_session_get_transport (ll);

  /* Make sure cct is valid after sct alloc */
  cct = ct_connection_get (cct_index, thread_index);

  sct->c_rmt_port = 0;
  sct->c_lcl_port = ll_ct->lcl_port;
  sct->c_is_ip4 = cct->c_is_ip4;
  clib_memcpy (&sct->c_lcl_ip, &cct->c_rmt_ip, sizeof (cct->c_rmt_ip));
  sct->client_wrk = cct->client_wrk;
  sct->c_proto = TRANSPORT_PROTO_CT;
  sct->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  sct->client_opaque = cct->client_opaque;
  sct->actual_tp = cct->actual_tp;

  sct->peer_index = cct->c_c_index;
  cct->peer_index = sct->c_c_index;

  /*
   * Accept server session. Client session is created only after
   * server confirms accept.
   */
  ss = session_alloc (thread_index);
  ll = listen_session_get (ll_index);
  ss->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_CT, sct->c_is_ip4);
  ss->connection_index = sct->c_c_index;
  ss->listener_handle = listen_session_get_handle (ll);
  session_set_state (ss, SESSION_STATE_CREATED);
  sct->c_s_index = ss->session_index;

  if (app_worker_init_accepted_ct (ss))
    {
      ct_session_connect_notify (ss, SESSION_E_ALLOC);
      ct_connection_free (sct);
      session_free (ss);
      return;
    }

  session_set_state (ss, SESSION_STATE_ACCEPTING);
  server_wrk = app_worker_get (ss->app_wrk_index);

  if (app_worker_accept_notify (server_wrk, ss))
    {
      ct_session_connect_notify (ss, SESSION_E_REFUSED);
      segment_manager_dealloc_fifos (ss->rx_fifo, ss->tx_fifo);
      ct_connection_free (sct);
      session_free (ss);
    }
}

static void
ct_accept_rpc_wrk_handler (void *rpc_args)
{
  clib_thread_index_t thread_index, n_connects, i, n_pending;
  const u32 max_connects = 32;
  ct_worker_t *wrk;
  u8 need_rpc = 0;

  thread_index = pointer_to_uword (rpc_args);
  wrk = ct_worker_get (thread_index);

  /* Connects could be handled without worker barrier so grab lock */
  clib_spinlock_lock (&wrk->pending_connects_lock);

  n_pending = clib_fifo_elts (wrk->pending_connects);
  n_connects = clib_min (n_pending, max_connects);
  vec_validate (wrk->new_connects, n_connects);

  for (i = 0; i < n_connects; i++)
    clib_fifo_sub1 (wrk->pending_connects, wrk->new_connects[i]);

  if (n_pending == n_connects)
    wrk->have_connects = 0;
  else
    need_rpc = 1;

  clib_spinlock_unlock (&wrk->pending_connects_lock);

  for (i = 0; i < n_connects; i++)
    ct_accept_one (thread_index, wrk->new_connects[i]);

  if (need_rpc)
    session_send_rpc_evt_to_thread_force (
      thread_index, ct_accept_rpc_wrk_handler,
      uword_to_pointer (thread_index, void *));
}

static void
ct_fwrk_flush_connects (void *rpc_args)
{
  clib_thread_index_t thread_index, fwrk_index, n_workers;
  ct_main_t *cm = &ct_main;
  ct_worker_t *wrk;
  u8 need_rpc;

  fwrk_index = cm->fwrk_thread;
  n_workers = vec_len (cm->fwrk_pending_connects);

  for (thread_index = fwrk_index; thread_index < n_workers; thread_index++)
    {
      if (!vec_len (cm->fwrk_pending_connects[thread_index]))
	continue;

      wrk = ct_worker_get (thread_index);

      /* Connects can be done without worker barrier, grab dst worker lock */
      if (thread_index != fwrk_index)
	clib_spinlock_lock (&wrk->pending_connects_lock);

      clib_fifo_add (wrk->pending_connects,
		     cm->fwrk_pending_connects[thread_index],
		     vec_len (cm->fwrk_pending_connects[thread_index]));
      if (!wrk->have_connects)
	{
	  wrk->have_connects = 1;
	  need_rpc = 1;
	}

      if (thread_index != fwrk_index)
	clib_spinlock_unlock (&wrk->pending_connects_lock);

      vec_reset_length (cm->fwrk_pending_connects[thread_index]);

      if (need_rpc)
	session_send_rpc_evt_to_thread_force (
	  thread_index, ct_accept_rpc_wrk_handler,
	  uword_to_pointer (thread_index, void *));
    }

  cm->fwrk_have_flush = 0;
}

static void
ct_program_connect_to_wrk (u32 ho_index)
{
  ct_main_t *cm = &ct_main;
  clib_thread_index_t thread_index;

  /* Simple round-robin policy for spreading sessions over workers. We skip
   * thread index 0, i.e., offset the index by 1, when we have workers as it
   * is the one dedicated to main thread. Note that n_workers does not include
   * main thread */
  cm->n_sessions += 1;
  thread_index = cm->n_workers ? (cm->n_sessions % cm->n_workers) + 1 : 0;

  /* Pospone flushing of connect request to dst worker until after session
   * layer fully initializes the half-open session. */
  vec_add1 (cm->fwrk_pending_connects[thread_index], ho_index);
  if (!cm->fwrk_have_flush)
    {
      session_send_rpc_evt_to_thread_force (
	cm->fwrk_thread, ct_fwrk_flush_connects,
	uword_to_pointer (thread_index, void *));
      cm->fwrk_have_flush = 1;
    }
}

static int
ct_connect (app_worker_t *client_wrk, session_t *ll,
	    session_endpoint_cfg_t *sep)
{
  ct_connection_t *ho;
  u32 ho_index;

  /*
   * Alloc and init client half-open transport
   */

  ho = ct_half_open_alloc ();
  ho_index = ho->c_c_index;
  ho->c_rmt_port = sep->port;
  ho->c_lcl_port = 0;
  ho->c_is_ip4 = sep->is_ip4;
  ho->client_opaque = sep->opaque;
  ho->client_wrk = client_wrk->wrk_index;
  ho->peer_index = ll->session_index;
  ho->c_proto = TRANSPORT_PROTO_CT;
  ho->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  clib_memcpy (&ho->c_rmt_ip, &sep->ip, sizeof (sep->ip));
  ho->flags |= CT_CONN_F_CLIENT;
  ho->c_s_index = ~0;
  ho->actual_tp = sep->original_tp;

  /*
   * Program connect on a worker, connected reply comes
   * after server accepts the connection.
   */
  ct_program_connect_to_wrk (ho_index);

  return ho_index;
}

static u32
ct_start_listen (u32 app_listener_index, transport_endpoint_cfg_t *tep)
{
  session_endpoint_cfg_t *sep;
  ct_connection_t *ct;

  sep = (session_endpoint_cfg_t *) tep;
  ct = ct_connection_alloc (0);
  ct->server_wrk = sep->app_wrk_index;
  ct->c_is_ip4 = sep->is_ip4;
  clib_memcpy (&ct->c_lcl_ip, &sep->ip, sizeof (sep->ip));
  ct->c_lcl_port = sep->port;
  ct->c_s_index = app_listener_index;
  ct->actual_tp = sep->transport_proto;
  return ct->c_c_index;
}

static u32
ct_stop_listen (u32 ct_index)
{
  ct_connection_t *ct;
  ct = ct_connection_get (ct_index, 0);
  ct_connection_free (ct);
  return 0;
}

static transport_connection_t *
ct_listener_get (u32 ct_index)
{
  return (transport_connection_t *) ct_connection_get (ct_index, 0);
}

static transport_connection_t *
ct_session_half_open_get (u32 ct_index)
{
  return (transport_connection_t *) ct_half_open_get (ct_index);
}

static void
ct_session_cleanup (u32 conn_index, clib_thread_index_t thread_index)
{
  ct_connection_t *ct, *peer_ct;

  ct = ct_connection_get (conn_index, thread_index);
  if (!ct)
    return;

  peer_ct = ct_connection_get (ct->peer_index, thread_index);
  if (peer_ct)
    peer_ct->peer_index = ~0;

  ct_connection_free (ct);
}

static void
ct_cleanup_ho (u32 ho_index)
{
  ct_connection_t *ho;

  ho = ct_half_open_get (ho_index);
  ct_connection_free (ho);
}

static int
ct_session_connect (transport_endpoint_cfg_t * tep)
{
  session_endpoint_cfg_t *sep_ext;
  session_endpoint_t _sep, *sep = &_sep;
  app_worker_t *app_wrk;
  session_handle_t lh;
  application_t *app;
  app_listener_t *al;
  u32 table_index;
  session_t *ll;
  u8 fib_proto;

  sep_ext = (session_endpoint_cfg_t *) tep;
  _sep = *(session_endpoint_t *) tep;
  app_wrk = app_worker_get (sep_ext->app_wrk_index);
  app = application_get (app_wrk->app_index);

  sep->transport_proto = sep_ext->original_tp;
  table_index = application_local_session_table (app);
  lh = session_lookup_local_endpoint (table_index, sep);
  if (lh == SESSION_DROP_HANDLE)
    return SESSION_E_FILTERED;

  if (lh == SESSION_INVALID_HANDLE)
    goto global_scope;

  ll = listen_session_get_from_handle (lh);
  al = app_listener_get (ll->al_index);

  /*
   * Break loop if rule in local table points to connecting app. This
   * can happen if client is a generic proxy. Route connect through
   * global table instead.
   */
  if (al->app_index == app->app_index)
    goto global_scope;

  return ct_connect (app_wrk, ll, sep_ext);

  /*
   * If nothing found, check the global scope for locally attached
   * destinations. Make sure first that we're allowed to.
   */

global_scope:
  if (session_endpoint_is_local (sep))
    return SESSION_E_NOROUTE;

  if (!application_has_global_scope (app))
    return SESSION_E_SCOPE;

  fib_proto = session_endpoint_fib_proto (sep);
  table_index = session_lookup_get_index_for_fib (fib_proto, sep->fib_index);
  ll = session_lookup_listener_wildcard (table_index, sep);

  /* Avoid connecting app to own listener */
  if (ll)
    {
      al = app_listener_get (ll->al_index);
      if (al->app_index != app->app_index)
	return ct_connect (app_wrk, ll, sep_ext);
    }

  /* Failed to connect but no error */
  return SESSION_E_LOCAL_CONNECT;
}

static inline int
ct_close_is_reset (ct_connection_t *ct, session_t *s)
{
  if (ct->flags & CT_CONN_F_RESET)
    return 1;
  if (ct->flags & CT_CONN_F_CLIENT)
    return (svm_fifo_max_dequeue (ct->client_rx_fifo) > 0);
  else
    return (svm_fifo_max_dequeue (s->rx_fifo) > 0);
}

static void
ct_session_postponed_cleanup (ct_connection_t *ct)
{
  ct_connection_t *peer_ct;
  session_t *s;

  s = session_get (ct->c_s_index, ct->c_thread_index);

  peer_ct = ct_connection_get (ct->peer_index, ct->c_thread_index);
  if (peer_ct)
    {
      if (ct_close_is_reset (ct, s))
	session_transport_reset_notify (&peer_ct->connection);
      else
	session_transport_closing_notify (&peer_ct->connection);
    }

  session_transport_closed_notify (&ct->connection);
  session_transport_delete_request (&ct->connection, ct_connection_free);
}

static void
ct_handle_cleanups (void *args)
{
  uword thread_index = pointer_to_uword (args);
  const u32 max_cleanups = 100;
  ct_cleanup_req_t *req;
  ct_connection_t *ct;
  u32 n_to_handle = 0;
  ct_worker_t *wrk;
  session_t *s;

  wrk = ct_worker_get (thread_index);
  wrk->have_cleanups = 0;
  n_to_handle = clib_fifo_elts (wrk->pending_cleanups);
  n_to_handle = clib_min (n_to_handle, max_cleanups);

  while (n_to_handle)
    {
      clib_fifo_sub2 (wrk->pending_cleanups, req);
      ct = ct_connection_get (req->ct_index, thread_index);
      s = session_get (ct->c_s_index, ct->c_thread_index);
      if (svm_fifo_has_event (s->tx_fifo) || (s->flags & SESSION_F_RX_EVT))
	clib_fifo_add1 (wrk->pending_cleanups, *req);
      else
	ct_session_postponed_cleanup (ct);
      n_to_handle -= 1;
    }

  if (clib_fifo_elts (wrk->pending_cleanups))
    {
      wrk->have_cleanups = 1;
      session_send_rpc_evt_to_thread_force (
	thread_index, ct_handle_cleanups,
	uword_to_pointer (thread_index, void *));
    }
}

static void
ct_program_cleanup (ct_connection_t *ct)
{
  ct_cleanup_req_t *req;
  uword thread_index;
  ct_worker_t *wrk;

  thread_index = ct->c_thread_index;
  wrk = ct_worker_get (ct->c_thread_index);

  clib_fifo_add2 (wrk->pending_cleanups, req);
  req->ct_index = ct->c_c_index;

  if (wrk->have_cleanups)
    return;

  wrk->have_cleanups = 1;
  session_send_rpc_evt_to_thread_force (
    thread_index, ct_handle_cleanups, uword_to_pointer (thread_index, void *));
}

static void
ct_session_close (u32 ct_index, clib_thread_index_t thread_index)
{
  ct_connection_t *ct, *peer_ct;
  session_t *s;

  ct = ct_connection_get (ct_index, thread_index);
  s = session_get (ct->c_s_index, ct->c_thread_index);
  peer_ct = ct_connection_get (ct->peer_index, thread_index);
  if (peer_ct)
    {
      peer_ct->peer_index = ~0;
      /* Make sure session was allocated */
      if (peer_ct->flags & CT_CONN_F_HALF_OPEN)
	{
	  ct_session_connect_notify (s, SESSION_E_REFUSED);
	  ct->peer_index = ~0;
	}
      else if (peer_ct->c_s_index == ~0)
	{
	  /* should not happen */
	  clib_warning ("ct peer without session");
	  ct_connection_free (peer_ct);
	}
    }

  /* Do not send closed notify to make sure pending tx events are
   * still delivered and program cleanup */
  ct_program_cleanup (ct);
}

static void
ct_session_reset (u32 ct_index, clib_thread_index_t thread_index)
{
  ct_connection_t *ct;
  ct = ct_connection_get (ct_index, thread_index);
  ct->flags |= CT_CONN_F_RESET;
  ct_session_close (ct_index, thread_index);
}

static transport_connection_t *
ct_session_get (u32 ct_index, clib_thread_index_t thread_index)
{
  return (transport_connection_t *) ct_connection_get (ct_index,
						       thread_index);
}

static u8 *
format_ct_connection_id (u8 * s, va_list * args)
{
  ct_connection_t *ct = va_arg (*args, ct_connection_t *);
  if (!ct)
    return s;
  if (ct->c_is_ip4)
    {
      s = format (s, "[%d:%d][CT:%U] %U:%d->%U:%d", ct->c_thread_index,
		  ct->c_s_index, format_transport_proto_short, ct->actual_tp,
		  format_ip4_address, &ct->c_lcl_ip4,
		  clib_net_to_host_u16 (ct->c_lcl_port), format_ip4_address,
		  &ct->c_rmt_ip4, clib_net_to_host_u16 (ct->c_rmt_port));
    }
  else
    {
      s = format (s, "[%d:%d][CT:%U] %U:%d->%U:%d", ct->c_thread_index,
		  ct->c_s_index, format_transport_proto_short, ct->actual_tp,
		  format_ip6_address, &ct->c_lcl_ip6,
		  clib_net_to_host_u16 (ct->c_lcl_port), format_ip6_address,
		  &ct->c_rmt_ip6, clib_net_to_host_u16 (ct->c_rmt_port));
    }

  return s;
}

static int
ct_custom_tx (void *session, transport_send_params_t * sp)
{
  session_t *s = (session_t *) session;
  if (session_has_transport (s))
    return 0;
  /* If event enqueued towards peer, remove from scheduler and remove
   * session tx flag, i.e., accept new tx events. Unset fifo flag now to
   * avoid missing events if peer did not clear fifo flag yet, which is
   * interpreted as successful notification and session is descheduled. */
  svm_fifo_unset_event (s->tx_fifo);
  if (!ct_session_tx (s))
    sp->flags = TRANSPORT_SND_F_DESCHED;

  /* The scheduler uses packet count as a means of upper bounding the amount
   * of work done per dispatch. So make it look like we have sent something */
  return 1;
}

static int
ct_app_rx_evt (transport_connection_t * tc)
{
  ct_connection_t *ct = (ct_connection_t *) tc, *peer_ct;
  session_t *ps, *s;

  s = session_get (ct->c_s_index, ct->c_thread_index);
  if (session_has_transport (s) || s->session_state < SESSION_STATE_READY)
    return -1;
  peer_ct = ct_connection_get (ct->peer_index, tc->thread_index);
  if (!peer_ct || (peer_ct->flags & CT_CONN_F_HALF_OPEN))
    return -1;
  ps = session_get (peer_ct->c_s_index, peer_ct->c_thread_index);
  if (ps->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return -1;
  svm_fifo_reset_has_deq_ntf (s->rx_fifo);
  /* Fifo was filled while notification was propagating, ask for another one */
  if (!svm_fifo_max_enqueue (ps->tx_fifo))
    {
      svm_fifo_add_want_deq_ntf (s->rx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }
  return session_dequeue_notify (ps);
}

static u8 *
format_ct_listener (u8 * s, va_list * args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 __clib_unused verbose = va_arg (*args, u32);
  ct_connection_t *ct = ct_connection_get (tc_index, 0);
  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_ct_connection_id, ct);
  if (verbose)
    s = format (s, "%-" SESSION_CLI_STATE_LEN "s", "LISTEN");
  return s;
}

static u8 *
format_ct_half_open (u8 *s, va_list *args)
{
  u32 ho_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  ct_connection_t *ct = ct_half_open_get (ho_index);
  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_ct_connection_id, ct);
  if (verbose)
    s = format (s, "%-" SESSION_CLI_STATE_LEN "s", "HALF-OPEN");
  return s;
}

static u8 *
format_ct_connection (u8 * s, va_list * args)
{
  ct_connection_t *ct = va_arg (*args, ct_connection_t *);
  u32 verbose = va_arg (*args, u32);

  if (!ct)
    return s;
  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_ct_connection_id, ct);
  if (verbose)
    {
      s = format (s, "%-" SESSION_CLI_STATE_LEN "s", "ESTABLISHED");
      if (verbose > 1)
	{
	  s = format (s, "\n");
	}
    }
  return s;
}

static u8 *
format_ct_session (u8 * s, va_list * args)
{
  u32 ct_index = va_arg (*args, u32);
  clib_thread_index_t thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  ct_connection_t *ct;

  ct = ct_connection_get (ct_index, thread_index);
  if (!ct)
    {
      s = format (s, "empty\n");
      return s;
    }

  s = format (s, "%U", format_ct_connection, ct, verbose);
  return s;
}

clib_error_t *
ct_enable_disable (vlib_main_t * vm, u8 is_en)
{
  vlib_thread_main_t *vtm = &vlib_thread_main;
  ct_main_t *cm = &ct_main;
  ct_worker_t *wrk;

  if (is_en == 0)
    return 0;

  if (cm->is_init)
    return 0;

  cm->n_workers = vlib_num_workers ();
  cm->fwrk_thread = transport_cl_thread ();
  vec_validate (cm->wrk, vtm->n_vlib_mains);
  vec_validate (cm->fwrk_pending_connects, cm->n_workers);
  vec_foreach (wrk, cm->wrk)
    clib_spinlock_init (&wrk->pending_connects_lock);
  clib_spinlock_init (&cm->ho_reuseable_lock);
  cm->is_init = 1;

  return 0;
}

static const transport_proto_vft_t cut_thru_proto = {
  .enable = ct_enable_disable,
  .start_listen = ct_start_listen,
  .stop_listen = ct_stop_listen,
  .get_connection = ct_session_get,
  .get_listener = ct_listener_get,
  .get_half_open = ct_session_half_open_get,
  .cleanup = ct_session_cleanup,
  .cleanup_ho = ct_cleanup_ho,
  .connect = ct_session_connect,
  .close = ct_session_close,
  .reset = ct_session_reset,
  .custom_tx = ct_custom_tx,
  .app_rx_evt = ct_app_rx_evt,
  .format_listener = format_ct_listener,
  .format_half_open = format_ct_half_open,
  .format_connection = format_ct_session,
  .transport_options = {
    .name = "ct",
    .short_name = "C",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_VC,
  },
};

static inline int
ct_session_can_tx (session_t *s)
{
  return (s->session_state == SESSION_STATE_READY ||
	  s->session_state == SESSION_STATE_CLOSING ||
	  s->session_state == SESSION_STATE_APP_CLOSED);
}

int
ct_session_tx (session_t * s)
{
  ct_connection_t *ct, *peer_ct;
  session_t *peer_s;

  if (!ct_session_can_tx (s))
    return 0;
  ct = (ct_connection_t *) session_get_transport (s);
  peer_ct = ct_connection_get (ct->peer_index, ct->c_thread_index);
  if (!peer_ct)
    return 0;
  peer_s = session_get (peer_ct->c_s_index, peer_ct->c_thread_index);
  if (peer_s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return 0;
  peer_s->flags |= SESSION_F_RX_EVT;
  /* Propagate dequeue ntf request along with enqueue notify */
  if (s->tx_fifo->signals->want_deq_ntf)
    peer_s->rx_fifo->signals->want_deq_ntf = s->tx_fifo->signals->want_deq_ntf;
  return session_enqueue_notify (peer_s);
}

static clib_error_t *
ct_transport_init (vlib_main_t * vm)
{
  transport_register_protocol (TRANSPORT_PROTO_CT, &cut_thru_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_CT, &cut_thru_proto,
			       FIB_PROTOCOL_IP6, ~0);
  return 0;
}

VLIB_INIT_FUNCTION (ct_transport_init);
