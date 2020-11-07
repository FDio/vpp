/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <vnet/session/application_local.h>
#include <vnet/session/session.h>

typedef struct ct_main_
{
  ct_connection_t **connections;	/**< Per-worker connection pools */
  u32 n_workers;			/**< Number of vpp workers */
  u32 n_sessions;			/**< Cumulative sessions counter */
} ct_main_t;

static ct_main_t ct_main;

static ct_connection_t *
ct_connection_alloc (u32 thread_index)
{
  ct_connection_t *ct;

  pool_get_zero (ct_main.connections[thread_index], ct);
  ct->c_c_index = ct - ct_main.connections[thread_index];
  ct->c_thread_index = thread_index;
  ct->client_wrk = ~0;
  ct->server_wrk = ~0;
  return ct;
}

static ct_connection_t *
ct_connection_get (u32 ct_index, u32 thread_index)
{
  if (pool_is_free_index (ct_main.connections[thread_index], ct_index))
    return 0;
  return pool_elt_at_index (ct_main.connections[thread_index], ct_index);
}

static void
ct_connection_free (ct_connection_t * ct)
{
  if (CLIB_DEBUG)
    {
      u32 thread_index = ct->c_thread_index;
      memset (ct, 0xfc, sizeof (*ct));
      pool_put (ct_main.connections[thread_index], ct);
      return;
    }
  pool_put (ct_main.connections[ct->c_thread_index], ct);
}

session_t *
ct_session_get_peer (session_t * s)
{
  ct_connection_t *ct, *peer_ct;
  ct = ct_connection_get (s->connection_index, s->thread_index);
  peer_ct = ct_connection_get (ct->peer_index, s->thread_index);
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

int
ct_session_connect_notify (session_t * ss)
{
  u32 ss_index, opaque, thread_index;
  ct_connection_t *sct, *cct;
  app_worker_t *client_wrk;
  segment_manager_t *sm;
  fifo_segment_t *seg;
  u64 segment_handle;
  int err = 0;
  session_t *cs;

  ss_index = ss->session_index;
  thread_index = ss->thread_index;
  sct = (ct_connection_t *) session_get_transport (ss);
  client_wrk = app_worker_get (sct->client_wrk);
  opaque = sct->client_opaque;

  sm = segment_manager_get (ss->rx_fifo->segment_manager);
  seg = segment_manager_get_segment_w_lock (sm, ss->rx_fifo->segment_index);
  segment_handle = segment_manager_segment_handle (sm, seg);

  if ((err = app_worker_add_segment_notify (client_wrk, segment_handle)))
    {
      clib_warning ("failed to notify client %u of new segment",
		    sct->client_wrk);
      segment_manager_segment_reader_unlock (sm);
      session_close (ss);
      goto error;
    }
  else
    {
      segment_manager_segment_reader_unlock (sm);
    }

  /* Alloc client session */
  cct = ct_connection_get (sct->peer_index, thread_index);

  cs = session_alloc (thread_index);
  ss = session_get (ss_index, thread_index);
  cs->session_type = ss->session_type;
  cs->listener_handle = SESSION_INVALID_HANDLE;
  cs->session_state = SESSION_STATE_CONNECTING;
  cs->app_wrk_index = client_wrk->wrk_index;
  cs->connection_index = cct->c_c_index;

  cct->c_s_index = cs->session_index;
  cct->client_rx_fifo = ss->tx_fifo;
  cct->client_tx_fifo = ss->rx_fifo;

  cct->client_rx_fifo->refcnt++;
  cct->client_tx_fifo->refcnt++;

  /* This will allocate fifos for the session. They won't be used for
   * exchanging data but they will be used to close the connection if
   * the segment manager/worker is freed */
  if ((err = app_worker_init_connected (client_wrk, cs)))
    {
      session_close (ss);
      session_free (cs);
      goto error;
    }

  cs->session_state = SESSION_STATE_CONNECTING;

  if (app_worker_connect_notify (client_wrk, cs, err, opaque))
    {
      session_close (ss);
      segment_manager_dealloc_fifos (cs->rx_fifo, cs->tx_fifo);
      session_free (cs);
      return -1;
    }

  cs = session_get (cct->c_s_index, cct->c_thread_index);
  cs->session_state = SESSION_STATE_READY;

  return 0;

error:
  app_worker_connect_notify (client_wrk, 0, err, opaque);
  return -1;
}

static int
ct_init_accepted_session (app_worker_t * server_wrk,
			  ct_connection_t * ct, session_t * ls,
			  session_t * ll)
{
  u32 round_rx_fifo_sz, round_tx_fifo_sz, sm_index, seg_size;
  segment_manager_props_t *props;
  application_t *server;
  segment_manager_t *sm;
  u32 margin = 16 << 10;
  fifo_segment_t *seg;
  u64 segment_handle;
  int seg_index, rv;

  server = application_get (server_wrk->app_index);

  props = application_segment_manager_properties (server);
  round_rx_fifo_sz = 1 << max_log2 (props->rx_fifo_size);
  round_tx_fifo_sz = 1 << max_log2 (props->tx_fifo_size);
  /* Increase size because of inefficient chunk allocations. Depending on
   * how data is consumed, it may happen that more chunks than needed are
   * allocated.
   * TODO should remove once allocations are done more efficiently */
  seg_size = 4 * (round_rx_fifo_sz + round_tx_fifo_sz + margin);

  sm = app_worker_get_listen_segment_manager (server_wrk, ll);
  seg_index = segment_manager_add_segment (sm, seg_size);
  if (seg_index < 0)
    {
      clib_warning ("failed to add new cut-through segment");
      return seg_index;
    }
  seg = segment_manager_get_segment_w_lock (sm, seg_index);

  rv = segment_manager_try_alloc_fifos (seg, ls->thread_index,
					props->rx_fifo_size,
					props->tx_fifo_size, &ls->rx_fifo,
					&ls->tx_fifo);
  if (rv)
    {
      clib_warning ("failed to add fifos in cut-through segment");
      segment_manager_segment_reader_unlock (sm);
      goto failed;
    }

  sm_index = segment_manager_index (sm);
  ls->rx_fifo->master_session_index = ls->session_index;
  ls->tx_fifo->master_session_index = ls->session_index;
  ls->rx_fifo->master_thread_index = ls->thread_index;
  ls->tx_fifo->master_thread_index = ls->thread_index;
  ls->rx_fifo->segment_manager = sm_index;
  ls->tx_fifo->segment_manager = sm_index;
  ls->rx_fifo->segment_index = seg_index;
  ls->tx_fifo->segment_index = seg_index;

  segment_handle = segment_manager_segment_handle (sm, seg);
  if ((rv = app_worker_add_segment_notify (server_wrk, segment_handle)))
    {
      clib_warning ("failed to notify server of new segment");
      segment_manager_segment_reader_unlock (sm);
      goto failed;
    }
  segment_manager_segment_reader_unlock (sm);
  ct->segment_handle = segment_handle;

  return 0;

failed:
  segment_manager_lock_and_del_segment (sm, seg_index);
  return rv;
}

typedef struct ct_accept_rpc_args
{
  u32 ll_s_index;
  u32 thread_index;
  ip46_address_t ip;
  u16 port;
  u8 is_ip4;
  u32 opaque;
  u32 client_wrk_index;
} ct_accept_rpc_args_t;

static void
ct_accept_rpc_wrk_handler (void *accept_args)
{
  ct_accept_rpc_args_t *args = (ct_accept_rpc_args_t *) accept_args;
  ct_connection_t *sct, *cct, *ll_ct;
  app_worker_t *server_wrk;
  session_t *ss, *ll;
  u32 cct_index;

  ll = listen_session_get (args->ll_s_index);

  cct = ct_connection_alloc (args->thread_index);
  cct_index = cct->c_c_index;
  sct = ct_connection_alloc (args->thread_index);
  ll_ct = ct_connection_get (ll->connection_index, 0 /* listener thread */ );

  /*
   * Alloc and init client transport
   */
  cct = ct_connection_get (cct_index, args->thread_index);
  cct->c_rmt_port = args->port;
  cct->c_lcl_port = 0;
  cct->c_is_ip4 = args->is_ip4;
  clib_memcpy (&cct->c_rmt_ip, &args->ip, sizeof (args->ip));
  cct->actual_tp = ll_ct->actual_tp;
  cct->is_client = 1;
  cct->c_s_index = ~0;

  /*
   * Init server transport
   */
  sct->c_rmt_port = 0;
  sct->c_lcl_port = ll_ct->c_lcl_port;
  sct->c_is_ip4 = args->is_ip4;
  clib_memcpy (&sct->c_lcl_ip, &ll_ct->c_lcl_ip, sizeof (ll_ct->c_lcl_ip));
  sct->client_wrk = args->client_wrk_index;
  sct->c_proto = TRANSPORT_PROTO_NONE;
  sct->client_opaque = args->opaque;
  sct->actual_tp = ll_ct->actual_tp;

  sct->peer_index = cct->c_c_index;
  cct->peer_index = sct->c_c_index;

  /*
   * Accept server session. Client session is created only after
   * server confirms accept.
   */
  ss = session_alloc (args->thread_index);
  ll = listen_session_get (args->ll_s_index);
  ss->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE,
						     sct->c_is_ip4);
  ss->connection_index = sct->c_c_index;
  ss->listener_handle = listen_session_get_handle (ll);
  ss->session_state = SESSION_STATE_CREATED;

  server_wrk = application_listener_select_worker (ll);
  ss->app_wrk_index = server_wrk->wrk_index;

  sct->c_s_index = ss->session_index;
  sct->server_wrk = ss->app_wrk_index;

  if (ct_init_accepted_session (server_wrk, sct, ss, ll))
    {
      ct_connection_free (sct);
      session_free (ss);
      return;
    }

  ss->session_state = SESSION_STATE_ACCEPTING;
  if (app_worker_accept_notify (server_wrk, ss))
    {
      ct_connection_free (sct);
      segment_manager_dealloc_fifos (ss->rx_fifo, ss->tx_fifo);
      session_free (ss);
      return;
    }

  cct->segment_handle = sct->segment_handle;

  clib_mem_free (args);
}

static int
ct_connect (app_worker_t * client_wrk, session_t * ll,
	    session_endpoint_cfg_t * sep)
{
  ct_accept_rpc_args_t *args;
  ct_main_t *cm = &ct_main;
  u32 thread_index;

  /* Simple round-robin policy for spreading sessions over workers. We skip
   * thread index 0, i.e., offset the index by 1, when we have workers as it
   * is the one dedicated to main thread. Note that n_workers does not include
   * main thread */
  cm->n_sessions += 1;
  thread_index = cm->n_workers ? (cm->n_sessions % cm->n_workers) + 1 : 0;

  args = clib_mem_alloc (sizeof (*args));
  args->ll_s_index = ll->session_index;
  args->thread_index = thread_index;
  clib_memcpy_fast (&args->ip, &sep->ip, sizeof (ip46_address_t));
  args->port = sep->port;
  args->is_ip4 = sep->is_ip4;
  args->opaque = sep->opaque;
  args->client_wrk_index = client_wrk->wrk_index;

  session_send_rpc_evt_to_thread (thread_index, ct_accept_rpc_wrk_handler,
				  args);
  return 0;
}

static u32
ct_start_listen (u32 app_listener_index, transport_endpoint_t * tep)
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

static int
ct_session_connect (transport_endpoint_cfg_t * tep)
{
  session_endpoint_cfg_t *sep_ext;
  session_endpoint_t *sep;
  app_worker_t *app_wrk;
  session_handle_t lh;
  application_t *app;
  app_listener_t *al;
  u32 table_index;
  session_t *ll;
  u8 fib_proto;

  sep_ext = (session_endpoint_cfg_t *) tep;
  sep = (session_endpoint_t *) tep;
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
  al = app_listener_get_w_session (ll);

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

  if (ll)
    return ct_connect (app_wrk, ll, sep_ext);

  /* Failed to connect but no error */
  return 1;
}

static void
ct_session_close (u32 ct_index, u32 thread_index)
{
  ct_connection_t *ct, *peer_ct;
  app_worker_t *app_wrk;
  session_t *s;

  ct = ct_connection_get (ct_index, thread_index);
  peer_ct = ct_connection_get (ct->peer_index, thread_index);
  if (peer_ct)
    {
      peer_ct->peer_index = ~0;
      /* Make sure session was allocated */
      if (peer_ct->c_s_index != ~0)
	session_transport_closing_notify (&peer_ct->connection);
      else
	ct_connection_free (peer_ct);
    }

  s = session_get (ct->c_s_index, ct->c_thread_index);
  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (app_wrk)
    app_worker_del_segment_notify (app_wrk, ct->segment_handle);
  session_free_w_fifos (s);
  if (ct->is_client)
    segment_manager_dealloc_fifos (ct->client_rx_fifo, ct->client_tx_fifo);

  ct_connection_free (ct);
}

static transport_connection_t *
ct_session_get (u32 ct_index, u32 thread_index)
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
  /* If event enqueued towards peer, remove from scheduler and
   * remove session tx flag, i.e., accept new tx events */
  if (!ct_session_tx (s))
    {
      sp->flags = TRANSPORT_SND_F_DESCHED;
      svm_fifo_unset_event (s->tx_fifo);
    }
  /* The scheduler uses packet count as a means of upper bounding the amount
   * of work done per dispatch. So make it look like we have sent something */
  return 1;
}

static int
ct_app_rx_evt (transport_connection_t * tc)
{
  ct_connection_t *ct = (ct_connection_t *) tc, *peer_ct;
  session_t *ps;

  peer_ct = ct_connection_get (ct->peer_index, tc->thread_index);
  if (!peer_ct)
    return -1;
  ps = session_get (peer_ct->c_s_index, peer_ct->c_thread_index);
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
  u32 thread_index = va_arg (*args, u32);
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
  ct_main.n_workers = vlib_num_workers ();
  vec_validate (ct_main.connections, ct_main.n_workers);
  return 0;
}

/* *INDENT-OFF* */
static const transport_proto_vft_t cut_thru_proto = {
  .enable = ct_enable_disable,
  .start_listen = ct_start_listen,
  .stop_listen = ct_stop_listen,
  .get_listener = ct_listener_get,
  .connect = ct_session_connect,
  .close = ct_session_close,
  .get_connection = ct_session_get,
  .custom_tx = ct_custom_tx,
  .app_rx_evt = ct_app_rx_evt,
  .format_listener = format_ct_listener,
  .format_connection = format_ct_session,
  .transport_options = {
    .name = "ct",
    .short_name = "C",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};
/* *INDENT-ON* */

int
ct_session_tx (session_t * s)
{
  ct_connection_t *ct, *peer_ct;
  session_t *peer_s;

  ct = (ct_connection_t *) session_get_transport (s);
  peer_ct = ct_connection_get (ct->peer_index, ct->c_thread_index);
  if (!peer_ct)
    return 0;
  peer_s = session_get (peer_ct->c_s_index, peer_ct->c_thread_index);
  if (peer_s->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
    return 0;
  return session_enqueue_notify (peer_s);
}

static clib_error_t *
ct_transport_init (vlib_main_t * vm)
{
  transport_register_protocol (TRANSPORT_PROTO_NONE, &cut_thru_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_NONE, &cut_thru_proto,
			       FIB_PROTOCOL_IP6, ~0);
  return 0;
}

VLIB_INIT_FUNCTION (ct_transport_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
