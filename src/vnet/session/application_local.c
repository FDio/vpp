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

static ct_connection_t *connections;

static void
ct_enable_disable_main_pre_input_node (u8 is_add)
{
  u32 n_conns;

  if (!vlib_num_workers ())
    return;

  n_conns = pool_elts (connections);
  if (n_conns > 2)
    return;

  if (n_conns > 0 && is_add)
    vlib_node_set_state (vlib_get_main (),
			 session_queue_pre_input_node.index,
			 VLIB_NODE_STATE_POLLING);
  else if (n_conns == 0)
    vlib_node_set_state (vlib_get_main (),
			 session_queue_pre_input_node.index,
			 VLIB_NODE_STATE_DISABLED);
}

static ct_connection_t *
ct_connection_alloc (void)
{
  ct_connection_t *ct;

  pool_get_zero (connections, ct);
  ct->c_c_index = ct - connections;
  ct->c_thread_index = 0;
  ct->client_wrk = ~0;
  ct->server_wrk = ~0;
  return ct;
}

static ct_connection_t *
ct_connection_get (u32 ct_index)
{
  if (pool_is_free_index (connections, ct_index))
    return 0;
  return pool_elt_at_index (connections, ct_index);
}

static void
ct_connection_free (ct_connection_t * ct)
{
  if (CLIB_DEBUG)
    memset (ct, 0xfc, sizeof (*ct));
  pool_put (connections, ct);
}

session_t *
ct_session_get_peer (session_t * s)
{
  ct_connection_t *ct, *peer_ct;
  ct = ct_connection_get (s->connection_index);
  peer_ct = ct_connection_get (ct->peer_index);
  return session_get (peer_ct->c_s_index, 0);
}

void
ct_session_endpoint (session_t * ll, session_endpoint_t * sep)
{
  ct_connection_t *ct;
  ct = (ct_connection_t *) session_get_transport (ll);
  sep->transport_proto = ct->actual_tp;
  sep->port = ct->c_lcl_port;
  sep->is_ip4 = ct->c_is_ip4;
}

int
ct_session_connect_notify (session_t * ss)
{
  ct_connection_t *sct, *cct;
  app_worker_t *client_wrk;
  segment_manager_t *sm;
  fifo_segment_t *seg;
  u64 segment_handle;
  int is_fail = 0;
  session_t *cs;
  u32 ss_index;

  ss_index = ss->session_index;
  sct = (ct_connection_t *) session_get_transport (ss);
  client_wrk = app_worker_get (sct->client_wrk);

  sm = segment_manager_get (ss->rx_fifo->segment_manager);
  seg = segment_manager_get_segment_w_lock (sm, ss->rx_fifo->segment_index);
  segment_handle = segment_manager_segment_handle (sm, seg);

  if (app_worker_add_segment_notify (client_wrk, segment_handle))
    {
      clib_warning ("failed to notify client %u of new segment",
		    sct->client_wrk);
      segment_manager_segment_reader_unlock (sm);
      session_close (ss);
      is_fail = 1;
    }
  else
    {
      segment_manager_segment_reader_unlock (sm);
    }

  /* Alloc client session */
  cct = ct_connection_get (sct->peer_index);

  cs = session_alloc (0);
  ss = session_get (ss_index, 0);
  cs->session_type = ss->session_type;
  cs->connection_index = sct->c_c_index;
  cs->listener_index = SESSION_INVALID_INDEX;
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
  if (app_worker_init_connected (client_wrk, cs))
    {
      session_close (ss);
      return -1;
    }

  if (app_worker_connect_notify (client_wrk, is_fail ? 0 : cs,
				 sct->client_opaque))
    {
      session_close (ss);
      return -1;
    }

  cs = session_get (cct->c_s_index, 0);
  cs->session_state = SESSION_STATE_READY;

  return 0;
}

static int
ct_init_local_session (app_worker_t * client_wrk, app_worker_t * server_wrk,
		       ct_connection_t * ct, session_t * ls, session_t * ll)
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
  seg_size = round_rx_fifo_sz + round_tx_fifo_sz + margin;

  sm = app_worker_get_listen_segment_manager (server_wrk, ll);
  seg_index = segment_manager_add_segment (sm, seg_size);
  if (seg_index < 0)
    {
      clib_warning ("failed to add new cut-through segment");
      return seg_index;
    }
  seg = segment_manager_get_segment_w_lock (sm, seg_index);

  rv = segment_manager_try_alloc_fifos (seg, props->rx_fifo_size,
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
  segment_manager_del_segment (sm, seg);
  return rv;
}

static int
ct_connect (app_worker_t * client_wrk, session_t * ll,
	    session_endpoint_cfg_t * sep)
{
  u32 cct_index, ll_index, ll_ct_index;
  ct_connection_t *sct, *cct, *ll_ct;
  app_worker_t *server_wrk;
  session_t *ss;

  ll_index = ll->session_index;
  ll_ct_index = ll->connection_index;

  cct = ct_connection_alloc ();
  cct_index = cct->c_c_index;
  sct = ct_connection_alloc ();
  ll_ct = ct_connection_get (ll_ct_index);

  /*
   * Alloc and init client transport
   */
  cct = ct_connection_get (cct_index);
  cct->c_thread_index = 0;
  cct->c_rmt_port = sep->port;
  cct->c_lcl_port = 0;
  cct->c_is_ip4 = sep->is_ip4;
  clib_memcpy (&cct->c_rmt_ip, &sep->ip, sizeof (sep->ip));
  cct->actual_tp = ll_ct->actual_tp;
  cct->is_client = 1;

  /*
   * Init server transport
   */
  sct->c_thread_index = 0;
  sct->c_rmt_port = 0;
  sct->c_lcl_port = ll_ct->c_lcl_port;
  sct->c_is_ip4 = sep->is_ip4;
  clib_memcpy (&sct->c_lcl_ip, &ll_ct->c_lcl_ip, sizeof (ll_ct->c_lcl_ip));
  sct->client_wrk = client_wrk->wrk_index;
  sct->c_proto = TRANSPORT_PROTO_NONE;
  sct->client_opaque = sep->opaque;
  sct->actual_tp = ll_ct->actual_tp;

  sct->peer_index = cct->c_c_index;
  cct->peer_index = sct->c_c_index;

  /*
   * Accept server session. Client session is created only after
   * server confirms accept.
   */
  ss = session_alloc (0);
  ll = listen_session_get (ll_index);
  ss->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE,
						     sct->c_is_ip4);
  ss->connection_index = sct->c_c_index;
  ss->listener_index = ll->session_index;
  ss->session_state = SESSION_STATE_CREATED;

  server_wrk = application_listener_select_worker (ll);
  ss->app_wrk_index = server_wrk->wrk_index;

  sct->c_s_index = ss->session_index;
  sct->server_wrk = ss->app_wrk_index;

  if (ct_init_local_session (client_wrk, server_wrk, sct, ss, ll))
    {
      clib_warning ("failed");
      ct_connection_free (sct);
      session_free (ss);
      return -1;
    }

  ss->session_state = SESSION_STATE_ACCEPTING;
  if (app_worker_accept_notify (server_wrk, ss))
    {
      clib_warning ("failed");
      ct_connection_free (sct);
      session_free_w_fifos (ss);
      return -1;
    }

  cct->segment_handle = sct->segment_handle;
  ct_enable_disable_main_pre_input_node (1 /* is_add */ );
  return 0;
}

static u32
ct_start_listen (u32 app_listener_index, transport_endpoint_t * tep)
{
  session_endpoint_cfg_t *sep;
  ct_connection_t *ct;

  sep = (session_endpoint_cfg_t *) tep;
  ct = ct_connection_alloc ();
  ct->server_wrk = sep->app_wrk_index;
  ct->c_is_ip4 = sep->is_ip4;
  clib_memcpy (&ct->c_lcl_ip, &sep->ip, sizeof (sep->ip));
  ct->c_lcl_port = sep->port;
  ct->actual_tp = sep->transport_proto;
  ct_enable_disable_main_pre_input_node (1 /* is_add */ );
  return ct->c_c_index;
}

static u32
ct_stop_listen (u32 ct_index)
{
  ct_connection_t *ct;
  ct = ct_connection_get (ct_index);
  ct_connection_free (ct);
  ct_enable_disable_main_pre_input_node (0 /* is_add */ );
  return 0;
}

static transport_connection_t *
ct_listener_get (u32 ct_index)
{
  return (transport_connection_t *) ct_connection_get (ct_index);
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
    return VNET_API_ERROR_APP_CONNECT_FILTERED;

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
    return VNET_API_ERROR_SESSION_CONNECT;

  if (!application_has_global_scope (app))
    return VNET_API_ERROR_APP_CONNECT_SCOPE;

  fib_proto = session_endpoint_fib_proto (sep);
  table_index = application_session_table (app, fib_proto);
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

  ct = ct_connection_get (ct_index);
  peer_ct = ct_connection_get (ct->peer_index);
  if (peer_ct)
    {
      peer_ct->peer_index = ~0;
      session_transport_closing_notify (&peer_ct->connection);
    }

  s = session_get (ct->c_s_index, 0);
  app_wrk = app_worker_get_if_valid (s->app_wrk_index);
  if (app_wrk)
    app_worker_del_segment_notify (app_wrk, ct->segment_handle);
  session_free_w_fifos (s);
  if (ct->is_client)
    segment_manager_dealloc_fifos (ct->client_rx_fifo, ct->client_tx_fifo);

  ct_connection_free (ct);
  ct_enable_disable_main_pre_input_node (0 /* is_add */ );
}

static transport_connection_t *
ct_session_get (u32 ct_index, u32 thread_index)
{
  return (transport_connection_t *) ct_connection_get (ct_index);
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
ct_custom_tx (void *session)
{
  session_t *s = (session_t *) session;
  if (session_has_transport (s))
    return 0;
  return ct_session_tx (s);
}

static int
ct_app_rx_evt (transport_connection_t * tc)
{
  ct_connection_t *ct = (ct_connection_t *) tc, *peer_ct;
  session_t *ps;

  peer_ct = ct_connection_get (ct->peer_index);
  if (!peer_ct)
    return -1;
  ps = session_get (peer_ct->c_s_index, peer_ct->c_thread_index);
  return session_dequeue_notify (ps);
}

static u8 *
format_ct_listener (u8 * s, va_list * args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 __clib_unused verbose = va_arg (*args, u32);
  ct_connection_t *ct = ct_connection_get (tc_index);
  s = format (s, "%-50U", format_ct_connection_id, ct);
  if (verbose)
    s = format (s, "%-15s", "LISTEN");
  return s;
}

static u8 *
format_ct_connection (u8 * s, va_list * args)
{
  ct_connection_t *ct = va_arg (*args, ct_connection_t *);
  u32 verbose = va_arg (*args, u32);

  if (!ct)
    return s;
  s = format (s, "%-50U", format_ct_connection_id, ct);
  if (verbose)
    {
      s = format (s, "%-15s", "ESTABLISHED");
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
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  ct_connection_t *ct;

  ct = ct_connection_get (ct_index);
  if (!ct)
    {
      s = format (s, "empty\n");
      return s;
    }

  s = format (s, "%U", format_ct_connection, ct, verbose);
  return s;
}

/* *INDENT-OFF* */
const static transport_proto_vft_t cut_thru_proto = {
  .start_listen = ct_start_listen,
  .stop_listen = ct_stop_listen,
  .get_listener = ct_listener_get,
  .connect = ct_session_connect,
  .close = ct_session_close,
  .get_connection = ct_session_get,
  .custom_tx = ct_custom_tx,
  .app_rx_evt = ct_app_rx_evt,
  .tx_type = TRANSPORT_TX_INTERNAL,
  .service_type = TRANSPORT_SERVICE_APP,
  .format_listener = format_ct_listener,
  .format_connection = format_ct_session,
};
/* *INDENT-ON* */

int
ct_session_tx (session_t * s)
{
  ct_connection_t *ct, *peer_ct;
  session_t *peer_s;

  ct = (ct_connection_t *) session_get_transport (s);
  peer_ct = ct_connection_get (ct->peer_index);
  if (!peer_ct)
    return -1;
  peer_s = session_get (peer_ct->c_s_index, 0);
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
