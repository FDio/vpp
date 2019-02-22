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

typedef struct ct_connection_
{
  transport_connection_t connection;
  u32 client_wrk;
  u32 server_wrk;
  u32 transport_listener_index;
  transport_proto_t actual_tp;
} ct_connection_t;

ct_connection_t *connections;

ct_connection_t *
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

ct_connection_t *
ct_connection_get (u32 ct_index)
{
  if (pool_is_free_index (connections, ct_index))
    return 0;
  return pool_elt_at_index (connections, ct_index);
}

void
ct_connection_free (ct_connection_t * ct)
{
  if (CLIB_DEBUG)
    memset (ct, 0xfc, sizeof (*ct));
  pool_put (connections, ct);
}

void
application_local_listener_session_endpoint (session_t * ll,
					     session_endpoint_t * sep)
{
  ct_connection_t *ct;
  ct = (ct_connection_t *) session_get_transport (ll);
  sep->transport_proto = ct->actual_tp;
  sep->port = ct->c_lcl_port;
  sep->is_ip4 = ct->c_is_ip4;
}

local_session_t *
app_worker_local_session_alloc (app_worker_t * app_wrk)
{
  local_session_t *s;
  pool_get (app_wrk->local_sessions, s);
  clib_memset (s, 0, sizeof (*s));
  s->app_wrk_index = app_wrk->wrk_index;
  s->session_index = s - app_wrk->local_sessions;
  s->session_type = session_type_from_proto_and_ip (TRANSPORT_PROTO_NONE, 0);
  return s;
}

void
app_worker_local_session_free (app_worker_t * app_wrk, local_session_t * s)
{
  pool_put (app_wrk->local_sessions, s);
  if (CLIB_DEBUG)
    clib_memset (s, 0xfc, sizeof (*s));
}

local_session_t *
app_worker_get_local_session (app_worker_t * app_wrk, u32 session_index)
{
  if (pool_is_free_index (app_wrk->local_sessions, session_index))
    return 0;
  return pool_elt_at_index (app_wrk->local_sessions, session_index);
}

local_session_t *
app_worker_get_local_session_from_handle (session_handle_t handle)
{
  app_worker_t *server_wrk;
  u32 session_index, server_wrk_index;
  local_session_parse_handle (handle, &server_wrk_index, &session_index);
  server_wrk = app_worker_get_if_valid (server_wrk_index);
  if (!server_wrk)
    return 0;
  return app_worker_get_local_session (server_wrk, session_index);
}

static inline u64
application_client_local_connect_key (local_session_t * ls)
{
  return (((u64) ls->app_wrk_index) << 32 | (u64) ls->session_index);
}

static inline void
application_client_local_connect_key_parse (u64 key, u32 * app_wrk_index,
					    u32 * session_index)
{
  *app_wrk_index = key >> 32;
  *session_index = key & 0xFFFFFFFF;
}

void
app_worker_local_sessions_free (app_worker_t * app_wrk)
{
  u32 index, server_wrk_index, session_index;
  u64 handle, *handles = 0;
  app_worker_t *server_wrk;
  segment_manager_t *sm;
  local_session_t *ls;
  int i;

  /*
   * Local sessions
   */
  if (app_wrk->local_sessions)
    {
      /* *INDENT-OFF* */
      pool_foreach (ls, app_wrk->local_sessions, ({
	app_worker_local_session_disconnect (app_wrk->wrk_index, ls);
      }));
      /* *INDENT-ON* */
    }

  /*
   * Local connects
   */
  vec_reset_length (handles);
  /* *INDENT-OFF* */
  hash_foreach (handle, index, app_wrk->local_connects, ({
    vec_add1 (handles, handle);
  }));
  /* *INDENT-ON* */

  for (i = 0; i < vec_len (handles); i++)
    {
      application_client_local_connect_key_parse (handles[i],
						  &server_wrk_index,
						  &session_index);
      server_wrk = app_worker_get_if_valid (server_wrk_index);
      if (server_wrk)
	{
	  ls = app_worker_get_local_session (server_wrk, session_index);
	  app_worker_local_session_disconnect (app_wrk->wrk_index, ls);
	}
    }

  sm = segment_manager_get (app_wrk->local_segment_manager);
  sm->app_wrk_index = SEGMENT_MANAGER_INVALID_APP_INDEX;
  segment_manager_del (sm);
}

int
app_worker_local_session_cleanup (app_worker_t * client_wrk,
				  app_worker_t * server_wrk,
				  local_session_t * ls)
{
  svm_fifo_segment_private_t *seg;
  session_t *listener;
  segment_manager_t *sm;
  u64 client_key;
  u8 has_transport;

  /* Retrieve listener transport type as it is the one that decides where
   * the fifos are allocated */
  has_transport = application_local_session_listener_has_transport (ls);
  if (!has_transport)
    sm = app_worker_get_local_segment_manager_w_session (server_wrk, ls);
  else
    {
      listener = listen_session_get (ls->listener_index);
      sm = app_worker_get_listen_segment_manager (server_wrk, listener);
    }

  seg = segment_manager_get_segment (sm, ls->svm_segment_index);
  if (client_wrk)
    {
      client_key = application_client_local_connect_key (ls);
      hash_unset (client_wrk->local_connects, client_key);
    }

  if (!has_transport)
    {
      application_t *server = application_get (server_wrk->app_index);
      u64 segment_handle = segment_manager_segment_handle (sm, seg);
      server->cb_fns.del_segment_callback (server_wrk->api_client_index,
					   segment_handle);
      if (client_wrk)
	{
	  application_t *client = application_get (client_wrk->app_index);
	  client->cb_fns.del_segment_callback (client_wrk->api_client_index,
					       segment_handle);
	}
      segment_manager_del_segment (sm, seg);
    }

  app_worker_local_session_free (server_wrk, ls);

  return 0;
}

int
app_worker_local_session_connect_notify (local_session_t * ls)
{
  svm_fifo_segment_private_t *seg;
  app_worker_t *client_wrk, *server_wrk;
  segment_manager_t *sm;
  application_t *client;
  int rv, is_fail = 0;
  u64 segment_handle;
  u64 client_key;

  client_wrk = app_worker_get (ls->client_wrk_index);
  server_wrk = app_worker_get (ls->app_wrk_index);
  client = application_get (client_wrk->app_index);

  sm = app_worker_get_local_segment_manager_w_session (server_wrk, ls);
  seg = segment_manager_get_segment_w_lock (sm, ls->svm_segment_index);
  segment_handle = segment_manager_segment_handle (sm, seg);
  if ((rv = client->cb_fns.add_segment_callback (client_wrk->api_client_index,
						 segment_handle)))
    {
      clib_warning ("failed to notify client %u of new segment",
		    ls->client_wrk_index);
      segment_manager_segment_reader_unlock (sm);
      app_worker_local_session_disconnect (ls->client_wrk_index, ls);
      is_fail = 1;
    }
  else
    {
      segment_manager_segment_reader_unlock (sm);
    }

  client->cb_fns.session_connected_callback (client_wrk->wrk_index,
					     ls->client_opaque,
					     (session_t *) ls, is_fail);

  client_key = application_client_local_connect_key (ls);
  hash_set (client_wrk->local_connects, client_key, client_key);
  return 0;
}

static void
application_local_session_fix_eventds (svm_msg_q_t * sq, svm_msg_q_t * cq)
{
  int fd;

  /*
   * segment manager initializes only the producer eventds, since vpp is
   * typically the producer. But for local sessions, we also pass to the
   * apps the mqs they listen on for events from peer apps, so they are also
   * consumer fds.
   */
  fd = svm_msg_q_get_producer_eventfd (sq);
  svm_msg_q_set_consumer_eventfd (sq, fd);
  fd = svm_msg_q_get_producer_eventfd (cq);
  svm_msg_q_set_consumer_eventfd (cq, fd);
}

int
app_worker_local_session_connect (app_worker_t * client_wrk,
				  app_worker_t * server_wrk,
				  session_t * ll, u32 opaque)
{
  u32 seg_size, evt_q_sz, evt_q_elts, margin = 16 << 10;
  u32 round_rx_fifo_sz, round_tx_fifo_sz, sm_index;
  segment_manager_properties_t *props, *cprops;
  int rv, has_transport, seg_index;
  svm_fifo_segment_private_t *seg;
  application_t *server, *client;
  segment_manager_t *sm;
  local_session_t *ls;
  svm_msg_q_t *sq, *cq;
  u64 segment_handle;

  ls = app_worker_local_session_alloc (server_wrk);
  server = application_get (server_wrk->app_index);
  client = application_get (client_wrk->app_index);

  props = application_segment_manager_properties (server);
  cprops = application_segment_manager_properties (client);
  evt_q_elts = props->evt_q_size + cprops->evt_q_size;
  evt_q_sz = segment_manager_evt_q_expected_size (evt_q_elts);
  round_rx_fifo_sz = 1 << max_log2 (props->rx_fifo_size);
  round_tx_fifo_sz = 1 << max_log2 (props->tx_fifo_size);
  seg_size = round_rx_fifo_sz + round_tx_fifo_sz + evt_q_sz + margin;

  has_transport = session_has_transport (ll);
  if (!has_transport)
    {
      /* Local sessions don't have backing transport */
      transport_connection_t *tc;
      tc = session_get_transport (ll);
      ls->port = tc->lcl_port;
      sm = app_worker_get_local_segment_manager (server_wrk);
    }
  else
    {
      session_t *sl = (session_t *) ll;
      transport_connection_t *tc;
      tc = listen_session_get_transport (sl);
      ls->port = tc->lcl_port;
      sm = app_worker_get_listen_segment_manager (server_wrk, sl);
    }

  seg_index = segment_manager_add_segment (sm, seg_size);
  if (seg_index < 0)
    {
      clib_warning ("failed to add new cut-through segment");
      return seg_index;
    }
  seg = segment_manager_get_segment_w_lock (sm, seg_index);
  sq = segment_manager_alloc_queue (seg, props);
  cq = segment_manager_alloc_queue (seg, cprops);

  if (props->use_mq_eventfd)
    application_local_session_fix_eventds (sq, cq);

  ls->server_evt_q = pointer_to_uword (sq);
  ls->client_evt_q = pointer_to_uword (cq);
  rv = segment_manager_try_alloc_fifos (seg, props->rx_fifo_size,
					props->tx_fifo_size,
					&ls->rx_fifo, &ls->tx_fifo);
  if (rv)
    {
      clib_warning ("failed to add fifos in cut-through segment");
      segment_manager_segment_reader_unlock (sm);
      goto failed;
    }
  sm_index = segment_manager_index (sm);
  ls->rx_fifo->ct_session_index = ls->session_index;
  ls->tx_fifo->ct_session_index = ls->session_index;
  ls->rx_fifo->segment_manager = sm_index;
  ls->tx_fifo->segment_manager = sm_index;
  ls->rx_fifo->segment_index = seg_index;
  ls->tx_fifo->segment_index = seg_index;
  ls->svm_segment_index = seg_index;
  ls->listener_index = ll->session_index;
  ls->client_wrk_index = client_wrk->wrk_index;
  ls->client_opaque = opaque;
  ls->listener_session_type = ll->session_type;
  ls->session_state = SESSION_STATE_READY;

  segment_handle = segment_manager_segment_handle (sm, seg);
  if ((rv = server->cb_fns.add_segment_callback (server_wrk->api_client_index,
						 segment_handle)))
    {
      clib_warning ("failed to notify server of new segment");
      segment_manager_segment_reader_unlock (sm);
      goto failed;
    }
  segment_manager_segment_reader_unlock (sm);
  if ((rv = server->cb_fns.session_accept_callback ((session_t *) ls)))
    {
      clib_warning ("failed to send accept cut-through notify to server");
      goto failed;
    }
  if (server->flags & APP_OPTIONS_FLAGS_IS_BUILTIN)
    app_worker_local_session_connect_notify (ls);

  return 0;

failed:
  if (!has_transport)
    segment_manager_del_segment (sm, seg);
  return rv;
}

int
app_worker_local_session_disconnect (u32 app_wrk_index, local_session_t * ls)
{
  app_worker_t *client_wrk, *server_wrk;

  client_wrk = app_worker_get_if_valid (ls->client_wrk_index);
  server_wrk = app_worker_get (ls->app_wrk_index);

  if (ls->session_state == SESSION_STATE_CLOSED)
    return app_worker_local_session_cleanup (client_wrk, server_wrk, ls);

  if (app_wrk_index == ls->client_wrk_index)
    {
      mq_send_local_session_disconnected_cb (ls->app_wrk_index, ls);
    }
  else
    {
      if (!client_wrk)
	{
	  return app_worker_local_session_cleanup (client_wrk, server_wrk,
						   ls);
	}
      else if (ls->session_state < SESSION_STATE_READY)
	{
	  application_t *client = application_get (client_wrk->app_index);
	  client->cb_fns.session_connected_callback (client_wrk->wrk_index,
						     ls->client_opaque,
						     (session_t *) ls,
						     1 /* is_fail */ );
	  ls->session_state = SESSION_STATE_CLOSED;
	  return app_worker_local_session_cleanup (client_wrk, server_wrk,
						   ls);
	}
      else
	{
	  mq_send_local_session_disconnected_cb (client_wrk->wrk_index, ls);
	}
    }

  ls->session_state = SESSION_STATE_CLOSED;

  return 0;
}

int
app_worker_local_session_disconnect_w_index (u32 app_wrk_index, u32 ls_index)
{
  app_worker_t *app_wrk;
  local_session_t *ls;
  app_wrk = app_worker_get (app_wrk_index);
  ls = app_worker_get_local_session (app_wrk, ls_index);
  return app_worker_local_session_disconnect (app_wrk_index, ls);
}

void
app_worker_format_local_sessions (app_worker_t * app_wrk, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  app_worker_t *client_wrk;
  local_session_t *ls;
  transport_proto_t tp;
  u8 *conn = 0;

  /* Header */
  if (app_wrk == 0)
    {
      vlib_cli_output (vm, "%-40s%-15s%-20s", "Connection", "ServerApp",
		       "ClientApp");
      return;
    }

  if (!pool_elts (app_wrk->local_sessions)
      && !pool_elts (app_wrk->local_connects))
    return;

  /* *INDENT-OFF* */
  pool_foreach (ls, app_wrk->local_sessions, ({
    tp = session_type_transport_proto(ls->listener_session_type);
    conn = format (0, "[L][%U] *:%u", format_transport_proto_short, tp,
                   ls->port);
    client_wrk = app_worker_get (ls->client_wrk_index);
    vlib_cli_output (vm, "%-40v%-15u%-20u", conn, ls->app_index,
                     client_wrk->app_index);
    vec_reset_length (conn);
  }));
  /* *INDENT-ON* */

  vec_free (conn);
}

void
app_worker_format_local_connects (app_worker_t * app, int verbose)
{
  vlib_main_t *vm = vlib_get_main ();
  u32 app_wrk_index, session_index;
  app_worker_t *server_wrk;
  local_session_t *ls;
  u64 client_key;
  u64 value;

  /* Header */
  if (app == 0)
    {
      if (verbose)
	vlib_cli_output (vm, "%-40s%-15s%-20s%-10s", "Connection", "App",
			 "Peer App", "SegManager");
      else
	vlib_cli_output (vm, "%-40s%-15s%-20s", "Connection", "App",
			 "Peer App");
      return;
    }

  if (!app->local_connects)
    return;

  /* *INDENT-OFF* */
  hash_foreach (client_key, value, app->local_connects, ({
    application_client_local_connect_key_parse (client_key, &app_wrk_index,
                                                &session_index);
    server_wrk = app_worker_get (app_wrk_index);
    ls = app_worker_get_local_session (server_wrk, session_index);
    vlib_cli_output (vm, "%-40s%-15s%-20s", "TODO", ls->app_wrk_index,
                     ls->client_wrk_index);
  }));
  /* *INDENT-ON* */
}

u32
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
  return ct->c_c_index;
}

u32
ct_stop_listen (u32 ct_index)
{
  ct_connection_t *ct;
  ct = ct_connection_get (ct_index);
  ct_connection_free (ct);
  return 0;
}

transport_connection_t *
ct_listener_get (u32 ct_index)
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

u8 *
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

/* *INDENT-OFF* */
const static transport_proto_vft_t cut_thru_proto = {
  .start_listen = ct_start_listen,
  .stop_listen = ct_stop_listen,
  .get_listener = ct_listener_get,
  .tx_type = TRANSPORT_TX_INTERNAL,
  .service_type = TRANSPORT_SERVICE_APP,
  .format_listener = format_ct_listener,
};
/* *INDENT-ON* */

static clib_error_t *
ct_transport_init (vlib_main_t * vm)
{
  transport_register_protocol (TRANSPORT_PROTO_NONE, &cut_thru_proto,
			       FIB_PROTOCOL_IP4, ~0);
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
