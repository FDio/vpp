/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application_eventing.h>
#include <vnet/session/application_local.h>
#include <vnet/session/session.h>
#include <vnet/udp/udp.h>

app_evt_main_t app_evt_main = { .app_index = APP_INVALID_INDEX };

void
app_evt_buffer_append_chunk (app_evt_buffer_t *buf,
			     app_evt_buffer_chunk_t *chunk)
{
  app_evt_buffer_chunk_t *tail;
  buf->len += chunk->len;

  if (buf->tail_chunk == ~0)
    {
      buf->head_chunk = chunk->chunk_index;
      buf->tail_chunk = chunk->chunk_index;
      return;
    }
  tail = app_evt_buffer_get_chunk (buf, buf->tail_chunk);
  tail->next_index = chunk->chunk_index;
  buf->tail_chunk = chunk->chunk_index;
}

void
app_evt_collector_wrk_send (app_evt_collector_wrk_t *cwrk)
{
  u32 max_enq, to_send = 0, next_c;
  app_evt_buffer_chunk_t *c;
  svm_fifo_seg_t *seg;
  session_t *cs;
  int wrote;

  cs = session_get_from_handle_if_valid (cwrk->session_handle);
  if (!cs)
    {
      clib_warning ("session not found");
      return;
    }
  max_enq = svm_fifo_max_enqueue_prod (cs->tx_fifo);

  if (!max_enq)
    {
      svm_fifo_add_want_deq_ntf (cs->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return;
    }

  c = app_evt_buffer_get_chunk (&cwrk->buf, cwrk->buf.head_chunk);
  while (c)
    {
      if (c->len + to_send > max_enq)
	break;

      to_send += c->len;
      vec_add2 (cwrk->segs, seg, 1);
      seg->data = c->data;
      seg->len = c->len;

      c = app_evt_buffer_get_chunk (&cwrk->buf, c->next_index);
    }

  if (session_has_transport (cs))
    {
      wrote = svm_fifo_enqueue_segments (
	cs->tx_fifo, cwrk->segs, vec_len (cwrk->segs), 0 /* allow partial*/);
    }
  else
    {
      /* Special handling of client cut-throughs */
      ct_connection_t *cct;

      cct = (ct_connection_t *) session_get_transport (cs);
      wrote =
	svm_fifo_enqueue_segments (cct->client_tx_fifo, cwrk->segs,
				   vec_len (cwrk->segs), 0 /* allow partial*/);
    }

  if (wrote > 0 && svm_fifo_set_event (cs->tx_fifo))
    session_program_tx_io_evt (cs->handle, SESSION_IO_EVT_TX);

  cwrk->buf.len -= wrote > 0 ? wrote : 0;

  next_c = cwrk->buf.head_chunk;
  while (wrote > 0)
    {
      c = app_evt_buffer_get_chunk (&cwrk->buf, next_c);
      next_c = c->next_index;
      ASSERT (wrote >= c->len);
      wrote -= c->len;
      app_evt_buffer_free_chunk (&cwrk->buf, c);
    }
  ASSERT (wrote == 0);
  cwrk->buf.head_chunk = next_c;
  if (cwrk->buf.head_chunk == ~0)
    cwrk->buf.tail_chunk = ~0;

  vec_reset_length (cwrk->segs);
  if (cwrk->buf.len)
    svm_fifo_add_want_deq_ntf (cs->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return;
}

static void
app_evt_collector_log_session (app_evt_collector_t *c, session_t *s)
{
  app_evt_msg_data_session_stats_t *sess_stats;
  app_evt_collector_wrk_t *cwrk;
  app_evt_buffer_chunk_t *chunk;
  app_evt_msg_data_t *data_msg;
  transport_connection_t *tc;
  app_evt_msg_t *msg;

  tc = session_get_transport (s);
  if (!tc)
    return;

  cwrk = app_evt_collector_wrk_get (c, s->thread_index);
  chunk = app_evt_buffer_alloc_chunk (&cwrk->buf);

  msg = app_evt_buf_chunk_append_uninit (chunk, sizeof (app_evt_msg_t));
  msg->msg_type = APP_EVT_MSG_DATA;

  data_msg =
    app_evt_buf_chunk_append_uninit (chunk, sizeof (app_evt_msg_data_t));
  data_msg->data_type = APP_EVT_MSG_DATA_SESSION_STATS;

  sess_stats = app_evt_buf_chunk_append_uninit (
    chunk, sizeof (app_evt_msg_data_session_stats_t));
  sess_stats->transport_proto_type = tc->proto;

  switch (tc->proto)
    {
    case TRANSPORT_PROTO_TCP:
      {
	tcp_connection_t *tcp_conn = (tcp_connection_t *) tc;
	tcp_session_stats_t *tcp_stats = app_evt_buf_chunk_append_uninit (
	  chunk, sizeof (tcp_session_stats_t));
	sess_stats->msg_len = sizeof (app_evt_msg_data_session_stats_t) +
			      sizeof (tcp_session_stats_t);
	clib_memcpy_fast (tcp_stats->conn_id, tc->opaque_conn_id,
			  sizeof (tc->opaque_conn_id));
	tcp_stats->end_ts = transport_time_now (s->thread_index);
	tcp_stats->close_reason = s->flags & SESSION_F_TPT_INIT_CLOSE ?
				    APP_EVT_SESSION_STAT_TRANSPORT_CLOSED :
				    APP_EVT_SESSION_STAT_APP_CLOSED;

#define _(type, name) tcp_stats->name = tcp_conn->name;
	foreach_tcp_transport_stat
#undef _
      }
      break;
    case TRANSPORT_PROTO_UDP:
      {
	udp_connection_t *udp_conn = (udp_connection_t *) tc;
	udp_session_stats_t *udp_stats = app_evt_buf_chunk_append_uninit (
	  chunk, sizeof (udp_session_stats_t));
	sess_stats->msg_len = sizeof (app_evt_msg_data_session_stats_t) +
			      sizeof (udp_session_stats_t);
	clib_memcpy_fast (udp_stats->conn_id, tc->opaque_conn_id,
			  sizeof (tc->opaque_conn_id));
	udp_stats->end_ts = transport_time_now (s->thread_index);

#define _(type, name) udp_stats->name = udp_conn->name;
	foreach_udp_transport_stat
#undef _
      }
      break;
    case TRANSPORT_PROTO_CT:
      {
	ct_connection_t *ct_conn = (ct_connection_t *) tc;
	ct_session_stats_t *ct_stats =
	  app_evt_buf_chunk_append_uninit (chunk, sizeof (ct_session_stats_t));
	sess_stats->msg_len = sizeof (app_evt_msg_data_session_stats_t) +
			      sizeof (ct_session_stats_t);
	clib_memcpy_fast (ct_stats->conn_id, tc->opaque_conn_id,
			  sizeof (tc->opaque_conn_id));
	ct_stats->actual_proto = ct_conn->actual_tp;
	ct_stats->end_ts = transport_time_now (s->thread_index);
	ct_stats->close_reason = s->flags & SESSION_F_TPT_INIT_CLOSE ?
				   APP_EVT_SESSION_STAT_TRANSPORT_CLOSED :
				   APP_EVT_SESSION_STAT_APP_CLOSED;
      }
      break;
    default:
      break;
    };

  data_msg->msg_len = sizeof (app_evt_msg_data_t) + sess_stats->msg_len;
  msg->msg_len = sizeof (app_evt_msg_t) + data_msg->msg_len;

  app_evt_buffer_append_chunk (&cwrk->buf, chunk);
  app_evt_collector_wrk_send (cwrk);
}

app_evt_collector_t *
app_evt_collector_get (u32 c_index)
{
  app_evt_main_t *alm = &app_evt_main;
  if (pool_is_free_index (alm->collectors, c_index))
    return 0;
  return pool_elt_at_index (alm->collectors, c_index);
}

static void
app_evt_collect_on_session_cleanup (session_t *s)
{
  app_evt_collector_t *c;
  app_worker_t *app_wrk;
  application_t *app;

  app_wrk = app_worker_get (s->app_wrk_index);
  app = application_get (app_wrk->app_index);
  /* If filtering configured, log only if listener found */
  if (app->evt_collector_session_filter &&
      !hash_get (app->evt_collector_session_filter, s->listener_handle))
    return;
  c = app_evt_collector_get (app->evt_collector_index);
  if (PREDICT_FALSE (!c || !c->is_ready))
    return;
  app_evt_collector_log_session (c, s);
}

void *
app_evt_collector_get_cb_fn (void)
{
  app_evt_main_t *alm = &app_evt_main;

  if (alm->app_index == APP_INVALID_INDEX)
    return 0;

  return app_evt_collect_on_session_cleanup;
}

static void
alc_more_connects_cb_fn (void *arg)
{
  app_evt_main_t *alm = &app_evt_main;
  vnet_connect_args_t _a = {}, *a = &_a;
  u32 c_index = pointer_to_uword (arg);
  app_evt_collector_t *c;
  int rv;

  c = app_evt_collector_get (c_index);
  a->sep_ext = c->cfg.sep;
  a->app_index = alm->app_index;
  a->api_context = c->collector_index;

  if ((rv = vnet_connect (a)))
    {
      clib_warning ("could not connect session for collector %u: %U", c_index,
		    format_session_error, rv);
      return;
    }
}

static void
app_evt_collector_program_connect (u32 c_index)
{
  u32 connects_thread = transport_cl_thread ();

  session_send_rpc_evt_to_thread_force (connects_thread,
					alc_more_connects_cb_fn,
					uword_to_pointer (c_index, void *));
}

static int
app_evt_collector_connected_callback (u32 app_index, u32 api_context,
				      session_t *s, session_error_t err)
{
  app_evt_main_t *alm = &app_evt_main;
  app_evt_collector_wrk_t *cwrk;
  u32 session_map, num_workers;
  app_evt_collector_t *c;

  c = app_evt_collector_get (api_context);
  if (!c)
    {
      clib_warning ("app_evt_collector_connected_callback: "
		    "invalid collector index %u",
		    api_context);
      return -1;
    }

  CLIB_SPINLOCK_LOCK (c->session_map_lock);
  session_map = c->session_map;
  CLIB_SPINLOCK_UNLOCK (c->session_map_lock);

  if (err)
    goto check_map;

  /* Already have a session */
  if (session_map & (1 << s->thread_index))
    {
      vnet_disconnect_args_t a = { session_handle (s), alm->app_index };
      vnet_disconnect_session (&a);
      goto check_map;
    }

  cwrk = app_evt_collector_wrk_get (c, s->thread_index);
  cwrk->session_handle = session_handle (s);
  s->opaque = c->collector_index << 16 | s->thread_index;
  s->session_state = SESSION_STATE_READY;

  CLIB_SPINLOCK_LOCK (c->session_map_lock);
  c->session_map |= 1 << s->thread_index;
  session_map = c->session_map;
  CLIB_SPINLOCK_UNLOCK (c->session_map_lock);

check_map:

  num_workers = vlib_num_workers ();

  /* If no workers and we have a session, accept it */
  if (!num_workers && (session_map != 0))
    return 0;

  /* If not all threads apart from 0 (main) are set
   * then we need to connect more sessions */
  if (session_map != (1 << (num_workers + 1)) - 2)
    app_evt_collector_program_connect (c->collector_index);
  else
    c->is_ready = 1;

  return 0;
}

static int
app_evt_collector_accept_callback (session_t *s)
{
  clib_warning ("not implemented");
  return -1;
}

static void
app_evt_collector_disconnect_callback (session_t *s)
{
  app_evt_collector_t *c = app_evt_collector_get (s->opaque >> 16);
  vnet_disconnect_args_t a = { session_handle (s), app_evt_main.app_index };
  app_evt_collector_wrk_t *cwrk;

  vnet_disconnect_session (&a);

  CLIB_SPINLOCK_LOCK (c->session_map_lock);
  c->session_map &= ~(1 << s->thread_index);
  c->is_ready = 0;
  CLIB_SPINLOCK_UNLOCK (c->session_map_lock);

  cwrk = app_evt_collector_wrk_get (c, s->thread_index);
  cwrk->session_handle = SESSION_INVALID_HANDLE;

  /* Worker session disconnected, try to reconnect */
  app_evt_collector_program_connect (c->collector_index);
}

static void
app_evt_collector_reset_callback (session_t *s)
{
  app_evt_collector_disconnect_callback (s);
}

static int
app_evt_collector_rx_callback (session_t *s)
{
  /* TODO */
  return 0;
}

static int
app_evt_collector_tx_callback (session_t *s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  application_t *app = application_get (app_wrk->app_index);
  app_evt_collector_t *c = app_evt_collector_get (app->evt_collector_index);
  app_evt_collector_wrk_t *cwrk = &c->wrk[s->thread_index];

  /* If we have data buffered, try to send it now */
  if (cwrk->buf.len)
    app_evt_collector_wrk_send (cwrk);

  return 0;
}

static int
app_evt_collector_add_segment_cb (u32 client_index, u64 segment_handle)
{
  return 0;
}

static int
app_evt_collector_del_segment_cb (u32 app_wrk_index, u64 segment_handle)
{
  return 0;
}

static session_cb_vft_t app_evtger_cb_vft = {
  .session_accept_callback = app_evt_collector_accept_callback,
  .session_connected_callback = app_evt_collector_connected_callback,
  .session_disconnect_callback = app_evt_collector_disconnect_callback,
  .session_reset_callback = app_evt_collector_reset_callback,
  .builtin_app_rx_callback = app_evt_collector_rx_callback,
  .builtin_app_tx_callback = app_evt_collector_tx_callback,
  .add_segment_callback = app_evt_collector_add_segment_cb,
  .del_segment_callback = app_evt_collector_del_segment_cb,
};

static int
app_evt_collector_connect (app_evt_collector_t *c)
{
  app_evt_main_t *alm = &app_evt_main;
  u32 num_threads;
  int i, rv;

  num_threads = vlib_num_workers ();
  num_threads = num_threads == 0 ? 1 : num_threads;

  vnet_connect_args_t cargs = {
    .sep_ext = c->cfg.sep,
    .app_index = alm->app_index,
    .api_context = c->collector_index,
  };

  for (i = 0; i < num_threads; i++)
    {
      rv = vnet_connect (&cargs);
      if (rv)
	{
	  clib_warning ("could not connect %U", format_session_error, rv);
	  return -1;
	}
    }

  return 0;
}

int
app_evt_collector_add (app_evt_collector_cfg_t *cfg)
{
  app_evt_main_t *alm = &app_evt_main;
  app_evt_collector_t *c;

  pool_get_zero (alm->collectors, c);
  c->cfg = *cfg;

  vec_validate (c->wrk, vlib_num_workers ());
  for (int i = 0; i < vec_len (c->wrk); i++)
    {
      c->wrk[i].session_handle = SESSION_INVALID_HANDLE;
      c->wrk[i].buf.head_chunk = ~0;
      c->wrk[i].buf.tail_chunk = ~0;
    }

  return app_evt_collector_connect (c);
}

static int
app_evt_collector_del (app_evt_collector_cfg_t *cfg)
{
  app_evt_collector_wrk_t *cwrk;
  app_evt_collector_t *c;

  pool_foreach (c, app_evt_main.collectors)
    {
      if (c->cfg.sep.is_ip4 == cfg->sep.is_ip4 &&
	  c->cfg.sep.port == cfg->sep.port &&
	  ip46_address_cmp (&c->cfg.sep.ip, &cfg->sep.ip) == 0)
	{
	  pool_put (app_evt_main.collectors, c);
	  vec_foreach (cwrk, c->wrk)
	    {
	      if (cwrk->session_handle != SESSION_INVALID_HANDLE)
		{
		  vnet_disconnect_args_t a = { cwrk->session_handle,
					       app_evt_main.app_index };
		  vnet_disconnect_session (&a);
		}
	    }
	  return 0;
	}
    }
  return -1;
}

static int
app_evt_collector_attach (void)
{
  app_evt_main_t *alm = &app_evt_main;
  vnet_app_attach_args_t _a = {}, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  int rv;

  clib_memset (options, 0, sizeof (options));

  a->name = format (0, "app-evt-collector");
  a->api_client_index = ~0;
  a->session_cb_vft = &app_evtger_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = alm->segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = alm->segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = alm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = alm->fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN |
				  APP_OPTIONS_FLAGS_USE_LOCAL_SCOPE |
				  APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  if ((rv = vnet_application_attach (a)))
    {
      clib_warning ("app session evt-collector attach failed: %U",
		    format_session_error, rv);
      return rv;
    }

  alm->app_index = a->app_index;

  return 0;
}

static clib_error_t *
app_evt_collector_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  u8 *collector_uri = 0, is_enable = 0, is_add = 1;
  app_evt_main_t *alm = &app_evt_main;
  clib_error_t *error = 0;
  u32 app_index = ~0, ls_index = ~0;
  u64 tmp64 = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (alm->app_index != APP_INVALID_INDEX)
    {
      /* Default configs  */
      alm->fifo_size = 4 << 20;
      alm->segment_size = 32 << 20;
    }

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "enable"))
	is_enable = 1;
      else if (unformat (line_input, "fifo-size %U", unformat_memory_size,
			 &alm->fifo_size))
	;
      else if (unformat (line_input, "segment-size %U", unformat_memory_size,
			 &tmp64))
	alm->segment_size = tmp64;
      else if (unformat (line_input, "uri %s", &collector_uri))
	vec_add1 (collector_uri, 0);
      else if (unformat (line_input, "app %U", unformat_app_index, &app_index))
	;
      else if (unformat (line_input, "listener %u", &ls_index))
	;
      else if (unformat (line_input, "add"))
	;
      else if (unformat (line_input, "del"))
	is_add = 0;
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  if (is_enable)
    {
      if (alm->app_index != APP_INVALID_INDEX)
	{
	  error = clib_error_return (0, "app evt-collector already enabled");
	  goto done;
	}
      app_evt_collector_attach ();
    }

  if (collector_uri)
    {
      app_evt_collector_cfg_t cfg = { .is_server = 1 };

      if (alm->app_index == APP_INVALID_INDEX)
	{
	  error = clib_error_return (0, "app evt-collector not enabled");
	  goto done;
	}

      if (parse_uri ((char *) collector_uri, &cfg.sep))
	{
	  error =
	    clib_error_return (0, "Invalid collector uri [%v]", collector_uri);
	  goto done;
	}
      if (is_add && app_evt_collector_add (&cfg))
	{
	  error = clib_error_return (0, "Failed to add collector");
	  goto done;
	}
      if (!is_add && app_evt_collector_del (&cfg))
	{
	  error = clib_error_return (0, "Failed to remove collector");
	  goto done;
	}
    }

  if (app_index != ~0)
    {
      application_t *app = application_get (app_index);
      if (!app)
	{
	  error = clib_error_return (0, "Invalid app index %u", app_index);
	  goto done;
	}
      if (!is_add)
	{
	  if (ls_index != ~0)
	    {
	      hash_unset (app->evt_collector_session_filter, ls_index);
	      goto done;
	    }
	  app->evt_collector_index = APP_INVALID_INDEX;
	  app->cb_fns.app_evt_callback = 0;
	  hash_free (app->evt_collector_session_filter);
	  goto done;
	}
      app->cb_fns.app_evt_callback = app_evt_collector_get_cb_fn ();
      /* listeners are allocated on main thread, so it's enough to use index */
      if (ls_index != ~0)
	hash_set (app->evt_collector_session_filter, ls_index, 1);
    }

done:
  unformat_free (line_input);
  vec_free (collector_uri);
  return error;
}

VLIB_CLI_COMMAND (app_evt_collector_command, static) = {
  .path = "app evt-collector",
  .short_help = "app evt-collector [enable] [segment-size <nn>[k|m]] "
		"[fifo-size <nn>[k|m]] [add|del] [uri <uri>] [app <index> "
		"[listener <index>]] ",
  .function = app_evt_collector_enable_command_fn,
};

static u8 *
format_app_evt_collector (u8 *s, va_list *args)
{
  app_evt_collector_t *c = va_arg (*args, app_evt_collector_t *);
  u32 i, indent;

  s = format (s, "[%u] ", c->collector_index);
  indent = format_get_indent (s);
  s = format (s, "remote %U:%u is server %d\n", format_ip46_address,
	      &c->cfg.sep.ip, c->cfg.sep.is_ip4, c->cfg.sep.port,
	      c->cfg.is_server);
  s = format (s, "%Uis ready: %u session map: 0x%x\n", format_white_space,
	      indent, c->is_ready, c->session_map);
  s = format (s, "%Usessions:\n", format_white_space, indent);
  for (i = vlib_num_workers () ? 1 : 0; i < vec_len (c->wrk); i++)
    {
      if (c->wrk[i].session_handle != SESSION_INVALID_HANDLE)
	{
	  session_t *cs = session_get_from_handle (c->wrk[i].session_handle);
	  transport_endpoint_t tep;
	  session_get_endpoint (cs, NULL, &tep);
	  s = format (s, "%U [%u:%u] %U:%u\n", format_white_space, indent,
		      cs->thread_index, cs->session_index, format_ip46_address,
		      &tep.ip, tep.is_ip4, tep.port);
	}
      else
	s = format (s, "%U <not-connected>\n", format_white_space, indent,
		    format_session, c->wrk[i].session_handle);
    }

  return s;
}

static clib_error_t *
show_app_evt_collector_command_fn (vlib_main_t *vm, unformat_input_t *input,
				   vlib_cli_command_t *cmd)
{
  app_evt_main_t *alm = &app_evt_main;
  clib_error_t *error = 0;
  app_evt_collector_t *c;
  u8 do_listeners = 0;
  u32 app_index = ~0, val;
  application_t *app = 0;
  session_handle_t lsh;
  session_t *ls;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "app %U", unformat_app_index, &app_index))
	;
      else if (unformat (input, "listeners-filter"))
	{
	  do_listeners = 1;
	}
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, input);
	  goto done;
	}
    }

  if (alm->app_index == APP_INVALID_INDEX)
    {
      error = clib_error_return (0, "app evt-collector not enabled");
      goto done;
    }

  if (app_index != ~0)
    {
      app = application_get (app_index);
      if (!app)
	{
	  error = clib_error_return (0, "Invalid app index %u", app_index);
	  goto done;
	}
    }
  if (do_listeners)
    {
      if (!app)
	{
	  error =
	    clib_error_return (0, "app index required to show listeners");
	  goto done;
	}
      hash_foreach (lsh, val, app->evt_collector_session_filter, ({
		      ls = listen_session_get_from_handle (lsh);
		      vlib_cli_output (vm, "%U", format_session, ls);
		    }));
      goto done;
    }
  vlib_cli_output (vm, "app evt-collector app-index: %u", alm->app_index);
  vlib_cli_output (vm, " fifo size %U segment size %U", format_memory_size,
		   alm->fifo_size, format_memory_size, alm->segment_size);
  pool_foreach (c, alm->collectors)
    vlib_cli_output (vm, " %U", format_app_evt_collector, c, 0);

done:
  return error;
}

VLIB_CLI_COMMAND (show_app_evt_collector_command, static) = {
  .path = "show app evt-collector",
  .short_help = "show app evt-collector [app <app> listeners-filter]",
  .function = show_app_evt_collector_command_fn,
};
