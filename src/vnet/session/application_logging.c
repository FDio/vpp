/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2025 Cisco Systems, Inc.
 */

#include <vnet/session/application_logging.h>
#include <vnet/session/session.h>

app_log_main_t app_log_main = { .app_index = APP_INVALID_INDEX };

static app_log_buffer_chunk_t *
app_log_buffer_chunk_alloc (app_log_buffer_t *buf)
{
  app_log_buffer_chunk_t *chunk;

  pool_get_zero (buf->chunks, chunk);
  chunk->chunk_index = chunk - buf->chunks;
  chunk->next_index = ~0;

  return chunk;
}

static app_log_buffer_chunk_t *
app_log_buffer_chunk_get (app_log_buffer_t *buf, u32 chunk_index)
{
  if (pool_is_free_index (buf->chunks, chunk_index))
    return 0;
  return pool_elt_at_index (buf->chunks, chunk_index);
}

static void
app_log_buffer_chunk_free (app_log_buffer_t *buf,
			   app_log_buffer_chunk_t *chunk)
{
  pool_put (buf->chunks, chunk);
}

static void
app_log_buffer_append_chunk (app_log_buffer_t *buf,
			     app_log_buffer_chunk_t *chunk)
{
  app_log_buffer_chunk_t *tail;
  buf->len += chunk->len;

  if (buf->tail_chunk == ~0)
    {
      buf->head_chunk = chunk->chunk_index;
      buf->tail_chunk = chunk->chunk_index;
      return;
    }
  tail = app_log_buffer_chunk_get (buf, buf->tail_chunk);
  tail->next_index = chunk->chunk_index;
  buf->tail_chunk = chunk->chunk_index;
}

static void
app_log_collector_send (app_log_collector_wrk_t *cwrk)
{
  u32 max_enq, to_send = 0, next_c;
  app_log_buffer_chunk_t *c;
  svm_fifo_seg_t *seg;
  session_t *cs;
  int wrote;

  cs = session_get_from_handle (cwrk->session_handle);
  max_enq = svm_fifo_max_enqueue_prod (cs->tx_fifo);

  if (!max_enq)
    {
      svm_fifo_add_want_deq_ntf (cs->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      return;
    }

  c = app_log_buffer_chunk_get (&cwrk->buf, cwrk->buf.head_chunk);
  while (c)
    {
      if (c->len + to_send > max_enq)
	break;

      to_send += c->len;
      vec_add2 (cwrk->segs, seg, 1);
      seg->data = c->data;
      seg->len = c->len;

      c = app_log_buffer_chunk_get (&cwrk->buf, c->next_index);
    }

  wrote = svm_fifo_enqueue_segments (
    cs->tx_fifo, cwrk->segs, vec_len (cwrk->segs), 0 /* allow partial*/);

  cwrk->buf.len -= wrote > 0 ? wrote : 0;

  next_c = cwrk->buf.head_chunk;
  while (wrote > 0)
    {
      c = app_log_buffer_chunk_get (&cwrk->buf, next_c);
      next_c = c->next_index;
      ASSERT (wrote >= c->len);
      wrote -= c->len;
      app_log_buffer_chunk_free (&cwrk->buf, c);
    }
  ASSERT (wrote == 0);
  cwrk->buf.head_chunk = next_c;
  if (cwrk->buf.head_chunk == ~0)
    cwrk->buf.tail_chunk = ~0;

  if (svm_fifo_set_event (cs->tx_fifo))
    session_program_tx_io_evt (cs->handle, SESSION_IO_EVT_TX);

  vec_reset_length (cwrk->segs);
  if (cwrk->buf.len)
    svm_fifo_add_want_deq_ntf (cs->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);

  return;
}

static void
app_log_collect (app_log_collector_t *c, session_t *s)
{
  app_log_collector_wrk_t *cwrk;
  app_log_buffer_chunk_t *chunk;

  cwrk = &c->wrk[s->thread_index];
  chunk = app_log_buffer_chunk_alloc (&cwrk->buf);
  // fill chunk
  char *msg = "Hello, world!";
  clib_memcpy (chunk->data, msg, strlen (msg));
  chunk->len = strlen (msg);
  app_log_buffer_append_chunk (&cwrk->buf, chunk);
  app_log_collector_send (cwrk);
}

app_log_collector_t *
app_log_collector_get (u32 slc_index)
{
  app_log_main_t *alm = &app_log_main;
  if (pool_is_free_index (alm->collectors, slc_index))
    return 0;
  return pool_elt_at_index (alm->collectors, slc_index);
}

static void
app_log_session_cleanup (session_t *s)
{
  app_log_collector_t *c;
  app_worker_t *app_wrk;
  application_t *app;

  app_wrk = app_worker_get (s->app_wrk_index);
  app = application_get (app_wrk->app_index);
  c = app_log_collector_get (app->log_collector_index);
  app_log_collect (c, s);
}

void *
app_log_collector_get_cb_fn (void)
{
  app_log_main_t *alm = &app_log_main;

  if (alm->app_index == APP_INVALID_INDEX)
    return 0;

  return app_log_session_cleanup;
}

static void
alc_more_connects_cb_fn (void *arg)
{
  app_log_main_t *alm = &app_log_main;
  vnet_connect_args_t _a = {}, *a = &_a;
  u32 c_index = pointer_to_uword (arg);
  app_log_collector_t *c;
  int rv;

  c = app_log_collector_get (c_index);
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
app_log_collector_program_connect (u32 c_index)
{
  u32 connects_thread = transport_cl_thread ();

  session_send_rpc_evt_to_thread_force (connects_thread,
					alc_more_connects_cb_fn,
					uword_to_pointer (c_index, void *));
}

static int
app_log_collector_connected_callback (u32 app_index, u32 api_context,
				      session_t *s, session_error_t err)
{
  app_log_main_t *alm = &app_log_main;
  app_log_collector_wrk_t *cwrk;
  u32 session_map, num_workers;
  app_log_collector_t *c;

  c = app_log_collector_get (api_context);
  if (!c)
    {
      clib_warning ("app_log_collector_connected_callback: "
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

  cwrk = &c->wrk[s->thread_index];
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
    app_log_collector_program_connect (c->collector_index);

  return 0;
}

static int
app_log_collector_accept_callback (session_t *s)
{
  clib_warning ("not implemented");
  return -1;
}

static void
app_log_collector_disconnect_callback (session_t *s)
{
  /* Clean up session-specific state here */
}

static void
app_log_collector_reset_callback (session_t *s)
{
  app_log_collector_disconnect_callback (s);
}

static int
app_log_collector_rx_callback (session_t *s)
{
  /* TODO */
  return 0;
}

static int
app_log_collector_tx_callback (session_t *s)
{
  app_worker_t *app_wrk = app_worker_get (s->app_wrk_index);
  application_t *app = application_get (app_wrk->app_index);
  app_log_collector_t *c = app_log_collector_get (app->log_collector_index);
  app_log_collector_wrk_t *cwrk = &c->wrk[s->thread_index];

  /* If we have data buffered, try to send it now */
  if (cwrk->buf.len)
    app_log_collector_send (cwrk);

  return 0;
}

static session_cb_vft_t app_logger_cb_vft = {
  .session_accept_callback = app_log_collector_accept_callback,
  .session_connected_callback = app_log_collector_connected_callback,
  .session_disconnect_callback = app_log_collector_disconnect_callback,
  .session_reset_callback = app_log_collector_reset_callback,
  .builtin_app_rx_callback = app_log_collector_rx_callback,
  .builtin_app_tx_callback = app_log_collector_tx_callback,
};

static int
app_log_collector_connect (app_log_collector_t *c)
{
  app_log_main_t *alm = &app_log_main;
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
app_log_collector_add (app_log_collector_cfg_t *cfg)
{
  app_log_main_t *alm = &app_log_main;
  app_log_collector_t *c;

  pool_get_zero (alm->collectors, c);
  c->cfg = *cfg;

  vec_validate (c->wrk, vlib_num_workers ());
  for (int i = 0; i < vec_len (c->wrk); i++)
    {
      c->wrk[i].session_handle = SESSION_INVALID_HANDLE;
      c->wrk[i].buf.head_chunk = ~0;
      c->wrk[i].buf.tail_chunk = ~0;
    }

  return app_log_collector_connect (c);
}

static int
app_log_collector_attach (void)
{
  app_log_main_t *alm = &app_log_main;
  vnet_app_attach_args_t _a = {}, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  int rv;

  clib_memset (options, 0, sizeof (options));

  a->name = format (0, "app-log-collector");
  a->api_client_index = ~0;
  a->session_cb_vft = &app_logger_cb_vft;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = alm->segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = alm->segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = alm->fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = alm->fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;

  if ((rv = vnet_application_attach (a)))
    {
      clib_warning ("app session log-collector attach failed: %U",
		    format_session_error, rv);
      return rv;
    }

  alm->app_index = a->app_index;

  return 0;
}

static clib_error_t *
app_log_collector_enable_command_fn (vlib_main_t *vm, unformat_input_t *input,
				     vlib_cli_command_t *cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  app_log_main_t *alm = &app_log_main;
  clib_error_t *error = 0;
  u8 *collector_uri = 0;
  u64 tmp64 = 0;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  if (alm->app_index != APP_INVALID_INDEX)
    {
      error = clib_error_return (0, "app log collector already enabled");
      goto done;
    }

  /* Default configs  */
  alm->fifo_size = 4 << 20;
  alm->segment_size = 32 << 20;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "fifo-size %U", unformat_memory_size,
		    &alm->fifo_size))
	;
      else if (unformat (line_input, "segment-size %U", unformat_memory_size,
			 &tmp64))
	alm->segment_size = tmp64;
      else if (unformat (line_input, "uri %s", &collector_uri))
	vec_add1 (collector_uri, 0);
      else
	{
	  error = clib_error_return (0, "unknown input `%U'",
				     format_unformat_error, line_input);
	  goto done;
	}
    }

  app_log_collector_attach ();

  if (collector_uri)
    {
      app_log_collector_cfg_t cfg = { .is_server = 1 };

      if (parse_uri ((char *) collector_uri, &cfg.sep))
	{
	  error =
	    clib_error_return (0, "Invalid collector uri [%v]", collector_uri);
	  goto done;
	}
      if (app_log_collector_add (&cfg))
	{
	  error = clib_error_return (0, "Failed to add collector");
	  goto done;
	}
    }

done:
  unformat_free (line_input);
  return error;
}

VLIB_CLI_COMMAND (app_log_collector_command, static) = {
  .path = "app log-collector enable",
  .short_help = "app log-collector enable [segment-size <nn>[k|m]] "
		"[fifo-size <nn>[k|m]] uri <uri>",
  .function = app_log_collector_enable_command_fn,
};
