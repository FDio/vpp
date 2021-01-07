/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <srtp/srtp.h>
#include <vnet/session/application_interface.h>
#include <vnet/session/session.h>

static srtp_main_t srtp_main;

static void srtp_disconnect (u32 ctx_handle, u32 thread_index);
static void srtp_disconnect_transport (srtp_tc_t *ctx);

static inline u32
srtp_ctx_alloc_w_thread (u32 thread_index)
{
  srtp_tc_t *ctx;
  pool_get_zero (srtp_main.ctx_pool[thread_index], ctx);
  ctx->c_thread_index = thread_index;
  ctx->srtp_ctx_handle = ctx - srtp_main.ctx_pool[thread_index];
  ctx->app_session_handle = SESSION_INVALID_HANDLE;
  return ctx->srtp_ctx_handle;
}

static inline srtp_tc_t *
srtp_ctx_get_w_thread (u32 ctx_index, u32 thread_index)
{
  return pool_elt_at_index (srtp_main.ctx_pool[thread_index], ctx_index);
}

void
srtp_ctx_free (srtp_tc_t *ctx)
{
  pool_put (srtp_main.ctx_pool[ctx->c_thread_index], ctx);
}

static inline u32
srtp_ctx_attach (u32 thread_index, void *ctx)
{
  // TODO
  return 0;
}

static inline void *
srtp_ctx_detach (srtp_tc_t *ctx)
{
  // TODO
  return 0;
}

u32
srtp_listener_ctx_alloc (void)
{
  srtp_main_t *sm = &srtp_main;
  srtp_tc_t *ctx;

  pool_get (sm->listener_ctx_pool, ctx);
  clib_memset (ctx, 0, sizeof (*ctx));
  return ctx - sm->listener_ctx_pool;
}

void
srtp_listener_ctx_free (srtp_tc_t *ctx)
{
  if (CLIB_DEBUG)
    clib_memset (ctx, 0xfb, sizeof (*ctx));
  pool_put (srtp_main.listener_ctx_pool, ctx);
}

srtp_tc_t *
srtp_listener_ctx_get (u32 ctx_index)
{
  return pool_elt_at_index (srtp_main.listener_ctx_pool, ctx_index);
}

u32
srtp_listener_ctx_index (srtp_tc_t *ctx)
{
  return (ctx - srtp_main.listener_ctx_pool);
}

static srtp_policy_t test_policy;
static unsigned char test_key[46] = {
  0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c,
  0x06, 0xde, 0x41, 0x39, 0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb,
  0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6, 0xc1, 0x73, 0xc3, 0x17, 0xf2, 0xda,
  0xbe, 0x35, 0x77, 0x93, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6
};

static int
srtp_ctx_init_client (srtp_tc_t *ctx)
{
  session_t *app_session;
  app_worker_t *app_wrk;
  session_error_t err;

  if (srtp_create (&ctx->srtp_ctx, &test_policy) != srtp_err_status_ok)
    {
      clib_warning ("failed to init srtp ctx");
      return -1;
    }

  app_wrk = app_worker_get (ctx->parent_app_wrk_index);
  app_session = session_get (ctx->c_s_index, ctx->c_thread_index);
  app_session->app_wrk_index = ctx->parent_app_wrk_index;
  app_session->connection_index = ctx->srtp_ctx_handle;
  app_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_SRTP, ctx->udp_is_ip4);

  if ((err = app_worker_init_connected (app_wrk, app_session)))
    goto failed;

  app_session->session_state = SESSION_STATE_READY;
  if (app_worker_connect_notify (app_wrk, app_session, SESSION_E_NONE,
				 ctx->parent_app_api_context))
    {
      SRTP_DBG (1, "failed to notify app");
      app_session->session_state = SESSION_STATE_CONNECTING;
      srtp_disconnect (ctx->srtp_ctx_handle, vlib_get_thread_index ());
      return -1;
    }

  ctx->app_session_handle = session_handle (app_session);

  return 0;

failed:
  /* Free app session pre-allocated when transport was established */
  session_free (session_get (ctx->c_s_index, ctx->c_thread_index));
  ctx->no_app_session = 1;
  srtp_disconnect (ctx->srtp_ctx_handle, vlib_get_thread_index ());
  return app_worker_connect_notify (app_wrk, 0, err,
				    ctx->parent_app_api_context);
}

static int
srtp_ctx_init_server (srtp_tc_t *ctx)
{
  session_t *app_listener, *app_session;
  app_worker_t *app_wrk;
  srtp_tc_t *lctx;
  int rv;

  if (srtp_create (&ctx->srtp_ctx, &test_policy) != srtp_err_status_ok)
    return -1;

  lctx = srtp_listener_ctx_get (ctx->listener_ctx_index);
  app_listener = listen_session_get_from_handle (lctx->app_session_handle);

  app_session = session_get (ctx->c_s_index, ctx->c_thread_index);
  app_session->app_wrk_index = ctx->parent_app_wrk_index;
  app_session->connection_index = ctx->srtp_ctx_handle;
  app_session->session_type = app_listener->session_type;
  app_session->listener_handle = listen_session_get_handle (app_listener);
  app_session->session_state = SESSION_STATE_ACCEPTING;

  if ((rv = app_worker_init_accepted (app_session)))
    {
      SRTP_DBG (1, "failed to allocate fifos");
      session_free (app_session);
      return rv;
    }
  ctx->app_session_handle = session_handle (app_session);
  ctx->parent_app_wrk_index = app_session->app_wrk_index;
  app_wrk = app_worker_get (app_session->app_wrk_index);
  return app_worker_accept_notify (app_wrk, app_session);
}

static int
srtp_ctx_deinit (srtp_tc_t *ctx)
{
  if (srtp_dealloc (ctx->srtp_ctx))
    SRTP_DBG (0, "%u failed to cleanup srtp state", ctx->c_c_index);
  return 0;
}

static inline int
srtp_ctx_write (srtp_tc_t *ctx, session_t *app_session,
		transport_send_params_t *sp)
{
  session_dgram_pre_hdr_t hdr;
  session_t *us;
  int rv, len;
  u32 n_wrote = 0, to_deq, dgram_sz;
  u8 buf[2000]; // FIXME
  svm_msg_q_t *mq;
  app_session_transport_t at;

  sp->max_burst_size = sp->max_burst_size * TRANSPORT_PACER_MIN_MSS;

  us = session_get_from_handle (ctx->srtp_session_handle);
  to_deq = svm_fifo_max_dequeue_cons (app_session->tx_fifo);
  mq = session_main_get_vpp_event_queue (us->thread_index);

  while (to_deq > 0)
    {
      /* Peeking only pre-header dgram because the session is connected */
      rv = svm_fifo_peek (app_session->tx_fifo, 0, sizeof (hdr), (u8 *) &hdr);
      ASSERT (rv == sizeof (hdr) && hdr.data_length < vec_len (buf));
      ASSERT (to_deq >= hdr.data_length + SESSION_CONN_HDR_LEN);

      dgram_sz = hdr.data_length + SESSION_CONN_HDR_LEN;
      if (svm_fifo_max_enqueue_prod (us->tx_fifo) < dgram_sz + 1000)
	{
	  svm_fifo_add_want_deq_ntf (us->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
	  transport_connection_deschedule (&ctx->connection);
	  sp->flags |= TRANSPORT_SND_F_DESCHED;
	  goto done;
	}

      rv = svm_fifo_peek (app_session->tx_fifo, SESSION_CONN_HDR_LEN,
			  hdr.data_length, buf);
      ASSERT (rv == hdr.data_length);
      svm_fifo_dequeue_drop (app_session->tx_fifo, dgram_sz);

      len = rv;

      rv = srtp_protect (ctx->srtp_ctx, buf, &len);
      if (rv != srtp_err_status_ok)
	{
	  clib_warning ("failed to protect");
	  ASSERT (0);
	}

      rv = app_send_dgram_raw (us->tx_fifo, &at, mq, (u8 *) buf, len,
			       SESSION_IO_EVT_TX, 1 /* do_evt */,
			       0 /* noblock */);
      ASSERT (rv == len);

      n_wrote += rv;
      to_deq -= dgram_sz;
    }

done:

  if (svm_fifo_needs_deq_ntf (app_session->tx_fifo, n_wrote))
    session_dequeue_notify (app_session);

  if (n_wrote)
    {
      if (svm_fifo_set_event (us->tx_fifo))
	session_send_io_evt_to_thread (us->tx_fifo, SESSION_IO_EVT_TX);
    }

  if (PREDICT_FALSE (ctx->app_closed &&
		     !svm_fifo_max_enqueue_prod (us->rx_fifo)))
    {
      srtp_disconnect_transport (ctx);
      session_transport_closed_notify (&ctx->connection);
    }

  return n_wrote > 0 ? clib_max (n_wrote / TRANSPORT_PACER_MIN_MSS, 1) : 0;
}

int
srtp_add_vpp_q_builtin_rx_evt (session_t *s)
{
  if (svm_fifo_set_event (s->rx_fifo))
    session_send_io_evt_to_thread (s->rx_fifo, SESSION_IO_EVT_BUILTIN_RX);
  return 0;
}

void
srtp_notify_app_enqueue (srtp_tc_t *ctx, session_t *app_session)
{
  app_worker_t *app_wrk;
  app_wrk = app_worker_get_if_valid (app_session->app_wrk_index);
  if (PREDICT_TRUE (app_wrk != 0))
    app_worker_lock_and_send_event (app_wrk, app_session, SESSION_IO_EVT_RX);
}

static inline int
srtp_ctx_read (srtp_tc_t *ctx, session_t *us)
{
  app_session_transport_t at;
  session_dgram_hdr_t hdr;
  session_t *app_session;
  u32 n_read = 0;
  u8 buf[2000]; // FIXME
  int rv, len;

  app_session = session_get_from_handle (ctx->app_session_handle);
  svm_fifo_fill_chunk_list (app_session->rx_fifo);

  while (svm_fifo_max_dequeue_cons (us->rx_fifo) > 0)
    {
      if (svm_fifo_max_enqueue_prod (app_session->rx_fifo) < 2000)
	{
	  srtp_add_vpp_q_builtin_rx_evt (us);
	  goto done;
	}

      rv = app_recv_dgram_raw (us->rx_fifo, (u8 *) buf, 2000, &at,
			       0 /* clear evt */, 0 /* peek */);
      ASSERT (rv > 0);
      len = rv;

      rv = srtp_unprotect (ctx->srtp_ctx, buf, &len);

      if (rv != srtp_err_status_ok)
	{
	  clib_warning ("failed to unprotect");
	  ASSERT (0);
	}
      n_read += len;

      hdr.data_length = len;
      hdr.data_offset = 0;

      svm_fifo_seg_t segs[2] = { { (u8 *) &hdr, sizeof (hdr) }, { buf, len } };

      rv = svm_fifo_enqueue_segments (app_session->rx_fifo, segs, 2,
				      0 /* allow partial */);
      ASSERT (rv > 0);
    }

done:

  srtp_notify_app_enqueue (ctx, app_session);

  return n_read;
}

int
srtp_add_segment_callback (u32 client_index, u64 segment_handle)
{
  /* No-op for builtin */
  return 0;
}

int
srtp_del_segment_callback (u32 client_index, u64 segment_handle)
{
  return 0;
}

void
srtp_session_disconnect_callback (session_t *us)
{
  clib_warning ("udp %u disconnected?", us->session_index);
}

void
srtp_session_reset_callback (session_t *us)
{
  clib_warning ("udp %u reset?", us->session_index);
}

static int
srtp_session_connected_callback (u32 srtp_app_index, u32 ctx_handle,
				 session_t *us, session_error_t err)
{
  session_t *app_session;
  session_type_t st;
  srtp_tc_t *ctx;

  ctx = srtp_ctx_get_w_thread (ctx_handle, 1 /* udp allocs on thread 1 */);

  ctx->srtp_session_handle = session_handle (us);
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  us->opaque = ctx_handle;

  /* Preallocate app session. Avoids allocating a session on srtp_session rx
   * and potentially invalidating the session pool */
  app_session = session_alloc (ctx->c_thread_index);
  app_session->session_state = SESSION_STATE_CREATED;
  ctx->c_s_index = app_session->session_index;

  st = session_type_from_proto_and_ip (TRANSPORT_PROTO_SRTP, ctx->udp_is_ip4);
  app_session->session_type = st;
  app_session->connection_index = ctx->srtp_ctx_handle;

  return srtp_ctx_init_client (ctx);
}

int
srtp_session_accept_callback (session_t *us)
{
  session_t *srtp_listener, *app_session;
  srtp_tc_t *lctx, *ctx;
  u32 ctx_handle;

  srtp_listener = listen_session_get_from_handle (us->listener_handle);
  lctx = srtp_listener_ctx_get (srtp_listener->opaque);

  ctx_handle = srtp_ctx_alloc_w_thread (us->thread_index);
  ctx = srtp_ctx_get_w_thread (ctx_handle, us->thread_index);
  clib_memcpy_fast (ctx, lctx, sizeof (*lctx));
  ctx->c_thread_index = vlib_get_thread_index ();
  ctx->srtp_ctx_handle = ctx_handle;
  us->session_state = SESSION_STATE_READY;
  us->opaque = ctx_handle;
  ctx->srtp_session_handle = session_handle (us);
  ctx->listener_ctx_index = srtp_listener->opaque;
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  app_session = session_alloc (ctx->c_thread_index);
  app_session->session_state = SESSION_STATE_CREATED;
  ctx->c_s_index = app_session->session_index;

  SRTP_DBG (1, "Accept on listener %u new connection [%u]%x",
	    srtp_listener->opaque, vlib_get_thread_index (), ctx_handle);

  return srtp_ctx_init_server (ctx);
}

int
srtp_app_rx_callback (session_t *us)
{
  srtp_tc_t *ctx;

  ctx = srtp_ctx_get_w_thread (us->opaque, us->thread_index);
  srtp_ctx_read (ctx, us);
  return 0;
}

int
srtp_app_tx_callback (session_t *us)
{
  srtp_tc_t *ctx;

  ctx = srtp_ctx_get_w_thread (us->opaque, us->thread_index);
  transport_connection_reschedule (&ctx->connection);

  return 0;
}

static void
srtp_app_session_cleanup (session_t *s, session_cleanup_ntf_t ntf)
{
  srtp_tc_t *ctx;

  if (ntf == SESSION_CLEANUP_TRANSPORT)
    {
      /* Allow cleanup of tcp session */
      if (s->session_state == SESSION_STATE_TRANSPORT_DELETED)
	session_close (s);
      return;
    }

  ctx = srtp_ctx_get_w_thread (s->opaque, s->thread_index);
  if (!ctx->no_app_session)
    session_transport_delete_notify (&ctx->connection);
  srtp_ctx_deinit (ctx);
  srtp_ctx_free (ctx);
}

static void
srtp_migrate_udp (void *arg)
{
  srtp_tc_t *ctx = (srtp_tc_t *) arg;
  u32 ctx_handle, thread_index;
  session_t *us;

  thread_index = session_thread_from_handle (ctx->srtp_session_handle);
  ASSERT (thread_index == vlib_get_thread_index ());

  ctx_handle = srtp_ctx_attach (thread_index, ctx);
  ctx = srtp_ctx_get_w_thread (ctx_handle, thread_index);
  clib_warning ("migrate handle %u", ctx_handle);
  ctx->srtp_ctx_handle = ctx_handle;

  us = session_get_from_handle (ctx->srtp_session_handle);
  us->opaque = ctx_handle;
  us->flags &= ~SESSION_F_IS_MIGRATING;
  if (svm_fifo_max_dequeue (us->tx_fifo))
    session_send_io_evt_to_thread (us->tx_fifo, SESSION_IO_EVT_TX);

  // TODO migrate app session
}

static void
srtp_session_migrate_callback (session_t *us, session_handle_t new_sh)
{
  u32 new_thread = session_thread_from_handle (new_sh);
  srtp_tc_t *ctx;

  clib_warning ("session about to migrate");
  ctx = srtp_ctx_get_w_thread (us->opaque, us->thread_index);
  ctx->srtp_session_handle = new_sh;
  ctx = srtp_ctx_detach (ctx);

  session_send_rpc_evt_to_thread (new_thread, srtp_migrate_udp, (void *) ctx);

  // TODO migrate app session
}

static session_cb_vft_t srtp_app_cb_vft = {
  .session_accept_callback = srtp_session_accept_callback,
  .session_disconnect_callback = srtp_session_disconnect_callback,
  .session_connected_callback = srtp_session_connected_callback,
  .session_reset_callback = srtp_session_reset_callback,
  .add_segment_callback = srtp_add_segment_callback,
  .del_segment_callback = srtp_del_segment_callback,
  .builtin_app_rx_callback = srtp_app_rx_callback,
  .builtin_app_tx_callback = srtp_app_tx_callback,
  .session_migrate_callback = srtp_session_migrate_callback,
  .session_cleanup_callback = srtp_app_session_cleanup,
};

static clib_error_t *
srtp_enable (vlib_main_t *vm, u8 is_en)
{
  u32 add_segment_size = 256 << 20, first_seg_size = 32 << 20;
  vnet_app_detach_args_t _da, *da = &_da;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  srtp_main_t *sm = &srtp_main;
  u32 fifo_size = 128 << 12;

  if (!is_en)
    {
      da->app_index = sm->app_index;
      da->api_client_index = APP_INVALID_INDEX;
      vnet_application_detach (da);
      return 0;
    }

  srtp_init ();
  vec_validate (sm->ctx_pool, vlib_num_workers ());

  first_seg_size = sm->first_seg_size ? sm->first_seg_size : first_seg_size;
  fifo_size = sm->fifo_size ? sm->fifo_size : fifo_size;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &srtp_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "srtp");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = first_seg_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = add_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach srtp app");
      return clib_error_return (0, "failed to attach srtp app");
    }

  sm->app_index = a->app_index;
  vec_free (a->name);

  memset (&test_policy, 0, sizeof (test_policy));
  srtp_crypto_policy_set_rtp_default (&test_policy.rtp);
  srtp_crypto_policy_set_rtcp_default (&test_policy.rtcp);
  test_policy.ssrc.type = ssrc_specific;
  test_policy.ssrc.value = 0xcafebabe;
  test_policy.key = test_key;
  test_policy.ekt = NULL;
  test_policy.window_size = 128;
  test_policy.allow_repeat_tx = 0;
  test_policy.next = NULL;

  return 0;
}

int
srtp_connect (transport_endpoint_cfg_t *tep)
{
  vnet_connect_args_t _cargs = { {}, }, *cargs = &_cargs;
  session_endpoint_cfg_t *sep;
  srtp_main_t *sm = &srtp_main;
  app_worker_t *app_wrk;
  application_t *app;
  srtp_tc_t *ctx;
  u32 ctx_index;
  int rv;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);

  ctx_index = srtp_ctx_alloc_w_thread (1 /* because of udp */);
  ctx = srtp_ctx_get_w_thread (ctx_index, 1);
  ctx->parent_app_wrk_index = sep->app_wrk_index;
  ctx->parent_app_api_context = sep->opaque;
  ctx->udp_is_ip4 = sep->is_ip4;
  ctx->srtp_ctx_handle = ctx_index;

  app_worker_alloc_connects_segment_manager (app_wrk);

  clib_memcpy_fast (&cargs->sep, sep, sizeof (session_endpoint_t));
  cargs->sep.transport_proto = TRANSPORT_PROTO_UDP;
  cargs->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  cargs->app_index = sm->app_index;
  cargs->api_context = ctx_index;
  cargs->sep_ext.ns_index = app->ns_index;
  if ((rv = vnet_connect (cargs)))
    return rv;

  SRTP_DBG (1, "New connect request %u", ctx_index);
  return 0;
}

static void
srtp_disconnect_transport (srtp_tc_t *ctx)
{
  vnet_disconnect_args_t a = {
    .handle = ctx->srtp_session_handle,
    .app_index = srtp_main.app_index,
  };

  if (vnet_disconnect_session (&a))
    clib_warning ("disconnect returned");
}

static void
srtp_disconnect (u32 ctx_handle, u32 thread_index)
{
  session_t *app_session;
  srtp_tc_t *ctx;

  SRTP_DBG (1, "App disconnecting %x", ctx_handle);

  ctx = srtp_ctx_get_w_thread (ctx_handle, thread_index);

  app_session = session_get_from_handle (ctx->app_session_handle);
  if (!svm_fifo_max_dequeue_cons (app_session->tx_fifo))
    {
      /* Confirm close */
      srtp_disconnect_transport (ctx);
      session_transport_closed_notify (&ctx->connection);
    }
  else
    {
      /* Wait for all data to be written to udp */
      ctx->app_closed = 1;
    }
}

static u32
srtp_start_listen (u32 app_listener_index, transport_endpoint_t *tep)
{
  vnet_listen_args_t _bargs, *args = &_bargs;
  session_handle_t udp_al_handle;
  srtp_main_t *sm = &srtp_main;
  session_endpoint_cfg_t *sep;
  session_t *srtp_listener;
  session_t *app_listener;
  app_worker_t *app_wrk;
  application_t *app;
  app_listener_t *al;
  srtp_tc_t *lctx;
  u32 lctx_index;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);

  clib_memset (args, 0, sizeof (*args));
  args->app_index = sm->app_index;
  args->sep_ext = *sep;
  args->sep_ext.ns_index = app->ns_index;
  args->sep_ext.transport_proto = TRANSPORT_PROTO_UDP;
  args->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  if (vnet_listen (args))
    return -1;

  lctx_index = srtp_listener_ctx_alloc ();
  udp_al_handle = args->handle;
  al = app_listener_get_w_handle (udp_al_handle);
  srtp_listener = app_listener_get_session (al);
  srtp_listener->opaque = lctx_index;

  app_listener = listen_session_get (app_listener_index);

  lctx = srtp_listener_ctx_get (lctx_index);
  lctx->parent_app_wrk_index = sep->app_wrk_index;
  lctx->srtp_session_handle = udp_al_handle;
  lctx->app_session_handle = listen_session_get_handle (app_listener);
  lctx->udp_is_ip4 = sep->is_ip4;

  //  if (srtp_ctx_init_server (lctx))
  //    {
  //      vnet_unlisten_args_t a = { .handle = lctx->srtp_session_handle,
  //				 .app_index = srtp_main.app_index,
  //				 .wrk_map_index = 0 };
  //      if ((vnet_unlisten (&a)))
  //	clib_warning ("unlisten returned");
  //      srtp_listener_ctx_free (lctx);
  //      lctx_index = SESSION_INVALID_INDEX;
  //    }

  SRTP_DBG (1, "Started listening %d", lctx_index);
  return lctx_index;
}

u32
srtp_stop_listen (u32 lctx_index)
{
  session_endpoint_t sep = SESSION_ENDPOINT_NULL;
  transport_connection_t *lc;
  srtp_tc_t *lctx;
  session_t *ls;
  int rv;

  lctx = srtp_listener_ctx_get (lctx_index);

  /* Cleanup listener from session lookup table */
  ls = session_get_from_handle (lctx->srtp_session_handle);
  lc = session_get_transport (ls);

  sep.fib_index = lc->fib_index;
  sep.port = lc->lcl_port;
  sep.is_ip4 = lc->is_ip4;
  sep.transport_proto = TRANSPORT_PROTO_TLS;
  clib_memcpy (&sep.ip, &lc->lcl_ip, sizeof (lc->lcl_ip));
  session_lookup_del_session_endpoint2 (&sep);

  vnet_unlisten_args_t a = {
    .handle = lctx->srtp_session_handle,
    .app_index = srtp_main.app_index,
    .wrk_map_index = 0 /* default wrk */
  };
  if ((rv = vnet_unlisten (&a)))
    clib_warning ("unlisten returned %d", rv);

  srtp_listener_ctx_free (lctx);
  return 0;
}

transport_connection_t *
srtp_connection_get (u32 ctx_index, u32 thread_index)
{
  srtp_tc_t *ctx;
  ctx = srtp_ctx_get_w_thread (ctx_index, thread_index);
  return &ctx->connection;
}

transport_connection_t *
srtp_listener_get (u32 listener_index)
{
  srtp_tc_t *ctx;
  ctx = srtp_listener_ctx_get (listener_index);
  return &ctx->connection;
}

int
srtp_custom_tx_callback (void *session, transport_send_params_t *sp)
{
  session_t *app_session = (session_t *) session;
  srtp_tc_t *ctx;

  if (PREDICT_FALSE (app_session->session_state >=
		     SESSION_STATE_TRANSPORT_CLOSED))
    return 0;

  sp->flags = 0;
  ctx = srtp_ctx_get_w_thread (app_session->connection_index,
			       app_session->thread_index);
  return srtp_ctx_write (ctx, app_session, sp);
}

u8 *
format_srtp_ctx (u8 *s, va_list *args)
{
  srtp_tc_t *ctx = va_arg (*args, srtp_tc_t *);
  u32 udp_si, udp_ti;

  session_parse_handle (ctx->srtp_session_handle, &udp_si, &udp_ti);
  s = format (s, "[%d:%d][SRTP] app_wrk %u index %u udp %d:%d",
	      ctx->c_thread_index, ctx->c_s_index, ctx->parent_app_wrk_index,
	      ctx->srtp_ctx_handle, udp_ti, udp_si);

  return s;
}

static u8 *
format_srtp_listener_ctx (u8 *s, va_list *args)
{
  session_t *udp_listener;
  app_listener_t *al;
  srtp_tc_t *ctx;

  ctx = va_arg (*args, srtp_tc_t *);

  al = app_listener_get_w_handle (ctx->srtp_session_handle);
  udp_listener = app_listener_get_session (al);
  s = format (s, "[%d:%d][SRTP] app_wrk %u udp %d:%d", ctx->c_thread_index,
	      ctx->c_s_index, ctx->parent_app_wrk_index,
	      udp_listener->thread_index, udp_listener->session_index);

  return s;
}

static u8 *
format_srtp_ctx_state (u8 *s, va_list *args)
{
  srtp_tc_t *ctx;
  session_t *us;

  ctx = va_arg (*args, srtp_tc_t *);
  us = session_get (ctx->c_s_index, ctx->c_thread_index);
  if (us->session_state == SESSION_STATE_LISTENING)
    s = format (s, "%s", "LISTEN");
  else
    {
      if (us->session_state >= SESSION_STATE_TRANSPORT_CLOSED)
	s = format (s, "%s", "CLOSED");
      else if (us->session_state == SESSION_STATE_APP_CLOSED)
	s = format (s, "%s", "APP-CLOSED");
      else if (us->session_state >= SESSION_STATE_TRANSPORT_CLOSING)
	s = format (s, "%s", "CLOSING");
      else
	s = format (s, "%s", "ESTABLISHED");
    }

  return s;
}

u8 *
format_srtp_connection (u8 *s, va_list *args)
{
  u32 ctx_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  srtp_tc_t *ctx;

  ctx = srtp_ctx_get_w_thread (ctx_index, thread_index);
  if (!ctx)
    return s;

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_srtp_ctx, ctx);
  if (verbose)
    {
      s =
	format (s, "%-" SESSION_CLI_STATE_LEN "U", format_srtp_ctx_state, ctx);
      if (verbose > 1)
	s = format (s, "\n");
    }
  return s;
}

u8 *
format_srtp_listener (u8 *s, va_list *args)
{
  u32 tc_index = va_arg (*args, u32);
  u32 __clib_unused thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  srtp_tc_t *ctx = srtp_listener_ctx_get (tc_index);

  s = format (s, "%-" SESSION_CLI_ID_LEN "U", format_srtp_listener_ctx, ctx);
  if (verbose)
    s = format (s, "%-" SESSION_CLI_STATE_LEN "U", format_srtp_ctx_state, ctx);
  return s;
}

u8 *
format_srtp_half_open (u8 *s, va_list *args)
{
  return 0;
}

static void
srtp_transport_endpoint_get (u32 ctx_handle, u32 thread_index,
			     transport_endpoint_t *tep, u8 is_lcl)
{
  srtp_tc_t *ctx = srtp_ctx_get_w_thread (ctx_handle, thread_index);
  session_t *udp_session;

  udp_session = session_get_from_handle (ctx->srtp_session_handle);
  session_get_endpoint (udp_session, tep, is_lcl);
}

static void
srtp_transport_listener_endpoint_get (u32 ctx_handle,
				      transport_endpoint_t *tep, u8 is_lcl)
{
  session_t *srtp_listener;
  app_listener_t *al;
  srtp_tc_t *ctx = srtp_listener_ctx_get (ctx_handle);

  al = app_listener_get_w_handle (ctx->srtp_session_handle);
  srtp_listener = app_listener_get_session (al);
  session_get_endpoint (srtp_listener, tep, is_lcl);
}

static const transport_proto_vft_t srtp_proto = {
  .enable = srtp_enable,
  .connect = srtp_connect,
  .close = srtp_disconnect,
  .start_listen = srtp_start_listen,
  .stop_listen = srtp_stop_listen,
  .get_connection = srtp_connection_get,
  .get_listener = srtp_listener_get,
  .custom_tx = srtp_custom_tx_callback,
  .format_connection = format_srtp_connection,
  .format_half_open = format_srtp_half_open,
  .format_listener = format_srtp_listener,
  .get_transport_endpoint = srtp_transport_endpoint_get,
  .get_transport_listener_endpoint = srtp_transport_listener_endpoint_get,
  .transport_options = {
    .name = "srtp",
    .short_name = "R",
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};

static clib_error_t *
srtp_transport_init (vlib_main_t *vm)
{
  transport_register_protocol (TRANSPORT_PROTO_SRTP, &srtp_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_SRTP, &srtp_proto,
			       FIB_PROTOCOL_IP6, ~0);
  return 0;
}

VLIB_INIT_FUNCTION (srtp_transport_init);

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Secure Real-time Transport Protocol (SRTP)",
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
