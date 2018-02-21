/*
 * Copyright (c) 2018 Cisco and/or its affiliates.
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

#include <vnet/session-apps/tls.h>
#include <vnet/session/application_interface.h>
#include <mbedtls/ssl.h>
#include <mbedtls/certs.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/timing.h>
#include <mbedtls/debug.h>

#define MBEDTLS_DEBUG_LEVEL_CLIENT 1
#define MBEDTLS_DEBUG_LEVEL_SERVER 1

typedef struct tls_ctx_
{
  transport_connection_t connection;
  u32 parent_app_index;
  u32 parent_app_api_context;
  session_handle_t app_session_handle;
  session_handle_t tls_session_handle;
  u8 is_ip4;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
  u8 mbedtls_timer_counter;
} tls_ctx_t;

typedef struct tls_main_
{
  u32 app_index;
  tls_ctx_t *ctx_pool;
  mbedtls_x509_crt cacert;
} tls_main_t;

static tls_main_t tls_main;

static inline int
tls_add_vpp_queue_event (svm_fifo_t *f, u8 evt_type)
{
  session_fifo_event_t evt;
  svm_queue_t *q;

  if (svm_fifo_set_event (f))
    {
      evt.fifo = f;
      evt.event_type = evt_type;

      q = session_manager_get_vpp_event_queue (f->master_thread_index);
      if (PREDICT_TRUE (q->cursize < q->maxsize))
	{
	  svm_queue_add (q, (u8 *) &evt, 0 /* do wait for mutex */);
	}
      else
	{
	  clib_warning ("vpp's evt q full");
	  return -1;
	}
    }
  return 0;
}

static inline int
tls_add_app_queue_event (application_t *app, svm_fifo_t *f, u8 evt_type)
{
  session_fifo_event_t evt;
  svm_queue_t *q;

  if (svm_fifo_set_event (f))
    {
      evt.fifo = f;
      evt.event_type = FIFO_EVENT_APP_RX;
      q = app->event_queue;

      if (PREDICT_TRUE (q->cursize < q->maxsize))
	{
	  svm_queue_add (q, (u8 *) &evt, 0 /* do wait for mutex */);
	}
      else
	{
	  clib_warning ("app evt q full");
	  return -1;
	}
    }
  return 0;
}

u32
tls_ctx_alloc (void)
{
  tls_main_t *tm = &tls_main;
  tls_ctx_t *ctx;

  pool_get (tm->ctx_pool, ctx);
  memset (ctx, 0, sizeof (*ctx));
  return ctx - tm->ctx_pool;
}

tls_ctx_t *
tls_ctx_get (u32 ctx_index)
{
  return pool_elt_at_index (tls_main.ctx_pool, ctx_index);
}

u32
tls_ctx_index (tls_ctx_t *ctx)
{
  return (ctx - tls_main.ctx_pool);
}

u32
tls_listener_ctx_alloc (void)
{
  tls_main_t *tm = &tls_main;
  tls_ctx_t *ctx;

  pool_get (tm->ctx_pool, ctx);
  memset (ctx, 0, sizeof (*ctx));
  return ctx - tm->ctx_pool;
}

tls_ctx_t *
tls_listener_ctx_get (u32 ctx_index)
{
  return pool_elt_at_index (tls_main.ctx_pool, ctx_index);
}

u32
tls_listener_ctx_index (tls_ctx_t *ctx)
{
  return (ctx - tls_main.ctx_pool);
}

static int
tls_net_send (void *ctx_indexp, const unsigned char *buf, size_t len)
{
  stream_session_t *tls_session;
  uword ctx_index;
  tls_ctx_t *ctx;
  int rv;

  ctx_index = pointer_to_uword (ctx_indexp);
  ctx = tls_ctx_get (ctx_index);
  tls_session = session_get_from_handle (ctx->tls_session_handle);
  rv = svm_fifo_enqueue_nowait (tls_session->server_tx_fifo, len, buf);
  tls_add_vpp_queue_event (tls_session->server_tx_fifo, FIFO_EVENT_APP_TX);
  return rv;
}

static int
tls_net_recv (void *ctx_indexp, unsigned char *buf, size_t len)
{
  stream_session_t *tls_session;
  uword ctx_index;
  tls_ctx_t *ctx;
  int rv;

  ctx_index = pointer_to_uword (ctx_indexp);
  ctx = tls_ctx_get (ctx_index);
  tls_session = session_get_from_handle (ctx->tls_session_handle);
  rv = svm_fifo_dequeue_nowait (tls_session->server_rx_fifo, len, buf);
  return rv;
}

static void
mbedtls_debug (void *ctx, int level, const char *file, int line, const char *str)
{
  ((void) level);
  fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
  fflush(  (FILE *) ctx  );
}

static void
tls_timing_set_delay (void *data, u32 int_ms, u32 fin_ms)
{
  uword ctx_index = pointer_to_uword (data);
  tls_ctx_t *ctx;

  ctx = tls_ctx_get (ctx_index);
  ctx->mbedtls_timer_counter = int_ms;
}

static int
tls_timing_get_delay (void *data)
{
  uword ctx_index = pointer_to_uword (data);
  tls_ctx_t *ctx;
  stream_session_t *tls_session;

  ctx = tls_ctx_get (ctx_index);
  tls_session = session_get_from_handle (ctx->tls_session_handle);

  if (!svm_fifo_max_dequeue(tls_session->server_rx_fifo))
    return 2;
//  ctx->mbedtls_timer_counter ++;
//  if (ctx->mbedtls_timer_counter >= 2)
//    return (2);
  return 0;
}

static int
tls_ctx_init_client (tls_ctx_t *ctx)
{
  const char *pers = "vpp_ssl_client";
  mbedtls_entropy_context entropy;
  tls_main_t *tm = &tls_main;
  mbedtls_ctr_drbg_context ctr_drbg;
  void *ctx_ptr;
  int rv;

  mbedtls_ssl_init(&ctx->ssl);
  mbedtls_ssl_config_init(&ctx->conf);
  if ((rv = mbedtls_ssl_config_defaults (&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
	                                 MBEDTLS_SSL_TRANSPORT_STREAM,
	                                 MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
      clib_warning("failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n",
                   rv);
      return -1;
    }

  mbedtls_ctr_drbg_init (&ctr_drbg);
  mbedtls_entropy_init (&entropy);
  if ((rv = mbedtls_ctr_drbg_seed (&ctr_drbg, mbedtls_entropy_func,
	                           &entropy, (const unsigned char *) pers,
	                           strlen (pers))) != 0)
    {
      clib_warning ("failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", rv);
      return -1;
    }

  mbedtls_ssl_conf_authmode (&ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain (&ctx->conf, &tm->cacert, NULL);
  mbedtls_ssl_conf_rng (&ctx->conf, mbedtls_ctr_drbg_random, &ctr_drbg);
  mbedtls_ssl_conf_dbg (&ctx->conf, mbedtls_debug, stdout);

  if ((rv = mbedtls_ssl_setup (&ctx->ssl, &ctx->conf)) != 0)
    {
      clib_warning("failed\n  ! mbedtls_ssl_setup returned %d\n", rv);
      return -1;
    }

  if ((rv = mbedtls_ssl_set_hostname (&ctx->ssl, "SERVER NAME")) != 0)
    {
      clib_warning("failed\n  ! mbedtls_ssl_set_hostname returned %d\n", rv);
      return -1;
    }

  ctx_ptr = uword_to_pointer (tls_ctx_index (ctx), void *);
  mbedtls_ssl_set_bio (&ctx->ssl, ctx_ptr, tls_net_send, tls_net_recv,
	               NULL);

  /*
   * Program timers. Will use these to avoid blocking on read
   */
  mbedtls_ssl_set_timer_cb (&ctx->ssl, ctx_ptr, tls_timing_set_delay,
	                    tls_timing_get_delay);
  mbedtls_debug_set_threshold (MBEDTLS_DEBUG_LEVEL_CLIENT);

  /*
   * Do the first 2 steps in the handshake.
   */

  /* To avoid blocking on read set the timer with delay 0 (value 2) */
  ctx->mbedtls_timer_counter = 2;
  while (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&ctx->ssl);
      if (rv != 0)
	break;
    }
  clib_warning ("TLS STATE IS %u", ctx->ssl.state);
  return 0;
}

static int
tls_ctx_init_server (tls_ctx_t *ctx)
{
  const char *pers = "vpp_ssl_server";
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  void *ctx_ptr;
  int rv;

  mbedtls_ssl_init (&ctx->ssl);
  mbedtls_ssl_config_init (&ctx->conf);
  mbedtls_x509_crt_init (&ctx->srvcert);
  mbedtls_pk_init( &ctx->pkey );
  mbedtls_entropy_init (&entropy);
  mbedtls_ctr_drbg_init (&ctr_drbg);

  /*
   * 1. Cert
   */
  rv = mbedtls_x509_crt_parse( &ctx->srvcert, (const unsigned char *) mbedtls_test_srv_crt,
                        mbedtls_test_srv_crt_len );
  if (rv != 0)
    {
      clib_warning (" failed\n  !  mbedtls_x509_crt_parse returned %d",
	              rv);
      goto exit;
    }

  rv = mbedtls_x509_crt_parse (&ctx->srvcert,
	                       (const unsigned char *) mbedtls_test_cas_pem,
	                       mbedtls_test_cas_pem_len);
  if (rv != 0)
    {
      clib_warning (" failed\n  !  mbedtls_x509_crt_parse returned %d",
	              rv);
      goto exit;
    }

  rv = mbedtls_pk_parse_key (&ctx->pkey,
	                     (const unsigned char *) mbedtls_test_srv_key,
	                     mbedtls_test_srv_key_len, NULL, 0);
  if (rv != 0)
    {
      clib_warning (" failed\n  !  mbedtls_pk_parse_key returned %d", rv);
      goto exit;
    }

  /*
   * 2. Seen the RNG
   */
  if ((rv = mbedtls_ctr_drbg_seed (&ctr_drbg, mbedtls_entropy_func, &entropy,
	                           (const unsigned char *) pers, strlen (pers)))
      != 0)
    {
      clib_warning (" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", rv);
      goto exit;
    }

  /*
   * 3. Setup remaining stuff
   */
  if ((rv = mbedtls_ssl_config_defaults (&ctx->conf, MBEDTLS_SSL_IS_SERVER,
	                                 MBEDTLS_SSL_TRANSPORT_STREAM,
	                                 MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
      clib_warning (" failed\n  ! mbedtls_ssl_config_defaults returned %d",
                    rv);
      goto exit;
    }

  mbedtls_ssl_conf_rng( &ctx->conf, mbedtls_ctr_drbg_random, &ctr_drbg );
  mbedtls_ssl_conf_dbg( &ctx->conf, mbedtls_debug, stdout );

  /* TODO CACHE
  mbedtls_ssl_conf_session_cache( &ctx->conf, &cache,
                                 mbedtls_ssl_cache_get,
                                 mbedtls_ssl_cache_set );
  */

  mbedtls_ssl_conf_ca_chain (&ctx->conf, ctx->srvcert.next, NULL);
  if ((rv = mbedtls_ssl_conf_own_cert (&ctx->conf, &ctx->srvcert, &ctx->pkey))
      != 0)
    {
      clib_warning (" failed\n  ! mbedtls_ssl_conf_own_cert returned %d", rv);
      goto exit;
    }

  if ((rv = mbedtls_ssl_setup (&ctx->ssl, &ctx->conf)) != 0)
    {
      clib_warning(" failed\n  ! mbedtls_ssl_setup returned %d", rv);
      goto exit;
    }

  mbedtls_ssl_session_reset (&ctx->ssl);
  ctx_ptr = uword_to_pointer (tls_ctx_index (ctx), void *);
  mbedtls_ssl_set_bio (&ctx->ssl, ctx_ptr, tls_net_send, tls_net_recv,
	               NULL);
  /*
   * 4. Setup timers. Will use these to avoid blocking on read
   */
  mbedtls_ssl_set_timer_cb (&ctx->ssl, ctx_ptr, tls_timing_set_delay,
	                    tls_timing_get_delay);

  mbedtls_debug_set_threshold (MBEDTLS_DEBUG_LEVEL_SERVER);

  /*
   * 5. Start handshake state machine
   */
  /* To avoid blocking on read set the timer with delay 0 (value 2) */
  ctx->mbedtls_timer_counter = 2;
  while (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&ctx->ssl);
      if (rv != 0)
	break;
    }

  clib_warning ("TLS STATE FOR %u IS %u", tls_ctx_index (ctx), ctx->ssl.state);
  return 0;

exit:
  return -1;
}

static int
tls_notify_app_accept (tls_ctx_t *ctx)
{
  stream_session_t *app_listener, *app_session;
  segment_manager_t *sm;
  application_t *app;
  int rv;

  app = application_get (ctx->parent_app_index);
  app_listener = listen_session_get_from_handle(ctx->app_session_handle);
  sm = application_get_listen_segment_manager (app, app_listener);

  app_session = session_alloc (vlib_get_thread_index ());
  app_session->app_index = ctx->parent_app_index;
  app_session->connection_index = tls_ctx_index (ctx);
  app_session->session_type = app_listener->session_type;
  app_session->listener_index = app_listener->session_index;
  if ((rv = session_alloc_fifos (sm, app_session)))
    return rv;
  ctx->app_session_handle = session_handle (app_session);
  return app->cb_fns.session_accept_callback (app_session);
}

static int
tls_notify_app_connected (tls_ctx_t *ctx)
{
  int (*cb_fn) (u32, u32, stream_session_t *, u8);
  stream_session_t *app_session;
  segment_manager_t *sm;
  application_t *app;

  app = application_get (ctx->parent_app_index);
  cb_fn = app->cb_fns.session_connected_callback;

  sm = application_get_connect_segment_manager (app);
  app_session = session_alloc (vlib_get_thread_index());
  app_session->app_index = ctx->parent_app_index;
  app_session->connection_index = tls_ctx_index (ctx);
  app_session->session_type = session_type_from_proto_and_ip (
      TRANSPORT_PROTO_TLS, ctx->is_ip4);
  if (session_alloc_fifos (sm, app_session))
    goto failed;

  ctx->app_session_handle = session_handle (app_session);
  app_session->session_state = SESSION_STATE_READY;
  if (cb_fn (ctx->parent_app_index, ctx->parent_app_api_context,
                app_session, 0 /* not failed */))
    {
      clib_warning ("failed to notify app");
      /* FIXME cleanup */
    }

  return 0;

failed:
  return cb_fn (ctx->parent_app_index, ctx->parent_app_api_context, 0,
	        1/* failed */);
}

static int
tls_handshake_rx (tls_ctx_t *ctx)
{
  int rv;
  ctx->mbedtls_timer_counter = 0;
  while (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&ctx->ssl);
      if (rv != 0)
	break;
    }
  clib_warning ("TLS STATE FOR %u IS %u", tls_ctx_index (ctx), ctx->ssl.state);

  if (ctx->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      if (ctx->ssl.conf->endpoint == MBEDTLS_SSL_IS_SERVER)
	tls_notify_app_accept (ctx);
      else
	tls_notify_app_connected (ctx);
    }
  return 0;
}

void
tls_session_reset_callback (stream_session_t * s)
{
  clib_warning ("called...");
}

int
tls_add_segment_callback (u32 client_index, const ssvm_private_t * fs)
{
  /* No-op for builtin */
  return 0;
}

int
tls_del_segment_callback (u32 client_index, const ssvm_private_t * fs)
{
  return 0;
}

void
tls_session_disconnect_callback (stream_session_t * tls_session)
{
  stream_session_t *app_session;
  tls_ctx_t *ctx;
  application_t *app;

  ctx = tls_ctx_get (tls_session->opaque);
  if (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      stream_session_disconnect (tls_session);
      return;
    }
  app = application_get (ctx->parent_app_index);
  app_session = session_get_from_handle(ctx->app_session_handle);
  app->cb_fns.session_disconnect_callback (app_session);
}

int
tls_session_accept_callback (stream_session_t * tls_session)
{
  stream_session_t *tls_listener;
  tls_ctx_t *lctx, *ctx;
  u32 ctx_index;

  tls_listener = listen_session_get (tls_session->session_type,
                                     tls_session->listener_index);
  lctx = tls_listener_ctx_get (tls_listener->opaque);
  ctx_index = tls_ctx_alloc ();
  ctx = tls_ctx_get (ctx_index);
  memcpy (ctx, lctx, sizeof (*lctx));

  tls_session->session_state = SESSION_STATE_READY;
  tls_session->opaque = ctx_index;
  ctx->tls_session_handle = session_handle (tls_session);

  return tls_ctx_init_server (ctx);
}

int
tls_app_tx_callback (stream_session_t * app_session)
{
  stream_session_t *tls_session;
  tls_ctx_t *ctx;
  static u8 *tmp_buf;
  u32 enq_max, deq_max, enq_now;
  int wrote;

  ctx = tls_ctx_get (app_session->connection_index);
  if (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    tls_add_vpp_queue_event (app_session->server_tx_fifo, FIFO_EVENT_APP_TX);

  tls_session = session_get_from_handle (ctx->tls_session_handle);

  enq_max = svm_fifo_max_enqueue (tls_session->server_tx_fifo);
  deq_max = svm_fifo_max_dequeue (app_session->server_tx_fifo);
  enq_now = clib_min (deq_max, enq_max);

  if (PREDICT_FALSE (enq_now == 0))
    {
      if (deq_max)
	tls_add_vpp_queue_event (app_session->server_tx_fifo,
	                         FIFO_EVENT_APP_TX);
      return 0;
    }

  vec_validate (tmp_buf, enq_now);
  svm_fifo_dequeue_nowait (app_session->server_tx_fifo, enq_now, tmp_buf);
  wrote = svm_fifo_enqueue_nowait (tls_session->server_tx_fifo, enq_now,
                                   tmp_buf);
  ASSERT (wrote == enq_now);
  vec_reset_length (tmp_buf);
  tls_add_vpp_queue_event (tls_session->server_tx_fifo, FIFO_EVENT_APP_TX);

  if (enq_now < deq_max)
    tls_add_vpp_queue_event (app_session->server_tx_fifo,
                             FIFO_EVENT_APP_TX);

  return 0;
}

int
tls_app_rx_callback (stream_session_t * tls_session)
{
  stream_session_t *app_session;
  u32 deq_max, enq_max, enq_now;
  application_t *app;
  static u8 *tmp_buf;
  tls_ctx_t *ctx;
  int wrote;

  ctx = tls_ctx_get (tls_session->opaque);
  if (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    return tls_handshake_rx (ctx);

  app_session = session_get_from_handle (ctx->app_session_handle);

  enq_max = svm_fifo_max_enqueue (app_session->server_rx_fifo);
  deq_max = svm_fifo_max_dequeue (tls_session->server_rx_fifo);
  enq_now = clib_min (enq_max, deq_max);

  if (PREDICT_FALSE (enq_now == 0))
    {
      if (deq_max)
	tls_add_vpp_queue_event (tls_session->server_rx_fifo,
	                         FIFO_EVENT_BUILTIN_RX);
      return 0;
    }

  vec_validate (tmp_buf, enq_now);
  svm_fifo_dequeue_nowait (tls_session->server_rx_fifo, enq_now, tmp_buf);
  wrote = svm_fifo_enqueue_nowait (app_session->server_rx_fifo, enq_now,
                                   tmp_buf);
  vec_reset_length (tmp_buf);

  ASSERT (wrote == enq_now);
  if (enq_now < enq_max)
    tls_add_vpp_queue_event (tls_session->server_rx_fifo,
                             FIFO_EVENT_BUILTIN_RX);

  app = application_get_if_valid (app_session->app_index);
  tls_add_app_queue_event (app, app_session->server_rx_fifo,
                           FIFO_EVENT_APP_RX);

  return 0;
}

int
tls_session_connected_callback (u32 tls_app_index, u32 ctx_index,
                                stream_session_t * tls_session,
                                u8 is_fail)
{
  int (*cb_fn) (u32, u32, stream_session_t *, u8);
  application_t *app;
  tls_ctx_t *ctx;

  ctx = tls_ctx_get (ctx_index);
  app = application_get (ctx->parent_app_index);
  cb_fn = app->cb_fns.session_connected_callback;

  if (is_fail)
    goto failed;

  ctx->tls_session_handle = session_handle (tls_session);
  tls_session->opaque = ctx_index;
  tls_session->session_state = SESSION_STATE_READY;

  return tls_ctx_init_client (ctx);

failed:
  return cb_fn (ctx->parent_app_index, ctx->parent_app_api_context, 0,
                1/* failed */);
}

/* *INDENT-OFF* */
static session_cb_vft_t tls_app_cb_vft = {
  .session_accept_callback = tls_session_accept_callback,
  .session_disconnect_callback = tls_session_disconnect_callback,
  .session_connected_callback = tls_session_connected_callback,
  .session_reset_callback = tls_session_reset_callback,
  .add_segment_callback = tls_add_segment_callback,
  .del_segment_callback = tls_del_segment_callback,
  .builtin_app_rx_callback = tls_app_rx_callback,
  .builtin_app_tx_callback = tls_app_tx_callback,
};
/* *INDENT-ON* */

int
tls_connect (transport_endpoint_t *tep)
{
  session_endpoint_extended_t *sep;
  session_endpoint_t tls_sep;
  tls_main_t *tm = &tls_main;
  application_t *app;
  tls_ctx_t *ctx;
  u32 ctx_index;
  int rv;

  sep = (session_endpoint_extended_t *)tep;

  ctx_index = tls_ctx_alloc ();
  ctx = tls_ctx_get (ctx_index);
  ctx->parent_app_index = sep->app_index;
  ctx->parent_app_api_context = sep->opaque;
  ctx->is_ip4 = sep->is_ip4;

  app = application_get (sep->app_index);
  application_alloc_connects_segment_manager (app);

  clib_memcpy (&tls_sep, sep, sizeof (tls_sep));
  tls_sep.transport_proto = TRANSPORT_PROTO_TCP;
  if ((rv = application_connect (tm->app_index, ctx_index, &tls_sep)))
    return rv;

  return 0;
}

void
tls_disconnect (u32 ctx_index, u32 thread_index)
{
  stream_session_t *tls_session, *app_session;
  tls_ctx_t *ctx;

  clib_warning ("disconnect called");

  ctx = tls_ctx_get (ctx_index);
  tls_session = session_get_from_handle (ctx->tls_session_handle);
  app_session = session_get_from_handle (ctx->app_session_handle);
  stream_session_disconnect (tls_session);
  segment_manager_dealloc_fifos (app_session->svm_segment_index,
                                 app_session->server_rx_fifo,
				 app_session->server_tx_fifo);
  session_free (app_session);
}

u32
tls_start_listen (u32 app_listener_index, transport_endpoint_t * tep)
{
  tls_main_t *tm = &tls_main;
  application_t *tls_app;
  session_handle_t tls_handle;
  session_endpoint_extended_t *sep;
  stream_session_t *tls_listener;
  tls_ctx_t *ctx;
  u32 ctx_index;
  session_type_t st;
  stream_session_t *app_listener;

  sep = (session_endpoint_extended_t *)tep;
  ctx_index = tls_listener_ctx_alloc ();
  ctx = tls_listener_ctx_get (ctx_index);
  st = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);
  app_listener = listen_session_get(st, app_listener_index);

  tls_app = application_get (tm->app_index);
  sep->transport_proto = TRANSPORT_PROTO_TCP;
  if (application_start_listen (tls_app, (session_endpoint_t *)sep,
                                &tls_handle))
    return ~0;

  tls_listener = listen_session_get_from_handle (tls_handle);
  tls_listener->opaque = ctx_index;
  ctx->parent_app_index = sep->app_index;
  ctx->tls_session_handle = tls_handle;
  ctx->app_session_handle = listen_session_get_handle (app_listener);
  return ctx_index;
}

u32
tls_unbind (u32 listener_index)
{
  clib_warning ("TBD");
  return 0;
}

transport_connection_t *
tls_listener_get (u32 listener_index)
{
  tls_ctx_t *ctx;
  ctx = tls_listener_ctx_get (listener_index);
  return &ctx->connection;
}

u8 *
format_tls_ctx (u8 * s, va_list * args)
{
  tls_ctx_t *ctx  = va_arg(*args, tls_ctx_t *);
  u32 thread_index = va_arg (*args, u32);
  u32 child_si, child_ti;

  session_parse_handle (ctx->tls_session_handle, &child_si, &child_ti);
  if (thread_index != child_ti)
    clib_warning ("app and tls sessions are on different threads!");

  s = format (s, "[#%d][TLS] app %u child %u", child_ti, ctx->parent_app_index,
	      child_si);
  return s;
}

u8 *
format_tls_connection (u8 * s, va_list * args)
{
  u32 ctx_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  tls_ctx_t *ctx;

  ctx = tls_ctx_get (ctx_index);
  if (!ctx)
    return s;

  s = format (s, "%-50U", format_tls_ctx, ctx, thread_index);
  if (verbose)
    {
      s = format (s, "%-15s", "state");
      if (verbose > 1)
	s = format (s, "\n");
    }
  return s;
}

/* *INDENT-OFF* */
const static transport_proto_vft_t tls_proto = {
  .open = tls_connect,
  .close = tls_disconnect,
  .bind = tls_start_listen,
  .get_listener = tls_listener_get,
  .unbind = tls_unbind,
  .tx_type = TRANSPORT_TX_INTERNAL,
  .service_type = TRANSPORT_SERVICE_APP,
  .format_connection = format_tls_connection,
};
/* *INDENT-ON* */

static int
tls_init_tls_data ()
{
  tls_main_t *tm = &tls_main;
  int rv;

  mbedtls_x509_crt_init(&tm->cacert);
  rv = mbedtls_x509_crt_parse(&tm->cacert, (const unsigned char *) mbedtls_test_cas_pem,
                              mbedtls_test_cas_pem_len );
  if (rv < 0)
    {
      clib_warning ("mbedtls_x509_crt_parse returned -0x%x", -rv);
      return -1;
    }

  return 0;
}

clib_error_t *
tls_init (vlib_main_t * vm)
{
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u32 segment_size = 512 << 20;
  tls_main_t *tm = &tls_main;
  u32 fifo_size = 64 << 10;

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->session_cb_vft = &tls_app_cb_vft;
  a->api_client_index = ~0;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach tls app");
      return clib_error_return(0, "failed to attach tls app");
    }

  tm->app_index = a->app_index;

  transport_register_protocol (TRANSPORT_PROTO_TLS, &tls_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_TLS, &tls_proto,
			       FIB_PROTOCOL_IP6, ~0);

  tls_init_tls_data ();
  return 0;
}

VLIB_INIT_FUNCTION (tls_init);

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
