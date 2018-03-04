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

#include <vnet/session/application_interface.h>
#include <vppinfra/lock.h>
#include <mbedtls/ssl.h>
#include <mbedtls/certs.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/timing.h>
#include <mbedtls/debug.h>

#define TLS_DEBUG (0)
#define TLS_DEBUG_LEVEL_CLIENT (0)
#define TLS_DEBUG_LEVEL_SERVER (0)
#define TLS_CHUNK_SIZE (1 << 14)
#define TLS_USE_OUR_MEM_FUNCS (0)

#if TLS_DEBUG
#define TLS_DBG(_lvl, _fmt, _args...) 			\
  if (_lvl <= TLS_DEBUG) 				\
    clib_warning (_fmt, ##_args)
#else
#define TLS_DBG(_fmt, _args...)
#endif

#if TLS_USE_OUR_MEM_FUNCS
#include <mbedtls/platform.h>

void *
mbedtls_calloc_fn (size_t n, size_t size)
{
  void *ptr;
  ptr = clib_mem_alloc (n * size);
  memset (ptr, 0, sizeof (*ptr));
  return ptr;
}

void
mbedtls_free_fn (void *ptr)
{
  if (ptr)
    clib_mem_free (ptr);
}
#endif

/* *INDENT-OFF* */
typedef CLIB_PACKED (struct tls_cxt_id_
{
  u32 parent_app_index;
  session_handle_t app_session_handle;
  session_handle_t tls_session_handle;
  u32 listener_ctx_index;
  u8 tcp_is_ip4;
}) tls_ctx_id_t;
/* *INDENT-ON* */

typedef struct tls_ctx_
{
  union
  {
    transport_connection_t connection;
    tls_ctx_id_t c_tls_ctx_id;
  };
#define parent_app_index c_tls_ctx_id.parent_app_index
#define app_session_handle c_tls_ctx_id.app_session_handle
#define tls_session_handle c_tls_ctx_id.tls_session_handle
#define listener_ctx_index c_tls_ctx_id.listener_ctx_index
#define tcp_is_ip4 c_tls_ctx_id.tcp_is_ip4
#define tls_ctx_idx c_c_index
  /* Temporary storage for session open opaque. Overwritten once
   * underlying tcp connection is established */
#define parent_app_api_context c_s_index

  u8 is_passive_close;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
} tls_ctx_t;

typedef struct tls_main_
{
  u32 app_index;
  tls_ctx_t ***ctx_pool;
  mbedtls_ctr_drbg_context *ctr_drbgs;
  mbedtls_entropy_context *entropy_pools;
  tls_ctx_t *listener_ctx_pool;
  tls_ctx_t *half_open_ctx_pool;
  clib_rwlock_t half_open_rwlock;
  mbedtls_x509_crt cacert;
} tls_main_t;

static tls_main_t tls_main;

void tls_disconnect (u32 ctx_index, u32 thread_index);

static inline int
tls_add_vpp_q_evt (svm_fifo_t * f, u8 evt_type)
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
	  svm_queue_add (q, (u8 *) & evt, 0 /* do wait for mutex */ );
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
tls_add_app_q_evt (application_t * app, stream_session_t * app_session)
{
  session_fifo_event_t evt;
  svm_queue_t *q;

  if (PREDICT_FALSE (app_session->session_state == SESSION_STATE_CLOSED))
    {
      /* Session is closed so app will never clean up. Flush rx fifo */
      u32 to_dequeue = svm_fifo_max_dequeue (app_session->server_rx_fifo);
      if (to_dequeue)
	svm_fifo_dequeue_drop (app_session->server_rx_fifo, to_dequeue);
      return 0;
    }

  if (app->cb_fns.builtin_app_rx_callback)
    return app->cb_fns.builtin_app_rx_callback (app_session);

  if (svm_fifo_set_event (app_session->server_rx_fifo))
    {
      evt.fifo = app_session->server_rx_fifo;
      evt.event_type = FIFO_EVENT_APP_RX;
      q = app->event_queue;

      if (PREDICT_TRUE (q->cursize < q->maxsize))
	{
	  svm_queue_add (q, (u8 *) & evt, 0 /* do wait for mutex */ );
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
  u8 thread_index = vlib_get_thread_index ();
  tls_main_t *tm = &tls_main;
  tls_ctx_t **ctx;

  pool_get (tm->ctx_pool[thread_index], ctx);
  if (!(*ctx))
    *ctx = clib_mem_alloc (sizeof (tls_ctx_t));

  memset (*ctx, 0, sizeof (tls_ctx_t));
  (*ctx)->c_thread_index = thread_index;
  return ctx - tm->ctx_pool[thread_index];
}

void
tls_ctx_free (tls_ctx_t * ctx)
{
  pool_put_index (tls_main.ctx_pool[vlib_get_thread_index ()],
		  ctx->tls_ctx_idx);
}

tls_ctx_t *
tls_ctx_get (u32 ctx_index)
{
  tls_ctx_t **ctx;
  ctx = pool_elt_at_index (tls_main.ctx_pool[vlib_get_thread_index ()],
			   ctx_index);
  return (*ctx);
}

tls_ctx_t *
tls_ctx_get_w_thread (u32 ctx_index, u8 thread_index)
{
  tls_ctx_t **ctx;
  ctx = pool_elt_at_index (tls_main.ctx_pool[thread_index], ctx_index);
  return (*ctx);
}

u32
tls_listener_ctx_alloc (void)
{
  tls_main_t *tm = &tls_main;
  tls_ctx_t *ctx;

  pool_get (tm->listener_ctx_pool, ctx);
  memset (ctx, 0, sizeof (*ctx));
  return ctx - tm->listener_ctx_pool;
}

void
tls_listener_ctx_free (tls_ctx_t * ctx)
{
  pool_put (tls_main.listener_ctx_pool, ctx);
}

tls_ctx_t *
tls_listener_ctx_get (u32 ctx_index)
{
  return pool_elt_at_index (tls_main.listener_ctx_pool, ctx_index);
}

u32
tls_listener_ctx_index (tls_ctx_t * ctx)
{
  return (ctx - tls_main.listener_ctx_pool);
}

u32
tls_ctx_half_open_alloc (void)
{
  tls_main_t *tm = &tls_main;
  u8 will_expand = 0;
  tls_ctx_t *ctx;
  u32 ctx_index;

  pool_get_aligned_will_expand (tm->half_open_ctx_pool, will_expand, 0);
  if (PREDICT_FALSE (will_expand && vlib_num_workers ()))
    {
      clib_rwlock_writer_lock (&tm->half_open_rwlock);
      pool_get (tm->half_open_ctx_pool, ctx);
      memset (ctx, 0, sizeof (*ctx));
      ctx_index = ctx - tm->half_open_ctx_pool;
      clib_rwlock_writer_unlock (&tm->half_open_rwlock);
    }
  else
    {
      pool_get (tm->half_open_ctx_pool, ctx);
      memset (ctx, 0, sizeof (*ctx));
      ctx_index = ctx - tm->half_open_ctx_pool;
    }
  return ctx_index;
}

void
tls_ctx_half_open_free (u32 ho_index)
{
  tls_main_t *tm = &tls_main;
  clib_rwlock_writer_lock (&tm->half_open_rwlock);
  pool_put_index (tls_main.half_open_ctx_pool, ho_index);
  clib_rwlock_writer_unlock (&tm->half_open_rwlock);
}

tls_ctx_t *
tls_ctx_half_open_get (u32 ctx_index)
{
  tls_main_t *tm = &tls_main;
  clib_rwlock_reader_lock (&tm->half_open_rwlock);
  return pool_elt_at_index (tm->half_open_ctx_pool, ctx_index);
}

void
tls_ctx_half_open_reader_unlock ()
{
  clib_rwlock_reader_unlock (&tls_main.half_open_rwlock);
}

u32
tls_ctx_half_open_index (tls_ctx_t * ctx)
{
  return (ctx - tls_main.half_open_ctx_pool);
}

static int
tls_init_ctr_drbgs_and_entropy (u32 num_threads)
{
  tls_main_t *tm = &tls_main;
  int i;

  vec_validate (tm->ctr_drbgs, num_threads - 1);
  vec_validate (tm->entropy_pools, num_threads - 1);
  for (i = 0; i < num_threads; i++)
    tls_main.ctr_drbgs[i].f_entropy = 0;

  return 0;
}

static int
tls_init_ctr_seed_drbgs (void)
{
  u32 thread_index = vlib_get_thread_index ();
  tls_main_t *tm = &tls_main;
  u8 *pers;
  int rv;
  pers = format (0, "vpp thread %u", thread_index);

  mbedtls_entropy_init (&tm->entropy_pools[thread_index]);
  mbedtls_ctr_drbg_init (&tls_main.ctr_drbgs[thread_index]);
  if ((rv = mbedtls_ctr_drbg_seed (&tm->ctr_drbgs[thread_index],
				   mbedtls_entropy_func,
				   &tm->entropy_pools[thread_index],
				   (const unsigned char *) pers,
				   vec_len (pers))) != 0)
    {
      vec_free (pers);
      TLS_DBG (1, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", rv);
      return -1;
    }
  vec_free (pers);
  return 0;
}

mbedtls_ctr_drbg_context *
tls_get_ctr_drbg ()
{
  u8 thread_index = vlib_get_thread_index ();
  if (PREDICT_FALSE (!tls_main.ctr_drbgs[thread_index].f_entropy))
    tls_init_ctr_seed_drbgs ();
  return &tls_main.ctr_drbgs[thread_index];
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
  if (rv < 0)
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  tls_add_vpp_q_evt (tls_session->server_tx_fifo, FIFO_EVENT_APP_TX);
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
  return (rv < 0) ? 0 : rv;
}

static void
mbedtls_debug (void *ctx, int level, const char *file, int line,
	       const char *str)
{
  ((void) level);
  fprintf ((FILE *) ctx, "%s:%04d: %s", file, line, str);
  fflush ((FILE *) ctx);
}

static int
tls_ctx_init_client (tls_ctx_t * ctx)
{
  tls_main_t *tm = &tls_main;
  void *ctx_ptr;
  int rv;

  /*
   * 1. Setup SSL
   */
  mbedtls_ssl_init (&ctx->ssl);
  mbedtls_ssl_config_init (&ctx->conf);
  if ((rv = mbedtls_ssl_config_defaults (&ctx->conf, MBEDTLS_SSL_IS_CLIENT,
					 MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
      TLS_DBG (1, "failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n",
	       rv);
      return -1;
    }

  mbedtls_ssl_conf_authmode (&ctx->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain (&ctx->conf, &tm->cacert, NULL);
  mbedtls_ssl_conf_rng (&ctx->conf, mbedtls_ctr_drbg_random,
			tls_get_ctr_drbg ());
  mbedtls_ssl_conf_dbg (&ctx->conf, mbedtls_debug, stdout);

  if ((rv = mbedtls_ssl_setup (&ctx->ssl, &ctx->conf)) != 0)
    {
      TLS_DBG (1, "failed\n  ! mbedtls_ssl_setup returned %d\n", rv);
      return -1;
    }

  if ((rv = mbedtls_ssl_set_hostname (&ctx->ssl, "SERVER NAME")) != 0)
    {
      TLS_DBG (1, "failed\n  ! mbedtls_ssl_set_hostname returned %d\n", rv);
      return -1;
    }

  ctx_ptr = uword_to_pointer (ctx->tls_ctx_idx, void *);
  mbedtls_ssl_set_bio (&ctx->ssl, ctx_ptr, tls_net_send, tls_net_recv, NULL);

  mbedtls_debug_set_threshold (TLS_DEBUG_LEVEL_CLIENT);

  /*
   * 2. Do the first 2 steps in the handshake.
   */
  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   tls_ctx_index (ctx));
  while (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&ctx->ssl);
      if (rv != 0)
	break;
    }
  TLS_DBG (2, "tls state for [%u]%u is %u", ctx->c_thread_index,
	   tls_ctx_index (ctx), ctx->ssl.state);
  return 0;
}

static int
tls_ctx_init_server (tls_ctx_t * ctx)
{
  application_t *app;
  void *ctx_ptr;
  int rv;

  mbedtls_ssl_init (&ctx->ssl);
  mbedtls_ssl_config_init (&ctx->conf);
  mbedtls_x509_crt_init (&ctx->srvcert);
  mbedtls_pk_init (&ctx->pkey);

  /*
   * 1. Cert
   */
  app = application_get (ctx->parent_app_index);
  if (!app->tls_cert || !app->tls_key)
    {
      TLS_DBG (1, " failed\n  ! tls cert and/or key not configured %d",
	       ctx->parent_app_index);
      return -1;
    }

  rv = mbedtls_x509_crt_parse (&ctx->srvcert,
			       (const unsigned char *) app->tls_cert,
			       mbedtls_test_srv_crt_len);
  if (rv != 0)
    {
      TLS_DBG (1, " failed\n  !  mbedtls_x509_crt_parse returned %d", rv);
      goto exit;
    }

  /* TODO clone CA */
  rv = mbedtls_x509_crt_parse (&ctx->srvcert,
			       (const unsigned char *) mbedtls_test_cas_pem,
			       mbedtls_test_cas_pem_len);
  if (rv != 0)
    {
      TLS_DBG (1, " failed\n  !  mbedtls_x509_crt_parse returned %d", rv);
      goto exit;
    }

  rv = mbedtls_pk_parse_key (&ctx->pkey,
			     (const unsigned char *) app->tls_key,
			     mbedtls_test_srv_key_len, NULL, 0);
  if (rv != 0)
    {
      TLS_DBG (1, " failed\n  !  mbedtls_pk_parse_key returned %d", rv);
      goto exit;
    }

  /*
   * 2. SSL context config
   */
  if ((rv = mbedtls_ssl_config_defaults (&ctx->conf, MBEDTLS_SSL_IS_SERVER,
					 MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
      TLS_DBG (1, " failed\n  ! mbedtls_ssl_config_defaults returned %d", rv);
      goto exit;
    }

  mbedtls_ssl_conf_rng (&ctx->conf, mbedtls_ctr_drbg_random,
			tls_get_ctr_drbg ());
  mbedtls_ssl_conf_dbg (&ctx->conf, mbedtls_debug, stdout);

  /* TODO CACHE
     mbedtls_ssl_conf_session_cache( &ctx->conf, &cache,
     mbedtls_ssl_cache_get,
     mbedtls_ssl_cache_set );
   */

  mbedtls_ssl_conf_ca_chain (&ctx->conf, ctx->srvcert.next, NULL);
  if ((rv = mbedtls_ssl_conf_own_cert (&ctx->conf, &ctx->srvcert, &ctx->pkey))
      != 0)
    {
      TLS_DBG (1, " failed\n  ! mbedtls_ssl_conf_own_cert returned %d", rv);
      goto exit;
    }

  if ((rv = mbedtls_ssl_setup (&ctx->ssl, &ctx->conf)) != 0)
    {
      TLS_DBG (1, " failed\n  ! mbedtls_ssl_setup returned %d", rv);
      goto exit;
    }

  mbedtls_ssl_session_reset (&ctx->ssl);
  ctx_ptr = uword_to_pointer (ctx->tls_ctx_idx, void *);
  mbedtls_ssl_set_bio (&ctx->ssl, ctx_ptr, tls_net_send, tls_net_recv, NULL);

  mbedtls_debug_set_threshold (TLS_DEBUG_LEVEL_SERVER);

  /*
   * 3. Start handshake state machine
   */
  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   tls_ctx_index (ctx));
  while (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&ctx->ssl);
      if (rv != 0)
	break;
    }

  TLS_DBG (2, "tls state for [%u]%u is %u", ctx->c_thread_index,
	   tls_ctx_index (ctx), ctx->ssl.state);
  return 0;

exit:
  return -1;
}

static int
tls_notify_app_accept (tls_ctx_t * ctx)
{
  stream_session_t *app_listener, *app_session;
  segment_manager_t *sm;
  application_t *app;
  tls_ctx_t *lctx;
  int rv;

  app = application_get (ctx->parent_app_index);
  lctx = tls_listener_ctx_get (ctx->listener_ctx_index);
  app_listener = listen_session_get_from_handle (lctx->app_session_handle);
  sm = application_get_listen_segment_manager (app, app_listener);

  app_session = session_alloc (vlib_get_thread_index ());
  app_session->app_index = ctx->parent_app_index;
  app_session->connection_index = ctx->tls_ctx_idx;
  app_session->session_type = app_listener->session_type;
  app_session->listener_index = app_listener->session_index;
  if ((rv = session_alloc_fifos (sm, app_session)))
    {
      TLS_DBG (1, "failed to allocate fifos");
      return rv;
    }
  ctx->c_s_index = app_session->session_index;
  ctx->app_session_handle = session_handle (app_session);
  return app->cb_fns.session_accept_callback (app_session);
}

static int
tls_notify_app_connected (tls_ctx_t * ctx)
{
  int (*cb_fn) (u32, u32, stream_session_t *, u8);
  stream_session_t *app_session;
  segment_manager_t *sm;
  application_t *app;

  app = application_get (ctx->parent_app_index);
  cb_fn = app->cb_fns.session_connected_callback;

  sm = application_get_connect_segment_manager (app);
  app_session = session_alloc (vlib_get_thread_index ());
  app_session->app_index = ctx->parent_app_index;
  app_session->connection_index = ctx->tls_ctx_idx;
  app_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_TLS, ctx->tcp_is_ip4);
  if (session_alloc_fifos (sm, app_session))
    goto failed;

  ctx->app_session_handle = session_handle (app_session);
  ctx->c_s_index = app_session->session_index;
  app_session->session_state = SESSION_STATE_READY;
  if (cb_fn (ctx->parent_app_index, ctx->parent_app_api_context,
	     app_session, 0 /* not failed */ ))
    {
      TLS_DBG (1, "failed to notify app");
      tls_disconnect (ctx->tls_ctx_idx, vlib_get_thread_index ());
    }

  return 0;

failed:
  return cb_fn (ctx->parent_app_index, ctx->parent_app_api_context, 0,
		1 /* failed */ );
}

static int
tls_handshake_rx (tls_ctx_t * ctx)
{
  u32 flags;
  int rv;
  while (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&ctx->ssl);
      if (rv != 0)
	break;
    }
  TLS_DBG (2, "tls state for %u is %u", tls_ctx_index (ctx), ctx->ssl.state);

  if (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    return 0;

  /*
   * Handshake complete
   */
  if (ctx->ssl.conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
    {
      /*
       * Verify server certificate
       */
      if ((flags = mbedtls_ssl_get_verify_result (&ctx->ssl)) != 0)
	{
	  char buf[512];
	  TLS_DBG (1, " failed\n");
	  mbedtls_x509_crt_verify_info (buf, sizeof (buf), "  ! ", flags);
	  TLS_DBG (1, "%s\n", buf);

	  /* For testing purposes not enforcing this */
	  /* tls_disconnect (tls_ctx_index (ctx), vlib_get_thread_index ());
	     return -1;
	   */
	}
      tls_notify_app_connected (ctx);
    }
  else
    {
      tls_notify_app_accept (ctx);
    }

  TLS_DBG (1, "Handshake for %u complete. TLS cipher is %x",
	   tls_ctx_index (ctx), ctx->ssl.session->ciphersuite);
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
  ctx->is_passive_close = 1;
  app = application_get (ctx->parent_app_index);
  app_session = session_get_from_handle (ctx->app_session_handle);
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
  ctx->c_thread_index = vlib_get_thread_index ();
  ctx->tls_ctx_idx = ctx_index;
  tls_session->session_state = SESSION_STATE_READY;
  tls_session->opaque = ctx_index;
  ctx->tls_session_handle = session_handle (tls_session);
  ctx->listener_ctx_index = tls_listener->opaque;

  TLS_DBG (1, "Accept on listener %u new connection [%u]%u",
	   tls_listener->opaque, vlib_get_thread_index (), ctx_index);

  return tls_ctx_init_server (ctx);
}

int
tls_app_tx_callback (stream_session_t * app_session)
{
  stream_session_t *tls_session;
  tls_ctx_t *ctx;
  static u8 *tmp_buf;
  u32 enq_max, deq_max, deq_now;
  int wrote;

  ctx = tls_ctx_get (app_session->connection_index);
  if (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    tls_add_vpp_q_evt (app_session->server_tx_fifo, FIFO_EVENT_APP_TX);

  deq_max = svm_fifo_max_dequeue (app_session->server_tx_fifo);
  if (!deq_max)
    return 0;

  tls_session = session_get_from_handle (ctx->tls_session_handle);
  enq_max = svm_fifo_max_enqueue (tls_session->server_tx_fifo);
  deq_now = clib_min (deq_max, TLS_CHUNK_SIZE);

  if (PREDICT_FALSE (enq_max == 0))
    {
      tls_add_vpp_q_evt (app_session->server_tx_fifo, FIFO_EVENT_APP_TX);
      return 0;
    }

  vec_validate (tmp_buf, deq_now);
  svm_fifo_peek (app_session->server_tx_fifo, 0, deq_now, tmp_buf);
  wrote = mbedtls_ssl_write (&ctx->ssl, tmp_buf, deq_now);
  if (wrote <= 0)
    {
      tls_add_vpp_q_evt (app_session->server_tx_fifo, FIFO_EVENT_APP_TX);
      return 0;
    }

  svm_fifo_dequeue_drop (app_session->server_tx_fifo, wrote);
  vec_reset_length (tmp_buf);

  tls_add_vpp_q_evt (tls_session->server_tx_fifo, FIFO_EVENT_APP_TX);

  if (deq_now < deq_max)
    tls_add_vpp_q_evt (app_session->server_tx_fifo, FIFO_EVENT_APP_TX);

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
  int read, enq;

  ctx = tls_ctx_get (tls_session->opaque);
  if (ctx->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    return tls_handshake_rx (ctx);

  deq_max = svm_fifo_max_dequeue (tls_session->server_rx_fifo);
  if (!deq_max)
    return 0;

  app_session = session_get_from_handle (ctx->app_session_handle);
  enq_max = svm_fifo_max_enqueue (app_session->server_rx_fifo);
  enq_now = clib_min (enq_max, TLS_CHUNK_SIZE);

  if (PREDICT_FALSE (enq_now == 0))
    {
      tls_add_vpp_q_evt (tls_session->server_rx_fifo, FIFO_EVENT_BUILTIN_RX);
      return 0;
    }

  vec_validate (tmp_buf, enq_now);
  read = mbedtls_ssl_read (&ctx->ssl, tmp_buf, enq_now);
  if (read <= 0)
    {
      tls_add_vpp_q_evt (tls_session->server_rx_fifo, FIFO_EVENT_BUILTIN_RX);
      return 0;
    }

  enq = svm_fifo_enqueue_nowait (app_session->server_rx_fifo, read, tmp_buf);
  ASSERT (enq == read);
  vec_reset_length (tmp_buf);

  if (svm_fifo_max_dequeue (tls_session->server_rx_fifo))
    tls_add_vpp_q_evt (tls_session->server_rx_fifo, FIFO_EVENT_BUILTIN_RX);

  app = application_get_if_valid (app_session->app_index);
  return tls_add_app_q_evt (app, app_session);
}

int
tls_session_connected_callback (u32 tls_app_index, u32 ho_ctx_index,
				stream_session_t * tls_session, u8 is_fail)
{
  int (*cb_fn) (u32, u32, stream_session_t *, u8);
  application_t *app;
  tls_ctx_t *ho_ctx, *ctx;
  u32 ctx_index;

  ho_ctx = tls_ctx_half_open_get (ho_ctx_index);
  app = application_get (ho_ctx->parent_app_index);
  cb_fn = app->cb_fns.session_connected_callback;

  if (is_fail)
    {
      tls_ctx_half_open_reader_unlock ();
      tls_ctx_half_open_free (ho_ctx_index);
      return cb_fn (ho_ctx->parent_app_index, ho_ctx->c_s_index, 0,
		    1 /* failed */ );
    }

  ctx_index = tls_ctx_alloc ();
  ctx = tls_ctx_get (ctx_index);
  clib_memcpy (ctx, ho_ctx, sizeof (*ctx));
  tls_ctx_half_open_reader_unlock ();
  tls_ctx_half_open_free (ho_ctx_index);

  ctx->c_thread_index = vlib_get_thread_index ();
  ctx->tls_ctx_idx = ctx_index;

  TLS_DBG (1, "TCP connect for %u returned %u. New connection [%u]%u",
	   ho_ctx_index, is_fail, vlib_get_thread_index (),
	   (ctx) ? ctx_index : ~0);

  ctx->tls_session_handle = session_handle (tls_session);
  tls_session->opaque = ctx_index;
  tls_session->session_state = SESSION_STATE_READY;

  return tls_ctx_init_client (ctx);
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
tls_connect (transport_endpoint_t * tep)
{
  session_endpoint_extended_t *sep;
  session_endpoint_t tls_sep;
  tls_main_t *tm = &tls_main;
  application_t *app;
  tls_ctx_t *ctx;
  u32 ctx_index;
  int rv;

  sep = (session_endpoint_extended_t *) tep;

  ctx_index = tls_ctx_half_open_alloc ();
  ctx = tls_ctx_half_open_get (ctx_index);
  ctx->parent_app_index = sep->app_index;
  ctx->parent_app_api_context = sep->opaque;
  ctx->tcp_is_ip4 = sep->is_ip4;
  tls_ctx_half_open_reader_unlock ();

  app = application_get (sep->app_index);
  application_alloc_connects_segment_manager (app);

  clib_memcpy (&tls_sep, sep, sizeof (tls_sep));
  tls_sep.transport_proto = TRANSPORT_PROTO_TCP;
  if ((rv = application_connect (tm->app_index, ctx_index, &tls_sep)))
    return rv;

  TLS_DBG (1, "New connect request %u", ctx_index);
  return 0;
}

void
tls_disconnect (u32 ctx_index, u32 thread_index)
{
  stream_session_t *tls_session, *app_session;
  tls_ctx_t *ctx;

  TLS_DBG (1, "Disconnecting %u", ctx_index);

  ctx = tls_ctx_get (ctx_index);
  if (ctx->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER && !ctx->is_passive_close)
    mbedtls_ssl_close_notify (&ctx->ssl);

  tls_session = session_get_from_handle (ctx->tls_session_handle);
  stream_session_disconnect (tls_session);

  app_session = session_get_from_handle_if_valid (ctx->app_session_handle);
  if (app_session)
    {
      segment_manager_dealloc_fifos (app_session->svm_segment_index,
				     app_session->server_rx_fifo,
				     app_session->server_tx_fifo);
      session_free (app_session);
    }
  if (ctx->ssl.conf->endpoint == MBEDTLS_SSL_IS_SERVER)
    {
      mbedtls_x509_crt_free (&ctx->srvcert);
      mbedtls_pk_free (&ctx->pkey);
    }
  mbedtls_ssl_free (&ctx->ssl);
  mbedtls_ssl_config_free (&ctx->conf);
  tls_ctx_free (ctx);
}

u32
tls_start_listen (u32 app_listener_index, transport_endpoint_t * tep)
{
  tls_main_t *tm = &tls_main;
  application_t *tls_app;
  session_handle_t tls_handle;
  session_endpoint_extended_t *sep;
  stream_session_t *tls_listener;
  tls_ctx_t *lctx;
  u32 lctx_index;
  session_type_t st;
  stream_session_t *app_listener;

  sep = (session_endpoint_extended_t *) tep;
  lctx_index = tls_listener_ctx_alloc ();
  lctx = tls_listener_ctx_get (lctx_index);
  st = session_type_from_proto_and_ip (sep->transport_proto, sep->is_ip4);
  app_listener = listen_session_get (st, app_listener_index);

  tls_app = application_get (tm->app_index);
  sep->transport_proto = TRANSPORT_PROTO_TCP;
  if (application_start_listen (tls_app, (session_endpoint_t *) sep,
				&tls_handle))
    return ~0;

  tls_listener = listen_session_get_from_handle (tls_handle);
  tls_listener->opaque = lctx_index;
  lctx->parent_app_index = sep->app_index;
  lctx->tls_session_handle = tls_handle;
  lctx->app_session_handle = listen_session_get_handle (app_listener);
  lctx->tcp_is_ip4 = sep->is_ip4;
  return lctx_index;
}

u32
tls_stop_listen (u32 lctx_index)
{
  tls_main_t *tm = &tls_main;
  application_t *tls_app;
  tls_ctx_t *lctx;
  lctx = tls_listener_ctx_get (lctx_index);
  tls_app = application_get (tm->app_index);
  application_stop_listen (tls_app, lctx->tls_session_handle);
  tls_listener_ctx_free (lctx);
  return 0;
}

transport_connection_t *
tls_connection_get (u32 ctx_index, u32 thread_index)
{
  tls_ctx_t *ctx;
  ctx = tls_ctx_get_w_thread (ctx_index, thread_index);
  return &ctx->connection;
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
  tls_ctx_t *ctx = va_arg (*args, tls_ctx_t *);
  u32 thread_index = va_arg (*args, u32);
  u32 child_si, child_ti;

  session_parse_handle (ctx->tls_session_handle, &child_si, &child_ti);
  if (thread_index != child_ti)
    clib_warning ("app and tls sessions are on different threads!");

  s = format (s, "[#%d][TLS] app %u child %u", child_ti,
	      ctx->parent_app_index, child_si);
  return s;
}

u8 *
format_tls_connection (u8 * s, va_list * args)
{
  u32 ctx_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  tls_ctx_t *ctx;

  ctx = tls_ctx_get_w_thread (ctx_index, thread_index);
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

u8 *
format_tls_listener (u8 * s, va_list * args)
{
  u32 tc_index = va_arg (*args, u32);
  tls_ctx_t *ctx = tls_listener_ctx_get (tc_index);
  u32 listener_index, type;

  listen_session_parse_handle (ctx->tls_session_handle, &type,
			       &listener_index);
  return format (s, "[TLS] listener app %u child %u", ctx->parent_app_index,
		 listener_index);
}

u8 *
format_tls_half_open (u8 * s, va_list * args)
{
  u32 tc_index = va_arg (*args, u32);
  tls_ctx_t *ctx = tls_ctx_half_open_get (tc_index);
  s = format (s, "[TLS] half-open app %u", ctx->parent_app_index);
  tls_ctx_half_open_reader_unlock ();
  return s;
}

/* *INDENT-OFF* */
const static transport_proto_vft_t tls_proto = {
  .open = tls_connect,
  .close = tls_disconnect,
  .bind = tls_start_listen,
  .get_connection = tls_connection_get,
  .get_listener = tls_listener_get,
  .unbind = tls_stop_listen,
  .tx_type = TRANSPORT_TX_INTERNAL,
  .service_type = TRANSPORT_SERVICE_APP,
  .format_connection = format_tls_connection,
  .format_half_open = format_tls_half_open,
  .format_listener = format_tls_listener,
};
/* *INDENT-ON* */

int
tls_init_mem (void)
{
#if TLS_USE_OUR_MEM_FUNCS
  mbedtls_platform_set_calloc_free (mbedtls_calloc_fn, mbedtls_free_fn);
#endif
  return 0;
}

int
tls_init_ca_chain (void)
{
  tls_main_t *tm = &tls_main;
  int rv;

  /* TODO config */
  mbedtls_x509_crt_init (&tm->cacert);
  rv = mbedtls_x509_crt_parse (&tm->cacert,
			       (const unsigned char *) mbedtls_test_cas_pem,
			       mbedtls_test_cas_pem_len);
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
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  u32 fifo_size = 64 << 10, num_threads;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  u32 segment_size = 512 << 20;
  tls_main_t *tm = &tls_main;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  if (tls_init_mem ())
    {
      clib_warning ("failed to initialize mem");
      return clib_error_return (0, "failed to initalize mem");
    }
  if (tls_init_ca_chain ())
    {
      clib_warning ("failed to initialize TLS CA chain");
      return clib_error_return (0, "failed to initalize TLS CA chain");
    }
  if (tls_init_ctr_drbgs_and_entropy (num_threads))
    {
      clib_warning ("failed to initialize entropy and random generators");
      return clib_error_return (0, "failed to initialize entropy and random "
				"generators");
    }

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->session_cb_vft = &tls_app_cb_vft;
  a->api_client_index = (1 << 24) + 1;
  a->options = options;
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach tls app");
      return clib_error_return (0, "failed to attach tls app");
    }

  tm->app_index = a->app_index;
  vec_validate (tm->ctx_pool, num_threads - 1);
  clib_rwlock_init (&tm->half_open_rwlock);

  transport_register_protocol (TRANSPORT_PROTO_TLS, &tls_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_TLS, &tls_proto,
			       FIB_PROTOCOL_IP6, ~0);

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
