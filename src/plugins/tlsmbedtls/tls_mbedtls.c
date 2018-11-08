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

#include <mbedtls/ssl.h>
#include <mbedtls/certs.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/timing.h>
#include <mbedtls/debug.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/tls/tls.h>

#define TLS_USE_OUR_MEM_FUNCS	0

typedef struct tls_ctx_mbedtls_
{
  tls_ctx_t ctx;			/**< First */
  u32 mbedtls_ctx_index;
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config conf;
  mbedtls_x509_crt srvcert;
  mbedtls_pk_context pkey;
} mbedtls_ctx_t;

typedef struct mbedtls_main_
{
  mbedtls_ctx_t ***ctx_pool;
  mbedtls_ctr_drbg_context *ctr_drbgs;
  mbedtls_entropy_context *entropy_pools;
  mbedtls_x509_crt cacert;
  u8 **rx_bufs;
  u8 **tx_bufs;
} mbedtls_main_t;

static mbedtls_main_t mbedtls_main;

#if TLS_USE_OUR_MEM_FUNCS
#include <mbedtls/platform.h>

void *
mbedtls_calloc_fn (size_t n, size_t size)
{
  void *ptr;
  ptr = clib_mem_alloc (n * size);
  clib_memset (ptr, 0, sizeof (*ptr));
  return ptr;
}

void
mbedtls_free_fn (void *ptr)
{
  if (ptr)
    clib_mem_free (ptr);
}
#endif

static u32
mbedtls_ctx_alloc (void)
{
  u8 thread_index = vlib_get_thread_index ();
  mbedtls_main_t *tm = &mbedtls_main;
  mbedtls_ctx_t **ctx;

  pool_get (tm->ctx_pool[thread_index], ctx);
  if (!(*ctx))
    *ctx = clib_mem_alloc (sizeof (mbedtls_ctx_t));

  clib_memset (*ctx, 0, sizeof (mbedtls_ctx_t));
  (*ctx)->ctx.c_thread_index = thread_index;
  (*ctx)->ctx.tls_ctx_engine = TLS_ENGINE_MBEDTLS;
  (*ctx)->mbedtls_ctx_index = ctx - tm->ctx_pool[thread_index];
  return ((*ctx)->mbedtls_ctx_index);
}

static void
mbedtls_ctx_free (tls_ctx_t * ctx)
{
  mbedtls_ctx_t *mc = (mbedtls_ctx_t *) ctx;

  if (mc->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER && !ctx->is_passive_close)
    mbedtls_ssl_close_notify (&mc->ssl);
  if (mc->ssl.conf->endpoint == MBEDTLS_SSL_IS_SERVER)
    {
      mbedtls_x509_crt_free (&mc->srvcert);
      mbedtls_pk_free (&mc->pkey);
    }
  mbedtls_ssl_free (&mc->ssl);
  mbedtls_ssl_config_free (&mc->conf);

  pool_put_index (mbedtls_main.ctx_pool[ctx->c_thread_index],
		  mc->mbedtls_ctx_index);
}

static tls_ctx_t *
mbedtls_ctx_get (u32 ctx_index)
{
  mbedtls_ctx_t **ctx;
  ctx = pool_elt_at_index (mbedtls_main.ctx_pool[vlib_get_thread_index ()],
			   ctx_index);
  return &(*ctx)->ctx;
}

static tls_ctx_t *
mbedtls_ctx_get_w_thread (u32 ctx_index, u8 thread_index)
{
  mbedtls_ctx_t **ctx;
  ctx = pool_elt_at_index (mbedtls_main.ctx_pool[thread_index], ctx_index);
  return &(*ctx)->ctx;
}

static int
tls_init_ctr_seed_drbgs (void)
{
  u32 thread_index = vlib_get_thread_index ();
  mbedtls_main_t *tm = &mbedtls_main;
  u8 *pers;
  int rv;
  pers = format (0, "vpp thread %u", thread_index);

  mbedtls_entropy_init (&tm->entropy_pools[thread_index]);
  mbedtls_ctr_drbg_init (&mbedtls_main.ctr_drbgs[thread_index]);
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
  if (PREDICT_FALSE (!mbedtls_main.ctr_drbgs[thread_index].f_entropy))
    tls_init_ctr_seed_drbgs ();
  return &mbedtls_main.ctr_drbgs[thread_index];
}

static int
tls_net_send (void *ctx_indexp, const unsigned char *buf, size_t len)
{
  stream_session_t *tls_session;
  uword ctx_index;
  tls_ctx_t *ctx;
  int rv;

  ctx_index = pointer_to_uword (ctx_indexp);
  ctx = mbedtls_ctx_get (ctx_index);
  tls_session = session_get_from_handle (ctx->tls_session_handle);
  rv = svm_fifo_enqueue_nowait (tls_session->server_tx_fifo, len, buf);
  if (rv < 0)
    return MBEDTLS_ERR_SSL_WANT_WRITE;
  tls_add_vpp_q_tx_evt (tls_session);
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
  ctx = mbedtls_ctx_get (ctx_index);
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
mbedtls_ctx_init_client (tls_ctx_t * ctx)
{
  mbedtls_ctx_t *mc = (mbedtls_ctx_t *) ctx;
  mbedtls_main_t *mm = &mbedtls_main;
  void *ctx_ptr;
  int rv;

  /*
   * 1. Setup SSL
   */
  mbedtls_ssl_init (&mc->ssl);
  mbedtls_ssl_config_init (&mc->conf);
  if ((rv = mbedtls_ssl_config_defaults (&mc->conf, MBEDTLS_SSL_IS_CLIENT,
					 MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
      TLS_DBG (1, "failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n",
	       rv);
      return -1;
    }

  mbedtls_ssl_conf_authmode (&mc->conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
  mbedtls_ssl_conf_ca_chain (&mc->conf, &mm->cacert, NULL);
  mbedtls_ssl_conf_rng (&mc->conf, mbedtls_ctr_drbg_random,
			tls_get_ctr_drbg ());
  mbedtls_ssl_conf_dbg (&mc->conf, mbedtls_debug, stdout);

  if ((rv = mbedtls_ssl_setup (&mc->ssl, &mc->conf)) != 0)
    {
      TLS_DBG (1, "failed\n  ! mbedtls_ssl_setup returned %d\n", rv);
      return -1;
    }

  if ((rv = mbedtls_ssl_set_hostname (&mc->ssl,
				      (const char *) ctx->srv_hostname)) != 0)
    {
      TLS_DBG (1, "failed\n  ! mbedtls_ssl_set_hostname returned %d\n", rv);
      return -1;
    }

  ctx_ptr = uword_to_pointer (mc->mbedtls_ctx_index, void *);
  mbedtls_ssl_set_bio (&mc->ssl, ctx_ptr, tls_net_send, tls_net_recv, NULL);
  mbedtls_debug_set_threshold (TLS_DEBUG_LEVEL_CLIENT);

  /*
   * 2. Do the first 2 steps in the handshake.
   */
  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   mc->mbedtls_ctx_index);
  while (mc->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&mc->ssl);
      if (rv != 0)
	break;
    }
  TLS_DBG (2, "tls state for [%u]%u is %u", ctx->c_thread_index,
	   mc->mbedtls_ctx_index, mc->ssl.state);
  return 0;
}

static int
mbedtls_start_listen (tls_ctx_t * lctx)
{
  return 0;
}

static int
mbedtls_stop_listen (tls_ctx_t * lctx)
{
  return 0;
}

static int
mbedtls_ctx_init_server (tls_ctx_t * ctx)
{
  mbedtls_ctx_t *mc = (mbedtls_ctx_t *) ctx;
  mbedtls_main_t *mm = &mbedtls_main;
  application_t *app;
  void *ctx_ptr;
  int rv;

  mbedtls_ssl_init (&mc->ssl);
  mbedtls_ssl_config_init (&mc->conf);
  mbedtls_x509_crt_init (&mc->srvcert);
  mbedtls_pk_init (&mc->pkey);

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

  rv = mbedtls_x509_crt_parse (&mc->srvcert,
			       (const unsigned char *) app->tls_cert,
			       vec_len (app->tls_cert));
  if (rv != 0)
    {
      TLS_DBG (1, " failed\n  !  mbedtls_x509_crt_parse returned %d", rv);
      goto exit;
    }

  rv = mbedtls_pk_parse_key (&mc->pkey,
			     (const unsigned char *) app->tls_key,
			     vec_len (app->tls_key), NULL, 0);
  if (rv != 0)
    {
      TLS_DBG (1, " failed\n  !  mbedtls_pk_parse_key returned %d", rv);
      goto exit;
    }

  /*
   * 2. SSL context config
   */
  if ((rv = mbedtls_ssl_config_defaults (&mc->conf, MBEDTLS_SSL_IS_SERVER,
					 MBEDTLS_SSL_TRANSPORT_STREAM,
					 MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
      TLS_DBG (1, " failed\n  ! mbedtls_ssl_config_defaults returned %d", rv);
      goto exit;
    }

  mbedtls_ssl_conf_rng (&mc->conf, mbedtls_ctr_drbg_random,
			tls_get_ctr_drbg ());
  mbedtls_ssl_conf_dbg (&mc->conf, mbedtls_debug, stdout);

  /* TODO CACHE
     mbedtls_ssl_conf_session_cache( &ctx->conf, &cache,
     mbedtls_ssl_cache_get,
     mbedtls_ssl_cache_set );
   */

  mbedtls_ssl_conf_ca_chain (&mc->conf, &mm->cacert, NULL);
  if ((rv = mbedtls_ssl_conf_own_cert (&mc->conf, &mc->srvcert, &mc->pkey))
      != 0)
    {
      TLS_DBG (1, " failed\n  ! mbedtls_ssl_conf_own_cert returned %d", rv);
      goto exit;
    }

  if ((rv = mbedtls_ssl_setup (&mc->ssl, &mc->conf)) != 0)
    {
      TLS_DBG (1, " failed\n  ! mbedtls_ssl_setup returned %d", rv);
      goto exit;
    }

  mbedtls_ssl_session_reset (&mc->ssl);
  ctx_ptr = uword_to_pointer (mc->mbedtls_ctx_index, void *);
  mbedtls_ssl_set_bio (&mc->ssl, ctx_ptr, tls_net_send, tls_net_recv, NULL);
  mbedtls_debug_set_threshold (TLS_DEBUG_LEVEL_SERVER);

  /*
   * 3. Start handshake state machine
   */
  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   mc->mbedtls_ctx_index);
  while (mc->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&mc->ssl);
      if (rv != 0)
	break;
    }

  TLS_DBG (2, "tls state for [%u]%u is %u", ctx->c_thread_index,
	   mc->mbedtls_ctx_index, mc->ssl.state);
  return 0;

exit:
  return -1;
}

static int
mbedtls_ctx_handshake_rx (tls_ctx_t * ctx)
{
  mbedtls_ctx_t *mc = (mbedtls_ctx_t *) ctx;
  u32 flags;
  int rv;
  while (mc->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&mc->ssl);
      if (rv != 0)
	break;
    }
  TLS_DBG (2, "tls state for %u is %u", mc->mbedtls_ctx_index, mc->ssl.state);

  if (mc->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    return 0;

  /*
   * Handshake complete
   */
  if (mc->ssl.conf->endpoint == MBEDTLS_SSL_IS_CLIENT)
    {
      /*
       * Verify server certificate
       */
      if ((flags = mbedtls_ssl_get_verify_result (&mc->ssl)) != 0)
	{
	  char buf[512];
	  TLS_DBG (1, " failed\n");
	  mbedtls_x509_crt_verify_info (buf, sizeof (buf), "  ! ", flags);
	  TLS_DBG (1, "%s\n", buf);

	  /*
	   * Presence of hostname enforces strict certificate verification
	   */
	  if (ctx->srv_hostname)
	    {
	      tls_notify_app_connected (ctx, /* is failed */ 0);
	      return -1;
	    }
	}
      tls_notify_app_connected (ctx, /* is failed */ 0);
    }
  else
    {
      tls_notify_app_accept (ctx);
    }

  TLS_DBG (1, "Handshake for %u complete. TLS cipher is %x",
	   mc->mbedtls_ctx_index, mc->ssl.session->ciphersuite);
  return 0;
}

static int
mbedtls_ctx_write (tls_ctx_t * ctx, stream_session_t * app_session)
{
  mbedtls_ctx_t *mc = (mbedtls_ctx_t *) ctx;
  u8 thread_index = ctx->c_thread_index;
  mbedtls_main_t *mm = &mbedtls_main;
  u32 enq_max, deq_max, deq_now;
  stream_session_t *tls_session;
  int wrote;

  ASSERT (mc->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER);

  deq_max = svm_fifo_max_dequeue (app_session->server_tx_fifo);
  if (!deq_max)
    return 0;

  tls_session = session_get_from_handle (ctx->tls_session_handle);
  enq_max = svm_fifo_max_enqueue (tls_session->server_tx_fifo);
  deq_now = clib_min (deq_max, TLS_CHUNK_SIZE);

  if (PREDICT_FALSE (enq_max == 0))
    {
      tls_add_vpp_q_builtin_tx_evt (app_session);
      return 0;
    }

  vec_validate (mm->tx_bufs[thread_index], deq_now);
  svm_fifo_peek (app_session->server_tx_fifo, 0, deq_now,
		 mm->tx_bufs[thread_index]);

  wrote = mbedtls_ssl_write (&mc->ssl, mm->tx_bufs[thread_index], deq_now);
  if (wrote <= 0)
    {
      tls_add_vpp_q_builtin_tx_evt (app_session);
      return 0;
    }

  svm_fifo_dequeue_drop (app_session->server_tx_fifo, wrote);
  vec_reset_length (mm->tx_bufs[thread_index]);
  tls_add_vpp_q_tx_evt (tls_session);

  if (deq_now < deq_max)
    tls_add_vpp_q_builtin_tx_evt (app_session);

  return 0;
}

static int
mbedtls_ctx_read (tls_ctx_t * ctx, stream_session_t * tls_session)
{
  mbedtls_ctx_t *mc = (mbedtls_ctx_t *) ctx;
  mbedtls_main_t *mm = &mbedtls_main;
  u8 thread_index = ctx->c_thread_index;
  u32 deq_max, enq_max, enq_now;
  stream_session_t *app_session;
  int read, enq;

  if (PREDICT_FALSE (mc->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER))
    {
      mbedtls_ctx_handshake_rx (ctx);
      return 0;
    }

  deq_max = svm_fifo_max_dequeue (tls_session->server_rx_fifo);
  if (!deq_max)
    return 0;

  app_session = session_get_from_handle (ctx->app_session_handle);
  enq_max = svm_fifo_max_enqueue (app_session->server_rx_fifo);
  enq_now = clib_min (enq_max, TLS_CHUNK_SIZE);

  if (PREDICT_FALSE (enq_now == 0))
    {
      tls_add_vpp_q_builtin_rx_evt (tls_session);
      return 0;
    }

  vec_validate (mm->rx_bufs[thread_index], enq_now);
  read = mbedtls_ssl_read (&mc->ssl, mm->rx_bufs[thread_index], enq_now);
  if (read <= 0)
    {
      tls_add_vpp_q_builtin_rx_evt (tls_session);
      return 0;
    }

  enq = svm_fifo_enqueue_nowait (app_session->server_rx_fifo, read,
				 mm->rx_bufs[thread_index]);
  ASSERT (enq == read);
  vec_reset_length (mm->rx_bufs[thread_index]);

  if (svm_fifo_max_dequeue (tls_session->server_rx_fifo))
    tls_add_vpp_q_builtin_rx_evt (tls_session);

  if (enq > 0)
    tls_notify_app_enqueue (ctx, app_session);

  return enq;
}

static u8
mbedtls_handshake_is_over (tls_ctx_t * ctx)
{
  mbedtls_ctx_t *mc = (mbedtls_ctx_t *) ctx;
  return (mc->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER);
}

const static tls_engine_vft_t mbedtls_engine = {
  .ctx_alloc = mbedtls_ctx_alloc,
  .ctx_free = mbedtls_ctx_free,
  .ctx_get = mbedtls_ctx_get,
  .ctx_get_w_thread = mbedtls_ctx_get_w_thread,
  .ctx_init_server = mbedtls_ctx_init_server,
  .ctx_init_client = mbedtls_ctx_init_client,
  .ctx_write = mbedtls_ctx_write,
  .ctx_read = mbedtls_ctx_read,
  .ctx_handshake_is_over = mbedtls_handshake_is_over,
  .ctx_start_listen = mbedtls_start_listen,
  .ctx_stop_listen = mbedtls_stop_listen,
};

int
tls_init_mem (void)
{
#if TLS_USE_OUR_MEM_FUNCS
  mbedtls_platform_set_calloc_free (mbedtls_calloc_fn, mbedtls_free_fn);
#endif
  return 0;
}

static int
tls_init_ctr_drbgs_and_entropy (u32 num_threads)
{
  mbedtls_main_t *mm = &mbedtls_main;
  int i;

  vec_validate (mm->ctr_drbgs, num_threads - 1);
  vec_validate (mm->entropy_pools, num_threads - 1);
  for (i = 0; i < num_threads; i++)
    mm->ctr_drbgs[i].f_entropy = 0;

  return 0;
}

int
tls_init_ca_chain (void)
{
  mbedtls_main_t *mm = &mbedtls_main;
  tls_main_t *tm = vnet_tls_get_main ();
  int rv;

  if (access (tm->ca_cert_path, F_OK | R_OK) == -1)
    {
      clib_warning ("Could not initialize TLS CA certificates");
      return -1;
    }

  mbedtls_x509_crt_init (&mm->cacert);
  rv = mbedtls_x509_crt_parse_file (&mm->cacert, tm->ca_cert_path);
  if (rv < 0)
    {
      clib_warning ("Couldn't parse system CA certificates: -0x%x", -rv);
    }
  if (tm->use_test_cert_in_ca)
    {
      rv = mbedtls_x509_crt_parse (&mm->cacert,
				   (const unsigned char *) test_srv_crt_rsa,
				   test_srv_crt_rsa_len);
      if (rv < 0)
	{
	  clib_warning ("Couldn't parse test certificate: -0x%x", -rv);
	  return -1;
	}
    }
  return (rv < 0 ? -1 : 0);
}

static clib_error_t *
tls_mbedtls_init (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  mbedtls_main_t *mm = &mbedtls_main;
  clib_error_t *error;
  u32 num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  if ((error = vlib_call_init_function (vm, tls_init)))
    return error;

  if (tls_init_ca_chain ())
    {
      clib_warning ("failed to initialize TLS CA chain");
      return 0;
    }
  if (tls_init_mem ())
    {
      clib_warning ("failed to initialize mem");
      return 0;
    }
  if (tls_init_ctr_drbgs_and_entropy (num_threads))
    {
      clib_warning ("failed to initialize entropy and random generators");
      return 0;
    }

  vec_validate (mm->ctx_pool, num_threads - 1);
  vec_validate (mm->rx_bufs, num_threads - 1);
  vec_validate (mm->tx_bufs, num_threads - 1);

  tls_register_engine (&mbedtls_engine, TLS_ENGINE_MBEDTLS);
  return 0;
}

VLIB_INIT_FUNCTION (tls_mbedtls_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "mbedtls based TLS Engine",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
