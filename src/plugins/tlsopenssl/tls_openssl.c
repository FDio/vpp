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

#include <openssl/ssl.h>
#include <openssl/ssl/statem/statem.h>
#include <openssl/conf.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/tls/tls.h>

typedef struct tls_ctx_openssl_
{
  tls_ctx_t ctx;			/**< First */
  SSL_CTX ssl_ctx;
  SSL *ssl;
  BIO *rbio;
  BIO *wbio;

} openssl_ctx_t;

typedef struct openssl_main_
{
  openssl_ctx_t ***ctx_pool;
  u8 **rx_bufs;
  u8 **tx_bufs;

  mbedtls_x509_crt cacert;
} openssl_main_t;

static openssl_main_t openssl_main;

u32
openssl_ctx_alloc (void)
{
  u8 thread_index = vlib_get_thread_index ();
  openssl_main_t *tm = &openssl_main;
  openssl_ctx_t **ctx;

  pool_get (tm->ctx_pool[thread_index], ctx);
  if (!(*ctx))
    *ctx = clib_mem_alloc (sizeof (openssl_ctx_t));

  memset (*ctx, 0, sizeof (openssl_ctx_t));
  (*ctx)->ctx.c_thread_index = thread_index;
  return ctx - tm->ctx_pool[thread_index];
}

void
openssl_ctx_free (tls_ctx_t * ctx)
{
  openssl_ctx_t *mc = (openssl_ctx_t *) ctx;

  if (mc->ssl_ctx.state == MBEDTLS_SSL_HANDSHAKE_OVER && !ctx->is_passive_close)
    mbedtls_ssl_close_notify (&mc->ssl_ctx);
  if (mc->ssl_ctx.conf->endpoint == MBEDTLS_SSL_IS_SERVER)
    {
      mbedtls_x509_crt_free (&mc->srvcert);
      mbedtls_pk_free (&mc->pkey);
    }
  mbedtls_ssl_free (&mc->ssl_ctx);
  mbedtls_ssl_config_free (&mc->conf);

  pool_put_index (openssl_main.ctx_pool[vlib_get_thread_index ()],
		  ctx->tls_ctx_idx);
}

tls_ctx_t *
openssl_ctx_get (u32 ctx_index)
{
  openssl_ctx_t **ctx;
  ctx = pool_elt_at_index (openssl_main.ctx_pool[vlib_get_thread_index ()],
			   ctx_index);
  return &(*ctx)->ctx;
}

tls_ctx_t *
openssl_ctx_get_w_thread (u32 ctx_index, u8 thread_index)
{
  openssl_ctx_t **ctx;
  ctx = pool_elt_at_index (openssl_main.ctx_pool[thread_index], ctx_index);
  return &(*ctx)->ctx;
}

static int
tls_fifo_send (svm_fifo_t *tls_tx_fifo, u8 *buf, u32 len)
{
  int rv;

  rv = svm_fifo_enqueue_nowait (tls_tx_fifo, len, buf);
  if (rv < 0)
    return rv;
  tls_add_vpp_q_evt (tls_tx_fifo, FIFO_EVENT_APP_TX);
  return rv;
}

static int
tls_fifo_recv (svm_fifo_t *tls_rx_fifo, unsigned char *buf, size_t len)
{
  int rv;

  rv = svm_fifo_dequeue_nowait (tls_rx_fifo, len, buf);
  return (rv < 0) ? 0 : rv;
}

static int
openssl_ctx_write (tls_ctx_t * ctx, svm_fifo_t *app_tx_fifo,
                   svm_fifo_t *tls_tx_fifo)
{
  u8 thread_index = vlib_get_thread_index ();
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  openssl_main_t *om = &openssl_main;
  int wrote = 0, read, pending, sent;
  u32 enq_max, deq_max, deq_now;

  deq_max = svm_fifo_max_dequeue (app_tx_fifo);
  if (!deq_max)
    goto check_pending;

  if (ossl_statem_get_in_handshake (oc->ssl))
    {
      tls_add_vpp_q_evt (app_tx_fifo, FIFO_EVENT_APP_TX);
      goto check_pending;
    }

  enq_max = svm_fifo_max_enqueue (tls_tx_fifo);
  deq_now = clib_min (deq_max, TLS_CHUNK_SIZE);

  if (PREDICT_FALSE (enq_max == 0))
    {
      tls_add_vpp_q_evt (app_tx_fifo, FIFO_EVENT_APP_TX);
      goto check_pending;
    }

  vec_validate (om->tx_bufs[thread_index], deq_now);
  svm_fifo_peek (app_tx_fifo, 0, deq_now,
                 om->tx_bufs[thread_index]);

  wrote = SSL_write (oc->ssl, om->tx_bufs[thread_index], deq_now);
  if (wrote <= 0)
    {
      tls_add_vpp_q_evt (app_tx_fifo, FIFO_EVENT_APP_TX);
      goto check_pending;
    }

  svm_fifo_dequeue_drop (app_tx_fifo, wrote);
  vec_reset_length (om->tx_bufs[thread_index]);
  tls_add_vpp_q_evt (tls_tx_fifo, FIFO_EVENT_APP_TX);

  if (deq_now < deq_max)
    tls_add_vpp_q_evt (app_tx_fifo, FIFO_EVENT_APP_TX);

check_pending:
  if ((pending = BIO_ctrl_pending (oc->rbio)) > 0)
    {
      read = BIO_read (oc->rbio, om->rx_bufs[thread_index], pending);
      sent = tls_fifo_send (tls_tx_fifo, om->rx_bufs[thread_index], read);
      if (sent < pending)
	tls_add_vpp_q_evt (app_tx_fifo, FIFO_EVENT_APP_TX);
    }
  return wrote;
}

static int
openssl_ctx_read (tls_ctx_t * ctx, svm_fifo_t *tls_rx_fifo,
                  svm_fifo_t *app_rx_fifo)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  openssl_main_t *om = &openssl_main;
  u8 thread_index = ctx->c_thread_index;
  u32 deq_max, enq_max, enq_now, deq_now;
  application_t *app;
  int read, enq = 0, wrote, pending;

  if (SSL_in_init (oc->ssl))
    {
      openssl_ctx_handshake_rx (ctx);
      return 0;
    }

  deq_max = svm_fifo_max_dequeue (tls_rx_fifo);
  enq_max = svm_fifo_max_enqueue (app_rx_fifo);
  enq_now = clib_min (enq_max, TLS_CHUNK_SIZE);

  if (PREDICT_FALSE (enq_now == 0))
    {
      tls_add_vpp_q_evt (tls_rx_fifo, FIFO_EVENT_BUILTIN_RX);
      return 0;
    }

  deq_now = clib_min (deq_max, enq_max);
  if (!deq_now)
    goto check_pending;

  vec_validate (om->rx_bufs[thread_index], deq_now);
  read = tls_fifo_recv (tls_rx_fifo, om->rx_bufs[thread_index], deq_now);
  if (read)
    {
      wrote = BIO_write (oc->wbio, om->rx_bufs[thread_index], read);
      ASSERT (wrote == read);
      vec_reset_length (om->rx_bufs[thread_index]);
      if (read < deq_max)
	tls_add_vpp_q_evt (tls_rx_fifo, FIFO_EVENT_BUILTIN_RX);
    }

check_pending:
  if ((pending = BIO_ctrl_pending (oc->wbio) > 0))
    {
      read = SSL_read (&oc->ssl, om->rx_bufs[thread_index], enq_max);
      enq = svm_fifo_enqueue_nowait (app_rx_fifo, read,
                                     om->rx_bufs[thread_index]);
      if (read < pending)
	tls_add_vpp_q_evt (tls_rx_fifo, FIFO_EVENT_BUILTIN_RX);
    }

  return enq;
}


static int
openssl_ctx_init_client (tls_ctx_t * ctx)
{
  char* PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
  long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  openssl_main_t *mm = &openssl_main;
  const SSL_METHOD* method;
  void *ctx_ptr;
  int rv, err;

  method = SSLv23_method();
  if (method == NULL)
    {
      TLS_DBG ("SSLv23_method returned null");
      return -1;
    }

  ctx = SSL_CTX_new (method);
  if (ctx == NULL)
    {
      TLS_DBG ("SSL_CTX_new returned null");
      return -1;
    }

  SSL_CTX_set_verify (ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify_depth (ctx, 4);
  SSL_CTX_set_options(ctx, flags);

  rv = SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", NULL);
  if (rv != 1)
    {
      TLS_DBG ("Coudln't read CA certificate");
      return -1;
    }

  oc->ssl = SSL_new (ctx);
  if (oc->ssl == NULL) {
      TLS_DBG ("Couldn't initialize ssl struct");
      return -1;
  }

  oc->rbio = BIO_new (BIO_s_mem ());
  oc->wbio = BIO_new (BIO_s_mem ());

  BIO_set_mem_eof_return(oc->rbio, -1);
  BIO_set_mem_eof_return(oc->wbio, -1);

  SSL_set_bio (oc->ssl, oc->wbio, oc->rbio);
  SSL_set_connect_state (oc->ssl);

//  rv = BIO_set_conn_hostname(web, ctx->srv_hostname);
//  if(rv != 1)
//    {
//      TLS_DBG ("Couldn't set hostname");
//      return -1;
//    }

  rv = SSL_set_cipher_list (oc->ssl, (const char *) PREFERRED_CIPHERS);
  if (rv != 1)
    {
      TLS_DBG ("Couldn't set cipher");
      return -1;
    }

  rv = SSL_set_tlsext_host_name (oc->ssl, ctx->srv_hostname);
  if(rv != 1)
    {
      TLS_DBG ("Couldn't set hostname");
      return -1;
    }

  /*
   * 2. Do the first steps in the handshake.
   */
  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   ctx->tls_ctx_idx);

  while (1)
    {
      rv = SSL_do_handshake (oc->ssl);
      err = SSL_get_error (oc->ssl, rv);
      if (err != SSL_ERROR_WANT_WRITE)
	break;
    }

  TLS_DBG (2, "tls state for [%u]%u is su", ctx->c_thread_index,
	   ctx->tls_ctx_idx, SSL_state_string_long (oc->ssl));
  return 0;
}

static int
openssl_ctx_init_server (tls_ctx_t * ctx)
{
  openssl_ctx_t *mc = (openssl_ctx_t *) ctx;
  openssl_main_t *mm = &openssl_main;
  application_t *app;
  void *ctx_ptr;
  int rv;


  method = SSLv23_server_method();

  mc->ctx = SSL_CTX_new(method);
  if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
  }


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

  if ((rv = mbedtls_ssl_setup (&mc->ssl_ctx, &mc->conf)) != 0)
    {
      TLS_DBG (1, " failed\n  ! mbedtls_ssl_setup returned %d", rv);
      goto exit;
    }

  mbedtls_ssl_session_reset (&mc->ssl_ctx);
  ctx_ptr = uword_to_pointer (ctx->tls_ctx_idx, void *);
  mbedtls_ssl_set_bio (&mc->ssl, ctx_ptr, tls_fifo_send, tls_fifo_recv, NULL);
  mbedtls_debug_set_threshold (TLS_DEBUG_LEVEL_SERVER);

  /*
   * 3. Start handshake state machine
   */
  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   ctx->tls_ctx_idx);
  while (mc->ssl_ctx.state != MBEDTLS_SSL_HANDSHAKE_OVER)
    {
      rv = mbedtls_ssl_handshake_step (&mc->ssl_ctx);
      if (rv != 0)
	break;
    }

  TLS_DBG (2, "tls state for [%u]%u is %u", ctx->c_thread_index,
	   ctx->tls_ctx_idx, mc->ssl_ctx.state);
  return 0;

exit:
  return -1;
}

static int
openssl_ctx_handshake_rx (tls_ctx_t * ctx)
{
  openssl_ctx_t *mc = (openssl_ctx_t *) ctx;
  u32 flags;
  int rv, err;
  while (SSL_in_init (mc->ssl))
    {
      rv = SSL_do_handshake (mc->ssl);
      err = SSL_get_error (mc->ssl, rv);
      if (err != SSL_ERROR_WANT_WRITE)
	break;
    }
  TLS_DBG (2, "tls state for %u is %u", ctx->tls_ctx_idx, mc->ssl.state);

  if (SSL_in_init (mc->ssl))
    return HANDSHAKE_NOT_OVER;

  /*
   * Handshake complete
   */
  if (!SSL_is_server (mc->ssl))
    {
      /*
       * Verify server certificate
       */
      if ((rv = SSL_get_verify_result(mc->ssl)) != X509_V_OK)
	{
	  TLS_DBG (1, " failed verify: %s\n",
	           X509_verify_cert_error_string (rv));

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
	   ctx->tls_ctx_idx, mc->ssl_ctx.session->ciphersuite);
  return rv;
}

static u8
openssl_handshake_is_over (tls_ctx_t * ctx)
{
  openssl_ctx_t *mc = (openssl_ctx_t *) ctx;
  return SSL_is_init_finished (mc->ssl);
}

const static tls_engine_vft_t openssl_engine = {
  .ctx_alloc = openssl_ctx_alloc,
  .ctx_free = openssl_ctx_free,
  .ctx_get = openssl_ctx_get,
  .ctx_get_w_thread = openssl_ctx_get_w_thread,
  .ctx_init_server = openssl_ctx_init_server,
  .ctx_init_client = openssl_ctx_init_client,
  .ctx_handshake_rx = openssl_ctx_handshake_rx,
  .ctx_write = openssl_ctx_write,
  .ctx_read = openssl_ctx_read,
  .ctx_handshake_is_over = openssl_handshake_is_over,
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
  openssl_main_t *mm = &openssl_main;
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
  openssl_main_t *mm = &openssl_main;
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
  openssl_main_t *mm = &openssl_main;
  clib_error_t *error;
  u32 num_threads;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  if ((error = vlib_call_init_function (vm, tls_init)))
    return error;

  init_openssl_library();

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
  tls_register_engine (&openssl_engine, TLS_ENGINE_OPENSSL);
  return 0;
}

VLIB_INIT_FUNCTION (tls_mbedtls_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
    .version = VPP_BUILD_VER,
    .description = "openssl based TLS Engine",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
