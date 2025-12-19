/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2018 Cisco and/or its affiliates.
 */

#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#ifdef HAVE_OPENSSL_ASYNC
#include <openssl/async.h>
#endif
#include <dlfcn.h>
#include <vnet/plugin/plugin.h>
#include <vpp/app/version.h>
#include <vnet/tls/tls.h>
#include <ctype.h>
#include <tlsopenssl/tls_openssl.h>
#include <tlsopenssl/tls_bios.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#define MAX_CRYPTO_LEN 64

openssl_main_t openssl_main;

static u32
openssl_ctx_alloc_w_thread (clib_thread_index_t thread_index)
{
  openssl_main_t *om = &openssl_main;
  openssl_ctx_t **ctx;

  pool_get_aligned_safe (om->ctx_pool[thread_index], ctx, 0);

  if (!(*ctx))
    *ctx = clib_mem_alloc (sizeof (openssl_ctx_t));

  clib_memset (*ctx, 0, sizeof (openssl_ctx_t));
  (*ctx)->ctx.c_thread_index = thread_index;
  (*ctx)->ctx.tls_ctx_engine = CRYPTO_ENGINE_OPENSSL;
  (*ctx)->ctx.app_session_handle = SESSION_INVALID_HANDLE;
  (*ctx)->openssl_ctx_index = ctx - om->ctx_pool[thread_index];

  /* Initialize llists for async events */
  if (openssl_main.async)
    tls_async_evts_init_list (&((*ctx)->async_ctx));

  return ((*ctx)->openssl_ctx_index);
}

static u32
openssl_ctx_alloc (void)
{
  return openssl_ctx_alloc_w_thread (vlib_get_thread_index ());
}

static void
openssl_ctx_free (tls_ctx_t * ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;

  /* Cleanup ssl ctx unless migrated */
  if (!(ctx->flags & TLS_CONN_F_MIGRATED))
    {
      if (SSL_is_init_finished (oc->ssl) &&
	  !(ctx->flags & TLS_CONN_F_PASSIVE_CLOSE))
	{
	  int rv = SSL_shutdown (oc->ssl);
	  if (rv < 0)
	    (void) SSL_get_error (oc->ssl, rv);
	}

      if (openssl_main.async)
	tls_async_evts_free_list (ctx);

      SSL_free (oc->ssl);
      vec_free (ctx->srv_hostname);
    }

  pool_put_index (openssl_main.ctx_pool[ctx->c_thread_index],
		  oc->openssl_ctx_index);
}

static void *
openssl_ctx_detach (tls_ctx_t *ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx, *oc_copy;

  oc_copy = clib_mem_alloc (sizeof (*oc_copy));
  clib_memcpy (oc_copy, oc, sizeof (*oc));

  return oc_copy;
}

static u32
openssl_ctx_attach (clib_thread_index_t thread_index, void *ctx_ptr)
{
  openssl_main_t *om = &openssl_main;
  session_handle_t sh;
  openssl_ctx_t **oc;

  pool_get_aligned_safe (om->ctx_pool[thread_index], oc, 0);
  /* Free the old instance instead of looking for an empty spot */
  if (*oc)
    clib_mem_free (*oc);

  *oc = ctx_ptr;
  (*oc)->openssl_ctx_index = oc - om->ctx_pool[thread_index];
  (*oc)->ctx.c_thread_index = thread_index;

  sh = (*oc)->ctx.tls_session_handle;
  BIO_set_data ((*oc)->rbio, uword_to_pointer (sh, void *));
  BIO_set_data ((*oc)->wbio, uword_to_pointer (sh, void *));

  return ((*oc)->openssl_ctx_index);
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

static u32
openssl_listen_ctx_alloc (void)
{
  openssl_main_t *om = &openssl_main;
  openssl_listen_ctx_t *lctx;

  pool_get (om->lctx_pool, lctx);

  clib_memset (lctx, 0, sizeof (openssl_listen_ctx_t));
  lctx->openssl_lctx_index = lctx - om->lctx_pool;
  return lctx->openssl_lctx_index;
}

static void
openssl_listen_ctx_free (openssl_listen_ctx_t * lctx)
{
  pool_put_index (openssl_main.lctx_pool, lctx->openssl_lctx_index);
}

openssl_listen_ctx_t *
openssl_lctx_get (u32 lctx_index)
{
  return pool_elt_at_index (openssl_main.lctx_pool, lctx_index);
}

int
openssl_read_from_ssl_into_fifo (svm_fifo_t *f, tls_ctx_t *ctx, u32 max_len)
{
  int read, rv, n_fs, i;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  const int n_segs = 2;
  svm_fifo_seg_t fs[n_segs];
  u32 max_enq;
  SSL *ssl = oc->ssl;

  max_enq = svm_fifo_max_enqueue_prod (f);
  if (!max_enq)
    return 0;

  max_enq = clib_min (max_len, max_enq);
  n_fs = svm_fifo_provision_chunks (f, fs, n_segs, max_enq);
  if (n_fs < 0)
    return 0;

  /* Return early if we can't read anything */
  read = SSL_read (ssl, fs[0].data, fs[0].len);
  if (read <= 0)
    {
      ossl_check_err_is_fatal (ssl, read);

      if (openssl_main.async && SSL_want_async (oc->ssl))
	{
	  session_t *tls_session =
	    session_get_from_handle (ctx->tls_session_handle);
	  vpp_tls_async_init_event (ctx, tls_async_read_event_handler,
				    tls_session, SSL_ASYNC_EVT_RD, NULL, 0);
	  return 0;
	}
      return 0;
    }

  if (read == (int) fs[0].len)
    {
      for (i = 1; i < n_fs; i++)
	{
	  rv = SSL_read (ssl, fs[i].data, fs[i].len);
	  read += rv > 0 ? rv : 0;

	  if (rv < (int) fs[i].len)
	    {
	      ossl_check_err_is_fatal (ssl, rv);
	      break;
	    }
	}
    }
  svm_fifo_enqueue_nocopy (f, read);

  return read;
}

static int
openssl_write_from_fifo_into_ssl (svm_fifo_t *f, tls_ctx_t *ctx,
				  transport_send_params_t *sp, u32 max_len)
{
  int wrote = 0, rv, i = 0, len;
  u32 n_segs = 2;
  svm_fifo_seg_t fs[n_segs];
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  SSL *ssl = oc->ssl;

  len = svm_fifo_segments (f, 0, fs, &n_segs, max_len);
  if (len <= 0)
    return 0;

  while (wrote < len && i < n_segs)
    {
      rv = SSL_write (ssl, fs[i].data, fs[i].len);
      wrote += (rv > 0) ? rv : 0;

      if (rv < (int) fs[i].len)
	{
	  if (rv < 0)
	    {
	      int err = SSL_get_error (ssl, rv);
	      if (err == SSL_ERROR_SSL)
		return -1;

	      if (err == SSL_ERROR_WANT_WRITE)
		break;
	      if (openssl_main.async &&
		  (err == SSL_ERROR_WANT_ASYNC || SSL_want_async (ssl)))
		{
		  session_t *ts =
		    session_get_from_handle (ctx->tls_session_handle);
		  vpp_tls_async_init_event (ctx, tls_async_write_event_handler,
					    ts, SSL_ASYNC_EVT_WR, sp,
					    sp->max_burst_size);
		  break;
		}
	    }
	  break;
	}
      i++;
    }

  if (wrote)
    svm_fifo_dequeue_drop (f, wrote);

  return wrote;
}

u8 *
format_openssl_alpn_proto (u8 *s, va_list *va)
{
  const unsigned char *proto = va_arg (*va, const unsigned char *);
  unsigned int proto_len = va_arg (*va, unsigned int);
  return format (s, "%U", format_ascii_bytes, proto, proto_len);
}

void
openssl_handle_handshake_failure (tls_ctx_t *ctx)
{
  /* Failed to renegotiate handshake */
  if (ctx->flags & TLS_CONN_F_HS_DONE)
    {
      tls_notify_app_io_error (ctx);
      tls_disconnect_transport (ctx);
      return;
    }

  if (SSL_is_server (((openssl_ctx_t *) ctx)->ssl))
    {
      ctx->flags |= TLS_CONN_F_NO_APP_SESSION;
      tls_disconnect_transport (ctx);
    }
  else
    {
      /*
       * Also handles cleanup of the pre-allocated session
       */
      tls_notify_app_connected (ctx, SESSION_E_TLS_HANDSHAKE);
      tls_disconnect_transport (ctx);
    }
}

int
openssl_ctx_handshake_rx (tls_ctx_t *ctx, session_t *tls_session)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  int rv = 0, err;

  ctx->app_wrk_connect_index = tls_session->app_wrk_connect_index;
  while (SSL_in_init (oc->ssl))
    {
      if (ctx->flags & TLS_CONN_F_RESUME)
	{
	  ctx->flags &= ~TLS_CONN_F_RESUME;
	}
      else if (!svm_fifo_max_dequeue_cons (tls_session->rx_fifo))
	break;

      rv = SSL_do_handshake (oc->ssl);
      err = SSL_get_error (oc->ssl, rv);

      if (openssl_main.async && err == SSL_ERROR_WANT_ASYNC)
	{
	  vpp_tls_async_init_event (ctx, tls_async_handshake_event_handler,
				    tls_session, SSL_ASYNC_EVT_INIT, NULL, 0);
	  return -1;
	}

      if (err == SSL_ERROR_SSL)
	{
	  char buf[512];
	  ERR_error_string (ERR_get_error (), buf);
	  clib_warning ("Err: %s", buf);
	  openssl_handle_handshake_failure (ctx);
	  return -1;
	}

      if (err != SSL_ERROR_WANT_WRITE && err != SSL_ERROR_WANT_READ)
	break;
    }
  TLS_DBG (2, "tls state for %u is %s", oc->openssl_ctx_index,
	   SSL_state_string_long (oc->ssl));

  if (SSL_in_init (oc->ssl))
    return -1;

  /* Renegotiated handshake, app must not be notified */
  if (PREDICT_FALSE (ctx->flags & TLS_CONN_F_HS_DONE))
    return 0;

  /*
   * Handshake complete
   */
  if (ctx->alpn_list)
    {
      const unsigned char *proto = 0;
      unsigned int proto_len;
      SSL_get0_alpn_selected (oc->ssl, &proto, &proto_len);
      if (proto_len)
	{
	  TLS_DBG (1, "Selected ALPN protocol: %U", format_openssl_alpn_proto,
		   proto, proto_len);
	  tls_alpn_proto_id_t id = { .len = (u8) proto_len,
				     .base = (u8 *) proto };
	  ctx->alpn_selected = tls_alpn_proto_by_str (&id);
	}
      else
	TLS_DBG (1, "No ALPN negotiated");
    }
  ctx->app_wrk_connect_index = tls_session->app_wrk_connect_index;
  if (!SSL_is_server (oc->ssl))
    {
      /*
       * Verify server certificate
       */
      if ((rv = SSL_get_verify_result (oc->ssl)) != X509_V_OK)
	{
	  TLS_DBG (1, " failed verify: %s\n",
		   X509_verify_cert_error_string (rv));

	  /*
	   * Presence of hostname enforces strict certificate verification
	   */
	  if (ctx->srv_hostname)
	    {
	      openssl_handle_handshake_failure (ctx);
	      return -1;
	    }
	}
      if (tls_notify_app_connected (ctx, SESSION_E_NONE))
	{
	  tls_disconnect_transport (ctx);
	  return -1;
	}
    }
  else
    {
      /* Need to check transport status */
      if (ctx->flags & TLS_CONN_F_PASSIVE_CLOSE)
	{
	  openssl_handle_handshake_failure (ctx);
	  return -1;
	}

      /* Accept failed, cleanup */
      if (tls_notify_app_accept (ctx))
	{
	  ctx->c_s_index = SESSION_INVALID_INDEX;
	  tls_disconnect_transport (ctx);
	  return -1;
	}
    }
  ctx->flags |= TLS_CONN_F_HS_DONE;
  TLS_DBG (1, "Handshake for %u complete. TLS cipher is %s",
	   oc->openssl_ctx_index, SSL_get_cipher (oc->ssl));
  return rv;
}

void
openssl_confirm_app_close (tls_ctx_t *ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  int rv = SSL_shutdown (oc->ssl);
  if (rv < 0)
    (void) SSL_get_error (oc->ssl, rv);
  if (ctx->flags & TLS_CONN_F_SHUTDOWN_TRANSPORT)
    tls_shutdown_transport (ctx);
  else
    tls_disconnect_transport (ctx);
  session_transport_closed_notify (&ctx->connection);
}

static int
openssl_ctx_write_tls (tls_ctx_t *ctx, session_t *app_session,
		       transport_send_params_t *sp)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  u32 deq_max, space, enq_buf;
  session_t *ts;
  int wrote = 0;
  svm_fifo_t *f;

  ts = session_get_from_handle (ctx->tls_session_handle);
  space = svm_fifo_max_enqueue_prod (ts->tx_fifo);
  /* Leave a bit of extra space for tls ctrl data, if any needed */
  space = clib_max ((int) space - TLSO_CTRL_BYTES, 0);

  f = app_session->tx_fifo;

  deq_max = svm_fifo_max_dequeue_cons (f);
  deq_max = clib_min (deq_max, space);
  if (!deq_max)
    goto check_tls_fifo;

  deq_max = clib_min (deq_max, sp->max_burst_size);

  /* Make sure tcp's tx fifo can actually buffer all bytes to be dequeued.
   * If under memory pressure, tls's fifo segment might not be able to
   * allocate the chunks needed. This also avoids errors from the underlying
   * custom bio to the ssl infra which at times can get stuck. */
  if (svm_fifo_provision_chunks (ts->tx_fifo, 0, 0, deq_max + TLSO_CTRL_BYTES))
    goto check_tls_fifo;

  wrote = openssl_write_from_fifo_into_ssl (f, ctx, sp, deq_max);

  /* Unrecoverable protocol error. Reset connection */
  if (PREDICT_FALSE (wrote < 0))
    {
      tls_notify_app_io_error (ctx);
      return 0;
    }

  if (!wrote)
    goto check_tls_fifo;

  if (svm_fifo_needs_deq_ntf (f, wrote))
    session_dequeue_notify (app_session);

check_tls_fifo:

  if (PREDICT_FALSE ((ctx->flags & TLS_CONN_F_APP_CLOSED) &&
		     BIO_ctrl_pending (oc->rbio) <= 0))
    openssl_confirm_app_close (ctx);

  /* Deschedule and wait for deq notification if fifo is almost full */
  enq_buf = clib_min (svm_fifo_size (ts->tx_fifo) / 2, TLSO_MIN_ENQ_SPACE);
  if (space < wrote + enq_buf)
    {
      svm_fifo_add_want_deq_ntf (ts->tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      transport_connection_deschedule (&ctx->connection);
      sp->flags |= TRANSPORT_SND_F_DESCHED;
    }
  else
    {
      /* Request tx reschedule of the app session */
      if (wrote)
	app_session->flags |= SESSION_F_CUSTOM_TX;
    }

  return wrote;
}

static int
openssl_ctx_write_dtls (tls_ctx_t *ctx, session_t *app_session,
			transport_send_params_t *sp)
{
  openssl_main_t *om = &openssl_main;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  u32 read = 0, to_deq, dgram_sz, enq_max;
  session_dgram_pre_hdr_t hdr;
  session_t *us;
  int wrote, rv;
  u8 *buf;

  us = session_get_from_handle (ctx->tls_session_handle);
  to_deq = svm_fifo_max_dequeue_cons (app_session->tx_fifo);
  buf = om->tx_bufs[ctx->c_thread_index];

  while (to_deq > 0)
    {
      /* Peeking only pre-header dgram because the session is connected */
      rv = svm_fifo_peek (app_session->tx_fifo, 0, sizeof (hdr), (u8 *) &hdr);
      ASSERT (rv == sizeof (hdr));
      if (PREDICT_FALSE (to_deq < hdr.data_length + SESSION_CONN_HDR_LEN))
	goto done;

      dgram_sz = hdr.data_length + SESSION_CONN_HDR_LEN;
      if (hdr.data_length > DTLSO_MAX_BUFSIZE)
	{
	  svm_fifo_dequeue_drop (app_session->tx_fifo, dgram_sz);
	  to_deq -= dgram_sz;
	  continue;
	}
      ASSERT (hdr.data_length < vec_len (buf));
      enq_max = dgram_sz + TLSO_CTRL_BYTES;
      if (svm_fifo_max_enqueue_prod (us->tx_fifo) < enq_max ||
	  svm_fifo_provision_chunks (us->tx_fifo, 0, 0, enq_max))
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

      wrote = SSL_write (oc->ssl, buf, rv);
      ASSERT (wrote > 0);

      read += rv;
      to_deq -= dgram_sz;
    }

done:

  if (svm_fifo_needs_deq_ntf (app_session->tx_fifo, read))
    session_dequeue_notify (app_session);

  if (read)
    tls_add_vpp_q_tx_evt (us);

  if (PREDICT_FALSE ((ctx->flags & TLS_CONN_F_APP_CLOSED) &&
		     !svm_fifo_max_enqueue_prod (us->rx_fifo)))
    openssl_confirm_app_close (ctx);

  return read;
}

static inline int
openssl_ctx_write (tls_ctx_t *ctx, session_t *app_session,
		   transport_send_params_t *sp)
{
  if (ctx->tls_type == TRANSPORT_PROTO_TLS)
    return openssl_ctx_write_tls (ctx, app_session, sp);
  else
    return openssl_ctx_write_dtls (ctx, app_session, sp);
}

int
openssl_ctx_read_tls (tls_ctx_t *ctx, session_t *tls_session)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  const u32 max_len = 128 << 10;
  session_t *app_session;
  svm_fifo_t *f;
  int read;

  if (PREDICT_FALSE (SSL_in_init (oc->ssl)))
    {
      if (openssl_ctx_handshake_rx (ctx, tls_session) < 0)
	return 0;

      /* Application might force a session pool realloc on accept */
      tls_session = session_get_from_handle (ctx->tls_session_handle);
    }

  app_session = session_get_from_handle (ctx->app_session_handle);
  f = app_session->rx_fifo;

  read = openssl_read_from_ssl_into_fifo (f, ctx, max_len);

  /* Unrecoverable protocol error. Reset connection */
  if (PREDICT_FALSE (read < 0))
    {
      tls_notify_app_io_error (ctx);
      return 0;
    }

  if (read)
    tls_notify_app_enqueue (ctx, app_session);

  if ((SSL_pending (oc->ssl) > 0) ||
      svm_fifo_max_dequeue_cons (tls_session->rx_fifo))
    tls_add_vpp_q_builtin_rx_evt (tls_session);

  return read;
}

static inline int
openssl_ctx_read_dtls (tls_ctx_t *ctx, session_t *us)
{
  openssl_main_t *om = &openssl_main;
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  session_dgram_hdr_t hdr;
  session_t *app_session;
  u32 wrote = 0;
  int read, rv;
  u8 *buf;

  if (PREDICT_FALSE (SSL_in_init (oc->ssl)))
    {
      u32 us_index = us->session_index;
      if (openssl_ctx_handshake_rx (ctx, us) < 0)
	return 0;
      /* Session pool might grow when allocating the app's session */
      us = session_get (us_index, ctx->c_thread_index);
    }

  buf = om->rx_bufs[ctx->c_thread_index];
  app_session = session_get_from_handle (ctx->app_session_handle);
  svm_fifo_fill_chunk_list (app_session->rx_fifo);

  while (svm_fifo_max_dequeue_cons (us->rx_fifo) > 0)
    {
      if (svm_fifo_max_enqueue_prod (app_session->rx_fifo) < DTLSO_MAX_DGRAM)
	{
	  tls_add_vpp_q_builtin_rx_evt (us);
	  goto done;
	}

      read = SSL_read (oc->ssl, buf, vec_len (buf));
      if (PREDICT_FALSE (read <= 0))
	{
	  if (read < 0)
	    tls_add_vpp_q_builtin_rx_evt (us);
	  goto done;
	}
      wrote += read;

      hdr.data_length = read;
      hdr.data_offset = 0;
      hdr.gso_size = 0;

      svm_fifo_seg_t segs[2] = { { (u8 *) &hdr, sizeof (hdr) },
				 { buf, read } };

      rv = svm_fifo_enqueue_segments (app_session->rx_fifo, segs, 2,
				      0 /* allow partial */);
      ASSERT (rv > 0);
    }

done:

  /* If handshake just completed, session may still be in accepting state */
  if (app_session->session_state >= SESSION_STATE_READY)
    tls_notify_app_enqueue (ctx, app_session);

  return wrote;
}

static inline int
openssl_ctx_read (tls_ctx_t *ctx, session_t *ts)
{
  if (ctx->tls_type == TRANSPORT_PROTO_TLS)
    return openssl_ctx_read_tls (ctx, ts);
  else
    return openssl_ctx_read_dtls (ctx, ts);
}

static void
openssl_cleanup_certkey_int_ctx (app_certkey_int_ctx_t *cki)
{
  X509_free (cki->cert);
  EVP_PKEY_free (cki->key);
}

static app_certkey_int_ctx_t *
openssl_init_certkey_init_ctx (app_cert_key_pair_t *ckpair,
			       clib_thread_index_t thread_index)
{
  app_certkey_int_ctx_t *cki = 0;
  EVP_PKEY *pkey;
  X509 *cert;
  BIO *bio;

  cki =
    app_certkey_alloc_int_ctx (ckpair, thread_index, CRYPTO_ENGINE_OPENSSL);
  bio = BIO_new (BIO_s_mem ());
  BIO_write (bio, ckpair->cert, vec_len (ckpair->cert));
  cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL);
  if (!cert)
    {
      clib_warning ("unable to parse certificate");
      BIO_free (bio);
      return 0;
    }
  cki->cert = cert;
  BIO_free (bio);

  bio = BIO_new (BIO_s_mem ());
  BIO_write (bio, ckpair->key, vec_len (ckpair->key));
  pkey = PEM_read_bio_PrivateKey (bio, NULL, NULL, NULL);
  if (!pkey)
    {
      clib_warning ("unable to parse pkey");
      BIO_free (bio);
      return 0;
    }
  cki->key = pkey;
  BIO_free (bio);

  cki->cleanup_cb = openssl_cleanup_certkey_int_ctx;

  return cki;
}

static int
openssl_set_ckpair (SSL *ssl, u32 ckpair_index,
		    clib_thread_index_t thread_index)
{
  app_cert_key_pair_t *ckpair;
  app_certkey_int_ctx_t *cki;

  ckpair = app_cert_key_pair_get_if_valid (ckpair_index);
  if (!ckpair)
    return -1;

  if (!ckpair->cert || !ckpair->key)
    {
      TLS_DBG (1, "tls cert and/or key not configured");
      return -1;
    }

  cki = app_certkey_get_int_ctx (ckpair, thread_index, CRYPTO_ENGINE_OPENSSL);
  if (!cki || !cki->cert)
    {
      cki = openssl_init_certkey_init_ctx (ckpair, thread_index);
      if (!cki)
	{
	  clib_warning ("unable to initialize certificate/key pair");
	  return -1;
	}
    }

  SSL_use_certificate (ssl, cki->cert);
  SSL_use_PrivateKey (ssl, cki->key);

  TLS_DBG (1, "TLS client using ckpair index: %d", ckpair_index);
  return 0;
}

static void
openssl_cleanup_ca_trust_int_ctx (app_crypto_ca_trust_int_ctx_t *cki)
{
  X509_STORE_free (cki->ca_store);
}

static app_crypto_ca_trust_int_ctx_t *
openssl_init_int_ca_trust_ctx (app_crypto_ca_trust_t *ca_trust,
			       clib_thread_index_t thread_index)
{
  app_crypto_ca_trust_int_ctx_t *cti = 0;
  X509_STORE *store;
  X509 *cert;
  BIO *bio;

  cti = app_crypto_alloc_int_ca_trust (ca_trust, thread_index);
  store = X509_STORE_new ();
  if (!store)
    {
      clib_warning ("unable to create x509 store");
      return 0;
    }

  /* Create BIO from the single PEM string containing multiple certificates */
  bio = BIO_new (BIO_s_mem ());
  BIO_write (bio, ca_trust->ca_chain, vec_len (ca_trust->ca_chain));

  /* Read all certificates from the PEM string */
  while ((cert = PEM_read_bio_X509 (bio, NULL, NULL, NULL)) != NULL)
    {
      if (X509_STORE_add_cert (store, cert) != 1)
	{
	  char buf[512];
	  ERR_error_string (ERR_get_error (), buf);
	  clib_warning ("unable to add certificate to store: %s", buf);
	  X509_free (cert);
	  BIO_free (bio);
	  X509_STORE_free (store);
	  return 0;
	}
      X509_free (cert);
    }

  BIO_free (bio);

  /* Parse and add CRL if present */
  if (ca_trust->crl && vec_len (ca_trust->crl) > 0)
    {
      X509_CRL *crl;
      bio = BIO_new (BIO_s_mem ());
      BIO_write (bio, ca_trust->crl, vec_len (ca_trust->crl));

      /* Read all CRLs from the PEM string */
      while ((crl = PEM_read_bio_X509_CRL (bio, NULL, NULL, NULL)) != NULL)
	{
	  if (X509_STORE_add_crl (store, crl) != 1)
	    {
	      char buf[512];
	      ERR_error_string (ERR_get_error (), buf);
	      clib_warning ("unable to add CRL to store: %s", buf);
	      X509_CRL_free (crl);
	      BIO_free (bio);
	      X509_STORE_free (store);
	      return 0;
	    }
	  X509_CRL_free (crl);
	}

      BIO_free (bio);

      /* Enable CRL checking */
      X509_STORE_set_flags (store,
			    X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
    }

  cti->ca_store = store;
  cti->cleanup_cb = openssl_cleanup_ca_trust_int_ctx;

  return cti;
}

static app_crypto_ca_trust_int_ctx_t *
openssl_get_int_ca_trust (tls_ctx_t *ctx)
{
  app_crypto_ca_trust_int_ctx_t *cti;
  app_crypto_ca_trust_t *ca_trust;

  ca_trust = app_crypto_get_wrk_ca_trust (ctx->parent_app_wrk_index,
					  ctx->ca_trust_index);
  if (!ca_trust)
    return 0;

  cti = app_crypto_get_int_ca_trust (ca_trust, ctx->c_thread_index);
  if (!cti || !cti->ca_store)
    {
      cti = openssl_init_int_ca_trust_ctx (ca_trust, ctx->c_thread_index);
      if (!cti)
	{
	  clib_warning ("unable to initialize certificate/key pair");
	  return 0;
	}
    }

  return cti;
}

static int
openssl_init_client_ctx (clib_thread_index_t thread_index,
			 transport_proto_t proto)
{
  long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  openssl_main_t *om = &openssl_main;
  const SSL_METHOD *method;
  SSL_CTX *client_ssl_ctx;
  int rv;

  method = proto == TRANSPORT_PROTO_TLS ? TLS_client_method () :
					  DTLS_client_method ();

  client_ssl_ctx = SSL_CTX_new (method);
  if (client_ssl_ctx == NULL)
    {
      TLS_DBG (1, "SSL_CTX_new returned null");
      return -1;
    }

  SSL_CTX_set_ecdh_auto (client_ssl_ctx, 1);
  SSL_CTX_set_mode (client_ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
#ifdef HAVE_OPENSSL_ASYNC
  if (om->async)
    {
      SSL_CTX_set_mode (client_ssl_ctx, SSL_MODE_ASYNC);
      SSL_CTX_set_async_callback (client_ssl_ctx, tls_async_openssl_callback);
    }
#endif

  rv = SSL_CTX_set_cipher_list (client_ssl_ctx, (const char *) om->ciphers);
  if (rv != 1)
    {
      TLS_DBG (1, "Couldn't set cipher");
      return -1;
    }

  SSL_CTX_set_options (client_ssl_ctx, flags);
  SSL_CTX_set1_cert_store (client_ssl_ctx, om->cert_store);

  /* Set TLS Record size */
  if (om->record_size)
    {
      rv = SSL_CTX_set_max_send_fragment (client_ssl_ctx, om->record_size);
      if (rv != 1)
	{
	  TLS_DBG (1, "Couldn't set TLS record-size");
	  return -1;
	}
      TLS_DBG (1, "Using TLS record-size of %d", om->record_size);
    }

  if (proto == TRANSPORT_PROTO_TLS)
    om->default_client_ssl_ctx[thread_index] = client_ssl_ctx;
  else
    om->default_dtls_client_ssl_ctx[thread_index] = client_ssl_ctx;

  return 0;
}

static inline SSL_CTX *
openssl_get_client_ssl_ctx (clib_thread_index_t thread_index,
			    transport_proto_t proto)
{
  openssl_main_t *om = &openssl_main;

  /* One time init of the default client ssl ctxs */
  if (PREDICT_FALSE (!om->default_client_ssl_ctx[thread_index]))
    {
      openssl_init_client_ctx (thread_index, TRANSPORT_PROTO_TLS);
      openssl_init_client_ctx (thread_index, TRANSPORT_PROTO_DTLS);
    }

  return proto == TRANSPORT_PROTO_TLS ?
	   om->default_client_ssl_ctx[thread_index] :
	   om->default_dtls_client_ssl_ctx[thread_index];
}

static int
openssl_make_verify_flags (tls_verify_cfg_t verify_cfg)
{
  int flags = SSL_VERIFY_PEER;

  if (verify_cfg & TLS_VERIFY_F_PEER)
    flags |= SSL_VERIFY_PEER;
  if (verify_cfg & TLS_VERIFY_F_PEER_CERT)
    flags |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;

  return flags;
}

static int
openssl_client_set_verify (tls_ctx_t *ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;

  if (ctx->verify_cfg & (TLS_VERIFY_F_HOSTNAME | TLS_VERIFY_F_HOSTNAME_STRICT))
    {
      X509_VERIFY_PARAM *param = SSL_get0_param (oc->ssl);
      if (!param)
	{
	  TLS_DBG (1, "Couldn't fetch SSL param");
	  return -1;
	}

      if (ctx->verify_cfg & TLS_VERIFY_F_HOSTNAME_STRICT)
	X509_VERIFY_PARAM_set_hostflags (param,
					 X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

      if (ctx->verify_cfg & TLS_VERIFY_F_HOSTNAME)
	{
	  if (!X509_VERIFY_PARAM_set1_host (
		param, (const char *) ctx->srv_hostname, 0))
	    {
	      TLS_DBG (1, "Couldn't set hostname for verification");
	      return -1;
	    }
	}
    }
  SSL_set_verify (oc->ssl, openssl_make_verify_flags (ctx->verify_cfg), 0);

  return 0;
}

static int
openssl_ctx_init_client (tls_ctx_t *ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  SSL_CTX *client_ssl_ctx;
  int rv, err;

  client_ssl_ctx =
    openssl_get_client_ssl_ctx (ctx->c_thread_index, ctx->tls_type);
  if (PREDICT_FALSE (!client_ssl_ctx))
    return -1;

  oc->ssl = SSL_new (client_ssl_ctx);
  if (oc->ssl == NULL)
    {
      TLS_DBG (1, "Couldn't initialize ssl struct");
      return -1;
    }

  if (ctx->alpn_list)
    {
      rv =
	SSL_set_alpn_protos (oc->ssl, (const unsigned char *) ctx->alpn_list,
			     (unsigned int) vec_len (ctx->alpn_list));
      if (rv != 0)
	{
	  TLS_DBG (1, "Couldn't set alpn protos");
	  return -1;
	}
    }

  if (!SSL_set_tlsext_host_name (oc->ssl, (const char *) ctx->srv_hostname))
    {
      TLS_DBG (1, "Couldn't set hostname");
      return -1;
    }

  if (ctx->verify_cfg)
    {
      if (openssl_client_set_verify (ctx))
	{
	  TLS_DBG (1, "ERROR: setting verify flags failed");
	  return -1;
	}
    }

  /* Configure a ckpair index only if non-default/test provided */
  if (ctx->ckpair_index)
    {
      if (openssl_set_ckpair (oc->ssl, ctx->ckpair_index, ctx->c_thread_index))
	{
	  TLS_DBG (1, "Couldn't set client certificate-key pair");
	}
    }

  /* Configure trusted ca only if non-default */
  if (ctx->ca_trust_index)
    {
      app_crypto_ca_trust_int_ctx_t *cti = openssl_get_int_ca_trust (ctx);
      if (!cti)
	{
	  TLS_DBG (1, "Couldn't get trusted CA");
	  return -1;
	}
      if (SSL_set1_verify_cert_store (oc->ssl, cti->ca_store) != 1)
	{
	  char buf[512];
	  ERR_error_string (ERR_get_error (), buf);
	  clib_warning ("Failed to set CA trust store: %s", buf);
	  return -1;
	}
    }

  if (ctx->tls_type == TRANSPORT_PROTO_TLS)
    {
      oc->rbio = BIO_new_tls (ctx->tls_session_handle);
      oc->wbio = BIO_new_tls (ctx->tls_session_handle);
    }
  else
    {
      oc->rbio = BIO_new_dtls (ctx->tls_session_handle);
      oc->wbio = BIO_new_dtls (ctx->tls_session_handle);
    }

  SSL_set_bio (oc->ssl, oc->wbio, oc->rbio);
  SSL_set_connect_state (oc->ssl);

  /*
   * 2. Do the first steps in the handshake.
   */
  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   oc->openssl_ctx_index);

#ifdef HAVE_OPENSSL_ASYNC
  session_t *tls_session = session_get_from_handle (ctx->tls_session_handle);
  openssl_ctx_handshake_rx (ctx, tls_session);
#endif
  while (1)
    {
      rv = SSL_do_handshake (oc->ssl);
      err = SSL_get_error (oc->ssl, rv);
#ifdef HAVE_OPENSSL_ASYNC
      if (err == SSL_ERROR_WANT_ASYNC)
	break;
#endif
      if (err != SSL_ERROR_WANT_WRITE)
	break;
    }

  TLS_DBG (2, "tls state for [%u]%u is %s", ctx->c_thread_index,
	   oc->openssl_ctx_index, SSL_state_string_long (oc->ssl));
  return 0;
}

static int
openssl_alpn_select_cb (SSL *ssl, const unsigned char **out,
			unsigned char *outlen, const unsigned char *in,
			unsigned int inlen, void *arg)
{
  u8 *proto_list = arg;
  if (SSL_select_next_proto (
	(unsigned char **) out, outlen, (const unsigned char *) proto_list,
	vec_len (proto_list), in, inlen) != OPENSSL_NPN_NEGOTIATED)
    {
      TLS_DBG (1, "server support no alpn proto advertised by client");
      return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
  return SSL_TLSEXT_ERR_OK;
}

static int
openssl_start_listen (tls_ctx_t * lctx)
{
  u64 flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  openssl_main_t *om = &openssl_main;
  const SSL_METHOD *method;
  SSL_CTX *ssl_ctx;
  int rv;
  u32 olc_index;
  openssl_listen_ctx_t *olc;
  app_cert_key_pair_t *ckpair;
  app_certkey_int_ctx_t *cki = 0;

  if (lctx->ckpair_index)
    {
      ckpair = app_cert_key_pair_get_if_valid (lctx->ckpair_index);
      if (!ckpair)
	return -1;

      if (!ckpair->cert || !ckpair->key)
	{
	  TLS_DBG (1, "tls cert and/or key not configured %d",
		   lctx->parent_app_wrk_index);
	  return -1;
	}

      cki = app_certkey_get_int_ctx (ckpair, lctx->c_thread_index,
				     CRYPTO_ENGINE_OPENSSL);
      if (!cki || !cki->cert)
	{
	  cki = openssl_init_certkey_init_ctx (ckpair, lctx->c_thread_index);
	  if (!cki)
	    {
	      clib_warning ("unable to initialize certificate/key pair");
	      return -1;
	    }
	}
    }

  method = lctx->tls_type == TRANSPORT_PROTO_TLS ? TLS_server_method () :
						   DTLS_server_method ();
  ssl_ctx = SSL_CTX_new (method);
  if (!ssl_ctx)
    {
      clib_warning ("Unable to create SSL context");
      return -1;
    }

  SSL_CTX_set_mode (ssl_ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
#ifdef HAVE_OPENSSL_ASYNC
  if (om->async)
    {
      SSL_CTX_set_mode (ssl_ctx, SSL_MODE_ASYNC);
      SSL_CTX_set_async_callback (ssl_ctx, tls_async_openssl_callback);
    }
#endif
  SSL_CTX_set_options (ssl_ctx, flags);
  SSL_CTX_set_ecdh_auto (ssl_ctx, 1);

  rv = SSL_CTX_set_cipher_list (ssl_ctx, (const char *) om->ciphers);
  if (rv != 1)
    {
      TLS_DBG (1, "Couldn't set cipher");
      return -1;
    }

  /* use the default OpenSSL built-in DH parameters */
  rv = SSL_CTX_set_dh_auto (ssl_ctx, 1);
  if (rv != 1)
    {
      TLS_DBG (1, "Couldn't set temp DH parameters");
      return -1;
    }

  if (lctx->verify_cfg)
    {
      SSL_CTX_set_verify (ssl_ctx,
			  openssl_make_verify_flags (lctx->verify_cfg), 0);
      /* Set the cert store for client verification */
      if (lctx->ca_trust_index)
	{
	  app_crypto_ca_trust_int_ctx_t *cti = openssl_get_int_ca_trust (lctx);
	  if (!cti)
	    {
	      TLS_DBG (1, "Couldn't get trusted CA");
	      return -1;
	    }
	  SSL_CTX_set1_verify_cert_store (ssl_ctx, cti->ca_store);
	}
      else
	{
	  SSL_CTX_set1_cert_store (ssl_ctx, om->cert_store);
	}
    }

  /* Set TLS Record size */
  if (om->record_size)
    {
      rv = SSL_CTX_set_max_send_fragment (ssl_ctx, om->record_size);
      if (rv != 1)
	{
	  TLS_DBG (1, "Couldn't set TLS record-size");
	  return -1;
	}
    }

  /* Set TLS Record Split size */
  if (om->record_split_size)
    {
      rv = SSL_CTX_set_split_send_fragment (ssl_ctx, om->record_split_size);
      if (rv != 1)
	{
	  TLS_DBG (1, "Couldn't set TLS record-split-size");
	  return -1;
	}
    }

  /* Set TLS Max Pipeline count */
  if (om->max_pipelines)
    {
      rv = SSL_CTX_set_max_pipelines (ssl_ctx, om->max_pipelines);
      if (rv != 1)
	{
	  TLS_DBG (1, "Couldn't set TLS max-pipelines");
	  return -1;
	}
    }

  /*
   * Set the key and cert
   */
  if (cki)
    {
      rv = SSL_CTX_use_certificate (ssl_ctx, cki->cert);
      if (rv != 1)
	{
	  clib_warning ("unable to use SSL certificate");
	  goto err;
	}
      rv = SSL_CTX_use_PrivateKey (ssl_ctx, cki->key);
      if (rv != 1)
	{
	  clib_warning ("unable to use SSL PrivateKey");
	  goto err;
	}
    }
  else
    {
      lctx->flags |= TLS_CONN_F_ASYNC_CERT;
    }

  if (lctx->alpn_list)
    SSL_CTX_set_alpn_select_cb (ssl_ctx, openssl_alpn_select_cb,
				(void *) lctx->alpn_list);

  olc_index = openssl_listen_ctx_alloc ();
  olc = openssl_lctx_get (olc_index);
  olc->ssl_ctx = ssl_ctx;

  /* store SSL_CTX into TLS level structure */
  lctx->tls_ssl_ctx = olc_index;

  return 0;

err:
  return -1;
}

static int
openssl_stop_listen (tls_ctx_t * lctx)
{
  u32 olc_index;
  openssl_listen_ctx_t *olc;

  olc_index = lctx->tls_ssl_ctx;
  olc = openssl_lctx_get (olc_index);

  SSL_CTX_free (olc->ssl_ctx);
  openssl_listen_ctx_free (olc);

  return 0;
}

static void
openssl_server_async_cert_cb (app_crypto_async_reply_t *reply)
{
  app_crypto_async_req_handle_t handle = reply->handle;
  clib_thread_index_t thread_index;
  app_cert_key_pair_t *ckpair;
  app_certkey_int_ctx_t *cki;
  openssl_ctx_t *oc;
  tls_ctx_t *ctx;

  thread_index = handle.thread_index;
  ASSERT (thread_index == vlib_get_thread_index ());
  ctx = openssl_ctx_get_w_thread (handle.opaque & TLS_IDX_MASK,
				  handle.thread_index);
  oc = (openssl_ctx_t *) ctx;

  ckpair = app_cert_key_pair_get_if_valid (reply->async_cert.ckpair_index);
  if (!ckpair || !ckpair->cert || !ckpair->key)
    {
      TLS_DBG (1, "Invalid certificate/key pair %u", ckpair_index);
      goto error;
    }

  /* Get or initialize certificate context */
  cki = app_certkey_get_int_ctx (ckpair, thread_index, CRYPTO_ENGINE_OPENSSL);
  if (!cki || !cki->cert)
    {
      cki = openssl_init_certkey_init_ctx (ckpair, thread_index);
      if (!cki)
	{
	  TLS_DBG (1, "Failed to initialize certificate context");
	  goto error;
	}
    }

  /* Set the certificate and private key */
  if (SSL_use_certificate (oc->ssl, cki->cert) != 1)
    {
      TLS_DBG (1, "Failed to set certificate");
      goto error;
    }

  if (SSL_use_PrivateKey (oc->ssl, cki->key) != 1)
    {
      TLS_DBG (1, "Failed to set private key");
      goto error;
    }

  /* Verify that the private key matches the certificate */
  if (SSL_check_private_key (oc->ssl) != 1)
    {
      TLS_DBG (1, "Private key does not match certificate");
      goto error;
    }

  TLS_DBG (2, "Successfully set certificate for server %s",
	   SSL_get_servername (oc->ssl, TLSEXT_NAMETYPE_host_name));

  /* Continue handshake */
  while (1)
    {
      int rv, err;
      rv = SSL_do_handshake (oc->ssl);
      err = SSL_get_error (oc->ssl, rv);
      if (openssl_main.async && err == SSL_ERROR_WANT_ASYNC)
	break;

      if (err != SSL_ERROR_WANT_WRITE)
	break;
    }

  return;

error:
  /* Do not free ctx yet, in case we have pending rx events */
  ctx->flags |= TLS_CONN_F_NO_APP_SESSION;
  tls_disconnect_transport (ctx);
}

static int
openssl_server_cert_callback (SSL *ssl, void *arg)
{
  u32 ctx_index = (u32) pointer_to_uword (arg);
  tls_ctx_t *ctx = openssl_ctx_get (ctx_index);
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  const char *servername;

  TLS_DBG (2, "Server certificate callback invoked for ctx %u",
	   oc->openssl_ctx_index);

  /* Get the requested server name from SNI extension */
  servername = SSL_get_servername (ssl, TLSEXT_NAMETYPE_host_name);
  if (!servername)
    {
      /* TODO maybe handle using default cert, if provided */
      TLS_DBG (1, "No SNI provided");
      return 0;
    }

  TLS_DBG (2, "SNI requested server name: %s", servername);

  app_crypto_async_req_t req = { .req_type = APP_CRYPTO_ASYNC_REQ_TYPE_CERT,
				 .handle = {
                                        .thread_index = ctx->c_thread_index,
                                        .opaque = ctx->tls_ctx_handle,
                                        },
				 .cb = openssl_server_async_cert_cb,
				 .app_wrk_index = ctx->parent_app_wrk_index,
				 .async_cert = {
				   .servername = (const u8 *) servername,
				 } };

  oc->req_ticket = app_crypto_async_req (&req);
  if (oc->req_ticket.as_u64 == APP_CRYPTO_ASYNC_INVALID_TICKET.as_u64)
    return 0;

  /* Certificate selection in progress */
  return -1;
}

static int
openssl_ctx_init_server (tls_ctx_t * ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  u32 olc_index = ctx->tls_ssl_ctx;
  openssl_listen_ctx_t *olc;
  int rv, err;

  /* Start a new connection */

  olc = openssl_lctx_get (olc_index);
  oc->ssl = SSL_new (olc->ssl_ctx);
  if (oc->ssl == NULL)
    {
      TLS_DBG (1, "Couldn't initialize ssl struct");
      return -1;
    }

  if (ctx->tls_type == TRANSPORT_PROTO_TLS)
    {
      oc->rbio = BIO_new_tls (ctx->tls_session_handle);
      oc->wbio = BIO_new_tls (ctx->tls_session_handle);
    }
  else
    {
      oc->rbio = BIO_new_dtls (ctx->tls_session_handle);
      oc->wbio = BIO_new_dtls (ctx->tls_session_handle);
    }

  SSL_set_bio (oc->ssl, oc->wbio, oc->rbio);
  SSL_set_accept_state (oc->ssl);

  TLS_DBG (1, "Initiating handshake for [%u]%u", ctx->c_thread_index,
	   oc->openssl_ctx_index);

  if (openssl_main.async)
    {
      session_t *tls_session =
	session_get_from_handle (ctx->tls_session_handle);
      openssl_ctx_handshake_rx (ctx, tls_session);
    }

  /* Set up certificate callback for async certificate retrieval */
  if (ctx->flags & TLS_CONN_F_ASYNC_CERT)
    {
      uword oc_index = oc->openssl_ctx_index;
      TLS_DBG (2, "Set async cert callback for ctx %u", oc_index);
      SSL_set_cert_cb (oc->ssl, openssl_server_cert_callback,
		       uword_to_pointer (oc_index, void *));
      return 0;
    }

  while (1)
    {
      rv = SSL_do_handshake (oc->ssl);
      err = SSL_get_error (oc->ssl, rv);
      if (openssl_main.async && err == SSL_ERROR_WANT_ASYNC)
	break;

      if (err != SSL_ERROR_WANT_WRITE)
	break;
    }

  TLS_DBG (2, "tls state for [%u]%u is %s", ctx->c_thread_index,
	   oc->openssl_ctx_index, SSL_state_string_long (oc->ssl));
  return 0;
}

static int
openssl_transport_close (tls_ctx_t * ctx)
{
  if (openssl_main.async && vpp_openssl_is_inflight (ctx))
    {
      TLS_DBG (2, "Close Transport but evts inflight: Flags: %ld", ctx->flags);
      return 0;
    }

  if (!(ctx->flags & TLS_CONN_F_HS_DONE))
    {
      openssl_handle_handshake_failure (ctx);
      return 0;
    }
  session_transport_closing_notify (&ctx->connection);
  return 0;
}

static int
openssl_transport_reset (tls_ctx_t *ctx)
{
  if (!(ctx->flags & TLS_CONN_F_HS_DONE))
    {
      openssl_handle_handshake_failure (ctx);
      return 0;
    }

  session_transport_reset_notify (&ctx->connection);
  session_transport_closed_notify (&ctx->connection);
  tls_disconnect_transport (ctx);

  return 0;
}

static int
openssl_app_close (tls_ctx_t * ctx)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  session_t *app_session;

  /* Wait for all data to be written to tcp */
  app_session = session_get_from_handle (ctx->app_session_handle);
  if (BIO_ctrl_pending (oc->rbio) <= 0
      && !svm_fifo_max_dequeue_cons (app_session->tx_fifo))
    openssl_confirm_app_close (ctx);
  return 0;
}

int
tls_init_ca_chain (void)
{
  openssl_main_t *om = &openssl_main;
  tls_main_t *tm = vnet_tls_get_main ();
  BIO *cert_bio;
  X509 *testcert;
  int rv;

  if (access (tm->ca_cert_path, F_OK | R_OK) == -1)
    {
      clib_warning ("Could not initialize TLS CA certificates");
      return -1;
    }

  if (!(om->cert_store = X509_STORE_new ()))
    {
      clib_warning ("failed to create cert store");
      return -1;
    }

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  rv = X509_STORE_load_file (om->cert_store, tm->ca_cert_path);
#else
  rv = X509_STORE_load_locations (om->cert_store, tm->ca_cert_path, 0);
#endif

  if (rv < 0)
    {
      clib_warning ("failed to load ca certificate");
    }

  if (tm->use_test_cert_in_ca)
    {
      cert_bio = BIO_new (BIO_s_mem ());
      BIO_write (cert_bio, test_srv_crt_rsa, test_srv_crt_rsa_len);
      testcert = PEM_read_bio_X509 (cert_bio, NULL, NULL, NULL);
      BIO_free (cert_bio);
      if (!testcert)
	{
	  clib_warning ("unable to parse certificate");
	  return -1;
	}
      X509_STORE_add_cert (om->cert_store, testcert);
      X509_free (testcert);
      rv = 0;
    }
  return (rv < 0 ? -1 : 0);
}

int
openssl_tls_ctx_attribute (tls_ctx_t *ctx, u8 is_get,
			   transport_endpt_attr_t *attr)
{
  openssl_ctx_t *oc = (openssl_ctx_t *) ctx;
  int rv = 0;

  if (!is_get)
    return -1;

  switch (attr->type)
    {
    case TRANSPORT_ENDPT_ATTR_TLS_PEER_CERT:
      {
	X509 *peer_cert = SSL_get_peer_certificate (oc->ssl);
	if (!peer_cert)
	  {
	    rv = -1;
	    break;
	  }
	attr->tls_peer_cert.cert = peer_cert;
      }
      break;
    default:
      rv = -1;
      break;
    }
  return rv;
}

int
openssl_reinit_ca_chain (void)
{
  openssl_main_t *om = &openssl_main;

  /* Remove/free existing x509_store */
  if (om->cert_store)
    {
      X509_STORE_free (om->cert_store);
    }
  return tls_init_ca_chain ();
}

const static tls_engine_vft_t openssl_engine = {
  .ctx_alloc = openssl_ctx_alloc,
  .ctx_alloc_w_thread = openssl_ctx_alloc_w_thread,
  .ctx_free = openssl_ctx_free,
  .ctx_attach = openssl_ctx_attach,
  .ctx_detach = openssl_ctx_detach,
  .ctx_get = openssl_ctx_get,
  .ctx_get_w_thread = openssl_ctx_get_w_thread,
  .ctx_init_server = openssl_ctx_init_server,
  .ctx_init_client = openssl_ctx_init_client,
  .ctx_write = openssl_ctx_write,
  .ctx_read = openssl_ctx_read,
  .ctx_start_listen = openssl_start_listen,
  .ctx_stop_listen = openssl_stop_listen,
  .ctx_transport_close = openssl_transport_close,
  .ctx_transport_reset = openssl_transport_reset,
  .ctx_app_close = openssl_app_close,
  .ctx_attribute = openssl_tls_ctx_attribute,
  .ctx_reinit_cachain = openssl_reinit_ca_chain,
};

int
tls_openssl_set_ciphers (char *ciphers)
{
  openssl_main_t *om = &openssl_main;

  if (!ciphers)
    {
      return -1;
    }

  vec_validate_init_c_string (om->ciphers, ciphers, strlen (ciphers));

  return 0;

}

static clib_error_t *
tls_openssl_init (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  openssl_main_t *om = &openssl_main;
  clib_error_t *error = 0;
  u32 num_threads, i;

  error = tls_openssl_api_init (vm);
  num_threads = 1 /* main thread */  + vtm->n_threads;

  SSL_library_init ();
  SSL_load_error_strings ();

  vec_validate (om->ctx_pool, num_threads - 1);
  vec_validate (om->rx_bufs, num_threads - 1);
  vec_validate (om->tx_bufs, num_threads - 1);
  vec_validate (om->default_client_ssl_ctx, num_threads - 1);
  vec_validate (om->default_dtls_client_ssl_ctx, num_threads - 1);

  for (i = 0; i < num_threads; i++)
    {
      vec_validate (om->rx_bufs[i], DTLSO_MAX_BUFSIZE);
      vec_validate (om->tx_bufs[i], DTLSO_MAX_BUFSIZE);
    }
  tls_register_engine (&openssl_engine, CRYPTO_ENGINE_OPENSSL);

  om->engine_init = 0;

  /* default ciphers */
  tls_openssl_set_ciphers
    ("ALL:!ADH:!LOW:!EXP:!MD5:!RC4-SHA:!DES-CBC3-SHA:@STRENGTH");

  if (tls_init_ca_chain ())
    {
      clib_warning ("failed to initialize TLS CA chain");
      return 0;
    }

  return error;
}
VLIB_INIT_FUNCTION (tls_openssl_init) =
{
  .runs_after = VLIB_INITS("tls_init"),
};

static clib_error_t *
tls_openssl_set_command_fn (vlib_main_t * vm, unformat_input_t * input,
			    vlib_cli_command_t * cmd)
{
  openssl_main_t *om = &openssl_main;
  char *engine_name = NULL;
  char *engine_alg = NULL;
  char *ciphers = NULL;
  u8 engine_name_set = 0;
  int i, async = 0;

  /* By present, it is not allowed to configure engine again after running */
  if (om->engine_init)
    {
      clib_warning ("engine has started!\n");
      return clib_error_return
	(0, "engine has started, and no config is accepted");
    }

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "engine %s", &engine_name))
	{
	  engine_name_set = 1;
	}
      else if (unformat (input, "async"))
	{
	  async = 1;
	}
      else if (unformat (input, "alg %s", &engine_alg))
	{
	  for (i = 0; i < strnlen (engine_alg, MAX_CRYPTO_LEN); i++)
	    engine_alg[i] = toupper (engine_alg[i]);
	}
      else if (unformat (input, "ciphers %s", &ciphers))
	{
	  tls_openssl_set_ciphers (ciphers);
	}
      else
	return clib_error_return (0, "failed: unknown input `%U'",
				  format_unformat_error, input);
    }

  /* reset parameters if engine is not configured */
  if (!engine_name_set)
    {
      clib_warning ("No engine provided! \n");
      async = 0;
    }
  else
    {
      session_enable_disable_args_t args = { .is_en = 1,
					     .rt_engine_type =
					       RT_BACKEND_ENGINE_RULE_TABLE };
      vnet_session_enable_disable (vm, &args);
      if (openssl_engine_register (engine_name, engine_alg, async) < 0)
	{
	  return clib_error_return (0, "Failed to register %s polling",
				    engine_name);
	}
      else
	{
	  vlib_cli_output (vm, "Successfully register engine %s\n",
			   engine_name);
	}
    }
  om->async = async;

  return 0;
}

VLIB_CLI_COMMAND (tls_openssl_set_command, static) =
{
  .path = "tls openssl set",
  .short_help = "tls openssl set [engine <engine name>] [alg [algorithm] [async]",
  .function = tls_openssl_set_command_fn,
};

static clib_error_t *
tls_openssl_set_tls_fn (vlib_main_t *vm, unformat_input_t *input,
			vlib_cli_command_t *cmd)
{
  openssl_main_t *om = &openssl_main;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "record-size %U", unformat_memory_size,
		    &om->record_size))
	{
	  clib_warning ("Using TLS record-size of %d", om->record_size);
	}
      else if (unformat (input, "record-split-size %U", unformat_memory_size,
			 &om->record_split_size))
	{
	  clib_warning ("Using TLS record-split-size of %d",
			om->record_split_size);
	}
      else if (unformat (input, "max-pipelines %U", unformat_memory_size,
			 &om->max_pipelines))
	{
	  clib_warning ("Using TLS max-pipelines of %d", om->max_pipelines);
	}
      else
	return clib_error_return (0, "failed: unknown input `%U'",
				  format_unformat_error, input);
    }

  return 0;
}

VLIB_CLI_COMMAND (tls_openssl_set_tls, static) = {
  .path = "tls openssl set-tls",
  .short_help = "tls openssl set-tls [record-size <size>] [record-split-size "
		"<size>] [max-pipelines <size>]",
  .function = tls_openssl_set_tls_fn,
};

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Transport Layer Security (TLS) Engine, OpenSSL Based",
};
