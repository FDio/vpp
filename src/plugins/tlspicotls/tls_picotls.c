#include <math.h>

#include "certs.h"
#include "tls_picotls.h"

picotls_main_t picotls_main;

#define MAX_QUEUE 12000
#define PTLS_MAX_PLAINTEXT_RECORD_SIZE 16384

static u32
picotls_ctx_alloc (void)
{
  u8 thread_id = vlib_get_thread_index ();
  picotls_main_t *pm = &picotls_main;
  picotls_ctx_t **ctx;

  pool_get (pm->ctx_pool[thread_id], ctx);
  if (!(*ctx))
    *ctx = clib_mem_alloc (sizeof (picotls_ctx_t));

  clib_memset (*ctx, 0, sizeof (picotls_ctx_t));
  (*ctx)->ctx.c_thread_index = thread_id;
  (*ctx)->ctx.tls_ctx_engine = CRYPTO_ENGINE_PICOTLS;
  (*ctx)->ctx.app_session_handle = SESSION_INVALID_HANDLE;
  (*ctx)->ptls_ctx_idx = ctx - pm->ctx_pool[thread_id];
  return (*ctx)->ptls_ctx_idx;
}

static void
picotls_ctx_free (tls_ctx_t * ctx)
{
  picotls_ctx_t *ptls_ctx = (picotls_ctx_t *) ctx;
  free (ptls_ctx->rx_content);
  pool_put_index (picotls_main.ctx_pool[ctx->c_thread_index],
		  ptls_ctx->ptls_ctx_idx);
}

static u32
picotls_listen_ctx_alloc (void)
{
  picotls_main_t *pm = &picotls_main;
  picotls_listen_ctx_t *ptls_lctx;

  pool_get (pm->lctx_pool, ptls_lctx);

  clib_memset (ptls_lctx, 0, sizeof (picotls_listen_ctx_t));
  ptls_lctx->ptls_lctx_index = ptls_lctx - pm->lctx_pool;
  return ptls_lctx->ptls_lctx_index;
}

static void
picotls_listen_ctx_free (picotls_listen_ctx_t * lctx)
{
  pool_put_index (picotls_main.lctx_pool, lctx->ptls_lctx_index);
}

tls_ctx_t *
picotls_ctx_get (u32 ctx_index)
{
  picotls_ctx_t **ctx;
  ctx =
    pool_elt_at_index (picotls_main.ctx_pool[vlib_get_thread_index ()],
		       ctx_index);
  return &(*ctx)->ctx;
}

picotls_listen_ctx_t *
picotls_lctx_get (u32 lctx_index)
{
  return pool_elt_at_index (picotls_main.lctx_pool, lctx_index);
}

static u8
picotls_handshake_is_over (tls_ctx_t * ctx)
{
  picotls_ctx_t *ptls_ctx = (picotls_ctx_t *) ctx;
  assert (ptls_ctx->tls);
  return ptls_handshake_is_complete (ptls_ctx->tls);
}

static int
picotls_try_handshake_write (picotls_ctx_t * ptls_ctx,
			     session_t * tls_session, ptls_buffer_t * buf)
{
  u32 enq_max, enq_now;
  svm_fifo_t *f;
  int write, buf_left;

  if (buf->off <= 0)
    return 0;

  f = tls_session->tx_fifo;
  buf_left = buf->off;
  enq_max = svm_fifo_max_enqueue_prod (f);
  if (!enq_max)
    return 0;

  enq_now = clib_min (svm_fifo_max_write_chunk (f), enq_max);
  enq_now = clib_min (enq_now, buf_left);
  write = svm_fifo_enqueue (f, enq_now, buf->base);
  buf_left -= write;
  tls_add_vpp_q_tx_evt (tls_session);
  return write;
}

static int
picotls_start_listen (tls_ctx_t * lctx)
{
  picotls_listen_ctx_t *ptls_lctx;
  ptls_context_t *ptls_ctx;
  u32 ptls_lctx_idx;
  app_cert_key_pair_t *ckpair;
  static ptls_key_exchange_algorithm_t *key_exchange[] = {
#ifdef PTLS_OPENSSL_HAVE_X25519
    &ptls_openssl_x25519,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP256r1
    &ptls_openssl_secp256r1,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP384r1
    &ptls_openssl_secp384r1,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP521r1
    &ptls_openssl_secp521r1
#endif
  };

  ckpair = app_cert_key_pair_get_if_valid (lctx->ckpair_index);
  if (!ckpair || !ckpair->cert || !ckpair->key)
    {
      TLS_DBG (1, "tls cert and/or key not configured %d",
	       ctx->parent_app_wrk_index);
      return -1;
    }

  ptls_lctx_idx = picotls_listen_ctx_alloc ();
  ptls_lctx = picotls_lctx_get (ptls_lctx_idx);
  ptls_ctx = malloc (sizeof (ptls_context_t));
  ptls_lctx->ptls_ctx = ptls_ctx;

  memset (ptls_ctx, 0, sizeof (ptls_context_t));
  ptls_ctx->update_open_count = NULL;

  /*
   * Process certificate & private key.
   */
  load_bio_certificate_chain (ptls_ctx, (char *) ckpair->cert);
  load_bio_private_key (ptls_ctx, (char *) ckpair->key);

  /* setup protocol related functions */
  ptls_ctx->key_exchanges = key_exchange;
  ptls_ctx->random_bytes = ptls_openssl_random_bytes;
  ptls_ctx->cipher_suites = ptls_openssl_cipher_suites;
  ptls_ctx->get_time = &ptls_get_time;

  lctx->tls_ssl_ctx = ptls_lctx_idx;

  return 0;
}

static int
picotls_stop_listen (tls_ctx_t * lctx)
{
  u32 ptls_lctx_index;
  picotls_listen_ctx_t *ptls_lctx;

  ptls_lctx_index = lctx->tls_ssl_ctx;
  ptls_lctx = picotls_lctx_get (ptls_lctx_index);

  picotls_listen_ctx_free (ptls_lctx);

  return 0;
}

static void
picotls_handle_handshake_failure (tls_ctx_t * ctx)
{
  session_free (session_get (ctx->c_s_index, ctx->c_thread_index));
  ctx->no_app_session = 1;
  ctx->c_s_index = SESSION_INVALID_INDEX;
  tls_disconnect_transport (ctx);
}

static void
picotls_confirm_app_close (tls_ctx_t * ctx)
{
  tls_disconnect_transport (ctx);
  session_transport_closed_notify (&ctx->connection);
}

static int
picotls_transport_close (tls_ctx_t * ctx)
{
  if (!picotls_handshake_is_over (ctx))
    {
      picotls_handle_handshake_failure (ctx);
      return 0;
    }
  picotls_ctx_t *ptls_ctx = (picotls_ctx_t *) ctx;
  ptls_free (ptls_ctx->tls);
  session_transport_closed_notify (&ctx->connection);
  return 0;
}

static int
picotls_app_close (tls_ctx_t * ctx)
{
  session_t *app_session;

  app_session = session_get_from_handle (ctx->app_session_handle);
  if (!svm_fifo_max_dequeue_cons (app_session->tx_fifo))
    picotls_confirm_app_close (ctx);
  else
    ctx->app_closed = 1;

  return 0;
}

static inline int
picotls_do_handshake (picotls_ctx_t * ptls_ctx, session_t * tls_session,
		      u8 * input, int input_len)
{
  ptls_t *tls = ptls_ctx->tls;
  ptls_buffer_t buf;
  int rv = PTLS_ERROR_IN_PROGRESS;
  int write = 0, off;

  do
    {
      off = 0;
      do
	{
	  ptls_buffer_init (&buf, "", 0);
	  size_t consumed = input_len - off;
	  rv = ptls_handshake (tls, &buf, input + off, &consumed, NULL);
	  off += consumed;
	  if ((rv == 0 || rv == PTLS_ERROR_IN_PROGRESS) && buf.off != 0)
	    {
	      write = picotls_try_handshake_write (ptls_ctx, tls_session,
						   &buf);
	    }
	  ptls_buffer_dispose (&buf);
	}
      while (rv == PTLS_ERROR_IN_PROGRESS && input_len != off);
    }
  while (rv == PTLS_ERROR_IN_PROGRESS);

  return write;
}

static inline int
picotls_ctx_read (tls_ctx_t * ctx, session_t * tls_session)
{
  picotls_ctx_t *ptls_ctx = (picotls_ctx_t *) ctx;
  u8 *input;
  int to_read, from_tls_len = 0, to_app_len = 0, crypto_len, ret;
  u32 deq_max, deq_now;
  u32 enq_max, enq_now;
  ptls_buffer_t _buf, *buf = &_buf;
  svm_fifo_t *tls_rx_fifo, *app_rx_fifo;
  session_t *app_session;

  tls_rx_fifo = tls_session->rx_fifo;

  if (!picotls_handshake_is_over (ctx))
    {
      deq_max = svm_fifo_max_dequeue_cons (tls_rx_fifo);
      input = clib_mem_alloc (deq_max);
      memset (input, 0, deq_max);

      deq_now = clib_min (deq_max, svm_fifo_max_read_chunk (tls_rx_fifo));
      if (!deq_now)
	goto done_hs;

      from_tls_len += svm_fifo_dequeue (tls_rx_fifo, deq_now, input);
      if (from_tls_len <= 0)
	{
	  tls_add_vpp_q_builtin_rx_evt (tls_session);
	  goto done_hs;
	}
      if (from_tls_len < deq_max)
	{
	  deq_now = clib_min (svm_fifo_max_read_chunk (tls_rx_fifo),
			      deq_max - from_tls_len);
	  from_tls_len += svm_fifo_dequeue (tls_rx_fifo, deq_now,
					    input + from_tls_len);
	}
      picotls_do_handshake (ptls_ctx, tls_session, input, from_tls_len);
      if (picotls_handshake_is_over (ctx))
	tls_notify_app_accept (ctx);

    done_hs:
      clib_mem_free (input);
      return 0;
    }

  app_session = session_get_from_handle (ctx->app_session_handle);
  app_rx_fifo = app_session->rx_fifo;

  ptls_buffer_init (buf, "", 0);

  deq_max = svm_fifo_max_dequeue_cons (tls_rx_fifo);

  if (!deq_max || deq_max > MAX_QUEUE - ptls_ctx->rx_len)
    {
      goto app_fifo;
    }

  deq_now = clib_min (deq_max, svm_fifo_max_read_chunk (tls_rx_fifo));

  from_tls_len =
    svm_fifo_dequeue (tls_rx_fifo, deq_now,
		      ptls_ctx->rx_content + ptls_ctx->rx_len);
  if (from_tls_len <= 0)
    {
      tls_add_vpp_q_builtin_rx_evt (tls_session);
      goto app_fifo;
    }
  if (from_tls_len < deq_max)
    {
      deq_now =
	clib_min (svm_fifo_max_read_chunk (tls_rx_fifo),
		  deq_max - from_tls_len);
      from_tls_len +=
	svm_fifo_dequeue (tls_rx_fifo, deq_now,
			  ptls_ctx->rx_content + ptls_ctx->rx_len +
			  from_tls_len);
    }
  ptls_ctx->rx_len += from_tls_len;

app_fifo:
  if (ptls_ctx->rx_len <= 0 || ptls_ctx->rx_offset == ptls_ctx->rx_len)
    {
      if (ptls_ctx->rx_len != 0)
	{
	  ptls_ctx->rx_len = 0;
	  ptls_ctx->rx_offset = 0;
	  tls_add_vpp_q_builtin_rx_evt (tls_session);
	}
      return from_tls_len;
    }

  enq_max = svm_fifo_max_enqueue_prod (app_rx_fifo);
  if (!enq_max)
    {
      tls_add_vpp_q_builtin_rx_evt (tls_session);
      goto final;
    }

  crypto_len = clib_min (enq_max, ptls_ctx->rx_len - ptls_ctx->rx_offset);
  crypto_len = clib_min (crypto_len, from_tls_len);
  int off = 0;

  do
    {
      size_t consumed = crypto_len - off;
      ret =
	ptls_receive (ptls_ctx->tls, buf,
		      ptls_ctx->rx_content + ptls_ctx->rx_offset + off,
		      &consumed);
      off += consumed;
    }
  while (ret == 0 && off < crypto_len);

  if (ret == 0)
    {
      ptls_ctx->rx_offset += crypto_len;

      to_read = clib_min (enq_max, buf->off);
      enq_now = clib_min (to_read, svm_fifo_max_write_chunk (app_rx_fifo));
      to_app_len = svm_fifo_enqueue (app_rx_fifo, enq_now, buf->base);
      if (to_app_len < buf->off)
	{
	  enq_now =
	    clib_min (svm_fifo_max_write_chunk (app_rx_fifo),
		      buf->off - to_app_len);
	  to_app_len +=
	    svm_fifo_enqueue (app_rx_fifo, enq_now, buf->base + to_app_len);
	}
    }

final:
  ptls_buffer_dispose (buf);
  if (ctx->app_closed)
    {
      picotls_confirm_app_close (ctx);
      return from_tls_len;
    }

  tls_notify_app_enqueue (ctx, app_session);
  return from_tls_len;
}

static inline int
picotls_content_process (ptls_t * tls, svm_fifo_t * src_fifo,
			 svm_fifo_t * dst_fifo, int content_len,
			 int total_record_overhead, int is_no_copy)
{
  ptls_buffer_t _buf, *buf = &_buf;
  int total_length = content_len + total_record_overhead;
  int to_dst_len;
  if (is_no_copy)
    {
      ptls_buffer_init (buf, svm_fifo_tail (dst_fifo), total_length);
      ptls_send (tls, buf, svm_fifo_head (src_fifo), content_len);

      assert (!buf->is_allocated);
      assert (buf->base == svm_fifo_tail (dst_fifo));

      svm_fifo_dequeue_drop (src_fifo, content_len);
      svm_fifo_enqueue_nocopy (dst_fifo, buf->off);
      to_dst_len = buf->off;
    }
  else
    {
      uint8_t *buf_content = malloc (total_length);
      ptls_buffer_init (buf, buf_content, total_length);

      ptls_send (tls, buf, svm_fifo_head (src_fifo), content_len);
      svm_fifo_dequeue_drop (src_fifo, content_len);

      to_dst_len = svm_fifo_enqueue (dst_fifo, buf->off, buf->base);
      if (to_dst_len < buf->off)
	to_dst_len +=
	  svm_fifo_enqueue (dst_fifo, buf->off - to_dst_len,
			    buf->base + to_dst_len);
      ptls_buffer_dispose (buf);
    }
  return to_dst_len;
}

static inline int
picotls_ctx_write (tls_ctx_t * ctx, session_t * app_session)
{
  picotls_ctx_t *ptls_ctx = (picotls_ctx_t *) ctx;
  u32 deq_max, deq_now;
  u32 enq_max, enq_now;
  int from_app_len = 0, to_tls_len = 0, is_nocopy = 0;
  svm_fifo_t *tls_tx_fifo, *app_tx_fifo;
  session_t *tls_session;

  int record_overhead = ptls_get_record_overhead (ptls_ctx->tls);
  int num_records, total_overhead;

  tls_session = session_get_from_handle (ctx->tls_session_handle);
  tls_tx_fifo = tls_session->tx_fifo;
  app_tx_fifo = app_session->tx_fifo;

  deq_max = svm_fifo_max_dequeue_cons (app_tx_fifo);
  if (!deq_max)
    return deq_max;
  deq_now = clib_min (deq_max, svm_fifo_max_read_chunk (app_tx_fifo));

  enq_max = svm_fifo_max_enqueue_prod (tls_tx_fifo);

    /** There is no engough enqueue space for one record **/
  if (enq_max < record_overhead)
    {
      tls_add_vpp_q_builtin_tx_evt (app_session);
      return 0;
    }

  enq_now = clib_min (enq_max, svm_fifo_max_write_chunk (tls_tx_fifo));

    /** Allowed to execute no-copy crypto operation **/
  if (enq_now > record_overhead)
    {
      is_nocopy = 1;
      from_app_len = clib_min (deq_now, enq_now);
      num_records =
	ceil ((f64) from_app_len / PTLS_MAX_PLAINTEXT_RECORD_SIZE);
      total_overhead = num_records * record_overhead;
      if (from_app_len + total_overhead > enq_now)
	from_app_len = enq_now - total_overhead;


    }
  else
    {
      from_app_len = clib_min (deq_now, enq_max);
      num_records =
	ceil ((f64) from_app_len / PTLS_MAX_PLAINTEXT_RECORD_SIZE);
      total_overhead = num_records * record_overhead;
      if (from_app_len + total_overhead > enq_max)
	from_app_len = enq_max - total_overhead;

    }

  to_tls_len =
    picotls_content_process (ptls_ctx->tls, app_tx_fifo, tls_tx_fifo,
			     from_app_len, total_overhead, is_nocopy);

  if (svm_fifo_needs_deq_ntf (app_tx_fifo, from_app_len))
    session_dequeue_notify (app_session);

  if (to_tls_len)
    tls_add_vpp_q_tx_evt (tls_session);
  tls_add_vpp_q_builtin_tx_evt (app_session);

  if (ctx->app_closed)
    picotls_app_close (ctx);

  return 0;
}

static int
picotls_ctx_init_server (tls_ctx_t * ctx)
{
  picotls_ctx_t *ptls_ctx = (picotls_ctx_t *) ctx;
  u32 ptls_lctx_idx = ctx->tls_ssl_ctx;
  picotls_listen_ctx_t *ptls_lctx;

  ptls_lctx = picotls_lctx_get (ptls_lctx_idx);
  ptls_ctx->tls = ptls_new (ptls_lctx->ptls_ctx, 1);
  if (ptls_ctx->tls == NULL)
    {
      TLS_DBG (1, "Failed to initialize ptls_ssl structure");
      return -1;
    }

  ptls_ctx->rx_len = 0;
  ptls_ctx->rx_offset = 0;

  ptls_ctx->rx_content = malloc (MAX_QUEUE);

  return 0;
}

tls_ctx_t *
picotls_ctx_get_w_thread (u32 ctx_index, u8 thread_index)
{
  picotls_ctx_t **ctx;
  ctx = pool_elt_at_index (picotls_main.ctx_pool[thread_index], ctx_index);
  return &(*ctx)->ctx;
}

const static tls_engine_vft_t picotls_engine = {
  .ctx_alloc = picotls_ctx_alloc,
  .ctx_free = picotls_ctx_free,
  .ctx_get = picotls_ctx_get,
  .ctx_get_w_thread = picotls_ctx_get_w_thread,
  .ctx_handshake_is_over = picotls_handshake_is_over,
  .ctx_start_listen = picotls_start_listen,
  .ctx_stop_listen = picotls_stop_listen,
  .ctx_init_server = picotls_ctx_init_server,
  .ctx_read = picotls_ctx_read,
  .ctx_write = picotls_ctx_write,
  .ctx_transport_close = picotls_transport_close,
  .ctx_app_close = picotls_app_close,
};

static clib_error_t *
tls_picotls_init (vlib_main_t * vm)
{
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  picotls_main_t *pm = &picotls_main;
  clib_error_t *error = 0;
  u32 num_threads;

  num_threads = 1 + vtm->n_threads;

  vec_validate (pm->ctx_pool, num_threads - 1);

  tls_register_engine (&picotls_engine, CRYPTO_ENGINE_PICOTLS);

  return error;
}

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION (tls_picotls_init) = {
  .runs_after = VLIB_INITS ("tls_init"),
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Transport Layer Security (TLS) Engine, Picotls Based",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
