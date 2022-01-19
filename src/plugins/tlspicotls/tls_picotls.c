#include <math.h>

#include <tlspicotls/certs.h>
#include <tlspicotls/tls_picotls.h>
#include <tlspicotls/pico_vpp_crypto.h>

picotls_main_t picotls_main;

#define MAX_QUEUE 12000
#define PTLS_MAX_PLAINTEXT_RECORD_SIZE 16384

static ptls_key_exchange_algorithm_t *default_key_exchange[] = {
#ifdef PTLS_OPENSSL_HAVE_X25519
  &ptls_openssl_x25519,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP256R1
  &ptls_openssl_secp256r1,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP384R1
  &ptls_openssl_secp384r1,
#endif
#ifdef PTLS_OPENSSL_HAVE_SECP521R1
  &ptls_openssl_secp521r1
#endif
};

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
  vec_free (ptls_ctx->rx_content);
  ptls_free (ptls_ctx->tls);
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

  ckpair = app_cert_key_pair_get_if_valid (lctx->ckpair_index);
  if (!ckpair || !ckpair->cert || !ckpair->key)
    {
      TLS_DBG (1, "tls cert and/or key not configured %d",
	       lctx->parent_app_wrk_index);
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
  ptls_ctx->key_exchanges = default_key_exchange;
  ptls_ctx->random_bytes = ptls_openssl_random_bytes;
  ptls_ctx->cipher_suites = ptls_vpp_crypto_cipher_suites;
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
  session_transport_closing_notify (&ctx->connection);
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
picotls_do_handshake (picotls_ctx_t *ptls_ctx, session_t *tcp_session)
{
  int rv = PTLS_ERROR_IN_PROGRESS, write = 0, i = 0, read = 0, len;
  svm_fifo_t *tcp_rx_fifo = tcp_session->rx_fifo;
  ptls_buffer_t *buf = &ptls_ctx->read_buffer;
  u32 n_segs = 2, max_len = 16384;
  ptls_t *tls = ptls_ctx->tls;
  svm_fifo_seg_t fs[n_segs];
  uword deq_now;

  ptls_buffer_init (buf, "", 0);

  len = svm_fifo_segments (tcp_rx_fifo, 0, fs, &n_segs, max_len);
  if (len <= 0)
    return 0;

  while (read < len && i < n_segs)
    {
      deq_now = fs[i].len;
      rv = ptls_handshake (tls, buf, fs[i].data, &deq_now, NULL);

      write += picotls_try_handshake_write (ptls_ctx, tcp_session, buf);
      read += deq_now;

      if (!(rv == 0 || rv == PTLS_ERROR_IN_PROGRESS))
	{
	  clib_error ("unexpected error %u", rv);
	  break;
	}

      if (!rv)
	break;

      if (deq_now < fs[i].len)
	{
	  fs[i].data += deq_now;
	  fs[i].len -= deq_now;
	}
      else
	i++;
    }

  if (read)
    svm_fifo_dequeue_drop (tcp_rx_fifo, read);

  ptls_buffer_dispose (buf);

  return write;
}

static inline int
ptls_copy_buf_to_fs (ptls_buffer_t *buf, u32 to_copy, svm_fifo_seg_t *fs,
		     u32 *fs_idx, u32 max_fs)
{
  u32 idx = *fs_idx;

  while (to_copy)
    {
      if (fs[idx].len <= to_copy)
	{
	  clib_memcpy_fast (fs[idx].data, buf->base + (buf->off - to_copy),
			    fs[idx].len);
	  to_copy -= fs[idx].len;
	  idx += 1;
	  /* no more space in the app's rx fifo */
	  if (idx == max_fs)
	    break;
	}
      else
	{
	  clib_memcpy_fast (fs[idx].data, buf->base + (buf->off - to_copy),
			    to_copy);
	  fs[idx].len -= to_copy;
	  fs[idx].data += to_copy;
	  to_copy = 0;
	}
    }

  *fs_idx = idx;

  return to_copy;
}

static u32
ptls_tcp_to_app_write (picotls_ctx_t *ptls_ctx, svm_fifo_t *app_rx_fifo,
		       svm_fifo_t *tcp_rx_fifo)
{
  u32 ai = 0, thread_index, min_buf_len, to_copy, left, wrote = 0;
  ptls_buffer_t *buf = &ptls_ctx->read_buffer;
  int ret, i = 0, read = 0, tcp_len, n_fs_app;
  u32 n_segs = 4, max_len = 1 << 16;
  svm_fifo_seg_t tcp_fs[n_segs], app_fs[n_segs];
  picotls_main_t *pm = &picotls_main;
  uword deq_now;
  u8 is_nocopy;

  thread_index = ptls_ctx->ctx.c_thread_index;

  n_fs_app = svm_fifo_provision_chunks (app_rx_fifo, app_fs, n_segs, max_len);
  if (n_fs_app <= 0)
    return 0;

  tcp_len = svm_fifo_segments (tcp_rx_fifo, 0, tcp_fs, &n_segs, max_len);
  if (tcp_len <= 0)
    return 0;

  if (ptls_ctx->read_buffer_offset)
    {
      to_copy = buf->off - ptls_ctx->read_buffer_offset;
      left = ptls_copy_buf_to_fs (buf, to_copy, app_fs, &ai, n_fs_app);
      wrote += to_copy - left;
      if (left)
	{
	  ptls_ctx->read_buffer_offset = buf->off - left;
	  goto do_checks;
	}
      ptls_ctx->read_buffer_offset = 0;
    }

  while (ai < n_fs_app && read < tcp_len)
    {
      deq_now = clib_min (tcp_fs[i].len, tcp_len - read);
      min_buf_len = deq_now + (16 << 10);
      is_nocopy = app_fs[ai].len < min_buf_len ? 0 : 1;
      if (is_nocopy)
	{
	  ptls_buffer_init (buf, app_fs[ai].data, app_fs[ai].len);
	  ret = ptls_receive (ptls_ctx->tls, buf, tcp_fs[i].data, &deq_now);
	  assert (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS);

	  wrote += buf->off;
	  if (buf->off == app_fs[ai].len)
	    {
	      ai++;
	    }
	  else
	    {
	      app_fs[ai].len -= buf->off;
	      app_fs[ai].data += buf->off;
	    }
	}
      else
	{
	  vec_validate (pm->rx_bufs[thread_index], min_buf_len);
	  ptls_buffer_init (buf, pm->rx_bufs[thread_index], min_buf_len);
	  ret = ptls_receive (ptls_ctx->tls, buf, tcp_fs[i].data, &deq_now);
	  assert (ret == 0 || ret == PTLS_ERROR_IN_PROGRESS);

	  left = ptls_copy_buf_to_fs (buf, buf->off, app_fs, &ai, n_fs_app);
	  if (!left)
	    {
	      ptls_ctx->read_buffer_offset = 0;
	      wrote += buf->off;
	    }
	  else
	    {
	      ptls_ctx->read_buffer_offset = buf->off - left;
	      wrote += ptls_ctx->read_buffer_offset;
	    }
	}

      assert (deq_now <= tcp_fs[i].len);
      read += deq_now;
      if (deq_now < tcp_fs[i].len)
	{
	  tcp_fs[i].data += deq_now;
	  tcp_fs[i].len -= deq_now;
	}
      else
	i++;
    }

do_checks:

  if (read)
    {
      svm_fifo_dequeue_drop (tcp_rx_fifo, read);
      if (svm_fifo_needs_deq_ntf (tcp_rx_fifo, read))
	{
	  svm_fifo_clear_deq_ntf (tcp_rx_fifo);
	  session_send_io_evt_to_thread (tcp_rx_fifo, SESSION_IO_EVT_RX);
	}
    }

  if (wrote)
    svm_fifo_enqueue_nocopy (app_rx_fifo, wrote);

  return wrote;
}

static inline int
picotls_ctx_read (tls_ctx_t *ctx, session_t *tcp_session)
{
  picotls_ctx_t *ptls_ctx = (picotls_ctx_t *) ctx;
  svm_fifo_t *tcp_rx_fifo;
  session_t *app_session;
  int wrote;

  if (PREDICT_FALSE (!ptls_handshake_is_complete (ptls_ctx->tls)))
    {
      picotls_do_handshake (ptls_ctx, tcp_session);
      if (picotls_handshake_is_over (ctx))
	{
	  if (ptls_is_server (ptls_ctx->tls))
	    {
	      if (tls_notify_app_accept (ctx))
		{
		  ctx->c_s_index = SESSION_INVALID_INDEX;
		  tls_disconnect_transport (ctx);
		  return -1;
		}
	    }
	  else
	    {
	      tls_notify_app_connected (ctx, SESSION_E_NONE);
	    }
	}

      if (!svm_fifo_max_dequeue (tcp_session->rx_fifo))
	return 0;
    }

  tcp_rx_fifo = tcp_session->rx_fifo;
  app_session = session_get_from_handle (ctx->app_session_handle);
  wrote = ptls_tcp_to_app_write (ptls_ctx, app_session->rx_fifo, tcp_rx_fifo);

  if (wrote && app_session->session_state >= SESSION_STATE_READY)
    tls_notify_app_enqueue (ctx, app_session);

  if (ptls_ctx->read_buffer_offset || svm_fifo_max_dequeue (tcp_rx_fifo))
    tls_add_vpp_q_builtin_rx_evt (tcp_session);

  return wrote;
}

static inline u32
ptls_compute_deq_len (picotls_ctx_t *ptls_ctx, u32 dst_chunk, u32 src_chunk,
		      u32 dst_space, u8 *is_nocopy)
{
  int record_overhead = ptls_get_record_overhead (ptls_ctx->tls);
  int num_records;
  u32 deq_len, total_overhead;

  if (dst_chunk >= clib_min (8192, src_chunk + record_overhead))
    {
      *is_nocopy = 1;
      deq_len = clib_min (src_chunk, dst_chunk);
      num_records = ceil ((f64) deq_len / PTLS_MAX_PLAINTEXT_RECORD_SIZE);
      total_overhead = num_records * record_overhead;
      if (deq_len + total_overhead > dst_chunk)
	deq_len = dst_chunk - total_overhead;
    }
  else
    {
      deq_len = clib_min (src_chunk, dst_space);
      num_records = ceil ((f64) deq_len / PTLS_MAX_PLAINTEXT_RECORD_SIZE);
      total_overhead = num_records * record_overhead;
      if (deq_len + total_overhead > dst_space)
	deq_len = dst_space - total_overhead;
    }

  return deq_len;
}

static u32
ptls_app_to_tcp_write (picotls_ctx_t *ptls_ctx, session_t *app_session,
		       svm_fifo_t *tcp_tx_fifo, u32 max_len)
{
  u32 wrote = 0, max_enq, thread_index, app_buf_len, left, ti = 0;
  int read = 0, rv, i = 0, len, n_tcp_segs = 4, deq_len;
  u32 n_app_segs = 2, min_chunk = 2048;
  svm_fifo_seg_t app_fs[n_app_segs], tcp_fs[n_tcp_segs];
  picotls_main_t *pm = &picotls_main;
  ptls_buffer_t _buf, *buf = &_buf;
  svm_fifo_t *app_tx_fifo;
  u8 is_nocopy, *app_buf;
  u32 first_chunk_len;

  thread_index = app_session->thread_index;
  app_tx_fifo = app_session->tx_fifo;

  len = svm_fifo_segments (app_tx_fifo, 0, app_fs, &n_app_segs, max_len);
  if (len <= 0)
    return 0;

  n_tcp_segs = svm_fifo_provision_chunks (tcp_tx_fifo, tcp_fs, n_tcp_segs,
					  1000 + max_len);
  if (n_tcp_segs <= 0)
    return 0;

  while ((left = len - read) && ti < n_tcp_segs)
    {
      /* If we wrote something and are left with few bytes, postpone write
       * as we may be able to encrypt a bigger chunk next time */
      if (wrote && left < min_chunk)
	break;

      /* Avoid short records if possible */
      if (app_fs[i].len < min_chunk && min_chunk < left)
	{
	  app_buf_len = app_fs[i].len + app_fs[i + 1].len;
	  app_buf = pm->rx_bufs[thread_index];
	  vec_validate (pm->rx_bufs[thread_index], app_buf_len);
	  clib_memcpy_fast (pm->rx_bufs[thread_index], app_fs[i].data,
			    app_fs[i].len);
	  clib_memcpy_fast (pm->rx_bufs[thread_index] + app_fs[i].len,
			    app_fs[i + 1].data, app_buf_len - app_fs[i].len);
	  first_chunk_len = app_fs[i].len;
	  i += 1;
	}
      else
	{
	  app_buf = app_fs[i].data;
	  app_buf_len = app_fs[i].len;
	  first_chunk_len = 0;
	}

      is_nocopy = 0;
      max_enq = tcp_fs[ti].len;
      max_enq += ti < (n_tcp_segs - 1) ? tcp_fs[ti + 1].len : 0;

      deq_len = ptls_compute_deq_len (ptls_ctx, tcp_fs[ti].len, app_buf_len,
				      max_enq, &is_nocopy);
      if (is_nocopy)
	{
	  ptls_buffer_init (buf, tcp_fs[ti].data, tcp_fs[ti].len);
	  rv = ptls_send (ptls_ctx->tls, buf, app_buf, deq_len);

	  assert (rv == 0);
	  wrote += buf->off;

	  tcp_fs[ti].len -= buf->off;
	  tcp_fs[ti].data += buf->off;
	  if (!tcp_fs[ti].len)
	    ti += 1;
	}
      else
	{
	  vec_validate (pm->tx_bufs[thread_index], max_enq);
	  ptls_buffer_init (buf, pm->tx_bufs[thread_index], max_enq);
	  rv = ptls_send (ptls_ctx->tls, buf, app_buf, deq_len);

	  assert (rv == 0);
	  wrote += buf->off;

	  left = ptls_copy_buf_to_fs (buf, buf->off, tcp_fs, &ti, n_tcp_segs);
	  assert (left == 0);
	}

      read += deq_len;
      ASSERT (deq_len >= first_chunk_len);

      if (deq_len == app_buf_len)
	{
	  i += 1;
	}
      else
	{
	  app_fs[i].len -= deq_len - first_chunk_len;
	  app_fs[i].data += deq_len - first_chunk_len;
	}
    }

  if (read)
    {
      svm_fifo_dequeue_drop (app_tx_fifo, read);
      if (svm_fifo_needs_deq_ntf (app_tx_fifo, read))
	session_dequeue_notify (app_session);
    }

  if (wrote)
    {
      svm_fifo_enqueue_nocopy (tcp_tx_fifo, wrote);
      if (svm_fifo_set_event (tcp_tx_fifo))
	session_send_io_evt_to_thread (tcp_tx_fifo, SESSION_IO_EVT_TX);
    }

  return wrote;
}

static inline int
picotls_ctx_write (tls_ctx_t *ctx, session_t *app_session,
		   transport_send_params_t *sp)
{
  picotls_ctx_t *ptls_ctx = (picotls_ctx_t *) ctx;
  u32 deq_max, deq_now, enq_max, enq_buf, wrote = 0;
  svm_fifo_t *tcp_tx_fifo;
  session_t *tcp_session;

  tcp_session = session_get_from_handle (ctx->tls_session_handle);
  tcp_tx_fifo = tcp_session->tx_fifo;

  enq_max = svm_fifo_max_enqueue_prod (tcp_tx_fifo);
  if (enq_max < 2048)
    goto check_tls_fifo;

  deq_max = svm_fifo_max_dequeue_cons (app_session->tx_fifo);
  deq_max = clib_min (deq_max, enq_max);
  if (!deq_max)
    goto check_tls_fifo;

  deq_now = clib_min (deq_max, sp->max_burst_size);
  wrote = ptls_app_to_tcp_write (ptls_ctx, app_session, tcp_tx_fifo, deq_now);

check_tls_fifo:

  if (ctx->app_closed)
    picotls_app_close (ctx);

  /* Deschedule and wait for deq notification if fifo is almost full */
  enq_buf = clib_min (svm_fifo_size (tcp_tx_fifo) / 2, TLSP_MIN_ENQ_SPACE);
  if (enq_max < wrote + enq_buf)
    {
      svm_fifo_add_want_deq_ntf (tcp_tx_fifo, SVM_FIFO_WANT_DEQ_NOTIF);
      transport_connection_deschedule (&ctx->connection);
      sp->flags |= TRANSPORT_SND_F_DESCHED;
    }
  else
    /* Request tx reschedule of the app session */
    app_session->flags |= SESSION_F_CUSTOM_TX;

  return wrote;
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

  return 0;
}

static int
picotls_ctx_init_client (tls_ctx_t *ctx)
{
  picotls_ctx_t *ptls_ctx = (picotls_ctx_t *) ctx;
  picotls_main_t *pm = &picotls_main;
  ptls_context_t *client_ptls_ctx = pm->client_ptls_ctx;
  ptls_handshake_properties_t hsprop = { { { { NULL } } } };

  session_t *tls_session = session_get_from_handle (ctx->tls_session_handle);
  ptls_buffer_t hs_buf;

  ptls_ctx->tls = ptls_new (client_ptls_ctx, 0);
  if (ptls_ctx->tls == NULL)
    {
      TLS_DBG (1, "Failed to initialize ptls_ssl structure");
      return -1;
    }

  ptls_ctx->rx_len = 0;
  ptls_ctx->rx_offset = 0;

  ptls_buffer_init (&hs_buf, "", 0);
  if (ptls_handshake (ptls_ctx->tls, &hs_buf, NULL, NULL, &hsprop) !=
      PTLS_ERROR_IN_PROGRESS)
    {
      TLS_DBG (1, "Failed to initialize tls connection");
    }

  picotls_try_handshake_write (ptls_ctx, tls_session, &hs_buf);

  ptls_buffer_dispose (&hs_buf);

  return 0;
}

tls_ctx_t *
picotls_ctx_get_w_thread (u32 ctx_index, u8 thread_index)
{
  picotls_ctx_t **ctx;
  ctx = pool_elt_at_index (picotls_main.ctx_pool[thread_index], ctx_index);
  return &(*ctx)->ctx;
}

int
picotls_init_client_ptls_ctx (ptls_context_t **client_ptls_ctx)
{
  *client_ptls_ctx = clib_mem_alloc (sizeof (ptls_context_t));
  memset (*client_ptls_ctx, 0, sizeof (ptls_context_t));

  (*client_ptls_ctx)->update_open_count = NULL;
  (*client_ptls_ctx)->key_exchanges = default_key_exchange;
  (*client_ptls_ctx)->random_bytes = ptls_openssl_random_bytes;
  (*client_ptls_ctx)->cipher_suites = ptls_vpp_crypto_cipher_suites;
  (*client_ptls_ctx)->get_time = &ptls_get_time;

  return 0;
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
  .ctx_init_client = picotls_ctx_init_client,
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
  vec_validate (pm->rx_bufs, num_threads - 1);
  vec_validate (pm->tx_bufs, num_threads - 1);

  clib_rwlock_init (&picotls_main.crypto_keys_rw_lock);

  tls_register_engine (&picotls_engine, CRYPTO_ENGINE_PICOTLS);

  picotls_init_client_ptls_ctx (&pm->client_ptls_ctx);

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
