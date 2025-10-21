/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#include <vlib/vlib.h>
#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>
#include <quic/quic.h>
#include <quic/quic_timer.h>
#include <quic_quicly/quic_quicly.h>
#include <quic_quicly/quic_quicly_error.h>
#include <quic_quicly/quic_quicly_crypto.h>
#include <vnet/session/application.h>
#include <vnet/session/session.h>

quic_quicly_main_t quic_quicly_main;

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Quicly QUIC Engine",
};

static_always_inline quicly_context_t *
quic_quicly_get_quicly_ctx_from_ctx (quic_ctx_t *ctx)
{
  crypto_context_t *crctx = quic_quicly_crypto_context_get (
    ctx->crypto_context_index, ctx->c_thread_index);
  quic_quicly_crypto_context_data_t *data =
    (quic_quicly_crypto_context_data_t *) crctx->data;
  return &data->quicly_ctx;
}

static_always_inline quicly_context_t *
quic_quicly_get_quicly_ctx_from_udp (u64 udp_session_handle)
{
  session_t *udp_session = session_get_from_handle (udp_session_handle);
  quic_ctx_t *ctx =
    quic_quicly_get_quic_ctx (udp_session->opaque, udp_session->thread_index);
  return quic_quicly_get_quicly_ctx_from_ctx (ctx);
}

static_always_inline int
quic_quicly_sendable_packet_count (session_t *udp_session)
{
  u32 max_enqueue;
  u32 packet_size = QUIC_MAX_PACKET_SIZE + SESSION_CONN_HDR_LEN;
  max_enqueue = svm_fifo_max_enqueue (udp_session->tx_fifo);
  return clib_min (max_enqueue / packet_size, QUIC_SEND_PACKET_VEC_SIZE);
}

static_always_inline void
quic_quicly_make_connection_key (clib_bihash_kv_16_8_t *kv,
				 const quicly_cid_plaintext_t *id)
{
  kv->key[0] = ((u64) id->master_id) << 32 | (u64) id->thread_id;
  kv->key[1] = id->node_id;
}

static void
quic_quicly_connection_delete (quic_ctx_t *ctx)
{
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;
  quic_quicly_main_t *qqm = &quic_quicly_main;
  quic_main_t *qm = qqm->qm;

  if (ctx->conn == NULL)
    {
      QUIC_DBG (2, "Skipping redundant delete of connection %u",
		ctx->c_c_index);
      return;
    }
  QUIC_DBG (2, "Deleting connection %u", ctx->c_c_index);

  QUIC_ASSERT (!quic_ctx_is_stream (ctx));
  quic_stop_ctx_timer (
    &quic_wrk_ctx_get (qm, ctx->c_thread_index)->timer_wheel, ctx);
  QUIC_DBG (4, "Stopped timer for ctx %u", ctx->c_c_index);

  /*  Delete the connection from the connection map */
  conn = ctx->conn;
  ctx->conn = NULL;
  quic_quicly_make_connection_key (&kv, quicly_get_master_id (conn));
  QUIC_DBG (2, "Deleting conn with id %lu %lu from map", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&qqm->connection_hash, &kv, 0 /* is_add */);

  quic_disconnect_transport (ctx, qm->app_index);
  quicly_free (conn);
  session_transport_delete_notify (&ctx->connection);
}

static void
quic_quicly_notify_app_connect_failed (quic_ctx_t *ctx, session_error_t err)
{
  app_worker_t *app_wrk;
  int rv;

  app_wrk = app_worker_get (ctx->parent_app_wrk_id);
  if (!app_wrk)
    {
      QUIC_DBG (2, "no app worker: ctx_index %u, thread %u", ctx->c_c_index,
		ctx->c_thread_index);
      return;
    }
  if ((rv = app_worker_connect_notify (app_wrk, 0, err, ctx->client_opaque)))
    QUIC_ERR ("failed to notify app: err %d, ctx_index %u, thread %u", rv,
	      ctx->c_c_index, ctx->c_thread_index);
}

/**
 * Called when quicly return an error
 * This function interacts tightly with quic_quicly_proto_on_close
 */
static void
quic_quicly_connection_closed (quic_ctx_t *ctx)
{
  QUIC_DBG (2, "QUIC connection %u/%u closed", ctx->c_thread_index,
	    ctx->c_c_index);

  switch (ctx->conn_state)
    {
    case QUIC_CONN_STATE_READY:
      /* Error on an opened connection (timeout...)
	 This puts the session in closing state, we should receive a
	 notification when the app has closed its session */
      session_transport_reset_notify (&ctx->connection);
      /* This ensures we delete the connection when the app confirms the close
       */
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED;
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING:
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED;
      /* quic_quicly_proto_on_close will eventually be called when the app
	 confirms the close , we delete the connection at that point */
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING_APP_CLOSED:
      /* App already confirmed close, we can delete the connection */
      quic_quicly_connection_delete (ctx);
      break;
    case QUIC_CONN_STATE_HANDSHAKE:
      /* handshake failed notify app that connect failed */
      quic_quicly_notify_app_connect_failed (ctx, SESSION_E_TLS_HANDSHAKE);
      quic_quicly_connection_delete (ctx);
      break;
    case QUIC_CONN_STATE_OPENED:
    case QUIC_CONN_STATE_ACTIVE_CLOSING:
      quic_quicly_connection_delete (ctx);
      break;
    default:
      QUIC_DBG (0, "BUG %d", ctx->conn_state);
      break;
    }
}

static int
quic_quicly_send_datagram (session_t *udp_session, struct iovec *packet,
			   ip46_address_t *rmt_ip, u16 rmt_port)
{
  u32 max_enqueue, len;
  session_dgram_hdr_t hdr;
  svm_fifo_t *f;
  transport_connection_t *tc;
  int ret;

  len = packet->iov_len;
  f = udp_session->tx_fifo;
  tc = session_get_transport (udp_session);
  max_enqueue = svm_fifo_max_enqueue (f);
  if (max_enqueue < SESSION_CONN_HDR_LEN + len)
    {
      QUIC_ERR ("Too much data to send, max_enqueue %u, len %u", max_enqueue,
		len + SESSION_CONN_HDR_LEN);
      return QUIC_QUICLY_ERROR_FULL_FIFO;
    }

  /*  Build packet header for fifo */
  hdr.data_length = len;
  hdr.data_offset = 0;
  hdr.is_ip4 = tc->is_ip4;
  clib_memcpy (&hdr.lcl_ip, &tc->lcl_ip, sizeof (ip46_address_t));
  hdr.lcl_port = tc->lcl_port;
  hdr.gso_size = 0;

  hdr.rmt_port = rmt_port;
  if (hdr.is_ip4)
    {
      hdr.rmt_ip.ip4.as_u32 = rmt_ip->ip4.as_u32;
    }
  else
    {
      clib_memcpy_fast (&hdr.rmt_ip.ip6, &rmt_ip->ip6, sizeof (rmt_ip->ip6));
    }

  svm_fifo_seg_t segs[2] = { { (u8 *) &hdr, sizeof (hdr) },
			     { packet->iov_base, len } };

  ret = svm_fifo_enqueue_segments (f, segs, 2, 0 /* allow partial */);
  if (PREDICT_FALSE (ret < 0))
    {
      QUIC_ERR ("Not enough space to enqueue dgram");
      return QUIC_QUICLY_ERROR_FULL_FIFO;
    }

  quic_increment_counter (quic_quicly_main.qm, QUIC_ERROR_TX_PACKETS, 1);

  return 0;
}

static_always_inline void
quic_quicly_set_udp_tx_evt (session_t *udp_session)
{
  int rv = 0;
  if (svm_fifo_set_event (udp_session->tx_fifo))
    {
      rv = session_program_tx_io_evt (udp_session->handle, SESSION_IO_EVT_TX);
    }
  if (PREDICT_FALSE (rv))
    {
      clib_warning ("Event enqueue errored %d", rv);
    }
}

static_always_inline void
quic_quicly_addr_to_ip46_addr (quicly_address_t *quicly_addr,
			       ip46_address_t *ip46_addr, u16 *ip46_port)
{
  if (quicly_addr->sa.sa_family == AF_INET)
    {
      struct sockaddr_in *sa4 = (struct sockaddr_in *) &quicly_addr->sa;
      *ip46_port = sa4->sin_port;
      ip46_addr->ip4.as_u32 = sa4->sin_addr.s_addr;
    }
  else
    {
      QUIC_ASSERT (quicly_addr->sa.sa_family == AF_INET6);
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &quicly_addr->sa;
      *ip46_port = sa6->sin6_port;
      clib_memcpy_fast (&ip46_addr->ip6, &sa6->sin6_addr, 16);
    }
}

static int
quic_quicly_send_packets (quic_ctx_t *ctx)
{
  /* TODO: GET packetsp[], buf[], next_timeout OFF OF THE STACK!!! */
  struct iovec packets[QUIC_SEND_PACKET_VEC_SIZE];
  uint64_t max_udp_payload_size = quic_quicly_get_quicly_ctx_from_ctx (ctx)
				    ->transport_params.max_udp_payload_size;
  uint8_t buf[QUIC_SEND_PACKET_VEC_SIZE * max_udp_payload_size];
  session_t *udp_session;
  quicly_conn_t *conn;
  size_t num_packets, i, max_packets;
  u32 n_sent = 0;
  int err = 0;
  quicly_address_t quicly_rmt_ip, quicly_lcl_ip;
  int64_t next_timeout;

  /* We have sctx, get qctx */
  if (quic_ctx_is_stream (ctx))
    {
      ctx = quic_quicly_get_quic_ctx (ctx->quic_connection_ctx_id,
				      ctx->c_thread_index);
    }

  QUIC_ASSERT (!quic_ctx_is_stream (ctx));

  udp_session = session_get_from_handle_if_valid (ctx->udp_session_handle);
  if (!udp_session)
    {
      goto quicly_error;
    }

  conn = ctx->conn;
  if (!conn)
    {
      return 0;
    }

  do
    {
      /* TODO : quicly can assert it can send min_packets up to 2 */
      max_packets = quic_quicly_sendable_packet_count (udp_session);
      if (max_packets < 2)
	{
	  break;
	}

      num_packets = max_packets;
      QUIC_DBG (3, "num_packets %u, packets %p, buf %p, buf_size %u",
		num_packets, packets, buf, sizeof (buf));
      if ((err = quicly_send (conn, &quicly_rmt_ip, &quicly_lcl_ip, packets,
			      &num_packets, buf, sizeof (buf))))
	{
	  goto quicly_error;
	}
      if (num_packets > 0)
	{
	  quic_quicly_addr_to_ip46_addr (&quicly_rmt_ip, &ctx->rmt_ip,
					 &ctx->rmt_port);
	  for (i = 0; i != num_packets; ++i)
	    {
	      if ((err = quic_quicly_send_datagram (
		     udp_session, &packets[i], &ctx->rmt_ip, ctx->rmt_port)))
		{
		  goto quicly_error;
		}
	    }
	  n_sent += num_packets;
	}
    }
  while (num_packets > 0 && num_packets == max_packets);

  quic_quicly_set_udp_tx_evt (udp_session);

  QUIC_DBG (3, "%u[TX] %u[RX]", svm_fifo_max_dequeue (udp_session->tx_fifo),
	    svm_fifo_max_dequeue (udp_session->rx_fifo));

  next_timeout = quicly_get_first_timeout (conn);
  quic_update_timer (
    quic_wrk_ctx_get (quic_quicly_main.qm, ctx->c_thread_index), ctx,
    next_timeout);
  return n_sent;

quicly_error:
  if (err && err != QUICLY_ERROR_PACKET_IGNORED &&
      err != QUICLY_ERROR_FREE_CONNECTION)
    {
      clib_warning ("Quic error '%U'.", quic_quicly_format_err, err);
    }
  quic_quicly_connection_closed (ctx);
  return 0;
}

static_always_inline void
quic_quicly_timer_expired (u32 conn_index)
{
  quic_ctx_t *ctx;

  ctx = quic_quicly_get_quic_ctx (conn_index, vlib_get_thread_index ());
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  quic_quicly_send_packets (ctx);
}

static void
quic_quicly_expired_timers_dispatch (u32 *expired_timers)
{
  int i;
#if QUIC_DEBUG >= 1
  int64_t time_now =
    quic_wrk_ctx_get (quic_quicly_main.qm, vlib_get_thread_index ())->time_now;
#endif
  for (i = 0; i < vec_len (expired_timers); i++)
    {
      QUIC_DBG (4, "Timer expired for conn %u at %ld", i, time_now);
      quic_quicly_timer_expired (expired_timers[i]);
    }
}

static_always_inline session_t *
get_stream_session_and_ctx_from_stream (quicly_stream_t *stream,
					quic_ctx_t **ctx)
{
  quic_stream_data_t *stream_data;

  stream_data = (quic_stream_data_t *) stream->data;
  *ctx =
    quic_quicly_get_quic_ctx (stream_data->ctx_id, stream_data->thread_index);
  return session_get ((*ctx)->c_s_index, stream_data->thread_index);
}

/* Quicly callbacks */

static void
quic_quicly_on_stream_destroy (quicly_stream_t *stream, int err)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx =
    quic_quicly_get_quic_ctx (stream_data->ctx_id, stream_data->thread_index);

  QUIC_DBG (2, "DESTROYED_STREAM: session 0x%lx (%U)",
	    sctx->udp_session_handle, quic_quicly_format_err, err);

  session_transport_closing_notify (&sctx->connection);
  session_transport_delete_notify (&sctx->connection);

  quic_increment_counter (quic_quicly_main.qm, QUIC_ERROR_CLOSED_STREAM, 1);
  quic_ctx_free (quic_quicly_main.qm, sctx);
  clib_mem_free (stream->data);
}

static void
quic_quicly_fifo_egress_shift (quicly_stream_t *stream, size_t delta)
{
  quic_stream_data_t *stream_data;
  session_t *stream_session;
  quic_ctx_t *ctx;
  svm_fifo_t *f;
  u32 rv;

  stream_data = (quic_stream_data_t *) stream->data;
  stream_session = get_stream_session_and_ctx_from_stream (stream, &ctx);
  f = stream_session->tx_fifo;

  QUIC_ASSERT (stream_data->app_tx_data_len >= delta);
  stream_data->app_tx_data_len -= delta;
  ctx->bytes_written += delta;
  rv = svm_fifo_dequeue_drop (f, delta);
  QUIC_ASSERT (rv == delta);

  rv = quicly_stream_sync_sendbuf (stream, 0);
  QUIC_ASSERT (!rv);
}

static void
quic_quicly_fifo_egress_emit (quicly_stream_t *stream, size_t off, void *dst,
			      size_t *len, int *wrote_all)
{
  quic_stream_data_t *stream_data;
  quic_ctx_t *ctx;
  session_t *stream_session;
  svm_fifo_t *f;
  u32 deq_max;

  stream_data = (quic_stream_data_t *) stream->data;
  stream_session = get_stream_session_and_ctx_from_stream (stream, &ctx);
  f = stream_session->tx_fifo;

  QUIC_DBG (3, "Emitting %u, offset %u", *len, off);

  deq_max = svm_fifo_max_dequeue_cons (f);
  QUIC_ASSERT (off <= deq_max);
  if (off + *len < deq_max)
    {
      *wrote_all = 0;
    }
  else
    {
      *wrote_all = 1;
      *len = deq_max - off;
    }
  QUIC_ASSERT (*len > 0);

  if (off + *len > stream_data->app_tx_data_len)
    {
      stream_data->app_tx_data_len = off + *len;
    }
  svm_fifo_peek (f, off, *len, dst);
}

static void
quic_quicly_on_stop_sending (quicly_stream_t *stream, int err)
{
  /* TODO : handle STOP_SENDING */
#if QUIC_DEBUG >= 2
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx =
    quic_quicly_get_quic_ctx (stream_data->ctx_id, stream_data->thread_index);
  session_t *stream_session =
    session_get (sctx->c_s_index, sctx->c_thread_index);
  clib_warning ("(NOT IMPLEMENTD) STOP_SENDING: session 0x%lx (%U)",
		session_handle (stream_session), quic_quicly_format_err, err);
#endif
}

static void
quic_quicly_ack_rx_data (session_t *stream_session)
{
  u32 max_deq;
  quic_ctx_t *sctx;
  svm_fifo_t *f;
  quicly_stream_t *stream;
  quic_stream_data_t *stream_data;

  sctx = quic_quicly_get_quic_ctx (stream_session->connection_index,
				   stream_session->thread_index);
  QUIC_ASSERT (quic_ctx_is_stream (sctx));
  stream = sctx->stream;
  stream_data = (quic_stream_data_t *) stream->data;

  f = stream_session->rx_fifo;
  max_deq = svm_fifo_max_dequeue (f);

  QUIC_ASSERT (stream_data->app_rx_data_len >= max_deq);
  quicly_stream_sync_recvbuf (stream, stream_data->app_rx_data_len - max_deq);
  QUIC_DBG (3, "Acking %u bytes", stream_data->app_rx_data_len - max_deq);
  stream_data->app_rx_data_len = max_deq;
}

static void
quic_quicly_on_receive (quicly_stream_t *stream, size_t off, const void *src,
			size_t len)
{
  QUIC_DBG (3, "received data: %lu bytes, offset %lu", len, off);
  u32 max_enq;
  quic_ctx_t *sctx;
  session_t *stream_session;
  app_worker_t *app_wrk;
  svm_fifo_t *f;
  quic_stream_data_t *stream_data;
  int rlen;

  if (!len)
    {
      return;
    }

  stream_data = (quic_stream_data_t *) stream->data;
  sctx =
    quic_quicly_get_quic_ctx (stream_data->ctx_id, stream_data->thread_index);
  stream_session = session_get (sctx->c_s_index, stream_data->thread_index);
  f = stream_session->rx_fifo;

  max_enq = svm_fifo_max_enqueue_prod (f);
  QUIC_DBG (3, "Enqueuing %u at off %u in %u space", len, off, max_enq);
  /* Handle duplicate packet/chunk from quicly */
  if (off < stream_data->app_rx_data_len)
    {
      QUIC_DBG (3,
		"Session [idx %u, app_wrk %u, thread %u, rx-fifo 0x%llx]: "
		"DUPLICATE PACKET (max_enq %u, len %u, "
		"app_rx_data_len %u, off %u, ToBeNQ %u)",
		stream_session->session_index, stream_session->app_wrk_index,
		stream_session->thread_index, f, max_enq, len,
		stream_data->app_rx_data_len, off,
		off - stream_data->app_rx_data_len + len);
      return;
    }
  if (PREDICT_FALSE ((off - stream_data->app_rx_data_len + len) > max_enq))
    {
      QUIC_ERR ("Session [idx %u, app_wrk %u, thread %u, rx-fifo 0x%llx]: "
		"RX FIFO IS FULL (max_enq %u, len %u, "
		"app_rx_data_len %u, off %u, ToBeNQ %u)",
		stream_session->session_index, stream_session->app_wrk_index,
		stream_session->thread_index, f, max_enq, len,
		stream_data->app_rx_data_len, off,
		off - stream_data->app_rx_data_len + len);
      return; /* This shouldn't happen */
    }
  if (off == stream_data->app_rx_data_len)
    {
      /* Streams live on the same thread so (f, stream_data) should stay
       * consistent */
      rlen = svm_fifo_enqueue (f, len, (u8 *) src);
      if (PREDICT_FALSE (rlen < 0))
	{
	  /*
	   * drop, fifo full
	   * drop, fifo grow
	   */
	  return;
	}
      QUIC_DBG (3,
		"Session [idx %u, app_wrk %u, ti %u, rx-fifo 0x%llx]: "
		"Enqueuing %u (rlen %u) at off %u in %u space, ",
		stream_session->session_index, stream_session->app_wrk_index,
		stream_session->thread_index, f, len, rlen, off, max_enq);
      stream_data->app_rx_data_len += rlen;
      QUIC_ASSERT (rlen >= len);
      app_wrk = app_worker_get_if_valid (stream_session->app_wrk_index);
      if (PREDICT_TRUE (app_wrk != 0))
	{
	  app_worker_rx_notify (app_wrk, stream_session);
	}
      quic_quicly_ack_rx_data (stream_session);
    }
  else
    {
      rlen = svm_fifo_enqueue_with_offset (
	f, off - stream_data->app_rx_data_len, len, (u8 *) src);
      if (PREDICT_FALSE (rlen < 0))
	{
	  /*
	   * drop, fifo full
	   * drop, fifo grow
	   */
	  return;
	}
      QUIC_ASSERT (rlen == 0);
    }
}

static void
quic_quicly_on_receive_reset (quicly_stream_t *stream, int quicly_error)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx =
    quic_quicly_get_quic_ctx (stream_data->ctx_id, stream_data->thread_index);
#if QUIC_DEBUG >= 2
  session_t *stream_session =
    session_get (sctx->c_s_index, sctx->c_thread_index);
  clib_warning ("RESET_STREAM: session 0x%lx (%U)",
		session_handle (stream_session), quic_quicly_format_err,
		quicly_error);
#endif
  session_transport_closing_notify (&sctx->connection);
}

const quicly_stream_callbacks_t quic_quicly_stream_callbacks = {
  .on_destroy = quic_quicly_on_stream_destroy,
  .on_send_shift = quic_quicly_fifo_egress_shift,
  .on_send_emit = quic_quicly_fifo_egress_emit,
  .on_send_stop = quic_quicly_on_stop_sending,
  .on_receive = quic_quicly_on_receive,
  .on_receive_reset = quic_quicly_on_receive_reset
};

quic_ctx_t *
quic_quicly_get_conn_ctx (void *conn)
{
  u64 conn_data;
  conn_data = (u64) *quicly_get_data ((quicly_conn_t *) conn);
  return quic_quicly_get_quic_ctx (conn_data & UINT32_MAX, conn_data >> 32);
}

static_always_inline void
quic_quicly_store_conn_ctx (void *conn, quic_ctx_t *ctx)
{
  *quicly_get_data ((quicly_conn_t *) conn) =
    (void *) (((u64) ctx->c_thread_index) << 32 | (u64) ctx->c_c_index);
}

static_always_inline void
quic_quicly_update_conn_ctx (quicly_conn_t *conn,
			     quicly_context_t *quicly_context)
{
  /* we need to update the quicly_conn on migrate
   * as it contains a pointer to the crypto context */
  ptls_context_t **tls;
  quicly_context_t **_quicly_context;
  _quicly_context = (quicly_context_t **) conn;
  *_quicly_context = quicly_context;
  tls = (ptls_context_t **) quicly_get_tls (conn);
  *tls = quicly_context->tls;
}

static void
quic_quicly_connection_migrate (quic_ctx_t *ctx)
{
  u32 new_ctx_index, thread_index = vlib_get_thread_index ();
  quic_ctx_t *new_ctx;
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;
  quicly_context_t *quicly_context;
  session_t *udp_session;
  int64_t next_timeout;

  new_ctx_index = quic_ctx_alloc (quic_quicly_main.qm, thread_index);
  new_ctx = quic_quicly_get_quic_ctx (new_ctx_index, thread_index);

  QUIC_DBG (
    2, "Migrate conn (ctx_index %u, thread %u) to new_ctx_index %u, thread %u",
    ctx->c_c_index, ctx->c_thread_index, new_ctx_index, thread_index);

  clib_memcpy (new_ctx, ctx, sizeof (quic_ctx_t));
  clib_mem_free (ctx);

  new_ctx->c_thread_index = thread_index;
  new_ctx->c_c_index = new_ctx_index;
  quic_quicly_crypto_context_acquire (new_ctx);

  conn = new_ctx->conn;
  quicly_context = quic_quicly_get_quicly_ctx_from_ctx (new_ctx);
  quic_quicly_update_conn_ctx (conn, quicly_context);

  quic_quicly_store_conn_ctx (conn, new_ctx);
  quic_quicly_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) new_ctx_index;
  QUIC_DBG (2, "Registering conn: key value 0x%llx, ctx_index %u, thread %u",
	    kv.value, new_ctx_index, thread_index);

  clib_bihash_add_del_16_8 (&quic_quicly_main.connection_hash, &kv,
			    1 /* is_add */);
  new_ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  next_timeout = quicly_get_first_timeout (ctx->conn);

  quic_update_timer (quic_wrk_ctx_get (quic_quicly_main.qm, thread_index),
		     new_ctx, next_timeout);

  /*  Trigger write on this connection if necessary */
  udp_session = session_get_from_handle (new_ctx->udp_session_handle);
  udp_session->opaque = new_ctx_index;
  udp_session->flags &= ~SESSION_F_IS_MIGRATING;
  if (svm_fifo_max_dequeue (udp_session->tx_fifo))
    {
      quic_quicly_set_udp_tx_evt (udp_session);
    }
}

static int
quic_quicly_reset_connection (u64 udp_session_handle,
			      quic_quicly_rx_packet_ctx_t *pctx)
{
  /* short header packet; potentially a dead connection. No need to check the
   * length of the incoming packet, because loop is prevented by authenticating
   * the CID (by checking node_id and thread_id). If the peer is also sending a
   * reset, then the next CID is highly likely to contain a non-authenticating
   * CID, ... */
  QUIC_DBG (2, "Sending stateless reset");
  int rv;
  session_t *udp_session;
  quicly_context_t *quicly_ctx;
  if (pctx->packet.cid.dest.plaintext.node_id != 0 ||
      pctx->packet.cid.dest.plaintext.thread_id != 0)
    {
      return 0;
    }
  quicly_ctx = quic_quicly_get_quicly_ctx_from_udp (udp_session_handle);
  quic_ctx_t *ctx =
    quic_quicly_get_quic_ctx (pctx->ctx_index, pctx->thread_index);

  quicly_address_t src;
  uint8_t payload[quicly_ctx->transport_params.max_udp_payload_size];
  size_t payload_len =
    quicly_send_stateless_reset (quicly_ctx, &src.sa, payload);
  if (payload_len == 0)
    {
      return 1;
    }

  struct iovec packet;
  packet.iov_len = payload_len;
  packet.iov_base = payload;

  udp_session = session_get_from_handle (udp_session_handle);
  quic_quicly_addr_to_ip46_addr (&src, &ctx->rmt_ip, &ctx->rmt_port);
  rv = quic_quicly_send_datagram (udp_session, &packet, &ctx->rmt_ip,
				  ctx->rmt_port);
  quic_quicly_set_udp_tx_evt (udp_session);
  return rv;
}

static_always_inline quic_ctx_t *
quic_quicly_get_quic_ctx_if_valid (u32 ctx_index,
				   clib_thread_index_t thread_index)
{
  quic_worker_ctx_t *wrk_ctx =
    quic_wrk_ctx_get (quic_quicly_main.qm, thread_index);

  if (pool_is_free_index (wrk_ctx->ctx_pool, ctx_index))
    return 0;
  return pool_elt_at_index (wrk_ctx->ctx_pool, ctx_index);
}

static void
quic_quicly_proto_on_close (u32 ctx_index, clib_thread_index_t thread_index)
{
  int err;
  quic_ctx_t *ctx =
    quic_quicly_get_quic_ctx_if_valid (ctx_index, thread_index);
  if (!ctx)
    {
      return;
    }
  session_t *stream_session =
    session_get (ctx->c_s_index, ctx->c_thread_index);
#if QUIC_DEBUG >= 2
  clib_warning ("Closing session 0x%lx", session_handle (stream_session));
#endif
  if (quic_ctx_is_stream (ctx))
    {
      quicly_stream_t *stream = ctx->stream;
      if (!quicly_stream_has_send_side (quicly_is_client (stream->conn),
					stream->stream_id))
	{
	  return;
	}
      quicly_sendstate_shutdown (
	&stream->sendstate,
	ctx->bytes_written + svm_fifo_max_dequeue (stream_session->tx_fifo));
      err = quicly_stream_sync_sendbuf (stream, 1);
      if (err)
	{
	  QUIC_DBG (1, "sendstate_shutdown failed for stream session %lu",
		    session_handle (stream_session));
	  quicly_reset_stream (stream, QUIC_QUICLY_APP_ERROR_CLOSE_NOTIFY);
	}
      quic_quicly_send_packets (ctx);
      return;
    }

  switch (ctx->conn_state)
    {
    case QUIC_CONN_STATE_OPENED:
    case QUIC_CONN_STATE_HANDSHAKE:
    case QUIC_CONN_STATE_READY:
      ctx->conn_state = QUIC_CONN_STATE_ACTIVE_CLOSING;
      quicly_conn_t *conn = ctx->conn;
      /* Start connection closing. Keep sending packets until quicly_send
	 returns QUICLY_ERROR_FREE_CONNECTION */

      quic_increment_counter (quic_quicly_main.qm,
			      QUIC_ERROR_CLOSED_CONNECTION, 1);
      quicly_close (conn, QUIC_QUICLY_APP_ERROR_CLOSE_NOTIFY,
		    "Closed by peer");
      /* This also causes all streams to be closed (and the cb called) */
      quic_quicly_send_packets (ctx);
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING:
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_APP_CLOSED;
      /* send_packets will eventually return an error, we delete the conn at
	 that point */
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED:
      quic_quicly_connection_delete (ctx);
      break;
    case QUIC_CONN_STATE_ACTIVE_CLOSING:
      break;
    default:
      QUIC_ERR ("Trying to close conn in state %d", ctx->conn_state);
      break;
    }
}

/*
 * Returns 0 if a matching connection is found and is on the right thread.
 * Otherwise returns -1.
 * If a connection is found, even on the wrong thread, ctx_thread and ctx_index
 * will be set.
 */
static_always_inline int
quic_quicly_find_packet_ctx (quic_quicly_rx_packet_ctx_t *pctx,
			     u32 caller_thread_index)
{
  clib_bihash_kv_16_8_t kv;
  clib_bihash_16_8_t *h;
  quic_ctx_t *ctx;
  u32 index, thread_id;
  quic_quicly_main_t *qqm = &quic_quicly_main;

  h = &qqm->connection_hash;
  quic_quicly_make_connection_key (&kv, &pctx->packet.cid.dest.plaintext);
  QUIC_DBG (3, "Searching conn with id 0x%llx", *(u64 *) kv.key);

  if (clib_bihash_search_16_8 (h, &kv, &kv))
    {
      QUIC_DBG (3, "connection not found");
      return QUIC_PACKET_TYPE_NONE;
    }

  index = kv.value & UINT32_MAX;
  thread_id = kv.value >> 32;
  /* Check if this connection belongs to this thread, otherwise
   * ask for it to be moved */
  if (thread_id != caller_thread_index)
    {
      QUIC_DBG (2, "Connection is on wrong thread");
      /* Cannot make full check with quicly_is_destination... */
      pctx->ctx_index = index;
      pctx->thread_index = thread_id;
      return QUIC_PACKET_TYPE_MIGRATE;
    }
  ctx = quic_quicly_get_quic_ctx (index, vlib_get_thread_index ());
  if (!ctx->conn)
    {
      QUIC_ERR ("ctx has no conn");
      return QUIC_PACKET_TYPE_NONE;
    }
  if (!quicly_is_destination (ctx->conn, NULL, &pctx->sa, &pctx->packet))
    {
      return QUIC_PACKET_TYPE_NONE;
    }

  QUIC_DBG (3, "Connection found");
  pctx->ctx_index = index;
  pctx->thread_index = thread_id;
  return QUIC_PACKET_TYPE_RECEIVE;
}

static void
quic_quicly_accept_connection (quic_quicly_rx_packet_ctx_t *pctx)
{
  quicly_context_t *quicly_ctx;
  session_t *quic_session;
  clib_bihash_kv_16_8_t kv;
  app_worker_t *app_wrk;
  quicly_conn_t *conn;
  quic_ctx_t *ctx;
  quic_ctx_t *lctx;
  int rv;
  quic_quicly_main_t *qqm = &quic_quicly_main;

  QUIC_DBG (2, "Accept connection: pkt ctx_index %u, thread %u",
	    pctx->ctx_index, pctx->thread_index);

  /* new connection, accept and create context if packet is valid
   * TODO: check if socket is actually listening? */
  ctx = quic_quicly_get_quic_ctx (pctx->ctx_index, pctx->thread_index);
  if (ctx->c_s_index != QUIC_SESSION_INVALID)
    {
      QUIC_DBG (
	2, "Accept connection (already accepted): session_index %u, thread %u",
	ctx->c_s_index, ctx->c_thread_index);
      return;
    }

  quicly_ctx = quic_quicly_get_quicly_ctx_from_ctx (ctx);
  rv = quicly_accept (&conn, quicly_ctx, NULL, &pctx->sa, &pctx->packet, NULL,
		      &qqm->next_cid[pctx->thread_index], NULL, NULL);
  if (rv)
    {
      /* Invalid packet, pass */
      assert (conn == NULL);
      QUIC_ERR ("Accept connection: failed with %U", quic_quicly_format_err,
		rv);
      /* TODO: cleanup created quic ctx and UDP session */
      return;
    }
  ASSERT (conn != NULL);

  ++qqm->next_cid[pctx->thread_index].master_id;
  /* Save ctx handle in quicly connection */
  quic_quicly_store_conn_ctx (conn, ctx);
  ctx->conn = conn;

  /* if handshake failed (e.g. ALPN negotiation failed) quicly connection is in
   * closing state, in this case we don't need to create session and notify
   * app, connection will be closed when error response is sent */
  if (quicly_get_state (conn) >= QUICLY_STATE_CLOSING)
    {
      QUIC_DBG (2, "Handshake failed, closing: ctx_index %u, thread %u",
		ctx->c_c_index, ctx->c_thread_index);
      return;
    }

  quic_session = session_alloc (ctx->c_thread_index);
  QUIC_DBG (2,
	    "Accept connection (new quic_session): session 0x%lx, "
	    "session_index %u, ctx_index %u, thread %u",
	    session_handle (quic_session), quic_session->session_index,
	    ctx->c_c_index, ctx->c_thread_index);
  ctx->c_s_index = quic_session->session_index;

  lctx = quic_quicly_get_quic_ctx (ctx->listener_ctx_id, 0);

  quic_session->app_wrk_index = lctx->parent_app_wrk_id;
  quic_session->connection_index = ctx->c_c_index;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, ctx->udp_is_ip4);
  quic_session->listener_handle = lctx->c_s_index;

  /* Register connection in connections map */
  quic_quicly_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) pctx->thread_index) << 32 | (u64) pctx->ctx_index;
  clib_bihash_add_del_16_8 (&qqm->connection_hash, &kv, 1 /* is_add */);
  QUIC_DBG (
    2, "Accept connection: conn key value 0x%llx, ctx_index %u, thread %u",
    kv.value, pctx->ctx_index, pctx->thread_index);

  if (lctx->alpn_protos[0])
    {
      const char *proto = ptls_get_negotiated_protocol (quicly_get_tls (conn));
      if (proto)
	{
	  tls_alpn_proto_id_t id = { .base = (u8 *) proto,
				     .len = strlen (proto) };
	  ctx->alpn_selected = tls_alpn_proto_by_str (&id);
	}
    }

  /* If notify fails, reset connection immediatly */
  rv = app_worker_init_accepted (quic_session);
  if (rv)
    {
      QUIC_ERR ("Accept connection: failed to allocate fifos");
      quic_quicly_proto_on_close (pctx->ctx_index, pctx->thread_index);
      return;
    }

  svm_fifo_init_ooo_lookup (quic_session->rx_fifo, 0 /* ooo enq */);
  svm_fifo_init_ooo_lookup (quic_session->tx_fifo, 1 /* ooo deq */);

  app_wrk = app_worker_get (quic_session->app_wrk_index);
  quic_session->session_state = SESSION_STATE_ACCEPTING;
  rv = app_worker_accept_notify (app_wrk, quic_session);
  if (rv)
    {
      QUIC_ERR ("Accept connection: failed to notify accept worker app");
      quic_quicly_proto_on_close (pctx->ctx_index, pctx->thread_index);
      return;
    }

  ctx->conn_state = QUIC_CONN_STATE_READY;
}

static int
quic_quicly_process_one_rx_packet (u64 udp_session_handle, svm_fifo_t *f,
				   u32 fifo_offset,
				   quic_quicly_rx_packet_ctx_t *pctx)
{
  size_t plen;
  u32 full_len, ret;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 cur_deq = svm_fifo_max_dequeue (f) - fifo_offset;
  quicly_context_t *quicly_ctx;
  session_t *udp_session;
  int rv;
  quic_quicly_main_t *qqm = &quic_quicly_main;
  quic_main_t *qm = qqm->qm;

  ret = svm_fifo_peek (f, fifo_offset, SESSION_CONN_HDR_LEN, (u8 *) &pctx->ph);
  QUIC_ASSERT (ret == SESSION_CONN_HDR_LEN);
  QUIC_ASSERT (pctx->ph.data_offset == 0);
  full_len = pctx->ph.data_length + SESSION_CONN_HDR_LEN;
  if (full_len > cur_deq)
    {
      QUIC_ERR ("Not enough data in fifo RX");
      return 1;
    }

  /* Quicly can read len bytes from the fifo at offset:
   * ph.data_offset + SESSION_CONN_HDR_LEN */
  ret = svm_fifo_peek (f, SESSION_CONN_HDR_LEN + fifo_offset,
		       pctx->ph.data_length, pctx->data);
  if (ret != pctx->ph.data_length)
    {
      QUIC_ERR ("Not enough data peeked in RX");
      return 1;
    }

  quic_increment_counter (quic_quicly_main.qm, QUIC_ERROR_RX_PACKETS, 1);
  quic_build_sockaddr (&pctx->sa, &pctx->salen, &pctx->ph.rmt_ip,
		       pctx->ph.rmt_port, pctx->ph.is_ip4);
  quicly_ctx = quic_quicly_get_quicly_ctx_from_udp (udp_session_handle);
  size_t off = 0;
  plen = quicly_decode_packet (quicly_ctx, &pctx->packet, pctx->data,
			       pctx->ph.data_length, &off);
  if (plen == SIZE_MAX)
    {
      return 1;
    }

  rv = quic_quicly_find_packet_ctx (pctx, thread_index);
  if (rv == QUIC_PACKET_TYPE_RECEIVE)
    {
      pctx->ptype = QUIC_PACKET_TYPE_RECEIVE;
      if (qqm->vnet_crypto_enabled &&
	  qm->default_crypto_engine == CRYPTO_ENGINE_VPP)
	{
	  quic_ctx_t *qctx =
	    quic_quicly_get_quic_ctx (pctx->ctx_index, thread_index);
	  quic_quicly_crypto_decrypt_packet (qctx, pctx);
	}
      return 0;
    }
  else if (rv == QUIC_PACKET_TYPE_MIGRATE)
    {
      /*  Connection found but on wrong thread, ask move */
      pctx->ptype = QUIC_PACKET_TYPE_MIGRATE;
    }
  else if (QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]))
    {
      pctx->ptype = QUIC_PACKET_TYPE_ACCEPT;
      udp_session = session_get_from_handle (udp_session_handle);
      pctx->ctx_index = udp_session->opaque;
      pctx->thread_index = thread_index;
    }
  else
    {
      pctx->ptype = QUIC_PACKET_TYPE_RESET;
    }
  return 1;
}

static int
quic_quicly_connect (quic_ctx_t *ctx, u32 ctx_index,
		     clib_thread_index_t thread_index, struct sockaddr *sa)
{
  clib_bihash_kv_16_8_t kv;
  quicly_context_t *quicly_ctx;
  ptls_iovec_t alpn_list[4];
  ptls_handshake_properties_t hs_properties = {
    .client.negotiated_protocols.list = alpn_list
  };
  const tls_alpn_proto_id_t *alpn_proto;
  quic_quicly_main_t *qqm = &quic_quicly_main;
  int ret, i;

  /* build alpn list if app provided something */
  for (i = 0; i < sizeof (ctx->alpn_protos) && ctx->alpn_protos[i]; i++)
    {
      alpn_proto = &tls_alpn_proto_ids[ctx->alpn_protos[i]];
      alpn_list[i].base = alpn_proto->base;
      alpn_list[i].len = (size_t) alpn_proto->len;
      hs_properties.client.negotiated_protocols.count++;
    }
  quicly_ctx = quic_quicly_get_quicly_ctx_from_ctx (ctx);
  ret = quicly_connect ((quicly_conn_t **) &ctx->conn, quicly_ctx,
			(char *) ctx->srv_hostname, sa, NULL,
			&qqm->next_cid[thread_index],
			ptls_iovec_init (NULL, 0), &hs_properties, NULL, NULL);
  ++qqm->next_cid[thread_index].master_id;
  /*  save context handle in quicly connection */
  quic_quicly_store_conn_ctx (ctx->conn, ctx);
  ASSERT (ret == 0);

  /*  Register connection in connections map */
  quic_quicly_make_connection_key (
    &kv, quicly_get_master_id ((quicly_conn_t *) ctx->conn));
  kv.value = ((u64) thread_index) << 32 | (u64) ctx_index;
  QUIC_DBG (
    2, "UDP Session connected: conn key value 0x%llx, ctx_index %u, thread %u",
    kv.value, ctx_index, thread_index);
  clib_bihash_add_del_16_8 (&qqm->connection_hash, &kv, 1 /* is_add */);

  return (ret);
}

static u8 *
quic_quicly_format_quicly_conn_id (u8 *s, va_list *args)
{
  quicly_cid_plaintext_t *mid = va_arg (*args, quicly_cid_plaintext_t *);
  s = format (s, "C%x_%x", mid->master_id, mid->thread_id);
  return s;
}

static u8 *
quic_quicly_format_stream_ctx_stream_id (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quicly_stream_t *stream = (quicly_stream_t *) ctx->stream;

  s = format (s, "%U S%lx", quic_quicly_format_quicly_conn_id,
	      quicly_get_master_id (stream->conn), stream->stream_id);
  return s;
}

static u8 *
quic_quicly_format_stream_connection (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quicly_stream_t *stream = (quicly_stream_t *) ctx->stream;

  s = format (s, "Stream %ld conn %d", stream->stream_id,
	      ctx->quic_connection_ctx_id);
  return s;
}

static_always_inline void
quic_quicly_connection_get_stats (void *conn, quic_stats_t *conn_stats)
{
  quicly_stats_t qstats;

  quicly_get_stats ((quicly_conn_t *) conn, &qstats);
  conn_stats->rtt_smoothed = qstats.rtt.smoothed;
  conn_stats->rtt_minimum = qstats.rtt.minimum;
  conn_stats->rtt_variance = qstats.rtt.variance;
  conn_stats->num_packets_received = qstats.num_packets.received;
  conn_stats->num_packets_sent = qstats.num_packets.sent;
  conn_stats->num_packets_lost = qstats.num_packets.lost;
  conn_stats->num_packets_ack_received = qstats.num_packets.ack_received;
  conn_stats->num_bytes_received = qstats.num_bytes.received;
  conn_stats->num_bytes_sent = qstats.num_bytes.sent;
}

static u8 *
quic_quicly_format_connection_stats (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quicly_stats_t quicly_stats;

  s = format (s, "[%U]", quic_quicly_format_quicly_conn_id,
	      quicly_get_master_id (ctx->conn));

  quicly_get_stats (ctx->conn, &quicly_stats);

  s = format (s, "[RTT >%3d, ~%3d, V%3d, last %3d]", quicly_stats.rtt.minimum,
	      quicly_stats.rtt.smoothed, quicly_stats.rtt.variance,
	      quicly_stats.rtt.latest);
  s = format (s, " TX:%d RX:%d loss:%d ack:%d", quicly_stats.num_packets.sent,
	      quicly_stats.num_packets.received, quicly_stats.num_packets.lost,
	      quicly_stats.num_packets.ack_received);
  s =
    format (s, "\ncwnd:%u ssthresh:%u recovery_end:%lu", quicly_stats.cc.cwnd,
	    quicly_stats.cc.ssthresh, quicly_stats.cc.recovery_end);

  quicly_context_t *quicly_ctx = quic_quicly_get_quicly_ctx_from_ctx (ctx);
  if (quicly_ctx->init_cc == &quicly_cc_cubic_init)
    {
      s = format (s,
		  "\nk:%d w_max:%u w_last_max:%u avoidance_start:%ld "
		  "last_sent_time:%ld",
		  quicly_stats.cc.state.cubic.k,
		  quicly_stats.cc.state.cubic.w_max,
		  quicly_stats.cc.state.cubic.w_last_max,
		  quicly_stats.cc.state.cubic.avoidance_start,
		  quicly_stats.cc.state.cubic.last_sent_time);
    }
  else if (quicly_ctx->init_cc == &quicly_cc_reno_init)
    {
      s = format (s, " stash:%u", quicly_stats.cc.state.reno.stash);
    }
  return s;
}

static_always_inline int
quic_quicly_receive_a_packet (quic_ctx_t *ctx,
			      quic_quicly_rx_packet_ctx_t *pctx)
{
  int rv = quicly_receive (ctx->conn, NULL, &pctx->sa, &pctx->packet);
  if (rv && rv != QUICLY_ERROR_PACKET_IGNORED)
    {
      QUIC_ERR ("quicly_receive return error %U", quic_quicly_format_err, rv);
    }

  /* FIXME: Don't return quicly error codes here.
   * TODO: Define appropriate QUIC return values for QUIC VFT's!
   */
  return rv;
}

static_always_inline int
quic_quicly_connect_stream (void *quic_conn, void **quic_stream,
			    quic_stream_data_t **quic_stream_data,
			    u8 is_unidir)
{
  quicly_conn_t *conn = quic_conn;
  quicly_stream_t *quicly_stream;
  int rv;

  if (!quicly_connection_is_ready (conn))
    {
      /* TODO: Define appropriate QUIC return values for QUIC VFT's!
       */
      return -1;
    }

  rv = quicly_open_stream (conn, (quicly_stream_t **) quic_stream, is_unidir);
  if (rv)
    {
      QUIC_DBG (2, "quicly_open_stream() failed with %d", rv);
      /* TODO: Define appropriate QUIC return values for QUIC VFT's!
       */
      if (rv == QUICLY_TRANSPORT_ERROR_STREAM_LIMIT)
	return SESSION_E_MAX_STREAMS_HIT;
      return -1;
    }

  quicly_stream = *(quicly_stream_t **) quic_stream;
  *quic_stream_data = (quic_stream_data_t *) quicly_stream->data;

  QUIC_DBG (2, "Opened quicly_stream %d, creating session",
	    quicly_stream->stream_id);
  return 0;
}

static_always_inline void
quic_quicly_connect_stream_error_reset (void *quic_stream)
{
  quicly_reset_stream ((quicly_stream_t *) quic_stream,
		       QUIC_QUICLY_APP_CONNECT_NOTIFY_ERROR);
}

static_always_inline u64
quic_quicly_stream_tx (quic_ctx_t *ctx, session_t *stream_session)
{
  quic_stream_data_t *stream_data;
  quicly_stream_t *stream;
  u32 max_deq;

  stream = ctx->stream;
  if (!quicly_sendstate_is_open (&stream->sendstate))
    {
      QUIC_ERR ("Warning: tried to send on closed stream");
      return 0;
    }

  stream_data = (quic_stream_data_t *) stream->data;
  max_deq = svm_fifo_max_dequeue (stream_session->tx_fifo);
  QUIC_ASSERT (max_deq >= stream_data->app_tx_data_len);
  if (max_deq == stream_data->app_tx_data_len)
    {
      QUIC_DBG (3,
		"No data: max_deq %d, app_tx_data_len %d, ctx_index "
		"%u, thread %u",
		max_deq, stream_data->app_tx_data_len,
		stream_session->connection_index,
		stream_session->thread_index);
      return 0;
    }
  stream_data->app_tx_data_len = max_deq;
  return quicly_stream_sync_sendbuf (stream, 1);
}

static void
quic_quicly_engine_init (quic_main_t *qm)
{
  quic_quicly_main_t *qqm = &quic_quicly_main;
  quicly_cid_plaintext_t *next_cid;
  clib_bihash_24_8_t *crctx_hash;
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  u32 i;

  QUIC_DBG (2, "Quic engine init: quicly");
  qm->default_crypto_engine = CRYPTO_ENGINE_PICOTLS;
  qm->default_quic_cc = QUIC_CC_RENO;
  qm->max_packets_per_key = DEFAULT_MAX_PACKETS_PER_KEY;
  qqm->session_cache.super.cb = quic_quicly_encrypt_ticket_cb;
  qqm->qm = qm;

  vec_validate (quic_quicly_main.next_cid, qm->num_threads - 1);
  next_cid = qqm->next_cid;
  vec_validate (quic_quicly_main.crypto_ctx_hash, qm->num_threads - 1);
  crctx_hash = qqm->crypto_ctx_hash;
  clib_bitmap_alloc (quic_quicly_main.available_crypto_engines,
		     app_crypto_engine_n_types ());
  clib_bihash_init_16_8 (&qqm->connection_hash,
			 "quic (quicly engine) connections", 1024, 4 << 20);
  quic_quicly_register_cipher_suite (CRYPTO_ENGINE_PICOTLS,
				     ptls_openssl_cipher_suites);

  /* TODO: Review comment from Florin
   * Should we move this to quic timers and have quic framework call it?
   * If we have dependencies issues, at least move it to quic framework.
   */
  for (i = 0; i < qm->num_threads; i++)
    {
      tw = &quic_wrk_ctx_get (qm, i)->timer_wheel;
      tw_timer_wheel_init_1t_3w_1024sl_ov (tw,
					   quic_quicly_expired_timers_dispatch,
					   1e-3 /* timer period 1ms */, ~0);
      tw->last_run_time = vlib_time_now (vlib_get_main ());
      next_cid[i].thread_id = i;
      clib_bihash_init_24_8 (&crctx_hash[i], "quic crypto contexts", 64,
			     128 << 10);
    }
}

static void
quic_quicly_on_quic_session_connected (quic_ctx_t *ctx)
{
  session_t *quic_session;
  app_worker_t *app_wrk;
  u32 ctx_id = ctx->c_c_index;
  clib_thread_index_t thread_index = ctx->c_thread_index;
  int rv;

  quic_session = session_alloc (thread_index);

  QUIC_DBG (2, "Allocated quic session 0x%lx", session_handle (quic_session));
  ctx->c_s_index = quic_session->session_index;
  quic_session->app_wrk_index = ctx->parent_app_wrk_id;
  quic_session->connection_index = ctx->c_c_index;
  quic_session->listener_handle = SESSION_INVALID_HANDLE;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, ctx->udp_is_ip4);

  if (ctx->alpn_protos[0])
    {
      const char *proto =
	ptls_get_negotiated_protocol (quicly_get_tls (ctx->conn));
      if (proto)
	{
	  QUIC_DBG (2, "alpn proto selected %s", proto);
	  tls_alpn_proto_id_t id = { .base = (u8 *) proto,
				     .len = strlen (proto) };
	  ctx->alpn_selected = tls_alpn_proto_by_str (&id);
	}
    }

  /* If quic session connected fails, immediatly close connection */
  app_wrk = app_worker_get (ctx->parent_app_wrk_id);
  if ((rv = app_worker_init_connected (app_wrk, quic_session)))
    {
      QUIC_ERR ("failed to app_worker_init_connected");
      quic_quicly_proto_on_close (ctx_id, thread_index);
      app_worker_connect_notify (app_wrk, NULL, rv, ctx->client_opaque);
      return;
    }

  svm_fifo_init_ooo_lookup (quic_session->rx_fifo, 0 /* ooo enq */);
  svm_fifo_init_ooo_lookup (quic_session->tx_fifo, 1 /* ooo deq */);

  quic_session->session_state = SESSION_STATE_CONNECTING;
  if ((rv = app_worker_connect_notify (app_wrk, quic_session, SESSION_E_NONE,
				       ctx->client_opaque)))
    {
      QUIC_ERR ("failed to notify app %d", rv);
      quic_quicly_proto_on_close (ctx_id, thread_index);
      return;
    }
}

void
quic_quicly_check_quic_session_connected (quic_ctx_t *ctx)
{
  /* Called when we need to trigger quic session connected
   * we may call this function on the server side / at
   * stream opening */
  quic_session_connected_t session_connected;

  /* Conn may be set to null if the connection is terminated */
  if (!ctx->conn || ctx->conn_state != QUIC_CONN_STATE_HANDSHAKE)
    return;

  session_connected = quic_quicly_is_session_connected (ctx);
  if (session_connected == QUIC_SESSION_CONNECTED_NONE)
    return;

  ctx->conn_state = QUIC_CONN_STATE_READY;
  if (session_connected == QUIC_SESSION_CONNECTED_CLIENT)
    {
      quic_quicly_on_quic_session_connected (ctx);
    }
}

static int
quic_quicly_udp_session_rx_packets (session_t *udp_session)
{
  /*  Read data from UDP rx_fifo and pass it to the quic_eng conn. */
  quic_ctx_t *ctx = NULL, *prev_ctx = NULL;
  svm_fifo_t *f = udp_session->rx_fifo;
  u32 max_deq;
  u64 udp_session_handle = session_handle (udp_session);
  int rv = 0;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 cur_deq, fifo_offset, max_packets, i;
  /* TODO: move packet buffer off of the stack and
   *       allocate a vector of packet_ct_t.
   */
  quic_quicly_rx_packet_ctx_t packets_ctx[QUIC_RCV_MAX_PACKETS];

  if (udp_session->flags & SESSION_F_IS_MIGRATING)
    {
      QUIC_DBG (3, "RX on migrating udp session");
      return 0;
    }

rx_start:
  max_deq = svm_fifo_max_dequeue (f);
  if (max_deq == 0)
    {
      return 0;
    }

  fifo_offset = 0;
  max_packets = QUIC_RCV_MAX_PACKETS;

#if CLIB_DEBUG > 0
  clib_memset (packets_ctx, 0xfa,
	       QUIC_RCV_MAX_PACKETS * sizeof (quic_quicly_rx_packet_ctx_t));
#endif
  for (i = 0; i < max_packets; i++)
    {
      packets_ctx[i].thread_index = UINT32_MAX;
      packets_ctx[i].ctx_index = UINT32_MAX;
      packets_ctx[i].ptype = QUIC_PACKET_TYPE_DROP;

      cur_deq = max_deq - fifo_offset;
      if (cur_deq == 0)
	{
	  max_packets = i + 1;
	  break;
	}
      if (cur_deq < SESSION_CONN_HDR_LEN)
	{
	  fifo_offset = max_deq;
	  max_packets = i + 1;
	  QUIC_ERR ("Fifo %d < header size in RX", cur_deq);
	  break;
	}
      rv = quic_quicly_process_one_rx_packet (udp_session_handle, f,
					      fifo_offset, &packets_ctx[i]);
      if (packets_ctx[i].ptype != QUIC_PACKET_TYPE_MIGRATE)
	{
	  fifo_offset += SESSION_CONN_HDR_LEN + packets_ctx[i].ph.data_length;
	}
      if (rv)
	{
	  max_packets = i + 1;
	  break;
	}
    }

  for (i = 0; i < max_packets; i++)
    {
      switch (packets_ctx[i].ptype)
	{
	case QUIC_PACKET_TYPE_RECEIVE:
	  ctx =
	    quic_quicly_get_quic_ctx (packets_ctx[i].ctx_index, thread_index);
	  /* FIXME: Process return value and handle errors. */
	  quic_quicly_receive_a_packet (ctx, &packets_ctx[i]);
	  break;
	case QUIC_PACKET_TYPE_ACCEPT:
	  /* FIXME: Process return value and handle errors. */
	  quic_quicly_accept_connection (&packets_ctx[i]);
	  break;
	case QUIC_PACKET_TYPE_RESET:
	  /* FIXME: Process return value and handle errors. */
	  quic_quicly_reset_connection (udp_session_handle, &packets_ctx[i]);
	  break;
	}
    }
  ctx = prev_ctx = NULL;
  for (i = 0; i < max_packets; i++)
    {
      prev_ctx = ctx;
      switch (packets_ctx[i].ptype)
	{
	case QUIC_PACKET_TYPE_RECEIVE:
	  ctx = quic_quicly_get_quic_ctx (packets_ctx[i].ctx_index,
					  packets_ctx[i].thread_index);
	  quic_quicly_check_quic_session_connected (ctx);
	  ctx = quic_quicly_get_quic_ctx (packets_ctx[i].ctx_index,
					  packets_ctx[i].thread_index);
	  break;
	case QUIC_PACKET_TYPE_ACCEPT:
	  ctx = quic_quicly_get_quic_ctx (packets_ctx[i].ctx_index,
					  packets_ctx[i].thread_index);
	  break;
	default:
	  continue; /* this exits the for loop since other packet types are
		     * necessarily the last in the batch */
	}
      if (ctx != prev_ctx)
	{
	  quic_quicly_send_packets (ctx);
	}
    }

  /*  session alloc might have happened, so get session again */
  udp_session = session_get_from_handle (udp_session_handle);
  f = udp_session->rx_fifo;
  svm_fifo_dequeue_drop (f, fifo_offset);

  if (svm_fifo_max_dequeue (f))
    {
      goto rx_start;
    }

  return 0;
}

const static quic_engine_vft_t quic_quicly_engine_vft = {
  .engine_init = quic_quicly_engine_init,
  .app_cert_key_pair_delete = quic_quicly_app_cert_key_pair_delete,
  .crypto_context_acquire = quic_quicly_crypto_context_acquire,
  .crypto_context_release = quic_quicly_crypto_context_release,
  .connect = quic_quicly_connect,
  .connect_stream = quic_quicly_connect_stream,
  .connect_stream_error_reset = quic_quicly_connect_stream_error_reset,
  .connection_migrate = quic_quicly_connection_migrate,
  .connection_get_stats = quic_quicly_connection_get_stats,
  .udp_session_rx_packets = quic_quicly_udp_session_rx_packets,
  .ack_rx_data = quic_quicly_ack_rx_data,
  .stream_tx = quic_quicly_stream_tx,
  .send_packets = quic_quicly_send_packets,
  .format_connection_stats = quic_quicly_format_connection_stats,
  .format_stream_connection = quic_quicly_format_stream_connection,
  .format_stream_ctx_stream_id = quic_quicly_format_stream_ctx_stream_id,
  .proto_on_close = quic_quicly_proto_on_close,
};

static clib_error_t *
quic_quicly_init (vlib_main_t *vm)
{
  quic_register_engine_fn register_engine;

  register_engine =
    vlib_get_plugin_symbol ("quic_plugin.so", "quic_register_engine");
  if (register_engine == 0)
    {
      clib_warning ("quic_plugin.so not loaded...");
      return clib_error_return (0, "Unable to get plugin symbol: "
				   "'quic_register_engine'");
    }
  (*register_engine) (&quic_quicly_engine_vft, QUIC_ENGINE_QUICLY);

  return 0;
}

VLIB_INIT_FUNCTION (quic_quicly_init) = {
  .runs_after = VLIB_INITS ("quic_init"),
};
