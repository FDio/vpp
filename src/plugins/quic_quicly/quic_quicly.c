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
quic_plugin_methods_t quic_mvt;

/* quicly assume that the buffer provided by the caller of quicly_send is no greater than the burst
 * size of the pacer (10 packets) */
#define QUIC_QUICLY_SEND_PACKET_VEC_SIZE 10

#define QUIC_QUICLY_RCV_MAX_DGRAMS  16
#define QUIC_QUICLY_RCV_MAX_PACKETS 64

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Quicly QUIC Engine",
};

typedef enum quic_quicly_rx_error_
{
  QUIC_QUICLY_RX_ERROR_NONE = 0,
  QUIC_QUICLY_RX_ERROR_CRITICAL = -1,
  QUIC_QUICLY_RX_ERROR_WARNING = 1,
} quic_quicly_rx_error_t;

typedef quic_quicly_rx_error_t (*quic_quicly_rx_handler) (quic_ctx_t *ctx,
							  quic_quicly_rx_packet_ctx_t *pctx,
							  struct sockaddr *src_addr);

static_always_inline quicly_context_t *
quic_quicly_get_quicly_ctx_from_ctx (quic_ctx_t *ctx)
{
  quic_quicly_crypto_ctx_t *crctx = quic_quicly_crypto_context_get (ctx->crypto_context_index);
  return &crctx->quicly_ctx;
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
  return clib_min (max_enqueue / packet_size, QUIC_QUICLY_SEND_PACKET_VEC_SIZE);
}

static void
quic_quicly_connection_delete (quic_ctx_t *ctx)
{
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
  quic_mvt.conn_tx_timer_stop (quic_wrk_ctx_get (qm, ctx->c_thread_index), ctx);
  QUIC_DBG (4, "Stopped timer for ctx %u", ctx->c_c_index);

  quic_increment_counter (qm, QUIC_ERROR_CLOSED_CONNECTION, 1);
  quic_disconnect_transport (ctx, qm->app_index);
  quicly_free (ctx->conn);
  if (ctx->c_s_index != QUIC_SESSION_INVALID && !(ctx->flags & QUIC_F_NO_APP_SESSION))
    session_transport_delete_notify (&ctx->connection);
}

static int
quic_quicly_notify_app_connected (quic_ctx_t *ctx, session_error_t err)
{
  session_t *app_session;
  app_worker_t *app_wrk;

  app_wrk = app_worker_get_if_valid (ctx->parent_app_wrk_id);
  if (!app_wrk)
    {
      ctx->flags |= QUIC_F_NO_APP_SESSION;
      return -1;
    }

  /* Cleanup half-open session as we don't get notification from udp */
  session_half_open_delete_notify (&ctx->connection);

  if (err)
    {
      ctx->flags |= QUIC_F_NO_APP_SESSION;
      goto send_reply;
    }

  app_session = session_alloc (ctx->c_thread_index);
  app_session->session_state = SESSION_STATE_CREATED;
  app_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, ctx->udp_is_ip4);
  app_session->listener_handle = SESSION_INVALID_HANDLE;
  app_session->app_wrk_index = ctx->parent_app_wrk_id;
  app_session->opaque = ctx->client_opaque;
  app_session->connection_index = ctx->c_c_index;
  ctx->c_s_index = app_session->session_index;

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

  if ((err = app_worker_init_connected (app_wrk, app_session)))
    {
      QUIC_ERR ("failed to app_worker_init_connected");
      app_worker_connect_notify (app_wrk, 0, err, ctx->client_opaque);
      ctx->flags |= QUIC_F_NO_APP_SESSION;
      session_free (app_session);
      return -1;
    }

  svm_fifo_init_ooo_lookup (app_session->rx_fifo, 0 /* ooo enq */);
  svm_fifo_init_ooo_lookup (app_session->tx_fifo, 1 /* ooo deq */);

  session_set_state (app_session, SESSION_STATE_READY);
  if ((err = app_worker_connect_notify (app_wrk, app_session, SESSION_E_NONE,
					ctx->client_opaque)))
    {
      QUIC_ERR ("failed to notify app %d", err);
      session_free (session_get (ctx->c_s_index, ctx->c_thread_index));
      ctx->flags |= QUIC_F_NO_APP_SESSION;
      return -1;
    }

  return 0;

send_reply:
  return app_worker_connect_notify (app_wrk, 0, err, ctx->client_opaque);
}

/**
 * Called when quicly return an error
 * This function interacts tightly with quic_quicly_proto_on_close
 */
static void
quic_quicly_connection_closed (quic_ctx_t *ctx)
{
  QUIC_DBG (2, "QUIC connection %u/%u closed, state %d", ctx->c_thread_index,
	    ctx->c_c_index, ctx->conn_state);

  switch (ctx->conn_state)
    {
    /* Not much can be done when UDP connection is closed */
    case QUIC_CONN_STATE_TRANSPORT_CLOSED:
      if (!(ctx->flags & QUIC_F_NO_APP_SESSION))
	session_transport_reset_notify (&ctx->connection);
      quic_quicly_connection_delete (ctx);
      break;
    case QUIC_CONN_STATE_READY:
      /* Error on an opened connection (timeout...)
	 This puts the session in closing state, we should receive a
	 notification when the app has closed its session */
      if (!(ctx->flags & QUIC_F_NO_APP_SESSION))
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
      /* handshake failed, notify app only if this was a client connection */
      if (ctx->listener_ctx_id == QUIC_CTX_INVALID_INDEX)
	quic_quicly_notify_app_connected (ctx, SESSION_E_TLS_HANDSHAKE);
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

static void
quic_quicly_reschedule_ctx (quic_ctx_t *ctx)
{
  ASSERT (!quic_ctx_is_stream (ctx));
  int64_t next_timeout = quicly_get_first_timeout (ctx->conn);
  quic_mvt.conn_tx_timer_update (quic_wrk_ctx_get (quic_quicly_main.qm, ctx->c_thread_index), ctx,
				 next_timeout);
}

static_always_inline void
quic_quicly_set_udp_tx_evt (session_t *udp_session)
{
  int rv = 0;
  if (svm_fifo_set_event (udp_session->tx_fifo))
    {
      rv = session_program_tx_io_evt (udp_session->handle, SESSION_IO_EVT_TX);
      if (PREDICT_FALSE (rv))
	{
	  clib_warning ("Event enqueue errored %d", rv);
	}
    }
}

static void
quic_quicly_send_packets (quic_ctx_t *ctx)
{
  quic_quicly_main_t *qqm = &quic_quicly_main;
  struct iovec *packets = qqm->tx_packets[ctx->c_thread_index];
  session_t *udp_session;
  quicly_conn_t *conn;
  size_t num_packets, i, max_packets;
  u32 buf_size;
  quicly_error_t err;
  quicly_address_t quicly_rmt_ip, quicly_lcl_ip;
  u8 *buf = qqm->tx_bufs[ctx->c_thread_index];
  session_dgram_hdr_t hdr;
  int ret;

  ASSERT (vec_len (buf) >= (QUIC_QUICLY_SEND_PACKET_VEC_SIZE * QUIC_MAX_PACKET_SIZE));
  ASSERT (vec_len (packets) >= QUIC_QUICLY_SEND_PACKET_VEC_SIZE);
  ASSERT (!quic_ctx_is_stream (ctx));

  udp_session = session_get_from_handle (ctx->udp_session_handle);
  if (PREDICT_FALSE (udp_session->session_state == SESSION_STATE_TRANSPORT_DELETED))
    return;

  conn = ctx->conn;
  ASSERT (conn);

  max_packets = quic_quicly_sendable_packet_count (udp_session);
  if (PREDICT_FALSE (max_packets < 2))
    {
      svm_fifo_add_want_deq_ntf (udp_session->tx_fifo,
				 SVM_FIFO_WANT_DEQ_NOTIF);
      return;
    }

  /* Shrink buf_size if we have less dgrams than QUIC_QUICLY_SEND_PACKET_VEC_SIZE */
  buf_size = clib_min (vec_len (buf), max_packets * QUIC_MAX_PACKET_SIZE);

  /* If under memory pressure and chunks cannot be allocated try reschedule */
  if (svm_fifo_provision_chunks (udp_session->tx_fifo, 0, 0, buf_size))
    {
      quic_worker_ctx_t *wc = quic_wrk_ctx_get (quic_quicly_main.qm, ctx->c_thread_index);
      quic_mvt.conn_tx_timer_update (wc, ctx, wc->time_now + 1);
      return;
    }

  num_packets = max_packets;
  err = quicly_send (conn, &quicly_rmt_ip, &quicly_lcl_ip, packets, &num_packets, buf, buf_size);
  if (PREDICT_FALSE (err))
    {
      QUIC_DBG (2, "quicly_send error %U'", quic_quicly_format_err, err);
      goto conn_close;
    }

  QUIC_DBG (3, "num_packets %u, packets %p, buf %p, buf_size %u", num_packets, packets, buf,
	    sizeof (buf));

  if (PREDICT_FALSE (!num_packets))
    goto reschedule;

  hdr.data_offset = 0;
  hdr.gso_size = 0;
  for (i = 0; i < num_packets; i++)
    {
      hdr.data_length = packets[i].iov_len;
      svm_fifo_seg_t segs[2] = { { (u8 *) &hdr, sizeof (hdr) },
				 { packets[i].iov_base, packets[i].iov_len } };
      ret = svm_fifo_enqueue_segments (udp_session->tx_fifo, segs, 2, 0 /* allow partial */);
      ASSERT (ret > 0);
    }

  quic_increment_counter (quic_quicly_main.qm, QUIC_ERROR_TX_PACKETS, num_packets);
  quic_quicly_set_udp_tx_evt (udp_session);

  QUIC_DBG (3, "%u[TX] %u[RX]", svm_fifo_max_dequeue (udp_session->tx_fifo),
	    svm_fifo_max_dequeue (udp_session->rx_fifo));

reschedule:
  quic_quicly_reschedule_ctx (ctx);

  return;

conn_close:
  QUIC_DBG (2, "connection closed, ctx_index %u, thread_index %u", ctx->c_c_index,
	    ctx->c_thread_index);
  quic_quicly_connection_closed (ctx);
}

static void
quic_quicly_tx_timer_expired (u32 conn_index, clib_thread_index_t thread_index)
{
  quic_ctx_t *ctx;

  ctx = quic_quicly_get_quic_ctx (conn_index, thread_index);
  ctx->timers[QUIC_TIMER_TX] = QUIC_TIMER_HANDLE_INVALID;
  quic_quicly_send_packets (ctx);
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
quic_quicly_on_stream_destroy (quicly_stream_t *stream, quicly_error_t err)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx =
    quic_quicly_get_quic_ctx (stream_data->ctx_id, stream_data->thread_index);

  QUIC_DBG (
    2,
    "DESTROYED_STREAM: stream_session handle 0x%lx, sctx_index %u, "
    "thread %u, err %U",
    session_handle (session_get (sctx->c_s_index, sctx->c_thread_index)),
    sctx->c_c_index, sctx->c_thread_index, quic_quicly_format_err, err);

  sctx->flags |= QUIC_F_STREAM_TX_CLOSED;
  sctx->stream = 0;
  sctx->udp_session_handle = SESSION_INVALID_HANDLE;

  /* free stream only when app already closed, otherwise it might has unread
   * data */
  if (sctx->flags & QUIC_F_APP_CLOSED)
    {
      session_transport_closed_notify (&sctx->connection);
      session_transport_delete_notify (&sctx->connection);
      quic_ctx_free (quic_quicly_main.qm, sctx);
    }
  else
    session_transport_closing_notify (&sctx->connection);

  quic_increment_counter (quic_quicly_main.qm, QUIC_ERROR_CLOSED_STREAM, 1);
  clib_mem_free (stream->data);
}

static void
quic_quicly_fifo_egress_shift (quicly_stream_t *stream, size_t delta)
{
  quic_stream_data_t *stream_data;
  session_t *stream_session;
  quic_ctx_t *sctx;
  svm_fifo_t *f;
  u32 rv, max_deq;

  stream_data = (quic_stream_data_t *) stream->data;
  stream_session = get_stream_session_and_ctx_from_stream (stream, &sctx);
  f = stream_session->tx_fifo;

  ASSERT (stream_data->app_tx_data_len >= delta);
  sctx->bytes_written += delta;
  rv = svm_fifo_dequeue_drop (f, delta);
  ASSERT (rv == delta);

  if (svm_fifo_needs_deq_ntf (f, delta))
    session_dequeue_notify (stream_session);

  max_deq = svm_fifo_max_dequeue (f);
  if (max_deq)
    {
      if (max_deq > stream_data->app_tx_data_len - delta)
	{
	  rv = quicly_stream_sync_sendbuf (stream, 1);
	  ASSERT (!rv);
	  sctx->flags &= ~QUIC_F_STREAM_TX_DRAINED;
	  quic_quicly_reschedule_ctx (quic_quicly_get_quic_ctx (
	    sctx->quic_connection_ctx_id, sctx->c_thread_index));
	}
      stream_data->app_tx_data_len = max_deq;
    }
  else
    {
      stream_data->app_tx_data_len = 0;
      ASSERT (sctx->flags & QUIC_F_STREAM_TX_DRAINED);
      /* All data drained and acked, clear fifo flag to allow new events from
       * app. Then check if we need to reschedule as session layer would */
      svm_fifo_unset_event (f);
      if (svm_fifo_max_dequeue (f))
	if (svm_fifo_set_event (f))
	  {
	    /* New data added as we cleared the flag, reschedule ctx */
	    sctx->flags &= ~QUIC_F_STREAM_TX_DRAINED;
	    stream_data->app_tx_data_len = svm_fifo_max_dequeue (f);
	    rv = quicly_stream_sync_sendbuf (stream, 1);
	    quic_quicly_reschedule_ctx (quic_quicly_get_quic_ctx (
	      sctx->quic_connection_ctx_id, sctx->c_thread_index));
	  }
    }
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
  ASSERT (off <= deq_max);
  if (off + *len < deq_max)
    {
      *wrote_all = 0;
    }
  else
    {
      *wrote_all = 1;
      *len = deq_max - off;
      /* if we send all data (final size is known) mark stream as TX_CLOSED */
      ctx->flags |= (ctx->flags & QUIC_F_APP_CLOSED_TX) ?
		      QUIC_F_STREAM_TX_DRAINED | QUIC_F_STREAM_TX_CLOSED :
		      QUIC_F_STREAM_TX_DRAINED;
    }
  ASSERT (*len > 0);

  if (off + *len > stream_data->app_tx_data_len)
    {
      stream_data->app_tx_data_len = off + *len;
    }
  svm_fifo_peek (f, off, *len, dst);
}

static void
quic_quicly_on_stop_sending (quicly_stream_t *stream, quicly_error_t quicly_error)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx =
    quic_quicly_get_quic_ctx (stream_data->ctx_id, stream_data->thread_index);

  QUIC_DBG (
    2, "STOP_SENDING: session 0x%lx (%U)",
    session_handle (session_get (sctx->c_s_index, sctx->c_thread_index)),
    quic_quicly_format_err, quicly_error);

  if (!(sctx->flags & QUIC_F_APP_CLOSED))
    {
      sctx->app_err_code = QUICLY_ERROR_GET_ERROR_CODE (quicly_error);
      session_transport_reset_notify (&sctx->connection);
    }
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
  ASSERT (quic_ctx_is_stream (sctx));
  if (!sctx->stream)
    return;
  stream = sctx->stream;
  stream_data = (quic_stream_data_t *) stream->data;

  f = stream_session->rx_fifo;
  max_deq = svm_fifo_max_dequeue (f);

  ASSERT (stream_data->app_rx_data_len >= max_deq);
  quicly_stream_sync_recvbuf (stream, stream_data->app_rx_data_len - max_deq);
  QUIC_DBG (3, "Acking %u bytes", stream_data->app_rx_data_len - max_deq);
  stream_data->app_rx_data_len = max_deq;

  /* Need to send packets (acks may never be sent otherwise) */
  if (sctx->flags & QUIC_F_STREAM_TX_DRAINED)
    {
      quic_quicly_reschedule_ctx (quic_quicly_get_quic_ctx (
	sctx->quic_connection_ctx_id, sctx->c_thread_index));
    }
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

  stream_data = (quic_stream_data_t *) stream->data;
  sctx =
    quic_quicly_get_quic_ctx (stream_data->ctx_id, stream_data->thread_index);
  stream_session = session_get (sctx->c_s_index, stream_data->thread_index);
  f = stream_session->rx_fifo;

  /* this happen only when we receive EOS without any data */
  if (PREDICT_FALSE (!len))
    goto check_eos;

  max_enq = svm_fifo_max_enqueue_prod (f);
  QUIC_DBG (3, "Enqueuing %u at off %u in %u space", len, off, max_enq);
  /* handle overlapping data */
  if (off < stream_data->app_rx_data_len)
    {
      QUIC_DBG (3,
		"Session [idx %u, app_wrk %u, thread %u, rx-fifo 0x%llx]: "
		"DUPLICATE PACKET (max_enq %u, len %u, "
		"app_rx_data_len %u, off %u, ToBeNQ %u)",
		stream_session->session_index, stream_session->app_wrk_index,
		stream_session->thread_index, f, max_enq, len, stream_data->app_rx_data_len, off,
		off - stream_data->app_rx_data_len + len);
      /* do we already have exactly same piece of the data? */
      if ((off + len) <= stream_data->app_rx_data_len)
	return;
      /* if we get something new adjust offset and length before enqueue (partially overlapping) */
      len = (off + len) - stream_data->app_rx_data_len;
      off = stream_data->app_rx_data_len;
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
      ASSERT (rlen >= len);
      ASSERT (stream_data->app_rx_data_len ==
	      quicly_recvstate_bytes_available (&stream->recvstate));
    }
  else
    {
      rlen = svm_fifo_enqueue_with_offset (f, off - stream_data->app_rx_data_len, len, (u8 *) src);
      if (PREDICT_FALSE (rlen < 0))
	{
	  /*
	   * drop, fifo full
	   * drop, fifo grow
	   */
	  return;
	}
      ASSERT (rlen == 0);
      ASSERT (stream_data->app_rx_data_len ==
	      quicly_recvstate_bytes_available (&stream->recvstate));
    }

  if (!(stream_session->flags & SESSION_F_RX_EVT))
    {
      app_wrk = app_worker_get_if_valid (stream_session->app_wrk_index);
      if (PREDICT_TRUE (app_wrk != 0))
	{
	  stream_session->flags |= SESSION_F_RX_EVT;
	  app_worker_rx_notify (app_wrk, stream_session);
	}
    }

  /* Ask app for deq ntf because we sent zero-window to our peer */
  if (quicly_stream_get_receive_window (stream) == stream_data->app_rx_data_len)
    svm_fifo_add_want_deq_ntf (f, SVM_FIFO_WANT_DEQ_NOTIF);

check_eos:
  /* send half-close notification to app */
  if (!(sctx->flags & QUIC_F_APP_CLOSED_TX) &&
      quicly_recvstate_transfer_complete (&stream->recvstate))
    {
      QUIC_DBG (2, "stream half-close: rcv side closed, ctx_index %u, thread_index %u",
		sctx->c_c_index, sctx->c_thread_index);
      session_transport_closing_notify (&sctx->connection);
    }
}

static void
quic_quicly_on_receive_reset (quicly_stream_t *stream, quicly_error_t quicly_error)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx =
    quic_quicly_get_quic_ctx (stream_data->ctx_id, stream_data->thread_index);

  QUIC_DBG (
    2, "RESET_STREAM: session 0x%lx (%U)",
    session_handle (session_get (sctx->c_s_index, sctx->c_thread_index)),
    quic_quicly_format_err, quicly_error);

  if (!(sctx->flags & QUIC_F_APP_CLOSED))
    {
      sctx->app_err_code = QUICLY_ERROR_GET_ERROR_CODE (quicly_error);
      session_transport_reset_notify (&sctx->connection);
    }
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

static void
quic_quicly_conn_app_init_failed (quic_ctx_t *ctx, const char *reason_phrase)
{
  ctx->flags |= QUIC_F_NO_APP_SESSION;
  /* use 0 as error code because we can't pass quic transport error codes to
   * quicly */
  quicly_close (ctx->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (0), reason_phrase);
  quic_quicly_reschedule_ctx (ctx);
}

static void
quic_quicly_on_quic_session_accepted (quic_ctx_t *ctx)
{
  session_t *quic_session;
  app_worker_t *app_wrk;
  quic_ctx_t *lctx;
  int rv;

  quic_session = session_alloc (ctx->c_thread_index);
  QUIC_DBG (2,
	    "Accept connection (new quic_session): session 0x%lx, "
	    "session_index %u, ctx_index %u, thread %u",
	    session_handle (quic_session), quic_session->session_index, ctx->c_c_index,
	    ctx->c_thread_index);
  ctx->c_s_index = quic_session->session_index;

  lctx = quic_quicly_get_quic_ctx (ctx->listener_ctx_id, 0);

  quic_session->connection_index = ctx->c_c_index;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, ctx->udp_is_ip4);
  quic_session->listener_handle = lctx->c_s_index;

  if (lctx->alpn_protos[0])
    {
      const char *proto = ptls_get_negotiated_protocol (quicly_get_tls (ctx->conn));
      if (proto)
	{
	  tls_alpn_proto_id_t id = { .base = (u8 *) proto, .len = strlen (proto) };
	  ctx->alpn_selected = tls_alpn_proto_by_str (&id);
	}
    }

  /* If notify fails, reset connection immediatly */
  rv = app_worker_init_accepted (quic_session);
  if (rv)
    {
      QUIC_ERR ("Accept connection: failed to allocate fifos");
      quic_quicly_conn_app_init_failed (ctx, "failed to allocate fifos");
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
      quic_quicly_conn_app_init_failed (ctx, "failed to notify app worker");
      return;
    }

  ctx->parent_app_wrk_id = quic_session->app_wrk_index;
  ctx->conn_state = QUIC_CONN_STATE_READY;
}

static_always_inline void
quic_quicly_try_establish (quic_ctx_t *ctx)
{
  /* Conn may be set to null if the connection is terminated */
  if (!ctx->conn || ctx->conn_state != QUIC_CONN_STATE_HANDSHAKE)
    return;

  if (!quic_quicly_handshake_is_complete (ctx->conn))
    return;

  ctx->conn_state = QUIC_CONN_STATE_READY;
  ctx->opaque = quic_quicly_crypto_engine_is_vpp () ? QUIC_QUICLY_RX_STATE_READY_VPP_CRYPTO :
						      QUIC_QUICLY_RX_STATE_READY;

  if (quicly_is_client (ctx->conn))
    {
      if (quic_quicly_notify_app_connected (ctx, SESSION_E_NONE))
	quic_quicly_conn_app_init_failed (ctx, "notify app connected failed");
    }
  else
    quic_quicly_on_quic_session_accepted (ctx);
}

static quicly_error_t
quic_quicly_on_stream_open (quicly_stream_open_t *self, quicly_stream_t *stream)
{
  /* Return code for this function ends either
   * - in quicly_receive : if not QUICLY_ERROR_PACKET_IGNORED, will close
   * connection
   * - in quicly_open_stream, returned directly
   */

  session_t *stream_session, *quic_session;
  quic_stream_data_t *stream_data;
  app_worker_t *app_wrk;
  quic_ctx_t *qctx, *sctx;
  u32 sctx_id;
  int rv;

  QUIC_DBG (2, "on_stream_open called");
  stream->data = clib_mem_alloc (sizeof (quic_stream_data_t));
  stream->callbacks = &quic_quicly_stream_callbacks;
  /* Notify accept on parent qsession, but only if this is not a locally
   * initiated stream */
  if (quicly_stream_is_self_initiated (stream))
    {
      QUIC_DBG (2, "Nothing to do on locally initiated stream");
      return 0;
    }

  sctx_id = quic_ctx_alloc (quic_quicly_main.qm, vlib_get_thread_index ());
  qctx = quic_quicly_get_conn_ctx (stream->conn);

  /* Might need to signal that the connection is ready if the first thing the
   * server does is open a stream */
  quic_quicly_try_establish (qctx);
  /* ctx might be invalidated */
  qctx = quic_quicly_get_conn_ctx (stream->conn);
  QUIC_DBG (2, "qctx->c_s_index %u, qctx->c_c_index %u", qctx->c_s_index,
	    qctx->c_c_index);

  if (qctx->c_s_index == QUIC_SESSION_INVALID)
    {
      QUIC_DBG (2, "Invalid session index on quic c_index %u",
		qctx->c_c_index);
      return 0;
    }
  stream_session = session_alloc (qctx->c_thread_index);
  stream_session->flags |= SESSION_F_STREAM;
  QUIC_DBG (2, "ACCEPTED stream_session 0x%lx ctx %u",
	    session_handle (stream_session), sctx_id);
  sctx = quic_quicly_get_quic_ctx (sctx_id, qctx->c_thread_index);
  sctx->parent_app_wrk_id = qctx->parent_app_wrk_id;
  sctx->parent_app_id = qctx->parent_app_id;
  sctx->crypto_owner_app_wrk_id = qctx->crypto_owner_app_wrk_id;
  sctx->quic_connection_ctx_id = qctx->c_c_index;
  sctx->c_c_index = sctx_id;
  sctx->c_s_index = stream_session->session_index;
  sctx->stream = stream;
  sctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  sctx->flags |= QUIC_F_IS_STREAM;
  sctx->crypto_context_index = qctx->crypto_context_index;
  sctx->udp_session_handle = qctx->udp_session_handle;

  if (quicly_stream_is_unidirectional (stream->stream_id))
    stream_session->flags |= SESSION_F_UNIDIRECTIONAL;

  stream_data = (quic_stream_data_t *) stream->data;
  stream_data->ctx_id = sctx_id;
  stream_data->thread_index = sctx->c_thread_index;
  stream_data->app_rx_data_len = 0;
  stream_data->app_tx_data_len = 0;

  stream_session->session_state = SESSION_STATE_CREATED;
  stream_session->app_wrk_index = sctx->parent_app_wrk_id;
  stream_session->connection_index = sctx->c_c_index;
  stream_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, qctx->udp_is_ip4);
  quic_session = session_get (qctx->c_s_index, qctx->c_thread_index);
  stream_session->listener_handle = listen_session_get_handle (quic_session);

  app_wrk = app_worker_get (stream_session->app_wrk_index);
  if ((rv = app_worker_init_connected (app_wrk, stream_session)))
    {
      QUIC_ERR ("failed to allocate fifos");
      return -1; /* close connection */
    }
  svm_fifo_add_want_deq_ntf (stream_session->rx_fifo,
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL |
			       SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);
  svm_fifo_init_ooo_lookup (stream_session->rx_fifo, 0 /* ooo enq */);
  svm_fifo_init_ooo_lookup (stream_session->tx_fifo, 1 /* ooo deq */);

  stream_session->session_state = SESSION_STATE_ACCEPTING;
  if ((rv = app_worker_accept_notify (app_wrk, stream_session)))
    {
      QUIC_ERR ("failed to notify accept worker app");
      return -1; /* close connection */
    }

  return 0;
}

static void
quic_quicly_on_closed_by_remote (quicly_closed_by_remote_t *self, quicly_conn_t *conn,
				 quicly_error_t code, uint64_t frame_type, const char *reason,
				 size_t reason_len)
{
  quic_ctx_t *ctx = quic_quicly_get_conn_ctx (conn);
#if QUIC_DEBUG >= 2
  if (ctx->c_s_index == QUIC_SESSION_INVALID)
    {
      clib_warning ("Unopened Session closed by peer: error %U, reason %U, "
		    "ctx_index %u, thread %u",
		    quic_quicly_format_err, code, format_ascii_bytes, reason,
		    reason_len, ctx->c_c_index, ctx->c_thread_index);
    }
  else
    {
      session_t *quic_session =
	session_get (ctx->c_s_index, ctx->c_thread_index);
      clib_warning ("Session closed by peer: session 0x%lx, error %U, reason "
		    "%U, ctx_index %u, thread %u",
		    session_handle (quic_session), quic_quicly_format_err,
		    code, format_ascii_bytes, reason, reason_len,
		    ctx->c_c_index, ctx->c_thread_index);
    }
#endif
  if (ctx->conn_state == QUIC_CONN_STATE_HANDSHAKE)
    {
      QUIC_DBG (2, "Handshake failed: ctx_index %u, thread %u", ctx->c_c_index,
		ctx->c_thread_index);
      return;
    }
  ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING;
  if (ctx->c_s_index != QUIC_SESSION_INVALID)
    {
      ctx->app_err_code = QUICLY_ERROR_GET_ERROR_CODE (code);
      session_transport_closing_notify (&ctx->connection);
    }
}

static int64_t
quic_quicly_get_time (quicly_now_t *self)
{
  return (int64_t) quic_wrk_ctx_get (quic_quicly_main.qm,
				     vlib_get_thread_index ())
    ->time_now;
}

static quicly_stream_open_t on_stream_open = { quic_quicly_on_stream_open };
static quicly_closed_by_remote_t on_closed_by_remote = {
  quic_quicly_on_closed_by_remote
};
static quicly_now_t quicly_vpp_now_cb = { quic_quicly_get_time };

static void
quic_quicly_crypto_context_release (u32 crctx_ndx, u8 thread_index)
{
  quic_quicly_crypto_context_free (crctx_ndx);
}

static quic_crypto_context_t *
quic_quicly_get_crypto_context (quic_ctx_t *ctx)
{
  quic_quicly_crypto_ctx_t *crctx = quic_quicly_crypto_context_get (ctx->crypto_context_index);
  return &crctx->ctx;
}

static_always_inline int
quic_quicly_crypto_ctx_get_or_init (quic_ctx_t *ctx)
{
  quic_quicly_crypto_ctx_t *crctx = quic_quicly_crypto_context_get_or_alloc (ctx);
  if (PREDICT_FALSE (!crctx->quicly_ctx.stream_open))
    {
      crctx->quicly_ctx.stream_open = &on_stream_open;
      crctx->quicly_ctx.closed_by_remote = &on_closed_by_remote;
      crctx->quicly_ctx.now = &quicly_vpp_now_cb;
    }
  return 0;
}

static int
quic_quicly_crypto_context_acquire_listen (quic_ctx_t *ctx)
{
  /* for server we init data (or reuse existing) when app start listen */
  return quic_quicly_crypto_ctx_get_or_init (ctx);
}

static int
quic_quicly_crypto_context_acquire_accept (quic_ctx_t *ctx)
{
  quic_ctx_t *lctx;
  quic_quicly_crypto_ctx_t *crctx;

  /* listener already created data */
  lctx = quic_quicly_get_quic_ctx (ctx->listener_ctx_id, 0);
  ctx->crypto_context_index = lctx->crypto_context_index;
  crctx = quic_quicly_crypto_context_get (ctx->crypto_context_index);
  quic_quicly_crypto_context_reserve_data (crctx);
  return 0;
}

static int
quic_quicly_crypto_context_acquire_connect (quic_ctx_t *ctx)
{
  /* connects are always done from same thread, init data for all workers here if needed because it
   * needs to stay same once used in quicly connection */
  return quic_quicly_crypto_ctx_get_or_init (ctx);
}

static void
quic_quicly_connection_migrate (quic_ctx_t *ctx)
{
  quic_quicly_crypto_ctx_t *crctx;

  /* increment ref count to be sure data is not freed before we process migrate rpc */
  crctx = quic_quicly_crypto_context_get (ctx->crypto_context_index);
  quic_quicly_crypto_context_reserve_data (crctx);
}

static void
quic_quicly_connection_migrate_rpc (quic_ctx_t *ctx)
{
  u32 new_ctx_index, thread_index = vlib_get_thread_index ();
  quic_ctx_t *new_ctx;
  quicly_conn_t *conn;
  session_t *udp_session;

  new_ctx_index = quic_ctx_alloc (quic_quicly_main.qm, thread_index);
  new_ctx = quic_quicly_get_quic_ctx (new_ctx_index, thread_index);

  QUIC_DBG (
    2, "Migrate conn (ctx_index %u, thread %u) to new_ctx_index %u, thread %u",
    ctx->c_c_index, ctx->c_thread_index, new_ctx_index, thread_index);

  clib_memcpy (new_ctx, ctx, sizeof (quic_ctx_t));
  clib_mem_free (ctx);

  new_ctx->c_thread_index = thread_index;
  new_ctx->c_c_index = new_ctx_index;

  conn = new_ctx->conn;
  quic_quicly_store_conn_ctx (conn, new_ctx);
  new_ctx->timers[QUIC_TIMER_TX] = QUIC_TIMER_HANDLE_INVALID;

  quic_quicly_reschedule_ctx (new_ctx);

  udp_session = session_get_from_handle (new_ctx->udp_session_handle);
  udp_session->opaque = new_ctx_index;
  udp_session->flags &= ~SESSION_F_IS_MIGRATING;

  /* app might detach meanwhile */
  if (session_half_open_migrated_notify (&new_ctx->connection))
    {
      new_ctx->flags |= QUIC_F_NO_APP_SESSION;
      quicly_close (new_ctx->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (0), "app detach");
      quic_quicly_reschedule_ctx (new_ctx);
      return;
    }

  /*  Trigger write on this connection if necessary */
  if (svm_fifo_max_dequeue (udp_session->tx_fifo))
    {
      quic_quicly_set_udp_tx_evt (udp_session);
    }
}

static void
quic_quicly_stateless_reset (session_handle_t udp_session_handle, quic_quicly_rx_packet_ctx_t *pctx)
{
  /* short header packet; potentially a dead connection. No need to check the
   * length of the incoming packet, because loop is prevented by authenticating
   * the CID (by checking thread_id). If the peer is also sending a
   * reset, then the next CID is highly likely to contain a non-authenticating
   * CID, ... */
  QUIC_DBG (2, "Sending stateless reset");
  quic_quicly_main_t *qqm = &quic_quicly_main;
  session_t *udp_session;
  quicly_context_t *quicly_ctx;
  session_dgram_hdr_t hdr;

  quicly_ctx = quic_quicly_get_quicly_ctx_from_udp (udp_session_handle);
  udp_session = session_get_from_handle (udp_session_handle);

  u8 *payload = qqm->tx_bufs[udp_session->thread_index];
  size_t payload_len =
    quicly_send_stateless_reset (quicly_ctx, pctx->packet.cid.dest.encrypted.base, payload);
  if (payload_len == 0)
    return;

  hdr.data_length = payload_len;
  hdr.data_offset = 0;
  hdr.gso_size = 0;
  svm_fifo_seg_t segs[2] = { { (u8 *) &hdr, sizeof (hdr) }, { payload, payload_len } };
  svm_fifo_enqueue_segments (udp_session->tx_fifo, segs, 2, 0 /* allow partial */);
  quic_quicly_set_udp_tx_evt (udp_session);
  return;
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
quic_quicly_on_app_closed (u32 ctx_index, clib_thread_index_t thread_index)
{
  int rv;
  quic_ctx_t *ctx =
    quic_quicly_get_quic_ctx_if_valid (ctx_index, thread_index);
  if (!ctx)
    {
      return;
    }
  ctx->flags |= QUIC_F_APP_CLOSED;
  session_t *stream_session =
    session_get (ctx->c_s_index, ctx->c_thread_index);
  QUIC_DBG (2, "App closing session 0x%lx ctx_index %u",
	    session_handle (stream_session), ctx->c_c_index);
  if (quic_ctx_is_stream (ctx))
    {
      if (!ctx->stream)
	{
	  QUIC_DBG (2,
		    "App confirm stream close going to free ctx, ctx_index %u "
		    "thread_index %u",
		    ctx->c_c_index, ctx->c_thread_index);
	  session_transport_closed_notify (&ctx->connection);
	  session_transport_delete_notify (&ctx->connection);
	  quic_ctx_free (quic_quicly_main.qm, ctx);
	  return;
	}
      quicly_stream_t *stream = ctx->stream;
      if (!quicly_stream_has_send_side (quicly_is_client (stream->conn),
					stream->stream_id))
	{
	  QUIC_ERR ("stream doesn't have send side: ctx_index %u, thread %u",
		    ctx_index, thread_index);
	  return;
	}
      if (!quicly_sendstate_is_open (&stream->sendstate))
	{
	  QUIC_DBG (2, "send side already closed");
	  return;
	}
      QUIC_DBG (2, "App closed stream, ctx_index %u thread_index %u",
		ctx->c_c_index, ctx->c_thread_index);
      quicly_sendstate_shutdown (
	&stream->sendstate,
	ctx->bytes_written + svm_fifo_max_dequeue (stream_session->tx_fifo));
      ctx->flags |= QUIC_F_APP_CLOSED_TX;
      rv = quicly_stream_sync_sendbuf (stream, 1);
      ASSERT (!rv);
      quic_quicly_reschedule_ctx (quic_quicly_get_quic_ctx (
	ctx->quic_connection_ctx_id, ctx->c_thread_index));
      return;
    }
  else
    {
      /* Cleaning up now to avoid ossl dependency in quic.c */
      if (ctx->peer_cert)
	{
	  X509_free ((X509 *) ctx->peer_cert);
	  ctx->peer_cert = 0;
	}
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
      quicly_close (
	conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (ctx->app_err_code),
	"shutting down");
      /* This also causes all streams to be closed (and the cb called) */
      quic_quicly_reschedule_ctx (ctx);
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

static void
quic_quicly_on_app_closed_tx (u32 ctx_index, clib_thread_index_t thread_index)
{
  session_t *stream_session;
  quic_ctx_t *ctx;
  quicly_stream_t *stream;

  ctx = quic_quicly_get_quic_ctx_if_valid (ctx_index, thread_index);
  if (!ctx)
    {
      return;
    }
  if (!quic_ctx_is_stream (ctx))
    {
      QUIC_ERR ("Trying to half-close connection");
      return;
    }
  stream = ctx->stream;
  if (!quicly_stream_has_send_side (quicly_is_client (stream->conn),
				    stream->stream_id))
    {
      QUIC_ERR ("Trying to half-close stream without send side");
      return;
    }
  if (!quicly_sendstate_is_open (&stream->sendstate))
    {
      QUIC_DBG (2, "send side already closed");
      return;
    }

  stream_session = session_get (ctx->c_s_index, ctx->c_thread_index);
  QUIC_DBG (2, "App half-closing session 0x%lx ctx_index %u",
	    session_handle (stream_session), ctx->c_c_index);
  quicly_sendstate_shutdown (&stream->sendstate,
			     ctx->bytes_written +
			       svm_fifo_max_dequeue (stream_session->tx_fifo));
  ctx->flags |= QUIC_F_APP_CLOSED_TX;
  quicly_stream_sync_sendbuf (stream, 1);
  quic_quicly_reschedule_ctx (quic_quicly_get_quic_ctx (
    ctx->quic_connection_ctx_id, ctx->c_thread_index));
}

static void
quic_quicly_on_app_reset (u32 ctx_index, clib_thread_index_t thread_index)
{
  quic_ctx_t *ctx;
  quicly_stream_t *stream;

  ctx = quic_quicly_get_quic_ctx_if_valid (ctx_index, thread_index);
  if (!ctx)
    {
      return;
    }
  if (!quic_ctx_is_stream (ctx))
    {
      /* TODO: handle as connection close? */
      QUIC_ERR ("Trying to reset connection");
      return;
    }

  QUIC_DBG (2,
	    "App reset session 0x%lx ctx_index %u, app proto error code 0x%lx",
	    session_handle (session_get (ctx->c_s_index, ctx->c_thread_index)),
	    ctx->c_c_index, ctx->app_err_code);
  ctx->flags |= QUIC_F_APP_CLOSED;
  /* stream might get destroyed by quicly meanwhile */
  if (!ctx->stream)
    {
      session_transport_closed_notify (&ctx->connection);
      session_transport_delete_notify (&ctx->connection);
      quic_ctx_free (quic_quicly_main.qm, ctx);
      return;
    }
  stream = ctx->stream;
  if (quicly_stream_has_receive_side (quicly_is_client (stream->conn),
				      stream->stream_id) &&
      !quicly_recvstate_transfer_complete (&stream->recvstate))
    {
      quicly_request_stop (
	stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (ctx->app_err_code));
    }
  if (quicly_stream_has_send_side (quicly_is_client (stream->conn),
				   stream->stream_id) &&
      !quicly_sendstate_transfer_complete (&stream->sendstate))
    {
      quicly_reset_stream (
	stream, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (ctx->app_err_code));
    }
}

static quic_quicly_rx_error_t
quic_quicly_accept_connection (quic_ctx_t *ctx, quic_quicly_rx_packet_ctx_t *pctx,
			       struct sockaddr *src_addr)
{
  quicly_context_t *quicly_ctx;
  quicly_conn_t *conn;
  int quicly_state;
  quicly_error_t rv;
  quic_quicly_main_t *qqm = &quic_quicly_main;
  quic_main_t *qm = qqm->qm;

  QUIC_DBG (2, "Accept connection: pkt ctx_index %u, thread %u", ctx->c_c_index,
	    ctx->c_thread_index);

  ASSERT (ctx->c_s_index == QUIC_SESSION_INVALID);

  quicly_ctx = quic_quicly_get_quicly_ctx_from_ctx (ctx);
  rv = quicly_accept (&conn, quicly_ctx, NULL, src_addr, &pctx->packet, NULL,
		      &qqm->next_cid[ctx->c_thread_index], NULL,
		      (void *) (((u64) ctx->c_thread_index) << 32 | (u64) ctx->c_c_index));
  quic_mvt.conn_accept_timer_stop (quic_wrk_ctx_get (qm, ctx->c_thread_index), ctx);
  if (rv)
    {
      /* Invalid packet, pass */
      ASSERT (conn == NULL);
      QUIC_ERR ("Accept connection: failed with %U", quic_quicly_format_err, rv);
      /* close UDP session */
      if (ctx->conn_state < QUIC_CONN_STATE_CLOSED)
	{
	  ctx->conn_state = QUIC_CONN_STATE_CLOSED;
	  quic_disconnect_transport (ctx, qm->app_index);
	}
      return QUIC_QUICLY_RX_ERROR_CRITICAL;
    }
  ASSERT (conn != NULL);

  ++qqm->next_cid[ctx->c_thread_index].master_id;
  ctx->conn = conn;
  quic_increment_counter (qm, QUIC_ERROR_ACCEPTED_CONNECTION, 1);

  QUIC_DBG (2, "Accept connection: ctx_index %u, thread %u", ctx->c_c_index, ctx->c_thread_index);

  quicly_state = quicly_get_state (conn);
  /* if handshake failed (e.g. ALPN negotiation failed) quicly connection is in
   * closing state, in this case we don't need to create session and notify
   * app, connection will be closed when error response is sent */
  if (quicly_state >= QUICLY_STATE_CLOSING)
    {
      QUIC_DBG (2, "Handshake failed, closing: ctx_index %u, thread %u",
		ctx->c_c_index, ctx->c_thread_index);
      ctx->conn_state = QUIC_CONN_STATE_ACTIVE_CLOSING;
      return QUIC_QUICLY_RX_ERROR_WARNING;
    }
  if (!quic_quicly_handshake_is_complete (conn))
    {
      QUIC_DBG (2, "Handshake not yet completed: ctx_index %u, thread %u", ctx->c_c_index,
		ctx->c_thread_index);
      ctx->opaque = quic_quicly_crypto_engine_is_vpp () ?
		      QUIC_QUICLY_RX_STATE_HANDSHAKE_VPP_CRYPTO :
		      QUIC_QUICLY_RX_STATE_HANDSHAKE;
      ctx->conn_state = QUIC_CONN_STATE_HANDSHAKE;
      return QUIC_QUICLY_RX_ERROR_NONE;
    }

  ctx->opaque = quic_quicly_crypto_engine_is_vpp () ? QUIC_QUICLY_RX_STATE_READY_VPP_CRYPTO :
						      QUIC_QUICLY_RX_STATE_READY;
  quic_quicly_on_quic_session_accepted (ctx);
  return QUIC_QUICLY_RX_ERROR_NONE;
}

static_always_inline int
quic_quicly_process_one_rx_dgram (quic_ctx_t *ctx, quicly_context_t *quicly_ctx,
				  svm_fifo_t *rx_fifo, u32 data_length, u32 fifo_offset,
				  u32 *packets_num, quic_quicly_rx_dgram_ctx_t *dctx,
				  session_handle_t udp_session_handle)
{
  clib_thread_index_t thread_index = ctx->c_thread_index;
  size_t plen;
  int rv;
  quic_quicly_rx_packet_ctx_t *pctx;
  quic_quicly_main_t *qqm = &quic_quicly_main;

  rv = svm_fifo_peek (rx_fifo, fifo_offset, data_length, dctx->data);
  ASSERT (rv == data_length);

  size_t off = 0;

  /* quic packets might be coalesced into single udp datagram */
  while (off < data_length)
    {
      pctx = vec_elt_at_index (qqm->rx_packets[thread_index], *packets_num);
      plen = quicly_decode_packet (quicly_ctx, &pctx->packet, dctx->data, data_length, &off);
      if (plen == SIZE_MAX)
	{
	  QUIC_ERR ("packet decode failed");
	  return 1;
	}
      (*packets_num)++;

      if (ctx->conn)
	{
	  const quicly_cid_plaintext_t *our_cid = quicly_get_master_id (ctx->conn);
	  if (our_cid->master_id != pctx->packet.cid.dest.plaintext.master_id ||
	      our_cid->thread_id != pctx->packet.cid.dest.plaintext.thread_id)
	    {
	      if (QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]))
		{
		  const quicly_cid_t *odcid = quicly_get_original_dcid (ctx->conn);
		  if (!(odcid->len == pctx->packet.cid.dest.encrypted.len &&
			0 == clib_memcmp (odcid->cid, pctx->packet.cid.dest.encrypted.base,
					  odcid->len)))
		    goto stateless_reset;
		}
	      else
		goto stateless_reset;
	    }
	}
      else
	{
	  if (!pctx->packet.cid.dest.might_be_client_generated ||
	      !QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]))
	    goto stateless_reset;
	}
    }
  return 0;

stateless_reset:
  quic_quicly_stateless_reset (udp_session_handle, pctx);
  (*packets_num)--;
  return 1;
}

static int
quic_quicly_connect (quic_ctx_t *ctx, u32 ctx_index,
		     clib_thread_index_t thread_index, struct sockaddr *sa)
{
  quicly_context_t *quicly_ctx;
  ptls_iovec_t alpn_list[4];
  ptls_handshake_properties_t hs_properties = {
    .client.negotiated_protocols.list = alpn_list
  };
  const tls_alpn_proto_id_t *alpn_proto;
  quic_quicly_main_t *qqm = &quic_quicly_main;
  int i;
  quicly_error_t ret;

  ctx->opaque = quic_quicly_crypto_engine_is_vpp () ? QUIC_QUICLY_RX_STATE_HANDSHAKE_VPP_CRYPTO :
						      QUIC_QUICLY_RX_STATE_HANDSHAKE;
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

  quic_increment_counter (qqm->qm, QUIC_ERROR_OPENED_CONNECTION, 1);
  return 0;
}

static quic_stream_id_t
quic_quicly_stream_get_stream_id (quic_ctx_t *ctx)
{
  quicly_stream_t *stream = (quicly_stream_t *) ctx->stream;

  return stream ? stream->stream_id : QUIC_INVALID_STREAM_ID;
}

static u8 *
quic_quicly_format_stream_stats (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quicly_stream_t *stream = (quicly_stream_t *) ctx->stream;
  quic_stream_data_t *stream_data;
  u32 i;

  if (!stream)
    s = format (s, " destroyed\n");
  else
    {
      stream_data = (quic_stream_data_t *) stream->data;
      s = format (s, " snd-wnd %lu rcv-wnd %lu app_rx_data_len %u app_tx_data_len %u\n",
		  stream->_send_aux.max_stream_data, stream->_recv_aux.window,
		  stream_data->app_rx_data_len, stream_data->app_tx_data_len);
      int is_client = quicly_is_client (stream->conn);
      if (quicly_stream_has_receive_side (is_client, stream->stream_id))
	{
	  if (quicly_recvstate_transfer_complete (&stream->recvstate))
	    s = format (s, " rcv-side-closed\n");
	  s = format (s, " received-ranges");
	  for (i = 0; i < stream->recvstate.received.num_ranges; i++)
	    s = format (s, " [%lu - %lu]", stream->recvstate.received.ranges[i].start,
			stream->recvstate.received.ranges[i].end);
	  s = format (s, "\n");
	  s = format (s, " data-offset %lu\n", stream->recvstate.data_off);
	  if (stream->recvstate.eos != UINT64_MAX)
	    s = format (s, " eos-offset %lu\n", stream->recvstate.eos);
	}
      if (quicly_stream_has_send_side (is_client, stream->stream_id))
	{
	  if (!quicly_sendstate_is_open (&stream->sendstate))
	    s = format (s, " snd-side-closed\n");
	  s = format (s, " snd-blocked %u\n", stream->_send_aux.blocked);
	  s = format (s, " acked-ranges");
	  for (i = 0; i < stream->sendstate.acked.num_ranges; i++)
	    s = format (s, " [%lu - %lu]", stream->sendstate.acked.ranges[i].start,
			stream->sendstate.acked.ranges[i].end);
	  s = format (s, "\n");
	  s = format (s, " pending-ranges");
	  for (i = 0; i < stream->sendstate.pending.num_ranges; i++)
	    s = format (s, " [%lu - %lu]", stream->sendstate.pending.ranges[i].start,
			stream->sendstate.pending.ranges[i].end);
	  s = format (s, "\n");
	}
    }
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
quic_quicly_format_rx_frame_stats (u8 *s, va_list *args)
{
  quicly_stats_t *quicly_stats = va_arg (*args, quicly_stats_t *);
  u32 indent = format_get_indent (s);

  s = format (
    s, "reset-stream %lu stop-sending %lu max-data %lu max-stream-data %lu\n",
    quicly_stats->num_frames_received.reset_stream, quicly_stats->num_frames_received.stop_sending,
    quicly_stats->num_frames_received.max_data, quicly_stats->num_frames_received.max_stream_data);
  s = format (s, "%Udata-blocked %lu stream-data-blocked %lu transport-close %lu app-close %lu\n",
	      format_white_space, indent, quicly_stats->num_frames_received.data_blocked,
	      quicly_stats->num_frames_received.stream_data_blocked,
	      quicly_stats->num_frames_received.transport_close,
	      quicly_stats->num_frames_received.application_close);
  s =
    format (s, "%Unew-conn-id %lu retire-conn-id %lu crypto %lu new-token %u\n", format_white_space,
	    indent, quicly_stats->num_frames_received.new_connection_id,
	    quicly_stats->num_frames_received.retire_connection_id,
	    quicly_stats->num_frames_received.crypto, quicly_stats->num_frames_received.new_token);
  return s;
}

static u8 *
quic_quicly_format_tx_frame_stats (u8 *s, va_list *args)
{
  quicly_stats_t *quicly_stats = va_arg (*args, quicly_stats_t *);
  u32 indent = format_get_indent (s);

  s =
    format (s, "reset-stream %lu stop-sending %lu max-data %lu max-stream-data %lu\n",
	    quicly_stats->num_frames_sent.reset_stream, quicly_stats->num_frames_sent.stop_sending,
	    quicly_stats->num_frames_sent.max_data, quicly_stats->num_frames_sent.max_stream_data);
  s = format (s, "%Udata-blocked %lu stream-data-blocked %lu transport-close %lu app-close %lu\n",
	      format_white_space, indent, quicly_stats->num_frames_sent.data_blocked,
	      quicly_stats->num_frames_sent.stream_data_blocked,
	      quicly_stats->num_frames_sent.transport_close,
	      quicly_stats->num_frames_sent.application_close);
  s = format (s, "%Unew-conn-id %lu retire-conn-id %lu crypto %lu new-token %u\n",
	      format_white_space, indent, quicly_stats->num_frames_sent.new_connection_id,
	      quicly_stats->num_frames_sent.retire_connection_id,
	      quicly_stats->num_frames_sent.crypto, quicly_stats->num_frames_sent.new_token);
  return s;
}

static u8 *
quic_quicly_format_connection_stats (u8 *s, va_list *args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quicly_stats_t quicly_stats;

  quicly_get_stats (ctx->conn, &quicly_stats);

  s = format (s, " rtt: min %lu smoothed %lu var %lu last %lu\n",
	      quicly_stats.rtt.minimum, quicly_stats.rtt.smoothed,
	      quicly_stats.rtt.variance, quicly_stats.rtt.latest);
  s =
    format (s, " rx: pkt %lu initial %lu zero-rtt %lu handshake %lu ack %lu\n",
	    quicly_stats.num_packets.received,
	    quicly_stats.num_packets.initial_received,
	    quicly_stats.num_packets.zero_rtt_received,
	    quicly_stats.num_packets.handshake_received,
	    quicly_stats.num_packets.ack_received);
  s = format (s, " tx: pkt %lu initial %lu zero-rtt %lu handshake %lu\n",
	      quicly_stats.num_packets.sent,
	      quicly_stats.num_packets.initial_sent,
	      quicly_stats.num_packets.zero_rtt_sent,
	      quicly_stats.num_packets.handshake_sent);
  s =
    format (s, " pkt-lost %lu late-ack %lu decrypt-failed %lu pkt-ooo %lu\n",
	    quicly_stats.num_packets.lost, quicly_stats.num_packets.late_acked,
	    quicly_stats.num_packets.decryption_failed,
	    quicly_stats.num_packets.received_out_of_order);
  s = format (s, " cc-algo %s cwnd %u ssthresh: %u recovery_end %lu\n",
	      quicly_stats.cc.type->name, quicly_stats.cc.cwnd,
	      quicly_stats.cc.ssthresh, quicly_stats.cc.recovery_end);
  s = format (s, " cwnd-init %u cwnd-min %u cwnd-max %u\n",
	      quicly_stats.cc.cwnd_initial, quicly_stats.cc.cwnd_minimum,
	      quicly_stats.cc.cwnd_maximum);
  s = format (s, " rx frames: %U", quic_quicly_format_rx_frame_stats, &quicly_stats);
  s = format (s, " tx frames: %U", quic_quicly_format_tx_frame_stats, &quicly_stats);
  return s;
}

static_always_inline quic_quicly_rx_error_t
quic_quicly_receive_a_packet (quic_ctx_t *ctx, quic_quicly_rx_packet_ctx_t *pctx,
			      struct sockaddr *src_addr, u8 is_vpp_crypto, u8 try_establish)
{
  QUIC_DBG (2, "ctx_index %u, thread_index %u, vpp_crypto %u, try_establish %u", ctx->c_c_index,
	    ctx->c_thread_index, is_vpp_crypto, try_establish);

  if (is_vpp_crypto)
    quic_quicly_crypto_decrypt_packet (ctx, pctx);

  quicly_error_t rv = quicly_receive (ctx->conn, NULL, src_addr, &pctx->packet);
  /* bail out if fatal error */
  if (rv == QUICLY_ERROR_STATE_EXHAUSTION || rv == PTLS_ERROR_NO_MEMORY)
    {
      QUIC_ERR ("quicly_receive return error %U", quic_quicly_format_err, rv);
      /* close UDP session */
      if (ctx->conn_state < QUIC_CONN_STATE_CLOSED)
	{
	  quic_quicly_main_t *qqm = &quic_quicly_main;
	  quic_main_t *qm = qqm->qm;
	  ctx->conn_state = QUIC_CONN_STATE_CLOSED;
	  quic_increment_counter (qm, QUIC_ERROR_CLOSED_CONNECTION, 1);
	  quic_disconnect_transport (ctx, qm->app_index);
	}
      return QUIC_QUICLY_RX_ERROR_CRITICAL;
    }

  if (try_establish)
    quic_quicly_try_establish (ctx);

  return QUIC_QUICLY_RX_ERROR_NONE;
}

static quic_quicly_rx_error_t
quic_quicly_rx_state_ready (quic_ctx_t *ctx, quic_quicly_rx_packet_ctx_t *pctx,
			    struct sockaddr *src_addr)
{
  return quic_quicly_receive_a_packet (ctx, pctx, src_addr, 0, 0);
}

static quic_quicly_rx_error_t
quic_quicly_rx_state_handshake (quic_ctx_t *ctx, quic_quicly_rx_packet_ctx_t *pctx,
				struct sockaddr *src_addr)
{
  return quic_quicly_receive_a_packet (ctx, pctx, src_addr, 0, 1);
}

static quic_quicly_rx_error_t
quic_quicly_rx_state_ready_vpp_crypto (quic_ctx_t *ctx, quic_quicly_rx_packet_ctx_t *pctx,
				       struct sockaddr *src_addr)
{
  return quic_quicly_receive_a_packet (ctx, pctx, src_addr, 1, 0);
}

static quic_quicly_rx_error_t
quic_quicly_rx_state_handshake_vpp_crypto (quic_ctx_t *ctx, quic_quicly_rx_packet_ctx_t *pctx,
					   struct sockaddr *src_addr)
{
  return quic_quicly_receive_a_packet (ctx, pctx, src_addr, 1, 1);
}

static_always_inline int
quic_quicly_connect_stream (void *quic_conn, void **quic_stream,
			    quic_stream_data_t **quic_stream_data,
			    u8 is_unidir)
{
  quicly_conn_t *conn = quic_conn;
  quicly_stream_t *quicly_stream;
  quicly_error_t rv;

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

static_always_inline u64
quic_quicly_stream_tx (quic_ctx_t *ctx, session_t *stream_session)
{
  quic_stream_data_t *stream_data;
  quicly_stream_t *stream;
  u32 max_deq;

  if (ctx->flags & QUIC_F_STREAM_TX_CLOSED)
    {
      QUIC_ERR ("tried to send on tx-closed stream");
      return 0;
    }

  stream = ctx->stream;
  ASSERT (stream);
  stream_data = (quic_stream_data_t *) stream->data;
  max_deq = svm_fifo_max_dequeue (stream_session->tx_fifo);
  ASSERT (max_deq >= stream_data->app_tx_data_len);

  /* Spurious send, nothing else to do */
  if (max_deq == stream_data->app_tx_data_len)
    {
      QUIC_DBG (3, "No new data: %u max_deq %d", stream_session->session_index,
		max_deq);
      return 0;
    }

  stream_data->app_tx_data_len = max_deq;
  int rv = quicly_stream_sync_sendbuf (stream, 1);
  ASSERT (!rv);

  /* Just in case engine is waiting for new app data */
  quic_quicly_reschedule_ctx (quic_quicly_get_quic_ctx (
    ctx->quic_connection_ctx_id, ctx->c_thread_index));
  ctx->flags &= ~QUIC_F_STREAM_TX_DRAINED;

  return 1;
}

static void
quic_quicly_engine_init (quic_main_t *qm)
{
  quic_quicly_main_t *qqm = &quic_quicly_main;
  quicly_cid_plaintext_t *next_cid;
  u32 i;

  QUIC_DBG (2, "Quic engine init: quicly");
  qm->default_crypto_engine = CRYPTO_ENGINE_PICOTLS;
  qm->default_quic_cc = QUIC_CC_RENO;
  qm->max_packets_per_key = DEFAULT_MAX_PACKETS_PER_KEY;
  qqm->session_cache.super.cb = quic_quicly_encrypt_ticket_cb;
  qqm->qm = qm;

  vec_validate (qqm->next_cid, qm->num_threads - 1);
  vec_validate (qqm->rx_packets, qm->num_threads - 1);
  vec_validate (qqm->rx_dgrams, qm->num_threads - 1);
  vec_validate (qqm->tx_packets, qm->num_threads - 1);
  vec_validate (qqm->tx_bufs, qm->num_threads - 1);
  next_cid = qqm->next_cid;
  quic_quicly_crypto_init (qqm);

  for (i = 0; i < qm->num_threads; i++)
    {
      next_cid[i].thread_id = i;
      vec_validate (qqm->rx_packets[i], QUIC_QUICLY_RCV_MAX_PACKETS - 1);
      vec_validate (qqm->rx_dgrams[i], QUIC_QUICLY_RCV_MAX_DGRAMS - 1);
      vec_validate (qqm->tx_packets[i], QUIC_QUICLY_SEND_PACKET_VEC_SIZE - 1);
      vec_validate (qqm->tx_bufs[i], QUIC_QUICLY_SEND_PACKET_VEC_SIZE * QUIC_MAX_PACKET_SIZE);
    }
}

static quic_quicly_rx_handler quic_quicly_rx_state_funcs[QUIC_QUICLY_RX_N_STATES] = {
  quic_quicly_accept_connection,
  quic_quicly_rx_state_ready,
  quic_quicly_rx_state_handshake,
  quic_quicly_rx_state_ready_vpp_crypto,
  quic_quicly_rx_state_handshake_vpp_crypto,
};

static int
quic_quicly_udp_session_rx_packets (session_t *us)
{
  /*  Read data from UDP rx_fifo and pass it to the quic_eng conn. */
  quic_quicly_main_t *qqm = &quic_quicly_main;
  clib_thread_index_t thread_index = us->thread_index;
  quic_worker_ctx_t *wc = quic_wrk_ctx_get (qqm->qm, thread_index);
  session_handle_t udp_session_handle = session_handle (us);
  u32 fifo_offset, i, max_deq, left_deq, packets_num, full_len;
  quic_ctx_t *ctx;
  quic_quicly_rx_packet_ctx_t *packet_ctx;
  quic_quicly_rx_dgram_ctx_t *dgram_ctx;
  int rv;
  transport_connection_t *tc;
  quicly_address_t src_addr;
  svm_fifo_t *rx_fifo = us->rx_fifo;
  u32 opaque = us->opaque;
  quicly_context_t *quicly_ctx;
  session_dgram_pre_hdr_t ph; /* only pre-header dgram because the session is connected */

  ASSERT (thread_index == vlib_get_thread_index ());
  ASSERT (vec_len (qqm->rx_packets[thread_index]) >= QUIC_QUICLY_RCV_MAX_PACKETS);

  if (PREDICT_FALSE (us->flags & SESSION_F_IS_MIGRATING))
    {
      QUIC_DBG (3, "RX on migrating udp session");
      return 0;
    }

  max_deq = svm_fifo_max_dequeue (us->rx_fifo);
  if (PREDICT_FALSE (max_deq < SESSION_CONN_HDR_LEN))
    {
      return 0;
    }
  left_deq = max_deq;
  fifo_offset = 0;

  /* we can do it here because the session is connected */
  tc = session_get_transport (us);
  quic_build_sockaddr (&src_addr.sa, &tc->rmt_ip, tc->rmt_port, tc->is_ip4);

  ctx = quic_quicly_get_quic_ctx (opaque, thread_index);
  ASSERT (!quic_ctx_is_stream (ctx));
  quicly_ctx = quic_quicly_get_quicly_ctx_from_ctx (ctx);

rx_start:

  packets_num = 0;

  /* expect worst case 4 coalesced quic packets in udp datagram (1-RTT packet can be only the last
   * because it doesn't have length field) */
  for (i = 0; i < QUIC_QUICLY_RCV_MAX_DGRAMS && packets_num < (QUIC_QUICLY_RCV_MAX_PACKETS - 4) &&
	      left_deq > SESSION_CONN_HDR_LEN;
       i++)
    {
      dgram_ctx = vec_elt_at_index (qqm->rx_dgrams[thread_index], i);
      rv = svm_fifo_peek (rx_fifo, fifo_offset, sizeof (ph), (u8 *) &ph);
      ASSERT (rv == sizeof (ph));
      ASSERT (ph.data_offset == 0);
      full_len = ph.data_length + SESSION_CONN_HDR_LEN;
      if (full_len > left_deq)
	{
	  QUIC_DBG (3, "Not enough data in fifo RX");
	  left_deq = 0;
	  break;
	}
      fifo_offset += SESSION_CONN_HDR_LEN;
      left_deq -= full_len;
      rv = quic_quicly_process_one_rx_dgram (ctx, quicly_ctx, rx_fifo, ph.data_length, fifo_offset,
					     &packets_num, dgram_ctx, udp_session_handle);
      fifo_offset += ph.data_length;
      if (rv)
	break;
    }
  quic_increment_counter (qqm->qm, QUIC_ERROR_RX_PACKETS, packets_num);

  for (i = 0; i < packets_num; i++)
    {
      packet_ctx = vec_elt_at_index (qqm->rx_packets[thread_index], i);
      ctx = quic_quicly_get_quic_ctx (opaque, thread_index);
      rv = quic_quicly_rx_state_funcs[ctx->opaque](ctx, packet_ctx, &src_addr.sa);
      if (PREDICT_FALSE (rv))
	{
	  /* connection closed? */
	  if (rv == QUIC_QUICLY_RX_ERROR_CRITICAL)
	    return -1;
	  /* otherwise stop processing and send response */
	  left_deq = 0;
	  goto send;
	}
    }

send:
  /* pool might grow */
  ctx = quic_quicly_get_quic_ctx (opaque, thread_index);
  if (PREDICT_TRUE (ctx->conn != NULL))
    {
      if (quicly_get_first_timeout (ctx->conn) <= wc->time_now)
	quic_quicly_send_packets (ctx);
      else
	quic_quicly_reschedule_ctx (ctx);
    }

  if (left_deq > SESSION_CONN_HDR_LEN)
    goto rx_start;

  svm_fifo_dequeue_drop (rx_fifo, fifo_offset);

  return 0;
}

static void
quic_quicly_transport_closed (quic_ctx_t *ctx)
{
  quic_quicly_connection_closed (ctx);
}

static int
quic_quicly_ctx_attribute (quic_ctx_t *ctx, u8 is_get, transport_endpt_attr_t *attr)
{
  if (!is_get)
    return -1;

  switch (attr->type)
    {
    case TRANSPORT_ENDPT_ATTR_TLS_PEER_CERT:
      {
	u32 requested = attr->tls_peer_cert.flags;

	attr->tls_peer_cert.cert = 0;
	attr->tls_peer_cert.chain = 0;
	attr->tls_peer_cert.flags = 0;

	if (!requested)
	  requested = TLS_CERT_F_LEAF;
	if (!(requested & TLS_CERT_F_LEAF))
	  return -1;

	if (quic_ctx_is_stream (ctx))
	  ctx = quic_quicly_get_quic_ctx (ctx->quic_connection_ctx_id, ctx->c_thread_index);
	X509 *peer_cert = quic_quicly_crypto_get_peer_cert (ctx);
	if (peer_cert)
	  {
	    attr->tls_peer_cert.cert = peer_cert;
	    attr->tls_peer_cert.flags = TLS_CERT_F_LEAF;
	    return 0;
	  }
	return -1;
      }
    case TRANSPORT_ENDPT_ATTR_TLS_PROFILE_INFO:
      {
	ptls_t *tls;
	ptls_cipher_suite_t *cipher;
	ptls_key_exchange_algorithm_t **kexs;

	if (quic_ctx_is_stream (ctx))
	  ctx = quic_quicly_get_quic_ctx (ctx->quic_connection_ctx_id, ctx->c_thread_index);
	if (!ctx->conn || !ptls_handshake_is_complete (quicly_get_tls (ctx->conn)))
	  return -1;

	tls = quicly_get_tls (ctx->conn);

	cipher = ptls_get_cipher (tls);
	if (cipher)
	  attr->tls_profile_info.cipher = format (0, "%s", cipher->name);
	else
	  attr->tls_profile_info.cipher = 0;

	/* QUIC always uses TLS 1.3 */
	attr->tls_profile_info.tls_version = ptls_get_protocol_version (tls);

	/* Picotls has no public API to retrieve the negotiated key exchange
	 * group after the handshake.  As a best-effort, return the first
	 * group from the configured key_exchanges list — which is what was
	 * selected when the profile restricts to a single group. */
	kexs = ptls_get_context (tls)->key_exchanges;
	if (kexs && kexs[0])
	  attr->tls_profile_info.key_agreement = format (0, "%s", kexs[0]->name);
	else
	  attr->tls_profile_info.key_agreement = 0;

	/* Picotls has no public API for the negotiated signature algorithm;
	 * leave NULL. Can potentially extend handshake to track this */
	attr->tls_profile_info.signature_algo = 0;

	return 0;
      }
    default:
      return -1;
    }
}

const static quic_engine_vft_t quic_quicly_engine_vft = {
  .engine_init = quic_quicly_engine_init,
  .crypto_context_acquire_listen = quic_quicly_crypto_context_acquire_listen,
  .crypto_context_acquire_accept = quic_quicly_crypto_context_acquire_accept,
  .crypto_context_acquire_connect = quic_quicly_crypto_context_acquire_connect,
  .crypto_context_release = quic_quicly_crypto_context_release,
  .crypto_context_get = quic_quicly_get_crypto_context,
  .crypto_context_list = quic_quicly_crypto_context_list,
  .connect = quic_quicly_connect,
  .connect_stream = quic_quicly_connect_stream,
  .connection_migrate = quic_quicly_connection_migrate,
  .connection_migrate_rpc = quic_quicly_connection_migrate_rpc,
  .connection_get_stats = quic_quicly_connection_get_stats,
  .udp_session_rx_packets = quic_quicly_udp_session_rx_packets,
  .ack_rx_data = quic_quicly_ack_rx_data,
  .stream_tx = quic_quicly_stream_tx,
  .send_packets = quic_quicly_send_packets,
  .format_connection_stats = quic_quicly_format_connection_stats,
  .format_stream_stats = quic_quicly_format_stream_stats,
  .stream_get_stream_id = quic_quicly_stream_get_stream_id,
  .proto_on_close = quic_quicly_on_app_closed,
  .proto_on_half_close = quic_quicly_on_app_closed_tx,
  .proto_on_reset = quic_quicly_on_app_reset,
  .transport_closed = quic_quicly_transport_closed,
  .ctx_attribute = quic_quicly_ctx_attribute,
  .conn_tx_timer_expired = quic_quicly_tx_timer_expired,
};

static clib_error_t *
quic_quicly_init (vlib_main_t *vm)
{
  clib_error_t *err = quic_plugin_exports_init (&quic_mvt);
  if (err)
    return err;

  quic_mvt.register_engine (&quic_quicly_engine_vft, QUIC_ENGINE_QUICLY);

  return 0;
}

VLIB_INIT_FUNCTION (quic_quicly_init) = {
  .runs_after = VLIB_INITS ("quic_init"),
};
