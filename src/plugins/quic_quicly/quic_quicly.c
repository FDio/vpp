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

/* quicly assume that the buffer provided by the caller of quicly_send is no greater than the burst
 * size of the pacer (10 packets) */
#define QUIC_QUICLY_SEND_PACKET_VEC_SIZE 10

#define QUIC_QUICLY_RCV_MAX_PACKETS 16

VLIB_PLUGIN_REGISTER () = {
  .version = VPP_BUILD_VER,
  .description = "Quicly QUIC Engine",
};

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
  clib_bihash_kv_24_8_t accepting_key = {};
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
  clib_bihash_add_del_16_8 (&qqm->connection_hash, &kv, 0 /* is_del */);
  const quicly_cid_t *rcid = quicly_get_remote_cid (conn);
  clib_memcpy_fast (&accepting_key.key, rcid->cid, rcid->len);
  clib_bihash_add_del_24_8 (&qqm->conn_accepting_hash, &accepting_key,
			    0 /* is del */);

  quic_disconnect_transport (ctx, qm->app_index);
  quicly_free (conn);
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
  int64_t next_timeout = quicly_get_first_timeout (ctx->conn);
  QUIC_ASSERT (!quic_ctx_is_stream (ctx));
  quic_update_timer (
    quic_wrk_ctx_get (quic_quicly_main.qm, ctx->c_thread_index), ctx,
    next_timeout);
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
  ASSERT (max_enqueue >= SESSION_CONN_HDR_LEN + len);

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
  ASSERT (ret > 0);

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
      if (PREDICT_FALSE (rv))
	{
	  clib_warning ("Event enqueue errored %d", rv);
	}
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
  quic_quicly_main_t *qqm = &quic_quicly_main;
  struct iovec *packets = qqm->tx_packets[ctx->c_thread_index];
  session_t *udp_session;
  quicly_conn_t *conn;
  size_t num_packets, i, max_packets;
  u32 n_sent = 0, buf_size;
  int err = 0;
  quicly_address_t quicly_rmt_ip, quicly_lcl_ip;
  u8 *buf = qqm->tx_bufs[ctx->c_thread_index];

  ASSERT (vec_len (buf) >= (QUIC_QUICLY_SEND_PACKET_VEC_SIZE * QUIC_MAX_PACKET_SIZE));
  ASSERT (vec_len (packets) >= QUIC_QUICLY_SEND_PACKET_VEC_SIZE);

  /* We have sctx, get qctx */
  if (quic_ctx_is_stream (ctx))
    {
      ctx = quic_quicly_get_quic_ctx (ctx->quic_connection_ctx_id,
				      ctx->c_thread_index);
    }

  QUIC_ASSERT (!quic_ctx_is_stream (ctx));

  udp_session = session_get_from_handle_if_valid (ctx->udp_session_handle);
  if (PREDICT_FALSE (!udp_session))
    goto quicly_error;

  if (PREDICT_FALSE (udp_session->session_state == SESSION_STATE_TRANSPORT_DELETED))
    return 0;

  conn = ctx->conn;
  ASSERT (conn);

  /* TODO : quicly can assert it can send min_packets up to 2 */
  max_packets = quic_quicly_sendable_packet_count (udp_session);
  if (max_packets < 2)
    {
      svm_fifo_add_want_deq_ntf (udp_session->tx_fifo,
				 SVM_FIFO_WANT_DEQ_NOTIF);
      return 0;
    }

  /* Shrink buf_size if we have less dgrams than QUIC_QUICLY_SEND_PACKET_VEC_SIZE */
  buf_size = clib_min (vec_len (buf), max_packets * QUIC_MAX_PACKET_SIZE);

  /* If under memory pressure and chunks cannot be allocated try reschedule */
  if (svm_fifo_provision_chunks (udp_session->tx_fifo, 0, 0, buf_size))
    {
      quic_worker_ctx_t *wc = quic_wrk_ctx_get (quic_quicly_main.qm, ctx->c_thread_index);
      quic_update_timer (wc, ctx, wc->time_now + 1);
      return 0;
    }

  num_packets = max_packets;
  if ((err = quicly_send (conn, &quicly_rmt_ip, &quicly_lcl_ip, packets,
			  &num_packets, buf, buf_size)))
    goto quicly_error;

  QUIC_DBG (3, "num_packets %u, packets %p, buf %p, buf_size %u", num_packets,
	    packets, buf, sizeof (buf));
  if (num_packets > 0)
    {
      quic_quicly_addr_to_ip46_addr (&quicly_rmt_ip, &ctx->rmt_ip,
				     &ctx->rmt_port);
      for (i = 0; i < num_packets; i++)
	{
	  if ((err = quic_quicly_send_datagram (udp_session, &packets[i],
						&ctx->rmt_ip, ctx->rmt_port)))
	    goto quicly_error;
	}
      n_sent += num_packets;
    }

  if (n_sent)
    quic_quicly_set_udp_tx_evt (udp_session);

  QUIC_DBG (3, "%u[TX] %u[RX]", svm_fifo_max_dequeue (udp_session->tx_fifo),
	    svm_fifo_max_dequeue (udp_session->rx_fifo));

  quic_quicly_reschedule_ctx (ctx);

  return n_sent;

quicly_error:

  if (err && err != QUICLY_ERROR_PACKET_IGNORED &&
      err != QUICLY_ERROR_FREE_CONNECTION)
    QUIC_ERR ("Quic error '%U'.", quic_quicly_format_err, err);
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

  QUIC_ASSERT (stream_data->app_tx_data_len >= delta);
  sctx->bytes_written += delta;
  rv = svm_fifo_dequeue_drop (f, delta);
  QUIC_ASSERT (rv == delta);

  if (svm_fifo_needs_deq_ntf (f, delta))
    session_dequeue_notify (stream_session);

  max_deq = svm_fifo_max_dequeue (f);
  if (max_deq)
    {
      if (max_deq > stream_data->app_tx_data_len - delta)
	{
	  rv = quicly_stream_sync_sendbuf (stream, 1);
	  QUIC_ASSERT (!rv);
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
  QUIC_ASSERT (off <= deq_max);
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
  QUIC_ASSERT (*len > 0);

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
  QUIC_ASSERT (quic_ctx_is_stream (sctx));
  if (!sctx->stream)
    return;
  stream = sctx->stream;
  stream_data = (quic_stream_data_t *) stream->data;

  f = stream_session->rx_fifo;
  max_deq = svm_fifo_max_dequeue (f);

  QUIC_ASSERT (stream_data->app_rx_data_len >= max_deq);
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

  if (PREDICT_FALSE (!len))
    return;

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
      /* send half-close notification to app */
      if (!(sctx->flags & QUIC_F_APP_CLOSED_TX) &&
	  quicly_recvstate_transfer_complete (&stream->recvstate))
	{
	  QUIC_DBG (2,
		    "stream half-close: rcv side closed, ctx_index %u, "
		    "thread_index %u",
		    sctx->c_c_index, sctx->c_thread_index);
	  session_transport_closing_notify (&sctx->connection);
	}
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
  quic_quicly_check_quic_session_connected (qctx);
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
  clib_bihash_kv_16_8_t kv;
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
  quic_quicly_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) new_ctx_index;
  QUIC_DBG (2, "Registering conn: key value 0x%llx, ctx_index %u, thread %u",
	    kv.value, new_ctx_index, thread_index);

  clib_bihash_add_del_16_8 (&quic_quicly_main.connection_hash, &kv,
			    1 /* is_add */);
  new_ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;

  quic_quicly_reschedule_ctx (new_ctx);

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

      quic_increment_counter (quic_quicly_main.qm,
			      QUIC_ERROR_CLOSED_CONNECTION, 1);
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
  clib_bihash_kv_24_8_t accepting_key = {};
  quic_ctx_t *ctx;
  u32 index, thread_id;
  quic_quicly_main_t *qqm = &quic_quicly_main;

  h = &qqm->connection_hash;
  quic_quicly_make_connection_key (&kv, &pctx->packet.cid.dest.plaintext);
  QUIC_DBG (3, "Searching conn with id 0x%llx", *(u64 *) kv.key);

  if (clib_bihash_search_16_8 (h, &kv, &kv))
    {
      if (QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]))
	{
	  QUIC_DBG (3, "Searching in accepting connections");
	  clib_memcpy_fast (&accepting_key.key, pctx->packet.cid.src.base,
			    pctx->packet.cid.src.len);
	  if (!clib_bihash_search_24_8 (&qqm->conn_accepting_hash,
					&accepting_key, &accepting_key))
	    {
	      index = accepting_key.value & UINT32_MAX;
	      thread_id = accepting_key.value >> 32;
	      goto conn_found;
	    }
	}
      QUIC_DBG (3, "connection not found");
      return QUIC_PACKET_TYPE_NONE;
    }

  index = kv.value & UINT32_MAX;
  thread_id = kv.value >> 32;
  /* Check if this connection belongs to this thread, otherwise
   * ask for it to be moved */
conn_found:
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
quic_quicly_conn_app_init_failed (quic_ctx_t *ctx, const char *reason_phrase)
{
  ctx->flags |= QUIC_F_NO_APP_SESSION;
  /* use 0 as error code because we can't pass quic transport error codes to
   * quicly */
  quicly_close (ctx->conn, QUICLY_ERROR_FROM_APPLICATION_ERROR_CODE (0),
		reason_phrase);
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
	    session_handle (quic_session), quic_session->session_index,
	    ctx->c_c_index, ctx->c_thread_index);
  ctx->c_s_index = quic_session->session_index;

  lctx = quic_quicly_get_quic_ctx (ctx->listener_ctx_id, 0);

  quic_session->connection_index = ctx->c_c_index;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, ctx->udp_is_ip4);
  quic_session->listener_handle = lctx->c_s_index;

  if (lctx->alpn_protos[0])
    {
      const char *proto =
	ptls_get_negotiated_protocol (quicly_get_tls (ctx->conn));
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

static void
quic_quicly_accept_connection (quic_quicly_rx_packet_ctx_t *pctx)
{
  quicly_context_t *quicly_ctx;
  clib_bihash_kv_16_8_t kv;
  clib_bihash_kv_24_8_t accepting_key = {};
  quicly_conn_t *conn;
  quic_ctx_t *ctx;
  int rv, quicly_state;
  quic_quicly_main_t *qqm = &quic_quicly_main;
  quic_main_t *qm = qqm->qm;

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
      /* Mark packet as drop and close UDP session */
      pctx->ptype = QUIC_PACKET_TYPE_DROP;
      if (ctx->conn_state < QUIC_CONN_STATE_CLOSED)
	{
	  ctx->conn_state = QUIC_CONN_STATE_CLOSED;
	  quic_disconnect_transport (ctx, qm->app_index);
	}
      return;
    }
  ASSERT (conn != NULL);

  ++qqm->next_cid[pctx->thread_index].master_id;
  /* Save ctx handle in quicly connection */
  quic_quicly_store_conn_ctx (conn, ctx);
  ctx->conn = conn;

  /* Register connection in connections map */
  quic_quicly_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) pctx->thread_index) << 32 | (u64) pctx->ctx_index;
  clib_bihash_add_del_16_8 (&qqm->connection_hash, &kv, 1 /* is_add */);
  clib_memcpy_fast (&accepting_key.key, pctx->packet.cid.src.base,
		    pctx->packet.cid.src.len);
  accepting_key.value = kv.value;
  clib_bihash_add_del_24_8 (&qqm->conn_accepting_hash, &accepting_key,
			    1 /* is add */);
  QUIC_DBG (
    2, "Accept connection: conn key value 0x%llx, ctx_index %u, thread %u",
    kv.value, pctx->ctx_index, pctx->thread_index);

  quicly_state = quicly_get_state (conn);
  /* if handshake failed (e.g. ALPN negotiation failed) quicly connection is in
   * closing state, in this case we don't need to create session and notify
   * app, connection will be closed when error response is sent */
  if (quicly_state >= QUICLY_STATE_CLOSING)
    {
      QUIC_DBG (2, "Handshake failed, closing: ctx_index %u, thread %u",
		ctx->c_c_index, ctx->c_thread_index);
      ctx->conn_state = QUIC_CONN_STATE_ACTIVE_CLOSING;
      return;
    }
  if (!quicly_connection_is_ready (conn))
    {
      QUIC_DBG (2, "Handshake not yet completed: ctx_index %u, thread %u",
		ctx->c_c_index, ctx->c_thread_index);
      ctx->conn_state = QUIC_CONN_STATE_HANDSHAKE;
      return;
    }

  quic_quicly_on_quic_session_accepted (ctx);
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
      QUIC_DBG (0, "invalid plen");
      return 1;
    }

  rv = quic_quicly_find_packet_ctx (pctx, thread_index);
  if (rv == QUIC_PACKET_TYPE_RECEIVE)
    {
      pctx->ptype = QUIC_PACKET_TYPE_RECEIVE;
      if (quic_quicly_crypto_engine_is_vpp ())
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

  if (!stream)
    s = format (s, " destroyed\n");
  else
    {
      stream_data = (quic_stream_data_t *) stream->data;
      s = format (s, " snd-wnd %lu rcv-wnd %lu app_rx_data_len %u",
		  stream->_send_aux.max_stream_data, stream->_recv_aux.window,
		  stream_data->app_rx_data_len);
      int is_client = quicly_is_client (stream->conn);
      if (quicly_stream_has_send_side (is_client, stream->stream_id) &&
	  !quicly_sendstate_is_open (&stream->sendstate))
	s = format (s, " snd-side-closed");
      if (quicly_stream_has_receive_side (is_client, stream->stream_id) &&
	  quicly_recvstate_transfer_complete (&stream->recvstate))
	s = format (s, " rcv-side-closed");
      s = format (s, "\n");
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
  QUIC_ASSERT (max_deq >= stream_data->app_tx_data_len);

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
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  u32 i;

  QUIC_DBG (2, "Quic engine init: quicly");
  qm->default_crypto_engine = CRYPTO_ENGINE_PICOTLS;
  qm->default_quic_cc = QUIC_CC_RENO;
  qm->max_packets_per_key = DEFAULT_MAX_PACKETS_PER_KEY;
  qqm->session_cache.super.cb = quic_quicly_encrypt_ticket_cb;
  qqm->qm = qm;

  vec_validate (qqm->next_cid, qm->num_threads - 1);
  vec_validate (qqm->rx_packets, qm->num_threads - 1);
  vec_validate (qqm->tx_packets, qm->num_threads - 1);
  vec_validate (qqm->tx_bufs, qm->num_threads - 1);
  next_cid = qqm->next_cid;
  clib_bihash_init_16_8 (&qqm->connection_hash,
			 "quic (quicly engine) connections", 1024, 4 << 20);
  clib_bihash_init_24_8 (&qqm->conn_accepting_hash,
			 "quic (quicly engine) accepting connections", 1024,
			 4 << 20);
  quic_quicly_crypto_init (qqm);

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
      vec_validate (qqm->rx_packets[i], QUIC_QUICLY_RCV_MAX_PACKETS);
      vec_validate (qqm->tx_packets[i], QUIC_QUICLY_SEND_PACKET_VEC_SIZE);
      vec_validate (qqm->tx_bufs[i], QUIC_QUICLY_SEND_PACKET_VEC_SIZE * QUIC_MAX_PACKET_SIZE);
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
      if (quic_quicly_notify_app_connected (ctx, SESSION_E_NONE))
	quic_quicly_conn_app_init_failed (ctx, "notify app connected failed");
    }
  else
    quic_quicly_on_quic_session_accepted (ctx);
}

static int
quic_quicly_udp_session_rx_packets (session_t *udp_session)
{
  /*  Read data from UDP rx_fifo and pass it to the quic_eng conn. */
  quic_quicly_main_t *qqm = &quic_quicly_main;
  quic_ctx_t *ctx = NULL, *prev_ctx = NULL;
  svm_fifo_t *f = udp_session->rx_fifo;
  u32 max_deq;
  u64 udp_session_handle = session_handle (udp_session);
  int rv = 0;
  clib_thread_index_t thread_index = vlib_get_thread_index ();
  u32 cur_deq, fifo_offset, max_packets, i;
  quic_quicly_rx_packet_ctx_t *packet_ctx;

  ASSERT (vec_len (qqm->rx_packets[thread_index]) >= QUIC_QUICLY_RCV_MAX_PACKETS);

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
  max_packets = QUIC_QUICLY_RCV_MAX_PACKETS;

  for (i = 0; i < max_packets; i++)
    {
      packet_ctx = vec_elt_at_index (qqm->rx_packets[thread_index], i);
      packet_ctx->thread_index = UINT32_MAX;
      packet_ctx->ctx_index = UINT32_MAX;
      packet_ctx->ptype = QUIC_PACKET_TYPE_DROP;

      cur_deq = max_deq - fifo_offset;

      if (cur_deq < SESSION_CONN_HDR_LEN)
	{
	  if (cur_deq == 0)
	    {
	      max_packets = i;
	      break;
	    }
	  fifo_offset = max_deq;
	  max_packets = i + 1;
	  QUIC_ERR ("Fifo %d < header size in RX", cur_deq);
	  break;
	}
      rv = quic_quicly_process_one_rx_packet (udp_session_handle, f, fifo_offset, packet_ctx);
      if (packet_ctx->ptype != QUIC_PACKET_TYPE_MIGRATE)
	{
	  fifo_offset += SESSION_CONN_HDR_LEN + packet_ctx->ph.data_length;
	}
      if (rv)
	{
	  max_packets = i + 1;
	  break;
	}
    }

  for (i = 0; i < max_packets; i++)
    {
      packet_ctx = vec_elt_at_index (qqm->rx_packets[thread_index], i);
      switch (packet_ctx->ptype)
	{
	case QUIC_PACKET_TYPE_RECEIVE:
	  ctx = quic_quicly_get_quic_ctx (packet_ctx->ctx_index, thread_index);
	  /* FIXME: Process return value and handle errors. */
	  quic_quicly_receive_a_packet (ctx, packet_ctx);
	  break;
	case QUIC_PACKET_TYPE_ACCEPT:
	  /* FIXME: Process return value and handle errors. */
	  quic_quicly_accept_connection (packet_ctx);
	  break;
	case QUIC_PACKET_TYPE_RESET:
	  /* FIXME: Process return value and handle errors. */
	  quic_quicly_reset_connection (udp_session_handle, packet_ctx);
	  break;
	}
    }
  ctx = prev_ctx = NULL;
  for (i = 0; i < max_packets; i++)
    {
      packet_ctx = vec_elt_at_index (qqm->rx_packets[thread_index], i);
      prev_ctx = ctx;
      switch (packet_ctx->ptype)
	{
	case QUIC_PACKET_TYPE_RECEIVE:
	  ctx = quic_quicly_get_quic_ctx (packet_ctx->ctx_index, packet_ctx->thread_index);
	  if (ctx->conn_state <= QUIC_CONN_STATE_HANDSHAKE)
	    {
	      quic_quicly_check_quic_session_connected (ctx);
	      ctx = quic_quicly_get_quic_ctx (packet_ctx->ctx_index, packet_ctx->thread_index);
	    }
	  break;
	case QUIC_PACKET_TYPE_ACCEPT:
	  ctx = quic_quicly_get_quic_ctx (packet_ctx->ctx_index, packet_ctx->thread_index);
	  break;
	default:
	  continue; /* this exits the for loop since other packet types are
		     * necessarily the last in the batch */
	}
      if (ctx != prev_ctx)
	{
	  if (!quic_ctx_is_stream (ctx))
	    quic_quicly_send_packets (ctx);
	  else
	    quic_quicly_reschedule_ctx (ctx);
	}
    }

  /* session alloc might have happened, so get session again */
  udp_session = session_get_from_handle (udp_session_handle);
  f = udp_session->rx_fifo;
  svm_fifo_dequeue_drop (f, fifo_offset);

  if (svm_fifo_max_dequeue (f))
    goto rx_start;

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
	if (quic_ctx_is_stream (ctx))
	  ctx = quic_quicly_get_quic_ctx (ctx->quic_connection_ctx_id, ctx->c_thread_index);
	X509 *peer_cert = quic_quicly_crypto_get_peer_cert (ctx);
	if (peer_cert)
	  {
	    attr->tls_peer_cert.cert = peer_cert;
	    return 0;
	  }
	return -1;
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
