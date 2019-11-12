/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
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

#include <sys/socket.h>

#include <vnet/session/application.h>
#include <vnet/session/transport.h>
#include <vnet/session/session.h>
#include <vlib/unix/plugin.h>
#include <vpp/app/version.h>

#include <vppinfra/lock.h>

#include <quic/quic.h>
#include <quic/certs.h>
#include <quic/error.h>
#include <quic/quic_crypto.h>

#include <quicly/defaults.h>

static char *quic_error_strings[] = {
#define quic_error(n,s) s,
#include <plugins/quic/quic_error.def>
#undef quic_error
};

static quic_main_t quic_main;
static void quic_update_timer (quic_ctx_t * ctx);
static int quic_check_quic_session_connected (quic_ctx_t * ctx);
static quicly_stream_open_t on_stream_open;
static quicly_closed_by_peer_t on_closed_by_peer;
static quicly_now_t quicly_vpp_now_cb;

static int
quic_store_quicly_ctx (application_t * app, u32 ckpair_index,
		       u8 crypto_engine)
{
  quic_main_t *qm = &quic_main;
  quicly_context_t *quicly_ctx;
  ptls_iovec_t key_vec;
  app_cert_key_pair_t *ckpair;
  u64 max_enq;
  if (app->quicly_ctx)
    return 0;

  if (crypto_engine == CRYPTO_ENGINE_NONE)
    {
      QUIC_DBG (2, "No crypto engine specified, using %d", crypto_engine);
      crypto_engine = qm->default_crypto_engine;
    }
  if (!clib_bitmap_get (qm->available_crypto_engines, crypto_engine))
    {
      QUIC_DBG (1, "Quic does not support crypto engine %d", crypto_engine);
      return VNET_API_ERROR_MISSING_CERT_KEY;
    }

  quicly_ctx_data_t *quicly_ctx_data =
    clib_mem_alloc (sizeof (quicly_ctx_data_t));
  clib_memset (quicly_ctx_data, 0, sizeof (*quicly_ctx_data));	/* picotls depends on this */
  quicly_ctx = &quicly_ctx_data->quicly_ctx;
  ptls_context_t *ptls_ctx = &quicly_ctx_data->ptls_ctx;
  ptls_ctx->random_bytes = ptls_openssl_random_bytes;
  ptls_ctx->get_time = &ptls_get_time;
  ptls_ctx->key_exchanges = ptls_openssl_key_exchanges;
  ptls_ctx->cipher_suites = qm->quic_ciphers[crypto_engine];
  ptls_ctx->certificates.list = NULL;
  ptls_ctx->certificates.count = 0;
  ptls_ctx->esni = NULL;
  ptls_ctx->on_client_hello = NULL;
  ptls_ctx->emit_certificate = NULL;
  ptls_ctx->sign_certificate = NULL;
  ptls_ctx->verify_certificate = NULL;
  ptls_ctx->ticket_lifetime = 86400;
  ptls_ctx->max_early_data_size = 8192;
  ptls_ctx->hkdf_label_prefix__obsolete = NULL;
  ptls_ctx->require_dhe_on_psk = 1;
  ptls_ctx->encrypt_ticket = &qm->session_cache.super;

  app->quicly_ctx = (u64 *) quicly_ctx;
  clib_memcpy (quicly_ctx, &quicly_spec_context, sizeof (quicly_context_t));

  quicly_ctx->max_packet_size = QUIC_MAX_PACKET_SIZE;
  quicly_ctx->tls = ptls_ctx;
  quicly_ctx->stream_open = &on_stream_open;
  quicly_ctx->closed_by_peer = &on_closed_by_peer;
  quicly_ctx->now = &quicly_vpp_now_cb;
  quicly_amend_ptls_context (quicly_ctx->tls);

  quicly_ctx->transport_params.max_data = QUIC_INT_MAX;
  quicly_ctx->transport_params.max_streams_uni = (uint64_t) 1 << 60;
  quicly_ctx->transport_params.max_streams_bidi = (uint64_t) 1 << 60;

  /* max_enq is FIFO_SIZE - 1 */
  max_enq = app->sm_properties.rx_fifo_size - 1;
  quicly_ctx->transport_params.max_stream_data.bidi_local = max_enq;
  max_enq = app->sm_properties.tx_fifo_size - 1;
  quicly_ctx->transport_params.max_stream_data.bidi_remote = max_enq;
  quicly_ctx->transport_params.max_stream_data.uni = QUIC_INT_MAX;

  quicly_ctx->tls->random_bytes (quicly_ctx_data->cid_key, 16);
  quicly_ctx_data->cid_key[16] = 0;
  key_vec = ptls_iovec_init (quicly_ctx_data->cid_key,
			     strlen (quicly_ctx_data->cid_key));
  quicly_ctx->cid_encryptor =
    quicly_new_default_cid_encryptor (&ptls_openssl_bfecb,
				      &ptls_openssl_aes128ecb,
				      &ptls_openssl_sha256, key_vec);

  ckpair = app_cert_key_pair_get_if_valid (ckpair_index);
  if (!ckpair || !ckpair->key || !ckpair->cert)
    {
      QUIC_DBG (1, "Wrong ckpair id %d\n", ckpair_index);
      goto error;
    }
  if (load_bio_private_key (quicly_ctx->tls, (char *) ckpair->key))
    {
      QUIC_DBG (1, "failed to read private key from app configuration\n");
      goto error;
    }
  if (load_bio_certificate_chain (quicly_ctx->tls, (char *) ckpair->cert))
    {
      QUIC_DBG (1, "failed to load certificate\n");
      goto error;
    }
  return 0;

error:
  clib_mem_free (quicly_ctx_data);
  return VNET_API_ERROR_MISSING_CERT_KEY;
}


/*  Helper functions */

static u32
quic_ctx_alloc (u32 thread_index)
{
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;

  pool_get (qm->ctx_pool[thread_index], ctx);

  clib_memset (ctx, 0, sizeof (quic_ctx_t));
  ctx->c_thread_index = thread_index;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  QUIC_DBG (3, "Allocated quic_ctx %u on thread %u",
	    ctx - qm->ctx_pool[thread_index], thread_index);
  return ctx - qm->ctx_pool[thread_index];
}

static void
quic_ctx_free (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "Free ctx %u %x", ctx->c_thread_index, ctx->c_c_index);
  u32 thread_index = ctx->c_thread_index;
  ASSERT (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID);
  if (CLIB_DEBUG)
    clib_memset (ctx, 0xfb, sizeof (*ctx));
  pool_put (quic_main.ctx_pool[thread_index], ctx);
}

static quic_ctx_t *
quic_ctx_get (u32 ctx_index, u32 thread_index)
{
  return pool_elt_at_index (quic_main.ctx_pool[thread_index], ctx_index);
}

static quic_ctx_t *
quic_ctx_get_if_valid (u32 ctx_index, u32 thread_index)
{
  if (pool_is_free_index (quic_main.ctx_pool[thread_index], ctx_index))
    return 0;
  return pool_elt_at_index (quic_main.ctx_pool[thread_index], ctx_index);
}

static quic_ctx_t *
quic_get_conn_ctx (quicly_conn_t * conn)
{
  u64 conn_data;
  conn_data = (u64) * quicly_get_data (conn);
  return quic_ctx_get (conn_data & UINT32_MAX, conn_data >> 32);
}

static void
quic_store_conn_ctx (quicly_conn_t * conn, quic_ctx_t * ctx)
{
  *quicly_get_data (conn) =
    (void *) (((u64) ctx->c_thread_index) << 32 | (u64) ctx->c_c_index);
}

static inline int
quic_ctx_is_stream (quic_ctx_t * ctx)
{
  return (ctx->flags & QUIC_F_IS_STREAM);
}

static inline int
quic_ctx_is_listener (quic_ctx_t * ctx)
{
  return (ctx->flags & QUIC_F_IS_LISTENER);
}

static session_t *
get_stream_session_from_stream (quicly_stream_t * stream)
{
  quic_ctx_t *ctx;
  quic_stream_data_t *stream_data;

  stream_data = (quic_stream_data_t *) stream->data;
  ctx = quic_ctx_get (stream_data->ctx_id, stream_data->thread_index);
  return session_get (ctx->c_s_index, stream_data->thread_index);
}

static inline void
quic_make_connection_key (clib_bihash_kv_16_8_t * kv,
			  const quicly_cid_plaintext_t * id)
{
  kv->key[0] = ((u64) id->master_id) << 32 | (u64) id->thread_id;
  kv->key[1] = id->node_id;
}

static int
quic_sendable_packet_count (session_t * udp_session)
{
  u32 max_enqueue;
  u32 packet_size = QUIC_MAX_PACKET_SIZE + SESSION_CONN_HDR_LEN;
  max_enqueue = svm_fifo_max_enqueue (udp_session->tx_fifo);
  return clib_min (max_enqueue / packet_size, QUIC_SEND_PACKET_VEC_SIZE);
}

static quicly_context_t *
quic_get_quicly_ctx_from_ctx (quic_ctx_t * ctx)
{
  return ctx->quicly_ctx;
}

static quicly_context_t *
quic_get_quicly_ctx_from_udp (u64 udp_session_handle)
{
  session_t *udp_session = session_get_from_handle (udp_session_handle);
  quic_ctx_t *ctx =
    quic_ctx_get (udp_session->opaque, udp_session->thread_index);
  return ctx->quicly_ctx;
}

static inline void
quic_set_udp_tx_evt (session_t * udp_session)
{
  int rv = 0;
  if (svm_fifo_set_event (udp_session->tx_fifo))
    rv = session_send_io_evt_to_thread (udp_session->tx_fifo,
					SESSION_IO_EVT_TX);
  if (PREDICT_FALSE (rv))
    clib_warning ("Event enqueue errored %d", rv);
}

static inline void
quic_stop_ctx_timer (quic_ctx_t * ctx)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  if (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID)
    return;
  tw = &quic_main.wrk_ctx[ctx->c_thread_index].timer_wheel;
  tw_timer_stop_1t_3w_1024sl_ov (tw, ctx->timer_handle);
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  QUIC_DBG (4, "Stopping timer for ctx %u", ctx->c_c_index);
}

/* QUIC protocol actions */

static void
quic_ack_rx_data (session_t * stream_session)
{
  u32 max_deq;
  quic_ctx_t *sctx;
  svm_fifo_t *f;
  quicly_stream_t *stream;
  quic_stream_data_t *stream_data;

  sctx = quic_ctx_get (stream_session->connection_index,
		       stream_session->thread_index);
  ASSERT (quic_ctx_is_stream (sctx));
  stream = sctx->stream;
  stream_data = (quic_stream_data_t *) stream->data;

  f = stream_session->rx_fifo;
  max_deq = svm_fifo_max_dequeue (f);

  ASSERT (stream_data->app_rx_data_len >= max_deq);
  quicly_stream_sync_recvbuf (stream, stream_data->app_rx_data_len - max_deq);
  QUIC_DBG (3, "Acking %u bytes", stream_data->app_rx_data_len - max_deq);
  stream_data->app_rx_data_len = max_deq;
}

static void
quic_disconnect_transport (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "Disconnecting transport 0x%lx", ctx->udp_session_handle);
  vnet_disconnect_args_t a = {
    .handle = ctx->udp_session_handle,
    .app_index = quic_main.app_index,
  };

  if (vnet_disconnect_session (&a))
    clib_warning ("UDP session 0x%lx disconnect errored",
		  ctx->udp_session_handle);
}

static void
quic_connection_delete (quic_ctx_t * ctx)
{
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;

  QUIC_DBG (2, "Deleting connection %u", ctx->c_c_index);

  ASSERT (!quic_ctx_is_stream (ctx));
  quic_stop_ctx_timer (ctx);

  /*  Delete the connection from the connection map */
  conn = ctx->conn;
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  QUIC_DBG (2, "Deleting conn with id %lu %lu from map", kv.key[0],
	    kv.key[1]);
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 0 /* is_add */ );

  quic_disconnect_transport (ctx);

  if (ctx->conn)
    quicly_free (ctx->conn);
  ctx->conn = NULL;
  session_transport_delete_notify (&ctx->connection);
}

void
quic_increment_counter (u8 evt, u8 val)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_increment_counter (vm, quic_input_node.index, evt, val);
}

/**
 * Called when quicly return an error
 * This function interacts tightly with quic_proto_on_close
 */
static void
quic_connection_closed (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "QUIC connection %u/%u closed", ctx->c_thread_index,
	    ctx->c_c_index);

  /* TODO if connection is not established, just delete the session? */
  /* Actually should send connect or accept error */

  switch (ctx->conn_state)
    {
    case QUIC_CONN_STATE_READY:
      /* Error on an opened connection (timeout...)
         This puts the session in closing state, we should receive a notification
         when the app has closed its session */
      session_transport_reset_notify (&ctx->connection);
      /* This ensures we delete the connection when the app confirms the close */
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED;
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING:
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED;
      /* quic_proto_on_close will eventually be called when the app confirms the close
         , we delete the connection at that point */
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING_APP_CLOSED:
      /* App already confirmed close, we can delete the connection */
      quic_connection_delete (ctx);
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED:
      QUIC_DBG (0, "BUG");
      break;
    case QUIC_CONN_STATE_ACTIVE_CLOSING:
      quic_connection_delete (ctx);
      break;
    default:
      QUIC_DBG (0, "BUG %d", ctx->conn_state);
      break;
    }
}

static int
quic_send_datagram (session_t * udp_session, quicly_datagram_t * packet)
{
  u32 max_enqueue;
  session_dgram_hdr_t hdr;
  u32 len, ret;
  svm_fifo_t *f;
  transport_connection_t *tc;

  len = packet->data.len;
  f = udp_session->tx_fifo;
  tc = session_get_transport (udp_session);
  max_enqueue = svm_fifo_max_enqueue (f);
  if (max_enqueue < SESSION_CONN_HDR_LEN + len)
    {
      QUIC_DBG (1, "Too much data to send, max_enqueue %u, len %u",
		max_enqueue, len + SESSION_CONN_HDR_LEN);
      return QUIC_ERROR_FULL_FIFO;
    }

  /*  Build packet header for fifo */
  hdr.data_length = len;
  hdr.data_offset = 0;
  hdr.is_ip4 = tc->is_ip4;
  clib_memcpy (&hdr.lcl_ip, &tc->lcl_ip, sizeof (ip46_address_t));
  hdr.lcl_port = tc->lcl_port;

  /*  Read dest address from quicly-provided sockaddr */
  if (hdr.is_ip4)
    {
      ASSERT (packet->dest.sa.sa_family == AF_INET);
      struct sockaddr_in *sa4 = (struct sockaddr_in *) &packet->dest.sa;
      hdr.rmt_port = sa4->sin_port;
      hdr.rmt_ip.ip4.as_u32 = sa4->sin_addr.s_addr;
    }
  else
    {
      ASSERT (packet->dest.sa.sa_family == AF_INET6);
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &packet->dest.sa;
      hdr.rmt_port = sa6->sin6_port;
      clib_memcpy (&hdr.rmt_ip.ip6, &sa6->sin6_addr, 16);
    }

  ret = svm_fifo_enqueue (f, sizeof (hdr), (u8 *) & hdr);
  if (ret != sizeof (hdr))
    {
      QUIC_DBG (1, "Not enough space to enqueue header");
      return QUIC_ERROR_FULL_FIFO;
    }
  ret = svm_fifo_enqueue (f, len, packet->data.base);
  if (ret != len)
    {
      QUIC_DBG (1, "Not enough space to enqueue payload");
      return QUIC_ERROR_FULL_FIFO;
    }

  quic_increment_counter (QUIC_ERROR_TX_PACKETS, 1);

  return 0;
}

static int
quic_send_packets (quic_ctx_t * ctx)
{
  quicly_datagram_t *packets[QUIC_SEND_PACKET_VEC_SIZE];
  session_t *udp_session;
  quicly_conn_t *conn;
  size_t num_packets, i, max_packets;
  quicly_packet_allocator_t *pa;
  quicly_context_t *quicly_context;
  int err = 0;

  /* We have sctx, get qctx */
  if (quic_ctx_is_stream (ctx))
    ctx = quic_ctx_get (ctx->quic_connection_ctx_id, ctx->c_thread_index);

  ASSERT (!quic_ctx_is_stream (ctx));

  udp_session = session_get_from_handle_if_valid (ctx->udp_session_handle);
  if (!udp_session)
    goto quicly_error;

  conn = ctx->conn;

  if (!conn)
    return 0;

  /* TODO : quicly can assert it can send min_packets up to 2 */
  if (quic_sendable_packet_count (udp_session) < 2)
    goto stop_sending;

  quicly_context = quic_get_quicly_ctx_from_ctx (ctx);
  if (!quicly_context)
    {
      clib_warning ("Tried to send packets on non existing app worker %u",
		    ctx->parent_app_wrk_id);
      quic_connection_delete (ctx);
      return 1;
    }
  pa = quicly_context->packet_allocator;
  do
    {
      max_packets = quic_sendable_packet_count (udp_session);
      if (max_packets < 2)
	break;
      num_packets = max_packets;
      if ((err = quicly_send (conn, packets, &num_packets)))
	goto quicly_error;

      for (i = 0; i != num_packets; ++i)
	{
	  if ((err = quic_send_datagram (udp_session, packets[i])))
	    goto quicly_error;

	  pa->free_packet (pa, packets[i]);
	}
    }
  while (num_packets > 0 && num_packets == max_packets);

stop_sending:
  quic_set_udp_tx_evt (udp_session);

  QUIC_DBG (3, "%u[TX] %u[RX]", svm_fifo_max_dequeue (udp_session->tx_fifo),
	    svm_fifo_max_dequeue (udp_session->rx_fifo));
  quic_update_timer (ctx);
  return 0;

quicly_error:
  if (err && err != QUICLY_ERROR_PACKET_IGNORED
      && err != QUICLY_ERROR_FREE_CONNECTION)
    clib_warning ("Quic error '%U'.", quic_format_err, err);
  quic_connection_closed (ctx);
  return 1;
}

/* Quicly callbacks */

static void
quic_on_stream_destroy (quicly_stream_t * stream, int err)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx = quic_ctx_get (stream_data->ctx_id,
				   stream_data->thread_index);
  session_t *stream_session = session_get (sctx->c_s_index,
					   sctx->c_thread_index);
  QUIC_DBG (2, "DESTROYED_STREAM: session 0x%lx (%U)",
	    session_handle (stream_session), quic_format_err, err);

  stream_session->session_state = SESSION_STATE_CLOSED;
  session_transport_delete_notify (&sctx->connection);

  quic_ctx_free (sctx);
  clib_mem_free (stream->data);
}

static int
quic_on_stop_sending (quicly_stream_t * stream, int err)
{
#if QUIC_DEBUG >= 2
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx = quic_ctx_get (stream_data->ctx_id,
				   stream_data->thread_index);
  session_t *stream_session = session_get (sctx->c_s_index,
					   sctx->c_thread_index);
  clib_warning ("(NOT IMPLEMENTD) STOP_SENDING: session 0x%lx (%U)",
		session_handle (stream_session), quic_format_err, err);
#endif
  /* TODO : handle STOP_SENDING */
  return 0;
}

static int
quic_on_receive_reset (quicly_stream_t * stream, int err)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  quic_ctx_t *sctx = quic_ctx_get (stream_data->ctx_id,
				   stream_data->thread_index);
#if QUIC_DEBUG >= 2
  session_t *stream_session = session_get (sctx->c_s_index,
					   sctx->c_thread_index);
  clib_warning ("RESET_STREAM: session 0x%lx (%U)",
		session_handle (stream_session), quic_format_err, err);
#endif
  session_transport_closing_notify (&sctx->connection);
  return 0;
}

static int
quic_on_receive (quicly_stream_t * stream, size_t off, const void *src,
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
  sctx = quic_ctx_get (stream_data->ctx_id, stream_data->thread_index);
  stream_session = session_get (sctx->c_s_index, stream_data->thread_index);
  f = stream_session->rx_fifo;

  max_enq = svm_fifo_max_enqueue_prod (f);
  QUIC_DBG (3, "Enqueuing %u at off %u in %u space", len, off, max_enq);
  if (off - stream_data->app_rx_data_len + len > max_enq)
    {
      QUIC_ERR ("Session [idx %u, app_wrk %u, thread %u, rx-fifo 0x%llx]: "
		"RX fifo is full (max_enq %u, len %u, "
		"app_rx_data_len %u, off %u, ToBeNQ %u)",
		stream_session->session_index,
		stream_session->app_wrk_index,
		stream_session->thread_index, f,
		max_enq, len, stream_data->app_rx_data_len, off,
		off - stream_data->app_rx_data_len + len);
      return 1;
    }
  if (off == stream_data->app_rx_data_len)
    {
      /* Streams live on the same thread so (f, stream_data) should stay consistent */
      rlen = svm_fifo_enqueue (f, len, (u8 *) src);
      QUIC_DBG (3, "Session [idx %u, app_wrk %u, ti %u, rx-fifo 0x%llx]: "
		"Enqueuing %u (rlen %u) at off %u in %u space, ",
		stream_session->session_index,
		stream_session->app_wrk_index,
		stream_session->thread_index, f, len, rlen, off, max_enq);
      stream_data->app_rx_data_len += rlen;
      ASSERT (rlen >= len);
      app_wrk = app_worker_get_if_valid (stream_session->app_wrk_index);
      if (PREDICT_TRUE (app_wrk != 0))
	app_worker_lock_and_send_event (app_wrk, stream_session,
					SESSION_IO_EVT_RX);
      quic_ack_rx_data (stream_session);
    }
  else
    {
      rlen = svm_fifo_enqueue_with_offset (f,
					   off - stream_data->app_rx_data_len,
					   len, (u8 *) src);
      ASSERT (rlen == 0);
    }
  return 0;
}

void
quic_fifo_egress_shift (quicly_stream_t * stream, size_t delta)
{
  session_t *stream_session;
  svm_fifo_t *f;
  int rv;

  stream_session = get_stream_session_from_stream (stream);
  f = stream_session->tx_fifo;

  rv = svm_fifo_dequeue_drop (f, delta);
  ASSERT (rv == delta);
  quicly_stream_sync_sendbuf (stream, 0);
}

int
quic_fifo_egress_emit (quicly_stream_t * stream, size_t off, void *dst,
		       size_t * len, int *wrote_all)
{
  session_t *stream_session;
  svm_fifo_t *f;
  u32 deq_max, first_deq, max_rd_chunk, rem_offset;

  stream_session = get_stream_session_from_stream (stream);
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
      QUIC_DBG (3, "Wrote ALL, %u", *len);
    }

  /* TODO, use something like : return svm_fifo_peek (f, off, *len, dst); */
  max_rd_chunk = svm_fifo_max_read_chunk (f);

  first_deq = 0;
  if (off < max_rd_chunk)
    {
      first_deq = clib_min (*len, max_rd_chunk - off);
      clib_memcpy_fast (dst, svm_fifo_head (f) + off, first_deq);
    }

  if (max_rd_chunk < off + *len)
    {
      rem_offset = max_rd_chunk < off ? off - max_rd_chunk : 0;
      clib_memcpy_fast (dst + first_deq, f->head_chunk->data + rem_offset,
			*len - first_deq);
    }

  return 0;
}

static const quicly_stream_callbacks_t quic_stream_callbacks = {
  .on_destroy = quic_on_stream_destroy,
  .on_send_shift = quic_fifo_egress_shift,
  .on_send_emit = quic_fifo_egress_emit,
  .on_send_stop = quic_on_stop_sending,
  .on_receive = quic_on_receive,
  .on_receive_reset = quic_on_receive_reset
};

static int
quic_on_stream_open (quicly_stream_open_t * self, quicly_stream_t * stream)
{
  session_t *stream_session, *quic_session;
  quic_stream_data_t *stream_data;
  app_worker_t *app_wrk;
  quic_ctx_t *qctx, *sctx;
  u32 sctx_id;
  int rv;

  QUIC_DBG (2, "on_stream_open called");
  stream->data = clib_mem_alloc (sizeof (quic_stream_data_t));
  stream->callbacks = &quic_stream_callbacks;
  /* Notify accept on parent qsession, but only if this is not a locally
   * initiated stream */
  if (quicly_stream_is_self_initiated (stream))
    return 0;

  sctx_id = quic_ctx_alloc (vlib_get_thread_index ());
  qctx = quic_get_conn_ctx (stream->conn);

  /* Might need to signal that the connection is ready if the first thing the
   * server does is open a stream */
  quic_check_quic_session_connected (qctx);
  /* ctx might be invalidated */
  qctx = quic_get_conn_ctx (stream->conn);

  stream_session = session_alloc (qctx->c_thread_index);
  QUIC_DBG (2, "ACCEPTED stream_session 0x%lx ctx %u",
	    session_handle (stream_session), sctx_id);
  sctx = quic_ctx_get (sctx_id, qctx->c_thread_index);
  sctx->parent_app_wrk_id = qctx->parent_app_wrk_id;
  sctx->parent_app_id = qctx->parent_app_id;
  sctx->quic_connection_ctx_id = qctx->c_c_index;
  sctx->c_c_index = sctx_id;
  sctx->c_s_index = stream_session->session_index;
  sctx->stream = stream;
  sctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  sctx->flags |= QUIC_F_IS_STREAM;

  stream_data = (quic_stream_data_t *) stream->data;
  stream_data->ctx_id = sctx_id;
  stream_data->thread_index = sctx->c_thread_index;
  stream_data->app_rx_data_len = 0;

  sctx->c_s_index = stream_session->session_index;
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
      QUIC_DBG (1, "failed to allocate fifos");
      session_free (stream_session);
      quicly_reset_stream (stream, QUIC_APP_ALLOCATION_ERROR);
      return 0;			/* Frame is still valid */
    }
  svm_fifo_add_want_deq_ntf (stream_session->rx_fifo,
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL |
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);

  if ((rv = app_worker_accept_notify (app_wrk, stream_session)))
    {
      QUIC_DBG (1, "failed to notify accept worker app");
      session_free_w_fifos (stream_session);
      quicly_reset_stream (stream, QUIC_APP_ACCEPT_NOTIFY_ERROR);
      return 0;			/* Frame is still valid */
    }

  return 0;
}

static void
quic_on_closed_by_peer (quicly_closed_by_peer_t * self, quicly_conn_t * conn,
			int code, uint64_t frame_type,
			const char *reason, size_t reason_len)
{
  quic_ctx_t *ctx = quic_get_conn_ctx (conn);
#if QUIC_DEBUG >= 2
  session_t *quic_session = session_get (ctx->c_s_index, ctx->c_thread_index);
  clib_warning ("Session 0x%lx closed by peer (%U) %.*s ",
		session_handle (quic_session), quic_format_err, code,
		reason_len, reason);
#endif
  ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING;
  session_transport_closing_notify (&ctx->connection);
}

/* Timer handling */

static int64_t
quic_get_thread_time (u8 thread_index)
{
  return quic_main.wrk_ctx[thread_index].time_now;
}

static int64_t
quic_get_time (quicly_now_t * self)
{
  u8 thread_index = vlib_get_thread_index ();
  return quic_get_thread_time (thread_index);
}

static u32
quic_set_time_now (u32 thread_index)
{
  vlib_main_t *vlib_main = vlib_get_main ();
  f64 time = vlib_time_now (vlib_main);
  quic_main.wrk_ctx[thread_index].time_now = (int64_t) (time * 1000.f);
  return quic_main.wrk_ctx[thread_index].time_now;
}

/* Transport proto callback */
static void
quic_update_time (f64 now, u8 thread_index)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;

  tw = &quic_main.wrk_ctx[thread_index].timer_wheel;
  quic_set_time_now (thread_index);
  tw_timer_expire_timers_1t_3w_1024sl_ov (tw, now);
}

static void
quic_timer_expired (u32 conn_index)
{
  quic_ctx_t *ctx;
  QUIC_DBG (4, "Timer expired for conn %u at %ld", conn_index,
	    quic_get_time (NULL));
  ctx = quic_ctx_get (conn_index, vlib_get_thread_index ());
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  quic_send_packets (ctx);
}

static void
quic_update_timer (quic_ctx_t * ctx)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  int64_t next_timeout, next_interval;
  session_t *quic_session;

  /*  This timeout is in ms which is the unit of our timer */
  next_timeout = quicly_get_first_timeout (ctx->conn);
  next_interval = next_timeout - quic_get_time (NULL);

  if (next_timeout == 0 || next_interval <= 0)
    {
      if (ctx->c_s_index == QUIC_SESSION_INVALID)
	{
	  next_interval = 1;
	}
      else
	{
	  quic_session = session_get (ctx->c_s_index, ctx->c_thread_index);
	  if (svm_fifo_set_event (quic_session->tx_fifo))
	    session_send_io_evt_to_thread_custom (quic_session,
						  quic_session->thread_index,
						  SESSION_IO_EVT_BUILTIN_TX);
	  return;
	}
    }

  tw = &quic_main.wrk_ctx[vlib_get_thread_index ()].timer_wheel;

  QUIC_DBG (4, "Timer set to %ld (int %ld) for ctx %u", next_timeout,
	    next_interval, ctx->c_c_index);

  if (ctx->timer_handle == QUIC_TIMER_HANDLE_INVALID)
    {
      if (next_timeout == INT64_MAX)
	{
	  QUIC_DBG (4, "timer for ctx %u already stopped", ctx->c_c_index);
	  return;
	}
      ctx->timer_handle = tw_timer_start_1t_3w_1024sl_ov (tw, ctx->c_c_index,
							  0, next_interval);
    }
  else
    {
      if (next_timeout == INT64_MAX)
	{
	  quic_stop_ctx_timer (ctx);
	}
      else
	tw_timer_update_1t_3w_1024sl_ov (tw, ctx->timer_handle,
					 next_interval);
    }
  return;
}

static void
quic_expired_timers_dispatch (u32 * expired_timers)
{
  int i;

  for (i = 0; i < vec_len (expired_timers); i++)
    {
      quic_timer_expired (expired_timers[i]);
    }
}

/* Transport proto functions */

static int
quic_connect_stream (session_t * quic_session, u32 opaque)
{
  uint64_t quic_session_handle;
  session_t *stream_session;
  quic_stream_data_t *stream_data;
  quicly_stream_t *stream;
  quicly_conn_t *conn;
  app_worker_t *app_wrk;
  quic_ctx_t *qctx, *sctx;
  u32 sctx_index;
  int rv;

  /*  Find base session to which the user want to attach a stream */
  quic_session_handle = session_handle (quic_session);
  QUIC_DBG (2, "Opening new stream (qsession %u)", quic_session_handle);

  if (session_type_transport_proto (quic_session->session_type) !=
      TRANSPORT_PROTO_QUIC)
    {
      QUIC_DBG (1, "received incompatible session");
      return -1;
    }

  app_wrk = app_worker_get_if_valid (quic_session->app_wrk_index);
  if (!app_wrk)
    {
      QUIC_DBG (1, "Invalid app worker :(");
      return -1;
    }

  sctx_index = quic_ctx_alloc (quic_session->thread_index);	/*  Allocate before we get pointers */
  sctx = quic_ctx_get (sctx_index, quic_session->thread_index);
  qctx = quic_ctx_get (quic_session->connection_index,
		       quic_session->thread_index);
  if (quic_ctx_is_stream (qctx))
    {
      QUIC_DBG (1, "session is a stream");
      quic_ctx_free (sctx);
      return -1;
    }

  sctx->parent_app_wrk_id = qctx->parent_app_wrk_id;
  sctx->parent_app_id = qctx->parent_app_id;
  sctx->quic_connection_ctx_id = qctx->c_c_index;
  sctx->c_c_index = sctx_index;
  sctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  sctx->flags |= QUIC_F_IS_STREAM;

  conn = qctx->conn;

  if (!conn || !quicly_connection_is_ready (conn))
    return -1;

  if ((rv = quicly_open_stream (conn, &stream, 0 /* uni */ )))
    {
      QUIC_DBG (2, "Stream open failed with %d", rv);
      return -1;
    }
  sctx->stream = stream;

  QUIC_DBG (2, "Opened stream %d, creating session", stream->stream_id);

  stream_session = session_alloc (qctx->c_thread_index);
  QUIC_DBG (2, "Allocated stream_session 0x%lx ctx %u",
	    session_handle (stream_session), sctx_index);
  stream_session->app_wrk_index = app_wrk->wrk_index;
  stream_session->connection_index = sctx_index;
  stream_session->listener_handle = quic_session_handle;
  stream_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, qctx->udp_is_ip4);

  sctx->c_s_index = stream_session->session_index;

  if (app_worker_init_connected (app_wrk, stream_session))
    {
      QUIC_DBG (1, "failed to app_worker_init_connected");
      quicly_reset_stream (stream, QUIC_APP_ALLOCATION_ERROR);
      session_free_w_fifos (stream_session);
      quic_ctx_free (sctx);
      return app_worker_connect_notify (app_wrk, NULL, opaque);
    }

  svm_fifo_add_want_deq_ntf (stream_session->rx_fifo,
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_FULL |
			     SVM_FIFO_WANT_DEQ_NOTIF_IF_EMPTY);

  stream_session->session_state = SESSION_STATE_READY;
  if (app_worker_connect_notify (app_wrk, stream_session, opaque))
    {
      QUIC_DBG (1, "failed to notify app");
      quicly_reset_stream (stream, QUIC_APP_CONNECT_NOTIFY_ERROR);
      session_free_w_fifos (stream_session);
      quic_ctx_free (sctx);
      return -1;
    }
  stream_data = (quic_stream_data_t *) stream->data;
  stream_data->ctx_id = sctx->c_c_index;
  stream_data->thread_index = sctx->c_thread_index;
  stream_data->app_rx_data_len = 0;
  return 0;
}

static int
quic_connect_connection (session_endpoint_cfg_t * sep)
{
  vnet_connect_args_t _cargs, *cargs = &_cargs;
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;
  app_worker_t *app_wrk;
  application_t *app;
  u32 ctx_index;
  u32 thread_index = vlib_get_thread_index ();
  int error;

  clib_memset (cargs, 0, sizeof (*cargs));
  ctx_index = quic_ctx_alloc (thread_index);
  ctx = quic_ctx_get (ctx_index, thread_index);
  ctx->parent_app_wrk_id = sep->app_wrk_index;
  ctx->c_s_index = QUIC_SESSION_INVALID;
  ctx->c_c_index = ctx_index;
  ctx->udp_is_ip4 = sep->is_ip4;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  ctx->conn_state = QUIC_CONN_STATE_HANDSHAKE;
  ctx->client_opaque = sep->opaque;
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;
  if (sep->hostname)
    ctx->srv_hostname = format (0, "%v", sep->hostname);
  else
    /*  needed by quic for crypto + determining client / server */
    ctx->srv_hostname = format (0, "%U", format_ip46_address,
				&sep->ip, sep->is_ip4);
  vec_terminate_c_string (ctx->srv_hostname);

  clib_memcpy (&cargs->sep, sep, sizeof (session_endpoint_cfg_t));
  cargs->sep.transport_proto = TRANSPORT_PROTO_UDPC;
  cargs->app_index = qm->app_index;
  cargs->api_context = ctx_index;

  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  ctx->parent_app_id = app_wrk->app_index;
  cargs->sep_ext.ns_index = app->ns_index;

  if ((error =
       quic_store_quicly_ctx (app, sep->ckpair_index, sep->crypto_engine)))
    return error;
  /* Also store it in ctx for convenience
   * Waiting for crypto_ctx logic */
  ctx->quicly_ctx = (quicly_context_t *) app->quicly_ctx;

  if ((error = vnet_connect (cargs)))
    return error;

  return 0;
}

static int
quic_connect (transport_endpoint_cfg_t * tep)
{
  QUIC_DBG (2, "Called quic_connect");
  session_endpoint_cfg_t *sep = (session_endpoint_cfg_t *) tep;
  session_t *quic_session;
  sep = (session_endpoint_cfg_t *) tep;

  quic_session = session_get_from_handle_if_valid (sep->parent_handle);
  if (quic_session)
    return quic_connect_stream (quic_session, sep->opaque);
  else
    return quic_connect_connection (sep);
}

static void
quic_proto_on_close (u32 ctx_index, u32 thread_index)
{
  quic_ctx_t *ctx = quic_ctx_get_if_valid (ctx_index, thread_index);
  if (!ctx)
    return;
#if QUIC_DEBUG >= 2
  session_t *stream_session = session_get (ctx->c_s_index,
					   ctx->c_thread_index);
  clib_warning ("Closing session 0x%lx", session_handle (stream_session));
#endif
  if (quic_ctx_is_stream (ctx))
    {
      quicly_stream_t *stream = ctx->stream;
      quicly_reset_stream (stream, QUIC_APP_ERROR_CLOSE_NOTIFY);
      quic_send_packets (ctx);
      return;
    }

  switch (ctx->conn_state)
    {
    case QUIC_CONN_STATE_READY:
      ctx->conn_state = QUIC_CONN_STATE_ACTIVE_CLOSING;
      quicly_conn_t *conn = ctx->conn;
      /* Start connection closing. Keep sending packets until quicly_send
         returns QUICLY_ERROR_FREE_CONNECTION */
      quicly_close (conn, QUIC_APP_ERROR_CLOSE_NOTIFY, "Closed by peer");
      /* This also causes all streams to be closed (and the cb called) */
      quic_send_packets (ctx);
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING:
      ctx->conn_state = QUIC_CONN_STATE_PASSIVE_CLOSING_APP_CLOSED;
      /* send_packets will eventually return an error, we delete the conn at
         that point */
      break;
    case QUIC_CONN_STATE_PASSIVE_CLOSING_QUIC_CLOSED:
      quic_connection_delete (ctx);
      break;
    default:
      QUIC_DBG (0, "BUG");
      break;
    }
}

static u32
quic_start_listen (u32 quic_listen_session_index, transport_endpoint_t * tep)
{
  vnet_listen_args_t _bargs, *args = &_bargs;
  quic_main_t *qm = &quic_main;
  session_handle_t udp_handle;
  session_endpoint_cfg_t *sep;
  session_t *udp_listen_session;
  app_worker_t *app_wrk;
  application_t *app;
  quic_ctx_t *lctx;
  u32 lctx_index;
  app_listener_t *app_listener;
  int rv;

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  /* We need to call this because we call app_worker_init_connected in
   * quic_accept_stream, which assumes the connect segment manager exists */
  app_worker_alloc_connects_segment_manager (app_wrk);
  app = application_get (app_wrk->app_index);
  QUIC_DBG (2, "Called quic_start_listen for app %d", app_wrk->app_index);

  if (quic_store_quicly_ctx (app, sep->ckpair_index, sep->crypto_engine))
    return -1;

  sep->transport_proto = TRANSPORT_PROTO_UDPC;
  clib_memset (args, 0, sizeof (*args));
  args->app_index = qm->app_index;
  args->sep_ext = *sep;
  args->sep_ext.ns_index = app->ns_index;
  if ((rv = vnet_listen (args)))
    return rv;

  lctx_index = quic_ctx_alloc (0);
  udp_handle = args->handle;
  app_listener = app_listener_get_w_handle (udp_handle);
  udp_listen_session = app_listener_get_session (app_listener);
  udp_listen_session->opaque = lctx_index;

  lctx = quic_ctx_get (lctx_index, 0);
  lctx->flags |= QUIC_F_IS_LISTENER;
  /* Also store it in ctx for convenience
   * Waiting for crypto_ctx logic */
  lctx->quicly_ctx = (quicly_context_t *) app->quicly_ctx;

  clib_memcpy (&lctx->c_rmt_ip, &args->sep.peer.ip, sizeof (ip46_address_t));
  clib_memcpy (&lctx->c_lcl_ip, &args->sep.ip, sizeof (ip46_address_t));
  lctx->c_rmt_port = args->sep.peer.port;
  lctx->c_lcl_port = args->sep.port;
  lctx->c_is_ip4 = args->sep.is_ip4;
  lctx->c_fib_index = args->sep.fib_index;
  lctx->c_proto = TRANSPORT_PROTO_QUIC;
  lctx->parent_app_wrk_id = sep->app_wrk_index;
  lctx->parent_app_id = app_wrk->app_index;
  lctx->udp_session_handle = udp_handle;
  lctx->c_s_index = quic_listen_session_index;

  QUIC_DBG (2, "Listening UDP session 0x%lx",
	    session_handle (udp_listen_session));
  QUIC_DBG (2, "Listening QUIC session 0x%lx", quic_listen_session_index);
  return lctx_index;
}

static u32
quic_stop_listen (u32 lctx_index)
{
  QUIC_DBG (2, "Called quic_stop_listen");
  quic_ctx_t *lctx;
  lctx = quic_ctx_get (lctx_index, 0);
  ASSERT (quic_ctx_is_listener (lctx));
  vnet_unlisten_args_t a = {
    .handle = lctx->udp_session_handle,
    .app_index = quic_main.app_index,
    .wrk_map_index = 0		/* default wrk */
  };
  if (vnet_unlisten (&a))
    clib_warning ("unlisten errored");

  /*  TODO: crypto state cleanup */

  quic_ctx_free (lctx);
  return 0;
}

static transport_connection_t *
quic_connection_get (u32 ctx_index, u32 thread_index)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (ctx_index, thread_index);
  return &ctx->connection;
}

static transport_connection_t *
quic_listener_get (u32 listener_index)
{
  QUIC_DBG (2, "Called quic_listener_get");
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (listener_index, 0);
  return &ctx->connection;
}

static u8 *
format_quic_ctx (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  u32 verbose = va_arg (*args, u32);
  u8 *str = 0;

  if (!ctx)
    return s;
  str = format (str, "[#%d][Q] ", ctx->c_thread_index);

  if (quic_ctx_is_listener (ctx))
    str = format (str, "Listener, UDP %ld", ctx->udp_session_handle);
  else if (quic_ctx_is_stream (ctx))
    str = format (str, "Stream %ld conn %d",
		  ctx->stream->stream_id, ctx->quic_connection_ctx_id);
  else				/* connection */
    str = format (str, "Conn %d UDP %d", ctx->c_c_index,
		  ctx->udp_session_handle);

  str = format (str, " app %d wrk %d", ctx->parent_app_id,
		ctx->parent_app_wrk_id);

  if (verbose == 1)
    s = format (s, "%-50s%-15d", str, ctx->conn_state);
  else
    s = format (s, "%s\n", str);
  vec_free (str);
  return s;
}

static u8 *
format_quic_connection (u8 * s, va_list * args)
{
  u32 qc_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, thread_index);
  s = format (s, "%U", format_quic_ctx, ctx, verbose);
  return s;
}

static u8 *
format_quic_half_open (u8 * s, va_list * args)
{
  u32 qc_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, thread_index);
  s = format (s, "[#%d][Q] half-open app %u", thread_index,
	      ctx->parent_app_id);
  return s;
}

/*  TODO improve */
static u8 *
format_quic_listener (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (tci, thread_index);
  s = format (s, "%U", format_quic_ctx, ctx, verbose);
  return s;
}

/* Session layer callbacks */

static inline void
quic_build_sockaddr (struct sockaddr *sa, socklen_t * salen,
		     ip46_address_t * addr, u16 port, u8 is_ip4)
{
  if (is_ip4)
    {
      struct sockaddr_in *sa4 = (struct sockaddr_in *) sa;
      sa4->sin_family = AF_INET;
      sa4->sin_port = port;
      sa4->sin_addr.s_addr = addr->ip4.as_u32;
      *salen = sizeof (struct sockaddr_in);
    }
  else
    {
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) sa;
      sa6->sin6_family = AF_INET6;
      sa6->sin6_port = port;
      clib_memcpy (&sa6->sin6_addr, &addr->ip6, 16);
      *salen = sizeof (struct sockaddr_in6);
    }
}

static int
quic_on_quic_session_connected (quic_ctx_t * ctx)
{
  session_t *quic_session;
  app_worker_t *app_wrk;
  u32 ctx_id = ctx->c_c_index;
  u32 thread_index = ctx->c_thread_index;
  int rv;

  app_wrk = app_worker_get_if_valid (ctx->parent_app_wrk_id);
  if (!app_wrk)
    {
      quic_disconnect_transport (ctx);
      return 0;
    }

  quic_session = session_alloc (thread_index);

  QUIC_DBG (2, "Allocated quic session 0x%lx", session_handle (quic_session));
  ctx->c_s_index = quic_session->session_index;
  quic_session->app_wrk_index = ctx->parent_app_wrk_id;
  quic_session->connection_index = ctx->c_c_index;
  quic_session->listener_handle = SESSION_INVALID_HANDLE;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, ctx->udp_is_ip4);

  if (app_worker_init_connected (app_wrk, quic_session))
    {
      QUIC_DBG (1, "failed to app_worker_init_connected");
      quic_proto_on_close (ctx_id, thread_index);
      return app_worker_connect_notify (app_wrk, NULL, ctx->client_opaque);
    }

  quic_session->session_state = SESSION_STATE_CONNECTING;
  if ((rv = app_worker_connect_notify (app_wrk, quic_session,
				       ctx->client_opaque)))
    {
      QUIC_DBG (1, "failed to notify app %d", rv);
      quic_proto_on_close (ctx_id, thread_index);
      return -1;
    }

  /*  If the app opens a stream in its callback it may invalidate ctx */
  ctx = quic_ctx_get (ctx_id, thread_index);
  /*
   * app_worker_connect_notify() might have reallocated pool, reload
   * quic_session pointer
   */
  quic_session = session_get (ctx->c_s_index, thread_index);
  quic_session->session_state = SESSION_STATE_LISTENING;

  return 0;
}

static int
quic_check_quic_session_connected (quic_ctx_t * ctx)
{
  /* Called when we need to trigger quic session connected
   * we may call this function on the server side / at
   * stream opening */

  /* Conn may be set to null if the connection is terminated */
  if (!ctx->conn || ctx->conn_state != QUIC_CONN_STATE_HANDSHAKE)
    return 0;
  if (!quicly_connection_is_ready (ctx->conn))
    return 0;
  ctx->conn_state = QUIC_CONN_STATE_READY;
  if (!quicly_is_client (ctx->conn))
    return 0;
  return quic_on_quic_session_connected (ctx);
}

static void
quic_receive_connection (void *arg)
{
  u32 new_ctx_id, thread_index = vlib_get_thread_index ();
  quic_ctx_t *temp_ctx, *new_ctx;
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;
  session_t *udp_session;

  temp_ctx = arg;
  new_ctx_id = quic_ctx_alloc (thread_index);
  new_ctx = quic_ctx_get (new_ctx_id, thread_index);

  QUIC_DBG (2, "Received conn %u (now %u)", temp_ctx->c_thread_index,
	    new_ctx_id);

  clib_memcpy (new_ctx, temp_ctx, sizeof (quic_ctx_t));
  clib_mem_free (temp_ctx);

  new_ctx->c_thread_index = thread_index;
  new_ctx->c_c_index = new_ctx_id;

  conn = new_ctx->conn;
  quic_store_conn_ctx (conn, new_ctx);
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) new_ctx_id;
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 1 /* is_add */ );
  new_ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  quic_update_timer (new_ctx);

  /*  Trigger write on this connection if necessary */
  udp_session = session_get_from_handle (new_ctx->udp_session_handle);
  udp_session->opaque = new_ctx_id;
  udp_session->flags &= ~SESSION_F_IS_MIGRATING;
  if (svm_fifo_max_dequeue (udp_session->tx_fifo))
    quic_set_udp_tx_evt (udp_session);
}

static void
quic_transfer_connection (u32 ctx_index, u32 dest_thread)
{
  quic_ctx_t *ctx, *temp_ctx;
  u32 thread_index = vlib_get_thread_index ();

  QUIC_DBG (2, "Transferring conn %u to thread %u", ctx_index, dest_thread);

  temp_ctx = clib_mem_alloc (sizeof (quic_ctx_t));
  ASSERT (temp_ctx);
  ctx = quic_ctx_get (ctx_index, thread_index);

  clib_memcpy (temp_ctx, ctx, sizeof (quic_ctx_t));

  quic_stop_ctx_timer (ctx);
  quic_ctx_free (ctx);

  /*  Send connection to destination thread */
  session_send_rpc_evt_to_thread (dest_thread, quic_receive_connection,
				  (void *) temp_ctx);
}

static int
quic_udp_session_connected_callback (u32 quic_app_index, u32 ctx_index,
				     session_t * udp_session, u8 is_fail)
{
  QUIC_DBG (2, "QSession is now connected (id %u)",
	    udp_session->session_index);
  /* This should always be called before quic_connect returns since UDP always
   * connects instantly. */
  clib_bihash_kv_16_8_t kv;
  struct sockaddr_in6 sa6;
  struct sockaddr *sa = (struct sockaddr *) &sa6;
  socklen_t salen;
  transport_connection_t *tc;
  app_worker_t *app_wrk;
  quicly_conn_t *conn;
  quic_ctx_t *ctx;
  u32 thread_index = vlib_get_thread_index ();
  int ret;
  quicly_context_t *quicly_ctx;


  ctx = quic_ctx_get (ctx_index, thread_index);
  if (is_fail)
    {
      u32 api_context;
      app_wrk = app_worker_get_if_valid (ctx->parent_app_wrk_id);
      if (app_wrk)
	{
	  api_context = ctx->c_s_index;
	  app_worker_connect_notify (app_wrk, 0, api_context);
	}
      return 0;
    }

  ctx->c_thread_index = thread_index;
  ctx->c_c_index = ctx_index;

  QUIC_DBG (2, "Quic connect returned %u. New ctx [%u]%x",
	    is_fail, thread_index, (ctx) ? ctx_index : ~0);

  ctx->udp_session_handle = session_handle (udp_session);
  udp_session->opaque = ctx_index;

  /* Init QUIC lib connection
   * Generate required sockaddr & salen */
  tc = session_get_transport (udp_session);
  quic_build_sockaddr (sa, &salen, &tc->rmt_ip, tc->rmt_port, tc->is_ip4);

  quicly_ctx = quic_get_quicly_ctx_from_ctx (ctx);
  ret = quicly_connect (&ctx->conn, quicly_ctx, (char *) ctx->srv_hostname,
			sa, NULL, &quic_main.next_cid, ptls_iovec_init (NULL,
									0),
			&quic_main.hs_properties, NULL);
  ++quic_main.next_cid.master_id;
  /*  Save context handle in quicly connection */
  quic_store_conn_ctx (ctx->conn, ctx);
  assert (ret == 0);

  /*  Register connection in connections map */
  conn = ctx->conn;
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) ctx_index;
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 1 /* is_add */ );

  /*  UDP stack quirk? preemptively transfer connection if that happens */
  if (udp_session->thread_index != thread_index)
    quic_transfer_connection (ctx_index, udp_session->thread_index);
  else
    quic_send_packets (ctx);

  return ret;
}

static void
quic_udp_session_disconnect_callback (session_t * s)
{
  clib_warning ("UDP session disconnected???");
}

static void
quic_udp_session_cleanup_callback (session_t * udp_session,
				   session_cleanup_ntf_t ntf)
{
  quic_ctx_t *ctx;

  if (ntf != SESSION_CLEANUP_SESSION)
    return;

  ctx = quic_ctx_get (udp_session->opaque, udp_session->thread_index);
  quic_stop_ctx_timer (ctx);
  quic_ctx_free (ctx);
}

static void
quic_udp_session_reset_callback (session_t * s)
{
  clib_warning ("UDP session reset???");
}

static void
quic_udp_session_migrate_callback (session_t * s, session_handle_t new_sh)
{
  u32 new_thread = session_thread_from_handle (new_sh);
  quic_ctx_t *ctx;

  QUIC_DBG (1, "Session %x migrated to %lx", s->session_index, new_sh);
  ASSERT (vlib_get_thread_index () == s->thread_index);
  ctx = quic_ctx_get (s->opaque, s->thread_index);
  ASSERT (ctx->udp_session_handle == session_handle (s));

  ctx->udp_session_handle = new_sh;
#if QUIC_DEBUG >= 1
  s->opaque = 0xfeedface;
#endif
  quic_transfer_connection (ctx->c_c_index, new_thread);
}

int
quic_udp_session_accepted_callback (session_t * udp_session)
{
  /* New UDP connection, try to accept it */
  u32 ctx_index;
  u32 *pool_index;
  quic_ctx_t *ctx, *lctx;
  session_t *udp_listen_session;
  u32 thread_index = vlib_get_thread_index ();

  udp_listen_session =
    listen_session_get_from_handle (udp_session->listener_handle);

  ctx_index = quic_ctx_alloc (thread_index);
  ctx = quic_ctx_get (ctx_index, thread_index);
  ctx->c_thread_index = udp_session->thread_index;
  ctx->c_c_index = ctx_index;
  ctx->c_s_index = QUIC_SESSION_INVALID;
  ctx->udp_session_handle = session_handle (udp_session);
  QUIC_DBG (2, "ACCEPTED UDP 0x%lx", ctx->udp_session_handle);
  ctx->listener_ctx_id = udp_listen_session->opaque;
  lctx = quic_ctx_get (udp_listen_session->opaque,
		       udp_listen_session->thread_index);
  ctx->udp_is_ip4 = lctx->c_is_ip4;
  ctx->parent_app_id = lctx->parent_app_id;
  ctx->parent_app_wrk_id = lctx->parent_app_wrk_id;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  ctx->conn_state = QUIC_CONN_STATE_OPENED;
  ctx->c_flags |= TRANSPORT_CONNECTION_F_NO_LOOKUP;

  /* Also store it in ctx for convenience
   * Waiting for crypto_ctx logic */
  ctx->quicly_ctx = lctx->quicly_ctx;

  udp_session->opaque = ctx_index;

  /* Put this ctx in the "opening" pool */
  pool_get (quic_main.wrk_ctx[ctx->c_thread_index].opening_ctx_pool,
	    pool_index);
  *pool_index = ctx_index;

  /* TODO timeout to delete these if they never connect */
  return 0;
}

static int
quic_add_segment_callback (u32 client_index, u64 seg_handle)
{
  /* No-op for builtin */
  return 0;
}

static int
quic_del_segment_callback (u32 client_index, u64 seg_handle)
{
  /* No-op for builtin */
  return 0;
}

static int
quic_custom_app_rx_callback (transport_connection_t * tc)
{
  quic_ctx_t *ctx;
  session_t *stream_session = session_get (tc->s_index, tc->thread_index);
  QUIC_DBG (3, "Received app READ notification");
  quic_ack_rx_data (stream_session);
  svm_fifo_reset_has_deq_ntf (stream_session->rx_fifo);

  /* Need to send packets (acks may never be sent otherwise) */
  ctx = quic_ctx_get (stream_session->connection_index,
		      stream_session->thread_index);
  quic_send_packets (ctx);
  return 0;
}

static int
quic_custom_tx_callback (void *s, u32 max_burst_size)
{
  session_t *stream_session = (session_t *) s;
  quicly_stream_t *stream;
  quic_ctx_t *ctx;
  int rv;

  if (PREDICT_FALSE
      (stream_session->session_state >= SESSION_STATE_TRANSPORT_CLOSING))
    return 0;
  ctx = quic_ctx_get (stream_session->connection_index,
		      stream_session->thread_index);
  if (PREDICT_FALSE (!quic_ctx_is_stream (ctx)))
    {
      goto tx_end;		/* Most probably a reschedule */
    }

  QUIC_DBG (3, "Stream TX event");
  quic_ack_rx_data (stream_session);
  if (!svm_fifo_max_dequeue (stream_session->tx_fifo))
    return 0;

  stream = ctx->stream;
  if (!quicly_sendstate_is_open (&stream->sendstate))
    {
      QUIC_DBG (1, "Warning: tried to send on closed stream");
      return -1;
    }

  if ((rv = quicly_stream_sync_sendbuf (stream, 1)) != 0)
    return rv;

tx_end:
  quic_send_packets (ctx);
  return 0;
}


/*
 * Returns 0 if a matching connection is found and is on the right thread.
 * Otherwise returns -1.
 * If a connection is found, even on the wrong thread, ctx_thread and ctx_index
 * will be set.
 */
static inline int
quic_find_packet_ctx (u32 * ctx_thread, u32 * ctx_index,
		      struct sockaddr *sa, socklen_t salen,
		      quicly_decoded_packet_t * packet,
		      u32 caller_thread_index)
{
  quic_ctx_t *ctx_;
  quicly_conn_t *conn_;
  clib_bihash_kv_16_8_t kv;
  clib_bihash_16_8_t *h;

  h = &quic_main.connection_hash;
  quic_make_connection_key (&kv, &packet->cid.dest.plaintext);
  QUIC_DBG (3, "Searching conn with id %lu %lu", kv.key[0], kv.key[1]);

  if (clib_bihash_search_16_8 (h, &kv, &kv) == 0)
    {
      u32 index = kv.value & UINT32_MAX;
      u32 thread_id = kv.value >> 32;
      /* Check if this connection belongs to this thread, otherwise
       * ask for it to be moved */
      if (thread_id != caller_thread_index)
	{
	  QUIC_DBG (2, "Connection is on wrong thread");
	  /* Cannot make full check with quicly_is_destination... */
	  *ctx_index = index;
	  *ctx_thread = thread_id;
	  return -1;
	}
      ctx_ = quic_ctx_get (index, vlib_get_thread_index ());
      conn_ = ctx_->conn;
      if (conn_ && quicly_is_destination (conn_, NULL, sa, packet))
	{
	  QUIC_DBG (3, "Connection found");
	  *ctx_index = index;
	  *ctx_thread = thread_id;
	  return 0;
	}
    }
  QUIC_DBG (3, "connection not found");
  return -1;
}

static int
quic_accept_connection (u32 ctx_index, struct sockaddr *sa,
			socklen_t salen, quicly_decoded_packet_t packet)
{
  u32 thread_index = vlib_get_thread_index ();
  quicly_context_t *quicly_ctx;
  session_t *quic_session;
  clib_bihash_kv_16_8_t kv;
  app_worker_t *app_wrk;
  quicly_conn_t *conn;
  quic_ctx_t *ctx;
  quic_ctx_t *lctx;
  int rv;

  /* new connection, accept and create context if packet is valid
   * TODO: check if socket is actually listening? */
  ctx = quic_ctx_get (ctx_index, thread_index);
  quicly_ctx = quic_get_quicly_ctx_from_ctx (ctx);
  if ((rv = quicly_accept (&conn, quicly_ctx, NULL, sa,
			   &packet, NULL, &quic_main.next_cid, NULL)))
    {
      /* Invalid packet, pass */
      assert (conn == NULL);
      QUIC_DBG (1, "Accept failed with %d", rv);
      /* TODO: cleanup created quic ctx and UDP session */
      return 0;
    }
  assert (conn != NULL);

  ++quic_main.next_cid.master_id;
  /* Save ctx handle in quicly connection */
  quic_store_conn_ctx (conn, ctx);
  ctx->conn = conn;
  ctx->conn_state = QUIC_CONN_STATE_HANDSHAKE;

  quic_session = session_alloc (ctx->c_thread_index);
  QUIC_DBG (2, "Allocated quic_session, 0x%lx ctx %u",
	    session_handle (quic_session), ctx->c_c_index);
  quic_session->session_state = SESSION_STATE_LISTENING;
  ctx->c_s_index = quic_session->session_index;

  lctx = quic_ctx_get (ctx->listener_ctx_id, 0);

  quic_session->app_wrk_index = lctx->parent_app_wrk_id;
  quic_session->connection_index = ctx->c_c_index;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, ctx->udp_is_ip4);
  quic_session->listener_handle = lctx->c_s_index;

  /* TODO: don't alloc fifos when we don't transfer data on this session
   * but we still need fifos for the events? */
  if ((rv = app_worker_init_accepted (quic_session)))
    {
      QUIC_DBG (1, "failed to allocate fifos");
      session_free (quic_session);
      return rv;
    }
  app_wrk = app_worker_get (quic_session->app_wrk_index);
  if ((rv = app_worker_accept_notify (app_wrk, quic_session)))
    {
      QUIC_DBG (1, "failed to notify accept worker app");
      return rv;
    }

  /* Register connection in connections map */
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) ctx_index;
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 1 /* is_add */ );
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);

  return quic_send_packets (ctx);
}

static int
quic_reset_connection (u64 udp_session_handle,
		       struct sockaddr *sa, socklen_t salen,
		       quicly_decoded_packet_t packet)
{
  /* short header packet; potentially a dead connection. No need to check the
   * length of the incoming packet, because loop is prevented by authenticating
   * the CID (by checking node_id and thread_id). If the peer is also sending a
   * reset, then the next CID is highly likely to contain a non-authenticating
   * CID, ... */
  QUIC_DBG (2, "Sending stateless reset");
  int rv;
  quicly_datagram_t *dgram;
  session_t *udp_session;
  quicly_context_t *quicly_ctx;
  if (packet.cid.dest.plaintext.node_id != 0
      || packet.cid.dest.plaintext.thread_id != 0)
    return 0;
  quicly_ctx = quic_get_quicly_ctx_from_udp (udp_session_handle);
  dgram = quicly_send_stateless_reset (quicly_ctx, sa, NULL,
				       &packet.cid.dest.plaintext);
  if (dgram == NULL)
    return 1;
  udp_session = session_get_from_handle (udp_session_handle);
  rv = quic_send_datagram (udp_session, dgram);
  quic_set_udp_tx_evt (udp_session);
  return rv;
}

static int
quic_process_one_rx_packet (u64 udp_session_handle, svm_fifo_t * f,
			    u32 * fifo_offset, u32 * max_packet, u32 packet_n,
			    quic_rx_packet_ctx_t * packet_ctx)
{
  session_dgram_hdr_t ph;
  quic_ctx_t *ctx = NULL;
  size_t plen;
  struct sockaddr_in6 sa6;
  struct sockaddr *sa = (struct sockaddr *) &sa6;
  socklen_t salen;
  u32 full_len, ret;
  int err, rv = 0;
  packet_ctx->thread_index = UINT32_MAX;
  packet_ctx->ctx_index = UINT32_MAX;
  u32 thread_index = vlib_get_thread_index ();
  u32 *opening_ctx_pool, *ctx_index_ptr;
  u32 cur_deq = svm_fifo_max_dequeue (f) - *fifo_offset;
  quicly_context_t *quicly_ctx;

  if (cur_deq == 0)
    {
      *max_packet = packet_n + 1;
      return 0;
    }

  if (cur_deq < SESSION_CONN_HDR_LEN)
    {
      QUIC_ERR ("Not enough data for even a header in RX");
      return 1;
    }
  ret = svm_fifo_peek (f, *fifo_offset, SESSION_CONN_HDR_LEN, (u8 *) & ph);
  if (ret != SESSION_CONN_HDR_LEN)
    {
      QUIC_ERR ("Not enough data for header in RX");
      return 1;
    }
  ASSERT (ph.data_offset == 0);
  full_len = ph.data_length + SESSION_CONN_HDR_LEN;
  if (full_len > cur_deq)
    {
      QUIC_ERR ("Not enough data in fifo RX");
      return 1;
    }

  /* Quicly can read len bytes from the fifo at offset:
   * ph.data_offset + SESSION_CONN_HDR_LEN */
  ret = svm_fifo_peek (f, SESSION_CONN_HDR_LEN + *fifo_offset,
		       ph.data_length, packet_ctx->data);
  if (ret != ph.data_length)
    {
      QUIC_ERR ("Not enough data peeked in RX");
      return 1;
    }

  quic_increment_counter (QUIC_ERROR_RX_PACKETS, 1);
  rv = 0;
  quic_build_sockaddr (sa, &salen, &ph.rmt_ip, ph.rmt_port, ph.is_ip4);
  quicly_ctx = quic_get_quicly_ctx_from_udp (udp_session_handle);
  plen = quicly_decode_packet (quicly_ctx, &packet_ctx->packet,
			       packet_ctx->data, ph.data_length);

  if (plen == SIZE_MAX)
    {
      *fifo_offset += SESSION_CONN_HDR_LEN + ph.data_length;
      return 1;
    }

  err = quic_find_packet_ctx (&packet_ctx->thread_index,
			      &packet_ctx->ctx_index, sa, salen,
			      &packet_ctx->packet, thread_index);
  if (err == 0)
    {
      ctx = quic_ctx_get (packet_ctx->ctx_index, thread_index);
      rv = quicly_receive (ctx->conn, NULL, sa, &packet_ctx->packet);
      if (rv)
	QUIC_ERR ("quicly_receive return error %d", rv);
    }
  else if (packet_ctx->ctx_index != UINT32_MAX)
    {
      /*  Connection found but on wrong thread, ask move */
      *max_packet = packet_n + 1;
      return 0;
    }
  else if ((packet_ctx->packet.octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) ==
	   QUICLY_PACKET_TYPE_INITIAL)
    {
      /*  Try to find matching "opening" ctx */
      opening_ctx_pool = quic_main.wrk_ctx[thread_index].opening_ctx_pool;

      /* *INDENT-OFF* */
      pool_foreach (ctx_index_ptr, opening_ctx_pool,
      ({
	ctx = quic_ctx_get (*ctx_index_ptr, thread_index);
	if (ctx->udp_session_handle == udp_session_handle)
	  {
	    /*  Right ctx found, create conn & remove from pool */
	    quic_accept_connection (*ctx_index_ptr, sa, salen, packet_ctx->packet);
	    *max_packet = packet_n + 1;
	    packet_ctx->thread_index = thread_index;
	    packet_ctx->ctx_index = *ctx_index_ptr;
	    pool_put (opening_ctx_pool, ctx_index_ptr);
	    goto updateOffset;
	  }
      }));
      /* *INDENT-ON* */
      QUIC_ERR ("Opening ctx not found!");
      goto reset_connection;
    }
  else
    {
    reset_connection:
      quic_reset_connection (udp_session_handle, sa, salen,
			     packet_ctx->packet);
    }

updateOffset:
  *fifo_offset += SESSION_CONN_HDR_LEN + ph.data_length;
  return 0;
}

static int
quic_udp_session_rx_callback (session_t * udp_session)
{
  /*  Read data from UDP rx_fifo and pass it to the quicly conn. */
  quic_ctx_t *ctx = NULL;
  svm_fifo_t *f;
  u32 max_deq;
  u64 udp_session_handle = session_handle (udp_session);
  int rv = 0;
  u32 thread_index = vlib_get_thread_index ();
  quic_rx_packet_ctx_t packets_ctx[16];
  u32 i, fifo_offset, max_packets;

  if (udp_session->flags & SESSION_F_IS_MIGRATING)
    {
      QUIC_DBG (3, "RX on migrating udp session");
      return 0;
    }

  while (1)
    {
      udp_session = session_get_from_handle (udp_session_handle);	/*  session alloc might have happened */
      f = udp_session->rx_fifo;
      max_deq = svm_fifo_max_dequeue (f);
      if (max_deq == 0)
	return 0;

      fifo_offset = 0;
      max_packets = 16;
      for (i = 0; i < max_packets; i++)
	quic_process_one_rx_packet (udp_session_handle, f, &fifo_offset,
				    &max_packets, i, &packets_ctx[i]);

      for (i = 0; i < max_packets; i++)
	{
	  if (packets_ctx[i].thread_index != thread_index)
	    continue;
	  ctx = quic_ctx_get (packets_ctx[i].ctx_index,
			      packets_ctx[i].thread_index);
	  quic_check_quic_session_connected (ctx);
	  ctx = quic_ctx_get (packets_ctx[i].ctx_index,
			      packets_ctx[i].thread_index);
	  quic_send_packets (ctx);
	}
      svm_fifo_dequeue_drop (f, fifo_offset);
    }
  return rv;
}

always_inline void
quic_common_get_transport_endpoint (quic_ctx_t * ctx,
				    transport_endpoint_t * tep, u8 is_lcl)
{
  session_t *udp_session;
  if (!quic_ctx_is_stream (ctx))
    {
      udp_session = session_get_from_handle (ctx->udp_session_handle);
      session_get_endpoint (udp_session, tep, is_lcl);
    }
}

static void
quic_get_transport_listener_endpoint (u32 listener_index,
				      transport_endpoint_t * tep, u8 is_lcl)
{
  quic_ctx_t *ctx;
  app_listener_t *app_listener;
  session_t *udp_listen_session;
  ctx = quic_ctx_get (listener_index, vlib_get_thread_index ());
  if (quic_ctx_is_listener (ctx))
    {
      app_listener = app_listener_get_w_handle (ctx->udp_session_handle);
      udp_listen_session = app_listener_get_session (app_listener);
      return session_get_endpoint (udp_listen_session, tep, is_lcl);
    }
  quic_common_get_transport_endpoint (ctx, tep, is_lcl);
}

static void
quic_get_transport_endpoint (u32 ctx_index, u32 thread_index,
			     transport_endpoint_t * tep, u8 is_lcl)
{
  quic_ctx_t *ctx;
  ctx = quic_ctx_get (ctx_index, thread_index);
  quic_common_get_transport_endpoint (ctx, tep, is_lcl);
}

/* *INDENT-OFF* */
static session_cb_vft_t quic_app_cb_vft = {
  .session_accept_callback = quic_udp_session_accepted_callback,
  .session_disconnect_callback = quic_udp_session_disconnect_callback,
  .session_connected_callback = quic_udp_session_connected_callback,
  .session_reset_callback = quic_udp_session_reset_callback,
  .session_migrate_callback = quic_udp_session_migrate_callback,
  .add_segment_callback = quic_add_segment_callback,
  .del_segment_callback = quic_del_segment_callback,
  .builtin_app_rx_callback = quic_udp_session_rx_callback,
  .session_cleanup_callback = quic_udp_session_cleanup_callback,
};

static const transport_proto_vft_t quic_proto = {
  .connect = quic_connect,
  .close = quic_proto_on_close,
  .start_listen = quic_start_listen,
  .stop_listen = quic_stop_listen,
  .get_connection = quic_connection_get,
  .get_listener = quic_listener_get,
  .update_time = quic_update_time,
  .app_rx_evt = quic_custom_app_rx_callback,
  .custom_tx = quic_custom_tx_callback,
  .format_connection = format_quic_connection,
  .format_half_open = format_quic_half_open,
  .format_listener = format_quic_listener,
  .get_transport_endpoint = quic_get_transport_endpoint,
  .get_transport_listener_endpoint = quic_get_transport_listener_endpoint,
  .transport_options = {
    .tx_type = TRANSPORT_TX_INTERNAL,
    .service_type = TRANSPORT_SERVICE_APP,
  },
};
/* *INDENT-ON* */

static quicly_stream_open_t on_stream_open = { quic_on_stream_open };
static quicly_closed_by_peer_t on_closed_by_peer = { quic_on_closed_by_peer };
static quicly_now_t quicly_vpp_now_cb = { quic_get_time };

static void
quic_register_cipher_suite (crypto_engine_type_t type,
			    ptls_cipher_suite_t ** ciphers)
{
  quic_main_t *qm = &quic_main;
  vec_validate (qm->quic_ciphers, type);
  clib_bitmap_set (qm->available_crypto_engines, type, 1);
  qm->quic_ciphers[type] = ciphers;
}

static void
quic_update_fifo_size ()
{
  quic_main_t *qm = &quic_main;
  segment_manager_props_t *seg_mgr_props =
    application_get_segment_manager_properties (qm->app_index);

  if (!seg_mgr_props)
    {
      clib_warning
	("error while getting segment_manager_props_t, can't update fifo-size");
      return;
    }

  seg_mgr_props->tx_fifo_size = qm->udp_fifo_size;
  seg_mgr_props->rx_fifo_size = qm->udp_fifo_size;
}

static clib_error_t *
quic_init (vlib_main_t * vm)
{
  u32 segment_size = 256 << 20;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  quic_main_t *qm = &quic_main;
  u32 num_threads, i;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  clib_memset (a, 0, sizeof (*a));
  clib_memset (options, 0, sizeof (options));

  a->session_cb_vft = &quic_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "quic");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = qm->udp_fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = qm->udp_fifo_size;
  a->options[APP_OPTIONS_PREALLOC_FIFO_PAIRS] = qm->udp_fifo_prealloc;
  a->options[APP_OPTIONS_FLAGS] = APP_OPTIONS_FLAGS_IS_BUILTIN;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_USE_GLOBAL_SCOPE;
  a->options[APP_OPTIONS_FLAGS] |= APP_OPTIONS_FLAGS_IS_TRANSPORT_APP;

  if (vnet_application_attach (a))
    {
      clib_warning ("failed to attach quic app");
      return clib_error_return (0, "failed to attach quic app");
    }

  vec_validate (qm->ctx_pool, num_threads - 1);
  vec_validate (qm->wrk_ctx, num_threads - 1);
  /*  Timer wheels, one per thread. */
  for (i = 0; i < num_threads; i++)
    {
      tw = &qm->wrk_ctx[i].timer_wheel;
      tw_timer_wheel_init_1t_3w_1024sl_ov (tw, quic_expired_timers_dispatch,
					   1e-3 /* timer period 1ms */ , ~0);
      tw->last_run_time = vlib_time_now (vlib_get_main ());
    }

  clib_bihash_init_16_8 (&qm->connection_hash, "quic connections", 1024,
			 4 << 20);


  qm->app_index = a->app_index;
  qm->tstamp_ticks_per_clock = vm->clib_time.seconds_per_clock
    / QUIC_TSTAMP_RESOLUTION;
  qm->session_cache.super.cb = quic_encrypt_ticket_cb;

  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP6, ~0);

  clib_bitmap_alloc (qm->available_crypto_engines,
		     app_crypto_engine_n_types ());
  quic_register_cipher_suite (CRYPTO_ENGINE_VPP, quic_crypto_cipher_suites);
  quic_register_cipher_suite (CRYPTO_ENGINE_PICOTLS,
			      ptls_openssl_cipher_suites);
  qm->default_crypto_engine = CRYPTO_ENGINE_PICOTLS;
  vec_free (a->name);
  return 0;
}

VLIB_INIT_FUNCTION (quic_init);

static clib_error_t *
quic_plugin_crypto_command_fn (vlib_main_t * vm,
			       unformat_input_t * input,
			       vlib_cli_command_t * cmd)
{
  quic_main_t *qm = &quic_main;
  if (unformat_check_input (input) == UNFORMAT_END_OF_INPUT)
    return clib_error_return (0, "unknown input '%U'",
			      format_unformat_error, input);
  if (unformat (input, "vpp"))
    qm->default_crypto_engine = CRYPTO_ENGINE_VPP;
  else if (unformat (input, "picotls"))
    qm->default_crypto_engine = CRYPTO_ENGINE_PICOTLS;
  else
    return clib_error_return (0, "unknown input '%U'",
			      format_unformat_error, input);
  return 0;
}

u64 quic_fifosize = 0;
static clib_error_t *
quic_plugin_set_fifo_size_command_fn (vlib_main_t * vm,
				      unformat_input_t * input,
				      vlib_cli_command_t * cmd)
{
  quic_main_t *qm = &quic_main;
  unformat_input_t _line_input, *line_input = &_line_input;
  uword tmp;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      return clib_error_return
		(0, "fifo-size %llu (0x%llx) too large", tmp, tmp);
	    }
	  qm->udp_fifo_size = tmp;
	  quic_update_fifo_size ();
	}
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, line_input);
    }

  return 0;
}

static u8 *
quic_format_ctx_stat (u8 * s, va_list * args)
{
  quic_ctx_t *ctx = va_arg (*args, quic_ctx_t *);
  quicly_stats_t quicly_stats;

  quicly_get_stats (ctx->conn, &quicly_stats);

  s = format (s, "\n\rQUIC conn stats \n\r");

  s =
    format (s, "RTT: min:%d, smoothed:%d, variance:%d, latest:%d \n\r",
	    quicly_stats.rtt.minimum, quicly_stats.rtt.smoothed,
	    quicly_stats.rtt.variance, quicly_stats.rtt.latest);
  s = format (s, "Packet loss:%d \n\r", quicly_stats.num_packets.lost);

  return s;
}

static clib_error_t *
quic_plugin_showstats_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx = NULL;
  u32 num_workers = vlib_num_workers ();

  for (int i = 0; i < num_workers + 1; i++)
    {
      /* *INDENT-OFF* */
      pool_foreach (ctx, qm->ctx_pool[i],
      ({
        if(!(ctx->flags & QUIC_F_IS_LISTENER) && !(ctx->flags & QUIC_F_IS_STREAM))
          vlib_cli_output (vm, "%U", quic_format_ctx_stat, ctx);
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

static clib_error_t *
quic_show_ctx_command_fn (vlib_main_t * vm, unformat_input_t * input,
			  vlib_cli_command_t * cmd)
{
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx = NULL;
  u32 num_workers = vlib_num_workers ();

  for (int i = 0; i < num_workers + 1; i++)
    {
      /* *INDENT-OFF* */
      pool_foreach (ctx, qm->ctx_pool[i],
      ({
        vlib_cli_output (vm, "%U", format_quic_ctx, ctx, 1);
      }));
      /* *INDENT-ON* */
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (quic_plugin_crypto_command, static) =
{
  .path = "quic set crypto api",
  .short_help = "quic set crypto api [picotls, vpp]",
  .function = quic_plugin_crypto_command_fn,
};
VLIB_CLI_COMMAND(quic_plugin_set_fifo_size_command, static)=
{
  .path = "quic set fifo-size",
  .short_help = "quic set fifo-size N[K|M|G] (default 64K)",
  .function = quic_plugin_set_fifo_size_command_fn,
};
VLIB_CLI_COMMAND(quic_plugin_stats_command, static)=
{
  .path = "show quic stats",
  .short_help = "show quic stats",
  .function = quic_plugin_showstats_command_fn,
};
VLIB_CLI_COMMAND(quic_show_ctx_command, static)=
{
  .path = "show quic ctx",
  .short_help = "show quic ctx",
  .function = quic_show_ctx_command_fn,
};
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Quic transport protocol",
  .default_disabled = 1,
};
/* *INDENT-ON* */

static clib_error_t *
quic_config_fn (vlib_main_t * vm, unformat_input_t * input)
{
  quic_main_t *qm = &quic_main;
  uword tmp;

  qm->udp_fifo_size = QUIC_DEFAULT_FIFO_SIZE;
  qm->udp_fifo_prealloc = 0;
  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "fifo-size %U", unformat_memory_size, &tmp))
	{
	  if (tmp >= 0x100000000ULL)
	    {
	      return clib_error_return
		(0, "fifo-size %llu (0x%llx) too large", tmp, tmp);
	    }
	  qm->udp_fifo_size = tmp;
	}
      else
	if (unformat
	    (input, "fifo-prealloc %u", &quic_main.udp_fifo_prealloc))
	;
      else
	return clib_error_return (0, "unknown input '%U'",
				  format_unformat_error, input);
    }

  return 0;
}

VLIB_EARLY_CONFIG_FUNCTION (quic_config_fn, "quic");

static uword
quic_node_fn (vlib_main_t * vm, vlib_node_runtime_t * node,
	      vlib_frame_t * frame)
{
  return 0;
}

/* *INDENT-OFF* */
VLIB_REGISTER_NODE (quic_input_node) =
{
  .function = quic_node_fn,
  .name = "quic-input",
  .vector_size = sizeof (u32),
  .type = VLIB_NODE_TYPE_INTERNAL,
  .n_errors = ARRAY_LEN (quic_error_strings),
  .error_strings = quic_error_strings,
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
