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
#include <openssl/pem.h>

#include <vppinfra/lock.h>

#include <quic/quic.h>

#include <quicly/defaults.h>
#include <picotls/openssl.h>
#include <picotls/pembase64.h>

static quic_main_t quic_main;

static void quic_update_timer (quic_ctx_t * ctx);
static void quic_connection_closed (u32 conn_index, u32 thread_index);
static void quic_disconnect (u32 ctx_index, u32 thread_index);
static int quic_connect_new_stream (session_endpoint_cfg_t * sep);
static int quic_connect_new_connection (session_endpoint_cfg_t * sep);

static int64_t quic_get_time (quicly_now_t * self);
static quicly_now_t quicly_vpp_now_cb = { quic_get_time };

static void quic_transfer_connection (u32 ctx_index, u32 dest_thread);

#define QUIC_TIMER_HANDLE_INVALID ((u32) ~0)
#define QUIC_SESSION_INVALID ((u32) ~0 - 1)
#define QUIC_MAX_PACKET_SIZE 1280

#define QUIC_INT_MAX  0x3FFFFFFFFFFFFFFF

/* Taken from quicly.c */
#define QUICLY_QUIC_BIT 0x40

#define QUICLY_PACKET_TYPE_INITIAL (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0)
#define QUICLY_PACKET_TYPE_0RTT (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x10)
#define QUICLY_PACKET_TYPE_HANDSHAKE (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x20)
#define QUICLY_PACKET_TYPE_RETRY (QUICLY_LONG_HEADER_BIT | QUICLY_QUIC_BIT | 0x30)
#define QUICLY_PACKET_TYPE_BITMASK 0xf0
#define QUIC_FIFO_SIZE (64 << 10)

#define QUIC_ERROR_FULL_FIFO 0xff10

static char *
quic_format_err (u64 code)
{
  switch (code)
    {
    case QUIC_ERROR_FULL_FIFO:
      return "full fifo";
    case QUICLY_ERROR_PACKET_IGNORED:
      return "QUICLY_ERROR_PACKET_IGNORED";
    case QUICLY_ERROR_SENDBUF_FULL:
      return "QUICLY_ERROR_SENDBUF_FULL";
    case QUICLY_ERROR_FREE_CONNECTION:
      return "no open stream on connection";
    case QUICLY_ERROR_RECEIVED_STATELESS_RESET:
      return "QUICLY_ERROR_RECEIVED_STATELESS_RESET";
    case QUICLY_TRANSPORT_ERROR_NONE:
      return "QUICLY_TRANSPORT_ERROR_NONE";
    case QUICLY_TRANSPORT_ERROR_INTERNAL:
      return "QUICLY_TRANSPORT_ERROR_INTERNAL";
    case QUICLY_TRANSPORT_ERROR_SERVER_BUSY:
      return "QUICLY_TRANSPORT_ERROR_SERVER_BUSY";
    case QUICLY_TRANSPORT_ERROR_FLOW_CONTROL:
      return "QUICLY_TRANSPORT_ERROR_FLOW_CONTROL";
    case QUICLY_TRANSPORT_ERROR_STREAM_ID:
      return "QUICLY_TRANSPORT_ERROR_STREAM_ID";
    case QUICLY_TRANSPORT_ERROR_STREAM_STATE:
      return "QUICLY_TRANSPORT_ERROR_STREAM_STATE";
    case QUICLY_TRANSPORT_ERROR_FINAL_OFFSET:
      return "QUICLY_TRANSPORT_ERROR_FINAL_OFFSET";
    case QUICLY_TRANSPORT_ERROR_FRAME_ENCODING:
      return "QUICLY_TRANSPORT_ERROR_FRAME_ENCODING";
    case QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER:
      return "QUICLY_TRANSPORT_ERROR_TRANSPORT_PARAMETER";
    case QUICLY_TRANSPORT_ERROR_VERSION_NEGOTIATION:
      return "QUICLY_TRANSPORT_ERROR_VERSION_NEGOTIATION";
    case QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION:
      return "QUICLY_TRANSPORT_ERROR_PROTOCOL_VIOLATION";
    case QUICLY_TRANSPORT_ERROR_INVALID_MIGRATION:
      return "QUICLY_TRANSPORT_ERROR_INVALID_MIGRATION";
    case QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE:
      return "QUICLY_TRANSPORT_ERROR_TLS_ALERT_BASE";
    default:
      return "unknown error";
    }
}

static u32
quic_ctx_alloc (u32 thread_index)
{
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;

  pool_get (qm->ctx_pool[thread_index], ctx);

  memset (ctx, 0, sizeof (quic_ctx_t));
  ctx->c_thread_index = thread_index;
  QUIC_DBG (1, "Allocated quic_ctx %u on thread %u",
	    ctx - qm->ctx_pool[thread_index], thread_index);
  return ctx - qm->ctx_pool[thread_index];
}

static void
quic_ctx_free (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "Free ctx %u", ctx->c_c_index);
  u32 thread_index = ctx->c_thread_index;
  if (CLIB_DEBUG)
    memset (ctx, 0xfb, sizeof (*ctx));
  pool_put (quic_main.ctx_pool[thread_index], ctx);
}

static quic_ctx_t *
quic_ctx_get (u32 ctx_index, u32 thread_index)
{
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

static void
quic_disconnect_transport (quic_ctx_t * ctx)
{
  QUIC_DBG (2, "Called quic_disconnect_transport");
  vnet_disconnect_args_t a = {
    .handle = ctx->c_quic_ctx_id.udp_session_handle,
    .app_index = quic_main.app_index,
  };

  if (vnet_disconnect_session (&a))
    clib_warning ("UDP session disconnect errored");
}

static int
quic_send_datagram (session_t * udp_session, quicly_datagram_t * packet)
{
  /*  QUIC_DBG (2, "Called quic_send_datagram at %ld", quic_get_time (NULL)); */
  u32 max_enqueue;
  session_dgram_hdr_t hdr;
  u32 len, ret;
  svm_fifo_t *f;
  transport_connection_t *tc;

  len = packet->data.len;
  f = udp_session->tx_fifo;
  tc = session_get_transport (udp_session);

  max_enqueue = svm_fifo_max_enqueue (f);
  if (max_enqueue <= sizeof (session_dgram_hdr_t))
    {
      QUIC_DBG (1, "Not enough space to enqueue header");
      return QUIC_ERROR_FULL_FIFO;
    }

  max_enqueue -= sizeof (session_dgram_hdr_t);

  if (max_enqueue < len)
    {
      QUIC_DBG (1, "Too much data to send, max_enqueue %u, len %u",
		max_enqueue, len);
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
      ASSERT (packet->sa.sa_family == AF_INET);
      struct sockaddr_in *sa4 = (struct sockaddr_in *) &packet->sa;
      hdr.rmt_port = sa4->sin_port;
      hdr.rmt_ip.ip4.as_u32 = sa4->sin_addr.s_addr;
    }
  else
    {
      ASSERT (packet->sa.sa_family == AF_INET6);
      struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *) &packet->sa;
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
  return 0;
}

#define QUIC_SEND_PACKET_VEC_SIZE 16

static int
quic_sendable_packet_count (session_t * udp_session)
{
  u32 max_enqueue;
  max_enqueue = svm_fifo_max_enqueue (udp_session->tx_fifo);
  return clib_min (max_enqueue /
		   (QUIC_MAX_PACKET_SIZE + sizeof (session_dgram_hdr_t)),
		   QUIC_SEND_PACKET_VEC_SIZE);
}

static int
quic_send_packets (quic_ctx_t * ctx)
{
  quicly_datagram_t *packets[QUIC_SEND_PACKET_VEC_SIZE];
  session_t *udp_session;
  quicly_conn_t *conn;
  size_t num_packets, i, max_packets;
  quicly_context_t *quicly_context;
  app_worker_t *app_wrk;
  application_t *app;
  int err;

  /* We have sctx, get qctx */
  if (ctx->c_quic_ctx_id.is_stream)
    ctx =
      quic_ctx_get (ctx->c_quic_ctx_id.quic_connection_ctx_id,
		    ctx->c_thread_index);

  ASSERT (!ctx->c_quic_ctx_id.is_stream);

  udp_session =
    session_get_from_handle (ctx->c_quic_ctx_id.udp_session_handle);
  conn = ctx->c_quic_ctx_id.conn;

  if (!conn)
    return 0;

  /* TODO : quicly can assert it can send min_packets up to 2 */
  if (quic_sendable_packet_count (udp_session) < 2)
    goto stop_sending;

  app_wrk = app_worker_get_if_valid (ctx->c_quic_ctx_id.parent_app_wrk_id);
  if (!app_wrk)
    {
      clib_warning ("Tried to send packets on non existing app worker %u",
		    ctx->c_quic_ctx_id.parent_app_wrk_id);
      quic_connection_closed (ctx->c_c_index, ctx->c_thread_index);
      return 1;
    }
  app = application_get (app_wrk->app_index);

  quicly_context = (quicly_context_t *) app->quicly_ctx;
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

	  quicly_context->packet_allocator->
	    free_packet (quicly_context->packet_allocator, packets[i]);
	}
    }
  while (num_packets > 0 && num_packets == max_packets);

  if (svm_fifo_set_event (udp_session->tx_fifo))
    session_send_io_evt_to_thread (udp_session->tx_fifo, SESSION_IO_EVT_TX);

stop_sending:
  quic_update_timer (ctx);
  return 0;

quicly_error:
  if (err != QUICLY_ERROR_PACKET_IGNORED)
    clib_warning ("Quic error '%s'.", quic_format_err (err));
  quic_connection_closed (ctx->c_c_index, ctx->c_thread_index);
  return 1;
}

/*****************************************************************************
 * START QUICLY CALLBACKS
 * Called from QUIC lib
 *****************************************************************************/

static void
quic_on_stream_destroy (quicly_stream_t * stream, int err)
{
  quic_stream_data_t *stream_data = (quic_stream_data_t *) stream->data;
  u32 sctx_id = stream_data->ctx_id;
  session_t *stream_session;
  quic_ctx_t *sctx = quic_ctx_get (sctx_id, stream_data->thread_index);
  QUIC_DBG (2, "Stream %ld (ctx %u) destroyed", stream->stream_id, sctx_id);
  stream_session = session_get (sctx->c_s_index, sctx->c_thread_index);
  stream_session->session_state = SESSION_STATE_CLOSED;
  session_transport_delete_notify (&sctx->connection);
  quic_ctx_free (sctx);
  free (stream->data);
}

static int
quic_on_stop_sending (quicly_stream_t * stream, int error_code)
{
  QUIC_DBG (2, "received STOP_SENDING: %d", error_code);
  return 0;
}

static int
quic_on_receive_reset (quicly_stream_t * stream, int error_code)
{
  QUIC_DBG (2, "received RESET_STREAM: %d", error_code);
  return 0;
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
  if (off + len > max_enq)
    {
      /* TODO : can we find a better solution, listening on RX fifo evts ? */
      QUIC_DBG (3, "Ingoring packet, RX fifo is full");
      return QUICLY_ERROR_PACKET_IGNORED;
    }
  if (off == 0)
    {
      rlen = svm_fifo_enqueue (f, len, (u8 *) src);
      ASSERT (rlen >= len);

      quicly_stream_sync_recvbuf (stream, rlen);
      app_wrk = app_worker_get_if_valid (stream_session->app_wrk_index);
      if (PREDICT_TRUE (app_wrk != 0))
	app_worker_lock_and_send_event (app_wrk, stream_session,
					SESSION_IO_EVT_RX);
    }
  else
    {
      rlen = svm_fifo_enqueue_with_offset (f, off, len, (u8 *) src);
      ASSERT (rlen == 0);
    }
  return 0;
}

void
quic_fifo_egress_shift (quicly_stream_t * stream, size_t delta)
{
  session_t *stream_session;
  svm_fifo_t *f;

  stream_session = get_stream_session_from_stream (stream);
  f = stream_session->tx_fifo;

  ASSERT (svm_fifo_dequeue_drop (f, delta) == delta);
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
      QUIC_DBG (3, "Wrote ALL");
      *wrote_all = 1;
      *len = deq_max - off;
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

static void
quic_accept_stream (void *s)
{
  quicly_stream_t *stream = (quicly_stream_t *) s;
  session_t *stream_session;
  quic_stream_data_t *stream_data;
  app_worker_t *app_wrk;
  quic_ctx_t *qctx, *sctx;
  u32 sctx_id;
  quic_main_t *qm = &quic_main;
  int rv;

  sctx_id = quic_ctx_alloc (vlib_get_thread_index ());

  qctx = quic_get_conn_ctx (stream->conn);

  stream_session = session_alloc (qctx->c_thread_index);
  QUIC_DBG (2, "Allocated stream_session, id %u, thread %u ctx %u",
	    stream_session->session_index, stream_session->thread_index,
	    sctx_id);
  sctx = quic_ctx_get (sctx_id, qctx->c_thread_index);
  sctx->c_quic_ctx_id.parent_app_wrk_id =
    qctx->c_quic_ctx_id.parent_app_wrk_id;
  sctx->c_quic_ctx_id.parent_app_id = qctx->c_quic_ctx_id.parent_app_id;
  sctx->c_quic_ctx_id.quic_connection_ctx_id = qctx->c_c_index;
  sctx->c_c_index = sctx_id;
  sctx->c_quic_ctx_id.is_stream = 1;
  sctx->c_s_index = stream_session->session_index;
  sctx->c_quic_ctx_id.stream = stream;

  stream_data = (quic_stream_data_t *) stream->data;
  stream_data->ctx_id = sctx_id;
  stream_data->thread_index = sctx->c_thread_index;

  sctx->c_s_index = stream_session->session_index;
  stream_session->session_state = SESSION_STATE_CREATED;
  stream_session->flags |= SESSION_F_QUIC_STREAM;
  stream_session->app_wrk_index = sctx->c_quic_ctx_id.parent_app_wrk_id;
  stream_session->connection_index = sctx->c_c_index;
  stream_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC,
				    qctx->c_quic_ctx_id.udp_is_ip4);
  stream_session->listener_index = qm->fake_app_listener_index;
  stream_session->app_index = sctx->c_quic_ctx_id.parent_app_id;

  app_wrk = app_worker_get (stream_session->app_wrk_index);
  if ((rv = app_worker_init_connected (app_wrk, stream_session)))
    {
      QUIC_DBG (1, "failed to allocate fifos");
      session_free (stream_session);
      quicly_reset_stream (stream, 0x30001);
      return;
    }

  rv = app_worker_accept_notify (app_wrk, stream_session);
  if (rv)
    {
      QUIC_DBG (1, "failed to notify accept worker app");
      session_free_w_fifos (stream_session);
      quicly_reset_stream (stream, 0x30002);
      return;
    }
  session_lookup_add_connection (&sctx->connection,
				 session_handle (stream_session));
}

static int
quic_on_stream_open (quicly_stream_open_t * self, quicly_stream_t * stream)
{
  QUIC_DBG (2, "on_stream_open called");
  stream->data = malloc (sizeof (quic_stream_data_t));
  stream->callbacks = &quic_stream_callbacks;
  /* Notify accept on parent qsession, but only if this is not a locally
   * initiated stream */
  if (!quicly_stream_is_self_initiated (stream))
    {
      quic_accept_stream (stream);
    }
  return 0;
}

static quicly_stream_open_t on_stream_open = { &quic_on_stream_open };

static void
quic_on_conn_close (quicly_closed_by_peer_t * self, quicly_conn_t * conn,
		    int code, uint64_t frame_type,
		    const char *reason, size_t reason_len)
{
  QUIC_DBG (2, "connection closed, reason: %.*s", reason, reason_len);
  quic_ctx_t *ctx = quic_get_conn_ctx (conn);
  session_transport_closing_notify (&ctx->connection);
}

static quicly_closed_by_peer_t on_closed_by_peer = { &quic_on_conn_close };


/*****************************************************************************
 * END QUICLY CALLBACKS
 *****************************************************************************/

/* single-entry session cache */
struct st_util_session_cache_t
{
  ptls_encrypt_ticket_t super;
  uint8_t id[32];
  ptls_iovec_t data;
};

static int
encrypt_ticket_cb (ptls_encrypt_ticket_t * _self, ptls_t * tls,
		   int is_encrypt, ptls_buffer_t * dst, ptls_iovec_t src)
{
  struct st_util_session_cache_t *self = (void *) _self;
  int ret;

  if (is_encrypt)
    {

      /* replace the cached entry along with a newly generated session id */
      free (self->data.base);
      if ((self->data.base = malloc (src.len)) == NULL)
	return PTLS_ERROR_NO_MEMORY;

      ptls_get_context (tls)->random_bytes (self->id, sizeof (self->id));
      memcpy (self->data.base, src.base, src.len);
      self->data.len = src.len;

      /* store the session id in buffer */
      if ((ret = ptls_buffer_reserve (dst, sizeof (self->id))) != 0)
	return ret;
      memcpy (dst->base + dst->off, self->id, sizeof (self->id));
      dst->off += sizeof (self->id);

    }
  else
    {

      /* check if session id is the one stored in cache */
      if (src.len != sizeof (self->id))
	return PTLS_ERROR_SESSION_NOT_FOUND;
      if (memcmp (self->id, src.base, sizeof (self->id)) != 0)
	return PTLS_ERROR_SESSION_NOT_FOUND;

      /* return the cached value */
      if ((ret = ptls_buffer_reserve (dst, self->data.len)) != 0)
	return ret;
      memcpy (dst->base + dst->off, self->data.base, self->data.len);
      dst->off += self->data.len;
    }

  return 0;
}

/* *INDENT-OFF* */
static struct st_util_session_cache_t sc = {
  .super = {
    .cb = encrypt_ticket_cb,
  },
};

static ptls_context_t quic_tlsctx = {
  .random_bytes = ptls_openssl_random_bytes,
  .get_time = &ptls_get_time,
  .key_exchanges = ptls_openssl_key_exchanges,
  .cipher_suites = ptls_openssl_cipher_suites,
  .certificates = {
    .list = NULL,
    .count = 0
  },
  .esni = NULL,
  .on_client_hello = NULL,
  .emit_certificate = NULL,
  .sign_certificate = NULL,
  .verify_certificate = NULL,
  .ticket_lifetime = 86400,
  .max_early_data_size = 8192,
  .hkdf_label_prefix__obsolete = NULL,
  .require_dhe_on_psk = 1,
  .encrypt_ticket = &sc.super,
};
/* *INDENT-ON* */

static int
ptls_compare_separator_line (const char *line, const char *begin_or_end,
			     const char *label)
{
  int ret = strncmp (line, "-----", 5);
  size_t text_index = 5;

  if (ret == 0)
    {
      size_t begin_or_end_length = strlen (begin_or_end);
      ret = strncmp (line + text_index, begin_or_end, begin_or_end_length);
      text_index += begin_or_end_length;
    }

  if (ret == 0)
    {
      ret = line[text_index] - ' ';
      text_index++;
    }

  if (ret == 0)
    {
      size_t label_length = strlen (label);
      ret = strncmp (line + text_index, label, label_length);
      text_index += label_length;
    }

  if (ret == 0)
    {
      ret = strncmp (line + text_index, "-----", 5);
    }

  return ret;
}

static int
ptls_get_bio_pem_object (BIO * bio, const char *label, ptls_buffer_t * buf)
{
  int ret = PTLS_ERROR_PEM_LABEL_NOT_FOUND;
  char line[256];
  ptls_base64_decode_state_t state;

  /* Get the label on a line by itself */
  while (BIO_gets (bio, line, 256))
    {
      if (ptls_compare_separator_line (line, "BEGIN", label) == 0)
	{
	  ret = 0;
	  ptls_base64_decode_init (&state);
	  break;
	}
    }
  /* Get the data in the buffer */
  while (ret == 0 && BIO_gets (bio, line, 256))
    {
      if (ptls_compare_separator_line (line, "END", label) == 0)
	{
	  if (state.status == PTLS_BASE64_DECODE_DONE
	      || (state.status == PTLS_BASE64_DECODE_IN_PROGRESS
		  && state.nbc == 0))
	    {
	      ret = 0;
	    }
	  else
	    {
	      ret = PTLS_ERROR_INCORRECT_BASE64;
	    }
	  break;
	}
      else
	{
	  ret = ptls_base64_decode (line, &state, buf);
	}
    }

  return ret;
}

static int
ptls_load_bio_pem_objects (BIO * bio, const char *label, ptls_iovec_t * list,
			   size_t list_max, size_t * nb_objects)
{
  int ret = 0;
  size_t count = 0;

  *nb_objects = 0;

  if (ret == 0)
    {
      while (count < list_max)
	{
	  ptls_buffer_t buf;

	  ptls_buffer_init (&buf, "", 0);

	  ret = ptls_get_bio_pem_object (bio, label, &buf);

	  if (ret == 0)
	    {
	      if (buf.off > 0 && buf.is_allocated)
		{
		  list[count].base = buf.base;
		  list[count].len = buf.off;
		  count++;
		}
	      else
		{
		  ptls_buffer_dispose (&buf);
		}
	    }
	  else
	    {
	      ptls_buffer_dispose (&buf);
	      break;
	    }
	}
    }

  if (ret == PTLS_ERROR_PEM_LABEL_NOT_FOUND && count > 0)
    {
      ret = 0;
    }

  *nb_objects = count;

  return ret;
}

#define PTLS_MAX_CERTS_IN_CONTEXT 16

static int
ptls_load_bio_certificates (ptls_context_t * ctx, BIO * bio)
{
  int ret = 0;

  ctx->certificates.list =
    (ptls_iovec_t *) malloc (PTLS_MAX_CERTS_IN_CONTEXT *
			     sizeof (ptls_iovec_t));

  if (ctx->certificates.list == NULL)
    {
      ret = PTLS_ERROR_NO_MEMORY;
    }
  else
    {
      ret =
	ptls_load_bio_pem_objects (bio, "CERTIFICATE", ctx->certificates.list,
				   PTLS_MAX_CERTS_IN_CONTEXT,
				   &ctx->certificates.count);
    }

  return ret;
}

static inline void
load_bio_certificate_chain (ptls_context_t * ctx, const char *cert_data)
{
  BIO *cert_bio;
  cert_bio = BIO_new_mem_buf (cert_data, -1);
  if (ptls_load_bio_certificates (ctx, cert_bio) != 0)
    {
      BIO_free (cert_bio);
      fprintf (stderr, "failed to load certificate:%s\n", strerror (errno));
      exit (1);
    }
  BIO_free (cert_bio);
}

static inline void
load_bio_private_key (ptls_context_t * ctx, const char *pk_data)
{
  static ptls_openssl_sign_certificate_t sc;
  EVP_PKEY *pkey;
  BIO *key_bio;

  key_bio = BIO_new_mem_buf (pk_data, -1);
  pkey = PEM_read_bio_PrivateKey (key_bio, NULL, NULL, NULL);
  BIO_free (key_bio);

  if (pkey == NULL)
    {
      fprintf (stderr, "failed to read private key from app configuration\n");
      exit (1);
    }

  ptls_openssl_init_sign_certificate (&sc, pkey);
  EVP_PKEY_free (pkey);

  ctx->sign_certificate = &sc.super;
}

static inline void
quic_make_connection_key (clib_bihash_kv_16_8_t * kv,
			  const quicly_cid_plaintext_t * id)
{
  kv->key[0] = ((u64) id->master_id) << 32 | (u64) id->thread_id;
  kv->key[1] = id->node_id;
}

static void
quic_connection_closed (u32 ctx_index, u32 thread_index)
{
  /*  TODO : free fifos */
  QUIC_DBG (2, "QUIC connection closed");
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;
  quic_ctx_t *ctx;

  ctx = quic_ctx_get (ctx_index, thread_index);

  ASSERT (!ctx->c_quic_ctx_id.is_stream);
  /*  TODO if connection is not established, just delete the session? */

  /*  Stop the timer */
  if (ctx->timer_handle != QUIC_TIMER_HANDLE_INVALID)
    {
      tw = &quic_main.wrk_ctx[thread_index].timer_wheel;
      tw_timer_stop_1t_3w_1024sl_ov (tw, ctx->timer_handle);
    }

  /*  Delete the connection from the connection map */
  conn = ctx->c_quic_ctx_id.conn;
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  QUIC_DBG (2, "Deleting conn with id %lu %lu", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 0 /* is_add */ );

  // session_close (session_get_from_handle (ctx->c_quic_ctx_id.udp_session_handle));
  quic_disconnect_transport (ctx);
  session_transport_delete_notify (&ctx->connection);
  /*  Do not try to send anything anymore */
  quicly_free (ctx->c_quic_ctx_id.conn);
  ctx->c_quic_ctx_id.conn = NULL;
  quic_ctx_free (ctx);
}

static void
allocate_quicly_ctx (application_t * app, u8 is_client)
{
  struct
  {
    quicly_context_t _;
    char cid_key[17];
  } *ctx_data;
  quicly_context_t *quicly_ctx;
  ptls_iovec_t key_vec;
  QUIC_DBG (2, "Called allocate_quicly_ctx");

  if (app->quicly_ctx)
    {
      QUIC_DBG (1, "Trying to reallocate quicly_ctx");
      return;
    }

  ctx_data = malloc (sizeof (*ctx_data));
  quicly_ctx = &ctx_data->_;
  app->quicly_ctx = (u64 *) quicly_ctx;
  memcpy (quicly_ctx, &quicly_spec_context, sizeof (quicly_context_t));

  quicly_ctx->max_packet_size = QUIC_MAX_PACKET_SIZE;
  quicly_ctx->tls = &quic_tlsctx;
  quicly_ctx->stream_open = &on_stream_open;
  quicly_ctx->closed_by_peer = &on_closed_by_peer;
  quicly_ctx->now = &quicly_vpp_now_cb;

  quicly_amend_ptls_context (quicly_ctx->tls);

  quicly_ctx->event_log.mask = 0;	/* logs */
  quicly_ctx->event_log.cb = quicly_new_default_event_logger (stderr);

  quicly_ctx->transport_params.max_data = QUIC_INT_MAX;
  quicly_ctx->transport_params.max_streams_uni = QUIC_INT_MAX;
  quicly_ctx->transport_params.max_streams_bidi = QUIC_INT_MAX;
  quicly_ctx->transport_params.max_stream_data.bidi_local = (QUIC_FIFO_SIZE - 1);	/* max_enq is SIZE - 1 */
  quicly_ctx->transport_params.max_stream_data.bidi_remote = (QUIC_FIFO_SIZE - 1);	/* max_enq is SIZE - 1 */
  quicly_ctx->transport_params.max_stream_data.uni = QUIC_INT_MAX;

  quicly_ctx->tls->random_bytes (ctx_data->cid_key, 16);
  ctx_data->cid_key[16] = 0;
  key_vec = ptls_iovec_init (ctx_data->cid_key, strlen (ctx_data->cid_key));
  quicly_ctx->cid_encryptor =
    quicly_new_default_cid_encryptor (&ptls_openssl_bfecb,
				      &ptls_openssl_sha256, key_vec);
  if (!is_client && app->tls_key != NULL && app->tls_cert != NULL)
    {
      load_bio_private_key (quicly_ctx->tls, (char *) app->tls_key);
      load_bio_certificate_chain (quicly_ctx->tls, (char *) app->tls_cert);
    }
}


/*****************************************************************************
 * BEGIN TIMERS HANDLING
 *****************************************************************************/

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
  next_timeout = quicly_get_first_timeout (ctx->c_quic_ctx_id.conn);
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
      ctx->timer_handle =
	tw_timer_start_1t_3w_1024sl_ov (tw, ctx->c_c_index, 0, next_interval);
    }
  else
    {
      if (next_timeout == INT64_MAX)
	{
	  tw_timer_stop_1t_3w_1024sl_ov (tw, ctx->timer_handle);
	  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
	  QUIC_DBG (4, "Stopping timer for ctx %u", ctx->c_c_index);
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


/*****************************************************************************
 * END TIMERS HANDLING
 *
 * BEGIN TRANSPORT PROTO FUNCTIONS
 *****************************************************************************/

static int
quic_connect (transport_endpoint_cfg_t * tep)
{
  QUIC_DBG (2, "Called quic_connect");
  session_endpoint_cfg_t *sep;
  int connect_stream = 0;

  sep = (session_endpoint_cfg_t *) tep;

  if (sep->port == 0)
    {
      /*  TODO: better logic to detect if this is a stream or a connection request */
      connect_stream = 1;
    }

  if (connect_stream)
    {
      return quic_connect_new_stream (sep);
    }
  else
    {
      return quic_connect_new_connection (sep);
    }
}

static int
quic_connect_new_stream (session_endpoint_cfg_t * sep)
{
  uint64_t quic_session_handle;
  session_t *quic_session, *stream_session;
  quic_stream_data_t *stream_data;
  quicly_stream_t *stream;
  quicly_conn_t *conn;
  app_worker_t *app_wrk;
  quic_ctx_t *qctx, *sctx;
  u32 sctx_index;
  quic_main_t *qm = &quic_main;
  int rv;

  /*  Find base session to which the user want to attach a stream */
  quic_session_handle = sep->transport_opts;
  QUIC_DBG (2, "Opening new stream (qsession %u)", sep->transport_opts);
  quic_session = session_get_from_handle (quic_session_handle);

  if (quic_session->session_type !=
      session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC, sep->is_ip4))
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
  qctx =
    quic_ctx_get (quic_session->connection_index, quic_session->thread_index);
  if (qctx->c_quic_ctx_id.is_stream)
    {
      QUIC_DBG (1, "session is a stream");
      quic_ctx_free (sctx);
      return -1;
    }

  sctx->c_quic_ctx_id.parent_app_wrk_id =
    qctx->c_quic_ctx_id.parent_app_wrk_id;
  sctx->c_quic_ctx_id.parent_app_id = qctx->c_quic_ctx_id.parent_app_id;
  sctx->c_quic_ctx_id.quic_connection_ctx_id = qctx->c_c_index;
  sctx->c_c_index = sctx_index;
  sctx->c_quic_ctx_id.is_stream = 1;

  conn = qctx->c_quic_ctx_id.conn;

  if (!conn || !quicly_connection_is_ready (conn))
    return -1;

  if ((rv = quicly_open_stream (conn, &stream, 0 /* uni */ )))
    {
      QUIC_DBG (2, "Stream open failed with %d", rv);
      return -1;
    }
  sctx->c_quic_ctx_id.stream = stream;

  QUIC_DBG (2, "Opened stream %d, creating session", stream->stream_id);

  stream_session = session_alloc (qctx->c_thread_index);
  QUIC_DBG (2, "Allocated stream_session, id %u, thread %u ctx %u",
	    stream_session->session_index, stream_session->thread_index,
	    sctx_index);
  stream_session->flags |= SESSION_F_QUIC_STREAM;
  stream_session->app_wrk_index = app_wrk->wrk_index;
  stream_session->connection_index = sctx_index;
  stream_session->listener_index = qm->fake_app_listener_index;
  stream_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC,
				    qctx->c_quic_ctx_id.udp_is_ip4);

  sctx->c_s_index = stream_session->session_index;

  if (app_worker_init_connected (app_wrk, stream_session))
    {
      QUIC_DBG (1, "failed to app_worker_init_connected");
      quicly_reset_stream (stream, 0x30003);
      session_free_w_fifos (stream_session);
      quic_ctx_free (sctx);
      return app_worker_connect_notify (app_wrk, NULL, sep->opaque);
    }

  stream_session->session_state = SESSION_STATE_READY;
  if (app_worker_connect_notify (app_wrk, stream_session, sep->opaque))
    {
      QUIC_DBG (1, "failed to notify app");
      quicly_reset_stream (stream, 0x30004);
      session_free_w_fifos (stream_session);
      quic_ctx_free (sctx);
      return -1;
    }
  session_lookup_add_connection (&sctx->connection,
				 session_handle (stream_session));
  stream_data = (quic_stream_data_t *) stream->data;
  stream_data->ctx_id = sctx->c_c_index;
  stream_data->thread_index = sctx->c_thread_index;
  return 0;
}

static int
quic_connect_new_connection (session_endpoint_cfg_t * sep)
{
  vnet_connect_args_t _cargs = { {}, }, *cargs = &_cargs;
  quic_main_t *qm = &quic_main;
  quic_ctx_t *ctx;
  app_worker_t *app_wrk;
  application_t *app;
  u32 ctx_index;
  int error;

  ctx_index = quic_ctx_alloc (vlib_get_thread_index ());
  ctx = quic_ctx_get (ctx_index, vlib_get_thread_index ());
  ctx->c_quic_ctx_id.parent_app_wrk_id = sep->app_wrk_index;
  ctx->c_s_index = QUIC_SESSION_INVALID;
  ctx->c_c_index = ctx_index;
  ctx->c_quic_ctx_id.udp_is_ip4 = sep->is_ip4;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  ctx->conn_state = QUIC_CONN_STATE_HANDSHAKE;
  ctx->client_opaque = sep->opaque;
  if (sep->hostname)
    {
      ctx->srv_hostname = format (0, "%v", sep->hostname);
      vec_terminate_c_string (ctx->srv_hostname);
    }
  else
    {
      /*  needed by quic for crypto + determining client / server */
      ctx->srv_hostname =
	format (0, "%U", format_ip46_address, &sep->ip, sep->is_ip4);
    }

  clib_memcpy (&cargs->sep, sep, sizeof (session_endpoint_cfg_t));
  cargs->sep.transport_proto = TRANSPORT_PROTO_UDPC;
  cargs->app_index = qm->app_index;
  cargs->api_context = ctx_index;

  app_wrk = app_worker_get (sep->app_wrk_index);
  app = application_get (app_wrk->app_index);
  ctx->c_quic_ctx_id.parent_app_id = app_wrk->app_index;
  cargs->sep_ext.ns_index = app->ns_index;

  allocate_quicly_ctx (app, 1 /* is client */ );

  if ((error = vnet_connect (cargs)))
    return error;

  return 0;
}

static void
quic_disconnect (u32 ctx_index, u32 thread_index)
{
  QUIC_DBG (2, "Called quic_disconnect");
  quic_ctx_t *ctx;

  ctx = quic_ctx_get (ctx_index, thread_index);
  if (ctx->c_quic_ctx_id.is_stream)
    {
      QUIC_DBG (2, "Closing stream %x, session %x", ctx_index,
		ctx->c_s_index);
      quicly_stream_t *stream = ctx->c_quic_ctx_id.stream;
      quicly_reset_stream (stream, 0x30000);
    }
  else
    {
      QUIC_DBG (2, "Closing connection %x, session %x", ctx_index,
		ctx->c_s_index);
      quicly_conn_t *conn = ctx->c_quic_ctx_id.conn;
      /* Start connection closing. Keep sending packets until quicly_send
         returns QUICLY_ERROR_FREE_CONNECTION */
      quicly_close (conn, 0, "");
      /* This also causes all streams to be closed (and the cb called) */
      quic_send_packets (ctx);
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

  sep = (session_endpoint_cfg_t *) tep;
  app_wrk = app_worker_get (sep->app_wrk_index);
  /* We need to call this because we call app_worker_init_connected in
   * quic_accept_stream, which assumes the connect segment manager exists */
  app_worker_alloc_connects_segment_manager (app_wrk);
  app = application_get (app_wrk->app_index);
  QUIC_DBG (2, "Called quic_start_listen for app %d", app_wrk->app_index);

  allocate_quicly_ctx (app, 0 /* is_client */ );

  sep->transport_proto = TRANSPORT_PROTO_UDPC;
  memset (args, 0, sizeof (*args));
  args->app_index = qm->app_index;
  args->sep_ext = *sep;
  args->sep_ext.ns_index = app->ns_index;
  if (vnet_listen (args))
    return -1;

  lctx_index = quic_ctx_alloc (0);	/*  listener */
  udp_handle = args->handle;
  app_listener = app_listener_get_w_handle (udp_handle);
  udp_listen_session = app_listener_get_session (app_listener);
  udp_listen_session->opaque = lctx_index;

  lctx = quic_ctx_get (lctx_index, 0);	/*  listener */
  lctx->is_listener = 1;
  lctx->c_quic_ctx_id.parent_app_wrk_id = sep->app_wrk_index;
  lctx->c_quic_ctx_id.parent_app_id = app_wrk->app_index;
  lctx->c_quic_ctx_id.udp_session_handle = udp_handle;
  lctx->c_quic_ctx_id.udp_is_ip4 = sep->is_ip4;
  lctx->c_s_index = quic_listen_session_index;

  QUIC_DBG (2, "Started listening %d", lctx_index);
  return lctx_index;
}

static u32
quic_stop_listen (u32 lctx_index)
{
  QUIC_DBG (2, "Called quic_stop_listen");
  quic_ctx_t *lctx;

  lctx = quic_ctx_get (lctx_index, 0);	/*  listener */
  vnet_unlisten_args_t a = {
    .handle = lctx->c_quic_ctx_id.udp_session_handle,
    .app_index = quic_main.app_index,
    .wrk_map_index = 0		/* default wrk */
  };
  if (vnet_unlisten (&a))
    clib_warning ("unlisten errored");

  /*  TODO: crypto state cleanup */

  quic_ctx_free (lctx);		/*  listener */
  return 0;
}

static transport_connection_t *
quic_connection_get (u32 ctx_index, u32 thread_index)
{
  QUIC_DBG (2, "Called quic_connection_get");
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

  if (!ctx)
    return s;
  s = format (s, "[#%d][%s] ", ctx->c_thread_index, "Q");

  if (ctx->is_listener)
    {
      s = format (s, "%s Listener: ", ctx->c_quic_ctx_id.is_stream ?
		  "Stream" : "QSession");
      if (verbose)
	s = format (s, "app %d wrk %d", ctx->c_quic_ctx_id.parent_app_id,
		    ctx->c_quic_ctx_id.parent_app_wrk_id);
    }
  else
    {
      if (ctx->c_is_ip4)
	s = format (s, "%U:%d->%U:%d", format_ip4_address, &ctx->c_lcl_ip4,
		    clib_net_to_host_u16 (ctx->c_lcl_port),
		    format_ip4_address, &ctx->c_rmt_ip4,
		    clib_net_to_host_u16 (ctx->c_rmt_port));
      else
	s = format (s, "%U:%d->%U:%d", format_ip6_address, &ctx->c_lcl_ip6,
		    clib_net_to_host_u16 (ctx->c_lcl_port),
		    format_ip6_address, &ctx->c_rmt_ip6,
		    clib_net_to_host_u16 (ctx->c_rmt_port));
    }
  return s;
}

static u8 *
format_quic_connection (u8 * s, va_list * args)
{
  u32 qc_index = va_arg (*args, u32);
  u32 thread_index = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, thread_index);
  if (ctx)
    s = format (s, "%-50U", format_quic_ctx, ctx, verbose);
  return s;
}

static u8 *
format_quic_half_open (u8 * s, va_list * args)
{
  u32 qc_index = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (qc_index, vlib_get_thread_index ());
  s = format (s, "[QUIC] half-open app %u", ctx->c_quic_ctx_id.parent_app_id);
  return s;
}

/*  TODO improve */
static u8 *
format_quic_listener (u8 * s, va_list * args)
{
  u32 tci = va_arg (*args, u32);
  u32 verbose = va_arg (*args, u32);
  quic_ctx_t *ctx = quic_ctx_get (tci, vlib_get_thread_index ());
  if (ctx)
    {
      ASSERT (ctx->is_listener);
      s = format (s, "%-50U", format_quic_ctx, ctx, verbose);
    }
  return s;
}

/*****************************************************************************
 * END TRANSPORT PROTO FUNCTIONS
 *
 * START SESSION CALLBACKS
 * Called from UDP layer
 *****************************************************************************/

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
quic_notify_app_connected (quic_ctx_t * ctx)
{
  QUIC_DBG (1, "quic_notify_app_connected");
  session_t *quic_session;
  app_worker_t *app_wrk;
  u32 ctx_id = ctx->c_c_index;
  u32 thread_index = ctx->c_thread_index;
  quic_main_t *qm = &quic_main;

  app_wrk = app_worker_get_if_valid (ctx->c_quic_ctx_id.parent_app_wrk_id);
  if (!app_wrk)
    {
      quic_disconnect_transport (ctx);
      return -1;
    }

  quic_session = session_alloc (thread_index);

  QUIC_DBG (2, "Allocated quic_session, id %u, thread %u",
	    quic_session->session_index, quic_session->thread_index);
  ctx->c_s_index = quic_session->session_index;
  quic_session->app_wrk_index = ctx->c_quic_ctx_id.parent_app_wrk_id;
  quic_session->connection_index = ctx->c_c_index;
  quic_session->listener_index = qm->fake_app_listener_index;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC,
				    ctx->c_quic_ctx_id.udp_is_ip4);

  if (app_worker_init_connected (app_wrk, quic_session))
    {
      QUIC_DBG (1, "failed to app_worker_init_connected");
      quic_disconnect (ctx_id, thread_index);
      return app_worker_connect_notify (app_wrk, NULL, ctx->client_opaque);
    }

  quic_session->session_state = SESSION_STATE_CONNECTING;
  if (app_worker_connect_notify (app_wrk, quic_session, ctx->client_opaque))
    {
      QUIC_DBG (1, "failed to notify app");
      quic_disconnect (ctx_id, thread_index);
      return -1;
    }

  /*  If the app opens a stream in its callback it may invalidate ctx */
  ctx = quic_ctx_get (ctx_id, thread_index);
  quic_session->session_state = SESSION_STATE_LISTENING;
  session_lookup_add_connection (&ctx->connection,
				 session_handle (quic_session));

  return 0;
}

static int
quic_session_connected_callback (u32 quic_app_index, u32 ctx_index,
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
  application_t *app;
  quic_ctx_t *ctx;
  u32 thread_index = vlib_get_thread_index ();
  int ret;

  ctx = quic_ctx_get (ctx_index, thread_index);
  if (is_fail)
    {
      u32 api_context;
      int rv = 0;

      app_wrk =
	app_worker_get_if_valid (ctx->c_quic_ctx_id.parent_app_wrk_id);
      if (app_wrk)
	{
	  api_context = ctx->c_s_index;
	  app_worker_connect_notify (app_wrk, 0, api_context);
	}
      return rv;
    }

  app_wrk = app_worker_get_if_valid (ctx->c_quic_ctx_id.parent_app_wrk_id);
  if (!app_wrk)
    {
      QUIC_DBG (1, "Appwrk not found");
      return -1;
    }
  app = application_get (app_wrk->app_index);

  ctx->c_thread_index = thread_index;
  ctx->c_c_index = ctx_index;

  QUIC_DBG (2, "Quic connect returned %u. New ctx [%u]%x",
	    is_fail, thread_index, (ctx) ? ctx_index : ~0);

  ctx->c_quic_ctx_id.udp_session_handle = session_handle (udp_session);
  udp_session->opaque = ctx->c_quic_ctx_id.parent_app_id;
  udp_session->session_state = SESSION_STATE_READY;

  /* Init QUIC lib connection
   * Generate required sockaddr & salen */
  tc = session_get_transport (udp_session);
  quic_build_sockaddr (sa, &salen, &tc->rmt_ip, tc->rmt_port, tc->is_ip4);

  ret =
    quicly_connect (&ctx->c_quic_ctx_id.conn,
		    (quicly_context_t *) app->quicly_ctx,
		    (char *) ctx->srv_hostname, sa, salen,
		    &quic_main.next_cid, &quic_main.hs_properties, NULL);
  ++quic_main.next_cid.master_id;
  /*  Save context handle in quicly connection */
  quic_store_conn_ctx (ctx->c_quic_ctx_id.conn, ctx);
  assert (ret == 0);

  /*  Register connection in connections map */
  conn = ctx->c_quic_ctx_id.conn;
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) ctx_index;
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 1 /* is_add */ );

  quic_send_packets (ctx);

  /*  UDP stack quirk? preemptively transfer connection if that happens */
  if (udp_session->thread_index != thread_index)
    quic_transfer_connection (ctx_index, udp_session->thread_index);

  return ret;
}

static void
quic_receive_connection (void *arg)
{
  u32 new_ctx_id, thread_index = vlib_get_thread_index ();
  quic_ctx_t *temp_ctx, *new_ctx;
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;

  temp_ctx = arg;
  new_ctx_id = quic_ctx_alloc (thread_index);
  new_ctx = quic_ctx_get (new_ctx_id, thread_index);

  QUIC_DBG (2, "Received conn %u (now %u)", temp_ctx->c_thread_index,
	    new_ctx_id);


  memcpy (new_ctx, temp_ctx, sizeof (quic_ctx_t));
  free (temp_ctx);

  new_ctx->c_thread_index = thread_index;
  new_ctx->c_c_index = new_ctx_id;

  conn = new_ctx->c_quic_ctx_id.conn;
  quic_store_conn_ctx (conn, new_ctx);
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) new_ctx_id;
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 1 /* is_add */ );
  new_ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  quic_update_timer (new_ctx);

  /*  Trigger read on this connection ? */
}

static void
quic_transfer_connection (u32 ctx_index, u32 dest_thread)
{
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  quic_ctx_t *ctx, *temp_ctx;
  clib_bihash_kv_16_8_t kv;
  quicly_conn_t *conn;
  u32 thread_index = vlib_get_thread_index ();

  QUIC_DBG (2, "Transferring conn %u to thread %u", ctx_index, dest_thread);

  temp_ctx = malloc (sizeof (quic_ctx_t));
  ASSERT (temp_ctx);
  ctx = quic_ctx_get (ctx_index, thread_index);

  memcpy (temp_ctx, ctx, sizeof (quic_ctx_t));

  /*  Remove from lookup hash, timer wheel and thread-local pool */
  conn = ctx->c_quic_ctx_id.conn;
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 0 /* is_add */ );
  if (ctx->timer_handle != QUIC_TIMER_HANDLE_INVALID)
    {
      tw = &quic_main.wrk_ctx[thread_index].timer_wheel;
      tw_timer_stop_1t_3w_1024sl_ov (tw, ctx->timer_handle);
    }
  quic_ctx_free (ctx);

  /*  Send connection to destination thread */
  session_send_rpc_evt_to_thread (dest_thread, quic_receive_connection,
				  (void *) temp_ctx);
}

static void
quic_transfer_connection_rpc (void *arg)
{
  u64 arg_int = (u64) arg;
  u32 ctx_index, dest_thread;

  ctx_index = (u32) (arg_int >> 32);
  dest_thread = (u32) (arg_int & UINT32_MAX);
  quic_transfer_connection (ctx_index, dest_thread);
}

/*
 * This assumes that the connection is not yet associated to a session
 * So currently it only works on the client side when receiving the first packet
 * from the server
 */
static void
quic_move_connection_to_thread (u32 ctx_index, u32 owner_thread,
				u32 to_thread)
{
  QUIC_DBG (2, "Requesting transfer of conn %u from thread %u", ctx_index,
	    owner_thread);
  u64 arg = ((u64) ctx_index) << 32 | to_thread;
  session_send_rpc_evt_to_thread (owner_thread, quic_transfer_connection_rpc,
				  (void *) arg);
}

static void
quic_session_disconnect_callback (session_t * s)
{
  clib_warning ("UDP session disconnected???");
}

static void
quic_session_reset_callback (session_t * s)
{
  clib_warning ("UDP session reset???");
}

int
quic_session_accepted_callback (session_t * udp_session)
{
  /* New UDP connection, try to accept it */
  QUIC_DBG (2, "UDP session accepted");
  u32 ctx_index;
  u32 *pool_index;
  quic_ctx_t *ctx, *lctx;
  session_t *udp_listen_session;
  u32 thread_index = vlib_get_thread_index ();

  udp_listen_session = listen_session_get (udp_session->listener_index);

  ctx_index = quic_ctx_alloc (thread_index);
  ctx = quic_ctx_get (ctx_index, thread_index);
  ctx->c_thread_index = udp_session->thread_index;
  ctx->c_c_index = ctx_index;
  ctx->c_s_index = QUIC_SESSION_INVALID;
  ctx->c_quic_ctx_id.udp_session_handle = session_handle (udp_session);
  ctx->c_quic_ctx_id.listener_ctx_id = udp_listen_session->opaque;
  lctx = quic_ctx_get (udp_listen_session->opaque,
		       udp_listen_session->thread_index);
  ctx->c_quic_ctx_id.udp_is_ip4 = lctx->c_quic_ctx_id.udp_is_ip4;
  ctx->c_quic_ctx_id.parent_app_id = lctx->c_quic_ctx_id.parent_app_id;
  ctx->c_quic_ctx_id.parent_app_wrk_id =
    lctx->c_quic_ctx_id.parent_app_wrk_id;
  ctx->timer_handle = QUIC_TIMER_HANDLE_INVALID;
  ctx->conn_state = QUIC_CONN_STATE_OPENED;

  udp_session->opaque = ctx->c_quic_ctx_id.parent_app_id;

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
  QUIC_DBG (2, "Called quic_add_segment_callback");
  QUIC_DBG (2, "NOT IMPLEMENTED");
  /* No-op for builtin */
  return 0;
}

static int
quic_del_segment_callback (u32 client_index, u64 seg_handle)
{
  QUIC_DBG (2, "Called quic_del_segment_callback");
  QUIC_DBG (2, "NOT IMPLEMENTED");
  /* No-op for builtin */
  return 0;
}

static int
quic_custom_tx_callback (void *s)
{
  session_t *stream_session = (session_t *) s;
  quicly_stream_t *stream;
  quic_ctx_t *ctx;
  int rv;

  svm_fifo_unset_event (stream_session->tx_fifo);
  if (PREDICT_FALSE
      (stream_session->session_state >= SESSION_STATE_TRANSPORT_CLOSING))
    return 0;
  ctx =
    quic_ctx_get (stream_session->connection_index,
		  stream_session->thread_index);
  if (PREDICT_FALSE (!ctx->c_quic_ctx_id.is_stream))
    {
      goto tx_end;		/* Most probably a reschedule */
    }

  stream = ctx->c_quic_ctx_id.stream;
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
      u8 thread_id = kv.value >> 32;
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
      conn_ = ctx_->c_quic_ctx_id.conn;
      if (conn_ && quicly_is_destination (conn_, sa, salen, packet))
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
quic_receive (quic_ctx_t * ctx, quicly_conn_t * conn,
	      quicly_decoded_packet_t packet)
{
  int rv;
  u32 ctx_id = ctx->c_c_index;
  u32 thread_index = ctx->c_thread_index;
  /* TODO : QUICLY_ERROR_PACKET_IGNORED sould be handled */
  rv = quicly_receive (conn, &packet);
  if (rv)
    {
      QUIC_DBG (2, "Quicly receive ignored packet code : %u", rv);
      return 0;
    }
  /* ctx pointer may change if a new stream is opened */
  ctx = quic_ctx_get (ctx_id, thread_index);
  /* Conn may be set to null if the connection is terminated */
  if (ctx->c_quic_ctx_id.conn && ctx->conn_state == QUIC_CONN_STATE_HANDSHAKE)
    {
      if (quicly_connection_is_ready (conn))
	{
	  ctx->conn_state = QUIC_CONN_STATE_READY;
	  if (quicly_is_client (conn))
	    {
	      quic_notify_app_connected (ctx);
	      ctx = quic_ctx_get (ctx_id, thread_index);
	    }
	}
    }
  return quic_send_packets (ctx);
}

static int
quic_create_quic_session (quic_ctx_t * ctx)
{
  session_t *quic_session;
  app_worker_t *app_wrk;
  quic_ctx_t *lctx;
  quic_main_t *qm = &quic_main;
  int rv;

  quic_session = session_alloc (ctx->c_thread_index);
  QUIC_DBG (2, "Allocated quic_session, id %u, thread %u ctx %u",
	    quic_session->session_index, quic_session->thread_index,
	    ctx->c_c_index);
  quic_session->session_state = SESSION_STATE_LISTENING;
  ctx->c_s_index = quic_session->session_index;

  lctx = quic_ctx_get (ctx->c_quic_ctx_id.listener_ctx_id, 0);

  quic_session->app_wrk_index = lctx->c_quic_ctx_id.parent_app_wrk_id;
  quic_session->connection_index = ctx->c_c_index;
  quic_session->session_type =
    session_type_from_proto_and_ip (TRANSPORT_PROTO_QUIC,
				    ctx->c_quic_ctx_id.udp_is_ip4);
  quic_session->listener_index = qm->fake_app_listener_index;
  quic_session->app_index = quic_main.app_index;

  /* TODO: don't alloc fifos when we don't transfer data on this session
   * but we still need fifos for the events? */
  if ((rv = app_worker_init_accepted (quic_session)))
    {
      QUIC_DBG (1, "failed to allocate fifos");
      session_free (quic_session);
      return rv;
    }
  session_lookup_add_connection (&ctx->connection,
				 session_handle (quic_session));
  app_wrk = app_worker_get (quic_session->app_wrk_index);
  rv = app_worker_accept_notify (app_wrk, quic_session);
  if (rv)
    {
      QUIC_DBG (1, "failed to notify accept worker app");
      return rv;
    }
  return 0;
}

static int
quic_create_connection (quicly_context_t * quicly_ctx,
			u64 udp_session_handle, u32 ctx_index,
			struct sockaddr *sa,
			socklen_t salen, quicly_decoded_packet_t packet)
{
  clib_bihash_kv_16_8_t kv;
  quic_ctx_t *ctx;
  quicly_conn_t *conn;
  u32 thread_index = vlib_get_thread_index ();
  int rv;

  /* new connection, accept and create context if packet is valid
   * TODO: check if socket is actually listening? */
  if ((rv = quicly_accept (&conn, quicly_ctx, sa, salen,
			   &packet, ptls_iovec_init (NULL, 0),
			   &quic_main.next_cid, NULL)))
    {
      /* Invalid packet, pass */
      assert (conn == NULL);
      QUIC_DBG (1, "Accept failed with %d", rv);
      /* TODO: cleanup created quic ctx and UDP session */
      return 0;
    }
  assert (conn != NULL);

  ++quic_main.next_cid.master_id;
  ctx = quic_ctx_get (ctx_index, thread_index);
  /* Save ctx handle in quicly connection */
  quic_store_conn_ctx (conn, ctx);
  ctx->c_quic_ctx_id.conn = conn;
  ctx->conn_state = QUIC_CONN_STATE_HANDSHAKE;

  quic_create_quic_session (ctx);

  /* Register connection in connections map */
  quic_make_connection_key (&kv, quicly_get_master_id (conn));
  kv.value = ((u64) thread_index) << 32 | (u64) ctx_index;
  clib_bihash_add_del_16_8 (&quic_main.connection_hash, &kv, 1 /* is_add */ );
  QUIC_DBG (2, "Registering conn with id %lu %lu", kv.key[0], kv.key[1]);

  return quic_send_packets (ctx);
}

static int
quic_reset_connection (quicly_context_t * quicly_ctx, u64 udp_session_handle,
		       struct sockaddr *sa, socklen_t salen,
		       quicly_decoded_packet_t packet)
{
  /* short header packet; potentially a dead connection. No need to check the
   * length of the incoming packet, because loop is prevented by authenticating
   * the CID (by checking node_id and thread_id). If the peer is also sending a
   * reset, then the next CID is highly likely to contain a non-authenticating
   * CID, ... */
  QUIC_DBG (2, "Sending stateless reset");
  quicly_datagram_t *dgram;
  session_t *udp_session;
  if (packet.cid.dest.plaintext.node_id == 0
      && packet.cid.dest.plaintext.thread_id == 0)
    {
      dgram = quicly_send_stateless_reset (quicly_ctx, sa, salen,
					   &packet.cid.dest.plaintext);
      if (dgram == NULL)
	return 1;
      udp_session = session_get_from_handle (udp_session_handle);
      return quic_send_datagram (udp_session, dgram);	/*  TODO : set event on fifo */
    }
  return 0;
}

static int
quic_app_rx_callback (session_t * udp_session)
{
  /*  Read data from UDP rx_fifo and pass it to the quicly conn. */
  quicly_decoded_packet_t packet;
  session_dgram_hdr_t ph;
  application_t *app;
  quic_ctx_t *ctx = NULL;
  svm_fifo_t *f;
  size_t plen;
  struct sockaddr_in6 sa6;
  struct sockaddr *sa = (struct sockaddr *) &sa6;
  socklen_t salen;
  u32 max_deq, len, full_len, ctx_index = UINT32_MAX, ctx_thread =
    UINT32_MAX, ret;
  u8 *data;
  int err;
  u32 *opening_ctx_pool, *ctx_index_ptr;
  u32 app_index = udp_session->opaque;
  u64 udp_session_handle = session_handle (udp_session);
  int rv = 0;
  u32 thread_index = vlib_get_thread_index ();

  app = application_get_if_valid (app_index);
  if (!app)
    {
      QUIC_DBG (1, "Got RX on detached app");
      /*  TODO: close this session, cleanup state? */
      return 1;
    }

  do
    {
      udp_session = session_get_from_handle (udp_session_handle);	/*  session alloc might have happened */
      f = udp_session->rx_fifo;
      svm_fifo_unset_event (f);
      max_deq = svm_fifo_max_dequeue (f);
      if (max_deq < sizeof (session_dgram_hdr_t))
	return 0;

      ret = svm_fifo_peek (f, 0, SESSION_CONN_HDR_LEN, (u8 *) & ph);
      if (ret != SESSION_CONN_HDR_LEN)
	{
	  QUIC_DBG (1, "Not enough data for header in RX");
	  return 1;
	}
      if (ph.data_length < ph.data_offset)
	{
	  QUIC_DBG (1, "Not enough data vs offset in RX");
	  return 1;
	}
      len = ph.data_length - ph.data_offset;
      full_len = ph.data_length + ph.data_offset + SESSION_CONN_HDR_LEN;
      if (full_len > max_deq)
	{
	  QUIC_DBG (1, "Not enough data in fifo RX");
	  return 1;
	}

      /* Quicly can read len bytes from the fifo at offset:
       * ph.data_offset + SESSION_CONN_HDR_LEN */
      data = malloc (ph.data_length);
      ret =
	svm_fifo_peek (f, ph.data_offset + SESSION_CONN_HDR_LEN,
		       ph.data_length, data);
      if (ret != ph.data_length)
	{
	  QUIC_DBG (1, "Not enough data peeked in RX");
	  free (data);
	  return 1;
	}

      plen =
	quicly_decode_packet ((quicly_context_t *) app->quicly_ctx, &packet,
			      data, len);

      rv = 0;
      quic_build_sockaddr (sa, &salen, &ph.rmt_ip, ph.rmt_port, ph.is_ip4);
      plen =
	quicly_decode_packet ((quicly_context_t *) app->quicly_ctx, &packet,
			      data, len);

      if (plen != SIZE_MAX)
	{

	  err = quic_find_packet_ctx (&ctx_thread, &ctx_index, sa, salen,
				      &packet, thread_index);
	  if (err == 0)
	    {
	      ctx = quic_ctx_get (ctx_index, thread_index);
	      quic_receive (ctx, ctx->c_quic_ctx_id.conn, packet);
	    }
	  else if (ctx_thread != UINT32_MAX)
	    {
	      /*  Connection found but on wrong thread, ask move */
	      quic_move_connection_to_thread (ctx_index, ctx_thread,
					      thread_index);
	    }
	  else if ((packet.octets.base[0] & QUICLY_PACKET_TYPE_BITMASK) ==
		   QUICLY_PACKET_TYPE_INITIAL)
	    {
	      /*  Try to find matching "opening" ctx */
	      opening_ctx_pool =
		quic_main.wrk_ctx[thread_index].opening_ctx_pool;

              /* *INDENT-OFF* */
              pool_foreach (ctx_index_ptr, opening_ctx_pool,
              ({
                ctx = quic_ctx_get (*ctx_index_ptr, thread_index);
                if (ctx->c_quic_ctx_id.udp_session_handle == udp_session_handle)
                  {
                    /*  Right ctx found, create conn & remove from pool */
                    quic_create_connection ((quicly_context_t *) app->quicly_ctx,
                                            udp_session_handle, *ctx_index_ptr,
                                            sa, salen, packet);
                    pool_put (opening_ctx_pool, ctx_index_ptr);
                    goto ctx_search_done;
                  }
              }));
              /* *INDENT-ON* */

	    }
	  else
	    {
	      quic_reset_connection ((quicly_context_t *) app->quicly_ctx,
				     udp_session_handle, sa, salen, packet);
	    }
	}
    ctx_search_done:
      svm_fifo_dequeue_drop (f,
			     ph.data_length + ph.data_offset +
			     SESSION_CONN_HDR_LEN);
      free (data);
    }
  while (1);
  return rv;
}

always_inline void
quic_common_get_transport_endpoint (quic_ctx_t * ctx,
				    transport_endpoint_t * tep, u8 is_lcl)
{
  session_t *udp_session;
  if (ctx->c_quic_ctx_id.is_stream)
    {
      tep->is_ip4 = 255;	/* well this is ugly */
    }
  else
    {
      udp_session =
	session_get_from_handle (ctx->c_quic_ctx_id.udp_session_handle);
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
  if (ctx->is_listener)
    {
      app_listener =
	app_listener_get_w_handle (ctx->c_quic_ctx_id.udp_session_handle);
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

/*****************************************************************************
 * END TRANSPORT PROTO FUNCTIONS
*****************************************************************************/

/* *INDENT-OFF* */
static session_cb_vft_t quic_app_cb_vft = {
  .session_accept_callback = quic_session_accepted_callback,
  .session_disconnect_callback = quic_session_disconnect_callback,
  .session_connected_callback = quic_session_connected_callback,
  .session_reset_callback = quic_session_reset_callback,
  .add_segment_callback = quic_add_segment_callback,
  .del_segment_callback = quic_del_segment_callback,
  .builtin_app_rx_callback = quic_app_rx_callback,
};

static const transport_proto_vft_t quic_proto = {
  .connect = quic_connect,
  .close = quic_disconnect,
  .start_listen = quic_start_listen,
  .stop_listen = quic_stop_listen,
  .get_connection = quic_connection_get,
  .get_listener = quic_listener_get,
  .update_time = quic_update_time,
  .custom_tx = quic_custom_tx_callback,
  .tx_type = TRANSPORT_TX_INTERNAL,
  .service_type = TRANSPORT_SERVICE_APP,
  .format_connection = format_quic_connection,
  .format_half_open = format_quic_half_open,
  .format_listener = format_quic_listener,
  .get_transport_endpoint = quic_get_transport_endpoint,
  .get_transport_listener_endpoint = quic_get_transport_listener_endpoint,
};
/* *INDENT-ON* */

static clib_error_t *
quic_init (vlib_main_t * vm)
{
  u32 add_segment_size = (4096ULL << 20) - 1, segment_size = 512 << 20;
  vlib_thread_main_t *vtm = vlib_get_thread_main ();
  tw_timer_wheel_1t_3w_1024sl_ov_t *tw;
  vnet_app_attach_args_t _a, *a = &_a;
  u64 options[APP_OPTIONS_N_OPTIONS];
  quic_main_t *qm = &quic_main;
  u32 fifo_size = QUIC_FIFO_SIZE;
  u32 num_threads, i;
  application_t *app;

  num_threads = 1 /* main thread */  + vtm->n_threads;

  memset (a, 0, sizeof (*a));
  memset (options, 0, sizeof (options));

  a->session_cb_vft = &quic_app_cb_vft;
  a->api_client_index = APP_INVALID_INDEX;
  a->options = options;
  a->name = format (0, "quic");
  a->options[APP_OPTIONS_SEGMENT_SIZE] = segment_size;
  a->options[APP_OPTIONS_ADD_SEGMENT_SIZE] = add_segment_size;
  a->options[APP_OPTIONS_RX_FIFO_SIZE] = fifo_size;
  a->options[APP_OPTIONS_TX_FIFO_SIZE] = fifo_size;
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

  if (!qm->ca_cert_path)
    qm->ca_cert_path = QUIC_DEFAULT_CA_CERT_PATH;

  qm->app_index = a->app_index;

  /*  Fake app listener hack, to remove */
  app = application_get (a->app_index);
  app_listener_t *fake_app_listener;
  pool_get (app->listeners, fake_app_listener);
  clib_memset (fake_app_listener, 0, sizeof (*fake_app_listener));
  fake_app_listener->al_index = fake_app_listener - app->listeners;
  fake_app_listener->app_index = app->app_index;
  fake_app_listener->session_index = SESSION_INVALID_INDEX;
  fake_app_listener->local_index = SESSION_INVALID_INDEX;
  qm->fake_app_listener_index = fake_app_listener->al_index;
  /* End fake listener hack */

  qm->tstamp_ticks_per_clock = vm->clib_time.seconds_per_clock
    / QUIC_TSTAMP_RESOLUTION;

  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP4, ~0);
  transport_register_protocol (TRANSPORT_PROTO_QUIC, &quic_proto,
			       FIB_PROTOCOL_IP6, ~0);

  vec_free (a->name);
  return 0;
}

VLIB_INIT_FUNCTION (quic_init);

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
{
  .version = VPP_BUILD_VER,
  .description = "Quic transport protocol",
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
