/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <hs_apps/builtin_echo/echo_test.h>

echo_test_main_t echo_test_main;

#define ET_MAX_RX_RETRIES 500000

static_always_inline void
et_test_bytes (u8 *rx_buf, int actual_transfer, u32 offset)
{
  int i;
  for (i = 0; i < actual_transfer; i++)
    {
      if (rx_buf[i] != ((offset + i) & 0xff))
	{
	  et_err ("at %lld expected %d got %d", offset + i, (offset + i) & 0xff, rx_buf[i]);
	}
    }
}

static u32
et_connected (session_t *s, echo_test_cfg_t *cfg, echo_test_worker_t *wrk, u32 app_index)
{
  echo_test_session_t *es;
  es = echo_test_session_alloc (wrk);
  hs_test_app_session_init (es, s);

  es->bytes_to_send = cfg->bytes_to_send;
  es->bytes_to_receive = cfg->echo_bytes ? cfg->bytes_to_send : 0ULL;
  es->vpp_session_handle = session_handle (s);
  es->vpp_session_index = s->session_index;
  es->bytes_paced_target = ~0;
  es->bytes_paced_current = ~0;
  s->opaque = es->session_index;

  vec_add1 (wrk->conn_indices, es->session_index);

  return 1;
}

static int
et_tcp_listen (vnet_listen_args_t *args, echo_test_cfg_t *cfg)
{
  return vnet_listen (args);
}

always_inline int
et_server_stream_rx_inline (echo_test_session_t *es, session_t *s, u8 *rx_buf, u8 test_bytes)
{
  u32 max_dequeue, max_enqueue, max_transfer;
  int actual_transfer;
  clib_thread_index_t thread_index = s->thread_index;
  svm_fifo_t *tx_fifo, *rx_fifo;

  rx_fifo = s->rx_fifo;
  tx_fifo = s->tx_fifo;

  ASSERT (rx_fifo->master_thread_index == thread_index);
  ASSERT (tx_fifo->master_thread_index == thread_index);

  max_enqueue = svm_fifo_max_enqueue_prod (tx_fifo);
  max_dequeue = svm_fifo_max_dequeue_cons (rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    return 0;

  /* Number of bytes we're going to copy */
  max_transfer = clib_min (max_dequeue, max_enqueue);

  /* No space in tx fifo */
  if (PREDICT_FALSE (max_transfer == 0))
    {
    rx_event:
      /* Program self-tap to retry */
      if (svm_fifo_set_event (rx_fifo))
	{
	  if (session_enqueue_notify (s))
	    et_err ("failed to enqueue self-tap");

	  if (es->rx_retries == 500000)
	    {
	      et_err ("session stuck: %U", format_session, s, 2);
	    }
	  if (es->rx_retries < 500001)
	    es->rx_retries++;
	}

      return 0;
    }

  vec_validate (rx_buf, max_transfer);
  actual_transfer = app_recv_stream ((app_session_t *) es, rx_buf, max_transfer);
  ASSERT (actual_transfer == max_transfer);

  if (test_bytes)
    {
      et_test_bytes (rx_buf, actual_transfer, es->byte_index);
      es->byte_index += actual_transfer;
    }

  /* Echo back */
  actual_transfer = app_send_stream ((app_session_t *) es, rx_buf, max_transfer, 0);
  if (PREDICT_FALSE (actual_transfer != max_transfer))
    et_err ("short trout! written %d read %u", actual_transfer, max_transfer);

  if (PREDICT_FALSE (svm_fifo_max_dequeue_cons (rx_fifo)))
    goto rx_event;

  return 0;
}

static int
et_server_stream_rx (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_server_stream_rx_inline (es, s, rx_buf, 0);
}

static int
et_server_stream_rx_test_bytes (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_server_stream_rx_inline (es, s, rx_buf, 1);
}

static int
et_tcp_connect (vnet_connect_args_t *a, echo_test_cfg_t *cfg)
{
  return vnet_connect (a);
}

static echo_test_proto_vft_t echo_test_tcp = {
  .listen = et_tcp_listen,
  .server_rx = et_server_stream_rx,
  .server_rx_test_bytes = et_server_stream_rx_test_bytes,
  .connect = et_tcp_connect,
  .connected = et_connected,
};

ECHO_TEST_REGISTER_PROTO (TRANSPORT_PROTO_TCP, echo_test_tcp);

static int
et_udp_listen (vnet_listen_args_t *args, echo_test_cfg_t *cfg)
{
  args->sep_ext.transport_flags = TRANSPORT_CFG_F_CONNECTED;
  return vnet_listen (args);
}

always_inline int
et_server_dgram_rx (echo_test_session_t *es, session_t *s, u8 *rx_buf, u8 test_bytes)
{
  u32 max_dequeue, max_enqueue, max_transfer;
  int actual_transfer;
  clib_thread_index_t thread_index = s->thread_index;
  svm_fifo_t *tx_fifo, *rx_fifo;
  session_dgram_pre_hdr_t ph;

  rx_fifo = s->rx_fifo;
  tx_fifo = s->tx_fifo;

  ASSERT (rx_fifo->master_thread_index == thread_index);
  ASSERT (tx_fifo->master_thread_index == thread_index);

  max_enqueue = svm_fifo_max_enqueue_prod (tx_fifo);

  svm_fifo_peek (rx_fifo, 0, sizeof (ph), (u8 *) &ph);
  max_dequeue = ph.data_length - ph.data_offset;
  if (PREDICT_FALSE (max_dequeue == 0))
    return 0;
  max_enqueue -= sizeof (session_dgram_hdr_t);

  /* Number of bytes we're going to copy */
  max_transfer = clib_min (max_dequeue, max_enqueue);

  /* No space in tx fifo */
  if (PREDICT_FALSE (max_transfer == 0))
    {
    rx_event:
      /* Program self-tap to retry */
      if (svm_fifo_set_event (rx_fifo))
	{
	  if (session_enqueue_notify (s))
	    et_err ("failed to enqueue self-tap");

	  if (es->rx_retries == 500000)
	    {
	      et_err ("session stuck: %U", format_session, s, 2);
	    }
	  if (es->rx_retries < 500001)
	    es->rx_retries++;
	}

      return 0;
    }

  vec_validate (rx_buf, max_transfer);
  actual_transfer = app_recv_dgram ((app_session_t *) es, rx_buf, max_transfer);
  ASSERT (actual_transfer == max_transfer);

  if (test_bytes)
    {
      /* Sanity check, in case of a broken dgram */
      if (actual_transfer < sizeof (u32) + 1)
	return 0;
      et_test_bytes ((rx_buf + sizeof (u32)), actual_transfer - sizeof (u32), *(u32 *) rx_buf);
    }

  /* Echo back */
  actual_transfer = app_send_dgram ((app_session_t *) es, rx_buf, max_transfer, 0);
  if (PREDICT_FALSE (actual_transfer != max_transfer))
    et_err ("short trout! written %d read %u", actual_transfer, max_transfer);

  if (PREDICT_FALSE (svm_fifo_max_dequeue_cons (rx_fifo)))
    goto rx_event;

  return 0;
}

static int
et_udp_server_rx (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_server_dgram_rx (es, s, rx_buf, 0);
}

static int
et_udp_server_rx_test_bytes (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_server_dgram_rx (es, s, rx_buf, 1);
}

static int
et_udp_connect (vnet_connect_args_t *a, echo_test_cfg_t *cfg)
{
  return vnet_connect (a);
}

static echo_test_proto_vft_t echo_test_udp = {
  .listen = et_udp_listen,
  .server_rx = et_udp_server_rx,
  .server_rx_test_bytes = et_udp_server_rx_test_bytes,
  .connect = et_udp_connect,
  .connected = et_connected,
};

ECHO_TEST_REGISTER_PROTO (TRANSPORT_PROTO_UDP, echo_test_udp);

static int
et_tls_listen (vnet_listen_args_t *args, echo_test_cfg_t *cfg)
{
  transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
    &args->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO, sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = cfg->ckpair_index;
  int rv = vnet_listen (args);
  session_endpoint_free_ext_cfgs (&args->sep_ext);
  return rv;
}

static int
et_tls_connect (vnet_connect_args_t *args, echo_test_cfg_t *cfg)
{
  transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
    &args->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO, sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = cfg->ckpair_index;
  ext_cfg->crypto.ca_trust_index = cfg->ca_trust_index;
  int rv = vnet_connect (args);
  session_endpoint_free_ext_cfgs (&args->sep_ext);
  return rv;
}

static echo_test_proto_vft_t echo_test_tls = {
  .listen = et_tls_listen,
  .server_rx = et_server_stream_rx,
  .server_rx_test_bytes = et_server_stream_rx_test_bytes,
  .connect = et_tls_connect,
  .connected = et_connected,
};

ECHO_TEST_REGISTER_PROTO (TRANSPORT_PROTO_TLS, echo_test_tls);

static int
et_quic_listen (vnet_listen_args_t *args, echo_test_cfg_t *cfg)
{
  transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
    &args->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO, sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = cfg->ckpair_index;
  int rv = vnet_listen (args);
  session_endpoint_free_ext_cfgs (&args->sep_ext);
  return rv;
}

always_inline int
et_quic_server_rx_inline (echo_test_session_t *es, session_t *s, u8 *rx_buf, u8 test_bytes)
{
  u32 max_dequeue, max_enqueue, max_transfer;
  int actual_transfer;
  clib_thread_index_t thread_index = s->thread_index;
  svm_fifo_t *tx_fifo, *rx_fifo;

  rx_fifo = s->rx_fifo;
  tx_fifo = s->tx_fifo;

  ASSERT (rx_fifo->master_thread_index == thread_index);
  ASSERT (tx_fifo->master_thread_index == thread_index);

  max_enqueue = svm_fifo_max_enqueue_prod (tx_fifo);
  max_dequeue = svm_fifo_max_dequeue_cons (rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    return 0;

  /* Number of bytes we're going to copy */
  max_transfer = clib_min (max_dequeue, max_enqueue);

  /* No space in tx fifo */
  if (PREDICT_FALSE (max_transfer == 0))
    {
    rx_event:
      /* Program self-tap to retry */
      if (svm_fifo_set_event (rx_fifo))
	{
	  /* NOTE: session_enqueue_notify() do not work with quic */
	  if (session_program_transport_io_evt (s->handle, SESSION_IO_EVT_BUILTIN_RX))
	    et_err ("failed to enqueue self-tap");

	  if (es->rx_retries == 500000)
	    {
	      et_err ("session stuck: %U", format_session, s, 2);
	    }
	  if (es->rx_retries < 500001)
	    es->rx_retries++;
	}

      return 0;
    }

  vec_validate (rx_buf, max_transfer);
  actual_transfer = app_recv_stream ((app_session_t *) es, rx_buf, max_transfer);
  ASSERT (actual_transfer == max_transfer);
  if (svm_fifo_needs_deq_ntf (rx_fifo, actual_transfer))
    {
      svm_fifo_clear_deq_ntf (rx_fifo);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }

  if (test_bytes)
    {
      et_test_bytes (rx_buf, actual_transfer, es->byte_index);
      es->byte_index += actual_transfer;
    }

  /* Echo back */
  actual_transfer = app_send_stream ((app_session_t *) es, rx_buf, max_transfer, 0);
  if (PREDICT_FALSE (actual_transfer != max_transfer))
    et_err ("short trout! written %d read %u", actual_transfer, max_transfer);

  if (PREDICT_FALSE (svm_fifo_max_dequeue_cons (rx_fifo)))
    goto rx_event;

  return 0;
}

static int
et_quic_server_rx (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_quic_server_rx_inline (es, s, rx_buf, 0);
}

static int
et_quic_server_rx_test_bytes (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_server_stream_rx_inline (es, s, rx_buf, 1);
}

static int
et_quic_connect (vnet_connect_args_t *args, echo_test_cfg_t *cfg)
{
  transport_endpt_ext_cfg_t *ext_cfg = session_endpoint_add_ext_cfg (
    &args->sep_ext, TRANSPORT_ENDPT_EXT_CFG_CRYPTO, sizeof (transport_endpt_crypto_cfg_t));
  ext_cfg->crypto.ckpair_index = cfg->ckpair_index;
  ext_cfg->crypto.ca_trust_index = cfg->ca_trust_index;
  int rv = vnet_connect (args);
  session_endpoint_free_ext_cfgs (&args->sep_ext);
  return rv;
}

static u32
et_quic_connected (session_t *s, echo_test_cfg_t *cfg, echo_test_worker_t *wrk, u32 app_index)
{
  echo_test_session_t *es;
  session_endpoint_cfg_t sep = SESSION_ENDPOINT_CFG_NULL;
  vnet_connect_args_t _a, *a = &_a;
  session_t *stream_session;
  u32 stream_n;
  int rv;

  ASSERT (s->listener_handle == SESSION_INVALID_HANDLE);
  ASSERT (!(s->flags & SESSION_F_STREAM));

  clib_memset (a, 0, sizeof (*a));
  a->app_index = app_index;
  sep.parent_handle = session_handle (s);
  sep.transport_proto = TRANSPORT_PROTO_QUIC;
  clib_memcpy (&a->sep_ext, &sep, sizeof (sep));

  for (stream_n = 0; stream_n < cfg->n_streams; stream_n++)
    {
      es = echo_test_session_alloc (wrk);
      a->api_context = es->session_index;
      if ((rv = vnet_connect_stream (a)))
	{
	  et_err ("Stream session #%d opening failed: %U", stream_n, format_session_error, rv);
	  break;
	}
      stream_session = session_get_from_handle (a->sh);
      hs_test_app_session_init (es, stream_session);
      es->bytes_to_send = cfg->bytes_to_send;
      es->bytes_to_receive = cfg->echo_bytes ? cfg->bytes_to_send : 0ULL;
      es->vpp_session_handle = a->sh;
      es->vpp_session_index = stream_session->session_index;
      vec_add1 (wrk->conn_indices, es->session_index);
    }

  return stream_n;
}

static echo_test_proto_vft_t echo_test_quic = {
  .listen = et_quic_listen,
  .server_rx = et_quic_server_rx,
  .server_rx_test_bytes = et_quic_server_rx_test_bytes,
  .connect = et_quic_connect,
  .connected = et_quic_connected,
};

ECHO_TEST_REGISTER_PROTO (TRANSPORT_PROTO_QUIC, echo_test_quic);
