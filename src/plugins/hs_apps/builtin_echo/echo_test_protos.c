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
  es->bytes_paced_target = ~0;
  es->bytes_paced_current = ~0;
  s->opaque = es->session_index;

  vec_add1 (wrk->conn_indices, es->session_index);

  return 1;
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

  ASSERT (vec_len (rx_buf) >= max_transfer);
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

always_inline u8
et_client_stream_rx_inline (echo_test_session_t *es, session_t *s, u8 *rx_buf, u8 test_bytes)
{
  u32 max_dequeue, test_buf_offset;
  int n_read, i;
  svm_fifo_t *rx_fifo;
  u8 *rx_buf_start;

  rx_fifo = es->rx_fifo;
  rx_buf_start = rx_buf;
  test_buf_offset = es->bytes_received;

  max_dequeue = svm_fifo_max_dequeue_cons (rx_fifo);
  if (PREDICT_FALSE (max_dequeue == 0))
    return 0;

  if (test_bytes)
    {
      n_read = app_recv_stream ((app_session_t *) es, rx_buf, vec_len (rx_buf));
      for (i = 0; i < n_read; i++)
	{
	  if (rx_buf_start[i] != ((test_buf_offset + i) & 0xff))
	    {
	      et_err ("read %d error at byte %lld, 0x%x not 0x%x", n_read, test_buf_offset + i,
		      rx_buf_start[i], ((test_buf_offset + i) & 0xff));
	      return 1;
	    }
	}
    }
  else
    {
      svm_fifo_dequeue_drop (rx_fifo, max_dequeue);
      n_read = (int) max_dequeue;
    }

  if (svm_fifo_needs_deq_ntf (rx_fifo, n_read))
    {
      svm_fifo_clear_deq_ntf (rx_fifo);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }

  if (PREDICT_FALSE (n_read > es->bytes_to_receive))
    {
      et_err ("expected %llu, received %llu bytes!", es->bytes_received + es->bytes_to_receive,
	      es->bytes_received + n_read);
      es->bytes_to_receive = 0;
      es->bytes_received += n_read;
      return 1;
    }
  es->bytes_to_receive -= n_read;
  es->bytes_received += n_read;

  return 0;
}

static u8
et_client_stream_rx (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_client_stream_rx_inline (es, s, rx_buf, 0);
}

static u8
et_client_stream_rx_test_bytes (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_client_stream_rx_inline (es, s, rx_buf, 0);
}

static u32
et_client_stream_tx (echo_test_session_t *es, u32 max_send)
{
  svm_fifo_t *f = es->tx_fifo;
  u32 to_send, max_enq;
  int rv;

  rv = svm_fifo_fill_chunk_list (f);
  if (rv < 0)
    return 0;

  max_enq = svm_fifo_max_enqueue_prod (f);
  if (max_enq == 0)
    return 0;

  to_send = clib_min (max_enq, max_send);
  svm_fifo_enqueue_nocopy (f, to_send);
  session_program_tx_io_evt (es->vpp_session_handle, SESSION_IO_EVT_TX);
  es->bytes_sent += to_send;
  return to_send;
}

static u32
et_client_stream_tx_test_bytes (echo_test_session_t *es, u8 *test_data, u32 max_send)
{
  u32 test_buf_len, test_buf_offset, n_sent;
  int rv;

  test_buf_len = vec_len (test_data);
  ASSERT (test_buf_len > 0);
  test_buf_offset = es->bytes_sent % test_buf_len;

  rv = app_send_stream ((app_session_t *) es, test_data + test_buf_offset, max_send, 0);
  n_sent = clib_max (rv, 0);
  es->bytes_sent += n_sent;
  return n_sent;
}

static int
et_tcp_listen (vnet_listen_args_t *args, echo_test_cfg_t *cfg)
{
  return vnet_listen (args);
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
  .client_rx = et_client_stream_rx,
  .client_rx_test_bytes = et_client_stream_rx_test_bytes,
  .client_tx = et_client_stream_tx,
  .client_tx_test_bytes = et_client_stream_tx_test_bytes,
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

  ASSERT (vec_len (rx_buf) >= max_transfer);
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

always_inline u8
et_client_dgram_rx_inline (echo_test_session_t *es, session_t *s, u8 *rx_buf, u8 test_bytes)
{
  u32 test_buf_offset;
  int n_read, i;
  svm_fifo_t *rx_fifo;
  u8 *rx_buf_start;

  rx_fifo = es->rx_fifo;

  n_read = app_recv_dgram ((app_session_t *) es, rx_buf, vec_len (rx_buf));
  if (PREDICT_FALSE (n_read <= 0))
    return 0;

  test_buf_offset = *(u32 *) rx_buf;
  n_read -= sizeof (u32);
  es->dgrams_received++;

  if (!(es->rtt_stat & ET_UDP_RTT_RX_FLAG) && test_buf_offset == es->rtt_udp_buffer_offset)
    {
      es->rtt_stat |= ET_UDP_RTT_RX_FLAG;
      f64 rtt = vlib_time_now (vlib_get_main ()) - es->send_rtt;
      es->jitter = clib_abs (rtt * 1000 - es->rtt * 1000);
      es->rtt = rtt;
    }

  if (test_bytes)
    {
      rx_buf_start = rx_buf + sizeof (u32);
      for (i = 0; i < n_read; i++)
	{
	  if (rx_buf_start[i] != ((test_buf_offset + i) & 0xff))
	    {
	      et_err ("read %d error at byte %lld, 0x%x not 0x%x", n_read, test_buf_offset + i,
		      rx_buf_start[i], ((test_buf_offset + i) & 0xff));
	      return 1;
	    }
	}
    }

  if (svm_fifo_needs_deq_ntf (rx_fifo, n_read))
    {
      svm_fifo_clear_deq_ntf (rx_fifo);
      session_program_transport_io_evt (s->handle, SESSION_IO_EVT_RX);
    }

  if (PREDICT_FALSE (n_read > es->bytes_to_receive))
    {
      et_err ("expected %llu, received %llu bytes!", es->bytes_received + es->bytes_to_receive,
	      es->bytes_received + n_read);
      es->bytes_to_receive = 0;
      es->bytes_received += n_read;
      return 1;
    }
  es->bytes_to_receive -= n_read;
  es->bytes_received += n_read;

  return 0;
}

static u8
et_client_dgram_rx (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_client_dgram_rx_inline (es, s, rx_buf, 0);
}

static u8
et_client_dgram_rx_test_bytes (echo_test_session_t *es, session_t *s, u8 *rx_buf)
{
  return et_client_dgram_rx_inline (es, s, rx_buf, 0);
}

static u32
et_client_dgram_tx (echo_test_session_t *es, u32 max_send)
{
  app_session_transport_t *at = &es->transport;
  svm_fifo_t *f = es->tx_fifo;
  u32 max_enqueue, n_sent = 0;
  int rv;

  rv = svm_fifo_fill_chunk_list (f);
  if (rv < 0)
    return 0;

  max_enqueue = svm_fifo_max_enqueue_prod (f);

  if (max_enqueue <= sizeof (session_dgram_hdr_t))
    return 0;

  session_dgram_hdr_t hdr = {
    .data_length = TRANSPORT_PACER_MIN_MSS,
    .data_offset = 0,
    .gso_size = 0,
    .rmt_ip = at->rmt_ip,
    .rmt_port = at->rmt_port,
    .is_ip4 = at->is_ip4,
    .lcl_ip = at->lcl_ip,
    .lcl_port = at->lcl_port,
  };

  /* send datagrams of size 1460 first */
  while (max_send >= TRANSPORT_PACER_MIN_MSS &&
	 max_enqueue >= (TRANSPORT_PACER_MIN_MSS + sizeof (session_dgram_hdr_t)))
    {
      svm_fifo_enqueue (f, sizeof (hdr), (u8 *) &hdr);
      svm_fifo_enqueue_nocopy (f, TRANSPORT_PACER_MIN_MSS);
      max_enqueue -= TRANSPORT_PACER_MIN_MSS;
      max_enqueue -= sizeof (session_dgram_hdr_t);
      max_send -= TRANSPORT_PACER_MIN_MSS;
      es->dgrams_sent++;
      n_sent += TRANSPORT_PACER_MIN_MSS;
    }

  /* remainder of bytes, this should be only last datagram if number of total bytes is not multiply
   * of 1460 or when we have target bandwidth */
  if (PREDICT_FALSE (max_enqueue > sizeof (session_dgram_hdr_t) && max_send))
    {
      max_enqueue -= sizeof (session_dgram_hdr_t);
      hdr.data_length = clib_min (max_enqueue, max_send);
      ASSERT (hdr.data_length);
      svm_fifo_enqueue (f, sizeof (hdr), (u8 *) &hdr);
      svm_fifo_enqueue_nocopy (f, hdr.data_length);
      es->dgrams_sent++;
      n_sent += hdr.data_length;
    }

  session_program_tx_io_evt (es->tx_fifo->vpp_sh, SESSION_IO_EVT_TX);
  es->bytes_sent += n_sent;
  return n_sent;
}

static u32
et_client_dgram_tx_test_bytes (echo_test_session_t *es, u8 *test_data, u32 max_send)
{
  u32 test_buf_len, test_buf_offset, n_sent, n_transfer;
  svm_fifo_t *f = es->tx_fifo;
  u32 max_enqueue = svm_fifo_max_enqueue_prod (f);

  if (max_enqueue <= (sizeof (session_dgram_hdr_t) + sizeof (u32)))
    return 0;

  test_buf_len = vec_len (test_data);
  ASSERT (test_buf_len > 0);

#define et_client_set_test_buf_offset()                                                            \
  do                                                                                               \
    {                                                                                              \
      test_buf_offset = es->bytes_sent % test_buf_len;                                             \
      /* make sure we're sending evenly sized dgrams */                                            \
      if ((test_buf_len - test_buf_offset) < n_transfer)                                           \
	test_buf_offset = 0;                                                                       \
    }                                                                                              \
  while (0);

  /* first datagram is special, we might need to update rtt */
  max_enqueue -= sizeof (session_dgram_hdr_t);
  max_enqueue -= sizeof (u32);
  n_transfer = clib_min (max_enqueue, max_send);
  n_transfer = clib_min (n_transfer, TRANSPORT_PACER_MIN_MSS);
  ASSERT (n_transfer);
  et_client_set_test_buf_offset ();
  /* Include buffer offset info to also be able to verify
   * out-of-order packets */
  svm_fifo_seg_t data_segs[3] = { { NULL, 0 },
				  { (u8 *) &test_buf_offset, sizeof (u32) },
				  { test_data + test_buf_offset, n_transfer } };
  if ((es->rtt_stat & ET_UDP_RTT_TX_FLAG) == 0)
    {
      es->rtt_udp_buffer_offset = test_buf_offset;
      es->send_rtt = vlib_time_now (vlib_get_main ());
      es->rtt_stat |= ET_UDP_RTT_TX_FLAG;
    }
  app_send_dgram_segs ((app_session_t *) es, data_segs, 2, n_transfer + sizeof (u32), 0);
  es->dgrams_sent++;
  es->bytes_sent += n_transfer;
  n_sent = n_transfer;
  max_enqueue -= n_transfer;
  max_send -= n_sent;

  /* send datagrams of size 1460 */
  n_transfer = TRANSPORT_PACER_MIN_MSS;
  data_segs[2].len = n_transfer;
  while (max_send >= n_transfer &&
	 max_enqueue >= (n_transfer + sizeof (session_dgram_hdr_t) + sizeof (u32)))
    {
      et_client_set_test_buf_offset ();
      max_enqueue -= sizeof (session_dgram_hdr_t);
      max_enqueue -= sizeof (u32);
      max_enqueue -= n_transfer;
      max_send -= n_transfer;
      data_segs[0].len = 0; /* app_send_dgram_segs side effect */
      data_segs[1].data = (u8 *) &test_buf_offset;
      data_segs[2].data = test_data + test_buf_offset;
      es->dgrams_sent++;
      es->bytes_sent += n_transfer;
      n_sent += n_transfer;
      app_send_dgram_segs ((app_session_t *) es, data_segs, 2, n_transfer + sizeof (u32), 0);
    }

  /* remainder of bytes, this should be only last datagram if number of total bytes is not multiply
   * of 1460 or when we have target bandwidth */
  if (max_enqueue > (sizeof (session_dgram_hdr_t) + sizeof (u32)) && max_send)
    {
      max_enqueue -= sizeof (session_dgram_hdr_t);
      max_enqueue -= sizeof (u32);
      n_transfer = clib_min (max_enqueue, max_send);
      ASSERT (n_transfer);
      et_client_set_test_buf_offset ();
      data_segs[0].len = 0; /* app_send_dgram_segs side effect */
      data_segs[1].data = (u8 *) &test_buf_offset;
      data_segs[2].data = test_data + test_buf_offset;
      data_segs[2].len = n_transfer;
      es->dgrams_sent++;
      es->bytes_sent += n_transfer;
      n_sent += n_transfer;
      app_send_dgram_segs ((app_session_t *) es, data_segs, 2, n_transfer + sizeof (u32), 0);
    }

#undef et_client_set_test_buf_offset

  return n_sent;
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
  .client_rx = et_client_dgram_rx,
  .client_rx_test_bytes = et_client_dgram_rx_test_bytes,
  .client_tx = et_client_dgram_tx,
  .client_tx_test_bytes = et_client_dgram_tx_test_bytes,
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
  .client_rx = et_client_stream_rx,
  .client_rx_test_bytes = et_client_stream_rx_test_bytes,
  .client_tx = et_client_stream_tx,
  .client_tx_test_bytes = et_client_stream_tx_test_bytes,
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

  ASSERT (vec_len (rx_buf) >= max_transfer);
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
  .client_rx = et_client_stream_rx,
  .client_rx_test_bytes = et_client_stream_rx_test_bytes,
  .client_tx = et_client_stream_tx,
  .client_tx_test_bytes = et_client_stream_tx_test_bytes,
};

ECHO_TEST_REGISTER_PROTO (TRANSPORT_PROTO_QUIC, echo_test_quic);
