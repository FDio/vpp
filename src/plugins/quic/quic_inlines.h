/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_inlines_h__
#define __included_quic_inlines_h__

#include <quic/quic.h>

static_always_inline void
quic_eng_engine_init (quic_main_t *qm)
{
  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].engine_init))
    {
      QUIC_DBG (1, "engine_init() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return;
    }
  quic_engine_vfts[qm->engine_type].engine_init (qm);
}

static_always_inline int
quic_eng_app_cert_key_pair_delete (app_cert_key_pair_t *ckpair)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return -1;
    }
  if (PREDICT_FALSE (
	!quic_engine_vfts[qm->engine_type].app_cert_key_pair_delete))
    {
      QUIC_DBG (1, "app_cert_key_pair_delete() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return -1;
    }
  return (quic_engine_vfts[qm->engine_type].app_cert_key_pair_delete (ckpair));
}

static_always_inline int
quic_eng_crypto_context_acquire (quic_ctx_t *ctx)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return -1;
    }
  if (PREDICT_FALSE (
	!quic_engine_vfts[qm->engine_type].crypto_context_acquire))
    {
      QUIC_DBG (1, "crypto_context_acquire() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return -1;
    }
  return (quic_engine_vfts[qm->engine_type].crypto_context_acquire (ctx));
}

static_always_inline void
quic_eng_crypto_context_release (u32 crypto_context_index, u8 thread_index)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return;
    }
  if (PREDICT_FALSE (
	!quic_engine_vfts[qm->engine_type].crypto_context_release))
    {
      QUIC_DBG (1, "crypto_context_release() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return;
    }
  quic_engine_vfts[qm->engine_type].crypto_context_release (
    crypto_context_index, thread_index);
}

static_always_inline int
quic_eng_connect (quic_ctx_t *ctx, u32 ctx_index, u32 thread_index,
		  struct sockaddr *sa)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return -1;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].connect))
    {
      QUIC_DBG (1, "connect() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return -1;
    }
  return (quic_engine_vfts[qm->engine_type].connect (ctx, ctx_index,
						     thread_index, sa));
}

static_always_inline int
quic_eng_connect_stream (void *quic_conn, void **quic_stream,
			 quic_stream_data_t **quic_stream_data, u8 is_unidir)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return -1;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].connect_stream))
    {
      QUIC_DBG (1, "connect_stream() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return -1;
    }
  return (quic_engine_vfts[qm->engine_type].connect_stream (
    quic_conn, quic_stream, quic_stream_data, is_unidir));
}

static_always_inline void
quic_eng_connect_stream_error_reset (void *quic_stream)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return;
    }
  if (PREDICT_FALSE (
	!quic_engine_vfts[qm->engine_type].connect_stream_error_reset))
    {
      QUIC_DBG (1,
		"connect_stream_error_reset() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return;
    }
  quic_engine_vfts[qm->engine_type].connect_stream_error_reset (quic_stream);
}

static_always_inline void
quic_eng_rpc_evt_to_thread_connection_receive (u32 dest_thread,
					       quic_ctx_t *temp_ctx)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].connection_receive))
    {
      QUIC_DBG (1, "connection_receive() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return;
    }
  session_send_rpc_evt_to_thread (
    dest_thread, quic_engine_vfts[qm->engine_type].connection_receive,
    temp_ctx);
}

static_always_inline void
quic_eng_connection_get_stats (void *conn, quic_stats_t *conn_stats)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].connection_get_stats))
    {
      QUIC_DBG (1, "connection_get_stats() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return;
    }
  quic_engine_vfts[qm->engine_type].connection_get_stats (conn, conn_stats);
}

static_always_inline int
quic_eng_udp_session_rx_packets (session_t *udp_session)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return -1;
    }
  if (PREDICT_FALSE (
	!quic_engine_vfts[qm->engine_type].udp_session_rx_packets))
    {
      QUIC_DBG (1, "udp_session_rx_packets() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return -1;
    }
  return (
    quic_engine_vfts[qm->engine_type].udp_session_rx_packets (udp_session));
}

static_always_inline void
quic_eng_ack_rx_data (session_t *stream_session)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].ack_rx_data))
    {
      QUIC_DBG (1, "ack_rx_data() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return;
    }
  quic_engine_vfts[qm->engine_type].ack_rx_data (stream_session);
}

static_always_inline int
quic_eng_encrypt_ticket_cb (ptls_encrypt_ticket_t *_self, ptls_t *tls,
			    int is_encrypt, ptls_buffer_t *dst,
			    ptls_iovec_t src)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return -1;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].encrypt_ticket_cb))
    {
      QUIC_DBG (1, "encrypt_ticket_cb() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return -1;
    }
  return (quic_engine_vfts[qm->engine_type].encrypt_ticket_cb (
    _self, tls, is_encrypt, dst, src));
}

static_always_inline int
quic_eng_stream_tx (quic_ctx_t *ctx, session_t *stream_session)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return -1;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].stream_tx))
    {
      QUIC_DBG (1, "stream_tx() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return -1;
    }
  return (quic_engine_vfts[qm->engine_type].stream_tx (ctx, stream_session));
}

static_always_inline int
quic_eng_send_packets (void *conn)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return 0;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].send_packets))
    {
      QUIC_DBG (1, "send_packets() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return 0;
    }
  return (quic_engine_vfts[qm->engine_type].send_packets (conn));
}

static_always_inline u8 *
quic_eng_format_connection_stats (u8 *s, va_list *args)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return s;
    }
  if (PREDICT_FALSE (
	!quic_engine_vfts[qm->engine_type].format_connection_stats))
    {
      QUIC_DBG (1, "format_connection_stats() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return s;
    }
  return (quic_engine_vfts[qm->engine_type].format_connection_stats (s, args));
}

static_always_inline u8 *
quic_eng_format_stream_connection (u8 *s, va_list *args)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return s;
    }
  if (PREDICT_FALSE (
	!quic_engine_vfts[qm->engine_type].format_stream_connection))
    {
      QUIC_DBG (1, "format_stream_connection() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return s;
    }
  return (
    quic_engine_vfts[qm->engine_type].format_stream_connection (s, args));
}

static_always_inline u8 *
quic_eng_format_stream_ctx_stream_id (u8 *s, va_list *args)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return s;
    }
  if (PREDICT_FALSE (
	!quic_engine_vfts[qm->engine_type].format_stream_ctx_stream_id))
    {
      QUIC_DBG (1,
		"format_stream_ctx_stream_id() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return s;
    }
  return (
    quic_engine_vfts[qm->engine_type].format_stream_ctx_stream_id (s, args));
}

static_always_inline void
quic_eng_proto_on_close (u32 ctx_index, u32 thread_index)
{
  quic_main_t *qm = &quic_main;

  if (PREDICT_FALSE (qm->engine_type == QUIC_ENGINE_NONE))
    {
      QUIC_DBG (1, "No QUIC engine is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_engine_vfts[qm->engine_type].proto_on_close))
    {
      QUIC_DBG (1, "proto_on_close() not available for %s engine\n",
		quic_engine_type_str (qm->engine_type));
      return;
    }
  quic_engine_vfts[qm->engine_type].proto_on_close (ctx_index, thread_index);
}

#endif /* __included_quic_inliqm->nes_h__ */
