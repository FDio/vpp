/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_inlines_h__
#define __included_quic_inlines_h__

#include "quic.h"
#include <quic/quic.h>

static_always_inline int
quic_lib_init_crypto_context (crypto_context_t *crctx, quic_ctx_t *ctx)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return -1;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].init_crypto_context))
    {
      QUIC_DBG (1, "init_crypto_context() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return -1;
    }
  return (quic_vfts[qm->lib_type].init_crypto_context (crctx, ctx));
}

static_always_inline void
quic_lib_crypto_context_make_key_from_crctx (clib_bihash_kv_24_8_t *kv,
					 crypto_context_t *crctx)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].crypto_context_make_key_from_crctx))
    {
      QUIC_DBG (1, "crypto_context_make_key_from_crctx() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].crypto_context_make_key_from_crctx (kv, crctx);
}

static_always_inline void
quic_lib_crypto_decrypt_packet (quic_ctx_t *qctx, quic_rx_packet_ctx_t *pctx)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].crypto_decrypt_packet))
    {
      QUIC_DBG (1, "crypto_decrypt_packet() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].crypto_decrypt_packet (qctx, pctx);
}

static_always_inline void
quic_lib_crypto_encrypt_packet (struct st_quicly_crypto_engine_t *engine,
			    quicly_conn_t *conn,
			    ptls_cipher_context_t *header_protect_ctx,
			    ptls_aead_context_t *packet_protect_ctx,
			    ptls_iovec_t datagram, size_t first_byte_at,
			    size_t payload_from, uint64_t packet_number,
			    int coalesced)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].crypto_encrypt_packet))
    {
      QUIC_DBG (1, "crypto_encrypt_packet() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].crypto_encrypt_packet (engine, conn,
                                                 header_protect_ctx,
                                                 packet_protect_ctx,
                                                 datagram, first_byte_at,
                                                 payload_from,
                                                 packet_number,
                                                 coalesced);
}

static_always_inline void
quic_lib_accept_connection (quic_rx_packet_ctx_t * pctx)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].accept_connection))
    {
      QUIC_DBG (1, "accept_connection() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].accept_connection (pctx);
}

static_always_inline void
quic_lib_receive_connection (void *arg)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].receive_connection))
    {
      QUIC_DBG (1, "receive_connection() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].receive_connection (arg);
}

static_always_inline int
quic_lib_reset_connection (u64 udp_session_handle, quic_rx_packet_ctx_t * pctx)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return -1;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].reset_connection))
    {
      QUIC_DBG (1, "reset_connection() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return -1;
    }
  return (quic_vfts[qm->lib_type].reset_connection (udp_session_handle, pctx));
}

static_always_inline void
quic_lib_connection_delete (quic_ctx_t * ctx)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].connection_delete))
    {
      QUIC_DBG (1, "connection_delete() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].connection_delete (ctx);
}

static_always_inline u8 *
quic_lib_format_connection_stats (u8 * s, va_list * args)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return s;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].format_connection_stats))
    {
      QUIC_DBG (1, "format_connection_stats() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return s;
    }
  return (quic_vfts[qm->lib_type].format_connection_stats (s, args));
}

static_always_inline u8 *
quic_lib_format_stream_ctx_stream_id (u8 * s, va_list * args)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return s;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].format_stream_ctx_stream_id))
    {
      QUIC_DBG (1, "format_stream_ctx_stream_id() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return s;
    }
  return (quic_vfts[qm->lib_type].format_stream_ctx_stream_id (s, args));
}

static_always_inline u8 *
quic_lib_format_stream_connection (u8 * s, va_list * args)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return s;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].format_stream_connection))
    {
      QUIC_DBG (1, "format_stream_connection() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return s;
    }
  return (quic_vfts[qm->lib_type].format_stream_connection (s, args));
}

static_always_inline void
quic_lib_ack_rx_data (session_t * stream_session)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].ack_rx_data))
    {
      QUIC_DBG (1, "ack_rx_data() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].ack_rx_data (stream_session);
}

static_always_inline quic_ctx_t *
quic_lib_get_conn_ctx (void *conn)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return NULL;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].get_conn_ctx))
    {
      QUIC_DBG (1, "get_conn_ctx() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return NULL;
    }
  return (quic_vfts[qm->lib_type].get_conn_ctx (conn));
}

static_always_inline void
quic_lib_proto_on_close (u32 ctx_index, u32 thread_index)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].proto_on_close))
    {
      QUIC_DBG (1, "proto_on_close() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].proto_on_close (ctx_index, thread_index);
}

static_always_inline void
quic_lib_store_conn_ctx (void * conn, quic_ctx_t * ctx)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].store_conn_ctx))
    {
      QUIC_DBG (1, "store_conn_ctx() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].store_conn_ctx (conn, ctx);
}

static_always_inline int
quic_lib_connect (quic_ctx_t * ctx, u32 ctx_index, u32 thread_index, struct sockaddr *sa)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return -1;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].connect))
    {
      QUIC_DBG (1, "connect() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return -1;
    }
  return (quic_vfts[qm->lib_type].connect (ctx, ctx_index, thread_index, sa));
}

static_always_inline int
quic_lib_connect_stream (void * quic_conn, void ** quic_stream, quic_stream_data_t ** quic_stream_data, u8 is_unidir) 
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return -1;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].connect_stream))
    {
      QUIC_DBG (1, "connect_stream() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return -1;
    }
  return (quic_vfts[qm->lib_type].connect_stream (quic_conn, quic_stream, quic_stream_data, is_unidir));
}

static_always_inline quic_session_connected_t
quic_lib_is_session_connected (quic_ctx_t * ctx) 
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return QUIC_SESSION_CONNECTED_NONE;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].is_session_connected))
    {
      QUIC_DBG (1, "is_session_connected() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return QUIC_SESSION_CONNECTED_NONE;
    }
  return (quic_vfts[qm->lib_type].is_session_connected (ctx));
}

static_always_inline int
quic_lib_stream_tx (quic_ctx_t * ctx, session_t * stream_session) 
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return -1;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].stream_tx))
    {
      QUIC_DBG (1, "stream_tx() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return -1;
    }
  return (quic_vfts[qm->lib_type].stream_tx (ctx, stream_session));
}

static_always_inline void
quic_lib_reset_stream (void * quic_stream, int error)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].reset_stream))
    {
      QUIC_DBG (1, "reset_stream() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return;
    }
  quic_vfts[qm->lib_type].reset_stream (quic_stream, error);
}

static_always_inline int
quic_lib_send_packets (void *conn)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return 0;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].send_packets))
    {
      QUIC_DBG (1, "send_packets() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return 0;
    }
  return (quic_vfts[qm->lib_type].send_packets (conn));
}

static_always_inline int
quic_lib_process_one_rx_packet (u64 udp_session_handle, svm_fifo_t *f,
			    u32 fifo_offset, quic_rx_packet_ctx_t *pctx)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return 0;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].process_one_rx_packet))
    {
      QUIC_DBG (1, "process_one_rx_packet() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return 0;
    }
  return (quic_vfts[qm->lib_type].process_one_rx_packet (udp_session_handle, f, fifo_offset, pctx));
}

static_always_inline int
quic_lib_receive_a_packet (quic_ctx_t *ctx, quic_rx_packet_ctx_t *pctx)
{
  quic_main_t *qm = get_quic_main ();

  if (PREDICT_FALSE (qm->lib_type == QUIC_LIB_NONE))
    {
      QUIC_DBG (1, "No QUIC library is available\n");
      return 0;
    }
  if (PREDICT_FALSE (!quic_vfts[qm->lib_type].receive_a_packet))
    {
      QUIC_DBG (1, "receive_a_packet() not available for %s library\n",
		quic_lib_type_str (qm->lib_type));
      return 0;
    }
  return (quic_vfts[qm->lib_type].receive_a_packet (ctx, pctx));
}

#endif /* __included_quic_inliqm->nes_h__ */
