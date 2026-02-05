/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_eng_inline_h__
#define __included_quic_eng_inline_h__

#include <quic/quic.h>

static_always_inline void
quic_eng_engine_init (quic_main_t *qm)
{
  quic_engine_vfts[qm->engine_type].engine_init (qm);
}

static_always_inline int
quic_eng_crypto_context_acquire_listen (quic_ctx_t *ctx)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].crypto_context_acquire_listen (ctx));
}

static_always_inline int
quic_eng_crypto_context_acquire_accept (quic_ctx_t *ctx)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].crypto_context_acquire_accept (ctx));
}

static_always_inline int
quic_eng_crypto_context_acquire_connect (quic_ctx_t *ctx)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].crypto_context_acquire_connect (ctx));
}

static_always_inline void
quic_eng_crypto_context_release (u32 crypto_context_index, u8 thread_index)
{
  quic_main_t *qm = &quic_main;
  quic_engine_vfts[qm->engine_type].crypto_context_release (
    crypto_context_index, thread_index);
}

static_always_inline quic_crypto_context_t *
quic_eng_crypto_context_get (quic_ctx_t *ctx)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].crypto_context_get (ctx));
}

static_always_inline void
quic_eng_crypto_context_list (vlib_main_t *vm)
{
  quic_main_t *qm = &quic_main;
  quic_engine_vfts[qm->engine_type].crypto_context_list (vm);
}

static_always_inline void
quic_eng_transport_closed (quic_ctx_t *ctx)
{
  quic_engine_vfts[quic_main.engine_type].transport_closed (ctx);
}

static_always_inline int
quic_eng_connect (quic_ctx_t *ctx, u32 ctx_index,
		  clib_thread_index_t thread_index, struct sockaddr *sa)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].connect (ctx, ctx_index,
						     thread_index, sa));
}

static_always_inline int
quic_eng_connect_stream (void *quic_conn, void **quic_stream,
			 quic_stream_data_t **quic_stream_data, u8 is_unidir)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].connect_stream (
    quic_conn, quic_stream, quic_stream_data, is_unidir));
}

static_always_inline void
quic_eng_connection_migrate (quic_ctx_t *ctx)
{
  quic_main_t *qm = &quic_main;
  quic_engine_vfts[qm->engine_type].connection_migrate (ctx);
}

static_always_inline void
quic_eng_rpc_evt_to_thread_connection_migrate (u32 dest_thread,
					       quic_ctx_t *ctx)
{
  quic_main_t *qm = &quic_main;
  session_send_rpc_evt_to_thread (dest_thread,
				  quic_engine_vfts[qm->engine_type].connection_migrate_rpc, ctx);
}

static_always_inline void
quic_eng_connection_get_stats (void *conn, quic_stats_t *conn_stats)
{
  quic_main_t *qm = &quic_main;
  quic_engine_vfts[qm->engine_type].connection_get_stats (conn, conn_stats);
}

static_always_inline int
quic_eng_udp_session_rx_packets (session_t *udp_session)
{
  quic_main_t *qm = &quic_main;
  return quic_engine_vfts[qm->engine_type].udp_session_rx_packets (
    udp_session);
}

static_always_inline void
quic_eng_ack_rx_data (session_t *stream_session)
{
  quic_main_t *qm = &quic_main;
  quic_engine_vfts[qm->engine_type].ack_rx_data (stream_session);
}

static_always_inline int
quic_eng_stream_tx (quic_ctx_t *ctx, session_t *stream_session)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].stream_tx (ctx, stream_session));
}

static_always_inline int
quic_eng_send_packets (void *conn)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].send_packets (conn));
}

static_always_inline u8 *
quic_eng_format_connection_stats (u8 *s, va_list *args)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].format_connection_stats (s, args));
}

static_always_inline u8 *
quic_eng_format_stream_stats (u8 *s, va_list *args)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].format_stream_stats (s, args));
}

static_always_inline quic_stream_id_t
quic_eng_stream_get_stream_id (quic_ctx_t *ctx)
{
  quic_main_t *qm = &quic_main;
  return (quic_engine_vfts[qm->engine_type].stream_get_stream_id (ctx));
}

static_always_inline void
quic_eng_proto_on_close (u32 ctx_index, u32 thread_index)
{
  quic_main_t *qm = &quic_main;
  quic_engine_vfts[qm->engine_type].proto_on_close (ctx_index, thread_index);
}

static_always_inline void
quic_eng_proto_on_half_close (u32 ctx_index, u32 thread_index)
{
  quic_main_t *qm = &quic_main;
  quic_engine_vfts[qm->engine_type].proto_on_half_close (ctx_index,
							 thread_index);
}

static_always_inline void
quic_eng_proto_on_reset (u32 ctx_index, u32 thread_index)
{
  quic_main_t *qm = &quic_main;
  quic_engine_vfts[qm->engine_type].proto_on_reset (ctx_index, thread_index);
}

static_always_inline int
quic_eng_ctx_attribute (quic_ctx_t *ctx, u8 is_get, transport_endpt_attr_t *attr)
{
  quic_main_t *qm = &quic_main;
  if (!quic_engine_vfts[qm->engine_type].ctx_attribute)
    return -1;
  return quic_engine_vfts[qm->engine_type].ctx_attribute (ctx, is_get, attr);
}

#endif /* __included_quic_eng_inline_h__ */
