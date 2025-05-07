/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_openssl_h__
#define __included_quic_openssl_h__

#include <quic/quic.h>
#include <vnet/session/session.h>

/* Main struct for openssl engine, if needed */
typedef struct quic_openssl_main_
{
  // Add fields as needed
} quic_openssl_main_t;

extern quic_openssl_main_t quic_openssl_main;

/* Function prototypes for the VFT */
void quic_openssl_engine_init (quic_main_t *qm);
int quic_openssl_app_cert_key_pair_delete (app_cert_key_pair_t *ckpair);
int quic_openssl_crypto_context_acquire (quic_ctx_t *ctx);
void quic_openssl_crypto_context_release (u32 crypto_context_index,
					  u8 thread_index);
int quic_openssl_connect (quic_ctx_t *ctx, u32 ctx_index,
			  clib_thread_index_t thread_index,
			  struct sockaddr *sa);
int quic_openssl_connect_stream (void *quic_conn, void **quic_stream,
				 quic_stream_data_t **quic_stream_data,
				 u8 is_unidir);
void quic_openssl_connect_stream_error_reset (void *quic_stream);
int quic_openssl_connection_receive (quic_ctx_t *ctx);
int quic_openssl_connection_get_stats (void *conn, u32 *stats);
int quic_openssl_udp_session_rx_packets (session_t *udp_session);
void quic_openssl_ack_rx_data (quic_ctx_t *ctx, session_t *stream_session);
int quic_openssl_stream_tx (quic_ctx_t *ctx, session_t *stream_session);
int quic_openssl_send_packets (quic_ctx_t *ctx);
u8 *quic_openssl_format_connection_stats (u8 *s, void *conn, int verbose);
u8 *quic_openssl_format_stream_connection (u8 *s, void *stream);
u8 *quic_openssl_format_stream_ctx_stream_id (u8 *s, void *stream);
void quic_openssl_proto_on_close (u32 ctx_index, u32 thread_index);

#endif /* __included_quic_openssl_h__ */
