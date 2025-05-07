/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_openssl_h__
#define __included_quic_openssl_h__

#include <quic/quic.h>
#include <vnet/session/session.h>
#include <openssl/ssl.h>

/* Main struct for openssl engine, if needed */
typedef struct
{
  quic_main_t *qm;
  SSL_CTX *ssl_ctx;
  SSL *ssl_conn;
  BIO *rbio;
  BIO *wbio;
  u32 num_threads;
  clib_bitmap_t *available_crypto_engines;
} quic_openssl_main_t;

extern quic_openssl_main_t quic_openssl_main;

#endif /* __included_quic_openssl_h__ */
