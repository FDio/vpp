/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_inlines_h__
#define __included_quic_inlines_h__

#include <quic/quic.h>

static_always_inline int
quic_lib_init_crypto_context (quic_lib_type_t lib_type, crypto_context_t *crctx, quic_ctx_t *ctx)
{
  if (!quic_vfts[lib_type].init_crypto_context) {
    QUIC_DBG (1, "init_crypto_context() not available for %s library\n", quic_lib_type_str(lib_type));
    return -1;
  }
  return (quic_vfts[lib_type].init_crypto_context (crctx, ctx));
}

static_always_inline quic_ctx_t *
quic_lib_conn_ctx_get (quic_lib_type_t lib_type, void *conn)
{
  if (!quic_vfts[lib_type].conn_ctx_get) {
    QUIC_DBG (1, "conn_ctx_get() not available for %s library\n", quic_lib_type_str(lib_type));
    return NULL;
  }
  return (quic_vfts[lib_type].conn_ctx_get(conn));
}
#endif /* __included_quic_inlines_h__ */
