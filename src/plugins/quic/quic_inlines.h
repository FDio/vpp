/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Cisco Systems, Inc.
 */

#ifndef __included_quic_inlines_h__
#define __included_quic_inlines_h__

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
#endif /* __included_quic_inliqm->nes_h__ */
