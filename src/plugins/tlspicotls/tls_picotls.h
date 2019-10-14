#ifndef __included_tls_picotls_h__
#define __included_tls_picotls_h__

#include <picotls.h>
#include <picotls/openssl.h>
#include <vnet/plugin/plugin.h>
#include <vnet/tls/tls.h>
#include <vpp/app/version.h>

typedef struct tls_ctx_picotls_
{
  tls_ctx_t ctx;
  u32 ptls_ctx_idx;
  ptls_t *tls;
  u8 *rx_content;
  int rx_offset;
  int rx_len;
} picotls_ctx_t;

typedef struct tls_listen_ctx_picotls_
{
  u32 ptls_lctx_index;
  ptls_context_t *ptls_ctx;
} picotls_listen_ctx_t;

typedef struct picotls_main_
{
  picotls_ctx_t ***ctx_pool;
  picotls_listen_ctx_t *lctx_pool;
} picotls_main_t;

#endif /* __included_quic_certs_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
