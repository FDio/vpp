#ifndef __included_tls_picotls_h__
#define __included_tls_picotls_h__

#include <picotls.h>
#include <picotls/openssl.h>
#include <vnet/plugin/plugin.h>
#include <vnet/tls/tls.h>
#include <vpp/app/version.h>

#define TLS_RX_LEN(x) ((x)->rx_content + (x)->rx_len)
#define TLS_RX_OFFSET(x) ((x)->rx_content + (x)->rx_offset)
#define TLS_RX_IS_LEFT(x) ((x)->rx_len != 0 && (x)->rx_len != (x)->rx_offset)
#define TLS_RX_LEFT_LEN(x) ((x)->rx_len - (x)->rx_offset)

#define TLS_READ_OFFSET(x) ((x)->read_buffer.base + (x)->read_buffer_offset)
#define TLS_READ_IS_LEFT(x) ((x)->read_buffer.off != 0 && (x)->read_buffer.off != (x)->read_buffer_offset)
#define TLS_READ_LEFT_LEN(x) ((x)->read_buffer.off - (x)->read_buffer_offset)

#define TLS_WRITE_OFFSET(x) ((x)->write_buffer.base + (x)->write_buffer_offset)
#define TLS_WRITE_IS_LEFT(x) ((x)->write_buffer.off != 0 && (x)->write_buffer.off != (x)->write_buffer_offset)


typedef struct tls_ctx_picotls_
{
  tls_ctx_t ctx;
  u32 ptls_ctx_idx;
  ptls_t *tls;
  u8 *rx_content;
  int rx_offset;
  int rx_len;
  ptls_buffer_t read_buffer;
  ptls_buffer_t write_buffer;
  uint8_t *write_content;
  int read_buffer_offset;
  int write_buffer_offset;
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
  ptls_context_t *client_ptls_ctx;
  clib_rwlock_t crypto_keys_rw_lock;
} picotls_main_t;

#endif /* __included_quic_certs_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
