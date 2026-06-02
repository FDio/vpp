/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2026 Cisco Systems, Inc.
 */

#include <quic_quicly/quic_quicly_cid_enc.h>

#if defined(__AES__) || defined(__ARM_FEATURE_CRYPTO)

#include <vppinfra/mem.h>
#include <vppinfra/clib.h>
#include <vppinfra/vector.h>
#include <vppinfra/crypto/aes.h>
#include <picotls/openssl.h>

#define QUIC_QUICLY_CID_ENC_KEY_SIZE AES_KEY_BYTES (AES_KEY_128)
#define QUIC_QUICLY_CID_SIZE	     8

typedef struct quic_quicly_cid_enc_ctx_
{
  CLIB_CACHE_LINE_ALIGN_MARK (cacheline0);
  quicly_cid_encryptor_t super;
  CLIB_CACHE_LINE_ALIGN_MARK (cid_key_expanded);
  u8x16 cid_key[AES_KEY_ROUNDS (AES_KEY_128) + 1];
  CLIB_CACHE_LINE_ALIGN_MARK (reset_key_expanded);
  u8x16 reset_key[AES_KEY_ROUNDS (AES_KEY_128) + 1];
} quic_quicly_cid_enc_ctx_t;

static_always_inline u8x16
quic_quicly_one_round (quic_quicly_cid_enc_ctx_t *ctx, u8x16 x, u8x16 y, u8x16 rnd)
{
  const u8x16 mask = { 0,    0,	   0,	 0,    0xFF, 0xFF, 0xFF, 0xFF,
		       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
  u8x16 b = u8x16_blend (y, rnd, mask);
  u8x16 e = aes_encrypt_block (b, ctx->cid_key, AES_KEY_128);
  return e ^ x;
}

/* simplified version of picotls_quiclb_transform */
static_always_inline void
quic_quicly_cid_transform (quic_quicly_cid_enc_ctx_t *ctx, u8 *dst, const u8 *src, u8 is_enc)
{
  u8x16 l1, r1, l2, r2;
  /* byte[14] is CID len and byte[15] is round number */
  const u8x16 len_rnd[4] = { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 1 },
			     { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 2 },
			     { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 3 },
			     { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8, 4 } };

  /* split */
  u8x16 l0 = (u8x16) u32x4_insert (u32x4_zero (), *(u32 *) src, 0);
  u8x16 r0 = (u8x16) u32x4_insert (u32x4_zero (), *(u32 *) (src + 4), 0);

  if (is_enc)
    {
      r1 = quic_quicly_one_round (ctx, r0, l0, len_rnd[0]);
      l1 = quic_quicly_one_round (ctx, l0, r1, len_rnd[1]);
      r2 = quic_quicly_one_round (ctx, r1, l1, len_rnd[2]);
      l2 = quic_quicly_one_round (ctx, l1, r2, len_rnd[3]);
    }
  else
    {
      l1 = quic_quicly_one_round (ctx, l0, r0, len_rnd[3]);
      r1 = quic_quicly_one_round (ctx, r0, l1, len_rnd[2]);
      l2 = quic_quicly_one_round (ctx, l1, r1, len_rnd[1]);
      r2 = quic_quicly_one_round (ctx, r1, l2, len_rnd[0]);
    }

  /* merge */
  u8x16_store_partial (l2, dst, 4);
  u8x16_store_partial (r2, dst + 4, 4);
}

static int
quic_quicly_generate_reset_token (quicly_cid_encryptor_t *self, void *token, const void *cid)
{
  quic_quicly_cid_enc_ctx_t *ctx = (quic_quicly_cid_enc_ctx_t *) self;
  u8x16 dst;
  /* expand input, CID is 8bytes and reset token is 16bytes */
  u8x16 expandbuf = (u8x16) u64x2_insert (u64x2_zero (), *(u64 *) cid, 0);

  dst = aes_encrypt_block (expandbuf, ctx->reset_key, AES_KEY_128);
  clib_memcpy_fast (token, &dst, sizeof (dst));
  return 1;
}

static void
quic_quicly_encrypt_cid (quicly_cid_encryptor_t *self, quicly_cid_t *encrypted, void *reset_token,
			 const quicly_cid_plaintext_t *plaintext)
{
  quic_quicly_cid_enc_ctx_t *ctx = (quic_quicly_cid_enc_ctx_t *) self;
  u8 buf[QUIC_QUICLY_CID_SIZE];
  u8 *p;

  /* encode */
  p = buf;
  p = quicly_encode32 (p, plaintext->master_id);
  p = quicly_encode32 (p, (plaintext->thread_id << 8) | plaintext->path_id);
  ASSERT (p - buf == QUIC_QUICLY_CID_SIZE);

  /* encrypt */
  quic_quicly_cid_transform (ctx, encrypted->cid, buf, 1);
  encrypted->len = QUIC_QUICLY_CID_SIZE;

  /* generate stateless reset token if requested */
  if (reset_token)
    quic_quicly_generate_reset_token (self, reset_token, encrypted->cid);
}

static size_t
quic_quicly_decrypt_cid (quicly_cid_encryptor_t *self, quicly_cid_plaintext_t *plaintext,
			 const void *encrypted, size_t len)
{
  quic_quicly_cid_enc_ctx_t *ctx = (quic_quicly_cid_enc_ctx_t *) self;
  u8 dst[QUIC_QUICLY_CID_SIZE];
  const u8 *p;
  if (PREDICT_TRUE (!len))
    {
      /* if short header packet, we are the one to name the size */
      len = QUIC_QUICLY_CID_SIZE;
    }
  else
    {
      /* if long header packet, decrypt only if given CID is 8bytes */
      if (PREDICT_FALSE (len != QUIC_QUICLY_CID_SIZE))
	return SIZE_MAX;
    }

  /* decrypt */
  quic_quicly_cid_transform (ctx, dst, encrypted, 0);

  /* decode */
  p = dst;
  plaintext->node_id = 0;
  plaintext->master_id = quicly_decode32 (&p);
  plaintext->thread_id = quicly_decode24 (&p);
  plaintext->path_id = *p;

  return len;
}

quicly_cid_encryptor_t *
quic_quicly_new_cid_encryptor (ptls_iovec_t key)
{
  quic_quicly_cid_enc_ctx_t *ctx = 0;
  u8 key_buf[QUIC_QUICLY_CID_ENC_KEY_SIZE];

  ctx = clib_mem_alloc_aligned (sizeof (*ctx), CLIB_CACHE_LINE_BYTES);
  if (!ctx)
    goto error;

  ctx->super.generate_stateless_reset_token = quic_quicly_generate_reset_token;
  ctx->super.encrypt_cid = quic_quicly_encrypt_cid;
  ctx->super.decrypt_cid = quic_quicly_decrypt_cid;

  if (ptls_hkdf_expand_label (&ptls_openssl_sha256, key_buf, QUIC_QUICLY_CID_ENC_KEY_SIZE, key,
			      "cid", ptls_iovec_init (NULL, 0), "") != 0)
    goto error;
  aes_key_expand (ctx->cid_key, key_buf, AES_KEY_128);

  if (ptls_hkdf_expand_label (&ptls_openssl_sha256, key_buf, QUIC_QUICLY_CID_ENC_KEY_SIZE, key,
			      "reset", ptls_iovec_init (NULL, 0), "") != 0)
    goto error;
  aes_key_expand (ctx->reset_key, key_buf, AES_KEY_128);

  ptls_clear_memory (key_buf, sizeof (key_buf));
  return &ctx->super;

error:
  if (ctx)
    {
      ptls_clear_memory (ctx->cid_key, sizeof (ctx->cid_key));
      ptls_clear_memory (ctx->reset_key, sizeof (ctx->reset_key));
      clib_mem_free (ctx);
    }
  ptls_clear_memory (key_buf, sizeof (key_buf));
  return 0;
}

void
quic_quicly_free_cid_encryptor (quicly_cid_encryptor_t *self)
{
  quic_quicly_cid_enc_ctx_t *ctx = (quic_quicly_cid_enc_ctx_t *) self;
  ptls_clear_memory (ctx->cid_key, sizeof (ctx->cid_key));
  ptls_clear_memory (ctx->reset_key, sizeof (ctx->reset_key));
  clib_mem_free (ctx);
}

#else

#include <vppinfra/error_bootstrap.h>

quicly_cid_encryptor_t *
quic_quicly_new_cid_encryptor (ptls_iovec_t key)
{
  ASSERT (0);
  return 0;
}

void
quic_quicly_free_cid_encryptor (quicly_cid_encryptor_t *self)
{
  ASSERT (0);
}

#endif
