/*
 * Copyright (c) 2019 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <quic/quic_crypto.h>
#include <quic/quic.h>

#include <vnet/crypto/crypto.h>

#include <picotls/openssl.h>
#include <quicly.h>

typedef void (*quicly_do_transform_fn) (ptls_cipher_context_t *, void *,
					const void *, size_t);

struct cipher_context_t
{
  ptls_cipher_context_t super;
  vnet_crypto_op_t op;
  u32 key_index;
};

struct aead_crypto_context_t
{
  ptls_aead_context_t super;
  vnet_crypto_op_t op;
  u32 key_index;
};

vnet_crypto_main_t *cm = &crypto_main;

static void
quic_crypto_cipher_do_init (ptls_cipher_context_t * _ctx, const void *iv)
{
  struct cipher_context_t *ctx = (struct cipher_context_t *) _ctx;

  vnet_crypto_op_id_t id;
  if (!strcmp (ctx->super.algo->name, "AES128-CTR"))
    {
      id = VNET_CRYPTO_OP_AES_128_CTR_ENC;
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-CTR"))
    {
      id = VNET_CRYPTO_OP_AES_256_CTR_ENC;
    }
  else
    {
      QUIC_DBG (1, "%s, Invalid crypto cipher : ", __FUNCTION__,
		_ctx->algo->name);
      assert (0);
    }

  vnet_crypto_op_init (&ctx->op, id);
  ctx->op.iv = (u8 *) iv;
  ctx->op.key_index = ctx->key_index;
}

static void
quic_crypto_cipher_dispose (ptls_cipher_context_t * _ctx)
{
  /* Do nothing */
}

static void
quic_crypto_cipher_encrypt (ptls_cipher_context_t * _ctx, void *output,
			    const void *input, size_t _len)
{
  vlib_main_t *vm = vlib_get_main ();
  struct cipher_context_t *ctx = (struct cipher_context_t *) _ctx;

  ctx->op.src = (u8 *) input;
  ctx->op.dst = output;
  ctx->op.len = _len;

  vnet_crypto_process_ops (vm, &ctx->op, 1);
}

static int
quic_crypto_cipher_setup_crypto (ptls_cipher_context_t * _ctx, int is_enc,
				 const void *key, const EVP_CIPHER * cipher,
				 quicly_do_transform_fn do_transform)
{
  struct cipher_context_t *ctx = (struct cipher_context_t *) _ctx;

  ctx->super.do_dispose = quic_crypto_cipher_dispose;
  ctx->super.do_init = quic_crypto_cipher_do_init;
  ctx->super.do_transform = do_transform;

  vlib_main_t *vm = vlib_get_main ();
  vnet_crypto_alg_t algo;
  if (!strcmp (ctx->super.algo->name, "AES128-CTR"))
    {
      algo = VNET_CRYPTO_ALG_AES_128_CTR;
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-CTR"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_CTR;
    }
  else
    {
      QUIC_DBG (1, "%s, Invalid crypto cipher : ", __FUNCTION__,
		_ctx->algo->name);
      assert (0);
    }

  ctx->key_index = vnet_crypto_key_add (vm, algo,
					(u8 *) key, _ctx->algo->key_size);

  return 0;
}

static int
aes128ctr_setup_crypto (ptls_cipher_context_t * ctx, int is_enc,
			const void *key)
{
  return quic_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_128_ctr (),
					  quic_crypto_cipher_encrypt);
}

static int
aes256ctr_setup_crypto (ptls_cipher_context_t * ctx, int is_enc,
			const void *key)
{
  return quic_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_256_ctr (),
					  quic_crypto_cipher_encrypt);
}

size_t
quic_crypto_aead_encrypt (ptls_aead_context_t * _ctx, void *output,
			  const void *input, size_t inlen, uint64_t seq,
			  const void *iv, const void *aad, size_t aadlen)
{
  vlib_main_t *vm = vlib_get_main ();
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  vnet_crypto_op_id_t id;
  if (!strcmp (ctx->super.algo->name, "AES128-GCM"))
    {
      id = VNET_CRYPTO_OP_AES_128_GCM_ENC;
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-GCM"))
    {
      id = VNET_CRYPTO_OP_AES_256_GCM_ENC;
    }
  else
    {
      assert (0);
    }

  vnet_crypto_op_init (&ctx->op, id);
  ctx->op.aad = (u8 *) aad;
  ctx->op.aad_len = aadlen;
  ctx->op.iv = (u8 *) iv;

  ctx->op.src = (u8 *) input;
  ctx->op.dst = output;
  ctx->op.key_index = ctx->key_index;
  ctx->op.len = inlen;

  ctx->op.tag_len = ctx->super.algo->tag_size;
  ctx->op.tag = ctx->op.src + inlen;

  vnet_crypto_process_ops (vm, &ctx->op, 1);

  return ctx->op.len + ctx->op.tag_len;
}

size_t
quic_crypto_aead_decrypt (ptls_aead_context_t * _ctx, void *_output,
			  const void *input, size_t inlen, const void *iv,
			  const void *aad, size_t aadlen)
{
  vlib_main_t *vm = vlib_get_main ();
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  vnet_crypto_op_id_t id;
  if (!strcmp (ctx->super.algo->name, "AES128-GCM"))
    {
      id = VNET_CRYPTO_OP_AES_128_GCM_DEC;
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-GCM"))
    {
      id = VNET_CRYPTO_OP_AES_256_GCM_DEC;
    }
  else
    {
      assert (0);
    }

  vnet_crypto_op_init (&ctx->op, id);
  ctx->op.aad = (u8 *) aad;
  ctx->op.aad_len = aadlen;
  ctx->op.iv = (u8 *) iv;

  ctx->op.src = (u8 *) input;
  ctx->op.dst = _output;
  ctx->op.key_index = ctx->key_index;
  ctx->op.len = inlen - ctx->super.algo->tag_size;

  ctx->op.tag_len = ctx->super.algo->tag_size;
  ctx->op.tag = ctx->op.src + ctx->op.len;

  vnet_crypto_process_ops (vm, &ctx->op, 1);

  return ctx->op.len;
}

static void
quic_crypto_aead_dispose_crypto (ptls_aead_context_t * _ctx)
{

}

static int
quic_crypto_aead_setup_crypto (ptls_aead_context_t * _ctx, int is_enc,
			       const void *key, const EVP_CIPHER * cipher)
{
  vlib_main_t *vm = vlib_get_main ();
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  vnet_crypto_alg_t algo;
  if (!strcmp (ctx->super.algo->name, "AES128-GCM"))
    {
      algo = VNET_CRYPTO_ALG_AES_128_GCM;
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-GCM"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_GCM;
    }
  else
    {
      QUIC_DBG (1, "%s, invalied aead cipher %s", __FUNCTION__,
		_ctx->algo->name);
      assert (0);
    }

  ctx->super.do_decrypt = quic_crypto_aead_decrypt;
  ctx->super.do_encrypt = quic_crypto_aead_encrypt;
  ctx->super.dispose_crypto = quic_crypto_aead_dispose_crypto;

  ctx->key_index = vnet_crypto_key_add (vm, algo,
					(u8 *) key, _ctx->algo->key_size);

  return 0;
}

static int
quic_crypto_aead_aes128gcm_setup_crypto (ptls_aead_context_t * ctx,
					 int is_enc, const void *key)
{
  return quic_crypto_aead_setup_crypto (ctx, is_enc, key, EVP_aes_128_gcm ());
}

static int
quic_crypto_aead_aes256gcm_setup_crypto (ptls_aead_context_t * ctx,
					 int is_enc, const void *key)
{
  return quic_crypto_aead_setup_crypto (ctx, is_enc, key, EVP_aes_256_gcm ());
}

ptls_cipher_algorithm_t quic_crypto_aes128ctr = { "AES128-CTR",
  PTLS_AES128_KEY_SIZE,
  1, PTLS_AES_IV_SIZE,
  sizeof (struct cipher_context_t),
  aes128ctr_setup_crypto
};

ptls_cipher_algorithm_t quic_crypto_aes256ctr = { "AES256-CTR",
  PTLS_AES256_KEY_SIZE,
  1 /* block size */ ,
  PTLS_AES_IV_SIZE,
  sizeof (struct cipher_context_t),
  aes256ctr_setup_crypto
};

ptls_aead_algorithm_t quic_crypto_aes128gcm = { "AES128-GCM",
  &quic_crypto_aes128ctr,
  NULL,
  PTLS_AES128_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  sizeof (struct aead_crypto_context_t),
  quic_crypto_aead_aes128gcm_setup_crypto
};

ptls_aead_algorithm_t quic_crypto_aes256gcm = { "AES256-GCM",
  &quic_crypto_aes256ctr,
  NULL,
  PTLS_AES256_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  sizeof (struct aead_crypto_context_t),
  quic_crypto_aead_aes256gcm_setup_crypto
};

ptls_cipher_suite_t quic_crypto_aes128gcmsha256 =
  { PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
  &quic_crypto_aes128gcm,
  &ptls_openssl_sha256
};

ptls_cipher_suite_t quic_crypto_aes256gcmsha384 =
  { PTLS_CIPHER_SUITE_AES_256_GCM_SHA384,
  &quic_crypto_aes256gcm,
  &ptls_openssl_sha384
};

ptls_cipher_suite_t *quic_crypto_cipher_suites[] =
  { &quic_crypto_aes256gcmsha384,
  &quic_crypto_aes128gcmsha256,
  NULL
};

int
quic_encrypt_ticket_cb (ptls_encrypt_ticket_t * _self, ptls_t * tls,
			int is_encrypt, ptls_buffer_t * dst, ptls_iovec_t src)
{
  quic_session_cache_t *self = (void *) _self;
  int ret;

  if (is_encrypt)
    {

      /* replace the cached entry along with a newly generated session id */
      clib_mem_free (self->data.base);
      if ((self->data.base = clib_mem_alloc (src.len)) == NULL)
	return PTLS_ERROR_NO_MEMORY;

      ptls_get_context (tls)->random_bytes (self->id, sizeof (self->id));
      clib_memcpy (self->data.base, src.base, src.len);
      self->data.len = src.len;

      /* store the session id in buffer */
      if ((ret = ptls_buffer_reserve (dst, sizeof (self->id))) != 0)
	return ret;
      clib_memcpy (dst->base + dst->off, self->id, sizeof (self->id));
      dst->off += sizeof (self->id);

    }
  else
    {

      /* check if session id is the one stored in cache */
      if (src.len != sizeof (self->id))
	return PTLS_ERROR_SESSION_NOT_FOUND;
      if (clib_memcmp (self->id, src.base, sizeof (self->id)) != 0)
	return PTLS_ERROR_SESSION_NOT_FOUND;

      /* return the cached value */
      if ((ret = ptls_buffer_reserve (dst, self->data.len)) != 0)
	return ret;
      clib_memcpy (dst->base + dst->off, self->data.base, self->data.len);
      dst->off += self->data.len;
    }

  return 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
