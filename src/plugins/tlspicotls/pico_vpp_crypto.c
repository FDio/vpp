/*
 * Copyright (c) 2020 Intel and/or its affiliates.
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

#include <vnet/crypto/crypto.h>
#include <vnet/tls/tls.h>
#include <picotls/openssl.h>
#include <picotls.h>

#include <tlspicotls/pico_vpp_crypto.h>
#include <tlspicotls/tls_picotls.h>

typedef void (*ptls_vpp_do_transform_fn) (ptls_cipher_context_t *, void *,
					  const void *, size_t);

vnet_crypto_main_t *cm = &crypto_main;
extern picotls_main_t picotls_main;

struct cipher_context_t
{
  ptls_cipher_context_t super;
  vnet_crypto_op_t op;
  u32 key_index;
};

struct vpp_aead_context_t
{
  ptls_aead_context_t super;
  vnet_crypto_op_t op;
  vnet_crypto_op_chunk_t chunks[2];
  vnet_crypto_alg_t alg;
  u32 key_index;
  u32 chunk_index;
  uint8_t iv[PTLS_MAX_IV_SIZE];
  uint8_t static_iv[PTLS_MAX_IV_SIZE];
};

static void
ptls_vpp_crypto_cipher_do_init (ptls_cipher_context_t * _ctx, const void *iv)
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
      TLS_DBG (1, "%s, Invalid crypto cipher : ", __FUNCTION__,
	       _ctx->algo->name);
      assert (0);
    }

  vnet_crypto_op_init (&ctx->op, id);
  ctx->op.iv = (u8 *) iv;
  ctx->op.key_index = ctx->key_index;
}

static void
ptls_vpp_crypto_cipher_dispose (ptls_cipher_context_t * _ctx)
{
  /* Do nothing */
}

static void
ptls_vpp_crypto_cipher_encrypt (ptls_cipher_context_t * _ctx, void *output,
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
ptls_vpp_crypto_cipher_setup_crypto (ptls_cipher_context_t * _ctx, int is_enc,
				     const void *key,
				     const EVP_CIPHER * cipher,
				     ptls_vpp_do_transform_fn do_transform)
{
  struct cipher_context_t *ctx = (struct cipher_context_t *) _ctx;

  ctx->super.do_dispose = ptls_vpp_crypto_cipher_dispose;
  ctx->super.do_init = ptls_vpp_crypto_cipher_do_init;
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
      TLS_DBG (1, "%s, Invalid crypto cipher : ", __FUNCTION__,
	       _ctx->algo->name);
      assert (0);
    }

  clib_rwlock_writer_lock (&picotls_main.crypto_keys_rw_lock);
  ctx->key_index = vnet_crypto_key_add (vm, algo,
					(u8 *) key, _ctx->algo->key_size);
  clib_rwlock_writer_unlock (&picotls_main.crypto_keys_rw_lock);

  return 0;
}

size_t
ptls_vpp_crypto_aead_decrypt (ptls_aead_context_t * _ctx, void *_output,
			      const void *input, size_t inlen, uint64_t seq,
			      const void *aad, size_t aadlen)
{
  vlib_main_t *vm = vlib_get_main ();
  struct vpp_aead_context_t *ctx = (struct vpp_aead_context_t *) _ctx;
  int tag_size = ctx->super.algo->tag_size;

  ctx->op.dst = _output;
  ctx->op.src = (void *) input;
  ctx->op.len = inlen - tag_size;;
  ctx->op.iv = ctx->static_iv;
  ctx->op.aad = (void *) aad;
  ctx->op.aad_len = aadlen;
  ctx->op.tag = (void *) input + inlen - tag_size;
  ctx->op.tag_len = tag_size;

  vnet_crypto_process_ops (vm, &(ctx->op), 1);
  assert (ctx->op.status == VNET_CRYPTO_OP_STATUS_COMPLETED);

  return inlen - tag_size;
}

static void
ptls_vpp_crypto_aead_encrypt_init (ptls_aead_context_t * _ctx, uint64_t seq,
				   const void *aad, size_t aadlen)
{
  struct vpp_aead_context_t *ctx = (struct vpp_aead_context_t *) _ctx;
  ctx->op.iv = ctx->iv;
  ptls_aead__build_iv (ctx->super.algo, ctx->op.iv, ctx->static_iv, seq);
  ctx->op.iv = ctx->static_iv;
  ctx->op.aad = (void *) aad;
  ctx->op.aad_len = aadlen;
  ctx->op.n_chunks = 2;
  ctx->op.chunk_index = 0;

  ctx->op.flags |= VNET_CRYPTO_OP_FLAG_CHAINED_BUFFERS;
}

static size_t
ptls_vpp_crypto_aead_encrypt_update (ptls_aead_context_t * _ctx, void *output,
				     const void *input, size_t inlen)
{
  struct vpp_aead_context_t *ctx = (struct vpp_aead_context_t *) _ctx;
  ctx->chunks[ctx->chunk_index].dst = output;
  ctx->chunks[ctx->chunk_index].src = (void *) input;
  ctx->chunks[ctx->chunk_index].len = inlen;

  ctx->chunk_index = ctx->chunk_index == 0 ? 1 : 0;

  return inlen;
}

static size_t
ptls_vpp_crypto_aead_encrypt_final (ptls_aead_context_t * _ctx, void *_output)
{
  struct vlib_main_t *vm = vlib_get_main ();
  struct vpp_aead_context_t *ctx = (struct vpp_aead_context_t *) _ctx;

  ctx->op.tag = _output;
  ctx->op.tag_len = ctx->super.algo->tag_size;

  vnet_crypto_process_chained_ops (vm, &(ctx->op), ctx->chunks, 1);
  assert (ctx->op.status == VNET_CRYPTO_OP_STATUS_COMPLETED);

  return ctx->super.algo->tag_size;
}

static void
ptls_vpp_crypto_aead_dispose_crypto (ptls_aead_context_t * _ctx)
{
  /* Do nothing */
}

static int
ptls_vpp_crypto_aead_setup_crypto (ptls_aead_context_t * _ctx, int is_enc,
				   const void *key, const void *iv,
				   vnet_crypto_alg_t alg)
{
  struct vlib_main_t *vm = vlib_get_main ();
  struct vpp_aead_context_t *ctx = (struct vpp_aead_context_t *) _ctx;
  u16 key_len = ctx->super.algo->key_size;

  memset (&(ctx->op), 0, sizeof (vnet_crypto_op_t));

  if (alg == VNET_CRYPTO_ALG_AES_128_GCM)
    {
      if (is_enc)
	vnet_crypto_op_init (&(ctx->op), VNET_CRYPTO_OP_AES_128_GCM_ENC);
      else
	vnet_crypto_op_init (&(ctx->op), VNET_CRYPTO_OP_AES_128_GCM_DEC);
    }
  else if (alg == VNET_CRYPTO_ALG_AES_256_GCM)
    {
      if (is_enc)
	{
	  vnet_crypto_op_init (&(ctx->op), VNET_CRYPTO_OP_AES_256_GCM_ENC);
	}
      else
	vnet_crypto_op_init (&(ctx->op), VNET_CRYPTO_OP_AES_256_GCM_DEC);
    }
  else
    {
      TLS_DBG (1, "%s, invalied aead cipher %s", __FUNCTION__,
	       _ctx->algo->name);
      return -1;
    }

  ctx->alg = alg;

  clib_rwlock_writer_lock (&picotls_main.crypto_keys_rw_lock);
  ctx->op.key_index =
    vnet_crypto_key_add (vm, ctx->alg, (void *) key, key_len);
  clib_rwlock_writer_unlock (&picotls_main.crypto_keys_rw_lock);
  ctx->chunk_index = 0;
  clib_memcpy (ctx->static_iv, iv, ctx->super.algo->iv_size);

  ctx->super.do_decrypt = ptls_vpp_crypto_aead_decrypt;
  ctx->super.do_encrypt_init = ptls_vpp_crypto_aead_encrypt_init;
  ctx->super.do_encrypt_update = ptls_vpp_crypto_aead_encrypt_update;
  ctx->super.do_encrypt_final = ptls_vpp_crypto_aead_encrypt_final;
  ctx->super.dispose_crypto = ptls_vpp_crypto_aead_dispose_crypto;

  return 0;
}

static int
ptls_vpp_crypto_aes128ctr_setup_crypto (ptls_cipher_context_t * ctx,
					int is_enc, const void *key)
{
  return ptls_vpp_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_128_ctr (),
					      ptls_vpp_crypto_cipher_encrypt);
}

static int
ptls_vpp_crypto_aes256ctr_setup_crypto (ptls_cipher_context_t * ctx,
					int is_enc, const void *key)
{
  return ptls_vpp_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_256_ctr (),
					      ptls_vpp_crypto_cipher_encrypt);
}

static int
ptls_vpp_crypto_aead_aes128gcm_setup_crypto (ptls_aead_context_t * ctx,
					     int is_enc, const void *key,
					     const void *iv)
{
  return ptls_vpp_crypto_aead_setup_crypto (ctx, is_enc, key, iv,
					    VNET_CRYPTO_ALG_AES_128_GCM);
}

static int
ptls_vpp_crypto_aead_aes256gcm_setup_crypto (ptls_aead_context_t * ctx,
					     int is_enc, const void *key,
					     const void *iv)
{
  return ptls_vpp_crypto_aead_setup_crypto (ctx, is_enc, key, iv,
					    VNET_CRYPTO_ALG_AES_256_GCM);
}

ptls_cipher_algorithm_t ptls_vpp_crypto_aes128ctr = { "AES128-CTR",
  PTLS_AES128_KEY_SIZE,
  1, PTLS_AES_IV_SIZE,
  sizeof (struct vpp_aead_context_t),
  ptls_vpp_crypto_aes128ctr_setup_crypto
};

ptls_cipher_algorithm_t ptls_vpp_crypto_aes256ctr = { "AES256-CTR",
  PTLS_AES256_KEY_SIZE,
  1 /* block size */ ,
  PTLS_AES_IV_SIZE,
  sizeof (struct vpp_aead_context_t),
  ptls_vpp_crypto_aes256ctr_setup_crypto
};

ptls_aead_algorithm_t ptls_vpp_crypto_aes128gcm = { "AES128-GCM",
  &ptls_vpp_crypto_aes128ctr,
  NULL,
  PTLS_AES128_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  sizeof (struct vpp_aead_context_t),
  ptls_vpp_crypto_aead_aes128gcm_setup_crypto
};

ptls_aead_algorithm_t ptls_vpp_crypto_aes256gcm = { "AES256-GCM",
  &ptls_vpp_crypto_aes256ctr,
  NULL,
  PTLS_AES256_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  sizeof (struct vpp_aead_context_t),
  ptls_vpp_crypto_aead_aes256gcm_setup_crypto
};

ptls_cipher_suite_t ptls_vpp_crypto_aes128gcmsha256 =
  { PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
  &ptls_vpp_crypto_aes128gcm,
  &ptls_openssl_sha256
};

ptls_cipher_suite_t ptls_vpp_crypto_aes256gcmsha384 =
  { PTLS_CIPHER_SUITE_AES_256_GCM_SHA384,
  &ptls_vpp_crypto_aes256gcm,
  &ptls_openssl_sha384
};

ptls_cipher_suite_t *ptls_vpp_crypto_cipher_suites[] =
  { &ptls_vpp_crypto_aes256gcmsha384,
  &ptls_vpp_crypto_aes128gcmsha256,
  NULL
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
