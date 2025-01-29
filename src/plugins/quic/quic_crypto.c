/*
 * Copyright (c) 2021 Cisco and/or its affiliates.
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

#include <quic/quic.h>
#include <quic/quic_inlines.h>
#include <quic/quic_crypto.h>
#include <vnet/session/session.h>

#include <quicly.h>
#include <picotls/openssl.h>
#include <pthread.h>

#define QUICLY_EPOCH_1RTT 3

extern quic_main_t quic_main;
extern quic_ctx_t *quic_get_conn_ctx (quicly_conn_t *conn);
vnet_crypto_main_t *cm = &crypto_main;

static int
quic_crypto_setup_cipher (quicly_crypto_engine_t *engine, quicly_conn_t *conn,
			  size_t epoch, int is_enc,
			  ptls_cipher_context_t **header_protect_ctx,
			  ptls_aead_context_t **packet_protect_ctx,
			  ptls_aead_algorithm_t *aead,
			  ptls_hash_algorithm_t *hash, const void *secret)
{
  uint8_t hpkey[PTLS_MAX_SECRET_SIZE];
  int ret;

  *packet_protect_ctx = NULL;
  /* generate new header protection key */
  if (header_protect_ctx != NULL)
    {
      *header_protect_ctx = NULL;
      ret =
	ptls_hkdf_expand_label (hash, hpkey, aead->ctr_cipher->key_size,
				ptls_iovec_init (secret, hash->digest_size),
				"quic hp", ptls_iovec_init (NULL, 0), NULL);
      if (ret)
	goto Exit;
      *header_protect_ctx = ptls_cipher_new (aead->ctr_cipher, is_enc, hpkey);
      if (NULL == *header_protect_ctx)
	{
	  ret = PTLS_ERROR_NO_MEMORY;
	  goto Exit;
	}
    }

  /* generate new AEAD context */
  *packet_protect_ctx =
    ptls_aead_new (aead, hash, is_enc, secret, QUICLY_AEAD_BASE_LABEL);
  if (NULL == *packet_protect_ctx)
    {
      ret = PTLS_ERROR_NO_MEMORY;
      goto Exit;
    }

  if (epoch == QUICLY_EPOCH_1RTT && !is_enc)
    {
      quic_ctx_t *qctx = quic_get_conn_ctx (conn);
      if (qctx->ingress_keys.aead_ctx != NULL)
	qctx->key_phase_ingress++;

      qctx->ingress_keys.aead_ctx = *packet_protect_ctx;
      if (header_protect_ctx != NULL)
	qctx->ingress_keys.hp_ctx = *header_protect_ctx;
    }

  ret = 0;

Exit:
  if (ret)
    {
      if (*packet_protect_ctx != NULL)
	{
	  ptls_aead_free (*packet_protect_ctx);
	  *packet_protect_ctx = NULL;
	}
      if (header_protect_ctx && *header_protect_ctx != NULL)
	{
	  ptls_cipher_free (*header_protect_ctx);
	  *header_protect_ctx = NULL;
	}
    }
  ptls_clear_memory (hpkey, sizeof (hpkey));
  return ret;
}

static void
quic_crypto_encrypt_packet (struct st_quicly_crypto_engine_t *engine,
			    quicly_conn_t *conn,
			    ptls_cipher_context_t *header_protect_ctx,
			    ptls_aead_context_t *packet_protect_ctx,
			    ptls_iovec_t datagram, size_t first_byte_at,
			    size_t payload_from, uint64_t packet_number,
			    int coalesced)
{
  quic_lib_crypto_encrypt_packet(engine, conn,
                                                 header_protect_ctx,
                                                 packet_protect_ctx,
                                                 datagram, first_byte_at,
                                                 payload_from,
                                                 packet_number,
                                                 coalesced);
}

static int
quic_crypto_cipher_setup_crypto (ptls_cipher_context_t *_ctx, int is_enc,
				 const void *key, const EVP_CIPHER *cipher)
{
  struct cipher_context_t *ctx = (struct cipher_context_t *) _ctx;

  vnet_crypto_alg_t algo;
  if (!strcmp (ctx->super.algo->name, "AES128-CTR"))
    {
      algo = VNET_CRYPTO_ALG_AES_128_CTR;
      ctx->id = is_enc ? VNET_CRYPTO_OP_AES_128_CTR_ENC :
			 VNET_CRYPTO_OP_AES_128_CTR_DEC;
      ptls_openssl_aes128ctr.setup_crypto (_ctx, is_enc, key);
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-CTR"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_CTR;
      ctx->id = is_enc ? VNET_CRYPTO_OP_AES_256_CTR_ENC :
			 VNET_CRYPTO_OP_AES_256_CTR_DEC;
      ptls_openssl_aes256ctr.setup_crypto (_ctx, is_enc, key);
    }
  else
    {
      QUIC_DBG (1, "%s, Invalid crypto cipher : ", __func__, _ctx->algo->name);
      assert (0);
    }

  if (quic_main.vnet_crypto_enabled)
    {
      //       ctx->key_index =
      // 	quic_crypto_go_setup_key (algo, key, _ctx->algo->key_size);
      ctx->key.algo = algo;
      ctx->key.key_len = _ctx->algo->key_size;
      assert (ctx->key.key_len <= 32);
      clib_memcpy (&ctx->key.key, key, ctx->key.key_len);
    }

  return 0;
}

static int
quic_crypto_aes128ctr_setup_crypto (ptls_cipher_context_t *ctx, int is_enc,
				    const void *key)
{
  return quic_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_128_ctr ());
}

static int
quic_crypto_aes256ctr_setup_crypto (ptls_cipher_context_t *ctx, int is_enc,
				    const void *key)
{
  return quic_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_256_ctr ());
}

static int
quic_crypto_aead_setup_crypto (ptls_aead_context_t *_ctx, int is_enc,
			       const void *key, const void *iv,
			       const EVP_CIPHER *cipher)
{
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  vnet_crypto_alg_t algo;
  if (!strcmp (ctx->super.algo->name, "AES128-GCM"))
    {
      algo = VNET_CRYPTO_ALG_AES_128_GCM;
      ctx->id = is_enc ? VNET_CRYPTO_OP_AES_128_GCM_ENC :
			 VNET_CRYPTO_OP_AES_128_GCM_DEC;
      ptls_openssl_aes128gcm.setup_crypto (_ctx, is_enc, key, iv);
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-GCM"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_GCM;
      ctx->id = is_enc ? VNET_CRYPTO_OP_AES_256_GCM_ENC :
			 VNET_CRYPTO_OP_AES_256_GCM_DEC;
      ptls_openssl_aes256gcm.setup_crypto (_ctx, is_enc, key, iv);
    }
  else
    {
      QUIC_DBG (1, "%s, invalied aead cipher %s", __func__, _ctx->algo->name);
      assert (0);
    }

  if (quic_main.vnet_crypto_enabled)
    {
      clib_memcpy (ctx->static_iv, iv, ctx->super.algo->iv_size);
      //       ctx->key_index =
      // 	quic_crypto_go_setup_key (algo, key, _ctx->algo->key_size);
      ctx->key.algo = algo;
      ctx->key.key_len = _ctx->algo->key_size;
      assert (ctx->key.key_len <= 32);
      clib_memcpy (&ctx->key.key, key, ctx->key.key_len);
    }

  return 0;
}

static int
quic_crypto_aead_aes128gcm_setup_crypto (ptls_aead_context_t *ctx, int is_enc,
					 const void *key, const void *iv)
{
  return quic_crypto_aead_setup_crypto (ctx, is_enc, key, iv,
					EVP_aes_128_gcm ());
}

static int
quic_crypto_aead_aes256gcm_setup_crypto (ptls_aead_context_t *ctx, int is_enc,
					 const void *key, const void *iv)
{
  return quic_crypto_aead_setup_crypto (ctx, is_enc, key, iv,
					EVP_aes_256_gcm ());
}

int
quic_encrypt_ticket_cb (ptls_encrypt_ticket_t *_self, ptls_t *tls,
			int is_encrypt, ptls_buffer_t *dst, ptls_iovec_t src)
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

ptls_cipher_algorithm_t quic_crypto_aes128ctr = {
  "AES128-CTR",
  PTLS_AES128_KEY_SIZE,
  1,
  PTLS_AES_IV_SIZE,
  sizeof (struct cipher_context_t),
  quic_crypto_aes128ctr_setup_crypto
};

ptls_cipher_algorithm_t quic_crypto_aes256ctr = {
  "AES256-CTR",
  PTLS_AES256_KEY_SIZE,
  1 /* block size */,
  PTLS_AES_IV_SIZE,
  sizeof (struct cipher_context_t),
  quic_crypto_aes256ctr_setup_crypto
};

#define PTLS_X86_CACHE_LINE_ALIGN_BITS 6
ptls_aead_algorithm_t quic_crypto_aes128gcm = {
  "AES128-GCM",
  PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
  PTLS_AESGCM_INTEGRITY_LIMIT,
  &quic_crypto_aes128ctr,
  &ptls_openssl_aes128ecb,
  PTLS_AES128_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  { PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE },
  1,
  PTLS_X86_CACHE_LINE_ALIGN_BITS,
  sizeof (struct aead_crypto_context_t),
  quic_crypto_aead_aes128gcm_setup_crypto
};

ptls_aead_algorithm_t quic_crypto_aes256gcm = {
  "AES256-GCM",
  PTLS_AESGCM_CONFIDENTIALITY_LIMIT,
  PTLS_AESGCM_INTEGRITY_LIMIT,
  &quic_crypto_aes256ctr,
  &ptls_openssl_aes256ecb,
  PTLS_AES256_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  { PTLS_TLS12_AESGCM_FIXED_IV_SIZE, PTLS_TLS12_AESGCM_RECORD_IV_SIZE },
  1,
  PTLS_X86_CACHE_LINE_ALIGN_BITS,
  sizeof (struct aead_crypto_context_t),
  quic_crypto_aead_aes256gcm_setup_crypto
};

ptls_cipher_suite_t quic_crypto_aes128gcmsha256 = {
  PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &quic_crypto_aes128gcm,
  &ptls_openssl_sha256
};

ptls_cipher_suite_t quic_crypto_aes256gcmsha384 = {
  PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &quic_crypto_aes256gcm,
  &ptls_openssl_sha384
};

ptls_cipher_suite_t *quic_crypto_cipher_suites[] = {
  &quic_crypto_aes256gcmsha384, &quic_crypto_aes128gcmsha256, NULL
};

quicly_crypto_engine_t quic_crypto_engine = { quic_crypto_setup_cipher,
					      quic_crypto_encrypt_packet };

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
