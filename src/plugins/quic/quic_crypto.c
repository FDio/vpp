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
#include <vnet/crypto/crypto.h>
#include <vppinfra/lock.h>

#include <quic/quic.h>
#include <quic/quic_crypto.h>

#include <quicly.h>
#include <picotls/openssl.h>

#define QUICLY_EPOCH_1RTT 3

extern quic_main_t quic_main;
extern quic_ctx_t *quic_get_conn_ctx (quicly_conn_t * conn);
vnet_crypto_main_t *cm = &crypto_main;

struct cipher_context_t
{
  ptls_cipher_context_t super;
  vnet_crypto_op_t op;
  vnet_crypto_op_id_t id;
  u32 key_index;
};

struct aead_crypto_context_t
{
  ptls_aead_context_t super;
  vnet_crypto_op_t op;
  u32 key_index;
  vnet_crypto_op_id_t id;
  uint8_t static_iv[PTLS_MAX_IV_SIZE];
};

void
quic_crypto_batch_tx_packets (quic_crypto_batch_ctx_t * batch_ctx)
{
  vlib_main_t *vm = vlib_get_main ();

  if (batch_ctx->nb_tx_packets <= 0)
    return;

  clib_rwlock_reader_lock (&quic_main.crypto_keys_quic_rw_lock);
  vnet_crypto_process_ops (vm, batch_ctx->aead_crypto_tx_packets_ops,
			   batch_ctx->nb_tx_packets);
  vnet_crypto_process_ops (vm, batch_ctx->hp_crypto_tx_packets_ops,
			   batch_ctx->nb_tx_packets);
  clib_rwlock_reader_unlock (&quic_main.crypto_keys_quic_rw_lock);

  batch_ctx->nb_tx_packets = 0;
}

void
quic_crypto_batch_rx_packets (quic_crypto_batch_ctx_t * batch_ctx)
{
  vlib_main_t *vm = vlib_get_main ();

  if (batch_ctx->nb_rx_packets <= 0)
    return;

  clib_rwlock_reader_lock (&quic_main.crypto_keys_quic_rw_lock);
  vnet_crypto_process_ops (vm, batch_ctx->aead_crypto_rx_packets_ops,
			   batch_ctx->nb_rx_packets);
  clib_rwlock_reader_unlock (&quic_main.crypto_keys_quic_rw_lock);

  for (int i = 0; i < batch_ctx->nb_rx_packets; i++)
    clib_mem_free (batch_ctx->aead_crypto_rx_packets_ops[i].iv);

  batch_ctx->nb_rx_packets = 0;
}

void
quic_crypto_finalize_send_packet (struct iovec *packet,
				  quic_encrypt_cb_ctx * encrypt_cb_ctx)
{
  ptls_iovec_t *datagram;
  size_t first_byte_at;
  size_t payload_from;
  const uint8_t *hp_crypto_io;

  for (int i = 0; i < encrypt_cb_ctx->snd_ctx_count; i++)
    {
      datagram = (ptls_iovec_t *) packet;
      first_byte_at = encrypt_cb_ctx->snd_ctx[i].first_byte_at;
      payload_from = encrypt_cb_ctx->snd_ctx[i].payload_from;
      hp_crypto_io = encrypt_cb_ctx->snd_ctx[i].hp_crypto_io;

      datagram->base[first_byte_at] ^=
	hp_crypto_io[0] &
	(QUICLY_PACKET_IS_LONG_HEADER (datagram->base[first_byte_at]) ? 0xf :
	 0x1f);
      for (size_t i = 0; i != QUICLY_SEND_PN_SIZE; ++i)
	datagram->base[payload_from + i - QUICLY_SEND_PN_SIZE] ^=
	  hp_crypto_io[i + 1];
    }
  encrypt_cb_ctx->snd_ctx_count = 0;
}

static int
quic_crypto_setup_cipher (quicly_crypto_engine_t * engine,
			  quicly_conn_t * conn, size_t epoch, int is_enc,
			  ptls_cipher_context_t ** header_protect_ctx,
			  ptls_aead_context_t ** packet_protect_ctx,
			  ptls_aead_algorithm_t * aead,
			  ptls_hash_algorithm_t * hash, const void *secret)
{
  uint8_t hpkey[PTLS_MAX_SECRET_SIZE];
  int ret;

  *packet_protect_ctx = NULL;

  /* generate new header protection key */
  if (header_protect_ctx != NULL)
    {
      *header_protect_ctx = NULL;
      if ((ret =
	   ptls_hkdf_expand_label (hash, hpkey, aead->ctr_cipher->key_size,
				   ptls_iovec_init (secret,
						    hash->digest_size),
				   "quic hp", ptls_iovec_init (NULL, 0),
				   NULL)) != 0)
	goto Exit;
      if ((*header_protect_ctx =
	   ptls_cipher_new (aead->ctr_cipher, is_enc, hpkey)) == NULL)
	{
	  ret = PTLS_ERROR_NO_MEMORY;
	  goto Exit;
	}
    }

  /* generate new AEAD context */
  if ((*packet_protect_ctx =
       ptls_aead_new (aead, hash, is_enc, secret,
		      QUICLY_AEAD_BASE_LABEL)) == NULL)
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
      if (packet_protect_ctx && *packet_protect_ctx != NULL)
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
			    quicly_conn_t * conn,
			    ptls_cipher_context_t * header_protect_ctx,
			    ptls_aead_context_t * packet_protect_ctx,
			    ptls_iovec_t datagram, size_t first_byte_at,
			    size_t payload_from, uint64_t packet_number,
			    int coalesced)
{
  quic_main_t *qm = &quic_main;
  u32 thread_index = vlib_get_thread_index ();
  quic_encrypt_cb_ctx *encrypt_cb_ctx =
    &qm->wrk_ctx[thread_index].crypto_context_batch.
    crypto_tx_packet_ctx[qm->wrk_ctx
			 [thread_index].crypto_context_batch.nb_tx_packets];

  encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].hp =
    header_protect_ctx;
  encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].first_byte_at =
    first_byte_at;
  encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].payload_from =
    payload_from;

  quic_crypto_batch_ctx_t *quic_crypto_batch_ctx =
    &qm->wrk_ctx[thread_index].crypto_context_batch;

  struct cipher_context_t *hp_ctx =
    (struct cipher_context_t *) header_protect_ctx;
  struct aead_crypto_context_t *aead_ctx =
    (struct aead_crypto_context_t *) packet_protect_ctx;

  vnet_crypto_op_t *hp_op =
    &quic_crypto_batch_ctx->hp_crypto_tx_packets_ops
    [quic_crypto_batch_ctx->nb_tx_packets];
  vnet_crypto_op_t *vnet_aead_op =
    &quic_crypto_batch_ctx->aead_crypto_tx_packets_ops
    [quic_crypto_batch_ctx->nb_tx_packets];

  void *input = datagram.base + payload_from;
  void *output = input;
  size_t inlen = datagram.len - payload_from -
    packet_protect_ctx->algo->tag_size;
  const void *aad = datagram.base + first_byte_at;
  size_t aadlen = payload_from - first_byte_at;

/* Build AEAD encrypt crypto operation */
  vnet_crypto_op_init (vnet_aead_op, aead_ctx->id);
  vnet_aead_op->aad = (u8 *) aad;
  vnet_aead_op->aad_len = aadlen;
  vnet_aead_op->iv =
    encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].aead_iv;
  ptls_aead__build_iv (aead_ctx->super.algo, vnet_aead_op->iv,
		       aead_ctx->static_iv, packet_number);
  vnet_aead_op->key_index = aead_ctx->key_index;
  vnet_aead_op->src = (u8 *) input;
  vnet_aead_op->dst = output;
  vnet_aead_op->len = inlen;
  vnet_aead_op->tag_len = aead_ctx->super.algo->tag_size;
  vnet_aead_op->tag = vnet_aead_op->src + inlen;

/* Build Header protection crypto operation */
  vnet_crypto_op_init (hp_op, hp_ctx->id);
  memset (encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].hp_crypto_io,
	  0,
	  sizeof (encrypt_cb_ctx->
		  snd_ctx[encrypt_cb_ctx->snd_ctx_count].hp_crypto_io));
  hp_op->iv =
    datagram.base + payload_from - QUICLY_SEND_PN_SIZE + QUICLY_MAX_PN_SIZE;
  hp_op->key_index = hp_ctx->key_index;
  hp_op->src =
    encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].hp_crypto_io;
  hp_op->dst =
    encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].hp_crypto_io;
  hp_op->len =
    sizeof (encrypt_cb_ctx->
	    snd_ctx[encrypt_cb_ctx->snd_ctx_count].hp_crypto_io);

  quic_crypto_batch_ctx->nb_tx_packets++;
  encrypt_cb_ctx->snd_ctx_count++;
}

static size_t
quic_crypto_aead_decrypt (quic_ctx_t * qctx,
			  ptls_aead_context_t * _ctx, void *_output,
			  const void *input, size_t inlen,
			  uint64_t decrypted_pn, const void *aad,
			  size_t aadlen)
{
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  quic_main_t *qm = &quic_main;
  quic_crypto_batch_ctx_t *quic_crypto_batch_ctx =
    &qm->wrk_ctx[qctx->c_thread_index].crypto_context_batch;

  vnet_crypto_op_t *vnet_op =
    &quic_crypto_batch_ctx->aead_crypto_rx_packets_ops
    [quic_crypto_batch_ctx->nb_rx_packets];

  vnet_crypto_op_init (vnet_op, ctx->id);
  vnet_op->aad = (u8 *) aad;
  vnet_op->aad_len = aadlen;
  vnet_op->iv = clib_mem_alloc (PTLS_MAX_IV_SIZE);
  ptls_aead__build_iv (ctx->super.algo, vnet_op->iv, ctx->static_iv,
		       decrypted_pn);

  vnet_op->src = (u8 *) input;
  vnet_op->dst = _output;
  vnet_op->key_index = ctx->key_index;
  vnet_op->len = inlen - ctx->super.algo->tag_size;
  vnet_op->tag_len = ctx->super.algo->tag_size;
  vnet_op->tag = vnet_op->src + vnet_op->len;
  quic_crypto_batch_ctx->nb_rx_packets++;
  return vnet_op->len;
}

void
quic_crypto_decrypt_packet (quic_ctx_t * qctx, quic_rx_packet_ctx_t * pctx)
{
  ptls_cipher_context_t *header_protection = NULL;
  ptls_aead_context_t *aead = NULL;
  int pn;

  /* Long Header packets are not decrypted by vpp */
  if (QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]))
    return;

  uint64_t next_expected_packet_number =
    quicly_get_next_expected_packet_number (qctx->conn);
  if (next_expected_packet_number == UINT64_MAX)
    return;

  aead = qctx->ingress_keys.aead_ctx;
  header_protection = qctx->ingress_keys.hp_ctx;

  if (!aead || !header_protection)
    return;

  size_t encrypted_len = pctx->packet.octets.len - pctx->packet.encrypted_off;
  uint8_t hpmask[5] = { 0 };
  uint32_t pnbits = 0;
  size_t pnlen, ptlen, i;

  /* decipher the header protection, as well as obtaining pnbits, pnlen */
  if (encrypted_len < header_protection->algo->iv_size + QUICLY_MAX_PN_SIZE)
    return;
  ptls_cipher_init (header_protection,
		    pctx->packet.octets.base + pctx->packet.encrypted_off +
		    QUICLY_MAX_PN_SIZE);
  ptls_cipher_encrypt (header_protection, hpmask, hpmask, sizeof (hpmask));
  pctx->packet.octets.base[0] ^=
    hpmask[0] & (QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]) ?
		 0xf : 0x1f);
  pnlen = (pctx->packet.octets.base[0] & 0x3) + 1;
  for (i = 0; i != pnlen; ++i)
    {
      pctx->packet.octets.base[pctx->packet.encrypted_off + i] ^=
	hpmask[i + 1];
      pnbits =
	(pnbits << 8) | pctx->packet.octets.base[pctx->packet.encrypted_off +
						 i];
    }

  size_t aead_off = pctx->packet.encrypted_off + pnlen;

  pn =
    quicly_determine_packet_number (pnbits, pnlen * 8,
				    next_expected_packet_number);

  int key_phase_bit =
    (pctx->packet.octets.base[0] & QUICLY_KEY_PHASE_BIT) != 0;

  if (key_phase_bit != (qctx->key_phase_ingress & 1))
    {
      pctx->packet.octets.base[0] ^=
	hpmask[0] &
	(QUICLY_PACKET_IS_LONG_HEADER (pctx->packet.octets.base[0]) ? 0xf :
	 0x1f);
      for (i = 0; i != pnlen; ++i)
	{
	  pctx->packet.octets.base[pctx->packet.encrypted_off + i] ^=
	    hpmask[i + 1];
	}
      return;
    }

  if ((ptlen =
       quic_crypto_aead_decrypt (qctx, aead,
				 pctx->packet.octets.base + aead_off,
				 pctx->packet.octets.base + aead_off,
				 pctx->packet.octets.len - aead_off,
				 pn, pctx->packet.octets.base,
				 aead_off)) == SIZE_MAX)
    {
      fprintf (stderr,
	       "%s: aead decryption failure (pn: %d)\n", __FUNCTION__, pn);
      return;
    }

  pctx->packet.encrypted_off = aead_off;
  pctx->packet.octets.len = ptlen + aead_off;

  pctx->packet.decrypted.pn = pn;
  pctx->packet.decrypted.key_phase = qctx->key_phase_ingress;
}

static int
quic_crypto_cipher_setup_crypto (ptls_cipher_context_t * _ctx, int is_enc,
				 const void *key, const EVP_CIPHER * cipher)
{
  struct cipher_context_t *ctx = (struct cipher_context_t *) _ctx;

  vlib_main_t *vm = vlib_get_main ();
  vnet_crypto_alg_t algo;
  if (!strcmp (ctx->super.algo->name, "AES128-CTR"))
    {
      algo = VNET_CRYPTO_ALG_AES_128_CTR;
      ctx->id =
	is_enc ? VNET_CRYPTO_OP_AES_128_CTR_ENC :
	VNET_CRYPTO_OP_AES_128_CTR_DEC;
      ptls_openssl_aes128ctr.setup_crypto (_ctx, is_enc, key);

    }
  else if (!strcmp (ctx->super.algo->name, "AES256-CTR"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_CTR;
      ctx->id =
	is_enc ? VNET_CRYPTO_OP_AES_256_CTR_ENC :
	VNET_CRYPTO_OP_AES_256_CTR_DEC;
      ptls_openssl_aes256ctr.setup_crypto (_ctx, is_enc, key);
    }
  else
    {
      QUIC_DBG (1, "%s, Invalid crypto cipher : ", __FUNCTION__,
		_ctx->algo->name);
      assert (0);
    }

  if (quic_main.vnet_crypto_enabled)
    {
      clib_rwlock_writer_lock (&quic_main.crypto_keys_quic_rw_lock);
      ctx->key_index = vnet_crypto_key_add (vm, algo,
					    (u8 *) key, _ctx->algo->key_size);
      clib_rwlock_writer_unlock (&quic_main.crypto_keys_quic_rw_lock);
    }

  return 0;
}

static int
quic_crypto_aes128ctr_setup_crypto (ptls_cipher_context_t * ctx, int is_enc,
				    const void *key)
{
  return quic_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_128_ctr ());
}

static int
quic_crypto_aes256ctr_setup_crypto (ptls_cipher_context_t * ctx, int is_enc,
				    const void *key)
{
  return quic_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_256_ctr ());
}

static int
quic_crypto_aead_setup_crypto (ptls_aead_context_t * _ctx, int is_enc,
			       const void *key, const void *iv,
			       const EVP_CIPHER * cipher)
{
  vlib_main_t *vm = vlib_get_main ();
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  vnet_crypto_alg_t algo;
  if (!strcmp (ctx->super.algo->name, "AES128-GCM"))
    {
      algo = VNET_CRYPTO_ALG_AES_128_GCM;
      ctx->id =
	is_enc ? VNET_CRYPTO_OP_AES_128_GCM_ENC :
	VNET_CRYPTO_OP_AES_128_GCM_DEC;
      ptls_openssl_aes128gcm.setup_crypto (_ctx, is_enc, key, iv);
    }
  else if (!strcmp (ctx->super.algo->name, "AES256-GCM"))
    {
      algo = VNET_CRYPTO_ALG_AES_256_GCM;
      ctx->id =
	is_enc ? VNET_CRYPTO_OP_AES_256_GCM_ENC :
	VNET_CRYPTO_OP_AES_256_GCM_DEC;
      ptls_openssl_aes256gcm.setup_crypto (_ctx, is_enc, key, iv);
    }
  else
    {
      QUIC_DBG (1, "%s, invalied aead cipher %s", __FUNCTION__,
		_ctx->algo->name);
      assert (0);
    }

  if (quic_main.vnet_crypto_enabled)
    {
      memcpy (ctx->static_iv, iv, ctx->super.algo->iv_size);

      clib_rwlock_writer_lock (&quic_main.crypto_keys_quic_rw_lock);
      ctx->key_index = vnet_crypto_key_add (vm, algo,
					    (u8 *) key, _ctx->algo->key_size);
      clib_rwlock_writer_unlock (&quic_main.crypto_keys_quic_rw_lock);
    }

  return 0;
}

static int
quic_crypto_aead_aes128gcm_setup_crypto (ptls_aead_context_t * ctx,
					 int is_enc, const void *key,
					 const void *iv)
{
  return quic_crypto_aead_setup_crypto (ctx, is_enc, key, iv,
					EVP_aes_128_gcm ());
}

static int
quic_crypto_aead_aes256gcm_setup_crypto (ptls_aead_context_t * ctx,
					 int is_enc, const void *key,
					 const void *iv)
{
  return quic_crypto_aead_setup_crypto (ctx, is_enc, key, iv,
					EVP_aes_256_gcm ());
}

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

ptls_cipher_algorithm_t quic_crypto_aes128ctr = {
  "AES128-CTR",
  PTLS_AES128_KEY_SIZE,
  1, PTLS_AES_IV_SIZE,
  sizeof (struct cipher_context_t), quic_crypto_aes128ctr_setup_crypto
};

ptls_cipher_algorithm_t quic_crypto_aes256ctr = {
  "AES256-CTR", PTLS_AES256_KEY_SIZE, 1 /* block size */ ,
  PTLS_AES_IV_SIZE, sizeof (struct cipher_context_t),
  quic_crypto_aes256ctr_setup_crypto
};

ptls_aead_algorithm_t quic_crypto_aes128gcm = {
  "AES128-GCM",
  &quic_crypto_aes128ctr,
  &ptls_openssl_aes128ecb,
  PTLS_AES128_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  sizeof (struct aead_crypto_context_t),
  quic_crypto_aead_aes128gcm_setup_crypto
};

ptls_aead_algorithm_t quic_crypto_aes256gcm = {
  "AES256-GCM",
  &quic_crypto_aes256ctr,
  &ptls_openssl_aes256ecb,
  PTLS_AES256_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  sizeof (struct aead_crypto_context_t),
  quic_crypto_aead_aes256gcm_setup_crypto
};

ptls_cipher_suite_t quic_crypto_aes128gcmsha256 = {
  PTLS_CIPHER_SUITE_AES_128_GCM_SHA256,
  &quic_crypto_aes128gcm, &ptls_openssl_sha256
};

ptls_cipher_suite_t quic_crypto_aes256gcmsha384 = {
  PTLS_CIPHER_SUITE_AES_256_GCM_SHA384,
  &quic_crypto_aes256gcm, &ptls_openssl_sha384
};

ptls_cipher_suite_t *quic_crypto_cipher_suites[] = {
  &quic_crypto_aes256gcmsha384, &quic_crypto_aes128gcmsha256, NULL
};

quicly_crypto_engine_t quic_crypto_engine = {
  quic_crypto_setup_cipher, quic_crypto_encrypt_packet
};

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
