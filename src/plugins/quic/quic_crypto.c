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

static size_t
quic_crypto_offload_aead_decrypt (quic_ctx_t * qctx,
				  ptls_aead_context_t * _ctx, void *_output,
				  const void *input, size_t inlen,
				  uint64_t decrypted_pn, const void *aad,
				  size_t aadlen);

vnet_crypto_main_t *cm = &crypto_main;

void
quic_crypto_batch_tx_packets (quic_crypto_batch_ctx_t * batch_ctx)
{
  vlib_main_t *vm = vlib_get_main ();

  if (batch_ctx->nb_tx_packets <= 0)
    return;

  clib_rwlock_reader_lock (&quic_main.crypto_keys_quic_rw_lock);
  vnet_crypto_process_ops (vm, batch_ctx->aead_crypto_tx_packets_ops,
			   batch_ctx->nb_tx_packets);
  clib_rwlock_reader_unlock (&quic_main.crypto_keys_quic_rw_lock);

  for (int i = 0; i < batch_ctx->nb_tx_packets; i++)
    clib_mem_free (batch_ctx->aead_crypto_tx_packets_ops[i].iv);

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
build_iv (ptls_aead_context_t * ctx, uint8_t * iv, uint64_t seq)
{
  size_t iv_size = ctx->algo->iv_size, i;
  const uint8_t *s = ctx->static_iv;
  uint8_t *d = iv;
  /* build iv */
  for (i = iv_size - 8; i != 0; --i)
    *d++ = *s++;
  i = 64;
  do
    {
      i -= 8;
      *d++ = *s++ ^ (uint8_t) (seq >> i);
    }
  while (i != 0);
}

static void
do_finalize_send_packet (ptls_cipher_context_t * hp,
			 quicly_datagram_t * packet,
			 size_t first_byte_at, size_t payload_from)
{
  uint8_t hpmask[1 + QUICLY_SEND_PN_SIZE] = {
    0
  };
  size_t i;

  ptls_cipher_init (hp,
		    packet->data.base + payload_from - QUICLY_SEND_PN_SIZE +
		    QUICLY_MAX_PN_SIZE);
  ptls_cipher_encrypt (hp, hpmask, hpmask, sizeof (hpmask));

  packet->data.base[first_byte_at] ^=
    hpmask[0] &
    (QUICLY_PACKET_IS_LONG_HEADER (packet->data.base[first_byte_at]) ? 0xf :
     0x1f);

  for (i = 0; i != QUICLY_SEND_PN_SIZE; ++i)
    packet->data.base[payload_from + i - QUICLY_SEND_PN_SIZE] ^=
      hpmask[i + 1];
}

void
quic_crypto_finalize_send_packet (quicly_datagram_t * packet)
{
  quic_encrypt_cb_ctx *encrypt_cb_ctx =
    (quic_encrypt_cb_ctx *) ((uint8_t *) packet + sizeof (*packet));

  for (int i = 0; i < encrypt_cb_ctx->snd_ctx_count; i++)
    {
      do_finalize_send_packet (encrypt_cb_ctx->snd_ctx[i].hp,
			       packet,
			       encrypt_cb_ctx->snd_ctx[i].first_byte_at,
			       encrypt_cb_ctx->snd_ctx[i].payload_from);
    }
  encrypt_cb_ctx->snd_ctx_count = 0;
}

static int
quic_crypto_setup_cipher (quicly_crypto_engine_t * engine,
			  quicly_conn_t * conn, size_t epoch, int is_enc,
			  ptls_cipher_context_t ** hp_ctx,
			  ptls_aead_context_t ** aead_ctx,
			  ptls_aead_algorithm_t * aead,
			  ptls_hash_algorithm_t * hash, const void *secret)
{
  uint8_t hpkey[PTLS_MAX_SECRET_SIZE];
  int ret;

  *aead_ctx = NULL;

  /* generate new header protection key */
  if (hp_ctx != NULL)
    {
      *hp_ctx = NULL;
      if ((ret =
	   ptls_hkdf_expand_label (hash, hpkey, aead->ctr_cipher->key_size,
				   ptls_iovec_init (secret,
						    hash->digest_size),
				   "quic hp", ptls_iovec_init (NULL, 0),
				   NULL)) != 0)
	goto Exit;
      if ((*hp_ctx =
	   ptls_cipher_new (aead->ctr_cipher, is_enc, hpkey)) == NULL)
	{
	  ret = PTLS_ERROR_NO_MEMORY;
	  goto Exit;
	}
    }

  /* generate new AEAD context */
  if ((*aead_ctx =
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
	{
	  qctx->key_phase_ingress++;
	}

      qctx->ingress_keys.aead_ctx = *aead_ctx;
      if (hp_ctx != NULL)
	qctx->ingress_keys.hp_ctx = *hp_ctx;
    }

  ret = 0;

Exit:
  if (ret != 0)
    {
      if (aead_ctx && *aead_ctx != NULL)
	{
	  ptls_aead_free (*aead_ctx);
	  *aead_ctx = NULL;
	}
      if (hp_ctx && *hp_ctx != NULL)
	{
	  ptls_cipher_free (*hp_ctx);
	  *hp_ctx = NULL;
	}
    }
  ptls_clear_memory (hpkey, sizeof (hpkey));
  return ret;
}

void
quic_crypto_finalize_send_packet_cb (struct st_quicly_crypto_engine_t
				     *engine, quicly_conn_t * conn,
				     ptls_cipher_context_t * hp,
				     ptls_aead_context_t * aead,
				     quicly_datagram_t * packet,
				     size_t first_byte_at,
				     size_t payload_from, int coalesced)
{
  quic_encrypt_cb_ctx *encrypt_cb_ctx =
    (quic_encrypt_cb_ctx *) ((uint8_t *) packet + sizeof (*packet));

  encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].hp = hp;
  encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].first_byte_at =
    first_byte_at;
  encrypt_cb_ctx->snd_ctx[encrypt_cb_ctx->snd_ctx_count].payload_from =
    payload_from;
  encrypt_cb_ctx->snd_ctx_count++;
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
       quic_crypto_offload_aead_decrypt (qctx, aead,
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

#ifdef QUIC_HP_CRYPTO
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
quic_crypto_aes128ctr_setup_crypto (ptls_cipher_context_t * ctx, int is_enc,
				    const void *key)
{
  return quic_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_128_ctr (),
					  quic_crypto_cipher_encrypt);
}

static int
quic_crypto_aes256ctr_setup_crypto (ptls_cipher_context_t * ctx, int is_enc,
				    const void *key)
{
  return quic_crypto_cipher_setup_crypto (ctx, 1, key, EVP_aes_256_ctr (),
					  quic_crypto_cipher_encrypt);
}

#endif // QUIC_HP_CRYPTO

void
quic_crypto_aead_encrypt_init (ptls_aead_context_t * _ctx, const void *iv,
			       const void *aad, size_t aadlen)
{
  quic_main_t *qm = &quic_main;
  u32 thread_index = vlib_get_thread_index ();

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

  quic_crypto_batch_ctx_t *quic_crypto_batch_ctx =
    &qm->wrk_ctx[thread_index].crypto_context_batch;

  vnet_crypto_op_t *vnet_op =
    &quic_crypto_batch_ctx->aead_crypto_tx_packets_ops
    [quic_crypto_batch_ctx->nb_tx_packets];
  vnet_crypto_op_init (vnet_op, id);
  vnet_op->aad = (u8 *) aad;
  vnet_op->aad_len = aadlen;
  vnet_op->iv = clib_mem_alloc (PTLS_MAX_IV_SIZE);
  clib_memcpy (vnet_op->iv, iv, PTLS_MAX_IV_SIZE);
  vnet_op->key_index = ctx->key_index;
}

size_t
quic_crypto_aead_encrypt_update (ptls_aead_context_t * _ctx, void *output,
				 const void *input, size_t inlen)
{
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  quic_main_t *qm = &quic_main;
  u32 thread_index = vlib_get_thread_index ();
  quic_crypto_batch_ctx_t *quic_crypto_batch_ctx =
    &qm->wrk_ctx[thread_index].crypto_context_batch;

  vnet_crypto_op_t *vnet_op =
    &quic_crypto_batch_ctx->aead_crypto_tx_packets_ops
    [quic_crypto_batch_ctx->nb_tx_packets];
  vnet_op->src = (u8 *) input;
  vnet_op->dst = output;
  vnet_op->len = inlen;
  vnet_op->tag_len = ctx->super.algo->tag_size;

  vnet_op->tag = vnet_op->src + inlen;

  return 0;
}

size_t
quic_crypto_aead_encrypt_final (ptls_aead_context_t * _ctx, void *output)
{
  quic_main_t *qm = &quic_main;
  u32 thread_index = vlib_get_thread_index ();
  quic_crypto_batch_ctx_t *quic_crypto_batch_ctx =
    &qm->wrk_ctx[thread_index].crypto_context_batch;

  vnet_crypto_op_t *vnet_op =
    &quic_crypto_batch_ctx->
    aead_crypto_tx_packets_ops[quic_crypto_batch_ctx->nb_tx_packets];
  quic_crypto_batch_ctx->nb_tx_packets++;
  return vnet_op->len + vnet_op->tag_len;
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

  if (ctx->op.status != VNET_CRYPTO_OP_STATUS_COMPLETED)
    return SIZE_MAX;

  return ctx->op.len;
}

static size_t
quic_crypto_offload_aead_decrypt (quic_ctx_t * qctx,
				  ptls_aead_context_t * _ctx, void *_output,
				  const void *input, size_t inlen,
				  uint64_t decrypted_pn, const void *aad,
				  size_t aadlen)
{
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
      return SIZE_MAX;
    }

  quic_main_t *qm = &quic_main;
  quic_crypto_batch_ctx_t *quic_crypto_batch_ctx =
    &qm->wrk_ctx[qctx->c_thread_index].crypto_context_batch;

  vnet_crypto_op_t *vnet_op =
    &quic_crypto_batch_ctx->aead_crypto_rx_packets_ops
    [quic_crypto_batch_ctx->nb_rx_packets];

  vnet_crypto_op_init (vnet_op, id);
  vnet_op->aad = (u8 *) aad;
  vnet_op->aad_len = aadlen;
  vnet_op->iv = clib_mem_alloc (PTLS_MAX_IV_SIZE);
  build_iv (_ctx, vnet_op->iv, decrypted_pn);
  vnet_op->src = (u8 *) input;
  vnet_op->dst = _output;
  vnet_op->key_index = ctx->key_index;
  vnet_op->len = inlen - ctx->super.algo->tag_size;
  vnet_op->tag_len = ctx->super.algo->tag_size;
  vnet_op->tag = vnet_op->src + vnet_op->len;
  quic_crypto_batch_ctx->nb_rx_packets++;
  return vnet_op->len;
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

  if (quic_main.vnet_crypto_enabled)
    {
      ctx->super.do_decrypt = quic_crypto_aead_decrypt;

      ctx->super.do_encrypt_init = quic_crypto_aead_encrypt_init;
      ctx->super.do_encrypt_update = quic_crypto_aead_encrypt_update;
      ctx->super.do_encrypt_final = quic_crypto_aead_encrypt_final;
      ctx->super.dispose_crypto = quic_crypto_aead_dispose_crypto;

      clib_rwlock_writer_lock (&quic_main.crypto_keys_quic_rw_lock);
      ctx->key_index = vnet_crypto_key_add (vm, algo,
					    (u8 *) key, _ctx->algo->key_size);
      clib_rwlock_writer_unlock (&quic_main.crypto_keys_quic_rw_lock);
    }
  else
    {
      if (!strcmp (ctx->super.algo->name, "AES128-GCM"))
	ptls_openssl_aes128gcm.setup_crypto (_ctx, is_enc, key);
      else if (!strcmp (ctx->super.algo->name, "AES256-GCM"))
	ptls_openssl_aes256gcm.setup_crypto (_ctx, is_enc, key);
    }

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

#ifdef QUIC_HP_CRYPTO
ptls_cipher_algorithm_t quic_crypto_aes128ctr = {
  "AES128-CTR",
  PTLS_AES128_KEY_SIZE,
  1, PTLS_AES_IV_SIZE,
  sizeof (struct cipher_context_t), aes128ctr_setup_crypto
};

ptls_cipher_algorithm_t quic_crypto_aes256ctr = {
  "AES256-CTR", PTLS_AES256_KEY_SIZE, 1 /* block size */ ,
  PTLS_AES_IV_SIZE, sizeof (struct cipher_context_t), aes256ctr_setup_crypto
};
#endif

ptls_aead_algorithm_t quic_crypto_aes128gcm = {
  "AES128-GCM",
#ifdef QUIC_HP_CRYPTO
  &quic_crypto_aes128ctr,
#else
  &ptls_openssl_aes128ctr,
#endif
  &ptls_openssl_aes128ecb,
  PTLS_AES128_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  sizeof (struct aead_crypto_context_t),
  quic_crypto_aead_aes128gcm_setup_crypto
};

ptls_aead_algorithm_t quic_crypto_aes256gcm = {
  "AES256-GCM",
#ifdef QUIC_HP_CRYPTO
  &quic_crypto_aes256ctr,
#else
  &ptls_openssl_aes256ctr,
#endif
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
  quic_crypto_setup_cipher, quic_crypto_finalize_send_packet_cb
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
