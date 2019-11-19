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

struct aead_crypto_context_t
{
  ptls_aead_context_t super;
  vnet_crypto_op_t op;
  u32 key_index;
};

struct cipher_context_t
{
  ptls_cipher_context_t super;
  vnet_crypto_op_t op;
  u32 key_index;
};

vnet_crypto_main_t *cm = &crypto_main;

typedef struct quic_crypto_op_
{
  vnet_crypto_op_t *aead_op;
  u8 iv[PTLS_MAX_IV_SIZE];
  u32 key_index;
} quic_crypto_op_t;

vnet_crypto_op_t aead_crypto_ops[QUIC_SEND_MAX_BATCH_PACKETS];
vnet_crypto_op_t aead_decrypt_ops[QUIC_RCV_MAX_BATCH_PACKETS];

size_t crypto_op_count = 0;
size_t decrypt_op_count = 0;

quic_crypto_op_t crypto_ops[QUIC_SEND_MAX_BATCH_PACKETS];
quic_crypto_op_t decrypt_ops[QUIC_RCV_MAX_BATCH_PACKETS];

static int
quic_do_decrypt_packet (ptls_cipher_context_t * header_protection,
			ptls_aead_context_t ** aead,
			uint64_t next_expected_pn,
			quicly_decoded_packet_t * packet, uint64_t * pn)
{

  size_t encrypted_len = packet->octets.len - packet->encrypted_off;
  uint8_t hpmask[5] = { 0 };
  uint32_t pnbits = 0;
  size_t pnlen, aead_index, i;

  /* decipher the header protection, as well as obtaining pnbits, pnlen */
  if (encrypted_len < header_protection->algo->iv_size + QUICLY_MAX_PN_SIZE)
    goto Error;
  ptls_cipher_init (header_protection,
		    packet->octets.base + packet->encrypted_off +
		    QUICLY_MAX_PN_SIZE);
  ptls_cipher_encrypt (header_protection, hpmask, hpmask, sizeof (hpmask));
  packet->octets.base[0] ^=
    hpmask[0] & (QUICLY_PACKET_IS_LONG_HEADER (packet->octets.base[0]) ? 0xf :
		 0x1f);
  pnlen = (packet->octets.base[0] & 0x3) + 1;
  for (i = 0; i != pnlen; ++i)
    {
      packet->octets.base[packet->encrypted_off + i] ^= hpmask[i + 1];
      pnbits = (pnbits << 8) | packet->octets.base[packet->encrypted_off + i];
    }

  /* determine aead index (FIXME move AEAD key selection and decryption logic to the caller?) */
  if (QUICLY_PACKET_IS_LONG_HEADER (packet->octets.base[0]))
    {
      aead_index = 0;
    }
  else
    {
      /* note: aead index 0 is used by 0-RTT */
      aead_index = (packet->octets.base[0] & QUICLY_KEY_PHASE_BIT) == 0;
      if (aead[aead_index] == NULL)
	goto Error;
    }

  /* AEAD */
  *pn = quicly_determine_packet_number (pnbits, pnlen * 8, next_expected_pn);
  size_t aead_off = packet->encrypted_off + pnlen, ptlen;
  if ((ptlen =
       quic_crypto_aead_decrypt_push (aead[aead_index],
				      packet->octets.base + aead_off,
				      packet->octets.base + aead_off,
				      packet->octets.len - aead_off, *pn,
				      packet->octets.base,
				      aead_off)) == SIZE_MAX)
    {
      if (QUICLY_DEBUG)
	fprintf (stderr, "%s: aead decryption failure (pn: %" PRIu64 ")\n",
		 __FUNCTION__, *pn);
      goto Error;
    }

  packet->encrypted_off = aead_off;
  packet->octets.len = ptlen + aead_off;
  return ptlen;

Error:
  return -1;
}

int
quic_decrypt_packet (quicly_conn_t * conn,
		     quicly_decoded_packet_t * packet,
		     struct sockaddr *dest_addr, struct sockaddr *src_addr)
{
  if (QUICLY_PACKET_IS_LONG_HEADER (packet->octets.base[0]))
    {
      return -1;
    }

  ptls_cipher_context_t *header_protection =
    quicly_get_conn_cipher_context (conn);
  ptls_aead_context_t **aead = quicly_get_conn_aead_context (conn);
  struct st_quicly_pn_space_t **space = quicly_get_conn_pn_space (conn);

  return quic_do_decrypt_packet (header_protection, aead,
				 (*space)->next_expected_packet_number,
				 packet, &packet->decrypted_pn);
}


#ifdef USE_VPP_HP_CIPHER
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
  //fprintf (stderr, "%s ptls_cipher_context_t %p \n\r", __FUNCTION__, _ctx);
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
#endif // USE_VPP_HP_CIPHER

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
quic_crypto_codec_packet_encrypt_done (ptls_cipher_context_t * hp,
				       quicly_datagram_t * packet,
				       size_t first_byte_at,
				       size_t payload_from)
{
  uint8_t hpmask[1 + QUICLY_SEND_PN_SIZE] = { 0 };
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
quic_finalize_send_packet (quicly_datagram_t * packet)
{
  quic_encrypt_cb_ctx *encrypt_cb_ctx =
    (quic_encrypt_cb_ctx *) ((uint8_t *) packet + sizeof (*packet));

  for (int i = 0; i < encrypt_cb_ctx->snd_ctx_count; i++)
    {
      quic_crypto_codec_packet_encrypt_done (encrypt_cb_ctx->snd_ctx[i].hp,
					     packet,
					     encrypt_cb_ctx->
					     snd_ctx[i].first_byte_at,
					     encrypt_cb_ctx->
					     snd_ctx[i].payload_from);
    }

  encrypt_cb_ctx->snd_ctx_count = 0;
}

void
quic_finalize_send_packet_cb (quicly_finalize_send_packet_t * _self,
			      quicly_conn_t * conn,
			      ptls_cipher_context_t * hp,
			      ptls_aead_context_t * aead,
			      quicly_datagram_t * packet,
			      size_t first_byte_at, size_t payload_from,
			      int coalesced)
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
quic_crypto_aead_encrypt_init (ptls_aead_context_t * _ctx, const void *iv,
			       const void *aad, size_t aadlen)
{
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

  vnet_crypto_op_t *vnet_op = &aead_crypto_ops[crypto_op_count];

  vnet_crypto_op_init (vnet_op, id);
  vnet_op->aad = (u8 *) aad;
  vnet_op->aad_len = aadlen;
  memcpy (crypto_ops[crypto_op_count].iv, iv, PTLS_MAX_IV_SIZE);
  vnet_op->iv = (u8 *) crypto_ops[crypto_op_count].iv;
  vnet_op->key_index = ctx->key_index;
}

size_t
quic_crypto_aead_encrypt_update (ptls_aead_context_t * _ctx, void *output,
				 const void *input, size_t inlen)
{
  struct aead_crypto_context_t *ctx = (struct aead_crypto_context_t *) _ctx;

  vnet_crypto_op_t *vnet_op = &aead_crypto_ops[crypto_op_count];
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
  vnet_crypto_op_t *vnet_op = &aead_crypto_ops[crypto_op_count];
  crypto_op_count++;

  return vnet_op->len + vnet_op->tag_len;
}

size_t
quic_crypto_aead_decrypt_push (ptls_aead_context_t * _ctx, void *_output,
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
      assert (0);
    }

  vnet_crypto_op_t *vnet_op = &aead_decrypt_ops[decrypt_op_count];

  vnet_crypto_op_init (vnet_op, id);
  vnet_op->aad = (u8 *) aad;
  vnet_op->aad_len = aadlen;
  build_iv (_ctx, decrypt_ops[decrypt_op_count].iv, decrypted_pn);
  vnet_op->iv = (u8 *) decrypt_ops[decrypt_op_count].iv;

  vnet_op->src = (u8 *) input;
  vnet_op->dst = _output;
  vnet_op->key_index = ctx->key_index;
  vnet_op->len = inlen - ctx->super.algo->tag_size;

  vnet_op->tag_len = ctx->super.algo->tag_size;
  vnet_op->tag = vnet_op->src + vnet_op->len;

  decrypt_op_count++;

  return vnet_op->len;
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
  ctx->super.do_encrypt_init = quic_crypto_aead_encrypt_init;
  ctx->super.do_encrypt_update = quic_crypto_aead_encrypt_update;
  ctx->super.do_encrypt_final = quic_crypto_aead_encrypt_final;
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

#ifdef USE_VPP_HP_CIPHER
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
#endif

ptls_aead_algorithm_t quic_crypto_aes128gcm = { "AES128-GCM",
#ifdef USE_VPP_HP_CIPHER
  &quic_crypto_aes128ctr,
#else
  &ptls_openssl_aes128ctr,
#endif
  NULL,
  PTLS_AES128_KEY_SIZE,
  PTLS_AESGCM_IV_SIZE,
  PTLS_AESGCM_TAG_SIZE,
  sizeof (struct aead_crypto_context_t),
  quic_crypto_aead_aes128gcm_setup_crypto
};

ptls_aead_algorithm_t quic_crypto_aes256gcm = { "AES256-GCM",
#ifdef USE_VPP_HP_CIPHER
  &quic_crypto_aes256ctr,
#else
  &ptls_openssl_aes256ctr,
#endif
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

void
quic_crypto_process ()
{
  vlib_main_t *vm = vlib_get_main ();

  if (crypto_op_count <= 0)
    return;

  vnet_crypto_process_ops (vm, aead_crypto_ops, crypto_op_count);

  crypto_op_count = 0;
}

void
quic_decrypt_process ()
{
  vlib_main_t *vm = vlib_get_main ();

  if (decrypt_op_count <= 0)
    return;

  vnet_crypto_process_ops (vm, aead_decrypt_ops, decrypt_op_count);

  decrypt_op_count = 0;
}

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
